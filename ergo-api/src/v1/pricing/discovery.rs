use crate::v1::decode::decoders::spectrum::{
    decode_n2t_pool, SpectrumN2TPool, SPECTRUM_N2T_V1_TEMPLATE_HASH_HEX,
};
use ergo_indexer_types::{
    BoxId, IndexedBoxDto, IndexedTokenDto, IndexerQuery, IndexerReadError, Page, SortDir,
    TemplateHash, TokenId,
};

use super::types::token_decimals_from_r6;

const PAGE_SIZE: u32 = 100;
const CANDIDATE_LIMIT: u32 = 5_000;

pub(crate) trait PricingIndex: Send + Sync {
    fn indexed_height(&self) -> u64;

    fn template_unspent_paged(
        &self,
        hash: &TemplateHash,
        page: Page,
        dir: SortDir,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError>;

    fn token_by_id(&self, id: &TokenId) -> Result<Option<IndexedTokenDto>, IndexerReadError>;

    fn box_by_id(&self, id: &BoxId) -> Result<Option<IndexedBoxDto>, IndexerReadError>;
}

impl<T: IndexerQuery + ?Sized> PricingIndex for T {
    fn indexed_height(&self) -> u64 {
        IndexerQuery::indexed_height(self)
    }

    fn template_unspent_paged(
        &self,
        hash: &TemplateHash,
        page: Page,
        dir: SortDir,
    ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
        IndexerQuery::try_template_unspent_paged(self, hash, page, dir)
    }

    fn token_by_id(&self, id: &TokenId) -> Result<Option<IndexedTokenDto>, IndexerReadError> {
        IndexerQuery::try_token_by_id(self, id)
    }

    fn box_by_id(&self, id: &BoxId) -> Result<Option<IndexedBoxDto>, IndexerReadError> {
        IndexerQuery::try_box_by_id(self, id)
    }
}

pub trait PoolDiscovery: Send + Sync {
    fn discover(&self, token_id: &TokenId) -> Result<DiscoverySnapshot, DiscoveryError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverySnapshot {
    pub height: u64,
    pub pools: Vec<SpectrumN2TPool>,
    pub token_decimals: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    Read(IndexerReadError),
    LimitExceeded,
    UnstableIndex,
}

impl From<IndexerReadError> for DiscoveryError {
    fn from(error: IndexerReadError) -> Self {
        Self::Read(error)
    }
}

pub struct IndexerPoolDiscovery<'a, I: ?Sized> {
    index: &'a I,
    template_hash: TemplateHash,
}

impl<'a, I: ?Sized> IndexerPoolDiscovery<'a, I> {
    pub fn new(index: &'a I) -> Self {
        let template_hash = hex::decode(SPECTRUM_N2T_V1_TEMPLATE_HASH_HEX)
            .expect("Spectrum N2T template hash must be valid hex")
            .try_into()
            .map(TemplateHash::from_bytes)
            .expect("Spectrum N2T template hash must be 32 bytes");
        Self {
            index,
            template_hash,
        }
    }
}

fn discover_once<I: PricingIndex + ?Sized>(
    discovery: &IndexerPoolDiscovery<'_, I>,
    token_id: &TokenId,
) -> Result<(Vec<SpectrumN2TPool>, Option<u32>), DiscoveryError> {
    let mut pools = Vec::new();
    let mut candidate_count = 0u32;
    let mut reached_limit = true;

    for offset in (0..CANDIDATE_LIMIT).step_by(PAGE_SIZE as usize) {
        let candidates = discovery.index.template_unspent_paged(
            &discovery.template_hash,
            Page {
                offset,
                limit: PAGE_SIZE,
            },
            SortDir::Asc,
        )?;
        let page_len =
            u32::try_from(candidates.len()).map_err(|_| DiscoveryError::LimitExceeded)?;
        candidate_count = candidate_count
            .checked_add(page_len)
            .ok_or(DiscoveryError::LimitExceeded)?;
        if candidate_count > CANDIDATE_LIMIT {
            return Err(DiscoveryError::LimitExceeded);
        }

        for candidate in candidates {
            if let Ok(pool) = decode_n2t_pool(&candidate) {
                if pool.token_y == *token_id {
                    pools.push(pool);
                }
            }
        }

        if page_len < PAGE_SIZE {
            reached_limit = false;
            break;
        }
    }

    if reached_limit {
        let probe = discovery.index.template_unspent_paged(
            &discovery.template_hash,
            Page {
                offset: CANDIDATE_LIMIT,
                limit: 1,
            },
            SortDir::Asc,
        )?;
        if !probe.is_empty() {
            return Err(DiscoveryError::LimitExceeded);
        }
    }

    let token_decimals = if pools.is_empty() {
        None
    } else {
        read_token_decimals(discovery.index, token_id)?
    };
    Ok((pools, token_decimals))
}

fn read_token_decimals<I: PricingIndex + ?Sized>(
    index: &I,
    token_id: &TokenId,
) -> Result<Option<u32>, DiscoveryError> {
    let Some(token) = index.token_by_id(token_id)? else {
        return Ok(None);
    };
    let creation_box_id = token.creating_box_id;
    let creation_box = index.box_by_id(&creation_box_id)?.ok_or_else(|| {
        IndexerReadError::new(format!(
            "token {} creation box {} is missing",
            hex::encode(token_id.as_bytes()),
            hex::encode(creation_box_id.as_bytes())
        ))
    })?;
    Ok(token_decimals_from_r6(&creation_box.box_data))
}

impl<I: PricingIndex + ?Sized> PoolDiscovery for IndexerPoolDiscovery<'_, I> {
    fn discover(&self, token_id: &TokenId) -> Result<DiscoverySnapshot, DiscoveryError> {
        for attempt in 0..2 {
            let before = self.index.indexed_height();
            let (pools, token_decimals) = discover_once(self, token_id)?;
            let after = self.index.indexed_height();
            if before == after {
                return Ok(DiscoverySnapshot {
                    height: before,
                    pools,
                    token_decimals,
                });
            }
            if attempt == 1 {
                return Err(DiscoveryError::UnstableIndex);
            }
        }
        unreachable!("discovery performs exactly two attempts")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::decode::decoders::spectrum::SPECTRUM_N2T_V1_TEMPLATE_HASH_HEX;
    use ergo_indexer::IndexerHandle;
    use ergo_indexer_types::{
        BoxId, IndexedBoxDto, IndexedTokenDto, IndexerHaltReason, IndexerQuery, IndexerReadError,
        Page, SortDir, TemplateHash, TokenId,
    };
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::register::{write_registers, AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{CollValue, SigmaValue};
    use ergo_ser::token::Token;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // ----- helpers -----

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Read {
        Page(u32, u32, SortDir),
        Token(TokenId),
        Box(BoxId),
    }

    struct HeightScript {
        values: VecDeque<u64>,
        last: u64,
    }

    struct StubIndex {
        heights: Mutex<HeightScript>,
        height_samples: Mutex<Vec<u64>>,
        first_page: Result<Vec<IndexedBoxDto>, IndexerReadError>,
        full_candidate: Option<IndexedBoxDto>,
        probe_hit: bool,
        token: Result<Option<IndexedTokenDto>, IndexerReadError>,
        boxes: Vec<(BoxId, Result<Option<IndexedBoxDto>, IndexerReadError>)>,
        reads: Mutex<Vec<Read>>,
        hashes: Mutex<Vec<TemplateHash>>,
    }

    impl StubIndex {
        fn new(heights: impl IntoIterator<Item = u64>) -> Self {
            let values = heights.into_iter().collect::<VecDeque<_>>();
            let last = values.front().copied().unwrap_or(700_000);
            Self {
                heights: Mutex::new(HeightScript { values, last }),
                height_samples: Mutex::new(Vec::new()),
                first_page: Ok(Vec::new()),
                full_candidate: None,
                probe_hit: false,
                token: Ok(None),
                boxes: Vec::new(),
                reads: Mutex::new(Vec::new()),
                hashes: Mutex::new(Vec::new()),
            }
        }

        fn with_first_page(mut self, page: Vec<IndexedBoxDto>) -> Self {
            self.first_page = Ok(page);
            self
        }

        fn with_page_error(mut self, message: &str) -> Self {
            self.first_page = Err(IndexerReadError::new(message));
            self
        }

        fn with_full_pages(mut self, candidate: IndexedBoxDto, probe_hit: bool) -> Self {
            self.full_candidate = Some(candidate);
            self.probe_hit = probe_hit;
            self
        }

        fn with_token(mut self, token: Option<IndexedTokenDto>) -> Self {
            self.token = Ok(token);
            self
        }

        fn with_token_error(mut self, message: &str) -> Self {
            self.token = Err(IndexerReadError::new(message));
            self
        }

        fn with_box(
            mut self,
            box_id: BoxId,
            result: Result<Option<IndexedBoxDto>, IndexerReadError>,
        ) -> Self {
            self.boxes.push((box_id, result));
            self
        }

        fn reads(&self) -> Vec<Read> {
            self.reads.lock().unwrap().clone()
        }

        fn height_samples(&self) -> Vec<u64> {
            self.height_samples.lock().unwrap().clone()
        }
    }

    impl PricingIndex for StubIndex {
        fn indexed_height(&self) -> u64 {
            let mut script = self.heights.lock().unwrap();
            let height = script.values.pop_front().unwrap_or(script.last);
            script.last = height;
            self.height_samples.lock().unwrap().push(height);
            height
        }

        fn template_unspent_paged(
            &self,
            hash: &TemplateHash,
            page: Page,
            dir: SortDir,
        ) -> Result<Vec<IndexedBoxDto>, IndexerReadError> {
            self.reads
                .lock()
                .unwrap()
                .push(Read::Page(page.offset, page.limit, dir));
            self.hashes.lock().unwrap().push(*hash);

            if let Some(candidate) = &self.full_candidate {
                if page.offset < 5_000 && page.limit == 100 {
                    return Ok(vec![candidate.clone(); 100]);
                }
                if page.offset == 5_000 && page.limit == 1 {
                    return Ok(self
                        .probe_hit
                        .then(|| candidate.clone())
                        .into_iter()
                        .collect());
                }
            }
            if page.offset == 0 && page.limit == 100 {
                return self.first_page.clone();
            }
            Ok(Vec::new())
        }

        fn token_by_id(&self, id: &TokenId) -> Result<Option<IndexedTokenDto>, IndexerReadError> {
            self.reads.lock().unwrap().push(Read::Token(*id));
            self.token.clone()
        }

        fn box_by_id(&self, id: &BoxId) -> Result<Option<IndexedBoxDto>, IndexerReadError> {
            self.reads.lock().unwrap().push(Read::Box(*id));
            self.boxes
                .iter()
                .find(|(box_id, _)| box_id == id)
                .map(|(_, result)| result.clone())
                .unwrap_or(Ok(None))
        }
    }

    fn fixture_tree_bytes() -> Vec<u8> {
        hex::decode(include_str!("../../../tests/fixtures/spectrum_n2t_v1_ergo_tree.hex").trim())
            .unwrap()
    }

    fn int_register(value: i32) -> RegisterValue {
        RegisterValue {
            tpe: SigmaType::SInt,
            value: SigmaValue::Int(value),
        }
    }

    fn bytes_register(value: &[u8]) -> RegisterValue {
        RegisterValue {
            tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
            value: SigmaValue::Coll(CollValue::Bytes(value.to_vec())),
        }
    }

    fn token(id: u8, amount: u64) -> Token {
        Token {
            token_id: TokenId::from_bytes([id; 32]),
            amount,
        }
    }

    fn indexed_box(
        transaction_byte: u8,
        value: u64,
        tokens: Vec<Token>,
        registers: Vec<RegisterValue>,
    ) -> IndexedBoxDto {
        let tree_bytes = fixture_tree_bytes();
        let mut tree_reader = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut tree_reader).unwrap();
        assert!(tree_reader.is_empty());
        let additional_registers = AdditionalRegisters { registers };
        let mut register_writer = VlqWriter::new();
        write_registers(&mut register_writer, &additional_registers).unwrap();
        let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
            value,
            ergo_tree,
            tree_bytes,
            700_000,
            tokens,
            additional_registers,
            register_writer.result(),
        );

        IndexedBoxDto {
            inclusion_height: 700_000,
            spending_tx_id: None,
            spending_height: None,
            spending_proof: None,
            box_data: ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes([transaction_byte; 32]),
                index: 0,
            },
            global_index: i64::from(transaction_byte),
        }
    }

    fn pool_box(token_y: u8, transaction_byte: u8) -> IndexedBoxDto {
        indexed_box(
            transaction_byte,
            60_000_000,
            vec![
                token(transaction_byte, 1),
                token(transaction_byte.wrapping_add(1), 1_000_000),
                token(token_y, 2_000_000),
            ],
            vec![int_register(997)],
        )
    }

    fn invalid_pool_box() -> IndexedBoxDto {
        indexed_box(
            20,
            60_000_000,
            vec![token(20, 1), token(21, 1_000_000)],
            vec![int_register(997)],
        )
    }

    fn mint_box(r6: Option<RegisterValue>) -> IndexedBoxDto {
        let registers = r6
            .map(|register| vec![int_register(0), int_register(0), register])
            .unwrap_or_default();
        indexed_box(90, 1_000_000, Vec::new(), registers)
    }

    fn token_dto(token_id: TokenId, creating_box_id: BoxId) -> IndexedTokenDto {
        IndexedTokenDto {
            token_id,
            creating_box_id,
            emission_amount: 1_000_000,
            name: String::new(),
            description: String::new(),
            decimals: 0,
        }
    }

    fn expected_cap_pages() -> Vec<(u32, u32, SortDir)> {
        (0..50)
            .map(|page| (page * 100, 100, SortDir::Asc))
            .chain(std::iter::once((5_000, 1, SortDir::Asc)))
            .collect()
    }

    fn page_reads(index: &StubIndex) -> Vec<(u32, u32, SortDir)> {
        index
            .reads()
            .into_iter()
            .filter_map(|read| match read {
                Read::Page(offset, limit, dir) => Some((offset, limit, dir)),
                Read::Token(_) | Read::Box(_) => None,
            })
            .collect()
    }

    fn read_error_message(error: DiscoveryError) -> String {
        match error {
            DiscoveryError::Read(error) => error.to_string(),
            other => panic!("expected read error, got {other:?}"),
        }
    }

    // ----- happy path -----

    #[test]
    fn pricing_index_adapter_forwards_fallible_reads() {
        fn assert_adapter<T: PricingIndex + ?Sized>() {}

        assert_adapter::<dyn IndexerQuery>();
        let index = IndexerHandle::halted(IndexerHaltReason::DbCorruption);
        let box_id = BoxId::from_bytes([1; 32]);
        let token_id = TokenId::from_bytes([2; 32]);
        let template_hash = TemplateHash::from_bytes([3; 32]);

        assert!(PricingIndex::box_by_id(&index, &box_id).is_err());
        assert!(PricingIndex::token_by_id(&index, &token_id).is_err());
        assert!(PricingIndex::template_unspent_paged(
            &index,
            &template_hash,
            Page {
                offset: 0,
                limit: 100,
            },
            SortDir::Asc,
        )
        .is_err());
    }

    #[test]
    fn ascending_scan_stops_after_short_page() {
        let index = StubIndex::new([700_000, 700_000]).with_first_page(vec![invalid_pool_box()]);
        let token_id = TokenId::from_bytes([3; 32]);

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap();

        assert!(snapshot.pools.is_empty());
        assert_eq!(page_reads(&index), vec![(0, 100, SortDir::Asc)]);
        let expected_hash = TemplateHash::from_bytes(
            hex::decode(SPECTRUM_N2T_V1_TEMPLATE_HASH_HEX)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(*index.hashes.lock().unwrap(), vec![expected_hash]);
    }

    #[test]
    fn strict_decoder_retains_only_requested_supported_pool() {
        let requested_id = TokenId::from_bytes([3; 32]);
        let requested = pool_box(3, 1);
        let expected_box_id = requested.box_data.box_id().unwrap();
        let index = StubIndex::new([700_000, 700_000]).with_first_page(vec![
            requested,
            pool_box(4, 5),
            invalid_pool_box(),
        ]);

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&requested_id)
            .unwrap();

        assert_eq!(snapshot.pools.len(), 1);
        assert_eq!(snapshot.pools[0].pool_box_id, expected_box_id);
        assert_eq!(snapshot.pools[0].token_y, requested_id);
    }

    #[test]
    fn five_thousand_candidates_probe_miss_is_complete() {
        let index = StubIndex::new([700_000, 700_000]).with_full_pages(invalid_pool_box(), false);
        let token_id = TokenId::from_bytes([3; 32]);

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap();

        assert!(snapshot.pools.is_empty());
        assert_eq!(page_reads(&index), expected_cap_pages());
    }

    #[test]
    fn no_supported_pool_skips_metadata_reads() {
        let index = StubIndex::new([700_000, 700_000])
            .with_first_page(vec![pool_box(4, 5)])
            .with_token_error("metadata must not be read");
        let token_id = TokenId::from_bytes([3; 32]);

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap();

        assert!(snapshot.pools.is_empty());
        assert_eq!(index.reads(), vec![Read::Page(0, 100, SortDir::Asc)]);
    }

    #[test]
    fn metadata_reads_token_then_creation_box() {
        let token_id = TokenId::from_bytes([3; 32]);
        let creation_box_id = BoxId::from_bytes([9; 32]);
        let index = StubIndex::new([700_000, 700_000])
            .with_first_page(vec![pool_box(3, 1)])
            .with_token(Some(token_dto(token_id, creation_box_id)))
            .with_box(
                creation_box_id,
                Ok(Some(mint_box(Some(bytes_register(b"6"))))),
            );

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap();

        assert_eq!(snapshot.token_decimals, Some(6));
        assert_eq!(
            index.reads(),
            vec![
                Read::Page(0, 100, SortDir::Asc),
                Read::Token(token_id),
                Read::Box(creation_box_id),
            ]
        );
    }

    #[test]
    fn missing_token_metadata_returns_unknown_decimals() {
        let token_id = TokenId::from_bytes([3; 32]);
        let index = StubIndex::new([700_000, 700_000]).with_first_page(vec![pool_box(3, 1)]);

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap();

        assert_eq!(snapshot.token_decimals, None);
        assert_eq!(
            index.reads(),
            vec![Read::Page(0, 100, SortDir::Asc), Read::Token(token_id)]
        );
    }

    #[test]
    fn missing_r6_returns_unknown_decimals() {
        let token_id = TokenId::from_bytes([3; 32]);
        let creation_box_id = BoxId::from_bytes([9; 32]);
        let index = StubIndex::new([700_000, 700_000])
            .with_first_page(vec![pool_box(3, 1)])
            .with_token(Some(token_dto(token_id, creation_box_id)))
            .with_box(creation_box_id, Ok(Some(mint_box(None))));

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap();

        assert_eq!(snapshot.token_decimals, None);
    }

    #[test]
    fn invalid_r6_returns_unknown_decimals() {
        let token_id = TokenId::from_bytes([3; 32]);
        let creation_box_id = BoxId::from_bytes([9; 32]);
        let index = StubIndex::new([700_000, 700_000])
            .with_first_page(vec![pool_box(3, 1)])
            .with_token(Some(token_dto(token_id, creation_box_id)))
            .with_box(
                creation_box_id,
                Ok(Some(mint_box(Some(bytes_register(b"nine"))))),
            );

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap();

        assert_eq!(snapshot.token_decimals, None);
    }

    #[test]
    fn moved_height_retries_complete_attempt() {
        let token_id = TokenId::from_bytes([3; 32]);
        let index = StubIndex::new([700_000, 700_001, 700_001, 700_001])
            .with_first_page(vec![pool_box(3, 1)]);

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap();

        assert_eq!(snapshot.height, 700_001);
        assert_eq!(
            index.height_samples(),
            vec![700_000, 700_001, 700_001, 700_001]
        );
        assert_eq!(
            page_reads(&index),
            vec![(0, 100, SortDir::Asc), (0, 100, SortDir::Asc)]
        );
        assert_eq!(
            index
                .reads()
                .into_iter()
                .filter(|read| matches!(read, Read::Token(_)))
                .count(),
            2
        );
    }

    #[test]
    fn stable_snapshot_uses_sampled_index_height() {
        let token_id = TokenId::from_bytes([3; 32]);
        let index = StubIndex::new([812_345, 812_345]);

        let snapshot = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap();

        assert_eq!(snapshot.height, 812_345);
    }

    // ----- round-trips -----

    // ----- error paths -----

    #[test]
    fn five_thousand_candidates_probe_hit_exceeds_limit() {
        let index = StubIndex::new([700_000]).with_full_pages(invalid_pool_box(), true);
        let token_id = TokenId::from_bytes([3; 32]);

        let result = IndexerPoolDiscovery::new(&index).discover(&token_id);

        assert_eq!(result, Err(DiscoveryError::LimitExceeded));
        assert_eq!(page_reads(&index), expected_cap_pages());
    }

    #[test]
    fn template_read_error_propagates() {
        let index = StubIndex::new([700_000]).with_page_error("template read failed");
        let token_id = TokenId::from_bytes([3; 32]);

        let error = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap_err();

        assert_eq!(read_error_message(error), "template read failed");
    }

    #[test]
    fn token_read_error_propagates() {
        let token_id = TokenId::from_bytes([3; 32]);
        let index = StubIndex::new([700_000])
            .with_first_page(vec![pool_box(3, 1)])
            .with_token_error("token read failed");

        let error = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap_err();

        assert_eq!(read_error_message(error), "token read failed");
    }

    #[test]
    fn creation_box_read_error_propagates() {
        let token_id = TokenId::from_bytes([3; 32]);
        let creation_box_id = BoxId::from_bytes([9; 32]);
        let index = StubIndex::new([700_000])
            .with_first_page(vec![pool_box(3, 1)])
            .with_token(Some(token_dto(token_id, creation_box_id)))
            .with_box(
                creation_box_id,
                Err(IndexerReadError::new("creation box read failed")),
            );

        let error = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap_err();

        assert_eq!(read_error_message(error), "creation box read failed");
    }

    #[test]
    fn missing_creation_box_error_names_token_and_box() {
        let token_id = TokenId::from_bytes([3; 32]);
        let creation_box_id = BoxId::from_bytes([9; 32]);
        let index = StubIndex::new([700_000])
            .with_first_page(vec![pool_box(3, 1)])
            .with_token(Some(token_dto(token_id, creation_box_id)));

        let error = IndexerPoolDiscovery::new(&index)
            .discover(&token_id)
            .unwrap_err();
        let message = read_error_message(error);

        assert!(message.contains(&hex::encode(token_id.as_bytes())));
        assert!(message.contains(&hex::encode(creation_box_id.as_bytes())));
    }

    #[test]
    fn second_height_movement_returns_unstable_index() {
        let token_id = TokenId::from_bytes([3; 32]);
        let index = StubIndex::new([700_000, 700_001, 700_002, 700_003]);

        let result = IndexerPoolDiscovery::new(&index).discover(&token_id);

        assert_eq!(result, Err(DiscoveryError::UnstableIndex));
        assert_eq!(
            index.height_samples(),
            vec![700_000, 700_001, 700_002, 700_003]
        );
    }

    // ----- oracle parity -----
}

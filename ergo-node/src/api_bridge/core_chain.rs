#![allow(clippy::result_large_err)]

use std::sync::Arc;

use ergo_api_core::chain::{
    ChainArchive, FullBlock, HeaderQuery, ProtocolHistory, SortOrder, Stored,
};
use ergo_api_core::error::{BackendFailure, ServiceError, ServiceResult};
use ergo_api_core::id::{HeaderId, ModifierId};
use ergo_api_core::page::{Cursor, Page, PageRequest, SnapshotRevision};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ad_proofs::read_ad_proofs;
use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::reader::ChainStoreReader;
use ergo_state::store::{CommittedSnapshot, StateError};

use super::compat::{parse_block_transactions, parse_extension, parse_header};
use super::scala_compat::ScalaCompatBridge;

fn read_error(operation: &'static str, error: impl std::fmt::Display) -> ServiceError {
    ServiceError::unavailable("chain_read_failed", "chain data is temporarily unavailable")
        .with_failure(BackendFailure::new(operation, error.to_string()))
}

fn parse_error(operation: &'static str, error: impl std::fmt::Display) -> ServiceError {
    ServiceError::unavailable(
        "chain_data_invalid",
        "stored chain data could not be decoded",
    )
    .with_failure(BackendFailure::new(operation, error.to_string()))
}

fn stored_bytes(bytes: Vec<u8>) -> Arc<[u8]> {
    Arc::from(bytes.into_boxed_slice())
}

fn expected_sections(header: &ergo_ser::header::Header, id: HeaderId) -> ExpectedSections {
    ExpectedSections::from_header(
        id.as_bytes(),
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    )
}

trait ChainSource {
    fn best_header_height(&self) -> Result<u32, StateError>;
    fn best_header_id(&self) -> Result<[u8; 32], StateError>;
    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError>;
    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError>;
    fn block_section(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError>;
}

impl ChainSource for CommittedSnapshot {
    fn best_header_height(&self) -> Result<u32, StateError> {
        Ok(CommittedSnapshot::best_header_height(self))
    }

    fn best_header_id(&self) -> Result<[u8; 32], StateError> {
        Ok(CommittedSnapshot::best_header_id(self))
    }

    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        CommittedSnapshot::header_id_at_height(self, height)
    }

    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::get_header_bytes(self, id)
    }

    fn block_section(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        CommittedSnapshot::block_section(self, id)
    }
}

impl ChainSource for ChainStoreReader {
    fn best_header_height(&self) -> Result<u32, StateError> {
        Ok(self
            .chain_state_meta()?
            .map(|meta| meta.best_header_height)
            .unwrap_or(0))
    }

    fn best_header_id(&self) -> Result<[u8; 32], StateError> {
        Ok(self
            .chain_state_meta()?
            .map(|meta| meta.best_header_id)
            .unwrap_or([0; 32]))
    }

    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        self.get_header_id_at_height(height)
    }

    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        self.get_header(id)
    }

    fn block_section(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        self.get_block_section(id)
    }
}

enum ChainReadSource {
    Committed(Box<CommittedSnapshot>),
    Reader(ChainStoreReader),
}

impl ChainSource for ChainReadSource {
    fn best_header_height(&self) -> Result<u32, StateError> {
        match self {
            Self::Committed(source) => ChainSource::best_header_height(source.as_ref()),
            Self::Reader(source) => ChainSource::best_header_height(source),
        }
    }

    fn best_header_id(&self) -> Result<[u8; 32], StateError> {
        match self {
            Self::Committed(source) => ChainSource::best_header_id(source.as_ref()),
            Self::Reader(source) => ChainSource::best_header_id(source),
        }
    }

    fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
        match self {
            Self::Committed(source) => ChainSource::header_id_at_height(source.as_ref(), height),
            Self::Reader(source) => ChainSource::header_id_at_height(source, height),
        }
    }

    fn get_header_bytes(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        match self {
            Self::Committed(source) => ChainSource::get_header_bytes(source.as_ref(), id),
            Self::Reader(source) => ChainSource::get_header_bytes(source, id),
        }
    }

    fn block_section(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        match self {
            Self::Committed(source) => ChainSource::block_section(source.as_ref(), id),
            Self::Reader(source) => ChainSource::block_section(source, id),
        }
    }
}

fn source_for(bridge: &ScalaCompatBridge) -> ServiceResult<ChainReadSource> {
    let reader = bridge.chain_store_reader().clone();
    match reader.committed_snapshot() {
        Ok(Some(snapshot)) => Ok(ChainReadSource::Committed(Box::new(snapshot))),
        Ok(None) => Ok(ChainReadSource::Reader(reader)),
        Err(_error) if bridge.state_type() == "digest" => Ok(ChainReadSource::Reader(reader)),
        Err(error) => Err(read_error("committed_snapshot", error)),
    }
}

fn source_error(operation: &'static str, error: StateError) -> ServiceError {
    read_error(operation, error)
}

fn revision_for(tip: [u8; 32]) -> SnapshotRevision {
    SnapshotRevision(u64::from_be_bytes(
        tip[..8].try_into().expect("fixed header id"),
    ))
}

fn decode_cursor(
    page: &PageRequest,
    tip: [u8; 32],
    order: SortOrder,
    from_bound: u32,
    to_bound: u32,
) -> ServiceResult<Option<u32>> {
    let Some(raw) = page.cursor() else {
        return Ok(None);
    };
    let parts = raw.as_str().split(':').collect::<Vec<_>>();
    if parts.len() != 6 || parts[0] != "v2" {
        return Err(ServiceError::validation(
            "invalid_cursor",
            "chain cursor is invalid",
        ));
    }
    let cursor_tip = hex::decode(parts[1])
        .map_err(|_| ServiceError::validation("invalid_cursor", "chain cursor is invalid"))?;
    let cursor_tip: [u8; 32] = cursor_tip
        .try_into()
        .map_err(|_| ServiceError::validation("invalid_cursor", "chain cursor is invalid"))?;
    let cursor_order = match parts[3] {
        "asc" => SortOrder::Ascending,
        "desc" => SortOrder::Descending,
        _ => {
            return Err(ServiceError::validation(
                "invalid_cursor",
                "chain cursor is invalid",
            ));
        }
    };
    let cursor_from = parts[4]
        .parse::<u32>()
        .map_err(|_| ServiceError::validation("invalid_cursor", "chain cursor is invalid"))?;
    let cursor_to = parts[5]
        .parse::<u32>()
        .map_err(|_| ServiceError::validation("invalid_cursor", "chain cursor is invalid"))?;
    if cursor_tip != tip
        || cursor_order != order
        || cursor_from != from_bound
        || cursor_to != to_bound
    {
        return Err(ServiceError::validation(
            "stale_cursor",
            "chain query or tip changed since this cursor was issued",
        ));
    }
    parts[2]
        .parse::<u32>()
        .map(Some)
        .map_err(|_| ServiceError::validation("invalid_cursor", "chain cursor is invalid"))
}

fn encode_cursor(
    tip: [u8; 32],
    height: u32,
    order: SortOrder,
    from_bound: u32,
    to_bound: u32,
) -> ServiceResult<Cursor> {
    let order = match order {
        SortOrder::Ascending => "asc",
        SortOrder::Descending => "desc",
    };
    Cursor::new(format!(
        "v2:{}:{height}:{order}:{from_bound}:{to_bound}",
        hex::encode(tip)
    ))
    .map_err(|_| ServiceError::internal("chain_cursor", "failed to encode cursor"))
}

fn query_bounds(query: HeaderQuery, tip_height: u32) -> (u32, u32) {
    let default_from = match query.order {
        SortOrder::Ascending => 0,
        SortOrder::Descending => tip_height,
    };
    (
        query.from_height.unwrap_or(default_from).min(tip_height),
        query.to_height.unwrap_or(tip_height).min(tip_height),
    )
}

fn canonical_header_ids<R: ChainSource>(
    source: &R,
    query: HeaderQuery,
    page: PageRequest,
) -> ServiceResult<Page<HeaderId>> {
    let tip = source
        .best_header_id()
        .map_err(|error| source_error("best_header_id", error))?;
    let tip_height = source
        .best_header_height()
        .map_err(|error| source_error("best_header_height", error))?;
    let (from_bound, end) = query_bounds(query, tip_height);
    let start = decode_cursor(&page, tip, query.order, from_bound, end)?.unwrap_or(from_bound);
    let revision = revision_for(tip);
    if (matches!(query.order, SortOrder::Ascending) && start > end)
        || (matches!(query.order, SortOrder::Descending) && start < end)
    {
        return Ok(Page::new(Vec::new(), None, None, Some(revision)));
    }

    let limit = page.limit() as usize;
    if limit > 1_000 {
        return Err(ServiceError::validation(
            "page_limit_exceeded",
            "chain page size exceeds the server limit",
        ));
    }
    let mut ids = Vec::with_capacity(limit);
    let mut height = start;
    let scan_budget = (limit.saturating_mul(4)).clamp(1_024, 8_192);
    let mut scanned = 0usize;
    loop {
        if scanned >= scan_budget {
            let next_cursor = Some(encode_cursor(tip, height, query.order, from_bound, end)?);
            return Ok(Page::new(ids, next_cursor, None, Some(revision)));
        }
        scanned += 1;
        if let Some(id) = source
            .header_id_at_height(height)
            .map_err(|error| source_error("header_id_at_height", error))?
        {
            ids.push(HeaderId::from_bytes(id));
            if ids.len() == limit {
                let next = match query.order {
                    SortOrder::Ascending if height < end => Some(height + 1),
                    SortOrder::Descending if height > end => Some(height - 1),
                    _ => None,
                };
                let next_cursor = next
                    .map(|value| encode_cursor(tip, value, query.order, from_bound, end))
                    .transpose()?;
                return Ok(Page::new(ids, next_cursor, None, Some(revision)));
            }
        }

        let next = match query.order {
            SortOrder::Ascending if height < end => Some(height + 1),
            SortOrder::Descending if height > end => Some(height - 1),
            _ => None,
        };
        let Some(next) = next else {
            break;
        };
        height = next;
    }
    Ok(Page::new(ids, None, None, Some(revision)))
}

fn stored_header<R: ChainSource>(
    source: &R,
    id: HeaderId,
) -> ServiceResult<Option<Stored<ergo_ser::header::Header>>> {
    let bytes = source
        .get_header_bytes(id.as_bytes())
        .map_err(|error| source_error("header", error))?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let header = parse_header(&bytes).map_err(|error| parse_error("header", error))?;
    Ok(Some(Stored::new(
        ModifierId::from_bytes(*id.as_bytes()),
        stored_bytes(bytes),
        header,
    )))
}

fn block_summary_from_source<R: ChainSource>(
    source: &R,
    id: HeaderId,
) -> ServiceResult<Option<ergo_api_core::chain::BlockSummary>> {
    let Some(header) = stored_header(source, id)? else {
        return Ok(None);
    };
    let sections = expected_sections(&header.value, id);
    let Some(transactions_bytes) = source
        .block_section(&sections.transactions_id)
        .map_err(|error| source_error("block_transactions", error))?
    else {
        return Ok(None);
    };
    let transactions = parse_block_transactions(&transactions_bytes)
        .map_err(|error| parse_error("block_transactions", error))?;
    let extension_size = source
        .block_section(&sections.extension_id)
        .map_err(|error| source_error("extension", error))?
        .map_or(0, |bytes| bytes.len() as u64);
    let ad_proofs_size = source
        .block_section(&sections.ad_proofs_id)
        .map_err(|error| source_error("ad_proofs", error))?
        .map_or(0, |bytes| bytes.len() as u64);
    Ok(Some(ergo_api_core::chain::BlockSummary {
        id,
        parent_id: HeaderId::from_bytes(*header.value.parent_id.as_bytes()),
        height: header.value.height,
        timestamp_unix_ms: header.value.timestamp,
        state_root: Some(header.value.state_root),
        transaction_count: transactions.transactions.len() as u32,
        size_bytes: header.bytes.len() as u64
            + transactions_bytes.len() as u64
            + extension_size
            + ad_proofs_size,
    }))
}

fn full_block_from_source<R: ChainSource>(
    source: &R,
    id: HeaderId,
) -> ServiceResult<Option<FullBlock>> {
    let Some(header) = stored_header(source, id)? else {
        return Ok(None);
    };
    let sections = expected_sections(&header.value, id);
    let Some(transactions_bytes) = source
        .block_section(&sections.transactions_id)
        .map_err(|error| source_error("block_transactions", error))?
    else {
        return Ok(None);
    };
    let Some(extension_bytes) = source
        .block_section(&sections.extension_id)
        .map_err(|error| source_error("extension", error))?
    else {
        return Ok(None);
    };
    let transactions = parse_block_transactions(&transactions_bytes)
        .map_err(|error| parse_error("block_transactions", error))?;
    let extension =
        parse_extension(&extension_bytes).map_err(|error| parse_error("extension", error))?;
    let ad_proofs_bytes = source
        .block_section(&sections.ad_proofs_id)
        .map_err(|error| source_error("ad_proofs", error))?;
    let ad_proofs_size = ad_proofs_bytes
        .as_ref()
        .map_or(0, |bytes| bytes.len() as u64);
    let ad_proofs = ad_proofs_bytes
        .map(|bytes| {
            let mut reader = VlqReader::new(&bytes);
            let value =
                read_ad_proofs(&mut reader).map_err(|error| parse_error("ad_proofs", error))?;
            Ok::<_, ServiceError>(Stored::new(
                ModifierId::from_bytes(sections.ad_proofs_id),
                stored_bytes(bytes),
                value,
            ))
        })
        .transpose()?;
    let size_bytes = header.bytes.len() as u64
        + transactions_bytes.len() as u64
        + extension_bytes.len() as u64
        + ad_proofs_size;
    Ok(Some(FullBlock {
        header,
        transactions: Stored::new(
            ModifierId::from_bytes(sections.transactions_id),
            stored_bytes(transactions_bytes),
            transactions,
        ),
        extension: Stored::new(
            ModifierId::from_bytes(sections.extension_id),
            stored_bytes(extension_bytes),
            extension,
        ),
        ad_proofs,
        size_bytes,
    }))
}

impl ChainArchive for ScalaCompatBridge {
    fn header_ids_at_height(&self, height: u32) -> ServiceResult<Vec<HeaderId>> {
        self.chain_store_reader()
            .header_ids_at_height_all(height)
            .map(|ids| ids.into_iter().map(HeaderId::from_bytes).collect())
            .map_err(|error| read_error("header_ids_at_height", error))
    }

    fn header_ids(&self, query: HeaderQuery, page: PageRequest) -> ServiceResult<Page<HeaderId>> {
        canonical_header_ids(&source_for(self)?, query, page)
    }

    fn headers(
        &self,
        query: HeaderQuery,
        page: PageRequest,
    ) -> ServiceResult<Page<Stored<ergo_ser::header::Header>>> {
        let source = source_for(self)?;
        let ids = canonical_header_ids(&source, query, page)?;
        let mut headers = Vec::with_capacity(ids.items.len());
        for id in ids.items {
            if let Some(header) = stored_header(&source, id)? {
                headers.push(header);
            }
        }
        Ok(Page::new(headers, ids.next_cursor, ids.total, ids.as_of))
    }

    fn protocol_parameter_history(&self) -> ServiceResult<ProtocolHistory> {
        let current_height = self.current_full_block_height();
        let rows = self
            .chain_store_reader()
            .voted_params_history()
            .map_err(|error| {
                ServiceError::unavailable(
                    "protocol_history_unavailable",
                    "protocol history is temporarily unavailable",
                )
                .with_failure(BackendFailure::new(
                    "voted_params_history",
                    error.to_string(),
                ))
            })?;
        Ok(super::scala_compat::build_protocol_history(
            &rows,
            self.voting_epoch_length(),
            current_height,
        ))
    }

    fn header_by_id(
        &self,
        id: HeaderId,
    ) -> ServiceResult<Option<Stored<ergo_ser::header::Header>>> {
        stored_header(&source_for(self)?, id)
    }

    fn block_transactions_by_id(
        &self,
        id: HeaderId,
    ) -> ServiceResult<Option<Stored<ergo_ser::block_transactions::BlockTransactions>>> {
        let source = source_for(self)?;
        let Some(header) = stored_header(&source, id)? else {
            return Ok(None);
        };
        let sections = expected_sections(&header.value, id);
        let bytes = source
            .block_section(&sections.transactions_id)
            .map_err(|error| source_error("block_transactions", error))?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let value = parse_block_transactions(&bytes)
            .map_err(|error| parse_error("block_transactions", error))?;
        Ok(Some(Stored::new(
            ModifierId::from_bytes(sections.transactions_id),
            stored_bytes(bytes),
            value,
        )))
    }

    fn full_block_by_id(&self, id: HeaderId) -> ServiceResult<Option<FullBlock>> {
        full_block_from_source(&source_for(self)?, id)
    }

    fn block_summary_by_id(
        &self,
        id: HeaderId,
    ) -> ServiceResult<Option<ergo_api_core::chain::BlockSummary>> {
        block_summary_from_source(&source_for(self)?, id)
    }

    fn full_blocks_by_ids(&self, ids: &[HeaderId]) -> ServiceResult<Page<FullBlock>> {
        if ids.len() > 256 {
            return Err(ServiceError::validation(
                "too_many_ids",
                "at most 256 block ids can be requested",
            ));
        }
        let source = source_for(self)?;
        let mut blocks = Vec::new();
        for id in ids {
            if let Some(block) = full_block_from_source(&source, *id)? {
                blocks.push(block);
            }
        }
        Ok(Page::new(blocks, None, None, None))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct TestSource {
        tip: [u8; 32],
        height: u32,
        ids: HashMap<u32, [u8; 32]>,
    }

    impl ChainSource for TestSource {
        fn best_header_height(&self) -> Result<u32, StateError> {
            Ok(self.height)
        }

        fn best_header_id(&self) -> Result<[u8; 32], StateError> {
            Ok(self.tip)
        }

        fn header_id_at_height(&self, height: u32) -> Result<Option<[u8; 32]>, StateError> {
            Ok(self.ids.get(&height).copied())
        }

        fn get_header_bytes(&self, _id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(None)
        }

        fn block_section(&self, _id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(None)
        }
    }

    fn source() -> TestSource {
        let mut ids = HashMap::new();
        for height in 0..=3 {
            ids.insert(height, [height as u8; 32]);
        }
        TestSource {
            tip: [9; 32],
            height: 3,
            ids,
        }
    }

    #[test]
    fn canonical_pages_use_a_stable_height_cursor() {
        let source = source();
        let first = canonical_header_ids(
            &source,
            HeaderQuery {
                from_height: None,
                to_height: None,
                order: SortOrder::Ascending,
            },
            PageRequest::new(2, None).unwrap(),
        )
        .unwrap();
        assert_eq!(first.items.len(), 2);
        let cursor = first.next_cursor.unwrap();
        let second = canonical_header_ids(
            &source,
            HeaderQuery {
                from_height: None,
                to_height: None,
                order: SortOrder::Ascending,
            },
            PageRequest::new(2, Some(cursor)).unwrap(),
        )
        .unwrap();
        assert_eq!(second.items.len(), 2);
        assert!(second.next_cursor.is_none());
        assert!(second.as_of.is_some());
    }

    #[test]
    fn canonical_cursor_rejects_a_different_tip() {
        let mut source = source();
        let page = canonical_header_ids(
            &source,
            HeaderQuery {
                from_height: None,
                to_height: Some(2),
                order: SortOrder::Descending,
            },
            PageRequest::new(1, None).unwrap(),
        )
        .unwrap();
        let cursor = page.next_cursor.unwrap();
        source.tip = [10; 32];
        let error = canonical_header_ids(
            &source,
            HeaderQuery {
                from_height: None,
                to_height: Some(2),
                order: SortOrder::Descending,
            },
            PageRequest::new(1, Some(cursor)).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "stale_cursor");
    }
}

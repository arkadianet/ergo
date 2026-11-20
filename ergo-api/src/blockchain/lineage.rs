//! Opt-in, template-scoped box lineage (`GET /blockchain/box/lineage/{seedBoxId}`).
//!
//! Walks `spendingTransactionId` forward from a known seed box and returns only
//! successors whose **full serialized ergoTree hash** matches `script` (plus
//! optional token-id / R6-index filters). The hash is the same value Scala calls
//! `hashErgoTree` (`Algos.hash(tree.bytes)`), deliberately *not* the
//! constants-stripped `hashTreeTemplate` used by `/box/byTemplateHash`: with the
//! latter, every P2PK box shares a hash and a token-holder graph becomes
//! enumerable.
//!
//! No new storage: each hop is three reads against the existing extra index
//! (spent box row → spending tx row → that tx's contiguous output range).

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ergo_indexer_types::types::{IndexedErgoBox, IndexedErgoTransaction};
use ergo_indexer_types::{BoxId, IndexerQuery, IndexerReadError, TxId};
use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_tree::tree_hash_from_bytes;
use ergo_ser::register::split_register_bytes;
use serde::{Deserialize, Serialize};

use super::{build_indexed_box_response, parse_modifier_id, BlockchainState};

/// Minimum/maximum page size and uncompressed response budget.
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES_WITH_TXS: usize = 4 * 1024 * 1024;
/// Independent traversal budget so filters that suppress every item (e.g. an
/// unreachable `fromHeight`) cannot turn one request into a full-chain walk.
const MAX_HOPS_PER_PAGE: usize = 4096;

/// The narrow slice of `IndexerQuery` this route needs. Kept separate so the
/// walk can be unit-tested without standing up a redb store.
trait LineageStore {
    fn box_by_id(&self, id: &BoxId) -> Result<Option<IndexedErgoBox>, IndexerReadError>;
    fn box_by_global_index(&self, n: u64) -> Result<Option<IndexedErgoBox>, IndexerReadError>;
    fn tx_by_id(&self, id: &TxId) -> Result<Option<IndexedErgoTransaction>, IndexerReadError>;
    fn boxes_by_global_range(
        &self,
        lo: u64,
        hi: u64,
    ) -> Result<Vec<IndexedErgoBox>, IndexerReadError>;
}

impl LineageStore for dyn IndexerQuery {
    fn box_by_id(&self, id: &BoxId) -> Result<Option<IndexedErgoBox>, IndexerReadError> {
        IndexerQuery::box_by_id(self, id)
    }
    fn box_by_global_index(&self, n: u64) -> Result<Option<IndexedErgoBox>, IndexerReadError> {
        IndexerQuery::box_by_global_index(self, n)
    }
    fn tx_by_id(&self, id: &TxId) -> Result<Option<IndexedErgoTransaction>, IndexerReadError> {
        IndexerQuery::tx_by_id(self, id)
    }
    fn boxes_by_global_range(
        &self,
        lo: u64,
        hi: u64,
    ) -> Result<Vec<IndexedErgoBox>, IndexerReadError> {
        IndexerQuery::boxes_by_global_range(self, lo, hi)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LineageQuery {
    script: String,
    #[serde(default)]
    token_id: Option<String>,
    #[serde(default)]
    index: Option<i32>,
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    from_height: Option<i32>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    include_txs: Option<u8>,
}

#[derive(Debug, Clone)]
struct Filters {
    script: [u8; 32],
    token_id: Option<[u8; 32]>,
    index: Option<i32>,
    from_height: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Termination {
    Limit,
    Unspent,
    NoSuccessor,
    Tip,
}

impl Termination {
    fn as_str(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Unspent => "unspent",
            Self::NoSuccessor => "no-successor",
            Self::Tip => "tip",
        }
    }
}

/// One lineage item: the canonical indexed-box JSON, plus the optional
/// spending transaction projection. `flatten` keeps every existing box field
/// at the top level so clients can reuse their `/box/byId` parser unchanged.
#[derive(Debug, Serialize)]
struct LineageItem {
    #[serde(flatten)]
    box_data: super::IndexedErgoBoxResponse,
    #[serde(rename = "spendingTx", skip_serializing_if = "Option::is_none")]
    spending_tx: Option<SpendingTxEntry>,
}

#[derive(Debug, Serialize)]
pub(crate) struct LineageResponse {
    items: Vec<LineageItem>,
    count: usize,
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    #[serde(rename = "seedBoxId")]
    seed_box_id: String,
    script: String,
    #[serde(rename = "indexedHeight")]
    indexed_height: u64,
    terminated: &'static str,
}

#[derive(Debug, Serialize)]
struct SpendingInputEntry {
    #[serde(rename = "boxId")]
    box_id: String,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    value: u64,
    #[serde(rename = "additionalRegisters")]
    additional_registers: BTreeMap<String, String>,
    extension: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct SpendingTxEntry {
    id: String,
    inputs: Vec<SpendingInputEntry>,
}

#[derive(Debug)]
enum LineageError {
    BadQuery(&'static str),
    SeedNotFound,
    StaleCursor,
    Read(String),
}

fn error_response(status: StatusCode, reason: &'static str, detail: &str) -> Response {
    let body = serde_json::json!({
        "error": status.as_u16(),
        "reason": reason,
        "detail": detail,
    });
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}

impl From<LineageError> for Response {
    fn from(error: LineageError) -> Self {
        match error {
            LineageError::BadQuery(detail) => {
                error_response(StatusCode::BAD_REQUEST, "bad-request", detail)
            }
            LineageError::SeedNotFound => {
                super::not_found("no indexed box found with that seed id")
            }
            LineageError::StaleCursor => error_response(
                StatusCode::BAD_REQUEST,
                "stale-cursor",
                "cursor box is unknown or pruned; restart from the seed",
            ),
            LineageError::Read(detail) => super::internal_error(&detail),
        }
    }
}

/// `GET /blockchain/box/lineage/{seedBoxId}`.
pub async fn box_lineage_handler(
    State(state): State<BlockchainState>,
    Path(seed_hex): Path<String>,
    Query(q): Query<LineageQuery>,
) -> Response {
    let result = run(&state, &seed_hex, &q);
    match result {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into(),
    }
}

fn run(
    state: &BlockchainState,
    seed_hex: &str,
    q: &LineageQuery,
) -> Result<LineageResponse, LineageError> {
    let seed = parse_box_id(seed_hex)?;
    match state.indexer.box_by_id(&seed) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(LineageError::SeedNotFound),
        Err(error) => return Err(LineageError::Read(format!("indexer read failed: {error}"))),
    }
    let script = parse_digest(&q.script)?;
    let token_id = q.token_id.as_deref().map(parse_digest).transpose()?;

    let filters = Filters {
        script,
        token_id,
        index: q.index,
        from_height: q.from_height,
    };
    let tag = query_tag(&seed, &filters);
    let after = match q.after.as_deref() {
        Some(raw) => Some(decode_cursor(raw, &tag)?),
        None => None,
    };
    if let Some(id) = after {
        match state.indexer.box_by_id(&id) {
            Ok(Some(_)) => {}
            Ok(None) => return Err(LineageError::StaleCursor),
            Err(error) => return Err(LineageError::Read(format!("indexer read failed: {error}"))),
        }
    }
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let include_txs = q.include_txs.unwrap_or(0) == 1;
    if include_txs && !state.indexer.lineage_include_txs() {
        return Err(LineageError::BadQuery(
            "includeTxs is disabled on this node",
        ));
    }

    let max_bytes = if include_txs {
        MAX_RESPONSE_BYTES_WITH_TXS
    } else {
        MAX_RESPONSE_BYTES
    };
    let (items, cursor_box, termination) = walk(
        state.indexer.as_ref(),
        state.network,
        WalkParams {
            seed,
            after,
            filters,
            limit,
            max_bytes,
            include_txs,
            max_hops: MAX_HOPS_PER_PAGE,
        },
    )?;

    let next_cursor = if termination == Termination::Limit {
        cursor_box.map(|id| encode_cursor(&id, &tag))
    } else {
        None
    };

    Ok(LineageResponse {
        count: items.len(),
        items,
        next_cursor,
        seed_box_id: hex::encode(seed.as_bytes()),
        script: hex::encode(script),
        indexed_height: state.indexer.indexed_height(),
        terminated: termination.as_str(),
    })
}

/// Follow the spend chain. `after` is included in the traversal for its
/// spending pointer but is never emitted; the first emitted box is its
/// successor (or the seed when `after` is absent).
#[derive(Debug, Clone)]
struct WalkParams {
    seed: BoxId,
    after: Option<BoxId>,
    filters: Filters,
    limit: usize,
    max_bytes: usize,
    include_txs: bool,
    max_hops: usize,
}

fn walk<S: LineageStore + ?Sized>(
    store: &S,
    network: ergo_ser::address::NetworkPrefix,
    params: WalkParams,
) -> Result<(Vec<LineageItem>, Option<BoxId>, Termination), LineageError> {
    let WalkParams {
        seed,
        after,
        filters,
        limit,
        max_bytes,
        include_txs,
        max_hops,
    } = params;
    let mut current = seed;
    let mut skip_current = false;
    if let Some(after_id) = after {
        // The `after` box supplies the spend pointer for the next hop but is
        // itself excluded; its successor is the first emitted item.
        current = after_id;
        skip_current = true;
    }

    let mut items = Vec::with_capacity(limit.min(1024));
    let mut bytes = 0usize;
    let mut last_emitted = None;
    let mut hops = 0usize;
    let termination;

    loop {
        hops += 1;
        let box_row = match store
            .box_by_id(&current)
            .map_err(|e| LineageError::Read(format!("indexer read failed: {e}")))?
        {
            Some(row) => row,
            None => {
                termination = Termination::Tip;
                break;
            }
        };

        if !skip_current && height_ok(&box_row, &filters) {
            let rendered =
                build_indexed_box_response(network, &box_row).map_err(LineageError::Read)?;
            let spending_tx = if include_txs {
                spending_tx_for(store, network, &box_row)?
            } else {
                None
            };
            let item = LineageItem {
                box_data: rendered,
                spending_tx,
            };
            bytes += serde_json::to_vec(&item)
                .map(|v| v.len())
                .unwrap_or(usize::MAX);
            if !items.is_empty() && bytes > max_bytes {
                termination = Termination::Limit;
                break;
            }
            items.push(item);
            last_emitted = Some(current);
        }
        skip_current = false;

        if items.len() >= limit {
            termination = Termination::Limit;
            break;
        }
        // Bound work even when filters suppressed every item: a continuation
        // is returned from the last visited box so the client can resume.
        if hops >= max_hops {
            termination = Termination::Limit;
            break;
        }

        let Some(tx_id) = box_row.spending_tx_id else {
            termination = Termination::Unspent;
            break;
        };
        match successor(store, &tx_id, &filters)? {
            Some(next) => current = next,
            None => {
                termination = Termination::NoSuccessor;
                break;
            }
        }
    }

    let cursor_box = if termination == Termination::Limit {
        last_emitted.or(Some(current))
    } else {
        None
    };
    Ok((items, cursor_box, termination))
}

/// Find the deterministic successor of a spent box: the lowest-index output of
/// the spending transaction that satisfies all filters.
fn successor<S: LineageStore + ?Sized>(
    store: &S,
    tx_id: &TxId,
    filters: &Filters,
) -> Result<Option<BoxId>, LineageError> {
    let tx = match store
        .tx_by_id(tx_id)
        .map_err(|e| LineageError::Read(format!("indexer read failed: {e}")))?
    {
        Some(tx) => tx,
        None => return Ok(None),
    };
    if tx.output_nums.is_empty() {
        return Ok(None);
    }
    let lo = *tx.output_nums.first().unwrap() as u64;
    let hi = *tx.output_nums.last().unwrap() as u64 + 1;
    let outputs = store
        .boxes_by_global_range(lo, hi)
        .map_err(|e| LineageError::Read(format!("indexer read failed: {e}")))?;
    Ok(outputs
        .into_iter()
        .find(|box_row| matches_filters(box_row, filters))
        .and_then(|box_row| box_row.box_data.box_id().ok()))
}

fn matches_filters(box_row: &IndexedErgoBox, filters: &Filters) -> bool {
    let candidate = &box_row.box_data.candidate;
    match tree_hash_from_bytes(candidate.ergo_tree_bytes()) {
        Ok(hash) if hash == filters.script => {}
        _ => return false,
    }
    if let Some(token) = filters.token_id {
        let found = candidate
            .tokens
            .iter()
            .any(|t| t.token_id.as_bytes().as_slice() == token.as_slice());
        if !found {
            return false;
        }
    }
    if let Some(expected) = filters.index {
        if r6_int(box_row) != Some(expected) {
            return false;
        }
    }
    true
}

fn height_ok(box_row: &IndexedErgoBox, filters: &Filters) -> bool {
    match filters.from_height {
        Some(min) => box_row.box_data.candidate.creation_height as i32 >= min,
        None => true,
    }
}

/// Decode R6 as a plain SInt constant (type byte `0x04` + zigzag VLQ i32).
/// Expression-form registers do not match — they are not shard indices.
fn r6_int(box_row: &IndexedErgoBox) -> Option<i32> {
    let slices = split_register_bytes(box_row.box_data.candidate.register_bytes()).ok()?;
    let r6 = slices.get(2)?;
    if r6.first() != Some(&0x04) {
        return None;
    }
    VlqReader::new(&r6[1..]).get_i32().ok()
}

fn spending_tx_for<S: LineageStore + ?Sized>(
    store: &S,
    network: ergo_ser::address::NetworkPrefix,
    box_row: &IndexedErgoBox,
) -> Result<Option<SpendingTxEntry>, LineageError> {
    let Some(tx_id) = box_row.spending_tx_id else {
        return Ok(None);
    };
    let tx = match store
        .tx_by_id(&tx_id)
        .map_err(|e| LineageError::Read(format!("indexer read failed: {e}")))?
    {
        Some(tx) => tx,
        None => return Ok(None),
    };
    let mut inputs = Vec::with_capacity(tx.input_nums.len());
    for n in &tx.input_nums {
        if *n < 0 {
            continue;
        }
        let Some(input_box) = store
            .box_by_global_index(*n as u64)
            .map_err(|e| LineageError::Read(format!("indexer read failed: {e}")))?
        else {
            continue;
        };
        let rendered =
            build_indexed_box_response(network, &input_box).map_err(LineageError::Read)?;
        inputs.push(SpendingInputEntry {
            box_id: rendered.box_id,
            ergo_tree: rendered.ergo_tree,
            value: rendered.value,
            additional_registers: rendered.additional_registers,
            extension: rendered
                .spending_proof
                .map(|proof| proof.extension)
                .unwrap_or_default(),
        });
    }
    Ok(Some(SpendingTxEntry {
        id: hex::encode(tx_id.as_bytes()),
        inputs,
    }))
}

fn parse_box_id(hex_str: &str) -> Result<BoxId, LineageError> {
    let raw = parse_modifier_id(hex_str).ok_or(LineageError::BadQuery(
        "seedBoxId must be 64 lowercase hex chars",
    ))?;
    Ok(BoxId::from_bytes(raw))
}

fn parse_digest(hex_str: &str) -> Result<[u8; 32], LineageError> {
    parse_modifier_id(hex_str).ok_or(LineageError::BadQuery(
        "parameter must be 64 lowercase hex chars",
    ))
}

/// Short binding tag so a cursor cannot be replayed under different filters.
fn query_tag(seed: &BoxId, filters: &Filters) -> String {
    let mut key = Vec::new();
    key.extend_from_slice(seed.as_bytes());
    key.extend_from_slice(&filters.script);
    if let Some(token) = filters.token_id {
        key.extend_from_slice(&token);
    } else {
        key.extend_from_slice(&[0u8; 32]);
    }
    key.extend_from_slice(&filters.index.unwrap_or(i32::MIN).to_be_bytes());
    key.extend_from_slice(&filters.from_height.unwrap_or(-1).to_be_bytes());
    hex::encode(&blake2b256(&key).as_bytes()[..8])
}

fn encode_cursor(box_id: &BoxId, tag: &str) -> String {
    let raw = format!("v1:{tag}:{}", hex::encode(box_id.as_bytes()));
    URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

fn decode_cursor(raw: &str, tag: &str) -> Result<BoxId, LineageError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| LineageError::BadQuery("malformed cursor"))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| LineageError::BadQuery("malformed cursor"))?;
    let mut parts = text.split(':');
    if parts.next() != Some("v1") || parts.next() != Some(tag) {
        return Err(LineageError::BadQuery(
            "cursor does not match the requested seed or filters",
        ));
    }
    let id_hex = parts
        .next()
        .ok_or(LineageError::BadQuery("malformed cursor"))?;
    if parts.next().is_some() {
        return Err(LineageError::BadQuery("malformed cursor"));
    }
    parse_box_id(id_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::address::NetworkPrefix;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
    use std::collections::HashMap;

    fn filters(
        script: u8,
        token: Option<u8>,
        index: Option<i32>,
        from_height: Option<i32>,
    ) -> Filters {
        Filters {
            script: [script; 32],
            token_id: token.map(|b| [b; 32]),
            index,
            from_height,
        }
    }

    #[test]
    fn cursor_binds_seed_filters_and_roundtrips() {
        let seed = BoxId::from_bytes([6u8; 32]);
        let f = filters(1, Some(2), Some(3), Some(100));
        let tag = query_tag(&seed, &f);
        let id = BoxId::from_bytes([7u8; 32]);
        let encoded = encode_cursor(&id, &tag);
        assert_eq!(decode_cursor(&encoded, &tag).unwrap(), id);

        let other = filters(1, Some(2), Some(4), Some(100));
        assert!(decode_cursor(&encoded, &query_tag(&seed, &other)).is_err());
        let other_seed = BoxId::from_bytes([8u8; 32]);
        assert!(decode_cursor(&encoded, &query_tag(&other_seed, &f)).is_err());
        assert!(decode_cursor("not-base64!!", &tag).is_err());
    }

    #[test]
    fn query_params_use_documented_camel_case_names() {
        let q: LineageQuery = serde_json::from_str(
            r#"{"script":"aa","tokenId":"bb","fromHeight":12,"includeTxs":1,"limit":5}"#,
        )
        .unwrap();
        assert_eq!(q.script, "aa");
        assert_eq!(q.token_id.as_deref(), Some("bb"));
        assert_eq!(q.from_height, Some(12));
        assert_eq!(q.include_txs, Some(1));
        assert_eq!(q.limit, Some(5));
        assert_eq!(q.index, None);
        assert_eq!(q.after, None);
    }

    #[test]
    fn r6_int_decodes_plain_sint_constant() {
        // R4 boolean, R5 byte, R6 Int(42) — zigzag(42) = 84 = 0x54.
        let registers = vec![3u8, 0x01, 0x01, 0x02, 0x05, 0x04, 0x54];
        let slices = split_register_bytes(&registers).unwrap();
        assert_eq!(slices.len(), 3);
        assert_eq!(slices[2][0], 0x04);
        assert_eq!(VlqReader::new(&slices[2][1..]).get_i32().unwrap(), 42);
    }

    #[test]
    fn query_tag_changes_with_seed_and_every_filter() {
        let seed = BoxId::from_bytes([6u8; 32]);
        let base = query_tag(&seed, &filters(1, None, None, None));
        assert_ne!(base, query_tag(&seed, &filters(2, None, None, None)));
        assert_ne!(base, query_tag(&seed, &filters(1, Some(9), None, None)));
        assert_ne!(base, query_tag(&seed, &filters(1, None, Some(1), None)));
        assert_ne!(base, query_tag(&seed, &filters(1, None, None, Some(1))));
        assert_ne!(
            base,
            query_tag(&BoxId::from_bytes([9u8; 32]), &filters(1, None, None, None))
        );
    }

    #[derive(Default)]
    struct FakeStore {
        boxes: HashMap<u64, IndexedErgoBox>,
        txs: HashMap<[u8; 32], IndexedErgoTransaction>,
    }

    impl FakeStore {
        fn put(&mut self, box_row: IndexedErgoBox) -> u64 {
            let n = box_row.global_index as u64;
            self.boxes.insert(n, box_row);
            n
        }
    }

    impl LineageStore for FakeStore {
        fn box_by_id(&self, id: &BoxId) -> Result<Option<IndexedErgoBox>, IndexerReadError> {
            Ok(self
                .boxes
                .values()
                .find(|b| {
                    b.box_data
                        .box_id()
                        .map(|computed| computed == *id)
                        .unwrap_or(false)
                })
                .cloned())
        }
        fn box_by_global_index(&self, n: u64) -> Result<Option<IndexedErgoBox>, IndexerReadError> {
            Ok(self.boxes.get(&n).cloned())
        }
        fn tx_by_id(&self, id: &TxId) -> Result<Option<IndexedErgoTransaction>, IndexerReadError> {
            Ok(self.txs.get(id.as_bytes()).cloned())
        }
        fn boxes_by_global_range(
            &self,
            lo: u64,
            hi: u64,
        ) -> Result<Vec<IndexedErgoBox>, IndexerReadError> {
            Ok((lo..hi)
                .filter_map(|n| self.boxes.get(&n).cloned())
                .collect())
        }
    }

    fn tree(pubkey_tag: u8) -> ErgoTree {
        let mut pubkey = [pubkey_tag; 33];
        pubkey[0] = 0x02;
        ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            reserved_header_bits: 0,
            constants: Vec::new(),
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(
                    pubkey,
                ))),
            },
        }
    }

    fn box_row(tree: &ErgoTree, height: u32, n: i64, spent_by: Option<TxId>) -> IndexedErgoBox {
        let candidate = ErgoBoxCandidate::new(
            1_000_000,
            tree.clone(),
            height,
            Vec::new(),
            AdditionalRegisters::empty(),
        )
        .expect("candidate");
        IndexedErgoBox {
            inclusion_height: height as i32,
            spending_tx_id: spent_by,
            spending_height: None,
            spending_proof: None,
            box_data: ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes([n as u8; 32]),
                index: 0,
            },
            global_index: n,
        }
    }

    fn tx(id_byte: u8, outs: &[u64]) -> (TxId, IndexedErgoTransaction) {
        let id = TxId::from_bytes([id_byte; 32]);
        let record = IndexedErgoTransaction {
            id,
            index_in_block: 0,
            height: 1,
            size: 100,
            global_index: id_byte as i64,
            input_nums: Vec::new(),
            output_nums: outs.iter().map(|n| *n as i64).collect(),
            data_inputs: Vec::new(),
        };
        (id, record)
    }

    #[test]
    fn walk_filters_successors_and_breaks_ties_by_output_index() {
        let good = tree(0x11);
        let other = tree(0x22);
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &good).unwrap();
        let script = tree_hash_from_bytes(&w.result()).unwrap();

        let (tx1, rec1) = tx(1, &[1, 2]);
        let (tx2, rec2) = tx(2, &[3]);
        let mut store = FakeStore::default();
        let a = store.put(box_row(&good, 100, 0, Some(tx1)));
        let _b = store.put(box_row(&good, 101, 1, Some(tx2)));
        store.put(box_row(&other, 101, 2, None)); // wrong script, same tx
        store.put(box_row(&good, 102, 3, None)); // final box
        store.txs.insert(*tx1.as_bytes(), rec1);
        store.txs.insert(*tx2.as_bytes(), rec2);

        let f = Filters {
            script,
            token_id: None,
            index: None,
            from_height: None,
        };
        let seed = store.boxes[&a].box_data.box_id().unwrap();
        let params = WalkParams {
            seed,
            after: None,
            filters: f.clone(),
            limit: 10,
            max_bytes: MAX_RESPONSE_BYTES,
            include_txs: false,
            max_hops: MAX_HOPS_PER_PAGE,
        };
        let (items, last, termination) = walk(&store, NetworkPrefix::Mainnet, params).unwrap();
        assert_eq!(
            items.len(),
            3,
            "A -> B -> final, skipping the wrong-script output"
        );
        assert_eq!(termination, Termination::Unspent);
        assert_eq!(last, None, "no continuation after normal termination");

        let params = WalkParams {
            seed,
            after: Some(seed),
            filters: f,
            limit: 10,
            max_bytes: MAX_RESPONSE_BYTES,
            include_txs: false,
            max_hops: MAX_HOPS_PER_PAGE,
        };
        let (items, _, _) = walk(&store, NetworkPrefix::Mainnet, params).unwrap();
        assert_eq!(items.len(), 2, "after=seed must not emit the seed again");
    }

    #[test]
    fn hop_budget_stops_a_fully_suppressed_walk_and_returns_a_cursor() {
        let good = tree(0x11);
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &good).unwrap();
        let f = Filters {
            script: tree_hash_from_bytes(&w.result()).unwrap(),
            token_id: None,
            index: None,
            from_height: Some(i32::MAX), // suppress every item
        };
        let (tx1, rec1) = tx(1, &[1, 2]);
        let (tx2, rec2) = tx(2, &[3]);
        let mut store = FakeStore::default();
        let a = store.put(box_row(&good, 100, 0, Some(tx1)));
        store.put(box_row(&good, 101, 1, Some(tx2)));
        store.put(box_row(&good, 102, 3, None));
        store.txs.insert(*tx1.as_bytes(), rec1);
        store.txs.insert(*tx2.as_bytes(), rec2);
        let seed = store.boxes[&a].box_data.box_id().unwrap();

        let params = WalkParams {
            seed,
            after: None,
            filters: f.clone(),
            limit: 1,
            max_bytes: MAX_RESPONSE_BYTES,
            include_txs: false,
            max_hops: 2,
        };
        let (items, cursor, termination) = walk(&store, NetworkPrefix::Mainnet, params).unwrap();
        assert!(items.is_empty());
        assert_eq!(termination, Termination::Limit);
        let first_cursor = cursor.expect("a suppressed page must still advance");
        assert_eq!(first_cursor, store.boxes[&1].box_data.box_id().unwrap());

        let params = WalkParams {
            seed,
            after: Some(first_cursor),
            filters: f,
            limit: 1,
            max_bytes: MAX_RESPONSE_BYTES,
            include_txs: false,
            max_hops: 2,
        };
        let (items, cursor, termination) = walk(&store, NetworkPrefix::Mainnet, params).unwrap();
        assert!(items.is_empty());
        assert_eq!(termination, Termination::Limit);
        assert_eq!(cursor, Some(store.boxes[&3].box_data.box_id().unwrap()));
    }
}

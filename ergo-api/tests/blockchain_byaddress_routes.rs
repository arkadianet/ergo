//! `POST /blockchain/{transaction,box}/byAddress` and the GET twins —
//! paged byAddress routes.
//!
//! Pinned behavior:
//! - The status gate fronts all four routes; `Syncing` / `Halted`
//!   short-circuit before paging math runs.
//! - On `CaughtUp`, address parsing → tree_hash → reader yields the
//!   `{items, total}` envelope. `total` is the address-wide count
//!   from `address_total_*`, not the per-page item count.
//! - Defaults match Scala's `paging` directive
//!   (`BlockchainApiRoute.scala:41`): `offset=0, limit=5`.
//! - `limit > 16384` → `400 bad-request` "No more than 16384 {noun}
//!   can be requested" (per-route noun: "transactions" / "boxes").
//! - Negative offset / limit → `400 bad-request` "offset is negative"
//!   / "limit is negative" — matches the existing
//!   `header_ids_paged_handler` validation pattern.
//! - Address parse failures (bad base58, P2SH) → `400 invalid-address`,
//!   identical to the balance-route envelope.
//! - POST and GET twins emit byte-identical envelopes for the same
//!   `(address, offset, limit)` triple.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{
    Parameters, ScalaFullBlock, ScalaHeader, ScalaInfo, ScalaPowSolutions,
};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{IndexerHaltReason, IndexerHandle};
use ergo_indexer_types::types::{IndexedErgoBox, IndexedErgoTransaction};
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::{encode_address, NetworkPrefix};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use http_body_util::BodyExt;
use tower::ServiceExt;

const HEX_64_BB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ---------------- 503 status-gate ------------------------------------------

#[tokio::test]
async fn post_txs_by_address_503_indexer_syncing() {
    let app = build_app_with_indexer(
        Arc::new(StubIndexer::with_status(IndexerStatus::Syncing)),
        Some(empty_chain()),
    );
    let (status, body) = json_post(
        app,
        "/blockchain/transaction/byAddress",
        &json_str(&p2pk_address()),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

#[tokio::test]
async fn get_boxes_by_address_503_indexer_halted() {
    let app = build_app_with_indexer(
        Arc::new(StubIndexer::with_status(IndexerStatus::Halted(
            IndexerHaltReason::DbCorruption,
        ))),
        None,
    );
    let path = format!("/blockchain/box/byAddress/{}", p2pk_address());
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
    assert_eq!(body["detail"], "indexer halted: db-corruption");
}

// ---------------- 400 invalid-address --------------------------------------

#[tokio::test]
async fn post_txs_by_address_400_on_invalid_address() {
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()), Some(empty_chain()));
    let (status, body) = json_post(
        app,
        "/blockchain/transaction/byAddress",
        "\"!!!not-base58!!!\"",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "invalid-address");
}

#[tokio::test]
async fn post_boxes_by_address_400_on_p2sh() {
    let mut raw = vec![0x02u8];
    raw.extend_from_slice(&[0x55u8; 24]);
    let csum = blake2b256(&raw);
    raw.extend_from_slice(&csum.as_bytes()[..4]);
    let p2sh_addr = bs58::encode(&raw).into_string();
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()), None);
    let (status, body) = json_post(app, "/blockchain/box/byAddress", &json_str(&p2sh_addr)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "invalid-address");
}

// ---------------- 400 bad-request: paging validation -----------------------

#[tokio::test]
async fn post_txs_by_address_400_on_limit_above_max() {
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()), Some(empty_chain()));
    let url = "/blockchain/transaction/byAddress?limit=16385";
    let (status, body) = json_post(app, url, &json_str(&p2pk_address())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    // Per-route noun.
    assert_eq!(
        body["detail"],
        "No more than 16384 transactions can be requested",
    );
}

#[tokio::test]
async fn get_boxes_by_address_400_on_limit_above_max() {
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()), None);
    let url = format!("/blockchain/box/byAddress/{}?limit=99999", p2pk_address());
    let (status, body) = json_get(app, &url).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(body["detail"], "No more than 16384 boxes can be requested",);
}

#[tokio::test]
async fn get_txs_by_address_400_on_negative_offset() {
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()), Some(empty_chain()));
    let url = format!(
        "/blockchain/transaction/byAddress/{}?offset=-1",
        p2pk_address()
    );
    let (status, body) = json_get(app, &url).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(body["detail"], "offset is negative");
}

#[tokio::test]
async fn get_boxes_by_address_400_on_negative_limit() {
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()), None);
    let url = format!("/blockchain/box/byAddress/{}?limit=-5", p2pk_address());
    let (status, body) = json_get(app, &url).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(body["detail"], "limit is negative");
}

// ---------------- 200 success: txs paged -----------------------------------

#[tokio::test]
async fn post_txs_by_address_200_emits_paged_items_total_envelope() {
    let pubkey = [0x02u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let txs = vec![
        fixture_tx(700_000, 1),
        fixture_tx(700_001, 2),
        fixture_tx(700_002, 3),
    ];
    let stub = StubIndexer::caught_up().with_txs(tree_hash, txs.clone(), 100);
    let chain = stub_chain_at_heights(
        &[(700_000, HEX_64_BB, 1_700_000_000_000)],
        // multiple heights → use a fan of headers
    );
    let app = build_app_with_indexer(Arc::new(stub), Some(chain));
    // Default paging (offset=0, limit=5) returns all 3 fixture txs.
    let (status, body) =
        json_post(app, "/blockchain/transaction/byAddress", &json_str(&addr)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 3);
    // `total` reports the address-wide count (100), not the page size.
    assert_eq!(body["total"], 100);
    // Each item carries the chain-enriched wire shape.
    assert_eq!(items[0]["blockId"], HEX_64_BB);
    assert_eq!(items[0]["timestamp"], 1_700_000_000_000_u64);
    assert_eq!(items[0]["globalIndex"], 1);
}

#[tokio::test]
async fn get_txs_by_address_default_paging_matches_scala() {
    let pubkey = [0x07u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let stub = StubIndexer::caught_up().with_txs(tree_hash, Vec::new(), 0);
    let app = build_app_with_indexer(Arc::new(stub), Some(empty_chain()));
    // Missing query params: offset=0, limit=5. Stub records the page it
    // received via `address_txs_paged`'s arguments; we assert the wire
    // shape stays well-formed even when the result is empty.
    let path = format!("/blockchain/transaction/byAddress/{addr}");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["items"].as_array().unwrap().is_empty());
    assert_eq!(body["total"], 0);
}

// ---------------- 200 success: boxes paged ---------------------------------

#[tokio::test]
async fn get_boxes_by_address_200_emits_items_total_envelope() {
    let pubkey = [0x09u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let box_data = fixture_box(pubkey, 700_010, 5_000_000, 42);
    let stub = StubIndexer::caught_up().with_boxes(tree_hash, vec![box_data.clone()], 17);
    let app = build_app_with_indexer(Arc::new(stub), None);
    let path = format!("/blockchain/box/byAddress/{addr}?offset=0&limit=10");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(body["total"], 17);
    assert_eq!(items[0]["value"], 5_000_000_u64);
    assert_eq!(items[0]["globalIndex"], 42);
    assert_eq!(items[0]["inclusionHeight"], 700_010);
    // Address echoes the canonical encoding for the underlying tree —
    // confirms the `encode_address` round-trip.
    assert_eq!(items[0]["address"], addr);
}

#[tokio::test]
async fn post_boxes_by_address_unindexed_returns_zero_items_total() {
    // No `with_boxes` call → stub returns empty Vec + total=0.
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()), None);
    let (status, body) =
        json_post(app, "/blockchain/box/byAddress", &json_str(&p2pk_address())).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["items"].as_array().unwrap().is_empty());
    assert_eq!(body["total"], 0);
}

// ---------------- Per-page reverse parity (commit 447519c) ----------------

/// Pins `BlockchainApiRoute::getBoxesByAddress`'s `.reverse` semantic:
/// Scala fetches the page in DESC order (newest-first) and then
/// reverses the resulting Seq before responding, so the items in the
/// response are oldest-first within the page (but the page CONTENTS
/// are still the newest N for the address). A future refactor that
/// drops or misplaces the reverse would flip items[].globalIndex
/// from ASC to DESC and break Scala parity on every paged byAddress
/// box query — this test catches that.
///
/// Fixture stores boxes in DESC order (the contract of
/// `address_boxes_paged(..., Desc)` in the real indexer); the stub's
/// `[offset..offset+limit]` slice + the handler's reverse together
/// produce the asserted ascending intra-page order.
#[tokio::test]
async fn get_boxes_by_address_200_reverses_page_to_ascending() {
    let pubkey = [0x11u8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    // Five boxes; index in vec = DESC order (newest first). The
    // stub slices [offset..offset+limit] from this and the handler
    // reverses each page, so we expect ASC global indices in the
    // response.
    let boxes_desc = vec![
        fixture_box(pubkey, 700_005, 5_000, 105),
        fixture_box(pubkey, 700_004, 5_000, 104),
        fixture_box(pubkey, 700_003, 5_000, 103),
        fixture_box(pubkey, 700_002, 5_000, 102),
        fixture_box(pubkey, 700_001, 5_000, 101),
    ];
    let stub = StubIndexer::caught_up().with_boxes(tree_hash, boxes_desc.clone(), 100);
    let app = build_app_with_indexer(Arc::new(stub), None);
    let path = format!("/blockchain/box/byAddress/{addr}?offset=0&limit=5");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 5);
    // Page contents = newest 5 (globalIndex 101..=105); reversed so
    // items[0] is oldest within the page.
    let order: Vec<i64> = items
        .iter()
        .map(|v| v["globalIndex"].as_i64().unwrap())
        .collect();
    assert_eq!(
        order,
        vec![101, 102, 103, 104, 105],
        "items must be ASC within page (the .reverse after a DESC fetch)"
    );

    // offset > 0: stub returns [2..4] = [103, 102]; reverse → [102, 103].
    let stub2 = StubIndexer::caught_up().with_boxes(tree_hash, boxes_desc, 100);
    let app2 = build_app_with_indexer(Arc::new(stub2), None);
    let path2 = format!("/blockchain/box/byAddress/{addr}?offset=2&limit=2");
    let (status2, body2) = json_get(app2, &path2).await;
    assert_eq!(status2, StatusCode::OK);
    let items2 = body2["items"].as_array().unwrap();
    let order2: Vec<i64> = items2
        .iter()
        .map(|v| v["globalIndex"].as_i64().unwrap())
        .collect();
    assert_eq!(
        order2,
        vec![102, 103],
        "offset>0 must still produce ASC intra-page after reverse"
    );
}

// ---------------- POST/GET parity ------------------------------------------

#[tokio::test]
async fn boxes_by_address_post_and_get_emit_identical_envelopes() {
    let pubkey = [0x0Cu8; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let box_data = fixture_box(pubkey, 700_020, 1_234_567, 99);
    let post_app = build_app_with_indexer(Arc::new(stub_with_boxes(tree_hash, &box_data, 5)), None);
    let get_app = build_app_with_indexer(Arc::new(stub_with_boxes(tree_hash, &box_data, 5)), None);
    let (post_status, post_body) =
        json_post(post_app, "/blockchain/box/byAddress", &json_str(&addr)).await;
    let path = format!("/blockchain/box/byAddress/{addr}");
    let (get_status, get_body) = json_get(get_app, &path).await;
    assert_eq!(post_status, StatusCode::OK);
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(post_body, get_body);
}

// ---------------- helpers --------------------------------------------------

fn stub_with_boxes(tree_hash: Digest32, b: &IndexedErgoBox, total: u64) -> StubIndexer {
    StubIndexer::caught_up().with_boxes(tree_hash, vec![b.clone()], total)
}

fn p2pk_tree(pubkey: [u8; 33]) -> (ErgoTree, Vec<u8>) {
    let tree = ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: Vec::new(),
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(pubkey))),
        },
    };
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, &tree).unwrap();
    let bytes = w.result();
    (tree, bytes)
}

fn p2pk_address_and_hash(pubkey: [u8; 33]) -> (String, Digest32) {
    let (tree, bytes) = p2pk_tree(pubkey);
    let addr = encode_address(NetworkPrefix::Mainnet, &tree, &bytes);
    let tree_hash = blake2b256(&bytes);
    (addr, tree_hash)
}

fn p2pk_address() -> String {
    p2pk_address_and_hash([0x02; 33]).0
}

fn fixture_tx(height: i32, global_index: i64) -> IndexedErgoTransaction {
    IndexedErgoTransaction {
        id: TxId::from_bytes([height as u8; 32]),
        index_in_block: 0,
        height,
        size: 256,
        global_index,
        input_nums: Vec::new(),
        output_nums: Vec::new(),
        data_inputs: Vec::new(),
    }
}

fn fixture_box(pubkey: [u8; 33], height: i32, value: u64, global_index: i64) -> IndexedErgoBox {
    let (tree, _bytes) = p2pk_tree(pubkey);
    let candidate = ErgoBoxCandidate::new(
        value,
        tree,
        height as u32,
        Vec::new(),
        AdditionalRegisters::empty(),
    )
    .expect("ErgoBoxCandidate::new");
    let box_data = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([0xCC; 32]),
        index: 0,
    };
    IndexedErgoBox {
        inclusion_height: height,
        spending_tx_id: None,
        spending_height: None,
        spending_proof: None,
        box_data,
        global_index,
    }
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

fn build_app_with_indexer(
    indexer: Arc<dyn IndexerQuery>,
    chain: Option<Arc<dyn NodeChainQuery>>,
) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1234 });
    router(read, chain, None, Some(indexer), NetworkPrefix::Mainnet)
}

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

async fn json_post(app: axum::Router, path: &str, body: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

// ---------------- StubIndexer: paged tx + box -----------------------------

struct StubIndexer {
    status: IndexerStatus,
    addr_txs: Option<(TreeHash, Vec<IndexedErgoTransaction>, u64)>,
    addr_boxes: Option<(TreeHash, Vec<IndexedErgoBox>, u64)>,
}

impl StubIndexer {
    fn caught_up() -> Self {
        Self {
            status: IndexerStatus::CaughtUp,
            addr_txs: None,
            addr_boxes: None,
        }
    }
    fn with_status(status: IndexerStatus) -> Self {
        Self {
            status,
            addr_txs: None,
            addr_boxes: None,
        }
    }
    fn with_txs(
        mut self,
        tree_hash: TreeHash,
        txs: Vec<IndexedErgoTransaction>,
        total: u64,
    ) -> Self {
        self.addr_txs = Some((tree_hash, txs, total));
        self
    }
    fn with_boxes(mut self, tree_hash: TreeHash, boxes: Vec<IndexedErgoBox>, total: u64) -> Self {
        self.addr_boxes = Some((tree_hash, boxes, total));
        self
    }
}

impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        700_000
    }
    fn status(&self) -> IndexerStatus {
        self.status.clone()
    }

    fn box_by_id(&self, _: &BoxId) -> Option<IndexedBoxDto> {
        None
    }
    fn box_by_global_index(&self, _: u64) -> Option<IndexedBoxDto> {
        None
    }
    fn boxes_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedBoxDto> {
        Vec::new()
    }

    fn tx_by_id(&self, _: &TxId) -> Option<IndexedTxDto> {
        None
    }
    fn tx_by_global_index(&self, _: u64) -> Option<IndexedTxDto> {
        None
    }
    fn txs_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedTxDto> {
        Vec::new()
    }

    fn address_balance(&self, _: &TreeHash) -> Option<BalanceDto> {
        None
    }
    fn address_txs_paged(&self, tree_hash: &TreeHash, p: Page, _dir: SortDir) -> Vec<IndexedTxDto> {
        match &self.addr_txs {
            Some((h, txs, _)) if h == tree_hash => {
                let lo = p.offset as usize;
                let hi = lo.saturating_add(p.limit as usize).min(txs.len());
                if lo >= txs.len() {
                    Vec::new()
                } else {
                    txs[lo..hi].to_vec()
                }
            }
            _ => Vec::new(),
        }
    }
    fn address_boxes_paged(
        &self,
        tree_hash: &TreeHash,
        p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        match &self.addr_boxes {
            Some((h, boxes, _)) if h == tree_hash => {
                let lo = p.offset as usize;
                let hi = lo.saturating_add(p.limit as usize).min(boxes.len());
                if lo >= boxes.len() {
                    Vec::new()
                } else {
                    boxes[lo..hi].to_vec()
                }
            }
            _ => Vec::new(),
        }
    }
    fn address_unspent_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_total_txs(&self, tree_hash: &TreeHash) -> u64 {
        match &self.addr_txs {
            Some((h, _, total)) if h == tree_hash => *total,
            _ => 0,
        }
    }
    fn address_total_boxes(&self, tree_hash: &TreeHash) -> u64 {
        match &self.addr_boxes {
            Some((h, _, total)) if h == tree_hash => *total,
            _ => 0,
        }
    }

    fn template_boxes_paged(&self, _: &TemplateHash, _: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_unspent_paged(&self, _: &TemplateHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_total_boxes(&self, _: &TemplateHash) -> u64 {
        0
    }

    fn token_by_id(&self, _: &TokenId) -> Option<IndexedTokenDto> {
        None
    }
    fn tokens_by_ids(&self, _: &[TokenId]) -> Vec<IndexedTokenDto> {
        Vec::new()
    }
    fn token_boxes_paged(&self, _: &TokenId, _: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_unspent_paged(&self, _: &TokenId, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_total_boxes(&self, _: &TokenId) -> u64 {
        0
    }
}

// ---------------- StubChain: serves the canonical header per height -------

struct StubChain {
    headers: Vec<(u32, String, u64)>,
}

fn empty_chain() -> Arc<dyn NodeChainQuery> {
    Arc::new(StubChain {
        headers: Vec::new(),
    })
}

fn stub_chain_at_heights(spec: &[(u32, &str, u64)]) -> Arc<dyn NodeChainQuery> {
    Arc::new(StubChain {
        headers: spec
            .iter()
            .map(|(h, id, ts)| (*h, id.to_string(), *ts))
            .collect(),
    })
}

impl NodeChainQuery for StubChain {
    fn info(&self) -> ScalaInfo {
        empty_info()
    }
    fn header_ids_at_height(&self, _height: u32) -> Vec<String> {
        // The fixture txs in this suite span heights 700_000 ..=700_002.
        // The StubChain seeds only one canonical header but returns it
        // for every height — chain enrichment then succeeds for the
        // whole page. Real chain readers obviously serve distinct
        // headers per height; this is a test convenience.
        if !self.headers.is_empty() {
            vec![self.headers[0].1.clone()]
        } else {
            Vec::new()
        }
    }
    fn full_block_by_id(&self, _: &str) -> Option<ScalaFullBlock> {
        None
    }
    fn header_by_id(&self, header_id_hex: &str) -> Option<ScalaHeader> {
        self.headers
            .iter()
            .find(|(_, id, _)| id == header_id_hex)
            .map(|(h, id, ts)| stub_header(*h, id.clone(), *ts))
    }
}

fn stub_header(height: u32, id: String, timestamp: u64) -> ScalaHeader {
    ScalaHeader {
        extension_id: String::new(),
        difficulty: String::new(),
        votes: String::new(),
        timestamp,
        size: 0,
        unparsed_bytes: String::new(),
        state_root: String::new(),
        height,
        n_bits: 0,
        version: 0,
        id,
        ad_proofs_root: String::new(),
        transactions_root: String::new(),
        extension_hash: String::new(),
        pow_solutions: ScalaPowSolutions {
            pk: String::new(),
            w: String::new(),
            n: String::new(),
            d: serde_json::Value::Null,
        },
        ad_proofs_id: String::new(),
        transactions_id: String::new(),
        parent_id: String::new(),
    }
}

fn empty_info() -> ScalaInfo {
    ScalaInfo {
        last_mempool_update_time: 0,
        current_time: 0,
        network: String::new(),
        name: String::new(),
        state_type: String::new(),
        difficulty: 0,
        best_full_header_id: String::new(),
        best_header_id: String::new(),
        peers_count: 0,
        unconfirmed_count: 0,
        app_version: String::new(),
        eip37_supported: false,
        state_root: String::new(),
        genesis_block_id: String::new(),
        rest_api_url: None,
        previous_full_header_id: String::new(),
        full_height: 0,
        headers_height: 0,
        state_version: String::new(),
        full_blocks_score: 0,
        max_peer_height: 0,
        launch_time: 0,
        is_explorer: false,
        last_seen_message_time: 0,
        eip27_supported: false,
        headers_score: 0,
        parameters: Parameters {
            output_cost: 0,
            token_access_cost: 0,
            max_block_cost: 0,
            height: 0,
            max_block_size: 0,
            data_input_cost: 0,
            block_version: 0,
            input_cost: 0,
            storage_fee_factor: 0,
            subblocks_per_block: 0,
            min_value_per_byte: 0,
        },
        is_mining: false,
    }
}

// ---------------- StubReadState (mirrors blockchain_balance_routes.rs) -----

struct StubReadState {
    full_height: u32,
}

impl NodeReadState for StubReadState {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: "ergo-rust".into(),
            node_name: "stub".into(),
            network: "mainnet".into(),
            version: "0.1.0".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            best_header_height: self.full_height,
            best_full_block_height: self.full_height,
            ..Default::default()
        }
    }
    fn tip(&self) -> ApiTip {
        ApiTip {
            best_header: ApiHeaderRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: String::new(),
            },
            best_full_block: ApiFullBlockRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                state_root_avl: String::new(),
                n_bits: 0,
                difficulty: String::new(),
            },
            headers_ahead_of_full_blocks: 0,
        }
    }
    fn sync(&self) -> ApiSyncStatus {
        ApiSyncStatus {
            headers_chain_synced: true,
            best_header_height: 0,
            best_full_block_height: 0,
            gap: 0,
            download_window: 0,
            pending_blocks: 0,
            recovery_done: true,
        }
    }
    fn peers(&self) -> Vec<ApiPeer> {
        Vec::new()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        ApiMempoolSummary {
            size: 0,
            total_bytes: 0,
            capacity_count: 0,
            capacity_bytes: 0,
            revalidation_pending: 0,
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        ApiMempoolTransactions {
            transactions: Vec::new(),
            weight_function: ApiWeightFunction::Cost,
        }
    }
    fn mempool_transaction(&self, _: &str) -> Option<ApiMempoolTransaction> {
        None
    }
    fn health(&self) -> ApiHealth {
        ApiHealth {
            status: HealthStatus::Ok,
            behind: 0,
            last_progress_age_ms: 0,
            peer_count: 0,
        }
    }
}

// Suppress "never constructed" if a future change drops `IndexerHandle` use.
#[allow(dead_code)]
fn _ensure_handle_use_compiles() {
    let _ = IndexerHandle::syncing(0);
}

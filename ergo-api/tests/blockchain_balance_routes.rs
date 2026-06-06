//! `POST /blockchain/balance` and `GET /blockchain/balanceForAddress/{address}` —
//! balance routes plus the mempool overlay.
//!
//! Pinned behavior:
//! - The status gate fronts both routes; `Syncing` / `Halted` short-circuit
//!   to the `503 indexer-syncing` / `indexer-halted` envelope before address
//!   parsing runs.
//! - On `CaughtUp`, an indexed address projects its persisted `BalanceInfo`
//!   to the `confirmed` field; an unindexed address yields all-zero
//!   `confirmed` (Scala parity — missing record is "no balance", not 404).
//! - `unconfirmed` is computed *strictly additively* from the
//!   [`MempoolView`] overlay's `pool_outputs` — pool tx outputs whose
//!   `ergoTree` hashes to the queried address contribute to `unconfirmed`,
//!   pool spends of confirmed boxes do NOT subtract from `confirmed`. With
//!   [`NoopMempoolView`] (the legacy `router()` entry point) `unconfirmed`
//!   is all-zero. Both shapes carry no `warning` field — the
//!   pre-overlay `mempool-not-implemented` flag is gone now that the
//!   seam is wired.
//! - Address parse failures (bad base58, bad checksum, network mismatch,
//!   P2SH) return `400 invalid-address`.
//! - Confirmed `tokens` order matches the indexer's first-touch
//!   `ArrayBuffer` parity. Unconfirmed `tokens` are sorted by `tokenId` hex
//!   so the wire shape is stable across snapshot rebuilds (the underlying
//!   `pool_outputs` HashMap iteration order is non-deterministic).

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::server::{router, router_with_mempool};
use ergo_api::traits::{MempoolView, NodeReadState};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{IndexerHaltReason, IndexerHandle, IndexerQuery, IndexerStatus};
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, Page, SortDir, TemplateHash,
    TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::address::{encode_address, NetworkPrefix};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::write_ergo_tree;
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_ser::token::Token;
use http_body_util::BodyExt;
use tower::ServiceExt;

// ---------------- 503 status-gate envelope -------------------------------

#[tokio::test]
async fn post_balance_503_indexer_syncing() {
    let app = build_app(IndexerHandle::syncing(500));
    let (status, body) = json_post(app, "/blockchain/balance", &json_str(&p2pk_address())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
    assert_eq!(body["detail"], "indexer at height 500, target 1234");
}

#[tokio::test]
async fn get_balance_for_address_503_indexer_halted() {
    let app = build_app(IndexerHandle::halted(IndexerHaltReason::DbCorruption));
    let path = format!("/blockchain/balanceForAddress/{}", p2pk_address());
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
    assert_eq!(body["detail"], "indexer halted: db-corruption");
}

// ---------------- success path: indexed address -------------------------

#[tokio::test]
async fn post_balance_indexed_address_returns_confirmed_no_warning() {
    let pubkey = [0x02; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let token_a = Digest32::from_bytes([0xB1; 32]);
    let token_b = Digest32::from_bytes([0xB2; 32]);
    let stub = StubIndexer::caught_up().with_balance(
        tree_hash,
        BalanceDto {
            nano_ergs: 1_000_000_000,
            tokens: vec![(token_a, 5), (token_b, 7)],
        },
    );
    let app = build_app_with_indexer(Arc::new(stub));
    let (status, body) = json_post(app, "/blockchain/balance", &json_str(&addr)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["confirmed"]["nanoErgs"], 1_000_000_000_i64);
    let tokens = body["confirmed"]["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0]["tokenId"], hex::encode(token_a.as_bytes()));
    assert_eq!(tokens[0]["amount"], 5);
    assert_eq!(tokens[1]["tokenId"], hex::encode(token_b.as_bytes()));
    assert_eq!(tokens[1]["amount"], 7);
    assert_eq!(body["unconfirmed"]["nanoErgs"], 0);
    assert!(body["unconfirmed"]["tokens"].as_array().unwrap().is_empty());
    assert!(body.get("warning").is_none(), "pre-P5 warning must be gone");
}

#[tokio::test]
async fn get_balance_for_address_indexed_yields_same_envelope_as_post() {
    let pubkey = [0x03; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let stub = StubIndexer::caught_up().with_balance(
        tree_hash,
        BalanceDto {
            nano_ergs: 42,
            tokens: Vec::new(),
        },
    );
    let app = build_app_with_indexer(Arc::new(stub));
    let path = format!("/blockchain/balanceForAddress/{addr}");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["confirmed"]["nanoErgs"], 42);
    assert!(body.get("warning").is_none());
}

// ---------------- success path: unindexed address ---------------------------

#[tokio::test]
async fn post_balance_unindexed_address_returns_zero_confirmed_no_warning() {
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(app, "/blockchain/balance", &json_str(&p2pk_address())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["confirmed"]["nanoErgs"], 0);
    assert!(body["confirmed"]["tokens"].as_array().unwrap().is_empty());
    assert_eq!(body["unconfirmed"]["nanoErgs"], 0);
    assert!(body.get("warning").is_none());
}

// ---------------- P5 mempool overlay path -----------------------------------

#[tokio::test]
async fn post_balance_with_pool_outputs_returns_unconfirmed() {
    let pubkey = [0x02; 33];
    let (addr, _) = p2pk_address_and_hash(pubkey);
    let pool_box = make_pool_box(pubkey, 500_000_000, Vec::new(), 0xAA);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let (status, body) = json_post(app, "/blockchain/balance", &json_str(&addr)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["confirmed"]["nanoErgs"], 0);
    assert_eq!(body["unconfirmed"]["nanoErgs"], 500_000_000_i64);
    assert!(body["unconfirmed"]["tokens"].as_array().unwrap().is_empty());
    assert!(body.get("warning").is_none());
}

#[tokio::test]
async fn post_balance_pool_output_for_other_address_no_contribution() {
    let user_pubkey = [0x02; 33];
    let other_pubkey = [0x03; 33];
    let (addr, _) = p2pk_address_and_hash(user_pubkey);
    let pool_box = make_pool_box(other_pubkey, 1_000, Vec::new(), 0xBB);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let (status, body) = json_post(app, "/blockchain/balance", &json_str(&addr)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["unconfirmed"]["nanoErgs"], 0);
    assert!(body["unconfirmed"]["tokens"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn post_balance_pool_outputs_aggregate_tokens_sorted() {
    let pubkey = [0x02; 33];
    let (addr, _) = p2pk_address_and_hash(pubkey);
    // token_b's id sorts before token_a's id by hex when we pick prefix
    // bytes 0xC1 vs 0xC2 — assert deterministic sort regardless of pool
    // iteration order (pool_outputs is HashMap).
    let token_a = Digest32::from_bytes([0xC2; 32]);
    let token_b = Digest32::from_bytes([0xC1; 32]);
    let box1 = make_pool_box(
        pubkey,
        1_000,
        vec![
            Token {
                token_id: token_a,
                amount: 5,
            },
            Token {
                token_id: token_b,
                amount: 7,
            },
        ],
        0xAA,
    );
    let box2 = make_pool_box(
        pubkey,
        2_000,
        vec![Token {
            token_id: token_a,
            amount: 3,
        }],
        0xBB,
    );
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![box1, box2]));
    let app = build_app_with_mempool(Arc::new(StubIndexer::caught_up()), mempool);
    let (status, body) = json_post(app, "/blockchain/balance", &json_str(&addr)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["unconfirmed"]["nanoErgs"], 3_000_i64);
    let tokens = body["unconfirmed"]["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0]["tokenId"], hex::encode(token_b.as_bytes()));
    assert_eq!(tokens[0]["amount"], 7);
    assert_eq!(tokens[1]["tokenId"], hex::encode(token_a.as_bytes()));
    assert_eq!(tokens[1]["amount"], 8); // 5 + 3 across two boxes
}

#[tokio::test]
async fn get_balance_for_address_overlays_confirmed_and_unconfirmed() {
    // Indexed user with 100 nanoErgs confirmed and a pool output paying
    // 50 nanoErgs to the same address — strictly additive: response
    // must show confirmed=100, unconfirmed=50. The mempool view never
    // subtracts from confirmed even if a pool tx were spending the
    // user's confirmed boxes (that's the [inherited] Scala behavior).
    let pubkey = [0x04; 33];
    let (addr, tree_hash) = p2pk_address_and_hash(pubkey);
    let stub_idx = StubIndexer::caught_up().with_balance(
        tree_hash,
        BalanceDto {
            nano_ergs: 100,
            tokens: Vec::new(),
        },
    );
    let pool_box = make_pool_box(pubkey, 50, Vec::new(), 0xAA);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempoolView::with_outputs(vec![pool_box]));
    let app = build_app_with_mempool(Arc::new(stub_idx), mempool);
    let path = format!("/blockchain/balanceForAddress/{addr}");
    let (status, body) = json_get(app, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["confirmed"]["nanoErgs"], 100);
    assert_eq!(body["unconfirmed"]["nanoErgs"], 50);
    assert!(body.get("warning").is_none());
}

// ---------------- 400 invalid-address envelopes -----------------------------

#[tokio::test]
async fn post_balance_400_on_invalid_base58() {
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(app, "/blockchain/balance", "\"!!!not-base58!!!\"").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "invalid-address");
}

#[tokio::test]
async fn post_balance_400_on_network_mismatch() {
    // Build a testnet address but submit to the mainnet router.
    let pubkey = [0x02; 33];
    let (tree, bytes) = p2pk_tree(pubkey);
    let testnet_addr = encode_address(NetworkPrefix::Testnet, &tree, &bytes);
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(app, "/blockchain/balance", &json_str(&testnet_addr)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "invalid-address");
}

#[tokio::test]
async fn post_balance_400_on_p2sh_address_type() {
    // Manually build a valid mainnet P2SH (type 0x02) address — Scala
    // would accept it but its synthetic script never matches any indexed
    // record. We surface the unsupported-type explicitly.
    let mut raw = vec![0x02u8];
    raw.extend_from_slice(&[0x55u8; 24]);
    let csum = blake2b256(&raw);
    raw.extend_from_slice(&csum.as_bytes()[..4]);
    let p2sh_addr = bs58::encode(&raw).into_string();
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()));
    let (status, body) = json_post(app, "/blockchain/balance", &json_str(&p2sh_addr)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "invalid-address");
}

#[tokio::test]
async fn get_balance_for_address_400_on_bad_address() {
    let app = build_app_with_indexer(Arc::new(StubIndexer::caught_up()));
    // base58 decoder rejects character 'l' / '0' / 'O' / 'I' — single
    // bad char triggers Base58 error.
    let (status, body) = json_get(app, "/blockchain/balanceForAddress/0OIl").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "invalid-address");
}

// ---------------- helpers ---------------------------------------------------

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

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

fn caught_up() -> IndexerHandle {
    let h = IndexerHandle::syncing(700_000);
    h.set_status(IndexerStatus::CaughtUp);
    h
}

#[allow(dead_code)]
fn build_app(handle: IndexerHandle) -> axum::Router {
    let indexer: Arc<dyn IndexerQuery> = Arc::new(handle);
    build_app_with_indexer(indexer)
}

fn build_app_with_indexer(indexer: Arc<dyn IndexerQuery>) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1234 });
    router(read, None, None, Some(indexer), NetworkPrefix::Mainnet)
}

fn build_app_with_mempool(
    indexer: Arc<dyn IndexerQuery>,
    mempool: Arc<dyn MempoolView>,
) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1234 });
    router_with_mempool(
        ergo_api::ServerCtx {
            read,
            compat: None,
            submit: None,
            indexer: Some(indexer),
            mempool,
            network: NetworkPrefix::Mainnet,
            chain_params: None,
            mining: None,
            emission: None,
            utxo_reads_supported: true,
        },
        None, // admin — tests don't exercise the shutdown endpoint
    )
}

fn make_pool_box(pubkey: [u8; 33], value: u64, tokens: Vec<Token>, tx_id_byte: u8) -> ErgoBox {
    let (tree, _bytes) = p2pk_tree(pubkey);
    let candidate = ErgoBoxCandidate::new(value, tree, 0, tokens, AdditionalRegisters::empty())
        .expect("ErgoBoxCandidate::new");
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([tx_id_byte; 32]),
        index: 0,
    }
}

struct StubMempoolView {
    outputs: Arc<HashMap<BoxId, ErgoBox>>,
}

impl StubMempoolView {
    fn with_outputs(boxes: Vec<ErgoBox>) -> Self {
        let mut outputs = HashMap::new();
        for b in boxes {
            let id = b.box_id().expect("box_id");
            outputs.insert(id, b);
        }
        Self {
            outputs: Arc::new(outputs),
        }
    }
}

impl MempoolView for StubMempoolView {
    fn is_spent_by_pool(&self, _box_id: &BoxId) -> bool {
        false
    }
    fn pool_spending_tx(&self, _box_id: &BoxId) -> Option<TxId> {
        None
    }
    fn pool_outputs(&self) -> Arc<HashMap<BoxId, ErgoBox>> {
        self.outputs.clone()
    }
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
            peer_count: 0,
            best_header_height: self.full_height,
            best_full_block_height: self.full_height,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
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
    fn mempool_transaction(&self, _tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
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

// ---------------- StubIndexer with seedable balance -------------------------

struct StubIndexer {
    status: IndexerStatus,
    balance: Option<(TreeHash, BalanceDto)>,
}

impl StubIndexer {
    fn caught_up() -> Self {
        Self {
            status: IndexerStatus::CaughtUp,
            balance: None,
        }
    }
    fn with_balance(mut self, tree_hash: TreeHash, dto: BalanceDto) -> Self {
        self.balance = Some((tree_hash, dto));
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
    fn address_balance(&self, tree_hash: &TreeHash) -> Option<BalanceDto> {
        self.balance
            .as_ref()
            .filter(|(h, _)| h == tree_hash)
            .map(|(_, dto)| dto.clone())
    }
    fn address_txs_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_boxes_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_unspent_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_total_txs(&self, _: &TreeHash) -> u64 {
        0
    }
    fn address_total_boxes(&self, _: &TreeHash) -> u64 {
        0
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

#[allow(dead_code)]
fn _ensure_caught_up_compiles() {
    let _ = caught_up();
}

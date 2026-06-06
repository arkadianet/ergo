//! `GET /blockchain/transaction/byId/{id}` and
//! `GET /blockchain/transaction/byIndex/{n}` — the byId/byIndex tx
//! surface.
//!
//! What this file pins:
//! - `Syncing` / `Halted` transitions return the pinned 503 envelopes
//!   identical in shape to box routes (re-checked here because the gate
//!   is per-route-layer; a future change that mounted the tx routes
//!   outside the gated subtree would slip past `blockchain_box_routes`
//!   without this coverage).
//! - `CaughtUp + miss` → canonical `404 not-found` envelope.
//! - Negative byIndex / malformed hex → 404 (i64 → u64 guard + hex
//!   parser are shared with box routes but exercised through the tx
//!   handler dispatch path so a future divergence would surface).
//! - The unique tx wire shape (chain `blockId`/`timestamp` enrichment,
//!   `numConfirmations` math against `NodeReadState::status()`, and DTO
//!   assembly) is exercised via a stub indexer that returns a fixture
//!   `IndexedErgoTransaction` with empty inputs / outputs / data inputs.
//!   Sidesteps full ErgoBox fixtures — the corpus-backed integration
//!   suite covers populated transactions.
//! - When the handler can't resolve the canonical header for the indexed
//!   tx height (chain reader returned an empty list), the response is
//!   500 internal-error — apply writes box rows + tx rows in the same
//!   redb txn as the chain commit, so a missing header at an indexed tx
//!   height is a consistency failure, not a not-found.
//!
//! Test wiring: gate / 404 cases reuse `IndexerHandle::syncing()` /
//! `::halted()` (store-less); the 200-path and consistency-failure cases
//! use `StubIndexer` + `StubChain` so we can inject the fixture without
//! a real `IndexerStore`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{
    Parameters, ScalaFullBlock, ScalaHeader, ScalaInfo, ScalaPowSolutions,
};
use ergo_api::server::{router, router_with_mempool, ServerCtx};
use ergo_api::traits::{MempoolView, NodeReadState, PoolTxDetail};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{
    BalanceDto, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerHaltReason, IndexerHandle,
    IndexerQuery, IndexerStatus, Page, SortDir,
};
use ergo_indexer_types::types::IndexedErgoTransaction;
use ergo_indexer_types::{BoxId, TemplateHash, TokenId, TreeHash, TxId};
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use ergo_ser::transaction::{write_transaction, Transaction};
use http_body_util::BodyExt;
use std::collections::HashMap;
use tower::ServiceExt;

const HEX_64_AA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HEX_64_BB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ---------- gate: Syncing → 503 indexer-syncing -------------------------

#[tokio::test]
async fn tx_by_id_503_indexer_syncing_pins_envelope() {
    let app = build_app(syncing_handle(500), Some(empty_chain()));
    let (status, body) = json_get(app, &format!("/blockchain/transaction/byId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], 503);
    assert_eq!(body["reason"], "indexer-syncing");
    assert_eq!(body["detail"], "indexer at height 500, target 1234");
}

#[tokio::test]
async fn tx_by_index_503_indexer_syncing_pins_envelope() {
    let app = build_app(syncing_handle(0), Some(empty_chain()));
    let (status, body) = json_get(app, "/blockchain/transaction/byIndex/42").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], 503);
    assert_eq!(body["reason"], "indexer-syncing");
    assert_eq!(body["detail"], "indexer at height 0, target 1234");
}

// ---------- gate: Halted → 503 indexer-halted ---------------------------

#[tokio::test]
async fn tx_by_id_503_indexer_halted_pins_envelope() {
    let h = IndexerHandle::halted(IndexerHaltReason::DbCorruption);
    let app = build_app(h, Some(empty_chain()));
    let (status, body) = json_get(app, &format!("/blockchain/transaction/byId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
    assert_eq!(body["detail"], "indexer halted: db-corruption");
}

#[tokio::test]
async fn tx_by_index_503_indexer_halted_pins_envelope() {
    let h = IndexerHandle::halted(IndexerHaltReason::UndoMissing);
    let app = build_app(h, Some(empty_chain()));
    let (status, body) = json_get(app, "/blockchain/transaction/byIndex/0").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
    assert_eq!(body["detail"], "indexer halted: undo-missing");
}

// ---------- gate passthrough: CaughtUp → handler runs -------------------

#[tokio::test]
async fn tx_by_id_404_when_caught_up_and_record_absent() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let (status, body) = json_get(app, &format!("/blockchain/transaction/byId/{HEX_64_AA}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], 404);
    assert_eq!(body["reason"], "not-found");
    assert_eq!(body["detail"], "transaction not found");
}

#[tokio::test]
async fn tx_by_index_404_when_caught_up_and_record_absent() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let (status, body) = json_get(app, "/blockchain/transaction/byIndex/123456789").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
    assert_eq!(body["detail"], "transaction not found");
}

// ---------- input validation ---------------------------------------------

#[tokio::test]
async fn tx_by_id_404_on_malformed_hex_short() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let (status, body) = json_get(app, "/blockchain/transaction/byId/aabbcc").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

#[tokio::test]
async fn tx_by_id_404_on_malformed_hex_nonhex_chars() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let bad = format!("z{}", &HEX_64_AA[1..]);
    let (status, _) = json_get(app, &format!("/blockchain/transaction/byId/{bad}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tx_by_index_404_on_negative_value() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let (status, body) = json_get(app, "/blockchain/transaction/byIndex/-1").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

// ---------- 200 success path: chain enrichment + numConfirmations -------

#[tokio::test]
async fn tx_by_id_200_emits_chain_enriched_wire_shape() {
    // Indexer holds a fixture tx at height 700_000 with empty inputs /
    // outputs / data_inputs. The chain stub answers `header_ids_at_height`
    // with one canonical id and `header_by_id` with a header carrying a
    // pinned timestamp. NodeReadState reports best_full_block_height
    // 1234 (via `StubReadState`), so numConfirmations = 1234-700000
    // (Scala formula, not the conventional Bitcoin tip-incl+1) clamps
    // to 0 — the floor branch. The positive branch is pinned by
    // `tx_by_index_200_emits_positive_confirmation_count` below.
    let tx = fixture_tx(700_000);
    let app = build_app_with_indexer(
        Arc::new(StubIndexer::with_tx(tx.clone(), IndexerStatus::CaughtUp)),
        Some(stub_chain_at_height(700_000, HEX_64_BB, 1_700_000_000_000)),
    );
    let id_hex = hex::encode(tx.id.as_bytes());
    let (status, body) = json_get(app, &format!("/blockchain/transaction/byId/{id_hex}")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["id"], id_hex);
    assert_eq!(body["inclusionHeight"], 700_000);
    assert_eq!(body["index"], 0);
    assert_eq!(body["globalIndex"], 0);
    assert_eq!(body["size"], 256);
    assert_eq!(body["blockId"], HEX_64_BB);
    assert_eq!(body["timestamp"], 1_700_000_000_000_u64);
    // Inputs / outputs / dataInputs are emitted as empty arrays; pinning
    // the wire shape confirms the DTO field set matches openapi.yaml.
    assert!(body["inputs"].is_array() && body["inputs"].as_array().unwrap().is_empty());
    assert!(body["outputs"].is_array() && body["outputs"].as_array().unwrap().is_empty());
    assert!(body["dataInputs"].is_array() && body["dataInputs"].as_array().unwrap().is_empty());
    // Confirmation floor: best_full_block_height (1234) < height (700000).
    assert_eq!(body["numConfirmations"], 0);
}

#[tokio::test]
async fn tx_by_index_200_emits_positive_confirmation_count() {
    // Indexed tx at height 1000; best_full_block_height is 1234.
    // Scala formula at `IndexedErgoTransaction.scala:62` is
    // `tip - inclusion` (NOT the conventional `tip - inclusion + 1`),
    // so numConfirmations = 1234 - 1000 = 234.
    let tx = fixture_tx(1000);
    let app = build_app_with_indexer(
        Arc::new(StubIndexer::with_tx(tx, IndexerStatus::CaughtUp)),
        Some(stub_chain_at_height(1000, HEX_64_BB, 1_700_000_000_000)),
    );
    let (status, body) = json_get(app, "/blockchain/transaction/byIndex/0").await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["numConfirmations"], 234);
    assert_eq!(body["inclusionHeight"], 1000);
}

// ---------- consistency failure: missing chain header → 500 ---------------

#[tokio::test]
async fn tx_by_id_500_when_chain_header_missing_at_indexed_height() {
    // Indexer returns the tx, but the chain stub has no header at the
    // indexed height — apply writes box+tx rows in the same redb txn as
    // the chain commit, so a missing header at an indexed tx height is a
    // consistency failure, not a not-found.
    let tx = fixture_tx(1000);
    let app = build_app_with_indexer(
        Arc::new(StubIndexer::with_tx(tx.clone(), IndexerStatus::CaughtUp)),
        Some(empty_chain()),
    );
    let id_hex = hex::encode(tx.id.as_bytes());
    let (status, body) = json_get(app, &format!("/blockchain/transaction/byId/{id_hex}")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"], 500);
}

// ---------- /api/v1/transactions/{id}/detail (resolved drawer) -----------

#[tokio::test]
async fn tx_detail_404_when_absent_from_index_and_pool() {
    // No indexed tx and no pool overlay (the no-mempool `router` wires
    // NoopMempoolView, so `pool_tx_detail` returns None) → the resolved
    // detail endpoint 404s with the canonical not-found envelope.
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let (status, body) = json_get(app, &format!("/api/v1/transactions/{HEX_64_AA}/detail")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

#[tokio::test]
async fn tx_detail_404_on_malformed_hex() {
    let app = build_app(caught_up_handle(), Some(empty_chain()));
    let (status, _) = json_get(app, "/api/v1/transactions/aabbcc/detail").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tx_detail_200_confirmed_reuses_indexed_shape() {
    // A confirmed (extra-indexed) tx resolves through the same renderer as
    // `/blockchain/transaction/byId`. The fixture carries empty io, so the
    // arrays are empty; what this pins is the DTO shape — `tx_id` present,
    // `inputs`/`outputs` arrays, and NO `confirmed` field (dropped so the
    // endpoint never emits a false extra-index-vs-chain label).
    let tx = fixture_tx(700_000);
    let app = build_app_with_indexer(
        Arc::new(StubIndexer::with_tx(tx.clone(), IndexerStatus::CaughtUp)),
        Some(stub_chain_at_height(700_000, HEX_64_BB, 1_700_000_000_000)),
    );
    let id_hex = hex::encode(tx.id.as_bytes());
    let (status, body) = json_get(app, &format!("/api/v1/transactions/{id_hex}/detail")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["tx_id"], id_hex);
    assert!(body["inputs"].is_array() && body["inputs"].as_array().unwrap().is_empty());
    assert!(body["outputs"].is_array() && body["outputs"].as_array().unwrap().is_empty());
    assert!(
        body.get("confirmed").is_none(),
        "confirmed flag must be dropped (extra-index != chain): {body}"
    );
}

// ---------- helpers ------------------------------------------------------

fn syncing_handle(indexed_height: u64) -> IndexerHandle {
    IndexerHandle::syncing(indexed_height)
}

fn caught_up_handle() -> IndexerHandle {
    let h = IndexerHandle::syncing(700_000);
    h.set_status(IndexerStatus::CaughtUp);
    h
}

fn fixture_tx(height: i32) -> IndexedErgoTransaction {
    IndexedErgoTransaction {
        id: TxId::from_bytes([0x33; 32]),
        index_in_block: 0,
        height,
        size: 256,
        global_index: 0,
        input_nums: Vec::new(),
        output_nums: Vec::new(),
        data_inputs: Vec::new(),
    }
}

fn build_app(handle: IndexerHandle, chain: Option<Arc<dyn NodeChainQuery>>) -> axum::Router {
    let indexer: Arc<dyn IndexerQuery> = Arc::new(handle);
    build_app_with_indexer(indexer, chain)
}

fn build_app_with_indexer(
    indexer: Arc<dyn IndexerQuery>,
    chain: Option<Arc<dyn NodeChainQuery>>,
) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1234 });
    router(
        read,
        chain,
        None,
        Some(indexer),
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
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

// ---------- stub IndexerQuery -------------------------------------------

/// Minimal `IndexerQuery` impl just rich enough to exercise the tx
/// success-path. `tx_by_id` and `tx_by_global_index` return the seeded
/// fixture; everything else returns the empty / `None` default. Box
/// lookups return `None` deliberately — the fixture tx has empty
/// `input_nums` / `output_nums`, so the handler never calls them.
struct StubIndexer {
    tx: IndexedErgoTransaction,
    status: IndexerStatus,
}

impl StubIndexer {
    fn with_tx(tx: IndexedErgoTransaction, status: IndexerStatus) -> Self {
        Self { tx, status }
    }
}

impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        self.tx.height.max(0) as u64
    }
    fn status(&self) -> IndexerStatus {
        self.status.clone()
    }

    fn box_by_id(&self, _box_id: &BoxId) -> Option<IndexedBoxDto> {
        None
    }
    fn box_by_global_index(&self, _n: u64) -> Option<IndexedBoxDto> {
        None
    }
    fn boxes_by_global_range(&self, _lo: u64, _hi: u64) -> Vec<IndexedBoxDto> {
        Vec::new()
    }

    fn tx_by_id(&self, tx_id: &TxId) -> Option<IndexedTxDto> {
        if tx_id == &self.tx.id {
            Some(self.tx.clone())
        } else {
            None
        }
    }
    fn tx_by_global_index(&self, n: u64) -> Option<IndexedTxDto> {
        if n as i64 == self.tx.global_index {
            Some(self.tx.clone())
        } else {
            None
        }
    }
    fn txs_by_global_range(&self, _lo: u64, _hi: u64) -> Vec<IndexedTxDto> {
        Vec::new()
    }

    fn address_balance(&self, _tree_hash: &TreeHash) -> Option<BalanceDto> {
        None
    }
    fn address_txs_paged(
        &self,
        _tree_hash: &TreeHash,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_boxes_paged(
        &self,
        _tree_hash: &TreeHash,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_unspent_paged(
        &self,
        _tree_hash: &TreeHash,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_total_txs(&self, _tree_hash: &TreeHash) -> u64 {
        0
    }
    fn address_total_boxes(&self, _tree_hash: &TreeHash) -> u64 {
        0
    }

    fn template_boxes_paged(&self, _template_hash: &TemplateHash, _p: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_unspent_paged(
        &self,
        _template_hash: &TemplateHash,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_total_boxes(&self, _template_hash: &TemplateHash) -> u64 {
        0
    }

    fn token_by_id(&self, _token_id: &TokenId) -> Option<IndexedTokenDto> {
        None
    }
    fn tokens_by_ids(&self, _ids: &[TokenId]) -> Vec<IndexedTokenDto> {
        Vec::new()
    }
    fn token_boxes_paged(&self, _token_id: &TokenId, _p: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_unspent_paged(
        &self,
        _token_id: &TokenId,
        _p: Page,
        _dir: SortDir,
    ) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_total_boxes(&self, _token_id: &TokenId) -> u64 {
        0
    }
}

// ---------- stub NodeChainQuery -----------------------------------------

fn empty_chain() -> Arc<dyn NodeChainQuery> {
    Arc::new(StubChain { at_height: None })
}

fn stub_chain_at_height(
    height: u32,
    header_id_hex: &str,
    timestamp_ms: u64,
) -> Arc<dyn NodeChainQuery> {
    Arc::new(StubChain {
        at_height: Some(StubChainHeader {
            height,
            id: header_id_hex.to_string(),
            timestamp: timestamp_ms,
        }),
    })
}

#[derive(Clone)]
struct StubChainHeader {
    height: u32,
    id: String,
    timestamp: u64,
}

struct StubChain {
    at_height: Option<StubChainHeader>,
}

impl NodeChainQuery for StubChain {
    fn info(&self) -> ScalaInfo {
        empty_info()
    }

    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        match &self.at_height {
            Some(h) if h.height == height => vec![h.id.clone()],
            _ => Vec::new(),
        }
    }

    fn full_block_by_id(&self, _header_id_hex: &str) -> Option<ScalaFullBlock> {
        None
    }

    fn header_by_id(&self, header_id_hex: &str) -> Option<ScalaHeader> {
        match &self.at_height {
            Some(h) if h.id == header_id_hex => Some(stub_header(h)),
            _ => None,
        }
    }
}

fn stub_header(h: &StubChainHeader) -> ScalaHeader {
    ScalaHeader {
        extension_id: String::new(),
        difficulty: String::new(),
        votes: String::new(),
        timestamp: h.timestamp,
        size: 0,
        unparsed_bytes: String::new(),
        state_root: String::new(),
        height: h.height,
        n_bits: 0,
        version: 0,
        id: h.id.clone(),
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

// ---------- stub NodeReadState ------------------------------------------

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

// ---------- /api/v1/transactions/{id}/detail — UNCONFIRMED (pool) -------
//
// The unconfirmed path: the indexer misses (store-less `CaughtUp` handle),
// so the handler resolves the tx from the mempool overlay via
// `pool_tx_detail`. Each spent input resolves against the confirmed UTXO
// set first, then the same-snapshot pool-output overlay, else null; output
// candidates always resolve (they carry value + ergoTree + tokens).

/// `MempoolView` that hands back one pooled tx's wire bytes + its
/// pool-output overlay for a single `tx_id` (the tx-detail seam). Every
/// other accessor reports an empty pool.
struct StubMempool {
    tx_id: TxId,
    bytes: Arc<[u8]>,
    pool_outputs: Arc<HashMap<BoxId, ErgoBox>>,
}

impl MempoolView for StubMempool {
    fn is_spent_by_pool(&self, _box_id: &BoxId) -> bool {
        false
    }
    fn pool_spending_tx(&self, _box_id: &BoxId) -> Option<TxId> {
        None
    }
    fn pool_outputs(&self) -> Arc<HashMap<BoxId, ErgoBox>> {
        self.pool_outputs.clone()
    }
    fn pool_tx_detail(&self, tx_id: &TxId) -> Option<PoolTxDetail> {
        (tx_id == &self.tx_id).then(|| (self.bytes.clone(), self.pool_outputs.clone()))
    }
}

fn build_app_with_mempool(indexer: IndexerHandle, mempool: Arc<dyn MempoolView>) -> axum::Router {
    // `router()` hardcodes a NoopMempoolView; the unconfirmed overlay needs a
    // real view, so build the `ServerCtx` directly and route through
    // `router_with_mempool`.
    let ctx = ServerCtx {
        read: Arc::new(StubReadState { full_height: 1234 }),
        compat: Some(empty_chain()),
        submit: None,
        indexer: Some(Arc::new(indexer)),
        mempool,
        network: ergo_ser::address::NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        emission: None,
        utxo_reads_supported: true,
    };
    router_with_mempool(ctx, None)
}

/// Minimal always-true (`SBoolean` const) script tree — `encode_address`
/// turns it into a valid P2S address, enough to assert a non-null address.
fn unconfirmed_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        },
    }
}

fn unconfirmed_candidate(value: u64, tokens: Vec<Token>) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        unconfirmed_tree(),
        100,
        tokens,
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn unconfirmed_input(box_id_fill: u8) -> Input {
    Input {
        box_id: Digest32::from_bytes([box_id_fill; 32]),
        spending_proof: SpendingProof::new(vec![0xDE, 0xAD], ContextExtension::empty()).unwrap(),
    }
}

#[tokio::test]
async fn tx_detail_200_unconfirmed_resolves_pool_overlay_and_nulls_unknown() {
    // Pooled tx: input A (0xA1) spends a pool-created box resolvable via the
    // overlay; input B (0xB2) spends a box known to neither the index nor
    // the pool (must null). One output carries a token.
    let token = Token {
        token_id: Digest32::from_bytes([0x07; 32]),
        amount: 42,
    };
    let tx = Transaction {
        inputs: vec![unconfirmed_input(0xA1), unconfirmed_input(0xB2)],
        data_inputs: vec![],
        output_candidates: vec![unconfirmed_candidate(5_000_000, vec![token])],
    };
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).unwrap();
    let bytes: Arc<[u8]> = Arc::from(w.result());

    // Pool-overlay box that input A spends, keyed by A's box_id.
    let mut overlay: HashMap<BoxId, ErgoBox> = HashMap::new();
    overlay.insert(
        Digest32::from_bytes([0xA1; 32]),
        ErgoBox {
            candidate: unconfirmed_candidate(3_000_000, vec![]),
            transaction_id: ModifierId::from_bytes([0xCC; 32]),
            index: 0,
        },
    );

    let tx_id = TxId::from_bytes([0x55; 32]);
    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempool {
        tx_id,
        bytes,
        pool_outputs: Arc::new(overlay),
    });
    let app = build_app_with_mempool(caught_up_handle(), mempool);

    let id_hex = hex::encode(tx_id.as_bytes());
    let (status, body) = json_get(app, &format!("/api/v1/transactions/{id_hex}/detail")).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["tx_id"], id_hex);

    // Output resolves: value + a non-null address + the token.
    let outs = body["outputs"].as_array().expect("outputs array");
    assert_eq!(outs.len(), 1);
    assert_eq!(outs[0]["value"].as_u64(), Some(5_000_000));
    assert!(outs[0]["address"].is_string(), "output address: {body}");
    let toks = outs[0]["tokens"].as_array().expect("tokens array");
    assert_eq!(toks.len(), 1);
    assert_eq!(toks[0]["amount"].as_u64(), Some(42));

    // Input A resolves via the pool overlay → value + address present.
    let ins = body["inputs"].as_array().expect("inputs array");
    assert_eq!(ins.len(), 2);
    assert_eq!(ins[0]["value"].as_u64(), Some(3_000_000));
    assert!(ins[0]["address"].is_string(), "input A address: {body}");

    // Input B resolves against neither surface → every projected field is
    // null (the null-honesty contract: "unknown" must not read as "[]").
    assert!(ins[1]["address"].is_null(), "input B address: {body}");
    assert!(ins[1]["value"].is_null(), "input B value: {body}");
    assert!(ins[1]["tokens"].is_null(), "input B tokens: {body}");
}

#[tokio::test]
async fn tx_detail_unconfirmed_404_for_non_matching_tx_id() {
    // `pool_tx_detail` returns None for a different tx_id; with the indexer
    // also missing, the handler falls through to the canonical not-found.
    let tx = Transaction {
        inputs: vec![unconfirmed_input(0xA1)],
        data_inputs: vec![],
        output_candidates: vec![unconfirmed_candidate(1_000_000, vec![])],
    };
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).unwrap();
    let bytes: Arc<[u8]> = Arc::from(w.result());

    let mempool: Arc<dyn MempoolView> = Arc::new(StubMempool {
        tx_id: TxId::from_bytes([0x55; 32]),
        bytes,
        pool_outputs: Arc::new(HashMap::new()),
    });
    let app = build_app_with_mempool(caught_up_handle(), mempool);

    // Query a different id than the stub holds.
    let (status, body) = json_get(app, &format!("/api/v1/transactions/{HEX_64_AA}/detail")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "not-found");
}

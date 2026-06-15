//! `GET|POST /blockchain/transaction/range` — extra-index row #8.
//!
//! Pinned behaviour:
//! - The status gate fires before the handler — `Syncing` / `Halted`
//!   short-circuits with the `503 indexer-{syncing,halted}` envelope.
//! - Paging contract: defaults `(offset=0, limit=5)`, `limit>16384`
//!   surfaces the `bad-request` envelope with the `"transactions"` noun
//!   (the route emits tx-ids, not boxes).
//! - Wire shape: bare `[ModifierId]` array — global-range projection of
//!   `IndexedErgoTransaction.id` only, no enrichment.
//! - Scala mounts no method directive (`*`); GET and POST go to the
//!   same dispatch and return identical bodies for identical queries.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{Parameters, ScalaFullBlock, ScalaInfo};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{IndexerHaltReason, IndexerHandle};
use ergo_indexer_types::types::IndexedErgoTransaction;
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
use ergo_primitives::digest::ModifierId;
use ergo_ser::address::NetworkPrefix;
use http_body_util::BodyExt;
use tower::ServiceExt;

// ---- 503 status-gate ------------------------------------------------------

#[tokio::test]
async fn range_503_indexer_syncing() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Syncing)));
    let (status, body) = json_get(app, "/blockchain/transaction/range").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-syncing");
}

#[tokio::test]
async fn range_503_indexer_halted() {
    let app = build_app(Arc::new(StubIndexer::with_status(IndexerStatus::Halted(
        IndexerHaltReason::DbCorruption,
    ))));
    let (status, body) = json_get(app, "/blockchain/transaction/range").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "indexer-halted");
}

// ---- 400 paging (transactions noun) ---------------------------------------

#[tokio::test]
async fn range_400_on_limit_above_max() {
    let app = build_app(Arc::new(StubIndexer::caught_up(Vec::new())));
    let (status, body) = json_get(app, "/blockchain/transaction/range?limit=16385").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
    assert_eq!(
        body["detail"],
        "No more than 16384 transactions can be requested",
    );
}

#[tokio::test]
async fn range_400_on_negative_offset() {
    let app = build_app(Arc::new(StubIndexer::caught_up(Vec::new())));
    let (status, body) = json_get(app, "/blockchain/transaction/range?offset=-1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad-request");
}

// ---- 200 dispatch + projection --------------------------------------------

#[tokio::test]
async fn range_200_returns_bare_id_array() {
    let txs = vec![
        tx_fixture(0xAA, 100),
        tx_fixture(0xBB, 101),
        tx_fixture(0xCC, 102),
    ];
    let app = build_app(Arc::new(StubIndexer::caught_up(txs)));
    let (status, body) = json_get(app, "/blockchain/transaction/range").await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("bare array response");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0], "aa".repeat(32));
    assert_eq!(arr[1], "bb".repeat(32));
    assert_eq!(arr[2], "cc".repeat(32));
}

#[tokio::test]
async fn range_200_post_get_parity() {
    let txs = vec![tx_fixture(0xAA, 100), tx_fixture(0xBB, 101)];
    let stub = Arc::new(StubIndexer::caught_up(txs));
    let app_get = build_app(stub.clone());
    let app_post = build_app(stub);

    let (s_get, b_get) = json_get(app_get, "/blockchain/transaction/range?offset=0&limit=2").await;
    let (s_post, b_post) =
        json_post_empty(app_post, "/blockchain/transaction/range?offset=0&limit=2").await;

    assert_eq!(s_get, StatusCode::OK);
    assert_eq!(s_post, StatusCode::OK);
    assert_eq!(b_get, b_post);
}

// ---- helpers --------------------------------------------------------------

fn tx_fixture(byte: u8, global_index: i64) -> IndexedErgoTransaction {
    IndexedErgoTransaction {
        id: TxId::from_bytes([byte; 32]),
        index_in_block: 0,
        height: 0,
        size: 0,
        global_index,
        input_nums: Vec::new(),
        output_nums: Vec::new(),
        data_inputs: Vec::new(),
    }
}

fn build_app(indexer: Arc<dyn IndexerQuery>) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat);
    router(
        read,
        Some(compat),
        None,
        Some(indexer),
        NetworkPrefix::Mainnet,
    )
}

async fn json_get(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    decode_response(resp).await
}

async fn json_post_empty(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    decode_response(resp).await
}

async fn decode_response(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

// ---- StubIndexer ----------------------------------------------------------

struct StubIndexer {
    status: IndexerStatus,
    txs: Vec<IndexedErgoTransaction>,
}

impl StubIndexer {
    fn with_status(status: IndexerStatus) -> Self {
        Self {
            status,
            txs: Vec::new(),
        }
    }
    fn caught_up(txs: Vec<IndexedErgoTransaction>) -> Self {
        Self {
            status: IndexerStatus::CaughtUp,
            txs,
        }
    }
}

impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        0
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
    fn txs_by_global_range(&self, lo: u64, hi: u64) -> Vec<IndexedTxDto> {
        let lo = lo as usize;
        let hi = (hi as usize).min(self.txs.len());
        if lo >= self.txs.len() {
            Vec::new()
        } else {
            self.txs[lo..hi].to_vec()
        }
    }

    fn address_balance(&self, _: &TreeHash) -> Option<BalanceDto> {
        None
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

// ---- StubReadState / StubCompat (minimal) ---------------------------------

struct StubReadState;

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
            best_header_height: 0,
            best_full_block_height: 0,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
            last_block_apply_error: None,
            block_apply_errors_total: 0,
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

struct StubCompat;

impl NodeChainQuery for StubCompat {
    fn header_ids_at_height(&self, _: u32) -> Vec<String> {
        Vec::new()
    }
    fn full_block_by_id(&self, _: &str) -> Option<ScalaFullBlock> {
        None
    }
    fn info(&self) -> ScalaInfo {
        ScalaInfo {
            last_mempool_update_time: 0,
            current_time: 0,
            network: "mainnet".into(),
            name: "stub".into(),
            state_type: "utxo".into(),
            difficulty: 0,
            best_full_header_id: String::new(),
            best_header_id: String::new(),
            peers_count: 0,
            unconfirmed_count: 0,
            app_version: "0.1.0".into(),
            eip37_supported: true,
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
            eip27_supported: true,
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
}

#[allow(dead_code)]
fn _ensure_handle_use_compiles() {
    let _: ModifierId = ModifierId::from_bytes([0; 32]);
    let _ = IndexerHandle::syncing(0);
}

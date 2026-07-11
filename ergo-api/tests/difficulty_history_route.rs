//! Behaviour of the native `GET /api/v1/difficulty/history` route.
//!
//! The snapshot test proves the OpenAPI *shape*; the mount-matrix test
//! proves the route is conditional on a wired chain reader. This test
//! drives the real handler and asserts what it *does*: it maps the chain's
//! ascending headers to `ApiDifficultyPoint`s (reusing the already-decoded
//! `difficulty` string verbatim), defaults the window to 720 blocks, and
//! clamps the `blocks` query into `[2, 16384]`.
//!
//! The chain stub records the `count` the handler forwards to
//! `last_headers`, so the clamp can be asserted directly without
//! materialising tens of thousands of synthetic headers.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{
    Parameters, ScalaFullBlock, ScalaHeader, ScalaInfo, ScalaPowSolutions,
};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiDifficultySeries, ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary,
    ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip,
    ApiWeightFunction, HealthStatus, SyncStateLabel,
};
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- helpers -----

/// Read-state is never touched by this route, but `router` requires one.
struct StubReadState;

impl NodeReadState for StubReadState {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: String::new(),
            node_name: String::new(),
            network: String::new(),
            version: String::new(),
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
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
            reorgs_total: 0,
            last_reorg_depth: None,
            last_reorg_unix_ms: None,
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

/// Chain stub that returns a fixed header list and records the `count` the
/// handler asked for, so the default/clamp logic can be asserted directly.
struct StubChain {
    headers: Vec<ScalaHeader>,
    last_requested: AtomicU32,
}

impl StubChain {
    fn new(headers: Vec<ScalaHeader>) -> Self {
        Self {
            headers,
            last_requested: AtomicU32::new(0),
        }
    }
}

impl NodeChainQuery for StubChain {
    fn info(&self) -> ScalaInfo {
        empty_info()
    }
    fn header_ids_at_height(&self, _height: u32) -> Vec<String> {
        Vec::new()
    }
    fn full_block_by_id(&self, _header_id_hex: &str) -> Option<ScalaFullBlock> {
        None
    }
    fn last_headers(&self, count: u32) -> Vec<ScalaHeader> {
        self.last_requested.store(count, Ordering::SeqCst);
        self.headers.clone()
    }
}

fn header(height: u32, timestamp: u64, difficulty: &str) -> ScalaHeader {
    ScalaHeader {
        extension_id: String::new(),
        difficulty: difficulty.to_string(),
        votes: String::new(),
        timestamp,
        size: 0,
        unparsed_bytes: String::new(),
        state_root: String::new(),
        height,
        n_bits: 0,
        version: 0,
        id: String::new(),
        ad_proofs_root: String::new(),
        transactions_root: String::new(),
        extension_hash: String::new(),
        pow_solutions: ScalaPowSolutions {
            pk: String::new(),
            w: String::new(),
            n: String::new(),
            d: serde_json::Value::from(0),
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

fn build_app(chain: Arc<dyn NodeChainQuery>) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    router(read, Some(chain), None, None, NetworkPrefix::Mainnet)
}

async fn get(app: axum::Router, path: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec();
    (status, bytes)
}

/// Issue the request and return the parsed series plus the `count` the
/// handler forwarded to `last_headers`.
async fn request(query: &str) -> (ApiDifficultySeries, u32) {
    let stub = Arc::new(StubChain::new(vec![
        header(100, 1_000, "111"),
        header(101, 2_000, "222"),
        header(102, 3_000, "333"),
    ]));
    let app = build_app(stub.clone());
    let path = format!("/api/v1/difficulty/history{query}");
    let (status, bytes) = get(app, &path).await;
    assert_eq!(status, StatusCode::OK, "history route must answer 200");
    let series: ApiDifficultySeries =
        serde_json::from_slice(&bytes).expect("body deserialises as ApiDifficultySeries");
    (series, stub.last_requested.load(Ordering::SeqCst))
}

// ----- happy path -----

#[tokio::test]
async fn difficulty_history_maps_headers_to_points_preserving_order() {
    let (series, _) = request("").await;
    assert_eq!(series.points.len(), 3);
    // Order is preserved verbatim (the chain contract already returns
    // ascending heights — the handler must not re-sort or reverse).
    let heights: Vec<u32> = series.points.iter().map(|p| p.height).collect();
    assert_eq!(heights, vec![100, 101, 102]);
    let p0 = &series.points[0];
    assert_eq!(p0.timestamp_unix_ms, 1_000);
    // The decoded difficulty string is reused verbatim — no re-decode.
    assert_eq!(p0.difficulty, "111");
    assert_eq!(series.points[2].difficulty, "333");
    assert_eq!(series.points[2].timestamp_unix_ms, 3_000);
}

#[tokio::test]
async fn difficulty_history_point_wire_shape_is_string_difficulty_without_n_bits() {
    // The typed-DTO tests prove the values; this asserts the raw wire
    // contract a browser actually sees: `difficulty` must stay a JSON
    // string (mainnet difficulty exceeds JS Number's safe-integer range),
    // and `n_bits` must not leak back in as a lossy duplicate field.
    let stub = Arc::new(StubChain::new(vec![header(100, 1_000, "263500538576896")]));
    let (status, bytes) = get(build_app(stub), "/api/v1/difficulty/history").await;
    assert_eq!(status, StatusCode::OK);
    let raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let point = &raw["points"][0];
    assert!(
        point["difficulty"].is_string(),
        "difficulty must serialise as a JSON string, not a number",
    );
    assert_eq!(point["difficulty"], "263500538576896");
    assert!(
        point.get("n_bits").is_none(),
        "n_bits must be absent from the wire shape",
    );
    assert!(point["height"].is_u64());
    assert!(point["timestamp_unix_ms"].is_u64());
}

#[tokio::test]
async fn difficulty_history_no_query_defaults_to_720_blocks() {
    let (_, requested) = request("").await;
    assert_eq!(
        requested, 720,
        "absent `blocks` defaults to a ~1-day window"
    );
}

#[tokio::test]
async fn difficulty_history_blocks_param_is_forwarded() {
    let (_, requested) = request("?blocks=50").await;
    assert_eq!(requested, 50, "an in-range `blocks` is forwarded unchanged");
}

// ----- error paths -----

#[tokio::test]
async fn difficulty_history_absent_without_chain_reader_404s() {
    // The route rides the Scala-compat chain reader; with `compat: None`
    // the sub-router is never mounted, so the path must 404.
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(read, None, None, None, NetworkPrefix::Mainnet);
    let (status, _) = get(app, "/api/v1/difficulty/history").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "history route must be absent without a chain reader",
    );
}

#[tokio::test]
async fn difficulty_history_blocks_below_floor_clamps_to_two() {
    assert_eq!(request("?blocks=1").await.1, 2, "blocks=1 clamps up to 2");
    assert_eq!(request("?blocks=0").await.1, 2, "blocks=0 clamps up to 2");
}

#[tokio::test]
async fn difficulty_history_blocks_above_ceiling_clamps_to_max() {
    let (_, requested) = request("?blocks=99999").await;
    assert_eq!(
        requested, 16_384,
        "an oversized `blocks` clamps to the ceiling"
    );
}

#[tokio::test]
async fn difficulty_history_unparseable_blocks_falls_back_to_default() {
    let (_, requested) = request("?blocks=not-a-number").await;
    assert_eq!(
        requested, 720,
        "a non-numeric `blocks` falls back to the default"
    );
}

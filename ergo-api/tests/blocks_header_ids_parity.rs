//! Shape parity for `POST /blocks/headerIds`.
//!
//! Mirrors `BlocksApiRoute.scala:70-73, 183-185`. The endpoint accepts a
//! bare JSON array of base16 modifier ids and returns an array of full
//! blocks for those ids that resolve. Behaviour matrix:
//!
//! - empty array → 200 with `[]`
//! - mix of known + unknown → 200 with only known ones, in request order
//! - any malformed hex → 400 (Scala: `ValidationRejection` from
//!   `handleModifierIds` at `ErgoBaseApiRoute.scala:44-58`)
//! - oversize array (> 16384) → 400 (Rust-side defensive cap; Scala has
//!   no cap on this route)

use std::sync::Arc;

use axum::body::{to_bytes, Body};
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
use tower::ServiceExt;

const FIXTURE_700K: &str = include_str!("fixtures/scala/blocks/700000.json");
const HEADER_ID_700K: &str = "54dd49ffbb32d35d8d6c41f3b427c68ac3cec91f6718fb7a50ec0d18d36e982a";

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

struct StubCompat {
    full_block_700k: ScalaFullBlock,
}

impl StubCompat {
    fn from_fixture() -> Self {
        let full_block_700k: ScalaFullBlock =
            serde_json::from_str(FIXTURE_700K).expect("fixture must parse as ScalaFullBlock");
        Self { full_block_700k }
    }
}

impl NodeChainQuery for StubCompat {
    fn info(&self) -> ScalaInfo {
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

    fn header_ids_at_height(&self, _height: u32) -> Vec<String> {
        Vec::new()
    }

    fn full_block_by_id(&self, header_id_hex: &str) -> Option<ScalaFullBlock> {
        if header_id_hex == HEADER_ID_700K {
            Some(self.full_block_700k.clone())
        } else {
            None
        }
    }
}

async fn json_post(
    app: axum::Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

fn build_app() -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat::from_fixture());
    router(
        read,
        Some(compat),
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

#[tokio::test]
async fn empty_array_returns_empty_response() {
    let (status, body) = json_post(build_app(), "/blocks/headerIds", serde_json::json!([])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!([]));
}

#[tokio::test]
async fn single_known_id_returns_block() {
    let (status, body) = json_post(
        build_app(),
        "/blocks/headerIds",
        serde_json::json!([HEADER_ID_700K]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("body must be a JSON array");
    assert_eq!(arr.len(), 1);
    let scala: serde_json::Value =
        serde_json::from_str(FIXTURE_700K).expect("parse fixture as JSON value");
    assert_eq!(
        arr[0], scala,
        "single-id response must match the same shape as /blocks/{{id}}"
    );
}

#[tokio::test]
async fn mix_of_known_and_unknown_drops_unknown_silently() {
    let unknown = "0".repeat(64);
    let (status, body) = json_post(
        build_app(),
        "/blocks/headerIds",
        serde_json::json!([unknown, HEADER_ID_700K, "f".repeat(64)]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("body must be a JSON array");
    assert_eq!(
        arr.len(),
        1,
        "only the known id should resolve; unknowns silently dropped"
    );
}

#[tokio::test]
async fn malformed_hex_rejects_whole_request() {
    let bad = format!("zz{}", "0".repeat(62));
    let (status, _) = json_post(
        build_app(),
        "/blocks/headerIds",
        serde_json::json!([HEADER_ID_700K, bad]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_length_id_rejects_whole_request() {
    let short = "ab".repeat(20);
    let (status, _) = json_post(build_app(), "/blocks/headerIds", serde_json::json!([short])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversize_array_rejected() {
    let ids: Vec<String> = (0..16385).map(|_| HEADER_ID_700K.to_string()).collect();
    let (status, _) = json_post(build_app(), "/blocks/headerIds", serde_json::json!(ids)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

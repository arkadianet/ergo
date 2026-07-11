//! Shape parity for `/blocks/at/{height}`.
//!
//! Scala emits a JSON array of unprefixed lowercase hex header IDs. We
//! verify the response shape (always an array of hex strings) plus a
//! known-stable height where mainnet has no orphans, so the array is a
//! single-element exact match. Empty-array responses for genesis (h=0)
//! and out-of-range heights are also pinned.

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

const FIXTURE_700K: &str = include_str!("fixtures/scala/blocks_at/700000.json");
const FIXTURE_GENESIS_PRE: &str = include_str!("fixtures/scala/blocks_at/0.json");
const FIXTURE_OUT_OF_RANGE: &str = include_str!("fixtures/scala/blocks_at/99999999.json");

const HEIGHT_700K_HEADER: &str = "54dd49ffbb32d35d8d6c41f3b427c68ac3cec91f6718fb7a50ec0d18d36e982a";

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

struct StubCompat;
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

    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        match height {
            700_000 => vec![HEIGHT_700K_HEADER.to_string()],
            // Mirror Scala: h=0 is below genesis (genesis is height 1),
            // and out-of-range heights both yield empty arrays.
            _ => Vec::new(),
        }
    }

    fn full_block_by_id(&self, _header_id_hex: &str) -> Option<ScalaFullBlock> {
        None
    }
}

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
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
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat);
    router(
        read,
        Some(compat),
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

#[tokio::test]
async fn known_height_matches_scala_exactly() {
    let scala: serde_json::Value = serde_json::from_str(FIXTURE_700K).expect("parse fixture");
    let (status, ours) = json_get(build_app(), "/blocks/at/700000").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(scala, ours, "h=700000 must match Scala exactly");
}

#[tokio::test]
async fn pre_genesis_height_returns_empty_array() {
    let scala: serde_json::Value =
        serde_json::from_str(FIXTURE_GENESIS_PRE).expect("parse fixture");
    let (status, ours) = json_get(build_app(), "/blocks/at/0").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        scala.as_array().unwrap().is_empty(),
        "scala fixture is empty"
    );
    assert_eq!(scala, ours, "h=0 must match Scala (empty array)");
}

#[tokio::test]
async fn out_of_range_height_returns_empty_array() {
    let scala: serde_json::Value =
        serde_json::from_str(FIXTURE_OUT_OF_RANGE).expect("parse fixture");
    let (status, ours) = json_get(build_app(), "/blocks/at/99999999").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        scala, ours,
        "out-of-range height must match Scala (empty array)"
    );
}

#[tokio::test]
async fn negative_height_is_rejected() {
    // Scala uses `IntNumber` which rejects negative values. axum's `Path<u32>`
    // rejects them with 400 too, so the surface contract matches even though
    // the error body shape differs.
    let (status, _) = json_get(build_app(), "/blocks/at/-1").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "negative heights must be rejected",
    );
}

#[tokio::test]
async fn non_numeric_height_is_rejected() {
    let (status, _) = json_get(build_app(), "/blocks/at/abc").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "non-numeric heights must be rejected",
    );
}

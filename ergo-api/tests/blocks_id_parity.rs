//! Shape parity for `/blocks/{header_id}`.
//!
//! Scala emits a single JSON object reassembled from the header,
//! blockTransactions, extension, and (optional) adProofs sections. This
//! test pins the *encoder* surface: given a `ScalaFullBlock` parsed from
//! a captured Scala response at h=700000, our serde renames and Option
//! handling must round-trip the value back to a byte-for-byte equivalent
//! JSON document. The bridge logic (bytes -> DTO) is tested separately
//! in `ergo-node`.
//!
//! 404 paths covered: unknown id and malformed hex. The bridge collapses
//! both cases into `None`, which the handler translates to 404 with a
//! minimal error body.

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
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
            reorgs_total: 0,
            last_reorg_depth: None,
            last_reorg_unix_ms: None,
            apply_in_progress: false,
            last_apply_duration_ms: 0,
            last_applied_height: 0,
            last_apply_age_ms: None,
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
async fn known_header_id_matches_scala_exactly() {
    let scala: serde_json::Value =
        serde_json::from_str(FIXTURE_700K).expect("parse fixture as JSON value");
    let path = format!("/blocks/{HEADER_ID_700K}");
    let (status, ours) = json_get(build_app(), &path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(scala, ours, "h=700000 full block must match Scala exactly");
}

#[tokio::test]
async fn unknown_header_id_returns_404() {
    let unknown = "0".repeat(64);
    let path = format!("/blocks/{unknown}");
    let (status, _) = json_get(build_app(), &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn malformed_hex_returns_404() {
    // 64 chars but contains a non-hex digit. The bridge rejects it as
    // unparseable, which the handler folds into 404 (same surface as a
    // truly unknown id — Scala behaves the same way).
    let bad = format!("zz{}", "0".repeat(62));
    let path = format!("/blocks/{bad}");
    let (status, _) = json_get(build_app(), &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn wrong_length_id_returns_404() {
    let too_short = "ab".repeat(20); // 40 chars
    let path = format!("/blocks/{too_short}");
    let (status, _) = json_get(build_app(), &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

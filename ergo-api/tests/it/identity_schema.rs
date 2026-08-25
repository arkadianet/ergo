//! `/api/v1/identity` schema regression guard.
//!
//! Tripwire for the deliberate `submission_enabled` field removal
//! that landed alongside the `[api] enable_submission` gate removal.
//! Asserts the field is absent from `/api/v1/identity`; any silent
//! re-introduction via merge or copy-paste flips this test red.
//!
//! Drives the router via `tower::ServiceExt::oneshot` against the same
//! `StubReadState` skeleton `submit_routes.rs` uses; the default
//! `NodeReadState::identity()` impl returns `ApiIdentity::default()`
//! which renders the full schema with default values — exactly what we
//! need to pin the wire shape.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use tower::ServiceExt;

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
    // identity() uses the trait default → ApiIdentity::default()
}

fn build_app() -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

async fn get_identity() -> (StatusCode, serde_json::Value) {
    let app = build_app();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/identity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("body is JSON");
    (status, value)
}

// ----- happy path -----

#[tokio::test]
async fn identity_returns_200_with_object_body() {
    let (status, body) = get_identity().await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.is_object(),
        "/api/v1/identity body must be a JSON object, got {body}",
    );
}

// ----- Post-gate-removal: submission_enabled is ABSENT -----

/// Tripwire for the deliberate breaking schema change: the
/// `submission_enabled` field was removed from `ApiIdentity`
/// atomically with the `[api] enable_submission` operator gate.
/// Any silent re-introduction of the field (via merge or copy-paste)
/// must flip this test red so the schema change cannot regress
/// unnoticed.
#[tokio::test]
async fn submission_enabled_field_is_absent_post_gate_removal() {
    let (_status, body) = get_identity().await;
    let obj = body.as_object().expect("identity body is an object");
    assert!(
        !obj.contains_key("submission_enabled"),
        "`submission_enabled` must not be present in /api/v1/identity \
         after gate removal. Re-introducing this field is a breaking \
         schema delta. body keys = {:?}",
        obj.keys().collect::<Vec<_>>(),
    );
}

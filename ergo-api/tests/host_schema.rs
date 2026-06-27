//! `/api/v1/host` schema regression guard.
//!
//! Pins the `Option<u64>` wire shape for `ApiHost` byte fields:
//! `None` serializes as JSON `null` (not as `0`, not as an absent
//! field). A monitoring scraper that pattern-matches `0` for "disk
//! full" or "process died" must see `null` for "could not determine"
//! instead — that disambiguation is the entire point of the
//! `Option` change.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiHost, ApiInfo, ApiMempoolSummary,
    ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip,
    ApiWeightFunction, HealthStatus, SyncStateLabel,
};
use tower::ServiceExt;

/// Stub returns a mix of `Some` and `None` byte fields so the
/// JSON-serialization assertions can distinguish both shapes in one
/// request.
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
    fn host(&self) -> ApiHost {
        ApiHost {
            rss_bytes: Some(42),
            state_db_bytes: Some(0),
            index_db_bytes: None,
            disk_free_bytes: None,
            disk_total_bytes: Some(1024),
            cpu_pct: None,
            net_in_bps: None,
            net_out_bps: None,
            load_1m: None,
        }
    }
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

async fn get_host() -> (StatusCode, serde_json::Value) {
    let app = build_app();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/host")
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
async fn host_returns_200_with_object_body() {
    let (status, body) = get_host().await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.is_object(),
        "/api/v1/host body must be a JSON object, got {body}",
    );
}

// ----- Option<u64> wire shape: null vs Some(0) vs Some(N) -----

/// `Some(N)` serializes as a JSON number, not as `null`. Without this
/// pin the wire could regress to `Option`-stripping serde attrs that
/// elide the field on `Some`.
#[tokio::test]
async fn host_some_value_serializes_as_number() {
    let (_status, body) = get_host().await;
    let obj = body.as_object().expect("host body is an object");
    assert_eq!(
        obj.get("rss_bytes")
            .expect("rss_bytes must be present")
            .as_u64(),
        Some(42),
        "Some(42) must serialize as JSON number 42, got {:?}",
        obj.get("rss_bytes"),
    );
    assert_eq!(
        obj.get("disk_total_bytes")
            .expect("disk_total_bytes must be present")
            .as_u64(),
        Some(1024),
    );
}

/// `Some(0)` serializes as JSON `0`, not as `null`. This disambiguates
/// "legitimately zero" (the file exists and is empty) from "could not
/// determine" (the file is missing).
#[tokio::test]
async fn host_some_zero_serializes_as_zero_not_null() {
    let (_status, body) = get_host().await;
    let obj = body.as_object().expect("host body is an object");
    let value = obj
        .get("state_db_bytes")
        .expect("state_db_bytes must be present");
    assert!(
        value.is_number() && value.as_u64() == Some(0),
        "Some(0) must serialize as JSON `0`, not `null`. got {value:?}",
    );
}

/// `None` serializes as JSON `null`, NOT as `0` and NOT as an absent
/// field. This is the load-bearing assertion of the Phase 1 change —
/// monitoring scrapers must see `null` for "could not determine," not
/// a misleading zero.
#[tokio::test]
async fn host_none_serializes_as_explicit_null() {
    let (_status, body) = get_host().await;
    let obj = body.as_object().expect("host body is an object");

    let index = obj
        .get("index_db_bytes")
        .expect("index_db_bytes key must be present (not omitted) when None");
    assert!(
        index.is_null(),
        "None on index_db_bytes must serialize as JSON `null`, not `0`. got {index:?}",
    );

    let free = obj
        .get("disk_free_bytes")
        .expect("disk_free_bytes key must be present (not omitted) when None");
    assert!(
        free.is_null(),
        "None on disk_free_bytes must serialize as JSON `null`, not `0`. got {free:?}",
    );
}

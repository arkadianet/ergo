//! `GET /api/v1/events` — the operator event feed. Always mounted (it
//! rides the always-present read state); the node-side ring projects into
//! the snapshot, so the handler is a pure snapshot read plus an optional
//! `?since=<seq>` filter. These tests pin the wire shape, the since-filter
//! semantics, and the defaulted-empty behavior for read states that never
//! override `events()`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiNodeEvent, ApiNodeEvents, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip,
    ApiWeightFunction, HealthStatus, SyncStateLabel,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn event(seq: u64, kind: &str) -> ApiNodeEvent {
    ApiNodeEvent {
        seq,
        unix_ms: 1_000 + seq,
        kind: kind.to_string(),
        height: (kind == "blockApplied").then_some(100 + seq as u32),
        header_id: (kind == "blockApplied").then(|| format!("{seq:064x}")),
        txs: (kind == "blockApplied").then_some(3),
        size_bytes: (kind == "blockApplied").then_some(4_096),
        addr: (kind == "peerConnected").then(|| "10.0.0.9:9030".to_string()),
        detail: None,
    }
}

/// Read state with a fixed three-event feed.
struct FeedStub;

impl NodeReadState for FeedStub {
    fn events(&self) -> ApiNodeEvents {
        ApiNodeEvents {
            latest_seq: 3,
            events: vec![
                event(1, "peerConnected"),
                event(2, "blockApplied"),
                event(3, "indexerStatus"),
            ],
        }
    }

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
            best_header_height: 900_000,
            best_full_block_height: 900_000,
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
}

async fn get_json(app: axum::Router, path: &str) -> serde_json::Value {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET {path} must 200");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("events response is JSON")
}

fn app(read: Arc<dyn NodeReadState>) -> axum::Router {
    router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    )
}

#[tokio::test]
async fn events_returns_full_tail_without_since() {
    let body = get_json(app(Arc::new(FeedStub)), "/api/v1/events").await;
    assert_eq!(body["latestSeq"], 3);
    let evs = body["events"].as_array().unwrap();
    assert_eq!(evs.len(), 3);
    assert_eq!(evs[0]["seq"], 1);
    assert_eq!(evs[0]["kind"], "peerConnected");
    assert_eq!(evs[0]["addr"], "10.0.0.9:9030");
    assert_eq!(evs[1]["kind"], "blockApplied");
    assert_eq!(evs[1]["height"], 102);
    assert_eq!(evs[1]["txs"], 3);
    assert!(evs[0].get("height").is_none(), "absent optionals omitted");
}

#[tokio::test]
async fn events_since_filters_strictly_greater() {
    let body = get_json(app(Arc::new(FeedStub)), "/api/v1/events?since=2").await;
    assert_eq!(
        body["latestSeq"], 3,
        "latestSeq reflects the ring, not the filter"
    );
    let evs = body["events"].as_array().unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0]["seq"], 3);
}

#[tokio::test]
async fn events_since_beyond_latest_returns_empty_list() {
    let body = get_json(app(Arc::new(FeedStub)), "/api/v1/events?since=99").await;
    assert_eq!(body["latestSeq"], 3);
    assert!(body["events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn events_default_impl_serves_empty_feed() {
    // A read state that never overrides events() — the trait default.
    let body = get_json(app(Arc::new(DefaultStub)), "/api/v1/events").await;
    assert_eq!(body["latestSeq"], 0);
    assert!(body["events"].as_array().unwrap().is_empty());
}

/// Same stub bodies, but relying on the DEFAULT events() impl.
struct DefaultStub;

impl NodeReadState for DefaultStub {
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
            best_header_height: 900_000,
            best_full_block_height: 900_000,
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
}

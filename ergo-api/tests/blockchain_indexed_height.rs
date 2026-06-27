//! `GET /blockchain/indexedHeight` — the always-200 sync-progress probe
//! (route #1). The status gate explicitly does not apply here: this
//! endpoint is the operator's only way to observe whether the indexer
//! has caught up, so it must answer regardless of state.
//!
//! The response body's `status` field carries the runtime state and
//! `haltReason` is populated only when `status == "halted"`. These
//! tests pin the wire shape across the three IndexerStatus variants
//! plus the "indexer not plumbed" path (which 404s — the entire
//! `/blockchain/*` router only mounts when an `IndexerQuery` handle is
//! provided).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer::{IndexerHaltReason, IndexerHandle, IndexerQuery, IndexerStatus};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn indexed_height_reports_syncing_status() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1234 });
    let indexer = IndexerHandle::syncing(500);
    let app = router(
        read,
        None,
        None,
        Some(Arc::new(indexer) as Arc<dyn IndexerQuery>),
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let body = get_json(app, "/blockchain/indexedHeight").await;
    assert_eq!(body["indexedHeight"], 500);
    assert_eq!(body["fullHeight"], 1234);
    assert_eq!(body["status"], "syncing");
    assert!(
        body.get("haltReason").is_none(),
        "no haltReason while syncing"
    );
}

#[tokio::test]
async fn indexed_height_reports_caught_up_status() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState {
        full_height: 700_000,
    });
    let indexer = IndexerHandle::syncing(700_000);
    indexer.set_status(IndexerStatus::CaughtUp);
    let app = router(
        read,
        None,
        None,
        Some(Arc::new(indexer) as Arc<dyn IndexerQuery>),
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let body = get_json(app, "/blockchain/indexedHeight").await;
    assert_eq!(body["indexedHeight"], 700_000);
    assert_eq!(body["fullHeight"], 700_000);
    assert_eq!(body["status"], "caughtUp");
    assert!(body.get("haltReason").is_none());
}

#[tokio::test]
async fn indexed_height_reports_halted_status_with_reason() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 100 });
    let indexer = IndexerHandle::halted(IndexerHaltReason::DbCorruption);
    let app = router(
        read,
        None,
        None,
        Some(Arc::new(indexer) as Arc<dyn IndexerQuery>),
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let body = get_json(app, "/blockchain/indexedHeight").await;
    assert_eq!(body["indexedHeight"], 0);
    assert_eq!(body["fullHeight"], 100);
    assert_eq!(body["status"], "halted");
    // `IndexerHaltReason` serializes as kebab-case (`db-corruption`).
    assert_eq!(body["haltReason"], "db-corruption");
}

#[tokio::test]
async fn indexed_height_404s_when_indexer_not_plumbed() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 0 });
    let app = router(
        read,
        None,
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/blockchain/indexedHeight")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "the entire /blockchain/* router must be unmounted when the indexer is not plumbed",
    );
}

// ---- helpers ------------------------------------------------------

async fn get_json(app: axum::Router, path: &str) -> serde_json::Value {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET {path} must 200");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("indexedHeight response is JSON")
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

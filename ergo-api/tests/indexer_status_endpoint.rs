//! `GET /api/v1/indexer/status` — the operator health surface (superset of
//! `/blockchain/indexedHeight`, which stays pinned to its Scala-parity
//! shape). Like indexedHeight it is always-200 and never status-gated: it
//! must answer while the index is syncing, repairing, or halted — that is
//! exactly when the operator needs it. These tests pin the wire shape across
//! the status variants, the repair/totals sub-objects, and the 404 on
//! indexer-less wiring.

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
use ergo_indexer::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerHaltReason,
    IndexerHandle, IndexerHealthDto, IndexerQuery, IndexerStatus, Page, SortDir, TemplateHash,
    TokenId, TreeHash, TxId,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// Stub that reports `CaughtUp` with a caller-chosen health block. Only
/// `indexed_height`/`status`/`health` are reachable through
/// `/api/v1/indexer/status`; every other trait method is `unreachable!` so a
/// routing regression that suddenly touches the read surface fails loudly.
struct HealthStub(IndexerHealthDto);

impl IndexerQuery for HealthStub {
    fn indexed_height(&self) -> u64 {
        900_000
    }
    fn status(&self) -> IndexerStatus {
        IndexerStatus::CaughtUp
    }
    fn health(&self) -> IndexerHealthDto {
        self.0.clone()
    }
    fn box_by_id(&self, _: &BoxId) -> Option<IndexedBoxDto> {
        unreachable!("indexer/status never reads boxes")
    }
    fn box_by_global_index(&self, _: u64) -> Option<IndexedBoxDto> {
        unreachable!()
    }
    fn boxes_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedBoxDto> {
        unreachable!()
    }
    fn tx_by_id(&self, _: &TxId) -> Option<IndexedTxDto> {
        unreachable!()
    }
    fn tx_by_global_index(&self, _: u64) -> Option<IndexedTxDto> {
        unreachable!()
    }
    fn txs_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedTxDto> {
        unreachable!()
    }
    fn address_balance(&self, _: &TreeHash) -> Option<BalanceDto> {
        unreachable!()
    }
    fn address_txs_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedTxDto> {
        unreachable!()
    }
    fn address_boxes_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        unreachable!()
    }
    fn address_unspent_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        unreachable!()
    }
    fn address_total_txs(&self, _: &TreeHash) -> u64 {
        unreachable!()
    }
    fn address_total_boxes(&self, _: &TreeHash) -> u64 {
        unreachable!()
    }
    fn template_boxes_paged(&self, _: &TemplateHash, _: Page) -> Vec<IndexedBoxDto> {
        unreachable!()
    }
    fn template_unspent_paged(&self, _: &TemplateHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        unreachable!()
    }
    fn template_total_boxes(&self, _: &TemplateHash) -> u64 {
        unreachable!()
    }
    fn token_by_id(&self, _: &TokenId) -> Option<IndexedTokenDto> {
        unreachable!()
    }
    fn tokens_by_ids(&self, _: &[TokenId]) -> Vec<IndexedTokenDto> {
        unreachable!()
    }
    fn token_boxes_paged(&self, _: &TokenId, _: Page) -> Vec<IndexedBoxDto> {
        unreachable!()
    }
    fn token_unspent_paged(&self, _: &TokenId, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        unreachable!()
    }
    fn token_total_boxes(&self, _: &TokenId) -> u64 {
        unreachable!()
    }
}

#[tokio::test]
async fn indexer_status_reports_syncing_with_default_health() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 1234 });
    let indexer = IndexerHandle::syncing(500);
    let app = router(
        read,
        None,
        None,
        Some(Arc::new(indexer) as Arc<dyn IndexerQuery>),
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let body = get_json(app, "/api/v1/indexer/status").await;
    assert_eq!(body["status"], "syncing");
    assert_eq!(body["indexedHeight"], 500);
    assert_eq!(body["fullHeight"], 1234);
    assert!(
        body.get("haltReason").is_none(),
        "no haltReason while syncing"
    );
    // Storeless handle → healthy-default repair block. `driftSkips` is a
    // process-global diagnostic counter shared across tests in this binary,
    // so assert presence/type rather than an exact value.
    assert_eq!(body["repair"]["pending"], false);
    assert_eq!(body["repair"]["skipped"], 0);
    assert!(
        body["repair"].get("nextGi").is_none(),
        "nextGi omitted when no rebuild is running"
    );
    assert!(body["repair"]["driftSkips"].is_u64());
    assert_eq!(body["totals"]["boxes"], 0);
    assert_eq!(body["totals"]["txs"], 0);
}

#[tokio::test]
async fn indexer_status_reports_halted_with_reason() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { full_height: 100 });
    let indexer = IndexerHandle::halted(IndexerHaltReason::DbCorruption);
    let app = router(
        read,
        None,
        None,
        Some(Arc::new(indexer) as Arc<dyn IndexerQuery>),
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let body = get_json(app, "/api/v1/indexer/status").await;
    assert_eq!(body["status"], "halted");
    assert_eq!(body["haltReason"], "db-corruption");
    assert_eq!(body["indexedHeight"], 0);
    // A halted (storeless) handle still serves the health block — the
    // endpoint must not error exactly when the operator needs it most.
    assert_eq!(body["repair"]["pending"], false);
}

#[tokio::test]
async fn indexer_status_reports_caught_up() {
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

    let body = get_json(app, "/api/v1/indexer/status").await;
    assert_eq!(body["status"], "caughtUp");
    assert!(body.get("haltReason").is_none());
}

/// Pin the full wire contract for a degraded index: an in-flight rebuild
/// (pending + cursor), a prior honest-marker skip count, drift diagnostics,
/// and real totals. Uses a bespoke stub because `IndexerHandle` only
/// surfaces these with a real redb store behind it.
#[tokio::test]
async fn indexer_status_pins_degraded_health_wire_shape() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState {
        full_height: 900_000,
    });
    let stub = HealthStub(IndexerHealthDto {
        repair_pending: true,
        repair_next_gi: Some(12_345),
        repair_skipped: 7,
        drift_skips: 3,
        global_boxes: 56_000_000,
        global_txs: 9_500_000,
    });
    let app = router(
        read,
        None,
        None,
        Some(Arc::new(stub) as Arc<dyn IndexerQuery>),
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let body = get_json(app, "/api/v1/indexer/status").await;
    assert_eq!(
        body["status"], "caughtUp",
        "caught up yet degraded — the whole point"
    );
    assert_eq!(body["repair"]["pending"], true);
    assert_eq!(
        body["repair"]["nextGi"], 12_345,
        "rebuild cursor surfaces as nextGi"
    );
    assert_eq!(body["repair"]["skipped"], 7);
    assert_eq!(body["repair"]["driftSkips"], 3);
    assert_eq!(body["totals"]["boxes"], 56_000_000_u64);
    assert_eq!(body["totals"]["txs"], 9_500_000_u64);
}

/// `pending=true` with `nextGi` ABSENT = phase-0 wipe still running: a
/// consumer must be able to distinguish "queued/wiping" from "0 boxes done"
/// (`nextGi: 0`, also valid — written the moment phase 1 starts).
#[tokio::test]
async fn indexer_status_omits_next_gi_during_wipe_phase() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState {
        full_height: 900_000,
    });
    let stub = HealthStub(IndexerHealthDto {
        repair_pending: true,
        repair_next_gi: None,
        ..IndexerHealthDto::default()
    });
    let app = router(
        read,
        None,
        None,
        Some(Arc::new(stub) as Arc<dyn IndexerQuery>),
        ergo_ser::address::NetworkPrefix::Mainnet,
    );

    let body = get_json(app, "/api/v1/indexer/status").await;
    assert_eq!(body["repair"]["pending"], true);
    assert!(
        body["repair"].get("nextGi").is_none(),
        "wipe phase = pending with the cursor omitted"
    );
}

#[tokio::test]
async fn indexer_status_404s_when_indexer_not_plumbed() {
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
                .uri("/api/v1/indexer/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "the route must be unmounted on indexer-less wiring (UI reads 404 as disabled)",
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
    serde_json::from_slice(&bytes).expect("indexer/status response is JSON")
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

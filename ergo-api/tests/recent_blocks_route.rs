//! `GET /api/v1/blocks/recent` route behavior.
//!
//! Backs the dashboard cockpit's "recent blocks" list. Drives the operator
//! router via `tower::ServiceExt::oneshot` against a `NodeReadState` stub
//! whose `recent_blocks` override returns a fixed newest-first list, so we
//! can pin: 200 + array, newest-first order, exact snake_case field names,
//! the `n` query bound + clamp, and that the route mounts with no indexer /
//! chain handle (it lives on the operator router, not the indexer-gated
//! `/blockchain/*` subtree).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiRecentBlock, ApiStatus, ApiSyncStatus, ApiTip,
    ApiWeightFunction, HealthStatus, SyncStateLabel,
};
use tower::ServiceExt;

struct StubReadState {
    recent: Vec<ApiRecentBlock>,
}

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
    // Mimics the production snapshot clone: hand back the precomputed tail,
    // truncated to the (already-clamped) `n` the handler passes.
    fn recent_blocks(&self, n: u32) -> Vec<ApiRecentBlock> {
        self.recent.iter().take(n as usize).cloned().collect()
    }
}

fn block(height: u32) -> ApiRecentBlock {
    ApiRecentBlock {
        height,
        header_id: format!("{height:064x}"),
        ts_unix_ms: 1_700_000_000_000 + height as u64,
        txs: height,
        size_bytes: 1000 + height as u64,
    }
}

async fn get(uri: &str, recent: Vec<ApiRecentBlock>) -> (StatusCode, serde_json::Value) {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { recent });
    // No chain / indexer handles — proves the route mounts on the bare
    // operator router.
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
                .method(Method::GET)
                .uri(uri)
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

#[tokio::test]
async fn recent_blocks_returns_newest_first_with_exact_fields() {
    let (status, body) = get("/api/v1/blocks/recent", vec![block(101), block(100)]).await;
    assert_eq!(status, StatusCode::OK);
    let arr = body.as_array().expect("array body");
    assert_eq!(arr.len(), 2);
    // Newest first.
    assert_eq!(arr[0]["height"].as_u64(), Some(101));
    assert_eq!(arr[1]["height"].as_u64(), Some(100));
    // Exact snake_case field set + values on the newest entry.
    let b = &arr[0];
    assert_eq!(
        b["header_id"].as_str(),
        Some(format!("{:064x}", 101).as_str())
    );
    assert_eq!(b["ts_unix_ms"].as_u64(), Some(1_700_000_000_000 + 101));
    assert_eq!(b["txs"].as_u64(), Some(101));
    assert_eq!(b["size_bytes"].as_u64(), Some(1000 + 101));
}

#[tokio::test]
async fn recent_blocks_respects_n_and_clamps() {
    // ?n=1 → exactly one (the newest).
    let (_, one) = get("/api/v1/blocks/recent?n=1", vec![block(101), block(100)]).await;
    assert_eq!(one.as_array().unwrap().len(), 1);
    assert_eq!(one.as_array().unwrap()[0]["height"].as_u64(), Some(101));
    // ?n=0 → clamped up to 1.
    let (_, zero) = get("/api/v1/blocks/recent?n=0", vec![block(101), block(100)]).await;
    assert_eq!(zero.as_array().unwrap().len(), 1);
    // ?n=999 → clamped to 32; only 2 available, so 2 (no error).
    let (status, many) = get("/api/v1/blocks/recent?n=999", vec![block(101), block(100)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(many.as_array().unwrap().len(), 2);
    // ?n=-1 → a numeric out-of-range value clamps to 1, not the default.
    let (_, neg) = get("/api/v1/blocks/recent?n=-1", vec![block(101), block(100)]).await;
    assert_eq!(neg.as_array().unwrap().len(), 1);
    assert_eq!(neg.as_array().unwrap()[0]["height"].as_u64(), Some(101));
    // ?n=abc → non-numeric falls back to the default (10); only 2 available.
    let (status_abc, abc) = get("/api/v1/blocks/recent?n=abc", vec![block(101), block(100)]).await;
    assert_eq!(status_abc, StatusCode::OK);
    assert_eq!(abc.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn recent_blocks_mounts_without_indexer_and_serves_empty() {
    // Operator-router route: must mount + serve `[]` with no chain/indexer
    // handle (regression guard against hanging it off the gated subtree).
    let (status, body) = get("/api/v1/blocks/recent", Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0);
}

//! Behaviour of the Matrix (input blocks) Scala-compat routes (Plan 2,
//! task 7): `/blocks/bestInputBlock`, `/blocks/bestInputChain`,
//! `/blocks/{id}/inputBlockTransactions`,
//! `/blocks/{id}/inputBlockTransactionIds`.
//!
//! Mirrors `difficulty_history_route.rs`'s conditional-mount contract:
//! with `NodeReadState::input_blocks()` answering `None` (the default —
//! `[input_blocks] enabled = false`) the four routes are entirely
//! absent (404, matching an unmounted route, not merely an empty body);
//! wired to `Some(_)` they serve the exact Scala JSON shapes copied from
//! `BlocksApiRoute.scala`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ergo_api::compat::types::ScalaTransaction;
use ergo_api::compat::ApiInputBlocks;
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, HealthStatus,
    SyncStateLabel,
};
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- helpers -----

const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BEST_HEADER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn stub_tx(id: &str) -> ScalaTransaction {
    ScalaTransaction {
        id: id.to_string(),
        inputs: Vec::new(),
        data_inputs: Vec::new(),
        outputs: Vec::new(),
        size: 0,
    }
}

/// Read-state stub. `input_blocks` controls the Task 7 surface under
/// test; every other method returns a minimal fixed shape (unused by
/// these routes, but `router()` needs a `NodeReadState`).
struct StubReadState {
    input_blocks: Option<ApiInputBlocks>,
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
            best_input_block_id: None,
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
                height: 10,
                header_id: BEST_HEADER.to_string(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: String::new(),
            },
            best_full_block: ApiFullBlockRef {
                height: 10,
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
            best_header_height: 10,
            best_full_block_height: 10,
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
            weight_function: ergo_api::types::ApiWeightFunction::Cost,
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
    fn input_blocks(&self) -> Option<ApiInputBlocks> {
        self.input_blocks.clone()
    }
}

fn build_app(input_blocks: Option<ApiInputBlocks>) -> axum::Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState { input_blocks });
    router(read, None, None, None, NetworkPrefix::Mainnet)
}

fn wired_input_blocks() -> ApiInputBlocks {
    let mut blocks = HashMap::new();
    blocks.insert(ID_A.to_string(), vec![stub_tx("t1"), stub_tx("t2")]);
    ApiInputBlocks {
        best_input_block_id: Some(ID_A.to_string()),
        best_chain: vec![ID_A.to_string(), ID_B.to_string()],
        blocks,
    }
}

async fn get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, body)
}

// ----- happy path -----

#[tokio::test]
async fn best_input_block_reports_best_ordering_and_best_input_block() {
    let app = build_app(Some(wired_input_blocks()));
    let (status, body) = get(app, "/blocks/bestInputBlock").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["bestOrdering"], BEST_HEADER);
    assert_eq!(body["bestInputBlock"], ID_A);
}

#[tokio::test]
async fn best_input_chain_reports_tip_first_chain() {
    let app = build_app(Some(wired_input_blocks()));
    let (status, body) = get(app, "/blocks/bestInputChain").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["bestOrdering"], BEST_HEADER);
    assert_eq!(
        body["bestInputBlocks"],
        serde_json::json!([ID_A, ID_B]),
        "tip first, as stored"
    );
}

#[tokio::test]
async fn input_block_transactions_serves_the_stored_bodies() {
    let app = build_app(Some(wired_input_blocks()));
    let (status, body) = get(app, &format!("/blocks/{ID_A}/inputBlockTransactions")).await;
    assert_eq!(status, StatusCode::OK);
    let txs = body.as_array().expect("array of transactions");
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[0]["id"], "t1");
    assert_eq!(txs[1]["id"], "t2");
}

#[tokio::test]
async fn input_block_transaction_ids_serves_just_the_ids() {
    let app = build_app(Some(wired_input_blocks()));
    let (status, body) = get(app, &format!("/blocks/{ID_A}/inputBlockTransactionIds")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!(["t1", "t2"]));
}

// ----- error paths -----

#[tokio::test]
async fn unknown_input_block_id_404s_on_both_id_keyed_routes() {
    let app = build_app(Some(wired_input_blocks()));
    let (status, _) = get(app, &format!("/blocks/{ID_B}/inputBlockTransactions")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "ID_B is on the best chain but the node holds no body record for it"
    );

    let app = build_app(Some(wired_input_blocks()));
    let (status, _) = get(
        app,
        "/blocks/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/inputBlockTransactionIds",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn routes_absent_when_input_blocks_disabled() {
    for path in [
        "/blocks/bestInputBlock",
        "/blocks/bestInputChain",
        &format!("/blocks/{ID_A}/inputBlockTransactions"),
        &format!("/blocks/{ID_A}/inputBlockTransactionIds"),
    ] {
        let app = build_app(None);
        let (status, _) = get(app, path).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} must be unmounted (not merely empty) when input_blocks() is None"
        );
    }
}

#[tokio::test]
async fn best_input_block_defaults_to_empty_string_not_null_when_none_leads() {
    let app = build_app(Some(ApiInputBlocks::default()));
    let (status, body) = get(app, "/blocks/bestInputBlock").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["bestInputBlock"], "",
        "Scala's Option.getOrElse(\"\") default, not null"
    );
}

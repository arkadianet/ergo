//! Route-level integration tests for the `/api/v1/script/*` ErgoScript
//! playground (`dev-docs/v1-design-fragments/script-tooling.md`).
//!
//! Drives the wired endpoints over `oneshot` through the real
//! `script_router` (governor `Compute` layer + T0 `Tier::Public` gate):
//! `compile` (happy round-trip + error envelope), `execute`/`cost` on a
//! trivial script, the **cost-cap anti-DoS bound** (an expensive script is
//! rejected with `cost_limit`, never hangs), `inspect`, `diff` →
//! `oracle_unavailable` (no oracle configured), and `simulate` →
//! `chain_reader_unavailable` (no chain reader). Loopback peer ⇒ governor-exempt
//! so the tests never flake on rate limits.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_api::v1::{script_router, ScriptConfig, ScriptState, V1AuthConfig};
use ergo_ser::address::{decode_address_to_tree_bytes, NetworkPrefix};
use tower::ServiceExt;

const HEIGHT: u32 = 900_000;
const HEX_64: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// ----- harness ------------------------------------------------------------

fn app(with_chain: bool) -> Router {
    let _ = with_chain; // chain reader intentionally None in these tests.
    let state = ScriptState {
        read: Arc::new(StubRead),
        chain: None,
        network: NetworkPrefix::Mainnet,
        oracle: None,
        config: ScriptConfig::default(),
    };
    let governor =
        ergo_api::v1::governor::Governor::new(Default::default()).expect("valid governor config");
    let auth = V1AuthConfig::new(None).into_shared();
    script_router(state, governor, auth)
}

async fn post(uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    // Loopback → governor-exempt, so tests never flake on rate limits.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let resp = app(false).oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

fn reason(v: &serde_json::Value) -> &str {
    v["error"]["reason"].as_str().unwrap_or("<none>")
}

// ----- compile ------------------------------------------------------------

#[tokio::test]
async fn compile_known_source_produces_roundtrippable_address() {
    let (status, body) = post(
        "/api/v1/script/compile",
        serde_json::json!({ "source": "sigmaProp(HEIGHT > 100)" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let ergo_tree = body["ergo_tree"].as_str().expect("ergo_tree hex");
    // A non-bare (HEIGHT-guard) root segregates: header byte 0x10.
    assert!(
        ergo_tree.starts_with("10"),
        "expected segregated header: {ergo_tree}"
    );

    // The P2S address must decode back to exactly the compiled tree bytes — a
    // real oracle round-trip, not a self-check on the compiler output.
    let p2s = body["p2s_address"].as_str().expect("p2s_address");
    let decoded =
        decode_address_to_tree_bytes(p2s, NetworkPrefix::Mainnet).expect("p2s address decodes");
    assert_eq!(
        hex::encode(decoded),
        ergo_tree,
        "p2s must round-trip to the tree"
    );

    assert!(body["typed_ast"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(body["p2sh_address"].as_str().is_some());
}

#[tokio::test]
async fn compile_bad_source_is_invalid_ergo_tree_envelope() {
    let (status, body) = post(
        "/api/v1/script/compile",
        serde_json::json!({ "source": "this is not ergoscript )(" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(reason(&body), "invalid_ergo_tree");
    // The error detail carries the machine-readable phase (fragment §4.7).
    assert!(
        body["error"]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("phase=")),
        "detail must carry the compile phase: {body}"
    );
}

// ----- execute / cost -----------------------------------------------------

#[tokio::test]
async fn execute_trivial_height_guard_reduces_true() {
    let (status, body) = post(
        "/api/v1/script/execute",
        serde_json::json!({
            "source": "sigmaProp(HEIGHT > 100)",
            "context": { "height": 200 }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["result"], serde_json::json!(true));
    assert_eq!(body["within_block_limit"], serde_json::json!(true));
    assert!(body["reduced_to"].as_str().is_some());
}

#[tokio::test]
async fn cost_trivial_reports_within_block_limit() {
    let (status, body) = post(
        "/api/v1/script/cost",
        serde_json::json!({
            "source": "sigmaProp(HEIGHT > 100)",
            "context": { "height": 200 }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["within_block_limit"], serde_json::json!(true));
    assert!(body["total_cost"].is_u64());
    assert!(body["breakdown"].is_array());
}

#[tokio::test]
async fn execute_cost_cap_rejects_expensive_script_not_hang() {
    // A per-request `max_cost` of 1 block-cost unit (10 JIT) is smaller than
    // any real reduction — the enforcing CostAccumulator rejects with
    // `cost_limit` instead of running (and never hangs).
    let (status, body) = post(
        "/api/v1/script/execute",
        serde_json::json!({
            "source": "sigmaProp(HEIGHT > 100 && HEIGHT > 101 && HEIGHT > 102 && HEIGHT > 103)",
            "context": { "height": 200 },
            "max_cost": 1
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(reason(&body), "cost_limit");
}

// ----- inspect ------------------------------------------------------------

#[tokio::test]
async fn inspect_ergo_tree_returns_structured_view() {
    // First compile a tree, then inspect its bytes.
    let (_, compiled) = post(
        "/api/v1/script/compile",
        serde_json::json!({ "source": "sigmaProp(HEIGHT > 100)" }),
    )
    .await;
    let ergo_tree = compiled["ergo_tree"].as_str().unwrap().to_string();

    let (status, body) = post(
        "/api/v1/script/inspect",
        serde_json::json!({ "ergo_tree": ergo_tree }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["constant_segregation"], serde_json::json!(true));
    assert!(body["constants"].is_array());
    assert!(body["opcode_count"].as_u64().unwrap() >= 1);
    assert!(body["p2s_address"].as_str().is_some());
}

// ----- diff (oracle unconfigured) -----------------------------------------

#[tokio::test]
async fn diff_without_oracle_is_oracle_unavailable() {
    let (status, body) = post(
        "/api/v1/script/diff",
        serde_json::json!({
            "source": "sigmaProp(HEIGHT > 100)",
            "context": { "height": 200 }
        }),
    )
    .await;
    // The canonical `Reason` enum maps `oracle_unavailable` to 501.
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "body: {body}");
    assert_eq!(reason(&body), "oracle_unavailable");
}

// ----- simulate (chain reader unwired) ------------------------------------

#[tokio::test]
async fn simulate_without_chain_is_chain_reader_unavailable() {
    let (status, body) = post(
        "/api/v1/script/simulate",
        serde_json::json!({ "box_id": HEX_64 }),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
    assert_eq!(reason(&body), "chain_reader_unavailable");
}

// ----- stub read state ----------------------------------------------------

struct StubRead;
impl NodeReadState for StubRead {
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
            best_header_height: HEIGHT,
            best_full_block_height: HEIGHT,
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
                height: HEIGHT,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: String::new(),
            },
            best_full_block: ApiFullBlockRef {
                height: HEIGHT,
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
            best_header_height: HEIGHT,
            best_full_block_height: HEIGHT,
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

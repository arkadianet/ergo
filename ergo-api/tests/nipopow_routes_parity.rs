//! Route-level parity for the `/nipopow/*` serve surface.
//!
//! Response BODIES are pinned by the captured Scala fixtures under
//! `test-vectors/mainnet/nipopow/` (same captures that pin the DTO
//! shapes in `ergo-rest-json/tests/nipopow_json_fixtures.rs`); this
//! file additionally pins ROUTING + STATUS + ERROR-ENVELOPE behavior,
//! oracle-probed against the live Scala node (:9053, 2026-07-05):
//! - malformed modifier id → 400 "Wrong modifierId format"
//!   (`popowHeaderById` and the anchored proof route)
//! - unknown id / out-of-range height → 404 with `detail: null`
//! - `k = 0` → 400 "requirement failed: 0 < 1" (Scala-verbatim)
//! - `m = 0` → 400 (Scala's detail is a bare JVM artifact "2"; ours is
//!   a meaningful message — status-only parity, documented deviation)
//! - prover failure (e.g. unknown anchor) → 400
//!
//! Known repo-wide envelope deviation: our `reason` is `bad-request`
//! where Scala emits `bad.request` — inherited from the shared
//! `bad_request` helper the `/blocks/*` routes already use.

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
use ergo_rest_json::types::{ScalaNipopowProof, ScalaPopowHeader};
use tower::ServiceExt;

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/../test-vectors/mainnet/nipopow/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn fixture_popow_header() -> (String, ScalaPopowHeader, serde_json::Value) {
    let raw = fixture("popowHeaderByHeight_1000.json");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let id = value["header"]["id"].as_str().unwrap().to_string();
    let dto: ScalaPopowHeader = serde_json::from_str(&raw).unwrap();
    (id, dto, value)
}

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

    fn header_ids_at_height(&self, _height: u32) -> Vec<String> {
        Vec::new()
    }

    fn full_block_by_id(&self, _header_id_hex: &str) -> Option<ScalaFullBlock> {
        None
    }

    fn nipopow_header_by_id(&self, header_id_hex: &str) -> Option<ScalaPopowHeader> {
        let (id, dto, _) = fixture_popow_header();
        (header_id_hex == id).then_some(dto)
    }

    fn nipopow_header_at_height(&self, height: u32) -> Option<ScalaPopowHeader> {
        (height == 1000).then(|| fixture_popow_header().1)
    }

    fn nipopow_proof(
        &self,
        m: u32,
        k: u32,
        header_id_hex: Option<&str>,
    ) -> Result<ScalaNipopowProof, String> {
        assert!(k >= 1, "handler must reject k=0 before the bridge");
        assert!(m >= 1, "handler must reject m=0 before the bridge");
        let (anchor_id, _, _) = fixture_popow_header();
        match (m, k, header_id_hex) {
            // Both the tip (2-segment) and anchored (3-segment) forms
            // return the one comprehensive fixture — the route test
            // exercises routing + handler serialization; proof-content
            // correctness rides the dedicated oracle tests + the T4 live
            // differential.
            (6, 10, None) => Ok(serde_json::from_str(&fixture("proof_m6_k10.json")).unwrap()),
            (6, 10, Some(id)) if id == anchor_id => {
                Ok(serde_json::from_str(&fixture("proof_m6_k10.json")).unwrap())
            }
            // Unknown anchor — Scala surfaces the prover failure as 400
            // ("None.get"); ours carries a meaningful message.
            _ => Err("proof anchor not found".to_string()),
        }
    }
}

async fn json_get(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 4 << 20).await.unwrap();
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

const UNKNOWN_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn not_found_null() -> serde_json::Value {
    serde_json::json!({"error": 404, "reason": "not-found", "detail": null})
}

#[tokio::test]
async fn popow_header_by_id_matches_fixture() {
    let (id, _, expected) = fixture_popow_header();
    let (status, ours) = json_get(build_app(), &format!("/nipopow/popowHeaderById/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(expected, ours);
}

#[tokio::test]
async fn popow_header_by_id_malformed_is_scala_400() {
    let (status, body) = json_get(build_app(), "/nipopow/popowHeaderById/zzzz").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["detail"], "Wrong modifierId format");
}

#[tokio::test]
async fn popow_header_by_id_unknown_is_404_null_detail() {
    let (status, body) = json_get(
        build_app(),
        &format!("/nipopow/popowHeaderById/{UNKNOWN_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, not_found_null());
}

#[tokio::test]
async fn popow_header_by_height_matches_fixture() {
    let (_, _, expected) = fixture_popow_header();
    let (status, ours) = json_get(build_app(), "/nipopow/popowHeaderByHeight/1000").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(expected, ours);
}

#[tokio::test]
async fn popow_header_by_height_zero_and_past_tip_are_404_null() {
    for path in [
        "/nipopow/popowHeaderByHeight/0",
        "/nipopow/popowHeaderByHeight/99999999",
    ] {
        let (status, body) = json_get(build_app(), path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body, not_found_null(), "{path}");
    }
}

#[tokio::test]
async fn proof_default_params_matches_fixture() {
    let expected: serde_json::Value = serde_json::from_str(&fixture("proof_m6_k10.json")).unwrap();
    let (status, ours) = json_get(build_app(), "/nipopow/proof/6/10").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(expected, ours);
}

#[tokio::test]
async fn proof_anchored_matches_fixture() {
    let (id, _, _) = fixture_popow_header();
    let expected: serde_json::Value = serde_json::from_str(&fixture("proof_m6_k10.json")).unwrap();
    let (status, ours) = json_get(build_app(), &format!("/nipopow/proof/6/10/{id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(expected, ours);
}

#[tokio::test]
async fn proof_k_zero_is_scala_verbatim_requirement_failure() {
    // Oracle-probed on both the 2- and 3-segment forms.
    let (id, _, _) = fixture_popow_header();
    for path in [
        "/nipopow/proof/6/0".to_string(),
        format!("/nipopow/proof/6/0/{id}"),
    ] {
        let (status, body) = json_get(build_app(), &path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(body["detail"], "requirement failed: 0 < 1", "{path}");
    }
}

#[tokio::test]
async fn proof_m_zero_is_400() {
    let (status, body) = json_get(build_app(), "/nipopow/proof/0/5").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Scala's detail here is the bare JVM artifact "2"; ours is
    // meaningful. Status parity is the contract.
    assert_eq!(body["error"], 400);
}

#[tokio::test]
async fn proof_m_over_cap_is_400() {
    // Scala 200s here (no cap); we diverge defensively — see
    // MAX_NIPOPOW_M. The guard fires before the prover runs, so this
    // pins the REST-edge ceiling independent of chain state.
    let (status, body) = json_get(build_app(), "/nipopow/proof/101/10").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], 400);
}

#[tokio::test]
async fn proof_k_over_cap_is_400() {
    let (status, body) = json_get(build_app(), "/nipopow/proof/6/101").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], 400);
}

#[tokio::test]
async fn proof_unknown_anchor_is_400() {
    let (status, body) = json_get(build_app(), &format!("/nipopow/proof/6/10/{UNKNOWN_ID}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], 400);
}

#[tokio::test]
async fn proof_malformed_anchor_is_scala_400() {
    let (status, body) = json_get(build_app(), "/nipopow/proof/6/10/zzzz").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["detail"], "Wrong modifierId format");
}

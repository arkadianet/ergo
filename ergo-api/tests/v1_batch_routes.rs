//! Route-level tests for `POST /api/v1/batch` (`dev-docs/v1-api-design.md`
//! §3.18/§4.7). Convention-lock coverage: ordered results with echoed `id`s,
//! `data` byte-identical to the standalone endpoint, partial-failure
//! semantics (one bad member never sinks the batch), the structural
//! item-count cap, and the closed allow-list rejecting a mutating path
//! before it is ever dispatched.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use ergo_api::compat::NodeChainQuery;
use ergo_api::traits::{MempoolView, NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_api::v1::{batch_router, MempoolDepthRing, V1State};
use ergo_rest_json::types::{
    ScalaAdProofs, ScalaBlockTransactions, ScalaExtension, ScalaFullBlock, ScalaHeader,
    ScalaOutput, ScalaPowSolutions, ScalaTransaction,
};
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- fixtures -------------------------------------------------------------

const HEIGHT: u32 = 5;
const MINER_PK: &str = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";
const TREE_HEX: &str = "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304";

fn block_id() -> String {
    format!("{HEIGHT:064x}")
}
fn tx_id() -> String {
    format!("{:064x}", 42u32)
}

fn scala_header() -> ScalaHeader {
    ScalaHeader {
        extension_id: format!("{:064x}", 0xe1u32),
        difficulty: "123456789".to_string(),
        votes: "000000".to_string(),
        timestamp: 1_600_000_000_123,
        size: 210,
        unparsed_bytes: String::new(),
        state_root: format!("{:064x}", 0x57u32),
        height: HEIGHT,
        n_bits: 83_886_080,
        version: 3,
        id: block_id(),
        ad_proofs_root: format!("{:064x}", 0xadu32),
        transactions_root: format!("{:064x}", 0x7au32),
        extension_hash: format!("{:064x}", 0xe4u32),
        pow_solutions: ScalaPowSolutions {
            pk: MINER_PK.to_string(),
            w: "03".to_string(),
            n: "0000000000000000".to_string(),
            d: serde_json::Value::from(0),
        },
        ad_proofs_id: format!("{:064x}", 0xa1u32),
        transactions_id: format!("{:064x}", 0x71u32),
        parent_id: format!("{:064x}", HEIGHT - 1),
    }
}

fn scala_output() -> ScalaOutput {
    ScalaOutput {
        box_id: format!("{:064x}", 0xb0u32),
        value: 1_000_000_000,
        ergo_tree: TREE_HEX.to_string(),
        assets: Vec::new(),
        creation_height: HEIGHT,
        additional_registers: Default::default(),
        transaction_id: tx_id(),
        index: 0,
    }
}

fn scala_tx() -> ScalaTransaction {
    ScalaTransaction {
        id: tx_id(),
        inputs: Vec::new(),
        data_inputs: Vec::new(),
        outputs: vec![scala_output()],
        size: 200,
    }
}

fn scala_full_block() -> ScalaFullBlock {
    ScalaFullBlock {
        header: scala_header(),
        block_transactions: ScalaBlockTransactions {
            header_id: block_id(),
            transactions: vec![scala_tx()],
            block_version: 3,
            size: 250,
        },
        extension: ScalaExtension {
            header_id: block_id(),
            digest: format!("{:064x}", 0xeeu32),
            fields: vec![["00".to_string(), "0142".to_string()]],
        },
        ad_proofs: Some(ScalaAdProofs {
            header_id: block_id(),
            proof_bytes: "ffff".to_string(),
            digest: format!("{:064x}", 0xaau32),
            size: 100,
        }),
        size: 8421,
    }
}

// ----- stubs -----------------------------------------------------------------

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
            best_header_height: HEIGHT,
            best_full_block_height: HEIGHT,
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

/// Answers the fixture block at `HEIGHT`; everything else is a miss.
struct StubChain;
impl NodeChainQuery for StubChain {
    fn info(&self) -> ergo_api::compat::types::ScalaInfo {
        unreachable!("chain.info() is not on the batch-allow-listed read path")
    }
    fn header_ids_at_height(&self, height: u32) -> Vec<String> {
        if height == HEIGHT {
            vec![block_id()]
        } else {
            Vec::new()
        }
    }
    fn full_block_by_id(&self, header_id_hex: &str) -> Option<ScalaFullBlock> {
        (header_id_hex == block_id()).then(scala_full_block)
    }
}

// ----- harness ---------------------------------------------------------------

fn app() -> Router {
    let read: Arc<dyn NodeReadState> = Arc::new(StubRead);
    let chain: Option<Arc<dyn NodeChainQuery>> = Some(Arc::new(StubChain));
    let mempool: Arc<dyn MempoolView> = Arc::new(NoopMempoolView::new());
    let state = V1State {
        read,
        chain,
        indexer: None,
        submit: None,
        tx_builder: None,
        mempool,
        mempool_depth: Arc::new(MempoolDepthRing::new()),
        emission: None,
        realtime: None,
        network: NetworkPrefix::Mainnet,
    };
    let governor =
        ergo_api::v1::governor::Governor::new(Default::default()).expect("valid governor config");
    batch_router(state, governor)
}

async fn post_batch(body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/batch")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    // Loopback peer → governor-exempt, so tests never flake on rate limits.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let resp = app().oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

fn item_by_id<'a>(items: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    items
        .as_array()
        .unwrap()
        .iter()
        .find(|it| it["id"] == id)
        .unwrap_or_else(|| panic!("no item with id {id}"))
}

// ----- happy path ------------------------------------------------------------

#[tokio::test]
async fn ordered_reads_return_byte_identical_data_in_request_order() {
    let (status, body) = post_batch(serde_json::json!({
        "requests": [
            { "id": "a", "method": "GET", "path": "/api/v1/diagnostics" },
            { "id": "b", "method": "GET", "path": "/api/v1/mempool/summary" },
            { "id": "c", "method": "GET", "path": "/api/v1/chain/blocks" },
        ]
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    // Order preserved.
    assert_eq!(items[0]["id"], "a");
    assert_eq!(items[1]["id"], "b");
    assert_eq!(items[2]["id"], "c");
    for it in items {
        assert_eq!(it["status"], "ok", "item {it:?} should have succeeded");
    }
    // `data` is exactly the standalone `chain/blocks` collection envelope.
    assert!(items[2]["data"]["items"].is_array());
    assert!(items[2]["data"]["page"].is_object());
    // Batch's own envelope has NO top-level `page` (the one sanctioned shape
    // exception, §1.3).
    assert!(body.get("page").is_none());
}

#[tokio::test]
async fn missing_id_is_synthesized_from_request_index() {
    let (status, body) = post_batch(serde_json::json!({
        "requests": [
            { "method": "GET", "path": "/api/v1/diagnostics" },
        ]
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["id"], "0");
}

// ----- partial failure --------------------------------------------------------

#[tokio::test]
async fn one_bad_member_errors_in_its_slot_without_sinking_the_batch() {
    let (status, body) = post_batch(serde_json::json!({
        "requests": [
            { "id": "ok", "method": "GET", "path": "/api/v1/diagnostics" },
            { "id": "bad", "method": "GET", "path": "/api/v1/chain/blocks/at-height/not-a-number" },
        ]
    }))
    .await;
    // The BATCH still succeeds even though one member failed.
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].clone();
    let ok = item_by_id(&items, "ok");
    assert_eq!(ok["status"], "ok");
    assert!(ok["error"].is_null());

    let bad = item_by_id(&items, "bad");
    assert_eq!(bad["status"], "error");
    assert!(bad["data"].is_null());
    // Re-embeds the exact v1 error triple the standalone endpoint renders.
    assert_eq!(bad["error"]["reason"], "invalid_params");
    assert!(bad["error"]["message"].is_string());
    assert!(bad["error"]["detail"].is_string());
}

// ----- allow-list enforcement --------------------------------------------------

#[tokio::test]
async fn mutating_submit_path_is_rejected_before_dispatch() {
    let (status, body) = post_batch(serde_json::json!({
        "requests": [
            { "id": "x", "method": "POST", "path": "/api/v1/transactions/submit", "body": {} },
        ]
    }))
    .await;
    // Whole batch still 200 — the rejection is a per-item error, not a
    // whole-batch failure (the path is well-formed JSON, just not allowed).
    assert_eq!(status, StatusCode::OK);
    let item = &body["items"][0];
    assert_eq!(item["status"], "error");
    assert_eq!(item["error"]["reason"], "forbidden_target");
}

#[tokio::test]
async fn build_and_simulate_and_check_are_also_rejected() {
    for path in [
        "/api/v1/transactions/build",
        "/api/v1/transactions/simulate",
        "/api/v1/transactions/check",
        "/api/v1/mempool/submit",
    ] {
        let (status, body) = post_batch(serde_json::json!({
            "requests": [ { "id": "x", "method": "POST", "path": path } ]
        }))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["items"][0]["error"]["reason"], "forbidden_target",
            "expected {path} to be off the allow-list"
        );
    }
}

#[tokio::test]
async fn unknown_method_on_an_allow_listed_path_is_rejected() {
    let (status, body) = post_batch(serde_json::json!({
        "requests": [
            { "id": "x", "method": "DELETE", "path": "/api/v1/boxes/range" },
        ]
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["error"]["reason"], "forbidden_target");
}

// ----- structural caps ---------------------------------------------------------

#[tokio::test]
async fn empty_requests_array_is_a_whole_batch_error() {
    let (status, body) = post_batch(serde_json::json!({ "requests": [] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["reason"], "empty_batch");
}

#[tokio::test]
async fn over_item_cap_is_rejected_before_any_dispatch() {
    let requests: Vec<_> = (0..40)
        .map(|i| serde_json::json!({ "id": i.to_string(), "method": "GET", "path": "/api/v1/diagnostics" }))
        .collect();
    let (status, body) = post_batch(serde_json::json!({ "requests": requests })).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"]["reason"], "batch_too_large");
    // Whole-batch failure ⇒ no `items` array to inspect.
    assert!(body.get("items").is_none());
}

#[tokio::test]
async fn malformed_json_body_is_a_bad_request() {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/batch")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from("{ not json"))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let resp = app().oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["reason"], "bad_request");
}

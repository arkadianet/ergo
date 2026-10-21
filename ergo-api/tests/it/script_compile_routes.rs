//! `POST /script/p2sAddress` + `POST /script/p2shAddress` — the two
//! compile-requiring members of Scala's `ScriptApiRoute` (M6).
//!
//! End-to-end routing/extractor coverage: drives the real handlers through
//! axum routing with the `(NetworkPrefix, ComputePool)` tuple state, so the
//! `Json`/`State` extractors and the compile-error->400 mapping are
//! exercised, not just the pure pieces. The node hosts no wallet, so the
//! compile env is empty: `myPubKey_N` is an unknown name.
//!
//! No live Scala node needed: expected addresses are derived by calling
//! `ergo_compiler::compile` directly (itself extensively oracle-verified
//! elsewhere, M1-M5) and asserting the ROUTE agrees — this pins the route's
//! OWN plumbing (DTO parsing, response shape), which is what's new here.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer,
    ApiStatus, ApiSyncStatus, ApiTip,
};
use ergo_compiler::{NetworkPrefix, ScriptEnv};
use tower::ServiceExt;

// ----- helpers -----

fn app() -> Router {
    app_with_compute(Default::default())
}

fn app_with_compute(compute: ergo_api::v1::ComputePool) -> Router {
    Router::new()
        .route(
            "/script/p2sAddress",
            post(ergo_api::script::p2s_address_handler),
        )
        .route(
            "/script/p2shAddress",
            post(ergo_api::script::p2sh_address_handler),
        )
        .with_state((NetworkPrefix::Mainnet, compute))
}
#[tokio::test]
async fn scala_script_admission_failures_match_the_public_contract() {
    let document: serde_json::Value =
        serde_norway::from_str(ergo_api::server::scala_openapi_yaml()).unwrap();
    let compute = ergo_api::v1::ComputePool::default();
    compute.close();
    let router = app_with_compute(compute);
    let request = serde_json::json!({"source": "sigmaProp(true)", "treeVersion": 0}).to_string();

    for path in ["/script/p2sAddress", "/script/p2shAddress"] {
        let operation = &document["paths"][path]["post"];
        assert_eq!(operation["security"], serde_json::json!([]));
        for status in ["503", "504"] {
            assert_eq!(
                operation["responses"][status]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/ScriptServiceError",
                "{path}: {status}"
            );
        }
        assert_eq!(
            operation["responses"]["500"]["content"]["application/json"]["schema"]["oneOf"],
            serde_json::json!([
                {"$ref": "#/components/schemas/ApiError"},
                {"$ref": "#/components/schemas/ScriptServiceError"}
            ])
        );
        let (status, body) = post_json(router.clone(), path, &request).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
        assert_eq!(body["error"]["reason"], "shutting_down");
        assert!(body["error"]["message"].is_string());
        assert!(body["error"]["detail"].is_string());
    }
}

async fn post_json(router: Router, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// `NodeReadState` stub whose methods panic if reached -- the real-router
/// wiring test below never touches the read surface (the two `/script/*`
/// compile routes need only `NetworkPrefix` and the compute pool), so a call
/// here would mean a routing regression.
struct UnusedReadState;

impl NodeReadState for UnusedReadState {
    fn info(&self) -> ApiInfo {
        unreachable!()
    }
    fn status(&self) -> ApiStatus {
        unreachable!()
    }
    fn tip(&self) -> ApiTip {
        unreachable!()
    }
    fn sync(&self) -> ApiSyncStatus {
        unreachable!()
    }
    fn peers(&self) -> Vec<ApiPeer> {
        unreachable!()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        unreachable!()
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        unreachable!()
    }
    fn mempool_transaction(&self, _tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        unreachable!()
    }
    fn health(&self) -> ApiHealth {
        unreachable!()
    }
}

// ----- happy path -----

#[tokio::test]
async fn p2s_address_route_matches_direct_compile() {
    let source = "sigmaProp(HEIGHT > 100)";
    let expected = ergo_compiler::compile(&ScriptEnv::new(), source, 0, NetworkPrefix::Mainnet)
        .expect("compiles");

    let body = serde_json::json!({ "source": source, "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["address"], expected.p2s_address);
}

#[tokio::test]
async fn p2sh_address_route_matches_direct_compile() {
    let source = "sigmaProp(HEIGHT > 100)";
    let expected = ergo_compiler::compile(&ScriptEnv::new(), source, 0, NetworkPrefix::Mainnet)
        .expect("compiles");

    let body = serde_json::json!({ "source": source, "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(), "/script/p2shAddress", &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["address"], expected.p2sh_address);
}

#[tokio::test]
async fn p2s_address_route_header_follows_tree_version_like_scala() {
    // Scala `ScriptApiRouteSpec` (ergo 6.0.7): the P2S tree's first byte is
    // 0x10 at treeVersion 0 and 0x19 at treeVersion 1, because the route
    // builds `ErgoTree.defaultHeaderWithVersion(treeVersion)`
    // (`ScriptApiRoute.scala:58`). P2SH hashes the proposition only, so it
    // does not move.
    let source = "sigmaProp(HEIGHT > 100)";
    let mut p2sh = Vec::new();
    for (tree_version, head) in [(0u8, 0x10u8), (1, 0x19), (3, 0x1b)] {
        let body = serde_json::json!({ "source": source, "treeVersion": tree_version }).to_string();
        let (status, json) = post_json(app(), "/script/p2sAddress", &body).await;
        assert_eq!(status, StatusCode::OK);
        let tree = ergo_ser::address::decode_address_to_tree_bytes(
            json["address"].as_str().unwrap(),
            NetworkPrefix::Mainnet,
        )
        .expect("P2S address decodes");
        assert_eq!(tree[0], head, "treeVersion {tree_version}");
        let (status, json) = post_json(app(), "/script/p2shAddress", &body).await;
        assert_eq!(status, StatusCode::OK);
        p2sh.push(json["address"].as_str().unwrap().to_string());
    }
    assert!(p2sh.windows(2).all(|w| w[0] == w[1]), "{p2sh:?}");
}

#[tokio::test]
async fn p2s_address_route_compiles_a_keyless_script() {
    // The env is empty, not an error: a script that doesn't reference
    // `myPubKey_N` compiles.
    let body =
        serde_json::json!({ "source": "sigmaProp(HEIGHT > 100)", "treeVersion": 0 }).to_string();
    let (status, _json) = post_json(app(), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::OK);
}

// ----- error paths -----

#[tokio::test]
async fn p2s_address_route_wallet_key_reference_is_bad_request() {
    // The node holds no wallet keys, so `myPubKey_0` fails to resolve at
    // bind/emit -- a 400, exactly like any other compile failure, not a 500.
    let body = serde_json::json!({ "source": "myPubKey_0", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], 400);
    assert_eq!(json["reason"], "bad-request");
}

#[tokio::test]
async fn p2s_address_route_invalid_source_is_bad_request() {
    let body = serde_json::json!({ "source": "{{{ not ergoscript", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], 400);
    assert_eq!(json["reason"], "bad-request");
    assert!(json["detail"].as_str().is_some());
}

#[tokio::test]
async fn p2sh_address_route_invalid_source_is_bad_request() {
    let body = serde_json::json!({ "source": "{{{ not ergoscript", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(), "/script/p2shAddress", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["reason"], "bad-request");
}

#[tokio::test]
async fn p2s_address_route_boolean_root_compiles_via_bool_to_sigmaprop() {
    // ScriptApiRoute.scala:60-65 root dispatch: a bare Boolean root wraps via
    // BoolToSigmaProp -- exercised end-to-end through the route (not just
    // `tree::compile`'s own unit tests).
    let body = serde_json::json!({ "source": "HEIGHT > 100", "treeVersion": 0 }).to_string();
    let (status, json) = post_json(app(), "/script/p2sAddress", &body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["address"].as_str().is_some());
}

// ----- real merged-router wiring (not the hand-built `app()` above) -----

#[tokio::test]
async fn p2s_address_route_is_reachable_and_public_on_the_real_merged_router() {
    // Drives `ergo_api::server::router` -- which delegates through
    // `router_with_mempool_and_security` with `security = None` -- proving
    // the `server.rs` merge actually wires `/script/p2sAddress` into the
    // assembled router, not just the hand-built single-purpose router `app()`
    // exercises above. Also proves the route is PUBLIC (no api_key required)
    // -- Scala's `ScriptApiRoute` carries no `withAuth` (decision 1).
    let router = ergo_api::server::router(
        Arc::new(UnusedReadState),
        None,
        None,
        None,
        NetworkPrefix::Mainnet,
    );
    let body =
        serde_json::json!({ "source": "sigmaProp(HEIGHT > 100)", "treeVersion": 0 }).to_string();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/script/p2sAddress")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "route must be reachable, unauthenticated, on the real assembled router"
    );
}

//! Auth-scope regression for the browser wallet UI.
//!
//! The wallet UI is served publicly so an operator can load it without
//! first authenticating; the `/wallet/*` JSON API it drives stays
//! api_key-gated. This test pins both halves of that boundary on the
//! *real* merged router (`router_with_mempool_and_wallet_and_security`
//! with `security = Some`), not a hand-assembled subset — so a future
//! refactor that accidentally gates `/wallet/ui` or ungates
//! `/wallet/status` fails here:
//!
//! * `GET /wallet/ui` / `…/index.html` / `…/wallet.js` → 308 redirect to
//!   `/#wallet` with no key (retired to the SPA; public, NOT swallowed by the
//!   gated `/wallet/*rest` catch-all).
//! * `GET /wallet/status` → 403 with no key (gate unmoved), 200 with the
//!   pinned Scala-parity key (proves the 403 is the gate, not a missing
//!   route).
//!
//! Reuses the Scala `(secret="hello", hash=324dcf…)` fixture pinned in
//! `ergo-api/tests/auth.rs`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use ergo_api::auth::{ApiSecurity, API_KEY_HEADER};
use ergo_api::server::{
    router_with_mempool_and_wallet_and_security, router_with_mempool_and_wallet_and_wallet_moved,
    ServerCtx,
};
use ergo_api::traits::{NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer,
    ApiStatus, ApiSyncStatus, ApiTip,
};
use ergo_api::wallet::NoopWalletAdmin;
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- helpers -----

const PLAINTEXT_KEY: &str = "hello";
const SCALA_HELLO_HASH: &str = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";

/// `NodeReadState` stub whose methods panic if reached. The routes this
/// test exercises — the static `/wallet/ui*` bundle and the gated
/// `/wallet/status` (served by `NoopWalletAdmin`) — never touch the read
/// surface, so a call here would mean a routing regression, which we
/// want to surface loudly rather than mask with placeholder data.
struct UnusedReadState;

impl NodeReadState for UnusedReadState {
    fn info(&self) -> ApiInfo {
        unreachable!("wallet-ui auth-scope test never hits the read surface")
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

fn security() -> Arc<ApiSecurity> {
    Arc::new(ApiSecurity::new(SCALA_HELLO_HASH.to_string()).expect("valid hex hash"))
}

/// The production merged router with the operator api_key gate enabled.
fn app() -> axum::Router {
    let ctx = ServerCtx {
        read: Arc::new(UnusedReadState),
        compat: None,
        submit: None,
        wallet_chain: None,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
    };
    router_with_mempool_and_wallet_and_security(
        ctx,
        None,
        Arc::new(NoopWalletAdmin),
        Some(security()),
    )
}

fn moved_app(address: &str, with_security: bool) -> axum::Router {
    let ctx = ServerCtx {
        read: Arc::new(UnusedReadState),
        compat: None,
        submit: None,
        wallet_chain: None,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
    };
    router_with_mempool_and_wallet_and_wallet_moved(
        ctx,
        None,
        Arc::new(NoopWalletAdmin),
        with_security.then(security),
        Some(address),
    )
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn get_with_header(path: &str, name: &str, value: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(name, value)
        .body(Body::empty())
        .unwrap()
}

fn location(resp: &axum::response::Response) -> Option<String> {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
}

// ----- happy path -----

#[tokio::test]
async fn wallet_ui_redirects_to_spa_without_api_key() {
    // Retired to the SPA: a public 308 → /#wallet, NOT a 403 from the gated
    // /wallet/*rest catch-all.
    let resp = app().oneshot(get("/wallet/ui")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(location(&resp).as_deref(), Some("/#wallet"));
}

#[tokio::test]
async fn wallet_ui_index_html_alias_redirects_to_spa() {
    let resp = app().oneshot(get("/wallet/ui/index.html")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(location(&resp).as_deref(), Some("/#wallet"));
}

#[tokio::test]
async fn wallet_ui_js_alias_redirects_to_spa() {
    let resp = app().oneshot(get("/wallet/ui/wallet.js")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(location(&resp).as_deref(), Some("/#wallet"));
}

#[tokio::test]
async fn wallet_status_with_correct_api_key_returns_200() {
    // Positive control: with the key, the gate opens and the route
    // exists — so the 403 below is the gate, never a missing route.
    let resp = app()
        .oneshot(get_with_header(
            "/wallet/status",
            API_KEY_HEADER,
            PLAINTEXT_KEY,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ----- error paths -----

#[tokio::test]
async fn external_wallet_routes_return_gone_with_daemon_address() {
    for path in [
        "/wallet/status",
        "/wallet/ui",
        "/api/v1/wallet/status",
        "/scan/listAll",
        "/api/v1/scan/scans",
        "/api/v1/accounts/watch",
        "/api/v1/accounts/watch/11/unspent",
        "/api/v1/accounts",
        "/api/v1/transactions-psbt",
        "/api/v1/accounts/private-key",
    ] {
        let response = moved_app("http://127.0.0.1:19090", true)
            .oneshot(get_with_header(path, API_KEY_HEADER, PLAINTEXT_KEY))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE, "path {path}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let nested = path.starts_with("/api/v1/accounts")
            || path.starts_with("/api/v1/scan")
            || path.starts_with("/api/v1/transactions-psbt");
        if nested {
            assert_eq!(body["error"]["reason"], "wallet_moved", "path {path}");
            assert_eq!(
                body["error"]["detail"], "http://127.0.0.1:19090",
                "path {path}"
            );
            assert!(body.get("reason").is_none(), "path {path}");
        } else {
            assert_eq!(body["reason"], "wallet_moved", "path {path}");
            assert_eq!(body["address"], "http://127.0.0.1:19090", "path {path}");
        }
    }
}

#[tokio::test]
async fn external_wallet_routes_preserve_api_key_gate() {
    let response = moved_app("http://127.0.0.1:19090", true)
        .oneshot(get("/wallet/status"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn external_wallet_routes_can_be_unauthenticated_in_test_mode() {
    let response = moved_app("http://127.0.0.1:19090", false)
        .oneshot(get("/api/v1/wallet/status"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn external_v1_operator_routes_preserve_auth_before_moved() {
    for (method, path) in [
        (Method::GET, "/api/v1/scan/scans"),
        (Method::GET, "/api/v1/accounts"),
        (Method::POST, "/api/v1/accounts/private-key"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let response = moved_app("http://127.0.0.1:19090", true)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "path {path}");
    }
}

#[tokio::test]
async fn external_v1_public_watch_routes_return_moved_without_auth() {
    for path in [
        "/api/v1/accounts/watch",
        "/api/v1/accounts/watch/11/unspent",
    ] {
        let response = moved_app("http://127.0.0.1:19090", true)
            .oneshot(get(path))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE, "path {path}");
    }
}

#[tokio::test]
async fn external_v1_script_route_remains_available() {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/script/compile")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"source":"sigmaProp(HEIGHT > 100)"}"#))
        .unwrap();
    let response = moved_app("http://127.0.0.1:19090", true)
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["ergo_tree"].as_str().is_some());
}

#[tokio::test]
async fn external_wallet_script_routes_return_moved() {
    for path in ["/script/p2sAddress", "/script/p2shAddress"] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let response = moved_app("http://127.0.0.1:19090", true)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE, "path {path}");
    }
}

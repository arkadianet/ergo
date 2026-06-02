//! Integration tests for the `api_key` middleware. Pins:
//!
//! * Scope: only `/wallet/*` and `/node/shutdown` are gated; the public
//!   read surface (`/info`, `/blocks/*`, …) stays unauthenticated.
//! * Header: exactly `api_key` (lowercase, underscore) — `api-key` and
//!   `x-api-key` do not work.
//! * Hash: byte-for-byte parity with the Scala node's `apiKeyHash` —
//!   the pinned oracle here is `Blake2b256("hello") =
//!   324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf`,
//!   the same value committed in every Scala `*.conf` template and
//!   used by the Scala `NodeApi.scala:52` integration tests.
//! * Rejection: HTTP 403 with body
//!   `{ "error": 403, "reason": "invalid.api-key", "detail": null }`,
//!   matching Scala `ApiError.ApiKeyNotValid` (`http/api/ApiError.scala:37`).

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ergo_api::auth::{ApiSecurity, API_KEY_HEADER};
use ergo_api::wallet::{router_with_security, NoopWalletAdmin, WalletAdmin};
use tower::ServiceExt;

// ----- helpers -----

/// Plaintext API key whose Blake2b-256 hex is pinned to the Scala
/// reference. The `(secret, hash)` pair below is the same one used
/// in `reference/ergo/src/main/resources/*.conf::apiKeyHash` and
/// `reference/ergo/src/it/scala/.../api/NodeApi.scala:52`.
///
/// Duplicated in `ergo-api/src/auth.rs::tests`,
/// `ergo-node/src/config.rs::tests::TEST_DEFAULT_API_KEY_HASH`, and
/// `ergo-node/tests/common/mod.rs`. All four MUST stay in sync if
/// Scala ever rotates this fixture.
const PLAINTEXT_KEY: &str = "hello";
const SCALA_HELLO_HASH: &str = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";

fn security() -> Arc<ApiSecurity> {
    Arc::new(ApiSecurity::new(SCALA_HELLO_HASH.to_string()).expect("valid hex hash"))
}

fn wallet_app_gated() -> axum::Router {
    let admin: Arc<dyn WalletAdmin> = Arc::new(NoopWalletAdmin);
    router_with_security(admin, Some(security()))
}

fn wallet_app_ungated() -> axum::Router {
    let admin: Arc<dyn WalletAdmin> = Arc::new(NoopWalletAdmin);
    router_with_security(admin, None)
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn get_with_header(path: &str, header: &str, value: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(header, value)
        .body(Body::empty())
        .unwrap()
}

// ----- happy path -----

#[tokio::test]
async fn wallet_status_with_correct_api_key_returns_200() {
    let app = wallet_app_gated();
    let req = get_with_header("/wallet/status", API_KEY_HEADER, PLAINTEXT_KEY);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn wallet_status_ungated_returns_200_without_header() {
    // Sanity check: when no `ApiSecurity` is configured, the
    // `/wallet/*` subtree is reachable without any header. Used by
    // tests and read-only mirrors. Pairs with the gated test above to
    // show the gate is the only thing producing 403.
    let app = wallet_app_ungated();
    let resp = app.oneshot(get("/wallet/status")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ----- error paths -----

#[tokio::test]
async fn wallet_status_without_api_key_returns_403_invalid() {
    // Audit C2: routes were previously bare. Pinning the Scala-parity
    // 403 envelope so any future serializer drift surfaces here.
    let app = wallet_app_gated();
    let resp = app.oneshot(get("/wallet/status")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_string(resp).await;
    assert!(body.contains(r#""error":403"#), "shape mismatch: {body}");
    assert!(
        body.contains(r#""reason":"invalid.api-key""#),
        "reason mismatch: {body}"
    );
}

#[tokio::test]
async fn wallet_status_with_wrong_api_key_returns_403() {
    let app = wallet_app_gated();
    let req = get_with_header("/wallet/status", API_KEY_HEADER, "not-hello");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn wallet_status_returns_403_not_404_to_avoid_route_leak() {
    // Audit-adjacent invariant: an unauth'd response must still tell
    // the operator the route EXISTS (just gated) — never 404. A 404
    // would let an unauthenticated probe enumerate which routes were
    // mounted vs not mounted.
    let app = wallet_app_gated();
    let resp = app.oneshot(get("/wallet/status")).await.unwrap();
    assert_ne!(resp.status(), StatusCode::NOT_FOUND);
}

// ----- header-name regression (Scala parity) -----

#[tokio::test]
async fn wallet_status_with_x_api_key_header_does_not_authenticate() {
    // The Scala node uses `api_key` (lowercase + underscore), not
    // `X-Api-Key`. Any drift to the more "modern" header name would
    // break Scala operator tooling silently. Pin the contract.
    let app = wallet_app_gated();
    let req = get_with_header("/wallet/status", "x-api-key", PLAINTEXT_KEY);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn wallet_status_with_dashed_api_key_header_does_not_authenticate() {
    let app = wallet_app_gated();
    let req = get_with_header("/wallet/status", "api-key", PLAINTEXT_KEY);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn wallet_status_with_authorization_bearer_does_not_authenticate() {
    let app = wallet_app_gated();
    let req = get_with_header(
        "/wallet/status",
        "authorization",
        &format!("Bearer {PLAINTEXT_KEY}"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ----- oracle parity -----

#[tokio::test]
async fn scala_hello_secret_unlocks_scala_hello_hash() {
    // End-to-end Scala-oracle parity: the same `(secret, hash)` pair
    // pinned in `reference/ergo/src/main/resources/mainnet.conf` and
    // sent by `reference/ergo/src/it/scala/.../api/NodeApi.scala:52`
    // must authenticate against our gate without modification.
    let app = wallet_app_gated();
    let req = get_with_header("/wallet/status", API_KEY_HEADER, PLAINTEXT_KEY);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Scala (secret=\"hello\", hash=324dcf...) must round-trip"
    );
}

// ----- shutdown-path scope -----
//
// Server-side wiring in `ergo-api/src/server.rs` wraps both shutdown
// aliases (`/node/shutdown`, `/api/v1/node/shutdown`) with the same
// middleware as the wallet subtree. The focused tests below
// reproduce the shutdown router shape and verify the middleware
// layer in isolation.
//
// **Known coverage gap:** these tests do NOT exercise the real
// `router_with_mempool_and_wallet_and_security(...)` merge path. A
// future refactor that reorders the merges or moves a route could
// ship an ungated alias without these tests failing. Closing the gap
// requires building ~80 LOC of `NodeReadState` + `IndexerQuery` +
// `NodeChainQuery` fixtures, which is a shared concern between this
// file, `wallet_*`, and `blockchain_*_routes.rs` tests.
//
// Scope reminder: TransactionsApiRoute.scala:174 leaves
// `POST /transactions` unauthenticated in the Scala node; we match.
// Any future expansion to gate submission routes belongs in a
// separate phase.

fn shutdown_app_gated() -> axum::Router {
    use axum::routing::post;
    async fn stub_shutdown() -> &'static str {
        "stub-shutdown-ok"
    }
    let admin_routes: axum::Router = axum::Router::new()
        .route("/api/v1/node/shutdown", post(stub_shutdown))
        .route("/node/shutdown", post(stub_shutdown));
    admin_routes.layer(axum::middleware::from_fn_with_state(
        security(),
        ergo_api::auth::require_api_key,
    ))
}

fn post_req(path: &str, header: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder().method("POST").uri(path);
    if let Some((k, v)) = header {
        b = b.header(k, v);
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn node_shutdown_bare_path_without_key_returns_403() {
    let resp = shutdown_app_gated()
        .oneshot(post_req("/node/shutdown", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn node_shutdown_v1_path_without_key_returns_403() {
    // Same gate, different alias — catches the regression where
    // someone gates one alias and forgets the other.
    let resp = shutdown_app_gated()
        .oneshot(post_req("/api/v1/node/shutdown", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn node_shutdown_bare_path_with_correct_key_returns_200() {
    let resp = shutdown_app_gated()
        .oneshot(post_req(
            "/node/shutdown",
            Some((API_KEY_HEADER, PLAINTEXT_KEY)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn node_shutdown_v1_path_with_correct_key_returns_200() {
    let resp = shutdown_app_gated()
        .oneshot(post_req(
            "/api/v1/node/shutdown",
            Some((API_KEY_HEADER, PLAINTEXT_KEY)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

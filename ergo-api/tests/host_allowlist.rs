//! Host-header allowlist middleware (DNS-rebinding guard, issue #247
//! item 4) — integration coverage over the *real* axum layer wiring,
//! not just the pure `HostAllowlist::permits` unit tests in
//! `ergo-api/src/host_guard.rs`.
//!
//! Mirrors production wiring in
//! `ergo_api::server::serve_on_with_mempool_and_wallet_and_security_and_hosts`:
//! build the router, then layer `require_allowed_host` around it with a
//! `HostAllowlist` resolved from a bind address + `allowed_hosts` list.
//! Since the guard is the outermost layer (wraps the 404 fallback too),
//! an unmatched path is enough to prove "the request reached routing" —
//! these tests never need a real handler, only a status that isn't 421.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use ergo_api::host_guard::{require_allowed_host, HostAllowlist};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer,
    ApiStatus, ApiSyncStatus, ApiTip,
};
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- helpers -----

/// Every route these tests hit is unmounted (`/__host-guard-probe`), so
/// the read surface is never reached — same "never called" stub
/// pattern as `ergo-api/tests/mining_auth_gate.rs`.
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

/// Build the real router, wrapped in the host-guard layer exactly as
/// production does — `.layer()`, not `.route_layer()`, so it also
/// covers the fallback 404.
fn app(bind: &str, allowed_hosts: &[&str]) -> axum::Router {
    let bind_addr: SocketAddr = bind.parse().unwrap();
    let allowed_hosts: Vec<String> = allowed_hosts.iter().map(|s| s.to_string()).collect();
    let allowlist = Arc::new(HostAllowlist::new(bind_addr, &allowed_hosts));
    let inner = router(
        Arc::new(UnusedReadState),
        None,
        None,
        None,
        NetworkPrefix::Mainnet,
    );
    inner.layer(axum::middleware::from_fn_with_state(
        allowlist,
        require_allowed_host,
    ))
}

fn probe_request(host: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri("/__host-guard-probe");
    if let Some(h) = host {
        builder = builder.header(header::HOST, h);
    }
    builder.body(Body::empty()).unwrap()
}

/// HTTP/2-style request: host identity lives in the URI's authority
/// component (`:authority` pseudo-header, which axum/hyper surface via
/// `Request::uri().authority()`) and there is deliberately no `Host`
/// header at all — that's exactly the shape hyper's h2 server produces
/// (P1-1).
fn probe_request_authority_only(authority: &str) -> Request<Body> {
    let uri = format!("http://{authority}/__host-guard-probe");
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// A `Host` header carrying a byte sequence that is valid as raw
/// header-value bytes (`HeaderValue` permits any byte outside
/// `0x00..=0x08`, `0x0A..=0x1F`, and `0x7F`) but is not valid UTF-8 —
/// obs-text, `0x80..=0xFF` (P2-1).
fn probe_request_raw_host_bytes(bytes: &[u8]) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/__host-guard-probe")
        .body(Body::empty())
        .unwrap();
    req.headers_mut().insert(
        header::HOST,
        axum::http::HeaderValue::from_bytes(bytes).unwrap(),
    );
    req
}

async fn status_for(app: axum::Router, host: Option<&str>) -> StatusCode {
    app.oneshot(probe_request(host)).await.unwrap().status()
}

// ----- happy path -----

#[tokio::test]
async fn loopback_bind_good_host_passes() {
    let status = status_for(app("127.0.0.1:9099", &[]), Some("127.0.0.1")).await;
    assert_ne!(status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn loopback_bind_localhost_host_passes() {
    let status = status_for(app("127.0.0.1:9099", &[]), Some("localhost:9099")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn missing_host_header_passes() {
    let status = status_for(app("127.0.0.1:9099", &[]), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn allowed_hosts_entry_passes() {
    let status = status_for(
        app("127.0.0.1:9099", &["my-node.local"]),
        Some("my-node.local"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn non_loopback_bind_empty_allowlist_passes_any_host() {
    let status = status_for(app("0.0.0.0:9099", &[]), Some("anything.example.com")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn port_variant_of_default_host_passes() {
    let status = status_for(app("127.0.0.1:9099", &[]), Some("127.0.0.1:1234")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn ipv6_loopback_bind_bracketed_host_passes() {
    let status = status_for(app("[::1]:9099", &[]), Some("[::1]:9099")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn http2_style_good_authority_no_host_header_passes() {
    // P1-1: no Host header, but a good :authority — must pass, not be
    // treated as "missing host identity, allow unconditionally".
    let resp = app("127.0.0.1:9099", &[])
        .oneshot(probe_request_authority_only("127.0.0.1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ----- error paths -----

#[tokio::test]
async fn loopback_bind_evil_host_rejected() {
    let status = status_for(app("127.0.0.1:9099", &[]), Some("evil.example.com")).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn loopback_bind_evil_host_rejected_body_shape() {
    let resp = app("127.0.0.1:9099", &[])
        .oneshot(probe_request(Some("evil.example.com")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], 421);
    assert_eq!(body["reason"], "invalid.host");
}

#[tokio::test]
async fn non_loopback_bind_with_allowlist_rejects_unlisted_host() {
    let status = status_for(
        app("0.0.0.0:9099", &["api.example.com"]),
        Some("evil.example.com"),
    )
    .await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn allowed_hosts_port_pin_rejects_wrong_port() {
    let status = status_for(
        app("127.0.0.1:9099", &["my-node.local:8443"]),
        Some("my-node.local:9099"),
    )
    .await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn allowed_hosts_port_pin_accepts_right_port() {
    let status = status_for(
        app("127.0.0.1:9099", &["my-node.local:8443"]),
        Some("my-node.local:8443"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn http2_style_evil_authority_no_host_header_rejected() {
    // P1-1: an h2c request never carries a `Host` header — before the
    // fix, the "missing Host" branch let this straight through. It
    // must now be checked against the same allowlist via `:authority`.
    let resp = app("127.0.0.1:9099", &[])
        .oneshot(probe_request_authority_only("evil.example.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn non_utf8_host_header_rejected() {
    // P2-1: obs-text bytes fail `HeaderValue::to_str()`, which used to
    // map to `None` and fail OPEN (treated as "no Host header" →
    // allowed). Must now fail closed.
    let resp = app("127.0.0.1:9099", &[])
        .oneshot(probe_request_raw_host_bytes(&[0xff, 0xfe, b'x']))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn subdomain_bypass_127_0_0_1_evil_com_rejected() {
    let status = status_for(app("127.0.0.1:9099", &[]), Some("127.0.0.1.evil.com")).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn subdomain_bypass_localhost_evil_com_rejected() {
    let status = status_for(app("127.0.0.1:9099", &[]), Some("localhost.evil.com")).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn trailing_dot_fqdn_passes() {
    // A trailing dot denotes the DNS root and is stripped before
    // matching (documented, user-typable) — `localhost.` behaves like
    // `localhost`.
    let status = status_for(app("127.0.0.1:9099", &[]), Some("localhost.")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn double_trailing_dot_rejected() {
    // Only ONE trailing dot is stripped; a second is left dangling.
    let status = status_for(app("127.0.0.1:9099", &[]), Some("localhost..")).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn malformed_bracket_host_rejected() {
    let resp = app("127.0.0.1:9099", &[])
        .oneshot(probe_request_raw_host_bytes(b"[::1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn empty_host_header_rejected() {
    let resp = app("127.0.0.1:9099", &[])
        .oneshot(probe_request_raw_host_bytes(b""))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);
}

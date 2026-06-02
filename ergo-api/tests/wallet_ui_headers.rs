//! Security-header regression for the wallet-UI route group.
//!
//! The wallet UI renders mnemonics (init/restore), so its responses carry
//! a strict CSP plus `Cache-Control: no-store` (a bfcache mitigation).
//! These headers must cover the bare `/wallet/ui` mount AND every sibling
//! asset, and must NOT leak onto the operator dashboard at `/`, which
//! relies on a CDN-hosted web font that `default-src 'self'` would block.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use ergo_api::server::{router_with_mempool_and_wallet_and_security, ServerCtx};
use ergo_api::traits::{NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer,
    ApiStatus, ApiSyncStatus, ApiTip,
};
use ergo_api::wallet::NoopWalletAdmin;
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- helpers -----

const EXPECTED_CSP: &str =
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'";
const EXPECTED_CACHE_CONTROL: &str = "no-store, no-cache, must-revalidate";

/// `NodeReadState` stub whose methods panic if reached. The routes this
/// test exercises — the static `/wallet/ui*` bundle and the static `/`
/// dashboard — never touch the read surface; a call here would be a
/// routing regression we want surfaced loudly.
struct UnusedReadState;

impl NodeReadState for UnusedReadState {
    fn info(&self) -> ApiInfo {
        unreachable!("wallet-ui header test never hits the read surface")
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

fn app() -> axum::Router {
    let ctx = ServerCtx {
        read: Arc::new(UnusedReadState),
        compat: None,
        submit: None,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        utxo_reads_supported: true,
    };
    // Security gate is irrelevant to these header assertions; `None`
    // keeps the static routes reachable without a key.
    router_with_mempool_and_wallet_and_security(ctx, None, Arc::new(NoopWalletAdmin), None)
}

fn get(path: &str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

fn header_str(resp: &axum::response::Response, name: header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
}

async fn assert_wallet_ui_headers(path: &str) {
    let resp = app().oneshot(get(path)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{path} should serve 200");
    assert_eq!(
        header_str(&resp, header::CONTENT_SECURITY_POLICY).as_deref(),
        Some(EXPECTED_CSP),
        "{path} CSP mismatch"
    );
    assert_eq!(
        header_str(&resp, header::CACHE_CONTROL).as_deref(),
        Some(EXPECTED_CACHE_CONTROL),
        "{path} Cache-Control mismatch"
    );
    assert_eq!(
        header_str(&resp, header::PRAGMA).as_deref(),
        Some("no-cache"),
        "{path} Pragma mismatch"
    );
    assert_eq!(
        header_str(&resp, header::REFERRER_POLICY).as_deref(),
        Some("no-referrer"),
        "{path} Referrer-Policy mismatch"
    );
}

// ----- happy path -----

#[tokio::test]
async fn wallet_ui_bare_mount_carries_security_headers() {
    // The bare `/wallet/ui` page is the sensitive one (renders mnemonics);
    // the layer must reach it, not just the sibling assets.
    assert_wallet_ui_headers("/wallet/ui").await;
}

#[tokio::test]
async fn wallet_ui_index_html_alias_carries_security_headers() {
    assert_wallet_ui_headers("/wallet/ui/index.html").await;
}

#[tokio::test]
async fn wallet_ui_js_carries_security_headers() {
    assert_wallet_ui_headers("/wallet/ui/wallet.js").await;
}

// ----- scope isolation -----

#[tokio::test]
async fn dashboard_root_does_not_carry_wallet_csp() {
    // The dashboard at `/` loads a CDN web font; `default-src 'self'`
    // would break it. The wallet CSP must stay scoped to `/wallet/ui*`.
    let resp = app().oneshot(get("/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        header_str(&resp, header::CONTENT_SECURITY_POLICY).is_none(),
        "dashboard `/` must not carry a Content-Security-Policy header"
    );
}

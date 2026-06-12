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
//! * `GET /wallet/ui` / `…/index.html` / `…/wallet.js` → 200 with no key.
//! * `GET /wallet/status` → 403 with no key (gate unmoved), 200 with the
//!   pinned Scala-parity key (proves the 403 is the gate, not a missing
//!   route).
//!
//! Reuses the Scala `(secret="hello", hash=324dcf…)` fixture pinned in
//! `ergo-api/tests/auth.rs`.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use ergo_api::auth::{ApiSecurity, API_KEY_HEADER};
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

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ----- happy path -----

#[tokio::test]
async fn wallet_ui_page_is_public_without_api_key() {
    let resp = app().oneshot(get("/wallet/ui")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains("/wallet/ui/wallet.js"),
        "served page should be the wallet UI shell"
    );
}

#[tokio::test]
async fn wallet_ui_index_html_alias_is_public_without_api_key() {
    let resp = app().oneshot(get("/wallet/ui/index.html")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn wallet_ui_js_is_public_with_javascript_content_type() {
    let resp = app().oneshot(get("/wallet/ui/wallet.js")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert!(
        ct.contains("javascript"),
        "expected a javascript content-type, got {ct:?}"
    );
    let body = body_string(resp).await;
    assert!(
        body.contains("api_key"),
        "wallet.js should drive /wallet/* via the api_key header"
    );
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
async fn wallet_status_stays_gated_403_without_api_key() {
    // The core invariant: adding the public UI must not move the gate.
    let resp = app().oneshot(get("/wallet/status")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

//! The node hosts no wallet: its former wallet, scan, account and PSBT routes
//! answer `410 wallet_moved` with the configured daemon address. Pinned on the
//! *real* merged router (`router_with_mempool_and_wallet_moved`):
//!
//! * authentication still comes first, with the same credential scopes, so
//!   an unauthenticated caller learns nothing about the wallet's location;
//! * the retired `/wallet/ui*` bundle and the two watch-only reads answer
//!   without a key, as they always did;
//! * every method on every path under the retired prefixes answers, so no
//!   request falls through to a handler.
//!
//! Reuses the Scala `(secret="hello", hash=324dcf…)` fixture pinned in
//! `ergo-api/tests/auth.rs`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use ergo_api::auth::{ApiSecurity, CredentialScope, ScopedCredentialConfig, API_KEY_HEADER};
use ergo_api::server::{router_with_mempool_and_wallet_moved, ServerCtx};
use ergo_api::traits::{NodeReadState, NoopMempoolView};
use ergo_api::types::{
    ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions, ApiPeer,
    ApiStatus, ApiSyncStatus, ApiTip,
};
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- helpers -----

const PLAINTEXT_KEY: &str = "hello";
const SCALA_HELLO_HASH: &str = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";

/// `NodeReadState` stub whose methods panic if reached. The retired wallet
/// paths never touch the read surface, so a call here would mean a routing
/// regression, which we want to surface loudly rather than mask with
/// placeholder data.
struct UnusedReadState;

impl NodeReadState for UnusedReadState {
    fn info(&self) -> ApiInfo {
        unreachable!("the retired wallet paths never hit the read surface")
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

fn moved_app(address: &str, with_security: bool) -> axum::Router {
    moved_app_with_security(address, with_security.then(security))
}

fn moved_app_with_security(address: &str, security: Option<Arc<ApiSecurity>>) -> axum::Router {
    moved_app_at(Some(address), security)
}

fn moved_app_at(address: Option<&str>, security: Option<Arc<ApiSecurity>>) -> axum::Router {
    let ctx = ServerCtx {
        local_reverse_proxy: false,
        services: Arc::new(ergo_api::ApiServices::new()),
        script_config: Default::default(),
        read: Arc::new(UnusedReadState),
        compat: None,
        submit: None,
        wallet_chain: None,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        private_queue: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported: true,
    };
    router_with_mempool_and_wallet_moved(ctx, None, security, address)
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

async fn json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

// ----- happy path -----

#[tokio::test]
async fn retired_wallet_ui_paths_answer_moved_without_a_key() {
    for path in [
        "/wallet/ui",
        "/wallet/ui/index.html",
        "/wallet/ui/wallet.js",
    ] {
        let response = moved_app("http://127.0.0.1:19090", true)
            .oneshot(get(path))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE, "{path}");
        let body = json(response).await;
        assert_eq!(body["reason"], "wallet_moved", "{path}");
        assert_eq!(body["address"], "http://127.0.0.1:19090", "{path}");
    }
}

#[tokio::test]
async fn every_method_and_subpath_under_the_retired_prefixes_is_moved() {
    for (method, path) in [
        (Method::GET, "/wallet"),
        (Method::DELETE, "/wallet/anything/at/all"),
        (Method::PUT, "/scan/register"),
        (Method::GET, "/scan"),
        (Method::PATCH, "/api/v1/wallet"),
        (Method::POST, "/api/v1/wallet/not/a/route"),
        (Method::PUT, "/api/v1/scan"),
        (Method::OPTIONS, "/api/v1/accounts/x/y/z"),
        (Method::DELETE, "/api/v1/transactions-psbt/x"),
    ] {
        let request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(API_KEY_HEADER, PLAINTEXT_KEY)
            .body(Body::empty())
            .unwrap();
        let response = moved_app("http://127.0.0.1:19090", true)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GONE, "{method} {path}");
    }
}

#[tokio::test]
async fn without_a_configured_daemon_address_the_body_omits_it() {
    let response = moved_app_at(None, Some(security()))
        .oneshot(get_with_header(
            "/wallet/status",
            API_KEY_HEADER,
            PLAINTEXT_KEY,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
    let body = json(response).await;
    assert_eq!(body["reason"], "wallet_moved");
    assert!(body.get("address").is_none());
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

/// External ownership guidance must pass the same scope gate as the
/// embedded wallet, including the admin-only private-key route.
#[tokio::test]
async fn external_wallet_guard_preserves_scoped_credential_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let credentials = [
        ("wallet", "wallet-key", CredentialScope::Wallet),
        ("operator", "operator-key", CredentialScope::Operator),
        ("mining", "mining-key", CredentialScope::Mining),
        ("admin", "admin-key", CredentialScope::Admin),
    ];
    let security = Arc::new(
        ApiSecurity::new(SCALA_HELLO_HASH.to_string())
            .unwrap()
            .with_credentials(
                credentials
                    .iter()
                    .map(|(id, key, scope)| ScopedCredentialConfig {
                        id: (*id).into(),
                        hash: ApiSecurity::hash_key(key.as_bytes()),
                        scopes: vec![*scope],
                        revoked: false,
                    })
                    .collect(),
                dir.path().join("revocations.json"),
            )
            .unwrap(),
    );
    let address = "http://127.0.0.1:19090";
    let app = moved_app_with_security(address, Some(security.clone()));
    for (_, key, scope) in credentials {
        for (method, path, admin_only) in [
            (Method::GET, "/wallet/status", false),
            (Method::GET, "/api/v1/wallet/status", false),
            (Method::POST, "/api/v1/wallet/mining-jobs", false),
            (Method::POST, "/api/v1/wallet/mining-jobs/1/cancel", false),
            (Method::POST, "/wallet/getPrivateKey", true),
        ] {
            let allowed = scope == CredentialScope::Admin
                || (scope == CredentialScope::Wallet && !admin_only);
            let request = Request::builder()
                .method(method.clone())
                .uri(path)
                .header(API_KEY_HEADER, key)
                .header(header::CONTENT_TYPE, "application/json")
                // The ownership guard runs before request parsing or wallet work.
                .body(Body::from("malformed"))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                if allowed {
                    StatusCode::GONE
                } else {
                    StatusCode::FORBIDDEN
                },
                "{scope:?}: {method} {path}",
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if allowed {
                assert_eq!(body["reason"], "wallet_moved");
                assert_eq!(body["address"], address);
            } else {
                assert!(
                    body.get("address").is_none(),
                    "scope rejection leaked daemon address"
                );
                assert_ne!(body["reason"], "wallet_moved");
            }
        }
    }
    // A live revocation must also reach the already-mounted ownership guard.
    security.revoke_credential("wallet").unwrap();
    let response = app
        .oneshot(get_with_header(
            "/wallet/status",
            API_KEY_HEADER,
            "wallet-key",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn external_wallet_routes_require_a_configured_key_before_ownership_guidance() {
    for path in ["/wallet/status", "/api/v1/wallet/status", "/scan/listAll"] {
        let response = moved_app("http://127.0.0.1:19090", false)
            .oneshot(get_with_header(path, API_KEY_HEADER, PLAINTEXT_KEY))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["reason"], "api-key-not-configured", "{path}");
    }
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

/// The node serves the Scala script-compile routes itself, compiling without
/// wallet keys: the daemon does not serve them.
#[tokio::test]
async fn script_compile_routes_stay_on_the_node() {
    for path in ["/script/p2sAddress", "/script/p2shAddress"] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"source":"sigmaProp(HEIGHT > 100)","treeVersion":0}"#,
            ))
            .unwrap();
        let response = moved_app("http://127.0.0.1:19090", true)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "path {path}");
        assert!(json(response).await["address"].as_str().is_some(), "{path}");
    }
}

#[tokio::test]
async fn wallet_mining_jobs_require_operator_key_before_body_parsing() {
    for (method, path) in [
        ("GET", "/api/v1/wallet/mining-jobs"),
        ("POST", "/api/v1/wallet/mining-jobs"),
        ("POST", "/api/v1/wallet/mining-jobs/1/cancel"),
    ] {
        for (key, expected) in [
            (None, StatusCode::FORBIDDEN),
            (Some("wrong"), StatusCode::FORBIDDEN),
            (Some(PLAINTEXT_KEY), StatusCode::GONE),
        ] {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(key) = key {
                request = request.header(API_KEY_HEADER, key);
            }
            let response = moved_app("http://127.0.0.1:19090", true)
                .oneshot(request.body(Body::from("malformed")).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{method} {path} {key:?}");
        }
    }
}

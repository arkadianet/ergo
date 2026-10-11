//! Drive the real serialized wallet engine through the authenticated local API.
//! The chain client is unavailable unless a test explicitly needs a key's
//! addition height; seed lifecycle never depends on node availability.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use ergo_wallet_service::{ChainClient, CommittedTip, RedbWalletStore, WalletService, WalletStore};
use ergo_walletd::api::{router, seed_router, ApiContext, READ_ROUTE_INVENTORY};
use ergo_walletd::config::{ApiKey, Network};
use ergo_walletd::engine_chain::LifecycleChainAccess;
use ergo_walletd::host::WalletHost;
use ergo_walletd::lifecycle_api::{LIFECYCLE_ROUTE_INVENTORY, MAX_LIFECYCLE_BODY_BYTES};
use ergo_walletd::tip::CachedNodeTip;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::support::{FakeChain, NoChain};

const LOCAL_KEY: &str = "wallet-local-test-key";
const NODE_KEY: &str = "node-only-test-key";
const PASSWORD: &str = "wallet-password-private-marker";
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn context(store: Arc<dyn WalletStore>, chain: Arc<dyn ChainClient>) -> ApiContext {
    ApiContext {
        service: Arc::new(WalletService::new(store, chain.clone())),
        network: Network::Testnet,
        tip: Arc::new(CachedNodeTip::new(chain)),
        tip_max_age: ApiContext::default_tip_max_age(Duration::from_secs(15)),
    }
}

fn app(dir: &tempfile::TempDir, chain: Arc<dyn ChainClient>) -> axum::Router {
    let store: Arc<dyn WalletStore> = Arc::new(
        RedbWalletStore::open_standalone(dir.path().join("wallet.redb"))
            .unwrap()
            .rebuild_history_on_key_additions(),
    );
    let context = context(store.clone(), chain.clone());
    let access = Arc::new(LifecycleChainAccess::new(store.clone(), chain));
    let host = WalletHost::new(
        store,
        context.service.clone(),
        access,
        dir.path(),
        Network::Testnet,
    )
    .unwrap();
    seed_router(
        context,
        host,
        ApiKey::from_test(LOCAL_KEY.as_bytes().to_vec()),
    )
}

async fn response(
    app: &axum::Router,
    method: Method,
    route: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let body = body.map_or_else(String::new, |body| body.to_string());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(route)
                .header("api_key", LOCAL_KEY)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

async fn restore(app: &axum::Router) {
    let (status, _) = response(
        app,
        Method::POST,
        "/api/v1/wallet/restore",
        Some(json!({
            "mnemonic": MNEMONIC,
            "pass": PASSWORD,
            "derivation": {"type": "eip3"}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

async fn unlock(app: &axum::Router) {
    let (status, _) = response(
        app,
        Method::POST,
        "/api/v1/wallet/unlock",
        Some(json!({"pass": PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn seed_routes_require_the_local_key_before_parsing_every_request() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(&dir, Arc::new(NoChain));
    for route in READ_ROUTE_INVENTORY {
        let route = route.replace(":id", &"11".repeat(32));
        let response = app
            .clone()
            .oneshot(Request::builder().uri(&route).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{route}");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    for (method, route) in LIFECYCLE_ROUTE_INVENTORY {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(*method)
                    .uri(*route)
                    .header("api_key", NODE_KEY)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{a-secret-body-that-is-not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {route}"
        );
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"reason":"unauthorized"})
        );
    }
    for keys in [
        vec!["wrong"],
        vec![LOCAL_KEY, LOCAL_KEY],
        vec![NODE_KEY, LOCAL_KEY],
    ] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/wallet/init");
        for key in keys {
            request = request.header("api_key", key);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let (status, body) = response(&app, Method::GET, "/api/v1/wallet/lifecycle/status", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"initialized":false,"locked":true}));
    assert!(
        !dir.path().join("wallet").exists(),
        "rejected requests must not publish a secret"
    );
}

#[tokio::test]
async fn init_unlock_key_changes_and_lock_use_the_shared_engine() {
    let dir = tempfile::tempdir().unwrap();
    let chain = FakeChain::new(CommittedTip::new(8, [8; 32]));
    let app = app(&dir, chain.clone());
    let (status, body) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/unlock",
        Some(json!({"pass":PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "wallet_uninitialized");
    let (status, body) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/init",
        Some(json!({"pass":PASSWORD,"strength":12})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mnemonic = body["mnemonic"].as_str().unwrap().to_owned();
    assert_eq!(mnemonic.split_whitespace().count(), 12);
    let (status, body) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/init",
        Some(json!({"pass":"another-password"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "wallet_exists");
    unlock(&app).await;
    let (status, body) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/mnemonic/verify",
        Some(json!({"mnemonic":mnemonic})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"matched":true}));
    let (status, derived) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/addresses",
        Some(json!({"type":"next"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(derived["index"], 1);
    assert_eq!(derived["derivationPath"], "m/44'/429'/0'/0/1");
    let (status, _) = response(
        &app,
        Method::PUT,
        "/api/v1/wallet/change-address",
        Some(json!({"address":derived["address"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = response(&app, Method::GET, "/api/v1/wallet/change-address", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["address"], derived["address"]);
    let (status, _) = response(&app, Method::POST, "/api/v1/wallet/lock", None).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = response(&app, Method::GET, "/api/v1/wallet/lifecycle/status", None).await;
    assert_eq!(body, json!({"initialized":true,"locked":true}));
    let (status, body) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/addresses",
        Some(json!({"type":"next"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "wallet_locked");
    // The encrypted file carries the seed, never the plaintext recovery phrase
    // or wallet password returned/supplied by the lifecycle API.
    let secret_file =
        ergo_wallet::storage::SecretStorage::find_secret_file(&dir.path().join("wallet")).unwrap();
    let secret = std::fs::read_to_string(secret_file).unwrap();
    assert!(!secret.contains(&mnemonic));
    assert!(!secret.contains(PASSWORD));
}

#[tokio::test]
async fn restore_status_and_password_budget_work_without_a_node() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(&dir, Arc::new(NoChain));
    restore(&app).await;
    for _ in 0..5 {
        let (status, body) = response(
            &app,
            Method::POST,
            "/api/v1/wallet/unlock",
            Some(json!({"pass":"wrong-password"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["reason"], "wrong_password");
    }
    let (status, body) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/unlock",
        Some(json!({"pass":PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["reason"], "rate_limited");
    let (status, body) = response(&app, Method::GET, "/api/v1/wallet/lifecycle/status", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"initialized":true,"locked":true}));
}

#[tokio::test]
async fn secret_bodies_are_strict_bounded_and_never_echoed_in_errors() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(&dir, Arc::new(NoChain));
    let marker = "recovery-secret-marker";
    let (status, body) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/restore",
        Some(json!({
            "mnemonic":MNEMONIC,"pass":PASSWORD,"derivation":{"type":"eip3"},(marker):marker
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body.to_string().contains(marker));
    let (status, _) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/init",
        Some(json!({"pass":PASSWORD,"strength":13})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for key in [None, Some(LOCAL_KEY)] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/wallet/init")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(key) = key {
            request = request.header("api_key", key);
        }
        let response = app
            .clone()
            .oneshot(
                request
                    .body(Body::from("x".repeat(MAX_LIFECYCLE_BODY_BYTES + 1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if key.is_some() {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    restore(&app).await;
    unlock(&app).await;
    // Derivation needs a bounded node-tip lookup. The unavailable adapter's
    // internal diagnostic stays inside the daemon.
    let (status, body) = response(
        &app,
        Method::POST,
        "/api/v1/wallet/addresses",
        Some(json!({"type":"next"})),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, json!({"reason":"internal"}));
}

#[tokio::test]
async fn watch_mode_stays_secret_free() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let watch = router(context(store, Arc::new(NoChain)));
    for (method, route) in LIFECYCLE_ROUTE_INVENTORY {
        // The watch router already supports GET addresses, but never derive.
        let response = watch
            .clone()
            .oneshot(
                Request::builder()
                    .method(*method)
                    .uri(*route)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if *route == "/api/v1/wallet/addresses" {
                StatusCode::METHOD_NOT_ALLOWED
            } else {
                StatusCode::NOT_FOUND
            },
            "{route}"
        );
    }
    assert!(!dir.path().join("wallet").exists());
}

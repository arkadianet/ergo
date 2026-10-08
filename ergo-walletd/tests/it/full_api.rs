//! Check the daemon against the documented embedded wallet/scan inventory,
//! and drive real hosted commands instead of response-only route stubs.
use crate::support::FakeChain;
use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use ergo_wallet_protocol::WalletAdminError;
use ergo_wallet_service::engine::{
    NoopMempoolOverlay, TxSubmitError, TxSubmitter, WalletEngineConfig,
};
use ergo_wallet_service::{ChainClient, CommittedTip, RedbWalletStore, WalletService, WalletStore};
use ergo_walletd::{
    api::{router, seed_router, ApiContext},
    config::{ApiKey, Network},
    engine_chain::LifecycleChainAccess,
    host::{SpendingCapabilities, SpendingPreparation, WalletHost},
    tip::CachedNodeTip,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tower::ServiceExt;

const KEY: &str = "local-wallet-transport-test-key";
const PASSWORD: &str = "local-wallet-secret-marker";
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[derive(Default)]
struct DisabledQueue {
    prepared: AtomicBool,
    fail_refresh: AtomicBool,
    fail_withdrawal: AtomicBool,
    queued: AtomicBool,
}
impl SpendingPreparation for DisabledQueue {
    fn refresh(&self) -> Result<WalletEngineConfig, WalletAdminError> {
        if self.fail_refresh.load(Ordering::SeqCst) {
            return Err(WalletAdminError::NodeUnavailable(
                "private transport detail".into(),
            ));
        }
        self.prepared.store(true, Ordering::SeqCst);
        Ok(WalletEngineConfig {
            network: Network::Testnet.prefix(),
            expose_private_keys: false,
            reemission: None,
            min_relay_fee_nano_erg: 1_000_000,
            max_tx_size_bytes: 90_000,
        })
    }
}
#[async_trait::async_trait]
impl TxSubmitter for DisabledQueue {
    async fn submit_transaction(&self, _: Vec<u8>) -> Result<String, TxSubmitError> {
        unreachable!("cancellation must not submit a transaction")
    }
    async fn private_transaction_status(
        &self,
        tx_id: String,
    ) -> Result<Option<ergo_wallet_protocol::mining::PrivateTransactionEntry>, TxSubmitError> {
        if !self.prepared.load(Ordering::SeqCst) {
            return Err(TxSubmitError {
                reason: "private_mining_unavailable".into(),
                detail: None,
            });
        }
        Ok(self.queued.load(Ordering::SeqCst).then(|| {
            ergo_wallet_protocol::mining::PrivateTransactionEntry {
                tx_id,
                state: "queued".into(),
                reason: None,
                created_at_ms: 0,
                expires_at_ms: None,
                expires_at_height: None,
                priority: 0,
                label: None,
                input_ids: vec![hex::encode([0x45; 32])],
                fee_nano_erg: "0".into(),
                size_bytes: 1,
                validation_cost: 0,
                mined_block_id: None,
                mined_height: None,
            }
        }))
    }
    async fn cancel_private_transaction(&self, _: String) -> Result<(), TxSubmitError> {
        assert!(self.prepared.load(Ordering::SeqCst));
        if self.fail_withdrawal.load(Ordering::SeqCst) {
            return Err(TxSubmitError {
                reason: "node_rpc_failed".into(),
                detail: None,
            });
        }
        self.queued.store(false, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn job_cancellation_refreshes_disabled_queue_and_keeps_inputs_reserved_until_withdrawal() {
    use ergo_wallet_protocol::native::dto::{WalletJobRequest, WalletJobState, WalletJobTask};
    use ergo_wallet_service::engine::jobs;
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn WalletStore> =
        Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let mut job = jobs::create(
        store.as_ref(),
        WalletJobRequest {
            label: "previously admitted private work".into(),
            task: WalletJobTask::Renew {
                box_ids: vec![hex::encode([0x45; 32])],
            },
            not_before_height: 1,
            expires_at_height: 20,
            max_attempts: 1,
        },
    )
    .unwrap();
    job.state = WalletJobState::Queued;
    job.tx_id = Some(hex::encode([0x46; 32]));
    jobs::save(
        store.as_ref(),
        job.id.parse().unwrap(),
        &jobs::Record {
            job: job.clone(),
            signed_hex: Some("aa".into()),
            last_attempt_height: Some(1),
        },
    )
    .unwrap();
    let queue = Arc::new(DisabledQueue::default());
    queue.queued.store(true, Ordering::SeqCst);
    queue.fail_refresh.store(true, Ordering::SeqCst);
    queue.fail_withdrawal.store(true, Ordering::SeqCst);
    let chain = FakeChain::new(CommittedTip::new(8, [8; 32]));
    let context = context(store.clone(), chain.clone());
    let host = WalletHost::with_spending(
        store.clone(),
        context.service.clone(),
        SpendingCapabilities {
            chain: Arc::new(LifecycleChainAccess::new(store.clone(), chain)),
            preparation: queue.clone(),
            submitter: queue.clone(),
            mempool: Arc::new(NoopMempoolOverlay::new()),
        },
        dir.path(),
        Network::Testnet,
    )
    .unwrap();
    let app = seed_router(context, host, ApiKey::from_test(KEY.as_bytes().to_vec()));
    let path = format!("/api/v1/wallet/mining-jobs/{}/cancel", job.id);

    let (status, body) = request(&app, "POST", &path, Some(KEY), "{}").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["reason"], "node_unavailable");
    assert!(!body.to_string().contains("private transport detail"));
    assert!(queue.queued.load(Ordering::SeqCst));
    assert!(jobs::reserved_inputs(store.as_ref())
        .unwrap()
        .contains(&[0x45; 32]));

    queue.fail_refresh.store(false, Ordering::SeqCst);
    let (status, body) = request(&app, "POST", &path, Some(KEY), "{}").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["reason"], "node_unavailable");
    assert!(queue.queued.load(Ordering::SeqCst));
    assert!(jobs::reserved_inputs(store.as_ref())
        .unwrap()
        .contains(&[0x45; 32]));
    assert_eq!(
        jobs::list(store.as_ref()).unwrap().items[0].state,
        WalletJobState::Queued
    );

    queue.fail_withdrawal.store(false, Ordering::SeqCst);
    let (status, body) = request(&app, "POST", &path, Some(KEY), "{}").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "cancelled");
    assert!(!queue.queued.load(Ordering::SeqCst));
    assert!(!jobs::reserved_inputs(store.as_ref())
        .unwrap()
        .contains(&[0x45; 32]));
}

#[derive(Default)]
struct SpendingSpy {
    refreshes: AtomicUsize,
    submissions: AtomicUsize,
}
impl SpendingPreparation for SpendingSpy {
    fn refresh(&self) -> Result<WalletEngineConfig, WalletAdminError> {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        Ok(WalletEngineConfig {
            network: Network::Testnet.prefix(),
            expose_private_keys: false,
            reemission: None,
            min_relay_fee_nano_erg: 1_000_000,
            max_tx_size_bytes: 8 * 1024 * 1024,
        })
    }
}
#[async_trait::async_trait]
impl TxSubmitter for SpendingSpy {
    async fn submit_transaction(&self, _: Vec<u8>) -> Result<String, TxSubmitError> {
        self.submissions.fetch_add(1, Ordering::SeqCst);
        Err(TxSubmitError {
            reason: "test_submission_rejected".into(),
            detail: None,
        })
    }
}
fn context(store: Arc<dyn WalletStore>, chain: Arc<dyn ChainClient>) -> ApiContext {
    ApiContext {
        service: Arc::new(WalletService::new(store, chain.clone())),
        network: Network::Testnet,
        tip: Arc::new(CachedNodeTip::new(chain)),
        tip_max_age: ApiContext::default_tip_max_age(Duration::from_secs(15)),
    }
}
fn app(dir: &tempfile::TempDir) -> (Router, Arc<SpendingSpy>, Arc<dyn WalletStore>) {
    let store: Arc<dyn WalletStore> = Arc::new(
        RedbWalletStore::open_standalone(dir.path().join("wallet.redb"))
            .unwrap()
            .rebuild_history_on_key_additions(),
    );
    let chain = FakeChain::new(CommittedTip::new(8, [8; 32]));
    let context = context(store.clone(), chain.clone());
    let spy = Arc::new(SpendingSpy::default());
    let host = WalletHost::with_spending(
        store.clone(),
        context.service.clone(),
        SpendingCapabilities {
            chain: Arc::new(LifecycleChainAccess::new(store.clone(), chain)),
            preparation: spy.clone(),
            submitter: spy.clone(),
            mempool: Arc::new(NoopMempoolOverlay::new()),
        },
        dir.path(),
        Network::Testnet,
    )
    .unwrap();
    (
        seed_router(context, host, ApiKey::from_test(KEY.as_bytes().to_vec())),
        spy,
        store,
    )
}
async fn request(
    app: &Router,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: &str,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        builder = builder.header("api_key", key);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON error or response")
        },
    )
}
fn operation_paths() -> Vec<(String, String)> {
    let native = include_str!("../../../ergo-api/tests/fixtures/api_family_rust_operations.txt");
    let scala = include_str!("../../../ergo-api/tests/fixtures/api_family_scala_operations.txt");
    native
        .lines()
        .chain(scala.lines())
        .filter_map(|line| {
            let (method, path) = line.split_once(' ')?;
            let backed = path.starts_with("/api/v1/wallet/")
                || path.starts_with("/wallet/")
                || path.starts_with("/scan/")
                || path.starts_with("/api/v1/scan/")
                || path.starts_with("/api/v1/accounts")
                || path.starts_with("/api/v1/transactions-psbt")
                || path.starts_with("/api/v1/mining/private-transactions");
            if !backed {
                return None;
            }
            let mut path = path.to_owned();
            for id in ["{scan_id}", "{scanId}"] {
                path = path.replace(id, "1000");
            }
            for id in ["{box_id}", "{boxId}", "{txId}", "{tx_id}"] {
                path = path.replace(id, &"11".repeat(32));
            }
            path = path
                .replace("{job_id}", "not-a-job")
                .replace("{account_id}", "account-id")
                .replace("{psbt_id}", "psbt-id");
            if path == "/wallet/transactionById" {
                path.push_str(&format!("?id={}", "11".repeat(32)));
            }
            Some((method.to_ascii_uppercase(), path))
        })
        .collect()
}

#[tokio::test]
async fn native_and_compat_inventory_is_mounted_and_auth_precedes_payload_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let (app, spy, _) = app(&dir);
    let operations = operation_paths();
    assert!(
        operations.len() >= 70,
        "the documented wallet inventory must be exercised"
    );
    for (method, path) in operations {
        for key in [None, Some("outbound-node-only-key")] {
            let (status, body) = request(&app, &method, &path, key, "{secret-not-json").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
            assert_eq!(body, json!({"reason":"unauthorized"}));
        }
        // Authenticate the same operation too: a nonexistent route can also
        // reject at the outer middleware, so its authorized surface matters.
        let (status, body) = request(&app, &method, &path, Some(KEY), "{secret-not-json").await;
        assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        if status == StatusCode::NOT_FOUND {
            assert!(
                body["reason"].is_string() || body["error"]["reason"].is_string(),
                "a mounted lookup returns a typed absence: {method} {path}"
            );
        }
        assert!(
            !body.to_string().contains("secret-not-json"),
            "{method} {path}"
        );
    }
    assert_eq!(spy.submissions.load(Ordering::SeqCst), 0);
    assert!(!dir.path().join("wallet").exists());
}

#[tokio::test]
async fn collection_parse_errors_preserve_v1_envelopes_redaction_and_authentication_order() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _, _) = app(&dir);
    for (method, path, body, reason) in [
        (
            "POST",
            "/api/v1/scan/scans",
            "{private-collection-marker",
            "bad_request",
        ),
        (
            "POST",
            "/api/v1/accounts/watch",
            r#"{"address":"private-collection-marker","unknownSecret":"private-collection-marker"}"#,
            "bad_request",
        ),
        (
            "POST",
            "/api/v1/accounts/private-key",
            r#"{"address":"private-collection-marker","acknowledge":"private-collection-marker"}"#,
            "bad_request",
        ),
        (
            "GET",
            "/api/v1/scan/scans?limit=private-collection-marker",
            "",
            "invalid_params",
        ),
        (
            "GET",
            "/api/v1/accounts/watch?limit=private-collection-marker",
            "",
            "invalid_params",
        ),
        (
            "GET",
            "/api/v1/scan/scans/1000/unspent?min_confirmations=private-collection-marker",
            "",
            "invalid_params",
        ),
    ] {
        for key in [None, Some("wrong-local-key")] {
            let (status, response) = request(&app, method, path, key, body).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path}: {response}"
            );
            assert_eq!(response["reason"], "unauthorized");
        }
        let (status, response) = request(&app, method, path, Some(KEY), body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{method} {path}: {response}"
        );
        assert_eq!(response["error"]["reason"], reason);
        assert!(response["error"]["message"].is_string());
        assert!(response["error"]["detail"].is_string());
        assert!(response.get("reason").is_none());
        assert!(!response.to_string().contains("private-collection-marker"));
    }
    let oversized = "private-collection-marker".repeat(1024);
    let (status, response) = request(
        &app,
        "POST",
        "/api/v1/accounts/private-key",
        Some(KEY),
        &oversized,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response["error"]["reason"], "bad_request");
    assert!(!response.to_string().contains("private-collection-marker"));

    for content_type in [None, Some("text/plain")] {
        for key in [None, Some(KEY)] {
            let mut builder = Request::builder()
                .method("POST")
                .uri("/api/v1/accounts/watch");
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            if let Some(key) = key {
                builder = builder.header("api_key", key);
            }
            let response = app
                .clone()
                .oneshot(
                    builder
                        .body(Body::from(r#"{"address":"private-collection-marker"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(
                response.status(),
                if key.is_some() {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::UNAUTHORIZED
                }
            );
            let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            let response: Value = serde_json::from_slice(&bytes).unwrap();
            if key.is_some() {
                assert_eq!(response["error"]["reason"], "bad_request");
                assert_eq!(response["error"]["message"], "request body is malformed");
            } else {
                assert_eq!(response["reason"], "unauthorized");
            }
            assert!(!response.to_string().contains("private-collection-marker"));
        }
    }

    let (status, response) = request(
        &app,
        "GET",
        "/api/v1/scan/scans?cursor=invalid",
        Some(KEY),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["error"]["reason"], "invalid_cursor");
    let (status, response) = request(
        &app,
        "POST",
        "/api/v1/wallet/init",
        Some(KEY),
        "{private-collection-marker",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["reason"], "bad_request");
    assert!(response.get("error").is_none());
}

#[tokio::test]
async fn locked_wallet_send_uses_the_engine_and_never_submits() {
    let dir = tempfile::tempdir().unwrap();
    let (app, spy, store) = app(&dir);
    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/wallet/restore",
        Some(KEY),
        &json!({"mnemonic":MNEMONIC,"pass":PASSWORD,"derivation":{"type":"eip3"}}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The fixture has no historical wallet activity. Mark its scan valid so
    // the command reaches the engine's lock gate, rather than the scan gate.
    store.persist_scan_invalidation(false).unwrap();
    let (status,body) = request(&app,"POST","/api/v1/wallet/transactions/send",Some(KEY),&json!({"type":"intent","intent":{"outputs":[{"type":"payment","address":"recipient-not-used-while-locked","value":"1000000"}]}}).to_string()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "wallet_locked");
    let (status, body) = request(
        &app,
        "POST",
        "/wallet/payment/send",
        Some(KEY),
        &json!([{"address":"recipient-not-used-while-locked","value":1000000}]).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "wallet_locked");
    assert_eq!(spy.refreshes.load(Ordering::SeqCst), 2);
    assert_eq!(spy.submissions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn transaction_bodies_have_a_larger_bound_and_private_export_stays_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _, _) = app(&dir);
    let padded = format!("{}{{}}", " ".repeat(20 * 1024));
    let (status, body) = request(
        &app,
        "POST",
        "/api/v1/wallet/transactions/sign",
        Some(KEY),
        &padded,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "bad_request");
    let (status, _) = request(&app, "POST", "/wallet/unlock", Some(KEY), &padded).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let oversized = " ".repeat(ergo_walletd::full_api::MAX_WALLET_BODY_BYTES + 1);
    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/wallet/transactions/sign",
        Some(KEY),
        &oversized,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, body) = request(
        &app,
        "POST",
        "/wallet/getPrivateKey",
        Some(KEY),
        r#"{"address":"not-used-while-disabled"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["reason"], "forbidden");
}

#[tokio::test]
async fn wallet_shell_is_public_but_every_wallet_operation_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _, _) = app(&dir);
    for path in [
        "/",
        "/wallet",
        "/wallet/",
        "/js/wallet-app.js",
        "/js/wallet.js",
        "/js/auth.js",
        "/js/api-client.js",
        "/js/format.js",
        "/js/table.js",
        "/js/token-meta.js",
        "/js/wallet-builder.js",
        "/js/wallet-transaction.js",
        "/js/wallet-private.js",
        "/js/wallet-maintenance.js",
        "/tokens.css",
        "/components.css",
        "/dashboard.css",
        "/fonts/inter-variable.woff2",
        "/fonts/jetbrains-mono.woff2",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert!(response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        if path == "/js/auth.js" {
            let source = std::str::from_utf8(&bytes).unwrap();
            assert!(source.contains("status === 401 && reason === 'unauthorized'"));
            assert!(source.contains("local_api_key_file"));
            assert!(source.contains("ergo.walletd.apikey"));
            assert!(!source.contains("features (logs, voting, wallet)"));
        }
        if path == "/js/wallet.js" {
            let source = std::str::from_utf8(&bytes).unwrap();
            assert!(source.contains("Your wallet daemon"));
            assert!(source.contains("sent solely to this wallet daemon"));
            assert!(!source.contains("wallet built into this node"));
            assert!(!source.contains("Keys remain on your node"));
        }
        if path == "/js/wallet-transaction.js" {
            let source = std::str::from_utf8(&bytes).unwrap();
            assert!(source.contains("stop both the node and wallet daemon"));
            assert!(source
                .contains("ergo-node wallet-scan-utxo NODE_DATA --wallet-data-dir WALLET_DATA"));
            assert!(!source.contains("wallet-scan-utxo with your data directory"));
        }
    }
    let (status, _) = request(&app, "GET", "/wallet/status", None, "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn default_watch_router_never_mounts_seed_ui_or_wallet_commands() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let chain = FakeChain::new(CommittedTip::new(8, [8; 32]));
    let watch = router(context(store, chain));
    for (method, path) in [
        (Method::GET, "/"),
        (Method::GET, "/wallet/status"),
        (Method::POST, "/wallet/unlock"),
        (Method::POST, "/api/v1/wallet/transactions/send"),
        (Method::POST, "/api/v1/mining/private-transactions"),
    ] {
        let response = watch
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("api_key", KEY)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                response.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{path}"
        );
    }
    assert!(!dir.path().join("wallet").exists());
}

#[tokio::test]
async fn unavailable_private_queue_and_future_account_routes_return_typed_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _, _) = app(&dir);
    let (status, body) = request(
        &app,
        "GET",
        "/api/v1/mining/private-transactions",
        Some(KEY),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"reason":"private_mining_unavailable"}));
    for path in ["/api/v1/accounts", "/api/v1/transactions-psbt/example"] {
        let (status, body) = request(&app, "GET", path, Some(KEY), "").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["reason"], "route_unavailable");
    }
}

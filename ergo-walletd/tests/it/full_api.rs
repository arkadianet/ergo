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
    app_with(dir, false)
}
fn app_with(
    dir: &tempfile::TempDir,
    message_signing: bool,
) -> (Router, Arc<SpendingSpy>, Arc<dyn WalletStore>) {
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
    if message_signing {
        host.allow_message_signing();
    }
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
/// The native and Scala wallet operations the daemon serves: the wallet,
/// scan, account, PSBT and private-queue routes the node's API documented
/// before it stopped hosting a wallet.
const WALLET_OPERATIONS: &str = include_str!("../fixtures/wallet_operations.txt");

fn operation_paths() -> Vec<(String, String)> {
    WALLET_OPERATIONS
        .lines()
        .filter_map(|line| {
            let (method, path) = line.split_once(' ')?;
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
            assert!(source.contains("wallet-api-key</code> beside the config"));
            assert!(source.contains("not the node’s api_key"));
            assert!(source.contains("invalid: 'Invalid wallet-api-key'"));
            assert!(source.contains("paste the wallet daemon’s wallet-api-key"));
            assert!(!source.contains("This is not the wallet password."));
        }
        if path == "/js/wallet.js" {
            let source = std::str::from_utf8(&bytes).unwrap();
            assert!(source.contains("Your wallet daemon"));
            assert!(source.contains("sent solely to this wallet daemon"));
            assert!(!source.contains("wallet built into this node"));
            assert!(!source.contains("YOUR NODE WALLET"));
            assert!(source
                .contains("Authorize with the contents of the <code>wallet-api-key</code> file"));
            assert!(!source.contains("Keys remain on your node"));
            // A sealed daemon must offer the unlock form, not a reconnect loop.
            assert!(source.contains("reason !== 'wallet_sealed'"));
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

#[tokio::test]
async fn status_and_confirmed_balance_reuse_the_first_node_refresh() {
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
    store.persist_scan_invalidation(false).unwrap();
    for path in [
        "/api/v1/wallet/status",
        "/api/v1/wallet/status",
        "/api/v1/wallet/balance",
        "/api/v1/wallet/balance",
    ] {
        let (status, body) = request(&app, "GET", path, Some(KEY), "").await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }
    assert_eq!(
        spy.refreshes.load(Ordering::SeqCst),
        1,
        "only the first read fetches the node's spending context"
    );
    // Unconfirmed balances need the mempool, so they always refresh.
    let (status, body) = request(
        &app,
        "GET",
        "/api/v1/wallet/balance?includeUnconfirmed=true",
        Some(KEY),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(spy.refreshes.load(Ordering::SeqCst), 2);
}

/// The Rosen Intents reference sample quote (testnet, 384 bytes).
fn rosen_quote() -> Vec<u8> {
    let mut b = b"rosen-intents/quote".to_vec();
    b.extend_from_slice(&[1, 0x10]);
    b.extend_from_slice(&[0x11; 32]);
    b.push(0);
    b.extend_from_slice(&100_000_000u64.to_be_bytes());
    b.extend_from_slice(&1_793_000_000_000u64.to_be_bytes());
    for fill in [0x22, 0x33, 0x44] {
        b.extend_from_slice(&[fill; 32]);
    }
    b.extend_from_slice(&100_000_000u64.to_be_bytes());
    b.extend_from_slice(&290_000_000_000u64.to_be_bytes());
    b.extend_from_slice(&15u16.to_be_bytes());
    b.extend_from_slice(&[0x55; 32]);
    b.extend_from_slice(&1u64.to_be_bytes());
    for s in ["ethereum", "0x11", "0xdac1", "monero", "4AdU", "native"] {
        b.extend_from_slice(&(s.len() as u16).to_be_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    b
}

fn maker_message() -> Value {
    json!({"vaultBoxId": "01".repeat(32), "side": 0, "priceNum": 1005, "priceDen": 2000,
           "minIn": 1000, "maxIn": 1_000_000_000, "expiryHeight": 1_200_010, "execFee": 1_000_000})
}

fn hex_n<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[tokio::test]
async fn message_signing_is_off_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _, _) = app(&dir);
    let body = json!({"scheme": "kadia-maker-quote-v1", "key": {"path": "m/44'/429'/0'/0/0"},
                      "message": maker_message(), "allowSpendKey": true});
    let (status, body) = request(
        &app,
        "POST",
        "/api/v1/wallet/messages/sign",
        Some(KEY),
        &body.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["reason"], "sensitive_op_disabled");
    assert!(body["detail"].as_str().unwrap().contains("message_signing"));
}

#[tokio::test]
async fn message_signing_signs_named_schemes_with_tracked_keys_only() {
    use ergo_wallet_service::engine::message_sign::{
        verify_maker_quote, verify_rosen_quote, MakerQuote, SchnorrSig,
    };
    const SIGN: &str = "/api/v1/wallet/messages/sign";
    let dir = tempfile::tempdir().unwrap();
    let (app, spy, _) = app_with(&dir, true);
    let sign = |body: Value| {
        let app = app.clone();
        async move { request(&app, "POST", SIGN, Some(KEY), &body.to_string()).await }
    };
    let maker = |key: Value, allow: bool| json!({"scheme": "kadia-maker-quote-v1", "key": key, "message": maker_message(), "allowSpendKey": allow});
    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/wallet/restore",
        Some(KEY),
        &json!({"mnemonic":MNEMONIC,"pass":PASSWORD,"derivation":{"type":"eip3"}}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Locked.
    let (status, body) = sign(maker(json!({"path": "m/44'/429'/0'/0/0"}), true)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "wallet_locked");
    // An unknown scheme is refused before any key is touched, even locked.
    let (status, body) =
        sign(json!({"scheme": "raw", "key": {"path": "m"}, "message": "00"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .contains("unknown signing scheme"));

    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/wallet/unlock",
        Some(KEY),
        &json!({"pass": PASSWORD}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, addresses) = request(&app, "GET", "/api/v1/wallet/addresses", Some(KEY), "").await;
    let first = addresses["items"][0]["address"]
        .as_str()
        .unwrap()
        .to_owned();

    // The first key holds the funds: refused without allowSpendKey.
    let (status, body) = sign(maker(json!({"address": first}), false)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("allowSpendKey"));
    let (status, body) = sign(maker(json!({"address": first}), true)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["address"], first);
    let quote = MakerQuote {
        vault_box_id: [1; 32],
        side: 0,
        price_num: 1005,
        price_den: 2000,
        min_in: 1000,
        max_in: 1_000_000_000,
        expiry_height: 1_200_010,
        exec_fee: 1_000_000,
    };
    let q: [u8; 33] = hex_n(&body["publicKey"]);
    let sig = SchnorrSig {
        a: hex_n(&body["a"]),
        z: hex_n(&body["z"]),
    };
    assert!(verify_maker_quote(&q, &quote, &sig));
    assert_eq!(body["signedMessage"], hex::encode(quote.message()));
    let mut moved = quote;
    moved.vault_box_id = [2; 32];
    assert!(!verify_maker_quote(&q, &moved, &sig));

    // A separate derived key signs without the flag, named by its path.
    let (status, body) = request(
        &app,
        "POST",
        "/wallet/deriveKey",
        Some(KEY),
        &json!({"derivationPath": "m/44'/429'/0'/0/1", "fresh": true}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let quote_key = body["address"].as_str().unwrap().to_owned();
    let path = json!({"path": "m/44'/429'/0'/0/1"});
    let rosen = rosen_quote();
    let (status, body) = sign(json!({"scheme": "rosen-intents-quote-v1", "key": path,
        "message": {"quote": hex::encode(&rosen)}}))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["address"], quote_key);
    let q2: [u8; 33] = hex_n(&body["publicKey"]);
    assert_ne!(q2, q, "a different key from the first address");
    let h: [u8; 32] = hex_n(&body["signedMessage"]);
    let sig: [u8; 65] = hex_n(&body["signature"]);
    let sig = SchnorrSig {
        a: sig[..33].try_into().unwrap(),
        z: sig[33..].try_into().unwrap(),
    };
    assert!(verify_rosen_quote(&q2, &h, &sig));
    assert!(!verify_rosen_quote(&q, &h, &sig), "the wrong key");

    // A bare hash, a quote with another domain, a mainnet quote: refused.
    let mut domain = rosen.clone();
    domain[0] ^= 1;
    let mut mainnet = rosen.clone();
    mainnet[20] = 0;
    for bad in [h.to_vec(), domain, mainnet] {
        let (status, body) = sign(json!({"scheme": "rosen-intents-quote-v1", "key": path,
            "message": {"quote": hex::encode(bad)}}))
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    // A maker message with an unknown field, or of the other scheme.
    let mut extra = maker_message();
    extra["raw"] = json!("00");
    for (scheme, message) in [
        ("kadia-maker-quote-v1", extra),
        (
            "kadia-maker-quote-v1",
            json!({"quote": hex::encode(&rosen)}),
        ),
    ] {
        let (status, body) = sign(json!({"scheme": scheme, "key": path, "message": message})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    // Keys the wallet does not track, and ambiguous key selectors.
    let (status, body) = sign(maker(json!({"path": "m/44'/429'/0'/0/7"}), true)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    // The secp256k1 generator: a valid key no wallet derives.
    let generator: [u8; 33] =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap();
    let stranger =
        ergo_wallet::address::pubkey_to_p2pk_address(&generator, Network::Testnet.prefix())
            .unwrap();
    let (status, body) = sign(maker(json!({"address": stranger}), true)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = sign(maker(
        json!({"address": first, "path": "m/44'/429'/0'/0/1"}),
        true,
    ))
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Locked again: refused.
    let (status, _) = request(&app, "POST", "/api/v1/wallet/lock", Some(KEY), "").await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = sign(json!({"scheme": "rosen-intents-quote-v1", "key": path,
        "message": {"quote": hex::encode(&rosen)}}))
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(spy.submissions.load(Ordering::SeqCst), 0);
}

//! Runtime route-mount matrix for the native `/api/v1/*` surface.
//!
//! The OpenAPI snapshot (`openapi_native_snapshot`) proves what the derive
//! *emitted*; it cannot prove what the router actually *mounted*. The
//! conditional routes — `mempool/submit`, `mempool/check`, `node/shutdown`
//! — mount only when the matching handle is wired through `ServerCtx` and
//! the security gate. This test drives the real axum router under each
//! wiring combination and asserts the observed HTTP status codes, so a
//! regression in conditional-mount wiring fails here even if the snapshot
//! stays green.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use ergo_api::auth::{ApiSecurity, API_KEY_HEADER};
use ergo_api::compat::types::ScalaTransactionInput;
use ergo_api::server::{
    router, router_with_mempool, router_with_mempool_and_wallet_and_security, ServerCtx,
};
use ergo_api::traits::{NodeAdmin, NodeReadState, NodeSubmit, NoopMempoolView, NoopNodeAdmin};
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiTxSource,
    ApiWeightFunction, HealthStatus, SubmitError, SubmitMode, SyncStateLabel,
};
use ergo_api::wallet::NoopWalletAdmin;
use ergo_ser::address::NetworkPrefix;
use tower::ServiceExt;

// ----- stubs -----

struct StubReadState;

impl NodeReadState for StubReadState {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: String::new(),
            node_name: String::new(),
            network: String::new(),
            version: String::new(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            peer_count: 0,
            best_header_height: 0,
            best_full_block_height: 0,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
        }
    }
    fn tip(&self) -> ApiTip {
        ApiTip {
            best_header: ApiHeaderRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: String::new(),
            },
            best_full_block: ApiFullBlockRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                state_root_avl: String::new(),
                n_bits: 0,
                difficulty: String::new(),
            },
            headers_ahead_of_full_blocks: 0,
        }
    }
    fn sync(&self) -> ApiSyncStatus {
        ApiSyncStatus {
            headers_chain_synced: true,
            best_header_height: 0,
            best_full_block_height: 0,
            gap: 0,
            download_window: 0,
            pending_blocks: 0,
            recovery_done: true,
        }
    }
    fn peers(&self) -> Vec<ApiPeer> {
        Vec::new()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        ApiMempoolSummary {
            size: 0,
            total_bytes: 0,
            capacity_count: 0,
            capacity_bytes: 0,
            revalidation_pending: 0,
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        ApiMempoolTransactions {
            transactions: Vec::new(),
            weight_function: ApiWeightFunction::Cost,
        }
    }
    /// Returns a stub tx for the id this test queries ("aa") so the
    /// mounted `transactions/{tx_id}` route answers 200 — distinguishing
    /// "mounted" from a bare "route absent" 404. Any other id is absent.
    fn mempool_transaction(&self, tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        if tx_id_hex != "aa" {
            return None;
        }
        Some(ApiMempoolTransaction {
            tx_id: "aa".to_string(),
            fee_nano_erg: 0,
            fee_per_byte_nano_erg: 0,
            size_bytes: 0,
            validation_cost_units: 0,
            priority_weight: 0,
            source: ApiTxSource::Api,
            input_count: 0,
            output_count: 0,
            parents_in_pool: 0,
            first_seen_unix_ms: 0,
            first_seen_age_ms: 0,
            last_checked_age_ms: 0,
        })
    }
    fn health(&self) -> ApiHealth {
        ApiHealth {
            status: HealthStatus::Ok,
            behind: 0,
            last_progress_age_ms: 0,
            peer_count: 0,
        }
    }
}

/// Always-accept submit stub — the mount matrix only cares whether the
/// route exists, not what admission decides.
struct StubSubmit;

#[async_trait]
impl NodeSubmit for StubSubmit {
    async fn submit_transaction(
        &self,
        _bytes: Vec<u8>,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        Ok("aa".to_string())
    }
    async fn submit_transaction_json(
        &self,
        _input: ScalaTransactionInput,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        Ok("aa".to_string())
    }
}

// ----- route inventory -----

/// The 11 always-on GET routes. `transactions/aa` resolves to the stubbed
/// tx so a mounted route answers 200 rather than a tx-absent 404.
const GET_ROUTES: &[&str] = &[
    "/api/v1/info",
    "/api/v1/identity",
    "/api/v1/host",
    "/api/v1/status",
    "/api/v1/tip",
    "/api/v1/sync",
    "/api/v1/peers",
    "/api/v1/mempool/summary",
    "/api/v1/mempool/transactions",
    "/api/v1/mempool/transactions/aa",
    "/api/v1/health",
];

const SUBMIT_ROUTES: &[&str] = &["/api/v1/mempool/submit", "/api/v1/mempool/check"];
const SHUTDOWN_ROUTE: &str = "/api/v1/node/shutdown";
// Native, but gated on the Scala-compat chain reader (`compat`), which no
// constructor in this file wires — so it is always absent here. The
// wired-reachable + behavioural cases live in `difficulty_history_route.rs`.
const DIFFICULTY_HISTORY_ROUTE: &str = "/api/v1/difficulty/history";

// ----- helpers -----

fn read() -> Arc<dyn NodeReadState> {
    Arc::new(StubReadState)
}

fn submit() -> Arc<dyn NodeSubmit> {
    Arc::new(StubSubmit)
}

fn admin() -> Arc<dyn NodeAdmin> {
    Arc::new(NoopNodeAdmin)
}

/// `ApiSecurity` whose key hash matches the plaintext `"hello"` (the same
/// pair pinned by the Scala reference and `auth.rs`).
fn security() -> Arc<ApiSecurity> {
    let hash = ApiSecurity::hash_key(b"hello");
    Arc::new(ApiSecurity::new(hash).expect("valid 64-char hex hash"))
}

fn ctx(submit: Option<Arc<dyn NodeSubmit>>) -> ServerCtx {
    ServerCtx {
        read: read(),
        compat: None,
        submit,
        indexer: None,
        mempool: Arc::new(NoopMempoolView::new()),
        network: NetworkPrefix::Mainnet,
        chain_params: None,
        mining: None,
        utxo_reads_supported: true,
    }
}

async fn get(app: &axum::Router, path: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn post(app: &axum::Router, path: &str, api_key: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().method(Method::POST).uri(path);
    if let Some(key) = api_key {
        builder = builder.header(API_KEY_HEADER, key);
    }
    let resp = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn assert_all_gets_mounted(app: &axum::Router) {
    for path in GET_ROUTES {
        assert_eq!(
            get(app, path).await,
            StatusCode::OK,
            "GET {path} should be mounted and answer 200",
        );
    }
}

// ----- mount matrix -----

#[tokio::test]
async fn runtime_mount_no_handles_mounts_only_unconditional_gets() {
    let app = router(read(), None, None, None, NetworkPrefix::Mainnet);
    assert_all_gets_mounted(&app).await;
    for path in SUBMIT_ROUTES {
        assert_eq!(
            post(&app, path, None).await.0,
            StatusCode::NOT_FOUND,
            "POST {path} must 404 when no submit handle is wired",
        );
    }
    assert_eq!(
        post(&app, SHUTDOWN_ROUTE, None).await.0,
        StatusCode::NOT_FOUND,
        "shutdown must 404 when no admin handle is wired",
    );
    assert_eq!(
        get(&app, DIFFICULTY_HISTORY_ROUTE).await,
        StatusCode::NOT_FOUND,
        "difficulty/history must 404 when no chain reader is wired",
    );
}

#[tokio::test]
async fn runtime_mount_submit_wired_mounts_submit_and_check() {
    let app = router(read(), None, Some(submit()), None, NetworkPrefix::Mainnet);
    assert_all_gets_mounted(&app).await;
    for path in SUBMIT_ROUTES {
        assert_ne!(
            post(&app, path, None).await.0,
            StatusCode::NOT_FOUND,
            "POST {path} should be mounted when a submit handle is wired",
        );
    }
    assert_eq!(
        post(&app, SHUTDOWN_ROUTE, None).await.0,
        StatusCode::NOT_FOUND,
        "shutdown still 404 without an admin handle",
    );
}

#[tokio::test]
async fn runtime_mount_admin_wired_mounts_unauthed_shutdown_202() {
    let app = router_with_mempool(ctx(None), Some(admin()));
    assert_all_gets_mounted(&app).await;
    for path in SUBMIT_ROUTES {
        assert_eq!(
            post(&app, path, None).await.0,
            StatusCode::NOT_FOUND,
            "submit/check 404 without a submit handle",
        );
    }
    // Admin wired, no security gate: shutdown accepts unauthenticated.
    let (status, body) = post(&app, SHUTDOWN_ROUTE, None).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "shutdown 202 when admin wired, no security"
    );
    assert_eq!(body, "shutdown_requested");
}

#[tokio::test]
async fn runtime_mount_all_wired_gates_shutdown_on_api_key() {
    let app = router_with_mempool_and_wallet_and_security(
        ctx(Some(submit())),
        Some(admin()),
        Arc::new(NoopWalletAdmin),
        Some(security()),
    );
    assert_all_gets_mounted(&app).await;
    for path in SUBMIT_ROUTES {
        assert_ne!(
            post(&app, path, None).await.0,
            StatusCode::NOT_FOUND,
            "submit/check are public (no api_key) and mounted when submit is wired",
        );
    }
    // Shutdown is admin + api_key gated.
    assert_eq!(
        post(&app, SHUTDOWN_ROUTE, None).await.0,
        StatusCode::FORBIDDEN,
        "shutdown 403 without api_key when security is wired",
    );
    let (status, body) = post(&app, SHUTDOWN_ROUTE, Some("hello")).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "shutdown 202 with a valid api_key"
    );
    assert_eq!(
        body, "shutdown_requested",
        "202 body is the literal shutdown_requested"
    );
}

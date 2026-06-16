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
            last_block_apply_error: None,
            block_apply_errors_total: 0,
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
        emission: None,
        emission_scripts: None,
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

// ----- POST /peers/connect (admin-wired, api_key-gated, Scala parity) -----

/// Admin recorder: captures the parsed `SocketAddr` handed to
/// `connect_to_peer` so the route tests can pin body parsing.
#[derive(Default)]
struct RecordingAdmin {
    connected: std::sync::Mutex<Option<std::net::SocketAddr>>,
}

impl NodeAdmin for RecordingAdmin {
    fn request_shutdown(&self) {}
    fn connect_to_peer(&self, addr: std::net::SocketAddr) {
        *self.connected.lock().unwrap() = Some(addr);
    }
}

async fn post_body(
    app: &axum::Router,
    path: &str,
    api_key: Option<&str>,
    body: &'static str,
) -> StatusCode {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(key) = api_key {
        builder = builder.header(API_KEY_HEADER, key);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn peers_connect_unwired_admin_is_404() {
    let app = router_with_mempool(ctx(None), None);
    assert_eq!(
        post_body(&app, "/peers/connect", None, "\"127.0.0.1:5673\"").await,
        StatusCode::NOT_FOUND,
        "connect must 404 when no admin handle is wired",
    );
}

#[tokio::test]
async fn peers_connect_is_api_key_gated_and_records_the_addr() {
    let recorder = Arc::new(RecordingAdmin::default());
    let app = router_with_mempool_and_wallet_and_security(
        ctx(None),
        Some(recorder.clone() as Arc<dyn NodeAdmin>),
        Arc::new(NoopWalletAdmin),
        Some(security()),
    );
    // Scala: `connect` carries withAuth — bare requests reject on the key.
    assert_eq!(
        post_body(&app, "/peers/connect", None, "\"127.0.0.1:5673\"").await,
        StatusCode::FORBIDDEN,
    );
    // With the key: 200, and the JSON-string body parses to the SocketAddr.
    assert_eq!(
        post_body(&app, "/peers/connect", Some("hello"), "\"127.0.0.1:5673\"").await,
        StatusCode::OK,
    );
    assert_eq!(
        *recorder.connected.lock().unwrap(),
        Some("127.0.0.1:5673".parse().unwrap()),
        "host:port body forwarded to the admin as a parsed SocketAddr",
    );
}

#[tokio::test]
async fn peers_connect_malformed_body_is_400() {
    let recorder = Arc::new(RecordingAdmin::default());
    let app = router_with_mempool_and_wallet_and_security(
        ctx(None),
        Some(recorder.clone() as Arc<dyn NodeAdmin>),
        Arc::new(NoopWalletAdmin),
        Some(security()),
    );
    // Scala: regex mismatch → ApiError.BadRequest. Both a non-address
    // string and a non-string JSON body reject.
    for body in ["\"not-an-address\"", "\"1.2.3.4\"", "{\"host\":\"x\"}"] {
        assert_eq!(
            post_body(&app, "/peers/connect", Some("hello"), body).await,
            StatusCode::BAD_REQUEST,
            "bad body {body} must 400",
        );
    }
    assert_eq!(*recorder.connected.lock().unwrap(), None);
}

// ----- POST /api/v1/votes (admin-wired, api_key-gated operator write) -----

/// Admin that mirrors the production `set_voting_targets` shape: rejects when
/// `mining` is off (MiningDisabled), rejects non-votable ids (NotVotable), else
/// records the accepted set. Lets the route tests pin gating + error mapping +
/// body parsing without pulling the node impl in.
struct RecordingVotingAdmin {
    mining: bool,
    last: std::sync::Mutex<Option<Vec<(u8, i64)>>>,
}

impl NodeAdmin for RecordingVotingAdmin {
    fn request_shutdown(&self) {}
    fn set_voting_targets(
        &self,
        targets: Vec<(u8, i64)>,
    ) -> Result<(), ergo_api::VotingControlError> {
        if !self.mining {
            return Err(ergo_api::VotingControlError::MiningDisabled);
        }
        for (id, _) in &targets {
            if !(1..=9).contains(id) {
                return Err(ergo_api::VotingControlError::NotVotable { parameter_id: *id });
            }
        }
        *self.last.lock().unwrap() = Some(targets);
        Ok(())
    }
}

fn voting_app(mining: bool) -> (axum::Router, Arc<RecordingVotingAdmin>) {
    let admin = Arc::new(RecordingVotingAdmin {
        mining,
        last: std::sync::Mutex::new(None),
    });
    let app = router_with_mempool_and_wallet_and_security(
        ctx(None),
        Some(admin.clone() as Arc<dyn NodeAdmin>),
        Arc::new(NoopWalletAdmin),
        Some(security()),
    );
    (app, admin)
}

#[tokio::test]
async fn votes_post_is_api_key_gated_and_records_targets() {
    let (app, admin) = voting_app(true);
    let body = "{\"votes\":[{\"parameterId\":3,\"target\":600000}]}";
    // Auth-gated: no key → 403, the handler never runs.
    assert_eq!(
        post_body(&app, "/api/v1/votes", None, body).await,
        StatusCode::FORBIDDEN,
        "voting write must reject without the api_key",
    );
    assert!(
        admin.last.lock().unwrap().is_none(),
        "rejected write never reached the admin"
    );
    // With the key → 204 and the parsed targets reach the admin.
    assert_eq!(
        post_body(&app, "/api/v1/votes", Some("hello"), body).await,
        StatusCode::NO_CONTENT,
    );
    assert_eq!(*admin.last.lock().unwrap(), Some(vec![(3u8, 600_000i64)]));
}

#[tokio::test]
async fn votes_post_mining_disabled_is_409() {
    let (app, _admin) = voting_app(false);
    assert_eq!(
        post_body(
            &app,
            "/api/v1/votes",
            Some("hello"),
            "{\"votes\":[{\"parameterId\":3,\"target\":600000}]}",
        )
        .await,
        StatusCode::CONFLICT,
        "a non-mining node rejects the voting write with 409",
    );
}

#[tokio::test]
async fn votes_post_non_votable_id_is_400() {
    let (app, _admin) = voting_app(true);
    // blockVersion (123) is not operator-votable.
    assert_eq!(
        post_body(
            &app,
            "/api/v1/votes",
            Some("hello"),
            "{\"votes\":[{\"parameterId\":123,\"target\":4}]}",
        )
        .await,
        StatusCode::BAD_REQUEST,
    );
}

#[tokio::test]
async fn votes_post_malformed_body_is_400() {
    let (app, _admin) = voting_app(true);
    for body in ["not json", "{}", "{\"votes\":\"x\"}"] {
        assert_eq!(
            post_body(&app, "/api/v1/votes", Some("hello"), body).await,
            StatusCode::BAD_REQUEST,
            "malformed body {body} must 400",
        );
    }
}

// ----- auth gate vs. router fallback (unknown paths must 404, never 403) -----
//
// Regression tests for the `.layer` fallback-capture bug: wrapping a
// subtree with `Router::layer` also wraps that subtree's implicit
// fallback, and `Router::merge` propagates the wrapped fallback into the
// assembled router. The observable symptom: with security wired, EVERY
// unmatched path (e.g. the then-unimplemented `/emission/at/{h}`)
// answered `403 invalid.api-key` instead of `404` — masking "route does
// not exist" as "you need a key". The gate must be mounted with
// `route_layer` (fires only on matched routes); the gated prefixes keep
// Scala's whole-prefix semantics via explicit catch-all routes instead.

async fn get_with_key(app: &axum::Router, path: &str, api_key: Option<&str>) -> StatusCode {
    let mut b = Request::builder().method(Method::GET).uri(path);
    if let Some(k) = api_key {
        b = b.header(API_KEY_HEADER, k);
    }
    app.clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

fn all_wired_app() -> axum::Router {
    router_with_mempool_and_wallet_and_security(
        ctx(Some(submit())),
        Some(admin()),
        Arc::new(NoopWalletAdmin),
        Some(security()),
    )
}

#[tokio::test]
async fn unknown_path_is_404_not_auth_gated() {
    let app = all_wired_app();
    assert_eq!(
        get_with_key(&app, "/zzz-definitely-not-a-route", None).await,
        StatusCode::NOT_FOUND,
        "an unmatched path must 404 bare — a 403 here means an auth layer \
         captured the router fallback",
    );
    assert_eq!(
        get_with_key(&app, "/zzz-definitely-not-a-route", Some("hello")).await,
        StatusCode::NOT_FOUND,
        "an unmatched path must 404 with a valid key too",
    );
}

#[tokio::test]
async fn unknown_wallet_subpath_keeps_whole_prefix_gated() {
    // Scala gates the whole `wallet` pathPrefix before inner route
    // matching (`(pathPrefix("wallet") & withAuth)`, WalletApiRoute.scala),
    // so an unknown subpath rejects on the key first.
    let app = all_wired_app();
    assert_eq!(
        get_with_key(&app, "/wallet/zzz-not-a-wallet-route", None).await,
        StatusCode::FORBIDDEN,
        "unknown /wallet/* subpath must still hit the api_key gate bare",
    );
    assert_eq!(
        get_with_key(&app, "/wallet/zzz-not-a-wallet-route", Some("hello")).await,
        StatusCode::NOT_FOUND,
        "unknown /wallet/* subpath is a plain 404 once the key passes \
         (house unmounted/unknown-surface rule; Scala would render its \
         global 400 bad.request envelope here — deliberate divergence)",
    );
    assert_eq!(
        get_with_key(&app, "/wallet", None).await,
        StatusCode::FORBIDDEN,
        "the bare /wallet prefix itself is gated (Scala pathPrefix parity)",
    );
}

#[tokio::test]
async fn unknown_node_subpath_keeps_whole_prefix_gated() {
    // Scala gates the whole `node` pathPrefix the same way (probed live:
    // GET /node/zzz on the reference node → 403 forbidden).
    let app = all_wired_app();
    assert_eq!(
        get_with_key(&app, "/node/zzz-not-a-node-route", None).await,
        StatusCode::FORBIDDEN,
        "unknown /node/* subpath must still hit the api_key gate bare",
    );
    assert_eq!(
        get_with_key(&app, "/node/zzz-not-a-node-route", Some("hello")).await,
        StatusCode::NOT_FOUND,
        "unknown /node/* subpath is a plain 404 once the key passes",
    );
}

// ----- /emission/at (Scala-compat, public, stateless) -----
//
// The schedule math is oracle-tested in `ergo-mining` against vectors
// captured from the live Scala node; these tests pin the route shape:
// JSON key spelling, publicness (no api_key even when security is
// wired — the original `/emission/at` 403 regression), the axum-default
// 400 on a malformed height (house pattern, same as `/blocks/at/:h`),
// and the unmounted→404 rule.

struct FixtureEmission;

impl ergo_api::emission::EmissionSchedule for FixtureEmission {
    fn emission_info_at(&self, height: u32) -> ergo_api::emission::EmissionInfoJson {
        // The h=1_786_000 live-Scala vector (15 ERG era: charge 12, miner 3).
        ergo_api::emission::EmissionInfoJson {
            height,
            miner_reward: 3_000_000_000,
            total_coins_issued: 95_261_940_000_000_000,
            total_remain_coins: 2_477_985_000_000_000,
            reemitted: 12_000_000_000,
        }
    }
}

fn app_with_emission_and_security() -> axum::Router {
    let mut c = ctx(None);
    c.emission = Some(Arc::new(FixtureEmission));
    router_with_mempool_and_wallet_and_security(
        c,
        Some(admin()),
        Arc::new(NoopWalletAdmin),
        Some(security()),
    )
}

#[tokio::test]
async fn emission_at_is_public_even_with_security_wired() {
    let app = app_with_emission_and_security();
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/emission/at/1786000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "emission/at is ungated — Scala's EmissionApiRoute carries no withAuth",
    );
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        got,
        serde_json::json!({
            "height": 1_786_000u32,
            "minerReward": 3_000_000_000u64,
            "totalCoinsIssued": 95_261_940_000_000_000u64,
            "totalRemainCoins": 2_477_985_000_000_000u64,
            "reemitted": 12_000_000_000u64,
        }),
        "JSON keys + values must match the live-Scala envelope",
    );
}

#[tokio::test]
async fn emission_at_malformed_height_is_400() {
    let app = app_with_emission_and_security();
    assert_eq!(
        get_with_key(&app, "/emission/at/not-a-number", None).await,
        StatusCode::BAD_REQUEST,
        "malformed height rejects with the axum-default 400 (house \
         pattern, same as /blocks/at/:height)",
    );
}

#[tokio::test]
async fn emission_unwired_is_404_bare() {
    // No emission view in the ctx → the route is not mounted → the
    // (ungated) fallback answers 404 even bare with security wired.
    let app = all_wired_app();
    assert_eq!(
        get_with_key(&app, "/emission/at/1786000", None).await,
        StatusCode::NOT_FOUND,
        "unmounted /emission/at must 404 bare, never 403",
    );
}

// ----- /emission/scripts (Scala-compat, public, static) -----

#[tokio::test]
async fn emission_scripts_serves_three_p2s_addresses_publicly() {
    // Pre-rendered P2S addresses handed in by the node (the bridge owns
    // the tree constants + address rendering; the oracle parity test
    // lives there). Public like /emission/at — no withAuth in Scala.
    let mut c = ctx(None);
    c.emission_scripts = Some(Arc::new(ergo_api::emission::EmissionScriptsJson {
        emission: "em-addr".to_string(),
        reemission: "re-addr".to_string(),
        pay2_reemission: "p2r-addr".to_string(),
    }));
    let app = router_with_mempool_and_wallet_and_security(
        c,
        Some(admin()),
        Arc::new(NoopWalletAdmin),
        Some(security()),
    );
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/emission/scripts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "public even with security");
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        got,
        serde_json::json!({
            "emission": "em-addr",
            "reemission": "re-addr",
            "pay2Reemission": "p2r-addr",
        }),
        "JSON keys must match the Scala EmissionApiRoute.scripts envelope",
    );
}

#[tokio::test]
async fn emission_scripts_mirrors_scala_method_and_subpath_quirk() {
    // Scala's route is a bare `pathPrefix("scripts")` — no method
    // directive, no pathEnd — so the live node 200s on POST and on
    // arbitrary subpaths (probed on the reference node). Mirrored per
    // the house standard of replicating missing-directive quirks.
    let mut c = ctx(None);
    c.emission_scripts = Some(Arc::new(ergo_api::emission::EmissionScriptsJson {
        emission: "em".to_string(),
        reemission: "re".to_string(),
        pay2_reemission: "p2r".to_string(),
    }));
    let app = router_with_mempool_and_wallet_and_security(
        c,
        Some(admin()),
        Arc::new(NoopWalletAdmin),
        Some(security()),
    );
    for (method, uri) in [
        (Method::POST, "/emission/scripts"),
        (Method::GET, "/emission/scripts/zzz"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{method} {uri}");
    }
}

#[tokio::test]
async fn emission_scripts_unwired_is_404() {
    // Chain specs without verified script constants (testnet/dev) leave
    // the view None → route unmounted → 404, documented in the openapi.
    let app = app_with_emission_and_security();
    assert_eq!(
        get_with_key(&app, "/emission/scripts", None).await,
        StatusCode::NOT_FOUND,
    );
}

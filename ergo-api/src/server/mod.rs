//! HTTP server: axum router, handlers, asset serving.
//!
//! Local-only by default. The caller chooses the bind address; binding
//! beyond loopback requires `[api] public_bind = true` plus
//! `[api.security].api_key_hash` at the config layer. `/wallet/*` and
//! `/node/shutdown` are auth-gated by `require_api_key` middleware
//! whenever a `Some(ApiSecurity)` reaches `router_with_mempool_and_
//! wallet_and_security`; the rest of the surface stays unauthenticated.
//!
//! Entry points come in two tiers. The positional convenience builders
//! (`serve_on`, `serve`, `router`, `router_with_wallet`) hardwire a
//! `NoopMempoolView`/`NoopWalletAdmin` and no auth gate — they let tests
//! stand up a router without assembling a full `ServerCtx`. Production
//! goes through the explicit builder
//! (`serve_on_with_mempool_and_wallet_and_security` /
//! `router_with_mempool_and_wallet_and_security`), which takes the
//! `Option<ApiSecurity>` gate as a required argument, never defaulted, so
//! enabling auth is a conscious decision at every call site rather than a
//! fallthrough.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::{error, info};

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{from_fn, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, head, post},
    Json, Router,
};
use tokio::task::JoinHandle;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::trace::TraceLayer;

use crate::blockchain::{
    balance_for_address_handler, balance_post_handler, block_by_header_id_handler,
    blocks_by_header_ids_handler, box_by_id_handler, box_by_index_handler, box_range_get_handler,
    box_range_post_handler, boxes_by_address_get_handler, boxes_by_address_post_handler,
    boxes_by_ergo_tree_post_handler, boxes_by_template_hash_handler, boxes_by_token_id_handler,
    boxes_unspent_by_address_get_handler, boxes_unspent_by_address_post_handler,
    boxes_unspent_by_ergo_tree_post_handler, boxes_unspent_by_template_hash_handler,
    boxes_unspent_by_token_id_handler, enforce_status_gate, indexed_height_handler,
    storage_rent_eligible_handler, storage_rent_matures_at_handler,
    storage_rent_matures_in_range_handler, token_by_id_handler, tokens_by_ids_handler,
    transaction_range_get_handler, transaction_range_post_handler, tx_by_id_handler,
    tx_by_index_handler, tx_detail_handler, txs_by_address_get_handler,
    txs_by_address_post_handler, BlockchainState,
};
use crate::compat::handlers::{
    block_by_id_handler as scala_block_by_id_handler,
    block_by_ids_handler as scala_block_by_ids_handler,
    block_ids_at_height_handler as scala_block_ids_at_height_handler,
    block_transactions_by_id_handler as scala_block_transactions_by_id_handler,
    chain_slice_handler as scala_chain_slice_handler,
    header_by_id_handler as scala_header_by_id_handler,
    header_ids_paged_handler as scala_header_ids_paged_handler, info_handler as scala_info_handler,
    last_headers_handler as scala_last_headers_handler,
    modifier_by_id_handler as scala_modifier_by_id_handler,
    nipopow_header_by_height_handler as scala_nipopow_header_by_height_handler,
    nipopow_header_by_id_handler as scala_nipopow_header_by_id_handler,
    nipopow_proof_at_handler as scala_nipopow_proof_at_handler,
    nipopow_proof_handler as scala_nipopow_proof_handler,
    peers_all_handler as scala_peers_all_handler,
    peers_connected_handler as scala_peers_connected_handler,
    pool_contains_handler as scala_pool_contains_handler,
    pool_tx_ids_handler as scala_pool_tx_ids_handler,
    proof_for_tx_handler as scala_proof_for_tx_handler,
    utxo_box_by_id_handler as scala_utxo_box_by_id_handler,
    utxo_box_bytes_by_id_handler as scala_utxo_box_bytes_by_id_handler,
    utxo_genesis_handler as scala_utxo_genesis_handler,
    utxo_with_pool_box_by_id_handler as scala_utxo_with_pool_box_by_id_handler,
    utxo_with_pool_box_bytes_by_id_handler as scala_utxo_with_pool_box_bytes_by_id_handler,
    utxo_with_pool_boxes_by_ids_handler as scala_utxo_with_pool_boxes_by_ids_handler,
};
use crate::compat::traits::NodeChainQuery;
use crate::traits::ChainParamsView;
use crate::traits::{MempoolView, NodeAdmin, NodeReadState, NodeSubmit, NoopMempoolView};
use crate::web::{
    JS_API_CLIENT, JS_APP, JS_AUTH, JS_CHART, JS_EXPLORER, JS_FEE_STATS, JS_FORMAT, JS_MEMPOOL,
    JS_MINERS, JS_MINING, JS_OVERVIEW, JS_PEERS, JS_ROUTER, JS_SETTINGS, JS_SPARKLINE, JS_TABLE,
    JS_TOKEN_META, JS_VOTING, JS_WALLET, JS_WS_CLIENT,
};
use ergo_indexer_types::IndexerQuery;
use ergo_ser::address::NetworkPrefix;

mod assets;
mod handlers;
mod openapi;
mod shared;

pub use openapi::native_openapi_yaml;
pub(crate) use openapi::NativeOpenApi;
pub(crate) use shared::{map_submit_error, submit_via_node};

use assets::{
    components_css, dashboard_css, index, inter_variable_woff2, jetbrains_mono_woff2, js,
    openapi_native_json, openapi_native_yaml, openapi_v1_json, openapi_v1_yaml_handler,
    openapi_yaml, swagger, swagger_native, swagger_v1, tokens_css,
};
use handlers::{
    difficulty_history_handler, events_handler, health_handler, host_handler, identity_handler,
    info_handler, metrics_handler, miner_stats_handler, peers_connect_handler, peers_handler,
    recent_blocks_handler, set_votes_handler, shutdown_handler, status_handler, sync_handler,
    tip_handler, votes_handler, votes_history_handler,
};

/// Bundle of router/server dependencies threaded through every entry
/// point on this module.
///
/// `read`, `compat`, `submit`, `indexer` and `network` are required by
/// every route. `mempool` is required for the unconfirmed overlay
/// (`/blockchain/balance`, `/blockchain/box/unspent/*`); the
/// no-overlay variants ([`serve_on`], [`serve`], [`router`])
/// construct a [`NoopMempoolView`] internally and route through this
/// same struct.
#[derive(Clone)]
pub struct ServerCtx {
    pub read: Arc<dyn NodeReadState>,
    pub compat: Option<Arc<dyn NodeChainQuery>>,
    pub submit: Option<Arc<dyn NodeSubmit>>,
    pub indexer: Option<Arc<dyn IndexerQuery>>,
    pub mempool: Arc<dyn MempoolView>,
    pub network: NetworkPrefix,
    /// Read-side voted-protocol parameter view used by the storage-rent
    /// eligibility endpoint. `None` ⇒ that route is not mounted; every
    /// other `/blockchain/*` route is unaffected.
    pub chain_params: Option<Arc<dyn ChainParamsView>>,
    /// `/mining/*` endpoints (external-miner candidate fetch + solution
    /// submission). `None` ⇒ those routes are not mounted; the rest of
    /// the API is unaffected. The integrator mounts a real handle when
    /// `[mining].enabled = true`.
    pub mining: Option<Arc<dyn crate::mining::NodeMining>>,
    /// Scala-compat `/emission/at/{height}` schedule view. `None` ⇒ the
    /// route is not mounted (404). Production always wires it — the
    /// schedule is static per-network math, valid in every node mode.
    /// Public by Scala parity: never touched by the `api_key` gate.
    pub emission: Option<Arc<dyn crate::emission::EmissionSchedule>>,
    /// Scala-compat `/emission/scripts` — the three emission-related
    /// contracts as pre-rendered P2S addresses. `None` ⇒ 404 (chain
    /// specs without verified script constants, i.e. testnet/dev
    /// pending an oracle capture). Public like the rest of `/emission`.
    pub emission_scripts: Option<Arc<crate::emission::EmissionScriptsJson>>,
    /// Whether the node's state backend retains UTXO box bytes. When
    /// `true` (default — Mode 1 UTXO backend), the seven `/utxo/*`
    /// routes mount the real handlers. When `false` (Mode 5 digest
    /// backend), the routes are replaced with a `503 Service
    /// Unavailable` carrying Scala's "lookup not supported in this
    /// state type" body — the rest of the API remains available.
    /// The integrator sets this from the resolved `state_type`.
    pub utxo_reads_supported: bool,
}

/// Bind a TCP listener for the API server without starting axum.
///
/// Splits the bind step out of [`serve`] so callers that need to know
/// the actual bound address before constructing dependent state (e.g.
/// the Scala-compat `rest_api_url` field) can resolve `:0` to a real
/// port first, build their bridges with that address, then hand the
/// listener to [`serve_on`] to start serving.
pub async fn bind(addr: SocketAddr) -> std::io::Result<(SocketAddr, tokio::net::TcpListener)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let actual = listener.local_addr()?;
    Ok((actual, listener))
}

/// The process-wide realtime handle (WS fan-out bus + connection limiter).
/// Constructed once, on first call, and shared for the life of the
/// process — same singleton the router uses internally to feed the
/// `blocks` coarse-ring bridge, so a caller reaching for it before or
/// after router assembly gets the identical `Arc<RealtimeBus>`.
///
/// This is the seam `ergo-node` uses to publish mempool `tx_accepted` /
/// `tx_dropped` events directly (bypassing the coarse ring, which only
/// carries block/reorg/peer events): grab the bus here, wrap it in an
/// adapter that implements `ergo_mempool::MempoolObserver`, and hand it to
/// `Mempool::set_observer`.
pub fn realtime_handle() -> crate::v1::RealtimeHandle {
    static V1_REALTIME: std::sync::OnceLock<crate::v1::RealtimeHandle> = std::sync::OnceLock::new();
    V1_REALTIME
        .get_or_init(crate::v1::RealtimeHandle::blocks_and_mempool)
        .clone()
}

/// Start serving on a pre-bound `listener`. Spawns the axum task and
/// returns its join handle.
///
/// Shutdown contract: when `shutdown_rx` resolves (or its sender is
/// dropped), axum stops accepting new connections and waits for
/// in-flight request handlers to complete naturally — `submit` /
/// `check` handlers waiting on the action loop's oneshot reply get
/// the chance to surface a structured `503 shutting_down` JSON body
/// (the `RecvError` path in `api_bridge.rs`) instead of the abrupt
/// TCP RST that `JoinHandle::abort()` produces. Pair this with the
/// action loop's shutdown so the loop stays alive long enough to
/// reply to in-flight handlers (typical drain: well under
/// `SUBMIT_TIMEOUT`). The pairing here is the difference between
/// "graceful drain with structured 503" and "TCP RST mid-flight".
///
/// Pair with [`bind`] when the bound address must be observed before
/// constructing router state. For the simple case where the caller
/// doesn't need the resolved address up front, use [`serve`].
#[allow(clippy::too_many_arguments)]
pub fn serve_on(
    read: Arc<dyn NodeReadState>,
    compat: Option<Arc<dyn NodeChainQuery>>,
    submit: Option<Arc<dyn NodeSubmit>>,
    indexer: Option<Arc<dyn IndexerQuery>>,
    network: NetworkPrefix,
    utxo_reads_supported: bool,
    listener: tokio::net::TcpListener,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> JoinHandle<()> {
    let ctx = ServerCtx {
        read,
        compat,
        submit,
        indexer,
        mempool: Arc::new(NoopMempoolView::new()),
        network,
        chain_params: None,
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported,
    };
    serve_on_with_mempool(ctx, listener, shutdown_rx, None)
}

/// Variant of [`serve_on`] that accepts a snapshot-backed
/// [`MempoolView`] so the P5 unconfirmed overlay (`/blockchain/balance`,
/// `/blockchain/box/unspent/*` `includeUnconfirmed` /
/// `excludeMempoolSpent`) can read pool state without going through the
/// node's main loop. Production code uses this entry point;
/// [`serve_on`] keeps the legacy positional signature for the test
/// callers that don't need the overlay.
///
/// Wallet routes are backed by a [`crate::wallet::NoopWalletAdmin`] and
/// the auth gate is `None`. For production, use
/// [`serve_on_with_mempool_and_wallet_and_security`] directly.
pub fn serve_on_with_mempool(
    ctx: ServerCtx,
    listener: tokio::net::TcpListener,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    admin: Option<Arc<dyn NodeAdmin>>,
) -> JoinHandle<()> {
    // Test entry point: no wallet, no auth. Production uses
    // [`serve_on_with_mempool_and_wallet_and_security`] directly.
    serve_on_with_mempool_and_wallet_and_security(
        ctx,
        listener,
        shutdown_rx,
        admin,
        Arc::new(crate::wallet::NoopWalletAdmin),
        None,
    )
}

/// Full-featured server entry point: mempool overlay + `NodeAdmin` +
/// `WalletAdmin` + explicit `Option<Arc<ApiSecurity>>`.
///
/// Production `ergo-node` passes `Some(operator_security)` so
/// `/wallet/*` and the two `/node/shutdown` aliases are gated by the
/// configured `api_key_hash`. Tests that don't exercise the auth gate
/// pass `None` and document the choice at the call site — no
/// convenience wrapper exists that hides the parameter, by design:
/// it would re-introduce the "did production remember to enable auth?"
/// footgun.
pub fn serve_on_with_mempool_and_wallet_and_security(
    ctx: ServerCtx,
    listener: tokio::net::TcpListener,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    admin: Option<Arc<dyn NodeAdmin>>,
    wallet_admin: Arc<dyn crate::wallet::WalletAdmin>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> JoinHandle<()> {
    let bind_addr = listener.local_addr().ok();
    // v1 boot-warn: loudly flag a network-reachable T1/T2 surface under
    // a weak/default (or absent) api_key. Called once here, right after the
    // bind address is known and before serving — the documented startup seam.
    if let Some(addr) = bind_addr {
        crate::v1::warn_startup_posture(security.as_deref(), addr);
    }
    let app = router_with_mempool_and_wallet_and_security(ctx, admin, wallet_admin, security);
    let actual = bind_addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
    info!(addr = %actual, "api listening");
    tokio::spawn(async move {
        // `into_make_service_with_connect_info` installs `ConnectInfo<SocketAddr>`
        // so the v1 governor / auth tier can read the real peer IP for per-IP
        // rate-bucketing and the loopback exemption (v1 `client_ip`). Absent it,
        // the governor buckets every caller under one shared "unknown" key.
        let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
        let server = axum::serve(listener, make_service).with_graceful_shutdown(async move {
            // RecvError → caller dropped the sender, also a shutdown
            // signal. Either way, we exit the accept loop and let
            // in-flight handlers complete.
            let _ = shutdown_rx.await;
        });
        if let Err(e) = server.await {
            error!(error = %e, "api server exited with error");
        }
    })
}

/// Convenience: bind + serve in one call. Returns the actually-bound
/// socket address (resolves `:0` to a kernel-assigned port) and the
/// join handle of the background task.
///
/// `compat` is optional. When provided, the Scala-compatible surface is
/// mounted at bare paths (e.g. `/info`) alongside the operator dashboard
/// at `/api/v1/*`. The two surfaces share the same listener but use
/// distinct state and DTOs.
///
/// `submit` is optional. When `Some`, the submission routes
/// (`POST /api/v1/mempool/{submit,check}`, `POST /transactions[/bytes]
/// [/check[Bytes]]`, `POST /blocks`, plus
/// `GET /api/v1/mempool/transactions/{tx_id}`) are mounted. `None`
/// keeps the API read-only — in production the node always passes
/// `Some(_)` (matching Scala's unconditional route registration); the
/// option stays for test fixtures that drive the read-side router
/// without a submit bridge.
///
/// `shutdown_rx` triggers axum's graceful drain. See [`serve_on`] for
/// the contract.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    read: Arc<dyn NodeReadState>,
    compat: Option<Arc<dyn NodeChainQuery>>,
    submit: Option<Arc<dyn NodeSubmit>>,
    indexer: Option<Arc<dyn IndexerQuery>>,
    network: NetworkPrefix,
    utxo_reads_supported: bool,
    addr: SocketAddr,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let (actual, listener) = bind(addr).await?;
    let handle = serve_on(
        read,
        compat,
        submit,
        indexer,
        network,
        utxo_reads_supported,
        listener,
        shutdown_rx,
    );
    Ok((actual, handle))
}

/// Handler mounted in place of the seven live `/utxo/*` Scala-compat
/// handlers whenever the node's state backend does not retain UTXO
/// box bytes. Returns `503 Service Unavailable` with a JSON body
/// describing the limitation. Mounted by
/// [`router_with_mempool_and_wallet_and_security`] when
/// `ServerCtx::utxo_reads_supported = false`.
///
/// The body shape is `[derived]` — locally authored to be
/// operator-actionable. No Scala oracle pin exists for the
/// `/utxo/*` envelope under `stateType=Digest` yet; a later phase
/// can tighten this against a captured Scala response.
async fn utxo_lookup_unsupported_in_digest_mode() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": 503,
            "reason": "Lookup is not supported for stateType=digest",
            "detail": "/utxo/* routes require the UTXO box store; the node's state backend retains only authenticated digests"
        })),
    )
        .into_response()
}

/// `GET /utxo/getSnapshotsInfo` — Scala `UtxoApiRoute.getSnapshotsInfo`
/// serves the locally-stored UTXO snapshot set. This build's serve side
/// caches at most one snapshot (rebuilt at each 52,224-block boundary,
/// in-memory only — empty at boot and on digest backends); the same
/// view answers the P2P `SnapshotsInfo` message, so REST and wire can
/// never disagree — the property Scala gets by reading one SnapshotsDb
/// from both paths. Value-identical to Scala's envelope
/// (`{"availableManifests": {height: manifestHex}}`).
async fn scala_utxo_snapshots_info_handler(
    State(chain): State<Arc<dyn NodeChainQuery>>,
) -> Json<serde_json::Value> {
    let manifests: serde_json::Map<String, serde_json::Value> = chain
        .snapshots_info()
        .into_iter()
        .map(|(h, id)| (h.to_string(), serde_json::Value::String(id)))
        .collect();
    Json(serde_json::json!({ "availableManifests": manifests }))
}

/// Build the Scala-compat `/utxo/*` subtree, typed to match the
/// surrounding Scala-compat router's state. When the state backend
/// retains UTXO box bytes (Mode 1), mount the seven live handlers.
/// When it does not (Mode 5 digest backend), mount the same
/// path+method shapes with the 503 handler, which takes no state and
/// so sits in the same `Router<Arc<dyn NodeChainQuery>>` shape and
/// merges cleanly into the parent without rebinding state.
fn scala_utxo_subtree(utxo_reads_supported: bool) -> Router<Arc<dyn NodeChainQuery>> {
    if utxo_reads_supported {
        Router::new()
            .route("/utxo/genesis", get(scala_utxo_genesis_handler))
            .route("/utxo/byId/:box_id", get(scala_utxo_box_by_id_handler))
            .route(
                "/utxo/byIdBinary/:box_id",
                get(scala_utxo_box_bytes_by_id_handler),
            )
            .route(
                "/utxo/withPool/byId/:box_id",
                get(scala_utxo_with_pool_box_by_id_handler),
            )
            .route(
                "/utxo/withPool/byIdBinary/:box_id",
                get(scala_utxo_with_pool_box_bytes_by_id_handler),
            )
            .route(
                "/utxo/withPool/byIds",
                post(scala_utxo_with_pool_boxes_by_ids_handler),
            )
            .route(
                "/utxo/getSnapshotsInfo",
                get(scala_utxo_snapshots_info_handler),
            )
    } else {
        // Mount the SAME seven path+method shapes the live router
        // mounts, but with the 503 handler. This keeps Scala-compat
        // behavior intact for the surface that doesn't exist under
        // the digest backend — unknown paths still get axum's
        // default 404 and wrong methods get 405, instead of being
        // swallowed by an over-broad wildcard.
        Router::new()
            .route("/utxo/genesis", get(utxo_lookup_unsupported_in_digest_mode))
            .route(
                "/utxo/byId/:box_id",
                get(utxo_lookup_unsupported_in_digest_mode),
            )
            .route(
                "/utxo/byIdBinary/:box_id",
                get(utxo_lookup_unsupported_in_digest_mode),
            )
            .route(
                "/utxo/withPool/byId/:box_id",
                get(utxo_lookup_unsupported_in_digest_mode),
            )
            .route(
                "/utxo/withPool/byIdBinary/:box_id",
                get(utxo_lookup_unsupported_in_digest_mode),
            )
            .route(
                "/utxo/withPool/byIds",
                post(utxo_lookup_unsupported_in_digest_mode),
            )
            // getSnapshotsInfo needs no box store, but the digest arm
            // keeps the whole /utxo surface on one posture. Known Scala
            // oracle (derivable from source): digest state is not a
            // UtxoSetSnapshotPersistence, so Scala 404s here — the
            // blanket 503 is the pre-existing documented divergence.
            .route(
                "/utxo/getSnapshotsInfo",
                get(utxo_lookup_unsupported_in_digest_mode),
            )
    }
}

/// Build the merged operator + Scala-compat router.
///
/// Exposed (`pub`) so integration tests can exercise the routing layout
/// without binding a TCP listener. Production code goes through
/// [`serve_on_with_mempool`] and reaches
/// the router via [`router_with_mempool`]; this entry point installs
/// [`NoopMempoolView`] for tests that don't care about the P5 overlay.
///
/// Mounts the wallet routes backed by a [`crate::wallet::NoopWalletAdmin`]
/// (returns zero-state for `/wallet/status`; 501 stubs for all others).
/// Pass [`router_with_wallet`] if you need a real or test `WalletAdmin`.
///
/// `/utxo/*` routes mount in their Mode 1 (UTXO backend) shape; callers
/// that need the Mode 5 digest-backend 503 shape construct a
/// [`ServerCtx`] directly and call [`router_with_mempool`] or
/// [`router_with_mempool_and_wallet_and_security`] with
/// `utxo_reads_supported: false`. Production goes through those
/// ServerCtx-direct paths via `ergo-node`'s boot dispatch, which
/// derives the field from the resolved `state_type`.
pub fn router(
    read: Arc<dyn NodeReadState>,
    compat: Option<Arc<dyn NodeChainQuery>>,
    submit: Option<Arc<dyn NodeSubmit>>,
    indexer: Option<Arc<dyn IndexerQuery>>,
    network: NetworkPrefix,
) -> Router {
    router_with_wallet(
        read,
        compat,
        submit,
        indexer,
        network,
        true,
        Arc::new(crate::wallet::NoopWalletAdmin),
    )
}

/// Variant of [`router`] that accepts a real (or test) [`crate::wallet::WalletAdmin`].
/// Used by tests that need a real `WalletAdmin` and a configurable
/// `utxo_reads_supported` without constructing a full
/// [`ServerCtx`]. Production `ergo-node` goes directly through
/// [`router_with_mempool_and_wallet_and_security`] with a fully-
/// resolved [`ServerCtx`] whose `utxo_reads_supported` is derived
/// from the resolved `state_type`.
pub fn router_with_wallet(
    read: Arc<dyn NodeReadState>,
    compat: Option<Arc<dyn NodeChainQuery>>,
    submit: Option<Arc<dyn NodeSubmit>>,
    indexer: Option<Arc<dyn IndexerQuery>>,
    network: NetworkPrefix,
    utxo_reads_supported: bool,
    wallet_admin: Arc<dyn crate::wallet::WalletAdmin>,
) -> Router {
    let ctx = ServerCtx {
        read,
        compat,
        submit,
        indexer,
        mempool: Arc::new(NoopMempoolView::new()),
        network,
        chain_params: None,
        mining: None,
        emission: None,
        emission_scripts: None,
        utxo_reads_supported,
    };
    router_with_mempool_and_wallet_and_security(ctx, None, wallet_admin, None)
}

/// Variant of [`router`] that installs a snapshot-backed
/// [`MempoolView`] in [`BlockchainState`]. Production code calls this
/// (via [`serve_on_with_mempool`]); tests that need to drive the
/// unconfirmed overlay (balance, unspent boxes) call this directly with
/// a fixture view.
///
/// Mounts wallet routes backed by a [`crate::wallet::NoopWalletAdmin`].
/// Test-only entry point — calls the security-aware builder with
/// `wallet_admin = NoopWalletAdmin` and `security = None`. Production
/// uses [`router_with_mempool_and_wallet_and_security`] directly.
pub fn router_with_mempool(ctx: ServerCtx, admin: Option<Arc<dyn NodeAdmin>>) -> Router {
    router_with_mempool_and_wallet_and_security(
        ctx,
        admin,
        Arc::new(crate::wallet::NoopWalletAdmin),
        None,
    )
}

/// Full-featured router builder: mempool overlay + explicit `WalletAdmin` +
/// explicit `Option<Arc<ApiSecurity>>` gate. When `security` is `Some`,
/// the `/wallet/*` subtree and both `/node/shutdown` aliases are wrapped
/// with [`crate::auth::require_api_key`] **before** they merge into the
/// public router — public routes (`/info`, `/blocks/*`, `/peers/*`,
/// `/transactions*`, `/utils/*`) stay unauthenticated. There is no
/// convenience wrapper that hides the security parameter; callers
/// must pass an explicit `Option` so the auth decision is local to
/// every call site rather than a default fallthrough.
pub fn router_with_mempool_and_wallet_and_security(
    ctx: ServerCtx,
    admin: Option<Arc<dyn NodeAdmin>>,
    wallet_admin: Arc<dyn crate::wallet::WalletAdmin>,
    security: Option<Arc<crate::auth::ApiSecurity>>,
) -> Router {
    let ServerCtx {
        read,
        compat,
        submit,
        indexer,
        mempool,
        network,
        chain_params,
        mining,
        emission,
        emission_scripts,
        utxo_reads_supported,
    } = ctx;
    // Native `/api/v1/*` product-API route group inputs (chain/* + transactions/*
    // reads). Cloned up front because the compat / submit handles are moved into
    // the Scala-compat match further down; the v1 group mounts unconditionally
    // and gates inside each handler on the honest `*_unavailable` / `*_disabled`
    // reason.
    let v1_read = read.clone();
    let v1_chain = compat.clone();
    let v1_indexer = indexer.clone();
    // Per-height emission schedule for the `stats/*` supply series.
    let v1_emission = emission.clone();
    let v1_submit = submit.clone();
    let v1_mempool = mempool.clone();
    // Same up-front-clone rationale for the `script/*` group: `compat` is
    // moved into the Scala-compat `match` further down, so the chain reader for
    // `simulate`/`explain` box lookups (and the tip-height reader) are captured
    // here before that move.
    let v1_script_read = read.clone();
    let v1_script_chain = compat.clone();
    // Operator/control group inputs (`node/*`, `network/*`, `mining/*`,
    // `voting/*`). Cloned up front because `admin` / `mining` are moved into
    // the Scala-compat mounts further down; the group mounts unconditionally
    // and gates inside each handler on the honest `*_unavailable` reason.
    let v1_op_read = read.clone();
    let v1_op_chain = compat.clone();
    let v1_op_admin = admin.clone();
    let v1_op_mining = mining.clone();
    let operator: Router = Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/tokens.css", get(tokens_css))
        .route("/components.css", get(components_css))
        .route("/dashboard.css", get(dashboard_css))
        .route("/fonts/jetbrains-mono.woff2", get(jetbrains_mono_woff2))
        .route("/fonts/inter-variable.woff2", get(inter_variable_woff2))
        .route("/js/app.js", get(|| async { js(JS_APP) }))
        .route("/js/api-client.js", get(|| async { js(JS_API_CLIENT) }))
        .route("/js/auth.js", get(|| async { js(JS_AUTH) }))
        .route("/js/format.js", get(|| async { js(JS_FORMAT) }))
        .route("/js/fee-stats.js", get(|| async { js(JS_FEE_STATS) }))
        .route("/js/router.js", get(|| async { js(JS_ROUTER) }))
        .route("/js/settings.js", get(|| async { js(JS_SETTINGS) }))
        .route("/js/table.js", get(|| async { js(JS_TABLE) }))
        .route("/js/sparkline.js", get(|| async { js(JS_SPARKLINE) }))
        .route("/js/chart.js", get(|| async { js(JS_CHART) }))
        .route("/js/overview.js", get(|| async { js(JS_OVERVIEW) }))
        .route("/js/explorer.js", get(|| async { js(JS_EXPLORER) }))
        .route("/js/token-meta.js", get(|| async { js(JS_TOKEN_META) }))
        .route("/js/peers.js", get(|| async { js(JS_PEERS) }))
        .route("/js/mempool.js", get(|| async { js(JS_MEMPOOL) }))
        .route("/js/voting.js", get(|| async { js(JS_VOTING) }))
        .route("/js/wallet.js", get(|| async { js(JS_WALLET) }))
        .route("/js/miners.js", get(|| async { js(JS_MINERS) }))
        .route("/js/mining.js", get(|| async { js(JS_MINING) }))
        .route("/js/ws-client.js", get(|| async { js(JS_WS_CLIENT) }))
        .route("/swagger", get(swagger))
        .route("/swagger/native", get(swagger_native))
        .route("/swagger/v1", get(swagger_v1))
        .route("/api-docs/openapi.yaml", get(openapi_yaml))
        .route("/api-docs/openapi-native.yaml", get(openapi_native_yaml))
        .route("/api-docs/openapi-native.json", get(openapi_native_json))
        .route("/api-docs/openapi-v1.yaml", get(openapi_v1_yaml_handler))
        .route("/api-docs/openapi-v1.json", get(openapi_v1_json))
        .route("/api/v1/info", get(info_handler))
        .route("/api/v1/identity", get(identity_handler))
        .route("/api/v1/host", get(host_handler))
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/votes", get(votes_handler))
        .route("/api/v1/tip", get(tip_handler))
        .route("/api/v1/blocks/recent", get(recent_blocks_handler))
        .route("/api/v1/events", get(events_handler))
        .route("/api/v1/sync", get(sync_handler))
        .route("/api/v1/peers", get(peers_handler))
        // `mempool/*` reads (summary, transactions[/{tx_id}]) are owned by the
        // v1 product router (`crate::v1::v1_router`) — reshaped into the
        // envelope + cursor. Not mounted here to avoid a route collision.
        .route("/api/v1/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(read.clone());

    // Shutdown route mounts only when an admin handle is plumbed.
    // Built as a separate Router<Arc<dyn NodeAdmin>> then state-
    // erased via `with_state` so it can `merge` into the operator
    // Router<()> without conflicting state types. Both the Scala-
    // compat path (`/node/shutdown`) and the operator path
    // (`/api/v1/node/shutdown`) are mounted.
    let operator = if let Some(admin) = admin {
        let admin_routes: Router = Router::new()
            .route("/api/v1/node/shutdown", post(shutdown_handler))
            .route("/node/shutdown", post(shutdown_handler))
            // Operator voting write — auth-gated so only the operator can change
            // what the node votes for (the read `GET /api/v1/votes` stays open).
            .route("/api/v1/votes", post(set_votes_handler))
            // Scala `ErgoPeersApiRoute.connect` is the one /peers route
            // with `withAuth` — it rides the same admin + key gate.
            .route("/peers/connect", post(peers_connect_handler))
            // Scala gates the whole `node` pathPrefix (probed live:
            // GET /node/zzz on the reference node → 403), so unknown
            // `/node/*` subpaths keep rejecting on the key first. Real
            // routes (not a fallback) so `route_layer` covers them.
            .route(
                "/node",
                axum::routing::any(crate::auth::unknown_gated_subpath),
            )
            .route(
                "/node/*rest",
                axum::routing::any(crate::auth::unknown_gated_subpath),
            )
            .with_state(admin);
        let admin_routes = match security.clone() {
            Some(sec) => admin_routes.route_layer(axum::middleware::from_fn_with_state(
                sec,
                crate::auth::require_api_key,
            )),
            None => admin_routes,
        };
        operator.merge(admin_routes)
    } else {
        operator
    };

    // `/blockchain/*` mounts only when an indexer handle is plumbed.
    // `/indexedHeight` always 200 — bypasses the status gate. The
    // byId / byIndex routes are layered with `enforce_status_gate` so
    // the `503 indexer-syncing` / `indexer-halted` envelopes
    // short-circuit before any trait method runs.
    let operator = if let Some(idx) = indexer.clone() {
        let blockchain_state = BlockchainState {
            read: read.clone(),
            indexer: idx,
            network,
            chain: compat.clone(),
            mempool: mempool.clone(),
            chain_params: chain_params.clone(),
        };
        let always_open: Router<BlockchainState> = Router::new()
            .route("/blockchain/indexedHeight", get(indexed_height_handler))
            // Operator health surface: indexedHeight + the self-repair
            // markers + totals. Ungated for the same reason indexedHeight
            // is — it must answer while syncing / repairing / halted.
            .route(
                "/api/v1/indexer/status",
                get(crate::blockchain::indexer_status_handler),
            )
            // Resolved tx detail for the UI drawer. Ungated so the
            // unconfirmed (pool) path works while the indexer is syncing.
            .route("/api/v1/transactions/:tx_id/detail", get(tx_detail_handler));
        // Tx routes mount only when both indexer and chain reader are
        // plumbed — they require the chain reader to enrich `blockId` /
        // `timestamp`. Box routes need only the indexer + network prefix.
        let mut gated: Router<BlockchainState> = Router::new()
            .route("/blockchain/box/byId/:box_id", get(box_by_id_handler))
            .route("/blockchain/box/byIndex/:n", get(box_by_index_handler))
            // Balance routes. POST takes a JSON-string body, GET takes
            // the address as a path parameter. Both project
            // `address_balance(tree_hash)` into the bare-balance envelope
            // with the pre-overlay silent-downgrade `warning`.
            .route("/blockchain/balance", post(balance_post_handler))
            .route(
                "/blockchain/balanceForAddress/:address",
                get(balance_for_address_handler),
            )
            // Box byAddress paged routes. POST takes a JSON-string body,
            // GET takes the address as a path parameter. Both project
            // `address_boxes_paged` + `address_total_boxes` into the
            // `{items, total}` envelope. Box routes mount unconditionally
            // (no chain enrichment needed beyond network).
            .route(
                "/blockchain/box/byAddress",
                post(boxes_by_address_post_handler),
            )
            .route(
                "/blockchain/box/byAddress/:address",
                get(boxes_by_address_get_handler),
            )
            // Unspent box byAddress paged routes. Same paging contract
            // as /box/byAddress but with sortDirection plus the mempool
            // overlay flags (`includeUnconfirmed`, `excludeMempoolSpent`).
            // Wire shape is a bare array, not the {items, total}
            // envelope. Mounts unconditionally — the unspent reader
            // needs only the indexer + network, not chain.
            .route(
                "/blockchain/box/unspent/byAddress",
                post(boxes_unspent_by_address_post_handler),
            )
            .route(
                "/blockchain/box/unspent/byAddress/:address",
                get(boxes_unspent_by_address_get_handler),
            )
            // byErgoTree dispatch routes (POST only). Hex-decode +
            // parse + reserialize + blake2b256 the body to obtain the
            // tree_hash, then dispatch into the same address-keyed
            // reader methods used by /box/byAddress and
            // /box/unspent/byAddress. Wire shapes match the address
            // counterparts:
            //   #24 → {items, total}
            //   #25 → bare [IndexedErgoBox]
            .route(
                "/blockchain/box/byErgoTree",
                post(boxes_by_ergo_tree_post_handler),
            )
            .route(
                "/blockchain/box/unspent/byErgoTree",
                post(boxes_unspent_by_ergo_tree_post_handler),
            )
            // byTemplateHash routes (#15, #16). Path-param hex template
            // hash (no body). Wire shapes match the address counterparts:
            //   #15 byTemplateHash         → {items, total}
            //   #16 unspent/byTemplateHash → bare [IndexedErgoBox]
            // Unknown templates return the empty envelope (Scala empty-
            // IndexedContractTemplate fallback); bad-hex path params
            // surface as 404 (Akka path-matcher rejection parity). The
            // status gate fronts both routes.
            .route(
                "/blockchain/box/byTemplateHash/:hash",
                get(boxes_by_template_hash_handler),
            )
            .route(
                "/blockchain/box/unspent/byTemplateHash/:hash",
                get(boxes_unspent_by_template_hash_handler),
            )
            // Token routes (#17, #18, #19, #20). Path-param hex tokenId
            // for #17/#19/#20; #18 takes a JSON array of hex tokenIds in
            // the body. Wire shapes:
            //   #17 byId               → IndexedToken (404 on miss)
            //   #18 tokens (POST)      → bare [IndexedToken]; misses dropped
            //   #19 byTokenId          → {items, total}
            //   #20 unspent/byTokenId  → bare [IndexedErgoBox]
            // Bad-hex path params surface as 404 (Akka path-matcher
            // parity); unknown tokens on #19/#20 return the empty
            // envelope/array (Scala fallback parity). The status gate
            // fronts all four routes.
            .route("/blockchain/token/byId/:token_id", get(token_by_id_handler))
            .route("/blockchain/tokens", post(tokens_by_ids_handler))
            .route(
                "/blockchain/box/byTokenId/:token_id",
                get(boxes_by_token_id_handler),
            )
            .route(
                "/blockchain/box/unspent/byTokenId/:token_id",
                get(boxes_unspent_by_token_id_handler),
            );
        // Storage-rent eligibility (Rust-node-exclusive). Mounts only
        // when the bridge supplied a `ChainParamsView`; otherwise the
        // route returns a `404` per axum's default routing — matches
        // the existing pattern for unwired routes.
        if blockchain_state.chain_params.is_some() {
            gated = gated
                .route(
                    "/blockchain/storageRent/eligibleAt/:height",
                    get(storage_rent_eligible_handler),
                )
                .route(
                    "/blockchain/storageRent/maturesAt/:height",
                    get(storage_rent_matures_at_handler),
                )
                .route(
                    "/blockchain/storageRent/maturesInRange",
                    get(storage_rent_matures_in_range_handler),
                );
        }
        if blockchain_state.chain.is_some() {
            gated = gated
                .route("/blockchain/transaction/byId/:tx_id", get(tx_by_id_handler))
                .route(
                    "/blockchain/transaction/byIndex/:n",
                    get(tx_by_index_handler),
                )
                // Tx byAddress paged routes. Same paging contract as the
                // box variant; tx routes additionally require the chain
                // reader to enrich `blockId` / `timestamp`, so they sit
                // inside the chain-conditional branch.
                .route(
                    "/blockchain/transaction/byAddress",
                    post(txs_by_address_post_handler),
                )
                .route(
                    "/blockchain/transaction/byAddress/:address",
                    get(txs_by_address_get_handler),
                )
                // Global tx-id range view (#8). Scala mounts no method
                // directive (`*`); we expose both GET and POST on the
                // same handler. Returns a bare `[ModifierId]` array;
                // chain reader is not required for the projection but
                // we keep #8 grouped with the rest of the transaction
                // routes so the family stays cohesive.
                .route(
                    "/blockchain/transaction/range",
                    get(transaction_range_get_handler).post(transaction_range_post_handler),
                )
                // Global box-id range view (#9). Same Scala dispatch
                // pattern as #8 (no method directive → both GET and POST
                // accepted on one handler). Returns a bare `[ModifierId]`
                // array of box ids, projected from `box.box_data.box_id()`
                // over `boxes_by_global_range(lo, hi)`.
                .route(
                    "/blockchain/box/range",
                    get(box_range_get_handler).post(box_range_post_handler),
                )
                // Block reassembly routes (#21, #22). Reassembles
                // IndexedFullBlock from chain-side header/sections joined
                // with per-tx IndexedErgoTransaction from the indexer.
                // Both routes require the chain reader, so they sit
                // inside the chain-conditional branch alongside the tx
                // routes. The status gate fronts both via the layered
                // middleware. Wire shapes:
                //   #21 byHeaderId            → IndexedFullBlock (404 on miss)
                //   #22 byHeaderIds (POST)    → bare [IndexedFullBlock];
                //                               malformed/unknown ids dropped.
                .route(
                    "/blockchain/block/byHeaderId/:header_id",
                    get(block_by_header_id_handler),
                )
                .route(
                    "/blockchain/block/byHeaderIds",
                    post(blocks_by_header_ids_handler),
                );
        }
        // `route_layer`, not `layer`: the status gate must fire only on
        // the routes registered above — a plain `layer` would also wrap
        // this subtree's implicit fallback, which `merge` propagates
        // router-wide (unknown paths would then 503 while the indexer
        // catches up, the same capture bug as the api_key gate).
        let gated = gated.route_layer(axum::middleware::from_fn_with_state(
            blockchain_state.clone(),
            enforce_status_gate,
        ));
        let blockchain = always_open.merge(gated).with_state(blockchain_state);
        operator.merge(blockchain)
    } else {
        operator
    };

    // `POST /api/v1/mempool/{submit,check}` are aliases of the
    // canonical `transactions/{submit,check}` handlers, owned by the v1 product
    // router (`crate::v1::v1_router`). They mount unconditionally there
    // and answer `409 submit_disabled` when no submit bridge is wired (the v1
    // honest-reason posture), superseding the old conditional native mount.

    // `/mining/*` mounts only when a NodeMining handle is plumbed
    // (integrator sets `[mining].enabled = true` and constructs the
    // bridge). All four routes are sourced from a single sub-router
    // builder in `crate::mining` so the handler list lives there.
    let operator = if let Some(m) = mining {
        operator.merge(crate::mining::mining_router(m))
    } else {
        operator
    };

    // `/emission/at/{height}` mounts whenever the schedule view is
    // wired (always, in production — static per-network math, valid in
    // every node mode). Public by Scala parity: `EmissionApiRoute`
    // carries no `withAuth`, so this merge happens entirely outside
    // the gated subtrees.
    let operator = if let Some(em) = emission {
        operator.merge(crate::emission::emission_router(em))
    } else {
        operator
    };

    // `/emission/scripts` mounts when the chain spec carries verified
    // script constants (mainnet). Same public posture as `/emission/at`.
    let operator = if let Some(es) = emission_scripts {
        operator.merge(crate::emission::emission_scripts_router(es))
    } else {
        operator
    };

    // `/utils/*` — Scala-parity stateless helper endpoints. Always
    // mounted (no node-state dependency); single piece of operator
    // config is `network` for address routes. Routes live in
    // `crate::utils`; we wire them here against a `Router<NetworkPrefix>`
    // and erase the state via `with_state` so the merged router stays
    // `Router<()>`.
    let utils_routes: Router<NetworkPrefix> = Router::new()
        .route("/utils/seed", get(crate::utils::seed_default_handler))
        .route(
            "/utils/seed/:length",
            get(crate::utils::seed_length_handler),
        )
        .route(
            "/utils/hash/blake2b",
            post(crate::utils::hash_blake2b_handler),
        )
        .route(
            "/utils/rawToAddress/:pubkey_hex",
            get(crate::utils::raw_to_address_handler),
        )
        .route(
            "/utils/addressToRaw/:address",
            get(crate::utils::address_to_raw_handler),
        )
        .route(
            "/utils/address/:address",
            get(crate::utils::validate_address_get_handler),
        )
        .route(
            "/utils/address",
            post(crate::utils::validate_address_post_handler),
        )
        .route(
            "/utils/ergoTreeToAddress/:tree_hex",
            get(crate::utils::ergo_tree_to_address_get_handler),
        )
        .route(
            "/utils/ergoTreeToAddress",
            post(crate::utils::ergo_tree_to_address_post_handler),
        )
        // `/script/*` decode endpoints (Scala ScriptApiRoute) — same
        // `NetworkPrefix`-only state as the `/utils` address routes. The two
        // compile-requiring members (p2sAddress / p2shAddress) mount just
        // below as their own tuple-state sub-router (`crate::script`, M6);
        // `executeWithContext` remains unimplemented.
        .route(
            "/script/addressToTree/:address",
            get(crate::utils::script_address_to_tree_handler),
        )
        .route(
            "/script/addressToBytes/:address",
            get(crate::utils::script_address_to_bytes_handler),
        );
    let operator = operator.merge(utils_routes.with_state(network));

    // `/script/p2sAddress` + `/script/p2shAddress` (Scala ScriptApiRoute's
    // compile-requiring members, M6) — a separate tuple-state sub-router
    // beside `utils_routes` above: these two need `Arc<dyn WalletAdmin>` in
    // addition to `NetworkPrefix` (Scala's `keysToEnv`, `ScriptApiRoute.scala:
    // 52-54, reads the wallet's tracked pubkeys server-side), a different
    // state shape than the stateless decode-only routes just above. PUBLIC —
    // Scala's `ScriptApiRoute` carries no `withAuth` (`ScriptApiRoute.scala:
    // 38-46`), so this does NOT ride the api-key-gated `crate::wallet::
    // router_with_security` subtree despite reading wallet state. Mirrors the
    // `miner_stats_routes` tuple-state precedent below.
    let script_routes: Router<(NetworkPrefix, Arc<dyn crate::wallet::WalletAdmin>)> = Router::new()
        .route(
            "/script/p2sAddress",
            post(crate::script::p2s_address_handler),
        )
        .route(
            "/script/p2shAddress",
            post(crate::script::p2sh_address_handler),
        );
    let operator = operator.merge(script_routes.with_state((network, wallet_admin.clone())));

    let assembled: Router = match compat {
        Some(c) => {
            // Native miner-stats rides the same chain-reader handle as the
            // Scala-compat routes but also needs the address-prefix byte,
            // so it mounts as its own mini router with a tuple state.
            let miner_stats_routes: Router = Router::new()
                .route("/api/v1/mining/minerStats", get(miner_stats_handler))
                .with_state((c.clone(), network));
            // Route ordering note: axum 0.7 picks the most specific match
            // automatically, but registering literal-segment routes
            // (`/blocks`, `/blocks/at/...`, `/blocks/chainSlice`,
            // `/blocks/lastHeaders/...`) before the catch-all
            // `/blocks/:header_id` keeps the registration log readable.
            let scala: Router = Router::new()
                // Native difficulty history rides the same chain-reader
                // state as the Scala-compat routes, so it is mounted here
                // and stays conditional on `compat` being wired.
                .route(
                    "/api/v1/difficulty/history",
                    get(difficulty_history_handler),
                )
                // Native votes-history rides the same chain-reader state as
                // the Scala-compat routes (the timeline comes from the stored
                // `voted_params` rows), so it is mounted here and stays
                // conditional on `compat` being wired.
                .route("/api/v1/votes/history", get(votes_history_handler))
                .route("/info", get(scala_info_handler))
                .route("/blocks", get(scala_header_ids_paged_handler))
                .route("/blocks/at/:height", get(scala_block_ids_at_height_handler))
                .route("/blocks/chainSlice", get(scala_chain_slice_handler))
                .route(
                    "/blocks/lastHeaders/:count",
                    get(scala_last_headers_handler),
                )
                // POST `headerIds` registers before the `:header_id` capture
                // so axum's literal-segment-first dispatch picks the literal
                // even though method routing would also disambiguate.
                .route("/blocks/headerIds", post(scala_block_by_ids_handler))
                // `modifier/:id` registers before `:header_id` for the same
                // literal-first reason. Both capture in the second segment.
                .route(
                    "/blocks/modifier/:modifier_id",
                    get(scala_modifier_by_id_handler),
                )
                .route("/blocks/:header_id", get(scala_block_by_id_handler))
                .route("/blocks/:header_id/header", get(scala_header_by_id_handler))
                .route(
                    "/blocks/:header_id/transactions",
                    get(scala_block_transactions_by_id_handler),
                )
                .route(
                    "/blocks/:header_id/proofFor/:tx_id",
                    get(scala_proof_for_tx_handler),
                )
                // NiPoPoW serve surface (`NipopowApiRoute.scala:55-90`).
                // All literal-prefixed, no capture collisions. The
                // 3-segment proof route registers after the 2-segment
                // one; axum disambiguates by arity.
                .route(
                    "/nipopow/popowHeaderById/:header_id",
                    get(scala_nipopow_header_by_id_handler),
                )
                .route(
                    "/nipopow/popowHeaderByHeight/:height",
                    get(scala_nipopow_header_by_height_handler),
                )
                .route("/nipopow/proof/:m/:k", get(scala_nipopow_proof_handler))
                .route(
                    "/nipopow/proof/:m/:k/:header_id",
                    get(scala_nipopow_proof_at_handler),
                )
                // Route ordering: the literal `/utxo/genesis` segment
                // must register before the `:box_id` capture so axum
                // doesn't misroute the literal as an id. The
                // `/utxo/withPool/*` group sits beside `/utxo/byId*`
                // because axum dispatches by the first non-matching
                // segment — `withPool` is a literal that doesn't collide
                // with `:box_id`. POST `byIds` mounts on the same path
                // axum routes by method, no extra discrimination needed.
                //
                // `/utxo/*` mounts in one of two shapes depending on
                // the state backend. Under Mode 1 (UTXO backend) the
                // seven live handlers mount. Under Mode 5 (digest
                // backend) the same seven (path, method) shapes mount
                // with a 503 handler, so unknown `/utxo/*` paths
                // still 404 and wrong methods still 405 — the
                // Scala-compat surface stays intact for everything
                // outside the seven known routes.
                .merge(scala_utxo_subtree(utxo_reads_supported))
                .route("/peers/all", get(scala_peers_all_handler))
                .route("/peers/connected", get(scala_peers_connected_handler))
                .route(
                    "/peers/blacklisted",
                    get(crate::compat::handlers::peers_blacklisted_handler),
                )
                .route(
                    "/peers/status",
                    get(crate::compat::handlers::peers_status_handler),
                )
                .route(
                    "/peers/syncInfo",
                    get(crate::compat::handlers::peers_sync_info_handler),
                )
                .route(
                    "/peers/trackInfo",
                    get(crate::compat::handlers::peers_track_info_handler),
                )
                .route(
                    "/transactions/unconfirmed/transactionIds",
                    get(scala_pool_tx_ids_handler),
                )
                // HEAD = presence probe (200/404). GET on the same
                // path is rejected with 400 to match Scala 6.0.3RC1
                // behaviour (parity probe 2026-05-19 — Scala accepts
                // the method but returns 400 with a "use
                // byTransactionId/{tx_id}" hint envelope). The wallet
                // /explorer surface uses
                // `/transactions/unconfirmed/byTransactionId/{tx_id}`
                // for the full-tx GET; this path is reserved for the
                // HEAD presence probe.
                .route(
                    "/transactions/unconfirmed/:tx_id",
                    head(scala_pool_contains_handler)
                        .get(crate::compat::handlers::pool_contains_get_hint_handler),
                )
                // Paged full-tx list. Sits at the bare `/unconfirmed`
                // path so it doesn't collide with `/:tx_id` (axum
                // routes them by exact-segment vs path-param shape).
                .route(
                    "/transactions/unconfirmed",
                    get(crate::compat::handlers::pool_txs_paged_handler),
                )
                .route(
                    "/transactions/unconfirmed/byTransactionId/:tx_id",
                    get(crate::compat::handlers::pool_tx_by_id_handler),
                )
                .route(
                    "/transactions/unconfirmed/byTransactionIds",
                    axum::routing::post(crate::compat::handlers::pool_txs_by_ids_handler),
                )
                .route(
                    "/transactions/unconfirmed/size",
                    get(crate::compat::handlers::pool_size_handler),
                )
                .route(
                    "/transactions/unconfirmed/byErgoTree",
                    post(crate::compat::handlers::pool_txs_by_ergo_tree_handler),
                )
                .route(
                    "/transactions/unconfirmed/byBoxId",
                    post(crate::compat::handlers::pool_txs_by_box_id_handler),
                )
                .route(
                    "/transactions/unconfirmed/byTokenId",
                    post(crate::compat::handlers::pool_txs_by_token_id_handler),
                )
                .route(
                    "/transactions/unconfirmed/byRegisters",
                    post(crate::compat::handlers::pool_txs_by_registers_handler),
                )
                .route(
                    "/transactions/poolHistogram",
                    get(crate::compat::handlers::pool_fee_histogram_handler),
                )
                .route(
                    "/transactions/getFee",
                    get(crate::compat::handlers::pool_recommended_fee_handler),
                )
                .route(
                    "/transactions/waitTime",
                    get(crate::compat::handlers::pool_wait_time_handler),
                )
                .with_state(c);
            let with_compat = operator.merge(scala).merge(miner_stats_routes);
            // Scala-compat write surface. The hex-body and JSON-body
            // variants share `NodeSubmit` state but dispatch through
            // different bridge methods (`submit_transaction` vs
            // `submit_transaction_json`).
            if let Some(s) = submit {
                let scala_writes: Router = Router::new()
                    .route(
                        "/transactions/bytes",
                        post(crate::compat::transactions::submit_bytes_handler),
                    )
                    .route(
                        "/transactions/checkBytes",
                        post(crate::compat::transactions::check_bytes_handler),
                    )
                    .route(
                        "/transactions",
                        post(crate::compat::transactions::submit_handler),
                    )
                    .route(
                        "/transactions/check",
                        post(crate::compat::transactions::check_handler),
                    )
                    // `sendMinedBlock`. axum 0.7 dispatches GET and
                    // POST on the same path independently, so the
                    // existing read-side `GET /blocks` (header pagination,
                    // line 603) and this POST live side-by-side without
                    // ordering concerns.
                    .route("/blocks", post(crate::compat::blocks::submit_handler))
                    .with_state(s);
                with_compat.merge(scala_writes)
            } else {
                with_compat
            }
        }
        None => operator,
    };

    // `/wallet/ui*` — retired: the wallet is now a section of the dashboard SPA
    // (`/#wallet`). These public paths 308-redirect there for bookmarks. Merged
    // BEFORE the gated `/wallet/*` router below so the static `/wallet/ui` routes
    // win over its `/wallet/*rest` catch-all (which would otherwise 403 them).
    let assembled = assembled.merge(wallet_ui_router());

    // `/wallet/*` — unconditionally mounted.
    // The wallet admin is always wired (never Optional); read-only
    // mirrors supply a `NoopWalletAdmin` so the routes return the
    // zero-state status rather than 404.
    let assembled = assembled.merge(crate::wallet::router_with_security(
        wallet_admin.clone(),
        security.clone(),
    ));
    // The v1 T1 (operator) auth config — the same api-key gate the wallet
    // surface uses, reused for the `webhooks/*` management routes below.
    // Captured before `security` is consumed by the native wallet mount.
    let v1_auth = crate::v1::auth::V1AuthConfig::new(security.clone()).into_shared();
    // Captured before the native mount consumes `wallet_admin`: the v1
    // scan/accounts group (`/api/v1/scan/*` + `/api/v1/accounts/*`)
    // reuses the SAME wallet-admin bridge for scan + key operations.
    let v1_accounts_admin = wallet_admin.clone();
    // Native `/api/v1/wallet/*` — a second adapter over the SAME wallet admin,
    // gated by the same operator api-key (route_layer + catch-alls). Factual
    // DTOs + EIP-27-aware balance; the Scala-compat router above is untouched.
    let assembled = assembled.merge(crate::wallet::native::router_with_security(
        wallet_admin,
        security,
    ));

    // Native `/api/v1/*` product API — the `chain/*` + `transactions/*` reads
    // group, the first consumer of the shared v1 primitives (error envelope,
    // cursor page builder, rate/cost governor). All routes are T0 (public),
    // fronted by the per-IP governor at route-class `HeavyRead`. The shared
    // governor is one per node, so later route groups reuse the same per-IP
    // budget.
    // Shared mempool-depth ring. Fed by a background sampler
    // (production only — guarded on a live Tokio runtime so non-async test
    // router builds never spawn a task), read by `mempool/summary?history=` and
    // the future `stats/mempool-depth`.
    // Shared once per process for the same reason as the realtime bus /
    // webhook engine below: the `_once` sampler feeds the FIRST ring only.
    static V1_MEMPOOL_DEPTH: std::sync::OnceLock<
        std::sync::Arc<crate::v1::mempool_depth::MempoolDepthRing>,
    > = std::sync::OnceLock::new();
    let v1_mempool_depth = V1_MEMPOOL_DEPTH
        .get_or_init(|| std::sync::Arc::new(crate::v1::mempool_depth::MempoolDepthRing::new()))
        .clone();
    if tokio::runtime::Handle::try_current().is_ok() {
        // Guarded to spawn exactly one sampler per process even though router
        // assembly can run many times (the whole test suite builds routers).
        crate::v1::mempool_depth::spawn_depth_sampler_once(
            v1_read.clone(),
            v1_mempool_depth.clone(),
            crate::v1::mempool_depth::DEFAULT_SAMPLE_INTERVAL,
        );
    }
    // Real-time subscriptions. The `RealtimeBus` is constructed once and
    // shared like the mempool-depth ring above. It is fed by the coarse-ring bridge task
    // (production only — same live-runtime + once-per-process guards as the
    // depth sampler so non-async test router builds never spawn it and repeated
    // router assembly never stacks pollers). `realtime_handle()` uses
    // `RealtimeHandle::blocks_and_mempool()`, which marks `blocks`, `mempool`,
    // `peers`, and `tx` live; fine-grained address/box/token taps remain a
    // follow-up.
    // Process singletons: the `*_once` workers below bind the FIRST bus/engine
    // they see, so every router assembly must share those exact instances — a
    // per-assembly bus/engine would leave later routers holding handles no
    // worker feeds (registrations that never deliver, subscriptions that never
    // fire).
    static V1_WEBHOOKS_ENGINE: std::sync::OnceLock<std::sync::Arc<crate::v1::WebhookEngine>> =
        std::sync::OnceLock::new();
    let v1_realtime = realtime_handle();
    if tokio::runtime::Handle::try_current().is_ok() {
        crate::v1::spawn_event_bridge_once(
            v1_read.clone(),
            v1_realtime.bus.clone(),
            crate::v1::realtime::DEFAULT_BRIDGE_INTERVAL,
        );
    }
    // Webhooks — the durable, retried, signed sibling of WS. An internal
    // subscriber to the SAME `RealtimeBus` (one event source, one global seq).
    // The registry + delivery-log + retry/backoff/HMAC state machine, and the
    // production `ReqwestSink` (rustls-TLS only — no system OpenSSL, see
    // `ergo-api/Cargo.toml`), are constructed here; the delivery worker is
    // spawned exactly once per process (guarded to a live Tokio runtime, same
    // idiom as the mempool-depth sampler / realtime-bridge feeder above), so
    // registered webhooks now actually deliver. Persistence is the one
    // remaining deferral: the registry + delivery log are in-memory, so
    // registrations are lost on restart until a durable `*-db` store lands
    // (documented in the webhooks module docs).
    let v1_webhooks_engine = V1_WEBHOOKS_ENGINE
        .get_or_init(|| std::sync::Arc::new(crate::v1::WebhookEngine::new(Default::default())))
        .clone();
    let mut v1_webhooks_handle = Some(crate::v1::WebhooksHandle {
        engine: v1_webhooks_engine.clone(),
        bus: v1_realtime.bus.clone(),
        url_policy: crate::v1::webhooks::model::UrlPolicy::default(),
    });
    if tokio::runtime::Handle::try_current().is_ok() {
        match crate::v1::ReqwestSink::new() {
            Ok(sink) => crate::v1::spawn_webhook_worker_once(
                v1_realtime.bus.clone(),
                v1_webhooks_engine,
                std::sync::Arc::new(sink),
                crate::v1::webhooks::worker::DEFAULT_WORKER_TICK,
            ),
            Err(error) => {
                // Webhooks are auxiliary — a sink build failure must not take
                // the node down. Without a sink, registrations would accept
                // but never deliver, so answer `webhooks_disabled` instead.
                tracing::error!(%error, "webhook HTTP sink failed to build; webhooks disabled");
                v1_webhooks_handle = None;
            }
        }
    }
    let v1_webhooks_state = crate::v1::WebhooksState {
        handle: v1_webhooks_handle,
        network,
    };
    let v1_state = crate::v1::V1State {
        read: v1_read,
        chain: v1_chain,
        indexer: v1_indexer,
        submit: v1_submit,
        // Keyless build stays honest-unavailable (route_unavailable) until the
        // extracted keyless TxBuilder core is wired in ergo-node.
        tx_builder: None,
        mempool: v1_mempool,
        mempool_depth: v1_mempool_depth,
        emission: v1_emission,
        realtime: Some(v1_realtime),
        network,
    };
    let v1_governor = crate::v1::governor::Governor::new(Default::default())
        .expect("default GovernorConfig is valid");
    // The `script/*` playground shares the one per-node governor (bounded
    // at the `Compute` class — the load-bearing anti-DoS control) and the
    // one v1 auth config (so `[api.script] require_api_key` can flip the group
    // to T1). Clone both before they move into the reads router / webhooks
    // router below. The Scala oracle for `script/diff` is unconfigured here, so
    // `diff` answers `oracle_unavailable` until a transport is wired.
    let script_state = crate::v1::script::ScriptState {
        read: v1_script_read,
        chain: v1_script_chain,
        network,
        oracle: None,
        config: crate::v1::script::ScriptConfig::default(),
    };
    let assembled = assembled.merge(crate::v1::script::script_router(
        script_state,
        v1_governor.clone(),
        v1_auth.clone(),
    ));
    let assembled = assembled.merge(crate::v1::v1_router(v1_state.clone(), v1_governor.clone()));
    // Operator/control group (`node/*`, `network/*`, `mining/*`, `voting/*`).
    // Mixed tiers over one `OperatorState`: T0 reads share the same
    // per-node governor (`CheapRead`); T1/T2 controls ride the v1 api-key gate
    // (`require_tier`), T2 (config-mutate) additionally loopback-preferred.
    // `node/shutdown` is NOT on this router's T2 gate — it stays on the frozen
    // compat admin mount (see the T2 note in `operator_router`).
    let v1_operator_state = crate::v1::OperatorState {
        read: v1_op_read,
        chain: v1_op_chain,
        admin: v1_op_admin,
        mining: v1_op_mining,
        network,
    };
    let assembled = assembled.merge(crate::v1::operator_router(
        v1_operator_state,
        v1_governor.clone(),
        v1_auth.clone(),
    ));
    // Scan registry + account-abstraction group (`/api/v1/scan/*`,
    // `/api/v1/accounts/*`). T0 watch reads (governor), T1 scan +
    // watch writes + account/PSBT seams (`require_tier(Operator)`), T2 private-key
    // export (`require_tier(Admin)` — api-key + loopback-preferred).
    let v1_accounts_state = crate::v1::AccountsState {
        admin: v1_accounts_admin,
        network,
    };
    let assembled = assembled.merge(crate::v1::accounts_router(
        v1_accounts_state,
        v1_governor.clone(),
        v1_auth.clone(),
    ));
    // `POST /api/v1/batch` — a bounded read-only multiplexer over
    // the SAME `chain/*`/`boxes/*`/`tokens/*`/`addresses/*`/`mempool/*`/
    // `transactions/*`(reads)/`stats/*`/`diagnostics`/`light/*`/`protocols/*`
    // handlers just mounted above, dispatched in-process (never HTTP-to-
    // itself) through a second, restricted router built from the same
    // `V1State` + the same shared per-node governor.
    let assembled = assembled.merge(crate::v1::batch_router(v1_state, v1_governor));
    // Mount the T1 `webhooks/*` router under the operator api-key gate.
    let assembled = assembled.merge(crate::v1::webhooks_router(v1_webhooks_state, v1_auth));

    // tower-http TraceLayer wraps every request in an INFO span carrying a
    // monotonic request id + method + path. Handler logs ride that span as
    // children, so a 5xx (e.g. the wallet boundary error log) is
    // correlatable end-to-end to the exact request — even when concurrent
    // requests interleave in the log. INFO (not the default DEBUG) so the
    // span is live under the default filter and its fields attach to the
    // error/warn events a failing request emits; the per-request
    // started/finished events stay at their DEBUG default, so a healthy
    // request still produces no INFO line of its own.
    //
    // Path only, never the full URI: query strings can carry caller
    // parameters we don't want promoted into higher-signal logs, and the
    // path alone identifies the endpoint for correlation. Sensitive
    // per-request detail belongs in sanitized handler-level logs.
    assembled.layer(from_fn(spa_security_headers)).layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request| {
                static HTTP_REQ_SEQ: AtomicU64 = AtomicU64::new(0);
                let req_id = HTTP_REQ_SEQ.fetch_add(1, Ordering::Relaxed);
                tracing::info_span!(
                    "http",
                    req_id,
                    method = %request.method(),
                    path = %request.uri().path(),
                )
            })
            // 503 is this API's expected-unavailability reply (e.g. the
            // tip-change gap on /mining/candidate, polled at 2 Hz by miners)
            // — operational, not a fault. Everything else keeps the
            // tower-http default ERROR. The closure cannot see the request
            // path (tower-http classify gives only the failure class), so
            // the demotion is status-scoped; the entered request span still
            // attaches req_id/method/path to the event either way.
            .on_failure(
                |class: ServerErrorsFailureClass,
                 latency: std::time::Duration,
                 _span: &tracing::Span| {
                    let latency_ms = latency.as_millis() as u64;
                    // `classification` renders identically on both levels so
                    // the field has one shape for log consumers.
                    match &class {
                        ServerErrorsFailureClass::StatusCode(code)
                            if *code == StatusCode::SERVICE_UNAVAILABLE =>
                        {
                            tracing::debug!(classification = %class, latency_ms, "response failed");
                        }
                        _ => {
                            tracing::error!(classification = %class, latency_ms, "response failed");
                        }
                    }
                },
            ),
    )
}

/// Public redirect routes for the retired `/wallet/ui*` paths → the dashboard
/// SPA's wallet section (`/#wallet`). Kept as their own router merged before the
/// gated `/wallet/*` router so the static routes win over its `/wallet/*rest`
/// catch-all (otherwise these would 403 instead of redirecting).
fn wallet_ui_router() -> Router {
    Router::new()
        .route("/wallet/ui", get(wallet_ui_redirect))
        .route("/wallet/ui/index.html", get(wallet_ui_redirect))
        .route("/wallet/ui/wallet.js", get(wallet_ui_redirect))
}

async fn wallet_ui_redirect() -> Redirect {
    Redirect::permanent("/#wallet")
}

/// Strict response headers for the mnemonic-bearing SPA surfaces (applied by
/// `spa_security_headers`). `Cache-Control: no-store` is a bfcache mitigation,
/// not a hard guarantee — some browsers retain bfcache snapshots regardless.
/// The web fonts are self-hosted (see `web.rs`), so `default-src 'self'` does
/// not block them.
///
/// `cache_sensitive` gates the no-store trio: HTML/JS/CSS can carry secrets or
/// secret-adjacent logic, but the fonts are inert public binaries — for those
/// the handler's `immutable` caching must survive (352 KB of Inter refetched on
/// every reload is pure waste), while CSP/Referrer-Policy still apply.
fn apply_strict_static_headers(headers: &mut HeaderMap, cache_sensitive: bool) {
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'",
        ),
    );
    if cache_sensitive {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        );
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// The dashboard SPA at `/` now hosts the wallet section (it renders mnemonics
/// during init), so the SPA document and its static assets carry the same
/// strict headers as the legacy `/wallet/ui` bundle did. Scoped by path so the
/// `/swagger*` pages (which load Swagger-UI from a CDN), `/api/*` and `/metrics`
/// are unaffected.
async fn spa_security_headers(req: Request, next: Next) -> Response {
    let (is_spa, is_font) = {
        let p = req.uri().path();
        let is_font = p.starts_with("/fonts/");
        (
            p == "/"
                || p == "/index.html"
                || p.starts_with("/js/")
                || is_font
                || p.ends_with(".css"),
            is_font,
        )
    };
    let mut resp = next.run(req).await;
    if is_spa {
        apply_strict_static_headers(resp.headers_mut(), !is_font);
    }
    resp
}

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
    extract::{Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{from_fn, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, head, post},
    Json, Router,
};
use tokio::task::JoinHandle;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

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
use crate::traits::{
    MempoolView, NodeAdmin, NodeReadState, NodeSubmit, NoopMempoolView, VotingControlError,
};
use crate::types::{
    ApiBlockApplyError, ApiBootstrapStatus, ApiConfiguredVote, ApiDifficultyPoint,
    ApiDifficultySeries, ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiHistoryMode, ApiHost,
    ApiIdentity, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction, ApiMempoolTransactions,
    ApiMinerStat, ApiMinerStats, ApiNativeSubmitError, ApiParamChange, ApiPeer, ApiRecentBlock,
    ApiSetVotesRequest, ApiStatus, ApiSubmitError, ApiSubmitResponse, ApiSyncStatus, ApiTip,
    ApiTxSource, ApiVotableParam, ApiVoteChangeEvent, ApiVoteTarget, ApiVotes, ApiVotesHistory,
    ApiWeightFunction, HealthStatus, RawTransactionBytes, SubmitError, SubmitMode, SyncStateLabel,
};
use crate::web::{
    COMPONENTS_CSS, DASHBOARD_CSS, INDEX_HTML, INTER_VARIABLE_WOFF2, JETBRAINS_MONO_WOFF2,
    JS_API_CLIENT, JS_APP, JS_AUTH, JS_CHART, JS_EXPLORER, JS_FEE_STATS, JS_FORMAT, JS_MEMPOOL,
    JS_MINERS, JS_MINING, JS_OVERVIEW, JS_PEERS, JS_ROUTER, JS_SETTINGS, JS_SPARKLINE, JS_TABLE,
    JS_VOTING, JS_WALLET, NATIVE_SWAGGER_HTML, OPENAPI_YAML, SWAGGER_HTML, TOKENS_CSS,
};
use ergo_indexer_types::IndexerQuery;
use ergo_ser::address::{encode_p2pk_from_pubkey, NetworkPrefix};

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
    // v1 boot-warn (§2.1): loudly flag a network-reachable T1/T2 surface under
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
    // reason (`dev-docs/v1-api-design.md` §3.5–§3.6).
    let v1_read = read.clone();
    let v1_chain = compat.clone();
    let v1_indexer = indexer.clone();
    // Per-height emission schedule for the `stats/*` supply series (§3.14).
    let v1_emission = emission.clone();
    let v1_submit = submit.clone();
    let v1_mempool = mempool.clone();
    // Same up-front-clone rationale for the `script/*` group (§5): `compat` is
    // moved into the Scala-compat `match` further down, so the chain reader for
    // `simulate`/`explain` box lookups (and the tip-height reader) are captured
    // here before that move.
    let v1_script_read = read.clone();
    let v1_script_chain = compat.clone();
    // Operator/control group inputs (`node/*`, `network/*`, `mining/*`,
    // `voting/*` — `dev-docs/v1-api-design.md` §3.1–§3.4). Cloned up front
    // because `admin` / `mining` are moved into the Scala-compat mounts further
    // down; the group mounts unconditionally and gates inside each handler on
    // the honest `*_unavailable` reason.
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
        .route("/js/peers.js", get(|| async { js(JS_PEERS) }))
        .route("/js/mempool.js", get(|| async { js(JS_MEMPOOL) }))
        .route("/js/voting.js", get(|| async { js(JS_VOTING) }))
        .route("/js/wallet.js", get(|| async { js(JS_WALLET) }))
        .route("/js/miners.js", get(|| async { js(JS_MINERS) }))
        .route("/js/mining.js", get(|| async { js(JS_MINING) }))
        .route("/swagger", get(swagger))
        .route("/swagger/native", get(swagger_native))
        .route("/api-docs/openapi.yaml", get(openapi_yaml))
        .route("/api-docs/openapi-native.yaml", get(openapi_native_yaml))
        .route("/api-docs/openapi-native.json", get(openapi_native_json))
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
        // v1 product router (`crate::v1::v1_router`, §3.8) — reshaped into the
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

    // `POST /api/v1/mempool/{submit,check}` are Overlap-O1 aliases of the
    // canonical `transactions/{submit,check}` handlers, owned by the v1 product
    // router (`crate::v1::v1_router`, §3.8). They mount unconditionally there
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
                    // §12 sendMinedBlock. axum 0.7 dispatches GET and
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

    // `/wallet/*` — unconditionally mounted per spec §8.1.
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
    // Native `/api/v1/wallet/*` — a second adapter over the SAME wallet admin,
    // gated by the same operator api-key (route_layer + catch-alls). Factual
    // DTOs + EIP-27-aware balance; the Scala-compat router above is untouched.
    let assembled = assembled.merge(crate::wallet::native::router_with_security(
        wallet_admin,
        security,
    ));

    // Native `/api/v1/*` product API — the `chain/*` + `transactions/*` reads
    // group, the first consumer of the G2 shared primitives (error envelope,
    // cursor page builder, rate/cost governor). All routes are T0 (public),
    // fronted by the per-IP governor at route-class `HeavyRead`. The shared
    // governor is one per node, so later route groups reuse the same per-IP
    // budget (`dev-docs/v1-api-design.md` §2.2).
    // O4 shared mempool-depth ring (Appendix A O4). Fed by a background sampler
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
    // Real-time subscriptions (§4.1). The `RealtimeBus` is constructed once and
    // shared like the O4 depth ring. It is fed by the coarse-ring bridge task
    // (production only — same live-runtime + once-per-process guards as the
    // depth sampler so non-async test router builds never spawn it and repeated
    // router assembly never stacks pollers). Phase-1 feeds only the `blocks`
    // channel; the fine-grained taps are a node-internals follow-up.
    // Process singletons: the `*_once` workers below bind the FIRST bus/engine
    // they see, so every router assembly must share those exact instances — a
    // per-assembly bus/engine would leave later routers holding handles no
    // worker feeds (registrations that never deliver, subscriptions that never
    // fire).
    static V1_REALTIME: std::sync::OnceLock<crate::v1::RealtimeHandle> = std::sync::OnceLock::new();
    static V1_WEBHOOKS_ENGINE: std::sync::OnceLock<std::sync::Arc<crate::v1::WebhookEngine>> =
        std::sync::OnceLock::new();
    let v1_realtime = V1_REALTIME
        .get_or_init(crate::v1::RealtimeHandle::blocks_only)
        .clone();
    if tokio::runtime::Handle::try_current().is_ok() {
        crate::v1::spawn_event_bridge_once(
            v1_read.clone(),
            v1_realtime.bus.clone(),
            crate::v1::realtime::DEFAULT_BRIDGE_INTERVAL,
        );
    }
    // Webhooks (§4.1) — the durable, retried, signed sibling of WS. An internal
    // subscriber to the SAME `RealtimeBus` (one event source, one global seq).
    // The registry + delivery-log + retry/backoff/HMAC state machine, and the
    // production `ReqwestSink` (rustls-TLS only — no system OpenSSL, see
    // `ergo-api/Cargo.toml`), are constructed here; the delivery worker is
    // spawned exactly once per process (guarded to a live Tokio runtime, same
    // idiom as the O4 depth sampler / realtime-bridge feeder above), so
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
        // extracted keyless TxBuilder core (§4.2 O7) is wired in ergo-node.
        tx_builder: None,
        mempool: v1_mempool,
        mempool_depth: v1_mempool_depth,
        emission: v1_emission,
        realtime: Some(v1_realtime),
        network,
    };
    let v1_governor = crate::v1::governor::Governor::new(Default::default())
        .expect("default GovernorConfig is valid");
    // The `script/*` playground (§5) shares the one per-node governor (bounded
    // at the `Compute` class — the load-bearing anti-DoS control, D2) and the
    // one v1 auth config (so `[api.script] require_api_key` can flip the group
    // to T1). Clone both before they move into the reads router / webhooks
    // router below. The Scala oracle for `script/diff` is unconfigured here, so
    // `diff` answers `oracle_unavailable` until a transport is wired (D3).
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
    // Operator/control group (`node/*`, `network/*`, `mining/*`, `voting/*` —
    // §3.1–§3.4). Mixed tiers over one `OperatorState`: T0 reads share the same
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
    // `POST /api/v1/batch` (§3.18/§4.7) — a bounded read-only multiplexer over
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

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn swagger() -> Html<&'static str> {
    Html(SWAGGER_HTML)
}

async fn swagger_native() -> Html<&'static str> {
    Html(NATIVE_SWAGGER_HTML)
}

async fn openapi_yaml() -> Response {
    ([(header::CONTENT_TYPE, "application/yaml")], OPENAPI_YAML).into_response()
}

/// Rust-native `/api/v1/*` OpenAPI spec as YAML, generated from the
/// [`NativeOpenApi`] derive. A separate surface from the Scala-parity
/// [`openapi_yaml`] above; both mounts coexist.
async fn openapi_native_yaml() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/yaml")],
        native_openapi_yaml(),
    )
        .into_response()
}

/// Rust-native `/api/v1/*` OpenAPI spec as JSON.
async fn openapi_native_json() -> Response {
    (StatusCode::OK, Json(NativeOpenApi::openapi())).into_response()
}

async fn jetbrains_mono_woff2() -> Response {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        JETBRAINS_MONO_WOFF2,
    )
        .into_response()
}

async fn inter_variable_woff2() -> Response {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        INTER_VARIABLE_WOFF2,
    )
        .into_response()
}

/// Serve a static JS module with the JavaScript content-type.
fn js(body: &'static str) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

async fn tokens_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        TOKENS_CSS,
    )
        .into_response()
}

async fn components_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        COMPONENTS_CSS,
    )
        .into_response()
}

async fn dashboard_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        DASHBOARD_CSS,
    )
        .into_response()
}

/// OpenAPI aggregator for the Rust-native `/api/v1/*` surface.
///
/// Defined here in `server.rs` so the derive can name the private handler
/// functions directly without widening their visibility. The Scala-parity
/// `openapi.yaml` and its `/swagger` mount are a separate surface,
/// untouched by this type.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ergo Rust Node — Native API",
        description = "Rust-native operator API for the Ergo node (`/api/v1/*`). \
This document describes the production-superset route set: the conditional routes \
(`/api/v1/node/shutdown`, \
`/api/v1/difficulty/history`, `/api/v1/mining/minerStats`, `/api/v1/votes/history`) are mounted only when the node is wired with the matching \
admin / chain-reader handles, so a given process may serve fewer routes than \
appear here. The `mempool/*` product routes are documented in the v1 product \
router. Query `GET /api/v1/health` to confirm a running node's state."
    ),
    paths(
        info_handler,
        difficulty_history_handler,
        miner_stats_handler,
        votes_history_handler,
        crate::blockchain::indexer_status_handler,
        identity_handler,
        host_handler,
        status_handler,
        votes_handler,
        set_votes_handler,
        tip_handler,
        recent_blocks_handler,
        events_handler,
        sync_handler,
        peers_handler,
        health_handler,
        shutdown_handler,
        crate::wallet::native::balance,
        crate::wallet::native::status,
        crate::wallet::native::addresses,
        crate::wallet::native::boxes,
        crate::wallet::native::box_by_id,
        crate::wallet::native::transactions,
        crate::wallet::native::transaction_by_id,
        crate::wallet::native::init,
        crate::wallet::native::restore,
        crate::wallet::native::unlock,
        crate::wallet::native::lock,
        crate::wallet::native::mnemonic_verify,
        crate::wallet::native::derive_address,
        crate::wallet::native::change_address_get,
        crate::wallet::native::change_address_put,
        crate::wallet::native::rescan,
        crate::wallet::native::select_boxes,
        crate::wallet::native::build_transaction,
        crate::wallet::native::sign_transaction,
        crate::wallet::native::send_transaction,
        crate::wallet::native::retrieve_rewards,
    ),
    components(schemas(
        ApiInfo,
        ApiIdentity,
        ApiHost,
        ApiStatus,
        ApiVotes,
        ApiVotableParam,
        ApiConfiguredVote,
        ApiSetVotesRequest,
        ApiVoteTarget,
        ApiVotesHistory,
        ApiVoteChangeEvent,
        ApiParamChange,
        ApiTip,
        ApiRecentBlock,
        ApiSyncStatus,
        ApiPeer,
        ApiMempoolSummary,
        ApiMempoolTransactions,
        ApiMempoolTransaction,
        ApiHealth,
        ApiSubmitResponse,
        ApiSubmitError,
        ApiNativeSubmitError,
        RawTransactionBytes,
        ApiHistoryMode,
        ApiBootstrapStatus,
        ApiBlockApplyError,
        ApiHeaderRef,
        ApiFullBlockRef,
        ApiDifficultyPoint,
        ApiDifficultySeries,
        ApiMinerStat,
        ApiMinerStats,
        crate::types::ApiNodeEvent,
        crate::types::ApiNodeEvents,
        crate::types::ApiIndexerStatus,
        crate::types::ApiIndexerRepair,
        crate::types::ApiIndexerTotals,
        ApiWeightFunction,
        ApiTxSource,
        SyncStateLabel,
        HealthStatus,
        crate::wallet::native::dto::WalletBalanceDto,
        crate::wallet::native::dto::NanoErgBreakdownDto,
        crate::wallet::native::dto::ReemissionInfoDto,
        crate::wallet::native::dto::UnconfirmedDeltaDto,
        crate::wallet::native::dto::ScopeDto,
        crate::wallet::native::dto::WalletAssetDto,
        crate::wallet::native::dto::WalletStatusDto,
        crate::wallet::native::dto::NetworkDto,
        crate::wallet::native::dto::RescanStateDto,
        crate::wallet::native::dto::WalletAddressDto,
        crate::wallet::native::dto::AddressPage,
        crate::wallet::native::dto::WalletBoxSummary,
        crate::wallet::native::dto::BoxStatusDto,
        crate::wallet::native::dto::BoxProvenanceDto,
        crate::wallet::native::dto::BoxPage,
        crate::wallet::native::dto::WalletTransactionSummary,
        crate::wallet::native::dto::TxPage,
        crate::wallet::native::dto::UnlockRequest,
        crate::wallet::native::dto::MnemonicVerifyRequest,
        crate::wallet::native::dto::MnemonicVerifyResult,
        crate::wallet::native::dto::InitRequest,
        crate::wallet::native::dto::InitResponse,
        crate::wallet::native::dto::RestoreRequest,
        crate::wallet::native::dto::DerivationMode,
        crate::wallet::native::dto::DeriveKeyRequest,
        crate::wallet::native::dto::DerivedAddress,
        crate::wallet::native::dto::ChangeAddressDto,
        crate::wallet::native::dto::SetChangeAddressRequest,
        crate::wallet::native::dto::RescanRequest,
        crate::wallet::native::dto::TxRepr,
        crate::wallet::native::dto::OutputIntent,
        crate::wallet::native::dto::InputSource,
        crate::wallet::native::dto::DataInputSource,
        crate::wallet::native::dto::TxIntent,
        crate::wallet::native::dto::SelectTarget,
        crate::wallet::native::dto::BoxSelectRequest,
        crate::wallet::native::dto::SelectedBoxRef,
        crate::wallet::native::dto::ChangePlan,
        crate::wallet::native::dto::ReemissionBurn,
        crate::wallet::native::dto::BoxSelectResponse,
        crate::wallet::native::dto::BuildTxResponse,
        crate::wallet::native::dto::ExternalSecret,
        crate::wallet::native::dto::SignTxRequest,
        crate::wallet::native::dto::SignTxResponse,
        crate::wallet::native::dto::SendTxRequest,
        crate::wallet::native::dto::SendTxResponse,
        crate::wallet::native::dto::RetrieveRewardsRequest,
        crate::wallet::native::dto::RetrieveRewardsResultDto,
        crate::wallet::native::dto::SweptTokenDto,
        crate::wallet::native::error::NativeWalletError,
    )),
    tags(
        (name = "node", description = "Node identity, host, status"),
        (name = "chain", description = "Tip, sync progress"),
        (name = "peers", description = "Peer manager view"),
        (name = "mempool", description = "Mempool overlay + submission"),
        (name = "admin", description = "API-key-gated operator routes"),
        (name = "health", description = "Liveness + readiness"),
        (name = "wallet", description = "Native api-key-gated wallet surface"),
    ),
    modifiers(&SecurityAddon),
)]
pub(crate) struct NativeOpenApi;

/// Registers the `ApiKeyAuth` security scheme on the native spec so Swagger UI
/// renders an Authorize control (and a per-operation padlock) for the
/// api-key-gated routes. The scheme matches the runtime gate exactly: the secret
/// rides the `api_key` request header ([`crate::auth::API_KEY_HEADER`]), which is
/// what [`crate::auth::require_api_key`] checks. Individual gated operations opt
/// in via `security(("ApiKeyAuth" = []))` on their `#[utoipa::path]`.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::new);
        components.add_security_scheme(
            "ApiKeyAuth",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new(
                crate::auth::API_KEY_HEADER,
            ))),
        );
    }
}

/// Serialise the native OpenAPI document to YAML.
///
/// Serialisation is deterministic in-memory work; a failure would be a
/// bug rather than a runtime condition, so this panics instead of serving
/// an empty spec.
pub fn native_openapi_yaml() -> String {
    NativeOpenApi::openapi()
        .to_yaml()
        .expect("openapi yaml serialize")
}

#[utoipa::path(
    get,
    path = "/api/v1/difficulty/history",
    tag = "chain",
    params(
        ("blocks" = Option<u32>, Query,
         description = "Most-recent blocks to return, ascending by height. \
Defaults to 720 (~one day at 120s blocks); clamped to [2, 16384]."),
    ),
    responses(
        (status = 200,
         description = "Per-block network difficulty across the recent chain, \
oldest first. Conditional: mounted only when the node is wired with a chain \
reader (the same handle the Scala-compat routes use).",
         body = ApiDifficultySeries, content_type = "application/json"),
    ),
)]
async fn difficulty_history_handler(
    State(chain): State<Arc<dyn NodeChainQuery>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let blocks = params
        .get("blocks")
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(720)
        .clamp(2, 16_384);
    let points = chain
        .last_headers(blocks)
        .into_iter()
        .map(|h| ApiDifficultyPoint {
            height: h.height,
            timestamp_unix_ms: h.timestamp,
            difficulty: h.difficulty,
        })
        .collect();
    Json(ApiDifficultySeries { points }).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/mining/minerStats",
    tag = "chain",
    params(
        ("window" = Option<u32>, Query,
         description = "Most-recent headers to fold, by miner pk. \
Defaults to 720 (~one day at 120s blocks); clamped to [1, 16384]."),
    ),
    responses(
        (status = 200,
         description = "Blocks-per-miner over the recent chain, sorted by \
count descending, each with the P2PK address derived from the miner pk. \
Conditional: mounted only when the node is wired with a chain reader.",
         body = ApiMinerStats, content_type = "application/json"),
    ),
)]
async fn miner_stats_handler(
    State((chain, network)): State<(Arc<dyn NodeChainQuery>, NetworkPrefix)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let window = params
        .get("window")
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(720)
        .clamp(1, 16_384);
    let headers = chain.last_headers(window);
    let blocks = headers.len() as u32;
    let tip_height = headers.last().map(|h| h.height).unwrap_or(0);
    // Fold by pk hex: (count, last_height). Headers arrive ascending, so
    // a plain max keeps the latest height per miner.
    let mut agg: std::collections::HashMap<String, (u32, u32)> = std::collections::HashMap::new();
    for h in &headers {
        let e = agg.entry(h.pow_solutions.pk.clone()).or_insert((0, 0));
        e.0 += 1;
        if h.height > e.1 {
            e.1 = h.height;
        }
    }
    let mut miners: Vec<ApiMinerStat> = agg
        .into_iter()
        .map(|(pk, (count, last_height))| {
            let address = hex::decode(&pk)
                .ok()
                .and_then(|b| encode_p2pk_from_pubkey(network, &b).ok());
            ApiMinerStat {
                pk,
                address,
                count,
                last_height,
            }
        })
        .collect();
    miners.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(b.last_height.cmp(&a.last_height))
    });
    Json(ApiMinerStats {
        tip_height,
        window,
        blocks,
        miners,
    })
    .into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/votes/history",
    tag = "node",
    responses(
        (status = 200,
         description = "Protocol-parameter change timeline (epoch boundaries where a \
parameter changed, oldest first). Conditional: mounted only when the node is wired with \
a chain reader (the same handle the Scala-compat routes use).",
         body = ApiVotesHistory, content_type = "application/json"),
    ),
)]
async fn votes_history_handler(State(chain): State<Arc<dyn NodeChainQuery>>) -> Response {
    Json(chain.votes_history()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/blocks/recent",
    tag = "chain",
    description = "Most-recent full blocks for the dashboard, newest first. \
Reflects the *committed* full-block chain: it reads durably-stored section \
bytes, whereas `/api/v1/tip` reads the in-memory tip. During the async-persist \
window this list may therefore trail `/tip` by a block or two — it never \
advertises a block whose sections are not yet committed. Self-heals as the \
sections commit.",
    params(
        ("n" = Option<u32>, Query, minimum = 1, maximum = 32,
         description = "Number of most-recent full blocks, newest first. \
Defaults to 10. Out-of-range values are clamped to [1, 32] (the \
snapshot-precomputed tail), not rejected."),
    ),
    responses(
        (status = 200, description = "Most-recent full blocks, newest first",
         body = Vec<ApiRecentBlock>, content_type = "application/json"),
    ),
)]
async fn recent_blocks_handler(
    State(read): State<Arc<dyn NodeReadState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Parse as `i64` so an out-of-range numeric value (e.g. `?n=-1` or
    // `?n=999`) clamps to the [1, 32] bound rather than silently falling
    // back to the default — only a non-numeric value uses the default.
    let n = params
        .get("n")
        .and_then(|raw| raw.parse::<i64>().ok())
        .map(|v| v.clamp(1, 32) as u32)
        .unwrap_or(10);
    Json(read.recent_blocks(n)).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/events",
    tag = "node",
    description = "Operator event feed, oldest-first: block applies, reorgs, peer \
connects/disconnects, extra-index status transitions. Backed by a bounded node-side \
ring (512 events) whose FULL retained tail is projected into the lock-free snapshot, \
so this read never touches live node state and a cold poll returns up to 512 events. \
`seq` is monotonic; a gap between polls means the ring evicted entries in between — \
eviction is the ONLY gap source. Reorg detection is approximate: derived from the \
committed recent-block tail (a replaced block within the last 32 heights), so a reorg \
deeper than that tail surfaces as plain `blockApplied` events only.",
    params(
        ("since" = Option<u64>, Query,
         description = "Return only events with `seq` strictly greater than this. \
Poll with the previous response's `latestSeq` to receive only what is new. \
Omitted or non-numeric = the full retained tail."),
    ),
    responses(
        (status = 200, description = "Retained event tail (filtered by `since`), oldest first",
         body = crate::types::ApiNodeEvents, content_type = "application/json"),
    ),
)]
async fn events_handler(
    State(read): State<Arc<dyn NodeReadState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let since = params
        .get("since")
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(0);
    let mut feed = read.events();
    if since > 0 {
        feed.events.retain(|e| e.seq > since);
    }
    Json(feed).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/info",
    tag = "node",
    responses(
        (status = 200, description = "Static node identity snapshot",
         body = ApiInfo, content_type = "application/json"),
    ),
)]
async fn info_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.info()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/identity",
    tag = "node",
    responses(
        (status = 200, description = "Node mode and protocol-visible flags",
         body = ApiIdentity, content_type = "application/json"),
    ),
)]
async fn identity_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.identity()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/host",
    tag = "node",
    responses(
        (status = 200, description = "Host-process metrics (memory, disk, CPU, network)",
         body = ApiHost, content_type = "application/json"),
    ),
)]
async fn host_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.host()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/votes",
    tag = "node",
    responses(
        (status = 200, description = "Votable protocol parameters + bounds and the operator's configured votes",
         body = ApiVotes, content_type = "application/json"),
    ),
)]
async fn votes_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.votes()).into_response()
}

#[utoipa::path(
    post,
    path = "/api/v1/votes",
    tag = "admin",
    request_body = ApiSetVotesRequest,
    security(("ApiKeyAuth" = [])),
    responses(
        (status = 204, description = "Voting targets replaced"),
        (status = 400, description = "A target named a non-votable parameter, or fell \
outside the parameter's allowable [min, max] voting range"),
        (status = 403, description = "Missing or invalid api_key"),
        (status = 409, description = "Node is not mining"),
    ),
)]
async fn set_votes_handler(
    State(admin): State<Arc<dyn NodeAdmin>>,
    body: axum::body::Bytes,
) -> Response {
    let req: crate::types::ApiSetVotesRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return crate::utils::bad_request(format!("invalid request body: {e}")),
    };
    let targets: Vec<(u8, i64)> = req
        .votes
        .iter()
        .map(|v| (v.parameter_id, v.target))
        .collect();
    match admin.set_voting_targets(targets) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(VotingControlError::NotVotable { parameter_id }) => crate::utils::bad_request(format!(
            "parameter id {parameter_id} is not operator-votable (votable ids: 1..=8, 9)"
        )),
        Err(VotingControlError::OutOfRange {
            parameter_id,
            target,
            min,
            max,
        }) => crate::utils::bad_request(format!(
            "target {target} for parameter id {parameter_id} is outside its allowable \
             voting range [{min}, {max}]"
        )),
        Err(VotingControlError::MiningDisabled) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": 409,
                "reason": "mining.disabled",
                "detail": "voting targets can only be set on a mining node",
            })),
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/status",
    tag = "node",
    responses(
        (status = 200, description = "Collapsed sync + tip + peer-count dashboard view",
         body = ApiStatus, content_type = "application/json"),
    ),
)]
async fn status_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.status()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/tip",
    tag = "chain",
    responses(
        (status = 200, description = "Best-header and best-full-block tip pointers",
         body = ApiTip, content_type = "application/json"),
    ),
)]
async fn tip_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.tip()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/sync",
    tag = "chain",
    responses(
        (status = 200, description = "Sync-pipeline state",
         body = ApiSyncStatus, content_type = "application/json"),
    ),
)]
async fn sync_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.sync()).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/peers",
    tag = "peers",
    responses(
        (status = 200, description = "Connected and known peer view",
         body = Vec<ApiPeer>, content_type = "application/json"),
    ),
)]
async fn peers_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    Json(read.peers()).into_response()
}

/// Prometheus-text exposition derived from the same `NodeReadState`
/// DTOs the operator API already serves. No new node state — every
/// metric is a projection of `status()` + `mempool_summary()` +
/// `info()`. Always at `/metrics` on the operator API; bind the
/// API to loopback (or behind a reverse proxy with auth) before
/// scraping over a network.
async fn metrics_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    let info = read.info();
    let status = read.status();
    let mempool = read.mempool_summary();

    let body = format!(
        "\
# HELP ergo_node_uptime_seconds Seconds since node start.
# TYPE ergo_node_uptime_seconds gauge
ergo_node_uptime_seconds {uptime}
# HELP ergo_node_best_header_height Best header chain height.
# TYPE ergo_node_best_header_height gauge
ergo_node_best_header_height {bh}
# HELP ergo_node_best_full_block_height Best full-block chain height.
# TYPE ergo_node_best_full_block_height gauge
ergo_node_best_full_block_height {bfb}
# HELP ergo_node_sync_gap Headers ahead of full blocks (catch-up gap).
# TYPE ergo_node_sync_gap gauge
ergo_node_sync_gap {gap}
# HELP ergo_node_peer_count Connected peers (handshaked).
# TYPE ergo_node_peer_count gauge
ergo_node_peer_count {peers}
# HELP ergo_node_mempool_size Pooled transactions.
# TYPE ergo_node_mempool_size gauge
ergo_node_mempool_size {pool_size}
# HELP ergo_node_mempool_bytes Pooled-transaction byte total.
# TYPE ergo_node_mempool_bytes gauge
ergo_node_mempool_bytes {pool_bytes}
# HELP ergo_node_mempool_capacity_count Configured pool capacity (count).
# TYPE ergo_node_mempool_capacity_count gauge
ergo_node_mempool_capacity_count {cap_count}
# HELP ergo_node_mempool_capacity_bytes Configured pool capacity (bytes).
# TYPE ergo_node_mempool_capacity_bytes gauge
ergo_node_mempool_capacity_bytes {cap_bytes}
# HELP ergo_node_mempool_revalidation_pending Demoted txs pending revalidation.
# TYPE ergo_node_mempool_revalidation_pending gauge
ergo_node_mempool_revalidation_pending {revalidating}
# HELP ergo_node_snapshot_age_ms Snapshot age — how stale the read view is.
# TYPE ergo_node_snapshot_age_ms gauge
ergo_node_snapshot_age_ms {snap_age}
# HELP ergo_node_block_apply_errors_total Block-apply rejections since node start.
# TYPE ergo_node_block_apply_errors_total counter
ergo_node_block_apply_errors_total {apply_errs}
# HELP ergo_node_mempool_tx_requested_total Unconfirmed-tx ids requested from peers since node start.
# TYPE ergo_node_mempool_tx_requested_total counter
ergo_node_mempool_tx_requested_total {tx_requested}
# HELP ergo_node_mempool_peer_tx_admitted_total Peer-sourced txs admitted to the mempool since node start.
# TYPE ergo_node_mempool_peer_tx_admitted_total counter
ergo_node_mempool_peer_tx_admitted_total {peer_tx_admitted}
# HELP ergo_node_mempool_peer_tx_rejected_total Peer-sourced txs rejected by admission since node start.
# TYPE ergo_node_mempool_peer_tx_rejected_total counter
ergo_node_mempool_peer_tx_rejected_total {peer_tx_rejected}
",
        uptime = info.uptime_seconds,
        bh = status.best_header_height,
        bfb = status.best_full_block_height,
        gap = status.headers_ahead_of_full_blocks,
        peers = status.peer_count,
        pool_size = mempool.size,
        pool_bytes = mempool.total_bytes,
        cap_count = mempool.capacity_count,
        cap_bytes = mempool.capacity_bytes,
        revalidating = mempool.revalidation_pending,
        snap_age = status.snapshot_age_ms,
        apply_errs = status.block_apply_errors_total,
        tx_requested = status.mempool_tx_requested_total,
        peer_tx_admitted = status.mempool_peer_tx_admitted_total,
        peer_tx_rejected = status.mempool_peer_tx_rejected_total,
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// Channel-hop wrapper that lifts a `SubmitError` into `(StatusCode,
/// ApiSubmitError)`. Shared between operator routes (JSON envelope on
/// success) and Scala-compat routes (plain-string body on success).
pub(crate) async fn submit_via_node(
    submit: Arc<dyn NodeSubmit>,
    bytes: Vec<u8>,
    mode: SubmitMode,
) -> Result<String, (StatusCode, ApiSubmitError)> {
    submit
        .submit_transaction(bytes, mode)
        .await
        .map_err(map_submit_error)
}

/// Status mapping for `SubmitError`:
/// - `overloaded` / `shutting_down` / `route_disabled` → 503
///   (channel-side or feature-disabled failures; client may retry
///   or check operator config)
/// - `timeout` → 504 (per-submission deadline elapsed)
/// - `internal_error` → 500 (local DB / storage failure during
///   admission — caller did nothing wrong; node-side issue)
/// - everything else from the admission pipeline → 400 (bad
///   submitter input: `deserialize`, `non_canonical`, `invalid_pow`,
///   `header_rejected`, etc.)
pub(crate) fn map_submit_error(err: SubmitError) -> (StatusCode, ApiSubmitError) {
    let SubmitError { reason, detail } = err;
    let status = match reason.as_str() {
        "overloaded" | "shutting_down" | "route_disabled" => StatusCode::SERVICE_UNAVAILABLE,
        "timeout" => StatusCode::GATEWAY_TIMEOUT,
        "internal_error" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        ApiSubmitError {
            error: status.as_u16(),
            reason,
            detail,
        },
    )
}

/// `POST /node/shutdown` (Scala-compat) and `POST /api/v1/node/shutdown`.
/// Fires the action loop's shutdown signal and returns 202 immediately.
/// The actual drain (UTXO commit, redb close) happens asynchronously in
/// the action loop's existing shutdown path. Operators that need to
/// confirm completion should poll `GET /api/v1/health` until the
/// connection refuses.
#[utoipa::path(
    post,
    path = "/api/v1/node/shutdown",
    tag = "admin",
    security(("ApiKeyAuth" = [])),
    responses(
        (status = 202,
         description = "Shutdown accepted; body is the literal text `shutdown_requested`. Drain proceeds asynchronously.",
         body = String, content_type = "text/plain"),
        (status = 403, description = "Missing or invalid api_key (when API security is configured)"),
    ),
)]
async fn shutdown_handler(State(admin): State<Arc<dyn NodeAdmin>>) -> (StatusCode, &'static str) {
    admin.request_shutdown();
    (StatusCode::ACCEPTED, "shutdown_requested")
}

/// `POST /peers/connect` — Scala `ErgoPeersApiRoute.connect`: the body is
/// a JSON string `"host:port"`; a parse failure is 400; success fires the
/// dial at the node and answers 200 (the JSON string `"OK"`, Scala's
/// `ApiResponse.OK`) without waiting for the dial's outcome. Hostnames
/// resolve asynchronously.
///
/// Deliberate divergences (all saner-direction, behind the api key):
/// Scala 500s on an unresolvable hostname (`InetAddress.getByName`
/// throws) and on regex-valid ports > 65535 — both are 400 here; Scala's
/// unanchored regex mis-truncates hyphenated hostnames and accepts
/// junk-wrapped input — rejected here; IPv6 literals work here, 400 in
/// Scala.
async fn peers_connect_handler(
    State(admin): State<Arc<dyn NodeAdmin>>,
    body: axum::body::Bytes,
) -> Response {
    let addr_str = match crate::utils::parse_json_string_body(&body) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    // Fast path: literal ip:port. Fallback: async DNS for hostnames.
    let addr = match addr_str.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => match tokio::net::lookup_host(addr_str.as_str()).await {
            Ok(mut iter) => match iter.next() {
                Some(a) => a,
                None => return crate::utils::bad_request("address resolved to nothing"),
            },
            Err(_) => return crate::utils::bad_request("invalid host:port"),
        },
    };
    admin.connect_to_peer(addr);
    (StatusCode::OK, Json(serde_json::json!("OK"))).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Node is healthy (synced and connected)",
         body = ApiHealth, content_type = "application/json"),
        (status = 503, description = "Node is stalled, disconnected, or rejecting blocks",
         body = ApiHealth, content_type = "application/json"),
    ),
)]
async fn health_handler(State(read): State<Arc<dyn NodeReadState>>) -> Response {
    let h = read.health();
    let status = match h.status {
        HealthStatus::Ok => StatusCode::OK,
        // `Rejecting` (an outstanding block-apply rejection) is a page-worthy
        // not-healthy condition, same 503 as Stalled/Disconnected.
        HealthStatus::Stalled | HealthStatus::Disconnected | HealthStatus::Rejecting => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    let body = serde_json::to_vec(&h).unwrap_or_else(|_| b"{}".to_vec());
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    /// The native spec serialises to a non-empty OpenAPI 3.1 document.
    /// Pins utoipa's default emission version and exercises the
    /// panic-on-error branch of [`native_openapi_yaml`].
    #[test]
    fn native_openapi_yaml_emits_openapi_3_1_document() {
        let yaml = native_openapi_yaml();
        assert!(
            yaml.starts_with("openapi: 3.1."),
            "expected utoipa 5 default OpenAPI 3.1 emission, got first line: {:?}",
            yaml.lines().next(),
        );
    }
}

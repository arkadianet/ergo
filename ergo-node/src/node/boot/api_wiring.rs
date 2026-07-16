//! Boot phase: API scaffolding (identity, snapshot publisher, read/submit
//! bridges) and the REST API bind itself (wallet bridge, `ServerCtx`,
//! Scala-compat bridge, admin/security wiring).
//!
//! Split into two calls because the mining subsystem (built between them
//! in the original monolithic function) needs [`Scaffold::voting_targets_slot`]
//! before it can build its own bridge, and [`bind`] needs the mining bridge
//! it produces — so the natural boot order is `build_scaffold` →
//! (mining subsystem) → `bind`.

use std::sync::Arc;

use ergo_state::HeaderSectionStore;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::info;

use crate::api_bridge::{
    HostPaths, ScalaCompatBridge, ScalaCompatStatic, SnapshotMempoolView, SnapshotReadState,
    SubmitBridge, SubmitRequest,
};
use crate::config::NodeConfig;
use crate::snapshot::SnapshotPublisher;

use super::super::NodeError;

/// Identity + read/submit-bridge scaffolding built before the mining
/// subsystem (which needs [`voting_targets_slot`](Self::voting_targets_slot)).
pub(super) struct Scaffold {
    pub api_info: ergo_api::types::ApiInfo,
    pub identity_slot: crate::api_bridge::IdentitySlot,
    pub snapshot_publisher: SnapshotPublisher,
    pub voting_targets_slot: Arc<std::sync::RwLock<std::collections::BTreeMap<u8, i64>>>,
    pub read_state: Arc<dyn ergo_api::NodeReadState>,
    pub submit_bridge: Arc<dyn ergo_api::NodeSubmit>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_scaffold(
    config: &NodeConfig,
    db_path: &std::path::Path,
    boot_sentinel: u32,
    bootstrap_kind: crate::node::identity::BootstrapKind,
    executor: &ergo_sync::executor::SyncExecutor,
    started_at: std::time::Instant,
    api_weight_function: ergo_api::types::ApiWeightFunction,
    submit_tx: &mpsc::Sender<SubmitRequest>,
    event_tx: &mpsc::Sender<crate::peer_loop::PeerEvent>,
) -> Result<Scaffold, NodeError> {
    // Operator API publisher — created up front so the API server can
    // share the snapshot handle. If `api_bind` is None the server isn't
    // started; the publisher itself stays cheap (one ArcSwap) and is
    // updated unconditionally so disabling/enabling the API never
    // changes the main loop's hot path.
    let api_info = ergo_api::types::ApiInfo {
        agent_name: config.agent_name.clone(),
        node_name: config.node_name.clone(),
        network: format!("{:?}", config.network).to_lowercase(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        started_at_unix_ms: crate::snapshot::unix_now_ms(),
        uptime_seconds: 0,
        // Pulled from the live chain spec so the operator dashboard
        // labels the "avg block time" hero against the *actual*
        // network target (mainnet 120s, testnet 45s) — not a
        // hardcoded mainnet value that misreads as broken on
        // testnet.
        target_block_interval_ms: config.chain_spec.difficulty.desired_interval_ms,
    };
    let api_identity =
        super::super::identity::build_api_identity(config, boot_sentinel, bootstrap_kind)?;
    let identity_inputs = crate::node::identity::IdentityInputs::from_config(config);
    let _ = &identity_inputs; // consumed by NodeState construction in the orchestrator
    let identity_slot: crate::api_bridge::IdentitySlot =
        Arc::new(arc_swap::ArcSwap::from_pointee(api_identity.clone()));
    let snapshot_publisher =
        SnapshotPublisher::new(api_info.clone(), started_at, api_weight_function);
    // Read state is constructed unconditionally so [`RunHandle`] can
    // expose it for in-process tests even when the HTTP server isn't
    // bound. The submit bridge is always constructed (matching the
    // always-on submission posture); RunHandle exposes it via
    // `Some(_)` so embedders can drive in-process submissions.
    let host_paths = HostPaths {
        state_db: db_path.to_path_buf(),
        index_db: config.data_dir.join(&config.indexer_config.db_filename),
        data_dir: config.data_dir.clone(),
    };
    // ONE shared voting-targets slot, seeded from `[voting.targets]`. The SAME
    // `Arc<RwLock<…>>` is handed to the API read state (so `GET /api/v1/votes`
    // reports the live policy), the mining handle (candidate building reads it
    // per build), and — only when mining is enabled — the admin write path (so
    // the auth-gated `POST /api/v1/votes` updates all three at once).
    let voting_targets_slot =
        std::sync::Arc::new(std::sync::RwLock::new(config.voting_targets.clone()));
    let read_state: Arc<dyn ergo_api::NodeReadState> = SnapshotReadState::new(
        snapshot_publisher.handle(),
        identity_slot.clone(),
        host_paths,
        voting_targets_slot.clone(),
        executor.apply_phase_metrics(),
    )
    .into_dyn();
    let submit_bridge: Arc<dyn ergo_api::NodeSubmit> =
        SubmitBridge::new(submit_tx.clone(), event_tx.clone()).into_dyn();

    Ok(Scaffold {
        api_info,
        identity_slot,
        snapshot_publisher,
        voting_targets_slot,
        read_state,
        submit_bridge,
    })
}

/// What [`bind`] produces.
pub(super) struct ApiBind {
    pub api_addr: Option<std::net::SocketAddr>,
    pub api_handle: Option<JoinHandle<()>>,
    pub api_shutdown_tx: Option<oneshot::Sender<()>>,
    pub live_wallet_hook: Option<Arc<super::super::wallet_bridge::WalletStateHook>>,
}

/// Bind the REST API (if `[api] bind = Some(_)`): builds the Scala-compat
/// bridge, wires the wallet admin + writer task, assembles `ServerCtx`, and
/// starts serving. Bind failure is logged-and-degraded, not fatal — REST is
/// an operator surface, not a prerequisite for sync/validation availability.
#[allow(clippy::too_many_arguments)]
pub(super) async fn bind(
    config: &NodeConfig,
    store: &ergo_state::StateBackendKind,
    api_info: &ergo_api::types::ApiInfo,
    snapshot_publisher: &SnapshotPublisher,
    read_state: Arc<dyn ergo_api::NodeReadState>,
    submit_bridge: Arc<dyn ergo_api::NodeSubmit>,
    indexer_handle: Option<ergo_indexer::IndexerHandle>,
    mempool: &mut ergo_mempool::Mempool,
    mining_bridge: Option<Arc<dyn ergo_api::NodeMining>>,
    voting_targets_slot: Arc<std::sync::RwLock<std::collections::BTreeMap<u8, i64>>>,
    shutdown_notify: &Arc<tokio::sync::Notify>,
    peer_connect_tx: &mpsc::Sender<std::net::SocketAddr>,
    votes_changed_tx: &mpsc::Sender<()>,
) -> Result<ApiBind, NodeError> {
    let Some(bind_addr) = config.api_bind else {
        info!("api disabled by config");
        return Ok(ApiBind {
            api_addr: None,
            api_handle: None,
            api_shutdown_tx: None,
            live_wallet_hook: None,
        });
    };

    let (api_shutdown_tx, api_shutdown_rx) = oneshot::channel::<()>();

    // Bind first so `rest_api_url` reflects the actual port (matters
    // for `:0` ephemeral binds in tests and embedders).
    //
    // Bind failure is logged-and-degraded, not fatal: REST is an
    // operator surface, not a prerequisite for sync / validation
    // availability. A test or embedder that needs strict bind
    // detection inspects the returned `RunHandle.api_addr` — `None`
    // after configuring `api_bind = Some(..)` is the failure signal,
    // distinguishable from "API disabled by config" (where
    // `api_bind` itself is `None`).
    let (actual, listener) = match ergo_api::bind(bind_addr).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(addr = %bind_addr, error = %e, "api bind failed; node continuing without API");
            drop(api_shutdown_rx);
            return Ok(ApiBind {
                api_addr: None,
                api_handle: None,
                api_shutdown_tx: None,
                live_wallet_hook: None,
            });
        }
    };

    let scala_static = ScalaCompatStatic {
        name: format!("ergo-rust-{}-{}", api_info.network, api_info.version),
        app_version: api_info.version.clone(),
        network: api_info.network.clone(),
        launch_time_unix_ms: api_info.started_at_unix_ms,
        rest_api_url: Some(format!("http://{actual}")),
    };
    let scala_compat_bridge_arc = Arc::new(ScalaCompatBridge::new(
        snapshot_publisher.handle(),
        scala_static,
        store.reader_handle(),
        config.chain_spec.difficulty.clone(),
    ));
    let scala_compat: Arc<dyn ergo_api::NodeChainQuery> = scala_compat_bridge_arc.clone();
    // Submission HTTP routes are always mounted, matching
    // Scala's TransactionsApiRoute / BlocksApiRoute which
    // register unconditionally. Not-ready signals come
    // from the admission pipeline (TipUnready / IbdGated /
    // Disabled) rather than from a route-level gate.
    info!("api submission enabled; POST /api/v1/mempool/{{submit,check}} and POST /transactions[/bytes][/check[Bytes]], POST /blocks are live");
    let mounted_submit = Some(submit_bridge.clone());
    let network_prefix = config.chain_spec.network_params.address_prefix;
    let indexer_for_api: Option<Arc<dyn ergo_indexer::IndexerQuery>> = indexer_handle
        .clone()
        .map(|h| Arc::new(h) as Arc<dyn ergo_indexer::IndexerQuery>);
    // P5 mempool overlay: hand the snapshot-backed view to
    // the API so `/blockchain/balance` (and future unspent
    // routes) can render `unconfirmed` from pool state
    // without going through the action loop. Reads are
    // lock-free `arc_swap.load()` per snapshot, so the
    // overlay adds no contention with the main loop.
    let mempool_view = SnapshotMempoolView::new(snapshot_publisher.handle()).into_dyn();
    // Realtime WS bridge (A2): the same process-wide bus the
    // router feeds the `blocks` coarse-ring bridge into. Wiring
    // it as a `MempoolObserver` lets admit/evict publish
    // `tx_accepted`/`tx_dropped` on the `mempool` channel
    // directly from the admission hot path, bypassing the
    // coarse ring (which only carries block/reorg/peer events).
    mempool.set_observer(Some(Arc::new(
        crate::realtime_mempool_bridge::RealtimeMempoolObserver::new(
            ergo_api::realtime_handle().bus,
        ),
    )));
    let mut admin = crate::api_bridge::ShutdownAdmin::new(
        shutdown_notify.clone(),
        Some(peer_connect_tx.clone()),
    )
    // Held regardless of mining state to keep the channel open; only
    // fired on a successful vote update (which requires mining).
    .with_votes_changed_signal(votes_changed_tx.clone());
    // Expose the runtime voting write only when mining is enabled —
    // votes have no effect without a candidate builder, so
    // `POST /api/v1/votes` otherwise returns `MiningDisabled`.
    if config.mining_config.enabled {
        admin = admin.with_voting_targets(voting_targets_slot.clone());
    }
    let admin_handle: Arc<dyn ergo_api::NodeAdmin> = admin.into_dyn();

    // Production wallet admin. Owns the secret storage + wallet
    // state behind RwLocks; the writer task is a dedicated tokio
    // task receiving commands via a channel.
    let db_arc = store.db_arc();
    let is_pruned = config.blocks_to_keep != -1;
    // `ChainStateAccessorImpl::tip_height()` now reads the live committed
    // tip from redb per-call (no captured value), so no boot-time tip is
    // threaded in.
    let chain_accessor: Arc<dyn super::super::wallet_bridge::ChainStateAccessor> =
        Arc::new(super::super::wallet_bridge::ChainStateAccessorImpl::new(
            db_arc.clone(),
            is_pruned,
            // Same EIP-27 rules the validator uses, so the wallet's
            // burn-aware builder + self-verify gate share consensus.
            super::build_reemission_rules(&config.chain_spec),
        ));
    let wallet_storage = {
        let secret_dir = config.data_dir.join("wallet");
        Arc::new(parking_lot::RwLock::new(
            ergo_wallet::storage::SecretStorage::open(secret_dir),
        ))
    };
    // Hydrate in-memory caches from redb on restart so that
    // /wallet/addresses and friends serve correct data while the
    // wallet is still locked. The wallet stays locked — operator
    // must /wallet/unlock to load the master key.
    let wallet_state = {
        let use_pre_1627 = {
            let mut s = wallet_storage.write();
            match s.lock_state() {
                ergo_wallet::storage::LockState::Uninitialized => false,
                _ => s.load_metadata().unwrap_or_else(|e| {
                    tracing::warn!("wallet boot: could not read use_pre_1627 metadata: {e}; defaulting to false");
                    false
                }),
            }
        };
        let mut state = ergo_wallet::state::WalletState::empty(use_pre_1627);
        match db_arc.begin_read() {
            Ok(read_txn) => {
                let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
                if let Err(e) = state.hydrate_from_reader(&reader, network_prefix) {
                    tracing::warn!(
                        "wallet boot: hydration from redb failed: {e}; starting with empty caches"
                    );
                }
            }
            Err(e) => {
                tracing::warn!("wallet boot: could not open redb read txn for hydration: {e}");
            }
        }
        Arc::new(parking_lot::RwLock::new(state))
    };
    // Clone the Arc before moving into run_wallet_writer so the
    // main loop retains a reference for the live apply hook.
    let wallet_state_for_hook = Arc::clone(&wallet_state);
    let (wallet_tx, wallet_rx) = mpsc::channel::<super::super::wallet_bridge::WalletCommand>(64);
    let writer_cfg = super::super::wallet_bridge::WriterConfig {
        network: network_prefix,
        expose_private_keys: config.wallet_expose_private_keys,
        // Same EIP-27 rule inputs the block/mempool validator uses, so
        // the wallet's re-emission reserve + burn-aware builder cannot
        // drift from consensus (None off EIP-27 nets, e.g. testnet).
        reemission: super::build_reemission_rules(&config.chain_spec),
        min_relay_fee_nano_erg: config.mempool_config.min_relay_fee_nano_erg,
        max_tx_size_bytes: config.mempool_config.max_tx_size_bytes,
    };
    let submit_handle: Arc<dyn super::super::wallet_bridge::TxSubmitter> = Arc::new(
        super::super::wallet_bridge::NodeSubmitAdapter::new(submit_bridge.clone()),
    );
    tokio::spawn(super::super::wallet_bridge::run_wallet_writer(
        wallet_rx,
        wallet_storage,
        wallet_state,
        db_arc.clone(),
        chain_accessor,
        writer_cfg,
        submit_handle,
        // Clone the mempool view for the wallet's unconfirmed-balance
        // overlay; the original moves into ServerCtx below.
        mempool_view.clone(),
    ));
    let wallet_admin: Arc<dyn ergo_api::wallet::WalletAdmin> =
        Arc::new(super::super::wallet_bridge::NodeWalletAdmin::new(wallet_tx));

    let api_ctx = ergo_api::ServerCtx {
        read: read_state.clone(),
        compat: Some(scala_compat.clone()),
        submit: mounted_submit,
        indexer: indexer_for_api,
        mempool: mempool_view,
        network: network_prefix,
        chain_params: Some(scala_compat_bridge_arc.clone().into_chain_params()),
        mining: mining_bridge.clone(),
        // Static per-network schedule math — always wired.
        // Public route by Scala parity (no withAuth).
        emission: Some(Arc::new(crate::api_bridge::EmissionScheduleBridge::new(
            config.chain_spec.monetary,
            config.chain_spec.reemission.clone(),
        ))),
        // Pre-rendered P2S addresses for /emission/scripts;
        // None off-mainnet (no verified tree constants), in
        // which case the route stays unmounted (404).
        emission_scripts: crate::api_bridge::render_emission_scripts(&config.chain_spec)
            .map(Arc::new),
        // `/utxo/*` mount-vs-503 follows the backend: only
        // the UTXO backend retains box bytes. The digest
        // backend's boot dispatch (Mode 5) doesn't reach
        // here yet, but the gate is the right shape now.
        utxo_reads_supported: config.state_type == crate::config::StateType::Utxo,
    };
    // Mandatory api_key_hash per Scala ErgoApp.scala:40-43.
    // `NodeConfig::load` rejects (api_bind = Some,
    // api_key_hash = None) at config.rs, so the typical
    // production path hits the Ok branches below. We still
    // surface a typed error rather than panic for callers
    // that build `NodeConfig` literals and bypass `load()`
    // (integration tests, future programmatic spawn paths,
    // etc.).
    let Some(hash) = config.api_key_hash.clone() else {
        return Err("config invariant broken: api_bind = Some(_) requires \
             api_key_hash = Some(_); NodeConfig::load would have \
             rejected this, so the caller built a NodeConfig \
             literal that bypassed validation"
            .into());
    };
    let security_inner = ergo_api::auth::ApiSecurity::new(hash)
        .map_err(|e| -> NodeError { format!("invalid api_key_hash in NodeConfig: {e}").into() })?;
    let security = Arc::new(security_inner);
    let handle = ergo_api::serve_on_with_mempool_and_wallet_and_security(
        api_ctx,
        listener,
        api_shutdown_rx,
        Some(admin_handle),
        wallet_admin,
        Some(security),
    );
    let hook = Arc::new(super::super::wallet_bridge::WalletStateHook {
        wallet: wallet_state_for_hook,
        db: db_arc.clone(),
    });

    Ok(ApiBind {
        api_addr: Some(actual),
        api_handle: Some(handle),
        api_shutdown_tx: Some(api_shutdown_tx),
        live_wallet_hook: Some(hook),
    })
}

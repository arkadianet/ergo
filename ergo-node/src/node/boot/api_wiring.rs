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
    pub runtime_control: Arc<crate::runtime_control::RuntimeControl>,
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
    let runtime_control = crate::runtime_control::RuntimeControl::new(config)?;
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
    // Starvation-free telemetry thread (issue #266): samples process RSS,
    // uptime, and wall-clock apply age on a plain thread the action loop
    // cannot starve, so /metrics stays truthful while a long synchronous
    // apply has frozen the snapshot publisher.
    let live_telemetry = crate::node::telemetry::spawn(
        executor.apply_phase_metrics(),
        std::time::Duration::from_secs(5),
    );
    // Keep potentially blocking filesystem probes separate from wedge telemetry.
    let live_storage =
        crate::node::storage_probe::spawn(host_paths, std::time::Duration::from_secs(10));
    let peer_details =
        crate::peer_details::PeerResolver::new(&config.peer_details, &config.data_dir);
    if config.api_bind.is_some() {
        peer_details.start_updates(&config.peer_details, &config.data_dir);
    }
    let read_state: Arc<dyn ergo_api::NodeReadState> = SnapshotReadState::new(
        snapshot_publisher.handle(),
        identity_slot.clone(),
        live_storage,
        voting_targets_slot.clone(),
        executor.apply_phase_metrics(),
        live_telemetry,
    )
    .with_peer_details(peer_details)
    .with_runtime_control(runtime_control.clone())
    .into_dyn();
    let submit_bridge: Arc<dyn ergo_api::NodeSubmit> =
        SubmitBridge::new(submit_tx.clone(), event_tx.clone())
            .with_direct_block_submit(config.network, config.allow_direct_block_submit)
            .into_dyn();

    Ok(Scaffold {
        api_info,
        runtime_control,
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
    pub api_services: Option<Arc<ergo_api::ApiServices>>,
}

#[derive(Default)]
struct WalletChainConfig {
    is_pruned: bool,
    reemission_rules: Option<ergo_validation::ReemissionRuleInputs>,
    reemission_inputs: Vec<ergo_wallet_service::chain::ReemissionInput>,
    private_queue: Option<Arc<ergo_mining::private_queue::PrivateTransactionQueue>>,
    spending: Option<(crate::snapshot::SnapshotHandle, u64, usize)>,
}

/// The chain API the wallet daemon reads: committed chain, spending context
/// and private queue, over the UTXO backend. `None` on the digest backend.
fn build_wallet_chain(
    store: &ergo_state::StateBackendKind,
    submit_bridge: Arc<dyn ergo_api::NodeSubmit>,
    config: WalletChainConfig,
) -> Option<Arc<dyn ergo_api::WalletChain>> {
    let WalletChainConfig {
        is_pruned,
        reemission_rules,
        reemission_inputs,
        private_queue,
        spending,
    } = config;
    store.as_utxo()?;
    let reader = store.reader_handle();
    let accessor = Arc::new(
        super::super::wallet_bridge::ChainStateAccessorImpl::chain_only(
            reader.clone(),
            is_pruned,
            reemission_rules,
        )
        .with_private_queue(private_queue.clone()),
    );
    let mut client = super::super::wallet_bridge::InProcessChainClient::new(reader, submit_bridge)
        .with_state_accessor(accessor)
        .with_reemission_inputs(reemission_inputs);
    if let Some((snapshot, fee, size)) = spending {
        client = client.with_spending_context(snapshot, fee, size, private_queue);
    }
    Some(Arc::new(
        super::super::wallet_bridge::WalletChainAdapter::new(
            Arc::new(client) as Arc<dyn ergo_wallet_service::chain::ChainClient>
        ),
    ))
}

/// Bind the REST API (if `[api] bind = Some(_)`): builds the Scala-compat
/// bridge, assembles `ServerCtx`, and starts serving. REST bind failure is
/// logged-and-degraded, not fatal — REST is an operator surface, not a
/// prerequisite for sync/validation availability.
///
/// The node hosts no wallet: wallet routes answer `410 wallet_moved` with the
/// configured daemon address, and the chain API serves the wallet daemon.
#[allow(clippy::too_many_arguments)]
pub(super) async fn bind(
    config: &NodeConfig,
    store: &ergo_state::StateBackendKind,
    api_info: &ergo_api::types::ApiInfo,
    snapshot_publisher: &SnapshotPublisher,
    read_state: Arc<dyn ergo_api::NodeReadState>,
    submit_bridge: Arc<dyn ergo_api::NodeSubmit>,
    indexer_handle: Option<ergo_indexer::IndexerHandle>,
    indexer_event_observer: Option<Arc<crate::realtime_indexer_bridge::RealtimeIndexerObserver>>,
    mempool: &mut ergo_mempool::Mempool,
    mining_bridge: Option<Arc<dyn ergo_api::NodeMining>>,
    private_queue: Option<Arc<ergo_mining::private_queue::PrivateTransactionQueue>>,
    voting_targets_slot: Arc<std::sync::RwLock<std::collections::BTreeMap<u8, i64>>>,
    shutdown_notify: &Arc<tokio::sync::Notify>,
    peer_connect_tx: &mpsc::Sender<std::net::SocketAddr>,
    peer_control_tx: &mpsc::Sender<crate::runtime_control::PeerControlRequest>,
    runtime_control: Arc<crate::runtime_control::RuntimeControl>,
    votes_changed_tx: &mpsc::Sender<()>,
) -> Result<ApiBind, NodeError> {
    // Validate/load the revocation ledger before spawning storage-owning tasks.
    let security = if config.api_bind.is_some() {
        api_security(config)?
    } else {
        None
    };
    let network_prefix = config.chain_spec.network_params.address_prefix;
    // P5 mempool overlay: hand the snapshot-backed view to
    // the API so `/blockchain/balance` (and future unspent
    // routes) can render `unconfirmed` from pool state
    // without going through the action loop. Reads are
    // lock-free `arc_swap.load()` per snapshot, so the
    // overlay adds no contention with the main loop. Also handed to the
    // wallet writer below for its unconfirmed-balance overlay — built
    // once here so both consumers share the same instance.
    let mempool_view = SnapshotMempoolView::new(snapshot_publisher.handle()).into_dyn();

    let indexer_probe = indexer_handle.clone();
    runtime_control.set_dependencies(Arc::new(move |require_indexer| {
        use ergo_indexer::IndexerQuery;
        let indexer_height = require_indexer
            .then(|| indexer_probe.as_ref().map(|handle| handle.indexed_height()))
            .flatten();
        let indexer_healthy = require_indexer
            && indexer_probe
                .as_ref()
                .is_some_and(|handle| handle.is_caught_up());
        crate::runtime_control::Dependencies {
            indexer_height,
            indexer_healthy,
        }
    }));
    let wallet_moved = Some(config.wallet_daemon_address.as_str());
    let is_pruned = config.blocks_to_keep != -1;
    let reemission_rules =
        super::build_reemission_rules(&config.chain_spec, config.check_reemission_rules);
    let reemission_inputs = reemission_rules
        .as_ref()
        .map(|rules| {
            vec![ergo_wallet_service::chain::ReemissionInput {
                token_id: rules.reemission_token_id,
                amount: 0,
                box_ids: Vec::new(),
            }]
        })
        .unwrap_or_default();
    let wallet_chain = build_wallet_chain(
        store,
        submit_bridge.clone(),
        WalletChainConfig {
            is_pruned,
            reemission_rules,
            reemission_inputs,
            private_queue: private_queue.clone(),
            spending: Some((
                snapshot_publisher.handle(),
                config.mempool_config.min_relay_fee_nano_erg,
                config.mempool_config.max_tx_size_bytes,
            )),
        },
    );

    let wallet_admin: Arc<dyn ergo_api::wallet::WalletAdmin> =
        Arc::new(ergo_api::wallet::NoopWalletAdmin);

    let Some(bind_addr) = config.api_bind else {
        info!("api disabled by config");
        return Ok(ApiBind {
            api_addr: None,
            api_handle: None,
            api_shutdown_tx: None,
            api_services: None,
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
                api_services: None,
            });
        }
    };

    let scala_static = ScalaCompatStatic {
        // Scala /info `name` = the configured `nodeName`
        // (mainnet.conf:127 defaults it to "ergo-mainnet-"${scorex.network.appVersion},
        // operators override it) — so ours must be the configured
        // node_name too, not a synthesized network/version string. This
        // is also the same value the handshake PeerSpec and the native
        // /api/v1/info already advertise; it was the only surface that
        // ignored it, so a configured name couldn't survive an upgrade
        // (v0.5.3 soak finding).
        name: config.node_name.clone(),
        app_version: api_info.version.clone(),
        network: api_info.network.clone(),
        state_type: config.state_type,
        voting_length: config.chain_spec.voting.voting_length,
        launch_time_unix_ms: api_info.started_at_unix_ms,
        rest_api_url: Some(format!("http://{actual}")),
        min_relay_fee_nano_erg: config.mempool_config.min_relay_fee_nano_erg,
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
    let indexer_for_api: Option<Arc<dyn ergo_indexer::IndexerQuery>> = indexer_handle
        .clone()
        .map(|h| Arc::new(h) as Arc<dyn ergo_indexer::IndexerQuery>);
    // Restore admitted delivery obligations before node-owned realtime observers
    // and the API listener start. An unavailable store disables webhooks rather
    // than acknowledging registrations that would disappear at restart.
    let webhook_path = config.data_dir.join("webhooks.redb");
    let api_services = tokio::task::spawn_blocking(move || {
        let store = match crate::webhook_store::RedbWebhookStore::open(&webhook_path) {
            Ok(store) => Arc::new(store),
            Err(error) => {
                tracing::error!(%error, "notification store unavailable; live realtime, durable replay and webhooks disabled");
                return Err(error);
            }
        };
        let webhook_engine = match ergo_api::v1::WebhookEngine::durable(Default::default(), store.clone()) {
            Ok(engine) => Some(Arc::new(engine)),
            Err(error) => {
                tracing::error!(%error, "durable webhook store unavailable; webhooks disabled");
                None
            }
        };
        ergo_api::ApiServices::with_durable_realtime(webhook_engine, store).map(Arc::new)
    })
    .await;
    let api_services = match api_services
        .map_err(|error| error.to_string())
        .and_then(|result| result)
    {
        Ok(services) => services,
        Err(error) => {
            tracing::error!(%error, "notification cursor initialization failed; realtime and webhooks disabled");
            Arc::new(ergo_api::ApiServices::without_notifications())
        }
    };
    // Realtime WS bridge (A2): the same node-owned bus the
    // router feeds the `blocks` coarse-ring bridge into. Wiring
    // it as a `MempoolObserver` lets admit/evict publish
    // `tx_accepted`/`tx_dropped` on the `mempool` channel
    // directly from the admission hot path, bypassing the
    // coarse ring (which only carries block/reorg/peer events).
    if api_services.realtime.bus.is_enabled() {
        mempool.set_observer(Some(Arc::new(
            crate::realtime_mempool_bridge::RealtimeMempoolObserver::new(
                api_services.realtime.bus.clone(),
            ),
        )));
        // Restore durable cursors before activating the indexer source.
        if let Some(observer) = indexer_event_observer {
            observer.activate(api_services.realtime.bus.clone());
        }
    }
    let mut admin = crate::api_bridge::ShutdownAdmin::new(
        shutdown_notify.clone(),
        Some(peer_connect_tx.clone()),
    )
    // Held regardless of mining state to keep the channel open; only
    // fired on a successful vote update (which requires mining).
    .with_votes_changed_signal(votes_changed_tx.clone())
    .with_operator_control(runtime_control, peer_control_tx.clone(), security.clone());
    // Expose the runtime voting write only when mining is enabled —
    // votes have no effect without a candidate builder, so
    // `POST /api/v1/votes` otherwise returns `MiningDisabled`.
    if config.mining_config.enabled {
        admin = admin.with_voting_targets(voting_targets_slot.clone());
    }
    let admin_handle: Arc<dyn ergo_api::NodeAdmin> = admin.into_dyn();

    let api_ctx = ergo_api::ServerCtx {
        read: read_state.clone(),
        compat: Some(scala_compat.clone()),
        submit: mounted_submit,
        wallet_chain,
        indexer: indexer_for_api,
        mempool: mempool_view,
        network: network_prefix,
        chain_params: Some(scala_compat_bridge_arc.clone().into_chain_params()),
        mining: mining_bridge.clone(),
        private_queue: if mining_bridge.is_none() {
            private_queue.clone().map(|queue| {
                Arc::new(super::super::wallet_bridge::StoredPrivateQueueBridge::new(
                    queue,
                )) as Arc<dyn ergo_api::NodeMining>
            })
        } else {
            None
        },
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
        local_reverse_proxy: config.api_local_reverse_proxy,
        services: api_services.clone(),
        script_config: config.api_script.clone(),
    };
    let handle = ergo_api::serve_on_with_mempool_and_wallet_and_security_and_hosts_and_wallet_moved(
        api_ctx,
        listener,
        api_shutdown_rx,
        Some(admin_handle),
        wallet_admin,
        security,
        &config.api_allowed_hosts,
        wallet_moved,
    );

    Ok(ApiBind {
        api_addr: Some(actual),
        api_handle: Some(handle),
        api_shutdown_tx: Some(api_shutdown_tx),
        api_services: Some(api_services),
    })
}

/// Preserve absent credentials as a closed privileged surface, and reject malformed
/// hashes even for programmatic configs that bypass the loader.
fn api_security(
    config: &NodeConfig,
) -> Result<Option<Arc<ergo_api::auth::ApiSecurity>>, NodeError> {
    if config.allow_unauthenticated_legacy_mining && config.api_key_hash.is_none() {
        return Err("allow_unauthenticated_legacy_mining requires api_key_hash".into());
    }
    let Some(hash) = config.api_key_hash.clone() else {
        ergo_api::auth::validate_credentials(&config.api_scoped_keys, None)?;
        return Ok(None);
    };
    let security = ergo_api::auth::ApiSecurity::new(hash)
        .map_err(|e| -> NodeError { format!("invalid api_key_hash in NodeConfig: {e}").into() })?
        .with_credentials(
            config.api_scoped_keys.clone(),
            config.data_dir.join("credentials-revoked.json"),
        )?
        .with_unauthenticated_legacy_mining(config.allow_unauthenticated_legacy_mining);
    Ok(Some(Arc::new(security)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use ergo_state::store::StateStore;
    use std::sync::Arc;

    fn template_config(source: &str) -> (tempfile::TempDir, NodeConfig) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.toml");
        std::fs::write(&path, source).unwrap();
        let cli = crate::config::Cli::parse_from([
            "ergo-node",
            "--config",
            path.to_str().unwrap(),
            "--data-dir",
            dir.path().to_str().unwrap(),
        ]);
        (dir, NodeConfig::load(cli).expect("template loads"))
    }

    #[tokio::test]
    async fn unreadable_replay_cursor_never_falls_back_to_reused_session_cursors() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("node.toml");
        std::fs::write(&config_path, "[api]\nbind = \"127.0.0.1:0\"\n").unwrap();
        let cli = crate::config::Cli::parse_from([
            "ergo-node",
            "--network",
            "devnet",
            "--data-dir",
            directory.path().to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "--peers",
            "127.0.0.1:1",
        ]);
        let config = NodeConfig::load(cli).unwrap();
        let path = directory.path().join("webhooks.redb");
        {
            let db = redb::Database::create(&path).unwrap();
            let write = db.begin_write().unwrap();
            {
                let mut table = write
                    .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                        "realtime_metadata_v1",
                    ))
                    .unwrap();
                table
                    .insert(
                        "state",
                        br#"{"version":2,"next_seq":100000,"retained_bytes":0}"#.as_slice(),
                    )
                    .unwrap();
            }
            write.commit().unwrap();
        }
        let handle = crate::node::run_inner(config).await.unwrap();
        let address = handle.api_addr.expect("other API routes remain available");
        let bus = &handle.api_services.as_ref().unwrap().realtime.bus;
        let published = bus.try_publish(ergo_api::v1::realtime::RealtimeEventBody::block_applied(
            1,
            "rejected".into(),
            1,
            1,
            100,
        ));
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = client
            .get(format!(
                "http://{address}/api/v1/events/replay?channels=blocks"
            ))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let value: serde_json::Value = response.json().await.unwrap();
        client
            .get(format!("http://{address}/api/v1/info"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        handle.shutdown().await.unwrap();
        assert_eq!(
            published, None,
            "uncertain persisted cursors must disable notification publication"
        );
        assert_eq!(status, reqwest::StatusCode::CONFLICT);
        assert_eq!(value["error"]["reason"], "realtime_disabled");
    }

    // ----- happy path -----

    #[test]
    fn api_security_shipped_templates_resolve_without_verifier() {
        for source in [
            include_str!("../../../ergo-node.toml"),
            include_str!("../../../ergo-node.toml.example"),
        ] {
            let (_dir, config) = template_config(source);
            assert!(config.api_bind.unwrap().ip().is_loopback());
            assert!(api_security(&config).unwrap().is_none());
        }
    }

    fn submit_bridge() -> Arc<dyn ergo_api::NodeSubmit> {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let (event_tx, _event_rx) = tokio::sync::mpsc::channel(1);
        crate::api_bridge::SubmitBridge::new(tx, event_tx).into_dyn()
    }

    #[test]
    fn chain_wiring_is_available_for_the_utxo_backend() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateStore::open(&dir.path().join("state.redb")).unwrap();
        state.initialize_genesis(&[]).unwrap();
        let backend = ergo_state::StateBackendKind::Utxo(state);
        assert!(
            build_wallet_chain(&backend, submit_bridge(), WalletChainConfig::default()).is_some()
        );
    }

    #[test]
    fn chain_wiring_is_absent_for_digest_backend() {
        let dir = tempfile::tempdir().unwrap();
        let state = ergo_state::DigestStateStore::open(
            &dir.path().join("state.redb"),
            ergo_validation::scala_launch(),
            ergo_chain_spec::VotingParams {
                voting_length: 2,
                ..ergo_chain_spec::VotingParams::mainnet()
            },
            [0; 33],
        )
        .unwrap();
        let backend = ergo_state::StateBackendKind::Digest(state);
        assert!(
            build_wallet_chain(&backend, submit_bridge(), WalletChainConfig::default()).is_none()
        );
    }

    // ----- error paths -----

    #[test]
    fn api_security_programmatic_malformed_hash_rejected() {
        let (_dir, mut config) = template_config(include_str!("../../../ergo-node.toml"));
        config.api_key_hash = Some("bad hash".into());
        assert!(api_security(&config)
            .unwrap_err()
            .to_string()
            .contains("invalid api_key_hash"));
    }
}

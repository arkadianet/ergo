mod api;
mod event_loop;
pub mod mining;
pub mod snapshot_bootstrap;
pub mod snapshots;
mod web_ui;

use std::path::Path;
use std::sync::Arc;

use tokio::sync::RwLock;

use ergo_network::block_processor::{self, ProcessorCommand, ProcessorEvent, ProcessorState};
use ergo_network::mempool::ErgoMemPool;
use ergo_network::node_view::NodeViewHolder;
use ergo_network::peer_conn::PeerConnection;
use ergo_settings::settings::ErgoSettings;
use ergo_storage::history_db::HistoryDb;

use crate::api::ApiState;
use crate::event_loop::SharedState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mut config_path: Option<String> = None;
    let mut network_flag: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--network" if i + 1 < args.len() => {
                network_flag = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                config_path = Some(args[i].clone());
                i += 1;
            }
        }
    }

    let config_str = if let Some(ref path) = config_path {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
    } else if let Some(ref net) = network_flag {
        match net.as_str() {
            "mainnet" => include_str!("../../../config/ergo-mainnet.toml").to_string(),
            "testnet" => include_str!("../../../config/ergo-testnet.toml").to_string(),
            _ => panic!("unknown network: {net}. Use 'mainnet' or 'testnet'"),
        }
    } else {
        // Fallback: ergo.toml in CWD, then ~/.ergo/ergo.toml, then built-in mainnet
        if std::path::Path::new("ergo.toml").exists() {
            std::fs::read_to_string("ergo.toml").unwrap()
        } else if let Some(home) = std::env::var_os("HOME") {
            let home_config = std::path::PathBuf::from(home).join(".ergo/ergo.toml");
            if home_config.exists() {
                std::fs::read_to_string(&home_config).unwrap()
            } else {
                tracing::info!("no config found, using built-in mainnet defaults");
                include_str!("../../../config/ergo-mainnet.toml").to_string()
            }
        } else {
            tracing::info!("no config found, using built-in mainnet defaults");
            include_str!("../../../config/ergo-mainnet.toml").to_string()
        }
    };

    let settings =
        ErgoSettings::from_toml(&config_str).unwrap_or_else(|e| panic!("invalid config: {e}"));

    tracing::info!(
        network = ?settings.ergo.network_type,
        directory = %settings.ergo.directory,
        "starting ergo-node",
    );

    let db_path = Path::new(&settings.ergo.directory).join("history");

    // Open a temporary read-write HistoryDb just to log the current state.
    {
        let history =
            HistoryDb::open(&db_path).unwrap_or_else(|e| panic!("cannot open database: {e}"));
        let best_header = history.best_header_id().unwrap();
        let best_block = history.best_full_block_id().unwrap();
        tracing::info!(best_header = ?best_header, best_block = ?best_block, "database opened");
        // history (rw) dropped here, freeing the primary lock
    }

    // Open a read-only DB handle for the HTTP API.
    let api_history = HistoryDb::open_read_only(&db_path)
        .unwrap_or_else(|e| panic!("cannot open API database: {e}"));

    // Open a secondary DB handle for the event loop (sync protocol).
    // Secondary mode allows periodic refresh via try_catch_up_with_primary()
    // so the sync protocol sees headers written by the processor thread.
    // The secondary path must be OUTSIDE the primary path to avoid interfering
    // with RocksDB's WAL and SST file management.
    let sync_secondary_path = Path::new(&settings.ergo.directory).join("history_sync_secondary");
    std::fs::create_dir_all(&sync_secondary_path)
        .unwrap_or_else(|e| panic!("cannot create sync secondary dir: {e}"));
    let sync_history = HistoryDb::open_as_secondary(&db_path, &sync_secondary_path)
        .unwrap_or_else(|e| panic!("cannot open sync database: {e}"));

    let mempool = Arc::new(std::sync::RwLock::new(ErgoMemPool::with_min_fee(
        settings.ergo.node.mempool_capacity as usize,
        settings.ergo.node.minimal_fee_amount,
    )));

    let is_utxo_mode = settings.ergo.node.state_type == "utxo";
    let is_digest_mode = !is_utxo_mode;

    // Create processor channels.
    let (cmd_tx, cmd_rx) =
        std::sync::mpsc::sync_channel::<ProcessorCommand>(block_processor::CHANNEL_CAPACITY);
    let (evt_tx, mut evt_rx) =
        tokio::sync::mpsc::channel::<ProcessorEvent>(block_processor::CHANNEL_CAPACITY);

    // Clone settings for the processor thread.
    let proc_settings = settings.clone();
    let proc_db_path = db_path.clone();
    let proc_mempool = mempool.clone();

    // Spawn the processor thread. The NodeViewHolder is constructed inside
    // the factory closure, so it lives entirely on the processor thread.
    let processor_handle = std::thread::Builder::new()
        .name("block-processor".into())
        .spawn(move || {
            block_processor::run_processor_with_state(cmd_rx, evt_tx, move || {
                let history = HistoryDb::open(&proc_db_path)
                    .unwrap_or_else(|e| panic!("processor: cannot open database: {e}"));

                let genesis_digest = proc_settings.ergo.chain.genesis_state_digest();
                let is_utxo = proc_settings.ergo.node.state_type == "utxo";
                let mut node_view =
                    NodeViewHolder::with_recovery(history, proc_mempool, !is_utxo, genesis_digest);

                // Set up UTXO persistence if in UTXO mode.
                if is_utxo {
                    let utxo_path = Path::new(&proc_settings.ergo.directory).join("utxo");
                    match ergo_storage::utxo_db::UtxoDb::open(&utxo_path) {
                        Ok(utxo_db) => match utxo_db.metadata() {
                            Ok(Some(meta)) => {
                                tracing::info!(
                                    version = hex::encode(meta.version),
                                    "processor: found existing UTXO DB, restoring state"
                                );
                                match ergo_state::utxo_state::UtxoState::restore_from_db(utxo_db) {
                                    Ok(utxo_state) => {
                                        let entries = utxo_state
                                            .utxo_db()
                                            .map(|db| db.entry_count())
                                            .unwrap_or(0);
                                        tracing::info!(entries, "processor: UTXO state restored");
                                        node_view.set_utxo_state(utxo_state);
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            error = %e,
                                            "processor: UTXO restore failed, starting fresh"
                                        );
                                        let fresh_db =
                                            ergo_storage::utxo_db::UtxoDb::open(&utxo_path)
                                                .unwrap();
                                        node_view.set_utxo_state(
                                            ergo_state::utxo_state::UtxoState::with_persistence(
                                                fresh_db,
                                            ),
                                        );
                                    }
                                }
                            }
                            _ => {
                                tracing::info!(
                                    "processor: no existing UTXO DB data, starting fresh"
                                );
                                node_view.set_utxo_state(
                                    ergo_state::utxo_state::UtxoState::with_persistence(utxo_db),
                                );
                            }
                        },
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "processor: failed to open UTXO DB"
                            );
                        }
                    }
                }

                if proc_settings.ergo.node.blocks_to_keep >= 0 {
                    node_view.set_blocks_to_keep(proc_settings.ergo.node.blocks_to_keep);
                }
                node_view.set_checkpoint_height(proc_settings.ergo.node.checkpoint_height);
                node_view.set_v2_activation_config(
                    proc_settings.ergo.chain.version2_activation_height,
                    proc_settings
                        .ergo
                        .chain
                        .version2_activation_difficulty_hex
                        .clone(),
                );
                node_view
                    .set_max_time_drift_from_interval(proc_settings.ergo.chain.block_interval_secs);

                // Restore state/history consistency (recovery after crash).
                if let Err(e) = node_view.restore_consistency() {
                    tracing::error!(
                        error = %e,
                        "processor: consistency restore failed, continuing anyway"
                    );
                }

                ProcessorState::new(node_view)
            });
        })
        .expect("failed to spawn processor thread");

    tracing::info!("block processor thread spawned");

    // Conditionally start the extra indexer.
    let extra_path = Path::new(&settings.ergo.directory)
        .join("history")
        .join("extra");

    let indexer_tx = if settings.ergo.node.extra_index {
        let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path)
            .unwrap_or_else(|e| panic!("cannot open extra indexer db: {e}"));

        let (idx_tx, idx_rx) = tokio::sync::mpsc::channel(1024);
        let idx_history = Arc::new(
            HistoryDb::open_read_only(&db_path)
                .unwrap_or_else(|e| panic!("cannot open indexer history db: {e}")),
        );

        tokio::spawn(ergo_indexer::task::run_indexer(
            extra_db,
            idx_history,
            idx_rx,
        ));

        tracing::info!("extra indexer enabled");
        Some(idx_tx)
    } else {
        None
    };

    // Open a read-only DB handle for the extra indexer API endpoints.
    let extra_db_api: Option<Arc<ergo_indexer::db::ExtraIndexerDb>> =
        if settings.ergo.node.extra_index {
            let extra_db_api = ergo_indexer::db::ExtraIndexerDb::open_read_only(&extra_path)
                .unwrap_or_else(|e| panic!("cannot open extra indexer API db: {e}"));
            Some(Arc::new(extra_db_api))
        } else {
            None
        };

    let shared = Arc::new(RwLock::new(SharedState::new()));
    let (tx_submit_tx, mut tx_submit_rx) =
        tokio::sync::mpsc::channel::<crate::api::TxSubmission>(256);
    let (peer_connect_tx, mut peer_connect_rx) =
        tokio::sync::mpsc::channel::<std::net::SocketAddr>(16);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let (mining_solution_tx, mut mining_solution_rx) =
        tokio::sync::mpsc::channel::<mining::MiningSolution>(16);
    let (block_submit_tx, mut block_submit_rx) =
        tokio::sync::mpsc::channel::<event_loop::BlockSubmission>(16);
    let (utxo_proof_tx, mut utxo_proof_rx) =
        tokio::sync::mpsc::channel::<event_loop::UtxoProofRequest>(16);

    // Open SnapshotsDb if configured.
    let snapshots_db_opt =
        if settings.ergo.node.storing_utxo_snapshots > 0 || settings.ergo.node.utxo_bootstrap {
            let snap_path = Path::new(&settings.ergo.directory).join("snapshots");
            match snapshots::SnapshotsDb::open(&snap_path) {
                Ok(sdb) => {
                    tracing::info!("snapshots DB opened");
                    Some(sdb)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to open snapshots DB");
                    None
                }
            }
        } else {
            None
        };
    let snapshots_db_arc = snapshots_db_opt.map(Arc::new);

    // Create wallet if feature enabled.
    #[cfg(feature = "wallet")]
    let wallet_arc = {
        let wallet_dir = Path::new(&settings.ergo.directory).join("wallet");
        match ergo_wallet::wallet_manager::WalletManager::open(&wallet_dir) {
            Ok(mut wm) => {
                // Auto-init from test mnemonic if configured and not already initialized.
                if let Some(ref ws) = settings.wallet {
                    if !ws.test_mnemonic.is_empty() && !wm.status().initialized {
                        let _ = wm.restore("test", &ws.test_mnemonic, &ws.test_mnemonic_password);
                        let _ = wm.unlock("test");
                        tracing::info!("wallet auto-initialized from test mnemonic");
                    }
                }
                tracing::info!(initialized = wm.status().initialized, "wallet opened");
                Some(Arc::new(tokio::sync::RwLock::new(wm)))
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to open wallet");
                None
            }
        }
    };
    #[cfg(not(feature = "wallet"))]
    let wallet_arc: Option<Arc<tokio::sync::RwLock<()>>> = None;

    // Create the candidate generator (shared between event loop and API).
    let candidate_gen_arc: Option<Arc<std::sync::RwLock<mining::CandidateGenerator>>> =
        if settings.ergo.node.mining {
            if let Some(pk) = settings.ergo.node.mining_pub_key() {
                tracing::info!(pk = hex::encode(pk), "mining enabled");
                Some(Arc::new(std::sync::RwLock::new(
                    mining::CandidateGenerator::new(pk, settings.ergo.node.votes()),
                )))
            } else {
                tracing::warn!(
                    "mining enabled but no mining_pub_key_hex configured — mining disabled"
                );
                None
            }
        } else {
            None
        };

    // Clone mining_solution_tx before it's moved into ApiState.
    let mining_solution_tx_for_miners = mining_solution_tx.clone();

    // Spawn HTTP API server.
    let api_state = ApiState {
        shared: shared.clone(),
        history: Arc::new(api_history),
        mempool: mempool.clone(),
        node_name: settings.network.node_name.clone(),
        app_version: settings.network.app_version.clone(),
        network: format!("{:?}", settings.ergo.network_type),
        tx_submit: Some(tx_submit_tx),
        peer_connect: Some(peer_connect_tx),
        shutdown_tx: Some(shutdown_tx),
        extra_db: extra_db_api,
        api_key_hash: settings.api.api_key_hash.clone(),
        max_transaction_size: settings.ergo.node.max_transaction_size,
        blacklisted_transactions: settings.ergo.node.blacklisted_transactions.clone(),
        cors_allowed_origin: settings.api.cors_allowed_origin.clone(),
        state_type: settings.ergo.node.state_type.clone(),
        candidate_generator: candidate_gen_arc.clone(),
        mining_solution_tx: Some(mining_solution_tx),
        block_submit: Some(block_submit_tx),
        utxo_proof: Some(utxo_proof_tx),
        mining_pub_key_hex: settings.ergo.node.mining_pub_key_hex.clone(),
        snapshots_db: snapshots_db_arc.clone(),
        #[cfg(feature = "wallet")]
        wallet: wallet_arc.clone(),
    };
    let api_bind = settings.api.bind_address.clone();
    tokio::spawn(async move {
        if let Err(e) = api::start_api_server(&api_bind, api_state).await {
            tracing::error!(error = %e, "API server failed");
        }
    });

    // Spawn internal CPU miners if configured.
    let shutdown_rx_for_miners = shutdown_rx.clone();
    let _miner_handles = if let Some(ref gen) = candidate_gen_arc {
        if settings.ergo.node.internal_miners_count > 0 && !settings.ergo.node.use_external_miner {
            let handles = mining::spawn_internal_miners(
                settings.ergo.node.internal_miners_count,
                settings.ergo.node.internal_miner_polling_ms,
                gen.clone(),
                mining_solution_tx_for_miners,
                shutdown_rx_for_miners,
            );
            tracing::info!(
                count = settings.ergo.node.internal_miners_count,
                "internal CPU miners started"
            );
            handles
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Generate a random session ID for self-connection detection.
    let session_id: u64 = rand::random();
    tracing::info!(
        session_id,
        "generated session ID for self-connection detection"
    );

    // Create inbound peer channel and spawn TCP listener.
    let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel::<event_loop::InboundPeer>(32);
    let magic: [u8; 4] = settings
        .network
        .magic_bytes
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([1, 0, 2, 4]);
    let our_handshake = ergo_wire::handshake::Handshake {
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        peer_spec: ergo_wire::handshake::PeerSpec {
            agent_name: settings.network.agent_name.clone(),
            protocol_version: ergo_wire::handshake::ProtocolVersion::from_version_str(
                &settings.network.app_version,
            )
            .unwrap_or(ergo_wire::handshake::ProtocolVersion {
                major: 5,
                minor: 0,
                patch: 2,
            }),
            node_name: settings.network.node_name.clone(),
            declared_address: settings
                .network
                .declared_address
                .as_deref()
                .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
                .or_else(|| {
                    settings
                        .network
                        .bind_address
                        .parse::<std::net::SocketAddr>()
                        .ok()
                        .filter(|addr| !addr.ip().is_unspecified())
                }),
            features: vec![
                ergo_wire::peer_feature::PeerFeature::Mode(ergo_wire::peer_feature::ModeFeature {
                    state_type: if is_utxo_mode {
                        ergo_wire::peer_feature::StateTypeCode::Utxo
                    } else {
                        ergo_wire::peer_feature::StateTypeCode::Digest
                    },
                    verifying_transactions: true,
                    nipopow_bootstrapped: None,
                    blocks_to_keep: settings.ergo.node.blocks_to_keep,
                }),
                ergo_wire::peer_feature::PeerFeature::Session(
                    ergo_wire::peer_feature::SessionFeature {
                        network_magic: magic,
                        session_id: session_id as i64,
                    },
                ),
            ],
        },
    };
    let handshake_timeout = settings.network.handshake_timeout_secs;
    let bind_addr = settings.network.bind_address.clone();

    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
            Ok(l) => {
                tracing::info!(addr = %bind_addr, "TCP listener started");
                l
            }
            Err(e) => {
                tracing::error!(addr = %bind_addr, error = %e, "failed to bind TCP listener");
                return;
            }
        };
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let inbound_tx = inbound_tx.clone();
                    let our_hs = our_handshake.clone();
                    tokio::spawn(async move {
                        match PeerConnection::accept(
                            stream,
                            magic,
                            &our_hs,
                            handshake_timeout,
                            Some(session_id),
                        )
                        .await
                        {
                            Ok((conn, peer_hs)) => {
                                let inbound = event_loop::InboundPeer {
                                    conn,
                                    addr,
                                    handshake: peer_hs,
                                };
                                if inbound_tx.send(inbound).await.is_err() {
                                    tracing::debug!(%addr, "inbound channel closed");
                                }
                            }
                            Err(e) => {
                                tracing::debug!(%addr, error = %e, "inbound handshake failed");
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TCP accept failed");
                }
            }
        }
    });

    if let Err(e) = event_loop::run(
        settings,
        cmd_tx,
        &mut evt_rx,
        &sync_history,
        mempool,
        is_digest_mode,
        shared,
        &mut tx_submit_rx,
        &mut peer_connect_rx,
        &mut inbound_rx,
        &mut shutdown_rx,
        indexer_tx,
        &mut mining_solution_rx,
        &mut block_submit_rx,
        &mut utxo_proof_rx,
        candidate_gen_arc,
        snapshots_db_arc,
        wallet_arc,
        session_id,
    )
    .await
    {
        tracing::error!(error = %e, "event loop exited with error");
    }

    // Signal the processor to shut down and wait for it to finish.
    // cmd_tx is already dropped when the event loop exits (it was moved into run()).
    // Just join the thread.
    if let Err(e) = processor_handle.join() {
        tracing::error!("processor thread panicked: {:?}", e);
    }

    tracing::info!("ergo-node stopped");
}

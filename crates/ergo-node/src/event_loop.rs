use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use ergo_network::block_processor::{ProcessorCommand, ProcessorEvent};
use ergo_network::connection_pool::ConnectionPool;
use ergo_network::delivery_tracker::DeliveryTracker;
use ergo_network::mempool::ErgoMemPool;
use ergo_network::message_handler;
use ergo_network::peer_conn::PeerConnection;
use ergo_network::peer_discovery::PeerDiscovery;
use ergo_network::penalty_manager::{PenaltyAction, PenaltyManager};
use ergo_network::sync_manager::{SyncAction, SyncManager};
use ergo_network::sync_metrics::SyncMetrics;
use ergo_network::sync_tracker::SyncTracker;
use ergo_settings::settings::ErgoSettings;
use ergo_storage::history_db::{header_score_key, HistoryDb};
use ergo_wire::handshake::ConnectionDirection;
use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};
use ergo_wire::header_ser::serialize_header;
use ergo_wire::message::MessageCode;
use ergo_wire::peer_feature::PeerFeature;

use crate::mining::{CandidateGenerator, MiningSolution};

/// A block submission from the API: individual modifier sections to be processed
/// through the existing modifier pipeline (same as receiving from peers).
///
/// Each entry is `(type_id, modifier_id, serialized_bytes)`.
pub struct BlockSubmission {
    pub modifiers: Vec<(u8, ergo_types::modifier_id::ModifierId, Vec<u8>)>,
}

/// A request from the API to generate a batch AVL+ proof for a set of box IDs.
///
/// The response is sent back via the `response_tx` oneshot channel.
#[allow(dead_code)]
pub struct UtxoProofRequest {
    pub box_ids: Vec<[u8; 32]>,
    pub response_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
}

/// Type alias for the optional wallet handle, gated on the `wallet` feature.
#[cfg(feature = "wallet")]
pub type WalletArc = Option<Arc<tokio::sync::RwLock<ergo_wallet::wallet_manager::WalletManager>>>;
#[cfg(not(feature = "wallet"))]
pub type WalletArc = Option<Arc<tokio::sync::RwLock<()>>>;

/// Peer info for API responses.
#[derive(Debug, Clone)]
pub struct ConnectedPeerInfo {
    pub address: String,
    pub name: String,
    /// User-configured node name from the handshake PeerSpec.
    pub node_name: String,
    /// Epoch milliseconds when the handshake completed.
    pub last_handshake: u64,
    /// Epoch milliseconds of the last received message from this peer.
    pub last_message: Option<u64>,
    /// "Incoming" or "Outgoing", or None if unknown.
    pub connection_type: Option<String>,
    /// Protocol version string, e.g. "6.0.1".
    pub version: Option<String>,
    /// "utxo" or "digest" from peer's ModeFeature.
    pub state_type: Option<String>,
    /// Whether the peer verifies transactions.
    pub verifying_transactions: Option<bool>,
    /// Number of blocks the peer keeps (-1 = all).
    pub blocks_to_keep: Option<i32>,
    /// Peer ID for cross-referencing with SyncTracker.
    pub peer_id: u64,
}

/// An inbound peer that has completed the handshake, ready to be added to the pool.
pub struct InboundPeer {
    pub conn: PeerConnection,
    pub addr: SocketAddr,
    pub handshake: Handshake,
}

/// A completed outbound connection from a background discovery task.
struct PendingOutboundConn {
    conn: PeerConnection,
    addr: SocketAddr,
    handshake: Handshake,
}

/// Shared state accessible from the event loop and HTTP API.
pub struct SharedState {
    pub headers_height: u64,
    pub full_height: u64,
    pub peer_count: usize,
    pub sync_state: String,
    pub state_root: Vec<u8>,
    pub best_header_id: Option<[u8; 32]>,
    pub best_full_block_id: Option<[u8; 32]>,
    pub connected_peers: Vec<ConnectedPeerInfo>,
    pub known_peers: Vec<String>,
    pub banned_peers: Vec<u64>,
    pub sync_tracker_snapshot: Option<serde_json::Value>,
    pub delivery_tracker_snapshot: Option<serde_json::Value>,
    pub last_message_time: Option<u64>,
    pub start_time: u64,
    pub max_peer_height: u64,
    /// Decoded difficulty as a JSON number (arbitrary precision).
    pub difficulty: serde_json::Value,
    /// Cumulative headers chain score as a JSON number.
    pub headers_score: serde_json::Value,
    /// Cumulative full-blocks chain score as a JSON number.
    pub full_blocks_score: serde_json::Value,
    /// Live on-chain parameters from the voting system.
    pub parameters: serde_json::Value,
    /// Parent of the best full block header.
    pub previous_full_header_id: Option<[u8; 32]>,
    /// ID of the last block whose state was applied.
    pub state_version: Option<[u8; 32]>,
    /// Whether mining is enabled (candidate generator is active).
    pub is_mining: bool,
    /// Unix-epoch milliseconds of the last mempool mutation.
    pub last_mempool_update_time: u64,
    /// Whether fast header sync via REST API is currently active.
    pub fast_sync_active: bool,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            headers_height: 0,
            full_height: 0,
            peer_count: 0,
            sync_state: "idle".to_string(),
            state_root: vec![0u8; 33],
            best_header_id: None,
            best_full_block_id: None,
            connected_peers: Vec::new(),
            known_peers: Vec::new(),
            banned_peers: Vec::new(),
            sync_tracker_snapshot: None,
            delivery_tracker_snapshot: None,
            last_message_time: None,
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            max_peer_height: 0,
            difficulty: serde_json::json!(0),
            headers_score: serde_json::json!(0),
            full_blocks_score: serde_json::json!(0),
            parameters: serde_json::json!({}),
            previous_full_header_id: None,
            state_version: None,
            is_mining: false,
            last_mempool_update_time: 0,
            fast_sync_active: false,
        }
    }
}

/// Run the main event loop.
///
/// The event loop is now a thin message router: block sections are forwarded to
/// the processor thread via `cmd_tx`, and responses come back via `evt_rx`.
/// Sync protocol reads use the read-only `sync_history`. The mempool is shared
/// via `Arc<RwLock>`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    settings: ErgoSettings,
    cmd_tx: std::sync::mpsc::SyncSender<ProcessorCommand>,
    evt_rx: &mut tokio::sync::mpsc::Receiver<ProcessorEvent>,
    sync_history: &HistoryDb,
    mempool: Arc<std::sync::RwLock<ErgoMemPool>>,
    is_digest_mode: bool,
    shared: Arc<RwLock<SharedState>>,
    tx_submit_rx: &mut tokio::sync::mpsc::Receiver<crate::api::TxSubmission>,
    peer_connect_rx: &mut tokio::sync::mpsc::Receiver<SocketAddr>,
    inbound_rx: &mut tokio::sync::mpsc::Receiver<InboundPeer>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    indexer_tx: Option<tokio::sync::mpsc::Sender<ergo_indexer::task::IndexerEvent>>,
    mining_solution_rx: &mut tokio::sync::mpsc::Receiver<MiningSolution>,
    block_submit_rx: &mut tokio::sync::mpsc::Receiver<BlockSubmission>,
    utxo_proof_rx: &mut tokio::sync::mpsc::Receiver<UtxoProofRequest>,
    candidate_gen: Option<Arc<std::sync::RwLock<CandidateGenerator>>>,
    snapshots_db: Option<Arc<crate::snapshots::SnapshotsDb>>,
    wallet: WalletArc,
    session_id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Suppress unused-variable warning when the `wallet` feature is disabled.
    let _ = &wallet;

    let magic: [u8; 4] = settings
        .network
        .magic_bytes
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([1, 0, 2, 4]);

    let our_handshake = build_handshake(&settings, magic, session_id);
    let our_handshake_for_discovery = our_handshake.clone();

    let mut pool = ConnectionPool::with_handshake_timeout(
        magic,
        our_handshake,
        settings.network.handshake_timeout_secs,
    );
    pool.set_session_id(session_id);
    let mut tracker = DeliveryTracker::new(
        settings.network.delivery_timeout_secs,
        settings.network.max_delivery_checks,
    );
    let utxo_mode = settings.ergo.node.state_type == "utxo";
    let mut sync_mgr =
        SyncManager::with_utxo_mode(settings.network.desired_inv_objects as usize, 64, utxo_mode);
    let mut discovery = PeerDiscovery::new(parse_seed_peers(&settings.network.known_peers), 1000);
    let mut penalties = PenaltyManager::new();
    let mut sync_tracker = SyncTracker::new();
    let mut sync_metrics = SyncMetrics::new(10);

    let data_dir = std::path::Path::new(&settings.ergo.directory);
    let mut peer_db = ergo_network::peer_db::PeerDb::new(data_dir);

    if !peer_db.is_empty() {
        for addr in peer_db.peers() {
            discovery.add_peer(*addr);
        }
        tracing::info!(saved_peers = peer_db.len(), "loaded peers from disk");
    }

    let mut last_msg_time: Option<u64> = None;

    // Connect to a small batch of peers at startup; the rest will be
    // connected via the periodic discovery_tick to avoid blocking the
    // event loop when peer_db contains many saved addresses.
    const MAX_STARTUP_CONNECTIONS: usize = 10;
    let startup_peers = discovery.peers_to_connect(&HashSet::new());
    for addr in startup_peers.into_iter().take(MAX_STARTUP_CONNECTIONS) {
        match pool.connect(addr).await {
            Ok(id) => tracing::info!(peer_id = id, %addr, "connected to peer"),
            Err(e) => tracing::warn!(%addr, error = %e, "failed to connect"),
        }
    }

    let sync_interval = Duration::from_secs(settings.network.sync_interval_secs);
    let mut sync_tick = tokio::time::interval(sync_interval);
    sync_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut discovery_tick = tokio::time::interval(Duration::from_secs(60));
    discovery_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut status_tick = tokio::time::interval(Duration::from_secs(10));
    status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut check_modifiers_tick = tokio::time::interval(Duration::from_secs(10));
    check_modifiers_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut mempool_audit_tick = tokio::time::interval(Duration::from_secs(60));
    mempool_audit_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut dead_conn_tick = tokio::time::interval(Duration::from_secs(60));
    dead_conn_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut eviction_tick = tokio::time::interval(Duration::from_secs(3600));
    eviction_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut stale_header_tick = tokio::time::interval(Duration::from_secs(1));
    stale_header_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Channel for completed outbound connections from background discovery tasks.
    let (pending_conn_tx, mut pending_conn_rx) =
        tokio::sync::mpsc::channel::<PendingOutboundConn>(32);

    let mining_interval = Duration::from_secs(settings.ergo.node.candidate_generation_interval_s);
    let mut mining_tick = tokio::time::interval(mining_interval);
    mining_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Snapshot bootstrap: discovery coordinator + chunk storage.
    let mut snapshot_discovery: Option<crate::snapshot_bootstrap::SnapshotDiscovery> =
        if settings.ergo.node.utxo_bootstrap {
            Some(crate::snapshot_bootstrap::SnapshotDiscovery::new(
                settings.ergo.node.p2p_utxo_snapshots,
            ))
        } else {
            None
        };
    let mut downloaded_chunks: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let mut snapshot_tick = tokio::time::interval(Duration::from_secs(30));
    snapshot_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Chain health monitoring: detect globally stuck sync and reset the
    // DeliveryTracker so that stale pending requests don't block progress.
    let mut last_best_height: u32 = 0;
    let mut last_height_change = Instant::now();
    let mut chain_health_interval = tokio::time::interval(Duration::from_secs(60));
    chain_health_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Per-peer rate limiting for SyncInfo messages (100ms lock time).
    let mut last_sync_from: HashMap<u64, Instant> = HashMap::new();

    // Height of the last continuation header applied from SyncInfoV2 to
    // prevent re-applying the same header on subsequent sync messages.
    let mut last_sync_header_applied: Option<u32> = None;

    // REST API URLs extracted from peer handshake features (PeerFeature::RestApiUrl)
    // plus any configured seed peers. Used by the fast header sync subsystem.
    // Shared with the fast sync task so it can read URLs as peers connect/disconnect.
    let api_peer_urls: crate::fast_header_sync::ApiPeerUrls = {
        let mut map = HashMap::new();
        // Pre-populate with configured seed API peers (use high synthetic IDs
        // that won't collide with real P2P peer IDs).
        for (i, url) in settings.ergo.node.fast_sync_api_peers.iter().enumerate() {
            map.insert(u64::MAX - i as u64, url.clone());
        }
        if !map.is_empty() {
            tracing::info!(
                count = map.len(),
                "pre-populated fast sync API peers from config"
            );
        }
        std::sync::Arc::new(std::sync::RwLock::new(map))
    };

    // Shared atomic header height — updated by the event loop whenever a
    // StateUpdate arrives, read by the fast sync task to skip already-synced chunks.
    let shared_headers_height: crate::fast_header_sync::SharedHeadersHeight =
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

    // Shared flag indicating whether fast header sync is currently active.
    let shared_fast_sync_active: crate::fast_header_sync::SharedFastSyncActive =
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Shared atomic for fast block sync: tracks the highest applied full block height.
    let shared_full_height: crate::fast_block_sync::SharedFullHeight =
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

    // Transaction cost rate limiter: rejects txs when the cumulative
    // processing cost since the last block exceeds per-peer / global limits.
    let mut tx_cost_tracker = message_handler::TxCostTracker::new();

    // Whether the node is synced enough to accept and verify transactions.
    let mut is_synced_for_txs = false;

    // Cached state from the processor thread, updated via ProcessorEvent::StateUpdate.
    let mut cached_headers_height: u32 = 0;
    let mut cached_full_height: u32 = 0;
    let mut cached_best_header_id: Option<ergo_types::modifier_id::ModifierId> = None;
    let mut cached_best_full_id: Option<ergo_types::modifier_id::ModifierId> = None;
    let mut cached_state_root: Vec<u8> = vec![0u8; 33];
    let mut cached_state_version: Option<[u8; 32]> = None;
    // Cached sync headers from the processor (newest first), used to build
    // SyncInfoV2 without reading from the secondary DB.
    let mut cached_sync_headers: Vec<ergo_types::header::Header> = Vec::new();
    // Cached on-chain parameters from the processor's voting state machine.
    let mut cached_parameters: ergo_consensus::parameters::Parameters =
        ergo_consensus::parameters::Parameters::genesis();
    // Tracks the last peer that delivered headers, for targeted SyncInfo response.
    let mut last_header_peer: Option<u64> = None;

    // Backpressure: count of body sections sent to the processor that have not
    // yet been consumed by a BlockApplied event.  Each applied block consumes
    // 2 sections (BlockTransactions + Extension in UTXO mode).  When this
    // exceeds the threshold (96), aggressive block downloads are paused.
    let mut pending_body_sections: u32 = 0;

    // Propagate mining status into shared state once at startup.
    {
        let mut s = shared.write().await;
        s.is_mining = candidate_gen.is_some();
    }

    // On restart, check if headers are already synced so we can transition
    // to BlockDownload immediately instead of waiting for new headers.
    if let Ok(Some(best_hdr_id)) = sync_history.best_header_id() {
        if let Ok(Some(hdr)) = sync_history.load_header(&best_hdr_id) {
            if sync_mgr.check_headers_chain_synced(hdr.timestamp) {
                tracing::info!(
                    tip_height = hdr.height,
                    tip_timestamp = hdr.timestamp,
                    "headers already synced on startup — block download can begin immediately"
                );
            }
        }
    }

    // Re-populate blocks_to_download from the DB window above best_full_block.
    // On restart, on_headers_received never fires for stored headers so the
    // primary download queue is empty.  Scanning here makes blocks_remaining
    // meaningful and restores the primary download path immediately.
    {
        let full_height = sync_history.best_full_block_height().unwrap_or(0);
        sync_mgr.enqueue_startup_gap(sync_history, full_height, 2048);
        if sync_mgr.blocks_remaining() > 0 {
            tracing::info!(
                full_height,
                queued = sync_mgr.blocks_remaining(),
                "startup: queued missing block sections for download"
            );
        }
    }

    // Spawn the fast header sync task if enabled.
    // The task runs alongside normal P2P sync without interfering with it.
    // A 5-second delay allows peers to connect and advertise REST API URLs.
    if settings.ergo.node.fast_sync {
        let api_urls_shared = api_peer_urls.clone();
        let our_h = cached_headers_height;
        let chunk_sz = settings.ergo.node.fast_sync_chunk_size;
        let max_conc = settings.ergo.node.fast_sync_max_concurrent;
        let fs_cmd_tx = cmd_tx.clone();
        let fs_shutdown = shutdown_rx.clone();
        let fs_headers_height = shared_headers_height.clone();
        let fs_active = shared_fast_sync_active.clone();
        tokio::spawn(async move {
            // Brief delay to allow peers to connect and advertise REST API URLs.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            crate::fast_header_sync::run_fast_sync(
                api_urls_shared,
                our_h,
                chunk_sz,
                max_conc,
                fs_cmd_tx,
                fs_shutdown,
                fs_headers_height,
                fs_active,
            )
            .await;
        });
        tracing::info!("fast header sync task spawned (will start after 5s delay)");
    }

    // Spawn fast block sync task if enabled (reuses the same gate as fast header sync).
    if settings.ergo.node.fast_sync {
        let fbs_api_urls = api_peer_urls.clone();
        let fbs_history =
            ergo_storage::history_db::HistoryDb::from_shared(sync_history.shared_db());
        let fbs_cmd_tx = cmd_tx.clone();
        let fbs_shutdown = shutdown_rx.clone();
        let fbs_full_height = shared_full_height.clone();
        let fbs_headers_height = shared_headers_height.clone();
        let fbs_active = shared_fast_sync_active.clone();
        tokio::spawn(async move {
            crate::fast_block_sync::run_fast_block_sync(
                fbs_api_urls,
                fbs_history,
                fbs_cmd_tx,
                fbs_shutdown,
                fbs_full_height,
                fbs_headers_height,
                fbs_active,
            )
            .await;
        });
        tracing::info!("fast block sync task spawned (waits for header sync completion)");
    }

    let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());

    loop {
        tokio::select! {
            _ = sync_tick.tick() => {
                handle_sync_tick(
                    &mut pool,
                    &mut sync_mgr,
                    &mut tracker,
                    sync_history,
                    &settings,
                    &shared,
                    &mut discovery,
                    &mut peer_db,
                    &penalties,
                    &mut sync_tracker,
                    last_msg_time,
                    cached_headers_height,
                    cached_full_height,
                    cached_best_header_id,
                    cached_best_full_id,
                    &cached_state_root,
                    cached_state_version,
                    is_digest_mode,
                    &cached_sync_headers,
                    &cached_parameters,
                    pending_body_sections,
                ).await;
                update_fast_sync_flag(&shared, &shared_fast_sync_active).await;

                // Recompute whether the node is synced enough for tx acceptance.
                is_synced_for_txs = !is_digest_mode && {
                    cached_headers_height > 0 && cached_full_height == cached_headers_height
                };
            }

            msg = pool.recv() => {
                if let Some(incoming) = msg {
                    tracing::info!(peer_id = incoming.peer_id, code = incoming.message.code, body_len = incoming.message.body.len(), "recv msg");
                    last_msg_time = Some(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    );

                    // Handle snapshot protocol messages directly.
                    match incoming.message.code {
                        76 => {
                            // GetSnapshotsInfo: respond with available snapshots.
                            if let Some(ref sdb) = snapshots_db {
                                if let Ok(info) = sdb.get_info() {
                                    if !info.manifests.is_empty() {
                                        let payload = info.serialize_p2p();
                                        let _ = pool.send_to(incoming.peer_id, 77, payload);
                                    }
                                }
                            }
                            continue;
                        }
                        78 => {
                            // GetManifest: respond with manifest bytes.
                            if incoming.message.body.len() == 32 {
                                if let Some(ref sdb) = snapshots_db {
                                    let mut manifest_id = [0u8; 32];
                                    manifest_id.copy_from_slice(&incoming.message.body);
                                    if let Ok(Some(manifest_bytes)) = sdb.load_manifest(&manifest_id) {
                                        let _ = pool.send_to(incoming.peer_id, 79, manifest_bytes);
                                    }
                                }
                            }
                            continue;
                        }
                        80 => {
                            // GetUtxoSnapshotChunk: respond with chunk bytes.
                            if incoming.message.body.len() == 32 {
                                if let Some(ref sdb) = snapshots_db {
                                    let mut chunk_id = [0u8; 32];
                                    chunk_id.copy_from_slice(&incoming.message.body);
                                    if let Ok(Some(chunk_bytes)) = sdb.load_chunk(&chunk_id) {
                                        let _ = pool.send_to(incoming.peer_id, 81, chunk_bytes);
                                    }
                                }
                            }
                            continue;
                        }
                        77 => {
                            // SnapshotsInfo response from a peer.
                            if let Some(ref mut disc) = snapshot_discovery {
                                if let Ok(info) = crate::snapshots::SnapshotsInfo::deserialize_p2p(&incoming.message.body) {
                                    let peer_id = incoming.peer_id;
                                    disc.record_info(peer_id, &info, &|height| {
                                        let ids = sync_history.header_ids_at_height(height).ok()?;
                                        let id = ids.first()?;
                                        let header = sync_history.load_header(id).ok()??;
                                        Some(header.state_root.0)
                                    });
                                    tracing::debug!(
                                        peer_id,
                                        manifests = info.manifests.len(),
                                        "received snapshots info"
                                    );
                                }
                            }
                            continue;
                        }
                        79 => {
                            // Manifest response.
                            if let Some(ref mut disc) = snapshot_discovery {
                                if let Ok(manifest) = crate::snapshots::SnapshotManifest::deserialize(&incoming.message.body) {
                                    let manifest_id = manifest.manifest_id();
                                    tracing::info!(
                                        height = manifest.height,
                                        chunks = manifest.chunk_ids.len(),
                                        "received snapshot manifest"
                                    );
                                    if let Some((_, _, peers)) = disc.ready_to_download() {
                                        disc.start_download(&manifest, manifest_id, peers);
                                        request_next_chunks(disc, &pool);
                                    }
                                }
                            }
                            continue;
                        }
                        81 => {
                            // UtxoSnapshotChunk response.
                            if let Some(ref mut disc) = snapshot_discovery {
                                let chunk_data = incoming.message.body.clone();
                                let chunk_id = crate::snapshots::blake2b256(&chunk_data);
                                downloaded_chunks.insert(chunk_id, chunk_data);
                                let complete = disc.mark_chunk_downloaded(&chunk_id);

                                if let Some(ref plan) = disc.plan {
                                    tracing::info!(
                                        downloaded = plan.downloaded_count(),
                                        total = plan.total_chunks(),
                                        "snapshot chunk received"
                                    );
                                }

                                if complete {
                                    // Snapshot bootstrap applies via the processor thread.
                                    // For now, log that we need manual intervention.
                                    tracing::warn!(
                                        "snapshot download complete; snapshot application via processor not yet implemented"
                                    );
                                    downloaded_chunks.clear();
                                    snapshot_discovery = None;
                                } else {
                                    request_next_chunks(disc, &pool);
                                }
                            }
                            continue;
                        }
                        _ => {} // Fall through to normal message handling.
                    }

                    // --- Modifier messages (code 33) are handled directly ---
                    if incoming.message.code == 33 {
                        let mods = match ergo_wire::inv::ModifiersData::parse(&incoming.message.body) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        let type_id = mods.type_id as u8;

                        // Transaction modifiers stay in the event loop (mempool is shared).
                        if type_id == 2 {
                            if is_synced_for_txs {
                                let result = message_handler::handle_tx_modifiers_shared(
                                    incoming.peer_id,
                                    &mods.modifiers,
                                    &mempool,
                                    &mut tracker,
                                    &mut tx_cost_tracker,
                                );
                                execute_actions(&mut pool, &result.actions, &mut discovery, &mut peer_db, &mut sync_tracker);
                            }
                            continue;
                        }

                        // Headers: parallel PoW validation in event loop, then forward to processor.
                        if type_id == 101 {
                            let (validated_headers, header_penalties, _invalid_ids) =
                                message_handler::validate_headers_parallel(
                                    incoming.peer_id,
                                    &mods,
                                    &mut tracker,
                                );

                            // Apply penalties from header validation.
                            for (penalty_type, peer_id) in &header_penalties {
                                apply_penalty(&mut pool, &mut penalties, *peer_id, *penalty_type);
                            }

                            // Log heights of validated headers.
                            {
                                let mut heights: Vec<u32> = validated_headers.iter().map(|(_, h, _)| h.height).collect();
                                heights.sort_unstable();
                                let min_h = heights.first().copied().unwrap_or(0);
                                let max_h = heights.last().copied().unwrap_or(0);
                                tracing::trace!(
                                    total = mods.modifiers.len(),
                                    validated = validated_headers.len(),
                                    penalties = header_penalties.len(),
                                    min_h, max_h,
                                    "parallel PoW result"
                                );
                            }

                            // Sort by height so the processor receives them in
                            // chain order, minimizing cache insertions for
                            // out-of-order delivery (matches Scala's sortBy).
                            let mut validated_headers = validated_headers;
                            validated_headers.sort_by_key(|(_, h, _)| h.height);

                            // Forward validated headers to processor thread.
                            last_header_peer = Some(incoming.peer_id);
                            let mut sent = 0usize;
                            let mut dropped = 0usize;
                            let mut disconnected = false;
                            for (mid, header, data) in validated_headers {
                                match cmd_tx.try_send(ProcessorCommand::StorePrevalidatedHeader {
                                    modifier_id: mid,
                                    header: Box::new(header),
                                    raw_data: data,
                                    peer_hint: Some(incoming.peer_id),
                                }) {
                                    Ok(()) => {
                                        // Only mark as received AFTER the processor accepted it.
                                        sync_mgr.on_section_received(101, &mid, &mut tracker);
                                        sent += 1;
                                    }
                                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                                        disconnected = true;
                                        dropped += 1;
                                        break;
                                    }
                                    Err(std::sync::mpsc::TrySendError::Full(_)) => {
                                        // Header stays in Requested state — stale detection
                                        // or timeout will re-request it from another peer.
                                        dropped += 1;
                                    }
                                }
                            }
                            let cache_sent = cmd_tx.try_send(ProcessorCommand::ApplyFromCache).is_ok();
                            if dropped > 0 {
                                tracing::warn!(sent, dropped, cache_sent, disconnected, "processor channel backpressure — headers will be re-requested");
                            } else {
                                tracing::trace!(sent, dropped, cache_sent, "forwarded to processor");
                            }
                            if disconnected {
                                tracing::error!("processor thread died, shutting down");
                                break;
                            }
                            continue;
                        }

                        // Body sections: skip invalid/received, forward everything else.
                        let mut body_disconnected = false;
                        for (id, data) in &mods.modifiers {
                            let mod_status = tracker.status(type_id, id);
                            if mod_status == ergo_network::delivery_tracker::ModifierStatus::Invalid {
                                penalties.add_penalty(incoming.peer_id, ergo_network::penalty_manager::PenaltyType::SpamMessage);
                                continue;
                            }
                            if mod_status == ergo_network::delivery_tracker::ModifierStatus::Received {
                                continue;
                            }
                            match cmd_tx.try_send(ProcessorCommand::StoreModifier {
                                type_id,
                                modifier_id: *id,
                                data: data.clone(),
                                peer_hint: Some(incoming.peer_id),
                            }) {
                                Ok(()) => {
                                    // Only mark as received AFTER the processor accepted it.
                                    sync_mgr.on_section_received(type_id, id, &mut tracker);
                                    pending_body_sections = pending_body_sections.saturating_add(1);
                                }
                                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                                    body_disconnected = true;
                                    break;
                                }
                                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                                    tracing::warn!(type_id, modifier_id = hex::encode(id.0), "processor channel full — body section will be re-requested");
                                }
                            }
                        }
                        if body_disconnected {
                            tracing::error!("processor thread died, shutting down");
                            break;
                        }
                        continue;
                    }

                    // --- All other message codes (SyncInfo, Inv, GetPeers, Peers, RequestModifier) ---
                    let connected_info = pool.connected_peers();
                    let peer_addrs: Vec<std::net::SocketAddr> = connected_info
                        .iter()
                        .map(|p| p.addr)
                        .collect();
                    let connected_peer_ids: Vec<u64> = connected_info
                        .iter()
                        .map(|p| p.id)
                        .collect();
                    // During HeaderSync, force single-peer header requests.
                    // Multi-peer partitioning is slower because headers must be
                    // applied sequentially — only one peer's chunk extends the
                    // chain, the rest go to cache and become redundant.
                    let force_single_peer = sync_mgr.state()
                        == ergo_network::sync_manager::SyncState::HeaderSync;
                    let result = message_handler::handle_message_without_modifiers(
                        incoming.peer_id,
                        &incoming.message,
                        sync_history,
                        &mempool,
                        &mut sync_mgr,
                        &mut tracker,
                        &peer_addrs,
                        &mut sync_tracker,
                        &mut last_sync_from,
                        is_synced_for_txs,
                        &mut last_sync_header_applied,
                        &mut tx_cost_tracker,
                        settings.network.sync_info_max_headers,
                        &connected_peer_ids,
                        &mut sync_metrics,
                        force_single_peer,
                    );

                    // Handle continuation headers: forward to processor thread.
                    apply_continuation_headers(
                        &result.actions,
                        &cmd_tx,
                        &mut sync_mgr,
                        &mut tracker,
                    );

                    execute_actions(&mut pool, &result.actions, &mut discovery, &mut peer_db, &mut sync_tracker);

                    // Process any penalties reported by the message handler.
                    for (penalty_type, peer_id) in &result.penalties {
                        apply_penalty(&mut pool, &mut penalties, *peer_id, *penalty_type);
                    }
                } else {
                    tracing::warn!("all peers disconnected, attempting reconnection");
                    let mut backoff = Duration::from_secs(1);
                    let max_backoff = Duration::from_secs(60);

                    loop {
                        // Try seed peers and known peers.
                        let connected: std::collections::HashSet<_> = pool
                            .connected_peers()
                            .iter()
                            .map(|p| p.addr)
                            .collect();
                        for addr in discovery.peers_to_connect(&connected).into_iter().take(5) {
                            if penalties.is_ip_banned(&addr.ip()) {
                                continue;
                            }
                            match pool.connect(addr).await {
                                Ok(id) => tracing::info!(peer_id = id, %addr, "reconnected"),
                                Err(e) => tracing::debug!(%addr, error = %e, "reconnect failed"),
                            }
                        }

                        if pool.peer_count() > 0 {
                            tracing::info!(peers = pool.peer_count(), "reconnected to peers");
                            break;
                        }

                        tracing::warn!(
                            backoff_secs = backoff.as_secs(),
                            "no peers available, waiting before retry"
                        );

                        // Wait with backoff, but still honor Ctrl-C and API shutdown.
                        tokio::select! {
                            _ = tokio::time::sleep(backoff) => {}
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() {
                                    tracing::info!("API-triggered shutdown during reconnection...");
                                    peer_db.flush();
                                    tracing::info!(peers = pool.peer_count(), "disconnecting peers");
                                    for p in pool.connected_peers() {
                                        pool.disconnect(p.id);
                                    }
                                    pool.cleanup_disconnected();
                                    tracing::info!("shutdown complete");
                                    let _ = cmd_tx.try_send(ProcessorCommand::Shutdown);
                                    return Ok(());
                                }
                            }
                            _ = tokio::signal::ctrl_c() => {
                                tracing::info!("shutting down during reconnection...");
                                peer_db.flush();
                                tracing::info!(peers = pool.peer_count(), "disconnecting peers");
                                for p in pool.connected_peers() {
                                    pool.disconnect(p.id);
                                }
                                pool.cleanup_disconnected();
                                tracing::info!("shutdown complete");
                                let _ = cmd_tx.try_send(ProcessorCommand::Shutdown);
                                return Ok(());
                            }
                        }

                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
            }

            // ProcessorEvent handling: responses from the block processor thread.
            Some(evt) = evt_rx.recv() => {
                match evt {
                    ProcessorEvent::HeadersApplied { new_header_ids, to_download } => {
                        if !new_header_ids.is_empty() {
                            tracing::info!(new = new_header_ids.len(), headers_height = cached_headers_height, "received headers");
                            sync_metrics.add_headers_applied(new_header_ids.len() as u64);

                            // No-op: Arc<NodeDb>-backed HistoryDb sees writes immediately.
                            let _ = sync_history.try_catch_up_with_primary();
                            sync_mgr.on_headers_received(&new_header_ids, sync_history);

                            // Check if the header chain tip is recent enough to
                            // trigger block body downloads (Scala's isHeadersChainSynced).
                            if let Some(newest) = cached_sync_headers.first() {
                                if sync_mgr.check_headers_chain_synced(newest.timestamp) {
                                    tracing::info!(
                                        tip_timestamp = newest.timestamp,
                                        tip_height = newest.height,
                                        "headers chain synced — block body download will begin"
                                    );
                                }
                            }

                            // Send targeted SyncInfoV2 to the delivering peer for a
                            // tight request/response loop.  No broadcast here — that
                            // is handled by the periodic sync_tick.
                            if let Some(peer) = last_header_peer {
                                if !cached_sync_headers.is_empty() {
                                    let v2 = ergo_wire::sync_info::ErgoSyncInfoV2 {
                                        last_headers: cached_sync_headers.clone(),
                                    };
                                    let sync_tip = v2.last_headers.first().map(|h| h.height).unwrap_or(0);
                                    let sync_bytes = v2.serialize();
                                    tracing::debug!(sync_tip, peer, "targeted SyncInfoV2 to delivering peer");
                                    let _ = pool.send_to(peer, MessageCode::SyncInfo as u8, sync_bytes);
                                }
                            }
                        }
                        if !to_download.is_empty() {
                            sync_mgr.enqueue_block_downloads(to_download);
                        }
                    }
                    ProcessorEvent::BlockApplied { header_id, height } => {
                        pending_body_sections = pending_body_sections.saturating_sub(2);
                        shared_full_height.store(height, std::sync::atomic::Ordering::Relaxed);
                        tracing::info!(height, pending_body_sections, header_id = hex::encode(header_id.0), "block applied");
                        // Notify the indexer.
                        if let Some(ref idx_tx) = indexer_tx {
                            let _ = idx_tx.try_send(ergo_indexer::task::IndexerEvent::BlockApplied {
                                header_id: header_id.0,
                                height,
                            });
                        }
                        // Reset tx cost tracker.
                        tx_cost_tracker.reset();
                        // Update mempool timestamp.
                        if let Ok(mut s) = shared.try_write() {
                            s.last_mempool_update_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;
                        }

                        // Wallet rollback/scan (requires history data from sync_history).
                        #[cfg(feature = "wallet")]
                        {
                            // Wallet scanning is deferred; data would need to come from processor.
                            let _ = &wallet;
                        }

                        // Broadcast Inv for recent blocks.
                        const BLOCK_BROADCAST_RECENCY_MS: u64 = 7_200_000; // 2 hours
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;

                        // Check if the block is recent enough to broadcast.
                        if let Ok(Some(hdr)) = sync_history.load_header(&header_id) {
                            if now_ms.saturating_sub(hdr.timestamp) < BLOCK_BROADCAST_RECENCY_MS {
                                let header_inv = ergo_wire::inv::InvData {
                                    type_id: 101i8,
                                    ids: vec![header_id],
                                };
                                pool.broadcast(MessageCode::Inv as u8, &header_inv.serialize());
                                for section_type_id in [102i8, 104i8, 108i8] {
                                    let section_inv = ergo_wire::inv::InvData {
                                        type_id: section_type_id,
                                        ids: vec![header_id],
                                    };
                                    pool.broadcast(MessageCode::Inv as u8, &section_inv.serialize());
                                }
                            }
                        }
                    }
                    ProcessorEvent::ValidationFailed { modifier_id: _, peer_hint, error } => {
                        if error.starts_with("FATAL:") {
                            tracing::error!(%error, "processor thread died, shutting down");
                            break;
                        }
                        if let Some(pid) = peer_hint {
                            apply_penalty(&mut pool, &mut penalties, pid, ergo_network::penalty_manager::PenaltyType::InvalidBlock);
                        }
                    }
                    ProcessorEvent::StateUpdate {
                        headers_height, full_height,
                        best_header_id, best_full_id,
                        state_root, applied_blocks: _,
                        rollback_height: _,
                        sync_headers,
                        parameters,
                    } => {
                        cached_headers_height = headers_height;
                        shared_headers_height.store(headers_height, std::sync::atomic::Ordering::Relaxed);
                        cached_full_height = full_height;
                        shared_full_height.store(full_height, std::sync::atomic::Ordering::Relaxed);
                        cached_best_header_id = best_header_id;
                        cached_best_full_id = best_full_id;
                        cached_state_root = state_root;
                        // Derive state_version from best_full_id
                        cached_state_version = best_full_id.map(|id| id.0);
                        cached_sync_headers = sync_headers;
                        cached_parameters = parameters;
                    }
                    ProcessorEvent::ModifierCached { .. } => {}
                }
            }

            // Completed outbound connections from background discovery tasks.
            Some(pending) = pending_conn_rx.recv() => {
                let id = pool.add_outbound(pending.conn, pending.addr, &pending.handshake);
                tracing::info!(peer_id = id, addr = %pending.addr, "connected (background)");
                // Extract REST API URL from handshake features for fast header sync.
                for feature in &pending.handshake.peer_spec.features {
                    if let PeerFeature::RestApiUrl(url) = feature {
                        tracing::debug!(peer_id = id, url, "peer advertises REST API");
                        api_peer_urls.write().unwrap().insert(id, url.clone());
                        break;
                    }
                }
            }

            _ = discovery_tick.tick() => {
                handle_discovery_tick(&mut pool, &mut discovery, &settings, &penalties, &pending_conn_tx, magic, &our_handshake_for_discovery, session_id);
            }

            Some(submission) = tx_submit_rx.recv() => {
                let inv = ergo_wire::inv::InvData {
                    type_id: 2i8,
                    ids: vec![ergo_types::modifier_id::ModifierId(submission.tx_id)],
                };
                pool.broadcast(MessageCode::Inv as u8, &inv.serialize());
                let _ = submission.response.send(Ok(()));
                // Record mempool mutation timestamp.
                if let Ok(mut s) = shared.try_write() {
                    s.last_mempool_update_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                }
            }

            // Block submission from the API (POST /blocks).
            // Forward each modifier to the processor thread.
            Some(block_sub) = block_submit_rx.recv() => {
                for (type_id, modifier_id, data) in block_sub.modifiers {
                    let _ = cmd_tx.try_send(ProcessorCommand::StoreModifier {
                        type_id,
                        modifier_id,
                        data,
                        peer_hint: None,
                    });
                }
                let _ = cmd_tx.try_send(ProcessorCommand::ApplyFromCache);
            }

            // UTXO batch proof request from the API.
            // UTXO state lives on the processor thread now; return an error.
            Some(req) = utxo_proof_rx.recv() => {
                let result = if is_digest_mode {
                    Err("UTXO proofs not available in digest mode".to_string())
                } else {
                    Err("UTXO proofs are not available while the state is on the processor thread".to_string())
                };
                let _ = req.response_tx.send(result);
            }

            _ = status_tick.tick() => {
                penalties.cleanup_expired_bans();
                peer_db.maybe_flush();
                sync_metrics.maybe_emit_rollup();
                let state = shared.read().await;
                tracing::info!(
                    sync_state = ?sync_mgr.state(),
                    peers = pool.peer_count(),
                    blocks_remaining = sync_mgr.blocks_remaining(),
                    headers_height = %state.headers_height,
                    pending_body_sections,
                    "sync status",
                );
            }

            _ = check_modifiers_tick.tick() => {
                // Gap-fill: find blocks with headers but missing body sections
                // and re-request them.  This must NOT be gated on backpressure
                // because it is the recovery mechanism for incomplete blocks —
                // blocking it under backpressure would deadlock the pipeline.
                if sync_mgr.is_headers_chain_synced() {
                    handle_check_modifiers(&mut pool, sync_history, &mut tracker, &sync_tracker);
                }
            }

            // Fast stale-header reassignment: every 1 s, check for header
            // requests that have been pending for >2 s and re-request them
            // from an alternative peer.  This runs independently of sync_tick
            // so that recovery doesn't wait for the next 5 s SyncInfoV2 cycle.
            _ = stale_header_tick.tick() => {
                let stale = tracker.collect_stale_headers(Duration::from_secs(2));
                if stale.is_empty() {
                    continue;
                }
                let cands = sync_tracker.peers_for_downloading_blocks();
                if cands.is_empty() {
                    continue;
                }

                let mut reassigned = 0u32;
                let mut deferred = 0u32;
                let mut per_peer_batch: HashMap<u64, Vec<ergo_types::modifier_id::ModifierId>> = HashMap::new();

                for (id, stale_peer) in &stale {
                    // Find an alternative peer that is not the stale peer and under the cap
                    if let Some(&alt) = cands.iter().find(|&&p| {
                        p != *stale_peer && tracker.outstanding_header_count(p) < 800
                    }) {
                        tracker.reassign(101, id, alt);
                        per_peer_batch.entry(alt).or_default().push(*id);
                        reassigned += 1;
                        sync_metrics.record_reassignment(*stale_peer, alt, 0);
                    } else {
                        deferred += 1;
                    }
                }

                // Send batched RequestModifiers per target peer
                for (alt, ids) in &per_peer_batch {
                    let inv = ergo_wire::inv::InvData {
                        type_id: 101,
                        ids: ids.clone(),
                    };
                    let _ = pool.send_to(*alt, MessageCode::RequestModifier as u8, inv.serialize());
                }

                if reassigned > 0 || deferred > 0 {
                    tracing::info!(
                        stale = stale.len(),
                        reassigned,
                        deferred,
                        target_peers = per_peer_batch.len(),
                        "stale header tick"
                    );
                }
            }

            _ = mempool_audit_tick.tick() => {
                // Step 1: Evict stale transactions.
                let max_age = Duration::from_secs(settings.ergo.node.mempool_cleanup_duration_secs);
                let evicted = {
                    let mut mp = mempool.write().unwrap();
                    mp.evict_stale(max_age)
                };
                if !evicted.is_empty() {
                    tracing::info!(evicted = evicted.len(), "mempool audit: evicted stale transactions");
                    if let Ok(mut s) = shared.try_write() {
                        s.last_mempool_update_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                    }
                }
                // Step 2: UTXO audit skipped (UTXO state is on processor thread).
                // Step 3: Rebroadcast surviving transactions.
                let rebroadcast_count = settings.ergo.node.rebroadcast_count as usize;
                let to_rebroadcast: Vec<ergo_types::modifier_id::ModifierId> = {
                    let mp = mempool.read().unwrap();
                    let all_ids = mp.get_all_tx_ids();
                    use rand::seq::SliceRandom;
                    let mut rng = rand::thread_rng();
                    let count = all_ids.len().min(rebroadcast_count);
                    all_ids.choose_multiple(&mut rng, count)
                        .map(|id| ergo_types::modifier_id::ModifierId(id.0))
                        .collect()
                };
                if !to_rebroadcast.is_empty() {
                    let inv = ergo_wire::inv::InvData {
                        type_id: 2i8,
                        ids: to_rebroadcast.clone(),
                    };
                    pool.broadcast(MessageCode::Inv as u8, &inv.serialize());
                    tracing::debug!(count = to_rebroadcast.len(), "mempool audit: rebroadcast transactions");
                }
            }

            _ = dead_conn_tick.tick() => {
                let deadline_ms = settings.network.inactive_connection_deadline_secs * 1000;
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let mut to_disconnect = Vec::new();
                for p in pool.connected_peers() {
                    if now_ms.saturating_sub(p.last_activity) > deadline_ms {
                        to_disconnect.push(p.id);
                    }
                }
                for id in &to_disconnect {
                    tracing::info!(peer_id = *id, "disconnecting inactive peer");
                    pool.disconnect(*id);
                }
                if !to_disconnect.is_empty() {
                    pool.cleanup_disconnected();
                }
                // Remove API URLs for disconnected P2P peers, but keep
                // configured seed peers (which use synthetic IDs >= u64::MAX - 1000).
                let connected_ids: HashSet<u64> = pool.connected_peers().iter().map(|p| p.id).collect();
                const SEED_ID_THRESHOLD: u64 = u64::MAX - 1000;
                api_peer_urls.write().unwrap().retain(|id, _| {
                    *id >= SEED_ID_THRESHOLD || connected_ids.contains(id)
                });
            }

            _ = eviction_tick.tick() => {
                const EVICTION_THRESHOLD: usize = 5;
                if pool.peer_count() >= EVICTION_THRESHOLD {
                    use rand::Rng;
                    let peers = pool.connected_peers();
                    let idx = rand::thread_rng().gen_range(0..peers.len());
                    let victim = peers[idx].id;
                    tracing::info!(peer_id = victim, "random anti-eclipse eviction");
                    pool.disconnect(victim);
                    pool.cleanup_disconnected();
                }
            }

            // Chain health check: if full block height has not advanced
            // in 5 minutes, reset the delivery tracker to unstick sync.
            _ = chain_health_interval.tick() => {
                let current_best = cached_full_height;
                if current_best > last_best_height {
                    last_best_height = current_best;
                    last_height_change = Instant::now();
                } else if current_best > 0
                    && last_height_change.elapsed() > Duration::from_secs(300)
                {
                    tracing::warn!(
                        height = current_best,
                        stuck_secs = last_height_change.elapsed().as_secs(),
                        "chain appears stuck, resetting delivery tracker"
                    );
                    tracker.reset();
                    last_height_change = Instant::now();
                }
            }

            // Snapshot bootstrap discovery tick.
            _ = snapshot_tick.tick(), if snapshot_discovery.is_some() => {
                if let Some(ref mut disc) = snapshot_discovery {
                    if disc.plan.is_none() {
                        if let Some((manifest_id, _, _)) = disc.ready_to_download() {
                            if let Some(p) = pool.connected_peers().first() {
                                tracing::info!("requesting snapshot manifest");
                                let _ = pool.send_to(p.id, 78, manifest_id.to_vec());
                            }
                        } else {
                            pool.broadcast(76, &[]);
                            tracing::debug!("sent GetSnapshotsInfo to all peers");
                        }
                    }
                }
            }

            // Mining candidate refresh tick.
            _ = mining_tick.tick(), if candidate_gen.is_some() => {
                if let Some(ref gen_arc) = candidate_gen {
                    // Mining uses sync_history (read-only) for candidate generation.
                    // UTXO state is not available here; pass None for utxo_ref.
                    let mut gen = gen_arc.write().unwrap();
                    let reward_delay = settings.ergo.chain.monetary.miner_reward_delay;
                    match gen.generate_candidate(
                        sync_history,
                        &mempool,
                        &ergo_consensus::parameters::Parameters::genesis(),
                        None, // UTXO not available on event loop
                        Some(reward_delay),
                    ) {
                        Ok(work) => {
                            tracing::debug!(height = work.h, "generated new mining candidate");
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "candidate generation failed");
                        }
                    }
                }
            }

            // Mining solution received from API.
            Some(solution) = mining_solution_rx.recv() => {
                if let Some(ref gen_arc) = candidate_gen {
                    let try_result = {
                        let gen = gen_arc.read().unwrap();
                        gen.try_solution(&solution)
                    };
                    match try_result {
                        Ok(header) => {
                            let serialized = serialize_header(&header);
                            let header_id = ergo_storage::continuation::compute_header_id(&serialized);
                            tracing::info!(
                                header_id = hex::encode(header_id.0),
                                height = header.height,
                                "mined block!"
                            );

                            // Broadcast the new block header to peers.
                            let inv = ergo_wire::inv::InvData {
                                type_id: 101i8,
                                ids: vec![header_id],
                            };
                            pool.broadcast(MessageCode::Inv as u8, &inv.serialize());
                        }
                        Err(e) => {
                            tracing::warn!(?e, "mining solution rejected");
                        }
                    }
                }
            }

            Some(inbound) = inbound_rx.recv() => {
                if penalties.is_ip_banned(&inbound.addr.ip()) {
                    tracing::debug!(addr = %inbound.addr, "rejecting inbound from banned IP");
                    continue;
                }
                if pool.peer_count() >= settings.network.max_connections as usize {
                    tracing::debug!(addr = %inbound.addr, "rejecting inbound: at max connections");
                    continue;
                }
                let id = pool.add_inbound(inbound.conn, inbound.addr, &inbound.handshake);
                tracing::info!(
                    peer_id = id,
                    addr = %inbound.addr,
                    version = %inbound.handshake.peer_spec.protocol_version,
                    "accepted inbound peer"
                );
                // Extract REST API URL from handshake features for fast header sync.
                for feature in &inbound.handshake.peer_spec.features {
                    if let PeerFeature::RestApiUrl(url) = feature {
                        tracing::debug!(peer_id = id, url, "inbound peer advertises REST API");
                        api_peer_urls.write().unwrap().insert(id, url.clone());
                        break;
                    }
                }
            }

            Some(addr) = peer_connect_rx.recv() => {
                if penalties.is_ip_banned(&addr.ip()) {
                    tracing::debug!(%addr, "skipping outbound connect to banned IP");
                    continue;
                }
                match pool.connect(addr).await {
                    Ok(id) => tracing::info!(peer_id = id, %addr, "manually connected"),
                    Err(e) => tracing::warn!(%addr, error = %e, "manual connect failed"),
                }
            }

            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::info!("API-triggered shutdown...");
                    break;
                }
            }

            _ = &mut ctrl_c => {
                tracing::info!("shutting down...");
                break;
            }
        }
    }

    // Graceful shutdown: signal the processor and then drain connections.
    let _ = cmd_tx.try_send(ProcessorCommand::Shutdown);
    drop(cmd_tx);

    peer_db.flush();
    tracing::info!(peers = pool.peer_count(), "disconnecting peers");
    for p in pool.connected_peers() {
        pool.disconnect(p.id);
    }
    pool.cleanup_disconnected();

    // Give pending writes 5 seconds to drain.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while pool.peer_count() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        pool.cleanup_disconnected();
    }
    tracing::info!("shutdown complete");

    Ok(())
}

/// Apply a penalty to a peer, disconnecting and banning if warranted.
fn apply_penalty(
    pool: &mut ConnectionPool,
    penalties: &mut PenaltyManager,
    peer_id: u64,
    penalty_type: ergo_network::penalty_manager::PenaltyType,
) {
    let action = penalties.add_penalty(peer_id, penalty_type);
    match action {
        PenaltyAction::Ban => {
            tracing::warn!(peer_id, "banning peer for misbehavior");
            let peer_ip = pool
                .connected_peers()
                .iter()
                .find(|p| p.id == peer_id)
                .map(|p| p.addr.ip());
            if let Some(ip) = peer_ip {
                penalties.ban_ip(ip);
                let same_ip_peers: Vec<u64> = pool
                    .connected_peers()
                    .iter()
                    .filter(|p| p.addr.ip() == ip)
                    .map(|p| p.id)
                    .collect();
                for id in same_ip_peers {
                    pool.disconnect(id);
                }
            }
            pool.disconnect(peer_id);
        }
        PenaltyAction::Warn => {
            tracing::warn!(peer_id, "peer misbehavior warning");
        }
        PenaltyAction::None => {}
    }
}

/// Handle periodic sync: run sync manager tick, process timeouts, update shared state.
#[allow(clippy::too_many_arguments)]
async fn handle_sync_tick(
    pool: &mut ConnectionPool,
    sync_mgr: &mut SyncManager,
    tracker: &mut DeliveryTracker,
    sync_history: &HistoryDb,
    settings: &ErgoSettings,
    shared: &Arc<RwLock<SharedState>>,
    discovery: &mut PeerDiscovery,
    peer_db: &mut ergo_network::peer_db::PeerDb,
    penalties: &PenaltyManager,
    sync_tracker: &mut SyncTracker,
    last_message_time: Option<u64>,
    cached_headers_height: u32,
    cached_full_height: u32,
    cached_best_header_id: Option<ergo_types::modifier_id::ModifierId>,
    cached_best_full_id: Option<ergo_types::modifier_id::ModifierId>,
    cached_state_root: &[u8],
    cached_state_version: Option<[u8; 32]>,
    is_digest_mode: bool,
    cached_sync_headers: &[ergo_types::header::Header],
    cached_parameters: &ergo_consensus::parameters::Parameters,
    pending_body_sections: u32,
) {
    // Reset stale peer statuses (no sync exchange within 3 minutes).
    sync_tracker.clear_stale_statuses(std::time::Duration::from_secs(180));

    // No-op: Arc<NodeDb>-backed HistoryDb sees writes immediately.
    let _ = sync_history.try_catch_up_with_primary();

    let peers: Vec<_> = pool
        .connected_peers()
        .iter()
        .map(|p| (p.id, true))
        .collect();

    // Use cached_headers_height from processor's StateUpdate (always fresh)
    // instead of reading from the potentially-stale secondary DB.
    let our_height: u32 = cached_headers_height;
    let max_peer = sync_tracker.max_peer_height();
    let is_caught_up = max_peer > 0 && our_height >= max_peer;

    // Build prebuilt SyncInfo bytes from processor-provided headers (always fresh).
    // This is passed to on_tick so it uses fresh data instead of the stale secondary DB.
    let prebuilt_sync = if !cached_sync_headers.is_empty() {
        let v2 = ergo_wire::sync_info::ErgoSyncInfoV2 {
            last_headers: cached_sync_headers.to_vec(),
        };
        Some(v2.serialize())
    } else {
        None
    };

    const BODY_SECTIONS_DOWNLOAD_THRESHOLD: u32 = 96;
    let download_allowed = pending_body_sections < BODY_SECTIONS_DOWNLOAD_THRESHOLD;

    let actions = sync_mgr.on_tick(
        sync_history,
        tracker,
        &peers,
        is_caught_up,
        prebuilt_sync,
        settings.network.sync_info_max_headers,
        download_allowed,
    );

    execute_actions(pool, &actions, discovery, peer_db, sync_tracker);

    let timed_out = tracker.collect_timed_out();

    let mut candidate_peers = sync_tracker.peers_for_downloading_blocks();
    if candidate_peers.is_empty() {
        candidate_peers = pool.connected_peers().iter().map(|p| p.id).collect();
    }

    for (type_id, id, failed_peer, checks) in timed_out {
        if checks >= settings.network.max_delivery_checks {
            tracker.set_unknown(type_id, &id);
        } else if let Some(&alt_peer) = candidate_peers.iter().find(|&&p| p != failed_peer) {
            tracker.reassign(type_id, &id, alt_peer);
            let inv = ergo_wire::inv::InvData {
                type_id: type_id as i8,
                ids: vec![id],
            };
            let _ = pool.send_to(
                alt_peer,
                MessageCode::RequestModifier as u8,
                inv.serialize(),
            );
        } else {
            tracker.set_unknown(type_id, &id);
        }
    }

    // Periodic cleanup: evict old entries from received (5 min) and invalid (30 min)
    // maps to prevent unbounded growth.
    // Note: stale header reassignment is handled by the dedicated 1s
    // stale_header_tick in the main select! loop (batched, not per-ID).
    tracker.cleanup_received(Duration::from_secs(300));
    tracker.cleanup_invalid(Duration::from_secs(1800));

    update_shared_state(
        sync_history,
        pool,
        sync_mgr,
        shared,
        discovery,
        penalties,
        sync_tracker,
        tracker,
        last_message_time,
        cached_headers_height,
        cached_full_height,
        cached_best_header_id,
        cached_best_full_id,
        cached_state_root,
        cached_state_version,
        is_digest_mode,
        cached_parameters,
    )
    .await;
    pool.cleanup_disconnected();
}

/// Read the shared fast sync active flag and update SharedState.
/// Called after `handle_sync_tick` in the main select loop.
async fn update_fast_sync_flag(
    shared: &Arc<RwLock<SharedState>>,
    flag: &crate::fast_header_sync::SharedFastSyncActive,
) {
    let mut state = shared.write().await;
    state.fast_sync_active = flag.load(std::sync::atomic::Ordering::Relaxed);
}

/// Proactively find and request missing block body sections.
fn handle_check_modifiers(
    pool: &mut ConnectionPool,
    sync_history: &HistoryDb,
    tracker: &mut DeliveryTracker,
    sync_tracker: &SyncTracker,
) {
    use ergo_network::delivery_tracker::ModifierStatus;
    use ergo_network::sync_manager::{distribute_requests_capped, MAX_SECTIONS_PER_PEER};

    let peer_count = pool.peer_count();
    let batch_size = ergo_network::sync_manager::scaled_check_batch_size(peer_count);
    let missing = sync_history.next_modifiers_to_download(batch_size);
    if missing.is_empty() {
        return;
    }

    let to_request: Vec<(u8, ergo_types::modifier_id::ModifierId)> = missing
        .into_iter()
        .filter(|(type_id, id)| tracker.status(*type_id, id) == ModifierStatus::Unknown)
        .collect();

    if to_request.is_empty() {
        return;
    }

    let mut peers = sync_tracker.peers_for_downloading_blocks();
    if peers.is_empty() {
        let connected: HashSet<u64> = pool.connected_peers().iter().map(|p| p.id).collect();
        peers = connected.into_iter().collect();
    }

    if peers.is_empty() {
        return;
    }

    let batches = distribute_requests_capped(&to_request, &peers, MAX_SECTIONS_PER_PEER);
    for (peer_id, type_id, ids) in batches {
        for id in &ids {
            tracker.set_requested(type_id, *id, peer_id);
        }
        let inv = ergo_wire::inv::InvData {
            type_id: type_id as i8,
            ids: ids.clone(),
        };
        let _ = pool.send_to(peer_id, MessageCode::RequestModifier as u8, inv.serialize());
    }

    tracing::debug!(
        requested = to_request.len(),
        "proactive block section download",
    );
}

/// Handle periodic peer discovery: request peers and spawn background connect tasks.
///
/// Connections are spawned as independent tokio tasks that send completed
/// connections back via `pending_conn_tx`. This prevents unreachable peers
/// from blocking the event loop.
#[allow(clippy::too_many_arguments)]
fn handle_discovery_tick(
    pool: &mut ConnectionPool,
    discovery: &mut PeerDiscovery,
    settings: &ErgoSettings,
    penalties: &PenaltyManager,
    pending_conn_tx: &tokio::sync::mpsc::Sender<PendingOutboundConn>,
    magic: [u8; 4],
    our_handshake: &Handshake,
    session_id: u64,
) {
    let peers = pool.connected_peers();
    if !peers.is_empty() {
        let idx = rand::random::<usize>() % peers.len();
        let _ = pool.send_to(peers[idx].id, MessageCode::GetPeers as u8, vec![]);
    }

    let connected: HashSet<_> = pool.connected_peers().iter().map(|p| p.addr).collect();

    if pool.peer_count() < settings.network.max_connections as usize {
        let hs_timeout = settings.network.handshake_timeout_secs;
        let connect_count = ergo_network::sync_manager::discovery_connect_count(
            pool.peer_count(),
            settings.network.max_connections as usize,
        );
        for addr in discovery
            .peers_to_connect(&connected)
            .into_iter()
            .take(connect_count)
        {
            if penalties.is_ip_banned(&addr.ip()) {
                tracing::debug!(%addr, "skipping discovery connect to banned IP");
                continue;
            }
            // Spawn connection as a background task so it doesn't block the event loop.
            let tx = pending_conn_tx.clone();
            let hs = our_handshake.clone();
            tokio::spawn(async move {
                match PeerConnection::connect(addr, magic, &hs, hs_timeout, Some(session_id)).await
                {
                    Ok((conn, peer_hs)) => {
                        let _ = tx
                            .send(PendingOutboundConn {
                                conn,
                                addr,
                                handshake: peer_hs,
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::debug!(%addr, error = %e, "background connect failed");
                    }
                }
            });
        }
    }
}

/// Request the next batch of snapshot chunks from connected peers.
fn request_next_chunks(
    disc: &mut crate::snapshot_bootstrap::SnapshotDiscovery,
    pool: &ConnectionPool,
) {
    let chunks_to_get = disc.next_chunks_to_download();
    let connected = pool.connected_peers();
    if connected.is_empty() {
        return;
    }
    for (i, (_, chunk_id)) in chunks_to_get.iter().enumerate() {
        let p = &connected[i % connected.len()];
        let _ = pool.send_to(p.id, 80, chunk_id.to_vec());
    }
}

/// Apply any continuation headers found in the sync actions.
///
/// Forward them to the processor thread instead of applying directly.
fn apply_continuation_headers(
    actions: &[SyncAction],
    cmd_tx: &std::sync::mpsc::SyncSender<ProcessorCommand>,
    sync_mgr: &mut ergo_network::sync_manager::SyncManager,
    tracker: &mut ergo_network::delivery_tracker::DeliveryTracker,
) {
    for action in actions {
        if let SyncAction::ApplyContinuationHeader {
            peer_id,
            header_bytes,
            header_id,
        } = action
        {
            tracker.set_received(101, header_id);
            sync_mgr.on_section_received(101, header_id, tracker);
            let _ = cmd_tx.try_send(ProcessorCommand::StoreModifier {
                type_id: 101,
                modifier_id: *header_id,
                data: header_bytes.clone(),
                peer_hint: Some(*peer_id),
            });
            tracing::trace!(
                header_id = hex::encode(header_id.0),
                "forwarded continuation header to processor"
            );
        }
    }
}

/// Execute a batch of sync actions by sending messages through the connection pool.
fn execute_actions(
    pool: &mut ConnectionPool,
    actions: &[SyncAction],
    discovery: &mut PeerDiscovery,
    peer_db: &mut ergo_network::peer_db::PeerDb,
    sync_tracker: &mut SyncTracker,
) {
    for action in actions {
        match action {
            SyncAction::SendSyncInfo { peer_id, data } => {
                if let Some(pid) = peer_id {
                    tracing::debug!(peer = pid, data_len = data.len(), "SendSyncInfo → targeted");
                    let _ = pool.send_to(*pid, MessageCode::SyncInfo as u8, data.clone());
                    sync_tracker.record_sync_sent(*pid);
                } else {
                    let n = pool.peer_count();
                    tracing::info!(peers = n, data_len = data.len(), "SendSyncInfo → broadcast");
                    pool.broadcast(MessageCode::SyncInfo as u8, data);
                    for p in pool.connected_peers() {
                        sync_tracker.record_sync_sent(p.id);
                    }
                }
            }
            SyncAction::RequestModifiers {
                peer_id,
                type_id,
                ids,
            } => {
                let inv = ergo_wire::inv::InvData {
                    type_id: *type_id as i8,
                    ids: ids.clone(),
                };
                let body = inv.serialize();
                let _ = pool.send_to(*peer_id, MessageCode::RequestModifier as u8, body);
            }
            SyncAction::SendPeers { peer_id, data } => {
                let _ = pool.send_to(*peer_id, MessageCode::Peers as u8, data.clone());
            }
            SyncAction::SendModifiers { peer_id, data } => {
                let _ = pool.send_to(*peer_id, MessageCode::Modifier as u8, data.clone());
            }
            SyncAction::BroadcastInv { type_id, ids } => {
                let inv = ergo_wire::inv::InvData {
                    type_id: *type_id as i8,
                    ids: ids.clone(),
                };
                pool.broadcast(MessageCode::Inv as u8, &inv.serialize());
            }
            SyncAction::BroadcastInvExcept {
                type_id,
                ids,
                exclude,
            } => {
                let inv = ergo_wire::inv::InvData {
                    type_id: *type_id as i8,
                    ids: ids.clone(),
                };
                pool.broadcast_except(*exclude, MessageCode::Inv as u8, &inv.serialize());
            }
            SyncAction::SendInv {
                peer_id,
                type_id,
                ids,
            } => {
                let inv = ergo_wire::inv::InvData {
                    type_id: *type_id as i8,
                    ids: ids.clone(),
                };
                let _ = pool.send_to(*peer_id, MessageCode::Inv as u8, inv.serialize());
            }
            SyncAction::AddPeers { addresses } => {
                for addr in addresses {
                    discovery.add_peer(*addr);
                    peer_db.add(*addr);
                }
            }
            SyncAction::ApplyContinuationHeader { .. } => {
                // Handled by apply_continuation_headers() before this function.
            }
            SyncAction::None => {}
        }
    }
}

/// Build our local handshake from the node settings.
fn build_handshake(settings: &ErgoSettings, magic: [u8; 4], session_id: u64) -> Handshake {
    use ergo_wire::peer_feature::{ModeFeature, PeerFeature, SessionFeature, StateTypeCode};

    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    Handshake {
        time,
        peer_spec: PeerSpec {
            agent_name: settings.network.agent_name.clone(),
            protocol_version: ProtocolVersion {
                major: 5,
                minor: 0,
                patch: 0,
            },
            node_name: settings.network.node_name.clone(),
            declared_address: settings.network.bind_address.parse::<SocketAddr>().ok(),
            features: vec![
                PeerFeature::Mode(ModeFeature {
                    state_type: if settings.ergo.node.state_type == "utxo" {
                        StateTypeCode::Utxo
                    } else {
                        StateTypeCode::Digest
                    },
                    verifying_transactions: settings.ergo.node.verify_transactions,
                    nipopow_bootstrapped: None,
                    blocks_to_keep: settings.ergo.node.blocks_to_keep,
                }),
                PeerFeature::Session(SessionFeature {
                    network_magic: magic,
                    session_id: session_id as i64,
                }),
            ],
        },
    }
}

/// Parse seed peer strings into socket addresses, skipping any that fail to parse.
fn parse_seed_peers(known_peers: &[String]) -> Vec<SocketAddr> {
    known_peers
        .iter()
        .filter_map(|s| s.parse::<SocketAddr>().ok())
        .collect()
}

/// Refresh the shared state snapshot from cached processor values and connection pool.
#[allow(clippy::too_many_arguments)]
async fn update_shared_state(
    sync_history: &HistoryDb,
    pool: &ConnectionPool,
    sync_mgr: &SyncManager,
    shared: &Arc<RwLock<SharedState>>,
    discovery: &PeerDiscovery,
    penalties: &PenaltyManager,
    sync_tracker: &SyncTracker,
    tracker: &DeliveryTracker,
    last_message_time: Option<u64>,
    cached_headers_height: u32,
    cached_full_height: u32,
    cached_best_header_id: Option<ergo_types::modifier_id::ModifierId>,
    cached_best_full_id: Option<ergo_types::modifier_id::ModifierId>,
    cached_state_root: &[u8],
    cached_state_version: Option<[u8; 32]>,
    _is_digest_mode: bool,
    cached_parameters: &ergo_consensus::parameters::Parameters,
) {
    // Read from sync_history as a fallback when processor hasn't sent updates yet.
    let (headers_height, best_header_id) = if cached_headers_height > 0 {
        (cached_headers_height as u64, cached_best_header_id)
    } else {
        let best_id = sync_history.best_header_id().ok().flatten();
        let height = best_id
            .as_ref()
            .and_then(|id| sync_history.load_header(id).ok().flatten())
            .map_or(0, |h| h.height as u64);
        (height, best_id)
    };

    let (full_height, best_full_block_id) = if cached_full_height > 0 {
        (cached_full_height as u64, cached_best_full_id)
    } else {
        let best_id = sync_history.best_full_block_id().ok().flatten();
        let height = best_id
            .as_ref()
            .and_then(|id| sync_history.load_header(id).ok().flatten())
            .map_or(0, |h| h.height as u64);
        (height, best_id)
    };

    // Difficulty: decode nBits to a BigUint and store as an arbitrary-precision JSON number.
    let best_full_header = best_full_block_id
        .as_ref()
        .and_then(|id| sync_history.load_header(id).ok().flatten());
    let difficulty: serde_json::Value = best_full_header
        .as_ref()
        .map(|h| {
            let decoded = ergo_consensus::difficulty::decode_compact_bits(h.n_bits);
            let decimal_str = decoded.to_str_radix(10);
            serde_json::from_str::<serde_json::Value>(&decimal_str).unwrap_or(serde_json::json!(0))
        })
        .unwrap_or(serde_json::json!(0));
    let previous_full_header_id = best_full_header.as_ref().map(|h| h.parent_id.0);

    // Headers score: cumulative score of best header, as a JSON number.
    let headers_score: serde_json::Value = best_header_id
        .as_ref()
        .and_then(|id| {
            let key = header_score_key(id);
            sync_history.get_index(&key).ok().flatten()
        })
        .map_or(serde_json::json!(0), |bytes| score_bytes_to_json(&bytes));

    // Full blocks score: cumulative score of best full block, as a JSON number.
    let full_blocks_score: serde_json::Value = best_full_block_id
        .as_ref()
        .and_then(|id| {
            let key = header_score_key(id);
            sync_history.get_index(&key).ok().flatten()
        })
        .map_or(serde_json::json!(0), |bytes| score_bytes_to_json(&bytes));

    // Build parameters JSON from the live on-chain consensus parameters.
    let parameters = parameters_to_json(cached_parameters);

    let state_version = cached_state_version;

    let mut state = shared.write().await;
    state.headers_height = headers_height;
    state.full_height = full_height;
    state.peer_count = pool.peer_count();
    state.sync_state = format!("{:?}", sync_mgr.state());
    state.state_root = cached_state_root.to_vec();
    state.best_header_id = best_header_id.map(|id| id.0);
    state.best_full_block_id = best_full_block_id.map(|id| id.0);
    state.connected_peers = pool
        .connected_peers()
        .iter()
        .map(|p| {
            let (state_type, verifying_transactions, blocks_to_keep) =
                if let Some(ref mode) = p.mode_feature {
                    let st = match mode.state_type {
                        ergo_wire::peer_feature::StateTypeCode::Utxo => "utxo",
                        ergo_wire::peer_feature::StateTypeCode::Digest => "digest",
                    };
                    (
                        Some(st.to_string()),
                        Some(mode.verifying_transactions),
                        Some(mode.blocks_to_keep),
                    )
                } else {
                    (None, None, None)
                };
            ConnectedPeerInfo {
                address: p.addr.to_string(),
                name: p.peer_name.clone(),
                node_name: p.node_name.clone(),
                last_handshake: p.connected_at,
                last_message: Some(p.last_activity),
                connection_type: Some(match p.direction {
                    ConnectionDirection::Incoming => "Incoming".to_string(),
                    ConnectionDirection::Outgoing => "Outgoing".to_string(),
                }),
                version: Some(p.version.to_string()),
                state_type,
                verifying_transactions,
                blocks_to_keep,
                peer_id: p.id,
            }
        })
        .collect();
    state.known_peers = discovery
        .known_peers()
        .iter()
        .map(|addr| addr.to_string())
        .collect();
    state.banned_peers = penalties.banned_peer_ids();
    state.sync_tracker_snapshot = serde_json::to_value(sync_tracker.snapshot()).ok();
    state.delivery_tracker_snapshot = serde_json::to_value(tracker.snapshot()).ok();
    state.last_message_time = last_message_time;

    state.max_peer_height = sync_tracker.max_peer_height() as u64;
    state.difficulty = difficulty;
    state.headers_score = headers_score;
    state.full_blocks_score = full_blocks_score;
    state.parameters = parameters;
    state.previous_full_header_id = previous_full_header_id;
    state.state_version = state_version;
}

/// Convert big-endian score bytes to a JSON number (arbitrary precision via serde_json).
fn score_bytes_to_json(bytes: &[u8]) -> serde_json::Value {
    if bytes.is_empty() {
        return serde_json::json!(0);
    }
    // For values that fit in u128, convert via integer arithmetic.
    if bytes.len() <= 16 {
        let mut padded = [0u8; 16];
        let start = 16 - bytes.len();
        padded[start..].copy_from_slice(bytes);
        let value = u128::from_be_bytes(padded);
        // Use serde_json arbitrary_precision to keep the full integer.
        let decimal_str = value.to_string();
        serde_json::from_str::<serde_json::Value>(&decimal_str).unwrap_or(serde_json::json!(0))
    } else {
        // For very large values, use BigUint for decimal string conversion.
        use num_bigint::BigUint;
        let big = BigUint::from_bytes_be(bytes);
        let decimal_str = big.to_str_radix(10);
        serde_json::from_str::<serde_json::Value>(&decimal_str).unwrap_or(serde_json::json!(0))
    }
}

/// Build the parameters JSON object from the live on-chain `Parameters` struct.
///
/// Field names match the Scala reference node API.
fn parameters_to_json(p: &ergo_consensus::parameters::Parameters) -> serde_json::Value {
    use ergo_consensus::parameters::*;
    // SubblocksPerBlockIncrease has parameter ID 9 in the Scala reference.
    // It is absent from the parameter table until block version 4 activates
    // sub-block support, so we emit null when not present.
    const SUBBLOCKS_PER_BLOCK_ID: u8 = 9;
    let subblocks_per_block: serde_json::Value = match p.get(SUBBLOCKS_PER_BLOCK_ID) {
        Some(v) => serde_json::Value::Number(v.into()),
        None => serde_json::Value::Null,
    };
    serde_json::json!({
        "storageFeeFactor": p.get(STORAGE_FEE_FACTOR_ID).unwrap_or(1_250_000),
        "minValuePerByte": p.get(MIN_VALUE_PER_BYTE_ID).unwrap_or(360),
        "maxBlockSize": p.get(MAX_BLOCK_SIZE_ID).unwrap_or(524_288),
        "maxBlockCost": p.get(MAX_BLOCK_COST_ID).unwrap_or(1_000_000),
        "tokenAccessCost": p.get(TOKEN_ACCESS_COST_ID).unwrap_or(100),
        "inputCost": p.get(INPUT_COST_ID).unwrap_or(2_000),
        "dataInputCost": p.get(DATA_INPUT_COST_ID).unwrap_or(100),
        "outputCost": p.get(OUTPUT_COST_ID).unwrap_or(100),
        "subblocksPerBlock": subblocks_per_block,
        "blockVersion": p.block_version(),
        "height": p.height,
    })
}

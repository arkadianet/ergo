use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use ergo_network::connection_pool::ConnectionPool;
use ergo_network::peer_conn::PeerConnection;
use ergo_wire::handshake::ConnectionDirection;
use ergo_network::delivery_tracker::DeliveryTracker;
use ergo_network::message_handler;
use ergo_network::node_view::NodeViewHolder;
use ergo_network::peer_discovery::PeerDiscovery;
use ergo_network::penalty_manager::{PenaltyAction, PenaltyManager};
use ergo_network::sync_manager::{SyncAction, SyncManager};
use ergo_network::sync_tracker::SyncTracker;
use ergo_settings::settings::ErgoSettings;
use ergo_storage::history_db::header_score_key;
use ergo_wire::handshake::{Handshake, PeerSpec, ProtocolVersion};
use ergo_wire::header_ser::serialize_header;
use ergo_wire::message::MessageCode;

use crate::mining::{CandidateGenerator, MiningSolution};

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
    /// Epoch milliseconds when the handshake completed.
    pub last_handshake: u64,
    /// Epoch milliseconds of the last received message from this peer.
    pub last_message: Option<u64>,
    /// "Incoming" or "Outgoing", or None if unknown.
    pub connection_type: Option<String>,
}

/// An inbound peer that has completed the handshake, ready to be added to the pool.
pub struct InboundPeer {
    pub conn: PeerConnection,
    pub addr: SocketAddr,
    pub handshake: Handshake,
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
    pub difficulty: u64,
    pub headers_score: String,
    pub full_blocks_score: String,
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
            difficulty: 0,
            headers_score: "0".into(),
            full_blocks_score: "0".into(),
        }
    }
}

/// Run the main event loop.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    settings: ErgoSettings,
    mut node_view: NodeViewHolder,
    shared: Arc<RwLock<SharedState>>,
    tx_submit_rx: &mut tokio::sync::mpsc::Receiver<crate::api::TxSubmission>,
    peer_connect_rx: &mut tokio::sync::mpsc::Receiver<SocketAddr>,
    inbound_rx: &mut tokio::sync::mpsc::Receiver<InboundPeer>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    indexer_tx: Option<tokio::sync::mpsc::Sender<ergo_indexer::task::IndexerEvent>>,
    mining_solution_rx: &mut tokio::sync::mpsc::Receiver<MiningSolution>,
    candidate_gen: Option<Arc<std::sync::RwLock<CandidateGenerator>>>,
    snapshots_db: Option<crate::snapshots::SnapshotsDb>,
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
    let mut sync_mgr = SyncManager::with_utxo_mode(
        settings.network.desired_inv_objects as usize,
        64,
        utxo_mode,
    );
    let mut discovery = PeerDiscovery::new(
        parse_seed_peers(&settings.network.known_peers),
        1000,
    );
    let mut penalties = PenaltyManager::new();
    let mut sync_tracker = SyncTracker::new();
    let mut mod_cache = ergo_network::modifiers_cache::ModifiersCache::with_default_capacities();

    let data_dir = std::path::Path::new(&settings.ergo.directory);
    let mut peer_db = ergo_network::peer_db::PeerDb::new(data_dir);

    if !peer_db.is_empty() {
        for addr in peer_db.peers() {
            discovery.add_peer(*addr);
        }
        tracing::info!(saved_peers = peer_db.len(), "loaded peers from disk");
    }

    let mut last_msg_time: Option<u64> = None;

    for addr in discovery.peers_to_connect(&HashSet::new()) {
        match pool.connect(addr).await {
            Ok(id) => tracing::info!(peer_id = id, %addr, "connected to peer"),
            Err(e) => tracing::warn!(%addr, error = %e, "failed to connect"),
        }
    }

    let sync_interval = Duration::from_secs(settings.network.sync_interval_secs);
    let mut sync_tick = tokio::time::interval(sync_interval);
    let mut discovery_tick = tokio::time::interval(Duration::from_secs(60));
    let mut status_tick = tokio::time::interval(Duration::from_secs(10));
    let mut check_modifiers_tick = tokio::time::interval(Duration::from_secs(10));
    let mut mempool_audit_tick = tokio::time::interval(Duration::from_secs(60));
    let mut dead_conn_tick = tokio::time::interval(Duration::from_secs(60));
    let mut eviction_tick = tokio::time::interval(Duration::from_secs(3600));

    let mining_interval = Duration::from_secs(settings.ergo.node.candidate_generation_interval_s);
    let mut mining_tick = tokio::time::interval(mining_interval);

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

    // Chain health monitoring: detect globally stuck sync and reset the
    // DeliveryTracker so that stale pending requests don't block progress.
    let mut last_best_height: u32 = 0;
    let mut last_height_change = Instant::now();
    let mut chain_health_interval = tokio::time::interval(Duration::from_secs(60));

    // Per-peer rate limiting for SyncInfo messages (100ms lock time).
    let mut last_sync_from: HashMap<u64, Instant> = HashMap::new();

    // Height of the last continuation header applied from SyncInfoV2 to
    // prevent re-applying the same header on subsequent sync messages.
    let mut last_sync_header_applied: Option<u32> = None;

    // Whether the node is synced enough to accept and verify transactions.
    // Only true in UTXO mode when headers and full blocks are at the same height.
    let mut is_synced_for_txs = false;

    let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());

    loop {
        tokio::select! {
            _ = sync_tick.tick() => {
                handle_sync_tick(
                    &mut pool,
                    &mut sync_mgr,
                    &mut tracker,
                    &node_view,
                    &settings,
                    &shared,
                    &mut discovery,
                    &mut peer_db,
                    &penalties,
                    &mut sync_tracker,
                    last_msg_time,
                ).await;

                // Recompute whether the node is synced enough for tx acceptance.
                // In UTXO mode, transactions can only be verified when headers
                // and full blocks are at the same height (UTXO set is complete).
                is_synced_for_txs = !node_view.is_digest_mode() && {
                    let best_hdr = node_view.history.best_header_id().ok().flatten()
                        .and_then(|id| node_view.history.load_header(&id).ok().flatten())
                        .map(|h| h.height)
                        .unwrap_or(0);
                    let best_full = node_view.history.best_full_block_height().unwrap_or(0);
                    best_hdr > 0 && best_full == best_hdr
                };
            }

            msg = pool.recv() => {
                if let Some(incoming) = msg {
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
                                        let _ = pool.send_to(incoming.peer_id, 77, payload).await;
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
                                        let _ = pool.send_to(incoming.peer_id, 79, manifest_bytes).await;
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
                                        let _ = pool.send_to(incoming.peer_id, 81, chunk_bytes).await;
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
                                        let ids = node_view.history.header_ids_at_height(height).ok()?;
                                        let id = ids.first()?;
                                        let header = node_view.history.load_header(id).ok()??;
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
                                        request_next_chunks(disc, &pool).await;
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
                                    apply_downloaded_snapshot(
                                        disc,
                                        &mut downloaded_chunks,
                                        &mut node_view,
                                        &settings,
                                    );
                                    downloaded_chunks.clear();
                                    snapshot_discovery = None;
                                } else {
                                    request_next_chunks(disc, &pool).await;
                                }
                            }
                            continue;
                        }
                        _ => {} // Fall through to normal message handling.
                    }

                    let peer_addrs: Vec<std::net::SocketAddr> = pool
                        .connected_peers()
                        .iter()
                        .map(|p| p.addr)
                        .collect();
                    let result = message_handler::handle_message(
                        incoming.peer_id,
                        &incoming.message,
                        &mut node_view,
                        &mut sync_mgr,
                        &mut tracker,
                        &peer_addrs,
                        &mut sync_tracker,
                        &mut mod_cache,
                        &mut last_sync_from,
                        is_synced_for_txs,
                        &mut last_sync_header_applied,
                    );

                    // Handle continuation headers before network actions.
                    apply_continuation_headers(
                        &result.actions,
                        &mut node_view,
                        &mut sync_mgr,
                        &mut tracker,
                    );

                    execute_actions(&mut pool, &result.actions, &mut discovery, &mut peer_db, &mut sync_tracker).await;

                    // Broadcast applied blocks to peers and create snapshots.
                    if !result.applied_blocks.is_empty() {
                        let applied_blocks = result.applied_blocks;

                        // Notify the indexer of each applied block.
                        if let Some(ref idx_tx) = indexer_tx {
                            for block_id in &applied_blocks {
                                if let Ok(Some(header)) = node_view.history.load_header(block_id) {
                                    let _ = idx_tx.try_send(
                                        ergo_indexer::task::IndexerEvent::BlockApplied {
                                            header_id: block_id.0,
                                            height: header.height,
                                        },
                                    );
                                }
                            }
                        }

                        // Handle wallet rollback on chain reorg.
                        #[cfg(feature = "wallet")]
                        if let Some(ref wallet_lock) = wallet {
                            if let Some(rollback_height) = node_view.take_rollback_height() {
                                let mut w = wallet_lock.write().await;
                                if let Err(e) = w.rollback_to_height(rollback_height) {
                                    tracing::warn!(
                                        error = %e,
                                        height = rollback_height,
                                        "wallet rollback failed"
                                    );
                                } else {
                                    tracing::info!(
                                        height = rollback_height,
                                        "wallet rolled back for chain reorg"
                                    );
                                }
                            }
                        }

                        // Scan applied blocks for wallet-relevant activity.
                        #[cfg(feature = "wallet")]
                        if let Some(ref wallet_lock) = wallet {
                            for block_id in &applied_blocks {
                                let header = match node_view.history.load_header(block_id) {
                                    Ok(Some(h)) => h,
                                    _ => continue,
                                };
                                let bt = match node_view.history.load_block_transactions(block_id) {
                                    Ok(Some(bt)) => bt,
                                    Ok(None) => {
                                        tracing::debug!(
                                            height = header.height,
                                            "wallet: no block transactions found, skipping"
                                        );
                                        continue;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            error = %e,
                                            height = header.height,
                                            "wallet: failed to load block transactions"
                                        );
                                        continue;
                                    }
                                };
                                let tx_infos: Vec<ergo_wallet::scan_logic::TxInfo> = bt
                                    .tx_bytes
                                    .iter()
                                    .filter_map(|raw_tx| {
                                        let tx = match ergo_wire::transaction_ser::parse_transaction(raw_tx) {
                                            Ok(t) => t,
                                            Err(e) => {
                                                tracing::warn!(error = %e, "wallet: tx parse failed");
                                                return None;
                                            }
                                        };
                                        Some(ergo_wallet::scan_logic::ergo_transaction_to_tx_info(
                                            &tx,
                                            &tx.tx_id,
                                            raw_tx,
                                        ))
                                    })
                                    .collect();
                                let mut w = wallet_lock.write().await;
                                if let Err(e) = w.scan_block(header.height, &block_id.0, &tx_infos) {
                                    tracing::warn!(
                                        error = %e,
                                        height = header.height,
                                        "wallet: scan_block failed"
                                    );
                                } else {
                                    tracing::debug!(
                                        height = header.height,
                                        txs = tx_infos.len(),
                                        "wallet: scanned block"
                                    );
                                }
                            }
                        }

                        // Create UTXO snapshots if configured.
                        if let Some(ref sdb) = snapshots_db {
                            if let Some(utxo_db) = node_view.utxo_db() {
                                for block_id in &applied_blocks {
                                    if let Ok(Some(header)) = node_view.history.load_header(block_id) {
                                        let estimated_tip = shared.read().await.max_peer_height as u32;
                                        if let Err(e) = crate::snapshots::maybe_create_snapshot(
                                            utxo_db,
                                            sdb,
                                            header.height,
                                            settings.ergo.node.make_snapshot_every,
                                            settings.ergo.node.storing_utxo_snapshots,
                                            estimated_tip,
                                        ) {
                                            tracing::warn!(error = %e, height = header.height, "snapshot creation failed");
                                        }
                                    }
                                }
                            }
                        }

                        // Only broadcast Inv for blocks with recent timestamps (within 2 hours).
                        // This prevents flooding peers with stale announcements during initial sync.
                        const BLOCK_BROADCAST_RECENCY_MS: u64 = 7_200_000; // 2 hours

                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;

                        let recent_blocks: Vec<ergo_types::modifier_id::ModifierId> =
                            applied_blocks
                                .iter()
                                .filter(|block_id| {
                                    node_view
                                        .history
                                        .load_header(block_id)
                                        .ok()
                                        .flatten()
                                        .map(|h| {
                                            now_ms.saturating_sub(h.timestamp)
                                                < BLOCK_BROADCAST_RECENCY_MS
                                        })
                                        .unwrap_or(false)
                                })
                                .cloned()
                                .collect();

                        if !recent_blocks.is_empty() {
                            // Broadcast header Inv (type_id = 101).
                            let header_inv = ergo_wire::inv::InvData {
                                type_id: 101i8,
                                ids: recent_blocks.clone(),
                            };
                            pool.broadcast(MessageCode::Inv as u8, &header_inv.serialize())
                                .await;

                            // Broadcast Inv for block sections (Scala: header.sectionIds).
                            // In our codebase, section modifier IDs equal header IDs.
                            // Section type IDs: BlockTransactions=102, ADProofs=104, Extension=108.
                            for section_type_id in [102i8, 104i8, 108i8] {
                                let section_inv = ergo_wire::inv::InvData {
                                    type_id: section_type_id,
                                    ids: recent_blocks.clone(),
                                };
                                pool.broadcast(MessageCode::Inv as u8, &section_inv.serialize())
                                    .await;
                            }
                        }
                    }

                    // Process any penalties reported by the message handler.
                    for (penalty_type, peer_id) in &result.penalties {
                        let action = penalties.add_penalty(*peer_id, *penalty_type);
                        match action {
                            PenaltyAction::Ban => {
                                tracing::warn!(peer_id = *peer_id, "banning peer for misbehavior");
                                // Also ban by IP so the peer cannot reconnect with a new ID.
                                let peer_ip = pool
                                    .connected_peers()
                                    .iter()
                                    .find(|p| p.id == *peer_id)
                                    .map(|p| p.addr.ip());
                                if let Some(ip) = peer_ip {
                                    penalties.ban_ip(ip);
                                    // Disconnect all peers from the same IP.
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
                                pool.disconnect(*peer_id);
                            }
                            PenaltyAction::Warn => {
                                tracing::warn!(peer_id = *peer_id, "peer misbehavior warning");
                            }
                            PenaltyAction::None => {}
                        }
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
                                return Ok(());
                            }
                        }

                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
            }

            _ = discovery_tick.tick() => {
                handle_discovery_tick(&mut pool, &mut discovery, &settings, &penalties).await;
            }

            Some(submission) = tx_submit_rx.recv() => {
                let inv = ergo_wire::inv::InvData {
                    type_id: 2i8,
                    ids: vec![ergo_types::modifier_id::ModifierId(submission.tx_id)],
                };
                pool.broadcast(MessageCode::Inv as u8, &inv.serialize()).await;
                let _ = submission.response.send(Ok(()));
            }

            _ = status_tick.tick() => {
                penalties.cleanup_expired_bans();
                peer_db.maybe_flush();
                let state = shared.read().await;
                tracing::info!(
                    sync_state = ?sync_mgr.state(),
                    peers = pool.peer_count(),
                    blocks_remaining = sync_mgr.blocks_remaining(),
                    headers_height = %state.headers_height,
                    "sync status",
                );
            }

            _ = check_modifiers_tick.tick() => {
                handle_check_modifiers(&mut pool, &node_view, &mut tracker, &sync_tracker).await;
            }

            _ = mempool_audit_tick.tick() => {
                // Step 1: Evict stale transactions.
                let max_age = Duration::from_secs(settings.ergo.node.mempool_cleanup_duration_mins * 60);
                let evicted = {
                    let mut mp = node_view.mempool.write().unwrap();
                    mp.evict_stale(max_age)
                };
                if !evicted.is_empty() {
                    tracing::info!(evicted = evicted.len(), "mempool audit: evicted stale transactions");
                }
                // Step 2: Re-validate against UTXO state.
                if !node_view.is_digest_mode() {
                    let invalid = {
                        let mp = node_view.mempool.read().unwrap();
                        mp.audit_against_utxo(
                            |box_id| node_view.box_exists_in_utxo(box_id),
                            7_000_000,
                        )
                    };
                    if !invalid.is_empty() {
                        let mut mp = node_view.mempool.write().unwrap();
                        mp.remove_batch(&invalid);
                        tracing::info!(removed = invalid.len(), "mempool: removed invalid txs after audit");
                    }
                }
                // Step 3: Rebroadcast up to `rebroadcast_count` random surviving transactions.
                let rebroadcast_count = settings.ergo.node.rebroadcast_count as usize;
                let to_rebroadcast: Vec<ergo_types::modifier_id::ModifierId> = {
                    let mp = node_view.mempool.read().unwrap();
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
                    pool.broadcast(MessageCode::Inv as u8, &inv.serialize()).await;
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
                let current_best = node_view.history.best_full_block_height().unwrap_or(0);
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
                    last_height_change = Instant::now(); // Avoid repeated resets
                }
            }

            // Snapshot bootstrap discovery tick.
            _ = snapshot_tick.tick(), if snapshot_discovery.is_some() => {
                if let Some(ref mut disc) = snapshot_discovery {
                    if disc.plan.is_none() {
                        if let Some((manifest_id, _, _)) = disc.ready_to_download() {
                            // Enough peers reported the same snapshot; request the manifest.
                            if let Some(p) = pool.connected_peers().first() {
                                tracing::info!("requesting snapshot manifest");
                                let _ = pool.send_to(p.id, 78, manifest_id.to_vec()).await;
                            }
                        } else {
                            // Not enough peers yet; ask everyone for snapshot info.
                            pool.broadcast(76, &[]).await;
                            tracing::debug!("sent GetSnapshotsInfo to all peers");
                        }
                    }
                }
            }

            // Mining candidate refresh tick.
            _ = mining_tick.tick(), if candidate_gen.is_some() => {
                if let Some(ref gen_arc) = candidate_gen {
                    let utxo_ref = if utxo_mode {
                        node_view.utxo_state()
                    } else {
                        None
                    };
                    let mut gen = gen_arc.write().unwrap();
                    match gen.generate_candidate(
                        &node_view.history,
                        &node_view.mempool,
                        node_view.current_parameters(),
                        utxo_ref,
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
                    // Acquire the lock in a limited scope so the guard is
                    // dropped before any `.await` point.
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
                            pool.broadcast(MessageCode::Inv as u8, &inv.serialize())
                                .await;
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

    // Graceful shutdown with 5-second timeout.
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

/// Handle periodic sync: run sync manager tick, process timeouts, update shared state.
#[allow(clippy::too_many_arguments)]
async fn handle_sync_tick(
    pool: &mut ConnectionPool,
    sync_mgr: &mut SyncManager,
    tracker: &mut DeliveryTracker,
    node_view: &NodeViewHolder,
    settings: &ErgoSettings,
    shared: &Arc<RwLock<SharedState>>,
    discovery: &mut PeerDiscovery,
    peer_db: &mut ergo_network::peer_db::PeerDb,
    penalties: &PenaltyManager,
    sync_tracker: &mut SyncTracker,
    last_message_time: Option<u64>,
) {
    // Reset stale peer statuses (no sync exchange within 3 minutes).
    sync_tracker.clear_stale_statuses(std::time::Duration::from_secs(180));

    let peers: Vec<_> = pool
        .connected_peers()
        .iter()
        .map(|p| (p.id, true))
        .collect();

    let actions = sync_mgr.on_tick(&node_view.history, tracker, &peers);
    execute_actions(pool, &actions, discovery, peer_db, sync_tracker).await;

    let timed_out = tracker.collect_timed_out();

    // Use two-tier peer selection for reassignment (Older/Equal first, then
    // Unknown/Fork), falling back to all connected peers if the tracker has
    // no classified peers yet.
    let mut candidate_peers = sync_tracker.peers_for_downloading_blocks();
    if candidate_peers.is_empty() {
        candidate_peers = pool
            .connected_peers()
            .iter()
            .map(|p| p.id)
            .collect();
    }

    for (type_id, id, failed_peer, checks) in timed_out {
        if checks >= settings.network.max_delivery_checks {
            // Max retries exceeded — reset to unknown for proactive download to pick up.
            tracker.set_unknown(type_id, &id);
        } else if let Some(&alt_peer) = candidate_peers.iter().find(|&&p| p != failed_peer) {
            // Re-request from a different peer.
            tracker.reassign(type_id, &id, alt_peer);
            let inv = ergo_wire::inv::InvData {
                type_id: type_id as i8,
                ids: vec![id],
            };
            let _ = pool
                .send_to(alt_peer, MessageCode::RequestModifier as u8, inv.serialize())
                .await;
        } else {
            // No alternative peer available — reset to unknown.
            tracker.set_unknown(type_id, &id);
        }
    }

    update_shared_state(
        node_view,
        pool,
        sync_mgr,
        shared,
        discovery,
        penalties,
        sync_tracker,
        tracker,
        last_message_time,
    )
    .await;
    pool.cleanup_disconnected();
}

/// Proactively find and request missing block body sections.
///
/// Uses the SyncTracker two-tier peer selection: prefers Older/Equal peers,
/// falls back to Unknown/Fork if none available (matching Scala's
/// `getPeersForDownloadingBlocks`).
async fn handle_check_modifiers(
    pool: &mut ConnectionPool,
    node_view: &NodeViewHolder,
    tracker: &mut DeliveryTracker,
    sync_tracker: &SyncTracker,
) {
    use ergo_network::delivery_tracker::ModifierStatus;
    use ergo_network::sync_manager::distribute_requests;

    // Find up to 192 missing sections (matching Scala's FullBlocksToDownloadAhead).
    let missing = node_view.history.next_modifiers_to_download(192);
    if missing.is_empty() {
        return;
    }

    // Filter out modifiers already being tracked.
    let to_request: Vec<(u8, ergo_types::modifier_id::ModifierId)> = missing
        .into_iter()
        .filter(|(type_id, id)| tracker.status(*type_id, id) == ModifierStatus::Unknown)
        .collect();

    if to_request.is_empty() {
        return;
    }

    // Get available peers for block download using two-tier selection.
    // Primary: Older + Equal peers; Fallback: Unknown + Fork peers.
    let mut peers = sync_tracker.peers_for_downloading_blocks();

    // If the sync tracker has no suitable peers (e.g. all peers are still
    // unclassified and haven't been added to the tracker yet), fall back
    // to all connected peers so we don't stall.
    if peers.is_empty() {
        let connected: HashSet<u64> = pool
            .connected_peers()
            .iter()
            .map(|p| p.id)
            .collect();
        peers = connected.into_iter().collect();
    }

    if peers.is_empty() {
        return;
    }

    // Distribute across peers and send requests.
    let batches = distribute_requests(&to_request, &peers);
    for (peer_id, type_id, ids) in batches {
        for id in &ids {
            tracker.set_requested(type_id, *id, peer_id);
        }
        let inv = ergo_wire::inv::InvData {
            type_id: type_id as i8,
            ids: ids.clone(),
        };
        let _ = pool
            .send_to(peer_id, MessageCode::RequestModifier as u8, inv.serialize())
            .await;
    }

    tracing::debug!(
        requested = to_request.len(),
        "proactive block section download",
    );
}

/// Handle periodic peer discovery: request peers and connect to new ones.
async fn handle_discovery_tick(
    pool: &mut ConnectionPool,
    discovery: &mut PeerDiscovery,
    settings: &ErgoSettings,
    penalties: &PenaltyManager,
) {
    let peers = pool.connected_peers();
    if !peers.is_empty() {
        let idx = rand::random::<usize>() % peers.len();
        let _ = pool
            .send_to(peers[idx].id, MessageCode::GetPeers as u8, vec![])
            .await;
    }

    let connected: HashSet<_> = pool
        .connected_peers()
        .iter()
        .map(|p| p.addr)
        .collect();

    if pool.peer_count() < settings.network.max_connections as usize {
        for addr in discovery.peers_to_connect(&connected).into_iter().take(3) {
            if penalties.is_ip_banned(&addr.ip()) {
                tracing::debug!(%addr, "skipping discovery connect to banned IP");
                continue;
            }
            match pool.connect(addr).await {
                Ok(id) => tracing::info!(peer_id = id, %addr, "connected"),
                Err(e) => tracing::debug!(%addr, error = %e, "connect failed"),
            }
        }
    }
}

/// Request the next batch of snapshot chunks from connected peers.
async fn request_next_chunks(
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
        let _ = pool.send_to(p.id, 80, chunk_id.to_vec()).await;
    }
}

/// Reconstruct and apply the UTXO state from downloaded snapshot chunks.
fn apply_downloaded_snapshot(
    disc: &crate::snapshot_bootstrap::SnapshotDiscovery,
    downloaded_chunks: &mut HashMap<[u8; 32], Vec<u8>>,
    node_view: &mut ergo_network::node_view::NodeViewHolder,
    settings: &ErgoSettings,
) {
    let plan = match disc.plan {
        Some(ref p) => p,
        None => return,
    };

    tracing::info!("all snapshot chunks downloaded, reconstructing UTXO state");

    let mut all_entries: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    for cid in &plan.chunk_ids {
        let data = match downloaded_chunks.get(cid) {
            Some(d) => d,
            None => {
                tracing::error!("missing chunk data during reconstruction");
                return;
            }
        };
        match crate::snapshots::parse_chunk(data) {
            Ok(entries) => all_entries.extend(entries),
            Err(e) => {
                tracing::error!(error = %e, "failed to parse snapshot chunk");
                return;
            }
        }
    }

    let utxo_db = match node_view.utxo_db() {
        Some(db) => db,
        None => {
            tracing::error!("no UTXO DB available for snapshot apply");
            return;
        }
    };

    let meta = ergo_storage::utxo_db::UtxoMetadata {
        digest: plan.root_digest,
        version: [0u8; 32],
    };
    if let Err(e) = utxo_db.apply_changes(&all_entries, &[], &meta) {
        tracing::error!(error = %e, "failed to write snapshot to UTXO DB");
        return;
    }

    tracing::info!(entries = all_entries.len(), "snapshot written to UTXO DB");

    let utxo_path = std::path::Path::new(&settings.ergo.directory).join("utxo");
    let fresh_db = match ergo_storage::utxo_db::UtxoDb::open(&utxo_path) {
        Ok(db) => db,
        Err(e) => {
            tracing::error!(error = %e, "failed to reopen UTXO DB after snapshot");
            return;
        }
    };

    match ergo_state::utxo_state::UtxoState::restore_from_db(fresh_db) {
        Ok(utxo_state) => {
            node_view.set_utxo_state(utxo_state);
            tracing::info!(
                height = plan.snapshot_height,
                "UTXO state restored from snapshot"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to restore UTXO state from snapshot");
        }
    }
}

/// Apply any continuation headers found in the sync actions.
///
/// A continuation header is extracted from a SyncInfoV2 message when the
/// peer's most recent header has `parent_id == our best_header_id`. This
/// lets us apply the header immediately without a full Inv/RequestModifier
/// roundtrip, and enqueue block section downloads.
fn apply_continuation_headers(
    actions: &[SyncAction],
    node_view: &mut ergo_network::node_view::NodeViewHolder,
    sync_mgr: &mut ergo_network::sync_manager::SyncManager,
    tracker: &mut ergo_network::delivery_tracker::DeliveryTracker,
) {
    for action in actions {
        if let SyncAction::ApplyContinuationHeader {
            peer_id: _,
            header_bytes,
            header_id,
        } = action
        {
            match node_view.process_modifier(101, header_id, header_bytes) {
                Ok(info) => {
                    tracker.set_received(101, header_id);
                    sync_mgr.on_section_received(101, header_id, tracker);
                    sync_mgr.on_headers_received(&[*header_id], &node_view.history);

                    // Enqueue block body section downloads for this header.
                    let mut blocks_to_download = Vec::new();
                    for (_section_type, hdr_id) in &info.to_download {
                        if !blocks_to_download.contains(hdr_id) {
                            blocks_to_download.push(*hdr_id);
                        }
                    }
                    if !blocks_to_download.is_empty() {
                        sync_mgr.enqueue_block_downloads(blocks_to_download);
                    }

                    tracing::debug!(
                        header_id = hex::encode(header_id.0),
                        "continuation header applied successfully"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        header_id = hex::encode(header_id.0),
                        error = %e,
                        "failed to apply continuation header"
                    );
                }
            }
        }
    }
}

/// Execute a batch of sync actions by sending messages through the connection pool.
async fn execute_actions(
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
                    let _ = pool
                        .send_to(*pid, MessageCode::SyncInfo as u8, data.clone())
                        .await;
                    sync_tracker.record_sync_sent(*pid);
                } else {
                    pool.broadcast(MessageCode::SyncInfo as u8, data).await;
                    // Record sync sent for all connected peers.
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
                let _ = pool
                    .send_to(*peer_id, MessageCode::RequestModifier as u8, body)
                    .await;
            }
            SyncAction::SendPeers { peer_id, data } => {
                let _ = pool
                    .send_to(*peer_id, MessageCode::Peers as u8, data.clone())
                    .await;
            }
            SyncAction::SendModifiers { peer_id, data } => {
                let _ = pool
                    .send_to(*peer_id, MessageCode::Modifier as u8, data.clone())
                    .await;
            }
            SyncAction::BroadcastInv { type_id, ids } => {
                let inv = ergo_wire::inv::InvData {
                    type_id: *type_id as i8,
                    ids: ids.clone(),
                };
                pool.broadcast(MessageCode::Inv as u8, &inv.serialize())
                    .await;
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
                pool.broadcast_except(*exclude, MessageCode::Inv as u8, &inv.serialize())
                    .await;
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
                let _ = pool
                    .send_to(*peer_id, MessageCode::Inv as u8, inv.serialize())
                    .await;
            }
            SyncAction::AddPeers { addresses } => {
                for addr in addresses {
                    discovery.add_peer(*addr);
                    peer_db.add(*addr);
                }
            }
            SyncAction::ApplyContinuationHeader { .. } => {
                // Handled by apply_continuation_headers() before this function
                // is called. The RequestModifiers actions for block sections
                // are emitted by apply_continuation_headers separately.
            }
            SyncAction::None => {}
        }
    }
}

/// Build our local handshake from the node settings, including a ModeFeature
/// (so peers know our operating mode) and a SessionFeature for self-connection
/// detection.
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

/// Refresh the shared state snapshot from current node view and connection pool.
#[allow(clippy::too_many_arguments)]
async fn update_shared_state(
    node_view: &NodeViewHolder,
    pool: &ConnectionPool,
    sync_mgr: &SyncManager,
    shared: &Arc<RwLock<SharedState>>,
    discovery: &PeerDiscovery,
    penalties: &PenaltyManager,
    sync_tracker: &SyncTracker,
    tracker: &DeliveryTracker,
    last_message_time: Option<u64>,
) {
    let best_header_id = node_view.history.best_header_id().ok().flatten();
    let best_full_block_id = node_view.history.best_full_block_id().ok().flatten();

    let headers_height = best_header_id
        .as_ref()
        .and_then(|id| node_view.history.load_header(id).ok().flatten())
        .map_or(0, |h| h.height as u64);

    let full_height = best_full_block_id
        .as_ref()
        .and_then(|id| node_view.history.load_header(id).ok().flatten())
        .map_or(0, |h| h.height as u64);

    // Difficulty from best full block header's nBits
    let difficulty = best_full_block_id
        .as_ref()
        .and_then(|id| node_view.history.load_header(id).ok().flatten())
        .map_or(0, |h| h.n_bits);

    // Headers score: cumulative score of best header
    let headers_score = best_header_id
        .as_ref()
        .and_then(|id| {
            let key = header_score_key(id);
            node_view.history.get_index(&key).ok().flatten()
        })
        .map_or_else(|| "0".to_string(), |bytes| score_bytes_to_decimal(&bytes));

    // Full blocks score: cumulative score of best full block
    let full_blocks_score = best_full_block_id
        .as_ref()
        .and_then(|id| {
            let key = header_score_key(id);
            node_view.history.get_index(&key).ok().flatten()
        })
        .map_or_else(|| "0".to_string(), |bytes| score_bytes_to_decimal(&bytes));

    let mut state = shared.write().await;
    state.headers_height = headers_height;
    state.full_height = full_height;
    state.peer_count = pool.peer_count();
    state.sync_state = format!("{:?}", sync_mgr.state());
    state.state_root = node_view.state_root().to_vec();
    state.best_header_id = best_header_id.map(|id| id.0);
    state.best_full_block_id = best_full_block_id.map(|id| id.0);
    state.connected_peers = pool
        .connected_peers()
        .iter()
        .map(|p| ConnectedPeerInfo {
            address: p.addr.to_string(),
            name: p.peer_name.clone(),
            last_handshake: p.connected_at,
            last_message: Some(p.last_activity),
            connection_type: Some(match p.direction {
                ConnectionDirection::Incoming => "Incoming".to_string(),
                ConnectionDirection::Outgoing => "Outgoing".to_string(),
            }),
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
}

/// Convert big-endian score bytes to a decimal string.
fn score_bytes_to_decimal(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_string();
    }
    // Score is stored as big-endian arbitrary-precision integer.
    // Try to fit in u128 first; if it overflows, fall back to hex.
    if bytes.len() <= 16 {
        let mut padded = [0u8; 16];
        let start = 16 - bytes.len();
        padded[start..].copy_from_slice(bytes);
        let value = u128::from_be_bytes(padded);
        value.to_string()
    } else {
        // Fallback: hex-encode for very large scores
        hex::encode(bytes)
    }
}

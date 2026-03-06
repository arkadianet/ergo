use std::collections::VecDeque;
use std::net::SocketAddr;

use ergo_storage::history_db::HistoryDb;
use ergo_types::modifier_id::ModifierId;
use ergo_wire::sync_info::ErgoSyncInfo;

use crate::delivery_tracker::{DeliveryTracker, ModifierStatus, PeerId};
use crate::persistent_sync;

/// Section type IDs for block body sections.
const BLOCK_TX_TYPE_ID: u8 = 102;
const AD_PROOFS_TYPE_ID: u8 = 104;
const EXTENSION_TYPE_ID: u8 = 108;

/// Body section types requested during block download (digest mode: all three).
const BODY_SECTION_TYPES_DIGEST: [u8; 3] = [BLOCK_TX_TYPE_ID, AD_PROOFS_TYPE_ID, EXTENSION_TYPE_ID];

/// Body section types for UTXO mode: ADProofs are not needed.
const BODY_SECTION_TYPES_UTXO: [u8; 2] = [BLOCK_TX_TYPE_ID, EXTENSION_TYPE_ID];

/// Average block interval in milliseconds (2 minutes).
const BLOCK_INTERVAL_MS: u64 = 120_000;

/// Number of blocks' worth of time we allow the header chain tip to lag behind
/// wall-clock time and still consider headers "synced". Matches Scala's
/// `HeadersChainDiff` mainnet default of 100.
const HEADER_CHAIN_DIFF: u64 = 100;

/// Current sync state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    HeaderSync,
    BlockDownload,
    Synced,
}

/// Actions the sync manager wants the event loop to perform.
#[derive(Debug)]
pub enum SyncAction {
    SendSyncInfo {
        peer_id: Option<PeerId>,
        data: Vec<u8>,
    },
    RequestModifiers {
        peer_id: PeerId,
        type_id: u8,
        ids: Vec<ModifierId>,
    },
    SendPeers {
        peer_id: PeerId,
        data: Vec<u8>,
    },
    SendModifiers {
        peer_id: PeerId,
        data: Vec<u8>,
    },
    BroadcastInv {
        type_id: u8,
        ids: Vec<ModifierId>,
    },
    BroadcastInvExcept {
        type_id: u8,
        ids: Vec<ModifierId>,
        exclude: PeerId,
    },
    SendInv {
        peer_id: PeerId,
        type_id: u8,
        ids: Vec<ModifierId>,
    },
    AddPeers {
        addresses: Vec<SocketAddr>,
    },
    /// Apply a continuation header extracted from SyncInfoV2 directly.
    ///
    /// When an Older peer's SyncInfoV2 contains a header whose parent_id
    /// equals our best header ID, that header can be applied immediately
    /// without a full Inv/RequestModifier roundtrip.
    ApplyContinuationHeader {
        /// Peer to request block sections from.
        peer_id: PeerId,
        /// The serialized header bytes.
        header_bytes: Vec<u8>,
        /// blake2b256 hash of `header_bytes` — the modifier ID.
        header_id: ModifierId,
    },
    None,
}

/// Drives blockchain synchronization.
pub struct SyncManager {
    state: SyncState,
    blocks_to_download: VecDeque<ModifierId>,
    max_per_request: usize,
    download_window: usize,
    /// When true (UTXO mode), ADProofs (type 104) are not requested during download.
    utxo_mode: bool,
    /// Becomes true (and stays true) once the header chain tip is within
    /// `BLOCK_INTERVAL_MS * HEADER_CHAIN_DIFF` of wall-clock time.
    /// Mirrors Scala's `isHeadersChainSynced` flag.
    is_headers_chain_synced: bool,
}

impl SyncManager {
    pub fn new(max_per_request: usize, download_window: usize) -> Self {
        Self {
            state: SyncState::Idle,
            blocks_to_download: VecDeque::new(),
            max_per_request,
            download_window,
            utxo_mode: false,
            is_headers_chain_synced: false,
        }
    }

    /// Create a new SyncManager with explicit state type awareness.
    /// When `utxo_mode` is true, ADProofs will not be downloaded.
    pub fn with_utxo_mode(max_per_request: usize, download_window: usize, utxo_mode: bool) -> Self {
        Self {
            state: SyncState::Idle,
            blocks_to_download: VecDeque::new(),
            max_per_request,
            download_window,
            utxo_mode,
            is_headers_chain_synced: false,
        }
    }

    /// Returns the body section type IDs to request during download.
    /// In UTXO mode, ADProofs (104) are excluded.
    fn body_section_types(&self) -> &[u8] {
        if self.utxo_mode {
            &BODY_SECTION_TYPES_UTXO
        } else {
            &BODY_SECTION_TYPES_DIGEST
        }
    }

    pub fn state(&self) -> SyncState {
        self.state
    }

    /// Returns whether the header chain is considered synced (tip is recent).
    pub fn is_headers_chain_synced(&self) -> bool {
        self.is_headers_chain_synced
    }

    /// Check if the header chain tip is within `BLOCK_INTERVAL_MS * HEADER_CHAIN_DIFF`
    /// of the current wall-clock time. Once set, the flag stays true permanently.
    ///
    /// Returns `true` if the flag was *newly* set by this call.
    pub fn check_headers_chain_synced(&mut self, header_timestamp_ms: u64) -> bool {
        if self.is_headers_chain_synced {
            return false;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let threshold = BLOCK_INTERVAL_MS * HEADER_CHAIN_DIFF;
        if now_ms.saturating_sub(header_timestamp_ms) < threshold {
            self.is_headers_chain_synced = true;
            true
        } else {
            false
        }
    }

    /// Called on periodic tick. Decides what to do next.
    ///
    /// `is_caught_up` should be true when our headers height >= max peer height,
    /// preventing premature transition to `Synced` during initial sync.
    #[allow(clippy::too_many_arguments)]
    pub fn on_tick(
        &mut self,
        history: &HistoryDb,
        tracker: &mut DeliveryTracker,
        available_peers: &[(PeerId, bool)],
        is_caught_up: bool,
        prebuilt_sync_data: Option<Vec<u8>>,
        max_headers: u32,
        download_allowed: bool,
    ) -> Vec<SyncAction> {
        let mut actions = Vec::new();

        // Always broadcast SyncInfo regardless of state, matching Scala's
        // periodic `SendLocalSyncInfo` that fires independently of sync phase.
        // Use prebuilt data from the processor thread when available (always fresh),
        // falling back to the secondary DB (may be stale during initial sync).
        let has_prebuilt = prebuilt_sync_data.is_some();
        let sync_data = prebuilt_sync_data.or_else(|| serialize_sync_info(history, max_headers));
        if let Some(ref data) = sync_data {
            tracing::debug!(
                has_prebuilt,
                data_len = data.len(),
                "on_tick: SyncInfo produced"
            );
            actions.push(SyncAction::SendSyncInfo {
                peer_id: None,
                data: data.clone(),
            });
        } else {
            tracing::warn!("on_tick: NO SyncInfo data — prebuilt=None, serialize_sync_info=None");
        }

        match self.state {
            SyncState::Idle | SyncState::HeaderSync => {
                self.state = SyncState::HeaderSync;
                // Transition to block download once the header chain tip is
                // recent enough (within ~3.3 hours of wall clock), matching
                // Scala's `isHeadersChainSynced` trigger.  This allows body
                // downloads to begin while the last ~100 headers still sync.
                if self.is_headers_chain_synced && !self.blocks_to_download.is_empty() {
                    // Rebuild queue in height order before first block download.
                    // After fast-sync, the queue may contain blocks in chunk-arrival
                    // order rather than height order, which prevents sequential
                    // block application.
                    let full_height = history.best_full_block_height().unwrap_or(0);
                    self.rebuild_download_queue_by_height(history, full_height);
                    self.state = SyncState::BlockDownload;
                    if download_allowed {
                        self.request_block_sections(
                            &mut actions,
                            tracker,
                            available_peers,
                            history,
                        );
                    }
                }
            }
            SyncState::BlockDownload => {
                if download_allowed {
                    self.request_block_sections(&mut actions, tracker, available_peers, history);
                }

                if self.blocks_to_download.is_empty()
                    && tracker.pending_count() == 0
                    && is_caught_up
                {
                    self.state = SyncState::Synced;
                }
            }
            SyncState::Synced => {
                // Service any blocks enqueued while in Synced state
                // (e.g., via on_headers_received from a newly-Older peer).
                if !self.blocks_to_download.is_empty() {
                    self.state = SyncState::BlockDownload;
                    if download_allowed {
                        self.request_block_sections(
                            &mut actions,
                            tracker,
                            available_peers,
                            history,
                        );
                    }
                }
            }
        }

        actions
    }

    /// Called when new headers have been stored.
    ///
    /// Enqueues block downloads.  During initial sync (HeaderSync/Idle) the
    /// state is NOT changed — block download only starts once headers are
    /// caught up (decided in `on_tick`), matching Scala's header-first
    /// strategy and preventing block traffic from starving header sync.
    ///
    /// When already `Synced`, transitions to `BlockDownload` immediately so
    /// newly-mined blocks are fetched without delay.
    pub fn on_headers_received(&mut self, new_header_ids: &[ModifierId], history: &HistoryDb) {
        let need_blocks: Vec<ModifierId> = new_header_ids
            .iter()
            .filter(|id| matches!(history.has_all_sections(id), Ok(false)))
            .copied()
            .collect();

        if !need_blocks.is_empty() {
            self.enqueue_block_downloads(need_blocks);
            // When already synced, immediately fetch new block bodies.
            if self.state == SyncState::Synced {
                self.state = SyncState::BlockDownload;
            }
        }
    }

    /// Called when a block section has been received and stored.
    pub fn on_section_received(
        &mut self,
        type_id: u8,
        id: &ModifierId,
        tracker: &mut DeliveryTracker,
    ) {
        tracker.set_received(type_id, id);
    }

    /// Called when a block has been fully assembled and applied.
    pub fn on_block_applied(&mut self, _block_id: &ModifierId) {
        // Nothing to remove from download queue; blocks are drained in on_tick.
    }

    /// Enqueue headers that need block bodies.
    pub fn enqueue_block_downloads(&mut self, ids: Vec<ModifierId>) {
        for id in ids {
            self.blocks_to_download.push_back(id);
        }
    }

    /// On startup, populate `blocks_to_download` from the DB window above `full_height`.
    ///
    /// After a restart, `on_headers_received` never fires for already-stored headers,
    /// leaving `blocks_to_download` empty. This method scans the FULL range
    /// `[full_height+1 .. best_header_height]` in height order, enqueuing
    /// header IDs whose body sections (BlockTransactions + Extension) are
    /// absent from the DB.
    ///
    /// Scanning the full range is essential after fast-sync, where all headers
    /// are stored but most blocks lack body sections. A small window would
    /// miss the vast majority of needed downloads and the node would never
    /// transition to BlockDownload.
    pub fn enqueue_startup_gap(&mut self, history: &HistoryDb, full_height: u32, _window: usize) {
        let headers_height = history.best_header_height().unwrap_or(0);
        if headers_height <= full_height {
            return;
        }
        for h in (full_height + 1)..=headers_height {
            let ids = history.header_ids_at_height(h).unwrap_or_default();
            for id in ids {
                if matches!(history.has_all_sections(&id), Ok(false)) {
                    self.blocks_to_download.push_back(id);
                }
            }
        }
    }

    /// Rebuild the download queue in strict height order.
    ///
    /// After fast-sync, headers are stored in chunk-arrival order, so the
    /// download queue may contain blocks scattered across the full chain
    /// range.  This prevents sequential block application because
    /// `collect_applicable_suffix` requires consecutive complete blocks
    /// starting from `best_full_block_height + 1`.
    ///
    /// This method clears the queue and repopulates it by walking the
    /// height index from `full_height + 1` to `best_header_height`,
    /// enqueuing only blocks that still need body sections.
    pub fn rebuild_download_queue_by_height(&mut self, history: &HistoryDb, full_height: u32) {
        let headers_height = history.best_header_height().unwrap_or(0);
        if headers_height <= full_height {
            return;
        }
        let old_len = self.blocks_to_download.len();
        self.blocks_to_download.clear();
        for h in (full_height + 1)..=headers_height {
            let ids = history.header_ids_at_height(h).unwrap_or_default();
            for id in ids {
                if matches!(history.has_all_sections(&id), Ok(false)) {
                    self.blocks_to_download.push_back(id);
                }
            }
        }
        tracing::info!(
            old_len,
            new_len = self.blocks_to_download.len(),
            full_height,
            headers_height,
            "rebuilt download queue in height order"
        );
    }

    /// Number of blocks remaining to download.
    pub fn blocks_remaining(&self) -> usize {
        self.blocks_to_download.len()
    }

    /// Effective download window scaled by peer count.
    ///
    /// Returns `max(base_window, peer_count * BLOCKS_PER_PEER)` so adding more
    /// peers actually increases throughput instead of leaving them idle.
    pub fn effective_download_window(&self, peer_count: usize) -> usize {
        if peer_count == 0 {
            return self.download_window;
        }
        (peer_count * BLOCKS_PER_PEER).max(self.download_window)
    }

    /// Request the next batch of block sections from available peers.
    ///
    /// The `blocks_to_download` queue contains **header_ids**. This method
    /// loads each header from `history` to compute the wire-format section_ids
    /// (`blake2b256([type_id] ++ header_id ++ root)`) for the `RequestModifier`
    /// messages sent to peers.
    fn request_block_sections(
        &mut self,
        actions: &mut Vec<SyncAction>,
        tracker: &mut DeliveryTracker,
        available_peers: &[(PeerId, bool)],
        history: &HistoryDb,
    ) {
        let peers_with_blocks: Vec<PeerId> = available_peers
            .iter()
            .filter(|(_, supports)| *supports)
            .map(|(id, _)| *id)
            .collect();

        if peers_with_blocks.is_empty() {
            return;
        }

        let effective_window = self.effective_download_window(peers_with_blocks.len());
        let mut peer_idx = 0;
        let mut requested = 0;

        while requested < effective_window && !self.blocks_to_download.is_empty() {
            let batch_size = self.max_per_request.min(self.blocks_to_download.len());
            let batch: Vec<ModifierId> = self.blocks_to_download.drain(..batch_size).collect();
            let peer_id = peers_with_blocks[peer_idx % peers_with_blocks.len()];

            // Build per-type section_id lists by loading headers
            let mut by_type: std::collections::HashMap<u8, Vec<ModifierId>> =
                std::collections::HashMap::new();
            for header_id in &batch {
                if let Ok(Some(header)) = history.load_header(header_id) {
                    for (type_id, section_id) in header.section_ids(header_id) {
                        // Only request types we need (digest vs UTXO mode)
                        if self.body_section_types().contains(&type_id) {
                            by_type.entry(type_id).or_default().push(section_id);
                        }
                    }
                }
            }

            for (type_id, ids) in by_type {
                for id in &ids {
                    if tracker.status(type_id, id) == ModifierStatus::Unknown {
                        tracker.set_requested(type_id, *id, peer_id);
                    }
                }
                actions.push(SyncAction::RequestModifiers {
                    peer_id,
                    type_id,
                    ids,
                });
            }

            requested += batch.len();
            peer_idx += 1;
        }
    }
}

/// Number of blocks per peer used when scaling the download window.
///
/// With N peers, the effective download window is `max(base_window, N * BLOCKS_PER_PEER)`.
const BLOCKS_PER_PEER: usize = 16;

/// Number of block sections per peer used when scaling the check_modifiers batch.
const SECTIONS_PER_PEER: usize = 32;

/// Minimum batch size for proactive block section downloads.
const MIN_CHECK_BATCH: usize = 192;

/// Minimum outbound connection attempts per discovery tick.
const MIN_DISCOVERY_CONNECTS: usize = 3;

/// Compute the proactive check_modifiers batch size, scaled by peer count.
///
/// Returns `max(192, peer_count * 32)` so more peers means we scan for more
/// missing sections per tick.
pub fn scaled_check_batch_size(peer_count: usize) -> usize {
    (peer_count * SECTIONS_PER_PEER).max(MIN_CHECK_BATCH)
}

/// Compute how many outbound connections to attempt per discovery tick.
///
/// Returns `max(3, (max_connections - current_connections) / 3)` so the node
/// ramps more aggressively when far from capacity.
pub fn discovery_connect_count(current: usize, max: usize) -> usize {
    let gap = max.saturating_sub(current);
    (gap / 3).max(MIN_DISCOVERY_CONNECTS)
}

/// Build and serialize sync info, returning `None` on error.
fn serialize_sync_info(history: &HistoryDb, max_headers: u32) -> Option<Vec<u8>> {
    let sync_info = persistent_sync::build_sync_info_persistent(history, max_headers).ok()?;
    match sync_info {
        ErgoSyncInfo::V2(v2) => Some(v2.serialize()),
        ErgoSyncInfo::V1(_) => None,
    }
}

/// Distribute download requests evenly across available peers.
///
/// Groups requests by type_id and distributes each group round-robin across peers.
/// Returns `Vec<(PeerId, type_id, Vec<ModifierId>)>` — one entry per peer per type.
pub fn distribute_requests(
    requests: &[(u8, ModifierId)],
    peers: &[PeerId],
) -> Vec<(PeerId, u8, Vec<ModifierId>)> {
    if peers.is_empty() || requests.is_empty() {
        return Vec::new();
    }

    use std::collections::HashMap;

    // Group by type_id.
    let mut by_type: HashMap<u8, Vec<ModifierId>> = HashMap::new();
    for &(type_id, id) in requests {
        by_type.entry(type_id).or_default().push(id);
    }

    // For each type, distribute IDs round-robin across peers.
    let mut result_map: HashMap<(PeerId, u8), Vec<ModifierId>> = HashMap::new();
    for (type_id, ids) in by_type {
        for (i, id) in ids.into_iter().enumerate() {
            let peer = peers[i % peers.len()];
            result_map.entry((peer, type_id)).or_default().push(id);
        }
    }

    result_map
        .into_iter()
        .map(|((peer_id, type_id), ids)| (peer_id, type_id, ids))
        .collect()
}

/// Maximum block sections to assign to a single peer per request cycle.
pub const MAX_SECTIONS_PER_PEER: usize = 12;

/// Distribute download requests across peers with a per-peer cap.
///
/// Like `distribute_requests` but limits each peer to `max_per_peer` sections
/// total across all type_ids. Matches Scala's `maxModifiersPerBucket`.
pub fn distribute_requests_capped(
    requests: &[(u8, ModifierId)],
    peers: &[PeerId],
    max_per_peer: usize,
) -> Vec<(PeerId, u8, Vec<ModifierId>)> {
    if peers.is_empty() || requests.is_empty() {
        return Vec::new();
    }

    use std::collections::HashMap;

    let mut per_peer_count: HashMap<PeerId, usize> = HashMap::new();
    let mut result: HashMap<(PeerId, u8), Vec<ModifierId>> = HashMap::new();
    let mut peer_idx = 0;

    for &(type_id, id) in requests {
        let mut assigned = false;
        for offset in 0..peers.len() {
            let pid = peers[(peer_idx + offset) % peers.len()];
            let count = per_peer_count.entry(pid).or_insert(0);
            if *count < max_per_peer {
                *count += 1;
                result.entry((pid, type_id)).or_default().push(id);
                assigned = true;
                peer_idx = (peer_idx + offset + 1) % peers.len();
                break;
            }
        }
        if !assigned {
            break;
        }
    }

    result
        .into_iter()
        .map(|((pid, tid), ids)| (pid, tid, ids))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::header::Header;
    use ergo_types::modifier_id::{Digest32, ModifierId};

    fn make_id(byte: u8) -> ModifierId {
        ModifierId([byte; 32])
    }

    /// Store test headers in the DB so request_block_sections can compute section_ids.
    fn store_test_headers(history: &ergo_storage::history_db::HistoryDb, ids: &[ModifierId]) {
        for (i, id) in ids.iter().enumerate() {
            let mut h = Header::default_for_test();
            h.height = (i + 1) as u32;
            h.transactions_root = Digest32([(i as u8).wrapping_add(0x10); 32]);
            h.ad_proofs_root = Digest32([(i as u8).wrapping_add(0x20); 32]);
            h.extension_root = Digest32([(i as u8).wrapping_add(0x30); 32]);
            if i > 0 {
                h.parent_id = ids[i - 1];
            }
            history.store_header_with_score(id, &h).unwrap();
        }
    }

    #[test]
    fn new_starts_idle() {
        let mgr = SyncManager::new(10, 64);
        assert_eq!(mgr.state(), SyncState::Idle);
    }

    #[test]
    fn on_tick_idle_broadcasts_sync_info_to_all_peers() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true), (2u64, true), (3u64, false)];

        let mut mgr = SyncManager::new(10, 64);
        let actions = mgr.on_tick(&history, &mut tracker, &peers, false, None, 10, true);

        assert_eq!(mgr.state(), SyncState::HeaderSync);
        assert!(!actions.is_empty());
        // SyncInfo should be broadcast to all peers (peer_id: None), not just the first.
        assert!(matches!(
            &actions[0],
            SyncAction::SendSyncInfo { peer_id: None, .. }
        ));
    }

    #[test]
    fn on_headers_received_enqueues_without_transitioning() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::HeaderSync;

        let ids = vec![make_id(1), make_id(2), make_id(3)];
        mgr.on_headers_received(&ids, &history);

        // Header-first: stays in HeaderSync, blocks just enqueued.
        assert_eq!(mgr.state(), SyncState::HeaderSync);
        assert_eq!(mgr.blocks_remaining(), 3);
    }

    #[test]
    fn on_tick_block_download_requests_sections() {
        use ergo_types::header::Header;
        use ergo_types::modifier_id::Digest32;

        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        // Store real headers so request_block_sections can compute section_ids.
        let mut h1 = Header::default_for_test();
        h1.height = 1;
        h1.transactions_root = Digest32([0x11; 32]);
        h1.ad_proofs_root = Digest32([0x22; 32]);
        h1.extension_root = Digest32([0x33; 32]);
        let id1 = make_id(1);
        history.store_header_with_score(&id1, &h1).unwrap();

        let mut h2 = Header::default_for_test();
        h2.height = 2;
        h2.parent_id = id1;
        h2.transactions_root = Digest32([0x44; 32]);
        h2.ad_proofs_root = Digest32([0x55; 32]);
        h2.extension_root = Digest32([0x66; 32]);
        let id2 = make_id(2);
        history.store_header_with_score(&id2, &h2).unwrap();

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::BlockDownload;
        mgr.enqueue_block_downloads(vec![id1, id2]);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false, None, 10, true);

        // Should have 3 RequestModifiers actions (one per body section type)
        let request_count = actions
            .iter()
            .filter(|a| matches!(a, SyncAction::RequestModifiers { .. }))
            .count();
        assert_eq!(request_count, 3);

        // Verify the IDs in requests are section_ids (not header_ids)
        for action in &actions {
            if let SyncAction::RequestModifiers { ids, .. } = action {
                for id in ids {
                    // Section IDs must differ from header IDs
                    assert_ne!(*id, id1);
                    assert_ne!(*id, id2);
                }
            }
        }
    }

    #[test]
    fn on_section_received_marks_delivered() {
        let mut tracker = DeliveryTracker::new(30, 3);
        let id = make_id(1);
        tracker.set_requested(102, id, 1);

        let mut mgr = SyncManager::new(10, 64);
        mgr.on_section_received(102, &id, &mut tracker);

        assert_eq!(tracker.status(102, &id), ModifierStatus::Received);
    }

    #[test]
    fn on_block_applied_does_not_modify_queue() {
        let mut mgr = SyncManager::new(10, 64);
        mgr.enqueue_block_downloads(vec![make_id(1), make_id(2)]);
        assert_eq!(mgr.blocks_remaining(), 2);

        mgr.on_block_applied(&make_id(1));
        assert_eq!(mgr.blocks_remaining(), 2);
    }

    #[test]
    fn synced_state_sends_periodic_sync() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::Synced;

        let actions = mgr.on_tick(&history, &mut tracker, &peers, true, None, 10, true);

        assert!(!actions.is_empty());
        assert!(matches!(
            &actions[0],
            SyncAction::SendSyncInfo { peer_id: None, .. }
        ));
    }

    #[test]
    fn enqueue_block_downloads_adds_to_queue() {
        let mut mgr = SyncManager::new(10, 64);
        assert_eq!(mgr.blocks_remaining(), 0);

        mgr.enqueue_block_downloads(vec![make_id(1), make_id(2), make_id(3)]);
        assert_eq!(mgr.blocks_remaining(), 3);

        mgr.enqueue_block_downloads(vec![make_id(4)]);
        assert_eq!(mgr.blocks_remaining(), 4);
    }

    #[test]
    fn sync_action_send_peers_variant() {
        let action = SyncAction::SendPeers {
            peer_id: 1,
            data: vec![0x01, 0x02],
        };
        match action {
            SyncAction::SendPeers { peer_id, data } => {
                assert_eq!(peer_id, 1);
                assert_eq!(data.len(), 2);
            }
            _ => panic!("expected SendPeers"),
        }
    }

    #[test]
    fn sync_action_send_modifiers_variant() {
        let action = SyncAction::SendModifiers {
            peer_id: 2,
            data: vec![0xAA],
        };
        assert!(matches!(
            action,
            SyncAction::SendModifiers { peer_id: 2, .. }
        ));
    }

    #[test]
    fn sync_action_broadcast_inv_variant() {
        let action = SyncAction::BroadcastInv {
            type_id: 101,
            ids: vec![make_id(1)],
        };
        match action {
            SyncAction::BroadcastInv { type_id, ids } => {
                assert_eq!(type_id, 101);
                assert_eq!(ids.len(), 1);
            }
            _ => panic!("expected BroadcastInv"),
        }
    }

    #[test]
    fn broadcast_inv_except_variant_constructed() {
        let action = SyncAction::BroadcastInvExcept {
            type_id: 2,
            ids: vec![ModifierId([0xAA; 32])],
            exclude: 42,
        };
        match action {
            SyncAction::BroadcastInvExcept {
                type_id,
                ids,
                exclude,
            } => {
                assert_eq!(type_id, 2);
                assert_eq!(ids.len(), 1);
                assert_eq!(exclude, 42);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn sync_action_add_peers_variant() {
        let addr: std::net::SocketAddr = "10.0.0.1:9030".parse().unwrap();
        let action = SyncAction::AddPeers {
            addresses: vec![addr],
        };
        match action {
            SyncAction::AddPeers { addresses } => {
                assert_eq!(addresses.len(), 1);
                assert_eq!(addresses[0].port(), 9030);
            }
            _ => panic!("expected AddPeers"),
        }
    }

    #[test]
    fn discovery_connect_count_minimum_three() {
        // Even when close to max, should attempt at least 3
        assert_eq!(discovery_connect_count(28, 30), 3);
        assert_eq!(discovery_connect_count(29, 30), 3);
        assert_eq!(discovery_connect_count(30, 30), 3);
    }

    #[test]
    fn discovery_connect_count_scales_with_capacity() {
        // 0 of 30 connected: (30-0)/3 = 10
        assert_eq!(discovery_connect_count(0, 30), 10);
        // 15 of 30: (30-15)/3 = 5
        assert_eq!(discovery_connect_count(15, 30), 5);
        // 0 of 60: (60-0)/3 = 20
        assert_eq!(discovery_connect_count(0, 60), 20);
    }

    #[test]
    fn scaled_check_batch_size_base_minimum() {
        // With 0 or few peers, should return at least the base of 192
        assert_eq!(scaled_check_batch_size(0), 192);
        assert_eq!(scaled_check_batch_size(1), 192);
        assert_eq!(scaled_check_batch_size(5), 192);
    }

    #[test]
    fn scaled_check_batch_size_scales_with_peers() {
        // With enough peers, should scale: peer_count * 32
        // 7 peers: 7 * 32 = 224 > 192
        assert_eq!(scaled_check_batch_size(7), 224);
        // 20 peers: 20 * 32 = 640
        assert_eq!(scaled_check_batch_size(20), 640);
        // 30 peers: 30 * 32 = 960
        assert_eq!(scaled_check_batch_size(30), 960);
    }

    #[test]
    fn distribute_requests_empty_inputs() {
        let result = distribute_requests(&[], &[1, 2, 3]);
        assert!(result.is_empty());
    }

    #[test]
    fn distribute_requests_empty_peers() {
        let requests = vec![(102u8, make_id(1))];
        let result = distribute_requests(&requests, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn distribute_requests_even_split() {
        let requests = vec![
            (102u8, make_id(1)),
            (102u8, make_id(2)),
            (104u8, make_id(1)),
            (104u8, make_id(2)),
        ];
        let result = distribute_requests(&requests, &[10, 20]);

        // 4 requests across 2 peers = 2 each
        let total: usize = result.iter().map(|(_, _, ids)| ids.len()).sum();
        assert_eq!(total, 4);

        // Each peer should have some requests
        assert!(result.iter().any(|(pid, _, _)| *pid == 10));
        assert!(result.iter().any(|(pid, _, _)| *pid == 20));
    }

    #[test]
    fn distribute_requests_single_peer() {
        let requests = vec![
            (102u8, make_id(1)),
            (102u8, make_id(2)),
            (104u8, make_id(3)),
        ];
        let result = distribute_requests(&requests, &[42]);

        // All requests go to the single peer
        let total: usize = result.iter().map(|(_, _, ids)| ids.len()).sum();
        assert_eq!(total, 3);
        assert!(result.iter().all(|(pid, _, _)| *pid == 42));
    }

    #[test]
    fn utxo_mode_skips_ad_proofs_download() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let ids = vec![make_id(1), make_id(2)];
        store_test_headers(&history, &ids);

        let mut mgr = SyncManager::with_utxo_mode(10, 64, true);
        mgr.state = SyncState::BlockDownload;
        mgr.enqueue_block_downloads(ids);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false, None, 10, true);

        // In UTXO mode, only BlockTransactions (102) and Extension (108) are requested.
        let request_actions: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                SyncAction::RequestModifiers { type_id, .. } => Some(*type_id),
                _ => None,
            })
            .collect();
        assert_eq!(request_actions.len(), 2);
        assert!(request_actions.contains(&102));
        assert!(request_actions.contains(&108));
        assert!(!request_actions.contains(&104));
    }

    #[test]
    fn digest_mode_downloads_all_three_sections() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let ids = vec![make_id(1), make_id(2)];
        store_test_headers(&history, &ids);

        let mut mgr = SyncManager::with_utxo_mode(10, 64, false);
        mgr.state = SyncState::BlockDownload;
        mgr.enqueue_block_downloads(ids);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false, None, 10, true);

        let request_actions: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                SyncAction::RequestModifiers { type_id, .. } => Some(*type_id),
                _ => None,
            })
            .collect();
        // Digest mode requests all 3 section types.
        assert_eq!(request_actions.len(), 3);
        assert!(request_actions.contains(&102));
        assert!(request_actions.contains(&104));
        assert!(request_actions.contains(&108));
    }

    #[test]
    fn synced_transitions_to_block_download_on_new_headers() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::Synced;

        let ids = vec![make_id(1), make_id(2)];
        mgr.on_headers_received(&ids, &history);

        assert_eq!(mgr.state(), SyncState::BlockDownload);
        assert_eq!(mgr.blocks_remaining(), 2);
    }

    #[test]
    fn header_sync_transitions_to_block_download_when_headers_chain_synced() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let ids = vec![make_id(1), make_id(2)];
        store_test_headers(&history, &ids);

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::HeaderSync;
        mgr.enqueue_block_downloads(ids);

        // Simulate header chain synced via recent timestamp.
        let recent_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 60_000; // 1 minute ago — well within threshold
        assert!(mgr.check_headers_chain_synced(recent_ts));

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false, None, 10, true);

        assert_eq!(mgr.state(), SyncState::BlockDownload);
        assert!(actions
            .iter()
            .any(|a| matches!(a, SyncAction::RequestModifiers { .. })));
    }

    #[test]
    fn header_sync_stays_when_headers_chain_not_synced() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::HeaderSync;
        mgr.enqueue_block_downloads(vec![make_id(1), make_id(2)]);

        // is_headers_chain_synced is false → should stay in HeaderSync.
        let _actions = mgr.on_tick(&history, &mut tracker, &peers, false, None, 10, true);

        assert_eq!(mgr.state(), SyncState::HeaderSync);
        assert_eq!(mgr.blocks_remaining(), 2); // blocks still queued
    }

    #[test]
    fn check_headers_chain_synced_with_recent_timestamp() {
        let mut mgr = SyncManager::new(10, 64);
        assert!(!mgr.is_headers_chain_synced());

        // Timestamp 1 minute ago — within 100 * 120s = 12000s threshold.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let recent = now_ms - 60_000;

        assert!(mgr.check_headers_chain_synced(recent));
        assert!(mgr.is_headers_chain_synced());
        // Second call returns false (already set).
        assert!(!mgr.check_headers_chain_synced(recent));
    }

    #[test]
    fn check_headers_chain_synced_with_old_timestamp() {
        let mut mgr = SyncManager::new(10, 64);

        // Timestamp 24 hours ago — way beyond threshold.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let old = now_ms - 86_400_000;

        assert!(!mgr.check_headers_chain_synced(old));
        assert!(!mgr.is_headers_chain_synced());
    }

    #[test]
    fn block_download_stays_when_not_caught_up() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::BlockDownload;
        // Empty queue but NOT caught up — should stay in BlockDownload.
        let actions = mgr.on_tick(&history, &mut tracker, &peers, false, None, 10, true);

        assert_eq!(mgr.state(), SyncState::BlockDownload);
        // Should still send SyncInfo even in BlockDownload.
        assert!(actions
            .iter()
            .any(|a| matches!(a, SyncAction::SendSyncInfo { .. })));
    }

    #[test]
    fn block_download_transitions_to_synced_when_caught_up() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::BlockDownload;
        // Empty queue AND caught up — should transition to Synced.
        let _actions = mgr.on_tick(&history, &mut tracker, &peers, true, None, 10, true);

        assert_eq!(mgr.state(), SyncState::Synced);
    }

    #[test]
    fn block_download_sends_sync_info() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let ids = vec![make_id(1)];
        store_test_headers(&history, &ids);

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::BlockDownload;
        mgr.enqueue_block_downloads(ids);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false, None, 10, true);

        // Should include both SyncInfo (for parallel header download) and RequestModifiers.
        assert!(actions
            .iter()
            .any(|a| matches!(a, SyncAction::SendSyncInfo { .. })));
        assert!(actions
            .iter()
            .any(|a| matches!(a, SyncAction::RequestModifiers { .. })));
    }

    #[test]
    fn effective_download_window_scales_with_peer_count() {
        let mgr = SyncManager::new(10, 64);
        // With 1 peer, should use at least the base window
        assert!(mgr.effective_download_window(1) >= 64);
        // With 10 peers, should scale up: 10 * BLOCKS_PER_PEER = 160
        assert!(mgr.effective_download_window(10) >= 160);
        // With 20 peers, should scale further
        assert!(mgr.effective_download_window(20) >= 320);
        // 0 peers should return the base window (no divide-by-zero)
        assert_eq!(mgr.effective_download_window(0), 64);
    }

    #[test]
    fn request_block_sections_drains_more_with_more_peers() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);

        // Create 200 headers
        let ids: Vec<ModifierId> = (0..200u8).map(|b| make_id(b)).collect();
        store_test_headers(&history, &ids);

        // Use small max_per_request so the window is the actual constraint.
        // With 1 peer: effective_window = max(64, 1*16) = 64, drains ~70 blocks
        let peers_1 = vec![(1u64, true)];
        let mut mgr1 = SyncManager::new(10, 64);
        mgr1.state = SyncState::BlockDownload;
        mgr1.enqueue_block_downloads(ids.clone());
        let _actions1 = mgr1.on_tick(&history, &mut tracker, &peers_1, false, None, 10, true);
        let remaining_1 = mgr1.blocks_remaining();

        // With 10 peers: effective_window = max(64, 10*16) = 160, drains ~160 blocks
        let peers_10: Vec<(u64, bool)> = (1..=10).map(|id| (id, true)).collect();
        let mut tracker2 = DeliveryTracker::new(30, 3);
        let mut mgr2 = SyncManager::new(10, 64);
        mgr2.state = SyncState::BlockDownload;
        mgr2.enqueue_block_downloads(ids.clone());
        let _actions2 = mgr2.on_tick(&history, &mut tracker2, &peers_10, false, None, 10, true);
        let remaining_10 = mgr2.blocks_remaining();

        // More peers should drain more blocks from the queue
        assert!(
            remaining_10 < remaining_1,
            "10 peers should drain more blocks: remaining_10={remaining_10}, remaining_1={remaining_1}"
        );
    }

    #[test]
    fn request_block_sections_distributes_across_peers() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);

        let ids: Vec<ModifierId> = (0..50u8).map(|b| make_id(b)).collect();
        store_test_headers(&history, &ids);

        let peers: Vec<(u64, bool)> = (1..=5).map(|id| (id, true)).collect();
        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::BlockDownload;
        mgr.enqueue_block_downloads(ids);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false, None, 10, true);

        // Verify that multiple peers received RequestModifiers
        let mut peers_used: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for action in &actions {
            if let SyncAction::RequestModifiers { peer_id, .. } = action {
                peers_used.insert(*peer_id);
            }
        }
        assert!(
            peers_used.len() > 1,
            "blocks should be distributed across multiple peers, got {peers_used:?}"
        );
    }

    #[test]
    fn synced_services_enqueued_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let ids = vec![make_id(1), make_id(2)];
        store_test_headers(&history, &ids);

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::Synced;
        mgr.enqueue_block_downloads(ids);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, true, None, 10, true);

        // Should transition to BlockDownload and request sections.
        assert_eq!(mgr.state(), SyncState::BlockDownload);
        assert!(actions
            .iter()
            .any(|a| matches!(a, SyncAction::RequestModifiers { .. })));
    }

    #[test]
    fn enqueue_startup_gap_fills_queue_from_db() {
        // After restart with headers in DB but no body sections downloaded,
        // enqueue_startup_gap should populate blocks_to_download.
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut mgr = SyncManager::new(10, 64);

        // Store headers at heights 1..=3 in history without body sections.
        let ids: Vec<ModifierId> = (1u8..=3).map(|b| make_id(b)).collect();
        store_test_headers(&history, &ids);

        assert_eq!(mgr.blocks_remaining(), 0);

        mgr.enqueue_startup_gap(&history, 0, 10);

        assert_eq!(
            mgr.blocks_remaining(),
            3,
            "should queue 3 headers without body sections"
        );
    }

    #[test]
    fn rebuild_download_queue_sorts_by_height() {
        // Simulate fast-sync scenario: headers stored at heights 1..=5 but
        // enqueued in chunk-arrival order (3, 4, 5, 1, 2) instead of height
        // order. rebuild_download_queue_by_height should re-order them.
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut mgr = SyncManager::new(10, 64);

        // Store 5 headers at heights 1..=5.
        let ids: Vec<ModifierId> = (1u8..=5).map(|b| make_id(b)).collect();
        store_test_headers(&history, &ids);

        // Enqueue in wrong order (simulating chunk-arrival order).
        mgr.enqueue_block_downloads(vec![ids[2], ids[3], ids[4], ids[0], ids[1]]);
        assert_eq!(mgr.blocks_remaining(), 5);

        // Front of queue should be id[2] (height 3), NOT id[0] (height 1).
        assert_eq!(mgr.blocks_to_download[0], ids[2]);

        // Rebuild in height order.
        mgr.rebuild_download_queue_by_height(&history, 0);

        assert_eq!(mgr.blocks_remaining(), 5);
        // Now front of queue should be id[0] (height 1).
        assert_eq!(mgr.blocks_to_download[0], ids[0]);
        assert_eq!(mgr.blocks_to_download[1], ids[1]);
        assert_eq!(mgr.blocks_to_download[2], ids[2]);
        assert_eq!(mgr.blocks_to_download[3], ids[3]);
        assert_eq!(mgr.blocks_to_download[4], ids[4]);
    }

    #[test]
    fn on_tick_skips_block_requests_when_download_not_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let db = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);

        let mut mgr = SyncManager::with_utxo_mode(10, 64, true);
        // Force headers chain synced
        mgr.check_headers_chain_synced(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );

        // Enqueue some blocks and store headers so request_block_sections can work
        let ids: Vec<ModifierId> = (0..10u8)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i;
                ModifierId(id)
            })
            .collect();
        store_test_headers(&db, &ids);
        mgr.enqueue_block_downloads(ids);

        let peers = vec![(1u64, true)];

        // First tick transitions to BlockDownload but with download_allowed=false, no requests
        let actions = mgr.on_tick(&db, &mut tracker, &peers, false, None, 10, false);
        let request_count = actions
            .iter()
            .filter(|a| matches!(a, SyncAction::RequestModifiers { .. }))
            .count();
        assert_eq!(
            request_count, 0,
            "should not request modifiers when download_not_allowed"
        );
        // State should have transitioned to BlockDownload
        assert_eq!(mgr.state(), SyncState::BlockDownload);
    }

    #[test]
    fn distribute_requests_capped_limits_per_peer() {
        let peers = vec![1u64, 2u64];
        let requests: Vec<(u8, ModifierId)> = (0..50)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                (102, ModifierId(id))
            })
            .collect();
        let batches = distribute_requests_capped(&requests, &peers, 12);
        let total: usize = batches.iter().map(|(_, _, ids)| ids.len()).sum();
        assert!(total <= 24, "total {} should be <= 24", total);
        for &pid in &peers {
            let peer_total: usize = batches
                .iter()
                .filter(|(p, _, _)| *p == pid)
                .map(|(_, _, ids)| ids.len())
                .sum();
            assert!(peer_total <= 12, "peer {} got {} sections", pid, peer_total);
        }
    }

    #[test]
    fn distribute_requests_capped_empty_inputs() {
        let batches = distribute_requests_capped(&[], &[1, 2], 12);
        assert!(batches.is_empty());
        let batches = distribute_requests_capped(&[(102, ModifierId([0; 32]))], &[], 12);
        assert!(batches.is_empty());
    }

    #[test]
    fn distribute_requests_capped_single_peer() {
        let requests: Vec<(u8, ModifierId)> = (0..20)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                (102, ModifierId(id))
            })
            .collect();
        let batches = distribute_requests_capped(&requests, &[1u64], 12);
        let total: usize = batches.iter().map(|(_, _, ids)| ids.len()).sum();
        assert_eq!(total, 12, "single peer should get exactly 12");
    }
}

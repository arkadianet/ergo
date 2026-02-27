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
}

impl SyncManager {
    pub fn new(max_per_request: usize, download_window: usize) -> Self {
        Self {
            state: SyncState::Idle,
            blocks_to_download: VecDeque::new(),
            max_per_request,
            download_window,
            utxo_mode: false,
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

    /// Called on periodic tick. Decides what to do next.
    ///
    /// `is_caught_up` should be true when our headers height >= max peer height,
    /// preventing premature transition to `Synced` during initial sync.
    pub fn on_tick(
        &mut self,
        history: &HistoryDb,
        tracker: &mut DeliveryTracker,
        available_peers: &[(PeerId, bool)],
        is_caught_up: bool,
    ) -> Vec<SyncAction> {
        let mut actions = Vec::new();

        // Always broadcast SyncInfo regardless of state, matching Scala's
        // periodic `SendLocalSyncInfo` that fires independently of sync phase.
        if let Some(data) = serialize_sync_info(history) {
            actions.push(SyncAction::SendSyncInfo {
                peer_id: None,
                data,
            });
        }

        match self.state {
            SyncState::Idle | SyncState::HeaderSync => {
                self.state = SyncState::HeaderSync;
                // Header-first sync: only start block download once headers
                // are caught up to the network tip.  This prevents block
                // section traffic from starving header synchronization.
                if is_caught_up && !self.blocks_to_download.is_empty() {
                    self.state = SyncState::BlockDownload;
                    self.request_block_sections(&mut actions, tracker, available_peers);
                }
            }
            SyncState::BlockDownload => {
                self.request_block_sections(&mut actions, tracker, available_peers);

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
                    self.request_block_sections(&mut actions, tracker, available_peers);
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

    /// Number of blocks remaining to download.
    pub fn blocks_remaining(&self) -> usize {
        self.blocks_to_download.len()
    }

    /// Request the next batch of block sections from available peers.
    fn request_block_sections(
        &mut self,
        actions: &mut Vec<SyncAction>,
        tracker: &mut DeliveryTracker,
        available_peers: &[(PeerId, bool)],
    ) {
        let peers_with_blocks: Vec<PeerId> = available_peers
            .iter()
            .filter(|(_, supports)| *supports)
            .map(|(id, _)| *id)
            .collect();

        if peers_with_blocks.is_empty() {
            return;
        }

        let mut peer_idx = 0;
        let mut requested = 0;

        while requested < self.download_window && !self.blocks_to_download.is_empty() {
            let batch_size = self.max_per_request.min(self.blocks_to_download.len());
            let batch: Vec<ModifierId> = self.blocks_to_download.drain(..batch_size).collect();
            let peer_id = peers_with_blocks[peer_idx % peers_with_blocks.len()];

            for &type_id in self.body_section_types() {
                for id in &batch {
                    if tracker.status(type_id, id) == ModifierStatus::Unknown {
                        tracker.set_requested(type_id, *id, peer_id);
                    }
                }
                actions.push(SyncAction::RequestModifiers {
                    peer_id,
                    type_id,
                    ids: batch.clone(),
                });
            }

            requested += batch.len();
            peer_idx += 1;
        }
    }
}

/// Build and serialize sync info, returning `None` on error.
fn serialize_sync_info(history: &HistoryDb) -> Option<Vec<u8>> {
    let sync_info = persistent_sync::build_sync_info_persistent(history).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::modifier_id::ModifierId;

    fn make_id(byte: u8) -> ModifierId {
        ModifierId([byte; 32])
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
        let actions = mgr.on_tick(&history, &mut tracker, &peers, false);

        assert_eq!(mgr.state(), SyncState::HeaderSync);
        assert!(!actions.is_empty());
        // SyncInfo should be broadcast to all peers (peer_id: None), not just the first.
        assert!(matches!(
            &actions[0],
            SyncAction::SendSyncInfo {
                peer_id: None,
                ..
            }
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
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::BlockDownload;
        mgr.enqueue_block_downloads(vec![make_id(1), make_id(2)]);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false);

        let request_count = actions
            .iter()
            .filter(|a| matches!(a, SyncAction::RequestModifiers { .. }))
            .count();
        assert_eq!(request_count, 3);
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

        let actions = mgr.on_tick(&history, &mut tracker, &peers, true);

        assert!(!actions.is_empty());
        assert!(matches!(
            &actions[0],
            SyncAction::SendSyncInfo {
                peer_id: None,
                ..
            }
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
        assert!(matches!(action, SyncAction::SendModifiers { peer_id: 2, .. }));
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
            SyncAction::BroadcastInvExcept { type_id, ids, exclude } => {
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
        let action = SyncAction::AddPeers { addresses: vec![addr] };
        match action {
            SyncAction::AddPeers { addresses } => {
                assert_eq!(addresses.len(), 1);
                assert_eq!(addresses[0].port(), 9030);
            }
            _ => panic!("expected AddPeers"),
        }
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

        let mut mgr = SyncManager::with_utxo_mode(10, 64, true);
        mgr.state = SyncState::BlockDownload;
        mgr.enqueue_block_downloads(vec![make_id(1), make_id(2)]);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false);

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

        let mut mgr = SyncManager::with_utxo_mode(10, 64, false);
        mgr.state = SyncState::BlockDownload;
        mgr.enqueue_block_downloads(vec![make_id(1), make_id(2)]);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false);

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
    fn header_sync_transitions_to_block_download_when_caught_up() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::HeaderSync;
        mgr.enqueue_block_downloads(vec![make_id(1), make_id(2)]);

        // Headers caught up → should transition to BlockDownload.
        let actions = mgr.on_tick(&history, &mut tracker, &peers, true);

        assert_eq!(mgr.state(), SyncState::BlockDownload);
        assert!(actions.iter().any(|a| matches!(a, SyncAction::RequestModifiers { .. })));
    }

    #[test]
    fn header_sync_stays_when_not_caught_up() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::HeaderSync;
        mgr.enqueue_block_downloads(vec![make_id(1), make_id(2)]);

        // Headers NOT caught up → should stay in HeaderSync.
        let _actions = mgr.on_tick(&history, &mut tracker, &peers, false);

        assert_eq!(mgr.state(), SyncState::HeaderSync);
        assert_eq!(mgr.blocks_remaining(), 2); // blocks still queued
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
        let actions = mgr.on_tick(&history, &mut tracker, &peers, false);

        assert_eq!(mgr.state(), SyncState::BlockDownload);
        // Should still send SyncInfo even in BlockDownload.
        assert!(actions.iter().any(|a| matches!(a, SyncAction::SendSyncInfo { .. })));
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
        let _actions = mgr.on_tick(&history, &mut tracker, &peers, true);

        assert_eq!(mgr.state(), SyncState::Synced);
    }

    #[test]
    fn block_download_sends_sync_info() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::BlockDownload;
        mgr.enqueue_block_downloads(vec![make_id(1)]);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, false);

        // Should include both SyncInfo (for parallel header download) and RequestModifiers.
        assert!(actions.iter().any(|a| matches!(a, SyncAction::SendSyncInfo { .. })));
        assert!(actions.iter().any(|a| matches!(a, SyncAction::RequestModifiers { .. })));
    }

    #[test]
    fn synced_services_enqueued_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mut tracker = DeliveryTracker::new(30, 3);
        let peers = vec![(1u64, true)];

        let mut mgr = SyncManager::new(10, 64);
        mgr.state = SyncState::Synced;
        mgr.enqueue_block_downloads(vec![make_id(1), make_id(2)]);

        let actions = mgr.on_tick(&history, &mut tracker, &peers, true);

        // Should transition to BlockDownload and request sections.
        assert_eq!(mgr.state(), SyncState::BlockDownload);
        assert!(actions.iter().any(|a| matches!(a, SyncAction::RequestModifiers { .. })));
    }
}

//! Per-peer chain status tracking for intelligent sync decisions.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ergo_types::modifier_id::ModifierId;
use serde::Serialize;

use crate::delivery_tracker::PeerId;

/// Classification of a peer's chain relative to ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerChainStatus {
    /// Peer's chain is ahead of ours (they have blocks we need).
    Older,
    /// Peer's chain is behind ours.
    Younger,
    /// Peer is at the same height.
    Equal,
    /// Peer is on a different fork.
    Fork,
    /// We haven't classified this peer yet.
    Unknown,
}

/// Tracks per-peer chain status and height for intelligent download decisions.
pub struct SyncTracker {
    peers: HashMap<PeerId, (PeerChainStatus, Option<u32>)>,
    last_sync_sent: HashMap<PeerId, Instant>,
}

impl SyncTracker {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            last_sync_sent: HashMap::new(),
        }
    }

    pub fn update_status(&mut self, peer_id: PeerId, status: PeerChainStatus, height: Option<u32>) {
        self.peers.insert(peer_id, (status, height));
    }

    pub fn status(&self, peer_id: PeerId) -> Option<PeerChainStatus> {
        self.peers.get(&peer_id).map(|(s, _)| *s)
    }

    /// Return the maximum reported height across all tracked peers.
    pub fn max_peer_height(&self) -> u32 {
        self.peers
            .values()
            .filter_map(|(_, h)| *h)
            .max()
            .unwrap_or(0)
    }

    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.peers.remove(&peer_id);
        self.last_sync_sent.remove(&peer_id);
    }

    /// Record when SyncInfo was last sent to a peer.
    pub fn record_sync_sent(&mut self, peer_id: PeerId) {
        self.last_sync_sent.insert(peer_id, Instant::now());
    }

    /// Reset peers to Unknown if no sync exchange within the threshold.
    pub fn clear_stale_statuses(&mut self, threshold: Duration) {
        let now = Instant::now();
        let stale: Vec<PeerId> = self
            .last_sync_sent
            .iter()
            .filter(|(_, &ts)| now.duration_since(ts) > threshold)
            .map(|(&id, _)| id)
            .collect();
        for id in stale {
            self.peers.insert(id, (PeerChainStatus::Unknown, None));
            self.last_sync_sent.remove(&id);
        }
    }

    /// Peers suitable for downloading block sections: Older or Equal.
    pub fn peers_for_blocks(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, (status, _))| {
                matches!(status, PeerChainStatus::Older | PeerChainStatus::Equal)
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get peer IDs suitable for downloading block sections with fallback.
    ///
    /// Primary tier: Older + Equal peers (they should have the blocks we need).
    /// Fallback tier: Unknown + Fork peers (if no Older/Equal available).
    /// Younger peers are never included (they are behind us).
    ///
    /// This mirrors the Scala `getPeersForDownloadingBlocks` two-tier strategy.
    pub fn peers_for_downloading_blocks(&self) -> Vec<PeerId> {
        let primary: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, (s, _))| matches!(s, PeerChainStatus::Older | PeerChainStatus::Equal))
            .map(|(id, _)| *id)
            .collect();
        if !primary.is_empty() {
            return primary;
        }
        // Fallback to Unknown + Fork
        self.peers
            .iter()
            .filter(|(_, (s, _))| matches!(s, PeerChainStatus::Unknown | PeerChainStatus::Fork))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Peers suitable for downloading headers: Older, Fork, Unknown.
    pub fn peers_for_headers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, (status, _))| {
                matches!(
                    status,
                    PeerChainStatus::Older | PeerChainStatus::Fork | PeerChainStatus::Unknown
                )
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Create a JSON-serializable snapshot of the current sync state.
    pub fn snapshot(&self) -> SyncTrackerSnapshot {
        SyncTrackerSnapshot {
            peers: self
                .peers
                .iter()
                .map(|(&peer_id, (status, height))| SyncTrackerPeerInfo {
                    peer_id,
                    status: format!("{:?}", status),
                    height: *height,
                })
                .collect(),
        }
    }
}

/// JSON-serializable snapshot of the sync tracker state.
#[derive(Debug, Serialize)]
pub struct SyncTrackerSnapshot {
    pub peers: Vec<SyncTrackerPeerInfo>,
}

/// Per-peer sync info within a snapshot.
#[derive(Debug, Serialize)]
pub struct SyncTrackerPeerInfo {
    pub peer_id: u64,
    pub status: String,
    pub height: Option<u32>,
}

impl Default for SyncTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify a peer based on height comparison and optional header ID comparison.
///
/// When both `their_best_id` and `our_id_at_their_height` are provided and the
/// height-based status is `Equal` or `Younger`, differing IDs indicate a fork.
/// For `Older` peers (ahead of us), we cannot verify their tip so no fork check
/// is performed.
pub fn classify_peer(
    their_height: u32,
    our_height: u32,
    their_best_id: Option<&ModifierId>,
    our_id_at_their_height: Option<&ModifierId>,
) -> PeerChainStatus {
    let height_status = if their_height > our_height {
        PeerChainStatus::Older
    } else if their_height < our_height {
        PeerChainStatus::Younger
    } else {
        PeerChainStatus::Equal
    };

    // Check for fork: if we have comparable IDs and they differ
    if matches!(height_status, PeerChainStatus::Equal | PeerChainStatus::Younger) {
        if let (Some(their_id), Some(our_id)) = (their_best_id, our_id_at_their_height) {
            if their_id != our_id {
                return PeerChainStatus::Fork;
            }
        }
    }

    height_status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_empty() {
        let tracker = SyncTracker::new();
        assert!(tracker.peers_for_blocks().is_empty());
        assert!(tracker.peers_for_headers().is_empty());
    }

    #[test]
    fn update_status_stores_peer() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Older, None);
        assert_eq!(tracker.status(1), Some(PeerChainStatus::Older));
    }

    #[test]
    fn peers_for_blocks_returns_older_and_equal() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Older, None);
        tracker.update_status(2, PeerChainStatus::Equal, None);
        tracker.update_status(3, PeerChainStatus::Younger, None);
        tracker.update_status(4, PeerChainStatus::Unknown, None);

        let block_peers = tracker.peers_for_blocks();
        assert!(block_peers.contains(&1));
        assert!(block_peers.contains(&2));
        assert!(!block_peers.contains(&3));
        assert!(!block_peers.contains(&4));
    }

    #[test]
    fn peers_for_headers_returns_older_fork_unknown() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Older, None);
        tracker.update_status(2, PeerChainStatus::Fork, None);
        tracker.update_status(3, PeerChainStatus::Unknown, None);
        tracker.update_status(4, PeerChainStatus::Younger, None);

        let header_peers = tracker.peers_for_headers();
        assert!(header_peers.contains(&1));
        assert!(header_peers.contains(&2));
        assert!(header_peers.contains(&3));
        assert!(!header_peers.contains(&4));
    }

    #[test]
    fn remove_peer_cleans_up() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Older, None);
        assert_eq!(tracker.status(1), Some(PeerChainStatus::Older));

        tracker.remove_peer(1);
        assert_eq!(tracker.status(1), None);
    }

    #[test]
    fn classify_peer_older_when_ahead() {
        // Their best height > our best height -> they are Older (ahead of us)
        let status = classify_peer(1000, 500, None, None);
        assert_eq!(status, PeerChainStatus::Older);
    }

    #[test]
    fn classify_peer_younger_when_behind() {
        let status = classify_peer(500, 1000, None, None);
        assert_eq!(status, PeerChainStatus::Younger);
    }

    #[test]
    fn classify_peer_equal_when_same() {
        let status = classify_peer(1000, 1000, None, None);
        assert_eq!(status, PeerChainStatus::Equal);
    }

    #[test]
    fn classify_peer_fork_same_height_different_id() {
        let their_id = ModifierId([1u8; 32]);
        let our_id = ModifierId([2u8; 32]);
        let status = classify_peer(1000, 1000, Some(&their_id), Some(&our_id));
        assert_eq!(status, PeerChainStatus::Fork);
    }

    #[test]
    fn classify_peer_equal_same_height_same_id() {
        let id = ModifierId([1u8; 32]);
        let status = classify_peer(1000, 1000, Some(&id), Some(&id));
        assert_eq!(status, PeerChainStatus::Equal);
    }

    #[test]
    fn classify_peer_fork_detection_with_none_ids() {
        // No IDs available — fall back to height-based classification
        let status = classify_peer(1000, 1000, None, None);
        assert_eq!(status, PeerChainStatus::Equal);
    }

    #[test]
    fn classify_peer_younger_fork() {
        let their_id = ModifierId([1u8; 32]);
        let our_id = ModifierId([2u8; 32]);
        let status = classify_peer(500, 1000, Some(&their_id), Some(&our_id));
        assert_eq!(status, PeerChainStatus::Fork);
    }

    #[test]
    fn classify_peer_older_no_fork_check() {
        // When peer is ahead, we don't check for fork (we can't know their future headers)
        let their_id = ModifierId([1u8; 32]);
        let our_id = ModifierId([2u8; 32]);
        let status = classify_peer(1000, 500, Some(&their_id), Some(&our_id));
        assert_eq!(status, PeerChainStatus::Older);
    }

    #[test]
    fn snapshot_serializes_to_json() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Older, None);
        tracker.update_status(2, PeerChainStatus::Younger, None);
        let snapshot = tracker.snapshot();
        let json = serde_json::to_value(&snapshot).unwrap();
        let peers = json["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn clear_stale_statuses_resets_to_unknown() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Younger, None);
        // Manually insert a past timestamp
        tracker
            .last_sync_sent
            .insert(1, Instant::now() - Duration::from_secs(200));

        tracker.clear_stale_statuses(Duration::from_secs(180));
        assert_eq!(tracker.status(1), Some(PeerChainStatus::Unknown));
    }

    #[test]
    fn clear_stale_statuses_preserves_fresh() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Older, None);
        tracker.record_sync_sent(1); // Fresh timestamp

        tracker.clear_stale_statuses(Duration::from_secs(180));
        assert_eq!(tracker.status(1), Some(PeerChainStatus::Older));
    }

    #[test]
    fn record_sync_sent_and_remove_peer() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Older, None);
        tracker.record_sync_sent(1);

        tracker.remove_peer(1);
        assert_eq!(tracker.status(1), None);
        // last_sync_sent should also be cleaned (verify no stale clearing for this peer)
        assert!(!tracker.last_sync_sent.contains_key(&1));
    }

    #[test]
    fn peers_for_downloading_blocks_prefers_older_equal() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Older, None);
        tracker.update_status(2, PeerChainStatus::Unknown, None);
        tracker.update_status(3, PeerChainStatus::Equal, None);
        let peers = tracker.peers_for_downloading_blocks();
        assert!(peers.contains(&1));
        assert!(peers.contains(&3));
        assert!(!peers.contains(&2)); // Unknown not included when Older/Equal available
    }

    #[test]
    fn peers_for_downloading_blocks_fallback_to_unknown_fork() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Unknown, None);
        tracker.update_status(2, PeerChainStatus::Fork, None);
        tracker.update_status(3, PeerChainStatus::Younger, None);
        let peers = tracker.peers_for_downloading_blocks();
        assert!(peers.contains(&1)); // Unknown included as fallback
        assert!(peers.contains(&2)); // Fork included as fallback
        assert!(!peers.contains(&3)); // Younger never included
    }

    #[test]
    fn peers_for_downloading_blocks_empty_when_only_younger() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Younger, None);
        let peers = tracker.peers_for_downloading_blocks();
        assert!(peers.is_empty());
    }

    #[test]
    fn peers_for_downloading_blocks_empty_when_no_peers() {
        let tracker = SyncTracker::new();
        let peers = tracker.peers_for_downloading_blocks();
        assert!(peers.is_empty());
    }

    #[test]
    fn max_peer_height_empty() {
        let tracker = SyncTracker::new();
        assert_eq!(tracker.max_peer_height(), 0);
    }

    #[test]
    fn max_peer_height_tracks_highest() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Older, Some(100));
        tracker.update_status(2, PeerChainStatus::Older, Some(200));
        tracker.update_status(3, PeerChainStatus::Equal, Some(150));
        assert_eq!(tracker.max_peer_height(), 200);
    }

    #[test]
    fn max_peer_height_ignores_none() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(1, PeerChainStatus::Unknown, None);
        tracker.update_status(2, PeerChainStatus::Older, Some(50));
        assert_eq!(tracker.max_peer_height(), 50);
    }
}

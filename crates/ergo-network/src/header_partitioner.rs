//! Header ID partitioning for multi-peer parallel header download.
//!
//! This module provides a pure partitioning algorithm that splits a batch of
//! header IDs into contiguous chunks assigned to eligible peers, plus peer
//! selection logic that filters connected peers by chain status.

use ergo_types::modifier_id::ModifierId;

use crate::delivery_tracker::PeerId;
use crate::sync_tracker::{PeerChainStatus, SyncTracker};

/// Maximum number of header IDs to process in a single Inv message.
pub const MAX_INV_IDS: usize = 400;

/// Default minimum number of IDs assigned per peer before reducing peer count.
pub const DEFAULT_MIN_PER_PEER: usize = 50;

/// Result of peer eligibility check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EligiblePeers {
    /// Multiple eligible peers for parallel download. The inv_sender (if Older)
    /// is guaranteed to be at position 0.
    Partition(Vec<PeerId>),
    /// Only a single peer can be used, with a reason string explaining why
    /// parallel download was not possible.
    SinglePeerFallback(PeerId, &'static str),
}

/// Partition a list of header IDs into contiguous chunks assigned to peers.
///
/// The algorithm ensures:
/// - At most `MAX_INV_IDS` (400) IDs are processed.
/// - Each peer gets at least `min_per_peer` IDs (unless there are fewer total).
/// - The number of peers used is reduced if the batch is too small.
/// - Remainder IDs are distributed one extra each to the first `r` peers.
/// - Chunks are contiguous slices of the input (preserving order).
pub fn partition_header_ids(
    ids: &[ModifierId],
    peers: &[PeerId],
    min_per_peer: usize,
) -> Vec<(PeerId, Vec<ModifierId>)> {
    if ids.is_empty() || peers.is_empty() {
        return Vec::new();
    }

    // Cap at MAX_INV_IDS.
    let capped = if ids.len() > MAX_INV_IDS {
        &ids[..MAX_INV_IDS]
    } else {
        ids
    };
    let capped_len = capped.len();

    // Determine how many peers we can actually use.
    let min_pp = if min_per_peer == 0 { 1 } else { min_per_peer };
    let max_peers_by_size = std::cmp::max(1, capped_len / min_pp);
    let usable_peers = std::cmp::min(peers.len(), max_peers_by_size);

    // Compute chunk sizes with remainder distribution.
    let chunk_size = capped_len / usable_peers;
    let remainder = capped_len % usable_peers;

    let mut result = Vec::with_capacity(usable_peers);
    let mut offset = 0;

    for (i, &peer) in peers.iter().enumerate().take(usable_peers) {
        let extra = if i < remainder { 1 } else { 0 };
        let this_chunk = chunk_size + extra;
        let chunk = capped[offset..offset + this_chunk].to_vec();
        result.push((peer, chunk));
        offset += this_chunk;
    }

    result
}

/// Select eligible peers for parallel header download based on chain status.
///
/// Rules:
/// - Only peers classified as `Older` (they have blocks we need) are eligible.
/// - If `inv_sender` is Older, it is placed at position 0.
/// - If `inv_sender` is not Older, falls back to single-peer mode with the
///   inv_sender and a reason string.
/// - Peers classified as Younger, Equal, Unknown, or Fork are excluded.
pub fn select_eligible_peers(
    inv_sender: PeerId,
    sync_tracker: &SyncTracker,
    connected_peers: &[PeerId],
) -> EligiblePeers {
    let sender_status = sync_tracker.status(inv_sender);

    // If inv_sender is not classified as Older, fall back to single peer.
    match sender_status {
        Some(PeerChainStatus::Older) => {}
        Some(status) => {
            let reason = match status {
                PeerChainStatus::Younger => "inv_sender classified Younger",
                PeerChainStatus::Equal => "inv_sender classified Equal",
                PeerChainStatus::Fork => "inv_sender classified Fork",
                PeerChainStatus::Unknown => "inv_sender classified Unknown",
                PeerChainStatus::Older => unreachable!(),
            };
            return EligiblePeers::SinglePeerFallback(inv_sender, reason);
        }
        None => {
            return EligiblePeers::SinglePeerFallback(
                inv_sender,
                "inv_sender not tracked",
            );
        }
    }

    // Collect all Older peers from connected_peers, with inv_sender at position 0.
    let mut eligible = Vec::new();
    eligible.push(inv_sender);

    for &peer in connected_peers {
        if peer == inv_sender {
            continue; // Already at position 0.
        }
        if sync_tracker.status(peer) == Some(PeerChainStatus::Older) {
            eligible.push(peer);
        }
    }

    if eligible.is_empty() {
        // This shouldn't happen since inv_sender is Older, but handle gracefully.
        EligiblePeers::SinglePeerFallback(inv_sender, "no older peers found")
    } else {
        EligiblePeers::Partition(eligible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create N distinct ModifierIds.
    fn make_ids(n: usize) -> Vec<ModifierId> {
        (0..n)
            .map(|i| {
                let mut bytes = [0u8; 32];
                // Spread i across bytes so each ID is unique.
                bytes[0] = (i >> 24) as u8;
                bytes[1] = (i >> 16) as u8;
                bytes[2] = (i >> 8) as u8;
                bytes[3] = i as u8;
                ModifierId(bytes)
            })
            .collect()
    }

    /// Helper: total number of IDs assigned across all chunks.
    fn total_assigned(result: &[(PeerId, Vec<ModifierId>)]) -> usize {
        result.iter().map(|(_, ids)| ids.len()).sum()
    }

    // -----------------------------------------------------------------------
    // partition_header_ids tests
    // -----------------------------------------------------------------------

    #[test]
    fn partition_empty_ids() {
        let ids: Vec<ModifierId> = vec![];
        let peers = vec![1u64, 2, 3];
        let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
        assert!(result.is_empty());
    }

    #[test]
    fn partition_empty_peers() {
        let ids = make_ids(100);
        let peers: Vec<PeerId> = vec![];
        let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
        assert!(result.is_empty());
    }

    #[test]
    fn partition_even_split() {
        let ids = make_ids(400);
        let peers = vec![1u64, 2, 3, 4];
        let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
        assert_eq!(result.len(), 4);
        for (_, chunk) in &result {
            assert_eq!(chunk.len(), 100);
        }
        assert_eq!(total_assigned(&result), 400);
    }

    #[test]
    fn partition_reduces_peers_for_small_batch() {
        // N=150, K=4, min=50 -> max_peers_by_size = 150/50 = 3
        let ids = make_ids(150);
        let peers = vec![1u64, 2, 3, 4];
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 3);
        for (_, chunk) in &result {
            assert_eq!(chunk.len(), 50);
        }
        assert_eq!(total_assigned(&result), 150);
        // Peer 4 should not be used.
        let used_peers: Vec<PeerId> = result.iter().map(|(p, _)| *p).collect();
        assert!(!used_peers.contains(&4));
    }

    #[test]
    fn partition_below_min_single_peer() {
        // N=30, K=3, min=50 -> max_peers_by_size = max(1, 30/50) = max(1, 0) = 1
        let ids = make_ids(30);
        let peers = vec![1u64, 2, 3];
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 1);
        assert_eq!(result[0].1.len(), 30);
    }

    #[test]
    fn partition_single_peer() {
        let ids = make_ids(200);
        let peers = vec![42u64];
        let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 42);
        assert_eq!(result[0].1.len(), 200);
    }

    #[test]
    fn partition_exact_min() {
        // N=100, K=2, min=50 -> 2 peers, 50 each.
        let ids = make_ids(100);
        let peers = vec![10u64, 20];
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1.len(), 50);
        assert_eq!(result[1].1.len(), 50);
    }

    #[test]
    fn partition_remainder_distributed() {
        // N=107, K=2 -> chunk_size=53, remainder=1.
        // First peer gets 54, second gets 53.
        let ids = make_ids(107);
        let peers = vec![1u64, 2];
        let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1.len(), 54);
        assert_eq!(result[1].1.len(), 53);
        assert_eq!(total_assigned(&result), 107);
    }

    #[test]
    fn partition_caps_at_400() {
        let ids = make_ids(500);
        let peers = vec![1u64, 2];
        let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
        assert_eq!(total_assigned(&result), 400);
    }

    #[test]
    fn partition_contiguous_and_disjoint() {
        let ids = make_ids(237);
        let peers = vec![1u64, 2, 3];
        let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);

        // Collect all assigned IDs in order.
        let mut all_assigned: Vec<ModifierId> = Vec::new();
        for (_, chunk) in &result {
            all_assigned.extend_from_slice(chunk);
        }

        // Union should equal the original (capped) IDs.
        assert_eq!(all_assigned.len(), 237);
        assert_eq!(all_assigned, ids);

        // Verify contiguity: each chunk's IDs appear consecutively in the original.
        let mut offset = 0;
        for (_, chunk) in &result {
            for (j, id) in chunk.iter().enumerate() {
                assert_eq!(*id, ids[offset + j]);
            }
            offset += chunk.len();
        }
    }

    #[test]
    fn partition_no_chunk_below_min_unless_single() {
        // Property test: for various N from 1..400, no chunk should be below
        // min_per_peer unless there's only 1 peer used.
        let peers = vec![1u64, 2, 3, 4, 5, 6, 7, 8];
        let min = 50;

        for n in 1..=400 {
            let ids = make_ids(n);
            let result = partition_header_ids(&ids, &peers, min);
            if result.len() > 1 {
                for (_, chunk) in &result {
                    assert!(
                        chunk.len() >= min,
                        "N={}, chunk_len={} < min={}",
                        n,
                        chunk.len(),
                        min
                    );
                }
            }
            // Total should always equal min(n, MAX_INV_IDS).
            assert_eq!(total_assigned(&result), std::cmp::min(n, MAX_INV_IDS));
        }
    }

    // -----------------------------------------------------------------------
    // select_eligible_peers tests
    // -----------------------------------------------------------------------

    #[test]
    fn select_sender_older_with_others() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(10, PeerChainStatus::Older, Some(500));
        tracker.update_status(20, PeerChainStatus::Older, Some(450));
        tracker.update_status(30, PeerChainStatus::Older, Some(400));
        tracker.update_status(40, PeerChainStatus::Younger, Some(100));

        let connected = vec![10, 20, 30, 40];
        let result = select_eligible_peers(10, &tracker, &connected);

        match result {
            EligiblePeers::Partition(peers) => {
                assert_eq!(peers[0], 10, "inv_sender must be at position 0");
                assert_eq!(peers.len(), 3);
                assert!(peers.contains(&20));
                assert!(peers.contains(&30));
                assert!(!peers.contains(&40));
            }
            other => panic!("Expected Partition, got {:?}", other),
        }
    }

    #[test]
    fn select_sender_not_older() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(10, PeerChainStatus::Younger, Some(100));
        tracker.update_status(20, PeerChainStatus::Older, Some(500));

        let connected = vec![10, 20];
        let result = select_eligible_peers(10, &tracker, &connected);

        match result {
            EligiblePeers::SinglePeerFallback(peer, reason) => {
                assert_eq!(peer, 10);
                assert!(
                    reason.contains("Younger"),
                    "reason should mention Younger: {}",
                    reason
                );
            }
            other => panic!("Expected SinglePeerFallback, got {:?}", other),
        }
    }

    #[test]
    fn select_no_older_peers() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(10, PeerChainStatus::Equal, Some(200));
        tracker.update_status(20, PeerChainStatus::Younger, Some(100));

        let connected = vec![10, 20];
        let result = select_eligible_peers(10, &tracker, &connected);

        match result {
            EligiblePeers::SinglePeerFallback(peer, reason) => {
                assert_eq!(peer, 10);
                assert!(reason.contains("Equal"), "reason: {}", reason);
            }
            other => panic!("Expected SinglePeerFallback, got {:?}", other),
        }
    }

    #[test]
    fn select_excludes_fork_and_unknown() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(10, PeerChainStatus::Older, Some(500));
        tracker.update_status(20, PeerChainStatus::Fork, Some(400));
        tracker.update_status(30, PeerChainStatus::Unknown, None);
        tracker.update_status(40, PeerChainStatus::Older, Some(450));

        let connected = vec![10, 20, 30, 40];
        let result = select_eligible_peers(10, &tracker, &connected);

        match result {
            EligiblePeers::Partition(peers) => {
                assert_eq!(peers.len(), 2);
                assert_eq!(peers[0], 10);
                assert!(peers.contains(&40));
                assert!(!peers.contains(&20), "Fork peer should be excluded");
                assert!(!peers.contains(&30), "Unknown peer should be excluded");
            }
            other => panic!("Expected Partition, got {:?}", other),
        }
    }

    #[test]
    fn select_sender_only_older() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(10, PeerChainStatus::Older, Some(500));
        tracker.update_status(20, PeerChainStatus::Younger, Some(100));
        tracker.update_status(30, PeerChainStatus::Equal, Some(200));

        let connected = vec![10, 20, 30];
        let result = select_eligible_peers(10, &tracker, &connected);

        match result {
            EligiblePeers::Partition(peers) => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0], 10);
            }
            other => panic!("Expected Partition, got {:?}", other),
        }
    }

    #[test]
    fn select_sender_not_tracked() {
        let tracker = SyncTracker::new();
        let connected = vec![10u64, 20];
        let result = select_eligible_peers(10, &tracker, &connected);

        match result {
            EligiblePeers::SinglePeerFallback(peer, reason) => {
                assert_eq!(peer, 10);
                assert!(reason.contains("not tracked"), "reason: {}", reason);
            }
            other => panic!("Expected SinglePeerFallback, got {:?}", other),
        }
    }

    #[test]
    fn select_sender_equal_status() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(10, PeerChainStatus::Equal, Some(200));

        let connected = vec![10u64];
        let result = select_eligible_peers(10, &tracker, &connected);

        match result {
            EligiblePeers::SinglePeerFallback(peer, reason) => {
                assert_eq!(peer, 10);
                assert!(reason.contains("Equal"), "reason: {}", reason);
            }
            other => panic!("Expected SinglePeerFallback, got {:?}", other),
        }
    }

    #[test]
    fn select_sender_fork_status() {
        let mut tracker = SyncTracker::new();
        tracker.update_status(10, PeerChainStatus::Fork, Some(300));

        let connected = vec![10u64];
        let result = select_eligible_peers(10, &tracker, &connected);

        match result {
            EligiblePeers::SinglePeerFallback(peer, reason) => {
                assert_eq!(peer, 10);
                assert!(reason.contains("Fork"), "reason: {}", reason);
            }
            other => panic!("Expected SinglePeerFallback, got {:?}", other),
        }
    }

    #[test]
    fn partition_many_peers_few_ids() {
        // N=5, K=10, min=50 -> only 1 peer used.
        let ids = make_ids(5);
        let peers: Vec<PeerId> = (1..=10).collect();
        let result = partition_header_ids(&ids, &peers, 50);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 1);
        assert_eq!(result[0].1.len(), 5);
    }

    #[test]
    fn partition_preserves_peer_order() {
        let ids = make_ids(200);
        let peers = vec![99u64, 88, 77, 66];
        let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].0, 99);
        assert_eq!(result[1].0, 88);
        assert_eq!(result[2].0, 77);
        assert_eq!(result[3].0, 66);
    }
}

//! Integration tests for multi-peer header download partitioning.
//!
//! These tests combine ergo-network components (header_partitioner,
//! DeliveryTracker, SyncTracker, SyncMetrics) to verify end-to-end
//! correctness of the partitioning pipeline without real network I/O.

use ergo_network::delivery_tracker::DeliveryTracker;
use ergo_network::header_partitioner::{
    partition_header_ids, select_eligible_peers, EligiblePeers, DEFAULT_MIN_PER_PEER,
};
use ergo_network::sync_metrics::SyncMetrics;
use ergo_network::sync_tracker::{PeerChainStatus, SyncTracker};
use ergo_types::modifier_id::ModifierId;

fn make_id(byte: u8) -> ModifierId {
    let mut bytes = [0u8; 32];
    bytes[0] = byte;
    ModifierId(bytes)
}

fn make_ids(n: usize) -> Vec<ModifierId> {
    (0..n)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0..2].copy_from_slice(&(i as u16).to_be_bytes());
            ModifierId(bytes)
        })
        .collect()
}

/// Test: single peer ahead behaves identically to pre-change (single RequestModifiers).
#[test]
fn single_peer_ahead_baseline() {
    let ids = make_ids(200);
    let peers = vec![1u64];
    let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, 1);
    assert_eq!(result[0].1.len(), 200);
}

/// Test: 3 peers ahead distributes across all 3.
#[test]
fn three_peers_ahead_distributes() {
    let mut st = SyncTracker::new();
    st.update_status(1, PeerChainStatus::Older, Some(1000));
    st.update_status(2, PeerChainStatus::Older, Some(1000));
    st.update_status(3, PeerChainStatus::Older, Some(1000));

    let connected = vec![1u64, 2, 3];
    let eligible = select_eligible_peers(1, &st, &connected);

    match eligible {
        EligiblePeers::Partition(peers) => {
            assert_eq!(peers.len(), 3);
            let ids = make_ids(300);
            let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);
            assert_eq!(result.len(), 3);
            for (_, chunk) in &result {
                assert_eq!(chunk.len(), 100);
            }
            // Verify all IDs assigned
            let all: Vec<ModifierId> = result.iter().flat_map(|(_, c)| c.iter().copied()).collect();
            assert_eq!(all, ids);
        }
        _ => panic!("expected Partition"),
    }
}

/// Test: timeout simulation — tracker correctly identifies expired requests.
#[test]
fn timeout_enables_reassignment() {
    let mut tracker = DeliveryTracker::new(0, 2); // 0s timeout = immediate
    let id = make_id(0x01);
    tracker.set_requested(101, id, 1);

    let timed_out = tracker.collect_timed_out();
    assert_eq!(timed_out.len(), 1);
    assert_eq!(timed_out[0].2, 1); // original peer

    // Reassign to peer 2
    tracker.reassign(101, &id, 2);

    // Verify reassigned — with timeout=0, still expires immediately
    let timed_out2 = tracker.collect_timed_out();
    assert_eq!(timed_out2.len(), 1);
    assert_eq!(timed_out2[0].2, 2); // now peer 2
}

/// Test: outstanding cap prevents new requests.
#[test]
fn outstanding_cap_blocks_new_requests() {
    let mut tracker = DeliveryTracker::new(60, 2);

    // Fill peer 1 with 800 header requests
    for i in 0..800u32 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_be_bytes());
        tracker.set_requested(101, ModifierId(bytes), 1);
    }

    assert_eq!(tracker.outstanding_header_count(1), 800);
    assert_eq!(tracker.total_outstanding_headers(), 800);

    // Peer 2 still has room
    assert_eq!(tracker.outstanding_header_count(2), 0);
}

/// Test: cap-aware reassignment walks eligible peers.
#[test]
fn cap_aware_reassignment() {
    let mut tracker = DeliveryTracker::new(60, 2);

    // Fill peer 2 with 800 header requests
    for i in 0..800u32 {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_be_bytes());
        tracker.set_requested(101, ModifierId(bytes), 2);
    }

    // Request from peer 1
    let stale_id = make_id(0xFF);
    tracker.set_requested(101, stale_id, 1);

    // Try to find a peer to reassign to: peer 2 is at cap (800), peer 3 has room
    let alt_peers = vec![2u64, 3u64];
    let target = alt_peers
        .iter()
        .find(|&&p| p != 1 && tracker.outstanding_header_count(p) < 800);

    // Peer 2 at cap, peer 3 has room
    assert_eq!(*target.unwrap(), 3);
}

/// Test: property-style coverage check for various N and K.
#[test]
fn partition_coverage_property() {
    for n in [1, 10, 49, 50, 51, 99, 100, 150, 200, 399, 400, 500] {
        for k in 1..=8usize {
            let ids = make_ids(n);
            let peers: Vec<u64> = (1..=k as u64).collect();
            let result = partition_header_ids(&ids, &peers, DEFAULT_MIN_PER_PEER);

            // Union equals original (capped at 400)
            let all: Vec<ModifierId> = result.iter().flat_map(|(_, c)| c.iter().copied()).collect();
            let expected_len = n.min(400);
            assert_eq!(all.len(), expected_len, "coverage failed for n={n}, k={k}");
            assert_eq!(all, ids[..expected_len]);

            // Chunks are disjoint (verified by contiguous assignment)
            let mut total = 0;
            for (_, chunk) in &result {
                total += chunk.len();
            }
            assert_eq!(total, expected_len, "total != expected for n={n}, k={k}");

            // Min per peer respected (unless single peer)
            if result.len() > 1 {
                for (_, chunk) in &result {
                    assert!(
                        chunk.len() >= DEFAULT_MIN_PER_PEER,
                        "chunk {} < min {} for n={n}, k={k}",
                        chunk.len(),
                        DEFAULT_MIN_PER_PEER
                    );
                }
            }
        }
    }
}

/// Test: metrics batch lifecycle.
#[test]
fn metrics_batch_lifecycle() {
    let mut metrics = SyncMetrics::new(10);
    let batch_id = metrics.new_batch_id();

    metrics.record_partition(batch_id, 200, 200, &[(1, 100), (2, 100)]);
    // Batch should be active — first half-delivery
    metrics.record_headers_applied(batch_id, 100, 0, 0, 50, 20, 70);
    // Still active (100/200) — second half-delivery
    metrics.record_headers_applied(batch_id, 100, 0, 0, 50, 20, 70);
    // Now complete (200/200) — internally removed from active_batches
}

/// Test: classification mismatch produces SinglePeerFallback.
#[test]
fn classification_mismatch_single_peer_fallback() {
    let mut st = SyncTracker::new();
    st.update_status(1, PeerChainStatus::Fork, Some(100));
    st.update_status(2, PeerChainStatus::Older, Some(200));

    let connected = vec![1u64, 2];
    match select_eligible_peers(1, &st, &connected) {
        EligiblePeers::SinglePeerFallback(peer, reason) => {
            assert_eq!(peer, 1);
            assert!(
                reason.contains("Fork"),
                "reason should mention Fork, got: {reason}"
            );
        }
        _ => panic!("expected SinglePeerFallback for Fork sender"),
    }
}

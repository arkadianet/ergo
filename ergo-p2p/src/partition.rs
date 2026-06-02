//! Pure partitioning of pending download IDs across peers.
//!
//! Inspired by Scala's `ElementPartitioner.distribute` (called from
//! `ErgoNodeViewSynchronizer.requestDownload`), this module produces one
//! bucket per (peer, modifier_type) pair. The caller emits one
//! `RequestModifier` per non-empty bucket. This is not a bit-for-bit
//! port — Scala's iteration order depends on JVM HashMap state, and we
//! intentionally diverge on determinism and remainder policy.
//!
//! Deliberate departures from Scala:
//! 1. **Deterministic input ordering.** Peers are pre-sorted by the
//!    caller (by `SocketAddr`); this makes oracle assertions exact
//!    rather than "happens to match JVM HashMap iteration today".
//! 2. **Rotation cursor.** The caller threads a `round: u64` counter so
//!    the first peer in the sorted list is not permanently the first
//!    assignee.
//! 3. **Remainder-for-liveness.** When total modifiers < N*max, buckets
//!    may be smaller than Scala's intended minimum. Small queues still
//!    make progress.
//!
//! Types are concrete (`PeerId`, `u8` type id, `[u8; 32]` modifier id)
//! — no generics.
//!
//! # Invariants (enforced by tests)
//! - Within one call, no modifier ID appears in more than one bucket.
//! - Within a (peer, type) bucket, IDs retain input order.
//! - Bucket emission order: types ascending (tx 102 before ext 108),
//!   within a type peers in rotated sorted order.
//! - If total IDs of a type exceed `peers.len() * max_per_bucket`, the
//!   overflow is NOT emitted this call. The caller (coordinator) MUST
//!   re-invoke on the next round; idempotency via DeliveryTracker's
//!   status ensures already-Requested IDs are skipped, leaving the
//!   overflow for partitioning. Overflow recovery is tested explicitly.
//! - Empty `peers` input returns empty output (no modulo-by-zero panic).

use std::collections::BTreeMap;

use crate::peer::PeerId;

/// One bucket: all the modifier IDs of a single type to request from one peer.
pub type Bucket = ((PeerId, u8), Vec<[u8; 32]>);

/// Configuration for `distribute`.
///
/// `max_per_bucket` caps one RequestModifier payload's ID count; it must
/// not exceed `MAX_INV_OBJECTS` (400) or the payload is rejected at
/// serialization.
///
/// Scala's bucket range is 8/12 per peer, assuming many connected peers.
/// In a single-peer scenario, 12/round starves a 192-block download
/// window — 16 rounds to enqueue. Callers should set `max_per_bucket`
/// adaptively based on peer count:
/// - N peers ≤ 2: ~100-200 (one large Inv batch keeps the pipe full)
/// - N peers ≥ 3: 12 (Scala-style spread)
///
/// `SyncCoordinator::request_missing_sections_bucketed` applies the
/// adaptive policy; this struct just passes it through.
#[derive(Debug, Clone, Copy)]
pub struct BucketConfig {
    pub max_per_bucket: usize,
}

impl Default for BucketConfig {
    /// Scala-like 12 per bucket. Coordinator overrides based on peer
    /// count (single-peer sync needs a much larger cap to avoid
    /// starving the download window).
    fn default() -> Self {
        Self { max_per_bucket: 12 }
    }
}

/// Partition a set of pending modifier IDs (grouped by type) across a
/// sorted peer list. `round` advances a rotation cursor so the first
/// peer in the sorted list isn't always the first assignee; callers
/// typically increment per-call.
///
/// # Edge cases
/// - Empty `peers`: returns empty Vec, never panics (no mod by zero).
/// - Empty `modifiers_by_type`: returns empty Vec.
/// - `peers.len() < min_per_bucket`-implied demand: buckets may be
///   `< min_per_bucket` (liveness over strict sizing).
/// - A modifier count `> peers.len() * max_per_bucket` for one type:
///   remainder is NOT emitted; caller should re-invoke next round
///   once the first batch is in-flight (matches Scala: one bucket per
///   peer per call).
///
/// # Determinism
/// Peers are iterated in input order. Callers must pre-sort (typically
/// by `SocketAddr`). Types are iterated in ascending `u8` order via
/// `BTreeMap`.
pub fn distribute(
    peers: &[PeerId],
    modifiers_by_type: &BTreeMap<u8, Vec<[u8; 32]>>,
    round: u64,
    cfg: BucketConfig,
) -> Vec<Bucket> {
    if peers.is_empty() || modifiers_by_type.values().all(|v| v.is_empty()) {
        return Vec::new();
    }

    // Rotation cursor: slide the peer list so peer index 0 of the
    // emitted buckets is `round % peers.len()` of the input list. Pure
    // shift — the relative order of peers is preserved.
    let n = peers.len();
    let start = (round as usize) % n;
    let rotated: Vec<PeerId> = peers[start..]
        .iter()
        .chain(peers[..start].iter())
        .copied()
        .collect();

    let mut out: Vec<Bucket> = Vec::new();

    // Iterate types in ascending u8 order (BTreeMap). Emit all buckets
    // for type T before moving to T+1, so the overall order is
    // (peer_i, t_low), (peer_j, t_low), ..., (peer_i, t_high), ...
    // This is the shape request_missing_sections already documents:
    // tx-batch precedes extension-batch within a single coordinator
    // call. With multiple peers, we preserve type-ordering globally.
    for (&type_id, ids) in modifiers_by_type.iter() {
        if ids.is_empty() {
            continue;
        }
        let mut cursor = 0usize;
        let mut peer_idx = 0usize;
        while cursor < ids.len() && peer_idx < rotated.len() {
            let peer = rotated[peer_idx];
            let remaining = ids.len() - cursor;
            let take = remaining.min(cfg.max_per_bucket);
            if take == 0 {
                break;
            }
            let bucket_ids: Vec<[u8; 32]> = ids[cursor..cursor + take].to_vec();
            out.push(((peer, type_id), bucket_ids));
            cursor += take;
            peer_idx += 1;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn peer(port: u16) -> PeerId {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn mk(v: u8) -> [u8; 32] {
        [v; 32]
    }

    const TX: u8 = 102;
    const EXT: u8 = 108;

    fn make_mods(types: &[(u8, usize)]) -> BTreeMap<u8, Vec<[u8; 32]>> {
        let mut out = BTreeMap::new();
        let mut counter = 1u8;
        for &(t, n) in types {
            let ids: Vec<_> = (0..n)
                .map(|_| {
                    let id = mk(counter);
                    counter += 1;
                    id
                })
                .collect();
            out.insert(t, ids);
        }
        out
    }

    #[test]
    fn distribute_degenerate_empty_peers() {
        // Safety: must not panic on modulo by zero.
        let mods = make_mods(&[(TX, 10)]);
        let out = distribute(&[], &mods, 0, BucketConfig::default());
        assert!(out.is_empty(), "empty peers → empty buckets");

        let out = distribute(&[], &mods, 42, BucketConfig::default());
        assert!(
            out.is_empty(),
            "empty peers with non-zero round → still empty"
        );
    }

    #[test]
    fn distribute_degenerate_empty_modifiers() {
        let peers = vec![peer(9030), peer(9031)];
        let mods = BTreeMap::new();
        let out = distribute(&peers, &mods, 0, BucketConfig::default());
        assert!(out.is_empty(), "empty modifiers → empty buckets");
    }

    #[test]
    fn distribute_degenerate_all_empty_type_entries() {
        let peers = vec![peer(9030), peer(9031)];
        let mut mods = BTreeMap::new();
        mods.insert(TX, Vec::new());
        mods.insert(EXT, Vec::new());
        let out = distribute(&peers, &mods, 0, BucketConfig::default());
        assert!(
            out.is_empty(),
            "map populated but all vecs empty → empty buckets, got {out:?}"
        );
    }

    #[test]
    fn distribute_three_peers_twenty_four_modifiers_exact_shape() {
        // 3 peers, 12 tx + 12 ext, min 8 max 12 → expect 2 buckets per
        // type (2 peers × 12 = 24 covers all 12 per type, 1 peer goes
        // empty per type). With max=12, peer 0 gets 12 tx, peer 1 gets
        // 0 (already satisfied). Actually — peer 0 gets 12 (all),
        // remaining 0, so peer 1 + 2 get nothing for tx. Same for ext.
        let peers = vec![peer(9030), peer(9031), peer(9032)];
        let mods = make_mods(&[(TX, 12), (EXT, 12)]);
        let out = distribute(&peers, &mods, 0, BucketConfig::default());

        // 12 tx / 12-per-peer = 1 peer takes the whole tx bucket.
        // Same for ext. So 2 buckets total.
        assert_eq!(
            out.len(),
            2,
            "expected 2 buckets, got {}: {out:?}",
            out.len()
        );
        // tx before ext
        assert_eq!(out[0].0 .1, TX);
        assert_eq!(out[1].0 .1, EXT);
        // peer 0 of the rotated list (round=0 → start=0 → rotated = [p0, p1, p2])
        assert_eq!(out[0].0 .0, peers[0]);
        assert_eq!(out[1].0 .0, peers[0]);
        assert_eq!(out[0].1.len(), 12);
        assert_eq!(out[1].1.len(), 12);
    }

    #[test]
    fn distribute_larger_pending_fills_multiple_peers() {
        // 3 peers, 30 tx. max=12 means peer 0 gets 12, peer 1 gets 12,
        // peer 2 gets 6. 3 buckets. Remaining 0.
        let peers = vec![peer(9030), peer(9031), peer(9032)];
        let mods = make_mods(&[(TX, 30)]);
        let out = distribute(&peers, &mods, 0, BucketConfig::default());
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].1.len(), 12);
        assert_eq!(out[1].1.len(), 12);
        assert_eq!(out[2].1.len(), 6);
        // No duplicate IDs across buckets.
        let mut seen = std::collections::HashSet::new();
        for (_, ids) in &out {
            for id in ids {
                assert!(seen.insert(*id), "duplicate ID across buckets: {id:?}");
            }
        }
        // Every input ID appears in output (complete coverage up to capacity).
        assert_eq!(seen.len(), 30);
    }

    #[test]
    fn distribute_overflow_defers_remainder_to_next_call() {
        // 2 peers, 40 tx, max=12 → first call emits peer 0: 12, peer
        // 1: 12. Remaining 16 are NOT dropped forever — the caller
        // (coordinator) sees them again on the next call because
        // DeliveryTracker's Requested-status filter only excludes
        // already-registered IDs. Partition is single-call; overflow
        // recovery is the caller's contract.
        let peers = vec![peer(9030), peer(9031)];
        let mods = make_mods(&[(TX, 40)]);
        let first = distribute(&peers, &mods, 0, BucketConfig::default());
        assert_eq!(first.len(), 2);
        assert_eq!(
            first.iter().map(|(_, ids)| ids.len()).sum::<usize>(),
            24,
            "first call emits 24 IDs (2 peers × max 12)"
        );

        // Simulate the coordinator calling again with the 16 that
        // weren't in the first two buckets. With 16 remaining, both
        // peers get another 8 each (cap=12 not hit since 16<24).
        let first_ids: std::collections::HashSet<_> = first
            .iter()
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();
        let remaining: Vec<[u8; 32]> = mods[&TX]
            .iter()
            .filter(|id| !first_ids.contains(*id))
            .copied()
            .collect();
        assert_eq!(remaining.len(), 16, "16 IDs deferred, not dropped");

        let mut mods2 = BTreeMap::new();
        mods2.insert(TX, remaining);
        let second = distribute(&peers, &mods2, 1, BucketConfig::default());
        let second_total: usize = second.iter().map(|(_, ids)| ids.len()).sum();
        assert_eq!(second_total, 16, "second call covers all 16 remaining");
    }

    #[test]
    fn distribute_remainder_policy_small_pending_still_emits() {
        // 3 peers, 5 tx, min=8 max=12. Total < min, but liveness
        // requires emission. Single bucket with all 5 IDs.
        let peers = vec![peer(9030), peer(9031), peer(9032)];
        let mods = make_mods(&[(TX, 5)]);
        let out = distribute(&peers, &mods, 0, BucketConfig::default());
        assert_eq!(out.len(), 1, "small pending → one partial bucket, not zero");
        assert_eq!(out[0].1.len(), 5);
    }

    #[test]
    fn distribute_rotation_cursor_advances_first_peer() {
        // 3 peers, 5 tx. Round advances first-peer in output.
        let peers = vec![peer(9030), peer(9031), peer(9032)];
        let mods = make_mods(&[(TX, 5)]);

        let r0 = distribute(&peers, &mods, 0, BucketConfig::default());
        let r1 = distribute(&peers, &mods, 1, BucketConfig::default());
        let r2 = distribute(&peers, &mods, 2, BucketConfig::default());

        assert_eq!(r0[0].0 .0, peers[0]);
        assert_eq!(r1[0].0 .0, peers[1]);
        assert_eq!(r2[0].0 .0, peers[2]);
    }

    #[test]
    fn distribute_type_ordering_tx_before_extension() {
        // Globally: all tx buckets emitted before any ext bucket.
        let peers = vec![peer(9030), peer(9031)];
        let mods = make_mods(&[(TX, 15), (EXT, 15)]);
        let out = distribute(&peers, &mods, 0, BucketConfig::default());

        let first_ext_idx = out
            .iter()
            .position(|((_, t), _)| *t == EXT)
            .expect("some ext bucket must exist");
        let all_before_are_tx = out[..first_ext_idx].iter().all(|((_, t), _)| *t == TX);
        assert!(
            all_before_are_tx,
            "tx buckets must precede ext buckets, got {:?}",
            out.iter().map(|((_, t), _)| *t).collect::<Vec<_>>()
        );
    }

    #[test]
    fn distribute_preserves_input_id_order_within_bucket() {
        // IDs in make_mods are mk(1), mk(2), ... in order. Output
        // buckets should preserve that order within each bucket.
        let peers = vec![peer(9030)];
        let mods = make_mods(&[(TX, 10)]);
        let out = distribute(&peers, &mods, 0, BucketConfig::default());
        assert_eq!(out.len(), 1);
        let expected: Vec<_> = (1..=10u8).map(mk).collect();
        assert_eq!(out[0].1, expected);
    }

    #[test]
    fn distribute_no_duplicate_ids_across_buckets() {
        // Invariant: every input ID appears in AT MOST one bucket.
        let peers = vec![peer(9030), peer(9031), peer(9032)];
        let mods = make_mods(&[(TX, 20), (EXT, 20)]);
        let out = distribute(&peers, &mods, 0, BucketConfig::default());

        let mut seen = std::collections::HashSet::new();
        for (_, ids) in &out {
            for id in ids {
                assert!(seen.insert(*id), "duplicate ID in output: {id:?}");
            }
        }
    }

    #[test]
    fn distribute_single_peer_degenerate() {
        // 1 peer + 5 tx + 5 ext → 2 buckets, both to that peer.
        let peers = vec![peer(9030)];
        let mods = make_mods(&[(TX, 5), (EXT, 5)]);
        let out = distribute(&peers, &mods, 0, BucketConfig::default());
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|((p, _), _)| *p == peers[0]));
    }
}

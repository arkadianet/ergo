//! Step C — per-peer SyncInfo crafting from the verified anchor map.
//!
//! Scala's `compareV1` / `continuationIdsV1` only requires **one** ID
//! in `lastHeaderIds` to be on the peer's best chain to classify the
//! comparison as `Fork` and respond with up to `MaxInvObjects = 400`
//! novel header IDs starting from that point. By sending each peer a
//! single anchor ID it has on disk (sourced from the REST-built
//! `AnchorMap`), we get 400 novel IDs per request instead of replaying
//! our 1000-ID overlap with whatever the peer already served us.
//!
//! This module owns only the *assignment* state — anchor selection,
//! per-peer claim tracking, reassignment-on-stall. The caller
//! (action loop) decides when to invoke us and is responsible for
//! actually shipping the crafted SyncInfo.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ergo_p2p::peer::PeerId;

use crate::anchor_map::ANCHOR_INTERVAL;

/// Maximum age of an outstanding `(peer, anchor_height)` claim before
/// the scheduler reclaims the slot. Per design constants. Effective
/// dispatch cadence per peer is `max(per-peer-throttle, sync_tick) =
/// max(1s, 3s) = 3s`, so a peer assigned an anchor has roughly 3
/// dispatch opportunities to deliver before the slot is reclaimed.
pub const ANCHOR_REASSIGN_TIMEOUT: Duration = Duration::from_secs(10);

/// Defense-in-depth cap: never assign an anchor whose 400-ID response
/// would land entirely outside the executor's
/// `ORPHAN_HEADER_IBD_LOOKAHEAD` window (currently 60,000 — sized
/// for ~60-peer fanout WITH anchor spacing per Step D follow-up).
/// Headers past that window are dropped by the orphan buffer with
/// a "deferring far-ahead orphan" log — wasted bandwidth. Setting
/// this to `lookahead - ANCHOR_INTERVAL` guarantees the *highest*
/// ID in the response (anchor + 399) still falls inside the
/// lookahead.
///
/// The lookahead constant lives in `ergo-sync/src/executor.rs` and
/// is not `pub` (kept private to that crate). We mirror its current
/// value here; if it changes there, this constant must be reviewed.
/// The pair is enforced empirically by the runtime: too small here
/// throttles Step C+D parallelism; too large allows wasted bandwidth.
pub const MAX_ANCHOR_AHEAD: u32 = 60_000 - ANCHOR_INTERVAL;

/// Minimum height-spacing between two concurrent peer assignments.
/// Live observation (2026-05-05) showed that consecutive anchors
/// (tip+400, tip+800, tip+1200, …) cause slow peers' responses to
/// arrive AFTER tip has moved past their slice — most of their
/// 400-ID response then dedup'd as already-have. Effective active
/// peers dropped to 1-2 per tick despite 60 connected.
///
/// Spacing peers SPACING apart guarantees a slow peer's slice is
/// at least SPACING headers ahead of any faster peer's already-
/// installed work, so the response stays useful even with 5s+ RTT
/// variance. With SPACING=4000 (10 anchor intervals) and
/// MAX_ANCHOR_AHEAD=59600, up to ~14 peers can hold concurrent
/// claims (59600 / 4000) — well above the 1-2 effective active
/// peers we measured pre-spacing.
pub const ANCHOR_SPACING: u32 = 4_000;

/// Per-tick counter snapshot drained by the heartbeat (same pattern
/// as `AnchorCounters`). `is_active()` lets the heartbeat suppress
/// silent ticks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerCounters {
    pub anchor_assignments: u64,
    pub anchor_reassignments: u64,
}

impl SchedulerCounters {
    pub fn is_active(&self) -> bool {
        self.anchor_assignments > 0 || self.anchor_reassignments > 0
    }
}

#[derive(Default)]
pub struct AnchorScheduler {
    /// anchor_height -> (peer_holding_claim, assigned_at).
    ///
    /// **Multiplicity**: a single peer can hold many concurrent
    /// claims — by design, so a fast peer naturally pipelines through
    /// several anchors per `ANCHOR_REASSIGN_TIMEOUT` window. Reclaim
    /// fires only when `now - assigned_at > timeout` (strict), so a
    /// peer dispatched at `t = 0, 3, 6, 9` (3s tick, 10s timeout) is
    /// still holding all four claims at `t = 9` — the `t = 0` claim
    /// is reclaimed at `t = 10.x`. Resource bound is therefore
    /// `min(verified.len(), peer_count * ⌈timeout / cadence⌉)`. With
    /// 5 REST peers, 10s timeout, and a 3s outer dispatch tick:
    /// `5 × ⌈10/3⌉ = 5 × 4 = 20` in-flight claims max — well below
    /// `verified.len()` (~4500 at full fill) and below the
    /// connection cap.
    assignments: HashMap<u32, (PeerId, Instant)>,
    counters: SchedulerCounters,
}

impl AnchorScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pick the smallest verified anchor height strictly above
    /// `our_tip` that no peer is currently working on, claim it for
    /// `peer`, and return `(height, header_id)` for the caller to
    /// pack into a single-element `lastHeaderIds`. Returns `None`
    /// when there is nothing left to assign.
    ///
    /// Stale claims (older than `ANCHOR_REASSIGN_TIMEOUT`) are
    /// reclaimed before selection so a dead-peer assignment cannot
    /// permanently lock an anchor. Below-tip assignments are also
    /// dropped — once we've validated past an anchor's height it's
    /// no longer useful.
    pub fn assign_for_peer(
        &mut self,
        peer: PeerId,
        our_tip: u32,
        verified: &HashMap<u32, [u8; 32]>,
        now: Instant,
    ) -> Option<(u32, [u8; 32])> {
        // Reclaim stale and below-tip anchors. `anchor_reassignments`
        // counts only timeouts (the design metric); below-tip drops
        // are a normal effect of forward progress, not a stall.
        let mut to_remove: Vec<u32> = Vec::new();
        let mut stale_count: u64 = 0;
        for (h, (_p, t)) in self.assignments.iter() {
            if *h <= our_tip {
                to_remove.push(*h);
            } else if now.duration_since(*t) > ANCHOR_REASSIGN_TIMEOUT {
                to_remove.push(*h);
                stale_count += 1;
            }
        }
        for h in &to_remove {
            self.assignments.remove(h);
        }
        self.counters.anchor_reassignments = self
            .counters
            .anchor_reassignments
            .saturating_add(stale_count);

        // Pick the smallest verified anchor above our tip that is
        // (a) currently unassigned, (b) within `MAX_ANCHOR_AHEAD`
        // of tip, AND (c) at least `ANCHOR_SPACING` away from every
        // other in-flight assignment. Constraint (c) prevents two
        // concurrent peers from being given consecutive anchors
        // whose responses would overlap (slow-peer-arrives-after-
        // fast-peer pattern observed live: 1-2 effective peers
        // despite 60 in-flight claims).
        //
        // Linear scan — verified is bounded by ~4500 on mainnet
        // and assignments by ~MAX_ANCHOR_AHEAD/ANCHOR_SPACING ≈ 14,
        // so this is cheap relative to network IO.
        let max_height = our_tip.saturating_add(MAX_ANCHOR_AHEAD);
        let mut best: Option<u32> = None;
        for h in verified.keys() {
            if *h <= our_tip {
                continue;
            }
            if *h > max_height {
                continue;
            }
            if self.assignments.contains_key(h) {
                continue;
            }
            // Spacing constraint: skip if too close to an
            // assignment held by a DIFFERENT peer. Same-peer
            // pipelining is allowed: per-peer pipelining of 2-3
            // anchored SyncInfos in flight amortizes per-peer RTT.
            // With spacing applied only across distinct peers, each
            // peer can hold a contiguous slice of K anchors while
            // peer-to-peer slices still stay disjoint.
            if self
                .assignments
                .iter()
                .any(|(a, (claimer, _))| *claimer != peer && h.abs_diff(*a) < ANCHOR_SPACING)
            {
                continue;
            }
            best = Some(match best {
                None => *h,
                Some(b) if *h < b => *h,
                Some(b) => b,
            });
        }
        let height = best?;
        let id = *verified.get(&height)?;
        self.assignments.insert(height, (peer, now));
        self.counters.anchor_assignments = self.counters.anchor_assignments.saturating_add(1);
        Some((height, id))
    }

    /// On peer disconnect — drop every claim held by `peer` so the
    /// anchors return to the pool immediately rather than waiting
    /// out the reassignment timeout.
    pub fn forget_peer(&mut self, peer: PeerId) {
        self.assignments.retain(|_, (p, _)| *p != peer);
    }

    /// Drain counters for the heartbeat. Same semantics as
    /// `AnchorMap::take_counters` — read-and-reset.
    pub fn take_counters(&mut self) -> SchedulerCounters {
        std::mem::take(&mut self.counters)
    }

    pub fn assigned_count(&self) -> usize {
        self.assignments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn peer(s: &str) -> PeerId {
        s.parse::<SocketAddr>().unwrap()
    }

    fn id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn map(entries: &[(u32, u8)]) -> HashMap<u32, [u8; 32]> {
        entries.iter().map(|(h, b)| (*h, id(*b))).collect()
    }

    /// Spacing-respecting test fixture: anchors placed at multiples of
    /// ANCHOR_SPACING so the spacing constraint doesn't filter them out.
    fn spaced(seeds: &[u8]) -> HashMap<u32, [u8; 32]> {
        seeds
            .iter()
            .enumerate()
            .map(|(i, b)| (((i + 1) as u32) * ANCHOR_SPACING, id(*b)))
            .collect()
    }

    #[test]
    fn assigns_smallest_above_tip() {
        let mut s = AnchorScheduler::new();
        let v = spaced(&[1, 2, 3]); // ANCHOR_SPACING, 2×, 3×
        let now = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        // tip = ANCHOR_SPACING+1 → first slot now-below, second is the smallest above
        assert_eq!(
            s.assign_for_peer(p1, ANCHOR_SPACING + 1, &v, now),
            Some((2 * ANCHOR_SPACING, id(2)))
        );
    }

    #[test]
    fn returns_none_when_no_anchors_above_tip() {
        let mut s = AnchorScheduler::new();
        let v = map(&[(ANCHOR_SPACING, 1)]);
        let now = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        assert_eq!(s.assign_for_peer(p1, ANCHOR_SPACING + 1, &v, now), None);
    }

    #[test]
    fn does_not_double_assign() {
        let mut s = AnchorScheduler::new();
        let v = spaced(&[1, 2]);
        let now = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        let p2 = peer("5.6.7.8:9030");
        assert_eq!(
            s.assign_for_peer(p1, 0, &v, now),
            Some((ANCHOR_SPACING, id(1)))
        );
        // p2 must NOT get the same height as p1 (already assigned)
        // and must respect ANCHOR_SPACING from it. The 2× anchor is
        // exactly ANCHOR_SPACING away, which IS allowed (strict <).
        assert_eq!(
            s.assign_for_peer(p2, 0, &v, now),
            Some((2 * ANCHOR_SPACING, id(2)))
        );
    }

    #[test]
    fn enforces_spacing_between_concurrent_assignments() {
        let mut s = AnchorScheduler::new();
        // Three close-together anchors: SPACING, SPACING+400,
        // SPACING+800. After p1 takes the first, p2 cannot take
        // either of the close ones.
        let v = map(&[
            (ANCHOR_SPACING, 1),
            (ANCHOR_SPACING + 400, 2),
            (ANCHOR_SPACING + 800, 3),
        ]);
        let now = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        let p2 = peer("5.6.7.8:9030");
        assert_eq!(
            s.assign_for_peer(p1, 0, &v, now),
            Some((ANCHOR_SPACING, id(1)))
        );
        // p2 sees no eligible anchor — the only options are within
        // ANCHOR_SPACING of p1's claim.
        assert_eq!(s.assign_for_peer(p2, 0, &v, now), None);
    }

    #[test]
    fn reassigns_after_timeout() {
        let mut s = AnchorScheduler::new();
        let v = map(&[(ANCHOR_SPACING, 1)]);
        let t0 = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        let p2 = peer("5.6.7.8:9030");
        assert_eq!(
            s.assign_for_peer(p1, 0, &v, t0),
            Some((ANCHOR_SPACING, id(1)))
        );
        // Within timeout — p2 still locked out
        let t_warm = t0 + ANCHOR_REASSIGN_TIMEOUT - Duration::from_secs(1);
        assert_eq!(s.assign_for_peer(p2, 0, &v, t_warm), None);
        // After timeout — p2 reclaims
        let t_late = t0 + ANCHOR_REASSIGN_TIMEOUT + Duration::from_secs(1);
        assert_eq!(
            s.assign_for_peer(p2, 0, &v, t_late),
            Some((ANCHOR_SPACING, id(1)))
        );
        let c = s.take_counters();
        assert_eq!(c.anchor_assignments, 2);
        assert_eq!(c.anchor_reassignments, 1);
    }

    #[test]
    fn drops_below_tip_silently() {
        let mut s = AnchorScheduler::new();
        let v = spaced(&[1, 2]);
        let now = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        assert_eq!(
            s.assign_for_peer(p1, 0, &v, now),
            Some((ANCHOR_SPACING, id(1)))
        );
        // Tip advances past the assigned anchor — slot freed,
        // counted as forward-progress not as reassignment. The
        // SECOND anchor is now the smallest above tip and the
        // first slot is below-tip-cleared (not a spacing blocker).
        let p2 = peer("5.6.7.8:9030");
        assert_eq!(
            s.assign_for_peer(p2, ANCHOR_SPACING + 1, &v, now),
            Some((2 * ANCHOR_SPACING, id(2)))
        );
        let c = s.take_counters();
        assert_eq!(c.anchor_assignments, 2);
        assert_eq!(c.anchor_reassignments, 0);
    }

    #[test]
    fn forget_peer_drops_all_claims() {
        let mut s = AnchorScheduler::new();
        let v = spaced(&[1, 2]);
        let now = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        let p2 = peer("5.6.7.8:9030");
        // Two ANCHOR_SPACING-apart anchors — both available.
        assert_eq!(
            s.assign_for_peer(p1, 0, &v, now),
            Some((ANCHOR_SPACING, id(1)))
        );
        assert_eq!(
            s.assign_for_peer(p1, 0, &v, now),
            Some((2 * ANCHOR_SPACING, id(2)))
        );
        // p2 sees nothing free (both held by p1, spacing exhausted)
        assert_eq!(s.assign_for_peer(p2, 0, &v, now), None);
        // p1 disconnects → both anchors freed
        s.forget_peer(p1);
        assert_eq!(s.assigned_count(), 0);
        assert_eq!(
            s.assign_for_peer(p2, 0, &v, now),
            Some((ANCHOR_SPACING, id(1)))
        );
    }

    #[test]
    fn skips_anchors_beyond_max_ahead() {
        let mut s = AnchorScheduler::new();
        // Three anchors at spacing-respecting positions:
        //   ANCHOR_SPACING                       — in window
        //   MAX_ANCHOR_AHEAD                     — at the boundary
        //   MAX_ANCHOR_AHEAD + ANCHOR_INTERVAL   — past the boundary
        let v = map(&[
            (ANCHOR_SPACING, 1),
            (MAX_ANCHOR_AHEAD, 2),
            (MAX_ANCHOR_AHEAD + ANCHOR_INTERVAL, 3),
        ]);
        let now = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        let p2 = peer("5.6.7.8:9030");
        let p3 = peer("9.8.7.6:9030");
        // tip = 0 → smallest eligible is ANCHOR_SPACING
        assert_eq!(
            s.assign_for_peer(p1, 0, &v, now),
            Some((ANCHOR_SPACING, id(1)))
        );
        // p2 → next eligible: MAX_ANCHOR_AHEAD (≥ ANCHOR_SPACING away
        // from p1's claim and within the lookahead window)
        assert_eq!(
            s.assign_for_peer(p2, 0, &v, now),
            Some((MAX_ANCHOR_AHEAD, id(2)))
        );
        // p3 → MAX_ANCHOR_AHEAD + ANCHOR_INTERVAL is past lookahead → None
        assert_eq!(s.assign_for_peer(p3, 0, &v, now), None);
    }

    #[test]
    fn empty_verified_returns_none() {
        let mut s = AnchorScheduler::new();
        let v = map(&[]);
        let now = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        assert_eq!(s.assign_for_peer(p1, 0, &v, now), None);
    }

    #[test]
    fn counters_drain_on_take() {
        let mut s = AnchorScheduler::new();
        let v = map(&[(400, 1)]);
        let now = Instant::now();
        let p1 = peer("1.2.3.4:9030");
        assert!(s.assign_for_peer(p1, 0, &v, now).is_some());
        let c1 = s.take_counters();
        assert_eq!(c1.anchor_assignments, 1);
        let c2 = s.take_counters();
        assert_eq!(c2.anchor_assignments, 0);
    }
}

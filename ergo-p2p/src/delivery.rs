//! Delivery tracker: request ownership, timeout, and reassignment.
//!
//! Per P2P protocol spec Section 11:
//! - Each RequestModifier is tagged with (peer_id, request_time, modifier_ids)
//! - Delivery timeout: 3s. Diverges from Scala's 10s `deliveryTimeout`
//!   deliberately (node-local policy, not consensus): combined with the
//!   sub-timeout head-of-line hedge it bounds block-body apply latency to a
//!   few seconds. 3s is generous for a body on a healthy peer; we do NOT go
//!   lower (large blocks / slow links need headroom, and an over-tight
//!   timeout causes false timeouts -> wasted re-requests + spurious
//!   NonDelivery penalties / body-streak increments).
//! - On timeout: NonDelivery penalty, reassign to different peer
//! - On duplicate delivery: ignore, no penalty
//! - On partial delivery: accept what arrived, re-request remainder
//! - Max in-flight requests per peer: 1200 (see [`MAX_IN_FLIGHT_PER_PEER`],
//!   sized for anchored multi-batch pipelining — see the const-level doc).
//!
//! Per spec Section 9 (unsolicited modifier policy):
//! - status=Requested: accept
//! - status=Received (duplicate): ignore
//! - Not tracked: reject, +25 Spam penalty

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::peer::PeerId;

pub const DELIVERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Max in-flight modifier IDs per peer.
///
/// Sized at `3 × MAX_INV_OBJECTS (400)` to enable per-peer anchored
/// pipelining: with multiple anchored SyncInfos dispatched to the same
/// peer (each producing a 400-ID Inv + 400-header Modifier round trip),
/// a single peer can have up to 3 batches in flight simultaneously,
/// amortizing the RTT ceiling that bounded per-peer throughput at one
/// batch per RTT before the bump from 400 → 1200.
pub const MAX_IN_FLIGHT_PER_PEER: usize = 1200;
/// Max retry attempts per modifier before giving up.
pub const MAX_RETRIES: u8 = 3;
/// Max head-of-line hedge reassignments per request cycle before a section
/// falls through to the normal timeout/retry path. `reassign` resets the
/// inflight clock, so without this cap a section that no capable peer answers
/// could be re-hedged every tick and never reach `DELIVERY_TIMEOUT` — i.e.
/// never accrue a `NonDelivery` penalty / body-delivery-streak increment and
/// never get bucketed-redistributed, stalling block apply when the tip
/// reaches it. After the budget is spent the section stays with its current
/// owner until the normal timeout fires.
pub const MAX_HEDGES: u8 = 2;
/// Max entries in the received set before oldest entries are pruned.
/// 10,000 matches Scala's invalidation cache size [inherited].
const MAX_RECEIVED_ENTRIES: usize = 10_000;
/// How long a `recently_released` type-shadow may linger before the
/// `check_timeouts` sweep reclaims it. The shadow is only read while a
/// just-released id is being re-requested (the same tick it was created),
/// so any entry older than this is abandoned — a timed-out id that was
/// never retried (no eligible peer, or pruned in a reorg). Generous
/// relative to `DELIVERY_TIMEOUT` so nothing in active use is ever swept.
const RELEASED_SHADOW_TTL: Duration = Duration::from_secs(60);

/// Status of a modifier in the delivery pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifierStatus {
    /// We've requested this modifier from a peer and are waiting for delivery.
    Requested,
    /// We've received this modifier (at least once).
    Received,
    /// We don't know about this modifier (never requested).
    Unknown,
    /// Delivery failed after MAX_RETRIES attempts. Will not be re-requested.
    Failed,
}

/// What the caller should do with a received modifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryAction {
    /// Accept and process the modifier.
    Accept,
    /// Ignore — duplicate delivery.
    Ignore,
    /// Reject — unsolicited modifier, penalize the sender.
    RejectSpam,
}

/// Result of cancelling a peer's requests.
#[derive(Debug)]
pub struct CancelResult {
    /// Modifier IDs that can be retried from a different peer.
    pub retryable: Vec<[u8; 32]>,
    /// Modifier IDs that have exceeded MAX_RETRIES and are permanently failed.
    pub exhausted: Vec<[u8; 32]>,
}

/// Result of checking for timed-out deliveries.
#[derive(Debug)]
pub struct TimeoutResult {
    /// (peer, modifier_ids) that can be retried from a different peer.
    pub retryable: Vec<(PeerId, Vec<[u8; 32]>)>,
    /// Modifier IDs that have exceeded MAX_RETRIES and are permanently failed.
    pub exhausted: Vec<[u8; 32]>,
}

/// A single in-flight request.
// `dead_code`: `modifier_type` is read by the sync coordinator
// (`ergo-sync`) when classifying timeouts; the field is kept on the
// struct so the read path doesn't need a parallel side-channel, even
// though no code in this crate reads it directly.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct InflightRequest {
    peer: PeerId,
    requested_at: Instant,
    modifier_type: u8,
    /// HOL-hedge reassignments so far in this request cycle. Bounded by
    /// [`MAX_HEDGES`]; reset to 0 by a fresh `request` (re-entry after a
    /// timeout), not by `reassign`.
    hedge_count: u8,
}

/// Tracks modifier delivery state across all peers.
pub struct DeliveryTracker {
    /// Modifier ID → in-flight request (if currently requested).
    inflight: HashMap<[u8; 32], InflightRequest>,
    /// Bounded set of received modifier IDs. FIFO eviction at MAX_RECEIVED_ENTRIES.
    received_order: VecDeque<[u8; 32]>,
    received_set: HashSet<[u8; 32]>,
    /// Count of in-flight requests per peer.
    peer_inflight_count: HashMap<PeerId, usize>,
    /// Retry count per modifier ID. Incremented on each timeout/cancel.
    retry_count: HashMap<[u8; 32], u8>,
    /// Modifiers that have exhausted retries. Will not be re-requested.
    failed: HashSet<[u8; 32]>,
    /// Peers whose late delivery is still acceptable for a modifier.
    ///
    /// Timeout and HOL-reassignment remove a peer from the active owner slot,
    /// but the peer may still legally answer a request we sent earlier. Keep
    /// those peers here so useful late data is accepted instead of discarded
    /// as unsolicited spam.
    late_acceptable: HashMap<[u8; 32], HashSet<PeerId>>,
    /// Last-known `modifier_type` for IDs whose `inflight` entry was
    /// removed by `check_timeouts` / `cancel_peer`. Lets retry-bucket
    /// classifiers read the original requested type AFTER the
    /// inflight entry is gone.
    ///
    /// Value is `(modifier_type, released_at)`. Precise eviction drops an
    /// entry when the ID re-enters `inflight` (via `request`), when
    /// retries are exhausted, or when it is marked received (a late
    /// delivery accepted post-timeout). An id that times out and is then
    /// abandoned (never retried) has no such trigger, so the
    /// `check_timeouts` sweep reclaims any entry older than
    /// `RELEASED_SHADOW_TTL`. Either way the map cannot grow for the
    /// node's lifetime.
    recently_released: HashMap<[u8; 32], (u8, Instant)>,
}

impl DeliveryTracker {
    pub fn new() -> Self {
        Self {
            inflight: HashMap::new(),
            received_order: VecDeque::new(),
            received_set: HashSet::new(),
            peer_inflight_count: HashMap::new(),
            retry_count: HashMap::new(),
            recently_released: HashMap::new(),
            failed: HashSet::new(),
            late_acceptable: HashMap::new(),
        }
    }

    /// Get the delivery status of a modifier.
    pub fn status(&self, modifier_id: &[u8; 32]) -> ModifierStatus {
        if self.inflight.contains_key(modifier_id) {
            ModifierStatus::Requested
        } else if self.received_set.contains(modifier_id) {
            ModifierStatus::Received
        } else if self.failed.contains(modifier_id) {
            ModifierStatus::Failed
        } else {
            ModifierStatus::Unknown
        }
    }

    /// Determine what to do when a modifier arrives from a specific peer.
    /// Validates that the delivering peer is the one we requested from.
    /// A modifier delivered by the wrong peer is treated as unsolicited.
    pub fn on_received(&self, modifier_id: &[u8; 32], from_peer: &PeerId) -> DeliveryAction {
        match self.inflight.get(modifier_id) {
            Some(req) if req.peer == *from_peer => DeliveryAction::Accept,
            // Wrong current owner, but this peer is answering a request we
            // previously sent before timeout/reassignment. Accept it: a late
            // valid section is exactly what unblocks HOL stalls.
            Some(_) if self.late_delivery_allowed(modifier_id, from_peer) => DeliveryAction::Accept,
            Some(_) => DeliveryAction::RejectSpam,
            None => {
                if self.received_set.contains(modifier_id) {
                    DeliveryAction::Ignore
                } else if self.late_delivery_allowed(modifier_id, from_peer) {
                    DeliveryAction::Accept
                } else {
                    DeliveryAction::RejectSpam
                }
            }
        }
    }

    /// Register a request: we've sent RequestModifier for these IDs to this peer.
    /// Returns the IDs that were actually registered (skipping already-requested,
    /// already-received, or failed ones, and respecting per-peer limits).
    pub fn request(
        &mut self,
        peer: PeerId,
        modifier_type: u8,
        modifier_ids: &[[u8; 32]],
        now: Instant,
    ) -> Vec<[u8; 32]> {
        self.request_inner(peer, modifier_type, modifier_ids, now, false)
    }

    /// Register a request that is allowed to retry IDs previously marked
    /// failed. This is used only for header parent-walk recovery: those
    /// parents are a liveness dependency, and later peers may be able to
    /// provide them after earlier peers exhausted retries.
    pub fn request_allow_failed(
        &mut self,
        peer: PeerId,
        modifier_type: u8,
        modifier_ids: &[[u8; 32]],
        now: Instant,
    ) -> Vec<[u8; 32]> {
        self.request_inner(peer, modifier_type, modifier_ids, now, true)
    }

    fn request_inner(
        &mut self,
        peer: PeerId,
        modifier_type: u8,
        modifier_ids: &[[u8; 32]],
        now: Instant,
        allow_failed: bool,
    ) -> Vec<[u8; 32]> {
        let current_count = self.peer_inflight_count.get(&peer).copied().unwrap_or(0);
        let available = MAX_IN_FLIGHT_PER_PEER.saturating_sub(current_count);

        let mut registered = Vec::new();
        for id in modifier_ids {
            if registered.len() >= available {
                break;
            }
            // Skip if already requested or received. Failed IDs are skipped
            // for ordinary requests but can be explicitly revived by recovery
            // paths that need to make forward progress.
            if self.inflight.contains_key(id)
                || self.received_set.contains(id)
                || (!allow_failed && self.failed.contains(id))
            {
                continue;
            }
            if allow_failed && self.failed.remove(id) {
                self.retry_count.remove(id);
            }
            // Re-entering inflight clears any stale recently-released
            // type record — the live entry below is now authoritative.
            self.recently_released.remove(id);
            self.inflight.insert(
                *id,
                InflightRequest {
                    peer,
                    requested_at: now,
                    modifier_type,
                    hedge_count: 0,
                },
            );
            registered.push(*id);
        }

        if !registered.is_empty() {
            *self.peer_inflight_count.entry(peer).or_insert(0) += registered.len();
        }
        registered
    }

    /// Mark a modifier as successfully received. Removes from inflight.
    /// Evicts oldest entry if the received set exceeds MAX_RECEIVED_ENTRIES.
    pub fn mark_received(&mut self, modifier_id: &[u8; 32]) {
        if let Some(req) = self.inflight.remove(modifier_id) {
            if let Some(count) = self.peer_inflight_count.get_mut(&req.peer) {
                *count = count.saturating_sub(1);
            }
        }
        self.late_acceptable.remove(modifier_id);
        self.failed.remove(modifier_id);
        self.retry_count.remove(modifier_id);
        // A modifier can reach `received` via a late delivery accepted
        // after it timed out — in which case it still carries a
        // `recently_released` type shadow. Receiving is terminal (it is
        // never re-requested, re-timed-out, or exhausted), so evict the
        // shadow here or it would never leave.
        self.recently_released.remove(modifier_id);
        if self.received_set.insert(*modifier_id) {
            self.received_order.push_back(*modifier_id);
            // FIFO eviction when over capacity.
            while self.received_order.len() > MAX_RECEIVED_ENTRIES {
                if let Some(old) = self.received_order.pop_front() {
                    self.received_set.remove(&old);
                }
            }
        }
    }

    /// Forget a previously received modifier so it can be requested again.
    ///
    /// This is intentionally narrower than a general status reset: it is used
    /// when a higher layer decides not to retain a received payload after all
    /// (for example, a far-ahead orphan header during IBD). If the bytes are
    /// dropped, keeping `Received` would make future legitimate `Inv`s skip the
    /// modifier and could strand header sync at that height.
    pub fn forget_received(&mut self, modifier_id: &[u8; 32]) -> bool {
        let removed = self.received_set.remove(modifier_id);
        if removed {
            self.received_order.retain(|id| id != modifier_id);
        }
        removed
    }

    /// Fully forget a modifier that just timed out, dropping every
    /// residual tracking record so it is neither re-requested nor
    /// remembered.
    ///
    /// By the time `check_timeouts` returns, the `inflight` entry is
    /// already gone (it was moved into the `recently_released` type
    /// shadow and a `retry_count` bump). This clears those leftovers
    /// (plus any `late_acceptable` allowance), returning the modifier
    /// to `Unknown` status with no state held against it.
    ///
    /// Scala parity: `checkDelivery` forgets a timed-out mempool
    /// transaction via `clearStatusForModifier(id, txTypeId, Requested)`
    /// — a tx may legitimately have left the peer's mempool, so the
    /// peer is not penalized and the tx is not re-requested
    /// (ErgoNodeViewSynchronizer.scala, "no reason to penalize").
    pub fn forget_timed_out(&mut self, modifier_id: &[u8; 32]) {
        self.recently_released.remove(modifier_id);
        self.retry_count.remove(modifier_id);
        self.late_acceptable.remove(modifier_id);
    }

    /// Check for timed-out requests. Returns a `TimeoutResult` with:
    /// - `retryable`: (peer, ids) that can be re-requested from a different peer
    /// - `exhausted`: ids that have exceeded MAX_RETRIES (marked as Failed)
    pub fn check_timeouts(&mut self, now: Instant) -> TimeoutResult {
        let mut by_peer: HashMap<PeerId, Vec<[u8; 32]>> = HashMap::new();
        let mut to_remove = Vec::new();

        for (id, req) in &self.inflight {
            if now.duration_since(req.requested_at) > DELIVERY_TIMEOUT {
                by_peer.entry(req.peer).or_default().push(*id);
                to_remove.push(*id);
            }
        }

        for id in &to_remove {
            if let Some(req) = self.inflight.remove(id) {
                self.allow_late_delivery(*id, req.peer);
                // Stash the modifier_type for the retry-bucket
                // classifier after the inflight entry is gone.
                self.recently_released.insert(*id, (req.modifier_type, now));
                if let Some(count) = self.peer_inflight_count.get_mut(&req.peer) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.peer_inflight_count.remove(&req.peer);
                    }
                }
            }
        }

        // Increment retry counts and partition into retryable vs exhausted.
        //
        // Scala parity (CheckDelivery handler in
        // ErgoNodeViewSynchronizer.scala:1278-1289): when
        // `checksDone >= maxDeliveryChecks` for non-header block
        // sections, Scala calls `setUnknown` and lets the next
        // CheckModifiersToDownload pick a fresh peer. There is NO
        // permanent "failed" state for block sections.
        //
        // We mirror that: at MAX_RETRIES, reset retry_count and drop
        // the recently-released stash. The id transitions to
        // ModifierStatus::Unknown and the bucketed request loop
        // picks a fresh peer next tick. The `exhausted` return
        // remains for caller logging — but the id is NOT inserted
        // into `self.failed`, so future `delivery.request` calls
        // will accept it without needing the `request_allow_failed`
        // workaround.
        let mut retryable: HashMap<PeerId, Vec<[u8; 32]>> = HashMap::new();
        let mut exhausted = Vec::new();

        for (peer, ids) in by_peer {
            for id in ids {
                let count = self.retry_count.entry(id).or_insert(0);
                *count += 1;
                if *count >= MAX_RETRIES {
                    self.retry_count.remove(&id);
                    self.recently_released.remove(&id);
                    exhausted.push(id);
                    // NOTE: deliberately NOT inserting into
                    // `self.failed`. Scala-parity: section becomes
                    // Unknown and is eligible for re-request.
                } else {
                    retryable.entry(peer).or_default().push(id);
                }
            }
        }

        // Sweep abandoned shadows: any released-type entry older than the
        // TTL was never re-requested (no eligible peer, or pruned in a
        // reorg). Entries created this tick are age-0, so the working set
        // the coordinator is about to re-request is never touched.
        self.recently_released
            .retain(|_, (_, released_at)| now.duration_since(*released_at) < RELEASED_SHADOW_TTL);

        TimeoutResult {
            retryable: retryable.into_iter().collect(),
            exhausted,
        }
    }

    /// Cancel all inflight requests for a peer (e.g., on disconnect).
    /// Increments retry count for each cancelled modifier. Returns two
    /// lists: retryable IDs (can be reassigned) and exhausted IDs (failed).
    pub fn cancel_peer(&mut self, peer: &PeerId, now: Instant) -> CancelResult {
        // Capture (id, type) BEFORE removing inflight entries — the
        // retry-bucket classifier consults `recently_released` after
        // this loop, so the type must be stashed BEFORE the inflight
        // entry disappears.
        let cancelled: Vec<([u8; 32], u8)> = self
            .inflight
            .iter()
            .filter(|(_, req)| req.peer == *peer)
            .map(|(id, req)| (*id, req.modifier_type))
            .collect();
        for (id, modifier_type) in &cancelled {
            self.inflight.remove(id);
            self.late_acceptable.remove(id);
            self.recently_released.insert(*id, (*modifier_type, now));
        }
        self.peer_inflight_count.remove(peer);

        let mut retryable = Vec::new();
        let mut exhausted = Vec::new();
        for (id, _) in cancelled {
            let count = self.retry_count.entry(id).or_insert(0);
            *count += 1;
            if *count >= MAX_RETRIES {
                // Scala-parity (CheckDelivery handler at
                // ErgoNodeViewSynchronizer.scala:1287): max retries
                // for non-header sections → setUnknown, NOT
                // permanent failure. Section is eligible for
                // re-request by the next CheckModifiersToDownload.
                self.retry_count.remove(&id);
                self.recently_released.remove(&id);
                exhausted.push(id);
            } else {
                retryable.push(id);
            }
        }
        CancelResult {
            retryable,
            exhausted,
        }
    }

    /// Returns (how long inflight, current owner peer) if the ID is in-flight,
    /// else None. Used by the HOL hedge path to find stale section assignments.
    pub fn inflight_age(&self, id: &[u8; 32], now: Instant) -> Option<(Duration, PeerId)> {
        self.inflight
            .get(id)
            .map(|req| (now.duration_since(req.requested_at), req.peer))
    }

    /// Early-reassign an in-flight section ID to a new peer without
    /// incrementing the retry count (not a timeout — original peer was
    /// slow, not necessarily faulty). The old peer remains acceptable
    /// for a late delivery, so useful data is not discarded just because
    /// the hedge raced it.
    ///
    /// Returns `true` if the reassignment happened, `false` if the ID
    /// was not in-flight or `new_peer` is the same as the current owner.
    pub fn reassign(&mut self, id: &[u8; 32], new_peer: PeerId, now: Instant) -> bool {
        if self.available_slots(&new_peer) == 0 {
            return false;
        }
        if let Some(req) = self.inflight.get_mut(id) {
            if req.peer == new_peer {
                return false;
            }
            if req.hedge_count >= MAX_HEDGES {
                // Hedge budget spent — leave the section with its current
                // owner so its inflight clock reaches DELIVERY_TIMEOUT and the
                // normal timeout/retry/degradation path takes over instead of
                // re-hedging forever.
                return false;
            }
            req.hedge_count += 1;
            let old_peer = req.peer;
            req.peer = new_peer;
            req.requested_at = now;
            if let Some(count) = self.peer_inflight_count.get_mut(&old_peer) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.peer_inflight_count.remove(&old_peer);
                }
            }
            *self.peer_inflight_count.entry(new_peer).or_insert(0) += 1;
            self.allow_late_delivery(*id, old_peer);
            true
        } else {
            false
        }
    }

    fn allow_late_delivery(&mut self, id: [u8; 32], peer: PeerId) {
        self.late_acceptable.entry(id).or_default().insert(peer);
    }

    /// **Hedged delivery registration.** After sending
    /// `RequestModifier` to a primary peer for an ID, the caller may
    /// also send the same `RequestModifier` to additional hedge peers
    /// and register them here. Hedge peers' responses arrive via the
    /// `late_delivery_allowed` path → `DeliveryAction::Accept`.
    /// First valid delivery wins; subsequent arrivals are
    /// `Ignore` (not `RejectSpam`) because `mark_received`
    /// clears the `late_acceptable` set.
    ///
    /// **Semantics vs `cancel_peer` / timeout-`allow_late_delivery`:**
    /// the existing private `allow_late_delivery` is for "after a
    /// timeout/reassignment, peer X is still accepted as a late
    /// answerer". This proactive variant is the hedged-request
    /// case — peer X never timed out; we asked them concurrently
    /// with a primary as a race-for-fastest-delivery strategy.
    /// Both populate the same `late_acceptable` map; the receive
    /// path treats them identically.
    pub fn register_hedge_peers(&mut self, ids: &[[u8; 32]], peers: &[PeerId]) {
        for id in ids {
            for &peer in peers {
                self.allow_late_delivery(*id, peer);
            }
        }
    }

    fn late_delivery_allowed(&self, id: &[u8; 32], peer: &PeerId) -> bool {
        self.late_acceptable
            .get(id)
            .is_some_and(|peers| peers.contains(peer))
    }

    /// Test-only: force a modifier back to Unknown, bypassing the
    /// timeout/disconnect paths. Used by coordinator rotation tests
    /// that need to observe successive request_missing_sections calls
    /// against the same pending set without simulating timeouts.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn test_reset_status(&mut self, modifier_id: &[u8; 32]) {
        if let Some(info) = self.inflight.remove(modifier_id) {
            if let Some(count) = self.peer_inflight_count.get_mut(&info.peer) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.peer_inflight_count.remove(&info.peer);
                }
            }
        }
        self.late_acceptable.remove(modifier_id);
    }

    /// How many in-flight requests for a given peer.
    pub fn inflight_count(&self, peer: &PeerId) -> usize {
        self.peer_inflight_count.get(peer).copied().unwrap_or(0)
    }

    /// Whether a peer has capacity for more requests.
    pub fn peer_has_capacity(&self, peer: &PeerId) -> bool {
        self.inflight_count(peer) < MAX_IN_FLIGHT_PER_PEER
    }

    /// Free slots for the given peer (`MAX_IN_FLIGHT_PER_PEER` minus
    /// current in-flight count). Used by the coordinator to balance
    /// section types across each peer's actual remaining budget rather
    /// than a static cap.
    pub fn available_slots(&self, peer: &PeerId) -> usize {
        MAX_IN_FLIGHT_PER_PEER.saturating_sub(self.inflight_count(peer))
    }

    /// Observability accessor: number of modifier IDs in the
    /// received-set dedupe ring (capped at MAX_RECEIVED_ENTRIES).
    pub fn received_set_len(&self) -> usize {
        self.received_set.len()
    }

    pub fn total_inflight(&self) -> usize {
        self.inflight.len()
    }

    /// Number of modifier ids currently recorded as received. Capped
    /// at `MAX_RECEIVED_ENTRIES` by the dedupe ring's eviction policy,
    /// so this saturates rather than monotonically growing on a long-
    /// lived node. Aliased to `received_set_len` for code that reads
    /// it semantically as a counter rather than a ring length.
    pub fn received_count(&self) -> usize {
        self.received_set.len()
    }

    /// Number of modifier ids in the persistent-failed set —
    /// modifiers that have exhausted their retry budget and won't be
    /// re-requested. Bounded by retry churn (entries only land here
    /// after the retry-count helper exceeds the cap). Drives the
    /// `failed` counter on `/peers/trackInfo`.
    pub fn failed_count(&self) -> usize {
        self.failed.len()
    }

    /// Type byte for a tracked modifier id (`101` for Header,
    /// `102` for BlockTransactions, `104` for ADProofs, `108` for
    /// Extension). Checks the live `inflight` map first and falls
    /// back to the `recently_released` shadow — IDs whose inflight
    /// entry was just removed by `check_timeouts` / `cancel_peer`
    /// still report their original type until they're re-requested
    /// or marked failed. Returns `None` only when the id has never
    /// been requested or has been received / failed-and-pruned.
    ///
    /// Retry-bucket classification must use what was requested via
    /// `request(...)` (recorded here), not what the `AssemblyTracker`
    /// knows — block-section IDs from `on_inv` are registered into
    /// `delivery` without an assembly entry, so assembly-keyed lookup
    /// would misclassify them as headers.
    pub fn modifier_type(&self, modifier_id: &[u8; 32]) -> Option<u8> {
        self.inflight
            .get(modifier_id)
            .map(|i| i.modifier_type)
            .or_else(|| self.recently_released.get(modifier_id).map(|(t, _)| *t))
    }

    /// Whether the aggregate in-flight count has dropped below
    /// `watermark`. Used by the executor to trigger an early refill of
    /// section requests without waiting for the next sync tick
    /// (Sync-S2).
    pub fn below_drain_watermark(&self, watermark: usize) -> bool {
        self.total_inflight() < watermark
    }
}

impl Default for DeliveryTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn peer(port: u16) -> PeerId {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn id(v: u8) -> [u8; 32] {
        [v; 32]
    }

    #[test]
    fn request_and_receive() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        let registered = tracker.request(p, 101, &[id(1), id(2)], now);
        assert_eq!(registered.len(), 2);
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Requested);
        assert_eq!(tracker.on_received(&id(1), &p), DeliveryAction::Accept);

        tracker.mark_received(&id(1));
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Received);
        assert_eq!(tracker.on_received(&id(1), &p), DeliveryAction::Ignore);
        assert_eq!(tracker.inflight_count(&p), 1); // id(2) still inflight
    }

    #[test]
    fn unsolicited_modifier_rejected() {
        let tracker = DeliveryTracker::new();
        let p = peer(9030);
        assert_eq!(tracker.status(&id(99)), ModifierStatus::Unknown);
        assert_eq!(tracker.on_received(&id(99), &p), DeliveryAction::RejectSpam);
    }

    #[test]
    fn wrong_peer_delivers_modifier_rejected() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p1 = peer(9030);
        let p2 = peer(9031);

        tracker.request(p1, 101, &[id(1)], now);
        // p1 is the owner — p2 delivering it is spam
        assert_eq!(tracker.on_received(&id(1), &p2), DeliveryAction::RejectSpam);
        // p1 delivering it is accepted
        assert_eq!(tracker.on_received(&id(1), &p1), DeliveryAction::Accept);
    }

    #[test]
    fn per_peer_limit_enforced() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        let overflow = MAX_IN_FLIGHT_PER_PEER + 10;
        let ids: Vec<[u8; 32]> = (0..overflow)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[..2].copy_from_slice(&(i as u16).to_be_bytes());
                arr
            })
            .collect();
        let registered = tracker.request(p, 101, &ids, now);
        assert_eq!(registered.len(), MAX_IN_FLIGHT_PER_PEER);
        assert_eq!(tracker.inflight_count(&p), MAX_IN_FLIGHT_PER_PEER);
        assert!(!tracker.peer_has_capacity(&p));
    }

    #[test]
    fn timeout_detection() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        tracker.request(p, 101, &[id(1), id(2)], now);
        // Before timeout (relative to the const so it survives retuning).
        let result = tracker.check_timeouts(now + DELIVERY_TIMEOUT / 2);
        assert!(result.retryable.is_empty() && result.exhausted.is_empty());
        // After timeout (first attempt — retryable)
        let result = tracker.check_timeouts(now + DELIVERY_TIMEOUT + Duration::from_secs(1));
        assert_eq!(result.retryable.len(), 1);
        assert_eq!(result.retryable[0].0, p);
        assert_eq!(result.retryable[0].1.len(), 2);
        assert!(result.exhausted.is_empty());
        // Inflight should be cleared
        assert_eq!(tracker.inflight_count(&p), 0);
        // IDs should be retryable (not received, not failed yet)
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);
    }

    #[test]
    fn mark_received_evicts_recently_released_shadow_after_late_delivery() {
        // Regression: a timed-out modifier is stashed in
        // `recently_released` (the type shadow read by the retry-bucket
        // classifier). If the original peer then answers late and the
        // modifier is accepted + marked received, the shadow must be
        // evicted — receiving is terminal, so the entry is otherwise
        // never re-requested, re-timed-out, or exhausted and would leak
        // one entry per timed-out-then-delivered modifier for the life
        // of the node.
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        tracker.request(p, 101, &[id(1)], now);
        // Time it out: inflight -> recently_released, still retryable.
        let result = tracker.check_timeouts(now + DELIVERY_TIMEOUT + Duration::from_secs(1));
        assert_eq!(result.retryable.len(), 1);
        assert!(
            tracker.recently_released.contains_key(&id(1)),
            "timeout should stash the type shadow"
        );

        // Original peer delivers late; the post-timeout window accepts it.
        assert_eq!(tracker.on_received(&id(1), &p), DeliveryAction::Accept);
        tracker.mark_received(&id(1));

        assert_eq!(tracker.status(&id(1)), ModifierStatus::Received);
        assert!(
            tracker.recently_released.is_empty(),
            "mark_received must evict the recently_released shadow, not leak it"
        );
        // Behavioural counterpart: the type lookup no longer resolves.
        assert_eq!(tracker.modifier_type(&id(1)), None);
    }

    #[test]
    fn check_timeouts_sweeps_abandoned_shadow_but_keeps_the_live_set() {
        // An abandoned timed-out id — never re-requested (no eligible
        // peer, or pruned in a reorg) — has no precise eviction point, so
        // the age-based sweep must reclaim it. Critically, the sweep must
        // NOT touch shadows created in the same tick: those are the live
        // working set the coordinator is about to re-request.
        let mut tracker = DeliveryTracker::new();
        let t0 = Instant::now();
        let p = peer(9030);

        // id(1) times out at t0 and is then abandoned (never re-requested).
        tracker.request(p, 102, &[id(1)], t0);
        tracker.check_timeouts(t0 + DELIVERY_TIMEOUT + Duration::from_secs(1));
        assert!(tracker.recently_released.contains_key(&id(1)));

        // A later tick, past the shadow TTL, also times out a fresh id(2).
        let later = t0 + RELEASED_SHADOW_TTL + DELIVERY_TIMEOUT + Duration::from_secs(2);
        tracker.request(p, 102, &[id(2)], later);
        tracker.check_timeouts(later + DELIVERY_TIMEOUT + Duration::from_secs(1));

        // id(1) was abandoned long enough to be swept; id(2) is fresh and
        // must survive (it is still awaiting re-request).
        assert!(
            !tracker.recently_released.contains_key(&id(1)),
            "abandoned shadow must be swept after the TTL"
        );
        assert!(
            tracker.recently_released.contains_key(&id(2)),
            "a just-released shadow must NOT be swept — it is the live set"
        );
        assert_eq!(tracker.modifier_type(&id(2)), Some(102));
    }

    #[test]
    fn cancel_peer_abandoned_shadow_swept_after_ttl() {
        // Disconnect-originated shadows are timestamped by cancel_peer but
        // swept by the periodic check_timeouts tick, so an abandoned one
        // (peer gone, never re-requested) is still reclaimed after the TTL.
        let mut tracker = DeliveryTracker::new();
        let t0 = Instant::now();
        let p = peer(9030);

        tracker.request(p, 104, &[id(7)], t0);
        tracker.cancel_peer(&p, t0);
        assert!(tracker.recently_released.contains_key(&id(7)));

        tracker.check_timeouts(t0 + RELEASED_SHADOW_TTL + Duration::from_secs(1));
        assert!(
            !tracker.recently_released.contains_key(&id(7)),
            "disconnect-originated abandoned shadow must be swept after the TTL"
        );
    }

    #[test]
    fn rerequest_makes_inflight_authoritative_and_drops_shadow() {
        // Re-requesting a timed-out id moves it back into `inflight`; the
        // stale released shadow must be dropped so the live entry wins.
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        tracker.request(p, 104, &[id(8)], now);
        tracker.check_timeouts(now + DELIVERY_TIMEOUT + Duration::from_secs(1));
        assert!(tracker.recently_released.contains_key(&id(8)));

        tracker.request(
            peer(9031),
            104,
            &[id(8)],
            now + DELIVERY_TIMEOUT + Duration::from_secs(2),
        );
        assert!(!tracker.recently_released.contains_key(&id(8)));
        assert_eq!(tracker.status(&id(8)), ModifierStatus::Requested);
    }

    #[test]
    fn retry_exhaustion_returns_to_unknown_scala_parity() {
        // Scala parity (CheckDelivery handler at
        // ErgoNodeViewSynchronizer.scala:1287): when a non-header
        // section's checks exceed maxDeliveryChecks, status returns
        // to Unknown. There is NO permanent "Failed" state for
        // sections — they remain eligible for re-request via
        // CheckModifiersToDownload picking a fresh peer.
        let mut tracker = DeliveryTracker::new();
        let p = peer(9030);

        for attempt in 1..=MAX_RETRIES {
            let now = Instant::now();
            tracker.request(p, 101, &[id(1)], now);
            let later = now + DELIVERY_TIMEOUT + Duration::from_secs(1);
            let result = tracker.check_timeouts(later);

            if attempt < MAX_RETRIES {
                assert!(
                    !result.retryable.is_empty(),
                    "attempt {attempt}: should be retryable",
                );
                assert!(result.exhausted.is_empty());
            } else {
                assert!(
                    result.retryable.is_empty(),
                    "attempt {attempt}: exhausted means moved out of retry bucket",
                );
                assert_eq!(result.exhausted, vec![id(1)]);
            }
        }

        // After exhaustion, status is Unknown (Scala parity), NOT a
        // permanent "Failed" state. The exhausted return is for
        // caller logging only.
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);

        // Re-requesting after exhaustion succeeds — id is eligible
        // for a fresh attempt against a different peer next tick.
        let now = Instant::now();
        let registered = tracker.request(p, 101, &[id(1)], now);
        assert_eq!(
            registered,
            vec![id(1)],
            "exhausted modifier must be re-requestable (Scala parity)",
        );
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Requested);
    }

    #[test]
    fn allow_failed_request_revives_modifier() {
        // With the 2Q Scala-parity change, the `failed` set is
        // never populated by ordinary timeout flows — so
        // `request_allow_failed` is now functionally equivalent to
        // `request` in practice. The test verifies the method
        // still works (it's a no-op for already-Unknown ids), so a
        // future caller that DOES set `failed` (e.g., manual
        // intervention or future code) can revive correctly.
        let mut tracker = DeliveryTracker::new();
        let p = peer(9030);

        for attempt in 1..=MAX_RETRIES {
            let now = Instant::now();
            tracker.request(p, 101, &[id(1)], now);
            let later = now + DELIVERY_TIMEOUT + Duration::from_secs(1);
            let result = tracker.check_timeouts(later);
            if attempt < MAX_RETRIES {
                assert!(!result.retryable.is_empty());
            } else {
                assert_eq!(result.exhausted, vec![id(1)]);
            }
        }
        // No permanent Failed under 2Q — id is Unknown after exhaustion.
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);

        let now = Instant::now();
        let registered = tracker.request_allow_failed(p, 101, &[id(1)], now);
        assert_eq!(registered, vec![id(1)]);
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Requested);
    }

    #[test]
    fn cancel_peer_returns_ids() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        tracker.request(p, 101, &[id(1), id(2), id(3)], now);
        let result = tracker.cancel_peer(&p, now);
        assert_eq!(result.retryable.len(), 3); // first cancel, all retryable
        assert!(result.exhausted.is_empty());
        assert_eq!(tracker.inflight_count(&p), 0);
        assert_eq!(tracker.total_inflight(), 0);
    }

    #[test]
    fn skip_already_requested_or_received() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p1 = peer(9030);
        let p2 = peer(9031);

        // p1 requests id(1)
        tracker.request(p1, 101, &[id(1)], now);
        // p2 tries to request id(1) again — should skip
        let registered = tracker.request(p2, 101, &[id(1), id(2)], now);
        assert_eq!(registered, vec![id(2)]);

        // Mark id(1) as received
        tracker.mark_received(&id(1));
        // p2 tries to request id(1) again — should skip (already received)
        let registered = tracker.request(p2, 101, &[id(1)], now);
        assert!(registered.is_empty());
    }

    #[test]
    fn forget_received_allows_future_request() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        tracker.request(p, 101, &[id(1)], now);
        tracker.mark_received(&id(1));
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Received);

        assert!(tracker.forget_received(&id(1)));
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);

        let registered = tracker.request(p, 101, &[id(1)], now);
        assert_eq!(registered, vec![id(1)]);
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Requested);
    }

    #[test]
    fn multiple_peers_independent_limits() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p1 = peer(9030);
        let p2 = peer(9031);

        let ids_p1: Vec<[u8; 32]> = (0..4).map(id).collect();
        let ids_p2: Vec<[u8; 32]> = (10..14).map(id).collect();

        tracker.request(p1, 101, &ids_p1, now);
        tracker.request(p2, 101, &ids_p2, now);

        assert_eq!(tracker.inflight_count(&p1), 4);
        assert_eq!(tracker.inflight_count(&p2), 4);
        assert_eq!(tracker.total_inflight(), 8);
    }

    #[test]
    fn s2_below_drain_watermark_tracks_total_inflight() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        // Empty pipeline → always below.
        assert!(tracker.below_drain_watermark(1));
        assert!(tracker.below_drain_watermark(64));

        // 10 in flight, watermark 64 → still below.
        let ids: Vec<[u8; 32]> = (0..10).map(id).collect();
        tracker.request(p, 101, &ids, now);
        assert_eq!(tracker.total_inflight(), 10);
        assert!(tracker.below_drain_watermark(64));
        assert!(
            !tracker.below_drain_watermark(10),
            "watermark equal to inflight is NOT below — strict <"
        );
        assert!(tracker.below_drain_watermark(11));
    }

    #[test]
    fn s2_available_slots_matches_inflight_complement() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);
        assert_eq!(tracker.available_slots(&p), MAX_IN_FLIGHT_PER_PEER);

        let ids: Vec<[u8; 32]> = (0..50).map(id).collect();
        tracker.request(p, 101, &ids, now);
        assert_eq!(tracker.available_slots(&p), MAX_IN_FLIGHT_PER_PEER - 50);
    }

    #[test]
    fn hol_hedge_reassign_accepts_new_owner_delivery() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p1 = peer(9030);
        let p2 = peer(9031);

        tracker.request(p1, 101, &[id(1)], now);

        // Reassign to p2 (HOL hedge)
        assert!(tracker.reassign(&id(1), p2, now));
        assert_eq!(tracker.inflight_count(&p1), 0);
        assert_eq!(tracker.inflight_count(&p2), 1);

        // p2 is now the owner — accepts
        assert_eq!(tracker.on_received(&id(1), &p2), DeliveryAction::Accept);
    }

    #[test]
    fn hol_hedge_original_peer_late_delivery_is_accepted() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p1 = peer(9030);
        let p2 = peer(9031);

        tracker.request(p1, 101, &[id(1)], now);
        tracker.reassign(&id(1), p2, now);

        // p1 delivers late with useful data. Accept it instead of
        // discarding the section and waiting on p2.
        assert_eq!(tracker.on_received(&id(1), &p1), DeliveryAction::Accept);
    }

    #[test]
    fn hol_hedge_inflight_age_returns_age_and_peer() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        assert!(tracker.inflight_age(&id(1), now).is_none());

        tracker.request(p, 101, &[id(1)], now);
        let later = now + Duration::from_secs(10);
        let (age, owner) = tracker.inflight_age(&id(1), later).unwrap();
        assert!(age >= Duration::from_secs(10));
        assert_eq!(owner, p);
    }

    #[test]
    fn hol_hedge_late_acceptance_cleared_on_mark_received() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p1 = peer(9030);
        let p2 = peer(9031);

        tracker.request(p1, 101, &[id(1)], now);
        tracker.reassign(&id(1), p2, now);
        // new peer delivers
        tracker.mark_received(&id(1));
        // after mark_received: duplicate ignored, not spam
        assert_eq!(tracker.on_received(&id(1), &p1), DeliveryAction::Ignore);
    }

    #[test]
    fn timeout_late_delivery_from_requested_peer_is_accepted() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let p = peer(9030);

        tracker.request(p, 101, &[id(1)], now);
        let result = tracker.check_timeouts(now + DELIVERY_TIMEOUT + Duration::from_secs(1));
        assert_eq!(result.retryable[0].1, vec![id(1)]);
        assert_eq!(tracker.status(&id(1)), ModifierStatus::Unknown);

        // The request timed out locally, but the peer is still answering a
        // request we actually sent. Accepting this can rescue HOL progress.
        assert_eq!(tracker.on_received(&id(1), &p), DeliveryAction::Accept);
    }

    #[test]
    fn hol_reassign_respects_new_peer_capacity() {
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let old = peer(9030);
        let full = peer(9031);

        tracker.request(old, 101, &[id(1)], now);
        let filler: Vec<[u8; 32]> = (0..MAX_IN_FLIGHT_PER_PEER)
            .map(|i| {
                let mut out = [0xAA; 32];
                out[..2].copy_from_slice(&(i as u16).to_be_bytes());
                out
            })
            .collect();
        assert_eq!(
            tracker.request(full, 101, &filler, now).len(),
            MAX_IN_FLIGHT_PER_PEER
        );

        assert!(!tracker.reassign(&id(1), full, now));
        assert_eq!(tracker.inflight_count(&old), 1);
        assert_eq!(tracker.inflight_count(&full), MAX_IN_FLIGHT_PER_PEER);
    }

    #[test]
    fn reassign_capped_at_max_hedges_so_stuck_section_can_time_out() {
        // Liveness guard: a section that no peer answers must not be
        // re-hedged forever (each reassign resets the inflight clock). After
        // MAX_HEDGES reassigns the next is refused, so the section stays put
        // and reaches the normal timeout/retry path.
        let mut tracker = DeliveryTracker::new();
        let now = Instant::now();
        let id0 = id(1);
        tracker.request(peer(9000), 102, &[id0], now);

        // Advance the clock per hedge so the timeout assertion below is taken
        // relative to the LAST successful reassign — this catches a regression
        // where an over-budget (refused) reassign accidentally refreshes
        // `requested_at`.
        let mut last_successful_reassign = now;
        for i in 0..MAX_HEDGES {
            last_successful_reassign += DELIVERY_TIMEOUT / 2;
            assert!(
                tracker.reassign(&id0, peer(9001 + u16::from(i)), last_successful_reassign),
                "reassign #{i} within budget should succeed"
            );
        }
        let refused_at = last_successful_reassign + DELIVERY_TIMEOUT / 2;
        assert!(
            !tracker.reassign(&id0, peer(9099), refused_at),
            "reassign past MAX_HEDGES must be refused so the section can time out"
        );

        let result = tracker
            .check_timeouts(last_successful_reassign + DELIVERY_TIMEOUT + Duration::from_millis(1));
        assert_eq!(
            result.retryable.len(),
            1,
            "a hedge-capped section must fall through to the timeout/retry path"
        );
    }
}

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
    /// shadow and a `retry_count` bump). This clears those leftovers,
    /// returning the modifier to `Unknown` status — but DELIBERATELY
    /// leaves the `late_acceptable` allowance that `check_timeouts`
    /// recorded (`allow_late_delivery`) in place: a tx the peer was slow
    /// on may still arrive, and that late delivery must be ACCEPTED, not
    /// `RejectSpam`-penalized — penalizing it would defeat the very
    /// "no reason to penalize" goal of forgetting. `mark_received` clears
    /// the allowance when the tx actually arrives. (Leaving it matches
    /// how block sections already behave; the entry is otherwise dropped
    /// on arrival or, for a never-arriving tx, persists like any other
    /// un-received modifier's allowance.)
    ///
    /// Scala parity: `checkDelivery` forgets a timed-out mempool
    /// transaction via `clearStatusForModifier(id, txTypeId, Requested)`
    /// — a tx may legitimately have left the peer's mempool, so the
    /// peer is not penalized and the tx is not re-requested
    /// (ErgoNodeViewSynchronizer.scala, "no reason to penalize").
    pub fn forget_timed_out(&mut self, modifier_id: &[u8; 32]) {
        self.recently_released.remove(modifier_id);
        self.retry_count.remove(modifier_id);
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
    /// section requests without waiting for the next sync tick.
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
mod tests;

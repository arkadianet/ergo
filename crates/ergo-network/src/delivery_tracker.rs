use std::collections::HashMap;
use std::time::{Duration, Instant};

use ergo_types::modifier_id::ModifierId;
use serde::Serialize;

/// Unique identifier for a connected peer.
pub type PeerId = u64;

/// Status of a modifier in the delivery pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifierStatus {
    Unknown,
    Requested,
    Received,
    Invalid,
}

/// Information about a pending request.
#[derive(Debug, Clone)]
struct RequestInfo {
    peer_id: PeerId,
    requested_at: Instant,
    checks: u32,
}

/// Tracks modifier delivery status across the network.
pub struct DeliveryTracker {
    requested: HashMap<(u8, ModifierId), RequestInfo>,
    received: HashMap<(u8, ModifierId), Instant>,
    invalid: HashMap<ModifierId, Instant>,
    delivery_timeout: Duration,
    max_checks: u32,
}

impl DeliveryTracker {
    pub fn new(delivery_timeout_secs: u64, max_checks: u32) -> Self {
        Self {
            requested: HashMap::new(),
            received: HashMap::new(),
            invalid: HashMap::new(),
            delivery_timeout: Duration::from_secs(delivery_timeout_secs),
            max_checks,
        }
    }

    /// Get the status of a modifier.
    pub fn status(&self, type_id: u8, id: &ModifierId) -> ModifierStatus {
        if self.invalid.contains_key(id) {
            ModifierStatus::Invalid
        } else if self.received.contains_key(&(type_id, *id)) {
            ModifierStatus::Received
        } else if self.requested.contains_key(&(type_id, *id)) {
            ModifierStatus::Requested
        } else {
            ModifierStatus::Unknown
        }
    }

    /// Mark a modifier as requested from a specific peer.
    pub fn set_requested(&mut self, type_id: u8, id: ModifierId, peer_id: PeerId) {
        self.requested.insert(
            (type_id, id),
            RequestInfo {
                peer_id,
                requested_at: Instant::now(),
                checks: 0,
            },
        );
    }

    /// Mark a modifier as received.
    pub fn set_received(&mut self, type_id: u8, id: &ModifierId) {
        self.requested.remove(&(type_id, *id));
        self.received.insert((type_id, *id), Instant::now());
    }

    /// Mark a modifier as permanently invalid.
    pub fn set_invalid(&mut self, id: &ModifierId) {
        // Remove from requested across all type_ids
        self.requested.retain(|(_tid, mid), _| mid != id);
        self.invalid.insert(*id, Instant::now());
    }

    /// Reset a modifier to unknown (for re-request after timeout).
    pub fn set_unknown(&mut self, type_id: u8, id: &ModifierId) {
        self.requested.remove(&(type_id, *id));
        self.received.remove(&(type_id, *id));
    }

    /// Collect all modifiers that have timed out.
    /// Returns (type_id, modifier_id, peer_id, checks) for expired requests.
    /// Increments the check count on each returned item.
    pub fn collect_timed_out(&mut self) -> Vec<(u8, ModifierId, PeerId, u32)> {
        let now = Instant::now();
        let mut timed_out = Vec::new();

        for (&(type_id, id), info) in &mut self.requested {
            if now.duration_since(info.requested_at) >= self.delivery_timeout {
                info.checks += 1;
                timed_out.push((type_id, id, info.peer_id, info.checks));
            }
        }

        // Remove timed out items that exceeded max checks
        for &(type_id, id, _, checks) in &timed_out {
            if checks >= self.max_checks {
                self.requested.remove(&(type_id, id));
            }
        }

        timed_out
    }

    /// Reassign a timed-out request to a different peer.
    ///
    /// Resets the request timer but preserves the check count.
    /// If the modifier is not in the requested state, this is a no-op.
    pub fn reassign(&mut self, type_id: u8, id: &ModifierId, new_peer: PeerId) {
        if let Some(info) = self.requested.get_mut(&(type_id, *id)) {
            info.peer_id = new_peer;
            info.requested_at = Instant::now();
        }
    }

    /// Number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.requested.len()
    }

    /// Remove all requests associated with a specific peer.
    pub fn clear_peer(&mut self, peer_id: PeerId) {
        self.requested.retain(|_, info| info.peer_id != peer_id);
    }

    /// Clear all pending state -- used when the chain appears stuck.
    ///
    /// Corresponds to Scala's `ChainIsStuck` message which triggers
    /// `deliveryTracker.reset()`.
    pub fn reset(&mut self) {
        let count = self.requested.len();
        self.requested.clear();
        self.received.clear();
        if count > 0 {
            tracing::warn!(cleared = count, "delivery tracker reset (chain stuck)");
        }
    }

    /// Return the age of a pending request, or `None` if not in `Requested` state.
    pub fn request_age(&self, type_id: u8, id: &ModifierId) -> Option<Duration> {
        self.requested
            .get(&(type_id, *id))
            .map(|info| Instant::now().duration_since(info.requested_at))
    }

    /// Evict entries from `received` older than `max_age`.
    pub fn cleanup_received(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.received
            .retain(|_, ts| now.duration_since(*ts) < max_age);
    }

    /// Evict entries from `invalid` older than `max_age`.
    pub fn cleanup_invalid(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.invalid
            .retain(|_, ts| now.duration_since(*ts) < max_age);
    }

    /// Collect header requests (type_id 101) older than `stale_threshold` that
    /// haven't yet reached the full `delivery_timeout`.
    ///
    /// Returns `(modifier_id, peer_id)` pairs. Does **not** increment the
    /// check counter or remove any entries — the caller should use `reassign`
    /// to hand them to an alternative peer.
    pub fn collect_stale_headers(&self, stale_threshold: Duration) -> Vec<(ModifierId, PeerId)> {
        let now = Instant::now();
        self.requested
            .iter()
            .filter(|(&(type_id, _), info)| {
                if type_id != 101 {
                    return false;
                }
                let age = now.duration_since(info.requested_at);
                age >= stale_threshold && age < self.delivery_timeout
            })
            .map(|(&(_, id), info)| (id, info.peer_id))
            .collect()
    }

    /// Count outstanding header (type_id=101) requests assigned to a specific peer.
    pub fn outstanding_header_count(&self, peer_id: PeerId) -> usize {
        self.requested
            .iter()
            .filter(|(&(type_id, _), info)| type_id == 101 && info.peer_id == peer_id)
            .count()
    }

    /// Count total outstanding header (type_id=101) requests across all peers.
    pub fn total_outstanding_headers(&self) -> usize {
        self.requested
            .keys()
            .filter(|(type_id, _)| *type_id == 101)
            .count()
    }

    /// Create a JSON-serializable snapshot of the current delivery state.
    pub fn snapshot(&self) -> DeliveryTrackerSnapshot {
        DeliveryTrackerSnapshot {
            pending_count: self.requested.len(),
            requested: self
                .requested
                .iter()
                .map(|(&(type_id, ref id), info)| DeliveryRequestInfo {
                    modifier_id: hex::encode(id.0),
                    type_id,
                    peer_id: info.peer_id,
                    checks: info.checks,
                })
                .collect(),
        }
    }
}

/// JSON-serializable snapshot of the delivery tracker state.
#[derive(Debug, Serialize)]
pub struct DeliveryTrackerSnapshot {
    pub pending_count: usize,
    pub requested: Vec<DeliveryRequestInfo>,
}

/// Per-request delivery info within a snapshot.
#[derive(Debug, Serialize)]
pub struct DeliveryRequestInfo {
    pub modifier_id: String,
    pub type_id: u8,
    pub peer_id: u64,
    pub checks: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(byte: u8) -> ModifierId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        ModifierId(bytes)
    }

    #[test]
    fn new_tracker_all_unknown() {
        let tracker = DeliveryTracker::new(60, 3);
        let id = make_id(0xAA);
        assert_eq!(tracker.status(101, &id), ModifierStatus::Unknown);
        assert_eq!(tracker.status(102, &id), ModifierStatus::Unknown);
        assert_eq!(tracker.status(104, &id), ModifierStatus::Unknown);
    }

    #[test]
    fn set_requested_then_status() {
        let mut tracker = DeliveryTracker::new(60, 3);
        let id = make_id(0x01);
        tracker.set_requested(101, id, 42);
        assert_eq!(tracker.status(101, &id), ModifierStatus::Requested);
        assert_eq!(tracker.pending_count(), 1);
    }

    #[test]
    fn set_received_transitions() {
        let mut tracker = DeliveryTracker::new(60, 3);
        let id = make_id(0x02);
        tracker.set_requested(101, id, 42);
        assert_eq!(tracker.status(101, &id), ModifierStatus::Requested);

        tracker.set_received(101, &id);
        assert_eq!(tracker.status(101, &id), ModifierStatus::Received);
        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn set_invalid_permanent() {
        let mut tracker = DeliveryTracker::new(60, 3);
        let id = make_id(0x03);
        tracker.set_requested(101, id, 42);
        tracker.set_invalid(&id);
        assert_eq!(tracker.status(101, &id), ModifierStatus::Invalid);
        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn set_unknown_resets() {
        let mut tracker = DeliveryTracker::new(60, 3);
        let id = make_id(0x04);
        tracker.set_requested(101, id, 42);
        assert_eq!(tracker.status(101, &id), ModifierStatus::Requested);

        tracker.set_unknown(101, &id);
        assert_eq!(tracker.status(101, &id), ModifierStatus::Unknown);
        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn collect_timed_out_empty_when_fresh() {
        let mut tracker = DeliveryTracker::new(60, 3);
        let id = make_id(0x05);
        tracker.set_requested(101, id, 42);
        let timed_out = tracker.collect_timed_out();
        assert!(timed_out.is_empty());
    }

    #[test]
    fn collect_timed_out_returns_expired() {
        // Use timeout=0 so requests immediately expire
        let mut tracker = DeliveryTracker::new(0, 3);
        let id = make_id(0x06);
        tracker.set_requested(101, id, 42);

        let timed_out = tracker.collect_timed_out();
        assert_eq!(timed_out.len(), 1);
        let (type_id, mod_id, peer_id, checks) = timed_out[0];
        assert_eq!(type_id, 101);
        assert_eq!(mod_id, id);
        assert_eq!(peer_id, 42);
        assert_eq!(checks, 1);

        // Item should still be requested (checks=1 < max_checks=3)
        assert_eq!(tracker.status(101, &id), ModifierStatus::Requested);
    }

    #[test]
    fn clear_peer_removes_requests() {
        let mut tracker = DeliveryTracker::new(60, 3);
        let id1 = make_id(0x07);
        let id2 = make_id(0x08);
        tracker.set_requested(101, id1, 1);
        tracker.set_requested(102, id2, 2);
        assert_eq!(tracker.pending_count(), 2);

        tracker.clear_peer(1);
        assert_eq!(tracker.status(101, &id1), ModifierStatus::Unknown);
        assert_eq!(tracker.status(102, &id2), ModifierStatus::Requested);
        assert_eq!(tracker.pending_count(), 1);
    }

    #[test]
    fn reassign_to_new_peer() {
        let mut tracker = DeliveryTracker::new(0, 3); // timeout=0 for immediate expiry
        let id = make_id(0x10);
        tracker.set_requested(101, id, 1);

        // Collect timed out — should return peer 1
        let timed_out = tracker.collect_timed_out();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].2, 1); // peer_id

        // Reassign to peer 2
        tracker.reassign(101, &id, 2);

        // Status should still be Requested
        assert_eq!(tracker.status(101, &id), ModifierStatus::Requested);

        // Next timeout should return peer 2
        let timed_out = tracker.collect_timed_out();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].2, 2); // new peer
    }

    #[test]
    fn reassign_resets_timer() {
        let mut tracker = DeliveryTracker::new(60, 3); // 60s timeout
        let id = make_id(0x11);
        tracker.set_requested(101, id, 1);

        // Reassign to peer 2 — timer should be reset
        tracker.reassign(101, &id, 2);

        // Should NOT be timed out since we just reassigned
        let timed_out = tracker.collect_timed_out();
        assert!(timed_out.is_empty());
    }

    #[test]
    fn reassign_preserves_check_count() {
        let mut tracker = DeliveryTracker::new(0, 3);
        let id = make_id(0x12);
        tracker.set_requested(101, id, 1);

        // First timeout increments checks to 1
        let _ = tracker.collect_timed_out();

        // Reassign
        tracker.reassign(101, &id, 2);

        // Second timeout should show checks=2
        let timed_out = tracker.collect_timed_out();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].3, 2); // checks
    }

    #[test]
    fn reassign_nonexistent_is_noop() {
        let mut tracker = DeliveryTracker::new(60, 3);
        let id = make_id(0x13);
        // Reassign something that was never requested — should not panic
        tracker.reassign(101, &id, 2);
        assert_eq!(tracker.status(101, &id), ModifierStatus::Unknown);
    }

    #[test]
    fn snapshot_serializes_to_json() {
        let mut tracker = DeliveryTracker::new(30, 3);
        tracker.set_requested(101, make_id(0xAA), 1);
        let snapshot = tracker.snapshot();
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["pending_count"], 1);
        let requested = json["requested"].as_array().unwrap();
        assert_eq!(requested.len(), 1);
        assert_eq!(requested[0]["type_id"], 101);
        assert_eq!(requested[0]["peer_id"], 1);
    }

    #[test]
    fn reset_clears_all_state() {
        let mut dt = DeliveryTracker::new(30, 2);
        let id1 = make_id(0x01);
        let id2 = make_id(0x02);
        dt.set_requested(101, id1, 1);
        dt.set_received(101, &id2);
        assert_eq!(dt.status(101, &id1), ModifierStatus::Requested);
        assert_eq!(dt.status(101, &id2), ModifierStatus::Received);
        dt.reset();
        assert_eq!(dt.status(101, &id1), ModifierStatus::Unknown);
        assert_eq!(dt.status(101, &id2), ModifierStatus::Unknown);
        assert_eq!(dt.pending_count(), 0);
    }

    #[test]
    fn cleanup_received_evicts_old() {
        let mut tracker = DeliveryTracker::new(60, 3);
        let id = make_id(0x20);
        // Insert directly with a backdated timestamp
        tracker
            .received
            .insert((101, id), Instant::now() - Duration::from_secs(600));
        assert_eq!(tracker.status(101, &id), ModifierStatus::Received);
        tracker.cleanup_received(Duration::from_secs(300));
        assert_eq!(tracker.status(101, &id), ModifierStatus::Unknown);
    }

    #[test]
    fn cleanup_invalid_evicts_old() {
        let mut tracker = DeliveryTracker::new(60, 3);
        let id = make_id(0x21);
        // Insert directly with a backdated timestamp
        tracker
            .invalid
            .insert(id, Instant::now() - Duration::from_secs(3600));
        assert_eq!(tracker.status(101, &id), ModifierStatus::Invalid);
        tracker.cleanup_invalid(Duration::from_secs(1800));
        assert_eq!(tracker.status(101, &id), ModifierStatus::Unknown);
    }

    #[test]
    fn collect_stale_headers_only_101() {
        // delivery_timeout=10s so stale threshold 3s is within range
        let mut tracker = DeliveryTracker::new(10, 3);
        let hdr_id = make_id(0x30);
        let body_id = make_id(0x31);
        // Backdate both requests to 5s ago
        let past = Instant::now() - Duration::from_secs(5);
        tracker.requested.insert(
            (101, hdr_id),
            RequestInfo {
                peer_id: 1,
                requested_at: past,
                checks: 0,
            },
        );
        tracker.requested.insert(
            (102, body_id),
            RequestInfo {
                peer_id: 2,
                requested_at: past,
                checks: 0,
            },
        );
        let stale = tracker.collect_stale_headers(Duration::from_secs(3));
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].0, hdr_id);
        assert_eq!(stale[0].1, 1);
    }

    #[test]
    fn collect_stale_headers_does_not_increment_checks() {
        let mut tracker = DeliveryTracker::new(10, 3);
        let id = make_id(0x32);
        let past = Instant::now() - Duration::from_secs(5);
        tracker.requested.insert(
            (101, id),
            RequestInfo {
                peer_id: 1,
                requested_at: past,
                checks: 0,
            },
        );
        let _ = tracker.collect_stale_headers(Duration::from_secs(3));
        // checks should still be 0
        let info = tracker.requested.get(&(101, id)).unwrap();
        assert_eq!(info.checks, 0);
    }

    #[test]
    fn collect_stale_headers_ignores_fresh() {
        let mut tracker = DeliveryTracker::new(10, 3);
        let id = make_id(0x33);
        // Just requested (fresh)
        tracker.set_requested(101, id, 1);
        let stale = tracker.collect_stale_headers(Duration::from_secs(3));
        assert!(stale.is_empty());
    }

    #[test]
    fn outstanding_header_count_per_peer() {
        let mut tracker = DeliveryTracker::new(60, 3);
        tracker.set_requested(101, make_id(0x40), 1);
        tracker.set_requested(101, make_id(0x41), 1);
        tracker.set_requested(101, make_id(0x42), 2);
        tracker.set_requested(102, make_id(0x43), 1); // body section, not header
        assert_eq!(tracker.outstanding_header_count(1), 2);
        assert_eq!(tracker.outstanding_header_count(2), 1);
        assert_eq!(tracker.outstanding_header_count(99), 0);
    }

    #[test]
    fn total_outstanding_headers() {
        let mut tracker = DeliveryTracker::new(60, 3);
        tracker.set_requested(101, make_id(0x50), 1);
        tracker.set_requested(101, make_id(0x51), 2);
        tracker.set_requested(101, make_id(0x52), 3);
        tracker.set_requested(102, make_id(0x53), 1); // not a header
        assert_eq!(tracker.total_outstanding_headers(), 3);
    }
}

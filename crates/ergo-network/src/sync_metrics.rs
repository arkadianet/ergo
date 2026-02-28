//! Rolling window counters and batch lifecycle tracking for sync diagnostics.
//!
//! `SyncMetrics` is owned by the event loop (single-threaded, no atomics needed).
//! It emits structured `tracing::info!` logs for each significant event and
//! periodically emits a rollup summary normalised to per-400-header rates.

use std::collections::HashMap;
use std::time::Instant;

use crate::delivery_tracker::PeerId;

/// Metadata for a single download batch (Inv -> request -> delivery cycle).
#[allow(dead_code)]
struct BatchInfo {
    started: Instant,
    inv_len: usize,
    to_request_len: usize,
    peer_count: usize,
    chunks: Vec<(PeerId, usize)>,
    /// Count of modifiers accounted for (applied + invalid + dup_blocked).
    delivered: usize,
}

/// Rolling window counters and active batch tracking for sync diagnostics.
pub struct SyncMetrics {
    next_batch_id: u64,
    window_start: Instant,
    window_secs: u64,

    // ── Window counters ──────────────────────────────────────────────
    headers_applied: u64,
    batches_started: u64,
    timeouts: u64,
    reassignments: u64,
    dup_requests_prevented: u64,
    validate_ms_total: u64,
    db_ms_total: u64,
    peers_used_total: u64,

    // ── Per-peer window counters ─────────────────────────────────────
    requests_sent_by_peer: HashMap<PeerId, u64>,
    mods_received_by_peer: HashMap<PeerId, u64>,
    timeouts_by_peer: HashMap<PeerId, u64>,

    // ── Active batch tracking ────────────────────────────────────────
    active_batches: HashMap<u64, BatchInfo>,
}

impl SyncMetrics {
    /// Create a new `SyncMetrics` instance.
    ///
    /// `window_secs` controls how often the rollup summary is emitted.
    /// A value of 0 means rollup is emitted on every call to `maybe_emit_rollup`.
    pub fn new(window_secs: u64) -> Self {
        Self {
            next_batch_id: 0,
            window_start: Instant::now(),
            window_secs,

            headers_applied: 0,
            batches_started: 0,
            timeouts: 0,
            reassignments: 0,
            dup_requests_prevented: 0,
            validate_ms_total: 0,
            db_ms_total: 0,
            peers_used_total: 0,

            requests_sent_by_peer: HashMap::new(),
            mods_received_by_peer: HashMap::new(),
            timeouts_by_peer: HashMap::new(),

            active_batches: HashMap::new(),
        }
    }

    /// Allocate a monotonically increasing batch ID.
    pub fn new_batch_id(&mut self) -> u64 {
        let id = self.next_batch_id;
        self.next_batch_id += 1;
        id
    }

    /// Record the partition decision for a batch.
    ///
    /// Creates a `BatchInfo` entry.  If >= 128 active batches, evicts the oldest.
    pub fn record_partition(
        &mut self,
        batch_id: u64,
        inv_len: usize,
        to_request_len: usize,
        assignments: &[(PeerId, usize)],
    ) {
        // Evict oldest if at capacity.
        if self.active_batches.len() >= 128 {
            if let Some(&oldest_id) = self
                .active_batches
                .iter()
                .min_by_key(|(_, b)| b.started)
                .map(|(id, _)| id)
            {
                self.active_batches.remove(&oldest_id);
                tracing::warn!(evicted_batch_id = oldest_id, "evicted oldest batch at capacity");
            }
        }

        let peer_count = assignments.len();
        let chunks: Vec<(PeerId, usize)> = assignments.to_vec();

        tracing::info!(
            event = "partition_decided",
            batch_id,
            inv_len,
            to_request_len,
            peer_count,
            "batch partition decided"
        );

        self.active_batches.insert(
            batch_id,
            BatchInfo {
                started: Instant::now(),
                inv_len,
                to_request_len,
                peer_count,
                chunks,
                delivered: 0,
            },
        );

        self.batches_started += 1;
        self.peers_used_total += peer_count as u64;
    }

    /// Record that requests were sent to a peer for a batch.
    pub fn record_requests_sent(
        &mut self,
        batch_id: u64,
        peer: PeerId,
        n_ids: usize,
        chunk_start_idx: usize,
        chunk_end_idx: usize,
    ) {
        *self.requests_sent_by_peer.entry(peer).or_insert(0) += n_ids as u64;

        tracing::info!(
            event = "requests_sent",
            batch_id,
            peer,
            n_ids,
            chunk_start_idx,
            chunk_end_idx,
            "sent modifier requests"
        );
    }

    /// Record that modifiers were received from a peer.
    pub fn record_modifier_received(
        &mut self,
        peer: PeerId,
        n_mods: usize,
        bytes: usize,
        batch_id: Option<u64>,
        elapsed_ms: u64,
    ) {
        *self.mods_received_by_peer.entry(peer).or_insert(0) += n_mods as u64;

        tracing::info!(
            event = "modifier_received",
            peer,
            n_mods,
            bytes,
            batch_id,
            elapsed_ms,
            "received modifiers"
        );
    }

    /// Record that headers have been applied (or rejected).
    ///
    /// Updates the batch's delivered count.  If the batch is fully delivered
    /// (delivered >= to_request_len), it is removed from tracking.
    #[allow(clippy::too_many_arguments)]
    pub fn record_headers_applied(
        &mut self,
        batch_id: u64,
        applied: u64,
        invalid: u64,
        dup_blocked: u64,
        pow_ms: u64,
        db_ms: u64,
        total_ms: u64,
    ) {
        self.headers_applied += applied;
        self.validate_ms_total += pow_ms;
        self.db_ms_total += db_ms;

        let total_this_call = (applied + invalid + dup_blocked) as usize;

        let (batch_age_ms, batch_complete) = if let Some(batch) = self.active_batches.get_mut(&batch_id) {
            batch.delivered += total_this_call;
            let age = batch.started.elapsed().as_millis() as u64;
            let complete = batch.delivered >= batch.to_request_len;
            (age, complete)
        } else {
            (0, false)
        };

        if batch_complete {
            self.active_batches.remove(&batch_id);
        }

        let headers_per_sec = if total_ms > 0 {
            (applied as f64 / total_ms as f64) * 1000.0
        } else {
            0.0
        };

        tracing::info!(
            event = "headers_applied",
            batch_id,
            applied,
            invalid,
            dup_blocked,
            pow_ms,
            db_ms,
            total_ms,
            batch_age_ms,
            headers_per_sec = format!("{:.1}", headers_per_sec),
            batch_complete,
            "applied headers"
        );
    }

    /// Record a delivery timeout event.
    pub fn record_timeout(
        &mut self,
        n_missing: usize,
        from_peer: PeerId,
        to_peer: Option<PeerId>,
        attempt: u32,
        age_ms: u64,
    ) {
        self.timeouts += 1;
        *self.timeouts_by_peer.entry(from_peer).or_insert(0) += 1;

        tracing::info!(
            event = "delivery_timeout",
            n_missing,
            from_peer,
            to_peer,
            attempt,
            age_ms,
            "delivery timeout"
        );
    }

    /// Record a reassignment from one peer to another.
    pub fn record_reassignment(
        &mut self,
        from_peer: PeerId,
        to_peer: PeerId,
        attempt: u32,
    ) {
        self.reassignments += 1;

        tracing::info!(
            event = "reassigned",
            from_peer,
            to_peer,
            attempt,
            "reassigned request"
        );
    }

    /// Record that a duplicate request was prevented.
    pub fn record_dup_prevented(&mut self) {
        self.dup_requests_prevented += 1;
    }

    /// Emit a rollup summary if the window has elapsed.
    ///
    /// Evicts stale batches (>60s) with a warning, then logs a normalised
    /// summary and resets all window counters.
    pub fn maybe_emit_rollup(&mut self) {
        let elapsed = self.window_start.elapsed();
        if elapsed.as_secs() < self.window_secs {
            return;
        }

        // Evict stale batches older than 60s.
        let stale_threshold = std::time::Duration::from_secs(60);
        let stale_ids: Vec<u64> = self
            .active_batches
            .iter()
            .filter(|(_, b)| b.started.elapsed() >= stale_threshold)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale_ids {
            tracing::warn!(batch_id = id, "evicting stale batch (>60s)");
            self.active_batches.remove(id);
        }

        let window_s = elapsed.as_secs_f64();

        let validate_ms_per_400 = if self.headers_applied > 0 {
            (self.validate_ms_total as f64 / self.headers_applied as f64) * 400.0
        } else {
            0.0
        };

        let db_ms_per_400 = if self.headers_applied > 0 {
            (self.db_ms_total as f64 / self.headers_applied as f64) * 400.0
        } else {
            0.0
        };

        let headers_per_sec = if window_s > 0.0 {
            self.headers_applied as f64 / window_s
        } else {
            0.0
        };

        let avg_peers = if self.batches_started > 0 {
            self.peers_used_total as f64 / self.batches_started as f64
        } else {
            0.0
        };

        tracing::info!(
            event = "sync_rollup",
            window_s = format!("{:.1}", window_s),
            headers_applied = self.headers_applied,
            headers_per_sec = format!("{:.1}", headers_per_sec),
            batches_started = self.batches_started,
            timeouts = self.timeouts,
            reassignments = self.reassignments,
            dup_prevented = self.dup_requests_prevented,
            validate_ms_per_400 = format!("{:.0}", validate_ms_per_400),
            db_ms_per_400 = format!("{:.0}", db_ms_per_400),
            avg_peers = format!("{:.1}", avg_peers),
            active_batches = self.active_batches.len(),
            stale_evicted = stale_ids.len(),
            "sync rollup"
        );

        // Reset window counters.
        self.window_start = Instant::now();
        self.headers_applied = 0;
        self.batches_started = 0;
        self.timeouts = 0;
        self.reassignments = 0;
        self.dup_requests_prevented = 0;
        self.validate_ms_total = 0;
        self.db_ms_total = 0;
        self.peers_used_total = 0;
        self.requests_sent_by_peer.clear();
        self.mods_received_by_peer.clear();
        self.timeouts_by_peer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_batch_id_monotonic() {
        let mut m = SyncMetrics::new(10);
        assert_eq!(m.new_batch_id(), 0);
        assert_eq!(m.new_batch_id(), 1);
        assert_eq!(m.new_batch_id(), 2);
    }

    #[test]
    fn record_partition_tracks_batch() {
        let mut m = SyncMetrics::new(10);
        let bid = m.new_batch_id();
        m.record_partition(bid, 500, 400, &[(1, 200), (2, 200)]);
        assert!(m.active_batches.contains_key(&bid));
        let batch = &m.active_batches[&bid];
        assert_eq!(batch.inv_len, 500);
        assert_eq!(batch.to_request_len, 400);
        assert_eq!(batch.peer_count, 2);
        assert_eq!(batch.chunks.len(), 2);
        assert_eq!(batch.delivered, 0);
    }

    #[test]
    fn batch_completes_when_fully_delivered() {
        let mut m = SyncMetrics::new(10);
        let bid = m.new_batch_id();
        m.record_partition(bid, 200, 200, &[(1, 100), (2, 100)]);

        // First half-delivery.
        m.record_headers_applied(bid, 100, 0, 0, 10, 5, 15);
        assert!(m.active_batches.contains_key(&bid));

        // Second half-delivery — batch should now be removed.
        m.record_headers_applied(bid, 100, 0, 0, 10, 5, 15);
        assert!(!m.active_batches.contains_key(&bid));
    }

    #[test]
    fn batch_eviction_at_capacity() {
        let mut m = SyncMetrics::new(10);

        // Fill 128 batches.
        for _ in 0..128 {
            let bid = m.new_batch_id();
            m.record_partition(bid, 10, 10, &[(1, 10)]);
        }
        assert_eq!(m.active_batches.len(), 128);

        // Adding one more should evict the oldest.
        let bid_new = m.new_batch_id();
        m.record_partition(bid_new, 10, 10, &[(1, 10)]);
        assert_eq!(m.active_batches.len(), 128);
        // Batch 0 (the oldest) should have been evicted.
        assert!(!m.active_batches.contains_key(&0));
        assert!(m.active_batches.contains_key(&bid_new));
    }

    #[test]
    fn record_dup_prevented_increments() {
        let mut m = SyncMetrics::new(10);
        assert_eq!(m.dup_requests_prevented, 0);
        m.record_dup_prevented();
        assert_eq!(m.dup_requests_prevented, 1);
        m.record_dup_prevented();
        assert_eq!(m.dup_requests_prevented, 2);
    }

    #[test]
    fn per_peer_counters_accumulate() {
        let mut m = SyncMetrics::new(10);
        let bid = m.new_batch_id();
        m.record_requests_sent(bid, 1, 50, 0, 50);
        m.record_requests_sent(bid, 1, 30, 50, 80);
        m.record_requests_sent(bid, 2, 20, 80, 100);

        assert_eq!(m.requests_sent_by_peer[&1], 80);
        assert_eq!(m.requests_sent_by_peer[&2], 20);
    }

    #[test]
    fn rollup_resets_counters() {
        // window_secs=0 forces rollup on every call.
        let mut m = SyncMetrics::new(0);
        let bid = m.new_batch_id();
        m.record_partition(bid, 100, 100, &[(1, 100)]);
        m.record_requests_sent(bid, 1, 100, 0, 100);
        m.record_headers_applied(bid, 100, 0, 0, 50, 20, 70);
        m.record_dup_prevented();
        m.record_timeout(5, 1, Some(2), 1, 500);
        m.record_reassignment(1, 2, 1);

        // Verify counters are non-zero before rollup.
        assert!(m.headers_applied > 0);
        assert!(m.batches_started > 0);
        assert!(m.timeouts > 0);
        assert!(m.reassignments > 0);
        assert!(m.dup_requests_prevented > 0);
        assert!(!m.requests_sent_by_peer.is_empty());

        m.maybe_emit_rollup();

        // All window counters should be reset.
        assert_eq!(m.headers_applied, 0);
        assert_eq!(m.batches_started, 0);
        assert_eq!(m.timeouts, 0);
        assert_eq!(m.reassignments, 0);
        assert_eq!(m.dup_requests_prevented, 0);
        assert_eq!(m.validate_ms_total, 0);
        assert_eq!(m.db_ms_total, 0);
        assert_eq!(m.peers_used_total, 0);
        assert!(m.requests_sent_by_peer.is_empty());
        assert!(m.mods_received_by_peer.is_empty());
        assert!(m.timeouts_by_peer.is_empty());
    }

    #[test]
    fn timeout_tracking() {
        let mut m = SyncMetrics::new(10);
        m.record_timeout(3, 1, Some(2), 1, 1000);
        m.record_timeout(2, 1, None, 2, 2000);
        m.record_timeout(1, 3, Some(4), 1, 500);

        assert_eq!(m.timeouts, 3);
        assert_eq!(m.timeouts_by_peer[&1], 2);
        assert_eq!(m.timeouts_by_peer[&3], 1);
    }

    #[test]
    fn reassignment_tracking() {
        let mut m = SyncMetrics::new(10);
        m.record_reassignment(1, 2, 1);
        m.record_reassignment(3, 4, 2);
        m.record_reassignment(1, 5, 1);

        assert_eq!(m.reassignments, 3);
    }
}

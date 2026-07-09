//! O4 — the shared mempool-depth sample ring (`v1-api-design.md` Appendix A
//! O4, §3.14 `stats/mempool-depth`).
//!
//! A bounded, in-memory ring that samples pool depth (size / bytes / capacity /
//! min-fee / revalidation backlog) over time. It is **shared infrastructure**:
//! this crate's `mempool/summary?history=` exposes it today, and the future
//! `stats/mempool-depth` time-series endpoint MUST consume this SAME ring
//! (Overlap O4 — one ring, two surfaces) rather than build a parallel one.
//! Consumers project a raw [`MempoolDepthSample`] onto the wire via
//! [`crate::v1::routes::dto::V1MempoolDepthPoint`].
//!
//! Design mirrors the operator event ring (`ergo-node/src/node/event_feed.rs`):
//! FIFO eviction at [`DEPTH_RING_CAP`], a monotonic `seq` per sample, and
//! dependency-light internals (a `std` `VecDeque` behind a `Mutex`). The ring
//! is a passive store — it takes fully-formed observations from a feeder
//! ([`spawn_depth_sampler`] in production; tests push directly) and never reads
//! the clock or the node itself, so it is trivially unit-testable.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use utoipa::ToSchema;

use serde::Serialize;

use crate::traits::NodeReadState;

/// Ring capacity — 512 samples, matching the event ring. At the default
/// [`DEFAULT_SAMPLE_INTERVAL`] this is a little over four hours of history.
pub const DEPTH_RING_CAP: usize = 512;

/// Production sampling cadence. Conservative: pool depth is a slow signal and
/// a denser series would only cost memory for no operator value.
pub const DEFAULT_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);

/// One raw depth observation. `min_fee_per_byte` is the cheapest pooled tx's
/// fee-per-byte (nanoERG/byte), or `0` on an empty pool. Amounts stay `u64`
/// here (the raw store); the wire projection restringifies per the §1.1
/// convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct MempoolDepthSample {
    /// Monotonic sample sequence (starts at 1, never reused) — lets a future
    /// `?since=<seq>` incremental read resume without gaps/dupes.
    pub seq: u64,
    /// Wall-clock time the sample was taken, unix milliseconds.
    pub unix_ms: u64,
    pub size: u32,
    pub total_bytes: u64,
    pub capacity_count: u32,
    pub capacity_bytes: u64,
    pub min_fee_per_byte: u64,
    pub revalidation_pending: u32,
}

/// A bounded ring of [`MempoolDepthSample`]s. Cheap to `Arc`-share between the
/// feeder task and the request handlers.
#[derive(Debug)]
pub struct MempoolDepthRing {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    samples: VecDeque<MempoolDepthSample>,
    next_seq: u64,
}

impl MempoolDepthRing {
    /// An empty ring.
    pub fn new() -> Self {
        MempoolDepthRing {
            inner: Mutex::new(Inner {
                samples: VecDeque::with_capacity(DEPTH_RING_CAP),
                next_seq: 1,
            }),
        }
    }

    /// Record one observation. Assigns the next `seq`, appends, and evicts the
    /// oldest sample once the ring is at [`DEPTH_RING_CAP`]. Returns the
    /// assigned `seq`.
    #[allow(clippy::too_many_arguments)]
    pub fn push_observation(
        &self,
        unix_ms: u64,
        size: u32,
        total_bytes: u64,
        capacity_count: u32,
        capacity_bytes: u64,
        min_fee_per_byte: u64,
        revalidation_pending: u32,
    ) -> u64 {
        // A poisoned lock means a prior panic while holding it; the ring is
        // pure observability, so recover the guard and keep serving rather
        // than propagate the poison into the request path.
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let seq = g.next_seq;
        g.next_seq += 1;
        if g.samples.len() >= DEPTH_RING_CAP {
            g.samples.pop_front();
        }
        g.samples.push_back(MempoolDepthSample {
            seq,
            unix_ms,
            size,
            total_bytes,
            capacity_count,
            capacity_bytes,
            min_fee_per_byte,
            revalidation_pending,
        });
        seq
    }

    /// The most recent `limit` samples, oldest-first (a time series appends).
    /// `limit == 0` yields an empty vec; a `limit` past the ring length yields
    /// everything held.
    pub fn recent(&self, limit: usize) -> Vec<MempoolDepthSample> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let n = limit.min(g.samples.len());
        g.samples
            .iter()
            .skip(g.samples.len() - n)
            .copied()
            .collect()
    }

    /// Every held sample, oldest-first.
    pub fn snapshot(&self) -> Vec<MempoolDepthSample> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.samples.iter().copied().collect()
    }

    /// The newest sample, or `None` when the ring is empty.
    pub fn latest(&self) -> Option<MempoolDepthSample> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.samples.back().copied()
    }

    /// Number of samples currently held.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .samples
            .len()
    }

    /// True when no samples have been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MempoolDepthRing {
    fn default() -> Self {
        Self::new()
    }
}

/// Feed one observation into `ring` from the current read snapshot. Shared by
/// the background sampler and reused wherever a fresh point is wanted. The
/// cheapest-pooled-tx fee-per-byte is derived from the pre-projected mempool
/// snapshot list (a single pass over the already-materialized rows).
pub fn sample_into(read: &dyn NodeReadState, ring: &MempoolDepthRing) {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let summary = read.mempool_summary();
    let min_fee_per_byte = read
        .mempool_transactions()
        .transactions
        .iter()
        .map(|t| t.fee_per_byte_nano_erg)
        .min()
        .unwrap_or(0);
    ring.push_observation(
        unix_ms,
        summary.size,
        summary.total_bytes,
        summary.capacity_count,
        summary.capacity_bytes,
        min_fee_per_byte,
        summary.revalidation_pending,
    );
}

/// Spawn the production depth sampler: a background task that records one
/// observation every `interval` for the life of the process. Returns the
/// `JoinHandle` (production drops it — the task lives as long as the runtime).
///
/// Spawn this ONLY from an async context (a Tokio runtime must be current);
/// the server wiring guards the call with a runtime check so non-async test
/// router builds never touch it.
pub fn spawn_depth_sampler(
    read: Arc<dyn NodeReadState>,
    ring: Arc<MempoolDepthRing>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip-missed-ticks: a stalled runtime must not burst a backlog of
        // samples once it resumes.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            sample_into(read.as_ref(), &ring);
        }
    })
}

/// Process-once guard for the sampler. Router assembly runs once in production
/// but many times across the test suite (each `#[tokio::test]` builds a router
/// under a live runtime); without this guard those builds would each spawn an
/// orphaned detached sampler. The `JoinHandle` is intentionally dropped — the
/// single task lives for the process — so a guarded call gives exactly one
/// sampler per process.
static SAMPLER_STARTED: AtomicBool = AtomicBool::new(false);

/// Spawn the production depth sampler at most ONCE per process (idempotent
/// across repeated router assembly). Subsequent calls are no-ops. Call only
/// from an async context (a Tokio runtime must be current).
pub fn spawn_depth_sampler_once(
    read: Arc<dyn NodeReadState>,
    ring: Arc<MempoolDepthRing>,
    interval: Duration,
) {
    if SAMPLER_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    // The JoinHandle is deliberately dropped: the task runs for the process.
    drop(spawn_depth_sampler(read, ring, interval));
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn push_n(ring: &MempoolDepthRing, n: u32) {
        for i in 0..n {
            ring.push_observation(
                u64::from(i),
                i,
                u64::from(i) * 10,
                100,
                1000,
                u64::from(i),
                0,
            );
        }
    }

    // ----- happy path -----

    #[test]
    fn push_assigns_monotonic_seq_from_one() {
        let ring = MempoolDepthRing::new();
        assert_eq!(ring.push_observation(0, 0, 0, 0, 0, 0, 0), 1);
        assert_eq!(ring.push_observation(0, 0, 0, 0, 0, 0, 0), 2);
        assert_eq!(ring.push_observation(0, 0, 0, 0, 0, 0, 0), 3);
    }

    #[test]
    fn snapshot_is_oldest_first() {
        let ring = MempoolDepthRing::new();
        push_n(&ring, 3);
        let snap = ring.snapshot();
        assert_eq!(
            snap.iter().map(|s| s.size).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            snap.iter().map(|s| s.seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn latest_returns_newest() {
        let ring = MempoolDepthRing::new();
        assert_eq!(ring.latest(), None);
        push_n(&ring, 5);
        assert_eq!(ring.latest().unwrap().size, 4);
    }

    #[test]
    fn recent_returns_tail_oldest_first() {
        let ring = MempoolDepthRing::new();
        push_n(&ring, 5);
        let tail = ring.recent(2);
        assert_eq!(tail.iter().map(|s| s.size).collect::<Vec<_>>(), vec![3, 4]);
    }

    #[test]
    fn recent_zero_is_empty_and_overshoot_is_clamped() {
        let ring = MempoolDepthRing::new();
        push_n(&ring, 3);
        assert!(ring.recent(0).is_empty());
        assert_eq!(ring.recent(999).len(), 3);
    }

    // ----- eviction -----

    #[test]
    fn ring_evicts_oldest_at_capacity_and_bounds_len() {
        let ring = MempoolDepthRing::new();
        // Overfill by one full ring.
        for i in 0..(DEPTH_RING_CAP as u64 + 10) {
            ring.push_observation(i, 0, 0, 0, 0, 0, 0);
        }
        assert_eq!(ring.len(), DEPTH_RING_CAP);
        let snap = ring.snapshot();
        // The oldest 11 were evicted; seqs never reset.
        assert_eq!(snap.first().unwrap().seq, 11);
        assert_eq!(snap.last().unwrap().seq, DEPTH_RING_CAP as u64 + 10);
    }
}

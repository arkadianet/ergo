//! Live apply-phase probes for operator metrics.
//!
//! Snapshot heights can lag while the action loop is inside
//! [`crate::block_proc::process_block`]. These atomics are updated around
//! that call so `/metrics` can show `apply_in_progress` without waiting for
//! the next snapshot publish.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Shared apply-phase gauges (cloned into the API read bridge).
#[derive(Debug, Default)]
pub struct ApplyPhaseMetrics {
    in_progress: AtomicBool,
    last_duration_ms: AtomicU64,
    last_applied_height: AtomicU32,
    /// Unix ms of last finished attempt; `0` = never.
    last_finished_unix_ms: AtomicU64,
}

/// RAII: sets `in_progress` for the duration of one `process_block` call.
pub struct ApplyPhaseGuard<'a> {
    metrics: &'a ApplyPhaseMetrics,
    started: Instant,
    finished: bool,
}

impl ApplyPhaseMetrics {
    pub fn begin(&self) -> ApplyPhaseGuard<'_> {
        self.in_progress.store(true, Ordering::Release);
        ApplyPhaseGuard {
            metrics: self,
            started: Instant::now(),
            finished: false,
        }
    }

    pub fn in_progress(&self) -> bool {
        self.in_progress.load(Ordering::Acquire)
    }

    pub fn last_duration_ms(&self) -> u64 {
        self.last_duration_ms.load(Ordering::Relaxed)
    }

    pub fn last_applied_height(&self) -> u32 {
        self.last_applied_height.load(Ordering::Relaxed)
    }

    /// Age of the last finished attempt in ms, or `None` if never.
    pub fn last_apply_age_ms(&self) -> Option<u64> {
        let finished = self.last_finished_unix_ms.load(Ordering::Relaxed);
        if finished == 0 {
            return None;
        }
        let now = unix_now_ms();
        Some(now.saturating_sub(finished))
    }
}

impl ApplyPhaseGuard<'_> {
    /// Record a successful apply (height) and clear in-progress.
    pub fn success(mut self, height: u32) {
        self.finish(Some(height));
    }

    /// Record a finished attempt without updating last-applied height.
    pub fn failure(mut self) {
        self.finish(None);
    }

    fn finish(&mut self, height: Option<u32>) {
        if self.finished {
            return;
        }
        self.finished = true;
        let ms = self.started.elapsed().as_millis() as u64;
        self.metrics.last_duration_ms.store(ms, Ordering::Relaxed);
        self.metrics
            .last_finished_unix_ms
            .store(unix_now_ms(), Ordering::Relaxed);
        if let Some(h) = height {
            self.metrics.last_applied_height.store(h, Ordering::Relaxed);
        }
        self.metrics.in_progress.store(false, Ordering::Release);
    }
}

impl Drop for ApplyPhaseGuard<'_> {
    fn drop(&mut self) {
        // Panic / early-return path: still clear the flag and stamp duration.
        self.finish(None);
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ----- happy path -----

    #[test]
    fn begin_sets_in_progress_success_clears_and_records_height() {
        let m = Arc::new(ApplyPhaseMetrics::default());
        assert!(!m.in_progress());
        let g = m.begin();
        assert!(m.in_progress());
        g.success(42);
        assert!(!m.in_progress());
        assert_eq!(m.last_applied_height(), 42);
        assert!(m.last_duration_ms() < 5_000);
        assert!(m.last_apply_age_ms().is_some());
    }

    #[test]
    fn drop_without_success_clears_in_progress_without_height() {
        let m = ApplyPhaseMetrics::default();
        {
            let _g = m.begin();
            assert!(m.in_progress());
        }
        assert!(!m.in_progress());
        assert_eq!(m.last_applied_height(), 0);
        assert!(m.last_apply_age_ms().is_some());
    }

    #[test]
    fn failure_does_not_clobber_prior_height() {
        let m = ApplyPhaseMetrics::default();
        m.begin().success(10);
        m.begin().failure();
        assert_eq!(m.last_applied_height(), 10);
    }
}

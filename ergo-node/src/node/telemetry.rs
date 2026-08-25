//! Starvation-free live telemetry (issue #266).
//!
//! The snapshot publisher that feeds `/metrics` runs on the same tokio
//! runtime as the action loop. While a long synchronous block apply owns
//! the loop (the #264 failure shape), the publisher never runs and every
//! gauge freezes at its last value — RSS reports boot-time numbers,
//! uptime stops, and no wedge alarm can fire, precisely when operators
//! need them.
//!
//! This module runs a plain [`std::thread`] that nothing on the runtime
//! can starve. Each tick it samples process-level truth (`/proc/self`,
//! wall clock) plus the lock-free [`ApplyPhaseMetrics`] atomics, stores
//! the results in atomics that `/metrics` overlays onto the served
//! values, and raises a wall-clock wedge alarm — with a single ERROR log
//! per episode — when the running apply exceeds the threshold.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ergo_sync::ApplyPhaseMetrics;

/// Wall-clock age beyond which a single running apply is considered
/// wedged. Steady-state applies complete in seconds; even the legacy
/// 2.4-min/block grind stayed two orders of magnitude below this. Not
/// configurable yet — revisit if a legitimate apply class approaches it.
pub const APPLY_WEDGED_THRESHOLD: Duration = Duration::from_secs(600);

/// Atomics overlaid onto `/metrics` by the API bridge. All readers are
/// wait-free; the writer is the telemetry thread.
#[derive(Debug, Default)]
pub struct LiveTelemetry {
    rss_kb: AtomicU64,
    uptime_secs: AtomicU64,
    /// Age of the currently running apply; `-1` = idle.
    apply_age_ms: AtomicI64,
    apply_wedged: AtomicBool,
}

impl LiveTelemetry {
    /// Latest sampled RSS, KiB (0 = sampler absent / non-Linux).
    pub fn rss_kb(&self) -> u64 {
        self.rss_kb.load(Ordering::Relaxed)
    }

    /// Latest sampled process uptime, seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.uptime_secs.load(Ordering::Relaxed)
    }

    /// Age of the currently running apply in ms (`None` = idle at last
    /// sample).
    pub fn apply_age_ms(&self) -> Option<i64> {
        let v = self.apply_age_ms.load(Ordering::Relaxed);
        (v >= 0).then_some(v)
    }

    /// Wall-clock wedge verdict at last sample.
    pub fn apply_wedged(&self) -> bool {
        self.apply_wedged.load(Ordering::Relaxed)
    }

    /// Record one telemetry sample. Called by the spawned thread each
    /// tick; also the seam tests use to simulate samples without a
    /// thread (`age_wedged = None` ⇒ idle).
    pub fn store_sample(
        &self,
        rss_kb: u64,
        uptime_secs: u64,
        apply_age_ms: Option<i64>,
        apply_wedged: bool,
    ) {
        self.rss_kb.store(rss_kb, Ordering::Relaxed);
        self.uptime_secs.store(uptime_secs, Ordering::Relaxed);
        self.apply_age_ms
            .store(apply_age_ms.unwrap_or(-1), Ordering::Relaxed);
        self.apply_wedged.store(apply_wedged, Ordering::Relaxed);
    }
}

/// Pure classifier so the wedge rule is unit-testable without threads:
/// `None` when idle, otherwise `(age_ms, wedged)` against `threshold`.
fn classify_apply(
    in_progress_started_unix_ms: u64,
    now_unix_ms: u64,
    threshold: Duration,
) -> Option<(i64, bool)> {
    if in_progress_started_unix_ms == 0 || now_unix_ms < in_progress_started_unix_ms {
        return None;
    }
    let age_ms = (now_unix_ms - in_progress_started_unix_ms) as i64;
    let wedged = age_ms >= threshold.as_millis() as i64;
    Some((age_ms, wedged))
}

fn read_rss_kb() -> u64 {
    // /proc/self/statm field 1 = resident pages. Cheaper than smaps and
    // sufficient for the gauge (smaps attribution lives in mem_smaps.rs).
    match std::fs::read_to_string("/proc/self/statm") {
        Ok(s) => s
            .split_whitespace()
            .nth(1)
            .and_then(|p| p.parse::<u64>().ok())
            .map(|pages| pages * 4096 / 1024)
            .unwrap_or(0),
        Err(_) => 0,
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Spawn the telemetry thread. Returns the shared [`LiveTelemetry`] the
/// API bridge overlays onto `/metrics`. The thread runs for the process
/// lifetime; it performs no locking and never touches the runtime.
pub fn spawn(
    phase: std::sync::Arc<ApplyPhaseMetrics>,
    sample_every: Duration,
) -> Arc<LiveTelemetry> {
    let live = Arc::new(LiveTelemetry::default());
    let writer = Arc::clone(&live);
    let started_at = Instant::now();
    std::thread::Builder::new()
        .name("live-telemetry".into())
        .spawn(move || {
            let mut wedged_latched = false;
            loop {
                std::thread::sleep(sample_every);
                let rss = read_rss_kb();
                let uptime = started_at.elapsed().as_secs();
                let sample = classify_apply(
                    phase.current_started_unix_ms(),
                    unix_now_ms(),
                    APPLY_WEDGED_THRESHOLD,
                );
                match &sample {
                    Some((age_ms, wedged)) => {
                        if *wedged && !wedged_latched {
                            wedged_latched = true;
                            tracing::error!(
                                event = "apply_wall_clock_wedge",
                                apply_age_ms = age_ms,
                                threshold_secs = APPLY_WEDGED_THRESHOLD.as_secs(),
                                "block apply exceeds wall-clock wedge threshold — \
                                 runtime telemetry may be starved; attribute memory via \
                                 /proc/<pid>/smaps_rollup (Pss_Anon) before restarting"
                            );
                        } else if !*wedged && wedged_latched {
                            wedged_latched = false;
                            tracing::warn!(
                                event = "apply_wall_clock_wedge_cleared",
                                apply_age_ms = age_ms,
                                "long apply finished — telemetry wedge alarm cleared"
                            );
                        }
                    }
                    None => {
                        if wedged_latched {
                            wedged_latched = false;
                            tracing::warn!(
                                event = "apply_wall_clock_wedge_cleared",
                                "apply phase ended — telemetry wedge alarm cleared"
                            );
                        }
                    }
                }
                writer.store_sample(
                    rss,
                    uptime,
                    sample.map(|(age, _)| age),
                    sample.map(|(_, w)| w).unwrap_or(false),
                );
            }
        })
        .expect("live-telemetry thread spawn");
    live
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD: Duration = Duration::from_secs(600);

    #[test]
    fn idle_phase_classifies_none() {
        assert_eq!(classify_apply(0, 1_000_000, THRESHOLD), None);
    }

    #[test]
    fn clock_skew_classifies_none_not_negative() {
        // started "after" now (skewed clock): treat as no sample rather
        // than emit a negative age.
        assert_eq!(classify_apply(2_000_000, 1_000_000, THRESHOLD), None);
    }

    #[test]
    fn young_apply_is_not_wedged() {
        let (age, wedged) =
            classify_apply(1_000_000, 1_000_000 + 599_999, THRESHOLD).expect("running");
        assert_eq!(age, 599_999);
        assert!(!wedged);
    }

    #[test]
    fn apply_at_threshold_is_wedged() {
        let (age, wedged) =
            classify_apply(1_000_000, 1_000_000 + 600_000, THRESHOLD).expect("running");
        assert_eq!(age, 600_000);
        assert!(wedged);
    }

    #[test]
    fn statm_reader_returns_nonzero_on_linux_or_zero_elsewhere() {
        // Ground-truth smoke: on Linux this must read our own RSS; on
        // other platforms the documented 0 fallback holds.
        let kb = read_rss_kb();
        if cfg!(target_os = "linux") {
            assert!(kb > 0, "statm RSS should be positive on Linux, got {kb}");
        } else {
            assert_eq!(kb, 0);
        }
    }
}

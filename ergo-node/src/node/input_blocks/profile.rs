//! Always-on phase timing for the input-block hot path (task 8b).
//!
//! The subsystem handles roughly one peer frame per second on a devnet
//! tuned to protocol scale, and the follower's lag is measured in input
//! blocks, so "which phase costs what" has to be answerable from a live
//! node rather than from a `perf` sample that cannot tell
//! `build_ctx_data` from `Processor::handle`.
//!
//! A `tracing` span per phase would allocate and lock once per frame at
//! DEBUG *and* be filtered out entirely at INFO, which is where the
//! measurement is needed. Instead each phase owns a fixed log2-bucketed
//! histogram of microseconds: a branchless `leading_zeros` and one
//! increment per observation, no allocation, and p50/p95 readable
//! without keeping samples. The whole table is dumped as one `debug!`
//! line every [`REPORT_INTERVAL`], with the per-phase events/s the
//! interval actually saw.
//!
//! Buckets are powers of two in microseconds: bucket `i` holds
//! `[2^(i-1), 2^i)` µs, bucket 0 holds `0 µs`. A percentile is reported
//! as its bucket's UPPER bound, so a quoted p95 is an over-estimate by
//! at most 2x and never an under-estimate — the direction that matters
//! when the number is used to decide what to optimise.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// How often [`Profile::report`] emits, when anything was measured.
pub(in crate::node) const REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// 32 buckets of powers of two microseconds reaches ~35 minutes, which
/// no phase can exceed without the node being dead anyway.
const BUCKETS: usize = 32;

/// One measured phase of the input-block hot path.
///
/// The order is the order the phases run in, which is also the order the
/// report prints, so a reader sees the pipeline rather than an alphabet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) enum Phase {
    /// Decoding one inbound frame (codes 100/102/104/105/106).
    FrameDecode,
    /// `build_ctx_data` — the per-event `ProcessorCtx` inputs.
    BuildCtx,
    /// `Processor::handle` itself.
    ProcessorHandle,
    /// The whole `execute_effects` drain, validation included.
    ExecuteEffects,
    /// Gathering `previous` + own bodies for one validation job.
    ValidateCollect,
    /// `build_input_block_context` — pre-header, params, last headers.
    ValidateContext,
    /// `validate_input_block_transactions` itself.
    ValidateRun,
    /// Rebuilding and publishing the REST read slot.
    ReadSlotRefresh,
    /// Applying an accepted input block's transactions to the mempool.
    MempoolApply,
    /// Planning + assembling an ordering block from input-block bodies.
    OrderingReconstruct,
}

impl Phase {
    /// Every phase, in pipeline order.
    const ALL: [Phase; 10] = [
        Phase::FrameDecode,
        Phase::BuildCtx,
        Phase::ProcessorHandle,
        Phase::ExecuteEffects,
        Phase::ValidateCollect,
        Phase::ValidateContext,
        Phase::ValidateRun,
        Phase::ReadSlotRefresh,
        Phase::MempoolApply,
        Phase::OrderingReconstruct,
    ];

    /// Stable name used as the report key.
    pub(in crate::node) fn name(self) -> &'static str {
        match self {
            Phase::FrameDecode => "frame_decode",
            Phase::BuildCtx => "build_ctx",
            Phase::ProcessorHandle => "processor_handle",
            Phase::ExecuteEffects => "execute_effects",
            Phase::ValidateCollect => "validate_collect",
            Phase::ValidateContext => "validate_context",
            Phase::ValidateRun => "validate_run",
            Phase::ReadSlotRefresh => "read_slot_refresh",
            Phase::MempoolApply => "mempool_apply",
            Phase::OrderingReconstruct => "ordering_reconstruct",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// A log2-bucketed microsecond histogram.
#[derive(Debug, Clone)]
struct Hist {
    buckets: [u64; BUCKETS],
    count: u64,
    total_us: u64,
    max_us: u64,
}

impl Default for Hist {
    fn default() -> Self {
        Self {
            buckets: [0; BUCKETS],
            count: 0,
            total_us: 0,
            max_us: 0,
        }
    }
}

/// The bucket `us` falls in: 0 for `0`, else `floor(log2(us)) + 1`, so
/// bucket `i > 0` covers `[2^(i-1), 2^i)` and its upper bound is `2^i`.
fn bucket_of(us: u64) -> usize {
    if us == 0 {
        return 0;
    }
    let hi = 64 - us.leading_zeros() as usize; // 1..=64 for us >= 1
    hi.min(BUCKETS - 1)
}

/// The upper bound of bucket `i`, in microseconds. The top bucket is an
/// overflow bucket — everything at or above `2^(BUCKETS-2)` µs lands in
/// it — so its bound is unbounded rather than a number that would
/// under-state the sample it holds. [`Hist::quantile_us`] narrows that
/// back to the largest value actually observed.
fn bucket_upper_us(i: usize) -> u64 {
    match i {
        0 => 0,
        i if i >= BUCKETS - 1 => u64::MAX,
        i => 1u64 << (i as u32),
    }
}

impl Hist {
    fn observe(&mut self, us: u64) {
        self.buckets[bucket_of(us)] += 1;
        self.count = self.count.saturating_add(1);
        self.total_us = self.total_us.saturating_add(us);
        self.max_us = self.max_us.max(us);
    }

    /// The upper bound of the bucket holding the `q`-quantile (`q` in
    /// `0.0..=1.0`), in microseconds. `0` when nothing was observed.
    fn quantile_us(&self, q: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        // `ceil(q * count)`, clamped to at least one sample, so q=0.5 on
        // a single observation names that observation's bucket.
        let target = ((q * self.count as f64).ceil() as u64).clamp(1, self.count);
        let mut seen = 0u64;
        for (i, n) in self.buckets.iter().enumerate() {
            seen += *n;
            if seen >= target {
                // A bucket's upper bound can exceed every sample in it;
                // the largest observation is a tighter bound that is
                // still never an under-estimate, and it is what keeps
                // the overflow bucket's `u64::MAX` readable.
                return bucket_upper_us(i).min(self.max_us.max(1));
            }
        }
        self.max_us
    }

    fn mean_us(&self) -> u64 {
        self.total_us.checked_div(self.count).unwrap_or(0)
    }
}

/// Per-phase timings since the last report.
///
/// Reset on every report so each line describes its own interval — a
/// cumulative table hides a regression that starts halfway through a
/// run, which is exactly the shape of the lag this was built to chase.
#[derive(Debug)]
pub(in crate::node) struct Profile {
    phases: [Hist; Phase::ALL.len()],
    /// How many of each effect the processor emitted this interval.
    ///
    /// The phase histograms answer "is a step expensive"; they cannot
    /// answer "is the step happening at all". The follower's lag turned
    /// out to be the second question — every phase costs microseconds
    /// and the chain still extends far slower than the miner publishes —
    /// so the effect mix is what says which part of the pipeline is
    /// starved.
    effects: BTreeMap<&'static str, u64>,
    window_start: Instant,
    last_report: Instant,
}

impl Profile {
    pub(in crate::node) fn new(now: Instant) -> Self {
        Self {
            phases: std::array::from_fn(|_| Hist::default()),
            effects: BTreeMap::new(),
            window_start: now,
            last_report: now,
        }
    }

    /// Count one emitted effect, by variant name.
    pub(in crate::node) fn count_effect(&mut self, name: &'static str) {
        *self.effects.entry(name).or_insert(0) += 1;
    }

    /// Record one observation of `phase`.
    pub(in crate::node) fn observe(&mut self, phase: Phase, elapsed: Duration) {
        self.phases[phase.index()].observe(elapsed.as_micros() as u64);
    }

    /// One report line per phase that saw at least one observation,
    /// emitted at most once per [`REPORT_INTERVAL`]. Returns the lines
    /// so the caller (and the tests) can see exactly what was published.
    ///
    /// The window is reset only when a report is actually produced, so
    /// an idle subsystem accumulates rather than silently discarding.
    pub(in crate::node) fn report(&mut self, now: Instant) -> Option<Report> {
        if now.saturating_duration_since(self.last_report) < REPORT_INTERVAL {
            return None;
        }
        let window = now.saturating_duration_since(self.window_start);
        let secs = window.as_secs_f64().max(f64::MIN_POSITIVE);
        let lines: Vec<PhaseReport> = Phase::ALL
            .iter()
            .filter(|p| self.phases[p.index()].count > 0)
            .map(|p| {
                let h = &self.phases[p.index()];
                PhaseReport {
                    phase: p.name(),
                    count: h.count,
                    per_sec: h.count as f64 / secs,
                    p50_us: h.quantile_us(0.50),
                    p95_us: h.quantile_us(0.95),
                    max_us: h.max_us,
                    mean_us: h.mean_us(),
                    // Share of the window this phase occupied. Phases
                    // nest (`execute_effects` contains `validate_run`),
                    // so these do not sum to 100 — which is the point:
                    // a nested phase's share is read against its parent.
                    busy_pct: (h.total_us as f64 / 1_000_000.0) / secs * 100.0,
                }
            })
            .collect();
        let effects = std::mem::take(&mut self.effects);
        self.phases = std::array::from_fn(|_| Hist::default());
        self.window_start = now;
        self.last_report = now;
        if lines.is_empty() && effects.is_empty() {
            return None;
        }
        Some(Report {
            phases: lines,
            effects: effects.into_iter().collect(),
            window,
        })
    }
}

/// One interval's measurement: the per-phase table plus the effect mix
/// that produced it.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::node) struct Report {
    pub(in crate::node) phases: Vec<PhaseReport>,
    /// `(effect name, count)`, name-ordered.
    pub(in crate::node) effects: Vec<(&'static str, u64)>,
    /// The interval these numbers cover.
    pub(in crate::node) window: Duration,
}

/// One phase's line in a [`Profile::report`].
#[derive(Debug, Clone, PartialEq)]
pub(in crate::node) struct PhaseReport {
    pub(in crate::node) phase: &'static str,
    pub(in crate::node) count: u64,
    pub(in crate::node) per_sec: f64,
    pub(in crate::node) p50_us: u64,
    pub(in crate::node) p95_us: u64,
    pub(in crate::node) max_us: u64,
    pub(in crate::node) mean_us: u64,
    pub(in crate::node) busy_pct: f64,
}

impl std::fmt::Display for PhaseReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} n={} rate={:.2}/s p50={}us p95={}us max={}us mean={}us busy={:.1}%",
            self.phase,
            self.count,
            self.per_sec,
            self.p50_us,
            self.p95_us,
            self.max_us,
            self.mean_us,
            self.busy_pct
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn hist_of(samples: &[u64]) -> Hist {
        let mut h = Hist::default();
        for s in samples {
            h.observe(*s);
        }
        h
    }

    // ----- happy path -----

    #[test]
    fn bucket_of_zero_is_bucket_zero() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_upper_us(0), 0);
    }

    #[test]
    fn bucket_upper_bound_never_understates_the_sample() {
        for us in [1u64, 2, 3, 7, 8, 9, 1_000, 999_999, 1 << 40] {
            let b = bucket_of(us);
            assert!(
                bucket_upper_us(b) >= us,
                "bucket {b} upper {} under-states {us}",
                bucket_upper_us(b)
            );
        }
    }

    #[test]
    fn quantiles_track_the_observed_spread() {
        // 99 samples at 1us, one at ~1ms: p50 must stay small, p95 too,
        // and the max must carry the outlier exactly.
        let mut samples = vec![1u64; 99];
        samples.push(1_000);
        let h = hist_of(&samples);
        assert_eq!(h.count, 100);
        assert!(h.quantile_us(0.50) <= 2, "p50 {}", h.quantile_us(0.50));
        assert!(h.quantile_us(0.95) <= 2, "p95 {}", h.quantile_us(0.95));
        assert_eq!(h.max_us, 1_000);
    }

    #[test]
    fn p95_names_the_tail_when_the_tail_is_large() {
        // 90 fast, 10 slow: the 95th percentile is inside the slow tail.
        let mut samples = vec![1u64; 90];
        samples.extend(std::iter::repeat_n(100_000u64, 10));
        let h = hist_of(&samples);
        assert!(
            h.quantile_us(0.95) >= 100_000,
            "p95 {} should name the 100ms tail",
            h.quantile_us(0.95)
        );
    }

    // ----- error paths -----

    #[test]
    fn an_empty_histogram_reports_zero_rather_than_panicking() {
        let h = Hist::default();
        assert_eq!(h.quantile_us(0.5), 0);
        assert_eq!(h.quantile_us(0.95), 0);
        assert_eq!(h.mean_us(), 0);
    }

    #[test]
    fn report_is_silent_before_the_interval_elapses() {
        let t0 = Instant::now();
        let mut p = Profile::new(t0);
        p.observe(Phase::ValidateRun, Duration::from_millis(5));
        assert!(p.report(t0 + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn report_is_silent_when_nothing_was_measured() {
        let t0 = Instant::now();
        let mut p = Profile::new(t0);
        assert!(p.report(t0 + REPORT_INTERVAL).is_none());
    }

    // ----- round-trips -----

    #[test]
    fn report_lists_only_phases_that_fired_and_resets_the_window() {
        let t0 = Instant::now();
        let mut p = Profile::new(t0);
        for _ in 0..4 {
            p.observe(Phase::ValidateRun, Duration::from_millis(10));
        }
        p.observe(Phase::BuildCtx, Duration::from_micros(3));

        let report = p.report(t0 + REPORT_INTERVAL).expect("a report");
        let lines = &report.phases;
        let names: Vec<&str> = lines.iter().map(|l| l.phase).collect();
        // Pipeline order, not insertion order.
        assert_eq!(names, vec!["build_ctx", "validate_run"]);
        let run = lines.iter().find(|l| l.phase == "validate_run").unwrap();
        assert_eq!(run.count, 4);
        assert!(run.p50_us >= 10_000, "p50 {}", run.p50_us);
        assert!((run.per_sec - 0.4).abs() < 0.05, "rate {}", run.per_sec);

        // The window reset: the next interval reports only what it saw.
        p.observe(Phase::BuildCtx, Duration::from_micros(3));
        let next = p.report(t0 + REPORT_INTERVAL * 2).expect("a second report");
        assert_eq!(next.phases.len(), 1);
        assert_eq!(next.phases[0].phase, "build_ctx");
        assert_eq!(next.phases[0].count, 1);
    }

    #[test]
    fn the_effect_mix_is_reported_and_reset_with_its_interval() {
        let t0 = Instant::now();
        let mut p = Profile::new(t0);
        p.count_effect("Validate");
        p.count_effect("Validate");
        p.count_effect("ChainChanged");
        let report = p.report(t0 + REPORT_INTERVAL).expect("a report");
        assert_eq!(
            report.effects,
            vec![("ChainChanged", 1u64), ("Validate", 2)],
            "name-ordered counts for the interval"
        );
        assert!(
            p.report(t0 + REPORT_INTERVAL * 2).is_none(),
            "the mix resets with the window"
        );
    }

    #[test]
    fn an_interval_with_only_effects_still_reports() {
        // A pipeline that emits requests but never validates is exactly
        // the shape the lag turned out to have; it must not be silent.
        let t0 = Instant::now();
        let mut p = Profile::new(t0);
        p.count_effect("RequestTransactions");
        let report = p.report(t0 + REPORT_INTERVAL).expect("a report");
        assert!(report.phases.is_empty());
        assert_eq!(report.effects, vec![("RequestTransactions", 1u64)]);
    }

    #[test]
    fn observe_records_against_the_named_phase_only() {
        let t0 = Instant::now();
        let mut p = Profile::new(t0);
        p.observe(Phase::FrameDecode, Duration::from_micros(4));
        assert_eq!(p.phases[Phase::FrameDecode.index()].count, 1);
        assert_eq!(p.phases[Phase::BuildCtx.index()].count, 0);
    }

    #[test]
    fn every_phase_has_a_distinct_name_and_index() {
        let mut seen = std::collections::HashSet::new();
        for (i, p) in Phase::ALL.iter().enumerate() {
            assert_eq!(p.index(), i, "{} is out of pipeline order", p.name());
            assert!(seen.insert(p.name()), "duplicate name {}", p.name());
        }
    }
}

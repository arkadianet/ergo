//! Per-step JIT-cost trace, gated behind the `cost-trace` feature.
//!
//! When enabled, the evaluator and the reduce/verify glue record one
//! `CostTraceEntry` per cost-charging step into a thread-local buffer.
//! Used to diagnose cost-divergence bugs against the Scala oracle —
//! switch the feature on, run a single fixture through both nodes, and
//! diff the resulting trace dumps.
//!
//! The whole module is feature-gated; with `cost-trace` off the
//! recording calls expand to no-ops at the call sites and this file
//! is excluded from the build entirely.

use std::cell::RefCell;

/// One cost-charging step recorded by the evaluator.
#[derive(Debug, Clone)]
pub struct CostTraceEntry {
    /// Short label identifying the cost source (opcode name, "Crypto:N",
    /// or similar).
    pub label: String,
    /// JitCost units added at this step.
    pub delta: u64,
    /// Running JitCost total after `delta` was added.
    pub total: u64,
}

/// Recording sink: an ordered list of cost-charging steps plus
/// snap-to-block-boundary events.
#[derive(Debug, Default)]
pub struct CostTrace {
    /// All `(label, delta, total)` entries in record order.
    pub entries: Vec<CostTraceEntry>,
    /// `(before, after)` pairs for each `snap_to_block_boundary` call,
    /// useful when reconciling per-input vs per-block cost rounding.
    pub snaps: Vec<(u64, u64)>,
}

impl CostTrace {
    /// Sum of `delta` for every entry whose label starts with `prefix`.
    pub fn sum_by_prefix(&self, prefix: &str) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.label.starts_with(prefix))
            .map(|e| e.delta)
            .sum()
    }

    /// Count of entries whose label starts with `prefix`.
    pub fn count_by_prefix(&self, prefix: &str) -> usize {
        self.entries
            .iter()
            .filter(|e| e.label.starts_with(prefix))
            .count()
    }

    /// Pretty-print the trace to stderr. Format is intentionally
    /// human-readable, not a stable machine format.
    pub fn dump(&self, header: &str) {
        eprintln!("=== COST TRACE: {} ===", header);
        for e in &self.entries {
            eprintln!("  +{:<6} {:<40} total={}", e.delta, e.label, e.total);
        }
        for &(before, after) in &self.snaps {
            eprintln!(
                "  SNAP: {} -> {} (dropped {})",
                before,
                after,
                before - after
            );
        }
        eprintln!(
            "=== total={} ===",
            self.entries.last().map_or(0, |e| e.total)
        );
    }
}

thread_local! {
    static TRACE: RefCell<Option<CostTrace>> = const { RefCell::new(None) };
}

/// Begin recording on the current thread. Replaces any existing trace.
pub fn enable() {
    TRACE.with(|t| *t.borrow_mut() = Some(CostTrace::default()));
}

/// Stop recording and consume the accumulated trace, if any.
pub fn take() -> Option<CostTrace> {
    TRACE.with(|t| t.borrow_mut().take())
}

/// Append a `(label, delta, total)` entry to the active trace if any.
/// No-op when no trace is active.
pub fn record(label: impl Into<String>, delta: u64, total: u64) {
    TRACE.with(|t| {
        if let Some(trace) = t.borrow_mut().as_mut() {
            trace.entries.push(CostTraceEntry {
                label: label.into(),
                delta,
                total,
            });
        }
    });
}

/// Append a `(before, after)` snap event to the active trace if any.
/// No-op when no trace is active.
pub fn record_snap(before: u64, after: u64) {
    TRACE.with(|t| {
        if let Some(trace) = t.borrow_mut().as_mut() {
            trace.snaps.push((before, after));
        }
    });
}

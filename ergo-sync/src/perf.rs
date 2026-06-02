//! Per-tick header-pipeline performance counters.
//!
//! Aggregates wall-clock and CPU-time spent in each header-processing
//! phase. Reset by the node heartbeat (~3s) which formats a `[perf-hdr]`
//! line. Cheap (a handful of `Instant::now()` calls per header) but
//! still feature-flagged so a future release build can drop it.
//!
//! Design notes:
//! - `pow_wall_ns` is wall time spent in Phase 1 (parse + PoW). For the
//!   batched / orphan paths this is the rayon `par_iter` wall — i.e.
//!   the time the action loop is blocked, not the sum of per-header
//!   work. `pow_cpu_ns` carries the per-header sum so we can derive
//!   parallel efficiency = pow_cpu_ns / (pow_wall_ns * cores).
//! - `finalize_ns` is the sequential Phase 2 (chain linkage + difficulty
//!   walk + per-header persist if not batched).
//! - `flush_ns` is the deferred batch flush at the end of
//!   `batch_validate_headers`.
//! - Orphan rerun is tracked separately because it is wasted work — the
//!   same headers re-PoW'd on every drain pass — and we want to see it
//!   independent of forward-progress headers.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct HeaderPerfCounters {
    pub headers: AtomicU64,
    pub pow_wall_ns: AtomicU64,
    pub pow_cpu_ns: AtomicU64,
    pub finalize_ns: AtomicU64,
    pub flush_ns: AtomicU64,
    pub orphan_headers: AtomicU64,
    pub orphan_pow_wall_ns: AtomicU64,
    pub orphan_pow_cpu_ns: AtomicU64,
    pub orphan_finalize_ns: AtomicU64,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct HeaderPerfSnapshot {
    pub headers: u64,
    pub pow_wall_ns: u64,
    pub pow_cpu_ns: u64,
    pub finalize_ns: u64,
    pub flush_ns: u64,
    pub orphan_headers: u64,
    pub orphan_pow_wall_ns: u64,
    pub orphan_pow_cpu_ns: u64,
    pub orphan_finalize_ns: u64,
}

impl HeaderPerfCounters {
    pub fn add_pow_wall(&self, ns: u64) {
        self.pow_wall_ns.fetch_add(ns, Ordering::Relaxed);
    }
    pub fn add_pow_cpu(&self, ns: u64) {
        self.pow_cpu_ns.fetch_add(ns, Ordering::Relaxed);
    }
    pub fn add_finalize(&self, ns: u64) {
        self.finalize_ns.fetch_add(ns, Ordering::Relaxed);
    }
    pub fn add_flush(&self, ns: u64) {
        self.flush_ns.fetch_add(ns, Ordering::Relaxed);
    }
    pub fn add_headers(&self, n: u64) {
        self.headers.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_orphan_pow_wall(&self, ns: u64) {
        self.orphan_pow_wall_ns.fetch_add(ns, Ordering::Relaxed);
    }
    pub fn add_orphan_pow_cpu(&self, ns: u64) {
        self.orphan_pow_cpu_ns.fetch_add(ns, Ordering::Relaxed);
    }
    pub fn add_orphan_finalize(&self, ns: u64) {
        self.orphan_finalize_ns.fetch_add(ns, Ordering::Relaxed);
    }
    pub fn add_orphan_headers(&self, n: u64) {
        self.orphan_headers.fetch_add(n, Ordering::Relaxed);
    }

    /// Atomically read all counters and reset them to zero.
    /// Called once per heartbeat from the node event loop.
    pub fn take(&self) -> HeaderPerfSnapshot {
        HeaderPerfSnapshot {
            headers: self.headers.swap(0, Ordering::Relaxed),
            pow_wall_ns: self.pow_wall_ns.swap(0, Ordering::Relaxed),
            pow_cpu_ns: self.pow_cpu_ns.swap(0, Ordering::Relaxed),
            finalize_ns: self.finalize_ns.swap(0, Ordering::Relaxed),
            flush_ns: self.flush_ns.swap(0, Ordering::Relaxed),
            orphan_headers: self.orphan_headers.swap(0, Ordering::Relaxed),
            orphan_pow_wall_ns: self.orphan_pow_wall_ns.swap(0, Ordering::Relaxed),
            orphan_pow_cpu_ns: self.orphan_pow_cpu_ns.swap(0, Ordering::Relaxed),
            orphan_finalize_ns: self.orphan_finalize_ns.swap(0, Ordering::Relaxed),
        }
    }
}

impl HeaderPerfSnapshot {
    /// True if any counter is non-zero (i.e. there's something to log).
    pub fn is_active(&self) -> bool {
        self.headers > 0 || self.orphan_headers > 0
    }
}

/// Per-tick block-pipeline performance counters.
///
/// All `*_ns` are summed wall-clock time spent in that phase across every
/// block applied this heartbeat window. Drain-loop counters describe the
/// scheduler that pulls sequential blocks off the store: how often it
/// runs, how much wall time each invocation takes, and how often it
/// stalls because the next block's sections haven't arrived yet
/// (`section_wait_calls`). High `section_wait_calls / drain_calls`
/// indicates the bottleneck is upstream networking (sections trickling
/// in), not validation.
#[derive(Default)]
pub struct BlockPerfCounters {
    pub blocks: AtomicU64,
    pub txs: AtomicU64,
    pub header_load_ns: AtomicU64,
    pub sections_load_ns: AtomicU64,
    pub parent_ctx_ns: AtomicU64,
    pub validate_ns: AtomicU64,
    pub apply_ns: AtomicU64,
    pub total_ns: AtomicU64,
    pub drain_calls: AtomicU64,
    pub drain_wall_ns: AtomicU64,
    pub drain_blocks: AtomicU64,
    pub section_wait_calls: AtomicU64,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct BlockPerfSnapshot {
    pub blocks: u64,
    pub txs: u64,
    pub header_load_ns: u64,
    pub sections_load_ns: u64,
    pub parent_ctx_ns: u64,
    pub validate_ns: u64,
    pub apply_ns: u64,
    pub total_ns: u64,
    pub drain_calls: u64,
    pub drain_wall_ns: u64,
    pub drain_blocks: u64,
    pub section_wait_calls: u64,
}

impl BlockPerfCounters {
    #[allow(clippy::too_many_arguments)]
    pub fn add_block(
        &self,
        txs: u64,
        header_load_ns: u64,
        sections_load_ns: u64,
        parent_ctx_ns: u64,
        validate_ns: u64,
        apply_ns: u64,
        total_ns: u64,
    ) {
        self.blocks.fetch_add(1, Ordering::Relaxed);
        self.txs.fetch_add(txs, Ordering::Relaxed);
        self.header_load_ns
            .fetch_add(header_load_ns, Ordering::Relaxed);
        self.sections_load_ns
            .fetch_add(sections_load_ns, Ordering::Relaxed);
        self.parent_ctx_ns
            .fetch_add(parent_ctx_ns, Ordering::Relaxed);
        self.validate_ns.fetch_add(validate_ns, Ordering::Relaxed);
        self.apply_ns.fetch_add(apply_ns, Ordering::Relaxed);
        self.total_ns.fetch_add(total_ns, Ordering::Relaxed);
    }

    pub fn add_drain(&self, wall_ns: u64, blocks_applied: u64, hit_section_wait: bool) {
        self.drain_calls.fetch_add(1, Ordering::Relaxed);
        self.drain_wall_ns.fetch_add(wall_ns, Ordering::Relaxed);
        self.drain_blocks
            .fetch_add(blocks_applied, Ordering::Relaxed);
        if hit_section_wait {
            self.section_wait_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn take(&self) -> BlockPerfSnapshot {
        BlockPerfSnapshot {
            blocks: self.blocks.swap(0, Ordering::Relaxed),
            txs: self.txs.swap(0, Ordering::Relaxed),
            header_load_ns: self.header_load_ns.swap(0, Ordering::Relaxed),
            sections_load_ns: self.sections_load_ns.swap(0, Ordering::Relaxed),
            parent_ctx_ns: self.parent_ctx_ns.swap(0, Ordering::Relaxed),
            validate_ns: self.validate_ns.swap(0, Ordering::Relaxed),
            apply_ns: self.apply_ns.swap(0, Ordering::Relaxed),
            total_ns: self.total_ns.swap(0, Ordering::Relaxed),
            drain_calls: self.drain_calls.swap(0, Ordering::Relaxed),
            drain_wall_ns: self.drain_wall_ns.swap(0, Ordering::Relaxed),
            drain_blocks: self.drain_blocks.swap(0, Ordering::Relaxed),
            section_wait_calls: self.section_wait_calls.swap(0, Ordering::Relaxed),
        }
    }
}

impl BlockPerfSnapshot {
    pub fn is_active(&self) -> bool {
        self.blocks > 0 || self.drain_calls > 0
    }
}

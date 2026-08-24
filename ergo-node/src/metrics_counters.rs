//! Process-lifetime solution-verdict counters for `/metrics`
//! (`ergo_solutions_*` series). Statics follow the `RESCAN_IN_PROGRESS`
//! precedent: the mining dispatch task is the sole writer, the snapshot
//! publisher the sole reader, so relaxed orderings suffice.

use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static SOLUTIONS_ACCEPTED: AtomicU64 = AtomicU64::new(0);
pub(crate) static SOLUTIONS_INVALID_POW: AtomicU64 = AtomicU64::new(0);
pub(crate) static SOLUTIONS_STALE_PARENT: AtomicU64 = AtomicU64::new(0);

pub(crate) fn incr_accepted() {
    SOLUTIONS_ACCEPTED.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn incr_invalid_pow() {
    SOLUTIONS_INVALID_POW.fetch_add(1, Ordering::Relaxed);
}
pub(crate) fn incr_stale_parent() {
    SOLUTIONS_STALE_PARENT.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot of the three verdict counters.
pub(crate) fn solutions_snapshot() -> (u64, u64, u64) {
    (
        SOLUTIONS_ACCEPTED.load(Ordering::Relaxed),
        SOLUTIONS_INVALID_POW.load(Ordering::Relaxed),
        SOLUTIONS_STALE_PARENT.load(Ordering::Relaxed),
    )
}

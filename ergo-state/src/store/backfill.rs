//! Modifier-type-index backfill observability + chunk caps.
//!
//! `ModifierIndexBackfillEvent` is the progress callback shape for
//! [`super::StateStore::back_fill_modifier_type_index_with_progress`];
//! each variant pins a specific phase of the streaming back-fill so
//! the node can attach memory-observability markers and attribute the
//! peak working-set to its source.
//!
//! `MODIFIER_INDEX_CHUNK_*` are the per-chunk caps used by the
//! production back-fill path. Tests drive smaller caps directly via
//! [`super::StateStore::back_fill_modifier_type_index_chunked`].

/// Progress callback events for
/// [`super::StateStore::back_fill_modifier_type_index_with_progress`]. Each
/// variant corresponds to a well-defined point in the back-fill flow;
/// the node attaches memory observability markers at each point so the
/// peak working-set of the back-fill (the in-memory `header_entries`
/// Vec) can be attributed to a specific phase.
#[derive(Debug, Clone, Copy)]
pub enum ModifierIndexBackfillEvent {
    /// Fired before any DB read. RSS at this point reflects the cost of
    /// just opening the store + entering this function.
    Start,
    /// Fired *between* `Start` and an early return when the
    /// `MODIFIER_INDEX_BACKFILL_DONE_V1` sentinel is present in
    /// `STATE_META`. No DB iteration is performed. Caller should treat
    /// this as the terminal event (`AfterCollect` / `BeforeCommit` /
    /// `AfterCommit` are NOT emitted on this path).
    Skipped,
    /// Fired once after the total HEADERS row count is determined.
    ///
    /// Streaming back-fill: the previous implementation materialised
    /// every header row in a single `Vec` and emitted this event after
    /// the Vec was built. The current streaming implementation emits
    /// this event right after counting HEADERS via a read txn
    /// `len()`-style pass, *before* any chunk is read.
    /// `est_bytes` is therefore always `0` (no full-table Vec exists)
    /// and `capacity_rows` reports the configured per-chunk row cap
    /// (informational; not the materialised capacity of any Vec).
    AfterCollect {
        /// Number of header rows present in `HEADERS` at the start of
        /// the run.
        rows: usize,
        /// Always `0` under the streaming back-fill (no full-table Vec
        /// to estimate).
        est_bytes: u64,
        /// Per-chunk row cap (informational).
        capacity_rows: usize,
    },
    /// Fired once, just before the final `Immediate`-durability
    /// sentinel commit at the end of the streaming run.
    BeforeCommit {
        /// Cumulative rows scanned across all chunks.
        rows: usize,
    },
    /// Fired once, after the final sentinel commit lands. `written` is
    /// the cumulative count of `MODIFIER_TYPE_INDEX` entries inserted
    /// across all chunks. `scan_secs` is the cumulative wall-clock for
    /// the entire streaming run (does not include the `STATE_META.get`
    /// fast-path probe at function entry).
    AfterCommit {
        /// Cumulative number of new index entries written across all
        /// chunks.
        written: usize,
        /// Cumulative wall-clock seconds for the streaming run.
        scan_secs: f32,
    },
}

/// Streaming back-fill caps. Production callers use these via
/// [`super::StateStore::back_fill_modifier_type_index_with_progress`].
/// Tests exercise multi-chunk paths via the lower-level
/// [`super::StateStore::back_fill_modifier_type_index_chunked`] entry point
/// with much smaller caps.
///
/// `BYTES_BUDGET` is the soft cap on per-chunk header payload bytes;
/// the chunker always admits at least one row, so a pathological
/// single-row payload larger than the budget still makes progress.
/// `ROWS_CAP` is the hard cap on per-chunk row count, sized so
/// per-chunk write txns commit in well under a second on commodity
/// SSDs even on cold pagecache.
pub(super) const MODIFIER_INDEX_CHUNK_BYTES_BUDGET: usize = 32 * 1024 * 1024;
pub(super) const MODIFIER_INDEX_CHUNK_ROWS_CAP: usize = 50_000;

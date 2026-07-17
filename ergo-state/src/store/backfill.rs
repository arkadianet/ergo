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

use redb::{ReadableTable, ReadableTableMetadata};
use tracing::{debug, info, warn};

use super::{
    read_height_index_ids, StateError, StateStore, BLOCK_SECTIONS, HEADERS, HEADERS_BY_HEIGHT,
    HEADERS_BY_HEIGHT_BACKFILL_DONE_V1, HEADER_CHAIN_INDEX, HEADER_META,
    MODIFIER_INDEX_BACKFILL_DONE_V1, MODIFIER_INDEX_BACKFILL_DONE_VAL, MODIFIER_TYPE_INDEX,
    SECTION_HEIGHT_BACKFILL_DONE_V1, SECTION_HEIGHT_BACKFILL_DONE_VAL, SECTION_HEIGHT_INDEX,
    STATE_META,
};

impl StateStore {
    /// Back-fill `MODIFIER_TYPE_INDEX` for pre-existing data.
    ///
    /// Walks every header in `HEADERS`, parses to recover the three
    /// section roots, computes each header's expected
    /// `(transactions_id, ad_proofs_id, extension_id)` via the
    /// `Blake2b256(typeByte ++ headerId ++ digest)` recipe, and tags
    /// any of those ids that exist in `BLOCK_SECTIONS`. Headers
    /// themselves get type 101.
    ///
    /// Idempotent. Safe to call repeatedly. Sections without a
    /// reachable parent header (orphaned downloads) stay untagged —
    /// that's the correct behaviour, since `/blocks/modifier/{id}` for
    /// such a section can't be served meaningfully.
    ///
    /// Returns the count of new entries written. Caller can use this
    /// to log a one-time migration message on first boot.
    ///
    /// Thin wrapper over [`back_fill_modifier_type_index_with_progress`]
    /// with a no-op callback.
    pub fn back_fill_modifier_type_index(&self) -> Result<usize, StateError> {
        self.back_fill_modifier_type_index_with_progress(|_| {})
    }

    /// Same as [`back_fill_modifier_type_index`] but with a progress
    /// callback at well-defined points (Start, optionally Skipped on
    /// the sentinel-present fast path; otherwise AfterCollect,
    /// BeforeCommit, AfterCommit). Used by the node's init markers to
    /// attribute the boot-phase memory shape.
    ///
    /// Thin wrapper over [`back_fill_modifier_type_index_chunked`]
    /// with the production chunk caps. The streaming implementation
    /// eliminates the previous `Vec<([u8;32], Vec<u8>)>` of every
    /// header row, and short-circuits on a `STATE_META` sentinel
    /// after the first successful run.
    ///
    /// The callback receives observability data only — it is invoked
    /// *between* DB ops, never inside the iteration hot loop.
    /// Implementations that block here will delay back-fill, so keep
    /// them cheap (record a marker, log a line, return).
    pub fn back_fill_modifier_type_index_with_progress<F>(
        &self,
        on_event: F,
    ) -> Result<usize, StateError>
    where
        F: FnMut(ModifierIndexBackfillEvent),
    {
        self.back_fill_modifier_type_index_chunked(
            MODIFIER_INDEX_CHUNK_BYTES_BUDGET,
            MODIFIER_INDEX_CHUNK_ROWS_CAP,
            on_event,
        )
    }

    /// Streaming back-fill with caller-provided chunk caps.
    ///
    /// Production code uses
    /// [`back_fill_modifier_type_index_with_progress`] which calls this
    /// with the module-level constants. Tests use this entry point with
    /// tiny caps (e.g. `bytes_budget = 1`, `rows_cap = 2`) to exercise
    /// multi-chunk paths and the always-admit-one-row invariant on
    /// minimal fixtures.
    ///
    /// Algorithm (true two-phase per chunk, no overlap between read
    /// and write transactions):
    /// 1. Probe the `STATE_META` sentinel
    ///    `MODIFIER_INDEX_BACKFILL_DONE_V1`. If present, emit
    ///    `Skipped` and return `Ok(0)`.
    /// 2. Count `HEADERS` rows in a single read txn for `AfterCollect`.
    /// 3. Loop:
    ///    - Read phase: open a fresh read txn, range-iterate `HEADERS`
    ///      from `Bound::Excluded(last_seen_id)` until either
    ///      `bytes_budget` or `rows_cap` is hit (always admits one row
    ///      first to guarantee progress on outsize payloads). Drop the
    ///      iterator and read txn.
    ///    - Write phase: open a `Durability::None` write txn, tag the
    ///      header (101) and the three derived section ids
    ///      (102/104/108) for each chunk row, commit. Drop the chunk
    ///      Vec.
    ///    - Stop when the read phase yielded zero rows.
    /// 4. Final `Immediate`-durability commit writes the sentinel into
    ///    `STATE_META`. This is the only write the skip path on future
    ///    boots trusts.
    ///
    /// Crash semantics: `Durability::None` per-chunk commits are
    /// idempotent (gated by `idx.get(..).is_none()` checks); a crash
    /// before the final sentinel commit causes the next boot to redo
    /// chunk probes (cheap when nothing is missing) and re-attempt the
    /// sentinel commit. The sentinel is only set once everything else
    /// has been written.
    #[doc(hidden)]
    pub fn back_fill_modifier_type_index_chunked<F>(
        &self,
        bytes_budget: usize,
        rows_cap: usize,
        mut on_event: F,
    ) -> Result<usize, StateError>
    where
        F: FnMut(ModifierIndexBackfillEvent),
    {
        use ergo_ser::modifier_id::{
            TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION, TYPE_HEADER,
        };
        use std::ops::Bound;

        on_event(ModifierIndexBackfillEvent::Start);

        // Step 1: sentinel fast path. STATE_META is shared with AVL
        // metadata; the key is unique to this back-fill.
        //
        // Validation matches the `hci_version` sentinel pattern in
        // `effective_hci_version`: TableDoesNotExist (fresh DB) falls
        // through to the back-fill, the payload must equal
        // `MODIFIER_INDEX_BACKFILL_DONE_VAL` (b"1") exactly, and any
        // other open error or unexpected payload surfaces as Err rather
        // than silently suppressing repair on corrupt metadata.
        {
            let r = self.db.begin_read()?;
            match r.open_table(STATE_META) {
                Ok(meta) => {
                    if let Some(guard) = meta.get(MODIFIER_INDEX_BACKFILL_DONE_V1)? {
                        let bytes = guard.value();
                        if bytes == MODIFIER_INDEX_BACKFILL_DONE_VAL {
                            on_event(ModifierIndexBackfillEvent::Skipped);
                            return Ok(0);
                        }
                        return Err(StateError::DbCorruption {
                            table: "state_meta",
                            key: hex::encode(MODIFIER_INDEX_BACKFILL_DONE_V1.as_bytes()),
                            reason: format!("sentinel has unexpected payload: {:?}", bytes),
                        });
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Step 2: total row count for AfterCollect. One cheap read txn.
        let total_rows: usize = {
            let r = self.db.begin_read()?;
            match r.open_table(HEADERS) {
                Ok(t) => t.len()? as usize,
                Err(redb::TableError::TableDoesNotExist(_)) => 0,
                Err(e) => return Err(e.into()),
            }
        };
        on_event(ModifierIndexBackfillEvent::AfterCollect {
            rows: total_rows,
            est_bytes: 0,
            capacity_rows: rows_cap,
        });

        let scan_start = std::time::Instant::now();
        let mut written: usize = 0;
        let mut rows_seen: usize = 0;

        // Empty-DB case: don't write the sentinel. The sentinel must only
        // be set after a *populated* successful pass; otherwise a fresh
        // node's first boot would lock out future back-fill, leaving any
        // legacy untyped `store_block_section` writes permanently
        // unindexed. Cost of re-checking on every empty-DB boot is one
        // read txn `len()` call (microseconds) — much cheaper than the
        // operator-debug surface a bad sentinel would create.
        if total_rows == 0 {
            return Ok(0);
        }

        let progress_enabled = total_rows > 10_000;
        if progress_enabled {
            info!(
                total_rows,
                chunk_bytes = bytes_budget,
                chunk_rows = rows_cap,
                "modifier-type-index: streaming headers",
            );
        }

        let mut last_id: Option<[u8; 32]> = None;
        let mut chunk_index: usize = 0;
        let mut max_chunk_bytes: usize = 0;

        loop {
            // === Read phase: collect a bounded chunk, drop the read txn ===
            let mut chunk: Vec<([u8; 32], Vec<u8>)> = Vec::new();
            let mut chunk_bytes: usize = 0;
            // Owned storage for the start-bound slice — must outlive the
            // range iterator. Always initialised so the Bound construction
            // below compiles regardless of the match arm.
            let last_id_owned: [u8; 32] = last_id.unwrap_or([0u8; 32]);
            let range: (Bound<&[u8]>, Bound<&[u8]>) = if last_id.is_some() {
                (Bound::Excluded(last_id_owned.as_slice()), Bound::Unbounded)
            } else {
                (Bound::Unbounded, Bound::Unbounded)
            };

            {
                let r = self.db.begin_read()?;
                let table = match r.open_table(HEADERS) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => break,
                    Err(e) => return Err(e.into()),
                };
                let iter = table.range::<&[u8]>(range)?;
                for entry in iter {
                    let (k, v) = entry?;
                    let kb = k.value();
                    if kb.len() != 32 {
                        continue;
                    }
                    let mut id = [0u8; 32];
                    id.copy_from_slice(kb);
                    let val_bytes = v.value().to_vec();
                    let val_len = val_bytes.len();
                    chunk.push((id, val_bytes));
                    chunk_bytes += val_len + 32;
                    // Always admit at least one row before checking caps,
                    // so a single oversized payload still makes progress.
                    if chunk.len() >= rows_cap || chunk_bytes >= bytes_budget {
                        break;
                    }
                }
                // read txn / iter / table all drop here on scope exit
            }

            if chunk.is_empty() {
                break;
            }
            if chunk_bytes > max_chunk_bytes {
                max_chunk_bytes = chunk_bytes;
            }

            let chunk_rows = chunk.len();
            let chunk_start = std::time::Instant::now();

            // === Write phase: tag header + 3 sections per row, commit ===
            let mut write_txn = crate::begin_write_qr(&self.db)?;
            write_txn.set_durability(redb::Durability::None);
            let mut written_in_chunk: usize = 0;
            {
                let sections = match write_txn.open_table(BLOCK_SECTIONS) {
                    Ok(t) => Some(t),
                    Err(redb::TableError::TableDoesNotExist(_)) => None,
                    Err(e) => return Err(e.into()),
                };
                let mut idx = write_txn.open_table(MODIFIER_TYPE_INDEX)?;

                for (header_id, header_bytes) in chunk.iter() {
                    if idx.get(header_id.as_slice())?.is_none() {
                        idx.insert(header_id.as_slice(), TYPE_HEADER)?;
                        written_in_chunk += 1;
                    }
                    let header = match ergo_ser::header::read_header(
                        &mut ergo_primitives::reader::VlqReader::new(header_bytes),
                    ) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };
                    let tx_root = header.transactions_root.as_bytes();
                    let ad_root = header.ad_proofs_root.as_bytes();
                    let ext_root = header.extension_root.as_bytes();

                    for (type_byte, root) in [
                        (TYPE_BLOCK_TRANSACTIONS, tx_root),
                        (TYPE_AD_PROOFS, ad_root),
                        (TYPE_EXTENSION, ext_root),
                    ] {
                        let section_id =
                            ergo_ser::modifier_id::compute_section_id(type_byte, header_id, root);

                        if idx.get(section_id.as_slice())?.is_some() {
                            continue;
                        }
                        let exists = match sections.as_ref() {
                            Some(s) => s.get(section_id.as_slice())?.is_some(),
                            None => false,
                        };
                        if exists {
                            idx.insert(section_id.as_slice(), type_byte)?;
                            written_in_chunk += 1;
                        }
                    }
                }
            }
            write_txn.commit()?;

            written += written_in_chunk;
            rows_seen += chunk_rows;
            // Last id seen this chunk = last entry pushed. Vec is non-empty
            // here (early-return above on empty chunk).
            last_id = Some(chunk.last().expect("non-empty chunk").0);
            if progress_enabled {
                let elapsed_ms = chunk_start.elapsed().as_millis() as u64;
                debug!(
                    chunk = chunk_index,
                    rows_in = chunk_rows,
                    bytes_in = chunk_bytes,
                    written_in = written_in_chunk,
                    cumulative_written = written,
                    rows_seen,
                    total_rows,
                    elapsed_ms,
                    "modifier-type-index chunk",
                );
            }
            chunk_index += 1;

            drop(chunk);
        }

        // Step 4: final Immediate-durability sentinel commit. This is the
        // only commit the skip-fast-path on future boots trusts.
        on_event(ModifierIndexBackfillEvent::BeforeCommit { rows: rows_seen });
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut meta = write_txn.open_table(STATE_META)?;
            meta.insert(
                MODIFIER_INDEX_BACKFILL_DONE_V1,
                MODIFIER_INDEX_BACKFILL_DONE_VAL,
            )?;
        }
        write_txn.commit()?;

        let scan_secs = scan_start.elapsed().as_secs_f32();
        if progress_enabled {
            info!(
                scan_secs,
                written,
                chunks = chunk_index,
                max_chunk_bytes,
                "modifier-type-index scan complete",
            );
        }
        on_event(ModifierIndexBackfillEvent::AfterCommit { written, scan_secs });
        Ok(written)
    }

    /// Back-fill [`HEADERS_BY_HEIGHT`] for pre-existing data.
    ///
    /// Walks every header in `HEADER_META`, groups header_ids by
    /// `meta.height`, then for each height writes the index row
    /// with the canonical best-chain id (from `HEADER_CHAIN_INDEX`)
    /// at slot 0 and any other known ids at that height appended
    /// after. Mirrors Scala's `heightIdsKey` invariant from
    /// `HeadersProcessor.scala:264-276`.
    ///
    /// **Known limitations for upgraded data dirs**:
    ///
    /// 1. **Orphan arrival order is not preserved.** `HEADER_META`
    ///    is keyed by header_id (random byte order, not arrival
    ///    order) and we don't store arrival timestamps. Forward
    ///    writes (post-upgrade) DO preserve arrival order via
    ///    `batch_insert_order` / `store_validated_header`'s direct
    ///    path. Orphan-ordering drift is bounded to historic forks
    ///    that existed pre-upgrade — typically empty on mainnet
    ///    outside reorg events. The API contract (best id first,
    ///    all orphan ids present) is preserved.
    ///
    /// 2. **Sparse-prefix slot-0 may be wrong on PoPoW-bootstrapped
    ///    DBs.** Slot-0 reconstruction reads `HEADER_CHAIN_INDEX`,
    ///    which `apply_popow_proof` intentionally writes only for
    ///    the dense suffix range. For sparse-prefix heights with
    ///    multiple ids in `HEADER_META` (rare — NiPoPoW prefixes
    ///    pick specific high-difficulty headers, so fork
    ///    coincidence at exactly a chosen sparse height is
    ///    unusual), backfill writes whatever id `HEADER_META` lists
    ///    first. Forward writes via `apply_popow_proof` are
    ///    correct (per-header `promote_to_height_index_slot_0`).
    ///    Mainnet impact: zero unless an operator both (a) ran
    ///    Mode 3 NiPoPoW bootstrap AND (b) is upgrading from a
    ///    pre-`HEADERS_BY_HEIGHT` build AND (c) hit a sparse-prefix
    ///    height with observed forks. Combined probability: ~0.
    ///
    /// Sentinel-gated via `HEADERS_BY_HEIGHT_BACKFILL_DONE_V1` in
    /// `STATE_META`: once a run completes successfully, future
    /// boots short-circuit on a single `STATE_META.get` instead
    /// of re-scanning `HEADER_META`.
    ///
    /// Idempotent. Safe to call repeatedly. Returns the number of
    /// `HEADERS_BY_HEIGHT` rows written (which is also the number
    /// of distinct heights that had at least one header).
    ///
    /// Memory profile: holds `(u32, [u8; 32])` per known header
    /// across the scan — ~36 bytes × N rows. Mainnet at ~1.7M
    /// headers: ~60 MB peak. Acceptable for a one-shot boot pass;
    /// chunked write commits keep redb txn size bounded.
    pub fn back_fill_headers_by_height_index(&self) -> Result<usize, StateError> {
        use std::collections::HashMap;
        use std::time::Instant;

        // 1. Sentinel short-circuit.
        {
            let r = self.db.begin_read()?;
            match r.open_table(STATE_META) {
                Ok(table) => {
                    if table.get(HEADERS_BY_HEIGHT_BACKFILL_DONE_V1)?.is_some() {
                        return Ok(0);
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        let scan_start = Instant::now();

        // 2. Walk HEADER_META, group ids by height.
        let mut by_height: HashMap<u32, Vec<[u8; 32]>> = HashMap::new();
        {
            let r = self.db.begin_read()?;
            let table = match r.open_table(HEADER_META) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => {
                    // Fresh DB — no headers, nothing to backfill. Set
                    // the sentinel so future boots skip even the
                    // table-exists check.
                    self.set_headers_by_height_backfill_sentinel()?;
                    return Ok(0);
                }
                Err(e) => return Err(e.into()),
            };
            for entry in table.iter()? {
                let (k, v) = entry?;
                if k.value().len() != 32 {
                    continue;
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(k.value());
                let m = crate::chain::HeaderMeta::deserialize(v.value()).map_err(|e| {
                    StateError::DbCorruption {
                        table: "header_meta",
                        key: hex::encode(id),
                        reason: e.to_string(),
                    }
                })?;
                by_height.entry(m.height).or_default().push(id);
            }
        }

        // 3. Read HEADER_CHAIN_INDEX so we know the best-chain id at
        //    each height (slot 0 invariant).
        let mut best_at_height: HashMap<u32, [u8; 32]> = HashMap::new();
        {
            let r = self.db.begin_read()?;
            if let Ok(table) = r.open_table(HEADER_CHAIN_INDEX) {
                for entry in table.iter()? {
                    let (k, v) = entry?;
                    let h = k.value() as u32;
                    let bytes = v.value();
                    if bytes.len() != 32 {
                        continue;
                    }
                    let mut id = [0u8; 32];
                    id.copy_from_slice(bytes);
                    best_at_height.insert(h, id);
                }
            }
        }

        // 4. Sort heights ascending, then chunk-write. Each chunk is
        //    one redb txn covering up to `WRITE_CHUNK_ROWS` heights so
        //    the txn-pending-bytes pool stays bounded.
        const WRITE_CHUNK_ROWS: usize = 8_192;
        let mut heights: Vec<u32> = by_height.keys().copied().collect();
        heights.sort_unstable();

        let mut written: usize = 0;
        for chunk in heights.chunks(WRITE_CHUNK_ROWS) {
            let write_txn = crate::begin_write_qr(&self.db)?;
            {
                let mut idx = write_txn.open_table(HEADERS_BY_HEIGHT)?;
                for &h in chunk {
                    let mut ids = by_height.remove(&h).expect("present by construction");
                    // Promote best-chain id to slot 0 if present.
                    if let Some(best) = best_at_height.get(&h) {
                        if let Some(pos) = ids.iter().position(|x| x == best) {
                            if pos != 0 {
                                ids.swap(0, pos);
                            }
                        }
                    }
                    // Skip rows that would already be populated by the
                    // forward write path — `existing == ids` short-circuit
                    // keeps the backfill no-op-on-rerun.
                    let existing = read_height_index_ids(&idx, h)?;
                    if existing == ids {
                        continue;
                    }
                    let payload: Vec<u8> = ids.iter().flat_map(|id| id.iter().copied()).collect();
                    idx.insert(h as u64, payload.as_slice())?;
                    written += 1;
                }
            }
            write_txn.commit()?;
        }

        // 5. Set sentinel so subsequent boots short-circuit.
        self.set_headers_by_height_backfill_sentinel()?;

        let scan_secs = scan_start.elapsed().as_secs_f32();
        info!(
            scan_secs,
            written,
            heights = heights.len(),
            "headers-by-height index back-fill complete",
        );
        Ok(written)
    }

    /// Mode 3 — back-fill `SECTION_HEIGHT_INDEX` for legacy
    /// archive DBs reopened in pruned mode. Walks every header in
    /// `HEADERS`, parses to recover the 3 expected section roots,
    /// computes each header's 3 section ids via
    /// `Blake2b256(typeByte ++ headerId ++ root)`, and writes
    /// `(section_id → header.height)` rows.
    ///
    /// Idempotent. Safe to call repeatedly. Gated by a sentinel
    /// in `STATE_META[SECTION_HEIGHT_BACKFILL_DONE_V1]`; the first
    /// successful run stamps the sentinel and subsequent calls
    /// short-circuit. Empty-DB case does NOT stamp the sentinel
    /// (matches the `MODIFIER_INDEX_BACKFILL_DONE_V1` pattern at
    /// `back_fill_modifier_type_index_chunked` — a fresh node's
    /// first boot must not lock out future back-fill).
    ///
    /// Writes are chunked at the same caps as
    /// `back_fill_modifier_type_index_chunked` so peak memory
    /// stays bounded. Sections that haven't arrived yet still
    /// get their height row populated — the serve gate cares
    /// about the height tag, not the section payload's presence.
    pub fn back_fill_section_height_index(&self) -> Result<usize, StateError> {
        use ergo_ser::modifier_id::{
            compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
        };
        use std::ops::Bound;

        // Sentinel short-circuit.
        {
            let r = self.db.begin_read()?;
            match r.open_table(STATE_META) {
                Ok(meta) => {
                    if let Some(guard) = meta.get(SECTION_HEIGHT_BACKFILL_DONE_V1)? {
                        let bytes = guard.value();
                        if bytes == SECTION_HEIGHT_BACKFILL_DONE_VAL {
                            return Ok(0);
                        }
                        return Err(StateError::DbCorruption {
                            table: "state_meta",
                            key: hex::encode(SECTION_HEIGHT_BACKFILL_DONE_V1.as_bytes()),
                            reason: format!(
                                "section-height backfill sentinel has unexpected payload: {bytes:?}"
                            ),
                        });
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Total row count for empty-DB detection.
        let total_rows: usize = {
            let r = self.db.begin_read()?;
            match r.open_table(HEADERS) {
                Ok(t) => t.len()? as usize,
                Err(redb::TableError::TableDoesNotExist(_)) => 0,
                Err(e) => return Err(e.into()),
            }
        };
        if total_rows == 0 {
            // Empty DB — no legacy headers to migrate. Stamp the
            // sentinel immediately so fresh-DB Mode 3 boot is
            // activation-ready (Phase 4 fail-closed gate requires
            // the sentinel before allowing `blocks_to_keep > 0`).
            // Diverges from `MODIFIER_INDEX_BACKFILL_DONE_V1`
            // (which never stamps on empty-DB) because that
            // sentinel is purely a back-fill short-circuit, while
            // this one is an activation gate.
            let write_txn = crate::begin_write_qr(&self.db)?;
            {
                let mut meta = write_txn.open_table(STATE_META)?;
                meta.insert(
                    SECTION_HEIGHT_BACKFILL_DONE_V1,
                    SECTION_HEIGHT_BACKFILL_DONE_VAL,
                )?;
            }
            write_txn.commit()?;
            return Ok(0);
        }

        let mut written: usize = 0;
        let mut parse_failures: usize = 0;
        let mut last_id: Option<[u8; 32]> = None;
        loop {
            // Read chunk: bounded copy of HEADERS rows out of a
            // short-lived read txn so the write txn that follows
            // doesn't overlap.
            let mut chunk: Vec<([u8; 32], Vec<u8>)> = Vec::new();
            let last_id_owned: [u8; 32] = last_id.unwrap_or([0u8; 32]);
            let range: (Bound<&[u8]>, Bound<&[u8]>) = if last_id.is_some() {
                (Bound::Excluded(last_id_owned.as_slice()), Bound::Unbounded)
            } else {
                (Bound::Unbounded, Bound::Unbounded)
            };
            {
                let r = self.db.begin_read()?;
                let table = match r.open_table(HEADERS) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => break,
                    Err(e) => return Err(e.into()),
                };
                let iter = table.range::<&[u8]>(range)?;
                let mut chunk_bytes: usize = 0;
                for entry in iter {
                    let (k, v) = entry?;
                    let kb = k.value();
                    if kb.len() != 32 {
                        continue;
                    }
                    let mut id = [0u8; 32];
                    id.copy_from_slice(kb);
                    let val_bytes = v.value().to_vec();
                    chunk_bytes += val_bytes.len() + 32;
                    chunk.push((id, val_bytes));
                    if chunk.len() >= MODIFIER_INDEX_CHUNK_ROWS_CAP
                        || chunk_bytes >= MODIFIER_INDEX_CHUNK_BYTES_BUDGET
                    {
                        break;
                    }
                }
            }
            if chunk.is_empty() {
                break;
            }

            let mut write_txn = crate::begin_write_qr(&self.db)?;
            write_txn.set_durability(redb::Durability::None);
            {
                let mut idx = write_txn.open_table(SECTION_HEIGHT_INDEX)?;
                for (header_id, header_bytes) in chunk.iter() {
                    let header = match ergo_ser::header::read_header(
                        &mut ergo_primitives::reader::VlqReader::new(header_bytes),
                    ) {
                        Ok(h) => h,
                        Err(_) => {
                            parse_failures += 1;
                            continue;
                        }
                    };
                    let height = header.height;
                    for (type_byte, root) in [
                        (TYPE_AD_PROOFS, header.ad_proofs_root.as_bytes()),
                        (TYPE_BLOCK_TRANSACTIONS, header.transactions_root.as_bytes()),
                        (TYPE_EXTENSION, header.extension_root.as_bytes()),
                    ] {
                        let section_id = compute_section_id(type_byte, header_id, root);
                        if idx.get(section_id.as_slice())?.is_none() {
                            idx.insert(section_id.as_slice(), height)?;
                            written += 1;
                        }
                    }
                }
            }
            write_txn.commit()?;
            last_id = Some(chunk.last().expect("non-empty chunk").0);
        }

        if parse_failures > 0 {
            // Do NOT stamp the sentinel — known-incomplete must be
            // retriable, not permanently locked out. The serve
            // gate is fail-closed for missing rows, so the
            // unindexed sections stay un-serveable, but the next
            // boot's back-fill walk will try again. Operators get
            // a warn-level log naming the count.
            warn!(
                parse_failures,
                written,
                headers_scanned = total_rows,
                "section-height back-fill incomplete: header parse failures \
                 left some derived section ids unindexed. Sentinel NOT \
                 stamped — back-fill will retry on next boot. Investigate \
                 `HEADERS` corruption if the count is persistent.",
            );
            return Ok(written);
        }

        // Stamp the sentinel — single durable write outside the
        // chunked loop so a mid-loop crash leaves the sentinel
        // unset and the next boot resumes the walk. Only runs
        // when every header parsed cleanly.
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut meta = write_txn.open_table(STATE_META)?;
            meta.insert(
                SECTION_HEIGHT_BACKFILL_DONE_V1,
                SECTION_HEIGHT_BACKFILL_DONE_VAL,
            )?;
        }
        write_txn.commit()?;

        info!(
            written,
            headers_scanned = total_rows,
            "section-height index back-fill complete",
        );
        Ok(written)
    }

    /// Write the `HEADERS_BY_HEIGHT_BACKFILL_DONE_V1` sentinel to
    /// `STATE_META`. Pulled out so both the fresh-DB short-circuit
    /// and the post-scan completion paths share one implementation.
    fn set_headers_by_height_backfill_sentinel(&self) -> Result<(), StateError> {
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut t = write_txn.open_table(STATE_META)?;
            t.insert(
                HEADERS_BY_HEIGHT_BACKFILL_DONE_V1,
                MODIFIER_INDEX_BACKFILL_DONE_VAL,
            )?;
        }
        write_txn.commit()?;
        Ok(())
    }
}

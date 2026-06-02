//! Header and block-section tables, factored out of `StateStore` so a
//! second persistence backend can embed the same redb-backed header
//! index without duplicating the batch overlay and the
//! `HEADERS_BY_HEIGHT` / `HEADER_CHAIN_INDEX` rewrite logic.
//!
//! Owns the four header tables (`HEADERS`, `HEADER_META`,
//! `HEADERS_BY_HEIGHT`, `SECTION_HEIGHT_INDEX`), the block-section
//! tables (`BLOCK_SECTIONS`, `MODIFIER_TYPE_INDEX`), and the in-memory
//! batch overlay that buffers header writes for a single flushing
//! commit. Reads consult the overlay before redb.
//!
//! Chain-state is NOT owned here. `store_validated_header` and
//! `flush_header_batch` take the `ChainStateMeta` by reference so the
//! embedding store stays the single source of truth for the
//! best-header pointers; this component only persists the rows and the
//! derived indexes.

use std::collections::HashMap;
use std::sync::Arc;

use redb::{Database, ReadableTable};

use crate::chain::{ChainStateMeta, HeaderMeta};
use crate::store::{
    append_orphan_to_height_index, rewrite_best_chain_into_index,
    rewrite_height_index_for_new_best, StateError, BLOCK_SECTIONS, CHAIN_STATE_META, HEADERS,
    HEADERS_BY_HEIGHT, HEADER_CHAIN_INDEX, HEADER_META, MINIMAL_FULL_BLOCK_HEIGHT_KEY,
    MODIFIER_TYPE_INDEX, SECTION_HEIGHT_INDEX, STATE_META,
};

/// Header + block-section tables with the buffered-write overlay.
///
/// `db` is shared with the embedding store: both hold an `Arc` to the
/// same `redb::Database`, so writes here are visible to the store's
/// own tables and vice versa within the same file.
#[derive(Debug)]
pub(crate) struct HeaderSectionTables {
    db: Arc<Database>,
    /// Buffered header writes for batch persistence.
    pub(crate) batch_headers: HashMap<[u8; 32], Vec<u8>>,
    pub(crate) batch_meta: HashMap<[u8; 32], HeaderMeta>,
    /// Arrival order of buffered headers — used by
    /// `flush_header_batch` to append into `HEADERS_BY_HEIGHT` in
    /// the order `store_validated_header` was called, so the orphan
    /// slots inside that index keep insertion order (Scala parity,
    /// `HeadersProcessor.scala:203-206`). Diverged from
    /// `batch_meta`'s HashMap iteration order, which is randomized.
    /// Same-id pushes are skipped so a re-call of
    /// `store_validated_header` on a buffered header doesn't bloat
    /// this list.
    pub(crate) batch_insert_order: Vec<[u8; 32]>,
    pub(crate) batching: bool,
}

impl HeaderSectionTables {
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            batch_headers: HashMap::new(),
            batch_meta: HashMap::new(),
            batch_insert_order: Vec::new(),
            batching: false,
        }
    }

    /// Number of headers buffered in the batch_headers map awaiting persist.
    /// Normally drained per-batch; sustained growth signals commit-pipeline
    /// stall.
    pub(crate) fn batch_headers_len(&self) -> usize {
        self.batch_headers.len()
    }

    /// Sum of buffered header bytes in `batch_headers`. Linear in the
    /// number of buffered headers; cheap because batch_headers is small in
    /// the steady state.
    pub(crate) fn batch_headers_bytes(&self) -> usize {
        self.batch_headers.values().map(|v| v.len()).sum()
    }

    /// Number of header_meta entries buffered awaiting persist.
    pub(crate) fn batch_meta_len(&self) -> usize {
        self.batch_meta.len()
    }

    pub(crate) fn store_header(
        &self,
        header_id: &[u8; 32],
        header_bytes: &[u8],
    ) -> Result<(), StateError> {
        use ergo_ser::modifier_id::{
            compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
        };
        let parsed = ergo_ser::header::read_header(&mut ergo_primitives::reader::VlqReader::new(
            header_bytes,
        ))
        .ok();
        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut table = write_txn.open_table(HEADERS)?;
            table.insert(header_id.as_slice(), header_bytes)?;
        }
        {
            let mut idx = write_txn.open_table(MODIFIER_TYPE_INDEX)?;
            idx.insert(header_id.as_slice(), 101u8)?;
        }
        if let Some(header) = parsed.as_ref() {
            let height = header.height;
            let mut sh_idx = write_txn.open_table(SECTION_HEIGHT_INDEX)?;
            for (type_byte, root) in [
                (TYPE_AD_PROOFS, header.ad_proofs_root.as_bytes()),
                (TYPE_BLOCK_TRANSACTIONS, header.transactions_root.as_bytes()),
                (TYPE_EXTENSION, header.extension_root.as_bytes()),
            ] {
                let section_id = compute_section_id(type_byte, header_id, root);
                sh_idx.insert(section_id.as_slice(), height)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Mode 3 — look up a section's parent-header height via the
    /// `SECTION_HEIGHT_INDEX`. Returns `None` for sections with no
    /// row (not-yet-indexed legacy + never-seen ids alike — the
    /// serve gate in Phase 3a treats both as fail-closed deny).
    ///
    /// The embedding store drains the persist pipeline before
    /// delegating here so async commit failures surface as
    /// `PersistFailed` rather than silently classifying the section
    /// as "unknown".
    pub(crate) fn get_section_height(
        &self,
        section_id: &[u8; 32],
    ) -> Result<Option<u32>, StateError> {
        let r = self.db.begin_read()?;
        match r.open_table(SECTION_HEIGHT_INDEX) {
            Ok(t) => Ok(t.get(section_id.as_slice())?.map(|g| g.value())),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Retrieve a header by its ID. Checks the batch buffer first.
    pub(crate) fn get_header(&self, header_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(bytes) = self.batch_headers.get(header_id) {
            return Ok(Some(bytes.clone()));
        }
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(HEADERS) {
            Ok(table) => match table.get(header_id.as_slice())? {
                Some(guard) => Ok(Some(guard.value().to_vec())),
                None => Ok(None),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Store a block section by its computed modifier ID.
    ///
    /// Uses `Durability::None`: the section bytes land in the redb file
    /// (and pagecache) but the commit marker is not durably written until
    /// the next higher-durability commit — which the batched persist
    /// pipeline produces every `ibd_flush_interval` blocks. This avoids
    /// the 44 fsync/sec stall the main thread was incurring at sustained
    /// 22 b/s (2 sections × ~15ms fsync each).
    ///
    /// Crash recovery: lost-but-not-yet-durable sections re-download
    /// from peers, same path as the rest of in-flight IBD state. The
    /// per-block AVL state-root verification at apply time catches any
    /// drift, so there's no path for stale section data to silently
    /// corrupt downstream state.
    ///
    /// Mode 3 gating: this entry point bypasses the prune-sentinel
    /// resurrection guard that lives on `store_block_section_typed`.
    /// Production callers (sync, coordinator, mining) MUST use
    /// `store_block_section_typed`; this variant is gated behind
    /// `test-helpers` so it is unreachable from the production build
    /// and cannot become an escape hatch around the storage
    /// invariant once pruning is live.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) fn store_block_section(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
    ) -> Result<(), StateError> {
        let mut write_txn = crate::begin_write_qr(&self.db)?;
        write_txn.set_durability(redb::Durability::None);
        {
            let mut table = write_txn.open_table(BLOCK_SECTIONS)?;
            table.insert(modifier_id.as_slice(), section_bytes)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Store a block section AND tag its modifier type in
    /// `MODIFIER_TYPE_INDEX`. Same durability semantics as
    /// `store_block_section`. Callers that know the section type
    /// (sync / coordinator) should prefer this variant so
    /// `/blocks/modifier/{id}` can dispatch immediately on the next
    /// read without waiting for a startup back-fill pass.
    ///
    /// Mode 3 Phase 3a defense-in-depth: rejects writes whose
    /// parent header is below the current prune sentinel. The
    /// receive-side gating in `ergo-sync::executor` silently
    /// drops these before they reach the store; the storage-side
    /// guard catches the case where the executor missed
    /// (resurrection attempt via a delayed peer delivery, a
    /// rogue peer pushing directly, or an executor bug that
    /// bypassed receive gating). `SECTION_HEIGHT_INDEX` provides
    /// the height lookup that was stamped at header-store time
    /// (Phase 1a wiring) — sections whose parent we never indexed
    /// are passed through (no height to compare against; the
    /// serve gate will catch them on read if needed).
    pub(crate) fn store_block_section_typed(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
        section_type: u8,
    ) -> Result<(), StateError> {
        let mut write_txn = crate::begin_write_qr(&self.db)?;
        write_txn.set_durability(redb::Durability::None);
        // Phase 3a guard — read sentinel + section-height INSIDE
        // the write_txn so a concurrent persist worker that's
        // advancing the sentinel can't race the check-then-write.
        // Gate fires whenever `sentinel > 1` (sentinel-based, not
        // `blocks_to_keep > 0`): the sentinel is also written by
        // `install_snapshot_state` and `apply_popow_proof`, so a
        // Mode 2 / NiPoPoW-bootstrapped archive node also needs
        // the resurrection guard. A fresh archive-from-genesis
        // store reads sentinel = 1 (default) and the gate is
        // inert.
        let sentinel: u32 = {
            let meta = write_txn.open_table(STATE_META)?;
            let bytes_opt = meta
                .get(MINIMAL_FULL_BLOCK_HEIGHT_KEY)?
                .map(|g| g.value().to_vec());
            drop(meta);
            match bytes_opt {
                Some(bytes) => {
                    if bytes.len() != 4 {
                        return Err(StateError::DbCorruption {
                            table: "state_meta",
                            key: hex::encode(MINIMAL_FULL_BLOCK_HEIGHT_KEY.as_bytes()),
                            reason: format!(
                                "minimal_full_block_height payload has unexpected length: {}",
                                bytes.len()
                            ),
                        });
                    }
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(&bytes);
                    u32::from_le_bytes(buf)
                }
                None => 1,
            }
        };
        if sentinel > 1 {
            // Section height — tombstone-retained by eviction so
            // sub-sentinel resurrection attempts are detected
            // post-eviction (see delete_block_sections_at_height_in_txn).
            // Fail-CLOSED on Ok(None): the boot backfill gate
            // makes SECTION_HEIGHT_INDEX complete
            // when sentinel > 1, so an unindexed section is
            // either an orphan or an attacker direct-write
            // attempt — either way, reject.
            let section_height: Option<u32> = match write_txn.open_table(SECTION_HEIGHT_INDEX) {
                Ok(t) => t.get(modifier_id.as_slice())?.map(|g| g.value()),
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(e.into()),
            };
            match section_height {
                Some(height) if height >= sentinel => {}
                Some(height) => {
                    return Err(StateError::PrunedSection {
                        section_id: hex::encode(modifier_id),
                        section_height: height,
                        sentinel,
                    });
                }
                None => {
                    return Err(StateError::PrunedSection {
                        section_id: hex::encode(modifier_id),
                        section_height: 0,
                        sentinel,
                    });
                }
            }
        }
        {
            let mut table = write_txn.open_table(BLOCK_SECTIONS)?;
            table.insert(modifier_id.as_slice(), section_bytes)?;
        }
        {
            let mut idx = write_txn.open_table(MODIFIER_TYPE_INDEX)?;
            idx.insert(modifier_id.as_slice(), section_type)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Retrieve a block section by its computed modifier ID.
    ///
    /// The embedding store drains the persist pipeline before
    /// delegating here so async commit failures surface rather than
    /// reading stale section state.
    pub(crate) fn get_block_section(
        &self,
        modifier_id: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, StateError> {
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(BLOCK_SECTIONS) {
            Ok(table) => match table.get(modifier_id.as_slice())? {
                Some(guard) => Ok(Some(guard.value().to_vec())),
                None => Ok(None),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Retrieve header metadata by header ID. Checks the batch buffer first.
    pub(crate) fn get_header_meta(
        &self,
        header_id: &[u8; 32],
    ) -> Result<Option<HeaderMeta>, StateError> {
        if let Some(meta) = self.batch_meta.get(header_id) {
            return Ok(Some(meta.clone()));
        }
        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(HEADER_META) {
            Ok(table) => match table.get(header_id.as_slice())? {
                Some(guard) => HeaderMeta::deserialize(guard.value())
                    .map(Some)
                    .map_err(|e| StateError::DbCorruption {
                        table: "header_meta",
                        key: hex::encode(header_id),
                        reason: e.to_string(),
                    }),
                None => Ok(None),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Look up the header_id on the best-header chain at a given height.
    pub(crate) fn get_header_id_at_height(
        &self,
        height: u32,
    ) -> Result<Option<[u8; 32]>, StateError> {
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(HEADER_CHAIN_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(height as u64)? {
            Some(guard) => {
                let bytes = guard.value();
                if bytes.len() != 32 {
                    return Err(StateError::DbCorruption {
                        table: "header_chain_index",
                        key: hex::encode((height as u64).to_be_bytes()),
                        reason: format!("row has len {} (expected 32)", bytes.len()),
                    });
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(bytes);
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    /// Range-scan the best-header chain index over [lo, hi] inclusive.
    /// Returns (height, header_id) pairs in ascending height order.
    pub(crate) fn scan_header_chain_range(
        &self,
        lo: u32,
        hi: u32,
    ) -> Result<Vec<(u32, [u8; 32])>, StateError> {
        if hi < lo {
            return Ok(Vec::new());
        }
        let read_txn = self.db.begin_read()?;
        let table = match read_txn.open_table(HEADER_CHAIN_INDEX) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::with_capacity((hi - lo + 1) as usize);
        for entry in table.range(lo as u64..=hi as u64)? {
            let (k, v) = entry?;
            let bytes = v.value();
            if bytes.len() != 32 {
                return Err(StateError::DbCorruption {
                    table: "header_chain_index",
                    key: hex::encode(k.value().to_be_bytes()),
                    reason: format!("row has len {} (expected 32)", bytes.len()),
                });
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(bytes);
            out.push((k.value() as u32, id));
        }
        Ok(out)
    }

    /// Begin buffering header writes. Subsequent store_validated_header calls
    /// write to an in-memory overlay instead of redb. Call flush_header_batch
    /// to commit all buffered headers in a single write transaction.
    pub(crate) fn begin_header_batch(&mut self) {
        debug_assert!(
            !self.batching,
            "begin_header_batch called while already batching"
        );
        self.batching = true;
        self.batch_headers.clear();
        self.batch_meta.clear();
        self.batch_insert_order.clear();
    }

    /// Flush all buffered header writes to redb in a single transaction.
    /// The in-memory chain_state was already updated during the batch;
    /// `cs_after` carries its projected persisted form.
    pub(crate) fn flush_header_batch(
        &mut self,
        cs_after: &ChainStateMeta,
    ) -> Result<(), StateError> {
        self.batching = false;
        if self.batch_headers.is_empty() {
            return Ok(());
        }
        let result = self.flush_header_batch_inner(cs_after);
        // Unconditional clear: on success we drop the redundant
        // in-memory mirror; on error we drop phantom uncommitted
        // state so it's not visible via `get_header` /
        // `get_header_meta` (both consult `batch_*` before redb).
        // `chain_state.best_header_*` stale-on-error is a
        // pre-existing batch concern outside Mode 3 scope.
        self.batch_headers.clear();
        self.batch_meta.clear();
        self.batch_insert_order.clear();
        result
    }

    fn flush_header_batch_inner(&mut self, cs_after: &ChainStateMeta) -> Result<(), StateError> {
        // Snapshot the PERSISTED best-header (id, height) before the batch.
        // chain_state was advanced in-memory during buffered writes, but the
        // DB doesn't reflect those updates yet — so the persisted value is the
        // true "before" state. We compare the full (id, height) tuple below so
        // same-height heavier-sibling flips are not missed.
        let (old_best_id, old_best_height) = {
            let read_txn = self.db.begin_read()?;
            let cs_table = match read_txn.open_table(CHAIN_STATE_META) {
                Ok(t) => Some(t),
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(e.into()),
            };
            match cs_table {
                Some(t) => match t.get("chain_state")? {
                    Some(guard) => {
                        let bytes = guard.value();
                        let m = crate::chain::ChainStateMeta::deserialize(bytes).map_err(|e| {
                            StateError::DbCorruption {
                                table: "chain_state_meta",
                                key: hex::encode(b"chain_state"),
                                reason: format!("decode: {e}"),
                            }
                        })?;
                        (m.best_header_id, m.best_header_height)
                    }
                    None => ([0u8; 32], 0),
                },
                None => ([0u8; 32], 0),
            }
        };

        let new_best_id = cs_after.best_header_id;
        let new_best_height = cs_after.best_header_height;

        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut h_table = write_txn.open_table(HEADERS)?;
            let mut m_table = write_txn.open_table(HEADER_META)?;
            for (id, bytes) in &self.batch_headers {
                h_table.insert(id.as_slice(), bytes.as_slice())?;
            }
            for (id, meta) in &self.batch_meta {
                m_table.insert(id.as_slice(), meta.serialize().as_slice())?;
            }

            // Mode 3 — populate SECTION_HEIGHT_INDEX inside the
            // same atomic write_txn as the header insert. The
            // section payloads may not have arrived yet; the row
            // is keyed on `compute_section_id(type, header_id,
            // root)` which is recoverable from the header alone.
            //
            // Invariant: parsed-bytes height MUST equal the
            // batched HeaderMeta.height. A mismatch fails the
            // whole flush — the atomic commit means HEADER_META
            // and SECTION_HEIGHT_INDEX cannot disagree on
            // height. Parse failures are silently skipped: the
            // next boot's `back_fill_section_height_index` walk
            // retries; the serve gate is fail-closed for missing
            // rows.
            use ergo_ser::modifier_id::{
                compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
            };
            let mut sh_idx = write_txn.open_table(SECTION_HEIGHT_INDEX)?;
            for (id, bytes) in &self.batch_headers {
                if let Ok(header) = ergo_ser::header::read_header(
                    &mut ergo_primitives::reader::VlqReader::new(bytes),
                ) {
                    if let Some(meta) = self.batch_meta.get(id) {
                        if header.height != meta.height {
                            return Err(StateError::HeaderHeightMismatch {
                                parsed: header.height,
                                meta: meta.height,
                                header_id: hex::encode(id),
                            });
                        }
                    }
                    let height = header.height;
                    for (type_byte, root) in [
                        (TYPE_AD_PROOFS, header.ad_proofs_root.as_bytes()),
                        (TYPE_BLOCK_TRANSACTIONS, header.transactions_root.as_bytes()),
                        (TYPE_EXTENSION, header.extension_root.as_bytes()),
                    ] {
                        let section_id = compute_section_id(type_byte, id, root);
                        sh_idx.insert(section_id.as_slice(), height)?;
                    }
                }
            }

            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            cs_table.insert("chain_state", cs_after.serialize().as_slice())?;

            // HEADERS_BY_HEIGHT — every batched header gets appended at
            // its height (idempotent). Orphans land here too so
            // `/blocks/at/{h}` returns fork ids after IBD. The best-chain
            // rewrite below then promotes the new-best id to slot 0 for
            // each height back to the fork point.
            //
            // Iterate `batch_insert_order` (Vec) rather than `batch_meta`
            // (HashMap) so the orphan slots reflect first-arrival order
            // — matches Scala's `orphanedBlockHeaderIdsRow` semantics
            // at `HeadersProcessor.scala:203-206`. HashMap iteration
            // would be randomized and break wire-shape parity for
            // multi-orphan heights.
            let mut height_idx = write_txn.open_table(HEADERS_BY_HEIGHT)?;
            for id in &self.batch_insert_order {
                if let Some(meta) = self.batch_meta.get(id) {
                    append_orphan_to_height_index(&mut height_idx, meta.height, id)?;
                }
            }

            // Rewrite HEADER_CHAIN_INDEX by walking backward from the final
            // best-header tip. HEADER_META now contains all buffered meta
            // (inserted just above in this same txn), so the walk can read
            // parents normally. Trigger the rewrite whenever the (id, height)
            // tuple changed — this covers height-advancing extensions AND
            // same-height heavier-sibling flips uniformly.
            let best_changed = new_best_height > 0
                && (new_best_id != old_best_id || new_best_height != old_best_height);
            if best_changed {
                let mut idx_table = write_txn.open_table(HEADER_CHAIN_INDEX)?;
                rewrite_best_chain_into_index(
                    &mut idx_table,
                    &m_table,
                    new_best_id,
                    new_best_height,
                    old_best_height,
                )?;
                rewrite_height_index_for_new_best(
                    &mut height_idx,
                    &m_table,
                    new_best_id,
                    new_best_height,
                )?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Atomically persist header bytes + header_meta + optional best-header
    /// update. When batching is active, writes to in-memory buffer instead
    /// of redb (flushed by flush_header_batch). Otherwise writes directly.
    ///
    /// `cs_meta` is the embedding store's projected chain-state. The
    /// best-header pointers it carries are read on the non-batching
    /// path and mutated in place when `new_best` is `Some` so the
    /// caller can mirror the update back onto its own `ChainState`.
    pub(crate) fn store_validated_header(
        &mut self,
        header_id: &[u8; 32],
        header_bytes: &[u8],
        meta: &HeaderMeta,
        new_best: Option<(u32, Vec<u8>)>, // (height, cumulative_score) if new best
        cs_meta: &mut ChainStateMeta,
    ) -> Result<(), StateError> {
        if self.batching {
            // Track first-arrival order for the orphan slots inside
            // `HEADERS_BY_HEIGHT` at flush time. HashMap iteration is
            // randomized; re-calls on the same id are skipped so the
            // list doesn't bloat (the same-id case overwrites in
            // `batch_meta` via `insert` — that's fine).
            if !self.batch_headers.contains_key(header_id) {
                self.batch_insert_order.push(*header_id);
            }
            self.batch_headers.insert(*header_id, header_bytes.to_vec());
            self.batch_meta.insert(*header_id, meta.clone());
            if let Some((height, score)) = new_best {
                cs_meta.best_header_id = *header_id;
                cs_meta.best_header_height = height;
                cs_meta.best_header_score = score;
            }
            return Ok(());
        }

        let write_txn = crate::begin_write_qr(&self.db)?;
        {
            let mut headers = write_txn.open_table(HEADERS)?;
            headers.insert(header_id.as_slice(), header_bytes)?;

            let mut header_meta_table = write_txn.open_table(HEADER_META)?;
            header_meta_table.insert(header_id.as_slice(), meta.serialize().as_slice())?;

            let mut height_idx = write_txn.open_table(HEADERS_BY_HEIGHT)?;
            // Append-if-absent before any best-chain rewrite — the
            // rewrite below will promote `header_id` to slot 0 if
            // this header is the new best. For an orphan
            // (`new_best.is_none()`), the append leaves it at the
            // tail of the row. Scala parity at
            // `HeadersProcessor.scala:203-226`.
            append_orphan_to_height_index(&mut height_idx, meta.height, header_id)?;

            // Mode 3 — populate SECTION_HEIGHT_INDEX inside the
            // same atomic write_txn as the header insert. Section
            // payloads may not have arrived yet; the row is keyed
            // on `compute_section_id(type, header_id, root)` so
            // the index entry only depends on the header.
            //
            // Invariant: parsed-bytes height MUST equal the
            // caller-supplied `meta.height`. A mismatch means
            // upstream HeaderMeta construction disagrees with
            // the bytes the chain validated; committing
            // inconsistent metadata would let HEADER_META and
            // SECTION_HEIGHT_INDEX carry different heights for
            // the same header (split-brain). Parse failures are
            // silently skipped (the next boot's
            // `back_fill_section_height_index` walk retries; the
            // serve gate is fail-closed for missing rows).
            if let Ok(header) = ergo_ser::header::read_header(
                &mut ergo_primitives::reader::VlqReader::new(header_bytes),
            ) {
                if header.height != meta.height {
                    return Err(StateError::HeaderHeightMismatch {
                        parsed: header.height,
                        meta: meta.height,
                        header_id: hex::encode(header_id),
                    });
                }
                use ergo_ser::modifier_id::{
                    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
                };
                let mut sh_idx = write_txn.open_table(SECTION_HEIGHT_INDEX)?;
                let height = header.height;
                for (type_byte, root) in [
                    (TYPE_AD_PROOFS, header.ad_proofs_root.as_bytes()),
                    (TYPE_BLOCK_TRANSACTIONS, header.transactions_root.as_bytes()),
                    (TYPE_EXTENSION, header.extension_root.as_bytes()),
                ] {
                    let section_id = compute_section_id(type_byte, header_id, root);
                    sh_idx.insert(section_id.as_slice(), height)?;
                }
            }

            if let Some((height, ref score)) = new_best {
                let old_best_height = cs_meta.best_header_height;

                let mut cs = cs_meta.clone();
                cs.best_header_id = *header_id;
                cs.best_header_height = height;
                cs.best_header_score = score.clone();
                let mut chain_meta = write_txn.open_table(CHAIN_STATE_META)?;
                chain_meta.insert("chain_state", cs.serialize().as_slice())?;

                let mut idx_table = write_txn.open_table(HEADER_CHAIN_INDEX)?;
                rewrite_best_chain_into_index(
                    &mut idx_table,
                    &header_meta_table,
                    *header_id,
                    height,
                    old_best_height,
                )?;
                rewrite_height_index_for_new_best(
                    &mut height_idx,
                    &header_meta_table,
                    *header_id,
                    height,
                )?;
            }
        }
        write_txn.commit()?;

        if let Some((height, score)) = new_best {
            cs_meta.best_header_id = *header_id;
            cs_meta.best_header_height = height;
            cs_meta.best_header_score = score;
        }
        Ok(())
    }
}

//! Chain-free rebuild of the DERIVED secondary (template / token) box-segment
//! indexes from the intact PRIMARY tables (`NUMERIC_BOX` + `INDEXED_BOX`).
//!
//! Motivation: a `SegmentEntryMissing` drift (an ancient box whose `+gi`
//! creation entry is absent from the shared template segment) is tolerated at
//! apply time (the indexer degrades-not-halts and sets a sticky repair marker;
//! see [`crate::segment_buffer::tolerate_secondary_drift`] and
//! [`crate::store::meta`]). This module RESTORES full correctness without a
//! full chain reindex: the secondary segments are a pure projection of the
//! primary box table, which retains every box (spends UPDATE the row, they are
//! never deleted), so they can be re-derived by replaying the apply append/flip
//! ops over the box history in `gi` order — no `state.redb` / block validation.
//!
//! Two phases, both crash-safe via a redb commit per chunk + a sticky
//! `INDEXER_META` checkpoint:
//!   * **Phase 0 (wipe)** — reset every template/token parent's box-segment and
//!     delete its box-segment spill rows (preserving token metadata and, of
//!     course, the uncorrupted ADDRESS segments, which share the `SEGMENTS`
//!     table). Idempotent: re-running completes the wipe. Only after the wipe
//!     fully finishes is the Phase-1 checkpoint sentinel written, so a crash
//!     mid-wipe re-wipes rather than corrupting partial rebuild progress.
//!   * **Phase 1 (rebuild)** — scan `gi` in `0..global_box_index`, and for each
//!     box append `+gi` (flip to `-gi` if the box is spent) to its template and
//!     token segments, REUSING the exact apply machinery
//!     (`append_box_entry` / `flip_box_segment_entry` / `flush_*`) so the
//!     rebuilt segments are byte-identical to a fresh linear index. Chunked by
//!     `gi` with a per-chunk checkpoint for bounded memory + resumability.
//!
//! Consensus is untouched: this writes only `indexer.redb` secondary tables.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;
use redb::ReadableTable;
use tracing::{info, warn};

use crate::error::IndexerError;
use crate::segment::Segment;
use crate::segment_buffer::{
    append_box_entry, flip_box_segment_entry, flush_staged_spills, DeletedSpills, StagedSpills,
};
use crate::segment_id::{box_segment_id, token_unique_id};
use crate::ser::boxes::deserialize_indexed_box;
use crate::store::meta as meta_io;
use crate::store::segment::remove_spill;
use crate::store::tables::{INDEXED_BOX, INDEXED_TEMPLATE, INDEXED_TOKEN, NUMERIC_BOX, SEGMENTS};
use crate::store::IndexerStore;
use crate::template::{
    flush_templates, load_template_into_map, read_indexed_template, template_hash_for_box_bytes,
    IndexedTemplate,
};
use crate::token::{flush_tokens, read_indexed_token, write_indexed_token, IndexedToken};
use crate::TokenId;
use ergo_indexer_types::IndexedErgoBox;
use ergo_primitives::reader::VlqReader;

/// Boxes processed per Phase-1 write transaction. Bounds txn size + peak memory
/// (touched parents per chunk) and the work re-done on a crash.
const REBUILD_BOX_CHUNK: u64 = 50_000;
/// Parent records processed per Phase-0 wipe transaction.
const WIPE_PARENT_CHUNK: usize = 20_000;

/// Run (or resume) a full chain-free rebuild of the template + token segments.
/// Clears the repair marker only after the final successful commit. Safe to
/// call whenever [`IndexerStore::secondary_repair_pending`] is true.
///
/// Self-arming: the FIRST committed action is to set the sticky repair marker if
/// it is not already set (see [`ensure_repair_marker_armed`]). The apply-time
/// degrade path always sets the marker before this runs, but this function is
/// also a public, destructive entrypoint — arming up front makes a direct/manual
/// invocation crash-safe too (a crash mid-rebuild leaves the marker set, so the
/// next poll resumes the rebuild rather than exposing a wiped/half-rebuilt index).
pub fn rebuild_secondary_indexes(store: &IndexerStore) -> Result<(), IndexerError> {
    rebuild_secondary_indexes_until(store, &AtomicBool::new(false))
}

/// As [`rebuild_secondary_indexes`], but checks `cancel` between Phase-1 chunks
/// (and between Phase-0 wipe batches) so a node SHUTDOWN drains promptly instead
/// of blocking for the entire multi-hour rebuild. On cancel it returns early
/// WITHOUT clearing the repair marker — the per-chunk checkpoint persists, so the
/// rebuild resumes from where it stopped on the next start. Returns `Ok(())` for
/// both a completed rebuild and an early cancel; the caller distinguishes the two
/// by re-checking the same `cancel` flag (the marker also stays pending on
/// cancel, so the next poll re-enters the rebuild before any apply/rollback).
pub fn rebuild_secondary_indexes_until(
    store: &IndexerStore,
    cancel: &AtomicBool,
) -> Result<(), IndexerError> {
    ensure_repair_marker_armed(store)?;

    let total = store.read_meta()?.global_box_index; // exclusive upper bound on gi

    // Phase-0 sentinel: `None` ⇒ wipe not yet finished; `Some(gi)` ⇒ resume
    // Phase 1 from `gi`.
    let mut next_gi = match store.secondary_repair_next_gi()? {
        None => {
            info!("secondary-index rebuild: phase 0 (wipe) starting");
            wipe_template_segments(store, cancel)?;
            wipe_token_segments(store, cancel)?;
            // A cancel during the (idempotent) wipe leaves the sentinel unwritten,
            // so a resume re-enters Phase 0 and finishes the wipe.
            if cancel.load(Ordering::Acquire) {
                info!("secondary-index rebuild: phase 0 interrupted (resumes on restart)");
                return Ok(());
            }
            // Mark the wipe done + Phase 1 start. Sentinel commit. Reset the skip
            // count to 0 so a fresh rebuild does not inherit a prior aborted run's
            // tally.
            let write_txn = store.begin_write()?;
            meta_io::write_secondary_repair_next_gi(&write_txn, 0)?;
            meta_io::write_secondary_repair_skipped(&write_txn, 0)?;
            write_txn.commit()?;
            info!("secondary-index rebuild: phase 0 complete");
            0
        }
        Some(gi) => {
            info!(resume_gi = gi, "secondary-index rebuild: resuming phase 1");
            gi
        }
    };

    info!(
        total,
        start = next_gi,
        "secondary-index rebuild: phase 1 (re-derive segments) starting"
    );
    // Resume-safe running total of undecodable boxes skipped by the fallback
    // (persisted with each checkpoint, so it accumulates correctly across a
    // crash + resume rather than resetting to the post-restart portion only).
    let mut skipped = store.secondary_repair_skipped()?;
    while next_gi < total {
        // Drain promptly on shutdown — the last committed checkpoint resumes us.
        if cancel.load(Ordering::Acquire) {
            info!(
                done = next_gi,
                total, "secondary-index rebuild: phase 1 interrupted (resumes on restart)"
            );
            return Ok(());
        }
        let chunk_end = next_gi.saturating_add(REBUILD_BOX_CHUNK).min(total);
        skipped = rebuild_box_chunk(store, next_gi, chunk_end, skipped)?;
        next_gi = chunk_end;
        info!(
            done = next_gi,
            total, skipped, "secondary-index rebuild: phase 1 progress"
        );
    }

    // Done. Drop the pending marker + checkpoint in one final commit. When boxes
    // were skipped, KEEP the durable skipped-count record so a knowingly-incomplete
    // index is never silently presented as fully repaired; otherwise clear it too.
    let write_txn = store.begin_write()?;
    meta_io::clear_secondary_repair(&write_txn)?;
    if skipped == 0 {
        meta_io::clear_secondary_repair_skipped(&write_txn)?;
    }
    write_txn.commit()?;
    if skipped == 0 {
        info!(
            total,
            "secondary-index rebuild: complete (index fully repaired)"
        );
    } else {
        warn!(
            total,
            skipped,
            "secondary-index rebuild: complete with undecodable box(es) skipped — their \
             template/token entries are omitted (box ids in earlier logs); address-index \
             entries are retained"
        );
    }
    Ok(())
}

/// Arm the sticky repair marker before any destructive rebuild work, unless it
/// is already set. Committed in its own write txn so it is durable before Phase 0
/// touches a single row. Idempotent: a no-op on the normal auto-repair path
/// (where the apply/rollback degrade already set the marker), and the guard that
/// makes a direct/manual [`rebuild_secondary_indexes`] call resumable across a
/// crash. Leaves the `next_gi` checkpoint untouched, so a resume-in-progress
/// rebuild (`Some(gi)`) is not reset to the wipe phase.
fn ensure_repair_marker_armed(store: &IndexerStore) -> Result<(), IndexerError> {
    if !store.secondary_repair_pending()? {
        let write_txn = store.begin_write()?;
        meta_io::set_secondary_repair_pending(&write_txn)?;
        write_txn.commit()?;
    }
    Ok(())
}

/// Phase 0a — delete every `INDEXED_TEMPLATE` row and its box-segment spills.
/// Templates carry no metadata (row = `template_hash || segment`), so they are
/// re-created from scratch in Phase 1. Idempotent + chunked. Checks `cancel`
/// between batches so a shutdown drains promptly; the wipe is idempotent, so a
/// resume re-runs it to completion.
fn wipe_template_segments(store: &IndexerStore, cancel: &AtomicBool) -> Result<(), IndexerError> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        let write_txn = store.begin_write()?;
        let mut wrote = 0usize;
        {
            // Collect a chunk of (template_hash, spill_count), then delete.
            let victims: Vec<(Digest32, i32)> = {
                let table = write_txn.open_table(INDEXED_TEMPLATE)?;
                let mut v = Vec::new();
                for row in table.iter()? {
                    let (k, val) = row?;
                    let hash = digest_from_key(k.value())?;
                    let mut r = VlqReader::new(val.value());
                    let t = read_indexed_template(&mut r).map_err(|e| IndexerError::DbDecode {
                        context: "rebuild_wipe_template",
                        source: e,
                    })?;
                    if !r.is_empty() {
                        return Err(IndexerError::DbRowLength {
                            context: "rebuild_wipe_template",
                            expected: r.position(),
                            got: val.value().len(),
                        });
                    }
                    v.push((hash, t.segment.box_segment_count));
                    if v.len() >= WIPE_PARENT_CHUNK {
                        break;
                    }
                }
                v
            };
            if victims.is_empty() {
                break;
            }
            let mut tmpl_table = write_txn.open_table(INDEXED_TEMPLATE)?;
            let mut seg_table = write_txn.open_table(SEGMENTS)?;
            for (hash, count) in &victims {
                for n in 0..*count {
                    remove_spill(&mut seg_table, &box_segment_id(hash, n))?;
                }
                tmpl_table.remove(hash.as_bytes().as_slice())?;
                wrote += 1;
            }
        }
        write_txn.commit()?;
        if wrote < WIPE_PARENT_CHUNK {
            break;
        }
    }
    Ok(())
}

/// Phase 0b — reset every `INDEXED_TOKEN`'s box-segment to empty (PRESERVING the
/// token metadata: `creating_box_id`, emission, name, description, decimals) and
/// delete its box-segment spills. Idempotent + chunked. Checks `cancel` between
/// batches so a shutdown drains promptly; the wipe is idempotent on resume.
fn wipe_token_segments(store: &IndexerStore, cancel: &AtomicBool) -> Result<(), IndexerError> {
    let mut start_after: Option<Vec<u8>> = None;
    loop {
        if cancel.load(Ordering::Acquire) {
            return Ok(());
        }
        let write_txn = store.begin_write()?;
        let mut processed = 0usize;
        let mut last_key: Option<Vec<u8>> = None;
        {
            // Read a chunk of token rows whose segment is non-empty (so the
            // pass converges: already-reset tokens are skipped, making re-runs
            // idempotent and terminating).
            let to_reset: Vec<(Vec<u8>, IndexedToken)> = {
                let table = write_txn.open_table(INDEXED_TOKEN)?;
                let iter = match &start_after {
                    None => table.iter()?,
                    Some(k) => {
                        use std::ops::Bound;
                        table.range::<&[u8]>((Bound::Excluded(k.as_slice()), Bound::Unbounded))?
                    }
                };
                let mut v = Vec::new();
                for row in iter {
                    let (k, val) = row?;
                    let key = k.value().to_vec();
                    last_key = Some(key.clone());
                    let mut r = VlqReader::new(val.value());
                    let t = read_indexed_token(&mut r).map_err(|e| IndexerError::DbDecode {
                        context: "rebuild_wipe_token",
                        source: e,
                    })?;
                    if !r.is_empty() {
                        return Err(IndexerError::DbRowLength {
                            context: "rebuild_wipe_token",
                            expected: r.position(),
                            got: val.value().len(),
                        });
                    }
                    let non_empty = !t.segment.boxes.is_empty() || t.segment.box_segment_count != 0;
                    if non_empty {
                        v.push((key, t));
                    }
                    processed += 1;
                    if processed >= WIPE_PARENT_CHUNK {
                        break;
                    }
                }
                v
            };
            let mut tok_table = write_txn.open_table(INDEXED_TOKEN)?;
            let mut seg_table = write_txn.open_table(SEGMENTS)?;
            let mut writer = VlqWriter::new();
            for (key, mut t) in to_reset {
                let parent = token_unique_id(&t.token_id);
                for n in 0..t.segment.box_segment_count {
                    remove_spill(&mut seg_table, &box_segment_id(&parent, n))?;
                }
                t.segment = Segment::empty();
                writer.clear();
                write_indexed_token(&mut writer, &t);
                tok_table.insert(key.as_slice(), writer.as_slice())?;
            }
        }
        write_txn.commit()?;
        if processed < WIPE_PARENT_CHUNK {
            break;
        }
        start_after = last_key;
    }
    Ok(())
}

/// Phase 1 — re-derive every template & token segment for boxes with global
/// index in `[start_gi, end_gi)`, in one write transaction, then checkpoint.
/// Reuses the apply append/flip/flush path so segments are identical to a fresh
/// linear index.
fn rebuild_box_chunk(
    store: &IndexerStore,
    start_gi: u64,
    end_gi: u64,
    skipped_so_far: u64,
) -> Result<u64, IndexerError> {
    let mut skipped = skipped_so_far;
    let write_txn = store.begin_write()?;
    {
        let num_box_table = write_txn.open_table(NUMERIC_BOX)?;
        let box_table = write_txn.open_table(INDEXED_BOX)?;
        let mut template_table = write_txn.open_table(INDEXED_TEMPLATE)?;
        let mut token_table = write_txn.open_table(INDEXED_TOKEN)?;
        let mut segments_table = write_txn.open_table(SEGMENTS)?;

        let mut touched_templates: HashMap<Digest32, IndexedTemplate> = HashMap::new();
        let mut touched_tokens: HashMap<TokenId, IndexedToken> = HashMap::new();
        let mut staged: StagedSpills = HashMap::new();
        let deleted: DeletedSpills = HashSet::new();
        let mut writer = VlqWriter::new();

        for gi in start_gi..end_gi {
            let Some(box_id) = read_box_id(&num_box_table, gi)? else {
                // A gap in NUMERIC_BOX is itself primary-index corruption, not a
                // secondary-index gap we may paper over.
                return Err(IndexerError::SegmentTopologyError {
                    detail: format!("rebuild: NUMERIC_BOX has no box_id for global_index {gi}"),
                });
            };
            let rec = match read_box(&box_table, &box_id, gi) {
                Ok(rec) => rec,
                Err(IndexerError::DbDecode { .. }) => {
                    // Degrade-not-halt FALLBACK: a stored row that even the
                    // trusted/lenient reader cannot decode is genuine primary-row
                    // corruption (not a tolerable secondary drift). Skip THIS one
                    // box so the rebuild still completes — its template/token
                    // segment entries are omitted (the box keeps its address-index
                    // entry). read_box already logged the offending gi+box_id; the
                    // running skip count is persisted with the checkpoint below so
                    // completion does NOT falsely claim a full repair.
                    skipped += 1;
                    continue;
                }
                // A missing NUMERIC_BOX/INDEXED_BOX row is structural primary
                // corruption we must NOT paper over — still fatal.
                Err(e) => return Err(e),
            };
            let gi_i64 = gi as i64;
            let spent = rec.is_spent();
            let tree_bytes = rec.box_data.candidate.ergo_tree_bytes();

            // Template segment.
            if let Some(template_hash) = template_hash_for_box_bytes(tree_bytes)? {
                let t =
                    load_template_into_map(&template_table, &mut touched_templates, template_hash)?;
                append_box_entry(&t.template_hash, &mut t.segment, gi_i64, &mut staged);
                if spent {
                    flip_box_segment_entry(
                        &t.template_hash,
                        &mut t.segment,
                        gi_i64,
                        &mut staged,
                        &segments_table,
                    )?;
                }
            }

            // Token segments (one entry per token the box carried — duplicates
            // intentionally produce multiple entries, matching apply).
            for token in &rec.box_data.candidate.tokens {
                let rec_t = load_token_or_skip(&token_table, &mut touched_tokens, token.token_id)?;
                if let Some(rec_t) = rec_t {
                    let parent = token_unique_id(&rec_t.token_id);
                    append_box_entry(&parent, &mut rec_t.segment, gi_i64, &mut staged);
                    if spent {
                        flip_box_segment_entry(
                            &parent,
                            &mut rec_t.segment,
                            gi_i64,
                            &mut staged,
                            &segments_table,
                        )?;
                    }
                }
            }
        }

        flush_templates(&mut template_table, &mut writer, &touched_templates)?;
        let no_removals: HashSet<TokenId> = HashSet::new();
        flush_tokens(&mut token_table, &mut writer, &touched_tokens, &no_removals)?;
        flush_staged_spills(&mut segments_table, &mut writer, &staged, &deleted)?;
    }
    // Checkpoint atomically with this chunk's writes — the `next_gi` cursor AND
    // the running skipped-box total, so a crash + resume neither re-processes a
    // committed chunk nor loses the skip count.
    meta_io::write_secondary_repair_next_gi(&write_txn, end_gi)?;
    meta_io::write_secondary_repair_skipped(&write_txn, skipped)?;
    write_txn.commit()?;
    Ok(skipped)
}

// ---- small read helpers over a write-txn-opened table ----

fn read_box_id(
    num_box_table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    gi: u64,
) -> Result<Option<Digest32>, IndexerError> {
    let key = gi.to_be_bytes();
    let Some(g) = num_box_table.get(key.as_slice())? else {
        return Ok(None);
    };
    Ok(Some(digest_from_key(g.value())?))
}

fn read_box(
    box_table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    box_id: &Digest32,
    gi: u64,
) -> Result<IndexedErgoBox, IndexerError> {
    let Some(g) = box_table.get(box_id.as_bytes().as_slice())? else {
        return Err(IndexerError::SegmentTopologyError {
            detail: format!(
                "rebuild: INDEXED_BOX missing for box_id {}",
                hex::encode(box_id.as_bytes())
            ),
        });
    };
    deserialize_indexed_box(g.value()).map_err(|e| {
        // The deserializer is lenient about already-validated stored boxes
        // (high-version opaque trees included), so a failure here is genuine
        // primary-row corruption — name the offending box so it is actionable
        // without re-running a 50M-box scan to find it.
        tracing::error!(
            gi,
            box_id = %hex::encode(box_id.as_bytes()),
            error = %e,
            "secondary-index rebuild: INDEXED_BOX row failed to decode",
        );
        IndexerError::DbDecode {
            context: "rebuild_read_box",
            source: e,
        }
    })
}

/// Load a token record into the touched map, skipping (returning `None`) if no
/// record exists — every chain-validated token has a mint record, so this is a
/// defensive no-op rather than a fabricated default.
fn load_token_or_skip<'a>(
    token_table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    map: &'a mut HashMap<TokenId, IndexedToken>,
    token_id: TokenId,
) -> Result<Option<&'a mut IndexedToken>, IndexerError> {
    use std::collections::hash_map::Entry;
    match map.entry(token_id) {
        Entry::Occupied(e) => Ok(Some(e.into_mut())),
        Entry::Vacant(e) => {
            let key = token_unique_id(&token_id);
            let Some(g) = token_table.get(key.as_bytes().as_slice())? else {
                return Ok(None);
            };
            let mut r = VlqReader::new(g.value());
            let t = read_indexed_token(&mut r).map_err(|err| IndexerError::DbDecode {
                context: "rebuild_load_token",
                source: err,
            })?;
            if !r.is_empty() {
                return Err(IndexerError::DbRowLength {
                    context: "rebuild_load_token",
                    expected: r.position(),
                    got: g.value().len(),
                });
            }
            Ok(Some(e.insert(t)))
        }
    }
}

fn digest_from_key(bytes: &[u8]) -> Result<Digest32, IndexerError> {
    if bytes.len() != 32 {
        return Err(IndexerError::DbRowLength {
            context: "rebuild_box_id",
            expected: 32,
            got: bytes.len(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(Digest32::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::IndexerStore;
    use tempfile::TempDir;

    /// `rebuild_secondary_indexes` self-arms the sticky marker before any
    /// destructive work, so a direct (non-degrade-path) invocation that crashes
    /// mid-rebuild still resumes on restart instead of serving a wiped index.
    /// This pins the arming step: it sets the marker on a healthy DB, fabricates
    /// no checkpoint, and never resets an in-progress resume checkpoint.
    #[test]
    fn ensure_repair_marker_armed_sets_marker_when_absent_and_preserves_checkpoint() {
        let tmp = TempDir::new().unwrap();
        let (store, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();

        // Fresh, healthy DB: no marker, no checkpoint.
        assert!(!store.secondary_repair_pending().unwrap());
        assert_eq!(store.secondary_repair_next_gi().unwrap(), None);

        // Arming a healthy DB sets the pending marker but fabricates no
        // checkpoint (None = wipe-due preserved), so a direct rebuild still
        // starts at Phase 0.
        ensure_repair_marker_armed(&store).unwrap();
        assert!(store.secondary_repair_pending().unwrap());
        assert_eq!(store.secondary_repair_next_gi().unwrap(), None);

        // A resume-in-progress checkpoint must NOT be reset by re-arming: the
        // marker is already set, so arming is a no-op and Phase 1 resumes at gi.
        {
            let write_txn = store.begin_write().unwrap();
            meta_io::write_secondary_repair_next_gi(&write_txn, 1_000).unwrap();
            write_txn.commit().unwrap();
        }
        ensure_repair_marker_armed(&store).unwrap();
        assert!(store.secondary_repair_pending().unwrap());
        assert_eq!(store.secondary_repair_next_gi().unwrap(), Some(1_000));
    }

    use ergo_indexer_types::IndexedErgoBox;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::{template_hash_from_bytes, write_ergo_tree, ErgoTree};
    use ergo_ser::opcode::{Body, Expr};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

    fn parseable_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
            } as Body,
        }
    }

    fn valid_box_row(tree: &ErgoTree, gi: i64) -> Vec<u8> {
        let candidate =
            ErgoBoxCandidate::new(1_000_000, tree.clone(), 1, vec![], AdditionalRegisters::empty())
                .unwrap();
        let b = IndexedErgoBox {
            inclusion_height: 1,
            spending_tx_id: None,
            spending_height: None,
            spending_proof: None,
            box_data: ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes([0x11; 32]),
                index: 0,
            },
            global_index: gi,
        };
        crate::ser::boxes::serialize_indexed_box(&b).unwrap()
    }

    /// Degrade-not-halt FALLBACK: a primary `INDEXED_BOX` row that no reader can
    /// decode (genuine corruption — NOT a tolerable high-version opaque tree, which
    /// the trusted reader handles) must be SKIPPED. The rebuild completes, the
    /// surviving boxes are re-derived, and the skip is recorded durably so the
    /// index is never silently presented as a full repair.
    #[test]
    fn rebuild_skips_undecodable_box_and_records_the_skip() {
        let tmp = TempDir::new().unwrap();
        let (store, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
        let tree = parseable_tree();
        let tree_bytes = {
            let mut w = VlqWriter::new();
            write_ergo_tree(&mut w, &tree).unwrap();
            w.result()
        };
        let template = Digest32::from_bytes(template_hash_from_bytes(&tree_bytes).unwrap());

        let id0 = Digest32::from_bytes([0xA0; 32]);
        let id1 = Digest32::from_bytes([0xA1; 32]);
        let id2 = Digest32::from_bytes([0xA2; 32]);

        // Populate the PRIMARY tables directly: gi 0 and 2 are valid boxes sharing
        // a template; gi 1 is an undecodable garbage row. global_box_index = 3.
        {
            let wt = store.begin_write().unwrap();
            {
                let mut nb = wt.open_table(NUMERIC_BOX).unwrap();
                nb.insert(0u64.to_be_bytes().as_slice(), id0.as_bytes().as_slice())
                    .unwrap();
                nb.insert(1u64.to_be_bytes().as_slice(), id1.as_bytes().as_slice())
                    .unwrap();
                nb.insert(2u64.to_be_bytes().as_slice(), id2.as_bytes().as_slice())
                    .unwrap();
                let mut bt = wt.open_table(INDEXED_BOX).unwrap();
                bt.insert(id0.as_bytes().as_slice(), valid_box_row(&tree, 0).as_slice())
                    .unwrap();
                bt.insert(id1.as_bytes().as_slice(), [0xFFu8, 0xFF, 0xFF].as_slice())
                    .unwrap();
                bt.insert(id2.as_bytes().as_slice(), valid_box_row(&tree, 2).as_slice())
                    .unwrap();
            }
            let mut meta = crate::store::IndexerMeta::empty();
            meta.global_box_index = 3;
            meta_io::write_meta(&wt, &meta).unwrap();
            meta_io::set_secondary_repair_pending(&wt).unwrap();
            wt.commit().unwrap();
        }

        rebuild_secondary_indexes(&store).unwrap();

        // The corrupt gi=1 row was skipped; 0 and 2 were re-derived into the
        // template segment.
        assert_eq!(
            store.read_template_box_entries(&template).unwrap().unwrap(),
            vec![0, 2],
            "valid boxes rebuilt, undecodable one omitted"
        );
        // The skip is recorded durably and the pending marker is cleared.
        assert_eq!(store.secondary_repair_skipped().unwrap(), 1);
        assert!(!store.secondary_repair_pending().unwrap());
        assert_eq!(store.secondary_repair_next_gi().unwrap(), None);
    }

    /// The rebuild drains promptly on shutdown: with the cancel flag set it
    /// returns early WITHOUT clearing the marker (so the half-rebuilt index is
    /// never exposed and is not extended by forward-apply), and a later
    /// uncancelled run resumes and completes it.
    #[test]
    fn rebuild_until_honors_cancel_and_resumes() {
        let tmp = TempDir::new().unwrap();
        let (store, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
        let tree = parseable_tree();
        let tree_bytes = {
            let mut w = VlqWriter::new();
            write_ergo_tree(&mut w, &tree).unwrap();
            w.result()
        };
        let template = Digest32::from_bytes(template_hash_from_bytes(&tree_bytes).unwrap());

        let id0 = Digest32::from_bytes([0xB0; 32]);
        let id1 = Digest32::from_bytes([0xB1; 32]);
        {
            let wt = store.begin_write().unwrap();
            {
                let mut nb = wt.open_table(NUMERIC_BOX).unwrap();
                nb.insert(0u64.to_be_bytes().as_slice(), id0.as_bytes().as_slice())
                    .unwrap();
                nb.insert(1u64.to_be_bytes().as_slice(), id1.as_bytes().as_slice())
                    .unwrap();
                let mut bt = wt.open_table(INDEXED_BOX).unwrap();
                bt.insert(id0.as_bytes().as_slice(), valid_box_row(&tree, 0).as_slice())
                    .unwrap();
                bt.insert(id1.as_bytes().as_slice(), valid_box_row(&tree, 1).as_slice())
                    .unwrap();
            }
            let mut meta = crate::store::IndexerMeta::empty();
            meta.global_box_index = 2;
            meta_io::write_meta(&wt, &meta).unwrap();
            meta_io::set_secondary_repair_pending(&wt).unwrap();
            wt.commit().unwrap();
        }

        // Cancel already set → the rebuild returns early; the marker STAYS pending.
        let cancel = AtomicBool::new(true);
        rebuild_secondary_indexes_until(&store, &cancel).unwrap();
        assert!(
            store.secondary_repair_pending().unwrap(),
            "cancel must leave the repair marker pending for a resume"
        );

        // An uncancelled resume completes it.
        rebuild_secondary_indexes(&store).unwrap();
        assert!(!store.secondary_repair_pending().unwrap());
        assert_eq!(
            store.read_template_box_entries(&template).unwrap().unwrap(),
            vec![0, 1]
        );
    }
}

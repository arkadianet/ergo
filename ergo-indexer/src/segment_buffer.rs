//! Head-buffer + spill mechanics for parent segment records.
//!
//! Used by both `IndexedAddress` (boxes + txs) and `IndexedTemplate`
//! (boxes only). The box helpers operate on a `(parent_id, segment)`
//! pair so the same code drives both — `parent_id` becomes
//! `tree_hash` for addresses and `template_hash` for templates, both
//! of which are `Digest32`. Tx helpers stay address-typed because
//! templates do not track transactions (Scala
//! `IndexedContractTemplate` only carries a box-segment).
//!
//! Each parent record's `Segment` arrays act as bounded head buffers.
//! When a head buffer grows strictly above `SEGMENT_THRESHOLD = 512`,
//! the oldest 512 entries are drained into a standalone *spill*
//! segment row under the `SEGMENTS` table, keyed by `box_segment_id`
//! / `tx_segment_id`. Spill segments are immutable in size — they
//! always carry exactly 512 entries — and the parent's head retains
//! the leftover newest entries.
//!
//! The helpers in this module are paired:
//!
//! - `append_box_entry` / `append_tx_entry` push a positive global
//!   index onto the head and trigger one or more spills if the head
//!   crosses the threshold.
//! - `flip_box_segment_entry` walks the segment chain to flip the sign
//!   of a previously-appended entry on spend.
//! - `pop_box_entry` / `pop_tx_entry` are the rollback inverses of
//!   append, popping from the head and merging back the most recent
//!   spill on underflow.
//! - `unflip_box_segment_entry` is the rollback inverse of
//!   `flip_box_segment_entry`, flipping the entry sign back from
//!   negative to positive.
//!
//! All functions operate on in-memory state (mutated in place) plus a
//! `staged_spills` map and a `deleted_spills` set so the caller can
//! persist all changes in a single redb pass at the end of the block.

use std::collections::{HashMap, HashSet};

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use redb::{ReadableTable, Table};

use crate::address::IndexedAddress;
use crate::error::IndexerError;
use crate::segment::{read_segment, Segment, SEGMENT_THRESHOLD};
use crate::segment_id::{box_segment_id, tx_segment_id};

/// Map keyed by spill segment id. The caller seeds this with the empty
/// map at the start of a block apply / rollback and persists all
/// entries via `flush_staged_spills` at the end.
pub(crate) type StagedSpills = HashMap<Digest32, Segment>;

/// Set of spill segment ids that must be deleted from `SEGMENTS` at the
/// end of a rollback (merge-back removes one spill per underflowed pop).
pub(crate) type DeletedSpills = HashSet<Digest32>;

/// Append `+global_index` to a parent's box-segment head and spill
/// the oldest 512 entries if the head crosses `SEGMENT_THRESHOLD`. May
/// produce more than one spill if a single block adds >>512 entries
/// (e.g. very large coinbase distribution to one tree).
///
/// `parent_id` is the parent record's key — `tree_hash` for an
/// `IndexedAddress`, `template_hash` for an `IndexedTemplate`. It
/// drives the spill-segment-id derivation (`box_segment_id`) which
/// must be unique per parent.
pub(crate) fn append_box_entry(
    parent_id: &Digest32,
    segment: &mut Segment,
    global_index: i64,
    staged_spills: &mut StagedSpills,
) {
    debug_assert!(
        global_index >= 0,
        "box global_index must be non-negative on append"
    );
    segment.boxes.push(global_index);
    while segment.boxes.len() > SEGMENT_THRESHOLD {
        let drained: Vec<i64> = segment.boxes.drain(..SEGMENT_THRESHOLD).collect();
        let seg_id = box_segment_id(parent_id, segment.box_segment_count);
        staged_spills.insert(
            seg_id,
            Segment {
                txs: Vec::new(),
                boxes: drained,
                box_segment_count: 0,
                tx_segment_count: 0,
            },
        );
        segment.box_segment_count += 1;
    }
}

/// Append `+tx_global_index` to the address's tx-segment head, spilling
/// the oldest 512 entries on overflow. Tx entries are always positive
/// — there is no per-tx spent flag (`Segment.scala:24` only flags box
/// entries).
pub(crate) fn append_tx_entry(
    addr: &mut IndexedAddress,
    tx_global_index: i64,
    staged_spills: &mut StagedSpills,
) {
    debug_assert!(tx_global_index >= 0, "tx global_index must be non-negative");
    addr.segment.txs.push(tx_global_index);
    while addr.segment.txs.len() > SEGMENT_THRESHOLD {
        let drained: Vec<i64> = addr.segment.txs.drain(..SEGMENT_THRESHOLD).collect();
        let seg_id = tx_segment_id(&addr.tree_hash, addr.segment.tx_segment_count);
        staged_spills.insert(
            seg_id,
            Segment {
                txs: drained,
                boxes: Vec::new(),
                box_segment_count: 0,
                tx_segment_count: 0,
            },
        );
        addr.segment.tx_segment_count += 1;
    }
}

/// Sign-flip the entry whose `abs(...) == global_index` from positive
/// to negative (apply on spend). Walks the head buffer first, then the
/// spill chain newest-first. Mirrors `Segment.findAndModBox`
/// (`Segment.scala:63-98`).
///
/// `parent_id` keys the spill-id derivation; same value as the parent
/// record's id (`tree_hash` for addresses, `template_hash` for
/// templates).
pub(crate) fn flip_box_segment_entry(
    parent_id: &Digest32,
    segment: &mut Segment,
    global_index: i64,
    staged_spills: &mut StagedSpills,
    segments_table: &Table<&[u8], &[u8]>,
) -> Result<(), IndexerError> {
    flip_helper(
        parent_id,
        segment,
        global_index,
        staged_spills,
        segments_table,
        FlipDirection::Apply,
    )
}

/// Inverse of `flip_box_segment_entry`: flip the entry whose
/// `abs(...) == global_index` back from negative to positive (rollback
/// on input restore).
pub(crate) fn unflip_box_segment_entry(
    parent_id: &Digest32,
    segment: &mut Segment,
    global_index: i64,
    staged_spills: &mut StagedSpills,
    segments_table: &Table<&[u8], &[u8]>,
) -> Result<(), IndexerError> {
    flip_helper(
        parent_id,
        segment,
        global_index,
        staged_spills,
        segments_table,
        FlipDirection::Rollback,
    )
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum FlipDirection {
    /// Apply: expects a positive entry, writes back its negation.
    Apply,
    /// Rollback: expects a negative entry, writes back its negation.
    Rollback,
}

fn flip_helper(
    parent_id: &Digest32,
    segment: &mut Segment,
    global_index: i64,
    staged_spills: &mut StagedSpills,
    segments_table: &Table<&[u8], &[u8]>,
    direction: FlipDirection,
) -> Result<(), IndexerError> {
    let target = global_index.abs();
    // Sign-aware match: Apply consumes the next +target entry, Rollback
    // consumes the next -target entry. Skipping opposite-sign entries
    // is what lets a box with duplicate token IDs in
    // `additionalTokens` (Ergo allows this — `Coll[(TokenId, Long)]`,
    // not a set) flip cleanly across N spend calls. With N duplicate
    // appends `[..., +gi, +gi, ...]`, each Apply call finds the next
    // remaining +gi and flips it; after N calls the segment ends as
    // `[..., -gi, -gi, ...]` — same shape Scala reaches via
    // `Segment.findAndModBox` + `binarySearch` (see
    // `Segment.scala:63-98`). Real "trying to spend a never-indexed
    // box" still surfaces as a not-found error.
    //
    // gi == 0 is special: -0 == 0, so the signed-flag scheme cannot
    // distinguish spent from unspent for the very first indexed box.
    // Scala has the same limitation — `binarySearch(boxes, 0)` finds the
    // entry regardless of stored sign, and `-0` writes back as `0`. We
    // preserve that no-op-but-success behavior here so apply/rollback
    // never spuriously errors on the genesis box.
    let matches = |e: &i64| e.abs() == target && (target == 0 || entry_sign_matches(*e, direction));
    // Also track abs-only matches so we can distinguish "no entry at all"
    // from "entry exists but every copy is already in the requested sign
    // direction". The two indicate different kinds of corruption — one
    // says topology drift (the entry was never appended); the other says
    // double-flip (an Apply ran for the same target without a Rollback
    // between them). Surfacing them separately keeps the post-mortem
    // signal sharp on reorg paths.
    let abs_match = |e: &i64| e.abs() == target;

    let mut saw_opposite_sign = false;

    if let Some(pos) = segment.boxes.iter().position(matches) {
        segment.boxes[pos] = -segment.boxes[pos];
        return Ok(());
    }
    if segment.boxes.iter().any(abs_match) {
        saw_opposite_sign = true;
    }

    for seg_num in (0..segment.box_segment_count).rev() {
        let seg_id = box_segment_id(parent_id, seg_num);
        let spill = load_spill_for_mutation(seg_id, staged_spills, segments_table)?;
        if let Some(pos) = spill.boxes.iter().position(matches) {
            spill.boxes[pos] = -spill.boxes[pos];
            return Ok(());
        }
        if !saw_opposite_sign && spill.boxes.iter().any(abs_match) {
            saw_opposite_sign = true;
        }
    }

    let direction_label = match direction {
        FlipDirection::Apply => "positive",
        FlipDirection::Rollback => "negative",
    };
    let detail = if saw_opposite_sign {
        format!(
            "segment_buffer: cannot flip global_index {target} in parent {}: entry exists but every copy is already {} (double-flip)",
            hex::encode(parent_id.as_bytes()),
            match direction {
                FlipDirection::Apply => "negative",
                FlipDirection::Rollback => "positive",
            },
        )
    } else {
        format!(
            "segment_buffer: cannot flip global_index {target} in parent {}: no {} entry found and no entry of either sign present (topology drift)",
            hex::encode(parent_id.as_bytes()),
            direction_label,
        )
    };
    Err(IndexerError::SegmentTopologyError { detail })
}

fn entry_sign_matches(entry: i64, direction: FlipDirection) -> bool {
    match direction {
        FlipDirection::Apply => entry > 0,
        FlipDirection::Rollback => entry < 0,
    }
}

/// Pop the most-recently-appended box entry from the head, merging back
/// the most recent spill if the head is empty. Returns the popped
/// entry (signed) so callers can sanity-check expectations.
///
/// `parent_id` keys the spill-id derivation; same value as the parent
/// record's id (`tree_hash` for addresses, `template_hash` for
/// templates).
pub(crate) fn pop_box_entry(
    parent_id: &Digest32,
    segment: &mut Segment,
    staged_spills: &mut StagedSpills,
    deleted_spills: &mut DeletedSpills,
    segments_table: &Table<&[u8], &[u8]>,
) -> Result<i64, IndexerError> {
    if let Some(entry) = segment.boxes.pop() {
        return Ok(entry);
    }
    if segment.box_segment_count == 0 {
        return Err(IndexerError::SegmentTopologyError {
            detail: format!(
                "segment_buffer: parent {}: pop_box_entry on empty segment",
                hex::encode(parent_id.as_bytes()),
            ),
        });
    }
    segment.box_segment_count -= 1;
    let seg_id = box_segment_id(parent_id, segment.box_segment_count);
    let spill = take_spill_for_mergeback(seg_id, staged_spills, segments_table)?;
    segment.boxes = spill.boxes;
    deleted_spills.insert(seg_id);
    segment
        .boxes
        .pop()
        .ok_or_else(|| IndexerError::SegmentTopologyError {
            detail: format!(
                "segment_buffer: parent {}: merged-back box spill was empty",
                hex::encode(parent_id.as_bytes()),
            ),
        })
}

/// Pop the most-recently-appended tx entry from the head, merging back
/// the most recent spill on underflow. Tx entries are always positive
/// so the popped value is the original global_index.
pub(crate) fn pop_tx_entry(
    addr: &mut IndexedAddress,
    staged_spills: &mut StagedSpills,
    deleted_spills: &mut DeletedSpills,
    segments_table: &Table<&[u8], &[u8]>,
) -> Result<i64, IndexerError> {
    if let Some(entry) = addr.segment.txs.pop() {
        return Ok(entry);
    }
    if addr.segment.tx_segment_count == 0 {
        return Err(IndexerError::SegmentTopologyError {
            detail: format!(
                "segment_buffer: tree_hash {}: pop_tx_entry on empty segment",
                hex::encode(addr.tree_hash.as_bytes()),
            ),
        });
    }
    addr.segment.tx_segment_count -= 1;
    let seg_id = tx_segment_id(&addr.tree_hash, addr.segment.tx_segment_count);
    let spill = take_spill_for_mergeback(seg_id, staged_spills, segments_table)?;
    addr.segment.txs = spill.txs;
    deleted_spills.insert(seg_id);
    addr.segment
        .txs
        .pop()
        .ok_or_else(|| IndexerError::SegmentTopologyError {
            detail: format!(
                "segment_buffer: tree_hash {}: merged-back tx spill was empty",
                hex::encode(addr.tree_hash.as_bytes()),
            ),
        })
}

/// Lazy-load helper for sign-flip: returns a mutable reference to the
/// staged copy of the spill, loading from disk on first touch.
fn load_spill_for_mutation<'a>(
    seg_id: Digest32,
    staged_spills: &'a mut StagedSpills,
    segments_table: &Table<&[u8], &[u8]>,
) -> Result<&'a mut Segment, IndexerError> {
    use std::collections::hash_map::Entry;
    match staged_spills.entry(seg_id) {
        Entry::Occupied(o) => Ok(o.into_mut()),
        Entry::Vacant(v) => {
            let loaded = read_spill_from_table(segments_table, &seg_id)?.ok_or_else(|| {
                IndexerError::SegmentTopologyError {
                    detail: format!(
                        "segment_buffer: spill {} missing on disk",
                        hex::encode(seg_id.as_bytes()),
                    ),
                }
            })?;
            Ok(v.insert(loaded))
        }
    }
}

/// Take helper for merge-back: removes from the staged map (or loads
/// from disk) the spill identified by `seg_id`, returning ownership.
fn take_spill_for_mergeback(
    seg_id: Digest32,
    staged_spills: &mut StagedSpills,
    segments_table: &Table<&[u8], &[u8]>,
) -> Result<Segment, IndexerError> {
    if let Some(s) = staged_spills.remove(&seg_id) {
        return Ok(s);
    }
    read_spill_from_table(segments_table, &seg_id)?.ok_or_else(|| {
        IndexerError::SegmentTopologyError {
            detail: format!(
                "segment_buffer: spill {} missing during merge-back",
                hex::encode(seg_id.as_bytes()),
            ),
        }
    })
}

fn read_spill_from_table(
    segments_table: &Table<&[u8], &[u8]>,
    seg_id: &Digest32,
) -> Result<Option<Segment>, IndexerError> {
    let Some(guard) = segments_table.get(seg_id.as_bytes().as_slice())? else {
        return Ok(None);
    };
    let bytes = guard.value();
    let mut r = VlqReader::new(bytes);
    let seg = read_segment(&mut r).map_err(|source| IndexerError::DbDecode {
        context: "segment",
        source,
    })?;
    // Mirror the EOF guard the public `store::segment::read_spill_in`
    // reader applies. Without it a malformed spill row could be loaded
    // during apply/rollback, mutated, and flushed back clean —
    // silently normalising on-disk corruption.
    if !r.is_empty() {
        return Err(IndexerError::DbRowLength {
            context: "segment",
            expected: r.position(),
            got: bytes.len(),
        });
    }
    Ok(Some(seg))
}

/// Persist all staged spills in `staged` and remove all spill ids in
/// `deleted` from `segments_table`. If a spill id appears in both, the
/// delete wins (caller's `pop_box_entry` / `pop_tx_entry` already
/// removed it from `staged`, so this is just a defense-in-depth).
///
/// `writer` is cleared before every row via `write_then_insert`, so a
/// caller passing a long-lived shared writer cannot leak bytes from a
/// prior emit into the first row, and an early `?` from any row cannot
/// leak into the next.
pub(crate) fn flush_staged_spills(
    segments_table: &mut Table<&[u8], &[u8]>,
    writer: &mut ergo_primitives::writer::VlqWriter,
    staged: &StagedSpills,
    deleted: &DeletedSpills,
) -> Result<(), IndexerError> {
    use crate::segment::write_segment;

    for (seg_id, seg) in staged {
        if deleted.contains(seg_id) {
            continue;
        }
        crate::apply::write_then_insert(
            segments_table,
            writer,
            seg_id.as_bytes().as_slice(),
            |w| {
                write_segment(w, seg);
                Ok(())
            },
        )?;
    }
    for seg_id in deleted {
        segments_table.remove(seg_id.as_bytes().as_slice())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_addr(seed: u8) -> IndexedAddress {
        IndexedAddress::empty(Digest32::from_bytes([seed; 32]))
    }

    // ----- happy path -----

    #[test]
    fn append_box_under_threshold_does_not_spill() {
        let mut addr = fresh_addr(0x01);
        let mut staged = StagedSpills::new();
        for i in 0..100 {
            append_box_entry(&addr.tree_hash, &mut addr.segment, i as i64, &mut staged);
        }
        assert_eq!(addr.segment.boxes.len(), 100);
        assert_eq!(addr.segment.box_segment_count, 0);
        assert!(staged.is_empty());
    }

    #[test]
    fn append_box_at_exactly_threshold_does_not_spill() {
        let mut addr = fresh_addr(0x02);
        let mut staged = StagedSpills::new();
        for i in 0..SEGMENT_THRESHOLD as i64 {
            append_box_entry(&addr.tree_hash, &mut addr.segment, i, &mut staged);
        }
        assert_eq!(addr.segment.boxes.len(), SEGMENT_THRESHOLD);
        assert_eq!(addr.segment.box_segment_count, 0);
        assert!(staged.is_empty());
    }

    #[test]
    fn append_box_one_above_threshold_spills_oldest_512() {
        let mut addr = fresh_addr(0x03);
        let mut staged = StagedSpills::new();
        for i in 0..(SEGMENT_THRESHOLD as i64 + 1) {
            append_box_entry(&addr.tree_hash, &mut addr.segment, i, &mut staged);
        }
        // Head retains the newest one; spill 0 carries 0..512.
        assert_eq!(addr.segment.boxes, vec![SEGMENT_THRESHOLD as i64]);
        assert_eq!(addr.segment.box_segment_count, 1);
        let spill_id = box_segment_id(&addr.tree_hash, 0);
        let spill = staged.get(&spill_id).unwrap();
        assert_eq!(spill.boxes.len(), SEGMENT_THRESHOLD);
        assert_eq!(spill.boxes.first(), Some(&0));
        assert_eq!(spill.boxes.last(), Some(&(SEGMENT_THRESHOLD as i64 - 1)));
    }

    #[test]
    fn append_box_can_spill_multiple_times_in_one_call_chain() {
        let mut addr = fresh_addr(0x04);
        let mut staged = StagedSpills::new();
        // 1025 entries: spill 0 at 513 (drain 512, head=[512]), spill 1
        // at 1025 (drain 512, head=[1024]).
        let total = SEGMENT_THRESHOLD as i64 * 2 + 1;
        for i in 0..total {
            append_box_entry(&addr.tree_hash, &mut addr.segment, i, &mut staged);
        }
        assert_eq!(addr.segment.box_segment_count, 2);
        assert_eq!(addr.segment.boxes, vec![total - 1]);

        let spill0 = staged.get(&box_segment_id(&addr.tree_hash, 0)).unwrap();
        let spill1 = staged.get(&box_segment_id(&addr.tree_hash, 1)).unwrap();
        assert_eq!(spill0.boxes.len(), SEGMENT_THRESHOLD);
        assert_eq!(spill1.boxes.len(), SEGMENT_THRESHOLD);
        assert_eq!(spill0.boxes[0], 0);
        assert_eq!(spill1.boxes[0], SEGMENT_THRESHOLD as i64);
    }

    #[test]
    fn append_tx_uses_tx_segment_id_not_box_segment_id() {
        // Tx and box spills must collide-free at the same segment number.
        let mut addr = fresh_addr(0x05);
        let mut staged = StagedSpills::new();
        for i in 0..(SEGMENT_THRESHOLD as i64 + 1) {
            append_tx_entry(&mut addr, i, &mut staged);
        }
        let tx_seg_id = tx_segment_id(&addr.tree_hash, 0);
        let box_seg_id = box_segment_id(&addr.tree_hash, 0);
        assert!(staged.contains_key(&tx_seg_id));
        assert!(!staged.contains_key(&box_seg_id));
    }

    #[test]
    fn pop_box_after_append_returns_to_empty_segment() {
        let mut addr = fresh_addr(0x06);
        let mut staged = StagedSpills::new();
        let mut deleted = DeletedSpills::new();
        // Stand-in segments table — pop should never need to read on
        // this codepath because all entries live in the head buffer.
        // We rely on the fact that this test never triggers
        // merge-back, so the table reference is unused.
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        for i in 0..50_i64 {
            append_box_entry(&addr.tree_hash, &mut addr.segment, i, &mut staged);
        }
        for i in (0..50_i64).rev() {
            let popped = pop_box_entry(
                &addr.tree_hash,
                &mut addr.segment,
                &mut staged,
                &mut deleted,
                &segments_table,
            )
            .unwrap();
            assert_eq!(popped, i);
        }
        assert!(addr.segment.boxes.is_empty());
        assert_eq!(addr.segment.box_segment_count, 0);
    }

    #[test]
    fn pop_box_underflows_into_merge_back_from_staged_spill() {
        let mut addr = fresh_addr(0x07);
        let mut staged = StagedSpills::new();
        let mut deleted = DeletedSpills::new();
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        // 513 appends: spill 0 holds 0..512, head holds [512].
        for i in 0..(SEGMENT_THRESHOLD as i64 + 1) {
            append_box_entry(&addr.tree_hash, &mut addr.segment, i, &mut staged);
        }
        // Pop newest first.
        let popped = pop_box_entry(
            &addr.tree_hash,
            &mut addr.segment,
            &mut staged,
            &mut deleted,
            &segments_table,
        )
        .unwrap();
        assert_eq!(popped, SEGMENT_THRESHOLD as i64);
        assert_eq!(addr.segment.box_segment_count, 1);
        assert!(addr.segment.boxes.is_empty());

        // Next pop must merge back the spill and pop its end.
        let popped = pop_box_entry(
            &addr.tree_hash,
            &mut addr.segment,
            &mut staged,
            &mut deleted,
            &segments_table,
        )
        .unwrap();
        assert_eq!(popped, SEGMENT_THRESHOLD as i64 - 1);
        assert_eq!(addr.segment.box_segment_count, 0);
        let merged_id = box_segment_id(&addr.tree_hash, 0);
        assert!(deleted.contains(&merged_id));
        assert_eq!(addr.segment.boxes.len(), SEGMENT_THRESHOLD - 1);
    }

    #[test]
    fn flip_in_head_negates_entry_in_place() {
        let mut addr = fresh_addr(0x08);
        let mut staged = StagedSpills::new();
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        append_box_entry(&addr.tree_hash, &mut addr.segment, 42, &mut staged);
        flip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            42,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        assert_eq!(addr.segment.boxes, vec![-42]);

        unflip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            42,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        assert_eq!(addr.segment.boxes, vec![42]);
    }

    #[test]
    fn flip_finds_entry_in_staged_spill() {
        let mut addr = fresh_addr(0x09);
        let mut staged = StagedSpills::new();
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        // Push 513 entries; spill 0 holds 0..512.
        for i in 0..(SEGMENT_THRESHOLD as i64 + 1) {
            append_box_entry(&addr.tree_hash, &mut addr.segment, i, &mut staged);
        }
        // Flip an entry that lives in the spill (not the head).
        flip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            100,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        let spill = staged.get(&box_segment_id(&addr.tree_hash, 0)).unwrap();
        assert_eq!(spill.boxes[100], -100);
        // Head untouched.
        assert_eq!(addr.segment.boxes, vec![SEGMENT_THRESHOLD as i64]);
    }

    #[test]
    fn flip_returns_error_when_only_negative_entries_remain() {
        // Single +entry, flipped once. A second flip has no positive
        // entries left to consume → not-found error (the new sign-aware
        // semantics replace the old "already negative" corruption check;
        // see flip_helper doc).
        let mut addr = fresh_addr(0x0A);
        let mut staged = StagedSpills::new();
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        append_box_entry(&addr.tree_hash, &mut addr.segment, 7, &mut staged);
        flip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            7,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        let err = flip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            7,
            &mut staged,
            &segments_table,
        )
        .unwrap_err();
        match err {
            IndexerError::SegmentTopologyError { detail } => assert!(
                detail.contains("entry exists but every copy is already negative")
                    && detail.contains("double-flip"),
                "got: {detail}"
            ),
            other => panic!("expected SegmentTopologyError, got {other:?}"),
        }
    }

    #[test]
    fn unflip_returns_error_when_only_positive_entries_remain() {
        let mut addr = fresh_addr(0x0B);
        let mut staged = StagedSpills::new();
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        append_box_entry(&addr.tree_hash, &mut addr.segment, 7, &mut staged);
        let err = unflip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            7,
            &mut staged,
            &segments_table,
        )
        .unwrap_err();
        match err {
            IndexerError::SegmentTopologyError { detail } => assert!(
                detail.contains("entry exists but every copy is already positive")
                    && detail.contains("double-flip"),
                "got: {detail}"
            ),
            other => panic!("expected SegmentTopologyError, got {other:?}"),
        }
    }

    #[test]
    fn flip_consumes_each_duplicate_entry_in_order() {
        // Mirrors the mainnet h=740,362 case: a box's `additionalTokens`
        // listed the same token id twice, so the create-side append
        // pushed `+gi` twice into the token's segment. The spend loop
        // calls flip twice with the same `gi`. With sign-aware matching
        // each call consumes one +gi, ending with `[-gi, -gi]` — same
        // segment shape Scala reaches (`Segment.scala:63-98`).
        let mut addr = fresh_addr(0x0E);
        let mut staged = StagedSpills::new();
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        append_box_entry(&addr.tree_hash, &mut addr.segment, 42, &mut staged);
        append_box_entry(&addr.tree_hash, &mut addr.segment, 42, &mut staged);
        assert_eq!(addr.segment.boxes, vec![42, 42]);

        flip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            42,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        assert_eq!(addr.segment.boxes, vec![-42, 42]);

        flip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            42,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        assert_eq!(addr.segment.boxes, vec![-42, -42]);
    }

    #[test]
    fn unflip_consumes_each_duplicate_entry_in_order() {
        // Inverse of flip_consumes_each_duplicate_entry_in_order: when
        // a block that spent a duplicate-token-id box is rolled back,
        // unflip is called once per duplicate entry and each call
        // restores one -gi to +gi.
        let mut addr = fresh_addr(0x0F);
        let mut staged = StagedSpills::new();
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        addr.segment.boxes = vec![-42, -42];

        unflip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            42,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        assert_eq!(addr.segment.boxes, vec![42, -42]);

        unflip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            42,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        assert_eq!(addr.segment.boxes, vec![42, 42]);
    }

    #[test]
    fn flip_at_global_index_zero_succeeds_as_silent_noop() {
        // gi=0 is the very first indexed box. -0 == 0, so the signed-flag
        // scheme cannot distinguish spent from unspent at that index;
        // Scala has the same limitation (`Segment.scala:63-98` —
        // `binarySearch(boxes, 0)` matches on abs value, then writes back
        // `-0 == 0`). We preserve Scala's silent-success behavior so the
        // genesis-box spend does not spuriously error in apply_block /
        // rollback.
        let mut addr = fresh_addr(0x10);
        let mut staged = StagedSpills::new();
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        append_box_entry(&addr.tree_hash, &mut addr.segment, 0, &mut staged);
        flip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            0,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        // `-0 == 0`, so the entry is unchanged.
        assert_eq!(addr.segment.boxes, vec![0]);

        unflip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            0,
            &mut staged,
            &segments_table,
        )
        .unwrap();
        assert_eq!(addr.segment.boxes, vec![0]);
    }

    #[test]
    fn flip_returns_error_when_target_not_in_any_segment() {
        let mut addr = fresh_addr(0x0C);
        let mut staged = StagedSpills::new();
        let store = open_segments_test_store();
        let read_txn = store.0.begin_write().unwrap();
        let segments_table = read_txn.open_table(crate::store::tables::SEGMENTS).unwrap();

        append_box_entry(&addr.tree_hash, &mut addr.segment, 1, &mut staged);
        let err = flip_box_segment_entry(
            &addr.tree_hash,
            &mut addr.segment,
            999,
            &mut staged,
            &segments_table,
        )
        .unwrap_err();
        match err {
            IndexerError::SegmentTopologyError { detail } => assert!(
                detail.contains("topology drift") && detail.contains("no positive entry found"),
                "got: {detail}"
            ),
            other => panic!("expected SegmentTopologyError, got {other:?}"),
        }
    }

    /// Open a fresh `IndexerStore` for tests that need access to a
    /// `Table<&[u8], &[u8]>` over `SEGMENTS`. The returned `TempDir`
    /// must outlive the store; tests bind it as `_tmp` so it stays in
    /// scope.
    fn open_segments_test_store() -> (crate::store::IndexerStore, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("indexer.redb");
        let (store, _) = crate::store::IndexerStore::open(&path).unwrap();
        (store, tmp)
    }

    /// The apply/rollback spill hot path enforces the same
    /// trailing-bytes guard the public `store::segment::read_spill_in`
    /// reader uses. Without it a malformed spill row would be silently
    /// normalised by mutation.
    #[test]
    fn read_spill_from_table_rejects_trailing_bytes() {
        use crate::segment::write_segment;
        use crate::store::tables::SEGMENTS;
        use crate::IndexerError;
        use ergo_primitives::writer::VlqWriter;
        use redb::Database;

        let tmp = tempfile::TempDir::new().unwrap();
        let db = Database::create(tmp.path().join("spill_hotpath.redb")).unwrap();

        let seg_id = Digest32::from_bytes([0x77; 32]);
        let mut w = VlqWriter::new();
        write_segment(
            &mut w,
            &Segment {
                txs: vec![],
                boxes: vec![],
                box_segment_count: 0,
                tx_segment_count: 0,
            },
        );
        let mut corrupted = w.result();
        corrupted.extend_from_slice(&[0xAA, 0xBB]);

        let wtxn = db.begin_write().unwrap();
        {
            let mut table = wtxn.open_table(SEGMENTS).unwrap();
            table
                .insert(seg_id.as_bytes().as_slice(), corrupted.as_slice())
                .unwrap();
            let result = read_spill_from_table(&table, &seg_id);
            assert!(
                matches!(
                    result,
                    Err(IndexerError::DbRowLength {
                        context: "segment",
                        ..
                    })
                ),
                "spill hot path must reject trailing bytes, got {result:?}",
            );
        }
    }
}

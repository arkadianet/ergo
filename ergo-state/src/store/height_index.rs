//! [`super::HEADERS_BY_HEIGHT`] / `HEADER_CHAIN_INDEX` height-index
//! rewrite helpers.
//!
//! Sibling of `mod.rs`; pure impl relocation. Free functions operating
//! on borrowed redb tables inside a caller-owned write transaction, so
//! the index rewrites commit atomically with the chain-state advance
//! that triggered them.

use redb::ReadableTable;

use super::StateError;

/// Rewrite HEADER_CHAIN_INDEX to reflect a new best-header chain tip.
///
/// Walks backward from (new_best_id, new_best_height) through HEADER_META.
/// Stops at the fork point: the highest height where the existing index
/// entry already matches the walked id. Deletes stale entries above it
/// (up to max(old_best_height, new_best_height)), then inserts the
/// new-chain entries.
///
/// For a strict extension (new id's parent == previous best id, height +1),
/// Read every header id stored at `height` in
/// [`HEADERS_BY_HEIGHT`]. Returns `Ok(vec![])` when the row is
/// absent. First entry is the best-chain id by invariant; subsequent
/// entries are orphans (validated headers at this height that aren't
/// on the current best chain).
///
/// Generic over the redb table type so both read-only and write
/// paths can share the parsing logic — `ReadableTable` covers
/// `redb::Table<'txn, ...>` AND `redb::ReadOnlyTable<...>`.
pub(crate) fn read_height_index_ids<T>(idx: &T, height: u32) -> Result<Vec<[u8; 32]>, StateError>
where
    T: redb::ReadableTable<u64, &'static [u8]>,
{
    match idx.get(height as u64)? {
        Some(guard) => {
            let bytes = guard.value();
            if !bytes.len().is_multiple_of(32) {
                return Err(StateError::DbCorruption {
                    table: "headers_by_height",
                    key: hex::encode((height as u64).to_be_bytes()),
                    reason: format!("row has len {} (must be a multiple of 32)", bytes.len()),
                });
            }
            let mut out = Vec::with_capacity(bytes.len() / 32);
            for chunk in bytes.chunks_exact(32) {
                let mut id = [0u8; 32];
                id.copy_from_slice(chunk);
                out.push(id);
            }
            Ok(out)
        }
        None => Ok(Vec::new()),
    }
}

/// Append `header_id` to [`HEADERS_BY_HEIGHT`] at `height` if not
/// already present. Mirrors Scala's `orphanedBlockHeaderIdsRow`
/// behaviour at `HeadersProcessor.scala:203-206`: existing ids stay
/// in place, the new id lands at the end of the row. Idempotent —
/// re-calling with the same `(height, header_id)` is a no-op.
///
/// Caller path: `store_validated_header` when `new_best.is_none()`
/// (an orphan/fork header that didn't beat the current best score).
pub(crate) fn append_orphan_to_height_index<'txn>(
    idx: &mut redb::Table<'txn, u64, &'static [u8]>,
    height: u32,
    header_id: &[u8; 32],
) -> Result<(), StateError> {
    let existing = read_height_index_ids(idx, height)?;
    if existing.iter().any(|id| id == header_id) {
        return Ok(());
    }
    let mut payload = Vec::with_capacity(existing.len() * 32 + 32);
    for id in &existing {
        payload.extend_from_slice(id);
    }
    payload.extend_from_slice(header_id);
    idx.insert(height as u64, payload.as_slice())?;
    Ok(())
}

/// Promote `header_id` to slot 0 of [`HEADERS_BY_HEIGHT`] at
/// `height`. If the row already starts with `header_id`, returns
/// without writing. Otherwise rewrites the row with `header_id` at
/// slot 0 and any other ids (including a possibly-different prior
/// slot 0) demoted to later slots — preserving their relative
/// order.
///
/// Per-height, no walk. The callers that need to rewrite an entire
/// chain ([`rewrite_height_index_for_new_best`]) walk by
/// `parent_id` and invoke this helper once per height. Callers
/// with a non-contiguous chain (NiPoPoW proof apply with its sparse
/// prefix) loop over their own header set and call this directly.
pub(crate) fn promote_to_height_index_slot_0<'txn>(
    idx: &mut redb::Table<'txn, u64, &'static [u8]>,
    height: u32,
    header_id: &[u8; 32],
) -> Result<(), StateError> {
    let existing = read_height_index_ids(idx, height)?;
    if existing.first() == Some(header_id) {
        return Ok(());
    }
    let mut payload = Vec::with_capacity((existing.len() + 1) * 32);
    payload.extend_from_slice(header_id);
    for id in &existing {
        if id != header_id {
            payload.extend_from_slice(id);
        }
    }
    idx.insert(height as u64, payload.as_slice())?;
    Ok(())
}

/// Walk back from `new_best_id` and, for every height on the new
/// best chain back to the fork point, rewrite the
/// [`HEADERS_BY_HEIGHT`] row so the new-best id occupies the first
/// slot. Any ids already in the row that aren't the new best stay,
/// shifted down — they're now orphans at that height. Mirrors
/// Scala's `bestBlockHeaderIdsRow` + fork-chain rewrite at
/// `HeadersProcessor.scala:212-226`.
///
/// Stops walking when the existing row's first entry already
/// equals `cur_id` (fork point reached) or when height drops to 1
/// (genesis boundary). HEADER_META must hold the meta for every
/// walked id; caller is responsible for that (matches the
/// precondition on [`rewrite_best_chain_into_index`]).
///
/// **Only safe for chains where `parent.height + 1 == child.height`**
/// — i.e. the validated-header path
/// ([`StateStore::store_validated_header`]) and the flush path
/// ([`StateStore::flush_header_batch`]). Callers with a sparse
/// chain (NiPoPoW proof apply) MUST iterate their own header set
/// and call [`promote_to_height_index_slot_0`] directly.
pub(crate) fn rewrite_height_index_for_new_best<'txn>(
    idx: &mut redb::Table<'txn, u64, &'static [u8]>,
    meta: &redb::Table<'txn, &'static [u8], &'static [u8]>,
    new_best_id: [u8; 32],
    new_best_height: u32,
) -> Result<(), StateError> {
    use crate::chain::HeaderMeta;

    let mut cur_id = new_best_id;
    let mut cur_height = new_best_height;

    loop {
        // Validate HEADER_META for the current walked id FIRST — before writing
        // the height row or taking the early return — matching
        // `rewrite_best_chain_into_index`. Otherwise a corrupt parent-chain
        // could promote an id under the wrong height, or the genesis boundary
        // (cur_height == 1) could return without ever validating its metadata.
        let meta_guard = meta.get(cur_id.as_slice())?.ok_or_else(|| {
            // The lookup is `meta.get(cur_id)` — the row missing is
            // the current walked id's own HEADER_META row, reached
            // by following its predecessor's `parent_id`. Cross-table
            // inconsistency between the chain's parent-pointer graph
            // and HEADER_META.
            StateError::DbCorruption {
                table: "header_meta",
                key: hex::encode(cur_id),
                reason: "rewrite_height_index_for_new_best: row missing during walk".to_string(),
            }
        })?;
        let m =
            HeaderMeta::deserialize(meta_guard.value()).map_err(|e| StateError::DbCorruption {
                table: "header_meta",
                key: hex::encode(cur_id),
                reason: e.to_string(),
            })?;
        drop(meta_guard);
        if m.height != cur_height {
            // HEADER_META.height disagrees with the height the walk arrived at.
            return Err(StateError::DbCorruption {
                table: "header_meta",
                key: hex::encode(cur_id),
                reason: format!(
                    "rewrite_height_index_for_new_best: height mismatch (expected \
                     {cur_height}, HEADER_META says {})",
                    m.height,
                ),
            });
        }

        let existing = read_height_index_ids(idx, cur_height)?;
        if existing.first() == Some(&cur_id) {
            return Ok(());
        }
        promote_to_height_index_slot_0(idx, cur_height, &cur_id)?;

        if cur_height == 1 {
            return Ok(());
        }

        cur_id = m.parent_id;
        cur_height = cur_height.saturating_sub(1);
    }
}

/// the walk is length 1 with no deletions. For a fork flip, the walk
/// unwinds to the shared ancestor and the old tail is deleted.
///
/// HEADER_META must already contain the meta for new_best_id AND all
/// ancestors up to the fork point — this is the caller's responsibility.
pub(crate) fn rewrite_best_chain_into_index<'txn>(
    idx: &mut redb::Table<'txn, u64, &'static [u8]>,
    meta: &redb::Table<'txn, &'static [u8], &'static [u8]>,
    new_best_id: [u8; 32],
    new_best_height: u32,
    old_best_height: u32,
) -> Result<(), StateError> {
    use crate::chain::HeaderMeta;

    let mut walked: Vec<(u32, [u8; 32])> = Vec::new();
    let mut cur_id = new_best_id;
    let mut cur_height = new_best_height;
    let fork_point: u32;

    loop {
        // Validate HEADER_META for the current walked id FIRST, before any
        // fork-point decision. This makes "every walked height validated
        // against HEADER_META" a true invariant — including the fork-point
        // height itself and the genesis boundary (cur_height == 1). The
        // cost is one extra meta read per call on the fork-point row,
        // which is fine for a storage-boundary guard.
        let current_guard = meta.get(cur_id.as_slice())?.ok_or_else(|| {
            // Storage-boundary guard: the chain-walk pointer arrived
            // at an id that HEADER_META doesn't know about. Caller
            // contract (this fn's docstring) says HEADER_META must
            // contain new_best_id + every ancestor to the fork point;
            // a miss here is cross-table inconsistency.
            StateError::DbCorruption {
                table: "header_meta",
                key: hex::encode(cur_id),
                reason: "rewrite_best_chain_into_index: row missing during walk".to_string(),
            }
        })?;
        let current_meta = HeaderMeta::deserialize(current_guard.value()).map_err(|e| {
            StateError::DbCorruption {
                table: "header_meta",
                key: hex::encode(cur_id),
                reason: e.to_string(),
            }
        })?;
        drop(current_guard);
        if current_meta.height != cur_height {
            // HEADER_META.height disagrees with the height the walk
            // arrived at — writer wrote an inconsistent row.
            return Err(StateError::DbCorruption {
                table: "header_meta",
                key: hex::encode(cur_id),
                reason: format!(
                    "rewrite_best_chain_into_index: height mismatch (expected {cur_height}, \
                     HEADER_META says {})",
                    current_meta.height,
                ),
            });
        }

        let existing_guard = idx.get(cur_height as u64)?;
        let already_matches = existing_guard
            .as_ref()
            .map(|g| g.value() == cur_id.as_slice())
            .unwrap_or(false);
        drop(existing_guard);

        if already_matches {
            fork_point = cur_height;
            break;
        }

        walked.push((cur_height, cur_id));
        if cur_height == 1 {
            fork_point = 0;
            break;
        }

        cur_id = current_meta.parent_id;
        cur_height -= 1;
    }

    let upper = old_best_height.max(new_best_height);
    for h in (fork_point + 1)..=upper {
        idx.remove(h as u64)?;
    }
    for &(h, id) in walked.iter().rev() {
        idx.insert(h as u64, id.as_slice())?;
    }
    Ok(())
}

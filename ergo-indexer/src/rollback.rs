//! Per-block rollback for boxes + txs — inverse of `apply_block`.
//!
//! Inverts `apply_block` by walking the rolled-back block's
//! transactions in reverse and undoing each apply step:
//!
//! - each output's `IndexedErgoBox` + `NUMERIC_BOX` entry is removed;
//! - each input's `spending_tx_id` / `spending_height` /
//!   `spending_proof` is cleared on the spent box record (the box
//!   record's `global_index` stays positive, so there is nothing to
//!   "flip back");
//! - the tx record + `NUMERIC_TX` entry are removed;
//! - per touched address, the `BalanceInfo` decrements/increments
//!   applied by the original block are reversed;
//! - per touched address, the box-segment append (per output) is undone
//!   via `pop_box_entry`, and the box-segment sign-flip (per input) is
//!   undone via `unflip_box_segment_entry`. Spill merge-back fires when
//!   a pop underflows the head buffer;
//! - per touched address per tx, the tx-segment append is undone via
//!   `pop_tx_entry`;
//! - meta is restored from the `UndoEntry` snapshot and the undo entry
//!   itself is deleted.
//!
//! Genesis (height == 1) skips the input-clear pass, mirroring the
//! `apply_block` skip per `ExtraIndexer.scala:318`.
//!
//! Atomicity: meta restore + per-row deletes + undo removal all live
//! in a single redb `WriteTransaction`. On any error we drop the txn
//! (no commit), so on-disk state stays exactly as it was before the
//! call.

use std::collections::{HashMap, HashSet};

use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::transaction_id;
use redb::ReadableTable;
use tracing::{info, warn};

use crate::address::IndexedAddress;
use crate::apply::{candidate_token_deltas, flush_addresses, load_address_into_map, IndexerBlock};
use crate::error::{BoxMissingContext, IndexerError};
use crate::segment_buffer::{
    flush_staged_spills, pop_box_entry, pop_tx_entry, tolerate_secondary_drift,
    unflip_box_segment_entry, DeletedSpills, StagedSpills,
};
use crate::segment_id::{token_unique_id, tree_hash_from_bytes};
use crate::ser::boxes::{deserialize_indexed_box, serialize_indexed_box};
use crate::ser::txs::deserialize_indexed_tx;
use crate::store::storage_rent::{
    insert_unspent as storage_rent_insert, remove_unspent as storage_rent_remove,
    UNSPENT_BY_CREATION_HEIGHT,
};
use crate::store::tables::{
    INDEXED_ADDRESS, INDEXED_BOX, INDEXED_TEMPLATE, INDEXED_TOKEN, INDEXED_TX, INDEXER_UNDO,
    NUMERIC_BOX, NUMERIC_TX, SEGMENTS,
};
use crate::store::{meta as meta_io, undo::UndoEntry, IndexerMeta, IndexerStore};
use crate::template::{
    flush_templates, load_template_into_map, template_hash_for_box_bytes, IndexedTemplate,
};
use crate::token::{flush_tokens, is_mint, try_load_token_into_map, IndexedToken};
use ergo_indexer_types::{is_protocol_genesis_box, IndexedErgoBox, TokenId};

/// Roll back the indexer's current tip block.
///
/// Caller responsibilities:
/// - `meta.indexed_height > 0` (cannot roll back below genesis);
/// - `block.height == meta.indexed_height` (we roll back exactly the
///   block whose meta-mirror is on disk);
/// - `Some(block.header_id) == meta.indexed_header_id` (the block bytes
///   the caller fetched match the applied tip — guards against a
///   chain-side reorg racing with our rollback).
///
/// Returns the post-rollback `IndexerMeta` on success.
pub fn rollback_one_block(
    store: &IndexerStore,
    meta: &IndexerMeta,
    block: &IndexerBlock<'_>,
) -> Result<IndexerMeta, IndexerError> {
    if meta.indexed_height == 0 {
        return Err(IndexerError::NothingToRollback { height: 0 });
    }

    let height_u64 = meta.indexed_height;
    if (block.height as u64) != height_u64 {
        return Err(IndexerError::HeightMismatch {
            expected: height_u64,
            got: block.height as u64,
        });
    }
    if Some(block.header_id) != meta.indexed_header_id {
        let expected_hex = meta
            .indexed_header_id
            .map(|h| hex::encode(h.as_bytes()))
            .unwrap_or_default();
        return Err(IndexerError::HeaderMismatch {
            expected: expected_hex,
            got: hex::encode(block.header_id.as_bytes()),
            height: height_u64,
        });
    }

    // Capture identity fields before any mutation so the `_failed`
    // event below carries the pre-attempt values, never rebuilt-state
    // values. Per the Codex supervisor plan for this phase.
    let header_id_hex = hex::encode(block.header_id.as_bytes());
    info!(
        event = "indexer_rollback_started",
        from_height = height_u64,
        header_id = %header_id_hex,
        "indexer rollback started",
    );

    let block_height = block.height;
    let result: Result<IndexerMeta, IndexerError> =
        rollback_one_block_inner(store, block, height_u64, block_height);

    match &result {
        Ok(new_meta) => {
            // Emit `_completed` only after the inner function's
            // commit succeeded — `Ok` is returned downstream of
            // `write_txn.commit()`.
            info!(
                event = "indexer_rollback_completed",
                from_height = height_u64,
                header_id = %header_id_hex,
                new_indexed_height = new_meta.indexed_height,
                "indexer rollback completed",
            );
        }
        Err(e) => {
            warn!(
                event = "indexer_rollback_failed",
                from_height = height_u64,
                header_id = %header_id_hex,
                error = %e,
                "indexer rollback failed",
            );
        }
    }

    result
}

/// Body of [`rollback_one_block`], factored out so the caller can wrap
/// it in start/complete/failed observability events without changing
/// the inner control flow. Pure refactor — every `?` and early return
/// behaves identically to the pre-split function.
fn rollback_one_block_inner(
    store: &IndexerStore,
    block: &IndexerBlock<'_>,
    height_u64: u64,
    block_height: i32,
) -> Result<IndexerMeta, IndexerError> {
    let write_txn = store.begin_write()?;
    // Mirror apply: set if any secondary unflip is skipped on a drift, flushed
    // to the sticky repair marker before commit.
    let mut secondary_skipped = false;

    // Read + remove the undo entry up front. If it's missing the chain
    // already rejects the reorg as too deep, so failing loudly here
    // mirrors that contract.
    let undo_entry: UndoEntry = {
        let mut undo_table = write_txn.open_table(INDEXER_UNDO)?;
        let guard = undo_table
            .get(height_u64)?
            .ok_or(IndexerError::UndoMissing(height_u64))?;
        let entry = UndoEntry::decode(guard.value())?;
        drop(guard);
        undo_table.remove(height_u64)?;
        entry
    };

    let mut touched_addresses: HashMap<Digest32, IndexedAddress> = HashMap::new();
    let mut touched_templates: HashMap<Digest32, IndexedTemplate> = HashMap::new();
    let mut touched_tokens: HashMap<TokenId, IndexedToken> = HashMap::new();
    // Token ids whose mint contributions were fully reversed in this
    // block. After all per-tx work, any such token whose segment is
    // now empty (no head boxes, no spill segments) must be deleted from
    // INDEXED_TOKEN — the mint that originally created the record was
    // in the rolled-back block. Built up across txs; consumed at flush.
    let mut mint_reversed_in_block: HashSet<TokenId> = HashSet::new();
    let mut staged_spills: StagedSpills = HashMap::new();
    let mut deleted_spills: DeletedSpills = HashSet::new();

    {
        let mut box_table = write_txn.open_table(INDEXED_BOX)?;
        let mut tx_table = write_txn.open_table(INDEXED_TX)?;
        let mut num_box_table = write_txn.open_table(NUMERIC_BOX)?;
        let mut num_tx_table = write_txn.open_table(NUMERIC_TX)?;
        let mut addr_table = write_txn.open_table(INDEXED_ADDRESS)?;
        let mut template_table = write_txn.open_table(INDEXED_TEMPLATE)?;
        let mut token_table = write_txn.open_table(INDEXED_TOKEN)?;
        let mut segments_table = write_txn.open_table(SEGMENTS)?;
        // Storage-rent eligibility index inverse (spec
        // `2026-05-01-storage-rent-eligibility.md` §4.2). Symmetric to
        // apply: deletes on output rollback (the output's row created
        // during apply is removed) and inserts on input rollback (the
        // unspent state of the consumed box is restored). All values
        // are derived from the unchanged `IndexedErgoBox` rows; the
        // `INDEXER_UNDO` payload is deliberately not extended (spec §7
        // O1).
        let mut storage_rent_table = write_txn.open_table(UNSPENT_BY_CREATION_HEIGHT)?;

        for tx in block.transactions.iter().rev() {
            let tx_id: Digest32 = *transaction_id(tx)
                .map_err(|e| IndexerError::HashDerivation {
                    context: "rollback_one_block: tx_id",
                    source: e,
                })?
                .as_digest();

            // Mirror apply.rs's per-tx touched set: each tree_hash that
            // got a tx-segment append needs exactly one tx-segment pop
            // in the inverse.
            let mut tx_touched_order: Vec<Digest32> = Vec::new();
            let mut tx_touched_seen: HashSet<Digest32> = HashSet::new();

            // Recompute the per-tx EIP-4 input_tokens accumulator that
            // apply.rs built up incrementally during step 1. Mint
            // detection in apply only fired for outputs whose tokenId
            // was NOT in this set, so the rollback inverse needs the
            // same set to identify which output tokens to reverse.
            // Genesis (height == 1) had no input processing in apply,
            // so input_tokens is empty there too.
            let input_tokens: HashSet<TokenId> = if block_height > 1 {
                let mut set = HashSet::new();
                for input in &tx.inputs {
                    let existing_opt: Option<IndexedErgoBox> = {
                        let raw = box_table.get(input.box_id.as_bytes().as_slice())?;
                        raw.map(|g| deserialize_indexed_box(g.value()))
                            .transpose()
                            .map_err(|e| IndexerError::DbDecode {
                                context: "indexed_box",
                                source: e,
                            })?
                    };
                    let Some(existing) = existing_opt else {
                        // Same protocol-genesis bypass as the spend
                        // step below: those 3 IDs were never inserted
                        // into `box_table`, so they contribute no token
                        // ids to the EIP-4 mint-detection set.
                        if is_protocol_genesis_box(input.box_id.as_bytes()) {
                            continue;
                        }
                        return Err(IndexerError::BoxMissing {
                            box_id: hex::encode(input.box_id.as_bytes()),
                            height: height_u64,
                            context: BoxMissingContext::RollbackInputTokens,
                        });
                    };
                    for t in &existing.box_data.candidate.tokens {
                        set.insert(t.token_id);
                    }
                }
                set
            } else {
                HashSet::new()
            };

            // Step 1 (inverse): remove outputs in reverse creation order.
            for (i, candidate) in tx.output_candidates.iter().enumerate().rev() {
                let sealed = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id.into(),
                    index: i as u16,
                };
                let box_id = sealed.box_id().map_err(|e| IndexerError::HashDerivation {
                    context: "rollback_one_block: box_id",
                    source: e,
                })?;
                let raw = box_table
                    .get(box_id.as_bytes().as_slice())?
                    .ok_or_else(|| IndexerError::BoxMissing {
                        box_id: hex::encode(box_id.as_bytes()),
                        height: height_u64,
                        context: BoxMissingContext::RollbackOutput,
                    })?;
                let existing =
                    deserialize_indexed_box(raw.value()).map_err(|e| IndexerError::DbDecode {
                        context: "indexed_box",
                        source: e,
                    })?;
                drop(raw);
                let owner_tree_hash =
                    tree_hash_from_bytes(existing.box_data.candidate.ergo_tree_bytes());
                let value_delta = existing.box_data.candidate.value as i64;
                let token_deltas = candidate_token_deltas(&existing.box_data.candidate);
                let global_index = existing.global_index;
                box_table.remove(box_id.as_bytes().as_slice())?;
                let num_key = (global_index as u64).to_be_bytes();
                num_box_table.remove(num_key.as_slice())?;
                // Storage-rent eligibility delete (inverse of apply
                // step 2's insert). Same compound key the original
                // insert used: the box's own `creationHeight` plus its
                // immutable `global_box_index`.
                storage_rent_remove(
                    &mut storage_rent_table,
                    existing.box_data.candidate.creation_height,
                    global_index,
                )?;

                // Inverse of apply step 2's `add_box` + `append_box_entry`.
                let addr =
                    load_address_into_map(&addr_table, &mut touched_addresses, owner_tree_hash)?;
                addr.balance
                    .as_mut()
                    .ok_or_else(|| IndexerError::AddressBalanceMissing {
                        tree_hash: hex::encode(owner_tree_hash.as_bytes()),
                    })?
                    .subtract_box(value_delta, &token_deltas);
                let popped = pop_box_entry(
                    &addr.tree_hash,
                    &mut addr.segment,
                    &mut staged_spills,
                    &mut deleted_spills,
                    &segments_table,
                )?;
                if popped != global_index {
                    return Err(IndexerError::SegmentTopologyError {
                        detail: format!(
                            "rollback_one_block: box-segment pop mismatch for {}: expected {global_index}, got {popped}",
                            hex::encode(owner_tree_hash.as_bytes()),
                        ),
                    });
                }

                if let Some(template_hash) =
                    template_hash_for_box_bytes(existing.box_data.candidate.ergo_tree_bytes())?
                {
                    let template = load_template_into_map(
                        &template_table,
                        &mut touched_templates,
                        template_hash,
                    )?;
                    let popped_template = pop_box_entry(
                        &template.template_hash,
                        &mut template.segment,
                        &mut staged_spills,
                        &mut deleted_spills,
                        &segments_table,
                    )?;
                    if popped_template != global_index {
                        return Err(IndexerError::SegmentTopologyError {
                            detail: format!(
                                "rollback_one_block: template box-segment pop mismatch for {}: expected {global_index}, got {popped_template}",
                                hex::encode(template_hash.as_bytes()),
                            ),
                        });
                    }
                }

                // Token box-segment rollback (mirror of apply step 2's
                // per-output token segment append). For every token
                // that this output carried, pop one entry from the
                // token's box-segment. Skips tokens whose record
                // doesn't exist (matches apply's `try_load` skip path).
                for token in &existing.box_data.candidate.tokens {
                    if let Some(record) =
                        try_load_token_into_map(&token_table, &mut touched_tokens, token.token_id)?
                    {
                        let parent_id = token_unique_id(&record.token_id);
                        let popped_token = pop_box_entry(
                            &parent_id,
                            &mut record.segment,
                            &mut staged_spills,
                            &mut deleted_spills,
                            &segments_table,
                        )?;
                        if popped_token != global_index {
                            return Err(IndexerError::SegmentTopologyError {
                                detail: format!(
                                    "rollback_one_block: token box-segment pop mismatch for {}: expected {global_index}, got {popped_token}",
                                    hex::encode(token.token_id.as_bytes()),
                                ),
                            });
                        }
                    }
                }

                // EIP-4 mint reversal (mirror of apply step 2's per-tx
                // mint detection). For every minted token in this
                // output, subtract this output's contribution from the
                // record's emission_amount. Marks the token id for
                // post-flush deletion review — if all of this block's
                // mint contributions reverse and the segment is now
                // empty, the record was created by the rolled-back
                // block and must be removed.
                let first_input_box_id_opt = tx.inputs.first().map(|i| i.box_id);
                for token in &existing.box_data.candidate.tokens {
                    if let Some(first_input_box_id) = first_input_box_id_opt {
                        if is_mint(&token.token_id, &first_input_box_id, &input_tokens) {
                            let record = touched_tokens.get_mut(&token.token_id).ok_or_else(|| {
                                IndexerError::SegmentTopologyError {
                                    detail: format!(
                                        "rollback_one_block: mint reversal: token {} missing from touched_tokens map (segment-pop pass should have loaded it)",
                                        hex::encode(token.token_id.as_bytes()),
                                    ),
                                }
                            })?;
                            let current = record.emission_amount.unwrap_or(0);
                            record.emission_amount = Some(current.saturating_sub(token.amount));
                            mint_reversed_in_block.insert(token.token_id);
                        }
                    }
                }

                if tx_touched_seen.insert(owner_tree_hash) {
                    tx_touched_order.push(owner_tree_hash);
                }
            }

            // Step 2 (inverse): clear spending fields on inputs.
            // Genesis (height == 1) had no input lookup in apply, so
            // mirror that and skip on rollback too.
            if block_height > 1 {
                for input in tx.inputs.iter().rev() {
                    let existing_opt: Option<IndexedErgoBox> = {
                        let raw = box_table.get(input.box_id.as_bytes().as_slice())?;
                        raw.map(|g| deserialize_indexed_box(g.value()))
                            .transpose()
                            .map_err(|e| IndexerError::DbDecode {
                                context: "indexed_box",
                                source: e,
                            })?
                    };
                    let Some(mut existing) = existing_opt else {
                        // Mirror apply's protocol-genesis bypass: those
                        // 3 IDs are never inserted into `box_table`, so
                        // their spend on apply was a no-op and the
                        // matching rollback must be a no-op too.
                        if is_protocol_genesis_box(input.box_id.as_bytes()) {
                            continue;
                        }
                        return Err(IndexerError::BoxMissing {
                            box_id: hex::encode(input.box_id.as_bytes()),
                            height: height_u64,
                            context: BoxMissingContext::RollbackInput,
                        });
                    };
                    let owner_tree_hash =
                        tree_hash_from_bytes(existing.box_data.candidate.ergo_tree_bytes());
                    let value_delta = existing.box_data.candidate.value as i64;
                    let token_deltas = candidate_token_deltas(&existing.box_data.candidate);
                    let spent_global_index = existing.global_index;
                    existing.spending_tx_id = None;
                    existing.spending_height = None;
                    existing.spending_proof = None;
                    let bytes =
                        serialize_indexed_box(&existing).map_err(|e| IndexerError::DbDecode {
                            context: "indexed_box encode",
                            source: e,
                        })?;
                    box_table.insert(input.box_id.as_bytes().as_slice(), bytes.as_slice())?;
                    // Storage-rent eligibility re-insert (inverse of
                    // apply step 1's delete). The 5-tuple
                    // `(creationHeight, box_id, global_box_index,
                    // box_value, box_bytes_len)` is reconstructed
                    // entirely from the in-hand `existing`
                    // `IndexedErgoBox` — no `INDEXER_UNDO` payload
                    // extension required (spec §7 O1).
                    let restored_bytes = ergo_ser::ergo_box::serialize_ergo_box(&existing.box_data)
                        .map_err(|e| IndexerError::Serialize {
                            context: "serialize_ergo_box for storage_rent",
                            source: e,
                        })?;
                    let restored_bytes_len: i32 =
                        i32::try_from(restored_bytes.len()).map_err(|_| {
                            IndexerError::LengthExceedsI32 {
                                context: "serialized_box",
                                len: restored_bytes.len(),
                            }
                        })?;
                    storage_rent_insert(
                        &mut storage_rent_table,
                        existing.box_data.candidate.creation_height,
                        spent_global_index,
                        &input.box_id,
                        existing.box_data.candidate.value,
                        restored_bytes_len,
                    )?;

                    // Inverse of apply step 1's `subtract_box` + `flip_box_segment_entry`.
                    let addr = load_address_into_map(
                        &addr_table,
                        &mut touched_addresses,
                        owner_tree_hash,
                    )?;
                    addr.balance
                        .as_mut()
                        .ok_or_else(|| IndexerError::AddressBalanceMissing {
                            tree_hash: hex::encode(owner_tree_hash.as_bytes()),
                        })?
                        .add_box(value_delta, &token_deltas);
                    unflip_box_segment_entry(
                        &addr.tree_hash,
                        &mut addr.segment,
                        spent_global_index,
                        &mut staged_spills,
                        &segments_table,
                    )?;

                    if let Some(template_hash) =
                        template_hash_for_box_bytes(existing.box_data.candidate.ergo_tree_bytes())?
                    {
                        let template = load_template_into_map(
                            &template_table,
                            &mut touched_templates,
                            template_hash,
                        )?;
                        // Secondary index — mirror the apply-side
                        // degrade-not-halt: if the apply skipped this
                        // template's flip on a drift gap, the rollback unflip
                        // would otherwise halt here; tolerate it the same way.
                        let unflip = unflip_box_segment_entry(
                            &template.template_hash,
                            &mut template.segment,
                            spent_global_index,
                            &mut staged_spills,
                            &segments_table,
                        );
                        if tolerate_secondary_drift(
                            "template",
                            &template.template_hash,
                            spent_global_index,
                            unflip,
                        )? {
                            secondary_skipped = true;
                        }
                    }

                    // Token box-segment sign-flip rollback (mirror of
                    // apply step 1's per-token flip on spend). For each
                    // token the spent box carried, flip the entry from
                    // -gi back to +gi.
                    for token in &existing.box_data.candidate.tokens {
                        if let Some(record) = try_load_token_into_map(
                            &token_table,
                            &mut touched_tokens,
                            token.token_id,
                        )? {
                            let parent_id = token_unique_id(&record.token_id);
                            // Secondary index — degrade-not-halt on drift.
                            let unflip = unflip_box_segment_entry(
                                &parent_id,
                                &mut record.segment,
                                spent_global_index,
                                &mut staged_spills,
                                &segments_table,
                            );
                            if tolerate_secondary_drift(
                                "token",
                                &parent_id,
                                spent_global_index,
                                unflip,
                            )? {
                                secondary_skipped = true;
                            }
                        }
                    }

                    if tx_touched_seen.insert(owner_tree_hash) {
                        tx_touched_order.push(owner_tree_hash);
                    }
                }
            }

            // Step 3 (inverse): pop tx-segment entry from each touched
            // address, then remove tx record + NUMERIC_TX entry.
            let raw_tx = tx_table.get(tx_id.as_bytes().as_slice())?.ok_or_else(|| {
                IndexerError::TxMissing {
                    tx_id: hex::encode(tx_id.as_bytes()),
                    height: height_u64,
                }
            })?;
            let existing_tx =
                deserialize_indexed_tx(raw_tx.value()).map_err(|e| IndexerError::DbDecode {
                    context: "indexed_tx",
                    source: e,
                })?;
            drop(raw_tx);
            let tx_global = existing_tx.global_index;

            for tree_hash in tx_touched_order.iter().rev() {
                let addr = touched_addresses.get_mut(tree_hash).ok_or_else(|| {
                    IndexerError::SegmentTopologyError {
                        detail: format!(
                            "rollback_one_block: tx-segment pop: missing touched address {}",
                            hex::encode(tree_hash.as_bytes()),
                        ),
                    }
                })?;
                let popped = pop_tx_entry(
                    addr,
                    &mut staged_spills,
                    &mut deleted_spills,
                    &segments_table,
                )?;
                if popped != tx_global {
                    return Err(IndexerError::SegmentTopologyError {
                        detail: format!(
                            "rollback_one_block: tx-segment pop mismatch for {}: expected {tx_global}, got {popped}",
                            hex::encode(tree_hash.as_bytes()),
                        ),
                    });
                }
            }

            tx_table.remove(tx_id.as_bytes().as_slice())?;
            let num_key = (tx_global as u64).to_be_bytes();
            num_tx_table.remove(num_key.as_slice())?;
        }

        // One short-lived writer reused across all four flush passes —
        // every row clears it via `write_then_insert` before emit, so
        // the writer's prior contents (or stale bytes from an earlier
        // row's `?`) cannot leak into the next row.
        let mut writer = VlqWriter::new();
        flush_addresses(&mut addr_table, &mut writer, &touched_addresses)?;
        flush_templates(&mut template_table, &mut writer, &touched_templates)?;

        // Tokens whose mint contributions were fully reversed in this
        // block AND whose segment is now empty must be deleted — the
        // mint that created the record was in the rolled-back block.
        // Token records that still hold segment entries (from earlier
        // blocks) are preserved.
        let mut tokens_to_remove: HashSet<TokenId> = HashSet::new();
        for token_id in &mint_reversed_in_block {
            if let Some(record) = touched_tokens.get(token_id) {
                if record.segment.boxes.is_empty() && record.segment.box_segment_count == 0 {
                    tokens_to_remove.insert(*token_id);
                }
            }
        }
        flush_tokens(
            &mut token_table,
            &mut writer,
            &touched_tokens,
            &tokens_to_remove,
        )?;

        flush_staged_spills(
            &mut segments_table,
            &mut writer,
            &staged_spills,
            &deleted_spills,
        )?;
    }

    let next = IndexerMeta {
        indexed_height: height_u64 - 1,
        indexed_header_id: undo_entry.prev_indexed_header_id,
        global_tx_index: undo_entry.prev_global_tx_index,
        global_box_index: undo_entry.prev_global_box_index,
    };
    meta_io::write_meta(&write_txn, &next)?;
    if secondary_skipped {
        meta_io::set_secondary_repair_pending(&write_txn)?;
    }

    write_txn.commit()?;

    Ok(next)
}

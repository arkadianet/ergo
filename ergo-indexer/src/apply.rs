//! Per-block apply for boxes + txs.
//!
//! Writes one IndexedErgoBox per output, one IndexedErgoTransaction
//! per tx, and the matching `NUMERIC_BOX` / `NUMERIC_TX` entries.
//! Spends existing IndexedErgoBox records by stamping
//! spending_tx_id / spending_height / spending_proof — `global_index`
//! on the box record stays positive.
//!
//! Address-side accounting:
//! per touched output, increment the owner address's `BalanceInfo`
//! (nano_ergs + per-token bundle) and append `+global_index` to the
//! address's box-segment head; per spent input, decrement
//! `BalanceInfo` (clamping nano_ergs at zero, dropping tokens at zero)
//! and flip the sign of the existing entry to negative. After all
//! input/output work, the tx's `global_tx_index` is appended once per
//! touched address to the address's tx-segment head. Spills cross
//! `SEGMENT_THRESHOLD` (512) and are staged in-memory then flushed to
//! `SEGMENTS` at the end of the inner scope.
//!
//! Atomicity: meta + per-row writes + undo + prune all live in a
//! single redb `WriteTransaction`. On any error we drop the txn (no
//! commit), so on-disk state stays exactly as it was before the call.

use std::collections::HashSet;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{box_id_with, ErgoBox, ErgoBoxCandidate};
use ergo_ser::transaction::{transaction_id_with, write_transaction, Transaction};
use redb::{ReadableTable, Table};
use std::collections::HashMap;

use crate::address::{read_indexed_address, write_indexed_address, IndexedAddress};
use crate::error::IndexerError;
use crate::scratch::BlockApplyScratch;
use crate::segment_buffer::{
    append_box_entry, append_tx_entry, flip_box_segment_entry, flush_staged_spills,
    tolerate_secondary_drift,
};
use crate::segment_id::{token_unique_id, tree_hash_from_bytes};
use crate::ser::boxes::{deserialize_indexed_box, write_indexed_box};
use crate::ser::txs::write_indexed_tx_parts;
use crate::store::storage_rent::{
    insert_unspent as storage_rent_insert, remove_unspent as storage_rent_remove,
    UNSPENT_BY_CREATION_HEIGHT,
};
use crate::store::tables::{
    INDEXED_ADDRESS, INDEXED_BOX, INDEXED_TEMPLATE, INDEXED_TOKEN, INDEXED_TX, NUMERIC_BOX,
    NUMERIC_TX, SEGMENTS,
};
use crate::store::{meta as meta_io, undo as undo_io, IndexerMeta, IndexerStore, UndoEntry};
use crate::template::{flush_templates, load_template_into_map, template_hash_for_box_bytes};
use crate::token::{
    flush_tokens, is_mint, load_token_into_map, try_load_token_into_map, IndexedToken,
};
use crate::HeaderId;
use ergo_indexer_types::{is_protocol_genesis_box, IndexedErgoBox, TokenId};

/// Caller-provided shape for `apply_block`. The polling task builds
/// this from the chain store's `BlockTransactions` plus the header
/// it was fetched against.
#[derive(Debug)]
pub struct IndexerBlock<'a> {
    pub height: i32,
    pub header_id: HeaderId,
    pub transactions: &'a [Transaction],
}

/// Centralizes the clear-before-emit contract for table writes that
/// share a long-lived `VlqWriter`. Clears `writer` at ENTRY, runs
/// `serialize` to fill it, then inserts the resulting bytes at `key`.
///
/// "Clear before, never clear after." A `?` from `serialize` or the
/// table insert returns early — but the next caller's clear (this
/// function, or a caller's explicit `clear()`) wipes any partial bytes
/// before they can leak into another row. Skipping the clear-after-
/// success path means an aborted apply cannot poison the next emit.
pub(crate) fn write_then_insert<F>(
    table: &mut Table<&[u8], &[u8]>,
    writer: &mut VlqWriter,
    key: &[u8],
    serialize: F,
) -> Result<(), IndexerError>
where
    F: FnOnce(&mut VlqWriter) -> Result<(), IndexerError>,
{
    writer.clear();
    serialize(writer)?;
    table.insert(key, writer.as_slice())?;
    Ok(())
}

/// Apply one block to the indexer DB.
///
/// Returns the post-apply `IndexerMeta` on success. The caller mirrors
/// `indexed_height` into `IndexerHandle::set_indexed_height` after the
/// commit returns.
///
/// Allocates a fresh `BlockApplyScratch` per call. The run-loop driver
/// (`IndexerTask`) holds a long-lived scratch and calls
/// `apply_block_with_scratch` instead — this entry point exists for
/// tests and one-shot callers that don't want to manage scratch state.
pub fn apply_block(
    store: &IndexerStore,
    meta: &IndexerMeta,
    block: &IndexerBlock<'_>,
) -> Result<IndexerMeta, IndexerError> {
    let mut scratch = BlockApplyScratch::new();
    apply_block_with_scratch(store, meta, block, &mut scratch)
}

/// Scratch-reuse variant of `apply_block`. Identical semantics; the
/// caller-owned `BlockApplyScratch` is fully cleared at entry, so any
/// state left by a prior aborted apply is wiped before this call's work
/// begins.
pub fn apply_block_with_scratch(
    store: &IndexerStore,
    meta: &IndexerMeta,
    block: &IndexerBlock<'_>,
    scratch: &mut BlockApplyScratch,
) -> Result<IndexerMeta, IndexerError> {
    let expected_next = meta.indexed_height + 1;
    if (block.height as u64) != expected_next {
        return Err(IndexerError::HeightMismatch {
            expected: expected_next,
            got: block.height as u64,
        });
    }

    let undo = UndoEntry {
        prev_indexed_header_id: meta.indexed_header_id,
        prev_global_tx_index: meta.global_tx_index,
        prev_global_box_index: meta.global_box_index,
    };

    let mut next = meta.clone();
    let block_height = block.height;
    let block_height_u64 = expected_next;

    // Reset all per-block + per-tx scratch unconditionally before any
    // table is touched. Any state from a prior aborted apply is wiped
    // here — never carries into a subsequent block.
    scratch.clear_block();

    // Apply doesn't delete spills (rollback does). Kept as a local
    // `&` parameter so `flush_staged_spills`'s shared signature stays
    // unchanged across the apply / rollback paths.
    let no_token_removals: HashSet<TokenId> = HashSet::new();

    let mut write_txn = store.begin_write()?;
    // Set when any secondary (template/token) sign-flip is skipped on a drift
    // this block; flushed to the sticky repair marker before commit so the task
    // rebuilds the degraded segments before next serving (atomic with apply).
    let mut secondary_skipped = false;
    // `indexer.redb` holds derived state — every row is reproducible by
    // replaying blocks from `state.redb`, which itself commits durably.
    // `Eventual` keeps the per-block redb txn atomic (meta + per-row writes
    // + undo + prune still all-or-nothing) but defers the fsync, letting
    // catchup amortize the syscall cost across many commits. Crash window:
    // OS-pagecache flush cadence; recovery: replay from chain tip.
    write_txn.set_durability(redb::Durability::Eventual);

    {
        let mut box_table = write_txn.open_table(INDEXED_BOX)?;
        let mut tx_table = write_txn.open_table(INDEXED_TX)?;
        let mut num_box_table = write_txn.open_table(NUMERIC_BOX)?;
        let mut num_tx_table = write_txn.open_table(NUMERIC_TX)?;
        let mut addr_table = write_txn.open_table(INDEXED_ADDRESS)?;
        let mut template_table = write_txn.open_table(INDEXED_TEMPLATE)?;
        let mut token_table = write_txn.open_table(INDEXED_TOKEN)?;
        let mut segments_table = write_txn.open_table(SEGMENTS)?;
        // Storage-rent eligibility index. Lazy-created on first
        // open — `WriteTransaction::open_table` is create-or-open
        // in redb 2.x, so fresh and post-wipe DBs both end up with
        // the table without an explicit `tables::create_all` entry.
        let mut storage_rent_table = write_txn.open_table(UNSPENT_BY_CREATION_HEIGHT)?;

        for (tx_index_in_block, tx) in block.transactions.iter().enumerate() {
            // Clear per-tx scratch unconditionally at loop entry. This
            // guarantees a legitimate first-output mint in tx-N is not
            // masked by token ids spent in tx-(N-1) of the same block,
            // and that the per-tx address-touched set never carries
            // entries from a prior tx.
            scratch.clear_tx();

            let tx_id: Digest32 = *transaction_id_with(&mut scratch.writer, tx)
                .map_err(|e| IndexerError::HashDerivation {
                    context: "apply_block: tx_id",
                    source: e,
                })?
                .as_digest();
            let tx_size = serialized_tx_size(tx)?;

            // Step 1: spend inputs (skip on genesis).
            if block_height > 1 {
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
                    let Some(mut existing) = existing_opt else {
                        // Match Scala `ExtraIndexer.scala:331` `log.warn`
                        // for the 3 protocol-genesis box IDs (foundation
                        // / no-premine / emission). They are seeded by
                        // the protocol before block 1 and are never
                        // present in `box_table`, so their first spend
                        // would otherwise terminate the indexer with
                        // `InputMissing`. Scala silently absorbs them
                        // and leaves the tx-record `inputs[i]` slot at
                        // its default 0 (Scala `Array.ofDim[Long]` —
                        // ExtraIndexer.scala:312); we mirror that by
                        // pushing 0 to `input_nums`. Real chain/indexer
                        // divergence still surfaces as `InputMissing`.
                        if is_protocol_genesis_box(input.box_id.as_bytes()) {
                            scratch.input_nums.push(0);
                            continue;
                        }
                        return Err(IndexerError::InputMissing {
                            box_id: hex::encode(input.box_id.as_bytes()),
                            height: block_height_u64,
                        });
                    };
                    let owner_tree_hash =
                        tree_hash_from_bytes(existing.box_data.candidate.ergo_tree_bytes());
                    let value_delta = existing.box_data.candidate.value as i64;
                    let token_deltas = candidate_token_deltas(&existing.box_data.candidate);
                    for t in &existing.box_data.candidate.tokens {
                        scratch.input_tokens.insert(t.token_id);
                    }
                    let spent_global_index = existing.global_index;
                    existing.spending_tx_id = Some(tx_id);
                    existing.spending_height = Some(block_height);
                    existing.spending_proof = Some(input.spending_proof.clone());
                    write_then_insert(
                        &mut box_table,
                        &mut scratch.writer,
                        input.box_id.as_bytes().as_slice(),
                        |w| {
                            write_indexed_box(w, &existing).map_err(|e| IndexerError::DbDecode {
                                context: "indexed_box encode",
                                source: e,
                            })
                        },
                    )?;
                    // The box leaves the unspent set, keyed by its
                    // own `creationHeight` (R3-related metadata
                    // stamped at creation time, NOT inclusion height)
                    // plus the immutable `global_box_index` assigned
                    // at apply.
                    storage_rent_remove(
                        &mut storage_rent_table,
                        existing.box_data.candidate.creation_height,
                        spent_global_index,
                    )?;
                    scratch.input_nums.push(spent_global_index);

                    let addr = load_address_into_map(
                        &addr_table,
                        &mut scratch.touched_addresses,
                        owner_tree_hash,
                    )?;
                    addr.balance
                        .as_mut()
                        .ok_or_else(|| IndexerError::AddressBalanceMissing {
                            tree_hash: hex::encode(owner_tree_hash.as_bytes()),
                        })?
                        .subtract_box(value_delta, &token_deltas);
                    flip_box_segment_entry(
                        &addr.tree_hash,
                        &mut addr.segment,
                        spent_global_index,
                        &mut scratch.staged_spills,
                        &segments_table,
                    )?;

                    if let Some(template_hash) =
                        template_hash_for_box_bytes(existing.box_data.candidate.ergo_tree_bytes())?
                    {
                        let template = load_template_into_map(
                            &template_table,
                            &mut scratch.touched_templates,
                            template_hash,
                        )?;
                        // Secondary index: a topology-drift gap degrades this
                        // template's box queries but must not halt the indexer
                        // (see `tolerate_secondary_drift`). All other errors
                        // still propagate.
                        let flip = flip_box_segment_entry(
                            &template.template_hash,
                            &mut template.segment,
                            spent_global_index,
                            &mut scratch.staged_spills,
                            &segments_table,
                        );
                        if tolerate_secondary_drift(
                            "template",
                            &template.template_hash,
                            spent_global_index,
                            flip,
                        )? {
                            secondary_skipped = true;
                        }
                    }

                    // Token box-segment sign-flip on spend: for each
                    // token the spent box carried,
                    // flip the matching token's box-segment entry from
                    // +gi to -gi. Skips tokens whose record doesn't
                    // exist (matches Scala's `findAndUpdateToken`
                    // empty-on-miss behavior — a chain-validated token
                    // should always have a record from its prior mint).
                    for token in &existing.box_data.candidate.tokens {
                        if let Some(record) = try_load_token_into_map(
                            &token_table,
                            &mut scratch.touched_tokens,
                            token.token_id,
                        )? {
                            let parent_id = token_unique_id(&record.token_id);
                            // Secondary index — degrade-not-halt on drift.
                            let flip = flip_box_segment_entry(
                                &parent_id,
                                &mut record.segment,
                                spent_global_index,
                                &mut scratch.staged_spills,
                                &segments_table,
                            );
                            if tolerate_secondary_drift(
                                "token",
                                &parent_id,
                                spent_global_index,
                                flip,
                            )? {
                                secondary_skipped = true;
                            }
                        }
                    }

                    if scratch.tx_touched_seen.insert(owner_tree_hash) {
                        scratch.tx_touched_order.push(owner_tree_hash);
                    }
                }
            }

            // Step 2: create outputs.
            for (i, candidate) in tx.output_candidates.iter().enumerate() {
                let owner_tree_hash = tree_hash_from_bytes(candidate.ergo_tree_bytes());
                let value_delta = candidate.value as i64;
                let token_deltas = candidate_token_deltas(candidate);
                let sealed = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id.into(),
                    index: i as u16,
                };
                let box_id = box_id_with(&mut scratch.writer, &sealed).map_err(|e| {
                    IndexerError::HashDerivation {
                        context: "apply_block: box_id",
                        source: e,
                    }
                })?;
                let global = next.global_box_index as i64;
                let indexed = IndexedErgoBox {
                    inclusion_height: block_height,
                    spending_tx_id: None,
                    spending_height: None,
                    spending_proof: None,
                    box_data: sealed,
                    global_index: global,
                };
                write_then_insert(
                    &mut box_table,
                    &mut scratch.writer,
                    box_id.as_bytes().as_slice(),
                    |w| {
                        write_indexed_box(w, &indexed).map_err(|e| IndexerError::DbDecode {
                            context: "indexed_box encode",
                            source: e,
                        })
                    },
                )?;
                let num_key = next.global_box_index.to_be_bytes();
                num_box_table.insert(num_key.as_slice(), box_id.as_bytes().as_slice())?;
                // The box enters the unspent set, keyed by its own
                // `creationHeight` and its immutable `global_box_index`.
                // `box_bytes_len` is the canonical serialized `ErgoBox`
                // length stored as `i32` so it composes directly with
                // the i32-typed `storage_fee_factor` voted parameter.
                // If the same block later spends this box, the
                // matching `remove_unspent` fires when the input is
                // processed by a subsequent transaction.
                let sealed_bytes = ergo_ser::ergo_box::serialize_ergo_box(&indexed.box_data)
                    .map_err(|e| IndexerError::Serialize {
                        context: "serialize_ergo_box for storage_rent",
                        source: e,
                    })?;
                let box_bytes_len: i32 = i32::try_from(sealed_bytes.len()).map_err(|_| {
                    IndexerError::LengthExceedsI32 {
                        context: "serialized_box",
                        len: sealed_bytes.len(),
                    }
                })?;
                storage_rent_insert(
                    &mut storage_rent_table,
                    candidate.creation_height,
                    global,
                    &box_id,
                    candidate.value,
                    box_bytes_len,
                )?;
                scratch.output_nums.push(global);
                next.global_box_index += 1;

                let addr = load_address_into_map(
                    &addr_table,
                    &mut scratch.touched_addresses,
                    owner_tree_hash,
                )?;
                addr.balance
                    .as_mut()
                    .ok_or_else(|| IndexerError::AddressBalanceMissing {
                        tree_hash: hex::encode(owner_tree_hash.as_bytes()),
                    })?
                    .add_box(value_delta, &token_deltas);
                append_box_entry(
                    &addr.tree_hash,
                    &mut addr.segment,
                    global,
                    &mut scratch.staged_spills,
                );

                if let Some(template_hash) =
                    template_hash_for_box_bytes(candidate.ergo_tree_bytes())?
                {
                    let template = load_template_into_map(
                        &template_table,
                        &mut scratch.touched_templates,
                        template_hash,
                    )?;
                    append_box_entry(
                        &template.template_hash,
                        &mut template.segment,
                        global,
                        &mut scratch.staged_spills,
                    );
                }

                // EIP-4 mint detection. For each token in
                // this output, if it satisfies the mint predicate,
                // upsert IndexedToken — first detection populates the
                // record from the emission box (R4/R5/R6 metadata),
                // second-and-later detections in the same tx call
                // `add_emission_amount` (multi-output mint case,
                // `ExtraIndexer.scala:355-357`).
                let first_input_box_id_opt = tx.inputs.first().map(|i| i.box_id);
                for token in &candidate.tokens {
                    if let Some(first_input_box_id) = first_input_box_id_opt {
                        if is_mint(&token.token_id, &first_input_box_id, &scratch.input_tokens) {
                            let record = load_token_into_map(
                                &token_table,
                                &mut scratch.touched_tokens,
                                token.token_id,
                            )?;
                            if record.creating_box_id.is_none() {
                                let fresh = IndexedToken::from_box(
                                    &box_id,
                                    token,
                                    &candidate.additional_registers,
                                );
                                record.creating_box_id = fresh.creating_box_id;
                                record.emission_amount = fresh.emission_amount;
                                record.name = fresh.name;
                                record.description = fresh.description;
                                record.decimals = fresh.decimals;
                            } else {
                                record.add_emission_amount(token.amount);
                            }
                        }
                    }
                }

                // Token box-segment maintenance — independent of
                // mint detection). For every token in this output —
                // mint or plain transfer — append the output's
                // global_box_index to the token's box-segment if a
                // record exists. Skips tokens with no record (the
                // chain-invariant says one should always exist via a
                // prior mint, but the skip path matches Scala's
                // `findAndUpdateToken` empty-on-miss behavior).
                for token in &candidate.tokens {
                    if let Some(record) = try_load_token_into_map(
                        &token_table,
                        &mut scratch.touched_tokens,
                        token.token_id,
                    )? {
                        let parent_id = token_unique_id(&record.token_id);
                        append_box_entry(
                            &parent_id,
                            &mut record.segment,
                            global,
                            &mut scratch.staged_spills,
                        );
                    }
                }

                if scratch.tx_touched_seen.insert(owner_tree_hash) {
                    scratch.tx_touched_order.push(owner_tree_hash);
                }
            }

            // Step 3: tx record + per-touched-address tx-segment append.
            let tx_global = next.global_tx_index as i64;
            scratch
                .data_inputs
                .extend(tx.data_inputs.iter().map(|di| di.box_id));

            // Pre-borrow disjoint scratch fields so the `write_then_insert`
            // closure captures only those references — capturing `scratch`
            // whole would conflict with the `&mut scratch.writer` argument.
            let tx_index_i32 = i32_from_usize(tx_index_in_block)?;
            let input_nums = &scratch.input_nums;
            let output_nums = &scratch.output_nums;
            let data_inputs = &scratch.data_inputs;
            write_then_insert(
                &mut tx_table,
                &mut scratch.writer,
                tx_id.as_bytes().as_slice(),
                |w| {
                    write_indexed_tx_parts(
                        w,
                        &tx_id,
                        tx_index_i32,
                        block_height,
                        tx_size,
                        tx_global,
                        input_nums,
                        output_nums,
                        data_inputs,
                    )
                    .map_err(|e| IndexerError::DbDecode {
                        context: "indexed_tx encode",
                        source: e,
                    })
                },
            )?;
            let num_key = next.global_tx_index.to_be_bytes();
            num_tx_table.insert(num_key.as_slice(), tx_id.as_bytes().as_slice())?;
            next.global_tx_index += 1;

            // Per-touched-address tx-segment append. Iterate by index to
            // avoid holding an immutable borrow on `scratch.tx_touched_order`
            // while reaching into `scratch.touched_addresses` /
            // `scratch.staged_spills` mutably.
            for i in 0..scratch.tx_touched_order.len() {
                let tree_hash = scratch.tx_touched_order[i];
                let addr = scratch
                    .touched_addresses
                    .get_mut(&tree_hash)
                    .ok_or_else(|| IndexerError::SegmentTopologyError {
                        detail: format!(
                            "apply_block: tx-segment append: missing touched address {}",
                            hex::encode(tree_hash.as_bytes()),
                        ),
                    })?;
                append_tx_entry(addr, tx_global, &mut scratch.staged_spills);
            }
        }

        flush_addresses(
            &mut addr_table,
            &mut scratch.writer,
            &scratch.touched_addresses,
        )?;
        flush_templates(
            &mut template_table,
            &mut scratch.writer,
            &scratch.touched_templates,
        )?;
        flush_tokens(
            &mut token_table,
            &mut scratch.writer,
            &scratch.touched_tokens,
            &no_token_removals,
        )?;
        flush_staged_spills(
            &mut segments_table,
            &mut scratch.writer,
            &scratch.staged_spills,
            &scratch.deleted_spills,
        )?;
    }

    next.indexed_height = block_height_u64;
    next.indexed_header_id = Some(block.header_id);

    meta_io::write_meta(&write_txn, &next)?;
    // A skipped secondary flip means the template/token index is now degraded;
    // persist the sticky repair marker in the SAME txn so it is durable iff this
    // block commits (and survives reorg meta-restore — see meta.rs).
    if secondary_skipped {
        meta_io::set_secondary_repair_pending(&write_txn)?;
    }
    undo_io::write_undo(&write_txn, block_height_u64, &undo)?;
    undo_io::prune_below_window(&write_txn, block_height_u64, store.rollback_window())?;

    write_txn.commit()?;

    Ok(next)
}

fn serialized_tx_size(tx: &Transaction) -> Result<i32, IndexerError> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, tx).map_err(|e| IndexerError::Serialize {
        context: "tx serialize",
        source: e,
    })?;
    let len = w.result().len();
    i32::try_from(len).map_err(|_| IndexerError::LengthExceedsI32 { context: "tx", len })
}

fn i32_from_usize(n: usize) -> Result<i32, IndexerError> {
    i32::try_from(n).map_err(|_| IndexerError::LengthExceedsI32 {
        context: "tx_index",
        len: n,
    })
}

/// Token amounts on chain are `u64`; the indexer's `BalanceInfo` stores
/// them as signed `i64` to match Scala's `Long` (`BalanceInfo.scala:18`).
/// In practice values are bounded well below `i64::MAX`, so the cast is
/// lossless.
pub(crate) fn candidate_token_deltas(c: &ErgoBoxCandidate) -> Vec<(Digest32, i64)> {
    c.tokens
        .iter()
        .map(|t| (t.token_id, t.amount as i64))
        .collect()
}

/// Lazy-load helper: on first touch of `tree_hash` in this block, read
/// the persisted `IndexedAddress` (or build an empty one if absent) and
/// stash it in `map`. Returns a mutable reference for in-place balance
/// edits. Subsequent touches skip the read.
pub(crate) fn load_address_into_map<'a>(
    addr_table: &Table<&[u8], &[u8]>,
    map: &'a mut HashMap<Digest32, IndexedAddress>,
    tree_hash: Digest32,
) -> Result<&'a mut IndexedAddress, IndexerError> {
    use std::collections::hash_map::Entry;
    match map.entry(tree_hash) {
        Entry::Occupied(e) => Ok(e.into_mut()),
        Entry::Vacant(e) => {
            let loaded = match addr_table.get(tree_hash.as_bytes().as_slice())? {
                Some(g) => {
                    let mut r = VlqReader::new(g.value());
                    let parsed =
                        read_indexed_address(&mut r).map_err(|err| IndexerError::DbDecode {
                            context: "indexed_address",
                            source: err,
                        })?;
                    if !r.is_empty() {
                        return Err(IndexerError::DbRowLength {
                            context: "indexed_address",
                            expected: r.position(),
                            got: g.value().len(),
                        });
                    }
                    parsed
                }
                None => IndexedAddress::empty(tree_hash),
            };
            Ok(e.insert(loaded))
        }
    }
}

/// Flush every touched `IndexedAddress` back to the table in a single
/// pass. Called once per block at the end of the apply / rollback inner
/// scope (so the borrow on `addr_table` is exclusive at write time).
///
/// `writer` is cleared before every row via `write_then_insert`, so a
/// caller passing a long-lived shared writer (apply's
/// `BlockApplyScratch.writer`) cannot leak bytes from a prior emit
/// into the first row, and an early `?` from any row cannot leak into
/// the next.
pub(crate) fn flush_addresses(
    addr_table: &mut Table<&[u8], &[u8]>,
    writer: &mut VlqWriter,
    map: &HashMap<Digest32, IndexedAddress>,
) -> Result<(), IndexerError> {
    for (tree_hash, addr) in map {
        write_then_insert(addr_table, writer, tree_hash.as_bytes().as_slice(), |w| {
            write_indexed_address(w, addr);
            Ok(())
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Stale-bleed coverage for `BlockApplyScratch`.
    //!
    //! Every test here exercises a multi-tx block and asserts that the
    //! per-tx fields are cleared at each tx loop entry — i.e. that the
    //! scratch reuse from one tx to the next never leaks state. The
    //! existing apply / rollback / corpus tests cover the per-block
    //! clear (every test that calls `apply_block` allocates a fresh
    //! scratch via the wrapper, then `clear_block` runs at entry).
    use super::*;
    use crate::{BoxId, IndexerStore};
    use ergo_indexer_types::PROTOCOL_GENESIS_BOX_IDS_MAINNET;
    use ergo_primitives::digest::Digest32;
    use ergo_primitives::writer::VlqWriter as Writer;
    use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::opcode::{Body, Expr};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use ergo_ser::token::Token;
    use ergo_ser::transaction::Transaction;
    use tempfile::TempDir;

    fn open_store() -> (IndexerStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("indexer.redb");
        let (store, _) = IndexerStore::open(&path).unwrap();
        (store, tmp)
    }

    fn tree_true() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            } as Body,
        }
    }

    fn tree_false() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: false,
            constants: vec![],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(false),
            } as Body,
        }
    }

    fn tree_hash_of(tree: &ErgoTree) -> Digest32 {
        let mut w = Writer::new();
        write_ergo_tree(&mut w, tree).unwrap();
        ergo_primitives::digest::blake2b256(&w.result())
    }

    fn proof_of(seed: u8) -> SpendingProof {
        SpendingProof::new(vec![seed; 4], ContextExtension::empty()).unwrap()
    }

    fn input_with(box_id: BoxId, seed: u8) -> Input {
        Input {
            box_id,
            spending_proof: proof_of(seed),
        }
    }

    fn fake_input(seed: u8) -> Input {
        input_with(BoxId::from_bytes([seed; 32]), seed)
    }

    fn cand_with(value: u64, tree: ErgoTree, height: u32, tokens: Vec<Token>) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(value, tree, height, tokens, AdditionalRegisters::empty()).unwrap()
    }

    fn sealed_box_id(tx: &Transaction, idx: u16) -> Digest32 {
        use ergo_ser::transaction::transaction_id;
        let tx_id = transaction_id(tx).unwrap();
        ErgoBox {
            candidate: tx.output_candidates[idx as usize].clone(),
            transaction_id: tx_id,
            index: idx,
        }
        .box_id()
        .unwrap()
    }

    /// If `scratch.input_tokens` bleeds from tx-0 to tx-1 of the same
    /// block, a legitimate first-output mint in tx-1 gets suppressed
    /// because `is_mint(token_id, first_input_box_id, &input_tokens)`
    /// requires `token_id ∉ input_tokens`. We exercise this by:
    ///
    /// 1. Setup block (height 1) mints token PG (id == one of the
    ///    protocol-genesis box ids), seeded amount 1000, output to a
    ///    box at a known address.
    /// 2. Test block (height 2):
    ///    - tx-0 spends the setup output. After step 1,
    ///      `input_tokens` = {PG}.
    ///    - tx-1's first input is the protocol-genesis box PG (apply
    ///      absorbs it, but `tx.inputs.first()` still yields PG for
    ///      mint detection). tx-1's first output carries token PG with
    ///      amount 500.
    ///
    /// `is_mint(PG, PG, ∅)` is true → record's `add_emission_amount`
    /// fires → final emission_amount = 1500. With bleed,
    /// `is_mint(PG, PG, {PG})` is false → emission stays at 1000.
    #[test]
    fn multi_tx_block_input_tokens_does_not_bleed_between_txs() {
        let (store, _tmp) = open_store();

        let pg_bytes = PROTOCOL_GENESIS_BOX_IDS_MAINNET[0];
        let pg_token_id: TokenId = Digest32::from_bytes(pg_bytes);
        let pg_box_id: BoxId = Digest32::from_bytes(pg_bytes);

        let setup_tx = Transaction {
            inputs: vec![input_with(pg_box_id, 0xAA)],
            data_inputs: vec![],
            output_candidates: vec![cand_with(
                1_000_000,
                tree_true(),
                1,
                vec![Token {
                    token_id: pg_token_id,
                    amount: 1000,
                }],
            )],
        };
        let setup_block = IndexerBlock {
            height: 1,
            header_id: Digest32::from_bytes([0x11; 32]),
            transactions: std::slice::from_ref(&setup_tx),
        };
        let meta1 = apply_block(&store, &IndexerMeta::empty(), &setup_block).unwrap();

        // Sanity: setup mint should populate the token record at amount 1000.
        let after_setup = store
            .read_token(&pg_token_id)
            .unwrap()
            .expect("setup mint must populate IndexedToken");
        assert_eq!(after_setup.emission_amount, Some(1000));

        let setup_box_id = sealed_box_id(&setup_tx, 0);

        let tx0 = Transaction {
            inputs: vec![input_with(setup_box_id, 0xCC)],
            data_inputs: vec![],
            // Plain transfer output — no tokens, no mint.
            output_candidates: vec![cand_with(900_000, tree_true(), 2, vec![])],
        };
        let tx1 = Transaction {
            // First input is the protocol-genesis box. apply absorbs
            // it (input_nums.push(0); continue) but `tx.inputs.first()`
            // still yields PG, which is the predicate's
            // `first_input_box_id`.
            inputs: vec![input_with(pg_box_id, 0xDD)],
            data_inputs: vec![],
            output_candidates: vec![cand_with(
                1_000,
                tree_true(),
                2,
                vec![Token {
                    token_id: pg_token_id,
                    amount: 500,
                }],
            )],
        };
        let block2 = IndexerBlock {
            height: 2,
            header_id: Digest32::from_bytes([0x22; 32]),
            transactions: &[tx0, tx1],
        };
        apply_block(&store, &meta1, &block2).unwrap();

        let final_record = store
            .read_token(&pg_token_id)
            .unwrap()
            .expect("token record must persist");
        assert_eq!(
            final_record.emission_amount,
            Some(1500),
            "tx-1's mint must fire because input_tokens was cleared at tx loop entry; \
             a stale {{PG}} from tx-0 would suppress is_mint and leave emission at 1000",
        );
    }

    /// If `scratch.tx_touched_seen` / `tx_touched_order` bleeds from
    /// tx-0 to tx-1 of the same block, addresses that tx-0 alone
    /// touched would still appear in tx-1's tx-segment append loop and
    /// erroneously gain tx-1's `global_tx_index`.
    ///
    /// Construction: 2-tx genesis block.
    ///  - tx-0 outputs to address A AND address B.
    ///  - tx-1 outputs to address A only.
    ///
    /// Without bleed, B's tx-segment ends at `[0]` (only tx-0).
    /// With bleed, tx_touched_order still contains B at the start of
    /// tx-1's step 3, so B picks up `1` and ends at `[0, 1]`.
    #[test]
    fn multi_tx_block_tx_touched_does_not_bleed_between_txs() {
        let (store, _tmp) = open_store();

        let tree_a = tree_true();
        let tree_b = tree_false();
        let hash_a = tree_hash_of(&tree_a);
        let hash_b = tree_hash_of(&tree_b);

        let tx0 = Transaction {
            inputs: vec![fake_input(0xAA)],
            data_inputs: vec![],
            output_candidates: vec![
                cand_with(1_000_000, tree_a.clone(), 1, vec![]),
                cand_with(1_000_000, tree_b.clone(), 1, vec![]),
            ],
        };
        let tx1 = Transaction {
            inputs: vec![fake_input(0xBB)],
            data_inputs: vec![],
            output_candidates: vec![cand_with(2_000_000, tree_a.clone(), 1, vec![])],
        };
        let block = IndexerBlock {
            height: 1,
            header_id: Digest32::from_bytes([0x42; 32]),
            transactions: &[tx0, tx1],
        };
        apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

        let txs_a = store
            .read_address_tx_entries(&hash_a)
            .unwrap()
            .expect("address A must have tx entries");
        let txs_b = store
            .read_address_tx_entries(&hash_b)
            .unwrap()
            .expect("address B must have tx entries");

        assert_eq!(txs_a, vec![0, 1], "address A is touched by tx-0 and tx-1");
        assert_eq!(
            txs_b,
            vec![0],
            "address B is touched only by tx-0 — a tx_touched bleed from tx-0 \
             into tx-1 would erroneously append tx-1's global_tx_index here",
        );
    }

    /// Reusing one `BlockApplyScratch` across two `apply_block_with_scratch`
    /// calls must produce byte-identical store state to the wrapper-path
    /// (fresh scratch per call). This pins the `clear_block` contract:
    /// no per-block field can leak from block N into block N+1.
    #[test]
    fn cross_block_scratch_reuse_matches_fresh_scratch() {
        // Build a small two-block fixture: genesis with 2 txs (one
        // mint, one transfer), then a tx that spends one of the
        // outputs.
        let pg_bytes = PROTOCOL_GENESIS_BOX_IDS_MAINNET[1];
        let mint_id: TokenId = Digest32::from_bytes(pg_bytes);
        let mint_input_box: BoxId = Digest32::from_bytes(pg_bytes);

        let g_tx0 = Transaction {
            inputs: vec![input_with(mint_input_box, 0x10)],
            data_inputs: vec![],
            output_candidates: vec![cand_with(
                500_000,
                tree_true(),
                1,
                vec![Token {
                    token_id: mint_id,
                    amount: 100,
                }],
            )],
        };
        let g_tx1 = Transaction {
            inputs: vec![fake_input(0x20)],
            data_inputs: vec![],
            output_candidates: vec![cand_with(750_000, tree_false(), 1, vec![])],
        };
        let genesis = IndexerBlock {
            height: 1,
            header_id: Digest32::from_bytes([0x31; 32]),
            transactions: &[g_tx0.clone(), g_tx1.clone()],
        };
        let g_box = sealed_box_id(&g_tx0, 0);

        let h2_tx = Transaction {
            inputs: vec![input_with(g_box, 0x30)],
            data_inputs: vec![],
            output_candidates: vec![cand_with(400_000, tree_true(), 2, vec![])],
        };
        let h2 = IndexerBlock {
            height: 2,
            header_id: Digest32::from_bytes([0x32; 32]),
            transactions: std::slice::from_ref(&h2_tx),
        };

        // Path A: wrapper-path, fresh scratch each call.
        let (store_a, _t_a) = open_store();
        let m1 = apply_block(&store_a, &IndexerMeta::empty(), &genesis).unwrap();
        let m2_a = apply_block(&store_a, &m1, &h2).unwrap();

        // Path B: long-lived scratch reused across both blocks.
        let (store_b, _t_b) = open_store();
        let mut scratch = BlockApplyScratch::new();
        let m1_b =
            apply_block_with_scratch(&store_b, &IndexerMeta::empty(), &genesis, &mut scratch)
                .unwrap();

        // Inject a stale touched-address that no real apply produces.
        // If `clear_block` is skipped, the next apply's
        // `flush_addresses` walks this entry and writes the bogus row
        // to disk. With the contract honored, `clear_block` wipes it
        // before any flush runs.
        let stale_hash = Digest32::from_bytes([0xEF; 32]);
        scratch
            .touched_addresses
            .insert(stale_hash, IndexedAddress::empty(stale_hash));

        let m2_b = apply_block_with_scratch(&store_b, &m1_b, &h2, &mut scratch).unwrap();

        assert!(
            store_b.read_address(&stale_hash).unwrap().is_none(),
            "clear_block must wipe scratch.touched_addresses at apply entry — \
             the injected stale row would otherwise be flushed",
        );
        assert_eq!(m2_a, m2_b, "post-apply meta must match across paths");

        // Spot-check: token record, address tx entries, spent box.
        let tok_a = store_a.read_token(&mint_id).unwrap().unwrap();
        let tok_b = store_b.read_token(&mint_id).unwrap().unwrap();
        assert_eq!(tok_a, tok_b);

        let hash_true = tree_hash_of(&tree_true());
        let txs_a = store_a.read_address_tx_entries(&hash_true).unwrap();
        let txs_b = store_b.read_address_tx_entries(&hash_true).unwrap();
        assert_eq!(txs_a, txs_b);

        let spent_a = store_a.read_box(&g_box).unwrap();
        let spent_b = store_b.read_box(&g_box).unwrap();
        assert_eq!(spent_a, spent_b);
    }

    // ----- error paths -----

    /// The apply / rollback hot path reads `INDEXED_ADDRESS` rows via
    /// `read_indexed_address` directly, then enforces the same
    /// trailing-bytes guard the public `store::address::read_address_in`
    /// reader uses. Without this EOF check, a malformed row could be
    /// loaded, mutated, and written back clean — masking persistence
    /// corruption.
    #[test]
    fn load_address_into_map_rejects_trailing_bytes() {
        use crate::address::write_indexed_address;
        use crate::store::tables::INDEXED_ADDRESS;
        use ergo_primitives::writer::VlqWriter as Writer;
        use redb::Database;

        let tmp = TempDir::new().unwrap();
        let db = Database::create(tmp.path().join("hotpath_addr.redb")).unwrap();

        let tree_hash = Digest32::from_bytes([0xAB; 32]);
        let mut w = Writer::new();
        write_indexed_address(&mut w, &IndexedAddress::empty(tree_hash));
        let mut corrupted = w.result();
        corrupted.extend_from_slice(&[0xFF, 0xFF, 0xFF]);

        let wtxn = db.begin_write().unwrap();
        {
            let mut table = wtxn.open_table(INDEXED_ADDRESS).unwrap();
            table
                .insert(tree_hash.as_bytes().as_slice(), corrupted.as_slice())
                .unwrap();
            let mut map = std::collections::HashMap::new();
            let result = load_address_into_map(&table, &mut map, tree_hash);
            assert!(
                matches!(
                    result,
                    Err(IndexerError::DbRowLength {
                        context: "indexed_address",
                        ..
                    })
                ),
                "hot path must reject trailing bytes via DbRowLength, got {result:?}",
            );
        }
        // drop wtxn without commit — the corrupted row stays in-test
    }
}

//! Per-event `ProcessorCtx` construction (spec 6.2, 6.5, 7.5).
//!
//! The processor reads no chain state of its own: every per-event fact it
//! needs arrives in a [`ProcessorCtx`], whose closure fields borrow. A
//! closure cannot outlive the expression that builds it, so this module
//! splits the job in two: [`CtxData`] owns (or borrows the store for) the
//! data, and [`CtxData::with`] hands a borrowed `ProcessorCtx` to a
//! callback — the same shape `ergo_inputblocks::test_support::TestCtx`
//! uses.

use std::collections::HashMap;

use ergo_crypto::difficulty::{
    epoch_length_for_height, next_n_bits, previous_heights_for_recalculation,
};
use ergo_inputblocks::processor::{Body, ProcessorCtx};
use ergo_inputblocks::types::{OrderingId, TxRef};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use ergo_ser::transaction::read_transaction;
use ergo_ser::weak_id::{weak_id_of, witness_id, WeakId};
use ergo_state::{ChainStateRead, HeaderSectionStore, StateBackendKind};

use super::super::NodeState;

/// Weak-id → bodies snapshot of the mempool, taken once per event.
///
/// A snapshot rather than a live `&Mempool` borrow: the effect executor
/// holds `&mut NodeState` while it drives the processor, and the
/// processor's `mempool_lookup` closure must not alias it. Cost is one
/// pass over the pool (parse + weak id per entry) per event; acceptable
/// at M2's devnet-only scale, and the obvious thing to make incremental
/// later (a weak-id index maintained by admission).
pub(in crate::node) type WeakIndex = HashMap<WeakId, Vec<Body>>;

/// Owned per-event inputs for a [`ProcessorCtx`], plus a borrow of the
/// store for the lookups that cannot be precomputed.
pub(in crate::node) struct CtxData<'a> {
    multiplier: Option<i32>,
    full_block_height: u32,
    utxo_mode: bool,
    weak_index: WeakIndex,
    /// Expected `nBits` per announced parent, precomputed for the parent
    /// ids the caller knew about. A miss falls through to
    /// [`expected_n_bits_after_store`] against `store`.
    expected: HashMap<[u8; 32], Option<u32>>,
    store: &'a StateBackendKind,
}

impl CtxData<'_> {
    /// Run `f` with a borrowed [`ProcessorCtx`] over this data.
    ///
    /// Not the brief's `as_ctx(&self) -> ProcessorCtx<'_>`: `ProcessorCtx`
    /// holds `&dyn Fn`, and a closure built inside `as_ctx` is a temporary
    /// that cannot be returned by reference. The callback shape is the
    /// only borrow-safe form, and is what the processor's own test harness
    /// uses.
    pub(in crate::node) fn with<R>(&self, f: impl FnOnce(&ProcessorCtx<'_>) -> R) -> R {
        let mempool_lookup = |w: &WeakId| self.weak_index.get(w).cloned().unwrap_or_default();
        let expected_n_bits = |parent: &[u8; 32]| match self.expected.get(parent) {
            Some(v) => *v,
            None => expected_n_bits_after_store(self.store, parent),
        };
        let block_transactions_known = |id: &OrderingId| block_transactions_known(self.store, id);
        let ctx = ProcessorCtx {
            multiplier: self.multiplier,
            expected_n_bits: &expected_n_bits,
            mempool_lookup: &mempool_lookup,
            utxo_mode: self.utxo_mode,
            full_block_height: self.full_block_height,
            block_transactions_known: &block_transactions_known,
        };
        f(&ctx)
    }
}

/// Build the per-event context data.
///
/// `parent_ids` are the ordering-block parents named by the event being
/// handled (an announcement's `header.parent_id`); their expected `nBits`
/// is precomputed so the hot path does not re-read headers per closure
/// call. Passing an empty slice is always correct — the closure falls back
/// to an on-demand store read.
pub(in crate::node) fn build_ctx_data<'a>(
    state: &'a NodeState,
    parent_ids: &[[u8; 32]],
) -> CtxData<'a> {
    let mut expected = HashMap::with_capacity(parent_ids.len());
    for id in parent_ids {
        expected.insert(*id, expected_n_bits_after_store(&state.store, id));
    }
    CtxData {
        // Spec 6.5: the CURRENT state's parameters, never the announced
        // parent's epoch. `last_seen_active_params` is the action loop's
        // mirror of `store.active_params()`, refreshed on every tip
        // change before any input-block event is handled.
        multiplier: state.last_seen_active_params.subblocks_per_block,
        full_block_height: state.store.chain_state_meta().best_full_block_height,
        utxo_mode: state.store.as_utxo().is_some(),
        weak_index: build_weak_index(state),
        expected,
        store: &state.store,
    }
}

/// One pass over the pool, indexing every entry by its weak id.
fn build_weak_index(state: &NodeState) -> WeakIndex {
    let mut index: WeakIndex = HashMap::new();
    for entry in state.mempool.iter_transactions() {
        let mut r = VlqReader::new(&entry.bytes);
        let tx = match read_transaction(&mut r) {
            Ok(tx) => tx,
            Err(err) => {
                // The bytes came from a successful admission, so a parse
                // failure here means the row no longer decodes — worth a
                // diagnostic, but the lookup contract is "skip".
                tracing::warn!(tx_id = ?entry.tx_id, error = ?err, "input_blocks: pooled entry does not decode, skipping");
                continue;
            }
        };
        let weak = match weak_id_of(&tx) {
            Ok(w) => w,
            Err(err) => {
                tracing::warn!(tx_id = ?entry.tx_id, error = ?err, "input_blocks: pooled entry has no weak id, skipping");
                continue;
            }
        };
        let wid = witness_id(&tx);
        index.entry(weak).or_default().push(Body {
            tx_ref: TxRef {
                tx_id: *entry.tx_id.as_bytes(),
                witness_id: wid,
            },
            weak_id: weak,
            bytes: entry.bytes.clone(),
            tx,
        });
    }
    index
}

/// Spec 6.2: `encode_compact(required_difficulty_after(parent))`, or
/// `None` when the parent header is unknown (parity with Scala, which
/// only checks `nBits` for a known parent).
pub(in crate::node) fn expected_n_bits_after(
    state: &NodeState,
    parent_id: &[u8; 32],
) -> Option<u32> {
    expected_n_bits_after_store(&state.store, parent_id)
}

fn read_stored_header(store: &StateBackendKind, id: &[u8; 32]) -> Option<Header> {
    let bytes = store.get_header(id).ok().flatten()?;
    let mut r = VlqReader::new(&bytes);
    read_header(&mut r).ok()
}

fn expected_n_bits_after_store(store: &StateBackendKind, parent_id: &[u8; 32]) -> Option<u32> {
    let parent = read_stored_header(store, parent_id)?;
    // The difficulty schedule is the network's, installed on the store at
    // boot (`set_difficulty_params`). A digest backend keeps no such
    // schedule — and cannot run input blocks anyway (`utxo_mode`), so the
    // check degrades to "parent unknown" rather than guessing mainnet.
    let params = store.as_utxo()?.difficulty_params().clone();
    let child_height = parent.height.checked_add(1)?;
    let epoch = epoch_length_for_height(child_height, &params);
    let needed = previous_heights_for_recalculation(child_height, epoch);
    let mut headers = Vec::with_capacity(needed.len());
    for h in needed {
        // Height 0 is the genesis pseudo-height: Scala's `flatMap` drops
        // it silently, as `ergo-mining::load_epoch_headers` does.
        if h == 0 {
            continue;
        }
        if h == parent.height {
            headers.push(parent.clone());
            continue;
        }
        let id = store.get_header_id_at_height(h).ok().flatten()?;
        headers.push(read_stored_header(store, &id)?);
    }
    next_n_bits(child_height, &headers, &params).ok()
}

/// Scala `historyReader.contains(header.transactionsId)`: does the node
/// already hold this ordering block's transaction section? Resolved
/// through the stored header, whose `transactions_root` IS the section's
/// modifier id.
fn block_transactions_known(store: &StateBackendKind, ordering_id: &OrderingId) -> bool {
    match read_stored_header(store, ordering_id) {
        Some(h) => store
            .get_block_section(h.transactions_root.as_bytes())
            .ok()
            .flatten()
            .is_some(),
        None => false,
    }
}

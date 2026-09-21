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
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_ser::transaction::read_transaction;
use ergo_ser::weak_id::{witness_id, WeakId};
use ergo_state::{ChainStateRead, HeaderSectionStore, StateBackendKind};

use super::super::NodeState;

/// Weak-id → bodies snapshot of the mempool, taken once per event.
///
/// Owned per-event inputs for a [`ProcessorCtx`], plus a borrow of the
/// store for the lookups that cannot be precomputed.
pub(in crate::node) struct CtxData<'a> {
    multiplier: Option<i32>,
    full_block_height: u32,
    utxo_mode: bool,
    /// Expected `nBits` per announced parent, precomputed for the parent
    /// ids the caller knew about. A miss falls through to
    /// [`expected_n_bits_after_store`] against `store`.
    expected: HashMap<[u8; 32], Option<u32>>,
    /// Borrowed for the lookups that cannot be precomputed: an arbitrary
    /// ordering id's stored header and section, and the `nBits`
    /// expectation for a parent the caller did not name.
    state: &'a NodeState,
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
        // Resolved on demand against the mempool's own weak-id index:
        // O(1) plus a parse of only the entries that actually carry `w`.
        // This used to be a precomputed snapshot rebuilt by parsing EVERY
        // pooled transaction on every input-block event — with the miner
        // publishing roughly one input block per second that scan was the
        // subsystem's dominant cost. `&NodeState` is shared here (the
        // executor took the runtime out of it), so the borrow is sound.
        let mempool_lookup = |w: &WeakId| bodies_for_weak_id(self.state, w);
        let expected_n_bits = |parent: &[u8; 32]| match self.expected.get(parent) {
            Some(v) => *v,
            None => expected_n_bits_after(self.state, parent),
        };
        let block_transactions_known = |id: &OrderingId| block_transactions_known(self.state, id);
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
        expected.insert(*id, expected_n_bits_after(state, id));
    }
    CtxData {
        // Spec 6.5: the CURRENT state's parameters, never the announced
        // parent's epoch. `last_seen_active_params` is the action loop's
        // mirror of `store.active_params()`, refreshed on every tip
        // change before any input-block event is handled.
        multiplier: state.last_seen_active_params.subblocks_per_block,
        full_block_height: state.store.chain_state_meta().best_full_block_height,
        utxo_mode: state.store.as_utxo().is_some(),
        expected,
        state,
    }
}

/// The pooled transactions carrying `weak`, as processor [`Body`]s.
///
/// A weak id is 6 bytes, so distinct pooled transactions legitimately
/// collide (spec §7.5); every collider is returned and the caller
/// resolves the ambiguity through the full-id request path. An entry
/// whose stored bytes no longer decode is skipped, never fatal — the
/// same contract the removed full-pool scan had.
fn bodies_for_weak_id(state: &NodeState, weak: &WeakId) -> Vec<Body> {
    state
        .mempool
        .find_by_weak_id(weak)
        .into_iter()
        .filter_map(|entry| {
            let mut r = VlqReader::new(&entry.bytes);
            let tx = read_transaction(&mut r)
                .inspect_err(|err| {
                    tracing::warn!(
                        tx_id = ?entry.tx_id, error = ?err,
                        "input_blocks: pooled entry does not decode, skipping"
                    );
                })
                .ok()?;
            let wid = witness_id(&tx);
            Some(Body {
                tx_ref: TxRef {
                    tx_id: *entry.tx_id.as_bytes(),
                    witness_id: wid,
                },
                weak_id: *weak,
                bytes: entry.bytes.clone(),
                tx,
            })
        })
        .collect()
}

/// Spec 6.2: `encode_compact(required_difficulty_after(parent))`, or
/// `None` when the parent header is unknown (parity with Scala, which
/// only checks `nBits` for a known parent).
fn read_stored_header(store: &StateBackendKind, id: &[u8; 32]) -> Option<Header> {
    let bytes = store.get_header(id).ok().flatten()?;
    let mut r = VlqReader::new(&bytes);
    read_header(&mut r).ok()
}

pub(in crate::node) fn expected_n_bits_after(
    state: &NodeState,
    parent_id: &[u8; 32],
) -> Option<u32> {
    let store = &state.store;
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

/// The modifier id of an ordering block's transactions section.
///
/// NOT the header's `transactions_root`: a non-header section is
/// identified by `blake2b256(type_id || header_id || root)` (Scala
/// `NonHeaderBlockSection.computeIdBytes`). Naming the bare root would
/// request a modifier no peer holds and make every stored section look
/// absent.
pub(in crate::node) fn transactions_section_id(
    state: &NodeState,
    header_id: &OrderingId,
) -> Option<[u8; 32]> {
    let header = read_stored_header(&state.store, header_id)?;
    Some(compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        header_id,
        header.transactions_root.as_bytes(),
    ))
}

/// Scala `historyReader.contains(header.transactionsId)`: does the node
/// already hold this ordering block's transaction section?
pub(in crate::node) fn block_transactions_known(
    state: &NodeState,
    ordering_id: &OrderingId,
) -> bool {
    match transactions_section_id(state, ordering_id) {
        Some(section_id) => state
            .store
            .get_block_section(&section_id)
            .ok()
            .flatten()
            .is_some(),
        None => false,
    }
}

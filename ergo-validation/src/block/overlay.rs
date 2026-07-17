use std::collections::{HashMap, HashSet};

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::Transaction;

use crate::context::UtxoView;

/// UTXO overlay for intra-block transaction dependencies.
///
/// Wraps a base UtxoView and tracks outputs created and inputs spent
/// within the current block, so transaction N can spend outputs of
/// transaction M (M < N) in the same block.
pub(super) struct BlockUtxoOverlay<'a> {
    base: &'a dyn UtxoView,
    in_block_outputs: HashMap<Digest32, ErgoBox>,
    spent_in_block: HashSet<Digest32>,
}

impl<'a> BlockUtxoOverlay<'a> {
    pub(super) fn new(base: &'a dyn UtxoView) -> Self {
        Self {
            base,
            in_block_outputs: HashMap::new(),
            spent_in_block: HashSet::new(),
        }
    }

    pub(super) fn apply_tx(&mut self, tx: &Transaction) {
        for input in &tx.inputs {
            self.spent_in_block.insert(input.box_id);
        }
        // `transaction_id` is fallible only on write-side errors that
        // require malformed in-memory state (token-id-not-in-table); a
        // Transaction that reached this overlay has already been
        // structurally validated, so the id derivation cannot fail.
        let tx_id = ergo_ser::transaction::transaction_id(tx)
            .expect("validated Transaction yields a deterministic id");
        for (idx, output) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: output.clone(),
                transaction_id: tx_id,
                index: idx as u16,
            };
            if let Ok(box_id) = ergo_box.box_id() {
                self.in_block_outputs.insert(box_id, ergo_box);
            }
        }
    }
}

impl BlockUtxoOverlay<'_> {
    /// Look up a box for data-input resolution.
    ///
    /// Resolves through the union of pre-block UTXO + intra-block
    /// creates, ignoring intra-block spends. This differs from regular
    /// input resolution (`UtxoView::get_box`) which both surfaces
    /// in-block creates AND filters out in-block spends.
    ///
    /// Mainnet oracle evidence:
    /// 1. Block 290684 — data input to a box SPENT earlier in the same
    ///    block resolves (the box was in pre-block UTXO; we don't
    ///    filter on `spent_in_block`).
    /// 2. Block 422179 — tx 2 has a data input on a box with
    ///    `settlementHeight = 422179` (created in this same block by
    ///    an earlier tx). Scala accepts this block — the box must be
    ///    found via `in_block_outputs`.
    ///
    /// An earlier version of this helper went to `base` only, citing
    /// "Scala parity: ErgoState.stateChanges resolves data inputs from
    /// the original state". That reading was wrong — Scala's stateful
    /// validation runs over a sequentially-applied per-block view, so
    /// a tx's data inputs see what earlier txs in the same block have
    /// already added. Mainnet block 422179 is the proof.
    pub(super) fn get_box_from_base(&self, box_id: &Digest32) -> Option<ErgoBox> {
        if let Some(b) = self.in_block_outputs.get(box_id) {
            return Some(b.clone());
        }
        self.base.get_box(box_id)
    }
}

impl UtxoView for BlockUtxoOverlay<'_> {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        if self.spent_in_block.contains(box_id) {
            return None;
        }
        if let Some(b) = self.in_block_outputs.get(box_id) {
            return Some(b.clone());
        }
        self.base.get_box(box_id)
    }
}

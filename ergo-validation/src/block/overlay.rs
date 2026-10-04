use std::collections::{HashMap, HashSet};

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::Transaction;

use crate::context::UtxoView;

/// UTXO overlay for intra-block transaction dependencies.
///
/// Wraps a base UtxoView and the block's outputs. Regular inputs see the
/// outputs of transactions already applied to the overlay, so transaction N
/// can spend outputs of transaction M (M < N) in the same block. Data inputs
/// see every output of the block, as Scala's `UtxoState.applyTransactions`
/// resolves both through `createdOutputs = transactions.flatMap(_.outputs)`
/// before falling back to the pre-block state.
pub(super) struct BlockUtxoOverlay<'a> {
    base: &'a dyn UtxoView,
    block_outputs: HashMap<Digest32, ErgoBox>,
    // Output ids per transaction index, in output order.
    outputs_by_tx: Vec<Vec<Digest32>>,
    applied_outputs: HashSet<Digest32>,
    spent_in_block: HashSet<Digest32>,
}

impl<'a> BlockUtxoOverlay<'a> {
    /// Build the overlay for a whole block. Transactions whose id or output
    /// ids cannot be derived contribute no outputs; block validation rejects
    /// such a transaction before its outputs could matter.
    pub(super) fn new(base: &'a dyn UtxoView, transactions: &[Transaction]) -> Self {
        let mut block_outputs = HashMap::new();
        let mut outputs_by_tx = Vec::with_capacity(transactions.len());
        for tx in transactions {
            let mut ids = Vec::with_capacity(tx.output_candidates.len());
            if let Ok(tx_id) = ergo_ser::transaction::transaction_id(tx) {
                for (idx, output) in tx.output_candidates.iter().enumerate() {
                    let ergo_box = ErgoBox::new(output.clone(), tx_id, idx as u16);
                    if let Ok(box_id) = ergo_box.box_id() {
                        ids.push(box_id);
                        block_outputs.insert(box_id, ergo_box);
                    }
                }
            }
            outputs_by_tx.push(ids);
        }
        Self {
            base,
            block_outputs,
            outputs_by_tx,
            applied_outputs: HashSet::new(),
            spent_in_block: HashSet::new(),
        }
    }

    /// Commit the transaction at `index` of the block passed to [`Self::new`]:
    /// its inputs become spent and its outputs become spendable.
    pub(super) fn apply_tx(&mut self, index: usize, tx: &Transaction) {
        for input in &tx.inputs {
            self.spent_in_block.insert(input.box_id);
        }
        if let Some(ids) = self.outputs_by_tx.get(index) {
            self.applied_outputs.extend(ids.iter().copied());
        }
    }
}

impl BlockUtxoOverlay<'_> {
    /// Look up a box for data-input resolution.
    ///
    /// Resolves through every output of the block, then the base view,
    /// ignoring intra-block spends and transaction order. This matches
    /// Scala's `checkBoxExistence` (`createdOutputs.get(id).orElse(boxById(id))`
    /// in `UtxoState.applyTransactions`); the AVL lookups for data inputs
    /// run before the block's removals and insertions and never fail
    /// (`StateChanges.operations`). It differs from regular input resolution
    /// (`UtxoView::get_box`), which surfaces only outputs of transactions
    /// already applied AND filters out in-block spends.
    ///
    /// Mainnet oracle evidence:
    /// 1. Block 290684 — data input to a box SPENT earlier in the same
    ///    block resolves (the box was in pre-block UTXO; we don't
    ///    filter on `spent_in_block`).
    /// 2. Block 422179 — tx 2 has a data input on a box with
    ///    `settlementHeight = 422179` (created in this same block by
    ///    an earlier tx). Scala accepts this block.
    ///
    /// A data input may also name an output of a later transaction in the
    /// block, which the digest path's `DigestUtxoView` resolves the same way.
    pub(super) fn get_box_from_base(&self, box_id: &Digest32) -> Option<ErgoBox> {
        if let Some(b) = self.block_outputs.get(box_id) {
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
        if self.applied_outputs.contains(box_id) {
            return self.block_outputs.get(box_id).cloned();
        }
        self.base.get_box(box_id)
    }
}

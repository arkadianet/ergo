use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::Transaction;

use crate::error::ValidationError;
use crate::tx::CheckedTransaction;

use super::error::BlockValidationError;

/// Topological layering of a block's transactions for parallel validation.
///
/// Every tx index in `[0, txs.len())` appears in exactly one layer. For any
/// pair where tx `j` spends (or data-reads) an output of tx `i` within the
/// same block, `layer[j] > layer[i]`. Within a single layer no tx depends
/// on any other in the same layer, so layer members can be validated
/// concurrently against a shared overlay snapshot that contains the
/// outputs of strictly lower layers.
///
/// Also rejects intra-block double-spends (two txs listing the same input
/// `box_id`) up front — this was caught implicitly by the sequential
/// [`BlockUtxoOverlay`](super::overlay::BlockUtxoOverlay) (the second tx's
/// input resolution returned `None`), but parallel validation must reject
/// explicitly since both txs would see the same pre-block UTXO snapshot.
#[derive(Debug)]
pub(crate) struct TxLayers {
    /// `layers[L]` = ascending-sorted tx indices whose dependency depth is `L`.
    pub(crate) layers: Vec<Vec<usize>>,
}

// (tx index, re-serialized tx bytes, resolved inputs, resolved data inputs).
// The per-tx group-element points are NOT carried here: they are borrowed and
// indexed (`group_elements[i]`) inside the parallel closure, avoiding a per-tx
// Vec clone — the points slice is `Sync` and outlives the parallel section.
pub(crate) type TxLayerInput = (usize, Vec<u8>, Vec<ErgoBox>, Vec<ErgoBox>);
pub(crate) type TxLayerResult = (usize, Result<(CheckedTransaction, u64), ValidationError>);

#[cfg(test)]
impl TxLayers {
    pub(crate) fn layer_count(&self) -> usize {
        self.layers.len()
    }
    pub(crate) fn tx_count(&self) -> usize {
        self.layers.iter().map(|v| v.len()).sum()
    }
}

/// Build the topological layering for a block's transactions.
///
/// Returns [`BlockValidationError::DoubleSpendInBlock`] if two txs list the
/// same `box_id` as an input.
///
/// Boxes whose `transaction_id` or `box_id` derivation fails (a structural
/// failure: malformed token table, duplicate output ids, etc.) are
/// omitted from the output→owner map. Layering correctness depends only
/// on syntactically well-formed boxes being mapped, which is the case
/// for any tx that will pass per-tx validation. Anything skipped here
/// is a structurally invalid tx that downstream `validate_transaction_parsed`
/// will reject explicitly — typically with `Deserialization` or
/// `InputBoxNotFound`. The whole block is rejected in either case.
///
/// Complexity: O(sum(inputs) + sum(outputs)) hashmap ops, plus one box
/// serialize per output. Benchmarked at <1ms for a 200-tx block.
pub(crate) fn build_tx_layers(txs: &[Transaction]) -> Result<TxLayers, BlockValidationError> {
    // 1. Detect intra-block double-spend. Two txs listing the same box_id
    //    as input are mutually exclusive regardless of whether the box is
    //    pre-block or created by another tx in the same block.
    let mut first_spender: HashMap<Digest32, usize> = HashMap::new();
    for (i, tx) in txs.iter().enumerate() {
        for input in &tx.inputs {
            if let Some(&prev) = first_spender.get(&input.box_id) {
                return Err(BlockValidationError::DoubleSpendInBlock {
                    first: prev,
                    second: i,
                    box_id: hex::encode(input.box_id.as_bytes()),
                });
            }
            first_spender.insert(input.box_id, i);
        }
    }

    // 2. Map each output box_id → owning tx index so input resolution in
    //    step 3 can detect intra-block produce→consume edges.
    let mut output_owner: HashMap<Digest32, usize> = HashMap::new();
    for (i, tx) in txs.iter().enumerate() {
        let tx_id = match ergo_ser::transaction::transaction_id(tx) {
            Ok(id) => id,
            Err(_) => continue, // malformed — will be rejected by canonical check
        };
        for (idx, output) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: output.clone(),
                transaction_id: tx_id,
                index: idx as u16,
            };
            if let Ok(box_id) = ergo_box.box_id() {
                output_owner.insert(box_id, i);
            }
        }
    }

    // 3. Compute dependency depth per tx. A block's canonical tx order
    //    places dependencies at lower indices, so forward iteration with
    //    layer[j] = max(layer[dep]) + 1 is sufficient. Backwards edges
    //    (j depends on k>j) cannot be stitched into a dag here — they
    //    fall through unresolved and the per-tx input resolution will
    //    fail normally, matching sequential behaviour.
    let mut layer: Vec<usize> = vec![0; txs.len()];
    for (i, tx) in txs.iter().enumerate() {
        let mut max_dep_layer: Option<usize> = None;
        let record_dep = |other_idx: usize, cur: &mut Option<usize>| {
            if other_idx < i {
                let l = layer[other_idx];
                *cur = Some(cur.map_or(l, |m| m.max(l)));
            }
        };
        for input in &tx.inputs {
            if let Some(&j) = output_owner.get(&input.box_id) {
                record_dep(j, &mut max_dep_layer);
            }
        }
        for di in &tx.data_inputs {
            if let Some(&j) = output_owner.get(&di.box_id) {
                record_dep(j, &mut max_dep_layer);
            }
        }
        if let Some(ml) = max_dep_layer {
            layer[i] = ml + 1;
        }
    }

    // 4. Bucket tx indices into layer vectors. Preserves ascending order
    //    within each layer because we iterate input in ascending tx index.
    let max_layer = layer.iter().copied().max().unwrap_or(0);
    let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_layer + 1];
    for (i, l) in layer.iter().enumerate() {
        layers[*l].push(i);
    }

    Ok(TxLayers { layers })
}

#[cfg(test)]
mod layering_tests {
    use super::*;
    use crate::context::UtxoView;
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, DataInput, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;

    use super::super::overlay::BlockUtxoOverlay;

    fn simple_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    fn make_candidate(value: u64) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            value,
            simple_tree(),
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn input_of(box_id: Digest32) -> Input {
        Input {
            box_id,
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }
    }

    fn input_filled(fill: u8) -> Input {
        input_of(Digest32::from_bytes([fill; 32]))
    }

    fn tx_with(inputs: Vec<Input>, data_inputs: Vec<DataInput>, outputs: usize) -> Transaction {
        Transaction {
            inputs,
            data_inputs,
            output_candidates: (0..outputs)
                .map(|_| make_candidate(1_000_000_000))
                .collect(),
        }
    }

    fn first_output_box_id(tx: &Transaction) -> Digest32 {
        let tx_id = ergo_ser::transaction::transaction_id(tx).unwrap();
        let ergo_box = ErgoBox {
            candidate: tx.output_candidates[0].clone(),
            transaction_id: tx_id,
            index: 0,
        };
        ergo_box.box_id().unwrap()
    }

    #[test]
    fn empty_block_has_no_layers() {
        let layers = build_tx_layers(&[]).unwrap();
        // Empty input → Vec::new max → 0, so we allocate one empty layer.
        // Consumers iterate layers, so one empty layer is indistinguishable from zero.
        assert_eq!(layers.tx_count(), 0);
    }

    #[test]
    fn independent_txs_all_in_layer_0() {
        // Three txs, each spending distinct pre-block boxes. No intra-block deps.
        let txs = vec![
            tx_with(vec![input_filled(1)], vec![], 1),
            tx_with(vec![input_filled(2)], vec![], 1),
            tx_with(vec![input_filled(3)], vec![], 1),
        ];
        let layers = build_tx_layers(&txs).unwrap();
        assert_eq!(layers.layer_count(), 1, "no deps → single layer");
        assert_eq!(layers.layers[0], vec![0, 1, 2]);
    }

    #[test]
    fn linear_chain_builds_deep_layering() {
        // tx0 spends pre-block box. tx1 spends tx0's output. tx2 spends tx1's output.
        let tx0 = tx_with(vec![input_filled(1)], vec![], 1);
        let tx0_out = first_output_box_id(&tx0);
        let tx1 = tx_with(vec![input_of(tx0_out)], vec![], 1);
        let tx1_out = first_output_box_id(&tx1);
        let tx2 = tx_with(vec![input_of(tx1_out)], vec![], 1);

        let layers = build_tx_layers(&[tx0, tx1, tx2]).unwrap();
        assert_eq!(layers.layer_count(), 3, "chain length 3 → three layers");
        assert_eq!(layers.layers[0], vec![0]);
        assert_eq!(layers.layers[1], vec![1]);
        assert_eq!(layers.layers[2], vec![2]);
    }

    #[test]
    fn data_input_creates_dependency() {
        // tx0 creates an output, tx1 READS it as a data input — still a dep.
        let tx0 = tx_with(vec![input_filled(1)], vec![], 1);
        let tx0_out = first_output_box_id(&tx0);
        let tx1 = tx_with(
            vec![input_filled(2)],
            vec![DataInput { box_id: tx0_out }],
            1,
        );
        let layers = build_tx_layers(&[tx0, tx1]).unwrap();
        assert_eq!(layers.layer_count(), 2);
        assert_eq!(layers.layers[0], vec![0]);
        assert_eq!(layers.layers[1], vec![1]);
    }

    #[test]
    fn fan_out_single_layer_of_children() {
        // tx0 has two outputs; tx1 and tx2 each spend one. tx1 and tx2 are
        // siblings of each other → both at layer 1, not serialized.
        let tx0 = tx_with(vec![input_filled(1)], vec![], 2);
        let tx_id = ergo_ser::transaction::transaction_id(&tx0).unwrap();
        let out0 = ErgoBox {
            candidate: tx0.output_candidates[0].clone(),
            transaction_id: tx_id,
            index: 0,
        }
        .box_id()
        .unwrap();
        let out1 = ErgoBox {
            candidate: tx0.output_candidates[1].clone(),
            transaction_id: tx_id,
            index: 1,
        }
        .box_id()
        .unwrap();
        let tx1 = tx_with(vec![input_of(out0)], vec![], 1);
        let tx2 = tx_with(vec![input_of(out1)], vec![], 1);

        let layers = build_tx_layers(&[tx0, tx1, tx2]).unwrap();
        assert_eq!(layers.layer_count(), 2);
        assert_eq!(layers.layers[0], vec![0]);
        assert_eq!(
            layers.layers[1],
            vec![1, 2],
            "fan-out children share a layer"
        );
    }

    #[test]
    fn fan_in_uses_max_parent_layer() {
        // tx0, tx1 are independent at layer 0. tx2 spends outputs of both.
        let tx0 = tx_with(vec![input_filled(1)], vec![], 1);
        let tx1 = tx_with(vec![input_filled(2)], vec![], 1);
        let out0 = first_output_box_id(&tx0);
        let out1 = first_output_box_id(&tx1);
        let tx2 = tx_with(vec![input_of(out0), input_of(out1)], vec![], 1);

        let layers = build_tx_layers(&[tx0, tx1, tx2]).unwrap();
        assert_eq!(layers.layer_count(), 2);
        assert_eq!(layers.layers[0], vec![0, 1]);
        assert_eq!(layers.layers[1], vec![2]);
    }

    #[test]
    fn intra_block_double_spend_rejected() {
        // tx0 and tx1 both try to consume the same pre-block box — must reject
        // BEFORE parallel dispatch; sequential overlay's implicit catch is
        // not available when both see the pre-block UTXO snapshot.
        let shared = Digest32::from_bytes([7u8; 32]);
        let tx0 = tx_with(vec![input_of(shared)], vec![], 1);
        let tx1 = tx_with(vec![input_of(shared)], vec![], 1);
        let err = build_tx_layers(&[tx0, tx1]).unwrap_err();
        match err {
            BlockValidationError::DoubleSpendInBlock { first, second, .. } => {
                assert_eq!((first, second), (0, 1));
            }
            other => panic!("expected DoubleSpendInBlock, got {other:?}"),
        }
    }

    /// Test-only `UtxoView` that exposes a single fixed box.
    struct OneBoxUtxo {
        id: Digest32,
        b: ErgoBox,
    }

    impl UtxoView for OneBoxUtxo {
        fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
            if *box_id == self.id {
                Some(self.b.clone())
            } else {
                None
            }
        }
    }

    /// Data-input resolution sees pre-block UTXO ∪ in-block creates,
    /// ignoring intra-block spends.
    ///
    /// Mainnet oracle evidence pinned here:
    /// - Block 290684 — data input to a box SPENT earlier in the same
    ///   block resolves through the pre-block base (we don't filter
    ///   `spent_in_block`).
    /// - Block 422179 — data input to a box CREATED earlier in the
    ///   same block resolves through `in_block_outputs`.
    ///
    /// Complements `data_input_creates_dependency` (the scheduling
    /// edge) with the lookup contract the schedule is defending.
    #[test]
    fn data_input_resolution_unions_preblock_with_inblock_creates() {
        let pre_block_id = Digest32::from_bytes([1u8; 32]);
        let pre_block_box = ErgoBox {
            candidate: make_candidate(1_000_000_000),
            transaction_id: ergo_primitives::digest::ModifierId::from_bytes([0u8; 32]),
            index: 0,
        };
        let base = OneBoxUtxo {
            id: pre_block_id,
            b: pre_block_box.clone(),
        };

        let mut overlay = BlockUtxoOverlay::new(&base);

        // Apply a tx that spends the pre-block box and creates a new one.
        let creator = tx_with(vec![input_of(pre_block_id)], vec![], 1);
        let created_id = first_output_box_id(&creator);
        overlay.apply_tx(&creator);

        // Spending-input view (UtxoView::get_box) respects in-block changes:
        //   - pre-block id is now spent_in_block → None
        //   - newly-created id is in in_block_outputs → Some
        assert!(
            overlay.get_box(&pre_block_id).is_none(),
            "spending view must hide a box spent earlier in the block"
        );
        assert!(
            overlay.get_box(&created_id).is_some(),
            "spending view must surface an in-block-created box for the next tx"
        );

        // Data-input view (get_box_from_base) is the union of pre-block
        // UTXO + in-block creates, with no spent_in_block filter:
        //   - pre-block id still resolves even though it's spent_in_block
        //     (mainnet block 290684)
        //   - newly-created id resolves via in_block_outputs
        //     (mainnet block 422179, tx 2 data input on settlementHeight=422179 box)
        assert!(
            overlay.get_box_from_base(&pre_block_id).is_some(),
            "data-input view must surface a box that pre-block UTXO has, \
             even after intra-block spend (block 290684 parity)"
        );
        assert!(
            overlay.get_box_from_base(&created_id).is_some(),
            "data-input view must surface in-block-created outputs \
             (block 422179 parity: tx 2 data-inputs a box with settlementHeight=422179)"
        );
    }
}

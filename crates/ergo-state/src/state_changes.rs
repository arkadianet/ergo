use ergo_types::transaction::{compute_box_id, BoxId, ErgoTransaction};
use ergo_wire::box_ser::serialize_ergo_box;
use std::collections::HashSet;

/// State changes computed from a block's transactions.
pub struct StateChanges {
    /// Box IDs to remove from the UTXO set (spent inputs).
    pub to_remove: Vec<BoxId>,
    /// Boxes to insert: (box_id, serialized_box_bytes).
    pub to_insert: Vec<(BoxId, Vec<u8>)>,
    /// Box IDs that need to be looked up (data inputs).
    pub to_lookup: Vec<BoxId>,
}

/// Compute state changes from a list of transactions.
///
/// Applies self-spending optimization: if a box is created and spent
/// in the same block, both operations cancel out.
///
/// Box IDs for newly created outputs are derived as
/// `blake2b256(tx_id ++ vlq(output_index))` via [`compute_box_id`].
/// Inserted box data uses standalone serialization via
/// [`serialize_ergo_box`].
pub fn compute_state_changes(txs: &[ErgoTransaction]) -> StateChanges {
    let mut to_remove = Vec::new();
    let mut to_insert: Vec<(BoxId, Vec<u8>)> = Vec::new();
    let mut to_lookup = Vec::new();
    let mut created_ids = HashSet::new();

    // First pass: collect all outputs (created boxes).
    for tx in txs {
        for (idx, candidate) in tx.output_candidates.iter().enumerate() {
            let box_id = compute_box_id(&tx.tx_id, idx as u16);
            created_ids.insert(box_id);
            to_insert.push((box_id, serialize_ergo_box(candidate)));
        }
    }

    // Second pass: collect inputs and data inputs, applying self-spending
    // cancellation.
    for tx in txs {
        for input in &tx.inputs {
            if created_ids.contains(&input.box_id) {
                // Self-spending: remove from to_insert instead of adding to to_remove.
                created_ids.remove(&input.box_id);
                to_insert.retain(|(id, _)| id != &input.box_id);
            } else {
                to_remove.push(input.box_id);
            }
        }
        for data_input in &tx.data_inputs {
            to_lookup.push(data_input.box_id);
        }
    }

    StateChanges {
        to_remove,
        to_insert,
        to_lookup,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::transaction::{DataInput, ErgoBoxCandidate, ErgoTransaction, Input, TxId};

    /// Helper to build a minimal transaction.
    fn make_tx(
        tx_id: [u8; 32],
        input_box_ids: &[[u8; 32]],
        data_input_box_ids: &[[u8; 32]],
        num_outputs: usize,
    ) -> ErgoTransaction {
        let inputs = input_box_ids
            .iter()
            .map(|id| Input {
                box_id: BoxId(*id),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            })
            .collect();

        let data_inputs = data_input_box_ids
            .iter()
            .map(|id| DataInput { box_id: BoxId(*id) })
            .collect();

        let output_candidates = (0..num_outputs)
            .map(|_| ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                creation_height: 1,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            })
            .collect();

        ErgoTransaction {
            inputs,
            data_inputs,
            output_candidates,
            tx_id: TxId(tx_id),
        }
    }

    /// Compute the real box_id for a given tx_id and output index.
    fn expected_box_id(tx_id: [u8; 32], idx: u16) -> BoxId {
        compute_box_id(&TxId(tx_id), idx)
    }

    #[test]
    fn simple_tx_one_input_one_output() {
        let tx_id = [0xAA; 32];
        let spent_box = [0xBB; 32];
        let tx = make_tx(tx_id, &[spent_box], &[], 1);

        let changes = compute_state_changes(&[tx]);

        assert_eq!(changes.to_remove.len(), 1);
        assert_eq!(changes.to_remove[0], BoxId(spent_box));

        assert_eq!(changes.to_insert.len(), 1);
        assert_eq!(changes.to_insert[0].0, expected_box_id(tx_id, 0));

        assert!(changes.to_lookup.is_empty());
    }

    #[test]
    fn self_spending_cancellation() {
        // Transaction 1 creates a box.
        let tx1_id = [0x01; 32];
        let tx1 = make_tx(tx1_id, &[], &[], 1);
        let created_box_id = expected_box_id(tx1_id, 0);

        // Transaction 2 spends the box created by tx1 in the same block.
        let tx2_id = [0x02; 32];
        let tx2 = make_tx(tx2_id, &[created_box_id.0], &[], 1);

        let changes = compute_state_changes(&[tx1, tx2]);

        // The created-and-spent box should cancel out: not in to_remove
        // and not in to_insert (for that particular box_id).
        assert!(
            !changes.to_remove.contains(&created_box_id),
            "self-spent box should not appear in to_remove"
        );
        assert!(
            !changes
                .to_insert
                .iter()
                .any(|(id, _)| *id == created_box_id),
            "self-spent box should not appear in to_insert"
        );

        // tx2's output should still be in to_insert.
        let tx2_output = expected_box_id(tx2_id, 0);
        assert!(changes.to_insert.iter().any(|(id, _)| *id == tx2_output));
    }

    #[test]
    fn data_inputs_appear_in_to_lookup() {
        let tx_id = [0xCC; 32];
        let data_box_1 = [0xD1; 32];
        let data_box_2 = [0xD2; 32];
        let tx = make_tx(tx_id, &[], &[data_box_1, data_box_2], 0);

        let changes = compute_state_changes(&[tx]);

        assert_eq!(changes.to_lookup.len(), 2);
        assert_eq!(changes.to_lookup[0], BoxId(data_box_1));
        assert_eq!(changes.to_lookup[1], BoxId(data_box_2));
        assert!(changes.to_remove.is_empty());
        assert!(changes.to_insert.is_empty());
    }

    #[test]
    fn inserted_box_data_is_non_empty() {
        let tx_id = [0xAA; 32];
        let spent_box = [0xBB; 32];
        let tx = make_tx(tx_id, &[spent_box], &[], 2);

        let changes = compute_state_changes(&[tx]);

        assert_eq!(changes.to_insert.len(), 2);
        for (_, data) in &changes.to_insert {
            assert!(
                !data.is_empty(),
                "inserted box data should be non-empty serialized bytes"
            );
        }
    }

    #[test]
    fn inserted_box_data_roundtrips() {
        use ergo_wire::box_ser::parse_ergo_box;

        let tx_id = [0xAA; 32];
        let spent_box = [0xBB; 32];
        let tx = make_tx(tx_id, &[spent_box], &[], 1);

        // The candidate we expect to recover.
        let original_candidate = ErgoBoxCandidate {
            value: 1_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 1,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };

        let changes = compute_state_changes(&[tx]);
        assert_eq!(changes.to_insert.len(), 1);

        let (_, ref data) = changes.to_insert[0];
        let parsed = parse_ergo_box(data).expect("parse_ergo_box should succeed");
        assert_eq!(parsed, original_candidate);
    }
}

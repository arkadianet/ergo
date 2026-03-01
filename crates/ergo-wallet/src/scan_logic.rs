//! Block scanning logic — identifies wallet-relevant outputs and spent inputs.
//!
//! The scanner examines each transaction in a block:
//! - For each **output**: checks if its ErgoTree bytes match any wallet address.
//! - For each **input**: checks if its box ID is a tracked (unspent) wallet box.

use std::collections::HashSet;

use crate::scan_types::{Scan, PAYMENTS_SCAN_ID};
use crate::tracked_box::TrackedBox;

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

/// Information about a transaction output for scanning purposes.
#[derive(Debug, Clone)]
pub struct OutputInfo {
    /// Blake2b-256 box ID.
    pub box_id: [u8; 32],
    /// Raw ErgoTree bytes of the output.
    pub ergo_tree_bytes: Vec<u8>,
    /// NanoERG value locked in the output.
    pub value: u64,
    /// Tokens: `(token_id, amount)` pairs.
    pub tokens: Vec<([u8; 32], u64)>,
    /// Creation height recorded in the output.
    pub creation_height: u32,
    /// Zero-based index of this output within the transaction.
    pub output_index: u16,
    /// Full wire-format serialized box bytes.
    pub serialized_box: Vec<u8>,
    /// Non-mandatory registers R4..R9: (register_index, serialized_value_bytes).
    pub additional_registers: Vec<(u8, Vec<u8>)>,
}

/// Information about a block transaction for scanning purposes.
#[derive(Debug, Clone)]
pub struct TxInfo {
    /// Transaction ID (Blake2b-256 hash).
    pub tx_id: [u8; 32],
    /// Box IDs consumed by this transaction's inputs.
    pub input_box_ids: Vec<[u8; 32]>,
    /// Outputs produced by this transaction.
    pub outputs: Vec<OutputInfo>,
    /// Full serialized transaction bytes.
    pub tx_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Conversion from ergo-types to scan types
// ---------------------------------------------------------------------------

/// Convert an [`ErgoTransaction`] (from ergo-types) into a [`TxInfo`] for scanning.
///
/// Computes box IDs for each output using [`compute_box_id`] and serializes
/// each output candidate in standalone format for the `serialized_box` field.
pub fn ergo_transaction_to_tx_info(
    tx: &ergo_types::transaction::ErgoTransaction,
    tx_id: &ergo_types::transaction::TxId,
    tx_bytes: &[u8],
) -> TxInfo {
    use ergo_types::transaction::compute_box_id;

    let input_box_ids = tx.inputs.iter().map(|input| input.box_id.0).collect();

    let outputs = tx
        .output_candidates
        .iter()
        .enumerate()
        .map(|(i, candidate)| {
            let box_id = compute_box_id(tx_id, i as u16);
            let tokens = candidate
                .tokens
                .iter()
                .map(|(token_id, amount)| (token_id.0, *amount))
                .collect();
            // Standalone box serialization (full token IDs, no indexing).
            let serialized_box = ergo_wire::box_ser::serialize_ergo_box(candidate);

            OutputInfo {
                box_id: box_id.0,
                ergo_tree_bytes: candidate.ergo_tree_bytes.clone(),
                value: candidate.value,
                tokens,
                creation_height: candidate.creation_height,
                output_index: i as u16,
                serialized_box,
                additional_registers: candidate.additional_registers.clone(),
            }
        })
        .collect();

    TxInfo {
        tx_id: tx_id.0,
        input_box_ids,
        outputs,
        tx_bytes: tx_bytes.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Result of scanning a block for wallet-relevant activity.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// New boxes belonging to the wallet (matched by ErgoTree).
    pub new_boxes: Vec<TrackedBox>,
    /// Box IDs of previously-tracked boxes that were spent in this block.
    pub spent_box_ids: Vec<[u8; 32]>,
    /// `(tx_id, tx_bytes)` pairs for every wallet-relevant transaction.
    pub wallet_txs: Vec<([u8; 32], Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// Core scanning function
// ---------------------------------------------------------------------------

/// Scan a block's transactions for wallet-relevant activity.
///
/// A transaction is "wallet-relevant" if **any** of its outputs match a
/// wallet ErgoTree, a scan predicate, **or** any of its inputs spend a
/// tracked box.
///
/// # Arguments
///
/// - `block_txs` — all transactions in the block, in order.
/// - `block_height` — the height of the block being scanned.
/// - `wallet_ergo_trees` — set of ErgoTree byte vectors for wallet addresses.
/// - `tracked_box_ids` — set of box IDs that the wallet currently tracks as
///   unspent.
/// - `scans` — user-defined scans whose predicates are evaluated against each
///   output.
pub fn scan_block(
    block_txs: &[TxInfo],
    block_height: u32,
    wallet_ergo_trees: &HashSet<Vec<u8>>,
    tracked_box_ids: &HashSet<[u8; 32]>,
    scans: &[Scan],
) -> ScanResult {
    let mut result = ScanResult::default();

    for tx in block_txs {
        let mut is_wallet_tx = false;

        // --- Check outputs: wallet addresses and scan predicates ---
        for output in &tx.outputs {
            let mut scan_ids: Vec<u16> = Vec::new();

            // Check wallet address match.
            if wallet_ergo_trees.contains(&output.ergo_tree_bytes) {
                scan_ids.push(PAYMENTS_SCAN_ID);
            }

            // Evaluate each scan's tracking predicate.
            for scan in scans {
                if scan
                    .tracking_rule
                    .matches(&output.ergo_tree_bytes, &output.tokens, output.value)
                {
                    scan_ids.push(scan.scan_id);
                }
            }

            if !scan_ids.is_empty() {
                result.new_boxes.push(TrackedBox {
                    box_id: output.box_id,
                    ergo_tree_bytes: output.ergo_tree_bytes.clone(),
                    value: output.value,
                    tokens: output.tokens.clone(),
                    creation_height: output.creation_height,
                    inclusion_height: block_height,
                    tx_id: tx.tx_id,
                    output_index: output.output_index,
                    serialized_box: output.serialized_box.clone(),
                    additional_registers: output.additional_registers.clone(),
                    spent: false,
                    spending_tx_id: None,
                    spending_height: None,
                    scan_ids,
                });
                is_wallet_tx = true;
            }
        }

        // --- Check inputs: do any spend tracked boxes? ---
        for input_id in &tx.input_box_ids {
            if tracked_box_ids.contains(input_id) {
                result.spent_box_ids.push(*input_id);
                is_wallet_tx = true;
            }
        }

        if is_wallet_tx {
            result.wallet_txs.push((tx.tx_id, tx.tx_bytes.clone()));
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- helpers ---

    /// Build a deterministic 32-byte array from a single seed byte.
    fn id32(seed: u8) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        arr
    }

    /// Build a simple ErgoTree byte vector from a seed.
    fn ergo_tree(seed: u8) -> Vec<u8> {
        vec![0x00, 0x08, 0xCD, seed]
    }

    /// Create a simple OutputInfo.
    fn make_output(seed: u8, tree: &[u8], value: u64, index: u16) -> OutputInfo {
        OutputInfo {
            box_id: id32(seed),
            ergo_tree_bytes: tree.to_vec(),
            value,
            tokens: vec![],
            creation_height: 100,
            output_index: index,
            serialized_box: vec![0xDE, 0xAD, seed],
            additional_registers: vec![],
        }
    }

    /// Create a simple TxInfo.
    fn make_tx(seed: u8, inputs: Vec<[u8; 32]>, outputs: Vec<OutputInfo>) -> TxInfo {
        TxInfo {
            tx_id: id32(seed),
            input_box_ids: inputs,
            outputs,
            tx_bytes: vec![0xCA, 0xFE, seed],
        }
    }

    // --- tests ---

    #[test]
    fn scan_finds_matching_outputs() {
        let wallet_tree = ergo_tree(0xAA);
        let other_tree = ergo_tree(0xBB);

        // TX 1 — has one output matching the wallet
        let tx1 = make_tx(
            1,
            vec![],
            vec![
                make_output(10, &wallet_tree, 1_000_000, 0),
                make_output(11, &other_tree, 2_000_000, 1),
            ],
        );
        // TX 2 — no matching outputs
        let tx2 = make_tx(2, vec![], vec![make_output(20, &other_tree, 3_000_000, 0)]);

        let mut wallet_trees = HashSet::new();
        wallet_trees.insert(wallet_tree);
        let tracked = HashSet::new();

        let result = scan_block(&[tx1, tx2], 500, &wallet_trees, &tracked, &[]);

        assert_eq!(result.new_boxes.len(), 1);
        assert_eq!(result.new_boxes[0].box_id, id32(10));
        assert_eq!(result.new_boxes[0].value, 1_000_000);
        assert_eq!(result.new_boxes[0].inclusion_height, 500);
        assert!(!result.new_boxes[0].spent);
        assert_eq!(result.spent_box_ids.len(), 0);
        assert_eq!(result.wallet_txs.len(), 1);
        assert_eq!(result.wallet_txs[0].0, id32(1));
    }

    #[test]
    fn scan_finds_spent_inputs() {
        let other_tree = ergo_tree(0xCC);
        let tracked_id = id32(0x42);

        // TX spends a tracked box
        let tx = make_tx(
            1,
            vec![tracked_id],
            vec![make_output(10, &other_tree, 1_000_000, 0)],
        );

        let wallet_trees = HashSet::new();
        let mut tracked = HashSet::new();
        tracked.insert(tracked_id);

        let result = scan_block(&[tx], 600, &wallet_trees, &tracked, &[]);

        assert_eq!(result.new_boxes.len(), 0);
        assert_eq!(result.spent_box_ids.len(), 1);
        assert_eq!(result.spent_box_ids[0], tracked_id);
        assert_eq!(result.wallet_txs.len(), 1);
        assert_eq!(result.wallet_txs[0].0, id32(1));
    }

    #[test]
    fn scan_empty_block() {
        let wallet_trees = HashSet::new();
        let tracked = HashSet::new();

        let result = scan_block(&[], 700, &wallet_trees, &tracked, &[]);

        assert!(result.new_boxes.is_empty());
        assert!(result.spent_box_ids.is_empty());
        assert!(result.wallet_txs.is_empty());
    }

    #[test]
    fn scan_no_matches() {
        let wallet_tree = ergo_tree(0xAA);
        let other_tree = ergo_tree(0xBB);

        let tx1 = make_tx(
            1,
            vec![id32(0x99)],                                 // not tracked
            vec![make_output(10, &other_tree, 1_000_000, 0)], // not wallet
        );
        let tx2 = make_tx(2, vec![], vec![make_output(20, &other_tree, 2_000_000, 0)]);

        let mut wallet_trees = HashSet::new();
        wallet_trees.insert(wallet_tree);
        let tracked = HashSet::new(); // nothing tracked

        let result = scan_block(&[tx1, tx2], 800, &wallet_trees, &tracked, &[]);

        assert!(result.new_boxes.is_empty());
        assert!(result.spent_box_ids.is_empty());
        assert!(result.wallet_txs.is_empty());
    }

    #[test]
    fn scan_mixed_scenario() {
        // One tx that both creates a wallet output AND spends a tracked box.
        let wallet_tree = ergo_tree(0xAA);
        let tracked_id = id32(0x42);

        let tx = make_tx(
            1,
            vec![tracked_id, id32(0x99)], // one tracked, one not
            vec![
                make_output(10, &wallet_tree, 5_000_000, 0),
                make_output(11, &ergo_tree(0xBB), 1_000_000, 1),
            ],
        );

        let mut wallet_trees = HashSet::new();
        wallet_trees.insert(wallet_tree.clone());
        let mut tracked = HashSet::new();
        tracked.insert(tracked_id);

        let result = scan_block(&[tx], 900, &wallet_trees, &tracked, &[]);

        assert_eq!(result.new_boxes.len(), 1);
        assert_eq!(result.new_boxes[0].box_id, id32(10));
        assert_eq!(result.new_boxes[0].value, 5_000_000);
        assert_eq!(result.new_boxes[0].ergo_tree_bytes, wallet_tree);

        assert_eq!(result.spent_box_ids.len(), 1);
        assert_eq!(result.spent_box_ids[0], tracked_id);

        // The tx should appear in wallet_txs exactly ONCE.
        assert_eq!(result.wallet_txs.len(), 1);
        assert_eq!(result.wallet_txs[0].0, id32(1));
    }

    #[test]
    fn scan_multiple_outputs_same_tx() {
        let wallet_tree = ergo_tree(0xAA);

        // One tx with two outputs matching the wallet tree.
        let tx = make_tx(
            1,
            vec![],
            vec![
                make_output(10, &wallet_tree, 1_000_000, 0),
                make_output(11, &wallet_tree, 2_000_000, 1),
            ],
        );

        let mut wallet_trees = HashSet::new();
        wallet_trees.insert(wallet_tree);
        let tracked = HashSet::new();

        let result = scan_block(&[tx], 1000, &wallet_trees, &tracked, &[]);

        assert_eq!(result.new_boxes.len(), 2);
        assert_eq!(result.new_boxes[0].box_id, id32(10));
        assert_eq!(result.new_boxes[0].output_index, 0);
        assert_eq!(result.new_boxes[1].box_id, id32(11));
        assert_eq!(result.new_boxes[1].output_index, 1);

        // Still only one wallet tx entry.
        assert_eq!(result.wallet_txs.len(), 1);
        assert_eq!(result.wallet_txs[0].0, id32(1));
    }

    #[test]
    fn scan_block_with_predicate() {
        use crate::scan_types::{Scan, ScanWalletInteraction, ScanningPredicate};

        let wallet_tree = ergo_tree(0xAA);
        let scan_tree = ergo_tree(0xBB);

        let scan = Scan {
            scan_id: 11,
            scan_name: "test".into(),
            tracking_rule: ScanningPredicate::Equals {
                register: "R1".into(),
                value: hex::encode(&scan_tree),
            },
            wallet_interaction: ScanWalletInteraction::Off,
            remove_offchain: false,
        };

        let tx = make_tx(
            1,
            vec![],
            vec![
                make_output(10, &wallet_tree, 1_000_000, 0),
                make_output(11, &scan_tree, 2_000_000, 1),
            ],
        );

        let mut wallet_trees = HashSet::new();
        wallet_trees.insert(wallet_tree);
        let tracked = HashSet::new();

        let result = scan_block(&[tx], 500, &wallet_trees, &tracked, &[scan]);

        assert_eq!(result.new_boxes.len(), 2);
        assert!(result.new_boxes[0].scan_ids.contains(&10)); // wallet
        assert!(result.new_boxes[1].scan_ids.contains(&11)); // scan
        assert_eq!(result.wallet_txs.len(), 1);
    }
}

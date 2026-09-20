//! Multi-tx block ordering analysis.
//!
//! Examines real multi-tx blocks to determine whether the collect-sort-batch
//! model (from Scala boxChanges) differs from per-tx sequential for any
//! blocks in the test corpus.

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox};
use ergo_ser::transaction::{bytes_to_sign, read_transaction};
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct BlockJson {
    #[serde(rename = "headerId")]
    header_id: String,
    height: u32,
    transactions: Vec<TxJson>,
}

#[derive(serde::Deserialize)]
struct TxJson {
    #[allow(dead_code)]
    id: String,
    bytes: String,
}

/// Analyze multi-tx blocks for intra-block dependencies.
/// Reports which blocks have created-then-spent patterns.
#[test]
fn analyze_multi_tx_blocks_for_dependencies() {
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/blocks_700000_700010.json").unwrap();
    let blocks: Vec<BlockJson> = serde_json::from_str(&data).unwrap();

    let mut blocks_with_deps = 0;
    let mut blocks_without_deps = 0;

    for block in &blocks {
        if block.transactions.len() < 2 {
            continue;
        }

        // Track box IDs created by each transaction
        let mut created_in_block: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        let mut has_intra_block_dep = false;
        let mut created_then_spent = 0;

        for tx_json in &block.transactions {
            let tx_bytes = hex::decode(&tx_json.bytes).unwrap();
            let mut r = VlqReader::new(&tx_bytes);
            let tx = read_transaction(&mut r).unwrap();
            let bts = bytes_to_sign(&tx).unwrap();
            let tx_id = blake2b256(&bts);

            // Check inputs against previously created outputs
            for input in &tx.inputs {
                if created_in_block.contains(input.box_id.as_bytes()) {
                    has_intra_block_dep = true;
                    created_then_spent += 1;
                }
            }

            // Record outputs
            for (i, candidate) in tx.output_candidates.iter().enumerate() {
                let output_box = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id.into(),
                    index: i as u16,
                };
                let box_id = output_box.box_id().unwrap();
                created_in_block.insert(*box_id.as_bytes());
            }
        }

        if has_intra_block_dep {
            eprintln!(
                "height {}: {} txs, {} created-then-spent boxes (INTRA-BLOCK DEPENDENCY)",
                block.height,
                block.transactions.len(),
                created_then_spent
            );
            blocks_with_deps += 1;
        } else {
            eprintln!(
                "height {}: {} txs, no intra-block dependencies",
                block.height,
                block.transactions.len()
            );
            blocks_without_deps += 1;
        }
    }

    eprintln!(
        "\nSummary: {blocks_with_deps} blocks WITH intra-block deps, {blocks_without_deps} WITHOUT"
    );

    // This test doesn't assert pass/fail — it's diagnostic.
    // The output tells us whether the ordering model matters for these blocks.
}

/// Compare the two ordering models on multi-tx blocks.
///
/// Model A (collect-sort-batch): Collect all removes and inserts across all txs,
///   deduplicate (created-then-spent excluded), apply removes sorted, then inserts sorted.
///
/// Model B (per-tx sequential): For each tx in block order,
///   remove inputs then insert outputs.
///
/// If a block has no intra-block dependencies, both models produce the same
/// set of (removes, inserts). If it does, Model A's dedup differs from Model B.
#[test]
fn compare_ordering_models_on_multi_tx_blocks() {
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/blocks_700000_700010.json").unwrap();
    let blocks: Vec<BlockJson> = serde_json::from_str(&data).unwrap();

    for block in &blocks {
        if block.transactions.len() < 2 {
            continue;
        }

        let mut txs = Vec::new();
        for tx_json in &block.transactions {
            let tx_bytes = hex::decode(&tx_json.bytes).unwrap();
            let mut r = VlqReader::new(&tx_bytes);
            txs.push(read_transaction(&mut r).unwrap());
        }

        // Model A: collect-sort-batch (Scala boxChanges style)
        let mut model_a_remove: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        let mut model_a_insert: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

        for tx in &txs {
            let bts = bytes_to_sign(tx).unwrap();
            let tx_id = blake2b256(&bts);

            for input in &tx.inputs {
                let box_id = *input.box_id.as_bytes();
                if model_a_insert.remove(&box_id).is_none() {
                    model_a_remove.insert(box_id, ());
                }
            }
            for (i, candidate) in tx.output_candidates.iter().enumerate() {
                let output_box = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id.into(),
                    index: i as u16,
                };
                let box_id = *output_box.box_id().unwrap().as_bytes();
                let serialized = serialize_ergo_box(&output_box).unwrap();
                model_a_insert.insert(box_id, serialized);
            }
        }

        // Model B: per-tx sequential
        let mut model_b_remove: BTreeMap<[u8; 32], ()> = BTreeMap::new();
        let mut model_b_insert: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

        for tx in &txs {
            let bts = bytes_to_sign(tx).unwrap();
            let tx_id = blake2b256(&bts);

            for input in &tx.inputs {
                let box_id = *input.box_id.as_bytes();
                model_b_remove.insert(box_id, ());
            }
            for (i, candidate) in tx.output_candidates.iter().enumerate() {
                let output_box = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id.into(),
                    index: i as u16,
                };
                let box_id = *output_box.box_id().unwrap().as_bytes();
                let serialized = serialize_ergo_box(&output_box).unwrap();
                model_b_insert.insert(box_id, serialized);
            }
        }

        let removes_match = model_a_remove == model_b_remove;
        let inserts_match = model_a_insert == model_b_insert;

        if !removes_match || !inserts_match {
            eprintln!(
                "height {}: MODELS DIFFER — removes_match={removes_match} inserts_match={inserts_match}",
                block.height
            );
            let a_removes: Vec<_> = model_a_remove.keys().collect();
            let b_removes: Vec<_> = model_b_remove.keys().collect();
            let extra_b = b_removes.iter().filter(|k| !a_removes.contains(k)).count();
            let extra_a = a_removes.iter().filter(|k| !b_removes.contains(k)).count();
            eprintln!(
                "  removes: A has {}, B has {} (extra_a={extra_a}, extra_b={extra_b})",
                a_removes.len(),
                b_removes.len()
            );
        } else {
            eprintln!(
                "height {}: models agree ({} removes, {} inserts)",
                block.height,
                model_a_remove.len(),
                model_a_insert.len()
            );
        }
    }
}

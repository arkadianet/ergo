//! Scala oracle for `merkle_proof_by_index`. Captures from live Scala
//! mainnet (`/blocks/{headerId}/proofFor/{txId}`) live in
//! `test-vectors/mainnet/proof_for_tx/` as `h{height}_{txId}.json`.
//!
//! Each fixture is matched against a proof we recompute from the same
//! block's transactions in `blocks_1_5.json` / `blocks_700000_700010.json`.
//! Byte-equal JSON (after re-serializing through our DTO) is the
//! parity invariant this test pins.
//!
//! Coverage:
//! - v1 blocks 1-5 (single-tx coinbase-only on this corpus) → exercises
//!   single-leaf padding (`InternalNode(Leaf, EmptyNode)`); proof has
//!   one empty-sibling level encoded as `""`.
//! - v2 block 700000 (3 txs → 6 leaves under `txIds ++ witnessIds`)
//!   → exercises a multi-level reduction whose intermediate level is
//!   odd-width (6 → 3 → 2 → 1). That level forces both an odd-trailing
//!   reduction in the root computation and an empty-sibling synthesis
//!   in proof extraction, which is the load-bearing case for the
//!   shared `build_levels` reducer in `ergo-crypto/src/merkle/mod.rs`.
//!
//! Gap: no Scala-backed proof for a v1 multi-tx block. Adding one
//! requires a fixture from a height with >1 tx in the v1 era.

use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::merkle::{merkle_proof_by_index, merkle_proof_verify};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use ergo_ser::transaction::{bytes_to_sign, read_transaction};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct BlockVector {
    height: u32,
    transactions: Vec<TxVector>,
}

#[derive(Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
}

#[derive(Deserialize)]
struct HeaderVector {
    height: u32,
    bytes: String,
}

#[derive(Deserialize, Debug)]
struct ScalaProof {
    #[serde(rename = "leafData")]
    leaf_data: String,
    levels: Vec<(String, u8)>,
}

fn load_blocks(path: &str) -> Vec<BlockVector> {
    let data = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&data).unwrap()
}

fn load_headers_map(path: &str) -> HashMap<u32, Header> {
    let data = std::fs::read_to_string(path).unwrap();
    let vectors: Vec<HeaderVector> = serde_json::from_str(&data).unwrap();
    vectors
        .into_iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            (v.height, read_header(&mut r).unwrap())
        })
        .collect()
}

fn tx_id(tx_bytes: &[u8]) -> [u8; 32] {
    let tx = read_transaction(&mut VlqReader::new(tx_bytes)).unwrap();
    blake2b256(&bytes_to_sign(&tx).unwrap())
}

fn witness_id(tx_bytes: &[u8]) -> Vec<u8> {
    let tx = read_transaction(&mut VlqReader::new(tx_bytes)).unwrap();
    let mut all_proofs = Vec::new();
    for input in &tx.inputs {
        all_proofs.extend_from_slice(&input.spending_proof.proof);
    }
    blake2b256(&all_proofs)[1..].to_vec()
}

/// Recompute the proof for `target_tx_id` against `block` and return
/// it in the Scala JSON shape `{leafData, levels: [[hex, side]]}`.
fn build_proof(block: &BlockVector, header: &Header, target_tx_id: &str) -> ScalaProof {
    let target = hex::decode(target_tx_id).unwrap();

    let tx_bytes_list: Vec<Vec<u8>> = block
        .transactions
        .iter()
        .map(|t| hex::decode(&t.bytes).unwrap())
        .collect();
    let tx_ids: Vec<[u8; 32]> = tx_bytes_list.iter().map(|b| tx_id(b)).collect();
    let mut target_index: Option<usize> = None;
    for (i, id) in tx_ids.iter().enumerate() {
        if id.as_slice() == target.as_slice() && target_index.is_none() {
            target_index = Some(i);
        }
    }
    let target_index = target_index.expect("target tx must be in block");

    let mut leaves: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
    let witnesses: Vec<Vec<u8>> = if header.version >= 2 {
        tx_bytes_list.iter().map(|b| witness_id(b)).collect()
    } else {
        Vec::new()
    };
    if header.version >= 2 {
        for w in &witnesses {
            leaves.push(w.as_slice());
        }
    }

    let proof = merkle_proof_by_index(&leaves, target_index).expect("proof");
    // Self-check before claiming parity.
    assert!(
        merkle_proof_verify(&proof, header.transactions_root.as_bytes()),
        "rust-side proof must verify against canonical transactions_root at h={}",
        block.height
    );

    ScalaProof {
        leaf_data: hex::encode(&proof.leaf_data),
        levels: proof
            .levels
            .into_iter()
            .map(|(s, side)| (hex::encode(s), side))
            .collect(),
    }
}

fn assert_proofs_equal(scala: &ScalaProof, ours: &ScalaProof, label: &str) {
    assert_eq!(
        scala.leaf_data, ours.leaf_data,
        "{label}: leafData mismatch"
    );
    assert_eq!(
        scala.levels.len(),
        ours.levels.len(),
        "{label}: levels count mismatch (scala={}, ours={})",
        scala.levels.len(),
        ours.levels.len(),
    );
    for (i, (s, o)) in scala.levels.iter().zip(ours.levels.iter()).enumerate() {
        assert_eq!(
            s.0, o.0,
            "{label}: level[{i}] sibling hex mismatch\n  scala: {}\n  ours:  {}",
            s.0, o.0,
        );
        assert_eq!(
            s.1, o.1,
            "{label}: level[{i}] side byte mismatch (scala={}, ours={})",
            s.1, o.1
        );
    }
}

fn run_oracle_for(block_fixture: &str, header_fixture: &str, height: u32) {
    let blocks = load_blocks(block_fixture);
    let headers = load_headers_map(header_fixture);
    let block = blocks
        .iter()
        .find(|b| b.height == height)
        .unwrap_or_else(|| panic!("no fixture block at height {height}"));
    let header = headers
        .get(&height)
        .unwrap_or_else(|| panic!("no fixture header at height {height}"));

    for tx in &block.transactions {
        let path = format!(
            "../test-vectors/mainnet/proof_for_tx/h{}_{}.json",
            height, tx.id
        );
        let scala_raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue, // fixture not captured for this tx
        };
        let scala: ScalaProof = serde_json::from_str(&scala_raw).expect("scala fixture must parse");
        let ours = build_proof(block, header, &tx.id);
        assert_proofs_equal(&scala, &ours, &format!("h={} tx={}", height, tx.id));
    }
}

#[test]
fn proof_oracle_v1_single_tx_blocks_1_through_5() {
    for h in [1u32, 2, 3, 4, 5] {
        run_oracle_for(
            "../test-vectors/mainnet/blocks_1_5.json",
            "../test-vectors/mainnet/headers_1_2000.json",
            h,
        );
    }
}

#[test]
#[ignore = "needs gitignored headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn proof_oracle_v2_block_700000_all_txs() {
    run_oracle_for(
        "../test-vectors/mainnet/blocks_700000_700010.json",
        "../test-vectors/mainnet/headers_700000_700500.json",
        700000,
    );
}

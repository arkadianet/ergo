//! Slice 3: Genesis state + height-1 digest verification.
//!
//! This test is the critical consensus gate for the AVL+ tree implementation.
//! It verifies that:
//! 1. Our serialization of the 3 genesis boxes produces the correct box_ids
//! 2. Inserting them into the AVL+ tree produces the correct genesis state digest
//! 3. Applying block 1's transaction produces the correct height-1 state digest

use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::token::Token;
use ergo_ser::transaction::{bytes_to_sign, read_transaction};
use ergo_state::avl::tree::AvlTree;

/// Expected genesis state digest (before block 1).
/// From mainnet.conf: genesisStateDigestHex
const GENESIS_STATE_DIGEST: &str =
    "a5df145d41ab15a01e0cd3ffbab046f0d029e5412293072ad0f5827428589b9302";

/// Expected state digest after applying block 1.
/// From test-vectors/mainnet/utxo_digests_1_10.json, height 1.
const HEIGHT_1_STATE_DIGEST: &str =
    "18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303";

#[derive(serde::Deserialize)]
struct GenesisBoxJson {
    #[serde(rename = "boxId")]
    box_id: String,
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u32,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: std::collections::HashMap<String, String>,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
}

#[derive(serde::Deserialize)]
struct BlockJson {
    #[serde(rename = "headerId")]
    _header_id: String,
    height: u32,
    transactions: Vec<TxJson>,
}

#[derive(serde::Deserialize)]
struct TxJson {
    #[allow(dead_code)]
    id: String,
    bytes: String,
}

fn parse_genesis_box(json: &GenesisBoxJson) -> ErgoBox {
    // Parse ErgoTree from hex
    let tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();

    // Parse additional registers
    let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
    for (key, val_hex) in &json.additional_registers {
        let reg_idx = match key.as_str() {
            "R4" => 0,
            "R5" => 1,
            "R6" => 2,
            "R7" => 3,
            "R8" => 4,
            "R9" => 5,
            _ => panic!("unknown register {key}"),
        };
        let val_bytes = hex::decode(val_hex).unwrap();
        let mut vr = VlqReader::new(&val_bytes);
        let (tpe, value) = read_constant(&mut vr).unwrap();
        reg_vec.push((reg_idx, RegisterValue { tpe, value }));
    }
    reg_vec.sort_by_key(|(idx, _)| *idx);
    let registers = AdditionalRegisters {
        registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
    };

    // Parse tokens (empty for genesis)
    let tokens: Vec<Token> = Vec::new();

    let candidate = ErgoBoxCandidate::new(
        json.value,
        ergo_tree,
        json.creation_height,
        tokens,
        registers,
    )
    .unwrap();

    // Parse transaction_id
    let tx_id_bytes: [u8; 32] = hex::decode(&json.transaction_id)
        .unwrap()
        .try_into()
        .unwrap();
    let transaction_id = ModifierId::from_bytes(tx_id_bytes);

    ErgoBox {
        candidate,
        transaction_id,
        index: json.index,
    }
}

#[test]
fn genesis_box_ids_match_api() {
    let data = std::fs::read_to_string("../test-vectors/mainnet/genesis_boxes.json").unwrap();
    let boxes: Vec<GenesisBoxJson> = serde_json::from_str(&data).unwrap();
    assert_eq!(boxes.len(), 3, "expected 3 genesis boxes");

    for json_box in &boxes {
        let ergo_box = parse_genesis_box(json_box);
        let computed_id = ergo_box.box_id().unwrap();
        let expected_id = hex::decode(&json_box.box_id).unwrap();
        assert_eq!(
            computed_id.as_bytes(),
            expected_id.as_slice(),
            "box_id mismatch for box {}",
            &json_box.box_id[..16]
        );
    }
}

#[test]
fn genesis_state_digest_matches_mainnet() {
    let data = std::fs::read_to_string("../test-vectors/mainnet/genesis_boxes.json").unwrap();
    let boxes: Vec<GenesisBoxJson> = serde_json::from_str(&data).unwrap();

    let mut tree = AvlTree::new();

    // Insert genesis boxes sorted by box_id (the AVL+ tree sorts internally,
    // but we verify the expected number of insertions)
    for json_box in &boxes {
        let ergo_box = parse_genesis_box(json_box);
        let box_id = ergo_box.box_id().unwrap();
        let serialized = serialize_ergo_box(&ergo_box).unwrap();
        tree.insert(*box_id.as_bytes(), serialized);
    }

    let digest = tree.root_digest();
    let expected = hex::decode(GENESIS_STATE_DIGEST).unwrap();
    assert_eq!(
        digest.as_bytes(),
        expected.as_slice(),
        "genesis state digest mismatch"
    );
}

#[test]
fn height_1_digest_after_block_1() {
    // Load genesis boxes
    let data = std::fs::read_to_string("../test-vectors/mainnet/genesis_boxes.json").unwrap();
    let genesis_boxes: Vec<GenesisBoxJson> = serde_json::from_str(&data).unwrap();

    let mut tree = AvlTree::new();
    for json_box in &genesis_boxes {
        let ergo_box = parse_genesis_box(json_box);
        let box_id = ergo_box.box_id().unwrap();
        let serialized = serialize_ergo_box(&ergo_box).unwrap();
        tree.insert(*box_id.as_bytes(), serialized);
    }

    // Verify genesis digest first
    let genesis_expected = hex::decode(GENESIS_STATE_DIGEST).unwrap();
    assert_eq!(
        tree.root_digest().as_bytes(),
        genesis_expected.as_slice(),
        "genesis state digest must match before applying block 1"
    );

    // Load block 1 transaction
    let blocks_data = std::fs::read_to_string("../test-vectors/mainnet/blocks_1_5.json").unwrap();
    let blocks: Vec<BlockJson> = serde_json::from_str(&blocks_data).unwrap();
    let block1 = blocks.iter().find(|b| b.height == 1).unwrap();
    assert_eq!(block1.transactions.len(), 1, "block 1 should have 1 tx");

    let tx_bytes = hex::decode(&block1.transactions[0].bytes).unwrap();
    let mut r = VlqReader::new(&tx_bytes);
    let tx = read_transaction(&mut r).unwrap();

    // Apply block 1's transaction.
    // Note: block 1 has exactly one transaction, so per-tx sequential and
    // batch-sorted application produce the same result. The correct ordering
    // model for multi-tx blocks is not yet proven — see Slice 4/5 for that.
    let txs = vec![&tx];
    let mut to_remove: std::collections::BTreeMap<[u8; 32], ()> = std::collections::BTreeMap::new();
    let mut to_insert: std::collections::BTreeMap<[u8; 32], Vec<u8>> =
        std::collections::BTreeMap::new();

    for tx in &txs {
        let bts = bytes_to_sign(tx).unwrap();
        let tx_id = blake2b256(&bts);

        for input in &tx.inputs {
            let box_id = *input.box_id.as_bytes();
            if to_insert.remove(&box_id).is_none() {
                to_remove.insert(box_id, ());
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
            to_insert.insert(box_id, serialized);
        }
    }

    // Apply removes first (sorted by key), then inserts (sorted by key)
    for box_id in to_remove.keys() {
        let removed = tree.remove(box_id);
        assert!(
            removed.is_some(),
            "input box {} should exist in UTXO set",
            hex::encode(box_id)
        );
    }
    for (box_id, serialized) in &to_insert {
        tree.insert(*box_id, serialized.clone());
    }

    // Verify height 1 state digest
    let digest = tree.root_digest();
    let expected = hex::decode(HEIGHT_1_STATE_DIGEST).unwrap();
    assert_eq!(
        digest.as_bytes(),
        expected.as_slice(),
        "height 1 state digest mismatch — AVL+ tree algorithm is incorrect"
    );
}

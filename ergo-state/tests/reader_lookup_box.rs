//! Integration coverage for `ChainStoreReader::lookup_box`.
//!
//! Proves four properties beyond what the inline unit tests cover:
//! - Raw-bytes equivalence with `StateStore::get_box_bytes` after a real
//!   commit (synthetic genesis + mainnet block 1-5).
//! - Cold restart: drop the writer, reopen, reader sees committed state.
//! - Rollback: after `rollback_to` rolls state back, the reader walks the
//!   restored tree, not the rolled-back one.
//! - Misses from a populated tree return `Ok(None)`, not `Err`.

use ergo_primitives::digest::{ADDigest, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::{read_transaction, transaction_id, Transaction};
use ergo_state::store::StateStore;

fn synthetic_boxes(count: u32) -> Vec<([u8; 32], Vec<u8>)> {
    (1u32..=count)
        .map(|i| {
            let mut id = [0u8; 32];
            id[28..].copy_from_slice(&i.to_be_bytes());
            // Vary length so byte-drift bugs surface on equality.
            let len = 16 + (i as usize % 96);
            (id, vec![(i & 0xFF) as u8; len])
        })
        .collect()
}

// ----- happy path -----

#[test]
fn empty_store_lookup_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    let reader = store.reader_handle();
    assert_eq!(reader.lookup_box(&[0u8; 32]).unwrap(), None);
    assert_eq!(reader.lookup_box(&[0xAA; 32]).unwrap(), None);
}

#[test]
fn synthetic_genesis_equivalence_raw_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    let boxes = synthetic_boxes(1024);
    store.initialize_genesis(&boxes).unwrap();
    let reader = store.reader_handle();

    for (id, expected) in &boxes {
        let oracle = store.get_box_bytes(id);
        assert_eq!(oracle.as_ref(), Some(expected), "oracle sanity check");
        let read = reader.lookup_box(id).unwrap();
        assert_eq!(
            read.as_ref(),
            oracle.as_ref(),
            "reader vs oracle byte mismatch for id={}",
            hex::encode(id)
        );
    }
}

#[test]
fn synthetic_genesis_misses_return_none() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    store.initialize_genesis(&synthetic_boxes(256)).unwrap();
    let reader = store.reader_handle();

    // High byte pattern outside the synthetic id space.
    for i in 0u32..32 {
        let mut id = [0xFFu8; 32];
        id[28..].copy_from_slice(&i.to_be_bytes());
        assert_eq!(reader.lookup_box(&id).unwrap(), None);
    }
}

#[test]
fn cold_restart_preserves_lookups() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let boxes = synthetic_boxes(1024);
    {
        let mut store = StateStore::open(&path).unwrap();
        store.initialize_genesis(&boxes).unwrap();
    }

    let store = StateStore::open(&path).unwrap();
    let reader = store.reader_handle();
    for (id, expected) in &boxes {
        assert_eq!(
            reader.lookup_box(id).unwrap().as_ref(),
            Some(expected),
            "post-restart miss for id={}",
            hex::encode(id),
        );
    }
}

// ---- Mainnet-fixture-driven helpers (mirrors persistent_blocks_1_10) ----

#[derive(serde::Deserialize)]
#[allow(dead_code)]
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
struct DigestJson {
    height: u32,
    #[serde(rename = "stateRoot")]
    state_root: String,
}

fn parse_genesis_box(json: &GenesisBoxJson) -> ErgoBox {
    let tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();
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
    let candidate = ErgoBoxCandidate::new(
        json.value,
        ergo_tree,
        json.creation_height,
        Vec::new(),
        registers,
    )
    .unwrap();
    let tx_id_bytes: [u8; 32] = hex::decode(&json.transaction_id)
        .unwrap()
        .try_into()
        .unwrap();
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id_bytes),
        index: json.index,
    }
}

fn init_mainnet_genesis(store: &mut StateStore) -> Vec<[u8; 32]> {
    let genesis_data =
        std::fs::read_to_string("../test-vectors/mainnet/genesis_boxes.json").unwrap();
    let genesis_boxes: Vec<GenesisBoxJson> = serde_json::from_str(&genesis_data).unwrap();
    let boxes: Vec<([u8; 32], Vec<u8>)> = genesis_boxes
        .iter()
        .map(|json_box| {
            let ergo_box = parse_genesis_box(json_box);
            let box_id = ergo_box.box_id().unwrap();
            let serialized = serialize_ergo_box(&ergo_box).unwrap();
            (*box_id.as_bytes(), serialized)
        })
        .collect();
    let ids = boxes.iter().map(|(id, _)| *id).collect();
    store.initialize_genesis(&boxes).unwrap();
    ids
}

fn parse_block_tx(tx_hex: &str) -> Transaction {
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let mut r = VlqReader::new(&tx_bytes);
    read_transaction(&mut r).unwrap()
}

struct TestData {
    digests: Vec<DigestJson>,
    all_txs: Vec<serde_json::Value>,
    headers: Vec<serde_json::Value>,
}

fn load_test_data() -> TestData {
    let digests_data =
        std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    TestData {
        digests: serde_json::from_str(&digests_data).unwrap(),
        all_txs: serde_json::from_str(&tx_data).unwrap(),
        headers: serde_json::from_str(&headers_data).unwrap(),
    }
}

fn apply_blocks(store: &mut StateStore, data: &TestData, from: u32, to: u32) -> Vec<[u8; 32]> {
    let mut output_ids = Vec::new();
    for height in from..=to {
        let expected = data.digests.iter().find(|d| d.height == height).unwrap();
        let expected_digest = ADDigest::from_bytes(
            hex::decode(&expected.state_root)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let tx_entry = data
            .all_txs
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
        let tx_id = transaction_id(&tx).unwrap();
        for (idx, candidate) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: candidate.clone(),
                transaction_id: tx_id,
                index: idx as u16,
            };
            let box_id = ergo_box.box_id().unwrap();
            output_ids.push(*box_id.as_bytes());
        }
        let header = data
            .headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        store
            .apply_block_unchecked_for_test(height, &header_id, &expected_digest, &[tx])
            .unwrap_or_else(|e| panic!("apply_block failed at height {height}: {e}"));
    }
    output_ids
}

#[test]
fn post_block_application_matches_oracle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).unwrap();
    let genesis_ids = init_mainnet_genesis(&mut store);
    let data = load_test_data();
    let block_output_ids = apply_blocks(&mut store, &data, 1, 5);

    let reader = store.reader_handle();
    let mut hits = 0usize;
    let mut misses = 0usize;
    for id in genesis_ids.iter().chain(block_output_ids.iter()) {
        let oracle = store.get_box_bytes(id);
        let read = reader.lookup_box(id).unwrap();
        assert_eq!(
            read.as_ref(),
            oracle.as_ref(),
            "reader vs oracle mismatch for id={}",
            hex::encode(id),
        );
        if oracle.is_some() {
            hits += 1;
        } else {
            misses += 1;
        }
    }
    // Sanity: the run must exercise both Some and None paths.
    assert!(hits > 0, "no hits across genesis + block outputs");
    assert!(
        misses > 0,
        "no misses — block 1-5 should have spent something"
    );
}

#[test]
fn post_reorg_matches_oracle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).unwrap();
    let genesis_ids = init_mainnet_genesis(&mut store);
    let data = load_test_data();
    let block_output_ids = apply_blocks(&mut store, &data, 1, 5);

    // Pre-reorg: capture what the oracle says about every id.
    let pre: Vec<(_, _)> = genesis_ids
        .iter()
        .chain(block_output_ids.iter())
        .map(|id| (*id, store.get_box_bytes(id)))
        .collect();

    // Pure rollback to height 3 — exercise the same surface the
    // production sync layer uses (`rollback_to` followed by forward-
    // apply of the new chain).
    store.rollback_to(3, None, None).unwrap();
    assert_eq!(store.height(), 3);

    // Post-reorg: the oracle and reader must both walk the rolled-back tree.
    // At least one id whose state changed across the reorg proves the reader
    // didn't pin to the old root_node_id.
    let reader = store.reader_handle();
    let mut state_changed = false;
    for (id, pre_oracle) in &pre {
        let post_oracle = store.get_box_bytes(id);
        let read = reader.lookup_box(id).unwrap();
        assert_eq!(
            read.as_ref(),
            post_oracle.as_ref(),
            "post-reorg reader vs oracle mismatch for id={}",
            hex::encode(id),
        );
        if pre_oracle != &post_oracle {
            state_changed = true;
        }
    }
    assert!(
        state_changed,
        "rollback from h=5 to h=3 changed nothing — fixtures or reorg semantics drifted",
    );
}

// ----- committed-snapshot opener (off-loop) -----

#[test]
fn committed_snapshot_opener_matches_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    // No committed state yet: the off-loop opener yields no snapshot.
    assert!(
        store
            .reader_handle()
            .committed_snapshot()
            .unwrap()
            .is_none(),
        "pre-genesis store must yield no snapshot via the reader opener"
    );

    store.initialize_genesis(&synthetic_boxes(64)).unwrap();

    // After genesis the off-loop reader opener returns a snapshot at the same
    // committed tip + state root as the on-loop StateStore opener.
    let via_reader = store
        .reader_handle()
        .committed_snapshot()
        .unwrap()
        .expect("reader snapshot");
    let via_store = store.committed_snapshot().unwrap().expect("store snapshot");
    assert_eq!(
        via_reader.best_full_block_id(),
        via_store.best_full_block_id()
    );
    assert_eq!(
        via_reader.best_full_block_height(),
        via_store.best_full_block_height()
    );
    assert_eq!(via_reader.state_root(), via_store.state_root());
}

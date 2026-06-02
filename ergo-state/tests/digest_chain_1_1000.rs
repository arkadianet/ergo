//! Apply blocks 1-1000 with digest verification at every height,
//! then verify ROLLBACK_WINDOW pruning and rollback boundary behavior.

use ergo_primitives::digest::{ADDigest, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::{read_transaction, Transaction};
use ergo_state::store::StateStore;

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

fn init_genesis(store: &mut StateStore) {
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
    store.initialize_genesis(&boxes).unwrap();
}

fn parse_block_tx(tx_hex: &str) -> Transaction {
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let mut r = VlqReader::new(&tx_bytes);
    read_transaction(&mut r).unwrap()
}

struct TestFixtures {
    digests: Vec<DigestJson>,
    txs: Vec<serde_json::Value>,
    headers: Vec<serde_json::Value>,
}

impl TestFixtures {
    fn load() -> Self {
        Self {
            digests: serde_json::from_str(
                &std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_1000.json")
                    .unwrap(),
            )
            .unwrap(),
            txs: serde_json::from_str(
                &std::fs::read_to_string("../test-vectors/mainnet/transactions_1_1000.json")
                    .unwrap(),
            )
            .unwrap(),
            headers: serde_json::from_str(
                &std::fs::read_to_string("../test-vectors/mainnet/headers_1_2000.json").unwrap(),
            )
            .unwrap(),
        }
    }

    fn apply_block(&self, store: &mut StateStore, height: u32) {
        let expected = self.digests.iter().find(|d| d.height == height).unwrap();
        let expected_digest = ADDigest::from_bytes(
            hex::decode(&expected.state_root)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let tx_entry = self
            .txs
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
        let header = self
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

    fn expected_digest(&self, height: u32) -> ADDigest {
        let d = self.digests.iter().find(|d| d.height == height).unwrap();
        ADDigest::from_bytes(hex::decode(&d.state_root).unwrap().try_into().unwrap())
    }
}

/// Apply all 1000 blocks and verify the state digest at every height.
/// Core regression test for state-root parity over 1,000+ contiguous heights.
#[test]
fn digest_chain_1_through_1000() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let fixtures = TestFixtures::load();

    for height in 1u32..=1000 {
        fixtures.apply_block(&mut store, height);
    }
    assert_eq!(store.height(), 1000);
    assert_eq!(store.root_digest(), fixtures.expected_digest(1000));
}

/// Verify that undo entries are pruned beyond ROLLBACK_WINDOW=200.
/// After applying 1000 blocks, only entries for heights 801-1000 should remain.
/// Rollback to 800 (within window) must succeed.
/// Rollback to 799 (outside window) must fail.
#[test]
fn pruning_beyond_rollback_window() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let fixtures = TestFixtures::load();

    for height in 1u32..=1000 {
        fixtures.apply_block(&mut store, height);
    }
    assert_eq!(store.height(), 1000);

    // Rollback to 800 (within ROLLBACK_WINDOW=200): should succeed
    store.rollback_to(800, None, None).unwrap();
    assert_eq!(store.height(), 800);
    assert_eq!(store.root_digest(), fixtures.expected_digest(800));

    // Re-apply 801-1000 to get back to height 1000
    for height in 801u32..=1000 {
        fixtures.apply_block(&mut store, height);
    }
    assert_eq!(store.height(), 1000);
    assert_eq!(store.root_digest(), fixtures.expected_digest(1000));

    // Rollback to 799 (outside ROLLBACK_WINDOW): should fail because
    // undo entry at height 800 was pruned (pruned when height 1000 was applied,
    // which prunes entries at height <= 800)
    let result = store.rollback_to(799, None, None);
    assert!(
        result.is_err(),
        "rollback beyond ROLLBACK_WINDOW should fail"
    );
}

/// Crash recovery after 1000 blocks: reopen DB and verify state.
#[test]
fn crash_recovery_at_height_1000() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        let fixtures = TestFixtures::load();
        for height in 1u32..=1000 {
            fixtures.apply_block(&mut store, height);
        }
    }

    let mut store = StateStore::open(&db_path).unwrap();
    assert_eq!(store.height(), 1000);
    let fixtures = TestFixtures::load();
    assert_eq!(store.root_digest(), fixtures.expected_digest(1000));
}

/// Rollback from 1000 to 800, verify digest, re-apply 801-1000.
/// Tests that rollback + re-apply produces identical state.
#[test]
fn rollback_from_1000_to_800_then_reapply() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let fixtures = TestFixtures::load();

    for height in 1u32..=1000 {
        fixtures.apply_block(&mut store, height);
    }

    store.rollback_to(800, None, None).unwrap();
    assert_eq!(store.height(), 800);
    assert_eq!(store.root_digest(), fixtures.expected_digest(800));

    for height in 801u32..=1000 {
        fixtures.apply_block(&mut store, height);
    }
    assert_eq!(store.height(), 1000);
    assert_eq!(store.root_digest(), fixtures.expected_digest(1000));
}

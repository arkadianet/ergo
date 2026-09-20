//! Slice 5: Apply blocks 1-200 with digest verification at every height.
//! Test rollback over longer ranges.

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
                &std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_200.json")
                    .unwrap(),
            )
            .unwrap(),
            txs: serde_json::from_str(
                &std::fs::read_to_string("../test-vectors/mainnet/transactions_1_200.json")
                    .unwrap(),
            )
            .unwrap(),
            headers: serde_json::from_str(
                &std::fs::read_to_string("../test-vectors/mainnet/headers_1_500.json").unwrap(),
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

/// Apply all 200 blocks and verify the state digest at every height.
#[test]
fn digest_chain_1_through_200() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let fixtures = TestFixtures::load();

    for height in 1u32..=200 {
        fixtures.apply_block(&mut store, height);
    }
    assert_eq!(store.height(), 200);
    assert_eq!(store.root_digest(), fixtures.expected_digest(200));
}

/// Rollback from 200 to 100, verify digest, re-apply 101-200.
#[test]
fn rollback_from_200_to_100_then_reapply() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let fixtures = TestFixtures::load();

    for height in 1u32..=200 {
        fixtures.apply_block(&mut store, height);
    }

    store.rollback_to(100, None, None).unwrap();
    assert_eq!(store.height(), 100);
    assert_eq!(store.root_digest(), fixtures.expected_digest(100));

    // Re-apply 101-200
    for height in 101u32..=200 {
        fixtures.apply_block(&mut store, height);
    }
    assert_eq!(store.height(), 200);
    assert_eq!(store.root_digest(), fixtures.expected_digest(200));
}

/// Rollback to genesis from height 200, verify genesis digest.
#[test]
fn rollback_from_200_to_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let fixtures = TestFixtures::load();

    let genesis_digest = store.root_digest();

    for height in 1u32..=200 {
        fixtures.apply_block(&mut store, height);
    }

    store.rollback_to(0, None, None).unwrap();
    assert_eq!(store.height(), 0);
    assert_eq!(store.root_digest(), genesis_digest);
}

/// Crash recovery after 200 blocks: reopen and verify state.
#[test]
fn crash_recovery_at_height_200() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        let fixtures = TestFixtures::load();
        for height in 1u32..=200 {
            fixtures.apply_block(&mut store, height);
        }
    }

    // Reopen
    let mut store = StateStore::open(&db_path).unwrap();
    assert_eq!(store.height(), 200);
    let fixtures = TestFixtures::load();
    assert_eq!(store.root_digest(), fixtures.expected_digest(200));
}

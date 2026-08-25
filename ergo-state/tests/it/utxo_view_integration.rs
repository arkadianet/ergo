//! Slice 6: UtxoView integration — validate transactions using real state store.
//!
//! Replaces the TestUtxo HashMap mock with StateStore-backed UtxoView for
//! the blocks 2-10 chain validation test. Block 1 is used to bootstrap
//! the state (same as the original test).

use ergo_primitives::digest::{ADDigest, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::read_transaction;
use ergo_state::store::StateStore;
use ergo_validation::{
    validate_transaction, CostAccumulator, LocalPolicy, ProtocolParams, TransactionContext,
};

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
struct TxVector {
    id: String,
    bytes: String,
    height: u32,
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

fn load_header_info(path: &str) -> std::collections::HashMap<u32, ([u8; 33], u64)> {
    let data = std::fs::read_to_string(path).unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
    let mut info = std::collections::HashMap::new();
    for h in &headers {
        let height = h["height"].as_u64().unwrap() as u32;
        let header_bytes = hex::decode(h["bytes"].as_str().unwrap()).unwrap();
        let mut r = VlqReader::new(&header_bytes);
        let header = ergo_ser::header::read_header(&mut r).unwrap();
        let pk = *header.solution.pk().as_bytes();
        info.insert(height, (pk, header.timestamp));
    }
    info
}

/// Validate transactions in blocks 2-10 using real StateStore-backed UTXO.
///
/// This replaces the TestUtxo HashMap mock from tx_validation_corpus.rs
/// with a real persistent state store. Block 1 bootstraps the state
/// (same as the original test — block 1's genesis input requires special handling).
#[test]
fn chain_validate_blocks_2_10_with_state_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);

    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let vectors: Vec<TxVector> = serde_json::from_str(&tx_data).unwrap();
    let digests_data =
        std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
    let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&headers_data).unwrap();
    let header_info = load_header_info("../test-vectors/mainnet/headers_1_10.json");

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();

    // Apply block 1 to state store (bootstrap, not validated)
    let v1 = &vectors[0];
    let tx1_bytes = hex::decode(&v1.bytes).unwrap();
    let mut r = VlqReader::new(&tx1_bytes);
    let tx1 = read_transaction(&mut r).unwrap();
    let expected_1 = digests.iter().find(|d| d.height == 1).unwrap();
    let expected_digest_1 = ADDigest::from_bytes(
        hex::decode(&expected_1.state_root)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let header_1 = headers
        .iter()
        .find(|h| h["height"].as_u64().unwrap() == 1)
        .unwrap();
    let header_id_1: [u8; 32] = hex::decode(header_1["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    store
        .apply_block_unchecked_for_test(1, &header_id_1, &expected_digest_1, &[tx1])
        .unwrap();

    // Validate blocks 2-10 using the store as UtxoView
    let mut validated = 0;
    for v in &vectors[1..] {
        let tx_bytes = hex::decode(&v.bytes).unwrap();
        let (miner_pubkey, timestamp) = *header_info.get(&v.height).unwrap();
        let ctx = TransactionContext {
            height: v.height,
            miner_pubkey,
            pre_header_timestamp: timestamp,
            activated_script_version: 0,
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        };
        let mut cost = CostAccumulator::recording_only();
        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
            rules: ergo_validation::TxValidationRules::default(),
        };

        match validate_transaction(&tx_bytes, &store, &policy, &mut tx_cx) {
            Ok(checked) => {
                let computed_id =
                    ergo_ser::transaction::transaction_id(checked.transaction()).unwrap();
                assert_eq!(
                    hex::encode(computed_id.as_bytes()),
                    v.id,
                    "tx ID mismatch at height {}",
                    v.height
                );

                // Apply validated tx to state — type boundary enforced:
                // apply_block requires CheckedTransaction, not raw Transaction
                let expected = digests.iter().find(|d| d.height == v.height).unwrap();
                let expected_digest = ADDigest::from_bytes(
                    hex::decode(&expected.state_root)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                );
                let header = headers
                    .iter()
                    .find(|h| h["height"].as_u64().unwrap() == v.height as u64)
                    .unwrap();
                let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                store
                    .apply_block_checked_for_test(
                        v.height,
                        &header_id,
                        &expected_digest,
                        &[checked],
                    )
                    .unwrap();

                validated += 1;
            }
            Err(e) => {
                panic!(
                    "height {} tx {}: validation failed with real state store: {e}",
                    v.height,
                    &v.id[..16]
                );
            }
        }
    }

    assert_eq!(validated, 9, "should validate 9 blocks (2-10)");
    assert_eq!(store.height(), 10);
}

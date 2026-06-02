//! Full block validation with state: header + tx root + ext root + section IDs
//! + transaction validation + state application for blocks 1-5.
//!
//! Uses `validate_full_block` from ergo-validation for the complete pipeline.

use std::collections::HashMap;

use ergo_primitives::digest::{ADDigest, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::BlockTransactions;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_ser::header::{read_header, serialize_header, Header};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::read_transaction;
use ergo_state::store::StateStore;
use ergo_validation::block::validate_full_block;
use ergo_validation::context::ProtocolParams;

use serde::Deserialize;

#[derive(Deserialize)]
struct BlockJson {
    #[serde(rename = "headerId")]
    header_id: String,
    height: u32,
    transactions: Vec<TxJson>,
    extension: ExtJson,
}

#[derive(Deserialize)]
struct TxJson {
    #[allow(dead_code)]
    id: String,
    bytes: String,
}

#[derive(Deserialize)]
struct ExtJson {
    #[serde(rename = "headerId")]
    header_id: Option<String>,
    #[allow(dead_code)]
    digest: String,
    fields: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct HeaderVec {
    height: u32,
    bytes: String,
}

#[derive(Deserialize)]
struct DigestJson {
    height: u32,
    #[serde(rename = "stateRoot")]
    state_root: String,
}

#[derive(Deserialize)]
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
    additional_registers: HashMap<String, String>,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
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

fn serialize_ergo_box(b: &ErgoBox) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::ergo_box::write_ergo_box(&mut w, b).unwrap();
    w.result()
}

fn load_headers_map(path: &str) -> HashMap<u32, (Header, [u8; 32])> {
    let data = std::fs::read_to_string(path).unwrap();
    let vecs: Vec<HeaderVec> = serde_json::from_str(&data).unwrap();
    vecs.iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            let h = read_header(&mut r).unwrap();
            let (_, id) = serialize_header(&h).expect("real mainnet header serializes");
            (v.height, (h, *id.as_bytes()))
        })
        .collect()
}

fn build_block_transactions(block: &BlockJson) -> BlockTransactions {
    let header_id =
        ModifierId::from_bytes(hex::decode(&block.header_id).unwrap().try_into().unwrap());
    let txs = block
        .transactions
        .iter()
        .map(|t| {
            let bytes = hex::decode(&t.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            read_transaction(&mut r).unwrap()
        })
        .collect();
    BlockTransactions {
        header_id,
        transactions: txs,
    }
}

fn build_extension(block: &BlockJson) -> Extension {
    let hid_hex = block
        .extension
        .header_id
        .as_deref()
        .unwrap_or(&block.header_id);
    let header_id = ModifierId::from_bytes(hex::decode(hid_hex).unwrap().try_into().unwrap());
    let fields = block
        .extension
        .fields
        .iter()
        .map(|(k, v)| ExtensionField {
            key: hex::decode(k).unwrap().try_into().unwrap(),
            value: hex::decode(v).unwrap(),
        })
        .collect();
    Extension { header_id, fields }
}

#[test]
fn full_block_pipeline_blocks_1_5() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    // Genesis
    let genesis_data =
        std::fs::read_to_string("../test-vectors/mainnet/genesis_boxes.json").unwrap();
    let genesis_boxes: Vec<GenesisBoxJson> = serde_json::from_str(&genesis_data).unwrap();
    let boxes: Vec<([u8; 32], Vec<u8>)> = genesis_boxes
        .iter()
        .map(|gb| {
            let b = parse_genesis_box(gb);
            let id = b.box_id().unwrap();
            let ser = serialize_ergo_box(&b);
            (*id.as_bytes(), ser)
        })
        .collect();
    store.initialize_genesis(&boxes).unwrap();

    // Vectors
    let blocks_data = std::fs::read_to_string("../test-vectors/mainnet/blocks_1_5.json").unwrap();
    let blocks: Vec<BlockJson> = serde_json::from_str(&blocks_data).unwrap();
    let headers = load_headers_map("../test-vectors/mainnet/headers_1_2000.json");
    let digests_data =
        std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
    let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
    let params = ProtocolParams::mainnet_default();

    // Block 1: apply unchecked (no parent to validate against)
    let b1 = &blocks[0];
    assert_eq!(b1.height, 1);
    let bt1 = build_block_transactions(b1);
    let (_, ref hid1) = headers[&1];
    let d1 = digests.iter().find(|d| d.height == 1).unwrap();
    let expected1 = ADDigest::from_bytes(hex::decode(&d1.state_root).unwrap().try_into().unwrap());
    store
        .apply_block_unchecked_for_test(1, hid1, &expected1, &bt1.transactions)
        .unwrap();

    // Blocks 2-5: full pipeline
    let mut validated = 0;
    for block in blocks.iter().skip(1) {
        let (ref header, ref header_id) = headers[&block.height];
        let (ref parent, ref parent_id) = headers[&(block.height - 1)];

        let bt = build_block_transactions(block);
        let ext = build_extension(block);

        let checked_parent =
            ergo_validation::header::CheckedHeader::trust_me(parent.clone(), *parent_id);
        let block_ctx = ergo_validation::block::BlockValidationContext {
            parent: &checked_parent,
            utxo: &store,
            params: &params,
            voting_length: 1024,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &[],
            script_validation_checkpoint: None,
        };
        let checked_header =
            ergo_validation::header::CheckedHeader::trust_me(header.clone(), *header_id);
        let checked_block = validate_full_block(checked_header, &bt, &ext, &block_ctx)
            .unwrap_or_else(|e| {
                panic!(
                    "full block validation failed at height {}: {e}",
                    block.height
                );
            });

        let tx_count = checked_block.transactions().len();
        store.apply_block(&checked_block, None, None).unwrap();

        validated += 1;
        eprintln!(
            "OK: h={} ({} txs) state_root verified",
            block.height, tx_count
        );
    }
    assert_eq!(validated, 4);
    assert_eq!(store.height(), 5);
    eprintln!("full_block_pipeline: {validated} blocks fully validated with state");
}

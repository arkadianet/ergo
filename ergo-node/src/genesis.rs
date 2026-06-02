//! Genesis box loading for state initialization.

use ergo_chain_spec::Network;
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;

#[derive(serde::Deserialize)]
struct GenesisBoxJson {
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

pub fn mainnet_genesis_boxes() -> Vec<([u8; 32], Vec<u8>)> {
    let json = include_str!("../../test-vectors/mainnet/genesis_boxes.json");
    parse_genesis_boxes(json)
}

pub fn testnet_genesis_boxes() -> Vec<([u8; 32], Vec<u8>)> {
    let json = include_str!("../../test-vectors/testnet/genesis_boxes.json");
    parse_genesis_boxes(json)
}

/// Network-aware genesis seeding. Sole entry point for runtime
/// initialization — keeps the `match Network` arm contained to one
/// place so callers stay network-agnostic.
pub fn genesis_boxes_for(network: Network) -> Vec<([u8; 32], Vec<u8>)> {
    match network {
        Network::Mainnet => mainnet_genesis_boxes(),
        Network::Testnet => testnet_genesis_boxes(),
    }
}

fn parse_genesis_boxes(json: &str) -> Vec<([u8; 32], Vec<u8>)> {
    let boxes: Vec<GenesisBoxJson> =
        serde_json::from_str(json).expect("failed to parse genesis boxes JSON");
    boxes
        .iter()
        .map(|jb| {
            let ergo_box = parse_one_box(jb);
            let box_id = ergo_box.box_id().expect("genesis box_id");
            let serialized = serialize_ergo_box(&ergo_box).expect("genesis serialize");
            (*box_id.as_bytes(), serialized)
        })
        .collect()
}

fn parse_one_box(json: &GenesisBoxJson) -> ErgoBox {
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
    let tx_id: [u8; 32] = hex::decode(&json.transaction_id)
        .unwrap()
        .try_into()
        .unwrap();
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id),
        index: json.index,
    }
}

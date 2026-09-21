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

/// Genesis seeding from the resolved chain spec.
///
/// Reads the spec's own `boxes_json` rather than re-deriving a box set
/// from the network name: on devnet the box set is selected by
/// `monetary.minerRewardDelay` (the delay is compiled into the emission
/// box's proposition), so a network-keyed lookup would seed the 720-delay
/// boxes into a chain whose peers agreed on a different genesis root —
/// a fork at height 0 that only shows up much later.
pub fn genesis_boxes_for_spec(
    genesis: &ergo_chain_spec::GenesisParams,
) -> Vec<([u8; 32], Vec<u8>)> {
    parse_genesis_boxes(
        genesis
            .boxes_json
            .expect("chain spec carries genesis boxes (checked at config load)"),
    )
}

/// Network-aware genesis seeding for callers that hold only a
/// `Network`. Equivalent to [`genesis_boxes_for_spec`] over that
/// network's pinned spec; runtime boot uses the spec form, because a
/// devnet spec can carry a different box set.
pub fn genesis_boxes_for(network: Network) -> Vec<([u8; 32], Vec<u8>)> {
    genesis_boxes_for_spec(&ergo_chain_spec::GenesisParams::for_network(network))
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

#[cfg(test)]
mod spec_tests {
    use super::*;

    // ----- happy path -----

    /// The devnet box set follows `monetary.minerRewardDelay`, not the
    /// network name. Seeding by network would put the 720-delay emission
    /// box into a chain whose peers agreed on the 10-delay genesis root.
    #[test]
    fn devnet_reward_delay_10_seeds_a_different_box_set() {
        let stock = genesis_boxes_for_spec(&ergo_chain_spec::GenesisParams::devnet());
        let shortened = genesis_boxes_for_spec(
            &ergo_chain_spec::GenesisParams::devnet_for_reward_delay(10).expect("captured"),
        );
        assert_eq!(stock.len(), shortened.len(), "same three genesis boxes");
        assert_ne!(stock[0], shortened[0], "the emission box differs");
        assert_eq!(
            &stock[1..],
            &shortened[1..],
            "only the emission box differs"
        );
    }

    #[test]
    fn genesis_boxes_for_network_matches_the_pinned_spec() {
        for net in [Network::Mainnet, Network::Testnet, Network::Devnet] {
            assert_eq!(
                genesis_boxes_for(net),
                genesis_boxes_for_spec(&ergo_chain_spec::GenesisParams::for_network(net)),
                "{net:?}"
            );
        }
    }
}

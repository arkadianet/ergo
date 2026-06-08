//! State-backed full block validation for v2 blocks 700,000-700,010.
//!
//! Exercises `validate_full_block()` on modern v2 multi-tx blocks with
//! real transaction validation using pre-extracted input boxes.
//! Uses HashMap UTXO (not StateStore) since we don't have full UTXO state
//! at 699,999. State root verification is proven separately on blocks 1-10k.

use std::collections::HashMap;

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::BlockTransactions;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_ser::header::{read_header, serialize_header, Header};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::read_transaction;
use ergo_validation::block::validate_full_block;
use ergo_validation::context::{ProtocolParams, UtxoView};

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
#[allow(dead_code)]
struct InputBoxJson {
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
    #[serde(default)]
    assets: Vec<AssetJson>,
}
#[derive(Deserialize)]
#[allow(dead_code)]
struct AssetJson {
    #[serde(rename = "tokenId")]
    token_id: String,
    amount: u64,
}

fn parse_input_box(json: &InputBoxJson) -> ErgoBox {
    let ergo_tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();

    // Parse registers and build register_bytes verbatim from raw hex,
    // so box.bytes (ExtractBytes 0xC3) matches Scala's emitted bytes.
    let mut reg_entries: Vec<(usize, Vec<u8>, RegisterValue)> = Vec::new();
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
        let raw = hex::decode(val_hex).unwrap();
        let mut vr = VlqReader::new(&raw);
        let (tpe, value) = read_constant(&mut vr).unwrap();
        reg_entries.push((reg_idx, raw, RegisterValue { tpe, value }));
    }
    reg_entries.sort_by_key(|(idx, _, _)| *idx);

    // Build register_bytes: count + verbatim raw bytes per register
    let mut register_bytes = Vec::new();
    register_bytes.push(reg_entries.len() as u8);
    for (_, raw, _) in &reg_entries {
        register_bytes.extend_from_slice(raw);
    }

    let registers = AdditionalRegisters {
        registers: reg_entries.into_iter().map(|(_, _, rv)| rv).collect(),
    };
    let tokens: Vec<ergo_ser::token::Token> = json
        .assets
        .iter()
        .map(|a| {
            let id: [u8; 32] = hex::decode(&a.token_id).unwrap().try_into().unwrap();
            ergo_ser::token::Token {
                token_id: ergo_primitives::digest::Digest32::from_bytes(id),
                amount: a.amount,
            }
        })
        .collect();
    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        json.value,
        ergo_tree,
        ergo_tree_bytes,
        json.creation_height,
        tokens,
        registers,
        register_bytes,
    );
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

struct MapUtxo {
    boxes: HashMap<Digest32, ErgoBox>,
}
impl MapUtxo {
    fn new() -> Self {
        Self {
            boxes: HashMap::new(),
        }
    }
    fn insert(&mut self, b: ErgoBox) {
        if let Ok(id) = b.box_id() {
            self.boxes.insert(id, b);
        }
    }
    fn apply_checked(&mut self, checked: &[ergo_validation::CheckedTransaction]) {
        for c in checked {
            for input in &c.transaction().inputs {
                self.boxes.remove(&input.box_id);
            }
            let tx_id = ergo_ser::transaction::transaction_id(c.transaction()).unwrap();
            for (i, cand) in c.transaction().output_candidates.iter().enumerate() {
                self.insert(ErgoBox {
                    candidate: cand.clone(),
                    transaction_id: tx_id,
                    index: i as u16,
                });
            }
        }
    }
}
impl UtxoView for MapUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.boxes.get(box_id).cloned()
    }
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

fn build_bt(block: &BlockJson) -> BlockTransactions {
    let hid = ModifierId::from_bytes(hex::decode(&block.header_id).unwrap().try_into().unwrap());
    let txs = block
        .transactions
        .iter()
        .map(|t| {
            let b = hex::decode(&t.bytes).unwrap();
            let mut r = VlqReader::new(&b);
            read_transaction(&mut r).unwrap()
        })
        .collect();
    BlockTransactions {
        header_id: hid,
        transactions: txs,
    }
}

fn build_ext(block: &BlockJson) -> Extension {
    let hid_hex = block
        .extension
        .header_id
        .as_deref()
        .unwrap_or(&block.header_id);
    let hid = ModifierId::from_bytes(hex::decode(hid_hex).unwrap().try_into().unwrap());
    let fields = block
        .extension
        .fields
        .iter()
        .map(|(k, v)| ExtensionField {
            key: hex::decode(k).unwrap().try_into().unwrap(),
            value: hex::decode(v).unwrap(),
        })
        .collect();
    Extension {
        header_id: hid,
        fields,
    }
}

#[test]
#[ignore = "needs gitignored headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn full_block_v2_700k_with_state() {
    let input_data =
        std::fs::read_to_string("../test-vectors/mainnet/input_boxes_700000_700010.json").unwrap();
    let input_boxes: Vec<InputBoxJson> = serde_json::from_str(&input_data).unwrap();
    let mut utxo = MapUtxo::new();
    for ib in &input_boxes {
        utxo.insert(parse_input_box(ib));
    }
    eprintln!("Seeded UTXO with {} input boxes", input_boxes.len());

    let blocks: Vec<BlockJson> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/blocks_700000_700010.json").unwrap(),
    )
    .unwrap();
    let headers = load_headers_map("../test-vectors/mainnet/headers_700000_700500.json");
    let params = ProtocolParams::mainnet_default();

    let mut sorted_heights: Vec<u32> = headers.keys().copied().collect();
    sorted_heights.sort();

    let mut validated = 0u32;
    let mut total_txs = 0usize;

    for block in &blocks {
        let (ref header, ref header_id) = match headers.get(&block.height) {
            Some(h) => h,
            None => continue,
        };
        let (ref parent, ref parent_id) = match headers.get(&(block.height - 1)) {
            Some(h) => h,
            None => continue,
        };

        let bt = build_bt(block);
        let ext = build_ext(block);

        let checked_last: Vec<ergo_validation::header::CheckedHeader> = {
            let pos = sorted_heights.partition_point(|&h| h < block.height);
            let start = pos.saturating_sub(10);
            sorted_heights[start..pos]
                .iter()
                .filter_map(|h| {
                    headers.get(h).map(|(hdr, id)| {
                        ergo_validation::header::CheckedHeader::trust_me(hdr.clone(), *id)
                    })
                })
                .collect()
        };

        let checked_parent =
            ergo_validation::header::CheckedHeader::trust_me(parent.clone(), *parent_id);
        let block_ctx = ergo_validation::block::BlockValidationContext {
            parent: &checked_parent,
            utxo: &utxo,
            params: &params,
            voting_length: 1024,
            votes_unknown_rule_disabled: false,
            parent_extension: None,
            soft_fork_state: None,
            last_headers: &checked_last,
            script_validation_checkpoint: None,
        };
        let checked_header =
            ergo_validation::header::CheckedHeader::trust_me(header.clone(), *header_id);
        match validate_full_block(checked_header, &bt, &ext, &block_ctx) {
            Ok(checked_block) => {
                let checked = checked_block.transactions();
                total_txs += checked.len();
                utxo.apply_checked(checked);
                validated += 1;
                eprintln!(
                    "OK: h={} ({} txs, v{}) fully validated",
                    block.height,
                    checked.len(),
                    header.version
                );
            }
            Err(e) => {
                panic!("UNEXPECTED error at h={}: {e}", block.height);
            }
        }
    }

    eprintln!("v2 full pipeline: {validated} validated, {total_txs} txs");
    // All 10 blocks now validate (auction contract divergence fixed)
    assert_eq!(validated, 10, "expected all 10 blocks validated");
    assert_eq!(total_txs, 56, "expected 56 validated transactions");
}

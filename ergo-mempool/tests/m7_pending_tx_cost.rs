//! One-off cost probe against a specific mainnet pending tx.
//!
//! Pulls raw tx + input boxes + context from `/tmp/cost_probe/*.json`
//! (fetched by the helper script above this test in the shell), runs
//! the tx through `validate_transaction_parsed` with an enforcing
//! 1,000,000 block-cost cap (the same Scala miners enforce at block
//! assembly), and reports:
//!   - accept/reject with reason
//!   - consumed_cost in block cost units
//!
//! If consumed_cost > 1,000,000 → mining-side rejection explained.
//! If accept with consumed_cost ≤ 1,000,000 → cost isn't the issue,
//! something else (miner-pool blacklist, custom filter) is keeping
//! the tx from being included.

use std::collections::HashMap;

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::token::Token;
use ergo_ser::transaction::{write_transaction, Transaction};

use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::tx::validate_transaction_parsed;

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct TxJson {
    id: String,
    inputs: Vec<InputJson>,
    #[serde(rename = "dataInputs", default)]
    data_inputs: Vec<InputJson>,
    outputs: Vec<OutputJson>,
    size: u32,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct InputJson {
    #[serde(rename = "boxId")]
    box_id: String,
    #[serde(rename = "spendingProof", default)]
    spending_proof: Option<SpendingProofJson>,
}

#[derive(serde::Deserialize, Default)]
#[allow(dead_code)]
struct SpendingProofJson {
    #[serde(rename = "proofBytes", default)]
    proof_bytes: String,
    #[serde(default)]
    extension: HashMap<String, String>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct OutputJson {
    #[serde(rename = "boxId", default)]
    box_id: String,
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u32,
    #[serde(default)]
    assets: Vec<AssetJson>,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: HashMap<String, String>,
    #[serde(rename = "transactionId", default)]
    transaction_id: String,
    #[serde(default)]
    index: u16,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct AssetJson {
    #[serde(rename = "tokenId")]
    token_id: String,
    amount: u64,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct InputBoxJson {
    #[serde(rename = "boxId")]
    box_id: String,
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u32,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: HashMap<String, String>,
    #[serde(default)]
    assets: Vec<AssetJson>,
}

fn parse_registers(map: &HashMap<String, String>) -> (AdditionalRegisters, Vec<u8>) {
    let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
    let mut reg_hex_vec: Vec<(usize, String)> = Vec::new();
    for (key, val_hex) in map {
        let reg_idx = match key.as_str() {
            "R4" => 0,
            "R5" => 1,
            "R6" => 2,
            "R7" => 3,
            "R8" => 4,
            "R9" => 5,
            _ => continue,
        };
        let val_bytes = hex::decode(val_hex).unwrap();
        let mut vr = VlqReader::new(&val_bytes);
        let (tpe, value) = read_constant(&mut vr).unwrap();
        reg_vec.push((reg_idx, RegisterValue { tpe, value }));
        reg_hex_vec.push((reg_idx, val_hex.clone()));
    }
    reg_vec.sort_by_key(|(i, _)| *i);
    reg_hex_vec.sort_by_key(|(i, _)| *i);
    let regs = AdditionalRegisters {
        registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
    };
    let mut bytes = vec![reg_hex_vec.len() as u8];
    for (_, h) in &reg_hex_vec {
        bytes.extend_from_slice(&hex::decode(h).unwrap());
    }
    (regs, bytes)
}

fn parse_assets(assets: &[AssetJson]) -> Vec<Token> {
    assets
        .iter()
        .map(|a| {
            let id: [u8; 32] = hex::decode(&a.token_id).unwrap().try_into().unwrap();
            Token {
                token_id: Digest32::from_bytes(id),
                amount: a.amount,
            }
        })
        .collect()
}

fn parse_input_box(j: &InputBoxJson) -> ErgoBox {
    let tree_bytes = hex::decode(&j.ergo_tree).unwrap();
    let mut r = VlqReader::new(&tree_bytes);
    let tree = read_ergo_tree(&mut r).unwrap();
    let (regs, reg_bytes) = parse_registers(&j.additional_registers);
    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        j.value,
        tree,
        tree_bytes,
        j.creation_height,
        parse_assets(&j.assets),
        regs,
        reg_bytes,
    );
    let tx_id: [u8; 32] = hex::decode(&j.transaction_id).unwrap().try_into().unwrap();
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id),
        index: j.index,
    }
}

fn parse_output_candidate(o: &OutputJson) -> ErgoBoxCandidate {
    let tree_bytes = hex::decode(&o.ergo_tree).unwrap();
    let mut r = VlqReader::new(&tree_bytes);
    let tree = read_ergo_tree(&mut r).unwrap();
    let (regs, reg_bytes) = parse_registers(&o.additional_registers);
    ErgoBoxCandidate::from_trusted_raw_parts(
        o.value,
        tree,
        tree_bytes,
        o.creation_height,
        parse_assets(&o.assets),
        regs,
        reg_bytes,
    )
}

fn parse_spending_proof(j: &SpendingProofJson) -> SpendingProof {
    let proof = hex::decode(&j.proof_bytes).unwrap_or_default();
    // Context extension: map of str(index) -> hex(constant bytes)
    let mut values: indexmap::IndexMap<
        u8,
        (
            ergo_ser::sigma_type::SigmaType,
            ergo_ser::sigma_value::SigmaValue,
        ),
    > = indexmap::IndexMap::new();
    for (k, v) in &j.extension {
        let idx: u8 = k.parse().unwrap();
        let bytes = hex::decode(v).unwrap();
        let mut r = VlqReader::new(&bytes);
        let (tpe, val) = read_constant(&mut r).unwrap();
        values.insert(idx, (tpe, val));
    }
    let ext = ContextExtension { values };
    SpendingProof::new(proof, ext).unwrap()
}

fn parse_transaction(tx: &TxJson) -> Transaction {
    let inputs: Vec<Input> = tx
        .inputs
        .iter()
        .map(|i| {
            let bid: [u8; 32] = hex::decode(&i.box_id).unwrap().try_into().unwrap();
            Input {
                box_id: Digest32::from_bytes(bid),
                spending_proof: parse_spending_proof(i.spending_proof.as_ref().unwrap()),
            }
        })
        .collect();
    let data_inputs = tx
        .data_inputs
        .iter()
        .map(|d| {
            let bid: [u8; 32] = hex::decode(&d.box_id).unwrap().try_into().unwrap();
            ergo_ser::input::DataInput {
                box_id: Digest32::from_bytes(bid),
            }
        })
        .collect();
    let output_candidates: Vec<ErgoBoxCandidate> =
        tx.outputs.iter().map(parse_output_candidate).collect();
    Transaction {
        inputs,
        data_inputs,
        output_candidates,
    }
}

#[test]
#[ignore = "probe; run with --ignored"]
fn probe_cost_of_pending_tx_e67() {
    let tx_json: TxJson = serde_json::from_reader(
        std::fs::File::open("/tmp/cost_probe/e67_tx.json").expect("fetch data first"),
    )
    .unwrap();
    let input_boxes: Vec<InputBoxJson> =
        serde_json::from_reader(std::fs::File::open("/tmp/cost_probe/e67_inputs.json").unwrap())
            .unwrap();
    let header_json: serde_json::Value =
        serde_json::from_reader(std::fs::File::open("/tmp/cost_probe/e67_header.json").unwrap())
            .unwrap();

    // Parse types
    let tx = parse_transaction(&tx_json);
    let resolved_inputs: Vec<ErgoBox> = input_boxes.iter().map(parse_input_box).collect();

    // Serialize tx to canonical bytes for the canonical-check
    let mut w = ergo_primitives::writer::VlqWriter::new();
    write_transaction(&mut w, &tx).expect("serialize tx");
    let tx_bytes = w.result();
    eprintln!(
        "[probe] tx reserialized to {} bytes (node reports size {})",
        tx_bytes.len(),
        tx_json.size
    );

    // Build transaction context from the tip header. Fields:
    //   height = next-block height (current tip + 1)
    //   miner_pubkey = solution.pk of the current tip (best-effort proxy)
    //   pre_header_* from current tip header
    let header = &header_json["header"];
    let height: u32 = header["height"].as_u64().unwrap() as u32;
    let timestamp: u64 = header["timestamp"].as_u64().unwrap();
    let parent_id_hex = header["parentId"].as_str().unwrap();
    let parent_id: [u8; 32] = hex::decode(parent_id_hex).unwrap().try_into().unwrap();
    let nbits: u64 = header["nBits"].as_u64().unwrap();
    let version: u8 = header["version"].as_u64().unwrap() as u8;
    let miner_pk_hex = header["powSolutions"]["pk"].as_str().unwrap();
    let miner_pubkey: [u8; 33] = hex::decode(miner_pk_hex).unwrap().try_into().unwrap();

    let ctx = TransactionContext {
        height: height + 1,
        miner_pubkey,
        pre_header_timestamp: timestamp,
        activated_script_version: version.saturating_sub(1),
        pre_header_version: version,
        pre_header_parent_id: parent_id,
        pre_header_n_bits: nbits,
        pre_header_votes: [0u8; 3],
    };
    let params = ProtocolParams::mainnet_default();

    // Enforcing cost: Scala miners use `maxTransactionCost = 1_000_000`
    // block-cost units. In JitCost that's 10_000_000.
    let mut cost = CostAccumulator::new(JitCost::from_block_cost(1_000_000).unwrap());
    let mut tx_cx = ergo_validation::TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[], // last_headers empty — fine unless script uses CONTEXT.headers
        rules: ergo_validation::TxValidationRules::default(),
    };
    let result = validate_transaction_parsed(
        tx.clone(),
        &tx_bytes,
        resolved_inputs,
        Vec::new(), // no data inputs on this tx
        false,      // skip_scripts = false
        &mut tx_cx,
    );

    eprintln!("\n[probe] RESULT");
    match &result {
        Ok(_) => {
            eprintln!("  ACCEPTED");
            eprintln!("  consumed_cost   = {} block cost units", cost.consumed());
            eprintln!("  vs miner cap    = 1,000,000 block cost units");
            eprintln!(
                "  utilization     = {:.1}%",
                cost.consumed() as f64 / 10_000.0
            );
        }
        Err(e) => {
            eprintln!("  REJECTED: {e:?}");
            eprintln!(
                "  consumed before error: {} block cost units",
                cost.consumed()
            );
        }
    }

    // Don't assert a specific verdict — this is a diagnostic probe.
    let _ = result;
}

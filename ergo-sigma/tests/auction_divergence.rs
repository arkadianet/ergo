//! Diagnostic test for the auction-contract evaluation divergence.
//!
//! At heights 700001 and 700003, inputs with ErgoTree 102f0400... have empty
//! proofs. Scala reduces these to TrivialProp(true) but our evaluator produces
//! a non-trivial SigmaBoolean. This test isolates the divergence.

use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::header::{read_header, serialize_header};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::{read_constant, SigmaBoolean};
use ergo_ser::transaction::read_transaction;
use ergo_sigma::evaluator::{reduce_expr_traced, EvalBox, EvalHeader, ReductionContext};
use ergo_sigma::reduce::trivial_reduce;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct BlockJson {
    #[serde(rename = "headerId")]
    #[allow(dead_code)]
    header_id: String,
    height: u32,
    transactions: Vec<TxJson>,
    #[allow(dead_code)]
    extension: serde_json::Value,
}
#[derive(Deserialize)]
struct TxJson {
    #[allow(dead_code)]
    id: String,
    bytes: String,
}
#[derive(Deserialize)]
struct HeaderVec {
    height: u32,
    bytes: String,
}
#[derive(Deserialize)]
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
struct AssetJson {
    #[serde(rename = "tokenId")]
    token_id: String,
    amount: u64,
}

fn parse_input_box(json: &InputBoxJson) -> ErgoBox {
    let ergo_tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&ergo_tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();

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
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes(tx_id),
        index: json.index,
    }
}

fn make_eval_box(b: &ErgoBox) -> EvalBox {
    let id = b.box_id().unwrap();
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::ergo_box::write_ergo_box(&mut w, b).unwrap_or_default();
    EvalBox {
        creation_height: b.candidate.creation_height,
        script_bytes: b.candidate.ergo_tree_bytes().to_vec(),
        value: b.candidate.value as i64,
        id: *id.as_bytes(),
        transaction_id: *b.transaction_id.as_bytes(),
        output_index: b.index,
        registers: {
            let mut result: [Option<ergo_ser::register::RegisterValue>; 6] =
                [None, None, None, None, None, None];
            for (i, reg) in b
                .candidate
                .additional_registers
                .registers
                .iter()
                .enumerate()
            {
                if i < 6 {
                    result[i] = Some(reg.clone());
                }
            }
            result
        },
        tokens: b
            .candidate
            .tokens
            .iter()
            .map(|t| (*t.token_id.as_bytes(), t.amount))
            .collect(),
        raw_bytes: w.result(),
        register_bytes: b.candidate.register_bytes().to_vec(),
    }
}

#[test]
#[ignore = "needs gitignored headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn diagnose_auction_divergence_700001() {
    // Load data
    let input_data =
        std::fs::read_to_string("../test-vectors/mainnet/input_boxes_700000_700010.json").unwrap();
    let input_boxes: Vec<InputBoxJson> = serde_json::from_str(&input_data).unwrap();
    let box_map: HashMap<String, ErgoBox> = input_boxes
        .iter()
        .map(|ib| (ib.box_id.clone(), parse_input_box(ib)))
        .collect();

    let blocks: Vec<BlockJson> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/blocks_700000_700010.json").unwrap(),
    )
    .unwrap();
    let block = blocks.iter().find(|b| b.height == 700001).unwrap();

    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_700000_700500.json").unwrap();
    let header_vecs: Vec<HeaderVec> = serde_json::from_str(&headers_data).unwrap();
    let headers: HashMap<u32, (ergo_ser::header::Header, [u8; 32])> = header_vecs
        .iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            let h = read_header(&mut r).unwrap();
            let (_, id) = serialize_header(&h).expect("real mainnet header serializes");
            (v.height, (h, *id.as_bytes()))
        })
        .collect();

    let (ref header, ref _header_id) = headers[&700001];

    // Build last_headers for CONTEXT.headers
    let mut sorted: Vec<u32> = headers.keys().copied().collect();
    sorted.sort();
    let pos = sorted.partition_point(|&h| h < 700001);
    let start = pos.saturating_sub(10);
    let eval_headers: Vec<EvalHeader> = sorted[start..pos]
        .iter()
        .filter_map(|h| {
            headers
                .get(h)
                .map(|(hdr, id)| EvalHeader::from_header(hdr, *id))
        })
        .collect();

    // Parse all txs in this block
    let txs: Vec<ergo_ser::transaction::Transaction> = block
        .transactions
        .iter()
        .map(|t| {
            let b = hex::decode(&t.bytes).unwrap();
            let mut r = VlqReader::new(&b);
            read_transaction(&mut r).unwrap()
        })
        .collect();

    // Build outputs from preceding txs for intra-block deps
    let mut all_eval_inputs: Vec<EvalBox> = Vec::new();
    let mut all_eval_outputs: Vec<EvalBox> = Vec::new();

    // For each tx, check if any input has the auction ErgoTree
    for (tx_idx, tx) in txs.iter().enumerate() {
        let _message = ergo_ser::transaction::bytes_to_sign(tx).unwrap();
        let tx_id = ergo_ser::transaction::transaction_id(tx).unwrap();

        // Resolve inputs
        let resolved: Vec<ErgoBox> = tx
            .inputs
            .iter()
            .map(|inp| {
                let id_hex = hex::encode(inp.box_id.as_bytes());
                box_map.get(&id_hex).cloned().unwrap_or_else(|| {
                    panic!("tx[{tx_idx}] input box {id_hex} not found in UTXO set");
                })
            })
            .collect();

        // Resolve data inputs
        let data_resolved: Vec<ErgoBox> = tx
            .data_inputs
            .iter()
            .filter_map(|di| {
                let id_hex = hex::encode(di.box_id.as_bytes());
                box_map.get(&id_hex).cloned()
            })
            .collect();

        let eval_inputs: Vec<EvalBox> = resolved.iter().map(make_eval_box).collect();
        let eval_outputs: Vec<EvalBox> = tx
            .output_candidates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let temp = ErgoBox {
                    candidate: c.clone(),
                    transaction_id: tx_id,
                    index: i as u16,
                };
                make_eval_box(&temp)
            })
            .collect();
        let eval_data: Vec<EvalBox> = data_resolved.iter().map(make_eval_box).collect();

        // Check each input for the auction ErgoTree
        for (inp_idx, (input, resolved_box)) in tx.inputs.iter().zip(resolved.iter()).enumerate() {
            let tree_hex = hex::encode(resolved_box.candidate.ergo_tree_bytes());
            if !tree_hex.starts_with("102f0400") {
                continue;
            }

            eprintln!("\n=== AUCTION INPUT: tx[{}] input[{}] ===", tx_idx, inp_idx);
            eprintln!("  box_id: {}", hex::encode(input.box_id.as_bytes()));
            eprintln!("  value: {}", resolved_box.candidate.value);
            eprintln!(
                "  creation_height: {}",
                resolved_box.candidate.creation_height
            );
            eprintln!("  proof len: {}", input.spending_proof.proof.len());
            eprintln!("  proof empty: {}", input.spending_proof.proof.is_empty());
            eprintln!("  tokens: {}", resolved_box.candidate.tokens.len());
            eprintln!(
                "  registers: {}",
                resolved_box.candidate.additional_registers.registers.len()
            );

            // Dump register contents
            for (ri, reg) in resolved_box
                .candidate
                .additional_registers
                .registers
                .iter()
                .enumerate()
            {
                eprintln!(
                    "  R{}: type={:?} val={:?}",
                    ri + 4,
                    reg.tpe,
                    match &reg.value {
                        ergo_ser::sigma_value::SigmaValue::Int(v) => format!("Int({})", v),
                        ergo_ser::sigma_value::SigmaValue::Long(v) => format!("Long({})", v),
                        ergo_ser::sigma_value::SigmaValue::Boolean(v) => format!("Boolean({})", v),
                        ergo_ser::sigma_value::SigmaValue::SigmaProp(sb) =>
                            format!("SigmaProp({:?})", sb),
                        ergo_ser::sigma_value::SigmaValue::Coll(c) => format!("Coll({:?})", c),
                        other => format!("{:?}", other),
                    }
                );
            }

            // Try trivial reduce (should fail for complex script)
            let ergo_tree = &resolved_box.candidate.ergo_tree();
            match trivial_reduce(ergo_tree) {
                Ok(sb) => eprintln!("  trivial_reduce: Ok({sb:?})"),
                Err(e) => eprintln!("  trivial_reduce: Err({e})"),
            }

            // Build reduction context
            let ctx = ReductionContext {
                height: 700001,
                self_box: Some(&eval_inputs[inp_idx]),
                self_creation_height: resolved_box.candidate.creation_height,
                outputs: &eval_outputs,
                inputs: &eval_inputs,
                data_inputs: &eval_data,
                miner_pubkey: *header.solution.pk().as_bytes(),
                pre_header_timestamp: header.timestamp,
                extension: input.spending_proof.extension().values.clone(),
                last_headers: &eval_headers,
                last_block_utxo_root: None,
                activated_script_version: 2,
                ergo_tree_version: 2,
                pre_header_version: 0,
                pre_header_parent_id: [0u8; 32],
                pre_header_n_bits: 0,
                pre_header_votes: [0u8; 3],
                input_extensions: &[],
            };

            // Evaluate with tracing
            let (result, trace) = reduce_expr_traced(&ergo_tree.body, &ctx, &ergo_tree.constants);

            eprintln!("\n  === TRACE ({} entries) ===", trace.len());
            for entry in &trace {
                if entry.label.starts_with("EQ(false)") && entry.value.contains("CollBytes") {
                    // Print full hex for byte comparisons
                    eprintln!("    {} [FULL]:", entry.label);
                    eprintln!("      {}", entry.value);
                } else {
                    eprintln!("    {}: {}", entry.label, entry.value);
                }
            }

            match &result {
                Ok(SigmaBoolean::TrivialProp(true)) => {
                    eprintln!("\n  RESULT: TrivialProp(true) — MATCHES SCALA");
                }
                other => {
                    panic!("Expected TrivialProp(true) for auction contract, got: {other:?}");
                }
            }

            // Also report the extension values
            eprintln!(
                "\n  context extension: {} values",
                input.spending_proof.extension().values.len()
            );
            for (k, (tpe, v)) in &input.spending_proof.extension().values {
                eprintln!("    var[{}]: type={:?} val={:?}", k, tpe, v);
            }
        }

        // Add outputs to box_map for intra-block resolution of subsequent txs
        all_eval_inputs.extend(eval_inputs);
        all_eval_outputs.extend(eval_outputs);
    }
}

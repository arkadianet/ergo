#![cfg(feature = "diagnostics")]
//! Focused trace for the first ProofFailed transaction in the 700000 range.
//!
//! Finds the first transaction that reaches proof verification and fails,
//! then dumps the script structure, constants, reduction path, and proof
//! details for the failing input.

use std::collections::HashMap;

use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::read_header;
use ergo_ser::transaction::read_transaction;

use ergo_sigma::evaluator::{reduce_expr_traced, EvalBox, ReductionContext};
use ergo_sigma::reduce::trivial_reduce;

use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::CostAccumulator;
use ergo_validation::error::ValidationError;
use ergo_validation::test_helpers::ergo_box_to_eval_box;
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

struct TestUtxo(HashMap<Digest32, ErgoBox>);
impl TestUtxo {
    fn apply_tx(&mut self, tx: &ergo_ser::transaction::Transaction) {
        for input in &tx.inputs {
            self.0.remove(&input.box_id);
        }
        let tx_id = ergo_ser::transaction::transaction_id(tx).unwrap();
        for (i, c) in tx.output_candidates.iter().enumerate() {
            let b = ErgoBox {
                candidate: c.clone(),
                transaction_id: tx_id,
                index: i as u16,
            };
            let box_id = b.box_id().unwrap();
            self.0.insert(box_id, b);
        }
    }
}
impl UtxoView for TestUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.0.get(box_id).cloned()
    }
}

#[derive(serde::Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
    #[serde(rename = "bytesToSign")]
    bytes_to_sign: String,
    height: u32,
}
#[derive(serde::Deserialize)]
struct HeaderVector {
    height: u32,
    bytes: String,
}

#[test]
fn trace_first_proof_failed() {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(trace_inner)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn trace_inner() {
    let tx_data: Vec<TxVector> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/transactions_700000_700200.json")
            .unwrap(),
    )
    .unwrap();
    let header_data: Vec<HeaderVector> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/headers_700000_700500.json").unwrap(),
    )
    .unwrap();
    let header_info: HashMap<u32, ([u8; 33], u64)> = header_data
        .iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            let h = read_header(&mut r).unwrap();
            (v.height, (*h.solution.pk().as_bytes(), h.timestamp))
        })
        .collect();

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut utxo = TestUtxo(HashMap::new());

    let mut sorted: Vec<&TxVector> = tx_data.iter().collect();
    sorted.sort_by_key(|v| v.height);

    for v in &sorted {
        let tx_bytes = hex::decode(&v.bytes).unwrap();
        let (miner_pubkey, timestamp) = *header_info
            .get(&v.height)
            .unwrap_or_else(|| panic!("missing header for height {}", v.height));
        let ctx = TransactionContext {
            height: v.height,
            miner_pubkey,
            pre_header_timestamp: timestamp,
            activated_script_version: 1,
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

        match validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx) {
            Ok(checked) => {
                utxo.apply_tx(checked.transaction());
            }
            Err(ValidationError::ProofFailed { index }) => {
                // Found the first ProofFailed — trace it
                let mut r = VlqReader::new(&tx_bytes);
                let tx = read_transaction(&mut r).unwrap();

                eprintln!("\n=== TRACE: first ProofFailed ===");
                eprintln!("  tx: {}", &v.id[..16]);
                eprintln!("  height: {}", v.height);
                eprintln!("  failing input: {index}");
                eprintln!(
                    "  inputs: {}, outputs: {}",
                    tx.inputs.len(),
                    tx.output_candidates.len()
                );

                // bytes_to_sign check
                let message = ergo_ser::transaction::bytes_to_sign(&tx).unwrap();
                let expected = hex::decode(&v.bytes_to_sign).unwrap();
                assert_eq!(message, expected, "bytes_to_sign mismatch");
                eprintln!("  bytes_to_sign: matches ✓");

                let input = &tx.inputs[index];
                let box_data = utxo
                    .get_box(&input.box_id)
                    .expect("failing input box must be in UTXO");
                let tree = box_data.candidate.ergo_tree();

                eprintln!("\n  Failing input {index}:");
                eprintln!("    box_id: {}", hex::encode(input.box_id.as_bytes()));
                eprintln!("    proof_len: {}", input.spending_proof.proof.len());
                if !input.spending_proof.proof.is_empty() {
                    eprintln!("    proof: {}", hex::encode(&input.spending_proof.proof));
                }
                eprintln!("    value: {} nanoErg", box_data.candidate.value);
                eprintln!(
                    "    creation_height: {}",
                    box_data.candidate.creation_height
                );
                eprintln!("    tokens: {}", box_data.candidate.tokens.len());
                for (ti, tok) in box_data.candidate.tokens.iter().enumerate() {
                    eprintln!(
                        "      token[{ti}]: {} amount={}",
                        hex::encode(tok.token_id.as_bytes()),
                        tok.amount
                    );
                }
                eprintln!(
                    "    registers: {}",
                    box_data.candidate.additional_registers.registers.len()
                );

                eprintln!("\n    ErgoTree:");
                eprintln!("      version: {}", tree.version);
                eprintln!("      has_size: {}", tree.has_size);
                eprintln!("      constant_segregation: {}", tree.constant_segregation);
                eprintln!("      constants: {}", tree.constants.len());
                for (ci, (tpe, val)) in tree.constants.iter().enumerate() {
                    let vs = format!("{val:?}");
                    let display = if vs.len() > 100 {
                        format!("{}...", &vs[..100])
                    } else {
                        vs
                    };
                    eprintln!("        [{ci}] {tpe:?} = {display}");
                }
                eprintln!("      body: {}", summarize_expr(&tree.body, 0));

                // Navigate into SigmaOr child 1 to dump its result expression
                dump_sigmaor_child1(tree);

                // Try trivial reduce
                eprintln!("\n    Reduction:");
                match trivial_reduce(tree) {
                    Ok(prop) => eprintln!("      trivial_reduce → {:?}", describe_sb(&prop)),
                    Err(e) => {
                        eprintln!("      trivial_reduce → {e}");

                        // Build context and evaluate
                        let tx_id = ModifierId::from_bytes(*blake2b256(&message).as_bytes());
                        let eval_box = ergo_box_to_eval_box(&box_data, index).unwrap();

                        let eval_outputs: Vec<EvalBox> = tx
                            .output_candidates
                            .iter()
                            .enumerate()
                            .map(|(j, c)| {
                                let temp = ErgoBox {
                                    candidate: c.clone(),
                                    transaction_id: tx_id,
                                    index: j as u16,
                                };
                                ergo_box_to_eval_box(&temp, j).unwrap()
                            })
                            .collect();
                        let eval_inputs: Vec<EvalBox> = tx
                            .inputs
                            .iter()
                            .enumerate()
                            .filter_map(|(j, inp)| Some((j, utxo.get_box(&inp.box_id)?)))
                            .filter_map(|(j, b)| ergo_box_to_eval_box(&b, j).ok())
                            .collect();
                        let eval_data_inputs: Vec<EvalBox> = tx
                            .data_inputs
                            .iter()
                            .enumerate()
                            .filter_map(|(j, di)| Some((j, utxo.get_box(&di.box_id)?)))
                            .filter_map(|(j, b)| ergo_box_to_eval_box(&b, j).ok())
                            .collect();

                        let rctx = ReductionContext {
                            height: v.height,
                            self_box: Some(&eval_box),
                            self_creation_height: box_data.candidate.creation_height,
                            outputs: &eval_outputs,
                            inputs: &eval_inputs,
                            data_inputs: &eval_data_inputs,
                            miner_pubkey,
                            pre_header_timestamp: timestamp,
                            extension: indexmap::IndexMap::new(),
                            last_headers: &[],
                            last_block_utxo_root: None,
                            activated_script_version: 1,
                            ergo_tree_version: 1,
                            pre_header_version: 0,
                            pre_header_parent_id: [0u8; 32],
                            pre_header_n_bits: 0,
                            pre_header_votes: [0u8; 3],
                            input_extensions: &[],
                        };

                        let (result, trace_entries) =
                            reduce_expr_traced(&tree.body, &rctx, &tree.constants);
                        eprintln!("\n    Trace ({} entries):", trace_entries.len());
                        for entry in &trace_entries {
                            eprintln!("      {} = {}", entry.label, entry.value);
                        }
                        match result {
                            Ok(prop) => {
                                eprintln!("\n      evaluator → {:?}", describe_sb(&prop));
                                if input.spending_proof.proof.is_empty() {
                                    match &prop {
                                        ergo_ser::sigma_value::SigmaBoolean::TrivialProp(true) => {
                                            eprintln!("      CORRECT: empty proof + TrivialTrue")
                                        }
                                        other => eprintln!(
                                            "      BUG: empty proof but reduced to {:?}",
                                            describe_sb(other)
                                        ),
                                    }
                                }
                            }
                            Err(e) => eprintln!("      evaluator error: {e}"),
                        }
                    }
                }

                // Update UTXO and stop
                utxo.apply_tx(&tx);
                return; // Only trace the first one
            }
            Err(_) => {
                // Update UTXO for non-ProofFailed failures
                if let Ok(tx) = {
                    let mut r = VlqReader::new(&tx_bytes);
                    read_transaction(&mut r)
                } {
                    utxo.apply_tx(&tx);
                }
            }
        }
    }
    // If we get here, no ProofFailed — the SigmaPropBytes fix eliminated them all.
    // This is the expected state after the fix.
    eprintln!("No ProofFailed transactions — SigmaPropBytes fix verified.");
}

fn summarize_expr(expr: &ergo_ser::opcode::Expr, depth: usize) -> String {
    use ergo_ser::opcode::{Expr, Payload};
    if depth > 4 {
        return "...".into();
    }
    match expr {
        Expr::Const { tpe, .. } => format!("Const({tpe:?})"),
        Expr::Unparsed(b) => format!("Unparsed({} bytes)", b.len()),
        Expr::Op(node) => {
            let name = ergo_ser::opcode::opcode_name(node.opcode);
            match &node.payload {
                Payload::Zero => format!("{name}()"),
                Payload::One(a) => format!("{name}({})", summarize_expr(a, depth + 1)),
                Payload::Two(a, b) => format!(
                    "{name}({}, {})",
                    summarize_expr(a, depth + 1),
                    summarize_expr(b, depth + 1)
                ),
                Payload::BlockValue { items, result } => format!(
                    "BlockValue([{} defs], {})",
                    items.len(),
                    summarize_expr(result, depth + 1)
                ),
                Payload::ConstPlaceholder { index } => format!("ConstPlaceholder({index})"),
                Payload::ValUse { id } => format!("ValUse({id})"),
                Payload::ValDef { id, rhs, .. } => {
                    format!("ValDef({id}, {})", summarize_expr(rhs, depth + 1))
                }
                _ => format!("{name}(..)"),
            }
        }
    }
}

/// Navigate tree.body → BlockValue → SigmaOr → child 1 → inner block
/// and dump the result expression at full depth.
fn dump_sigmaor_child1(tree: &ergo_ser::ergo_tree::ErgoTree) {
    use ergo_ser::opcode::{Expr, Payload};

    // body = BlockValue([3 defs], SigmaOr(..))
    let sigma_or = match &tree.body {
        Expr::Op(n) if n.opcode == 0xD8 => {
            if let Payload::BlockValue { result, .. } = &n.payload {
                result.as_ref()
            } else {
                return;
            }
        }
        _ => return,
    };

    // SigmaOr = SigmaCollection { items: [child0, child1] }
    let child1 = match sigma_or {
        Expr::Op(n) if n.opcode == 0xEB => {
            if let Payload::SigmaCollection { items } = &n.payload {
                items.get(1)
            } else {
                return;
            }
        }
        _ => return,
    };

    let child1 = match child1 {
        Some(c) => c,
        None => {
            eprintln!("    SigmaOr has < 2 children");
            return;
        }
    };

    eprintln!("\n    SigmaOr child 1 expression tree (full depth):");
    print_expr_tree(child1, 6);
}

fn print_expr_tree(expr: &ergo_ser::opcode::Expr, indent: usize) {
    use ergo_ser::opcode::{Expr, Payload};
    let pad = " ".repeat(indent);

    match expr {
        Expr::Const { tpe, val } => {
            let vs = format!("{val:?}");
            let display = if vs.len() > 80 {
                format!("{}...", &vs[..80])
            } else {
                vs
            };
            eprintln!("{pad}Const({tpe:?}) = {display}");
        }
        Expr::Unparsed(raw) => eprintln!("{pad}Unparsed({} bytes)", raw.len()),
        Expr::Op(node) => {
            let name = ergo_ser::opcode::opcode_name(node.opcode);
            match &node.payload {
                Payload::Zero => eprintln!("{pad}{name}()  [0x{:02X}]", node.opcode),
                Payload::One(a) => {
                    eprintln!("{pad}{name}(  [0x{:02X}]", node.opcode);
                    print_expr_tree(a, indent + 2);
                    eprintln!("{pad})");
                }
                Payload::Two(a, b) => {
                    eprintln!("{pad}{name}(  [0x{:02X}]", node.opcode);
                    print_expr_tree(a, indent + 2);
                    print_expr_tree(b, indent + 2);
                    eprintln!("{pad})");
                }
                Payload::Three(a, b, c) => {
                    eprintln!("{pad}{name}(  [0x{:02X}]", node.opcode);
                    print_expr_tree(a, indent + 2);
                    print_expr_tree(b, indent + 2);
                    print_expr_tree(c, indent + 2);
                    eprintln!("{pad})");
                }
                Payload::ConstPlaceholder { index } => eprintln!("{pad}ConstPlaceholder({index})"),
                Payload::ValUse { id } => eprintln!("{pad}ValUse({id})"),
                Payload::ValDef { id, rhs, .. } => {
                    eprintln!("{pad}ValDef({id},");
                    print_expr_tree(rhs, indent + 2);
                    eprintln!("{pad})");
                }
                Payload::BlockValue { items, result } => {
                    eprintln!("{pad}BlockValue([");
                    for item in items {
                        print_expr_tree(item, indent + 2);
                    }
                    eprintln!("{pad}],");
                    print_expr_tree(result, indent + 2);
                    eprintln!("{pad})");
                }
                Payload::MethodCall {
                    type_id,
                    method_id,
                    obj,
                    args,
                    type_args: _,
                } => {
                    eprintln!(
                        "{pad}MethodCall(type={type_id}, method={method_id},  [0x{:02X}]",
                        node.opcode
                    );
                    print_expr_tree(obj, indent + 2);
                    for arg in args {
                        print_expr_tree(arg, indent + 2);
                    }
                    eprintln!("{pad})");
                }
                Payload::SelectField { input, field_idx } => {
                    eprintln!("{pad}SelectField({field_idx},  [0x{:02X}]", node.opcode);
                    print_expr_tree(input, indent + 2);
                    eprintln!("{pad})");
                }
                Payload::ByIndex {
                    input,
                    index,
                    default,
                } => {
                    eprintln!("{pad}ByIndex(  [0x{:02X}]", node.opcode);
                    print_expr_tree(input, indent + 2);
                    print_expr_tree(index, indent + 2);
                    if let Some(d) = default {
                        eprintln!("{pad}  default:");
                        print_expr_tree(d, indent + 4);
                    }
                    eprintln!("{pad})");
                }
                Payload::ExtractRegisterAs { input, reg_id, tpe } => {
                    eprintln!(
                        "{pad}ExtractRegisterAs(R{reg_id}, {tpe:?},  [0x{:02X}]",
                        node.opcode
                    );
                    print_expr_tree(input, indent + 2);
                    eprintln!("{pad})");
                }
                Payload::NumericCast { input, tpe } => {
                    eprintln!("{pad}Upcast({tpe:?},  [0x{:02X}]", node.opcode);
                    print_expr_tree(input, indent + 2);
                    eprintln!("{pad})");
                }
                _ => eprintln!("{pad}{name}(..)  [0x{:02X}]", node.opcode),
            }
        }
    }
}

fn describe_sb(sb: &ergo_ser::sigma_value::SigmaBoolean) -> String {
    use ergo_ser::sigma_value::SigmaBoolean;
    match sb {
        SigmaBoolean::TrivialProp(true) => "TrivialTrue".into(),
        SigmaBoolean::TrivialProp(false) => "TrivialFalse".into(),
        SigmaBoolean::ProveDlog(ge) => format!("ProveDlog({})", hex::encode(&ge.as_bytes()[..8])),
        SigmaBoolean::ProveDHTuple { .. } => "ProveDHTuple".into(),
        SigmaBoolean::Cand(c) => format!("AND({})", c.len()),
        SigmaBoolean::Cor(c) => format!("OR({})", c.len()),
        SigmaBoolean::Cthreshold { k, children } => format!("THRESHOLD({}/{})", k, children.len()),
    }
}

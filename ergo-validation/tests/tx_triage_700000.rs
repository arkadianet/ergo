//! Transaction validation triage: heights 700000-700200.
//!
//! Processes 1,278 real mainnet transactions through the full validation
//! pipeline. Transactions are processed in height order. UTXO is built
//! progressively from transaction outputs.
//!
//! Most transactions will fail at InputBoxNotFound because their inputs
//! were created before height 700000 (we don't have historical UTXO).
//! The valuable signal is which transactions REACH script validation
//! and what errors they produce — that drives interpreter work.
//!
//! This test produces a triage artifact, not a pass/fail gate.

use std::collections::HashMap;

use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::read_header;
use ergo_ser::transaction::{read_transaction, Transaction};

use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::CostAccumulator;
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

struct ProgressiveUtxo {
    boxes: HashMap<Digest32, ErgoBox>,
}

impl ProgressiveUtxo {
    fn new() -> Self {
        Self {
            boxes: HashMap::new(),
        }
    }

    fn apply_tx(&mut self, tx: &Transaction) {
        // Spend inputs
        for input in &tx.inputs {
            self.boxes.remove(&input.box_id);
        }
        // Add outputs
        let tx_id = ergo_ser::transaction::transaction_id(tx).unwrap();
        for (i, candidate) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: candidate.clone(),
                transaction_id: tx_id,
                index: i as u16,
            };
            let box_id = ergo_box.box_id().unwrap();
            self.boxes.insert(box_id, ergo_box);
        }
    }
}

impl UtxoView for ProgressiveUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.boxes.get(box_id).cloned()
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

/// Triage categories for validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TriageCategory {
    /// Transaction validated successfully
    Pass,
    /// Input box not in our progressive UTXO (expected for pre-range boxes)
    MissingUtxo,
    /// Deserialization or canonical encoding failure
    Deserialization,
    /// Structural validation failure
    Structural,
    /// Monetary conservation failure
    Monetary,
    /// Script evaluation produced unsupported opcode
    UnsupportedOpcode(u8),
    /// Script evaluation failed for other reason
    ScriptError,
    /// Proof verification returned false
    ProofFailed,
    /// Cost limit exceeded
    CostExceeded,
    /// Other / unclassified
    Other,
}

fn categorize_error(e: &ValidationError) -> TriageCategory {
    match e {
        ValidationError::InputBoxNotFound { .. } | ValidationError::DataInputBoxNotFound { .. } => {
            TriageCategory::MissingUtxo
        }

        ValidationError::Deserialization(_) | ValidationError::NonCanonical => {
            TriageCategory::Deserialization
        }

        ValidationError::NoInputs
        | ValidationError::DuplicateInput { .. }
        | ValidationError::OutputValueTooLow { .. }
        | ValidationError::TooManyTokens { .. }
        | ValidationError::BoxTooLarge { .. } => TriageCategory::Structural,

        ValidationError::ErgNotConserved { .. }
        | ValidationError::TokenNotConserved { .. }
        | ValidationError::InvalidMinting { .. } => TriageCategory::Monetary,

        ValidationError::ScriptError { reason, .. } => {
            // Extract unsupported opcode from error message
            if let Some(rest) = reason.strip_prefix("evaluation error: unsupported opcode: 0x") {
                if let Ok(opcode) = u8::from_str_radix(&rest[..2.min(rest.len())], 16) {
                    return TriageCategory::UnsupportedOpcode(opcode);
                }
            }
            TriageCategory::ScriptError
        }

        ValidationError::ProofFailed { .. } => TriageCategory::ProofFailed,
        ValidationError::CostExceeded { .. } => TriageCategory::CostExceeded,
        _ => TriageCategory::Other,
    }
}

#[test]
#[ignore = "needs gitignored transactions_700000_700200.json + headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn triage_700000_700200() {
    // Spawn on a thread with 16MB stack — the lambda runtime's env cloning
    // requires more stack in debug mode than the default 2MB test thread.
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(triage_700000_inner)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn triage_700000_inner() {
    let tx_data: Vec<TxVector> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/transactions_700000_700200.json")
            .unwrap(),
    )
    .unwrap();

    let header_data: Vec<HeaderVector> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/headers_700000_700500.json").unwrap(),
    )
    .unwrap();

    // Build height → (miner_pubkey, timestamp) map
    let header_info: HashMap<u32, ([u8; 33], u64)> = header_data
        .iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            let header = read_header(&mut r).unwrap();
            (
                v.height,
                (*header.solution.pk().as_bytes(), header.timestamp),
            )
        })
        .collect();

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut utxo = ProgressiveUtxo::new();

    // Sort by height (should already be, but ensure)
    let mut sorted_txs: Vec<&TxVector> = tx_data.iter().collect();
    sorted_txs.sort_by_key(|v| v.height);

    // Triage counters
    let mut triage: HashMap<TriageCategory, Vec<(u32, String)>> = HashMap::new();
    let mut script_error_reasons: HashMap<String, usize> = HashMap::new();
    let mut proof_failed_shapes: HashMap<String, usize> = HashMap::new();
    let mut proof_failed_rederr: HashMap<String, usize> = HashMap::new();
    let mut total = 0;

    for v in &sorted_txs {
        total += 1;
        let tx_bytes = hex::decode(&v.bytes).unwrap();
        let (miner_pubkey, timestamp) = *header_info.get(&v.height).unwrap_or_else(|| {
            panic!(
                "missing header for height {} — test fixture incomplete",
                v.height
            )
        });
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
        };

        let category = match validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx) {
            Ok(checked) => {
                utxo.apply_tx(checked.transaction());
                TriageCategory::Pass
            }
            Err(ref e) => {
                // Collect ScriptError reasons for detailed triage
                if let ValidationError::ScriptError { reason, .. } = e {
                    *script_error_reasons.entry(reason.clone()).or_insert(0) += 1;
                }
                // ProofFailed: diagnose reduction shape BEFORE UTXO mutation
                if matches!(e, ValidationError::ProofFailed { .. }) {
                    let tx = {
                        let mut r = VlqReader::new(&tx_bytes);
                        read_transaction(&mut r).unwrap()
                    };
                    let expected_bts = hex::decode(&v.bytes_to_sign).unwrap();
                    diagnose_proof_failed(
                        &tx,
                        v.height,
                        &expected_bts,
                        &utxo,
                        &header_info,
                        &mut proof_failed_shapes,
                        &mut proof_failed_rederr,
                    );
                }
                // Update UTXO after diagnostic so later txs can be tested
                if let Ok(tx) = {
                    let mut r = VlqReader::new(&tx_bytes);
                    read_transaction(&mut r)
                } {
                    utxo.apply_tx(&tx);
                }
                categorize_error(e)
            }
        };

        triage
            .entry(category.clone())
            .or_default()
            .push((v.height, v.id[..16].to_string()));
    }

    // Print triage summary
    eprintln!("\n=== TRIAGE: heights 700000-700200 ({total} transactions) ===\n");

    let pass_count = triage.get(&TriageCategory::Pass).map_or(0, |v| v.len());
    let missing = triage
        .get(&TriageCategory::MissingUtxo)
        .map_or(0, |v| v.len());
    eprintln!("  PASS:          {pass_count}");
    eprintln!("  MissingUtxo:   {missing}  (expected — pre-range inputs)");

    // Script-level failures (the interesting ones)
    let mut opcode_counts: Vec<(u8, usize)> = Vec::new();
    for (cat, txs) in &triage {
        match cat {
            TriageCategory::UnsupportedOpcode(op) => {
                opcode_counts.push((*op, txs.len()));
            }
            TriageCategory::ScriptError => {
                eprintln!("  ScriptError:   {}  (non-opcode failures)", txs.len());
            }
            TriageCategory::ProofFailed => {
                eprintln!("  ProofFailed:   {}", txs.len());
            }
            TriageCategory::Deserialization => {
                eprintln!("  Deser error:   {}", txs.len());
            }
            TriageCategory::Structural => {
                eprintln!("  Structural:    {}", txs.len());
            }
            TriageCategory::Monetary => {
                eprintln!("  Monetary:      {}", txs.len());
            }
            TriageCategory::CostExceeded => {
                eprintln!("  CostExceeded:  {}", txs.len());
            }
            TriageCategory::Other => {
                eprintln!("  Other:         {}", txs.len());
            }
            _ => {}
        }
    }

    if !opcode_counts.is_empty() {
        opcode_counts.sort_by_key(|b| std::cmp::Reverse(b.1));
        eprintln!("\n  Unsupported opcodes (frequency-ranked):");
        for (op, count) in &opcode_counts {
            let name = ergo_ser::opcode::opcode_name(*op);
            eprintln!("    0x{op:02X} ({name}): {count} transactions");
        }
    }

    // Print non-opcode ScriptError reasons (frequency-ranked)
    let non_opcode_errors: Vec<_> = script_error_reasons
        .iter()
        .filter(|(reason, _)| !reason.contains("unsupported opcode"))
        .collect();
    if !non_opcode_errors.is_empty() {
        let mut sorted: Vec<_> = non_opcode_errors;
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
        eprintln!("\n  Non-opcode ScriptError reasons (frequency-ranked):");
        for (reason, count) in &sorted {
            // Truncate long reasons for readability
            let display = if reason.len() > 100 {
                &reason[..100]
            } else {
                reason
            };
            eprintln!("    [{count}x] {display}");
        }
    }

    eprintln!("\n  UTXO entries at end: {}", utxo.boxes.len());

    // --- ProofFailed diagnostic ---
    let pf_count = triage
        .get(&TriageCategory::ProofFailed)
        .map_or(0, |v| v.len());
    if pf_count > 0 {
        eprintln!("\n  ProofFailed diagnostic ({pf_count} transactions):");
        if !proof_failed_shapes.is_empty() {
            let mut sorted: Vec<_> = proof_failed_shapes.iter().collect();
            sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
            eprintln!("    Reduced proposition shapes:");
            for (shape, count) in &sorted {
                eprintln!("      [{count}x] {shape}");
            }
        }
        if !proof_failed_rederr.is_empty() {
            let mut sorted: Vec<_> = proof_failed_rederr.iter().collect();
            sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
            eprintln!("    Reduction errors during diagnostic:");
            for (err, count) in &sorted {
                eprintln!("      [{count}x] {err}");
            }
        }
    }

    eprintln!();

    // Gate: no deserialization, structural, or monetary failures on real mainnet data.
    // These would indicate bugs in our validation logic, not interpreter gaps.
    let deser_count = triage
        .get(&TriageCategory::Deserialization)
        .map_or(0, |v| v.len());
    let struct_count = triage
        .get(&TriageCategory::Structural)
        .map_or(0, |v| v.len());
    let monetary_count = triage.get(&TriageCategory::Monetary).map_or(0, |v| v.len());
    assert_eq!(
        deser_count, 0,
        "deserialization failures on valid mainnet data"
    );
    assert_eq!(struct_count, 0, "structural failures on valid mainnet data");
    assert_eq!(monetary_count, 0, "monetary failures on valid mainnet data");
}

/// Diagnose a ProofFailed transaction by reducing and verifying each input independently.
fn diagnose_proof_failed(
    tx: &Transaction,
    height: u32,
    expected_bts: &[u8],
    utxo: &ProgressiveUtxo,
    header_info: &HashMap<u32, ([u8; 33], u64)>,
    shapes: &mut HashMap<String, usize>,
    errors: &mut HashMap<String, usize>,
) {
    use ergo_sigma::evaluator::ReductionContext;
    use ergo_sigma::reduce::trivial_reduce;
    use ergo_sigma::verify::verify_sigma_proof;
    use ergo_validation::test_helpers::{candidate_to_eval_box, ergo_box_to_eval_box};

    let message = match ergo_ser::transaction::bytes_to_sign(tx) {
        Ok(m) => m,
        Err(e) => {
            *errors.entry(format!("bytes_to_sign: {e}")).or_insert(0) += 1;
            return;
        }
    };

    // Check bytes_to_sign parity with Scala node
    if message != expected_bts {
        *errors
            .entry(format!(
                "bytes_to_sign MISMATCH: computed {} bytes vs expected {} bytes",
                message.len(),
                expected_bts.len()
            ))
            .or_insert(0) += 1;
    }

    let tx_id = ModifierId::from_bytes(*blake2b256(&message).as_bytes());
    let (miner_pubkey, _timestamp) = *header_info
        .get(&height)
        .expect("missing header for ProofFailed diagnostic");

    // Build shared eval collections using the production bridge
    let eval_inputs: Vec<_> = tx
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(i, inp)| {
            let b = utxo.get_box(&inp.box_id)?;
            ergo_box_to_eval_box(&b, i).ok()
        })
        .collect();

    let eval_outputs: Vec<_> = tx
        .output_candidates
        .iter()
        .enumerate()
        .filter_map(|(i, c)| candidate_to_eval_box(c, &tx_id, i as u16).ok())
        .collect();

    let eval_data_inputs: Vec<_> = tx
        .data_inputs
        .iter()
        .enumerate()
        .filter_map(|(i, di)| {
            let b = utxo.get_box(&di.box_id)?;
            ergo_box_to_eval_box(&b, i).ok()
        })
        .collect();

    for (i, input) in tx.inputs.iter().enumerate() {
        let resolved = match utxo.get_box(&input.box_id) {
            Some(b) => b,
            None => continue,
        };
        let ergo_tree = resolved.candidate.ergo_tree();

        // Step 1: reduce to proposition (tracking which path)
        let mut reduction_path = "trivial";
        let proposition = match trivial_reduce(ergo_tree) {
            Ok(prop) => prop,
            Err(ergo_sigma::reduce::ReductionError::NotTriviallyReducible) => {
                reduction_path = "evaluator";
                let eval_box = match ergo_box_to_eval_box(&resolved, i) {
                    Ok(b) => b,
                    Err(e) => {
                        *errors.entry(format!("input {i} bridge: {e}")).or_insert(0) += 1;
                        continue;
                    }
                };

                let ctx = ReductionContext {
                    height,
                    self_box: Some(&eval_box),
                    self_creation_height: resolved.candidate.creation_height,
                    outputs: &eval_outputs,
                    inputs: &eval_inputs,
                    data_inputs: &eval_data_inputs,
                    miner_pubkey,
                    pre_header_timestamp: 0,
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

                match ergo_sigma::evaluator::reduce_expr(
                    &ergo_tree.body,
                    &ctx,
                    &ergo_tree.constants,
                ) {
                    Ok(prop) => prop,
                    Err(e) => {
                        *errors.entry(format!("input {i} eval: {e}")).or_insert(0) += 1;
                        continue;
                    }
                }
            }
            Err(e) => {
                *errors.entry(format!("input {i} trivial: {e}")).or_insert(0) += 1;
                continue;
            }
        };

        // Step 2: verify this input's proof independently
        let proof = &input.spending_proof.proof;
        let verify_result = verify_sigma_proof(&proposition, proof, &message);

        let shape = describe_proposition(&proposition);
        let detail = match verify_result {
            Ok(true) => format!("input {i}: {shape} → PASS"),
            Ok(false) => {
                let mut extra = format!(" via={reduction_path}");
                if let ergo_ser::sigma_value::SigmaBoolean::ProveDlog(ge) = &proposition {
                    extra.push_str(&format!(" pk={}", hex::encode(ge.as_bytes())));
                    if let Some(tree_pk) = extract_pk_from_tree(ergo_tree) {
                        if ge.as_bytes() != &tree_pk {
                            extra.push_str(&format!(" TREE_PK_MISMATCH={}", hex::encode(tree_pk)));
                        }
                    }
                    extra.push_str(&format!(" proof_len={}", proof.len()));
                    // Show ErgoTree header to identify script type
                    let tree_hex = hex::encode(resolved.candidate.ergo_tree_bytes());
                    extra.push_str(&format!(" tree={}...", &tree_hex[..40.min(tree_hex.len())]));
                }
                format!("input {i}: {shape} → FAIL{extra}")
            }
            Err(e) => format!("input {i}: {shape} → ERROR ({e})"),
        };
        *shapes.entry(detail).or_insert(0) += 1;
    }
}

/// Extract the ProveDlog public key directly from an ErgoTree's constants,
/// bypassing evaluation. Returns None if the tree isn't a simple P2PK.
fn extract_pk_from_tree(tree: &ergo_ser::ergo_tree::ErgoTree) -> Option<[u8; 33]> {
    use ergo_ser::opcode::{Expr, Payload};
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_ser::sigma_value::SigmaValue;

    // Non-segregated: body is Const with SSigmaProp
    if let Expr::Const {
        tpe: SigmaType::SSigmaProp,
        val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(ge)),
    } = &tree.body
    {
        return Some(*ge.as_bytes());
    }

    // Segregated: body is ConstPlaceholder(0), constant[0] is SSigmaProp
    if let Expr::Op(node) = &tree.body {
        if let (0x73, Payload::ConstPlaceholder { index: 0 }) = (node.opcode, &node.payload) {
            if let Some((
                SigmaType::SSigmaProp,
                SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(ge)),
            )) = tree.constants.first()
            {
                return Some(*ge.as_bytes());
            }
        }
    }

    None
}

fn describe_proposition(prop: &ergo_ser::sigma_value::SigmaBoolean) -> String {
    use ergo_ser::sigma_value::SigmaBoolean;
    match prop {
        SigmaBoolean::TrivialProp(true) => "TrivialTrue".into(),
        SigmaBoolean::TrivialProp(false) => "TrivialFalse".into(),
        SigmaBoolean::ProveDlog(_) => "ProveDlog".into(),
        SigmaBoolean::ProveDHTuple { .. } => "ProveDHTuple".into(),
        SigmaBoolean::Cand(children) => {
            format!(
                "AND({})",
                children
                    .iter()
                    .map(describe_proposition)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        SigmaBoolean::Cor(children) => {
            format!(
                "OR({})",
                children
                    .iter()
                    .map(describe_proposition)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        SigmaBoolean::Cthreshold { k, children } => {
            format!("THRESHOLD({}/{})", k, children.len())
        }
    }
}

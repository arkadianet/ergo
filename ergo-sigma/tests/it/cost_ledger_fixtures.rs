//! Oracle: test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/p2pk.json
//! Generator: scripts/gen-cost-fixture.sh (JVM verify)
//!
//! UTF-8 JSON request bytes, with the JVM's exact field names and embedded
//! consensus hex frames, matching the Task 3.2 verify adapter decoding.
//! The direct verify call supplies costs through its thread-local trace.
//! JVM diagnostics and legacy reduction remain supplementary fixture metadata.

use anyhow::{ensure, Context, Result};
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::{ergo_box, ergo_tree, header, input, transaction};
use ergo_sigma::evaluator::{EvalHeader, ReductionContext};
use serde::Deserialize;
use serde_json::{json, Value};

use std::path::{Path, PathBuf};

// ----- helpers -----

#[derive(Deserialize)]
struct Request {
    tree_hex: String,
    ctx_ext_hex: String,
    proof_hex: String,
    message_hex: String,
    cost_limit_block: u64,
    init_cost_block: u64,
    activated_version: u8,
    tree_version_expected: u8,
    self_box_hex: String,
    inputs_hex: Vec<String>,
    data_inputs_hex: Vec<String>,
    outputs_hex: Vec<String>,
    headers_hex: Vec<String>,
    pre_header_hex: String,
    #[serde(default)]
    rent: Option<bool>,
}

fn decode<T>(
    s: &str,
    read: fn(&mut VlqReader) -> Result<T, ergo_primitives::reader::ReadError>,
) -> Result<T> {
    let bytes = hex::decode(s).context("hex frame")?;
    let mut reader = VlqReader::new(&bytes).with_activated_script_version(1);
    let value = read(&mut reader).context("consensus frame")?;
    for point in reader.take_group_elements() {
        ergo_sigma::evaluator::validate_group_element(point).context("group element")?;
    }
    Ok(value)
}

fn record(rent: bool) -> Value {
    json!({"verdict":"RejectOther", "eval_block_cost":"unavailable",
        "crypto_block_cost":"unavailable", "rent_block_cost":0, "rent_path":rent,
        "total_block_cost":"unavailable", "failure_class":null,
        "rejection_detail":"", "legacy":"unavailable"})
}

fn verify(bytes: &[u8], output: &mut Value) -> Result<()> {
    use ergo_validation::test_helpers::{candidate_to_eval_box, ergo_box_to_eval_box};
    let value: Value = serde_json::from_slice(bytes).context("verify request JSON")?;
    let rent = value.get("rent").and_then(Value::as_bool).unwrap_or(false);
    *output = record(rent);
    let req: Request = serde_json::from_value(value).context("verify request fields")?;
    let rent = req.rent.unwrap_or(false);
    ensure!(
        req.activated_version <= 127 && req.tree_version_expected <= 127,
        "script version range"
    );
    let tree = decode(&req.tree_hex, ergo_tree::read_ergo_tree)?;
    ergo_tree::check_header_size_bit(&tree)?;
    ergo_tree::check_resolvable_methods(&tree)?;
    ergo_tree::check_sigma_prop_root(&tree)?;
    ensure!(
        tree.version == req.tree_version_expected,
        "tree_version_expected differs from serialized tree"
    );
    let self_box = decode(&req.self_box_hex, ergo_box::read_ergo_box)?;
    let inputs = req
        .inputs_hex
        .iter()
        .map(|s| decode(s, ergo_box::read_ergo_box))
        .collect::<Result<Vec<_>>>()?;
    let data = req
        .data_inputs_hex
        .iter()
        .map(|s| decode(s, ergo_box::read_ergo_box))
        .collect::<Result<Vec<_>>>()?;
    let outputs = req
        .outputs_hex
        .iter()
        .map(|s| decode(s, ergo_box::read_ergo_box_candidate))
        .collect::<Result<Vec<_>>>()?;
    let headers = req
        .headers_hex
        .iter()
        .map(|s| decode(s, header::read_header))
        .collect::<Result<Vec<_>>>()?;
    let self_bytes = ergo_box::serialize_ergo_box(&self_box)?;
    let index = inputs
        .iter()
        .position(|b| ergo_box::serialize_ergo_box(b).is_ok_and(|b| b == self_bytes))
        .context("self_box_hex must occur in inputs_hex")?;
    let pre = hex::decode(&req.pre_header_hex).context("pre_header_hex")?;
    ensure!(
        pre.len() == 89,
        "pre_header_hex must contain the 89-byte pre-header frame"
    );
    let pre_context = ergo_validation::context::TransactionContext {
        height: u32::from_be_bytes(pre[49..53].try_into()?),
        miner_pubkey: pre[53..86].try_into()?,
        pre_header_timestamp: u64::from_be_bytes(pre[33..41].try_into()?),
        activated_script_version: req.activated_version,
        pre_header_version: pre[0],
        pre_header_parent_id: pre[1..33].try_into()?,
        pre_header_n_bits: u64::from_be_bytes(pre[41..49].try_into()?),
        pre_header_votes: pre[86..89].try_into()?,
    };
    // The same curve validation used by consensus frame readers.
    let mut pk = vec![7];
    pk.extend_from_slice(&pre_context.miner_pubkey);
    decode(&hex::encode(pk), ergo_ser::sigma_value::read_constant)?;
    let extension = decode(&req.ctx_ext_hex, input::read_context_extension)?;
    let proof = hex::decode(&req.proof_hex).context("proof_hex")?;
    let message = hex::decode(&req.message_hex).context("message_hex")?;
    let spending_proof = input::SpendingProof::new(proof.clone(), extension.clone())?;
    let tx = transaction::Transaction {
        inputs: inputs
            .iter()
            .map(|b| {
                Ok(input::Input {
                    box_id: b.box_id()?,
                    spending_proof: spending_proof.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
        data_inputs: data
            .iter()
            .map(|b| {
                Ok(input::DataInput {
                    box_id: b.box_id()?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        output_candidates: outputs,
    };
    let tx_id = ModifierId::from_bytes(*blake2b256(&transaction::bytes_to_sign(&tx)?).as_bytes());
    let eval_inputs = inputs
        .iter()
        .enumerate()
        .map(|(i, b)| ergo_box_to_eval_box(b, i))
        .collect::<Result<Vec<_>, _>>()?;
    let eval_data = data
        .iter()
        .enumerate()
        .map(|(i, b)| ergo_box_to_eval_box(b, i))
        .collect::<Result<Vec<_>, _>>()?;
    let eval_outputs = tx
        .output_candidates
        .iter()
        .enumerate()
        .map(|(i, b)| candidate_to_eval_box(b, &tx_id, i as u16))
        .collect::<Result<Vec<_>, _>>()?;
    let eval_headers = headers
        .iter()
        .map(|h| {
            Ok(EvalHeader::from_header(
                h,
                *header::serialize_header(h)?.1.as_bytes(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let input_extensions = vec![extension.values.clone(); inputs.len()];
    let ctx = ReductionContext {
        height: pre_context.height,
        self_box: Some(&eval_inputs[index]),
        self_creation_height: self_box.candidate.creation_height,
        outputs: &eval_outputs,
        inputs: &eval_inputs,
        data_inputs: &eval_data,
        miner_pubkey: pre_context.miner_pubkey,
        pre_header_timestamp: pre_context.pre_header_timestamp,
        pre_header_version: pre_context.pre_header_version,
        pre_header_parent_id: pre_context.pre_header_parent_id,
        pre_header_n_bits: pre_context.pre_header_n_bits,
        pre_header_votes: pre_context.pre_header_votes,
        extension: extension.values,
        input_extensions: &input_extensions,
        last_headers: &eval_headers,
        last_block_utxo_root: Some(ergo_ser::sigma_value::AvlTreeData {
            digest: eval_headers
                .first()
                .map_or_else(|| vec![0; 33], |h| h.state_root.to_vec()),
            insert_allowed: true,
            update_allowed: true,
            remove_allowed: true,
            key_length: 32,
            value_length_opt: None,
        }),
        activated_script_version: req.activated_version,
        ergo_tree_version: tree.version,
    };
    ensure!(
        !rent,
        "wallet rent fixtures belong in the transaction runner"
    );
    let limit = JitCost::from_block_cost(req.cost_limit_block)?;
    let mut cost = CostAccumulator::new(limit);
    let baseline = JitCost::from_block_cost(req.init_cost_block)?;
    if let Err(e) = cost.add(baseline) {
        output["verdict"] = json!("RejectCost");
        output["total_block_cost"] = json!(cost.total_block_cost());
        output["failure_class"] = json!("RustCostError");
        output["rejection_detail"] = json!(e.to_string());
        return Ok(());
    }
    ergo_sigma::cost_trace::enable();
    let result = {
        ergo_sigma::reduce::verify_spending_proof_with_context_and_cost(
            &tree, &proof, &message, &ctx, &mut cost,
        )
        .map_err(|e| {
            (
                matches!(
                    e,
                    ergo_sigma::reduce::VerifySpendingError::Eval(
                        ergo_sigma::evaluator::EvalError::CostExceeded(_)
                    )
                ),
                e.to_string(),
            )
        })
    };
    let trace = ergo_sigma::cost_trace::take().context("verify trace")?;
    if let Some((_, snapped)) = trace.snaps.last() {
        output["eval_block_cost"] = json!((snapped - baseline.value()) / 10);
        output["crypto_block_cost"] = json!(trace.sum_by_prefix("Crypto:") / 10);
    }
    match result {
        Ok(ok) => {
            output["verdict"] = json!(if ok { "Accept" } else { "RejectScript" });
            output["total_block_cost"] = json!(cost.total_block_cost());
            if !ok {
                output["rejection_detail"] = json!("Script reduced to false or proof invalid");
            }
        }
        Err((is_cost, detail)) => {
            output["verdict"] = json!(if is_cost {
                "RejectCost"
            } else {
                "RejectScript"
            });
            if is_cost || !trace.snaps.is_empty() {
                output["total_block_cost"] = json!(cost.total_block_cost());
            }
            output["failure_class"] = json!("RustVerifyError");
            output["rejection_detail"] = json!(detail);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct Fixture {
    manifest: Value,
    ledger: Vec<String>,
    request: Value,
    expected: Value,
}

#[derive(Deserialize)]
struct Ledger {
    rows: Vec<LedgerRow>,
}

#[derive(Deserialize)]
struct LedgerRow {
    id: String,
}

fn fixture_paths(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(directory).context("fixture directory")? {
        let path = entry.context("fixture entry")?.path();
        if path.is_dir() {
            fixture_paths(&path, paths)?;
        } else if path.extension().is_some_and(|ext| ext == "json") {
            paths.push(path);
        }
    }
    Ok(())
}

// ----- happy path -----
// ----- round-trips -----
// ----- error paths -----
// ----- oracle parity -----

// ledger: INTERP-eval-sigmaprop-constant
#[test]
fn cost_ledger_fixtures_jvm_verify_fields_match() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/ergo-sigma/cost-ledger");
    let ledger: Ledger =
        toml::from_str(&std::fs::read_to_string(root.join("ledger.toml")).context("ledger.toml")?)
            .context("parse authoritative ledger")?;
    let mut paths = Vec::new();
    fixture_paths(&root.join("fixtures"), &mut paths)?;
    paths.sort();
    ensure!(!paths.is_empty(), "no cost fixtures selected");
    let selected = paths.len();
    for path in paths {
        let fixture: Fixture = serde_json::from_slice(
            &std::fs::read(&path).with_context(|| path.display().to_string())?,
        )
        .with_context(|| format!("parse {}", path.display()))?;
        ensure!(
            !fixture.ledger.is_empty(),
            "{}: missing ledger ids",
            path.display()
        );
        for id in &fixture.ledger {
            ensure!(
                ledger.rows.iter().any(|row| &row.id == id),
                "{}: unknown ledger id {id}",
                path.display()
            );
        }
        ensure!(
            fixture.manifest["scala_sigmastate"] == "6.0.2",
            "{}: unpinned oracle",
            path.display()
        );
        ensure!(
            fixture.manifest["generator"]
                .as_str()
                .is_some_and(|s| s.starts_with("scripts/gen-cost-fixture.sh@")),
            "missing generator"
        );
        ensure!(
            fixture.manifest["date"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "missing generation date"
        );
        let mut actual = record(false);
        verify(&serde_json::to_vec(&fixture.request)?, &mut actual)
            .with_context(|| format!("verify {}", path.display()))?;
        for field in [
            "verdict",
            "eval_block_cost",
            "crypto_block_cost",
            "total_block_cost",
            "failure_class",
        ] {
            let expected = fixture
                .expected
                .get(field)
                .with_context(|| format!("{}: missing {field}", path.display()))?;
            assert_eq!(&actual[field], expected, "{}: {field}", path.display());
        }
        for field in ["rent_block_cost", "rent_path"] {
            if let Some(expected) = fixture.expected.get(field) {
                assert_eq!(&actual[field], expected, "{}: {field}", path.display());
            }
        }
    }
    eprintln!("cost fixtures: selected={selected} executed={selected} skipped=0 failed=0");
    Ok(())
}

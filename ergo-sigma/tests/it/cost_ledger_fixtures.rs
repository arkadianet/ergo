//! Oracle: test-vectors/ergo-sigma/cost-ledger/fixtures/version/
//! Oracle: test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/
//! Oracle: test-vectors/ergo-sigma/cost-ledger/fixtures/op-fixed/
//! Oracle: test-vectors/ergo-sigma/cost-ledger/fixtures/op-per-item/
//! Oracle: test-vectors/ergo-sigma/cost-ledger/fixtures/eval/
//! Oracle: test-vectors/ergo-sigma/cost-ledger/fixtures/method/
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

use std::io::Read;
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
    #[serde(default)]
    observe_evaluator_failure: bool,
    #[serde(default)]
    observe_deserialization_failure: bool,
    #[serde(default)]
    parse_only: bool,
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
    ensure!(
        value.get("validation_settings_replaced_rules").is_none(),
        "validation-settings overrides require JVM-only evidence until L4/L5 plumbing exists"
    );
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
    if req.parse_only {
        ensure!(
            matches!(tree.body, ergo_ser::opcode::Expr::Unparsed(_)),
            "parse-only rejection requires a retained parser validation failure"
        );
        // Recover the parser's rule-1001 reason from the retained wire body.
        // The fixture has no segregated constants; other unparsed failures
        // must not be mislabeled as Boolean-root validation.
        let bytes = hex::decode(&req.tree_hex)?;
        let mut reader = VlqReader::new(&bytes);
        let header = reader.get_u8()?;
        ensure!(header & 0x10 == 0, "parse-only probe must be nonsegregated");
        if header & 8 != 0 {
            reader.get_u32_exact()?;
        }
        let body = ergo_ser::opcode::parse_body(&mut reader, tree.version)?;
        ensure!(
            ergo_tree::determinable_root_type_of(&body, &[])
                == Some(ergo_ser::sigma_type::SigmaType::SBoolean),
            "parse-only probe must retain a Boolean root"
        );
        output["verdict"] = json!("RejectScript");
        output["failure_class"] = json!("sigma.validation.ValidationException");
        return Ok(());
    }
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
        output["failure_class"] = json!("sigma.exceptions.CostLimitException");
        output["rejection_detail"] = json!(e.to_string());
        return Ok(());
    }
    ergo_sigma::cost_trace::enable();
    let result = ergo_sigma::reduce::verify_spending_proof_with_context_and_cost(
        &tree, &proof, &message, &ctx, &mut cost,
    );
    let trace = ergo_sigma::cost_trace::take().context("verify trace")?;
    if let Some((_, snapped)) = trace.snaps.last() {
        output["eval_block_cost"] = json!((snapped - baseline.value()) / 10);
        output["crypto_block_cost"] = json!(trace.sum_by_prefix("Crypto:") / 10);
    }
    match result {
        Ok(ok) => {
            if tree.version > 3 && req.activated_version > 3 {
                ensure!(trace.snaps.is_empty(), "future-version bypass evaluated");
                output["eval_block_cost"] = json!(0);
                output["crypto_block_cost"] = json!(0);
            }
            output["verdict"] = json!(if ok { "Accept" } else { "RejectScript" });
            output["total_block_cost"] = json!(cost.total_block_cost());
            if !ok {
                output["rejection_detail"] = json!("Script reduced to false or proof invalid");
            }
        }
        Err(error) => {
            let (verdict, failure_class) = jvm_failure(&error)?;
            let is_cost = verdict == "RejectCost";
            if req.observe_evaluator_failure {
                ensure!(
                    baseline.value() == 0,
                    "failure observation requires zero init"
                );
                output["evaluator_failure_block_cost"] = json!(cost.total_block_cost());
            }
            output["verdict"] = json!(verdict);
            if is_cost
                || !trace.snaps.is_empty()
                || req.observe_deserialization_failure
                || matches!(
                    error,
                    ergo_sigma::reduce::VerifySpendingError::Eval(
                        ergo_sigma::evaluator::EvalError::TreeVersionAboveActivated { .. }
                            | ergo_sigma::evaluator::EvalError::UnparsedErgoTree
                    )
                )
            {
                output["total_block_cost"] = json!(cost.total_block_cost());
            }
            output["failure_class"] = json!(failure_class);
            output["rejection_detail"] = json!(error.to_string());
        }
    }
    Ok(())
}

// Semantic equivalence for the oracle verify failure table (design section 4).
// CostExceeded -> CostLimitException, including baseline exhaustion.
// Non-executable/deprecated/internal nodes and TaggedVariable (0x71)
// -> RuntimeException from Value.eval (op-fixed rejection fixtures).
// Interpreter version guards -> InterpreterException.
// Conjecture equality's bare RuntimeException -> RejectOther, as classified by
// the JVM adapter; the supplementary evaluator observation retains its cost.
// Unknown Rust errors fail the adapter: their JVM class needs oracle evidence;
// comparing only exception presence would silently accept the wrong failure.
fn jvm_failure(
    error: &ergo_sigma::reduce::VerifySpendingError,
) -> Result<(&'static str, &'static str)> {
    use ergo_sigma::evaluator::EvalError;
    use ergo_sigma::reduce::VerifySpendingError;
    match error {
        VerifySpendingError::Eval(EvalError::TypeError {
            expected: "matching numeric types for Plus",
            ..
        }) => Ok(("RejectScript", "java.lang.ClassCastException")),
        VerifySpendingError::Eval(EvalError::TypeError {
            expected: "matching deserialized script type",
            ..
        }) => Ok(("RejectScript", "sigma.validation.ValidationException")),
        VerifySpendingError::Eval(EvalError::CostExceeded(_)) => {
            Ok(("RejectCost", "sigma.exceptions.CostLimitException"))
        }
        VerifySpendingError::Eval(
            EvalError::TypeError {
                expected: "substituted DeserializeContext" | "substituted DeserializeRegister",
                ..
            }
            | EvalError::UnsupportedOpcode(0x71)
            | EvalError::NotExecutable(..)
            | EvalError::DeprecatedOpcode(_)
            | EvalError::InternalOpcode(..),
        ) => Ok(("RejectScript", "java.lang.RuntimeException")),
        VerifySpendingError::Eval(EvalError::RuntimeException(
            "Cannot compare SigmaBoolean values: unknown type"
            | "Unknown type SString"
            | "DeserializeRegister script type mismatch",
        )) => Ok(("RejectOther", "java.lang.RuntimeException")),
        VerifySpendingError::Eval(EvalError::InvocationTargetException("Unknown type SString")) => {
            Ok(("RejectOther", "java.lang.reflect.InvocationTargetException"))
        }
        VerifySpendingError::Eval(
            EvalError::SoftForkNotActivated { .. }
            | EvalError::UnparsedErgoTree
            | EvalError::TreeVersionAboveActivated { .. },
        ) => Ok(("RejectScript", "sigma.exceptions.InterpreterException")),
        // Reusing a single-lookup proof for two getMany keys can exhaust
        // its directions. The JVM evaluator reports this as InterpreterException.
        VerifySpendingError::Eval(EvalError::TypeError {
            expected: "valid AVL proof for getMany",
            got,
        }) if got == "proof verification failed" => {
            Ok(("RejectScript", "sigma.exceptions.InterpreterException"))
        }
        VerifySpendingError::Eval(EvalError::RuntimeException(
            "Coll.updated: index out of bounds",
        )) => Ok(("RejectScript", "java.lang.IndexOutOfBoundsException")),
        VerifySpendingError::Eval(EvalError::RuntimeException(
            "SigmaAnd requires nonempty children" | "SigmaOr requires nonempty children",
        )) => Ok(("RejectScript", "java.lang.IllegalArgumentException")),
        VerifySpendingError::Eval(EvalError::TypeError {
            expected: "Some value",
            got,
        }) if got == "None" => Ok(("RejectScript", "java.util.NoSuchElementException")),
        VerifySpendingError::Eval(EvalError::TypeError {
            expected: "valid AVL proof for get",
            ..
        }) => Ok(("RejectScript", "sigma.exceptions.InterpreterException")),
        VerifySpendingError::Eval(EvalError::RuntimeException(
            "SGlobal.powHit: k must be in [2, 32]" | "SGlobal.powHit: N must be >= 16",
        ))
        | VerifySpendingError::Eval(EvalError::TypeError {
            expected: "Header for SHeader access" | "BigInt for SGlobal.encodeNbits",
            ..
        }) => Ok(("RejectScript", "java.lang.IllegalArgumentException")),
        VerifySpendingError::Eval(EvalError::TypeError {
            expected: "serializable value for SubstConstants",
            got,
        }) if got == "PreHeader" => Ok(("RejectScript", "sigma.serialization.SerializerException")),
        _ => anyhow::bail!("no oracle-backed JVM failure mapping for {error:?}"),
    }
}

#[derive(Deserialize)]
struct Fixture {
    manifest: Value,
    ledger: Vec<String>,
    request: Value,
    expected: Value,
    #[serde(default)]
    known_divergence: Option<KnownDivergence>,
}

#[derive(Deserialize)]
struct KnownDivergence {
    ledger: String,
    classification: String,
    tracking: String,
    differences: Value,
}

#[derive(Deserialize)]
struct Ledger {
    rows: Vec<LedgerRow>,
}

#[derive(Deserialize)]
struct LedgerRow {
    id: String,
    state: String,
}

fn read_fixture(path: &Path) -> Result<Vec<u8>> {
    let compressed = path.with_extension("json.gz");
    let path = if path.extension().is_some_and(|ext| ext == "json") && compressed.exists() {
        compressed.as_path()
    } else {
        path
    };
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut bytes = Vec::new();
    if path.extension().is_some_and(|ext| ext == "gz") {
        flate2::read::GzDecoder::new(file)
            .read_to_end(&mut bytes)
            .with_context(|| format!("decompress {}", path.display()))?;
    } else {
        std::io::BufReader::new(file)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read {}", path.display()))?;
    }
    Ok(bytes)
}

fn fixture_paths(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(directory).context("fixture directory")? {
        let path = entry.context("fixture entry")?.path();
        if path.is_dir() {
            fixture_paths(&path, paths)?;
        } else if path.to_string_lossy().ends_with(".json.gz")
            || (path.extension().is_some_and(|ext| ext == "json")
                && !path.with_extension("json.gz").exists())
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn verify_fixture(path: &Path, fixture: Fixture, ledger: &Ledger) -> Result<bool> {
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
        "{}: missing manifest.generator",
        path.display()
    );
    ensure!(
        fixture.manifest["date"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "{}: missing manifest.date",
        path.display()
    );
    let mut actual = record(false);
    verify(&serde_json::to_vec(&fixture.request)?, &mut actual)
        .with_context(|| format!("verify {}", path.display()))?;
    let mut differences = serde_json::Map::new();
    for field in [
        "verdict",
        "eval_block_cost",
        "crypto_block_cost",
        "total_block_cost",
    ] {
        let expected = fixture
            .expected
            .get(field)
            .with_context(|| format!("{}: missing {field}", path.display()))?;
        if fixture.request["parse_only"] == true
            || ((fixture.request["observe_deserialization_failure"] == true
                || fixture
                    .ledger
                    .iter()
                    .any(|id| id == "VERSION-v6-method-gate")
                || fixture
                    .ledger
                    .iter()
                    .any(|id| id == "VERSION-tree-version-gate"))
                && field == "total_block_cost")
        {
            ensure!(
                &actual[field] == expected,
                "{}: strict {field}: Rust={} JVM={expected}",
                path.display(),
                actual[field]
            );
        }
        // Section 4: an unavailable rejected-input cost is not a mismatch.
        if field != "verdict"
            && (actual["verdict"] != "Accept" || fixture.expected["verdict"] != "Accept")
            && (actual[field] == "unavailable" || *expected == "unavailable")
        {
            continue;
        }
        if &actual[field] != expected {
            differences.insert(
                field.to_owned(),
                json!({"rust": actual[field], "jvm": expected}),
            );
        }
    }
    let failure_class = fixture
        .expected
        .get("failure_class")
        .with_context(|| format!("{}: missing failure_class", path.display()))?;
    if &actual["failure_class"] != failure_class {
        differences.insert(
            "failure_class".to_owned(),
            json!({"rust": actual["failure_class"], "jvm": failure_class}),
        );
    }
    if fixture.request["observe_evaluator_failure"] == true {
        let expected = &fixture.expected["evaluator_failure_block_cost"];
        ensure!(
            expected.is_u64(),
            "{}: missing JVM failure observation",
            path.display()
        );
        if &actual["evaluator_failure_block_cost"] != expected {
            differences.insert(
                "evaluator_failure_block_cost".to_owned(),
                json!({"rust": actual["evaluator_failure_block_cost"], "jvm": expected}),
            );
        }
    }
    for field in ["rent_block_cost", "rent_path"] {
        if let Some(expected) = fixture.expected.get(field) {
            ensure!(
                &actual[field] == expected,
                "{}: {field}: Rust={} JVM={expected}",
                path.display(),
                actual[field]
            );
        }
    }
    let differences = Value::Object(differences);
    if let Some(known) = fixture.known_divergence {
        ensure!(
            fixture.ledger.contains(&known.ledger)
                && ledger
                    .rows
                    .iter()
                    .any(|row| row.id == known.ledger && row.state == "DIVERGENT"),
            "{}: known divergence requires an attached DIVERGENT ledger row",
            path.display()
        );
        let classified = match known.classification.as_str() {
            "cost-only" => differences.as_object().is_some_and(|fields| {
                fields.keys().all(|field| {
                    matches!(
                        field.as_str(),
                        "eval_block_cost" | "total_block_cost" | "evaluator_failure_block_cost"
                    )
                })
            }),
            "accept-invalid" => {
                actual["verdict"] == "Accept"
                    && matches!(
                        fixture.expected["verdict"].as_str(),
                        Some("RejectScript" | "RejectOther")
                    )
                    && differences.as_object().is_some_and(|fields| {
                        fields
                            .keys()
                            .all(|field| matches!(field.as_str(), "verdict" | "failure_class"))
                    })
            }
            _ => false,
        };
        let tracking = if path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|family| family == "interpreter")
        {
            "test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/DIVERGENCES.md"
        } else {
            "test-vectors/ergo-sigma/cost-ledger/fixtures/eval/DIVERGENCES.md"
        };
        ensure!(
            classified
                && known.tracking == tracking
                && differences
                    .as_object()
                    .is_some_and(|fields| !fields.is_empty()),
            "{}: stale or misclassified divergence; triage required",
            path.display()
        );
        ensure!(
            differences == known.differences,
            "{}: recorded divergence changed: {differences}",
            path.display()
        );
        Ok(true)
    } else {
        ensure!(
            differences == json!({}),
            "{}: unexplained divergence: {differences}",
            path.display()
        );
        Ok(false)
    }
}

// ----- happy path -----
// ----- round-trips -----
// ----- error paths -----

#[test]
fn cost_ledger_divergence_invalid_annotations_rejected() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/ergo-sigma/cost-ledger");
    let path = root.join("fixtures/eval/collection-group.json.gz");
    let document: Value = serde_json::from_slice(&read_fixture(&path)?)?;
    let mut case = document["cases"]
        .as_array()
        .context("cases")?
        .iter()
        .find(|case| case["name"] == "group-equal-n0-prefix0")
        .context("oracle case")?
        .clone();
    case["manifest"] = document["manifest"].clone();
    case["ledger"] = document["ledger"].clone();
    let mut ledger: Ledger = toml::from_str(&std::fs::read_to_string(root.join("ledger.toml"))?)?;
    // Synthetic metadata exercises runner validation; oracle expectations in
    // the tracked fixture stay unchanged and the parity test uses them directly.
    let actual_eval = case["expected"]["eval_block_cost"].clone();
    let actual_total = case["expected"]["total_block_cost"].clone();
    case["expected"]["eval_block_cost"] = json!(999);
    case["expected"]["total_block_cost"] = json!(999);
    case["known_divergence"] = json!({
        "ledger": "EVAL-eq-coll-descriptor",
        "classification": "cost-only",
        "tracking": "test-vectors/ergo-sigma/cost-ledger/fixtures/eval/DIVERGENCES.md",
        "differences": {
            "eval_block_cost": {"rust": actual_eval, "jvm": 999},
            "total_block_cost": {"rust": actual_total, "jvm": 999}
        }
    });
    for row in &mut ledger.rows {
        if row.id == "EVAL-eq-coll-descriptor" {
            row.state = "DIVERGENT".to_owned();
        }
    }
    let check = |value: Value| verify_fixture(&path, serde_json::from_value(value)?, &ledger);
    assert!(check(case.clone())?);

    let mut wrong_tracking = case.clone();
    wrong_tracking["known_divergence"]["tracking"] =
        json!("test-vectors/ergo-sigma/cost-ledger/fixtures/method/DIVERGENCES.md");
    assert!(check(wrong_tracking)
        .unwrap_err()
        .to_string()
        .contains("stale or misclassified divergence"));

    let mut changed = case.clone();
    changed["known_divergence"]["differences"]["eval_block_cost"]["rust"] = json!(0);
    assert!(check(changed)
        .unwrap_err()
        .to_string()
        .contains("recorded divergence changed"));

    let mut untracked = case.clone();
    untracked
        .as_object_mut()
        .context("case object")?
        .remove("known_divergence");
    assert!(check(untracked)
        .unwrap_err()
        .to_string()
        .contains("unexplained divergence"));

    let mut stale = case.clone();
    for field in ["eval_block_cost", "total_block_cost"] {
        stale["expected"][field] = case["known_divergence"]["differences"][field]["rust"].clone();
    }
    assert!(check(stale)
        .unwrap_err()
        .to_string()
        .contains("stale or misclassified divergence"));

    let mut closed_ledger = ledger;
    for row in &mut closed_ledger.rows {
        if row.id == "EVAL-eq-coll-descriptor" {
            row.state = "CLOSED".to_owned();
        }
    }
    assert!(
        verify_fixture(&path, serde_json::from_value(case)?, &closed_ledger)
            .unwrap_err()
            .to_string()
            .contains("requires an attached DIVERGENT ledger row")
    );
    Ok(())
}

// ----- oracle parity -----

// ledger: VERSION-pre-v3-upcast, VERSION-v3-bool-root, VERSION-v6-method-gate, VERSION-selfboxindex-bug, VERSION-tree-version-gate, VERSION-v6-lazy-defaults, INTERP-crypto-conjunction, INTERP-crypto-threshold, INTERP-crypto-trivial-I013, INTERP-costlimit-op, INTERP-embedded-script-deser, INTERP-deser-subst, ORDER-propertycall-receiver, ORDER-methodcall-arguments, ORDER-powHit-validation, ORDER-serialize-incremental, ORDER-fixed-method-invocation, ORDER-avl-verifier-lookup, ORDER-if-condition, ORDER-optionget-input, METHOD-header-props, METHOD-global-encodeNbits, METHOD-coll-flatMap, METHOD-coll-indexOf, METHOD-coll-indices, METHOD-coll-patch, METHOD-coll-reverse, METHOD-coll-startsEndsWith, METHOD-coll-updateMany, METHOD-coll-updated, METHOD-coll-zip, METHOD-global-deserializeTo, METHOD-global-powHit, METHOD-global-xor, EVAL-avl-cost-height, METHOD-avl-contains, METHOD-avl-get, METHOD-avl-getMany, METHOD-avl-insert, METHOD-avl-insertOrUpdate, METHOD-avl-remove, METHOD-avl-update, METHOD-global-serialize, METHOD-global-serialize-E042, METHOD-global-serialize-E043, METHOD-global-serialize-E044, METHOD-global-serialize-E045, METHOD-global-serialize-E046, METHOD-global-serialize-E047, METHOD-option-map, METHOD-option-filter, EVAL-sstring-rejected, OP-0x96, OP-0xB3, OP-0x98, OP-0xCB, OP-0xD8, ROUND-perItem-chunking, OP-0xAE, OP-0xB5, OP-0xB0, OP-0xAF, OP-0xAD, OP-0x97, OP-0xCC, OP-0xEA, OP-0xEB, OP-0xD0, OP-0xB4, OP-0x74, OP-0xFF, OP-0x9B, INTERP-eval-sigmaprop-constant, OP-0x95, OP-0xDA, OP-0xE7-0xE9, OP-0xEC, OP-0xED, OP-0xF2, OP-0xF3, OP-0xF5, OP-0xF6, OP-0xF7, OP-0xF8, OP-TaggedVariable-A003, ORDER-bitop-charge-then-reject, EVAL-const-inline, EVAL-hasdeserialize-fork, EVAL-addtoenv, EVAL-numeric-cast, EVAL-arith-bigint, EVAL-eq-prim, EVAL-eq-matchtype, EVAL-eq-tuple, EVAL-eq-groupelement, EVAL-eq-bigint, EVAL-eq-avltree, EVAL-eq-box, EVAL-eq-option, EVAL-eq-preheader, EVAL-eq-header, EVAL-eq-coll-sigmaprop-descriptor, EVAL-eq-coll-fallback, EVAL-eq-tokens, EVAL-eq-sigmaboolean, EVAL-deferred-charge-on-exception, EVAL-eq-boxcollection, EVAL-eq-coll-descriptor, EVAL-eq-mismatch-and-unit-E032
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
    let mut fixtures = Vec::new();
    for path in paths {
        let value: Value = serde_json::from_slice(
            &read_fixture(&path).with_context(|| path.display().to_string())?,
        )
        .with_context(|| format!("parse {}", path.display()))?;
        if let Some(cases) = value.get("cases") {
            let cases = cases.as_array().context("fixture cases must be an array")?;
            ensure!(!cases.is_empty(), "{}: empty cases", path.display());
            for (index, case) in cases.iter().enumerate() {
                let mut case = case.clone();
                case["manifest"] = value["manifest"].clone();
                case["ledger"] = value["ledger"].clone();
                let label = PathBuf::from(format!("{} [case {index}]", path.display()));
                let fixture: Fixture = serde_json::from_value(case)
                    .with_context(|| format!("parse {}", label.display()))?;
                fixtures.push((label, fixture));
            }
        } else {
            let fixture: Fixture = serde_json::from_value(value)
                .with_context(|| format!("parse {}", path.display()))?;
            fixtures.push((path, fixture));
        }
    }
    let selected = fixtures.len();
    let mut failed = 0;
    let mut known_divergent = 0;
    for (path, fixture) in fixtures {
        match verify_fixture(&path, fixture, &ledger) {
            Ok(true) => known_divergent += 1,
            Ok(false) => (),
            Err(error) => {
                eprintln!("{error:#}");
                failed += 1;
            }
        }
    }
    eprintln!("cost fixtures: selected={selected} executed={selected} skipped=0 failed={failed} known_divergent={known_divergent}");
    ensure!(failed == 0, "{failed} cost fixtures diverged");
    Ok(())
}

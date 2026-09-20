//! Oracle: scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala (verify)
//!
//! UTF-8 JSON request bytes, with the JVM's exact field names and embedded
//! consensus hex frames. Diagnostics and legacy reduction are supplementary;
//! differential equality compares verdict and all cost components, including on failure.

use anyhow::{ensure, Context, Result};
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::{ergo_box, ergo_tree, header, input, transaction};
use ergo_sigma::evaluator::{EvalHeader, ReductionContext};
use serde::Deserialize;
use serde_json::{json, Value};

use super::Verdict;

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
    storage_fee_factor: Option<Value>,
}

fn decode<T>(
    s: &str,
    read: fn(&mut VlqReader) -> Result<T, ergo_primitives::reader::ReadError>,
) -> Result<T> {
    let bytes = hex::decode(s).context("hex frame")?;
    let mut reader = VlqReader::new(&bytes).with_activated_script_version(1);
    let value = read(&mut reader).context("consensus frame")?;
    super::drain_and_check_group_elements(&mut reader).map_err(anyhow::Error::msg)?;
    Ok(value)
}

fn record(rent: bool) -> Value {
    json!({"verdict":"RejectOther", "eval_block_cost":"unavailable",
        "crypto_block_cost":"unavailable", "rent_block_cost":0, "rent_path":rent,
        "total_block_cost":"unavailable", "failure_class":null,
        "rejection_detail":"", "legacy":"unavailable"})
}

pub(crate) fn verify_verdict(bytes: &[u8]) -> (Verdict, usize) {
    let mut output = record(false);
    if let Err(error) = verify(bytes, &mut output) {
        output["failure_class"] = json!("RustRequestError");
        output["rejection_detail"] = json!(format!("{error:#}"));
    }
    (Verdict::Accept(output.to_string()), bytes.len())
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
        validation_settings: Default::default(),
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
    let mut params = ergo_validation::context::ProtocolParams::mainnet_default();
    if rent {
        params.storage_fee_factor = serde_json::from_value(
            req.storage_fee_factor
                .context("storage_fee_factor required for rent")?,
        )
        .context("storage_fee_factor must be an i32")?;
        ensure!(
            params.storage_fee_factor >= 0,
            "storage_fee_factor must be nonnegative"
        );
    }
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
    let result = if rent {
        let mut cx = ergo_validation::tx::TxValidationCtx {
            ctx: &pre_context,
            params: &params,
            cost: &mut cost,
            last_headers: &headers,
            rules: Default::default(),
        };
        ergo_validation::test_helpers::validate_script_input(
            &tx, &inputs, &data, &message, &mut cx, index, &tree,
        )
        .map(|()| true)
        .map_err(|error| (cost.total() > limit, false, error.to_string()))
    } else {
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
                matches!(
                    e,
                    ergo_sigma::reduce::VerifySpendingError::Eval(
                        ergo_sigma::evaluator::EvalError::RuntimeException(
                            "DeserializeRegister script type mismatch"
                        )
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
        // Supplementary direct evaluator output, matching the JVM legacy probe.
        let mut legacy_cost = CostAccumulator::new(JitCost::from_block_cost(req.cost_limit_block)?);
        if let Ok(prop) = ergo_sigma::evaluator::reduce_expr_with_cost(
            &tree.body,
            &ctx,
            &tree.constants,
            &mut legacy_cost,
        ) {
            let mut writer = ergo_primitives::writer::VlqWriter::new();
            ergo_ser::sigma_value::write_sigma_boolean(&mut writer, &prop)?;
            output["legacy"] = json!(format!(
                "P:{}|{}",
                hex::encode(writer.result()),
                legacy_cost.total().value()
            ));
        }
    } else if rent && result.is_ok() {
        output["eval_block_cost"] = json!(0);
        output["crypto_block_cost"] = json!(0);
        output["rent_block_cost"] = json!((cost.total().value() - baseline.value()) / 10);
    }
    match result {
        Ok(ok) => {
            output["verdict"] = json!(if ok { "Accept" } else { "RejectScript" });
            output["total_block_cost"] = json!(cost.total_block_cost());
            if !ok {
                output["rejection_detail"] = json!("Script reduced to false or proof invalid");
            }
        }
        Err((is_cost, is_other, detail)) => {
            output["verdict"] = json!(if is_cost {
                "RejectCost"
            } else if is_other {
                "RejectOther"
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

/// Compare observable costs independently; unavailable components carry no evidence.
pub(super) fn components_agree(a: &Value, b: &Value) -> bool {
    ["verdict", "rent_path"].iter().all(|key| a[key] == b[key])
        && [
            "eval_block_cost",
            "crypto_block_cost",
            "rent_block_cost",
            "total_block_cost",
        ]
        .iter()
        .all(|key| a[key] == "unavailable" || b[key] == "unavailable" || a[key] == b[key])
}

pub(super) fn comparable(line: &str) -> Option<Value> {
    let record: Value = serde_json::from_str(line).ok()?;
    if !matches!(
        record.get("verdict")?.as_str()?,
        "Accept" | "RejectScript" | "RejectCost" | "RejectOther"
    ) {
        return None;
    }
    record.get("rent_path")?.as_bool()?;
    for key in [
        "eval_block_cost",
        "crypto_block_cost",
        "rent_block_cost",
        "total_block_cost",
    ] {
        let value = record.get(key)?;
        if value.as_u64().is_none() && value != "unavailable" {
            return None;
        }
    }
    record.get("rejection_detail")?.as_str()?;
    let failure = record.get("failure_class")?;
    if !failure.is_null() && !failure.is_string() {
        return None;
    }
    record.get("legacy")?.as_str()?;
    let mut result = serde_json::Map::new();
    for key in [
        "verdict",
        "eval_block_cost",
        "crypto_block_cost",
        "total_block_cost",
        "rent_block_cost",
        "rent_path",
    ] {
        result.insert(key.into(), record.get(key)?.clone());
    }
    Some(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn fixtures() -> Vec<Value> {
        serde_json::from_str(include_str!(
            "../../../test-vectors/ergo-sigma/verify/cases.json"
        ))
        .unwrap()
    }

    fn actual(request: &Value) -> Value {
        let (Verdict::Accept(record), consumed) =
            verify_verdict(&serde_json::to_vec(request).unwrap())
        else {
            panic!("verify must return a structured record");
        };
        assert_eq!(consumed, serde_json::to_vec(request).unwrap().len());
        serde_json::from_str(&record).unwrap()
    }

    fn reconciliation(a: &Value, b: &Value) -> super::super::Reconciliation {
        let spec = super::super::oracle_surfaces()
            .into_iter()
            .find(|s| s.name == "verify")
            .unwrap();
        super::super::reconcile(
            &spec,
            Verdict::Accept(a.to_string()),
            Verdict::Accept(b.to_string()),
            &[],
        )
    }

    // ----- happy path -----

    #[test]
    fn verify_unavailable_components_agree_with_numeric_costs() {
        let record = fixtures()[0]["expected"].clone();
        for key in [
            "eval_block_cost",
            "crypto_block_cost",
            "rent_block_cost",
            "total_block_cost",
        ] {
            let mut numeric = record.clone();
            numeric[key] = json!(123);
            let mut unavailable = numeric.clone();
            unavailable[key] = json!("unavailable");
            assert_eq!(
                reconciliation(&numeric, &unavailable),
                super::super::Reconciliation::Agree
            );
            assert_eq!(
                reconciliation(&unavailable, &numeric),
                super::super::Reconciliation::Agree
            );
        }
    }

    #[test]
    fn verify_numeric_cost_and_verdict_mismatches_diverge() {
        let record = fixtures()[0]["expected"].clone();
        for key in [
            "eval_block_cost",
            "crypto_block_cost",
            "rent_block_cost",
            "total_block_cost",
            "verdict",
            "rent_path",
        ] {
            let mut a = record.clone();
            let mut b = record.clone();
            a["total_block_cost"] = json!("unavailable");
            b["total_block_cost"] = json!(123);
            match key {
                "verdict" => {
                    a[key] = json!("RejectCost");
                    b[key] = json!("RejectScript");
                }
                "rent_path" => {
                    a[key] = json!(false);
                    b[key] = json!(true);
                }
                _ => {
                    a[key] = json!(123);
                    b[key] = json!(124);
                }
            }
            assert!(matches!(
                reconciliation(&a, &b),
                super::super::Reconciliation::Diverges(_)
            ));
        }
    }

    #[test]
    fn verify_surface_registered_available() {
        assert!(crate::surfaces::names().contains(&"verify"));
        assert!(super::super::oracle_surfaces()
            .iter()
            .any(|s| s.name == "verify"));
    }

    // ----- round-trips -----

    #[test]
    fn verify_request_json_whitespace_preserves_record() {
        let request = &fixtures()[0]["request"];
        let (a, _) = verify_verdict(&serde_json::to_vec(request).unwrap());
        let (b, _) = verify_verdict(&serde_json::to_vec_pretty(request).unwrap());
        assert_eq!(a, b);
    }

    // ----- error paths -----

    #[test]
    fn verify_request_malformed_reject_other() {
        for bytes in [b"{".as_slice(), b"null", b"{}", &[255]] {
            let (Verdict::Accept(record), _) = verify_verdict(bytes) else {
                panic!("missing record")
            };
            assert_eq!(
                serde_json::from_str::<Value>(&record).unwrap()["verdict"],
                "RejectOther"
            );
        }
        let mut request = fixtures()[0]["request"].clone();
        request["pre_header_hex"] = json!("00");
        assert_eq!(actual(&request)["verdict"], "RejectOther");
        request = fixtures()[0]["request"].clone();
        request["inputs_hex"] = json!([]);
        assert_eq!(actual(&request)["verdict"], "RejectOther");
    }

    #[test]
    fn verify_rejected_cost_difference_detected() {
        let spec = super::super::oracle_surfaces()
            .into_iter()
            .find(|s| s.name == "verify")
            .unwrap();
        let a = fixtures()[4]["expected"].clone();
        let mut b = a.clone();
        b["total_block_cost"] = json!(404);
        assert!(matches!(
            super::super::reconcile(
                &spec,
                Verdict::Accept(a.to_string()),
                Verdict::Accept(b.to_string()),
                b""
            ),
            super::super::Reconciliation::Diverges(_)
        ));
        b = a.clone();
        b["failure_class"] = json!("DifferentRuntimeException");
        b["rejection_detail"] = json!("runtime diagnostic");
        b["legacy"] = json!("unavailable");
        assert_eq!(
            super::super::reconcile(
                &spec,
                Verdict::Accept(a.to_string()),
                Verdict::Accept(b.to_string()),
                b""
            ),
            super::super::Reconciliation::Agree
        );
    }

    // ----- oracle parity -----

    #[test]
    fn verify_rent_fallback_fractional_overrun_reject_cost() {
        let cases: Vec<Value> = serde_json::from_str(include_str!(
            "../../../test-vectors/ergo-sigma/verify/fix-cases.json"
        ))
        .unwrap();
        let case = &cases[0];
        assert_eq!(case["name"], "rent-fallback-fractional-overrun");
        assert_eq!(case["expected"]["verdict"], "RejectCost");
        assert_eq!(
            comparable(&actual(&case["request"]).to_string()),
            comparable(&case["expected"].to_string())
        );
    }

    #[test]
    fn verify_storage_fee_factor_conditional_validation_matches_jvm() {
        let cases: Vec<Value> = serde_json::from_str(include_str!(
            "../../../test-vectors/ergo-sigma/verify/fix-cases.json"
        ))
        .unwrap();
        for case in &cases[1..] {
            assert_eq!(
                comparable(&actual(&case["request"]).to_string()),
                comparable(&case["expected"].to_string()),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn verify_rent_jvm_fixtures_block_costs_match() {
        for case in fixtures()
            .into_iter()
            .filter(|case| case["expected"]["rent_block_cost"] == 50)
        {
            let result = actual(&case["request"]);
            assert_eq!(case["expected"]["rent_block_cost"], 50);
            assert_eq!(result["verdict"], case["expected"]["verdict"]);
            assert_eq!(
                result["rent_block_cost"],
                case["expected"]["rent_block_cost"]
            );
            assert_eq!(
                result["total_block_cost"],
                case["expected"]["total_block_cost"]
            );
        }
    }

    #[test]
    fn verify_jvm_fixtures_costs_and_verdicts_match() {
        for case in fixtures() {
            let result = actual(&case["request"]);
            assert_eq!(
                comparable(&result.to_string()),
                comparable(&case["expected"].to_string()),
                "{}: {result}",
                case["name"]
            );
            assert_eq!(
                result.as_object().unwrap().keys().collect::<Vec<_>>(),
                case["expected"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn deserialize_fixture_corpus_verify_verdicts_match_jvm() {
        let fixture: Value = serde_json::from_reader(flate2::read::GzDecoder::new(
            &include_bytes!("../../../test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/deserialize-types.json.gz")[..],
        )).expect("JVM fixture JSON");
        let cases = fixture["cases"].as_array().expect("fixture cases");
        for case in cases {
            let request = serde_json::to_vec(&case["request"]).expect("request JSON");
            let (Verdict::Accept(record), consumed) = verify_verdict(&request) else {
                panic!("verify surface must return a structured record");
            };
            let actual: Value = serde_json::from_str(&record).expect("verify record");
            assert_eq!(consumed, request.len());
            assert_eq!(
                actual["verdict"], case["expected"]["verdict"],
                "{}: {actual}",
                case["name"]
            );
        }
        eprintln!(
            "deserialize verify corpus: selected={} executed={} skipped=0 failed=0",
            cases.len(),
            cases.len()
        );
    }
}

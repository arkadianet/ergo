//! Oracle: test-vectors/ergo-sigma/cost-ledger/sweeps/ (JVM verify and validateStateful).

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_ser::{ergo_box, input, transaction};
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::error::ValidationError;
use ergo_validation::test_helpers::validate_script_input;
use ergo_validation::{TxValidationCtx, TxValidationRules};
use serde_json::Value;

// ----- helpers -----

fn decode<T>(value: &Value, read: fn(&mut VlqReader) -> Result<T, ReadError>) -> T {
    let bytes = hex::decode(value.as_str().expect("hex string")).expect("hex frame");
    let mut reader = VlqReader::new(&bytes).with_activated_script_version(1);
    let result = read(&mut reader).expect("consensus frame");
    for element in reader.take_group_elements() {
        ergo_sigma::evaluator::validate_group_element(element).expect("valid group element");
    }
    result
}

fn verify_case(req: &Value) -> (&'static str, u64) {
    let inputs: Vec<_> = req["inputs_hex"]
        .as_array()
        .expect("inputs")
        .iter()
        .map(|value| decode(value, ergo_box::read_ergo_box))
        .collect();
    assert_eq!(inputs.len(), 1);
    let outputs = req["outputs_hex"]
        .as_array()
        .expect("outputs")
        .iter()
        .map(|value| decode(value, ergo_box::read_ergo_box_candidate))
        .collect();
    assert!(req["data_inputs_hex"].as_array().unwrap().is_empty());
    assert!(req["headers_hex"].as_array().unwrap().is_empty());
    let extension = decode(&req["ctx_ext_hex"], input::read_context_extension);
    let proof = hex::decode(req["proof_hex"].as_str().unwrap()).unwrap();
    let spending_proof = input::SpendingProof::new(proof, extension).unwrap();
    let tx = transaction::Transaction {
        inputs: inputs
            .iter()
            .map(|b| input::Input {
                box_id: b.box_id().unwrap(),
                spending_proof: spending_proof.clone(),
            })
            .collect(),
        data_inputs: vec![],
        output_candidates: outputs,
    };
    let pre = hex::decode(req["pre_header_hex"].as_str().unwrap()).unwrap();
    assert_eq!(pre.len(), 89);
    let ctx = TransactionContext {
        height: u32::from_be_bytes(pre[49..53].try_into().unwrap()),
        miner_pubkey: pre[53..86].try_into().unwrap(),
        pre_header_timestamp: u64::from_be_bytes(pre[33..41].try_into().unwrap()),
        activated_script_version: req["activated_version"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        pre_header_version: pre[0],
        pre_header_parent_id: pre[1..33].try_into().unwrap(),
        pre_header_n_bits: u64::from_be_bytes(pre[41..49].try_into().unwrap()),
        pre_header_votes: pre[86..89].try_into().unwrap(),
    };
    let params = ProtocolParams {
        storage_fee_factor: req["storage_fee_factor"]
            .as_i64()
            .unwrap_or(1_250_000)
            .try_into()
            .unwrap(),
        ..ProtocolParams::mainnet_default()
    };
    let mut cost = CostAccumulator::new(
        JitCost::from_block_cost(req["cost_limit_block"].as_u64().unwrap()).unwrap(),
    );
    // The verify fixtures supply the caller's init cost in block units.
    if cost
        .add(JitCost::from_block_cost(req["init_cost_block"].as_u64().unwrap()).unwrap())
        .is_err()
    {
        return ("RejectCost", cost.total_block_cost());
    }
    let mut cx = TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
        rules: TxValidationRules::default(),
    };
    let message = hex::decode(req["message_hex"].as_str().unwrap()).unwrap();
    let tree = decode(&req["tree_hex"], ergo_ser::ergo_tree::read_ergo_tree);
    let verdict = match validate_script_input(&tx, &inputs, &[], &message, &mut cx, 0, &tree) {
        Ok(()) => "Accept",
        Err(ValidationError::ProofFailed { .. }) => "RejectScript",
        Err(ValidationError::CostExceeded { .. }) => "RejectCost",
        Err(ValidationError::ScriptError { reason, .. })
            if reason.contains("cost limit exceeded") =>
        {
            "RejectCost"
        }
        Err(error) => panic!("{error}"),
    };
    (verdict, cost.total_block_cost())
}

fn read_json(path: &std::path::Path) -> Value {
    use std::io::Read;
    let file = std::fs::File::open(path).expect("sweep or base fixture");
    let mut bytes = Vec::new();
    if path.extension().is_some_and(|ext| ext == "gz") {
        flate2::read::GzDecoder::new(file)
            .read_to_end(&mut bytes)
            .unwrap();
    } else {
        std::io::BufReader::new(file)
            .read_to_end(&mut bytes)
            .unwrap();
    }
    serde_json::from_slice(&bytes).expect("fixture JSON")
}

// ----- oracle parity -----

// ledger: ROUND-snap-per-input, ORDER-init-token, ORDER-pre-v3-upcast, ORDER-crypto-before-verify, LIMIT-tx-start, LIMIT-per-input, TX-accumulator-shared, INTERP-costlimit-op, TX-storage-rent
#[test]
fn cost_sweeps_all_classes_match_jvm() {
    use super::cost_crypto_truncation::{validate_with_accumulated, Case, Context};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let directory = root.join("test-vectors/ergo-sigma/cost-ledger/sweeps");
    let inventory: toml::Value =
        toml::from_str(&std::fs::read_to_string(directory.join("CLASSES.toml")).unwrap()).unwrap();
    let mut listed = std::collections::BTreeSet::new();
    let mut classes = std::collections::BTreeSet::new();
    for class in inventory["classes"].as_array().unwrap() {
        assert!(classes.insert(class["name"].as_str().unwrap()));
        let files = class["files"].as_array().unwrap();
        assert!(!files.is_empty(), "empty sweep class: {class}");
        for file in files {
            let name = file.as_str().unwrap();
            assert!(directory.join(name).is_file(), "missing sweep {name}");
            listed.insert(name.to_owned());
        }
    }
    for required in [
        "L2-interpreter",
        "L2-op-fixed",
        "L2-op-per-item",
        "L2-eval",
        "L2-method",
        "L2-version",
        "TX-A",
        "TX-B",
        "init-only-exhaustion",
        "token-exhaustion",
        "later-input-exhaustion",
        "failed-proof-at-C",
        "storage-rent-success",
        "storage-rent-fallback",
        "competing-failures",
    ] {
        assert!(classes.contains(required), "missing class {required}");
    }
    let mut executed = 0;
    let mut nonzero = 0;
    let mut files = 0;
    for entry in std::fs::read_dir(&directory).unwrap() {
        let path = entry.unwrap().path();
        if !path.to_string_lossy().ends_with(".json.gz") {
            continue;
        }
        let sweep = read_json(&path);
        files += 1;
        assert!(
            listed.contains(path.file_name().unwrap().to_str().unwrap()),
            "unlisted sweep {}",
            path.display()
        );
        let accumulated = sweep["accumulated_block_cost"].as_u64().unwrap();
        nonzero += usize::from(accumulated > 0);
        assert!(sweep["manifest"].is_object());
        let base = root.join(sweep["base_fixture"].as_str().unwrap());
        assert!(
            base.exists()
                || (base.extension().is_some_and(|ext| ext == "gz")
                    && base.with_extension("").exists()),
            "missing base fixture {}",
            base.display()
        );
        let points = sweep["points"].as_array().unwrap();
        assert!(points.len() >= 3);
        if sweep["base_fixture"] == "test-vectors/scala/multi_input_conjunction_cost.json" {
            let original = read_json(&base);
            assert_eq!(sweep["context"], original["context"]);
            assert_eq!(accumulated, 0);
            let case = original["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == sweep["case"]["name"])
                .expect("imported case");
            assert_eq!(&sweep["case"], case, "preserve imported bytes and verdicts");
            let imported = case["sweep"].as_array().unwrap();
            assert_eq!(points.len(), imported.len());
            for (point, original) in points.iter().zip(imported) {
                assert_eq!(point["limit"], original["limit"]);
                assert_eq!(point["verdict"], original["verdict"]);
            }
            assert!(sweep["manifest"]["evidence"]["per_limit_oracle_sha256"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64));
        }
        for point in points {
            if point["verdict"] == "Accept" {
                assert!(
                    point["total"].as_u64().is_some(),
                    "accepted JVM total required"
                );
            }
        }
        let measured = sweep["measured_total"]
            .as_u64()
            .expect("JVM measured total");
        for boundary in [measured - 1, measured, measured + 1] {
            assert!(
                points.iter().any(|point| point["limit"] == boundary),
                "missing boundary {boundary}"
            );
        }
        if sweep["surface"] == "input" {
            assert!(sweep["request"]["init_cost_block"].as_u64().unwrap() >= accumulated);
        }
        let transaction: Option<(Case, Context)> = (sweep["surface"] == "transaction").then(|| {
            (
                serde_json::from_value(sweep["case"].clone()).unwrap(),
                serde_json::from_value(sweep["context"].clone()).unwrap(),
            )
        });
        for point in points {
            let limit = point["limit"].as_u64().unwrap();
            let (verdict, total) = match sweep["surface"].as_str().unwrap() {
                "input" => {
                    let mut request = sweep["request"].clone();
                    request["cost_limit_block"] = limit.into();
                    let (verdict, total) = verify_case(&request);
                    (verdict.to_owned(), total)
                }
                "transaction" => {
                    let (case, context) = transaction.as_ref().unwrap();
                    let (verdict, total) =
                        validate_with_accumulated(case, context, limit, accumulated);
                    (format!("{verdict:?}"), total)
                }
                other => panic!("unknown surface {other}"),
            };
            assert_eq!(
                verdict,
                point["verdict"].as_str().unwrap(),
                "{} limit {limit}",
                path.display()
            );
            if let Some(expected) = point["total"].as_u64() {
                assert_eq!(total, expected, "{} limit {limit}", path.display());
            } else {
                assert_eq!(point["total"], "unavailable");
            }
            executed += 1;
        }
    }
    assert!(
        nonzero * 2 >= files,
        "at least half the sweeps must precharge"
    );
    assert!(files >= listed.len());
    println!(
        "selected={executed} executed={executed} skipped=0 failed=0 classes={} sweeps={files}",
        classes.len()
    );
}

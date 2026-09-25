//! Oracle: test-vectors/ergo-sigma/verify/cases.json (JVM ErgoInterpreter.verify).
//! Oracle: scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala (`verify_self_test` rent checks).

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_ser::{ergo_box, input, transaction};
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::error::ValidationError;
use ergo_validation::test_helpers::validate_script_input;
use ergo_validation::{TxValidationCtx, TxValidationRules};
use serde_json::{json, Value};

// ----- helpers -----

/// `sigmaProp(true)`, so only the storage-rent branch can reject its box.
const TRUE_TREE: &str = "0008d3";
/// 1 ERG under `TRUE_TREE`, created at height 0. Its 44 serialized bytes
/// owe 55_000_000 at factor 1_250_000, so `checkExpiredBox` requires a
/// recreated output worth at least 945_000_000.
const TRUE_BOX: &str =
    "8094ebdc030008d3000000000000000000000000000000000000000000000000000000000000000000000000";
/// `TRUE_TREE` recreated at height 1_051_200 with exactly 945_000_000.
const RECREATED_AT_FLOOR: &str = "c09ccec2030008d3c094400000";
/// As `RECREATED_AT_FLOOR`, one nanoErg short.
const RECREATED_BELOW_FLOOR: &str = "bf9ccec2030008d3c094400000";
/// Context extensions holding only variable 127.
const VAR_127_SHORT_0: &str = "017f0300";
const VAR_127_SHORT_1: &str = "017f0302";
const VAR_127_SHORT_MINUS_1: &str = "017f0301";
const VAR_127_INT_0: &str = "017f0400";

fn fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/verify/cases.json"
    ))
    .expect("JVM verify fixtures")
}

/// The JVM `rent_expired` request (P2PK box, one output at index 0) with
/// `fields` replaced, as `verify_self_test` in EvaluatedValueOracle.scala
/// patches its `rent` request.
fn rent_case(name: &str, fields: &[(&str, &str)]) -> Value {
    let mut case = fixtures()
        .into_iter()
        .find(|case| case["name"] == "rent_expired")
        .unwrap();
    case["name"] = json!(name);
    for (key, value) in fields {
        case["request"][*key] = json!(value);
    }
    case
}

/// `rent_case` for `TRUE_BOX` spent with `extension`, creating `output`.
fn true_box_case(name: &str, extension: &str, output: &str) -> Value {
    let mut case = rent_case(
        name,
        &[
            ("tree_hex", TRUE_TREE),
            ("self_box_hex", TRUE_BOX),
            ("ctx_ext_hex", extension),
        ],
    );
    case["request"]["inputs_hex"] = json!([TRUE_BOX]);
    case["request"]["outputs_hex"] = json!([output]);
    case
}

fn decode<T>(value: &Value, read: fn(&mut VlqReader) -> Result<T, ReadError>) -> T {
    let bytes = hex::decode(value.as_str().expect("hex string")).expect("hex frame");
    let mut reader = VlqReader::new(&bytes).with_activated_script_version(1);
    let result = read(&mut reader).expect("consensus frame");
    for element in reader.take_group_elements() {
        ergo_sigma::evaluator::validate_group_element(element).expect("valid group element");
    }
    result
}

fn verify_case(case: &Value) -> (&'static str, u64) {
    let req = &case["request"];
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
            .unwrap()
            .try_into()
            .unwrap(),
        ..ProtocolParams::mainnet_default()
    };
    let mut cost = CostAccumulator::new(
        JitCost::from_block_cost(req["cost_limit_block"].as_u64().unwrap()).unwrap(),
    );
    // The verify fixtures supply the caller's init cost in block units.
    cost.add(JitCost::from_block_cost(req["init_cost_block"].as_u64().unwrap()).unwrap())
        .unwrap();
    let mut cx = TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
        rules: TxValidationRules::default(),
    };
    let message = hex::decode(req["message_hex"].as_str().unwrap()).unwrap();
    let verdict = match validate_script_input(
        &tx,
        &inputs,
        &[],
        &message,
        &mut cx,
        0,
        inputs[0].candidate.ergo_tree(),
    ) {
        Ok(()) => "Accept",
        Err(ValidationError::ProofFailed { .. }) => "RejectScript",
        Err(ValidationError::CostExceeded { .. }) => "RejectCost",
        Err(error) => panic!("{}: {error}", case["name"]),
    };
    (verdict, cost.total_block_cost())
}

// ----- oracle parity -----

// ledger: TX-storage-rent
#[test]
fn storage_rent_shortcut_block_totals_match_jvm() {
    let cases = fixtures();
    for name in ["rent_init", "rent_expired"] {
        let case = cases.iter().find(|case| case["name"] == name).unwrap();
        let (verdict, total) = verify_case(case);
        assert_eq!(verdict, case["expected"]["verdict"], "{name}");
        assert_eq!(
            total,
            case["expected"]["total_block_cost"].as_u64().unwrap(),
            "{name}"
        );
    }
}

// ledger: TX-storage-rent
#[test]
fn storage_rent_fallback_block_total_matches_jvm() {
    let cases = fixtures();
    let case = cases
        .iter()
        .find(|case| case["name"] == "rent_fallback")
        .unwrap();
    let (verdict, total) = verify_case(case);
    assert_eq!(verdict, case["expected"]["verdict"]);
    assert_eq!(
        total,
        case["expected"]["total_block_cost"].as_u64().unwrap()
    );
}

// ledger: TX-storage-rent
#[test]
fn storage_rent_int_index_verifies_script_like_jvm() {
    // Scala reads var 127 with `asInstanceOf[Short]`, which throws on an
    // Int, so `recoverWith` verifies the box script. The P2PK case is the
    // JVM oracle's `rent_bad_type_fallback_reject_script` (403 BC).
    let p2pk = rent_case("rent_int_index_p2pk", &[("ctx_ext_hex", VAR_127_INT_0)]);
    assert_eq!(verify_case(&p2pk), ("RejectScript", 403));
    // A Short index would accept this output at 50 BC; the Int index
    // evaluates `sigmaProp(true)` instead (JVM: `Success((true,5))`).
    let truth = true_box_case("rent_int_index_true", VAR_127_INT_0, RECREATED_AT_FLOOR);
    assert_eq!(verify_case(&truth), ("Accept", 5));
}

// ledger: TX-storage-rent
#[test]
fn storage_rent_failed_expired_box_check_rejects_without_script() {
    // A false `checkExpiredBox` returns `Success((false,50))` from the JVM
    // `verify`; `recoverWith` never runs, so `sigmaProp(true)` cannot
    // rescue the input.
    let below = true_box_case(
        "rent_true_box_below_floor",
        VAR_127_SHORT_0,
        RECREATED_BELOW_FLOOR,
    );
    assert_eq!(verify_case(&below).0, "RejectScript");
    // Positive control: the same box recreated at the fee floor.
    let at_floor = true_box_case(
        "rent_true_box_at_floor",
        VAR_127_SHORT_0,
        RECREATED_AT_FLOOR,
    );
    assert_eq!(verify_case(&at_floor), ("Accept", 50));
    // The JVM oracle's `rent_uncovered_fee_bad_output_reject_script`:
    // factor 0 covers the fee and the `true` output changes the script.
    let mut factor_zero = rent_case("rent_factor_zero_bad_output", &[]);
    factor_zero["request"]["storage_fee_factor"] = json!(0);
    assert_eq!(verify_case(&factor_zero).0, "RejectScript");
}

// ledger: TX-storage-rent
#[test]
fn storage_rent_failed_check_at_low_cost_limit_rejects_script() {
    // Scala `verifyInput` fails `txScriptValidation` before its
    // `bsBlockTransactionsCost` check and validation is fail-fast, so a
    // limit below init + 50 BC must not turn the rejection into a cost
    // one. The JVM `verify` returns `Success((false,50))` at 17 / 49.
    let mut case = true_box_case(
        "rent_true_box_below_floor_low_limit",
        VAR_127_SHORT_0,
        RECREATED_BELOW_FLOOR,
    );
    case["request"]["init_cost_block"] = json!(17);
    case["request"]["cost_limit_block"] = json!(49);
    assert_eq!(verify_case(&case).0, "RejectScript");
}

// ledger: TX-storage-rent
#[test]
fn storage_rent_unreadable_short_index_verifies_script_like_jvm() {
    // `outputCandidates(idx)` throws for index 1 of one output and for -1,
    // so `recoverWith` verifies the box script. Index 1 on the P2PK box is
    // the JVM oracle's `rent_bad_index_fallback_reject_script` (403 BC).
    for extension in [VAR_127_SHORT_1, VAR_127_SHORT_MINUS_1] {
        let p2pk = rent_case("rent_unreadable_index_p2pk", &[("ctx_ext_hex", extension)]);
        assert_eq!(verify_case(&p2pk), ("RejectScript", 403), "{extension}");
        let truth = true_box_case("rent_unreadable_index_true", extension, RECREATED_AT_FLOOR);
        assert_eq!(verify_case(&truth), ("Accept", 5), "{extension}");
    }
}

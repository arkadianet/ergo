//! Oracle: test-vectors/ergo-sigma/verify/cases.json (JVM ErgoInterpreter.verify).
//! Oracle: test-vectors/ergo-sigma/verify/rent-cases.json (JVM ErgoInterpreter.verify, storage-rent branch).

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_ser::{ergo_box, input, transaction};
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::error::ValidationError;
use ergo_validation::test_helpers::validate_script_input;
use ergo_validation::{TxValidationCtx, TxValidationRules};
use serde_json::Value;

// ----- helpers -----

fn fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/verify/cases.json"
    ))
    .expect("JVM verify fixtures")
}

/// Runs the named `rent-cases.json` case and compares it with the JVM.
/// A failed `checkExpiredBox` makes the JVM `verify` return
/// `Success((false,50))`, but `verifyInput` rejects the input before it
/// adds the 50, so only the verdict is compared for those cases.
fn assert_rent_case_matches_jvm(name: &str) {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/verify/rent-cases.json"
    ))
    .expect("JVM rent fixtures");
    let case = cases
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("missing rent case {name}"));
    let expected = &case["expected"];
    let (verdict, total) = verify_case(case);
    assert_eq!(verdict, expected["verdict"], "{name}");
    if !(verdict == "RejectScript" && expected["rent_block_cost"] == 50) {
        assert_eq!(
            total,
            expected["total_block_cost"].as_u64().unwrap(),
            "{name}"
        );
    }
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
    // Int, so `recoverWith` verifies the box script: P2PK rejects (403 BC)
    // and `sigmaProp(true)` accepts (5 BC) where a Short index would take
    // the 50 BC rent path.
    assert_rent_case_matches_jvm("rent-int-index-p2pk");
    assert_rent_case_matches_jvm("rent-int-index-true-box");
}

// ledger: TX-storage-rent
#[test]
fn storage_rent_failed_expired_box_check_rejects_without_script() {
    // A false `checkExpiredBox` is final: `recoverWith` never runs, so
    // `sigmaProp(true)` cannot rescue an output one nanoErg below the fee
    // floor. The at-floor recreate is the positive control; factor 0 with
    // a script-changing output is the oracle's
    // `rent_uncovered_fee_bad_output_reject_script`.
    assert_rent_case_matches_jvm("rent-true-box-below-floor");
    assert_rent_case_matches_jvm("rent-true-box-at-floor");
    assert_rent_case_matches_jvm("rent-factor-zero-bad-output");
}

// ledger: TX-storage-rent
#[test]
fn storage_rent_failed_check_at_low_cost_limit_rejects_script() {
    // Scala `verifyInput` fails `txScriptValidation` before its
    // `bsBlockTransactionsCost` check and validation is fail-fast, so a
    // limit below init + 50 BC (17 / 49) must not turn the rejection into
    // a cost one.
    assert_rent_case_matches_jvm("rent-true-box-below-floor-low-limit");
}

// ledger: TX-storage-rent
#[test]
fn storage_rent_unreadable_short_index_verifies_script_like_jvm() {
    // `outputCandidates(idx)` throws for index 1 of one output and for -1,
    // so `recoverWith` verifies the box script.
    for name in [
        "rent-short-index-1-p2pk",
        "rent-short-index-1-true-box",
        "rent-short-index-minus-1-p2pk",
        "rent-short-index-minus-1-true-box",
    ] {
        assert_rent_case_matches_jvm(name);
    }
}

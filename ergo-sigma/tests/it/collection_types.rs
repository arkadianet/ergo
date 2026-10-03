//! Independently compiled sigma-state 6.0.6 collection contracts.

use ergo_primitives::{cost::CostAccumulator, reader::VlqReader};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::evaluator::{
    reduce_expr_with_cost, EvalBox, ReductionContext, SECP256K1_GENERATOR,
};

#[derive(serde::Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    tree_hex: String,
    tree_version: u8,
    activated_version: u8,
    expected_proposition: bool,
    expected_jit_cost: u64,
    expected_verified: bool,
}

// ----- oracle parity -----

#[test]
fn collection_types_scala_contracts_preserve_propositions_and_costs() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/collection-types/cases.json"
    ))
    .unwrap();
    assert_eq!(
        fixture.cases.len(),
        7,
        "complete independent oracle denominator"
    );
    let mut failures = Vec::new();
    for case in fixture.cases {
        let bytes = hex::decode(&case.tree_hex).unwrap();
        let mut reader = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut reader).unwrap();
        assert_eq!(reader.position(), bytes.len(), "{} EOF", case.id);
        assert_eq!(tree.version, case.tree_version, "{} version", case.id);
        let mut self_box = EvalBox::simple(0, bytes.clone());
        self_box.value = 1_000_000;
        let inputs = [self_box.clone()];
        let mut context = ReductionContext::minimal(0, 0);
        context.self_box = Some(&self_box);
        context.inputs = &inputs;
        context.miner_pubkey = SECP256K1_GENERATOR;
        context.pre_header_version = 4;
        context.pre_header_timestamp = 3;
        context.activated_script_version = case.activated_version;
        context.ergo_tree_version = tree.version;
        let mut cost = CostAccumulator::recording_only();
        let reduced = reduce_expr_with_cost(&tree.body, &context, &tree.constants, &mut cost);
        let expected = SigmaBoolean::TrivialProp(case.expected_proposition);
        if reduced.as_ref().ok() != Some(&expected)
            || cost.total().value() != case.expected_jit_cost
        {
            failures.push(format!(
                "{}: {reduced:?} at {} JIT, expected {expected:?} at {}",
                case.id,
                cost.total().value(),
                case.expected_jit_cost
            ));
        }
        // Independently captured trivial propositions verify with an empty
        // proof/message. This exercises the public spending entry point;
        // it is not a full transaction or block-validation assertion.
        let verified =
            ergo_sigma::reduce::verify_spending_proof_with_context(&tree, &[], &[], &context);
        if verified.as_ref().ok() != Some(&case.expected_verified) {
            failures.push(format!("{} spending verification: {verified:?}", case.id));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

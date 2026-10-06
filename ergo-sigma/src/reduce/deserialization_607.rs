//! Actual node settings omit rule 1020; core settings alone would allow replacement.
use super::{verify_spending_proof_with_context_and_cost, VerifySpendingError};
use crate::evaluator::{EvalBox, EvalError, ReductionContext, RuleStatus};
use ergo_primitives::cost::CostAccumulator;
use ergo_primitives::reader::VlqReader;
use ergo_ser::{
    ergo_tree,
    register::RegisterValue,
    sigma_type::SigmaType,
    sigma_value::{CollValue, SigmaValue},
};

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    tree_hex: String,
    payload_hex: String,
    carrier: String,
    activated: u8,
    status: String,
    result: String,
    cost: Option<u64>,
    core_soft_fork: bool,
    node_soft_fork: bool,
}

#[test]
fn node_rule_1020_spends_and_controls_match_jvm_607() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        entries: Vec<Vector>,
    }
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/scala/softfork_607.json"
    ))
    .unwrap();
    for v in fixture.entries {
        let bytes = hex::decode(&v.tree_hex).unwrap();
        let tree = ergo_tree::read_ergo_tree(
            &mut VlqReader::new(&bytes).with_activated_script_version(v.activated),
        )
        .unwrap();
        let payload = SigmaValue::Coll(CollValue::Bytes(hex::decode(&v.payload_hex).unwrap()));
        let payload_type = SigmaType::SColl(Box::new(SigmaType::SByte));
        let mut b = EvalBox::simple(1_000_000, bytes);
        if v.carrier == "register" {
            b.registers[0] = Some(RegisterValue {
                tpe: payload_type.clone(),
                value: payload.clone(),
            });
        }
        let mut ctx = ReductionContext {
            self_box: Some(&b),
            ergo_tree_version: tree.version,
            activated_script_version: v.activated,
            ..ReductionContext::minimal_v6(0, 0)
        };
        if v.carrier == "extension" {
            ctx.extension.insert(0, (payload_type, payload));
        }
        let status = match v.status.as_str() {
            "enabled" => RuleStatus::Enabled,
            "disabled" => RuleStatus::Disabled,
            "changed" => RuleStatus::Changed(vec![0]),
            "replaced" => RuleStatus::Replaced(1021),
            _ => unreachable!(),
        };
        ctx.validation_settings.0.insert(1020, status);
        assert_eq!(v.core_soft_fork, v.status == "replaced", "{}", v.name);
        assert!(!v.node_soft_fork, "{}", v.name);
        assert!(
            !ctx.validation_settings.is_soft_fork(1020, &[], v.activated),
            "{}",
            v.name
        );
        let mut cost = CostAccumulator::recording_only();
        let result = verify_spending_proof_with_context_and_cost(&tree, &[], &[], &ctx, &mut cost);
        match v.result.as_str() {
            "true" => {
                assert!(result.unwrap(), "{}", v.name);
                assert_eq!(Some(cost.total().to_block_cost()), v.cost, "{}", v.name);
            }
            "InterpreterException" => assert!(
                matches!(
                    result,
                    Err(VerifySpendingError::Eval(EvalError::UnparsedErgoTree))
                ),
                "{}: {result:?}",
                v.name
            ),
            "ValidationException" => assert!(
                matches!(
                    result,
                    Err(VerifySpendingError::Eval(EvalError::SigmaValidation {
                        rule_id: 1020,
                        ..
                    }))
                ),
                "{}: {result:?}",
                v.name
            ),
            "InvocationTargetException" => assert!(
                matches!(
                    result,
                    Err(VerifySpendingError::Eval(EvalError::EvaluationValidation {
                        rule_id: 1020,
                        ..
                    }))
                ),
                "{}: {result:?}",
                v.name
            ),
            "DeserializeCallDepthExceeded" => assert!(
                matches!(
                    result,
                    Err(VerifySpendingError::Eval(EvalError::TypeError { .. }))
                ),
                "{}: {result:?}",
                v.name
            ),
            other => panic!("{}: unexpected JVM result {other}", v.name),
        }
    }
}

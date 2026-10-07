//! Oracle: scripts/reference_evaluator_oracle/EvaluationOrderOracle.scala.
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::reader::VlqReader;
use ergo_ser::opcode::parse_expr;
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::evaluator::{reduce_expr_with_cost, ReductionContext};

#[test]
fn evaluation_order_matches_recorded_jvm_costs() {
    let inputs =
        include_str!("../../../test-vectors/reference-6.0.7/evaluator/evaluation-order.tsv");
    let oracle =
        include_str!("../../../test-vectors/reference-6.0.7/evaluator/evaluation-order.jvm.tsv");
    let inputs: Vec<_> = inputs.lines().filter(|l| !l.starts_with('#')).collect();
    let oracle: Vec<_> = oracle.lines().collect();
    assert_eq!(inputs.len(), oracle.len());
    let mut differences = Vec::new();
    for (input, expected) in inputs.iter().zip(oracle) {
        let p: Vec<_> = input.split('\t').collect();
        let o: Vec<_> = expected.split('\t').collect();
        assert_eq!(p[0], o[0]);
        let version = p[1].parse().unwrap();
        let bytes = hex::decode(p[2]).unwrap();
        let expr = parse_expr(&mut VlqReader::new(&bytes), 0, version).unwrap();
        let mut ctx = ReductionContext::minimal(1_000_000, 0);
        ctx.ergo_tree_version = version;
        let mut cost = CostAccumulator::new(JitCost::from_jit(p[3].parse().unwrap()));
        let outcome = match reduce_expr_with_cost(&expr, &ctx, &[], &mut cost) {
            Ok(SigmaBoolean::TrivialProp(true)) => "true",
            Ok(SigmaBoolean::TrivialProp(false)) => "false",
            Ok(_) => "value",
            Err(_) => "error",
        };
        if outcome != o[1] || cost.total().value() != o[2].parse::<u64>().unwrap() {
            differences.push(format!(
                "{}: {} {} => {} {}",
                p[0],
                outcome,
                cost.total().value(),
                o[1],
                o[2]
            ));
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

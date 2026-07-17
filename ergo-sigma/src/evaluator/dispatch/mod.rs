//! Evaluation entry points and the reduction pipeline, split by concern.
//! `mod.rs` holds the crate-facing reduce/trace API; the exhaustive tree
//! walks, consensus pre-checks, and opcode dispatch live in the submodules
//! and are re-exported here so `crate::evaluator::dispatch::*` (and the
//! `pub use dispatch::*` at `evaluator/mod.rs`) surface the same items.

use ergo_primitives::cost::CostAccumulator;
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

use crate::evaluator::types::*;

mod ast_walk;
mod eval;
mod pre_checks;

// Re-exports preserving the pre-split `dispatch::*` surface (and, transitively,
// `evaluator::*` via `pub use dispatch::*`). `eval_expr` is the depth-aware
// router the opcode handlers recurse through; `expr_has_deserialize` and
// `pre_reduction_checks` are consumed by `crate::reduce`.
pub(crate) use ast_walk::expr_has_deserialize;
pub(in crate::evaluator) use eval::eval_expr;
pub(crate) use pre_checks::pre_reduction_checks;
pub use pre_checks::validate_group_element;

pub fn reduce_expr(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
) -> Result<SigmaBoolean, EvalError> {
    let mut cost = CostAccumulator::recording_only();
    reduce_expr_with_cost(expr, ctx, constants, &mut cost)
}

/// Evaluate an ErgoTree expression to a SigmaBoolean, accumulating cost.
pub fn reduce_expr_with_cost(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
    cost: &mut CostAccumulator,
) -> Result<SigmaBoolean, EvalError> {
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = None;
    let val = eval_expr(expr, ctx, constants, &mut env, &mut depth, cost, &mut trace)?;
    match val {
        Value::SigmaProp(sb) => Ok(sb),
        Value::Bool(true) => Ok(SigmaBoolean::TrivialProp(true)),
        Value::Bool(false) => Ok(SigmaBoolean::TrivialProp(false)),
        other => Err(EvalError::TypeError {
            expected: "SigmaProp or Bool",
            got: format!("{other:?}"),
        }),
    }
}

/// Trace entry recording an intermediate evaluation result.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub label: String,
    pub value: String,
}

/// Evaluate an expression to a raw Value (test-only).
#[cfg(test)]
pub(crate) fn eval_to_value(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
) -> Result<Value, EvalError> {
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut cost = CostAccumulator::recording_only();
    let mut trace = None;
    eval_expr(
        expr, ctx, constants, &mut env, &mut depth, &mut cost, &mut trace,
    )
}

/// Evaluate with tracing — records each ValDef binding, If condition,
/// and SigmaOr/SigmaAnd child result. For debugging wrong-branch reductions.
pub fn reduce_expr_traced(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
) -> (Result<SigmaBoolean, EvalError>, Vec<TraceEntry>) {
    let mut cost = CostAccumulator::recording_only();
    reduce_expr_traced_with_cost(expr, ctx, constants, &mut cost)
}

/// Evaluate with tracing, accumulating cost.
pub fn reduce_expr_traced_with_cost(
    expr: &Expr,
    ctx: &ReductionContext<'_>,
    constants: &[(SigmaType, SigmaValue)],
    cost: &mut CostAccumulator,
) -> (Result<SigmaBoolean, EvalError>, Vec<TraceEntry>) {
    let mut env = Env::new();
    let mut depth = 0usize;
    let mut trace = Some(Vec::new());
    let result = eval_expr(expr, ctx, constants, &mut env, &mut depth, cost, &mut trace);
    let entries = trace.unwrap_or_default();
    let sb_result = result.and_then(|val| match val {
        Value::SigmaProp(sb) => Ok(sb),
        Value::Bool(true) => Ok(SigmaBoolean::TrivialProp(true)),
        Value::Bool(false) => Ok(SigmaBoolean::TrivialProp(false)),
        other => Err(EvalError::TypeError {
            expected: "SigmaProp or Bool",
            got: format!("{other:?}"),
        }),
    });
    (sb_result, entries)
}

//! Binding and control-flow opcodes:
//!
//! - 0x73 ConstPlaceholder — index into the segregated constant pool
//! - 0x72 ValUse           — reference a bound variable
//! - 0xD8 BlockValue       — sequence of ValDefs then a result expression
//! - 0xD6 ValDef           — bind a value to an id in the environment
//! - 0x95 If               — three-arm conditional with trace push for the condition
//! - 0x86 Tuple            — eager n-ary tuple construction
//! - 0x8C SelectField      — 1-indexed tuple field access
//! - 0xD9 FuncValue        — closure capturing the current environment
//! - 0xDA FuncApply        — closure invocation (charges AddToEnv per call)
//!
//! These arms drive the recursion contract: every arm calls back into
//! `eval_expr` (the same depth-aware router from `dispatch::eval_expr`)
//! so depth accounting stays in one place.

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use super::super::cost::{add_cost, add_cost_per_item};
use super::super::dispatch::{eval_expr, TraceEntry};
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::{sigma_to_value, trace_val};
use super::super::types::{Env, EvalError, Value};

// 0x73 ConstPlaceholder(index)
pub(in crate::evaluator) fn eval_const_placeholder(
    index: u32,
    constants: &[(SigmaType, SigmaValue)],
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0x73)?;
    let idx = index as usize;
    if idx >= constants.len() {
        return Err(EvalError::ConstantOutOfBounds(index));
    }
    sigma_to_value(&constants[idx].0, &constants[idx].1)
}

// 0x72 ValUse — reference a bound variable
pub(in crate::evaluator) fn eval_val_use(
    id: u32,
    env: &Env,
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0x72)?;
    env.get(&id).cloned().ok_or(EvalError::TypeError {
        expected: "bound variable",
        got: format!("unbound ValUse(id={id})"),
    })
}

// 0xD8 BlockValue — evaluate ValDefs then return result
pub(in crate::evaluator) fn eval_block_value(
    items: &[Expr],
    result: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost_per_item(cx.cost, 0xD8, items.len() as u32)?;
    for item in items {
        cx.eval_expr(item)?;
    }
    let result_val = cx.eval_expr(result)?;
    if let Some(t) = cx.trace.as_mut() {
        t.push(TraceEntry {
            label: "BlockValue result".into(),
            value: trace_val(&result_val),
        });
    }
    Ok(result_val)
}

// 0xD6 ValDef — bind a value to an id in the environment
pub(in crate::evaluator) fn eval_val_def(
    id: u32,
    rhs: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xD6)?;
    let val = cx.eval_expr(rhs)?;
    if let Some(t) = cx.trace.as_mut() {
        t.push(TraceEntry {
            label: format!("ValDef({id})"),
            value: trace_val(&val),
        });
    }
    cx.env.insert(id, val.clone());
    Ok(val)
}

// 0x95 If(condition, then_branch, else_branch)
pub(in crate::evaluator) fn eval_if(
    cond: &Expr,
    then_br: &Expr,
    else_br: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0x95)?;
    let c = cx.eval_expr(cond)?;
    if let Some(t) = cx.trace.as_mut() {
        t.push(TraceEntry {
            label: "If condition".into(),
            value: trace_val(&c),
        });
    }
    match c {
        Value::Bool(true) => cx.eval_expr(then_br),
        Value::Bool(false) => cx.eval_expr(else_br),
        _ => Err(EvalError::TypeError {
            expected: "Bool for If condition",
            got: format!("{c:?}"),
        }),
    }
}

// 0x86 Tuple — eager construction. Scala `Tuple.eval` (values.scala) rejects
// any arity other than 2 (`if (items.length != 2) syntax.error("Invalid
// tuple ...")`) — only pairs are valid in v4/v5/v6. (ExtractCreationInfo is a
// separate node producing an arity-2 result and is unaffected.)
//
// The arity check is intentionally BEFORE `add_cost`, mirroring Scala
// exactly: Tuple.eval runs the `items.length != 2` check first and calls
// `addCost(Tuple.costKind)` only at the very end (after evaluating the two
// items). So a non-pair tuple errors with the arity error WITHOUT charging
// the Tuple cost — even under a cost budget below 0x86's fixed cost, the
// arity error must win over a cost-limit error (matching Scala's
// `syntax.error` firing before `addCost`). Do NOT move `add_cost` above this
// guard: that would surface CostExceeded where Scala surfaces "Invalid
// tuple" — a consensus divergence on the error class.
pub(in crate::evaluator) fn eval_tuple(
    items: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if items.len() != 2 {
        return Err(EvalError::ArityMismatch {
            expected: 2,
            got: items.len(),
        });
    }
    add_cost(cx.cost, 0x86)?;
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        values.push(cx.eval_expr(item)?);
    }
    Ok(Value::Tuple(values))
}

// 0x8C SelectField(input, field_idx) — 1-indexed tuple field access
pub(in crate::evaluator) fn eval_select_field(
    input: &Expr,
    field_idx: u8,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0x8C)?;
    let tuple = cx.eval_expr(input)?;
    match tuple {
        Value::Tuple(items) => {
            let idx = (field_idx as usize).saturating_sub(1);
            items.get(idx).cloned().ok_or(EvalError::TypeError {
                expected: "valid tuple index",
                got: format!("index {field_idx} in tuple of len {}", items.len()),
            })
        }
        _ => Err(EvalError::TypeError {
            expected: "Tuple",
            got: format!("{tuple:?}"),
        }),
    }
}

// 0xD9 FuncValue — closure capturing the current environment
pub(in crate::evaluator) fn eval_func_value(
    args: &[(u32, Option<SigmaType>)],
    body: &Expr,
    env: &Env,
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0xD9)?;
    let params: Vec<u32> = args.iter().map(|(id, _)| *id).collect();
    Ok(Value::Func {
        captured_env: std::rc::Rc::new(env.clone()),
        params,
        param_types: args.to_vec(),
        body: Box::new(body.clone()),
    })
}

// 0xDA FuncApply — closure invocation. Charges AddToEnv (5 jit) per call.
pub(in crate::evaluator) fn eval_func_apply(
    func: &Expr,
    arg_exprs: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xDA)?;
    let func_val = cx.eval_expr(func)?;
    match func_val {
        Value::Func {
            captured_env,
            params,
            param_types: _,
            body,
        } => {
            if params.len() != arg_exprs.len() {
                return Err(EvalError::ArityMismatch {
                    expected: params.len(),
                    got: arg_exprs.len(),
                });
            }
            // AddToEnvironment — charged per closure invocation
            cx.cost.add(JitCost::from_jit(5))?;
            #[cfg(feature = "cost-trace")]
            crate::cost_trace::record("AddToEnv", 5, cx.cost.total().value());
            let mut call_env = (*captured_env).clone();
            for (param_id, arg_expr) in params.iter().zip(arg_exprs.iter()) {
                let arg_val = cx.eval_expr(arg_expr)?;
                call_env.insert(*param_id, arg_val);
            }
            // Body evaluates with a fresh `call_env`, not the caller's env.
            // Direct call to the free function so we can swap envs without
            // disturbing `cx.env`.
            eval_expr(
                &body,
                cx.ctx,
                cx.constants,
                &mut call_env,
                cx.depth,
                cx.cost,
                cx.trace,
            )
        }
        _ => Err(EvalError::TypeError {
            expected: "Func for FuncApply",
            got: format!("{func_val:?}"),
        }),
    }
}

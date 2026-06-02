//! Boolean opcodes: BoolToSigmaProp (0xD1), BinOr (0xEC), BinAnd (0xED),
//! LogicalNot (0xEF), AND-collection (0x96).
//!
//! BinOr/BinAnd are short-circuit (`||`/`&&`) — right side evaluates
//! conditionally. Trace push order, labels, and the `trace_val`
//! truncation behavior are byte-preserved against the Scala interpreter.

use ergo_ser::opcode::Expr;
use ergo_ser::sigma_value::SigmaBoolean;

use super::super::cost::{add_cost, add_cost_per_item, collection_len};
use super::super::dispatch::TraceEntry;
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::trace_val;
use super::super::types::{EvalError, Value};

// 0xD1 BoolToSigmaProp — Scala is lenient: if the input is already a
// SigmaProp it passes through (handles double-wrapped
// BoolToSigmaProp(BoolToSigmaProp(x)) seen on mainnet). Reject anything
// else.
pub(in crate::evaluator) fn eval_bool_to_sigma_prop(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xD1)?;
    let val = cx.eval_expr(inner)?;
    if let Some(t) = cx.trace.as_mut() {
        t.push(TraceEntry {
            label: "BoolToSigmaProp".into(),
            value: trace_val(&val),
        });
    }
    match val {
        Value::Bool(b) => Ok(Value::SigmaProp(if b {
            SigmaBoolean::TrivialProp(true)
        } else {
            SigmaBoolean::TrivialProp(false)
        })),
        // Scala is lenient: if input is already a SigmaProp, pass through.
        Value::SigmaProp(_) => Ok(val),
        _ => Err(EvalError::TypeError {
            expected: "Bool",
            got: format!("{val:?}"),
        }),
    }
}

// 0xEC BinOr (lazy ||) — short-circuit
pub(in crate::evaluator) fn eval_bin_or(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xEC)?;
    let l = cx.eval_expr(left)?;
    match l {
        Value::Bool(true) => {
            if let Some(t) = cx.trace.as_mut() {
                t.push(TraceEntry {
                    label: "BinOr short-circuit".into(),
                    value: "left=true → true".into(),
                });
            }
            Ok(Value::Bool(true))
        }
        Value::Bool(false) => {
            let r = cx.eval_expr(right)?;
            if let Some(t) = cx.trace.as_mut() {
                t.push(TraceEntry {
                    label: "BinOr".into(),
                    value: format!("left=false, right={}", trace_val(&r)),
                });
            }
            Ok(r)
        }
        _ => Err(EvalError::TypeError {
            expected: "Bool for BinOr",
            got: format!("{l:?}"),
        }),
    }
}

// 0xED BinAnd (lazy &&) — short-circuit
pub(in crate::evaluator) fn eval_bin_and(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xED)?;
    let l = cx.eval_expr(left)?;
    match l {
        Value::Bool(false) => {
            if let Some(t) = cx.trace.as_mut() {
                t.push(TraceEntry {
                    label: "BinAnd short-circuit".into(),
                    value: "left=false → false".into(),
                });
            }
            Ok(Value::Bool(false))
        }
        Value::Bool(true) => {
            let r = cx.eval_expr(right)?;
            if let Some(t) = cx.trace.as_mut() {
                t.push(TraceEntry {
                    label: "BinAnd".into(),
                    value: format!("left=true, right={}", trace_val(&r)),
                });
            }
            Ok(r)
        }
        _ => Err(EvalError::TypeError {
            expected: "Bool for BinAnd",
            got: format!("{l:?}"),
        }),
    }
}

// 0xEF LogicalNot
pub(in crate::evaluator) fn eval_logical_not(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xEF)?;
    match cx.eval_expr(inner)? {
        Value::Bool(b) => Ok(Value::Bool(!b)),
        other => Err(EvalError::TypeError {
            expected: "Bool for LogicalNot",
            got: format!("{other:?}"),
        }),
    }
}

// 0x96 AND on Coll[Boolean] (NOT sigma — boolean reducer over a collection)
pub(in crate::evaluator) fn eval_and_collection(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let val = cx.eval_expr(inner)?;
    add_cost_per_item(cx.cost, 0x96, collection_len(&val, cx.ctx) as u32)?;
    match val {
        Value::CollBool(items) => Ok(Value::Bool(items.iter().all(|b| *b))),
        _ => Err(EvalError::TypeError {
            expected: "Coll[Boolean]",
            got: format!("{val:?}"),
        }),
    }
}

// 0x97 OR on Coll[Boolean] (NOT sigma — boolean reducer over a collection)
pub(in crate::evaluator) fn eval_or_collection(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let val = cx.eval_expr(inner)?;
    add_cost_per_item(cx.cost, 0x97, collection_len(&val, cx.ctx) as u32)?;
    match val {
        Value::CollBool(items) => Ok(Value::Bool(items.iter().any(|b| *b))),
        _ => Err(EvalError::TypeError {
            expected: "Coll[Boolean] for OR",
            got: format!("{val:?}"),
        }),
    }
}

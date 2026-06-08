//! Numeric comparison and equality opcodes: LT (0x8F), LE (0x90),
//! GT (0x91), GE (0x92), EQ (0x93), NEQ (0x94).
//!
//! LT/LE/GT/GE charge cost AFTER both operand evaluations; EQ/NEQ use
//! `add_eq_neq_cost` because Scala charges a value-dependent cost on
//! the equality path. The cost-charge order vs recursion is preserved
//! exactly against the Scala interpreter.

use ergo_ser::opcode::Expr;

use super::super::cost::{add_cost, eq_with_cost};
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::require_comparable;
use super::super::types::{EvalError, Value};

// 0x8F LT (<)
pub(in crate::evaluator) fn eval_lt(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_cost(cx.cost, 0x8F)?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Bool(a < b)),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Bool(a < b)),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a < b)),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Bool(a < b)),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::Bool(a < b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Lt",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0x90 LE (<=)
pub(in crate::evaluator) fn eval_le(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_cost(cx.cost, 0x90)?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Bool(a <= b)),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Bool(a <= b)),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a <= b)),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Bool(a <= b)),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::Bool(a <= b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Le",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0x91 GT (>)
pub(in crate::evaluator) fn eval_gt(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_cost(cx.cost, 0x91)?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Bool(a > b)),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Bool(a > b)),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a > b)),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Bool(a > b)),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::Bool(a > b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Gt",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0x92 GE (>=)
pub(in crate::evaluator) fn eval_ge(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_cost(cx.cost, 0x92)?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Bool(a >= b)),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Bool(a >= b)),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a >= b)),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Bool(a >= b)),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::Bool(a >= b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for GE",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0x93 EQ (==)
pub(in crate::evaluator) fn eval_eq(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    require_comparable(&l, &r)?;
    Ok(Value::Bool(eq_with_cost(&l, &r, cx.ctx, cx.cost)?))
}

// 0x94 NEQ (!=)
pub(in crate::evaluator) fn eval_neq(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    require_comparable(&l, &r)?;
    Ok(Value::Bool(!eq_with_cost(&l, &r, cx.ctx, cx.cost)?))
}

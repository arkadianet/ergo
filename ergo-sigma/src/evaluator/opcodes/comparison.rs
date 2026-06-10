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
use super::cast::apply_pre_v3_auto_upcast;

// 0x8F LT (<)
pub(in crate::evaluator) fn eval_lt(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    let (l, r) = apply_pre_v3_auto_upcast(l, r, cx)?;
    add_cost(cx.cost, 0x8F)?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Bool(a < b)),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Bool(a < b)),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a < b)),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Bool(a < b)),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::Bool(a < b)),
        (Value::UnsignedBigInt(a), Value::UnsignedBigInt(b)) => Ok(Value::Bool(a < b)),
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
    let (l, r) = apply_pre_v3_auto_upcast(l, r, cx)?;
    add_cost(cx.cost, 0x90)?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Bool(a <= b)),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Bool(a <= b)),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a <= b)),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Bool(a <= b)),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::Bool(a <= b)),
        (Value::UnsignedBigInt(a), Value::UnsignedBigInt(b)) => Ok(Value::Bool(a <= b)),
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
    let (l, r) = apply_pre_v3_auto_upcast(l, r, cx)?;
    add_cost(cx.cost, 0x91)?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Bool(a > b)),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Bool(a > b)),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a > b)),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Bool(a > b)),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::Bool(a > b)),
        (Value::UnsignedBigInt(a), Value::UnsignedBigInt(b)) => Ok(Value::Bool(a > b)),
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
    let (l, r) = apply_pre_v3_auto_upcast(l, r, cx)?;
    add_cost(cx.cost, 0x92)?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Bool(a >= b)),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Bool(a >= b)),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Bool(a >= b)),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Bool(a >= b)),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::Bool(a >= b)),
        (Value::UnsignedBigInt(a), Value::UnsignedBigInt(b)) => Ok(Value::Bool(a >= b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for GE",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

/// Scala `equalityOp` (SigmaBuilder.scala:678-686) enforces
/// `SameTypeConstrain` AFTER the (pre-v3) upcast: an EQ/NEQ whose
/// operand types still differ fails — at DESERIALIZATION in Scala
/// (`ConstraintFailed`), mirrored here at evaluation for the numeric
/// kinds, whose runtime carriers map 1:1 to static types. Without
/// this guard a v3+ mixed-kind equality falls through to PartialEq's
/// catch-all and produces a WRONG VALUE: `EQ(Int 1, Long 1)` → false,
/// and `NEQ` → true — a crafted v3 tree would VALIDATE here while
/// Scala rejects it (accept-vs-reject divergence). Post-upcast mixed
/// numeric kinds can only exist on v3+ trees (pre-v3 the upcast just
/// equalized them), so the guard is self-gating — no version check.
///
/// Non-numeric `SameTypeConstrain` mismatches (e.g. Int vs Coll[Byte],
/// mixed-kind tuples) remain a documented residual: collection/tuple
/// carriers are not 1:1 with static types here, so a runtime-kind
/// guard for them could falsely reject valid spends.
fn reject_mixed_numeric_equality(l: &Value, r: &Value) -> Result<(), EvalError> {
    fn kind(v: &Value) -> Option<u8> {
        match v {
            Value::Byte(_) => Some(1),
            Value::Short(_) => Some(2),
            Value::Int(_) => Some(3),
            Value::Long(_) => Some(4),
            Value::BigInt(_) => Some(5),
            // SUnsignedBigInt is its own SNumericType: BigInt vs
            // UnsignedBigInt likewise fails SameTypeConstrain.
            Value::UnsignedBigInt(_) => Some(6),
            _ => None,
        }
    }
    match (kind(l), kind(r)) {
        (Some(a), Some(b)) if a != b => Err(EvalError::TypeError {
            expected: "same numeric type for EQ/NEQ (Scala SameTypeConstrain)",
            got: format!("{l:?} vs {r:?}"),
        }),
        _ => Ok(()),
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
    let (l, r) = apply_pre_v3_auto_upcast(l, r, cx)?;
    reject_mixed_numeric_equality(&l, &r)?;
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
    let (l, r) = apply_pre_v3_auto_upcast(l, r, cx)?;
    reject_mixed_numeric_equality(&l, &r)?;
    require_comparable(&l, &r)?;
    Ok(Value::Bool(!eq_with_cost(&l, &r, cx.ctx, cx.cost)?))
}

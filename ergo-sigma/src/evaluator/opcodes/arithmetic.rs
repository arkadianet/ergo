//! Arithmetic and byte-array-numeric opcodes:
//!
//! - 0x99 Minus, 0x9A Plus, 0x9C Multiply, 0x9D Divide, 0x9E Modulo —
//!   binary arithmetic. Byte/Short/Int/Long all use checked_* for Plus/
//!   Minus/Multiply, matching Scala ExactIntegral (add/subtract/multiply
//!   Exact throw ArithmeticException on overflow). Divide/Modulo use
//!   wrapping_div/wrapping_rem for the fixed-width integers, matching
//!   Java/Scala `/`/`%` (MinValue / -1 wraps to MinValue, MinValue % -1
//!   == 0 — no exception, and no Rust divide-overflow panic). BigInt
//!   Modulo follows java.math.BigInteger.mod (Euclidean, non-negative
//!   remainder).
//! - 0xA1 Min, 0xA2 Max — n-ary numeric reducers.
//! - 0xF0 Negation — unary minus, checked_neg for Byte/Short.
//! - 0xFF XorOf — XOR-reduce of a Coll[Boolean] -> Boolean
//!   (LogicalTransformerSerializer, one input).
//! - 0x7A LongToByteArray, 0x7B ByteArrayToBigInt, 0x7C ByteArrayToLong
//!   — numeric ↔ byte-array conversions.
//!
//! Cost-charge sequencing relative to the recursive operand evaluations
//! is preserved exactly (eval-both-then-charge for binary ops; etc.).

use ergo_ser::opcode::Expr;
use num_traits::{Signed, Zero};

use super::super::cost::{add_arith_cost, add_cost, add_cost_per_item};
use super::super::eval_ctx::EvalCtx;
use super::super::types::{EvalError, Value};

// 0x99 Minus
pub(in crate::evaluator) fn eval_minus(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_arith_cost(cx.cost, 0x99, matches!(&l, Value::BigInt(_)))?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => a
            .checked_sub(b)
            .map(Value::Byte)
            .ok_or(EvalError::RuntimeException("Byte.- overflow")),
        (Value::Short(a), Value::Short(b)) => a
            .checked_sub(b)
            .map(Value::Short)
            .ok_or(EvalError::RuntimeException("Short.- overflow")),
        (Value::Int(a), Value::Int(b)) => a
            .checked_sub(b)
            .map(Value::Int)
            .ok_or(EvalError::RuntimeException("Int.- overflow")),
        (Value::Long(a), Value::Long(b)) => a
            .checked_sub(b)
            .map(Value::Long)
            .ok_or(EvalError::RuntimeException("Long.- overflow")),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::BigInt(a - b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Minus",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0x9A Plus
pub(in crate::evaluator) fn eval_plus(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_arith_cost(cx.cost, 0x9A, matches!(&l, Value::BigInt(_)))?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => a
            .checked_add(b)
            .map(Value::Byte)
            .ok_or(EvalError::RuntimeException("Byte.+ overflow")),
        (Value::Short(a), Value::Short(b)) => a
            .checked_add(b)
            .map(Value::Short)
            .ok_or(EvalError::RuntimeException("Short.+ overflow")),
        (Value::Int(a), Value::Int(b)) => a
            .checked_add(b)
            .map(Value::Int)
            .ok_or(EvalError::RuntimeException("Int.+ overflow")),
        (Value::Long(a), Value::Long(b)) => a
            .checked_add(b)
            .map(Value::Long)
            .ok_or(EvalError::RuntimeException("Long.+ overflow")),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::BigInt(a + b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Plus",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0x9C Multiply
pub(in crate::evaluator) fn eval_multiply(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_arith_cost(cx.cost, 0x9C, matches!(&l, Value::BigInt(_)))?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => a
            .checked_mul(b)
            .map(Value::Byte)
            .ok_or(EvalError::RuntimeException("Byte.* overflow")),
        (Value::Short(a), Value::Short(b)) => a
            .checked_mul(b)
            .map(Value::Short)
            .ok_or(EvalError::RuntimeException("Short.* overflow")),
        (Value::Int(a), Value::Int(b)) => a
            .checked_mul(b)
            .map(Value::Int)
            .ok_or(EvalError::RuntimeException("Int.* overflow")),
        (Value::Long(a), Value::Long(b)) => a
            .checked_mul(b)
            .map(Value::Long)
            .ok_or(EvalError::RuntimeException("Long.* overflow")),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::BigInt(a * b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Multiply",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0x9D Division
pub(in crate::evaluator) fn eval_division(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_arith_cost(cx.cost, 0x9D, matches!(&l, Value::BigInt(_)))?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => {
            a.checked_div(b)
                .map(Value::Byte)
                .ok_or(EvalError::RuntimeException(
                    "Byte./ overflow or divide-by-zero",
                ))
        }
        (Value::Short(a), Value::Short(b)) => {
            a.checked_div(b)
                .map(Value::Short)
                .ok_or(EvalError::RuntimeException(
                    "Short./ overflow or divide-by-zero",
                ))
        }
        // wrapping_div matches Java/Scala integer `/`: MinValue / -1 wraps
        // to MinValue (no exception), where Rust's native `/` would panic.
        (Value::Int(a), Value::Int(b)) if b != 0 => Ok(Value::Int(a.wrapping_div(b))),
        (Value::Long(a), Value::Long(b)) if b != 0 => Ok(Value::Long(a.wrapping_div(b))),
        (Value::BigInt(a), Value::BigInt(ref b)) if !b.is_zero() => Ok(Value::BigInt(a / b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Division (non-zero divisor)",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0x9E Modulo
pub(in crate::evaluator) fn eval_modulo(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_arith_cost(cx.cost, 0x9E, matches!(&l, Value::BigInt(_)))?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => {
            a.checked_rem(b)
                .map(Value::Byte)
                .ok_or(EvalError::RuntimeException(
                    "Byte.% overflow or divide-by-zero",
                ))
        }
        (Value::Short(a), Value::Short(b)) => {
            a.checked_rem(b)
                .map(Value::Short)
                .ok_or(EvalError::RuntimeException(
                    "Short.% overflow or divide-by-zero",
                ))
        }
        // wrapping_rem matches Java/Scala `%`: MinValue % -1 == 0 (no
        // exception), where Rust's native `%` would panic on that pair.
        (Value::Int(a), Value::Int(b)) if b != 0 => Ok(Value::Int(a.wrapping_rem(b))),
        (Value::Long(a), Value::Long(b)) if b != 0 => Ok(Value::Long(a.wrapping_rem(b))),
        // Scala's `%` on BigInt uses java.math.BigInteger.mod() which
        // returns the non-negative remainder (Euclidean mod), not
        // Rust's truncated remainder.
        (Value::BigInt(a), Value::BigInt(ref b)) if !b.is_zero() => {
            let r = &a % b;
            // Java BigInteger.mod: result is always non-negative for positive modulus
            if r.sign() == num_bigint::Sign::Minus {
                Ok(Value::BigInt(r + b.abs()))
            } else {
                Ok(Value::BigInt(r))
            }
        }
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Modulo (non-zero divisor)",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0xA1 Min
pub(in crate::evaluator) fn eval_min(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_arith_cost(cx.cost, 0xA1, matches!(&l, Value::BigInt(_)))?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Byte(a.min(b))),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Short(a.min(b))),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.min(b))),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Long(a.min(b))),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::BigInt(a.min(b))),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Min",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0xA2 Max
pub(in crate::evaluator) fn eval_max(
    left: &Expr,
    right: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let l = cx.eval_expr(left)?;
    let r = cx.eval_expr(right)?;
    add_arith_cost(cx.cost, 0xA2, matches!(&l, Value::BigInt(_)))?;
    match (l, r) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Byte(a.max(b))),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Short(a.max(b))),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.max(b))),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Long(a.max(b))),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::BigInt(a.max(b))),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Max",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

// 0xF0 Negation — unary minus. Byte/Short use checked_neg for Scala
// ExactIntegral parity (Scala throws on `-Byte.MinValue` / `-Short.MinValue`).
pub(in crate::evaluator) fn eval_negation(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xF0)?;
    let val = cx.eval_expr(inner)?;
    match val {
        Value::Byte(n) => n
            .checked_neg()
            .map(Value::Byte)
            .ok_or(EvalError::RuntimeException(
                "Byte negate overflow (-Byte.MinValue)",
            )),
        Value::Short(n) => n
            .checked_neg()
            .map(Value::Short)
            .ok_or(EvalError::RuntimeException(
                "Short negate overflow (-Short.MinValue)",
            )),
        Value::Int(n) => Ok(Value::Int(n.wrapping_neg())),
        Value::Long(n) => Ok(Value::Long(n.wrapping_neg())),
        Value::BigInt(n) => Ok(Value::BigInt(-n)),
        _ => Err(EvalError::TypeError {
            expected: "numeric type for Negation",
            got: format!("{val:?}"),
        }),
    }
}

// 0xFF XorOf(Coll[Boolean]) -> Boolean — XOR-reduce a collection of
// booleans. Scala `sigma.ast.XorOf` is a `LogicalTransformerCompanion`
// (one input, `Value[SCollection[SBoolean]]`). Element-wise byte XOR
// belongs to 0x9B `Xor`, not here. Cost: PerItem(20, 5, 32) over the
// collection length, matching `XorOf$.costKind`.
pub(in crate::evaluator) fn eval_xor_of(
    input: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    let v = cx.eval_expr(input)?;
    match v {
        Value::CollBool(bs) => {
            add_cost_per_item(cx.cost, 0xFF, bs.len() as u32)?;
            Ok(Value::Bool(bs.iter().fold(false, |acc, b| acc ^ b)))
        }
        other => Err(EvalError::TypeError {
            expected: "Coll[Boolean] for XorOf",
            got: format!("{other:?}"),
        }),
    }
}

// 0x7A LongToByteArray
pub(in crate::evaluator) fn eval_long_to_byte_array(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0x7A)?;
    match cx.eval_expr(inner)? {
        Value::Long(v) => Ok(Value::CollBytes(v.to_be_bytes().to_vec())),
        other => Err(EvalError::TypeError {
            expected: "Long for LongToByteArray",
            got: format!("{other:?}"),
        }),
    }
}

// 0x7B ByteArrayToBigInt
pub(in crate::evaluator) fn eval_byte_array_to_big_int(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0x7B)?;
    match cx.eval_expr(inner)? {
        Value::CollBytes(bytes) => Ok(Value::BigInt(num_bigint::BigInt::from_signed_bytes_be(
            &bytes,
        ))),
        other => Err(EvalError::TypeError {
            expected: "Coll[Byte] for ByteArrayToBigInt",
            got: format!("{other:?}"),
        }),
    }
}

// 0x7C ByteArrayToLong
pub(in crate::evaluator) fn eval_byte_array_to_long(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0x7C)?;
    match cx.eval_expr(inner)? {
        Value::CollBytes(bytes) if bytes.len() >= 8 => {
            let arr: [u8; 8] = bytes[..8].try_into().unwrap();
            Ok(Value::Long(i64::from_be_bytes(arr)))
        }
        Value::CollBytes(bytes) => Err(EvalError::TypeError {
            expected: "Coll[Byte] with at least 8 bytes",
            got: format!("Coll[Byte] with {} bytes", bytes.len()),
        }),
        other => Err(EvalError::TypeError {
            expected: "Coll[Byte] for ByteArrayToLong",
            got: format!("{other:?}"),
        }),
    }
}

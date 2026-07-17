//! `SNumericType` (type_id 2..=6) v6 bitwise/shift arms and
//! `SBigInt.toUnsignedMod` (type_id 6, method 15). `expect_unsigned_bigint`
//! (used here and by `unsigned_bigint`) lives in the sibling `unsigned_bigint`
//! module; `expect_bigint` is private to this file.

use ergo_ser::opcode::Expr;

use super::check_arity;
use super::unsigned_bigint::expect_unsigned_bigint;
use crate::evaluator::cost::add_method_cost;
use crate::evaluator::eval_ctx::EvalCtx;
use crate::evaluator::types::{EvalError, Value};

// SNumericType (Byte=2, Short=3, Int=4, Long=5, BigInt=6) v6
// bitwise + shift methods. All cost FixedCost(JitCost(5)).
// Source: `ScorexFoundation/sigmastate-interpreter@6.0-deserialize`
// `data/.../sigma/ast/methods.scala::SNumericTypeMethods`.
//
//   8  bitwiseInverse       (this)              -> tNum
//   9  bitwiseOr            (this, that: tNum)  -> tNum
//  10  bitwiseAnd           (this, that: tNum)  -> tNum
//  11  bitwiseXor           (this, that: tNum)  -> tNum
//  12  shiftLeft            (this, n: SInt)     -> tNum
//  13  shiftRight           (this, n: SInt)     -> tNum
//
// Semantics mirror Java: Byte/Short are promoted to Int before
// the shift then narrowed back, mod-32 shift count; Int uses
// mod-32; Long uses mod-64; BigInt accepts any non-negative
// shift count and rejects negatives as `RuntimeException` (mirrors
// Scala's `IllegalArgumentException` from `BigInteger.shiftLeft`).
// bitwiseInverse (2..=6, 8) is a zero-arg method handled by the shared
// `eval_no_arg_method` table (reachable via 0xDB PropertyCall — the
// form the compiler emits — and the 0xDC no-arg fallthrough), so it is
// intentionally not duplicated here.
pub(super) fn bitwise(
    method_id: u8,
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let rhs_val = cx.eval_expr(&args[0])?;
    add_method_cost(cx.cost, 5)?;
    let op = method_id; // 9=or, 10=and, 11=xor
    let bin_byte = |a: i8, b: i8| -> i8 {
        match op {
            9 => a | b,
            10 => a & b,
            _ => a ^ b,
        }
    };
    let bin_short = |a: i16, b: i16| -> i16 {
        match op {
            9 => a | b,
            10 => a & b,
            _ => a ^ b,
        }
    };
    let bin_int = |a: i32, b: i32| -> i32 {
        match op {
            9 => a | b,
            10 => a & b,
            _ => a ^ b,
        }
    };
    let bin_long = |a: i64, b: i64| -> i64 {
        match op {
            9 => a | b,
            10 => a & b,
            _ => a ^ b,
        }
    };
    let bin_big = |a: num_bigint::BigInt, b: &num_bigint::BigInt| -> num_bigint::BigInt {
        match op {
            9 => a | b,
            10 => a & b,
            _ => a ^ b,
        }
    };
    match (obj_val, rhs_val) {
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Byte(bin_byte(a, b))),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Short(bin_short(a, b))),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Int(bin_int(a, b))),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Long(bin_long(a, b))),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::BigInt(bin_big(a, &b))),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for bitwise op",
            got: format!("{l:?}, {r:?}"),
        }),
    }
}

pub(super) fn shift(
    method_id: u8,
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let n_val = cx.eval_expr(&args[0])?;
    let n = match n_val {
        Value::Int(x) => x,
        other => {
            return Err(EvalError::TypeError {
                expected: "Int shift count for shift method",
                got: format!("{other:?}"),
            })
        }
    };
    add_method_cost(cx.cost, 5)?;
    let is_left = method_id == 12;
    // Scala ExactIntegral.shiftLeft/shiftRight REJECT an
    // out-of-range count: they throw IllegalArgumentException
    // when `bits < 0 || bits >= width` (Byte 8, Short 16, Int 32,
    // Long 64; BigIntegerOps uses 256 for BigInt). We previously
    // masked the count (n & 31 / n & 63) and so silently accepted
    // out-of-range shifts the reference rejects. With the count
    // validated in range, the shift then matches Java: Byte/Short
    // promote through i32 and truncate; right shift is arithmetic
    // (sign-preserving).
    let width: i32 = match &obj_val {
        Value::Byte(_) => 8,
        Value::Short(_) => 16,
        Value::Int(_) => 32,
        Value::Long(_) => 64,
        Value::BigInt(_) => 256,
        other => {
            return Err(EvalError::TypeError {
                expected: "numeric type for shift",
                got: format!("{other:?}"),
            })
        }
    };
    if n < 0 || n >= width {
        return Err(EvalError::RuntimeException(
            "shift count out of range (0 <= bits < bit width)",
        ));
    }
    let shift = n as u32;
    match obj_val {
        Value::Byte(v) => {
            let promoted = v as i32;
            let r = if is_left {
                promoted.wrapping_shl(shift)
            } else {
                promoted.wrapping_shr(shift)
            };
            Ok(Value::Byte(r as i8))
        }
        Value::Short(v) => {
            let promoted = v as i32;
            let r = if is_left {
                promoted.wrapping_shl(shift)
            } else {
                promoted.wrapping_shr(shift)
            };
            Ok(Value::Short(r as i16))
        }
        Value::Int(v) => {
            let r = if is_left {
                v.wrapping_shl(shift)
            } else {
                v.wrapping_shr(shift)
            };
            Ok(Value::Int(r))
        }
        Value::Long(v) => {
            let r = if is_left {
                v.wrapping_shl(shift)
            } else {
                v.wrapping_shr(shift)
            };
            Ok(Value::Long(r))
        }
        Value::BigInt(v) => {
            let amt = shift as usize;
            let r = if is_left { v << amt } else { v >> amt };
            Ok(Value::BigInt(r))
        }
        // The `width` match above already rejected non-numeric types.
        other => Err(EvalError::TypeError {
            expected: "numeric type for shift",
            got: format!("{other:?}"),
        }),
    }
}

// SBigInt(6).toUnsigned(14) -> UnsignedBigInt
// SBigInt(6).toUnsignedMod(15, m: UnsignedBigInt) -> UnsignedBigInt
// Sigma 6.0 conversions from signed â†’ unsigned. Scala costs:
//   ToUnsigned     FixedCost(JitCost(5)) — methods.scala:545-546
//   ToUnsignedMod  FixedCost(JitCost(15)) — methods.scala:552-553
// toUnsigned: errors if `this` is negative (caller bug; the
// unsigned type can't represent it). toUnsignedMod: reduces
// any signed value modulo `m`, always producing a value in
// [0, m). `m` must be non-zero.
// SBigInt.toUnsigned (6, 14) is a zero-arg method handled by the shared
// `eval_no_arg_method` table (reachable via 0xDB PropertyCall).
pub(super) fn to_unsigned_mod(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let signed = expect_bigint(&obj_val, "SBigInt.toUnsignedMod receiver")?;
    let m_val = cx.eval_expr(&args[0])?;
    let m = expect_unsigned_bigint(&m_val, "SBigInt.toUnsignedMod modulus")?;
    add_method_cost(cx.cost, 15)?;
    if m.sign() == num_bigint::Sign::NoSign {
        return Err(EvalError::RuntimeException(
            "SBigInt.toUnsignedMod: modulus is zero",
        ));
    }
    // Mathematical mod: result is always in [0, m). Rust's `%`
    // returns a value with sign matching the dividend, so for
    // negative `signed` we add `m` to bring it into range.
    let r = signed % m;
    let result = if r.sign() == num_bigint::Sign::Minus {
        r + m
    } else {
        r
    };
    Ok(Value::UnsignedBigInt(result))
}

fn expect_bigint<'a>(
    v: &'a Value,
    where_used: &'static str,
) -> Result<&'a num_bigint::BigInt, EvalError> {
    match v {
        Value::BigInt(n) => Ok(n),
        other => Err(EvalError::TypeError {
            expected: where_used,
            got: format!("{other:?}"),
        }),
    }
}

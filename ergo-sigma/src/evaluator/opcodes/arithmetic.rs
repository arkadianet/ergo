//! Arithmetic and byte-array-numeric opcodes:
//!
//! - 0x99 Minus, 0x9A Plus, 0x9C Multiply, 0x9D Divide, 0x9E Modulo —
//!   binary arithmetic. Byte/Short/Int/Long use checked_* for Plus/Minus/
//!   Multiply, matching Scala ExactIntegral (add/subtract/multiply Exact
//!   throw ArithmeticException on overflow). Divide/Modulo use wrapping_div/
//!   wrapping_rem for ALL fixed-width integers, matching Java/Scala `/`/`%`
//!   (MinValue / -1 wraps to MinValue, MinValue % -1 == 0 — no exception,
//!   and no Rust divide-overflow panic; Scala's ExactIntegral does not
//!   override quot/divisionRemainder, so Byte/Short behave like Int/Long).
//!   BigInt Plus/Minus/Multiply enforce the signed-256-bit bound
//!   (CBigInt.* -> toSignedBigIntValueExact, unconditional). BigInt Modulo
//!   follows java.math.BigInteger.mod: a non-positive modulus throws
//!   ("modulus not positive"); for a positive modulus the result is the
//!   non-negative remainder in [0, b). BigInt Divide has no 256-bit check.
//! - 0xA1 Min, 0xA2 Max — n-ary numeric reducers.
//! - 0xF0 Negation — unary minus. Fixed-width integers wrap (Scala
//!   ExactNumeric.negate is not exact); BigInt negate enforces the 256-bit
//!   bound.
//! - 0xFF XorOf — XOR-reduce of a Coll[Boolean] -> Boolean
//!   (LogicalTransformerSerializer, one input).
//! - 0x7A LongToByteArray, 0x7B ByteArrayToBigInt, 0x7C ByteArrayToLong
//!   — numeric ↔ byte-array conversions. ByteArrayToBigInt rejects an empty
//!   input and a value outside the signed 256-bit range.
//!
//! Cost-charge sequencing relative to the recursive operand evaluations
//! is preserved exactly (eval-both-then-charge for binary ops; etc.).

use ergo_ser::opcode::Expr;
use num_traits::{Signed, Zero};

use super::super::cost::{add_arith_cost, add_cost, add_cost_per_item};
use super::super::eval_ctx::EvalCtx;
use super::super::types::{EvalError, Value};

/// Scala `Extensions.fitsIn256Bits` = `bitLength() <= 255`, i.e. the value
/// fits a signed 256-bit two's-complement representation: `x ∈ [-2^255,
/// 2^255-1]`. The boundaries `-2^255` (bitLength 255) and `2^255-1` are
/// accepted; `2^255` and `-2^255-1` are not. `CBigInt.add/subtract/multiply
/// /negate` route their result through `toSignedBigIntValueExact`
/// (UNCONDITIONAL — not ErgoTree-version gated; the only v3-gated 256 check
/// is the separate `CBigInt` constructor guard), and `byteArrayToBigInt`
/// uses the same bound. We check the value range directly rather than a bit
/// count because `num_bigint::BigInt::bits()` returns the magnitude width
/// and would wrongly reject `-2^255`.
fn fits_in_256_bits(x: &num_bigint::BigInt) -> bool {
    let two_pow_255 = num_bigint::BigInt::from(1) << 255u32;
    let min = -&two_pow_255;
    x >= &min && x < &two_pow_255
}

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
        (Value::BigInt(a), Value::BigInt(b)) => {
            let r = a - b;
            if fits_in_256_bits(&r) {
                Ok(Value::BigInt(r))
            } else {
                Err(EvalError::RuntimeException("BigInt.- out of 256-bit range"))
            }
        }
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
        (Value::BigInt(a), Value::BigInt(b)) => {
            let r = a + b;
            if fits_in_256_bits(&r) {
                Ok(Value::BigInt(r))
            } else {
                Err(EvalError::RuntimeException("BigInt.+ out of 256-bit range"))
            }
        }
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
        (Value::BigInt(a), Value::BigInt(b)) => {
            let r = a * b;
            if fits_in_256_bits(&r) {
                Ok(Value::BigInt(r))
            } else {
                Err(EvalError::RuntimeException("BigInt.* out of 256-bit range"))
            }
        }
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
        // Zero divisor is a runtime arithmetic error (Scala/Java throw
        // ArithmeticException), not a type error — surfaced as
        // RuntimeException. Handled explicitly so the wrapping divide arms
        // below never see a zero divisor.
        (Value::Byte(_), Value::Byte(0)) => {
            Err(EvalError::RuntimeException("Byte./ divide by zero"))
        }
        (Value::Short(_), Value::Short(0)) => {
            Err(EvalError::RuntimeException("Short./ divide by zero"))
        }
        (Value::Int(_), Value::Int(0)) => Err(EvalError::RuntimeException("Int./ divide by zero")),
        (Value::Long(_), Value::Long(0)) => {
            Err(EvalError::RuntimeException("Long./ divide by zero"))
        }
        (Value::BigInt(_), Value::BigInt(ref b)) if b.is_zero() => {
            Err(EvalError::RuntimeException("BigInt./ divide by zero"))
        }
        // wrapping_div matches Java/Scala integer `/`: MinValue / -1 wraps
        // to MinValue (no exception) for ALL fixed-width types. Scala's
        // ExactIntegral does not override quot, so it delegates to plain
        // Numeric.quot (promote to wider, divide, truncate back) — Byte/Short
        // behave the same as Int/Long here. Divisor is non-zero (zero handled
        // above), so wrapping_div only differs from native `/` on MIN/-1.
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Byte(a.wrapping_div(b))),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Short(a.wrapping_div(b))),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.wrapping_div(b))),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Long(a.wrapping_div(b))),
        (Value::BigInt(a), Value::BigInt(b)) => Ok(Value::BigInt(a / b)),
        (l, r) => Err(EvalError::TypeError {
            expected: "matching numeric types for Division",
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
        // Zero divisor is a runtime arithmetic error (Scala/Java throw
        // ArithmeticException), not a type error. Handled explicitly so the
        // wrapping remainder arms below never see a zero divisor. (BigInt %
        // 0 is caught by the non-positive-modulus check in its arm instead.)
        (Value::Byte(_), Value::Byte(0)) => {
            Err(EvalError::RuntimeException("Byte.% divide by zero"))
        }
        (Value::Short(_), Value::Short(0)) => {
            Err(EvalError::RuntimeException("Short.% divide by zero"))
        }
        (Value::Int(_), Value::Int(0)) => Err(EvalError::RuntimeException("Int.% divide by zero")),
        (Value::Long(_), Value::Long(0)) => {
            Err(EvalError::RuntimeException("Long.% divide by zero"))
        }
        // wrapping_rem matches Java/Scala `%`: MinValue % -1 == 0 (no
        // exception) for ALL fixed-width types (ExactIntegral does not
        // override divisionRemainder; it delegates to plain Numeric.rem).
        // Divisor is non-zero here (zero handled above).
        (Value::Byte(a), Value::Byte(b)) => Ok(Value::Byte(a.wrapping_rem(b))),
        (Value::Short(a), Value::Short(b)) => Ok(Value::Short(a.wrapping_rem(b))),
        (Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.wrapping_rem(b))),
        (Value::Long(a), Value::Long(b)) => Ok(Value::Long(a.wrapping_rem(b))),
        // Scala's `%` on BigInt uses java.math.BigInteger.mod(): it THROWS
        // ("modulus not positive") for any non-positive modulus (b <= 0,
        // including b == 0), and for b > 0 returns the NON-NEGATIVE remainder
        // in [0, b) regardless of the dividend's sign (floored mod, not the
        // truncated/sign-of-dividend remainder). No 256-bit check applies.
        (Value::BigInt(a), Value::BigInt(ref b)) => {
            if !b.is_positive() {
                return Err(EvalError::RuntimeException("BigInt.% modulus not positive"));
            }
            let r = &a % b;
            if r.sign() == num_bigint::Sign::Minus {
                Ok(Value::BigInt(r + b))
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

// 0xF0 Negation — unary minus. All fixed-width integers WRAP: Scala routes
// negate through ExactNumeric.negate = plain scala.math.Numeric.negate,
// which is NOT exact (unlike plus/minus/times). So -Byte.MinValue =
// Byte.MinValue, -Short.MinValue = Short.MinValue, etc. — no throw. BigInt
// negate enforces the signed-256-bit bound (CBigInt.negate =
// wrappedValue.negate().toSignedBigIntValueExact), so -(-2^255) = 2^255
// overflows and throws.
pub(in crate::evaluator) fn eval_negation(
    inner: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xF0)?;
    let val = cx.eval_expr(inner)?;
    match val {
        Value::Byte(n) => Ok(Value::Byte(n.wrapping_neg())),
        Value::Short(n) => Ok(Value::Short(n.wrapping_neg())),
        Value::Int(n) => Ok(Value::Int(n.wrapping_neg())),
        Value::Long(n) => Ok(Value::Long(n.wrapping_neg())),
        Value::BigInt(n) => {
            let r = -n;
            if fits_in_256_bits(&r) {
                Ok(Value::BigInt(r))
            } else {
                Err(EvalError::RuntimeException(
                    "BigInt negate out of 256-bit range",
                ))
            }
        }
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
        Value::CollBytes(bytes) => {
            // Scala: `new BigInteger(bytes.toArray).toSignedBigIntValueExact`.
            // An empty array makes the java BigInteger constructor throw
            // (NumberFormatException "Zero length BigInteger"); a value
            // outside the signed 256-bit range makes toSignedBigIntValueExact
            // throw. The decode is SIGNED big-endian (matches from_signed_
            // bytes_be), so 0x80 ++ 0*31 = -2^255 is accepted.
            if bytes.is_empty() {
                return Err(EvalError::RuntimeException(
                    "byteArrayToBigInt: empty input (zero-length BigInteger)",
                ));
            }
            let v = num_bigint::BigInt::from_signed_bytes_be(&bytes);
            if !fits_in_256_bits(&v) {
                return Err(EvalError::RuntimeException(
                    "byteArrayToBigInt: out of 256-bit range",
                ));
            }
            Ok(Value::BigInt(v))
        }
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

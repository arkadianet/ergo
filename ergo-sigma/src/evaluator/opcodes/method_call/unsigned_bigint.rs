//! `SUnsignedBigInt` (type_id 9) v6 arms: bitwise/shift (9..=13) and modular
//! arithmetic (14..=18) — already a contiguous, self-contained cluster in the
//! original file, lifted whole. `expect_unsigned_bigint` is shared with the
//! `numeric` sibling (`SBigInt.toUnsignedMod`), so it is `pub(super)`.

use ergo_ser::opcode::Expr;
use num_integer::Integer;
use num_traits::One;

use super::check_arity;
use crate::evaluator::cost::add_method_cost;
use crate::evaluator::eval_ctx::EvalCtx;
use crate::evaluator::types::{EvalError, Value};

// SUnsignedBigInt(9) v6 bitwise/shift methods, INHERITED from
// SNumericTypeMethods.v6Methods (SUnsignedBigIntMethods extends
// SNumericTypeMethods). All FixedCost(JitCost(5)), no type args.
//   8 bitwiseInverse  9 bitwiseOr  10 bitwiseAnd  11 bitwiseXor
//   12 shiftLeft       13 shiftRight
// Unlike SBigInt (signed two's-complement), these operate on the
// UNSIGNED 256-bit domain: bitwiseInverse is the masked complement
// (2^256-1) XOR n (Scala `CUnsignedBigInt.bitwiseInverse` flips a
// fixed 32-byte array), and shiftLeft/shiftRight hard-reject a
// count outside [0, 256) and reject a shiftLeft result exceeding
// 256 bits (CUnsignedBigInt's ctor throws), rather than masking
// the count the way the fixed-width (2..=6, 12|13) arms do.
// SUnsignedBigInt.bitwiseInverse (9, 8) is a zero-arg method handled by
// the shared `eval_no_arg_method` table (reachable via 0xDB
// PropertyCall), so it is intentionally not duplicated here.
pub(super) fn bitwise(
    method_id: u8,
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt bitwise receiver")?.clone();
    let b_val = cx.eval_expr(&args[0])?;
    let b = expect_unsigned_bigint(&b_val, "SUnsignedBigInt bitwise operand")?;
    add_method_cost(cx.cost, 5)?;
    // Inputs are in [0, 2^256); or/and/xor stay in range (no mask).
    let r = match method_id {
        9 => a | b,
        10 => a & b,
        _ => a ^ b,
    };
    Ok(Value::UnsignedBigInt(r))
}

pub(super) fn shift_left(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.shiftLeft receiver")?.clone();
    let bits = match cx.eval_expr(&args[0])? {
        Value::Int(x) => x,
        other => {
            return Err(EvalError::TypeError {
                expected: "Int shift count for SUnsignedBigInt.shiftLeft",
                got: format!("{other:?}"),
            })
        }
    };
    add_method_cost(cx.cost, 5)?;
    if !(0..256).contains(&bits) {
        return Err(EvalError::RuntimeException(
            "SUnsignedBigInt.shiftLeft: shift count out of range [0, 256)",
        ));
    }
    let r = a << bits as usize;
    if r.bits() > 256 {
        return Err(EvalError::RuntimeException(
            "SUnsignedBigInt.shiftLeft: result exceeds 256 bits",
        ));
    }
    Ok(Value::UnsignedBigInt(r))
}

pub(super) fn shift_right(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.shiftRight receiver")?.clone();
    let bits = match cx.eval_expr(&args[0])? {
        Value::Int(x) => x,
        other => {
            return Err(EvalError::TypeError {
                expected: "Int shift count for SUnsignedBigInt.shiftRight",
                got: format!("{other:?}"),
            })
        }
    };
    add_method_cost(cx.cost, 5)?;
    if !(0..256).contains(&bits) {
        return Err(EvalError::RuntimeException(
            "SUnsignedBigInt.shiftRight: shift count out of range [0, 256)",
        ));
    }
    // Logical shift (receiver >= 0, no sign extension).
    Ok(Value::UnsignedBigInt(a >> bits as usize))
}

// SUnsignedBigInt(9) v6 modular-arithmetic methods. Costs
// per methods.scala:574-609 — fixed costs (no per-bit scaling
// in Scala for these operations either).
//   14 modInverse   FixedCost(JitCost(150))  (this, m)
//   15 plusMod      FixedCost(JitCost(30))   (this, that, m)
//   16 subtractMod  FixedCost(JitCost(30))   (this, that, m)
//   17 multiplyMod  FixedCost(JitCost(40))   (this, that, m)
//   18 mod          FixedCost(JitCost(20))   (this, m)
//   19 toSigned     FixedCost(JitCost(10))   (this)
pub(super) fn mod_inverse(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.modInverse receiver")?;
    let m_val = cx.eval_expr(&args[0])?;
    let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.modInverse modulus")?;
    add_method_cost(cx.cost, 150)?;
    // Java's BigInteger.modInverse throws on a non-positive modulus;
    // guard m == 0 here so a crafted `modInverse(1, 0)` rejects the
    // transaction instead of panicking on `1 % 0` below.
    if m.sign() == num_bigint::Sign::NoSign {
        return Err(EvalError::RuntimeException(
            "SUnsignedBigInt.modInverse: modulus is zero",
        ));
    }
    // num-bigint provides modpow but not modinverse directly.
    // Use the extended Euclidean algorithm: if gcd(a, m) = 1,
    // the Bezout coefficient for `a` is the inverse mod m.
    let egcd = a.extended_gcd(m);
    if !egcd.gcd.is_one() {
        return Err(EvalError::RuntimeException(
            "SUnsignedBigInt.modInverse: receiver not coprime with modulus",
        ));
    }
    let r = egcd.x % m;
    let inv = if r.sign() == num_bigint::Sign::Minus {
        r + m
    } else {
        r
    };
    Ok(Value::UnsignedBigInt(inv))
}

pub(super) fn plus_mod(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 2)?;
    let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.plusMod receiver")?;
    let b_val = cx.eval_expr(&args[0])?;
    let b = expect_unsigned_bigint(&b_val, "SUnsignedBigInt.plusMod addend")?;
    let m_val = cx.eval_expr(&args[1])?;
    let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.plusMod modulus")?;
    add_method_cost(cx.cost, 30)?;
    if m.sign() == num_bigint::Sign::NoSign {
        return Err(EvalError::RuntimeException(
            "SUnsignedBigInt.plusMod: modulus is zero",
        ));
    }
    Ok(Value::UnsignedBigInt((a + b) % m))
}

pub(super) fn subtract_mod(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 2)?;
    let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.subtractMod receiver")?;
    let b_val = cx.eval_expr(&args[0])?;
    let b = expect_unsigned_bigint(&b_val, "SUnsignedBigInt.subtractMod subtrahend")?;
    let m_val = cx.eval_expr(&args[1])?;
    let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.subtractMod modulus")?;
    add_method_cost(cx.cost, 30)?;
    if m.sign() == num_bigint::Sign::NoSign {
        return Err(EvalError::RuntimeException(
            "SUnsignedBigInt.subtractMod: modulus is zero",
        ));
    }
    // (a - b) mod m — unsigned semantics: if a < b, the
    // difference is negative; add m to wrap into [0, m).
    let diff = a - b;
    let r = diff % m;
    let result = if r.sign() == num_bigint::Sign::Minus {
        r + m
    } else {
        r
    };
    Ok(Value::UnsignedBigInt(result))
}

pub(super) fn multiply_mod(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 2)?;
    let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.multiplyMod receiver")?;
    let b_val = cx.eval_expr(&args[0])?;
    let b = expect_unsigned_bigint(&b_val, "SUnsignedBigInt.multiplyMod multiplier")?;
    let m_val = cx.eval_expr(&args[1])?;
    let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.multiplyMod modulus")?;
    add_method_cost(cx.cost, 40)?;
    if m.sign() == num_bigint::Sign::NoSign {
        return Err(EvalError::RuntimeException(
            "SUnsignedBigInt.multiplyMod: modulus is zero",
        ));
    }
    Ok(Value::UnsignedBigInt((a * b) % m))
}

pub(super) fn mod_op(
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let a = expect_unsigned_bigint(&obj_val, "SUnsignedBigInt.mod receiver")?;
    let m_val = cx.eval_expr(&args[0])?;
    let m = expect_unsigned_bigint(&m_val, "SUnsignedBigInt.mod modulus")?;
    add_method_cost(cx.cost, 20)?;
    if m.sign() == num_bigint::Sign::NoSign {
        return Err(EvalError::RuntimeException(
            "SUnsignedBigInt.mod: modulus is zero",
        ));
    }
    Ok(Value::UnsignedBigInt(a % m))
}

pub(super) fn expect_unsigned_bigint<'a>(
    v: &'a Value,
    where_used: &'static str,
) -> Result<&'a num_bigint::BigInt, EvalError> {
    match v {
        Value::UnsignedBigInt(n) => Ok(n),
        other => Err(EvalError::TypeError {
            expected: where_used,
            got: format!("{other:?}"),
        }),
    }
}

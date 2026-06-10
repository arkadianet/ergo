//! Numeric type casts: Upcast (0x7E, widening) and Downcast (0x7D,
//! narrowing). Downcast follows Scala `SType.scala:370-498`'s
//! `Math.toIntExact / toShortExact / toByteExact` semantics — overflow
//! throws (Rust `TryFrom` → `EvalError::RuntimeException`).

use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;

use super::super::cost::add_method_cost;
use super::super::eval_ctx::EvalCtx;
use super::super::types::{EvalError, Value};

/// Scala numeric-cast cost is `TypeBasedCost`: a widening/narrowing to a
/// BigInt-family target costs `JitCost(30)`; all other (fixed-width) targets
/// cost `JitCost(10)`. Charging a flat 10 undercharged casts to BigInt.
fn numeric_cast_cost(tpe: &SigmaType) -> u64 {
    match tpe {
        SigmaType::SBigInt | SigmaType::SUnsignedBigInt => 30,
        _ => 10,
    }
}

/// Cast a non-negative integer value into an `UnsignedBigInt`. Scala
/// `SUnsignedBigInt` numeric casts (SType.scala) reject a negative source
/// (an unsigned big int cannot represent it) — a `RuntimeException` here.
fn to_unsigned_bigint(n: num_bigint::BigInt) -> Result<Value, EvalError> {
    if n.sign() == num_bigint::Sign::Minus {
        Err(EvalError::RuntimeException(
            "cannot cast a negative value to UnsignedBigInt",
        ))
    } else {
        Ok(Value::UnsignedBigInt(n))
    }
}

/// Scala `DeserializationSigmaBuilder.applyUpcast` equivalent, applied at
/// EVAL time.
///
/// Pre-v3 ErgoTrees auto-insert an `Upcast` node on the narrower operand
/// of a mixed-kind numeric two-operand op at DESERIALIZATION
/// (SigmaBuilder.scala:741-756, gated on `!isV3OrLaterErgoTreeVersion` —
/// "since v3 trees, Upcast nodes are not inserted automatically").
/// Exactly three builder families route through it
/// (SigmaBuilder.scala:678-705): `arithOp`
/// (Plus/Minus/Multiply/Divide/Modulo/Min/Max), `comparisonOp`
/// (GT/GE/LT/LE) and `equalityOp` (EQ/NEQ); `BitOp` constructs directly
/// and is NOT upcast.
///
/// Our parser stays byte-faithful (no node insertion — reserialization
/// must remain byte-identical), so the inserted node's value/cost effect
/// lands here instead: the narrower operand widens to the other
/// operand's kind, charging the Upcast `NumericCastCostKind` (10; 30 for
/// a BigInt target) exactly once per op — Scala's `upcastTo` is a no-op
/// on the already-max operand (syntax.scala:174 `if (targetType ==
/// tV.tpe) v`), so it likewise inserts exactly one node.
/// `UnsignedBigInt` is a v6-only carrier unreachable in a pre-v3 tree
/// and never participates (rank `None`).
///
/// CHARGE-POINT NOTE: Scala's `Upcast.eval` evaluates its input and then
/// charges (trees.scala:402-407), so when the LEFT operand wears the
/// node the charge lands between the two operand evaluations; here it
/// lands after both. Totals are identical on every success path (and a
/// budget breach therefore fires in both implementations), but the
/// breach point / error class can differ on error paths — invisible to
/// conformance (cost is not compared on errors) and consensus-equivalent
/// (both are script failures). Exact charge-point parity is structurally
/// unavailable at eval time: Scala picks the upcast operand from STATIC
/// types during builder rewriting, while the kinds here are only known
/// after both operands evaluate.
pub(in crate::evaluator) fn apply_pre_v3_auto_upcast(
    l: Value,
    r: Value,
    cx: &mut EvalCtx<'_>,
) -> Result<(Value, Value), EvalError> {
    if cx.ctx.is_v3_ergo_tree() {
        return Ok((l, r));
    }
    // SNumericType ordering: SByte < SShort < SInt < SLong < SBigInt.
    fn rank(v: &Value) -> Option<u8> {
        match v {
            Value::Byte(_) => Some(1),
            Value::Short(_) => Some(2),
            Value::Int(_) => Some(3),
            Value::Long(_) => Some(4),
            Value::BigInt(_) => Some(5),
            _ => None,
        }
    }
    let (Some(a), Some(b)) = (rank(&l), rank(&r)) else {
        return Ok((l, r));
    };
    if a == b {
        Ok((l, r))
    } else if a < b {
        Ok((widen_to_kind_of(l, &r, cx)?, r))
    } else {
        let widened = widen_to_kind_of(r, &l, cx)?;
        Ok((l, widened))
    }
}

/// Widen `v` to the numeric kind of `target`, charging the same
/// `NumericCastCostKind` an explicit `Upcast` node charges in
/// [`eval_upcast`]. Only called with `rank(v) < rank(target)`.
fn widen_to_kind_of(v: Value, target: &Value, cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    let target_tpe = match target {
        Value::Short(_) => SigmaType::SShort,
        Value::Int(_) => SigmaType::SInt,
        Value::Long(_) => SigmaType::SLong,
        Value::BigInt(_) => SigmaType::SBigInt,
        other => {
            return Err(EvalError::TypeError {
                expected: "numeric upcast target",
                got: format!("{other:?}"),
            })
        }
    };
    add_method_cost(cx.cost, numeric_cast_cost(&target_tpe))?;
    match (v, &target_tpe) {
        (Value::Byte(n), SigmaType::SShort) => Ok(Value::Short(n as i16)),
        (Value::Byte(n), SigmaType::SInt) => Ok(Value::Int(n as i32)),
        (Value::Byte(n), SigmaType::SLong) => Ok(Value::Long(n as i64)),
        (Value::Byte(n), SigmaType::SBigInt) => Ok(Value::BigInt(n.into())),
        (Value::Short(n), SigmaType::SInt) => Ok(Value::Int(n as i32)),
        (Value::Short(n), SigmaType::SLong) => Ok(Value::Long(n as i64)),
        (Value::Short(n), SigmaType::SBigInt) => Ok(Value::BigInt(n.into())),
        (Value::Int(n), SigmaType::SLong) => Ok(Value::Long(n as i64)),
        (Value::Int(n), SigmaType::SBigInt) => Ok(Value::BigInt(n.into())),
        (Value::Long(n), SigmaType::SBigInt) => Ok(Value::BigInt(n.into())),
        (v, _) => Err(EvalError::TypeError {
            expected: "widening numeric upcast",
            got: format!("{v:?} -> {target_tpe:?}"),
        }),
    }
}

// 0x7E Upcast — numeric type widening. Byte/Short preserved as typed carriers.
pub(in crate::evaluator) fn eval_upcast(
    input: &Expr,
    tpe: &SigmaType,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_method_cost(cx.cost, numeric_cast_cost(tpe))?;
    let val = cx.eval_expr(input)?;
    match (val, tpe) {
        // Byte → {Byte, Short, Int, Long, BigInt}
        (Value::Byte(n), SigmaType::SByte) => Ok(Value::Byte(n)),
        (Value::Byte(n), SigmaType::SShort) => Ok(Value::Short(n as i16)),
        (Value::Byte(n), SigmaType::SInt) => Ok(Value::Int(n as i32)),
        (Value::Byte(n), SigmaType::SLong) => Ok(Value::Long(n as i64)),
        (Value::Byte(n), SigmaType::SBigInt) => Ok(Value::BigInt(n.into())),
        // Short → {Short, Int, Long, BigInt}
        (Value::Short(n), SigmaType::SShort) => Ok(Value::Short(n)),
        (Value::Short(n), SigmaType::SInt) => Ok(Value::Int(n as i32)),
        (Value::Short(n), SigmaType::SLong) => Ok(Value::Long(n as i64)),
        (Value::Short(n), SigmaType::SBigInt) => Ok(Value::BigInt(n.into())),
        // Int → {Int, Long, BigInt}
        (Value::Int(n), SigmaType::SInt) => Ok(Value::Int(n)),
        (Value::Int(n), SigmaType::SLong) => Ok(Value::Long(n as i64)),
        (Value::Int(n), SigmaType::SBigInt) => Ok(Value::BigInt(n.into())),
        // Long → {Long, BigInt}
        (Value::Long(n), SigmaType::SLong) => Ok(Value::Long(n)),
        (Value::Long(n), SigmaType::SBigInt) => Ok(Value::BigInt(n.into())),
        // BigInt → BigInt (identity)
        (Value::BigInt(n), SigmaType::SBigInt) => Ok(Value::BigInt(n)),
        // {Byte, Short, Int, Long} → UnsignedBigInt (v6): a negative source
        // rejects (unsigned cannot represent it).
        (Value::Byte(n), SigmaType::SUnsignedBigInt) => to_unsigned_bigint(n.into()),
        (Value::Short(n), SigmaType::SUnsignedBigInt) => to_unsigned_bigint(n.into()),
        (Value::Int(n), SigmaType::SUnsignedBigInt) => to_unsigned_bigint(n.into()),
        (Value::Long(n), SigmaType::SUnsignedBigInt) => to_unsigned_bigint(n.into()),
        // UnsignedBigInt → UnsignedBigInt (identity; the value is already
        // non-negative, so no re-check — mirrors the BigInt identity arm).
        (Value::UnsignedBigInt(n), SigmaType::SUnsignedBigInt) => Ok(Value::UnsignedBigInt(n)),
        (v, _) => Err(EvalError::TypeError {
            expected: "numeric value for Upcast",
            got: format!("{v:?}"),
        }),
    }
}

// 0x7D Downcast — numeric type narrowing. Scala SType.scala:370-498 uses
// Math.toIntExact/toShortExact/toByteExact semantics — overflow throws.
// Rust equivalent is TryFrom; out-of-range → EvalError::RuntimeException.
pub(in crate::evaluator) fn eval_downcast(
    input: &Expr,
    tpe: &SigmaType,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_method_cost(cx.cost, numeric_cast_cost(tpe))?;
    let val = cx.eval_expr(input)?;
    match (val, tpe) {
        // Identity
        (Value::Byte(n), SigmaType::SByte) => Ok(Value::Byte(n)),
        (Value::Short(n), SigmaType::SShort) => Ok(Value::Short(n)),
        (Value::Long(n), SigmaType::SLong) => Ok(Value::Long(n)),
        (Value::Int(n), SigmaType::SInt) => Ok(Value::Int(n)),
        // Long → smaller (exact-fit; overflow throws per Scala SLong.downcast)
        (Value::Long(n), SigmaType::SInt) => i32::try_from(n)
            .map(Value::Int)
            .map_err(|_| EvalError::RuntimeException("Long.toIntExact overflow")),
        (Value::Long(n), SigmaType::SShort) => i16::try_from(n)
            .map(Value::Short)
            .map_err(|_| EvalError::RuntimeException("Long.toShortExact overflow")),
        (Value::Long(n), SigmaType::SByte) => i8::try_from(n)
            .map(Value::Byte)
            .map_err(|_| EvalError::RuntimeException("Long.toByteExact overflow")),
        // Int → smaller
        (Value::Int(n), SigmaType::SShort) => i16::try_from(n)
            .map(Value::Short)
            .map_err(|_| EvalError::RuntimeException("Int.toShortExact overflow")),
        (Value::Int(n), SigmaType::SByte) => i8::try_from(n)
            .map(Value::Byte)
            .map_err(|_| EvalError::RuntimeException("Int.toByteExact overflow")),
        // Short → smaller
        (Value::Short(n), SigmaType::SByte) => i8::try_from(n)
            .map(Value::Byte)
            .map_err(|_| EvalError::RuntimeException("Short.toByteExact overflow")),
        // BigInt → smaller (Scala uses BigInt.toInt/toShort/toByte which
        // throw ArithmeticException on overflow; v3+ VersionContext).
        (Value::BigInt(n), SigmaType::SLong) => {
            let v: i64 = (&n)
                .try_into()
                .map_err(|_| EvalError::RuntimeException("BigInt.toLongExact overflow"))?;
            Ok(Value::Long(v))
        }
        (Value::BigInt(n), SigmaType::SInt) => {
            let v: i32 = (&n)
                .try_into()
                .map_err(|_| EvalError::RuntimeException("BigInt.toIntExact overflow"))?;
            Ok(Value::Int(v))
        }
        (Value::BigInt(ref n), SigmaType::SShort) => {
            let v: i16 = n
                .try_into()
                .map_err(|_| EvalError::RuntimeException("BigInt.toShortExact overflow"))?;
            Ok(Value::Short(v))
        }
        (Value::BigInt(ref n), SigmaType::SByte) => {
            let v: i8 = n
                .try_into()
                .map_err(|_| EvalError::RuntimeException("BigInt.toByteExact overflow"))?;
            Ok(Value::Byte(v))
        }
        (v, _) => Err(EvalError::TypeError {
            expected: "numeric value for Downcast",
            got: format!("{v:?}"),
        }),
    }
}

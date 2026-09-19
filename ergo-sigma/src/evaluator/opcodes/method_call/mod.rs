//! `0xDC MethodCall` — dispatch on `(type_id, method_id)` to the
//! corresponding type-method handler. Scala charges `MethodCall`
//! overhead (4) after receiver evaluation plus per-method cost; this module is the
//! single largest opcode in the evaluator.
//!
//! Cost discipline is per-method: each arm calls `add_method_cost(cx.cost, n)`
//! after the dispatcher's `add_cost(cx.cost, 0xDC)`. The two are kept distinct —
//! a shared "method overhead" wrapper would silently collapse the per-method
//! cost into the dispatcher cost.
//!
//! The `(type_id, method_id)` match body was decomposed into per-receiver-type
//! sibling modules; `eval_method_call` is now a thin router that charges the
//! dispatcher cost after applying the v6 soft-fork gate and evaluating the receiver,
//! and delegates each arm to a named handler in the sibling below.

use ergo_ser::opcode::Expr;

use super::super::cost::add_cost;
use super::super::eval_ctx::EvalCtx;
use super::super::types::{EvalError, Value};

mod avl;
mod coll;
mod global;
mod misc;
mod numeric;
mod option;
mod unsigned_bigint;

// `serialize_put_cost` is exercised directly by the evaluator test-suite via
// the path `crate::evaluator::opcodes::method_call::serialize_put_cost`; keep
// that path stable by re-exporting it from its new home in `global`. The
// re-export is consumed only under `cfg(test)`.
#[cfg(test)]
pub(in crate::evaluator) use global::serialize_put_cost;

pub(in crate::evaluator) fn eval_method_call(
    type_id: u8,
    method_id: u8,
    obj: &Expr,
    args: &[Expr],
    type_args: &[ergo_ser::sigma_type::SigmaType],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    // Soft-fork activation gate for EIP-50 / Sigma 6.0 methods.
    // Scala parity: `MethodCall.evaluate` cross-checks
    // `method.methodVersion` (declared in `_v6Methods`) against
    // `context.activatedScriptVersion`. The table below mirrors the
    // Scala v6 method registry — any method-id appearing in `_v6Methods`
    // for a given type-id requires `activatedScriptVersion >= 3` (block
    // header version 4). The (12, 31 | 32) range is fused with
    // 30..=33 since 31 and 32 are the startsWith/endsWith arm. (101, 8)
    // selfBoxIndex stays v5 with its own pre-JIT bug-preservation logic
    // in property_call.rs. (106, 2) Global.xor is V5+ (predates EIP-50).
    if is_v6_method(type_id, method_id) {
        cx.ctx.require_method_version(type_id, method_id, 3)?;
    }
    let obj_val = cx.eval_expr(obj)?;
    add_cost(cx.cost, 0xDC)?;
    match (type_id, method_id) {
        (12, 2) => coll::get_or_else(obj_val, args, cx),
        (12, 3) => coll::map(obj_val, args, cx),
        (12, 10) => coll::apply(obj_val, args, cx),
        (12, 26) => coll::index_of(obj_val, args, cx),
        (12, 29) => coll::zip(obj_val, args, cx),
        (12, 31) | (12, 32) => coll::starts_ends_with(method_id, obj_val, args, cx),
        (12, 33) => coll::get(obj_val, args, cx),
        (106, 6) => global::encode_nbits(args, cx),
        (106, 7) => global::decode_nbits(args, cx),
        (106, 9) => global::some(args, cx),
        (106, 8) => global::pow_hit(args, cx),
        (2..=6, 9) | (2..=6, 10) | (2..=6, 11) => numeric::bitwise(method_id, obj_val, args, cx),
        (2..=6, 12) | (2..=6, 13) => numeric::shift(method_id, obj_val, args, cx),
        (99, 7) => misc::get_reg_v5(args, cx),
        (99, 19) => misc::get_reg(obj_val, args, type_args, cx),
        (101, 12) => misc::get_var_from_input(args, type_args, cx),
        (106, 4) => global::deserialize_to(args, type_args, cx),
        (106, 5) => global::from_big_endian_bytes(args, type_args, cx),
        (104, 16) => misc::check_pow(type_id, method_id, obj_val, args, cx),
        (106, 2) => global::xor(args, cx),
        (106, 3) => global::serialize(args, cx),
        (100, 9) => avl::contains(obj_val, args, cx),
        (100, 10) => avl::get(obj_val, args, cx),
        (100, 11) => avl::get_many(obj_val, args, cx),
        (100, 13) => avl::update(obj_val, args, cx),
        (100, 12) => avl::insert(obj_val, args, cx),
        (100, 16) => avl::insert_or_update(obj_val, args, cx),
        (100, 14) => avl::remove(obj_val, args, cx),
        (100, 15) => avl::update_digest(obj_val, args, cx),
        (100, 8) => avl::update_operations(obj_val, args, cx),
        (12, 15) => coll::flat_map(obj_val, args, cx),
        (12, 19) => coll::patch(obj_val, args, cx),
        (12, 20) => coll::updated(obj_val, args, cx),
        (12, 21) => coll::update_many(obj_val, args, cx),
        (36, 7) => option::map(obj_val, args, cx),
        (36, 8) => option::filter(obj_val, args, cx),
        (6, 15) => numeric::to_unsigned_mod(obj_val, args, cx),
        (9, 9) | (9, 10) | (9, 11) => unsigned_bigint::bitwise(method_id, obj_val, args, cx),
        (9, 12) => unsigned_bigint::shift_left(obj_val, args, cx),
        (9, 13) => unsigned_bigint::shift_right(obj_val, args, cx),
        (9, 14) => unsigned_bigint::mod_inverse(obj_val, args, cx),
        (9, 15) => unsigned_bigint::plus_mod(obj_val, args, cx),
        (9, 16) => unsigned_bigint::subtract_mod(obj_val, args, cx),
        (9, 17) => unsigned_bigint::multiply_mod(obj_val, args, cx),
        (9, 18) => unsigned_bigint::mod_op(obj_val, args, cx),
        (7, 3) => misc::exp_signed(obj_val, args, cx),
        (7, 6) => misc::exp(obj_val, args, cx),
        // Fall through to the shared no-arg method table for any
        // (type_id, method_id) the args-using arms above did not
        // claim. This dedupes the header / preheader / global / AVL
        // property logic that otherwise lives in two places. The table
        // is NO-arg only, so enforce arity here: a no-arg method invoked
        // with arguments is malformed and must error (preserving the
        // `check_arity(args, 0)` the moved bitwiseInverse / toUnsigned /
        // toSigned / reverse arms used to enforce — a 0xDC MethodCall
        // carrying extra args must not silently ignore them).
        _ => match super::property_call::eval_no_arg_method(
            type_id, method_id, &obj_val, cx.ctx, cx.cost,
        )? {
            // The shared table is NO-arg only: if it claims this method but the
            // 0xDC MethodCall carried arguments, the tree is malformed — error
            // on arity (preserving the `check_arity(args, 0)` the moved
            // bitwiseInverse / toUnsigned / toSigned / reverse arms enforced, so
            // extra args are never silently ignored). Methods the table does NOT
            // claim (e.g. SContext.getVar, which legitimately takes args) fall
            // through to the unsupported-MethodCall error regardless of arity.
            Some(_) if !args.is_empty() => Err(EvalError::ArityMismatch {
                expected: 0,
                got: args.len(),
            }),
            Some(v) => Ok(v),
            None => Err(EvalError::TypeError {
                expected: "supported MethodCall",
                got: format!("type_id={}, method_id={}", type_id, method_id),
            }),
        },
    }
}

/// Returns `true` if `(type_id, method_id)` is a Sigma 6.0 / EIP-50
/// method requiring `activatedScriptVersion >= 3`. Mirrors the Scala
/// `_v6Methods` declarations across `sigma/ast/methods.scala` —
/// specifically:
///
/// * `SNumericTypeMethods._v6Methods` (Byte=2, Short=3, Int=4, Long=5,
///   BigInt=6): bitwiseInverse(8), bitwiseOr(9), bitwiseAnd(10),
///   bitwiseXor(11), shiftLeft(12), shiftRight(13).
/// * `SBigIntMethods._v6Methods`: toUnsigned(14), toUnsignedMod(15).
/// * `SGroupElementMethods._v6Methods`: exp(6) with `UnsignedBigInt`
///   exponent (existing exp(5) with `BigInt` exponent stays v5).
/// * `SUnsignedBigIntMethods` (entire type, 9): inherited numeric
///   bitwiseInverse(8) through shiftRight(13), plus its own modular
///   modInverse(14) through toSigned(19).
/// * `SCollectionMethods._v6Methods`: reverse(30), startsWith(31),
///   endsWith(32), get(33). (No `distinct` exists in Scala v6.0.2.)
/// * `SBoxMethods._v6Methods`: getReg(19) (getRegMethodV5 id 7 is V5+).
/// * `SContextMethods._v6Methods`: getVarFromInput(12) only. getVar
///   (id 11) is V5+ (commonMethods), NOT v6-gated.
/// * `SHeaderMethods._v6Methods`: checkPow(16).
/// * `SGlobalMethods._v6Methods`: serialize(3), deserializeTo(4),
///   fromBigEndianBytes(5), encodeNbits(6), decodeNbits(7), powHit(8),
///   some(9), none(10).
///   (Global.xor(2) predates EIP-50 — V5+, not gated here.)
///
/// (12, 26)/(12, 29) `indexOf`/`updateMany`, (36, *) Option methods,
/// the V5+ SAvlTree methods (`contains` / `get` / `getMany` /
/// `insert` / `update` / `remove` / `updateDigest` etc.),
/// (101, 8) `selfBoxIndex`, and (106, 2) `Global.xor` are V5+ and
/// intentionally not listed. The only v6 addition to SAvlTree —
/// `insertOrUpdate` (100, 16) — IS listed below.
pub(super) fn is_v6_method(type_id: u8, method_id: u8) -> bool {
    match (type_id, method_id) {
        // SNumericType bitwise + shifts
        (2..=6, 8..=13) => true,
        // SBigInt â†’ unsigned conversions
        (6, 14) | (6, 15) => true,
        // SGroupElement.exp with UnsignedBigInt exponent
        (7, 6) => true,
        // SUnsignedBigInt: inherited numeric bitwise/shift (8..=13) +
        // its own modular arithmetic (14..=19). All v6 / EIP-50.
        (9, 8..=19) => true,
        // SCollection reverse/startsWith/endsWith/get
        (12, 30..=33) => true,
        // SBox.getReg v6 slot (getRegMethodV5 id 7 is V5+, ungated)
        (99, 19) => true,
        // SAvlTree.insertOrUpdate (v6 — methods.scala:1671-1686).
        // Pre-v6 SAvlTree methods stay non-gated (caller already
        // pre-v6 callable).
        (100, 16) => true,
        // SContext.getVarFromInput (v6-only). getVar (id 11) is V5+
        // (commonMethods), so it is NOT gated here.
        (101, 12) => true,
        // SHeader.checkPow
        (104, 16) => true,
        // SGlobal: serialize, deserializeTo, fromBigEndianBytes,
        // encodeNbits, decodeNbits, powHit(8), some(9), none(10).
        (106, 3..=10) => true,
        _ => false,
    }
}

pub(super) fn check_arity(args: &[Expr], expected: usize) -> Result<(), EvalError> {
    if args.len() != expected {
        return Err(EvalError::ArityMismatch {
            expected,
            got: args.len(),
        });
    }
    Ok(())
}

/// Prices charged by argument-taking method handlers and the shared no-arg table.
/// Methods lowered to opcodes and dynamic formulas are inventoried separately.
pub fn method_cost_rows() -> Vec<((u8, u8), &'static str, ergo_primitives::cost::CostKind)> {
    use ergo_primitives::cost::{CostKind, JitCost};
    let fixed = |value| CostKind::Fixed(JitCost::from_jit(value));
    let mut rows = super::property_call::no_arg_cost_rows();
    rows.extend([
        ((12, 26), "indexOf", coll::COST_INDEX_OF),
        ((12, 29), "zip", coll::COST_ZIP),
        ((12, 31), "startsWith", coll::COST_STARTS_ENDS_WITH),
        ((12, 32), "endsWith", coll::COST_STARTS_ENDS_WITH),
        ((12, 33), "get", fixed(coll::COST_GET)),
        ((12, 15), "flatMap", coll::COST_FLAT_MAP),
        ((12, 19), "patch", coll::COST_PATCH),
        ((12, 20), "updated", coll::COST_UPDATED),
        ((12, 21), "updateMany", coll::COST_UPDATE_MANY),
        ((106, 6), "encodeNbits", fixed(global::COST_ENCODE_NBITS)),
        ((106, 7), "decodeNbits", fixed(global::COST_DECODE_NBITS)),
        ((106, 9), "some", fixed(global::COST_SOME)),
        ((106, 4), "deserializeTo", global::COST_DESERIALIZE_TO),
        (
            (106, 5),
            "fromBigEndianBytes",
            fixed(global::COST_FROM_BIG_ENDIAN_BYTES),
        ),
        (
            (100, 8),
            "updateOperations",
            fixed(avl::COST_UPDATE_OPERATIONS),
        ),
        ((100, 15), "updateDigest", fixed(avl::COST_UPDATE_DIGEST)),
        ((36, 7), "map", fixed(option::COST_MAP)),
        ((36, 8), "filter", fixed(option::COST_FILTER)),
        (
            (6, 15),
            "toUnsignedMod",
            fixed(numeric::COST_TO_UNSIGNED_MOD),
        ),
        ((7, 3), "exp", fixed(misc::COST_EXP)),
        ((7, 6), "expUnsigned", fixed(misc::COST_EXP)),
        ((2, 9), "bitwiseOr", fixed(numeric::COST_BITWISE)),
        ((2, 10), "bitwiseAnd", fixed(numeric::COST_BITWISE)),
        ((2, 11), "bitwiseXor", fixed(numeric::COST_BITWISE)),
        ((2, 12), "shiftLeft", fixed(numeric::COST_SHIFT)),
        ((2, 13), "shiftRight", fixed(numeric::COST_SHIFT)),
        ((3, 9), "bitwiseOr", fixed(numeric::COST_BITWISE)),
        ((3, 10), "bitwiseAnd", fixed(numeric::COST_BITWISE)),
        ((3, 11), "bitwiseXor", fixed(numeric::COST_BITWISE)),
        ((3, 12), "shiftLeft", fixed(numeric::COST_SHIFT)),
        ((3, 13), "shiftRight", fixed(numeric::COST_SHIFT)),
        ((4, 9), "bitwiseOr", fixed(numeric::COST_BITWISE)),
        ((4, 10), "bitwiseAnd", fixed(numeric::COST_BITWISE)),
        ((4, 11), "bitwiseXor", fixed(numeric::COST_BITWISE)),
        ((4, 12), "shiftLeft", fixed(numeric::COST_SHIFT)),
        ((4, 13), "shiftRight", fixed(numeric::COST_SHIFT)),
        ((5, 9), "bitwiseOr", fixed(numeric::COST_BITWISE)),
        ((5, 10), "bitwiseAnd", fixed(numeric::COST_BITWISE)),
        ((5, 11), "bitwiseXor", fixed(numeric::COST_BITWISE)),
        ((5, 12), "shiftLeft", fixed(numeric::COST_SHIFT)),
        ((5, 13), "shiftRight", fixed(numeric::COST_SHIFT)),
        ((6, 9), "bitwiseOr", fixed(numeric::COST_BITWISE)),
        ((6, 10), "bitwiseAnd", fixed(numeric::COST_BITWISE)),
        ((6, 11), "bitwiseXor", fixed(numeric::COST_BITWISE)),
        ((6, 12), "shiftLeft", fixed(numeric::COST_SHIFT)),
        ((6, 13), "shiftRight", fixed(numeric::COST_SHIFT)),
        ((9, 9), "bitwiseOr", fixed(unsigned_bigint::COST_BITWISE)),
        ((9, 10), "bitwiseAnd", fixed(unsigned_bigint::COST_BITWISE)),
        ((9, 11), "bitwiseXor", fixed(unsigned_bigint::COST_BITWISE)),
        (
            (9, 12),
            "shiftLeft",
            fixed(unsigned_bigint::COST_SHIFT_LEFT),
        ),
        (
            (9, 13),
            "shiftRight",
            fixed(unsigned_bigint::COST_SHIFT_RIGHT),
        ),
        (
            (9, 14),
            "modInverse",
            fixed(unsigned_bigint::COST_MOD_INVERSE),
        ),
        ((9, 15), "plusMod", fixed(unsigned_bigint::COST_PLUS_MOD)),
        (
            (9, 16),
            "subtractMod",
            fixed(unsigned_bigint::COST_SUBTRACT_MOD),
        ),
        (
            (9, 17),
            "multiplyMod",
            fixed(unsigned_bigint::COST_MULTIPLY_MOD),
        ),
        ((9, 18), "mod", fixed(unsigned_bigint::COST_MOD_OP)),
    ]);
    // These handlers charge through the same opcode declarations.
    for (ids, name, opcode) in [
        ((99, 7), "getRegV5", 0xC6),
        ((99, 19), "getReg", 0xC6),
        ((101, 12), "getVarFromInput", 0xE3),
        ((106, 2), "xor", 0x9B),
    ] {
        if let Ok(cost) = crate::cost_table::opcode_cost(opcode) {
            rows.push((ids, name, cost));
        }
    }
    rows
}

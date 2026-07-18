//! Small receiver-type `0xDC MethodCall` arms that do not warrant their own
//! file: SBox(99).getRegV5(7)/getReg(19), SContext(101).getVarFromInput(12),
//! SHeader(104).checkPow(16), and SGroupElement(7).exp(6).

use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;

use super::check_arity;
use crate::evaluator::cost::{add_cost, add_method_cost};
use crate::evaluator::eval_ctx::EvalCtx;
use crate::evaluator::types::{EvalError, Value};

// SBox(99).getRegV5 (id 7; regId: Int) — deserializable at all
// versions (it sits in `SBoxMethods.commonBoxMethods`), but live
// evaluation ALWAYS throws in Scala v6.0.x: the descriptor is
// named "getRegV5" and carries no `javaMethodOf`/reflection
// registration, so `SMethod.javaMethod` falls back to
// `Box.getMethod("getRegV5", Int)` → NoSuchMethodException.
// A dead-branch occurrence parses and reduces fine; only an
// evaluated call errors. Scala `MethodCall.eval` evaluates the
// args before the invoke, so arg-eval errors fire first, and
// `addFixedCost` charges the method's `ExtractRegisterAs`
// costKind BEFORE running the invoke block
// (CErgoTreeEvaluator.addFixedCost: coster.add, then block) —
// the charge lands even though the reflective lookup throws.
pub(super) fn get_reg_v5(args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let _ = cx.eval_expr(&args[0])?;
    add_cost(cx.cost, 0xC6)?;
    Err(EvalError::RuntimeException(
        "SBox.getRegV5 (99, 7) has no runtime implementation \
                 (Scala NoSuchMethodException on Box.getRegV5)",
    ))
}

// SBox(99).getReg (v6 id 19; regId: Int) -> Option[T]
// EIP-50 v6 variant of the inline `0xC6 ExtractRegisterAs`,
// with a DYNAMIC index: `SFunc(Array(SBox, SInt), SOption(tT))`
// — the index is an Int expression, and Scala `CBox.getReg`
// returns None when `i < 0 || i >= 10` (out-of-range is NOT an
// error on this path, unlike the inline form whose register id
// is validated at the wire). The explicit `[T]` arrives in
// `type_args[0]` (hasExplicitTypeArgs) and is enforced by
// `read_register_option` per Scala's typeSubst resolution into
// `CBox.getReg(i)(tT)`.
//
// Version gate: id 19 exists only in `SBoxMethods.v6Methods`,
// selected by `isV3OrLaterErgoTreeVersion` — the TREE version,
// not the activated version. Scala rejects a pre-v3 tree at
// spend-time DESERIALIZATION (`SMethod.fromIds` →
// `getMethodById` → CheckAndGetMethod ValidationException);
// our wire layer must stay version-independent because real
// 6.x-compiled trees carry v6 method calls under v0 headers
// and outputs paying to them must decode (oracle-confirmed),
// so the reject lands here on the evaluation path.
// KNOWN RESIDUAL (pre-existing): a DEAD-BRANCH (99, 19) in a
// pre-v3 tree evaluates past this gate while Scala fails the
// whole tree at parse — needs a spend-path AST pre-walk.
pub(super) fn get_reg(
    obj_val: Value,
    args: &[Expr],
    type_args: &[SigmaType],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    if !cx.ctx.is_v3_ergo_tree() {
        return Err(EvalError::TypeError {
            expected: "ErgoTree version >= 3 for SBox.getReg (99, 19) \
                               (Scala v6Methods is keyed on isV3OrLaterErgoTreeVersion)",
            got: format!("ergoTreeVersion={}", cx.ctx.ergo_tree_version),
        });
    }
    check_arity(args, 1)?;
    let idx_val = cx.eval_expr(&args[0])?;
    let idx = match idx_val {
        Value::Int(i) => i,
        other => {
            return Err(EvalError::TypeError {
                expected: "Int register index for SBox.getReg",
                got: format!("{other:?}"),
            })
        }
    };
    // Cost mirrors the inline `0xC6 ExtractRegisterAs`
    // dispatch (`add_cost(cx.cost, 0xC6)`) — Scala charges the
    // method's `ExtractRegisterAs.costKind` around the invoke,
    // so the None returns inside `CBox.getReg` cost the same.
    add_cost(cx.cost, 0xC6)?;
    let b = crate::evaluator::helpers::resolve_box(&obj_val, cx.ctx)?;
    if !(0..=9).contains(&idx) {
        return Ok(Value::Opt(None));
    }
    crate::evaluator::opcodes::box_context::read_register_option(
        b,
        idx as u8,
        0xDC,
        type_args.first(),
        cx.ctx,
    )
}

// SContext.getVar (101, 11) is intentionally NOT handled here:
// it falls through to the catch-all "unsupported MethodCall"
// reject, matching v6.0.2. `getVarV5Method` (id 11) is V5+
// (commonMethods) but has NO `.withIRInfo`, so the Scala compiler
// never lowers `CONTEXT.getVar[T](id)` to a MethodCall; it always
// emits the inline `0xE3 GetVar` node, which carries T on the
// wire. A hand-crafted (101, 11) MethodCall has no way to recover
// T (no explicit type-arg byte; `tT` stays abstract after
// `specializeFor`), and Scala throws on both eval paths
// (NoSuchMethodException in the AST interpreter, `throwError` in
// GraphBuilding) rather than returning None. So rejecting it is
// the consensus-correct behaviour. (getVarFromInput (101, 12) IS
// a real v6 MethodCall and is handled just below.)
// SContext(101).getVarFromInput(12, inputIndex: Short, varId: Byte)[T] -> Option[T]
// EIP-50 v6 method, new in 6.0 (no v5 inline twin). Reads
// `tx.inputs(inputIndex).extension.getVar[T](varId)` —
// same exact-type-match rule as `0xE3 GetVar`, just on a
// different input than SELF. `hasExplicitTypeArgs =
// Seq(tT)` per Scala source. Returns `None` when the
// input index is out of range, the var id is missing, or
// the stored type doesn't match `[T]`.
pub(super) fn get_var_from_input(
    args: &[Expr],
    type_args: &[SigmaType],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 2)?;
    let idx_val = cx.eval_expr(&args[0])?;
    let input_idx = match idx_val {
        Value::Short(n) => n,
        other => {
            return Err(EvalError::TypeError {
                expected: "Short for SContext.getVarFromInput input index",
                got: format!("{other:?}"),
            })
        }
    };
    let var_val = cx.eval_expr(&args[1])?;
    let var_id = match var_val {
        Value::Byte(b) => b as u8,
        other => {
            return Err(EvalError::TypeError {
                expected: "Byte for SContext.getVarFromInput var id",
                got: format!("{other:?}"),
            })
        }
    };
    let tpe = type_args
        .first()
        .cloned()
        .unwrap_or(ergo_ser::sigma_type::SigmaType::SAny);
    // Cost: identical evaluator work to `0xE3 GetVar`,
    // charge through the same row.
    crate::evaluator::cost::add_cost(cx.cost, 0xE3)?;
    // Out-of-range input index â†’ None (Scala silently
    // returns None rather than throwing).
    if input_idx < 0 {
        return Ok(Value::Opt(None));
    }
    let idx = input_idx as usize;
    let Some(ext) = cx.ctx.input_extensions.get(idx) else {
        return Ok(Value::Opt(None));
    };
    match ext.get(&var_id) {
        Some((ext_tpe, ext_val)) if *ext_tpe == tpe => {
            let val =
                crate::evaluator::helpers::sigma_to_value_versioned(ext_tpe, ext_val, cx.ctx)?;
            Ok(Value::Opt(Some(Box::new(val))))
        }
        _ => Ok(Value::Opt(None)),
    }
}

// SHeader(104).checkPow(16): zero-arg, normally emitted as a 0xDB
// PropertyCall and handled by the shared `eval_no_arg_method` table.
// A 0xDC MethodCall form must reject extra args on ARITY *before* the
// table runs the expensive Autolykos PoW (the catch-all checks arity
// only after the handler returns). Guard arity, then delegate to the
// same handler so the cost/value stay identical to the 0xDB path.
pub(super) fn check_pow(
    type_id: u8,
    method_id: u8,
    obj_val: Value,
    args: &[Expr],
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    check_arity(args, 0)?;
    match crate::evaluator::opcodes::property_call::eval_no_arg_method(
        type_id, method_id, &obj_val, cx.ctx, cx.cost,
    )? {
        Some(v) => Ok(v),
        None => Err(EvalError::TypeError {
            expected: "supported MethodCall",
            got: format!("type_id={type_id}, method_id={method_id}"),
        }),
    }
}

// SUnsignedBigInt.toSigned (9, 19) is a zero-arg method handled by the
// shared `eval_no_arg_method` table (reachable via 0xDB PropertyCall).
// SGroupElement(7).exp(6, e: UnsignedBigInt) -> GroupElement
// Scala `SGroupElementMethods.ExponentiateUnsignedMethod`
// (EIP-50 / v6Methods, confirmed by disassembly of
// `sigma/ast/SGroupElementMethods$.class` — method id 6).
// Semantics: same EC scalar multiplication as the inline
// 0x9F `Exponentiate` opcode, but the exponent carrier is
// `SUnsignedBigInt` rather than `SBigInt`. Because the
// unsigned value is already in [0, 2^256), the signed
// Euclidean correction needed in 0x9F is unnecessary —
// `Scalar::reduce` over the 256-bit big-endian magnitude
// is the canonical reduction mod the secp256k1 group order.
// Cost matches `Exponentiate.costKind` = `FixedCost(900)`.
pub(super) fn exp(obj_val: Value, args: &[Expr], cx: &mut EvalCtx<'_>) -> Result<Value, EvalError> {
    check_arity(args, 1)?;
    let ge_bytes = match &obj_val {
        Value::GroupElement(b) => *b,
        other => {
            return Err(EvalError::TypeError {
                expected: "GroupElement for SGroupElement.exp(unsigned)",
                got: format!("{other:?}"),
            })
        }
    };
    let exp_val = cx.eval_expr(&args[0])?;
    let exp = match exp_val {
        Value::UnsignedBigInt(n) => n,
        other => {
            return Err(EvalError::TypeError {
                expected: "UnsignedBigInt for SGroupElement.exp(unsigned) exponent",
                got: format!("{other:?}"),
            })
        }
    };
    add_method_cost(cx.cost, 900)?;

    use k256::elliptic_curve::group::GroupEncoding;
    use k256::elliptic_curve::ops::Reduce;
    use k256::Scalar;

    let point = crate::evaluator::opcodes::sigma::decode_group_element(&ge_bytes)?;
    let (_, exp_bytes) = exp.to_bytes_be();
    let mut scalar_bytes = [0u8; 32];
    let take = exp_bytes.len().min(32);
    scalar_bytes[32 - take..].copy_from_slice(&exp_bytes[exp_bytes.len() - take..]);
    let wide = k256::U256::from_be_slice(&scalar_bytes);
    let scalar = Scalar::reduce(wide);
    let result = point * scalar;
    let result_bytes = result.to_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(&result_bytes);
    Ok(Value::GroupElement(out))
}

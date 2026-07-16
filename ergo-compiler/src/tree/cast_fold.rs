use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;

use crate::emit::EmitError;

/// Numeric widths participating in the compile-time constant fold (the
/// signed ladder only — BigInt arithmetic is NOT compile-folded by Scala,
/// oracle control `cc sigmaProp(bigInt(2^254) + bigInt(2^254) > 0)` → OK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FoldWidth {
    Byte,
    Short,
    Int,
    Long,
}

fn fold_width(t: &SigmaType) -> Option<FoldWidth> {
    match t {
        SigmaType::SByte => Some(FoldWidth::Byte),
        SigmaType::SShort => Some(FoldWidth::Short),
        SigmaType::SInt => Some(FoldWidth::Int),
        SigmaType::SLong => Some(FoldWidth::Long),
        _ => None,
    }
}

pub(crate) fn in_fold_range(w: FoldWidth, v: i64) -> bool {
    match w {
        FoldWidth::Byte => i8::try_from(v).is_ok(),
        FoldWidth::Short => i16::try_from(v).is_ok(),
        FoldWidth::Int => i32::try_from(v).is_ok(),
        FoldWidth::Long => true,
    }
}

/// Explicit-cast folds, BOTH directions (recon-transforms.md §7).
///
/// Scala's `buildNode`/`eval` intercepts `Upcast(Constant(v,_), toTpe)` /
/// `Downcast(Constant(v,_), toTpe)` (`GraphBuilding.scala:514-518`) as a
/// STRUCTURAL, non-recursive pattern match against the untouched AST: it
/// fires only when the cast's immediate argument, as it was ORIGINALLY
/// built (before any lowering — ours or Scala's), is itself a bare
/// `Constant` node. This walk mirrors that exactly:
///
/// - **fold** (direction (a)): a `Downcast`/`Upcast` whose immediate child
///   IS `Expr::Const` folds to the cast target's `Const` — range-checked
///   exactly like Scala's `toByteExact`/`toShortExact`/`toIntExact`
///   (`300.toByte` REJECTs, `ArithmeticException`); Upcast never overflows
///   (widening only). A chain of unfolded casts still reaching this pass
///   (e.g. from the chaincash corpus) needs [`crate::fold`]'s generic
///   const-fold for the surrounding `Eq`/bitwise.
/// - **do NOT fold** (direction (b) — the cascade a naive bottom-up
///   implementation of this SAME pass would introduce; pinned by the
///   `mod tests` regression pair
///   `compile_cast_chain_keeps_only_innermost_fold_matching_oracle_probe_34`
///   / `compile_cast_chain_depth_three_nested_under_gt_keeps_all_outer_casts`):
///   when the child is anything else — critically, ANOTHER
///   `Downcast`/`Upcast` node. A literal cast CHAIN (`1.toByte.toLong
///   .toBigInt`) builds `Upcast(Upcast(Downcast(Const(1),Byte),Long),BigInt)`
///   at emit time (`ergo-compiler/src/emit.rs`'s Select-cast arm wraps
///   whatever `self.emit(obj)` returns, one opcode per source `.castMethod`,
///   with NO fold). Recursing into that non-constant child (to give the
///   innermost `Downcast` its OWN, independent fold decision) and then
///   REBUILDING the same outer node — never re-checking whether the
///   now-lowered child happens to have become a `Const` — is what keeps
///   this non-cascading: only the cast immediately adjacent to the literal
///   folds, matching the oracle capture (`d1917e7e730005067301`: TWO real
///   `Upcast` nodes over the folded Byte constant, not one folded `BigInt`
///   constant). A naive bottom-up "recurse first, then check if the
///   (now-lowered) child is `Const`" traversal would cascade-fold the whole
///   chain — this is the exact bug class this function must NOT
///   reintroduce.
///
/// **Pass position:** runs immediately BEFORE [`crate::fold::fold`] (the
/// generic constant fold, whose overflow-reject arm this pass's retired D-C5
/// twin folded into) and BEFORE that pass's `SizeOf`-literal fold / the
/// v0-data gate / [`crate::lower::lower`]. Both orderings are load-bearing,
/// not incidental:
/// - **before the arithmetic fold:** a direct-constant `Upcast` (e.g. the
///   typer's mixed-width widening in `9223372036854775807L + 1` — the Int
///   `1` upcasts to `Long`) must already be a plain `Const` by the time the
///   arithmetic fold inspects it, or its `Expr::Const` fast path never sees a
///   value to propagate into the enclosing `+`/`-`/`*`/`min`/`max`, silently
///   losing the overflow detection. Symmetrically, [`crate::fold::fold`] never
///   folds a `NumericCast` node itself — so a cast whose child only BECOMES a
///   `Const` via a later arith fold (`ccs (x*100).toByte`) stays unfolded,
///   exactly like the oracle.
/// - **before the `SizeOf` fold:** `sigmaProp(Coll[UnsignedBigInt]()
///   .size.toLong == SELF.value)` is an oracle-pinned regression
///   (`compile_sizeof_coll_literal_folds_to_clean_v0_bytes`, tree_hex
///   `10010400d1937e730005c1a7`) whose `.toLong` wraps a `SizeOf` that is
///   STILL an unevaluated `Op` node at THIS pass's position — so this walk
///   correctly leaves the `Upcast` unfolded, exactly like the oracle (Scala's
///   `.size` fold is a separate, later rewrite that never retroactively
///   un-wraps an already-built enclosing `Upcast`). Running this cast fold any
///   later — after [`crate::fold::fold`] has already turned that `SizeOf` into
///   `Const(0)` — would see an apparently-direct constant and WRONGLY fold the
///   `Upcast`, regressing that pin.
pub(crate) fn fold_direct_const_casts(e: Expr) -> Result<Expr, EmitError> {
    match e {
        Expr::Op(IrNode {
            opcode: opcode @ (0x7D | 0x7E),
            payload: Payload::NumericCast { input, tpe },
        }) => {
            if let Expr::Const { tpe: src_tpe, val } = input.as_ref() {
                if let Some(folded) = fold_numeric_cast(opcode, src_tpe, val, &tpe)? {
                    return Ok(folded);
                }
            }
            // Not a direct constant: give the child its OWN independent
            // fold decision, then rebuild THIS node around the (possibly
            // rewritten) result — never re-examining whether that result
            // is now `Const` (the anti-cascade discipline the fn docs
            // describe).
            let input = fold_direct_const_casts(*input)?;
            Ok(Expr::Op(IrNode {
                opcode,
                payload: Payload::NumericCast {
                    input: Box::new(input),
                    tpe,
                },
            }))
        }
        Expr::Op(IrNode { opcode, payload }) => Ok(Expr::Op(IrNode {
            opcode,
            payload: fold_direct_const_casts_children(payload)?,
        })),
        other => Ok(other),
    }
}

/// By-value, fallible child map for [`fold_direct_const_casts`] — the
/// exhaustive twin of [`push_children`]/[`crate::fold`]'s private
/// `fold_children` (a new child-carrying `Payload` variant fails to compile
/// here until it is mapped). Kept separate from `crate::lower`'s own
/// (infallible) child map: this pass runs at a different, earlier pipeline
/// position (see the fn docs) and must reject on downcast overflow, so it
/// cannot share that traversal.
fn fold_direct_const_casts_children(payload: Payload) -> Result<Payload, EmitError> {
    let f = |b: Box<Expr>| -> Result<Box<Expr>, EmitError> {
        Ok(Box::new(fold_direct_const_casts(*b)?))
    };
    let fv = |items: Vec<Expr>| -> Result<Vec<Expr>, EmitError> {
        items.into_iter().map(fold_direct_const_casts).collect()
    };
    Ok(match payload {
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => payload,
        Payload::One(a) => Payload::One(f(a)?),
        Payload::NumericCast { input, tpe } => Payload::NumericCast {
            input: f(input)?,
            tpe,
        },
        Payload::Two(a, b) => Payload::Two(f(a)?, f(b)?),
        Payload::Three(a, b, c) => Payload::Three(f(a)?, f(b)?, f(c)?),
        Payload::Four(a, b, c, d) => Payload::Four(f(a)?, f(b)?, f(c)?, f(d)?),
        Payload::ValDef { id, tpe, rhs } => Payload::ValDef {
            id,
            tpe,
            rhs: f(rhs)?,
        },
        Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs,
        } => Payload::FunDef {
            id,
            tpe,
            tpe_args,
            rhs: f(rhs)?,
        },
        Payload::BlockValue { items, result } => Payload::BlockValue {
            items: fv(items)?,
            result: f(result)?,
        },
        Payload::FuncValue { args, body } => Payload::FuncValue {
            args,
            body: f(body)?,
        },
        Payload::MethodCall {
            type_id,
            method_id,
            obj,
            args,
            type_args,
        } => Payload::MethodCall {
            type_id,
            method_id,
            obj: f(obj)?,
            args: fv(args)?,
            type_args,
        },
        Payload::ConcreteCollection { elem_type, items } => Payload::ConcreteCollection {
            elem_type,
            items: fv(items)?,
        },
        Payload::Tuple { items } => Payload::Tuple { items: fv(items)? },
        Payload::SigmaCollection { items } => Payload::SigmaCollection { items: fv(items)? },
        Payload::SelectField { input, field_idx } => Payload::SelectField {
            input: f(input)?,
            field_idx,
        },
        Payload::ExtractRegisterAs { input, reg_id, tpe } => Payload::ExtractRegisterAs {
            input: f(input)?,
            reg_id,
            tpe,
        },
        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => Payload::DeserializeRegister {
            reg_id,
            tpe,
            default: default.map(f).transpose()?,
        },
        Payload::ByIndex {
            input,
            index,
            default,
        } => Payload::ByIndex {
            input: f(input)?,
            index: f(index)?,
            default: default.map(f).transpose()?,
        },
        Payload::FuncApply { func, args } => Payload::FuncApply {
            func: f(func)?,
            args: fv(args)?,
        },
    })
}

/// Fold a DIRECT-constant `Downcast` (`opcode == 0x7D`, range-checked, exact
/// Scala `toByteExact`/`toShortExact`/`toIntExact`/`BigInt.toXExact`
/// semantics) or `Upcast` (`opcode == 0x7E`, never overflows — widening
/// only) to a plain `Expr::Const`. `Ok(None)` when `(src_tpe, target)` is not
/// one of the five numeric types' (Byte/Short/Int/Long/BigInt) valid
/// cast pairs — defensive: emit only ever builds `NumericCast` nodes over
/// this ladder (`ergo-compiler/src/emit.rs` `emit_select`'s cast arm), so
/// every REAL invocation matches; an unrecognized pair just stays unfolded
/// rather than mis-handling an unexpected shape.
fn fold_numeric_cast(
    opcode: u8,
    src_tpe: &SigmaType,
    val: &SigmaValue,
    target: &SigmaType,
) -> Result<Option<Expr>, EmitError> {
    let overflow = |what: String| EmitError::GraphBuildingReject {
        class: "ArithmeticException",
        what,
    };
    match (src_tpe, val) {
        (SigmaType::SByte | SigmaType::SShort | SigmaType::SInt | SigmaType::SLong, _) => {
            let v: i64 = match val {
                SigmaValue::Byte(n) => i64::from(*n),
                SigmaValue::Short(n) => i64::from(*n),
                SigmaValue::Int(n) => i64::from(*n),
                SigmaValue::Long(n) => *n,
                _ => return Ok(None),
            };
            fold_i64_cast(opcode, v, target, overflow)
        }
        (SigmaType::SBigInt, SigmaValue::BigInt(n)) => {
            fold_bigint_cast(opcode, n, target, overflow)
        }
        _ => Ok(None),
    }
}

/// The Byte/Short/Int/Long half of [`fold_numeric_cast`] — `v` is exact for
/// every source width (i64 losslessly carries all four). Upcast targets
/// among these four are always in range by construction (the source is
/// strictly narrower — that is what made `opcode == 0x7E` in the first
/// place); Downcast is range-checked via [`in_fold_range`]/[`fold_width`],
/// the SAME width ladder [`crate::fold`]'s arithmetic fold uses.
fn fold_i64_cast(
    opcode: u8,
    v: i64,
    target: &SigmaType,
    overflow: impl Fn(String) -> EmitError,
) -> Result<Option<Expr>, EmitError> {
    let width = match fold_width(target) {
        Some(w) => w,
        // Long -> BigInt upcast: BigInt has no `FoldWidth` member (it is
        // unbounded), handled directly here rather than through the shared
        // width table.
        None if matches!(target, SigmaType::SBigInt) => {
            return Ok(Some(Expr::Const {
                tpe: SigmaType::SBigInt,
                val: SigmaValue::BigInt(num_bigint::BigInt::from(v)),
            }));
        }
        None => return Ok(None),
    };
    if opcode == 0x7D && !in_fold_range(width, v) {
        return Err(overflow(format!(
            "compile-time constant downcast out of {width:?} range: {v}"
        )));
    }
    Ok(Some(match width {
        FoldWidth::Byte => Expr::Const {
            tpe: SigmaType::SByte,
            // In range by the check above (Downcast) or by construction
            // (Upcast never targets a narrower width).
            val: SigmaValue::Byte(v as i8),
        },
        FoldWidth::Short => Expr::Const {
            tpe: SigmaType::SShort,
            val: SigmaValue::Short(v as i16),
        },
        FoldWidth::Int => Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(v as i32),
        },
        FoldWidth::Long => Expr::Const {
            tpe: SigmaType::SLong,
            val: SigmaValue::Long(v),
        },
    }))
}

/// The `SBigInt`-source half of [`fold_numeric_cast`] — only reachable as a
/// `Downcast` (BigInt is the top of this 5-type ladder, so an `Upcast` FROM
/// BigInt would only ever be a same-type identity, which `emit.rs`'s
/// same-type arm already unwraps to the bare input before a `NumericCast`
/// node is ever built — defensive `Ok(None)` if ever reached). Range-checked
/// via `num_bigint`'s own `TryFrom<&BigInt>` impls, mirroring
/// `ergo-sigma/src/evaluator/opcodes/cast.rs::eval_downcast`'s BigInt arm
/// exactly (same overflow semantics, compile-time instead of eval-time).
fn fold_bigint_cast(
    opcode: u8,
    n: &num_bigint::BigInt,
    target: &SigmaType,
    overflow: impl Fn(String) -> EmitError,
) -> Result<Option<Expr>, EmitError> {
    if opcode != 0x7D {
        return Ok(None);
    }
    Ok(Some(match target {
        SigmaType::SByte => Expr::Const {
            tpe: SigmaType::SByte,
            val: SigmaValue::Byte(i8::try_from(n).map_err(|_| {
                overflow(format!(
                    "compile-time constant downcast out of Byte range: {n}"
                ))
            })?),
        },
        SigmaType::SShort => Expr::Const {
            tpe: SigmaType::SShort,
            val: SigmaValue::Short(i16::try_from(n).map_err(|_| {
                overflow(format!(
                    "compile-time constant downcast out of Short range: {n}"
                ))
            })?),
        },
        SigmaType::SInt => Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(i32::try_from(n).map_err(|_| {
                overflow(format!(
                    "compile-time constant downcast out of Int range: {n}"
                ))
            })?),
        },
        SigmaType::SLong => Expr::Const {
            tpe: SigmaType::SLong,
            val: SigmaValue::Long(i64::try_from(n).map_err(|_| {
                overflow(format!(
                    "compile-time constant downcast out of Long range: {n}"
                ))
            })?),
        },
        _ => return Ok(None),
    }))
}

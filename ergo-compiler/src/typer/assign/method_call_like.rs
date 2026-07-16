use ergo_crypto::group_element::{decompress_to_affine_hex, strip_leading_zero_hex};

use crate::stype::SType;
use crate::typed::{
    node_tpe, ConstPayload, MethodRef, TypedExpr, ARITH_MULTIPLY, ARITH_PLUS, BIT_SHIFT_LEFT,
    BIT_SHIFT_RIGHT, BIT_SHIFT_RIGHT_ZEROED, BIT_XOR,
};
use crate::typer::methods::{get_method, SMethodDesc};
use crate::typer::unify::{apply_subst_func, arith_op, is_numeric, unify_type_lists, TypeSubst};
use crate::typer::{TypeEnv, TyperCtx};

use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// §1.11 MethodCallLike receiver dispatch (SigmaTyper.scala:302-421)
// ─────────────────────────────────────────────────────────────────────────────

/// `MethodCallLike(obj, m, args)` — SigmaTyper.scala:302-421.
///
/// Operator resolution keyed on the receiver's assigned type.  A `MethodCallLike`
/// is **always eliminated**: rewritten to a dedicated op / `MethodCall`, or an
/// error is thrown.  The only `m` values reaching here are the infix
/// `parseAsMethods` set (`* ++ || && + ^ << >> >>>`, SigmaParser.scala:71) and the
/// postfix-ident form `obj name` (Exprs.scala:113, `args = []`).
pub(crate) fn assign_method_call_like(
    env: &TypeEnv,
    obj: TypedExpr,
    name: String,
    args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    // newObj = assignType(env, obj); newArgs = args.map(assignType) (:303-304).
    let new_obj = assign_type(env, obj, ctx)?;
    let new_args = type_all(env, args, ctx)?;
    let recv = node_tpe(&new_obj).clone();
    match &recv {
        // SCollectionType[a] (:306-337).
        SType::SColl(_) => mcl_collection(new_obj, recv, &name, new_args, ctx),
        // SGroupElement (:338-346).
        SType::SGroupElement => mcl_group_element(new_obj, &name, new_args),
        // SSigmaProp (:364-387).
        SType::SSigmaProp => mcl_sigma_prop(new_obj, &name, new_args),
        // SBoolean (:388-408).
        SType::SBoolean => mcl_boolean(new_obj, &name, new_args),
        // SString (:409-418).
        SType::SString => mcl_string(new_obj, &name, new_args),
        // SNumericType (:347-362) — SByte/SShort/SInt/SLong/SBigInt/SUnsignedBigInt.
        t if is_numeric(t) => mcl_numeric(env, ctx, new_obj, &name, new_args),
        // else (:419-420) — a valid operator on an unsupported receiver.
        t => Err(TyperError::typer(format!(
            "Invalid operation MethodCallLike({name}) on type {t:?}"
        ))),
    }
}

/// Receiver `SCollectionType[a]` (SigmaTyper.scala:306-337).
pub(crate) fn mcl_collection(
    new_obj: TypedExpr,
    recv: SType,
    name: &str,
    new_args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    // ("++", Seq(r)): exact-type Append (:307-311).
    if name == "++" && new_args.len() == 1 {
        let mut it = new_args.into_iter();
        let r = it.next().unwrap();
        if *node_tpe(&r) == recv {
            return Ok(TypedExpr::Append {
                input: Box::new(new_obj),
                col2: Box::new(r),
                tpe: recv,
            });
        }
        return Err(TyperError::typer(format!(
            "Invalid argument type for {name}, expected {recv:?} but was {:?}",
            node_tpe(&r)
        )));
    }
    // (SCollectionMethods(method), _): resolve a collection method by name (:312-333).
    // Reachable in practice only via the postfix-ident form (`xs size`) — no infix
    // operator symbol is a collection-method name.
    match get_method(&recv, name, ctx.tree_version) {
        Some(method) => {
            // method.stype is the FULL SFunc (dom[0] = receiver); actualTypes prepends
            // the receiver's concrete type (:315-316).
            let new_arg_types: Vec<SType> = new_args.iter().map(|a| node_tpe(a).clone()).collect();
            let mut actual_types = Vec::with_capacity(1 + new_arg_types.len());
            actual_types.push(recv.clone());
            actual_types.extend(new_arg_types.iter().cloned());
            match unify_type_lists(&method.stype.dom, &actual_types) {
                Some(subst) => {
                    // concrFunTpe = applySubst(sfunc, subst); post-subst arg-type
                    // EQUALITY check on the tail (:319-323).
                    let concr = apply_subst_func(&method.stype, &subst);
                    if new_arg_types.as_slice() != concr.dom_tail() {
                        return Err(TyperError::typer(format!(
                            "Invalid method {name} argument type: expected {:?}; actual: {new_arg_types:?}",
                            concr.dom_tail()
                        )));
                    }
                    // irBuilder(lowerMethodCalls).lift(...).getOrElse(mkMethodCall(subst))
                    // (:330-333).  lowerMethodCalls is always true in our typer.  The
                    // custom lowerings (map/filter/…) ignore the subst; a surviving
                    // MethodCall (MethodCallIrBuilder or no irBuilder) carries it.
                    let lowered = lower_method(
                        &recv,
                        name,
                        new_obj,
                        new_args,
                        concr.range.clone(),
                        ctx.tree_version,
                    );
                    Ok(thread_method_subst(lowered, &subst))
                }
                // None: unification failed (:325-326).
                None => Err(TyperError::typer(format!(
                    "Invalid argument type of method call MethodCallLike({name}): expected {:?}; actual: {actual_types:?}",
                    method.stype.dom
                ))),
            }
        }
        // else: unknown symbol (:335-336).
        None => Err(TyperError::non_applicable(format!(
            "Unknown symbol {name}, which is used as operation with arguments on {recv:?}"
        ))),
    }
}

/// Receiver `SGroupElement` (SigmaTyper.scala:338-346).
pub(crate) fn mcl_group_element(
    new_obj: TypedExpr,
    name: &str,
    new_args: Vec<TypedExpr>,
) -> Result<TypedExpr, TyperError> {
    // ("*", Seq(r)): GroupElement-only MultiplyGroup (:339-343).
    if name == "*" && new_args.len() == 1 {
        let mut it = new_args.into_iter();
        let r = it.next().unwrap();
        if *node_tpe(&r) == SType::SGroupElement {
            return Ok(TypedExpr::MultiplyGroup {
                left: Box::new(new_obj),
                right: Box::new(r),
                tpe: SType::SGroupElement,
            });
        }
        return Err(TyperError::typer(format!(
            "Invalid argument type for {name}, expected GroupElement but was {:?}",
            node_tpe(&r)
        )));
    }
    // else (:344-345).
    Err(TyperError::non_applicable(format!(
        "Unknown symbol {name}, which is used as (GroupElement) {name} (args)"
    )))
}

/// Receiver `SNumericType` (SigmaTyper.scala:347-362).
pub(crate) fn mcl_numeric(
    env: &TypeEnv,
    ctx: &TyperCtx,
    new_obj: TypedExpr,
    name: &str,
    new_args: Vec<TypedExpr>,
) -> Result<TypedExpr, TyperError> {
    // ("+"|"*"|"^"|">>"|"<<"|">>>", Seq(r)) (:348).  `-`/`/`/`%` never arrive here
    // (the parser emits ArithOp for those); `|`/`&` emit BitOp directly.
    let is_num_op = matches!(name, "+" | "*" | "^" | ">>" | "<<" | ">>>");
    if is_num_op && new_args.len() == 1 {
        let mut it = new_args.into_iter();
        let r = it.next().unwrap();
        // r.tpe: numeric → bimap; non-numeric → InvalidBinaryOperationParameters (:357-358).
        if !is_numeric(node_tpe(&r)) {
            return Err(TyperError::invalid_binary(format!(
                "Invalid argument type for {name}, expected {:?} but was {:?}",
                node_tpe(&new_obj),
                node_tpe(&r)
            )));
        }
        // Dispatch to the mk* node builder via bimap(env, op, l, r)(mk)(tT, tT) (:349-356).
        // `+`/`*` → mkPlus/mkMultiply (arithOp: upcast then ArithOp).
        // `^`/`>>`/`<<`/`>>>` → mkBitXor/mkBitShiftRight/Left/RightZeroed (BitOp direct,
        // NO upcast — SigmaBuilder.scala:636-646).
        let opcode = match name {
            "*" => ARITH_MULTIPLY,
            "+" => ARITH_PLUS,
            "^" => BIT_XOR,
            ">>" => BIT_SHIFT_RIGHT,
            "<<" => BIT_SHIFT_LEFT,
            ">>>" => BIT_SHIFT_RIGHT_ZEROED,
            _ => unreachable!("guarded by is_num_op"),
        };
        let is_arith = matches!(name, "+" | "*");
        return bimap(
            env,
            ctx,
            name,
            new_obj,
            r,
            move |l, r| {
                if is_arith {
                    let (l, r) = arith_op(l, r)?;
                    let tpe = node_tpe(&l).clone();
                    Ok(TypedExpr::ArithOp {
                        left: Box::new(l),
                        right: Box::new(r),
                        opcode,
                        tpe,
                    })
                } else {
                    let tpe = node_tpe(&l).clone();
                    Ok(TypedExpr::BitOp {
                        left: Box::new(l),
                        right: Box::new(r),
                        opcode,
                        tpe,
                    })
                }
            },
            tt(),
            tt(),
        );
    }
    // else (:360-361).
    Err(TyperError::non_applicable(format!(
        "Unknown symbol {name}, which is used as ({:?}) {name} (args)",
        node_tpe(&new_obj)
    )))
}

/// Receiver `SSigmaProp` (SigmaTyper.scala:364-387).
pub(crate) fn mcl_sigma_prop(
    new_obj: TypedExpr,
    name: &str,
    new_args: Vec<TypedExpr>,
) -> Result<TypedExpr, TyperError> {
    // ("||"|"&&"|"^", Seq(r)) (:365).
    if matches!(name, "||" | "&&" | "^") && new_args.len() == 1 {
        let mut it = new_args.into_iter();
        let r = it.next().unwrap();
        return match node_tpe(&r) {
            // rhs Boolean: coerce the LEFT sigma to Bool via Select(isProven), then Bin* (:366-373).
            SType::SBoolean => {
                let a = TypedExpr::Select {
                    obj: Box::new(new_obj),
                    field: "isProven".to_string(),
                    res_type: Some(SType::SBoolean),
                    tpe: SType::SBoolean,
                };
                Ok(build_bin_bool(a, r, name))
            }
            // rhs SigmaProp: SigmaOr/SigmaAnd(Seq(a,b)); `^` is NotImplementedError (:374-381).
            SType::SSigmaProp => match name {
                "||" => Ok(TypedExpr::SigmaOr {
                    items: vec![new_obj, r],
                    tpe: SType::SSigmaProp,
                }),
                "&&" => Ok(TypedExpr::SigmaAnd {
                    items: vec![new_obj, r],
                    tpe: SType::SSigmaProp,
                }),
                "^" => Err(TyperError::not_implemented(
                    "Xor operation is not defined between SigmaProps".to_string(),
                )),
                _ => unreachable!("guarded by matches!"),
            },
            // else (:382-383).
            other => Err(TyperError::typer(format!(
                "Invalid argument type for {name}, expected SigmaProp but was {other:?}"
            ))),
        };
    }
    // else (:385-386).
    Err(TyperError::non_applicable(format!(
        "Unknown symbol {name}, which is used as (SigmaProp) {name} (args)"
    )))
}

/// Receiver `SBoolean` (SigmaTyper.scala:388-408).
pub(crate) fn mcl_boolean(
    new_obj: TypedExpr,
    name: &str,
    new_args: Vec<TypedExpr>,
) -> Result<TypedExpr, TyperError> {
    // ("||"|"&&"|"^", Seq(r)) (:389).
    if matches!(name, "||" | "&&" | "^") && new_args.len() == 1 {
        let mut it = new_args.into_iter();
        let r = it.next().unwrap();
        return match node_tpe(&r) {
            // rhs Boolean: Bin*(newObj, r) (:390-394).
            SType::SBoolean => Ok(build_bin_bool(new_obj, r, name)),
            // rhs SigmaProp: coerce the RIGHT sigma via Select(isProven), then Bin* (:395-402).
            SType::SSigmaProp => {
                let b = TypedExpr::Select {
                    obj: Box::new(r),
                    field: "isProven".to_string(),
                    res_type: Some(SType::SBoolean),
                    tpe: SType::SBoolean,
                };
                Ok(build_bin_bool(new_obj, b, name))
            }
            // else (:403-404).
            other => Err(TyperError::typer(format!(
                "Invalid argument type for {name}, expected Boolean but was {other:?}"
            ))),
        };
    }
    // else (:406-407).
    Err(TyperError::non_applicable(format!(
        "Unknown symbol {name}, which is used as (Boolean) {name} (args)"
    )))
}

/// The JVM `.toString` of a constant payload, for the `String + <const>` fold
/// (A4).  `Some` for payloads whose Scala `.toString` we reproduce byte-exactly;
/// `None` for the residual payloads whose runtime forms are not reproducible
/// from our stored representation (see `mcl_string`).
///
/// D-T12 (CLOSED for GroupElement/ProveDlog at M3 Task 4): Scala's `.toString`
/// on an `ECPoint` (BouncyCastle's default, non-canonical repr — actually
/// `CryptoFacade.showPoint`, `Platform.scala:81-85`) truncates each affine
/// coordinate's UNPADDED `BigInteger.toString(16)` hex to its first 6 chars,
/// e.g. `GroupElement(ECPoint(79be66,483ada,...))`. This IS byte-derivable
/// from our stored `[u8; 33]` via `decompress_to_affine_hex` (Task 3) —
/// oracle-pinned at the generator, a non-generator point (golden_seed.txt
/// §23(d)), and — the case that actually pins the UNPADDED-vs-padded
/// question, since neither prior point has a leading-zero coordinate — a
/// point whose y-coordinate has a leading zero nibble (§23(d) third probe,
/// §23(f)); `strip_leading_zero_hex` reproduces the unpadded form before
/// truncating. A `ProveDlog` constant (real on-curve bytes, e.g. from
/// `PK("<addr>")`) folds via the identical scheme wrapped as
/// `SigmaProp(ProveDlog(...))` (also oracle-pinned, §23(d)). Both are
/// on-curve-checked before reaching a `Constant` node (`env::lift` D-T5 /
/// `binder::bind_pk` D-T5), so decompression here cannot fail for a
/// well-formed compile — mirrors the `.expect` invariant already used by
/// `typed_print.rs`'s GroupElement/ProveDlog printer arms (which need the
/// same unpadding for their full-length `Ecp @(x,y,1)` render, §23(f)).
///
/// Residual (still unpinned, kept as reject): an opaque env-lifted
/// `ConstPayload::SigmaProp(String)` carries no real curve bytes in our
/// representation (only a label) — the fold cannot be reproduced. `ByteColl`/
/// `LongColl` RHS (Scala prints `Coll(<v1>,<v2>,...)`, oracle-probed but not
/// wired — see golden_seed.txt §23(d)) are likewise left unimplemented.
pub(crate) fn const_java_to_string(p: &ConstPayload) -> Option<String> {
    match p {
        ConstPayload::Bool(b) => Some(if *b { "true" } else { "false" }.to_string()),
        ConstPayload::Byte(v) => Some(v.to_string()),
        ConstPayload::Short(v) => Some(v.to_string()),
        ConstPayload::Int(v) => Some(v.to_string()),
        ConstPayload::Long(v) => Some(v.to_string()),
        // BigIntConstant.value.toString → "CBigInt(<decimal>)" (oracle-pinned).
        ConstPayload::BigInt(s) => Some(format!("CBigInt({s})")),
        // UnsignedBigIntConstant.value.toString → "CUnsignedBigInt(<decimal>)"
        // (oracle-pinned: `"x" + unsignedBigInt("5")` → `'xCUnsignedBigInt(5)'`,
        // golden_seed.txt §24, D-T3 M3 Task-6).
        ConstPayload::UnsignedBigInt(s) => Some(format!("CUnsignedBigInt({s})")),
        ConstPayload::String(s) => Some(s.clone()),
        // UnitConstant → "()" (Scala BoxedUnit toString).
        ConstPayload::Unit => Some("()".to_string()),
        ConstPayload::GroupElement(bytes) => {
            let (x, y) = decompress_to_affine_hex(bytes).expect(
                "GroupElement constant bytes must be on-curve — checked at env::lift (D-T5)",
            );
            // Java's `substring(0, 6)` on the UNPADDED `BigInteger.toString(16)`
            // (`showPoint`, Platform.scala:81-85) — never `<6` chars for an
            // on-curve 256-bit coordinate (would throw
            // StringIndexOutOfBoundsException in Java; unreachable here).
            let x = strip_leading_zero_hex(&x);
            let y = strip_leading_zero_hex(&y);
            Some(format!(
                "GroupElement(ECPoint({},{},...))",
                &x[..6],
                &y[..6]
            ))
        }
        ConstPayload::ProveDlog(bytes) => {
            let (x, y) = decompress_to_affine_hex(bytes)
                .expect("ProveDlog constant bytes must be on-curve — checked at bind_pk (D-T5)");
            // Same unpadded-then-truncate scheme as GroupElement above.
            let x = strip_leading_zero_hex(&x);
            let y = strip_leading_zero_hex(&y);
            Some(format!(
                "SigmaProp(ProveDlog(ECPoint({},{},...)))",
                &x[..6],
                &y[..6]
            ))
        }
        // Non-reproducible runtime `.toString` forms — keep the reject (D-T12 residual).
        ConstPayload::ByteColl(_) | ConstPayload::LongColl(_) | ConstPayload::SigmaProp(_) => None,
    }
}

/// Receiver `SString` (SigmaTyper.scala:409-418).
pub(crate) fn mcl_string(
    new_obj: TypedExpr,
    name: &str,
    new_args: Vec<TypedExpr>,
) -> Result<TypedExpr, TyperError> {
    // ("+", Seq(r)): compile-time concat fold → StringConstant (:410-414).
    if name == "+" && new_args.len() == 1 {
        let mut it = new_args.into_iter();
        let r = it.next().unwrap();
        // Scala's SString arm matches `(cl: Constant[SString]@unchecked, cr:
        // Constant[SString]@unchecked)`; the `@unchecked` type arg is ERASED at
        // runtime, so the real guard is "both operands are `Constant` of ANY type".
        // `mkStringConcat` then builds `StringConstant(cl.value + cr.value)`, and
        // Scala `String + Any` calls `.toString` on the RHS — so an Int folds to
        // its decimal, a Bool to "true"/"false", Unit to "()", a BigInt to
        // "CBigInt(n)", etc. (adversarial finding A4; oracle-pinned).  The LEFT
        // operand is always a String constant here (this arm is reached only for an
        // SString receiver; a non-constant String value, e.g. a `val`-bound Ident,
        // is not a `Constant` and correctly falls through to the reject).
        if let (
            TypedExpr::Constant {
                value: ConstPayload::String(cl),
                ..
            },
            TypedExpr::Constant { value: rp, .. },
        ) = (&new_obj, &r)
        {
            if let Some(rs) = const_java_to_string(rp) {
                return Ok(TypedExpr::Constant {
                    value: ConstPayload::String(format!("{cl}{rs}")),
                    tpe: SType::SString,
                });
            }
            // Reproducibility boundary (D-T12 residual, narrowed at M3 Task 4): a
            // GroupElement / ProveDlog RHS now folds above via `decompress_to_affine_hex`
            // (byte-derivable from the stored on-curve payload). An opaque
            // env-lifted SigmaProp (no real curve bytes, only a label) or a
            // ByteColl/LongColl RHS still folds in Scala via a JVM-runtime
            // `.toString` we cannot reproduce byte-exactly — REJECT rather than
            // fold wrong bytes (see the lib.rs deviation ledger).  Falls through
            // to the Err.
        }
        // Non-constant RHS (Height/Select/EQ/ConcreteCollection/…), or a Constant
        // RHS with a non-reproducible payload → InvalidBinaryOperationParameters
        // (:413-414).  A non-constant LHS likewise reaches here.
        return Err(TyperError::invalid_binary(format!(
            "Invalid argument type for {name}, expected String but was {:?}",
            node_tpe(&r)
        )));
    }
    // else (:416-417).
    Err(TyperError::non_applicable(format!(
        "Unknown symbol {name}, which is used as (String) {name} (args)"
    )))
}

/// Build `BinOr`/`BinAnd`/`BinXor(l, r)` for the `||`/`&&`/`^` bool ops (§1.11
/// SigmaProp/Boolean arms).  Result type is always `SBoolean`.
pub(crate) fn build_bin_bool(l: TypedExpr, r: TypedExpr, op: &str) -> TypedExpr {
    let (left, right) = (Box::new(l), Box::new(r));
    let tpe = SType::SBoolean;
    match op {
        "||" => TypedExpr::BinOr { left, right, tpe },
        "&&" => TypedExpr::BinAnd { left, right, tpe },
        "^" => TypedExpr::BinXor { left, right, tpe },
        _ => unreachable!("build_bin_bool only called for ||/&&/^"),
    }
}

/// Thread the §1.11 unify substitution onto a lowered `MethodCall` node.
///
/// `mkMethodCall(newObj, method, newArgs, typeSubst)` (SigmaTyper.scala:333) carries
/// the unify subst; `lower_method`'s MethodCall fallback uses an empty subst (correct
/// for §1.5/§1.8, which resolve the subst through the Select machinery).  For §1.11
/// we thread it back on.  Custom-lowered nodes (`Append`/`MapCollection`/…) have no
/// subst field and pass through unchanged.
pub(crate) fn thread_method_subst(node: TypedExpr, subst: &TypeSubst) -> TypedExpr {
    match node {
        TypedExpr::MethodCall {
            obj,
            method,
            args,
            tpe,
            ..
        } => TypedExpr::MethodCall {
            obj,
            method,
            args,
            type_subst: subst.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            tpe,
        },
        other => other,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// processGlobalMethod (§8.1) + the method-lowering catalog
// ─────────────────────────────────────────────────────────────────────────────

/// `processGlobalMethod(srcCtx, method, args)` — SigmaTyper.scala:38-48.
/// groupGenerator -> GroupGenerator, xor -> Xor (their custom irBuilders), all
/// other SGlobal methods fall back to MethodCall(Global, …).
pub(crate) fn process_global_method(
    method: &SMethodDesc,
    args: Vec<TypedExpr>,
) -> Result<TypedExpr, TyperError> {
    // A1 (accept-invalid fix): a bare `fromBigEndianBytes(a)` / `deserializeTo(a)` /
    // `some(x)` / `none()` call (§1.9 `Apply(Ident)` → SGlobal method) without an
    // explicit `[T]` reaches here with `method.explicit_type_args` set (or a result
    // still carrying a free type var).  The reference typer REJECTS
    // (IllegalArgumentException — unresolved tpeParams at MethodCall construction);
    // we reject for verdict parity.  `groupGenerator`/`xor`/`serialize` are
    // monomorphic (explicit_type_args=false, concrete range) and unaffected.
    // Oracle-pinned; boundary: predef `getVar(1)` → `Option[T]` is NOT an SGlobal
    // method and does not reach here.
    if method.explicit_type_args || stype_has_free_type_var(&method.stype.range) {
        return Err(TyperError::typer(format!(
            "Global method '{}' is type-parametric and requires an explicit type argument [T]",
            method.name
        )));
    }
    match method.name {
        "groupGenerator" if args.is_empty() => Ok(TypedExpr::GroupGenerator {
            tpe: SType::SGroupElement,
        }),
        "xor" if args.len() == 2 => {
            let mut it = args.into_iter();
            let left = it.next().unwrap();
            let right = it.next().unwrap();
            Ok(TypedExpr::Xor {
                left: Box::new(left),
                right: Box::new(right),
                tpe: SType::SColl(Box::new(SType::SByte)),
            })
        }
        _ => Ok(TypedExpr::MethodCall {
            obj: Box::new(TypedExpr::Global {
                tpe: SType::SGlobal,
            }),
            method: MethodRef {
                owner: "SigmaDslBuilder".to_string(),
                name: method.name.to_string(),
            },
            args,
            type_subst: vec![],
            tpe: method.stype.range.clone(),
        }),
    }
}

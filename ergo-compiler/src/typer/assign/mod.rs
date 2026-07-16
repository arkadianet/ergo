//! `assignType` dispatch — the structural arms of `SigmaTyper.assignType`.
//!
//! Port of `SigmaTyper.assignType` (pinned v6.0.2 worktree
//! `ergo-core/sigmastate-interpreter-v6.0.2/
//!   sc/shared/src/main/scala/sigma/compiler/phases/SigmaTyper.scala:53-543`).
//! Spec: `dev-docs/m2-recon/m2-typer.md` §1.1-1.25, §5, §6 (with the E1
//! correction from the M2 plan — see below).
//!
//! # Scope (M2 Tasks 5-7 — the complete `assignType` accept surface)
//!
//! Implemented (source order matters, first-match): §1.1 Block (E1-lenient),
//! §1.2 Tuple, §1.3 ConcreteCollection, §1.4 Ident, §1.5 Select (resolver),
//! §1.6 Lambda, §1.7 Apply(ApplyTypes(Select…)) explicit type args, §1.8
//! Apply(Select…) method call, §1.9 Apply(Ident) SGlobal method, §1.10 generic
//! Apply (predef funcs / collection & tuple index), §1.11 MethodCallLike receiver
//! dispatch (the `* ++ || && + ^ << >> >>>` operators), §1.12 ApplyTypes, §1.13
//! If, §1.14 AND/OR, §1.15 relations, §1.16 ArithOp, §1.17 BitOp, §1.18
//! Xor/MultiplyGroup, §1.19 Exponentiate, §1.20 ByIndex, §1.21 SizeOf, §1.22
//! SigmaProp ops, §1.23 unary, §1.24 passthroughs, §1.25 fallthrough.
//!
//! The dispatch arms live here (`assign_type`/`dispatch`); the grammar is split
//! across submodules:
//! - [`simple_arms`] — §1.1-1.6/1.13/1.14/1.19/1.20: block, concrete-collection,
//!   ident, select, lambda, if, and/or, exponentiate, byindex.
//! - [`apply`] — §1.7-1.10/1.12: the `assign_apply*`/`assign_apply_types` routing
//!   family and its arg-adaptation/numeric-const helpers.
//! - [`method_call_like`] — §1.11: the `mcl_*` receiver-family functions and the
//!   `assign_method_call_like` dispatcher.
//! - [`lower_method`] — the shared method/property irBuilder lowering catalog,
//!   a single receiver/name-keyed dispatch table kept as one function.
//! - [`arith_bitop`] — §1.16/1.17: `ArithOp`/`BitOp` arms plus the relation/
//!   equality node builders.
//! - [`harness`] — §6: the `bimap`/`bimap2`/`unmap` shared numeric-op harness.
//!
//! `expr_contains_untyped_node` (a generic `TypedExpr` tree-walk, not
//! typer-specific logic) lives in `typed.rs` alongside the type it walks. The
//! predef irBuilder lowering table lives in `predef_ir.rs`.
//!
//! `MethodCallLike` (and `ApplyTypes`) are **always eliminated** by the typer — the
//! entry point `assign_type` `debug_assert!`s that no returned node is either.  Every
//! arm is now ported: no deferred-arm markers or panics remain, and the accept
//! surface is complete.
//!
//! # E1 (CRITICAL) — lenient v6.0.2 Block rule
//!
//! In v6.0.2 the Block `Val`'s explicit annotation is **DISCARDED**: bind
//! `n -> b1.tpe`, `mkVal(n, b1.tpe, b1)`.  The typer-dossier §1.1's
//! `isAssignableTo`/`getResultType` explicit-type check is HEAD-only (a
//! post-6.0.2 commit) and is **NOT** implemented here.  `{ val x: Long = 1; x }`
//! ACCEPTS with `x: SInt` (oracle-confirmed, golden_seed §11).
//!
//! # Positions (deviation D-T7)
//!
//! `TypedExpr` carries no source positions (binder.rs; positions surface only in
//! `BindError`).  Every `TyperError` therefore reports `pos = 0` (E12).  This is
//! consistent with the parity policy: reject **class** is graded, reject
//! `line:col` is advisory and captured from the JVM oracle (E5, golden_seed §3).
//! Ledger: `lib.rs` § "Known M2 deviations" D-T7.

use crate::span::Pos;
use crate::stype::SType;
use crate::typed::{expr_contains_untyped_node, node_tpe, product_prefix, TypedExpr};
use crate::typer::is_collection_like;
use crate::typer::{TypeEnv, TyperCtx};

mod apply;
mod arith_bitop;
mod harness;
mod lower_method;
mod method_call_like;
mod simple_arms;
pub(crate) use apply::*;
pub(crate) use arith_bitop::*;
pub(crate) use harness::*;
pub(crate) use lower_method::*;
pub(crate) use method_call_like::*;
pub(crate) use simple_arms::*;

// ─────────────────────────────────────────────────────────────────────────────
// TyperError — the reject surface (§5)
// ─────────────────────────────────────────────────────────────────────────────

/// Typer reject surface.  Error MESSAGES are not parity-relevant (same policy as
/// `ParseError`/`BindError`); the accept/reject verdict and the error CLASS are.
///
/// Class tags mirror the Scala exception hierarchy
/// (`sigma.exceptions.TyperException` + `sigmastate.exceptions.*`,
/// CompilerExceptions.scala / SigmaTyperExceptions.scala):
/// `TyperException`, `InvalidBinaryOperationParameters`,
/// `InvalidUnaryOperationParameters`, `MethodNotFound`, `NonApplicableMethod`,
/// `NotImplementedError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TyperError {
    /// `TyperException` — thrown by `SigmaTyper.error` (SigmaTyper.scala:640).
    /// The generic typer rejection used by nearly every `error(...)` call.
    #[error("{msg} (pos {pos})")]
    TyperException { pos: Pos, msg: String },
    /// `InvalidBinaryOperationParameters` — numeric-op operand mismatch,
    /// string-concat non-const, and the `bimap`/`bimap2` catch rewraps (§6).
    #[error("{msg} (pos {pos})")]
    InvalidBinaryOperationParameters { pos: Pos, msg: String },
    /// `InvalidUnaryOperationParameters` — thrown by `unmap` (§6).
    #[error("{msg} (pos {pos})")]
    InvalidUnaryOperationParameters { pos: Pos, msg: String },
    /// `MethodNotFound` — `MethodsContainer.getMethod` returned None in a
    /// Select/Apply-Select arm (SigmaTyper.scala:93,175).
    #[error("{msg} (pos {pos})")]
    MethodNotFound { pos: Pos, msg: String },
    /// `NonApplicableMethod` — unknown operator symbol in a MethodCallLike arm
    /// (SigmaTyper.scala:336,345,361,386,407,417 — §1.11).
    #[error("{msg} (pos {pos})")]
    NonApplicableMethod { pos: Pos, msg: String },
    /// `scala.NotImplementedError` — `SigmaProp ^ SigmaProp` (SigmaTyper.scala:379 —
    /// §1.11).
    #[error("{msg} (pos {pos})")]
    NotImplementedError { pos: Pos, msg: String },
}

impl TyperError {
    /// Source offset of the error (always `0` — see the module deviation note).
    pub fn pos(&self) -> Pos {
        match self {
            TyperError::TyperException { pos, .. }
            | TyperError::InvalidBinaryOperationParameters { pos, .. }
            | TyperError::InvalidUnaryOperationParameters { pos, .. }
            | TyperError::MethodNotFound { pos, .. }
            | TyperError::NonApplicableMethod { pos, .. }
            | TyperError::NotImplementedError { pos, .. } => *pos,
        }
    }

    /// The Scala exception class name for accept/reject-class parity grading.
    pub fn class_tag(&self) -> &'static str {
        match self {
            TyperError::TyperException { .. } => "TyperException",
            TyperError::InvalidBinaryOperationParameters { .. } => {
                "InvalidBinaryOperationParameters"
            }
            TyperError::InvalidUnaryOperationParameters { .. } => "InvalidUnaryOperationParameters",
            TyperError::MethodNotFound { .. } => "MethodNotFound",
            TyperError::NonApplicableMethod { .. } => "NonApplicableMethod",
            TyperError::NotImplementedError { .. } => "NotImplementedError",
        }
    }

    // ----- constructors (pos is always 0; see module note) -----

    fn typer(msg: String) -> Self {
        TyperError::TyperException { pos: 0, msg }
    }
    fn invalid_binary(msg: String) -> Self {
        TyperError::InvalidBinaryOperationParameters { pos: 0, msg }
    }
    fn invalid_unary(msg: String) -> Self {
        TyperError::InvalidUnaryOperationParameters { pos: 0, msg }
    }
    fn method_not_found(msg: String) -> Self {
        TyperError::MethodNotFound { pos: 0, msg }
    }
    fn non_applicable(msg: String) -> Self {
        TyperError::NonApplicableMethod { pos: 0, msg }
    }
    fn not_implemented(msg: String) -> Self {
        TyperError::NotImplementedError { pos: 0, msg }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// small type helpers
// ─────────────────────────────────────────────────────────────────────────────

/// The type var `tT = STypeVar("T")` (SType.tT, SigmaTyper.scala:31).
#[inline]
fn tt() -> SType {
    SType::STypeVar("T".to_string())
}

/// `SByteArray = Coll[Byte]` (SCollection.SByteArray).
#[inline]
fn coll_byte() -> SType {
    SType::SColl(Box::new(SType::SByte))
}

/// `true` iff `t` contains any free `STypeVar` (an unresolved type parameter).
/// Used by the A1 guards (§1.8 method calls and the predef-IR `global_deserialize`
/// path) to reject a type-parametric SMethod reached without an explicit `[T]`.
pub(crate) fn stype_has_free_type_var(t: &SType) -> bool {
    let mut acc = Vec::new();
    collect_type_vars(t, &mut acc);
    !acc.is_empty()
}

pub(crate) fn collect_type_vars(t: &SType, acc: &mut Vec<String>) {
    match t {
        SType::STypeVar(n) if !acc.contains(n) => acc.push(n.clone()),
        SType::STypeVar(_) => {}
        SType::SColl(e) | SType::SOption(e) => collect_type_vars(e, acc),
        SType::STuple(items) => {
            for i in items {
                collect_type_vars(i, acc);
            }
        }
        SType::SFunc { dom, range, .. } => {
            for d in dom {
                collect_type_vars(d, acc);
            }
            collect_type_vars(range, acc);
        }
        SType::STypeApply { args, .. } => {
            for a in args {
                collect_type_vars(a, acc);
            }
        }
        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point + global post-condition (§0)
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrite a bound `TypedExpr` into a fully typed `TypedExpr`.
///
/// Mirrors `assignType(env, bound)` (SigmaTyper.scala:53-543).  The global
/// post-condition `v.tpe != NoType` (SigmaTyper.scala:541-542) is enforced on
/// every return.
///
/// `pub` (re-exported from `typer`), matching the crate's convention of
/// exposing each phase's entry point (see `unify`/`methods`).
pub fn assign_type(env: &TypeEnv, e: TypedExpr, ctx: &TyperCtx) -> Result<TypedExpr, TyperError> {
    let result = dispatch(env, e, ctx)?;
    // §7 post-condition: the typer eliminates `MethodCallLike` (§1.11) and
    // `ApplyTypes` (§1.12) on EVERY node — they never survive into typed output.
    // `assign_type` is the recursion point, so this covers the whole tree.
    debug_assert!(
        !matches!(
            result,
            TypedExpr::MethodCallLike { .. } | TypedExpr::ApplyTypes { .. }
        ),
        "typer must eliminate MethodCallLike/ApplyTypes; got {}",
        product_prefix(&result)
    );
    // .ensuring(v => v.tpe != NoType, ...) (SigmaTyper.scala:541-542)
    if *node_tpe(&result) == SType::NoType {
        return Err(TyperError::typer(format!(
            "Errors found while assigning types: {} assigned NoType",
            product_prefix(&result)
        )));
    }
    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// dispatch — the ordered `assignType` match (§1.1-1.25)
// ─────────────────────────────────────────────────────────────────────────────

fn dispatch(env: &TypeEnv, e: TypedExpr, ctx: &TyperCtx) -> Result<TypedExpr, TyperError> {
    use TypedExpr::*;
    match e {
        // §1.1 Block (E1-lenient) — SigmaTyper.scala:54-66
        Block {
            bindings, result, ..
        } => assign_block(env, bindings, *result, ctx),

        // §1.2 Tuple — SigmaTyper.scala:68-69
        Tuple { items, .. } => {
            let typed = type_all(env, items, ctx)?;
            let tpe = SType::STuple(typed.iter().map(|i| node_tpe(i).clone()).collect());
            Ok(Tuple { items: typed, tpe })
        }

        // §1.3 ConcreteCollection — SigmaTyper.scala:71-73 + assignConcreteCollection:545-556
        ConcreteCollection {
            items, elem_type, ..
        } => assign_concrete_collection(env, items, elem_type, ctx),

        // §1.4 Ident — SigmaTyper.scala:75-86
        Ident { name, .. } => assign_ident(&name, env, ctx),

        // §1.5 Select(obj, n, None) — the resolver — SigmaTyper.scala:88-122.
        // Only res_type == None reaches here; Some(_) is a §1.24 passthrough.
        Select {
            obj,
            field,
            res_type: None,
            ..
        } => assign_select(env, *obj, field, ctx),

        // §1.6 Lambda — SigmaTyper.scala:124-135
        Lambda {
            tpe_params,
            args,
            given_res_type,
            body,
            ..
        } => assign_lambda(env, tpe_params, args, given_res_type, body, ctx),

        // §1.7-1.10 Apply arms — SigmaTyper.scala:137-300.
        Apply { func, args, .. } => assign_apply(env, *func, args, ctx),
        // §1.12 ApplyTypes standalone — SigmaTyper.scala:423-438.
        ApplyTypes {
            input, type_args, ..
        } => assign_apply_types(env, *input, type_args, ctx),
        // §1.11 MethodCallLike receiver dispatch — SigmaTyper.scala:302-421.
        MethodCallLike {
            obj, name, args, ..
        } => assign_method_call_like(env, *obj, name, args, ctx),

        // §1.13 If — SigmaTyper.scala:440-449
        If {
            condition,
            true_branch,
            false_branch,
            ..
        } => assign_if(env, *condition, *true_branch, *false_branch, ctx),

        // §1.14 AND/OR — SigmaTyper.scala:451-461
        AND { input, .. } => assign_and_or(env, *input, true, ctx),
        OR { input, .. } => assign_and_or(env, *input, false, ctx),

        // §1.15 relations — SigmaTyper.scala:463-468
        GE { left, right, .. } => bimap(
            env,
            ctx,
            ">=",
            *left,
            *right,
            |l, r| build_relation(l, r, RelOp::Ge),
            tt(),
            SType::SBoolean,
        ),
        LE { left, right, .. } => bimap(
            env,
            ctx,
            "<=",
            *left,
            *right,
            |l, r| build_relation(l, r, RelOp::Le),
            tt(),
            SType::SBoolean,
        ),
        GT { left, right, .. } => bimap(
            env,
            ctx,
            ">",
            *left,
            *right,
            |l, r| build_relation(l, r, RelOp::Gt),
            tt(),
            SType::SBoolean,
        ),
        LT { left, right, .. } => bimap(
            env,
            ctx,
            "<",
            *left,
            *right,
            |l, r| build_relation(l, r, RelOp::Lt),
            tt(),
            SType::SBoolean,
        ),
        EQ { left, right, .. } => bimap2(env, ctx, "==", *left, *right, |l, r| {
            build_equality(l, r, true)
        }),
        NEQ { left, right, .. } => bimap2(env, ctx, "!=", *left, *right, |l, r| {
            build_equality(l, r, false)
        }),

        // §1.16 arithmetic — SigmaTyper.scala:470-476
        ArithOp {
            left,
            right,
            opcode,
            ..
        } => assign_arith(env, ctx, *left, *right, opcode),

        // §1.17 bitwise — SigmaTyper.scala:478-480
        BitOp {
            left,
            right,
            opcode,
            ..
        } => assign_bitop(env, ctx, *left, *right, opcode),

        // §1.18 Xor / MultiplyGroup — SigmaTyper.scala:482-483
        Xor { left, right, .. } => bimap(
            env,
            ctx,
            "|",
            *left,
            *right,
            |l, r| {
                Ok(TypedExpr::Xor {
                    left: Box::new(l),
                    right: Box::new(r),
                    tpe: coll_byte(),
                })
            },
            coll_byte(),
            coll_byte(),
        ),
        MultiplyGroup { left, right, .. } => bimap(
            env,
            ctx,
            "*",
            *left,
            *right,
            |l, r| {
                Ok(TypedExpr::MultiplyGroup {
                    left: Box::new(l),
                    right: Box::new(r),
                    tpe: SType::SGroupElement,
                })
            },
            SType::SGroupElement,
            SType::SGroupElement,
        ),

        // §1.19 Exponentiate — SigmaTyper.scala:485-490
        Exponentiate { left, right, .. } => assign_exponentiate(env, ctx, *left, *right),

        // §1.20 ByIndex — SigmaTyper.scala:492-500
        ByIndex {
            input,
            index,
            default,
            ..
        } => assign_byindex(env, ctx, *input, index, default),

        // §1.21 SizeOf — SigmaTyper.scala:502-506
        SizeOf { input, .. } => {
            let c1 = assign_type(env, *input, ctx)?;
            if !is_collection_like(node_tpe(&c1)) {
                return Err(TyperError::typer(format!(
                    "Invalid operation SizeOf: expected Collection argument; actual: {:?}",
                    node_tpe(&c1)
                )));
            }
            Ok(SizeOf {
                input: Box::new(c1),
                tpe: SType::SInt,
            })
        }

        // §1.22 SigmaPropIsProven / SigmaPropBytes — SigmaTyper.scala:508-518
        SigmaPropIsProven { input, .. } => {
            let p1 = assign_type(env, *input, ctx)?;
            if !matches!(node_tpe(&p1), SType::SSigmaProp) {
                return Err(TyperError::typer(format!(
                    "Invalid operation IsValid: expected SigmaProp; actual: {:?}",
                    node_tpe(&p1)
                )));
            }
            Ok(SigmaPropIsProven {
                input: Box::new(p1),
                tpe: SType::SBoolean,
            })
        }
        SigmaPropBytes { input, .. } => {
            let p1 = assign_type(env, *input, ctx)?;
            if !matches!(node_tpe(&p1), SType::SSigmaProp) {
                return Err(TyperError::typer(format!(
                    "Invalid operation ProofBytes: expected SigmaProp; actual: {:?}",
                    node_tpe(&p1)
                )));
            }
            Ok(SigmaPropBytes {
                input: Box::new(p1),
                tpe: coll_byte(),
            })
        }

        // §1.23 unary via unmap — SigmaTyper.scala:520-522
        LogicalNot { input, .. } => unmap(
            env,
            ctx,
            "!",
            *input,
            |i| {
                Ok(TypedExpr::LogicalNot {
                    input: Box::new(i),
                    tpe: SType::SBoolean,
                })
            },
            SType::SBoolean,
        ),
        Negation { input, .. } => unmap(
            env,
            ctx,
            "-",
            *input,
            |i| {
                let tpe = node_tpe(&i).clone();
                Ok(TypedExpr::Negation {
                    input: Box::new(i),
                    tpe,
                })
            },
            tt(),
        ),
        BitInversion { input, .. } => unmap(
            env,
            ctx,
            "~",
            *input,
            |i| {
                let tpe = node_tpe(&i).clone();
                Ok(TypedExpr::BitInversion {
                    input: Box::new(i),
                    tpe,
                })
            },
            tt(),
        ),

        // §1.24 terminal passthroughs (already typed) — SigmaTyper.scala:524-538.
        // These match nodes that arrive already-typed and are returned unchanged.
        // `GroupGenerator` is now *produced* by §1.9/§1.4 (processGlobalMethod) but
        // never appears in binder output, so this passthrough is idempotency-only.
        // `Downcast` likewise: no arm or binder rule constructs it in M2 (numeric
        // casts stay `Select`), so its passthrough is inert but kept for structural
        // completeness (matches the Scala `case v: <Node> => v` arms).
        node @ (Height { .. }
        | Self_ { .. }
        | Inputs { .. }
        | Outputs { .. }
        | Context { .. }
        | Global { .. }
        | MinerPubkey { .. }
        | LastBlockUtxoRootHash { .. }
        | GroupGenerator { .. }
        | Constant { .. }
        | GetVar { .. }
        | OptionGet { .. }
        | Upcast { .. }
        | Downcast { .. }
        | Select {
            res_type: Some(_), ..
        }) => Ok(node),

        // §1.24 MethodCall passthrough (SigmaTyper.scala:538 `case v: MethodCall => v`)
        // — returned UNCHANGED; the typer does NOT re-type its args.
        //
        // The binder pre-builds bare `serialize(v)` as `MethodCall(Global, serialize,
        // [v])` (Rule-10, `bind_serialize`) with a BOUND-but-un-typed arg, then this
        // passthrough returns it verbatim — mirroring the reference, whose bare
        // `serialize` irBuilder also runs at bind time and whose typer likewise leaves
        // the arg un-typed (`res_type` stays `None`).  The reference then RENDERS the
        // bound arg, and its s-expression printer THROWS (`RuntimeException` → oracle
        // REJECT) on any node with an unresolvable `tpe` (`NoType`): an unbound Ident,
        // an un-lowered `MethodCallLike` operator (`+ ++ * …`), an unresolved predef
        // `Apply`/`ApplyTypes` (`blake2b256(a)`, `getVar[Int](1)`, `xorOf(...)`), a
        // Block with a NoType result, or a `.get`/property chained on a function-typed
        // receiver (`SELF.R4[Long].get`, `SELF.tokens.size`).  We mirror that reject.
        //
        // Boundary (oracle-pinned): every node the binder types renders clean and stays
        // ACCEPT — plain constants, `Coll(...)`, `if`, relations (`==`/`>`), `min`/`max`
        // (→ ArithOp), collection index (`col1(0)`), a nested `serialize(...)`, AND a
        // property/method `Select` (`SELF.value → Select:(Box) => Long`, `xs.size →
        // (Coll[IV]) => Int`), whose bound `tpe` the binder supplies from the declared
        // method signature (`bind_serialize` note / `declared_select_tpe`).  The
        // Select-form `Global.serialize(v)` is typed via §1.8 and unaffected.
        node @ MethodCall { .. } => {
            if let MethodCall { args, .. } = &node {
                if args.iter().any(expr_contains_untyped_node) {
                    return Err(TyperError::typer(
                        "serialize: argument contains an unresolved (NoType) node that the \
                         reference s-expression printer cannot render (RuntimeException)"
                            .to_string(),
                    ));
                }
            }
            Ok(node)
        }

        // §1.25 fallthrough — SigmaTyper.scala:539-540
        other => Err(TyperError::typer(format!(
            "Don't know how to assignType({})",
            product_prefix(&other)
        ))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binder::bind;
    use crate::env::{EnvValue, ScriptEnv};
    use crate::parse::parse;
    use crate::typed::ConstPayload;
    use crate::typed_print::print_typed;
    use crate::typer::predef_ir::predefined_env;
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::address::NetworkPrefix;

    // ----- helpers -----

    fn ctx() -> TyperCtx {
        TyperCtx::new(3)
    }

    /// The base typer env: predefined func names (`predefinedEnv`) plus any test
    /// overlay entries (mirrors `predefFuncs ++ typeEnv`, SigmaTyper.scala:33-36).
    fn tenv(entries: &[(&str, SType)]) -> TypeEnv {
        let mut env = predefined_env(3);
        for (n, t) in entries {
            env.insert((*n).to_string(), t.clone());
        }
        env
    }

    /// The oracle `tce` demo binder env: a,b:Coll[Byte]; col1,col2:Coll[Long];
    /// g1,g2:GroupElement; n1:BigInt; bb1,bb2:Byte (TyperOracle.scala:112-126).
    fn demo_script_env() -> ScriptEnv {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        let ge = GroupElement::from_bytes(bytes);
        // g3 = g^7, a fixed NON-generator point (TyperOracle.scala demoEnv;
        // golden_seed.txt §23(c), x cross-checked against the oracle's
        // decompressed `Ecp @(x,y,1)` reply for `tce g3`).
        let mut g3_bytes = [0u8; 33];
        g3_bytes[0] = 0x02;
        let g3_x = hex::decode("5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
            .expect("valid hex");
        g3_bytes[1..].copy_from_slice(&g3_x);
        let g3 = GroupElement::from_bytes(g3_bytes);
        let mut env = ScriptEnv::new();
        env.insert("a", EnvValue::ByteArray(vec![1, 2]));
        env.insert("b", EnvValue::ByteArray(vec![3, 4]));
        env.insert("col1", EnvValue::LongArray(vec![1, 2]));
        env.insert("col2", EnvValue::LongArray(vec![3, 4]));
        env.insert("g1", EnvValue::GroupElement(ge));
        env.insert("g2", EnvValue::GroupElement(ge));
        env.insert("g3", EnvValue::GroupElement(g3));
        env.insert("n1", EnvValue::BigInt("5".to_string()));
        env.insert("bb1", EnvValue::Byte(1));
        env.insert("bb2", EnvValue::Byte(2));
        env
    }

    /// parse -> bind (`script_env`, testnet) -> assign_type(`env` + predef) -> Result.
    fn type_res(src: &str, script_env: &ScriptEnv, env: &TypeEnv) -> Result<TypedExpr, TyperError> {
        let ast = parse(src, 3).expect("parse must succeed");
        let bound = bind(script_env, &ast, NetworkPrefix::Testnet, 3).expect("bind ok");
        assign_type(env, bound, &ctx())
    }

    /// `tc`: empty binder env, predefined typer env.
    fn type_env_res(src: &str, env: &TypeEnv) -> Result<TypedExpr, TyperError> {
        type_res(src, &ScriptEnv::new(), env)
    }

    /// `tc` (empty env) — print the typed tree.
    fn type_tc(src: &str) -> String {
        print_typed(&type_env_res(src, &tenv(&[])).expect("typecheck must succeed"))
    }

    /// `tce` (demo env) — print the typed tree.
    fn type_tce(src: &str) -> String {
        print_typed(
            &type_res(src, &demo_script_env(), &tenv(&[])).expect("typecheck (tce) must succeed"),
        )
    }

    fn type_err(src: &str) -> TyperError {
        type_env_res(src, &tenv(&[])).expect_err("typecheck must fail")
    }

    /// Look up the committed OK-line for `source` in the golden seed (compile-time
    /// embedded so tests can't drift from the oracle-captured expected values).
    fn seed_expected(source: &str) -> String {
        let seed = include_str!("../../../../test-vectors/ergoscript/typer/golden_seed.txt");
        for line in seed.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, '\t').collect();
            if parts.len() == 3 && parts[1] == source {
                let expected = parts[2];
                if let Some(rest) = expected.strip_prefix("OK ") {
                    return rest.to_string();
                }
                panic!("seed line for {source:?} is not OK: {expected}");
            }
        }
        panic!("no seed line found for source: {source:?}");
    }

    fn int_const(v: i32) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Int(v),
            tpe: SType::SInt,
        }
    }
    fn bool_const(v: bool) -> TypedExpr {
        TypedExpr::Constant {
            value: ConstPayload::Bool(v),
            tpe: SType::SBoolean,
        }
    }

    // ----- happy path — E1 (CRITICAL, SigmaTyper.scala:54-66) -----

    /// E1: `{ val x: Long = 1; x }` ACCEPTS with x:SInt — the Val's explicit
    /// `Long` annotation is DISCARDED (bind n->b1.tpe; mkVal(n, b1.tpe, b1)).
    /// Oracle-captured: golden_seed §11.  SigmaTyper.scala:60,62 (v6.0.2).
    #[test]
    fn block_val_explicit_annotation_discarded_e1_accepts_x_as_int() {
        let typed = type_env_res("{ val x: Long = 1; x }", &TypeEnv::new()).expect("E1 accepts");
        // Structural: the ValNode and the result Ident are :Int (NOT Long).
        match &typed {
            TypedExpr::Block {
                bindings, result, ..
            } => {
                assert_eq!(node_tpe(&bindings[0]), &SType::SInt, "ValNode binds x:Int");
                if let TypedExpr::ValNode { given_type, .. } = &bindings[0] {
                    assert_eq!(*given_type, SType::SInt, "givenType discarded -> b1.tpe");
                } else {
                    panic!("expected ValNode");
                }
                assert_eq!(node_tpe(result), &SType::SInt, "result Ident x:Int");
            }
            other => panic!("expected Block, got {other:?}"),
        }
        // Byte-exact vs the oracle.
        assert_eq!(print_typed(&typed), seed_expected("{ val x: Long = 1; x }"));
    }

    /// PK passes through unchanged (§1.24 EvaluatedValue).  NOT byte-compared to
    /// golden_seed §10: the printer renders ProveDlog with an M2 hex placeholder
    /// (documented deviation), whereas the oracle prints the decompressed Ecp form.
    #[test]
    fn pk_constant_passes_through_unchanged() {
        let src = "PK(\"3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN\")";
        let typed = type_env_res(src, &TypeEnv::new()).expect("PK accepts");
        assert!(
            matches!(
                &typed,
                TypedExpr::Constant {
                    value: ConstPayload::ProveDlog(_),
                    ..
                }
            ),
            "PK -> SigmaProp constant passthrough; got {typed:?}"
        );
        assert_eq!(node_tpe(&typed), &SType::SSigmaProp);
    }

    // ----- happy path — §1.5 Select resolver (seeded typer env) -----

    /// §1.5: a no-irBuilder property survives as `Select` (cast-method-style).
    /// `b.value` with b:Box -> `(Select:Long (Ident:Box 'b') 'value')` — the exact
    /// inner Select of golden_seed line 21.  SBox.value has has_ir_builder=false
    /// (methods.rs) so it takes the Select branch (SigmaTyper.scala:117-118).
    #[test]
    fn select_no_ir_builder_property_survives_as_select() {
        let env = tenv(&[("b", SType::SBox)]);
        let printed = print_typed(&type_env_res("b.value", &env).expect("types"));
        assert_eq!(printed, "(Select:Long (Ident:Box 'b') 'value')");
    }

    /// §1.5: an irBuilder property lowers to `MethodCall`.  `t.digest` with
    /// t:AvlTree -> `%AvlTree.digest [] {}` — the method shape of golden_seed §7
    /// (line 80).  SAvlTree.digest has has_ir_builder=true (SigmaTyper.scala:108-116).
    #[test]
    fn select_ir_builder_property_lowers_to_method_call() {
        let env = tenv(&[("t", SType::SAvlTree)]);
        let printed = print_typed(&type_env_res("t.digest", &env).expect("types"));
        assert_eq!(
            printed,
            "(MethodCall:Coll[Byte] (Ident:AvlTree 't') %AvlTree.digest [] {})"
        );
    }

    /// §1.5: a numeric cast method survives as Select (no irBuilder).
    /// `5.toByte` -> `(Select:Byte (ConstantNode:Int @5) 'toByte')`.
    #[test]
    fn select_numeric_cast_method_survives_as_select() {
        assert_eq!(
            type_tc("5.toByte"),
            "(Select:Byte (ConstantNode:Int @5) 'toByte')"
        );
    }

    // ----- happy path — §1.6 Lambda (constructed input) -----

    /// §1.6: lambda arg goes into scope; result type inferred from the body.
    /// `{(x:Int) => x}` -> `(Lambda:(Int) => Int [] [x:#Int] #Int (Ident:Int 'x'))`.
    /// (Lambda format is oracle-grounded by golden_seed lines 21/30.)
    #[test]
    fn lambda_binds_arg_and_infers_result_type() {
        let lam = TypedExpr::Lambda {
            tpe_params: vec![],
            args: vec![("x".to_string(), SType::SInt)],
            given_res_type: SType::NoType,
            body: Some(Box::new(TypedExpr::Ident {
                name: "x".to_string(),
                tpe: SType::NoType,
            })),
            tpe: SType::NoType,
        };
        let typed = assign_type(&TypeEnv::new(), lam, &ctx()).expect("types");
        assert_eq!(
            print_typed(&typed),
            "(Lambda:(Int) => Int [] [x:#Int] #Int (Ident:Int 'x'))"
        );
    }

    /// §1.6: an un-annotated lambda arg (NoType) is rejected (SigmaTyper.scala:125-127).
    #[test]
    fn lambda_unannotated_arg_errors_typer_exception() {
        let lam = TypedExpr::Lambda {
            tpe_params: vec![],
            args: vec![("x".to_string(), SType::NoType)],
            given_res_type: SType::NoType,
            body: Some(Box::new(int_const(1))),
            tpe: SType::NoType,
        };
        let err = assign_type(&TypeEnv::new(), lam, &ctx()).expect_err("must fail");
        assert_eq!(err.class_tag(), "TyperException");
    }

    /// §1.6: a declared result type that disagrees with the body is rejected.
    #[test]
    fn lambda_wrong_declared_result_errors_typer_exception() {
        let lam = TypedExpr::Lambda {
            tpe_params: vec![],
            args: vec![("x".to_string(), SType::SInt)],
            given_res_type: SType::SLong, // body is Int
            body: Some(Box::new(TypedExpr::Ident {
                name: "x".to_string(),
                tpe: SType::NoType,
            })),
            tpe: SType::NoType,
        };
        let err = assign_type(&TypeEnv::new(), lam, &ctx()).expect_err("must fail");
        assert_eq!(err.class_tag(), "TyperException");
    }

    // ----- happy path — arms via constructed input (not reachable from binder) -----

    /// §1.14: `AND(Coll[Boolean])` -> `(AND:Boolean ...)`.
    #[test]
    fn and_over_bool_collection_types() {
        let coll = TypedExpr::ConcreteCollection {
            items: vec![bool_const(true), bool_const(false)],
            elem_type: SType::SBoolean,
            tpe: SType::SColl(Box::new(SType::SBoolean)),
        };
        let node = TypedExpr::AND {
            input: Box::new(coll),
            tpe: SType::NoType,
        };
        let typed = assign_type(&TypeEnv::new(), node, &ctx()).expect("types");
        assert!(matches!(typed, TypedExpr::AND { .. }));
        assert_eq!(node_tpe(&typed), &SType::SBoolean);
    }

    /// §1.14: AND over a non-boolean collection is rejected.
    #[test]
    fn and_over_int_collection_errors() {
        let coll = TypedExpr::ConcreteCollection {
            items: vec![int_const(1)],
            elem_type: SType::SInt,
            tpe: SType::SColl(Box::new(SType::SInt)),
        };
        let node = TypedExpr::AND {
            input: Box::new(coll),
            tpe: SType::NoType,
        };
        let err = assign_type(&TypeEnv::new(), node, &ctx()).expect_err("fail");
        assert_eq!(err.class_tag(), "TyperException");
    }

    /// §1.21: `SizeOf(Coll[Int])` -> `(SizeOf:Int ...)`.
    #[test]
    fn sizeof_over_collection_is_int() {
        let coll = TypedExpr::ConcreteCollection {
            items: vec![int_const(1), int_const(2)],
            elem_type: SType::SInt,
            tpe: SType::SColl(Box::new(SType::SInt)),
        };
        let node = TypedExpr::SizeOf {
            input: Box::new(coll),
            tpe: SType::NoType,
        };
        let typed = assign_type(&TypeEnv::new(), node, &ctx()).expect("types");
        assert_eq!(node_tpe(&typed), &SType::SInt);
    }

    /// §1.22: `SigmaPropIsProven(p)` requires a SigmaProp; result is Boolean.
    #[test]
    fn sigma_prop_is_proven_requires_sigma_prop() {
        let prop = TypedExpr::Constant {
            value: ConstPayload::ProveDlog([0x02; 33]),
            tpe: SType::SSigmaProp,
        };
        let node = TypedExpr::SigmaPropIsProven {
            input: Box::new(prop),
            tpe: SType::NoType,
        };
        let typed = assign_type(&TypeEnv::new(), node, &ctx()).expect("types");
        assert_eq!(node_tpe(&typed), &SType::SBoolean);

        // Non-SigmaProp input rejects.
        let bad = TypedExpr::SigmaPropIsProven {
            input: Box::new(bool_const(true)),
            tpe: SType::NoType,
        };
        assert_eq!(
            assign_type(&TypeEnv::new(), bad, &ctx())
                .expect_err("fail")
                .class_tag(),
            "TyperException"
        );
    }

    /// §1.19: `Exponentiate(GroupElement, BigInt)` -> GroupElement; wrong types reject.
    #[test]
    fn exponentiate_requires_group_element_and_bigint() {
        let bad = TypedExpr::Exponentiate {
            left: Box::new(int_const(1)),
            right: Box::new(int_const(2)),
            tpe: SType::NoType,
        };
        assert_eq!(
            assign_type(&TypeEnv::new(), bad, &ctx())
                .expect_err("fail")
                .class_tag(),
            "TyperException"
        );
    }

    // ----- harness — bimap / bimap2 / unmap (§6) -----

    /// §6 bimap first branch: (numeric, numeric) with t1 != t2 -> builder inserts
    /// Upcast on the smaller operand.  `1L - 1` (via the dedicated ArithOp node).
    #[test]
    fn bimap_numeric_widening_inserts_upcast() {
        assert_eq!(type_tc("1L - 1"), seed_expected("1L - 1"));
        // The right operand became Upcast:Long.
        match type_env_res("1L - 1", &TypeEnv::new()).expect("types") {
            TypedExpr::ArithOp { right, tpe, .. } => {
                assert!(matches!(*right, TypedExpr::Upcast { .. }));
                assert_eq!(tpe, SType::SLong);
            }
            other => panic!("expected ArithOp, got {other:?}"),
        }
    }

    /// §6 bimap else branch: comparison requires numeric operands.
    /// `HEIGHT >= true` — right is Boolean -> comparisonOp OnlyNumeric fails ->
    /// safeMkNode catch -> InvalidBinaryOperationParameters.
    #[test]
    fn bimap_comparison_non_numeric_errors_invalid_binary() {
        // GE(Height, true) constructed directly (the parser's `>=` -> GE node).
        let node = TypedExpr::GE {
            left: Box::new(TypedExpr::Height { tpe: SType::SInt }),
            right: Box::new(bool_const(true)),
            tpe: SType::SBoolean,
        };
        let err = assign_type(&TypeEnv::new(), node, &ctx()).expect_err("fail");
        assert_eq!(err.class_tag(), "InvalidBinaryOperationParameters");
    }

    /// §6 bimap2: EQ with mismatched types -> equalityOp SameType fails ->
    /// InvalidBinaryOperationParameters (golden_seed §11 `1 == true`).
    #[test]
    fn bimap2_equality_type_mismatch_errors_invalid_binary() {
        let err = type_err("1 == true");
        assert_eq!(err.class_tag(), "InvalidBinaryOperationParameters");
    }

    /// §6 unmap: `!` on a non-boolean, non-numeric operand ->
    /// InvalidUnaryOperationParameters.
    #[test]
    fn unmap_logical_not_on_group_element_errors_invalid_unary() {
        let ge = TypedExpr::Constant {
            value: ConstPayload::GroupElement([0x02u8; 33]),
            tpe: SType::SGroupElement,
        };
        let node = TypedExpr::LogicalNot {
            input: Box::new(ge),
            tpe: SType::SBoolean,
        };
        let err = assign_type(&TypeEnv::new(), node, &ctx()).expect_err("fail");
        assert_eq!(err.class_tag(), "InvalidUnaryOperationParameters");
    }

    // ----- error paths — §5 classes (oracle-grounded, golden_seed §3/§11) -----

    #[test]
    fn reject_classes_match_oracle() {
        // (source, expected class) — positions are advisory (our pos == 0).
        let cases: &[(&str, &str)] = &[
            ("Coll()", "TyperException"),                    // §1.3 empty undefined
            ("if (5) 1 else 2", "TyperException"),           // §1.13 condition
            ("if (HEIGHT > 5) 1 else 2L", "TyperException"), // §1.13 branch mismatch
            ("Coll(1, 2L)", "TyperException"),               // §1.3 no widening
            ("HEIGHT.foo", "MethodNotFound"),                // §1.5 unknown method
            ("1 == true", "InvalidBinaryOperationParameters"), // §1.15 eq mismatch
            (
                "{ val x = HEIGHT; val x = 5; x }",
                "TyperException", // §1.1 duplicate name
            ),
            // §1.11 MethodCallLike reject surface (live oracle §14).
            ("(1, 2) ++ Coll(3)", "TyperException"), // else-arm: tuple receiver
            ("HEIGHT ^ true", "InvalidBinaryOperationParameters"), // numeric non-numeric rhs
            ("HEIGHT && true", "NonApplicableMethod"), // numeric unknown op
            (
                "sigmaProp(true) ^ sigmaProp(false)",
                "NotImplementedError", // SigmaProp ^ SigmaProp
            ),
        ];
        for (src, cls) in cases {
            let err = type_err(src);
            assert_eq!(err.class_tag(), *cls, "class mismatch for {src:?}");
        }
    }

    /// id-narrowing overflow rejects — oracle-confirmed §13.
    ///
    /// Scala `SByte.downcast` / `SShort.downcast` = `toByteExact` / `toShortExact`:
    /// throw `ArithmeticException` on overflow.  We reject with `TyperError`.
    /// Verdict parity is exact; class-tag differs (ArithmeticException vs TyperError
    /// — see lib.rs Known M2 deviations).
    #[test]
    fn id_narrowing_overflow_rejects() {
        // getVar[Int](200): 200 > i8::MAX (127) → ArithmeticException (oracle §13).
        let err = type_err("getVar[Int](200)");
        assert_eq!(
            err.class_tag(),
            "TyperException",
            "getVar[Int](200) must reject"
        );
        // executeFromVar[Int](300): 300 > 127 → ArithmeticException (oracle §13).
        let err2 = type_err("executeFromVar[Int](300)");
        assert_eq!(
            err2.class_tag(),
            "TyperException",
            "executeFromVar[Int](300) must reject"
        );
        // getVarFromInput[Int](70000, 1): 70000 > i16::MAX (32767) → same (oracle §13).
        let err3 = type_err("getVarFromInput[Int](70000, 1)");
        assert_eq!(
            err3.class_tag(),
            "TyperException",
            "getVarFromInput[Int](70000, 1) must reject"
        );
    }

    /// unsignedBigInt negative literal rejects — oracle-confirmed §13 (InvalidArguments).
    #[test]
    fn unsigned_big_int_negative_literal_rejects() {
        let err = type_err("unsignedBigInt(\"-5\")");
        // Scala: InvalidArguments; we map to TyperException (verdict parity).
        assert_eq!(err.class_tag(), "TyperException", "unsignedBigInt(\"-5\")");
    }

    /// §1.5: field access on a non-product type is a TyperException (not MethodNotFound).
    #[test]
    fn select_on_non_product_type_errors_typer_exception() {
        // A function-typed obj (SFunc) is not an SProduct.
        let node = TypedExpr::Select {
            obj: Box::new(TypedExpr::Ident {
                name: "f".to_string(),
                tpe: SType::NoType,
            }),
            field: "x".to_string(),
            res_type: None,
            tpe: SType::NoType,
        };
        let env = tenv(&[(
            "f",
            SType::SFunc {
                dom: vec![SType::SInt],
                range: Box::new(SType::SInt),
                tpe_params: vec![],
            },
        )]);
        let err = assign_type(&env, node, &ctx()).expect_err("fail");
        assert_eq!(err.class_tag(), "TyperException");
    }

    /// §1.4: an unbound identifier that is not a global property is a TyperException.
    #[test]
    fn unbound_ident_errors_typer_exception() {
        let node = TypedExpr::Ident {
            name: "nope".to_string(),
            tpe: SType::NoType,
        };
        let err = assign_type(&TypeEnv::new(), node, &ctx()).expect_err("fail");
        assert_eq!(err.class_tag(), "TyperException");
    }

    // ----- §1.11 MethodCallLike receiver dispatch (SigmaTyper.scala:302-421) -----

    /// §7 post-condition: `MethodCallLike` is ALWAYS eliminated — the typed output
    /// (and, via the `assign_type` `debug_assert`, every subtree) never contains a
    /// `MethodCallLike` or `ApplyTypes` node.  The printed s-expression covers the
    /// whole tree by construction.
    #[test]
    fn method_call_like_is_always_eliminated() {
        // Each source's top node arrives as a MethodCallLike from the binder; after
        // typing, neither the top node nor any descendant may remain.
        let tc_srcs = [
            "1 + 2",
            "1L + 1",
            "5 * 2",
            "5 ^ 3",
            "5 << 1",
            "5 >> 1",
            "5 >>> 1",
            "true && (1 == 1)",
            "true ^ false",
            "\"ab\" + \"cd\"",
            // nested: a MethodCallLike buried inside an If branch and a Block body.
            "if (true) 1 + 2 else 3",
            "{ val x = 1 + 2; x * 4 }",
        ];
        for src in tc_srcs {
            let printed = type_tc(src);
            assert!(
                !printed.contains("MethodCallLike") && !printed.contains("ApplyTypes"),
                "residual node in {src:?}: {printed}"
            );
        }
        // Demo-env records (Coll ++, SigmaProp combiners).
        for src in ["a ++ b", "sigmaProp(true) && sigmaProp(false)"] {
            let printed = type_tce(src);
            assert!(
                !printed.contains("MethodCallLike") && !printed.contains("ApplyTypes"),
                "residual node in {src:?}: {printed}"
            );
        }
    }

    /// §1.11 SColl `("++", r)`: exact-type `Append` (SigmaTyper.scala:307-311).
    #[test]
    fn mcl_collection_append_exact_type() {
        assert_eq!(type_tce("a ++ b"), seed_expected("a ++ b"));
    }

    /// §1.11 SColl `++` type mismatch: `col1 ++ a` (Coll[Long] ++ Coll[Byte]) rejects
    /// with `TyperException` (SigmaTyper.scala:310-311; live oracle §14).
    #[test]
    fn mcl_collection_append_type_mismatch_rejects() {
        let err = type_res("col1 ++ a", &demo_script_env(), &tenv(&[])).expect_err("reject");
        assert_eq!(err.class_tag(), "TyperException");
    }

    /// §1.11 SNumeric `+`/`*` → ArithOp (upcast); `1L + 1` inserts `Upcast:Long`
    /// (SigmaTyper.scala:350-351; seed §1/§2).
    #[test]
    fn mcl_numeric_plus_multiply_byte_parity() {
        assert_eq!(type_tc("1L + 1"), seed_expected("1L + 1"));
        assert_eq!(
            type_tc("1.toByte + 2.toByte"),
            seed_expected("1.toByte + 2.toByte")
        );
        assert_eq!(type_tc("5 * 2"), seed_expected("5 * 2"));
    }

    /// §1.11 SNumeric `^`/`>>`/`<<`/`>>>` → BitOp (NO upcast, direct node)
    /// (SigmaTyper.scala:352-355; live oracle §14).
    #[test]
    fn mcl_numeric_bit_ops_byte_parity() {
        for src in ["5 ^ 3", "5 >> 1", "5 << 1", "5 >>> 1"] {
            assert_eq!(type_tc(src), seed_expected(src), "{src}");
        }
    }

    /// §1.11 SNumeric non-numeric rhs → `InvalidBinaryOperationParameters`
    /// (SigmaTyper.scala:357-358; live oracle §14 `HEIGHT ^ true`).
    #[test]
    fn mcl_numeric_non_numeric_rhs_rejects() {
        let err = type_err("HEIGHT ^ true");
        assert_eq!(err.class_tag(), "InvalidBinaryOperationParameters");
    }

    /// §1.11 SNumeric unknown op (`&&` on Int) → `NonApplicableMethod`
    /// (SigmaTyper.scala:360-361; seed §3 `HEIGHT && true`).
    #[test]
    fn mcl_numeric_unknown_op_non_applicable() {
        let err = type_err("HEIGHT && true");
        assert_eq!(err.class_tag(), "NonApplicableMethod");
    }

    /// §1.11 SSigmaProp/SBoolean coercion matrix (SigmaTyper.scala:364-408; live
    /// oracle §14): prop∘prop → SigmaOr/SigmaAnd; prop∘bool → left isProven; bool∘prop
    /// → right isProven.
    #[test]
    fn mcl_sigma_prop_boolean_coercion_matrix() {
        for src in [
            "sigmaProp(true) && sigmaProp(false)",
            "sigmaProp(true) || sigmaProp(false)",
            "sigmaProp(true) && (1 == 1)",
            "(1 == 1) && sigmaProp(true)",
            "sigmaProp(true) ^ (1 == 1)",
            "(1 == 1) ^ sigmaProp(true)",
            "true ^ false",
            "true && (1 == 1)",
        ] {
            assert_eq!(type_tc(src), seed_expected(src), "{src}");
        }
    }

    /// §1.11 SSigmaProp `^` between two SigmaProps → `NotImplementedError`
    /// (SigmaTyper.scala:379; live oracle §14).
    #[test]
    fn mcl_sigma_prop_xor_between_sigmaprops_not_implemented() {
        let err = type_err("sigmaProp(true) ^ sigmaProp(false)");
        assert_eq!(err.class_tag(), "NotImplementedError");
    }

    /// §1.11 SString `"a" + "b"`: compile-time concat fold → StringConstant
    /// (SigmaTyper.scala:410-414; seed §8).
    #[test]
    fn mcl_string_const_concat_fold() {
        assert_eq!(type_tc("\"ab\" + \"cd\""), seed_expected("\"ab\" + \"cd\""));
    }

    // ----- M2 adversarial wave A — verdict parity (seed §18/§19) -----

    /// A1 (§1.8/§1.9): a type-parametric SGlobal/SBox method reached WITHOUT an
    /// explicit `[T]` ApplyTypes is rejected (the reference throws
    /// IllegalArgumentException at MethodCall construction; we reject for verdict
    /// parity, class → TyperException).  Covers both the `Global.<m>(...)` Select
    /// path (§1.8) and the bare `Ident(...)` SGlobal path (§1.9).
    #[test]
    fn type_parametric_method_without_explicit_type_arg_rejects() {
        for src in ["Global.some(1)", "Global.none()", "SELF.getReg(4)"] {
            let err = type_err(src);
            assert_eq!(err.class_tag(), "TyperException", "{src}");
        }
        // bare `Ident` SGlobal call (§1.9) + Select form (§1.8), demo env for `a`.
        for src in ["fromBigEndianBytes(a)", "Global.fromBigEndianBytes(a)"] {
            let err = type_res(src, &demo_script_env(), &tenv(&[])).expect_err(src);
            assert_eq!(err.class_tag(), "TyperException", "{src}");
        }
    }

    /// A1 boundary: the explicit-`[T]` control still ACCEPTS (both paths), and the
    /// predef `getVar(1)` — a free `T` nested inside `SOption` — is tolerated by the
    /// reference and ACCEPTS on both sides (it does not reach the §1.8/§1.9 guard).
    #[test]
    fn type_parametric_method_boundary_accepts() {
        assert_eq!(type_tc("getVar(1)"), "(GetVar:Option[T] @1)");
        // explicit [T] control (byte-pinned by seed §4 / §18).
        assert!(type_tc("Global.some[Int](1)").contains("{#T->#Int}"));
        // bare Ident explicit [T] via demo env.
        let ok = type_res("fromBigEndianBytes[Int](a)", &demo_script_env(), &tenv(&[]))
            .expect("explicit [T] accepts");
        assert_eq!(node_tpe(&ok), &SType::SInt);
    }

    /// A3 (§1.24 MethodCall passthrough): a binder-prebuilt `serialize(<operator
    /// expr>)` embeds an untyped `MethodCallLike` (parseAsMethods `+ ++ …`) that the
    /// reference typer cannot type → RuntimeException (verdict REJECT).  Fires for a
    /// top-level operator arg AND for one nested inside a relation.
    #[test]
    fn serialize_with_unresolved_operator_arg_rejects() {
        for src in ["serialize(1 + 1)", "serialize((1 + 1) == 2)"] {
            let err = type_err(src);
            assert_eq!(err.class_tag(), "TyperException", "{src}");
        }
        // demo-env `++` operator arg (bare-serialize binder path).
        let err = type_res("serialize(a ++ b)", &demo_script_env(), &tenv(&[]))
            .expect_err("serialize(a ++ b) rejects");
        assert_eq!(err.class_tag(), "TyperException");
    }

    /// A3 boundary: typed args (constant / relation / `if` / `Coll`) still ACCEPT
    /// and byte-match; the Select-form `Global.serialize(a ++ b)` (typed via §1.8,
    /// arg lowered to `Append`) is unaffected.
    #[test]
    fn serialize_with_typed_arg_accepts_and_select_form_unaffected() {
        assert_eq!(type_tc("serialize(1)"), seed_expected("serialize(1)"));
        assert_eq!(
            type_tc("serialize(Coll(1, 2))"),
            seed_expected("serialize(Coll(1, 2))")
        );
        // relations / if stay typed → accept.
        assert!(type_tc("serialize(1 == 2)").contains("(EQ:Boolean"));
        assert!(type_tc("serialize(if (1 == 1) 1 else 2)").contains("(If:Int"));
        // Select form: arg lowered to Append (not a MethodCallLike survivor).
        let sel = type_tce("Global.serialize(a ++ b)");
        assert_eq!(sel, seed_expected("Global.serialize(a ++ b)"));
        assert!(sel.contains("(Append:Coll[Byte]"));
    }

    /// §1.24 passthrough (broadened): the reference renders the BOUND arg, throwing
    /// (RuntimeException → REJECT) on ANY node whose bound `tpe` is NoType — not only
    /// an operator `MethodCallLike`.  Covers an unbound Ident, a NoType-result Block,
    /// an unresolved predef `Apply`/`ApplyTypes` (`blake2b256`/`getVar`/`xorOf`), and a
    /// property/method chained on a function-typed `Select` (`SELF.R4[Long].get`,
    /// `SELF.tokens.size`).
    #[test]
    fn serialize_with_unrenderable_bound_arg_rejects() {
        for src in [
            "serialize(a)",
            "serialize({val x = 1; x})",
            "serialize(getVar[Int](1))",
            "serialize(getVar[Int](1).get)",
            "serialize(SELF.R4[Long].get)",
            "serialize(xorOf(Coll(true, false)))",
            "serialize(SELF.tokens.size)",
            "serialize(SELF.value + 1)",
        ] {
            assert_eq!(type_err(src).class_tag(), "TyperException", "{src}");
        }
        // demo-env predef Apply with a BOUND (typed) arg still rejects: the reject is
        // the un-lowered predef `Apply`, not an unbound variable.
        let err = type_res("serialize(blake2b256(a))", &demo_script_env(), &tenv(&[]))
            .expect_err("serialize(blake2b256(a)) rejects");
        assert_eq!(err.class_tag(), "TyperException");
    }

    /// §1.24 passthrough (shape): a property/method `Select` surviving un-typed carries
    /// the DECLARED method signature — `SELF.value → (Box) => Long`, `Coll(1,2).size →
    /// (Coll[IV]) => Int` (receiver kept, IV un-substituted, res_type=None) — supplied
    /// by `bind::declared_select_tpe`.  This is the reference bound form, distinct from
    /// the typed Select (receiver dropped, IV→concrete).
    #[test]
    fn serialize_bound_select_arg_carries_declared_signature() {
        assert_eq!(
            type_tc("serialize(SELF.value)"),
            seed_expected("serialize(SELF.value)")
        );
        assert_eq!(
            type_tc("serialize(Coll(1, 2).size)"),
            seed_expected("serialize(Coll(1, 2).size)")
        );
        // Un-substituted declared receiver / kept receiver in dom.
        assert!(type_tc("serialize(SELF.value)").contains("(Select:(Box) => Long"));
        assert!(type_tc("serialize(Coll(1, 2).size)").contains("(Select:(Coll[IV]) => Int"));
        // Standalone (typed) Select is UNCHANGED — receiver dropped, IV→concrete.
        assert_eq!(type_tc("SELF.value"), "(Select:Long (Self:Box) 'value')");
        assert!(type_tc("Coll(1, 2, 3).map").starts_with("(Select:[OV]((Int) => OV) => Coll[OV]"));
    }

    /// A4 (SString `+` fold): a String constant `+` ANY other constant folds via the
    /// JVM `.toString` — the reference's `@unchecked` type args are erased, so the
    /// guard is "both operands are Constant".  Oracle-pinned decimal/bool/unit/BigInt
    /// forms (seed §19).
    #[test]
    fn mcl_string_const_plus_any_const_folds() {
        assert_eq!(type_tc("\"ab\" + 1"), "(ConstantNode:String 'ab1')");
        assert_eq!(type_tc("\"ab\" + 1L"), "(ConstantNode:String 'ab1')");
        assert_eq!(type_tc("\"ab\" + true"), "(ConstantNode:String 'abtrue')");
        assert_eq!(type_tc("\"ab\" + ()"), "(ConstantNode:String 'ab()')");
        assert_eq!(type_tc("\"ab\" + -1"), "(ConstantNode:String 'ab-1')");
        // BigInt RHS → "CBigInt(<decimal>)" (demo env `n1 = 5`).
        assert_eq!(
            type_tce("\"ab\" + n1"),
            "(ConstantNode:String 'abCBigInt(5)')"
        );
    }

    /// D-T12 (CLOSED, M3 Task 4): a GroupElement-constant RHS folds via the JVM
    /// `.toString`'s truncated `GroupElement(ECPoint(<x[0:6]>,<y[0:6]>,...))` form,
    /// byte-derivable from the stored `[u8; 33]` via `decompress_to_affine_hex`
    /// (Task 3) plus `strip_leading_zero_hex` (unpadded `BigInteger.toString(16)`
    /// semantics). Oracle-pinned at the generator (g1, golden_seed.txt §23(d))
    /// and a non-generator point (g3, same section) — NEITHER exercises a
    /// leading-zero coordinate; the truncation format's UNPADDED-hex semantics
    /// are pinned separately by the leading-zero `PK(...)` fold below
    /// (§23(d) third probe) and the plain-render case (§23(f)).
    #[test]
    fn mcl_string_const_plus_group_element_const_folds() {
        assert_eq!(
            type_tce("\"ab\" + g1"),
            "(ConstantNode:String 'abGroupElement(ECPoint(79be66,483ada,...))')"
        );
        assert_eq!(
            type_tce("\"x\" + g3"),
            "(ConstantNode:String 'xGroupElement(ECPoint(5cbdf0,6aebca,...))')"
        );
    }

    /// D-T12 (CLOSED, M3 Task 4): a `ProveDlog`-constant RHS (real on-curve bytes,
    /// e.g. from `PK("<addr>")`) folds via the same JVM `.toString` scheme but
    /// through the `SigmaProp(ProveDlog(...))` wrapper. Oracle-pinned,
    /// golden_seed.txt §23(d) (same generator pubkey as g1).
    #[test]
    fn mcl_string_const_plus_provedlog_const_folds() {
        assert_eq!(
            type_tc("\"x\" + PK(\"3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN\")"),
            "(ConstantNode:String 'xSigmaProp(ProveDlog(ECPoint(79be66,483ada,...)))')"
        );
    }

    /// D-T12 leading-zero-coordinate fix: the fold uses the coordinate's
    /// UNPADDED `BigInteger.toString(16)` hex, NOT our fixed-width 64-char
    /// decompression, before truncating to 6 chars. This pubkey's y-coordinate
    /// (`0ab0902e...`) has a leading zero nibble — the padded-slice bug would
    /// have produced `0ab090`; the oracle (and this fix) produce `ab0902`.
    /// Oracle-pinned via `PK("3WzPmMVoyrrj1m9NkmpWchWoiZy1wN3wYsmn8gE1cZXcdwck7LBg")`
    /// (testnet), golden_seed.txt §23(d) fourth probe.
    #[test]
    fn mcl_string_const_plus_provedlog_const_leading_zero_y_folds_unpadded() {
        assert_eq!(
            type_tc("\"x\" + PK(\"3WzPmMVoyrrj1m9NkmpWchWoiZy1wN3wYsmn8gE1cZXcdwck7LBg\")"),
            "(ConstantNode:String 'xSigmaProp(ProveDlog(ECPoint(f28773,ab0902,...)))')"
        );
    }

    /// D-T12 residual: an opaque env-lifted `ConstPayload::SigmaProp(String)` (no
    /// real curve bytes in our representation — only a label) stays a NAMED
    /// reject (documented in the lib.rs deviation ledger) — the still-open half
    /// of D-T12, distinct from the now-closed GroupElement/ProveDlog arms above.
    #[test]
    fn mcl_string_const_plus_opaque_sigmaprop_const_rejects_residual() {
        let mut script_env = ScriptEnv::new();
        script_env.insert("p1", EnvValue::SigmaProp("p1".to_string()));
        let err = type_res("\"ab\" + p1", &script_env, &tenv(&[]))
            .expect_err("opaque SigmaProp RHS kept as reject (D-T12 residual)");
        assert_eq!(err.class_tag(), "InvalidBinaryOperationParameters");
    }

    /// A2: `min`/`max` are valid idents in `predefined_env` (word-named infixFuncs).
    /// Bare `min` ACCEPTS as a polymorphic function value.  Wave B: `SType::SFunc` now
    /// carries `tpe_params`, so the bare form prints the oracle's leading `[T]` binder
    /// (`[T](T,T) => T`).  Full byte assert (oracle-pinned, ORACLE_TREE_VERSION=3).
    #[test]
    fn predef_env_min_max_bare_accepts_with_type_param_prefix() {
        assert_eq!(type_tc("min"), "(Ident:[T](T,T) => T 'min')");
        assert_eq!(type_tc("max"), "(Ident:[T](T,T) => T 'max')");
        // value form: `{ val x = min; x }` accepts (the SFunc flows through the val),
        // and the block result prints the `[T]` binder too.
        assert_eq!(
            type_tc("{ val x = min; x }"),
            "(Block:[T](T,T) => T [(ValNode:[T](T,T) => T 'x' (Ident:[T](T,T) => T 'min'))] (Ident:[T](T,T) => T 'x'))"
        );
    }

    /// B1 (wave B): SGlobal methods with dedicated-node irBuilders lower on the
    /// `Global.<m>` receiver form too — groupGenerator → GroupGenerator, xor → Xor.
    /// Other SGlobal methods (serialize/…) stay MethodCall.
    #[test]
    fn global_receiver_method_lowers_to_dedicated_node() {
        assert_eq!(
            type_tc("Global.groupGenerator"),
            "(GroupGenerator:GroupElement)"
        );
        assert_eq!(
            type_tce("Global.xor(a, b)"),
            "(Xor:Coll[Byte] (ConstantNode:Coll[Byte] <@1 @2>) (ConstantNode:Coll[Byte] <@3 @4>))"
        );
        // MethodCallIrBuilder SGlobal method still survives as a MethodCall.
        assert!(type_tc("Global.serialize(1)").starts_with("(MethodCall:"));
    }

    /// B5 (wave B): an unapplied polymorphic method Select prints its `[T]`/`[OV]`
    /// binder (carried on `SType::SFunc.tpe_params`).
    #[test]
    fn bare_polymorphic_method_select_prints_type_param_binder() {
        assert_eq!(
            type_tc("SELF.R4"),
            "(Select:[T]() => Option[T] (Self:Box) 'R4')"
        );
        assert_eq!(
            type_tc("SELF.getReg"),
            "(Select:[T](Int) => Option[T] (Self:Box) 'getReg')"
        );
        assert_eq!(
            type_tc("Coll(1, 2, 3).map"),
            "(Select:[OV]((Int) => OV) => Coll[OV] (ConcreteCollection:Coll[Int] [(ConstantNode:Int @1) (ConstantNode:Int @2) (ConstantNode:Int @3)] #Int) 'map')"
        );
        // Applied form collapses the binder away (monomorphic result).
        assert_eq!(
            type_tce("col1.map({(x: Long) => x})"),
            "(MapCollection:Coll[Long] (ConstantNode:Coll[Long] <@1 @2>) (Lambda:(Long) => Long [] [x:#Long] #Long (Ident:Long 'x')))"
        );
    }

    /// A2: because `min`/`max` are in the env, shadowing them in a block is a
    /// duplicate-name error (SigmaTyper.scala:58-59): the 2-arg application form
    /// desugars to `ArithOp` directly, but the bare/shadow forms must see the env
    /// entry.
    #[test]
    fn predef_env_min_shadow_rejects_duplicate() {
        for src in ["{ val min = 1; min }", "{ val max = 1; max }"] {
            let err = type_err(src);
            assert_eq!(err.class_tag(), "TyperException", "{src}");
        }
    }

    /// A2: `PK` is NOT a func ident (it is a binder-only rewrite, `SigmaPredef`
    /// `PKFunc`, not a member of `funcs`).  Removed from the typer env: bare `PK`
    /// rejects (not found), and `{ val PK = 1; PK }` does NOT spuriously duplicate.
    #[test]
    fn predef_env_pk_is_binder_only_not_a_func_ident() {
        assert_eq!(type_err("PK").class_tag(), "TyperException");
        assert_eq!(
            type_tc("{ val PK = 1; PK }"),
            seed_expected("{ val PK = 1; PK }")
        );
    }

    /// §1.11 else-arm: a valid operator on an unsupported receiver (tuple `++`)
    /// → `TyperException` (SigmaTyper.scala:419-420; live oracle §14).
    #[test]
    fn mcl_else_arm_invalid_operation_rejects() {
        let err = type_err("(1, 2) ++ Coll(3)");
        assert_eq!(err.class_tag(), "TyperException");
    }

    /// §1.11 unknown alphanumeric infix (`x foo y`) is rejected at PARSE time
    /// (SigmaParser.scala:99 "Unknown binary operation"), never reaching §1.11.
    /// End-to-end verdict is REJECT, matching the M1-era expectation.
    #[test]
    fn unknown_alpha_infix_rejected_at_parse() {
        assert!(parse("a foo b", 3).is_err(), "`a foo b` must fail to parse");
    }

    /// §1.10: an Apply whose callee is unbound (not env/predef) errors with a
    /// `TyperException` at the callee Ident (SigmaTyper.scala:232 → §1.4).
    #[test]
    fn apply_unbound_callee_errors_typer_exception() {
        // `f(1)` with f unbound binds to Apply(Ident(f), [1]); new_f resolution
        // fails in §1.4.
        let err = type_err("f(1)");
        assert_eq!(err.class_tag(), "TyperException");
    }

    /// §1.12: partial type-argument application is rejected (SigmaTyper.scala:427-429).
    #[test]
    fn apply_types_partial_application_errors() {
        // f: SFunc with NO type params; providing [Long] is a partial application.
        let node = TypedExpr::ApplyTypes {
            input: Box::new(TypedExpr::Ident {
                name: "f".to_string(),
                tpe: SType::SFunc {
                    dom: vec![],
                    range: Box::new(SType::SLong),
                    tpe_params: vec![],
                },
            }),
            type_args: vec![SType::SLong],
            tpe: SType::NoType,
        };
        let env = tenv(&[(
            "f",
            SType::SFunc {
                dom: vec![],
                range: Box::new(SType::SLong),
                tpe_params: vec![],
            },
        )]);
        let err = assign_type(&env, node, &ctx()).expect_err("fail");
        assert_eq!(err.class_tag(), "TyperException");
    }

    /// §1.4/§8.1: a bare `groupGenerator` (no-arg SGlobal property) lowers to the
    /// dedicated GroupGenerator node (E3).  Oracle: `(GroupGenerator:GroupElement)`.
    #[test]
    fn bare_group_generator_lowers_to_group_generator_node() {
        let typed = type_env_res("groupGenerator", &tenv(&[])).expect("types");
        assert!(matches!(typed, TypedExpr::GroupGenerator { .. }));
        assert_eq!(print_typed(&typed), "(GroupGenerator:GroupElement)");
    }

    /// §6 v2-gate rejects: the same explicit-type-arg SGlobal method calls that
    /// accept at v3 (§4) reject with `MethodNotFound` at tree_version 2 (the method
    /// container has no v6 methods).  Verifies the §1.7 getMethod-None path.
    #[test]
    fn v2_gated_global_methods_reject_method_not_found() {
        fn type_v2(src: &str, script_env: &ScriptEnv) -> TyperError {
            let ast = parse(src, 2).expect("parse");
            let bound = bind(script_env, &ast, NetworkPrefix::Testnet, 2).expect("bind");
            assign_type(&predefined_env(2), bound, &TyperCtx::new(2)).expect_err("v2 rejects")
        }
        let demo = demo_script_env();
        for (src, se) in [
            ("Global.fromBigEndianBytes[Long](a)", &demo),
            ("Global.deserializeTo[Long](a)", &demo),
        ] {
            assert_eq!(type_v2(src, se).class_tag(), "MethodNotFound", "{src}");
        }
        assert_eq!(
            type_v2("Global.none[Int]()", &ScriptEnv::new()).class_tag(),
            "MethodNotFound"
        );
    }

    // ----- per-arm units — Apply arms (v6.0.2 SigmaTyper.scala cites inline) -----

    /// §1.7: `SELF.getReg[Long](4)` -> MethodCall with the {T->Long} subst
    /// (SigmaTyper.scala:137-179).
    #[test]
    fn apply_explicit_type_arg_method_is_method_call() {
        let typed = type_env_res("SELF.getReg[Long](4)", &tenv(&[])).expect("types");
        assert_eq!(
            print_typed(&typed),
            "(MethodCall:Option[Long] (Self:Box) %Box.getReg [(ConstantNode:Int @4)] {#T->#Long})"
        );
    }

    /// §1.8 exp-overload: `g.exp(ubi)` renames to expUnsigned when the arg is
    /// UnsignedBigInt (SigmaTyper.scala:188-193) -> MethodCall on expUnsigned.
    #[test]
    fn apply_select_exp_overload_renames_to_exp_unsigned() {
        // A UnsignedBigInt-typed receiver arg via a seeded env (u: UnsignedBigInt).
        let env = tenv(&[("g", SType::SGroupElement), ("u", SType::SUnsignedBigInt)]);
        let typed = type_env_res("g.exp(u)", &env).expect("types");
        // expUnsigned has no dedicated lowering -> survives as MethodCall.
        match &typed {
            TypedExpr::MethodCall { method, .. } => {
                assert_eq!(method.name, "expUnsigned");
                assert_eq!(method.owner, "GroupElement");
            }
            other => panic!("expected MethodCall expUnsigned, got {other:?}"),
        }
    }

    /// §1.8: a method-with-args MethodCall survivor via Apply(Select) — `col1.zip`.
    #[test]
    fn apply_select_method_survives_as_method_call() {
        let typed = type_tce("col1.zip(col2)");
        assert_eq!(typed, seed_expected("col1.zip(col2)"));
        assert!(typed.contains("%SCollection.zip"));
    }

    /// §1.9: `xor(a, b)` lowers to the dedicated Xor node (E3), NOT a MethodCall.
    #[test]
    fn apply_ident_xor_lowers_to_xor_node() {
        let typed = type_res("xor(a, b)", &demo_script_env(), &tenv(&[])).expect("types");
        assert!(matches!(typed, TypedExpr::Xor { .. }));
    }

    /// §1.10: collection const index folds to IntConstant; non-const upcasts to Int.
    #[test]
    fn apply_collection_index_const_and_non_const() {
        // const 0 -> ByIndex with IntConstant(0), no Upcast.
        assert_eq!(
            type_tc("Coll(1, 2, 3)(0)"),
            seed_expected("Coll(1, 2, 3)(0)")
        );
        // non-const Byte index i -> Upcast:Int.
        let src = "{ val i = 1.toByte; Coll(1, 2, 3)(i) }";
        assert_eq!(type_tc(src), seed_expected(src));
    }

    /// §1.10: tuple const index -> 1-based SelectField (SigmaTyper.scala:281-283).
    #[test]
    fn apply_tuple_index_const_is_select_field_one_based() {
        assert_eq!(type_tc("(1, 2L)(1)"), seed_expected("(1, 2L)(1)"));
        assert_eq!(
            type_tc("(1, 2L, HEIGHT)(2)"),
            seed_expected("(1, 2L, HEIGHT)(2)")
        );
    }

    /// §1.12: standalone `getVar[Int]` -> `Ident:(Byte) => Option[Int] 'getVar'`.
    #[test]
    fn apply_types_standalone_ident_substitutes_range() {
        assert_eq!(type_tc("getVar[Int]"), seed_expected("getVar[Int]"));
    }

    /// §8.3 adaptSigmaPropToBoolean (nested): `allOf(Coll(proveDlog(g1)))` wraps the
    /// SigmaProp element in SigmaPropIsProven then re-finalizes the Coll[Boolean]
    /// (SigmaTyper.scala:558-567).  Structural check (the embedded GroupElement
    /// constant renders with an M2 hex placeholder — see SWEEP_SKIP).
    #[test]
    fn adapt_sigma_prop_to_boolean_nested_wraps_is_proven() {
        let typed =
            type_res("allOf(Coll(proveDlog(g1)))", &demo_script_env(), &tenv(&[])).expect("types");
        // allOf -> AND over a Coll[Boolean] whose sole item is SigmaPropIsProven(...).
        match &typed {
            TypedExpr::AND { input, .. } => match input.as_ref() {
                TypedExpr::ConcreteCollection {
                    items, elem_type, ..
                } => {
                    assert_eq!(*elem_type, SType::SBoolean);
                    assert!(matches!(items[0], TypedExpr::SigmaPropIsProven { .. }));
                }
                other => panic!("expected ConcreteCollection, got {other:?}"),
            },
            other => panic!("expected AND, got {other:?}"),
        }
    }

    /// §1.10 predef + §1.8 method GroupElement lowerings (structural — the GE
    /// constant rendering is an M2 deviation, so bytes are not compared): proveDlog
    /// -> CreateProveDlog, atLeast -> AtLeast, proveDHTuple -> CreateProveDHTuple,
    /// g1.exp -> Exponentiate, g1.multiply -> MultiplyGroup, g1.negate -> MethodCall.
    #[test]
    fn group_element_lowerings_produce_dedicated_nodes() {
        let se = demo_script_env();
        let env = tenv(&[]);
        let t = |src: &str| type_res(src, &se, &env).expect("types");
        assert!(matches!(
            t("proveDlog(g1)"),
            TypedExpr::CreateProveDlog { .. }
        ));
        assert!(matches!(
            t("proveDHTuple(g1, g2, g1, g2)"),
            TypedExpr::CreateProveDHTuple { .. }
        ));
        assert!(matches!(
            t("atLeast(1, Coll(proveDlog(g1)))"),
            TypedExpr::AtLeast { .. }
        ));
        assert!(matches!(t("g1.exp(n1)"), TypedExpr::Exponentiate { .. }));
        assert!(matches!(
            t("g1.multiply(g2)"),
            TypedExpr::MultiplyGroup { .. }
        ));
        // negate is a MethodCallIrBuilder property -> MethodCall survivor.
        match t("g1.negate") {
            TypedExpr::MethodCall { method, .. } => {
                assert_eq!(method.owner, "GroupElement");
                assert_eq!(method.name, "negate");
            }
            other => panic!("expected MethodCall, got {other:?}"),
        }
    }

    // ----- carry-forwards from the Task-5 review -----

    /// BitOp `1 | 2L`: `|` is a direct BitOp node (NOT MethodCallLike), no upcast —
    /// the Long operand stays Long (SigmaBuilder.scala:630-637).  Task-5 arm,
    /// oracle-pinned in seed §12.
    #[test]
    fn bit_or_mixed_width_no_upcast() {
        assert_eq!(type_tc("1 | 2L"), seed_expected("1 | 2L"));
    }

    /// §1.18 Xor arm (direct node): bimap over (SByteArray, SByteArray).
    #[test]
    fn xor_arm_over_byte_arrays_types() {
        let ba = |v: Vec<i8>| TypedExpr::Constant {
            value: ConstPayload::ByteColl(v),
            tpe: SType::SColl(Box::new(SType::SByte)),
        };
        let node = TypedExpr::Xor {
            left: Box::new(ba(vec![1, 2])),
            right: Box::new(ba(vec![3, 4])),
            tpe: SType::NoType,
        };
        let typed = assign_type(&tenv(&[]), node, &ctx()).expect("types");
        assert!(matches!(typed, TypedExpr::Xor { .. }));
        assert_eq!(node_tpe(&typed), &SType::SColl(Box::new(SType::SByte)));
    }

    /// §1.18 MultiplyGroup arm (direct node): bimap over (GroupElement, GroupElement).
    #[test]
    fn multiply_group_arm_types() {
        let ge = || TypedExpr::Constant {
            value: ConstPayload::GroupElement([0x02u8; 33]),
            tpe: SType::SGroupElement,
        };
        let node = TypedExpr::MultiplyGroup {
            left: Box::new(ge()),
            right: Box::new(ge()),
            tpe: SType::NoType,
        };
        let typed = assign_type(&tenv(&[]), node, &ctx()).expect("types");
        assert_eq!(node_tpe(&typed), &SType::SGroupElement);
    }

    /// §1.23 BitInversion arm: `~x` over a numeric operand keeps the operand type.
    #[test]
    fn bit_inversion_arm_keeps_numeric_type() {
        let node = TypedExpr::BitInversion {
            input: Box::new(int_const(1)),
            tpe: SType::NoType,
        };
        let typed = assign_type(&tenv(&[]), node, &ctx()).expect("types");
        assert!(matches!(typed, TypedExpr::BitInversion { .. }));
        assert_eq!(node_tpe(&typed), &SType::SInt);
    }

    /// §1.23 Negation on a non-numeric operand (`-true`) rejects with
    /// InvalidUnaryOperationParameters (unmap guard, SigmaTyper.scala:521).
    #[test]
    fn negation_on_boolean_errors_invalid_unary() {
        let node = TypedExpr::Negation {
            input: Box::new(bool_const(true)),
            tpe: SType::NoType,
        };
        let err = assign_type(&tenv(&[]), node, &ctx()).expect_err("fail");
        assert_eq!(err.class_tag(), "InvalidUnaryOperationParameters");
    }

    /// §1.1: a block val whose name is already in the OUTER (env-provided) scope is
    /// a duplicate-definition error (SigmaTyper.scala:58).
    #[test]
    fn block_val_collides_with_env_provided_name_errors() {
        let env = tenv(&[("x", SType::SInt)]);
        let err = type_env_res("{ val x = 5; x }", &env).expect_err("dup name");
        assert_eq!(err.class_tag(), "TyperException");
    }

    // ----- round-trips -----

    /// Determinism: the same source types to the same tree twice.
    #[test]
    fn typecheck_is_deterministic() {
        let src = "{ val x = HEIGHT; if (x > 5) x - 1 else x }";
        assert_eq!(type_tc(src), type_tc(src));
    }

    /// Global post-condition: every typed node has a non-NoType type.
    #[test]
    fn typed_nodes_are_never_no_type() {
        for src in ["{ val x = HEIGHT; x >= 5 }", "(1, 2L, HEIGHT)", "5 - 3"] {
            let typed = type_env_res(src, &TypeEnv::new()).expect("types");
            assert_ne!(node_tpe(&typed), &SType::NoType, "{src}");
        }
    }
}

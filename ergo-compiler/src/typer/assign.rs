//! `assignType` dispatch — the structural arms of `SigmaTyper.assignType`.
//!
//! Port of `SigmaTyper.assignType` (pinned v6.0.2 worktree
//! `/home/rkadias/coding/reference/ergo-core/sigmastate-interpreter-v6.0.2/
//!   sc/shared/src/main/scala/sigma/compiler/phases/SigmaTyper.scala:53-543`).
//! Spec: `dev-docs/m2-recon/m2-typer.md` §1.1-1.25, §5, §6 (with the E1
//! correction from the M2 plan — see below).
//!
//! # Scope (M2 Tasks 5-6 — structural arms + Apply arms + predef lowering)
//!
//! Implemented here (source order matters, first-match): §1.1 Block (E1-lenient),
//! §1.2 Tuple, §1.3 ConcreteCollection, §1.4 Ident, §1.5 Select (resolver),
//! §1.6 Lambda, §1.7 Apply(ApplyTypes(Select…)) explicit type args, §1.8
//! Apply(Select…) method call, §1.9 Apply(Ident) SGlobal method, §1.10 generic
//! Apply (predef funcs / collection & tuple index), §1.12 ApplyTypes, §1.13 If,
//! §1.14 AND/OR, §1.15 relations, §1.16 ArithOp, §1.17 BitOp, §1.18
//! Xor/MultiplyGroup, §1.19 Exponentiate, §1.20 ByIndex, §1.21 SizeOf, §1.22
//! SigmaProp ops, §1.23 unary, §1.24 passthroughs, §1.25 fallthrough.  The §6
//! `bimap`/`bimap2`/`unmap` harness and the predef irBuilder lowering table
//! (`predef_ir.rs`) + method-lowering catalog (`lower_method`) are ported here.
//!
//! Deferred to Task 7 (returned as [`TyperError::NotYetImplemented`], a grep-able
//! marker — never `todo!`/`unimplemented!`): §1.11 MethodCallLike receiver
//! dispatch (the `* ++ || && + ^ << >> >>>` operators).
//!
//! # E1 (CRITICAL) — lenient v6.0.2 Block rule
//!
//! In v6.0.2 the Block `Val`'s explicit annotation is **DISCARDED**: bind
//! `n -> b1.tpe`, `mkVal(n, b1.tpe, b1)`.  The typer-dossier §1.1's
//! `isAssignableTo`/`getResultType` explicit-type check is HEAD-only (a
//! post-6.0.2 commit) and is **NOT** implemented here.  `{ val x: Long = 1; x }`
//! ACCEPTS with `x: SInt` (oracle-confirmed, golden_seed §11).
//!
//! # Positions (deviation)
//!
//! `TypedExpr` carries no source positions (binder.rs; positions surface only in
//! `BindError`).  Every `TyperError` therefore reports `pos = 0`.  This is
//! consistent with the parity policy: reject **class** is graded, reject
//! `line:col` is advisory and captured from the JVM oracle (E5, golden_seed §3).

use crate::span::Pos;
use crate::stype::SType;
use crate::typed::{
    node_tpe, product_prefix, ConstPayload, MethodRef, TypedExpr, ARITH_DIVISION, ARITH_MAX,
    ARITH_MIN, ARITH_MINUS, ARITH_MODULO, ARITH_MULTIPLY, ARITH_PLUS, BIT_AND, BIT_OR, BIT_XOR,
};
use crate::typer::methods::{
    container_exists, get_method, global_method, owner_name_for_type, SMethodDesc,
};
use crate::typer::predef_ir::predef_ir_builder;
use crate::typer::unify::{
    apply_subst, apply_subst_func, arith_op, comparison_op, const_downcast, const_upcast,
    equality_op, is_numeric, msg_type_of, unify_type_lists, unify_types, upcast_to, BuildError,
    TypeSubst,
};
use crate::typer::{coll_elem, is_collection_like, TypeEnv, TyperCtx};

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
/// `NotImplementedError`.  `NotYetImplemented` is a Task-5 handoff marker (not a
/// Scala class): the arm exists in `SigmaTyper` but is ported in Task 6/7.
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
    /// (SigmaTyper.scala:336…; produced by Task 7).
    #[error("{msg} (pos {pos})")]
    NonApplicableMethod { pos: Pos, msg: String },
    /// `scala.NotImplementedError` — `SigmaProp ^ SigmaProp` (SigmaTyper.scala:379;
    /// produced by Task 7).
    #[error("{msg} (pos {pos})")]
    NotImplementedError { pos: Pos, msg: String },
    /// Task 6/7 handoff marker — an in-scope arm reached a node whose typing is
    /// implemented in a later task (Apply/ApplyTypes/MethodCallLike, global
    /// property lowering).  Grep-able; never a panic.
    #[error("typer arm not yet implemented: {arm}")]
    NotYetImplemented { arm: &'static str },
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
            TyperError::NotYetImplemented { .. } => 0,
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
            TyperError::NotYetImplemented { .. } => "NotYetImplemented",
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

// ─────────────────────────────────────────────────────────────────────────────
// Entry point + global post-condition (§0)
// ─────────────────────────────────────────────────────────────────────────────

/// Rewrite a bound `TypedExpr` into a fully typed `TypedExpr`.
///
/// Mirrors `assignType(env, bound)` (SigmaTyper.scala:53-543).  The global
/// post-condition `v.tpe != NoType` (SigmaTyper.scala:541-542) is enforced on
/// every return.
///
/// Exposed `pub` (re-exported from `typer`) to match the crate convention for
/// reachable typer surface (see `unify`/`methods`); the brief's `pub(crate)` can
/// be narrowed once Task 8's `typecheck` API consumes it in-crate.
pub fn assign_type(env: &TypeEnv, e: TypedExpr, ctx: &TyperCtx) -> Result<TypedExpr, TyperError> {
    let result = dispatch(env, e, ctx)?;
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
        // §1.11 MethodCallLike receiver dispatch — Task 7.
        MethodCallLike { .. } => Err(TyperError::NotYetImplemented {
            arm: "MethodCallLike (§1.11, Task 7)",
        }),

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
        }
        | MethodCall { .. }) => Ok(node),

        // §1.25 fallthrough — SigmaTyper.scala:539-540
        other => Err(TyperError::typer(format!(
            "Don't know how to assignType({})",
            product_prefix(&other)
        ))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.1 Block (E1-lenient)
// ─────────────────────────────────────────────────────────────────────────────

fn assign_block(
    env: &TypeEnv,
    bindings: Vec<TypedExpr>,
    result: TypedExpr,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let mut cur_env = env.clone();
    let mut new_binds = Vec::with_capacity(bindings.len());
    for b in bindings {
        let (name, body) = match b {
            TypedExpr::ValNode { name, body, .. } => (name, *body),
            other => {
                return Err(TyperError::typer(format!(
                    "Block binding is not a Val: {}",
                    product_prefix(&other)
                )))
            }
        };
        // Duplicate-name check (SigmaTyper.scala:58-59).
        if let Some(prev) = cur_env.get(&name) {
            return Err(TyperError::typer(format!(
                "Variable {name} already defined ({name} = {prev:?}"
            )));
        }
        let b1 = assign_type(&cur_env, body, ctx)?;
        let b1_tpe = node_tpe(&b1).clone();
        // E1: the Val's explicit annotation is DISCARDED — bind n -> b1.tpe,
        // mkVal(n, b1.tpe, b1) (SigmaTyper.scala:60,62; NOT the HEAD-only
        // isAssignableTo check).
        cur_env.insert(name.clone(), b1_tpe.clone());
        new_binds.push(TypedExpr::ValNode {
            name,
            given_type: b1_tpe.clone(),
            body: Box::new(b1),
            tpe: b1_tpe,
        });
    }
    let result1 = assign_type(&cur_env, result, ctx)?;
    let tpe = node_tpe(&result1).clone();
    Ok(TypedExpr::Block {
        bindings: new_binds,
        result: Box::new(result1),
        tpe,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.3 ConcreteCollection (msgTypeOf — NO numeric widening across elements)
// ─────────────────────────────────────────────────────────────────────────────

fn assign_concrete_collection(
    env: &TypeEnv,
    items: Vec<TypedExpr>,
    elem_type: SType,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let is_empty = items.is_empty();
    let new_items = type_all(env, items, ctx)?;
    // types = newItems.map(_.tpe).distinct (SigmaTyper.scala:546)
    let mut types: Vec<SType> = Vec::new();
    for it in &new_items {
        let t = node_tpe(it).clone();
        if !types.contains(&t) {
            types.push(t);
        }
    }
    let t_item = if is_empty {
        if elem_type == SType::NoType {
            return Err(TyperError::typer(
                "Undefined type of empty collection".to_string(),
            ));
        }
        elem_type
    } else {
        // msgTypeOf(types) (SigmaTyper.scala:552): folds msgType — collections do
        // NOT numeric-widen across elements ([1, 2L] -> None -> error).
        msg_type_of(&types).ok_or_else(|| {
            TyperError::typer(format!(
                "All element of array should have the same type but found {types:?}"
            ))
        })?
    };
    let tpe = SType::SColl(Box::new(t_item.clone()));
    Ok(TypedExpr::ConcreteCollection {
        items: new_items,
        elem_type: t_item,
        tpe,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.4 Ident
// ─────────────────────────────────────────────────────────────────────────────

fn assign_ident(name: &str, env: &TypeEnv, ctx: &TyperCtx) -> Result<TypedExpr, TyperError> {
    // env.get(n) -> mkIdent(n, t) (SigmaTyper.scala:76-77)
    if let Some(t) = env.get(name) {
        return Ok(TypedExpr::Ident {
            name: name.to_string(),
            tpe: t.clone(),
        });
    }
    // None -> SGlobalMethods.method(n): a no-arg global property (tDom.length==1,
    // e.g. `groupGenerator` without parens) -> processGlobalMethod
    // (SigmaTyper.scala:79-82).  groupGenerator lowers to the dedicated
    // GroupGenerator node via processGlobalMethod (§8.1); other no-arg SGlobal
    // properties fall back to a MethodCall(Global, …).
    if let Some(method) = global_method(name, ctx.tree_version) {
        if method.stype.dom.len() == 1 {
            return process_global_method(&method, vec![]);
        }
    }
    // else -> error (SigmaTyper.scala:84)
    Err(TyperError::typer(format!(
        "Cannot assign type for variable '{name}' because it is not found in env"
    )))
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.5 Select(obj, n, None) — the method/property resolver
// ─────────────────────────────────────────────────────────────────────────────

fn assign_select(
    env: &TypeEnv,
    obj: TypedExpr,
    field: String,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let new_obj = assign_type(env, obj, ctx)?;
    let t_obj = node_tpe(&new_obj).clone();
    // newObj.tpe must be SProduct (SigmaTyper.scala:90-91); container_exists is
    // true for every SProduct (incl. the empty SBoolean/SString/SAny/SUnit
    // containers), false for non-product types (SFunc/NoType/STypeVar/...).
    if !container_exists(&t_obj) {
        return Err(TyperError::typer(format!(
            "Cannot get field '{field}' in the object of non-product type {t_obj:?}"
        )));
    }
    // getMethod(tNewObj, n) — None -> MethodNotFound (incl. empty containers, E4).
    let method = get_method(&t_obj, &field, ctx.tree_version).ok_or_else(|| {
        TyperError::method_not_found(format!(
            "Cannot find method '{field}' in the object of Product type {t_obj:?}"
        ))
    })?;

    // Compute tRes (SigmaTyper.scala:97-107).  Every descriptor has an SFunc
    // stype (SFuncSpec), so the SFunc branch always applies.
    let t_meth = &method.stype;
    let t_this = t_meth.dom.first().cloned().unwrap_or(SType::SAny); // dom[0] is always the receiver in practice
    let spec = match unify_types(&t_this, &t_obj) {
        Some(subst) if !subst.is_empty() => apply_subst_func(t_meth, &subst),
        _ => t_meth.clone(),
    };
    let t_res = if spec.dom.len() == 1 && spec.tpe_params.is_empty() {
        // property / nullary method -> tRange
        spec.range.clone()
    } else {
        // function type: drop the receiver, keep remaining args (consumed by Apply)
        SType::SFunc {
            dom: spec.dom_tail().to_vec(),
            range: Box::new(spec.range.clone()),
        }
    };
    let t_res_is_func = matches!(t_res, SType::SFunc { .. });

    // Node choice (SigmaTyper.scala:108-119).
    if method.has_ir_builder && !t_res_is_func {
        // Parameter-less property with a lowering builder.  Custom irBuilders
        // lower to dedicated nodes (SOption.get -> OptionGet, isDefined ->
        // OptionIsDefined); every other property survives as MethodCall (the golden
        // seed shows box/context/avltree/header properties as `%Owner.name [] {}`).
        // Cast methods (toByte..) and SCollection.size have has_ir_builder=false
        // and take the Select branch below (they stay Select until GraphBuilding).
        Ok(lower_method(&t_obj, &field, new_obj, vec![], t_res))
    } else {
        // Select survives: numeric cast methods (no irBuilder) and method-with-args
        // carriers (tRes.isFunc), consumed by an enclosing Apply (Task 6).
        Ok(TypedExpr::Select {
            obj: Box::new(new_obj),
            field,
            res_type: Some(t_res.clone()),
            tpe: t_res,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.6 Lambda
// ─────────────────────────────────────────────────────────────────────────────

fn assign_lambda(
    env: &TypeEnv,
    tpe_params: Vec<crate::typed::STypeParam>,
    args: Vec<(String, SType)>,
    given_res_type: SType,
    body: Option<Box<TypedExpr>>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    // Args must be fully annotated (SigmaTyper.scala:125-127).
    for (name, arg_t) in &args {
        if *arg_t == SType::NoType {
            return Err(TyperError::typer(format!(
                "Invalid function: undefined type of argument {name}"
            )));
        }
    }
    // lambdaEnv = env ++ args (SigmaTyper.scala:128)
    let mut lambda_env = env.clone();
    for (name, arg_t) in &args {
        lambda_env.insert(name.clone(), arg_t.clone());
    }
    let new_body = match body {
        Some(b) => Some(Box::new(assign_type(&lambda_env, *b, ctx)?)),
        None => None,
    };
    // Declared-result check (SigmaTyper.scala:130-133).
    if given_res_type != SType::NoType {
        if let Some(b) = &new_body {
            if given_res_type != *node_tpe(b) {
                return Err(TyperError::typer(format!(
                    "Invalid function: resulting expression type {:?} doesn't equal declared type {given_res_type:?}",
                    node_tpe(b)
                )));
            }
        }
    }
    // mkGenLambda: resultType = newBody.fold(t)(_.tpe) (SigmaTyper.scala:134).
    let result_type = match &new_body {
        Some(b) => node_tpe(b).clone(),
        None => given_res_type,
    };
    let tpe = SType::SFunc {
        dom: args.iter().map(|(_, t)| t.clone()).collect(),
        range: Box::new(result_type.clone()),
    };
    Ok(TypedExpr::Lambda {
        tpe_params,
        args,
        given_res_type: result_type,
        body: new_body,
        tpe,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.13 If, §1.14 AND/OR, §1.19 Exponentiate, §1.20 ByIndex
// ─────────────────────────────────────────────────────────────────────────────

fn assign_if(
    env: &TypeEnv,
    c: TypedExpr,
    t: TypedExpr,
    e: TypedExpr,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let c1 = assign_type(env, c, ctx)?;
    let t1 = assign_type(env, t, ctx)?;
    let e1 = assign_type(env, e, ctx)?;
    let tpe = node_tpe(&t1).clone(); // If.tpe = trueBranch.tpe
                                     // Condition check first, then branch-equality (SigmaTyper.scala:445-448).
    if !matches!(node_tpe(&c1), SType::SBoolean) {
        return Err(TyperError::typer(format!(
            "Invalid type of condition in If: expected Boolean; actual: {:?}",
            node_tpe(&c1)
        )));
    }
    if node_tpe(&t1) != node_tpe(&e1) {
        return Err(TyperError::typer(format!(
            "Invalid type of condition If: both branches should have the same type but was {:?} and {:?}",
            node_tpe(&t1),
            node_tpe(&e1)
        )));
    }
    Ok(TypedExpr::If {
        condition: Box::new(c1),
        true_branch: Box::new(t1),
        false_branch: Box::new(e1),
        tpe,
    })
}

fn assign_and_or(
    env: &TypeEnv,
    input: TypedExpr,
    is_and: bool,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let input1 = assign_type(env, input, ctx)?;
    // require input1.tpe.isCollection && elemType == SBoolean (SigmaTyper.scala:453/459)
    let ok = matches!(node_tpe(&input1), SType::SColl(e) if **e == SType::SBoolean);
    if !ok {
        let opn = if is_and { "AND" } else { "OR" };
        return Err(TyperError::typer(format!(
            "Invalid operation {opn}: {:?}",
            node_tpe(&input1)
        )));
    }
    Ok(if is_and {
        TypedExpr::AND {
            input: Box::new(input1),
            tpe: SType::SBoolean,
        }
    } else {
        TypedExpr::OR {
            input: Box::new(input1),
            tpe: SType::SBoolean,
        }
    })
}

fn assign_exponentiate(
    env: &TypeEnv,
    ctx: &TyperCtx,
    left: TypedExpr,
    right: TypedExpr,
) -> Result<TypedExpr, TyperError> {
    let l1 = assign_type(env, left, ctx)?;
    let r1 = assign_type(env, right, ctx)?;
    // require exactly (SGroupElement, SBigInt) (SigmaTyper.scala:488-489)
    if !matches!(node_tpe(&l1), SType::SGroupElement) || !matches!(node_tpe(&r1), SType::SBigInt) {
        return Err(TyperError::typer(format!(
            "Invalid binary operation Exponentiate: expected argument types (GroupElement, BigInt); actual: ({:?}, {:?})",
            node_tpe(&l1),
            node_tpe(&r1)
        )));
    }
    Ok(TypedExpr::Exponentiate {
        left: Box::new(l1),
        right: Box::new(r1),
        tpe: SType::SGroupElement,
    })
}

fn assign_byindex(
    env: &TypeEnv,
    ctx: &TyperCtx,
    input: TypedExpr,
    index: Box<TypedExpr>,
    default: Option<Box<TypedExpr>>,
) -> Result<TypedExpr, TyperError> {
    let c1 = assign_type(env, input, ctx)?;
    // require isCollectionLike (SigmaTyper.scala:494)
    let elem = match coll_elem(node_tpe(&c1)) {
        Some(e) => e.clone(),
        None => {
            return Err(TyperError::typer(format!(
                "Invalid operation ByIndex: expected Collection argument type; actual: {:?}",
                node_tpe(&c1)
            )))
        }
    };
    // default value type must match the element type (SigmaTyper.scala:497-498).
    // deviation: Scala compares typeCode (which ignores type args); we compare
    // structural equality.  ByIndex is not produced by the binder or any in-scope
    // arm — the index/default carry pre-typed children and are passed through
    // un-retyped, exactly as Scala does (SigmaTyper.scala:499).
    if let Some(v) = &default {
        if *node_tpe(v) != elem {
            return Err(TyperError::typer(format!(
                "Invalid operation ByIndex: expected default value type ({elem:?}); actual: ({:?})",
                node_tpe(v)
            )));
        }
    }
    Ok(TypedExpr::ByIndex {
        input: Box::new(c1),
        index,
        default,
        tpe: elem,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.7-1.10 Apply arms + §1.12 ApplyTypes (SigmaTyper.scala:137-300, 423-438)
// ─────────────────────────────────────────────────────────────────────────────

/// Route an `Apply(func, args)` to the correct arm (source order is load-bearing):
/// §1.7 `Apply(ApplyTypes(Select…, [T]), …)`, §1.8 `Apply(Select…, …)`,
/// §1.9 `Apply(Ident, …)` when the ident names a SGlobal method, else §1.10.
fn assign_apply(
    env: &TypeEnv,
    func: TypedExpr,
    args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    // §1.7 — Apply(ApplyTypes(Select(obj, n, _), Seq(rangeTpe)), args).
    if let TypedExpr::ApplyTypes {
        input, type_args, ..
    } = &func
    {
        if type_args.len() == 1 {
            if let TypedExpr::Select { obj, field, .. } = input.as_ref() {
                return assign_apply_explicit_method(
                    env,
                    obj.as_ref().clone(),
                    field.clone(),
                    type_args[0].clone(),
                    args,
                    ctx,
                );
            }
        }
    }
    // §1.8 — Apply(Select(obj, nOriginal, resType), args).
    if let TypedExpr::Select {
        obj,
        field,
        res_type,
        ..
    } = &func
    {
        return assign_apply_select(
            env,
            obj.as_ref().clone(),
            field.clone(),
            res_type.clone(),
            args,
            ctx,
        );
    }
    // §1.9 — Apply(Ident, args) if SGlobalMethods.hasMethod(ident.name).
    if let TypedExpr::Ident { name, .. } = &func {
        if let Some(method) = global_method(name, ctx.tree_version) {
            let new_args = type_all(env, args, ctx)?;
            return process_global_method(&method, new_args);
        }
    }
    // §1.10 — generic application.
    assign_apply_generic(env, func, args, ctx)
}

/// §1.7 `Apply(ApplyTypes(Select(obj, n, _), Seq(rangeTpe)), args)` —
/// SigmaTyper.scala:137-179 (`obj.m[T](args)` explicit type args on a method).
fn assign_apply_explicit_method(
    env: &TypeEnv,
    obj: TypedExpr,
    field: String,
    range_tpe: SType,
    args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    // getVarFromInput arg-narrow (SigmaTyper.scala:139-147): both args are
    // numeric constants -> (Short, Byte).  Range-checked via const_downcast
    // (Scala toShortExact/toByteExact throw ArithmeticException on overflow;
    // we propagate as TyperError — verdict parity, class-tag differs).
    let n_args = if field == "getVarFromInput"
        && args.len() == 2
        && numeric_const_value(&args[0]).is_some()
        && numeric_const_value(&args[1]).is_some()
    {
        vec![
            narrow_numeric_const_to(&args[0], &SType::SShort, ctx.tree_version)?,
            narrow_numeric_const_to(&args[1], &SType::SByte, ctx.tree_version)?,
        ]
    } else {
        args
    };

    let new_obj = assign_type(env, obj, ctx)?;
    let t_obj = node_tpe(&new_obj).clone();
    let new_args = type_all(env, n_args, ctx)?;
    if !container_exists(&t_obj) {
        return Err(TyperError::typer(format!(
            "Cannot get field '{field}' in the object of non-product type {t_obj:?}"
        )));
    }
    let method = get_method(&t_obj, &field, ctx.tree_version).ok_or_else(|| {
        TyperError::method_not_found(format!(
            "Cannot find method '{field}' in the object of Product type {t_obj:?}"
        ))
    })?;
    // subst = Map(genFunTpe.tpeParams.head.ident -> rangeTpe) (SigmaTyper.scala:156).
    let tparam = method.stype.tpe_params.first().ok_or_else(|| {
        TyperError::typer(format!("Method '{field}' has no type parameter for [T]"))
    })?;
    let subst: TypeSubst = std::iter::once((tparam.clone(), range_tpe.clone())).collect();
    let concr = apply_subst_func(&method.stype, &subst);
    let expected_args = concr.dom_tail();
    let actual_types: Vec<SType> = new_args.iter().map(|a| node_tpe(a).clone()).collect();
    if expected_args.len() != actual_types.len()
        || !expected_args
            .iter()
            .zip(&actual_types)
            .all(|(ea, na)| *ea == SType::SAny || ea == na)
    {
        return Err(TyperError::typer(format!(
            "For method {field} expected args: {expected_args:?}; actual: {actual_types:?}"
        )));
    }
    if method.has_ir_builder {
        // Every §1.7-reachable method (some/none/getReg/deserializeTo/
        // fromBigEndianBytes/getVarFromInput) uses a MethodCallIrBuilder that lifts
        // to a MethodCall carrying the {T->rangeTpe} substitution (seed §4).
        let owner = owner_name_for_type(&t_obj).ok_or_else(|| {
            TyperError::typer(format!("No MethodCall owner name for type {t_obj:?}"))
        })?;
        Ok(TypedExpr::MethodCall {
            obj: Box::new(new_obj),
            method: MethodRef {
                owner: owner.to_string(),
                name: field,
            },
            args: new_args,
            type_subst: vec![(tparam.clone(), range_tpe)],
            tpe: concr.range,
        })
    } else {
        // mkApply(mkSelect(newObj, n, Some(concrFunTpe)), newArgs).
        let concr_ty = spec_to_stype(&concr);
        let sel = TypedExpr::Select {
            obj: Box::new(new_obj),
            field,
            res_type: Some(concr_ty.clone()),
            tpe: concr_ty,
        };
        Ok(TypedExpr::Apply {
            func: Box::new(sel),
            args: new_args,
            tpe: concr.range,
        })
    }
}

/// §1.8 `Apply(Select(obj, nOriginal, resType), args)` — SigmaTyper.scala:181-223
/// (`obj.m(args)`).
fn assign_apply_select(
    env: &TypeEnv,
    obj: TypedExpr,
    n_original: String,
    res_type: Option<SType>,
    args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let new_args = type_all(env, args, ctx)?;
    // exp -> expUnsigned hack (SigmaTyper.scala:188-193).
    let n = if n_original == "exp"
        && new_args
            .first()
            .is_some_and(|a| matches!(node_tpe(a), SType::SUnsignedBigInt))
    {
        "expUnsigned".to_string()
    } else {
        n_original
    };
    // newSel = assignType(Select(obj, n, resType)) — re-runs §1.5.
    let sel = TypedExpr::Select {
        obj: Box::new(obj.clone()),
        field: n.clone(),
        res_type,
        tpe: SType::NoType,
    };
    let new_sel = assign_type(env, sel, ctx)?;
    match node_tpe(&new_sel).clone() {
        SType::SFunc {
            dom: arg_types,
            range: _,
        } => {
            let new_obj = assign_type(env, obj, ctx)?;
            let new_arg_types: Vec<SType> = new_args.iter().map(|a| node_tpe(a).clone()).collect();
            match unify_type_lists(&arg_types, &new_arg_types) {
                Some(subst) => {
                    let concr = apply_subst(node_tpe(&new_sel), &subst);
                    let (concr_dom, concr_range) = func_parts(&concr);
                    let t_obj = node_tpe(&new_obj).clone();
                    match get_method(&t_obj, &n, ctx.tree_version) {
                        Some(method) if method.has_ir_builder => {
                            // expectedArgs = concrFunTpe.tDom (receiver already dropped).
                            if concr_dom.len() != new_arg_types.len()
                                || !concr_dom
                                    .iter()
                                    .zip(&new_arg_types)
                                    .all(|(ea, na)| *ea == SType::SAny || ea == na)
                            {
                                return Err(TyperError::typer(format!(
                                    "For method {n} expected args: {concr_dom:?}; actual: {new_arg_types:?}"
                                )));
                            }
                            Ok(lower_method(&t_obj, &n, new_obj, new_args, concr_range.clone()))
                        }
                        _ => {
                            // mkApply(mkSelect(newObj, n, Some(concrFunTpe)), newArgs).
                            let sel2 = TypedExpr::Select {
                                obj: Box::new(new_obj),
                                field: n,
                                res_type: Some(concr.clone()),
                                tpe: concr,
                            };
                            Ok(TypedExpr::Apply {
                                func: Box::new(sel2),
                                args: new_args,
                                tpe: concr_range.clone(),
                            })
                        }
                    }
                }
                None => Err(TyperError::typer(format!(
                    "Invalid argument type of application: expected {arg_types:?}; actual: {new_arg_types:?}"
                ))),
            }
        }
        // else -> mkApply(newSel, newArgs) (newSel is not a function type).
        other => {
            let tpe = apply_result_tpe(&other);
            Ok(TypedExpr::Apply {
                func: Box::new(new_sel),
                args: new_args,
                tpe,
            })
        }
    }
}

/// §1.10 `Apply(f, args)` — SigmaTyper.scala:231-300 (generic application:
/// predefined funcs, collection indexing, tuple indexing).
fn assign_apply_generic(
    env: &TypeEnv,
    f: TypedExpr,
    args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let new_f = assign_type(env, f, ctx)?;
    match node_tpe(&new_f).clone() {
        // Predefined function application (SigmaTyper.scala:233-259).
        SType::SFunc { dom, range } => {
            if args.len() != dom.len() {
                return Err(TyperError::typer(
                    "Invalid argument type of application: invalid number of arguments".to_string(),
                ));
            }
            let typed_args = type_all(env, args, ctx)?;
            let adapted = adapt_apply_args(&new_f, typed_args, ctx)?;
            let actual: Vec<SType> = adapted.iter().map(|a| node_tpe(a).clone()).collect();
            if unify_type_lists(&dom, &actual).is_none() {
                return Err(TyperError::typer(format!(
                    "Invalid argument type of application: expected {dom:?}; actual after typing: {actual:?}"
                )));
            }
            // PredefinedFuncApply post-wrapper (SigmaTyper.scala:297-299).
            if let TypedExpr::Ident { name, .. } = &new_f {
                if let Some(res) = predef_ir_builder(name, &new_f, &adapted) {
                    return res;
                }
            }
            Ok(TypedExpr::Apply {
                func: Box::new(new_f),
                args: adapted,
                tpe: *range,
            })
        }
        // Collection indexing `coll(i)` (SigmaTyper.scala:261-277).
        SType::SColl(elem) => assign_collection_index(env, new_f, args, *elem, ctx),
        // Tuple indexing `tup(i)` (SigmaTyper.scala:278-294).
        SType::STuple(items) => assign_tuple_index(env, new_f, args, items, ctx),
        other => Err(TyperError::typer(format!(
            "Invalid array application: array type is expected but was {other:?}"
        ))),
    }
}

/// Collection application `coll(i)` (SigmaTyper.scala:261-277).
fn assign_collection_index(
    env: &TypeEnv,
    new_f: TypedExpr,
    mut args: Vec<TypedExpr>,
    elem: SType,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    if args.len() != 1 {
        return Err(TyperError::typer(
            "Invalid argument of array application: expected integer value".to_string(),
        ));
    }
    let index = args.pop().unwrap();
    // Seq(c @ Constant(index, _: SNumericType)) -> IntConstant(SInt.upcast(index)).
    if let Some((payload, ctype)) = numeric_constant_parts(&index) {
        let folded = const_upcast(&payload, &ctype, &SType::SInt, ctx.tree_version)
            .map_err(build_to_typer)?;
        return Ok(TypedExpr::ByIndex {
            input: Box::new(new_f),
            index: Box::new(TypedExpr::Constant {
                value: folded,
                tpe: SType::SInt,
            }),
            default: None,
            tpe: elem,
        });
    }
    // Seq(index) -> typedIndex.upcastTo(SInt) if numeric, else error.
    let typed_index = assign_type(env, index, ctx)?;
    if !is_numeric(node_tpe(&typed_index)) {
        return Err(TyperError::typer(format!(
            "Invalid argument type of array application: expected numeric type; actual: {:?}",
            node_tpe(&typed_index)
        )));
    }
    let idx = upcast_to(typed_index, &SType::SInt).map_err(build_to_typer)?;
    Ok(TypedExpr::ByIndex {
        input: Box::new(new_f),
        index: Box::new(idx),
        default: None,
        tpe: elem,
    })
}

/// Tuple application `tup(i)` (SigmaTyper.scala:278-294).
fn assign_tuple_index(
    env: &TypeEnv,
    new_f: TypedExpr,
    mut args: Vec<TypedExpr>,
    items: Vec<SType>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    if args.len() != 1 {
        return Err(TyperError::typer(
            "Invalid argument of tuple application: expected integer value".to_string(),
        ));
    }
    let index = args.pop().unwrap();
    // Seq(Constant(index, _: SNumericType)) -> SelectField(tup, SByte.downcast(index)+1).
    if let Some((payload, ctype)) = numeric_constant_parts(&index) {
        let narrowed = const_downcast(&payload, &ctype, &SType::SByte, ctx.tree_version)
            .map_err(build_to_typer)?;
        let byte_idx = match narrowed {
            ConstPayload::Byte(v) => v,
            _ => unreachable!("const_downcast to SByte yields a Byte payload"),
        };
        let field_index = byte_idx as i16 + 1; // 1-based
        if field_index < 1 || field_index as usize > items.len() {
            return Err(TyperError::typer(format!(
                "Invalid tuple field index {field_index} for tuple of arity {}",
                items.len()
            )));
        }
        let tpe = items[(field_index as usize) - 1].clone();
        return Ok(TypedExpr::SelectField {
            input: Box::new(new_f),
            field_index: field_index as i8,
            tpe,
        });
    }
    // Seq(index) non-const -> mkByIndex(new_f.asCollection[SAny], upcastTo(SInt), None).
    let typed_index = assign_type(env, index, ctx)?;
    if !is_numeric(node_tpe(&typed_index)) {
        return Err(TyperError::typer(format!(
            "Invalid argument type of tuple application: expected numeric type; actual: {:?}",
            node_tpe(&typed_index)
        )));
    }
    let idx = upcast_to(typed_index, &SType::SInt).map_err(build_to_typer)?;
    Ok(TypedExpr::ByIndex {
        input: Box::new(new_f),
        index: Box::new(idx),
        default: None,
        tpe: SType::SAny,
    })
}

/// §1.12 `ApplyTypes(input, targs)` — SigmaTyper.scala:423-438 (standalone `f[T]`).
fn assign_apply_types(
    env: &TypeEnv,
    input: TypedExpr,
    type_args: Vec<SType>,
    ctx: &TyperCtx,
) -> Result<TypedExpr, TyperError> {
    let new_input = assign_type(env, input, ctx)?;
    match node_tpe(&new_input).clone() {
        SType::SFunc { dom, range } => {
            // tpeParams recovered as the free type vars of the SFunc, in
            // first-appearance order (our SType::SFunc has no tpeParams slot).
            let tpe_params = free_type_vars(&dom, &range);
            if tpe_params.len() != type_args.len() {
                return Err(TyperError::typer(format!(
                    "Wrong number of type arguments: expected {tpe_params:?} but provided {type_args:?}. \
                     Note that partial application of type parameters is not supported."
                )));
            }
            let subst: TypeSubst = tpe_params.into_iter().zip(type_args).collect();
            let concr = apply_subst(node_tpe(&new_input), &subst);
            match new_input {
                TypedExpr::Select { obj, field, .. } => {
                    // mkSelect(obj, n, Some(concrFunTpe.tRange)).
                    let (_, concr_range) = func_parts(&concr);
                    let r = concr_range.clone();
                    Ok(TypedExpr::Select {
                        obj,
                        field,
                        res_type: Some(r.clone()),
                        tpe: r,
                    })
                }
                TypedExpr::Ident { name, .. } => {
                    // mkIdent(name, concrFunTpe).
                    Ok(TypedExpr::Ident { name, tpe: concr })
                }
                other => Err(TyperError::typer(format!(
                    "Invalid application of type arguments: unexpected input {}",
                    product_prefix(&other)
                ))),
            }
        }
        _ => Err(TyperError::typer(
            "Invalid application of type arguments: function doesn't have type parameters"
                .to_string(),
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// processGlobalMethod (§8.1) + the method-lowering catalog
// ─────────────────────────────────────────────────────────────────────────────

/// `processGlobalMethod(srcCtx, method, args)` — SigmaTyper.scala:38-48.
/// groupGenerator -> GroupGenerator, xor -> Xor (their custom irBuilders), all
/// other SGlobal methods fall back to MethodCall(Global, …).
fn process_global_method(
    method: &SMethodDesc,
    args: Vec<TypedExpr>,
) -> Result<TypedExpr, TyperError> {
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

/// The shared method/property irBuilder lowering catalog.
///
/// Maps custom-irBuilder methods to their dedicated typed nodes; everything else
/// (MethodCallIrBuilder) falls back to `MethodCall(obj, %Owner.name, args, {})`.
/// Keyed on `(receiver type, method name)` — receiver-specific because e.g.
/// `SCollection.map` lowers to `MapCollection` while `SOption.map` survives as a
/// MethodCall (seed line 21 vs 107).  `ret` is the method's specialized return
/// type.  Used by §1.5 (properties, `args = []`) and §1.8 (methods with args).
fn lower_method(
    recv: &SType,
    name: &str,
    obj: TypedExpr,
    args: Vec<TypedExpr>,
    ret: SType,
) -> TypedExpr {
    let b = Box::new;
    let mut it = args.clone().into_iter();
    match (recv, name) {
        // ── SOption custom irBuilders ─────────────────────────────────────────
        (SType::SOption(_), "get") => TypedExpr::OptionGet {
            input: b(obj),
            tpe: ret,
        },
        (SType::SOption(_), "isDefined") => TypedExpr::OptionIsDefined {
            input: b(obj),
            tpe: ret,
        },
        (SType::SOption(_), "getOrElse") => TypedExpr::OptionGetOrElse {
            input: b(obj),
            default: b(it.next().expect("getOrElse arg")),
            tpe: ret,
        },
        // ── SCollection custom irBuilders ─────────────────────────────────────
        (SType::SColl(_), "map") => TypedExpr::MapCollection {
            input: b(obj),
            mapper: b(it.next().expect("map arg")),
            tpe: ret,
        },
        (SType::SColl(_), "filter") => TypedExpr::Filter {
            input: b(obj),
            condition: b(it.next().expect("filter arg")),
            tpe: ret,
        },
        (SType::SColl(_), "exists") => TypedExpr::Exists {
            input: b(obj),
            condition: b(it.next().expect("exists arg")),
            tpe: ret,
        },
        (SType::SColl(_), "forall") => TypedExpr::ForAll {
            input: b(obj),
            condition: b(it.next().expect("forall arg")),
            tpe: ret,
        },
        (SType::SColl(_), "fold") => {
            let zero = it.next().expect("fold zero");
            let fold_op = it.next().expect("fold op");
            TypedExpr::Fold {
                input: b(obj),
                zero: b(zero),
                fold_op: b(fold_op),
                tpe: ret,
            }
        }
        (SType::SColl(_), "slice") => {
            let from = it.next().expect("slice from");
            let until = it.next().expect("slice until");
            TypedExpr::Slice {
                input: b(obj),
                from: b(from),
                until: b(until),
                tpe: ret,
            }
        }
        (SType::SColl(_), "append") => TypedExpr::Append {
            input: b(obj),
            col2: b(it.next().expect("append arg")),
            tpe: ret,
        },
        (SType::SColl(_), "getOrElse") => {
            let index = it.next().expect("getOrElse index");
            let default = it.next().expect("getOrElse default");
            TypedExpr::ByIndex {
                input: b(obj),
                index: b(index),
                default: Some(b(default)),
                tpe: ret,
            }
        }
        // ── SGroupElement custom irBuilders ──────────────────────────────────
        (SType::SGroupElement, "exp") => TypedExpr::Exponentiate {
            left: b(obj),
            right: b(it.next().expect("exp arg")),
            tpe: ret,
        },
        (SType::SGroupElement, "multiply") => TypedExpr::MultiplyGroup {
            left: b(obj),
            right: b(it.next().expect("multiply arg")),
            tpe: ret,
        },
        // ── everything else: MethodCall(obj, %Owner.name, args, {}) ──────────
        _ => {
            let owner = owner_name_for_type(recv).unwrap_or("?");
            TypedExpr::MethodCall {
                obj: b(obj),
                method: MethodRef {
                    owner: owner.to_string(),
                    name: name.to_string(),
                },
                args,
                type_subst: vec![],
                tpe: ret,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// arg adaptation (§8.3 adaptSigmaPropToBoolean + getVar-family narrowing)
// ─────────────────────────────────────────────────────────────────────────────

/// §1.10 arg adaptation (SigmaTyper.scala:241-252): allOf/anyOf coerce SigmaProp
/// elements to Boolean; getVar/executeFromVar/getVarFromInput narrow constant ids.
fn adapt_apply_args(
    new_f: &TypedExpr,
    typed_args: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<Vec<TypedExpr>, TyperError> {
    let name = match new_f {
        TypedExpr::Ident { name, .. } => name.as_str(),
        _ => return Ok(typed_args),
    };
    match name {
        "allOf" | "anyOf" => {
            // adaptSigmaPropToBoolean(typedArgs, argTypes) with argTypes = [Coll[Bool]].
            adapt_sigma_prop_to_boolean(typed_args, &[SType::SColl(Box::new(SType::SBoolean))])
        }
        // Range-checked via const_downcast (Scala toByteExact throws ArithmeticException
        // on overflow; we propagate as TyperError — verdict parity, class-tag differs).
        "getVar" | "executeFromVar"
            if typed_args.len() == 1 && numeric_const_value(&typed_args[0]).is_some() =>
        {
            Ok(vec![narrow_numeric_const_to(
                &typed_args[0],
                &SType::SByte,
                ctx.tree_version,
            )?])
        }
        "getVarFromInput"
            if typed_args.len() == 2
                && numeric_const_value(&typed_args[0]).is_some()
                && numeric_const_value(&typed_args[1]).is_some() =>
        {
            Ok(vec![
                narrow_numeric_const_to(&typed_args[0], &SType::SShort, ctx.tree_version)?,
                narrow_numeric_const_to(&typed_args[1], &SType::SByte, ctx.tree_version)?,
            ])
        }
        _ => Ok(typed_args),
    }
}

/// `adaptSigmaPropToBoolean(items, expectedTypes)` — SigmaTyper.scala:558-567.
fn adapt_sigma_prop_to_boolean(
    items: Vec<TypedExpr>,
    expected: &[SType],
) -> Result<Vec<TypedExpr>, TyperError> {
    let bool_array = SType::SColl(Box::new(SType::SBoolean));
    let mut out = Vec::with_capacity(items.len());
    for (i, it) in items.into_iter().enumerate() {
        let exp = expected.get(i);
        match (it, exp) {
            // (cc: ConcreteCollection, SBooleanArray) -> recurse + finalize.
            (
                TypedExpr::ConcreteCollection {
                    items: inner_items, ..
                },
                Some(e),
            ) if *e == bool_array => {
                let filled = vec![SType::SBoolean; inner_items.len()];
                let adapted = adapt_sigma_prop_to_boolean(inner_items, &filled)?;
                out.push(finalize_collection(adapted)?);
            }
            // (it, SBoolean) where it.tpe == SSigmaProp -> SigmaPropIsProven(it).
            (it, Some(e)) if *e == SType::SBoolean && *node_tpe(&it) == SType::SSigmaProp => {
                out.push(TypedExpr::SigmaPropIsProven {
                    input: Box::new(it),
                    tpe: SType::SBoolean,
                });
            }
            (it, _) => out.push(it),
        }
    }
    Ok(out)
}

/// `assignConcreteCollection(cc, items)` over ALREADY-TYPED items (no re-typing) —
/// SigmaTyper.scala:545-556.  Computes the element type via msgTypeOf.
fn finalize_collection(items: Vec<TypedExpr>) -> Result<TypedExpr, TyperError> {
    let mut types: Vec<SType> = Vec::new();
    for it in &items {
        let t = node_tpe(it).clone();
        if !types.contains(&t) {
            types.push(t);
        }
    }
    let t_item = if items.is_empty() {
        return Err(TyperError::typer(
            "Undefined type of empty collection".to_string(),
        ));
    } else {
        msg_type_of(&types).ok_or_else(|| {
            TyperError::typer(format!(
                "All element of array should have the same type but found {types:?}"
            ))
        })?
    };
    Ok(TypedExpr::ConcreteCollection {
        tpe: SType::SColl(Box::new(t_item.clone())),
        items,
        elem_type: t_item,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// small helpers for the Apply arms
// ─────────────────────────────────────────────────────────────────────────────

/// Numeric value of a numeric `Constant` (Byte/Short/Int/Long), else `None`.
fn numeric_const_value(e: &TypedExpr) -> Option<i64> {
    numeric_constant_parts(e).map(|(payload, _)| match payload {
        ConstPayload::Byte(v) => v as i64,
        ConstPayload::Short(v) => v as i64,
        ConstPayload::Int(v) => v as i64,
        ConstPayload::Long(v) => v,
        _ => unreachable!("numeric_constant_parts only yields numeric payloads"),
    })
}

/// `(payload, type)` of a numeric `Constant` (Byte/Short/Int/Long/BigInt), else
/// `None`.  Mirrors the `Constant(index, _: SNumericType)` match arms.
fn numeric_constant_parts(e: &TypedExpr) -> Option<(ConstPayload, SType)> {
    match e {
        TypedExpr::Constant { value, tpe } => match value {
            ConstPayload::Byte(_)
            | ConstPayload::Short(_)
            | ConstPayload::Int(_)
            | ConstPayload::Long(_)
            | ConstPayload::BigInt(_) => Some((value.clone(), tpe.clone())),
            _ => None,
        },
        _ => None,
    }
}

/// Range-check and narrow a numeric constant to `target` via Scala's
/// `SByte.downcast` / `SShort.downcast` (= `toByteExact` / `toShortExact`).
///
/// Scala throws `ArithmeticException` on overflow; we return `Err(TyperError)`.
/// Verdict parity is exact (both sides REJECT on out-of-range input).
/// Class-tag deviation: ArithmeticException vs TyperError — recorded in
/// lib.rs § "Known M2 deviations".
fn narrow_numeric_const_to(
    e: &TypedExpr,
    target: &SType,
    tree_version: u8,
) -> Result<TypedExpr, TyperError> {
    let (payload, ctype) = numeric_constant_parts(e).ok_or_else(|| {
        TyperError::typer("narrow_numeric_const_to: not a numeric constant".to_string())
    })?;
    let narrowed =
        const_downcast(&payload, &ctype, target, tree_version).map_err(build_to_typer)?;
    Ok(TypedExpr::Constant {
        value: narrowed,
        tpe: target.clone(),
    })
}

/// Destructure an `SType::SFunc` into `(dom, range)`; empty/NoType for non-funcs.
fn func_parts(t: &SType) -> (Vec<SType>, SType) {
    match t {
        SType::SFunc { dom, range } => (dom.clone(), (**range).clone()),
        _ => (vec![], SType::NoType),
    }
}

/// Convert an `SFuncSpec` to the `SType::SFunc` shape (tpeParams dropped — our
/// `SType::SFunc` has no slot; the free type vars still live in dom/range).
fn spec_to_stype(spec: &crate::typer::unify::SFuncSpec) -> SType {
    SType::SFunc {
        dom: spec.dom.clone(),
        range: Box::new(spec.range.clone()),
    }
}

/// `mkApply` result type: the callee's `SFunc` range, else `NoType` (the global
/// post-condition then rejects — matching Scala's `Apply.tpe`).
fn apply_result_tpe(func_tpe: &SType) -> SType {
    match func_tpe {
        SType::SFunc { range, .. } => (**range).clone(),
        _ => SType::NoType,
    }
}

/// Free type variables of an `SFunc(dom, range)` in first-appearance order.
/// Recovers the `tpeParams` that `SType::SFunc` cannot carry, for §1.12.
fn free_type_vars(dom: &[SType], range: &SType) -> Vec<String> {
    let mut acc = Vec::new();
    for d in dom {
        collect_type_vars(d, &mut acc);
    }
    collect_type_vars(range, &mut acc);
    acc
}

fn collect_type_vars(t: &SType, acc: &mut Vec<String>) {
    match t {
        SType::STypeVar(n) if !acc.contains(n) => acc.push(n.clone()),
        SType::STypeVar(_) => {}
        SType::SColl(e) | SType::SOption(e) => collect_type_vars(e, acc),
        SType::STuple(items) => {
            for i in items {
                collect_type_vars(i, acc);
            }
        }
        SType::SFunc { dom, range } => {
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

/// Map a builder-layer error to a typer exception (the `mkByIndex`/`upcastTo`
/// paths are outside `bimap`, so their throws surface as generic rejections).
fn build_to_typer(be: BuildError) -> TyperError {
    TyperError::typer(format!("{be:?}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// §1.16 ArithOp / §1.17 BitOp arms
// ─────────────────────────────────────────────────────────────────────────────

fn assign_arith(
    env: &TypeEnv,
    ctx: &TyperCtx,
    left: TypedExpr,
    right: TypedExpr,
    opcode: i8,
) -> Result<TypedExpr, TyperError> {
    // Map opcode -> op symbol (SigmaTyper.scala:470-476).  Unknown opcodes fall to
    // the §1.25 fallthrough in Scala (no matching ArithOp arm).
    let op = match opcode {
        ARITH_MINUS => "-",
        ARITH_PLUS => "+",
        ARITH_MULTIPLY => "*",
        ARITH_MODULO => "%",
        ARITH_DIVISION => "/",
        ARITH_MIN => "min",
        ARITH_MAX => "max",
        _ => {
            return Err(TyperError::typer(format!(
                "Don't know how to assignType(ArithOp opcode {opcode})"
            )))
        }
    };
    // mk*: arith_op (upcast, no constraint) then ArithOp; tpe = left.tpe post-upcast.
    bimap(
        env,
        ctx,
        op,
        left,
        right,
        move |l, r| {
            let (l, r) = arith_op(l, r)?;
            let tpe = node_tpe(&l).clone();
            Ok(TypedExpr::ArithOp {
                left: Box::new(l),
                right: Box::new(r),
                opcode,
                tpe,
            })
        },
        tt(),
        tt(),
    )
}

fn assign_bitop(
    env: &TypeEnv,
    ctx: &TyperCtx,
    left: TypedExpr,
    right: TypedExpr,
    opcode: i8,
) -> Result<TypedExpr, TyperError> {
    let op = match opcode {
        BIT_OR => "|",
        BIT_AND => "&",
        BIT_XOR => "^",
        _ => {
            return Err(TyperError::typer(format!(
                "Don't know how to assignType(BitOp opcode {opcode})"
            )))
        }
    };
    // mkBitOr/And/Xor build BitOp DIRECTLY — NO upcast (SigmaBuilder.scala:630-637;
    // oracle: `1 | 2L` -> BitOp:Int with a Long operand).  tpe = left.tpe.
    bimap(
        env,
        ctx,
        op,
        left,
        right,
        move |l, r| {
            let tpe = node_tpe(&l).clone();
            Ok(TypedExpr::BitOp {
                left: Box::new(l),
                right: Box::new(r),
                opcode,
                tpe,
            })
        },
        tt(),
        tt(),
    )
}

// ----- relation / equality node builders (the builder-op layer, §3) -----

enum RelOp {
    Ge,
    Le,
    Gt,
    Lt,
}

/// `comparisonOp` (OnlyNumeric -> upcast -> SameType) then the relation node.
fn build_relation(l: TypedExpr, r: TypedExpr, op: RelOp) -> Result<TypedExpr, BuildError> {
    let (l, r) = comparison_op(l, r)?;
    let (left, right) = (Box::new(l), Box::new(r));
    let tpe = SType::SBoolean;
    Ok(match op {
        RelOp::Ge => TypedExpr::GE { left, right, tpe },
        RelOp::Le => TypedExpr::LE { left, right, tpe },
        RelOp::Gt => TypedExpr::GT { left, right, tpe },
        RelOp::Lt => TypedExpr::LT { left, right, tpe },
    })
}

/// `equalityOp` (upcast -> SameType) then EQ/NEQ.
fn build_equality(l: TypedExpr, r: TypedExpr, is_eq: bool) -> Result<TypedExpr, BuildError> {
    let (l, r) = equality_op(l, r)?;
    let (left, right) = (Box::new(l), Box::new(r));
    let tpe = SType::SBoolean;
    Ok(if is_eq {
        TypedExpr::EQ { left, right, tpe }
    } else {
        TypedExpr::NEQ { left, right, tpe }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// §6 bimap / bimap2 / unmap — the shared numeric-op harness (SigmaTyper.scala:569-628)
// ─────────────────────────────────────────────────────────────────────────────

/// `bimap[T](env, op, l, r)(mkNode)(tArg, tRes)` (SigmaTyper.scala:569-597).
///
/// `mk` is the node builder that runs the builder-op layer (arith/comparison/…)
/// and constructs the node — the Rust analogue of `mkNode` inside
/// `TransformingSigmaBuilder`.
#[allow(clippy::too_many_arguments)]
fn bimap(
    env: &TypeEnv,
    ctx: &TyperCtx,
    op: &str,
    l: TypedExpr,
    r: TypedExpr,
    mk: impl FnOnce(TypedExpr, TypedExpr) -> Result<TypedExpr, BuildError>,
    t_arg: SType,
    t_res: SType,
) -> Result<TypedExpr, TyperError> {
    let l1 = assign_type(env, l, ctx)?;
    let r1 = assign_type(env, r, ctx)?;
    let lt = node_tpe(&l1).clone();
    let rt = node_tpe(&r1).clone();
    // (numeric, numeric) with t1 != t2 -> allowed (the builder inserts Upcast);
    // else the unify enforces the concrete/consistent arg types.
    let numeric_diff = is_numeric(&lt) && is_numeric(&rt) && lt != rt;
    if !numeric_diff {
        let pat = SType::SFunc {
            dom: vec![t_arg.clone(), t_arg.clone()],
            range: Box::new(t_res.clone()),
        };
        let act = SType::SFunc {
            dom: vec![lt.clone(), rt.clone()],
            range: Box::new(t_res.clone()),
        };
        if unify_types(&pat, &act).is_none() {
            return Err(TyperError::invalid_binary(format!(
                "Invalid binary operation {op}: expected argument types ({t_arg:?}, {t_arg:?}); actual: ({lt:?}, {rt:?})"
            )));
        }
    }
    // safeMkNode: the NoType-error and any thrown error BOTH rewrap to
    // InvalidBinaryOperationParameters (the error(...) throw is inside the try).
    match mk(l1, r1) {
        Ok(node) if *node_tpe(&node) == SType::NoType => Err(TyperError::invalid_binary(format!(
            "operation: {op}: No type can be assigned to expression"
        ))),
        Ok(node) => Ok(node),
        Err(be) => Err(TyperError::invalid_binary(format!(
            "operation: {op}: {be:?}"
        ))),
    }
}

/// `bimap2[T](env, op, l, r)(newNode)` (SigmaTyper.scala:599-614).
///
/// No typer-side type check — the builder's `equalityOp` does upcast + SameType;
/// any thrown error rewraps to InvalidBinaryOperationParameters.
fn bimap2(
    env: &TypeEnv,
    ctx: &TyperCtx,
    op: &str,
    l: TypedExpr,
    r: TypedExpr,
    mk: impl FnOnce(TypedExpr, TypedExpr) -> Result<TypedExpr, BuildError>,
) -> Result<TypedExpr, TyperError> {
    let l1 = assign_type(env, l, ctx)?;
    let r1 = assign_type(env, r, ctx)?;
    mk(l1, r1).map_err(|be| TyperError::invalid_binary(format!("operation {op}: {be:?}")))
}

/// `unmap[T](env, op, i)(newNode)(tArg)` (SigmaTyper.scala:616-628).
fn unmap(
    env: &TypeEnv,
    ctx: &TyperCtx,
    op: &str,
    i: TypedExpr,
    mk: impl FnOnce(TypedExpr) -> Result<TypedExpr, BuildError>,
    t_arg: SType,
) -> Result<TypedExpr, TyperError> {
    let i1 = assign_type(env, i, ctx)?;
    let it = node_tpe(&i1).clone();
    // !isNumType && tpe != tArg -> InvalidUnaryOperationParameters (any numeric
    // passes for !/-/~ via the isNumType short-circuit).
    if !is_numeric(&it) && it != t_arg {
        return Err(TyperError::invalid_unary(format!(
            "Invalid unary op {op}: expected argument type {t_arg:?}, actual: {it:?}"
        )));
    }
    mk(i1).map_err(|be| TyperError::invalid_unary(format!("operation {op} error: {be:?}")))
}

// ─────────────────────────────────────────────────────────────────────────────
// shared: type a list of expressions
// ─────────────────────────────────────────────────────────────────────────────

fn type_all(
    env: &TypeEnv,
    items: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<Vec<TypedExpr>, TyperError> {
    items
        .into_iter()
        .map(|it| assign_type(env, it, ctx))
        .collect()
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
        let mut env = ScriptEnv::new();
        env.insert("a", EnvValue::ByteArray(vec![1, 2]));
        env.insert("b", EnvValue::ByteArray(vec![3, 4]));
        env.insert("col1", EnvValue::LongArray(vec![1, 2]));
        env.insert("col2", EnvValue::LongArray(vec![3, 4]));
        env.insert("g1", EnvValue::GroupElement(ge));
        env.insert("g2", EnvValue::GroupElement(ge));
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
        let seed = include_str!("../../../test-vectors/ergoscript/typer/golden_seed.txt");
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

    // ----- happy path — end-to-end oracle parity (in-scope shapes) -----

    /// Every in-scope ACCEPT seed source: parse->bind->assign_type->print must
    /// byte-match the committed oracle record.  Covers Block/Val/Ident (§1.1/1.4),
    /// ConcreteCollection (§1.3), GT/LT/EQ relations (§1.15), ArithOp incl. Upcast
    /// (§1.16), If (§1.13), LogicalNot/Negation (§1.23), Tuple (§1.2), and the
    /// Unit constant passthrough (§1.24).
    #[test]
    fn end_to_end_accept_records_byte_match_oracle() {
        let sources = [
            // committed §1/§2/§8 records that are fully in-scope
            "{ val x = HEIGHT; x > 5 }",
            "Coll(1, 2, 3)",
            "HEIGHT > 5",
            "()",
            // §11 Task-5 captures
            "{ val x: Long = 1; x }",
            "5 - 3",
            "1L - 1",
            "if (HEIGHT > 5) 1 else 2",
            "!true",
            "1 == 2",
            "(1, 2L)",
            "1 < 2L",
            "{ val x = 5; -x }",
        ];
        for src in sources {
            assert_eq!(type_tc(src), seed_expected(src), "mismatch for {src:?}");
        }
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
            value: ConstPayload::GroupElement("(x,y,1)".to_string()),
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

    // ----- oracle parity — Task-7 handoff marker (MethodCallLike only) -----

    /// §1.11: a MethodCallLike (`+`, `*`, `++`, `&&`, …) is Task 7.  This is the
    /// ONLY remaining NotYetImplemented arm after Task 6.
    #[test]
    fn method_call_like_input_is_not_yet_implemented() {
        // `1 + 2` binds to MethodCallLike("+").
        let err = type_err("1 + 2");
        assert!(
            matches!(err, TyperError::NotYetImplemented { .. }),
            "got {err:?}"
        );
        assert_eq!(err.class_tag(), "NotYetImplemented");
    }

    /// §1.10: an Apply whose callee is unbound (not env/predef) errors at the
    /// callee Ident, NOT NotYetImplemented (SigmaTyper.scala:232 → §1.4).
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

    // ----- oracle parity — Task-6 accept byte-parity sweep (file-driven) -----

    /// Sources that remain Task-7 (MethodCallLike operators) or carry a documented
    /// M2 rendering deviation (PK), excluded from the byte-parity sweep.
    const SWEEP_SKIP: &[&str] = &[
        // §1.11 MethodCallLike (`* ++ || && + ^ << >> >>>`) — Task 7.
        "1L + 1",
        "1.toByte + 2.toByte",
        "true && (1 == 1)",
        "HEIGHT>5 && HEIGHT<9",
        "a ++ b",
        "\"ab\" + \"cd\"",
        // PK renders ProveDlog with an M2 hex placeholder (deviation; see typed.rs).
        "PK(\"3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN\")",
        // Records embedding a demo-env GroupElement CONSTANT (g1/g2): env.rs `lift`
        // renders the 33-byte key as an M2 hex placeholder, not the oracle's
        // decompressed `Ecp (x,y,1)` form (documented deviation, M3).  Their
        // LOWERING is verified structurally instead (see the per-arm tests below).
        "proveDlog(g1)",
        "atLeast(1, Coll(proveDlog(g1)))",
        "allOf(Coll(proveDlog(g1)))",
        "g1.exp(n1)",
        "g1.negate",
        "g1.multiply(g2)",
        "proveDHTuple(g1, g2, g1, g2)",
    ];

    /// Every in-scope ACCEPT record in the golden seed (tc + tce) types end-to-end
    /// (parse -> bind -> assignType -> print) to the byte-exact oracle string.
    /// This sweeps ALL previously-NYI-blocked records that Task 6 now enables
    /// (§1/§4/§7/§9/§12 predef lowerings, method calls, indexing) plus the Task-5
    /// structural records — the whole accept surface minus the Task-7 SKIP set.
    #[test]
    fn seed_accept_records_byte_match_oracle_v3() {
        let seed = include_str!("../../../test-vectors/ergoscript/typer/golden_seed.txt");
        let mut checked = 0usize;
        for line in seed.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(3, '\t').collect();
            if parts.len() != 3 {
                continue;
            }
            let (verb, src, expected) = (parts[0], parts[1], parts[2]);
            let Some(sexpr) = expected.strip_prefix("OK ") else {
                continue; // REJECT/ERR records handled elsewhere
            };
            if SWEEP_SKIP.contains(&src) {
                continue;
            }
            let got = match verb {
                "tc" => type_tc(src),
                "tce" => type_tce(src),
                _ => continue,
            };
            assert_eq!(got, sexpr, "byte-parity mismatch for {verb} {src:?}");
            checked += 1;
        }
        // Guard: the sweep must actually exercise a substantial set.
        // §13 adds 2 new accept records (avlTree 4-arg + executeFromSelfRegWithDefault).
        assert!(checked >= 47, "swept only {checked} accept records");
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
            value: ConstPayload::GroupElement("(x,y,1)".to_string()),
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

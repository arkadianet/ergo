use crate::stype::SType;
use crate::typed::TypedExpr;
use crate::typer::unify::{is_numeric, unify_types, BuildError};
use crate::typer::{TypeEnv, TyperCtx};

use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// §6 bimap / bimap2 / unmap — the shared numeric-op harness (SigmaTyper.scala:569-628)
// ─────────────────────────────────────────────────────────────────────────────

/// `bimap[T](env, op, l, r)(mkNode)(tArg, tRes)` (SigmaTyper.scala:569-597).
///
/// `mk` is the node builder that runs the builder-op layer (arith/comparison/…)
/// and constructs the node — the Rust analogue of `mkNode` inside
/// `TransformingSigmaBuilder`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn bimap(
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
            tpe_params: vec![],
        };
        let act = SType::SFunc {
            dom: vec![lt.clone(), rt.clone()],
            range: Box::new(t_res.clone()),
            tpe_params: vec![],
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
pub(crate) fn bimap2(
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
pub(crate) fn unmap(
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

pub(crate) fn type_all(
    env: &TypeEnv,
    items: Vec<TypedExpr>,
    ctx: &TyperCtx,
) -> Result<Vec<TypedExpr>, TyperError> {
    items
        .into_iter()
        .map(|it| assign_type(env, it, ctx))
        .collect()
}

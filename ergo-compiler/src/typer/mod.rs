//! Typer phase: unification, type substitution, and numeric upcast machinery.
//!
//! This module is the Rust port of the Scala type-checker machinery from
//! sigma-state 6.0.2.  Phase pipeline:
//!   untyped `Expr` (M1) → `binder.rs` → `typer/` → `TypedExpr`
//!
//! Core sources (pinned v6.0.2 worktree):
//! - `core/shared/src/main/scala/sigma/ast/package.scala` (unify/subst/msgType)
//! - `core/shared/src/main/scala/sigma/ast/SType.scala` (numeric ladder)
//! - `data/shared/src/main/scala/sigma/ast/syntax.scala` (upcastTo)
//! - `data/shared/src/main/scala/sigma/ast/SigmaBuilder.scala` (builder op layers)
//!
//! Module structure: [`unify`] holds unification, substitution, and numeric
//! upcast machinery; [`methods`] the SMethod tables; [`predef_ir`] the
//! predefined-function environment and irBuilder lowering; [`assign`] the
//! structural `assignType` dispatch, including the Apply/MethodCallLike arms.

use std::collections::BTreeMap;

use crate::stype::SType;

pub mod assign;
pub mod methods;
pub mod predef_ir;
pub mod unify;

// Re-export the primary public surface for typer consumers.
pub use assign::{assign_type, TyperError};
pub use methods::{
    container_exists, get_method, global_method, has_method, owner_name_for_type, specialize_for,
    SMethodDesc,
};
pub use predef_ir::{predef_ir_builder, predefined_env};
pub use unify::{
    apply_subst, apply_subst_func, apply_upcast, arith_op, comparison_op, const_downcast,
    const_upcast, equality_op, is_numeric, is_prim_type, msg_type, msg_type_of, numeric_index,
    numeric_max, upcast_to, BuildError, SFuncSpec, TypeSubst,
};

/// The block/lambda scope map handed to `assign_type`.
///
/// Mirrors the `env: Map[String, SType]` threaded through `SigmaTyper.assignType`
/// (SigmaTyper.scala:53, v6.0.2 worktree).  `BTreeMap` for deterministic
/// iteration in error messages / tests.  The caller pre-seeds it: block `val`
/// names and lambda parameters are added by the typer itself as it descends;
/// the top-level `predefinedEnv` wiring (predefined func names → their `SFunc`
/// declaration types) lives in `typecheck.rs`.
pub type TypeEnv = BTreeMap<String, SType>;

/// Knobs threaded through the typer dispatch.
///
/// Mirrors the `SigmaTyper` constructor parameters relevant to typing
/// (SigmaTyper.scala:21-24).  `builder`/`predefFuncRegistry` are folded into the
/// Rust port's method tables + node constructors, so only `tree_version` remains.
///
/// The Scala constructor's `lowerMethodCalls` parameter is not modeled as a
/// runtime toggle: `SigmaCompiler.scala` always constructs `SigmaTyper` with
/// `lowerMethodCalls = true` in the production `compile()` path this port
/// targets, so the Rust port's property/method irBuilders
/// (`predef_ir::predef_ir_builder`, `assign::lower_method`) are correspondingly
/// unconditional, matching that fixed value.
#[derive(Debug, Clone, Copy)]
pub struct TyperCtx {
    /// ErgoTree version, gating the v5/v6 method tables
    /// (`VersionContext.isV3OrLaterErgoTreeVersion` ⇔ `tree_version >= 3`).
    pub tree_version: u8,
}

impl TyperCtx {
    pub fn new(tree_version: u8) -> Self {
        TyperCtx { tree_version }
    }
}

/// Convenience: the empty type environment.
pub fn empty_type_env() -> TypeEnv {
    TypeEnv::new()
}

/// True iff `t` is a collection type (`SColl`).
///
/// Mirrors `SType.isCollectionLike`/`isCollection` (used by the ByIndex/SizeOf
/// arms, SigmaTyper.scala:494,504).  Only `SColl` qualifies at the typer surface.
pub(crate) fn is_collection_like(t: &SType) -> bool {
    matches!(t, SType::SColl(_))
}

/// The element type of a collection, or `None` if `t` is not a collection.
pub(crate) fn coll_elem(t: &SType) -> Option<&SType> {
    match t {
        SType::SColl(e) => Some(e),
        _ => None,
    }
}

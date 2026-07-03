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
//! Task scope (M2 Task 2): unification + numeric machinery only.
//! Later tasks (3+) add the SMethod tables and full typer dispatch.

pub mod methods;
pub mod unify;

// Re-export the primary public surface for typer consumers.
pub use methods::{
    container_exists, get_method, global_method, has_method, owner_name_for_type, specialize_for,
    SMethodDesc,
};
pub use unify::{
    apply_subst, apply_subst_func, apply_upcast, arith_op, comparison_op, const_downcast,
    const_upcast, equality_op, is_numeric, is_prim_type, msg_type, msg_type_of, numeric_index,
    numeric_max, upcast_to, BuildError, SFuncSpec, TypeSubst,
};

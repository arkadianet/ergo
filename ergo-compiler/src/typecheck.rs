//! Public compile front-end: `typecheck` = parse → bind → assign_type.
//!
//! Mirrors `SigmaCompiler.typecheck` (sigma-state 6.0.2,
//! `sc/shared/src/main/scala/sigma/compiler/SigmaCompiler.scala:72-85`): parse the
//! source, bind it against the `ScriptEnv` (constant substitution + predef
//! desugaring), then assign types.  The typer is seeded with `predefinedEnv =
//! predefFuncs ++ typeEnv` (SigmaTyper.scala:33-36).  `predefFuncs` comes from
//! [`crate::typer::predefined_env`]; `typeEnv` is the `SType`-valued subset of the
//! script env (`env.collect { case (k, v: SType) => k -> v }`,
//! SigmaCompiler.scala:76).  Our [`ScriptEnv`] carries VALUES only (E9), so the
//! `typeEnv` contribution is always empty and the predef env is the whole top-level
//! typer environment.
//!
//! # Error shape (E9 + E12)
//!
//! [`CompileError`] tags the failing phase.  `Parse`/`Bind` carry real source
//! positions (`pos()` is meaningful); `Type` errors carry `pos ≡ 0` — the typer is
//! the single, documented phase-level position gap (E12): `TypedExpr` nodes hold no
//! positions, so a typer rejection cannot cite one.  The accept/reject verdict and
//! the exception CLASS are the parity-relevant facts (E5 makes reject positions
//! advisory).

use ergo_ser::address::NetworkPrefix;

use crate::binder::{bind, BindError};
use crate::emit::EmitError;
use crate::env::ScriptEnv;
use crate::error::ParseError;
use crate::parse::parse;
use crate::span::Pos;
use crate::typed::TypedExpr;
use crate::typer::{assign_type, predefined_env, TyperCtx, TyperError};

/// A compile failure, tagged by the phase that rejected the source.
///
/// Mirrors the three Scala compiler-exception families thrown along
/// `SigmaCompiler.typecheck`:
/// - [`CompileError::Parse`] — `ParserException` (grammar / lexical / semantic
///   build failures), carries a real position.
/// - [`CompileError::Bind`] — `BinderException` family (incl. `InvalidArguments`,
///   PK address decode), carries a real position.
/// - [`CompileError::Type`] — `TyperException` family (incl. `MethodNotFound`,
///   `NonApplicableMethod`, …); `pos()` is always `0` (E12).
///
/// The M3 `compile()` pipeline (`tree.rs`) adds three post-typecheck variants:
/// - [`CompileError::Root`] — the typed root is neither `Boolean` nor
///   `SigmaProp` (`ScriptApiRoute.scala:60-65` throws a bare `new Exception`;
///   oracle: `cc HEIGHT` → `REJECT 0:0 Exception`).
/// - [`CompileError::Emit`] — emit-phase failure ([`EmitError`]); a compiler
///   bug surface or an `ergo-ser`-unrepresentable node (lib.rs D-E1..D-E3),
///   not a user error. No dedicated Scala exception class exists — the route
///   collapses every non-`CompilerException` throwable into its catch-all.
/// - [`CompileError::Write`] — wire serialization of the assembled tree
///   failed (`ergo_ser::error::WriteError`); same compiler-bug surface.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// Parse-phase rejection (`sigmastate.lang.parsers.ParserException`).
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),
    /// Bind-phase rejection (`sigma.exceptions.BinderException` / `InvalidArguments`).
    #[error("bind error: {0}")]
    Bind(#[from] BindError),
    /// Typer-phase rejection (`sigma.exceptions.TyperException` and subclasses).
    #[error("type error: {0}")]
    Type(#[from] TyperError),
    /// Root-type rejection: the compiled root is neither `Boolean` nor
    /// `SigmaProp`. Message mirrors `ScriptApiRoute.scala:64-65`.
    #[error("source compilation result is of type {tpe}, but `SBoolean` expected")]
    Root {
        /// Term-string of the offending root type ([`crate::typed_print::to_term_string`]).
        tpe: String,
    },
    /// Emit-phase rejection (typed AST → opcode IR lowering failed).
    #[error("emit error: {0}")]
    Emit(#[from] EmitError),
    /// Wire-write rejection (opcode IR → bytes failed).
    #[error("tree serialization error: {0}")]
    Write(#[from] ergo_ser::error::WriteError),
}

impl CompileError {
    /// The 1-based source offset of the error.
    ///
    /// `Parse`/`Bind` return the real offset; `Type` returns `0` — `TypedExpr`
    /// carries no positions, so typer rejections have no citable position (E12).
    /// The post-typecheck phases (`Root`/`Emit`/`Write`) also return `0`: they
    /// operate on position-less typed/IR nodes (and the oracle agrees — the
    /// route's root-type throw grades as `REJECT 0:0 Exception`).
    pub fn pos(&self) -> Pos {
        match self {
            CompileError::Parse(e) => e.pos(),
            CompileError::Bind(e) => e.pos(),
            CompileError::Type(e) => e.pos(),
            CompileError::Root { .. } | CompileError::Emit(_) | CompileError::Write(_) => 0,
        }
    }

    /// The Scala exception class name for accept/reject-class parity grading.
    ///
    /// `Type` delegates to [`TyperError::class_tag`] (`TyperException`,
    /// `MethodNotFound`, `NonApplicableMethod`, …).  `Parse` reports
    /// `ParserException` (the single Scala parser exception class; the M1 lexical
    /// vs syntax vs semantic split is a Rust-side refinement, design doc §10).
    /// `Bind` reports the `BinderException`-family class.
    pub fn class(&self) -> &'static str {
        match self {
            CompileError::Parse(_) => "ParserException",
            CompileError::Bind(e) => match e {
                BindError::BinderException { .. } => "BinderException",
                BindError::InvalidArguments { .. } => "InvalidArguments",
                BindError::InvalidAddress { .. } => "InvalidAddress",
            },
            CompileError::Type(e) => e.class_tag(),
            // `Root` mirrors the route's bare `new Exception(...)`
            // (ScriptApiRoute.scala:64-65; oracle `cc HEIGHT` → `REJECT 0:0
            // Exception`). `Emit`/`Write` have no Scala analog (compiler-bug
            // surfaces); they grade as the same generic catch-all class.
            CompileError::Root { .. } | CompileError::Emit(_) | CompileError::Write(_) => {
                "Exception"
            }
        }
    }
}

/// Parse, bind, and typecheck `source`, producing a fully typed [`TypedExpr`].
///
/// The production entry point (E9).  Network defaults to
/// [`NetworkPrefix::Mainnet`] — the only network-sensitive surface is `PK("addr")`
/// address decoding (binder rule 9); every other construct is network-independent.
/// Use [`typecheck_with_network`] to compile testnet `PK` addresses.
///
/// `tree_version` threads the v5/v6 method-table + predef gate
/// (`tree_version >= 3` ⇔ `VersionContext.isV3OrLaterErgoTreeVersion`, E8).
///
/// # Examples
///
/// ```
/// use ergo_compiler::{typecheck, ScriptEnv, SType, node_tpe};
///
/// let env = ScriptEnv::new();
/// // `sigmaProp(HEIGHT > 1000)` types to `SigmaProp` (v6 tree_version = 3).
/// let typed = typecheck(&env, "sigmaProp(HEIGHT > 1000)", 3).unwrap();
/// assert_eq!(*node_tpe(&typed), SType::SSigmaProp);
/// ```
pub fn typecheck(
    env: &ScriptEnv,
    source: &str,
    tree_version: u8,
) -> Result<TypedExpr, CompileError> {
    typecheck_with_network(env, source, tree_version, NetworkPrefix::Mainnet)
}

/// Like [`typecheck`], but with an explicit network prefix for `PK("addr")`
/// address decoding (binder rule 9, SigmaCompiler.scala:74 `networkPrefix`).
///
/// Only `PK("base58addr")` reads the network; all other constructs ignore it.
pub fn typecheck_with_network(
    env: &ScriptEnv,
    source: &str,
    tree_version: u8,
    network: NetworkPrefix,
) -> Result<TypedExpr, CompileError> {
    // SigmaCompiler.typecheck:63-84 — parse, then bind, then assignType.
    let parsed = parse(source, tree_version)?;
    let bound = bind(env, &parsed, network, tree_version)?;
    // predefinedEnv = predefFuncs ++ typeEnv (SigmaTyper.scala:33-36).  typeEnv is
    // the SType-valued subset of `env`; our ScriptEnv carries values only (E9), so
    // it is empty and the predef env is the whole top-level typer environment.
    let type_env = predefined_env(tree_version);
    let ctx = TyperCtx::new(tree_version);
    let typed = assign_type(&type_env, bound, &ctx)?;
    Ok(typed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed::node_tpe;
    use crate::typed_print::print_typed;

    // ----- helpers -----

    fn tc(source: &str) -> Result<TypedExpr, CompileError> {
        typecheck(&ScriptEnv::new(), source, 3)
    }

    // ----- happy path -----

    #[test]
    fn typecheck_height_gt_5_types_boolean() {
        let typed = tc("HEIGHT > 5").expect("typecheck");
        assert_eq!(*node_tpe(&typed), crate::stype::SType::SBoolean);
    }

    #[test]
    fn typecheck_arith_upcast_shape_matches_seed() {
        // golden_seed.txt §1: `1L + 1` → ArithOp with an Upcast of the Int operand.
        let typed = tc("1L + 1").expect("typecheck");
        assert_eq!(
            print_typed(&typed),
            "(ArithOp:Long (ConstantNode:Long @1) (Upcast:Long (ConstantNode:Int @1)) @-102)"
        );
    }

    #[test]
    fn typecheck_sigma_prop_types_sigmaprop() {
        let typed = tc("sigmaProp(HEIGHT > 1000)").expect("typecheck");
        assert_eq!(*node_tpe(&typed), crate::stype::SType::SSigmaProp);
    }

    // ----- error paths -----

    #[test]
    fn typecheck_parse_error_is_parse_phase() {
        // An unbalanced open paren cannot parse.
        let err = tc(")(").expect_err("parse must fail");
        assert!(matches!(err, CompileError::Parse(_)));
        assert_eq!(err.class(), "ParserException");
    }

    #[test]
    fn typecheck_type_error_is_type_phase_pos_zero() {
        // `HEIGHT && true` — Boolean-op on a non-Boolean receiver (§1.11).
        let err = tc("HEIGHT && true").expect_err("typer must fail");
        assert!(matches!(err, CompileError::Type(_)));
        // E12: typer rejections carry pos == 0.
        assert_eq!(err.pos(), 0);
    }

    #[test]
    fn typecheck_method_not_found_class_tag() {
        // `HEIGHT.foo` — SInt has no method `foo` (§1.5).
        let err = tc("HEIGHT.foo").expect_err("typer must fail");
        assert_eq!(err.class(), "MethodNotFound");
    }
}

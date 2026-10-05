//! ErgoScript source → typed ErgoTree, canonical wire bytes, and addresses.
//!
//! The pipeline parses source, binds the environment, typechecks, emits opcode
//! expressions, applies graph-building transformations, segregates constants,
//! and constructs P2S/P2SH addresses. Compiler behavior is tested against the
//! pinned Scala/sigma-state oracles and committed fixtures. A compiler error can
//! produce an unusable contract or address, so byte parity matters even though
//! source compilation is outside block consensus validation.
//!
//! # Public entry points
//!
//! - [`parse`] / [`parse_type`] produce untyped expressions and source types.
//! - [`fn@typecheck`] / [`typecheck_with_network`] bind and typecheck source.
//! - [`compile`] / [`compile_with_source_map`] produce a [`CompileResult`].
//! - [`parse_contract`] / [`compile_contract`] handle named
//!   contract parameters; [`ScriptEnv`] supplies explicitly typed bindings.
//!
//! The requested tree version selects language semantics; the network selects
//! address encoding. Returned errors distinguish parse, binding, typing and
//! emission failures. Callers should preserve those errors instead of silently
//! substituting another tree or address.
//!
//! Current limitations, oracle versions, pass-order rationale and historical
//! closure evidence are maintained in the
//! [compiler design ledger](https://github.com/arkadianet/ergo/blob/main/ergo-compiler/docs/compiler-design-ledger.md).
//!
//! # Examples
//!
//! ```
//! use ergo_compiler::{parse, parse_type, Expr, SType};
//! let ast = parse("1 + 2", 0)?;
//! assert!(matches!(ast, Expr::MethodCallLike { .. }));
//! assert_eq!(parse_type("Coll[Int]", 0)?, SType::SColl(Box::new(SType::SInt)));
//! # Ok::<(), ergo_compiler::ParseError>(())
//! ```
//!
//! ```
//! use ergo_compiler::{compile, NetworkPrefix, ScriptEnv};
//! let result = compile(&ScriptEnv::new(), "sigmaProp(HEIGHT > 100)", 0,
//!                      NetworkPrefix::Mainnet)?;
//! assert!(!result.tree_bytes.is_empty());
//! assert!(!result.p2s_address.is_empty());
//! # Ok::<(), ergo_compiler::CompileError>(())
//! ```

pub mod ast;
pub mod binder;
pub mod contract_parse;
pub mod contract_template;
// CSE scope-chain hash-cons substrate, wired into `compile()` (`tree::mod`)
// as the sole subexpression-sharing pass; see D-C6/D-C7 in the compiler design ledger.
pub mod cse;
pub mod emit;
pub mod env;
pub mod error;
mod fold;
mod inline;
mod isproven;
mod lower;
pub(crate) mod param_order;
mod parse;
pub mod source_map;
pub mod span;
pub mod stype;
pub mod token;
pub mod tree;
mod tuple;
pub mod typecheck;
pub mod typed;
pub mod typed_print;
pub mod typer;

pub use ast::{ArithKind, BitKind, Expr, RelKind, ValDef};
pub use binder::{bind, BindError};
pub use contract_parse::{
    parse_contract, ContractDoc, ContractParam, ContractSignature, ParameterDoc,
    ParsedContractTemplate,
};
pub use contract_template::{
    compile_contract, ApplyError, ContractError, ContractTemplate, Parameter,
};
pub use emit::{emit, emit_with_version, EmitError};
pub use env::{lift, EnvValue, ScriptEnv};
pub use error::ParseError;
pub use parse::{parse, parse_type};
pub use source_map::SourceMap;
pub use stype::SType;
pub use tree::{compile, compile_with_source_map, CompileResult};
pub use typecheck::{typecheck, typecheck_with_network, CompileError};
pub use typed::{node_tpe, ConstPayload, TypedExpr};
pub use typed_print::print_typed;
pub use typer::TyperError;

// Re-exported so `PK("addr")` compiles can select the address network without a
// direct `ergo-ser` dependency in downstream crates.
pub use ergo_ser::address::NetworkPrefix;
// Re-exported so callers can build `EnvValue::GroupElement` without a direct
// `ergo-primitives` dependency (the type is part of the `ScriptEnv` surface).
pub use ergo_primitives::group_element::GroupElement;

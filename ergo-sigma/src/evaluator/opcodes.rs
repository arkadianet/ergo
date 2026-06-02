//! Per-category opcode evaluation arms for `dispatch::eval_op`.
//!
//! Each submodule holds the verbatim arm bodies for one taxonomic
//! category. The dispatch table in `dispatch.rs` maps `(opcode, payload)`
//! pairs 1:1 to functions exposed here. Cost accounting, recursion
//! through `eval_expr`, trace push order, and error-variant identity
//! are byte-preserved from the original monolithic match.

pub(super) mod arithmetic;
pub(super) mod binding;
pub(super) mod boolean;
pub(super) mod box_context;
pub(super) mod cast;
pub(super) mod collection;
pub(super) mod comparison;
pub(super) mod constants;
pub(super) mod errors;
pub(super) mod method_call;
pub(super) mod option;
pub(super) mod property_call;
pub(super) mod sigma;

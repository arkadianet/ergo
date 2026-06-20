//! ErgoTree opcode dispatch: types and dispatch tables, plus matching
//! reader and writer. Split into three submodules so each piece can be
//! audited in isolation:
//!
//! * `types` — the [`Expr`] / [`IrNode`] / [`Payload`] AST nodes, the
//!   private `ArgPattern` enum, and the `opcode_pattern` / [`opcode_name`]
//!   dispatch tables that both reader and writer consume.
//! * `parse` — [`parse_body`] / [`parse_expr`]: bytes → AST.
//! * `write` — [`write_body`] / [`write_expr`]: AST → bytes.
//!
//! `parse` and `write` share `types` but do not depend on each other —
//! the dispatch table is the consensus contract; the read and write
//! sides each consume it independently.

mod parse;
mod types;
mod write;

#[cfg(test)]
mod tests;

pub use parse::{parse_body, parse_expr};
pub use types::{find_v3_only_method, is_v3_only_method, opcode_name, Body, Expr, IrNode, Payload};
pub use write::{write_body, write_expr};

//! Reject-only opcode arms.
//!
//! Two distinct cost disciplines are preserved here:
//!
//! - **Charge-then-reject** (BitOp family `0xF2 0xF3 0xF5 0xF6 0xF7 0xF8`):
//!   Scala registers these as `Fixed(1)` and accumulates cost before
//!   the reject for parity with `Value.eval` default at
//!   `values.scala:101`. A shared helper would silently lose the
//!   charge.
//! - **Zero-cost reject** (`0xCF 0xD7 0xE7 0xE8 0xE9 0xF1 0xB6 0xB7`):
//!   internal / deprecated / not-executable arms. Scala declares
//!   `costKind = Value.notSupportedError` and never charges.
//!
//! Each arm therefore gets its own `eval_<opname>` rather than a
//! shared `reject(opcode)` helper.

use ergo_primitives::cost::CostAccumulator;

use super::super::cost::add_cost;
use super::super::types::{EvalError, Value};

// 0xB6 CreateAvlTree — zero-cost reject.
// `trees.scala:77` "TODO v6.0: implement `eval` method and add support
// in GraphBuilding". Companion at `trees.scala:87-91` declares
// `costKind = Value.notSupportedError`. Serializer registered for
// deserialization parity but no runtime path.
pub(in crate::evaluator) fn eval_create_avl_tree() -> Result<Value, EvalError> {
    Err(EvalError::NotExecutable(0xB6, "CreateAvlTree"))
}

// 0xB7 TreeLookup — zero-cost reject.
// `trees.scala:1334-1338` declares `costKind = Value.notSupportedError`
// and has no `eval` override. User-level AVL lookup goes through
// `SAvlTree.get` method-call dispatch (type_id=100, method_id=10).
// A synthesized tree containing bare 0xB7 cannot come from the Scala
// compiler.
pub(in crate::evaluator) fn eval_tree_lookup() -> Result<Value, EvalError> {
    Err(EvalError::NotExecutable(0xB7, "TreeLookup"))
}

// 0xF2 BitOr — charge-then-reject.
pub(in crate::evaluator) fn eval_bit_or(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0xF2)?;
    Err(EvalError::NotExecutable(0xF2, "BitOr"))
}

// 0xF3 BitAnd — charge-then-reject.
pub(in crate::evaluator) fn eval_bit_and(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0xF3)?;
    Err(EvalError::NotExecutable(0xF3, "BitAnd"))
}

// 0xF5 BitXor — charge-then-reject.
pub(in crate::evaluator) fn eval_bit_xor(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0xF5)?;
    Err(EvalError::NotExecutable(0xF5, "BitXor"))
}

// 0xF6 BitShiftRight — charge-then-reject.
pub(in crate::evaluator) fn eval_bit_shift_right(
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0xF6)?;
    Err(EvalError::NotExecutable(0xF6, "BitShiftRight"))
}

// 0xF7 BitShiftLeft — charge-then-reject.
pub(in crate::evaluator) fn eval_bit_shift_left(
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0xF7)?;
    Err(EvalError::NotExecutable(0xF7, "BitShiftLeft"))
}

// 0xF8 BitShiftRightZeroed — charge-then-reject.
pub(in crate::evaluator) fn eval_bit_shift_right_zeroed(
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0xF8)?;
    Err(EvalError::NotExecutable(0xF8, "BitShiftRightZeroed"))
}

// 0xCF SigmaPropIsProven — zero-cost reject.
// `transformers.scala:321-329` `costKind = notSupportedError`. Internal —
// a projection on sigma boolean internals, not a user-level op.
pub(in crate::evaluator) fn eval_sigma_prop_is_proven() -> Result<Value, EvalError> {
    Err(EvalError::InternalOpcode(0xCF, "SigmaPropIsProven"))
}

// 0xD7 FunDef standalone — zero-cost reject.
// ValDef/FunDef have no `eval` override in Scala — a bare node at any
// live expression position hits `Value.eval`'s default
// `notSupportedError`. Items are bound ONLY by the BlockValue item
// loop (`BlockValue.eval` casts `asInstanceOf[ValDef]` and binds
// inline, never dispatching the node).
pub(in crate::evaluator) fn eval_fun_def_standalone() -> Result<Value, EvalError> {
    Err(EvalError::InternalOpcode(0xD7, "FunDef standalone"))
}

// 0xD6 ValDef standalone — zero-cost reject (same rule as FunDef).
pub(in crate::evaluator) fn eval_val_def_standalone() -> Result<Value, EvalError> {
    Err(EvalError::InternalOpcode(0xD6, "ValDef standalone"))
}

// 0xE7/E8/E9 ModQ family — zero-cost reject.
// `trees.scala:953-991`, all three declare `FixedCost(JitCost::from_jit(1))`
// and have no `eval` override. Class-level comment "TODO v6.0: implement
// modular operations". Serializers deliberately kept for
// deserialization round-trip per `ValueSerializer.scala:138-144`.
pub(in crate::evaluator) fn eval_mod_q_e7() -> Result<Value, EvalError> {
    Err(EvalError::DeprecatedOpcode(0xE7))
}
pub(in crate::evaluator) fn eval_mod_q_e8() -> Result<Value, EvalError> {
    Err(EvalError::DeprecatedOpcode(0xE8))
}
pub(in crate::evaluator) fn eval_mod_q_e9() -> Result<Value, EvalError> {
    Err(EvalError::DeprecatedOpcode(0xE9))
}

// 0xF1 BitInversion — zero-cost reject.
// `trees.scala:898-908`, class comment "Not implemented in v4.x",
// `costKind = notSupportedError`.
pub(in crate::evaluator) fn eval_bit_inversion() -> Result<Value, EvalError> {
    Err(EvalError::NotExecutable(0xF1, "BitInversion"))
}

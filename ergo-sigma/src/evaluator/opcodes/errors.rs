//! Reject-only opcode arms.
//!
//! These nodes inherit Scala Value.eval, which throws without charging
//! (values.scala:101). Declared costKind entries, including BitOp Fixed(1),
//! do not imply an evaluator charge. Each arm preserves its typed rejection.

use super::super::types::{EvalError, Value};

// 0xB6 CreateAvlTree — zero-cost reject.
// `trees.scala:77` "TODO v6.0: implement `eval` method and add support
// in GraphBuilding". Companion at `trees.scala:87-91` declares
// `costKind = Value.notSupportedError`. Serializer registered for
// deserialization parity. Value.eval (values.scala:101-102) throws before
// evaluating any children or adding cost; prefixes retain their accumulated cost.
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

// 0xF2 BitOr — zero-cost reject.
pub(in crate::evaluator) fn eval_bit_or() -> Result<Value, EvalError> {
    Err(EvalError::NotExecutable(0xF2, "BitOr"))
}

// 0xF3 BitAnd — zero-cost reject.
pub(in crate::evaluator) fn eval_bit_and() -> Result<Value, EvalError> {
    Err(EvalError::NotExecutable(0xF3, "BitAnd"))
}

// 0xF5 BitXor — zero-cost reject.
pub(in crate::evaluator) fn eval_bit_xor() -> Result<Value, EvalError> {
    Err(EvalError::NotExecutable(0xF5, "BitXor"))
}

// 0xF6 BitShiftRight — zero-cost reject.
pub(in crate::evaluator) fn eval_bit_shift_right() -> Result<Value, EvalError> {
    Err(EvalError::NotExecutable(0xF6, "BitShiftRight"))
}

// 0xF7 BitShiftLeft — zero-cost reject.
pub(in crate::evaluator) fn eval_bit_shift_left() -> Result<Value, EvalError> {
    Err(EvalError::NotExecutable(0xF7, "BitShiftLeft"))
}

// 0xF8 BitShiftRightZeroed — zero-cost reject.
pub(in crate::evaluator) fn eval_bit_shift_right_zeroed() -> Result<Value, EvalError> {
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

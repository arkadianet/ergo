//! Zero-payload constant emitters: True/False, the secp256k1 group
//! generator, the four `BoxCollection` / `Box` context constants
//! (HEIGHT, INPUTS, OUTPUTS, SELF, CONTEXT), MinerPubkey, the prior-state
//! `LastBlockUtxoRootHash`, the `Global` singleton, and the parser-decoded
//! BoolCollection literal (0x85).
//!
//! Each function charges cost first then constructs the result, matching
//! the original arm bodies byte-for-byte.

use ergo_primitives::cost::CostAccumulator;

use super::super::cost::add_cost;
use super::super::types::{BoxSource, EvalError, ReductionContext, Value, SECP256K1_GENERATOR};

// 0x7F True
pub(in crate::evaluator) fn eval_true(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0x7F)?;
    Ok(Value::Bool(true))
}

// 0x80 False
pub(in crate::evaluator) fn eval_false(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0x80)?;
    Ok(Value::Bool(false))
}

// 0x82 GroupGenerator — secp256k1 generator. values.scala:709-723, Fixed(10).
pub(in crate::evaluator) fn eval_group_generator(
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0x82)?;
    Ok(Value::GroupElement(SECP256K1_GENERATOR))
}

// 0xA3 HEIGHT
pub(in crate::evaluator) fn eval_height(
    ctx: &ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0xA3)?;
    Ok(Value::Int(ctx.height as i32))
}

// 0xA4 INPUTS
pub(in crate::evaluator) fn eval_inputs(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0xA4)?;
    Ok(Value::BoxCollection(BoxSource::Inputs))
}

// 0xA5 OUTPUTS
pub(in crate::evaluator) fn eval_outputs(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0xA5)?;
    Ok(Value::BoxCollection(BoxSource::Outputs))
}

// 0xA6 LastBlockUtxoRootHash — values.scala:1490-1502, Fixed(15).
// Returns the prior-state AvlTreeData that mainnet populates via
// `ErgoInterpreter.avlTreeFromDigest(stateContext.previousStateDigest)`
// at block-apply time (ergo-master/ergo-wallet/…/ErgoInterpreter.scala:103):
// digest from the prior header, AllOperationsAllowed flags,
// keyLength=32, valueLengthOpt=None. The metadata is NOT derivable
// from the header alone — the context owner is responsible
// for populating `last_block_utxo_root`. Empty means this
// opcode is unreachable in the current pipeline (e.g.,
// synthetic test context).
pub(in crate::evaluator) fn eval_last_block_utxo_root_hash(
    ctx: &ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0xA6)?;
    let avl = ctx
        .last_block_utxo_root
        .clone()
        .ok_or(EvalError::EmptyHeaderWindow)?;
    Ok(Value::AvlTree(avl))
}

// 0xA7 SELF
pub(in crate::evaluator) fn eval_self(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0xA7)?;
    Ok(Value::SelfBox)
}

// 0xAC MinerPubkey
pub(in crate::evaluator) fn eval_miner_pubkey(
    ctx: &ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0xAC)?;
    Ok(Value::CollBytes(ctx.miner_pubkey.to_vec()))
}

// 0xDD Global object — SGlobal singleton for method dispatch
pub(in crate::evaluator) fn eval_global(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0xDD)?;
    Ok(Value::Global)
}

// 0xFE CONTEXT — placeholder; context ops handled via MethodCall
pub(in crate::evaluator) fn eval_context(cost: &mut CostAccumulator) -> Result<Value, EvalError> {
    add_cost(cost, 0xFE)?;
    Ok(Value::SelfBox)
}

// 0x85 BoolCollection — packed-bits literal vector. The parser pre-decodes
// the packed bits into `Payload::BoolCollection`, so the arm wires the
// Vec<bool> to Value::CollBool.
//
// Cost: the packed form is a WIRE optimisation only. Scala's
// `ConcreteCollectionBooleanConstantSerializer.parse` rebuilds a plain
// `ConcreteCollection(items = BooleanConstant.fromBoolean(bit), SBoolean)`
// (ConcreteCollectionBooleanConstantSerializer.scala:35-48), so evaluation
// goes through `ConcreteCollection.eval` (values.scala:858-869): the
// collection's Fixed(20) once, then `evalTo` on EVERY item, each of which is
// `Constant.eval` at Fixed(5) (values.scala:351-354, 380). Total 20 + 5·n —
// identical to the unpacked 0x83 form with n TrueLeaf/FalseLeaf children.
// Charging the flat 20 alone under-costs by 5·n (issue #311).
pub(in crate::evaluator) fn eval_bool_collection(
    bits: &[bool],
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0x85)?;
    for &bit in bits {
        add_cost(cost, if bit { 0x7F } else { 0x80 })?;
    }
    Ok(Value::CollBool(bits.to_vec()))
}

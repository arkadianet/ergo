//! Box / context accessor opcodes:
//!
//! - 0xC7 ExtractCreationInfo — `(creationHeight, txId++index)` tuple
//! - 0xC1 ExtractAmount       — box.value as Long
//! - 0xC5 ExtractId           — box.id as Coll[Byte]
//! - 0xC6 ExtractRegisterAs   — register read with R0..R9 dispatch
//! - 0xC2 ExtractScriptBytes  — box.script_bytes as Coll[Byte]
//! - 0xC3 ExtractBytes        — full serialized box bytes
//! - 0xC4 ExtractBytesWithNoRef — candidate bytes (raw_bytes minus 32-byte txId + VLQ index suffix)
//! - 0xE3 GetVar              — context-extension Option lookup with exact-type match

use ergo_primitives::cost::CostAccumulator;
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;

use super::super::cost::add_cost;
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::{resolve_box, sigma_to_value};
use super::super::types::{EvalBox, EvalError, ReductionContext, Value};

// 0xC7 ExtractCreationInfo — (creationHeight, transactionId ++ Shorts.toByteArray(outputIndex))
// 34 bytes total: 32-byte txId + 2-byte big-endian index.
pub(in crate::evaluator) fn eval_extract_creation_info(
    input: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xC7)?;
    let box_val = cx.eval_expr(input)?;
    match &box_val {
        Value::SelfBox if cx.ctx.self_box.is_none() => Ok(Value::Tuple(vec![
            Value::Int(cx.ctx.self_creation_height as i32),
            Value::CollBytes(vec![0u8; 34]),
        ])),
        _ => {
            let b = resolve_box(&box_val, cx.ctx)?;
            let mut ref_bytes = Vec::with_capacity(34);
            ref_bytes.extend_from_slice(&b.transaction_id);
            ref_bytes.extend_from_slice(&b.output_index.to_be_bytes());
            Ok(Value::Tuple(vec![
                Value::Int(b.creation_height as i32),
                Value::CollBytes(ref_bytes),
            ]))
        }
    }
}

// 0xC1 ExtractAmount(box) -> Long
pub(in crate::evaluator) fn eval_extract_amount(
    input: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xC1)?;
    let box_val = cx.eval_expr(input)?;
    let b = resolve_box(&box_val, cx.ctx)?;
    Ok(Value::Long(b.value))
}

// 0xC5 ExtractId(box) -> Coll[Byte]
pub(in crate::evaluator) fn eval_extract_id(
    input: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xC5)?;
    let box_val = cx.eval_expr(input)?;
    let b = resolve_box(&box_val, cx.ctx)?;
    Ok(Value::CollBytes(b.id.to_vec()))
}

// 0xC6 ExtractRegisterAs(box, reg_id, tpe) -> Option[T]
// R0-R3 mandatory (always Some); R4-R9 additional (may be None).
pub(in crate::evaluator) fn eval_extract_register_as(
    input: &Expr,
    reg_id: u8,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xC6)?;
    let box_val = cx.eval_expr(input)?;
    let b = resolve_box(&box_val, cx.ctx)?;
    read_register_option(b, reg_id, 0xC6)
}

/// Shared register-read helper: resolves register `reg_id` on a
/// box to `Option[T]` per Scala's `ErgoBox.get(reg_id): Option[Value[_]]`
/// (R0-R3 mandatory, R4-R9 additional). Used by both the inline
/// `0xC6 ExtractRegisterAs` opcode and the v6 `SBox.getReg[T]`
/// MethodCall (type_id=99, method_id=7). `unsupported_opcode` is
/// the opcode byte to report if `reg_id` is out of the 0..=9 range
/// — kept distinct between callers so the surface error names the
/// right opcode.
pub(in crate::evaluator) fn read_register_option(
    b: &EvalBox,
    reg_id: u8,
    unsupported_opcode: u8,
) -> Result<Value, EvalError> {
    match reg_id {
        // R0: box.value (Long)
        0 => Ok(Value::Opt(Some(Box::new(Value::Long(b.value))))),
        // R1: box.propositionBytes (Coll[Byte])
        1 => Ok(Value::Opt(Some(Box::new(Value::CollBytes(
            b.script_bytes.clone(),
        ))))),
        // R2: box.tokens (Coll[(Coll[Byte], Long)])
        2 => Ok(Value::Opt(Some(Box::new(Value::Tokens(b.tokens.clone()))))),
        // R3: box.creationInfo ((Int, Coll[Byte]))
        // Scala: (creationHeight, transactionId.toBytes ++ Shorts.toByteArray(index))
        // = 34 bytes: 32-byte txId + 2-byte big-endian output index
        3 => {
            let mut ref_bytes = Vec::with_capacity(34);
            ref_bytes.extend_from_slice(&b.transaction_id);
            ref_bytes.extend_from_slice(&b.output_index.to_be_bytes());
            Ok(Value::Opt(Some(Box::new(Value::Tuple(vec![
                Value::Int(b.creation_height as i32),
                Value::CollBytes(ref_bytes),
            ])))))
        }
        // R4-R9: additional registers
        4..=9 => {
            let reg_idx = (reg_id - 4) as usize;
            match &b.registers[reg_idx] {
                Some(rv) => {
                    let val = sigma_to_value(&rv.tpe, &rv.value)?;
                    Ok(Value::Opt(Some(Box::new(val))))
                }
                None => Ok(Value::Opt(None)),
            }
        }
        _ => Err(EvalError::UnsupportedOpcode(unsupported_opcode)),
    }
}

// 0xC2 ExtractScriptBytes(box)
pub(in crate::evaluator) fn eval_extract_script_bytes(
    input: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xC2)?;
    let box_val = cx.eval_expr(input)?;
    let b = resolve_box(&box_val, cx.ctx)?;
    Ok(Value::CollBytes(b.script_bytes.clone()))
}

// 0xC3 ExtractBytes(box) — full serialized box bytes
pub(in crate::evaluator) fn eval_extract_bytes(
    input: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xC3)?;
    let box_val = cx.eval_expr(input)?;
    let b = resolve_box(&box_val, cx.ctx)?;
    Ok(Value::CollBytes(b.raw_bytes.clone()))
}

// 0xC4 ExtractBytesWithNoRef(box) — candidate bytes (raw_bytes minus
// last 32-byte txId + VLQ-encoded output_index).
pub(in crate::evaluator) fn eval_extract_bytes_with_no_ref(
    input: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xC4)?;
    let box_val = cx.eval_expr(input)?;
    let b = resolve_box(&box_val, cx.ctx)?;
    // Candidate bytes = raw_bytes minus last 34 bytes (32 txId + 2 index)
    // But index is VLQ-encoded (1 byte for values < 128, 2 for >= 128).
    // Use the known txId+index to compute the suffix length.
    let suffix_len = 32 + ergo_primitives::vlq::encode_vlq(b.output_index as u64).len();
    let end = b.raw_bytes.len().saturating_sub(suffix_len);
    Ok(Value::CollBytes(b.raw_bytes[..end].to_vec()))
}

// 0xE3 GetVar(var_id, type) -> Option[T]
// Scala uses exact type match: extension.tpe == declared.tpe
pub(in crate::evaluator) fn eval_get_var(
    var_id: u8,
    tpe: &SigmaType,
    ctx: &ReductionContext<'_>,
    cost: &mut CostAccumulator,
) -> Result<Value, EvalError> {
    add_cost(cost, 0xE3)?;
    match ctx.extension.get(&var_id) {
        Some((ext_tpe, ext_val)) => {
            if ext_tpe != tpe {
                return Ok(Value::Opt(None));
            }
            let val = sigma_to_value(ext_tpe, ext_val)?;
            Ok(Value::Opt(Some(Box::new(val))))
        }
        None => Ok(Value::Opt(None)),
    }
}

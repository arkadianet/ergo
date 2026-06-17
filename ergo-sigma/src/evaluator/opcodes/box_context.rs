//! Box / context accessor opcodes:
//!
//! - 0xC7 ExtractCreationInfo — `(creationHeight, txId++index)` tuple
//! - 0xC1 ExtractAmount       — box.value as Long
//! - 0xC5 ExtractId           — box.id as Coll[Byte]
//! - 0xC6 ExtractRegisterAs   — register read with R0..R9 dispatch
//! - 0xC2 ExtractScriptBytes  — box.script_bytes as Coll[Byte]
//! - 0xC3 ExtractBytes        — full serialized box bytes
//! - 0xC4 ExtractBytesWithNoRef — CANONICAL candidate bytes (re-serialized from structure)
//! - 0xE3 GetVar              — context-extension Option lookup with exact-type match

use ergo_primitives::cost::CostAccumulator;
use ergo_primitives::reader::VlqReader;
use ergo_ser::opcode::{parse_expr, write_expr, Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;

use super::super::cost::add_cost;
use super::super::eval_ctx::EvalCtx;
use super::super::helpers::{resolve_box, sigma_to_value_versioned};
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
    tpe: &SigmaType,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xC6)?;
    let box_val = cx.eval_expr(input)?;
    let b = resolve_box(&box_val, cx.ctx)?;
    read_register_option(b, reg_id, 0xC6, Some(tpe), cx.ctx)
}

/// Scala `CBox.getReg[T]`: a PRESENT register whose stored type differs
/// from the requested type `T` throws `InvalidType` — it does NOT
/// degrade to `None`. Absent registers return `None` without any type
/// check. Mandatory registers R0-R3 carry fixed types and are checked
/// the same way (`CBox.regs` stores them as typed `CAnyValue`s).
fn check_requested_type(
    requested: Option<&SigmaType>,
    stored: &SigmaType,
    reg_id: u8,
) -> Result<(), EvalError> {
    match requested {
        Some(req) if req != stored => Err(EvalError::TypeError {
            expected: "register value of the requested type (Scala CBox.getReg InvalidType)",
            got: format!("R{reg_id}: stored {stored:?}, requested {req:?}"),
        }),
        _ => Ok(()),
    }
}

/// Shared register-read helper: resolves register `reg_id` on a
/// box to `Option[T]` per Scala's `CBox.getReg(reg_id)(tT)`
/// (R0-R3 mandatory, R4-R9 additional). Used by both the inline
/// `0xC6 ExtractRegisterAs` opcode and the v6 `SBox.getReg[T]`
/// MethodCall (type_id=99, method_id=7). `requested` is the static
/// type the register is read at (`T`); `None` skips the type check
/// (MethodCall call sites that carry no recoverable type argument).
/// `unsupported_opcode` is the opcode byte to report if `reg_id` is
/// out of the 0..=9 range — kept distinct between callers so the
/// surface error names the right opcode.
pub(in crate::evaluator) fn read_register_option(
    b: &EvalBox,
    reg_id: u8,
    unsupported_opcode: u8,
    requested: Option<&SigmaType>,
    ctx: &ReductionContext<'_>,
) -> Result<Value, EvalError> {
    match reg_id {
        // R0: box.value (Long)
        0 => {
            check_requested_type(requested, &SigmaType::SLong, 0)?;
            Ok(Value::Opt(Some(Box::new(Value::Long(b.value)))))
        }
        // R1: box.propositionBytes (Coll[Byte])
        1 => {
            check_requested_type(requested, &SigmaType::SColl(Box::new(SigmaType::SByte)), 1)?;
            Ok(Value::Opt(Some(Box::new(Value::CollBytes(
                b.script_bytes.clone(),
            )))))
        }
        // R2: box.tokens (Coll[(Coll[Byte], Long)])
        2 => {
            check_requested_type(
                requested,
                &SigmaType::SColl(Box::new(SigmaType::STuple(vec![
                    SigmaType::SColl(Box::new(SigmaType::SByte)),
                    SigmaType::SLong,
                ]))),
                2,
            )?;
            Ok(Value::Opt(Some(Box::new(Value::Tokens(b.tokens.clone())))))
        }
        // R3: box.creationInfo ((Int, Coll[Byte]))
        // Scala: (creationHeight, transactionId.toBytes ++ Shorts.toByteArray(index))
        // = 34 bytes: 32-byte txId + 2-byte big-endian output index
        3 => {
            check_requested_type(
                requested,
                &SigmaType::STuple(vec![
                    SigmaType::SInt,
                    SigmaType::SColl(Box::new(SigmaType::SByte)),
                ]),
                3,
            )?;
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
                    check_requested_type(requested, &rv.tpe, reg_id)?;
                    let val = sigma_to_value_versioned(&rv.tpe, &rv.value, ctx)?;
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

// 0xC4 ExtractBytesWithNoRef(box) — CANONICAL candidate bytes.
//
// Scala `ErgoBox.bytesWithNoRef` re-serializes the candidate from its parsed
// structure (`ErgoBoxCandidate.serializer`), so any non-canonical wire encoding
// is normalized away — notably a register holding the IDENTITY GroupElement
// written as a lead-0x00 byte with trailing garbage (`00 aa..aa`) re-emits as
// the canonical 33 zero bytes (the trailing bytes are discarded at parse).
// This is distinct from `.bytes`/`.id` (0xC3/0xC5), which Scala surfaces from
// the RETAINED original bytes (garbage preserved) — so do NOT touch raw_bytes
// or the box id here.
pub(in crate::evaluator) fn eval_extract_bytes_with_no_ref(
    input: &Expr,
    cx: &mut EvalCtx<'_>,
) -> Result<Value, EvalError> {
    add_cost(cx.cost, 0xC4)?;
    let box_val = cx.eval_expr(input)?;
    let b = resolve_box(&box_val, cx.ctx)?;
    Ok(Value::CollBytes(box_candidate_bytes_canonical(b)?))
}

/// Canonical candidate serialization (`bytesWithNoRef`): value, script, height,
/// tokens, then the register block re-emitted with every `GroupElement`
/// canonicalized (identity garbage normalized; non-identity points
/// curve-validated). Mirrors `write_ergo_box_candidate` exactly except the
/// register block is re-serialized through GE normalization rather than copied
/// verbatim — which is what normalizes the encoding. For a canonically-encoded
/// box this reproduces `raw_bytes` minus the 32-byte txId + VLQ index suffix
/// byte-for-byte.
///
/// The register block is re-emitted from the verbatim wire bytes
/// (`EvalBox.register_bytes`), NOT from the parsed `registers` field, so each
/// register's node provenance is preserved: a Constant-encoded tuple stays a
/// Constant, a `CreateTuple` (0x86) register stays 0x86, a `ConcreteCollection`
/// (0x83) register stays 0x83. This matches Scala `ErgoBoxCandidate.serializer`,
/// which re-serializes each register's parsed AST node as-is. Re-encoding from
/// the parsed `RegisterValue` instead would force every tuple-typed register
/// into `CreateTuple` form (`register::write_register_value`), producing a wrong
/// `bytesWithNoRef` preimage for a Constant-encoded tuple register — the
/// divergence that stalled mainnet block 1808895.
///
/// Test-only boxes carry no wire `register_bytes`; they fall back to a
/// structural re-encode from the parsed registers (behavior-preserving for the
/// boxes that path serves, none of which carry a Constant-encoded tuple).
pub(in crate::evaluator) fn box_candidate_bytes_canonical(
    b: &EvalBox,
) -> Result<Vec<u8>, EvalError> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    w.put_u64(b.value as u64);
    w.put_bytes(&b.script_bytes);
    w.put_u32(b.creation_height);
    w.put_u8(b.tokens.len() as u8);
    for (id, amount) in &b.tokens {
        w.put_bytes(id);
        w.put_u64(*amount);
    }
    if b.register_bytes.is_empty() {
        write_registers_structural(&mut w, b)?;
    } else {
        write_registers_canonical(&mut w, &b.register_bytes)?;
    }
    Ok(w.result())
}

/// Re-emit the register block from its verbatim wire bytes, normalizing only
/// `GroupElement` encodings while preserving each register's node shape. See
/// [`box_candidate_bytes_canonical`] for why provenance must be preserved.
fn write_registers_canonical(
    w: &mut ergo_primitives::writer::VlqWriter,
    register_bytes: &[u8],
) -> Result<(), EvalError> {
    let entries = ergo_ser::register::split_register_bytes(register_bytes).map_err(|e| {
        EvalError::TypeError {
            expected: "splittable register block",
            got: format!("register block split failed: {e}"),
        }
    })?;
    w.put_u8(entries.len() as u8);
    for entry in &entries {
        let mut r = VlqReader::new(entry);
        let expr = parse_expr(&mut r, 0, 0).map_err(|e| EvalError::TypeError {
            expected: "parseable register expression",
            got: format!("register expr parse failed: {e}"),
        })?;
        let canon = canonicalize_register_expr(&expr)?;
        write_expr(w, &canon, false).map_err(|e| EvalError::TypeError {
            expected: "serializable register expression",
            got: format!("register expr re-serialization failed: {e}"),
        })?;
    }
    Ok(())
}

/// Return a copy of register expression `e` with every `GroupElement`
/// canonicalized, preserving the node's form: a `Const` re-canonicalizes its
/// inline value; a `CreateTuple` (0x86) / `ConcreteCollection` (0x83) recurses
/// into its items; any other form (e.g. `Coll[Boolean]` bit-packed) carries no
/// `GroupElement` and is returned unchanged.
fn canonicalize_register_expr(e: &Expr) -> Result<Expr, EvalError> {
    Ok(match e {
        Expr::Const { tpe, val } => Expr::Const {
            tpe: tpe.clone(),
            val: canonicalize_group_elements(val)?,
        },
        Expr::Op(IrNode {
            opcode: opcode @ 0x86,
            payload: Payload::Tuple { items },
        }) => Expr::Op(IrNode {
            opcode: *opcode,
            payload: Payload::Tuple {
                items: items
                    .iter()
                    .map(canonicalize_register_expr)
                    .collect::<Result<_, _>>()?,
            },
        }),
        Expr::Op(IrNode {
            opcode: opcode @ 0x83,
            payload: Payload::ConcreteCollection { elem_type, items },
        }) => Expr::Op(IrNode {
            opcode: *opcode,
            payload: Payload::ConcreteCollection {
                elem_type: elem_type.clone(),
                items: items
                    .iter()
                    .map(canonicalize_register_expr)
                    .collect::<Result<_, _>>()?,
            },
        }),
        other => other.clone(),
    })
}

/// Structural register re-encode for test-only boxes that carry no wire
/// `register_bytes`. Tuple-typed registers go out in `CreateTuple` form (see
/// `register::write_register_value`); this is acceptable only because the boxes
/// reaching this path never carry a Constant-encoded tuple register.
fn write_registers_structural(
    w: &mut ergo_primitives::writer::VlqWriter,
    b: &EvalBox,
) -> Result<(), EvalError> {
    use ergo_ser::register::{write_registers, AdditionalRegisters, RegisterValue};

    let registers: Vec<RegisterValue> = b
        .registers
        .iter()
        .flatten()
        .map(|r| {
            Ok(RegisterValue {
                tpe: r.tpe.clone(),
                value: canonicalize_group_elements(&r.value)?,
            })
        })
        .collect::<Result<_, EvalError>>()?;
    write_registers(w, &AdditionalRegisters { registers }).map_err(|e| EvalError::TypeError {
        expected: "serializable box registers",
        got: format!("register re-serialization failed: {e}"),
    })
}

/// Return a copy of `v` with every `GroupElement` canonicalized (recursing
/// through `Coll`/`Tuple`/`Option`). A lead-0x00 identity encoding normalizes to
/// 33 zero bytes; a non-identity point is curve-validated (and propagates an
/// error if off-curve, matching Scala's parse-time reject).
fn canonicalize_group_elements(
    v: &ergo_ser::sigma_value::SigmaValue,
) -> Result<ergo_ser::sigma_value::SigmaValue, EvalError> {
    use ergo_ser::sigma_value::{CollValue, SigmaValue};
    Ok(match v {
        SigmaValue::GroupElement(ge) => {
            let canon = super::sigma::canonicalize_group_element(*ge.as_bytes())?;
            SigmaValue::GroupElement(ergo_primitives::group_element::GroupElement::from_bytes(
                canon,
            ))
        }
        SigmaValue::Coll(CollValue::Values(vs)) => SigmaValue::Coll(CollValue::Values(
            vs.iter()
                .map(canonicalize_group_elements)
                .collect::<Result<_, _>>()?,
        )),
        SigmaValue::Tuple(vs) => SigmaValue::Tuple(
            vs.iter()
                .map(canonicalize_group_elements)
                .collect::<Result<_, _>>()?,
        ),
        SigmaValue::Opt(Some(inner)) => {
            SigmaValue::Opt(Some(Box::new(canonicalize_group_elements(inner)?)))
        }
        other => other.clone(),
    })
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
            let val = sigma_to_value_versioned(ext_tpe, ext_val, ctx)?;
            Ok(Value::Opt(Some(Box::new(val))))
        }
        None => Ok(Value::Opt(None)),
    }
}

use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::sigma_type::write_type;
use crate::sigma_value::write_constant;

use super::types::{Body, Expr, Payload};

/// Write an ErgoTree body (single root expression) to bytes.
pub fn write_body(
    w: &mut VlqWriter,
    body: &Body,
    constant_segregation: bool,
) -> Result<(), WriteError> {
    write_expr(w, body, constant_segregation)
}

/// Serialize a single expression to the byte stream.
///
/// Public so that register values can be written back as expressions.
pub fn write_expr(w: &mut VlqWriter, expr: &Expr, cseg: bool) -> Result<(), WriteError> {
    match expr {
        Expr::Const { tpe, val } => {
            write_constant(w, tpe, val)?;
        }
        Expr::Op(node) => {
            w.put_u8(node.opcode);
            write_payload(w, node.opcode, &node.payload, cseg)?;
        }
    }
    Ok(())
}

fn write_payload(
    w: &mut VlqWriter,
    opcode: u8,
    payload: &Payload,
    cseg: bool,
) -> Result<(), WriteError> {
    match payload {
        Payload::Zero => {}

        Payload::One(a) => {
            write_expr(w, a, cseg)?;
        }

        Payload::Two(a, b) => {
            write_expr(w, a, cseg)?;
            write_expr(w, b, cseg)?;
        }

        Payload::Three(a, b, c) => {
            write_expr(w, a, cseg)?;
            write_expr(w, b, cseg)?;
            write_expr(w, c, cseg)?;
        }

        Payload::Four(a, b, c, d) => {
            write_expr(w, a, cseg)?;
            write_expr(w, b, cseg)?;
            write_expr(w, c, cseg)?;
            write_expr(w, d, cseg)?;
        }

        Payload::ValUse { id } => {
            w.put_u32(*id);
        }

        Payload::ConstPlaceholder { index } => {
            w.put_u32(*index);
        }

        Payload::TaggedVar { id, .. } => {
            // 1-byte write to mirror Scala TaggedVariableSerializer.scala:12
            // (`w.put(varId)`). For the round-trip to be byte-faithful
            // with our `id: u32` field that sign-extends on read, we
            // truncate to the low byte here. Valid `id` values are
            // signed-Byte sign-extensions: `0..=127` (positive Bytes)
            // or `0xFFFF_FF80..=0xFFFF_FFFF` (negative Bytes). Any
            // other value would silently corrupt the wire byte.
            let as_byte = *id as u8;
            assert!(
                ((as_byte as i8) as i32 as u32) == *id,
                "TaggedVar id {id:#x} outside Scala signed-Byte range; \
                 valid ids are 0..=127 or 0xFFFF_FF80..=0xFFFF_FFFF"
            );
            w.put_u8(as_byte);
            // Type is never written (see parse comment above).
        }

        Payload::ValDef { id, rhs, .. } => {
            w.put_u32(*id);
            // Type is never written (see parse comment above).
            write_expr(w, rhs, cseg)?;
        }

        Payload::FunDef {
            id, tpe_args, rhs, ..
        } => {
            w.put_u32(*id);
            // Scala ValDefSerializer writes the tpeArgs block for the
            // FunDef opcode: count byte + STypeVar types, then the rhs.
            // Count is a single unsigned byte; a programmatic FunDef
            // with > 255 type args would wrap the count and desync the
            // stream from the written types (same guard as SFunc).
            assert!(
                tpe_args.len() <= u8::MAX as usize,
                "FunDef tpeArgs count too large for Scala wire format: {} (max 255)",
                tpe_args.len()
            );
            w.put_u8(tpe_args.len() as u8);
            for t in tpe_args {
                crate::sigma_type::write_type(w, t);
            }
            write_expr(w, rhs, cseg)?;
        }

        Payload::BlockValue { items, result } => {
            w.put_u32(items.len() as u32);
            for item in items {
                write_expr(w, item, cseg)?;
            }
            write_expr(w, result, cseg)?;
        }

        Payload::FuncValue { args, body } => {
            w.put_u32(args.len() as u32);
            for (id, tpe) in args {
                w.put_u32(*id);
                let t = tpe.as_ref().expect("FuncValue arg always has type");
                write_type(w, t);
            }
            write_expr(w, body, cseg)?;
        }

        Payload::MethodCall {
            type_id,
            method_id,
            obj,
            args,
            type_args,
        } => {
            w.put_u8(*type_id);
            w.put_u8(*method_id);
            write_expr(w, obj, cseg)?;
            // MethodCall (0xDC) writes arg count + args; PropertyCall
            // (0xDB) writes neither. BOTH then write the v6 explicit
            // type-args block for methods whose
            // `SMethod.hasExplicitTypeArgs` is true: e.g. `SGlobal.none`
            // is a PropertyCall that still carries `[T]`. Byte order
            // matches Scala's Method/PropertyCallSerializer (obj, then
            // the args list only for MethodCall, then the type block).
            if opcode != 0xDB {
                w.put_u32(args.len() as u32);
                for arg in args {
                    write_expr(w, arg, cseg)?;
                }
            }
            // Round-trip the explicit type args the parser captured.
            // Length is fixed at parse time by
            // `method_explicit_type_args_count` (0 for almost everything,
            // 1 for the v6 methods declaring `Seq(tT)`); zero writes zero.
            for t in type_args {
                crate::sigma_type::write_type(w, t);
            }
        }

        Payload::ConcreteCollection { elem_type, items } => {
            w.put_u16(items.len() as u16);
            write_type(w, elem_type);
            for item in items {
                write_expr(w, item, cseg)?;
            }
        }

        Payload::BoolCollection { bits } => {
            w.put_u16(bits.len() as u16);
            let n_bytes = bits.len().div_ceil(8);
            let mut packed = vec![0u8; n_bytes];
            for (i, &bit) in bits.iter().enumerate() {
                if bit {
                    let byte_idx = i / 8;
                    let bit_idx = i % 8; // LSB-first
                    packed[byte_idx] |= 1 << bit_idx;
                }
            }
            w.put_bytes(&packed);
        }

        Payload::Tuple { items } => {
            // 1-byte count to mirror Scala TupleSerializer.scala:21
            // (`w.putUByte(length)`). Scala's reader path uses signed
            // `getByte` so anything > 127 fails on the receiver side
            // anyway; emitting a single byte keeps wire fidelity.
            // Assert against silent wrap of usize → u8.
            assert!(
                items.len() <= u8::MAX as usize,
                "Tuple item count too large for Scala wire format: {} (max 255)",
                items.len()
            );
            w.put_u8(items.len() as u8);
            for item in items {
                write_expr(w, item, cseg)?;
            }
        }

        Payload::SelectField { input, field_idx } => {
            write_expr(w, input, cseg)?;
            w.put_u8(*field_idx);
        }

        Payload::ExtractRegisterAs { input, reg_id, tpe } => {
            write_expr(w, input, cseg)?;
            w.put_u8(*reg_id);
            write_type(w, tpe);
        }

        Payload::GetVar { var_id, tpe } => {
            w.put_u8(*var_id);
            write_type(w, tpe);
        }

        Payload::DeserializeContext { id, tpe } => {
            // Scala: type first, then id
            write_type(w, tpe);
            w.put_u8(*id);
        }

        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => {
            w.put_u8(*reg_id);
            write_type(w, tpe);
            if let Some(d) = default {
                w.put_u8(1);
                write_expr(w, d, cseg)?;
            } else {
                w.put_u8(0);
            }
        }

        Payload::SigmaCollection { items } => {
            w.put_u16(items.len() as u16);
            for item in items {
                write_expr(w, item, cseg)?;
            }
        }

        Payload::NoneValue { tpe } => {
            write_type(w, tpe);
        }

        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            write_expr(w, input, cseg)?;
            write_expr(w, index, cseg)?;
            if let Some(d) = default {
                w.put_u8(1);
                write_expr(w, d, cseg)?;
            } else {
                w.put_u8(0);
            }
        }

        Payload::NumericCast { input, tpe } => {
            write_expr(w, input, cseg)?;
            write_type(w, tpe);
        }

        Payload::FuncApply { func, args } => {
            write_expr(w, func, cseg)?;
            w.put_u32(args.len() as u32);
            for arg in args {
                write_expr(w, arg, cseg)?;
            }
        }
    }
    Ok(())
}

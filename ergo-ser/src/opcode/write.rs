use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::sigma_type::{write_type, SigmaType};
use crate::sigma_value::{write_constant, SigmaValue};

use super::types::{opcode_pattern, ArgPattern, Body, Expr, Payload};

/// If `opcode` is a `Relation2` operator and both operands are boolean
/// *constants*, return their values. Scala's `Relation2Serializer` then encodes
/// the pair as a compact `BoolCollection` (`0x85` + one packed byte, LSB-first)
/// instead of two child expressions; mirroring that keeps re-serialization
/// byte-identical to the reference. A genuine `Coll[Boolean]` operand is an
/// `Op(0x85, ..)`, not a bool `Const`, so it never matches here.
///
/// `0x85` in a Relation2 operand position is reserved for this compact form
/// (the reader in `opcode/parse.rs` treats a leading `0x85` there as the packed
/// pair), so a *bare* `BoolCollection` first operand is a grammar edge that
/// valid Scala-produced trees never emit — this writer is consistent with that
/// reader. Relation2 opcodes are `0x8F`–`0x94` (Lt/Le/Gt/Ge/Eq/Neq), `0xEC`
/// (BinOr), `0xED` (BinAnd) and `0xF4` (BinXor) — keyed via `opcode_pattern`.
fn relation2_bool_pair(opcode: u8, a: &Expr, b: &Expr) -> Option<(bool, bool)> {
    if !matches!(opcode_pattern(opcode), Some(ArgPattern::Relation2)) {
        return None;
    }
    match (a, b) {
        (
            Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(left),
            },
            Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(right),
            },
        ) => Some((*left, *right)),
        _ => None,
    }
}

/// Constant sink for the segregation write pass — the Rust analogue of Scala's
/// `ConstantStore` (`sigma/serialization/ConstantStore.scala:12-17`). When a
/// sink is threaded through [`write_expr_segregating`], every `Expr::Const`
/// node encountered during serialization is appended here and a
/// `ConstPlaceholder(index)` is written in its place — mirroring
/// `ValueSerializer.serialize`'s `constantExtractionStore` side effect
/// (`ValueSerializer.scala:359-368`).
///
/// **Append-only, slot = position = first-write order, NO dedup**
/// (`store += c`, source-confirmed): two syntactically-equal constants at
/// different tree positions get two distinct slots. This is deliberate —
/// Scala never introduces a shared `ValDef` for constants
/// (`TreeBuilding.scala:506-509`), so the store never needs a dedup path.
#[derive(Debug, Default)]
pub struct ConstantSink {
    constants: Vec<(SigmaType, SigmaValue)>,
}

impl ConstantSink {
    /// A fresh, empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `(tpe, val)` and return its placeholder slot index — always
    /// `constants.len()` at insertion time, matching `ConstantStore.put`'s
    /// returned `store.length - 1`.
    fn put(&mut self, tpe: SigmaType, val: SigmaValue) -> u32 {
        let index = self.constants.len() as u32;
        self.constants.push((tpe, val));
        index
    }

    /// Consume the sink, yielding the collected constants in first-write
    /// order — the `ErgoTree.constants` table for the segregated tree.
    pub fn into_constants(self) -> Vec<(SigmaType, SigmaValue)> {
        self.constants
    }
}

/// Write an ErgoTree body (single root expression) to bytes.
///
/// The `constant_segregation` flag is retained for signature stability (many
/// callers pass `tree.constant_segregation`): a materialized tree body already
/// carries its `ConstPlaceholder`/`Const` nodes verbatim, so no live constant
/// sink is threaded here — the flag only ever selects a *body* whose constants
/// are already placeholders. The extraction pass is [`write_expr_segregating`],
/// run BEFORE the tree is built (see `ergo-compiler/src/tree.rs`).
pub fn write_body(
    w: &mut VlqWriter,
    body: &Body,
    constant_segregation: bool,
) -> Result<(), WriteError> {
    let _ = constant_segregation;
    write_expr_inner(w, body, None)
}

/// Serialize a single expression to the byte stream (no constant extraction).
///
/// Public so that register values can be written back as expressions. The
/// `cseg` flag is inert (see [`write_body`]); a body reaching this path already
/// holds its constants inline or as placeholders.
pub fn write_expr(w: &mut VlqWriter, expr: &Expr, cseg: bool) -> Result<(), WriteError> {
    let _ = cseg;
    write_expr_inner(w, expr, None)
}

/// Serialize `expr`, extracting every `Expr::Const` into `sink` and writing a
/// `ConstPlaceholder(index)` in its place — Scala's `withSegregation` write
/// step (`ErgoTree.scala:384-398`; the extraction hook,
/// `ValueSerializer.scala:359-368`). This is the SAME recursive writer as
/// [`write_expr`], so the placeholder slot order is exactly the serialization
/// pre-order (writer child order), and the Relation2 bool-pair compact form
/// (`0x85`) — which bypasses the `Expr::Const` arm entirely — is never
/// segregated, for free.
///
/// The caller re-reads the produced bytes with [`super::parse_expr`] to
/// materialize the placeholder-bearing body, and takes the constants via
/// [`ConstantSink::into_constants`].
pub fn write_expr_segregating(
    w: &mut VlqWriter,
    expr: &Expr,
    sink: &mut ConstantSink,
) -> Result<(), WriteError> {
    write_expr_inner(w, expr, Some(sink))
}

/// The single recursive writer shared by [`write_expr`] (no sink) and
/// [`write_expr_segregating`] (with sink). Threading `Option<&mut ConstantSink>`
/// keeps ONE traversal as the source of truth for writer child order — a
/// hand-rolled second walk could silently drift from it.
fn write_expr_inner(
    w: &mut VlqWriter,
    expr: &Expr,
    sink: Option<&mut ConstantSink>,
) -> Result<(), WriteError> {
    match expr {
        Expr::Const { tpe, val } => match sink {
            // Segregation: append to the store, emit ConstPlaceholder (opcode
            // 0x73 + VLQ index; the TYPE is never written — it is recovered
            // from the store on read, ConstantPlaceholderSerializer parity).
            Some(sink) => {
                let index = sink.put(tpe.clone(), val.clone());
                w.put_u8(0x73);
                w.put_u32(index);
            }
            None => write_constant(w, tpe, val)?,
        },
        Expr::Op(node) => {
            w.put_u8(node.opcode);
            write_payload(w, node.opcode, &node.payload, sink)?;
        }
        // `Expr::Unparsed` is a whole-tree body (the full original bytes,
        // including the header), re-emitted only via `write_ergo_tree`; it is
        // never a sub-expression, so writing it here would corrupt the stream.
        Expr::Unparsed(_) => {
            return Err(WriteError::InvalidData(
                "Expr::Unparsed is a whole-tree body, not a sub-expression; use write_ergo_tree"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn write_payload(
    w: &mut VlqWriter,
    opcode: u8,
    payload: &Payload,
    mut sink: Option<&mut ConstantSink>,
) -> Result<(), WriteError> {
    match payload {
        Payload::Zero => {}

        Payload::One(a) => {
            write_expr_inner(w, a, sink.as_deref_mut())?;
        }

        Payload::Two(a, b) => {
            if let Some((left, right)) = relation2_bool_pair(opcode, a, b) {
                // Compact Relation2 bool-constant pair (Scala
                // Relation2Serializer): the 0x85 BoolCollection marker + one
                // packed byte, LSB-first (bit 0 = left, bit 1 = right). The
                // reader (opcode/parse.rs) decodes this back to the two Consts.
                w.put_u8(0x85);
                w.put_u8(u8::from(left) | (u8::from(right) << 1));
            } else {
                write_expr_inner(w, a, sink.as_deref_mut())?;
                write_expr_inner(w, b, sink.as_deref_mut())?;
            }
        }

        Payload::Three(a, b, c) => {
            write_expr_inner(w, a, sink.as_deref_mut())?;
            write_expr_inner(w, b, sink.as_deref_mut())?;
            write_expr_inner(w, c, sink.as_deref_mut())?;
        }

        Payload::Four(a, b, c, d) => {
            write_expr_inner(w, a, sink.as_deref_mut())?;
            write_expr_inner(w, b, sink.as_deref_mut())?;
            write_expr_inner(w, c, sink.as_deref_mut())?;
            write_expr_inner(w, d, sink.as_deref_mut())?;
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
            write_expr_inner(w, rhs, sink.as_deref_mut())?;
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
                crate::sigma_type::write_type(w, t)?;
            }
            write_expr_inner(w, rhs, sink.as_deref_mut())?;
        }

        Payload::BlockValue { items, result } => {
            w.put_u32(items.len() as u32);
            for item in items {
                write_expr_inner(w, item, sink.as_deref_mut())?;
            }
            write_expr_inner(w, result, sink.as_deref_mut())?;
        }

        Payload::FuncValue { args, body } => {
            w.put_u32(args.len() as u32);
            for (id, tpe) in args {
                w.put_u32(*id);
                let t = tpe.as_ref().expect("FuncValue arg always has type");
                write_type(w, t)?;
            }
            write_expr_inner(w, body, sink.as_deref_mut())?;
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
            write_expr_inner(w, obj, sink.as_deref_mut())?;
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
                    write_expr_inner(w, arg, sink.as_deref_mut())?;
                }
            }
            // Round-trip the explicit type args the parser captured.
            // Length is fixed at parse time by
            // `method_explicit_type_args_count` (0 for almost everything,
            // 1 for the v6 methods declaring `Seq(tT)`); zero writes zero.
            for t in type_args {
                crate::sigma_type::write_type(w, t)?;
            }
        }

        Payload::ConcreteCollection { elem_type, items } => {
            w.put_u16(items.len() as u16);
            write_type(w, elem_type)?;
            for item in items {
                write_expr_inner(w, item, sink.as_deref_mut())?;
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
                write_expr_inner(w, item, sink.as_deref_mut())?;
            }
        }

        Payload::SelectField { input, field_idx } => {
            write_expr_inner(w, input, sink.as_deref_mut())?;
            w.put_u8(*field_idx);
        }

        Payload::ExtractRegisterAs { input, reg_id, tpe } => {
            write_expr_inner(w, input, sink.as_deref_mut())?;
            w.put_u8(*reg_id);
            write_type(w, tpe)?;
        }

        Payload::GetVar { var_id, tpe } => {
            w.put_u8(*var_id);
            write_type(w, tpe)?;
        }

        Payload::DeserializeContext { id, tpe } => {
            // Scala: type first, then id
            write_type(w, tpe)?;
            w.put_u8(*id);
        }

        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => {
            w.put_u8(*reg_id);
            write_type(w, tpe)?;
            if let Some(d) = default {
                w.put_u8(1);
                write_expr_inner(w, d, sink.as_deref_mut())?;
            } else {
                w.put_u8(0);
            }
        }

        Payload::SigmaCollection { items } => {
            // SigmaAnd/SigmaOr child count is a u32 (`putUInt`), matching Scala's
            // `getUIntExact` on read — not a u16. For counts that fit a u16 the
            // VLQ is identical, so this preserves byte parity for real trees.
            w.put_u32(items.len() as u32);
            for item in items {
                write_expr_inner(w, item, sink.as_deref_mut())?;
            }
        }

        Payload::NoneValue { tpe } => {
            write_type(w, tpe)?;
        }

        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            write_expr_inner(w, input, sink.as_deref_mut())?;
            write_expr_inner(w, index, sink.as_deref_mut())?;
            if let Some(d) = default {
                w.put_u8(1);
                write_expr_inner(w, d, sink.as_deref_mut())?;
            } else {
                w.put_u8(0);
            }
        }

        Payload::NumericCast { input, tpe } => {
            write_expr_inner(w, input, sink.as_deref_mut())?;
            write_type(w, tpe)?;
        }

        Payload::FuncApply { func, args } => {
            write_expr_inner(w, func, sink.as_deref_mut())?;
            w.put_u32(args.len() as u32);
            for arg in args {
                write_expr_inner(w, arg, sink.as_deref_mut())?;
            }
        }
    }
    Ok(())
}

use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::sigma_type::{write_type, SigmaType};
use crate::sigma_value::{write_constant_versioned, SigmaValue};

use super::types::{opcode_pattern, ArgPattern, Body, Expr, IrNode, Payload};

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
    // `TrueLeaf` / `FalseLeaf` are Boolean constants here too, so a relation
    // over them packs like one over `01 01` / `01 00` (see [`boolean_leaf`]).
    let boolean = |e: &Expr| match e {
        Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(b),
        } => Some(*b),
        other => boolean_leaf(other),
    };
    Some((boolean(a)?, boolean(b)?))
}

/// The packed bit values if `node` is a `ConcreteCollection` (`0x83`) whose
/// element type is `SBoolean` and whose every item is a boolean `Const` —
/// Scala's `ConcreteCollection.isBooleanConstants` predicate (`values.scala:842`:
/// `elementType == SBoolean && items.forall(_.isInstanceOf[Constant[_]])`),
/// which flips `opCode` to `ConcreteCollectionBooleanConstantCode` (`0x85`).
///
/// An empty `Coll[Boolean]` qualifies (empty `forall` is vacuously true, and the
/// oracle packs it as `85 00`). A collection with any NON-constant item — a
/// `HEIGHT > 5` element, a `ValUse`, a nested `Op` — returns `None`, so it stays
/// the generic `0x83` `ConcreteCollection` whose items segregate individually
/// (the `Coll[Int]` / mixed-`Coll[Boolean]` control paths).
fn concrete_bool_collection(node: &IrNode) -> Option<Vec<bool>> {
    if node.opcode != 0x83 {
        return None;
    }
    let Payload::ConcreteCollection { elem_type, items } = &node.payload else {
        return None;
    };
    if *elem_type != SigmaType::SBoolean {
        return None;
    }
    items
        .iter()
        .map(|it| match it {
            Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(b),
            } => Some(*b),
            other => boolean_leaf(other),
        })
        .collect()
}

/// `TrueLeaf` / `FalseLeaf` (opcodes 0x7F / 0x80) as the Boolean they are.
///
/// Scala declares both as `ConstantNode`s (`values.scala:771`, `:782`), so the
/// parser accepts the bare opcode while every write treats them as constants:
/// `ValueSerializer.serialize` sends a `Constant` through `ConstantSerializer`
/// or the segregation store (`ValueSerializer.scala:362-370`), and a
/// `Coll[Boolean]` of them counts as constants for the packed `0x85` form
/// (`values.scala:871`). The writer never emits the opcode form.
fn boolean_leaf(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::Op(IrNode {
            opcode: 0x7F,
            payload: Payload::Zero,
        }) => Some(true),
        Expr::Op(IrNode {
            opcode: 0x80,
            payload: Payload::Zero,
        }) => Some(false),
        _ => None,
    }
}

/// Collection expression counts use the reference's unsigned-short field.
/// Caller-constructed IR must fit that field before any narrowing or packing.
fn collection_count(count: usize) -> Result<u16, WriteError> {
    u16::try_from(count).map_err(|_| {
        WriteError::InvalidData(format!(
            "collection expression has {count} elements, maximum is {}",
            u16::MAX
        ))
    })
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
    write_expr_inner(w, body, None, 3)
}

/// Serialize a single expression to the byte stream (no constant extraction).
///
/// Public so that register values can be written back as expressions. The
/// `cseg` flag is inert (see [`write_body`]); a body reaching this path already
/// holds its constants inline or as placeholders.
pub fn write_expr(w: &mut VlqWriter, expr: &Expr, cseg: bool) -> Result<(), WriteError> {
    let _ = cseg;
    write_expr_inner(w, expr, None, 3)
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
    write_expr_inner(w, expr, Some(sink), 3)
}

/// Serialize an expression with Scala's version-dependent constant Upcast rewrite.
/// The unversioned writer preserves explicit casts, as tree version 3 does.
pub fn write_expr_versioned(
    w: &mut VlqWriter,
    expr: &Expr,
    tree_version: u8,
) -> Result<(), WriteError> {
    write_expr_inner(w, expr, None, tree_version)
}

/// The single recursive writer shared by [`write_expr`] (no sink) and
/// [`write_expr_segregating`] (with sink). Threading `Option<&mut ConstantSink>`
/// keeps ONE traversal as the source of truth for writer child order — a
/// hand-rolled second walk could silently drift from it.
fn write_expr_inner(
    w: &mut VlqWriter,
    expr: &Expr,
    sink: Option<&mut ConstantSink>,
    tree_version: u8,
) -> Result<(), WriteError> {
    // ValueSerializer.serializable feeds the constant match only: a cast whose
    // input is nonconstant still uses the original opcode and serializer.
    // The ambient version can also come from block activation when serializing
    // registers/extensions. Deliberately preserve the JVM's signed-byte quirk.
    // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/serialization/ValueSerializer.scala#L157-L170
    let expr = if (tree_version as i8) < 3 {
        match expr {
            Expr::Op(IrNode {
                opcode: 0x7e,
                payload: Payload::NumericCast { input, .. },
            }) if matches!(input.as_ref(), Expr::Const { .. }) => input.as_ref(),
            _ => expr,
        }
    } else {
        expr
    };
    let leaf;
    let expr = match boolean_leaf(expr) {
        Some(b) => {
            leaf = Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(b),
            };
            &leaf
        }
        None => expr,
    };
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
            None => write_constant_versioned(w, tpe, val, tree_version)?,
        },
        Expr::Op(node) => {
            // Check before building the compact Boolean copy as well.
            match &node.payload {
                Payload::ConcreteCollection { items, .. } => {
                    collection_count(items.len())?;
                }
                Payload::BoolCollection { bits } => {
                    collection_count(bits.len())?;
                }
                _ => {}
            }
            if let Some(bits) = concrete_bool_collection(node) {
                // Scala's `ConcreteCollectionSerializer` dispatches an
                // all-boolean-*constant* collection to
                // `ConcreteCollectionBooleanConstantSerializer` (opcode `0x85`,
                // bit-packed) for ANY value position — `isBooleanConstants =
                // elementType == SBoolean && items.forall(_.isInstanceOf[Constant])`
                // (`values.scala:842/888`; `forall` on an empty collection is
                // vacuously true, so an empty `Coll[Boolean]` packs too). The
                // packed bits bypass the `Expr::Const` arm entirely, so they are
                // never segregated — exactly like the Relation2 bool-pair above,
                // and matching the oracle's single-entry constant table.
                w.put_u8(0x85);
                write_payload(
                    w,
                    0x85,
                    &Payload::BoolCollection { bits },
                    sink,
                    tree_version,
                )?;
            } else {
                // Deliberately match MethodCall.companion, including accepted
                // noncanonical wire nodes: empty args serialize as PropertyCall.
                // https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/values.scala#L1351
                let opcode = match &node.payload {
                    Payload::MethodCall { args, .. } if args.is_empty() => 0xDB,
                    _ => node.opcode,
                };
                w.put_u8(opcode);
                write_payload(w, opcode, &node.payload, sink, tree_version)?;
            }
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

/// Write a DIRECT Relation2 operand, suppressing the top-level
/// `ConcreteCollection[Boolean]` → `0x85` compaction that [`write_expr_inner`]
/// would otherwise apply (a leading `0x85` here is the reserved packed-pair
/// grammar — see the `Payload::Two` Relation2 arm). Only the operand's OWN node
/// is exempt; nested bool collections (e.g. under a `SizeOf`) recurse through
/// [`write_expr_inner`] normally and still compact where legal.
fn write_relation2_operand(
    w: &mut VlqWriter,
    expr: &Expr,
    sink: Option<&mut ConstantSink>,
    tree_version: u8,
) -> Result<(), WriteError> {
    if let Expr::Op(node) = expr {
        if node.opcode == 0x83 && concrete_bool_collection(node).is_some() {
            w.put_u8(0x83);
            return write_payload(w, 0x83, &node.payload, sink, tree_version);
        }
    }
    write_expr_inner(w, expr, sink, tree_version)
}

fn write_payload(
    w: &mut VlqWriter,
    opcode: u8,
    payload: &Payload,
    mut sink: Option<&mut ConstantSink>,
    tree_version: u8,
) -> Result<(), WriteError> {
    match payload {
        Payload::Zero => {}

        Payload::One(a) => {
            write_expr_inner(w, a, sink.as_deref_mut(), tree_version)?;
        }

        Payload::Two(a, b) => {
            if let Some((left, right)) = relation2_bool_pair(opcode, a, b) {
                // Compact Relation2 bool-constant pair (Scala
                // Relation2Serializer): the 0x85 BoolCollection marker + one
                // packed byte, LSB-first (bit 0 = left, bit 1 = right). The
                // reader (opcode/parse.rs) decodes this back to the two Consts.
                w.put_u8(0x85);
                w.put_u8(u8::from(left) | (u8::from(right) << 1));
            } else if matches!(opcode_pattern(opcode), Some(ArgPattern::Relation2)) {
                // A Relation2 operand position reserves a leading `0x85` for the
                // packed bool-PAIR form above (`Relation2Serializer.parse` reads
                // it as `getBits(2)`), so a top-level `ConcreteCollection[Boolean]`
                // operand must NOT be compacted to `0x85` here — it would be
                // misread as two loose bools. Scala never reaches this shape (it
                // lifts/folds an all-const bool `Coll` to a `Coll` Constant before
                // a Relation2 sees it — `Coll(true,false) == Coll(true,false)`
                // folds to `true`); our fold doesn't lift it yet (a D-C7 residual),
                // so we keep the self-readable generic `0x83` form here.
                write_relation2_operand(w, a, sink.as_deref_mut(), tree_version)?;
                write_relation2_operand(w, b, sink.as_deref_mut(), tree_version)?;
            } else {
                write_expr_inner(w, a, sink.as_deref_mut(), tree_version)?;
                write_expr_inner(w, b, sink.as_deref_mut(), tree_version)?;
            }
        }

        Payload::Three(a, b, c) => {
            write_expr_inner(w, a, sink.as_deref_mut(), tree_version)?;
            write_expr_inner(w, b, sink.as_deref_mut(), tree_version)?;
            write_expr_inner(w, c, sink.as_deref_mut(), tree_version)?;
        }

        Payload::Four(a, b, c, d) => {
            write_expr_inner(w, a, sink.as_deref_mut(), tree_version)?;
            write_expr_inner(w, b, sink.as_deref_mut(), tree_version)?;
            write_expr_inner(w, c, sink.as_deref_mut(), tree_version)?;
            write_expr_inner(w, d, sink.as_deref_mut(), tree_version)?;
        }

        Payload::ValUse { id } => {
            w.put_u32(*id);
        }

        Payload::ConstPlaceholder { index } => {
            w.put_u32(*index);
        }

        Payload::TaggedVar { id, tpe } => {
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
            // TaggedVariableSerializer.serialize always writes the type.
            let tpe = tpe.as_ref().ok_or_else(|| {
                WriteError::InvalidData("TaggedVar requires its type on the wire".into())
            })?;
            write_type_versioned(w, tpe, tree_version)?;
        }

        Payload::ValDef { id, rhs, .. } => {
            w.put_u32(*id);
            // Type is never written (see parse comment above).
            write_expr_inner(w, rhs, sink.as_deref_mut(), tree_version)?;
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
                write_type_versioned(w, t, tree_version)?;
            }
            write_expr_inner(w, rhs, sink.as_deref_mut(), tree_version)?;
        }

        Payload::BlockValue { items, result } => {
            w.put_u32(items.len() as u32);
            for item in items {
                write_expr_inner(w, item, sink.as_deref_mut(), tree_version)?;
            }
            write_expr_inner(w, result, sink.as_deref_mut(), tree_version)?;
        }

        Payload::FuncValue { args, body } => {
            w.put_u32(args.len() as u32);
            for (id, tpe) in args {
                w.put_u32(*id);
                let t = tpe.as_ref().expect("FuncValue arg always has type");
                write_type_versioned(w, t, tree_version)?;
            }
            write_expr_inner(w, body, sink.as_deref_mut(), tree_version)?;
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
            write_expr_inner(w, obj, sink.as_deref_mut(), tree_version)?;
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
                    write_expr_inner(w, arg, sink.as_deref_mut(), tree_version)?;
                }
            }
            // Round-trip the explicit type args the parser captured.
            // Length is fixed at parse time by
            // `method_explicit_type_args_count` (0 for almost everything,
            // 1 for the v6 methods declaring `Seq(tT)`); zero writes zero.
            for t in type_args {
                write_type_versioned(w, t, tree_version)?;
            }
        }

        Payload::ConcreteCollection { elem_type, items } => {
            w.put_u16(collection_count(items.len())?);
            write_type_versioned(w, elem_type, tree_version)?;
            for item in items {
                write_expr_inner(w, item, sink.as_deref_mut(), tree_version)?;
            }
        }

        Payload::BoolCollection { bits } => {
            w.put_u16(collection_count(bits.len())?);
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
                write_expr_inner(w, item, sink.as_deref_mut(), tree_version)?;
            }
        }

        Payload::SelectField { input, field_idx } => {
            write_expr_inner(w, input, sink.as_deref_mut(), tree_version)?;
            w.put_u8(*field_idx);
        }

        Payload::ExtractRegisterAs { input, reg_id, tpe } => {
            write_expr_inner(w, input, sink.as_deref_mut(), tree_version)?;
            w.put_u8(*reg_id);
            write_type_versioned(w, tpe, tree_version)?;
        }

        Payload::GetVar { var_id, tpe } => {
            w.put_u8(*var_id);
            write_type_versioned(w, tpe, tree_version)?;
        }

        Payload::DeserializeContext { id, tpe } => {
            // Scala: type first, then id
            write_type_versioned(w, tpe, tree_version)?;
            w.put_u8(*id);
        }

        Payload::DeserializeRegister {
            reg_id,
            tpe,
            default,
        } => {
            w.put_u8(*reg_id);
            write_type_versioned(w, tpe, tree_version)?;
            if let Some(d) = default {
                w.put_u8(1);
                write_expr_inner(w, d, sink.as_deref_mut(), tree_version)?;
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
                write_expr_inner(w, item, sink.as_deref_mut(), tree_version)?;
            }
        }

        Payload::NoneValue { tpe } => {
            write_type_versioned(w, tpe, tree_version)?;
        }

        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            write_expr_inner(w, input, sink.as_deref_mut(), tree_version)?;
            write_expr_inner(w, index, sink.as_deref_mut(), tree_version)?;
            if let Some(d) = default {
                w.put_u8(1);
                write_expr_inner(w, d, sink.as_deref_mut(), tree_version)?;
            } else {
                w.put_u8(0);
            }
        }

        Payload::NumericCast { input, tpe } => {
            write_expr_inner(w, input, sink.as_deref_mut(), tree_version)?;
            write_type_versioned(w, tpe, tree_version)?;
        }

        Payload::FuncApply { func, args } => {
            write_expr_inner(w, func, sink.as_deref_mut(), tree_version)?;
            w.put_u32(args.len() as u32);
            for arg in args {
                write_expr_inner(w, arg, sink.as_deref_mut(), tree_version)?;
            }
        }
    }
    Ok(())
}

fn write_type_versioned(w: &mut VlqWriter, tpe: &SigmaType, version: u8) -> Result<(), WriteError> {
    fn contains_func(tpe: &SigmaType) -> bool {
        match tpe {
            SigmaType::SFunc { .. } => true,
            SigmaType::SColl(inner) | SigmaType::SOption(inner) => contains_func(inner),
            SigmaType::STuple(items) => items.iter().any(contains_func),
            _ => false,
        }
    }
    if (version as i8) < 3 && contains_func(tpe) {
        return Err(WriteError::InvalidData(
            "SFunc type requires ErgoTree version >= 3".into(),
        ));
    }
    write_type(w, tpe)
}

#[cfg(test)]
mod count_tests {
    use super::*;

    #[test]
    fn collection_count_field_boundaries() {
        assert_eq!(collection_count(u16::MAX as usize).unwrap(), u16::MAX);
        assert!(collection_count(u16::MAX as usize + 1).is_err());
    }

    #[test]
    fn public_writer_refuses_all_oversized_collection_forms() {
        let count = u16::MAX as usize + 1;
        let boolean = Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        };
        let integer = Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(1),
        };
        let payloads = [
            (
                0x85,
                Payload::BoolCollection {
                    bits: vec![true; count],
                },
            ),
            (
                0x83,
                Payload::ConcreteCollection {
                    elem_type: SigmaType::SBoolean,
                    items: vec![boolean; count],
                },
            ),
            (
                0x83,
                Payload::ConcreteCollection {
                    elem_type: SigmaType::SInt,
                    items: vec![integer; count],
                },
            ),
        ];
        for (opcode, payload) in payloads {
            let mut writer = VlqWriter::new();
            let expression = Expr::Op(IrNode { opcode, payload });
            assert!(write_expr(&mut writer, &expression, false).is_err());
            assert!(writer.result().is_empty(), "no narrowed root count emitted");
        }
    }
}

//! The **`EvaluatedValue` vocabulary** shared by every wire position that Scala
//! parses with `ValueSerializer.deserialize(...).asInstanceOf[EvaluatedValue[_]]`
//! rather than with the constant reader: box **registers** and input
//! **context-extension** values.
//!
//! `EvaluatedValue` is a sealed trait (`sigma/ast/values.scala:310`) with exactly
//! four inhabitants, and `ValidationRules.CheckV6Type` (rule 1019,
//! `ValidationRules.scala:186-192`) enumerates them:
//!
//! | node | opcode | reference verdict |
//! |---|---|---|
//! | `Constant` | its own type code (`<= 0x70`) | accept |
//! | `ConcreteCollection` | `0x83` / `0x85` (bool-packed) | accept |
//! | `Tuple` | `0x86` | accept |
//! | `GroupGenerator` | `0x82` | accept |
//! | anything else (`Height` `0xA3`, `Inputs` `0xA4`, `Self` `0xA7`, …) | — | **reject** (`ClassCastException`) |
//!
//! The generators place all five classes at both positions and record a feature
//! bit for each, so a campaign that never reaches one is provably a gap. The
//! `Constant` arm also draws from the FULL constant vocabulary — every primitive
//! plus nested `Coll[Coll[Byte]]` / tuple shapes — because the register and
//! extension readers are the only places those nest without an enclosing tree.
//!
//! Provenance for the accept column: PR #301 (`Refs #301`) verified each verdict
//! against sigma-state 6.0.2 + ergo-core 6.0.2 via the JVM oracle.

use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaBoolean, SigmaValue};

use crate::gen::asm;
use crate::gen::Feature;
use crate::rng::Rng;

/// Where an evaluated value is being placed. Only the recorded feature bits
/// differ — the wire vocabulary is identical at both positions, which is the
/// whole point (Scala uses the same `getValue()` call for both).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    /// A box register entry (`ErgoBoxCandidate.serializer`, `R4..R9`).
    Register,
    /// An input's context-extension entry (`ContextExtension.serializer`).
    ContextExtension,
}

/// One generated evaluated-value slot.
pub struct EvValue {
    /// Wire bytes of the value (no key / register-id prefix).
    pub bytes: Vec<u8>,
    /// The feature bit this slot contributes.
    pub feature: Feature,
    /// `true` when the Scala reference is believed to PARSE this value.
    pub reference_accepts: bool,
}

/// Serialize a standalone value node the way `ValueSerializer.serialize` does
/// (no constant segregation — a register / extension value is written
/// self-contained).
pub(crate) fn value_bytes(expr: &Expr) -> Vec<u8> {
    use ergo_primitives::writer::VlqWriter;
    let mut w = VlqWriter::new();
    // Every expression this module builds is writer-serializable; a WriteError
    // would be a generator bug, so surface it rather than emit truncated bytes.
    ergo_ser::opcode::write_expr(&mut w, expr, false).expect("evaluated value must serialize");
    w.result()
}

fn konst(tpe: SigmaType, val: SigmaValue) -> Expr {
    Expr::Const { tpe, val }
}

fn coll_byte(tpe: SigmaType) -> SigmaType {
    SigmaType::SColl(Box::new(tpe))
}

/// A `Constant` drawn from the full constant vocabulary, including the nested
/// `Coll` / tuple shapes that only ever appear un-nested at these two positions.
fn constant(rng: &mut Rng) -> Expr {
    match rng.below(12) {
        0 => konst(SigmaType::SBoolean, SigmaValue::Boolean(rng.coin())),
        1 => konst(SigmaType::SByte, SigmaValue::Byte(rng.byte() as i8)),
        2 => konst(SigmaType::SShort, SigmaValue::Short(rng.next_u64() as i16)),
        3 => konst(SigmaType::SInt, SigmaValue::Int(rng.next_u64() as i32)),
        4 => konst(SigmaType::SLong, SigmaValue::Long(rng.next_u64() as i64)),
        5 => konst(
            SigmaType::SBigInt,
            SigmaValue::BigInt(num_bigint::BigInt::from(rng.next_u64() as i64)),
        ),
        6 => konst(
            SigmaType::SGroupElement,
            SigmaValue::GroupElement(ergo_primitives::group_element::GroupElement::from_bytes(
                asm::VALID_GENERATOR_GE,
            )),
        ),
        7 => konst(
            SigmaType::SSigmaProp,
            SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(rng.coin())),
        ),
        8 => konst(
            coll_byte(SigmaType::SByte),
            SigmaValue::Coll(CollValue::Bytes(
                (0..rng.range(0, 8)).map(|i| i as u8).collect(),
            )),
        ),
        9 => konst(
            coll_byte(SigmaType::SInt),
            SigmaValue::Coll(CollValue::Values(
                (0..rng.range(1, 4))
                    .map(|i| SigmaValue::Int(i as i32))
                    .collect(),
            )),
        ),
        // Coll[Coll[Byte]] — the nested-collection shape.
        10 => konst(
            coll_byte(coll_byte(SigmaType::SByte)),
            SigmaValue::Coll(CollValue::Values(vec![
                SigmaValue::Coll(CollValue::Bytes(vec![1, 2, 3])),
                SigmaValue::Coll(CollValue::Bytes(vec![4])),
            ])),
        ),
        // (Coll[Byte], Long) — the token-shaped tuple CONSTANT (distinct from the
        // `Tuple` NODE below: a tuple Constant keeps real pair semantics).
        _ => konst(
            SigmaType::STuple(vec![coll_byte(SigmaType::SByte), SigmaType::SLong]),
            SigmaValue::Tuple(vec![
                SigmaValue::Coll(CollValue::Bytes(vec![0xAA; 4])),
                SigmaValue::Long(rng.next_u64() as i64),
            ]),
        ),
    }
}

/// A `Tuple` NODE (`0x86`) — an `EvaluatedValue` whose `.value` is a `Coll`, not
/// a `Tuple2` (`values.scala:786-791`). Accepted at parse by the reference; a
/// consumer that type-checks against `STuple` then fails.
fn tuple_node(rng: &mut Rng) -> Expr {
    let items = match rng.below(3) {
        0 => vec![
            konst(SigmaType::SInt, SigmaValue::Int(1)),
            konst(SigmaType::SInt, SigmaValue::Int(2)),
        ],
        1 => vec![
            konst(SigmaType::SLong, SigmaValue::Long(rng.next_u64() as i64)),
            konst(SigmaType::SBoolean, SigmaValue::Boolean(rng.coin())),
        ],
        _ => vec![
            konst(
                coll_byte(SigmaType::SByte),
                SigmaValue::Coll(CollValue::Bytes(vec![0x11; 4])),
            ),
            konst(SigmaType::SInt, SigmaValue::Int(7)),
            konst(SigmaType::SInt, SigmaValue::Int(8)),
        ],
    };
    Expr::Op(IrNode {
        opcode: 0x86,
        payload: Payload::Tuple { items },
    })
}

/// A `ConcreteCollection` NODE (`0x83`, or `0x85` when the element type is
/// `SBoolean` and every item is a constant).
fn concrete_collection_node(rng: &mut Rng) -> Expr {
    let (elem_type, items) = match rng.below(3) {
        0 => (
            SigmaType::SInt,
            vec![
                konst(SigmaType::SInt, SigmaValue::Int(7)),
                konst(SigmaType::SInt, SigmaValue::Int(8)),
            ],
        ),
        1 => (
            SigmaType::SBoolean,
            vec![
                konst(SigmaType::SBoolean, SigmaValue::Boolean(true)),
                konst(SigmaType::SBoolean, SigmaValue::Boolean(false)),
                konst(SigmaType::SBoolean, SigmaValue::Boolean(rng.coin())),
            ],
        ),
        _ => (
            SigmaType::SLong,
            (0..rng.range(1, 4))
                .map(|i| konst(SigmaType::SLong, SigmaValue::Long(i as i64)))
                .collect(),
        ),
    };
    Expr::Op(IrNode {
        opcode: 0x83,
        payload: Payload::ConcreteCollection { elem_type, items },
    })
}

/// `GroupGenerator` (`0x82`) — a zero-argument `EvaluatedValue`.
fn group_generator_node() -> Expr {
    Expr::Op(IrNode {
        opcode: 0x82,
        payload: Payload::Zero,
    })
}

/// A node that is a `Value` but NOT an `EvaluatedValue`. Scala's
/// `asInstanceOf[EvaluatedValue[_]]` raises `ClassCastException` on these, so
/// the reference REJECTS them at both positions.
fn non_evaluated_node(rng: &mut Rng) -> Expr {
    // Height (0xA3), Inputs (0xA4), Outputs (0xA5), Self (0xA7) — all zero-arg,
    // so the wire form is a single opcode byte and the reject cause is
    // unambiguous (the node kind, not a malformed payload).
    let opcode = match rng.below(4) {
        0 => 0xA3,
        1 => 0xA4,
        2 => 0xA5,
        _ => 0xA7,
    };
    Expr::Op(IrNode {
        opcode,
        payload: Payload::Zero,
    })
}

/// Draw one evaluated-value slot for `position`.
///
/// Distribution: ~40 % plain/nested `Constant` (the only form the pre-#301 Rust
/// reader accepted), ~45 % the three non-`Constant` `EvaluatedValue` nodes (the
/// reject-valid class), ~15 % a non-evaluated node (the accept-invalid guard).
pub fn gen_value(rng: &mut Rng, position: Position) -> EvValue {
    let (expr, evaluated_node, reference_accepts) = match rng.below(20) {
        0..=7 => (constant(rng), false, true),
        8..=11 => (tuple_node(rng), true, true),
        12..=15 => (concrete_collection_node(rng), true, true),
        16 => (group_generator_node(), true, true),
        _ => (non_evaluated_node(rng), false, false),
    };
    let feature = match (position, reference_accepts, evaluated_node) {
        (Position::Register, true, false) => Feature::RegisterConstantVocabulary,
        (Position::Register, true, true) => Feature::RegisterEvaluatedNode,
        (Position::Register, false, _) => Feature::RegisterNonEvaluatedNode,
        (Position::ContextExtension, true, false) => Feature::CtxExtConstantVocabulary,
        (Position::ContextExtension, true, true) => Feature::CtxExtEvaluatedNode,
        (Position::ContextExtension, false, _) => Feature::CtxExtNonEvaluatedNode,
    };
    EvValue {
        bytes: value_bytes(&expr),
        feature,
        reference_accepts,
    }
}

/// Assemble a full context-extension block: `count(u8) · (key(u8) · value)*`.
/// Returns the bytes, the union of the per-slot features, and whether the
/// reference is believed to accept the whole block (it rejects on the FIRST
/// non-evaluated entry).
pub fn gen_context_extension(rng: &mut Rng, max_entries: usize) -> (Vec<u8>, Vec<Feature>, bool) {
    let n = rng.range(1, max_entries);
    let mut bytes = vec![n as u8];
    let mut features = Vec::with_capacity(n);
    let mut accepts = true;
    for i in 0..n {
        let v = gen_value(rng, Position::ContextExtension);
        // Keys 1..=n: var 0 is reserved by convention for the P2S script argument
        // and carries no special parse meaning, but keeping keys distinct and
        // small keeps the ≤ 4-entry `Map1`-`Map4` order path (no HAMT re-sort).
        bytes.push((i + 1) as u8);
        bytes.extend_from_slice(&v.bytes);
        features.push(v.feature);
        accepts &= v.reference_accepts;
    }
    (bytes, features, accepts)
}

/// Assemble a full register block: `count(u8) · value*` for `R4..R(4+count-1)`.
/// Registers are positional — there is no id byte — so a block of `n` values
/// fills `R4..`, and the reference rejects the whole box on the first
/// non-evaluated entry.
pub fn gen_register_block(rng: &mut Rng, max_registers: usize) -> (Vec<u8>, Vec<Feature>, bool) {
    let n = rng.range(1, max_registers);
    let mut bytes = vec![n as u8];
    let mut features = Vec::with_capacity(n);
    let mut accepts = true;
    for _ in 0..n {
        let v = gen_value(rng, Position::Register);
        bytes.extend_from_slice(&v.bytes);
        features.push(v.feature);
        accepts &= v.reference_accepts;
    }
    (bytes, features, accepts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;

    // ----- helpers -----

    fn features_of(n: usize, position: Position) -> Vec<Feature> {
        let mut rng = Rng::new(0xE7A1_5EED_0000_0001);
        (0..n)
            .map(|_| gen_value(&mut rng, position).feature)
            .collect()
    }

    // ----- happy path -----

    #[test]
    fn gen_value_reaches_every_evaluated_value_class_at_both_positions() {
        for (position, expected) in [
            (
                Position::Register,
                [
                    Feature::RegisterConstantVocabulary,
                    Feature::RegisterEvaluatedNode,
                    Feature::RegisterNonEvaluatedNode,
                ],
            ),
            (
                Position::ContextExtension,
                [
                    Feature::CtxExtConstantVocabulary,
                    Feature::CtxExtEvaluatedNode,
                    Feature::CtxExtNonEvaluatedNode,
                ],
            ),
        ] {
            let seen = features_of(500, position);
            for f in expected {
                assert!(
                    seen.contains(&f),
                    "{position:?}: feature {} never generated",
                    f.name()
                );
            }
        }
    }

    // ----- round-trips -----

    #[test]
    fn generated_context_extension_blocks_are_self_delimiting() {
        let mut rng = Rng::new(7);
        for _ in 0..500 {
            let (bytes, features, accepts) = gen_context_extension(&mut rng, 4);
            assert!(!features.is_empty());
            let mut r = VlqReader::new(&bytes);
            match ergo_ser::input::read_context_extension(&mut r) {
                // Whatever the node's reader decides, it must never over-read:
                // a parse that succeeds has to consume the WHOLE block, since
                // the frame that follows depends on the boundary.
                Ok(_) => assert_eq!(
                    r.position(),
                    bytes.len(),
                    "extension parse did not consume the block: {}",
                    crate::to_hex(&bytes)
                ),
                Err(_) => assert!(
                    !accepts || bytes.len() > 1,
                    "empty block must never fail to parse"
                ),
            }
        }
    }

    // ----- error paths -----

    #[test]
    fn non_evaluated_node_blocks_are_marked_reference_rejected() {
        let mut rng = Rng::new(11);
        let mut saw = false;
        for _ in 0..2_000 {
            let v = gen_value(&mut rng, Position::ContextExtension);
            if v.feature == Feature::CtxExtNonEvaluatedNode {
                saw = true;
                assert!(
                    !v.reference_accepts,
                    "a non-evaluated node must be marked reference-rejected"
                );
                assert_eq!(v.bytes.len(), 1, "zero-arg node is one opcode byte");
            }
        }
        assert!(saw, "non-evaluated vocabulary never generated");
    }
}

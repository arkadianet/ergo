//! Oracle-parity regression for the testnet-431366 (and mainnet-1808895 family)
//! `0x86` generic-tuple register evaluation divergence.
//!
//! Testnet block 431,367 (`66bfa980ca05f35b6d6be583208e8157b3334ea5764d931f3746d286a54dd05c`)
//! contains tx `65238ca7254e0cdeda335b4954d6e234af4a89bab3d78d56837cf35621335424`
//! whose input #0 spends box
//! `43d46db11f55e7b1e047842db0920910e845227b8310f6bfdf8a89e38d204e0c`
//! (created height 431358 by tx `16b29b4a58417be9b9cdbeff78382d15fa0e6510d1499f629e416960d1d4a5db`).
//! That box carries registers serialized as `CreateTuple` (opcode `0x86`) AST
//! nodes rather than plain `Constant`s (fetched live, read-only, from the local
//! testnet node `http://127.0.0.1:9052`):
//!
//! - R8 = `860204cce3340454`                            → `(Int, Int) = (432358, 42)`
//! - R9 = `86020e201f2f27fda40c7fcb73c67469ad40e712c926ea1e43f8ab1e11d7e38f1e63c72205f02e`
//!
//! The box script does `SELF.R8[(Int, Int)].get`. Scala 6.0.3 REJECTS the spend
//! during `verifyInput` (the observed oracle log line):
//!
//! ```text
//! sigma.exceptions.InterpreterException: Invalid type returned by evaluator:
//!   expression: ValDef(10, OptionGet(ExtractRegisterAs(Self, R8, Option[(SInt,SInt)])))
//!   expected type: (SInt,SInt)
//!   resulting value: Coll(432358,42)          (ErgoTree scriptVersion 3)
//! ```
//!
//! Root cause (Scala source, reference/ergo-core sigmastate-interpreter):
//! `CBox.regs` (CBox.scala:85) stores each register as its `EvaluatedValue`
//! node's `.value`. A `Tuple` node's `.value` is `Colls.fromArray(items)` — a
//! `Coll`, NOT a `Tuple2` (values.scala:789-793) — whereas a `Constant[STuple]`
//! deserializes to a real `Tuple2` (CoreDataSerializer `toDslTuple`). Reading
//! the register at its `(Int, Int)` type therefore yields a `Coll`, and
//! `Value.checkType` at the `BlockValue` ValDef boundary (values.scala:998) —
//! `SType.isValueOfType` requires a 2-item tuple value to be a `Tuple2`
//! (SType.scala:200-201) — throws. `SelectField.eval` throws the same way on a
//! non-`Tuple2` (transformers.scala). Both are version-independent.
//!
//! Our node previously lowered BOTH the `0x86` `Tuple` node and a
//! `Constant[STuple]` to `Value::Tuple`, so it ACCEPTED the spend
//! (accept-invalid). The fix: a `0x86` `CreateTuple` register read at its
//! `STuple` type materializes as a `Value::CollGeneric` (Scala's `Coll`), which
//! the ValDef `checkType` and `SelectField` reject — while a `Constant`-encoded
//! pair register keeps its `Value::Tuple` and is still accepted.

use ergo_primitives::cost::CostAccumulator;
use ergo_primitives::reader::VlqReader;
use ergo_ser::opcode::{Expr, IrNode, Payload};
use ergo_ser::register::{read_registers, RegisterId};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_sigma::evaluator::{reduce_expr_with_cost, EvalBox, ReductionContext};

// ----- helpers -----

/// The real R8 wire bytes from the live spend, wrapped as a one-register
/// (R4-slot) block: `count(1) || 0x86-CreateTuple entry`.
const R8_TUPLE_NODE_ENTRY: &[u8] = &[0x86, 0x02, 0x04, 0xcc, 0xe3, 0x34, 0x04, 0x54];

/// The SAME logical `(432358, 42)` pair encoded as a plain `Constant` with the
/// symmetric-`Int`-pair type code `0x58` (= PairSymmetricTypeCode 84 + SInt
/// typeCode 4) followed by the two zig-zag VLQ ints `cce334` and `54`. This is
/// the canonical form standard tooling emits (a `ConstantNode[STuple]`), which
/// Scala deserializes to a real `Tuple2` and ACCEPTS.
const PAIR_CONSTANT_ENTRY: &[u8] = &[0x58, 0xcc, 0xe3, 0x34, 0x54];

fn register_block(entry: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + entry.len());
    v.push(0x01); // one register (R4)
    v.extend_from_slice(entry);
    v
}

/// Build a SELF box whose R4 register is `entry` (verbatim wire), with matching
/// parsed `registers` and `register_bytes` so the evaluator's node-provenance
/// detection sees the real encoding.
fn self_box_with_r4(entry: &[u8]) -> EvalBox {
    let block = register_block(entry);
    let regs = read_registers(&mut VlqReader::new(&block)).expect("register block parses");
    let r4 = regs.get(RegisterId::R4).expect("R4 present").clone();
    // Sanity: both encodings parse to the identical logical value.
    assert_eq!(
        r4.tpe,
        SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SInt])
    );
    assert_eq!(
        r4.value,
        SigmaValue::Tuple(vec![SigmaValue::Int(432358), SigmaValue::Int(42)])
    );
    let mut b = EvalBox::simple(431_358, vec![0x00]);
    b.registers[0] = Some(r4);
    b.register_bytes = block;
    b
}

fn op(opcode: u8, payload: Payload) -> Expr {
    Expr::Op(IrNode { opcode, payload })
}

/// `SELF.R4[(Int, Int)]` — `ExtractRegisterAs(Self, R4, (Int,Int))`.
fn extract_r4_pair() -> Expr {
    op(
        0xC6,
        Payload::ExtractRegisterAs {
            input: Box::new(op(0xA7, Payload::Zero)), // Self
            reg_id: 4,
            tpe: SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SInt]),
        },
    )
}

/// `SELF.R4[(Int, Int)].get` — `OptionGet(ExtractRegisterAs(...))`.
fn get_r4_pair() -> Expr {
    op(0xE4, Payload::One(Box::new(extract_r4_pair())))
}

/// `BoolToSigmaProp(SelectField(input, 1) >= 0)` — a valid `SigmaProp` result
/// that first destructures the pair (so a `Coll` masquerading as a tuple is
/// caught by `SelectField`, matching Scala's `SelectField.eval` typeError).
fn use_first_field_ge_zero(input: Expr) -> Expr {
    let field = op(
        0x8C,
        Payload::SelectField {
            input: Box::new(input),
            field_idx: 1,
        },
    );
    let zero = Expr::Const {
        tpe: SigmaType::SInt,
        val: SigmaValue::Int(0),
    };
    let ge = op(0x92, Payload::Two(Box::new(field), Box::new(zero)));
    op(0xD1, Payload::One(Box::new(ge))) // BoolToSigmaProp
}

fn reduce_with_self(
    expr: &Expr,
    self_box: &EvalBox,
) -> Result<SigmaBoolean, ergo_sigma::evaluator::EvalError> {
    // scriptVersion 3 / activated v6, matching the live block's ErgoTree.
    let mut ctx = ReductionContext::minimal_v6(431_367, 431_358);
    ctx.self_box = Some(self_box);
    let mut cost = CostAccumulator::recording_only();
    reduce_expr_with_cost(expr, &ctx, &[], &mut cost)
}

// ----- oracle parity -----

/// Vector 1 (THE live spend): a `0x86` CreateTuple register bound at a pair
/// type via `ValDef(10, OptionGet(ExtractRegisterAs(Self, R4, (Int,Int))))` —
/// the exact shape from the Scala reject log — must FAIL script verification.
/// Oracle: the observed Scala `InterpreterException: Invalid type returned by
/// evaluator ... resulting value: Coll(432358,42)`.
#[test]
fn tuple_node_register_bound_at_pair_type_via_valdef_rejects() {
    let self_box = self_box_with_r4(R8_TUPLE_NODE_ENTRY);
    // { val x = SELF.R4[(Int,Int)].get; BoolToSigmaProp(x._1 >= 0) }
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 10,
                    tpe: None, // Scala never serializes the ValDef type; it is rhs.tpe
                    rhs: Box::new(get_r4_pair()),
                },
            )],
            result: Box::new(use_first_field_ge_zero(op(
                0x72,
                Payload::ValUse { id: 10 },
            ))),
        },
    );
    let res = reduce_with_self(&block, &self_box);
    assert!(
        res.is_err(),
        "0x86 CreateTuple register read as (Int,Int) and bound at a ValDef must \
         REJECT (Scala InterpreterException 'Invalid type returned by evaluator'), \
         got {res:?}",
    );
}

/// Vector 1 (direct path, no ValDef): `SELF.R4[(Int,Int)].get._1` — the `Coll`
/// is caught by `SelectField` (Scala `SelectField.eval` typeError on a
/// non-`Tuple2`). Must FAIL.
#[test]
fn tuple_node_register_select_field_rejects() {
    let self_box = self_box_with_r4(R8_TUPLE_NODE_ENTRY);
    let expr = use_first_field_ge_zero(get_r4_pair());
    let res = reduce_with_self(&expr, &self_box);
    assert!(
        res.is_err(),
        "SelectField over a 0x86 CreateTuple register read as (Int,Int) must \
         REJECT (Scala SelectField typeError), got {res:?}",
    );
}

/// Vector 2 (over-rejection guard): the SAME logical `(432358, 42)` pair encoded
/// as a plain `Constant` (pair type code `0x58`) keeps its real `Tuple2` value
/// and must still be ACCEPTED — both via the ValDef path and directly.
///
/// Oracle (Scala source): a `Constant[STuple]` deserializes through
/// `CoreDataSerializer` `toDslTuple` to a `Tuple2`; `CBox.regs` stores that
/// `Tuple2`; `getReg[(Int,Int)]` returns it; `SType.isValueOfType(Tuple2,
/// (Int,Int))` is `true` (SType.scala:200-201) — no `checkType` throw.
#[test]
fn pair_constant_register_bound_at_pair_type_accepts() {
    let self_box = self_box_with_r4(PAIR_CONSTANT_ENTRY);
    let block = op(
        0xD8,
        Payload::BlockValue {
            items: vec![op(
                0xD6,
                Payload::ValDef {
                    id: 10,
                    tpe: None,
                    rhs: Box::new(get_r4_pair()),
                },
            )],
            result: Box::new(use_first_field_ge_zero(op(
                0x72,
                Payload::ValUse { id: 10 },
            ))),
        },
    );
    let res = reduce_with_self(&block, &self_box);
    assert_eq!(
        res.ok(),
        Some(SigmaBoolean::TrivialProp(true)),
        "a Constant-encoded (0x58) pair register must still be ACCEPTED \
         (432358 >= 0 -> TrivialProp(true)) — guards against over-rejection",
    );
}

/// Vector 2 (direct path): `SELF.R4[(Int,Int)].get._1 >= 0` on the
/// Constant-encoded register also accepts.
#[test]
fn pair_constant_register_select_field_accepts() {
    let self_box = self_box_with_r4(PAIR_CONSTANT_ENTRY);
    let expr = use_first_field_ge_zero(get_r4_pair());
    let res = reduce_with_self(&expr, &self_box);
    assert_eq!(
        res.ok(),
        Some(SigmaBoolean::TrivialProp(true)),
        "Constant-encoded pair register field access must accept, got a rejection",
    );
}

/// The two encodings are byte-distinct at their leading provenance byte
/// (`0x86` CreateTuple vs `0x58` Constant) but decode to the identical logical
/// register value — the whole point of the divergence.
#[test]
fn both_encodings_decode_to_same_pair_value() {
    assert_eq!(R8_TUPLE_NODE_ENTRY[0], 0x86, "tuple-node provenance byte");
    assert_eq!(PAIR_CONSTANT_ENTRY[0], 0x58, "constant provenance byte");
    let a = read_registers(&mut VlqReader::new(&register_block(R8_TUPLE_NODE_ENTRY))).unwrap();
    let b = read_registers(&mut VlqReader::new(&register_block(PAIR_CONSTANT_ENTRY))).unwrap();
    assert_eq!(a.get(RegisterId::R4), b.get(RegisterId::R4));
}

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::opcode::{parse_expr, write_expr, Expr, IrNode, Payload};
use crate::sigma_type::SigmaType;
use crate::sigma_value::{read_constant, write_constant, CollValue, SigmaValue};

/// Non-mandatory register identifier (R4 through R9). The discriminant
/// is the slot index inside [`AdditionalRegisters`] — `R4 == 0`,
/// `R9 == 5`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegisterId {
    /// First non-mandatory register.
    R4 = 0,
    /// Second non-mandatory register.
    R5 = 1,
    /// Third non-mandatory register.
    R6 = 2,
    /// Fourth non-mandatory register.
    R7 = 3,
    /// Fifth non-mandatory register.
    R8 = 4,
    /// Sixth (last) non-mandatory register.
    R9 = 5,
}

/// A single typed register entry — the sigma type descriptor and the
/// matching evaluated value.
#[derive(Debug, Clone, PartialEq)]
pub struct RegisterValue {
    /// Sigma type of the register payload.
    pub tpe: SigmaType,
    /// Evaluated sigma value matching `tpe`.
    pub value: SigmaValue,
}

/// Non-mandatory register block R4-R9.
///
/// Registers are densely packed from R4 upward: if R6 is present, R4 and
/// R5 must also be present. `registers[0]` is R4, `registers[1]` is R5,
/// and so on through `registers[5]` for R9.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AdditionalRegisters {
    /// Densely packed register entries, R4 first.
    pub registers: Vec<RegisterValue>,
}

impl AdditionalRegisters {
    /// Empty register block. Equivalent to `Default::default()`.
    pub fn empty() -> Self {
        Self {
            registers: Vec::new(),
        }
    }

    /// Number of populated registers (0..=6).
    pub fn count(&self) -> usize {
        self.registers.len()
    }

    /// Look up a register by id. Returns `None` if the slot is past the
    /// end of the densely packed block.
    pub fn get(&self, id: RegisterId) -> Option<&RegisterValue> {
        self.registers.get(id as usize)
    }
}

/// Serialize additional registers. The count byte is a raw UByte (not VLQ).
///
/// Tuple-typed values are written as `CreateTuple` expressions (opcode 0x86)
/// matching the Scala node's `ValueSerializer` encoding. All other values
/// are written as plain Constants (type code + value data).
pub fn write_registers(w: &mut VlqWriter, regs: &AdditionalRegisters) -> Result<(), WriteError> {
    // Mirrors the read-side strict cap: AdditionalRegisters holds at
    // most R4..R9 (6 entries); the read path rejects any count > 6.
    // A programmer constructing an out-of-spec block would otherwise
    // silently produce bytes the reader rejects.
    if regs.registers.len() > 6 {
        return Err(WriteError::InvalidData(format!(
            "AdditionalRegisters has {} entries; max is 6 (R4-R9)",
            regs.registers.len()
        )));
    }
    w.put_u8(regs.registers.len() as u8);
    for reg in &regs.registers {
        write_register_value(w, &reg.tpe, &reg.value)?;
    }
    Ok(())
}

fn write_register_value(
    w: &mut VlqWriter,
    tpe: &SigmaType,
    val: &SigmaValue,
) -> Result<(), WriteError> {
    if matches!(
        (tpe, val),
        (SigmaType::STuple(_), SigmaValue::Coll(CollValue::Values(_)))
            | (SigmaType::SGroupElement, SigmaValue::GroupGenerator)
            | (_, SigmaValue::ConcreteCollection { .. })
    ) {
        // Node-form register values: `ValueSerializer` writes a tuple as a
        // `CreateTuple` expression (each element itself a serialized
        // expression, typically a Const) and `GroupGenerator` as its bare
        // opcode. Both must round-trip in that form — the box id is a hash
        // of these bytes.
        let expr = register_value_to_expr(tpe, val)?;
        write_expr(w, &expr, false)
    } else {
        write_constant(w, tpe, val)
    }
}

/// Deserialize additional registers. The count byte is a raw UByte (not VLQ).
///
/// Register values are serialized as expressions (via ValueSerializer in Scala),
/// not just plain Constants. A leading byte <= 0x70 indicates a plain Constant
/// (type code + value). A leading byte > 0x70 is an opcode — commonly 0x86
/// (CreateTuple) for tuple register values or 0x83 (ConcreteCollection) for
/// inline collections.
pub fn read_registers(r: &mut VlqReader) -> Result<AdditionalRegisters, ReadError> {
    let count = r.get_u8()? as usize;
    if count > 6 {
        return Err(ReadError::InvalidData(format!(
            "register count {count} exceeds maximum 6 (R4-R9)"
        )));
    }
    let mut registers = Vec::with_capacity(count);
    for _ in 0..count {
        let (tpe, value) = read_register_value(r)?;
        // Scala `CheckV6Type` (rule 1019, ValidationRules.scala:165-186): a
        // register value's type must not contain a v6.0-only type — SOption,
        // SHeader, or SUnsignedBigInt — at ANY nesting depth (recursing
        // STuple/SColl). Version-INDEPENDENT (the JVM rejects at all ErgoTree
        // versions; the check is unconditional, not gated on isV6).
        if type_has_v6_only_type(&tpe) {
            return Err(ReadError::InvalidData(format!(
                "register type {tpe:?} contains a v6 type (Option / Header / \
                 UnsignedBigInt) — rule 1019 CheckV6Type"
            )));
        }
        registers.push(RegisterValue { tpe, value });
    }
    Ok(AdditionalRegisters { registers })
}

/// Scala `CheckV6Type.step` + `v6TypeCheck`
/// (`ValidationRules.scala:172-186`, rule 1019): `true` when `tpe` IS — or
/// (recursing `STuple` items / `SColl` element) CONTAINS — a v6.0-only type
/// that may not appear in a register **or** context-extension var value:
/// `SOption`, `SHeader`, or `SUnsignedBigInt`. The recursion mirrors Scala's
/// `step`: `STuple => items.foreach(step)`, `SCollection => step(elemType)`,
/// every other leaf type => `v6TypeCheck` (reject on `isOption` /
/// `SHeader.typeCode` / `SUnsignedBigInt.typeCode`). Shared by both the
/// register reader (here) and `crate::input::read_context_extension` — the
/// single Scala rule covers both surfaces (see `ContextExtension.parse`,
/// which calls `CheckV6Type(v)` on every entry at parse).
pub(crate) fn type_has_v6_only_type(tpe: &SigmaType) -> bool {
    match tpe {
        SigmaType::SOption(_) | SigmaType::SHeader | SigmaType::SUnsignedBigInt => true,
        SigmaType::STuple(items) => items.iter().any(type_has_v6_only_type),
        SigmaType::SColl(elem) => type_has_v6_only_type(elem),
        _ => false,
    }
}

/// Read a single register value. Handles both plain Constants (type <= 0x70)
/// and expression opcodes (> 0x70) like CreateTuple.
fn read_register_value(r: &mut VlqReader) -> Result<(SigmaType, SigmaValue), ReadError> {
    let first = r.peek_u8()?;
    if first <= 0x70 {
        // Plain constant: type code + value data
        read_constant(r)
    } else {
        // Expression opcode — parse the full expression and extract type + value.
        // Register bytes carry no tree header, so pass `tree_version=0`.
        // The version does not affect method-call parsing: explicit
        // type-args reads are keyed on `(type_id, method_id)` alone, so
        // a v6 MethodCall here consumes its full wire shape without
        // desyncing the stream. `expr_to_register_value` below then
        // accepts only evaluated forms (Const, CreateTuple,
        // ConcreteCollection), so a method-call register value is a
        // typed error, not a mis-parse.
        let expr = parse_expr(r, 0, 0)?;
        expr_to_register_value(&expr)
    }
}

/// Walk verbatim register bytes (count byte + concatenated entries) and
/// return one byte slice per register, in R4..R9 order.
///
/// This is byte-exact: each returned slice is a sub-slice of the input,
/// preserving the original wire encoding of each entry (Const or
/// expression form). Useful for emitting parity-correct hex per register
/// without re-serializing through the structured encoders.
pub fn split_register_bytes(register_bytes: &[u8]) -> Result<Vec<Vec<u8>>, ReadError> {
    let mut r = VlqReader::new(register_bytes);
    let count = r.get_u8()? as usize;
    if count > 6 {
        return Err(ReadError::InvalidData(format!(
            "register count {count} exceeds maximum 6 (R4-R9)"
        )));
    }
    let mut slices = Vec::with_capacity(count);
    for _ in 0..count {
        let start = r.position();
        let _ = read_register_value(&mut r)?;
        let end = r.position();
        slices.push(r.data_slice(start, end).to_vec());
    }
    Ok(slices)
}

/// Extract (SigmaType, SigmaValue) from a parsed expression.
///
/// Registers store evaluated values, so only a limited set of expression forms
/// are valid: Constants, Tuples (CreateTuple), and ConcreteCollections.
fn expr_to_register_value(expr: &Expr) -> Result<(SigmaType, SigmaValue), ReadError> {
    match expr {
        Expr::Const { tpe, val } => Ok((tpe.clone(), val.clone())),
        // `Tuple` (0x86 CreateTuple). Type = STuple of the item types
        // (`Tuple.tpe`, `sigma/ast/values.scala:783`); value = the items'
        // values as a `Coll` (`Tuple.value`, `:786-791`) — deliberately NOT
        // `SigmaValue::Tuple`, which is reserved for a tuple CONSTANT.
        //
        // The distinction is load-bearing twice over. On the wire, Scala keeps
        // the parsed node, so a `Constant[STuple]` register re-serializes as a
        // constant (`3c 0e 0e ...`) and a `CreateTuple` register as `86 ...`;
        // collapsing them would give a live mainnet box (block 836113,
        // tx[18].R9) the wrong id. At evaluation, `Tuple.value` really is a
        // `Coll`, so a tuple-typed consumer of the node form throws
        // `Value.checkType` — see `sigma_to_value`'s `(STuple, Coll)` arm.
        Expr::Op(IrNode {
            opcode: 0x86,
            payload: Payload::Tuple { items },
        }) => {
            let mut types = Vec::with_capacity(items.len());
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                let (t, v) = expr_to_register_value(item)?;
                types.push(t);
                values.push(v);
            }
            Ok((
                SigmaType::STuple(types),
                SigmaValue::Coll(CollValue::Values(values)),
            ))
        }
        Expr::Op(IrNode {
            opcode: 0x83,
            payload: Payload::ConcreteCollection { elem_type, items },
        }) => {
            // ConcreteCollection: an EvaluatedCollection whose value is the
            // collection of item values. Kept as the NODE (not a plain
            // `SigmaValue::Coll`) so the `0x83` wire form re-serializes
            // unchanged — the box id hashes these bytes.
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                let (_, v) = expr_to_register_value(item)?;
                values.push(v);
            }
            Ok((
                SigmaType::SColl(Box::new(elem_type.clone())),
                SigmaValue::ConcreteCollection {
                    elem_type: Box::new(elem_type.clone()),
                    items: values,
                },
            ))
        }
        // Packed all-boolean ConcreteCollection (`0x85`). Scala's
        // `ConcreteCollection.apply` routes a collection of boolean constants
        // to `ConcreteCollectionBooleanConstant` unconditionally
        // (`sigma/ast/values.scala:845`), so this is the only wire form such a
        // node ever takes.
        Expr::Op(IrNode {
            opcode: 0x85,
            payload: Payload::BoolCollection { bits },
        }) => Ok((
            SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            SigmaValue::ConcreteCollection {
                elem_type: Box::new(SigmaType::SBoolean),
                items: bits.iter().map(|b| SigmaValue::Boolean(*b)).collect(),
            },
        )),
        // `TrueLeaf` / `FalseLeaf` (`0x7F` / `0x80`). Both are
        // `ConstantNode[SBoolean]` (`values.scala:742`, `:753`) registered
        // with `CaseObjectSerialization`, so `ValueSerializer.deserialize`
        // accepts the bare opcode while `serialize` routes them back through
        // `ConstantSerializer` and emits the canonical `0101` / `0100`
        // constant form. We canonicalize identically — verified against the
        // JVM, which re-serializes a `7f`-encoded register as `0101`.
        Expr::Op(IrNode {
            opcode: 0x7F,
            payload: Payload::Zero,
        }) => Ok((SigmaType::SBoolean, SigmaValue::Boolean(true))),
        Expr::Op(IrNode {
            opcode: 0x80,
            payload: Payload::Zero,
        }) => Ok((SigmaType::SBoolean, SigmaValue::Boolean(false))),
        // `GroupGenerator` (0x82) — a `case object` extending
        // `EvaluatedValue[SGroupElement.type]` (`sigma/ast/values.scala:709`),
        // so `ErgoBoxCandidate.serializer`'s `r.getValue()` accepts it and
        // stores the node. Kept as `SigmaValue::GroupGenerator` rather than a
        // group-element constant so the one-byte wire form survives
        // re-serialization — the box id is `blake2b256` of the structurally
        // re-encoded box bytes, so collapsing it to the 34-byte constant form
        // would compute a different id for a box Scala accepts.
        Expr::Op(IrNode {
            opcode: 0x82,
            payload: Payload::Zero,
        }) => Ok((SigmaType::SGroupElement, SigmaValue::GroupGenerator)),
        Expr::Op(node) => Err(ReadError::InvalidData(format!(
            "unsupported expression opcode 0x{:02X} in register value",
            node.opcode
        ))),
        // A register value is parsed via `parse_expr`, which never yields an
        // unparsed whole-tree body.
        Expr::Unparsed(_) => Err(ReadError::InvalidData(
            "unexpected unparsed-tree body as a register value".into(),
        )),
    }
}

/// Convert a typed register value back to an expression for serialization.
fn register_value_to_expr(tpe: &SigmaType, val: &SigmaValue) -> Result<Expr, WriteError> {
    match (tpe, val) {
        // `GroupGenerator` goes back out as its bare opcode, never as a
        // group-element constant — see `expr_to_register_value`.
        (SigmaType::SGroupElement, SigmaValue::GroupGenerator) => Ok(Expr::Op(IrNode {
            opcode: 0x82,
            payload: Payload::Zero,
        })),
        // A `ConcreteCollection` node goes back out in node form: the packed
        // `0x85` shape when the element type is Boolean (Scala's only encoding
        // for that case), otherwise `0x83` with each item as an expression.
        (_, SigmaValue::ConcreteCollection { elem_type, items }) => {
            if matches!(elem_type.as_ref(), SigmaType::SBoolean) {
                let bits = items
                    .iter()
                    .map(|v| match v {
                        SigmaValue::Boolean(b) => Ok(*b),
                        other => Err(WriteError::InvalidData(format!(
                            "non-Boolean item {other:?} in a Boolean ConcreteCollection node"
                        ))),
                    })
                    .collect::<Result<Vec<bool>, _>>()?;
                return Ok(Expr::Op(IrNode {
                    opcode: 0x85,
                    payload: Payload::BoolCollection { bits },
                }));
            }
            let elems: Vec<Expr> = items
                .iter()
                .map(|v| register_value_to_expr(elem_type, v))
                .collect::<Result<_, _>>()?;
            Ok(Expr::Op(IrNode {
                opcode: 0x83,
                payload: Payload::ConcreteCollection {
                    elem_type: elem_type.as_ref().clone(),
                    items: elems,
                },
            }))
        }
        (SigmaType::STuple(types), SigmaValue::Coll(CollValue::Values(values))) => {
            if types.len() != values.len() {
                return Err(WriteError::InvalidData(
                    "tuple type/value length mismatch".into(),
                ));
            }
            let items: Vec<Expr> = types
                .iter()
                .zip(values.iter())
                .map(|(t, v)| register_value_to_expr(t, v))
                .collect::<Result<_, _>>()?;
            Ok(Expr::Op(IrNode {
                opcode: 0x86,
                payload: Payload::Tuple { items },
            }))
        }
        _ => Ok(Expr::Const {
            tpe: tpe.clone(),
            val: val.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;

    // ----- helpers -----

    fn roundtrip(regs: &AdditionalRegisters) -> AdditionalRegisters {
        let mut w = VlqWriter::new();
        write_registers(&mut w, regs).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_registers(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after decoding");
        decoded
    }

    // ----- happy path -----

    #[test]
    fn get_by_register_id() {
        let regs = AdditionalRegisters {
            registers: vec![
                RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(10),
                },
                RegisterValue {
                    tpe: SigmaType::SLong,
                    value: SigmaValue::Long(20),
                },
            ],
        };
        assert!(regs.get(RegisterId::R4).is_some());
        assert!(regs.get(RegisterId::R5).is_some());
        assert!(regs.get(RegisterId::R6).is_none());
        assert_eq!(regs.get(RegisterId::R4).unwrap().value, SigmaValue::Int(10));
        assert_eq!(
            regs.get(RegisterId::R5).unwrap().value,
            SigmaValue::Long(20)
        );
    }

    // ----- round-trips -----

    #[test]
    fn empty_registers_roundtrip() {
        let regs = AdditionalRegisters::empty();
        let decoded = roundtrip(&regs);
        assert_eq!(decoded, regs);
        assert_eq!(decoded.count(), 0);
    }

    #[test]
    fn single_register_r4_int() {
        let regs = AdditionalRegisters {
            registers: vec![RegisterValue {
                tpe: SigmaType::SInt,
                value: SigmaValue::Int(42),
            }],
        };
        let decoded = roundtrip(&regs);
        assert_eq!(decoded, regs);
        assert_eq!(decoded.count(), 1);
    }

    #[test]
    fn two_registers_r4_r5_different_types() {
        let regs = AdditionalRegisters {
            registers: vec![
                RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(-100),
                },
                RegisterValue {
                    tpe: SigmaType::SLong,
                    value: SigmaValue::Long(999_999_999_999i64),
                },
            ],
        };
        let decoded = roundtrip(&regs);
        assert_eq!(decoded, regs);
    }

    #[test]
    fn full_registers_r4_through_r9() {
        let regs = AdditionalRegisters {
            registers: vec![
                RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(1),
                },
                RegisterValue {
                    tpe: SigmaType::SLong,
                    value: SigmaValue::Long(2),
                },
                RegisterValue {
                    tpe: SigmaType::SBoolean,
                    value: SigmaValue::Boolean(true),
                },
                RegisterValue {
                    tpe: SigmaType::SByte,
                    value: SigmaValue::Byte(3),
                },
                RegisterValue {
                    tpe: SigmaType::SShort,
                    value: SigmaValue::Short(4),
                },
                RegisterValue {
                    tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                    value: SigmaValue::Coll(crate::sigma_value::CollValue::Bytes(vec![0xDE, 0xAD])),
                },
            ],
        };
        let decoded = roundtrip(&regs);
        assert_eq!(decoded, regs);
        assert_eq!(decoded.count(), 6);
    }

    #[test]
    fn count_byte_is_raw_ubyte_not_vlq() {
        // Write 3 registers and verify the first byte is exactly 0x03 (not VLQ-expanded).
        // For values 0-127, VLQ and raw UByte produce the same single byte, but
        // we verify the structural contract: count is always one raw byte.
        let regs = AdditionalRegisters {
            registers: vec![
                RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(1),
                },
                RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(2),
                },
                RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(3),
                },
            ],
        };
        let mut w = VlqWriter::new();
        write_registers(&mut w, &regs).unwrap();
        let data = w.result();
        // First byte is the count: must be exactly 0x03 (raw byte, not VLQ).
        assert_eq!(data[0], 0x03, "count byte must be a raw UByte");
    }

    #[test]
    fn tuple_register_roundtrip() {
        let regs = AdditionalRegisters {
            registers: vec![RegisterValue {
                tpe: SigmaType::STuple(vec![SigmaType::SByte, SigmaType::SByte]),
                value: SigmaValue::Tuple(vec![SigmaValue::Byte(102), SigmaValue::Byte(99)]),
            }],
        };
        let decoded = roundtrip(&regs);
        assert_eq!(decoded, regs);
    }

    #[test]
    fn mixed_constant_and_tuple_registers() {
        // Mimics the register layout from block 855650 TX1 output 0:
        // R4: SSigmaProp (constant), R5: SLong (constant),
        // R6: SBoolean (constant), R7: SLong (constant),
        // R8: (SByte, SByte) tuple (expression)
        let regs = AdditionalRegisters {
            registers: vec![
                RegisterValue {
                    tpe: SigmaType::SLong,
                    value: SigmaValue::Long(4545454),
                },
                RegisterValue {
                    tpe: SigmaType::SBoolean,
                    value: SigmaValue::Boolean(true),
                },
                RegisterValue {
                    tpe: SigmaType::SLong,
                    value: SigmaValue::Long(50),
                },
                RegisterValue {
                    tpe: SigmaType::STuple(vec![SigmaType::SByte, SigmaType::SByte]),
                    value: SigmaValue::Tuple(vec![SigmaValue::Byte(102), SigmaValue::Byte(99)]),
                },
            ],
        };
        let decoded = roundtrip(&regs);
        assert_eq!(decoded, regs);
    }

    // ----- error paths -----

    #[test]
    fn error_count_exceeds_six() {
        // Craft bytes where count = 7.
        let data = [0x07u8, 0x04, 0x02]; // count=7, then garbage
        let mut r = VlqReader::new(&data);
        let err = read_registers(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::InvalidData(_)),
            "expected InvalidData for count > 6, got: {err:?}"
        );
    }

    #[test]
    fn write_registers_above_six_returns_invalid_data() {
        // Programmer constructs an out-of-spec block with 7 registers.
        // Cap is R4..R9 (6); the writer surfaces this as `WriteError`
        // so downstream call sites (REST encoders, mempool synthetic
        // boxes) can handle it without bringing down the process.
        let regs = AdditionalRegisters {
            registers: (0..7)
                .map(|i| RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(i),
                })
                .collect(),
        };
        let mut w = VlqWriter::new();
        let err = write_registers(&mut w, &regs).unwrap_err();
        let WriteError::InvalidData(msg) = &err;
        assert!(
            msg.contains('7'),
            "message should name the count, got: {msg}"
        );
        assert!(
            msg.contains("max"),
            "message should name the cap, got: {msg}"
        );
    }

    // ----- rule 1019 CheckV6Type on register types -----

    #[test]
    fn v6_type_check_recurses_tuple_and_coll() {
        use SigmaType::*;
        // Direct v6 types.
        assert!(type_has_v6_only_type(&SOption(Box::new(SInt))));
        assert!(type_has_v6_only_type(&SHeader));
        assert!(type_has_v6_only_type(&SUnsignedBigInt));
        // Nested inside Tuple / Coll (any depth).
        assert!(type_has_v6_only_type(&STuple(vec![
            SInt,
            SOption(Box::new(SByte))
        ])));
        assert!(type_has_v6_only_type(&SColl(Box::new(SUnsignedBigInt))));
        assert!(type_has_v6_only_type(&SColl(Box::new(STuple(vec![
            SByte, SHeader
        ])))));
        // Non-v6 types pass.
        assert!(!type_has_v6_only_type(&SInt));
        assert!(!type_has_v6_only_type(&STuple(vec![SInt, SByte])));
        assert!(!type_has_v6_only_type(&SColl(Box::new(SByte))));
    }

    #[test]
    fn read_rejects_register_with_option_type() {
        // SANTA: Rule1019_check_v6_type (box R4 = Option[Int] -> errored).
        let regs = AdditionalRegisters {
            registers: vec![RegisterValue {
                tpe: SigmaType::SOption(Box::new(SigmaType::SInt)),
                value: SigmaValue::Opt(Some(Box::new(SigmaValue::Int(5)))),
            }],
        };
        let mut w = VlqWriter::new();
        write_registers(&mut w, &regs).expect("write option register");
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = read_registers(&mut r).expect_err("Option register must be rejected (rule 1019)");
        assert!(
            matches!(&err, ReadError::InvalidData(m) if m.contains("1019")),
            "expected rule-1019 error, got {err:?}",
        );
    }

    #[test]
    fn read_accepts_plain_int_register() {
        let regs = AdditionalRegisters {
            registers: vec![RegisterValue {
                tpe: SigmaType::SInt,
                value: SigmaValue::Int(42),
            }],
        };
        let mut w = VlqWriter::new();
        write_registers(&mut w, &regs).unwrap();
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        assert!(read_registers(&mut r).is_ok());
    }

    // ----- oracle parity -----

    /// Every `EvaluatedValue` form Scala accepts as a box-register value, with
    /// the JVM's canonical re-serialization and the resulting box id.
    ///
    /// A box id is `blake2b256` of the STRUCTURALLY re-serialized box bytes,
    /// so an encoder that canonicalizes a node into its `Constant` form
    /// computes a different id than the reference for a box the reference
    /// accepts — a silent state-root divergence. `0x82` / `0x83` / `0x85` are
    /// therefore preserved; `0x7f` / `0x80` are canonicalized to `0101` /
    /// `0100` because the JVM itself does that (`ValueSerializer.serialize`
    /// routes `TrueLeaf`/`FalseLeaf` through `ConstantSerializer`).
    ///
    /// Vector: `test-vectors/scala/evaluated_value_forms.json`.
    #[test]
    fn register_evaluated_value_forms_match_scala_bytes_and_box_ids() {
        use ergo_primitives::digest::blake2b256;

        // Box: 1000000 nanoERG, script sigmaProp(true), height 0, one register.
        const PREFIX: &str = "c0843d10010101d17300000001";
        // ...as output index 3 of transaction 0x0707..07.
        const SUFFIX: &str = "070707070707070707070707070707070707070707070707070707070707070703";

        // (register bytes in, Scala's re-serialized register bytes, Scala box id)
        let cases = [
            (
                "82",
                "82",
                "05b02f98770d6178bb39f4ceecaa78bbcaacf2c8b8752f9d0d13b418604305a8",
            ),
            (
                "850201",
                "850201",
                "37213bebf038b01db735fad8acea2a0f52b9115723509fd482bed7d2ac5297b2",
            ),
            (
                "830204040e0410",
                "830204040e0410",
                "6d346c1bbf6e1a4b004e560cb6a30a2fe7e7d9e4579f416c4d13c8f4dc3ec495",
            ),
            (
                "7f",
                "0101",
                "2c62fee9cba04f4dda73909663097d395eb9a7d6e3eb56d7791720be148cdd40",
            ),
            (
                "80",
                "0100",
                "26e30bfb4f9b978596322e53b23e89807878751ddf9308359b2504fefc92f74d",
            ),
            // CreateTuple (0x86) — preserved; the mainnet-855650 vector below
            // pins the same form against a real on-chain register.
            ("860204020404", "860204020404", ""),
        ];

        for (input, expected_reg, expected_box_id) in cases {
            let candidate_hex = format!("{PREFIX}{input}");
            let bytes = hex::decode(&candidate_hex).unwrap();
            let mut r = VlqReader::new(&bytes);
            let candidate = crate::ergo_box::read_ergo_box_candidate(&mut r)
                .unwrap_or_else(|e| panic!("Scala accepts register {input}, got {e:?}"));
            assert!(r.is_empty(), "{input}: trailing bytes");

            let mut w = VlqWriter::new();
            crate::ergo_box::write_ergo_box_candidate(&mut w, &candidate).unwrap();
            assert_eq!(
                hex::encode(w.result()),
                format!("{PREFIX}{expected_reg}"),
                "{input} must re-serialize as the JVM does",
            );

            if expected_box_id.is_empty() {
                continue;
            }
            let box_bytes = hex::decode(format!("{PREFIX}{expected_reg}{SUFFIX}")).unwrap();
            assert_eq!(
                hex::encode(blake2b256(&box_bytes).as_bytes()),
                expected_box_id,
                "{input}: box id must match the JVM",
            );
        }
    }

    /// `GroupElement` register values normalize the way the JVM does, and the
    /// box id is computed over the normalized bytes.
    ///
    /// `GroupElementSerializer.parse` (`GroupElementSerializer.scala:35-42`)
    /// maps ANY 33-byte encoding whose lead byte is `0x00` to the infinity
    /// point, whatever the other 32 bytes hold, and `serialize` (`:20-33`)
    /// writes infinity as 33 zeroes. `ErgoBox.id` is `Blake2b256` of the
    /// RE-SERIALIZED box (`ErgoBox.scala:87-92`), so `07 00 aa*32` and
    /// `07 00*33` are one box with one id. Preserving the trailing garbage
    /// gave such a box a different id than the reference -- a UTXO-set /
    /// AVL-root divergence on a box the reference accepts. A compressed
    /// point (`0x02`/`0x03` lead) re-encodes to itself. The same normalization
    /// applies to the point inside a `ProveDlog` `SigmaProp` constant.
    ///
    /// Vector: `test-vectors/scala/canonical_extension_and_group_element.json`.
    #[test]
    fn register_group_element_encodings_normalize_to_scala_bytes_and_box_ids() {
        use ergo_primitives::digest::blake2b256;
        const PREFIX: &str = "c0843d10010101d17300000001";
        const SUFFIX: &str = "070707070707070707070707070707070707070707070707070707070707070703";
        const ZERO33: &str = "000000000000000000000000000000000000000000000000000000000000000000";
        const GARBAGE: &str = "00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const GENERATOR: &str =
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        // (label, wire point, Scala re-serialized point, Scala box id)
        let cases = [
            (
                "identity_all_zero",
                ZERO33,
                ZERO33,
                "f97a4bddd81927722ead4b4c83fac917905440d69cd2a997fb64e892013ca7f8",
            ),
            (
                "identity_zero_lead_garbage",
                GARBAGE,
                ZERO33,
                "f97a4bddd81927722ead4b4c83fac917905440d69cd2a997fb64e892013ca7f8",
            ),
            (
                "generator",
                GENERATOR,
                GENERATOR,
                "b13d2f0732d91f7d8a1cf5dd38cfb10d1fa48ac537dbc747f0224331f510457c",
            ),
        ];
        for (label, wire_point, canonical_point, expected_box_id) in cases {
            // R4 = GroupElement constant (`07` + point).
            let candidate_hex = format!("{PREFIX}07{wire_point}");
            let bytes = hex::decode(&candidate_hex).unwrap();
            let mut r = VlqReader::new(&bytes);
            let candidate = crate::ergo_box::read_ergo_box_candidate(&mut r)
                .unwrap_or_else(|e| panic!("{label}: Scala accepts this register, got {e:?}"));
            assert!(r.is_empty(), "{label}: trailing bytes");
            let mut w = VlqWriter::new();
            crate::ergo_box::write_ergo_box_candidate(&mut w, &candidate).unwrap();
            let canonical_candidate = format!("{PREFIX}07{canonical_point}");
            assert_eq!(
                hex::encode(w.result()),
                canonical_candidate,
                "{label}: the register must re-serialize as GroupElementSerializer does",
            );
            let box_bytes = hex::decode(format!("{canonical_candidate}{SUFFIX}")).unwrap();
            assert_eq!(
                hex::encode(blake2b256(&box_bytes).as_bytes()),
                expected_box_id,
                "{label}: box id must match the JVM",
            );

            // The same point inside a ProveDlog SigmaProp constant (`08cd` + point).
            let dlog_hex = format!("{PREFIX}08cd{wire_point}");
            let bytes = hex::decode(&dlog_hex).unwrap();
            let mut r = VlqReader::new(&bytes);
            let candidate = crate::ergo_box::read_ergo_box_candidate(&mut r).unwrap_or_else(|e| {
                panic!("{label}: Scala accepts this ProveDlog register, got {e:?}")
            });
            let mut w = VlqWriter::new();
            crate::ergo_box::write_ergo_box_candidate(&mut w, &candidate).unwrap();
            assert_eq!(
                hex::encode(w.result()),
                format!("{PREFIX}08cd{canonical_point}"),
                "{label}: the ProveDlog point must normalize identically",
            );
        }
    }

    /// The decoded values behind the register node forms.
    #[test]
    fn register_evaluated_value_forms_decode_to_scala_values() {
        let decode = |reg_hex: &str| {
            let bytes = hex::decode(format!("01{reg_hex}")).unwrap();
            let mut r = VlqReader::new(&bytes);
            read_registers(&mut r).unwrap().registers[0].clone()
        };
        assert_eq!(
            decode("82"),
            RegisterValue {
                tpe: SigmaType::SGroupElement,
                value: SigmaValue::GroupGenerator,
            }
        );
        assert_eq!(
            decode("850201"),
            RegisterValue {
                tpe: SigmaType::SColl(Box::new(SigmaType::SBoolean)),
                value: SigmaValue::ConcreteCollection {
                    elem_type: Box::new(SigmaType::SBoolean),
                    items: vec![SigmaValue::Boolean(true), SigmaValue::Boolean(false)],
                },
            }
        );
        assert_eq!(
            decode("7f"),
            RegisterValue {
                tpe: SigmaType::SBoolean,
                value: SigmaValue::Boolean(true),
            }
        );
    }

    #[test]
    fn tuple_register_from_block_855650() {
        // R8 from block 855650, TX b5fd96c9..., output 0.
        // Serialized as CreateTuple (opcode 0x86) expression, NOT a plain Constant.
        // Scala: ValueSerializer writes tuples as CreateTuple opcode + count + items.
        // Bytes: 86 02 02 66 02 63
        //   0x86 = CreateTuple opcode
        //   0x02 = VLQ count (2 items)
        //   0x02 0x66 = Const(SByte, 102)  [type=SByte(2), value=0x66=102]
        //   0x02 0x63 = Const(SByte, 99)   [type=SByte(2), value=0x63=99]
        let raw = [
            0x01u8, // register count = 1
            0x86, 0x02, 0x02, 0x66, 0x02, 0x63,
        ];
        let mut r = VlqReader::new(&raw);
        let decoded = read_registers(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert_eq!(decoded.count(), 1);
        let reg = &decoded.registers[0];
        assert_eq!(
            reg.tpe,
            SigmaType::STuple(vec![SigmaType::SByte, SigmaType::SByte])
        );
        // A `CreateTuple` NODE decodes to Scala's `Tuple.value` -- a `Coll` of
        // the item values, not a `Tuple2` -- which is what distinguishes it
        // from a tuple `Constant` on the wire and at evaluation.
        assert_eq!(
            reg.value,
            SigmaValue::Coll(CollValue::Values(vec![
                SigmaValue::Byte(102),
                SigmaValue::Byte(99)
            ]))
        );
        // ...and it re-serializes as `0x86`, byte-for-byte.
        let mut w = VlqWriter::new();
        write_registers(&mut w, &decoded).unwrap();
        assert_eq!(w.result(), raw.to_vec());
    }

    /// The counterpart: a tuple CONSTANT register (Scala
    /// `Constant[STuple]`, wire form `3c 0e 0e ...`) decodes to a real
    /// `SigmaValue::Tuple` and re-serializes as a constant -- NOT as
    /// `CreateTuple`. Block 836113 tx[18].R9 carries this shape on mainnet,
    /// and its box id / transaction id commit to the constant bytes.
    #[test]
    fn constant_tuple_register_round_trips_as_a_constant() {
        let raw = hex::decode("013c0e0e0000").unwrap();
        let mut r = VlqReader::new(&raw);
        let decoded = read_registers(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes");
        assert!(
            matches!(decoded.registers[0].value, SigmaValue::Tuple(_)),
            "a Constant[STuple] must NOT decode to the CreateTuple node shape, got {:?}",
            decoded.registers[0].value
        );
        let mut w = VlqWriter::new();
        write_registers(&mut w, &decoded).unwrap();
        assert_eq!(
            hex::encode(w.result()),
            "013c0e0e0000",
            "a tuple Constant must re-serialize as a Constant"
        );
    }
}

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
    if let (SigmaType::STuple(_), SigmaValue::Tuple(_)) = (tpe, val) {
        // Tuples are serialized as CreateTuple expressions in the register
        // encoding used by the Scala node's ValueSerializer. Each element
        // is itself a serialized expression (typically a Const).
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
        registers.push(RegisterValue { tpe, value });
    }
    Ok(AdditionalRegisters { registers })
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
        Expr::Op(IrNode {
            opcode: 0x86,
            payload: Payload::Tuple { items },
        }) => {
            // CreateTuple: extract type and value from each element
            let mut types = Vec::with_capacity(items.len());
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                let (t, v) = expr_to_register_value(item)?;
                types.push(t);
                values.push(v);
            }
            Ok((SigmaType::STuple(types), SigmaValue::Tuple(values)))
        }
        Expr::Op(IrNode {
            opcode: 0x83,
            payload: Payload::ConcreteCollection { elem_type, items },
        }) => {
            // ConcreteCollection: extract value from each element
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                let (_, v) = expr_to_register_value(item)?;
                values.push(v);
            }
            Ok((
                SigmaType::SColl(Box::new(elem_type.clone())),
                SigmaValue::Coll(CollValue::Values(values)),
            ))
        }
        Expr::Op(node) => Err(ReadError::InvalidData(format!(
            "unsupported expression opcode 0x{:02X} in register value",
            node.opcode
        ))),
    }
}

/// Convert a typed register value back to an expression for serialization.
fn register_value_to_expr(tpe: &SigmaType, val: &SigmaValue) -> Result<Expr, WriteError> {
    match (tpe, val) {
        (SigmaType::STuple(types), SigmaValue::Tuple(values)) => {
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

    // ----- oracle parity -----

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
        assert_eq!(
            reg.value,
            SigmaValue::Tuple(vec![SigmaValue::Byte(102), SigmaValue::Byte(99)])
        );
    }
}

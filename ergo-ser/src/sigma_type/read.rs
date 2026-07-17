//! Deserialization direction of the sigma type-descriptor codec:
//! [`read_type`] / [`decode_type`] and the depth-tracked recursive
//! decoders enforcing `MAX_TYPE_DEPTH`.

use ergo_primitives::reader::{ReadError, VlqReader};

use super::{
    embeddable_gate_version, prim_from_code, SigmaType, FUNC_CODE, MAX_TYPE_DEPTH, PRIM_RANGE,
    SANY_CODE, SAVL_TREE_CODE, SBOX_CODE, SCONTEXT_CODE, SGLOBAL_CODE, SHEADER_CODE,
    SPREHEADER_CODE, SSTRING_CODE, STYPEVAR_CODE, SUNIT_CODE, TUPLE_CODE,
};

/// Deserialize a Sigma type descriptor. Public entry — starts the
/// recursion-depth counter at 0; nested calls go through
/// `read_type_at_depth` which enforces `MAX_TYPE_DEPTH`.
pub fn read_type(r: &mut VlqReader) -> Result<SigmaType, ReadError> {
    read_type_at_depth(r, 0)
}

/// Internal: decoding entry that propagates the recursion-depth
/// counter. All recursive `read_type` calls inside `decode_type` and
/// `decode_constructor` use this so the depth check fires before a
/// malicious payload exhausts the stack.
fn read_type_at_depth(r: &mut VlqReader, depth: usize) -> Result<SigmaType, ReadError> {
    if depth > MAX_TYPE_DEPTH {
        return Err(ReadError::InvalidData(format!(
            "type recursion depth exceeds maximum ({MAX_TYPE_DEPTH})"
        )));
    }
    let byte = r.get_u8()?;
    decode_type_at_depth(r, byte, depth)
}

/// Decode a type descriptor given the first byte already consumed.
/// Public so the opcode parser can decode inline constant types.
/// Starts a fresh depth counter; for nested decodes within an
/// already-recursing parse, use `decode_type_at_depth` (private).
pub fn decode_type(r: &mut VlqReader, byte: u8) -> Result<SigmaType, ReadError> {
    decode_type_at_depth(r, byte, 0)
}

fn decode_type_at_depth(r: &mut VlqReader, byte: u8, depth: usize) -> Result<SigmaType, ReadError> {
    let next = depth + 1;
    match byte {
        // Primitive embeddable types (1..=11), version-gated exactly like Scala's
        // `getEmbeddableType` (embeddableV5 = codes 1..=8 pre-v3; embeddableV6 adds
        // SUnsignedBigInt = code 9 at v3+).
        1..=11 => prim_from_code(byte, embeddable_gate_version(r)),

        // Special non-embeddable
        SANY_CODE => Ok(SigmaType::SAny),
        SUNIT_CODE => Ok(SigmaType::SUnit),
        SBOX_CODE => Ok(SigmaType::SBox),
        SAVL_TREE_CODE => Ok(SigmaType::SAvlTree),
        SCONTEXT_CODE => Ok(SigmaType::SContext),
        SSTRING_CODE => Ok(SigmaType::SString),
        STYPEVAR_CODE => {
            // Scala TypeSerializer.scala:203-204 reads the name length as an
            // unsigned byte (anything 0..=255) and decodes the bytes with
            // `new String(bytes, UTF_8)` — the JVM's LOSSY decoder. A strict
            // `from_utf8` here rejected ill-formed names the Scala node
            // accepts (reject-valid on sizeless trees; a too-broad soft-fork
            // placeholder on size-delimited ones), so we mirror the JVM byte
            // for byte. See [`crate::jvm_utf8`].
            let name_len = r.get_u8()? as usize;
            let name_bytes = r.get_bytes(name_len)?;
            Ok(SigmaType::STypeVar(crate::jvm_utf8::decode(name_bytes)))
        }
        SHEADER_CODE => Ok(SigmaType::SHeader),
        SPREHEADER_CODE => Ok(SigmaType::SPreHeader),
        SGLOBAL_CODE => Ok(SigmaType::SGlobal),

        // ConstrId-based ranges (12..=95)
        b @ 12..=95 => decode_constructor_at_depth(r, b, depth),

        // General tuple (5+ elements). Scala TypeSerializer.scala:189
        // reads count as a single unsigned byte (max 255).
        TUPLE_CODE => {
            let count = r.get_u8()? as usize;
            if count < 2 {
                return Err(ReadError::InvalidData(format!(
                    "tuple must have at least 2 elements, got {count}"
                )));
            }
            let mut elems = Vec::with_capacity(count);
            for _ in 0..count {
                elems.push(read_type_at_depth(r, next)?);
            }
            Ok(SigmaType::STuple(elems))
        }

        // SFunc: 0x70 + 1-byte domain count + domain types + range type
        // + 1-byte tpeParams count + STypeVar idents. Scala
        // TypeSerializer.scala:212-224 reads counts as unsigned bytes
        // and requires each tpeParam ident to be an STypeVar
        // (`require(ident.isInstanceOf[STypeVar])`).
        FUNC_CODE => {
            let dom_count = r.get_u8()? as usize;
            let mut t_dom = Vec::with_capacity(dom_count);
            for _ in 0..dom_count {
                t_dom.push(read_type_at_depth(r, next)?);
            }
            let t_range = read_type_at_depth(r, next)?;
            let params_count = r.get_u8()? as usize;
            let mut tpe_params = Vec::with_capacity(params_count);
            for _ in 0..params_count {
                let ident = read_type_at_depth(r, next)?;
                if !matches!(ident, SigmaType::STypeVar(_)) {
                    return Err(ReadError::InvalidData(format!(
                        "SFunc tpeParam must be an STypeVar, got {ident:?}"
                    )));
                }
                tpe_params.push(ident);
            }
            Ok(SigmaType::SFunc {
                t_dom,
                t_range: Box::new(t_range),
                tpe_params,
            })
        }

        _ => Err(ReadError::InvalidData(format!(
            "unknown type code: 0x{byte:02X}"
        ))),
    }
}

fn decode_constructor_at_depth(
    r: &mut VlqReader,
    byte: u8,
    depth: usize,
) -> Result<SigmaType, ReadError> {
    let constr_id = byte / PRIM_RANGE;
    let prim_id = byte % PRIM_RANGE;
    let next = depth + 1;
    let gate_v = embeddable_gate_version(r);

    match constr_id {
        // constrId 1: Coll[T]
        1 => {
            let elem = if prim_id == 0 {
                read_type_at_depth(r, next)?
            } else {
                prim_from_code(prim_id, gate_v)?
            };
            Ok(SigmaType::SColl(Box::new(elem)))
        }

        // constrId 2: Coll[Coll[T]]
        2 => {
            let inner = if prim_id == 0 {
                read_type_at_depth(r, next)?
            } else {
                prim_from_code(prim_id, gate_v)?
            };
            Ok(SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(
                inner,
            )))))
        }

        // constrId 3: Option[T]
        3 => {
            let elem = if prim_id == 0 {
                read_type_at_depth(r, next)?
            } else {
                prim_from_code(prim_id, gate_v)?
            };
            Ok(SigmaType::SOption(Box::new(elem)))
        }

        // constrId 4: Option[Coll[T]]
        4 => {
            let inner = if prim_id == 0 {
                read_type_at_depth(r, next)?
            } else {
                prim_from_code(prim_id, gate_v)?
            };
            Ok(SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(
                inner,
            )))))
        }

        // constrId 5: Pair — first element embeddable, or general pair (primId=0)
        5 => {
            if prim_id == 0 {
                let t1 = read_type_at_depth(r, next)?;
                let t2 = read_type_at_depth(r, next)?;
                Ok(SigmaType::STuple(vec![t1, t2]))
            } else {
                let t1 = prim_from_code(prim_id, gate_v)?;
                let t2 = read_type_at_depth(r, next)?;
                Ok(SigmaType::STuple(vec![t1, t2]))
            }
        }

        // constrId 6: Pair — second element embeddable (primId>0), or Triple (primId=0)
        6 => {
            if prim_id == 0 {
                // Triple: read 3 types
                let t1 = read_type_at_depth(r, next)?;
                let t2 = read_type_at_depth(r, next)?;
                let t3 = read_type_at_depth(r, next)?;
                Ok(SigmaType::STuple(vec![t1, t2, t3]))
            } else {
                let t1 = read_type_at_depth(r, next)?;
                let t2 = prim_from_code(prim_id, gate_v)?;
                Ok(SigmaType::STuple(vec![t1, t2]))
            }
        }

        // constrId 7: Symmetric pair (primId>0) or Quad (primId=0)
        7 => {
            if prim_id == 0 {
                // Quad: read 4 types
                let t1 = read_type_at_depth(r, next)?;
                let t2 = read_type_at_depth(r, next)?;
                let t3 = read_type_at_depth(r, next)?;
                let t4 = read_type_at_depth(r, next)?;
                Ok(SigmaType::STuple(vec![t1, t2, t3, t4]))
            } else {
                let t = prim_from_code(prim_id, gate_v)?;
                Ok(SigmaType::STuple(vec![t.clone(), t]))
            }
        }

        _ => Err(ReadError::InvalidData(format!(
            "unknown type constructor: constrId={constr_id} (byte=0x{byte:02X})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_type::write_type;
    use ergo_primitives::writer::VlqWriter;

    // ----- helpers -----

    fn encode(t: &SigmaType) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_type(&mut w, t).unwrap();
        w.result()
    }

    fn roundtrip(t: &SigmaType) {
        let bytes = encode(t);
        let mut r = VlqReader::new(&bytes);
        let decoded = read_type(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after decoding {t:?}");
        assert_eq!(&decoded, t);
    }

    // ----- round-trips -----

    #[test]
    fn roundtrip_primitives() {
        for t in [
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SShort,
            SigmaType::SInt,
            SigmaType::SLong,
            SigmaType::SBigInt,
            SigmaType::SGroupElement,
            SigmaType::SSigmaProp,
            SigmaType::SBox,
            SigmaType::SAvlTree,
            SigmaType::SContext,
            SigmaType::SHeader,
            SigmaType::SPreHeader,
        ] {
            roundtrip(&t);
        }
    }

    #[test]
    fn roundtrip_coll_embeddable() {
        for inner in [
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SInt,
            SigmaType::SLong,
            SigmaType::SBigInt,
            SigmaType::SGroupElement,
            SigmaType::SSigmaProp,
        ] {
            roundtrip(&SigmaType::SColl(Box::new(inner)));
        }
    }

    #[test]
    fn roundtrip_coll_nested() {
        // Coll[Coll[Byte]] — constrId 2
        roundtrip(&SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(
            SigmaType::SByte,
        )))));
        // Coll[SBox] — constrId 1, primId 0
        roundtrip(&SigmaType::SColl(Box::new(SigmaType::SBox)));
        roundtrip(&SigmaType::SColl(Box::new(SigmaType::SAvlTree)));
    }

    #[test]
    fn roundtrip_option_embeddable() {
        for inner in [
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SInt,
            SigmaType::SLong,
        ] {
            roundtrip(&SigmaType::SOption(Box::new(inner)));
        }
    }

    #[test]
    fn roundtrip_option_nested() {
        // Option[Coll[Int]] — constrId 4
        roundtrip(&SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(
            SigmaType::SInt,
        )))));
        // Option[SBox] — constrId 3, primId 0
        roundtrip(&SigmaType::SOption(Box::new(SigmaType::SBox)));
    }

    #[test]
    fn roundtrip_pair() {
        roundtrip(&SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]));
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaType::SInt,
        ]));
    }

    #[test]
    fn roundtrip_pair_symmetric() {
        roundtrip(&SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SInt]));
        roundtrip(&SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SLong]));
    }

    #[test]
    fn roundtrip_pair_second_embed() {
        roundtrip(&SigmaType::STuple(vec![SigmaType::SBox, SigmaType::SInt]));
    }

    #[test]
    fn roundtrip_nested_pair() {
        // (Int, (Long, Byte))
        let inner = SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SByte]);
        roundtrip(&SigmaType::STuple(vec![SigmaType::SInt, inner]));
    }

    #[test]
    fn roundtrip_triple() {
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SInt,
            SigmaType::SLong,
            SigmaType::SByte,
        ]));
        // Non-embeddable first element
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SBox,
            SigmaType::SInt,
            SigmaType::SLong,
        ]));
    }

    #[test]
    fn roundtrip_quad() {
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SInt,
            SigmaType::SLong,
        ]));
        // Non-embeddable first element
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SAvlTree,
            SigmaType::SInt,
            SigmaType::SLong,
            SigmaType::SByte,
        ]));
    }

    #[test]
    fn roundtrip_general_tuple_5() {
        roundtrip(&SigmaType::STuple(vec![
            SigmaType::SBoolean,
            SigmaType::SByte,
            SigmaType::SShort,
            SigmaType::SInt,
            SigmaType::SLong,
        ]));
    }

    #[test]
    fn roundtrip_func() {
        roundtrip(&SigmaType::SFunc {
            t_dom: vec![SigmaType::SInt],
            t_range: Box::new(SigmaType::SLong),
            tpe_params: vec![],
        });
        roundtrip(&SigmaType::SFunc {
            t_dom: vec![SigmaType::SInt, SigmaType::SLong],
            t_range: Box::new(SigmaType::SBoolean),
            tpe_params: vec![],
        });
        // Non-embeddable domain
        roundtrip(&SigmaType::SFunc {
            t_dom: vec![SigmaType::SBox],
            t_range: Box::new(SigmaType::SInt),
            tpe_params: vec![],
        });
        // Generic function type: tpeParams carried after the range.
        roundtrip(&SigmaType::SFunc {
            t_dom: vec![SigmaType::STypeVar("T".into())],
            t_range: Box::new(SigmaType::STypeVar("T".into())),
            tpe_params: vec![SigmaType::STypeVar("T".into())],
        });
    }

    #[test]
    fn roundtrip_sstring() {
        let t = SigmaType::SString;
        let data = encode(&t);
        let mut r = VlqReader::new(&data);
        assert_eq!(read_type(&mut r).unwrap(), t);
    }

    #[test]
    fn roundtrip_sglobal() {
        let t = SigmaType::SGlobal;
        let data = encode(&t);
        let mut r = VlqReader::new(&data);
        assert_eq!(read_type(&mut r).unwrap(), t);
    }

    #[test]
    fn roundtrip_stypevar() {
        let t = SigmaType::STypeVar("T".into());
        let data = encode(&t);
        let mut r = VlqReader::new(&data);
        assert_eq!(read_type(&mut r).unwrap(), t);
    }

    #[test]
    fn stypevar_name_at_255_byte_max_round_trips_per_scala() {
        // Scala accepts 0..=255 byte names for STypeVar. The previous
        // Rust-only 64-byte cap rejected legitimate Scala-valid
        // descriptors. Pin the round-trip at the actual Scala max so
        // any reintroduction of a tighter cap fails loudly.
        let name = "x".repeat(255);
        let t = SigmaType::STypeVar(name.clone());
        let bytes = encode(&t);
        let mut r = VlqReader::new(&bytes);
        assert_eq!(read_type(&mut r).unwrap(), t);
    }

    // ----- error paths -----

    #[test]
    fn error_unknown_type_code() {
        let data = [0xFE];
        let mut r = VlqReader::new(&data);
        let err = read_type(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::InvalidData(_)),
            "expected InvalidData, got: {err:?}"
        );
    }

    #[test]
    fn error_unexpected_eof() {
        let data = [];
        let mut r = VlqReader::new(&data);
        let err = read_type(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::UnexpectedEnd { .. }),
            "expected UnexpectedEnd, got: {err:?}"
        );
    }

    #[test]
    fn error_truncated_nested_coll() {
        // Coll with non-embeddable element but no element type follows
        let data = [0x0C]; // COLL_CODE with primId 0
        let mut r = VlqReader::new(&data);
        let err = read_type(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::UnexpectedEnd { .. }),
            "expected UnexpectedEnd for truncated Coll, got: {err:?}"
        );
    }

    #[test]
    fn error_code_zero() {
        let data = [0x00];
        let mut r = VlqReader::new(&data);
        let err = read_type(&mut r).unwrap_err();
        assert!(
            matches!(err, ReadError::InvalidData(_)),
            "expected InvalidData for code 0, got: {err:?}"
        );
    }

    #[test]
    fn read_type_above_max_depth_returns_error_not_stack_overflow() {
        // Construct wire bytes for a deeply-nested
        // `Coll[Coll[Coll[...Coll[SBoolean]]]]`:
        //   - Each `Coll[T]` (with non-embeddable T) is byte
        //     `0x0C` (`COLL_CODE` = 1*PRIM_RANGE = 12, primId 0).
        //   - Final inner type can be the embeddable SBoolean (0x01).
        //
        // Past MAX_TYPE_DEPTH our recursive reader must error gracefully
        // rather than overflow the native stack. The cap is a conservative
        // stack-safety bound, not the true Scala ceiling (= MaxPropositionBytes
        // = 4096) — see the constant's doc. The relative `MAX_TYPE_DEPTH + 5`
        // keeps this honest if the constant changes.
        let mut bytes = vec![0x0Cu8; MAX_TYPE_DEPTH + 5];
        // Inner type after the chain: SBoolean (1).
        bytes.push(0x01);
        let mut r = VlqReader::new(&bytes);
        let err = read_type(&mut r).expect_err("must not stack-overflow");
        match err {
            ReadError::InvalidData(msg) => {
                assert!(
                    msg.contains("recursion depth"),
                    "expected depth error, got: {msg}"
                );
            }
            other => panic!("expected depth error, got: {other:?}"),
        }
    }
}

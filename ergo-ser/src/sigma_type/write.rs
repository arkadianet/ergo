//! Serialization direction of the sigma type-descriptor codec:
//! [`write_type`] and its per-constructor helpers.

use crate::error::WriteError;
use ergo_primitives::writer::VlqWriter;

use super::{
    SigmaType, COLL_CODE, COLL_COLL_CODE, FUNC_CODE, OPTION_CODE, OPTION_COLL_CODE, PAIR1_CODE,
    PAIR2_CODE, PAIR_SYM_CODE, SANY_CODE, SAVL_TREE_CODE, SBOX_CODE, SCONTEXT_CODE, SGLOBAL_CODE,
    SHEADER_CODE, SPREHEADER_CODE, SSTRING_CODE, STYPEVAR_CODE, SUNIT_CODE, TUPLE_CODE,
};

/// Serialize a Sigma type descriptor.
pub fn write_type(w: &mut VlqWriter, t: &SigmaType) -> Result<(), WriteError> {
    match t {
        // Primitives: single byte = type code
        SigmaType::SBoolean => w.put_u8(1),
        SigmaType::SByte => w.put_u8(2),
        SigmaType::SShort => w.put_u8(3),
        SigmaType::SInt => w.put_u8(4),
        SigmaType::SLong => w.put_u8(5),
        SigmaType::SBigInt => w.put_u8(6),
        SigmaType::SGroupElement => w.put_u8(7),
        SigmaType::SSigmaProp => w.put_u8(8),
        SigmaType::SUnsignedBigInt => w.put_u8(9),
        // Codes 10 and 11 are NOT valid embeddable types — Scala's embeddable
        // set stops at 8 (V5) / 9 (V6), so SReserved10/11 must never reach the
        // wire. Unreachable from parsing (the reader rejects codes 10/11);
        // error defensively so a programmatically-built value can't emit a
        // type descriptor the reference rejects.
        SigmaType::SReserved10 | SigmaType::SReserved11 => {
            return Err(WriteError::InvalidData(
                "reserved embeddable type codes 10/11 are not serializable \
                 (outside the Scala embeddable set)"
                    .into(),
            ));
        }

        // Special non-embeddable types
        SigmaType::SAny => w.put_u8(SANY_CODE),
        SigmaType::SUnit => w.put_u8(SUNIT_CODE),
        SigmaType::SBox => w.put_u8(SBOX_CODE),
        SigmaType::SAvlTree => w.put_u8(SAVL_TREE_CODE),
        SigmaType::SContext => w.put_u8(SCONTEXT_CODE),
        SigmaType::SString => w.put_u8(SSTRING_CODE),
        SigmaType::STypeVar(ref name) => {
            // Scala TypeSerializer writes the name length as a single unsigned
            // byte (`w.putUByte(bytes.length)` at TypeSerializer.scala:124).
            // A lossy-decoded name (see [`crate::jvm_utf8`]) can re-encode
            // longer than the original wire bytes — e.g. 86 bytes of 0xff
            // expand to 258 bytes of U+FFFD — overflowing the length byte.
            // Scala's `putUByte` throws on the same overflow, so we mirror it
            // with a recoverable error rather than a panic (the consensus
            // box/tx ids use the original wire bytes, never this writer).
            let bytes = name.as_bytes();
            if bytes.len() > u8::MAX as usize {
                return Err(WriteError::InvalidData(format!(
                    "STypeVar name too long for Scala wire format: {} bytes (max 255)",
                    bytes.len()
                )));
            }
            w.put_u8(STYPEVAR_CODE);
            w.put_u8(bytes.len() as u8);
            w.put_bytes(bytes);
        }
        SigmaType::SHeader => w.put_u8(SHEADER_CODE),
        SigmaType::SPreHeader => w.put_u8(SPREHEADER_CODE),
        SigmaType::SGlobal => w.put_u8(SGLOBAL_CODE),

        // Coll[T] — constrId 1, or Coll[Coll[T]] — constrId 2
        SigmaType::SColl(elem) => write_coll(w, elem)?,

        // Option[T] — constrId 3, or Option[Coll[T]] — constrId 4
        SigmaType::SOption(elem) => write_option(w, elem)?,

        // Tuples: pairs (constrId 5/6/7), triples (constrId 6 primId=0),
        // quads (constrId 7 primId=0), and general (TUPLE_CODE for 5+)
        SigmaType::STuple(elems) => write_tuple(w, elems)?,

        // SFunc: FUNC_CODE + 1-byte domain count + domain types + range
        // type + 1-byte tpeParams count + STypeVar idents. Counts are
        // single unsigned bytes to match Scala (`w.putUByte` /
        // `r.getUByte()` at TypeSerializer.scala:112-119).
        SigmaType::SFunc {
            t_dom,
            t_range,
            tpe_params,
        } => {
            if t_dom.len() > u8::MAX as usize {
                return Err(WriteError::InvalidData(format!(
                    "SFunc domain count too large for Scala wire format: {} (max 255)",
                    t_dom.len()
                )));
            }
            if tpe_params.len() > u8::MAX as usize {
                return Err(WriteError::InvalidData(format!(
                    "SFunc tpeParams count too large for Scala wire format: {} (max 255)",
                    tpe_params.len()
                )));
            }
            // The reader requires each tpeParam to be an STypeVar
            // (`require(ident.isInstanceOf[STypeVar])`); refuse to emit a
            // descriptor that would not round-trip.
            for p in tpe_params {
                if !matches!(p, SigmaType::STypeVar(_)) {
                    return Err(WriteError::InvalidData(format!(
                        "SFunc tpeParam must be an STypeVar, got {p:?}"
                    )));
                }
            }
            w.put_u8(FUNC_CODE);
            w.put_u8(t_dom.len() as u8);
            for d in t_dom {
                write_type(w, d)?;
            }
            write_type(w, t_range)?;
            w.put_u8(tpe_params.len() as u8);
            for p in tpe_params {
                write_type(w, p)?;
            }
        }
    }
    Ok(())
}

fn write_coll(w: &mut VlqWriter, elem: &SigmaType) -> Result<(), WriteError> {
    // Coll[Coll[embeddable]] has a compressed single-byte form (constrId 2,
    // 0x18 + the embeddable code). This optimization applies ONLY when the
    // innermost element is embeddable; Coll[Coll[non-embeddable]] uses the
    // general nested form `0x0c <Coll[inner]>` = `0x0c 0x0c <inner>` (Scala
    // `TypeSerializer.serialize`). Emitting the compressed `0x18` prefix for
    // a non-embeddable inner produced non-canonical bytes vs the reference.
    if let SigmaType::SColl(inner) = elem {
        if let Some(code) = inner.embeddable_code() {
            w.put_u8(COLL_COLL_CODE + code);
            return Ok(());
        }
        // else: fall through to the general Coll[elem] path below, which
        // writes COLL_CODE then recurses into `elem` (the inner Coll).
    }
    // Coll[T] — constrId 1
    if let Some(code) = elem.embeddable_code() {
        w.put_u8(COLL_CODE + code);
    } else {
        w.put_u8(COLL_CODE);
        write_type(w, elem)?;
    }
    Ok(())
}

fn write_option(w: &mut VlqWriter, elem: &SigmaType) -> Result<(), WriteError> {
    // Option[Coll[embeddable]] has a compressed single-byte form (constrId 4,
    // OPTION_COLL_CODE + the embeddable code). This applies ONLY when the
    // collection's element is embeddable; Option[Coll[non-embeddable]] uses
    // the general Option prefix `0x24 <Coll[inner]>` — Scala
    // `TypeSerializer.serialize` puts OptionTypeCode then serializes the WHOLE
    // collection. Emitting `OPTION_COLL_CODE <inner>` for a non-embeddable
    // inner produced non-canonical bytes vs the reference (e.g.
    // Option[Coll[Box]] = 0x30 0x63 instead of 0x24 0x0c 0x63), which shifts
    // derived IDs. Mirrors the identical `write_coll` nested-collection rule.
    if let SigmaType::SColl(inner) = elem {
        if let Some(code) = inner.embeddable_code() {
            // Option[Coll[embeddable]] — single byte
            w.put_u8(OPTION_COLL_CODE + code);
            return Ok(());
        }
        // else: fall through to the general Option[T] path below, which writes
        // OPTION_CODE then recurses into `elem` (the whole Coll).
    }
    // Option[T] — constrId 3
    if let Some(code) = elem.embeddable_code() {
        w.put_u8(OPTION_CODE + code);
    } else {
        w.put_u8(OPTION_CODE);
        write_type(w, elem)?;
    }
    Ok(())
}

fn write_tuple(w: &mut VlqWriter, elems: &[SigmaType]) -> Result<(), WriteError> {
    match elems.len() {
        0 | 1 => {
            // STuple is read back as 2+ elements (the TUPLE_CODE reader rejects
            // count < 2); refuse to emit a degenerate tuple that would not
            // round-trip.
            return Err(WriteError::InvalidData(format!(
                "STuple must have at least 2 elements, got {}",
                elems.len()
            )));
        }
        2 => write_pair(w, &elems[0], &elems[1])?,
        3 => {
            // Triple: constrId 6, primId 0 => byte 72, then 3 types
            w.put_u8(PAIR2_CODE);
            for elem in elems {
                write_type(w, elem)?;
            }
        }
        4 => {
            // Quad: constrId 7, primId 0 => byte 84, then 4 types
            w.put_u8(PAIR_SYM_CODE);
            for elem in elems {
                write_type(w, elem)?;
            }
        }
        n => {
            // General tuple (5+): sentinel byte, 1-byte count, then each type.
            // Scala writes count as a single unsigned byte
            // (`w.putUByte` at TypeSerializer.scala:189 read path;
            // matched in TupleSerializer for the value-level tuple).
            if n > u8::MAX as usize {
                return Err(WriteError::InvalidData(format!(
                    "STuple element count too large for Scala wire format: {n} (max 255)"
                )));
            }
            w.put_u8(TUPLE_CODE);
            w.put_u8(n as u8);
            for elem in elems {
                write_type(w, elem)?;
            }
        }
    }
    Ok(())
}

fn write_pair(w: &mut VlqWriter, t1: &SigmaType, t2: &SigmaType) -> Result<(), WriteError> {
    // Symmetric pair: both elements are the same embeddable type — constrId 7
    if t1 == t2 {
        if let Some(code) = t1.embeddable_code() {
            w.put_u8(PAIR_SYM_CODE + code);
            return Ok(());
        }
    }
    // First element embeddable — constrId 5
    if let Some(code) = t1.embeddable_code() {
        w.put_u8(PAIR1_CODE + code);
        write_type(w, t2)?;
        return Ok(());
    }
    // Second element embeddable — constrId 6
    if let Some(code) = t2.embeddable_code() {
        w.put_u8(PAIR2_CODE + code);
        write_type(w, t1)?;
        return Ok(());
    }
    // Neither element embeddable — constrId 5, primId 0 (general pair)
    w.put_u8(PAIR1_CODE);
    write_type(w, t1)?;
    write_type(w, t2)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_type::read_type;
    use ergo_primitives::reader::VlqReader;

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

    // ----- canonical-form checks -----

    #[test]
    fn coll_coll_nonembeddable_uses_general_prefix() {
        // Coll[Coll[X]] with a NON-embeddable inner element X must serialize
        // as the general nested form `0x0c 0x0c <X>` (two Coll constructors),
        // NOT the compressed `0x18` prefix — Scala reserves the compressed
        // form for Coll[Coll[embeddable]] only. (SANTA Constant.json
        // coll_62/63/69 re-encode to the canonical 0x0c0c form.)
        let nested_box = SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SBox))));
        assert_eq!(encode(&nested_box), vec![COLL_CODE, COLL_CODE, SBOX_CODE]);
        roundtrip(&nested_box);

        // The compressed prefix is still used when the inner element IS
        // embeddable (Coll[Coll[Byte]] -> 0x18 + Byte's embeddable code).
        let nested_byte = SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))));
        let byte_code = SigmaType::SByte.embeddable_code().unwrap();
        assert_eq!(encode(&nested_byte), vec![COLL_COLL_CODE + byte_code]);
    }

    #[test]
    fn option_coll_nonembeddable_uses_general_prefix() {
        // Option[Coll[X]] with a NON-embeddable inner X must serialize as the
        // general Option prefix `0x24 <Coll[X]>` = `0x24 0x0c <X>` (Scala puts
        // OptionTypeCode then serializes the WHOLE collection), NOT the
        // compressed OptionCollection form. Emitting `OPTION_COLL_CODE <X>`
        // (0x30 0x63 for Option[Coll[Box]] instead of 0x24 0x0c 0x63) shifts
        // derived IDs — the consensus-critical drift this fixes.
        let opt_coll_box =
            SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(SigmaType::SBox))));
        assert_eq!(
            encode(&opt_coll_box),
            vec![OPTION_CODE, COLL_CODE, SBOX_CODE]
        );
        roundtrip(&opt_coll_box);

        // The compressed prefix is still used when the collection element IS
        // embeddable (Option[Coll[Byte]] -> OPTION_COLL_CODE + Byte's code).
        let opt_coll_byte =
            SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))));
        let byte_code = SigmaType::SByte.embeddable_code().unwrap();
        assert_eq!(encode(&opt_coll_byte), vec![OPTION_COLL_CODE + byte_code]);
        roundtrip(&opt_coll_byte);
    }

    #[test]
    fn reserved_embeddable_codes_10_and_11_rejected_both_directions() {
        // Codes 10/11 are outside the Scala embeddable set (1..=8 V5, 1..=9 V6).
        // The reader must reject them (was accept-invalid) and the writer must
        // never emit them.
        for code in [10u8, 11u8] {
            let bytes = [code];
            let mut r = VlqReader::new(&bytes);
            assert!(
                read_type(&mut r).is_err(),
                "embeddable type code {code} must be rejected on read"
            );
        }
        assert!(matches!(
            write_err(&SigmaType::SReserved10),
            WriteError::InvalidData(_)
        ));
        assert!(matches!(
            write_err(&SigmaType::SReserved11),
            WriteError::InvalidData(_)
        ));
    }

    // ----- error paths -----

    // Write-side bound checks: a SigmaType whose length / count overflows
    // Scala's single-byte wire form must surface a recoverable WriteError
    // (Scala's `putUByte` throws on the same overflow). A lossy-decoded
    // STypeVar name (see [`crate::jvm_utf8`]) is the reachable trigger — it
    // can expand past 255 bytes — so this MUST NOT panic the node.

    fn write_err(t: &SigmaType) -> WriteError {
        let mut w = VlqWriter::new();
        write_type(&mut w, t).expect_err("expected a WriteError, got Ok")
    }

    #[test]
    fn stypevar_name_above_255_errors_on_write() {
        let err = write_err(&SigmaType::STypeVar("x".repeat(256)));
        assert!(
            matches!(&err, WriteError::InvalidData(m) if m.contains("STypeVar name too long")),
            "got: {err:?}"
        );
    }

    /// The reachable trigger: a lossy-decoded name can EXPAND past 255 bytes
    /// (86 bytes of 0xff -> 86x U+FFFD = 258 bytes). Such a name is accepted at
    /// parse (matching the JVM) but must surface a WriteError on re-serialize,
    /// NOT panic the node.
    #[test]
    fn lossy_expanded_stypevar_name_errors_on_write_not_panics() {
        let name = crate::jvm_utf8::decode(&[0xffu8; 86]);
        assert_eq!(name.len(), 86 * 3, "each 0xff -> 3-byte U+FFFD");
        let err = write_err(&SigmaType::STypeVar(name));
        assert!(
            matches!(&err, WriteError::InvalidData(m) if m.contains("STypeVar name too long")),
            "got: {err:?}"
        );
    }

    #[test]
    fn stuple_count_above_255_errors_on_write() {
        let elems: Vec<SigmaType> = (0..256).map(|_| SigmaType::SInt).collect();
        let err = write_err(&SigmaType::STuple(elems));
        assert!(
            matches!(&err, WriteError::InvalidData(m) if m.contains("STuple element count too large")),
            "got: {err:?}"
        );
    }

    #[test]
    fn sfunc_dom_count_above_255_errors_on_write() {
        let t_dom: Vec<SigmaType> = (0..256).map(|_| SigmaType::SInt).collect();
        let err = write_err(&SigmaType::SFunc {
            t_dom,
            t_range: Box::new(SigmaType::SUnit),
            tpe_params: vec![],
        });
        assert!(
            matches!(&err, WriteError::InvalidData(m) if m.contains("SFunc domain count too large")),
            "got: {err:?}"
        );
    }

    #[test]
    fn sfunc_non_typevar_tpe_param_errors_on_write() {
        // The reader rejects non-STypeVar tpeParams; the writer must not emit
        // a descriptor that fails to round-trip.
        let err = write_err(&SigmaType::SFunc {
            t_dom: vec![SigmaType::SInt],
            t_range: Box::new(SigmaType::SInt),
            tpe_params: vec![SigmaType::SInt],
        });
        assert!(
            matches!(&err, WriteError::InvalidData(m) if m.contains("SFunc tpeParam must be an STypeVar")),
            "got: {err:?}"
        );
    }

    #[test]
    fn tuple_below_two_elements_errors_on_write() {
        for elems in [vec![], vec![SigmaType::SInt]] {
            let err = write_err(&SigmaType::STuple(elems));
            assert!(
                matches!(&err, WriteError::InvalidData(m) if m.contains("STuple must have at least 2 elements")),
                "got: {err:?}"
            );
        }
    }
}

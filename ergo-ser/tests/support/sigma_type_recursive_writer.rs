//! Serialization direction of the sigma type-descriptor codec:
//! [`write_type`] and its per-constructor helpers.

use crate::error::WriteError;
use ergo_primitives::writer::VlqWriter;

use super::{
    SigmaType, COLL_CODE, COLL_COLL_CODE, FUNC_CODE, MAX_TYPE_DEPTH, OPTION_CODE, OPTION_COLL_CODE,
    PAIR1_CODE, PAIR2_CODE, PAIR_SYM_CODE, SANY_CODE, SAVL_TREE_CODE, SBOX_CODE, SCONTEXT_CODE,
    SGLOBAL_CODE, SHEADER_CODE, SPREHEADER_CODE, SSTRING_CODE, STYPEVAR_CODE, SUNIT_CODE,
    TUPLE_CODE,
};

/// Serialize a Sigma type descriptor.
pub fn write_type(w: &mut VlqWriter, t: &SigmaType) -> Result<(), WriteError> {
    write_type_at(w, t, 0)
}

/// [`write_type`] with the current nesting level, so the walk can bound its own
/// recursion the way [`super::read_type`] bounds its own.
///
/// This walk is recursive on the native stack, unlike the reader's heap stack,
/// so it needs its own guard. The reader refuses a descriptor deeper than
/// [`MAX_TYPE_DEPTH`], so a parsed type cannot drive this past that depth; the
/// guard covers the other direction, a `SigmaType` built in-process to a depth
/// the reader would never have produced. It returns an error instead of
/// overflowing the stack, which is unrecoverable and takes the process down
/// rather than the one call.
fn write_type_at(w: &mut VlqWriter, t: &SigmaType, depth: usize) -> Result<(), WriteError> {
    if depth > MAX_TYPE_DEPTH {
        // Past this depth the reference's own recursive writer overflows its
        // thread stack, so refusing matches the reference rather than
        // diverging from it. See read.rs's `read_type_byte` for the same
        // reasoning on the read side.
        return Err(WriteError::InvalidData(format!(
            "type recursion depth exceeds maximum ({MAX_TYPE_DEPTH})"
        )));
    }
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
        SigmaType::NoType => {
            return Err(WriteError::InvalidData(
                "NoType has no type code; it is only ever inferred".into(),
            ));
        }
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
        SigmaType::SColl(elem) => write_coll(w, elem, depth)?,

        // Option[T] — constrId 3, or Option[Coll[T]] — constrId 4
        SigmaType::SOption(elem) => write_option(w, elem, depth)?,

        // Tuples: pairs (constrId 5/6/7), triples (constrId 6 primId=0),
        // quads (constrId 7 primId=0), and general (TUPLE_CODE for 5+)
        SigmaType::STuple(elems) => write_tuple(w, elems, depth)?,

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
                write_type_at(w, d, depth + 1)?;
            }
            write_type_at(w, t_range, depth + 1)?;
            w.put_u8(tpe_params.len() as u8);
            for p in tpe_params {
                write_type_at(w, p, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn write_coll(w: &mut VlqWriter, elem: &SigmaType, depth: usize) -> Result<(), WriteError> {
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
        write_type_at(w, elem, depth + 1)?;
    }
    Ok(())
}

fn write_option(w: &mut VlqWriter, elem: &SigmaType, depth: usize) -> Result<(), WriteError> {
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
        write_type_at(w, elem, depth + 1)?;
    }
    Ok(())
}

fn write_tuple(w: &mut VlqWriter, elems: &[SigmaType], depth: usize) -> Result<(), WriteError> {
    match elems.len() {
        0 | 1 => {
            // Deliberate read/write asymmetry, matching Scala exactly: the
            // TUPLE_CODE reader accepts a 0- or 1-element STuple (Scala
            // `TypeSerializer.deserialize` has no arity floor on read — see
            // `read.rs`'s TUPLE_CODE arm), but `TypeSerializer.serialize`
            // itself throws re-emitting one (oracle, `sigma_type` surface:
            // `600104` -> ACCEPT on read, write throws). A degenerate tuple
            // can arrive by reading an existing tree; refuse to ORIGINATE
            // one here, matching the reference's own write-side refusal.
            return Err(WriteError::InvalidData(format!(
                "STuple must have at least 2 elements, got {}",
                elems.len()
            )));
        }
        2 => write_pair(w, &elems[0], &elems[1], depth)?,
        3 => {
            // Triple: constrId 6, primId 0 => byte 72, then 3 types
            w.put_u8(PAIR2_CODE);
            for elem in elems {
                write_type_at(w, elem, depth + 1)?;
            }
        }
        4 => {
            // Quad: constrId 7, primId 0 => byte 84, then 4 types
            w.put_u8(PAIR_SYM_CODE);
            for elem in elems {
                write_type_at(w, elem, depth + 1)?;
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
                write_type_at(w, elem, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn write_pair(
    w: &mut VlqWriter,
    t1: &SigmaType,
    t2: &SigmaType,
    depth: usize,
) -> Result<(), WriteError> {
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
        write_type_at(w, t2, depth + 1)?;
        return Ok(());
    }
    // Second element embeddable — constrId 6
    if let Some(code) = t2.embeddable_code() {
        w.put_u8(PAIR2_CODE + code);
        write_type_at(w, t1, depth + 1)?;
        return Ok(());
    }
    // Neither element embeddable — constrId 5, primId 0 (general pair)
    w.put_u8(PAIR1_CODE);
    write_type_at(w, t1, depth + 1)?;
    write_type_at(w, t2, depth + 1)?;
    Ok(())
}


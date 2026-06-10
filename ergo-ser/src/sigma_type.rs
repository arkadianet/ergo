use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

// Type code constants matching sigmastate-interpreter's TypeSerializer.
//
// constrId = byte / PRIM_RANGE, primId = byte % PRIM_RANGE.
// constrId 1: Coll[T]
// constrId 2: Coll[Coll[T]]
// constrId 3: Option[T]
// constrId 4: Option[Coll[T]]
// constrId 5: Pair — first element embeddable (primId>0) or general pair (primId=0)
// constrId 6: Pair — second element embeddable (primId>0) or Triple (primId=0)
// constrId 7: Symmetric pair (primId>0) or Quad (primId=0)
const PRIM_RANGE: u8 = 12;

const COLL_CODE: u8 = PRIM_RANGE; // 12
const COLL_COLL_CODE: u8 = 2 * PRIM_RANGE; // 24
const OPTION_CODE: u8 = 3 * PRIM_RANGE; // 36
const OPTION_COLL_CODE: u8 = 4 * PRIM_RANGE; // 48
const PAIR1_CODE: u8 = 5 * PRIM_RANGE; // 60 — first elem embeddable
const PAIR2_CODE: u8 = 6 * PRIM_RANGE; // 72 — second elem embeddable / triple
const PAIR_SYM_CODE: u8 = 7 * PRIM_RANGE; // 84 — symmetric pair / quad

// Special type codes
const TUPLE_CODE: u8 = 0x60; // 96: general tuple (5+ elements)
const FUNC_CODE: u8 = 0x70; // 112: SFunc

// Special pre-defined type codes (not embeddable)
const SANY_CODE: u8 = 97;
const SUNIT_CODE: u8 = 98;
const SBOX_CODE: u8 = 99;
const SAVL_TREE_CODE: u8 = 100;
const SCONTEXT_CODE: u8 = 101;
const SSTRING_CODE: u8 = 102;
const STYPEVAR_CODE: u8 = 103;
const SHEADER_CODE: u8 = 104;
const SPREHEADER_CODE: u8 = 105;
const SGLOBAL_CODE: u8 = 106;

/// Maximum nesting depth for `read_type` recursion. Mirrors Scala's
/// `CoreSerializer.MaxTreeDepth` (default 100, used by
/// `CoreByteReader.level_=` to throw `DeserializeCallDepthExceeded`).
/// Without this guard, a maliciously deeply-nested type
/// (`Coll[Coll[Coll[...]]]`) would blow our recursion stack —
/// Scala rejects gracefully at 100 levels.
const MAX_TYPE_DEPTH: usize = 100;

/// Sigma type descriptors used by the Ergo protocol for serializing
/// typed values.
///
/// The encoding is designed so that common types (a primitive element
/// inside a collection or option) fit in a single byte. The eleven
/// "embeddable" types (`SBoolean..=SReserved11`) get codes 1..=11 and
/// can be packed into the constructor byte of a higher-kinded type
/// (`SColl`, `SOption`, `STuple` of pairs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigmaType {
    /// Embeddable code 1 — boolean.
    SBoolean,
    /// Embeddable code 2 — signed 8-bit integer.
    SByte,
    /// Embeddable code 3 — signed 16-bit integer.
    SShort,
    /// Embeddable code 4 — signed 32-bit integer.
    SInt,
    /// Embeddable code 5 — signed 64-bit integer.
    SLong,
    /// Embeddable code 6 — arbitrary-precision signed integer.
    SBigInt,
    /// Embeddable code 7 — secp256k1 group element (33-byte SEC1).
    SGroupElement,
    /// Embeddable code 8 — sigma protocol proposition.
    SSigmaProp,
    /// Embeddable code 9 — unsigned 256-bit integer (protocol v6+).
    SUnsignedBigInt,
    /// Embeddable code 10 — placeholder for a type observed on mainnet
    /// whose runtime semantics are not yet finalized.
    SReserved10,
    /// Embeddable code 11 — placeholder for a type observed on mainnet
    /// whose runtime semantics are not yet finalized.
    SReserved11,
    /// Top type — every other type is a subtype of `SAny`.
    SAny,
    /// Unit (the zero-information type).
    SUnit,
    /// On-chain UTXO box.
    SBox,
    /// Authenticated AVL+ tree handle.
    SAvlTree,
    /// Script execution context.
    SContext,
    /// UTF-8 string (`Coll[SByte]` at the value level, distinct type
    /// code `102` so the wire form is unambiguous).
    SString,
    /// Type variable placeholder, e.g. `T` in a generic signature.
    STypeVar(String),
    /// Block header.
    SHeader,
    /// Pre-header (header without PoW solution / id).
    SPreHeader,
    /// Global / `CONTEXT.Global` object type, type code `106`.
    SGlobal,
    /// Homogeneous collection.
    SColl(Box<SigmaType>),
    /// Optional value (the type-level `Option`).
    SOption(Box<SigmaType>),
    /// Heterogeneous tuple of two or more elements.
    STuple(Vec<SigmaType>),
    /// Function type: a list of domain types and a single range type.
    SFunc {
        /// Domain (parameter) types in declaration order.
        t_dom: Vec<SigmaType>,
        /// Range (return) type.
        t_range: Box<SigmaType>,
        /// Type-variable parameters of a generic function type. Scala
        /// `TypeSerializer` writes `nTpeParams(u8)` + that many
        /// `STypeVar` idents after the range type — always present on
        /// the wire (usually 0).
        tpe_params: Vec<SigmaType>,
    },
}

impl SigmaType {
    /// Returns the primitive type code if this type is embeddable (1..=11), or None.
    fn embeddable_code(&self) -> Option<u8> {
        match self {
            SigmaType::SBoolean => Some(1),
            SigmaType::SByte => Some(2),
            SigmaType::SShort => Some(3),
            SigmaType::SInt => Some(4),
            SigmaType::SLong => Some(5),
            SigmaType::SBigInt => Some(6),
            SigmaType::SGroupElement => Some(7),
            SigmaType::SSigmaProp => Some(8),
            SigmaType::SUnsignedBigInt => Some(9),
            SigmaType::SReserved10 => Some(10),
            SigmaType::SReserved11 => Some(11),
            _ => None,
        }
    }
}

/// Serialize a Sigma type descriptor.
pub fn write_type(w: &mut VlqWriter, t: &SigmaType) {
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
        SigmaType::SReserved10 => w.put_u8(10),
        SigmaType::SReserved11 => w.put_u8(11),

        // Special non-embeddable types
        SigmaType::SAny => w.put_u8(SANY_CODE),
        SigmaType::SUnit => w.put_u8(SUNIT_CODE),
        SigmaType::SBox => w.put_u8(SBOX_CODE),
        SigmaType::SAvlTree => w.put_u8(SAVL_TREE_CODE),
        SigmaType::SContext => w.put_u8(SCONTEXT_CODE),
        SigmaType::SString => w.put_u8(SSTRING_CODE),
        SigmaType::STypeVar(ref name) => {
            // Scala TypeSerializer writes name length as a single
            // unsigned byte (`w.putUByte(name.length)` /
            // `r.getUByte()` at TypeSerializer.scala:203). VLQ-u32 would
            // round-trip on the wire for length < 128 (VLQ 1-byte and
            // raw u8 alias) but desync from Scala for 128..=255.
            assert!(
                name.len() <= u8::MAX as usize,
                "STypeVar name too long for Scala wire format: {} bytes (max 255)",
                name.len()
            );
            w.put_u8(STYPEVAR_CODE);
            w.put_u8(name.len() as u8);
            w.put_bytes(name.as_bytes());
        }
        SigmaType::SHeader => w.put_u8(SHEADER_CODE),
        SigmaType::SPreHeader => w.put_u8(SPREHEADER_CODE),
        SigmaType::SGlobal => w.put_u8(SGLOBAL_CODE),

        // Coll[T] — constrId 1, or Coll[Coll[T]] — constrId 2
        SigmaType::SColl(elem) => write_coll(w, elem),

        // Option[T] — constrId 3, or Option[Coll[T]] — constrId 4
        SigmaType::SOption(elem) => write_option(w, elem),

        // Tuples: pairs (constrId 5/6/7), triples (constrId 6 primId=0),
        // quads (constrId 7 primId=0), and general (TUPLE_CODE for 5+)
        SigmaType::STuple(elems) => write_tuple(w, elems),

        // SFunc: FUNC_CODE + 1-byte domain count + domain types + range
        // type + 1-byte tpeParams count + STypeVar idents. Counts are
        // single unsigned bytes to match Scala (`w.putUByte` /
        // `r.getUByte()` at TypeSerializer.scala:112-119).
        SigmaType::SFunc {
            t_dom,
            t_range,
            tpe_params,
        } => {
            assert!(
                t_dom.len() <= u8::MAX as usize,
                "SFunc domain count too large for Scala wire format: {} (max 255)",
                t_dom.len()
            );
            assert!(
                tpe_params.len() <= u8::MAX as usize,
                "SFunc tpeParams count too large for Scala wire format: {} (max 255)",
                tpe_params.len()
            );
            w.put_u8(FUNC_CODE);
            w.put_u8(t_dom.len() as u8);
            for d in t_dom {
                write_type(w, d);
            }
            write_type(w, t_range);
            w.put_u8(tpe_params.len() as u8);
            for p in tpe_params {
                write_type(w, p);
            }
        }
    }
}

fn write_coll(w: &mut VlqWriter, elem: &SigmaType) {
    // Coll[Coll[embeddable]] has a compressed single-byte form (constrId 2,
    // 0x18 + the embeddable code). This optimization applies ONLY when the
    // innermost element is embeddable; Coll[Coll[non-embeddable]] uses the
    // general nested form `0x0c <Coll[inner]>` = `0x0c 0x0c <inner>` (Scala
    // `TypeSerializer.serialize`). Emitting the compressed `0x18` prefix for
    // a non-embeddable inner produced non-canonical bytes vs the reference.
    if let SigmaType::SColl(inner) = elem {
        if let Some(code) = inner.embeddable_code() {
            w.put_u8(COLL_COLL_CODE + code);
            return;
        }
        // else: fall through to the general Coll[elem] path below, which
        // writes COLL_CODE then recurses into `elem` (the inner Coll).
    }
    // Coll[T] — constrId 1
    if let Some(code) = elem.embeddable_code() {
        w.put_u8(COLL_CODE + code);
    } else {
        w.put_u8(COLL_CODE);
        write_type(w, elem);
    }
}

fn write_option(w: &mut VlqWriter, elem: &SigmaType) {
    // Check for Option[Coll[T]] — constrId 4
    if let SigmaType::SColl(inner) = elem {
        if let Some(code) = inner.embeddable_code() {
            // Option[Coll[embeddable]] — single byte
            w.put_u8(OPTION_COLL_CODE + code);
        } else {
            // Option[Coll[complex]] — constrId 4 + primId 0, then inner type
            w.put_u8(OPTION_COLL_CODE);
            write_type(w, inner);
        }
        return;
    }
    // Option[T] — constrId 3
    if let Some(code) = elem.embeddable_code() {
        w.put_u8(OPTION_CODE + code);
    } else {
        w.put_u8(OPTION_CODE);
        write_type(w, elem);
    }
}

fn write_tuple(w: &mut VlqWriter, elems: &[SigmaType]) {
    match elems.len() {
        2 => write_pair(w, &elems[0], &elems[1]),
        3 => {
            // Triple: constrId 6, primId 0 => byte 72, then 3 types
            w.put_u8(PAIR2_CODE);
            for elem in elems {
                write_type(w, elem);
            }
        }
        4 => {
            // Quad: constrId 7, primId 0 => byte 84, then 4 types
            w.put_u8(PAIR_SYM_CODE);
            for elem in elems {
                write_type(w, elem);
            }
        }
        n => {
            // General tuple (5+): sentinel byte, 1-byte count, then each type.
            // Scala writes count as a single unsigned byte
            // (`w.putUByte` at TypeSerializer.scala:189 read path;
            // matched in TupleSerializer for the value-level tuple).
            assert!(
                n <= u8::MAX as usize,
                "STuple element count too large for Scala wire format: {n} (max 255)"
            );
            w.put_u8(TUPLE_CODE);
            w.put_u8(n as u8);
            for elem in elems {
                write_type(w, elem);
            }
        }
    }
}

fn write_pair(w: &mut VlqWriter, t1: &SigmaType, t2: &SigmaType) {
    // Symmetric pair: both elements are the same embeddable type — constrId 7
    if t1 == t2 {
        if let Some(code) = t1.embeddable_code() {
            w.put_u8(PAIR_SYM_CODE + code);
            return;
        }
    }
    // First element embeddable — constrId 5
    if let Some(code) = t1.embeddable_code() {
        w.put_u8(PAIR1_CODE + code);
        write_type(w, t2);
        return;
    }
    // Second element embeddable — constrId 6
    if let Some(code) = t2.embeddable_code() {
        w.put_u8(PAIR2_CODE + code);
        write_type(w, t1);
        return;
    }
    // Neither element embeddable — constrId 5, primId 0 (general pair)
    w.put_u8(PAIR1_CODE);
    write_type(w, t1);
    write_type(w, t2);
}

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
        // Primitive embeddable types (1..=11)
        1 => Ok(SigmaType::SBoolean),
        2 => Ok(SigmaType::SByte),
        3 => Ok(SigmaType::SShort),
        4 => Ok(SigmaType::SInt),
        5 => Ok(SigmaType::SLong),
        6 => Ok(SigmaType::SBigInt),
        7 => Ok(SigmaType::SGroupElement),
        8 => Ok(SigmaType::SSigmaProp),
        9 => Ok(SigmaType::SUnsignedBigInt),
        10 => Ok(SigmaType::SReserved10),
        11 => Ok(SigmaType::SReserved11),

        // Special non-embeddable
        SANY_CODE => Ok(SigmaType::SAny),
        SUNIT_CODE => Ok(SigmaType::SUnit),
        SBOX_CODE => Ok(SigmaType::SBox),
        SAVL_TREE_CODE => Ok(SigmaType::SAvlTree),
        SCONTEXT_CODE => Ok(SigmaType::SContext),
        SSTRING_CODE => Ok(SigmaType::SString),
        STYPEVAR_CODE => {
            // Scala TypeSerializer.scala:203 reads name length as
            // unsigned byte and accepts anything in 0..=255 — no
            // additional Rust-side cap. A tighter cap would reject
            // Scala-valid descriptors and silently diverge from the
            // accept set.
            let name_len = r.get_u8()? as usize;
            let name_bytes = r.get_bytes(name_len)?;
            let name = String::from_utf8(name_bytes.to_vec())
                .map_err(|e| ReadError::InvalidData(format!("invalid type variable name: {e}")))?;
            Ok(SigmaType::STypeVar(name))
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

    match constr_id {
        // constrId 1: Coll[T]
        1 => {
            let elem = if prim_id == 0 {
                read_type_at_depth(r, next)?
            } else {
                prim_from_code(prim_id)?
            };
            Ok(SigmaType::SColl(Box::new(elem)))
        }

        // constrId 2: Coll[Coll[T]]
        2 => {
            let inner = if prim_id == 0 {
                read_type_at_depth(r, next)?
            } else {
                prim_from_code(prim_id)?
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
                prim_from_code(prim_id)?
            };
            Ok(SigmaType::SOption(Box::new(elem)))
        }

        // constrId 4: Option[Coll[T]]
        4 => {
            let inner = if prim_id == 0 {
                read_type_at_depth(r, next)?
            } else {
                prim_from_code(prim_id)?
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
                let t1 = prim_from_code(prim_id)?;
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
                let t2 = prim_from_code(prim_id)?;
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
                let t = prim_from_code(prim_id)?;
                Ok(SigmaType::STuple(vec![t.clone(), t]))
            }
        }

        _ => Err(ReadError::InvalidData(format!(
            "unknown type constructor: constrId={constr_id} (byte=0x{byte:02X})"
        ))),
    }
}

fn prim_from_code(code: u8) -> Result<SigmaType, ReadError> {
    match code {
        1 => Ok(SigmaType::SBoolean),
        2 => Ok(SigmaType::SByte),
        3 => Ok(SigmaType::SShort),
        4 => Ok(SigmaType::SInt),
        5 => Ok(SigmaType::SLong),
        6 => Ok(SigmaType::SBigInt),
        7 => Ok(SigmaType::SGroupElement),
        8 => Ok(SigmaType::SSigmaProp),
        9 => Ok(SigmaType::SUnsignedBigInt),
        10 => Ok(SigmaType::SReserved10),
        11 => Ok(SigmaType::SReserved11),
        _ => Err(ReadError::InvalidData(format!(
            "invalid embeddable type code: {code}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn encode(t: &SigmaType) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_type(&mut w, t);
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

    // Write-side bound assertions: programmer constructing a SigmaType
    // with a length / count that overflows Scala's single-byte wire
    // form. Panic at the construction site so the bug surfaces before
    // a corrupted wire stream propagates downstream.

    #[test]
    #[should_panic(expected = "STypeVar name too long for Scala wire format")]
    fn stypevar_name_above_255_panics_on_write() {
        let name = "x".repeat(256);
        let t = SigmaType::STypeVar(name);
        let _ = encode(&t);
    }

    #[test]
    #[should_panic(expected = "STuple element count too large for Scala wire format")]
    fn stuple_count_above_255_panics_on_write() {
        let elems: Vec<SigmaType> = (0..256).map(|_| SigmaType::SInt).collect();
        let t = SigmaType::STuple(elems);
        let _ = encode(&t);
    }

    #[test]
    #[should_panic(expected = "SFunc domain count too large for Scala wire format")]
    fn sfunc_dom_count_above_255_panics_on_write() {
        let t_dom: Vec<SigmaType> = (0..256).map(|_| SigmaType::SInt).collect();
        let t = SigmaType::SFunc {
            t_dom,
            t_range: Box::new(SigmaType::SUnit),
            tpe_params: vec![],
        };
        let _ = encode(&t);
    }

    #[test]
    fn read_type_above_max_depth_returns_error_not_stack_overflow() {
        // Construct wire bytes for a deeply-nested
        // `Coll[Coll[Coll[...Coll[SBoolean]]]]`:
        //   - Each `Coll[T]` (with non-embeddable T) is byte
        //     `0x0C` (`COLL_CODE` = 1*PRIM_RANGE = 12, primId 0).
        //   - Final inner type can be the embeddable SBoolean (0x01).
        //
        // With MAX_TYPE_DEPTH levels of Coll wrappers, our reader
        // must error gracefully (not stack-overflow). The error
        // message names the limit.
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

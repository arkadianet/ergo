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

/// Pending work in wire order, stored in reverse on the heap stack.
/// Slices keep wide tuples/domains from adding one stack entry per child.
enum Work<'a> {
    Type(&'a SigmaType, usize),
    Types(&'a [SigmaType], usize),
    Byte(u8),
}

/// Serialize a Sigma type descriptor without recursing on the native stack.
/// Depth is checked at the same visits as the recursive writer, including
/// its compressed terminal forms, so reader-accepted types remain writable.
pub fn write_type(w: &mut VlqWriter, t: &SigmaType) -> Result<(), WriteError> {
    let mut stack = vec![Work::Type(t, 0)];
    while let Some(work) = stack.pop() {
        match work {
            Work::Type(t, depth) => write_one(w, t, depth, &mut stack)?,
            Work::Types(types, depth) => {
                if let Some((first, rest)) = types.split_first() {
                    stack.push(Work::Types(rest, depth));
                    stack.push(Work::Type(first, depth));
                }
            }
            Work::Byte(byte) => w.put_u8(byte),
        }
    }
    Ok(())
}

fn write_one<'a>(
    w: &mut VlqWriter,
    t: &'a SigmaType,
    depth: usize,
    stack: &mut Vec<Work<'a>>,
) -> Result<(), WriteError> {
    if depth > MAX_TYPE_DEPTH {
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
        SigmaType::SColl(elem) => write_coll(w, elem, depth, stack),

        // Option[T] — constrId 3, or Option[Coll[T]] — constrId 4
        SigmaType::SOption(elem) => write_option(w, elem, depth, stack),

        // Tuples: pairs (constrId 5/6/7), triples (constrId 6 primId=0),
        // quads (constrId 7 primId=0), and general (TUPLE_CODE for 5+)
        SigmaType::STuple(elems) => write_tuple(w, elems, depth, stack)?,

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
            stack.push(Work::Types(tpe_params, depth + 1));
            stack.push(Work::Byte(tpe_params.len() as u8));
            stack.push(Work::Type(t_range, depth + 1));
            stack.push(Work::Types(t_dom, depth + 1));
        }
    }
    Ok(())
}

fn write_coll<'a>(w: &mut VlqWriter, elem: &'a SigmaType, depth: usize, stack: &mut Vec<Work<'a>>) {
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
        // writes COLL_CODE then schedules `elem` (the inner Coll).
    }
    // Coll[T] — constrId 1
    if let Some(code) = elem.embeddable_code() {
        w.put_u8(COLL_CODE + code);
    } else {
        w.put_u8(COLL_CODE);
        stack.push(Work::Type(elem, depth + 1));
    }
}

fn write_option<'a>(
    w: &mut VlqWriter,
    elem: &'a SigmaType,
    depth: usize,
    stack: &mut Vec<Work<'a>>,
) {
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
            return;
        }
        // else: fall through to the general Option[T] path below, which writes
        // OPTION_CODE then schedules `elem` (the whole Coll).
    }
    // Option[T] — constrId 3
    if let Some(code) = elem.embeddable_code() {
        w.put_u8(OPTION_CODE + code);
    } else {
        w.put_u8(OPTION_CODE);
        stack.push(Work::Type(elem, depth + 1));
    }
}

fn write_tuple<'a>(
    w: &mut VlqWriter,
    elems: &'a [SigmaType],
    depth: usize,
    stack: &mut Vec<Work<'a>>,
) -> Result<(), WriteError> {
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
        2 => write_pair(w, &elems[0], &elems[1], depth, stack),
        3 => {
            // Triple: constrId 6, primId 0 => byte 72, then 3 types
            w.put_u8(PAIR2_CODE);
            stack.push(Work::Types(elems, depth + 1));
        }
        4 => {
            // Quad: constrId 7, primId 0 => byte 84, then 4 types
            w.put_u8(PAIR_SYM_CODE);
            stack.push(Work::Types(elems, depth + 1));
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
            stack.push(Work::Types(elems, depth + 1));
        }
    }
    Ok(())
}

fn write_pair<'a>(
    w: &mut VlqWriter,
    t1: &'a SigmaType,
    t2: &'a SigmaType,
    depth: usize,
    stack: &mut Vec<Work<'a>>,
) {
    // Symmetric pair: both elements are the same embeddable type — constrId 7
    let codes = (t1.embeddable_code(), t2.embeddable_code());
    if let (Some(a), Some(b)) = codes {
        if a == b {
            w.put_u8(PAIR_SYM_CODE + a);
            return;
        }
    }
    // First element embeddable — constrId 5
    if let Some(code) = codes.0 {
        w.put_u8(PAIR1_CODE + code);
        stack.push(Work::Type(t2, depth + 1));
        return;
    }
    // Second element embeddable — constrId 6
    if let Some(code) = codes.1 {
        w.put_u8(PAIR2_CODE + code);
        stack.push(Work::Type(t1, depth + 1));
        return;
    }
    // Neither element embeddable — constrId 5, primId 0 (general pair)
    w.put_u8(PAIR1_CODE);
    stack.push(Work::Type(t2, depth + 1));
    stack.push(Work::Type(t1, depth + 1));
}

// The pre-change writer is copied verbatim from dba00a73, without its tests.
#[cfg(test)]
#[rustfmt::skip]
#[path = "../../tests/support/sigma_type_recursive_writer.rs"]
mod recursive_reference;

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

    // Deep checks use an ordinary fuzz-sized stack and compare canonical
    // bytes instead of invoking recursive Eq/Debug on the resulting types.
    fn on_8mib_stack(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    fn nested_coll(depth: usize, leaf: SigmaType) -> SigmaType {
        (0..depth).fold(leaf, |t, _| SigmaType::SColl(Box::new(t)))
    }

    fn deep_wire(shape: u8, depth: usize) -> Vec<u8> {
        let mut bytes = match shape {
            0 => vec![COLL_CODE; depth],
            1 => vec![COLL_COLL_CODE; depth / 2],
            2 => vec![OPTION_CODE; depth],
            3 => vec![OPTION_COLL_CODE; depth / 2],
            4 => vec![PAIR1_CODE; depth],
            5 => [TUPLE_CODE, 2].repeat(depth),
            6 => [FUNC_CODE, 1].repeat(depth),
            7 => [FUNC_CODE, 0].repeat(depth),
            _ => unreachable!(),
        };
        bytes.push(match shape {
            0..=3 => COLL_CODE + 2,
            _ => SBOX_CODE,
        });
        match shape {
            4 | 5 => bytes.extend(vec![SBOX_CODE; depth]),
            6 => bytes.extend([SBOX_CODE, 0].repeat(depth)),
            7 => bytes.extend(vec![0; depth]),
            _ => (),
        }
        bytes
    }

    #[test]
    fn write_type_reader_max_depth_on_8mib_stack() {
        on_8mib_stack(|| {
            for shape in 0..=7 {
                let bytes = deep_wire(shape, MAX_TYPE_DEPTH);
                let mut r = VlqReader::new(&bytes);
                let parsed = read_type(&mut r).expect("reader must accept its depth boundary");
                assert!(r.is_empty());
                let canonical = encode(&parsed);
                let mut r = VlqReader::new(&canonical);
                let decoded = read_type(&mut r).expect("writer output must round-trip");
                assert!(r.is_empty());
                assert_eq!(encode(&decoded), canonical, "shape {shape}");
                // Exercise ordinary Drop as well as the writer.
                drop(decoded);
                drop(parsed);
            }
            // A compressed terminal can contain two constructors at depth MAX.
            let mut bytes = vec![COLL_CODE; MAX_TYPE_DEPTH];
            bytes.push(COLL_COLL_CODE + 2);
            let parsed = read_type(&mut VlqReader::new(&bytes)).unwrap();
            assert_eq!(encode(&parsed), bytes);
        });
    }

    #[test]
    fn write_type_past_max_depth_on_8mib_stack() {
        on_8mib_stack(|| {
            for t in [
                nested_coll(MAX_TYPE_DEPTH + 1, SigmaType::SBox),
                nested_coll(MAX_TYPE_DEPTH + 3, SigmaType::SByte),
                // Equal compound children used to invoke unbounded derived Eq
                // before the writer could reach its depth guard.
                SigmaType::STuple(vec![
                    nested_coll(MAX_TYPE_DEPTH + 4_000, SigmaType::SByte),
                    nested_coll(MAX_TYPE_DEPTH + 4_000, SigmaType::SByte),
                ]),
            ] {
                let err = write_err(&t);
                assert!(matches!(err, WriteError::InvalidData(msg)
                    if msg == format!("type recursion depth exceeds maximum ({MAX_TYPE_DEPTH})")));
            }
            // Pin compressed prefixes against the reader's refusal too.
            for shape in 0..=7 {
                let bytes = deep_wire(shape, MAX_TYPE_DEPTH + 2);
                assert!(read_type(&mut VlqReader::new(&bytes)).is_err());
            }
        });
    }

    use proptest::prelude::*;

    fn arbitrary_type() -> BoxedStrategy<SigmaType> {
        let leaf = prop_oneof![
            (1u8..=9).prop_map(|code| super::super::prim_from_code(code, 3).unwrap()),
            proptest::sample::select(vec![
                SigmaType::SAny,
                SigmaType::SUnit,
                SigmaType::SBox,
                SigmaType::SAvlTree,
                SigmaType::SContext,
                SigmaType::SString,
                SigmaType::SHeader,
                SigmaType::SPreHeader,
                SigmaType::SGlobal,
            ]),
            "[A-Za-z0-9]{0,32}".prop_map(SigmaType::STypeVar),
        ];
        leaf.prop_recursive(6, 256, 6, |inner| {
            prop_oneof![
                inner.clone().prop_map(|t| SigmaType::SColl(Box::new(t))),
                inner.clone().prop_map(|t| SigmaType::SOption(Box::new(t))),
                proptest::collection::vec(inner.clone(), 2..=8).prop_map(SigmaType::STuple),
                (
                    proptest::collection::vec(inner.clone(), 0..=4),
                    inner,
                    proptest::collection::vec("[A-Z]{1,4}", 0..=4)
                )
                    .prop_map(|(t_dom, range, params)| SigmaType::SFunc {
                        t_dom,
                        t_range: Box::new(range),
                        tpe_params: params.into_iter().map(SigmaType::STypeVar).collect(),
                    }),
            ]
        })
        .boxed()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn iterative_bytes_match_recursive_writer(
            mut t in arbitrary_type(),
            wrappers in proptest::collection::vec(0u8..=7, 0..=384),
        ) {
            // Deep but narrow random spines supplement the branching trees.
            for wrapper in wrappers {
                t = match wrapper {
                    0 => SigmaType::SColl(Box::new(t)),
                    1 => SigmaType::SOption(Box::new(t)),
                    2 => SigmaType::STuple(vec![SigmaType::SInt, t]),
                    3 => SigmaType::STuple(vec![t, SigmaType::SLong]),
                    4 => SigmaType::STuple(vec![SigmaType::SBox, t]),
                    5 => SigmaType::STuple(vec![t, SigmaType::SUnit, SigmaType::SByte]),
                    6 => SigmaType::SFunc {
                        t_dom: vec![t], t_range: Box::new(SigmaType::SUnit),
                        tpe_params: vec![SigmaType::STypeVar("T".into())],
                    },
                    _ => SigmaType::SFunc {
                        t_dom: vec![], t_range: Box::new(t), tpe_params: vec![],
                    },
                };
            }
            let bytes = encode(&t);
            let mut reference = VlqWriter::new();
            recursive_reference::write_type(&mut reference, &t).unwrap();
            let reference = reference.result();
            prop_assert_eq!(&bytes, &reference);
            for wire in [&bytes, &reference] {
                let mut r = VlqReader::new(wire);
                let parsed = read_type(&mut r).unwrap();
                prop_assert!(r.is_empty());
                prop_assert_eq!(&parsed, &t);
            }
        }
    }

    #[test]
    fn all_compressed_forms_have_identical_bytes() {
        for code in 1..=9 {
            let prim = super::super::prim_from_code(code, 3).unwrap();
            let cases = [
                (
                    SigmaType::SColl(Box::new(prim.clone())),
                    vec![COLL_CODE + code],
                ),
                (
                    SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(prim.clone())))),
                    vec![COLL_COLL_CODE + code],
                ),
                (
                    SigmaType::SOption(Box::new(prim.clone())),
                    vec![OPTION_CODE + code],
                ),
                (
                    SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(prim.clone())))),
                    vec![OPTION_COLL_CODE + code],
                ),
                (
                    SigmaType::STuple(vec![prim.clone(), SigmaType::SBox]),
                    vec![PAIR1_CODE + code, SBOX_CODE],
                ),
                (
                    SigmaType::STuple(vec![SigmaType::SBox, prim.clone()]),
                    vec![PAIR2_CODE + code, SBOX_CODE],
                ),
                (
                    SigmaType::STuple(vec![prim.clone(), prim]),
                    vec![PAIR_SYM_CODE + code],
                ),
            ];
            for (t, expected) in cases {
                assert_eq!(encode(&t), expected);
                let mut w = VlqWriter::new();
                recursive_reference::write_type(&mut w, &t).unwrap();
                assert_eq!(w.result(), expected);
                roundtrip(&t);
            }
            for second in 1..=9 {
                let t = SigmaType::STuple(vec![
                    super::super::prim_from_code(code, 3).unwrap(),
                    super::super::prim_from_code(second, 3).unwrap(),
                ]);
                let expected = if code == second {
                    vec![PAIR_SYM_CODE + code]
                } else {
                    vec![PAIR1_CODE + code, second]
                };
                assert_eq!(encode(&t), expected);
                roundtrip(&t);
            }
        }
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

//! Golden-byte and Scala-encoding-scheme parity tests for `SigmaType`.
//!
//! Each test below pins an exact wire layout — failure means the encoding
//! drifted from Scala's `TypeSerializer`. These tests live as integration
//! tests rather than inline in `sigma_type.rs` because they (1) form a
//! large self-contained oracle suite and (2) only consume the public
//! `read_type` / `write_type` / `SigmaType` API.

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::sigma_type::{read_type, write_type, SigmaType};

fn encode(t: &SigmaType) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_type(&mut w, t);
    w.result()
}

// -- primitives --

#[test]
fn golden_sboolean() {
    assert_eq!(encode(&SigmaType::SBoolean), [0x01]);
}

#[test]
fn golden_sbyte() {
    assert_eq!(encode(&SigmaType::SByte), [0x02]);
}

#[test]
fn golden_sshort() {
    assert_eq!(encode(&SigmaType::SShort), [0x03]);
}

#[test]
fn golden_sint() {
    assert_eq!(encode(&SigmaType::SInt), [0x04]);
}

#[test]
fn golden_slong() {
    assert_eq!(encode(&SigmaType::SLong), [0x05]);
}

#[test]
fn golden_sbigint() {
    assert_eq!(encode(&SigmaType::SBigInt), [0x06]);
}

#[test]
fn golden_sgroup_element() {
    assert_eq!(encode(&SigmaType::SGroupElement), [0x07]);
}

#[test]
fn golden_ssigma_prop() {
    assert_eq!(encode(&SigmaType::SSigmaProp), [0x08]);
}

#[test]
fn golden_sbox() {
    assert_eq!(encode(&SigmaType::SBox), [0x63]);
}

#[test]
fn golden_savl_tree() {
    assert_eq!(encode(&SigmaType::SAvlTree), [0x64]);
}

// -- Coll (constrId 1) --

#[test]
fn golden_coll_boolean() {
    // constrId 1, primId 1 = 12+1 = 13 = 0x0D
    assert_eq!(
        encode(&SigmaType::SColl(Box::new(SigmaType::SBoolean))),
        [0x0D]
    );
}

#[test]
fn golden_coll_byte() {
    // constrId 1, primId 2 = 12+2 = 14 = 0x0E
    assert_eq!(
        encode(&SigmaType::SColl(Box::new(SigmaType::SByte))),
        [0x0E]
    );
}

#[test]
fn golden_coll_short() {
    assert_eq!(
        encode(&SigmaType::SColl(Box::new(SigmaType::SShort))),
        [0x0F]
    );
}

#[test]
fn golden_coll_int() {
    assert_eq!(encode(&SigmaType::SColl(Box::new(SigmaType::SInt))), [0x10]);
}

#[test]
fn golden_coll_long() {
    assert_eq!(
        encode(&SigmaType::SColl(Box::new(SigmaType::SLong))),
        [0x11]
    );
}

#[test]
fn golden_coll_box() {
    // Coll[SBox]: constrId 1, primId 0 = 12, then SBox = 0x63
    assert_eq!(
        encode(&SigmaType::SColl(Box::new(SigmaType::SBox))),
        [0x0C, 0x63]
    );
}

// -- Coll[Coll[T]] (constrId 2) --

#[test]
fn golden_coll_coll_byte() {
    // constrId 2, primId 2 = 24+2 = 26 = 0x1A — single byte!
    let t = SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))));
    assert_eq!(encode(&t), [0x1A]);
}

#[test]
fn golden_coll_coll_int() {
    // constrId 2, primId 4 = 24+4 = 28 = 0x1C
    let t = SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SInt))));
    assert_eq!(encode(&t), [0x1C]);
}

#[test]
fn golden_coll_coll_box() {
    // Coll[Coll[non-embeddable]] is NOT the compressed constrId-2 form.
    // Scala's TypeSerializer reserves 0x18+code for Coll[Coll[embeddable]];
    // a non-embeddable inner (SBox) serializes as the general nested form
    // 0x0c (outer Coll) + 0x0c (inner Coll) + 0x63 (SBox). Confirmed against
    // the JVM-blessed SANTA wire vectors (Constant.json coll_62/63/69).
    let t = SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SBox))));
    assert_eq!(encode(&t), [0x0C, 0x0C, 0x63]);
}

// -- Option (constrId 3) --

#[test]
fn golden_option_byte() {
    // constrId 3, primId 2 = 36+2 = 38 = 0x26
    assert_eq!(
        encode(&SigmaType::SOption(Box::new(SigmaType::SByte))),
        [0x26]
    );
}

#[test]
fn golden_option_int() {
    // constrId 3, primId 4 = 36+4 = 40 = 0x28
    assert_eq!(
        encode(&SigmaType::SOption(Box::new(SigmaType::SInt))),
        [0x28]
    );
}

#[test]
fn golden_option_long() {
    // constrId 3, primId 5 = 36+5 = 41 = 0x29
    assert_eq!(
        encode(&SigmaType::SOption(Box::new(SigmaType::SLong))),
        [0x29]
    );
}

#[test]
fn golden_option_box() {
    // constrId 3, primId 0 = 36, then SBox = 0x63
    assert_eq!(
        encode(&SigmaType::SOption(Box::new(SigmaType::SBox))),
        [0x24, 0x63]
    );
}

// -- Option[Coll[T]] (constrId 4) --

#[test]
fn golden_option_coll_byte() {
    // constrId 4, primId 2 = 48+2 = 50 = 0x32
    let t = SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))));
    assert_eq!(encode(&t), [0x32]);
}

#[test]
fn golden_option_coll_int() {
    // constrId 4, primId 4 = 48+4 = 52 = 0x34
    let t = SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(SigmaType::SInt))));
    assert_eq!(encode(&t), [0x34]);
}

#[test]
fn golden_option_coll_box() {
    // constrId 4, primId 0 = 48, then SBox = 0x63
    let t = SigmaType::SOption(Box::new(SigmaType::SColl(Box::new(SigmaType::SBox))));
    assert_eq!(encode(&t), [0x30, 0x63]);
}

// -- Pair — constrId 5 (first elem embeddable) --

#[test]
fn golden_pair_int_long() {
    // constrId 5, primId 4 (SInt) = 60+4 = 64 = 0x40, then SLong = 0x05
    let t = SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]);
    assert_eq!(encode(&t), [0x40, 0x05]);
}

#[test]
fn golden_pair_coll_byte_int() {
    // Second element embeddable: constrId 6, primId 4 (SInt) = 72+4 = 76 = 0x4C
    // then first = Coll[Byte] = 0x0E
    let t = SigmaType::STuple(vec![
        SigmaType::SColl(Box::new(SigmaType::SByte)),
        SigmaType::SInt,
    ]);
    assert_eq!(encode(&t), [0x4C, 0x0E]);
}

// -- Pair — constrId 7 (symmetric) --

#[test]
fn golden_pair_int_int() {
    // Symmetric pair: constrId 7, primId 4 = 84+4 = 88 = 0x58
    let t = SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SInt]);
    assert_eq!(encode(&t), [0x58]);
}

#[test]
fn golden_pair_long_long() {
    // Symmetric pair: constrId 7, primId 5 = 84+5 = 89 = 0x59
    let t = SigmaType::STuple(vec![SigmaType::SLong, SigmaType::SLong]);
    assert_eq!(encode(&t), [0x59]);
}

// -- Pair — constrId 6 (second elem embeddable) --

#[test]
fn golden_pair_box_int() {
    // Second element embeddable: constrId 6, primId 4 = 72+4 = 76 = 0x4C, then SBox
    let t = SigmaType::STuple(vec![SigmaType::SBox, SigmaType::SInt]);
    assert_eq!(encode(&t), [0x4C, 0x63]);
}

// -- Triple (constrId 6, primId=0) --

#[test]
fn golden_triple() {
    // constrId 6, primId 0 = 72 = 0x48, then 3 types
    let t = SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong, SigmaType::SByte]);
    assert_eq!(encode(&t), [0x48, 0x04, 0x05, 0x02]);
}

// -- Quad (constrId 7, primId=0) --

#[test]
fn golden_quad() {
    // constrId 7, primId 0 = 84 = 0x54, then 4 types
    let t = SigmaType::STuple(vec![
        SigmaType::SBoolean,
        SigmaType::SByte,
        SigmaType::SInt,
        SigmaType::SLong,
    ]);
    assert_eq!(encode(&t), [0x54, 0x01, 0x02, 0x04, 0x05]);
}

// -- SFunc (FUNC_CODE = 0x70) --

#[test]
fn golden_func_int_to_long() {
    // 0x70, count 1, SInt, SLong, tpeParams count 0 — Scala
    // TypeSerializer always writes the trailing tpeParams count byte
    // (`w.putUByte(tpeParams.length)`, TypeSerializer.scala:117-119).
    let t = SigmaType::SFunc {
        t_dom: vec![SigmaType::SInt],
        t_range: Box::new(SigmaType::SLong),
        tpe_params: vec![],
    };
    assert_eq!(encode(&t), [0x70, 0x01, 0x04, 0x05, 0x00]);
}

#[test]
fn golden_func_two_domain() {
    // 0x70, count 2, SInt, SLong, SBoolean, tpeParams count 0
    let t = SigmaType::SFunc {
        t_dom: vec![SigmaType::SInt, SigmaType::SLong],
        t_range: Box::new(SigmaType::SBoolean),
        tpe_params: vec![],
    };
    assert_eq!(encode(&t), [0x70, 0x02, 0x04, 0x05, 0x01, 0x00]);
}

// -- New predefined types (SString, SGlobal) --

#[test]
fn golden_sstring() {
    assert_eq!(encode(&SigmaType::SString), [0x66]);
}

#[test]
fn golden_sglobal() {
    assert_eq!(encode(&SigmaType::SGlobal), [0x6A]);
}

#[test]
fn decode_0x66_as_sstring() {
    // 0x66 = 102 = SString, the type code seen at block 766915
    let data = [0x66];
    let mut r = VlqReader::new(&data);
    assert_eq!(read_type(&mut r).unwrap(), SigmaType::SString);
}

#[test]
fn coll_sstring() {
    // Coll[SString] = COLL_CODE (12) + primId 0, then SString type code
    let t = SigmaType::SColl(Box::new(SigmaType::SString));
    let data = encode(&t);
    assert_eq!(data, [0x0C, 0x66]); // Coll<non-embeddable> + SString
    let mut r = VlqReader::new(&data);
    assert_eq!(read_type(&mut r).unwrap(), t);
}

// -- Above-127 length encoding (Scala raw u8 vs VLQ) --
//
// These three tests pin the boundary that was previously hidden by VLQ-1-byte
// aliasing: any count/length above 127 in STypeVar / STuple / SFunc would
// have produced multi-byte VLQ bytes — off the wire format Scala writes.
// Each test pins a single-byte length encoding for a value above the alias
// band, so any regression that re-introduces VLQ would fail loudly. For
// values < 128 the wire is byte-identical to a raw u8 (high bit clear), so
// a roundtrip test at low values would pass under either implementation.

#[test]
fn stypevar_name_length_above_127_uses_single_length_byte() {
    // Bypass the read-side cap (64) by encoding directly and
    // asserting the writer emits 1 byte for length 200.
    let mut name = String::new();
    for _ in 0..200 {
        name.push('x');
    }
    let t = SigmaType::STypeVar(name);
    let bytes = encode(&t);
    // Layout: STYPEVAR_CODE (= 103 = 0x67) + 1-byte length + 200 name bytes.
    assert_eq!(bytes.len(), 1 + 1 + 200);
    assert_eq!(bytes[0], 0x67, "STYPEVAR_CODE = 103 = 0x67");
    // 200 = 0xC8. As raw u8 this is one byte; as VLQ this would
    // be 0xC8 0x01 (continuation bit set). Pin the raw-u8 case.
    assert_eq!(
        bytes[1], 0xC8,
        "length byte must be raw u8 (200=0xC8), not VLQ"
    );
    assert_ne!(
        bytes[2], 0x01,
        "second byte must NOT be VLQ continuation 0x01"
    );
}

#[test]
fn stuple_count_above_127_uses_single_count_byte() {
    // 200-element tuple: forces general-tuple branch (TUPLE_CODE = 0x60)
    // and pushes the count above the VLQ alias band.
    let elems: Vec<SigmaType> = (0..200).map(|_| SigmaType::SInt).collect();
    let t = SigmaType::STuple(elems);
    let bytes = encode(&t);
    assert_eq!(bytes[0], 0x60, "TUPLE_CODE = 0x60");
    // 200 = 0xC8 raw; VLQ would be 0xC8 0x01.
    assert_eq!(
        bytes[1], 0xC8,
        "tuple count must be raw u8 (200=0xC8), not VLQ"
    );
    // Following byte must be the first element's type code, not
    // a VLQ continuation. SInt = 0x04.
    assert_eq!(
        bytes[2], 0x04,
        "byte after count must be first element type"
    );
    // Roundtrip parity.
    let mut r = VlqReader::new(&bytes);
    assert_eq!(read_type(&mut r).unwrap(), t);
}

#[test]
fn sfunc_dom_count_above_127_uses_single_count_byte() {
    // SFunc with 200-element domain. read_type recursion depth
    // is fine because each element is a primitive (SInt = 1 byte).
    let t_dom: Vec<SigmaType> = (0..200).map(|_| SigmaType::SInt).collect();
    let t = SigmaType::SFunc {
        t_dom,
        t_range: Box::new(SigmaType::SUnit),
        tpe_params: vec![],
    };
    let bytes = encode(&t);
    assert_eq!(bytes[0], 0x70, "FUNC_CODE = 0x70");
    assert_eq!(
        bytes[1], 0xC8,
        "SFunc dom count must be raw u8 (200=0xC8), not VLQ"
    );
    assert_eq!(bytes[2], 0x04, "byte after count must be first dom type");
    let mut r = VlqReader::new(&bytes);
    assert_eq!(read_type(&mut r).unwrap(), t);
}

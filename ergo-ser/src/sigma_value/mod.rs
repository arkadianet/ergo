//! Sigma value (constant data) wire codecs.
//!
//! `mod.rs` holds the data types ([`SigmaBoolean`], [`AvlTreeData`],
//! [`SigmaValue`], [`CollValue`]) and the central `write_constant` /
//! `read_constant` / `write_value` / `read_value(_at_depth)` dispatch pair
//! — kept whole as one exhaustive match over every [`SigmaValue`] variant.
//! Per-concern codecs live in the submodules: `bigint` (BigInt /
//! UnsignedBigInt), `boxed` (nested `SBox` skip logic — the crate's
//! circular-dependency point back into [`crate::ergo_tree`]),
//! `sigma_boolean` (SigmaBoolean tree), `coll` (collections /
//! bit-packing / Option), and `avl_tree` (AvlTree).

use ergo_primitives::group_element::{read_group_element, GroupElement};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::sigma_type::{read_type, write_type, SigmaType};

mod avl_tree;
mod bigint;
mod boxed;
mod coll;
mod sigma_boolean;

pub use sigma_boolean::write_sigma_boolean;

use avl_tree::{read_avl_tree, write_avl_tree};
use bigint::{
    read_bigint_value, read_unsigned_bigint_value, write_bigint_value, write_unsigned_bigint_value,
};
use boxed::read_opaque_box;
use coll::{read_coll, read_option, write_coll, write_option};
use sigma_boolean::read_sigma_boolean_at_depth;

/// Sigma-protocol boolean proposition tree. Leaves are the cryptographic
/// atoms (`ProveDlog`, `ProveDHTuple`); inner nodes (`Cand`, `Cor`,
/// `Cthreshold`) compose them into the conjunctions / disjunctions /
/// k-of-n thresholds that an [`super::ergo_tree::ErgoTree`] reduces to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigmaBoolean {
    /// Statically-known proposition that always evaluates to the wrapped
    /// boolean — used when reduction collapses the tree to a constant.
    TrivialProp(bool),
    /// "I know the discrete log of `ge`" — the canonical Schnorr-style
    /// proof of knowledge. `ge` is the public key `g^x`.
    ProveDlog(GroupElement),
    /// "I know `x` such that `u = g^x` and `v = h^x`" — Diffie-Hellman
    /// tuple proof of equal exponents.
    ProveDHTuple {
        /// First base.
        g: GroupElement,
        /// Second base.
        h: GroupElement,
        /// `g^x`.
        u: GroupElement,
        /// `h^x`.
        v: GroupElement,
    },
    /// Conjunction — every child must be satisfied.
    Cand(Vec<SigmaBoolean>),
    /// Disjunction — at least one child must be satisfied.
    Cor(Vec<SigmaBoolean>),
    /// `k`-of-n threshold — at least `k` of the `children` must be
    /// satisfied.
    Cthreshold {
        /// Minimum number of satisfied children required.
        k: u8,
        /// Candidate sub-propositions.
        children: Vec<SigmaBoolean>,
    },
}

/// On-chain AVL+ tree handle: the authenticated digest plus the tree's
/// mutability flags and key/value shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvlTreeData {
    /// AVL+ root digest. 33 bytes on the wire / from deserialization
    /// (32-byte digest + 1-byte tree height), but may hold a
    /// variable-length value at runtime after `SAvlTree.updateDigest`
    /// (Scala `CAvlTree.updateDigest` stores the new digest verbatim with
    /// no length check — 3-byte, empty, and over-length digests are all
    /// accepted). Hence `Vec<u8>`, not a fixed `ADDigest`.
    pub digest: Vec<u8>,
    /// Whether new keys may be inserted into the tree.
    pub insert_allowed: bool,
    /// Whether existing values may be updated.
    pub update_allowed: bool,
    /// Whether existing keys may be removed.
    pub remove_allowed: bool,
    /// Required length of every key, in bytes. Signed `i32` to match Scala
    /// `AvlTreeData.keyLength: Int`: the wire reader (`getUInt().toInt`)
    /// wraps a length above `i32::MAX` to a NEGATIVE value rather than
    /// rejecting it — "the deserializer succeeds with invalid AvlTreeData".
    /// A non-positive `keyLength` is invalid metadata (scrypto
    /// `require(keyLength > 0)`), surfaced as a graceful op failure downstream.
    pub key_length: i32,
    /// Optional fixed value length; `None` means values are variable-sized.
    /// Signed `i32` for the same wrapping-on-deserialize reason as
    /// `key_length` (Scala `valueLengthOpt: Option[Int]`).
    pub value_length_opt: Option<i32>,
}

/// A typed sigma value — the runtime form of every constant the wire
/// protocol can carry. The discriminant always matches a [`SigmaType`]
/// variant (`SInt` ↔ `Int`, `SColl(_)` ↔ `Coll`, etc).
#[derive(Debug, Clone, PartialEq)]
pub enum SigmaValue {
    /// The unit value (zero-information).
    Unit,
    /// Boolean.
    Boolean(bool),
    /// Signed 8-bit integer.
    Byte(i8),
    /// UTF-8 string, serialized as VLQ length + raw bytes.
    Str(String),
    /// Signed 16-bit integer.
    Short(i16),
    /// Signed 32-bit integer.
    Int(i32),
    /// Signed 64-bit integer.
    Long(i64),
    /// Arbitrary-precision signed integer.
    BigInt(num_bigint::BigInt),
    /// secp256k1 group element (SEC1-compressed 33 bytes).
    GroupElement(GroupElement),
    /// Sigma-protocol proposition.
    SigmaProp(SigmaBoolean),
    /// AVL+ tree handle.
    AvlTree(AvlTreeData),
    /// Homogeneous collection — see [`CollValue`] for the layout.
    Coll(CollValue),
    /// Optional value.
    Opt(Option<Box<SigmaValue>>),
    /// Heterogeneous tuple.
    Tuple(Vec<SigmaValue>),
    /// Opaque serialized box bytes (used for SBox inline constants).
    /// Preserved verbatim for roundtrip; full structural parsing happens
    /// at the ergo_box layer.
    OpaqueBoxBytes(Vec<u8>),
    /// Block header (`SHeader`) value — the full parsed header. Carries the
    /// same data as the block-header wire format; (de)serialized via
    /// `read_header`/`write_header`. Only reachable on v6 (ErgoTree v3+) trees:
    /// Scala gates `DataSerializer.{de,}serialize(SHeader)` on
    /// `isV3OrLaterErgoTreeVersion`, enforced by the evaluator at the
    /// value-materialization boundary.
    Header(Box<crate::header::Header>),
}

impl SigmaValue {
    /// `true` if an actual `Header` value appears anywhere in this value tree.
    /// Scala gates `SHeader` (de)serialization on `isV3OrLaterErgoTreeVersion`
    /// PER MATERIALIZED VALUE (`DataSerializer.deserialize(SHeader)`), not per
    /// static type — so an EMPTY `Coll[Header]` (which materializes no header)
    /// is NOT gated. Callers gate on this, not on the type containing SHeader.
    pub fn contains_header(&self) -> bool {
        match self {
            SigmaValue::Header(_) => true,
            SigmaValue::Coll(CollValue::Values(vs)) | SigmaValue::Tuple(vs) => {
                vs.iter().any(SigmaValue::contains_header)
            }
            SigmaValue::Opt(Some(inner)) => inner.contains_header(),
            _ => false,
        }
    }

    /// Whether this value materializes an `Option` anywhere within it. Scala
    /// gates `SOption` data (de)serialization on `isV3OrLaterErgoTreeVersion`
    /// (`CoreDataSerializer` → `CheckSerializableTypeCode` throws on
    /// `SOption.OptionTypeCode` pre-v3) — for BOTH `Some` and `None`. So a
    /// materialized `Option` constant (either variant) is rejected on a pre-v3
    /// tree; an empty `Coll[Option[T]]` materializes none and is accepted. Used
    /// by the pre-v3 constant gates alongside [`contains_header`].
    pub fn contains_option(&self) -> bool {
        match self {
            SigmaValue::Opt(_) => true,
            SigmaValue::Coll(CollValue::Values(vs)) | SigmaValue::Tuple(vs) => {
                vs.iter().any(SigmaValue::contains_option)
            }
            _ => false,
        }
    }
}

/// Element-type-specialised collection storage. The bool and byte
/// variants pack their elements densely so the wire form matches Scala's
/// `BoolBits` / `Bytes` specializations; everything else goes through
/// the generic `Values` path.
#[derive(Debug, Clone, PartialEq)]
pub enum CollValue {
    /// `Coll[Boolean]` packed as one bit per element.
    BoolBits(Vec<bool>),
    /// `Coll[Byte]` stored as raw bytes.
    Bytes(Vec<u8>),
    /// Generic collection — one full [`SigmaValue`] per slot.
    Values(Vec<SigmaValue>),
}

// -- Constant (type + value) serialization --

/// Write a Constant: type descriptor followed by value data.
pub fn write_constant(
    w: &mut VlqWriter,
    tpe: &SigmaType,
    val: &SigmaValue,
) -> Result<(), WriteError> {
    write_type(w, tpe)?;
    write_value(w, tpe, val)
}

/// Read a Constant: type descriptor followed by value data.
pub fn read_constant(r: &mut VlqReader) -> Result<(SigmaType, SigmaValue), ReadError> {
    let tpe = read_type(r)?;
    let val = read_value(r, &tpe)?;
    Ok((tpe, val))
}

// -- Value-only serialization --

/// Write value data for a known type. The caller is responsible for ensuring
/// that `val` matches `tpe`.
pub fn write_value(w: &mut VlqWriter, tpe: &SigmaType, val: &SigmaValue) -> Result<(), WriteError> {
    match (tpe, val) {
        (SigmaType::SUnit, SigmaValue::Unit) => {}
        (SigmaType::SFunc { .. }, _) => {
            return Err(WriteError::InvalidData(
                "SFunc value serialization not supported".into(),
            ));
        }
        (SigmaType::SBox, SigmaValue::OpaqueBoxBytes(bytes)) => {
            w.put_bytes(bytes);
        }
        // SHeader: full block-header data format (Scala DataSerializer ->
        // ErgoHeader.sigmaSerializer). The v3+ gate is enforced by the
        // evaluator before this point.
        (SigmaType::SHeader, SigmaValue::Header(h)) => {
            crate::header::write_header(w, h)?;
        }
        (SigmaType::SString, SigmaValue::Str(s)) => {
            w.put_u32(s.len() as u32);
            w.put_bytes(s.as_bytes());
        }
        (SigmaType::SUnsignedBigInt, SigmaValue::BigInt(v)) => {
            write_unsigned_bigint_value(w, v)?;
        }
        (SigmaType::SReserved10, _) | (SigmaType::SReserved11, _) => {
            return Err(WriteError::InvalidData(
                "reserved type value serialization not supported".into(),
            ));
        }
        (SigmaType::SBoolean, SigmaValue::Boolean(b)) => {
            w.put_u8(if *b { 0x01 } else { 0x00 });
        }
        (SigmaType::SByte, SigmaValue::Byte(v)) => {
            w.put_u8(*v as u8);
        }
        (SigmaType::SShort, SigmaValue::Short(v)) => {
            w.put_i32(*v as i32);
        }
        (SigmaType::SInt, SigmaValue::Int(v)) => {
            w.put_i32(*v);
        }
        (SigmaType::SLong, SigmaValue::Long(v)) => {
            w.put_i64(*v);
        }
        (SigmaType::SBigInt, SigmaValue::BigInt(v)) => {
            write_bigint_value(w, v)?;
        }
        (SigmaType::SGroupElement, SigmaValue::GroupElement(ge)) => {
            w.put_bytes(ge.as_bytes());
        }
        (SigmaType::SSigmaProp, SigmaValue::SigmaProp(sb)) => {
            write_sigma_boolean(w, sb);
        }
        (SigmaType::SAvlTree, SigmaValue::AvlTree(avl)) => {
            write_avl_tree(w, avl);
        }
        (SigmaType::SColl(elem_type), SigmaValue::Coll(coll)) => {
            write_coll(w, elem_type, coll)?;
        }
        (SigmaType::SOption(elem_type), SigmaValue::Opt(opt)) => {
            write_option(w, elem_type, opt)?;
        }
        (SigmaType::STuple(elem_types), SigmaValue::Tuple(vals)) => {
            if elem_types.len() != vals.len() {
                return Err(WriteError::InvalidData(format!(
                    "tuple arity mismatch: type has {} element(s), value has {}",
                    elem_types.len(),
                    vals.len()
                )));
            }
            for (t, v) in elem_types.iter().zip(vals.iter()) {
                write_value(w, t, v)?;
            }
        }
        _ => {
            return Err(WriteError::InvalidData(format!(
                "type/value mismatch: type={tpe:?}, value discriminant does not match"
            )));
        }
    }
    Ok(())
}

/// Read value data for a known type.
pub fn read_value(r: &mut VlqReader, tpe: &SigmaType) -> Result<SigmaValue, ReadError> {
    read_value_at_depth(r, tpe, 0)
}

/// Depth-threaded [`read_value`]. `depth` is the shared reader-level budget
/// (Scala `CoreByteReader.level`): it is carried in from `parse_expr` so a
/// `SigmaProp` constant nested inside a deep ErgoTree expression continues the
/// SAME MaxTreeDepth (110) budget rather than restarting at 0. Composite values
/// (Coll/Option/Tuple elements) recurse at `depth + 1`, mirroring Scala's
/// per-nested-value level increment.
pub(crate) fn read_value_at_depth(
    r: &mut VlqReader,
    tpe: &SigmaType,
    depth: usize,
) -> Result<SigmaValue, ReadError> {
    match tpe {
        SigmaType::SBoolean => {
            let b = r.get_u8()?;
            Ok(SigmaValue::Boolean(b != 0))
        }
        SigmaType::SByte => {
            let b = r.get_u8()?;
            Ok(SigmaValue::Byte(b as i8))
        }
        SigmaType::SShort => {
            let v = r.get_i32()?;
            Ok(SigmaValue::Short(v as i16))
        }
        SigmaType::SInt => {
            let v = r.get_i32()?;
            Ok(SigmaValue::Int(v))
        }
        SigmaType::SLong => {
            let v = r.get_i64()?;
            Ok(SigmaValue::Long(v))
        }
        SigmaType::SBigInt => {
            let v = read_bigint_value(r)?;
            Ok(SigmaValue::BigInt(v))
        }
        SigmaType::SGroupElement => Ok(SigmaValue::GroupElement(read_group_element(r)?)),
        SigmaType::SSigmaProp => {
            // Continue the shared depth budget into the SigmaBoolean tree.
            let sb = read_sigma_boolean_at_depth(r, depth)?;
            Ok(SigmaValue::SigmaProp(sb))
        }
        SigmaType::SAvlTree => {
            let avl = read_avl_tree(r)?;
            Ok(SigmaValue::AvlTree(avl))
        }
        SigmaType::SColl(elem_type) => {
            let coll = read_coll(r, elem_type, depth)?;
            Ok(SigmaValue::Coll(coll))
        }
        SigmaType::SOption(elem_type) => {
            let opt = read_option(r, elem_type, depth)?;
            Ok(SigmaValue::Opt(opt))
        }
        SigmaType::STuple(elem_types) => {
            let mut vals = Vec::with_capacity(elem_types.len());
            for t in elem_types {
                vals.push(read_value_at_depth(r, t, depth + 1)?);
            }
            Ok(SigmaValue::Tuple(vals))
        }
        SigmaType::SUnit => Ok(SigmaValue::Unit),
        SigmaType::SString => {
            let len = r.get_u32_exact()? as usize;
            if len > 4096 {
                return Err(ReadError::InvalidData(format!(
                    "SString value too long: {len}"
                )));
            }
            let bytes = r.get_bytes(len)?;
            // Scala CoreDataSerializer.scala:104-110 decodes SString values
            // with `new String(bytes, UTF_8)` (lossy). The decoded value is
            // EQ-compared and length-costed at eval, so it must match the JVM
            // codepoint for codepoint — a strict `from_utf8` would both
            // reject Scala-accepted values AND, if relaxed naively, diverge on
            // the replacement count. See [`crate::jvm_utf8`].
            Ok(SigmaValue::Str(crate::jvm_utf8::decode(bytes)))
        }
        SigmaType::SUnsignedBigInt => {
            let v = read_unsigned_bigint_value(r)?;
            Ok(SigmaValue::BigInt(v))
        }
        SigmaType::SBox => read_opaque_box(r),
        // SHeader: full block-header data format (Scala DataSerializer ->
        // ErgoHeader.sigmaSerializer.parse). This decoder is version-agnostic;
        // the v3+ (isV3OrLaterErgoTreeVersion) gate is applied by the callers
        // that have the ErgoTree version (the evaluator's value-materialization
        // boundary and the tree-constant parser), NOT here, so a stray
        // pre-v3 SHeader constant cannot slip through ungated.
        SigmaType::SHeader => Ok(SigmaValue::Header(Box::new(crate::header::read_header(r)?))),
        SigmaType::SFunc { .. } => Err(ReadError::InvalidData(
            "SFunc value deserialization is not supported".into(),
        )),
        SigmaType::SReserved10 | SigmaType::SReserved11 => Err(ReadError::InvalidData(format!(
            "reserved type value deserialization not supported: {tpe:?}"
        ))),
        SigmaType::SAny
        | SigmaType::SContext
        | SigmaType::SPreHeader
        | SigmaType::SGlobal
        | SigmaType::STypeVar(_) => Err(ReadError::InvalidData(format!(
            "value deserialization not supported for {tpe:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    // ----- helpers -----

    fn roundtrip_value(tpe: &SigmaType, val: &SigmaValue) {
        let mut w = VlqWriter::new();
        write_value(&mut w, tpe, val).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_value(&mut r, tpe).unwrap();
        assert!(r.is_empty(), "leftover bytes for {tpe:?}");
        assert_eq!(&decoded, val);
    }

    fn roundtrip_constant(tpe: &SigmaType, val: &SigmaValue) {
        let mut w = VlqWriter::new();
        write_constant(&mut w, tpe, val).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let (dec_tpe, dec_val) = read_constant(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes for constant {tpe:?}");
        assert_eq!(&dec_tpe, tpe);
        assert_eq!(&dec_val, val);
    }

    // -- Helper: fake group element --
    fn fake_ge(prefix: u8) -> GroupElement {
        let mut bytes = [prefix; 33];
        bytes[0] = 0x02; // valid SEC1 compressed prefix
        GroupElement::from_bytes(bytes)
    }

    // ===== 1. Primitive roundtrips =====

    // ----- round-trips -----

    #[test]
    fn roundtrip_boolean() {
        roundtrip_value(&SigmaType::SBoolean, &SigmaValue::Boolean(true));
        roundtrip_value(&SigmaType::SBoolean, &SigmaValue::Boolean(false));
    }

    #[test]
    fn roundtrip_byte() {
        roundtrip_value(&SigmaType::SByte, &SigmaValue::Byte(0));
        roundtrip_value(&SigmaType::SByte, &SigmaValue::Byte(127));
        roundtrip_value(&SigmaType::SByte, &SigmaValue::Byte(-128));
    }

    #[test]
    fn roundtrip_short() {
        roundtrip_value(&SigmaType::SShort, &SigmaValue::Short(0));
        roundtrip_value(&SigmaType::SShort, &SigmaValue::Short(1234));
        roundtrip_value(&SigmaType::SShort, &SigmaValue::Short(-1234));
        roundtrip_value(&SigmaType::SShort, &SigmaValue::Short(i16::MAX));
        roundtrip_value(&SigmaType::SShort, &SigmaValue::Short(i16::MIN));
    }

    #[test]
    fn roundtrip_int() {
        roundtrip_value(&SigmaType::SInt, &SigmaValue::Int(0));
        roundtrip_value(&SigmaType::SInt, &SigmaValue::Int(i32::MAX));
        roundtrip_value(&SigmaType::SInt, &SigmaValue::Int(i32::MIN));
        roundtrip_value(&SigmaType::SInt, &SigmaValue::Int(-42));
    }

    #[test]
    fn roundtrip_long() {
        roundtrip_value(&SigmaType::SLong, &SigmaValue::Long(0));
        roundtrip_value(&SigmaType::SLong, &SigmaValue::Long(i64::MAX));
        roundtrip_value(&SigmaType::SLong, &SigmaValue::Long(i64::MIN));
        roundtrip_value(&SigmaType::SLong, &SigmaValue::Long(-999_999));
    }

    #[test]
    fn roundtrip_group_element() {
        roundtrip_value(
            &SigmaType::SGroupElement,
            &SigmaValue::GroupElement(fake_ge(0xAA)),
        );
    }

    #[test]
    fn roundtrip_tuple_int_long() {
        let tpe = SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]);
        let val = SigmaValue::Tuple(vec![SigmaValue::Int(42), SigmaValue::Long(-1)]);
        roundtrip_value(&tpe, &val);
    }

    #[test]
    fn write_value_tuple_arity_mismatch_errors_without_writing() {
        // Type declares a 3-tuple but the value carries 2 elements. A
        // bare `zip` would silently truncate to the shorter side and
        // emit a malformed 2-element encoding; the arity guard must
        // reject it, and reject it before writing any bytes.
        let tpe = SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong, SigmaType::SByte]);
        let val = SigmaValue::Tuple(vec![SigmaValue::Int(1), SigmaValue::Long(2)]);
        let mut w = VlqWriter::new();
        let err = write_value(&mut w, &tpe, &val).unwrap_err();
        assert!(
            matches!(err, WriteError::InvalidData(_)),
            "expected InvalidData, got {err:?}"
        );
        assert!(
            w.result().is_empty(),
            "guard must reject before writing any bytes"
        );
    }

    // ===== 6. Constant roundtrips =====

    #[test]
    fn constant_roundtrip_int() {
        roundtrip_constant(&SigmaType::SInt, &SigmaValue::Int(12345));
    }

    #[test]
    fn constant_roundtrip_coll_byte() {
        let tpe = SigmaType::SColl(Box::new(SigmaType::SByte));
        let val = SigmaValue::Coll(CollValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        roundtrip_constant(&tpe, &val);
    }

    #[test]
    fn constant_roundtrip_sigma_prop() {
        let tpe = SigmaType::SSigmaProp;
        let val = SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(fake_ge(0x55)));
        roundtrip_constant(&tpe, &val);
    }

    #[test]
    fn constant_roundtrip_option_long() {
        let tpe = SigmaType::SOption(Box::new(SigmaType::SLong));
        let val = SigmaValue::Opt(Some(Box::new(SigmaValue::Long(i64::MAX))));
        roundtrip_constant(&tpe, &val);
    }

    #[test]
    fn constant_roundtrip_tuple() {
        let tpe = SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SLong]);
        let val = SigmaValue::Tuple(vec![SigmaValue::Int(-1), SigmaValue::Long(999)]);
        roundtrip_constant(&tpe, &val);
    }

    #[test]
    fn constant_roundtrip_avl_tree() {
        let tpe = SigmaType::SAvlTree;
        let avl = AvlTreeData {
            digest: vec![0x01; 33],
            insert_allowed: true,
            update_allowed: true,
            remove_allowed: true,
            key_length: 32,
            value_length_opt: Some(256),
        };
        roundtrip_constant(&tpe, &SigmaValue::AvlTree(avl));
    }

    #[test]
    fn constant_roundtrip_bigint() {
        let tpe = SigmaType::SBigInt;
        let big = BigInt::parse_bytes(b"-99999999999999999999", 10).unwrap();
        roundtrip_constant(&tpe, &SigmaValue::BigInt(big));
    }

    #[test]
    fn constant_roundtrip_coll_boolean() {
        let tpe = SigmaType::SColl(Box::new(SigmaType::SBoolean));
        let val = SigmaValue::Coll(CollValue::BoolBits(vec![true, false, true]));
        roundtrip_constant(&tpe, &val);
    }

    // ----- oracle parity (golden byte tests for specific encodings) -----

    /// SString values with ill-formed UTF-8 must decode like the Scala node's
    /// `new String(bytes, UTF_8)` (CoreDataSerializer.scala:104-110) — lossy,
    /// not a strict `from_utf8` reject. The decoded value is EQ-compared at
    /// eval, so it must match the JVM codepoint for codepoint. Expected
    /// strings are the JVM (Corretto 17) decode of each byte sequence; the
    /// surrogate case `ed a0 80` is the JVM/Rust-lossy divergence (1 vs 3
    /// U+FFFD) that pins why `jvm_utf8::decode` is required here.
    #[test]
    fn sstring_value_illformed_utf8_decodes_like_jvm() {
        for (name_bytes, expected) in [
            (vec![0xffu8], "\u{FFFD}"),
            (vec![0xed, 0xa0, 0x80], "\u{FFFD}"),
            (vec![0xc0, 0x80], "\u{FFFD}\u{FFFD}"),
            (vec![0x61, 0xff, 0x62], "a\u{FFFD}b"),
        ] {
            let mut w = VlqWriter::new();
            w.put_u32(name_bytes.len() as u32);
            w.put_bytes(&name_bytes);
            let data = w.result();
            let mut r = VlqReader::new(&data);
            let v = read_value(&mut r, &SigmaType::SString)
                .unwrap_or_else(|e| panic!("expected lossy accept for {name_bytes:?}, got {e:?}"));
            assert_eq!(
                v,
                SigmaValue::Str(expected.to_string()),
                "for {name_bytes:?}"
            );
        }
    }

    #[test]
    fn golden_boolean_bytes() {
        let mut w = VlqWriter::new();
        write_value(&mut w, &SigmaType::SBoolean, &SigmaValue::Boolean(true)).unwrap();
        assert_eq!(w.result(), [0x01]);

        let mut w = VlqWriter::new();
        write_value(&mut w, &SigmaType::SBoolean, &SigmaValue::Boolean(false)).unwrap();
        assert_eq!(w.result(), [0x00]);
    }

    #[test]
    fn golden_byte_value() {
        let mut w = VlqWriter::new();
        write_value(&mut w, &SigmaType::SByte, &SigmaValue::Byte(-1)).unwrap();
        assert_eq!(w.result(), [0xFF]); // -1 as u8
    }
}

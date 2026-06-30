use ergo_primitives::group_element::{read_group_element, GroupElement};
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;
use crate::sigma_type::{read_type, write_type, SigmaType};

// SigmaPropCodes from sigmastate-interpreter (SigmaPropCodes.scala).
// Computed as LastConstantCode(0x70) + shift.
const PROVE_DLOG: u8 = 0xCD; // 0x70 + 93
const PROVE_DHTUPLE: u8 = 0xCE; // 0x70 + 94
const SIGMA_AND: u8 = 0x96; // 0x70 + 38
const SIGMA_OR: u8 = 0x97; // 0x70 + 39
const SIGMA_THRESHOLD: u8 = 0x98; // 0x70 + 40
const TRIVIAL_PROP_FALSE: u8 = 0xD2; // 0x70 + 98
const TRIVIAL_PROP_TRUE: u8 = 0xD3; // 0x70 + 99

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

// -- BigInt (DataSerializer convention: u16 length prefix) --

fn write_bigint_value(w: &mut VlqWriter, value: &num_bigint::BigInt) -> Result<(), WriteError> {
    let bytes = value.to_signed_bytes_be();
    // Scala DataSerializer encodes BigInt as `putUShort(len) + bytes`,
    // gated by `MaxBigIntSizeInBytes = 32` at CoreDataSerializer.
    // Writing a value that needs >32 signed bytes (e.g., +2^255 needs
    // 33 bytes because the sign bit forces a leading 0x00) would
    // produce wire bytes Scala rejects on read — emit-side parity
    // requires the same cap as the reader. Returning a typed error
    // beats the previous `assert!` which panicked above u16::MAX
    // (and silently accepted 33..65535).
    if bytes.len() > BIGINT_VALUE_MAX_BYTES {
        return Err(WriteError::InvalidData(format!(
            "SBigInt value too long: {} bytes (max {BIGINT_VALUE_MAX_BYTES})",
            bytes.len(),
        )));
    }
    w.put_u16(bytes.len() as u16);
    w.put_bytes(&bytes);
    Ok(())
}

fn read_bigint_value(r: &mut VlqReader) -> Result<num_bigint::BigInt, ReadError> {
    let len = r.get_u16()? as usize;
    if len == 0 {
        return Ok(num_bigint::BigInt::from(0));
    }
    // Mirrors `read_unsigned_bigint_value`'s gate at the same const.
    // Scala's `CoreDataSerializer.deserializeBigInt` rejects `len > 32`.
    // The cap fires BEFORE `get_bytes(len)` so a hostile `len=65535`
    // payload can't trigger a 65 KiB allocation before reading any
    // bytes.
    if len > BIGINT_VALUE_MAX_BYTES {
        return Err(ReadError::InvalidData(format!(
            "SBigInt value too long: {len} bytes (max {BIGINT_VALUE_MAX_BYTES})",
        )));
    }
    let bytes = r.get_bytes(len)?;
    Ok(num_bigint::BigInt::from_signed_bytes_be(bytes))
}

/// Per-spec maximum byte length for `SBigInt` and `SUnsignedBigInt`
/// on-wire values. Mirrors Scala's `CoreDataSerializer`
/// `MaxBigIntSizeInBytes = 32` (256 bits unsigned, or signed in range
/// `[-2^255, 2^255)`). Note the asymmetry: the signed encoding of
/// `+2^255` requires 33 bytes (a leading 0x00 to keep the sign bit
/// clear), so this cap rejects positive `2^255` and accepts negative
/// `-2^255` — matching Scala.
const BIGINT_VALUE_MAX_BYTES: usize = 32;

/// `SUnsignedBigInt` wire reader. Mirrors Scala's
/// `CoreDataSerializer.scala:36` which uses
/// `BigIntegers.fromUnsignedByteArray` — bytes are interpreted as a
/// non-negative big-endian magnitude with no sign bit.
///
/// Distinct from [`read_bigint_value`] (signed two's-complement) so
/// values with the top bit set decode as the intended positive
/// integer rather than as a negative number with magnitude
/// `2^(8·len) - value`. Length is range-checked to
/// [`BIGINT_VALUE_MAX_BYTES`] so a malformed wire payload can't
/// expand the unsigned value past Scala's 256-bit bound.
fn read_unsigned_bigint_value(r: &mut VlqReader) -> Result<num_bigint::BigInt, ReadError> {
    let len = r.get_u16()? as usize;
    if len == 0 {
        return Ok(num_bigint::BigInt::from(0));
    }
    if len > BIGINT_VALUE_MAX_BYTES {
        return Err(ReadError::InvalidData(format!(
            "SUnsignedBigInt value too long: {len} bytes (max {BIGINT_VALUE_MAX_BYTES})",
        )));
    }
    let bytes = r.get_bytes(len)?;
    Ok(num_bigint::BigInt::from_bytes_be(
        num_bigint::Sign::Plus,
        bytes,
    ))
}

/// `SUnsignedBigInt` wire writer — round-trip counterpart to
/// [`read_unsigned_bigint_value`]. Emits unsigned magnitude bytes
/// with no leading sign-extension zero byte; Scala's
/// `BigIntegers.asUnsignedByteArray` does the same.
///
/// Refuses negative values up front. A negative `SUnsignedBigInt`
/// is a caller bug (type-system invariant violated) — the alternative
/// would be silently treating it as `value + 2^256`, which would
/// re-introduce the very class of bug the unsigned decoder fixes.
fn write_unsigned_bigint_value(
    w: &mut VlqWriter,
    value: &num_bigint::BigInt,
) -> Result<(), WriteError> {
    if value.sign() == num_bigint::Sign::Minus {
        return Err(WriteError::InvalidData(format!(
            "SUnsignedBigInt cannot serialize a negative value: {value}",
        )));
    }
    let (_sign, bytes) = value.to_bytes_be();
    // `to_bytes_be` for zero returns `[0]` (one byte), but the wire
    // format encodes zero as `len=0` with no payload — matches the
    // reader's early-return for `len == 0`.
    let bytes: &[u8] = if value.sign() == num_bigint::Sign::NoSign {
        &[]
    } else {
        &bytes
    };
    if bytes.len() > BIGINT_VALUE_MAX_BYTES {
        return Err(WriteError::InvalidData(format!(
            "SUnsignedBigInt value too long: {} bytes (max {BIGINT_VALUE_MAX_BYTES})",
            bytes.len(),
        )));
    }
    w.put_u16(bytes.len() as u16);
    w.put_bytes(bytes);
    Ok(())
}

/// Skip past an ErgoTree in the reader without fully parsing the body.
///
/// For size-delimited trees: reads header + size + body_bytes (skips body).
/// For non-size-delimited trees: reads header + constants (if cseg) +
///   falls back to the full opcode parser for the body.
/// Parse a SIZELESS nested box script's constants + body to find the box-field
/// boundary, and apply the v6/EIP-50 pre-v3 method gate. Returns SOFT errors
/// (`InvalidData`) — the caller (`skip_ergo_tree`) hardens them via
/// [`harden_sizeless_inner_error`], because for a sizeless inner tree Scala
/// re-raises any inner `ValidationException` as a `SerializerException`. The
/// rule-1012 / `version != 0` check is done by the caller BEFORE this (Scala
/// runs `CheckHeaderSizeBit` ahead of constants, outside the inner `try`).
fn parse_sizeless_inner_box_script(
    r: &mut VlqReader,
    version: u8,
    cseg: bool,
) -> Result<(), ReadError> {
    // A nested box-constant script is its OWN deserialization scope, parsed on the
    // SAME reader as the enclosing tree, so two pieces of version-scoped reader state
    // are saved/set/restored around the ENTIRE inner parse — segregated constants AND
    // body — so the inner tree uses ITS OWN header version, not the outer's:
    //  - `ergo_tree_version`: the embeddable type-code gate must resolve against the
    //    inner version (a sizeless inner is v0). An `SUnsignedBigInt` (code 9) type in
    //    a v0 script nested under a v3+ outer tree must reject, whether it appears in a
    //    segregated constant or the body; without scoping it inherits the outer
    //    `Some(3)` and is accepted — accept-invalid. It is therefore set BEFORE the
    //    constants are read. (The has_size nested path recurses through
    //    `read_ergo_tree_tracking_wrap`, which scopes its own inner reader.)
    //  - the unresolved-method checkpoint: an unresolved method inside the inner tree
    //    is hard-rejected here (Scala re-raises the sizeless `ValidationException` as a
    //    `SerializerException`), NOT folded into the enclosing size-delimited tree's
    //    wrap, so it must not mark the OUTER reader's checkpoint.
    let saved_checkpoint = r.unresolved_method_checkpoint();
    let saved_version = r.ergo_tree_version();
    r.set_ergo_tree_version(Some(version));
    let result = parse_sizeless_inner_box_script_scoped(r, version, cseg);
    r.set_ergo_tree_version(saved_version);
    r.restore_unresolved_method_checkpoint(saved_checkpoint);
    result
}

/// Inner of [`parse_sizeless_inner_box_script`], run with the reader's
/// `ergo_tree_version` already set to the inner tree's version so the embeddable
/// type gate applies to the segregated constants and the body alike.
fn parse_sizeless_inner_box_script_scoped(
    r: &mut VlqReader,
    version: u8,
    cseg: bool,
) -> Result<(), ReadError> {
    let mut constants = Vec::new();
    if cseg {
        // Nested-tree `deserializeConstants` reads the count via `getUInt().toInt`
        // (non-exact), same as the top-level tree: an overflowed count wraps
        // negative and yields ZERO constants in Scala, not a hard rejection.
        let count = r.get_uint_to_i32()?.max(0) as usize;
        if count > 4096 {
            return Err(ReadError::InvalidData(format!(
                "unreasonable constant count in inner tree: {count}"
            )));
        }
        constants.reserve(count.min(4096));
        for _ in 0..count {
            constants.push(read_constant(r)?);
        }
    }
    let body = crate::opcode::parse_body(r, version)?;
    // Sizeless inner tree => version 0 (the caller ran rule 1012 first), so methods
    // resolve against the v5 registry; a v6-only OR genuinely-unknown id makes Scala
    // throw a method-resolution `ValidationException`, hardened by the caller.
    if let Some((type_id, method_id)) = crate::opcode::find_unresolved_v5_method(&body) {
        return Err(ReadError::InvalidData(format!(
            "nested box script: method ({type_id}, {method_id}) does not resolve in the v5 registry for tree version {version}"
        )));
    }
    // CheckDeserializedScriptIsSigmaProp (rule 1001): the inner box script is
    // deserialized with `checkType = true` too, so a determinable non-SigmaProp
    // root (bare Boolean/Long `Const`, `TrueLeaf`/`FalseLeaf`, or a placeholder
    // resolving to one) is a sizeless `ValidationException` Scala re-raises as a
    // `SerializerException` — hardened by the caller. Mirrors the box-reader
    // `check_sigma_prop_root` gate for the top-level tree.
    if let Some(tpe) = crate::ergo_tree::determinable_root_type_of(&body, &constants) {
        if tpe != crate::sigma_type::SigmaType::SSigmaProp {
            return Err(ReadError::InvalidData(format!(
                "nested box script: sizeless root has type {tpe:?}, expected SigmaProp (CheckDeserializedScriptIsSigmaProp, rule 1001)"
            )));
        }
    }
    Ok(())
}

/// Harden a sizeless inner box-script parse failure to [`ReadError::HardReject`]
/// (a Scala `SerializerException`), so an enclosing SIZE-DELIMITED outer tree
/// re-raises it rather than soft-fork-wrapping it into an `UnparsedErgoTree`.
/// Already-hard errors (`DepthLimitExceeded`, nested `HardReject`) pass through.
fn harden_sizeless_inner_error(e: ReadError) -> ReadError {
    match e {
        e @ (ReadError::DepthLimitExceeded { .. } | ReadError::HardReject(_)) => e,
        other => ReadError::HardReject(format!("nested sizeless box script: {other}")),
    }
}

fn skip_ergo_tree(r: &mut VlqReader) -> Result<(), ReadError> {
    let tree_start = r.position();
    let header = r.get_u8()?;
    let version = header & 0x07;
    let has_size = header & 0x08 != 0;
    let cseg = header & 0x10 != 0;

    if has_size {
        // Size-delimited: Scala deserializes the nested box's proposition INLINE via
        // `ErgoTreeSerializer.deserializeErgoTree`, which is structure-delimited —
        // the declared size does NOT bound the parse or advance the reader on
        // success (it leaves the reader at the actual body end, where the box's
        // next field is read). Rewind to before the header and delegate to
        // `read_ergo_tree_tracking_wrap`, which (since #123) advances `r` by the
        // true body length on success or to Scala's `numBytes` boundary on a wrap,
        // forwards the inner tree's group elements onto `r` (the JVM curve-checks an
        // off-curve point inside a nested box while deserializing it), and re-raises
        // `DepthLimitExceeded` / `HardReject` so they escape the enclosing tree's
        // soft-fork wrap. The box stays opaque for round-trip fidelity via the
        // caller's preserved bytes; only the reader advance moves here. (The old
        // `get_bytes(size)` skip desynced the box tail when size != body length.)
        r.set_position(tree_start);
        let (sub_tree, _) = crate::ergo_tree::read_ergo_tree_tracking_wrap(r)?;
        // A future-version inner tree is HARD-rejected (Scala's
        // `VersionContext.withVersions` throws a `SerializerException` the enclosing
        // tree does not catch). `read_ergo_tree` wrapped it leniently; reject here —
        // UNLESS the reader is decoding a TRUSTED, already-validated stored box
        // (`VlqReader::trusted`), where a legacy high-version opaque NESTED tree
        // must round-trip exactly like the top-level case (the indexer re-reading
        // its own `INDEXED_BOX` rows). The structural parse above already advanced
        // the reader, so only the acceptance check is skipped.
        if !r.is_trusted() {
            crate::ergo_tree::check_tree_version_supported(&sub_tree)?;
        }
    } else {
        // SIZELESS nested box script (an `SBox` constant's inner ErgoTree). This
        // mirrors Scala `deserializeErgoTree` for `sizeOpt = None`, where the
        // exception CLASS decides whether an enclosing SIZE-DELIMITED outer tree
        // wraps the failure (`UnparsedErgoTree`) or is rejected by it:
        //
        // - `CheckHeaderSizeBit` (rule 1012, `version != 0`) runs in
        //   `deserializeHeaderAndSize`, BEFORE constants/body and OUTSIDE the
        //   inner `try` — so it is a `ValidationException` the OUTER tree's catch
        //   WRAPS. It is checked FIRST (before any constant is read) and kept
        //   SOFT (`InvalidData`): a size-delimited outer wraps it; a sizeless
        //   outer / register / standalone read rejects.
        // - Everything else (constants, body, and the v6/EIP-50 method check) is
        //   INSIDE Scala's inner `try`. For `sizeOpt = None`, EVERY
        //   `ValidationException` thrown there is re-raised as a hard
        //   `SerializerException`, which the outer catch does NOT catch — so all
        //   soft failures of the inner parse are hardened to `HardReject`
        //   (already-hard `DepthLimitExceeded` / nested `HardReject` pass
        //   through). A size-delimited outer must reject, not wrap.
        //
        // Size-delimited nested trees are kept opaque above — Scala wraps an
        // inner failure as `UnparsedErgoTree`, rejected only on spend, which the
        // evaluator's spend-path gate handles.
        if version != 0 && !r.is_trusted() {
            return Err(ReadError::InvalidData(format!(
                "nested box script: ErgoTree version {version} requires the size bit (CheckHeaderSizeBit, rule 1012)"
            )));
        }
        parse_sizeless_inner_box_script(r, version, cseg).map_err(harden_sizeless_inner_error)?;
    }
    Ok(())
}

/// Maximum serialized box size (`SigmaConstants.MaxBoxSize = 4 * 1024`). Scala's
/// `ErgoBoxCandidate.parseBodyWithIndexedDigests` bounds the candidate body to
/// `position + MaxBoxSize` via the reader's position limit.
const MAX_BOX_SIZE: usize = 4 * 1024;

/// Read an inline SBox constant by structurally advancing through the box
/// fields, then capturing the raw bytes as opaque data for roundtrip fidelity.
///
/// The candidate body (value..registers) is bounded to `start + MaxBoxSize`
/// exactly as Scala's `parseBodyWithIndexedDigests` sets `positionLimit`: a read
/// that BEGINS past the window trips `CheckPositionLimit` (rule 1014) and the box
/// parse errors — so e.g. `deserializeTo[Box]` of an over-large token list is
/// rejected. The limit is restored before the ref tail (txId + index), which
/// Scala reads after `positionLimit` is reset, so the tail is unbounded.
fn read_opaque_box(r: &mut VlqReader) -> Result<SigmaValue, ReadError> {
    let start = r.position();

    let previous_limit = r.position_limit();
    r.set_position_limit(Some(start + MAX_BOX_SIZE));
    let body = (|| {
        // value (nanoErgs) - VLQ u64
        let _ = r.get_u64()?;
        // ergo tree - skip past without full body parse (for size-delimited trees)
        skip_ergo_tree(r)?;
        // creation height - VLQ u32
        let _ = r.get_u32_exact()?;
        // token count + tokens (full 32-byte token IDs for inline constants)
        let tc = r.get_u8()? as usize;
        for _ in 0..tc {
            let _ = r.get_bytes(32)?; // token id
            let _ = r.get_u64()?; // amount
        }
        // additional registers
        let _ = crate::register::read_registers(r)?;
        Ok::<(), ReadError>(())
    })();
    // Restore on both the success and error paths (Scala previousPositionLimit).
    r.set_position_limit(previous_limit);
    body?;

    // transaction id (32 bytes) + output index (VLQ u16) — outside the window.
    let _ = r.get_bytes(32)?;
    let _ = r.get_u16()?;

    let end = r.position();
    let raw = r.data_slice(start, end).to_vec();
    Ok(SigmaValue::OpaqueBoxBytes(raw))
}

// -- SigmaBoolean tree serialization --

/// Serialize a [`SigmaBoolean`] tree using the Scala
/// `SigmaBooleanSerializer` tag layout: a one-byte node tag (`0xCD`
/// ProveDlog, `0xCE` ProveDHTuple, `0x96` Cand, `0x97` Cor, `0x98`
/// Cthreshold, `0xD2`/`0xD3` trivial false/true) followed by the
/// node-specific payload.
pub fn write_sigma_boolean(w: &mut VlqWriter, sb: &SigmaBoolean) {
    match sb {
        SigmaBoolean::TrivialProp(false) => w.put_u8(TRIVIAL_PROP_FALSE),
        SigmaBoolean::TrivialProp(true) => w.put_u8(TRIVIAL_PROP_TRUE),
        SigmaBoolean::ProveDlog(ge) => {
            w.put_u8(PROVE_DLOG);
            w.put_bytes(ge.as_bytes());
        }
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            w.put_u8(PROVE_DHTUPLE);
            w.put_bytes(g.as_bytes());
            w.put_bytes(h.as_bytes());
            w.put_bytes(u.as_bytes());
            w.put_bytes(v.as_bytes());
        }
        SigmaBoolean::Cand(children) => {
            assert!(
                children.len() <= u16::MAX as usize,
                "Cand children count too large for Scala wire format: {} (max 65535)",
                children.len()
            );
            w.put_u8(SIGMA_AND);
            w.put_u16(children.len() as u16);
            for child in children {
                write_sigma_boolean(w, child);
            }
        }
        SigmaBoolean::Cor(children) => {
            assert!(
                children.len() <= u16::MAX as usize,
                "Cor children count too large for Scala wire format: {} (max 65535)",
                children.len()
            );
            w.put_u8(SIGMA_OR);
            w.put_u16(children.len() as u16);
            for child in children {
                write_sigma_boolean(w, child);
            }
        }
        SigmaBoolean::Cthreshold { k, children } => {
            assert!(
                children.len() <= u16::MAX as usize,
                "Cthreshold children count too large for Scala wire format: {} (max 65535)",
                children.len()
            );
            w.put_u8(SIGMA_THRESHOLD);
            w.put_u16(*k as u16);
            w.put_u16(children.len() as u16);
            for child in children {
                write_sigma_boolean(w, child);
            }
        }
    }
}

/// Scala bounds nested value/`SigmaBoolean` deserialization at
/// `SigmaConstants.MaxTreeDepth` (= 110) via the shared reader level
/// (`CoreByteReader`); past it `DeserializeCallDepthExceeded` is thrown. Mirror
/// that bound here so a deeply nested `Cand`/`Cor`/`Cthreshold` chain from peer
/// data (a box register or context-extension `SigmaProp` constant) is rejected
/// rather than overflowing the worker-thread stack.
const MAX_SIGMA_TREE_DEPTH: usize = 110;

fn read_sigma_boolean_at_depth(r: &mut VlqReader, depth: usize) -> Result<SigmaBoolean, ReadError> {
    // `>=`: depth is 0-based (root enters at 0) while Scala increments the
    // shared reader level BEFORE parsing each nested node, so Rust `depth` ==
    // Scala `level - 1`; `depth >= MAX` matches Scala's `level > MaxTreeDepth`.
    if depth >= MAX_SIGMA_TREE_DEPTH {
        return Err(ReadError::DepthLimitExceeded {
            max: MAX_SIGMA_TREE_DEPTH,
        });
    }
    let tag = r.get_u8()?;
    let next = depth + 1;
    match tag {
        TRIVIAL_PROP_FALSE => Ok(SigmaBoolean::TrivialProp(false)),
        TRIVIAL_PROP_TRUE => Ok(SigmaBoolean::TrivialProp(true)),
        PROVE_DLOG => Ok(SigmaBoolean::ProveDlog(read_group_element(r)?)),
        PROVE_DHTUPLE => {
            let g = read_group_element(r)?;
            let h = read_group_element(r)?;
            let u = read_group_element(r)?;
            let v = read_group_element(r)?;
            Ok(SigmaBoolean::ProveDHTuple { g, h, u, v })
        }
        SIGMA_AND => {
            let count = r.get_u16()? as usize;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(read_sigma_boolean_at_depth(r, next)?);
            }
            Ok(SigmaBoolean::Cand(children))
        }
        SIGMA_OR => {
            let count = r.get_u16()? as usize;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(read_sigma_boolean_at_depth(r, next)?);
            }
            Ok(SigmaBoolean::Cor(children))
        }
        SIGMA_THRESHOLD => {
            // Scala: k = r.getUShort(), n = r.getUShort()
            let k = r.get_u16()? as u8;
            let count = r.get_u16()? as usize;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(read_sigma_boolean_at_depth(r, next)?);
            }
            Ok(SigmaBoolean::Cthreshold { k, children })
        }
        _ => Err(ReadError::InvalidData(format!(
            "unknown SigmaBoolean tag: 0x{tag:02X}"
        ))),
    }
}

// -- Collection serialization --

fn write_coll(
    w: &mut VlqWriter,
    elem_type: &SigmaType,
    coll: &CollValue,
) -> Result<(), WriteError> {
    // Scala writes Coll length as a u16 across all element-type
    // specializations; >65535-element collections silently wrap on
    // `as u16`. Cap once for all three branches.
    let len_for_cap = match coll {
        CollValue::BoolBits(b) => b.len(),
        CollValue::Bytes(b) => b.len(),
        CollValue::Values(v) => v.len(),
    };
    assert!(
        len_for_cap <= u16::MAX as usize,
        "Coll length too large for Scala wire format: {len_for_cap} (max 65535)",
    );
    match (elem_type, coll) {
        (SigmaType::SBoolean, CollValue::BoolBits(bits)) => {
            w.put_u16(bits.len() as u16);
            write_bits(w, bits);
        }
        (SigmaType::SByte, CollValue::Bytes(bytes)) => {
            w.put_u16(bytes.len() as u16);
            w.put_bytes(bytes);
        }
        (_, CollValue::Values(vals)) => {
            w.put_u16(vals.len() as u16);
            for v in vals {
                write_value(w, elem_type, v)?;
            }
        }
        _ => {
            return Err(WriteError::InvalidData(format!(
                "collection type/value mismatch: elem_type={elem_type:?}"
            )));
        }
    }
    Ok(())
}

fn read_coll(
    r: &mut VlqReader,
    elem_type: &SigmaType,
    depth: usize,
) -> Result<CollValue, ReadError> {
    let count = r.get_u16()? as usize;
    match elem_type {
        SigmaType::SBoolean => {
            let bits = read_bits(r, count)?;
            Ok(CollValue::BoolBits(bits))
        }
        SigmaType::SByte => {
            let bytes = r.get_bytes(count)?;
            Ok(CollValue::Bytes(bytes.to_vec()))
        }
        _ => {
            let mut vals = Vec::with_capacity(count);
            for _ in 0..count {
                vals.push(read_value_at_depth(r, elem_type, depth + 1)?);
            }
            Ok(CollValue::Values(vals))
        }
    }
}

// -- Bit-packing for Coll[Boolean] --

fn write_bits(w: &mut VlqWriter, bits: &[bool]) {
    let byte_count = bits.len().div_ceil(8);
    for i in 0..byte_count {
        let mut byte = 0u8;
        for bit_idx in 0..8 {
            let flat_idx = i * 8 + bit_idx;
            if flat_idx < bits.len() && bits[flat_idx] {
                byte |= 1 << bit_idx; // LSB-first (matches Scala)
            }
        }
        w.put_u8(byte);
    }
}

fn read_bits(r: &mut VlqReader, count: usize) -> Result<Vec<bool>, ReadError> {
    let byte_count = count.div_ceil(8);
    let bytes = r.get_bytes(byte_count)?;
    let mut bits = Vec::with_capacity(count);
    for i in 0..count {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        bits.push((bytes[byte_idx] >> bit_idx) & 1 == 1); // LSB-first (matches Scala)
    }
    Ok(bits)
}

// -- Option serialization --

fn write_option(
    w: &mut VlqWriter,
    elem_type: &SigmaType,
    opt: &Option<Box<SigmaValue>>,
) -> Result<(), WriteError> {
    match opt {
        None => w.put_u8(0x00),
        Some(val) => {
            w.put_u8(0x01);
            write_value(w, elem_type, val)?;
        }
    }
    Ok(())
}

fn read_option(
    r: &mut VlqReader,
    elem_type: &SigmaType,
    depth: usize,
) -> Result<Option<Box<SigmaValue>>, ReadError> {
    // scorex VLQReader.getOption: `if (tag != 0) Some(getValue) else None`.
    // ANY nonzero discriminant byte (not just 0x01) is Some; only 0x00 is
    // None. The SOption data path delegates to this reader, so e.g. tag 0x02
    // deserializes as Some(value).
    let tag = r.get_u8()?;
    if tag == 0 {
        Ok(None)
    } else {
        let val = read_value_at_depth(r, elem_type, depth + 1)?;
        Ok(Some(Box::new(val)))
    }
}

// -- AvlTree serialization --

fn write_avl_tree(w: &mut VlqWriter, avl: &AvlTreeData) {
    // Raw digest bytes, NO length prefix (Scala AvlTreeData.serializer:
    // `putBytes(digest.toArray)`). Wire-derived / literal trees always carry a
    // 33-byte digest, so the emitted bytes are unchanged from the old fixed
    // `ADDigest`; a runtime updateDigest result is consumed in-memory and never
    // re-serialized to the AvlTree wire.
    w.put_bytes(&avl.digest);
    let flags = (avl.insert_allowed as u8)
        | ((avl.update_allowed as u8) << 1)
        | ((avl.remove_allowed as u8) << 2);
    w.put_u8(flags);
    // Write the signed length back through the unsigned VLQ codec (round-trips
    // the original bytes for a wrapped-negative length). Scala's putUInt would
    // throw on a negative length; that only matters for re-serializing an
    // already-invalid tree, which is out of scope here.
    w.put_u32(avl.key_length as u32);
    // Scala: w.putOption(data.valueLengthOpt)(_.putUInt(_))
    match avl.value_length_opt {
        None => w.put_u8(0),
        Some(len) => {
            w.put_u8(1);
            w.put_u32(len as u32);
        }
    }
}

fn read_avl_tree(r: &mut VlqReader) -> Result<AvlTreeData, ReadError> {
    // Wire digest is ALWAYS a fixed 33 bytes (Scala AvlTreeData.parse reads
    // `getBytes(DigestSize=33)`, no length prefix); store as a Vec. A
    // length-prefixed read would fork.
    let digest = r.get_array::<33>()?.to_vec();

    let flags = r.get_u8()?;
    let insert_allowed = flags & 0x01 != 0;
    let update_allowed = flags & 0x02 != 0;
    let remove_allowed = flags & 0x04 != 0;

    // Scala AvlTreeData.parse: keyLength = r.getUInt().toInt — a length above
    // i32::MAX WRAPS to a negative Int (the deserializer succeeds with
    // invalid-but-parseable AvlTreeData), it is NOT rejected. (Previously
    // get_u32_exact rejected it, erroring the whole tree.)
    let key_length = r.get_uint_to_i32()?;
    // Scala: r.getOption(r.getUInt().toInt) — reads 1-byte flag, then optional VLQ uint
    let has_value_length = r.get_u8()?;
    let value_length_opt = if has_value_length != 0 {
        Some(r.get_uint_to_i32()?)
    } else {
        None
    };

    Ok(AvlTreeData {
        digest,
        insert_allowed,
        update_allowed,
        remove_allowed,
        key_length,
        value_length_opt,
    })
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

    /// Full box bytes (candidate ++ txId ++ index) with `n` single-byte-amount
    /// tokens. candidate length = 3(value)+7(tree)+1(height)+1(tokenCount)
    /// +33*n+1(regCount); n=124 crosses 4096, n=120 stays under.
    fn box_bytes_with_tokens(n: usize) -> Vec<u8> {
        let mut w = VlqWriter::new();
        w.put_u64(1_000_000); // value
        w.put_bytes(&[0x10, 0x01, 0x01, 0x01, 0xD1, 0x73, 0x00]); // minimal tree
        w.put_u32(0); // creation height
        w.put_u8(n as u8); // token count
        for i in 0..n {
            w.put_bytes(&[(i & 0xff) as u8; 32]); // token id
            w.put_u64(1); // amount
        }
        w.put_u8(0); // register count
        w.put_bytes(&[0x11; 32]); // transaction id
        w.put_u16(0); // output index
        w.result()
    }

    /// Scala `ErgoBoxCandidate.parseBodyWithIndexedDigests` sets
    /// `positionLimit = position + ErgoBox.MaxBoxSize` (4096) before reading the
    /// candidate body. A token loop read that BEGINS past 4096 trips
    /// CheckPositionLimit (rule 1014) and the box parse errors.
    #[test]
    fn opaque_box_over_4096_candidate_errors() {
        let bytes = box_bytes_with_tokens(124); // candidate 4105 > 4096
        let mut r = VlqReader::new(&bytes);
        let res = read_value(&mut r, &SigmaType::SBox);
        assert!(
            res.is_err(),
            "124-token box candidate (> 4096) must error, got {res:?}"
        );
    }

    /// A candidate at/under the 4096 window parses normally (no read begins past
    /// the limit).
    #[test]
    fn opaque_box_under_4096_candidate_ok() {
        let bytes = box_bytes_with_tokens(120); // candidate 3973 < 4096
        let mut r = VlqReader::new(&bytes);
        let res = read_value(&mut r, &SigmaType::SBox);
        assert!(
            res.is_ok(),
            "120-token box candidate (< 4096) must parse, got {res:?}"
        );
    }

    /// scorex `VLQReader.getOption` reads one discriminant byte and treats
    /// ANY nonzero value as `Some` (`if (tag != 0) Some(getValue) else None`)
    /// — only `0x00` is `None`. We previously rejected any tag other than
    /// 0x00/0x01.
    #[test]
    fn read_option_treats_any_nonzero_tag_as_some() {
        let tpe = SigmaType::SOption(Box::new(SigmaType::SInt));
        // Encode Some(Int 5): write_option emits discriminant 0x01 + payload.
        let mut w = VlqWriter::new();
        write_value(
            &mut w,
            &tpe,
            &SigmaValue::Opt(Some(Box::new(SigmaValue::Int(5)))),
        )
        .unwrap();
        let mut bytes = w.result();
        assert_eq!(bytes[0], 0x01, "Some writes discriminant 0x01");

        // Flip the discriminant to 0x02 — scorex still reads it as Some.
        bytes[0] = 0x02;
        let mut r = VlqReader::new(&bytes);
        let decoded = read_value(&mut r, &tpe).unwrap();
        assert!(r.is_empty(), "option read must consume all bytes");
        assert_eq!(
            decoded,
            SigmaValue::Opt(Some(Box::new(SigmaValue::Int(5)))),
            "any nonzero Option discriminant must decode as Some",
        );

        // 0x00 still decodes as None.
        let mut r0 = VlqReader::new(&[0x00]);
        assert_eq!(
            read_value(&mut r0, &tpe).unwrap(),
            SigmaValue::Opt(None),
            "0x00 discriminant is None",
        );
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
    fn roundtrip_bigint() {
        roundtrip_value(&SigmaType::SBigInt, &SigmaValue::BigInt(BigInt::from(0)));
        roundtrip_value(
            &SigmaType::SBigInt,
            &SigmaValue::BigInt(BigInt::from(i64::MAX)),
        );
        roundtrip_value(
            &SigmaType::SBigInt,
            &SigmaValue::BigInt(BigInt::from(i64::MIN)),
        );
        // Large value beyond i64 range
        let big = BigInt::parse_bytes(b"123456789012345678901234567890123456789", 10).unwrap();
        roundtrip_value(&SigmaType::SBigInt, &SigmaValue::BigInt(big));
    }

    #[test]
    fn roundtrip_unsigned_bigint() {
        // Zero — wire shape `len=0`, no payload bytes.
        roundtrip_value(
            &SigmaType::SUnsignedBigInt,
            &SigmaValue::BigInt(BigInt::from(0)),
        );
        // Small magnitude (fits in one wire byte).
        roundtrip_value(
            &SigmaType::SUnsignedBigInt,
            &SigmaValue::BigInt(BigInt::from(1)),
        );
        // High-bit-set magnitude — the case the old signed reader
        // misinterpreted as negative.
        let n_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        let n = BigInt::parse_bytes(n_hex.as_bytes(), 16).unwrap();
        roundtrip_value(&SigmaType::SUnsignedBigInt, &SigmaValue::BigInt(n));
        // 2^256 - 1 — the maximum permitted unsigned magnitude.
        let max_u256 = (BigInt::from(1) << 256) - 1;
        roundtrip_value(&SigmaType::SUnsignedBigInt, &SigmaValue::BigInt(max_u256));
    }

    #[test]
    fn unsigned_bigint_rejects_negative_on_write() {
        let mut w = VlqWriter::new();
        let err = super::write_value(
            &mut w,
            &SigmaType::SUnsignedBigInt,
            &SigmaValue::BigInt(BigInt::from(-1)),
        )
        .expect_err("writing a negative SUnsignedBigInt must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("negative"),
            "error should explain the negative-value violation: {msg}",
        );
    }

    #[test]
    fn unsigned_bigint_rejects_oversize_on_read() {
        // Construct a wire payload with len=33 (one over the 32-byte
        // unsigned bound). The reader must refuse it loudly.
        let mut w = VlqWriter::new();
        w.put_u16(33);
        w.put_bytes(&[0xffu8; 33]);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = super::read_value(&mut r, &SigmaType::SUnsignedBigInt)
            .expect_err("33-byte unsigned magnitude must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("too long"),
            "error should explain the length violation: {msg}",
        );
    }

    // ----- SBigInt 32-byte length cap -----
    //
    // Oracle: Scala's `CoreDataSerializer.deserializeBigInt` rejects
    // `len > MaxBigIntSizeInBytes = 32`. Mirrors the gate already
    // present on the unsigned twin (`read_unsigned_bigint_value`).

    #[test]
    fn bigint_accepts_32_byte_signed_value_with_top_bit_set_as_negative() {
        // 32 bytes with top bit set encodes a negative signed value
        // near -2^255. This is the largest legal signed payload AND
        // tests the boundary-byte sign handling. Pin via round-trip.
        let mut bytes = vec![0u8; 32];
        bytes[0] = 0x80; // sign bit set → negative in two's complement
        let n = BigInt::from_signed_bytes_be(&bytes);
        assert!(n < BigInt::from(0), "0x80 0x00... must decode as negative");
        roundtrip_value(&SigmaType::SBigInt, &SigmaValue::BigInt(n));
    }

    #[test]
    fn bigint_rejects_oversize_on_read() {
        // Construct a wire payload with len=33 (one over the 32-byte
        // signed bound). Mirrors `unsigned_bigint_rejects_oversize_on_read`
        // for the signed twin.
        let mut w = VlqWriter::new();
        w.put_u16(33);
        w.put_bytes(&[0xffu8; 33]);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = super::read_value(&mut r, &SigmaType::SBigInt)
            .expect_err("33-byte signed BigInt must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("SBigInt") && msg.contains("too long"),
            "error should cite SBigInt + length: {msg}",
        );
    }

    #[test]
    fn bigint_rejects_huge_size_on_read_before_alloc() {
        // Hostile payload: len=65535 (the old wire-cap). The new gate
        // must fire BEFORE `get_bytes(65535)` so a single message can't
        // trigger 65 KiB allocation. The test supplies only 4 bytes —
        // if the cap is correctly placed before the alloc, we see
        // `InvalidData("SBigInt ... too long")`. If misplaced, we'd
        // see `UnexpectedEnd` from `get_bytes` running past EOF.
        let mut w = VlqWriter::new();
        w.put_u16(65535);
        w.put_bytes(&[0u8; 4]);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err =
            super::read_value(&mut r, &SigmaType::SBigInt).expect_err("len=65535 must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("too long"),
            "cap must fire before get_bytes; got {msg}",
        );
    }

    #[test]
    fn bigint_rejects_33_byte_value_on_write() {
        // Off-by-one trap: `+2^255` requires 33 bytes in signed
        // encoding (leading 0x00 to keep the sign bit clear). The
        // writer must reject with `InvalidData` at write time so a
        // programmatic caller can't produce Scala-invalid bytes.
        let two_to_255: BigInt = BigInt::from(1) << 255;
        // Confirm the test premise: signed encoding really takes 33 bytes.
        assert_eq!(
            two_to_255.to_signed_bytes_be().len(),
            33,
            "test premise: +2^255 signed encoding is 33 bytes"
        );
        let mut w = VlqWriter::new();
        let err = super::write_value(&mut w, &SigmaType::SBigInt, &SigmaValue::BigInt(two_to_255))
            .expect_err("writing +2^255 (33 signed bytes) must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("SBigInt") && msg.contains("too long"),
            "error should cite SBigInt + length: {msg}",
        );
    }

    #[test]
    fn bigint_accepts_32_byte_value_on_write() {
        // Boundary positive case: largest positive that fits in 32
        // signed bytes is `2^255 - 1` (top byte 0x7F, sign bit clear).
        // Must round-trip; pairs with the `+2^255` reject test above
        // to fully specify the writer boundary.
        let max_signed_32: BigInt = (BigInt::from(1) << 255) - 1;
        assert_eq!(
            max_signed_32.to_signed_bytes_be().len(),
            32,
            "test premise: 2^255 - 1 signed encoding is 32 bytes"
        );
        roundtrip_value(&SigmaType::SBigInt, &SigmaValue::BigInt(max_signed_32));
    }

    #[test]
    fn bigint_golden_wire_bytes_for_minus_two_pow_255() {
        // Golden-byte parity test. The Scala `CoreDataSerializer`
        // SBigInt wire format is exactly
        // `putUShort(len) | bytes`, where `putUShort` is Scorex's
        // VLQ-encoded unsigned short and `bytes` is Scala's
        // `BigInteger.toByteArray` (signed two's-complement big-endian).
        //
        // For `-2^255`, the signed payload is `0x80 0x00 ... 0x00`
        // (32 bytes). The VLQ encoding of length 32 is the single
        // byte `0x20` (any value < 128 VLQ-encodes to a single byte
        // with no continuation bit). The full wire bytes are:
        //   0x20  0x80  0x00 (x31)   — 33 bytes total
        //
        // These bytes are derived from the Scala DataSerializer
        // contract, not from our writer's output. Asserting that our
        // writer produces them is an external oracle proof of byte
        // parity at the cap-boundary.
        let pos: BigInt = BigInt::from(1) << 255;
        let n: BigInt = -pos;
        let mut w = VlqWriter::new();
        super::write_value(&mut w, &SigmaType::SBigInt, &SigmaValue::BigInt(n.clone()))
            .expect("-2^255 fits in 32 signed bytes; writer must accept");
        let bytes = w.result();
        let mut expected = vec![0x20u8, 0x80];
        expected.extend(std::iter::repeat_n(0u8, 31));
        assert_eq!(
            bytes, expected,
            "wire bytes for -2^255 must match the Scala DataSerializer \
             golden value derived from CoreDataSerializer.scala (VLQ \
             length 0x20 || signed two's-complement payload [0x80, 0; 31])"
        );
        // Round-trip back from the golden bytes to pin the reader.
        let mut r = VlqReader::new(&bytes);
        let decoded =
            super::read_value(&mut r, &SigmaType::SBigInt).expect("golden wire bytes must decode");
        assert_eq!(decoded, SigmaValue::BigInt(n));
    }

    #[test]
    fn roundtrip_group_element() {
        roundtrip_value(
            &SigmaType::SGroupElement,
            &SigmaValue::GroupElement(fake_ge(0xAA)),
        );
    }

    // ===== 2. SigmaProp roundtrips =====

    #[test]
    fn roundtrip_sigma_prop_prove_dlog() {
        let sb = SigmaBoolean::ProveDlog(fake_ge(0xBB));
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn roundtrip_sigma_prop_prove_dh_tuple() {
        let sb = SigmaBoolean::ProveDHTuple {
            g: fake_ge(0x11),
            h: fake_ge(0x22),
            u: fake_ge(0x33),
            v: fake_ge(0x44),
        };
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn roundtrip_sigma_prop_trivial() {
        roundtrip_value(
            &SigmaType::SSigmaProp,
            &SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        );
        roundtrip_value(
            &SigmaType::SSigmaProp,
            &SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(false)),
        );
    }

    #[test]
    fn roundtrip_sigma_prop_cand() {
        let sb = SigmaBoolean::Cand(vec![
            SigmaBoolean::ProveDlog(fake_ge(0xAA)),
            SigmaBoolean::ProveDlog(fake_ge(0xBB)),
        ]);
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn roundtrip_sigma_prop_cor() {
        let sb = SigmaBoolean::Cor(vec![
            SigmaBoolean::ProveDlog(fake_ge(0xCC)),
            SigmaBoolean::ProveDHTuple {
                g: fake_ge(0x11),
                h: fake_ge(0x22),
                u: fake_ge(0x33),
                v: fake_ge(0x44),
            },
        ]);
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn roundtrip_sigma_prop_threshold() {
        let sb = SigmaBoolean::Cthreshold {
            k: 2,
            children: vec![
                SigmaBoolean::ProveDlog(fake_ge(0xAA)),
                SigmaBoolean::ProveDlog(fake_ge(0xBB)),
                SigmaBoolean::ProveDlog(fake_ge(0xCC)),
            ],
        };
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn read_sigma_boolean_within_depth_limit_roundtrips() {
        // A single-child Cand chain within MaxTreeDepth (110) must still parse.
        let mut sb = SigmaBoolean::TrivialProp(true);
        for _ in 0..100 {
            sb = SigmaBoolean::Cand(vec![sb]);
        }
        roundtrip_value(&SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb));
    }

    #[test]
    fn read_sigma_boolean_deep_nesting_rejected_not_overflow() {
        // A SigmaProp constant value is peer-controllable (box register /
        // context extension). A long single-child Cand chain (~3 wire bytes per
        // level) must be REJECTED at the MaxTreeDepth bound rather than
        // recursing unbounded and overflowing the worker-thread stack — Scala
        // throws DeserializeCallDepthExceeded past depth 110.
        let mut sb = SigmaBoolean::TrivialProp(true);
        for _ in 0..200 {
            sb = SigmaBoolean::Cand(vec![sb]);
        }
        let mut w = VlqWriter::new();
        write_value(&mut w, &SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb)).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let err = read_value(&mut r, &SigmaType::SSigmaProp).unwrap_err();
        assert!(
            matches!(err, ReadError::DepthLimitExceeded { max } if max == MAX_SIGMA_TREE_DEPTH),
            "expected depth-limit error, got {err:?}"
        );
    }

    #[test]
    fn read_sigma_boolean_depth_boundary_matches_scala() {
        // Scala rejects the 110-deep chain (level reaches 111 before the leaf)
        // and accepts the 109-deep one. With a 0-based counter and `depth >=
        // MAX`, our leaf sits at depth == (#Cand), so 110 Cands reject and 109
        // accept — the exact Scala boundary.
        let chain = |n: usize| {
            let mut sb = SigmaBoolean::TrivialProp(true);
            for _ in 0..n {
                sb = SigmaBoolean::Cand(vec![sb]);
            }
            let mut w = VlqWriter::new();
            write_value(&mut w, &SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb)).unwrap();
            w.result()
        };
        // 109 Cands: accepted.
        let ok = chain(MAX_SIGMA_TREE_DEPTH - 1);
        assert!(read_value(&mut VlqReader::new(&ok), &SigmaType::SSigmaProp).is_ok());
        // 110 Cands: rejected (matches Scala level 111 > MaxTreeDepth).
        let bad = chain(MAX_SIGMA_TREE_DEPTH);
        assert!(matches!(
            read_value(&mut VlqReader::new(&bad), &SigmaType::SSigmaProp).unwrap_err(),
            ReadError::DepthLimitExceeded { .. }
        ));
    }

    #[test]
    fn shared_depth_budget_across_expr_and_sigma_boundary() {
        // The leak: an inline SigmaProp constant nested inside a deep ErgoTree
        // expression used to restart the SigmaBoolean budget at 0. Scala shares
        // one CoreByteReader.level across expr + value + SigmaBoolean, so the
        // counts ADD. Here N SizeOf expr wrappers wrap a SigmaProp constant with
        // M Cands: neither N nor M alone exceeds MaxTreeDepth (110), but N+M does.
        let sigma_const = |m: usize| {
            let mut sb = SigmaBoolean::TrivialProp(true);
            for _ in 0..m {
                sb = SigmaBoolean::Cand(vec![sb]);
            }
            let mut w = VlqWriter::new();
            write_constant(&mut w, &SigmaType::SSigmaProp, &SigmaValue::SigmaProp(sb)).unwrap();
            w.result()
        };
        let body = |n: usize, m: usize| {
            let mut b = vec![0xB1u8; n]; // n SizeOf (One-arg) expr wrappers
            b.extend_from_slice(&sigma_const(m));
            b
        };
        // 60 expr + 60 sigma = 120 >= 110 → rejected via the shared budget
        // (was accepted before the fix, when the sigma counter reset to 0).
        let over = body(60, 60);
        assert!(matches!(
            crate::opcode::parse_body(&mut VlqReader::new(&over), 0).unwrap_err(),
            ReadError::DepthLimitExceeded { .. }
        ));
        // 40 expr + 40 sigma = 80 < 110 → accepted.
        let ok = body(40, 40);
        assert!(crate::opcode::parse_body(&mut VlqReader::new(&ok), 0).is_ok());
    }

    #[test]
    fn sbox_constant_with_over_depth_tree_hard_rejects() {
        // An SBox inline constant whose proposition is a SIZE-DELIMITED tree
        // nested past MaxTreeDepth must hard-reject (Scala deserializes the
        // embedded box tree via ErgoTreeSerializer, which depth-checks it) — not
        // be accepted as opaque bytes by skip_ergo_tree.
        let mut tree = vec![0x08u8]; // header: v0, has_size
        let mut tree_body = vec![0xB1u8; 150]; // SizeOf chain (over-depth)
        tree_body.push(0xA3); // Height leaf
        ergo_primitives::vlq::encode_vlq_into(tree_body.len() as u64, &mut tree);
        tree.extend_from_slice(&tree_body);
        let mut box_bytes = vec![0x01u8]; // box value = 1 nanoErg
        box_bytes.extend_from_slice(&tree); // proposition (parse fails here)
        let mut r = VlqReader::new(&box_bytes);
        let err = read_value(&mut r, &SigmaType::SBox).unwrap_err();
        assert!(
            matches!(err, ReadError::DepthLimitExceeded { .. }),
            "SBox-embedded over-depth tree must hard-reject, got {err:?}"
        );
    }

    // ===== 3. Collection roundtrips =====

    #[test]
    fn roundtrip_coll_byte() {
        let coll = CollValue::Bytes(vec![0x01, 0x02, 0xFF, 0x00]);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SByte)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_byte_empty() {
        let coll = CollValue::Bytes(vec![]);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SByte)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_int() {
        let coll = CollValue::Values(vec![
            SigmaValue::Int(1),
            SigmaValue::Int(-42),
            SigmaValue::Int(i32::MAX),
        ]);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SInt)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_boolean_bitpacked() {
        let bits = vec![true, false, true, true, false, false, true, false, true];
        let coll = CollValue::BoolBits(bits);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_boolean_exact_byte_boundary() {
        let bits = vec![true, false, true, false, true, false, true, false]; // exactly 8
        let coll = CollValue::BoolBits(bits);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            &SigmaValue::Coll(coll),
        );
    }

    #[test]
    fn roundtrip_coll_boolean_empty() {
        let coll = CollValue::BoolBits(vec![]);
        roundtrip_value(
            &SigmaType::SColl(Box::new(SigmaType::SBoolean)),
            &SigmaValue::Coll(coll),
        );
    }

    // ===== 4. Nested roundtrips =====

    #[test]
    fn roundtrip_coll_coll_byte() {
        let inner1 = SigmaValue::Coll(CollValue::Bytes(vec![0x01, 0x02]));
        let inner2 = SigmaValue::Coll(CollValue::Bytes(vec![0x03]));
        let coll = CollValue::Values(vec![inner1, inner2]);
        let tpe = SigmaType::SColl(Box::new(SigmaType::SColl(Box::new(SigmaType::SByte))));
        roundtrip_value(&tpe, &SigmaValue::Coll(coll));
    }

    #[test]
    fn roundtrip_option_int_some() {
        let tpe = SigmaType::SOption(Box::new(SigmaType::SInt));
        let val = SigmaValue::Opt(Some(Box::new(SigmaValue::Int(42))));
        roundtrip_value(&tpe, &val);
    }

    #[test]
    fn roundtrip_option_int_none() {
        let tpe = SigmaType::SOption(Box::new(SigmaType::SInt));
        let val = SigmaValue::Opt(None);
        roundtrip_value(&tpe, &val);
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

    // ===== 5. AvlTree roundtrips =====

    /// Scala `AvlTreeData.parse`: `keyLength = r.getUInt().toInt` — a length
    /// encoding above `i32::MAX` WRAPS to a negative `Int` and the deserializer
    /// SUCCEEDS with invalid-but-parseable `AvlTreeData` (it is NOT rejected,
    /// as `getUIntExact` would). Same for `valueLengthOpt`.
    #[test]
    fn read_avl_tree_wraps_lengths_above_i32_max() {
        let mut w = VlqWriter::new();
        w.put_bytes(&[0x07u8; 33]); // 33-byte digest
        w.put_u8(0x07); // flags: insert/update/remove allowed
        w.put_u32(0x8000_0000); // keyLength = 2^31 -> i32::MIN
        w.put_u8(0x01); // valueLengthOpt present
        w.put_u32(0xFFFF_FFFF); // valueLengthOpt = 2^32-1 -> -1
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        match read_value(&mut r, &SigmaType::SAvlTree)
            .expect("AvlTree must parse (not reject) a wrapped keyLength/valueLengthOpt")
        {
            SigmaValue::AvlTree(avl) => {
                assert_eq!(avl.key_length, i32::MIN, "keyLength 2^31 wraps to i32::MIN");
                assert_eq!(
                    avl.value_length_opt,
                    Some(-1),
                    "valueLengthOpt 2^32-1 wraps to -1"
                );
            }
            other => panic!("expected AvlTree, got {other:?}"),
        }
        assert!(r.is_empty(), "all bytes consumed");
    }

    #[test]
    fn roundtrip_avl_tree_with_value_length() {
        let avl = AvlTreeData {
            digest: vec![0xAB; 33],
            insert_allowed: true,
            update_allowed: false,
            remove_allowed: true,
            key_length: 32,
            value_length_opt: Some(8),
        };
        roundtrip_value(&SigmaType::SAvlTree, &SigmaValue::AvlTree(avl));
    }

    #[test]
    fn roundtrip_avl_tree_without_value_length() {
        let avl = AvlTreeData {
            digest: vec![0xCD; 33],
            insert_allowed: false,
            update_allowed: true,
            remove_allowed: false,
            key_length: 64,
            value_length_opt: None,
        };
        roundtrip_value(&SigmaType::SAvlTree, &SigmaValue::AvlTree(avl));
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

    #[test]
    fn golden_prove_dlog_tag() {
        let mut w = VlqWriter::new();
        let sb = SigmaBoolean::ProveDlog(fake_ge(0x00));
        write_sigma_boolean(&mut w, &sb);
        let data = w.result();
        assert_eq!(data[0], 0xCD);
        assert_eq!(data.len(), 1 + 33);
    }

    #[test]
    fn golden_bit_packing() {
        // 9 bools: [T,F,T,T,F,F,T,F, T]  — LSB-first packing
        // byte 0: bits 0-7 → 0b_0100_1101 = 0x4D
        // byte 1: bit 8 → 0b_0000_0001 = 0x01
        let mut w = VlqWriter::new();
        let bits = vec![true, false, true, true, false, false, true, false, true];
        write_bits(&mut w, &bits);
        assert_eq!(w.result(), [0x4D, 0x01]);
    }

    /// Assemble standalone SBox-constant bytes (value + proposition + box tail).
    fn sbox_constant_bytes(tree: &[u8]) -> Vec<u8> {
        let mut w = VlqWriter::new();
        w.put_u64(1_000_000); // value
        w.put_bytes(tree); // proposition
        w.put_u32(100); // creation height
        w.put_u8(0); // token count
        w.put_u8(0); // register count
        w.put_bytes(&[0u8; 32]); // tx id
        w.put_u16(0); // output index
        w.result()
    }

    /// A SIZELESS pre-v3 (`0x10` = v0 + const-seg) `SBox` constant whose
    /// proposition carries the `SGlobal.none[T]` v6 PropertyCall is REJECTED at
    /// deserialize. With no size bit, `skip_ergo_tree` walks the body through
    /// the full parser to find the box-field boundary, and the mirrored gate
    /// rejects the v6-only method exactly as Scala's box deserialize does
    /// (method resolution against the pre-v3 method table; no size bit means the
    /// `ValidationException` is re-raised as a `SerializerException`). This is an
    /// accept-invalid the box-script-reader gate alone would miss: a box
    /// embedded as a CONSTANT is never spent, so the evaluator's spend-path gate
    /// never fires on its inner tree. The rejection is a `HardReject` so it
    /// survives an enclosing size-delimited tree's soft-fork wrap.
    #[test]
    fn sbox_constant_sizeless_v6_tree_rejected() {
        let tree = hex::decode("1000d1efe6db6a0add04").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);
        let mut r = VlqReader::new(&box_bytes);
        let err = read_value(&mut r, &SigmaType::SBox).expect_err(
            "sizeless pre-v3 SBox constant carrying a v6 method must reject at deserialize",
        );
        assert!(
            matches!(&err, ReadError::HardReject(m) if m.contains("does not resolve in the v5 registry")),
            "got {err:?}",
        );
    }

    /// A sizeless v0 nested `SBox`-constant script carrying the v6-only embeddable
    /// type `SUnsignedBigInt` (code 9) must be gated against the INNER tree's own
    /// version (0), NOT the enclosing tree's. We pre-set the reader's
    /// `ergo_tree_version` to `Some(3)` (a v3+ outer context); the nested parse must
    /// still reject code 9 because its own header is v0. Without the per-nested-tree
    /// version scoping, the inner script would inherit `Some(3)` and wrongly accept —
    /// accept-invalid (codex P1).
    #[test]
    fn sbox_constant_sizeless_unsigned_bigint_gated_by_inner_version() {
        // The v6-only type must reject under the INNER v0 version whether it appears
        // inline in the body OR as a segregated constant (which is read BEFORE the
        // body) — both are within the nested tree's own version scope.
        let inners = [
            // inline: header 0x00 + Const(SUnsignedBigInt) (type 0x09 + len 0x00).
            "000900",
            // const-segregated: header 0x10 (v0+cseg) + count 0x01 + segregated
            // Const(SUnsignedBigInt) (09 00) + body ConstPlaceholder(0) (73 00).
            "100109007300",
        ];
        for inner_hex in inners {
            let inner = hex::decode(inner_hex).unwrap();
            let box_bytes = sbox_constant_bytes(&inner);
            let mut r = VlqReader::new(&box_bytes);
            r.set_ergo_tree_version(Some(3)); // simulate a v3+ enclosing tree
            let err = read_value(&mut r, &SigmaType::SBox).expect_err(&format!(
                "sizeless v0 nested script ({inner_hex}) with SUnsignedBigInt must reject under inner version 0",
            ));
            assert!(
                matches!(&err, ReadError::HardReject(m) if m.contains("SUnsignedBigInt")),
                "inner {inner_hex}: got {err:?}",
            );
        }
    }

    /// A sizeless `version != 0` nested box script violates rule 1012
    /// (`CheckHeaderSizeBit`). Read standalone (no enclosing tree), the
    /// rejection propagates and the box is rejected. The error is a SOFT
    /// `InvalidData` (Scala throws this as a `ValidationException`), so an
    /// enclosing size-delimited tree would instead WRAP it — see
    /// `ergo_tree::tests::nested_box_constant_rule1012_in_size_delimited_outer_wraps`.
    #[test]
    fn sbox_constant_sizeless_nonzero_version_rejected() {
        // header 0x01 = version 1, no size bit, no const-seg; body `d3`.
        let tree = hex::decode("01d3").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);
        let mut r = VlqReader::new(&box_bytes);
        let err = read_value(&mut r, &SigmaType::SBox)
            .expect_err("sizeless version!=0 nested box script must reject (rule 1012)");
        assert!(
            matches!(&err, ReadError::InvalidData(m) if m.contains("rule 1012")),
            "got {err:?}",
        );
    }

    /// A SIZELESS valid `SBox` constant round-trips: `skip_ergo_tree` has no
    /// blob length to skip by, so it walks the non-size-delimited body to find
    /// the box-field boundary — the box fields after the tree must still land
    /// exactly. Uses a minimal v0 `sigmaProp(true)` proposition (no v6 method),
    /// proving the gate does not over-reject a legitimate sizeless tree.
    #[test]
    fn sbox_constant_sizeless_valid_tree_roundtrips() {
        let tree = hex::decode("0008d3").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);
        let mut r = VlqReader::new(&box_bytes);
        let val =
            read_value(&mut r, &SigmaType::SBox).expect("valid sizeless SBox constant must parse");
        assert!(r.is_empty(), "box-field boundary must land exactly at end");
        assert_eq!(val, SigmaValue::OpaqueBoxBytes(box_bytes));
        roundtrip_value(&SigmaType::SBox, &val);
    }

    /// A nested `SBox` constant whose inner ErgoTree is a HIGH-VERSION
    /// size-delimited (opaque) tree (header `0xcd` = version 5, has_size) is
    /// HARD-rejected by the strict consensus reader (`check_tree_version_supported`
    /// inside `skip_ergo_tree`), but a TRUSTED reader accepts it. This is the
    /// nested mirror of the top-level legacy-box case: a stored box can carry such
    /// a tree nested in a register / `SBox` constant / context-extension, and the
    /// indexer (re-reading its OWN already-validated data with a trusted reader)
    /// must round-trip it instead of halting the rebuild. The trusted flag rides
    /// on the reader, so it reaches this nested gate without any param threading.
    #[test]
    fn sbox_constant_high_version_opaque_tree_strict_rejects_trusted_accepts() {
        // Real nested-tree bytes shape from mainnet box gi 5918565: header 0xcd
        // (version 5, has_size), declared size 7, 7 opaque body bytes.
        let tree = hex::decode("cd07021a8e6f59fd4a").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);

        // Strict (untrusted) consensus reader rejects the future-version tree.
        let mut strict = VlqReader::new(&box_bytes);
        read_value(&mut strict, &SigmaType::SBox)
            .expect_err("strict reader must reject a version-5 nested box-constant tree");

        // Trusted reader (already-validated stored data) accepts it, landing the
        // box-field boundary exactly.
        let mut trusted = VlqReader::new(&box_bytes).trusted();
        let val = read_value(&mut trusted, &SigmaType::SBox)
            .expect("trusted reader must accept a stored high-version nested opaque tree");
        assert!(trusted.is_empty(), "box-field boundary must land exactly at end");
        assert_eq!(val, SigmaValue::OpaqueBoxBytes(box_bytes));
    }

    /// A nested `SBox`-constant whose inner script is a sizeless Boolean-root tree
    /// (`00 01 73` = Const(SBoolean, true)) must REJECT, matching Scala's
    /// `CheckDeserializedScriptIsSigmaProp` (rule 1001) on the inner root — the
    /// same gate `check_sigma_prop_root` enforces for a top-level box script. The
    /// valid SigmaProp-root case above proves this does not over-reject.
    #[test]
    fn sbox_constant_sizeless_non_sigmaprop_root_rejects() {
        let tree = hex::decode("000173").unwrap();
        let box_bytes = sbox_constant_bytes(&tree);
        let mut r = VlqReader::new(&box_bytes);
        assert!(
            read_value(&mut r, &SigmaType::SBox).is_err(),
            "nested sizeless Boolean-root box script must reject (rule 1001)"
        );
    }

    /// `harden_sizeless_inner_error` turns ANY soft inner-parse failure of a
    /// sizeless inner box tree into a `HardReject` (Scala re-raises every inner
    /// `ValidationException` as a `SerializerException` for `sizeOpt = None`),
    /// while already-hard errors pass through unchanged.
    #[test]
    fn harden_sizeless_inner_error_classifies() {
        // Soft `InvalidData` (e.g. unknown opcode / bad type / v6 method) -> hard.
        assert!(matches!(
            super::harden_sizeless_inner_error(ReadError::InvalidData("x".into())),
            ReadError::HardReject(_)
        ));
        // Already-hard errors are preserved.
        assert!(matches!(
            super::harden_sizeless_inner_error(ReadError::DepthLimitExceeded { max: 110 }),
            ReadError::DepthLimitExceeded { .. }
        ));
        assert!(matches!(
            super::harden_sizeless_inner_error(ReadError::HardReject("y".into())),
            ReadError::HardReject(_)
        ));
    }

    /// A nested `SBox`-constant SIZE-delimited inner tree is skipped by STRUCTURE,
    /// not the declared size (matching Scala's inline `deserializeErgoTree`): a
    /// tree declaring size 5 but a 2-byte body (`08d3` = sigmaProp(true)),
    /// followed by trailing box bytes, must advance only past the 2-byte body so
    /// the box's next field is read from the right offset. The old
    /// `get_bytes(size)` skip would consume 5 bytes (two of the trailing field),
    /// desyncing the box.
    #[test]
    fn skip_ergo_tree_size_delimited_advances_by_body_not_declared_size() {
        // header 08 | size 05 | body 08d3 (2 bytes) | trailing aabbcc (3 bytes)
        let bytes = hex::decode("080508d3aabbcc").unwrap();
        let mut r = VlqReader::new(&bytes);
        super::skip_ergo_tree(&mut r).expect("nested size-delimited tree must skip");
        assert_eq!(
            r.remaining(),
            3,
            "must advance by the 2-byte body, leaving the 3 trailing box bytes"
        );
    }
}

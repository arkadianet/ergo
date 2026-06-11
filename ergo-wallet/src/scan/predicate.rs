//! Scan tracking-rule predicates (`/scan/*` subsystem, PR 1 of N).
//!
//! Mirrors Scala `org.ergoplatform.nodeView.wallet.scanning.ScanningPredicate`
//! and its JSON codec: a tracking rule is a predicate tree over a box, and the
//! wallet's apply-hook (a later slice) runs every registered scan's rule over
//! each output box to decide what to track. This module is just the language +
//! the box matcher; the registry, persistence, apply-hook, and the eight HTTP
//! endpoints land in following PRs.
//!
//! Verification note: the `/scan` family is auth-gated, so — unlike the other
//! Scala-compat surfaces — this is grounded against the Scala node source + the
//! published swagger rather than captured from a live oracle. The byte forms it
//! compares lean on `ergo-ser`'s already-oracle-tested constant serialization.
//!
//! ## Wire shape (Scala `ScanningPredicateJsonCodecs`)
//!
//! ```json
//! {"predicate":"containsAsset","assetId":"<32-byte token id hex>"}
//! {"predicate":"contains","register":"R4","value":"<serialized constant hex>"}
//! {"predicate":"equals","register":"R1","value":"<serialized constant hex>"}
//! {"predicate":"and","args":[ ... ]}
//! {"predicate":"or","args":[ ... ]}
//! ```
//!
//! `register` is optional and defaults to **R1** (the box's propositionBytes),
//! matching Scala's `register.getOrElse(ErgoBox.R1)`. The `value` field is a
//! serialized `EvaluatedValue` (a typed constant). PR 1 evaluates `register` R1 and the
//! additional registers R4-R9 — the registers real scans address; R0/R2/R3
//! (monetary value / tokens / creation info) parse and round-trip but never
//! match yet, tracked as a follow-up.

use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::register::RegisterId;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{read_constant, CollValue, SigmaValue};
use serde::{Deserialize, Serialize};

/// The box register a `Contains` / `Equals` predicate addresses. Serialized as
/// `"R0".."R9"`; absent in JSON means [`ScanRegister::R1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanRegister {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
}

impl Default for ScanRegister {
    /// Scala `register.getOrElse(ErgoBox.R1)`.
    fn default() -> Self {
        ScanRegister::R1
    }
}

impl ScanRegister {
    /// Map to a non-mandatory [`RegisterId`] (R4-R9), or `None` for the
    /// mandatory registers R0-R3.
    fn additional(self) -> Option<RegisterId> {
        match self {
            ScanRegister::R4 => Some(RegisterId::R4),
            ScanRegister::R5 => Some(RegisterId::R5),
            ScanRegister::R6 => Some(RegisterId::R6),
            ScanRegister::R7 => Some(RegisterId::R7),
            ScanRegister::R8 => Some(RegisterId::R8),
            ScanRegister::R9 => Some(RegisterId::R9),
            _ => None,
        }
    }
}

/// A scan tracking rule: the predicate tree Scala evaluates against each box.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "predicate", rename_all = "camelCase")]
pub enum ScanningPredicate {
    /// The register's value, as bytes, contains `value`'s bytes as a
    /// contiguous slice (Scala `containsSlice`). Scala
    /// `ContainsScanningPredicate.filter` supports **only** `Coll[Byte]`: both
    /// the predicate value and the register value must be byte arrays, else the
    /// box does not match.
    Contains {
        #[serde(default, deserialize_with = "de_register_or_default")]
        register: ScanRegister,
        // Wire key is `value`: the serialized `EvaluatedValue` hex, per EIP-1
        // and Scala `ScanningPredicateJsonCodecs` (encoder emits `value`,
        // decoder reads `downField("value")`). The Scala swagger doc's `bytes`
        // is a drift from its own codec — `value` is what nodes accept/emit.
        #[serde(rename = "value", with = "hex_bytes")]
        value: Vec<u8>,
    },
    /// The register's evaluated value equals `value`. Scala
    /// `EqualsScanningPredicate.filter` is type-restricted, not a generic value
    /// equality: it matches **only** `Coll[Byte]`, `GroupElement`, `Boolean`,
    /// `Int`, and `Long` values (and returns false for any other type, e.g.
    /// tuples / `BigInt`). See [`equals_filter`].
    Equals {
        #[serde(default, deserialize_with = "de_register_or_default")]
        register: ScanRegister,
        // Wire key is `value` (see `Contains` above): serialized
        // `EvaluatedValue` hex, per EIP-1 / Scala `ScanningPredicateJsonCodecs`.
        #[serde(rename = "value", with = "hex_bytes")]
        value: Vec<u8>,
    },
    /// The box carries a token with this id.
    ContainsAsset {
        #[serde(rename = "assetId", with = "hex_32")]
        asset_id: [u8; 32],
    },
    /// All sub-predicates match.
    And { args: Vec<ScanningPredicate> },
    /// At least one sub-predicate matches.
    Or { args: Vec<ScanningPredicate> },
}

impl ScanningPredicate {
    /// Whether `b` satisfies this tracking rule (Scala
    /// `ScanningPredicate.filter(box)`).
    pub fn matches(&self, b: &ErgoBox) -> bool {
        match self {
            ScanningPredicate::ContainsAsset { asset_id } => b
                .candidate
                .tokens
                .iter()
                .any(|t| t.token_id.as_bytes() == asset_id),
            ScanningPredicate::And { args } => args.iter().all(|p| p.matches(b)),
            ScanningPredicate::Or { args } => args.iter().any(|p| p.matches(b)),
            ScanningPredicate::Contains { register, value } => {
                // Scala `ContainsScanningPredicate.filter`: only `Coll[Byte]` —
                // the predicate value and the register value must both be byte
                // arrays, then test contiguous-slice membership. Any other type
                // (on either side) -> false.
                match (
                    coll_bytes_of_constant(value),
                    register_coll_bytes(*register, b),
                ) {
                    (Some(needle), Some(haystack)) => contains_slice(&haystack, &needle),
                    _ => false,
                }
            }
            ScanningPredicate::Equals { register, value } => equals_filter(*register, value, b),
        }
    }
}

/// Mirror of Scala `EqualsScanningPredicate.filter`.
///
/// Scala does NOT compare arbitrary evaluated values — it matches on the
/// predicate value's type and only handles five constant types, returning false
/// for everything else (tuples, `BigInt`, generic collections, options, …):
///
/// ```text
/// value match {
///   case ByteArrayConstant(bytes) =>
///     box.get(regId).isDefined && box.get(regId).get.tpe == value.tpe &&
///       (box.get(regId) match { case ByteArrayConstant(arr) => arr.sameElements(bytes); case _ => false })
///   case GroupElementConstant(ge0) => box.get(regId) match { case GroupElementConstant(ge) => ge == ge0; ... }
///   case BooleanConstant(b0)       => box.get(regId) match { case BooleanConstant(b)       => b  == b0;  ... }
///   case IntConstant(i0)           => box.get(regId) match { case IntConstant(i)           => i  == i0;  ... }
///   case LongConstant(l0)          => box.get(regId) match { case IntConstant(l)           => l0 == l;   ... }
///   case _ => false
/// }
/// ```
fn equals_filter(register: ScanRegister, value: &[u8], b: &ErgoBox) -> bool {
    let Some((pred_tpe, pred_val)) = parse_constant(value) else {
        return false;
    };
    let Some((reg_tpe, reg_val)) = register_value(register, b) else {
        return false;
    };
    match (&pred_tpe, &pred_val) {
        // ByteArrayConstant: register must be a same-typed `Coll[Byte]` (Scala's
        // `tpe == value.tpe` guard), then exact byte equality (`sameElements`).
        (SigmaType::SColl(elem), SigmaValue::Coll(CollValue::Bytes(pred_bytes)))
            if **elem == SigmaType::SByte =>
        {
            reg_tpe == pred_tpe
                && matches!(&reg_val, SigmaValue::Coll(CollValue::Bytes(arr)) if arr == pred_bytes)
        }
        (SigmaType::SGroupElement, SigmaValue::GroupElement(pred_ge)) => {
            matches!(&reg_val, SigmaValue::GroupElement(ge) if ge == pred_ge)
        }
        (SigmaType::SBoolean, SigmaValue::Boolean(pred_b)) => {
            matches!(&reg_val, SigmaValue::Boolean(rb) if rb == pred_b)
        }
        (SigmaType::SInt, SigmaValue::Int(pred_i)) => {
            matches!(&reg_val, SigmaValue::Int(ri) if ri == pred_i)
        }
        // Scala quirk (faithfully reproduced): a `Long` predicate is compared
        // against an `Int` register — the inner case is `case IntConstant(l)`,
        // not `LongConstant`. So a Long predicate matches an Int register with
        // the same numeric value, and never matches a Long register. Kept for
        // observable parity with the reference node.
        (SigmaType::SLong, SigmaValue::Long(pred_l)) => {
            matches!(&reg_val, SigmaValue::Int(ri) if i64::from(*ri) == *pred_l)
        }
        _ => false,
    }
}

/// Decode a serialized constant (`EvaluatedValue` in plain constant form) to
/// `(type, value)`, requiring the whole byte slice to be consumed.
///
/// Every value type Scala's contains/equals predicates support (`Coll[Byte]`,
/// `GroupElement`, `Boolean`, `Int`, `Long`) is a plain constant, so
/// `read_constant` decodes all of them. Tuple / generic-collection values
/// (`CreateTuple` / `ConcreteCollection` expression form) are not supported by
/// those predicates — Scala returns false for them — so failing to decode them
/// here produces the same no-match result.
///
/// `None` means the bytes are not a well-formed constant; the matcher treats
/// that as "no match". Scala rejects a malformed `value` at its `/scan`
/// registration codec — the equivalent reject-at-decode lands with this node's
/// registration endpoint (a later slice), so a malformed rule never reaches the
/// matcher in practice.
fn parse_constant(bytes: &[u8]) -> Option<(SigmaType, SigmaValue)> {
    let mut r = VlqReader::new(bytes);
    let parsed = read_constant(&mut r).ok()?;
    // Trailing bytes mean a malformed predicate value; reject rather than match
    // on a partial decode.
    if r.position() == bytes.len() {
        Some(parsed)
    } else {
        None
    }
}

/// Decode a serialized constant and, if it is a `Coll[Byte]`, return its bytes.
fn coll_bytes_of_constant(bytes: &[u8]) -> Option<Vec<u8>> {
    match parse_constant(bytes)? {
        (_, SigmaValue::Coll(CollValue::Bytes(b))) => Some(b),
        _ => None,
    }
}

/// Deserialize the optional `register` field, treating both an absent field and
/// an explicit JSON `null` as the default (R1) — matching Scala's
/// `cursor.downField("register").as[Option[RegisterId]]`, where missing and
/// `null` both decode to `None` and fall back to `ErgoBox.R1`.
fn de_register_or_default<'de, D>(d: D) -> Result<ScanRegister, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<ScanRegister>::deserialize(d)?.unwrap_or_default())
}

/// The box register's evaluated value as `(type, value)`. R1 is the
/// propositionBytes (a `Coll[Byte]`); R4-R9 are the stored additional
/// registers. R0/R2/R3 are not evaluated in this slice (returns `None`).
fn register_value(register: ScanRegister, b: &ErgoBox) -> Option<(SigmaType, SigmaValue)> {
    match register {
        ScanRegister::R1 => Some((
            SigmaType::SColl(Box::new(SigmaType::SByte)),
            SigmaValue::Coll(CollValue::Bytes(b.candidate.ergo_tree_bytes().to_vec())),
        )),
        other => {
            let rid = other.additional()?;
            let rv = b.candidate.additional_registers.get(rid)?;
            Some((rv.tpe.clone(), rv.value.clone()))
        }
    }
}

/// The box register's value as raw bytes, when it is a `Coll[Byte]`.
fn register_coll_bytes(register: ScanRegister, b: &ErgoBox) -> Option<Vec<u8>> {
    match register_value(register, b)? {
        (_, SigmaValue::Coll(CollValue::Bytes(bytes))) => Some(bytes),
        _ => None,
    }
}

/// Scala `Coll.containsSlice`: is `needle` a contiguous sub-slice of `haystack`?
/// An empty needle is contained by everything.
fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Hex (de)serialization for the `value` byte field — Scala emits the
/// serialized constant as a hex string.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Hex (de)serialization for the 32-byte `assetId` token id.
mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("assetId must be 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_value::write_constant;
    use ergo_ser::token::{Token, TokenId};

    // ----- helpers -----

    /// Serialize a `Coll[Byte]` constant exactly as Scala does — type code
    /// `0x0e`, VLQ length, then the bytes (the form a scanning `value` field
    /// carries for a byte-array predicate).
    fn coll_byte_const(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x0e];
        ergo_primitives::vlq::encode_vlq_into(bytes.len() as u64, &mut out);
        out.extend_from_slice(bytes);
        out
    }

    fn trivial_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    fn box_with(tokens: Vec<Token>, registers: AdditionalRegisters) -> ErgoBox {
        let cand = ErgoBoxCandidate::new(1_000_000, trivial_tree(), 1, tokens, registers).unwrap();
        ErgoBox {
            candidate: cand,
            transaction_id: ModifierId::from_bytes([7u8; 32]),
            index: 0,
        }
    }

    fn token(fill: u8) -> Token {
        Token {
            token_id: TokenId::from_bytes([fill; 32]),
            amount: 1,
        }
    }

    fn coll_byte_register(bytes: &[u8]) -> AdditionalRegisters {
        AdditionalRegisters {
            registers: vec![RegisterValue {
                tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
                value: SigmaValue::Coll(CollValue::Bytes(bytes.to_vec())),
            }],
        }
    }

    /// Serialize a `(type, value)` as a plain constant (`ConstantSerializer`
    /// form) — the byte form a scan-predicate `value` field carries for the
    /// scalar types Scala's predicates support.
    fn const_bytes(tpe: &SigmaType, val: &SigmaValue) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_constant(&mut w, tpe, val).expect("serializable constant");
        w.result()
    }

    /// A pair `(SInt, SInt)` constant — a value type Scala's `equals` does NOT
    /// support (so it must never match, even against an identical register).
    fn int_pair(a: i32, c: i32) -> (SigmaType, SigmaValue) {
        (
            SigmaType::STuple(vec![SigmaType::SInt, SigmaType::SInt]),
            SigmaValue::Tuple(vec![SigmaValue::Int(a), SigmaValue::Int(c)]),
        )
    }

    /// An R4 register holding the given `(type, value)` constant.
    fn r4_register(tpe: SigmaType, value: SigmaValue) -> AdditionalRegisters {
        AdditionalRegisters {
            registers: vec![RegisterValue { tpe, value }],
        }
    }

    fn parse(json: &str) -> ScanningPredicate {
        serde_json::from_str(json).expect("valid predicate JSON")
    }

    // ----- JSON wire parity -----

    #[test]
    fn parses_contains_asset() {
        let p = parse(
            r#"{"predicate":"containsAsset","assetId":"1111111111111111111111111111111111111111111111111111111111111111"}"#,
        );
        assert_eq!(
            p,
            ScanningPredicate::ContainsAsset {
                asset_id: [0x11; 32]
            }
        );
        // round-trips back to the same shape
        assert_eq!(
            serde_json::from_str::<ScanningPredicate>(&serde_json::to_string(&p).unwrap()).unwrap(),
            p
        );
    }

    #[test]
    fn contains_register_defaults_to_r1() {
        // `register` absent -> R1 (Scala `register.getOrElse(ErgoBox.R1)`).
        // Wire key is `value` (EIP-1 + Scala `ScanningPredicateJsonCodecs`),
        // NOT `bytes` (which is a drifted key in the Scala swagger doc).
        let p = parse(r#"{"predicate":"contains","value":"0e020102"}"#);
        assert_eq!(
            p,
            ScanningPredicate::Contains {
                register: ScanRegister::R1,
                value: vec![0x0e, 0x02, 0x01, 0x02],
            }
        );
        // Serialize-direction: a real Scala node decodes `downField("value")`,
        // so we MUST emit `value` (and never `bytes`) for interop.
        let out = serde_json::to_string(&p).unwrap();
        assert!(
            out.contains(r#""value":"0e020102""#),
            "emits `value` key: {out}"
        );
        assert!(
            !out.contains("bytes"),
            "never emits the drifted `bytes` key: {out}"
        );
    }

    #[test]
    fn parses_equals_with_explicit_register_and_and_or() {
        let p = parse(
            r#"{"predicate":"and","args":[
                {"predicate":"equals","register":"R4","value":"0e020102"},
                {"predicate":"or","args":[{"predicate":"containsAsset","assetId":"2222222222222222222222222222222222222222222222222222222222222222"}]}
            ]}"#,
        );
        match p {
            ScanningPredicate::And { args } => {
                assert_eq!(args.len(), 2);
                assert!(matches!(
                    args[0],
                    ScanningPredicate::Equals {
                        register: ScanRegister::R4,
                        ..
                    }
                ));
                assert!(matches!(args[1], ScanningPredicate::Or { .. }));
            }
            other => panic!("expected And, got {other:?}"),
        }
    }

    // ----- matching semantics -----

    #[test]
    fn contains_asset_matches_only_held_tokens() {
        let b = box_with(vec![token(0x11)], AdditionalRegisters::empty());
        assert!(ScanningPredicate::ContainsAsset {
            asset_id: [0x11; 32]
        }
        .matches(&b));
        assert!(!ScanningPredicate::ContainsAsset {
            asset_id: [0x22; 32]
        }
        .matches(&b));
    }

    #[test]
    fn contains_r1_tests_proposition_bytes_subsequence() {
        let b = box_with(vec![], AdditionalRegisters::empty());
        let tree = b.candidate.ergo_tree_bytes().to_vec();
        // A genuine sub-slice of the propositionBytes matches; foreign bytes do not.
        let needle = &tree[1..3];
        assert!(ScanningPredicate::Contains {
            register: ScanRegister::R1,
            value: coll_byte_const(needle),
        }
        .matches(&b));
        assert!(!ScanningPredicate::Contains {
            register: ScanRegister::R1,
            value: coll_byte_const(&[0xFE, 0xFF, 0xFE, 0xFF]),
        }
        .matches(&b));
    }

    #[test]
    fn equals_r1_matches_exact_proposition_bytes_only() {
        let b = box_with(vec![], AdditionalRegisters::empty());
        let tree = b.candidate.ergo_tree_bytes().to_vec();
        assert!(ScanningPredicate::Equals {
            register: ScanRegister::R1,
            value: coll_byte_const(&tree),
        }
        .matches(&b));
        // A sub-slice is "contained" but not "equal".
        assert!(!ScanningPredicate::Equals {
            register: ScanRegister::R1,
            value: coll_byte_const(&tree[1..3]),
        }
        .matches(&b));
    }

    #[test]
    fn contains_and_equals_over_additional_register_r4() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let b = box_with(vec![], coll_byte_register(&payload));
        // contains a sub-slice
        assert!(ScanningPredicate::Contains {
            register: ScanRegister::R4,
            value: coll_byte_const(&[0xAD, 0xBE]),
        }
        .matches(&b));
        // equals the whole value
        assert!(ScanningPredicate::Equals {
            register: ScanRegister::R4,
            value: coll_byte_const(&payload),
        }
        .matches(&b));
        // a box without R4 cannot match
        let empty = box_with(vec![], AdditionalRegisters::empty());
        assert!(!ScanningPredicate::Contains {
            register: ScanRegister::R4,
            value: coll_byte_const(&[0xAD, 0xBE]),
        }
        .matches(&empty));
    }

    #[test]
    fn and_requires_all_or_requires_any() {
        let b = box_with(vec![token(0x11)], coll_byte_register(&[0x01, 0x02, 0x03]));
        let asset_hit = ScanningPredicate::ContainsAsset {
            asset_id: [0x11; 32],
        };
        let asset_miss = ScanningPredicate::ContainsAsset {
            asset_id: [0x99; 32],
        };
        let reg_hit = ScanningPredicate::Contains {
            register: ScanRegister::R4,
            value: coll_byte_const(&[0x02, 0x03]),
        };
        assert!(ScanningPredicate::And {
            args: vec![asset_hit.clone(), reg_hit.clone()]
        }
        .matches(&b));
        assert!(!ScanningPredicate::And {
            args: vec![asset_miss.clone(), reg_hit.clone()]
        }
        .matches(&b));
        assert!(ScanningPredicate::Or {
            args: vec![asset_miss, reg_hit]
        }
        .matches(&b));
    }

    #[test]
    fn unsupported_mandatory_register_does_not_match_yet() {
        // R0/R2/R3 parse but are not evaluated in this slice — they must
        // return false, never a spurious match.
        let b = box_with(vec![], AdditionalRegisters::empty());
        assert!(!ScanningPredicate::Equals {
            register: ScanRegister::R0,
            value: coll_byte_const(&[0x00]),
        }
        .matches(&b));
    }

    #[test]
    fn equals_supported_scalars_int_and_boolean() {
        // Scala `EqualsScanningPredicate.filter` supports Int and Boolean with
        // exact equality against a same-typed register.
        let bi = box_with(vec![], r4_register(SigmaType::SInt, SigmaValue::Int(7)));
        assert!(ScanningPredicate::Equals {
            register: ScanRegister::R4,
            value: const_bytes(&SigmaType::SInt, &SigmaValue::Int(7)),
        }
        .matches(&bi));
        assert!(!ScanningPredicate::Equals {
            register: ScanRegister::R4,
            value: const_bytes(&SigmaType::SInt, &SigmaValue::Int(8)),
        }
        .matches(&bi));

        let bb = box_with(
            vec![],
            r4_register(SigmaType::SBoolean, SigmaValue::Boolean(true)),
        );
        assert!(ScanningPredicate::Equals {
            register: ScanRegister::R4,
            value: const_bytes(&SigmaType::SBoolean, &SigmaValue::Boolean(true)),
        }
        .matches(&bb));
        assert!(!ScanningPredicate::Equals {
            register: ScanRegister::R4,
            value: const_bytes(&SigmaType::SBoolean, &SigmaValue::Boolean(false)),
        }
        .matches(&bb));
    }

    #[test]
    fn equals_long_matches_int_register_scala_quirk() {
        // Scala quirk: `case LongConstant(long) => box.get match { case
        // IntConstant(l) => long == l }`. A Long predicate matches an *Int*
        // register with the same numeric value, and never a Long register.
        let long_value = const_bytes(&SigmaType::SLong, &SigmaValue::Long(5));

        // Int register with the same value -> MATCH (the quirk).
        let int_reg = box_with(vec![], r4_register(SigmaType::SInt, SigmaValue::Int(5)));
        assert!(
            ScanningPredicate::Equals {
                register: ScanRegister::R4,
                value: long_value.clone(),
            }
            .matches(&int_reg),
            "Long predicate matches an Int register of equal value (Scala quirk)"
        );

        // Long register -> NO match (the inner case is IntConstant only).
        let long_reg = box_with(vec![], r4_register(SigmaType::SLong, SigmaValue::Long(5)));
        assert!(
            !ScanningPredicate::Equals {
                register: ScanRegister::R4,
                value: long_value,
            }
            .matches(&long_reg),
            "Long predicate never matches a Long register (Scala quirk)"
        );
    }

    #[test]
    fn equals_rejects_unsupported_value_types() {
        // Scala's equals handles only ByteArray/GroupElement/Boolean/Int/Long
        // and returns false for everything else — even when the register holds
        // the identical value. A tuple is the canonical unsupported type.
        let (tpe, val) = int_pair(1, 2);
        let b = box_with(vec![], r4_register(tpe.clone(), val.clone()));
        // The predicate value decodes fine (a Constant[(Int,Int)]), but the
        // type is unsupported, so the box must NOT match.
        assert!(
            !ScanningPredicate::Equals {
                register: ScanRegister::R4,
                value: const_bytes(&tpe, &val),
            }
            .matches(&b),
            "equals must not match an unsupported (tuple) value type"
        );
    }

    #[test]
    fn register_null_deserializes_to_default_r1() {
        // Scala decodes `register` via `as[Option[RegisterId]]`: both a missing
        // field and explicit `null` mean `None` -> R1. `#[serde(default)]`
        // alone only covers the missing case, so an explicit null must be
        // handled by the custom deserializer.
        let p = parse(r#"{"predicate":"equals","register":null,"value":"0e020102"}"#);
        assert!(matches!(
            p,
            ScanningPredicate::Equals {
                register: ScanRegister::R1,
                ..
            }
        ));
        // An invalid register string is still rejected (not silently defaulted).
        assert!(
            serde_json::from_str::<ScanningPredicate>(
                r#"{"predicate":"equals","register":"R99","value":"0e020102"}"#,
            )
            .is_err(),
            "an invalid register name must be a decode error"
        );
    }

    #[test]
    fn malformed_predicate_value_never_matches() {
        // A `value` that is not a well-formed serialized value yields no match
        // (parse fails -> false), never a spurious hit. Scala rejects such a
        // value at its `/scan` registration codec; this node's registration
        // boundary (a later PR) will reject it the same way, so a malformed
        // rule never reaches the matcher in practice. Pinned here so the
        // matcher's defensive no-match stays deliberate.
        let b = box_with(vec![], coll_byte_register(&[0x01, 0x02, 0x03]));
        // 0xFF is neither a valid type code (<=0x70) nor a valid opcode.
        let garbage = vec![0xFF, 0xFF, 0xFF];
        assert!(!ScanningPredicate::Equals {
            register: ScanRegister::R4,
            value: garbage.clone(),
        }
        .matches(&b));
        assert!(!ScanningPredicate::Contains {
            register: ScanRegister::R4,
            value: garbage,
        }
        .matches(&b));
    }
}

//! Sigma type-descriptor wire codec.
//!
//! Split by direction:
//!
//! * `mod.rs` — the [`SigmaType`] enum, the constructor-id / type-code
//!   constants shared by both directions, and the version-gating helpers
//!   (`V6_EMBEDDABLE_TREE_VERSION`, `embeddable_gate_version`,
//!   `prim_from_code`).
//! * `write.rs` — [`write_type`] and its per-constructor helpers.
//! * `read.rs` — [`read_type`] / [`decode_type`] and the depth-tracked
//!   recursive decoders.

use ergo_primitives::reader::{ReadError, VlqReader};

mod read;
mod write;

pub use read::{decode_type, read_type};
pub use write::write_type;

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

/// Maximum nesting depth for `read_type` recursion — a stack-overflow guard,
/// NOT a faithful consensus boundary. Scala applies NO type-descriptor depth
/// limit: `TypeSerializer.deserialize` threads a `depth` parameter but never
/// checks it, and the `CoreByteReader.level` / `SigmaConstants.MaxTreeDepth`
/// (=110) mechanism is incremented only by the value/expression serializers
/// (`ValueSerializer`, `DataSerializer`, `SigmaBoolean`), never by
/// `TypeSerializer`. The only real Scala bound on type-descriptor nesting is
/// the reader position limit = `SigmaConstants.MaxPropositionBytes` (4096),
/// since each `Coll`/`Option` level costs one type byte.
///
/// We deliberately keep a *conservative* recursion bound rather than the true
/// 4096 ceiling: `read_type` is recursive descent, and ~4096-deep recursion
/// overflows the native stack (a worse failure than the reject-valid it would
/// cure). So a type descriptor nested 101..4096 deep — which Scala accepts —
/// is rejected here. That divergence is theoretical (no consensus-reachable
/// mainnet box nests type descriptors anywhere near this deep) and strictly
/// safer than crashing. Full parity needs an iterative (heap-stack) `read_type`
/// that can absorb a 4 KB-deep chain without native recursion; that rewrite is
/// tracked as a follow-up, not attempted here.
const MAX_TYPE_DEPTH: usize = 100;

/// Sigma type descriptors used by the Ergo protocol for serializing
/// typed values.
///
/// The encoding is designed so that common types (a primitive element
/// inside a collection or option) fit in a single byte. The "embeddable"
/// types (`SBoolean..=SUnsignedBigInt`) get codes 1..=9 — 1..=8 in the V5
/// set, plus `SUnsignedBigInt` = 9 in the V6 set — and can be packed into
/// the constructor byte of a higher-kinded type (`SColl`, `SOption`,
/// `STuple` of pairs). Codes 10 and 11 are NOT embeddable types: they only
/// exist so the primitive-code range (`MaxPrimTypeCode = 11`) yields clean
/// constructor multipliers. The reader rejects codes 10/11 and the writer
/// refuses to emit the reserved variants below.
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
    /// Reserved primitive-code slot 10 — NOT an embeddable type. Outside the
    /// Scala embeddable set (1..=8 V5 / 1..=9 V6); the reader rejects code 10
    /// and the writer refuses to serialize this variant.
    SReserved10,
    /// Reserved primitive-code slot 11 — NOT an embeddable type (see
    /// [`SigmaType::SReserved10`]). Reader rejects code 11; writer refuses it.
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
            // Codes 10/11 are outside the Scala embeddable set (1..=8 V5,
            // 1..=9 V6); SReserved10/11 are not embeddable and never emitted.
            _ => None,
        }
    }
}

/// ErgoTree version at/above which the v6/EIP-50 embeddable set (`embeddableV6`,
/// adding `SUnsignedBigInt` = code 9) is in effect; below it Scala uses
/// `embeddableV5` (codes 1..=8). Matches `isV3OrLaterErgoTreeVersion`.
const V6_EMBEDDABLE_TREE_VERSION: u8 = 3;

/// The version used to gate embeddable type codes.
///
/// Scala's `TypeSerializer.getEmbeddableType` selects `embeddableV5` vs
/// `embeddableV6` by `VersionContext.current.isV6Activated` — the ACTIVATED
/// version (`VersionContext.scala:33`, `activatedVersion >= V6SoftForkVersion`),
/// NOT the tree header. On the consensus path this crate uses the body's header
/// version as the gate (the activated version is not threaded through the
/// byte-level reader): a headerless register/context-var value falls back to the
/// v6 set, and a v0/v1/v2-header tree body gates on that header version.
///
/// The ergo-compiler self-check needs the true activated axis: it emits a
/// header-v0 tree whose body may carry a V6 type code that a `tree_version >= 3`
/// (V6-activated) compile legitimately produces and Scala re-parses. It sets
/// [`VlqReader::set_embeddable_activated_version`]; when present, that override
/// takes precedence here, mirroring Scala's activated-version gate exactly.
/// `None` (every consensus caller) keeps the header-version fallback — byte-inert.
fn embeddable_gate_version(r: &VlqReader) -> u8 {
    r.embeddable_activated_version()
        .unwrap_or_else(|| r.ergo_tree_version().unwrap_or(V6_EMBEDDABLE_TREE_VERSION))
}

fn prim_from_code(code: u8, gate_version: u8) -> Result<SigmaType, ReadError> {
    match code {
        1 => Ok(SigmaType::SBoolean),
        2 => Ok(SigmaType::SByte),
        3 => Ok(SigmaType::SShort),
        4 => Ok(SigmaType::SInt),
        5 => Ok(SigmaType::SLong),
        6 => Ok(SigmaType::SBigInt),
        7 => Ok(SigmaType::SGroupElement),
        8 => Ok(SigmaType::SSigmaProp),
        // `SUnsignedBigInt` (code 9) is in `embeddableV6` only: a pre-v3 tree's
        // `getEmbeddableType` selects `embeddableV5` (length 9 → code 9 out of
        // range) and throws a soft `ValidationException` (rule 1016), which
        // `deserializeErgoTree` catches → `UnparsedErgoTree` under has_size, and
        // hard-rejects sizeless. The node previously accepted code 9 at any
        // version and then hard-rejected on the bigint value read — a reject-valid.
        9 if gate_version >= V6_EMBEDDABLE_TREE_VERSION => Ok(SigmaType::SUnsignedBigInt),
        9 => Err(ReadError::InvalidData(format!(
            "embeddable type SUnsignedBigInt (code 9) requires ErgoTree version >= {V6_EMBEDDABLE_TREE_VERSION}, got tree version {gate_version}"
        ))),
        // Codes 10 and 11 are NOT in the Scala embeddable set (`embeddableV5`
        // length 9 → codes 1..=8; `embeddableV6` length 10 → codes 1..=9).
        // Scala's `getEmbeddableType` indexes those arrays and throws on an
        // out-of-range code; accepting them as SReserved10/11 was accept-invalid.
        _ => Err(ReadError::InvalidData(format!(
            "invalid embeddable type code: {code}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity -----

    /// `SUnsignedBigInt` (embeddable code 9) is in `embeddableV6` only: Scala's
    /// `getEmbeddableType` selects `embeddableV5` (codes 1..=8) for a pre-v3 tree
    /// and throws, vs `embeddableV6` (adds code 9) at v3+. The version-gated
    /// `prim_from_code` must match: reject code 9 below v3, accept at v3+. Codes
    /// 1..=8 are version-independent.
    #[test]
    fn unsigned_bigint_embeddable_code_gated_by_tree_version() {
        for v in 0u8..=2 {
            assert!(
                prim_from_code(9, v).is_err(),
                "code 9 (SUnsignedBigInt) must be rejected at tree version {v} (embeddableV5)"
            );
        }
        for v in 3u8..=4 {
            assert_eq!(
                prim_from_code(9, v).unwrap(),
                SigmaType::SUnsignedBigInt,
                "code 9 must resolve at tree version {v} (embeddableV6)"
            );
        }
        // The v5 embeddables (1..=8) are version-independent.
        for code in 1u8..=8 {
            assert!(prim_from_code(code, 0).is_ok());
            assert!(prim_from_code(code, 3).is_ok());
        }
        // A headerless context (None → v6 default) admits code 9 at the TYPE layer
        // (the value gate rejects the unsigned-bigint value separately).
        let mut r = VlqReader::new(&[]);
        assert_eq!(embeddable_gate_version(&r), V6_EMBEDDABLE_TREE_VERSION);
        r.set_ergo_tree_version(Some(1));
        assert_eq!(embeddable_gate_version(&r), 1);
    }

    /// F1: the activated-version OVERRIDE
    /// ([`VlqReader::set_embeddable_activated_version`]) takes precedence over the
    /// header version for embeddable-code gating — mirroring Scala
    /// `getEmbeddableType` gating on `VersionContext.isV6Activated` (the ACTIVATED
    /// version), NOT the tree header. A header-v0 reader with an activated
    /// override of 3 admits code 9; the default (`None`) keeps header-version
    /// gating (byte-inert for consensus callers).
    #[test]
    fn embeddable_activated_version_override_wins_over_header() {
        let mut r = VlqReader::new(&[]);
        // Header v0, no override → strict v5 set, code 9 rejected.
        r.set_ergo_tree_version(Some(0));
        assert_eq!(embeddable_gate_version(&r), 0);
        assert!(prim_from_code(9, embeddable_gate_version(&r)).is_err());
        // Header v0 but activated override = 3 → code 9 admitted at the TYPE layer.
        r.set_embeddable_activated_version(Some(3));
        assert_eq!(embeddable_gate_version(&r), 3);
        assert_eq!(
            prim_from_code(9, embeddable_gate_version(&r)).unwrap(),
            SigmaType::SUnsignedBigInt
        );
        // An override BELOW v3 keeps the strict gate (an activated < V6 network).
        r.set_embeddable_activated_version(Some(2));
        assert_eq!(embeddable_gate_version(&r), 2);
        assert!(prim_from_code(9, embeddable_gate_version(&r)).is_err());
        // Clearing the override restores header-version gating (the consensus
        // default) — the knob is byte-inert once removed.
        r.set_embeddable_activated_version(None);
        assert_eq!(embeddable_gate_version(&r), 0);
    }
}

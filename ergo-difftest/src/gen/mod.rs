//! Structure-aware generators for the SER (wire-format) surfaces.
//!
//! This is the high-signal replacement for the byte-mutation baseline in
//! [`crate::generate`]. Where that flips bytes on a corpus, these generators
//! ASSEMBLE bytes at real grammar positions and place per-position adversarial
//! values the `ergo-ser` writers never emit — non-canonical VLQ, out-of-band
//! field bytes, ill-formed sub-fields — each mapped to a known SER bug it must
//! be able to reach (see [`Feature::bug_id`]).
//!
//! Every surface generator offers two complementary modes, chosen per call:
//!
//! * [`GenMode::OnManifold`] — build a VALID structure and serialize it via the
//!   real `ergo-ser` writers. Guarantees seeds the reference accepts, and
//!   `intended_valid` is `true`.
//! * [`GenMode::Adversarial`] — hand-assemble the wire bytes so a value can sit
//!   at a position the writers cannot produce. `intended_valid` is set honestly
//!   (true only when we believe the reference parses the result).
//!
//! Determinism: [`gen_structured_at`] maps a `(seed, iter, surface)` triple to
//! an identical [`GenOutput`], so any finding is reproducible.

use crate::rng::Rng;

pub(crate) mod asm;
mod box_candidate;
mod constant;
mod ergo_tree;
mod header;
mod transaction;

/// The SER surfaces a structured generator targets. Names match the hermetic
/// surface registry ([`crate::surfaces::registry`]) so a [`GenOutput`] can be
/// fed straight through [`crate::run_one`].
pub const SURFACES: [&str; 5] = [
    "ergo_tree",
    "constant",
    "ergo_box_candidate",
    "transaction",
    "header",
];

/// An adversarial wire feature a generator can place at a real grammar
/// position. `FeatureSet` records which of these a campaign touched, so
/// coverage of the bug surface is measurable and a gap is provable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Feature {
    /// A fully-valid structure serialized by the real writers (mode A).
    OnManifoldValid = 0,
    /// Header version byte in `0x80..=0xFF` (signed-Byte grammar gate).
    HeaderVersionHighBit,
    /// ErgoTree header version bits set to a non-zero layout version (`1..=7`).
    TreeVersionNonZero,
    /// ErgoTree header size bit set (size-delimited body).
    TreeSizeBit,
    /// ErgoTree header constant-segregation bit set.
    TreeConstSegBit,
    /// A sizeless ErgoTree whose determinable root type is NOT `SSigmaProp`.
    TreeSigmaPropRootViolation,
    /// A size-delimited ErgoTree whose declared size field ≠ actual body length.
    TreeDeclaredSizeMismatch,
    /// `FunDef` (0xD7) with an `nTpeArgs` byte in `0x80..=0xFF` (negative-as-signed).
    FunDefNTpeArgsHighBit,
    /// An `STypeVar` name that is ill-formed UTF-8 (e.g. `ED A0 80`).
    STypeVarIllFormedUtf8,
    /// A count / id VLQ just above `i32::MAX` (`80 80 80 80 08`).
    VlqAboveI32Max,
    /// Type code 9 (`SUnsignedBigInt`) placed in a pre-v3 tree.
    UnsignedBigIntTypePreV3,
    /// A `Relation2` operator over two boolean `Const`s (compact `0x85` form).
    Relation2CompactBoolPair,
    /// A box register typed `SOption` / `SHeader` / `SUnsignedBigInt` (v6 types).
    RegisterV6Type,
    /// A 33-byte group element, prefix `0x02`/`0x03`, with an off-curve x.
    OffCurveGroupElement,
    /// A transaction with an empty output-candidate list.
    TxEmptyOutputs,
    /// An output box token entry with amount 0.
    TxZeroAmountToken,
}

impl Feature {
    /// Every feature, in declaration order.
    pub const ALL: [Feature; 16] = [
        Feature::OnManifoldValid,
        Feature::HeaderVersionHighBit,
        Feature::TreeVersionNonZero,
        Feature::TreeSizeBit,
        Feature::TreeConstSegBit,
        Feature::TreeSigmaPropRootViolation,
        Feature::TreeDeclaredSizeMismatch,
        Feature::FunDefNTpeArgsHighBit,
        Feature::STypeVarIllFormedUtf8,
        Feature::VlqAboveI32Max,
        Feature::UnsignedBigIntTypePreV3,
        Feature::Relation2CompactBoolPair,
        Feature::RegisterV6Type,
        Feature::OffCurveGroupElement,
        Feature::TxEmptyOutputs,
        Feature::TxZeroAmountToken,
    ];

    /// Stable identifier for reports.
    pub fn name(self) -> &'static str {
        match self {
            Feature::OnManifoldValid => "on_manifold_valid",
            Feature::HeaderVersionHighBit => "header_version_high_bit",
            Feature::TreeVersionNonZero => "tree_version_nonzero",
            Feature::TreeSizeBit => "tree_size_bit",
            Feature::TreeConstSegBit => "tree_const_seg_bit",
            Feature::TreeSigmaPropRootViolation => "tree_sigmaprop_root_violation",
            Feature::TreeDeclaredSizeMismatch => "tree_declared_size_mismatch",
            Feature::FunDefNTpeArgsHighBit => "fundef_ntpeargs_high_bit",
            Feature::STypeVarIllFormedUtf8 => "stypevar_illformed_utf8",
            Feature::VlqAboveI32Max => "vlq_above_i32_max",
            Feature::UnsignedBigIntTypePreV3 => "unsigned_bigint_type_pre_v3",
            Feature::Relation2CompactBoolPair => "relation2_compact_bool_pair",
            Feature::RegisterV6Type => "register_v6_type",
            Feature::OffCurveGroupElement => "off_curve_group_element",
            Feature::TxEmptyOutputs => "tx_empty_outputs",
            Feature::TxZeroAmountToken => "tx_zero_amount_token",
        }
    }

    /// The known-bug id this feature is the wire surface for, if any. A
    /// campaign that never touches the feature provably cannot reach the bug.
    pub fn bug_id(self) -> Option<&'static str> {
        match self {
            Feature::OnManifoldValid | Feature::TreeConstSegBit => None,
            Feature::HeaderVersionHighBit => Some("#8"),
            Feature::TreeVersionNonZero => Some("#17"),
            Feature::TreeSizeBit => Some("#9"),
            Feature::TreeSigmaPropRootViolation => Some("#25"),
            Feature::TreeDeclaredSizeMismatch => Some("#19"),
            Feature::FunDefNTpeArgsHighBit => Some("#14"),
            Feature::STypeVarIllFormedUtf8 => Some("#1"),
            Feature::VlqAboveI32Max => Some("#20"),
            Feature::UnsignedBigIntTypePreV3 => Some("#21"),
            Feature::Relation2CompactBoolPair => Some("#12"),
            Feature::RegisterV6Type => Some("#5"),
            Feature::OffCurveGroupElement => Some("#4"),
            Feature::TxEmptyOutputs | Feature::TxZeroAmountToken => Some("#23"),
        }
    }

    #[inline]
    fn bit(self) -> u32 {
        1u32 << (self as u8)
    }
}

/// A compact set of [`Feature`]s (bitset over the 16 features).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeatureSet(u32);

impl FeatureSet {
    /// The empty set.
    pub const fn empty() -> FeatureSet {
        FeatureSet(0)
    }

    /// Add `f` to the set.
    pub fn insert(&mut self, f: Feature) {
        self.0 |= f.bit();
    }

    /// `true` if `f` is present.
    pub fn contains(&self, f: Feature) -> bool {
        self.0 & f.bit() != 0
    }

    /// Set union (accumulate coverage).
    pub fn union(&self, other: &FeatureSet) -> FeatureSet {
        FeatureSet(self.0 | other.0)
    }

    /// In-place union.
    pub fn extend(&mut self, other: &FeatureSet) {
        self.0 |= other.0;
    }

    /// Set intersection.
    pub fn intersect(&self, other: &FeatureSet) -> FeatureSet {
        FeatureSet(self.0 & other.0)
    }

    /// Features in `self` but not in `other`.
    pub fn difference(&self, other: &FeatureSet) -> FeatureSet {
        FeatureSet(self.0 & !other.0)
    }

    /// Number of features present.
    pub fn len(&self) -> u32 {
        self.0.count_ones()
    }

    /// `true` if no features are present.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Iterate the present features in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = Feature> + '_ {
        Feature::ALL.into_iter().filter(move |f| self.contains(*f))
    }
}

impl FromIterator<Feature> for FeatureSet {
    fn from_iter<I: IntoIterator<Item = Feature>>(it: I) -> FeatureSet {
        let mut s = FeatureSet::empty();
        for f in it {
            s.insert(f);
        }
        s
    }
}

/// Which construction mode produced a [`GenOutput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenMode {
    /// Valid structure serialized by the real writers.
    OnManifold,
    /// Hand-assembled adversarial wire bytes.
    Adversarial,
}

/// One structured generator output: the bytes, which SER surface they target,
/// whether the reference is believed to accept them, and the adversarial
/// features they touched. This is the generator output contract.
#[derive(Debug, Clone)]
pub struct GenOutput {
    /// Target SER surface name (one of [`SURFACES`]).
    pub surface: &'static str,
    /// The generated wire bytes.
    pub bytes: Vec<u8>,
    /// `true` only when we believe the reference (Scala) parses these bytes.
    pub intended_valid: bool,
    /// The construction mode.
    pub mode: GenMode,
    /// Adversarial features placed in `bytes`.
    pub features: FeatureSet,
}

/// Dispatch to the per-surface structured generator.
pub fn gen_structured(rng: &mut Rng, surface: &str) -> GenOutput {
    match surface {
        "ergo_tree" => ergo_tree::gen(rng),
        "constant" => constant::gen(rng),
        "ergo_box_candidate" => box_candidate::gen(rng),
        "transaction" => transaction::gen(rng),
        "header" => header::gen(rng),
        other => {
            debug_assert!(false, "gen_structured: unknown surface {other:?}");
            // Fall back to the crown-jewel surface rather than panic in a
            // release campaign (the CLI validates the surface name up front).
            ergo_tree::gen(rng)
        }
    }
}

/// Force an ON-MANIFOLD (mode A) output for `surface`. Used by the
/// "mode A is mostly accepted" sanity test and by callers wanting valid seeds.
pub fn gen_on_manifold(rng: &mut Rng, surface: &str) -> GenOutput {
    match surface {
        "ergo_tree" => ergo_tree::gen_valid(rng),
        "constant" => constant::gen_valid(rng),
        "ergo_box_candidate" => box_candidate::gen_valid(rng),
        "transaction" => transaction::gen_valid(rng),
        "header" => header::gen_valid(rng),
        other => {
            debug_assert!(false, "gen_on_manifold: unknown surface {other:?}");
            ergo_tree::gen_valid(rng)
        }
    }
}

/// Deterministically reproduce the `(seed, iter, surface)` output. The campaign
/// derives a fresh, decorrelated sub-seed per triple so an identical triple
/// yields identical bytes regardless of surface iteration order.
pub fn gen_structured_at(seed: u64, iter: u64, surface: &str) -> GenOutput {
    let mut rng = Rng::new(derive_seed(seed, iter, surface));
    gen_structured(&mut rng, surface)
}

/// SplitMix-style mixing of `(seed, iter, surface)` into a decorrelated PRNG
/// seed. Any change to the triple changes the seed; equal triples are equal.
fn derive_seed(seed: u64, iter: u64, surface: &str) -> u64 {
    let mut z = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(iter.wrapping_mul(0xD1B5_4A32_D192_ED03))
        .wrapping_add(fnv1a64(surface));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// The full set of adversarial features a surface's generator SHOULD cover.
/// The coverage test asserts a campaign reaches every one of these — a
/// generator that cannot emit a declared feature is a real gap, not a pass.
pub fn declared_vocabulary(surface: &str) -> FeatureSet {
    use Feature::*;
    let features: &[Feature] = match surface {
        "ergo_tree" => &[
            OnManifoldValid,
            TreeVersionNonZero,
            TreeSizeBit,
            TreeConstSegBit,
            TreeSigmaPropRootViolation,
            TreeDeclaredSizeMismatch,
            FunDefNTpeArgsHighBit,
            STypeVarIllFormedUtf8,
            VlqAboveI32Max,
            UnsignedBigIntTypePreV3,
            Relation2CompactBoolPair,
            OffCurveGroupElement,
        ],
        "constant" => &[OnManifoldValid, OffCurveGroupElement, VlqAboveI32Max],
        "ergo_box_candidate" => &[
            OnManifoldValid,
            TreeSigmaPropRootViolation,
            TreeVersionNonZero,
            RegisterV6Type,
            TxZeroAmountToken,
            OffCurveGroupElement,
        ],
        "transaction" => &[OnManifoldValid, TxEmptyOutputs, TxZeroAmountToken],
        "header" => &[OnManifoldValid, HeaderVersionHighBit],
        _ => &[],
    };
    FeatureSet::from_iter(features.iter().copied())
}

/// Coverage of one surface's declared vocabulary by a campaign.
#[derive(Debug, Clone)]
pub struct SurfaceCoverage {
    /// Surface name.
    pub surface: &'static str,
    /// Features actually touched by the campaign.
    pub touched: FeatureSet,
    /// Features the surface should cover ([`declared_vocabulary`]).
    pub declared: FeatureSet,
}

impl SurfaceCoverage {
    /// Fraction of the declared vocabulary that was touched (0.0..=1.0).
    pub fn ratio(&self) -> f64 {
        let declared = self.declared.len();
        if declared == 0 {
            return 1.0;
        }
        self.touched.intersect(&self.declared).len() as f64 / declared as f64
    }

    /// Declared features the campaign never reached.
    pub fn missing(&self) -> FeatureSet {
        self.declared.difference(&self.touched)
    }
}

/// Per-surface coverage union for a whole campaign.
#[derive(Debug, Clone, Default)]
pub struct Coverage(pub Vec<SurfaceCoverage>);

impl Coverage {
    /// Union of every surface's touched features.
    pub fn total_touched(&self) -> FeatureSet {
        self.0
            .iter()
            .fold(FeatureSet::empty(), |acc, c| acc.union(&c.touched))
    }

    /// Union of every surface's declared vocabulary.
    pub fn total_declared(&self) -> FeatureSet {
        self.0
            .iter()
            .fold(FeatureSet::empty(), |acc, c| acc.union(&c.declared))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_bits_are_distinct() {
        let mut s = FeatureSet::empty();
        for f in Feature::ALL {
            assert!(!s.contains(f), "duplicate bit for {}", f.name());
            s.insert(f);
        }
        assert_eq!(s.len(), Feature::ALL.len() as u32);
    }

    #[test]
    fn declared_vocab_names_are_known_surfaces() {
        for surf in SURFACES {
            assert!(
                !declared_vocabulary(surf).is_empty(),
                "surface {surf} has an empty declared vocabulary"
            );
        }
    }

    #[test]
    fn derive_seed_is_stable_and_surface_sensitive() {
        assert_eq!(
            derive_seed(7, 3, "ergo_tree"),
            derive_seed(7, 3, "ergo_tree")
        );
        assert_ne!(derive_seed(7, 3, "ergo_tree"), derive_seed(7, 3, "header"));
        assert_ne!(
            derive_seed(7, 3, "ergo_tree"),
            derive_seed(7, 4, "ergo_tree")
        );
    }
}

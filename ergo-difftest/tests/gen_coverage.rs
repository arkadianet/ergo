//! Proof that the structure-aware generators emit SIGNAL, not theater.
//!
//! These tests are the acceptance gate for the generator: they assert the
//! coverage union reaches every declared adversarial feature (a generator that
//! never emits `nTpeArgs >= 0x80` provably cannot find bug #14, and the test
//! catches that), that generation is deterministic, that on-manifold seeds are
//! accepted by our own decoder, and that each adversarial feature actually
//! lands on the intended codec code path with the intended verdict.

use ergo_difftest::gen::{
    self, declared_vocabulary, gen_on_manifold, gen_structured_at, Feature, FeatureSet,
};
use ergo_difftest::rng::Rng;
use ergo_difftest::{run_input, run_structured_campaign, Outcome};

/// Run the surface's own hermetic decoder over `bytes` and return the outcome.
fn hermetic_outcome(surface: &str, bytes: &[u8]) -> Outcome {
    run_input(bytes, Some(surface))
        .into_iter()
        .find(|(name, _)| *name == surface)
        .map(|(_, outcome)| outcome)
        .unwrap_or_else(|| panic!("no hermetic surface named {surface}"))
}

/// Collect the hermetic outcomes for every generated output (at `seed`,
/// `0..iters`) whose feature set contains `feature`.
fn outcomes_for_feature(surface: &str, feature: Feature, seed: u64, iters: u64) -> Vec<Outcome> {
    let mut out = Vec::new();
    for iter in 0..iters {
        let g = gen_structured_at(seed, iter, surface);
        if g.features.contains(feature) {
            out.push(hermetic_outcome(surface, &g.bytes));
        }
    }
    out
}

// ------------------------------------------------------------------
// (1) Coverage: each surface reaches every declared adversarial feature.
// ------------------------------------------------------------------

#[test]
fn each_surface_reaches_full_declared_vocabulary() {
    const MAX_ITERS: u64 = 40_000;
    for surface in gen::SURFACES {
        let declared = declared_vocabulary(surface);
        let mut touched = FeatureSet::empty();
        for iter in 0..MAX_ITERS {
            touched.extend(&gen_structured_at(1, iter, surface).features);
            if declared.difference(&touched).is_empty() {
                break;
            }
        }
        let missing = declared.difference(&touched);
        assert!(
            missing.is_empty(),
            "surface {surface} never emitted declared feature(s): {:?} in {MAX_ITERS} iters",
            missing.iter().map(Feature::name).collect::<Vec<_>>(),
        );
    }
}

#[test]
fn full_campaign_union_covers_every_bug_mapped_feature() {
    // The union across all surfaces must reach every feature that maps to a
    // catalog bug id — otherwise the harness silently loses a bug surface.
    let (_stats, coverage, _findings) = run_structured_campaign(7, 8_000, None, &[]);
    let touched = coverage.total_touched();
    for f in Feature::ALL {
        if f.bug_id().is_some() {
            assert!(
                touched.contains(f),
                "no surface reached bug-mapped feature {} ({:?})",
                f.name(),
                f.bug_id(),
            );
        }
    }
}

// ------------------------------------------------------------------
// (2) Determinism: same (seed, iter, surface) → identical bytes.
// ------------------------------------------------------------------

#[test]
fn same_seed_iter_surface_is_deterministic() {
    for surface in gen::SURFACES {
        for iter in [0u64, 1, 7, 42, 100, 9_999, 39_999] {
            let a = gen_structured_at(2024, iter, surface);
            let b = gen_structured_at(2024, iter, surface);
            assert_eq!(a.bytes, b.bytes, "bytes differ: {surface} iter {iter}");
            assert_eq!(
                a.features, b.features,
                "features differ: {surface} iter {iter}"
            );
            assert_eq!(a.mode, b.mode, "mode differs: {surface} iter {iter}");
        }
    }
}

#[test]
fn distinct_iters_produce_distinct_bytes() {
    // Sanity: the per-iter sub-seed actually decorrelates output (a stuck
    // generator that ignored `iter` would be a silent coverage collapse).
    for surface in gen::SURFACES {
        let a = gen_structured_at(5, 0, surface).bytes;
        let b = gen_structured_at(5, 1, surface).bytes;
        let c = gen_structured_at(5, 2, surface).bytes;
        assert!(
            a != b || b != c,
            "surface {surface} produced identical bytes across 3 iters"
        );
    }
}

// ------------------------------------------------------------------
// (3) On-manifold seeds are accepted by our own decoder at a high rate.
// ------------------------------------------------------------------

#[test]
fn on_manifold_outputs_are_mostly_accepted() {
    const TOTAL: usize = 3_000;
    for (i, surface) in gen::SURFACES.iter().enumerate() {
        let mut rng = Rng::new(0xA5A5_0000 ^ (i as u64));
        let mut accepted = 0usize;
        for _ in 0..TOTAL {
            let g = gen_on_manifold(&mut rng, surface);
            assert!(
                g.intended_valid,
                "mode A must set intended_valid: {surface}"
            );
            match hermetic_outcome(surface, &g.bytes) {
                Outcome::Accepted => accepted += 1,
                Outcome::Bug(detail) => panic!("mode A produced a Bug on {surface}: {detail}"),
                other => panic!("mode A produced {other:?} on {surface} (miscalibrated seed)"),
            }
        }
        let ratio = accepted as f64 / TOTAL as f64;
        assert!(
            ratio > 0.95,
            "surface {surface}: on-manifold accept ratio {ratio:.3} is too low"
        );
    }
}

// ------------------------------------------------------------------
// (4) No structured input ever trips a hermetic invariant (no-panic /
//     no fixed-point break). Rejecting malformed input is correct; a Bug
//     would be a real decoder defect.
// ------------------------------------------------------------------

#[test]
fn structured_campaign_never_produces_a_bug() {
    let (stats, _coverage, findings) = run_structured_campaign(13, 6_000, None, &[]);
    assert_eq!(
        stats.bugs,
        0,
        "structured campaign tripped {} hermetic invariant(s): {:?}",
        stats.bugs,
        findings.iter().map(|f| &f.detail).collect::<Vec<_>>(),
    );
    assert!(findings.is_empty());
    // The campaign must actually exercise the decoders, not silently no-op.
    assert!(stats.iters > 0);
    assert!(stats.accepted > 0 && stats.rejected > 0);
}

// ------------------------------------------------------------------
// (5) Signal: each adversarial feature lands on its intended code path
//     with its intended verdict — not a trivially-malformed reject.
// ------------------------------------------------------------------

/// Assert every observed outcome for `(surface, feature)` matches `pred`, and
/// that the feature was observed at all.
fn assert_all_outcomes(
    surface: &str,
    feature: Feature,
    pred: impl Fn(&Outcome) -> bool,
    label: &str,
) {
    let outcomes = outcomes_for_feature(surface, feature, 1, 30_000);
    assert!(
        !outcomes.is_empty(),
        "{surface}/{} was never emitted (cannot reach its bug surface)",
        feature.name()
    );
    let bad: Vec<&Outcome> = outcomes.iter().filter(|o| !pred(o)).collect();
    assert!(
        bad.is_empty(),
        "{surface}/{} expected {label}, but saw {} off-verdict outcome(s), e.g. {:?}",
        feature.name(),
        bad.len(),
        bad.first()
    );
}

#[test]
fn ergo_tree_features_reach_intended_verdicts() {
    // A FunDef with a negative-as-signed nTpeArgs must be rejected (bug #14).
    assert_all_outcomes(
        "ergo_tree",
        Feature::FunDefNTpeArgsHighBit,
        |o| matches!(o, Outcome::Rejected),
        "Rejected",
    );
    // Type code 9 in a pre-v3 tree must be rejected at the type layer (bug #21).
    assert_all_outcomes(
        "ergo_tree",
        Feature::UnsignedBigIntTypePreV3,
        |o| matches!(o, Outcome::Rejected),
        "Rejected",
    );
    // Ill-formed-UTF-8 STypeVar name round-trips via the JVM-parity lossy decode
    // (bug #1) — a strict decoder that rejected it would be a reject-valid.
    assert_all_outcomes(
        "ergo_tree",
        Feature::STypeVarIllFormedUtf8,
        |o| matches!(o, Outcome::Accepted),
        "Accepted",
    );
    // The compact 0x85 Relation2 bool-pair round-trips byte-identically (bug #12).
    assert_all_outcomes(
        "ergo_tree",
        Feature::Relation2CompactBoolPair,
        |o| matches!(o, Outcome::Accepted),
        "Accepted",
    );
}

#[test]
fn box_features_reach_intended_verdicts() {
    // A register typed with a v6-only type is rejected by CheckV6Type (bug #5).
    assert_all_outcomes(
        "ergo_box_candidate",
        Feature::RegisterV6Type,
        |o| matches!(o, Outcome::Rejected),
        "Rejected",
    );
    // A sizeless non-SigmaProp box script is rejected by rule 1001 (bug #25).
    assert_all_outcomes(
        "ergo_box_candidate",
        Feature::TreeSigmaPropRootViolation,
        |o| matches!(o, Outcome::Rejected),
        "Rejected",
    );
}

#[test]
fn header_and_tx_features_reach_intended_verdicts() {
    // A high-bit (signed-negative) header version parses under the signed
    // grammar — no spurious unparsed_bytes section (bug #8).
    assert_all_outcomes(
        "header",
        Feature::HeaderVersionHighBit,
        |o| matches!(o, Outcome::Accepted),
        "Accepted",
    );
    // Empty outputs / a 0-amount token are codec-accepted (validation-layer
    // rules, not serializer rules) so they round-trip (bug #23).
    assert_all_outcomes(
        "transaction",
        Feature::TxEmptyOutputs,
        |o| matches!(o, Outcome::Accepted),
        "Accepted",
    );
    assert_all_outcomes(
        "transaction",
        Feature::TxZeroAmountToken,
        |o| matches!(o, Outcome::Accepted),
        "Accepted",
    );
}

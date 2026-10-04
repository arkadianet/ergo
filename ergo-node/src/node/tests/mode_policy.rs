// ----- classify_node_mode (Phase 4a) -----

use super::identity::{classify_node_mode, NodeMode};

fn floor_keep() -> i32 {
    (ergo_state::store::ROLLBACK_WINDOW + ergo_state::store::SAFETY_MARGIN) as i32
}

fn inputs_for(
    state_type: crate::config::StateType,
    verify_transactions: bool,
    blocks_to_keep: i32,
    utxo_bootstrap: bool,
    nipopow_bootstrap: bool,
) -> crate::node::identity::IdentityInputs {
    crate::node::identity::IdentityInputs {
        state_type,
        verify_transactions,
        blocks_to_keep,
        keep_versions: ergo_state::store::ROLLBACK_WINDOW,
        utxo_bootstrap,
        nipopow_bootstrap,
        mining_enabled: false,
        mempool_enabled: true,
        extra_index_enabled: false,
        declared_addr: None,
        bind_addr: None,
    }
}

#[test]
fn classify_archive_default() {
    let i = inputs_for(crate::config::StateType::Utxo, true, -1, false, false);
    assert_eq!(classify_node_mode(&i), NodeMode::Archive);
}

#[test]
fn classify_utxo_bootstrap_with_archive_keep() {
    let i = inputs_for(crate::config::StateType::Utxo, true, -1, true, false);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::UtxoBootstrap {
            with_nipopow: false
        },
    );
}

#[test]
fn classify_utxo_bootstrap_with_nipopow_archive_keep() {
    let i = inputs_for(crate::config::StateType::Utxo, true, -1, true, true);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::UtxoBootstrap { with_nipopow: true },
    );
}

#[test]
fn classify_pruned_without_bootstrap() {
    let keep = floor_keep();
    let i = inputs_for(crate::config::StateType::Utxo, true, keep, false, false);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::Pruned { keep: keep as u32 },
    );
}

#[test]
fn classify_pruned_plus_utxo_bootstrap_is_mode_4() {
    let keep = floor_keep();
    let i = inputs_for(crate::config::StateType::Utxo, true, keep, true, false);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::PrunedBootstrap {
            keep: keep as u32,
            utxo: true,
            nipopow: false,
        },
    );
}

#[test]
fn classify_pruned_plus_nipopow_bootstrap_is_mode_4() {
    let keep = floor_keep();
    let i = inputs_for(crate::config::StateType::Utxo, true, keep, false, true);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::PrunedBootstrap {
            keep: keep as u32,
            utxo: false,
            nipopow: true,
        },
    );
}

#[test]
fn classify_pruned_plus_both_bootstraps_is_mode_4() {
    let keep = floor_keep();
    let i = inputs_for(crate::config::StateType::Utxo, true, keep, true, true);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::PrunedBootstrap {
            keep: keep as u32,
            utxo: true,
            nipopow: true,
        },
    );
}

#[test]
fn classify_headers_only() {
    let i = inputs_for(crate::config::StateType::Digest, false, 0, false, false);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::HeadersOnly {
            with_nipopow: false
        },
    );
}

#[test]
fn classify_digest_verifier_combo_is_digest_verifier() {
    let i = inputs_for(crate::config::StateType::Digest, true, -1, false, false);
    assert_eq!(classify_node_mode(&i), NodeMode::DigestVerifier);
}

#[test]
fn classify_headers_only_plus_nipopow_surfaces_in_variant() {
    // `Digest + verify=false + keep=0 + nipopow_bootstrap=true`
    // passes R3 (keep >= 0 satisfies the NiPoPoW consumer rule).
    // Scala accepts this combo (`ErgoSettingsReader.scala:191`),
    // so the classifier must too — but the bootstrap flag MUST
    // surface in the variant rather than being silently dropped.
    let i = inputs_for(crate::config::StateType::Digest, false, 0, false, true);
    assert_eq!(
        classify_node_mode(&i),
        NodeMode::HeadersOnly { with_nipopow: true },
    );
}

#[test]
fn classify_digest_verifier_plus_nipopow_invalid() {
    // R3 (config/load.rs:253) rejects nipopow_bootstrap without
    // utxo_bootstrap or blocks_to_keep >= 0. For the digest
    // verifier shape (keep = -1, no utxo_bootstrap), nipopow
    // therefore has no consumer and must classify as Invalid.
    let i = inputs_for(crate::config::StateType::Digest, true, -1, false, true);
    match classify_node_mode(&i) {
        NodeMode::Invalid { reason } => {
            assert!(
                reason.contains("nipopow_bootstrap"),
                "reason must name nipopow_bootstrap: {reason}",
            );
        }
        other => {
            panic!("digest verifier + nipopow without consumer must be Invalid, got {other:?}")
        }
    }
}

#[test]
fn classify_digest_plus_utxo_bootstrap_invalid() {
    let i = inputs_for(crate::config::StateType::Digest, true, -1, true, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("digest + utxo_bootstrap must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_utxo_no_verify_invalid() {
    let i = inputs_for(crate::config::StateType::Utxo, false, -1, false, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("utxo + !verify_tx must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_nipopow_archive_without_utxo_bootstrap_invalid() {
    // Mirrors the existing TOML-time rejection: NiPoPoW requires
    // either utxo_bootstrap or blocks_to_keep >= 0.
    let i = inputs_for(crate::config::StateType::Utxo, true, -1, false, true);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("nipopow archive without utxo_bootstrap must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_utxo_keep_zero_invalid() {
    let i = inputs_for(crate::config::StateType::Utxo, true, 0, false, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("utxo + keep=0 must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_keep_below_minus_one_invalid() {
    let i = inputs_for(crate::config::StateType::Utxo, true, -3, false, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("keep < -1 must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_sub_floor_keep_invalid() {
    // Positive blocks_to_keep below the rollback-window floor must
    // be classified as Invalid — same contract the TOML loader
    // enforces. Without this the classifier would tolerate
    // configurations the rest of the runtime refuses to boot.
    let i = inputs_for(
        crate::config::StateType::Utxo,
        true,
        floor_keep() - 1,
        false,
        false,
    );
    match classify_node_mode(&i) {
        NodeMode::Invalid { reason } => {
            assert!(
                reason.contains("rollback-window floor"),
                "reason must name the floor: {reason}",
            );
        }
        other => panic!("sub-floor keep must be Invalid, got {other:?}"),
    }
    // The lowest legal positive value (keep == 1) is also
    // sub-floor and must reject.
    let i = inputs_for(crate::config::StateType::Utxo, true, 1, false, false);
    match classify_node_mode(&i) {
        NodeMode::Invalid { .. } => {}
        other => panic!("keep == 1 must be Invalid, got {other:?}"),
    }
}

fn inputs_for_with_indexer(
    blocks_to_keep: i32,
    utxo_bootstrap: bool,
    extra_index_enabled: bool,
) -> crate::node::identity::IdentityInputs {
    let mut i = inputs_for(
        crate::config::StateType::Utxo,
        true,
        blocks_to_keep,
        utxo_bootstrap,
        false,
    );
    i.extra_index_enabled = extra_index_enabled;
    i
}

#[test]
fn classify_extra_index_plus_pruning_invalid() {
    // Indexer + pruning is rejected by the config loader because
    // extra-index needs the full archive. Classifier mirrors the
    // rejection.
    let i = inputs_for_with_indexer(floor_keep(), false, true);
    match classify_node_mode(&i) {
        NodeMode::Invalid { reason } => {
            assert!(
                reason.contains("extra-index"),
                "reason must name extra-index: {reason}",
            );
        }
        other => panic!("extra_index + pruning must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_extra_index_plus_utxo_bootstrap_invalid() {
    // Indexer + utxo_bootstrap is also rejected — the bootstrap
    // skips the chain below the snapshot, leaving nothing for
    // extra-index to index.
    let i = inputs_for_with_indexer(-1, true, true);
    match classify_node_mode(&i) {
        NodeMode::Invalid { reason } => {
            assert!(
                reason.contains("extra-index"),
                "reason must name extra-index: {reason}",
            );
        }
        other => panic!("extra_index + utxo_bootstrap must be Invalid, got {other:?}"),
    }
}

#[test]
fn classify_extra_index_with_archive_is_archive() {
    // The valid extra-index combo is the full-archive node: no
    // pruning, no bootstrap. Classify still returns Archive.
    let i = inputs_for_with_indexer(-1, false, true);
    assert_eq!(classify_node_mode(&i), NodeMode::Archive);
}

#[test]
fn classify_agrees_with_build_api_identity_on_canonical_combos() {
    // The classifier and the identity-projection paths must not
    // disagree on which combos are valid. For every row that
    // classify returns a non-Invalid mode, `build_api_identity`
    // must succeed; for every Invalid row, `build_api_identity`
    // is allowed to either succeed (with the resulting label
    // self-flagged as `invalid mode:`) or fail. The asymmetry is
    // intentional: build_api_identity has its own rejections at
    // a different layer; classify is the stricter projection.
    use crate::node::identity::{build_api_identity_from_inputs, BootstrapKind};
    let floor = floor_keep();
    let canonical: &[(crate::config::StateType, bool, i32, bool, bool)] = &[
        (crate::config::StateType::Utxo, true, -1, false, false),
        (crate::config::StateType::Utxo, true, -1, true, false),
        (crate::config::StateType::Utxo, true, -1, true, true),
        (crate::config::StateType::Utxo, true, floor, false, false),
        (crate::config::StateType::Utxo, true, floor, true, false),
        (crate::config::StateType::Utxo, true, floor, false, true),
        (crate::config::StateType::Utxo, true, floor, true, true),
        (crate::config::StateType::Digest, false, 0, false, false),
        (crate::config::StateType::Digest, true, -1, false, false),
    ];
    for &(st, vt, btk, ub, np) in canonical {
        let i = inputs_for(st, vt, btk, ub, np);
        let mode = classify_node_mode(&i);
        let id = build_api_identity_from_inputs(&i, 1, BootstrapKind::None);
        if matches!(mode, NodeMode::Invalid { .. }) {
            // Skip — classify rejected; identity is allowed to
            // disagree.
            continue;
        }
        assert!(
            id.is_ok(),
            "classify_node_mode returned {mode:?} but build_api_identity_from_inputs \
             failed for inputs (state_type={st:?}, vt={vt}, btk={btk}, ub={ub}, np={np}): \
             {:?}",
            id.err(),
        );
    }
}

/// Cross-product the plan calls out: `{utxo_bootstrap,
/// nipopow_bootstrap} × {-1, ≥ floor}`. Mode 4 must be reached on
/// the `(*, ≥ floor)` rows where at least one bootstrap flag is
/// set; archive / Mode 2 / Mode 3 cover the rest.
#[test]
fn classify_cross_product_utxo_nipopow_keep_minus_one_or_floor() {
    let floor = floor_keep();
    let cases: &[(bool, bool, i32, NodeMode)] = &[
        (false, false, -1, NodeMode::Archive),
        (
            true,
            false,
            -1,
            NodeMode::UtxoBootstrap {
                with_nipopow: false,
            },
        ),
        (
            true,
            true,
            -1,
            NodeMode::UtxoBootstrap { with_nipopow: true },
        ),
        (false, false, floor, NodeMode::Pruned { keep: floor as u32 }),
        (
            true,
            false,
            floor,
            NodeMode::PrunedBootstrap {
                keep: floor as u32,
                utxo: true,
                nipopow: false,
            },
        ),
        (
            false,
            true,
            floor,
            NodeMode::PrunedBootstrap {
                keep: floor as u32,
                utxo: false,
                nipopow: true,
            },
        ),
        (
            true,
            true,
            floor,
            NodeMode::PrunedBootstrap {
                keep: floor as u32,
                utxo: true,
                nipopow: true,
            },
        ),
    ];
    // (false, true, -1) is intentionally absent — the classifier
    // returns Invalid for it, covered separately.
    for &(utxo, popow, keep, ref expected) in cases {
        let i = inputs_for(crate::config::StateType::Utxo, true, keep, utxo, popow);
        let got = classify_node_mode(&i);
        assert_eq!(
            got, *expected,
            "cross-product row (utxo={utxo}, popow={popow}, keep={keep}): \
             expected {expected:?}, got {got:?}",
        );
    }
}

// ----- Phase 4c: Mode 4 label projection -----

/// Mode 4 via config flag — `utxo_bootstrap = true +
/// blocks_to_keep > 0` emits the mode-4 label with the
/// utxo-bootstrapped source AND the suffix length, not the Mode
/// 2 short-circuit. Wire-visible fields stay Scala-parity.
#[test]
fn build_api_identity_mode_4_utxo_via_config_emits_mode_4_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, true);
    cfg.nipopow_bootstrap = false;
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("Mode 4 config must project");
    assert!(
        id.mode.starts_with("mode-4 · utxo-bootstrapped"),
        "expected Mode 4 label, got {:?}",
        id.mode,
    );
    assert!(id.mode.ends_with("keep 1440"));
    assert!(id.utxo_bootstrap);
    assert!(!id.nipopow_bootstrap);
}

/// Mode 4 via NiPoPoW config flag.
#[test]
fn build_api_identity_mode_4_nipopow_via_config_emits_mode_4_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, false);
    cfg.nipopow_bootstrap = true;
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("Mode 4 + nipopow config must project");
    assert_eq!(
        id.mode, "mode-4 · popow-bootstrapped · keep 1440",
        "expected Mode 4 popow label, got {:?}",
        id.mode,
    );
    assert!(!id.utxo_bootstrap);
    assert!(id.nipopow_bootstrap);
}

/// Mode 4 with both config flags set — label MUST surface both
/// provenance sources.
#[test]
fn build_api_identity_mode_4_both_bootstrap_config_flags_emits_both_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, true);
    cfg.nipopow_bootstrap = true;
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("Mode 4 + both config flags must project");
    assert_eq!(
        id.mode, "mode-4 · utxo+popow-bootstrapped · keep 1440",
        "expected Mode 4 utxo+popow label, got {:?}",
        id.mode,
    );
    assert!(id.utxo_bootstrap);
    assert!(id.nipopow_bootstrap);
}

/// Mode 4 detected via runtime provenance — config-side flags
/// cleared but `BootstrapKind::Utxo` from the persistent marker
/// still drives the Mode 4 label.
#[test]
fn build_api_identity_mode_4_via_provenance_only_emits_mode_4_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, false);
    cfg.nipopow_bootstrap = false;
    let id = build_api_identity(&cfg, 100_000, crate::node::identity::BootstrapKind::Utxo)
        .expect("Mode 4 via provenance must project");
    assert_eq!(
        id.mode, "mode-4 · utxo-bootstrapped · keep 1440",
        "expected Mode 4 label via provenance, got {:?}",
        id.mode,
    );
    assert!(id.utxo_bootstrap);
}

/// `BootstrapKind::Both` — both bootstrap mechanisms ran on a
/// pure Mode 4 store. The label MUST name both.
#[test]
fn build_api_identity_mode_4_both_provenance_emits_both_label() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, false);
    cfg.nipopow_bootstrap = false;
    let id = build_api_identity(&cfg, 100_000, crate::node::identity::BootstrapKind::Both)
        .expect("Mode 4 Both provenance must project");
    assert_eq!(
        id.mode, "mode-4 · utxo+popow-bootstrapped · keep 1440",
        "Both provenance must surface both bootstrap sources",
    );
    assert!(id.utxo_bootstrap);
    assert!(id.nipopow_bootstrap);
}

/// Sentinel-active archive label refinement gains a Both arm
/// when an archive-config restart sees both provenance markers.
#[test]
fn build_api_identity_sentinel_active_archive_both_label_refines() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, false);
    let id = build_api_identity(&cfg, 100_000, crate::node::identity::BootstrapKind::Both)
        .expect("sentinel-active archive Both provenance must project");
    assert!(
        id.mode.contains("utxo+popow-bootstrapped"),
        "post-bootstrap archive label must surface both sources, got {:?}",
        id.mode,
    );
    // Effective flags reflect both detections.
    assert!(id.utxo_bootstrap);
    assert!(id.nipopow_bootstrap);
}

/// Mode 3 (pruned, no bootstrap, no provenance) keeps the
/// existing "pruned · utxo · keep N" label — Mode 4 label MUST
/// NOT swallow plain Mode 3 configs.
#[test]
fn build_api_identity_mode_3_pure_pruned_label_unchanged() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, 1440, false);
    cfg.nipopow_bootstrap = false;
    let id = build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None)
        .expect("Mode 3 must project");
    assert_eq!(id.mode, "pruned · utxo · keep 1440");
}

// ----- Phase 4b': classify_nipopow_resume truth table -----

use super::identity::{classify_nipopow_resume, NipopowResumeState};
use ergo_state::chain::HeaderAvailability;

fn sparse() -> HeaderAvailability {
    HeaderAvailability::PoPowSparse {
        dense_from_height: 1024,
        proof_suffix_height: 2048,
    }
}

#[test]
fn nipopow_resume_disabled_when_flag_off() {
    assert_eq!(
        classify_nipopow_resume(false, &HeaderAvailability::Dense, 0, 0),
        NipopowResumeState::Disabled,
    );
    // Even with non-default chain state, disabled wins when the
    // flag is off.
    assert_eq!(
        classify_nipopow_resume(false, &sparse(), 2048, 2048),
        NipopowResumeState::Disabled,
    );
}

#[test]
fn nipopow_resume_fresh_at_zero_state() {
    // Row 1 of the truth table.
    assert_eq!(
        classify_nipopow_resume(true, &HeaderAvailability::Dense, 0, 0),
        NipopowResumeState::Fresh,
    );
}

#[test]
fn nipopow_resume_partial_header_sync_when_headers_but_no_full_blocks() {
    // Row 2 — partial header progress, full-block state still 0.
    assert_eq!(
        classify_nipopow_resume(true, &HeaderAvailability::Dense, 500, 0),
        NipopowResumeState::PartialHeaderSync,
    );
}

#[test]
fn nipopow_resume_normal_store_when_full_block_applied() {
    // Row 3 — regression guard. A store with any applied full
    // block MUST NOT be classified as bootstrap-resumable.
    assert_eq!(
        classify_nipopow_resume(true, &HeaderAvailability::Dense, 500, 100),
        NipopowResumeState::NormalStore,
    );
    assert_eq!(
        classify_nipopow_resume(true, &HeaderAvailability::Dense, 500, 1),
        NipopowResumeState::NormalStore,
    );
}

#[test]
fn nipopow_resume_proof_committed_on_sparse_history() {
    // Row 4 — apply_popow_proof has committed; the dense suffix
    // is built out and any further bootstrap is a no-op.
    assert_eq!(
        classify_nipopow_resume(true, &sparse(), 2048, 0),
        NipopowResumeState::ProofCommitted,
    );
    // ProofCommitted also wins when a full block has applied
    // after the proof.
    assert_eq!(
        classify_nipopow_resume(true, &sparse(), 2048, 2048),
        NipopowResumeState::ProofCommitted,
    );
}

// ----- Phase 4b: should_engage_utxo_install -----

use super::identity::should_engage_utxo_install;

#[test]
fn utxo_install_engages_on_fresh_store_with_config_flag() {
    assert!(should_engage_utxo_install(true, 0, false));
}

#[test]
fn utxo_install_skips_when_config_flag_off() {
    // Operator never asked for a snapshot install.
    assert!(!should_engage_utxo_install(false, 0, false));
}

#[test]
fn utxo_install_skips_when_full_block_already_applied() {
    // Post-install restart: best_full_block_height > 0 means
    // the install happened (or normal forward sync ran).
    assert!(!should_engage_utxo_install(true, 100, false));
}

#[test]
fn utxo_install_skips_when_marker_armed() {
    // Phase 4b core invariant — repeat boot with the same
    // config skips the install path.
    assert!(!should_engage_utxo_install(true, 0, true));
}

#[test]
fn utxo_install_skips_when_both_marker_and_full_block_present() {
    // Healthy steady state after the install.
    assert!(!should_engage_utxo_install(true, 100, true));
}

// ----- validate_runtime_mode_support -----

use super::identity::validate_runtime_mode_support;

/// Mode 6 (headers-only) baseline — the canonical combo `Digest +
/// verify_tx=false + blocks_to_keep=0 + utxo_bootstrap=false`. Must
/// pass.
#[test]
fn validate_runtime_mode_canonical_mode_6_accepted() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Digest, false, 0, false);
    validate_runtime_mode_support(&cfg).expect("canonical Mode 6 must pass");
}

/// Headers-only + `utxo_bootstrap=true` is a physically nonsensical
/// combo: there is no UTXO state to bootstrap into. The runtime gate
/// must reject so the boot path never wires snapshot orchestration
/// onto a digest data dir.
#[test]
fn validate_runtime_mode_rejects_mode_6_plus_utxo_bootstrap() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Digest, false, 0, true);
    let err = validate_runtime_mode_support(&cfg).expect_err("Mode 6 + utxo_bootstrap must reject");
    let msg = err.to_string();
    // The error can surface via the verify_transactions arm (which now
    // mentions utxo_bootstrap=false in the canonical combo) or via the
    // dedicated `utxo_bootstrap` arm — either is acceptable as long as
    // the combo is refused.
    assert!(
        msg.contains("verify_transactions") || msg.contains("utxo_bootstrap"),
        "rejection must reference verify_transactions or utxo_bootstrap: {msg}",
    );
}

/// `utxo_bootstrap=true` with `state_type=digest` (without the rest
/// of the Mode 6 combo, so it doesn't hit the Mode 6 path) must be
/// rejected — snapshot bootstrap only makes sense for the UTXO
/// backend.
#[test]
fn validate_runtime_mode_rejects_utxo_bootstrap_on_digest() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Digest, true, -1, true);
    let err =
        validate_runtime_mode_support(&cfg).expect_err("utxo_bootstrap on digest must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("state_type") || msg.contains("utxo_bootstrap"),
        "rejection must reference state_type or utxo_bootstrap: {msg}",
    );
}

/// Mode 2 baseline (Utxo + utxo_bootstrap=true + archive btk) must
/// still pass the runtime gate; the snapshot pipeline takes over
/// from there.
#[test]
fn validate_runtime_mode_mode_2_accepted() {
    let cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, true);
    validate_runtime_mode_support(&cfg).expect("Mode 2 must pass");
}

/// Single-source-of-truth check: both gates delegate to
/// `is_canonical_mode_6_combo`, so they agree on every 4-tuple. This
/// test exercises the predicate directly across the interesting
/// corners.
#[test]
fn is_canonical_mode_6_combo_pins_the_contract() {
    use crate::config::{is_canonical_mode_6_combo, StateType};
    // Positive: canonical
    assert!(is_canonical_mode_6_combo(
        StateType::Digest,
        false,
        0,
        false
    ));
    // Negative: utxo_bootstrap flips the predicate
    assert!(!is_canonical_mode_6_combo(
        StateType::Digest,
        false,
        0,
        true
    ));
    // Negative: verify_transactions=true
    assert!(!is_canonical_mode_6_combo(
        StateType::Digest,
        true,
        0,
        false
    ));
    // Negative: state_type=utxo
    assert!(!is_canonical_mode_6_combo(StateType::Utxo, false, 0, false));
    // Negative: blocks_to_keep != 0
    assert!(!is_canonical_mode_6_combo(
        StateType::Digest,
        false,
        -1,
        false
    ));
}

#[test]
fn is_canonical_mode_5_combo_pins_the_contract() {
    use crate::config::{is_canonical_mode_5_combo, StateType};
    // Positive: the bare Mode 5 row (digest + verify + archive, no bootstrap).
    assert!(is_canonical_mode_5_combo(
        StateType::Digest,
        true,
        -1,
        false
    ));
    // Negative: verify_transactions=false is Mode 6, not Mode 5.
    assert!(!is_canonical_mode_5_combo(
        StateType::Digest,
        false,
        -1,
        false
    ));
    // Negative: state_type=utxo.
    assert!(!is_canonical_mode_5_combo(StateType::Utxo, true, -1, false));
    // Negative: pruning (blocks_to_keep >= 0) — digest mode is archive-only.
    assert!(!is_canonical_mode_5_combo(
        StateType::Digest,
        true,
        0,
        false
    ));
    assert!(!is_canonical_mode_5_combo(
        StateType::Digest,
        true,
        100,
        false
    ));
    // Negative: utxo_bootstrap has no box arena to install into.
    assert!(!is_canonical_mode_5_combo(
        StateType::Digest,
        true,
        -1,
        true
    ));
}

#[test]
fn identity_projects_configured_mempool_capability() {
    let mut cfg = cfg_for_history_mode(crate::config::StateType::Utxo, true, -1, false);
    for enabled in [false, true] {
        cfg.mempool_config.enabled = enabled;
        let identity =
            build_api_identity(&cfg, 1, crate::node::identity::BootstrapKind::None).unwrap();
        assert_eq!(identity.mempool_enabled, enabled);
        assert_eq!(
            serde_json::to_value(identity).unwrap()["mempool_enabled"],
            enabled
        );
    }
}

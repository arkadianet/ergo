//! Pin the typed-error variants split out from
//! `StateError::Serialization(String)` so a future flatten-back
//! regression fails the test, not a `match` arm in production code.

use ergo_state::store::StateError;

// ----- helpers -----

fn variant_label(e: &StateError) -> &'static str {
    match e {
        StateError::InvalidPrecondition { .. } => "InvalidPrecondition",
        StateError::InternalInvariant { .. } => "InternalInvariant",
        StateError::InternalInvariantAt { .. } => "InternalInvariantAt",
        StateError::EarlyIBD { .. } => "EarlyIBD",
        StateError::AppliedChainGap { .. } => "AppliedChainGap",
        StateError::PopowDataMissing { .. } => "PopowDataMissing",
        StateError::Serialization(_) => "Serialization",
        StateError::DbCorruption { .. } => "DbCorruption",
        StateError::WalletApply { .. } => "WalletApply",
        StateError::WalletApplyCommit { .. } => "WalletApplyCommit",
        StateError::VotedParamsWriteFailed { .. } => "VotedParamsWriteFailed",
        StateError::StateTypeMismatch { .. } => "StateTypeMismatch",
        StateError::InstallSnapshotRefused { .. } => "InstallSnapshotRefused",
        StateError::InstallSnapshotRootMismatch { .. } => "InstallSnapshotRootMismatch",
        StateError::PersistFailed { .. } => "PersistFailed",
        StateError::VotedParamsMigrateFailed { .. } => "VotedParamsMigrateFailed",
        StateError::VotedParamsRecomputeFailed { .. } => "VotedParamsRecomputeFailed",
        StateError::ApplyPopowProofWrongMode { .. } => "ApplyPopowProofWrongMode",
        StateError::CandidateDryRunProverFailed { .. } => "CandidateDryRunProverFailed",
        StateError::ProveWithDbAnchorNotFound { .. } => "ProveWithDbAnchorNotFound",
        _ => "other",
    }
}

// ----- happy path -----

#[test]
fn invalid_precondition_carries_static_what_and_distinct_display() {
    let e = StateError::InvalidPrecondition {
        what: "persist pipeline already shut down",
    };
    assert_eq!(variant_label(&e), "InvalidPrecondition");
    assert!(
        e.to_string().contains("persist pipeline already shut down"),
        "got: {e}"
    );
    assert!(
        e.to_string().starts_with("invalid precondition:"),
        "got: {e}"
    );
}

#[test]
fn internal_invariant_carries_static_what_and_distinct_display() {
    let e = StateError::InternalInvariant {
        what: "voted_params: parameter set failed its invariant check",
    };
    assert_eq!(variant_label(&e), "InternalInvariant");
    assert!(e.to_string().contains("parameter set failed"), "got: {e}");
    assert!(
        e.to_string().starts_with("internal invariant violated:"),
        "got: {e}"
    );
}

#[test]
fn voted_params_write_failed_carries_op_height_and_typed_source() {
    use ergo_state::store::VotedParamsWriteError;
    let inner = VotedParamsWriteError::InvalidParams(
        ergo_validation::ActiveParamsError::ExtraDuplicateId(7),
    );
    let inner_msg = inner.to_string();
    let e = StateError::VotedParamsWriteFailed {
        op: "reconcile",
        height: 6_144,
        source: Box::new(inner),
    };
    assert_eq!(variant_label(&e), "VotedParamsWriteFailed");
    // Exact Display: `voted_params {op} failed at h={height}: {source}`.
    // The inner VotedParamsWriteError::Display now embeds the leaf
    // ActiveParamsError, so the outer rendering carries the underlying
    // detail end-to-end without requiring chain-aware reporters.
    assert_eq!(
        e.to_string(),
        format!("voted_params reconcile failed at h=6144: {inner_msg}")
    );
    assert!(
        e.to_string().contains("extra entry has duplicate id 7"),
        "leaf ActiveParamsError detail must surface in outer Display; got: {e}",
    );

    // First source hop: typed VotedParamsWriteError.
    let src = std::error::Error::source(&e).expect("source missing");
    src.downcast_ref::<Box<VotedParamsWriteError>>()
        .expect("source must downcast to Box<VotedParamsWriteError>");

    // Second source hop: the leaf ActiveParamsError, reachable via
    // std::error::Error::source chain. Confirms the typed cause is
    // accessible to chain-walking reporters.
    let leaf = std::error::Error::source(src).expect("inner source missing");
    leaf.downcast_ref::<ergo_validation::ActiveParamsError>()
        .expect("inner source must downcast to ActiveParamsError");
}

#[test]
fn voted_params_recompute_failed_carries_typed_source_and_chains_display() {
    use ergo_validation::RecomputeError;
    let inner = RecomputeError::NotEpochStart(700_001);
    let inner_msg = inner.to_string();
    let e = StateError::VotedParamsRecomputeFailed {
        height: 12_288,
        source: Box::new(inner),
    };
    assert_eq!(variant_label(&e), "VotedParamsRecomputeFailed");
    assert_eq!(
        e.to_string(),
        format!("voted_params migrate compute_next_params failed at h=12288: {inner_msg}"),
    );
    // Error::source chain: first hop is Box<RecomputeError>.
    let src = std::error::Error::source(&e).expect("source missing");
    src.downcast_ref::<Box<RecomputeError>>()
        .expect("source must downcast to Box<RecomputeError>");
}

#[test]
fn apply_popow_proof_wrong_mode_carries_runtime_mode_and_height() {
    let e = StateError::ApplyPopowProofWrongMode {
        mode_description: "PoPowSparse { dense_from_height: 705000 }".to_string(),
        best_header_height: 705_010,
    };
    assert_eq!(variant_label(&e), "ApplyPopowProofWrongMode");
    assert_eq!(
        e.to_string(),
        "apply_popow_proof: store must be in Dense mode \
         (got header_availability=PoPowSparse { dense_from_height: 705000 }, \
         best_header_height=705010)",
    );
}

#[test]
fn prove_with_db_anchor_not_found_carries_header_id_in_display() {
    // Caller-supplied anchor absent from BOTH HEADER_CHAIN_INDEX and
    // HEADERS — caller-side misuse. An id present in
    // HEADER_CHAIN_INDEX but missing from HEADERS is cross-table
    // corruption and routes through DbCorruption instead.
    let header_id = "ab".repeat(32);
    let e = StateError::ProveWithDbAnchorNotFound {
        header_id: header_id.clone(),
    };
    assert_eq!(variant_label(&e), "ProveWithDbAnchorNotFound");
    assert_eq!(
        e.to_string(),
        format!(
            "prove_with_db: caller-supplied anchor header_id not in canonical chain \
             (absent from both HEADER_CHAIN_INDEX and HEADERS): {header_id}"
        ),
    );
}

#[test]
fn candidate_dry_run_prover_failed_carries_op_box_and_detail() {
    let box_id = "aa".repeat(32);
    let e = StateError::CandidateDryRunProverFailed {
        op: "remove",
        box_id: box_id.clone(),
        error: "key not found".to_string(),
    };
    assert_eq!(variant_label(&e), "CandidateDryRunProverFailed");
    assert_eq!(
        e.to_string(),
        format!("candidate dry-run prover remove failed for box {box_id}: key not found")
    );
}

#[test]
fn voted_params_migrate_failed_carries_op_height_detail_in_display() {
    let e = StateError::VotedParamsMigrateFailed {
        op: "compute_next_params",
        height: 6_144,
        detail: "step_for_id missing for id 4".to_string(),
    };
    assert_eq!(variant_label(&e), "VotedParamsMigrateFailed");
    assert_eq!(
        e.to_string(),
        "voted_params migrate compute_next_params failed at h=6144: step_for_id missing for id 4"
    );
}

#[test]
fn persist_failed_carries_typed_height_and_inner_error_text() {
    let e = StateError::PersistFailed {
        height: 999_888,
        error: "redb commit aborted: simulated".to_string(),
    };
    assert_eq!(variant_label(&e), "PersistFailed");
    // Exact Display: `background persist failed at h={height}: {error}`.
    assert_eq!(
        e.to_string(),
        "background persist failed at h=999888: redb commit aborted: simulated"
    );
}

#[test]
fn install_snapshot_refused_carries_current_height_in_display() {
    let e = StateError::InstallSnapshotRefused {
        current_height: 1_234_567,
    };
    assert_eq!(variant_label(&e), "InstallSnapshotRefused");
    // Exact Display contract: typed height + remediation hint surface
    // verbatim. `contains` would let a future wording tweak silently
    // drop either; `assert_eq` rejects any drift.
    assert_eq!(
        e.to_string(),
        "install_snapshot_state refused: store already has best_full_block_height=1234567 \
         (bootstrap requires a fresh data_dir)"
    );
}

#[test]
fn install_snapshot_root_mismatch_carries_both_hashes_in_display() {
    let computed = "aa".repeat(32);
    let expected_hex = "bb".repeat(32);
    let e = StateError::InstallSnapshotRootMismatch {
        computed: computed.clone(),
        expected: expected_hex.clone(),
    };
    assert_eq!(variant_label(&e), "InstallSnapshotRootMismatch");
    // Exact Display contract pins the install-site framing + both
    // hashes; a future variant rename or wording drift fails here.
    assert_eq!(
        e.to_string(),
        format!(
            "install_snapshot_state: reconstructed root {computed} != expected state_root prefix {expected_hex}"
        )
    );
}

#[test]
fn state_type_mismatch_carries_both_configured_and_recorded_in_display() {
    let e = StateError::StateTypeMismatch {
        configured: "digest".to_string(),
        recorded: "utxo".to_string(),
    };
    assert_eq!(variant_label(&e), "StateTypeMismatch");
    let s = e.to_string();
    // Both values must surface so operators can identify the
    // misconfiguration without parsing the variant.
    assert!(s.contains("utxo"), "missing recorded in display: {s}");
    assert!(s.contains("digest"), "missing configured in display: {s}");
}

#[test]
fn popow_data_missing_at_height_renders_height_form() {
    use ergo_state::store::PopowMissingAt;
    let e = StateError::PopowDataMissing {
        what: "prove_with_db: genesis",
        at: PopowMissingAt::Height(1),
    };
    assert_eq!(variant_label(&e), "PopowDataMissing");
    assert_eq!(
        e.to_string(),
        "popow data missing at h=1: prove_with_db: genesis"
    );
}

#[test]
fn popow_data_missing_for_header_id_renders_hex_id_form() {
    use ergo_state::store::PopowMissingAt;
    let e = StateError::PopowDataMissing {
        what: "collect_level: popow lookup miss",
        at: PopowMissingAt::HeaderId([0xab; 32]),
    };
    assert_eq!(variant_label(&e), "PopowDataMissing");
    let expected_hex = "abababababababababababababababababababababababababababababababab";
    assert_eq!(
        e.to_string(),
        format!("popow data missing at id={expected_hex}: collect_level: popow lookup miss"),
    );
}

#[test]
fn internal_invariant_at_carries_what_and_height_in_display() {
    let e = StateError::InternalInvariantAt {
        what: "prove_with_db: suffix-head missing from HEADER_CHAIN_INDEX",
        height: 700_000,
    };
    assert_eq!(variant_label(&e), "InternalInvariantAt");
    // Exact Display: `internal invariant violated at h={height}: {what}`.
    assert_eq!(
        e.to_string(),
        "internal invariant violated at h=700000: \
         prove_with_db: suffix-head missing from HEADER_CHAIN_INDEX"
    );
}

#[test]
fn applied_chain_gap_carries_at_height_and_renders_in_display() {
    let e = StateError::AppliedChainGap { at_height: 1234 };
    assert_eq!(variant_label(&e), "AppliedChainGap");
    // Exact Display: `applied chain has no row at h={at_height}`.
    assert_eq!(e.to_string(), "applied chain has no row at h=1234");
}

#[test]
fn early_ibd_carries_typed_heights_and_renders_both_in_display() {
    let e = StateError::EarlyIBD {
        needed_min: 10,
        observed: 3,
    };
    assert_eq!(variant_label(&e), "EarlyIBD");
    let s = e.to_string();
    assert!(s.contains("tip at 3"), "got: {s}");
    assert!(s.contains("at least 10"), "got: {s}");
}

#[test]
fn wallet_apply_carries_what_height_and_typed_source() {
    let inner = redb::Error::Corrupted("simulated".to_string());
    let inner_msg = inner.to_string();
    let e = StateError::WalletApply {
        what: "apply hook",
        height: 1_234_567,
        source: Box::new(inner),
    };
    assert_eq!(variant_label(&e), "WalletApply");

    // Exact Display format: `wallet {what} at h={height}: {source}`.
    let expected_display = format!("wallet apply hook at h=1234567: {inner_msg}");
    assert_eq!(e.to_string(), expected_display);

    // `#[source]` must expose the redb error. Thiserror's `#[source]`
    // on `Box<T>` casts the Box itself to `&dyn Error` (no auto-deref),
    // so the trait-object's concrete type is `Box<redb::Error>`.
    let src = std::error::Error::source(&e).expect("source missing");
    src.downcast_ref::<Box<redb::Error>>()
        .expect("source must downcast to Box<redb::Error>");
}

#[test]
fn wallet_apply_commit_carries_height_and_typed_commit_error() {
    // `redb::CommitError` is `#[non_exhaustive]` but its
    // `Storage(StorageError)` variant is publicly constructible, and
    // `StorageError::Corrupted(String)` is the simplest test seed.
    let inner = redb::CommitError::Storage(redb::StorageError::Corrupted(
        "simulated commit failure".to_string(),
    ));
    let inner_msg = inner.to_string();
    let e = StateError::WalletApplyCommit {
        height: 999_111,
        source: Box::new(inner),
    };
    assert_eq!(variant_label(&e), "WalletApplyCommit");

    // Exact Display format: `wallet commit at h={height}: {source}`.
    let expected_display = format!("wallet commit at h=999111: {inner_msg}");
    assert_eq!(e.to_string(), expected_display);

    // `#[source]` must expose the commit error. Thiserror casts the
    // Box itself to `&dyn Error`, so the trait-object's concrete type
    // is `Box<redb::CommitError>`.
    let src = std::error::Error::source(&e).expect("source missing");
    src.downcast_ref::<Box<redb::CommitError>>()
        .expect("source must downcast to Box<redb::CommitError>");
}

// ----- error paths / variant distinctness -----

#[test]
fn typed_variants_are_disjoint_under_pattern_match() {
    let cases: Vec<StateError> = vec![
        StateError::InvalidPrecondition { what: "x" },
        StateError::InternalInvariant { what: "y" },
        StateError::EarlyIBD {
            needed_min: 1,
            observed: 0,
        },
        StateError::InternalInvariantAt {
            what: "z",
            height: 1,
        },
        StateError::AppliedChainGap { at_height: 1 },
        StateError::PopowDataMissing {
            what: "x",
            at: ergo_state::store::PopowMissingAt::Height(1),
        },
        StateError::StateTypeMismatch {
            configured: "a".to_string(),
            recorded: "b".to_string(),
        },
        StateError::InstallSnapshotRefused { current_height: 1 },
        StateError::InstallSnapshotRootMismatch {
            computed: "c".to_string(),
            expected: "d".to_string(),
        },
        StateError::PersistFailed {
            height: 1,
            error: "x".to_string(),
        },
        StateError::VotedParamsMigrateFailed {
            op: "y",
            height: 1,
            detail: "z".to_string(),
        },
        StateError::VotedParamsRecomputeFailed {
            height: 1,
            source: Box::new(ergo_validation::RecomputeError::NotEpochStart(1)),
        },
        StateError::ApplyPopowProofWrongMode {
            mode_description: "x".to_string(),
            best_header_height: 1,
        },
        StateError::CandidateDryRunProverFailed {
            op: "insert",
            box_id: "aa".repeat(32),
            error: "x".to_string(),
        },
        StateError::ProveWithDbAnchorNotFound {
            header_id: "ab".repeat(32),
        },
        StateError::Serialization("byte truncated".into()),
        StateError::DbCorruption {
            table: "t",
            key: "k".into(),
            reason: "r".into(),
        },
        StateError::WalletApply {
            what: "z",
            height: 1,
            source: Box::new(redb::Error::Corrupted("zz".to_string())),
        },
        StateError::WalletApplyCommit {
            height: 2,
            source: Box::new(redb::CommitError::Storage(redb::StorageError::Corrupted(
                "qq".to_string(),
            ))),
        },
        StateError::VotedParamsWriteFailed {
            op: "apply",
            height: 3,
            source: Box::new(ergo_state::store::VotedParamsWriteError::InvalidParams(
                ergo_validation::ActiveParamsError::ExtraDuplicateId(1),
            )),
        },
    ];
    let labels: Vec<_> = cases.iter().map(variant_label).collect();
    assert_eq!(
        labels,
        vec![
            "InvalidPrecondition",
            "InternalInvariant",
            "EarlyIBD",
            "InternalInvariantAt",
            "AppliedChainGap",
            "PopowDataMissing",
            "StateTypeMismatch",
            "InstallSnapshotRefused",
            "InstallSnapshotRootMismatch",
            "PersistFailed",
            "VotedParamsMigrateFailed",
            "VotedParamsRecomputeFailed",
            "ApplyPopowProofWrongMode",
            "CandidateDryRunProverFailed",
            "ProveWithDbAnchorNotFound",
            "Serialization",
            "DbCorruption",
            "WalletApply",
            "WalletApplyCommit",
            "VotedParamsWriteFailed",
        ]
    );
}

// ----- oracle parity -----

// (none — pure error-taxonomy change; no Scala/mainnet oracle applies)

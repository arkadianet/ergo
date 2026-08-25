//! Regression coverage for the `cached_validation_settings` forward-apply
//! update path in `apply_utxo_changes`.
//!
//! Bug history (2026-05-06): the in-memory `cached_validation_settings`
//! was only refreshed by `refresh_cached_active_params{,_post_commit}`
//! (open / rollback / reorg). Forward applies advanced
//! `cached_active_params` from `cache_advance` but left
//! `cached_validation_settings` stale, so any session that crossed the
//! v6.0 soft-fork activation epoch (h=1628160) without restarting
//! rejected the next epoch boundary (h=1629184) on
//! `exMatchValidationSettings`. The fix folds `p.activated_update`
//! into `cached_validation_settings` alongside the active-params
//! advance, mirroring the on-disk fold in `compute_validation_settings_at`.

use ergo_state::store::StateStore;
use ergo_validation::{
    scala_launch, ActiveProtocolParameters, ErgoValidationSettingsUpdate, RuleStatus,
};

/// One synthetic box in genesis — enough for a non-trivial root_digest.
fn seed_genesis(store: &mut StateStore) {
    let boxes: Vec<([u8; 32], Vec<u8>)> = vec![{
        let mut id = [0u8; 32];
        id[31] = 1;
        (id, vec![0xAAu8; 32])
    }];
    store.initialize_genesis(&boxes).unwrap();
}

/// Synthetic header_id derived from height. Matching the value the
/// `test-helpers`-only HEADER_META synthesis writes when `apply_block`
/// is called without a real header pipeline.
fn synthetic_header_id(height: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[28..].copy_from_slice(&height.to_be_bytes());
    h
}

fn epoch_row(height: u32, activated: ErgoValidationSettingsUpdate) -> ActiveProtocolParameters {
    let mut p = scala_launch();
    p.epoch_start_height = height;
    p.activated_update = activated;
    p
}

/// Drive a no-op apply at `height`. Empty tx list → zero UTXO changes →
/// expected_state_root equals the pre-apply root. Does not touch the
/// validation pipeline; goes straight to `apply_utxo_changes`.
fn apply_no_op(
    store: &mut StateStore,
    height: u32,
    voted_params_row: Option<ActiveProtocolParameters>,
) {
    let header_id = synthetic_header_id(height);
    let expected = store.root_digest();
    store
        .apply_block_unchecked_for_test_with_voted_params(
            height,
            &header_id,
            &expected,
            &[],
            voted_params_row,
        )
        .unwrap();
}

/// Walk the synthetic chain from h=1 up to (and including) `target`,
/// passing `voted_params_row` only at the epoch boundary at `target`.
/// Required because `rewrite_best_chain_into_index` walks the parent
/// chain back through HEADER_META; we need every height filled in by
/// the test-helpers synthesis path.
fn apply_chain_to_epoch_boundary(
    store: &mut StateStore,
    target: u32,
    activated: ErgoValidationSettingsUpdate,
) {
    assert!(target > 0 && target.is_multiple_of(1024));
    for h in 1..target {
        apply_no_op(store, h, None);
    }
    apply_no_op(store, target, Some(epoch_row(target, activated)));
}

/// Forward apply across an activation epoch must advance
/// `cached_validation_settings` in the same call — without requiring
/// a restart to fold the new row from disk.
#[test]
fn forward_apply_advances_cached_validation_settings_in_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");

    let mut store = StateStore::open(&path).unwrap();
    seed_genesis(&mut store);

    // Pre-apply: cache reflects the empty initial cumulative.
    assert!(!store.validation_settings().is_rule_disabled(409));

    let activated = ErgoValidationSettingsUpdate {
        rules_to_disable: vec![215, 409],
        status_updates: vec![
            (1007, RuleStatus::Replaced(1017)),
            (1008, RuleStatus::Replaced(1018)),
            (1011, RuleStatus::Replaced(1016)),
        ],
    };
    apply_chain_to_epoch_boundary(&mut store, 1024, activated);

    // The bug pre-fix: this assertion failed in-session — the cache
    // stayed empty until restart.
    assert!(
        store.validation_settings().is_rule_disabled(409),
        "cached_validation_settings did not pick up the activation in-session"
    );
    assert!(store.validation_settings().is_rule_disabled(215));

    let cumul = store.validation_settings();
    let su = cumul.status_updates();
    assert!(su.iter().any(|(id, _)| *id == 1007));
    assert!(su.iter().any(|(id, _)| *id == 1008));
    assert!(su.iter().any(|(id, _)| *id == 1011));
}

/// In-session cumulative (after a forward apply across an activation)
/// must equal the cumulative reconstructed from disk on a fresh open.
/// This is the "restart oracle" the bug violated.
#[test]
fn in_session_cumulative_matches_post_restart_cumulative() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");

    let activated = ErgoValidationSettingsUpdate {
        rules_to_disable: vec![409],
        status_updates: vec![],
    };

    let in_session_rules: Vec<u16> = {
        let mut store = StateStore::open(&path).unwrap();
        seed_genesis(&mut store);
        apply_chain_to_epoch_boundary(&mut store, 1024, activated.clone());
        store.validation_settings().disabled_rules().to_vec()
    };

    let post_restart_rules: Vec<u16> = {
        let store = StateStore::open(&path).unwrap();
        store.validation_settings().disabled_rules().to_vec()
    };

    assert_eq!(
        in_session_rules, post_restart_rules,
        "in-session cumulative must equal reopened cumulative (proves the cache fold matches the on-disk fold)"
    );
    assert_eq!(in_session_rules, vec![409]);
}

/// Mode 2 install trust path persistence regression.
///
/// At the first epoch-boundary block after a UTXO snapshot install, the
/// validator is allowed to trust the block's `parsed_settings_update`
/// (the cumulative-from-launch validation_settings in the extension)
/// as authoritative. `block_proc.rs` encodes this trusted cumulative
/// into `voted_params_row.activated_update` so the standard
/// `apply_block` persistence path commits it to `voted_params` on
/// disk. This test pins that the trusted cumulative survives a store
/// drop + reopen — i.e., the trust isn't an in-memory-only override
/// that gets recomputed away on restart.
///
/// Why this matters: pre-snapshot history on mainnet has activated
/// rules 215 + 409 disabled (see the mainnet activated-rules report).
/// If the trust were RAM-only, the cache would reload as launch
/// defaults after restart and the next epoch boundary block would
/// reject again on `exMatchValidationSettings`.
#[test]
fn mode2_trusted_cumulative_survives_store_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");

    // Mainnet's cumulative at snapshot height 1,775,615 per
    // test-vectors/mainnet/voted_params_softfork_blobs.json
    // (extracted live on 2026-04-28).
    let trusted_cumulative = ErgoValidationSettingsUpdate {
        rules_to_disable: vec![215, 409],
        status_updates: vec![
            (1007, RuleStatus::Replaced(1017)),
            (1008, RuleStatus::Replaced(1018)),
            (1011, RuleStatus::Replaced(1016)),
        ],
    };

    let in_session = {
        let mut store = StateStore::open(&path).unwrap();
        seed_genesis(&mut store);
        // The first post-install epoch boundary block, simulated.
        // `apply_chain_to_epoch_boundary` writes a voted_params row
        // at h=1024 with activated_update=trusted_cumulative — exactly
        // what `block_proc.rs` does when the trust flag is consumed.
        apply_chain_to_epoch_boundary(&mut store, 1024, trusted_cumulative.clone());
        let s = store.validation_settings().clone();
        assert!(s.is_rule_disabled(215));
        assert!(s.is_rule_disabled(409));
        s
    };

    // Drop the in-memory store, re-open from the same data dir. The
    // cumulative MUST be reconstructed from the persisted voted_params
    // row — without that, the trust path's "fix" only survives until
    // the next restart.
    let after_reopen = {
        let store = StateStore::open(&path).unwrap();
        store.validation_settings().clone()
    };

    assert_eq!(in_session, after_reopen);
    assert_eq!(
        after_reopen.disabled_rules(),
        &[215, 409][..],
        "post-reopen cumulative must include the pre-snapshot disabled rules",
    );
    let su = after_reopen.status_updates();
    assert_eq!(su.len(), 3);
    assert!(su
        .iter()
        .any(|(id, s)| *id == 1007 && matches!(s, RuleStatus::Replaced(1017))));
    assert!(su
        .iter()
        .any(|(id, s)| *id == 1008 && matches!(s, RuleStatus::Replaced(1018))));
    assert!(su
        .iter()
        .any(|(id, s)| *id == 1011 && matches!(s, RuleStatus::Replaced(1016))));
}

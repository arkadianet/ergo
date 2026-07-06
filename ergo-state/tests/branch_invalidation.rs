//! Tests for durable full-block-validation branch invalidation
//! (`StateStore::invalidate_validation_branch`).
//!
//! Scala parity: `ErgoHistory.reportModifierIsInvalid` — on a state-apply
//! failure it writes a durable `validityKey(id) -> 0` for the failing header
//! and every descendant, then re-anchors the best-header pointer down to the
//! highest surviving header (`loopHeightDown`). These tests assert the same
//! liveness semantics against the Rust store: descendants are flagged,
//! invalidity survives restart, best_header re-anchors to the branch point,
//! and a fresh competing branch from the fork point extends normally.

use ergo_state::chain::HeaderMeta;
use ergo_state::store::StateStore;
use tempfile::TempDir;

// ----- helpers -----

fn meta(parent: [u8; 32], height: u32) -> HeaderMeta {
    HeaderMeta {
        parent_id: parent,
        height,
        // Monotone-increasing score so each stored header is a new best.
        cumulative_score: vec![0x01, height as u8],
        pow_validity: 1,
        timestamp: 1_700_000_000 + height as u64,
    }
}

/// Store `id` at `height` as the new best-header, maintaining the height
/// index exactly as the production header pipeline does.
fn extend(store: &mut StateStore, id: [u8; 32], parent: [u8; 32], height: u32) {
    let m = meta(parent, height);
    store
        .store_validated_header(
            &id,
            &[0u8; 8],
            &m,
            Some((height, m.cumulative_score.clone())),
        )
        .unwrap();
}

/// Build a linear best-header chain g(1) -> a1(2) -> a2(3) -> a3(4) -> a4(5).
/// Returns the five ids in height order.
fn linear_chain(store: &mut StateStore) -> [[u8; 32]; 5] {
    let g = [0x01; 32];
    let a1 = [0xA1; 32];
    let a2 = [0xA2; 32];
    let a3 = [0xA3; 32];
    let a4 = [0xA4; 32];
    extend(store, g, [0u8; 32], 1);
    extend(store, a1, g, 2);
    extend(store, a2, a1, 3);
    extend(store, a3, a2, 4);
    extend(store, a4, a3, 5);
    [g, a1, a2, a3, a4]
}

// ----- happy path -----

#[test]
fn invalidate_flags_failing_block_and_all_descendants() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    let [g, a1, a2, a3, a4] = linear_chain(&mut store);

    // Reject the block at height 3 (a2). Scala invalidates a2 + everything
    // reachable forward from it: {a2, a3, a4}.
    let invalidated = store.invalidate_validation_branch(a2).unwrap();
    assert_eq!(invalidated.len(), 3, "a2 + two descendants");
    assert!(invalidated.contains(&a2));
    assert!(invalidated.contains(&a3));
    assert!(invalidated.contains(&a4));

    // Descendants carry the durable validation-invalid flag (3), ancestors
    // are untouched (1 = valid).
    for id in [a2, a3, a4] {
        assert_eq!(store.get_header_meta(&id).unwrap().unwrap().pow_validity, 3);
        assert!(store.is_invalid(&id).unwrap());
    }
    for id in [g, a1] {
        assert_eq!(store.get_header_meta(&id).unwrap().unwrap().pow_validity, 1);
        assert!(!store.is_invalid(&id).unwrap());
    }
}

#[test]
fn invalidate_reanchors_best_header_to_branch_point() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    let [_g, a1, a2, _a3, _a4] = linear_chain(&mut store);
    assert_eq!(store.chain_state().best_header_height, 5);

    store.invalidate_validation_branch(a2).unwrap();

    // best_header re-anchors to a1 (height 2), the highest surviving header —
    // restoring the mining gate's `headers == full` equality at the branch
    // point (best_full sits at a1 because the a2 apply never committed).
    let cs = store.chain_state();
    assert_eq!(cs.best_header_height, 2);
    assert_eq!(cs.best_header_id, a1);
    assert_eq!(cs.best_header_score, meta([0u8; 32], 2).cumulative_score);
}

// ----- round-trips -----

#[test]
fn invalidation_survives_reopen() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("db");
    let a2;
    let a3;
    {
        let mut store = StateStore::open(&db).unwrap();
        let ids = linear_chain(&mut store);
        a2 = ids[2];
        a3 = ids[3];
        store.invalidate_validation_branch(a2).unwrap();
        store.shutdown_cleanly().unwrap();
    }

    // Reopen: session_invalids are cleared on restart, so this proves the
    // flag is PERSISTENT (pow_validity == 3), not session-scoped.
    let store = StateStore::open(&db).unwrap();
    assert!(
        store.is_invalid(&a2).unwrap(),
        "a2 still invalid after restart"
    );
    assert!(
        store.is_invalid(&a3).unwrap(),
        "descendant still invalid after restart"
    );
    assert_eq!(store.get_header_meta(&a2).unwrap().unwrap().pow_validity, 3);
    // Re-anchored best_header pointer also survived.
    assert_eq!(store.chain_state().best_header_height, 2);
}

// ----- competing branch -----

#[test]
fn valid_competing_branch_from_fork_point_extends_normally() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    let [_g, a1, a2, _a3, _a4] = linear_chain(&mut store);
    store.invalidate_validation_branch(a2).unwrap();
    assert_eq!(store.chain_state().best_header_height, 2);

    // A fresh, valid fork building on a1 (the fork point) must extend the
    // chain normally and re-advance best_header. The stale a2 entry at
    // height 3 is overwritten by the fork-flip in store_validated_header.
    let b2 = [0xB2; 32];
    let b3 = [0xB3; 32];
    extend(&mut store, b2, a1, 3);
    extend(&mut store, b3, b2, 4);

    let cs = store.chain_state();
    assert_eq!(cs.best_header_height, 4);
    assert_eq!(cs.best_header_id, b3);
    assert_eq!(store.get_header_id_at_height(3).unwrap(), Some(b2));
    assert!(!store.is_invalid(&b2).unwrap());
    assert!(!store.is_invalid(&b3).unwrap());
    // The abandoned invalid branch stays invalid.
    assert!(store.is_invalid(&a2).unwrap());
}

// ----- error paths -----

#[test]
fn invalidate_missing_header_meta_errors() {
    let dir = TempDir::new().unwrap();
    let mut store = StateStore::open(&dir.path().join("db")).unwrap();
    let err = store
        .invalidate_validation_branch([0xEE; 32])
        .expect_err("must reject an unknown header id");
    assert!(
        matches!(
            err,
            ergo_state::store::StateError::InvalidPrecondition { .. }
        ),
        "unknown header is caller misuse, not corruption: {err:?}"
    );
}

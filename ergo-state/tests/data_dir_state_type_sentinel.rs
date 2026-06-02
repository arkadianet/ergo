//! `StateStore` data_dir mode sentinel — `peek_state_type` +
//! `verify_or_init_state_type`.
//!
//! Two responsibilities:
//! - **Pre-open peek**: refuse a mode mismatch BEFORE any open-time
//!   migration can mutate an incompatible data dir.
//! - **Post-open stamp**: write the sentinel for fresh + legacy
//!   directories.
//!
//! Today only `"utxo"` is honored — the `StateStore` backend is UTXO-
//! only. `"digest"` is refused so we can't accidentally stamp a
//! digest label onto UTXO storage before the real `DigestState`
//! backend ships in Mode 5/6 part 2b.

use ergo_state::store::StateStore;
use tempfile::tempdir;

#[test]
fn fresh_dir_with_utxo_writes_sentinel_and_passes() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("state.redb");
    let store = StateStore::open(&path).unwrap();
    store.verify_or_init_state_type("utxo").expect("fresh utxo");
    // Sentinel must be persisted — the next peek sees it.
    drop(store);
    let recorded = StateStore::peek_state_type(&path).expect("peek");
    assert_eq!(recorded.as_deref(), Some("utxo"));
}

#[test]
fn fresh_dir_with_digest_accepted_for_mode_6() {
    // Mode 6 (headers-only) ships in part 2b — the `StateStore`
    // backend is reused but `apply_block` is never invoked, so the
    // on-disk shape stays empty. The sentinel records the operator's
    // intent so a fresh digest dir can't later be reopened as utxo
    // (which would silently turn on UTXO mode against an empty store).
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("state.redb");
    let store = StateStore::open(&path).unwrap();
    store
        .verify_or_init_state_type("digest")
        .expect("Mode 6 canonical: fresh dir + digest must accept");
    drop(store);
    let recorded = StateStore::peek_state_type(&path).expect("peek");
    assert_eq!(recorded.as_deref(), Some("digest"));
}

#[test]
fn utxo_dir_reopened_as_digest_rejected() {
    // An existing UTXO archive cannot be reinterpreted as Mode 6 in
    // place — UTXO state would coexist with the digest sentinel,
    // creating an undefined hybrid. Operator must use a fresh
    // data_dir for Mode 6.
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("state.redb");
    {
        let store = StateStore::open(&path).unwrap();
        store.verify_or_init_state_type("utxo").unwrap();
    }
    {
        let store = StateStore::open(&path).unwrap();
        let err = store
            .verify_or_init_state_type("digest")
            .expect_err("utxo→digest must be refused");
        let msg = format!("{err}");
        assert!(msg.contains("utxo"), "error: {msg}");
        assert!(msg.contains("digest"), "error: {msg}");
        assert!(
            msg.contains("interconvertible") || msg.contains("fresh data_dir"),
            "error: {msg}",
        );
    }
}

#[test]
fn digest_dir_reopened_as_utxo_rejected() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("state.redb");
    {
        let store = StateStore::open(&path).unwrap();
        store.verify_or_init_state_type("digest").unwrap();
    }
    {
        let store = StateStore::open(&path).unwrap();
        let err = store
            .verify_or_init_state_type("utxo")
            .expect_err("digest→utxo must be refused");
        let msg = format!("{err}");
        assert!(msg.contains("utxo"), "error: {msg}");
        assert!(msg.contains("digest"), "error: {msg}");
    }
}

#[test]
fn same_mode_utxo_reopen_passes() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("state.redb");
    {
        let store = StateStore::open(&path).unwrap();
        store.verify_or_init_state_type("utxo").unwrap();
    }
    {
        let store = StateStore::open(&path).unwrap();
        store
            .verify_or_init_state_type("utxo")
            .expect("same mode reopen must pass");
    }
}

#[test]
fn legacy_unsentinel_dir_gets_stamped_on_first_verify() {
    // A pre-sentinel archive DB has no `DATA_DIR_STATE_TYPE_KEY`
    // entry. First verify-call must infer UTXO and stamp the
    // sentinel, so subsequent opens see a recorded value.
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("state.redb");
    {
        // Open + close without calling verify — simulates a legacy DB.
        let _store = StateStore::open(&path).unwrap();
    }
    let pre = StateStore::peek_state_type(&path).unwrap();
    assert_eq!(pre, None, "pre-verify: no sentinel");
    {
        let store = StateStore::open(&path).unwrap();
        store.verify_or_init_state_type("utxo").unwrap();
    }
    let post = StateStore::peek_state_type(&path).unwrap();
    assert_eq!(post.as_deref(), Some("utxo"), "verify must have stamped");
}

#[test]
fn peek_on_fresh_dir_returns_none() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("state.redb");
    // Open and immediately close — no verify call, so no sentinel
    // ever stamped.
    {
        let _store = StateStore::open(&path).unwrap();
    }
    let peeked = StateStore::peek_state_type(&path).expect("peek");
    assert_eq!(peeked, None, "fresh dir has no sentinel");
}

#[test]
fn invalid_expected_value_rejected() {
    let tmp = tempdir().unwrap();
    let store = StateStore::open(&tmp.path().join("state.redb")).unwrap();
    let err = store
        .verify_or_init_state_type("flux-capacitor")
        .expect_err("only utxo|digest accepted");
    let msg = format!("{err}");
    assert!(
        msg.contains("flux-capacitor") || msg.contains("expected_state_type"),
        "error: {msg}",
    );
}

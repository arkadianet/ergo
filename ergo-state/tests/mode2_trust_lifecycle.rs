//! Mode-2 install trust-flag lifecycle round-trip.
//!
//! Pins the four-step sequence `install_snapshot_state` arms +
//! the validator consumes:
//!
//! 1. Fresh store: `is_armed() == false`.
//! 2. Arm via the production sentinel-write primitive
//!    (`MODE2_TRUST_FIRST_EPOCH_KEY` insert into `CHAIN_STATE_META`).
//!    `is_armed() == true`.
//! 3. Drop + reopen: `is_armed() == true` (persistence across
//!    restart — this is the invariant the Mode-2 bootstrap relies
//!    on between snapshot install at boot and the first
//!    post-install epoch boundary).
//! 4. Consume + drop + reopen: `is_armed() == false` (clear
//!    persisted across restart — re-arming on restart would let
//!    the trust path fire twice).
//!
//! The arming primitive `arm_mode2_trust_first_epoch_internal`
//! lives next to `consume_mode2_trust_first_epoch` in
//! `store/open.rs` and is the same write the production
//! `install_snapshot_state` performs inside its atomic write_txn.
//! Re-using the same primitive (not a synthetic redb write)
//! means a future drift in the sentinel byte / key would fail
//! this test the same way it would fail the production install
//! path.

#![cfg(feature = "test-helpers")]

use tempfile::TempDir;

use ergo_state::store::StateStore;

#[test]
fn mode2_trust_flag_arms_persists_consumes_and_stays_consumed() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("state.redb");

    // (1) Fresh store: flag absent.
    {
        let store = StateStore::open(&path).expect("open fresh");
        assert!(
            !store.is_mode2_trust_first_epoch_armed(),
            "fresh store must not have the Mode-2 trust flag armed",
        );
    }

    // (2) Arm via the same primitive `install_snapshot_state` uses.
    {
        let mut store = StateStore::open(&path).expect("reopen for arming");
        assert!(
            !store.is_mode2_trust_first_epoch_armed(),
            "still unarmed before the arming call",
        );
        store
            .arm_mode2_trust_first_epoch_for_test()
            .expect("arming primitive must commit");
        assert!(
            store.is_mode2_trust_first_epoch_armed(),
            "in-memory latch must flip immediately after the arming commit",
        );
    }

    // (3) Drop + reopen: the persisted sentinel must rehydrate the
    // in-memory latch. This is the invariant Mode-2 bootstrap relies
    // on across the restart window between snapshot install and the
    // first post-install epoch boundary.
    {
        let store = StateStore::open(&path).expect("reopen after arm");
        assert!(
            store.is_mode2_trust_first_epoch_armed(),
            "persisted Mode-2 sentinel must rehydrate is_armed() on reopen",
        );
    }

    // (4a) Consume: in-memory latch clears, persisted byte removed.
    {
        let mut store = StateStore::open(&path).expect("reopen for consume");
        assert!(
            store.is_mode2_trust_first_epoch_armed(),
            "still armed pre-consume"
        );
        store.consume_mode2_trust_first_epoch();
        assert!(
            !store.is_mode2_trust_first_epoch_armed(),
            "in-memory latch clears immediately after consume",
        );
    }

    // (4b) Drop + reopen: consumed flag stays consumed across
    // restart. A regression that left the sentinel disk-set after
    // consume would re-arm on next boot and fire the trust path
    // twice — a Mode-2 acceptance fault.
    {
        let store = StateStore::open(&path).expect("reopen after consume");
        assert!(
            !store.is_mode2_trust_first_epoch_armed(),
            "consumed Mode-2 sentinel must STAY consumed across reopen",
        );
    }
}

/// Idempotent arming: arming twice over a reopen boundary must not
/// double-fire or leave the in-memory latch out of sync with the
/// persisted byte. Mirrors the production safety property — if the
/// snapshot install crashes between arming and the AVL tree rebuild,
/// the next boot may re-enter the same arming path; the second arm
/// must observe the already-set flag without corrupting it.
#[test]
fn mode2_trust_flag_double_arm_is_idempotent_across_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("state.redb");

    {
        let mut store = StateStore::open(&path).expect("open");
        store
            .arm_mode2_trust_first_epoch_for_test()
            .expect("first arm");
        assert!(store.is_mode2_trust_first_epoch_armed());
    }
    {
        let mut store = StateStore::open(&path).expect("reopen");
        assert!(store.is_mode2_trust_first_epoch_armed(), "still armed");
        // Re-arming over a still-armed flag MUST NOT clear it.
        store
            .arm_mode2_trust_first_epoch_for_test()
            .expect("second arm");
        assert!(
            store.is_mode2_trust_first_epoch_armed(),
            "double-arm preserves the armed state, doesn't toggle",
        );
    }
    {
        let store = StateStore::open(&path).expect("third reopen");
        assert!(
            store.is_mode2_trust_first_epoch_armed(),
            "two arms + reopen still armed",
        );
    }
}

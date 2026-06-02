//! Phase 2a coverage: `CommittedSnapshot` — the single-read-transaction
//! committed view that the off-loop mining-candidate engine builds from.
//!
//! The headline property is **consensus parity**: a candidate dry-run run
//! against a `CommittedSnapshot` must produce byte-identical
//! `(state_root, ad_proof_bytes, tip)` to the on-loop
//! `StateStore::candidate_dry_run` for the same parent and change-set.
//! Both paths hydrate a `BatchAVLProver` from equivalent committed state
//! and then run the identical mutation/digest/proof sequence, so the only
//! thing this proves — and the only thing that could break consensus — is
//! that the snapshot's redb-txn-sourced hydration reproduces the live
//! arena's tree exactly.
//!
//! Also covers: the single-transaction inputs (tip, header, last-10
//! window, params, settings, root) all come from one frozen MVCC view,
//! the `synced()` predicate matches the live mining gate, and the view is
//! immune to commits that land after it opened.

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header, Header};
use ergo_state::store::StateStore;

// ----- helpers -----

fn seed_genesis(store: &mut StateStore) {
    let boxes: Vec<([u8; 32], Vec<u8>)> = vec![{
        let mut id = [0u8; 32];
        id[31] = 1;
        (id, vec![0xAAu8; 32])
    }];
    store.initialize_genesis(&boxes).unwrap();
}

fn synthetic_header(height: u32, parent_id: ModifierId) -> Header {
    Header {
        version: 2,
        parent_id,
        ad_proofs_root: Digest32::from_bytes([0u8; 32]),
        transactions_root: Digest32::from_bytes([0u8; 32]),
        state_root: ADDigest::from_bytes([0u8; 33]),
        timestamp: 1_000_000 + height as u64,
        extension_root: Digest32::from_bytes([0u8; 32]),
        n_bits: 16842752,
        height,
        votes: [0u8; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
            nonce: [0u8; 8],
        },
    }
}

/// Apply `n` synthetic blocks (each with a real, decodable header) on top
/// of genesis. Returns the tip header id.
fn apply_n_blocks(store: &mut StateStore, n: u32) -> [u8; 32] {
    let mut parent_id: ModifierId = Digest32::from_bytes([0u8; 32]).into();
    let mut tip = [0u8; 32];
    for h in 1..=n {
        let hdr = synthetic_header(h, parent_id);
        let (bytes, id) = serialize_header(&hdr).expect("serialize header");
        let id_bytes: [u8; 32] = *id.as_bytes();
        store.store_header(&id_bytes, &bytes).expect("store_header");
        let expected = store.root_digest();
        store
            .apply_block_unchecked_for_test(h, &id_bytes, &expected, &[])
            .expect("apply");
        parent_id = id;
        tip = id_bytes;
    }
    tip
}

fn synced_predicate(store: &StateStore) -> bool {
    let cs = store.chain_state();
    cs.best_full_block_height > 0
        && cs.best_header_height == cs.best_full_block_height
        && cs.best_header_id == cs.best_full_block_id
}

// ----- happy path -----

#[test]
fn open_returns_none_on_store_without_committed_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    // No genesis committed yet: there is no committed AVL state to snapshot.
    assert!(
        store.committed_snapshot().unwrap().is_none(),
        "a store with no committed state must yield no snapshot"
    );
}

#[test]
fn snapshot_tip_and_root_match_store_at_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    seed_genesis(&mut store);

    let snap = store
        .committed_snapshot()
        .unwrap()
        .expect("genesis is committed state");
    let cs = store.chain_state();
    assert_eq!(snap.best_full_block_id(), cs.best_full_block_id);
    assert_eq!(snap.best_full_block_height(), cs.best_full_block_height);
    assert_eq!(snap.best_full_block_height(), 0, "genesis is height 0");
    assert_eq!(snap.state_root(), store.root_digest());
    assert!(
        !snap.synced(),
        "genesis (height 0) must not satisfy the synced predicate"
    );
}

// ----- oracle parity -----

#[test]
fn dry_run_matches_store_oracle_at_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    seed_genesis(&mut store);

    let oracle = store.candidate_dry_run(&[]).expect("on-loop dry-run");
    let snap = store.committed_snapshot().unwrap().expect("snapshot");
    let got = snap.candidate_dry_run(&[]).expect("off-loop dry-run");

    assert_eq!(oracle.0, got.0, "state_root must be byte-identical");
    assert_eq!(oracle.1, got.1, "ad_proof_bytes must be byte-identical");
    assert_eq!(oracle.2, got.2, "snapshot tip id must match");
}

#[test]
fn dry_run_matches_store_oracle_at_height_15() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    seed_genesis(&mut store);
    apply_n_blocks(&mut store, 15);

    let oracle = store.candidate_dry_run(&[]).expect("on-loop dry-run");
    let snap = store.committed_snapshot().unwrap().expect("snapshot");

    // Every consensus-bearing input the snapshot exposes must agree with
    // the live store.
    let cs = store.chain_state();
    assert_eq!(snap.best_full_block_id(), cs.best_full_block_id);
    assert_eq!(snap.best_full_block_height(), 15);
    assert_eq!(snap.best_header_id(), cs.best_header_id);
    assert_eq!(snap.best_header_height(), cs.best_header_height);
    assert_eq!(snap.synced(), synced_predicate(&store));
    assert!(snap.synced(), "15 applied blocks, header==full => synced");
    assert_eq!(snap.state_root(), store.root_digest());

    let got = snap.candidate_dry_run(&[]).expect("off-loop dry-run");
    assert_eq!(oracle.0, got.0, "state_root must be byte-identical");
    assert_eq!(oracle.1, got.1, "ad_proof_bytes must be byte-identical");
    assert_eq!(oracle.2, got.2, "snapshot tip id must match");
}

// ----- accessor parity -----

#[test]
fn header_window_and_params_match_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    seed_genesis(&mut store);
    let tip = apply_n_blocks(&mut store, 15);

    let snap = store.committed_snapshot().unwrap().expect("snapshot");

    // header(tip) decodes and is height 15.
    let hdr = snap
        .header(&tip)
        .expect("header read")
        .expect("tip present");
    assert_eq!(hdr.height, 15);

    // get_header_bytes parity: the raw bytes the CandidateStateView trait
    // reads must equal the StateStore oracle.
    assert_eq!(
        snap.get_header_bytes(&tip).expect("snap header bytes"),
        store.get_header(&tip).expect("store header bytes"),
        "get_header_bytes must match StateStore::get_header"
    );

    // window matches the on-loop window exactly (tip-first, 10 entries).
    let snap_window = snap.last_headers_window().expect("snapshot window");
    let store_window = store.last_applied_chain_window_10().expect("store window");
    assert_eq!(snap_window.len(), 10);
    for (a, b) in snap_window.iter().zip(store_window.iter()) {
        assert_eq!(a.height, b.height);
        assert_eq!(
            serialize_header(a).unwrap().1.as_bytes(),
            serialize_header(b).unwrap().1.as_bytes(),
            "window header id mismatch at height {}",
            a.height
        );
    }

    // params + settings match the on-loop tip snapshot.
    let (store_params, store_settings) = store.tip_snapshot_params();
    assert_eq!(snap.active_params().expect("params"), store_params);
    assert_eq!(
        snap.validation_settings()
            .expect("settings")
            .disabled_rules(),
        store_settings.disabled_rules(),
    );
}

// ----- snapshot isolation (MVCC) -----

#[test]
fn snapshot_is_frozen_against_later_commits() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    seed_genesis(&mut store);
    apply_n_blocks(&mut store, 15);

    // Freeze a snapshot at h=15, capturing the h=15 root via dry-run.
    let snap = store.committed_snapshot().unwrap().expect("snapshot");
    let frozen_root = snap.candidate_dry_run(&[]).expect("dry-run").0;
    assert_eq!(frozen_root, store.root_digest());

    // Advance the live store one block. The snapshot must NOT observe it:
    // its held read transaction pins the h=15 view of AVL_NODES.
    let mut parent_id: ModifierId = ModifierId::from_bytes(snap.best_full_block_id());
    let hdr = synthetic_header(16, parent_id);
    let (bytes, id) = serialize_header(&hdr).unwrap();
    let id_bytes: [u8; 32] = *id.as_bytes();
    parent_id = id; // silence unused-assignment in case of future edits
    let _ = parent_id;
    store.store_header(&id_bytes, &bytes).unwrap();
    let new_expected = store.root_digest();
    store
        .apply_block_unchecked_for_test(16, &id_bytes, &new_expected, &[])
        .unwrap();

    assert_eq!(store.height(), 16, "live store advanced");
    assert_eq!(
        snap.best_full_block_height(),
        15,
        "snapshot tip is frozen at open time"
    );
    assert_eq!(
        snap.candidate_dry_run(&[]).expect("dry-run again").0,
        frozen_root,
        "snapshot dry-run still reflects the h=15 tree, not the h=16 commit"
    );
}

// ----- error paths -----

#[test]
fn window_errors_when_tip_below_10() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    seed_genesis(&mut store);
    apply_n_blocks(&mut store, 5);

    let snap = store.committed_snapshot().unwrap().expect("snapshot");
    let err = snap.last_headers_window().expect_err("must error below 10");
    match err {
        ergo_state::store::StateError::EarlyIBD {
            needed_min,
            observed,
        } => {
            assert_eq!(needed_min, 10);
            assert_eq!(observed, 5);
        }
        other => panic!("expected EarlyIBD, got {other:?}"),
    }
}

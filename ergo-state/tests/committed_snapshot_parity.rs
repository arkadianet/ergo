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
    synthetic_header_with_ts_base(height, parent_id, 1_000_000)
}

fn synthetic_header_with_ts_base(height: u32, parent_id: ModifierId, ts_base: u64) -> Header {
    Header {
        version: 2,
        parent_id,
        ad_proofs_root: Digest32::from_bytes([0u8; 32]),
        transactions_root: Digest32::from_bytes([0u8; 32]),
        state_root: ADDigest::from_bytes([0u8; 33]),
        timestamp: ts_base + height as u64,
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

/// Like [`apply_n_blocks`] but with a custom timestamp base, so a second
/// chain of the same height gets DIFFERENT header ids (the id hashes the
/// timestamp). Used only by the equal-height reorg cache test.
fn apply_n_blocks_with_timestamp_base(store: &mut StateStore, n: u32, ts_base: u64) -> [u8; 32] {
    let mut parent_id: ModifierId = Digest32::from_bytes([0u8; 32]).into();
    let mut tip = [0u8; 32];
    for h in 1..=n {
        let hdr = synthetic_header_with_ts_base(h, parent_id, ts_base);
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

// ----- cached dry-run parity (per-tip base) -----

/// Same-tip repeat: 1 miss + 2 hits, each bit-equal to a fresh uncached
/// dry-run. Through the PUBLIC `candidate_dry_run_cached` entry point with an
/// empty change set — the structural-parallel `build_utxo_changes_checked`
/// path. (Hit-reuses-base identity is asserted by the crate-internal unit
/// test, which can read the `Rc` root; this integration test pins the
/// consensus property: cached bytes == uncached bytes.)
#[test]
fn cached_same_tip_repeat_matches_uncached() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    seed_genesis(&mut store);
    apply_n_blocks(&mut store, 12);

    let mut base = None;
    for call in 0..3 {
        let oracle = store.candidate_dry_run(&[]).expect("uncached oracle");
        let snap = store.committed_snapshot().unwrap().expect("snapshot");
        let mut disp = None;
        let got = snap
            .candidate_dry_run_cached(&mut base, &[], &mut disp)
            .expect("cached dry-run");
        assert_eq!(oracle.0, got.0, "call {call}: state_root must match oracle");
        assert_eq!(
            oracle.1, got.1,
            "call {call}: proof bytes must match oracle"
        );
        assert_eq!(oracle.2, got.2, "call {call}: tip id must match oracle");
        assert!(base.is_some(), "call {call}: base memoized after success");
    }
}

/// Tip advance: a cached call after applying a block must miss (tip id
/// changed — even though an empty block leaves the AVL root unchanged, the
/// key is the tip id, not the root), rebuild, and match the uncached oracle
/// at the new tip. Proves the cache key is the committed tip id.
#[test]
fn cached_tip_advance_rebuilds_and_matches() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    seed_genesis(&mut store);
    let tip_a = apply_n_blocks(&mut store, 10);

    let mut base = None;
    let snap_a = store.committed_snapshot().unwrap().expect("snapshot A");
    snap_a
        .candidate_dry_run_cached(&mut base, &[], &mut None)
        .expect("first cached build");
    assert_eq!(
        base.as_ref().map(|b| b.tip_id()),
        Some(tip_a),
        "base keyed to tip A"
    );

    // Advance one block; the committed tip id changes.
    let tip_b = apply_n_blocks(&mut store, 1);
    assert_ne!(tip_a, tip_b, "applying a block changes the tip id");

    let oracle = store.candidate_dry_run(&[]).expect("uncached oracle at B");
    let snap_b = store.committed_snapshot().unwrap().expect("snapshot B");
    let mut disp_b = None;
    let got = snap_b
        .candidate_dry_run_cached(&mut base, &[], &mut disp_b)
        .expect("cached build at B");
    assert_eq!(
        base.as_ref().map(|b| b.tip_id()),
        Some(tip_b),
        "base rebuilt and rekeyed to tip B (miss on tip change)"
    );
    assert_eq!(oracle.0, got.0, "state_root must match oracle at new tip");
    assert_eq!(oracle.1, got.1, "proof bytes must match oracle at new tip");
    assert_eq!(oracle.2, got.2, "tip id must match oracle at new tip");
    // The tip changed (N→N+1) so the cache misses. A stale base exists (keyed
    // to tip_a), so try_advance_base runs: the parent-id check passes
    // (tip_b's header.parent_id == tip_a), but no BlockTransactions section is
    // stored for tip_b (apply_n_blocks does not store BT sections), so the
    // advance fails on the missing-section guard and falls back to full rehydrate.
    // The disposition is RehydratedAfterFailedAdvance (not Rehydrated, which only
    // fires when no prior base exists at all).
    assert_eq!(
        disp_b,
        Some(ergo_state::store::BaseDisposition::RehydratedAfterFailedAdvance),
        "tip-advance without a stored BT section must report RehydratedAfterFailedAdvance"
    );
}

/// Equal-height reorg: the parity harness builds only a single linear chain
/// (`apply_block_unchecked_for_test` enforces parent linkage), so a true
/// in-store sibling tip at the same height is not cheaply producible. We
/// instead drive the exact key-mismatch the reorg invariant relies on: two
/// independent stores reach height 10 along DIFFERENT block ids, and a base
/// memoized against store A's tip is fed a snapshot of store B. Because the
/// cache key is the committed tip id ONLY (never height, never the root),
/// the differing tip id forces a miss + rebuild, and the rebuilt base matches
/// B's uncached oracle.
///
/// What this proves: the tip-id key invalidates on an equal-height tip swap.
/// What it does NOT prove: an in-store reorg's rollback mechanics (covered by
/// the state-store reorg suite) — only the cache seam's reaction to a tip-id
/// change at equal height.
#[test]
fn cached_reorg_same_height_rebuilds() {
    let dir_a = tempfile::tempdir().unwrap();
    let mut store_a = StateStore::open(dir_a.path().join("a.redb").as_path()).unwrap();
    seed_genesis(&mut store_a);
    let tip_a = apply_n_blocks(&mut store_a, 10);

    // Store B: same height, different tip id. The synthetic header id is a
    // hash over (height, parent_id, timestamp, ...), so a distinct timestamp
    // offset yields a divergent chain with different ids at every height —
    // the genesis box alone would NOT change the header ids.
    let dir_b = tempfile::tempdir().unwrap();
    let mut store_b = StateStore::open(dir_b.path().join("b.redb").as_path()).unwrap();
    seed_genesis(&mut store_b);
    let tip_b = apply_n_blocks_with_timestamp_base(&mut store_b, 10, 9_000_000);
    assert_ne!(
        tip_a, tip_b,
        "two divergent height-10 chains must have different tip ids"
    );

    // Memoize a base against store A's tip.
    let mut base = None;
    let snap_a = store_a.committed_snapshot().unwrap().expect("snapshot A");
    snap_a
        .candidate_dry_run_cached(&mut base, &[], &mut None)
        .expect("cached build on A");
    assert_eq!(base.as_ref().map(|b| b.tip_id()), Some(tip_a));

    // Now run against store B's snapshot: tip id differs ⇒ miss ⇒ rebuild.
    let oracle_b = store_b.candidate_dry_run(&[]).expect("uncached oracle B");
    let snap_b = store_b.committed_snapshot().unwrap().expect("snapshot B");
    let mut disp_b = None;
    let got = snap_b
        .candidate_dry_run_cached(&mut base, &[], &mut disp_b)
        .expect("cached build on B");
    assert_eq!(
        base.as_ref().map(|b| b.tip_id()),
        Some(tip_b),
        "equal-height tip swap forces a rebuild rekeyed to B"
    );
    assert_eq!(oracle_b.0, got.0, "state_root must match B's oracle");
    assert_eq!(oracle_b.1, got.1, "proof bytes must match B's oracle");
    assert_eq!(oracle_b.2, got.2, "tip id must match B's oracle");
    // A stale base exists (keyed to tip_a). For the sibling reorg, store B's
    // tip_b has a different parent_id than tip_a (they're independent chains),
    // so try_advance_base's parent-id check fires first and returns an error
    // ("not single-step"). The advance falls back to full rehydrate with
    // RehydratedAfterFailedAdvance (not Rehydrated, which only fires when
    // no prior base exists at all).
    assert_eq!(
        disp_b,
        Some(ergo_state::store::BaseDisposition::RehydratedAfterFailedAdvance),
        "equal-height tip swap (sibling reorg) must report RehydratedAfterFailedAdvance"
    );
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

// ----- short window (early chain) -----

/// Below 10 applied blocks the snapshot window returns the AVAILABLE headers
/// (tip-first), not an error — parity with `StateStore::last_applied_chain_window_10`
/// and the apply path, so a chain mined up from genesis is buildable at heights 1..9.
#[test]
fn window_returns_available_headers_when_tip_below_10() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    seed_genesis(&mut store);
    apply_n_blocks(&mut store, 5);

    let snap = store.committed_snapshot().unwrap().expect("snapshot");
    let window = snap.last_headers_window().expect("window");
    assert_eq!(window.len(), 5, "5 applied blocks → 5 headers");
    assert_eq!(window[0].height, 5, "index 0 is tip-first");
    assert_eq!(window.last().unwrap().height, 1, "oldest is height 1");
}

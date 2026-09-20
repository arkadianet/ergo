//! Mode 3 Phase 3a + Phase 4 — storage-side resurrection guard
//! and rollback-below-sentinel guard.
//!
//! Phase 3a defense-in-depth: `store_block_section_typed` rejects
//! writes whose parent header is below the prune sentinel. The
//! receive-side gating in `ergo-sync::executor` silently drops
//! these; the storage-side guard catches executor bypasses and
//! direct-write attempts (a rogue peer pushing sections that
//! bypassed the assembly pipeline). Together they make pruning
//! monotonic — once evicted, a section can't be resurrected.
//!
//! Phase 4 rollback guard: `rollback_to` refuses target heights
//! below the prune sentinel BEFORE any mutation. The
//! `blocks_to_keep >= ROLLBACK_WINDOW + SAFETY_MARGIN` config
//! floor (enforced at TOML parse time) makes this unreachable in
//! normal operation; the storage seam catches misconfiguration
//! and off-by-one edges.

#![cfg(feature = "test-helpers")]

use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::Header;
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::store::StateStore;
use tempfile::TempDir;

fn open_store() -> (StateStore, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).expect("open store");
    store.initialize_genesis(&[]).expect("init genesis");
    (store, dir)
}

fn synth_header(height: u32) -> Header {
    use ergo_primitives::digest::{ADDigest as AD, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    let root = |seed: u8| {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&height.to_be_bytes());
        b[4] = seed;
        b
    };
    let mut state_root_bytes = [0u8; 33];
    state_root_bytes[32] = 0;
    Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0u8; 32]),
        ad_proofs_root: Digest32::from_bytes(root(0xAD)),
        state_root: AD::from_bytes(state_root_bytes),
        transactions_root: Digest32::from_bytes(root(0x77)),
        timestamp: 1_700_000_000 + height as u64,
        n_bits: 0x1d00ffff,
        height,
        extension_root: Digest32::from_bytes(root(0xEE)),
        votes: [0u8; 3],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x02; 33]),
            nonce: [0xAA; 8],
        },
    }
}

fn header_id_and_bytes(h: &Header) -> ([u8; 32], Vec<u8>) {
    let (bytes, id) = ergo_ser::header::serialize_header(h).expect("synth header serialize");
    (*id.as_bytes(), bytes)
}

fn stamp_height(store: &StateStore, height: u32) {
    let h = synth_header(height);
    let (id, bytes) = header_id_and_bytes(&h);
    store.store_header(&id, &bytes).expect("store_header");
    store
        .promote_header_to_height_index_for_test(height, &id)
        .expect("promote_header_to_height_index_for_test");
    for (type_byte, root) in [
        (TYPE_AD_PROOFS, h.ad_proofs_root.as_bytes()),
        (TYPE_BLOCK_TRANSACTIONS, h.transactions_root.as_bytes()),
        (TYPE_EXTENSION, h.extension_root.as_bytes()),
    ] {
        let section_id = compute_section_id(type_byte, &id, root);
        store
            .store_block_section_typed(&section_id, &[0xAA; 8], type_byte)
            .expect("initial section write");
    }
}

fn apply_empty_block(store: &mut StateStore, height: u32) {
    let canonical = synth_header(height);
    let (id, _) = header_id_and_bytes(&canonical);
    let expected = store.root_digest();
    store
        .apply_block_unchecked_for_test(height, &id, &expected, &[])
        .unwrap_or_else(|e| panic!("apply at height {height}: {e:?}"));
}

// ----- Phase 3a — storage-side resurrection guard -----

#[test]
fn verify_height_indexes_completeness_passes_after_clean_setup() {
    // A normally-populated store has matching row counts in
    // HEADER_META, HEADERS_BY_HEIGHT, and SECTION_HEIGHT_INDEX
    // (3 section rows per header). The completeness check must
    // accept it.
    let (mut store, _dir) = open_store();
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    store
        .verify_height_indexes_completeness()
        .expect("normally-populated store passes completeness check");
}

#[test]
fn verify_height_indexes_completeness_fails_when_headers_by_height_wiped() {
    // Apply blocks to populate HEADER_META + HEADERS_BY_HEIGHT,
    // then wipe HEADERS_BY_HEIGHT via the test-helper to
    // simulate a sentinel-stamped backfill whose rows were later
    // deleted. The completeness check must fail loud.
    let (mut store, _dir) = open_store();
    for h in 1..=5 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    store
        .verify_height_indexes_completeness()
        .expect("pre-wipe store is complete");
    store
        .clear_headers_by_height_state_for_test()
        .expect("simulate wipe");
    let err = store
        .verify_height_indexes_completeness()
        .expect_err("wiped HEADERS_BY_HEIGHT must fail loud");
    assert!(
        format!("{err:?}").contains("DbCorruption")
            && format!("{err:?}").contains("headers_by_height"),
        "expected DbCorruption(headers_by_height), got {err:?}",
    );
}

#[test]
fn verify_height_indexes_completeness_fails_on_malformed_headers_by_height_row() {
    // A `HEADERS_BY_HEIGHT` row whose payload is NOT a multiple
    // of 32 bytes is the corruption shape that
    // `read_height_index_ids` rejects at prune time. The boot
    // verifier MUST surface it at boot rather than letting the
    // node start cleanly and blow up on the first eviction.
    let (mut store, _dir) = open_store();
    for h in 1..=5 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    store
        .verify_height_indexes_completeness()
        .expect("pre-corruption store is complete");
    store
        .write_malformed_headers_by_height_row_for_test(3)
        .expect("simulate malformed row");
    let err = store
        .verify_height_indexes_completeness()
        .expect_err("malformed row must fail loud");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("DbCorruption")
            && msg.contains("headers_by_height")
            && msg.contains("multiple of 32"),
        "expected DbCorruption(headers_by_height, 'multiple of 32'), got {msg}",
    );
}

#[test]
fn verify_height_indexes_completeness_fails_when_section_height_index_wiped() {
    // Apply blocks to populate HEADER_META + SECTION_HEIGHT_INDEX,
    // then wipe SECTION_HEIGHT_INDEX while leaving HEADER_META
    // and HEADERS_BY_HEIGHT intact. The checker walks HEADER_META
    // and must fail loud as soon as the first section lookup
    // returns no row.
    let (mut store, _dir) = open_store();
    for h in 1..=5 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    store
        .verify_height_indexes_completeness()
        .expect("pre-wipe store is complete");
    store
        .clear_section_height_index_for_test()
        .expect("simulate wipe");
    let err = store
        .verify_height_indexes_completeness()
        .expect_err("wiped SECTION_HEIGHT_INDEX must fail loud");
    assert!(
        format!("{err:?}").contains("DbCorruption")
            && format!("{err:?}").contains("section_height_index"),
        "expected DbCorruption(section_height_index), got {err:?}",
    );
}

#[test]
fn phase3a_archive_mode_does_not_gate_section_writes() {
    // Archive: `blocks_to_keep = -1`. The guard short-circuits to
    // skip the index lookup entirely — section writes succeed
    // regardless of any sentinel value.
    let (mut store, _dir) = open_store();
    // Archive is the default; explicit set for clarity.
    store.set_blocks_to_keep(-1);

    // Stamp a header + section at h=1. The store_header writes
    // the SECTION_HEIGHT_INDEX row; subsequent section writes
    // would hit the guard if it were active.
    let h = synth_header(1);
    let (id, bytes) = header_id_and_bytes(&h);
    store.store_header(&id, &bytes).unwrap();
    let section_id = compute_section_id(TYPE_AD_PROOFS, &id, h.ad_proofs_root.as_bytes());
    store
        .store_block_section_typed(&section_id, &[0xAA; 8], TYPE_AD_PROOFS)
        .expect("archive must accept sub-genesis section writes");
}

#[test]
fn phase3a_rejects_sub_sentinel_section_resurrection_after_eviction() {
    // Set up a pruned store, drive eviction past h=1, then
    // attempt to resurrect the (now-deleted) section bytes for
    // h=1 WITHOUT restamping the header. Eviction retains
    // SECTION_HEIGHT_INDEX as a tombstone (only deletes
    // BLOCK_SECTIONS), so the storage guard's
    // `get_section_height` lookup still resolves the height as
    // sub-sentinel and the write is rejected with PrunedSection.
    //
    // Without the tombstone-retention design, post-eviction
    // lookups would return None and the guard would fail-OPEN,
    // breaking monotonic pruning.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);

    // stamp_height writes the SECTION_HEIGHT_INDEX row for h=1.
    // The section_id we derive below is the SAME id eviction
    // computes and deletes from BLOCK_SECTIONS.
    let h1 = synth_header(1);
    let (h1_id, _) = header_id_and_bytes(&h1);
    let section_id = compute_section_id(TYPE_AD_PROOFS, &h1_id, h1.ad_proofs_root.as_bytes());
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    assert!(
        store.read_minimal_full_block_height().unwrap() > 1,
        "sentinel must have advanced past h=1",
    );
    // Sanity: section bytes at h=1 are gone post-eviction.
    assert!(
        store.get_block_section(&section_id).unwrap().is_none(),
        "h=1 section must be evicted from BLOCK_SECTIONS",
    );
    // Tombstone retained: index still resolves the height.
    assert_eq!(
        store.get_section_height(&section_id).unwrap(),
        Some(1),
        "SECTION_HEIGHT_INDEX tombstone retained for post-eviction guard",
    );

    // Resurrection attempt — must reject without any restamp.
    let err = store
        .store_block_section_typed(&section_id, &[0xBB; 8], TYPE_AD_PROOFS)
        .expect_err("resurrection write at sub-sentinel must reject via tombstone");
    assert!(
        format!("{err:?}").contains("PrunedSection"),
        "expected PrunedSection, got {err:?}",
    );
}

#[test]
fn phase3a_accepts_section_at_or_above_sentinel() {
    // Section writes at the sentinel boundary and above must
    // succeed — that's the live retention window.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 6);

    // h=6 is at the sentinel — writes accepted.
    let h6 = synth_header(6);
    let (h6_id, _) = header_id_and_bytes(&h6);
    let section_id = compute_section_id(TYPE_AD_PROOFS, &h6_id, h6.ad_proofs_root.as_bytes());
    store
        .store_block_section_typed(&section_id, &[0xCC; 8], TYPE_AD_PROOFS)
        .expect("at-sentinel section write must succeed");
}

#[test]
fn phase3a_rejects_unindexed_section_when_sentinel_active() {
    // Storage-side gate fails CLOSED on unindexed sections when
    // sentinel > 1. The boot backfill
    // gate makes SECTION_HEIGHT_INDEX complete in that state, so
    // an unindexed section ID is either an orphan or an attacker
    // direct-write attempt — either way, reject. The receive +
    // serve gates have the matching contract.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    assert!(
        store.read_minimal_full_block_height().unwrap() > 1,
        "sentinel must be active for this test",
    );

    let unknown_section_id = [0x99; 32];
    let err = store
        .store_block_section_typed(&unknown_section_id, &[0xDD; 8], TYPE_AD_PROOFS)
        .expect_err("unindexed section in sentinel-active store must reject");
    assert!(
        format!("{err:?}").contains("PrunedSection"),
        "expected PrunedSection, got {err:?}",
    );
}

// ----- Phase 4 — rollback below sentinel -----

#[test]
fn phase4_rollback_below_sentinel_rejects_before_mutation() {
    // Force the prune sentinel forward, then attempt a rollback
    // to a height below it. The rollback must reject with
    // RollbackBelowPruningSentinel BEFORE any chain-state /
    // wallet mutation. We verify the pre-call chain_state is
    // observably identical post-call.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    let sentinel = store.read_minimal_full_block_height().unwrap();
    assert!(sentinel > 1);
    let pre_height = store.chain_state().best_full_block_height;
    let pre_header_id = store.chain_state().best_header_id;

    let err = store
        .rollback_to(1, None, None)
        .expect_err("rollback to h=1 below sentinel must reject");
    assert!(
        format!("{err:?}").contains("RollbackBelowPruningSentinel"),
        "expected RollbackBelowPruningSentinel, got {err:?}",
    );

    // Chain state and header_id MUST be observably unchanged —
    // the guard fires before flush + before any read of undo
    // entries, so no mutation could land.
    assert_eq!(
        store.chain_state().best_full_block_height,
        pre_height,
        "rejected rollback must not advance chain_state",
    );
    assert_eq!(store.chain_state().best_header_id, pre_header_id);
}

#[test]
fn phase4_rollback_at_and_below_sentinel_by_one_succeeds() {
    // Wallet replay walks `target_height + 1 ..= from_height`.
    // The lowest replayed block sits at `target_height + 1`, so
    // sections at that height MUST be present. The guard
    // therefore allows `target_height = sentinel - 1`
    // (lowest replayed block = sentinel, still retained) AND
    // `target_height = sentinel` — both are above-boundary
    // rollbacks whose replay set lies entirely inside the
    // retention window.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    let sentinel = store.read_minimal_full_block_height().unwrap();
    // Below-by-one must not trip the Phase 4 guard.
    if let Err(e) = store.rollback_to(sentinel - 1, None, None) {
        assert!(
            !format!("{e:?}").contains("RollbackBelowPruningSentinel"),
            "rollback to sentinel - 1 must not trip the Phase 4 guard, got {e:?}",
        );
    }
    // At-boundary likewise.
    if let Err(e) = store.rollback_to(sentinel, None, None) {
        assert!(
            !format!("{e:?}").contains("RollbackBelowPruningSentinel"),
            "rollback to sentinel must not trip the Phase 4 guard, got {e:?}",
        );
    }
}

#[test]
fn phase4_rollback_to_sentinel_succeeds_and_forward_apply_re_advances() {
    // Positive boundary proof: rollback to `target_height = sentinel`
    // (an above-window-boundary target) succeeds, chain_state
    // lands at `target_height`, and a fresh forward-apply at
    // `target_height + 1` re-advances cleanly through the normal
    // path. This is the path the network drives when a reorg
    // converges at the lowest-retained block. Together with the
    // negative tests above, it proves the rollback boundary is
    // truthful in both directions.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    let sentinel = store.read_minimal_full_block_height().unwrap();
    assert!(sentinel > 1, "test setup must produce sentinel > 1");
    let pre_tip = store.chain_state().best_full_block_height;
    assert_eq!(pre_tip, 10);

    // Rollback to sentinel — the lowest legal target whose
    // wallet-replay set starts strictly above the retained
    // window. Must complete cleanly (no
    // `RollbackBelowPruningSentinel`, no `NoCommittedState`).
    store
        .rollback_to(sentinel, None, None)
        .expect("rollback to sentinel must succeed");
    assert_eq!(
        store.chain_state().best_full_block_height,
        sentinel,
        "chain_state.best_full_block_height must land at the target",
    );

    // Forward re-apply must work — the prior eviction cleared
    // BLOCK_SECTIONS but retained SECTION_HEIGHT_INDEX tombstones,
    // so a fresh forward apply at `sentinel + 1` carries its own
    // section bytes and the storage-side resurrection guard
    // recognises the height (above sentinel = accept).
    apply_empty_block(&mut store, sentinel + 1);
    assert_eq!(
        store.chain_state().best_full_block_height,
        sentinel + 1,
        "forward re-apply post-rollback must advance chain_state",
    );
}

#[test]
fn archive_toggle_after_natural_pruning_preserves_sentinel_and_blocks_resurrection() {
    // Drive a real Mode 3 prune (sentinel advances naturally,
    // sub-sentinel sections are evicted), then toggle the
    // config to archive (`blocks_to_keep = -1`) and continue
    // applying. The sentinel MUST stay where the prune left it,
    // AND a sub-sentinel section write attempt MUST still be
    // refused. This proves the post-prune-then-toggle-to-archive
    // path is monotonic — the formula's archive arm never
    // resets a sentinel that was advanced by a prior prune.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    let advanced = store.read_minimal_full_block_height().unwrap();
    assert!(
        advanced > 1,
        "pruned apply must advance sentinel for the test premise",
    );
    // Operator toggles to archive after the prune.
    store.set_blocks_to_keep(-1);
    assert_eq!(store.read_minimal_full_block_height().unwrap(), advanced);

    // Forward apply under archive config must not move the
    // sentinel.
    for h in 11..=12 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        advanced,
        "archive apply on a previously-pruned store must keep the sentinel",
    );

    // Sub-sentinel section write must still be refused.
    let sub = synth_header(advanced - 1);
    let (id, bytes) = header_id_and_bytes(&sub);
    store.store_header(&id, &bytes).unwrap();
    let section_id = compute_section_id(TYPE_AD_PROOFS, &id, sub.ad_proofs_root.as_bytes());
    let err = store
        .store_block_section_typed(&section_id, &[0xAA; 8], TYPE_AD_PROOFS)
        .expect_err("sub-sentinel write must be refused even under archive toggle");
    assert!(
        format!("{err:?}").contains("PrunedSection"),
        "expected PrunedSection, got {err:?}",
    );

    // Rollback to `< sentinel - 1` must still trip the Phase 4
    // guard (wallet replay window starts at `target + 1`, so
    // `sentinel - 1` is the lowest legal target — see
    // `phase4_rollback_at_and_below_sentinel_by_one_succeeds`).
    assert!(advanced >= 2, "test premise: sentinel must be >= 2");
    let err = store
        .rollback_to(advanced.saturating_sub(2), None, None)
        .expect_err("rollback below the legal boundary must be refused");
    assert!(
        format!("{err:?}").contains("RollbackBelowPruningSentinel"),
        "expected RollbackBelowPruningSentinel, got {err:?}",
    );
}

#[test]
fn phase4_rollback_below_sentinel_pre_call_state_observable() {
    // Prove the rejected rollback's pre-call state is observably
    // identical to its post-call state across the full
    // chain_state surface (best_full_block_height,
    // best_full_block_id, best_header_id, best_header_height).
    // The Phase 4 guard fires before flush, before undo-entry
    // reads, before any mutation — no field should drift.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    let sentinel = store.read_minimal_full_block_height().unwrap();
    assert!(sentinel > 1);

    let pre_full_height = store.chain_state().best_full_block_height;
    let pre_full_id = store.chain_state().best_full_block_id;
    let pre_header_id = store.chain_state().best_header_id;
    let pre_header_height = store.chain_state().best_header_height;

    let _ = store.rollback_to(1, None, None).expect_err("must reject");

    let post = store.chain_state();
    assert_eq!(pre_full_height, post.best_full_block_height);
    assert_eq!(pre_full_id, post.best_full_block_id);
    assert_eq!(pre_header_id, post.best_header_id);
    assert_eq!(pre_header_height, post.best_header_height);
}

#[test]
fn phase4_rollback_below_bootstrap_sentinel_rejects_even_in_archive_mode() {
    // The rollback guard must fire whenever the sentinel is > 1,
    // not only when `blocks_to_keep > 0`. The sentinel is also
    // written by `install_snapshot_state`
    // (Mode 2 — `snapshot_height + 1`) and `apply_popow_proof`
    // (Mode 4 — `dense_from_height`) regardless of the
    // pruning config. A Mode-2-bootstrapped archive node has no
    // section bytes below snapshot_height; rolling back into
    // that range cannot reconstruct from undo entries because
    // the wallet replay needs BlockTransactions that don't
    // exist locally.
    //
    // Setup: archive mode (blocks_to_keep = -1), but write the
    // sentinel directly to simulate a post-bootstrap state.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(-1);
    // Inject best_full_block_height = 105 via the test-only seam
    // to simulate post-bootstrap chain_state without driving a
    // synthetic apply chain (which would need contiguous
    // HEADER_META rows from genesis).
    store.set_best_full_block_for_test([0xAB; 32], 105).unwrap();
    // Write the sentinel to 100, mimicking
    // `install_snapshot_state`'s co-commit at the snapshot anchor.
    store.write_minimal_full_block_height(100).unwrap();
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 100);
    assert_eq!(store.chain_state().best_full_block_height, 105);

    // Rollback target h=50 is BELOW the bootstrap-seeded sentinel
    // (100). Must reject even though blocks_to_keep = -1.
    let err = store
        .rollback_to(50, None, None)
        .expect_err("below-sentinel rollback must reject in Mode 2 archive too");
    assert!(
        format!("{err:?}").contains("RollbackBelowPruningSentinel"),
        "expected RollbackBelowPruningSentinel, got {err:?}",
    );
}

#[test]
fn phase4_archive_does_not_gate_rollback() {
    // Archive (`blocks_to_keep = -1`): no sentinel maintained,
    // rollback to any height must not trip the new guard.
    let (mut store, _dir) = open_store();
    // Default is -1 (archive); set explicitly for clarity.
    store.set_blocks_to_keep(-1);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    // Rollback to h=1 — archive must not see the Phase 4 error.
    let result = store.rollback_to(1, None, None);
    if let Err(e) = result {
        assert!(
            !format!("{e:?}").contains("RollbackBelowPruningSentinel"),
            "archive rollback must not trip the Phase 4 guard, but got {e:?}",
        );
    }
}

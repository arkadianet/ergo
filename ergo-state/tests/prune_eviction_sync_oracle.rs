//! Mode 3 Phase 2a — block-section eviction at the synchronous
//! apply seam.
//!
//! Drives `apply_block_unchecked_for_test` repeatedly with empty
//! transactions (no UTXO mutation, so the AVL+ root stays at the
//! genesis-empty digest) and asserts:
//!   * sentinel advances per the Scala
//!     `FullBlockPruningProcessor.updateBestFullBlock` formula,
//!     including the voting-epoch snap.
//!   * `BLOCK_SECTIONS` + `SECTION_HEIGHT_INDEX` rows at
//!     sub-sentinel heights are gone after the eviction commit.
//!   * Orphan headers at a pruned height also have their section
//!     ids dropped — eviction walks every header_id at the
//!     height, not just the best-chain one.
//!   * Archive (`blocks_to_keep = -1`) is a no-op: sections stay,
//!     sentinel stays absent.
//!
//! Built without any mainnet fixture — empty-transactions apply
//! keeps the digest at the initial empty-tree value, so we can
//! generate as many synthetic heights as the test needs.
//!
//! The pure formula function lives at
//! `ergo_state::store::apply::compute_minimal_full_block_height`
//! and gets its own dedicated coverage in this file's
//! `compute_helper_*` block.

#![cfg(feature = "test-helpers")]

use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::Header;
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::store::{compute_minimal_full_block_height, StateStore};
use tempfile::TempDir;

// ----- helpers -----

fn open_store() -> (StateStore, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).expect("open store");
    // apply_block requires `initialize_genesis` to have committed
    // first. Eviction tests don't care about real UTXO state — an
    // empty genesis (zero boxes) lets every subsequent
    // `apply_block_unchecked_for_test(..., transactions=[])` reuse
    // the empty-tree digest verbatim.
    store
        .initialize_genesis(&[])
        .expect("initialize_genesis with empty box set");
    (store, dir)
}

/// Synthesize a header at the given height. We don't care about
/// the consensus-validity of the header bytes — eviction only
/// needs to be able to derive the three section ids from
/// `(ad_proofs_root, transactions_root, extension_root)`, all of
/// which we set to height-derived placeholders so they're unique
/// per height and per orphan slot.
fn synth_header(height: u32, salt: u8) -> Header {
    use ergo_primitives::digest::{ADDigest as AD, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    let mut ad_root = [0u8; 32];
    ad_root[..4].copy_from_slice(&height.to_be_bytes());
    ad_root[4] = 0xAD;
    ad_root[5] = salt;
    let mut tx_root = [0u8; 32];
    tx_root[..4].copy_from_slice(&height.to_be_bytes());
    tx_root[4] = 0x77;
    tx_root[5] = salt;
    let mut ext_root = [0u8; 32];
    ext_root[..4].copy_from_slice(&height.to_be_bytes());
    ext_root[4] = 0xEE;
    ext_root[5] = salt;
    let mut state_root_bytes = [0u8; 33];
    state_root_bytes[32] = 0;
    Header {
        // Version 2 matches Autolykos V2; version 1 expected V1.
        version: 2,
        parent_id: ModifierId::from_bytes([0u8; 32]),
        ad_proofs_root: Digest32::from_bytes(ad_root),
        state_root: AD::from_bytes(state_root_bytes),
        transactions_root: Digest32::from_bytes(tx_root),
        timestamp: 1_700_000_000 + height as u64,
        n_bits: 0x1d00ffff,
        height,
        extension_root: Digest32::from_bytes(ext_root),
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

/// Write header + section ids for a height. `orphan_count` extra
/// header slots at the same height let us exercise the
/// "walk every header_id at the height" eviction semantics.
fn stamp_height(store: &StateStore, height: u32, orphan_count: u8) {
    for salt in 0..=orphan_count {
        let h = synth_header(height, salt);
        let (id, bytes) = header_id_and_bytes(&h);
        store.store_header(&id, &bytes).expect("store_header");
        // Eviction reads HEADERS_BY_HEIGHT to walk every
        // header_id at a pruned height. Production populates this
        // via block_proc; tests seed it explicitly.
        store
            .promote_header_to_height_index_for_test(height, &id)
            .expect("promote_header_to_height_index_for_test");
        // Write the three section bytes so eviction has something
        // tangible to delete. Section ids are derived the same way
        // store_header derived the SECTION_HEIGHT_INDEX rows.
        for (type_byte, root) in [
            (TYPE_AD_PROOFS, h.ad_proofs_root.as_bytes()),
            (TYPE_BLOCK_TRANSACTIONS, h.transactions_root.as_bytes()),
            (TYPE_EXTENSION, h.extension_root.as_bytes()),
        ] {
            let section_id = compute_section_id(type_byte, &id, root);
            store
                .store_block_section_typed(&section_id, &[0xAA; 8], type_byte)
                .expect("store_block_section_typed");
        }
    }
}

/// Drive apply through the persist seam at `height`. Empty
/// transactions keep the AVL+ root at its previous value, so the
/// expected_state_root we pass is whatever `root_digest()` reads
/// before the call.
fn apply_empty_block(store: &mut StateStore, height: u32) {
    let canonical = synth_header(height, 0);
    let (id, _) = header_id_and_bytes(&canonical);
    let expected = store.root_digest();
    store
        .apply_block_unchecked_for_test(height, &id, &expected, &[])
        .unwrap_or_else(|e| panic!("apply at height {height}: {e:?}"));
}

fn section_present(
    store: &StateStore,
    header: &Header,
    header_id: &[u8; 32],
    type_byte: u8,
) -> bool {
    let root = match type_byte {
        TYPE_AD_PROOFS => header.ad_proofs_root.as_bytes(),
        TYPE_BLOCK_TRANSACTIONS => header.transactions_root.as_bytes(),
        TYPE_EXTENSION => header.extension_root.as_bytes(),
        _ => unreachable!(),
    };
    let section_id = compute_section_id(type_byte, header_id, root);
    store.get_block_section(&section_id).unwrap().is_some()
}

fn sentinel(store: &StateStore) -> u32 {
    store.read_minimal_full_block_height().unwrap()
}

// ----- compute helper unit coverage -----
//
// Pure function — exercised here rather than in a separate file
// so the formula's contract sits next to its primary consumer.

#[test]
fn compute_helper_archive_never_advances_sentinel() {
    // blocks_to_keep = -1 (archive) → returns current_min.
    assert_eq!(compute_minimal_full_block_height(1, 100, -1, 1024), 1);
    assert_eq!(
        compute_minimal_full_block_height(50, 1_000_000, -1, 1024),
        50
    );
}

#[test]
fn compute_helper_mode6_never_advances_sentinel() {
    // blocks_to_keep = 0 (canonical Mode 6) → returns current_min.
    assert_eq!(compute_minimal_full_block_height(1, 100, 0, 1024), 1);
}

#[test]
fn compute_helper_suffix_window_no_snap_below_voting_epoch() {
    // header_height = 10, blocks_to_keep = 5 → candidate = max(1, 10-5+1) = 6.
    // voting_length = 1024, candidate (6) <= voting_length → no snap.
    assert_eq!(compute_minimal_full_block_height(1, 10, 5, 1024), 6);
}

#[test]
fn compute_helper_voting_epoch_snap_above_first_epoch() {
    // header_height = 2000, blocks_to_keep = 500 → candidate = max(1, 2000-500+1) = 1501.
    // voting_length = 1024, candidate (1501) > voting_length → snap to floor(1501/1024)*1024 = 1024.
    assert_eq!(compute_minimal_full_block_height(1, 2000, 500, 1024), 1024);
}

#[test]
fn compute_helper_monotonic_floor() {
    // current_min already at 2048, formula's candidate would compute lower → keep current.
    // header_height = 2100, blocks_to_keep = 500 → candidate = max(2048, 2100-500+1=1601) = 2048.
    // Snap: 2048 % 1024 = 0, so snapped = 2048 (same). Result = 2048.
    assert_eq!(
        compute_minimal_full_block_height(2048, 2100, 500, 1024),
        2048
    );
}

#[test]
fn compute_helper_saturating_sub_on_small_heights() {
    // header_height = 10, blocks_to_keep = 100 (window larger than chain).
    // Scala: max(1, 10-100+1=-89) → saturating to 0 → max(1, 0) = 1. Returns current_min unchanged.
    assert_eq!(compute_minimal_full_block_height(1, 10, 100, 1024), 1);
}

// ----- end-to-end eviction via the sync apply seam -----

#[test]
fn archive_default_does_not_evict() {
    let (mut store, _dir) = open_store();
    // No set_blocks_to_keep → defaults to -1 (archive).
    assert_eq!(store.blocks_to_keep(), -1);

    for h in 1..=10 {
        stamp_height(&store, h, 0);
        apply_empty_block(&mut store, h);
    }

    // Archive: sentinel row absent (read returns the GenesisHeight
    // default of 1), and every section we stamped is still there.
    assert_eq!(
        store.try_read_minimal_full_block_height_raw().unwrap(),
        None,
        "archive must not stamp the sentinel row",
    );
    let h1 = synth_header(1, 0);
    let (h1_id, _) = header_id_and_bytes(&h1);
    assert!(section_present(&store, &h1, &h1_id, TYPE_AD_PROOFS));
    assert!(section_present(
        &store,
        &h1,
        &h1_id,
        TYPE_BLOCK_TRANSACTIONS
    ));
    assert!(section_present(&store, &h1, &h1_id, TYPE_EXTENSION));
}

#[test]
fn suffix_window_advances_sentinel_and_evicts_sub_sentinel_sections() {
    let (mut store, _dir) = open_store();
    let blocks_to_keep = 5i32;
    store.set_blocks_to_keep(blocks_to_keep);

    for h in 1..=10 {
        stamp_height(&store, h, 0);
        apply_empty_block(&mut store, h);
    }

    // After applying block 10 with blocks_to_keep=5:
    //   candidate = max(1, 10 - 5 + 1) = 6. voting_length=1024 > 6,
    //   so no snap. sentinel = 6.
    assert_eq!(
        sentinel(&store),
        6,
        "sentinel = max(1, header_height - blocks_to_keep + 1)"
    );

    // Heights 1..6 (exclusive 6) are below the new sentinel → evicted.
    for h in 1..6 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        assert!(
            !section_present(&store, &hdr, &id, TYPE_AD_PROOFS),
            "ad_proofs at height {h} must be evicted",
        );
        assert!(
            !section_present(&store, &hdr, &id, TYPE_BLOCK_TRANSACTIONS),
            "block_txs at height {h} must be evicted",
        );
        assert!(
            !section_present(&store, &hdr, &id, TYPE_EXTENSION),
            "extension at height {h} must be evicted",
        );
    }
    // Heights >= 6 are inside the retention window → kept.
    for h in 6..=10 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        assert!(
            section_present(&store, &hdr, &id, TYPE_AD_PROOFS),
            "ad_proofs at height {h} must be kept",
        );
    }
}

#[test]
fn eviction_walks_orphan_headers_at_pruned_heights() {
    // Scala parity: `pruneBlockDataAt` flat-maps over EVERY header
    // at the height, not just the best-chain one. An orphan at a
    // pruned height must have its section ids dropped, otherwise
    // a peer's `Inv` for the orphan section would still resolve.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);

    for h in 1..=10 {
        // Two orphan headers at each height (salt 1 + salt 2)
        // alongside the canonical (salt 0). Eviction must reach
        // all three.
        stamp_height(&store, h, 2);
        apply_empty_block(&mut store, h);
    }
    assert_eq!(sentinel(&store), 6);

    for h in 1..6 {
        for salt in 0..=2u8 {
            let hdr = synth_header(h, salt);
            let (id, _) = header_id_and_bytes(&hdr);
            assert!(
                !section_present(&store, &hdr, &id, TYPE_AD_PROOFS),
                "orphan-salt-{salt} ad_proofs at height {h} must be evicted",
            );
            assert!(
                !section_present(&store, &hdr, &id, TYPE_BLOCK_TRANSACTIONS),
                "orphan-salt-{salt} block_txs at height {h} must be evicted",
            );
            assert!(
                !section_present(&store, &hdr, &id, TYPE_EXTENSION),
                "orphan-salt-{salt} extension at height {h} must be evicted",
            );
        }
    }
}

#[test]
fn archive_to_pruned_transition_preserves_historical_prefix() {
    // Plan §366 + §812 + Scala parity contract: when an archive
    // store transitions to pruned (`blocks_to_keep > 0`), the
    // first apply MUST only evict the new pruning frontier — NOT
    // retroactively wipe the archive prefix. The Scala formula's
    // `[lastKept - diff, lastKept)` range with `diff = 1` for
    // steady-state apply means a single height per block,
    // bounded by what the batch advanced the tip by.
    //
    // Fixture: simulate an archive at heights 1..=15 (no
    // pruning), then enable pruning with `blocks_to_keep = 5`
    // and apply h=16. The archive prefix [1, 10] must STAY;
    // only height 11 (the new frontier per Scala formula) is
    // evicted.
    let (mut store, _dir) = open_store();
    // Archive phase: blocks_to_keep stays at -1.
    for h in 1..=15 {
        stamp_height(&store, h, 0);
        apply_empty_block(&mut store, h);
    }
    // No eviction happened in archive phase.
    for h in 1..=15 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        assert!(
            section_present(&store, &hdr, &id, TYPE_AD_PROOFS),
            "archive: ad_proofs at height {h} must still be present",
        );
    }
    assert_eq!(
        store.try_read_minimal_full_block_height_raw().unwrap(),
        None,
        "archive: sentinel row stays absent",
    );

    // Flip to pruned and apply ONE more block.
    store.set_blocks_to_keep(5);
    stamp_height(&store, 16, 0);
    apply_empty_block(&mut store, 16);

    // Scala formula: new_min = max(1, 16 - 5 + 1) = 12.
    // diff = 16 - 15 = 1. Range = [max(1, 12-1), 12) = [11, 12).
    // ONLY height 11 evicted. Archive prefix [1, 10] preserved.
    assert_eq!(sentinel(&store), 12);
    for h in 1..=10 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        assert!(
            section_present(&store, &hdr, &id, TYPE_AD_PROOFS),
            "archive→pruned transition must NOT wipe the historical \
             prefix; ad_proofs at height {h} must stay",
        );
    }
    // Height 11 is the newly-pruned frontier.
    let h11 = synth_header(11, 0);
    let (h11_id, _) = header_id_and_bytes(&h11);
    assert!(
        !section_present(&store, &h11, &h11_id, TYPE_AD_PROOFS),
        "new pruning frontier at height 11 must be evicted",
    );
    // Heights 12..=16 are inside the keep window.
    for h in 12..=16 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        assert!(
            section_present(&store, &hdr, &id, TYPE_AD_PROOFS),
            "keep window: ad_proofs at height {h} must stay",
        );
    }
}

#[test]
fn eviction_crossing_voting_epoch_boundary_snaps_sentinel() {
    // Scala-parity contract: the prune range is `[new_min - diff,
    // new_min)` with `diff = 1` per steady-state apply. When the
    // sentinel JUMPS across an epoch boundary (via the
    // voting-epoch snap), only ONE height is evicted per apply —
    // older sub-sentinel section bytes stay on disk but are
    // serve-gated (the gate rejects on `height < sentinel`).
    // This matches Scala's
    // `pruneBlockDataAt(((lastKept - diff) until lastKept))`
    // verbatim: storage cleanup of the snap-skipped range is a
    // separate concern, not part of the per-block eviction.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.redb");
    let launch = ergo_validation::scala_launch_for_network(ergo_chain_spec::Network::Mainnet);
    let voting = ergo_chain_spec::VotingParams {
        voting_length: 4,
        ..ergo_chain_spec::VotingParams::mainnet()
    };
    let mut store = StateStore::open_with_cache_launch_voting(
        &path,
        StateStore::DEFAULT_CACHE_BYTES,
        launch,
        voting,
    )
    .unwrap();
    store.initialize_genesis(&[]).unwrap();
    store.set_blocks_to_keep(2);

    for h in 1..=10 {
        stamp_height(&store, h, 0);
        apply_empty_block(&mut store, h);
    }

    // Trace with voting_length=4, blocks_to_keep=2 (no-snap below 4):
    //   h=3: candidate=2, no snap, new_min=2. Evict [1, 2)  → 1.
    //   h=4: candidate=3, no snap, new_min=3. Evict [2, 3)  → 2.
    //   h=5: candidate=4, no snap (4 == voting_length, not >),
    //        new_min=4. Evict [3, 4) → 3.
    //   h=6..8: candidate=5..7, all snap to 4. Sentinel stays 4.
    //   h=9: candidate=8, snap to 8. new_min=8. Evict [7, 8) → 7.
    //   h=10: candidate=9, snap to 8. No eviction.
    // Final sentinel = 8. Physically evicted: {1, 2, 3, 7}.
    // Heights {4, 5, 6} stay on disk (below sentinel but
    // snap-skipped) — serve gate denies them; bytes remain.
    assert_eq!(sentinel(&store), 8);
    let physically_evicted_below_sentinel: Vec<u32> = (1..8u32)
        .filter(|h| {
            let hdr = synth_header(*h, 0);
            let (id, _) = header_id_and_bytes(&hdr);
            !section_present(&store, &hdr, &id, TYPE_AD_PROOFS)
        })
        .collect();
    assert_eq!(
        physically_evicted_below_sentinel,
        vec![1, 2, 3, 7],
        "Scala-parity per-block eviction range: only the moving \
         frontier height per apply gets physically evicted; snap \
         jumps leave older sub-sentinel data on disk (serve-gated, \
         not advertised)",
    );
}

#[test]
fn corrupted_index_inconsistency_fails_loud() {
    // Defense-in-depth: HEADERS_BY_HEIGHT and HEADERS are jointly
    // maintained. If a header_id is indexed in HEADERS_BY_HEIGHT
    // but the matching HEADERS row is missing, eviction can't
    // derive the section ids to delete — advancing the sentinel
    // anyway would let the serve gate lie about availability.
    // The eviction txn must fail loud and abort the apply.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);

    // Stamp HEADERS_BY_HEIGHT for height 1 with a header_id whose
    // HEADERS row was never written. Then drive an apply at
    // height 6 to trigger eviction at height 1 → must fail with
    // DbCorruption.
    let bogus_id = [0x99; 32];
    store
        .promote_header_to_height_index_for_test(1, &bogus_id)
        .unwrap();
    // Apply h=1..5 doesn't trigger eviction (current_min = new_min).
    for h in 1..=5 {
        stamp_height(&store, h, 0);
        apply_empty_block(&mut store, h);
    }
    // Now stamp HEADERS_BY_HEIGHT for h=1 with bogus_id AGAIN
    // (gets shifted into slot 1; canonical from stamp_height stays
    // in slot 0). Both ids will be visited by eviction; the bogus
    // one fails the HEADERS lookup.
    store
        .promote_header_to_height_index_for_test(1, &bogus_id)
        .unwrap();
    // The h=6 stamp + apply will try to evict h=1, hitting the bogus row.
    stamp_height(&store, 6, 0);
    let err = {
        let canonical = synth_header(6, 0);
        let (id, _) = header_id_and_bytes(&canonical);
        let expected = store.root_digest();
        store
            .apply_block_unchecked_for_test(6, &id, &expected, &[])
            .expect_err("eviction must fail loud on missing HEADERS row")
    };
    assert!(
        format!("{err:?}").contains("DbCorruption"),
        "expected DbCorruption, got {err:?}",
    );
}

#[test]
fn eviction_persists_across_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.redb");
    {
        let mut store = StateStore::open(&path).unwrap();
        store.initialize_genesis(&[]).unwrap();
        store.set_blocks_to_keep(5);
        for h in 1..=10 {
            stamp_height(&store, h, 0);
            apply_empty_block(&mut store, h);
        }
        assert_eq!(sentinel(&store), 6);
    }
    // Reopen — sentinel + deletions are durable.
    let store = StateStore::open(&path).unwrap();
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        6,
        "sentinel co-committed with apply must survive reopen",
    );
    // Spot-check one evicted height.
    let h1 = synth_header(1, 0);
    let (h1_id, _) = header_id_and_bytes(&h1);
    assert!(!section_present(&store, &h1, &h1_id, TYPE_AD_PROOFS));
}

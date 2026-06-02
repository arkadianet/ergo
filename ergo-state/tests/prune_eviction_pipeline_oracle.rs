//! Mode 3 Phase 2b — block-section eviction at the pipeline-batch
//! seam.
//!
//! Mirror of `prune_eviction_sync_oracle.rs` but drives applies
//! through the background `execute_batch` path
//! (`enable_persist_pipeline`). Phases 2a + 2b ship together per
//! the governing plan §768: leaving only the sync seam wired
//! would let IBD batches advance the chain without pruning,
//! causing deleted heights to accumulate. This test pins the
//! pipeline seam's eviction by matching the synchronous-path
//! oracle's terminal state byte-for-byte (same sentinel value +
//! same section table contents after the same input sequence).

#![cfg(feature = "test-helpers")]

use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::Header;
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::store::StateStore;
use tempfile::TempDir;

fn open_pipelined_store(blocks_to_keep: i32) -> (StateStore, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).expect("open store");
    store.initialize_genesis(&[]).expect("init genesis");
    // Set BEFORE enabling the pipeline — the pipeline worker
    // captures `blocks_to_keep` at spawn time.
    store.set_blocks_to_keep(blocks_to_keep);
    store.enable_persist_pipeline(8);
    (store, dir)
}

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

fn stamp_height(store: &StateStore, height: u32) {
    let h = synth_header(height, 0);
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
            .expect("store_block_section_typed");
    }
}

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

#[test]
fn pipeline_seam_evicts_sub_sentinel_sections_all_three_types() {
    // Prove the pipeline seam evicts ALL three section types
    // (ADProofs, BlockTransactions, Extension), not just
    // ADProofs. Required for byte-for-byte parity with the sync
    // oracle.
    let (mut store, _dir) = open_pipelined_store(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    store.flush_persist_pipeline().expect("flush pipeline");

    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        6,
        "pipeline seam must advance sentinel per Scala formula",
    );
    // Heights 1..6 evicted — assert ALL three section types.
    for h in 1..6 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        for type_byte in [TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION] {
            assert!(
                !section_present(&store, &hdr, &id, type_byte),
                "pipeline-path type={type_byte:#x} at height {h} must be evicted",
            );
        }
    }
    // Heights 6..=10 kept — assert ALL three section types.
    for h in 6..=10 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        for type_byte in [TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION] {
            assert!(
                section_present(&store, &hdr, &id, type_byte),
                "pipeline-path type={type_byte:#x} at height {h} must be kept",
            );
        }
    }
}

#[test]
fn pipeline_seam_archive_is_no_op() {
    // Mirror of `archive_default_does_not_evict` from the sync
    // oracle, but through the pipeline path. Archive must NOT
    // touch the sentinel row.
    let (mut store, _dir) = open_pipelined_store(-1);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    store.flush_persist_pipeline().expect("flush pipeline");
    assert_eq!(
        store.try_read_minimal_full_block_height_raw().unwrap(),
        None,
        "archive must not stamp the sentinel row even through the pipeline",
    );
    let h1 = synth_header(1, 0);
    let (h1_id, _) = header_id_and_bytes(&h1);
    assert!(section_present(&store, &h1, &h1_id, TYPE_AD_PROOFS));
}

#[test]
fn pipeline_seam_matches_sync_seam_terminal_state() {
    // Byte-for-byte parity with the synchronous oracle: same
    // input sequence → same sentinel + same section table
    // contents at the end, regardless of which seam ran the
    // eviction. Pins the contract the plan §768 names.
    let (mut store, _dir) = open_pipelined_store(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    store.flush_persist_pipeline().expect("flush pipeline");

    let sentinel = store.read_minimal_full_block_height().unwrap();
    let mut kept_heights = Vec::new();
    let mut evicted_heights = Vec::new();
    for h in 1..=10 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        if section_present(&store, &hdr, &id, TYPE_AD_PROOFS) {
            kept_heights.push(h);
        } else {
            evicted_heights.push(h);
        }
    }
    assert_eq!(sentinel, 6);
    assert_eq!(kept_heights, vec![6, 7, 8, 9, 10]);
    assert_eq!(evicted_heights, vec![1, 2, 3, 4, 5]);

    // Additionally check BlockTransactions + Extension parity
    // for the same heights (the kept/evicted split must be
    // identical across all three section types).
    for h in 1..6 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        assert!(!section_present(&store, &hdr, &id, TYPE_BLOCK_TRANSACTIONS));
        assert!(!section_present(&store, &hdr, &id, TYPE_EXTENSION));
    }
    for h in 6..=10 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        assert!(section_present(&store, &hdr, &id, TYPE_BLOCK_TRANSACTIONS));
        assert!(section_present(&store, &hdr, &id, TYPE_EXTENSION));
    }
}

#[test]
fn pipeline_archive_to_pruned_transition_preserves_historical_prefix() {
    // Pipeline-path version of the sync oracle's
    // `archive_to_pruned_transition_preserves_historical_prefix`.
    // Verifies the batch seam computes
    // `diff = last.height - first.old_best_full_block_height`
    // correctly across the archive→pruned flip, so only the new
    // pruning frontier is evicted (archive prefix [1, old_tip -
    // blocks_to_keep] stays).
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.redb");
    {
        let mut store = StateStore::open(&path).expect("open archive");
        store.initialize_genesis(&[]).unwrap();
        store.set_blocks_to_keep(-1);
        store.enable_persist_pipeline(8);
        for h in 1..=15 {
            stamp_height(&store, h);
            apply_empty_block(&mut store, h);
        }
        store.flush_persist_pipeline().expect("flush archive phase");
    }
    // Drop closes the pipeline (via Drop), then reopen with the
    // new `blocks_to_keep`. Mirrors production: Mode 3 activation
    // is a restart, not a hot-flip.
    let mut store = StateStore::open(&path).expect("reopen pruned");
    store.set_blocks_to_keep(5);
    store.enable_persist_pipeline(8);
    stamp_height(&store, 16);
    apply_empty_block(&mut store, 16);
    store
        .flush_persist_pipeline()
        .expect("flush pruned-mode apply");

    // Expected: sentinel = max(1, 16 - 5 + 1) = 12. diff = 16 - 15 = 1.
    // Range [max(1, 12-1), 12) = [11, 12). Only height 11 evicted.
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 12);
    for h in 1..=10 {
        let hdr = synth_header(h, 0);
        let (id, _) = header_id_and_bytes(&hdr);
        assert!(
            section_present(&store, &hdr, &id, TYPE_AD_PROOFS),
            "pipeline-path archive prefix at {h} must stay",
        );
    }
    let h11 = synth_header(11, 0);
    let (h11_id, _) = header_id_and_bytes(&h11);
    assert!(
        !section_present(&store, &h11, &h11_id, TYPE_AD_PROOFS),
        "pipeline-path new pruning frontier at 11 must be evicted",
    );
}

#[test]
fn pipeline_batch_spanning_voting_epoch_snap_matches_sync() {
    // Deterministically force a single persist batch to span a
    // voting-epoch snap and assert the terminal state matches
    // the synchronous-seam outcome. A naive batch-wide range
    // `[new_min - batch_size, new_min)` would over-evict heights
    // that the sync seam keeps on disk (snap-skip semantics);
    // per-job iteration inside `execute_batch` preserves the
    // Scala-parity behavior.
    //
    // Setup: queue a multi-block batch crossing the snap (e.g.
    // 8→9 with voting_length=4), then flush. Compare to a sync
    // store that received the same blocks one at a time.
    let dir_a = tempfile::tempdir().expect("tempdir pipe");
    let path_a = dir_a.path().join("a.redb");
    let dir_b = tempfile::tempdir().expect("tempdir sync");
    let path_b = dir_b.path().join("b.redb");
    let launch = ergo_validation::scala_launch_for_network(ergo_chain_spec::Network::Mainnet);
    let voting = ergo_chain_spec::VotingParams {
        voting_length: 4,
        ..ergo_chain_spec::VotingParams::mainnet()
    };

    // Pipeline-path store.
    let mut pipe = StateStore::open_with_cache_launch_voting(
        &path_a,
        StateStore::DEFAULT_CACHE_BYTES,
        launch.clone(),
        voting,
    )
    .unwrap();
    pipe.initialize_genesis(&[]).unwrap();
    pipe.set_blocks_to_keep(2);
    pipe.enable_persist_pipeline(64); // large queue ⇒ one big batch on flush

    // Sync-path store — pipeline NOT enabled, same config.
    let mut sync_store = StateStore::open_with_cache_launch_voting(
        &path_b,
        StateStore::DEFAULT_CACHE_BYTES,
        launch,
        voting,
    )
    .unwrap();
    sync_store.initialize_genesis(&[]).unwrap();
    sync_store.set_blocks_to_keep(2);

    for h in 1..=10 {
        stamp_height(&pipe, h);
        apply_empty_block(&mut pipe, h);
        stamp_height(&sync_store, h);
        apply_empty_block(&mut sync_store, h);
    }
    pipe.flush_persist_pipeline().expect("flush");

    // Terminal sentinel + physical-eviction set MUST match.
    assert_eq!(
        pipe.read_minimal_full_block_height().unwrap(),
        sync_store.read_minimal_full_block_height().unwrap(),
        "pipeline and sync seams must agree on sentinel",
    );
    let pipe_evicted: Vec<u32> = (1..10u32)
        .filter(|h| {
            let hdr = synth_header(*h, 0);
            let (id, _) = header_id_and_bytes(&hdr);
            !section_present(&pipe, &hdr, &id, TYPE_AD_PROOFS)
        })
        .collect();
    let sync_evicted: Vec<u32> = (1..10u32)
        .filter(|h| {
            let hdr = synth_header(*h, 0);
            let (id, _) = header_id_and_bytes(&hdr);
            !section_present(&sync_store, &hdr, &id, TYPE_AD_PROOFS)
        })
        .collect();
    assert_eq!(
        pipe_evicted, sync_evicted,
        "pipeline and sync seams must evict the same heights across snap",
    );
}

#[test]
fn pipeline_eviction_voting_epoch_snap_matches_sync() {
    // Pipeline parity for `eviction_crossing_voting_epoch_boundary_snaps_sentinel`
    // (see sync oracle). Snap-skip semantics must match across
    // seams — the batch math in `execute_batch` uses the same
    // `compute_minimal_full_block_height` formula and the same
    // `[new_min - diff, new_min)` range, so the terminal state
    // is identical to the sync seam's output for the same input.
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
    store.enable_persist_pipeline(8);

    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    store.flush_persist_pipeline().expect("flush");

    // Same expected terminal state as the sync-seam test:
    //   sentinel = 8, physically evicted = {1, 2, 3, 7}.
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 8);
    let physically_evicted: Vec<u32> = (1..8u32)
        .filter(|h| {
            let hdr = synth_header(*h, 0);
            let (id, _) = header_id_and_bytes(&hdr);
            !section_present(&store, &hdr, &id, TYPE_AD_PROOFS)
        })
        .collect();
    assert_eq!(physically_evicted, vec![1, 2, 3, 7]);
}

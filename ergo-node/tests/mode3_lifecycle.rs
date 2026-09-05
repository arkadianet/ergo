//! Mode 3 (pruned node) activation lifecycle through `run_inner`.
//!
//! Covers the Gate 1 sequence a real from-scratch pruned node walks:
//!
//! 1. the headers-synced flip seeds the prune sentinel at the
//!    Scala-parity value (`FullBlockPruningProcessor.updateBestFullBlock`,
//!    reached from `ToDownloadProcessor.toDownload` — the boot arm here,
//!    where `recover_coordinator` flips the latch off the best header's
//!    freshness),
//! 2. an archive node under the same fixture arms nothing,
//! 3. restart resumes with the sentinel intact and does not re-seed it,
//! 4. a rollback below the sentinel is refused.
//!
//! The fixture is a synthetic 1200-header chain with fresh timestamps
//! seeded directly into the store, which is what lets the flip happen
//! with no peers: `SyncState::check_headers_synced` is a pure function
//! of the best header's timestamp. `blocks_to_keep = 250` is the
//! smallest legal pruned window (`keep_versions + SAFETY_MARGIN`), so
//! the expected sentinel is the Scala oracle vector
//! `flip_h1200_keep250_mainnet` in
//! `test-vectors/mode3-pruning/runtime-vectors.json`.
//!
//! The download-side consequences of the seeded sentinel are pinned
//! next to the code that implements them: the window floor and the
//! sub-sentinel filter in `ergo-p2p/src/sync.rs`'s `blocks_to_download`
//! tests, and the composed request / receive / storage gates against a
//! real coordinator in `ergo-sync/tests/prune_e2e_activation.rs`.
//! Eviction as blocks apply is pinned by
//! `ergo-state/tests/prune_eviction_sync_oracle.rs`; this file's
//! fixture applies no blocks, because a from-scratch pruned node has
//! none at the flip — that is the state under test.

#[allow(dead_code)]
mod common;

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header, Header};
use ergo_state::chain::HeaderMeta;
use ergo_state::store::StateStore;
use ergo_state::ChainStateRead;

// ----- helpers -----

/// Header-chain tip the fixture seeds.
const HEADER_TIP: u32 = 1200;
/// Smallest legal pruned window: the config/runtime floor is
/// `keep_versions (200, = ROLLBACK_WINDOW) + SAFETY_MARGIN (50)`.
const BLOCKS_TO_KEEP: i32 = 250;
/// Scala oracle output for `updateBestFullBlock` at
/// `(current_min = 1, header_height = 1200, blocksToKeep = 250,
/// votingLength = 1024)` — vector `flip_h1200_keep250_mainnet`.
/// `1200 - 250 + 1 = 951`, below `votingLength`, so no epoch snap.
const EXPECTED_SENTINEL: u32 = 951;

fn synth_header(height: u32, parent: [u8; 32], timestamp_ms: u64) -> Header {
    let root = |seed: u8| {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&height.to_be_bytes());
        b[4] = seed;
        b
    };
    Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent),
        ad_proofs_root: Digest32::from_bytes(root(0xAD)),
        state_root: ADDigest::from_bytes([0u8; 33]),
        transactions_root: Digest32::from_bytes(root(0x77)),
        timestamp: timestamp_ms,
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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_millis() as u64
}

/// Seed `data_dir` with a genesis-initialized store carrying a linear
/// synthetic header chain `1..=HEADER_TIP`. The tip's timestamp is
/// `now`, which is what makes `check_headers_synced` flip at boot with
/// no peers connected. No block sections and no full blocks are
/// written — that is exactly the from-scratch pruned node's state at
/// the flip.
fn seed_header_chain(data_dir: &std::path::Path) {
    std::fs::create_dir_all(data_dir).expect("create data dir");
    let mut store = StateStore::open(&data_dir.join("state.redb")).expect("open store");
    store.initialize_genesis(&[]).expect("init genesis");
    let base = now_ms() - u64::from(HEADER_TIP) * 120_000;
    let mut parent = store.chain_state_meta().best_header_id;
    for height in 1..=HEADER_TIP {
        // Tip timestamp lands at `now`; the rest walk backwards at the
        // mainnet block interval so the chain reads as freshly mined.
        let ts = base + u64::from(height) * 120_000;
        let header = synth_header(height, parent, ts);
        let (bytes, id) = serialize_header(&header).expect("serialize header");
        let id = *id.as_bytes();
        let meta = HeaderMeta {
            parent_id: parent,
            height,
            // Strictly increasing so each header is the new best.
            cumulative_score: u64::from(height).to_be_bytes().to_vec(),
            pow_validity: 1,
            timestamp: ts,
        };
        store
            .store_validated_header(
                &id,
                &bytes,
                &meta,
                Some((height, meta.cumulative_score.clone())),
            )
            .unwrap_or_else(|e| panic!("store header h={height}: {e:?}"));
        parent = id;
    }
    let cs = store.chain_state_meta();
    assert_eq!(cs.best_header_height, HEADER_TIP, "fixture header tip");
    assert_eq!(cs.best_full_block_height, 0, "fixture applies no blocks");
    assert_eq!(
        store.try_read_minimal_full_block_height_raw().unwrap(),
        None,
        "fixture must leave the sentinel row absent — that absence is \
         the activation latch under test",
    );
}

fn pruned_config(data_dir: std::path::PathBuf) -> ergo_node::config::NodeConfig {
    let mut cfg = common::make_test_config(data_dir);
    cfg.blocks_to_keep = BLOCKS_TO_KEEP;
    cfg
}

fn read_sentinel(data_dir: &std::path::Path) -> Option<u32> {
    let store = StateStore::open(&data_dir.join("state.redb")).expect("reopen store");
    store
        .try_read_minimal_full_block_height_raw()
        .expect("read sentinel")
}

// ----- happy path -----

#[tokio::test]
async fn mode3_fresh_node_seeds_the_sentinel_at_the_headers_synced_flip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("node");
    seed_header_chain(&data_dir);

    let handle = ergo_node::run_inner(pruned_config(data_dir.clone()))
        .await
        .expect("Mode 3 with blocks_to_keep = 250 is a live runtime path");
    handle.shutdown().await.expect("clean shutdown");

    assert_eq!(
        read_sentinel(&data_dir),
        Some(EXPECTED_SENTINEL),
        "the flip must seed the sentinel at the Scala oracle value; a \
         `None` here means the node would IBD from genesis and only \
         start evicting afterwards (the pre-Gate-1 behaviour)",
    );
}

#[tokio::test]
async fn mode3_archive_node_never_seeds_a_sentinel_at_the_flip() {
    // Same fixture, `blocks_to_keep = -1`. The flip still happens (the
    // header chain is equally fresh) but an archive node keeps every
    // block, so the sentinel row must stay absent. Guards the
    // `blocks_to_keep <= 0` refusal at the activation seam.
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("node");
    seed_header_chain(&data_dir);

    let handle = ergo_node::run_inner(common::make_test_config(data_dir.clone()))
        .await
        .expect("archive boot");
    handle.shutdown().await.expect("clean shutdown");

    assert_eq!(
        read_sentinel(&data_dir),
        None,
        "an archive node must never arm the prune gates",
    );
}

#[tokio::test]
async fn mode3_seeded_sentinel_survives_restart_and_is_not_re_seeded() {
    // The seed is one-shot: a present sentinel row is one of the
    // refusal conditions, so the second boot must observe the same
    // value even though the header tip (and therefore the candidate)
    // has not moved. Without the latch, a growing header chain would
    // walk the download floor forward under a node that has applied
    // nothing.
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("node");
    seed_header_chain(&data_dir);

    let handle = ergo_node::run_inner(pruned_config(data_dir.clone()))
        .await
        .expect("first boot");
    handle.shutdown().await.expect("clean shutdown");
    let after_first = read_sentinel(&data_dir);
    assert_eq!(after_first, Some(EXPECTED_SENTINEL));

    let handle = ergo_node::run_inner(pruned_config(data_dir.clone()))
        .await
        .expect("restart");
    handle.shutdown().await.expect("clean shutdown");

    assert_eq!(
        read_sentinel(&data_dir),
        after_first,
        "restart must resume with the sentinel intact",
    );
}

// ----- error paths -----

#[tokio::test]
async fn mode3_rollback_below_the_seeded_sentinel_is_refused() {
    // The sections below the sentinel are the ones a pruned node will
    // never hold, so a reorg whose wallet replay would need them must
    // be declined rather than half-applied. The guard keys off the
    // persisted sentinel, so seeding it at the flip arms this refusal
    // from the node's first tick — before any block has been applied.
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("node");
    seed_header_chain(&data_dir);

    let handle = ergo_node::run_inner(pruned_config(data_dir.clone()))
        .await
        .expect("boot");
    handle.shutdown().await.expect("clean shutdown");
    assert_eq!(read_sentinel(&data_dir), Some(EXPECTED_SENTINEL));

    let mut store = StateStore::open(&data_dir.join("state.redb")).expect("reopen store");
    // `target_height + 1 < sentinel` is the refusal boundary: replay
    // starts at `target_height + 1`, which must still be retained.
    let err = store
        .rollback_to(EXPECTED_SENTINEL - 2, None, None)
        .expect_err("a sub-sentinel rollback target must be refused");
    assert!(
        matches!(
            err,
            ergo_state::store::StateError::RollbackBelowPruningSentinel { .. }
        ),
        "expected RollbackBelowPruningSentinel, got {err:?}",
    );
}

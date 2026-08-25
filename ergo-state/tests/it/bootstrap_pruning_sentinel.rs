//! Mode 3 Phase 1b — prune-sentinel seeding at the writer side.
//!
//! `install_snapshot_state` and `apply_popow_proof` co-commit the
//! prune low-water mark inside their existing atomic txns:
//!
//!   * `install_snapshot_state` writes `snapshot_height + 1`
//!     (the first not-pre-bootstrap height).
//!   * `apply_popow_proof` writes `dense_from_height` verbatim
//!     (the first dense-coverage height; `+1` would prune it).
//!
//! Writing at the writer captures the bootstrap boundary while
//! the value is unambiguously available. A later read (post-
//! forward-sync) would lie about `snapshot_height` because
//! `best_full_block_height` advances on every apply.
//!
//! Composition contract: when both writers run (Mode 4 with a
//! NiPoPoW prefix), the higher candidate wins. The in-txn
//! helper `advance_minimal_full_block_height_in_txn` is
//! max-style — a backward candidate is a silent no-op rather
//! than an error, so the second writer's atomic apply is not
//! aborted just because the first writer pinned the sentinel
//! higher. The strict monotonic variant lives in
//! `StateStore::write_minimal_full_block_height`, used by
//! tests and any defensive caller that wants a hard error on
//! backward writes.
//!
//! `install_snapshot_state` integration coverage exercises a real
//! `ReconstructedTree` via the public snapshot-codec round-trip
//! (`SnapshotServer::build` → `reconstruct_tree`). Mode 4
//! composition tests run BOTH writers in either order and verify
//! the max-style sentinel + atomicity contracts.

use std::collections::HashMap;
use std::path::Path;

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use ergo_ser::popow_header::PoPowHeader;
use ergo_ser::popow_proof::NipopowProof;
use ergo_state::avl::snapshot_codec::{
    reconstruct_tree, ReconstructedTree, SnapshotServer, MAINNET_MANIFEST_DEPTH,
};
use ergo_state::avl::tree::AvlTree;
use ergo_state::chain::HeaderAvailability;
use ergo_state::store::StateStore;
use tempfile::TempDir;

/// Open a StateStore for Phase 1b integration tests. Mainnet
/// defaults (voting_length=1024) keep the reopen-time voted-params
/// reconcile happy even though our synthetic fixture uses heights
/// 1..=8 (the reconcile walks `voting_length`-multiples from
/// `chain_floor` to `tip`; with vl=1024 and tip≤8, the walk is
/// empty — only the genesis row at height 0 is checked, which
/// `scala_launch_for_network` seeds).
fn open_test_store(path: &Path) -> StateStore {
    StateStore::open(path).expect("test store")
}

const MAINNET_HEADERS_1_10: &[&str] = &[
    "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b",
    "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd",
    "01855fc5c9eed868b43ea2c3df99ec17dd9d903187d891e2365a89b98125c994b2d80fc4ec24e7874760c6e42a8bce13791f15fe7f83d4cd055f614c25527a304b4202efb982197ef2b6629c2202796584a7351bbc0563b27ed35c295e95021b947bb6a177e849e45ce5313ab7fa08e90daed00ceeadec13f271eea500df3e801303e0a9d0e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce060117650300000002d3a9410ac758ad45dfc85af8626efdacf398439c73977b13064aa8e6c8f2ac880255d213ecba5fd74e52002e08a69a2e5e08378f2e43fbbf3f1130dde976db34260000000900cb491a1b9ac9dbcdf083bb80926012e041c623adb1ed964a80eb10bbb147ac",
    "013ff49e2419f779390a9347e8c3ee6391dd3f9e543c12dabcb0f1ebc8168754f466a0ed18269ae22ff110eafed64e6c45cfe8fdf2815d06ccd98afd4d3bed950492bea47dc72d2bc33e4f5a05cb5ac99876534d23537742e6fbdfd3cea455c81ac5410cbb9dff9a4a98f4c9016a156a6696e609601e8c81e9c19e79816c698e9904d3fbd0e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce06011765040000000337024f9dd20621ecd32baeee4741130d24797eda8cad0d09c794cb4458c4f2a30369f2e10d3a65b5c275bf5ce7ea5105ca9a5a25f81905305454a1196a2a01d42700000012006a2db91bb1ab362b64b298bd023859869c796a05aa4e66a50f4f374c72240c",
    "01d46df95124a711724990f40299bb166babc56d86de624db48776e2afb80e0302073cd5a1bff88021bfb51d13ecdac28387e6d1afe96d6871f1af20d53c93ff86ccccd693bd6461f094fe0bdf15b8284e4e65183c1a0ef596dfb1c56dfe0c61201803847b5e2d8a4fa6377c4ef47b51bda27b1ba8dda853f9b4f64cd5dc7367aa04ebbed1e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce0601176505000000027de3a01d95abec7ca4a110a45ca7e22193df9b51229e0fdfeaa19ebebf3f53e6031c96172660c9f068adb6e74e10b4afe17be3ce50837d0d670aadd988e79d2e1e00000015000f94951b87b6f29b3b5c86ee003baa22e10b490045b8046b14c9281d25fd6c",
    "01875aaa0886c229607b3da2440f9cdb12f61ed2a0e56c6a9dd9536ac11079ff038f118c8c15e83b19c467f35ac81ff3d88ea344b4ae88231cb08304cdb1aca961296a3e3d6485b9c32a67d18f09af8758ba5f393bbcb29ed4ddcd6e357877e70f346be81869e254cbb192ee5013a9b48f07fb66e0f809b00a63d92649e12129b704e392d2e9ba2ddf4ff3b77824042f5c16a5da006c992258bd8574e8429b59cd02fc59ff0d22ce0601176506000000022846c4f17a909080d7cb8bcf6217e2139666f420582f04e628a1e1225b4ecf49036066a84d6ab109fd53ee769e7bbb89daf191d883007c5625a9b762c542108b8600000024030068221b48756b6ff480f656a82f94f11d479538d008c412508175748f1b9c",
    "01918d0c4ccb9a26cc69a3250eef1117b07bf843367a25455fd0873349a0821a61c8099d28b23cfe8a56553291318650740775b6d827818eae51ad2b0b23cc049cb96c900bef70956ca7c6b01c6e1aa543d6d50e709f852062287fdfc53e2647f91302a55e568b0075165ea085172f834a60d957c98982a51044a6931ec981ade604cb81d3e9ba2da08b33945a758152368ad5b6e2172bf4e669d04c4c951df483da39079908d107060117650700000003a1b5faf27aab713ac2114b3710fb3cf0af580d95997197435c54da4b332efd6902d2c567d69d65d6d5e621d3c2473bdb2880579eb05728cd0384a58592e6d883540000002703206c871b98190c2204cddab9e205f26bd4c7973e7d6ce2b0070e30fd46cf33",
    "01baffd756f86275213fb4dd9400d1d667d0a35a2ba712af050cf0a6f0dfd799919f779fdeb12596973dcaf413a8af18c1d9138bd3420414cc2d2bdb5db2c2d2e955a45f129a2a11888cb74c3c3664caa9c6ac1c1ce6d712e1fbdc1c387b88af3ee40028aadf914a098ee11a02bfcb2d5bf499c920ebce81e6a3b6c738e5c20273048fc2d3e9ba2da08b33945a758152368ad5b6e2172bf4e669d04c4c951df483da39079908d107060117650800000003149c52fbfac539d818d68eb2856b42a2053452bad123b361d5374320a77dc2bb025a20ba1794773296d1018a7a21599d15b3389b06c60c7094f936fe1fc86d968f0000002901361e821bc66259888997722b41d567a1a33e3387116416fa867c0bc37e34be",
];

fn header_from_hex(hex: &str) -> Header {
    let raw = hex::decode(hex).unwrap();
    let mut r = VlqReader::new(&raw);
    read_header(&mut r).unwrap()
}

fn popow_hdr(h: Header, links: Vec<ModifierId>) -> PoPowHeader {
    PoPowHeader {
        header: h,
        interlinks: links,
        interlinks_proof: vec![],
    }
}

/// Production Mode 4 flow requires the header chain to be
/// validated up to `snapshot_height` BEFORE `install_snapshot_state`
/// runs (Mode 2's header-sync seam, or the NiPoPoW prefix). Tests
/// simulate header sync by applying the popow proof first — that
/// writes `best_header_height = suffix_tip_height` (= 8 for this
/// fixture, since `headers.last()` after `prefix ++ [suffix_head]
/// ++ suffix_tail` is `h_8`). Install-side tests therefore use
/// `snapshot_height = SUFFIX_TIP_HEIGHT` so the post-install
/// invariant `best_full_block_height <= best_header_height`
/// holds, mirroring what production sees at a real Mode 4 anchor.
const SUFFIX_TIP_HEIGHT: u32 = 8;

/// k=4 proof over heights 1..=8: dense_from_height = 5 - 4 + 1 = 2.
/// Mirror of `popow_apply::synthetic_proof_k4_over_1_to_8`.
fn nipopow_proof_dense_from_2() -> NipopowProof {
    let mut headers: Vec<Header> = MAINNET_HEADERS_1_10
        .iter()
        .take(8)
        .map(|h| header_from_hex(h))
        .collect();
    let suffix_tail: Vec<Header> = headers.drain(5..).collect();
    let suffix_head_h = headers.pop().unwrap();
    let prefix: Vec<PoPowHeader> = headers.drain(..).map(|h| popow_hdr(h, vec![])).collect();
    NipopowProof {
        m: 6,
        k: 4,
        prefix,
        suffix_head: popow_hdr(suffix_head_h, vec![]),
        suffix_tail,
        continuous: true,
    }
}

// ----- happy path -----

#[test]
fn apply_popow_proof_seeds_prune_sentinel_to_dense_from_height() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    // Pre-state: no apply yet → sentinel at read-default 1.
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 1);

    let proof = nipopow_proof_dense_from_2();
    store.apply_popow_proof(&proof).unwrap();
    match store.chain_state().header_availability {
        HeaderAvailability::PoPowSparse {
            dense_from_height, ..
        } => assert_eq!(dense_from_height, 2),
        other => panic!("expected PoPowSparse, got {other:?}"),
    }
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        2,
        "apply_popow_proof must co-commit prune sentinel = dense_from_height",
    );
}

#[test]
fn apply_popow_proof_sentinel_survives_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    {
        let mut store = open_test_store(&path);
        let proof = nipopow_proof_dense_from_2();
        store.apply_popow_proof(&proof).unwrap();
        assert_eq!(store.read_minimal_full_block_height().unwrap(), 2);
    }
    // Reopen — sentinel persisted alongside chain_state.
    let store = open_test_store(&path);
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        2,
        "prune sentinel co-committed with apply_popow_proof's atomic \
         write_txn must survive reopen",
    );
}

#[test]
fn writer_side_lower_candidate_is_silent_noop() {
    // Dual-bootstrap composition contract: if one writer has
    // already pinned the prune sentinel at a higher value, a
    // later writer with a lower candidate must not abort —
    // `advance_minimal_full_block_height_in_txn` is max-style
    // (Ok no-op on backward, NOT a PruneSentinelMonotonicity
    // error). This is the order
    // `install_snapshot_state (snapshot_height + 1) ` then
    // `apply_popow_proof (dense_from_height)` in Mode 4 when
    // `snapshot_height + 1 > dense_from_height`.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    // Hand-bump the sentinel above the proof's dense_from_height (= 2).
    store.write_minimal_full_block_height(100).unwrap();

    // apply_popow_proof tries to write dense_from_height = 2, which
    // is < 100 — the in-txn helper silently no-ops on backward,
    // so the apply succeeds and the rest of its state lands.
    let proof = nipopow_proof_dense_from_2();
    store
        .apply_popow_proof(&proof)
        .expect("popow apply must succeed with lower candidate (silent no-op on sentinel)");
    // Sentinel pinned at 100 — the prior higher write wins, no
    // ratchet backward.
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        100,
        "lower writer must not lower the sentinel",
    );
    // And the popow apply's chain_state changes did land.
    match store.chain_state().header_availability {
        HeaderAvailability::PoPowSparse {
            dense_from_height, ..
        } => assert_eq!(
            dense_from_height, 2,
            "popow apply's chain_state must have advanced normally",
        ),
        other => panic!("expected PoPowSparse, got {other:?}"),
    }
}

#[test]
fn strict_standalone_writer_still_rejects_backward() {
    // `write_minimal_full_block_height` is the strict variant —
    // backward writes return `PruneSentinelMonotonicity`. Tests
    // and any defensive caller that wants "must advance forward"
    // as a hard invariant use this rather than the in-txn helper.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let store = open_test_store(&path);
    store.write_minimal_full_block_height(100).unwrap();
    let err = store
        .write_minimal_full_block_height(50)
        .expect_err("strict standalone variant must reject backward writes");
    assert!(
        format!("{err:?}").contains("PruneSentinelMonotonicity"),
        "expected PruneSentinelMonotonicity, got {err:?}",
    );
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 100);
}

// ----- real install_snapshot_state coverage -----

/// Build a small populated AvlTree, round-trip it through the
/// public snapshot codec, and return a (reconstructed_tree,
/// expected_state_root) pair that satisfies
/// `install_snapshot_state`'s defense-in-depth root check.
fn build_reconstructed_tree(n_leaves: u8) -> (ReconstructedTree, ADDigest) {
    let mut tree = AvlTree::new();
    for i in 0..n_leaves {
        let key = [i.wrapping_add(0x10); 32];
        let value = vec![i, i.wrapping_add(0x20), i.wrapping_add(0x40)];
        tree.insert(key, value);
    }
    let server = SnapshotServer::build(&tree, 100, MAINNET_MANIFEST_DEPTH).unwrap();
    let chunks_map: HashMap<Digest32, Vec<u8>> = server.chunks.iter().cloned().collect();
    let reconstructed = reconstruct_tree(&server.manifest_bytes, &chunks_map).unwrap();
    // ADDigest = 32-byte root label + 1-byte tree height suffix.
    let mut root_bytes = [0u8; 33];
    root_bytes[..32].copy_from_slice(reconstructed.root_label.as_bytes());
    root_bytes[32] = reconstructed.tree_height;
    (reconstructed, ADDigest::from_bytes(root_bytes))
}

#[test]
fn install_snapshot_state_seeds_prune_sentinel_to_snapshot_height_plus_one() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    // Pre-state: no install yet — sentinel at default 1.
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 1);

    // Header-sync simulation — popow proof writes
    // best_header_height = SUFFIX_TIP_HEIGHT and populates
    // HEADER_CHAIN_INDEX so install's documented "headers up to
    // snapshot_height already validated" precondition holds AND
    // the canonical_header_id cross-check has a row to compare
    // against.
    store
        .apply_popow_proof(&nipopow_proof_dense_from_2())
        .unwrap();

    let snapshot_height = SUFFIX_TIP_HEIGHT;
    let canonical_header_id = store
        .get_header_id_at_height(snapshot_height)
        .unwrap()
        .expect("popow must have indexed the suffix tip");
    let (reconstructed, expected_state_root) = build_reconstructed_tree(3);

    store
        .install_snapshot_state(
            reconstructed,
            snapshot_height,
            canonical_header_id,
            &expected_state_root,
        )
        .expect("install must succeed after header-sync");

    // Sentinel pinned at the first not-pre-bootstrap height.
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        snapshot_height + 1,
        "install must co-commit sentinel = snapshot_height + 1",
    );
    // chain_state advanced AND invariant holds.
    assert_eq!(store.chain_state().best_full_block_height, snapshot_height,);
    assert_eq!(store.chain_state().best_full_block_id, canonical_header_id,);
    assert!(
        store.chain_state().best_full_block_height <= store.chain_state().best_header_height,
        "best_full ({}) must not exceed best_header ({})",
        store.chain_state().best_full_block_height,
        store.chain_state().best_header_height,
    );
}

#[test]
fn install_snapshot_state_sentinel_survives_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let snapshot_height = SUFFIX_TIP_HEIGHT;
    {
        let mut store = open_test_store(&path);
        store
            .apply_popow_proof(&nipopow_proof_dense_from_2())
            .unwrap();
        let canonical_header_id = store
            .get_header_id_at_height(snapshot_height)
            .unwrap()
            .expect("popow must have indexed the suffix tip");
        let (reconstructed, expected_state_root) = build_reconstructed_tree(3);
        store
            .install_snapshot_state(
                reconstructed,
                snapshot_height,
                canonical_header_id,
                &expected_state_root,
            )
            .unwrap();
        assert_eq!(
            store.read_minimal_full_block_height().unwrap(),
            snapshot_height + 1,
        );
    }
    let store = open_test_store(&path);
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        snapshot_height + 1,
        "install-time sentinel must persist across reopen",
    );
}

#[test]
fn install_snapshot_state_seeds_chain_index_anchor_at_snapshot_height() {
    // Phase 4 rollback boundary regression: a rollback whose
    // target is `sentinel - 1 = snapshot_height` is legal under
    // the Phase 4 guard (wallet replay walks `target + 1 ..= from`
    // so sections at `target + 1` are the lowest read), but the
    // reorg path resolves the new tip id via `CHAIN_INDEX[target]`.
    // Without an install-time anchor, that read returns None and
    // the reorg falls through to `NoCommittedState`. Install MUST
    // seed `CHAIN_INDEX[snapshot_height] = canonical_header_id` so
    // the rollback path resolves uniformly.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    store
        .apply_popow_proof(&nipopow_proof_dense_from_2())
        .unwrap();
    let snapshot_height = SUFFIX_TIP_HEIGHT;
    let canonical_header_id = store
        .get_header_id_at_height(snapshot_height)
        .unwrap()
        .expect("popow must have indexed the suffix tip");
    let (reconstructed, expected_state_root) = build_reconstructed_tree(3);
    store
        .install_snapshot_state(
            reconstructed,
            snapshot_height,
            canonical_header_id,
            &expected_state_root,
        )
        .expect("install must succeed");
    // The anchor lookup matches the snapshot's canonical id.
    let anchor_id = store
        .chain_index_id_at_height(snapshot_height)
        .expect("CHAIN_INDEX read");
    assert_eq!(
        anchor_id,
        Some(canonical_header_id),
        "install must seed CHAIN_INDEX[snapshot_height] = canonical_header_id",
    );
}

#[test]
fn mode4_composition_popow_first_then_install_takes_max() {
    // Production Mode 4 order: header sync (popow proof) first,
    // then install_snapshot_state at the anchor height. After
    // composition: sentinel = max(dense_from_height = 2,
    // snapshot_height + 1 = SUFFIX_TIP_HEIGHT + 1) = 9. Both
    // writers' chain_state changes are preserved AND the
    // best_full <= best_header invariant holds.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);

    store
        .apply_popow_proof(&nipopow_proof_dense_from_2())
        .unwrap();
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 2);

    let snapshot_height = SUFFIX_TIP_HEIGHT;
    let canonical_header_id = store
        .get_header_id_at_height(snapshot_height)
        .unwrap()
        .expect("popow must have indexed the suffix tip");
    let (reconstructed, expected_state_root) = build_reconstructed_tree(3);
    store
        .install_snapshot_state(
            reconstructed,
            snapshot_height,
            canonical_header_id,
            &expected_state_root,
        )
        .expect("install must succeed at the popow-anchored height");

    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        snapshot_height + 1,
        "install's higher candidate wins (max-style composition)",
    );
    match store.chain_state().header_availability {
        HeaderAvailability::PoPowSparse {
            dense_from_height, ..
        } => assert_eq!(dense_from_height, 2),
        other => panic!("expected PoPowSparse, got {other:?}"),
    }
    assert_eq!(store.chain_state().best_full_block_height, snapshot_height);
    assert!(
        store.chain_state().best_full_block_height <= store.chain_state().best_header_height,
        "best_full must not exceed best_header after composition",
    );
}

#[test]
fn fresh_db_sentinel_row_is_absent_serving_default_one() {
    // Read-side serve default contract: a never-written row
    // collapses to `1` via `read_minimal_full_block_height`, but
    // the raw peek must distinguish "never written" from
    // "written and pinned at 1".
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let store = open_test_store(&path);
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        1,
        "absent row reads as GenesisHeight (1)",
    );
    assert_eq!(
        store.try_read_minimal_full_block_height_raw().unwrap(),
        None,
        "fresh DB must NOT have stamped the row — open is lazy",
    );
}

#[test]
fn install_snapshot_state_refuses_snapshot_height_zero() {
    // Defensive guard: snapshot at GenesisHeight is meaningless
    // (no pre-bootstrap state to jump past). Scala never targets
    // snapshot_height = 0. Allowing this would leave the store
    // half-installed-but-fresh-looking (AVL + chain_state +
    // trust sentinel committed while best_full_block_height ==
    // 0), and both reciprocal bootstrap guards would still see
    // the store as fresh — opening a window for a misordered
    // second writer to overwrite the install.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    let (reconstructed, expected_state_root) = build_reconstructed_tree(3);
    let err = store
        .install_snapshot_state(reconstructed, 0, [0x66; 32], &expected_state_root)
        .expect_err("snapshot_height == 0 must be rejected");
    assert!(
        format!("{err:?}").contains("InstallSnapshotAtGenesisRefused"),
        "expected InstallSnapshotAtGenesisRefused, got {err:?}",
    );
    // Store stayed fresh — nothing committed.
    assert_eq!(store.chain_state().best_full_block_height, 0);
    assert_eq!(
        store.try_read_minimal_full_block_height_raw().unwrap(),
        None,
    );
}

#[test]
fn install_snapshot_state_cross_check_finds_anchor_in_sparse_prefix() {
    // `apply_popow_proof` writes the sparse prefix to
    // HEADERS_BY_HEIGHT (slot 0) but NOT to HEADER_CHAIN_INDEX.
    // Real Mode 4 anchors at epoch boundaries typically fall in
    // the sparse prefix (the boundary is far below the chain tip,
    // and the popow suffix covers only the recent k blocks).
    // install_snapshot_state's cross-check MUST find the anchor
    // via HEADERS_BY_HEIGHT — using HEADER_CHAIN_INDEX would
    // falsely reject. Exercise this directly: the proof fixture's
    // prefix covers heights 1..=4; pick a prefix-height anchor and
    // prove install accepts it.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    store
        .apply_popow_proof(&nipopow_proof_dense_from_2())
        .unwrap();
    // Sanity: pick a height in the SPARSE PREFIX (dense_from = 2,
    // so heights 1 is sparse; heights 2..=8 are dense per
    // popow_cache.rs).
    let prefix_height: u32 = 1;
    let prefix_id_in_chain_index = store.get_header_id_at_height(prefix_height).unwrap();
    assert_eq!(
        prefix_id_in_chain_index, None,
        "precondition: prefix height NOT in HEADER_CHAIN_INDEX",
    );
    let prefix_id_in_height_table = store
        .header_ids_at_height_all(prefix_height)
        .unwrap()
        .first()
        .copied();
    assert!(
        prefix_id_in_height_table.is_some(),
        "precondition: prefix height IS in HEADERS_BY_HEIGHT slot 0",
    );

    // The cross-check uses HEADERS_BY_HEIGHT — install accepts.
    let canonical_header_id = prefix_id_in_height_table.unwrap();
    let (reconstructed, expected_state_root) = build_reconstructed_tree(3);
    store
        .install_snapshot_state(
            reconstructed,
            prefix_height,
            canonical_header_id,
            &expected_state_root,
        )
        .expect("install must succeed for a sparse-prefix anchor via HEADERS_BY_HEIGHT");
    assert_eq!(store.chain_state().best_full_block_height, prefix_height);
}

#[test]
fn double_install_refused_leaves_chain_state_from_first_install() {
    // Atomicity guard: the second install must be refused by the
    // `best_full_block_height > 0` precondition, and its arguments
    // must NOT leak into `self.chain_state`. Mirrors the staging
    // fix — the install writer only promotes the staged
    // chain_state after `write_txn.commit()?` succeeds.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);

    store
        .apply_popow_proof(&nipopow_proof_dense_from_2())
        .unwrap();
    let first_height = SUFFIX_TIP_HEIGHT;
    let first_header_id = store
        .get_header_id_at_height(first_height)
        .unwrap()
        .expect("popow indexes suffix tip");
    let (rec_1, root_1) = build_reconstructed_tree(3);
    store
        .install_snapshot_state(rec_1, first_height, first_header_id, &root_1)
        .unwrap();
    assert_eq!(store.chain_state().best_full_block_height, first_height);
    assert_eq!(store.chain_state().best_full_block_id, first_header_id);

    // Second install must be refused — the
    // `best_full_block_height > 0` precondition fires before the
    // canonical_header_id cross-check, so the arbitrary
    // [0xBB; 32] id never gets validated; the install rejects
    // earlier.
    let second_height = SUFFIX_TIP_HEIGHT;
    let second_header_id = [0xBB; 32];
    let (rec_2, root_2) = build_reconstructed_tree(4);
    let err = store
        .install_snapshot_state(rec_2, second_height, second_header_id, &root_2)
        .expect_err("install must refuse on a non-fresh store");
    assert!(
        format!("{err:?}").contains("InstallSnapshotRefused"),
        "expected InstallSnapshotRefused, got {err:?}",
    );

    // chain_state still reflects the FIRST install — second
    // install's arguments did NOT leak into memory.
    assert_eq!(
        store.chain_state().best_full_block_height,
        first_height,
        "second install must not advance best_full_block_height",
    );
    assert_eq!(
        store.chain_state().best_full_block_id,
        first_header_id,
        "second install must not overwrite best_full_block_id",
    );
}

#[test]
fn mode4_composition_popow_first_then_install_survives_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let snapshot_height = SUFFIX_TIP_HEIGHT;
    {
        let mut store = open_test_store(&path);
        store
            .apply_popow_proof(&nipopow_proof_dense_from_2())
            .unwrap();
        let canonical_header_id = store
            .get_header_id_at_height(snapshot_height)
            .unwrap()
            .expect("popow indexes suffix tip");
        let (reconstructed, expected_state_root) = build_reconstructed_tree(3);
        store
            .install_snapshot_state(
                reconstructed,
                snapshot_height,
                canonical_header_id,
                &expected_state_root,
            )
            .unwrap();
        assert_eq!(
            store.read_minimal_full_block_height().unwrap(),
            snapshot_height + 1,
        );
    }
    let store = open_test_store(&path);
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        snapshot_height + 1,
        "popow→install composition's higher pin must persist across reopen",
    );
    match store.chain_state().header_availability {
        HeaderAvailability::PoPowSparse {
            dense_from_height, ..
        } => assert_eq!(dense_from_height, 2),
        other => panic!("expected PoPowSparse, got {other:?}"),
    }
    assert_eq!(store.chain_state().best_full_block_height, snapshot_height);
    assert!(store.chain_state().best_full_block_height <= store.chain_state().best_header_height,);
}

#[test]
fn apply_popow_proof_rejects_after_install_snapshot_state() {
    // Reciprocal precondition (symmetric to install's
    // `best_full_block_height > 0` refusal). After install runs,
    // the store is full-state past the snapshot anchor. Running
    // apply_popow_proof against that store would downgrade
    // header_availability to PoPowSparse and could persist
    // `best_header_height < best_full_block_height`. The
    // store-level guard refuses this rather than relying on the
    // orchestrator.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    // Set up an installed store: popow first to synchronize
    // headers, then install at the anchor.
    store
        .apply_popow_proof(&nipopow_proof_dense_from_2())
        .unwrap();
    let snapshot_height = SUFFIX_TIP_HEIGHT;
    let canonical_header_id = store
        .get_header_id_at_height(snapshot_height)
        .unwrap()
        .expect("popow indexes suffix tip");
    let (reconstructed, expected_state_root) = build_reconstructed_tree(3);
    store
        .install_snapshot_state(
            reconstructed,
            snapshot_height,
            canonical_header_id,
            &expected_state_root,
        )
        .unwrap();
    assert!(store.chain_state().best_full_block_height > 0);

    // Now try to re-apply popow — must reject.
    let err = store
        .apply_popow_proof(&nipopow_proof_dense_from_2())
        .expect_err("apply_popow_proof must refuse on an installed store");
    // First guard is mode (PoPowSparse from prior apply); the
    // reciprocal best_full_block_height guard would fire if the
    // store were re-set to Dense and full-block applied, which
    // requires a richer fixture. The mode guard is sufficient to
    // prove the writer refuses the misordered case.
    assert!(
        format!("{err:?}").contains("ApplyPopowProofWrongMode")
            || format!("{err:?}").contains("ApplyPopowProofRefused"),
        "expected ApplyPopowProofWrongMode or ApplyPopowProofRefused, got {err:?}",
    );
}

#[test]
fn apply_popow_proof_rejects_when_best_full_block_height_above_zero() {
    // Direct exercise of the new reciprocal best_full_block guard.
    // Fresh store + Dense mode + best_full > 0 → refuse with
    // ApplyPopowProofRefused.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    // Inject best_full_block_height = 5 directly via the test-only
    // seam, leaving header_availability = Dense (the default for
    // a fresh store). This is the only way to reach the new guard
    // without setting up a full installed-store fixture which
    // also flips header_availability to PoPowSparse.
    store
        .set_best_full_block_for_test([0u8; 32], 5)
        .expect("test-helper injection");
    assert_eq!(store.chain_state().best_full_block_height, 5);
    assert!(matches!(
        store.chain_state().header_availability,
        ergo_state::chain::HeaderAvailability::Dense,
    ));

    let err = store
        .apply_popow_proof(&nipopow_proof_dense_from_2())
        .expect_err("apply must reject when best_full_block_height > 0");
    assert!(
        format!("{err:?}").contains("ApplyPopowProofRefused"),
        "expected ApplyPopowProofRefused, got {err:?}",
    );
}

#[test]
fn open_does_not_migrate_archive_or_bootstrap_db() {
    // Open MUST NOT touch the sentinel row regardless of
    // chain_state. An archive store with best_full > 1 must keep
    // sentinel absent (read returns the GenesisHeight default
    // of 1), because archive has all blocks. A pre-Phase-1b
    // bootstrap DB also keeps the row absent at open; the
    // Phase 5 boot-consistency check (with config access) owns
    // the bootstrap-side migration when Mode 4 ships.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    {
        let mut store = open_test_store(&path);
        store.set_best_full_block_for_test([0xCD; 32], 5).unwrap();
        assert_eq!(
            store.try_read_minimal_full_block_height_raw().unwrap(),
            None,
            "precondition: sentinel row absent",
        );
    }
    // Reopen — open must NOT have stamped the row.
    let store = open_test_store(&path);
    assert_eq!(
        store.try_read_minimal_full_block_height_raw().unwrap(),
        None,
        "open must keep sentinel row absent for archive / pre-Phase-1b stores",
    );
    // Read-side serve gate still collapses absent to 1.
    assert_eq!(store.read_minimal_full_block_height().unwrap(), 1);
}

#[test]
fn install_snapshot_state_rejects_unindexed_canonical_header_id() {
    // Cross-check defense-in-depth: if caller passes a
    // canonical_header_id that doesn't match the locally indexed
    // header at snapshot_height, install must reject. Production
    // callers pass the id from the snapshot anchor's header
    // lookup; a drift between caller and persisted index would
    // split best_full_block_id from HEADER_CHAIN_INDEX.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    store
        .apply_popow_proof(&nipopow_proof_dense_from_2())
        .unwrap();
    let snapshot_height = SUFFIX_TIP_HEIGHT;
    let real_id = store
        .get_header_id_at_height(snapshot_height)
        .unwrap()
        .unwrap();
    let bogus_id = [0xEE; 32];
    assert_ne!(real_id, bogus_id);

    let (reconstructed, expected_state_root) = build_reconstructed_tree(3);
    let err = store
        .install_snapshot_state(
            reconstructed,
            snapshot_height,
            bogus_id,
            &expected_state_root,
        )
        .expect_err("install must reject mismatched canonical_header_id");
    assert!(
        format!("{err:?}").contains("InstallSnapshotHeaderIdMismatch"),
        "expected InstallSnapshotHeaderIdMismatch, got {err:?}",
    );
    // chain_state stayed unchanged.
    assert_eq!(store.chain_state().best_full_block_height, 0);
}

#[test]
fn install_snapshot_state_rejects_when_headers_not_synced_to_anchor() {
    // Defense-in-depth: install_snapshot_state must refuse if
    // headers up to `snapshot_height` are not yet validated and
    // indexed. Production Mode 4 always runs header sync before
    // install at the anchor; the runtime guard hardens what was
    // previously a docstring-only precondition. Without it, an
    // orchestration bug could persist
    // `best_full_block_height > best_header_height`, a
    // chain-state invariant violation.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = open_test_store(&path);
    // Fresh store: best_header_height = 0. Install at any
    // snapshot_height > 0 must reject.
    let snapshot_height: u32 = 5;
    let (reconstructed, expected_state_root) = build_reconstructed_tree(3);
    let err = store
        .install_snapshot_state(
            reconstructed,
            snapshot_height,
            [0xCC; 32],
            &expected_state_root,
        )
        .expect_err("install must reject when headers not synced");
    assert!(
        format!("{err:?}").contains("InstallSnapshotPreconditionUnmet"),
        "expected InstallSnapshotPreconditionUnmet, got {err:?}",
    );
    // chain_state must NOT have been mutated.
    assert_eq!(store.chain_state().best_full_block_height, 0);
    assert_eq!(store.chain_state().best_header_height, 0);
    // Sentinel row must not have been written either.
    assert_eq!(
        store.try_read_minimal_full_block_height_raw().unwrap(),
        None,
        "rejected install must not have touched the sentinel row",
    );
}

// Note on writer order: production Mode 4 is always header-sync
// first (via NiPoPoW prefix or Mode 2's full header download), then
// snapshot install. The reverse order — install before any header
// sync — would violate install_snapshot_state's documented
// precondition that "headers up to snapshot_height have already
// been validated and indexed". The max-style sentinel helper makes
// the sentinel COMPOSITION order-independent as a defense-in-depth
// guarantee, but the chain-state invariants (best_full <=
// best_header) only hold for the production order. We therefore
// do not encode "install-first-then-popow" as a supported test
// case here.

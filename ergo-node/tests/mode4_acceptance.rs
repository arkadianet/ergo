//! Mode 4 Phase 4d end-to-end acceptance tests.
//!
//! Drives the boot orchestration against real persisted state
//! produced by `apply_popow_proof` and `install_snapshot_state`
//! (rather than the fabricated marker / chain-state shapes used
//! in Phase 4b). Covers:
//!
//! - **Row B (NiPoPoW-only) reopen** — proof committed, store
//!   reopens cleanly with `nipopow_bootstrap = true`, boot
//!   classifies `ProofCommitted` and skips reducer construction.
//! - **Live identity refresh after apply_popow_proof** — the
//!   `/api/v1/identity` projection reflects the NiPoPoW
//!   provenance after reopen, with sentinel pinned at
//!   `dense_from_height`.
//! - **Row A (UTXO-only install)** — a REAL snapshot install
//!   (`ergo_state::test_helpers::reconstructed_snapshot_fixture`,
//!   the `SnapshotServer::build` → `reconstruct_tree` round-trip)
//!   is committed through `install_snapshot_state` on a Dense
//!   header chain, then driven through `run_inner`: boot skips a
//!   second install, the sentinel stays at `snapshot_height + 1`,
//!   the identity label is the mode-4 utxo-bootstrapped keep-N
//!   form, and the value boot seeds `SyncState.best_full_block_height`
//!   from is aligned with the install anchor.
//! - **Row C (composed lifecycle, both orders)** — NiPoPoW proof
//!   then install at a height inside the dense window (sentinel
//!   composes max-style, `HeaderAvailability` stays `PoPowSparse`,
//!   boot labels both provenance sources), AND the reverse order,
//!   where `apply_popow_proof` is refused on an installed store
//!   and the store stays coherently `Dense`. The deferred
//!   `HeightLookup::SparseGap` install branch and its resolution to
//!   `Dense` via bounded forward catch-up are covered by the
//!   `resolve_install_anchor` unit tests in
//!   `ergo-node/src/node/sync_tick.rs`, which also pin the
//!   composition bug this row found: an anchor BELOW the proof's
//!   `dense_from_height` used to defer forever (forward catch-up
//!   never back-fills the sparse prefix), and is now terminal.
//! - **Scala pin (archive + utxo_bootstrap)** — an archive-configured
//!   node with `utxo_bootstrap = true` keeps a CONSTANT prune
//!   sentinel across boot, matching
//!   `FullBlockPruningProcessor.scala:49-55`'s
//!   `blocksToKeep < 0 && utxoBootstrap` arm (which returns
//!   `readMinimalFullBlockHeight()` rather than resetting to
//!   `GenesisHeight`).

#[allow(dead_code)]
mod common;

use ergo_state::store::StateStore;
use ergo_state::test_helpers::{
    nipopow_proof_dense_from_2, reconstructed_snapshot_fixture, seed_dense_mainnet_headers,
};
use ergo_state::ChainStateRead;
use std::path::PathBuf;

fn data_dir(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "ergo-mode4-{label}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}

fn open_store(data_dir: &std::path::Path) -> StateStore {
    std::fs::create_dir_all(data_dir).unwrap();
    let mut store = StateStore::open(&data_dir.join("state.redb")).expect("open store");
    // Mirror production boot order: `run_inner` always calls
    // `initialize_genesis(&[])` before any forward operation.
    // Applying `apply_popow_proof` to a non-genesis store
    // matches what the production bootstrap path actually
    // exercises at restart.
    store.initialize_genesis(&[]).expect("init genesis");
    store
}

/// Sentinel value `dense_from_height` lifted from the
/// `nipopow_proof_dense_from_2` fixture — k=4 proof over heights
/// 1..=8 with suffix head at h=5, so dense_from = 5 - 4 + 1 = 2.
const PROOF_DENSE_FROM_HEIGHT: u32 = 2;

fn floor_keep() -> i32 {
    (ergo_state::store::ROLLBACK_WINDOW + ergo_state::store::SAFETY_MARGIN) as i32
}

#[tokio::test]
async fn row_b_nipopow_only_reopen_boots_cleanly_after_proof_commit() {
    // Drive a real NiPoPoW proof commit to the store. The proof
    // advances chain_state into `PoPowSparse` with
    // `dense_from_height = 2` and pins the prune sentinel at
    // the dense boundary.
    let dir = data_dir("nipopow-reopen");
    {
        let mut store = open_store(&dir);
        let proof = nipopow_proof_dense_from_2();
        store.apply_popow_proof(&proof).expect("apply popow proof");
        assert!(
            matches!(
                store.chain_state().header_availability,
                ergo_state::chain::HeaderAvailability::PoPowSparse { .. }
            ),
            "post-apply state must be PoPowSparse",
        );
        assert_eq!(
            store.read_minimal_full_block_height().unwrap(),
            PROOF_DENSE_FROM_HEIGHT,
            "proof commit must seed sentinel at dense_from_height",
        );
        assert_eq!(
            store.chain_state().best_full_block_height,
            0,
            "proof commit does not advance best_full_block_height",
        );
    }
    // Boot truly NiPoPoW-only: R3 (`nipopow_bootstrap` requires
    // `utxo_bootstrap` OR `blocks_to_keep >= 0`) is satisfied
    // via `blocks_to_keep = floor`, so `utxo_bootstrap = false`
    // isolates the NiPoPoW resume path. The Phase 4b' resume
    // classifier MUST detect `PoPowSparse` and skip reducer
    // construction — boot succeeds with no ApplyPopowProofWrongMode.
    let mut cfg = common::make_test_config(dir.clone());
    cfg.nipopow_bootstrap = true;
    cfg.utxo_bootstrap = false;
    cfg.blocks_to_keep = floor_keep();
    let handle = ergo_node::run_inner(cfg)
        .await
        .expect("boot must succeed after proof commit");
    handle.shutdown().await.expect("clean shutdown");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn row_b_identity_reflects_nipopow_provenance_after_reopen() {
    // Same setup as the previous test. The Mode 4 label arm
    // fires because:
    //   * `nipopow_bootstrap` config flag is set, AND
    //   * `blocks_to_keep > 0` (pruning enabled), AND
    //   * the live store has `PoPowSparse + sentinel > 1` →
    //     `BootstrapKind::Nipopow` (no UTXO marker present).
    // The composed label MUST surface
    // `"mode-4 · popow-bootstrapped · keep N"`, not the Mode 2
    // short-circuit and not the post-prune-archive refinement.
    let dir = data_dir("nipopow-identity");
    {
        let mut store = open_store(&dir);
        let proof = nipopow_proof_dense_from_2();
        store.apply_popow_proof(&proof).expect("apply proof");
    }
    let mut cfg = common::make_test_config(dir.clone());
    cfg.nipopow_bootstrap = true;
    cfg.utxo_bootstrap = false;
    cfg.blocks_to_keep = floor_keep();
    let handle = ergo_node::run_inner(cfg).await.expect("boot must succeed");
    let id = handle.read.identity();
    let keep = floor_keep();
    let expected_label = format!("mode-4 · popow-bootstrapped · keep {keep}");
    assert_eq!(
        id.mode, expected_label,
        "Mode 4 NiPoPoW-only label must compose provenance + suffix length",
    );
    assert!(
        id.nipopow_bootstrap,
        "nipopow_bootstrap effective flag must reflect both config and provenance",
    );
    assert!(
        !id.utxo_bootstrap,
        "no UTXO install ran — utxo_bootstrap effective flag must be false: {:?}",
        id,
    );
    handle.shutdown().await.expect("shutdown");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Wait for the action loop's first published API snapshot.
///
/// `SnapshotPublisher::new` seeds an all-zero snapshot at boot and the
/// real one lands on the first `sync_tick`, so reading
/// `handle.read.sync()` immediately after `run_inner` returns the
/// placeholder. Poll until the projection reflects committed chain
/// state (or the bound elapses, in which case the caller's assertion
/// reports the placeholder and fails loudly rather than hanging).
async fn wait_for_published_sync(
    handle: &ergo_node::RunHandle,
    expect_best_full: u32,
) -> ergo_api::types::ApiSyncStatus {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let sync = handle.read.sync();
        if sync.best_full_block_height == expect_best_full || std::time::Instant::now() > deadline {
            return sync;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Pin the coordinator seed expression from
/// `ergo-node/src/node/boot/sync_setup.rs` (`SyncCoordinator::new_with_timing(
/// store.chain_state_meta().best_full_block_height, ..)`) against the
/// store this boot actually opened. Boot never re-seeds
/// `SyncState.best_full_block_height` afterwards — only the install
/// path and a block apply move it — so a store whose committed height
/// is the install anchor is exactly what keeps the request-side
/// window from collapsing to `[0, download_window]` after a Mode 2/4
/// restart (the split-brain the post-install `set_best_full_block`
/// call in `sync_tick.rs` fixes for the in-session case).
fn assert_coordinator_seed_is(store: &StateStore, expected: u32) {
    let coordinator = ergo_sync::coordinator::SyncCoordinator::new_with_timing(
        store.chain_state_meta().best_full_block_height,
        ergo_p2p::sync::DOWNLOAD_WINDOW,
        false,
        ergo_chain_spec::ChainSpec::mainnet()
            .block_timing
            .header_freshness_threshold_ms(),
    );
    assert_eq!(
        coordinator.sync_state().best_full_block_height(),
        expected,
        "boot must seed SyncState.best_full_block_height from the \
         committed install anchor, not 0",
    );
}

/// Height inside the dense suffix of `nipopow_proof_dense_from_2`
/// (heights 1..=8, `dense_from_height = 2`). Also the tip of the
/// Dense chain `seed_dense_mainnet_headers(_, 8)` writes, so both
/// Row A and Row C anchor their install here.
const SNAPSHOT_ANCHOR_HEIGHT: u32 = 8;

/// Reopen a store the way boot does, so a post-shutdown assertion
/// reads committed state rather than the writer's in-memory copy.
fn reopen_store(data_dir: &std::path::Path) -> StateStore {
    StateStore::open(&data_dir.join("state.redb")).expect("reopen store")
}

/// Commit a REAL UTXO snapshot install at `SNAPSHOT_ANCHOR_HEIGHT`
/// on a Dense header chain, the shape a Mode 2/4 node has after its
/// first boot completed the install. Returns the anchor header id.
fn install_on_dense_chain(data_dir: &std::path::Path) -> [u8; 32] {
    let mut store = open_store(data_dir);
    let seeded = seed_dense_mainnet_headers(&mut store, SNAPSHOT_ANCHOR_HEIGHT as usize)
        .expect("seed dense header chain");
    let (height, header_id) = *seeded.last().expect("chain is non-empty");
    assert_eq!(height, SNAPSHOT_ANCHOR_HEIGHT);
    let (reconstructed, expected_state_root) =
        reconstructed_snapshot_fixture(3, SNAPSHOT_ANCHOR_HEIGHT);
    store
        .install_snapshot_state(
            reconstructed,
            SNAPSHOT_ANCHOR_HEIGHT,
            header_id,
            &expected_state_root,
        )
        .expect("install must succeed on a header-synced Dense store");
    header_id
}

// ----- Row A: real UTXO install driven through run_inner -----

#[tokio::test]
async fn row_a_real_utxo_install_boots_without_reinstalling() {
    let dir = data_dir("utxo-install-boot");
    let anchor_id = install_on_dense_chain(&dir);
    {
        // Pre-boot invariants the boot path depends on.
        let store = reopen_store(&dir);
        assert!(
            store.was_utxo_bootstrapped().unwrap(),
            "install must arm the UTXO_BOOTSTRAP_INSTALLED_V1 provenance marker",
        );
        assert_eq!(
            store.chain_state().best_full_block_height,
            SNAPSHOT_ANCHOR_HEIGHT,
        );
        assert_eq!(
            store.read_minimal_full_block_height().unwrap(),
            SNAPSHOT_ANCHOR_HEIGHT + 1,
            "install co-commits sentinel = snapshot_height + 1",
        );
        assert!(matches!(
            store.chain_state().header_availability,
            ergo_state::chain::HeaderAvailability::Dense,
        ));
    }

    let keep = floor_keep();
    let mut cfg = common::make_test_config(dir.clone());
    cfg.utxo_bootstrap = true;
    cfg.nipopow_bootstrap = false;
    cfg.blocks_to_keep = keep;
    let handle = ergo_node::run_inner(cfg)
        .await
        .expect("Mode 4 boot must succeed on an already-installed store");

    let id = handle.read.identity();
    assert_eq!(
        id.mode,
        format!("mode-4 · utxo-bootstrapped · keep {keep}"),
        "Mode 4 UTXO-only label must compose provenance + suffix length",
    );
    assert!(id.utxo_bootstrap, "install provenance must surface: {id:?}");
    assert!(
        !id.nipopow_bootstrap,
        "no proof was applied — nipopow flag must stay false: {id:?}",
    );

    // `boot/sync_setup.rs` seeds `SyncCoordinator` (and therefore
    // `SyncState.best_full_block_height`) from the store's committed
    // `best_full_block_height`. Assert the live projection of that
    // field is the install anchor — the Mode 2 post-install fix at
    // `sync_tick.rs` (`set_best_full_block` after install) exists
    // because a stale 0 here empties every request batch.
    assert_eq!(
        wait_for_published_sync(&handle, SNAPSHOT_ANCHOR_HEIGHT)
            .await
            .best_full_block_height,
        SNAPSHOT_ANCHOR_HEIGHT,
        "the live sync projection must report the install anchor",
    );

    handle.shutdown().await.expect("clean shutdown");

    // No second install ran: chain state, anchor id, provenance
    // marker and sentinel are all exactly as the install left them.
    let store = reopen_store(&dir);
    assert_eq!(
        store.chain_state().best_full_block_height,
        SNAPSHOT_ANCHOR_HEIGHT,
        "boot must not re-run the install",
    );
    assert_eq!(store.chain_state().best_full_block_id, anchor_id);
    assert!(store.was_utxo_bootstrapped().unwrap());
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        SNAPSHOT_ANCHOR_HEIGHT + 1,
        "boot must not move the install-time prune sentinel",
    );
    assert_coordinator_seed_is(&store, SNAPSHOT_ANCHOR_HEIGHT);
    let _ = std::fs::remove_dir_all(&dir);
}

// ----- Row C: composed NiPoPoW + UTXO lifecycle, both orders -----

#[tokio::test]
async fn row_c_popow_then_install_composes_max_sentinel_and_labels_both() {
    // Production Mode 4 order: NiPoPoW proof establishes the header
    // chain, then the UTXO snapshot installs at an anchor inside the
    // proof's DENSE window. Sentinel composition is max-style, so the
    // install's `snapshot_height + 1` (= 9) wins over the proof's
    // `dense_from_height` (= 2).
    let dir = data_dir("popow-then-install");
    let anchor_id = {
        let mut store = open_store(&dir);
        store
            .apply_popow_proof(&nipopow_proof_dense_from_2())
            .expect("apply popow proof");
        assert_eq!(
            store.read_minimal_full_block_height().unwrap(),
            PROOF_DENSE_FROM_HEIGHT,
        );
        let header_id = store
            .get_header_id_at_height(SNAPSHOT_ANCHOR_HEIGHT)
            .unwrap()
            .expect("anchor is inside the proof's dense window");
        let (reconstructed, expected_state_root) =
            reconstructed_snapshot_fixture(3, SNAPSHOT_ANCHOR_HEIGHT);
        store
            .install_snapshot_state(
                reconstructed,
                SNAPSHOT_ANCHOR_HEIGHT,
                header_id,
                &expected_state_root,
            )
            .expect("install must succeed at a dense-window anchor");
        assert_eq!(
            store.read_minimal_full_block_height().unwrap(),
            SNAPSHOT_ANCHOR_HEIGHT + 1,
            "max-style composition: the install's higher candidate wins",
        );
        header_id
    };

    let keep = floor_keep();
    let mut cfg = common::make_test_config(dir.clone());
    cfg.utxo_bootstrap = true;
    cfg.nipopow_bootstrap = true;
    cfg.blocks_to_keep = keep;
    let handle = ergo_node::run_inner(cfg)
        .await
        .expect("composed Mode 4 boot must succeed");

    let id = handle.read.identity();
    assert_eq!(
        id.mode,
        format!("mode-4 · utxo+popow-bootstrapped · keep {keep}"),
        "both provenance sources must be named in the label",
    );
    assert!(id.utxo_bootstrap && id.nipopow_bootstrap, "{id:?}");
    assert_eq!(
        wait_for_published_sync(&handle, SNAPSHOT_ANCHOR_HEIGHT)
            .await
            .best_full_block_height,
        SNAPSHOT_ANCHOR_HEIGHT,
    );
    handle.shutdown().await.expect("clean shutdown");

    // Composition survives the boot: both writers' state is intact.
    let store = reopen_store(&dir);
    match store.chain_state().header_availability {
        ergo_state::chain::HeaderAvailability::PoPowSparse {
            dense_from_height, ..
        } => assert_eq!(
            dense_from_height, PROOF_DENSE_FROM_HEIGHT,
            "the install must not clobber the proof's sparse-mode tag",
        ),
        other => panic!("expected PoPowSparse after composition, got {other:?}"),
    }
    assert_eq!(store.chain_state().best_full_block_id, anchor_id);
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        SNAPSHOT_ANCHOR_HEIGHT + 1,
    );
    assert!(
        store.chain_state().best_full_block_height <= store.chain_state().best_header_height,
        "best_full must not exceed best_header after composed boot",
    );
    assert_coordinator_seed_is(&store, SNAPSHOT_ANCHOR_HEIGHT);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn row_c_install_then_popow_is_refused_and_store_stays_dense() {
    // Reverse order. `install_snapshot_state` requires
    // `snapshot_height <= best_header_height`, so by the time an
    // install has run the store always has headers — and
    // `apply_popow_proof`'s reciprocal guard refuses on
    // `best_full_block_height > 0` rather than downgrading
    // `header_availability` to PoPowSparse behind the installed
    // state. Composition is therefore ORDER-CONSTRAINED, and the
    // refusal must leave the install fully coherent.
    let dir = data_dir("install-then-popow");
    let anchor_id = install_on_dense_chain(&dir);
    {
        let mut store = reopen_store(&dir);
        let err = store
            .apply_popow_proof(&nipopow_proof_dense_from_2())
            .expect_err("popow apply must be refused on an installed store");
        assert!(
            format!("{err:?}").contains("ApplyPopowProofRefused"),
            "expected ApplyPopowProofRefused, got {err:?}",
        );
        // The refused writer changed nothing.
        assert!(matches!(
            store.chain_state().header_availability,
            ergo_state::chain::HeaderAvailability::Dense,
        ));
        assert_eq!(
            store.chain_state().best_full_block_height,
            SNAPSHOT_ANCHOR_HEIGHT,
        );
        assert_eq!(
            store.read_minimal_full_block_height().unwrap(),
            SNAPSHOT_ANCHOR_HEIGHT + 1,
            "a refused proof must not lower the install-time sentinel",
        );
    }

    // The node still boots with BOTH operator flags set: the NiPoPoW
    // resume classifier sees a Dense store with
    // `best_full_block_height > 0` (`NormalStore`) and skips the
    // reducer instead of arming one whose apply would be refused.
    let keep = floor_keep();
    let mut cfg = common::make_test_config(dir.clone());
    cfg.utxo_bootstrap = true;
    cfg.nipopow_bootstrap = true;
    cfg.blocks_to_keep = keep;
    let handle = ergo_node::run_inner(cfg)
        .await
        .expect("boot must succeed after a refused proof apply");
    assert_eq!(
        wait_for_published_sync(&handle, SNAPSHOT_ANCHOR_HEIGHT)
            .await
            .best_full_block_height,
        SNAPSHOT_ANCHOR_HEIGHT,
    );
    handle.shutdown().await.expect("clean shutdown");

    let store = reopen_store(&dir);
    assert!(
        matches!(
            store.chain_state().header_availability,
            ergo_state::chain::HeaderAvailability::Dense,
        ),
        "boot must not flip availability on behalf of the refused proof",
    );
    assert_eq!(store.chain_state().best_full_block_id, anchor_id);
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        SNAPSHOT_ANCHOR_HEIGHT + 1,
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ----- oracle parity -----

#[tokio::test]
async fn archive_with_utxo_bootstrap_keeps_constant_sentinel_across_boot() {
    // Scala oracle (`FullBlockPruningProcessor.scala:49-55`):
    //
    //   if (nodeConfig.blocksToKeep < 0) {
    //     if (nodeConfig.utxoSettings.utxoBootstrap) {
    //       readMinimalFullBlockHeight()   // CONSTANT
    //     } else { GenesisHeight }         // reset to 1
    //   }
    //
    // Captured against the upstream Scala runtime as
    // `archive_with_utxo_bootstrap_keeps_current_min` in
    // `test-vectors/mode3-pruning/runtime-vectors.json`
    // (current_min = 5000, blocks_to_keep = -1, utxo_bootstrap =
    // true → scala_runtime_output = 5000).
    //
    // `boot/mod.rs` reads the sentinel through
    // `read_minimal_full_block_height` and threads that value into
    // the coordinator, identity and storage gates. This test pins
    // that an archive + `utxo_bootstrap` boot preserves the
    // install-time sentinel rather than collapsing it to
    // GenesisHeight — the exact constant-sentinel arm above.
    let dir = data_dir("archive-utxo-bootstrap");
    install_on_dense_chain(&dir);

    let mut cfg = common::make_test_config(dir.clone());
    cfg.utxo_bootstrap = true;
    cfg.nipopow_bootstrap = false;
    cfg.blocks_to_keep = -1; // archive
    let handle = ergo_node::run_inner(cfg)
        .await
        .expect("archive + utxo_bootstrap boot must succeed");

    let id = handle.read.identity();
    assert_eq!(
        id.mode, "utxo · utxo-bootstrapped",
        "archive-shaped bootstrap config takes the Mode 2 label",
    );
    assert!(id.utxo_bootstrap);
    handle.shutdown().await.expect("clean shutdown");

    let store = reopen_store(&dir);
    assert_eq!(
        store.read_minimal_full_block_height().unwrap(),
        SNAPSHOT_ANCHOR_HEIGHT + 1,
        "archive + utxo_bootstrap must keep a CONSTANT sentinel — Scala \
         returns readMinimalFullBlockHeight() here, never GenesisHeight",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

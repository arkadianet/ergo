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
//!
//! Row A (UTXO-only install) and Row C (both-bootstrap composed
//! lifecycle) remain open follow-ups; the install-state
//! reconstructed-tree fixture lives next to the existing
//! `ergo-state/tests/bootstrap_pruning_sentinel.rs` coverage
//! and integrating it into the boot path requires additional
//! cross-crate plumbing.

#[allow(dead_code)]
mod common;

use ergo_state::store::StateStore;
use ergo_state::test_helpers::nipopow_proof_dense_from_2;
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

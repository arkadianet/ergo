//! Mode 4 Phase 4b boot refusal + skip-path tests.
//!
//! Three boot-time contracts:
//! 1. `(utxo_bootstrap = true, marker = armed,
//!    best_full_block_height = 0)` is state corruption — the
//!    marker is written atomically with the install which
//!    advances `best_full`. Boot refuses with a clear error.
//! 2. `nipopow_bootstrap = true` against a `Dense` store with
//!    `best_header_height > 0` AND `best_full_block_height = 0`
//!    (PartialHeaderSync) is not a supported resume state.
//!    Boot refuses rather than arm a reducer whose proof apply
//!    would later silently abort bootstrap.
//! 3. The healthy post-install restart path:
//!    `(utxo_bootstrap = true, marker = armed,
//!    best_full_block_height > 0)` MUST boot cleanly and skip
//!    the install path, logging the resume.

#[allow(dead_code)]
mod common;

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header, Header};
use ergo_state::store::StateStore;
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
    store.initialize_genesis(&[]).expect("init genesis");
    store
}

fn synth_header(height: u32) -> Header {
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
        state_root: ADDigest::from_bytes(state_root_bytes),
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

fn apply_empty_block(store: &mut StateStore, height: u32) {
    let h = synth_header(height);
    let (bytes, id) = serialize_header(&h).expect("serialize");
    let id_bytes = *id.as_bytes();
    store.store_header(&id_bytes, &bytes).expect("store_header");
    store
        .promote_header_to_height_index_for_test(height, &id_bytes)
        .expect("promote header");
    let expected = store.root_digest();
    store
        .apply_block_unchecked_for_test(height, &id_bytes, &expected, &[])
        .unwrap_or_else(|e| panic!("apply h={height}: {e:?}"));
}

#[tokio::test]
async fn boot_refuses_corrupt_utxo_marker_without_full_block() {
    let dir = data_dir("corrupt-marker");
    {
        let store = open_store(&dir);
        store
            .test_force_arm_utxo_bootstrap_marker()
            .expect("arm marker");
        assert_eq!(store.chain_state().best_full_block_height, 0);
        assert!(store.was_utxo_bootstrapped().unwrap());
    }
    let mut cfg = common::make_test_config(dir.clone());
    cfg.utxo_bootstrap = true;
    let err = match ergo_node::run_inner(cfg).await {
        Ok(_) => panic!("boot must refuse on corrupt utxo marker"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("UTXO_BOOTSTRAP_INSTALLED_V1") && msg.contains("corruption"),
        "refusal must name the marker + corruption: {msg}",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// NOTE: A boot-level integration test for the
// PartialHeaderSync refusal row is intentionally omitted here.
// Synthesizing the (Dense + best_header > 0 +
// best_full_block_height = 0) state requires advancing the
// in-memory `chain_state.best_header_height` mirror via either
// (a) the production header-sync path (which needs a working
// p2p surface in the test) or (b) a test helper that does not
// disturb the `HEADER_CHAIN_INDEX` version sentinel
// (`test_force_set_best_header_unsafe` clears it, which then
// triggers HCI backfill against an unexpected table layout).
// The pure-function refusal predicate is covered in
// `ergo-node/src/node/tests.rs::nipopow_resume_*`; the
// production refusal text is reviewed in code. Standing up the
// fuller integration test is tracked as Phase 4d work.

#[tokio::test]
async fn boot_skips_install_when_marker_armed_and_full_block_present() {
    // The healthy post-install restart shape: marker armed AND
    // best_full_block_height > 0. We can't drive a real
    // install_snapshot_state without a reconstructed-tree
    // fixture, so we simulate the persisted state by applying an
    // empty block (advances best_full_block_height) then arming
    // the marker. Boot MUST succeed, skip the install path, and
    // come up as a normal node.
    let dir = data_dir("install-skipped");
    {
        let mut store = open_store(&dir);
        apply_empty_block(&mut store, 1);
        store
            .test_force_arm_utxo_bootstrap_marker()
            .expect("arm marker");
        let cs = store.chain_state();
        assert!(cs.best_full_block_height > 0);
        assert!(store.was_utxo_bootstrapped().unwrap());
    }
    let mut cfg = common::make_test_config(dir.clone());
    cfg.utxo_bootstrap = true;
    let handle = ergo_node::run_inner(cfg)
        .await
        .expect("healthy post-install restart must boot cleanly");
    handle.shutdown().await.expect("shutdown");
    let _ = std::fs::remove_dir_all(&dir);
}

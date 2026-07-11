//! `/api/v1/identity` live-refresh integration test.
//!
//! Builds a real `StateStore`, a real `IdentitySlot`, drives the
//! `rebuild_and_publish_identity` path the action loop calls on
//! bootstrap transitions, and asserts the projection observed
//! through the slot changes when the underlying store state
//! changes (sentinel advance, persistent UTXO-bootstrap marker
//! commit).

use std::sync::Arc;

use arc_swap::ArcSwap;
use ergo_api::types::{ApiHistoryMode, ApiIdentity};
use ergo_node::node::identity::{rebuild_and_publish_identity, IdentityInputs};
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::store::StateStore;

fn open_store() -> (StateStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).expect("open store");
    store.initialize_genesis(&[]).expect("init genesis");
    (store, dir)
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

fn header_id_and_bytes(h: &Header) -> ([u8; 32], Vec<u8>) {
    let (bytes, id) = serialize_header(h).expect("serialize");
    (*id.as_bytes(), bytes)
}

fn stamp_height(store: &StateStore, height: u32) {
    let h = synth_header(height);
    let (id, bytes) = header_id_and_bytes(&h);
    store.store_header(&id, &bytes).expect("store_header");
    store
        .promote_header_to_height_index_for_test(height, &id)
        .expect("promote_header");
    for (type_byte, root) in [
        (TYPE_AD_PROOFS, h.ad_proofs_root.as_bytes()),
        (TYPE_BLOCK_TRANSACTIONS, h.transactions_root.as_bytes()),
        (TYPE_EXTENSION, h.extension_root.as_bytes()),
    ] {
        let section_id = compute_section_id(type_byte, &id, root);
        store
            .store_block_section_typed(&section_id, &[0xAA; 8], type_byte)
            .expect("section write");
    }
}

fn apply_empty_block(store: &mut StateStore, height: u32) {
    let h = synth_header(height);
    let (id, _) = header_id_and_bytes(&h);
    let expected = store.root_digest();
    store
        .apply_block_unchecked_for_test(height, &id, &expected, &[])
        .unwrap_or_else(|e| panic!("apply h={height}: {e:?}"));
}

fn archive_inputs() -> IdentityInputs {
    IdentityInputs {
        state_type: ergo_node::config::StateType::Utxo,
        verify_transactions: true,
        blocks_to_keep: -1,
        keep_versions: ergo_state::store::ROLLBACK_WINDOW,
        utxo_bootstrap: false,
        nipopow_bootstrap: false,
        mining_enabled: false,
        extra_index_enabled: false,
        declared_addr: None,
        bind_addr: None,
    }
}

fn read_slot(slot: &Arc<ArcSwap<ApiIdentity>>) -> ApiIdentity {
    (**slot.load()).clone()
}

#[test]
fn identity_slot_publishes_archive_on_fresh_boot() {
    let (store, _dir) = open_store();
    let inputs = archive_inputs();
    let slot: Arc<ArcSwap<ApiIdentity>> = Arc::new(ArcSwap::from_pointee(ApiIdentity::default()));

    rebuild_and_publish_identity(&store, &inputs, &slot).expect("refresh");

    let id = read_slot(&slot);
    assert_eq!(id.history_mode, ApiHistoryMode::Archive);
    assert!(!id.utxo_bootstrap);
    assert!(!id.nipopow_bootstrap);
    assert_eq!(id.mode, "archive · utxo");
}

#[test]
fn identity_slot_refreshes_to_post_prune_archive_after_sentinel_advance() {
    // Drive a real Mode 3 prune so the sentinel advances above
    // 1 WITHOUT setting the UTXO-bootstrap provenance marker.
    // Detection rule says: `Dense + sentinel > 1 +
    // !was_utxo_bootstrapped` → `BootstrapKind::None`, which
    // refines the label to `post-prune archive`. This proves the
    // refresh observes the sentinel change without restart.
    let (mut store, _dir) = open_store();
    let inputs = archive_inputs();
    let slot: Arc<ArcSwap<ApiIdentity>> = Arc::new(ArcSwap::from_pointee(ApiIdentity::default()));

    rebuild_and_publish_identity(&store, &inputs, &slot).expect("initial refresh");
    let pre = read_slot(&slot);
    assert_eq!(pre.history_mode, ApiHistoryMode::Archive);
    assert_eq!(pre.mode, "archive · utxo");

    // Advance the sentinel through real Mode 3 forward apply.
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    let sentinel = store.read_minimal_full_block_height().unwrap();
    assert!(sentinel > 1, "test premise: sentinel must advance");

    rebuild_and_publish_identity(&store, &inputs, &slot).expect("post-prune refresh");
    let post = read_slot(&slot);
    // history_mode stays config-driven (Scala parity).
    assert_eq!(post.history_mode, ApiHistoryMode::Archive);
    assert!(!post.utxo_bootstrap);
    assert!(!post.nipopow_bootstrap);
    // Operator-facing label refines.
    assert!(
        post.mode.contains("post-prune archive"),
        "post-prune label refinement expected, got {:?}",
        post.mode,
    );
    assert_ne!(pre.mode, post.mode, "slot must observe the label change");
}

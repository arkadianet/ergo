//! End-to-end activation parity for the Mode 3 prune sentinel.
//!
//! Walks the full path the action loop wires up:
//!   1. StateStore boots with a Mode 3 config and naturally
//!      advances the prune sentinel via real forward apply.
//!   2. The boot path mirrors the sentinel into `SyncState`
//!      (here simulated by `set_prune_sentinel`, which is what
//!      `sync_tick` calls post-apply).
//!   3. `on_inv` drops sub-sentinel section advertisements.
//!   4. `request_missing_sections` drops sub-sentinel pending
//!      blocks.
//!   5. The storage gate refuses a sub-sentinel section write
//!      even if the request gate were bypassed.
//!
//! The individual seams have unit coverage; this test pins
//! that the composition holds against a real store + real
//! coordinator.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use ergo_crypto::difficulty::DifficultyParams;
use ergo_p2p::types::{InvData, ModifierTypeId};
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::store::StateStore;
use ergo_sync::coordinator::{Action, SyncCoordinator};
use ergo_sync::executor::SyncExecutor;
use ergo_validation::context::ProtocolParams;
use tempfile::TempDir;

fn open_store() -> (StateStore, TempDir) {
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
            .expect("initial section write");
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

fn peer(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

#[test]
fn boot_mirror_to_coordinator_request_gate_storage_gate_compose_correctly() {
    let (mut store, _dir) = open_store();
    // Drive Mode 3 forward apply so the sentinel advances naturally.
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    let sentinel = store.read_minimal_full_block_height().unwrap();
    assert!(
        sentinel > 1,
        "test premise: sentinel must advance during the prune setup",
    );

    // Boot-mirror simulation: in production, `boot.rs` reads the
    // store sentinel and seeds SyncState; `sync_tick` mirrors any
    // post-apply changes. Here we set it directly on a fresh
    // coordinator, matching the same wire.
    let mut coord = SyncCoordinator::new(store.chain_state().best_full_block_height);
    coord.sync_state_mut().set_prune_sentinel(sentinel);
    assert_eq!(coord.sync_state().prune_sentinel(), sentinel);

    // Build an Inv that advertises a sub-sentinel section id (an
    // id whose parent header is below the sentinel). The
    // coordinator MUST drop it from the requested set.
    let sub_header = synth_header(sentinel - 2);
    let (sub_header_id, _) = header_id_and_bytes(&sub_header);
    let sub_section_id = compute_section_id(
        TYPE_AD_PROOFS,
        &sub_header_id,
        sub_header.ad_proofs_root.as_bytes(),
    );
    let inv = InvData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        ids: vec![sub_section_id],
    };
    let actions = coord.on_inv(peer(9030), &inv, &store, Instant::now());
    let request_actions: Vec<&Action> = actions
        .iter()
        .filter(|a| matches!(a, Action::SendToPeer { .. }))
        .collect();
    assert!(
        request_actions.is_empty(),
        "coordinator must emit no SendToPeer when every Inv id is sub-sentinel; \
         got {} action(s): {:?}",
        request_actions.len(),
        request_actions,
    );

    // Storage-side defense-in-depth: a sub-sentinel section
    // write must be refused at the store layer even if the
    // coordinator's request gate were bypassed.
    let err = store
        .store_block_section_typed(&sub_section_id, &[0xCC; 8], TYPE_AD_PROOFS)
        .expect_err("store gate must refuse sub-sentinel write");
    assert!(
        format!("{err:?}").contains("PrunedSection"),
        "expected PrunedSection from storage gate, got {err:?}",
    );

    let _ = coord;
}

#[test]
fn executor_receive_gate_drops_sub_sentinel_persist_section() {
    // Even if the request-side gate were bypassed (rogue peer
    // pushing a section we never asked for), the executor's
    // receive gate inside `handle_persist_section` must drop a
    // sub-sentinel section before it reaches the storage layer.
    // We verify by feeding a PersistSection action with a
    // sub-sentinel section id and asserting (a) the executor
    // returns no follow-up actions and (b) the section is not
    // persisted to the store.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    let sentinel = store.read_minimal_full_block_height().unwrap();
    assert!(sentinel > 1);

    let mut coord = SyncCoordinator::new(store.chain_state().best_full_block_height);
    coord.sync_state_mut().set_prune_sentinel(sentinel);
    let mut exec = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );

    let sub_header = synth_header(sentinel - 2);
    let (sub_header_id, _) = header_id_and_bytes(&sub_header);
    let sub_section_id = compute_section_id(
        TYPE_AD_PROOFS,
        &sub_header_id,
        sub_header.ad_proofs_root.as_bytes(),
    );

    let action = Action::PersistSection {
        modifier_id: sub_section_id,
        section_bytes: vec![0xDD; 8],
        section_type: TYPE_AD_PROOFS,
    };
    // The executor takes the backend enum; wrap the UTXO store for the
    // call (the underlying store is mutated in place either way).
    let mut store = ergo_state::StateBackendKind::Utxo(store);
    let follow_ups = exec.execute(action, &mut store, &mut coord, Instant::now(), None);
    assert!(
        follow_ups.is_empty(),
        "executor must drop sub-sentinel PersistSection silently (no follow-up): {:?}",
        follow_ups,
    );
    // Confirm nothing was written for that section id.
    use ergo_sync::coordinator::ChainView;
    assert!(
        !ChainView::has_block_section(&store, &sub_section_id),
        "executor must not have persisted the sub-sentinel section",
    );
}

#[test]
fn boot_mirror_does_not_block_above_sentinel_inv_requests() {
    // Counterpart to the gate-fires test: prove the same wiring
    // does NOT drop legitimate above-sentinel Inv ids. Without
    // this, a regression that always-drops would silently break
    // sync while still passing the gate-fires test.
    let (mut store, _dir) = open_store();
    store.set_blocks_to_keep(5);
    for h in 1..=10 {
        stamp_height(&store, h);
        apply_empty_block(&mut store, h);
    }
    let sentinel = store.read_minimal_full_block_height().unwrap();
    assert!(sentinel > 1);
    let chain_tip = store.chain_state().best_full_block_height;

    let mut coord = SyncCoordinator::new(chain_tip);
    coord.sync_state_mut().set_prune_sentinel(sentinel);

    // Build an Inv with a section id whose parent header is at
    // tip + 1 — an unknown future height. The request gate
    // fail-CLOSES on unknown sections, so we use an above-
    // sentinel KNOWN section id instead: stamp a header at the
    // tip (its sections are already at tip via stamp_height, so
    // they're already in the store). We need an id the chain
    // does NOT have AND whose height is >= sentinel — synth a
    // fresh header at tip+1, store its header so
    // SECTION_HEIGHT_INDEX gets populated for its sections,
    // then advertise one of those section ids.
    let new_header = synth_header(chain_tip + 1);
    let (new_id, new_bytes) = header_id_and_bytes(&new_header);
    store.store_header(&new_id, &new_bytes).unwrap();
    store
        .promote_header_to_height_index_for_test(chain_tip + 1, &new_id)
        .unwrap();
    let new_section_id = compute_section_id(
        TYPE_AD_PROOFS,
        &new_id,
        new_header.ad_proofs_root.as_bytes(),
    );
    // Confirm the section is NOT yet in the store (so the Inv
    // would normally drive a request).
    use ergo_sync::coordinator::ChainView;
    assert!(!ChainView::has_block_section(&store, &new_section_id));

    let inv = InvData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        ids: vec![new_section_id],
    };
    let actions = coord.on_inv(peer(9031), &inv, &store, Instant::now());
    let request_actions: Vec<&Action> = actions
        .iter()
        .filter(|a| matches!(a, Action::SendToPeer { .. }))
        .collect();
    assert!(
        !request_actions.is_empty(),
        "coordinator must emit a SendToPeer for an above-sentinel section Inv",
    );
}

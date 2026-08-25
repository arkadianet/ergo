//! Phase 3 coverage: `StateStore::last_applied_chain_window_10` and
//! `tip_snapshot_params`.
//!
//! Walks a 15-block synthetic chain. After applying h=15, asserts:
//! - `last_applied_chain_window_10` returns 10 entries
//! - index 0 is h=15 (tip-first), index 9 is h=6
//! - `tip_snapshot_params` returns the cached active params + validation
//!   settings unchanged across calls

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{serialize_header, Header};
use ergo_state::store::StateStore;

fn seed_genesis(store: &mut StateStore) {
    let boxes: Vec<([u8; 32], Vec<u8>)> = vec![{
        let mut id = [0u8; 32];
        id[31] = 1;
        (id, vec![0xAAu8; 32])
    }];
    store.initialize_genesis(&boxes).unwrap();
}

fn synthetic_header(height: u32, parent_id: ModifierId) -> Header {
    Header {
        version: 2,
        parent_id,
        ad_proofs_root: Digest32::from_bytes([0u8; 32]),
        transactions_root: Digest32::from_bytes([0u8; 32]),
        state_root: ADDigest::from_bytes([0u8; 33]),
        timestamp: 1_000_000 + height as u64,
        extension_root: Digest32::from_bytes([0u8; 32]),
        n_bits: 16842752, // arbitrary; not exercised by the window read
        height,
        votes: [0u8; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
            nonce: [0u8; 8],
        },
    }
}

#[test]
fn window_returns_10_tip_first_after_15_applied_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).unwrap();
    seed_genesis(&mut store);

    let mut parent_id: ModifierId = Digest32::from_bytes([0u8; 32]).into();
    for h in 1..=15u32 {
        let hdr = synthetic_header(h, parent_id);
        let (bytes, id) = serialize_header(&hdr).expect("serialize header");
        let id_bytes: [u8; 32] = *id.as_bytes();
        store.store_header(&id_bytes, &bytes).expect("store_header");
        let expected = store.root_digest();
        store
            .apply_block_unchecked_for_test(h, &id_bytes, &expected, &[])
            .expect("apply");
        parent_id = id;
    }

    let window = store.last_applied_chain_window_10().expect("window");
    assert_eq!(window.len(), 10);
    assert_eq!(window[0].height, 15, "index 0 must be tip-first");
    assert_eq!(window[9].height, 6, "index 9 must be tip - 9");
    for (i, hdr) in window.iter().enumerate() {
        assert_eq!(hdr.height, 15 - i as u32);
    }

    // Parent-chain invariant: header[i].parent_id == id(header[i+1]).
    for w in window.windows(2) {
        let (_, next_id) = serialize_header(&w[1]).unwrap();
        assert_eq!(
            *w[0].parent_id.as_bytes(),
            *next_id.as_bytes(),
            "h={} parent_id must equal h={} header_id",
            w[0].height,
            w[1].height,
        );
    }
}

#[test]
fn tip_snapshot_params_returns_cached_settings_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).unwrap();
    seed_genesis(&mut store);

    // No epoch advance: cumulative settings equal the launch defaults.
    let (params_a, settings_a) = store.tip_snapshot_params();
    let (params_b, settings_b) = store.tip_snapshot_params();
    assert_eq!(params_a, params_b, "params clone must be stable");
    assert_eq!(
        settings_a.disabled_rules(),
        settings_b.disabled_rules(),
        "validation settings clone must be stable"
    );
}

#[test]
fn window_errors_when_tip_below_10() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).unwrap();
    seed_genesis(&mut store);
    // Apply only 5 blocks.
    let mut parent_id: ModifierId = Digest32::from_bytes([0u8; 32]).into();
    for h in 1..=5u32 {
        let hdr = synthetic_header(h, parent_id);
        let (bytes, id) = serialize_header(&hdr).unwrap();
        let id_bytes: [u8; 32] = *id.as_bytes();
        store.store_header(&id_bytes, &bytes).unwrap();
        let expected = store.root_digest();
        store
            .apply_block_unchecked_for_test(h, &id_bytes, &expected, &[])
            .unwrap();
        parent_id = id;
    }
    let err = store
        .last_applied_chain_window_10()
        .expect_err("must error");
    match err {
        ergo_state::store::StateError::EarlyIBD {
            needed_min,
            observed,
        } => {
            assert_eq!(needed_min, 10);
            assert_eq!(observed, 5);
        }
        other => panic!("expected EarlyIBD, got {other:?}"),
    }
}

use ergo_primitives::reader::VlqReader;
use ergo_primitives::{
    digest::{blake2b256, ADDigest, Digest32, ModifierId},
    group_element::GroupElement,
    writer::VlqWriter,
};
use ergo_ser::{
    autolykos::AutolykosSolution,
    header::{read_header, write_header, Header},
};
use ergo_state::{chain::HeaderMeta, store::StateStore};
use ergo_sync::header_proc::{process_header, HeaderProcessError};

fn full_chain(store: &mut StateStore, tip: u32) {
    let mut parent = [0; 32];
    for height in 1..=tip {
        let header = Header {
            version: 2,
            parent_id: ModifierId::from_bytes(parent),
            ad_proofs_root: Digest32::ZERO,
            transactions_root: Digest32::ZERO,
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 1_700_000_000 + u64::from(height),
            extension_root: Digest32::ZERO,
            n_bits: 0,
            height,
            votes: [0; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0; 33]),
                nonce: [0; 8],
            },
        };
        let mut w = VlqWriter::new();
        write_header(&mut w, &header).unwrap();
        let raw = w.result();
        let id = *blake2b256(&raw).as_bytes();
        let root = store.root_digest();
        store
            .apply_block_unchecked_for_test(height, &id, &root, &[])
            .unwrap();
        store.store_header(&id, &raw).unwrap();
        parent = id;
    }
}

fn mainnet_header(height: u32) -> Vec<u8> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/headers_1_10.json"
    ))
    .unwrap();
    hex::decode(
        rows.iter().find(|h| h["height"] == height).unwrap()["bytes"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

fn seed_parent(store: &mut StateStore) {
    let raw = mainnet_header(1);
    let id = *blake2b256(&raw).as_bytes();
    let h = read_header(&mut VlqReader::new(&raw)).unwrap();
    store
        .store_validated_header(
            &id,
            &raw,
            &HeaderMeta {
                parent_id: [0; 32],
                height: 1,
                cumulative_score: ergo_ser::difficulty::decode_compact_bits(h.n_bits).to_bytes_be(),
                pow_validity: 1,
                timestamp: h.timestamp,
            },
            None,
        )
        .unwrap();
}

#[test]
fn header_age_boundary_rejects_before_persistence() {
    for (tip, window, accepted) in [
        (200, 200, true),
        (201, 200, false),
        (201, 201, true),
        (51, 50, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        store.set_rollback_window(window);
        full_chain(&mut store, tip);
        seed_parent(&mut store);
        let raw = mainnet_header(2);
        let id = *blake2b256(&raw).as_bytes();
        let result = process_header(&mut store, &raw);
        if accepted {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert!(matches!(result, Err(HeaderProcessError::TooOld { .. })));
        }
        assert_eq!(store.get_header(&id).unwrap().is_some(), accepted);
    }
}

#[test]
fn old_genesis_is_rejected_and_header_sync_uses_full_height() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    store.initialize_genesis(&[]).unwrap();
    full_chain(&mut store, 200);
    assert!(matches!(
        process_header(&mut store, &mainnet_header(1)),
        Err(HeaderProcessError::TooOld {
            parent_height: 0,
            ..
        })
    ));
    let dir = tempfile::tempdir().unwrap();
    let mut syncing = StateStore::open(&dir.path().join("state.redb")).unwrap();
    syncing.initialize_genesis(&[]).unwrap();
    seed_parent(&mut syncing);
    syncing
        .test_force_set_best_header_unsafe([9; 32], 10000, vec![255])
        .unwrap();
    assert!(process_header(&mut syncing, &mainnet_header(2)).is_ok());
}

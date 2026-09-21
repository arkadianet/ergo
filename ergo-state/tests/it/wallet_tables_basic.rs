//! Basic table read/write integration test for the wallet
//! persistence layer. Uses a `tempfile::tempdir` for the redb file.

use ergo_state::wallet::tables::*;
use ergo_state::wallet::types::{BoxProvenance, BoxStatus, WalletBox};
use redb::{Database, ReadableTable};

#[test]
fn wallet_boxes_round_trip_through_redb() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = Database::create(&db_path).unwrap();

    let wb = WalletBox {
        box_id: [0xAA; 32],
        creation_tx_id: [0xBB; 32],
        creation_output_index: 0,
        creation_height: 100,
        value: 1_000_000_000,
        assets: vec![],
        status: BoxStatus::Confirmed,
        provenance: BoxProvenance::Owned,
    };

    // Write.
    let txn = db.begin_write().unwrap();
    {
        let mut tbl = txn.open_table(WALLET_BOXES).unwrap();
        let bytes = bincode::serialize(&wb).unwrap();
        tbl.insert(wb.box_id, bytes).unwrap();
    }
    txn.commit().unwrap();

    // Read.
    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    let raw = tbl.get(wb.box_id).unwrap().expect("box must be present");
    let restored: WalletBox = bincode::deserialize(raw.value().as_slice()).unwrap();
    assert_eq!(restored.box_id, wb.box_id);
    assert_eq!(restored.value, wb.value);
    assert!(matches!(restored.status, BoxStatus::Confirmed));
}

#[test]
fn tracked_pubkeys_iterate_in_derivation_order() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = Database::create(&db_path).unwrap();

    let pk_a = [0xAA; 33];
    let pk_b = [0xBB; 33];
    let pk_c = [0xCC; 33];

    let txn = db.begin_write().unwrap();
    {
        let mut tbl = txn.open_table(WALLET_TRACKED_PUBKEYS).unwrap();
        let meta_a = ergo_state::wallet::types::TrackedPubkeyMeta {
            derivation_path: vec![],
            derivation_path_label: String::new(),
            added_at_height: 0,
        };
        let meta_b = ergo_state::wallet::types::TrackedPubkeyMeta {
            derivation_path: vec![44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 0],
            derivation_path_label: String::new(),
            added_at_height: 0,
        };
        let meta_c = ergo_state::wallet::types::TrackedPubkeyMeta {
            derivation_path: vec![44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 1],
            derivation_path_label: String::from("test"),
            added_at_height: 10,
        };
        let serialize =
            |m: &ergo_state::wallet::types::TrackedPubkeyMeta| bincode::serialize(m).unwrap();
        // Insert OUT of order.
        tbl.insert(tracked_pubkey_key(2, &pk_c), serialize(&meta_c))
            .unwrap();
        tbl.insert(tracked_pubkey_key(0, &pk_a), serialize(&meta_a))
            .unwrap();
        tbl.insert(tracked_pubkey_key(1, &pk_b), serialize(&meta_b))
            .unwrap();
    }
    txn.commit().unwrap();

    // Iterate — should be sorted by derivation_path_index ASC.
    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_TRACKED_PUBKEYS).unwrap();
    let mut got = Vec::new();
    for entry in tbl.iter().unwrap() {
        let (k, _) = entry.unwrap();
        let k_bytes: [u8; 41] = k.value();
        got.push(parse_tracked_pubkey_key(&k_bytes));
    }
    assert_eq!(got, vec![(0, pk_a), (1, pk_b), (2, pk_c)]);
}

#[test]
fn tracked_pubkeys_with_paths_returns_derivation_components() {
    let dir = tempfile::tempdir().unwrap();
    let db = redb::Database::create(dir.path().join("test.redb")).unwrap();

    let pk = [0xAAu8; 33];
    let path_components: Vec<u32> = vec![44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 0];
    let meta = ergo_state::wallet::types::TrackedPubkeyMeta {
        derivation_path: path_components.clone(),
        derivation_path_label: String::new(),
        added_at_height: 0,
    };

    let txn = db.begin_write().unwrap();
    {
        let mut tbl = txn.open_table(WALLET_TRACKED_PUBKEYS).unwrap();
        let bytes = bincode::serialize(&meta).unwrap();
        tbl.insert(tracked_pubkey_key(0, &pk), bytes).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let reader = ergo_state::wallet::reader::WalletReader::new(&txn);
    let entries = reader.tracked_pubkeys_with_paths().unwrap();
    assert_eq!(entries.len(), 1);
    let (idx, returned_pk, returned_path) = &entries[0];
    assert_eq!(*idx, 0);
    assert_eq!(*returned_pk, pk);
    assert_eq!(*returned_path, path_components);
}

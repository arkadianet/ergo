use super::*;
use crate::store::StateStore;
use ergo_primitives::{digest::ModifierId, reader::VlqReader};
use ergo_ser::{
    ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate},
    register::AdditionalRegisters,
};
use std::sync::Arc;

const PK: &str = "0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f";
type BoxRows = Vec<([u8; 32], Vec<u8>)>;

fn box_fixture(index: u16, reward: bool, owned: bool) -> ([u8; 32], Vec<u8>) {
    let tree_bytes = if reward {
        hex::decode(format!("100204a00b08cd{PK}ea02d192a39a8cc7a70173007301")).unwrap()
    } else if owned {
        hex::decode(format!("0008cd{PK}")).unwrap()
    } else {
        hex::decode("0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
    };
    let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&tree_bytes)).unwrap();
    let candidate =
        ErgoBoxCandidate::new(1_000_000, tree, 1, vec![], AdditionalRegisters::empty()).unwrap();
    let b = ErgoBox::new(candidate, ModifierId::from_bytes([0x44; 32]), index);
    (
        *b.box_id().unwrap().as_bytes(),
        serialize_ergo_box(&b).unwrap(),
    )
}

fn fixture(count: u16) -> (tempfile::TempDir, Arc<Database>, BoxRows) {
    fixture_at(count, 1000)
}

fn fixture_at(count: u16, height: u32) -> (tempfile::TempDir, Arc<Database>, BoxRows) {
    let dir = tempfile::tempdir().unwrap();
    let mut boxes: Vec<_> = (0..count).map(|i| box_fixture(i, i == 0, i != 1)).collect();
    boxes.sort_by_key(|b| b.0);
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    store.initialize_genesis(&boxes).unwrap();
    let db = store.db_arc();
    drop(store);
    if height > 0 {
        crate::maintenance::test_set_tip(&db, height);
    }
    let txn = db.begin_write().unwrap();
    let pk: [u8; 33] = hex::decode(PK).unwrap().try_into().unwrap();
    let meta = super::super::types::TrackedPubkeyMeta {
        derivation_path: vec![],
        derivation_path_label: String::new(),
        added_at_height: 0,
    };
    txn.open_table(WALLET_TRACKED_PUBKEYS)
        .unwrap()
        .insert(
            tracked_pubkey_key(0, &pk),
            bincode::serialize(&meta).unwrap(),
        )
        .unwrap();
    txn.commit().unwrap();
    (dir, db, boxes)
}

fn seed_checkpoint(db: &Database, prefix: &[([u8; 32], Vec<u8>)]) {
    let snapshot = db.begin_read().unwrap();
    let mut job = Job {
        version: 1,
        tip: inspect_tip(&snapshot).unwrap(),
        pubkeys: vec![PK.to_string()],
        last_key: prefix.last().map(|v| v.0),
        visited: prefix.len() as u64,
        matched: 0,
    };
    let mut pending = Vec::new();
    for (id, bytes) in prefix {
        let b = ergo_ser::ergo_box::read_ergo_box(&mut VlqReader::new(bytes)).unwrap();
        if b.index != 1 {
            job.matched += 1;
            pending.push((*id, bytes.clone()));
        }
    }
    checkpoint(db, &job, &mut pending).unwrap();
}

#[test]
fn discovers_pruned_holdings_without_fabricating_history() {
    let (_dir, db, boxes) = fixture(5);
    let result = discover(&db, false).unwrap();
    assert_eq!(result.matched_boxes, 4);
    assert!(!result.history_complete);
    let txn = db.begin_read().unwrap();
    let reader = super::super::reader::WalletReader::new(&txn);
    assert!(reader.all_transactions().unwrap().is_empty());
    assert_eq!(reader.scan_height().unwrap(), Some(1000));
    for wb in reader.all_boxes().unwrap() {
        assert_eq!(wb.creation_height, 1000);
        assert!(!inclusion_height_known(&txn, wb.box_id).unwrap());
        assert!(matches!(wb.status, BoxStatus::Confirmed));
        let stored = txn
            .open_table(WALLET_BOX_BYTES)
            .unwrap()
            .get(wb.box_id)
            .unwrap()
            .unwrap()
            .value();
        assert_eq!(&stored, &boxes.iter().find(|v| v.0 == wb.box_id).unwrap().1);
    }
}

#[test]
fn durable_checkpoint_resumes_after_database_reopen() {
    let (dir, db, boxes) = fixture(40);
    seed_checkpoint(&db, &boxes[..17]);
    assert!(
        super::super::reader::WalletReader::new(&db.begin_read().unwrap())
            .all_boxes()
            .unwrap()
            .is_empty()
    );
    drop(db);
    let db = Database::open(dir.path().join("state.redb")).unwrap();
    assert_eq!(discover(&db, false).unwrap().matched_boxes, 39);
    assert!(db
        .begin_read()
        .unwrap()
        .open_table(JOB)
        .unwrap()
        .get(())
        .unwrap()
        .is_none());
}

#[test]
fn changed_tip_and_corrupt_checkpoint_do_not_replace_visible_wallet() {
    let (_dir, db, boxes) = fixture(8);
    discover(&db, false).unwrap();
    let before = super::super::reader::WalletReader::new(&db.begin_read().unwrap())
        .balance()
        .unwrap()
        .confirmed_nano_ergs;
    seed_checkpoint(&db, &boxes[..4]);
    crate::maintenance::test_set_tip(&db, 1001);
    assert!(discover(&db, false)
        .unwrap_err()
        .to_string()
        .contains("checkpoint tip"));
    assert_eq!(
        super::super::reader::WalletReader::new(&db.begin_read().unwrap())
            .balance()
            .unwrap()
            .confirmed_nano_ergs,
        before
    );
    assert_eq!(discover(&db, true).unwrap().anchor_height, 1001);
    seed_checkpoint(&db, &boxes[..4]);
    let txn = db.begin_write().unwrap();
    {
        let mut staged = txn.open_table(STAGING).unwrap();
        let first = staged.iter().unwrap().next().unwrap().unwrap().0.value();
        staged.insert(first, vec![0xff]).unwrap();
    }
    txn.commit().unwrap();
    assert!(discover(&db, false)
        .unwrap_err()
        .to_string()
        .contains("staged holdings"));
    assert_eq!(
        super::super::reader::WalletReader::new(&db.begin_read().unwrap())
            .balance()
            .unwrap()
            .confirmed_nano_ergs,
        before
    );
}

#[test]
fn reward_maturity_and_anchor_invalidation_are_correct_on_rollback() {
    let (_dir, db, _) = fixture(4);
    discover(&db, false).unwrap();
    let txn = db.begin_write().unwrap();
    assert_eq!(
        super::super::maturity::unpromote_matured_boxes(&txn, 1000).unwrap(),
        0
    );
    invalidate_below_anchor(&txn, 1001).unwrap();
    assert!(!super::super::apply::is_scan_invalidated(&txn).unwrap());
    invalidate_below_anchor(&txn, 1000).unwrap();
    assert!(super::super::apply::is_scan_invalidated(&txn).unwrap());
    txn.commit().unwrap();
}

#[test]
fn unsupported_partial_rescan_leaves_discovered_wallet_valid() {
    let (_dir, db, _) = fixture(4);
    discover(&db, false).unwrap();
    let result = super::super::scan::WalletScanService::rescan_full_rebuild(
        &db,
        BTreeSet::new(),
        Default::default(),
        10,
        1000,
        |_| panic!("preflight must not read history"),
        || Ok(1000),
        || false,
        None,
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("full historical rebuild"));
    assert!(!db
        .begin_read()
        .unwrap()
        .open_table(WALLET_SCAN_INVALIDATED)
        .unwrap()
        .get(())
        .unwrap()
        .unwrap()
        .value());
    assert!(coverage(&db.begin_read().unwrap()).unwrap().is_some());
}

#[test]
fn custom_scan_table_errors_fail_before_wallet_changes() {
    let (_dir, db, _) = fixture(4);
    let txn = db.begin_write().unwrap();
    txn.open_table(TableDefinition::<u16, u32>::new("wallet_scans"))
        .unwrap()
        .insert(11, 5)
        .unwrap();
    txn.commit().unwrap();
    assert!(discover(&db, false).is_err());
    assert!(coverage(&db.begin_read().unwrap()).unwrap().is_none());
    assert!(
        super::super::reader::WalletReader::new(&db.begin_read().unwrap())
            .all_boxes()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn discovery_survives_wallet_migration_at_genesis_and_sparse_snapshot_tip() {
    let (_dir, db, _) = fixture_at(4, 0);
    discover(&db, false).unwrap();
    super::super::migrate_schema(&db).unwrap();
    assert!(!db
        .begin_read()
        .unwrap()
        .open_table(WALLET_SCAN_INVALIDATED)
        .unwrap()
        .get(())
        .unwrap()
        .unwrap()
        .value());
    assert_eq!(
        super::super::reader::WalletReader::new(&db.begin_read().unwrap())
            .scan_height()
            .unwrap(),
        Some(0)
    );

    let (_dir, db, _) = fixture(4);
    let txn = db.begin_write().unwrap();
    txn.delete_table(crate::store::CHAIN_INDEX).unwrap();
    txn.commit().unwrap();
    discover(&db, false).unwrap();
    super::super::migrate_schema(&db).unwrap();
    let txn = db.begin_read().unwrap();
    assert!(!txn
        .open_table(WALLET_SCAN_INVALIDATED)
        .unwrap()
        .get(())
        .unwrap()
        .unwrap()
        .value());
    assert_eq!(
        super::super::reader::WalletReader::new(&txn)
            .scan_height()
            .unwrap(),
        Some(1000)
    );
    assert!(matches!(
        txn.open_table(crate::store::CHAIN_INDEX),
        Err(redb::TableError::TableDoesNotExist(_))
    ));
}

#[test]
fn sparse_snapshot_discovery_anchor_mismatch_invalidates_on_migration() {
    let (_dir, db, _) = fixture(4);
    let txn = db.begin_write().unwrap();
    txn.delete_table(crate::store::CHAIN_INDEX).unwrap();
    txn.commit().unwrap();
    discover(&db, false).unwrap();
    let mut meta = coverage(&db.begin_read().unwrap()).unwrap().unwrap();
    meta.anchor_header_id = "ff".repeat(32);
    let txn = db.begin_write().unwrap();
    txn.open_table(WALLET_UTXO_DISCOVERY)
        .unwrap()
        .insert((), serde_json::to_vec(&meta).unwrap())
        .unwrap();
    txn.commit().unwrap();
    super::super::migrate_schema(&db).unwrap();
    assert!(db
        .begin_read()
        .unwrap()
        .open_table(WALLET_SCAN_INVALIDATED)
        .unwrap()
        .get(())
        .unwrap()
        .unwrap()
        .value());
}

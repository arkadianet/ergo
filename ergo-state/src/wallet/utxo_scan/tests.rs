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
    let txn = crate::begin_write_qr(&db).unwrap();
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
fn discovers_current_holdings_without_fabricating_history() {
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
    let txn = crate::begin_write_qr(&db).unwrap();
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
    let txn = crate::begin_write_qr(&db).unwrap();
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
fn registered_custom_scans_fail_before_wallet_changes() {
    let (_dir, db, _) = fixture(4);
    let txn = crate::begin_write_qr(&db).unwrap();
    txn.open_table(WALLET_SCANS)
        .unwrap()
        .insert(11, vec![5])
        .unwrap();
    txn.commit().unwrap();
    assert!(
        matches!(discover(&db, false), Err(StateError::WalletDiscoveryUnavailable(reason)) if reason.contains("registered custom scans"))
    );
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
    let txn = crate::begin_write_qr(&db).unwrap();
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
    let txn = crate::begin_write_qr(&db).unwrap();
    txn.delete_table(crate::store::CHAIN_INDEX).unwrap();
    txn.commit().unwrap();
    discover(&db, false).unwrap();
    let mut meta = coverage(&db.begin_read().unwrap()).unwrap().unwrap();
    meta.anchor_header_id = "ff".repeat(32);
    let txn = crate::begin_write_qr(&db).unwrap();
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

#[test]
fn discovery_preconditions_have_operator_errors() {
    let (_dir, db, _) = fixture(4);
    let txn = crate::begin_write_qr(&db).unwrap();
    txn.open_table(WALLET_TRACKED_PUBKEYS)
        .unwrap()
        .retain(|_, _| false)
        .unwrap();
    txn.commit().unwrap();
    assert!(matches!(
        discover(&db, false),
        Err(StateError::WalletDiscoveryUnavailable(_))
    ));

    let (_dir, db, boxes) = fixture(4);
    seed_checkpoint(&db, &boxes[..2]);
    crate::maintenance::test_set_tip(&db, 1001);
    assert!(matches!(
        discover(&db, false),
        Err(StateError::WalletDiscoveryRestartRequired(_))
    ));

    let (_dir, db, _) = fixture_at(4, 0);
    let txn = crate::begin_write_qr(&db).unwrap();
    txn.open_table(crate::store::STATE_META)
        .unwrap()
        .remove("root")
        .unwrap();
    txn.commit().unwrap();
    assert!(matches!(
        discover(&db, false),
        Err(StateError::WalletDiscoveryUnavailable(_))
    ));
}

#[test]
fn wrong_custom_scan_table_type_fails_before_wallet_changes() {
    let (_dir, db, _) = fixture(4);
    let txn = crate::begin_write_qr(&db).unwrap();
    txn.open_table(TableDefinition::<u16, u32>::new("wallet_scans"))
        .unwrap()
        .insert(11, 5)
        .unwrap();
    txn.commit().unwrap();
    assert!(matches!(
        discover(&db, false),
        Err(StateError::TableError(_))
    ));
    assert!(coverage(&db.begin_read().unwrap()).unwrap().is_none());
}

#[test]
fn discovered_immature_rewards_promote_and_unpromote_using_script_height() {
    let (_dir, db, _) = fixture_at(4, 720);
    discover(&db, false).unwrap();
    let reward = super::super::reader::WalletReader::new(&db.begin_read().unwrap())
        .all_boxes()
        .unwrap()
        .into_iter()
        .find(|b| matches!(b.provenance, BoxProvenance::MinerReward))
        .unwrap();
    assert_eq!(reward.status, BoxStatus::Immature { matures_at: 721 });
    let txn = crate::begin_write_qr(&db).unwrap();
    assert_eq!(
        super::super::maturity::promote_matured_boxes(&txn, 721).unwrap(),
        1
    );
    assert_eq!(
        super::super::maturity::unpromote_matured_boxes(&txn, 720).unwrap(),
        1
    );
    txn.commit().unwrap();
    assert_eq!(
        super::super::reader::WalletReader::new(&db.begin_read().unwrap())
            .box_by_id(&reward.box_id)
            .unwrap()
            .unwrap()
            .status,
        BoxStatus::Immature { matures_at: 721 }
    );
}

#[test]
fn wallet_rollback_below_discovery_anchor_invalidates_atomically() {
    use super::super::store::WalletStore;
    let (_dir, db, _) = fixture(4);
    discover(&db, false).unwrap();
    let store = super::super::store::RedbWalletStore::new(db.clone());
    let mut txn = store.begin_write().unwrap();
    txn.rollback_block(999, &[], false).unwrap();
    assert!(!store.begin_read().unwrap().scan_invalidated().unwrap());
    txn.commit().unwrap();
    assert!(store.begin_read().unwrap().scan_invalidated().unwrap());
}

#[test]
fn corrupt_discovery_metadata_invalidates_wallet_without_aborting_rollback() {
    use super::super::store::WalletStore;
    let (_dir, db, _) = fixture(4);
    discover(&db, false).unwrap();
    let txn = crate::begin_write_qr(&db).unwrap();
    txn.open_table(WALLET_UTXO_DISCOVERY)
        .unwrap()
        .insert((), b"broken JSON".to_vec())
        .unwrap();
    txn.commit().unwrap();
    let store = super::super::store::RedbWalletStore::new(db.clone());
    let mut txn = store.begin_write().unwrap();
    txn.rollback_block(1001, &[], false).unwrap();
    txn.commit().unwrap();
    assert!(store.begin_read().unwrap().scan_invalidated().unwrap());
}

#[test]
fn discovery_persists_key_coverage_and_flags_new_keys_until_rediscovery() {
    use super::super::store::WalletStore;
    let (dir, db, _) = fixture(4);
    let result = discover(&db, false).unwrap();
    assert_eq!(result.covered_pubkeys, vec![PK.to_string()]);
    assert!(
        !requires_discovery(&redb::ReadableDatabase::begin_read(db.as_ref()).unwrap()).unwrap()
    );
    let new_pk: [u8; 33] =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap();
    let txn = crate::begin_write_qr(&db).unwrap();
    txn.open_table(WALLET_TRACKED_PUBKEYS)
        .unwrap()
        .insert(
            tracked_pubkey_key(1, &new_pk),
            bincode::serialize(&super::super::types::TrackedPubkeyMeta {
                derivation_path: vec![1],
                derivation_path_label: "new".into(),
                added_at_height: 1000,
            })
            .unwrap(),
        )
        .unwrap();
    txn.commit().unwrap();
    let store = super::super::store::RedbWalletStore::new(db.clone());
    assert!(store.begin_read().unwrap().scan_invalidated().unwrap());
    drop(store);
    drop(db);
    let db = Database::open(dir.path().join("state.redb")).unwrap();
    let read = redb::ReadableDatabase::begin_read(&db).unwrap();
    let meta = coverage(&read).unwrap().unwrap();
    assert_eq!(meta.covered_pubkeys, vec![PK.to_string()]);
    assert_eq!(
        uncovered_pubkeys(&read, &meta).unwrap(),
        vec![hex::encode(new_pk)]
    );
    drop(read);
    assert_eq!(discover(&db, false).unwrap().matched_boxes, 4);
    assert!(!requires_discovery(&redb::ReadableDatabase::begin_read(&db).unwrap()).unwrap());
}

#[test]
fn pending_wallet_jobs_refuse_discovery_without_erasing_history() {
    use super::super::mining_jobs::JOURNAL;
    let (_dir, db, _) = fixture(4);
    discover(&db, false).unwrap();
    let wt = super::super::types::WalletTransaction {
        tx_id: [0x55; 32],
        block_id: [0x66; 32],
        block_height: 900,
        wallet_inputs: vec![],
        wallet_outputs: vec![],
    };
    let txn = crate::begin_write_qr(&db).unwrap();
    txn.open_table(WALLET_TXS)
        .unwrap()
        .insert(
            wallet_tx_key(900, &wt.tx_id),
            bincode::serialize(&wt).unwrap(),
        )
        .unwrap();
    txn.commit().unwrap();
    let before = bincode::serialize(
        &super::super::reader::WalletReader::new(&db.begin_read().unwrap())
            .all_boxes()
            .unwrap(),
    )
    .unwrap();
    for state in [
        "waiting",
        "waitingForWallet",
        "preparing",
        "prepared",
        "queued",
        "inCandidate",
    ] {
        let bytes = serde_json::to_vec(&serde_json::json!({"job": {"state": state}})).unwrap();
        let txn = crate::begin_write_qr(&db).unwrap();
        txn.open_table(JOURNAL)
            .unwrap()
            .insert(1, bytes.as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert!(
            matches!(discover(&db, true), Err(StateError::WalletDiscoveryUnavailable(reason)) if reason.contains("non-terminal"))
        );
        let read = db.begin_read().unwrap();
        let reader = super::super::reader::WalletReader::new(&read);
        assert_eq!(
            bincode::serialize(&reader.all_boxes().unwrap()).unwrap(),
            before
        );
        assert_eq!(reader.all_transactions().unwrap().len(), 1);
        assert_eq!(
            read.open_table(JOURNAL)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            bytes
        );
    }
    let bytes = br#"{"job":{"state":"cancelled"}}"#;
    let txn = crate::begin_write_qr(&db).unwrap();
    txn.open_table(JOURNAL)
        .unwrap()
        .insert(1, bytes.as_slice())
        .unwrap();
    txn.commit().unwrap();
    discover(&db, true).unwrap();
    assert_eq!(
        db.begin_read()
            .unwrap()
            .open_table(JOURNAL)
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap()
            .value(),
        bytes
    );
}

fn external_wallet() -> (tempfile::TempDir, Database) {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("wallet.redb")).unwrap();
    let txn = crate::begin_write_qr(&db).unwrap();
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
    (dir, db)
}

#[test]
fn external_discovery_writes_only_the_wallet_target_and_preserves_honest_coverage() {
    let (source_dir, source, _) = fixture(5);
    let source_path = source_dir.path().join("state.redb");
    drop(source);
    let before = std::fs::read(&source_path).unwrap();
    let source = redb::ReadOnlyDatabase::open(&source_path).unwrap();
    let (_target_dir, target) = external_wallet();
    let snapshot = source.begin_read().unwrap();
    let result = discover_into(&snapshot, &target, false).unwrap();
    assert_eq!(result.matched_boxes, 4);
    assert!(!result.history_complete);
    assert!(coverage(&snapshot).unwrap().is_none());
    assert!(super::super::reader::WalletReader::new(&snapshot)
        .all_boxes()
        .unwrap()
        .is_empty());
    drop(snapshot);
    drop(source);
    assert!(
        std::fs::read(&source_path).unwrap() == before,
        "external discovery modified the source database"
    );
    let target_snapshot = target.begin_read().unwrap();
    let reader = super::super::reader::WalletReader::new(&target_snapshot);
    assert_eq!(reader.all_boxes().unwrap().len(), 4);
    assert!(reader.all_transactions().unwrap().is_empty());
    assert_eq!(coverage(&target_snapshot).unwrap(), Some(result));
    for wallet_box in reader.all_boxes().unwrap() {
        assert!(!inclusion_height_known(&target_snapshot, wallet_box.box_id).unwrap());
    }
}

#[test]
fn external_discovery_checkpoint_uses_source_anchor_and_target_keys() {
    let (_source_dir, source, boxes) = fixture(40);
    let (_target_dir, target) = external_wallet();
    let snapshot = source.begin_read().unwrap();
    let mut job = Job {
        version: 1,
        tip: inspect_tip(&snapshot).unwrap(),
        pubkeys: vec![PK.into()],
        last_key: Some(boxes[16].0),
        visited: 17,
        matched: 0,
    };
    let mut pending = Vec::new();
    for (id, bytes) in &boxes[..17] {
        let b = ergo_ser::ergo_box::read_ergo_box(&mut VlqReader::new(bytes)).unwrap();
        if b.index != 1 {
            job.matched += 1;
            pending.push((*id, bytes.clone()));
        }
    }
    checkpoint(&target, &job, &mut pending).unwrap();
    assert_eq!(
        discover_into(&snapshot, &target, false)
            .unwrap()
            .matched_boxes,
        39
    );
    // A stale source anchor cannot reuse the external target's checkpoint.
    checkpoint(&target, &job, &mut pending).unwrap();
    drop(snapshot);
    crate::maintenance::test_set_tip(&source, 1001);
    let snapshot = source.begin_read().unwrap();
    assert!(discover_into(&snapshot, &target, false)
        .unwrap_err()
        .to_string()
        .contains("checkpoint tip"));
    assert_eq!(
        discover_into(&snapshot, &target, true)
            .unwrap()
            .anchor_height,
        1001
    );
}

#[test]
fn external_discovery_refuses_pending_jobs_before_mutating_target() {
    use ergo_wallet_service::wallet::mining_jobs::JOURNAL;
    use redb::TableHandle;

    let (_source_dir, source, _) = fixture(5);
    let (_target_dir, target) = external_wallet();
    let txn = crate::begin_write_qr(&target).unwrap();
    txn.open_table(JOURNAL)
        .unwrap()
        .insert(1, r#"{"job":{"state":"queued"}}"#.as_bytes())
        .unwrap();
    txn.commit().unwrap();
    // Snapshot every target table and its exact rows. Opening or closing a
    // writable redb database can change physical allocator metadata, and its
    // live file cannot be read directly on Windows.
    let target_contents = || {
        let read = target.begin_read().unwrap();
        let mut tables: Vec<_> = read
            .list_tables()
            .unwrap()
            .map(|handle| handle.name().to_owned())
            .collect();
        tables.sort();
        let mut expected = vec![
            JOURNAL.name().to_owned(),
            WALLET_TRACKED_PUBKEYS.name().to_owned(),
        ];
        expected.sort();
        assert_eq!(tables, expected);
        assert!(read.list_multimap_tables().unwrap().next().is_none());
        let pubkeys: Vec<_> = read
            .open_table(WALLET_TRACKED_PUBKEYS)
            .unwrap()
            .iter()
            .unwrap()
            .map(|row| {
                let (key, value) = row.unwrap();
                (key.value(), value.value().to_vec())
            })
            .collect();
        let jobs: Vec<_> = read
            .open_table(JOURNAL)
            .unwrap()
            .iter()
            .unwrap()
            .map(|row| {
                let (key, value) = row.unwrap();
                (key.value(), value.value().to_vec())
            })
            .collect();
        (tables, pubkeys, jobs)
    };
    let before = target_contents();
    let snapshot = source.begin_read().unwrap();
    assert!(discover_into(&snapshot, &target, false)
        .unwrap_err()
        .to_string()
        .contains("non-terminal wallet mining jobs"));
    assert_eq!(target_contents(), before);
}

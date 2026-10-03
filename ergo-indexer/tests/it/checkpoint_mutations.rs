//! Public storage transitions compare their checkpoint inside the writer.
//! Synthetic blocks exercise derived storage, not consensus acceptance.

use ergo_indexer::{
    apply_block, rollback_one_block, IndexerBlock, IndexerError, IndexerMeta, IndexerStore,
};
use ergo_primitives::{digest::Digest32, reader::VlqReader};
use ergo_ser::{
    ergo_box::ErgoBoxCandidate, ergo_tree::read_ergo_tree, register::AdditionalRegisters,
    transaction::Transaction,
};
use redb::{ReadableDatabase, TableDefinition};
use std::sync::{Arc, Barrier};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("indexer_meta");

fn transactions() -> Vec<Transaction> {
    let bytes = hex::decode("1000d10101").unwrap();
    let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
    vec![Transaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate::new(
            1000,
            tree,
            1,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()],
    }]
}

fn block(transactions: &[Transaction], height: i32, header: u8) -> IndexerBlock<'_> {
    IndexerBlock {
        height,
        header_id: Digest32::from_bytes([header; 32]),
        transactions,
    }
}

#[test]
fn competing_public_writers_commit_one_complete_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = IndexerStore::open(&dir.path().join("indexer.redb")).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let transactions = transactions();
                barrier.wait();
                apply_block(&store, &IndexerMeta::empty(), &block(&transactions, 1, 1))
            })
        })
        .collect();
    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, Err(IndexerError::StaleCheckpoint)))
            .count(),
        1
    );
    let meta = store.read_meta().unwrap();
    assert_eq!(
        (
            meta.indexed_height,
            meta.global_tx_index,
            meta.global_box_index
        ),
        (1, 1, 1)
    );
    let id = store.read_numeric_box(0).unwrap().unwrap();
    assert_eq!(
        store
            .read_box(&id)
            .unwrap()
            .unwrap()
            .box_data
            .candidate
            .value,
        1000
    );
    assert!(store.read_numeric_box(1).unwrap().is_none());
}

#[test]
fn every_stale_checkpoint_field_refuses_apply_and_rollback_without_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = IndexerStore::open(&dir.path().join("indexer.redb")).unwrap();
    let transactions = transactions();
    let current = apply_block(&store, &IndexerMeta::empty(), &block(&transactions, 1, 1)).unwrap();
    for field in 0..4 {
        let mut stale = current.clone();
        match field {
            0 => stale.indexed_height += 1,
            1 => stale.indexed_header_id = Some(Digest32::from_bytes([2; 32])),
            2 => stale.global_tx_index += 1,
            _ => stale.global_box_index += 1,
        }
        let apply = block(&transactions, (stale.indexed_height + 1) as i32, 3);
        assert!(matches!(
            apply_block(&store, &stale, &apply),
            Err(IndexerError::StaleCheckpoint)
        ));
        let rollback = IndexerBlock {
            height: stale.indexed_height as i32,
            header_id: stale.indexed_header_id.unwrap(),
            transactions: &transactions,
        };
        assert!(matches!(
            rollback_one_block(&store, &stale, &rollback),
            Err(IndexerError::StaleCheckpoint)
        ));
        assert_eq!(store.read_meta().unwrap(), current);
        assert!(store.read_undo(1).unwrap().is_some());
        assert!(store.read_numeric_box(0).unwrap().is_some());
        assert!(store.read_numeric_box(1).unwrap().is_none());
    }
    assert_eq!(
        rollback_one_block(&store, &current, &block(&transactions, 1, 1)).unwrap(),
        IndexerMeta::empty()
    );
}

fn edit_meta(path: &std::path::Path, edit: impl FnOnce(&mut redb::Table<&str, &[u8]>)) {
    let db = redb::Database::open(path).unwrap();
    let write = db.begin_write().unwrap();
    {
        let mut table = write.open_table(META).unwrap();
        edit(&mut table);
    }
    write.commit().unwrap();
}

#[test]
fn initialized_store_refuses_each_missing_checkpoint_field_and_preserves_rows() {
    for key in [
        "indexed_height",
        "indexed_header_id",
        "global_tx_index",
        "global_box_index",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("indexer.redb");
        let (store, _) = IndexerStore::open(&path).unwrap();
        drop(store);
        edit_meta(&path, |table| {
            table.remove(key).unwrap();
        });
        assert!(
            matches!(IndexerStore::open(&path), Err(IndexerError::MetadataMissing {key: missing}) if missing == key)
        );
        let db = redb::Database::open(&path).unwrap();
        let read = db.begin_read().unwrap();
        let table = read.open_table(META).unwrap();
        assert!(table.get(key).unwrap().is_none());
        assert!(table.get("schema_version").unwrap().is_some());
    }
}

#[test]
fn initialized_store_refuses_inconsistent_height_header_and_counter_rows() {
    for (key, bytes) in [
        ("indexed_height", 1u64.to_be_bytes().to_vec()),
        ("indexed_header_id", vec![1; 32]),
        ("global_box_index", 1u64.to_be_bytes().to_vec()),
        ("global_tx_index", u64::MAX.to_be_bytes().to_vec()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("indexer.redb");
        let (store, _) = IndexerStore::open(&path).unwrap();
        drop(store);
        edit_meta(&path, |table| {
            table.insert(key, bytes.as_slice()).unwrap();
        });
        assert!(matches!(
            IndexerStore::open(&path),
            Err(IndexerError::MetadataInvalid)
        ));
    }
}

#[test]
fn durable_repair_checkpoint_excludes_public_block_mutation_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();
    let transactions = transactions();
    let current = apply_block(&store, &IndexerMeta::empty(), &block(&transactions, 1, 1)).unwrap();
    drop(store);
    edit_meta(&path, |table| {
        table
            .insert("secondary_repair_pending", &[1u8][..])
            .unwrap();
        table
            .insert("secondary_repair_next_gi", 0u64.to_be_bytes().as_slice())
            .unwrap();
    });
    let (store, _) = IndexerStore::open(&path).unwrap();
    assert!(matches!(
        apply_block(&store, &current, &block(&[], 2, 2)),
        Err(IndexerError::RepairInProgress)
    ));
    assert!(matches!(
        rollback_one_block(&store, &current, &block(&transactions, 1, 1)),
        Err(IndexerError::RepairInProgress)
    ));
    assert_eq!(store.read_meta().unwrap(), current);
    assert_eq!(store.secondary_repair_next_gi().unwrap(), Some(0));
    assert!(store.secondary_repair_pending().unwrap());
    assert!(store.read_undo(1).unwrap().is_some());
}

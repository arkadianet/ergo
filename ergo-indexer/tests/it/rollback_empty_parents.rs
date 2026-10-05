//! Parent deletion and preservation across rollback, checked against raw rows.

use ergo_indexer::{apply_block, rollback_one_block, IndexerBlock, IndexerMeta, IndexerStore};
use ergo_primitives::{digest::Digest32, reader::VlqReader};
use ergo_ser::{
    ergo_box::{ErgoBox, ErgoBoxCandidate},
    ergo_tree::read_ergo_tree,
    input::{ContextExtension, Input, SpendingProof},
    register::AdditionalRegisters,
    transaction::{transaction_id, Transaction},
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use tempfile::TempDir;

type RawRows = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Debug, PartialEq, Eq)]
struct ParentTables {
    addresses: RawRows,
    templates: RawRows,
}

// Close and reopen the store to read the actual persisted bytes without
// exposing new production APIs just for these integration tests.
fn parent_tables(store: IndexerStore) -> (IndexerStore, ParentTables) {
    let path = store.path().to_owned();
    drop(store);
    let snapshot = {
        let db = redb::Database::open(&path).unwrap();
        let read = db.begin_read().unwrap();
        let rows = |name| {
            let table = read
                .open_table(TableDefinition::<&[u8], &[u8]>::new(name))
                .unwrap();
            table
                .iter()
                .unwrap()
                .map(|row| {
                    let (key, value) = row.unwrap();
                    (key.value().to_vec(), value.value().to_vec())
                })
                .collect()
        };
        ParentTables {
            addresses: rows("indexed_address"),
            templates: rows("indexed_template"),
        }
    };
    (IndexerStore::open(&path).unwrap().0, snapshot)
}

fn open_store() -> (IndexerStore, TempDir) {
    let tmp = TempDir::new().unwrap();
    let store = IndexerStore::open(&tmp.path().join("indexer.redb"))
        .unwrap()
        .0;
    (store, tmp)
}

fn candidate(value: u64, height: u32, tree_byte: u8) -> ErgoBoxCandidate {
    // SigmaProp-rooted true (d3) / false (d2) have distinct addresses
    // and distinct templates, both parseable by the template index.
    let tree = read_ergo_tree(&mut VlqReader::new(&[0x00, 0x08, tree_byte])).unwrap();
    ErgoBoxCandidate::new(value, tree, height, vec![], AdditionalRegisters::empty()).unwrap()
}

fn transaction(parent: Option<&Transaction>, outputs: Vec<ErgoBoxCandidate>) -> Transaction {
    let inputs = parent
        .map(|tx| {
            let sealed = ErgoBox {
                candidate: tx.output_candidates[0].clone(),
                transaction_id: transaction_id(tx).unwrap(),
                index: 0,
            };
            vec![Input {
                box_id: sealed.box_id().unwrap(),
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }]
        })
        .unwrap_or_default();
    Transaction {
        inputs,
        data_inputs: vec![],
        output_candidates: outputs,
    }
}

fn block(tx: &Transaction, height: i32) -> IndexerBlock<'_> {
    IndexerBlock {
        height,
        header_id: Digest32::from_bytes([height as u8; 32]),
        transactions: std::slice::from_ref(tx),
    }
}

#[test]
fn rollback_removes_new_address_and_template() {
    let (store, _tmp) = open_store();
    let (store, before) = parent_tables(store);
    assert!(before.addresses.is_empty());
    assert!(before.templates.is_empty());
    let tx = transaction(None, vec![candidate(1_000_000, 1, 0xd3)]);
    let meta = apply_block(&store, &IndexerMeta::empty(), &block(&tx, 1)).unwrap();
    let (store, applied) = parent_tables(store);
    assert_eq!(applied.addresses.len(), 1);
    assert_eq!(applied.templates.len(), 1);

    rollback_one_block(&store, &meta, &block(&tx, 1)).unwrap();
    let (_store, after) = parent_tables(store);
    assert_eq!(after, before);
}

#[test]
fn rollback_preserves_earlier_address_and_template_bytes() {
    let (store, _tmp) = open_store();
    let first = transaction(None, vec![candidate(1_000_000, 1, 0xd3)]);
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block(&first, 1)).unwrap();
    let (store, before) = parent_tables(store);
    let later = transaction(
        Some(&first),
        vec![candidate(800_000, 2, 0xd3), candidate(100_000, 2, 0xd2)],
    );
    let meta2 = apply_block(&store, &meta1, &block(&later, 2)).unwrap();
    let (store, applied) = parent_tables(store);
    assert_eq!(applied.addresses.len(), 2);
    assert_eq!(applied.templates.len(), 2);
    let old_key = &before.addresses[0].0;
    let changed_address = applied
        .addresses
        .iter()
        .find(|(key, _)| key == old_key)
        .unwrap();
    assert_ne!(changed_address.1, before.addresses[0].1);

    assert_eq!(
        rollback_one_block(&store, &meta2, &block(&later, 2)).unwrap(),
        meta1
    );
    // This checks both restored historical parents and absence of the
    // parents introduced only in the later block.
    let (_store, after) = parent_tables(store);
    assert_eq!(after, before);
}

#[test]
fn two_block_reorg_keeps_parent_until_its_last_history_is_removed() {
    let (store, _tmp) = open_store();
    let genesis = transaction(None, vec![candidate(1_000_000, 1, 0xd2)]);
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block(&genesis, 1)).unwrap();
    let (store, before_fork) = parent_tables(store);
    let first = transaction(Some(&genesis), vec![candidate(900_000, 2, 0xd3)]);
    let meta2 = apply_block(&store, &meta1, &block(&first, 2)).unwrap();
    let (store, after_first) = parent_tables(store);
    assert_eq!(after_first.addresses.len(), 2);
    assert_eq!(after_first.templates.len(), 2);
    let second = transaction(Some(&first), vec![candidate(800_000, 3, 0xd3)]);
    let meta3 = apply_block(&store, &meta2, &block(&second, 3)).unwrap();

    assert_eq!(
        rollback_one_block(&store, &meta3, &block(&second, 3)).unwrap(),
        meta2
    );
    let (store, after_one_rollback) = parent_tables(store);
    assert_eq!(after_one_rollback, after_first);
    assert_eq!(
        rollback_one_block(&store, &meta2, &block(&first, 2)).unwrap(),
        meta1
    );
    let (_store, after_two_rollbacks) = parent_tables(store);
    assert_eq!(after_two_rollbacks, before_fork);
}

#[test]
fn reapply_address_and_template_tables_match_single_apply_bytes() {
    let (store, _tmp) = open_store();
    let (store, empty) = parent_tables(store);
    let tx = transaction(
        None,
        vec![candidate(800_000, 1, 0xd3), candidate(100_000, 1, 0xd2)],
    );
    let meta = apply_block(&store, &IndexerMeta::empty(), &block(&tx, 1)).unwrap();
    let (store, single_apply) = parent_tables(store);
    let rolled_back = rollback_one_block(&store, &meta, &block(&tx, 1)).unwrap();
    let (store, after_rollback) = parent_tables(store);
    assert_eq!(after_rollback, empty);
    assert_eq!(
        apply_block(&store, &rolled_back, &block(&tx, 1)).unwrap(),
        meta
    );
    let (_store, reapplied) = parent_tables(store);
    assert_eq!(reapplied, single_apply);
}

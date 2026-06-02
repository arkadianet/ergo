//! Wipe/resume table coverage, meta round-trip, undo serde, and the
//! `ROLLBACK_WINDOW = 200` prune rule.

use ergo_indexer::store::{
    IndexerMeta, IndexerStore, OpenOutcome, UndoEntry, INDEXER_SCHEMA_VERSION, ROLLBACK_WINDOW,
};
use ergo_indexer::IndexerError;
use ergo_primitives::digest::Digest32;
use redb::{Database, TableDefinition};
use tempfile::tempdir;

const INDEXER_META: TableDefinition<&str, &[u8]> = TableDefinition::new("indexer_meta");

fn header_id(seed: u8) -> Digest32 {
    Digest32::from_bytes([seed; 32])
}

// ----- happy path -----

#[test]
fn open_fresh_creates_empty_meta_and_schema_version() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    let (store, outcome) = IndexerStore::open(&path).expect("fresh open");
    assert_eq!(outcome, OpenOutcome::CreatedFresh);

    let meta = store.read_meta().unwrap();
    assert_eq!(meta, IndexerMeta::empty());
    assert_eq!(meta.indexed_height, 0);
    assert!(meta.indexed_header_id.is_none());
    assert_eq!(meta.global_tx_index, 0);
    assert_eq!(meta.global_box_index, 0);
}

#[test]
fn open_resumes_when_schema_matches() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    {
        let (_, outcome) = IndexerStore::open(&path).unwrap();
        assert_eq!(outcome, OpenOutcome::CreatedFresh);
    }
    let (_, outcome) = IndexerStore::open(&path).unwrap();
    assert_eq!(outcome, OpenOutcome::Resumed);
}

#[test]
fn open_wipes_when_schema_version_mismatches() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");

    {
        let (_, _) = IndexerStore::open(&path).unwrap();
    }
    // Forcibly stomp schema_version with a future value to simulate a
    // schema bump.
    {
        let db = Database::open(&path).unwrap();
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        {
            let mut t = txn.open_table(INDEXER_META).unwrap();
            let v = 9999u32.to_be_bytes();
            t.insert("schema_version", v.as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }
    let (_, outcome) = IndexerStore::open(&path).unwrap();
    assert_eq!(
        outcome,
        OpenOutcome::WipedAndRecreated {
            previous_version: 9999
        }
    );
    // After wipe, meta is empty again.
    let (store, _) = IndexerStore::open(&path).unwrap();
    assert_eq!(store.read_meta().unwrap(), IndexerMeta::empty());
}

#[test]
fn open_halts_when_schema_version_key_missing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");

    // Create a redb file with INDEXER_META table but no schema_version
    // key — this is the "populated DB without schema_version" case the
    // open path classifies as `SchemaCorruption`.
    {
        let db = Database::create(&path).unwrap();
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        let _ = txn.open_table(INDEXER_META).unwrap();
        txn.commit().unwrap();
    }

    let err = IndexerStore::open(&path).expect_err("should halt");
    assert!(
        matches!(err, IndexerError::SchemaCorruption),
        "expected SchemaCorruption, got {err:?}"
    );
}

#[test]
fn open_rejects_malformed_schema_version_with_db_row_length() {
    // Malformed `schema_version` bytes surface as the specific
    // `DbRowLength { context: "schema_version" }` so operators can
    // distinguish "table missing" from "table present but corrupt".
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");

    {
        let db = Database::create(&path).unwrap();
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        {
            let mut t = txn.open_table(INDEXER_META).unwrap();
            // Real schema_version is 4 bytes (u32 BE). Write 3 bytes
            // to trigger the length mismatch.
            t.insert("schema_version", [0xAB, 0xCD, 0xEF].as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
    }

    let err = IndexerStore::open(&path).expect_err("malformed schema_version must halt");
    assert!(
        matches!(
            err,
            IndexerError::DbRowLength {
                context: "schema_version",
                expected: 4,
                got: 3,
            }
        ),
        "expected DbRowLength{{schema_version, expected:4, got:3}}, got {err:?}",
    );
}

#[test]
fn meta_roundtrip_through_apply_helper() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();

    let meta = IndexerMeta {
        indexed_height: 42,
        indexed_header_id: Some(header_id(0xAB)),
        global_tx_index: 17,
        global_box_index: 99,
    };
    let undo = UndoEntry {
        prev_indexed_header_id: Some(header_id(0xCD)),
        prev_global_tx_index: 16,
        prev_global_box_index: 98,
    };
    store.commit_apply_meta_only(&meta, 42, &undo).unwrap();

    let read_back = store.read_meta().unwrap();
    assert_eq!(read_back, meta);

    let entry = store.read_undo(42).unwrap().unwrap();
    assert_eq!(entry, undo);
}

#[test]
fn undo_entry_genesis_roundtrip_no_prev_header() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();

    let meta = IndexerMeta {
        indexed_height: 1,
        indexed_header_id: Some(header_id(0xFF)),
        global_tx_index: 1,
        global_box_index: 1,
    };
    let undo = UndoEntry {
        prev_indexed_header_id: None,
        prev_global_tx_index: 0,
        prev_global_box_index: 0,
    };
    store.commit_apply_meta_only(&meta, 1, &undo).unwrap();

    let read_back = store.read_undo(1).unwrap().unwrap();
    assert_eq!(read_back, undo);
    assert!(read_back.prev_indexed_header_id.is_none());
}

#[test]
fn rollback_window_prune_keeps_exactly_201_entries() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();

    // Apply heights 1..=300, each writing an undo entry. After height
    // 300, retained undo heights should be exactly [100..=300] (201
    // entries), with [1..100] pruned (strictly less than
    // current_height - ROLLBACK_WINDOW).
    for h in 1u64..=300 {
        let meta = IndexerMeta {
            indexed_height: h,
            indexed_header_id: Some(header_id((h % 251 + 1) as u8)),
            global_tx_index: h,
            global_box_index: h,
        };
        let undo = UndoEntry {
            prev_indexed_header_id: if h == 1 {
                None
            } else {
                Some(header_id(((h - 1) % 251 + 1) as u8))
            },
            prev_global_tx_index: h - 1,
            prev_global_box_index: h - 1,
        };
        store.commit_apply_meta_only(&meta, h, &undo).unwrap();
    }

    // Heights below 100 must be pruned.
    for h in 1u64..100 {
        assert!(
            store.read_undo(h).unwrap().is_none(),
            "expected undo[{h}] pruned"
        );
    }
    // Heights 100..=300 must be retained — 201 entries.
    for h in 100u64..=300 {
        assert!(
            store.read_undo(h).unwrap().is_some(),
            "expected undo[{h}] retained"
        );
    }
}

#[test]
fn no_pruning_below_rollback_window() {
    // current_height <= ROLLBACK_WINDOW → nothing pruned.
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();

    for h in 1u64..=ROLLBACK_WINDOW {
        let meta = IndexerMeta {
            indexed_height: h,
            indexed_header_id: Some(header_id(1)),
            global_tx_index: h,
            global_box_index: h,
        };
        let undo = UndoEntry {
            prev_indexed_header_id: if h == 1 { None } else { Some(header_id(1)) },
            prev_global_tx_index: h - 1,
            prev_global_box_index: h - 1,
        };
        store.commit_apply_meta_only(&meta, h, &undo).unwrap();
    }

    for h in 1u64..=ROLLBACK_WINDOW {
        assert!(store.read_undo(h).unwrap().is_some());
    }
}

#[test]
fn rollback_meta_helper_removes_undo_entry() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();

    let meta_h2 = IndexerMeta {
        indexed_height: 2,
        indexed_header_id: Some(header_id(0x22)),
        global_tx_index: 4,
        global_box_index: 8,
    };
    let undo_h2 = UndoEntry {
        prev_indexed_header_id: Some(header_id(0x11)),
        prev_global_tx_index: 2,
        prev_global_box_index: 4,
    };
    store.commit_apply_meta_only(&meta_h2, 2, &undo_h2).unwrap();

    // Roll back: meta returns to (height 1, prev header), undo[2] removed.
    let meta_h1 = IndexerMeta {
        indexed_height: 1,
        indexed_header_id: undo_h2.prev_indexed_header_id,
        global_tx_index: undo_h2.prev_global_tx_index,
        global_box_index: undo_h2.prev_global_box_index,
    };
    store.commit_rollback_meta_only(&meta_h1, 2).unwrap();

    assert_eq!(store.read_meta().unwrap(), meta_h1);
    assert!(store.read_undo(2).unwrap().is_none());
}

#[test]
fn schema_version_constant_is_two() {
    // Bumped from 1 to 2 alongside the storage-rent eligibility index
    // (spec `2026-05-01-storage-rent-eligibility.md` slice 1). Bump
    // again whenever the on-disk format changes so this canary forces
    // a deliberate test update rather than a silent migration.
    assert_eq!(INDEXER_SCHEMA_VERSION, 2);
}

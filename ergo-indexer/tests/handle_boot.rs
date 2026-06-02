//! `IndexerHandle::boot` covers the mounting contract — `None` when
//! disabled, `Some(syncing)` on successful boot, and
//! `Some(halted(DbCorruption|SchemaCorruption))` on the halt-naming
//! rows of the open path.

use std::fs;

use ergo_indexer::store::{IndexerStore, UndoEntry};
use ergo_indexer::{
    IndexerConfig, IndexerHaltReason, IndexerHandle, IndexerMeta, IndexerQuery, IndexerStatus,
};
use ergo_primitives::digest::Digest32;
use redb::{Database, TableDefinition};
use tempfile::tempdir;

const INDEXER_META: TableDefinition<&str, &[u8]> = TableDefinition::new("indexer_meta");

fn cfg(enabled: bool) -> IndexerConfig {
    IndexerConfig {
        enabled,
        ..IndexerConfig::default()
    }
}

// ----- happy path -----

#[test]
fn boot_disabled_returns_none() {
    let dir = tempdir().unwrap();
    assert!(IndexerHandle::boot(&cfg(false), dir.path()).is_none());
}

#[test]
fn boot_enabled_fresh_returns_syncing_with_height_0() {
    let dir = tempdir().unwrap();
    let h = IndexerHandle::boot(&cfg(true), dir.path()).expect("Some on enabled");
    assert_eq!(h.status(), IndexerStatus::Syncing);
    assert_eq!(h.indexed_height(), 0);
    assert!(h.store().is_some());
    // The DB file was created.
    assert!(dir.path().join("indexer.redb").exists());
}

#[test]
fn boot_enabled_resumes_persisted_height() {
    let dir = tempdir().unwrap();
    // First boot creates the DB; mutate meta to height=42 directly.
    {
        let _ = IndexerHandle::boot(&cfg(true), dir.path()).unwrap();
    }
    {
        let path = dir.path().join("indexer.redb");
        let (store, _) = IndexerStore::open(&path).unwrap();
        let meta = IndexerMeta {
            indexed_height: 42,
            indexed_header_id: Some(Digest32::from_bytes([0xAA; 32])),
            global_tx_index: 100,
            global_box_index: 250,
        };
        let undo = UndoEntry {
            prev_indexed_header_id: Some(Digest32::from_bytes([0xBB; 32])),
            prev_global_tx_index: 99,
            prev_global_box_index: 249,
        };
        store.commit_apply_meta_only(&meta, 42, &undo).unwrap();
    }

    let h = IndexerHandle::boot(&cfg(true), dir.path()).expect("Some on enabled");
    assert_eq!(h.status(), IndexerStatus::Syncing);
    assert_eq!(h.indexed_height(), 42);
}

#[test]
fn boot_with_garbage_db_file_halts_db_corruption() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    fs::write(&path, b"this is not a redb file, just garbage").unwrap();

    let h = IndexerHandle::boot(&cfg(true), dir.path()).expect("Some on enabled");
    assert_eq!(
        h.status(),
        IndexerStatus::Halted(IndexerHaltReason::DbCorruption)
    );
    assert!(h.store().is_none(), "halted handle holds no store");
    assert_eq!(h.indexed_height(), 0);
}

#[test]
fn boot_with_missing_schema_version_key_halts_schema_corruption() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    {
        let db = Database::create(&path).unwrap();
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        // Open but don't write the key.
        let _ = txn.open_table(INDEXER_META).unwrap();
        txn.commit().unwrap();
    }

    let h = IndexerHandle::boot(&cfg(true), dir.path()).expect("Some on enabled");
    assert_eq!(
        h.status(),
        IndexerStatus::Halted(IndexerHaltReason::SchemaCorruption)
    );
    assert!(h.store().is_none());
}

#[test]
fn boot_with_missing_meta_table_halts_db_corruption() {
    // META table absent (nothing ever opened it) — DbCorruption from
    // the "table missing on resume" branch.
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    {
        let db = Database::create(&path).unwrap();
        let txn = ergo_state::begin_write_qr(&db).unwrap();
        // No INDEXER_META table opened. Commit empty txn.
        txn.commit().unwrap();
    }

    let h = IndexerHandle::boot(&cfg(true), dir.path()).expect("Some on enabled");
    assert_eq!(
        h.status(),
        IndexerStatus::Halted(IndexerHaltReason::DbCorruption)
    );
}

#[test]
fn schema_version_mismatch_wipes_and_returns_syncing() {
    // Schema bump path: previous v=99 differs from code's v=1. The
    // wipe/resume table row 3 deletes the file and recreates fresh.
    // Boot must therefore return Syncing, not halted.
    let dir = tempdir().unwrap();
    let path = dir.path().join("indexer.redb");
    {
        let _ = IndexerStore::open(&path).unwrap();
    }
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

    let h = IndexerHandle::boot(&cfg(true), dir.path()).expect("Some on enabled");
    assert_eq!(h.status(), IndexerStatus::Syncing);
    assert_eq!(h.indexed_height(), 0, "wipe resets height to 0");
    assert!(h.store().is_some());
}

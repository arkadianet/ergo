//! Persistent UTXO key-value store backed by RocksDB.
//!
//! Keys are 32-byte box IDs, values are serialized box bytes.
//! A single metadata entry (key = `[0x00]`) stores the current AVL digest
//! (33 bytes) and version block ID (32 bytes).

use std::path::Path;
use std::sync::Arc;

use rocksdb::{IteratorMode, WriteBatch};

use crate::node_db::NodeDb;

// ---------------------------------------------------------------------------
// Metadata key
// ---------------------------------------------------------------------------

/// The single-byte key used to store UTXO metadata (digest + version).
const METADATA_KEY: &[u8] = &[0x00];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during UTXO DB operations.
#[derive(Debug, thiserror::Error)]
pub enum UtxoDbError {
    #[error("RocksDB error: {0}")]
    Rocks(#[from] rocksdb::Error),

    #[error("invalid metadata")]
    InvalidMetadata,

    #[error("storage error: {0}")]
    Storage(String),
}

// ---------------------------------------------------------------------------
// UtxoMetadata
// ---------------------------------------------------------------------------

/// Metadata stored alongside UTXO entries: the AVL digest and version block ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoMetadata {
    /// 33-byte AVL tree digest.
    pub digest: [u8; 33],
    /// 32-byte version (block ID whose state this reflects).
    pub version: [u8; 32],
}

impl UtxoMetadata {
    /// Total byte length of a serialized metadata entry.
    const SERIALIZED_LEN: usize = 33 + 32; // 65

    /// Serialize to 65 bytes: digest (33) ++ version (32).
    fn to_bytes(&self) -> [u8; Self::SERIALIZED_LEN] {
        let mut buf = [0u8; Self::SERIALIZED_LEN];
        buf[..33].copy_from_slice(&self.digest);
        buf[33..].copy_from_slice(&self.version);
        buf
    }

    /// Deserialize from exactly 65 bytes.
    fn from_bytes(data: &[u8]) -> Result<Self, UtxoDbError> {
        if data.len() != Self::SERIALIZED_LEN {
            return Err(UtxoDbError::InvalidMetadata);
        }
        let mut digest = [0u8; 33];
        digest.copy_from_slice(&data[..33]);
        let mut version = [0u8; 32];
        version.copy_from_slice(&data[33..]);
        Ok(Self { digest, version })
    }
}

// ---------------------------------------------------------------------------
// UtxoDb
// ---------------------------------------------------------------------------

/// RocksDB-backed persistent UTXO store.
///
/// Stores the same key-value pairs as the in-memory AVL tree:
/// - Regular entries: key = 32-byte box_id, value = serialized box bytes.
/// - Metadata entry: key = `[0x00]` (1 byte), value = 33-byte digest + 32-byte version.
///
/// Used for state recovery on restart and snapshot creation via iteration.
pub struct UtxoDb {
    db: Arc<NodeDb>,
}

impl UtxoDb {
    /// Opens (or creates) a UTXO RocksDB database at `path`.
    ///
    /// Creates a standalone `NodeDb` — suitable for tests and legacy callers.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, UtxoDbError> {
        NodeDb::open(path)
            .map(|db| Self { db: Arc::new(db) })
            .map_err(|e| match e {
                crate::history_db::StorageError::Rocks(r) => UtxoDbError::Rocks(r),
                crate::history_db::StorageError::Codec(s) => UtxoDbError::Storage(s),
            })
    }

    /// Wraps a shared `NodeDb`. Used in production to share a single DB instance.
    pub fn from_shared(db: Arc<NodeDb>) -> Self {
        Self { db }
    }

    /// Atomically applies a batch of inserts, removals, and metadata update.
    ///
    /// - `to_insert`: pairs of (32-byte box_id, serialized box bytes) to add.
    /// - `to_remove`: 32-byte box_ids to delete.
    /// - `metadata`: the new UTXO metadata (digest + version) to store.
    pub fn apply_changes(
        &self,
        to_insert: &[([u8; 32], Vec<u8>)],
        to_remove: &[[u8; 32]],
        metadata: &UtxoMetadata,
    ) -> Result<(), UtxoDbError> {
        let mut batch = WriteBatch::default();

        for (key, value) in to_insert {
            batch.put_cf(&self.db.cf_utxo(), key, value);
        }
        for key in to_remove {
            batch.delete_cf(&self.db.cf_utxo(), key);
        }
        batch.put_cf(&self.db.cf_utxo(), METADATA_KEY, metadata.to_bytes());

        self.db.raw().write(batch)?;
        Ok(())
    }

    /// Returns the current metadata, or `None` if the DB has never been written to.
    pub fn metadata(&self) -> Result<Option<UtxoMetadata>, UtxoDbError> {
        match self.db.raw().get_cf(&self.db.cf_utxo(), METADATA_KEY)? {
            Some(data) => Ok(Some(UtxoMetadata::from_bytes(&data)?)),
            None => Ok(None),
        }
    }

    /// Iterates over all UTXO entries, skipping the metadata key.
    ///
    /// Keys whose length is not 32 bytes are skipped (the metadata key is 1 byte).
    pub fn iter_entries(&self) -> impl Iterator<Item = ([u8; 32], Vec<u8>)> + '_ {
        self.db
            .raw()
            .iterator_cf(&self.db.cf_utxo(), IteratorMode::Start)
            .filter_map(|item| {
                let (key, value) = item.ok()?;
                if key.len() != 32 {
                    return None;
                }
                let mut box_id = [0u8; 32];
                box_id.copy_from_slice(&key);
                Some((box_id, value.to_vec()))
            })
    }

    /// Returns the number of UTXO entries (excluding metadata).
    pub fn entry_count(&self) -> usize {
        self.iter_entries().count()
    }

    /// Looks up a single UTXO entry by its 32-byte box ID.
    pub fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, UtxoDbError> {
        Ok(self.db.raw().get_cf(&self.db.cf_utxo(), key)?)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_test_db() -> (UtxoDb, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = UtxoDb::open(dir.path()).unwrap();
        (db, dir)
    }

    fn test_metadata(fill_digest: u8, fill_version: u8) -> UtxoMetadata {
        UtxoMetadata {
            digest: [fill_digest; 33],
            version: [fill_version; 32],
        }
    }

    fn test_box_id(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    #[test]
    fn empty_db_has_no_metadata() {
        let (db, _dir) = open_test_db();
        assert!(db.metadata().unwrap().is_none());
    }

    #[test]
    fn apply_changes_stores_entries_and_metadata() {
        let (db, _dir) = open_test_db();

        let id1 = test_box_id(0xAA);
        let id2 = test_box_id(0xBB);
        let meta = test_metadata(0x11, 0x22);

        db.apply_changes(
            &[
                (id1, b"box-bytes-1".to_vec()),
                (id2, b"box-bytes-2".to_vec()),
            ],
            &[],
            &meta,
        )
        .unwrap();

        // Verify entries.
        assert_eq!(db.get(&id1).unwrap().unwrap(), b"box-bytes-1");
        assert_eq!(db.get(&id2).unwrap().unwrap(), b"box-bytes-2");

        // Verify metadata.
        let got_meta = db.metadata().unwrap().unwrap();
        assert_eq!(got_meta, meta);
    }

    #[test]
    fn apply_changes_removes_entries() {
        let (db, _dir) = open_test_db();

        let id1 = test_box_id(0xAA);
        let id2 = test_box_id(0xBB);
        let meta1 = test_metadata(0x11, 0x22);

        // Insert two entries.
        db.apply_changes(
            &[(id1, b"box-1".to_vec()), (id2, b"box-2".to_vec())],
            &[],
            &meta1,
        )
        .unwrap();
        assert_eq!(db.entry_count(), 2);

        // Remove one entry.
        let meta2 = test_metadata(0x33, 0x44);
        db.apply_changes(&[], &[id1], &meta2).unwrap();

        assert!(db.get(&id1).unwrap().is_none());
        assert_eq!(db.get(&id2).unwrap().unwrap(), b"box-2");
        assert_eq!(db.entry_count(), 1);

        // Metadata should be updated.
        assert_eq!(db.metadata().unwrap().unwrap(), meta2);
    }

    #[test]
    fn iter_entries_returns_only_utxo_entries() {
        let (db, _dir) = open_test_db();

        let id1 = test_box_id(0xAA);
        let id2 = test_box_id(0xBB);
        let meta = test_metadata(0x11, 0x22);

        db.apply_changes(
            &[(id1, b"box-1".to_vec()), (id2, b"box-2".to_vec())],
            &[],
            &meta,
        )
        .unwrap();

        let entries: Vec<_> = db.iter_entries().collect();
        assert_eq!(entries.len(), 2);

        // Verify no entry has the metadata key (length 1).
        for (key, _) in &entries {
            assert_eq!(key.len(), 32);
        }

        // Both box IDs should be present.
        let ids: Vec<[u8; 32]> = entries.iter().map(|(k, _)| *k).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn entry_count_excludes_metadata() {
        let (db, _dir) = open_test_db();

        // Empty DB — no entries.
        assert_eq!(db.entry_count(), 0);

        // Apply metadata only (no UTXO inserts).
        let meta = test_metadata(0x01, 0x02);
        db.apply_changes(&[], &[], &meta).unwrap();
        assert_eq!(db.entry_count(), 0);

        // Add one UTXO entry.
        let id = test_box_id(0xCC);
        let meta2 = test_metadata(0x03, 0x04);
        db.apply_changes(&[(id, b"box-data".to_vec())], &[], &meta2)
            .unwrap();
        assert_eq!(db.entry_count(), 1);
    }

    #[test]
    fn get_returns_stored_value() {
        let (db, _dir) = open_test_db();

        let id = test_box_id(0xDD);
        let meta = test_metadata(0x55, 0x66);
        db.apply_changes(&[(id, b"the-box-data".to_vec())], &[], &meta)
            .unwrap();

        let val = db.get(&id).unwrap();
        assert_eq!(val.as_deref(), Some(b"the-box-data".as_slice()));

        // Non-existent key returns None.
        let missing = test_box_id(0xEE);
        assert!(db.get(&missing).unwrap().is_none());
    }

    #[test]
    fn from_shared_shares_data() {
        use crate::node_db::NodeDb;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let node_db = Arc::new(NodeDb::open(tmp.path()).unwrap());
        let db1 = UtxoDb::from_shared(node_db.clone());
        let db2 = UtxoDb::from_shared(node_db.clone());

        let id = [0xAAu8; 32];
        let meta = UtxoMetadata {
            digest: [0x11; 33],
            version: [0x22; 32],
        };
        db1.apply_changes(&[(id, b"box-data".to_vec())], &[], &meta)
            .unwrap();

        // db2 sees the write immediately.
        assert!(db2.get(&id).unwrap().is_some());
        assert_eq!(db2.metadata().unwrap().unwrap(), meta);
    }
}

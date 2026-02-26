use std::path::Path;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use rocksdb::{Options, WriteBatch, DB};

use ergo_types::modifier_id::ModifierId;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during extra-indexer storage operations.
#[derive(Debug, thiserror::Error)]
pub enum IndexerDbError {
    #[error("RocksDB error: {0}")]
    Rocks(#[from] rocksdb::Error),

    #[error("Codec error: {0}")]
    Codec(String),
}

// ---------------------------------------------------------------------------
// blake2b256 helper
// ---------------------------------------------------------------------------

fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).unwrap();
    out
}

// ---------------------------------------------------------------------------
// Key generators
// ---------------------------------------------------------------------------

/// Key for the indexed-height progress counter.
pub fn indexed_height_key() -> [u8; 32] {
    blake2b256(b"indexed height")
}

/// Key for the global transaction index counter.
pub fn global_tx_index_key() -> [u8; 32] {
    blake2b256(b"txns height")
}

/// Key for the global box index counter.
pub fn global_box_index_key() -> [u8; 32] {
    blake2b256(b"boxes height")
}

/// Key for the schema version tag.
pub fn schema_version_key() -> [u8; 32] {
    blake2b256(b"schema version")
}

/// Key for the n-th transaction in the global numbering.
pub fn numeric_tx_key(n: u64) -> [u8; 32] {
    blake2b256(format!("txns height {n}").as_bytes())
}

/// Key for the n-th box in the global numbering.
pub fn numeric_box_key(n: u64) -> [u8; 32] {
    blake2b256(format!("boxes height {n}").as_bytes())
}

/// Key for a token entry, derived from the token ID.
pub fn token_key(token_id: &ModifierId) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 5);
    buf.extend_from_slice(&token_id.0);
    buf.extend_from_slice(b"token");
    blake2b256(&buf)
}

/// Key for an ErgoTree hash lookup.
pub fn tree_hash_key(ergo_tree_bytes: &[u8]) -> [u8; 32] {
    blake2b256(ergo_tree_bytes)
}

/// Key for an ErgoTree template hash lookup.
pub fn template_hash_key(template_bytes: &[u8]) -> [u8; 32] {
    blake2b256(template_bytes)
}

/// Key for a box-index segment under a parent (e.g. an ErgoTree hash).
pub fn box_segment_key(parent_id: &[u8; 32], n: u32) -> [u8; 32] {
    let parent_hex = hex::encode(parent_id);
    blake2b256(format!("{parent_hex} box segment {n}").as_bytes())
}

/// Key for a tx-index segment under a parent.
pub fn tx_segment_key(parent_id: &[u8; 32], n: u32) -> [u8; 32] {
    let parent_hex = hex::encode(parent_id);
    blake2b256(format!("{parent_hex} tx segment {n}").as_bytes())
}

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Current schema version for the extra-indexer store.
pub const SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// ExtraIndexerDb
// ---------------------------------------------------------------------------

/// Thin RocksDB wrapper for the extra-indexer store (`history/extra/`).
///
/// Uses a single default column family with 32-byte keys.  Stores indexer
/// progress counters, segment-based box/tx indexes, and token metadata.
pub struct ExtraIndexerDb {
    db: DB,
}

impl ExtraIndexerDb {
    /// Opens (or creates) the extra-indexer RocksDB at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, IndexerDbError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(Self { db })
    }

    /// Opens the extra-indexer RocksDB at `path` in read-only mode.
    ///
    /// Useful for the HTTP API while the indexer holds the primary
    /// read-write handle.
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self, IndexerDbError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        std::fs::create_dir_all(path.as_ref()).ok();
        let db = DB::open_for_read_only(&opts, path, false)?;
        Ok(Self { db })
    }

    // -----------------------------------------------------------------------
    // Basic key-value operations
    // -----------------------------------------------------------------------

    /// Get the value associated with a 32-byte key, or `None` if absent.
    pub fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, IndexerDbError> {
        Ok(self.db.get(key)?)
    }

    /// Put a value under a 32-byte key.
    pub fn put(&self, key: &[u8; 32], value: &[u8]) -> Result<(), IndexerDbError> {
        self.db.put(key, value)?;
        Ok(())
    }

    /// Delete the entry at a 32-byte key.
    pub fn delete(&self, key: &[u8; 32]) -> Result<(), IndexerDbError> {
        self.db.delete(key)?;
        Ok(())
    }

    /// Atomically write a batch of operations.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<(), IndexerDbError> {
        self.db.write(batch)?;
        Ok(())
    }

    /// Create a new empty write batch.
    pub fn new_batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    // -----------------------------------------------------------------------
    // Progress helpers
    // -----------------------------------------------------------------------

    /// Read a u32 progress counter.  Returns 0 if the key is absent.
    pub fn get_progress_u32(&self, key: &[u8; 32]) -> Result<u32, IndexerDbError> {
        match self.get(key)? {
            Some(data) if data.len() == 4 => {
                Ok(u32::from_be_bytes(data.try_into().unwrap()))
            }
            Some(_) => Err(IndexerDbError::Codec("invalid u32 length".into())),
            None => Ok(0),
        }
    }

    /// Write a u32 progress counter.
    pub fn set_progress_u32(
        &self,
        key: &[u8; 32],
        val: u32,
    ) -> Result<(), IndexerDbError> {
        self.put(key, &val.to_be_bytes())
    }

    /// Read a u64 progress counter.  Returns 0 if the key is absent.
    pub fn get_progress_u64(&self, key: &[u8; 32]) -> Result<u64, IndexerDbError> {
        match self.get(key)? {
            Some(data) if data.len() == 8 => {
                Ok(u64::from_be_bytes(data.try_into().unwrap()))
            }
            Some(_) => Err(IndexerDbError::Codec("invalid u64 length".into())),
            None => Ok(0),
        }
    }

    /// Write a u64 progress counter.
    pub fn set_progress_u64(
        &self,
        key: &[u8; 32],
        val: u64,
    ) -> Result<(), IndexerDbError> {
        self.put(key, &val.to_be_bytes())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_put_get() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let key = blake2b256(b"test key");
        db.put(&key, b"hello world").unwrap();
        let val = db.get(&key).unwrap().unwrap();
        assert_eq!(val, b"hello world");
    }

    #[test]
    fn get_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let key = blake2b256(b"nonexistent");
        assert!(db.get(&key).unwrap().is_none());
    }

    #[test]
    fn delete_removes_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let key = blake2b256(b"delete me");
        db.put(&key, b"value").unwrap();
        assert!(db.get(&key).unwrap().is_some());
        db.delete(&key).unwrap();
        assert!(db.get(&key).unwrap().is_none());
    }

    #[test]
    fn progress_u32_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let key = indexed_height_key();
        // Default is 0 when absent.
        assert_eq!(db.get_progress_u32(&key).unwrap(), 0);
        db.set_progress_u32(&key, 42_000).unwrap();
        assert_eq!(db.get_progress_u32(&key).unwrap(), 42_000);
        db.set_progress_u32(&key, u32::MAX).unwrap();
        assert_eq!(db.get_progress_u32(&key).unwrap(), u32::MAX);
    }

    #[test]
    fn progress_u64_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let db = ExtraIndexerDb::open(tmp.path()).unwrap();
        let key = global_tx_index_key();
        // Default is 0 when absent.
        assert_eq!(db.get_progress_u64(&key).unwrap(), 0);
        db.set_progress_u64(&key, 1_000_000_000_000).unwrap();
        assert_eq!(db.get_progress_u64(&key).unwrap(), 1_000_000_000_000);
        db.set_progress_u64(&key, u64::MAX).unwrap();
        assert_eq!(db.get_progress_u64(&key).unwrap(), u64::MAX);
    }

    #[test]
    fn key_generators_deterministic() {
        // Same input produces the same key.
        assert_eq!(indexed_height_key(), indexed_height_key());
        assert_eq!(numeric_tx_key(7), numeric_tx_key(7));
        assert_eq!(numeric_box_key(99), numeric_box_key(99));

        let parent = [0xABu8; 32];
        assert_eq!(box_segment_key(&parent, 0), box_segment_key(&parent, 0));
        assert_eq!(tx_segment_key(&parent, 5), tx_segment_key(&parent, 5));

        // Different inputs produce different keys.
        assert_ne!(indexed_height_key(), global_tx_index_key());
        assert_ne!(numeric_tx_key(0), numeric_tx_key(1));
        assert_ne!(numeric_box_key(0), numeric_box_key(1));
        assert_ne!(box_segment_key(&parent, 0), box_segment_key(&parent, 1));
        assert_ne!(tx_segment_key(&parent, 0), tx_segment_key(&parent, 1));
        assert_ne!(
            box_segment_key(&parent, 0),
            tx_segment_key(&parent, 0),
        );

        // token_key with different IDs produces different keys.
        let id_a = ModifierId([1u8; 32]);
        let id_b = ModifierId([2u8; 32]);
        assert_eq!(token_key(&id_a), token_key(&id_a));
        assert_ne!(token_key(&id_a), token_key(&id_b));

        // tree_hash_key and template_hash_key.
        assert_eq!(tree_hash_key(b"tree1"), tree_hash_key(b"tree1"));
        assert_ne!(tree_hash_key(b"tree1"), tree_hash_key(b"tree2"));
        assert_eq!(template_hash_key(b"tpl"), template_hash_key(b"tpl"));
        assert_ne!(template_hash_key(b"tpl1"), template_hash_key(b"tpl2"));
    }
}

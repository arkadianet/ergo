use std::path::Path;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatchWithTransaction, DB};

use ergo_types::modifier_id::ModifierId;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("RocksDB error: {0}")]
    Rocks(#[from] rocksdb::Error),

    #[error("Codec error: {0}")]
    Codec(String),
}

// ---------------------------------------------------------------------------
// Column family names
// ---------------------------------------------------------------------------

const CF_OBJECTS: &str = "objects";
const CF_INDEXES: &str = "indexes";

// ---------------------------------------------------------------------------
// HistoryDb
// ---------------------------------------------------------------------------

/// RocksDB-backed storage for block modifiers and consensus indexes.
///
/// Uses two column families:
/// - `objects`: Block section storage. Key = `[1-byte type_id][32-byte ModifierId]`.
/// - `indexes`: Consensus metadata. Key = 32-byte hash. Value = variable.
pub struct HistoryDb {
    db: DB,
}

impl HistoryDb {
    /// Opens (or creates) a RocksDB database at `path` with the `objects` and
    /// `indexes` column families.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.increase_parallelism(
            std::thread::available_parallelism()
                .map(|n| n.get() as i32)
                .unwrap_or(4),
        );
        opts.set_max_background_jobs(4);

        // Shared block cache (256 MB).
        let cache = rocksdb::Cache::new_lru_cache(256 * 1024 * 1024);

        // CF_OBJECTS: block sections (write-heavy during sync).
        let mut obj_bb = rocksdb::BlockBasedOptions::default();
        obj_bb.set_block_cache(&cache);
        obj_bb.set_bloom_filter(10.0, false);
        let mut obj_opts = Options::default();
        obj_opts.set_write_buffer_size(64 * 1024 * 1024);
        obj_opts.set_max_write_buffer_number(3);
        obj_opts.set_block_based_table_factory(&obj_bb);
        let cf_objects = ColumnFamilyDescriptor::new(CF_OBJECTS, obj_opts);

        // CF_INDEXES: consensus metadata (frequent point lookups).
        let mut idx_bb = rocksdb::BlockBasedOptions::default();
        idx_bb.set_block_cache(&cache);
        idx_bb.set_bloom_filter(10.0, false);
        let mut idx_opts = Options::default();
        idx_opts.set_write_buffer_size(32 * 1024 * 1024);
        idx_opts.set_max_write_buffer_number(3);
        idx_opts.set_block_based_table_factory(&idx_bb);
        let cf_indexes = ColumnFamilyDescriptor::new(CF_INDEXES, idx_opts);

        let db = DB::open_cf_descriptors(&opts, path, vec![cf_objects, cf_indexes])?;
        Ok(Self { db })
    }

    /// Opens a RocksDB database at `path` in read-only mode for concurrent
    /// read access.  Useful for the HTTP API while the event loop holds the
    /// primary read-write handle.
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let opts = Options::default();
        let cf_objects = ColumnFamilyDescriptor::new(CF_OBJECTS, Options::default());
        let cf_indexes = ColumnFamilyDescriptor::new(CF_INDEXES, Options::default());
        let db =
            DB::open_cf_descriptors_read_only(&opts, path, vec![cf_objects, cf_indexes], false)?;
        Ok(Self { db })
    }

    /// Opens a RocksDB database as a secondary instance that can be refreshed
    /// to see writes from the primary via [`try_catch_up_with_primary`].
    pub fn open_as_secondary<P: AsRef<Path>>(
        primary_path: P,
        secondary_path: P,
    ) -> Result<Self, StorageError> {
        let opts = Options::default();
        let cf_objects = ColumnFamilyDescriptor::new(CF_OBJECTS, Options::default());
        let cf_indexes = ColumnFamilyDescriptor::new(CF_INDEXES, Options::default());
        let db = DB::open_cf_descriptors_as_secondary(
            &opts,
            primary_path,
            secondary_path,
            vec![cf_objects, cf_indexes],
        )?;
        Ok(Self { db })
    }

    /// Refreshes a secondary instance to see the latest writes from the
    /// primary. No-op on read-write or read-only instances.
    pub fn try_catch_up_with_primary(&self) -> Result<(), StorageError> {
        self.db.try_catch_up_with_primary().map_err(StorageError::Rocks)
    }

    // -----------------------------------------------------------------------
    // Modifier (objects CF) operations
    // -----------------------------------------------------------------------

    /// Builds the 33-byte key used in the `objects` column family.
    fn modifier_key(type_id: u8, id: &ModifierId) -> [u8; 33] {
        let mut key = [0u8; 33];
        key[0] = type_id;
        key[1..].copy_from_slice(&id.0);
        key
    }

    /// Stores a block section in the `objects` column family.
    pub fn put_modifier(
        &self,
        type_id: u8,
        id: &ModifierId,
        data: &[u8],
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_OBJECTS).unwrap();
        let key = Self::modifier_key(type_id, id);
        self.db.put_cf(&cf, key, data)?;
        Ok(())
    }

    /// Retrieves a block section from the `objects` column family.
    pub fn get_modifier(
        &self,
        type_id: u8,
        id: &ModifierId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self.db.cf_handle(CF_OBJECTS).unwrap();
        let key = Self::modifier_key(type_id, id);
        Ok(self.db.get_cf(&cf, key)?)
    }

    /// Checks whether a block section exists in the `objects` column family.
    ///
    /// Uses `get_pinned_cf` to avoid allocating a full copy of the value bytes.
    pub fn contains_modifier(
        &self,
        type_id: u8,
        id: &ModifierId,
    ) -> Result<bool, StorageError> {
        let cf = self.db.cf_handle(CF_OBJECTS).unwrap();
        let key = Self::modifier_key(type_id, id);
        Ok(self.db.get_pinned_cf(&cf, key)?.is_some())
    }
    /// Deletes a block section from the `objects` column family.
    pub fn delete_modifier(
        &self,
        type_id: u8,
        id: &ModifierId,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_OBJECTS).unwrap();
        let key = Self::modifier_key(type_id, id);
        self.db.delete_cf(&cf, key)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Section ID → Header ID mapping
    // -----------------------------------------------------------------------

    /// Prefix byte for section_id → header_id mappings.
    /// Uses 0xFD to avoid collision with modifier type IDs (101-108).
    const SECTION_MAP_PREFIX: u8 = 0xFD;

    /// Builds the 34-byte key for a section_id mapping:
    /// `[0xFD, type_id, section_id(32)]`.
    fn section_map_key(type_id: u8, section_id: &ModifierId) -> [u8; 34] {
        let mut key = [0u8; 34];
        key[0] = Self::SECTION_MAP_PREFIX;
        key[1] = type_id;
        key[2..34].copy_from_slice(&section_id.0);
        key
    }

    /// Stores a mapping from wire section_id to internal header_id.
    pub fn store_section_mapping(
        &self,
        type_id: u8,
        section_id: &ModifierId,
        header_id: &ModifierId,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_OBJECTS).unwrap();
        let key = Self::section_map_key(type_id, section_id);
        self.db.put_cf(&cf, key, header_id.0)?;
        Ok(())
    }

    /// Looks up the header_id for a given wire section_id.
    pub fn lookup_header_for_section(
        &self,
        type_id: u8,
        section_id: &ModifierId,
    ) -> Result<Option<ModifierId>, StorageError> {
        let cf = self.db.cf_handle(CF_OBJECTS).unwrap();
        let key = Self::section_map_key(type_id, section_id);
        match self.db.get_cf(&cf, key)? {
            Some(bytes) if bytes.len() == 32 => {
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                Ok(Some(ModifierId(id)))
            }
            _ => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // Index operations
    // -----------------------------------------------------------------------

    /// Stores an index entry in the `indexes` column family.
    pub fn put_index(&self, key: &[u8; 32], value: &[u8]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_INDEXES).unwrap();
        self.db.put_cf(&cf, key, value)?;
        Ok(())
    }

    /// Retrieves an index entry from the `indexes` column family.
    pub fn get_index(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self.db.cf_handle(CF_INDEXES).unwrap();
        Ok(self.db.get_cf(&cf, key)?)
    }

    /// Get the minimum height at which full block data is available.
    /// Returns 0 if not set (no pruning has occurred).
    pub fn minimal_full_block_height(&self) -> Result<u32, StorageError> {
        let key = minimal_full_block_height_key();
        match self.get_index(&key)? {
            Some(bytes) if bytes.len() == 4 => {
                Ok(u32::from_be_bytes(bytes[..4].try_into().unwrap()))
            }
            _ => Ok(0),
        }
    }

    /// Set the minimum height at which full block data is available.
    pub fn set_minimal_full_block_height(&self, height: u32) -> Result<(), StorageError> {
        let key = minimal_full_block_height_key();
        self.put_index(&key, &height.to_be_bytes())
    }

    // -----------------------------------------------------------------------
    // Batch operations
    // -----------------------------------------------------------------------

    /// Creates a new write batch for atomic multi-put operations.
    pub fn new_batch(&self) -> HistoryBatch<'_> {
        HistoryBatch {
            db: &self.db,
            batch: WriteBatchWithTransaction::<false>::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// HistoryBatch
// ---------------------------------------------------------------------------

/// A write batch that allows multiple puts to be committed atomically.
pub struct HistoryBatch<'a> {
    db: &'a DB,
    batch: WriteBatchWithTransaction<false>,
}

impl<'a> HistoryBatch<'a> {
    /// Queues a modifier put in the batch.
    pub fn put_modifier(&mut self, type_id: u8, id: &ModifierId, data: &[u8]) {
        let cf = self.db.cf_handle(CF_OBJECTS).unwrap();
        let key = HistoryDb::modifier_key(type_id, id);
        self.batch.put_cf(&cf, key, data);
    }

    /// Queues an index put in the batch.
    pub fn put_index(&mut self, key: &[u8; 32], value: &[u8]) {
        let cf = self.db.cf_handle(CF_INDEXES).unwrap();
        self.batch.put_cf(&cf, key, value);
    }

    /// Queues a modifier delete in the batch.
    pub fn delete_modifier(&mut self, type_id: u8, id: &ModifierId) {
        let cf = self.db.cf_handle(CF_OBJECTS).unwrap();
        let key = HistoryDb::modifier_key(type_id, id);
        self.batch.delete_cf(&cf, key);
    }

    /// Atomically writes all queued operations to the database.
    pub fn write(self) -> Result<(), StorageError> {
        self.db.write(self.batch)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Index key helpers (matching Scala HeadersProcessor)
// ---------------------------------------------------------------------------

/// Computes `blake2b256(data)` and returns the 32-byte digest.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("correct output size");
    out
}

/// Key for the best header pointer: 32 bytes of `0x65` (Header type ID = 101).
pub fn best_header_key() -> [u8; 32] {
    [0x65u8; 32]
}

/// Key for the best full block pointer: 32 bytes of `0xFF`.
pub fn best_full_block_key() -> [u8; 32] {
    [0xFFu8; 32]
}

/// Key for the last-applied block state version: 32 bytes of `0xFE`.
pub fn state_version_key() -> [u8; 32] {
    [0xFEu8; 32]
}

/// Key for the minimal full block height index: 32 bytes of `0xFD`.
pub fn minimal_full_block_height_key() -> [u8; 32] {
    [0xFDu8; 32]
}

/// Key for the list of header IDs at a given `height`.
pub fn height_ids_key(height: u32) -> [u8; 32] {
    blake2b256(&height.to_be_bytes())
}

/// Key for a header's cumulative score index entry.
pub fn header_score_key(id: &ModifierId) -> [u8; 32] {
    let mut buf = Vec::with_capacity(5 + 32);
    buf.extend_from_slice(b"score");
    buf.extend_from_slice(&id.0);
    blake2b256(&buf)
}

/// Key for a header's height index entry.
pub fn header_height_key(id: &ModifierId) -> [u8; 32] {
    let mut buf = Vec::with_capacity(6 + 32);
    buf.extend_from_slice(b"height");
    buf.extend_from_slice(&id.0);
    blake2b256(&buf)
}

/// Key for a modifier's validity index entry.
pub fn validity_key(id: &ModifierId) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 32);
    buf.extend_from_slice(b"validity");
    buf.extend_from_slice(&id.0);
    blake2b256(&buf)
}

/// Key for a header's main-chain status index entry.
pub fn chain_status_key(id: &ModifierId) -> [u8; 32] {
    let mut buf = Vec::with_capacity(10 + 32);
    buf.extend_from_slice(b"main_chain");
    buf.extend_from_slice(&id.0);
    blake2b256(&buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_test_db() -> (HistoryDb, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = HistoryDb::open(dir.path()).unwrap();
        (db, dir)
    }

    fn test_modifier_id(fill: u8) -> ModifierId {
        ModifierId([fill; 32])
    }

    #[test]
    fn open_and_close() {
        let (_db, _dir) = open_test_db();
        // Successfully opened and will be dropped.
    }

    #[test]
    fn put_get_modifier() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xAB);
        let data = b"block-section-bytes";
        db.put_modifier(101, &id, data).unwrap();

        let got = db.get_modifier(101, &id).unwrap();
        assert_eq!(got.as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn get_missing_modifier() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0x01);
        let got = db.get_modifier(101, &id).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn contains_modifier() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0x02);
        assert!(!db.contains_modifier(101, &id).unwrap());

        db.put_modifier(101, &id, b"data").unwrap();
        assert!(db.contains_modifier(101, &id).unwrap());
    }

    #[test]
    fn different_type_ids_independent() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xCC);

        db.put_modifier(101, &id, b"header-bytes").unwrap();
        db.put_modifier(102, &id, b"tx-bytes").unwrap();

        let header = db.get_modifier(101, &id).unwrap().unwrap();
        let tx = db.get_modifier(102, &id).unwrap().unwrap();
        assert_eq!(header, b"header-bytes");
        assert_eq!(tx, b"tx-bytes");
        assert_ne!(header, tx);
    }

    #[test]
    fn put_get_index() {
        let (db, _dir) = open_test_db();
        let key = best_header_key();
        let value = b"some-index-value";

        db.put_index(&key, value).unwrap();
        let got = db.get_index(&key).unwrap();
        assert_eq!(got.as_deref(), Some(value.as_slice()));
    }

    #[test]
    fn batch_write_atomic() {
        let (db, _dir) = open_test_db();

        let id1 = test_modifier_id(0x10);
        let id2 = test_modifier_id(0x20);
        let idx_key = best_full_block_key();

        let mut batch = db.new_batch();
        batch.put_modifier(101, &id1, b"mod1");
        batch.put_modifier(102, &id2, b"mod2");
        batch.put_index(&idx_key, b"idx-val");
        batch.write().unwrap();

        assert_eq!(db.get_modifier(101, &id1).unwrap().unwrap(), b"mod1");
        assert_eq!(db.get_modifier(102, &id2).unwrap().unwrap(), b"mod2");
        assert_eq!(db.get_index(&idx_key).unwrap().unwrap(), b"idx-val");
    }

    #[test]
    fn index_key_deterministic() {
        let id = test_modifier_id(0xAA);
        let k1 = header_score_key(&id);
        let k2 = header_score_key(&id);
        assert_eq!(k1, k2);

        let k3 = header_height_key(&id);
        let k4 = header_height_key(&id);
        assert_eq!(k3, k4);

        // Different key functions should produce different keys.
        assert_ne!(k1, k3);
    }

    #[test]
    fn height_ids_key_deterministic() {
        let k1 = height_ids_key(42);
        let k2 = height_ids_key(42);
        assert_eq!(k1, k2);

        let k3 = height_ids_key(43);
        assert_ne!(k1, k3);
    }

    #[test]
    fn best_header_key_is_filled_65() {
        let key = best_header_key();
        assert_eq!(key.len(), 32);
        assert!(key.iter().all(|&b| b == 0x65));
    }

    #[test]
    fn best_full_block_key_is_filled_ff() {
        let key = best_full_block_key();
        assert_eq!(key.len(), 32);
        assert!(key.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn reopen_persists_data() {
        let dir = TempDir::new().unwrap();
        let id = test_modifier_id(0xDD);
        let idx_key = best_header_key();

        // First open: write data.
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            db.put_modifier(101, &id, b"persisted-mod").unwrap();
            db.put_index(&idx_key, b"persisted-idx").unwrap();
        }

        // Second open: data should still be there.
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            assert_eq!(
                db.get_modifier(101, &id).unwrap().unwrap(),
                b"persisted-mod"
            );
            assert_eq!(
                db.get_index(&idx_key).unwrap().unwrap(),
                b"persisted-idx"
            );
        }
    }

    #[test]
    fn delete_modifier_removes_data() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xDE);
        db.put_modifier(102, &id, b"tx-bytes").unwrap();
        assert!(db.contains_modifier(102, &id).unwrap());

        db.delete_modifier(102, &id).unwrap();
        assert!(!db.contains_modifier(102, &id).unwrap());
        assert!(db.get_modifier(102, &id).unwrap().is_none());
    }

    #[test]
    fn delete_modifier_noop_when_missing() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xDF);
        // Should not error when deleting a key that doesn't exist.
        db.delete_modifier(102, &id).unwrap();
    }

    #[test]
    fn minimal_full_block_height_default_zero() {
        let (db, _dir) = open_test_db();
        assert_eq!(db.minimal_full_block_height().unwrap(), 0);
    }

    #[test]
    fn set_and_get_minimal_full_block_height() {
        let (db, _dir) = open_test_db();
        db.set_minimal_full_block_height(50_000).unwrap();
        assert_eq!(db.minimal_full_block_height().unwrap(), 50_000);
        db.set_minimal_full_block_height(100_000).unwrap();
        assert_eq!(db.minimal_full_block_height().unwrap(), 100_000);
    }

    #[test]
    fn minimal_full_block_height_persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            db.set_minimal_full_block_height(42_000).unwrap();
        }
        {
            let db = HistoryDb::open(dir.path()).unwrap();
            assert_eq!(db.minimal_full_block_height().unwrap(), 42_000);
        }
    }

    #[test]
    fn minimal_full_block_height_key_is_filled_fd() {
        let key = minimal_full_block_height_key();
        assert_eq!(key.len(), 32);
        assert!(key.iter().all(|&b| b == 0xFD));
    }

    #[test]
    fn batch_delete_modifier() {
        let (db, _dir) = open_test_db();
        let id = test_modifier_id(0xE0);
        db.put_modifier(102, &id, b"data-to-delete").unwrap();
        assert!(db.contains_modifier(102, &id).unwrap());

        let mut batch = db.new_batch();
        batch.delete_modifier(102, &id);
        batch.write().unwrap();

        assert!(!db.contains_modifier(102, &id).unwrap());
    }

}
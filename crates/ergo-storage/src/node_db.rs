//! Single shared RocksDB instance with named column families for all node stores.

use std::path::Path;

use rocksdb::{
    BlockBasedOptions, BoundColumnFamily, Cache, ColumnFamilyDescriptor, DBWithThreadMode,
    MultiThreaded, Options,
};
use std::sync::Arc;

use crate::history_db::StorageError;

// ---------------------------------------------------------------------------
// CF name constants — pub so wrapper crates can reference them
// ---------------------------------------------------------------------------

pub const CF_OBJECTS: &str = "objects";
pub const CF_INDEXES: &str = "indexes";
pub const CF_UTXO: &str = "utxo";
pub const CF_INDEXER: &str = "indexer";
pub const CF_SNAPSHOTS: &str = "snapshots";

// ---------------------------------------------------------------------------
// NodeDb
// ---------------------------------------------------------------------------

/// Single RocksDB instance shared by all node storage subsystems.
///
/// Uses `DBWithThreadMode<MultiThreaded>` — it is `Send + Sync` so an
/// `Arc<NodeDb>` can be cloned freely across threads without any additional
/// locking.  Each subsystem wrapper (`HistoryDb`, `UtxoDb`, etc.) holds an
/// `Arc<NodeDb>` and accesses only its own column family.
pub struct NodeDb {
    db: DBWithThreadMode<MultiThreaded>,
}

impl NodeDb {
    /// Opens (or creates) the node DB at `path` with all 5 column families.
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
        // Single FD budget for all CFs (vs. 1000 per separate DB instance).
        opts.set_max_open_files(4096);
        opts.set_keep_log_file_num(2);

        // Shared block cache across all CFs — critical for bounded memory usage.
        let cache = Cache::new_lru_cache(256 * 1024 * 1024);
        let cfs = Self::build_cf_descriptors(&cache);

        let db = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self { db })
    }

    fn build_cf_descriptors(cache: &Cache) -> Vec<ColumnFamilyDescriptor> {
        // objects: write-heavy during sync — large buffer, LZ4, 16KB blocks.
        let mut obj_bb = BlockBasedOptions::default();
        obj_bb.set_block_cache(cache);
        obj_bb.set_bloom_filter(10.0, false);
        obj_bb.set_block_size(16 * 1024);
        let mut obj_opts = Options::default();
        obj_opts.set_write_buffer_size(64 * 1024 * 1024);
        obj_opts.set_max_write_buffer_number(3);
        obj_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        obj_opts.set_block_based_table_factory(&obj_bb);

        // indexes: frequent small point lookups.
        let mut idx_bb = BlockBasedOptions::default();
        idx_bb.set_block_cache(cache);
        idx_bb.set_bloom_filter(10.0, false);
        let mut idx_opts = Options::default();
        idx_opts.set_write_buffer_size(32 * 1024 * 1024);
        idx_opts.set_max_write_buffer_number(3);
        idx_opts.set_block_based_table_factory(&idx_bb);

        // utxo: point-lookup optimized with pinned index/filter blocks.
        let mut utxo_bb = BlockBasedOptions::default();
        utxo_bb.set_block_cache(cache);
        utxo_bb.set_bloom_filter(10.0, false);
        utxo_bb.set_cache_index_and_filter_blocks(true);
        utxo_bb.set_pin_l0_filter_and_index_blocks_in_cache(true);
        let mut utxo_opts = Options::default();
        utxo_opts.set_write_buffer_size(64 * 1024 * 1024);
        utxo_opts.set_max_write_buffer_number(3);
        utxo_opts.set_block_based_table_factory(&utxo_bb);

        // indexer: similar to indexes.
        let mut ixr_bb = BlockBasedOptions::default();
        ixr_bb.set_block_cache(cache);
        ixr_bb.set_bloom_filter(10.0, false);
        let mut ixr_opts = Options::default();
        ixr_opts.set_write_buffer_size(32 * 1024 * 1024);
        ixr_opts.set_max_write_buffer_number(3);
        ixr_opts.set_block_based_table_factory(&ixr_bb);

        // snapshots: large sequential values.
        let mut snap_bb = BlockBasedOptions::default();
        snap_bb.set_block_cache(cache);
        let mut snap_opts = Options::default();
        snap_opts.set_write_buffer_size(32 * 1024 * 1024);
        snap_opts.set_block_based_table_factory(&snap_bb);

        vec![
            ColumnFamilyDescriptor::new(CF_OBJECTS, obj_opts),
            ColumnFamilyDescriptor::new(CF_INDEXES, idx_opts),
            ColumnFamilyDescriptor::new(CF_UTXO, utxo_opts),
            ColumnFamilyDescriptor::new(CF_INDEXER, ixr_opts),
            ColumnFamilyDescriptor::new(CF_SNAPSHOTS, snap_opts),
        ]
    }

    /// Raw access to the underlying `DBWithThreadMode<MultiThreaded>`.
    ///
    /// Wrappers use this to call RocksDB methods directly
    /// (iterators, prefix scans, get_pinned_cf, etc.).
    pub fn raw(&self) -> &DBWithThreadMode<MultiThreaded> {
        &self.db
    }

    pub fn cf_objects(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_OBJECTS)
            .expect("CF_OBJECTS must exist")
    }
    pub fn cf_indexes(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_INDEXES)
            .expect("CF_INDEXES must exist")
    }
    pub fn cf_utxo(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(CF_UTXO).expect("CF_UTXO must exist")
    }
    pub fn cf_indexer(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_INDEXER)
            .expect("CF_INDEXER must exist")
    }
    pub fn cf_snapshots(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(CF_SNAPSHOTS)
            .expect("CF_SNAPSHOTS must exist")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::WriteBatch;

    #[test]
    fn cross_cf_atomic_write() {
        let tmp = tempfile::tempdir().unwrap();
        let db = NodeDb::open(tmp.path()).unwrap();

        let mut batch = WriteBatch::default();
        batch.put_cf(&db.cf_objects(), b"obj-key", b"obj-value");
        batch.put_cf(&db.cf_indexes(), b"idx-key", b"idx-value");
        db.raw().write(batch).unwrap();

        assert_eq!(
            db.raw()
                .get_cf(&db.cf_objects(), b"obj-key")
                .unwrap()
                .as_deref(),
            Some(b"obj-value".as_slice()),
        );
        assert_eq!(
            db.raw()
                .get_cf(&db.cf_indexes(), b"idx-key")
                .unwrap()
                .as_deref(),
            Some(b"idx-value".as_slice()),
        );
        assert!(db
            .raw()
            .get_cf(&db.cf_indexes(), b"obj-key")
            .unwrap()
            .is_none());
    }

    #[test]
    fn open_creates_all_cfs() {
        let tmp = tempfile::tempdir().unwrap();
        let db = NodeDb::open(tmp.path()).unwrap();
        let _ = db.cf_objects();
        let _ = db.cf_indexes();
        let _ = db.cf_utxo();
        let _ = db.cf_indexer();
        let _ = db.cf_snapshots();
    }
}

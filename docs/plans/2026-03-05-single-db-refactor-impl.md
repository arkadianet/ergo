# Single-DB Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace 5 separate RocksDB instances with one shared `NodeDb` (one RocksDB, 5 named column families), eliminating FD exhaustion and enabling cross-store atomic writes.

**Architecture:** New `NodeDb` struct in `ergo-storage` wraps `DBWithThreadMode<MultiThreaded>` with 5 CFs (`objects`, `indexes`, `utxo`, `indexer`, `snapshots`). Existing wrappers (`HistoryDb`, `UtxoDb`, `ExtraIndexerDb`, `SnapshotsDb`) change their inner `db: DB` field to `db: Arc<NodeDb>` and gain a `from_shared(Arc<NodeDb>) -> Self` constructor. Their `open(path)` constructors are kept (they internally create a `NodeDb`) so all test code continues to work without modification. `main.rs` creates one `NodeDb` and calls `from_shared` for all wrappers. Data path changes from `.ergo/history/` to `.ergo/node/`.

**Tech Stack:** `rocksdb` crate (already in workspace), `DBWithThreadMode<MultiThreaded>` for thread-safe shared access, `Arc<NodeDb>` for shared ownership across threads, `WriteBatch` (replaces `WriteBatchWithTransaction<false>` internally).

---

### Task 1: Create `NodeDb` in `ergo-storage`

**Files:**
- Create: `crates/ergo-storage/src/node_db.rs`
- Modify: `crates/ergo-storage/src/lib.rs`

**Background:** `DBWithThreadMode<MultiThreaded>` is the thread-safe variant of RocksDB in the `rocksdb` crate. It is `Send + Sync`, so an `Arc<NodeDb>` can be freely cloned across threads. Column families are named sub-spaces within a single RocksDB directory — each has independent tuning but shares one WAL, MANIFEST, block cache, and OS FD pool.

**Step 1: Write the failing test**

Add to `crates/ergo-storage/src/node_db.rs` (create the file with just the test first):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::WriteBatch;

    #[test]
    fn cross_cf_atomic_write() {
        let tmp = tempfile::tempdir().unwrap();
        let db = NodeDb::open(tmp.path()).unwrap();

        // Write to two CFs in one batch.
        let mut batch = WriteBatch::default();
        batch.put_cf(db.cf_objects(), b"obj-key", b"obj-value");
        batch.put_cf(db.cf_indexes(), b"idx-key", b"idx-value");
        db.raw().write(batch).unwrap();

        // Read from each CF independently.
        assert_eq!(
            db.raw().get_cf(db.cf_objects(), b"obj-key").unwrap().as_deref(),
            Some(b"obj-value".as_slice()),
        );
        assert_eq!(
            db.raw().get_cf(db.cf_indexes(), b"idx-key").unwrap().as_deref(),
            Some(b"idx-value".as_slice()),
        );
        // Different CFs are independent — key written to objects is absent in indexes.
        assert!(db.raw().get_cf(db.cf_indexes(), b"obj-key").unwrap().is_none());
    }
}
```

**Step 2: Run test to verify it fails**

```bash
cargo test -p ergo-storage node_db 2>&1 | tail -5
```
Expected: compile error (`NodeDb` not defined yet).

**Step 3: Implement `NodeDb`**

Write `crates/ergo-storage/src/node_db.rs`:

```rust
//! Single shared RocksDB instance with named column families for all node stores.

use std::path::Path;

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamily, ColumnFamilyDescriptor,
    DBWithThreadMode, MultiThreaded, Options,
};

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

    // -----------------------------------------------------------------------
    // Raw access and CF handles — for use by wrapper structs
    // -----------------------------------------------------------------------

    /// Raw access to the underlying `DBWithThreadMode<MultiThreaded>`.
    ///
    /// Wrappers use this to call RocksDB methods directly
    /// (iterators, prefix scans, get_pinned_cf, etc.).
    pub fn raw(&self) -> &DBWithThreadMode<MultiThreaded> {
        &self.db
    }

    pub fn cf_objects(&self) -> &ColumnFamily {
        self.db.cf_handle(CF_OBJECTS).expect("CF_OBJECTS must exist")
    }
    pub fn cf_indexes(&self) -> &ColumnFamily {
        self.db.cf_handle(CF_INDEXES).expect("CF_INDEXES must exist")
    }
    pub fn cf_utxo(&self) -> &ColumnFamily {
        self.db.cf_handle(CF_UTXO).expect("CF_UTXO must exist")
    }
    pub fn cf_indexer(&self) -> &ColumnFamily {
        self.db.cf_handle(CF_INDEXER).expect("CF_INDEXER must exist")
    }
    pub fn cf_snapshots(&self) -> &ColumnFamily {
        self.db.cf_handle(CF_SNAPSHOTS).expect("CF_SNAPSHOTS must exist")
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
        batch.put_cf(db.cf_objects(), b"obj-key", b"obj-value");
        batch.put_cf(db.cf_indexes(), b"idx-key", b"idx-value");
        db.raw().write(batch).unwrap();

        assert_eq!(
            db.raw().get_cf(db.cf_objects(), b"obj-key").unwrap().as_deref(),
            Some(b"obj-value".as_slice()),
        );
        assert_eq!(
            db.raw().get_cf(db.cf_indexes(), b"idx-key").unwrap().as_deref(),
            Some(b"idx-value".as_slice()),
        );
        assert!(db.raw().get_cf(db.cf_indexes(), b"obj-key").unwrap().is_none());
    }

    #[test]
    fn open_creates_all_cfs() {
        let tmp = tempfile::tempdir().unwrap();
        let db = NodeDb::open(tmp.path()).unwrap();
        // Accessing all CF handles panics if any is missing.
        let _ = db.cf_objects();
        let _ = db.cf_indexes();
        let _ = db.cf_utxo();
        let _ = db.cf_indexer();
        let _ = db.cf_snapshots();
    }
}
```

**Step 4: Add module to `lib.rs`**

Edit `crates/ergo-storage/src/lib.rs`:
```rust
pub mod block_processor;
pub mod chain_scoring;
pub mod continuation;
pub mod header_store;
pub mod history_db;
pub mod node_db;          // ← add this line
pub mod section_store;
pub mod utxo_db;
```

**Step 5: Run test to verify it passes**

```bash
cargo test -p ergo-storage node_db 2>&1 | tail -5
```
Expected:
```
test node_db::tests::cross_cf_atomic_write ... ok
test node_db::tests::open_creates_all_cfs ... ok
test result: ok. 2 passed
```

**Step 6: Run full workspace tests**

```bash
cargo test --workspace 2>&1 | tail -5
```
Expected: all tests pass (no regressions — `NodeDb` is new code).

**Step 7: Commit**

```bash
git add crates/ergo-storage/src/node_db.rs crates/ergo-storage/src/lib.rs
git commit -m "feat(storage): add NodeDb — shared RocksDB with 5 named column families"
```

---

### Task 2: Refactor `HistoryDb` to wrap `Arc<NodeDb>`

**Files:**
- Modify: `crates/ergo-storage/src/history_db.rs`

**Background:** `HistoryDb` currently holds `db: DB` (a `DBWithThreadMode<SingleThreaded>`). After this task it holds `db: Arc<NodeDb>`. The `HistoryBatch` inner struct holds `db: &'a DB` and `batch: WriteBatchWithTransaction<false>` — both change to `db: &'a NodeDb` and `batch: WriteBatch`. All call sites that use `self.db.cf_handle(CF_OBJECTS)` become `self.db.cf_objects()`. All `self.db.put_cf(...)` become `self.db.raw().put_cf(...)`.

The `open_read_only` and `open_as_secondary` constructors are removed — callers receive a `from_shared` wrapper instead. `try_catch_up_with_primary` becomes a no-op (kept to avoid breaking call sites in `event_loop.rs`).

**Step 1: Write a test that verifies `from_shared` works**

Add to the `#[cfg(test)]` block at the bottom of `history_db.rs`:

```rust
#[test]
fn from_shared_shares_data() {
    use std::sync::Arc;
    use crate::node_db::NodeDb;

    let tmp = tempfile::tempdir().unwrap();
    let node_db = Arc::new(NodeDb::open(tmp.path()).unwrap());
    let db1 = HistoryDb::from_shared(node_db.clone());
    let db2 = HistoryDb::from_shared(node_db.clone());

    // Write via db1, read via db2 — they share the same underlying DB.
    let key = best_header_key();
    let val = [0xABu8; 32];
    db1.set_best_header_id(&ergo_types::modifier_id::ModifierId(val)).unwrap();
    let got = db2.best_header_id().unwrap();
    assert_eq!(got.map(|id| id.0), Some(val));
}
```

**Step 2: Run test to verify it fails**

```bash
cargo test -p ergo-storage from_shared_shares_data 2>&1 | tail -5
```
Expected: compile error (`from_shared` not defined).

**Step 3: Implement the refactored `HistoryDb`**

At the top of `history_db.rs`, change the imports:

```rust
// REMOVE:
use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatchWithTransaction, DB};

// ADD:
use std::sync::Arc;
use rocksdb::WriteBatch;
use crate::node_db::NodeDb;
```

Change the struct definition:
```rust
// BEFORE:
pub struct HistoryDb {
    db: DB,
}

// AFTER:
pub struct HistoryDb {
    db: Arc<NodeDb>,
}
```

Replace ALL THREE constructors (`open`, `open_read_only`, `open_as_secondary`) with:

```rust
impl HistoryDb {
    /// Opens (or creates) a standalone `HistoryDb` at `path`.
    ///
    /// Creates its own internal `NodeDb` with all 5 CFs. This constructor is
    /// used in unit tests. In production, use `from_shared` instead.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        Ok(Self { db: Arc::new(NodeDb::open(path)?) })
    }

    /// Wraps a shared `NodeDb`. All instances sharing the same `Arc<NodeDb>`
    /// see each other's writes immediately (no refresh needed).
    pub fn from_shared(db: Arc<NodeDb>) -> Self {
        Self { db }
    }

    /// No-op. Kept for call-site compatibility.
    /// Previously refreshed a secondary RocksDB instance; no longer needed
    /// because `from_shared` wrappers see writes immediately.
    pub fn try_catch_up_with_primary(&self) -> Result<(), StorageError> {
        Ok(())
    }
```

Update `HistoryBatch`:

```rust
// BEFORE:
pub struct HistoryBatch<'a> {
    db: &'a DB,
    batch: WriteBatchWithTransaction<false>,
}

// AFTER:
pub struct HistoryBatch<'a> {
    db: &'a NodeDb,
    batch: WriteBatch,
}
```

Update `HistoryDb::new_batch`:
```rust
pub fn new_batch(&self) -> HistoryBatch<'_> {
    HistoryBatch {
        db: &self.db,
        batch: WriteBatch::default(),
    }
}
```

Update `HistoryBatch` methods (change `self.db.cf_handle(CF_OBJECTS)` → `self.db.cf_objects()` and `self.db.cf_handle(CF_INDEXES)` → `self.db.cf_indexes()`, and `self.db.write(self.batch)` → `self.db.raw().write(self.batch)`):

```rust
impl<'a> HistoryBatch<'a> {
    pub fn put_modifier(&mut self, type_id: u8, id: &ModifierId, data: &[u8]) {
        let key = HistoryDb::modifier_key(type_id, id);
        self.batch.put_cf(self.db.cf_objects(), key, data);
    }

    pub fn put_index(&mut self, key: &[u8; 32], value: &[u8]) {
        self.batch.put_cf(self.db.cf_indexes(), key, value);
    }

    pub fn delete_modifier(&mut self, type_id: u8, id: &ModifierId) {
        let key = HistoryDb::modifier_key(type_id, id);
        self.batch.delete_cf(self.db.cf_objects(), key);
    }

    pub fn write(self) -> Result<(), StorageError> {
        self.db.raw().write(self.batch)?;
        Ok(())
    }
}
```

For all other methods in `HistoryDb` that directly access `self.db`, apply the same pattern:
- `self.db.cf_handle(CF_OBJECTS).unwrap()` → `self.db.cf_objects()`
- `self.db.cf_handle(CF_INDEXES).unwrap()` → `self.db.cf_indexes()`
- `self.db.put_cf(&cf, ...)` → `self.db.raw().put_cf(cf, ...)`
- `self.db.get_cf(&cf, ...)` → `self.db.raw().get_cf(cf, ...)`
- `self.db.delete_cf(&cf, ...)` → `self.db.raw().delete_cf(cf, ...)`
- `self.db.get_pinned_cf(&cf, ...)` → `self.db.raw().get_pinned_cf(cf, ...)`
- `self.db.write(batch)` → `self.db.raw().write(batch)`
- `self.db.iterator_cf_opt(&cf, mode, opts)` → `self.db.raw().iterator_cf_opt(cf, mode, opts)`
- `self.db.prefix_iterator_cf(&cf, prefix)` → `self.db.raw().prefix_iterator_cf(cf, prefix)`

Note on `HistoryBatch` lifetime: `db: &'a NodeDb` now (not `&'a DB`). `new_batch` returns `HistoryBatch<'_>` with `db: &self.db` — this works because `self.db` is `Arc<NodeDb>` and `&self.db` dereferences to `&NodeDb`.

**Step 4: Run test to verify it passes**

```bash
cargo test -p ergo-storage 2>&1 | tail -10
```
Expected: all existing tests pass + `from_shared_shares_data` passes.

**Step 5: Verify full workspace compiles**

```bash
cargo check --workspace 2>&1 | tail -5
```
Fix any compile errors. Most will be `self.db.cf_handle(...)` patterns not yet updated.

**Step 6: Commit**

```bash
git add crates/ergo-storage/src/history_db.rs
git commit -m "refactor(storage): HistoryDb wraps Arc<NodeDb>, add from_shared, remove read-only/secondary constructors"
```

---

### Task 3: Refactor `UtxoDb` to wrap `Arc<NodeDb>`

**Files:**
- Modify: `crates/ergo-storage/src/utxo_db.rs`

**Background:** `UtxoDb` currently holds `db: DB` using the default column family (no named CFs). After this task it uses the `CF_UTXO` column family in a shared `NodeDb`. All keys (box IDs + metadata) live in `CF_UTXO`.

The main changes:
- `db: DB` → `db: Arc<NodeDb>`
- `self.db.get(key)` → `self.db.raw().get_cf(self.db.cf_utxo(), key)`
- `batch.put(key, val)` → `batch.put_cf(self.db.cf_utxo(), key, val)`
- `batch.delete(key)` → `batch.delete_cf(self.db.cf_utxo(), key)`
- `self.db.write(batch)` → `self.db.raw().write(batch)`
- `self.db.iterator(IteratorMode::Start)` → `self.db.raw().iterator_cf(self.db.cf_utxo(), IteratorMode::Start)`
- `WriteBatchWithTransaction::<false>::default()` → `WriteBatch::default()`

**Step 1: Write a test that verifies `from_shared` works**

Add to the `#[cfg(test)]` block at the bottom of `utxo_db.rs`:

```rust
#[test]
fn from_shared_shares_data() {
    use std::sync::Arc;
    use crate::node_db::NodeDb;

    let tmp = tempfile::tempdir().unwrap();
    let node_db = Arc::new(NodeDb::open(tmp.path()).unwrap());
    let db1 = UtxoDb::from_shared(node_db.clone());
    let db2 = UtxoDb::from_shared(node_db.clone());

    let id = [0xAAu8; 32];
    let meta = UtxoMetadata { digest: [0x11; 33], version: [0x22; 32] };
    db1.apply_changes(&[(id, b"box-data".to_vec())], &[], &meta).unwrap();

    // db2 sees the write immediately.
    assert!(db2.get(&id).unwrap().is_some());
    assert_eq!(db2.metadata().unwrap().unwrap(), meta);
}
```

**Step 2: Run test to verify it fails**

```bash
cargo test -p ergo-storage from_shared_shares_data 2>&1 | tail -5
```
Expected: compile error.

**Step 3: Implement the refactored `UtxoDb`**

At the top of `utxo_db.rs`, change imports:

```rust
// REMOVE:
use rocksdb::{Options, WriteBatchWithTransaction, DB};

// ADD:
use std::sync::Arc;
use rocksdb::{IteratorMode, WriteBatch};
use crate::node_db::NodeDb;
```

Change the struct:
```rust
// BEFORE:
pub struct UtxoDb { db: DB }

// AFTER:
pub struct UtxoDb { db: Arc<NodeDb> }
```

Replace constructors:
```rust
impl UtxoDb {
    /// Standalone open — creates its own NodeDb. Used in tests.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, UtxoDbError> {
        Ok(Self { db: Arc::new(NodeDb::open(path)?) })
    }

    /// Wraps a shared NodeDb. Used in production.
    pub fn from_shared(db: Arc<NodeDb>) -> Self {
        Self { db }
    }
```

Update `apply_changes`:
```rust
pub fn apply_changes(
    &self,
    to_insert: &[([u8; 32], Vec<u8>)],
    to_remove: &[[u8; 32]],
    metadata: &UtxoMetadata,
) -> Result<(), UtxoDbError> {
    let cf = self.db.cf_utxo();
    let mut batch = WriteBatch::default();
    for (key, value) in to_insert {
        batch.put_cf(cf, key, value);
    }
    for key in to_remove {
        batch.delete_cf(cf, key);
    }
    batch.put_cf(cf, METADATA_KEY, metadata.to_bytes());
    self.db.raw().write(batch)?;
    Ok(())
}
```

Update `metadata`:
```rust
pub fn metadata(&self) -> Result<Option<UtxoMetadata>, UtxoDbError> {
    match self.db.raw().get_cf(self.db.cf_utxo(), METADATA_KEY)? {
        Some(data) => Ok(Some(UtxoMetadata::from_bytes(&data)?)),
        None => Ok(None),
    }
}
```

Update `iter_entries`:
```rust
pub fn iter_entries(&self) -> impl Iterator<Item = ([u8; 32], Vec<u8>)> + '_ {
    self.db
        .raw()
        .iterator_cf(self.db.cf_utxo(), IteratorMode::Start)
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
```

Update `get`:
```rust
pub fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, UtxoDbError> {
    Ok(self.db.raw().get_cf(self.db.cf_utxo(), key)?)
}
```

Also add this `From` impl for `rocksdb::Error` on `UtxoDbError` since the raw DB now returns `rocksdb::Error` directly — it should already exist via `#[from]` on `Rocks(#[from] rocksdb::Error)`.

**Step 4: Run test to verify it passes**

```bash
cargo test -p ergo-storage 2>&1 | tail -10
```
Expected: all tests pass.

**Step 5: Check state crate compiles**

```bash
cargo check -p ergo-state 2>&1 | tail -5
```
Fix any compile errors in `ergo-state` that use `UtxoDb`.

**Step 6: Commit**

```bash
git add crates/ergo-storage/src/utxo_db.rs
git commit -m "refactor(storage): UtxoDb wraps Arc<NodeDb>, uses CF_UTXO column family"
```

---

### Task 4: Refactor `ExtraIndexerDb` to wrap `Arc<NodeDb>`

**Files:**
- Modify: `crates/ergo-indexer/src/db.rs`

**Background:** `ExtraIndexerDb` currently has its own `DB`. It uses only 32-byte hash keys and byte-value entries (no CFs). After this task it uses the `CF_INDEXER` column family. The `ergo-indexer` crate already depends on `ergo-storage` (confirmed in `Cargo.toml`), so no new dependency is needed.

The key changes:
- `db: DB` → `db: Arc<NodeDb>` (import `NodeDb` from `ergo_storage::node_db`)
- `self.db.get(key)` → `self.db.raw().get_cf(self.db.cf_indexer(), key)`
- `self.db.put(key, value)` → `self.db.raw().put_cf(self.db.cf_indexer(), key, value)` ... etc.
- `open_read_only` is removed (callers get `from_shared` instead)
- `WriteBatch::default()` stays (it already used `WriteBatch`)

**Step 1: Write the failing test**

Add to `#[cfg(test)]` in `crates/ergo-indexer/src/db.rs`:

```rust
#[test]
fn from_shared_shares_data() {
    use std::sync::Arc;
    use ergo_storage::node_db::NodeDb;

    let tmp = tempfile::tempdir().unwrap();
    let node_db = Arc::new(NodeDb::open(tmp.path()).unwrap());
    let db1 = ExtraIndexerDb::from_shared(node_db.clone());
    let db2 = ExtraIndexerDb::from_shared(node_db.clone());

    let key = blake2b256(b"test key");
    db1.put(&key, b"hello").unwrap();
    assert_eq!(db2.get(&key).unwrap().as_deref(), Some(b"hello".as_slice()));
}
```

**Step 2: Run test to verify it fails**

```bash
cargo test -p ergo-indexer from_shared_shares_data 2>&1 | tail -5
```

**Step 3: Implement the refactored `ExtraIndexerDb`**

At the top of `crates/ergo-indexer/src/db.rs`, change imports:

```rust
// REMOVE:
use rocksdb::{Options, WriteBatch, DB};

// ADD:
use std::sync::Arc;
use rocksdb::WriteBatch;
use ergo_storage::node_db::NodeDb;
```

Change struct:
```rust
// BEFORE:
pub struct ExtraIndexerDb { db: DB }

// AFTER:
pub struct ExtraIndexerDb { db: Arc<NodeDb> }
```

Replace constructors:
```rust
impl ExtraIndexerDb {
    /// Standalone open — creates its own NodeDb. Used in tests.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, IndexerDbError> {
        Ok(Self { db: Arc::new(NodeDb::open(path)?) })
    }

    /// Wraps a shared NodeDb. Used in production (API + indexer task share same handle).
    pub fn from_shared(db: Arc<NodeDb>) -> Self {
        Self { db }
    }
```

Update all operations to use `CF_INDEXER`:
```rust
pub fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, IndexerDbError> {
    Ok(self.db.raw().get_cf(self.db.cf_indexer(), key)?)
}

pub fn put(&self, key: &[u8; 32], value: &[u8]) -> Result<(), IndexerDbError> {
    self.db.raw().put_cf(self.db.cf_indexer(), key, value)?;
    Ok(())
}

pub fn delete(&self, key: &[u8; 32]) -> Result<(), IndexerDbError> {
    self.db.raw().delete_cf(self.db.cf_indexer(), key)?;
    Ok(())
}

pub fn write_batch(&self, batch: WriteBatch) -> Result<(), IndexerDbError> {
    self.db.raw().write(batch)?;
    Ok(())
}

pub fn new_batch(&self) -> WriteBatch {
    WriteBatch::default()
}
```

For `get_progress_u32` and `get_progress_u64`, they call `self.get(key)?` — those already delegate to `get()` above so no change needed.
For `set_progress_u32` and `set_progress_u64`, they call `self.put(key, ...)` — same.

For batches built and written internally: when callers call `db.new_batch()` → build with `batch.put_cf(db.cf_indexer(), key, val)` they'll need the CF handle. But wait — the current `new_batch` returns just a raw `WriteBatch`. The batch-building callers in `ergo-indexer` need to put into the right CF. Let me check how `write_batch` is used...

Actually looking at the design, `new_batch()` returns a `WriteBatch` and callers build it themselves. The callers in `ergo-indexer/src/segment.rs` and `ergo-indexer/src/indexer.rs` call `db.new_batch()`, then `batch.put(&key, val)`. After this change, they need to use `batch.put_cf(db.cf_indexer(), &key, val)` instead of `batch.put(&key, val)`.

So this task also requires updating `ergo-indexer/src/segment.rs` and `ergo-indexer/src/indexer.rs` wherever they build batches. The pattern change is:

```rust
// BEFORE (no CF — uses default):
batch.put(&key, val);
batch.delete(&key);

// AFTER (explicit CF):
batch.put_cf(db.cf_indexer(), &key, val);
batch.delete_cf(db.cf_indexer(), &key);
```

Search for all `batch.put(` and `batch.delete(` in `ergo-indexer/src/` and update them.

Also add `From<rocksdb::Error>` for `IndexerDbError` if not already present (it should be via `#[from]`).

**Step 4: Run all indexer tests**

```bash
cargo test -p ergo-indexer 2>&1 | tail -10
```
Expected: all tests pass.

**Step 5: Check full workspace**

```bash
cargo check --workspace 2>&1 | tail -5
```

**Step 6: Commit**

```bash
git add crates/ergo-indexer/src/db.rs crates/ergo-indexer/src/segment.rs crates/ergo-indexer/src/indexer.rs
git commit -m "refactor(indexer): ExtraIndexerDb wraps Arc<NodeDb>, uses CF_INDEXER column family"
```

---

### Task 5: Refactor `SnapshotsDb` to wrap `Arc<NodeDb>`

**Files:**
- Modify: `crates/ergo-node/src/snapshots.rs`

**Background:** `SnapshotsDb` holds `db: rocksdb::DB`. It moves to `Arc<NodeDb>` using `CF_SNAPSHOTS`. Pattern is identical to the previous tasks. The `ergo-node` crate already depends on `ergo-storage`.

**Step 1: Write the failing test**

Add to the `#[cfg(test)]` block (or create one) in `crates/ergo-node/src/snapshots.rs`:

```rust
#[cfg(test)]
mod snapshot_db_tests {
    use super::*;
    use std::sync::Arc;
    use ergo_storage::node_db::NodeDb;

    #[test]
    fn from_shared_snapshots_db() {
        let tmp = tempfile::tempdir().unwrap();
        let node_db = Arc::new(NodeDb::open(tmp.path()).unwrap());
        let db1 = SnapshotsDb::from_shared(node_db.clone());
        let db2 = SnapshotsDb::from_shared(node_db.clone());

        // Write a raw key-value via db1's raw access, read via db2.
        let cf = node_db.cf_snapshots();
        node_db.raw().put_cf(cf, b"snap-key", b"snap-val").unwrap();
        let val = node_db.raw().get_cf(cf, b"snap-key").unwrap();
        assert_eq!(val.as_deref(), Some(b"snap-val".as_slice()));
        // Both db1 and db2 are valid (no panic on construction).
        let _ = db1;
        let _ = db2;
    }
}
```

**Step 2: Run test to verify it fails**

```bash
cargo test -p ergo-node from_shared_snapshots_db 2>&1 | tail -5
```

**Step 3: Implement the refactored `SnapshotsDb`**

In `crates/ergo-node/src/snapshots.rs`, find the `SnapshotsDb` struct (search for `pub struct SnapshotsDb`). Change:

```rust
// ADD import at top of file:
use std::sync::Arc;
use ergo_storage::node_db::NodeDb;

// BEFORE:
pub struct SnapshotsDb {
    db: rocksdb::DB,
}

// AFTER:
pub struct SnapshotsDb {
    db: Arc<NodeDb>,
}
```

Replace constructors in `impl SnapshotsDb`:
```rust
/// Standalone open — creates its own NodeDb. Used in tests.
pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, SnapshotError> {
    let db = NodeDb::open(path).map_err(|e| SnapshotError::Storage(e.to_string()))?;
    Ok(Self { db: Arc::new(db) })
}

/// Wraps a shared NodeDb.
pub fn from_shared(db: Arc<NodeDb>) -> Self {
    Self { db }
}
```

For all operations in `SnapshotsDb` that use `self.db.get(key)`, `self.db.put(key, val)`, `self.db.delete(key)`, `self.db.write(batch)`, `self.db.iterator(...)` — apply the same pattern:

```rust
// BEFORE:
self.db.put(&key, &value).map_err(|e| SnapshotError::Storage(e.to_string()))?;
self.db.get(&key).map_err(|e| SnapshotError::Storage(e.to_string()))?;

// AFTER:
let cf = self.db.cf_snapshots();
self.db.raw().put_cf(cf, &key, &value).map_err(|e| SnapshotError::Storage(e.to_string()))?;
self.db.raw().get_cf(cf, &key).map_err(|e| SnapshotError::Storage(e.to_string()))?;
```

For iterator in `SnapshotsDb`:
```rust
// BEFORE:
self.db.iterator(rocksdb::IteratorMode::Start)

// AFTER:
self.db.raw().iterator_cf(self.db.cf_snapshots(), rocksdb::IteratorMode::Start)
```

For `WriteBatch` operations, batches need CF-prefixed puts:
```rust
batch.put_cf(self.db.cf_snapshots(), &key, &val);
```

**Step 4: Run tests**

```bash
cargo test -p ergo-node 2>&1 | tail -10
```

**Step 5: Check full workspace**

```bash
cargo check --workspace 2>&1 | tail -5
```

**Step 6: Commit**

```bash
git add crates/ergo-node/src/snapshots.rs
git commit -m "refactor(node): SnapshotsDb wraps Arc<NodeDb>, uses CF_SNAPSHOTS column family"
```

---

### Task 6: Update `main.rs` to use one shared `NodeDb`

**Files:**
- Modify: `crates/ergo-node/src/main.rs`

**Background:** Currently `main.rs` opens 6+ separate DB handles (history R/W, history read-only ×2, UTXO, indexer, indexer read-only, snapshots). After this task it opens **one** `NodeDb` and passes `Arc<NodeDb>` clones to all subsystems via `from_shared`. The secondary history path (`history_sync_secondary/`) is no longer created.

Data path changes: old `.ergo/history/` → new `.ergo/node/`. Add startup detection: if `.ergo/history/` exists but `.ergo/node/` does not, print an error and exit with instructions.

**Step 1: No pre-written test** — this task's correctness is verified by `cargo check` + running the node.

**Step 2: Implement**

At the top of `main.rs`, add import:
```rust
use ergo_storage::node_db::NodeDb;
```

Find the line:
```rust
let db_path = Path::new(&settings.ergo.directory).join("history");
```

Replace the entire block from `let db_path = ...` through to the creation of `api_history` and `sync_history` (approximately lines 87–112) with:

```rust
let data_dir = Path::new(&settings.ergo.directory);

// Detect old DB format and refuse to start — user must re-sync.
let old_history_path = data_dir.join("history");
let node_db_path = data_dir.join("node");
if old_history_path.exists() && !node_db_path.exists() {
    tracing::error!(
        old_path = %old_history_path.display(),
        new_path = %node_db_path.display(),
        "Old database format detected. The storage layout has changed. \
         Please delete your data directory ({}) and re-sync from the network.",
        data_dir.display()
    );
    std::process::exit(1);
}

// Open the single shared NodeDb — all subsystems share this instance.
let node_db = Arc::new(
    NodeDb::open(&node_db_path)
        .unwrap_or_else(|e| panic!("cannot open node database: {e}")),
);

// Create HistoryDb wrapper for initial state logging.
{
    let history = HistoryDb::from_shared(node_db.clone());
    let best_header = history.best_header_id().unwrap();
    let best_block = history.best_full_block_id().unwrap();
    tracing::info!(best_header = ?best_header, best_block = ?best_block, "database opened");
}

// HistoryDb for the HTTP API — same Arc<NodeDb>, no separate handle needed.
let api_history = HistoryDb::from_shared(node_db.clone());

// HistoryDb for the event loop sync protocol.
let sync_history = HistoryDb::from_shared(node_db.clone());
```

Remove the `sync_secondary_path` lines:
```rust
// DELETE these lines:
let sync_secondary_path = Path::new(&settings.ergo.directory).join("history_sync_secondary");
std::fs::create_dir_all(&sync_secondary_path)...
let sync_history = HistoryDb::open_as_secondary(...)...
```

In the processor thread closure, replace:
```rust
// BEFORE:
let history = HistoryDb::open(&proc_db_path)
    .unwrap_or_else(|e| panic!("processor: cannot open database: {e}"));
...
let utxo_path = Path::new(&proc_settings.ergo.directory).join("utxo");
match ergo_storage::utxo_db::UtxoDb::open(&utxo_path) { ... }
let fresh_db = ergo_storage::utxo_db::UtxoDb::open(&utxo_path).unwrap();

// AFTER (proc_node_db is a clone of Arc<NodeDb> moved into the closure):
let history = HistoryDb::from_shared(proc_node_db.clone());
...
// No utxo_path needed — UTXO is in CF_UTXO of the shared DB.
match ergo_storage::utxo_db::UtxoDb::from_shared(proc_node_db.clone()) ... {
    // (the outer match now just checks metadata — no separate open)
}
let fresh_db = ergo_storage::utxo_db::UtxoDb::from_shared(proc_node_db.clone());
```

To move `Arc<NodeDb>` into the processor closure, clone it before `std::thread::Builder::new()`:
```rust
let proc_node_db = node_db.clone();
let processor_handle = std::thread::Builder::new()
    .name("block-processor".into())
    .spawn(move || {
        block_processor::run_processor_with_state(cmd_rx, evt_tx, move || {
            let history = HistoryDb::from_shared(proc_node_db.clone());
            ...
```

For the UtxoDb section in the processor: the original code did `UtxoDb::open(&utxo_path)` twice (once to check metadata, once for fresh). Replace both with `UtxoDb::from_shared(proc_node_db.clone())`. The `UtxoDb` returned by `restore_from_db` takes ownership, so you still need two separate `from_shared` calls (each gives a new `UtxoDb` wrapper over the same `Arc<NodeDb>`).

For the indexer:
```rust
// BEFORE:
let extra_path = Path::new(&settings.ergo.directory).join("history").join("extra");
let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path)...;
let idx_history = Arc::new(HistoryDb::open_read_only(&db_path)...);
...
let extra_db_api = ergo_indexer::db::ExtraIndexerDb::open_read_only(&extra_path)...;

// AFTER:
let extra_db = ergo_indexer::db::ExtraIndexerDb::from_shared(node_db.clone());
let idx_history = Arc::new(HistoryDb::from_shared(node_db.clone()));
...
let extra_db_api = ergo_indexer::db::ExtraIndexerDb::from_shared(node_db.clone());
```

For snapshots:
```rust
// BEFORE:
let snap_path = Path::new(&settings.ergo.directory).join("snapshots");
match snapshots::SnapshotsDb::open(&snap_path) { ... }

// AFTER:
match snapshots::SnapshotsDb::from_shared(node_db.clone()) { ... }
// (no snap_path needed)
```

Also remove the now-unused `proc_db_path` variable and all `utxo_path` / `extra_path` / `snap_path` variables.

Update `ApiState` — `history` field is `Arc<HistoryDb>`:
```rust
let api_state = ApiState {
    history: Arc::new(api_history),  // api_history is already HistoryDb::from_shared
    ...
};
```

**Step 3: Verify compilation**

```bash
cargo check -p ergo-node 2>&1 | tail -10
```
Fix all remaining compile errors.

**Step 4: Run full test suite**

```bash
cargo test --workspace 2>&1 | tail -10
```
Expected: all existing tests pass. Tests that use `HistoryDb::open(tempdir)` create their own standalone `NodeDb` — no changes needed there.

**Step 5: Build release binary**

```bash
cargo build --release -p ergo-node 2>&1 | tail -5
```
Expected: `Finished release profile`.

**Step 6: Commit**

```bash
git add crates/ergo-node/src/main.rs
git commit -m "refactor(node): main.rs uses single shared NodeDb, removes separate DB handles and secondary path"
```

---

### Task 7: Final verification

**Step 1: Run clippy**

```bash
cargo clippy --workspace -- -D warnings 2>&1 | tail -20
```
Fix any warnings (unused imports from old `rocksdb::{DB}` usage, etc.).

**Step 2: Run fmt check**

```bash
cargo fmt --check 2>&1
```
Run `cargo fmt` if any formatting issues.

**Step 3: Run full test suite**

```bash
cargo test --workspace 2>&1 | tail -10
```
Expected: all tests pass.

**Step 4: Verify old `set_max_open_files` calls are gone**

```bash
grep -rn "set_max_open_files" crates/ --include="*.rs"
```
Expected: only `node_db.rs` should have `set_max_open_files(4096)`. If any other file still has it, remove it (it was only needed for the old per-DB workaround).

**Step 5: Commit cleanup**

```bash
cargo fmt
git add -u
git commit -m "chore(storage): cleanup clippy warnings and formatting after single-DB refactor"
```

# Single-DB Refactor Design

**Goal:** Replace 5 separate RocksDB instances with one shared `NodeDb` using named column families, eliminating FD exhaustion and enabling cross-store atomic writes.

**Architecture:** One `NodeDb` struct in `ergo-storage` wraps a single `DBWithThreadMode<MultiThreaded>` with 5 column families. Existing structs (`HistoryDb`, `UtxoDb`, `ExtraIndexerDb`, `SnapshotsDb`) become thin wrappers holding `Arc<NodeDb>`. Their public APIs are unchanged, so all callers (event loop, node view, API handlers, tests) require no modification.

**Tech stack:** `rocksdb` crate, `DBWithThreadMode<MultiThreaded>` for thread safety, `Arc<NodeDb>` for shared ownership.

---

## Column Families

| CF constant | Name | Contents | Tuning |
|-------------|------|----------|--------|
| `CF_OBJECTS` | `"objects"` | Block sections keyed by `[type_id][ModifierId]` | Write-heavy, LZ4 compression, bloom filter, 16KB blocks |
| `CF_INDEXES` | `"indexes"` | History metadata: height index, best header, state version, continuation IDs | Small writes, frequent point reads |
| `CF_UTXO` | `"utxo"` | UTXO set: `box_id → serialized ErgoBox` | Point-lookup optimized, large block cache |
| `CF_INDEXER` | `"indexer"` | Extra indexer: segments, tokens, progress counters | Similar to indexes |
| `CF_SNAPSHOTS`| `"snapshots"` | Snapshot manifests and chunk data | Large values, sequential access |

Wallet DBs (`wallet_storage`, `wallet_registry`) stay separate — wallet is optional and users back it up independently.

---

## `NodeDb` API

```rust
// ergo-storage/src/node_db.rs

pub struct NodeDb {
    db: DBWithThreadMode<MultiThreaded>,
}

impl NodeDb {
    /// Open (or create) the node DB at `path` with all 5 CFs.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError>;

    // CF handle accessors (used internally by wrapper structs)
    pub(crate) fn cf_objects(&self) -> &ColumnFamily;
    pub(crate) fn cf_indexes(&self) -> &ColumnFamily;
    pub(crate) fn cf_utxo(&self)    -> &ColumnFamily;
    pub(crate) fn cf_indexer(&self) -> &ColumnFamily;
    pub(crate) fn cf_snapshots(&self) -> &ColumnFamily;

    // Generic operations — wrappers call these with their CF
    pub fn get_cf(&self, cf: &ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;
    pub fn put_cf(&self, cf: &ColumnFamily, key: &[u8], val: &[u8]) -> Result<(), StorageError>;
    pub fn delete_cf(&self, cf: &ColumnFamily, key: &[u8]) -> Result<(), StorageError>;
    pub fn write(&self, batch: WriteBatch) -> Result<(), StorageError>;
    pub fn new_batch(&self) -> WriteBatch;
    pub fn iterator_cf(&self, cf: &ColumnFamily, mode: IteratorMode) -> DBIteratorWithThreadMode<...>;
}
```

`NodeDb` is `Send + Sync` (via `MultiThreaded`), so `Arc<NodeDb>` can be cloned freely across threads — no read-only or secondary handles needed.

---

## Wrapper Pattern

Each existing struct gains a `from_shared` constructor and keeps its `open` constructor (which internally creates its own `NodeDb`). This means **all test code that calls `HistoryDb::open(tempdir)` continues to work unchanged**.

```rust
pub struct HistoryDb { db: Arc<NodeDb> }

impl HistoryDb {
    /// Standalone open — creates its own NodeDb. Used in tests.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        Ok(Self { db: Arc::new(NodeDb::open(path)?) })
    }
    /// Shared open — wraps an existing NodeDb. Used in production.
    pub fn from_shared(db: Arc<NodeDb>) -> Self { Self { db } }
}
```

Same pattern for `UtxoDb`, `ExtraIndexerDb`, `SnapshotsDb`.

---

## Changes to `main.rs`

Before (6 separate DB opens, including read-only and secondary handles):
```rust
let history     = HistoryDb::open(&db_path)?;
let api_history = HistoryDb::open_read_only(&db_path)?;
let sync_history = HistoryDb::open_as_secondary(&db_path, &secondary_path)?;
let utxo        = UtxoDb::open(&utxo_path)?;
let extra_db    = ExtraIndexerDb::open(&extra_path)?;
let extra_db_api = ExtraIndexerDb::open_read_only(&extra_path)?;
let snapshots   = SnapshotsDb::open(&snap_path)?;
```

After (one NodeDb, all wrappers share it):
```rust
let node_db  = Arc::new(NodeDb::open(data_dir.join("node"))?);
let history  = HistoryDb::from_shared(node_db.clone());  // block processor + API + sync
let utxo     = UtxoDb::from_shared(node_db.clone());     // block processor
let extra_db = ExtraIndexerDb::from_shared(node_db.clone()); // indexer + API
let snapshots = SnapshotsDb::from_shared(node_db.clone()); // snapshots
```

`open_read_only` and `open_as_secondary` methods are removed. The API and sync manager receive `Arc<NodeDb>`-backed wrappers directly — no separate handles.

---

## Data Path Change

| Old path | New path |
|----------|----------|
| `.ergo/history/` | `.ergo/node/` (all CFs) |
| `.ergo/utxo/` | merged into `.ergo/node/` |
| `.ergo/history/extra/` | merged into `.ergo/node/` |
| `.ergo/snapshots/` | merged into `.ergo/node/` |
| `.ergo/history_secondary/` | removed |

On startup, if `.ergo/history/` exists but `.ergo/node/` does not, print a clear warning and exit with instructions to delete `.ergo/` and re-sync. No migration script — still in development.

---

## Cross-Store Atomic Writes (Future Benefit)

With all data in one DB, a single `WriteBatch` can update history + UTXO atomically:

```rust
let mut batch = node_db.new_batch();
batch.put_cf(node_db.cf_indexes(), &state_version_key, &block_id.0);
batch.put_cf(node_db.cf_utxo(), &box_id, &box_bytes);
batch.delete_cf(node_db.cf_utxo(), &spent_box_id);
node_db.write(batch)?;
```

This eliminates a class of crash-recovery bugs where history and UTXO diverge.

---

## Testing Strategy

- All existing unit tests in `ergo-storage`, `ergo-indexer`, `ergo-state` use `HistoryDb::open(tempdir)` / `UtxoDb::open(tempdir)` / `ExtraIndexerDb::open(tempdir)` — **no changes needed** because `open()` still works standalone.
- Add one `NodeDb` unit test: open, write to two CFs in one batch, verify reads.
- Run full `cargo test --workspace` after each task to catch regressions.

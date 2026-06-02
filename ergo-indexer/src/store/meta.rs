//! Indexer meta-key persistence.
//!
//! Five fixed string keys live under `INDEXER_META`:
//! - `schema_version` (4-byte big-endian u32)
//! - `indexed_height` (8-byte big-endian u64)
//! - `indexed_header_id` (32 bytes, or 0 bytes for `None`)
//! - `global_tx_index` (8-byte big-endian u64)
//! - `global_box_index` (8-byte big-endian u64)

use ergo_primitives::digest::Digest32;
use redb::{ReadableTable, WriteTransaction};

use crate::error::IndexerError;
use crate::store::tables::INDEXER_META;
use crate::HeaderId;

/// Bumped any time the on-disk format changes incompatibly. A bump
/// triggers the wipe/resume table's `schema_version mismatch` row:
/// the file is deleted and recreated, forcing a full resync. New
/// tables introduced at the current version are lazy-created on first
/// apply (`WriteTransaction::open_table` is create-or-open in redb
/// 2.x), so the wipe-and-resync path is the only mechanism that
/// backfills them — older DBs are deleted on first boot, never
/// migrated in place.
pub const INDEXER_SCHEMA_VERSION: u32 = 2;

pub(crate) const KEY_SCHEMA_VERSION: &str = "schema_version";
pub(crate) const KEY_INDEXED_HEIGHT: &str = "indexed_height";
pub(crate) const KEY_INDEXED_HEADER_ID: &str = "indexed_header_id";
pub(crate) const KEY_GLOBAL_TX_INDEX: &str = "global_tx_index";
pub(crate) const KEY_GLOBAL_BOX_INDEX: &str = "global_box_index";

/// In-memory mirror of the meta-key set. Read on boot, mutated per
/// block during apply/rollback, then written back inside the same
/// `WriteTransaction` that wrote the per-type rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexerMeta {
    pub indexed_height: u64,
    pub indexed_header_id: Option<HeaderId>,
    pub global_tx_index: u64,
    pub global_box_index: u64,
}

impl IndexerMeta {
    /// Initial state on a fresh / wiped DB: nothing indexed yet.
    pub fn empty() -> Self {
        Self {
            indexed_height: 0,
            indexed_header_id: None,
            global_tx_index: 0,
            global_box_index: 0,
        }
    }
}

/// Read the persisted `schema_version`. Differentiates "table missing"
/// (`Err(IndexerError::SchemaTableMissing)` → caller halts
/// `DbCorruption`) from "key missing inside the table" (`Ok(None)` →
/// caller halts `SchemaCorruption`).
pub(crate) fn read_schema_version(
    read_txn: &redb::ReadTransaction,
) -> Result<Option<u32>, IndexerError> {
    // Only the literal `TableDoesNotExist` arm is "schema table absent";
    // every other TableError shape (TableTypeMismatch, TypeDefinitionChanged,
    // Storage(io_err), etc.) is real DB-level corruption and must
    // propagate as a typed `Db(redb::Error)` so operators can tell a
    // missing table from a malformed one.
    let table = match read_txn.open_table(INDEXER_META) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(IndexerError::SchemaTableMissing)
        }
        Err(other) => return Err(other.into()),
    };
    let guard = table.get(KEY_SCHEMA_VERSION)?;
    let Some(g) = guard else { return Ok(None) };
    let bytes = g.value();
    if bytes.len() != 4 {
        return Err(IndexerError::DbRowLength {
            context: "schema_version",
            expected: 4,
            got: bytes.len(),
        });
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(bytes);
    Ok(Some(u32::from_be_bytes(buf)))
}

pub(crate) fn write_schema_version(
    write_txn: &WriteTransaction,
    version: u32,
) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(INDEXER_META)?;
    let v = version.to_be_bytes();
    table.insert(KEY_SCHEMA_VERSION, v.as_slice())?;
    Ok(())
}

pub(crate) fn read_meta(read_txn: &redb::ReadTransaction) -> Result<IndexerMeta, IndexerError> {
    let table = read_txn.open_table(INDEXER_META)?;

    let indexed_height = read_u64(&table, KEY_INDEXED_HEIGHT)?.unwrap_or(0);
    let global_tx_index = read_u64(&table, KEY_GLOBAL_TX_INDEX)?.unwrap_or(0);
    let global_box_index = read_u64(&table, KEY_GLOBAL_BOX_INDEX)?.unwrap_or(0);
    let indexed_header_id = match table.get(KEY_INDEXED_HEADER_ID)? {
        None => None,
        Some(g) => {
            let bytes = g.value();
            if bytes.is_empty() {
                None
            } else if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                Some(Digest32::from_bytes(arr))
            } else {
                // Stored value is allowed to be 0 bytes (None) or 32
                // bytes (Some). Reaching here means the row is neither
                // — classify against the non-empty expected width.
                return Err(IndexerError::DbRowLength {
                    context: "indexed_header_id",
                    expected: 32,
                    got: bytes.len(),
                });
            }
        }
    };

    Ok(IndexerMeta {
        indexed_height,
        indexed_header_id,
        global_tx_index,
        global_box_index,
    })
}

pub(crate) fn write_meta(
    write_txn: &WriteTransaction,
    meta: &IndexerMeta,
) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(INDEXER_META)?;

    let h = meta.indexed_height.to_be_bytes();
    table.insert(KEY_INDEXED_HEIGHT, h.as_slice())?;
    let tx_idx = meta.global_tx_index.to_be_bytes();
    table.insert(KEY_GLOBAL_TX_INDEX, tx_idx.as_slice())?;
    let box_idx = meta.global_box_index.to_be_bytes();
    table.insert(KEY_GLOBAL_BOX_INDEX, box_idx.as_slice())?;

    let empty: &[u8] = &[];
    let header_bytes: &[u8] = match &meta.indexed_header_id {
        Some(id) => id.as_bytes().as_slice(),
        None => empty,
    };
    table.insert(KEY_INDEXED_HEADER_ID, header_bytes)?;
    Ok(())
}

fn read_u64<T>(table: &T, key: &'static str) -> Result<Option<u64>, IndexerError>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    // `key` doubles as the row-corruption context so the operator can
    // tell which of `indexed_height` / `global_tx_index` /
    // `global_box_index` is malformed without reproducing it.
    let guard = table.get(key)?;
    let Some(g) = guard else { return Ok(None) };
    let bytes = g.value();
    if bytes.len() != 8 {
        return Err(IndexerError::DbRowLength {
            context: key,
            expected: 8,
            got: bytes.len(),
        });
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    Ok(Some(u64::from_be_bytes(buf)))
}

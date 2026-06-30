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

/// Sticky "the derived template/token segments are degraded; rebuild them"
/// marker. Set (atomically, in the block-apply / rollback write txn) the first
/// time a secondary sign-flip is skipped on a topology drift; checked by the
/// indexer task before it transitions to `CaughtUp`, which runs the chain-free
/// secondary-index rebuild and clears the marker on success. Deliberately NOT a
/// field of [`IndexerMeta`] / `UndoEntry`: `write_meta` only rewrites its four
/// known keys and rollback only restores the `UndoEntry` fields, so this extra
/// key survives a reorg meta-restore — it is sticky until a rebuild clears it.
pub(crate) const KEY_SECONDARY_REPAIR_PENDING: &str = "secondary_repair_pending";
/// Chunk checkpoint for an in-progress rebuild: the next global box index to
/// process. Lets a crash mid-rebuild resume instead of restarting. Absent /
/// 0 = start from the beginning.
pub(crate) const KEY_SECONDARY_REPAIR_NEXT_GI: &str = "secondary_repair_next_gi";
/// Running count of boxes the rebuild had to SKIP because their primary
/// `INDEXED_BOX` row could not be decoded even by the trusted/lenient reader
/// (genuine row corruption). Persisted with each chunk checkpoint so it survives
/// a crash + resume, and KEPT after a completed-with-skips rebuild as the durable
/// "the repaired index is knowingly incomplete" signal. Absent = 0.
pub(crate) const KEY_SECONDARY_REPAIR_SKIPPED: &str = "secondary_repair_skipped";

/// Mark the derived (template/token) secondary index as degraded so the task
/// rebuilds it before serving. Idempotent. Written in the SAME write txn as the
/// block apply/rollback that skipped the flip, so the marker is durable iff the
/// degraded block committed.
pub(crate) fn set_secondary_repair_pending(
    write_txn: &WriteTransaction,
) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(INDEXER_META)?;
    table.insert(KEY_SECONDARY_REPAIR_PENDING, [1u8].as_slice())?;
    Ok(())
}

/// Whether a secondary-index rebuild is pending (marker present and truthy).
pub(crate) fn read_secondary_repair_pending(
    read_txn: &redb::ReadTransaction,
) -> Result<bool, IndexerError> {
    let table = read_txn.open_table(INDEXER_META)?;
    Ok(table
        .get(KEY_SECONDARY_REPAIR_PENDING)?
        .map(|g| g.value().first().copied().unwrap_or(0) != 0)
        .unwrap_or(false))
}

/// Persist the rebuild chunk checkpoint (next global box index to process).
pub(crate) fn write_secondary_repair_next_gi(
    write_txn: &WriteTransaction,
    next_gi: u64,
) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(INDEXER_META)?;
    table.insert(
        KEY_SECONDARY_REPAIR_NEXT_GI,
        next_gi.to_be_bytes().as_slice(),
    )?;
    Ok(())
}

/// Read the rebuild chunk checkpoint as an Option: `None` when the key is
/// absent (no rebuild started yet → Phase 0 wipe must run first), `Some(gi)`
/// when a rebuild is in progress (resume Phase 1 from `gi`, skip the wipe). The
/// `None`-vs-`Some(0)` distinction is what makes a crashed rebuild resume
/// correctly instead of re-wiping the partial progress.
pub(crate) fn read_secondary_repair_next_gi_opt(
    read_txn: &redb::ReadTransaction,
) -> Result<Option<u64>, IndexerError> {
    let table = read_txn.open_table(INDEXER_META)?;
    read_u64(&table, KEY_SECONDARY_REPAIR_NEXT_GI)
}

/// Persist the running skipped-box count (undecodable primary rows the rebuild
/// stepped over). Written with each chunk checkpoint and at Phase-0 reset.
pub(crate) fn write_secondary_repair_skipped(
    write_txn: &WriteTransaction,
    skipped: u64,
) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(INDEXER_META)?;
    table.insert(KEY_SECONDARY_REPAIR_SKIPPED, skipped.to_be_bytes().as_slice())?;
    Ok(())
}

/// Read the durable skipped-box count: `0` when the key is absent (no rebuild has
/// skipped anything) or explicitly zero. A non-zero value persists after a
/// completed rebuild as the "knowingly incomplete" signal.
pub(crate) fn read_secondary_repair_skipped(
    read_txn: &redb::ReadTransaction,
) -> Result<u64, IndexerError> {
    let table = read_txn.open_table(INDEXER_META)?;
    Ok(read_u64(&table, KEY_SECONDARY_REPAIR_SKIPPED)?.unwrap_or(0))
}

/// Remove the skipped-box record — called on a fully-clean (zero-skip) rebuild
/// completion so the key does not linger.
pub(crate) fn clear_secondary_repair_skipped(
    write_txn: &WriteTransaction,
) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(INDEXER_META)?;
    table.remove(KEY_SECONDARY_REPAIR_SKIPPED)?;
    Ok(())
}

/// Clear both rebuild marker keys — called only inside the FINAL successful
/// rebuild commit, so the index is fully repaired before the pending flag drops.
/// The skipped-box record (if any) is managed separately so a completed-with-skips
/// rebuild can retain it.
pub(crate) fn clear_secondary_repair(write_txn: &WriteTransaction) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(INDEXER_META)?;
    table.remove(KEY_SECONDARY_REPAIR_PENDING)?;
    table.remove(KEY_SECONDARY_REPAIR_NEXT_GI)?;
    Ok(())
}

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

#[cfg(test)]
mod repair_marker_tests {
    use super::*;
    use crate::store::tables::INDEXER_META;

    fn temp_db() -> (redb::Database, tempfile::TempDir) {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = redb::Database::create(tmp.path().join("m.redb")).unwrap();
        // Create INDEXER_META so the read paths can open it.
        let w = db.begin_write().unwrap();
        {
            w.open_table(INDEXER_META).unwrap();
        }
        w.commit().unwrap();
        (db, tmp)
    }

    #[test]
    fn repair_marker_set_read_clear_and_is_sticky_across_write_meta() {
        let (db, _t) = temp_db();

        // Initially clear.
        {
            let r = db.begin_read().unwrap();
            assert!(!read_secondary_repair_pending(&r).unwrap());
            assert_eq!(read_secondary_repair_next_gi_opt(&r).unwrap(), None);
        }

        // Set pending + a checkpoint.
        {
            let w = db.begin_write().unwrap();
            set_secondary_repair_pending(&w).unwrap();
            write_secondary_repair_next_gi(&w, 12_345).unwrap();
            w.commit().unwrap();
        }
        {
            let r = db.begin_read().unwrap();
            assert!(read_secondary_repair_pending(&r).unwrap());
            assert_eq!(read_secondary_repair_next_gi_opt(&r).unwrap(), Some(12_345));
        }

        // CRITICAL: a normal block-meta write must NOT clear the sticky marker
        // (this is what makes it survive a reorg's meta-restore).
        {
            let w = db.begin_write().unwrap();
            write_meta(&w, &IndexerMeta::empty()).unwrap();
            w.commit().unwrap();
        }
        {
            let r = db.begin_read().unwrap();
            assert!(
                read_secondary_repair_pending(&r).unwrap(),
                "write_meta must not clear the sticky repair marker"
            );
            assert_eq!(read_secondary_repair_next_gi_opt(&r).unwrap(), Some(12_345));
        }

        // Clear (only the rebuild does this on success).
        {
            let w = db.begin_write().unwrap();
            clear_secondary_repair(&w).unwrap();
            w.commit().unwrap();
        }
        {
            let r = db.begin_read().unwrap();
            assert!(!read_secondary_repair_pending(&r).unwrap());
            assert_eq!(read_secondary_repair_next_gi_opt(&r).unwrap(), None);
        }
    }
}

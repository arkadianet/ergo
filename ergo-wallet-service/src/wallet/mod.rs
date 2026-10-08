//! Wallet persistence layer: tracked-pubkey/box/transaction storage
//! that lives alongside chain state.
//!
//! Tables live in the SAME `state.redb` as chain state. Wallet writes,
//! cursor updates, and scan-index updates are part of the same redb write
//! transaction as the corresponding chain mutation on both the synchronous
//! and persist-pipeline paths. Rollback uses the same atomic transaction.
//!
//! The `tables` submodule defines the redb `TableDefinition`
//! constants; `types` defines the value structs; `apply` and
//! `maturity` contain the chain-hook logic; `reader` exposes the
//! read-only interface the REST layer uses.

pub mod apply;
pub mod error;
pub mod hydration;
pub mod maturity;
pub mod migration;
pub mod mining_jobs;
pub mod reader;
pub mod scan;
pub mod store;
pub mod tables;
pub mod types;
pub mod utxo_scan;

use std::sync::Arc;

use redb::{Database, ReadableTable, ReadableTableMetadata, WriteTransaction};

pub use crate::wallet::error::WalletStoreError;
use crate::wallet::store::{begin_write_quick, clear_standalone_headers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletScanCursor {
    pub height: u32,
    pub header_id: Option<[u8; 32]>,
}

/// Current wallet-table schema version.
pub const WALLET_SCHEMA_VERSION: u32 = 2;

pub fn migrate_schema(db: &Arc<Database>) -> Result<(), WalletStoreError> {
    migrate_schema_with_index(db, false, None)
}

pub fn migrate_standalone_schema(db: &Arc<Database>) -> Result<(), WalletStoreError> {
    migrate_schema_with_index(db, true, None)
}

type DiscoveryAnchorReader<'a> =
    dyn Fn(&redb::ReadTransaction, u32) -> Result<Option<[u8; 32]>, WalletStoreError> + 'a;

/// The embedded chain adapter validates a discovery anchor when snapshot state
/// has no historical applied-header index at the wallet cursor.
pub fn migrate_schema_with_anchor(
    db: &Arc<Database>,
    anchor: &DiscoveryAnchorReader<'_>,
) -> Result<(), WalletStoreError> {
    migrate_schema_with_index(db, false, Some(anchor))
}

fn migrate_schema_with_index(
    db: &Arc<Database>,
    standalone: bool,
    anchor: Option<&DiscoveryAnchorReader<'_>>,
) -> Result<(), WalletStoreError> {
    let (version, height, stored_id) = {
        let txn = crate::wallet::store::read_redb(db)?;
        let version = match txn.open_table(tables::WALLET_SCHEMA_VERSION_TABLE) {
            Ok(table) => table.get(())?.map(|row| row.value()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(error.into()),
        };
        let height = match txn.open_table(tables::WALLET_SCAN_HEIGHT) {
            Ok(table) => table.get(())?.map(|row| row.value()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(error.into()),
        };
        let stored_id = match txn.open_table(tables::WALLET_SCAN_HEADER_ID) {
            Ok(table) => table.get(())?.map(|row| row.value()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(error.into()),
        };
        (version.unwrap_or(1), height, stored_id)
    };

    if version > WALLET_SCHEMA_VERSION {
        return Err(WalletStoreError::decode(format!(
            "wallet schema version {version} is newer than supported version {}",
            WALLET_SCHEMA_VERSION
        )));
    }

    let mut invalidate = false;
    let expected_id = match height {
        None => {
            invalidate |= stored_id.is_some();
            None
        }
        Some(0) => {
            invalidate |= stored_id.is_some();
            None
        }
        Some(height) => match read_index_header(db, height, standalone, anchor) {
            Ok(expected) if stored_id.is_some_and(|stored| stored != expected) => {
                invalidate = true;
                None
            }
            Ok(expected) => Some(expected),
            Err(WalletStoreError::Decode(_)) => {
                invalidate = true;
                None
            }
            Err(error) => return Err(error),
        },
    };

    let txn = begin_write_quick(db)?;
    {
        let mut version_table = txn.open_table(tables::WALLET_SCHEMA_VERSION_TABLE)?;
        let mut height_table = txn.open_table(tables::WALLET_SCAN_HEIGHT)?;
        let mut header_table = txn.open_table(tables::WALLET_SCAN_HEADER_ID)?;
        if invalidate {
            height_table.remove(())?;
            header_table.remove(())?;
            txn.open_table(tables::WALLET_SCAN_INVALIDATED)?
                .insert((), true)?;
        } else if let Some(header_id) = expected_id {
            header_table.insert((), header_id)?;
        } else {
            header_table.remove(())?;
        }
        version_table.insert((), WALLET_SCHEMA_VERSION)?;
        if standalone {
            if invalidate || height == Some(0) {
                // The cursor was discarded, so nothing the store recorded is
                // trustworthy: drop both directions of the applied-header index.
                clear_standalone_headers(&txn, 0)?;
            } else {
                // The reverse index is derived state. A store written by a
                // build without it (or one truncated outside a transaction)
                // would otherwise silently lose duplicate detection, so
                // reconcile it from the forward table at open. This runs once
                // per store, not per block.
                rebuild_applied_header_ids(&txn)?;
            }
        }
    }
    txn.commit()?;
    Ok(())
}

/// Rebuild the `block id -> height` reverse index from the forward
/// `height -> block id` table when the two disagree in size. Both tables are
/// maintained inside the same write transaction, so equal sizes mean they are
/// in step; a mismatch means the reverse index is missing or stale.
fn rebuild_applied_header_ids(txn: &WriteTransaction) -> Result<(), WalletStoreError> {
    let applied = txn.open_table(tables::WALLET_APPLIED_HEADERS)?;
    let mut index = txn.open_table(tables::WALLET_APPLIED_HEADER_IDS)?;
    if index.len()? == applied.len()? {
        return Ok(());
    }
    let stale: Vec<[u8; 32]> = index
        .iter()?
        .map(|entry| entry.map(|(key, _)| key.value()))
        .collect::<Result<_, _>>()?;
    for block_id in stale {
        index.remove(block_id)?;
    }
    let rows: Vec<(u64, [u8; 32])> = applied
        .iter()?
        .map(|entry| {
            let (key, value) = entry?;
            let height = key.value();
            if value.value().len() != 32 {
                return Err(WalletStoreError::decode(format!(
                    "standalone applied-header row at {height} is not 32 bytes"
                )));
            }
            let mut block_id = [0u8; 32];
            block_id.copy_from_slice(value.value());
            Ok((height, block_id))
        })
        .collect::<Result<_, WalletStoreError>>()?;
    for (height, block_id) in rows {
        index.insert(block_id, height)?;
    }
    Ok(())
}

fn read_index_header(
    db: &Database,
    height: u32,
    standalone: bool,
    anchor: Option<&DiscoveryAnchorReader<'_>>,
) -> Result<[u8; 32], WalletStoreError> {
    let txn = crate::wallet::store::read_redb(db)?;
    let table = if standalone {
        txn.open_table(tables::WALLET_APPLIED_HEADERS)
    } else {
        txn.open_table(tables::CHAIN_INDEX)
    };
    let table = match table {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            if let Some(id) = anchor.map(|read| read(&txn, height)).transpose()?.flatten() {
                return Ok(id);
            }
            return Err(WalletStoreError::decode(
                "wallet cursor points to a height without its applied-header index",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let row = match table.get(height as u64)? {
        Some(row) => row,
        None => {
            if let Some(id) = anchor.map(|read| read(&txn, height)).transpose()?.flatten() {
                return Ok(id);
            }
            return Err(WalletStoreError::decode(
                "wallet cursor points to a height without its applied-header index",
            ));
        }
    };
    let bytes = row.value();
    if bytes.len() != 32 {
        return Err(WalletStoreError::decode(format!(
            "applied-header row at {height} is not 32 bytes"
        )));
    }
    let mut header_id = [0u8; 32];
    header_id.copy_from_slice(bytes);
    Ok(header_id)
}
pub use apply::{owned_to_block_txs, BlockOutput, BlockTx, BoundBlockTxs, RescanGuard};
pub use hydration::{HydrationSource, WalletApplyHook};
pub use reader::{RewardKeyResolution, WalletReader};
pub use scan::{
    RescanBlock, RescanError, RescanReadError, RescanTx, ScanRescanMatcher, WalletScanMatcher,
    WalletScanService,
};
pub use store::{
    RedbWalletStore, RedbWalletWrite, RescanState, ScanRegistrySnapshot, StoredScan, WalletRead,
    WalletStore, WalletWrite,
};
pub use types::{
    Balance, BoxProvenance, BoxStatus, OwnedBlockOutput, OwnedBlockTxData, ScanBoxStatus,
    ScanMatchRecord, ScanTrackedBox, ScanTxRecord, TrackedPubkeyMeta, WalletApplyPayload,
    WalletBox, WalletTransaction,
};

/// Bundle of wallet-side dependencies threaded through the chain-
/// apply / chain-rollback paths. Carries the apply hook (snapshot of
/// tracked-pubkey state at block-apply time) plus the rescan guard
/// (aborts an in-progress rescan atomically with rollback). Both
/// references live on the main thread; this struct is short-lived
/// and never crosses the persist-pipeline worker boundary.
#[derive(Copy, Clone)]
pub struct WalletWiring<'a> {
    pub hook: &'a dyn WalletApplyHook,
    pub rescan_guard: &'a dyn RescanGuard,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_schema_fills_legacy_cursor_from_applied_chain() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let header_id = [0x42; 32];
        {
            let txn = db.begin_write().unwrap();
            txn.open_table(tables::CHAIN_INDEX)
                .unwrap()
                .insert(7u64, header_id.as_slice())
                .unwrap();
            txn.open_table(tables::WALLET_SCAN_HEIGHT)
                .unwrap()
                .insert((), 7u32)
                .unwrap();
            txn.commit().unwrap();
        }

        migrate_schema(&db).unwrap();

        let txn = crate::wallet::store::read_redb(&db).unwrap();
        assert_eq!(
            txn.open_table(tables::WALLET_SCHEMA_VERSION_TABLE)
                .unwrap()
                .get(())
                .unwrap()
                .map(|row| row.value()),
            Some(WALLET_SCHEMA_VERSION)
        );
        assert_eq!(
            txn.open_table(tables::WALLET_SCAN_HEADER_ID)
                .unwrap()
                .get(())
                .unwrap()
                .map(|row| row.value()),
            Some(header_id)
        );
    }

    #[test]
    fn migrate_schema_invalidates_legacy_cursor_without_chain_index() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        {
            let txn = db.begin_write().unwrap();
            txn.open_table(tables::WALLET_SCAN_HEIGHT)
                .unwrap()
                .insert((), 7u32)
                .unwrap();
            txn.commit().unwrap();
        }

        migrate_schema(&db).unwrap();
        let txn = crate::wallet::store::read_redb(&db).unwrap();
        assert!(txn
            .open_table(tables::WALLET_SCAN_INVALIDATED)
            .unwrap()
            .get(())
            .unwrap()
            .map(|row| row.value())
            .unwrap_or(false));
        assert!(txn
            .open_table(tables::WALLET_SCAN_HEIGHT)
            .unwrap()
            .get(())
            .unwrap()
            .is_none());
        assert_eq!(
            txn.open_table(tables::WALLET_SCHEMA_VERSION_TABLE)
                .unwrap()
                .get(())
                .unwrap()
                .map(|row| row.value()),
            Some(WALLET_SCHEMA_VERSION)
        );
    }

    #[test]
    fn migrate_schema_invalidates_cursor_header_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let chain_id = [0x42; 32];
        let stored_id = [0x43; 32];
        {
            let txn = db.begin_write().unwrap();
            txn.open_table(tables::CHAIN_INDEX)
                .unwrap()
                .insert(7u64, chain_id.as_slice())
                .unwrap();
            txn.open_table(tables::WALLET_SCAN_HEIGHT)
                .unwrap()
                .insert((), 7u32)
                .unwrap();
            txn.open_table(tables::WALLET_SCAN_HEADER_ID)
                .unwrap()
                .insert((), stored_id)
                .unwrap();
            txn.commit().unwrap();
        }

        migrate_schema(&db).unwrap();
        let txn = crate::wallet::store::read_redb(&db).unwrap();
        assert!(txn
            .open_table(tables::WALLET_SCAN_INVALIDATED)
            .unwrap()
            .get(())
            .unwrap()
            .map(|row| row.value())
            .unwrap_or(false));
        assert!(txn
            .open_table(tables::WALLET_SCAN_HEIGHT)
            .unwrap()
            .get(())
            .unwrap()
            .is_none());
    }
    #[test]
    fn migrate_schema_unreadable_chain_index_preserves_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let wrong_type: redb::TableDefinition<u64, u64> = redb::TableDefinition::new("chain_index");
        let txn = db.begin_write().unwrap();
        txn.open_table(wrong_type).unwrap().insert(7, 42).unwrap();
        txn.open_table(tables::WALLET_SCAN_HEIGHT)
            .unwrap()
            .insert((), 7)
            .unwrap();
        txn.open_table(tables::WALLET_SCAN_HEADER_ID)
            .unwrap()
            .insert((), [0x42; 32])
            .unwrap();
        txn.open_table(tables::WALLET_SCAN_INVALIDATED)
            .unwrap()
            .insert((), false)
            .unwrap();
        txn.open_table(tables::WALLET_SCHEMA_VERSION_TABLE)
            .unwrap()
            .insert((), 1)
            .unwrap();
        txn.commit().unwrap();

        assert!(matches!(
            migrate_schema(&db),
            Err(WalletStoreError::Database(_))
        ));
        let txn = crate::wallet::store::read_redb(&db).unwrap();
        assert_eq!(
            txn.open_table(tables::WALLET_SCAN_HEIGHT)
                .unwrap()
                .get(())
                .unwrap()
                .unwrap()
                .value(),
            7
        );
        assert_eq!(
            txn.open_table(tables::WALLET_SCAN_HEADER_ID)
                .unwrap()
                .get(())
                .unwrap()
                .unwrap()
                .value(),
            [0x42; 32]
        );
        assert!(!txn
            .open_table(tables::WALLET_SCAN_INVALIDATED)
            .unwrap()
            .get(())
            .unwrap()
            .unwrap()
            .value());
        assert_eq!(
            txn.open_table(tables::WALLET_SCHEMA_VERSION_TABLE)
                .unwrap()
                .get(())
                .unwrap()
                .unwrap()
                .value(),
            1
        );
    }

    #[test]
    fn migrate_schema_corrupt_chain_index_invalidates_cursor() {
        // Absent table, absent row, and malformed row are recoverable corruption.
        for row in [None, Some(Vec::new()), Some(vec![0x42; 31])] {
            let dir = tempfile::tempdir().unwrap();
            let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
            let txn = db.begin_write().unwrap();
            if let Some(bytes) = row {
                let mut table = txn.open_table(tables::CHAIN_INDEX).unwrap();
                if !bytes.is_empty() {
                    table.insert(7, bytes.as_slice()).unwrap();
                }
            }
            txn.open_table(tables::WALLET_SCAN_HEIGHT)
                .unwrap()
                .insert((), 7)
                .unwrap();
            txn.open_table(tables::WALLET_SCAN_HEADER_ID)
                .unwrap()
                .insert((), [0x42; 32])
                .unwrap();
            txn.commit().unwrap();

            migrate_schema(&db).unwrap();
            let read = RedbWalletStore::new(db).begin_read().unwrap();
            assert!(read.scan_invalidated().unwrap());
            assert_eq!(read.scan_cursor().unwrap(), None);
        }
    }
}

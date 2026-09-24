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
pub mod hydration;
pub mod maturity;
pub mod miner_reward;
pub mod reader;
pub mod scan;
pub mod store;
pub mod tables;
pub mod types;

use std::sync::Arc;

use redb::Database;

use crate::store::{StateError, CHAIN_INDEX};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletScanCursor {
    pub height: u32,
    pub header_id: Option<[u8; 32]>,
}

/// Current wallet-table schema version.
pub const WALLET_SCHEMA_VERSION: u32 = 2;

pub(crate) fn migrate_schema(db: &Arc<Database>) -> Result<(), StateError> {
    let (version, height, stored_id) = {
        let txn = db.begin_read()?;
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
        return Err(StateError::DbCorruption {
            table: "wallet_schema_version",
            key: String::new(),
            reason: format!("unsupported schema version {version}"),
        });
    }

    let expected_id = match height {
        None | Some(0) => None,
        Some(height) => Some(read_chain_index_header(db, height)?),
    };
    if let (Some(stored), Some(expected)) = (stored_id, expected_id) {
        if stored != expected {
            return Err(StateError::DbCorruption {
                table: "wallet_scan_header_id",
                key: String::new(),
                reason: "cursor header does not match chain_index".to_string(),
            });
        }
    }

    let txn = crate::begin_write_qr(db)?;
    {
        let mut version_table = txn.open_table(tables::WALLET_SCHEMA_VERSION_TABLE)?;
        let mut header_table = txn.open_table(tables::WALLET_SCAN_HEADER_ID)?;
        if let Some(header_id) = expected_id {
            header_table.insert((), header_id)?;
        } else {
            header_table.remove(())?;
        }
        version_table.insert((), WALLET_SCHEMA_VERSION)?;
    }
    txn.commit()?;
    Ok(())
}

fn read_chain_index_header(db: &Database, height: u32) -> Result<[u8; 32], StateError> {
    let txn = db.begin_read()?;
    let table = match txn.open_table(CHAIN_INDEX) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(StateError::DbCorruption {
                table: "chain_index",
                key: hex::encode((height as u64).to_be_bytes()),
                reason: "wallet cursor points to a height without chain_index".to_string(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let bytes = table
        .get(height as u64)?
        .ok_or_else(|| StateError::DbCorruption {
            table: "chain_index",
            key: hex::encode((height as u64).to_be_bytes()),
            reason: "wallet cursor points to a height without chain_index".to_string(),
        })?;
    let bytes = bytes.value();
    if bytes.len() != 32 {
        return Err(StateError::DbCorruption {
            table: "chain_index",
            key: hex::encode((height as u64).to_be_bytes()),
            reason: format!("row has len {} (expected 32)", bytes.len()),
        });
    }
    let mut header_id = [0u8; 32];
    header_id.copy_from_slice(bytes);
    Ok(header_id)
}
pub use apply::RescanGuard;
pub use hydration::{HydrationSource, WalletApplyHook};
pub use reader::{RewardKeyResolution, WalletReader};
pub use store::{
    RedbWalletStore, RescanState, ScanRegistrySnapshot, StoredScan, WalletRead, WalletStore,
    WalletStoreError, WalletWrite,
};
pub use types::{Balance, BoxProvenance, BoxStatus, WalletBox, WalletTransaction};

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
            txn.open_table(CHAIN_INDEX)
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

        let txn = db.begin_read().unwrap();
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
    fn migrate_schema_rejects_legacy_cursor_without_chain_index() {
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

        assert!(matches!(
            migrate_schema(&db),
            Err(StateError::DbCorruption {
                table: "chain_index",
                ..
            })
        ));
        let txn = db.begin_read().unwrap();
        assert!(txn.open_table(tables::WALLET_SCHEMA_VERSION_TABLE).is_err());
    }
}

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
pub mod reader;
pub mod scan;
pub mod store;
pub mod tables;
pub mod types;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use redb::Database;

use crate::store::{StateError, CHAIN_INDEX};

static CHAIN_APPLY_FINALIZATION_LOCK: RwLock<()> = RwLock::new(());

pub fn chain_apply_read_guard() -> RwLockReadGuard<'static, ()> {
    CHAIN_APPLY_FINALIZATION_LOCK
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn chain_apply_write_guard() -> RwLockWriteGuard<'static, ()> {
    CHAIN_APPLY_FINALIZATION_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

static WALLET_APPLY_FENCED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static WALLET_FINALIZATION_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static WALLET_FINALIZATION_OWNER: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static WALLET_APPLY_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
pub(crate) static WALLET_APPLY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn wallet_apply_generation() -> u64 {
    WALLET_APPLY_GENERATION.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn advance_wallet_apply_generation() -> u64 {
    WALLET_APPLY_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
}

pub fn wallet_apply_fenced() -> bool {
    WALLET_APPLY_FENCED.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn fence_wallet_apply() {
    WALLET_APPLY_FENCED.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub fn unfence_wallet_apply() {
    WALLET_APPLY_FENCED.store(false, std::sync::atomic::Ordering::SeqCst);
}

pub fn wallet_finalization_in_progress() -> bool {
    WALLET_FINALIZATION_IN_PROGRESS.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn wallet_finalization_owned() -> bool {
    WALLET_FINALIZATION_OWNER.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn set_wallet_finalization_in_progress(in_progress: bool) {
    WALLET_FINALIZATION_IN_PROGRESS.store(in_progress, std::sync::atomic::Ordering::SeqCst);
}

pub fn set_wallet_finalization_owned(owned: bool) {
    WALLET_FINALIZATION_OWNER.store(owned, std::sync::atomic::Ordering::SeqCst);
}

pub const WALLET_FINALIZATION_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn wait_for_wallet_finalization(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while wallet_finalization_in_progress() {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1).min(deadline.saturating_duration_since(now)));
    }
    true
}

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
        Some(height) => match read_chain_index_header(db, height) {
            Ok(expected) if stored_id.is_some_and(|stored| stored != expected) => {
                tracing::warn!(
                    height,
                    "wallet scan cursor header does not match chain_index; invalidating wallet"
                );
                invalidate = true;
                None
            }
            Ok(expected) => Some(expected),
            Err(error) => {
                tracing::warn!(
                    height,
                    %error,
                    "wallet scan cursor cannot be anchored in chain_index; invalidating wallet"
                );
                invalidate = true;
                None
            }
        },
    };

    let txn = crate::begin_write_qr(db)?;
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
pub use types::{
    Balance, BoxProvenance, BoxStatus, ScanTrackedBox, ScanTxRecord, WalletBox, WalletTransaction,
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
    fn chain_apply_finalization_lock_blocks_opposite_guards() {
        let read = chain_apply_read_guard();
        assert!(CHAIN_APPLY_FINALIZATION_LOCK.try_write().is_err());
        drop(read);
        let write = chain_apply_write_guard();
        assert!(CHAIN_APPLY_FINALIZATION_LOCK.try_read().is_err());
        drop(write);
    }

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
        let txn = db.begin_read().unwrap();
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
            txn.open_table(CHAIN_INDEX)
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
        let txn = db.begin_read().unwrap();
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
}

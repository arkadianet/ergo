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
pub mod reader;
pub mod scan;
pub mod store;
pub mod tables;
pub mod types;

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use redb::{Database, ReadableTable, ReadableTableMetadata, WriteTransaction};

pub use crate::wallet::error::WalletStoreError;
use crate::wallet::store::{begin_write_quick, clear_standalone_headers};

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

/// Give wallet finalization a bounded opportunity to finish, then let chain
/// persistence proceed with the wallet fenced. Callers must persist that fence
/// in the same transaction as the chain update, even without a wallet payload.
pub fn chain_apply_guard_after_wallet_finalization() -> RwLockReadGuard<'static, ()> {
    let started = Instant::now();
    loop {
        wait_for_wallet_finalization(
            WALLET_FINALIZATION_WAIT_TIMEOUT.saturating_sub(started.elapsed()),
        );
        let guard = chain_apply_read_guard();
        if !wallet_finalization_in_progress() {
            return guard;
        }
        if started.elapsed() >= WALLET_FINALIZATION_WAIT_TIMEOUT {
            advance_wallet_apply_generation();
            fence_wallet_apply();
            tracing::warn!("wallet finalization timed out; continuing chain persistence with wallet invalidated");
            return guard;
        }
        // A finalizer started between the wait and taking the lock. Release
        // the read lock so its owner can acquire the write lock and finish.
        drop(guard);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletScanCursor {
    pub height: u32,
    pub header_id: Option<[u8; 32]>,
}

/// Current wallet-table schema version.
pub const WALLET_SCHEMA_VERSION: u32 = 2;

pub fn migrate_schema(db: &Arc<Database>) -> Result<(), WalletStoreError> {
    migrate_schema_with_index(db, false)
}

pub fn migrate_standalone_schema(db: &Arc<Database>) -> Result<(), WalletStoreError> {
    migrate_schema_with_index(db, true)
}

fn migrate_schema_with_index(db: &Arc<Database>, standalone: bool) -> Result<(), WalletStoreError> {
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
        Some(height) => match read_index_header(db, height, standalone) {
            Ok(expected) if stored_id.is_some_and(|stored| stored != expected) => {
                invalidate = true;
                None
            }
            Ok(expected) => Some(expected),
            Err(_) => {
                invalidate = true;
                None
            }
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
) -> Result<[u8; 32], WalletStoreError> {
    let txn = db.begin_read()?;
    let table = if standalone {
        txn.open_table(tables::WALLET_APPLIED_HEADERS)
    } else {
        txn.open_table(tables::CHAIN_INDEX)
    };
    let table = match table {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Err(WalletStoreError::decode(
                "wallet cursor points to a height without its applied-header index",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let row = table.get(height as u64)?.ok_or_else(|| {
        WalletStoreError::decode(
            "wallet cursor points to a height without its applied-header index",
        )
    })?;
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

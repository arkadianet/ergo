use std::sync::Arc;

use redb::{Database, ReadTransaction, ReadableTable, ReadableTableMetadata, WriteTransaction};
use thiserror::Error;

use crate::store::{owned_to_block_txs, WalletApplyPayload};
use crate::wallet::apply::{
    apply_block_to_scans, apply_block_to_wallet, clear_scan_tracking, rollback_block_from_wallet,
    rollback_scans_from_block, set_scan_cursor,
};
use crate::wallet::maturity::{promote_matured_boxes, unpromote_matured_boxes};
use crate::wallet::reader::{
    ReservedScanBox, RewardKeyResolution, TrackedAddressMeta, WalletReader,
};
use crate::wallet::tables::WALLET_SCANS;
use crate::wallet::types::{Balance, WalletBox, WalletTransaction};
use crate::wallet::WalletScanCursor;

#[derive(Debug, Error)]
pub enum WalletStoreError {
    #[error("wallet store database error: {0}")]
    Database(#[source] Box<redb::Error>),
    #[error("wallet store decode error: {0}")]
    Decode(String),
}

impl From<redb::Error> for WalletStoreError {
    fn from(error: redb::Error) -> Self {
        Self::Database(Box::new(error))
    }
}

impl From<WalletStoreError> for redb::Error {
    fn from(error: WalletStoreError) -> Self {
        match error {
            WalletStoreError::Database(error) => *error,
            WalletStoreError::Decode(message) => redb::Error::Io(std::io::Error::other(message)),
        }
    }
}

macro_rules! impl_wallet_store_error_from {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for WalletStoreError {
                fn from(error: $error) -> Self {
                    Self::Database(Box::new(error.into()))
                }
            }
        )+
    };
}

impl_wallet_store_error_from!(
    redb::StorageError,
    redb::TableError,
    redb::TransactionError,
    redb::CommitError,
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredScan {
    pub id: u16,
    pub json: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanRegistrySnapshot {
    pub scans: Vec<StoredScan>,
    pub last_used_id: Option<u16>,
}

pub type TrackedPubkeyPath = (u64, [u8; 33], Vec<u32>);

pub trait WalletRead {
    fn scan_cursor(&self) -> Result<Option<WalletScanCursor>, WalletStoreError>;
    fn scan_invalidated(&self) -> Result<bool, WalletStoreError>;
    fn all_boxes(&self) -> Result<Vec<WalletBox>, WalletStoreError>;
    fn box_by_id(&self, box_id: &[u8; 32]) -> Result<Option<WalletBox>, WalletStoreError>;
    fn all_transactions(&self) -> Result<Vec<WalletTransaction>, WalletStoreError>;
    fn transaction_by_id(
        &self,
        tx_id: &[u8; 32],
    ) -> Result<Option<WalletTransaction>, WalletStoreError>;
    fn balance(&self) -> Result<Balance, WalletStoreError>;
    fn reserved_scan_boxes(
        &self,
        mining: bool,
        spent: bool,
    ) -> Result<Vec<ReservedScanBox>, WalletStoreError>;
    fn tracked_pubkeys_with_paths(&self) -> Result<Vec<TrackedPubkeyPath>, WalletStoreError>;
    fn tracked_addresses_with_meta(&self) -> Result<Vec<TrackedAddressMeta>, WalletStoreError>;
    fn change_address_pubkey(&self) -> Result<Option<[u8; 33]>, WalletStoreError>;
    fn resolve_reward_key(&self) -> Result<RewardKeyResolution, WalletStoreError>;
    fn registered_scan_count(&self) -> Result<usize, WalletStoreError>;
    fn scan_registry(&self) -> Result<ScanRegistrySnapshot, WalletStoreError>;
}

pub trait WalletWrite {
    fn set_scan_invalidated(&mut self, invalidated: bool) -> Result<(), WalletStoreError>;
    fn set_scan_cursor(
        &mut self,
        height: u32,
        header_id: Option<&[u8; 32]>,
    ) -> Result<(), WalletStoreError>;
    fn put_scan(
        &mut self,
        id: u16,
        json: Vec<u8>,
        last_used_id: u16,
    ) -> Result<(), WalletStoreError>;
    fn remove_scan(&mut self, id: u16, last_used_id: u16) -> Result<(), WalletStoreError>;
    fn apply_block(
        &mut self,
        height: u32,
        header_id: &[u8; 32],
        payload: &WalletApplyPayload,
    ) -> Result<(), WalletStoreError>;
    fn rollback_block(
        &mut self,
        height: u32,
        txs: &[crate::store::OwnedBlockTxData],
        invalidate: bool,
    ) -> Result<(), WalletStoreError>;
    fn commit(self: Box<Self>) -> Result<(), WalletStoreError>;
}

pub trait WalletStore: Send + Sync {
    fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError>;
    fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError>;
}

#[derive(Clone)]
pub struct RedbWalletStore {
    db: Arc<Database>,
}

impl RedbWalletStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub(crate) fn attach_write_transaction(txn: &WriteTransaction) -> RedbWalletWrite<'_> {
        RedbWalletWrite {
            owned: None,
            borrowed: Some(txn),
        }
    }
}

impl WalletStore for RedbWalletStore {
    fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
        Ok(Box::new(RedbWalletRead {
            txn: self.db.begin_read()?,
        }))
    }

    fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
        Ok(Box::new(RedbWalletWrite {
            owned: Some(crate::begin_write_qr(&self.db).map_err(redb::Error::from)?),
            borrowed: None,
        }))
    }
}

struct RedbWalletRead {
    txn: ReadTransaction,
}

impl RedbWalletRead {
    fn reader(&self) -> WalletReader<'_> {
        WalletReader::new(&self.txn)
    }
}

impl WalletRead for RedbWalletRead {
    fn scan_cursor(&self) -> Result<Option<WalletScanCursor>, WalletStoreError> {
        self.reader().scan_cursor().map_err(Into::into)
    }

    fn scan_invalidated(&self) -> Result<bool, WalletStoreError> {
        let table = match self
            .txn
            .open_table(crate::wallet::tables::WALLET_SCAN_INVALIDATED)
        {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        Ok(table.get(())?.map(|row| row.value()).unwrap_or(false))
    }

    fn all_boxes(&self) -> Result<Vec<WalletBox>, WalletStoreError> {
        self.reader().all_boxes().map_err(Into::into)
    }

    fn box_by_id(&self, box_id: &[u8; 32]) -> Result<Option<WalletBox>, WalletStoreError> {
        self.reader().box_by_id(box_id).map_err(Into::into)
    }

    fn all_transactions(&self) -> Result<Vec<WalletTransaction>, WalletStoreError> {
        self.reader().all_transactions().map_err(Into::into)
    }

    fn transaction_by_id(
        &self,
        tx_id: &[u8; 32],
    ) -> Result<Option<WalletTransaction>, WalletStoreError> {
        self.reader().transaction_by_id(tx_id).map_err(Into::into)
    }

    fn balance(&self) -> Result<Balance, WalletStoreError> {
        self.reader().balance().map_err(Into::into)
    }

    fn reserved_scan_boxes(
        &self,
        mining: bool,
        spent: bool,
    ) -> Result<Vec<ReservedScanBox>, WalletStoreError> {
        self.reader()
            .reserved_scan_boxes(mining, spent)
            .map_err(Into::into)
    }

    fn tracked_pubkeys_with_paths(&self) -> Result<Vec<TrackedPubkeyPath>, WalletStoreError> {
        self.reader()
            .tracked_pubkeys_with_paths()
            .map_err(Into::into)
    }

    fn tracked_addresses_with_meta(&self) -> Result<Vec<TrackedAddressMeta>, WalletStoreError> {
        self.reader()
            .tracked_addresses_with_meta()
            .map_err(Into::into)
    }

    fn change_address_pubkey(&self) -> Result<Option<[u8; 33]>, WalletStoreError> {
        let table = match self
            .txn
            .open_table(crate::wallet::tables::WALLET_CHANGE_ADDRESS)
        {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(table.get(())?.map(|row| row.value()))
    }

    fn resolve_reward_key(&self) -> Result<RewardKeyResolution, WalletStoreError> {
        Ok(self.reader().resolve_eip3_reward_key())
    }

    fn registered_scan_count(&self) -> Result<usize, WalletStoreError> {
        let table = match self.txn.open_table(WALLET_SCANS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        Ok(table.len()? as usize)
    }

    fn scan_registry(&self) -> Result<ScanRegistrySnapshot, WalletStoreError> {
        let scans = match self.txn.open_table(WALLET_SCANS) {
            Ok(table) => {
                let mut scans = Vec::with_capacity(table.len()? as usize);
                for entry in table.iter()? {
                    let (key, value) = entry?;
                    scans.push(StoredScan {
                        id: key.value(),
                        json: value.value().to_vec(),
                    });
                }
                scans
            }
            Err(redb::TableError::TableDoesNotExist(_)) => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        let last_used_id = match self
            .txn
            .open_table(crate::wallet::tables::WALLET_LAST_USED_SCAN_ID)
        {
            Ok(table) => table.get(())?.map(|row| row.value()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(error) => return Err(error.into()),
        };
        Ok(ScanRegistrySnapshot {
            scans,
            last_used_id,
        })
    }
}

pub(crate) struct RedbWalletWrite<'a> {
    owned: Option<WriteTransaction>,
    borrowed: Option<&'a WriteTransaction>,
}

impl<'a> RedbWalletWrite<'a> {
    fn txn(&self) -> &WriteTransaction {
        self.owned
            .as_ref()
            .or(self.borrowed)
            .expect("wallet write transaction missing")
    }
}

struct RollbackGuard {
    invalidate: bool,
}

impl crate::wallet::RescanGuard for RollbackGuard {
    fn abort_in_progress(&self, _txn: &WriteTransaction) -> Result<(), redb::Error> {
        Ok(())
    }

    fn force_invalidate(&self, txn: &WriteTransaction) -> Result<(), redb::Error> {
        if self.invalidate {
            txn.open_table(crate::wallet::tables::WALLET_SCAN_INVALIDATED)?
                .insert((), true)?;
        }
        Ok(())
    }
}

impl WalletWrite for RedbWalletWrite<'_> {
    fn set_scan_invalidated(&mut self, invalidated: bool) -> Result<(), WalletStoreError> {
        self.txn()
            .open_table(crate::wallet::tables::WALLET_SCAN_INVALIDATED)?
            .insert((), invalidated)?;
        Ok(())
    }

    fn set_scan_cursor(
        &mut self,
        height: u32,
        header_id: Option<&[u8; 32]>,
    ) -> Result<(), WalletStoreError> {
        set_scan_cursor(self.txn(), height, header_id)?;
        Ok(())
    }

    fn put_scan(
        &mut self,
        id: u16,
        json: Vec<u8>,
        last_used_id: u16,
    ) -> Result<(), WalletStoreError> {
        self.txn().open_table(WALLET_SCANS)?.insert(id, json)?;
        self.txn()
            .open_table(crate::wallet::tables::WALLET_LAST_USED_SCAN_ID)?
            .insert((), last_used_id)?;
        Ok(())
    }

    fn remove_scan(&mut self, id: u16, last_used_id: u16) -> Result<(), WalletStoreError> {
        self.txn().open_table(WALLET_SCANS)?.remove(id)?;
        self.txn()
            .open_table(crate::wallet::tables::WALLET_LAST_USED_SCAN_ID)?
            .insert((), last_used_id)?;
        Ok(())
    }

    fn apply_block(
        &mut self,
        height: u32,
        header_id: &[u8; 32],
        payload: &WalletApplyPayload,
    ) -> Result<(), WalletStoreError> {
        let bound = owned_to_block_txs(&payload.block_txs_owned);
        let txs = bound.as_block_txs();
        if payload.has_wallet_tracking() {
            apply_block_to_wallet(
                self.txn(),
                &payload.tracked_p2pk_trees,
                &payload.cached_pubkeys,
                height,
                header_id,
                &txs,
            )?;
            promote_matured_boxes(self.txn(), height)?;
        }
        if payload.has_registered_scans {
            apply_block_to_scans(self.txn(), &payload.scan_matches, &txs, height, header_id)?;
        }
        Ok(())
    }

    fn rollback_block(
        &mut self,
        height: u32,
        txs: &[crate::store::OwnedBlockTxData],
        invalidate: bool,
    ) -> Result<(), WalletStoreError> {
        let bound = owned_to_block_txs(txs);
        let block_txs = bound.as_block_txs();
        let guard = RollbackGuard { invalidate };
        rollback_block_from_wallet(self.txn(), height, &block_txs, &guard)?;
        unpromote_matured_boxes(self.txn(), height.saturating_sub(1))?;
        rollback_scans_from_block(self.txn(), &block_txs, height)?;
        if invalidate {
            clear_scan_tracking(self.txn())?;
        }
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), WalletStoreError> {
        let owned = self.owned.ok_or_else(|| {
            WalletStoreError::Decode("borrowed wallet transaction cannot commit".to_string())
        })?;
        owned.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn payload() -> (WalletApplyPayload, Vec<crate::store::OwnedBlockTxData>) {
        let txs = vec![crate::store::OwnedBlockTxData {
            tx_id: [1; 32],
            inputs: vec![],
            outputs: vec![crate::store::OwnedBlockOutput {
                box_id: [2; 32],
                output_index: 0,
                ergo_tree_bytes: vec![3],
                value: 1,
                assets: vec![],
                miner_reward_pubkey: None,
                box_bytes: vec![],
            }],
        }];
        let payload = WalletApplyPayload {
            tracked_p2pk_trees: BTreeSet::from([vec![3]]),
            cached_pubkeys: BTreeMap::new(),
            block_txs_owned: txs.clone(),
            scan_matches: Vec::new(),
            has_registered_scans: false,
        };
        (payload, txs)
    }

    #[test]
    fn redb_store_applies_and_rolls_back_wallet_payload() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::new(Arc::new(
            Database::create(dir.path().join("state.redb")).unwrap(),
        ));
        let (payload, txs) = payload();
        let header_id = [4; 32];
        let mut write = store.begin_write().unwrap();
        write.apply_block(1, &header_id, &payload).unwrap();
        write.commit().unwrap();

        let read = store.begin_read().unwrap();
        assert_eq!(read.scan_cursor().unwrap().unwrap().height, 1);
        assert_eq!(
            read.scan_cursor().unwrap().unwrap().header_id,
            Some(header_id)
        );
        assert_eq!(read.all_boxes().unwrap().len(), 1);
        assert_eq!(read.all_transactions().unwrap().len(), 1);
        drop(read);

        let mut write = store.begin_write().unwrap();
        write.rollback_block(1, &txs, false).unwrap();
        write.commit().unwrap();
        let read = store.begin_read().unwrap();
        assert_eq!(read.scan_cursor().unwrap().unwrap().height, 0);
        assert!(read.all_boxes().unwrap().is_empty());
        assert!(read.all_transactions().unwrap().is_empty());
    }

    #[test]
    fn redb_store_reads_and_writes_scan_registry() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::new(Arc::new(
            Database::create(dir.path().join("state.redb")).unwrap(),
        ));
        let mut write = store.begin_write().unwrap();
        write.put_scan(11, b"{\"scanId\":11}".to_vec(), 11).unwrap();
        write.commit().unwrap();
        let read = store.begin_read().unwrap();
        let registry = read.scan_registry().unwrap();
        assert_eq!(registry.scans[0].id, 11);
        assert_eq!(registry.last_used_id, Some(11));
    }

    #[test]
    fn redb_store_reads_and_writes_invalidation_flag() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::new(Arc::new(
            Database::create(dir.path().join("state.redb")).unwrap(),
        ));
        assert!(!store.begin_read().unwrap().scan_invalidated().unwrap());
        let mut write = store.begin_write().unwrap();
        write.set_scan_invalidated(true).unwrap();
        write.commit().unwrap();
        assert!(store.begin_read().unwrap().scan_invalidated().unwrap());
    }
}

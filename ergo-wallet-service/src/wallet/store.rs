use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::wallet::apply::{
    apply_block_to_scans, apply_block_to_scans_rescan, apply_block_to_wallet,
    apply_block_to_wallet_rescan, clear_scan_registry, clear_scan_tracking, owned_to_block_txs,
    rollback_block_from_wallet, rollback_scans_from_block, set_scan_cursor,
};
pub use crate::wallet::error::WalletStoreError;
use crate::wallet::maturity::{
    promote_matured_boxes, promote_matured_boxes_rescan, unpromote_matured_boxes,
};
use crate::wallet::reader::{
    committed_tip_in, ReservedScanBox, RewardKeyResolution, TrackedAddressMeta, WalletReader,
};
use crate::wallet::tables::{CHAIN_INDEX, WALLET_SCANS};
use crate::wallet::types::{
    Balance, BoxProvenance, BoxStatus, ScanTrackedBox, ScanTxRecord, TrackedPubkeyMeta,
    WalletApplyPayload, WalletBox, WalletTransaction,
};
use crate::wallet::WalletScanCursor;
use redb::{Database, ReadTransaction, ReadableTable, ReadableTableMetadata, WriteTransaction};

#[allow(clippy::result_large_err)]
pub(crate) fn begin_write_quick(db: &Database) -> Result<WriteTransaction, redb::TransactionError> {
    let mut txn = db.begin_write()?;
    txn.set_quick_repair(true);
    Ok(txn)
}

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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RescanState {
    Idle,
    Running { from_height: u32 },
    Failed { height: u32, reason: String },
}

pub type TrackedPubkeyPath = (u64, [u8; 33], Vec<u32>);

pub trait WalletRead {
    fn scan_cursor(&self) -> Result<Option<WalletScanCursor>, WalletStoreError>;
    fn chain_index_header(&self, height: u32) -> Result<Option<[u8; 32]>, WalletStoreError>;
    fn scan_invalidated(&self) -> Result<bool, WalletStoreError>;
    fn rescan_state(&self) -> Result<RescanState, WalletStoreError>;
    fn all_boxes(&self) -> Result<Vec<WalletBox>, WalletStoreError>;
    fn unspent_boxes(&self) -> Result<Vec<WalletBox>, WalletStoreError>;
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
    fn visible_pubkeys(&self) -> Result<Vec<(u32, [u8; 33])>, WalletStoreError>;
    fn derivation_head(&self) -> Result<u64, WalletStoreError>;
    fn change_address_pubkey(&self) -> Result<Option<[u8; 33]>, WalletStoreError>;
    fn committed_tip(&self) -> Result<Option<(u32, [u8; 32])>, WalletStoreError>;
    fn scan_boxes(&self, scan_id: u16) -> Result<Vec<ScanTrackedBox>, WalletStoreError>;
    fn scan_boxes_with_tip(
        &self,
        scan_id: u16,
    ) -> Result<(u32, Vec<ScanTrackedBox>), WalletStoreError>;
    fn reserved_scan_boxes_with_tip(
        &self,
        mining: bool,
        spent: bool,
    ) -> Result<(u32, Vec<ReservedScanBox>), WalletStoreError>;
    fn scan_transactions(&self, scan_id: u16) -> Result<Vec<ScanTxRecord>, WalletStoreError>;
    fn resolve_reward_key(&self) -> Result<RewardKeyResolution, WalletStoreError>;
    fn registered_scan_count(&self) -> Result<usize, WalletStoreError>;
    fn scan_registry(&self) -> Result<ScanRegistrySnapshot, WalletStoreError>;
}

pub trait WalletWrite {
    fn set_scan_invalidated(&mut self, invalidated: bool) -> Result<(), WalletStoreError>;
    fn clear_scan_registry(&mut self) -> Result<(), WalletStoreError>;
    fn set_rescan_state(&mut self, state: &RescanState) -> Result<(), WalletStoreError>;
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
    fn stop_tracking_scan_box(
        &mut self,
        scan_id: u16,
        box_id: &[u8; 32],
    ) -> Result<bool, WalletStoreError>;
    fn replace_scan_box(
        &mut self,
        scan_ids: &[u16],
        box_id: [u8; 32],
        inclusion_height: u32,
        output_index: u16,
        box_bytes: Vec<u8>,
    ) -> Result<bool, WalletStoreError>;
    fn set_change_address(&mut self, pubkey: [u8; 33]) -> Result<(), WalletStoreError>;
    fn insert_tracked_pubkey(
        &mut self,
        path_idx: u64,
        pubkey: [u8; 33],
        meta: &TrackedPubkeyMeta,
    ) -> Result<(), WalletStoreError>;
    fn rebuild_visible_addresses(&mut self) -> Result<(), WalletStoreError>;
    fn set_derivation_head(&mut self, head: u64) -> Result<(), WalletStoreError>;
    fn prepare_rescan(
        &mut self,
        start_height: u32,
        scan_rebuild: bool,
    ) -> Result<(), WalletStoreError>;
    fn apply_rescan_block(
        &mut self,
        height: u32,
        tracked_p2pk_trees: &BTreeSet<Vec<u8>>,
        cached_pubkeys: &BTreeMap<u64, [u8; 33]>,
        block: &crate::wallet::scan::RescanBlock,
        scan_records: Option<&[crate::wallet::types::ScanMatchRecord]>,
    ) -> Result<(), WalletStoreError>;
    fn finish_rescan(&mut self, start_height: u32) -> Result<(), WalletStoreError>;
    fn apply_block(
        &mut self,
        height: u32,
        header_id: &[u8; 32],
        payload: &WalletApplyPayload,
    ) -> Result<(), WalletStoreError>;
    fn rollback_block(
        &mut self,
        height: u32,
        txs: &[crate::wallet::types::OwnedBlockTxData],
        invalidate: bool,
    ) -> Result<(), WalletStoreError>;
    fn commit(self: Box<Self>) -> Result<(), WalletStoreError>;
}

pub trait WalletStore: Send + Sync {
    fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError>;

    fn read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
        self.begin_read()
    }

    fn persist_scan_invalidation(&self, invalidated: bool) -> Result<(), WalletStoreError> {
        let mut write = WalletStore::begin_write(self)?;
        write.set_scan_invalidated(invalidated)?;
        write.commit()
    }

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

    pub fn attach_write_transaction(txn: &WriteTransaction) -> RedbWalletWrite<'_> {
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
            owned: Some(begin_write_quick(&self.db)?),
            borrowed: None,
        }))
    }
}

impl WalletStore for Database {
    fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
        Ok(Box::new(RedbWalletRead {
            txn: self.begin_read()?,
        }))
    }

    fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
        Ok(Box::new(RedbWalletWrite {
            owned: Some(begin_write_quick(self)?),
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

    fn chain_index_header(&self, height: u32) -> Result<Option<[u8; 32]>, WalletStoreError> {
        self.reader().chain_index_header(height).map_err(Into::into)
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

    fn rescan_state(&self) -> Result<RescanState, WalletStoreError> {
        let table = match self
            .txn
            .open_table(crate::wallet::tables::WALLET_RESCAN_STATE)
        {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(RescanState::Idle),
            Err(error) => return Err(error.into()),
        };
        let Some(row) = table.get(())? else {
            return Ok(RescanState::Idle);
        };
        bincode::deserialize(row.value().as_slice())
            .map_err(|error| WalletStoreError::Decode(format!("rescan state decode: {error}")))
    }

    fn all_boxes(&self) -> Result<Vec<WalletBox>, WalletStoreError> {
        self.reader().all_boxes().map_err(Into::into)
    }

    fn unspent_boxes(&self) -> Result<Vec<WalletBox>, WalletStoreError> {
        self.reader().unspent_boxes().map_err(Into::into)
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

    fn visible_pubkeys(&self) -> Result<Vec<(u32, [u8; 33])>, WalletStoreError> {
        let table = match self
            .txn
            .open_table(crate::wallet::tables::WALLET_VISIBLE_ADDRESSES)
        {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut visible = Vec::with_capacity(table.len()? as usize);
        for entry in table.iter()? {
            let (key, value) = entry?;
            visible.push((key.value(), value.value()));
        }
        Ok(visible)
    }

    fn derivation_head(&self) -> Result<u64, WalletStoreError> {
        let table = match self
            .txn
            .open_table(crate::wallet::tables::WALLET_DERIVATION_HEAD)
        {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        Ok(table.get(())?.map(|row| row.value()).unwrap_or(0))
    }

    fn scan_boxes(&self, scan_id: u16) -> Result<Vec<ScanTrackedBox>, WalletStoreError> {
        let table = match self
            .txn
            .open_table(crate::wallet::tables::WALLET_SCAN_BOXES)
        {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let lo = crate::wallet::tables::scan_box_key(scan_id, &[0; 32]);
        let hi = crate::wallet::tables::scan_box_key(scan_id, &[0xff; 32]);
        let mut boxes = Vec::new();
        for entry in table.range(lo..=hi)? {
            let (_, value) = entry?;
            boxes.push(
                bincode::deserialize(value.value().as_slice()).map_err(|error| {
                    WalletStoreError::Decode(format!("scan box decode: {error}"))
                })?,
            );
        }
        Ok(boxes)
    }

    fn committed_tip(&self) -> Result<Option<(u32, [u8; 32])>, WalletStoreError> {
        committed_tip_in(&self.txn).map_err(|error| WalletStoreError::Decode(error.to_string()))
    }

    fn scan_boxes_with_tip(
        &self,
        scan_id: u16,
    ) -> Result<(u32, Vec<ScanTrackedBox>), WalletStoreError> {
        let tip = self.committed_tip()?.map(|(height, _)| height).unwrap_or(0);
        Ok((tip, self.scan_boxes(scan_id)?))
    }

    fn reserved_scan_boxes_with_tip(
        &self,
        mining: bool,
        spent: bool,
    ) -> Result<(u32, Vec<ReservedScanBox>), WalletStoreError> {
        let tip = self.committed_tip()?.map(|(height, _)| height).unwrap_or(0);
        Ok((tip, self.reserved_scan_boxes(mining, spent)?))
    }

    fn scan_transactions(&self, scan_id: u16) -> Result<Vec<ScanTxRecord>, WalletStoreError> {
        let table = match self.txn.open_table(crate::wallet::tables::WALLET_SCAN_TXS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut transactions = Vec::new();
        for entry in table.iter()? {
            let (_, value) = entry?;
            let record: ScanTxRecord =
                bincode::deserialize(value.value().as_slice()).map_err(|error| {
                    WalletStoreError::Decode(format!("scan transaction decode: {error}"))
                })?;
            if record.scan_ids.contains(&scan_id) {
                transactions.push(record);
            }
        }
        Ok(transactions)
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

pub struct RedbWalletWrite<'a> {
    owned: Option<WriteTransaction>,
    borrowed: Option<&'a WriteTransaction>,
}

#[allow(clippy::result_large_err)]
fn read_wallet_cursor(txn: &WriteTransaction) -> Result<Option<WalletScanCursor>, redb::Error> {
    let height = match txn.open_table(crate::wallet::tables::WALLET_SCAN_HEIGHT) {
        Ok(table) => table.get(())?.map(|row| row.value()),
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let Some(height) = height else {
        return Ok(None);
    };
    let header_id = match txn.open_table(crate::wallet::tables::WALLET_SCAN_HEADER_ID) {
        Ok(table) => table.get(())?.map(|row| row.value()),
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(error) => return Err(error.into()),
    };
    Ok(Some(WalletScanCursor { height, header_id }))
}

#[allow(clippy::result_large_err)]
fn read_chain_index_header(
    txn: &WriteTransaction,
    height: u32,
) -> Result<Option<[u8; 32]>, redb::Error> {
    let table = match txn.open_table(CHAIN_INDEX) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let Some(bytes) = table.get(height as u64)? else {
        return Ok(None);
    };
    let bytes = bytes.value();
    if bytes.len() != 32 {
        return Err(redb::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("chain index row at {height} is not 32 bytes"),
        )));
    }
    let mut header_id = [0u8; 32];
    header_id.copy_from_slice(bytes);
    Ok(Some(header_id))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WalletCursorContinuity {
    Contiguous,
    Gap,
    HeaderMismatch,
}

#[allow(clippy::result_large_err)]
fn wallet_apply_continuity(
    txn: &WriteTransaction,
    height: u32,
    header_id: &[u8; 32],
) -> Result<WalletCursorContinuity, redb::Error> {
    if height == 0 {
        return Ok(WalletCursorContinuity::HeaderMismatch);
    }
    let cursor = read_wallet_cursor(txn)?;
    let expected_height = match cursor {
        Some(cursor) => match cursor.height.checked_add(1) {
            Some(expected) => expected,
            None => return Ok(WalletCursorContinuity::Gap),
        },
        None => 1,
    };
    if height != expected_height {
        return Ok(WalletCursorContinuity::Gap);
    }
    if read_chain_index_header(txn, height)?.as_ref() != Some(header_id) {
        return Ok(WalletCursorContinuity::HeaderMismatch);
    }
    if let Some(cursor) = cursor {
        if cursor.height == 0 {
            if cursor.header_id.is_some() {
                return Ok(WalletCursorContinuity::HeaderMismatch);
            }
        } else {
            let Some(cursor_header_id) = cursor.header_id else {
                return Ok(WalletCursorContinuity::HeaderMismatch);
            };
            if read_chain_index_header(txn, cursor.height)?.as_ref() != Some(&cursor_header_id) {
                return Ok(WalletCursorContinuity::HeaderMismatch);
            }
        }
    }
    Ok(WalletCursorContinuity::Contiguous)
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

    fn clear_scan_registry(&mut self) -> Result<(), WalletStoreError> {
        clear_scan_registry(self.txn())?;
        Ok(())
    }

    fn set_rescan_state(&mut self, state: &RescanState) -> Result<(), WalletStoreError> {
        let bytes = bincode::serialize(state)
            .map_err(|error| WalletStoreError::Decode(format!("rescan state encode: {error}")))?;
        self.txn()
            .open_table(crate::wallet::tables::WALLET_RESCAN_STATE)?
            .insert((), bytes)?;
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

        let mut boxes = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_SCAN_BOXES)?;
        let lo = crate::wallet::tables::scan_box_key(id, &[0; 32]);
        let hi = crate::wallet::tables::scan_box_key(id, &[0xff; 32]);
        let mut box_ids: Vec<[u8; 32]> = Vec::new();
        for entry in boxes.range(lo..=hi)? {
            let (key, _) = entry?;
            let key = key.value();
            let mut box_id = [0; 32];
            box_id.copy_from_slice(&key[2..]);
            box_ids.push(box_id);
        }
        for box_id in &box_ids {
            boxes.remove(crate::wallet::tables::scan_box_key(id, box_id))?;
        }
        drop(boxes);

        let mut index = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_SCAN_BOX_INDEX)?;
        for box_id in box_ids {
            let mut ids: Vec<u16> = match index.get(&box_id)? {
                Some(value) => {
                    let ids = bincode::deserialize(value.value().as_slice()).map_err(|error| {
                        WalletStoreError::Decode(format!("scan index decode: {error}"))
                    })?;
                    drop(value);
                    ids
                }
                None => continue,
            };
            ids.retain(|scan_id| *scan_id != id);
            if ids.is_empty() {
                index.remove(&box_id)?;
            } else {
                index.insert(
                    box_id,
                    bincode::serialize(&ids).map_err(|error| {
                        WalletStoreError::Decode(format!("scan index encode: {error}"))
                    })?,
                )?;
            }
        }
        drop(index);

        let mut transactions = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_SCAN_TXS)?;
        let mut updates = Vec::new();
        let mut deletes = Vec::new();
        for entry in transactions.iter()? {
            let (key, value) = entry?;
            let mut record: ScanTxRecord =
                bincode::deserialize(value.value().as_slice()).map_err(|error| {
                    WalletStoreError::Decode(format!("scan transaction decode: {error}"))
                })?;
            if !record.scan_ids.contains(&id) {
                continue;
            }
            record.scan_ids.retain(|scan_id| *scan_id != id);
            if record.scan_ids.is_empty() {
                deletes.push(key.value());
            } else {
                updates.push((
                    key.value(),
                    bincode::serialize(&record).map_err(|error| {
                        WalletStoreError::Decode(format!("scan transaction encode: {error}"))
                    })?,
                ));
            }
        }
        for (key, value) in updates {
            transactions.insert(key, value)?;
        }
        for key in deletes {
            transactions.remove(key)?;
        }
        Ok(())
    }

    fn stop_tracking_scan_box(
        &mut self,
        scan_id: u16,
        box_id: &[u8; 32],
    ) -> Result<bool, WalletStoreError> {
        let index = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_SCAN_BOX_INDEX)?;
        let ids: Vec<u16> = match index.get(box_id)? {
            Some(value) => {
                let ids = bincode::deserialize(value.value().as_slice()).map_err(|error| {
                    WalletStoreError::Decode(format!("scan index decode: {error}"))
                })?;
                drop(value);
                ids
            }
            None => return Ok(false),
        };
        drop(index);
        self.txn()
            .open_table(crate::wallet::tables::WALLET_SCAN_BOXES)?
            .remove(crate::wallet::tables::scan_box_key(scan_id, box_id))?;
        let mut index = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_SCAN_BOX_INDEX)?;
        let remaining: Vec<u16> = ids.into_iter().filter(|id| *id != scan_id).collect();
        if remaining.is_empty() {
            index.remove(box_id)?;
        } else {
            index.insert(
                *box_id,
                bincode::serialize(&remaining).map_err(|error| {
                    WalletStoreError::Decode(format!("scan index encode: {error}"))
                })?,
            )?;
        }
        Ok(true)
    }

    fn replace_scan_box(
        &mut self,
        scan_ids: &[u16],
        box_id: [u8; 32],
        inclusion_height: u32,
        output_index: u16,
        box_bytes: Vec<u8>,
    ) -> Result<bool, WalletStoreError> {
        let mut index = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_SCAN_BOX_INDEX)?;
        let old_ids: Vec<u16> = match index.get(&box_id)? {
            Some(value) => bincode::deserialize(value.value().as_slice())
                .map_err(|error| WalletStoreError::Decode(format!("scan index decode: {error}")))?,
            None => Vec::new(),
        };
        if scan_ids.is_empty() && old_ids.is_empty() {
            return Ok(false);
        }
        let mut boxes = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_SCAN_BOXES)?;
        for old_id in old_ids {
            boxes.remove(crate::wallet::tables::scan_box_key(old_id, &box_id))?;
        }
        for scan_id in scan_ids {
            let record = ScanTrackedBox {
                scan_id: *scan_id,
                box_id,
                inclusion_height,
                creation_out_index: output_index,
                box_bytes: box_bytes.clone(),
                status: crate::wallet::types::ScanBoxStatus::Unspent,
            };
            boxes.insert(
                crate::wallet::tables::scan_box_key(*scan_id, &box_id),
                bincode::serialize(&record).map_err(|error| {
                    WalletStoreError::Decode(format!("scan box encode: {error}"))
                })?,
            )?;
        }
        if scan_ids.is_empty() {
            index.remove(&box_id)?;
        } else {
            index.insert(
                box_id,
                bincode::serialize(scan_ids).map_err(|error| {
                    WalletStoreError::Decode(format!("scan index encode: {error}"))
                })?,
            )?;
        }
        Ok(true)
    }

    fn set_change_address(&mut self, pubkey: [u8; 33]) -> Result<(), WalletStoreError> {
        self.txn()
            .open_table(crate::wallet::tables::WALLET_CHANGE_ADDRESS)?
            .insert((), pubkey)?;
        Ok(())
    }

    fn insert_tracked_pubkey(
        &mut self,
        path_idx: u64,
        pubkey: [u8; 33],
        meta: &TrackedPubkeyMeta,
    ) -> Result<(), WalletStoreError> {
        let meta_bytes = bincode::serialize(meta).map_err(|error| {
            WalletStoreError::Decode(format!("tracked pubkey metadata encode: {error}"))
        })?;
        self.txn()
            .open_table(crate::wallet::tables::WALLET_TRACKED_PUBKEYS)?
            .insert(
                crate::wallet::tables::tracked_pubkey_key(path_idx, &pubkey),
                meta_bytes,
            )?;
        Ok(())
    }

    fn rebuild_visible_addresses(&mut self) -> Result<(), WalletStoreError> {
        let tracked = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_TRACKED_PUBKEYS)?;
        let mut all_tracked: Vec<(u64, [u8; 33], Vec<u32>)> = Vec::new();
        for entry in tracked.iter()? {
            let (key, value) = entry?;
            let key_bytes: [u8; 41] = key.value();
            let (index, pubkey) = crate::wallet::tables::parse_tracked_pubkey_key(&key_bytes);
            let metadata: TrackedPubkeyMeta = bincode::deserialize(value.value().as_slice())
                .map_err(|error| {
                    WalletStoreError::Decode(format!("tracked pubkey metadata decode: {error}"))
                })?;
            all_tracked.push((index, pubkey, metadata.derivation_path));
        }
        drop(tracked);
        let mut visible = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_VISIBLE_ADDRESSES)?;
        let existing: Vec<u32> = visible
            .iter()?
            .map(|entry| entry.map(|(key, _)| key.value()))
            .collect::<Result<_, _>>()?;
        for key in existing {
            visible.remove(key)?;
        }
        let mut visible_index = 0u32;
        for (index, pubkey, path) in all_tracked {
            if index == 0 && path.is_empty() {
                continue;
            }
            visible.insert(visible_index, pubkey)?;
            visible_index += 1;
        }
        Ok(())
    }

    fn set_derivation_head(&mut self, head: u64) -> Result<(), WalletStoreError> {
        self.txn()
            .open_table(crate::wallet::tables::WALLET_DERIVATION_HEAD)?
            .insert((), head)?;
        Ok(())
    }

    fn prepare_rescan(
        &mut self,
        start_height: u32,
        scan_rebuild: bool,
    ) -> Result<(), WalletStoreError> {
        if start_height == 0 {
            self.set_scan_invalidated(true)?;
            if scan_rebuild {
                clear_scan_tracking(self.txn())?;
            }
            let mut boxes = self.txn().open_table(crate::wallet::tables::WALLET_BOXES)?;
            let mut box_bytes = self
                .txn()
                .open_table(crate::wallet::tables::WALLET_BOX_BYTES)?;
            let box_ids: Vec<[u8; 32]> = boxes
                .iter()?
                .map(|entry| entry.map(|(key, _)| key.value()))
                .collect::<Result<_, _>>()?;
            for box_id in box_ids {
                boxes.remove(box_id)?;
                box_bytes.remove(box_id)?;
            }
            let mut by_tx = self
                .txn()
                .open_table(crate::wallet::tables::WALLET_BOXES_BY_TX)?;
            let keys: Vec<[u8; 34]> = by_tx
                .iter()?
                .map(|entry| entry.map(|(key, _)| key.value()))
                .collect::<Result<_, _>>()?;
            for key in keys {
                by_tx.remove(key)?;
            }
            let mut transactions = self.txn().open_table(crate::wallet::tables::WALLET_TXS)?;
            let keys: Vec<[u8; 36]> = transactions
                .iter()?
                .map(|entry| entry.map(|(key, _)| key.value()))
                .collect::<Result<_, _>>()?;
            for key in keys {
                transactions.remove(key)?;
            }
            set_scan_cursor(self.txn(), 0, None)?;
            return Ok(());
        }

        let mut boxes = self.txn().open_table(crate::wallet::tables::WALLET_BOXES)?;
        let mut remove = Vec::new();
        for entry in boxes.iter()? {
            let (key, value) = entry?;
            let wallet_box: WalletBox = bincode::deserialize(value.value().as_slice())
                .map_err(|error| WalletStoreError::Decode(format!("wallet box decode: {error}")))?;
            if wallet_box.creation_height >= start_height {
                remove.push(key.value());
            }
        }
        let mut box_bytes = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_BOX_BYTES)?;
        for box_id in remove {
            boxes.remove(box_id)?;
            box_bytes.remove(box_id)?;
        }
        let mut by_tx = self
            .txn()
            .open_table(crate::wallet::tables::WALLET_BOXES_BY_TX)?;
        let old_keys: Vec<[u8; 34]> = by_tx
            .iter()?
            .map(|entry| entry.map(|(key, _)| key.value()))
            .collect::<Result<_, _>>()?;
        for key in old_keys {
            by_tx.remove(key)?;
        }
        for entry in boxes.iter()? {
            let (_, value) = entry?;
            let wallet_box: WalletBox = bincode::deserialize(value.value().as_slice())
                .map_err(|error| WalletStoreError::Decode(format!("wallet box decode: {error}")))?;
            by_tx.insert(
                crate::wallet::tables::box_by_tx_key(
                    &wallet_box.creation_tx_id,
                    wallet_box.creation_output_index,
                ),
                wallet_box.box_id,
            )?;
        }
        let mut transactions = self.txn().open_table(crate::wallet::tables::WALLET_TXS)?;
        let keys: Vec<[u8; 36]> = transactions
            .iter()?
            .map(|entry| entry.map(|(key, _)| key.value()))
            .collect::<Result<_, _>>()?;
        for key in keys {
            let height = u32::from_be_bytes(key[..4].try_into().expect("four-byte key"));
            if height >= start_height {
                transactions.remove(key)?;
            }
        }
        let mut updates = Vec::new();
        for entry in boxes.iter()? {
            let (key, value) = entry?;
            let mut wallet_box: WalletBox = bincode::deserialize(value.value().as_slice())
                .map_err(|error| WalletStoreError::Decode(format!("wallet box decode: {error}")))?;
            let mut changed = false;
            match wallet_box.status {
                BoxStatus::Spent { spent_at, .. } if spent_at >= start_height => {
                    wallet_box.status = match wallet_box.provenance {
                        BoxProvenance::MinerReward => {
                            let matures_at = wallet_box
                                .creation_height
                                .saturating_add(crate::wallet::apply::REWARD_MATURITY_MAINNET);
                            if matures_at > start_height.saturating_sub(1) {
                                BoxStatus::Immature { matures_at }
                            } else {
                                BoxStatus::Confirmed
                            }
                        }
                        _ => BoxStatus::Confirmed,
                    };
                    changed = true;
                }
                BoxStatus::Confirmed
                    if matches!(wallet_box.provenance, BoxProvenance::MinerReward) =>
                {
                    let matures_at = wallet_box
                        .creation_height
                        .saturating_add(crate::wallet::apply::REWARD_MATURITY_MAINNET);
                    if matures_at > start_height.saturating_sub(1) {
                        wallet_box.status = BoxStatus::Immature { matures_at };
                        changed = true;
                    }
                }
                _ => {}
            }
            if changed {
                updates.push((key.value(), wallet_box));
            }
        }
        for (key, wallet_box) in updates {
            boxes.insert(
                key,
                bincode::serialize(&wallet_box).map_err(|error| {
                    WalletStoreError::Decode(format!("wallet box encode: {error}"))
                })?,
            )?;
        }
        let height = start_height.saturating_sub(1);
        let header_id = if height == 0 {
            if let Some(cursor) = read_wallet_cursor(self.txn())? {
                if cursor.height != 0 || cursor.header_id.is_some() {
                    return Err(WalletStoreError::Decode(
                        "rescan boundary cursor 0 is not the genesis sentinel".to_string(),
                    ));
                }
            }
            None
        } else {
            let cursor = read_wallet_cursor(self.txn())?.ok_or_else(|| {
                WalletStoreError::Decode(format!("rescan boundary cursor {height} is missing"))
            })?;
            if cursor.height != height {
                return Err(WalletStoreError::Decode(format!(
                    "rescan boundary cursor height {} does not match {height}",
                    cursor.height
                )));
            }
            let cursor_id = cursor.header_id.ok_or_else(|| {
                WalletStoreError::Decode(format!(
                    "rescan boundary cursor {height} has no header identity"
                ))
            })?;
            let table = self.txn().open_table(crate::wallet::tables::CHAIN_INDEX)?;
            let bytes = table.get(height as u64)?.ok_or_else(|| {
                WalletStoreError::Decode(format!("rescan boundary {height} is missing"))
            })?;
            if bytes.value().len() != 32 {
                return Err(WalletStoreError::Decode(format!(
                    "chain index row at {height} is not 32 bytes"
                )));
            }
            let mut indexed_id = [0; 32];
            indexed_id.copy_from_slice(bytes.value());
            if indexed_id != cursor_id {
                return Err(WalletStoreError::Decode(format!(
                    "rescan boundary cursor identity changed at {height}"
                )));
            }
            Some(cursor_id)
        };
        set_scan_cursor(self.txn(), height, header_id.as_ref())?;
        Ok(())
    }

    fn apply_rescan_block(
        &mut self,
        height: u32,
        tracked_p2pk_trees: &BTreeSet<Vec<u8>>,
        cached_pubkeys: &BTreeMap<u64, [u8; 33]>,
        block: &crate::wallet::scan::RescanBlock,
        scan_records: Option<&[crate::wallet::types::ScanMatchRecord]>,
    ) -> Result<(), WalletStoreError> {
        let bound: Vec<Vec<crate::wallet::apply::BlockOutput<'_>>> = block
            .txs
            .iter()
            .map(|tx| {
                tx.outputs
                    .iter()
                    .map(|output| crate::wallet::apply::BlockOutput {
                        box_id: output.box_id,
                        output_index: output.output_index,
                        ergo_tree_bytes: &output.ergo_tree_bytes,
                        value: output.value,
                        assets: output.assets.clone(),
                        miner_reward_pubkey: output.miner_reward_pubkey,
                        box_bytes: &output.box_bytes,
                    })
                    .collect()
            })
            .collect();
        let txs: Vec<crate::wallet::apply::BlockTx<'_>> = block
            .txs
            .iter()
            .zip(bound.iter())
            .map(|(tx, outputs)| crate::wallet::apply::BlockTx {
                tx_id: tx.tx_id,
                inputs: &tx.inputs,
                outputs,
            })
            .collect();
        apply_block_to_wallet_rescan(
            self.txn(),
            tracked_p2pk_trees,
            cached_pubkeys,
            height,
            &block.block_id,
            &txs,
        )?;
        promote_matured_boxes_rescan(self.txn(), height)?;
        if let Some(records) = scan_records {
            apply_block_to_scans_rescan(self.txn(), records, &txs, height, &block.block_id)?;
        }
        Ok(())
    }

    fn finish_rescan(&mut self, start_height: u32) -> Result<(), WalletStoreError> {
        if start_height == 0 {
            self.set_scan_invalidated(false)?;
        }
        Ok(())
    }

    fn apply_block(
        &mut self,
        height: u32,
        header_id: &[u8; 32],
        payload: &WalletApplyPayload,
    ) -> Result<(), WalletStoreError> {
        if payload.apply_generation != crate::wallet::wallet_apply_generation()
            || crate::wallet::wallet_apply_fenced()
        {
            return Ok(());
        }
        let bound = owned_to_block_txs(&payload.block_txs_owned);
        let txs = bound.as_block_txs();
        let apply_wallet = if payload.has_wallet_tracking() {
            match wallet_apply_continuity(self.txn(), height, header_id)? {
                WalletCursorContinuity::Contiguous => true,
                WalletCursorContinuity::Gap if payload.allow_non_contiguous_wallet => false,
                WalletCursorContinuity::Gap => {
                    self.set_scan_invalidated(true)?;
                    crate::wallet::fence_wallet_apply();
                    if payload.has_registered_scans {
                        apply_block_to_scans_rescan(
                            self.txn(),
                            &payload.scan_matches,
                            &txs,
                            height,
                            header_id,
                        )?;
                    }
                    return Ok(());
                }
                WalletCursorContinuity::HeaderMismatch => {
                    self.set_scan_invalidated(true)?;
                    crate::wallet::fence_wallet_apply();
                    return Ok(());
                }
            }
        } else {
            false
        };
        if apply_wallet {
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
        txs: &[crate::wallet::types::OwnedBlockTxData],
        invalidate: bool,
    ) -> Result<(), WalletStoreError> {
        let bound = owned_to_block_txs(txs);
        let block_txs = bound.as_block_txs();
        let guard = RollbackGuard { invalidate };
        rollback_block_from_wallet(self.txn(), height, &block_txs, &guard)?;
        unpromote_matured_boxes(self.txn(), height.saturating_sub(1))?;
        rollback_scans_from_block(self.txn(), &block_txs, height)?;
        if invalidate {
            self.set_scan_invalidated(true)?;
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
    use crate::wallet::tables::{wallet_tx_key, WALLET_SCAN_TXS};
    use crate::wallet::types::ScanMatchRecord;
    use crate::wallet::types::{ScanTxRecord, TrackedPubkeyMeta};
    use std::collections::{BTreeMap, BTreeSet};

    fn seed_chain_index(db: &Database, entries: &[(u32, [u8; 32])]) {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(CHAIN_INDEX).unwrap();
            for (height, header_id) in entries {
                table.insert(*height as u64, header_id.as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
    }

    fn payload() -> (
        WalletApplyPayload,
        Vec<crate::wallet::types::OwnedBlockTxData>,
    ) {
        let txs = vec![crate::wallet::types::OwnedBlockTxData {
            tx_id: [1; 32],
            inputs: vec![],
            outputs: vec![crate::wallet::types::OwnedBlockOutput {
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
            apply_generation: crate::wallet::wallet_apply_generation(),
            tracked_p2pk_trees: BTreeSet::from([vec![3]]),
            cached_pubkeys: BTreeMap::new(),
            block_txs_owned: txs.clone(),
            scan_matches: Vec::new(),
            has_registered_scans: false,
            allow_non_contiguous_wallet: false,
        };
        (payload, txs)
    }

    #[test]
    fn stale_generation_skips_wallet_apply() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::new(Arc::new(
            Database::create(dir.path().join("state.redb")).unwrap(),
        ));
        let (mut payload, _) = payload();
        payload.apply_generation = payload.apply_generation.wrapping_sub(1);
        let mut write = store.begin_write().unwrap();
        write.apply_block(1, &[4; 32], &payload).unwrap();
        write.commit().unwrap();
        let read = store.read().unwrap();
        assert!(read.scan_cursor().unwrap().is_none());
        assert!(read.all_boxes().unwrap().is_empty());
    }

    #[test]
    fn fenced_generation_skips_wallet_apply() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::new(Arc::new(
            Database::create(dir.path().join("state.redb")).unwrap(),
        ));
        crate::wallet::fence_wallet_apply();
        let (payload, _) = payload();
        let mut write = store.begin_write().unwrap();
        write.apply_block(1, &[4; 32], &payload).unwrap();
        write.commit().unwrap();
        crate::wallet::unfence_wallet_apply();
        let read = store.read().unwrap();
        assert!(read.scan_cursor().unwrap().is_none());
        assert!(read.all_boxes().unwrap().is_empty());
    }

    #[test]
    fn redb_store_applies_and_rolls_back_wallet_payload() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let header_id = [4; 32];
        seed_chain_index(db.as_ref(), &[(1, header_id)]);
        let store = RedbWalletStore::new(db);
        let (payload, txs) = payload();
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
    fn duplicate_wallet_payload_does_not_advance_cursor() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let header_id = [4; 32];
        seed_chain_index(db.as_ref(), &[(1, header_id)]);
        let store = RedbWalletStore::new(db);
        let (mut payload, _) = payload();
        let mut write = store.begin_write().unwrap();
        write.apply_block(1, &header_id, &payload).unwrap();
        write.commit().unwrap();
        payload.allow_non_contiguous_wallet = true;
        let mut write = store.begin_write().unwrap();
        write.apply_block(1, &header_id, &payload).unwrap();
        write.commit().unwrap();
        let read = store.read().unwrap();
        assert_eq!(read.scan_cursor().unwrap().unwrap().height, 1);
        assert_eq!(read.all_boxes().unwrap().len(), 1);
    }

    #[test]
    fn rescan_prepare_rejects_a_reorged_boundary_instead_of_substituting_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        seed_chain_index(db.as_ref(), &[(1, [9; 32])]);
        let store = RedbWalletStore::new(db);
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(1, Some(&[4; 32])).unwrap();
        write.commit().unwrap();

        let mut write = store.begin_write().unwrap();
        assert!(write.prepare_rescan(2, false).is_err());
        drop(write);

        let read = store.read().unwrap();
        assert_eq!(
            read.scan_cursor().unwrap().unwrap(),
            crate::wallet::WalletScanCursor {
                height: 1,
                header_id: Some([4; 32]),
            }
        );
    }

    #[test]
    fn partial_rescan_gap_keeps_scan_rows() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let header_id = [4; 32];
        seed_chain_index(db.as_ref(), &[(1, header_id), (3, [6; 32])]);
        let store = RedbWalletStore::new(db);
        let (mut payload, _) = payload();
        let mut write = store.begin_write().unwrap();
        write.apply_block(1, &header_id, &payload).unwrap();
        write.commit().unwrap();
        payload.allow_non_contiguous_wallet = true;
        payload.has_registered_scans = true;
        payload.scan_matches = vec![ScanMatchRecord {
            box_id: [8; 32],
            scan_ids: vec![11],
            box_bytes: Vec::new(),
            inclusion_height: 3,
            creation_out_index: 0,
        }];
        let mut write = store.begin_write().unwrap();
        write.apply_block(3, &[6; 32], &payload).unwrap();
        write.commit().unwrap();
        let read = store.read().unwrap();
        assert_eq!(read.scan_cursor().unwrap().unwrap().height, 1);
        assert_eq!(read.all_boxes().unwrap().len(), 1);
        assert_eq!(read.scan_boxes(11).unwrap().len(), 1);
    }

    #[test]
    fn ahead_wallet_payload_does_not_rewind_cursor() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        seed_chain_index(db.as_ref(), &[(3, [6; 32])]);
        let store = RedbWalletStore::new(db);
        let (mut payload, _) = payload();
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(3, Some(&[6; 32])).unwrap();
        write.commit().unwrap();
        payload.allow_non_contiguous_wallet = true;
        let mut write = store.begin_write().unwrap();
        write.apply_block(2, &[5; 32], &payload).unwrap();
        write.commit().unwrap();
        let read = store.read().unwrap();
        assert_eq!(read.scan_cursor().unwrap().unwrap().height, 3);
        assert!(read.all_boxes().unwrap().is_empty());
    }

    #[test]
    fn non_contiguous_wallet_payload_commits_invalidation_and_scan_rows() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let header_id = [4; 32];
        seed_chain_index(db.as_ref(), &[(1, header_id), (3, [6; 32])]);
        let store = RedbWalletStore::new(db);
        let (mut payload, _) = payload();
        let mut write = store.begin_write().unwrap();
        write.apply_block(1, &header_id, &payload).unwrap();
        write.commit().unwrap();
        payload.has_registered_scans = true;
        payload.scan_matches = vec![ScanMatchRecord {
            box_id: [9; 32],
            scan_ids: vec![11],
            box_bytes: Vec::new(),
            inclusion_height: 3,
            creation_out_index: 0,
        }];
        let mut write = store.begin_write().unwrap();
        write.apply_block(3, &[6; 32], &payload).unwrap();
        write.commit().unwrap();
        let read = store.read().unwrap();
        assert!(read.scan_invalidated().unwrap());
        assert_eq!(read.scan_cursor().unwrap().unwrap().height, 1);
        assert_eq!(read.scan_boxes(11).unwrap().len(), 1);
        crate::wallet::unfence_wallet_apply();
    }

    #[test]
    fn header_mismatch_does_not_apply_wallet_payload() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        seed_chain_index(db.as_ref(), &[(1, [9; 32])]);
        let store = RedbWalletStore::new(db);
        let (payload, _) = payload();
        let mut write = store.begin_write().unwrap();
        write.apply_block(1, &[4; 32], &payload).unwrap();
        write.commit().unwrap();
        let read = store.read().unwrap();
        assert!(read.scan_invalidated().unwrap());
        assert!(read.scan_cursor().unwrap().is_none());
        assert!(read.all_boxes().unwrap().is_empty());
        crate::wallet::unfence_wallet_apply();
    }

    #[test]
    fn scan_only_payload_is_not_gated_by_wallet_cursor() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::new(Arc::new(
            Database::create(dir.path().join("state.redb")).unwrap(),
        ));
        let (mut payload, _) = payload();
        payload.tracked_p2pk_trees.clear();
        payload.cached_pubkeys.clear();
        payload.has_registered_scans = true;
        payload.scan_matches = vec![ScanMatchRecord {
            box_id: [2; 32],
            scan_ids: vec![11],
            box_bytes: Vec::new(),
            inclusion_height: 5,
            creation_out_index: 0,
        }];
        let mut write = store.begin_write().unwrap();
        write.apply_block(5, &[4; 32], &payload).unwrap();
        write.commit().unwrap();
        let read = store.read().unwrap();
        assert!(read.scan_cursor().unwrap().is_none());
        assert_eq!(read.scan_boxes(11).unwrap().len(), 1);
    }

    #[test]
    fn rollback_block_with_invalidate_sets_scan_invalidated() {
        let _guard = crate::wallet::WALLET_APPLY_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        let header_id = [4; 32];
        seed_chain_index(db.as_ref(), &[(1, header_id)]);
        let store = RedbWalletStore::new(db);
        let (payload, txs) = payload();
        let mut write = store.begin_write().unwrap();
        write.apply_block(1, &header_id, &payload).unwrap();
        write.commit().unwrap();
        let mut write = store.begin_write().unwrap();
        write.rollback_block(1, &txs, true).unwrap();
        write.commit().unwrap();
        assert!(store.begin_read().unwrap().scan_invalidated().unwrap());
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
        let read = store.read().unwrap();
        let registry = read.scan_registry().unwrap();
        assert_eq!(registry.scans[0].id, 11);
        assert_eq!(registry.last_used_id, Some(11));
    }

    #[test]
    fn clear_scan_registry_preserves_wallet_facts_and_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("state.redb")).unwrap());
        {
            let txn = db.begin_write().unwrap();
            txn.open_table(WALLET_SCAN_TXS)
                .unwrap()
                .insert(
                    wallet_tx_key(3, &[4; 32]),
                    bincode::serialize(&ScanTxRecord {
                        tx_id: [4; 32],
                        block_height: 3,
                        block_id: [5; 32],
                        scan_ids: vec![11],
                        created: vec![[6; 32]],
                        spent: vec![],
                    })
                    .unwrap(),
                )
                .unwrap();
            txn.commit().unwrap();
        }
        let store = RedbWalletStore::new(db.clone());
        let mut write = store.begin_write().unwrap();
        write.put_scan(11, b"{\"scanId\":11}".to_vec(), 11).unwrap();
        write
            .replace_scan_box(&[11], [6; 32], 3, 0, vec![])
            .unwrap();
        write.set_scan_cursor(7, Some(&[7; 32])).unwrap();
        write
            .insert_tracked_pubkey(
                0,
                [1; 33],
                &TrackedPubkeyMeta {
                    derivation_path: Vec::new(),
                    derivation_path_label: String::new(),
                    added_at_height: 0,
                },
            )
            .unwrap();
        write.commit().unwrap();

        let mut write = store.begin_write().unwrap();
        write.clear_scan_registry().unwrap();
        write.commit().unwrap();

        let read = store.read().unwrap();
        assert!(read.scan_registry().unwrap().scans.is_empty());
        assert_eq!(read.scan_registry().unwrap().last_used_id, Some(11));
        assert!(read.scan_boxes(11).unwrap().is_empty());
        assert!(read.scan_transactions(11).unwrap().is_empty());
        assert_eq!(read.scan_cursor().unwrap().unwrap().height, 7);
        assert_eq!(read.tracked_pubkeys_with_paths().unwrap().len(), 1);
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

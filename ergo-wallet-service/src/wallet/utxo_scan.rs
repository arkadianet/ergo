//! Wallet-owned metadata and atomic publication for verified UTXO discovery.
//! Chain traversal and root verification belong to the stopped-node adapter.

use super::tables::*;
use super::types::{BoxProvenance, BoxStatus, WalletBox};
use super::WalletStoreError;
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const DISCOVERY_JOB: TableDefinition<(), Vec<u8>> =
    TableDefinition::new("wallet_utxo_discovery_job");
pub const DISCOVERY_STAGING: TableDefinition<[u8; 32], Vec<u8>> =
    TableDefinition::new("wallet_utxo_discovery_staging");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryCoverage {
    pub version: u32,
    pub anchor_height: u32,
    pub anchor_header_id: String,
    pub state_root: String,
    /// Historical transactions before this height have not been reconstructed.
    pub history_complete: bool,
    pub matched_boxes: u64,
    /// Public keys included in the verified UTXO traversal. Older coverage
    /// without this field needs discovery again before claiming complete funds.
    #[serde(default)]
    pub covered_pubkeys: Vec<String>,
}

fn corrupt(reason: impl Into<String>) -> WalletStoreError {
    WalletStoreError::decode(reason)
}

pub fn coverage(txn: &ReadTransaction) -> Result<Option<DiscoveryCoverage>, WalletStoreError> {
    match txn.open_table(WALLET_UTXO_DISCOVERY) {
        Ok(table) => table
            .get(())?
            .map(|v| serde_json::from_slice(&v.value()).map_err(|e| corrupt(e.to_string())))
            .transpose(),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn uncovered_pubkeys(
    txn: &ReadTransaction,
    meta: &DiscoveryCoverage,
) -> Result<Vec<String>, WalletStoreError> {
    let covered: BTreeSet<_> = meta.covered_pubkeys.iter().collect();
    let current: BTreeSet<_> = super::reader::WalletReader::new(txn)
        .tracked_pubkeys_with_paths()?
        .into_iter()
        .map(|(_, pk, _)| hex::encode(pk))
        .collect();
    Ok(current
        .into_iter()
        .filter(|pk| !covered.contains(pk))
        .collect())
}

pub fn requires_discovery(txn: &ReadTransaction) -> Result<bool, WalletStoreError> {
    match coverage(txn)? {
        Some(meta) => Ok(!uncovered_pubkeys(txn, &meta)?.is_empty()),
        None => Ok(false),
    }
}

pub fn inclusion_height_known(
    txn: &ReadTransaction,
    id: [u8; 32],
) -> Result<bool, WalletStoreError> {
    match txn.open_table(WALLET_DISCOVERED_BOXES) {
        Ok(table) => Ok(table.get(id)?.is_none()),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// Publish only after the chain adapter has verified the entire committed UTXO tree.
pub fn publish_discovery(
    db: &Database,
    result: &DiscoveryCoverage,
) -> Result<(), WalletStoreError> {
    let txn = super::store::begin_write_quick(db)?;
    {
        let staged = txn.open_table(DISCOVERY_STAGING)?;
        use redb::ReadableTableMetadata;
        if staged.len()? != result.matched_boxes {
            return Err(corrupt(
                "checkpoint contains unexpected staged boxes; use --restart",
            ));
        }
        let mut boxes = txn.open_table(WALLET_BOXES)?;
        let mut bytes_table = txn.open_table(WALLET_BOX_BYTES)?;
        let mut index = txn.open_table(WALLET_BOXES_BY_TX)?;
        let mut unknown = txn.open_table(WALLET_DISCOVERED_BOXES)?;
        boxes.retain(|_, _| false)?;
        bytes_table.retain(|_, _| false)?;
        index.retain(|_, _| false)?;
        unknown.retain(|_, _| false)?;
        txn.open_table(WALLET_TXS)?.retain(|_, _| false)?;
        for entry in staged.iter()? {
            let (id, bytes) = entry?;
            let raw = bytes.value();
            let mut reader = ergo_primitives::reader::VlqReader::new(&raw).trusted();
            let b = ergo_ser::ergo_box::read_ergo_box(&mut reader)
                .map_err(|e| corrupt(e.to_string()))?;
            let reward = ergo_wallet::proving::miner_reward::extract_miner_reward_pubkey(
                b.candidate.ergo_tree_bytes(),
            )
            .is_some();
            let matures_at = b
                .candidate
                .creation_height
                .saturating_add(super::apply::REWARD_MATURITY_MAINNET);
            let wb = WalletBox {
                box_id: id.value(),
                creation_tx_id: *b.transaction_id.as_bytes(),
                creation_output_index: b.index,
                // First observation, NOT a fabricated historical inclusion height.
                creation_height: result.anchor_height,
                value: b.candidate.value,
                assets: b
                    .candidate
                    .tokens
                    .iter()
                    .map(|t| (*t.token_id.as_bytes(), t.amount))
                    .collect(),
                status: if reward && matures_at > result.anchor_height {
                    BoxStatus::Immature { matures_at }
                } else {
                    BoxStatus::Confirmed
                },
                provenance: if reward {
                    BoxProvenance::MinerReward
                } else {
                    BoxProvenance::Owned
                },
            };
            boxes.insert(
                wb.box_id,
                bincode::serialize(&wb).map_err(|e| corrupt(e.to_string()))?,
            )?;
            bytes_table.insert(wb.box_id, raw)?;
            index.insert(
                box_by_tx_key(&wb.creation_tx_id, wb.creation_output_index),
                wb.box_id,
            )?;
            unknown.insert(wb.box_id, b.candidate.creation_height)?;
        }
    }
    txn.open_table(WALLET_SCAN_HEIGHT)?
        .insert((), result.anchor_height)?;
    let header_id: [u8; 32] = hex::decode(&result.anchor_header_id)
        .map_err(|e| corrupt(e.to_string()))?
        .try_into()
        .map_err(|_| corrupt("invalid anchor header ID"))?;
    if result.anchor_height > 0 {
        txn.open_table(WALLET_SCAN_HEADER_ID)?
            .insert((), header_id)?;
    } else {
        txn.open_table(WALLET_SCAN_HEADER_ID)?.remove(())?;
    }
    txn.open_table(WALLET_UTXO_DISCOVERY)?.insert(
        (),
        serde_json::to_vec(&result).map_err(|e| corrupt(e.to_string()))?,
    )?;
    txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), false)?;
    txn.open_table(WALLET_RESCAN_STATE)?.insert(
        (),
        bincode::serialize(&super::store::RescanState::Idle).map_err(|e| corrupt(e.to_string()))?,
    )?;
    txn.open_table(DISCOVERY_STAGING)?.retain(|_, _| false)?;
    txn.open_table(DISCOVERY_JOB)?.remove(())?;
    txn.commit()?;
    Ok(())
}

/// Rollback below the discovery anchor cannot reconstruct boxes already spent
/// before that anchor. Invalidate rather than silently presenting partial funds.
pub fn invalidate_below_anchor(
    txn: &redb::WriteTransaction,
    removed_height: u32,
) -> Result<(), redb::Error> {
    let table = txn.open_table(WALLET_UTXO_DISCOVERY)?;
    if let Some(row) = table.get(())? {
        let invalidate = match serde_json::from_slice::<DiscoveryCoverage>(&row.value()) {
            Ok(meta) => removed_height <= meta.anchor_height,
            Err(error) => {
                tracing::warn!(%error, "unreadable wallet discovery coverage; invalidating wallet during rollback");
                true
            }
        };
        if invalidate {
            txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), true)?;
        }
    }
    Ok(())
}

pub(crate) fn reward_creation_height(
    txn: &redb::WriteTransaction,
    id: [u8; 32],
    fallback: u32,
) -> Result<u32, redb::Error> {
    Ok(txn
        .open_table(WALLET_DISCOVERED_BOXES)?
        .get(id)?
        .map_or(fallback, |v| v.value()))
}

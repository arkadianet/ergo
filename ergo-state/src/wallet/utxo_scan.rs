//! Resumable offline discovery from the committed UTXO tree. Staging tables
//! never replace the visible wallet until the entire tree verifies successfully.
//! No transaction history or historical inclusion height is invented.

use super::tables::*;
use super::types::{BoxProvenance, BoxStatus, WalletBox};
use crate::maintenance::{inspect_tip, visit_utxos, MaintenanceTip};
use crate::store::StateError;
use redb::{Database, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const JOB: TableDefinition<(), Vec<u8>> = TableDefinition::new("wallet_utxo_discovery_job");
const STAGING: TableDefinition<[u8; 32], Vec<u8>> =
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Job {
    version: u32,
    tip: MaintenanceTip,
    pubkeys: Vec<String>,
    last_key: Option<[u8; 32]>,
    visited: u64,
    matched: u64,
}

fn corrupt(reason: impl Into<String>) -> StateError {
    StateError::DbCorruption {
        table: "wallet UTXO discovery",
        key: String::new(),
        reason: reason.into(),
    }
}

pub fn coverage(txn: &ReadTransaction) -> Result<Option<DiscoveryCoverage>, StateError> {
    match txn.open_table(WALLET_UTXO_DISCOVERY) {
        Ok(table) => table
            .get(())?
            .map(|v| serde_json::from_slice(&v.value()).map_err(|e| corrupt(e.to_string())))
            .transpose(),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn inclusion_height_known(txn: &ReadTransaction, id: [u8; 32]) -> Result<bool, StateError> {
    match txn.open_table(WALLET_DISCOVERED_BOXES) {
        Ok(table) => Ok(table.get(id)?.is_none()),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// A snapshot can omit historical CHAIN_INDEX rows. Wallet discovery may
/// anchor at its verified current tip without changing any chain table.
pub(crate) fn committed_discovery_anchor(
    txn: &ReadTransaction,
    height: u32,
) -> Result<Option<[u8; 32]>, StateError> {
    let Some(meta) = coverage(txn)? else {
        return Ok(None);
    };
    if meta.version != 1 || meta.anchor_height != height {
        return Ok(None);
    }
    let tip = inspect_tip(txn)?;
    if tip.height != height
        || tip.header_id != meta.anchor_header_id
        || tip.state_root.as_deref() != Some(meta.state_root.as_str())
    {
        return Ok(None);
    }
    let id = hex::decode(meta.anchor_header_id)
        .map_err(|e| corrupt(e.to_string()))?
        .try_into()
        .map_err(|_| corrupt("invalid discovery anchor ID"))?;
    Ok(Some(id))
}

fn checkpoint(
    db: &Database,
    job: &Job,
    pending: &mut Vec<([u8; 32], Vec<u8>)>,
) -> Result<(), StateError> {
    let txn = db.begin_write()?;
    {
        let mut staged = txn.open_table(STAGING)?;
        for (id, bytes) in pending.iter() {
            staged.insert(*id, bytes.clone())?;
        }
        txn.open_table(JOB)?.insert(
            (),
            serde_json::to_vec(job).map_err(|e| corrupt(e.to_string()))?,
        )?;
    }
    txn.commit()?;
    pending.clear();
    Ok(())
}

/// The caller owns the stopped node's exclusive database handle. A checkpoint
/// may be resumed only at the identical root/tip with identical tracked keys.
pub fn discover(db: &Database, restart: bool) -> Result<DiscoveryCoverage, StateError> {
    let snapshot = db.begin_read()?;
    let tip = inspect_tip(&snapshot)?;
    if tip.state_type.as_deref().is_some_and(|kind| kind != "utxo") || tip.state_root.is_none() {
        return Err(corrupt("discovery requires an initialized UTXO backend"));
    }
    let pubkeys: BTreeSet<Vec<u8>> = super::reader::WalletReader::new(&snapshot)
        .tracked_pubkeys_with_paths()?
        .into_iter()
        .map(|(_, pk, _)| pk.to_vec())
        .collect();
    if pubkeys.is_empty() {
        return Err(corrupt("no persisted tracked keys; initialize/restore and unlock the wallet before stopping the node"));
    }
    match snapshot.open_table(WALLET_SCANS) {
        Ok(scans) => {
            use redb::ReadableTableMetadata;
            if !scans.is_empty()? {
                return Err(corrupt("registered custom scans require historical rescan; current-UTXO discovery only rebuilds owned wallet holdings"));
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(e) => return Err(e.into()),
    }
    let key_strings: Vec<_> = pubkeys.iter().map(hex::encode).collect();
    let previous = match snapshot.open_table(JOB) {
        Ok(table) => table
            .get(())?
            .map(|v| serde_json::from_slice::<Job>(&v.value()).map_err(|e| corrupt(e.to_string())))
            .transpose()?,
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(e) => return Err(e.into()),
    };
    let mut job = if let Some(previous) = previous.filter(|_| !restart) {
        if previous.version != 1 || previous.tip != tip || previous.pubkeys != key_strings {
            return Err(corrupt(
                "checkpoint tip or tracked keys changed; rerun with --restart",
            ));
        }
        previous
    } else {
        let txn = db.begin_write()?;
        txn.open_table(STAGING)?.retain(|_, _| false)?;
        txn.open_table(JOB)?.remove(())?;
        txn.commit()?;
        Job {
            version: 1,
            tip: tip.clone(),
            pubkeys: key_strings,
            last_key: None,
            visited: 0,
            matched: 0,
        }
    };
    let resume_key = job.last_key;
    let resumed_staging = if resume_key.is_some() {
        Some(snapshot.open_table(STAGING)?)
    } else {
        None
    };
    let mut pending = Vec::new();
    let mut pending_bytes = 0usize;
    let mut verified_matches = 0u64;
    let verified = visit_utxos(&snapshot, |id, bytes, ergo_box| {
        let tree = ergo_box.candidate.ergo_tree_bytes();
        let owned = tree.len() == 36 && tree[..3] == [0, 8, 0xcd] && pubkeys.contains(&tree[3..]);
        let reward = super::miner_reward::extract_miner_reward_pubkey(tree)
            .is_some_and(|pk| pubkeys.contains(pk.as_slice()));
        if owned || reward {
            verified_matches += 1;
        }
        if resume_key.is_some_and(|last| *id <= last) {
            let row = resumed_staging.as_ref().unwrap().get(*id)?;
            if row.as_ref().is_some_and(|v| v.value().as_slice() != bytes)
                || row.is_some() != (owned || reward)
            {
                return Err(corrupt(
                    "checkpoint staged holdings disagree with committed UTXOs; use --restart",
                ));
            }
            return Ok(());
        }
        job.visited += 1;
        job.last_key = Some(*id);
        if owned || reward {
            job.matched += 1;
            pending_bytes += bytes.len();
            pending.push((*id, bytes.to_vec()));
        }
        if job.visited % 1024 == 0 || pending_bytes >= 8 * 1024 * 1024 {
            checkpoint(db, &job, &mut pending)?;
            pending_bytes = 0;
        }
        Ok(())
    })?;
    if verified.box_count != job.visited || verified_matches != job.matched {
        return Err(corrupt(
            "checkpoint counters disagree with verified UTXOs; use --restart",
        ));
    }
    checkpoint(db, &job, &mut pending)?;
    let result = DiscoveryCoverage {
        version: 1,
        anchor_height: tip.height,
        anchor_header_id: tip.header_id.clone(),
        state_root: tip.state_root.clone().unwrap(),
        history_complete: false,
        matched_boxes: job.matched,
    };
    let txn = db.begin_write()?;
    {
        let staged = txn.open_table(STAGING)?;
        use redb::ReadableTableMetadata;
        if staged.len()? != job.matched {
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
            let reward =
                super::miner_reward::extract_miner_reward_pubkey(b.candidate.ergo_tree_bytes())
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
                creation_height: tip.height,
                value: b.candidate.value,
                assets: b
                    .candidate
                    .tokens
                    .iter()
                    .map(|t| (*t.token_id.as_bytes(), t.amount))
                    .collect(),
                status: if reward && matures_at > tip.height {
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
    txn.open_table(WALLET_SCAN_HEIGHT)?.insert((), tip.height)?;
    let header_id: [u8; 32] = hex::decode(&tip.header_id)
        .map_err(|e| corrupt(e.to_string()))?
        .try_into()
        .map_err(|_| corrupt("invalid anchor header ID"))?;
    if tip.height > 0 {
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
    txn.open_table(STAGING)?.retain(|_, _| false)?;
    txn.open_table(JOB)?.remove(())?;
    txn.commit()?;
    Ok(result)
}

/// Rollback below the discovery anchor cannot reconstruct boxes already spent
/// before that anchor. Invalidate rather than silently presenting partial funds.
pub(crate) fn invalidate_below_anchor(
    txn: &redb::WriteTransaction,
    removed_height: u32,
) -> Result<(), redb::Error> {
    let table = txn.open_table(WALLET_UTXO_DISCOVERY)?;
    if let Some(row) = table.get(())? {
        let meta: DiscoveryCoverage = serde_json::from_slice(&row.value())
            .map_err(|e| redb::Error::Io(std::io::Error::other(e.to_string())))?;
        if removed_height <= meta.anchor_height {
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

#[cfg(test)]
mod tests;

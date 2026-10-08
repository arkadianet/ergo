//! Resumable offline discovery from the committed UTXO tree. Staging tables
//! never replace the visible wallet until the entire tree verifies successfully.
//! No transaction history or historical inclusion height is invented.

use super::tables::*;
#[cfg(test)]
use super::types::{BoxProvenance, BoxStatus};
use crate::maintenance::{inspect_tip, visit_utxos, MaintenanceTip};
use crate::store::StateError;
use redb::{Database, ReadTransaction, ReadableDatabase};
#[cfg(test)]
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[cfg(test)]
use ergo_wallet_service::wallet::utxo_scan::invalidate_below_anchor;
pub use ergo_wallet_service::wallet::utxo_scan::DiscoveryCoverage;
use ergo_wallet_service::wallet::utxo_scan::{DISCOVERY_JOB as JOB, DISCOVERY_STAGING as STAGING};

fn wallet_error(error: super::WalletStoreError) -> StateError {
    match error {
        super::WalletStoreError::Decode(reason) => corrupt(reason),
        error => error.into(),
    }
}

pub fn coverage(txn: &ReadTransaction) -> Result<Option<DiscoveryCoverage>, StateError> {
    ergo_wallet_service::wallet::utxo_scan::coverage(txn).map_err(wallet_error)
}

pub fn uncovered_pubkeys(
    txn: &ReadTransaction,
    meta: &DiscoveryCoverage,
) -> Result<Vec<String>, StateError> {
    ergo_wallet_service::wallet::utxo_scan::uncovered_pubkeys(txn, meta).map_err(wallet_error)
}

pub fn requires_discovery(txn: &ReadTransaction) -> Result<bool, StateError> {
    ergo_wallet_service::wallet::utxo_scan::requires_discovery(txn).map_err(wallet_error)
}

pub fn inclusion_height_known(txn: &ReadTransaction, id: [u8; 32]) -> Result<bool, StateError> {
    ergo_wallet_service::wallet::utxo_scan::inclusion_height_known(txn, id).map_err(wallet_error)
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
    let txn = crate::begin_write_qr(db)?;
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
    discover_into(&snapshot, db, restart)
}

/// Verify the stopped node's committed UTXO snapshot while writing discovery
/// staging and wallet projections only into the independently locked target.
/// The caller validates target ownership/network before entering this adapter.
pub fn discover_into(
    snapshot: &ReadTransaction,
    db: &Database,
    restart: bool,
) -> Result<DiscoveryCoverage, StateError> {
    let wallet_snapshot = db.begin_read()?;
    let tip = inspect_tip(snapshot)?;
    if tip.state_type.as_deref().is_some_and(|kind| kind != "utxo") || tip.state_root.is_none() {
        return Err(StateError::WalletDiscoveryUnavailable(
            "discovery requires an initialized UTXO backend".into(),
        ));
    }
    let pubkeys: BTreeSet<Vec<u8>> = super::reader::WalletReader::new(&wallet_snapshot)
        .tracked_pubkeys_with_paths()?
        .into_iter()
        .map(|(_, pk, _)| pk.to_vec())
        .collect();
    if pubkeys.is_empty() {
        return Err(StateError::WalletDiscoveryUnavailable("no persisted tracked keys; initialize/restore and unlock the wallet before stopping the node".into()));
    }
    match wallet_snapshot.open_table(WALLET_SCANS) {
        Ok(scans) => {
            use redb::ReadableTableMetadata;
            if !scans.is_empty()? {
                return Err(StateError::WalletDiscoveryUnavailable("registered custom scans require historical rescan; current-UTXO discovery only rebuilds owned wallet holdings".into()));
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(e) => return Err(e.into()),
    }
    if !super::mining_jobs::pending_jobs(&wallet_snapshot)?.is_empty() {
        return Err(StateError::WalletDiscoveryUnavailable(
            "non-terminal wallet mining jobs require wallet history; finish or cancel them before discovery".into(),
        ));
    }
    let key_strings: Vec<_> = pubkeys.iter().map(hex::encode).collect();
    let previous = match wallet_snapshot.open_table(JOB) {
        Ok(table) => table
            .get(())?
            .map(|v| serde_json::from_slice::<Job>(&v.value()).map_err(|e| corrupt(e.to_string())))
            .transpose()?,
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(e) => return Err(e.into()),
    };
    let mut job = if let Some(previous) = previous.filter(|_| !restart) {
        if previous.version != 1 || previous.tip != tip || previous.pubkeys != key_strings {
            return Err(StateError::WalletDiscoveryRestartRequired(
                "checkpoint tip or tracked keys changed; rerun with --restart".into(),
            ));
        }
        previous
    } else {
        let txn = crate::begin_write_qr(db)?;
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
        Some(wallet_snapshot.open_table(STAGING)?)
    } else {
        None
    };
    let mut pending = Vec::new();
    let mut pending_bytes = 0usize;
    let mut verified_matches = 0u64;
    let verified = visit_utxos(snapshot, |id, bytes, ergo_box| {
        let tree = ergo_box.candidate.ergo_tree_bytes();
        let owned = tree.len() == 36 && tree[..3] == [0, 8, 0xcd] && pubkeys.contains(&tree[3..]);
        let reward = ergo_wallet::proving::miner_reward::extract_miner_reward_pubkey(tree)
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
        covered_pubkeys: job.pubkeys.clone(),
    };
    ergo_wallet_service::wallet::utxo_scan::publish_discovery(db, &result).map_err(wallet_error)?;
    Ok(result)
}

#[cfg(test)]
mod tests;

//! Mining-reward maturity gating per Scala `WalletScanLogic.scala:92`.
//!
//! On every block apply, scan `WALLET_BOXES` for Immature boxes
//! whose `matures_at` reaches the new tip and transition them to
//! Confirmed. This is invoked AFTER `apply_block_to_wallet` so the
//! new tip's outputs are first inserted as Immature (if miner-reward
//! shape), THEN any previously-immature boxes that mature THIS block
//! get promoted.
//!
//! Called from the chain apply hook in the SAME redb write txn.

#![allow(clippy::result_large_err)] // redb::Error shape is fixed upstream

use crate::wallet::tables::*;
use crate::wallet::types::{BoxStatus, WalletBox};
use redb::{ReadableTable, WriteTransaction};

/// Promote all Immature boxes whose `matures_at <= new_tip_height`
/// to Confirmed. O(WALLET_BOXES.len) — the linear scan is acceptable
/// since wallet box counts are bounded (≤ low thousands for a miner
/// wallet). A secondary index by `matures_at` could be added if this
/// becomes a hot path.
///
/// Live-apply maturity promotion. Same invalidated-gating as
/// `apply_block_to_wallet` — no-op when scan is invalidated.
/// Rescan replay uses `promote_matured_boxes_rescan` (bypasses check).
pub fn promote_matured_boxes(
    txn: &WriteTransaction,
    new_tip_height: u32,
) -> Result<usize, redb::Error> {
    if crate::wallet::apply::is_scan_invalidated(txn)? {
        return Ok(0);
    }
    promote_matured_boxes_rescan(txn, new_tip_height)
}

/// Privileged rescan-replay variant. Used by
/// `WalletScanService::rescan_full_rebuild` inside the per-block
/// txn during replay.
pub fn promote_matured_boxes_rescan(
    txn: &WriteTransaction,
    new_tip_height: u32,
) -> Result<usize, redb::Error> {
    let mut boxes_tbl = txn.open_table(WALLET_BOXES)?;
    let mut promoted = 0usize;

    // Collect box ids first so we don't iterate-and-mutate.
    let mut to_promote: Vec<[u8; 32]> = Vec::new();
    for entry in boxes_tbl.iter()? {
        let (k, v) = entry?;
        let wb: WalletBox = bincode::deserialize(v.value().as_slice()).map_err(|e| {
            redb::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("WalletBox deserialize: {e}"),
            ))
        })?;
        if let BoxStatus::Immature { matures_at } = wb.status {
            if matures_at <= new_tip_height {
                to_promote.push(k.value());
            }
        }
    }

    for box_id in to_promote {
        let existing: Option<Vec<u8>> = boxes_tbl.get(box_id)?.map(|g| g.value().to_owned());
        if let Some(raw_bytes) = existing {
            let mut wb: WalletBox = bincode::deserialize(&raw_bytes).map_err(|e| {
                redb::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("WalletBox deserialize: {e}"),
                ))
            })?;
            wb.status = BoxStatus::Confirmed;
            let bytes = bincode::serialize(&wb).map_err(|e| {
                redb::Error::Io(std::io::Error::other(format!("WalletBox serialize: {e}")))
            })?;
            boxes_tbl.insert(box_id, bytes)?;
            promoted += 1;
        }
    }
    Ok(promoted)
}

/// On rollback, un-promote any boxes that should now be Immature
/// again. A box that was Confirmed before rollback but whose
/// `creation_height + REWARD_MATURITY_MAINNET` exceeds the new tip
/// height after rollback transitions back to Immature.
///
/// Only applies to boxes with provenance = MinerReward — non-reward
/// boxes don't have maturity gating.
pub fn unpromote_matured_boxes(
    txn: &WriteTransaction,
    new_tip_height: u32,
) -> Result<usize, redb::Error> {
    use crate::wallet::apply::REWARD_MATURITY_MAINNET;
    use crate::wallet::types::BoxProvenance;

    let mut boxes_tbl = txn.open_table(WALLET_BOXES)?;
    let mut unpromoted = 0usize;
    let mut to_unpromote: Vec<[u8; 32]> = Vec::new();

    for entry in boxes_tbl.iter()? {
        let (k, v) = entry?;
        let wb: WalletBox = bincode::deserialize(v.value().as_slice()).map_err(|e| {
            redb::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("WalletBox deserialize: {e}"),
            ))
        })?;
        if !matches!(wb.provenance, BoxProvenance::MinerReward) {
            continue;
        }
        if !matches!(wb.status, BoxStatus::Confirmed) {
            continue;
        }
        let matures_at = wb.creation_height.saturating_add(REWARD_MATURITY_MAINNET);
        if matures_at > new_tip_height {
            to_unpromote.push(k.value());
        }
    }

    for box_id in to_unpromote {
        let existing: Option<Vec<u8>> = boxes_tbl.get(box_id)?.map(|g| g.value().to_owned());
        if let Some(raw_bytes) = existing {
            let mut wb: WalletBox = bincode::deserialize(&raw_bytes).map_err(|e| {
                redb::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("WalletBox deserialize: {e}"),
                ))
            })?;
            let matures_at = wb.creation_height.saturating_add(REWARD_MATURITY_MAINNET);
            wb.status = BoxStatus::Immature { matures_at };
            let bytes = bincode::serialize(&wb).map_err(|e| {
                redb::Error::Io(std::io::Error::other(format!("WalletBox serialize: {e}")))
            })?;
            boxes_tbl.insert(box_id, bytes)?;
            unpromoted += 1;
        }
    }
    Ok(unpromoted)
}

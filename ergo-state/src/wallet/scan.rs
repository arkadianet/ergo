//! Full-chain rescan helper for /wallet/rescan.
//!
//! Iterates blocks from a start height up to the chain tip, replaying
//! `apply_block_to_wallet_rescan` for each block. Used when the operator
//! wants to rescan after restoring an existing wallet or after adding new
//! tracked pubkeys.
//!
//! Atomicity note: each block applies in its own write txn (NOT one txn
//! for the whole rescan). This avoids holding the redb write lock for
//! the duration of a long rescan, at the cost of partial-progress
//! visibility. Rescan progress is observable via WALLET_SCAN_HEIGHT.

#![allow(clippy::result_large_err)] // redb::Error shape is fixed upstream

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use redb::{Database, ReadableTable};

use crate::wallet::apply::{apply_block_to_wallet_rescan, BlockOutput, BlockTx};
use crate::wallet::maturity::promote_matured_boxes_rescan;
use crate::wallet::tables::{
    box_by_tx_key, WALLET_BOXES, WALLET_BOXES_BY_TX, WALLET_SCAN_HEIGHT, WALLET_SCAN_INVALIDATED,
    WALLET_TXS,
};
use crate::wallet::types::WalletBox;

/// Service that drives a rescan against a chain-state read interface.
pub struct WalletScanService;

impl WalletScanService {
    /// Full-rebuild (or range-scoped) rescan.
    ///
    /// When `start_height == 0`: full rebuild — clears WALLET_BOXES,
    /// WALLET_BOXES_BY_TX, and WALLET_TXS, sets WALLET_SCAN_INVALIDATED=true,
    /// resets WALLET_SCAN_HEIGHT=0, then replays all blocks in [0..=tip_height].
    /// Clears WALLET_SCAN_INVALIDATED at the end.
    ///
    /// When `start_height > 0`: range-scoped rebuild — deletes rows whose
    /// recorded height >= start_height, rewinds surviving rows whose state
    /// changed at/above start_height back to their pre-start_height status,
    /// rewinds WALLET_SCAN_HEIGHT to start_height-1, then replays
    /// [start_height..=tip_height]. Does NOT touch WALLET_SCAN_INVALIDATED.
    ///
    /// After the main replay, a catch-up loop re-reads the tip and replays
    /// any blocks that arrived during the rebuild, until steady state.
    ///
    /// `is_cancelled` is polled at every iteration boundary; returns true
    /// if rollback (or operator action) aborted the rescan.
    ///
    /// Returns the count of blocks processed.
    #[allow(clippy::too_many_arguments)]
    pub fn rescan_full_rebuild<F, T, C>(
        db: &Arc<Database>,
        tracked_p2pk_trees: BTreeSet<Vec<u8>>,
        cached_pubkeys: BTreeMap<u64, [u8; 33]>,
        start_height: u32,
        tip_height: u32,
        mut read_block: F,
        mut read_tip: T,
        mut is_cancelled: C,
    ) -> Result<u32, redb::Error>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, redb::Error>,
        T: FnMut() -> Result<u32, redb::Error>,
        C: FnMut() -> bool,
    {
        if start_height == 0 {
            // Full rebuild: clear all chain-derived tables + mark invalidated.
            let txn = crate::begin_write_qr(db)?;
            {
                let mut inv_tbl = txn.open_table(WALLET_SCAN_INVALIDATED)?;
                inv_tbl.insert((), true)?;
            }
            {
                let mut boxes_tbl = txn.open_table(WALLET_BOXES)?;
                let to_remove: Vec<[u8; 32]> = boxes_tbl
                    .iter()?
                    .filter_map(|e| e.ok().map(|(k, _)| k.value()))
                    .collect();
                for k in to_remove {
                    boxes_tbl.remove(k)?;
                }
            }
            {
                let mut by_tx = txn.open_table(WALLET_BOXES_BY_TX)?;
                let to_remove: Vec<[u8; 34]> = by_tx
                    .iter()?
                    .filter_map(|e| e.ok().map(|(k, _)| k.value()))
                    .collect();
                for k in to_remove {
                    by_tx.remove(k)?;
                }
            }
            {
                let mut txs_tbl = txn.open_table(WALLET_TXS)?;
                let to_remove: Vec<[u8; 36]> = txs_tbl
                    .iter()?
                    .filter_map(|e| e.ok().map(|(k, _)| k.value()))
                    .collect();
                for k in to_remove {
                    txs_tbl.remove(k)?;
                }
            }
            {
                let mut sh = txn.open_table(WALLET_SCAN_HEIGHT)?;
                sh.insert((), 0u32)?;
            }
            txn.commit()?;
        } else {
            // Range-scoped rebuild: delete rows >= start_height, rewind
            // surviving rows, reset scan_height.
            let txn = crate::begin_write_qr(db)?;

            // STEP 1a: delete WALLET_BOXES rows with creation_height >= start_height.
            let to_remove: Vec<[u8; 32]> = {
                let tbl = txn.open_table(WALLET_BOXES)?;
                let mut out = Vec::new();
                for entry in tbl.iter()? {
                    let (k, v) = entry?;
                    let wb: WalletBox = deserialize_box(v.value().as_slice())?;
                    if wb.creation_height >= start_height {
                        out.push(k.value());
                    }
                }
                out
            };
            {
                let mut tbl = txn.open_table(WALLET_BOXES)?;
                for box_id in to_remove {
                    tbl.remove(box_id)?;
                }
            }

            // STEP 1b: rebuild WALLET_BOXES_BY_TX from surviving WALLET_BOXES.
            {
                let mut by_tx = txn.open_table(WALLET_BOXES_BY_TX)?;
                let existing_keys: Vec<[u8; 34]> = by_tx
                    .iter()?
                    .filter_map(|e| e.ok().map(|(k, _)| k.value()))
                    .collect();
                for k in existing_keys {
                    by_tx.remove(k)?;
                }
                let boxes_tbl = txn.open_table(WALLET_BOXES)?;
                for entry in boxes_tbl.iter()? {
                    let (_, v) = entry?;
                    let wb: WalletBox = deserialize_box(v.value().as_slice())?;
                    by_tx.insert(
                        box_by_tx_key(&wb.creation_tx_id, wb.creation_output_index),
                        wb.box_id,
                    )?;
                }
            }

            // STEP 1c: delete WALLET_TXS rows with block_height >= start_height.
            {
                let mut txs_tbl = txn.open_table(WALLET_TXS)?;
                let start_be = start_height.to_be_bytes();
                let to_remove: Vec<[u8; 36]> = txs_tbl
                    .iter()?
                    .filter_map(|e| e.ok())
                    .filter_map(|(k, _)| {
                        let key = k.value();
                        if key[..4] >= start_be[..] {
                            Some(key)
                        } else {
                            None
                        }
                    })
                    .collect();
                for k in to_remove {
                    txs_tbl.remove(k)?;
                }
            }

            // STEP 1d: rewind surviving WALLET_BOXES rows whose state
            // changed at/above start_height.
            {
                use crate::wallet::apply::REWARD_MATURITY_MAINNET;
                use crate::wallet::types::{BoxProvenance, BoxStatus};

                let mut tbl = txn.open_table(WALLET_BOXES)?;
                let mut updates: Vec<([u8; 32], WalletBox)> = Vec::new();
                for entry in tbl.iter()? {
                    let (k, v) = entry?;
                    let mut wb: WalletBox = deserialize_box(v.value().as_slice())?;
                    // All remaining rows have creation_height < start_height.
                    let mut changed = false;
                    match wb.status {
                        BoxStatus::Spent { spent_at, .. } if spent_at >= start_height => {
                            // Revert to pre-spend status.
                            wb.status = match wb.provenance {
                                BoxProvenance::MinerReward => {
                                    let matures_at =
                                        wb.creation_height.saturating_add(REWARD_MATURITY_MAINNET);
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
                            if matches!(wb.provenance, BoxProvenance::MinerReward) =>
                        {
                            let matures_at =
                                wb.creation_height.saturating_add(REWARD_MATURITY_MAINNET);
                            if matures_at > start_height.saturating_sub(1) {
                                // Pre-N this box was still Immature.
                                wb.status = BoxStatus::Immature { matures_at };
                                changed = true;
                            }
                        }
                        _ => {}
                    }
                    if changed {
                        updates.push((k.value(), wb));
                    }
                }
                for (box_id, wb) in updates {
                    let bytes = serialize_box(&wb)?;
                    tbl.insert(box_id, bytes)?;
                }
            }

            // STEP 1e: rewind scan height.
            {
                let mut sh = txn.open_table(WALLET_SCAN_HEIGHT)?;
                sh.insert((), start_height.saturating_sub(1))?;
            }
            txn.commit()?;
        }

        // STEP 2: replay block-by-block with maturity promotion per block.
        // Catch-up loop: after the main replay, re-read tip and replay any
        // blocks that arrived during the rebuild.
        let mut processed = 0u32;
        let mut current_target = tip_height;
        let mut current_start = start_height;

        loop {
            for h in current_start..=current_target {
                // Per-block cancellation check.
                if is_cancelled() {
                    return Ok(processed);
                }
                let block = match read_block(h)? {
                    Some(b) => b,
                    None => continue,
                };
                let txn = crate::begin_write_qr(db)?;
                {
                    // Convert RescanBlock → per-tx owned structs so BlockOutput<'_>
                    // can borrow from them within the txn scope.
                    let bound: Vec<BlockTxBound<'_>> = block
                        .txs
                        .iter()
                        .map(|t| BlockTxBound {
                            tx_id: t.tx_id,
                            inputs: t.inputs.clone(),
                            outputs: t
                                .outputs
                                .iter()
                                .map(|o| BlockOutput {
                                    box_id: o.box_id,
                                    output_index: o.output_index,
                                    ergo_tree_bytes: &o.ergo_tree_bytes,
                                    value: o.value,
                                    assets: o.assets.clone(),
                                    miner_reward_pubkey: o.miner_reward_pubkey,
                                })
                                .collect(),
                        })
                        .collect();
                    let btxs: Vec<BlockTx<'_>> = bound
                        .iter()
                        .map(|b| BlockTx {
                            tx_id: b.tx_id,
                            inputs: &b.inputs,
                            outputs: &b.outputs,
                        })
                        .collect();
                    apply_block_to_wallet_rescan(
                        &txn,
                        &tracked_p2pk_trees,
                        &cached_pubkeys,
                        h,
                        &block.block_id,
                        &btxs,
                    )?;
                    promote_matured_boxes_rescan(&txn, h)?;
                }
                txn.commit()?;
                processed += 1;
            }

            // Cancellation check at catch-up boundary.
            if is_cancelled() {
                return Ok(processed);
            }

            // Catch-up: did new blocks arrive during our replay?
            let new_target = read_tip()?;
            if new_target <= current_target {
                break; // steady state
            }
            current_start = current_target + 1;
            current_target = new_target;
        }

        // Clear the invalidated flag only after a full rebuild from height 0.
        // Partial rescans don't fully reconstruct state.
        if start_height == 0 {
            let txn = crate::begin_write_qr(db)?;
            txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), false)?;
            txn.commit()?;
        }

        Ok(processed)
    }

    /// Read the current scan height from `WALLET_SCAN_HEIGHT`.
    /// Returns 0 if the table doesn't exist yet (fresh wallet).
    pub fn current_scan_height(db: &Database) -> Result<u32, redb::Error> {
        let txn = db.begin_read()?;
        let tbl = match txn.open_table(WALLET_SCAN_HEIGHT) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        Ok(tbl.get(()).ok().flatten().map(|g| g.value()).unwrap_or(0))
    }
}

// --- internal helpers ---

fn deserialize_box(bytes: &[u8]) -> Result<WalletBox, redb::Error> {
    bincode::deserialize(bytes).map_err(|e| {
        redb::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("WalletBox deserialize: {e}"),
        ))
    })
}

fn serialize_box(wb: &WalletBox) -> Result<Vec<u8>, redb::Error> {
    bincode::serialize(wb)
        .map_err(|e| redb::Error::Io(std::io::Error::other(format!("WalletBox serialize: {e}"))))
}

/// Intermediate struct to hold owned input/output vecs for a
/// single replay-loop block transaction so lifetimes work out.
struct BlockTxBound<'a> {
    tx_id: [u8; 32],
    inputs: Vec<[u8; 32]>,
    outputs: Vec<BlockOutput<'a>>,
}

// --- public types ---

/// Block snapshot passed to `read_block` during rescan. Owns all its
/// data so the integrator's closure doesn't need to hold redb read
/// locks across block iterations.
pub struct RescanBlock {
    pub block_id: [u8; 32],
    pub txs: Vec<RescanTx>,
}

/// Transaction snapshot inside a `RescanBlock`. Uses owned byte vecs
/// for the ErgoTree bytes so the lifetime is self-contained.
pub struct RescanTx {
    pub tx_id: [u8; 32],
    pub inputs: Vec<[u8; 32]>,
    pub outputs: Vec<OwnedBlockOutput>,
}

/// An owned-bytes analog of `BlockOutput<'a>`. The rescan loop
/// borrows from these to build `BlockOutput<'_>` values.
pub struct OwnedBlockOutput {
    pub box_id: [u8; 32],
    pub output_index: u16,
    pub ergo_tree_bytes: Vec<u8>,
    pub value: u64,
    pub assets: Vec<([u8; 32], u64)>,
    pub miner_reward_pubkey: Option<[u8; 33]>,
}

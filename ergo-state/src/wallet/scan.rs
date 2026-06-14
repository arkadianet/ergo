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

use crate::wallet::apply::{
    apply_block_to_scans_rescan, apply_block_to_wallet_rescan, clear_scan_tracking, BlockOutput,
    BlockTx,
};
use crate::wallet::maturity::promote_matured_boxes_rescan;
use crate::wallet::tables::{
    box_by_tx_key, WALLET_BOXES, WALLET_BOXES_BY_TX, WALLET_BOX_BYTES, WALLET_SCAN_HEIGHT,
    WALLET_SCAN_INVALIDATED, WALLET_TXS,
};
use crate::wallet::types::WalletBox;

/// Matches a block's output boxes against the registered `/scan/*` rules
/// during a rescan. The `ergo-wallet` predicate matcher isn't reachable from
/// `ergo-state` (dependency direction), so the integrator (`ergo-node`)
/// supplies this — the rescan analog of the live `WalletApplyHook::match_boxes`.
pub trait ScanRescanMatcher {
    /// For each serialized output box (in block order, across all of the
    /// block's transactions), the ids of registered scans whose rule matches
    /// it. MUST return exactly one result per input box, in the same order.
    fn match_boxes(&self, boxes: &[&[u8]]) -> Vec<Vec<u16>>;
}

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
    /// `scan_matcher` drives registered-`/scan/*` rebuild: when `Some` AND
    /// this is a full rebuild (`start_height == 0`), the scan tables
    /// (`WALLET_SCAN_BOXES` / `_INDEX` / `_TXS`) are cleared up front and
    /// rebuilt per block via the same `apply_block_to_scans` the live path
    /// uses — so a rescan reproduces live scan tracking exactly. `None` (a
    /// node with no registered scans) leaves the scan tables untouched. Scan
    /// rebuild is gated to the full-rebuild path because scans have no
    /// range-rewind semantics; a partial wallet rescan does not touch them.
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
        scan_matcher: Option<&dyn ScanRescanMatcher>,
    ) -> Result<u32, redb::Error>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, redb::Error>,
        T: FnMut() -> Result<u32, redb::Error>,
        C: FnMut() -> bool,
    {
        // Registered-scan rebuild only on a full rebuild (scans have no
        // range-rewind path). `None` matcher = a node with no scans.
        let scan_rebuild = scan_matcher.is_some() && start_height == 0;
        // Cleared if any block's scan apply had to be skipped (matcher
        // contract violation). When false, the final WALLET_SCAN_INVALIDATED
        // clear is skipped so the rebuild does not advertise a complete scan
        // set it didn't actually produce.
        let mut scan_rebuild_complete = true;

        if start_height == 0 {
            // Full rebuild: clear all chain-derived tables + mark invalidated.
            let txn = crate::begin_write_qr(db)?;
            {
                let mut inv_tbl = txn.open_table(WALLET_SCAN_INVALIDATED)?;
                inv_tbl.insert((), true)?;
            }
            if scan_rebuild {
                // Wipe scan-tracked boxes/index/txs so the replay rebuilds
                // them from scratch (no orphan rows from a prior chain).
                clear_scan_tracking(&txn)?;
            }
            {
                let mut boxes_tbl = txn.open_table(WALLET_BOXES)?;
                let mut box_bytes_tbl = txn.open_table(WALLET_BOX_BYTES)?;
                let to_remove: Vec<[u8; 32]> = boxes_tbl
                    .iter()?
                    .filter_map(|e| e.ok().map(|(k, _)| k.value()))
                    .collect();
                for k in to_remove {
                    boxes_tbl.remove(k)?;
                    box_bytes_tbl.remove(k)?;
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
                let mut box_bytes_tbl = txn.open_table(WALLET_BOX_BYTES)?;
                for box_id in to_remove {
                    tbl.remove(box_id)?;
                    box_bytes_tbl.remove(box_id)?;
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
                // Precompute registered-scan matches OUTSIDE the write txn: the
                // predicate-match pass only READS block data, so running it here
                // (instead of inside the per-block txn below) keeps the redb
                // writer lock unheld during matching. Only `apply_block_to_scans`
                // (inside the txn) mutates. `None` when no rebuild is active or
                // the matcher returned the wrong cardinality (a matcher bug:
                // skip scan apply for this block + mark the rebuild incomplete so
                // the final WALLET_SCAN_INVALIDATED clear is suppressed).
                let scan_records: Option<Vec<crate::store::ScanMatchRecord>> =
                    if let Some(matcher) = scan_matcher.filter(|_| scan_rebuild) {
                        let mut box_refs: Vec<&[u8]> = Vec::new();
                        let mut box_meta: Vec<([u8; 32], u16)> = Vec::new();
                        for tx in &block.txs {
                            for o in &tx.outputs {
                                box_refs.push(&o.box_bytes);
                                box_meta.push((o.box_id, o.output_index));
                            }
                        }
                        let matches = matcher.match_boxes(&box_refs);
                        if matches.len() == box_refs.len() {
                            Some(
                                box_meta
                                    .into_iter()
                                    .zip(matches)
                                    .zip(box_refs)
                                    .filter(|((_, scan_ids), _)| !scan_ids.is_empty())
                                    .map(|(((box_id, out_idx), scan_ids), bytes)| {
                                        crate::store::ScanMatchRecord {
                                            box_id,
                                            scan_ids,
                                            box_bytes: bytes.to_vec(),
                                            inclusion_height: h,
                                            creation_out_index: out_idx,
                                        }
                                    })
                                    .collect(),
                            )
                        } else {
                            scan_rebuild_complete = false;
                            tracing::error!(
                                height = h,
                                got = matches.len(),
                                want = box_refs.len(),
                                "scan rescan: matcher returned wrong result count; skipping block"
                            );
                            None
                        }
                    } else {
                        None
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
                                    // The replay/rescan builder serializes the
                                    // full box, so a `/wallet/rescan` backfills
                                    // WALLET_BOX_BYTES for boxes that predate it.
                                    box_bytes: &o.box_bytes,
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

                    // Registered-scan rebuild, in the SAME per-block txn so
                    // chain + scan state regress together. The match pass was
                    // precomputed above (outside the txn); here we only persist
                    // matches + spends. `None` = no rebuild active or a matcher
                    // cardinality bug (already logged + rebuild marked incomplete).
                    if let Some(records) = &scan_records {
                        // Privileged variant: the rescan runs WITH
                        // WALLET_SCAN_INVALIDATED set (it is the recovery path),
                        // so it must bypass the live-apply gate.
                        apply_block_to_scans_rescan(&txn, records, &btxs, h, &block.block_id)?;
                    }
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

        // Clear the invalidated flag only after a full rebuild from height 0
        // that fully reconstructed state. Partial rescans don't reconstruct
        // state; a scan rebuild that skipped a block (matcher contract
        // violation, `scan_rebuild_complete == false`) left the scan tables
        // incomplete and must stay invalidated so the operator rescans again.
        if start_height == 0 && scan_rebuild_complete {
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
#[derive(Clone)]
pub struct RescanBlock {
    pub block_id: [u8; 32],
    pub txs: Vec<RescanTx>,
}

/// Transaction snapshot inside a `RescanBlock`. Uses owned byte vecs
/// for the ErgoTree bytes so the lifetime is self-contained.
#[derive(Clone)]
pub struct RescanTx {
    pub tx_id: [u8; 32],
    pub inputs: Vec<[u8; 32]>,
    pub outputs: Vec<OwnedBlockOutput>,
}

/// An owned-bytes analog of `BlockOutput<'a>`. The rescan loop
/// borrows from these to build `BlockOutput<'_>` values.
#[derive(Clone)]
pub struct OwnedBlockOutput {
    pub box_id: [u8; 32],
    pub output_index: u16,
    pub ergo_tree_bytes: Vec<u8>,
    pub value: u64,
    pub assets: Vec<([u8; 32], u64)>,
    pub miner_reward_pubkey: Option<[u8; 33]>,
    /// Full serialized `ErgoBox` bytes — supplied by the section reader so
    /// the rescan loop can match registered scans against historical boxes
    /// and persist `ScanTrackedBox.box_bytes`. Empty when scan rescan is
    /// not in play.
    pub box_bytes: Vec<u8>,
}

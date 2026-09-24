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
use thiserror::Error;

use crate::store::StateError;
use crate::wallet::apply::{
    apply_block_to_scans_rescan, apply_block_to_wallet_rescan, clear_scan_tracking,
    set_scan_cursor, BlockOutput, BlockTx,
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
    fn match_boxes(&self, boxes: &[&[u8]]) -> Result<Vec<Vec<u16>>, String>;
}

/// A failure while reading the chain data required by a wallet rescan.
#[derive(Debug, Error)]
pub enum RescanReadError {
    #[error("block data missing at height {height}")]
    Missing { height: u32 },
    #[error("block data corrupt at height {height}: {source}")]
    Corrupt {
        height: u32,
        #[source]
        source: StateError,
    },
    #[error("block data storage failure at height {height}: {source}")]
    Storage {
        height: u32,
        #[source]
        source: StateError,
    },
}

impl RescanReadError {
    pub fn from_state(height: u32, source: StateError) -> Self {
        match source {
            StateError::Serialization(_) | StateError::DbCorruption { .. } => {
                Self::Corrupt { height, source }
            }
            other => Self::Storage {
                height,
                source: other,
            },
        }
    }
}

/// A failure during a wallet rescan operation.
#[derive(Debug, Error)]
pub enum RescanError {
    #[error(transparent)]
    Read(#[from] RescanReadError),
    #[error("rescan cancelled at height {height}")]
    Cancelled { height: u32 },
    #[error("scan matcher failed at height {height}: {reason}")]
    Matcher { height: u32, reason: String },
    #[error("rescan storage failure: {0}")]
    Storage(#[source] redb::Error),
}

impl From<redb::Error> for RescanError {
    fn from(error: redb::Error) -> Self {
        Self::Storage(error)
    }
}

macro_rules! impl_rescan_error_from {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for RescanError {
                fn from(error: $error) -> Self {
                    Self::Storage(error.into())
                }
            }
        )+
    };
}

impl_rescan_error_from!(
    redb::StorageError,
    redb::TableError,
    redb::DatabaseError,
    redb::TransactionError,
    redb::CommitError,
);

/// Service that drives a rescan against a chain-state read interface.
pub struct WalletScanService;

impl WalletScanService {
    /// Full-rebuild (or range-scoped) rescan.
    ///
    /// When `start_height == 0`: full rebuild — clears WALLET_BOXES,
    /// WALLET_BOXES_BY_TX, and WALLET_TXS, sets WALLET_SCAN_INVALIDATED=true,
    /// resets WALLET_SCAN_HEIGHT=0, then replays all blocks in [1..=tip_height].
    /// Clears WALLET_SCAN_INVALIDATED at the end.
    ///
    /// When `start_height > 0`: range-scoped rebuild — deletes rows whose
    /// recorded height >= start_height, rewinds surviving rows whose state
    /// changed at/above start_height back to their pre-start_height status,
    /// rewinds WALLET_SCAN_HEIGHT to start_height-1, then replays
    /// [start_height..=tip_height]. Preserves WALLET_SCAN_INVALIDATED on success;
    /// failure or cancellation sets it and requires a full rescan.
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
    ) -> Result<u32, RescanError>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, RescanReadError>,
        T: FnMut() -> Result<u32, RescanReadError>,
        C: FnMut() -> bool,
    {
        let mut invalidation_guard = InvalidateOnError::new(db);
        let result = Self::rescan_full_rebuild_inner(
            db,
            tracked_p2pk_trees,
            cached_pubkeys,
            start_height,
            tip_height,
            &mut read_block,
            &mut read_tip,
            &mut is_cancelled,
            scan_matcher,
        );
        if result.is_ok() {
            invalidation_guard.disarm();
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn rescan_full_rebuild_inner<F, T, C>(
        db: &Arc<Database>,
        tracked_p2pk_trees: BTreeSet<Vec<u8>>,
        cached_pubkeys: BTreeMap<u64, [u8; 33]>,
        start_height: u32,
        tip_height: u32,
        read_block: &mut F,
        read_tip: &mut T,
        is_cancelled: &mut C,
        scan_matcher: Option<&dyn ScanRescanMatcher>,
    ) -> Result<u32, RescanError>
    where
        F: FnMut(u32) -> Result<Option<RescanBlock>, RescanReadError>,
        T: FnMut() -> Result<u32, RescanReadError>,
        C: FnMut() -> bool,
    {
        if is_cancelled() {
            return Err(RescanError::Cancelled {
                height: start_height,
            });
        }
        // Registered-scan rebuild only on a full rebuild (scans have no
        // range-rewind path). `None` matcher = a node with no scans.
        let scan_rebuild = scan_matcher.is_some() && start_height == 0;

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
                    .map(|entry| entry.map(|(k, _)| k.value()))
                    .collect::<Result<_, _>>()?;
                for k in to_remove {
                    boxes_tbl.remove(k)?;
                    box_bytes_tbl.remove(k)?;
                }
            }
            {
                let mut by_tx = txn.open_table(WALLET_BOXES_BY_TX)?;
                let to_remove: Vec<[u8; 34]> = by_tx
                    .iter()?
                    .map(|entry| entry.map(|(k, _)| k.value()))
                    .collect::<Result<_, _>>()?;
                for k in to_remove {
                    by_tx.remove(k)?;
                }
            }
            {
                let mut txs_tbl = txn.open_table(WALLET_TXS)?;
                let to_remove: Vec<[u8; 36]> = txs_tbl
                    .iter()?
                    .map(|entry| entry.map(|(k, _)| k.value()))
                    .collect::<Result<_, _>>()?;
                for k in to_remove {
                    txs_tbl.remove(k)?;
                }
            }
            set_scan_cursor(&txn, 0, None)?;
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
                    .map(|entry| entry.map(|(k, _)| k.value()))
                    .collect::<Result<_, _>>()?;
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
                let keys = txs_tbl
                    .iter()?
                    .map(|entry| entry.map(|(k, _)| k.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                let to_remove: Vec<[u8; 36]> = keys
                    .into_iter()
                    .filter(|key| key[..4] >= start_be[..])
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
            set_rescan_boundary(&txn, start_height.saturating_sub(1))?;
            txn.commit()?;
        }

        // STEP 2: replay block-by-block with maturity promotion per block.
        // Catch-up loop: after the main replay, re-read tip and replay any
        // blocks that arrived during the rebuild.
        let mut processed = 0u32;
        let mut current_target = tip_height;
        let mut current_start = start_height.max(1);

        loop {
            for h in current_start..=current_target {
                // Per-block cancellation check.
                if is_cancelled() {
                    return Err(RescanError::Cancelled { height: h });
                }
                let block = match read_block(h)? {
                    Some(b) => b,
                    None => {
                        return Err(RescanError::Read(RescanReadError::Missing { height: h }));
                    }
                };
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
                        let matches = matcher
                            .match_boxes(&box_refs)
                            .map_err(|reason| RescanError::Matcher { height: h, reason })?;
                        if matches.len() != box_refs.len() {
                            return Err(RescanError::Matcher {
                                height: h,
                                reason: format!(
                                    "wrong result count: got {}, want {}",
                                    matches.len(),
                                    box_refs.len()
                                ),
                            });
                        }
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
                    // matches + spends. `None` means no scan rebuild is active.
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
                return Err(RescanError::Cancelled {
                    height: current_target,
                });
            }

            let new_target = read_tip()?;
            if new_target <= current_target {
                break; // steady state
            }
            current_start = current_target + 1;
            current_target = new_target;
        }

        // Only a complete full rebuild repairs invalidated wallet state.
        if is_cancelled() {
            return Err(RescanError::Cancelled {
                height: current_target,
            });
        }
        if start_height == 0 {
            let txn = crate::begin_write_qr(db)?;
            // Rollback cancels while holding this writer lock. Recheck under
            // the lock before clearing its durable invalidation.
            if is_cancelled() {
                return Err(RescanError::Cancelled {
                    height: current_target,
                });
            }
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
        Ok(tbl.get(())?.map(|g| g.value()).unwrap_or(0))
    }
}

struct InvalidateOnError<'a> {
    db: &'a Database,
    armed: bool,
}

impl<'a> InvalidateOnError<'a> {
    fn new(db: &'a Database) -> Self {
        Self { db, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for InvalidateOnError<'_> {
    fn drop(&mut self) {
        if self.armed {
            if let Err(e) = invalidate_scan(self.db) {
                tracing::error!(error = %e, "wallet rescan: failed to persist scan invalidation");
            }
        }
    }
}

fn invalidate_scan(db: &Database) -> Result<(), redb::Error> {
    let txn = crate::begin_write_qr(db)?;
    txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), true)?;
    txn.commit()?;
    Ok(())
}

fn set_rescan_boundary(txn: &redb::WriteTransaction, height: u32) -> Result<(), redb::Error> {
    let header_id = if height == 0 {
        None
    } else {
        let table = txn.open_table(crate::store::CHAIN_INDEX)?;
        let bytes = table.get(height as u64)?.ok_or_else(|| {
            redb::Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("rescan boundary {height} missing from chain_index"),
            ))
        })?;
        let bytes = bytes.value();
        if bytes.len() != 32 {
            return Err(redb::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("chain_index row at {height} is not 32 bytes"),
            )));
        }
        let mut header_id = [0u8; 32];
        header_id.copy_from_slice(bytes);
        Some(header_id)
    };
    set_scan_cursor(txn, height, header_id.as_ref())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // ----- helpers -----

    fn database() -> (tempfile::TempDir, Arc<Database>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("rescan.redb")).unwrap());
        (dir, db)
    }

    fn empty_block() -> RescanBlock {
        RescanBlock {
            block_id: [1; 32],
            txs: vec![],
        }
    }

    fn invalidated(db: &Database) -> bool {
        db.begin_read()
            .unwrap()
            .open_table(WALLET_SCAN_INVALIDATED)
            .unwrap()
            .get(())
            .unwrap()
            .unwrap()
            .value()
    }

    #[derive(Debug)]
    struct ReadFaultBackend {
        inner: redb::backends::FileBackend,
        reads: Arc<std::sync::Mutex<Option<Vec<u64>>>>,
        fail_offset: Arc<std::sync::atomic::AtomicU64>,
    }

    impl redb::StorageBackend for ReadFaultBackend {
        fn len(&self) -> std::io::Result<u64> {
            self.inner.len()
        }
        fn read(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
            use std::sync::atomic::Ordering;
            if let Some(reads) = self.reads.lock().unwrap().as_mut() {
                reads.push(offset);
            }
            if self
                .fail_offset
                .compare_exchange(offset, u64::MAX, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Err(std::io::Error::other(
                    "injected transaction-row read failure",
                ));
            }
            self.inner.read(offset, len)
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.inner.set_len(len)
        }
        fn sync_data(&self, eventual: bool) -> std::io::Result<()> {
            self.inner.sync_data(eventual)
        }
        fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
            self.inner.write(offset, data)
        }
    }

    // ----- happy path -----

    #[test]
    fn partial_rescan_success_preserves_invalidation() {
        for initial in [false, true] {
            let (_dir, db) = database();
            let txn = db.begin_write().unwrap();
            txn.open_table(WALLET_SCAN_INVALIDATED)
                .unwrap()
                .insert((), initial)
                .unwrap();
            txn.commit().unwrap();
            let processed = WalletScanService::rescan_full_rebuild(
                &db,
                BTreeSet::new(),
                BTreeMap::new(),
                1,
                1,
                |_| Ok(Some(empty_block())),
                || Ok(1),
                || false,
                None,
            )
            .unwrap();
            assert_eq!(processed, 1);
            assert_eq!(invalidated(&db), initial);
        }
    }

    // ----- error paths -----

    #[test]
    fn full_rebuild_unreadable_transaction_row_preserves_original_error() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rescan.redb");
        let reads = Arc::new(std::sync::Mutex::new(None));
        let fail_offset = Arc::new(AtomicU64::new(u64::MAX));
        let db = Arc::new(
            Database::builder()
                .set_cache_size(0)
                .create_with_backend(ReadFaultBackend {
                    inner: redb::backends::FileBackend::new(
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .open(&path)
                            .unwrap(),
                    )
                    .unwrap(),
                    reads: reads.clone(),
                    fail_offset: fail_offset.clone(),
                })
                .unwrap(),
        );
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(WALLET_TXS).unwrap();
            for index in 0u32..512 {
                let mut key = [0; 36];
                key[..4].copy_from_slice(&index.to_be_bytes());
                table.insert(key, vec![0; 128]).unwrap();
            }
        }
        // A recovery rescan starts with durable invalidation already set.
        txn.open_table(WALLET_SCAN_INVALIDATED)
            .unwrap()
            .insert((), true)
            .unwrap();
        set_scan_cursor(&txn, 7, Some(&[7; 32])).unwrap();
        txn.commit().unwrap();

        // Find a leaf-page read caused by advancing the iterator, after its
        // construction has already loaded the first and last pages.
        let offset = {
            let txn = db.begin_read().unwrap();
            let table = txn.open_table(WALLET_TXS).unwrap();
            let iter = table.iter().unwrap();
            *reads.lock().unwrap() = Some(Vec::new());
            let mut offset = None;
            for entry in iter {
                entry.unwrap();
                if let Some(first) = reads.lock().unwrap().as_ref().unwrap().first() {
                    offset = Some(*first);
                    break;
                }
            }
            *reads.lock().unwrap() = None;
            offset.expect("transaction rows must span multiple leaf pages")
        };
        fail_offset.store(offset, Ordering::SeqCst);
        let result = WalletScanService::rescan_full_rebuild(
            &db,
            BTreeSet::new(),
            BTreeMap::new(),
            0,
            1,
            |_| Ok(Some(empty_block())),
            || Ok(1),
            || false,
            None,
        );
        let error = result.unwrap_err();
        assert!(matches!(error, RescanError::Storage(_)), "{error:?}");
        assert!(
            error
                .to_string()
                .contains("injected transaction-row read failure"),
            "{error}"
        );
        assert_eq!(
            fail_offset.load(Ordering::SeqCst),
            u64::MAX,
            "fault must fire"
        );
        // redb poisons the handle on I/O failure. Reopen to inspect the last
        // durable commit; the failed clear transaction must not publish rows.
        drop(db);
        let db = Database::open(&path).unwrap();
        assert!(invalidated(&db));
        assert_eq!(WalletScanService::current_scan_height(&db).unwrap(), 7);
        assert_eq!(
            db.begin_read()
                .unwrap()
                .open_table(WALLET_TXS)
                .unwrap()
                .iter()
                .unwrap()
                .count(),
            512
        );
    }

    #[test]
    fn rescan_mid_loop_cancellation_invalidates() {
        let (_dir, db) = database();
        let txn = db.begin_write().unwrap();
        txn.open_table(WALLET_SCAN_INVALIDATED)
            .unwrap()
            .insert((), false)
            .unwrap();
        txn.commit().unwrap();
        let cancelled = Cell::new(false);
        let result = WalletScanService::rescan_full_rebuild(
            &db,
            BTreeSet::new(),
            BTreeMap::new(),
            1,
            2,
            |height| {
                assert_eq!(height, 1);
                cancelled.set(true);
                Ok(Some(empty_block()))
            },
            || Ok(2),
            || cancelled.get(),
            None,
        );
        assert!(matches!(result, Err(RescanError::Cancelled { .. })));
        assert!(invalidated(&db));
    }

    #[test]
    fn rescan_rollback_before_final_write_preserves_invalidation() {
        let (_dir, db) = database();
        let reached_tip = Cell::new(false);
        let cancelled = Cell::new(false);
        let result = WalletScanService::rescan_full_rebuild(
            &db,
            BTreeSet::new(),
            BTreeMap::new(),
            0,
            1,
            |height| Ok((height == 1).then(empty_block)),
            || {
                reached_tip.set(true);
                Ok(1)
            },
            || {
                let observed = cancelled.get();
                if reached_tip.get() && !observed {
                    // Commit rollback invalidation after the last unlocked check
                    // took its snapshot, before the rescan acquires the writer.
                    let txn = db.begin_write().unwrap();
                    cancelled.set(true);
                    txn.open_table(WALLET_SCAN_INVALIDATED)
                        .unwrap()
                        .insert((), true)
                        .unwrap();
                    txn.commit().unwrap();
                }
                observed
            },
            None,
        );
        assert!(matches!(result, Err(RescanError::Cancelled { .. })));
        assert!(invalidated(&db));
    }
}

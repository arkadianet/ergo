//! Wallet apply / rollback hook. Called from
//! `ergo-state::store::apply_block` and `::rollback_block` so wallet
//! state advances atomically with chain state — both writes share
//! the same `WriteTransaction`, both commit or both abort.
//!
//! Classification per Scala `WalletScanLogic.scala:92-93,168,183-209`:
//! - Output with ErgoTree bytes in `WalletState::tracked_p2pk_trees`
//!   → record as Confirmed (or Immature if miner-reward shape).
//! - Output whose ErgoTree matches the mining-reward template (top-
//!   level `{ height > rewardWithdrawal && proveDlog(p) }`) AND
//!   goes to a tracked pubkey → MinerReward { matures_at }.
//! - Input box_id present in `WALLET_BOXES` → mark Spent.
//! - Everything else: ignored.

#![allow(clippy::result_large_err)] // redb::Error shape is fixed upstream

use crate::wallet::tables::*;
use crate::wallet::types::{BoxProvenance, BoxStatus, WalletBox, WalletTransaction};
use redb::{ReadableTable, WriteTransaction};
use std::collections::{BTreeMap, BTreeSet};

/// Mining-reward maturity per Scala `WalletScanLogic`:
/// mainnet = 720 blocks. Hardcoded to mainnet; testnet/devnet
/// support requires integrators surfacing a network-aware constant.
pub const REWARD_MATURITY_MAINNET: u32 = 720;

/// Minimal block-tx view the apply hook needs. The integrator
/// (ergo-state::store::apply_block) constructs this from its full
/// `Transaction` representation.
pub struct BlockTx<'a> {
    pub tx_id: [u8; 32],
    pub inputs: &'a [[u8; 32]], // box ids referenced
    pub outputs: &'a [BlockOutput<'a>],
}

pub struct BlockOutput<'a> {
    pub box_id: [u8; 32],
    pub output_index: u16,
    /// Canonical ErgoTree bytes (the bytes that go on disk in the
    /// block's BlockTransactions section). For a miner-reward box,
    /// these are the WRAPPER-script bytes (not bare P2PK) — Scala
    /// `WalletScanLogic.scala:183-209` recognizes mining rewards via
    /// the wrapper shape, NOT via tracked-tree membership.
    pub ergo_tree_bytes: &'a [u8],
    pub value: u64,
    pub assets: Vec<([u8; 32], u64)>,
    /// If `Some(pk)`, this output's ErgoTree matched the canonical
    /// mining-reward template `{ HEIGHT >= rewardUnlockHeight &&
    /// proveDlog(pk) }`, and `pk` is the 33-byte compressed pubkey
    /// embedded in the proveDlog branch. The apply hook checks
    /// `pk ∈ wallet.cached_pubkeys` to decide whether THIS wallet
    /// owns the reward.
    ///
    /// `None` means: not a miner-reward shape. The output is then
    /// classified by bare-P2PK tracked-tree membership against
    /// `wallet.tracked_p2pk_trees` (which is the Owned/Custom
    /// branch).
    ///
    /// Integrator extracts both the shape match and the embedded
    /// pubkey at parse time. If the integrator mis-classifies (e.g.,
    /// a non-reward wrapper script that happens to embed a tracked
    /// pubkey is flagged as MinerReward), the consequence is wrong
    /// maturity window — not a spending-correctness break.
    pub miner_reward_pubkey: Option<[u8; 33]>,
    /// Full serialized box bytes (`serialize_ergo_box`), stored in
    /// `WALLET_BOX_BYTES` for matched wallet boxes so the reserved-scan reads
    /// (`/scan/{unspent,spent}Boxes/9|10`) can surface the box. May be empty —
    /// the live builder reuses the box-id serialization to fill it for free, but
    /// callers that don't have the bytes pass `&[]`, in which case the read
    /// degrades to empty `bytes` until a `/wallet/rescan` backfills it.
    pub box_bytes: &'a [u8],
}

/// Apply a single full block to the wallet tables. Called inside
/// the SAME redb write txn as chain apply.
///
/// Order matters: for each tx in block-order, process inputs THEN
/// outputs (so a same-block create-then-spend correctly transitions
/// the created box through Confirmed → Spent in one txn).
///
/// Live chain-apply path. Checks the persistent
/// `WALLET_SCAN_INVALIDATED` flag and SKIPS ALL wallet side-effects
/// (input-marking, output-classification, maturity-promotion, AND
/// `WALLET_SCAN_HEIGHT` advance) when set. The chain-apply
/// integrator should still proceed with chain state; only the
/// wallet hook no-ops.
///
/// Use this from the chain-apply hook. For rescan replay, use
/// `apply_block_to_wallet_rescan` (the privileged variant that
/// bypasses the invalidated check).
///
/// The apply hook is data-driven, not type-driven: the integrator
/// passes the wallet's `tracked_p2pk_trees` (a `BTreeSet<Vec<u8>>`
/// of canonical P2PK tree bytes) and `cached_pubkeys` (a
/// `BTreeMap<u64, [u8; 33]>` of derivation-index → pubkey bytes)
/// directly. This avoids `ergo-state` needing to import
/// `ergo-wallet::state::WalletState` (which would invert the dep
/// direction).
pub fn apply_block_to_wallet(
    txn: &WriteTransaction,
    tracked_p2pk_trees: &BTreeSet<Vec<u8>>,
    cached_pubkeys: &BTreeMap<u64, [u8; 33]>,
    block_height: u32,
    block_id: &[u8; 32],
    txs: &[BlockTx<'_>],
) -> Result<(), redb::Error> {
    if is_scan_invalidated(txn)? {
        return Ok(()); // pause ALL wallet side-effects
    }
    apply_block_to_wallet_rescan(
        txn,
        tracked_p2pk_trees,
        cached_pubkeys,
        block_height,
        block_id,
        txs,
    )
}

/// Privileged rescan-replay variant. Bypasses the invalidated check
/// since rescan IS the recovery path from invalidated state. The
/// caller (`WalletScanService::rescan_full_rebuild`) is responsible
/// for setting/clearing `WALLET_SCAN_INVALIDATED` around the full
/// replay loop.
pub fn apply_block_to_wallet_rescan(
    txn: &WriteTransaction,
    tracked_p2pk_trees: &BTreeSet<Vec<u8>>,
    cached_pubkeys: &BTreeMap<u64, [u8; 33]>,
    block_height: u32,
    block_id: &[u8; 32],
    txs: &[BlockTx<'_>],
) -> Result<(), redb::Error> {
    for tx in txs {
        apply_inputs(txn, tx, block_height)?;
        apply_outputs(
            txn,
            tracked_p2pk_trees,
            cached_pubkeys,
            block_height,
            block_id,
            tx,
        )?;
    }
    // Advance scan height.
    let mut scan_height_tbl = txn.open_table(WALLET_SCAN_HEIGHT)?;
    scan_height_tbl.insert((), block_height)?;
    Ok(())
}

/// Read the persistent "scan invalidated" flag. Returns false if
/// the table doesn't exist yet (fresh wallet) or contains false.
pub fn is_scan_invalidated(txn: &WriteTransaction) -> Result<bool, redb::Error> {
    match txn.open_table(WALLET_SCAN_INVALIDATED) {
        Ok(t) => Ok(t.get(()).ok().flatten().map(|g| g.value()).unwrap_or(false)),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn apply_inputs(
    txn: &WriteTransaction,
    tx: &BlockTx<'_>,
    block_height: u32,
) -> Result<(), redb::Error> {
    let mut boxes_tbl = txn.open_table(WALLET_BOXES)?;
    for input_box_id in tx.inputs {
        // Clone the bytes out of the AccessGuard before the mutable borrow.
        let existing: Option<Vec<u8>> = boxes_tbl.get(*input_box_id)?.map(|g| g.value().to_owned());
        if let Some(raw_bytes) = existing {
            let mut wb: WalletBox = bincode::deserialize(&raw_bytes).map_err(|e| {
                redb::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("WalletBox deserialize: {e}"),
                ))
            })?;
            // Only transition Confirmed/Immature → Spent.
            // Re-spending an already-Spent box should never happen
            // for a valid chain, but guard against double-marking.
            if matches!(wb.status, BoxStatus::Confirmed | BoxStatus::Immature { .. }) {
                wb.status = BoxStatus::Spent {
                    spent_in_tx: tx.tx_id,
                    spent_at: block_height,
                };
                let bytes = bincode::serialize(&wb).map_err(|e| {
                    redb::Error::Io(std::io::Error::other(format!("WalletBox serialize: {e}")))
                })?;
                boxes_tbl.insert(*input_box_id, bytes)?;
            }
        }
    }
    Ok(())
}

fn apply_outputs(
    txn: &WriteTransaction,
    tracked_p2pk_trees: &BTreeSet<Vec<u8>>,
    cached_pubkeys: &BTreeMap<u64, [u8; 33]>,
    block_height: u32,
    block_id: &[u8; 32],
    tx: &BlockTx<'_>,
) -> Result<(), redb::Error> {
    let mut boxes_tbl = txn.open_table(WALLET_BOXES)?;
    let mut idx_tbl = txn.open_table(WALLET_BOXES_BY_TX)?;
    let mut box_bytes_tbl = txn.open_table(WALLET_BOX_BYTES)?;
    let mut wallet_outputs: Vec<[u8; 32]> = Vec::new();

    for output in tx.outputs {
        // Classify per Scala WalletScanLogic.scala:183-209:
        // - If output is a miner-reward wrapper script AND the embedded
        //   pubkey is tracked → MinerReward (Immature).
        // - Else if output's tree itself is in tracked_p2pk_trees
        //   (bare P2PK to a tracked pubkey) → Owned (Confirmed).
        // - Else: ignored.
        let (status, provenance) = if let Some(pk) = output.miner_reward_pubkey {
            if cached_pubkeys.values().any(|tracked| tracked == &pk) {
                (
                    BoxStatus::Immature {
                        matures_at: block_height.saturating_add(REWARD_MATURITY_MAINNET),
                    },
                    BoxProvenance::MinerReward,
                )
            } else {
                continue; // miner-reward to a non-tracked pubkey
            }
        } else if tracked_p2pk_trees.contains(output.ergo_tree_bytes) {
            (BoxStatus::Confirmed, BoxProvenance::Owned)
        } else {
            continue; // untracked
        };

        let wb = WalletBox {
            box_id: output.box_id,
            creation_tx_id: tx.tx_id,
            creation_output_index: output.output_index,
            creation_height: block_height,
            value: output.value,
            assets: output.assets.clone(),
            status,
            provenance,
        };
        let bytes = bincode::serialize(&wb).map_err(|e| {
            redb::Error::Io(std::io::Error::other(format!("WalletBox serialize: {e}")))
        })?;
        boxes_tbl.insert(output.box_id, bytes)?;
        idx_tbl.insert(box_by_tx_key(&tx.tx_id, output.output_index), output.box_id)?;
        // Store the full box bytes for the reserved-scan reads (9/10). Skip when
        // empty (a caller without the bytes) — the read degrades to empty
        // `bytes` until a rescan backfills it.
        if !output.box_bytes.is_empty() {
            box_bytes_tbl.insert(output.box_id, output.box_bytes.to_vec())?;
        }
        wallet_outputs.push(output.box_id);
    }

    // If this tx touched the wallet (in or out), record it in WALLET_TXS.
    let wallet_inputs: Vec<[u8; 32]> = tx
        .inputs
        .iter()
        .filter(|id| boxes_tbl.get(**id).ok().flatten().is_some())
        .copied()
        .collect();
    if !wallet_outputs.is_empty() || !wallet_inputs.is_empty() {
        let wt = WalletTransaction {
            tx_id: tx.tx_id,
            block_height,
            block_id: *block_id,
            wallet_outputs,
            wallet_inputs,
        };
        let bytes = bincode::serialize(&wt).map_err(|e| {
            redb::Error::Io(std::io::Error::other(format!(
                "WalletTransaction serialize: {e}"
            )))
        })?;
        let mut txs_tbl = txn.open_table(WALLET_TXS)?;
        txs_tbl.insert(wallet_tx_key(block_height, &tx.tx_id), bytes)?;
    }
    Ok(())
}

/// Trait the integrator implements to give rollback access to the
/// rescan-cancellation primitive. Wiring is explicit so the
/// integrator can't omit it.
///
/// Production impl (in `ergo-node/src/wallet_boot.rs`): flips
/// `RESCAN_IN_PROGRESS = false` AND writes
/// `WALLET_SCAN_INVALIDATED = true` (via the supplied `txn`, so
/// both rollback's table changes and the invalidated flip commit
/// atomically).
pub trait RescanGuard {
    /// Abort any in-progress rescan AND invalidate wallet scan
    /// state IF (and only if) a rescan was actually running.
    /// Called from `rollback_block_from_wallet` on EVERY rollback
    /// (success or failure) — the wallet may have been partially
    /// reorged by an active rescan, so any rescan-in-progress
    /// becomes invalid once the underlying chain rolls back. A
    /// successful rollback without an active rescan is a no-op:
    /// wallet state is consistent with the rolled-back chain, no
    /// invalidation needed.
    fn abort_in_progress(&self, txn: &WriteTransaction) -> Result<(), redb::Error>;

    /// Unconditionally invalidate wallet scan state. Called from
    /// `StateStore::rollback_to`'s failure branches (missing block
    /// section, block-section read error) where wallet history
    /// cannot be reliably maintained against chain state. The next
    /// restart sees `WALLET_SCAN_INVALIDATED = true` and triggers
    /// a full rescan. Distinct from `abort_in_progress` because
    /// this path must invalidate even when no rescan was active —
    /// the wallet is stale by construction, not by interrupted
    /// work.
    fn force_invalidate(&self, txn: &WriteTransaction) -> Result<(), redb::Error>;
}

/// Rollback a previously-applied block from the wallet tables.
/// Called inside the SAME redb write txn as chain rollback, after
/// the chain rollback completes — wallet state regresses to match.
///
/// For each tx in REVERSE order:
/// - Outputs that were inserted into WALLET_BOXES are removed.
/// - Inputs whose target box transitioned to Spent at this height
///   transition back to their pre-spend status.
///
/// Determining the pre-spend status: we stored it implicitly by
/// keeping the box around in the Spent state. To rollback, we
/// transition Spent → Confirmed (or Immature, if the box was
/// originally a miner reward — we re-derive from creation_height
/// and the box's provenance flag).
pub fn rollback_block_from_wallet(
    txn: &WriteTransaction,
    block_height: u32,
    txs: &[BlockTx<'_>],
    rescan_guard: &dyn RescanGuard,
) -> Result<(), redb::Error> {
    // `abort_in_progress` is conditional: it sets
    // `WALLET_SCAN_INVALIDATED = true` only if a rescan was actually
    // running. Successful rollback without an active rescan keeps
    // wallet state consistent with the rolled-back chain — no
    // invalidation needed. If a rescan WAS running, it was working
    // against a chain state that's now gone, so its accumulated
    // state is invalid and `WALLET_SCAN_INVALIDATED` must be set.
    // Both writes go through `txn` so they commit atomically with
    // rollback's table changes. The distinct `force_invalidate`
    // call is used by `StateStore::rollback_to`'s failure branches
    // (missing section / read error) where wallet history cannot
    // be replayed.
    rescan_guard.abort_in_progress(txn)?;
    let mut boxes_tbl = txn.open_table(WALLET_BOXES)?;
    let mut idx_tbl = txn.open_table(WALLET_BOXES_BY_TX)?;
    let mut box_bytes_tbl = txn.open_table(WALLET_BOX_BYTES)?;
    let mut txs_tbl = txn.open_table(WALLET_TXS)?;

    // Reverse-order pass.
    for tx in txs.iter().rev() {
        // Remove wallet_tx row (if present).
        txs_tbl.remove(wallet_tx_key(block_height, &tx.tx_id))?;

        // Un-spend inputs: any input that transitioned at this
        // block height should revert to its prior status.
        for input_box_id in tx.inputs {
            // Clone bytes out before the mutable borrow.
            let existing: Option<Vec<u8>> =
                boxes_tbl.get(*input_box_id)?.map(|g| g.value().to_owned());
            if let Some(raw_bytes) = existing {
                let mut wb: WalletBox = bincode::deserialize(&raw_bytes).map_err(|e| {
                    redb::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("WalletBox deserialize: {e}"),
                    ))
                })?;
                if let BoxStatus::Spent {
                    spent_in_tx,
                    spent_at,
                } = &wb.status
                {
                    if *spent_at == block_height && spent_in_tx == &tx.tx_id {
                        // Revert: if the box was originally a miner
                        // reward AND it's still inside the maturity
                        // window relative to the new tip, status =
                        // Immature; else Confirmed. We're inside the
                        // rollback, so block_height is the height we
                        // just rolled back FROM. The new tip is
                        // block_height - 1. The box matures at
                        // creation_height + REWARD_MATURITY_MAINNET.
                        wb.status = match wb.provenance {
                            BoxProvenance::MinerReward => {
                                let matures_at =
                                    wb.creation_height.saturating_add(REWARD_MATURITY_MAINNET);
                                if matures_at > block_height.saturating_sub(1) {
                                    BoxStatus::Immature { matures_at }
                                } else {
                                    BoxStatus::Confirmed
                                }
                            }
                            _ => BoxStatus::Confirmed,
                        };
                        let bytes = bincode::serialize(&wb).map_err(|e| {
                            redb::Error::Io(std::io::Error::other(format!(
                                "WalletBox serialize: {e}"
                            )))
                        })?;
                        boxes_tbl.insert(*input_box_id, bytes)?;
                    }
                }
            }
        }

        // Remove outputs that were created in this tx.
        for output in tx.outputs {
            boxes_tbl.remove(output.box_id)?;
            box_bytes_tbl.remove(output.box_id)?;
            idx_tbl.remove(box_by_tx_key(&tx.tx_id, output.output_index))?;
        }
    }

    // Roll back scan height — but only LOWER an existing row, never create or
    // raise one. A keyless / scan-only wallet never advanced WALLET_SCAN_HEIGHT
    // at apply (the `has_wallet_tracking` gate), so a reorg must not conjure a
    // bogus height for it (which `/wallet/status` + `/wallet/balances` would
    // then report as `walletHeight`). And a wallet frozen behind the tip
    // (e.g. mid-rescan) must not be dragged forward by a rollback.
    let target = block_height.saturating_sub(1);
    let mut scan_height_tbl = txn.open_table(WALLET_SCAN_HEIGHT)?;
    let current = scan_height_tbl.get(())?.map(|g| g.value());
    if let Some(current) = current {
        if current > target {
            scan_height_tbl.insert((), target)?;
        }
    }
    Ok(())
}

mod scan_tracking;

pub(crate) use scan_tracking::{
    apply_block_to_scans, apply_block_to_scans_rescan, clear_scan_tracking,
    rollback_scans_from_block,
};

#[cfg(test)]
mod scan_tests;

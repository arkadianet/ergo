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

use crate::store::ScanMatchRecord;
use crate::wallet::tables::*;
use crate::wallet::types::{
    BoxProvenance, BoxStatus, ScanBoxStatus, ScanTrackedBox, ScanTxRecord, WalletBox,
    WalletTransaction,
};
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

// ---- `/scan/*` block-apply tracking ----
//
// Independent of the pubkey-wallet hook above and of the
// `WALLET_SCAN_INVALIDATED` flag (which governs wallet-pubkey rescan, not
// scans): registered scans track every applied block forward. Matching itself
// runs on the main thread via the hook (the `ergo-wallet` matcher); here we
// only persist the pre-computed match records + spend transitions, atomically
// in the chain write-txn.

fn scan_ser<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, redb::Error> {
    bincode::serialize(v)
        .map_err(|e| redb::Error::Io(std::io::Error::other(format!("scan serialize: {e}"))))
}

fn scan_de_box(raw: &[u8]) -> Result<ScanTrackedBox, redb::Error> {
    bincode::deserialize(raw).map_err(|e| {
        redb::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("ScanTrackedBox deserialize: {e}"),
        ))
    })
}

fn scan_de_ids(raw: &[u8]) -> Result<Vec<u16>, redb::Error> {
    bincode::deserialize(raw).map_err(|e| {
        redb::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("scan index deserialize: {e}"),
        ))
    })
}

/// Persist a block's scan matches into the scan-box tables, inside the SAME
/// write txn as chain apply. Two phases (mirroring the wallet hook): phase 1
/// creates each matched output as an `Unspent` [`ScanTrackedBox`] (one row per
/// `(scan, box)`) and unions the scans into the box→scans reverse index; phase
/// 2 marks any input that spends a scan-tracked box as `Spent`.
///
/// A box created AND spent within the same block is handled, because phase 1
/// runs before phase 2.
pub(crate) fn apply_block_to_scans(
    txn: &WriteTransaction,
    scan_matches: &[ScanMatchRecord],
    txs: &[BlockTx<'_>],
    block_height: u32,
    block_id: &[u8; 32],
) -> Result<(), redb::Error> {
    let mut boxes_tbl = txn.open_table(WALLET_SCAN_BOXES)?;
    let mut index_tbl = txn.open_table(WALLET_SCAN_BOX_INDEX)?;

    // Phase 1: create matched boxes + reverse index.
    for rec in scan_matches {
        let mut ids: Vec<u16> = match index_tbl.get(rec.box_id)? {
            Some(g) => scan_de_ids(&g.value())?,
            None => Vec::new(),
        };
        for &sid in &rec.scan_ids {
            if !ids.contains(&sid) {
                ids.push(sid);
            }
        }
        ids.sort_unstable();
        index_tbl.insert(rec.box_id, scan_ser(&ids)?)?;

        for &sid in &rec.scan_ids {
            let tb = ScanTrackedBox {
                scan_id: sid,
                box_id: rec.box_id,
                inclusion_height: rec.inclusion_height,
                creation_out_index: rec.creation_out_index,
                box_bytes: rec.box_bytes.clone(),
                status: ScanBoxStatus::Unspent,
            };
            boxes_tbl.insert(scan_box_key(sid, &rec.box_id), scan_ser(&tb)?)?;
        }
    }

    // Created-box lookup for phase 3: box_id -> the scans that matched it.
    let matched_by_box: std::collections::BTreeMap<[u8; 32], &Vec<u16>> = scan_matches
        .iter()
        .map(|rec| (rec.box_id, &rec.scan_ids))
        .collect();

    // Phase 2: mark spends. Each input that hits a tracked box transitions it
    // Unspent → Spent for every scan that tracks it. Per-tx spend hits are
    // collected for phase 3's per-tx scan-id union.
    let mut spent_hits: Vec<(Vec<[u8; 32]>, Vec<u16>)> = vec![(Vec::new(), Vec::new()); txs.len()];
    for (ti, tx) in txs.iter().enumerate() {
        for input_box_id in tx.inputs {
            let ids = match index_tbl.get(*input_box_id)? {
                Some(g) => scan_de_ids(&g.value())?,
                None => continue,
            };
            spent_hits[ti].0.push(*input_box_id);
            spent_hits[ti].1.extend(ids.iter().copied());
            for sid in ids {
                let key = scan_box_key(sid, input_box_id);
                let raw = match boxes_tbl.get(key)? {
                    Some(g) => g.value().to_vec(),
                    None => continue,
                };
                let mut tb = scan_de_box(&raw)?;
                if matches!(tb.status, ScanBoxStatus::Unspent) {
                    tb.status = ScanBoxStatus::Spent {
                        spent_in_tx: tx.tx_id,
                        spent_at: block_height,
                    };
                    boxes_tbl.insert(key, scan_ser(&tb)?)?;
                }
            }
        }
    }

    // Phase 3: per-tx scan tagging (Scala `WalletScanLogic`: a tx is stored
    // with the union of scan ids over its spent + created scan-relevant
    // boxes). One `ScanTxRecord` per tx with a non-empty union — backs
    // `/wallet/transactionsByScanId` for user scans.
    let mut txs_tbl = txn.open_table(WALLET_SCAN_TXS)?;
    for (ti, tx) in txs.iter().enumerate() {
        let (spent, mut union) = std::mem::take(&mut spent_hits[ti]);
        let mut created: Vec<[u8; 32]> = Vec::new();
        for output in tx.outputs {
            if let Some(ids) = matched_by_box.get(&output.box_id) {
                created.push(output.box_id);
                union.extend(ids.iter().copied());
            }
        }
        if union.is_empty() {
            continue;
        }
        union.sort_unstable();
        union.dedup();
        let rec = ScanTxRecord {
            tx_id: tx.tx_id,
            block_height,
            block_id: *block_id,
            scan_ids: union,
            created,
            spent,
        };
        txs_tbl.insert(wallet_tx_key(block_height, &tx.tx_id), scan_ser(&rec)?)?;
    }
    Ok(())
}

/// Roll back a block's scan tracking (mirror of [`apply_block_to_scans`]),
/// inside the SAME write txn as chain rollback. For each tx in REVERSE order:
///   - un-spend inputs that were spent AT this height by THIS tx;
///   - remove output boxes created in this block (looked up via the reverse
///     index, so the original match records aren't needed at rollback).
///
/// Reorg rolls back tip-down, so a box created here but spent in a later block
/// is first un-spent (that later block's rollback) and then removed here.
pub(crate) fn rollback_scans_from_block(
    txn: &WriteTransaction,
    txs: &[BlockTx<'_>],
    block_height: u32,
) -> Result<(), redb::Error> {
    let mut boxes_tbl = txn.open_table(WALLET_SCAN_BOXES)?;
    let mut index_tbl = txn.open_table(WALLET_SCAN_BOX_INDEX)?;
    let mut txs_tbl = txn.open_table(WALLET_SCAN_TXS)?;

    for tx in txs.iter().rev() {
        // Remove this tx's scan-tx row (if present) — mirror of phase 3.
        txs_tbl.remove(wallet_tx_key(block_height, &tx.tx_id))?;

        // Un-spend inputs spent at this height by this tx.
        for input_box_id in tx.inputs {
            let ids = match index_tbl.get(*input_box_id)? {
                Some(g) => scan_de_ids(&g.value())?,
                None => continue,
            };
            for sid in ids {
                let key = scan_box_key(sid, input_box_id);
                let raw = match boxes_tbl.get(key)? {
                    Some(g) => g.value().to_vec(),
                    None => continue,
                };
                let mut tb = scan_de_box(&raw)?;
                if let ScanBoxStatus::Spent {
                    spent_at,
                    spent_in_tx,
                } = &tb.status
                {
                    if *spent_at == block_height && spent_in_tx == &tx.tx_id {
                        tb.status = ScanBoxStatus::Unspent;
                        boxes_tbl.insert(key, scan_ser(&tb)?)?;
                    }
                }
            }
        }
        // Remove outputs created by this tx (via the reverse index).
        for output in tx.outputs {
            let ids = match index_tbl.get(output.box_id)? {
                Some(g) => scan_de_ids(&g.value())?,
                None => continue,
            };
            for sid in ids {
                boxes_tbl.remove(scan_box_key(sid, &output.box_id))?;
            }
            index_tbl.remove(output.box_id)?;
        }
    }
    Ok(())
}

/// Drop ALL scan-tracked boxes + the reverse index, inside the chain
/// write-txn. Called from the reorg paths that cannot replay a block's txs
/// (pruned / unreadable section) and so can't selectively roll scans back:
/// rather than leave orphaned-fork boxes visible via `/scan/*Boxes`, we clear
/// the scan tables so scans re-track forward from the new tip. (Those paths
/// already force-invalidate the wallet for a full rescan; rebuilding scan
/// history is a follow-up — there is no scan rescan yet.)
pub(crate) fn clear_scan_tracking(txn: &WriteTransaction) -> Result<(), redb::Error> {
    txn.delete_table(WALLET_SCAN_BOXES)
        .map_err(redb::Error::from)?;
    txn.delete_table(WALLET_SCAN_BOX_INDEX)
        .map_err(redb::Error::from)?;
    txn.delete_table(WALLET_SCAN_TXS)
        .map_err(redb::Error::from)?;
    Ok(())
}

#[cfg(test)]
mod scan_tests {
    use super::*;
    use crate::store::ScanMatchRecord;

    fn temp_db() -> (tempfile::TempDir, redb::Database) {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("scan.redb")).unwrap();
        (dir, db)
    }

    fn match_rec(box_fill: u8, scan_ids: Vec<u16>, h: u32) -> ScanMatchRecord {
        ScanMatchRecord {
            box_id: [box_fill; 32],
            scan_ids,
            box_bytes: vec![0xAB, 0xCD],
            inclusion_height: h,
            creation_out_index: 0,
        }
    }

    fn out(box_fill: u8, tree: &[u8]) -> BlockOutput<'_> {
        BlockOutput {
            box_id: [box_fill; 32],
            output_index: 0,
            ergo_tree_bytes: tree,
            value: 0,
            assets: Vec::new(),
            miner_reward_pubkey: None,
            box_bytes: &[],
        }
    }

    /// Fixed block id for all scan-test applies (the record's `block_id`
    /// field is asserted against this).
    const TEST_BLOCK_ID: [u8; 32] = [0xE0; 32];

    fn apply(db: &redb::Database, matches: &[ScanMatchRecord], txs: &[BlockTx<'_>], h: u32) {
        let w = db.begin_write().unwrap();
        apply_block_to_scans(&w, matches, txs, h, &TEST_BLOCK_ID).unwrap();
        w.commit().unwrap();
    }

    /// Every `WALLET_SCAN_TXS` row, in table (height, tx_id) order.
    fn scan_txs(db: &redb::Database) -> Vec<ScanTxRecord> {
        let r = db.begin_read().unwrap();
        let t = match r.open_table(WALLET_SCAN_TXS) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        t.iter()
            .unwrap()
            .map(|e| bincode::deserialize(&e.unwrap().1.value()).unwrap())
            .collect()
    }

    fn rollback(db: &redb::Database, txs: &[BlockTx<'_>], h: u32) {
        let w = db.begin_write().unwrap();
        rollback_scans_from_block(&w, txs, h).unwrap();
        w.commit().unwrap();
    }

    fn tracked(db: &redb::Database, scan_id: u16, box_fill: u8) -> Option<ScanTrackedBox> {
        let r = db.begin_read().unwrap();
        let t = match r.open_table(WALLET_SCAN_BOXES) {
            Ok(t) => t,
            Err(_) => return None,
        };
        t.get(scan_box_key(scan_id, &[box_fill; 32]))
            .unwrap()
            .map(|g| bincode::deserialize(&g.value()).unwrap())
    }

    #[test]
    fn apply_creates_one_unspent_row_per_matching_scan() {
        let (_d, db) = temp_db();
        let tree = Vec::new();
        let outs = vec![out(0xA1, &tree)];
        let inputs: Vec<[u8; 32]> = vec![];
        let txs = vec![BlockTx {
            tx_id: [1u8; 32],
            inputs: &inputs,
            outputs: &outs,
        }];
        apply(&db, &[match_rec(0xA1, vec![11, 12], 100)], &txs, 100);

        let b11 = tracked(&db, 11, 0xA1).expect("scan 11 tracks the box");
        assert!(matches!(b11.status, ScanBoxStatus::Unspent));
        assert_eq!(b11.inclusion_height, 100);
        assert!(matches!(
            tracked(&db, 12, 0xA1).unwrap().status,
            ScanBoxStatus::Unspent
        ));
        assert!(tracked(&db, 13, 0xA1).is_none(), "non-matching scan absent");
    }

    #[test]
    fn input_spending_a_tracked_box_marks_it_spent_for_all_scans() {
        let (_d, db) = temp_db();
        let tree = Vec::new();
        // Block 100: create box A for scans 11 + 12.
        let outs1 = vec![out(0xA1, &tree)];
        let in1: Vec<[u8; 32]> = vec![];
        apply(
            &db,
            &[match_rec(0xA1, vec![11, 12], 100)],
            &[BlockTx {
                tx_id: [1u8; 32],
                inputs: &in1,
                outputs: &outs1,
            }],
            100,
        );
        // Block 101: a tx spends box A.
        let in2: Vec<[u8; 32]> = vec![[0xA1; 32]];
        let outs2: Vec<BlockOutput<'_>> = vec![];
        apply(
            &db,
            &[],
            &[BlockTx {
                tx_id: [2u8; 32],
                inputs: &in2,
                outputs: &outs2,
            }],
            101,
        );

        for sid in [11u16, 12] {
            assert!(
                matches!(
                    tracked(&db, sid, 0xA1).unwrap().status,
                    ScanBoxStatus::Spent { spent_at: 101, .. }
                ),
                "scan {sid} box marked spent at 101"
            );
        }
    }

    #[test]
    fn same_block_create_then_spend_ends_spent() {
        let (_d, db) = temp_db();
        let tree = Vec::new();
        let outs = vec![out(0xA1, &tree)];
        // tx1 creates A (matched); tx2 spends A — same block.
        let in1: Vec<[u8; 32]> = vec![];
        let in2: Vec<[u8; 32]> = vec![[0xA1; 32]];
        let empty: Vec<BlockOutput<'_>> = vec![];
        let txs = vec![
            BlockTx {
                tx_id: [1u8; 32],
                inputs: &in1,
                outputs: &outs,
            },
            BlockTx {
                tx_id: [2u8; 32],
                inputs: &in2,
                outputs: &empty,
            },
        ];
        apply(&db, &[match_rec(0xA1, vec![11], 100)], &txs, 100);
        assert!(matches!(
            tracked(&db, 11, 0xA1).unwrap().status,
            ScanBoxStatus::Spent { spent_at: 100, .. }
        ));
    }

    #[test]
    fn rollback_removes_boxes_created_in_the_block() {
        let (_d, db) = temp_db();
        let tree = Vec::new();
        let outs = vec![out(0xA1, &tree)];
        let inputs: Vec<[u8; 32]> = vec![];
        let txs = vec![BlockTx {
            tx_id: [1u8; 32],
            inputs: &inputs,
            outputs: &outs,
        }];
        apply(&db, &[match_rec(0xA1, vec![11], 100)], &txs, 100);
        assert!(tracked(&db, 11, 0xA1).is_some());

        rollback(&db, &txs, 100);
        assert!(tracked(&db, 11, 0xA1).is_none(), "created box removed");
        // index entry gone too.
        let r = db.begin_read().unwrap();
        let idx = r.open_table(WALLET_SCAN_BOX_INDEX).unwrap();
        assert!(idx.get([0xA1u8; 32]).unwrap().is_none());
    }

    #[test]
    fn clear_scan_tracking_drops_all_scan_rows() {
        let (_d, db) = temp_db();
        let tree = Vec::new();
        let outs = vec![out(0xA1, &tree)];
        let inputs: Vec<[u8; 32]> = vec![];
        apply(
            &db,
            &[match_rec(0xA1, vec![11, 12], 100)],
            &[BlockTx {
                tx_id: [1u8; 32],
                inputs: &inputs,
                outputs: &outs,
            }],
            100,
        );
        assert!(tracked(&db, 11, 0xA1).is_some());

        let w = db.begin_write().unwrap();
        clear_scan_tracking(&w).unwrap();
        w.commit().unwrap();

        assert!(tracked(&db, 11, 0xA1).is_none(), "all scan boxes cleared");
        assert!(tracked(&db, 12, 0xA1).is_none());
        // Clearing an already-empty/absent set is a no-op (idempotent).
        let w = db.begin_write().unwrap();
        clear_scan_tracking(&w).unwrap();
        w.commit().unwrap();
    }

    #[test]
    fn rollback_unspends_inputs_spent_in_the_block() {
        let (_d, db) = temp_db();
        let tree = Vec::new();
        // Block 100 creates A; block 101 spends A.
        let outs1 = vec![out(0xA1, &tree)];
        let in1: Vec<[u8; 32]> = vec![];
        apply(
            &db,
            &[match_rec(0xA1, vec![11], 100)],
            &[BlockTx {
                tx_id: [1u8; 32],
                inputs: &in1,
                outputs: &outs1,
            }],
            100,
        );
        let in2: Vec<[u8; 32]> = vec![[0xA1; 32]];
        let empty: Vec<BlockOutput<'_>> = vec![];
        let txs2 = vec![BlockTx {
            tx_id: [2u8; 32],
            inputs: &in2,
            outputs: &empty,
        }];
        apply(&db, &[], &txs2, 101);
        assert!(matches!(
            tracked(&db, 11, 0xA1).unwrap().status,
            ScanBoxStatus::Spent { .. }
        ));

        // Roll back block 101: A goes back to Unspent (it was created in 100).
        rollback(&db, &txs2, 101);
        assert!(
            matches!(
                tracked(&db, 11, 0xA1).unwrap().status,
                ScanBoxStatus::Unspent
            ),
            "input un-spent on rollback; box still tracked"
        );
    }

    // ----- rollback_block_from_wallet: WALLET_SCAN_HEIGHT regression -----

    struct NoopGuard;
    impl RescanGuard for NoopGuard {
        fn abort_in_progress(&self, _txn: &WriteTransaction) -> Result<(), redb::Error> {
            Ok(())
        }
        fn force_invalidate(&self, _txn: &WriteTransaction) -> Result<(), redb::Error> {
            Ok(())
        }
    }

    fn read_scan_height(db: &redb::Database) -> Option<u32> {
        let r = db.begin_read().unwrap();
        match r.open_table(WALLET_SCAN_HEIGHT) {
            Ok(t) => t.get(()).unwrap().map(|g| g.value()),
            Err(_) => None,
        }
    }

    fn set_scan_height(db: &redb::Database, h: u32) {
        let w = db.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_SCAN_HEIGHT).unwrap();
            t.insert((), h).unwrap();
        }
        w.commit().unwrap();
    }

    fn rollback_wallet(db: &redb::Database, h: u32) {
        let w = db.begin_write().unwrap();
        let txs: Vec<BlockTx<'_>> = vec![];
        rollback_block_from_wallet(&w, h, &txs, &NoopGuard).unwrap();
        w.commit().unwrap();
    }

    #[test]
    fn rollback_does_not_create_scan_height_for_keyless_wallet() {
        // A keyless / scan-only wallet never advanced WALLET_SCAN_HEIGHT at
        // apply (the has_wallet_tracking gate). A reorg must not conjure a row,
        // which would make /wallet/status + /wallet/balances report a bogus
        // walletHeight for a wallet that never scanned anything.
        let (_d, db) = temp_db();
        rollback_wallet(&db, 100);
        assert_eq!(read_scan_height(&db), None, "no scan-height row created");
    }

    #[test]
    fn rollback_lowers_existing_scan_height_to_h_minus_1() {
        // A keyed wallet scanned to 100; rolling back block 100 regresses it.
        let (_d, db) = temp_db();
        set_scan_height(&db, 100);
        rollback_wallet(&db, 100);
        assert_eq!(read_scan_height(&db), Some(99));
    }

    #[test]
    fn rollback_never_raises_scan_height() {
        // Wallet frozen behind the tip (e.g. mid-rescan) at 50; rolling back a
        // higher block must not raise its scan height to 99.
        let (_d, db) = temp_db();
        set_scan_height(&db, 50);
        rollback_wallet(&db, 100);
        assert_eq!(read_scan_height(&db), Some(50), "rollback never raises");
    }

    // ----- WALLET_SCAN_TXS (per-tx scan tagging, Scala WalletScanLogic) -----

    #[test]
    fn apply_records_scan_tx_with_union_of_created_and_spent_scans() {
        let (_d, db) = temp_db();
        let tree = Vec::new();

        // Block 100: tx1 creates A (scans 11+12); tx2 has no scan involvement.
        let outs_a = vec![out(0xA1, &tree)];
        let outs_n = vec![out(0xD0, &tree)];
        let no_in: Vec<[u8; 32]> = vec![];
        apply(
            &db,
            &[match_rec(0xA1, vec![11, 12], 100)],
            &[
                BlockTx {
                    tx_id: [1u8; 32],
                    inputs: &no_in,
                    outputs: &outs_a,
                },
                BlockTx {
                    tx_id: [2u8; 32],
                    inputs: &no_in,
                    outputs: &outs_n,
                },
            ],
            100,
        );
        let rows = scan_txs(&db);
        assert_eq!(rows.len(), 1, "only the scan-involved tx gets a row");
        assert_eq!(rows[0].tx_id, [1u8; 32]);
        assert_eq!(rows[0].block_height, 100);
        assert_eq!(rows[0].block_id, TEST_BLOCK_ID);
        assert_eq!(rows[0].scan_ids, vec![11, 12]);
        assert_eq!(rows[0].created, vec![[0xA1; 32]]);
        assert!(rows[0].spent.is_empty());

        // Block 101: tx3 spends A AND creates C (scan 13) — the row carries
        // the UNION over spent + created (Scala WalletScanLogic:157).
        let outs_c = vec![out(0xC1, &tree)];
        let in_a: Vec<[u8; 32]> = vec![[0xA1; 32]];
        apply(
            &db,
            &[match_rec(0xC1, vec![13], 101)],
            &[BlockTx {
                tx_id: [3u8; 32],
                inputs: &in_a,
                outputs: &outs_c,
            }],
            101,
        );
        let rows = scan_txs(&db);
        assert_eq!(rows.len(), 2);
        let tx3 = &rows[1]; // (height, tx_id) order: block 101 row is second
        assert_eq!(tx3.tx_id, [3u8; 32]);
        assert_eq!(tx3.scan_ids, vec![11, 12, 13], "union, ascending, deduped");
        assert_eq!(tx3.created, vec![[0xC1; 32]]);
        assert_eq!(tx3.spent, vec![[0xA1; 32]]);
    }

    #[test]
    fn same_block_create_then_spend_tags_both_txs() {
        let (_d, db) = temp_db();
        let tree = Vec::new();
        let outs_a = vec![out(0xA1, &tree)];
        let no_in: Vec<[u8; 32]> = vec![];
        let in_a: Vec<[u8; 32]> = vec![[0xA1; 32]];
        let no_out: Vec<BlockOutput<'_>> = vec![];
        apply(
            &db,
            &[match_rec(0xA1, vec![11], 100)],
            &[
                BlockTx {
                    tx_id: [1u8; 32],
                    inputs: &no_in,
                    outputs: &outs_a,
                },
                BlockTx {
                    tx_id: [2u8; 32],
                    inputs: &in_a,
                    outputs: &no_out,
                },
            ],
            100,
        );
        let rows = scan_txs(&db);
        assert_eq!(rows.len(), 2, "creator and same-block spender both tagged");
        assert_eq!(rows[0].created, vec![[0xA1; 32]]);
        assert_eq!(rows[1].spent, vec![[0xA1; 32]]);
        assert_eq!(rows[1].scan_ids, vec![11]);
    }

    #[test]
    fn rollback_removes_scan_tx_rows_at_that_height_only() {
        let (_d, db) = temp_db();
        let tree = Vec::new();
        let outs_a = vec![out(0xA1, &tree)];
        let outs_b = vec![out(0xB1, &tree)];
        let no_in: Vec<[u8; 32]> = vec![];
        apply(
            &db,
            &[match_rec(0xA1, vec![11], 100)],
            &[BlockTx {
                tx_id: [1u8; 32],
                inputs: &no_in,
                outputs: &outs_a,
            }],
            100,
        );
        apply(
            &db,
            &[match_rec(0xB1, vec![11], 101)],
            &[BlockTx {
                tx_id: [2u8; 32],
                inputs: &no_in,
                outputs: &outs_b,
            }],
            101,
        );
        assert_eq!(scan_txs(&db).len(), 2);

        rollback(
            &db,
            &[BlockTx {
                tx_id: [2u8; 32],
                inputs: &no_in,
                outputs: &outs_b,
            }],
            101,
        );
        let rows = scan_txs(&db);
        assert_eq!(rows.len(), 1, "only the rolled-back height's row removed");
        assert_eq!(rows[0].block_height, 100);
    }

    #[test]
    fn clear_scan_tracking_drops_scan_tx_rows() {
        let (_d, db) = temp_db();
        let tree = Vec::new();
        let outs = vec![out(0xA1, &tree)];
        let no_in: Vec<[u8; 32]> = vec![];
        apply(
            &db,
            &[match_rec(0xA1, vec![11], 100)],
            &[BlockTx {
                tx_id: [1u8; 32],
                inputs: &no_in,
                outputs: &outs,
            }],
            100,
        );
        assert_eq!(scan_txs(&db).len(), 1);

        let w = db.begin_write().unwrap();
        clear_scan_tracking(&w).unwrap();
        w.commit().unwrap();
        assert!(scan_txs(&db).is_empty(), "scan-tx rows cleared");
    }
}

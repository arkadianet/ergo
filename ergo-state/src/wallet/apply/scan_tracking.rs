//! `/scan/*` block-apply tracking: persists pre-computed scan-match
//! records and spend transitions atomically in the chain write-txn,
//! independent of the pubkey-wallet hook in `mod.rs`.
//!
//! Sibling of `mod.rs`; pure impl relocation.

use crate::store::ScanMatchRecord;
use crate::wallet::tables::*;
use crate::wallet::types::{ScanBoxStatus, ScanTrackedBox, ScanTxRecord};
use redb::{ReadableTable, WriteTransaction};

use super::{is_scan_invalidated, BlockTx};

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

/// Live chain-apply variant: skips ALL scan-table writes while
/// `WALLET_SCAN_INVALIDATED` is set (a scan-registry read failure, or a
/// non-replayable reorg), mirroring [`apply_block_to_wallet`] /
/// [`promote_matured_boxes`]. Otherwise a block whose match pass failed (empty
/// matches) would still mutate the scan tables, and tracking would keep
/// advancing while `/wallet/status` reports `scan_invalidated`. A
/// `/wallet/rescan` (which calls [`apply_block_to_scans_rescan`]) rebuilds them.
pub(crate) fn apply_block_to_scans(
    txn: &WriteTransaction,
    scan_matches: &[ScanMatchRecord],
    txs: &[BlockTx<'_>],
    block_height: u32,
    block_id: &[u8; 32],
) -> Result<(), redb::Error> {
    if is_scan_invalidated(txn)? {
        return Ok(());
    }
    apply_block_to_scans_rescan(txn, scan_matches, txs, block_height, block_id)
}

/// Persist a block's scan matches into the scan-box tables, inside the SAME
/// write txn as chain apply. Two phases (mirroring the wallet hook): phase 1
/// creates each matched output as an `Unspent` [`ScanTrackedBox`] (one row per
/// `(scan, box)`) and unions the scans into the box→scans reverse index; phase
/// 2 marks any input that spends a scan-tracked box as `Spent`.
///
/// A box created AND spent within the same block is handled, because phase 1
/// runs before phase 2.
///
/// Privileged: bypasses the `WALLET_SCAN_INVALIDATED` check (the rescan IS the
/// recovery path), so the rescan rebuild calls this directly.
pub(crate) fn apply_block_to_scans_rescan(
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

//! Wallet/scan bridge: build owned per-block tx data for the wallet
//! apply hook from `CheckedTransaction`s (live apply) or by re-reading
//! `BLOCK_SECTIONS` (rollback / rescan replay), plus the borrow
//! adapter (`BoundBlockTxs`) that converts owned data into the
//! `BlockTx<'_>` view the wallet-hook functions take.
//!
//! Sibling of `mod.rs`; pure impl relocation.

use super::{
    OwnedBlockOutput, OwnedBlockTxData, ScanMatchRecord, StateError, BLOCK_SECTIONS, CHAIN_INDEX,
    HEADERS,
};
use crate::wallet::scan::RescanReadError;
use crate::wallet::WalletStoreError;

pub(crate) enum WalletBlockSections {
    MissingHeader,
    MissingBlockTransactions,
    Found(Vec<OwnedBlockTxData>),
}

// ---- wallet integration helpers ----

/// Build the wallet-apply input from a slice of `CheckedTransaction`.
/// Computes box_ids from the `ErgoBox` serialization formula.
pub(crate) fn build_wallet_block_txs_checked(
    txs: &[ergo_validation::CheckedTransaction],
    block_height: u32,
) -> Result<Vec<OwnedBlockTxData>, StateError> {
    txs.iter()
        .map(|ct| build_owned_tx_data_checked(ct, block_height))
        .collect()
}

/// Guard the `match_boxes` hook contract: it must return exactly one result
/// per box. A mismatch would make `build_scan_match_records`' `zip` silently
/// drop trailing boxes' scan matches, so treat it as an internal invariant
/// violation rather than a recoverable condition.
fn check_match_count(boxes_len: usize, matches_len: usize, height: u32) -> Result<(), StateError> {
    if matches_len != boxes_len {
        return Err(StateError::InternalInvariantAt {
            what: "match_boxes returned wrong result count",
            height,
        });
    }
    Ok(())
}

/// Build the scan-match records for a block: one per output box whose
/// `ErgoBox` matched ≥1 registered scan (via `hook.match_boxes`). Only called
/// when the hook reports registered scans, so the per-box matcher cost is
/// never paid on a node with no scans. The full serialized box is captured so
/// a later-spent box can still be rendered.
pub(crate) fn build_scan_match_records(
    txs: &[ergo_validation::CheckedTransaction],
    block_height: u32,
    hook: &dyn crate::wallet::WalletApplyHook,
) -> Result<Vec<ScanMatchRecord>, StateError> {
    // Collect every output box of the whole block, then match them all in one
    // hook call so ergo-node loads the scan registry once per block.
    let mut boxes: Vec<ergo_ser::ergo_box::ErgoBox> = Vec::new();
    for ct in txs {
        let modifier_tx_id = ergo_primitives::digest::ModifierId::from_bytes(*ct.tx_id());
        for (idx, candidate) in ct.transaction().output_candidates.iter().enumerate() {
            boxes.push(ergo_ser::ergo_box::ErgoBox {
                candidate: candidate.clone(),
                transaction_id: modifier_tx_id,
                index: idx as u16,
            });
        }
    }

    let matches = hook.match_boxes(&boxes);
    // The hook must return exactly one result per box, in order; the `zip`
    // below would silently truncate (dropping trailing boxes' matches)
    // otherwise. Our only hook satisfies this by construction, so a mismatch
    // is an internal contract violation — surface it, don't swallow it.
    check_match_count(boxes.len(), matches.len(), block_height)?;

    let mut records = Vec::new();
    for (ergo_box, scan_ids) in boxes.iter().zip(matches) {
        if scan_ids.is_empty() {
            continue;
        }
        let box_id = ergo_box
            .box_id()
            .map_err(|e| StateError::Serialization(format!("scan box_id: {e}")))?;
        let box_bytes = ergo_ser::ergo_box::serialize_ergo_box(ergo_box)
            .map_err(|e| StateError::Serialization(format!("scan box serialize: {e}")))?;
        records.push(ScanMatchRecord {
            box_id: *box_id.as_bytes(),
            scan_ids,
            box_bytes,
            inclusion_height: block_height,
            creation_out_index: ergo_box.index,
        });
    }
    Ok(records)
}

fn build_owned_tx_data_checked(
    ct: &ergo_validation::CheckedTransaction,
    block_height: u32,
) -> Result<OwnedBlockTxData, StateError> {
    let tx = ct.transaction();
    let tx_id = *ct.tx_id();
    let modifier_tx_id = ergo_primitives::digest::ModifierId::from_bytes(tx_id);

    let inputs: Vec<[u8; 32]> = tx.inputs.iter().map(|i| *i.box_id.as_bytes()).collect();

    let outputs = tx
        .output_candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            // Ergo box_id = blake2b256(candidate_bytes || tx_id || index_u16_le)
            // We construct an ErgoBox and hash it.
            let ergo_box = ergo_ser::ergo_box::ErgoBox {
                candidate: candidate.clone(),
                transaction_id: modifier_tx_id,
                index: idx as u16,
            };
            // Serialize once and reuse for BOTH the box id (blake2b256 of the
            // canonical box bytes) AND `box_bytes` below — `box_id()` already
            // serialized internally, so capturing the bytes for the
            // reserved-scan reads (WALLET_BOX_BYTES) costs no extra encode.
            let box_bytes = ergo_ser::ergo_box::serialize_ergo_box(&ergo_box)
                .map_err(|e| StateError::Serialization(format!("box serialize: {e}")))?;
            let box_id = ergo_primitives::digest::blake2b256(&box_bytes);
            let ergo_tree_bytes = candidate.ergo_tree_bytes().to_vec();
            let value = candidate.value;
            let assets: Vec<([u8; 32], u64)> = candidate
                .tokens
                .iter()
                .map(|t| (*t.token_id.as_bytes(), t.amount))
                .collect();
            let miner_reward_pubkey =
                ergo_wallet::proving::miner_reward::extract_miner_reward_pubkey(&ergo_tree_bytes);
            Ok(OwnedBlockOutput {
                box_id: *box_id.as_bytes(),
                output_index: idx as u16,
                ergo_tree_bytes,
                value,
                assets,
                miner_reward_pubkey,
                // Captured for free from the box-id serialization above; the
                // apply hook stores it in WALLET_BOX_BYTES for matched wallet
                // boxes (reserved-scan reads). The live scan-match path
                // (`build_scan_match_records`) is separate and re-serializes
                // its own boxes — it does not read this field.
                box_bytes,
            })
        })
        .collect::<Result<Vec<_>, StateError>>()?;

    // Suppress unused variable warning — block_height is intentionally
    // available for future use (e.g. creation_height cross-check).
    let _ = block_height;

    Ok(OwnedBlockTxData {
        tx_id,
        inputs,
        outputs,
    })
}

/// Build wallet-apply input by re-reading raw txs from BLOCK_SECTIONS.
/// Used by the rollback path which has only header_id, not CheckedTransactions.
pub(crate) fn build_wallet_block_txs_from_sections(
    db: &redb::Database,
    header_id: &[u8; 32],
) -> Result<Option<Vec<OwnedBlockTxData>>, StateError> {
    let read_txn = db.begin_read()?;
    build_wallet_block_txs_from_read_txn(&read_txn, header_id)
}

/// Section-read core of [`build_wallet_block_txs_from_sections`], taking an
/// existing read transaction so the caller can keep the height→header_id lookup
/// and these section reads on ONE snapshot (a reorg/rewrite between two separate
/// transactions could otherwise pair a height with a different block's txs).
pub(crate) fn build_wallet_block_txs_from_read_txn(
    read_txn: &redb::ReadTransaction,
    header_id: &[u8; 32],
) -> Result<Option<Vec<OwnedBlockTxData>>, StateError> {
    Ok(
        match build_wallet_block_txs_from_read_txn_classified(read_txn, header_id)? {
            WalletBlockSections::MissingHeader | WalletBlockSections::MissingBlockTransactions => {
                None
            }
            WalletBlockSections::Found(txs) => Some(txs),
        },
    )
}

pub(crate) fn build_wallet_block_txs_from_read_txn_classified(
    read_txn: &redb::ReadTransaction,
    header_id: &[u8; 32],
) -> Result<WalletBlockSections, StateError> {
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::block_transactions::read_stored_block_transactions;
    use ergo_ser::header::read_header;
    use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
    use ergo_ser::transaction::transaction_id;

    // Read header bytes to get transactions_root.
    let header_bytes = match read_txn.open_table(HEADERS) {
        Ok(t) => match t.get(header_id.as_slice())? {
            Some(g) => g.value().to_vec(),
            None => return Ok(WalletBlockSections::MissingHeader),
        },
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Ok(WalletBlockSections::MissingHeader);
        }
        Err(e) => return Err(e.into()),
    };
    let mut r = VlqReader::new(&header_bytes);
    let header = read_header(&mut r).map_err(|e| {
        StateError::Serialization(format!("header parse in wallet rollback: {e:?}"))
    })?;

    // Compute the block-transactions modifier_id from the header.
    let bt_id = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        header_id,
        header.transactions_root.as_bytes(),
    );

    // Read the block-transactions section bytes.
    let bt_bytes = match read_txn.open_table(BLOCK_SECTIONS) {
        Ok(t) => match t.get(bt_id.as_slice())? {
            Some(g) => g.value().to_vec(),
            None => return Ok(WalletBlockSections::MissingBlockTransactions),
        },
        Err(redb::TableError::TableDoesNotExist(_)) => {
            return Ok(WalletBlockSections::MissingBlockTransactions);
        }
        Err(e) => return Err(e.into()),
    };

    // Parse the block transactions. Trusted: these are the node's own applied
    // and persisted bytes, so the box-script acceptance gates must not re-run.
    let bt = read_stored_block_transactions(&bt_bytes).map_err(|e| {
        StateError::Serialization(format!("block_txs parse in wallet rollback: {e:?}"))
    })?;

    let owned: Vec<OwnedBlockTxData> = bt
        .transactions
        .iter()
        .map(|tx| {
            let tx_id_modifier = transaction_id(tx).map_err(|e| {
                StateError::Serialization(format!("transaction_id in rollback: {e:?}"))
            })?;
            let tx_id = *tx_id_modifier.as_bytes();

            let inputs: Vec<[u8; 32]> = tx.inputs.iter().map(|i| *i.box_id.as_bytes()).collect();

            let outputs = tx
                .output_candidates
                .iter()
                .enumerate()
                .map(|(idx, candidate)| {
                    let ergo_box = ergo_ser::ergo_box::ErgoBox {
                        candidate: candidate.clone(),
                        transaction_id: tx_id_modifier,
                        index: idx as u16,
                    };
                    let box_id = ergo_box.box_id().map_err(|e| {
                        StateError::Serialization(format!("box_id in rollback: {e}"))
                    })?;
                    let ergo_tree_bytes = candidate.ergo_tree_bytes().to_vec();
                    let value = candidate.value;
                    let assets: Vec<([u8; 32], u64)> = candidate
                        .tokens
                        .iter()
                        .map(|t| (*t.token_id.as_bytes(), t.amount))
                        .collect();
                    let miner_reward_pubkey =
                        ergo_wallet::proving::miner_reward::extract_miner_reward_pubkey(
                            &ergo_tree_bytes,
                        );
                    // Replay/rescan path: carry the full box so the rescan
                    // scan-matcher can re-derive scan membership and so
                    // `ScanTrackedBox.box_bytes` can be reconstructed. The
                    // box is already built (for box_id) — serializing it is
                    // near-free.
                    let box_bytes =
                        ergo_ser::ergo_box::serialize_ergo_box(&ergo_box).map_err(|e| {
                            StateError::Serialization(format!("box serialize in replay: {e}"))
                        })?;
                    Ok(OwnedBlockOutput {
                        box_id: *box_id.as_bytes(),
                        output_index: idx as u16,
                        ergo_tree_bytes,
                        value,
                        assets,
                        miner_reward_pubkey,
                        box_bytes,
                    })
                })
                .collect::<Result<Vec<_>, StateError>>()?;

            Ok(OwnedBlockTxData {
                tx_id,
                inputs,
                outputs,
            })
        })
        .collect::<Result<Vec<_>, StateError>>()?;

    Ok(WalletBlockSections::Found(owned))
}

fn rescan_error(height: u32, source: StateError) -> RescanReadError {
    if matches!(
        &source,
        StateError::Serialization(_) | StateError::DbCorruption { .. }
    ) {
        RescanReadError::Corrupt {
            height,
            reason: source.to_string(),
        }
    } else {
        RescanReadError::Storage {
            height,
            source: WalletStoreError::decode(source.to_string()),
        }
    }
}

/// Read block transactions for the wallet rescan path. Returns `None` when
/// the height has no applied-chain entry (above tip or pruned).
///
/// Reads `CHAIN_INDEX` (full-block applied chain, distinct from
/// `HEADER_CHAIN_INDEX`). Returns `None` when no entry exists for the
/// height, which indicates either: the node hasn't applied a full block
/// at this height yet, or the undo log was pruned below this height.
#[allow(clippy::type_complexity)] // (block_id, txs) pair; a named struct would add indirection
pub fn block_txs_for_wallet_at_height(
    db: &redb::Database,
    height: u32,
) -> Result<Option<([u8; 32], Vec<OwnedBlockTxData>)>, RescanReadError> {
    let read_txn = db
        .begin_read()
        .map_err(|e| rescan_error(height, e.into()))?;
    block_txs_for_wallet_at_height_in_read_txn(&read_txn, height)
}

#[allow(clippy::type_complexity)]
pub(crate) fn block_txs_for_wallet_at_height_in_read_txn(
    read_txn: &redb::ReadTransaction,
    height: u32,
) -> Result<Option<([u8; 32], Vec<OwnedBlockTxData>)>, RescanReadError> {
    // Read from CHAIN_INDEX (full-block applied chain).
    let chain_table = match read_txn.open_table(CHAIN_INDEX) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(rescan_error(height, e.into())),
    };
    let header_id: [u8; 32] = match chain_table.get(height as u64) {
        Ok(Some(g)) => {
            let bytes = g.value();
            if bytes.len() != 32 {
                return Err(RescanReadError::Corrupt {
                    height,
                    reason: format!("chain_index row has len {} (expected 32)", bytes.len()),
                });
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(bytes);
            id
        }
        Ok(None) => return Ok(None),
        Err(e) => return Err(rescan_error(height, e.into())),
    };

    // Reuse the SAME read transaction for the section reads so the height's
    // header_id and the block txs are read from one consistent snapshot — a
    // reorg between two separate transactions could pair the height with a
    // different block's transactions.
    match build_wallet_block_txs_from_read_txn_classified(read_txn, &header_id) {
        Ok(WalletBlockSections::Found(txs)) => Ok(Some((header_id, txs))),
        Ok(WalletBlockSections::MissingBlockTransactions) => Ok(None),
        Ok(WalletBlockSections::MissingHeader) => Err(RescanReadError::Corrupt {
            height,
            reason: "applied-chain header missing during rescan".to_string(),
        }),
        Err(e) => Err(rescan_error(height, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- check_match_count (scan-hook contract guard) -----

    #[test]
    fn check_match_count_ok_when_lengths_match() {
        assert!(check_match_count(3, 3, 100).is_ok());
        assert!(check_match_count(0, 0, 100).is_ok());
    }

    #[test]
    fn check_match_count_errors_when_hook_returns_wrong_count() {
        // A hook returning fewer results than boxes would make the downstream
        // `zip` silently drop trailing boxes' matches. Fail loud instead.
        let err = check_match_count(3, 2, 777).unwrap_err();
        assert!(matches!(
            err,
            StateError::InternalInvariantAt {
                height: 777,
                what: _
            }
        ));
        assert!(check_match_count(2, 3, 100).is_err());
    }
}

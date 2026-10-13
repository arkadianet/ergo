//! Wallet block reads: re-read a committed block's transactions from
//! `BLOCK_SECTIONS` as owned per-block tx data, for the chain API that
//! external wallets sync from and for offline UTXO discovery.
//!
//! Sibling of `mod.rs`.

use super::{OwnedBlockOutput, OwnedBlockTxData, StateError, BLOCK_SECTIONS, CHAIN_INDEX, HEADERS};
use crate::wallet::scan::RescanReadError;
use crate::wallet::WalletStoreError;
use redb::ReadableDatabase;

pub(crate) enum WalletBlockSections {
    MissingHeader,
    MissingBlockTransactions,
    Found(Vec<OwnedBlockTxData>),
}

/// Read one block's transactions back from `BLOCK_SECTIONS`, taking an
/// existing read transaction so the caller can keep the height→header_id lookup
/// and these section reads on ONE snapshot (a reorg/rewrite between two separate
/// transactions could otherwise pair a height with a different block's txs).
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
    // Keep typed redb failures typed, so the wallet can tell a storage fault
    // from bad data; anything else is reported as a decode problem.
    let storage = match source {
        StateError::Serialization(_) | StateError::DbCorruption { .. } => {
            return RescanReadError::Corrupt {
                height,
                reason: source.to_string(),
            };
        }
        StateError::Db(error) => WalletStoreError::from(*error),
        StateError::DatabaseError(error) => WalletStoreError::from(redb::Error::from(*error)),
        StateError::StorageError(error) => WalletStoreError::from(redb::Error::from(*error)),
        StateError::TransactionError(error) => WalletStoreError::from(redb::Error::from(*error)),
        StateError::TableError(error) => WalletStoreError::from(redb::Error::from(*error)),
        StateError::CommitError(error) => WalletStoreError::from(redb::Error::from(*error)),
        other => WalletStoreError::decode(other.to_string()),
    };
    RescanReadError::Storage {
        height,
        source: storage,
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

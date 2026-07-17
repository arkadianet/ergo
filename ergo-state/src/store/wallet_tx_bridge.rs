//! Wallet/scan bridge: build owned per-block tx data for the wallet
//! apply hook from `CheckedTransaction`s (live apply) or by re-reading
//! `BLOCK_SECTIONS` (rollback / rescan replay), plus the borrow
//! adapter (`BoundBlockTxs`) that converts owned data into the
//! `BlockTx<'_>` view the wallet-hook functions take.
//!
//! Sibling of `mod.rs`; pure impl relocation.

use super::{ScanMatchRecord, StateError, BLOCK_SECTIONS, CHAIN_INDEX, HEADERS};

// ---- wallet integration helpers ----

/// Owned per-output data for the wallet hook (avoids lifetime complexity).
#[derive(Clone)]
pub struct OwnedBlockOutput {
    pub box_id: [u8; 32],
    pub output_index: u16,
    pub ergo_tree_bytes: Vec<u8>,
    pub value: u64,
    pub assets: Vec<([u8; 32], u64)>,
    pub miner_reward_pubkey: Option<[u8; 33]>,
    /// Full serialized `ErgoBox` bytes. Populated by BOTH builders:
    /// - the section/replay builder ([`build_wallet_block_txs_from_sections`])
    ///   feeds the rescan read path's registered-scan matching +
    ///   `ScanTrackedBox.box_bytes`;
    /// - the live-apply builder ([`build_owned_tx_data_checked`]) captures it
    ///   for free by reusing the box-id serialization (the id IS
    ///   `blake2b256` of these bytes), so the apply hook can store it in
    ///   `WALLET_BOX_BYTES` for the reserved-scan reads
    ///   (`/scan/{unspent,spent}Boxes/9|10`).
    ///
    /// May still be empty for callers that have no bytes to carry; the apply
    /// hook then skips the `WALLET_BOX_BYTES` row and the read degrades to
    /// empty `bytes` until a `/wallet/rescan` backfills it.
    pub box_bytes: Vec<u8>,
}

/// Owned per-tx data for the wallet hook.
#[derive(Clone)]
pub struct OwnedBlockTxData {
    pub tx_id: [u8; 32],
    pub inputs: Vec<[u8; 32]>,
    pub outputs: Vec<OwnedBlockOutput>,
}

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
                crate::wallet::miner_reward::extract_miner_reward_pubkey(&ergo_tree_bytes);
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
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::block_transactions::read_block_transactions;
    use ergo_ser::header::read_header;
    use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
    use ergo_ser::transaction::transaction_id;

    let read_txn = db.begin_read()?;

    // Read header bytes to get transactions_root.
    let header_bytes = match read_txn.open_table(HEADERS) {
        Ok(t) => match t.get(header_id.as_slice())? {
            Some(g) => g.value().to_vec(),
            None => return Ok(None),
        },
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
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
            None => return Ok(None), // section pruned / not yet stored
        },
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    // Parse the block transactions.
    let mut r = VlqReader::new(&bt_bytes);
    let bt = read_block_transactions(&mut r).map_err(|e| {
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
                        crate::wallet::miner_reward::extract_miner_reward_pubkey(&ergo_tree_bytes);
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

    Ok(Some(owned))
}

/// Intermediate binding that keeps per-tx `BlockOutput` vecs alive long
/// enough for `BlockTx<'_>` slices to borrow from them.
///
/// `BlockTx.outputs` is `&'a [BlockOutput<'a>]` — a reference into stable
/// memory — so the intermediate `Vec<BlockOutput>` must outlive the
/// `BlockTx` slice. `BoundBlockTxs` owns both allocations and exposes an
/// `as_block_txs()` method that creates the borrows.
pub struct BoundBlockTxs<'a> {
    // One Vec<BlockOutput<'a>> per tx, in block order.
    outputs: Vec<Vec<crate::wallet::apply::BlockOutput<'a>>>,
    // Parallel tx metadata (tx_id, inputs slice).
    meta: Vec<([u8; 32], &'a [[u8; 32]])>,
}

impl<'a> BoundBlockTxs<'a> {
    pub fn as_block_txs(&self) -> Vec<crate::wallet::apply::BlockTx<'_>> {
        self.meta
            .iter()
            .zip(self.outputs.iter())
            .map(|((tx_id, inputs), outs)| crate::wallet::apply::BlockTx {
                tx_id: *tx_id,
                inputs,
                outputs: outs.as_slice(),
            })
            .collect()
    }
}

/// Convert owned block-tx data into `BoundBlockTxs<'_>` which borrows from
/// `owned`. Call `.as_block_txs()` to get the `&[BlockTx<'_>]` view needed
/// by the wallet-hook functions.
///
/// Two-step construction avoids the lifetime pitfall of creating a
/// `Vec<BlockOutput>` inside a closure that also produces a `BlockTx`
/// holding a reference into that same Vec.
pub fn owned_to_block_txs(owned: &[OwnedBlockTxData]) -> BoundBlockTxs<'_> {
    let outputs: Vec<Vec<crate::wallet::apply::BlockOutput<'_>>> = owned
        .iter()
        .map(|d| {
            d.outputs
                .iter()
                .map(|o| crate::wallet::apply::BlockOutput {
                    box_id: o.box_id,
                    output_index: o.output_index,
                    ergo_tree_bytes: &o.ergo_tree_bytes,
                    value: o.value,
                    assets: o.assets.clone(),
                    miner_reward_pubkey: o.miner_reward_pubkey,
                    box_bytes: &o.box_bytes,
                })
                .collect()
        })
        .collect();
    let meta: Vec<([u8; 32], &[[u8; 32]])> = owned
        .iter()
        .map(|d| (d.tx_id, d.inputs.as_slice()))
        .collect();
    BoundBlockTxs { outputs, meta }
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
) -> Result<Option<([u8; 32], Vec<OwnedBlockTxData>)>, StateError> {
    let read_txn = db.begin_read()?;

    // Read from CHAIN_INDEX (full-block applied chain).
    let header_id: [u8; 32] = match read_txn.open_table(CHAIN_INDEX) {
        Ok(t) => match t.get(height as u64)? {
            Some(g) => {
                let bytes = g.value();
                if bytes.len() != 32 {
                    return Err(StateError::DbCorruption {
                        table: "chain_index",
                        key: hex::encode((height as u64).to_be_bytes()),
                        reason: format!("row has len {} (expected 32)", bytes.len()),
                    });
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(bytes);
                id
            }
            None => return Ok(None),
        },
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    drop(read_txn);

    match build_wallet_block_txs_from_sections(db, &header_id)? {
        Some(txs) => Ok(Some((header_id, txs))),
        None => Ok(None),
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

//! Chain-tip diff API for consumers that need to track "what changed
//! since I last looked" without replaying the whole chain.
//!
//! Used by the mempool to reconcile pool state across linear
//! block applications, rollbacks, and reorgs. The types here are
//! state-crate-side — header ids are `[u8; 32]` to match the store's
//! existing conventions. Higher crates that prefer their own ID wrappers
//! translate at the boundary.

use std::collections::HashSet;

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_ser::transaction::{bytes_to_sign, write_transaction};
use thiserror::Error;

use crate::store::{StateStore, ROLLBACK_WINDOW};

/// Identifier of a committed-chain tip. Retained by callers between
/// polls so [`StateStore::tx_diff_since`] can compute the delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TipPointer {
    /// Height of the tip block.
    pub height: u32,
    /// Identifier of the tip header.
    pub header_id: [u8; 32],
}

/// A tx that entered the committed chain since the caller's previous
/// tip. Spent inputs are carried explicitly so a consumer can evict
/// pool txs whose inputs were consumed even when the consumer never
/// saw the block's tx itself.
#[derive(Debug, Clone)]
pub struct AppliedTx {
    /// Transaction id (`Blake2b256(bytes_to_sign(tx))`).
    pub tx_id: [u8; 32],
    /// Box ids consumed by this transaction.
    pub spent_inputs: Vec<[u8; 32]>,
}

/// A tx that was in a block now rolled back. Raw canonical bytes are
/// preserved so relay + revalidation can reuse them without
/// re-serializing.
#[derive(Debug, Clone)]
pub struct DemotedTx {
    /// Transaction id of the demoted tx.
    pub tx_id: [u8; 32],
    /// Canonical wire bytes for relay / revalidation.
    pub bytes: Vec<u8>,
}

/// Result of [`StateStore::tx_diff_since`]. Chain-forward ordering is
/// guaranteed for both `applied` and `demoted` — LCA+1 first, then
/// intra-block tx order — so consumers that feed the demoted stream
/// back through revalidation process parents before children.
#[derive(Debug, Clone)]
pub struct TxDiff {
    /// The committed tip the diff is anchored to.
    pub new_tip: TipPointer,
    /// Transactions applied since the caller's previous tip, in
    /// chain-forward order.
    pub applied: Vec<AppliedTx>,
    /// Transactions rolled back since the caller's previous tip,
    /// LCA-first.
    pub demoted: Vec<DemotedTx>,
    /// Union of `applied[*].spent_inputs`. Materialized once here so
    /// callers doing conflict checks don't iterate the nested shape.
    pub applied_spent_inputs: HashSet<[u8; 32]>,
}

/// Failure modes for diff computation. Both error variants force the
/// caller to reseed from empty — partial diffs are never produced.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TxDiffError {
    /// `since` pointer is not in `header_meta` — the store has moved on
    /// beyond any chain we can reach by walking parent pointers.
    #[error("since pointer not reachable: header not in header_meta")]
    TooFarBehind,
    /// A block section required to reconstruct the diff has been pruned.
    /// Conservatively treated as `TooFarBehind` by consumers.
    #[error(
        "missing block sections at height {height}, header {}",
        hex::encode(header_id)
    )]
    MissingSections { height: u32, header_id: [u8; 32] },
    /// LCA walk exceeded the rollback window (200) — a reorg deeper
    /// than we retain undo data for.
    #[error("reorg deeper than rollback window")]
    ReorgTooDeep,
}

impl StateStore {
    /// Committed-tip identity. Reads `chain_state` atomically (the
    /// in-memory copy is updated in lockstep with `chain_state_meta`
    /// persistence, so this is consistent with the AVL tree root).
    pub fn committed_tip(&self) -> TipPointer {
        let cs = self.chain_state();
        TipPointer {
            height: cs.best_full_block_height,
            header_id: cs.best_full_block_id,
        }
    }

    /// Compute the tx-level diff between `since` and the committed tip.
    ///
    /// Walks parent pointers from both
    /// sides to the LCA so reorgs are handled without relying on
    /// `chain_index` (which only reflects the current best chain).
    /// Missing-header or missing-section errors produce a clean error
    /// value; partial diffs are never returned.
    pub fn tx_diff_since(&self, since: TipPointer) -> Result<TxDiff, TxDiffError> {
        let tip = self.committed_tip();

        // Short-circuit: same tip ⇒ empty diff.
        if since.header_id == tip.header_id {
            return Ok(TxDiff {
                new_tip: tip,
                applied: Vec::new(),
                demoted: Vec::new(),
                applied_spent_inputs: HashSet::new(),
            });
        }

        // Verify `since` exists in header_meta.
        let since_meta = self
            .get_header_meta(&since.header_id)
            .map_err(|_| TxDiffError::TooFarBehind)?
            .ok_or(TxDiffError::TooFarBehind)?;
        if since_meta.height != since.height {
            return Err(TxDiffError::TooFarBehind);
        }

        // Walk back from the taller side until heights equal, then
        // step both in lockstep until header ids match. Bound each
        // side at ROLLBACK_WINDOW to cap the reorg depth.
        let mut a_id = since.header_id;
        let mut a_height = since.height;
        let mut b_id = tip.header_id;
        let mut b_height = tip.height;
        let mut demoted_ids: Vec<(u32, [u8; 32])> = Vec::new();
        let mut applied_ids: Vec<(u32, [u8; 32])> = Vec::new();

        let mut steps = 0u32;
        while a_height > b_height {
            demoted_ids.push((a_height, a_id));
            let meta = self
                .get_header_meta(&a_id)
                .map_err(|_| TxDiffError::TooFarBehind)?
                .ok_or(TxDiffError::TooFarBehind)?;
            a_id = meta.parent_id;
            a_height = a_height.saturating_sub(1);
            steps += 1;
            if steps > ROLLBACK_WINDOW {
                return Err(TxDiffError::ReorgTooDeep);
            }
        }
        while b_height > a_height {
            applied_ids.push((b_height, b_id));
            let meta = self
                .get_header_meta(&b_id)
                .map_err(|_| TxDiffError::TooFarBehind)?
                .ok_or(TxDiffError::TooFarBehind)?;
            b_id = meta.parent_id;
            b_height = b_height.saturating_sub(1);
            steps += 1;
            if steps > ROLLBACK_WINDOW {
                return Err(TxDiffError::ReorgTooDeep);
            }
        }

        while a_id != b_id {
            demoted_ids.push((a_height, a_id));
            applied_ids.push((b_height, b_id));
            let a_meta = self
                .get_header_meta(&a_id)
                .map_err(|_| TxDiffError::TooFarBehind)?
                .ok_or(TxDiffError::TooFarBehind)?;
            let b_meta = self
                .get_header_meta(&b_id)
                .map_err(|_| TxDiffError::TooFarBehind)?
                .ok_or(TxDiffError::TooFarBehind)?;
            a_id = a_meta.parent_id;
            b_id = b_meta.parent_id;
            if a_height == 0 {
                // Walked through genesis on one side; LCA unreachable.
                return Err(TxDiffError::TooFarBehind);
            }
            a_height = a_height.saturating_sub(1);
            b_height = b_height.saturating_sub(1);
            steps += 1;
            if steps > ROLLBACK_WINDOW {
                return Err(TxDiffError::ReorgTooDeep);
            }
        }

        // Both lists are newest-first. Reverse to chain-forward so the
        // applied stream replays in block order (parents before
        // children), and the demoted stream is LCA+1 first so
        // revalidation on the consumer side sees parents first.
        demoted_ids.reverse();
        applied_ids.reverse();

        // Load + parse block txs for each side.
        let demoted = self.load_demoted(&demoted_ids)?;
        let applied = self.load_applied(&applied_ids)?;
        let applied_spent_inputs = applied
            .iter()
            .flat_map(|a| a.spent_inputs.iter().copied())
            .collect();

        Ok(TxDiff {
            new_tip: tip,
            applied,
            demoted,
            applied_spent_inputs,
        })
    }

    fn load_applied(&self, blocks: &[(u32, [u8; 32])]) -> Result<Vec<AppliedTx>, TxDiffError> {
        let mut out = Vec::new();
        for (height, header_id) in blocks {
            let (_, txs) = self.load_block_transactions(*height, header_id)?;
            for tx in txs {
                let message = bytes_to_sign(&tx).map_err(|_| TxDiffError::MissingSections {
                    height: *height,
                    header_id: *header_id,
                })?;
                let tx_id = *blake2b256(&message).as_bytes();
                let spent_inputs: Vec<[u8; 32]> =
                    tx.inputs.iter().map(|i| *i.box_id.as_bytes()).collect();
                out.push(AppliedTx {
                    tx_id,
                    spent_inputs,
                });
            }
        }
        Ok(out)
    }

    fn load_demoted(&self, blocks: &[(u32, [u8; 32])]) -> Result<Vec<DemotedTx>, TxDiffError> {
        let mut out = Vec::new();
        for (height, header_id) in blocks {
            let (_, txs) = self.load_block_transactions(*height, header_id)?;
            for tx in txs {
                let message = bytes_to_sign(&tx).map_err(|_| TxDiffError::MissingSections {
                    height: *height,
                    header_id: *header_id,
                })?;
                let tx_id = *blake2b256(&message).as_bytes();
                // Re-serialize to canonical bytes for relay. Canonical
                // parity is enforced at block acceptance so this must
                // match the original bytes.
                let mut w = VlqWriter::new();
                write_transaction(&mut w, &tx).map_err(|_| TxDiffError::MissingSections {
                    height: *height,
                    header_id: *header_id,
                })?;
                out.push(DemotedTx {
                    tx_id,
                    bytes: w.result(),
                });
            }
        }
        Ok(out)
    }

    /// Load and parse the BlockTransactions section for a given header.
    /// Returns `MissingSections` if the section bytes are absent or
    /// malformed, `TooFarBehind` for any lower-level I/O failure.
    fn load_block_transactions(
        &self,
        height: u32,
        header_id: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<ergo_ser::transaction::Transaction>), TxDiffError> {
        let header_bytes = self
            .get_header(header_id)
            .map_err(|_| TxDiffError::TooFarBehind)?
            .ok_or(TxDiffError::MissingSections {
                height,
                header_id: *header_id,
            })?;
        let header = {
            let mut r = VlqReader::new(&header_bytes);
            read_header(&mut r).map_err(|_| TxDiffError::MissingSections {
                height,
                header_id: *header_id,
            })?
        };
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            header_id,
            header.transactions_root.as_bytes(),
        );
        let section_bytes = self
            .get_block_section(&section_id)
            .map_err(|_| TxDiffError::TooFarBehind)?
            .ok_or(TxDiffError::MissingSections {
                height,
                header_id: *header_id,
            })?;
        let bt = {
            let mut r = VlqReader::new(&section_bytes);
            read_block_transactions(&mut r).map_err(|_| TxDiffError::MissingSections {
                height,
                header_id: *header_id,
            })?
        };
        Ok((header_bytes, bt.transactions))
    }
}

//! Post-failure in-memory state recovery: `rebuild_from_committed`
//! restores the AVL+ tree pointers, current height, and
//! `chain_state` from committed disk state. Called by
//! `apply_utxo_changes` on apply failure and by `rollback_to` on
//! rollback failure — recovery infrastructure shared by both
//! apply and reorg paths, kept in its own file for that reason
//! rather than buried under either.

use ergo_primitives::digest::Digest32;

use crate::avl::serialization::AllocMeta;
use crate::chain::{ChainState, ChainStateMeta};

use super::meta::StateMeta;
use super::{StateError, StateStore, CHAIN_INDEX, CHAIN_STATE_META, STATE_META};

impl StateStore {
    /// Restore in-memory state from the committed on-disk state.
    /// Called after any apply or rollback that left the in-memory
    /// arena dirty without a commit — the reorg-abort discipline
    /// guarantees that on failure, the caller drops uncommitted
    /// changes and reads the truth from redb.
    ///
    /// Restores: AVL tree pointers, height, AND chain_state.
    ///
    /// With CachedDiskArena this is O(1): abort discards dirty +
    /// clean cache, then we reset tree pointers from StateMeta.
    /// Next reads fall through to redb.
    pub(super) fn rebuild_from_committed(&mut self) -> Result<(), StateError> {
        // Discard all uncommitted arena state.
        self.tree.arena_abort();

        let sentinel_label = crate::avl::digest::leaf_label(
            &crate::avl::digest::NEGATIVE_INFINITY_KEY,
            &[],
            &crate::avl::digest::POSITIVE_INFINITY_KEY,
        );

        let read_txn = self.db.begin_read()?;
        match read_txn.open_table(STATE_META) {
            Ok(table) => {
                match table.get("root")? {
                    Some(guard) => {
                        let meta = StateMeta::deserialize(guard.value())?;
                        let next_id = match table.get("allocator")? {
                            Some(ag) => AllocMeta::deserialize(ag.value())?.next_id,
                            None => Self::derive_next_id_from_scan(&read_txn)?,
                        };
                        let root_label_bytes: [u8; 32] = meta.root_digest[..32]
                            .try_into()
                            .expect("state_meta.root_digest[..32] must be 32 bytes");
                        let root_label = Digest32::from_bytes(root_label_bytes);
                        self.tree
                            .reset(meta.root_node_id, meta.tree_height, next_id, root_label);
                        self.height = meta.height;
                    }
                    None => {
                        // sentinel is node 1, next_id = 2
                        self.tree.reset(1, 0, 2, sentinel_label);
                        self.height = 0;
                    }
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {
                self.tree.reset(1, 0, 2, sentinel_label);
                self.height = 0;
            }
            Err(e) => return Err(e.into()),
        }

        // Restore chain_state from chain_state_meta, or derive from UTXO state.
        let chain_state = match read_txn.open_table(CHAIN_STATE_META) {
            Ok(table) => match table.get("chain_state")? {
                Some(guard) => {
                    let meta = ChainStateMeta::deserialize(guard.value()).map_err(|e| {
                        StateError::DbCorruption {
                            table: "chain_state_meta",
                            key: hex::encode(b"chain_state"),
                            reason: format!("decode: {e}"),
                        }
                    })?;
                    ChainState::from_persisted(&meta)
                }
                None => self.derive_chain_state_from_utxo(&read_txn)?,
            },
            Err(redb::TableError::TableDoesNotExist(_)) => {
                self.derive_chain_state_from_utxo(&read_txn)?
            }
            Err(e) => return Err(e.into()),
        };
        self.chain_state = chain_state;
        // Voted params: refresh the in-memory cache from the now-restored
        // chain state, using the post-commit (fail-stop) variant on purpose.
        // The cache governs validation — `BlockValidationContext.params` and
        // mempool admission read it — so continuing a rebuild with a stale
        // active-params cache would validate later blocks against the wrong
        // active set, a consensus divergence. A refresh failure here (db
        // corruption / missing genesis row) is a stop-the-world event, so we
        // surface it immediately rather than recover into a wrong state.
        self.refresh_cached_active_params_post_commit();
        Ok(())
    }

    /// Derive chain_state from committed UTXO state when
    /// chain_state_meta is absent — happens on databases predating
    /// the chain_state_meta table or after a corruption-recovery
    /// path that wiped it.
    fn derive_chain_state_from_utxo(
        &self,
        read_txn: &redb::ReadTransaction,
    ) -> Result<ChainState, StateError> {
        if self.height > 0 {
            let chain_table = read_txn.open_table(CHAIN_INDEX)?;
            let guard = chain_table
                .get(self.height as u64)?
                .ok_or(StateError::NoCommittedState)?;
            let mut tip_id = [0u8; 32];
            tip_id.copy_from_slice(guard.value());
            Ok(ChainState {
                best_header_id: tip_id,
                best_header_height: self.height,
                best_header_score: vec![0],
                best_full_block_id: tip_id,
                best_full_block_height: self.height,
                header_availability: crate::chain::HeaderAvailability::Dense,
                session_invalids: std::collections::HashSet::new(),
            })
        } else {
            Ok(ChainState::empty())
        }
    }
}

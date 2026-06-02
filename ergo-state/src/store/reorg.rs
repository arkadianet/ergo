//! Chain rollback: `rollback_to` orchestrates the reorg sequence
//! (pre-read undo entries, apply reverse change-logs, persist
//! truncation atomically), with `apply_rollback_mutations` driving
//! the AVL+ reverse-replay and `persist_rollback` holding the
//! atomic-commit unit (single `begin_write` → all-tables update →
//! `commit()`).
//!
//! Sibling of `mod.rs`. Recovery infrastructure lives in
//! `store/rebuild.rs`; on any rollback failure here we call
//! `self.rebuild_from_committed()` to restore in-memory state
//! from disk.

use redb::ReadableTable;
use tracing::{info, warn};

use super::meta::StateMeta;
use super::undo::undo_log_key;
use super::{
    build_wallet_block_txs_from_sections, node_to_bytes, owned_to_block_txs, StateError,
    StateStore, UndoEntry, AVL_NODES, CHAIN_INDEX, CHAIN_STATE_META, NODE_FORMAT_V2,
    NODE_FORMAT_VERSION_KEY, STATE_META, UNDO_LOG,
};

impl StateStore {
    /// Roll the persistent state back to `target_height`.
    ///
    /// Three-phase: (1) pre-read all undo entries from `UNDO_LOG`
    /// before mutating the AVL tree so a DB read failure leaves
    /// the tree untouched; (2) replay each entry's change-log in
    /// reverse via [`apply_rollback_mutations`]; (3) persist the
    /// truncation atomically via [`persist_rollback`]. Any failure
    /// after step 2 routes through `rebuild_from_committed` so the
    /// in-memory state is restored from committed disk state.
    ///
    /// `wallet_hook` and `rescan_guard` are optional. When supplied,
    /// the wallet tables are rolled back for each block atomically
    /// with the chain-state rollback (both in the same
    /// `persist_rollback` txn). Pass `None, None` from test
    /// harnesses and library callers that do not manage wallet
    /// state.
    pub fn rollback_to(
        &mut self,
        target_height: u32,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
        rescan_guard: Option<&dyn crate::wallet::apply::RescanGuard>,
    ) -> Result<(), StateError> {
        // Capture identity fields before any mutation so the
        // `_failed` event below carries the pre-attempt values,
        // never rebuilt-from-committed values. Depth is
        // `from - target`, not undo-entries length after mutation.
        let from_height = self.height;
        let depth = from_height.saturating_sub(target_height);
        info!(
            event = "state_rollback_started",
            from_height, target_height, depth, "state rollback started",
        );

        // Flush background persist pipeline — all in-flight blocks must be
        // committed before we can rollback against consistent DB state.
        // Must run BEFORE the Phase 4 prune-sentinel check below;
        // queued applies may advance the sentinel, and checking
        // before flush would race the flushed value with our read.
        if let Err(e) = self.flush_persist_pipeline() {
            warn!(
                event = "state_rollback_failed",
                from_height,
                target_height,
                depth,
                phase = "flush_persist_pipeline",
                error = %e,
                "state rollback failed",
            );
            return Err(e);
        }

        // Mode 3 Phase 4 — reject below-sentinel rollback AFTER
        // the pipeline flush so the sentinel reflects all
        // committed apply work. Section bytes at the target have
        // been pruned (or were never downloaded after a Mode 2
        // snapshot install / Mode 4 NiPoPoW dense-from), so the
        // wallet replay path (which re-reads BlockTransactions
        // to recompute affected boxes) cannot reconstruct the
        // rollback.
        //
        // The guard fires whenever `sentinel > 1`, NOT only when
        // `blocks_to_keep > 0`. The sentinel is also written by
        // `install_snapshot_state` (Mode 2 — `snapshot_height +
        // 1`) and `apply_popow_proof` (Mode 4 NiPoPoW —
        // `dense_from_height`) regardless of `blocks_to_keep`,
        // so a Mode 2 / NiPoPoW-bootstrapped archive node would
        // otherwise be vulnerable to a below-snapshot rollback
        // whose sections never existed locally.
        //
        // Returns BEFORE the durable flush + undo-read path
        // below, so a rejected rollback leaves the chain-state
        // observably unchanged.
        // Wallet replay re-reads `BlockTransactions` for the
        // blocks `target_height + 1 ..= from_height`. The lowest
        // replayed block is at height `target_height + 1`, so
        // sections at that height MUST still be present. The
        // boundary is therefore `target_height + 1 >= sentinel`
        // (i.e. `target_height >= sentinel - 1`), NOT
        // `target_height >= sentinel`. Rejecting at the strict
        // `<` would refuse a valid reorg whose replay set starts
        // at the sentinel itself, which is the first retained
        // height.
        let sentinel = self.read_minimal_full_block_height()?;
        if sentinel > 1 && target_height + 1 < sentinel {
            warn!(
                event = "state_rollback_refused",
                from_height, target_height, sentinel, "rollback target below sentinel — refusing",
            );
            return Err(StateError::RollbackBelowPruningSentinel {
                target_height,
                sentinel,
            });
        }

        // Force durable flush before rollback.
        if self.ibd_mode && self.ibd_blocks_since_flush > 0 {
            if let Err(e) = self.force_durable_flush() {
                warn!(
                    event = "state_rollback_failed",
                    from_height,
                    target_height,
                    depth,
                    phase = "force_durable_flush",
                    error = %e,
                    "state rollback failed",
                );
                return Err(e);
            }
            self.ibd_blocks_since_flush = 0;
        }

        // Phase 1: pre-read all undo entries BEFORE mutating the tree.
        // This ensures DB read failures don't leave a partially-mutated tree.
        let mut undo_entries: Vec<(u32, [u8; 32], UndoEntry)> = Vec::new();
        {
            let read_txn = match self.db.begin_read() {
                Ok(t) => t,
                Err(e) => {
                    let se: StateError = e.into();
                    warn!(
                        event = "state_rollback_failed",
                        from_height,
                        target_height,
                        depth,
                        phase = "undo_preread_begin",
                        error = %se,
                        "state rollback failed",
                    );
                    return Err(se);
                }
            };
            let chain_table = match read_txn.open_table(CHAIN_INDEX) {
                Ok(t) => t,
                Err(e) => {
                    let se: StateError = e.into();
                    warn!(
                        event = "state_rollback_failed",
                        from_height,
                        target_height,
                        depth,
                        phase = "undo_preread_chain_index",
                        error = %se,
                        "state rollback failed",
                    );
                    return Err(se);
                }
            };
            let undo_table = match read_txn.open_table(UNDO_LOG) {
                Ok(t) => t,
                Err(e) => {
                    let se: StateError = e.into();
                    warn!(
                        event = "state_rollback_failed",
                        from_height,
                        target_height,
                        depth,
                        phase = "undo_preread_undo_log",
                        error = %se,
                        "state rollback failed",
                    );
                    return Err(se);
                }
            };

            let mut h = self.height;
            while h > target_height {
                let header_id = {
                    let guard = chain_table
                        .get(h as u64)?
                        .ok_or(StateError::NoCommittedState)?;
                    let mut id = [0u8; 32];
                    id.copy_from_slice(guard.value());
                    id
                };
                let key = undo_log_key(h, &header_id);
                let undo_bytes = {
                    let guard = undo_table
                        .get(key.as_slice())?
                        .ok_or(StateError::NoCommittedState)?;
                    guard.value().to_vec()
                };
                let undo_entry = UndoEntry::deserialize(&undo_bytes).map_err(|e| {
                    warn!(
                        height = h,
                        header_id = %hex::encode(header_id),
                        error = ?e,
                        "rollback: undo entry decode failed"
                    );
                    e
                })?;
                undo_entries.push((h, header_id, undo_entry));
                h -= 1;
            }
        }

        // Phase 2: apply undo deltas. All data is pre-read; only tree mutations
        // can fail here (they won't — remove/insert are infallible on valid data).
        // Wrap in a recovery scope anyway for defense-in-depth.
        let result = self.apply_rollback_mutations(&undo_entries, target_height);
        match result {
            Ok(()) => {
                // Phase 3: persist — on failure, rebuild
                if let Err(e) =
                    self.persist_rollback(target_height, &undo_entries, wallet_hook, rescan_guard)
                {
                    self.rebuild_from_committed()?;
                    warn!(
                        event = "state_rollback_failed",
                        from_height,
                        target_height,
                        depth,
                        phase = "persist_rollback",
                        error = %e,
                        "state rollback failed",
                    );
                    return Err(e);
                }
                self.tree.clear_dirty();
                self.tree.arena_commit();
                // Voted params: refresh in-memory cache from the now-consistent
                // table. delete_above ran inside persist_rollback's txn. Cache
                // refresh failure is non-fatal here — the rollback itself
                // committed.
                self.refresh_cached_active_params_post_commit();
                // `_completed` fires only after `persist_rollback` returned
                // Ok — meaning the durable commit succeeded. Earlier-phase
                // failures take the `_failed` exits above.
                info!(
                    event = "state_rollback_completed",
                    from_height,
                    target_height,
                    depth,
                    undo_entries = undo_entries.len(),
                    "state rollback completed",
                );
                Ok(())
            }
            Err(e) => {
                self.rebuild_from_committed()?;
                warn!(
                    event = "state_rollback_failed",
                    from_height,
                    target_height,
                    depth,
                    phase = "apply_rollback_mutations",
                    error = %e,
                    "state rollback failed",
                );
                Err(e)
            }
        }
    }

    /// Rollback tree state using before-image change logs.
    /// Each undo entry's change_log is replayed in reverse to
    /// restore the exact prior tree structure, then the digest is
    /// verified. Sets `self.height = target_height` only after the
    /// full replay completes successfully.
    fn apply_rollback_mutations(
        &mut self,
        undo_entries: &[(u32, [u8; 32], UndoEntry)],
        target_height: u32,
    ) -> Result<(), StateError> {
        for (_height, _header_id, undo) in undo_entries {
            self.tree.rollback(
                &undo.change_log,
                undo.root_node_id_before,
                undo.tree_height_before,
            );

            let restored_digest = self.tree.root_digest();
            if restored_digest != undo.digest_before {
                return Err(StateError::DigestMismatch {
                    computed: hex::encode(restored_digest.as_bytes()),
                    expected: hex::encode(undo.digest_before.as_bytes()),
                });
            }
        }
        self.height = target_height;
        Ok(())
    }

    /// Internal: persist a rollback, pruning chain_index and
    /// undo_log above target. Uses the undo entries' change_logs to
    /// determine which AVL nodes need writing/deletion rather than
    /// snapshotting all live nodes. Single write transaction —
    /// AVL_NODES, CHAIN_INDEX, UNDO_LOG, STATE_META, CHAIN_STATE_META,
    /// voted_params, and wallet tables all update before `commit()`.
    fn persist_rollback(
        &mut self,
        target_height: u32,
        undo_entries: &[(u32, [u8; 32], UndoEntry)],
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
        rescan_guard: Option<&dyn crate::wallet::apply::RescanGuard>,
    ) -> Result<(), StateError> {
        // Collect all node IDs touched by the rolled-back blocks
        use crate::avl::changelog::NodeChange;
        let mut touched_ids = std::collections::HashSet::new();
        for (_, _, undo) in undo_entries {
            for change in undo.change_log.changes() {
                match change {
                    NodeChange::Created(id) | NodeChange::Modified(id, _) => {
                        touched_ids.insert(*id);
                    }
                }
            }
        }

        let write_txn = crate::begin_write_qr(&self.db)?;
        let new_tip_id = {
            // Write/delete only nodes that were touched during the rolled-back blocks
            let mut avl_table = write_txn.open_table(AVL_NODES)?;
            for id in &touched_ids {
                if let Some(node) = self.tree.get_node(*id) {
                    avl_table.insert(*id, node_to_bytes(&node).as_slice())?;
                } else {
                    avl_table.remove(*id)?;
                }
            }

            // Prune chain_index and undo_log entries for the rolled-back blocks
            let mut chain_table = write_txn.open_table(CHAIN_INDEX)?;
            let mut undo_table = write_txn.open_table(UNDO_LOG)?;
            for &(h, ref hid, _) in undo_entries {
                chain_table.remove(h as u64)?;
                let key = undo_log_key(h, hid);
                undo_table.remove(key.as_slice())?;
            }

            // Update state meta
            let meta = StateMeta {
                height: target_height,
                tree_height: self.tree.tree_height(),
                root_digest: *self.tree.root_digest().as_bytes(),
                root_node_id: self.tree.root_id(),
            };
            let mut meta_table = write_txn.open_table(STATE_META)?;
            meta_table.insert("root", meta.serialize().as_slice())?;
            meta_table.insert(NODE_FORMAT_VERSION_KEY, NODE_FORMAT_V2)?;

            // Chain state meta: compute new tip_id for rollback target.
            let tip_id = if target_height > 0 {
                let guard = chain_table
                    .get(target_height as u64)?
                    .ok_or(StateError::NoCommittedState)?;
                let mut id = [0u8; 32];
                id.copy_from_slice(guard.value());
                id
            } else {
                [0u8; 32]
            };
            // Write chain_state_meta with computed values (no self mutation yet).
            let mut cs = self.chain_state.to_persisted();
            cs.best_full_block_height = target_height;
            cs.best_full_block_id = tip_id;
            let mut cs_table = write_txn.open_table(CHAIN_STATE_META)?;
            cs_table.insert("chain_state", cs.serialize().as_slice())?;
            tip_id
        };

        // Voted parameters: drop every row whose key is strictly above
        // the rollback target. Genesis row at key 0 is preserved.
        // Rollback failures route through the same VotedParamsWriteFailed
        // family as reconcile/apply so operators see one variant for the
        // whole voted-params write surface.
        crate::active_params::delete_above(&write_txn, target_height).map_err(|e| {
            StateError::VotedParamsWriteFailed {
                op: "rollback",
                height: target_height,
                source: Box::new(e),
            }
        })?;

        // Wallet rollback: invoked inside the same write txn so the wallet
        // state regresses atomically with chain state. Processed in
        // REVERSE block order (highest height first), matching the undo
        // entry ordering (undo_entries is tip-first since we walked
        // self.height downward).
        if let (Some(_hook), Some(guard)) = (wallet_hook, rescan_guard) {
            // undo_entries is ordered tip-first; rollback processes each block
            // from tip down to target+1.
            for &(h, ref hid, _) in undo_entries {
                // Re-read block transactions from BLOCK_SECTIONS.
                match build_wallet_block_txs_from_sections(&self.db, hid) {
                    Ok(Some(owned)) => {
                        let bound = owned_to_block_txs(&owned);
                        let btxs = bound.as_block_txs();
                        crate::wallet::apply::rollback_block_from_wallet(
                            &write_txn, h, &btxs, guard,
                        )
                        .map_err(|e| StateError::WalletApply {
                            what: "rollback",
                            height: h,
                            source: Box::new(e),
                        })?;
                        crate::wallet::maturity::unpromote_matured_boxes(
                            &write_txn,
                            h.saturating_sub(1),
                        )
                        .map_err(|e| StateError::WalletApply {
                            what: "maturity unpromote",
                            height: h,
                            source: Box::new(e),
                        })?;
                    }
                    Ok(None) => {
                        // Block section not available (pruned / not yet downloaded).
                        // Wallet history cannot be replayed for this height —
                        // force-invalidate so the next restart triggers a full
                        // rescan. Distinct from `abort_in_progress` (which only
                        // invalidates if a rescan was already running) because
                        // wallet stale-ness here is by construction, not by
                        // interrupted work.
                        tracing::warn!(
                            height = h,
                            "wallet rollback: block section missing — invalidating for rescan",
                        );
                        guard.force_invalidate(&write_txn).map_err(|e| {
                            StateError::WalletApply {
                                what: "force_invalidate",
                                height: h,
                                source: Box::new(e),
                            }
                        })?;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            height = h,
                            error = %e,
                            "wallet rollback: error reading block section — invalidating for rescan",
                        );
                        guard.force_invalidate(&write_txn).map_err(|e2| {
                            StateError::WalletApply {
                                what: "force_invalidate",
                                height: h,
                                source: Box::new(e2),
                            }
                        })?;
                        break;
                    }
                }
            }
        }

        write_txn.commit()?;
        // Mutation after successful commit.
        self.chain_state.best_full_block_height = target_height;
        self.chain_state.best_full_block_id = new_tip_id;
        Ok(())
    }
}

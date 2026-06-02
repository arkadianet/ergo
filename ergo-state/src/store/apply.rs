//! Block application: orchestrates `apply_block` from a
//! `CheckedBlock`, plus the validated / unchecked / genesis /
//! voted-params apply paths, the UTXO mutation core, and the
//! post-mutation in-memory bookkeeping that advances
//! `chain_state.best_full_block_*`, the AVL+ arena, and the
//! cumulative validation-settings cache.
//!
//! Sibling of `mod.rs` kept for navigability. All items are
//! `impl StateStore { ... }` methods on the parent struct; the
//! atomic-commit invariant lives one layer down in
//! `mod.rs::persist_apply`, which `apply_mutations` calls.

use std::collections::BTreeMap;

use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox};
use ergo_ser::transaction::{bytes_to_sign, Transaction};
use ergo_validation::CheckedTransaction;
use tracing::debug;

use super::{
    build_wallet_block_txs_checked, StateError, StateStore, UndoEntry, UtxoChangeMaps,
    UtxoInsertMap, UtxoMutation, UtxoRemoveMap,
};

/// Scala-parity compute for the Mode 3 prune low-water mark, mirroring
/// `FullBlockPruningProcessor.updateBestFullBlock` (lines 49-67 of the
/// Scala reference).
///
/// Inputs:
/// - `current_min`: the persisted sentinel value
///   (`STATE_META["minimal_full_block_height"]`), or `1` if absent.
/// - `header_height`: the height of the block being applied.
/// - `blocks_to_keep`: retention window. `< 0` = archive (no pruning;
///   return `current_min` unchanged). `0` = canonical Mode 6
///   (full-block applies don't happen, but a defensive call returns
///   `current_min`). `> 0` = suffix window.
/// - `voting_length`: voting epoch length (1024 mainnet, 128 testnet).
///   Used for the epoch-boundary snap.
///
/// Output:
///   `max(current_min, header_height - blocks_to_keep + 1)`, then snapped
///   DOWN to the nearest voting-epoch boundary when the un-snapped result
///   exceeds `voting_length`. The snap ensures we never keep a partial
///   voting epoch — the extension at the epoch boundary carries the
///   voted protocol parameters that downstream re-validation needs.
///
/// Monotonic by construction: never returns a value less than
/// `current_min`. Saturating subtraction handles small heights so
/// `compute_minimal_full_block_height(_, header_height=10,
/// blocks_to_keep=100, _)` returns `current_min` rather than
/// underflowing.
pub fn compute_minimal_full_block_height(
    current_min: u32,
    header_height: u32,
    blocks_to_keep: i32,
    voting_length: u32,
) -> u32 {
    if blocks_to_keep < 0 {
        // Archive: sentinel never advances.
        return current_min;
    }
    if blocks_to_keep == 0 {
        // Canonical Mode 6: headers-only, no full-block applies
        // drive the sentinel. Defensive: callers shouldn't reach
        // this from `persist_apply` (Mode 6 doesn't apply
        // full blocks), but `compute_*` is a pure function and
        // returning `current_min` is the right "no advance" answer.
        return current_min;
    }
    // `blocks_to_keep > 0` → suffix window.
    let blocks_to_keep_u = blocks_to_keep as u32;
    // Scala: max(currentMinimal, header.height - blocksToKeep + 1)
    // Saturating sub: small heights stay at current_min.
    let candidate = header_height
        .saturating_sub(blocks_to_keep_u.saturating_sub(1))
        .max(current_min);
    // Voting-epoch snap: only fires when the candidate is past the
    // first voting epoch (Scala: `if (h > VotingEpochLength)`).
    // Below that boundary, the sentinel sits in the bootstrap
    // prefix where epoch-boundary semantics don't apply yet.
    if voting_length > 0 && candidate > voting_length {
        let snapped = candidate - (candidate % voting_length);
        // Snap DOWN — never below `current_min` (the floor).
        // If `current_min` is already past the snapped boundary
        // (e.g. a tighter previous prune), keep `current_min`
        // rather than walking the sentinel backward.
        snapped.max(current_min)
    } else {
        candidate
    }
}

impl StateStore {
    /// Apply validated transactions to the UTXO state.
    ///
    /// Consumes `CheckedTransaction` to enforce the trust boundary at
    /// the type level: only transactions that passed validation can
    /// reach state application.
    ///
    /// Implements the spec's atomic commit (spec:419-453):
    /// 1. Record digest_before
    /// 2. Apply UTXO changes
    /// 3. Verify new_digest == expected_state_root (abort on mismatch)
    /// 4. Write undo_log, chain_index, state_meta + (when active)
    ///    wallet tables — all inside the same redb write_txn
    /// 5. Atomic commit
    ///
    /// Wallet hook atomicity (M5):
    ///
    /// - **Synchronous path** (no persist pipeline): the payload is
    ///   consumed inside `persist_apply`'s write_txn before the commit
    ///   fires. Chain + wallet state advance atomically.
    ///
    /// - **Pipeline path** (`enable_persist_pipeline(_)` active):
    ///   `persist_apply` queues the chain mutation AND the wallet
    ///   payload to the background worker. `execute_batch` (the
    ///   worker) applies wallet writes inside the same redb
    ///   write_txn that commits the batched chain mutations — chain
    ///   + wallet atomic on the pipeline path too. The IBD
    ///   throughput advantage of the pipeline is preserved (no
    ///   per-block synchronous flush) because the worker handles
    ///   the atomic seam.
    ///
    /// Either path: a crash between the two phases is no longer
    /// reachable. Failure inside the worker's batch (chain or
    /// wallet) aborts the whole batch via redb's documented
    /// atomicity.
    #[tracing::instrument(
        name = "apply_block",
        level = "debug",
        skip_all,
        fields(
            height = block.header().height(),
            header_id = %hex::encode(block.header().header_id()),
            n_txs = block.transactions().len(),
        ),
    )]
    pub fn apply_block(
        &mut self,
        block: &ergo_validation::block::CheckedBlock,
        voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
        wallet_hook: Option<&dyn crate::wallet::WalletApplyHook>,
    ) -> Result<(), StateError> {
        let header = block.header();
        let height = header.height();
        let header_id = *header.header_id();

        // Pre-build the wallet payload on the main thread BEFORE chain
        // apply. The payload bundles owned data only, so it can later
        // cross the pipeline-worker thread boundary (M5 follow-up).
        let payload: Option<crate::store::WalletApplyPayload> = if let Some(hook) = wallet_hook {
            let trees = hook.tracked_p2pk_trees();
            let pubkeys = hook.cached_pubkeys();
            if trees.is_empty() && pubkeys.is_empty() {
                None
            } else {
                let owned = build_wallet_block_txs_checked(block.transactions(), height)?;
                Some(crate::store::WalletApplyPayload {
                    tracked_p2pk_trees: trees,
                    cached_pubkeys: pubkeys,
                    block_txs_owned: owned,
                })
            }
        } else {
            None
        };

        // Persist-pipeline path predicate: capture BEFORE
        // `apply_checked_transactions` so the fallback (pipeline-path
        // separate wallet write) fires only when persist_apply did
        // NOT consume the payload atomically.
        let pipeline_active = self.persist_pipeline.is_some();

        self.apply_checked_transactions(
            height,
            &header_id,
            &header.header().state_root,
            block.transactions(),
            voted_params_row,
            payload.as_ref(),
        )?;

        // M5 final-slice: pipeline-path wallet writes now travel
        // through `PersistJob` and apply inside the worker's batch
        // write_txn (see `persist::execute_batch` step 9). No
        // separate fallback write_txn is needed — chain + wallet
        // commit atomically on both paths.
        let _ = pipeline_active;
        let _ = payload;
        Ok(())
    }

    /// Shared apply core for a `CheckedBlock` and the test harness path
    /// that drives individual CheckedTransactions without building a real
    /// block header. Production code should not call this directly.
    pub(crate) fn apply_checked_transactions(
        &mut self,
        height: u32,
        header_id: &[u8; 32],
        expected_state_root: &ADDigest,
        checked: &[CheckedTransaction],
        voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
        wallet_payload: Option<&crate::store::WalletApplyPayload>,
    ) -> Result<(), StateError> {
        if !self.genesis_committed {
            return Err(StateError::InvalidPrecondition {
                what: "apply_block called before initialize_genesis",
            });
        }

        // Build UTXO changes using precomputed tx_id from CheckedTransaction.
        // Uses the Scala boxChanges model: intra-block creates that are spent
        // within the same block are excluded from both sets.
        let t_build_start = std::time::Instant::now();
        let (to_remove, to_insert) = Self::build_utxo_changes_checked(checked)?;
        let t_build = t_build_start.elapsed();
        // Track build_utxo_changes time so the apply-phase breakdown
        // accounts for the gap between outer `apply` (in [perf-blk])
        // and inner `tree+digest+persist` (in [perf:apply]). Sampled
        // every 100 heights for visibility without log spam.
        if height.is_multiple_of(100) {
            let tx_count = checked.len();
            debug!(
                height,
                tx_count,
                build_ms = t_build.as_secs_f64() * 1000.0,
                "perf build",
            );
        }

        self.apply_utxo_changes(
            height,
            header_id,
            expected_state_root,
            to_remove,
            to_insert,
            voted_params_row,
            wallet_payload,
        )
    }

    /// Apply the genesis block's transactions. Production entry point for
    /// block 1 where validate_full_block cannot run (no parent header, no
    /// prior state to validate against). Enforces `height == 1` so callers
    /// cannot accidentally reuse this as a general unchecked-apply.
    pub fn apply_genesis(
        &mut self,
        header_id: &[u8; 32],
        expected_state_root: &ADDigest,
        transactions: &[Transaction],
    ) -> Result<(), StateError> {
        self.apply_block_unchecked(1, header_id, expected_state_root, transactions)
    }

    /// Apply transactions without validation type enforcement.
    /// Reached in production only via [`apply_genesis`] (height == 1) and
    /// in tests via the `apply_block_unchecked_for_test` helper behind
    /// the `test-helpers` feature. Recomputes tx_ids from transaction
    /// bytes internally.
    pub(crate) fn apply_block_unchecked(
        &mut self,
        height: u32,
        header_id: &[u8; 32],
        expected_state_root: &ADDigest,
        transactions: &[Transaction],
    ) -> Result<(), StateError> {
        if !self.genesis_committed {
            return Err(StateError::InvalidPrecondition {
                what: "apply_block called before initialize_genesis",
            });
        }

        let txs: Vec<&Transaction> = transactions.iter().collect();
        let (to_remove, to_insert) = Self::build_utxo_changes_raw(&txs)?;

        // Genesis (height 1) is not an epoch start; raw-tx test paths do
        // not exercise voted-params logic. For tests that need to write a
        // voted_params row alongside an unchecked apply, see
        // `apply_block_unchecked_with_voted_params_for_test`.
        // No wallet payload: the genesis path predates any wallet
        // tracking, and the test harness path runs without a wallet
        // hook.
        self.apply_utxo_changes(
            height,
            header_id,
            expected_state_root,
            to_remove,
            to_insert,
            None,
            None,
        )
    }

    /// Test-only: same as `apply_block_unchecked` but lets the caller
    /// supply a `voted_params_row` to exercise the voted-params
    /// storage path on synthetic epoch-boundary blocks. The lifecycle
    /// test in `tests/voted_params_lifecycle.rs` is the only intended
    /// caller.
    #[cfg(feature = "test-helpers")]
    pub(crate) fn apply_block_unchecked_with_voted_params(
        &mut self,
        height: u32,
        header_id: &[u8; 32],
        expected_state_root: &ADDigest,
        transactions: &[Transaction],
        voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
    ) -> Result<(), StateError> {
        if !self.genesis_committed {
            return Err(StateError::InvalidPrecondition {
                what: "apply_block called before initialize_genesis",
            });
        }
        let txs: Vec<&Transaction> = transactions.iter().collect();
        let (to_remove, to_insert) = Self::build_utxo_changes_raw(&txs)?;
        self.apply_utxo_changes(
            height,
            header_id,
            expected_state_root,
            to_remove,
            to_insert,
            voted_params_row,
            None,
        )
    }

    /// Build UTXO change maps from checked transactions (precomputed tx_id).
    /// `pub(crate)` so the three consumers share one net-change-set
    /// construction: `candidate_dry_run` (UTXO AVL-prover dry-run), Mode 1
    /// apply, and the Mode 5 digest apply-bridge. A forked builder would
    /// let the digest verifier and the UTXO tree diverge on the same
    /// block — a consensus split — so this stays the single source.
    pub(crate) fn build_utxo_changes_checked(
        checked: &[CheckedTransaction],
    ) -> Result<UtxoChangeMaps, StateError> {
        let mut to_remove: UtxoRemoveMap = BTreeMap::new();
        let mut to_insert: UtxoInsertMap = BTreeMap::new();

        for c in checked {
            let tx = c.transaction();
            let tx_id: ModifierId = Digest32::from_bytes(*c.tx_id()).into();

            for input in &tx.inputs {
                let box_id = *input.box_id.as_bytes();
                if to_insert.remove(&box_id).is_none() {
                    to_remove.insert(box_id, ());
                }
            }
            for (i, candidate) in tx.output_candidates.iter().enumerate() {
                let output_box = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id,
                    index: i as u16,
                };
                let box_id = output_box
                    .box_id()
                    .map_err(|e| StateError::Serialization(format!("box_id: {e}")))?;
                let serialized = serialize_ergo_box(&output_box)
                    .map_err(|e| StateError::Serialization(format!("serialize: {e}")))?;
                to_insert.insert(*box_id.as_bytes(), serialized);
            }
        }

        Ok((to_remove, to_insert))
    }

    /// Build UTXO change maps from raw transactions (recomputes tx_id).
    /// Used by `apply_block_unchecked` for genesis and tests, and by the
    /// Mode 5 digest block-processing path (in `ergo-sync`), which works
    /// from raw `Transaction`s rather than `CheckedTransaction`s. Shares
    /// the create-then-spend netting with the checked builder so the
    /// digest verifier and the UTXO tree cannot diverge on the same
    /// block's change set. `pub` (not `pub(crate)`) because the digest
    /// consumer lives in a sibling crate — there must be exactly one
    /// netting builder, so it is exported rather than duplicated.
    pub fn build_utxo_changes_raw(
        transactions: &[&Transaction],
    ) -> Result<UtxoChangeMaps, StateError> {
        let mut to_remove: UtxoRemoveMap = BTreeMap::new();
        let mut to_insert: UtxoInsertMap = BTreeMap::new();

        for &tx in transactions {
            let bts = bytes_to_sign(tx)
                .map_err(|e| StateError::Serialization(format!("bytes_to_sign: {e}")))?;
            let tx_id: ModifierId = blake2b256(&bts).into();

            for input in &tx.inputs {
                let box_id = *input.box_id.as_bytes();
                if to_insert.remove(&box_id).is_none() {
                    to_remove.insert(box_id, ());
                }
            }
            for (i, candidate) in tx.output_candidates.iter().enumerate() {
                let output_box = ErgoBox {
                    candidate: candidate.clone(),
                    transaction_id: tx_id,
                    index: i as u16,
                };
                let box_id = output_box
                    .box_id()
                    .map_err(|e| StateError::Serialization(format!("box_id: {e}")))?;
                let serialized = serialize_ergo_box(&output_box)
                    .map_err(|e| StateError::Serialization(format!("serialize: {e}")))?;
                to_insert.insert(*box_id.as_bytes(), serialized);
            }
        }

        Ok((to_remove, to_insert))
    }

    /// Shared block application logic: mutate AVL tree, verify digest,
    /// persist via `apply_mutations`, then update in-memory chain state
    /// (height, best_full_block, validation-settings cache) on success.
    /// On error, rebuilds in-memory state from disk via
    /// `rebuild_from_committed`.
    #[allow(clippy::too_many_arguments)]
    fn apply_utxo_changes(
        &mut self,
        height: u32,
        header_id: &[u8; 32],
        expected_state_root: &ADDigest,
        to_remove: UtxoRemoveMap,
        to_insert: UtxoInsertMap,
        voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
        wallet_payload: Option<&crate::store::WalletApplyPayload>,
    ) -> Result<(), StateError> {
        let digest_before = self.tree.root_digest();
        let cache_advance = voted_params_row.clone();

        let result = self.apply_mutations(UtxoMutation {
            height,
            header_id,
            expected_state_root,
            digest_before,
            to_remove: &to_remove,
            to_insert: &to_insert,
            voted_params_row,
            wallet_payload,
        });
        match result {
            Ok(()) => {
                // Post-mutation bookkeeping: clear_dirty + arena_commit
                // are AVL+ tree finalization (potentially the missing
                // 5-10ms per block that doesn't show in tree/digest/
                // persist phase samples). Time them so the gap between
                // the inner [perf:apply] sum and the outer [perf-blk]
                // apply phase becomes visible.
                let t_post = std::time::Instant::now();
                self.height = height;
                self.tree.clear_dirty();
                self.tree.arena_commit();
                self.chain_state.best_full_block_height = height;
                self.chain_state.best_full_block_id = *header_id;
                if self.chain_state.best_header_height < height {
                    self.chain_state.best_header_id = *header_id;
                    self.chain_state.best_header_height = height;
                }
                if let Some(p) = cache_advance {
                    // Fold this epoch's activated_update into the
                    // cumulative validation settings cache. Without
                    // this, `cached_validation_settings` only refreshes
                    // on open()/rollback/reorg, so any in-session
                    // forward apply across an activation epoch leaves
                    // the cache stale and the next epoch boundary
                    // rejects on `exMatchValidationSettings`. Mirror
                    // of the on-disk fold in
                    // `compute_validation_settings_at`.
                    self.cached_validation_settings =
                        self.cached_validation_settings.updated(&p.activated_update);
                    self.cached_active_params = p;
                }
                let t_post = t_post.elapsed();
                if height.is_multiple_of(100) {
                    debug!(height, post_ms = t_post.as_secs_f64() * 1000.0, "perf post",);
                }
                // NiPoPoW serve-side auto-trigger. When a Dense archive
                // node crosses a snapshot-epoch boundary, recompute +
                // cache the proof so peers requesting `GetNipopowProof`
                // get a fresh one. Mirrors Scala's apply-time trigger
                // at `HeadersProcessor.scala:182-194`. Uses the fast
                // interlinks-walk variant ([`Self::prove_with_db`])
                // so compute time is seconds, not minutes.
                //
                // Best-effort: any error here is logged but does
                // NOT fail the block apply (apply has already
                // committed). Sparse-mode stores skip via the
                // method's own precondition check.
                self.maybe_recompute_popow_proof(height);
                Ok(())
            }
            Err(e) => {
                self.rebuild_from_committed()?;
                Err(e)
            }
        }
    }

    /// Inner mutation path for apply_block. All fallible operations after the
    /// first tree mutation are here so the caller can catch any error and rebuild.
    fn apply_mutations(&mut self, mutation: UtxoMutation<'_>) -> Result<(), StateError> {
        let UtxoMutation {
            height,
            header_id,
            expected_state_root,
            digest_before,
            to_remove,
            to_insert,
            voted_params_row,
            wallet_payload,
        } = mutation;

        let root_id_before = self.tree.root_id();
        let tree_height_before = self.tree.tree_height();
        let mut box_removed = Vec::with_capacity(to_remove.len());
        let mut box_created = Vec::with_capacity(to_insert.len());

        let t0 = std::time::Instant::now();
        for box_id in to_remove.keys() {
            let old_bytes = self.tree.remove(box_id).ok_or_else(|| {
                tracing::warn!(
                    height,
                    header_id = %hex::encode(header_id),
                    box_id = %hex::encode(box_id),
                    "apply: box not found for remove — rejecting block"
                );
                StateError::BoxNotFound(hex::encode(box_id))
            })?;
            box_removed.push((*box_id, old_bytes));
        }

        for (box_id, serialized) in to_insert {
            self.tree.insert(*box_id, serialized.clone());
            box_created.push(*box_id);
        }
        let t_tree = t0.elapsed();

        let t0 = std::time::Instant::now();
        let new_digest = self.tree.root_digest();
        let t_digest = t0.elapsed();

        if &new_digest != expected_state_root {
            tracing::warn!(
                height,
                header_id = %hex::encode(header_id),
                computed = %hex::encode(new_digest.as_bytes()),
                expected = %hex::encode(expected_state_root.as_bytes()),
                "apply: state-root mismatch — rejecting block"
            );
            return Err(StateError::DigestMismatch {
                computed: hex::encode(new_digest.as_bytes()),
                expected: hex::encode(expected_state_root.as_bytes()),
            });
        }

        let change_log = self.tree.take_change_log();

        let undo = UndoEntry {
            digest_before,
            root_node_id_before: root_id_before,
            tree_height_before,
            change_log,
            removed: box_removed,
            created: box_created,
        };

        // M5 atomic commit on both paths:
        //   - Synchronous path: persist_apply consumes the wallet
        //     payload inside the same write_txn as chain mutations.
        //   - Pipeline path: persist_apply queues the payload on
        //     the PersistJob; the worker's execute_batch applies it
        //     inside the same batch write_txn that commits the
        //     chain mutations.
        let t0 = std::time::Instant::now();
        let result = self.persist_apply(
            height,
            header_id,
            &new_digest,
            &undo,
            voted_params_row,
            wallet_payload,
        );
        let t_persist = t0.elapsed();

        // Sample every 100 heights to get 10x density vs the prior
        // every-1000 sampling — light enough not to spam logs, dense
        // enough to catch heavy-block outliers that the 1000-block
        // window misses entirely. `tree+digest+persist` are the only
        // phases inside `apply_mutations`; the gap between this sum
        // and the outer `apply` time (visible in [perf-blk]) is in
        // post-mutation bookkeeping (`clear_dirty`, `arena_commit`,
        // chain_state updates) timed separately by the caller.
        if height.is_multiple_of(100) || height <= 5 {
            let rm = to_remove.len();
            let ins = to_insert.len();
            debug!(
                height,
                rm,
                ins,
                tree_ms = t_tree.as_secs_f64() * 1000.0,
                digest_ms = t_digest.as_secs_f64() * 1000.0,
                persist_ms = t_persist.as_secs_f64() * 1000.0,
                "perf apply",
            );
        }

        result.map(|_| ())
    }
}

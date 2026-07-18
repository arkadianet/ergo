//! Full-chain reorg handling for [`SyncExecutor`].
//!
//! One load-bearing state machine kept together as a unit: fork
//! detection ([`SyncExecutor::full_chain_fork_point`]) → wedge
//! classification ([`ForkPoint::TooDeep`] / [`DeepForkWedge`]) →
//! rollback ([`SyncExecutor::rollback_full_chain_to_best_header`]) →
//! sequential re-apply ([`SyncExecutor::try_apply_next_blocks`]).
//! Also carries the block-apply rejection bookkeeping surfaced via
//! /health and /status.

use std::time::Instant;

use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::{BlockApply, ChainStateRead, HeaderSectionStore};
use tracing::{info, warn};

use crate::block_proc;
use crate::coordinator::SyncCoordinator;

use super::{is_validation_verdict, StorageResult, SyncExecutor, DEEP_FORK_REWARN};

/// A block this node rejected during apply. `at` is an `Instant` so callers
/// compute `age_ms` at read time (matching the snapshot-age pattern) rather
/// than storing a wall-clock.
#[derive(Clone, Debug)]
pub struct LastBlockApplyError {
    pub header_id: [u8; 32],
    pub height: u32,
    pub reason: String,
    pub at: Instant,
}

/// Terminal deep-fork wedge descriptor (see the field on [`SyncExecutor`]).
/// `since` is an `Instant` so callers compute `age_ms` at read time.
#[derive(Clone, Debug)]
pub struct DeepForkWedge {
    /// The stuck full-block tip (on the abandoned branch).
    pub best_full_id: [u8; 32],
    pub best_full_height: u32,
    /// Lowest height the fork-point walk examined before hitting the
    /// horizon — the best-header chain still disagreed there.
    pub scanned_to_height: u32,
    /// The backend's undo-retention window the fork exceeded.
    pub max_rollback_depth: u32,
    pub since: Instant,
}

/// Outcome of [`SyncExecutor::full_chain_fork_point`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForkPoint {
    /// The best-header chain leaves the applied full chain at this
    /// `(height, header_id)` — roll back to it and re-apply.
    Found(u32, [u8; 32]),
    /// The applied full chain lies on the best-header chain (or there is
    /// nothing to compare yet) — no reorg needed.
    NotForked,
    /// The best-header chain forks deeper below the full tip than the state
    /// backend can roll back (undo log pruned): the reorg is impossible and
    /// the node is wedged until a resync.
    TooDeep {
        /// Lowest height examined; the chains still disagreed there.
        scanned_to: u32,
        max_depth: u32,
    },
}

/// Outcome of [`SyncExecutor::rollback_full_chain_to_best_header`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReorgOutcome {
    /// A rollback to the fork point was performed — re-drive block apply.
    Performed,
    /// The full chain already lies on the best-header chain.
    NotNeeded,
    /// Declined: the fork is below the rollback horizon (wedge recorded).
    TooDeep,
}

impl SyncExecutor {
    /// The most recent block-apply rejection, if any (see
    /// [`LastBlockApplyError`]).
    pub fn last_block_apply_error(&self) -> Option<&LastBlockApplyError> {
        self.last_block_apply_error.as_ref()
    }

    /// Monotonic count of block-apply rejections since start.
    pub fn block_apply_error_count(&self) -> u64 {
        self.block_apply_error_count
    }

    /// Record a block-apply REJECTION for observability. Called only from the
    /// two genuine invalid-block sinks — NOT the data-wait (SectionNotFound /
    /// AdProofsUnavailable) or reorg (ParentNotBestFull / Digest*) arms, which
    /// are benign during normal IBD and would otherwise pin a red health state.
    ///
    /// Deduplicated against the SAME header: `mark_session_invalid` does not
    /// remove the header from `HEADER_CHAIN_INDEX`, so the executor re-selects
    /// and re-rejects the same `best_chain` block every sync tick. Without the
    /// guard the counter would count retries (not distinct rejections) and
    /// `at` would never age. Only a DISTINCT rejected header is a new event;
    /// repeats keep the original timestamp and counter.
    pub(super) fn record_block_apply_error(
        &mut self,
        header_id: [u8; 32],
        height: u32,
        reason: String,
    ) {
        if self
            .last_block_apply_error
            .as_ref()
            .is_some_and(|e| e.header_id == header_id)
        {
            return;
        }
        self.last_block_apply_error = Some(LastBlockApplyError {
            header_id,
            height,
            reason,
            at: Instant::now(),
        });
        self.block_apply_error_count += 1;
    }

    /// The active deep-fork wedge, if any (see [`DeepForkWedge`]).
    pub fn deep_fork_wedge(&self) -> Option<&DeepForkWedge> {
        self.deep_fork_wedge.as_ref()
    }

    /// Record (or refresh) the deep-fork wedge and emit the operator
    /// warning, rate-limited to once per [`DEEP_FORK_REWARN`] — the wedge is
    /// re-detected every tick, and a per-tick warn would bury the one line
    /// that explains the stall. A wedge on a NEW stuck tip warns
    /// immediately and restarts the `since` clock; the same stuck tip keeps
    /// its original `since` so `age_ms` ages honestly.
    fn note_deep_fork_wedge(
        &mut self,
        store: &ergo_state::StateBackendKind,
        scanned_to: u32,
        max_depth: u32,
    ) {
        let cs = store.chain_state_meta();
        let same_tip = self
            .deep_fork_wedge
            .as_ref()
            .is_some_and(|w| w.best_full_id == cs.best_full_block_id);
        if !same_tip {
            self.deep_fork_wedge = Some(DeepForkWedge {
                best_full_id: cs.best_full_block_id,
                best_full_height: cs.best_full_block_height,
                scanned_to_height: scanned_to,
                max_rollback_depth: max_depth,
                since: Instant::now(),
            });
            self.deep_fork_wedge_last_warn = None;
        }
        let due = self
            .deep_fork_wedge_last_warn
            .is_none_or(|at| at.elapsed() >= DEEP_FORK_REWARN);
        if due {
            warn!(
                event = "full_chain_fork_too_deep",
                best_full_height = cs.best_full_block_height,
                best_full_id = %hex::encode(cs.best_full_block_id),
                scanned_to,
                max_rollback_depth = max_depth,
                "best-header chain forks deeper than the rollback window: this \
                 node cannot reorg onto it and will not apply further blocks — \
                 recovery requires a resync (wipe the data dir and sync fresh)",
            );
            self.deep_fork_wedge_last_warn = Some(Instant::now());
        }
    }

    /// Clear the deep-fork wedge (the chains agree again, or a reorg
    /// performed). Logs the recovery transition once.
    fn clear_deep_fork_wedge(&mut self) {
        if let Some(w) = self.deep_fork_wedge.take() {
            info!(
                event = "full_chain_fork_wedge_cleared",
                best_full_height = w.best_full_height,
                best_full_id = %hex::encode(w.best_full_id),
                "deep-fork wedge cleared — the best-header chain is reachable again",
            );
            self.deep_fork_wedge_last_warn = None;
        }
    }

    /// Try to apply the next sequential block(s) directly from the store.
    /// Uses the in-memory header_index for O(1) height→header_id lookups.
    /// Applies as many consecutive blocks as possible in one tick.
    /// Drain pending block applies in a tight loop until no progress is made.
    ///
    /// Emits no entries to the action transcript by design: every effect is
    /// a state mutation on `SyncCoordinator` (`sync_state.best_full_block`,
    /// `assembly`) observable via getters. Spec §3's "ordered emission,
    /// testable" property covers transcript-emitted variants
    /// (`SendToPeer`/`Penalize`/`PersistSection`/`AssembleBlock`); chained
    /// block-apply is a state event, not an external effect. Returning
    /// `()` rather than `Vec<Action>` keeps that contract honest.
    /// Shared apply-failure handler for a block `process_block` rejected.
    ///
    /// A definitive validation verdict ([`is_validation_verdict`]) means the
    /// Scala reference node also rejects the block, so it can never apply:
    /// durably invalidate it and every stored descendant, re-anchor
    /// best_header to the surviving tip (Scala `reportModifierIsInvalid`),
    /// evict the dead branch from the download queue, and drop stale
    /// `header_index` rows above the re-anchored tip. Persisting this across
    /// restart is what stops an invalid block being retried forever. Any other
    /// error (transient / IO / digest-ambiguous) gets only a session-scoped
    /// mark, cleared on restart — we must never persistently poison a branch
    /// that might be failing on our own bug or a stale local root. If the
    /// durable walk itself fails (IO), fall back to the session mark.
    ///
    /// Shared by [`Self::try_apply_next_blocks`] and `handle_assemble_block`
    /// so both apply-failure paths classify a failure identically.
    pub(super) fn invalidate_or_session_mark(
        &mut self,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        header_id: [u8; 32],
        height: u32,
        err: &block_proc::BlockProcessError,
    ) {
        if !is_validation_verdict(err) {
            // Transient / IO / digest-ambiguous failure: never poison the
            // branch persistently. Session-scoped only, cleared on restart.
            store.mark_session_invalid(header_id);
            return;
        }
        match store.invalidate_validation_branch(header_id) {
            Ok(invalidated) => {
                let invalid_ids: std::collections::HashSet<[u8; 32]> =
                    invalidated.iter().copied().collect();
                // Evict the dead branch from the download queue so the
                // coordinator stops targeting it.
                coordinator
                    .sync_state_mut()
                    .retain_pending_blocks(|b| !invalid_ids.contains(&b.header_id));
                let cs = store.chain_state_meta();
                // Drop stale header_index entries above the re-anchored tip so
                // a later recover_coordinator can't re-seed the dead branch.
                self.header_index.retain(|&h, _| h <= cs.best_header_height);
                warn!(
                    height,
                    header_id = %hex::encode(header_id),
                    invalidated = invalidated.len(),
                    reanchored_best_header_height = cs.best_header_height,
                    "invalidated block and descendants; best_header re-anchored",
                );
            }
            Err(inv_err) => {
                // Persisting the invalidation itself failed (IO). Fall back to
                // a session mark so we at least stop re-applying this tick; the
                // durable walk retries next drain.
                warn!(
                    height,
                    error = %inv_err,
                    "branch invalidation failed; session-marking",
                );
                store.mark_session_invalid(header_id);
            }
        }
    }

    pub fn try_apply_next_blocks(
        &mut self,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        _now: Instant,
        wallet_wiring: Option<ergo_state::wallet::WalletWiring<'_>>,
    ) {
        // Mode 6 (headers-only) AND Mode 2 (mid-bootstrap)
        // defense-in-depth: even if a block section somehow landed
        // in the store (in-flight at restart, partial wipe, future
        // bug), refuse to apply. The suppression covers both
        // permanent headers-only and transient bootstrap-in-progress.
        if coordinator.should_skip_block_sections() {
            return;
        }
        let drain_start = Instant::now();
        let blocks_before = store.chain_state_meta().best_full_block_height;
        let mut hit_section_wait = false;
        let mut progressed = false;
        loop {
            match self.rollback_full_chain_to_best_header(store, coordinator, wallet_wiring) {
                Ok(ReorgOutcome::Performed) => {
                    progressed = true;
                    continue;
                }
                Ok(ReorgOutcome::NotNeeded) => {}
                // Terminal wedge: the rate-limited `full_chain_fork_too_deep`
                // warn already explains the stall — bail before the selection
                // below re-derives it as a per-tick parent-mismatch warn.
                Ok(ReorgOutcome::TooDeep) => break,
                Err(e) => {
                    warn!(error = %e, "full-block reorg failed");
                    break;
                }
            }

            let next = store.chain_state_meta().best_full_block_height + 1;

            let header_id = match self.best_chain_header_id_at(store, next) {
                Ok(Some(id)) => id,
                Ok(None) => break,
                Err(e) => {
                    warn!(height = next, error = %e, "best-chain lookup failed");
                    break;
                }
            };

            // Refuse to (re-)apply a block already reported invalid. After a
            // validation-verdict rejection the failing header (and every
            // descendant) is durably flagged and best_header re-anchored below
            // it, but its id may still sit in the stale canonical height index
            // above the re-anchor. Without this guard the loop would re-select
            // and re-reject the same block every tick — and re-wedge after a
            // restart. Scala refuses re-application via the `validityKey -> 0`
            // row (`ErgoHistoryReader.isSemanticallyValid`).
            match HeaderSectionStore::is_invalid(store, &header_id) {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => {
                    warn!(height = next, error = %e, "invalidity lookup failed");
                    break;
                }
            }

            let parent_id = match store.get_header_meta(&header_id) {
                Ok(Some(meta)) => meta.parent_id,
                Ok(None) => break,
                Err(e) => {
                    warn!(
                        header_id = %hex::encode(header_id),
                        error = %e,
                        "failed to load header metadata",
                    );
                    break;
                }
            };
            if parent_id != store.chain_state_meta().best_full_block_id {
                match self.rollback_full_chain_to_best_header(store, coordinator, wallet_wiring) {
                    Ok(ReorgOutcome::Performed) => {
                        progressed = true;
                        continue;
                    }
                    Ok(ReorgOutcome::NotNeeded) => {
                        warn!(
                            height = next,
                            parent_id = %hex::encode(parent_id),
                            best_full = %hex::encode(store.chain_state_meta().best_full_block_id),
                            "cannot apply block: parent is not best_full",
                        );
                        break;
                    }
                    // Terminal wedge: explained by the rate-limited
                    // `full_chain_fork_too_deep` warn, not a per-tick line.
                    Ok(ReorgOutcome::TooDeep) => break,
                    Err(e) => {
                        warn!(error = %e, "full-block reorg failed");
                        break;
                    }
                }
            }

            let cache = if self.block_context_headers.is_empty() {
                None
            } else {
                Some(self.block_context_headers.as_slice())
            };
            let guard = self.apply_phase.begin();
            let apply_result = block_proc::process_block(
                store,
                &header_id,
                &self.params,
                cache,
                self.script_validation_checkpoint,
                self.reemission.as_ref(),
                Some(&self.block_perf),
                wallet_wiring.map(|w| w.hook),
            );
            match apply_result {
                Ok(processed) => {
                    guard.success(processed.height);
                    self.update_block_context_cache(&processed);
                    coordinator.on_block_applied(processed.header_id, processed.height);
                    progressed = true;
                    if processed.height % 100 == 0 {
                        info!(height = processed.height, "block applied");
                    }
                }
                Err(
                    block_proc::BlockProcessError::SectionNotFound { .. }
                    // Digest data-availability: ADProofs not stored yet.
                    // Same wait-for-section semantics; never poison.
                    | block_proc::BlockProcessError::AdProofsUnavailable { .. },
                ) => {
                    guard.failure();
                    hit_section_wait = true;
                    break;
                }
                Err(
                    block_proc::BlockProcessError::ParentNotBestFull { .. }
                    // Digest fork / out-of-order: not invalid — reorg.
                    | block_proc::BlockProcessError::DigestNonLinearParent { .. }
                    | block_proc::BlockProcessError::DigestOutOfOrder { .. },
                ) => {
                    guard.failure();
                    match self.rollback_full_chain_to_best_header(store, coordinator, wallet_wiring) {
                        Ok(ReorgOutcome::Performed) => {
                            progressed = true;
                            continue;
                        }
                        Ok(ReorgOutcome::NotNeeded | ReorgOutcome::TooDeep) => break,
                        Err(e) => {
                            warn!(error = %e, "full-block reorg failed");
                            break;
                        }
                    }
                }
                Err(e) => {
                    guard.failure();
                    warn!(height = next, error = %e, "block apply failed");
                    self.record_block_apply_error(header_id, next, e.to_string());
                    self.invalidate_or_session_mark(store, coordinator, header_id, next, &e);
                    break;
                }
            }
        }

        // After applying blocks or rolling back across a fork, register the
        // download window from the authoritative best-header chain.
        if progressed {
            self.register_download_window(store, coordinator);
        }

        let blocks_after = store.chain_state_meta().best_full_block_height;
        let blocks_applied = blocks_after.saturating_sub(blocks_before) as u64;
        self.block_perf.add_drain(
            drain_start.elapsed().as_nanos() as u64,
            blocks_applied,
            hit_section_wait,
        );
    }

    pub(super) fn best_chain_header_id_at(
        &mut self,
        store: &ergo_state::StateBackendKind,
        height: u32,
    ) -> StorageResult<Option<[u8; 32]>> {
        let id = store.get_header_id_at_height(height)?;
        if let Some(id) = id {
            self.header_index.insert(height, id);
        }
        Ok(id)
    }

    fn register_download_window(
        &mut self,
        store: &ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
    ) {
        let cs = store.chain_state_meta();
        let base = cs.best_full_block_height + 1;
        // Inclusive upper bound spans at most `download_window` blocks from
        // `base` (heights base..=best_full+window), matching
        // on_header_validated's request gate `height <= best_full + window`.
        // A zero window yields an empty range (base > upper) so nothing is
        // registered, mirroring recover_coordinator. Capped at the best
        // header height so we never register beyond the header chain.
        let window = coordinator.sync_state().download_window() as u32;
        let upper = cs
            .best_full_block_height
            .saturating_add(window)
            .min(cs.best_header_height);
        for h in base..=upper {
            let hid = match store.get_header_id_at_height(h) {
                Ok(Some(id)) => id,
                Ok(None) => continue,
                Err(e) => {
                    warn!(height = h, error = %e, "best-chain lookup failed");
                    continue;
                }
            };
            self.header_index.insert(h, hid);
            coordinator.sync_state_mut().add_pending_block(h, hid);
            // Register with assembly tracker so request_missing_sections
            // knows which section IDs to request.
            if let Ok(Some(header_bytes)) = store.get_header(&hid) {
                let mut r = ergo_primitives::reader::VlqReader::new(&header_bytes);
                if let Ok(header) = ergo_ser::header::read_header(&mut r) {
                    let expected = ExpectedSections::from_header(
                        &hid,
                        header.transactions_root.as_bytes(),
                        header.extension_root.as_bytes(),
                        header.ad_proofs_root.as_bytes(),
                    );
                    coordinator.assembly_mut().register_header(expected);
                }
            }
        }
    }

    pub(super) fn rollback_full_chain_to_best_header(
        &mut self,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        wallet_wiring: Option<ergo_state::wallet::WalletWiring<'_>>,
    ) -> StorageResult<ReorgOutcome> {
        let (fork_height, fork_id) = match self.full_chain_fork_point(store)? {
            ForkPoint::Found(h, id) => (h, id),
            ForkPoint::NotForked => {
                self.clear_deep_fork_wedge();
                return Ok(ReorgOutcome::NotNeeded);
            }
            ForkPoint::TooDeep {
                scanned_to,
                max_depth,
            } => {
                // Terminal: the undo log below the fork is pruned, so this
                // reorg can never succeed — record the wedge and warn
                // (rate-limited) so the stall is explained, not just visible.
                self.note_deep_fork_wedge(store, scanned_to, max_depth);
                return Ok(ReorgOutcome::TooDeep);
            }
        };
        // A reachable fork point means the wedge condition no longer holds —
        // clear it HERE, not only after a successful rollback, so a prior
        // TooDeep wedge can't persist through a transient `rollback_to`
        // failure below (the Err return would otherwise keep /health wedged
        // while the chain is in fact recoverable again).
        self.clear_deep_fork_wedge();
        // Capture identity fields before any mutation so the `_failed`
        // event below carries pre-attempt values, not rebuilt-state
        // values. `fork_id` is the common-ancestor header at
        // `fork_height`, not the new tip.
        let old_height = store.chain_state_meta().best_full_block_height;
        let old_id = store.chain_state_meta().best_full_block_id;
        if fork_height == old_height {
            return Ok(ReorgOutcome::NotNeeded);
        }
        let depth = old_height.saturating_sub(fork_height);
        let old_id_hex = hex::encode(old_id);
        let fork_id_hex = hex::encode(fork_id);

        info!(
            event = "full_block_reorg_started",
            old_height,
            old_id = %old_id_hex,
            fork_height,
            fork_id = %fork_id_hex,
            depth,
            "full-block reorg: rolling back",
        );
        // Reorg success here means rollback + rebuild + coordinator
        // update + prune + window refresh all complete; emitting
        // `_completed` immediately after `store.rollback_to` would lie
        // about the operation. Failures of `store.rollback_to` itself
        // are already double-tracked by the state-layer
        // `state_rollback_failed` event but reporting them here too
        // gives operators the reorg-level context (old_id, fork_id,
        // depth) the state event doesn't carry.
        // M5 atomic rollback: wallet hook + rescan guard threaded
        // from the node level so wallet tables roll back inside the
        // same redb write_txn as chain state. Without this, a reorg
        // would leave wallet state on the abandoned branch — the
        // pre-M5 gap that the rescan-on-restart path covered. The
        // hook is `None` for tests and library callers that don't
        // manage wallet state; the rescan guard is `None` whenever
        // there's no rescan-in-progress to abort.
        let wallet_hook_arg = wallet_wiring.map(|w| w.hook);
        let rescan_guard_arg = wallet_wiring.map(|w| w.rescan_guard);
        if let Err(e) = store.rollback_to(fork_height, wallet_hook_arg, rescan_guard_arg) {
            warn!(
                event = "full_block_reorg_failed",
                old_height,
                old_id = %old_id_hex,
                fork_height,
                fork_id = %fork_id_hex,
                depth,
                phase = "rollback_to",
                error = %e,
                "full-block reorg failed",
            );
            return Err(e);
        }
        // Persistent header table is the source of truth for the rebuilt
        // cache after rollback. If hydration trips on integrity failure
        // here, we cannot proceed: the same corrupt row will fail any
        // subsequent block-validation read. Panic with the structured
        // error so the operator sees the affected id.
        self.rebuild_block_context(store).expect(
            "rebuild_block_context after rollback: persistent header table integrity failure",
        );
        coordinator.on_block_applied(fork_id, fork_height);
        coordinator.prune_pending_to_best_chain(store);
        self.register_download_window(store, coordinator);
        info!(
            event = "full_block_reorg_completed",
            old_height,
            old_id = %old_id_hex,
            fork_height,
            fork_id = %fork_id_hex,
            depth,
            "full-block reorg completed",
        );
        Ok(ReorgOutcome::Performed)
    }

    pub(super) fn full_chain_fork_point(
        &self,
        store: &ergo_state::StateBackendKind,
    ) -> StorageResult<ForkPoint> {
        let cs = store.chain_state_meta();
        let original_height = cs.best_full_block_height;
        if original_height == 0 {
            return Ok(ForkPoint::NotForked);
        }

        // RD-02 — the deepest reorg the active backend can serve. The UTXO
        // store prunes its undo log past ROLLBACK_WINDOW; the digest store
        // retains full history (unbounded → `None`), so a digest node must
        // still be allowed to follow a legitimately deep better branch.
        let max_rollback_depth = store.max_rollback_depth();

        let mut height = original_height;
        let mut full_id = cs.best_full_block_id;
        loop {
            // Never propose a fork point the state layer cannot roll back to.
            // Beyond the backend's rollback depth the resulting `target_height`
            // would make `rollback_to` doomed (`StateError::ReorgTooDeep`), so
            // stop the descent and decline the reorg (`TooDeep`) instead of
            // walking to genesis and handing the executor an unrollbackable
            // target it would re-attempt — and re-fail — every tick. Scala
            // parity: `FullBlockProcessor` never caches a non-best block deeper
            // than `keepVersions = 200`, so it never attempts such a reorg. A
            // UTXO node this far behind must resync (snapshot / NiPoPoW), which
            // it cannot do by rolling its pruned undo log back. The caller
            // records the wedge and owns the operator-facing warn
            // (`note_deep_fork_wedge`); this `&self` walk stays silent.
            if let Some(max_depth) = max_rollback_depth {
                if original_height - height > max_depth {
                    return Ok(ForkPoint::TooDeep {
                        scanned_to: height,
                        max_depth,
                    });
                }
            }
            if height == 0 {
                return Ok(ForkPoint::Found(0, [0u8; 32]));
            }

            match store.get_header_id_at_height(height)? {
                Some(best_id) if best_id == full_id => {
                    if height == original_height {
                        return Ok(ForkPoint::NotForked);
                    }
                    return Ok(ForkPoint::Found(height, full_id));
                }
                Some(_) => {}
                None => return Ok(ForkPoint::NotForked),
            }

            let meta = store.get_header_meta(&full_id)?.ok_or_else(|| {
                ergo_state::store::StateError::Serialization(format!(
                    "missing header_meta for full-chain block {} at height {}",
                    hex::encode(full_id),
                    height
                ))
            })?;
            full_id = meta.parent_id;
            height -= 1;
        }
    }
}

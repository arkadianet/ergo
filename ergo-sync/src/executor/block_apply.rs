//! Block assemble/persist action handlers for [`SyncExecutor`].
//!
//! `handle_assemble_block` applies one block via
//! [`crate::block_proc::process_block`] — the same pattern as the
//! sequential drain in [`super::reorg`]'s
//! [`SyncExecutor::try_apply_next_blocks`]; review them side by side.
//! `handle_persist_section` stores a delivered block section with the
//! Mode 3 receive-side prune gating.

use std::time::Instant;

use ergo_state::{ChainStateRead, HeaderSectionStore};
use tracing::{debug, info, warn};

use crate::block_proc::{self, BlockProcessError};
use crate::coordinator::{Action, SyncCoordinator};

use super::{ReorgOutcome, SyncExecutor};

impl SyncExecutor {
    pub(super) fn handle_assemble_block(
        &mut self,
        header_id: &[u8; 32],
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        wallet_wiring: Option<ergo_state::wallet::WalletWiring<'_>>,
    ) -> Vec<Action> {
        match self.rollback_full_chain_to_best_header(store, coordinator, wallet_wiring) {
            Ok(ReorgOutcome::Performed) => {
                self.try_apply_next_blocks(store, coordinator, Instant::now(), wallet_wiring);
                return Vec::new();
            }
            Ok(ReorgOutcome::NotNeeded) => {}
            // Wedged: nothing at or above the stuck tip can assemble/apply.
            Ok(ReorgOutcome::TooDeep) => return Vec::new(),
            Err(e) => {
                warn!(error = %e, "full-block reorg check failed");
                return Vec::new();
            }
        }

        // Only assemble the next sequential block.
        let next_height = store.chain_state_meta().best_full_block_height + 1;
        match self.best_chain_header_id_at(store, next_height) {
            Ok(Some(best_id)) if best_id == *header_id => {}
            Ok(Some(_)) | Ok(None) => return Vec::new(),
            Err(e) => {
                warn!(height = next_height, error = %e, "best-chain lookup failed");
                return Vec::new();
            }
        }
        let meta = match store.get_header_meta(header_id) {
            Ok(Some(m)) => m,
            _ => return Vec::new(),
        };
        if meta.height != next_height {
            return Vec::new();
        }

        let cache = if self.block_context_headers.is_empty() {
            None
        } else {
            Some(self.block_context_headers.as_slice())
        };
        let guard = self.apply_phase.begin();
        match block_proc::process_block(
            store,
            header_id,
            &self.params,
            cache,
            self.script_validation_checkpoint,
            self.reemission.as_ref(),
            Some(&self.block_perf),
            wallet_wiring.map(|w| w.hook),
        ) {
            Ok(processed) => {
                guard.success(processed.height);
                self.update_block_context_cache(&processed);
                coordinator.on_block_applied(processed.header_id, processed.height);
                if processed.height % 100 == 0 {
                    info!(height = processed.height, "block applied");
                }
                // Chain: apply as many consecutive blocks as possible.
                // Don't wait for the next sync tick.
                self.try_apply_next_blocks(store, coordinator, Instant::now(), wallet_wiring);
                Vec::new()
            }
            Err(
                BlockProcessError::HeaderNotFound { .. }
                | BlockProcessError::SectionNotFound { .. }
                | BlockProcessError::ParentNotFound { .. }
                // Digest data-availability: the ADProofs section has not
                // arrived yet. Same "wait for the section" semantics as
                // SectionNotFound — NOT block invalidity, never poison.
                | BlockProcessError::AdProofsUnavailable { .. },
            ) => {
                guard.failure();
                Vec::new()
            }
            Err(
                BlockProcessError::ParentNotBestFull { .. }
                // Digest fork / out-of-order: the block's parent is not
                // the committed tip, or its height is not tip+1. Not
                // invalid — drive the same reorg path as the UTXO arm.
                | BlockProcessError::DigestNonLinearParent { .. }
                | BlockProcessError::DigestOutOfOrder { .. },
            ) => {
                guard.failure();
                match self.rollback_full_chain_to_best_header(store, coordinator, wallet_wiring) {
                    Ok(ReorgOutcome::Performed) => {
                        self.try_apply_next_blocks(store, coordinator, Instant::now(), wallet_wiring);
                    }
                    Ok(ReorgOutcome::NotNeeded | ReorgOutcome::TooDeep) => {}
                    Err(e) => warn!(error = %e, "full-block reorg failed"),
                }
                Vec::new()
            }
            Err(e) => {
                guard.failure();
                warn!(
                    block_id = %hex::encode(header_id),
                    error = %e,
                    "block validation failed",
                );
                self.record_block_apply_error(*header_id, meta.height, e.to_string());
                // Same classifier as try_apply_next_blocks: a definitive
                // validation verdict durably invalidates the block + its
                // descendants and re-anchors best_header across restart, so an
                // invalid block isn't retried every tick; anything else stays a
                // session-only mark.
                self.invalidate_or_session_mark(store, coordinator, *header_id, meta.height, &e);
                Vec::new()
            }
        }
    }

    pub(super) fn handle_persist_section(
        &self,
        modifier_id: &[u8; 32],
        section_bytes: &[u8],
        section_type: u8,
        store: &mut ergo_state::StateBackendKind,
    ) -> Vec<Action> {
        // Mode 3 Phase 3a — receive-side gating. Silently drop
        // sections whose parent header is below our prune
        // sentinel. The peer is NOT penalized: timing-racy late
        // deliveries are normal during sync, and a misbehavior
        // signal here would over-punish honest peers that just
        // queued the section before our pruning frontier caught
        // up. Mirrors Scala's
        // `ErgoNodeViewSynchronizer.processModifierFromPeer`
        // silent-drop behavior. The storage-side guard in
        // `store_block_section_typed` is defense-in-depth for
        // executors that bypass this check.
        //
        // Gate fires on `sentinel > 1` — covers Mode 2 / NiPoPoW
        // bootstrapped nodes too, not just pruned mode. A fresh
        // archive-from-genesis store reads sentinel = 1 (default)
        // and the gate is inert.
        //
        // Fail-CLOSED on missing height lookups when the gate is
        // active: the boot backfill gate makes
        // SECTION_HEIGHT_INDEX complete by the time `sentinel >
        // 1`, so `Ok(None)` means "section ID we never indexed"
        // = orphan / attacker delivery and we drop it. Without
        // this, a peer pushing arbitrary section IDs could
        // resurrect storage outside the height-based model.
        let sentinel = match store.read_minimal_full_block_height() {
            Ok(s) => s,
            Err(e) => {
                // Fail-closed on unreadable sentinel; warn so
                // operators see the partial-DB-failure
                // degradation rather than a silent drop.
                warn!(
                    modifier_id = %hex::encode(modifier_id),
                    error = %e,
                    "Mode 3: sentinel read failed — dropping section delivery",
                );
                return Vec::new();
            }
        };
        if sentinel > 1 {
            match HeaderSectionStore::get_section_height(store, modifier_id) {
                Ok(Some(height)) if height < sentinel => {
                    debug!(
                        modifier_id = %hex::encode(modifier_id),
                        height,
                        sentinel,
                        "Mode 3: dropping sub-sentinel section delivery",
                    );
                    return Vec::new();
                }
                Ok(Some(_)) => {} // height >= sentinel: accept
                Ok(None) | Err(_) => {
                    // Fail-closed: unindexed section in a
                    // sentinel-active store is either orphan or
                    // attacker. Drop silently (no peer penalty —
                    // honest peers don't know our index state).
                    debug!(
                        modifier_id = %hex::encode(modifier_id),
                        sentinel,
                        "Mode 3: dropping unindexed section delivery (fail-closed)",
                    );
                    return Vec::new();
                }
            }
        }
        if let Err(e) = store.store_block_section_typed(modifier_id, section_bytes, section_type) {
            warn!(
                modifier_id = %hex::encode(modifier_id),
                error = %e,
                "failed to persist section",
            );
        }
        Vec::new()
    }
}

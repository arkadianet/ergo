//! Block assemble/persist action handlers for [`SyncExecutor`].
//!
//! `handle_assemble_block` drives [`SyncExecutor::try_apply_next_blocks`]
//! so arrival-driven and periodic application share full-chain selection.
//! `handle_persist_section` stores a delivered block section with the
//! Mode 3 receive-side prune gating.

use std::time::Instant;

use ergo_state::{ChainStateRead, HeaderSectionStore};
use tracing::{debug, warn};

use crate::block_proc::BlockProcessError;
use crate::coordinator::{Action, SyncCoordinator};

use super::SyncExecutor;

fn report_section_storage_failure(
    store: &ergo_state::StateBackendKind,
    operation: &'static str,
    error: &ergo_state::store::StateError,
) {
    super::report_sync_storage_failure(store, "section_persistence", operation, error);
}

pub(super) fn report_block_process_failure(
    store: &ergo_state::StateBackendKind,
    block_id: &[u8; 32],
    error: &BlockProcessError,
) {
    if let BlockProcessError::State(state_error) = error {
        super::report_sync_storage_failure(
            store,
            "block_validation",
            "validate_and_persist_block",
            state_error,
        );
        return;
    }

    let chain = store.chain_state_meta();
    let diagnostics = ergo_state::storage_observability::ErrorDiagnostics::from_error(error);
    warn!(
        event = "sync_block_validation_failed",
        subsystem = "sync",
        component = "block_validation",
        operation = "validate_block",
        block_id = %hex::encode(block_id),
        error = %diagnostics.display,
        error_debug = %diagnostics.debug,
        error_chain = %diagnostics.chain,
        best_full_block_height = chain.best_full_block_height,
        best_header_height = chain.best_header_height,
        "block validation failed",
    );
}

impl SyncExecutor {
    /// Drain transaction IDs named by block validation, for local and remote blocks.
    pub fn take_failed_transactions(&mut self) -> Vec<[u8; 32]> {
        std::mem::take(&mut self.failed_transactions)
    }

    pub(super) fn record_failed_transaction(&mut self, error: &BlockProcessError) {
        if let BlockProcessError::TransactionValidation { tx_id, .. } = error {
            self.failed_transactions.push(*tx_id);
        }
    }

    #[tracing::instrument(skip_all, fields(block = %hex::encode(header_id)))]
    pub(super) fn handle_assemble_block(
        &mut self,
        header_id: &[u8; 32],
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        wallet_wiring: Option<ergo_state::wallet::WalletWiring<'_>>,
    ) -> Vec<Action> {
        match store.get_header_meta(header_id) {
            Ok(Some(meta)) => match store.get_header_id_at_height(meta.height) {
                Ok(Some(id)) if id == *header_id => {}
                Ok(_) => self.full_candidate_height = Some(meta.height),
                Err(error) => {
                    super::report_sync_storage_failure(
                        store,
                        "block_apply",
                        "assembled_chain_lookup",
                        &error,
                    );
                    return Vec::new();
                }
            },
            Ok(None) => return Vec::new(),
            Err(error) => {
                super::report_sync_storage_failure(
                    store,
                    "block_apply",
                    "assembled_header_lookup",
                    &error,
                );
                return Vec::new();
            }
        }
        self.try_apply_next_blocks(store, coordinator, Instant::now(), wallet_wiring);
        Vec::new()
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
                report_section_storage_failure(store, "sync_read_prune_sentinel", &e);
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
                Ok(None) => {
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
                Err(e) => {
                    report_section_storage_failure(store, "sync_read_section_height", &e);
                    return Vec::new();
                }
            }
        }
        if let Err(e) = store.store_block_section_typed(modifier_id, section_bytes, section_type) {
            report_section_storage_failure(store, "sync_store_block_section", &e);
        }
        Vec::new()
    }
}

//! Startup hydration and recovery for [`SyncExecutor`].
//!
//! Rebuilds the executor's in-memory caches from the persisted store on
//! node startup (and after snapshot install): the recent-header window,
//! the block-context header cache, the height→header_id index, and the
//! coordinator's pending-block queue.

use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_validation::header::CheckedHeader;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::coordinator::SyncCoordinator;

use super::{SyncExecutor, LAST_HEADERS_WINDOW};

/// Errors returned during startup while hydrating executor state from the
/// persisted store. A variant here means the node must abort startup — the
/// operator needs to see the specific cause.
#[derive(Debug, Error)]
pub enum StartupError {
    #[error("storage error during startup: {0}")]
    Storage(#[from] ergo_state::store::StateError),
    #[error(
        "HEADER_CHAIN_INDEX coverage gap: expected {expected} entries in \
         [{lo},{hi}] but got {got}. Database is inconsistent. To repair: \
         open the redb database and delete BOTH the `header_chain_index` \
         table AND the `hci_version` key from `state_meta`, then restart \
         the node — backfill will rebuild the index on the next open. \
         (Deleting only the table leaves hci_version=1, which makes \
         backfill skip and the gap persists.)"
    )]
    IndexGap {
        lo: u32,
        hi: u32,
        expected: usize,
        got: usize,
    },
    /// Defense-in-depth: triggers only if `scan_header_chain_range` ever regresses
    /// to return entries outside `[lo, hi]` or out of ascending-height order.
    /// Normal paths should hit `IndexGap` first.
    #[error(
        "HEADER_CHAIN_INDEX boundary mismatch: lo={lo} got_first_height={first:?}, \
         hi={hi} got_last_height={last:?}"
    )]
    IndexBoundaryMismatch {
        lo: u32,
        hi: u32,
        first: Option<u32>,
        last: Option<u32>,
    },
}

/// Failures from rebuilding the in-memory header caches (`last_headers`,
/// `block_context_headers`) from persisted store. A variant here means
/// the persistent header table is corrupt or unreadable; downstream
/// validation cannot recover by retrying the same row, so the node must
/// abort and let the operator decide whether to re-fetch the affected
/// header from peers.
#[derive(Debug, Error)]
pub enum HydrationError {
    #[error("hydration store error: {0}")]
    Store(#[from] ergo_state::store::StateError),
    #[error("hydration {phase}: persisted-header integrity failure at id={id}: {source}")]
    HeaderIntegrity {
        phase: &'static str,
        id: String,
        source: ergo_validation::header::HeaderValidationError,
    },
    /// A non-genesis ancestor id resolved through chain-state walking is
    /// expected to be present in the header table — chain_state pointing
    /// at a row that doesn't exist (or whose meta row is missing) is a
    /// mid-chain hole, not a legitimate chain-end termination.
    #[error(
        "hydration {phase}: persisted-{kind} row missing for id={id} (chain-state inconsistency)"
    )]
    MissingPersistedRow {
        phase: &'static str,
        kind: &'static str,
        id: String,
    },
}

impl SyncExecutor {
    /// Hydrate the recent-header window from persisted chain state.
    /// Must be called on startup/resume so that block validation has
    /// the correct CONTEXT.headers even after a restart.
    ///
    /// Walks backwards from best_header (not best_full_block) through
    /// parent_ids, loading up to LAST_HEADERS_WINDOW headers. Uses the
    /// header chain tip because CONTEXT.headers reflects the header chain,
    /// and during header-first sync the header tip is ahead of the full
    /// block tip.
    ///
    /// Reaching the end of the chain (`current_id == [0; 32]`, store
    /// returns `Ok(None)`) is a successful termination — the cache may
    /// be shorter than `LAST_HEADERS_WINDOW` early in the chain. Any
    /// other error (store I/O, header reconstruction integrity) is
    /// fatal: the persistent header table is the source of truth for
    /// `CheckedHeader.header_id` after restart, and silent truncation
    /// would mask DB corruption that downstream validation also can't
    /// recover from.
    pub fn hydrate_from_store(
        &mut self,
        store: &ergo_state::StateBackendKind,
    ) -> Result<(), HydrationError> {
        self.last_headers.clear();
        let mut current_id = store.chain_state_meta().best_header_id;
        for _ in 0..LAST_HEADERS_WINDOW {
            if current_id == [0u8; 32] {
                break;
            }
            let header_bytes = store.get_header(&current_id)?.ok_or_else(|| {
                HydrationError::MissingPersistedRow {
                    phase: "hydrate_from_store",
                    kind: "header",
                    id: hex::encode(current_id),
                }
            })?;
            let meta = store.get_header_meta(&current_id)?.ok_or_else(|| {
                HydrationError::MissingPersistedRow {
                    phase: "hydrate_from_store",
                    kind: "header_meta",
                    id: hex::encode(current_id),
                }
            })?;
            let checked = CheckedHeader::from_persisted_parts(
                &header_bytes,
                current_id,
                meta.pow_validity,
                meta.height,
                meta.parent_id,
                meta.timestamp,
            )
            .map_err(|e| HydrationError::HeaderIntegrity {
                phase: "hydrate_from_store",
                id: hex::encode(current_id),
                source: e,
            })?;
            let parent_id = *checked.header().parent_id.as_bytes();
            self.last_headers.push_back((checked, header_bytes));
            current_id = parent_id;
        }
        Ok(())
    }

    /// Hydrate the block-context header cache from best_full_block.
    /// Loads up to 10 headers backward for CONTEXT.headers in script eval.
    /// Called on startup and after rollback/reorg.
    ///
    /// Same fail-fast contract as [`Self::hydrate_from_store`]: legitimate
    /// chain-end termination returns `Ok(())`; integrity / I/O failures
    /// surface as `HydrationError`.
    pub fn hydrate_block_context(
        &mut self,
        store: &ergo_state::StateBackendKind,
    ) -> Result<(), HydrationError> {
        self.block_context_headers.clear();
        let best_id = store.chain_state_meta().best_full_block_id;
        if best_id == [0u8; 32] {
            return Ok(()); // no blocks applied yet
        }
        let mut current_id = best_id;
        for _ in 0..10 {
            let header_bytes = store.get_header(&current_id)?.ok_or_else(|| {
                HydrationError::MissingPersistedRow {
                    phase: "hydrate_block_context",
                    kind: "header",
                    id: hex::encode(current_id),
                }
            })?;
            let meta = store.get_header_meta(&current_id)?.ok_or_else(|| {
                HydrationError::MissingPersistedRow {
                    phase: "hydrate_block_context",
                    kind: "header_meta",
                    id: hex::encode(current_id),
                }
            })?;
            let checked = CheckedHeader::from_persisted_parts(
                &header_bytes,
                current_id,
                meta.pow_validity,
                meta.height,
                meta.parent_id,
                meta.timestamp,
            )
            .map_err(|e| HydrationError::HeaderIntegrity {
                phase: "hydrate_block_context",
                id: hex::encode(current_id),
                source: e,
            })?;
            let parent_id = *checked.header().parent_id.as_bytes();
            self.block_context_headers.push(checked);
            if parent_id == [0u8; 32] {
                break;
            }
            current_id = parent_id;
        }
        Ok(())
    }

    /// Rebuild the block-context cache from store. Called after rollback.
    /// Propagates `HydrationError` — a hydration failure during rollback
    /// recovery means the persistent header table is corrupt; the caller
    /// (typically the rollback orchestrator) must surface this rather
    /// than silently degrade the cache.
    pub fn rebuild_block_context(
        &mut self,
        store: &ergo_state::StateBackendKind,
    ) -> Result<(), HydrationError> {
        self.hydrate_block_context(store)
    }

    /// Load the in-memory height→header_id index from the persisted
    /// HEADER_CHAIN_INDEX table for the unapplied-header gap
    /// (best_full_block_height+1 ..= best_header_height).
    ///
    /// In `HeaderAvailability::Dense` mode (the default for a node
    /// that has not been NiPoPoW-bootstrapped) the load is strict:
    /// returns an error if the persisted index does not cover the
    /// full `[lo, hi]` range contiguously. A gap there indicates a
    /// bug or corruption.
    ///
    /// In `HeaderAvailability::PoPowSparse` mode (set by
    /// `apply_popow_proof` in sub-phase 14.5) the load scans only
    /// the dense suffix range `[max(best_full+1, dense_from_height),
    /// best_header_height]`. Heights below `dense_from_height` are
    /// known to be absent by construction — the executor's
    /// `header_index` cache reflects only what's locally indexed.
    /// Downstream consumers must consult `StateStore::lookup_header_at_height`
    /// (rather than the in-memory cache) to learn about
    /// `HeightLookup::SparseGap` cases for heights below the dense
    /// floor.
    ///
    /// The sparse-aware `lo` floor is load-bearing for crash
    /// recovery: without it, a crash between `apply_popow_proof`
    /// commit and snapshot install would brick startup, because the
    /// strict-mode scan fails on the sparse prefix.
    pub fn load_header_index(
        &mut self,
        store: &ergo_state::StateBackendKind,
    ) -> Result<(), StartupError> {
        use ergo_state::chain::HeaderAvailability;

        self.header_index.clear();
        let cs = store.chain_state_meta();
        if cs.best_header_height <= cs.best_full_block_height {
            return Ok(());
        }
        let nominal_lo = cs.best_full_block_height + 1;
        let hi = cs.best_header_height;
        let (lo, sparse_mode) = match cs.header_availability {
            HeaderAvailability::Dense => (nominal_lo, false),
            HeaderAvailability::PoPowSparse {
                dense_from_height, ..
            } => (nominal_lo.max(dense_from_height), true),
        };
        if lo > hi {
            // Sparse mode with dense_from_height > best_header_height:
            // nothing to load. The proof apply path enforces
            // dense_from_height ≤ best_header_height, so this is
            // defensive only.
            return Ok(());
        }

        let t0 = std::time::Instant::now();
        let entries = store.scan_header_chain_range(lo, hi)?;
        let expected = (hi - lo + 1) as usize;
        if entries.len() != expected {
            return Err(StartupError::IndexGap {
                lo,
                hi,
                expected,
                got: entries.len(),
            });
        }
        let first = entries.first().map(|(h, _)| *h);
        let last = entries.last().map(|(h, _)| *h);
        if first != Some(lo) || last != Some(hi) {
            return Err(StartupError::IndexBoundaryMismatch {
                lo,
                hi,
                first,
                last,
            });
        }

        for (h, id) in entries {
            self.header_index.insert(h, id);
        }
        debug!(
            entries = self.header_index.len(),
            lo,
            hi,
            sparse_mode,
            elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0,
            "header index loaded",
        );
        Ok(())
    }

    /// Recover coordinator pending-block and assembly state from persisted chain.
    ///
    /// After restart, the coordinator is fresh. This rebuilds its knowledge
    /// of headers that were validated but not yet block-applied by walking
    /// from best_full_block+1 to best_header through the stored header chain.
    ///
    /// Only recovers if headers are near tip (headers_chain_synced will be
    /// detected). During initial header sync, recovery is skipped — headers
    /// need to catch up first, and walking 1M+ entries wastes minutes.
    ///
    /// Should be called after hydrate_from_store() and before processing
    /// new actions.
    pub fn recover_coordinator(
        &mut self,
        store: &ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
    ) -> Result<usize, HydrationError> {
        let cs = store.chain_state_meta();

        // Skip recovery if headers aren't synced — during initial header sync,
        // pending blocks aren't useful. The headers_chain_synced flag may have
        // been set by the caller (e.g., after detecting recent header timestamps).
        if !coordinator.sync_state().headers_chain_synced() {
            // Check if headers are near tip to auto-detect synced state
            if let Ok(Some(meta)) = store.get_header_meta(&cs.best_header_id) {
                coordinator
                    .sync_state_mut()
                    .check_headers_synced(meta.timestamp);
            }
            if !coordinator.sync_state().headers_chain_synced() {
                info!("skipping recovery — headers not near tip");
                return Ok(0);
            }
        }

        // Mode 6 (headers-only) AND Mode 2 (mid-bootstrap) defense-in-depth:
        // these modes must not download or assemble block sections, so register
        // no pending blocks for them — even when the edge-triggered latch
        // flipped on a fresh header (which bypasses on_header_validated's own
        // should_skip gate). Mirrors the apply-path guard in
        // `try_apply_next_blocks`. NB: this returns AFTER the header-synced
        // auto-detection above, on purpose — recovery may still OPEN the latch
        // from a fresh persisted tip (harmless while suppressed, since every
        // section path is guarded) so the pipeline starts promptly once
        // bootstrap clears, while we still register nothing here.
        if coordinator.should_skip_block_sections() {
            // Permanent headers-only (Mode 6) has nothing to recover, ever —
            // mark recovery done so sync_tick stops re-calling every tick (the
            // `headers_chain_synced && !recovery_done` gate) and the API stops
            // reporting recovery_done=false. Mid-bootstrap is TRANSIENT: the
            // install path calls `reset_recovery_done` when it clears, after
            // which a normal recovery seeds the post-snapshot blocks — so leave
            // its latch untouched here.
            if coordinator.is_headers_only() {
                self.recovery_done = true;
            }
            return Ok(0);
        }

        // Only recover blocks within the download window.
        let recovery_limit = cs
            .best_full_block_height
            .saturating_add(coordinator.sync_state().download_window() as u32);
        let effective_header_height = cs.best_header_height.min(recovery_limit);

        if effective_header_height <= cs.best_full_block_height {
            // Nothing to re-seed: every header within the window is already
            // block-applied. Latch recovery_done (as the walk-completed path
            // at the end does) so sync_tick's `headers_chain_synced &&
            // !recovery_done` gate stops re-calling every tick and the API
            // stops reporting recovery_done=false. Safe because headers are
            // synced here (gated above); any later header is seeded live via
            // on_header_validated, and the mid-bootstrap transient re-opens
            // this latch through reset_recovery_done.
            self.recovery_done = true;
            return Ok(0);
        }

        // Use the header_index to find the correct starting header_id.
        // We can't use best_header_id (at tip) because the walk is capped
        // and would end at the wrong heights.
        let start_id = match self.header_index.get(&effective_header_height) {
            Some(id) => *id,
            None => {
                warn!(
                    height = effective_header_height,
                    "recovery: height not in header_index"
                );
                return Ok(0);
            }
        };

        // Walk backwards from the start header to best_full_block+1, collecting
        // entries that need block application. Previously this was on the
        // coordinator behind a closure callback; moved here so ergo-p2p
        // stays free of a ergo-state dependency.
        //
        // Each walked row is reconstructed via
        // [`CheckedHeader::from_persisted_parts`] — the same trust boundary
        // hydrate_from_store / hydrate_block_context use. That re-derives
        // `header_id` from bytes (catching DB-key vs body drift), parses
        // with EOF enforcement (catching trailing-bytes corruption), and
        // verifies meta consistency (height, parent_id, timestamp). The
        // legitimate stop is `meta.height <= best_full_block_height` — a
        // height check, not an absent-row check.
        let mut headers_to_register = Vec::new();
        let mut current_id = start_id;
        for _ in 0..(effective_header_height - cs.best_full_block_height) {
            let meta = store.get_header_meta(&current_id)?.ok_or_else(|| {
                HydrationError::MissingPersistedRow {
                    phase: "recover_coordinator",
                    kind: "header_meta",
                    id: hex::encode(current_id),
                }
            })?;
            if meta.height <= cs.best_full_block_height {
                break;
            }
            let header_bytes = store.get_header(&current_id)?.ok_or_else(|| {
                HydrationError::MissingPersistedRow {
                    phase: "recover_coordinator",
                    kind: "header",
                    id: hex::encode(current_id),
                }
            })?;
            let parent_id = meta.parent_id;
            let checked = CheckedHeader::from_persisted_parts(
                &header_bytes,
                current_id,
                meta.pow_validity,
                meta.height,
                meta.parent_id,
                meta.timestamp,
            )
            .map_err(|e| HydrationError::HeaderIntegrity {
                phase: "recover_coordinator",
                id: hex::encode(current_id),
                source: e,
            })?;
            let header = checked.header();
            headers_to_register.push((
                current_id,
                meta.height,
                *header.transactions_root.as_bytes(),
                *header.extension_root.as_bytes(),
                *header.ad_proofs_root.as_bytes(),
            ));
            current_id = parent_id;
        }

        headers_to_register.reverse();
        let count = headers_to_register.len();
        for (header_id, height, tx_root, ext_root, proof_root) in headers_to_register {
            let expected =
                ExpectedSections::from_header(&header_id, &tx_root, &ext_root, &proof_root);
            coordinator.sync_state_mut().set_best_known_header(height);
            coordinator
                .sync_state_mut()
                .add_pending_block(height, header_id);
            coordinator.assembly_mut().register_header(expected);
        }
        // Reached here = the near-tip gate passed and the walk completed
        // (even if the walk was empty because header_height <= full_block_height).
        // Future sync ticks will skip re-recovery.
        self.recovery_done = true;
        Ok(count)
    }
}

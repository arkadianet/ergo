//! Sync executor: consumes coordinator Actions and drives the sync pipeline.
//!
//! This is the runtime glue that connects:
//! - SyncCoordinator (produces Actions)
//! - process_header() (validates + persists headers)
//! - process_block() (validates + applies blocks to UTXO state)
//! - PeerManager (penalties, peer state)
//!
//! The executor owns:
//! - ProtocolParams (mainnet defaults; epoch-boundary updates not yet implemented)
//! - Recent validated header window (last 10 CheckedHeaders for CONTEXT.headers)
//!   Must be hydrated from store on startup via hydrate_from_store().
//! - The feedback loop: action results → coordinator state updates

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use crate::coordinator::{Action, SyncCoordinator};
use ergo_crypto::difficulty::DifficultyParams;
use ergo_p2p::peer::PeerId;

use ergo_state::store::StateStore;
use ergo_validation::context::ProtocolParams;
use ergo_validation::header::CheckedHeader;
use ergo_validation::ReemissionRuleInputs;

use crate::block_proc::{self, BlockProcessError};
use crate::header_proc;
use crate::perf::{BlockPerfCounters, HeaderPerfCounters};

mod block_apply;
mod header_pipeline;
mod peer_requests;
mod reorg;
mod startup;

#[cfg(test)]
pub(crate) use header_pipeline::{ORPHAN_HEADER_IBD_LOOKAHEAD, ORPHAN_HEADER_LIMIT};
#[cfg(test)]
pub(crate) use reorg::ForkPoint;
pub(crate) use reorg::ReorgOutcome;
pub use reorg::{DeepForkWedge, LastBlockApplyError};
pub use startup::{HydrationError, StartupError};

type StorageResult<T> = Result<T, ergo_state::store::StateError>;

/// The header-validation pipeline (`header_proc::finalize_header` and
/// friends) is still typed against the concrete UTXO `StateStore`: it
/// performs no box-arena work, but threading the backend enum through
/// the whole header pipeline (and its `ergo-mining` / test callers) is a
/// separate slice. Until then, the executor reaches the UTXO header
/// tables here. The Mode 5 boot gate is REJECT, so a digest backend
/// never reaches this seam — the `expect` documents that invariant
/// rather than silently degrading.
fn utxo_header_store_mut(store: &mut ergo_state::StateBackendKind) -> &mut StateStore {
    store
        .as_utxo_mut()
        .expect("header pipeline is UTXO-typed; Mode 5 digest header sync is gated off")
}

/// Classify a full-block apply failure as a definitive VALIDATION verdict —
/// a block the Scala reference node also rejects and therefore can never
/// apply — versus a transient/IO/consistency failure that must NOT poison
/// the branch (it might be our bug, a stale local root, or missing data).
///
/// Only the three consensus-rule verdicts qualify. `Deserialize`,
/// `HeaderNotFound`, `ParentNotFound`, and `State` are data/IO/consistency
/// paths (a stored section that won't parse could be disk corruption, not a
/// bad block); `DigestApply` is session-scoped by its own contract. When in
/// doubt we do NOT invalidate — the conservative direction, since a wrongly
/// persisted invalidity would permanently orphan a valid chain, whereas a
/// missed one only leaves the (correct) session mark.
///
/// Scala mirror: `ErgoNodeViewHolder.applyState` reports invalid on ANY
/// `applyModifier` `Failure`; the Rust node is deliberately stricter about
/// which failures earn a *durable* flag, but the liveness effect
/// (re-anchor + refuse re-apply) is the same for the consensus-verdict case
/// that motivated it.
fn is_validation_verdict(e: &BlockProcessError) -> bool {
    matches!(
        e,
        BlockProcessError::Validation(_)
            | BlockProcessError::HeaderMeta(_)
            | BlockProcessError::EpochExtension(_)
    )
}

/// Maximum number of recent headers kept for CONTEXT.headers and SyncInfo cache.
/// Sized to cover SyncInfo V2's 50-header requirement plus script evaluation.
const LAST_HEADERS_WINDOW: usize = 50;

/// Sync-S2 low-watermark for drain-triggered download refill.
///
/// When total in-flight drops below this many IDs, the executor's
/// `pipeline_needs_refill` returns true and the node-level event loop
/// can re-run `request_missing_sections` without waiting for the next
/// sync tick. Picked conservatively at 64 IDs so the pipeline refills
/// before it goes fully empty but we don't fire on every delivery.
/// Kept as an internal constant; promote to a TOML knob when live-sync
/// evidence justifies operator tuning.
const DRAIN_WATERMARK: usize = 64;
/// If an in-window pending block's sections have been inflight this long,
/// early-reassign them to a capable peer instead of waiting for the full
/// `DELIVERY_TIMEOUT`. Fires on the first 1 s sync tick past the threshold,
/// so a "1.5 s" hedge actually lands ~2 s in — leaving real slack before the
/// 3 s `DELIVERY_TIMEOUT` for the hedge peer to win. Lower than the timeout
/// but not so low that healthy bodies (which arrive in well under 1.5 s) get
/// needlessly duplicated.
const HOL_HEDGE_THRESHOLD: std::time::Duration = std::time::Duration::from_millis(1500);
/// Re-warn interval for the terminal deep-fork wedge (see
/// [`SyncExecutor::note_deep_fork_wedge`]). Long enough not to flood a
/// tailed log, short enough that the explanation is always within the
/// last screenful of a stalled node's output.
const DEEP_FORK_REWARN: std::time::Duration = std::time::Duration::from_secs(600);

/// One queued orphan-header retry entry: (announcing peer, the
/// pre-validated header so retries skip Phase 1, raw header bytes
/// because `finalize_header` consumes the `PreValidatedHeader` and
/// storage needs the bytes).
type OrphanHeaderEntry = (PeerId, header_proc::PreValidatedHeader, Vec<u8>);

/// The sync executor. Owns the mutable state needed to drive the pipeline.
pub struct SyncExecutor {
    params: ProtocolParams,
    chain_config: DifficultyParams,
    /// Recent validated headers + raw bytes (newest first, max 50).
    /// Header-tip aligned. Used for SyncInfo V2 payload cache.
    last_headers: VecDeque<(CheckedHeader, Vec<u8>)>,
    /// Rolling block-context cache aligned to best_full_block (NOT header tip).
    /// Element 0 = best_full_block header (height H). When validating block H+1,
    /// CONTEXT.headers sees [H, H-1, ..., H-9]. Max 10 entries.
    /// Updated after each successful block apply. Rebuilt on rollback.
    block_context_headers: Vec<CheckedHeader>,
    /// Header IDs installed since the last `drain_orphans` call. Used by
    /// the orphan drain to filter the buffer down to "orphans whose parent
    /// MIGHT have just appeared" without doing a full per-orphan
    /// `store.get_header(parent_id)` redb read each pass. Cleared at the
    /// start of each drain. Bounded by the install rate × time-between-
    /// drains; since drain runs after every batch flush and every single-
    /// header success, this stays small (a few hundred entries typically).
    recently_installed: HashSet<[u8; 32]>,
    /// Headers whose parent isn't stored yet, INDEXED BY PARENT ID.
    ///
    /// Drain doesn't scan the whole buffer: it iterates only
    /// `recently_installed` and looks up the orphans waiting on each
    /// just-installed header in O(1). At Step C+D fanout (60 peers
    /// × 400 headers/anchor = 24k buffered after each round) a Vec
    /// scan would cost O(buffer_size × drains/sec) — the dominant
    /// CPU cost in the previous design.
    ///
    /// Each entry caches the `PreValidatedHeader` (PoW already done)
    /// so retries skip Phase 1 entirely. The raw `bytes` ride along
    /// because `finalize_header` consumes the `PreValidatedHeader`
    /// and storage needs the bytes.
    orphan_headers: HashMap<[u8; 32], Vec<OrphanHeaderEntry>>,
    /// Total entries across all `orphan_headers` values — kept in
    /// sync on insert/remove so `cap_orphan_buffer` and the
    /// `mem_csv` reporter don't have to recount on every read.
    orphan_headers_len: usize,
    /// In-memory height → header_id index. Spec budget: 64 MB (~1.3M headers × 36B).
    /// Populated during header validation, used for O(1) block application lookups.
    /// Eliminates the O(gap) backward walk through parent_id chains.
    header_index: BTreeMap<u32, [u8; 32]>,
    /// Set to true once recover_coordinator has successfully populated the
    /// pending-block queue (or confirmed there's nothing to recover).
    /// Startup call may bail with "headers not near tip" and return without
    /// seeding pending; the caller checks this flag on each sync tick and
    /// re-runs recovery the first time headers_chain_synced flips true,
    /// so a long header-sync gap doesn't strand pending forever empty.
    recovery_done: bool,
    /// Script-validation checkpoint, plumbed through to
    /// `validate_full_block_parallel` via `process_block`. See
    /// [`BlockValidationContext::script_validation_checkpoint`] for the
    /// safety contract.
    script_validation_checkpoint: Option<(u32, [u8; 32])>,
    /// EIP-27 re-emission rule inputs for this node's network, plumbed
    /// through to `validate_full_block_parallel` via `process_block` so
    /// every block transaction is checked against the re-emission burning
    /// condition. `None` disables the check (testnet / no EIP-27). See
    /// [`ReemissionRuleInputs`].
    reemission: Option<ReemissionRuleInputs>,
    /// Per-tick header-pipeline timings. Read+reset by the node heartbeat.
    pub header_perf: HeaderPerfCounters,
    /// Per-tick block-pipeline timings (process_block phases + drain
    /// scheduler stats). Read+reset by the node heartbeat.
    pub block_perf: BlockPerfCounters,
    /// The most recent block-apply REJECTION (a block this node refused while
    /// its peers may have accepted it). Set only in the two genuine
    /// invalid-block sinks (NOT data-wait or reorg arms). Surfaced to operators
    /// via /health (`HealthStatus::Rejecting`) and /status so a consensus
    /// fork-from-network is visible, not just a `warn!` line. Session-scoped
    /// (cleared on restart, like `block_perf`).
    last_block_apply_error: Option<LastBlockApplyError>,
    /// Monotonic count of block-apply rejections since start. Backs the
    /// `ergo_node_block_apply_errors_total` Prometheus counter.
    block_apply_error_count: u64,
    /// Live apply-phase gauges shared with the API `/metrics` bridge.
    apply_phase: std::sync::Arc<crate::ApplyPhaseMetrics>,
    /// Terminal deep-fork wedge: the best-header chain forks below the state
    /// backend's rollback horizon, so this node cannot reorg onto it and can
    /// never apply another block — only a resync recovers. Set when the
    /// fork-point walk declines with [`ForkPoint::TooDeep`], cleared the
    /// moment the chains agree again or a reorg performs. Surfaced via
    /// /health (`HealthStatus::Wedged`), /status (`sync_wedged`) and the
    /// operator event feed. Session-scoped (re-detected within one tick
    /// after a restart).
    deep_fork_wedge: Option<DeepForkWedge>,
    /// Last wedge warning emission, rate-limiting the re-warn: the wedge is
    /// re-detected every tick, and warning every tick would bury the one log
    /// line that explains the stall.
    deep_fork_wedge_last_warn: Option<Instant>,
    /// Rate-limiter for the single-header orphan-root parent-walk. That walk
    /// is an O(orphan-buffer) scan (bounded by `ORPHAN_HEADER_LIMIT` but still
    /// large), and the ParentNotFound path would otherwise run it on every
    /// buffered orphan — quadratic under an orphan flood. Throttled to at most
    /// once per [`header_pipeline::ORPHAN_ROOT_WALK_MIN_INTERVAL`]; the batch
    /// drain path and reciprocal SyncInfo still surface missing parents.
    orphan_root_walk_last: Option<Instant>,
}

impl SyncExecutor {
    pub fn new(params: ProtocolParams, chain_config: DifficultyParams) -> Self {
        Self {
            params,
            chain_config,
            last_headers: VecDeque::with_capacity(LAST_HEADERS_WINDOW),
            block_context_headers: Vec::with_capacity(10),
            recently_installed: HashSet::new(),
            orphan_headers: HashMap::new(),
            orphan_headers_len: 0,
            header_index: BTreeMap::new(),
            recovery_done: false,
            script_validation_checkpoint: None,
            reemission: None,
            header_perf: HeaderPerfCounters::default(),
            block_perf: BlockPerfCounters::default(),
            last_block_apply_error: None,
            block_apply_error_count: 0,
            apply_phase: std::sync::Arc::new(crate::ApplyPhaseMetrics::default()),
            deep_fork_wedge: None,
            deep_fork_wedge_last_warn: None,
            orphan_root_walk_last: None,
        }
    }

    /// Shared apply-phase metrics (clone into the API read bridge).
    pub fn apply_phase_metrics(&self) -> std::sync::Arc<crate::ApplyPhaseMetrics> {
        self.apply_phase.clone()
    }

    /// Set the script-validation checkpoint. Blocks at or below `height`
    /// skip per-input ErgoScript evaluation; the observed `header_id` at
    /// exactly `height` is asserted against `block_id` (mismatch is fatal).
    pub fn set_script_validation_checkpoint(&mut self, ckpt: Option<(u32, [u8; 32])>) {
        self.script_validation_checkpoint = ckpt;
    }

    /// Set the EIP-27 re-emission rule inputs. `Some` enables the
    /// re-emission burning check (Scala `verifyReemissionSpending`) on every
    /// block transaction; `None` disables it (testnet / no EIP-27). Sourced
    /// from the chain spec at boot.
    pub fn set_reemission_rules(&mut self, reemission: Option<ReemissionRuleInputs>) {
        self.reemission = reemission;
    }

    /// The EIP-27 re-emission rule inputs installed at boot, if any. Mempool
    /// admission and mining candidate assembly borrow these so every
    /// transaction-validation path enforces the same burning condition the
    /// block validator does.
    pub fn reemission_rules(&self) -> Option<&ReemissionRuleInputs> {
        self.reemission.as_ref()
    }

    /// Whether `recover_coordinator` has run to completion (actually walked
    /// the header chain, not just bailed on the near-tip gate).
    pub fn recovery_done(&self) -> bool {
        self.recovery_done
    }

    /// Clear the `recovery_done` latch so the next sync_tick re-runs
    /// `recover_coordinator`. Used by Mode 2 part 2L after a snapshot
    /// install advances `best_full_block_height` — the original
    /// recovery walked the pre-snapshot window (empty for fresh
    /// bootstrap), so the post-snapshot range
    /// `[snapshot_height+1, best_header_height]` needs a fresh seed
    /// to populate the pending-block queue.
    pub fn reset_recovery_done(&mut self) {
        self.recovery_done = false;
    }

    /// Update the block-context cache after a successful block apply.
    fn update_block_context_cache(&mut self, processed: &block_proc::ProcessedBlock) {
        if let Some(ref checked) = processed.checked_header {
            self.block_context_headers.insert(0, checked.clone());
            self.block_context_headers.truncate(10);
        }
        // If checked_header is None (genesis), leave cache as-is.
        // hydrate_block_context will be called separately.
    }

    /// Access the rolling block-context cache (last 10 validated
    /// headers aligned to `best_full_block`). Used by the mempool to
    /// assemble `TipContext.last_headers` without re-reading them
    /// from the store. Element 0 is the best_full_block header.
    pub fn block_context_headers(&self) -> &[CheckedHeader] {
        &self.block_context_headers
    }

    /// Test accessor: number of entries in the in-memory header index.
    /// Not part of the public API; do not call from production code.
    #[doc(hidden)]
    pub fn header_index_len(&self) -> usize {
        self.header_index.len()
    }

    /// Test accessor: look up a height in the in-memory header index.
    /// Not part of the public API; do not call from production code.
    #[doc(hidden)]
    pub fn header_index_get(&self, height: u32) -> Option<[u8; 32]> {
        self.header_index.get(&height).copied()
    }

    /// Observability accessor: estimated bytes resident in the
    /// in-memory `header_index` BTreeMap. Estimate is
    /// `len * (4 + 32 + ~50 BTreeMap overhead)`; treat as an
    /// order-of-magnitude figure, not exact.
    pub fn header_index_estimated_bytes(&self) -> usize {
        self.header_index.len() * 86
    }

    /// Observability accessor: number of headers buffered for
    /// SyncInfo V2 and TipContext assembly (capped at
    /// LAST_HEADERS_WINDOW).
    pub fn last_headers_len(&self) -> usize {
        self.last_headers.len()
    }

    /// Observability accessor: sum of raw header bytes held in the
    /// `last_headers` cache.
    pub fn last_headers_bytes(&self) -> usize {
        self.last_headers.iter().map(|(_, b)| b.len()).sum()
    }

    /// Observability accessor: orphan-header buffer entry count
    /// (capped at ORPHAN_HEADER_LIMIT).
    pub fn orphan_headers_len(&self) -> usize {
        self.orphan_headers_len
    }

    /// Observability accessor: sum of bytes held in the
    /// orphan-header buffer.
    pub fn orphan_headers_bytes(&self) -> usize {
        self.orphan_headers
            .values()
            .flat_map(|v| v.iter())
            .map(|(_, _, b)| b.len())
            .sum()
    }

    /// Execute one Action against the store and coordinator.
    /// Returns a (possibly empty) list of follow-up actions for the
    /// network loop to handle (SendToPeer / Penalize) or the executor
    /// queue to drain (internal ValidateHeader / PersistSection /
    /// AssembleBlock). Log actions produce no follow-ups.
    pub fn execute(
        &mut self,
        action: Action,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
        wallet_wiring: Option<ergo_state::wallet::WalletWiring<'_>>,
    ) -> Vec<Action> {
        match action {
            Action::ValidateHeader { peer, header_bytes } => {
                self.handle_validate_header(peer, &header_bytes, store, coordinator, now)
            }
            Action::AssembleBlock { header_id } => {
                self.handle_assemble_block(&header_id, store, coordinator, wallet_wiring)
            }
            Action::PersistSection {
                modifier_id,
                section_bytes,
                section_type,
            } => self.handle_persist_section(&modifier_id, &section_bytes, section_type, store),
            Action::Penalize { .. } => {
                // Pass through to the network loop as-is.
                vec![action]
            }
            Action::NoteDeliveryOutcome { .. } => {
                // Peer-state bookkeeping — pass through to the action loop.
                vec![action]
            }
            Action::SendToPeer { .. } => {
                // Network I/O — the caller sends this over the connection.
                vec![action]
            }
        }
    }

    /// Process all actions from a list, feeding results back into the coordinator.
    /// Returns actions that need network I/O (SendToPeer, Penalize).
    ///
    /// ValidateHeader actions are partitioned out and batch-processed:
    /// Phase 1 (rayon parallel) — parse + PoW verify all headers
    /// Phase 2 (sequential) — chain linkage + atomic persist
    /// Remaining actions processed normally after headers.
    pub fn execute_all(
        &mut self,
        actions: Vec<Action>,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
        wallet_wiring: Option<ergo_state::wallet::WalletWiring<'_>>,
    ) -> Vec<Action> {
        let mut network_actions = Vec::new();

        // Partition: extract ValidateHeader for batch processing
        let mut headers_to_validate = Vec::new();
        let mut remaining = VecDeque::new();
        for action in actions {
            if let Action::ValidateHeader { peer, header_bytes } = action {
                headers_to_validate.push((peer, header_bytes));
            } else {
                remaining.push_back(action);
            }
        }

        // Batch pre-validate headers (rayon parallel PoW, sequential finalize)
        if !headers_to_validate.is_empty() {
            let batch_actions =
                self.batch_validate_headers(headers_to_validate, store, coordinator, now);
            for a in batch_actions {
                if matches!(
                    a,
                    Action::SendToPeer { .. }
                        | Action::Penalize { .. }
                        | Action::NoteDeliveryOutcome { .. }
                ) {
                    network_actions.push(a);
                } else {
                    remaining.push_back(a);
                }
            }
        }

        // Process remaining non-header actions
        while let Some(action) = remaining.pop_front() {
            for a in self.execute(action, store, coordinator, now, wallet_wiring) {
                if matches!(
                    a,
                    Action::SendToPeer { .. }
                        | Action::Penalize { .. }
                        | Action::NoteDeliveryOutcome { .. }
                ) {
                    network_actions.push(a);
                } else {
                    remaining.push_back(a);
                }
            }
        }
        network_actions
    }

    /// Cached recent header bytes for SyncInfo V2 (avoids 100 DB reads per SyncInfo).
    pub fn cached_header_bytes(&self, count: usize) -> Vec<Vec<u8>> {
        self.last_headers
            .iter()
            .take(count)
            .map(|(_, bytes)| bytes.clone())
            .collect()
    }

    /// Get the current recent-header window (CheckedHeaders only).
    pub fn last_headers(&self) -> Vec<CheckedHeader> {
        self.last_headers.iter().map(|(ch, _)| ch.clone()).collect()
    }

    pub fn params(&self) -> &ProtocolParams {
        &self.params
    }
}

#[cfg(test)]
mod tests;

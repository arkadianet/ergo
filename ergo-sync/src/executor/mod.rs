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

use crate::coordinator::{Action, ChainView, SyncCoordinator};
use ergo_crypto::difficulty::DifficultyParams;
use ergo_p2p::peer::{PeerId, Penalty};
use ergo_p2p::peer_manager::PeerManager;
use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::store::StateStore;
use ergo_state::{BlockApply, ChainStateRead, HeaderSectionStore};
use ergo_validation::context::ProtocolParams;
use ergo_validation::header::CheckedHeader;
use ergo_validation::ReemissionRuleInputs;
use rayon::prelude::*;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::block_proc::{self, BlockProcessError};
use crate::header_proc::{self, HeaderProcessError, ProcessedHeader};
use crate::perf::{BlockPerfCounters, HeaderPerfCounters};

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
/// Cap on total buffered orphan headers. Sized for Step D's
/// anchor-spacing scheduler: with `ANCHOR_SPACING = 4_000` and
/// `MAX_ANCHOR_AHEAD = 60_000`, up to ~14 peers can hold
/// concurrent disjoint anchor claims — each shipping a 400-ID
/// response. Actual buffered-header span is bounded by the
/// lookahead window (60_000 headers) so 100_000 leaves
/// comfortable headroom for slow-peer arrivals plus
/// request_orphan_root_parents fetches. Memory: 100_000 ×
/// ~1.5 KB (bytes + cached PreValidated) ≈ 150 MB. Acceptable
/// against the spec §4 "~448 MB total" budget — the orphan
/// buffer is the temporary IBD overflow, not steady-state state.
const ORPHAN_HEADER_LIMIT: usize = 100_000;
/// During IBD, ignore orphan headers too far ahead of `best_header`.
///
/// Bumped from 30_000 → 60_000 with Step D's anchor-spacing
/// scheduler. Spacing concurrent peer assignments by
/// `ANCHOR_SPACING = 4_000` means a 60_000-deep window holds
/// 60_000 / 4_000 = 15 concurrent disjoint slices — the maximum
/// pipeline width before slow-peer responses get dropped. Slow
/// anchored responses (5s+ RTT variance) need this depth so their
/// 400-ID slice still lands inside the buffer even after faster
/// peers have advanced tip several thousand headers. Live-tip
/// far-ahead announces (hundreds of thousands ahead) still drop.
const ORPHAN_HEADER_IBD_LOOKAHEAD: u32 = 60_000;

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
}

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

impl SyncExecutor {
    /// Run the full single-header validation pipeline for an
    /// out-of-band local header (e.g. the §12 `POST /blocks`
    /// sendMinedBlock path) without going through
    /// `Action::ValidateHeader` / `coordinator::on_header_validated`
    /// — those emit per-peer `delivery.request` / `SendToPeer` for
    /// the submitting peer, but a locally-injected header has no peer.
    ///
    /// Equivalent to the success path of `handle_validate_header`:
    /// PoW verify + chain linkage + persist + push into the
    /// recent-header cache + `recently_installed` registration +
    /// orphan-drain pass. The last two matter because orphan headers
    /// previously buffered against this header as parent will only
    /// drain if `recently_installed` knows we just installed it
    /// (`drain_orphans:1589`).
    ///
    /// Returns `(ProcessedHeader, drain_actions)`. The caller MUST
    /// flush `drain_actions` — they are NOT cosmetic; `drain_orphans`
    /// calls `coordinator::on_header_validated` for any orphan that
    /// just unblocked, which registers section downloads
    /// (`delivery.request`) AND emits
    /// `Action::SendToPeer(RequestModifier, …)` for real peers.
    /// Discarding those leaves entries in the delivery tracker for
    /// requests that were never actually sent, leading to false
    /// non-delivery penalties on the affected peers.
    ///
    /// Errors mirror `process_header_cfg` exactly — caller maps to
    /// its own transport-layer error vocabulary.
    pub fn process_local_header(
        &mut self,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        header_bytes: &[u8],
        now: Instant,
    ) -> Result<(ProcessedHeader, Vec<Action>), HeaderProcessError> {
        // Header-pipeline telemetry — mirror the single-header path
        // at `handle_validate_header:769-804` so `/metrics`
        // `ergo_node_header_pow_*` / `_headers_total` /
        // `_header_finalize_*` reflect locally-submitted headers too.
        let t_pow = Instant::now();
        let pre_result = header_proc::pre_validate_header(header_bytes);
        let pow_ns = t_pow.elapsed().as_nanos() as u64;
        self.header_perf.add_pow_wall(pow_ns);
        self.header_perf.add_pow_cpu(pow_ns);
        self.header_perf.add_headers(1);
        let pre = pre_result?;

        let t_fin = Instant::now();
        let finalize_result = header_proc::finalize_header(
            utxo_header_store_mut(store),
            pre,
            header_bytes,
            &self.chain_config,
        );
        self.header_perf
            .add_finalize(t_fin.elapsed().as_nanos() as u64);
        let processed = finalize_result?;

        self.push_validated_header(&processed, header_bytes);
        let drain_actions = self.drain_orphans(store, coordinator, now);
        Ok((processed, drain_actions))
    }

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
        }
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
    fn record_block_apply_error(&mut self, header_id: [u8; 32], height: u32, reason: String) {
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

    /// Update the block-context cache after a successful block apply.
    fn update_block_context_cache(&mut self, processed: &block_proc::ProcessedBlock) {
        if let Some(ref checked) = processed.checked_header {
            self.block_context_headers.insert(0, checked.clone());
            self.block_context_headers.truncate(10);
        }
        // If checked_header is None (genesis), leave cache as-is.
        // hydrate_block_context will be called separately.
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

    /// Access the rolling block-context cache (last 10 validated
    /// headers aligned to `best_full_block`). Used by the mempool to
    /// assemble `TipContext.last_headers` without re-reading them
    /// from the store. Element 0 is the best_full_block header.
    pub fn block_context_headers(&self) -> &[CheckedHeader] {
        &self.block_context_headers
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

        // Only recover blocks within the download window.
        let recovery_limit = cs
            .best_full_block_height
            .saturating_add(coordinator.sync_state().download_window() as u32);
        let effective_header_height = cs.best_header_height.min(recovery_limit);

        if effective_header_height <= cs.best_full_block_height {
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

    // ---- Action handlers ----

    fn handle_validate_header(
        &mut self,
        peer: PeerId,
        header_bytes: &[u8],
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
    ) -> Vec<Action> {
        // Single-header path: PoW wall == CPU (one thread). Persist is
        // included in finalize_ns here because store_validated_header
        // happens inside finalize_header on the non-batched path.
        let t_pow = Instant::now();
        let pre = match header_proc::pre_validate_header(header_bytes) {
            Ok(pre) => pre,
            Err(e) => {
                let pow_ns = t_pow.elapsed().as_nanos() as u64;
                self.header_perf.add_pow_wall(pow_ns);
                self.header_perf.add_pow_cpu(pow_ns);
                self.header_perf.add_headers(1);
                warn!(peer = %peer, error = %e, "header validation failed");
                return vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }];
            }
        };
        let pow_ns = t_pow.elapsed().as_nanos() as u64;
        self.header_perf.add_pow_wall(pow_ns);
        self.header_perf.add_pow_cpu(pow_ns);
        self.header_perf.add_headers(1);

        let header_id = *pre.header_id();
        let header_height = pre.height;
        // Clone before finalize consumes pre — if finalize returns
        // ParentNotFound we use the clone to seed the orphan buffer
        // with a cached PoW proof, so retries skip Phase 1 entirely.
        // Cheap clone (PreValidatedHeader is ~hundreds of bytes).
        let pre_for_buffer = pre.clone();

        let t_fin = Instant::now();
        let finalize_result = header_proc::finalize_header(
            utxo_header_store_mut(store),
            pre,
            header_bytes,
            &self.chain_config,
        );
        self.header_perf
            .add_finalize(t_fin.elapsed().as_nanos() as u64);
        match finalize_result {
            Ok(processed) => {
                let expected = ExpectedSections::from_header(
                    &processed.header_id,
                    &processed.transactions_root,
                    &processed.extension_root,
                    &processed.ad_proofs_root,
                );
                let mut followup = coordinator.on_header_validated(
                    peer,
                    processed.header_id,
                    processed.height,
                    processed.header.timestamp,
                    expected,
                    now,
                );
                self.push_validated_header(&processed, header_bytes);

                // Drain orphan buffer — each success may unlock more orphans.
                followup.extend(self.drain_orphans(store, coordinator, now));

                followup
            }
            Err(HeaderProcessError::AlreadyKnown { .. }) => Vec::new(),
            Err(HeaderProcessError::ParentNotFound { .. }) => {
                if !self.buffer_or_defer_orphan_header(
                    peer,
                    pre_for_buffer,
                    header_bytes.to_vec(),
                    header_id,
                    header_height,
                    store,
                    coordinator,
                ) {
                    return Vec::new();
                }
                // Single-header path on ParentNotFound: nothing was
                // installed, so the orphan buffer can't have any new
                // unlocks. Skip the full drain — calling it would
                // re-finalize the entire 50k-cap buffer for nothing
                // (the dominant CPU cost observed at Step C+D
                // fanout — `orphan_n=800k+` per perf-hdr line). Just
                // emit the parent-walk requests so peers ship us
                // the missing parent for the fork-stitch case.
                self.request_orphan_root_parents(store, coordinator, now)
            }
            Err(HeaderProcessError::EpochContextIncomplete { height, .. }) => {
                // Local context gap (older epoch ancestors missing for
                // EIP-37 difficulty recalculation). Not peer
                // misbehavior — buffer + retry once more ancestors
                // arrive. Empirically unreachable on mainnet/testnet
                // preset; matters for custom configs and partial-window
                // recovery.
                warn!(
                    height,
                    peer = %peer,
                    "epoch context incomplete; buffering header for retry (no peer penalty)",
                );
                let _kept = self.buffer_or_defer_orphan_header(
                    peer,
                    pre_for_buffer,
                    header_bytes.to_vec(),
                    header_id,
                    header_height,
                    store,
                    coordinator,
                );
                Vec::new()
            }
            Err(e) => {
                warn!(peer = %peer, error = %e, "header validation failed");
                vec![Action::Penalize {
                    peer,
                    penalty: Penalty::Misbehavior,
                }]
            }
        }
    }

    fn handle_assemble_block(
        &mut self,
        header_id: &[u8; 32],
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        wallet_wiring: Option<ergo_state::wallet::WalletWiring<'_>>,
    ) -> Vec<Action> {
        match self.rollback_full_chain_to_best_header(store, coordinator, wallet_wiring) {
            Ok(true) => {
                self.try_apply_next_blocks(store, coordinator, Instant::now(), wallet_wiring);
                return Vec::new();
            }
            Ok(false) => {}
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
            ) => Vec::new(),
            Err(
                BlockProcessError::ParentNotBestFull { .. }
                // Digest fork / out-of-order: the block's parent is not
                // the committed tip, or its height is not tip+1. Not
                // invalid — drive the same reorg path as the UTXO arm.
                | BlockProcessError::DigestNonLinearParent { .. }
                | BlockProcessError::DigestOutOfOrder { .. },
            ) => {
                match self.rollback_full_chain_to_best_header(store, coordinator, wallet_wiring) {
                    Ok(true) => {
                        self.try_apply_next_blocks(store, coordinator, Instant::now(), wallet_wiring);
                    }
                    Ok(false) => {}
                    Err(e) => warn!(error = %e, "full-block reorg failed"),
                }
                Vec::new()
            }
            Err(e) => {
                warn!(
                    block_id = %hex::encode(header_id),
                    error = %e,
                    "block validation failed",
                );
                self.record_block_apply_error(*header_id, meta.height, e.to_string());
                store.mark_session_invalid(*header_id);
                Vec::new()
            }
        }
    }

    fn handle_persist_section(
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

    // ---- Timeout, disconnect, missing-section recovery ----

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
                Ok(true) => {
                    progressed = true;
                    continue;
                }
                Ok(false) => {}
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
                    Ok(true) => {
                        progressed = true;
                        continue;
                    }
                    Ok(false) => {
                        warn!(
                            height = next,
                            parent_id = %hex::encode(parent_id),
                            best_full = %hex::encode(store.chain_state_meta().best_full_block_id),
                            "cannot apply block: parent is not best_full",
                        );
                        break;
                    }
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
            match block_proc::process_block(
                store,
                &header_id,
                &self.params,
                cache,
                self.script_validation_checkpoint,
                self.reemission.as_ref(),
                Some(&self.block_perf),
                wallet_wiring.map(|w| w.hook),
            ) {
                Ok(processed) => {
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
                    hit_section_wait = true;
                    break;
                }
                Err(
                    block_proc::BlockProcessError::ParentNotBestFull { .. }
                    // Digest fork / out-of-order: not invalid — reorg.
                    | block_proc::BlockProcessError::DigestNonLinearParent { .. }
                    | block_proc::BlockProcessError::DigestOutOfOrder { .. },
                ) => {
                    match self.rollback_full_chain_to_best_header(store, coordinator, wallet_wiring) {
                        Ok(true) => {
                            progressed = true;
                            continue;
                        }
                        Ok(false) => break,
                        Err(e) => {
                            warn!(error = %e, "full-block reorg failed");
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!(height = next, error = %e, "block apply failed");
                    self.record_block_apply_error(header_id, next, e.to_string());
                    store.mark_session_invalid(header_id);
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

    fn best_chain_header_id_at(
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
        let limit = base.saturating_add(coordinator.sync_state().download_window() as u32);
        let best_h = cs.best_header_height;
        for h in base..=limit.min(best_h) {
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

    fn rollback_full_chain_to_best_header(
        &mut self,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        wallet_wiring: Option<ergo_state::wallet::WalletWiring<'_>>,
    ) -> StorageResult<bool> {
        let Some((fork_height, fork_id)) = self.full_chain_fork_point(store)? else {
            return Ok(false);
        };
        // Capture identity fields before any mutation so the `_failed`
        // event below carries pre-attempt values, not rebuilt-state
        // values. `fork_id` is the common-ancestor header at
        // `fork_height`, not the new tip — per the Codex supervisor
        // plan for this phase.
        let old_height = store.chain_state_meta().best_full_block_height;
        let old_id = store.chain_state_meta().best_full_block_id;
        if fork_height == old_height {
            return Ok(false);
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
        Ok(true)
    }

    fn full_chain_fork_point(
        &self,
        store: &ergo_state::StateBackendKind,
    ) -> StorageResult<Option<(u32, [u8; 32])>> {
        let cs = store.chain_state_meta();
        let original_height = cs.best_full_block_height;
        if original_height == 0 {
            return Ok(None);
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
            // stop the descent and decline the reorg (`None`) instead of
            // walking to genesis and handing the executor an unrollbackable
            // target it would re-attempt — and re-fail — every tick. Scala
            // parity: `FullBlockProcessor` never caches a non-best block deeper
            // than `keepVersions = 200`, so it never attempts such a reorg. A
            // UTXO node this far behind must resync (snapshot / NiPoPoW), which
            // it cannot do by rolling its pruned undo log back.
            if let Some(max_depth) = max_rollback_depth {
                if original_height - height > max_depth {
                    debug!(
                        event = "full_chain_fork_too_deep",
                        original_height,
                        scanned_to = height,
                        max = max_depth,
                        "best-header fork deeper than backend rollback depth — declining reorg",
                    );
                    return Ok(None);
                }
            }
            if height == 0 {
                return Ok(Some((0, [0u8; 32])));
            }

            match store.get_header_id_at_height(height)? {
                Some(best_id) if best_id == full_id => {
                    if height == original_height {
                        return Ok(None);
                    }
                    return Ok(Some((height, full_id)));
                }
                Some(_) => {}
                None => return Ok(None),
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

    /// Check for delivery timeouts and re-request from alternative peers.
    /// Uses PeerManager::select_peer_excluding to find a peer that is NOT
    /// the one that timed out.
    pub fn check_timeouts(
        &mut self,
        coordinator: &mut SyncCoordinator,
        peer_mgr: &PeerManager,
        now: Instant,
    ) -> Vec<Action> {
        let peers = peer_mgr.eligible_download_peers(now);
        coordinator.check_timeouts(now, &peers)
    }

    /// HOL hedge: early-reassign stuck sections for any in-window pending
    /// block (inflight longer than `HOL_HEDGE_THRESHOLD`) to a *capable*
    /// peer. Called every sync tick; acts only when a section is actually
    /// stuck.
    ///
    /// Hedge peers come from `block_section_capable_peers` (full archive), not
    /// the broader `eligible_download_peers`: capability is the hard filter,
    /// so we never reassign a section to a peer that can't serve it (and that
    /// set is already kept clear of delivery-degraded peers).
    pub fn check_hol_hedges(
        &mut self,
        best_full_block_height: u32,
        coordinator: &mut SyncCoordinator,
        peer_mgr: &PeerManager,
        now: Instant,
    ) -> Vec<Action> {
        let peers = peer_mgr.block_section_capable_peers(now);
        coordinator.check_hol_hedges(best_full_block_height, HOL_HEDGE_THRESHOLD, now, &peers)
    }

    /// Handle peer disconnection: cancel requests and re-request from alternatives.
    pub fn on_peer_disconnected(
        &mut self,
        peer: &PeerId,
        coordinator: &mut SyncCoordinator,
        peer_mgr: &PeerManager,
        now: Instant,
    ) -> Vec<Action> {
        let peers = peer_mgr.eligible_download_peers(now);
        coordinator.on_peer_disconnected(peer, now, &peers)
    }

    /// Request sections for pending blocks that are missing from the store.
    /// Used after restart or when the download window advances.
    ///
    /// Sync-S1: now wires the bucketed multi-peer partitioner. Pending
    /// sections are distributed across ALL eligible download peers in
    /// per-peer buckets (Scala 8/12 parity), with a rotation cursor in
    /// the coordinator so the first peer in the sorted list isn't
    /// permanently the first assignee. Falls back to empty-action when
    /// no peer is eligible (caller sees the same no-op as before).
    pub fn request_missing_sections(
        &mut self,
        coordinator: &mut SyncCoordinator,
        chain: &dyn ChainView,
        peer_mgr: &PeerManager,
        now: Instant,
    ) -> Vec<Action> {
        // Prefer archive-mode peers (Scala parity, see
        // `VersionBasedPeerFilteringRule.scala:99-103`), but always
        // fall through to eligible peers as a secondary set so the
        // bucketed partitioner has enough fan-out. Attempt 6
        // demonstrated that strict-only-archive filtering left the
        // request loop with too few peers and stalled post-install
        // catch-up for 9+ minutes. With 2Q (no permanent Failed
        // state), the bucketed partitioner rotates across peers
        // naturally — sections eventually find a capable peer.
        let archive_peers = peer_mgr.block_section_capable_peers(now);
        let eligible = peer_mgr.eligible_download_peers(now);
        let peers: Vec<PeerId> = if archive_peers.is_empty() {
            eligible
        } else {
            // Archive peers first (they're guaranteed to have the
            // data), then everyone else (best-effort, may still
            // succeed for Mode 2 / Mode 3 peers that retain enough
            // history).
            let mut combined = archive_peers;
            for p in eligible {
                if !combined.contains(&p) {
                    combined.push(p);
                }
            }
            combined
        };
        coordinator.request_missing_sections_bucketed(chain, now, &peers)
    }

    /// Sync-S2: whether the delivery pipeline has drained below the
    /// low-watermark and should be refilled now instead of waiting for
    /// the next sync tick. Preserves the effect-transcript tenet — this
    /// is a pure query, the caller (node event loop) decides whether to
    /// invoke `request_missing_sections`.
    pub fn pipeline_needs_refill(&self, coordinator: &SyncCoordinator) -> bool {
        coordinator
            .delivery()
            .below_drain_watermark(DRAIN_WATERMARK)
    }

    // ---- Internal ----

    /// Batch-validate a set of headers using two-phase processing:
    /// Phase 1 (rayon parallel): parse + PoW verify
    /// Phase 2 (sequential): chain linkage + atomic persist
    /// Single orphan drain at the end covers all newly stored headers.
    fn batch_validate_headers(
        &mut self,
        headers: Vec<(PeerId, Vec<u8>)>,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
    ) -> Vec<Action> {
        // Single header: skip rayon overhead, use direct path
        if headers.len() == 1 {
            let (peer, bytes) = headers.into_iter().next().unwrap();
            return self.handle_validate_header(peer, &bytes, store, coordinator, now);
        }

        // Phase 1: parallel pre-validation (parse + PoW)
        let config = self.chain_config.clone();
        let batch_len = headers.len() as u64;
        // Per-header CPU time accumulator. Captured by reference inside the
        // rayon closure so each worker thread can fetch_add its own work
        // without contending on `self.header_perf` (which would also fail
        // the Send check on `&mut self`).
        let pow_cpu_acc = std::sync::atomic::AtomicU64::new(0);
        let t_pow_wall = Instant::now();
        let mut pre_validated: Vec<_> = headers
            .into_par_iter()
            .map(|(peer, bytes)| {
                let t = Instant::now();
                let result = header_proc::pre_validate_header(&bytes);
                pow_cpu_acc.fetch_add(
                    t.elapsed().as_nanos() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                (peer, bytes, result)
            })
            .collect();
        self.header_perf
            .add_pow_wall(t_pow_wall.elapsed().as_nanos() as u64);
        self.header_perf
            .add_pow_cpu(pow_cpu_acc.load(std::sync::atomic::Ordering::Relaxed));
        self.header_perf.add_headers(batch_len);

        // Topological order: sort by height ascending so parents precede
        // children during sequential finalize. Scala's `continuationIdsV2`
        // is documented as oldest-first, but `sendExtension`'s `groupBy`
        // does not preserve wire order, and we have seen real peers ship
        // Inv batches newest-first. Without this sort, every ParentNotFound
        // ends up in the orphan buffer whose own drain can't resolve
        // self-contained chains — progress stalls hard. Parse/PoW errors
        // bubble to the end (u32::MAX) so they don't contaminate ordering.
        pre_validated.sort_by_key(|(_, _, result)| {
            result
                .as_ref()
                .map(|pre| pre.header().height)
                .unwrap_or(u32::MAX)
        });

        // Phase 2: sequential finalization (chain linkage + deferred persist)
        // Batch mode: store writes go to in-memory buffer, flushed to one
        // redb transaction at the end. Parent lookups hit the buffer first.
        store.begin_header_batch();
        let t_fin = Instant::now();
        let mut actions = Vec::new();
        for (peer, bytes, result) in pre_validated {
            match result {
                Ok(pre) => {
                    let header_id = *pre.header_id();
                    let header_height = pre.height;
                    let pre_for_buffer = pre.clone();
                    match header_proc::finalize_header(
                        utxo_header_store_mut(store),
                        pre,
                        &bytes,
                        &config,
                    ) {
                        Ok(processed) => {
                            let expected = ExpectedSections::from_header(
                                &processed.header_id,
                                &processed.transactions_root,
                                &processed.extension_root,
                                &processed.ad_proofs_root,
                            );
                            let followup = coordinator.on_header_validated(
                                peer,
                                processed.header_id,
                                processed.height,
                                processed.header.timestamp,
                                expected,
                                now,
                            );
                            actions.extend(followup);
                            self.push_validated_header(&processed, &bytes);
                        }
                        Err(HeaderProcessError::AlreadyKnown { .. }) => {}
                        Err(HeaderProcessError::ParentNotFound { .. }) => {
                            self.buffer_or_defer_orphan_header(
                                peer,
                                pre_for_buffer,
                                bytes,
                                header_id,
                                header_height,
                                store,
                                coordinator,
                            );
                        }
                        Err(HeaderProcessError::EpochContextIncomplete { height, .. }) => {
                            // Local context gap, not peer misbehavior —
                            // see single-header path for rationale.
                            warn!(
                                height,
                                peer = %peer,
                                "epoch context incomplete; buffering header for retry (no peer penalty)",
                            );
                            self.buffer_or_defer_orphan_header(
                                peer,
                                pre_for_buffer,
                                bytes,
                                header_id,
                                header_height,
                                store,
                                coordinator,
                            );
                        }
                        Err(e) => {
                            warn!(peer = %peer, error = %e, "header validation failed");
                            actions.push(Action::Penalize {
                                peer,
                                penalty: Penalty::Misbehavior,
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "header pre-validation failed");
                    actions.push(Action::Penalize {
                        peer,
                        penalty: Penalty::Misbehavior,
                    });
                }
            }
        }
        self.header_perf
            .add_finalize(t_fin.elapsed().as_nanos() as u64);
        // Flush all validated headers to redb in one transaction.
        // Panic on failure: chain_state was already updated in-memory during
        // the batch. Continuing with a desynced in-memory/DB state is worse
        // than crashing. On restart, redb is consistent and we re-sync.
        let t_flush = Instant::now();
        store
            .flush_header_batch()
            .expect("header batch flush failed — redb write error is fatal");
        self.header_perf
            .add_flush(t_flush.elapsed().as_nanos() as u64);

        // Single orphan drain covers all newly stored headers
        actions.extend(self.drain_orphans(store, coordinator, now));
        actions
    }

    /// Try to process buffered orphan headers — single pass, no PoW.
    ///
    /// PoW is paid once at insertion (the cached `PreValidatedHeader`
    /// rides along in the buffer), so this drain only does the
    /// height-sorted finalize: try `finalize_header` for each in
    /// order, re-buffer the still-orphaned ones with their cached
    /// `PreValidatedHeader` intact. Cascade ("installing parent X
    /// unlocks child Y") happens naturally inside the loop because
    /// `finalize_header` consults the live `store`.
    ///
    /// Cost: `O(N × finalize_cost)`, no PoW. Re-PoW'ing the residual
    /// buffer (10k entries × 1k+ flushes/min) would dominate CPU and
    /// starve mainline throughput.
    fn drain_orphans(
        &mut self,
        store: &mut ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
    ) -> Vec<Action> {
        let mut all_actions = Vec::new();

        // Take headers installed since last drain — these are the
        // ONLY parents that could unblock orphans. Skipping the
        // orphan if parent_id ∉ this set is correct because orphans
        // entered the buffer with a missing parent; if it was in
        // store BEFORE last drain it would already be installable;
        // if it was installed SINCE it's in this set. Cleared on take.
        let newly_installed = std::mem::take(&mut self.recently_installed);

        if self.orphan_headers.is_empty() {
            self.cap_orphan_buffer();
            all_actions.extend(self.request_orphan_root_parents(store, coordinator, now));
            return all_actions;
        }

        // Pull only the orphans whose parent is in the just-installed
        // set. The buffer is keyed by parent_id, so this is O(|newly_installed|)
        // hashmap lookups instead of O(|buffer|) scans. Cascade
        // within the drain extends `newly_installed` so children
        // become eligible as their parents land.
        let mut work_queue: Vec<(PeerId, header_proc::PreValidatedHeader, Vec<u8>)> = Vec::new();
        for parent_id in &newly_installed {
            if let Some(children) = self.orphan_headers.remove(parent_id) {
                self.orphan_headers_len = self.orphan_headers_len.saturating_sub(children.len());
                work_queue.extend(children);
            }
        }
        if work_queue.is_empty() {
            self.cap_orphan_buffer();
            all_actions.extend(self.request_orphan_root_parents(store, coordinator, now));
            return all_actions;
        }

        // Topological order by height inside the work queue — same
        // reasoning as batch_validate_headers.
        work_queue.sort_by_key(|(_, pre, _)| pre.height);

        let orphan_count = work_queue.len() as u64;
        self.header_perf.add_orphan_headers(orphan_count);

        // Cascade: as we install, more children may become eligible
        // (their parent is in the new install set). Process via a
        // worklist that grows during the loop.
        //
        // Per spec §4 (Crash Safety) and §3 (Concurrency Model
        // "fixed-point drain"): the cascade is logically one chain
        // segment and MUST commit atomically. Wrap the loop in
        // `begin_header_batch()` / `flush_header_batch()` so all
        // cascaded `finalize_header` calls write to the in-memory
        // overlay, then flush as a single redb transaction at the
        // end. Without this, every cascaded header was its own redb
        // commit (~400μs each) — at 24k cascade length that's ~10s
        // of write churn blocking the action loop.
        store.begin_header_batch();
        let mut newly_installed_local = newly_installed;
        let config = self.chain_config.clone();
        let t_fin = Instant::now();
        while let Some((peer, pre, bytes)) = work_queue.pop() {
            let header_id = *pre.header_id();
            let header_height = pre.height;
            let pre_for_buffer = pre.clone();
            match header_proc::finalize_header(utxo_header_store_mut(store), pre, &bytes, &config) {
                Ok(processed) => {
                    // Children waiting on THIS header are now eligible
                    // — pull them out of the buffer and onto the queue.
                    newly_installed_local.insert(processed.header_id);
                    if let Some(children) = self.orphan_headers.remove(&processed.header_id) {
                        self.orphan_headers_len =
                            self.orphan_headers_len.saturating_sub(children.len());
                        work_queue.extend(children);
                        // Re-sort: pop() is LIFO, so later additions
                        // shouldn't reorder mid-stream — but the
                        // height-sort invariant is cheap to maintain.
                        work_queue.sort_by_key(|(_, pre, _)| pre.height);
                    }
                    let expected = ExpectedSections::from_header(
                        &processed.header_id,
                        &processed.transactions_root,
                        &processed.extension_root,
                        &processed.ad_proofs_root,
                    );
                    let followup = coordinator.on_header_validated(
                        peer,
                        processed.header_id,
                        processed.height,
                        processed.header.timestamp,
                        expected,
                        now,
                    );
                    all_actions.extend(followup);
                    self.push_validated_header(&processed, &bytes);
                }
                Err(HeaderProcessError::ParentNotFound { .. }) => {
                    // Defensive — the pre-filter said parent was
                    // installed, but finalize disagreed (e.g. a
                    // fork-choice race). Re-buffer with cached pre.
                    self.buffer_or_defer_orphan_header(
                        peer,
                        pre_for_buffer,
                        bytes,
                        header_id,
                        header_height,
                        store,
                        coordinator,
                    );
                }
                Err(HeaderProcessError::EpochContextIncomplete { .. }) => {
                    // Drain-path equivalent of the single-header /
                    // batch handlers: epoch context still missing on
                    // retry, re-buffer rather than silently drop. Must
                    // come BEFORE the `Err(_) => drop invalid` arm
                    // below — without this match, an EIP-37 boundary
                    // header that re-fails on drain would be
                    // permanently lost. Empirically unreachable on
                    // mainnet/testnet preset; matters for custom
                    // configs and partial-window recovery.
                    self.buffer_or_defer_orphan_header(
                        peer,
                        pre_for_buffer,
                        bytes,
                        header_id,
                        header_height,
                        store,
                        coordinator,
                    );
                }
                Err(HeaderProcessError::AlreadyKnown { .. }) => {}
                Err(_) => {} // drop invalid
            }
        }
        self.header_perf
            .add_orphan_finalize(t_fin.elapsed().as_nanos() as u64);
        // Flush the cascade as a single redb transaction. Per spec
        // §4, a flush failure here means the in-memory state is
        // ahead of disk — same fatal class as the batch path's
        // flush at line ~1247. Match that behaviour: panic so a
        // fresh restart re-syncs from a consistent on-disk state.
        store
            .flush_header_batch()
            .expect("orphan drain flush_header_batch failed — redb write error is fatal");
        // Suppress dead_code: keep the local set live until end of
        // function so cascade tracking is observable in trace.
        let _ = newly_installed_local;

        self.cap_orphan_buffer();

        // Parent-walk: if the buffer is still non-empty after drain, the
        // chain bottoms out at a header we don't have yet. Ask peers for
        // those missing parents so the chain can stitch backward until it
        // meets our store. Once the common ancestor is reached, cumulative-
        // score fork-choice in `finalize_header` + `store.store_validated_header`
        // handles the reorg atomically (best_header_id switch + HEADER_CHAIN_INDEX
        // rewrite). No manual rollback needed because best_full_block_height
        // is gated separately from best_header_height.
        all_actions.extend(self.request_orphan_root_parents(store, coordinator, now));
        all_actions
    }

    #[allow(clippy::too_many_arguments)]
    fn buffer_or_defer_orphan_header(
        &mut self,
        peer: PeerId,
        pre: header_proc::PreValidatedHeader,
        bytes: Vec<u8>,
        header_id: [u8; 32],
        height: u32,
        store: &ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
    ) -> bool {
        if self.should_buffer_orphan_header(height, store, coordinator) {
            let parent_id = pre.parent_id;
            self.orphan_headers
                .entry(parent_id)
                .or_default()
                .push((peer, pre, bytes));
            self.orphan_headers_len = self.orphan_headers_len.saturating_add(1);
            return true;
        }

        coordinator.forget_received_modifier(&header_id);
        let best = store.chain_state_meta().best_header_height;
        warn!(
            height,
            best_header_height = best,
            peer = %peer,
            "deferring far-ahead orphan header; not parent-walking during IBD",
        );
        false
    }

    fn should_buffer_orphan_header(
        &self,
        height: u32,
        store: &ergo_state::StateBackendKind,
        coordinator: &SyncCoordinator,
    ) -> bool {
        if coordinator.sync_state().headers_chain_synced() {
            return true;
        }
        let best = store.chain_state_meta().best_header_height;
        height <= best.saturating_add(ORPHAN_HEADER_IBD_LOOKAHEAD)
    }

    fn cap_orphan_buffer(&mut self) {
        if self.orphan_headers_len <= ORPHAN_HEADER_LIMIT {
            return;
        }
        // Buffer is HashMap<parent_id, Vec<orphan>>. Cap by dropping
        // the highest-height ENTRIES — keep the root side of orphan
        // chains so once their parents reconnect, higher tips can
        // be re-fetched through normal SyncInfo/Inv flow.
        //
        // Collect all (height, parent_id, orphan_index) tuples, sort
        // descending by height, drop until under cap. O(N log N) on
        // overflow; only fires when buffer overflows.
        let overflow = self.orphan_headers_len - ORPHAN_HEADER_LIMIT;
        let mut by_height: Vec<(u32, [u8; 32], usize)> =
            Vec::with_capacity(self.orphan_headers_len);
        for (parent_id, children) in &self.orphan_headers {
            for (idx, (_, pre, _)) in children.iter().enumerate() {
                by_height.push((pre.height, *parent_id, idx));
            }
        }
        // Highest first.
        by_height.sort_by_key(|(h, _, _)| std::cmp::Reverse(*h));
        // Drop indices in REVERSE order per parent_id so swap_remove
        // doesn't shift earlier indices.
        let to_drop: Vec<([u8; 32], usize)> = by_height
            .into_iter()
            .take(overflow)
            .map(|(_, p, i)| (p, i))
            .collect();
        // Group by parent_id, sort indices desc per group, swap_remove.
        let mut by_parent: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
        for (p, i) in to_drop {
            by_parent.entry(p).or_default().push(i);
        }
        for (parent_id, mut indices) in by_parent {
            indices.sort_unstable_by(|a, b| b.cmp(a));
            if let Some(children) = self.orphan_headers.get_mut(&parent_id) {
                for i in indices {
                    if i < children.len() {
                        children.swap_remove(i);
                        self.orphan_headers_len = self.orphan_headers_len.saturating_sub(1);
                    }
                }
                if children.is_empty() {
                    self.orphan_headers.remove(&parent_id);
                }
            }
        }
    }

    /// Emit `RequestModifier(Header, [parent_id])` per peer for orphan-buffer
    /// headers whose parent is neither in our store nor the id of another
    /// buffered orphan. "Root" parents — the points where the orphan chain
    /// dangles into nothing. Groups by the peer that originally delivered
    /// each orphan so we ask the peer that has the chain; deduplicates
    /// per-peer parent sets.
    fn request_orphan_root_parents(
        &self,
        store: &ergo_state::StateBackendKind,
        coordinator: &mut SyncCoordinator,
        now: Instant,
    ) -> Vec<Action> {
        if self.orphan_headers.is_empty() {
            return Vec::new();
        }

        // Build set of header IDs of every orphan we hold — so we
        // can identify which `parent_id`s are "internal" (parent is
        // another orphan we're already holding) vs "root" (parent
        // is genuinely missing from our world).
        let mut orphan_ids: HashSet<[u8; 32]> = HashSet::with_capacity(self.orphan_headers_len);
        for children in self.orphan_headers.values() {
            for (_, pre, _) in children {
                orphan_ids.insert(*pre.header_id());
            }
        }

        let mut needed_per_peer: HashMap<PeerId, HashSet<[u8; 32]>> = HashMap::new();
        for (parent_id_key, children) in &self.orphan_headers {
            let parent_id = *parent_id_key;
            if orphan_ids.contains(&parent_id) {
                continue; // parent is another orphan we already have buffered
            }
            match store.get_header(&parent_id) {
                Ok(Some(_)) => continue, // parent already in store; drain will retry
                Ok(None) => {}
                Err(e) => {
                    warn!(
                        parent_id = %hex::encode(parent_id),
                        error = %e,
                        "get_header failed during parent-walk",
                    );
                    continue;
                }
            }
            // Ask the FIRST peer that delivered an orphan for this
            // parent — they had the chain when they shipped the
            // child, so they likely have the parent too. Other peers
            // for the same parent_id needn't be re-asked: per-peer
            // sets dedupe and one parent fetch is enough.
            if let Some((peer, _, _)) = children.first() {
                needed_per_peer.entry(*peer).or_default().insert(parent_id);
            }
        }

        if needed_per_peer.is_empty() {
            return Vec::new();
        }

        let mut actions = Vec::new();
        let mut total_req = 0usize;
        for (peer, parents) in needed_per_peer {
            let parent_vec: Vec<[u8; 32]> = parents.into_iter().collect();
            total_req += parent_vec.len();
            actions.extend(coordinator.request_missing_header_parents(peer, &parent_vec, now));
        }
        if total_req > 0 {
            // A reorg signal: logging once per parent-walk request helps
            // operators see when the node traverses a fork boundary.
            info!(
                missing_parents = total_req,
                orphan_buffer = self.orphan_headers_len,
                "parent-walk: requesting missing parents",
            );
        }
        actions
    }

    /// Add a newly validated header + raw bytes to the recent-header window.
    fn push_validated_header(&mut self, processed: &ProcessedHeader, header_bytes: &[u8]) {
        self.last_headers
            .push_front((processed.checked.clone(), header_bytes.to_vec()));
        if self.last_headers.len() > LAST_HEADERS_WINDOW {
            self.last_headers.pop_back();
        }
        if processed.is_new_best {
            self.header_index
                .insert(processed.height, processed.header_id);
        }
        // Track for the orphan drain's parent-existence pre-filter.
        // Cleared at the start of each drain — this set means
        // "headers added since the last drain ran", i.e. potential
        // newly-unlocked parents.
        self.recently_installed.insert(processed.header_id);
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

//! `IndexerTask` — periodic poll loop with reorg detection.
//!
//! The chain doesn't expose a commit broadcast today (verified — no
//! `BlockApplied` channel), so the indexer mirrors the mempool
//! notifier's pattern: tip-poll, atomic `(height, header_id)` reads,
//! re-verify canonical after block load.
//!
//! The implementation is generic over an [`IndexerChainSource`] trait
//! so tests can script tip / header / block responses without a real
//! chain store. The production adapter wires this against
//! `ChainStoreReader`.
//!
//! Single-step semantics. `step` is the unit of forward progress: it
//! either applies one block, rolls one block back, returns idle when caught
//! up, or surfaces a halt/race condition. The blocking [`IndexerTask::run`]
//! driver loop turns those outcomes into a long-running task — backing
//! off on missing sections or applied heights (5 × 1 s), continuing after
//! committed progress, and waiting at least 50 ms after `Idle` or `Race`.
//! Waits observe cancellation.
//! Production uses [`IndexerTask::spawn`] to run this synchronous I/O and
//! compute work on a dedicated thread, outside the node's async worker pool.
//!
//! Header lookups must follow the committed fully applied block chain.
//! Header-only fork choice cannot establish validated bodies. Tip/height reads
//! may straddle State commits, so both forward progress and rollback verify
//! the captured applied tip's branch before mutating the index. An indexed
//! height merely absent from the applied chain, as after State restarts below
//! the index from its last durable commit, is no reorg: rollback also needs
//! the best-header chain to select another block there.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ergo_ser::transaction::Transaction;

use crate::apply::{apply_block_in_transaction, IndexerBlock};
use crate::error::{HeightOverflowContext, IndexerError};
use crate::events::{BlockChanges, IndexerObserver};
use crate::handle::IndexerHandle;
use crate::rollback::rollback_one_block_with_changes;
use crate::scratch::BlockApplyScratch;
use crate::store::{IndexerMeta, IndexerStore};
use crate::HeaderId;
use ergo_indexer_types::{IndexerHaltReason, IndexerQuery, IndexerStatus};

/// Atomic `(height, header_id)` snapshot of the chain's committed tip,
/// shaped to match `ergo_state::diff::TipPointer` so the production
/// adapter can pass through without a struct copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    pub height: u32,
    pub header_id: HeaderId,
}

/// Block payload the indexer polls from the chain. Carries the parsed
/// transaction list because both `apply_block` and `rollback_one_block`
/// need typed `Transaction`s, not raw bytes.
#[derive(Debug, Clone)]
pub struct IndexerFullBlock {
    pub height: i32,
    pub header_id: HeaderId,
    pub transactions: Vec<Transaction>,
}

/// Read surface the polling task depends on. Production wires this
/// against `ChainStoreReader`; tests use a scripted impl.
///
/// `Ok(None)` means absent data. Storage and decode failures must return
/// `Err`, preserving their cause where available; the task halts and abandons
/// any uncommitted batch. Each call may use a different chain snapshot, so
/// the task rechecks canonicality before committing forward progress.
pub trait IndexerChainSource: Send + Sync {
    /// Committed tip as `(height, header_id)`. Must be a single atomic
    /// snapshot — two reads from the same poll may otherwise see
    /// different values (the chain reader opens a fresh redb txn per
    /// call, so callers cannot count on snapshot stability).
    /// Pre-genesis is height zero with [`HeaderId::ZERO`], including after
    /// State rolls all applied blocks back. It has no height-zero header.
    fn committed_tip(&self) -> Result<ChainTip, IndexerError>;

    /// Header ID on the committed fully applied block chain at `height`, or
    /// `None` if past that tip, unwritten, or pruned. A best-header-only index
    /// is insufficient: section presence does not establish block validation.
    fn header_id_at(&self, height: u32) -> Result<Option<HeaderId>, IndexerError>;

    /// Header ID on the best-header chain at `height`, or `None` if absent.
    /// Never selects bodies to index: the task reads it only as reorg evidence
    /// when the applied chain has no block at the indexed height.
    fn best_header_id_at(&self, height: u32) -> Result<Option<HeaderId>, IndexerError>;

    /// Block (height + header_id + parsed transactions) by header_id.
    /// `None` when the chain has the header but section bytes haven't
    /// landed yet — driver retries with bounded backoff.
    fn full_block(&self, header_id: &HeaderId) -> Result<Option<IndexerFullBlock>, IndexerError>;
}

/// Outcome of one `step` iteration. The blocking [`IndexerTask::run`]
/// driver maps each variant to a sleep / retry / halt decision.
#[derive(Debug)]
pub enum IndexerPoll {
    /// Caught up. Status was set to `CaughtUp`.
    Idle,
    /// Committed forward progress through this height.
    Applied(u64),
    /// Rolled back the tip; the height in the variant is the height
    /// that was rolled back (post-rollback tip is `height - 1`).
    RolledBack(u64),
    /// Header is canonical but section bytes are missing — chain crash
    /// window. Driver retries with bounded backoff.
    SectionRetry { header_id: HeaderId, height: u64 },
    /// Mid-load fork flip or absent canonical height. Retry after a
    /// cancellation-aware delay so persistent races cannot spin.
    Race,
    /// The applied chain has no block at `height` although the captured tip
    /// above it stayed anchored: missing chain data, not a fork flip. Driver
    /// retries with the section-missing backoff, then halts `SectionMissing`.
    AppliedGap { height: u64 },
    /// Indexer halted with this error. Terminal — driver exits.
    Halted(IndexerError),
}

// Missing data retains the ordinary retry contract; read failures halt and
// abandon any uncommitted batch instead of becoming a genesis or race value.
macro_rules! chain_read {
    ($read:expr) => {
        match $read {
            Ok(value) => value,
            Err(error) => return IndexerPoll::Halted(error),
        }
    };
}

/// Polling task. Holds the indexer handle (status + height mirror), an
/// `Arc` to a chain source, and a long-lived `BlockApplyScratch` reused
/// across every block apply so per-block / per-tx
/// allocations amortize over the run.
pub struct IndexerTask<C: IndexerChainSource> {
    observer: Option<Arc<dyn IndexerObserver>>,
    handle: IndexerHandle,
    chain: Arc<C>,
    scratch: BlockApplyScratch,
    /// Shutdown flag, shared with [`IndexerTask::run`]'s driver loop. Threaded
    /// into the secondary-index rebuild so a multi-hour rebuild drains promptly
    /// on shutdown instead of ignoring SIGTERM until it finishes. Defaults to a
    /// never-set flag (e.g. for `step`-only tests); `run` overwrites it with the
    /// real cancel handle before the first poll.
    cancel: Arc<AtomicBool>,
    /// Warn-once latch for the deferred-rollback hold (see the gate in
    /// [`IndexerTask::step`]): the hold re-evaluates every poll, so an
    /// unlatched warn would fire once per second for the (potentially
    /// unbounded) life of a deep-fork wedge.
    hold_logged: bool,
}

/// Owned dedicated indexer thread. Dropping requests cancellation; use
/// [`Self::join`] to wait for the current atomic step and release worker-owned
/// database references. Drop alone cannot synchronously drain a blocking step.
pub struct IndexerWorker {
    cancel: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl IndexerWorker {
    /// Request cancellation and wait for the worker. This blocks, so async
    /// callers must join through `spawn_blocking`, not on a runtime worker.
    pub fn join(mut self) -> std::thread::Result<()> {
        self.cancel.store(true, Ordering::Release);
        self.thread.take().expect("owned indexer thread").join()
    }
}

impl Drop for IndexerWorker {
    fn drop(&mut self) {
        // Also covers partial node boot failure before RunHandle is created.
        self.cancel.store(true, Ordering::Release);
    }
}

impl<C: IndexerChainSource> IndexerTask<C> {
    pub fn new(handle: IndexerHandle, chain: Arc<C>) -> Self {
        Self {
            observer: None,
            handle,
            chain,
            scratch: BlockApplyScratch::new(),
            cancel: Arc::new(AtomicBool::new(false)),
            hold_logged: false,
        }
    }

    /// Install a post-commit observer. Capturing box data is opt-in and does
    /// not change indexer writes or chain validation.
    pub fn with_observer(mut self, observer: Arc<dyn IndexerObserver>) -> Self {
        self.scratch.capture_changes = true;
        self.observer = Some(observer);
        self
    }

    /// Start a dedicated worker for the node's lifetime. All step/rebuild work
    /// and idle waits stay on this OS thread; no nested runtime is needed.
    /// Neither the node's async nor blocking pools are occupied
    /// by the persistent catch-up loop. Spawn failure propagates to node boot.
    pub fn spawn(
        self,
        cancel: Arc<AtomicBool>,
        poll_idle: Duration,
    ) -> std::io::Result<IndexerWorker>
    where
        C: 'static,
    {
        let worker_cancel = Arc::clone(&cancel);
        let thread = std::thread::Builder::new()
            .name("extra-indexer".into())
            .stack_size(ergo_ser::decode_stack::DECODE_THREAD_STACK_BYTES)
            .spawn(move || self.run(worker_cancel, poll_idle))?;
        Ok(IndexerWorker {
            cancel,
            thread: Some(thread),
        })
    }

    /// One poll iteration. Synchronous — does no sleeping itself.
    ///
    /// Order: reorg check → caught-up check → forward
    /// load+verify+apply.
    pub fn step(&mut self) -> IndexerPoll {
        let poll = self.step_with_budget(1, Duration::ZERO, 0);
        self.finish_poll(poll)
    }

    /// Catch up in a bounded atomic batch. Limits are checked between blocks;
    /// one slow/large block still finishes atomically. Rollback remains per block.
    /// The driver uses this method while `step()` retains single-block semantics.
    pub fn step_batch(&mut self) -> IndexerPoll {
        let poll = self.step_with_budget(16, Duration::from_millis(50), 8 * 1024 * 1024);
        self.finish_poll(poll)
    }

    fn finish_poll(&self, poll: IndexerPoll) -> IndexerPoll {
        if let IndexerPoll::Halted(error) = &poll {
            self.handle
                .set_status(IndexerStatus::Halted(error.halt_reason()));
        }
        poll
    }

    fn step_with_budget(
        &mut self,
        max_blocks: usize,
        time_budget: Duration,
        byte_budget: u64,
    ) -> IndexerPoll {
        // `run` finishes a pending schema migration before its first poll; a
        // caller stepping the task directly must not see a missing store.
        if matches!(self.handle.status(), IndexerStatus::Migrating) {
            if let Err(error) = self.handle.finish_boot(&self.cancel) {
                return IndexerPoll::Halted(error);
            }
        }
        let store = match self.handle.store() {
            Some(s) => s,
            None => {
                return IndexerPoll::Halted(IndexerError::BootStoreMissing);
            }
        };

        let meta = match store.read_meta() {
            Ok(m) => m,
            Err(e) => return IndexerPoll::Halted(e),
        };

        let tip = chain_read!(self.chain.committed_tip());

        // Self-repair gate — MUST run before the reorg + forward-apply paths.
        // If a tolerated drift flagged the derived template/token index degraded
        // (sticky marker), run/resume the chain-free rebuild to completion now,
        // with status held at `Syncing` (the gated read API only serves at
        // `CaughtUp`, so a half-rebuilt index is never exposed). Placement is
        // load-bearing: the rebuild checkpoints by global box index, so applying
        // a new block (extending `global_box_index`) or rolling back BEFORE the
        // rebuild finishes would double-append those entries or operate on
        // half-wiped segments. The marker is sticky until the rebuild clears it,
        // so an interrupted rebuild resumes here on the next poll — always ahead
        // of any apply/rollback. No overhead on a healthy node (one bool read).
        match store.secondary_repair_pending() {
            Ok(true) => {
                self.handle.set_status(IndexerStatus::Syncing);
                if let Err(e) =
                    crate::rebuild::rebuild_secondary_indexes_until(&store, &self.cancel)
                {
                    return IndexerPoll::Halted(e);
                }
                // The rebuild returns early on shutdown WITHOUT finishing (marker
                // still pending, index half-rebuilt). Do NOT fall through to the
                // reorg / forward-apply paths — that would extend or roll back the
                // box index under a half-rebuilt secondary index. The driver loop
                // sees the cancel flag next and exits; the rebuild resumes on the
                // next start (its per-chunk checkpoint persists).
                if self.cancel.load(Ordering::Acquire) {
                    return IndexerPoll::Idle;
                }
            }
            Ok(false) => {}
            Err(e) => return IndexerPoll::Halted(e),
        }

        if let Some(prev_id) = meta.indexed_header_id {
            let our_h = match u32::try_from(meta.indexed_height) {
                Ok(h) => h,
                Err(_) => {
                    return IndexerPoll::Halted(IndexerError::HeightOverflowsU32 {
                        height: meta.indexed_height,
                        context: HeightOverflowContext::Indexed,
                    });
                }
            };
            let diverged = match chain_read!(self.chain.header_id_at(our_h)) {
                Some(id) => id != prev_id,
                // IBD commits State without durability, so after a hard crash
                // the applied chain can restart below blocks this index kept.
                // Absence alone is not a reorg: unwind only once the
                // best-header chain selects another block here, and otherwise
                // wait for State to re-apply ours.
                None => {
                    chain_read!(self.chain.best_header_id_at(our_h)).is_some_and(|id| id != prev_id)
                }
            };
            if diverged {
                // Separate source calls can observe a rollback between the
                // tip and height lookups. Only unwind when the captured State
                // tip belongs to the same applied chain we now observe.
                let state_reorged = if tip.height == 0 {
                    // There is no applied header at height zero to anchor a
                    // complete rollback. Require the legitimate pre-genesis
                    // sentinel and a second coherent atomic tip observation.
                    tip.header_id == HeaderId::ZERO
                        && chain_read!(self.chain.committed_tip()) == tip
                } else {
                    chain_read!(self.chain.header_id_at(tip.height)) == Some(tip.header_id)
                };
                if !state_reorged {
                    if !self.hold_logged {
                        tracing::warn!(
                            indexed_height = meta.indexed_height,
                            state_tip_height = tip.height,
                            "indexer rollback deferred: applied-chain reads changed and \
                             the captured chain-state tip no longer matches (reorg \
                             in progress) — holding the index \
                             instead of unwinding it",
                        );
                        self.hold_logged = true;
                    }
                    return IndexerPoll::Idle;
                }
                self.hold_logged = false;
                return self.do_rollback(&store, &meta, prev_id);
            }
            self.hold_logged = false;
        }

        // Separate source reads can straddle a State rollback. The captured
        // applied tip must still anchor the chain before forward catch-up;
        // its height alone cannot validate bodies from another applied branch.
        if tip.height > 0 && chain_read!(self.chain.header_id_at(tip.height)) != Some(tip.header_id)
        {
            self.handle.set_status(IndexerStatus::Syncing);
            return IndexerPoll::Race;
        }

        let next_height = meta.indexed_height + 1;
        if next_height > tip.height as u64 {
            self.handle.set_status(IndexerStatus::CaughtUp);
            return IndexerPoll::Idle;
        }

        self.handle.set_status(IndexerStatus::Syncing);

        let next_h32 = match u32::try_from(next_height) {
            Ok(h) => h,
            Err(_) => {
                return IndexerPoll::Halted(IndexerError::HeightOverflowsU32 {
                    height: next_height,
                    context: HeightOverflowContext::Next,
                });
            }
        };

        let header_id = match chain_read!(self.chain.header_id_at(next_h32)) {
            Some(id) => id,
            // A State rollback below this height also removes the captured
            // tip. A tip that still anchors the applied chain leaves a
            // permanent gap below it, such as `CHAIN_INDEX` coverage that
            // starts at a UTXO-snapshot anchor: bound it like missing
            // sections instead of racing forever.
            None if chain_read!(self.chain.header_id_at(tip.height)) == Some(tip.header_id) => {
                return IndexerPoll::AppliedGap {
                    height: next_height,
                };
            }
            None => return IndexerPoll::Race,
        };

        let mut block = match chain_read!(self.chain.full_block(&header_id)) {
            Some(b) => b,
            None => {
                return IndexerPoll::SectionRetry {
                    header_id,
                    height: next_height,
                };
            }
        };

        if chain_read!(self.chain.header_id_at(next_h32)) != Some(header_id)
            || block.header_id != header_id
        {
            return IndexerPoll::Race;
        }
        if self.cancel.load(Ordering::Acquire) {
            return IndexerPoll::Idle;
        }

        let mut write = match store.begin_write() {
            Ok(write) => write,
            Err(error) => return IndexerPoll::Halted(error),
        };
        // Same quick-repair transaction and Immediate durability as single-block
        // apply. A crash exposes the old checkpoint or the whole committed batch.
        if let Err(error) = write.set_durability(redb::Durability::Immediate) {
            return IndexerPoll::Halted(error.into());
        }
        let start = Instant::now();
        let mut next = meta;
        let mut bytes = 0_u64;
        let mut observations = Vec::new();
        for applied_count in 1..=max_blocks {
            let indexed = IndexerBlock {
                height: block.height,
                header_id: block.header_id,
                transactions: &block.transactions,
            };
            let applied = match apply_block_in_transaction(
                &write,
                store.rollback_window(),
                &next,
                &indexed,
                &mut self.scratch,
            ) {
                Ok(applied) => applied,
                Err(error) => return IndexerPoll::Halted(error), // abort all uncommitted rows
            };
            next = applied.meta;
            if self.observer.is_some() {
                observations.push(BlockChanges {
                    header_id: block.header_id,
                    height: block.height as u32,
                    boxes: applied.changes,
                });
            }
            bytes += applied.serialized_bytes;
            if applied.secondary_repair_pending
                || applied_count == max_blocks
                || next.indexed_height >= u64::from(tip.height)
                || start.elapsed() >= time_budget
                || bytes >= byte_budget
                || self.cancel.load(Ordering::Acquire)
            {
                break;
            }
            let height = (next.indexed_height + 1) as u32; // bounded by the captured u32 tip
            let Some(id) = chain_read!(self.chain.header_id_at(height)) else {
                break;
            };
            let Some(loaded) = chain_read!(self.chain.full_block(&id)) else {
                break;
            };
            if chain_read!(self.chain.header_id_at(height)) != Some(id)
                || loaded.header_id != id
                || chain_read!(self.chain.header_id_at(next.indexed_height as u32))
                    != next.indexed_header_id
            {
                return IndexerPoll::Race; // discard the entire batch on a fork flip
            }
            if self.cancel.load(Ordering::Acquire) || start.elapsed() >= time_budget {
                break;
            }
            block = loaded;
        }
        // The captured applied tip anchors this entire batch to validated
        // State, including when State rolls back during loading.
        if chain_read!(self.chain.header_id_at(next.indexed_height as u32))
            != next.indexed_header_id
            || chain_read!(self.chain.header_id_at(tip.height)) != Some(tip.header_id)
        {
            return IndexerPoll::Race;
        }
        if let Err(error) = write.commit() {
            return IndexerPoll::Halted(error.into());
        }
        self.handle.set_indexed_height(next.indexed_height);
        if let Some(observer) = &self.observer {
            for changes in observations {
                observer.on_committed(changes);
            }
        }
        IndexerPoll::Applied(next.indexed_height)
    }

    fn do_rollback(
        &self,
        store: &IndexerStore,
        meta: &IndexerMeta,
        prev_id: HeaderId,
    ) -> IndexerPoll {
        self.handle.set_status(IndexerStatus::Syncing);

        let block = match chain_read!(self.chain.full_block(&prev_id)) {
            Some(b) => b,
            None => {
                return IndexerPoll::SectionRetry {
                    header_id: prev_id,
                    height: meta.indexed_height,
                };
            }
        };

        let indexer_block = IndexerBlock {
            height: block.height,
            header_id: block.header_id,
            transactions: &block.transactions,
        };
        let prev_height = meta.indexed_height;
        match rollback_one_block_with_changes(store, meta, &indexer_block, self.observer.is_some())
        {
            Ok((next_meta, changes)) => {
                self.handle.set_indexed_height(next_meta.indexed_height);
                if let (Some(observer), Some(changes)) = (&self.observer, changes) {
                    observer.on_committed(changes);
                }
                IndexerPoll::RolledBack(prev_height)
            }
            Err(e) => IndexerPoll::Halted(e),
        }
    }

    /// Long-running driver loop. Exits cleanly when `cancel` flips to
    /// `true`, halts on terminal errors (sets `IndexerStatus::Halted`
    /// and returns).
    ///
    /// This method blocks the calling thread. Use [`Self::spawn`] in production;
    /// never call it directly on a shared async runtime worker.
    ///
    /// Sleeping policy:
    /// - `Idle`: sleep `poll_idle`, with a 50 ms minimum.
    /// - `Applied` / `RolledBack`: tight loop (no sleep — backfill
    ///   throughput is bound by I/O, not wall clock).
    /// - `Race`: a cancellation-aware 50 ms delay.
    /// - `SectionRetry` / `AppliedGap`: 1 s backoff per attempt; halt
    ///   `SectionMissing` after [`MAX_SECTION_RETRIES`].
    /// - `Halted`: set status, exit.
    pub fn run(mut self, cancel: Arc<AtomicBool>, poll_idle: Duration) {
        // Share the driver's cancel flag with `step` so an in-progress
        // secondary-index rebuild can drain promptly on shutdown.
        self.cancel = cancel.clone();
        if let Err(error) = self.handle.finish_boot(&cancel) {
            if !cancel.load(Ordering::Acquire) {
                if error.is_storage_error() {
                    crate::handle::report_indexer_storage_failure(
                        None,
                        "indexer_finish_boot",
                        None,
                        &error,
                    );
                }
                tracing::error!(%error, "indexer background boot failed");
                self.handle
                    .set_status(IndexerStatus::Halted(error.halt_reason()));
            }
            return;
        }
        let poll_idle = poll_idle.max(MIN_POLL_DELAY);
        let mut section_retry_count: u32 = 0;
        loop {
            if cancel.load(Ordering::Acquire) {
                return;
            }
            match self.step_batch() {
                IndexerPoll::Idle => {
                    section_retry_count = 0;
                    if !sleep_or_cancel(poll_idle, &cancel) {
                        return;
                    }
                }
                IndexerPoll::Applied(_) | IndexerPoll::RolledBack(_) => {
                    section_retry_count = 0;
                }
                IndexerPoll::Race => {
                    section_retry_count = 0;
                    if !sleep_or_cancel(MIN_POLL_DELAY, &cancel) {
                        return;
                    }
                }
                IndexerPoll::SectionRetry { header_id, height } => {
                    section_retry_count += 1;
                    if section_retry_count >= MAX_SECTION_RETRIES {
                        tracing::error!(
                            header_id = ?header_id,
                            height,
                            attempts = MAX_SECTION_RETRIES,
                            "indexer halted: section bytes still missing",
                        );
                        self.handle
                            .set_status(IndexerStatus::Halted(IndexerHaltReason::SectionMissing));
                        return;
                    }
                    if !sleep_or_cancel(SECTION_RETRY_DELAY, &cancel) {
                        return;
                    }
                }
                // Same budget as missing sections: absent chain data below an
                // anchored tip must end in a diagnosed halt, not spin.
                IndexerPoll::AppliedGap { height } => {
                    section_retry_count += 1;
                    if section_retry_count >= MAX_SECTION_RETRIES {
                        tracing::error!(
                            height,
                            attempts = MAX_SECTION_RETRIES,
                            "indexer halted: applied chain has no block at this height \
                             below its committed tip",
                        );
                        self.handle
                            .set_status(IndexerStatus::Halted(IndexerHaltReason::SectionMissing));
                        return;
                    }
                    if !sleep_or_cancel(SECTION_RETRY_DELAY, &cancel) {
                        return;
                    }
                }
                IndexerPoll::Halted(e) => {
                    let reason = e.halt_reason();
                    tracing::error!(error = %e, reason = ?reason, "indexer halted in-loop");
                    if e.is_storage_error() {
                        crate::handle::report_indexer_storage_failure(
                            self.handle.store().as_deref().map(IndexerStore::path),
                            "indexer_task",
                            Some(self.handle.indexed_height()),
                            &e,
                        );
                    }
                    self.handle.set_status(IndexerStatus::Halted(reason));
                    return;
                }
            }
        }
    }
}

/// Bounded retry: 5 attempts × 1 s backoff before halting on
/// SectionMissing.
pub const MAX_SECTION_RETRIES: u32 = 5;
const SECTION_RETRY_DELAY: Duration = Duration::from_secs(1);
const MIN_POLL_DELAY: Duration = Duration::from_millis(50);

#[cfg(test)]
#[path = "task_batch_tests.rs"]
mod batch_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "task_mainnet_bench.rs"]
mod task_mainnet_bench;

/// Returns `true` if the sleep elapsed; `false` if the cancel flag
/// flipped during sleep. Used by the driver loop to exit promptly on
/// shutdown.
fn sleep_or_cancel(d: Duration, cancel: &AtomicBool) -> bool {
    let started = std::time::Instant::now();
    loop {
        if cancel.load(Ordering::Acquire) {
            return false;
        }
        let remaining = d.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return true;
        }
        // Honor cancellation even with a long configured idle interval.
        std::thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

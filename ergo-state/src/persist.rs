//! Background persist pipeline.
//!
//! Moves redb write transactions off the block-processing hot path.
//! A dedicated thread owns the write handle; the main thread sends
//! pre-serialized `PersistJob`s over a bounded channel and continues
//! validating the next block immediately.
//!
//! Crash safety: redb guarantees per-transaction atomicity. In-memory
//! state leads persisted state by up to `queue_depth` blocks. On restart,
//! the persisted tip is read from CHAIN_STATE_META and replay continues
//! from the block store.
//!
//! Backpressure: bounded channel. When full, the main thread blocks on
//! send. This bounds memory from in-flight dirty sets.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crossbeam_channel::{bounded, Receiver, Sender};
use redb::{Database, ReadableTable};
use tracing::{debug, warn};

use crate::store::{
    StateError, AVL_NODES, CHAIN_INDEX, CHAIN_STATE_META, HEADER_CHAIN_INDEX, HEADER_META,
    STATE_META, UNDO_LOG,
};

/// Shared commit progress + error state used as a real barrier between the
/// persist worker and any caller of `flush()`.
///
/// **Why count-based, not height-based.** Heights are not monotonic across
/// rollback / reorg: branch A may apply to height 100, then `rollback_to(95)`
/// drops the in-memory tip, then branch B queues new jobs at heights
/// 96..=H. A height-based watermark from branch A would falsely satisfy any
/// branch-B target ≤ A's high-water — letting `flush_persist_pipeline()`
/// return before B's jobs commit and breaking the rollback/reorg
/// precondition that durable tip == in-memory tip. We track the *count* of
/// jobs queued (`sent_count` on the pipeline) vs. the count that have
/// committed (`committed_count` here). Counts are strictly monotonic across
/// any sequence of branches.
///
/// Why this exists at all: the per-job `PersistResult` channel is bounded
/// to `queue_depth + 1` (see `PersistPipeline::new`), but the worker
/// batches up to `MAX_BATCH_BLOCKS` jobs into one redb commit and emits
/// one result event per job via `try_send`. When the batch exceeds the
/// channel capacity (or the producer hasn't drained between submissions)
/// those completion events are silently dropped. A flush implementation
/// that only watches `result_rx` therefore can't tell "all jobs committed"
/// from "events were dropped". The `CommitWatch` records commit progress
/// on the worker side regardless of the channel's success — its state is
/// the durable source of truth for "have N jobs committed".
///
/// Scope: this barrier proves *redb-committed N jobs*. It does NOT prove
/// *OS-fsync* — durability beyond redb's commit is governed by the
/// `Durability::Eventual` setting and the separate `force_durable_flush`
/// path in `StateStore`.
struct CommitWatch {
    state: Mutex<CommitState>,
    cond: Condvar,
}

#[derive(Default)]
struct CommitState {
    /// Number of jobs the worker has successfully committed to redb so
    /// far. Strictly monotonic on success — independent of block height,
    /// so it remains correct across rollback / reorg branch swaps.
    committed_count: u64,
    /// First persist error since pipeline start, if any. Sticky:
    /// subsequent `wait_for` calls keep returning it until the pipeline
    /// is reconstructed. The carried `height` is informational.
    error: Option<(u32, String)>,
    /// Set when the worker thread is exiting (channel closed / shutdown).
    closed: bool,
}

impl CommitWatch {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(CommitState::default()),
            cond: Condvar::new(),
        })
    }

    /// Take the `state` mutex, recovering from any prior `PoisonError`
    /// by extracting the inner guard. The fields we mutate
    /// (`committed_count`, `error`, `closed`) are all monotone
    /// or sticky-first-wins, so a thread that died holding the lock
    /// did not leave them in a half-updated state we need to drop —
    /// continuing with the same state is the right action. Avoids
    /// turning a hypothetical poisoning into a hard panic on the
    /// reorg/rollback `flush()` barrier.
    fn take_lock(&self) -> std::sync::MutexGuard<'_, CommitState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn record_committed_jobs(&self, n: u64) {
        let mut s = self.take_lock();
        s.committed_count = s.committed_count.saturating_add(n);
        self.cond.notify_all();
    }

    fn record_error(&self, height: u32, error: String) {
        let mut s = self.take_lock();
        if s.error.is_none() {
            s.error = Some((height, error));
        }
        self.cond.notify_all();
    }

    fn record_closed(&self) {
        let mut s = self.take_lock();
        s.closed = true;
        self.cond.notify_all();
    }

    /// Block until `committed_count >= target_count` or an error is
    /// recorded. Returns `Ok(())` when the target is reached;
    /// `Err((h, e))` for the first error since pipeline start, OR for an
    /// unexpected worker shutdown before the target was reached.
    ///
    /// **No false-success on close.** Callers (`flush_persist_pipeline`)
    /// rely on `Ok(())` meaning "every queued job has committed" so it
    /// is safe to mutate the database — `rollback_to` assumes the
    /// persisted tip equals the in-memory tip. If the worker thread
    /// panics or the channel is closed
    /// before all queued jobs land, we MUST surface that as an error
    /// so the barrier never lies.
    fn wait_for(&self, target_count: u64) -> Result<(), (u32, String)> {
        let mut s = self.take_lock();
        loop {
            if let Some((h, e)) = &s.error {
                return Err((*h, e.clone()));
            }
            if s.committed_count >= target_count {
                return Ok(());
            }
            if s.closed {
                // Worker exited before completing every queued job and
                // recorded no error. Treat this as a fatal barrier
                // failure: the persist thread died (panic), or was
                // shut down concurrently with a flush request. Either
                // way, pretending the queued jobs committed would
                // corrupt the rollback/reorg invariant.
                return Err((
                    0,
                    format!(
                        "persist worker exited with {} of {target_count} \
                         queued jobs committed",
                        s.committed_count
                    ),
                ));
            }
            // Same poison-recovery contract as `take_lock`.
            s = self.cond.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// RAII guard the worker holds so the watch is marked closed even on
/// panic. Clones the underlying `Arc<CommitWatch>` for the worker thread
/// and signals close on drop.
struct WorkerWatchGuard(Arc<CommitWatch>);

impl Drop for WorkerWatchGuard {
    fn drop(&mut self) {
        self.0.record_closed();
    }
}

/// A single block's worth of pre-serialized persist data.
///
/// Built on the main thread, consumed by the persist thread.
/// All serialization happens before send — the persist thread
/// only does redb writes.
pub(crate) struct PersistJob {
    /// Height of the block being persisted.
    pub height: u32,
    /// Identifier of the block's header.
    pub header_id: [u8; 32],
    /// AVL nodes to write: (node_id, serialized_bytes).
    pub avl_writes: Vec<(u64, Vec<u8>)>,
    /// AVL node IDs to delete.
    pub avl_deletes: Vec<u64>,
    /// Undo log composite key (4-byte height BE + 32-byte header_id).
    pub undo_key: Vec<u8>,
    /// Serialized UndoEntry.
    pub undo_bytes: Vec<u8>,
    /// Serialized StateMeta (for "root" key).
    pub state_meta_bytes: Vec<u8>,
    /// Serialized AllocMeta (for "allocator" key).
    pub alloc_meta_bytes: Vec<u8>,
    /// Serialized ChainStateMeta (for "chain_state" key).
    pub chain_state_bytes: Vec<u8>,
    /// True iff this block extended best_header_height. Triggers
    /// HEADER_CHAIN_INDEX rewrite on the persist thread.
    pub best_header_bumped: bool,
    /// Pre-bump best_header_height, needed by rewrite_best_chain_into_index.
    pub old_best_header_height: u32,
    /// Pre-apply `chain_state.best_full_block_height`, captured by
    /// `persist_apply` BEFORE the staged update. Used by the
    /// pipeline-seam eviction to compute the Scala-parity prune
    /// range `[new_min - diff, new_min)` where
    /// `diff = last.height - first.old_best_full_block_height`.
    /// Carrying this in the job (rather than re-reading current
    /// state in `execute_batch`) handles the archive→pruned
    /// transition: an archive prefix at heights [1, old_tip] must
    /// stay intact when pruning starts; only the heights between
    /// `new_min - diff` and `new_min` are evicted.
    pub old_best_full_block_height: u32,
    /// Whether this commit must be durable (`Durability::Eventual`) or
    /// in-memory only (`Durability::None`). `Eventual` writes data + the
    /// durable commit marker but skips the synchronous fsync, deferring
    /// disk durability to OS writeback (~30s on Linux). Eliminates the
    /// 1-3s fsync stalls that `Immediate` causes on busy databases at
    /// the cost of a small additional crash-recovery window beyond
    /// `ibd_flush_interval`. Set per `ibd_blocks_since_flush >=
    /// ibd_flush_interval` so the durable flush still happens
    /// periodically — just without the stall.
    pub durable: bool,
    /// Prune undo entries below this height (None = no pruning).
    pub prune_below: Option<u32>,
    /// Parent header_id at the moment this job was queued — i.e. the
    /// previous best_header_id (or [0u8; 32] for the first block on a
    /// fresh chain). Used only by the test-helpers HEADER_META synthesis
    /// in `execute_batch` so the chain-walk inside
    /// `rewrite_best_chain_into_index` terminates correctly when the
    /// unchecked-test harness runs without populating HEADER_META.
    /// Production never touches this — header_proc has already written
    /// HEADER_META before apply_block is called.
    #[cfg_attr(not(feature = "test-helpers"), allow(dead_code))]
    pub parent_header_id: [u8; 32],
    /// Voted protocol parameters parsed from this block's extension.
    /// `Some` iff `height % 1024 == 0 && height > 0` (i.e. this block
    /// is an epoch start). Computed in the sync layer (block_proc)
    /// before the job is queued.
    pub voted_params_row: Option<ergo_validation::ActiveProtocolParameters>,
    /// Owned wallet-apply payload (M5 final slice). When `Some`, the
    /// worker applies the wallet writes inside the same redb
    /// write_txn that commits the chain mutation — chain + wallet
    /// atomic on the pipeline path too. Bundled as owned data so it
    /// crosses the worker-thread boundary without lifetime or
    /// Send/Sync friction. `None` when no wallet hook is wired (no-
    /// wallet deployments, tests).
    pub wallet_payload: Option<crate::store::WalletApplyPayload>,
}

/// One block-section payload to persist alongside the AVL / chain
/// metadata in the same redb commit.
#[derive(Clone)]
pub struct PersistedBlockSection {
    /// 32-byte modifier id of the section.
    pub modifier_id: [u8; 32],
    /// Section type byte (e.g. `100` header, `102` block transactions).
    pub section_type: u8,
    /// Serialized section bytes.
    pub bytes: Vec<u8>,
}

/// Result sent back from the persist thread after each job.
pub enum PersistResult {
    /// Job committed successfully.
    Ok {
        /// Height of the persisted block.
        height: u32,
        /// Number of AVL nodes written in this commit (only non-zero
        /// for the last job in a batch — earlier jobs report `0`).
        avl_writes: u32,
        /// Wall-clock time of the redb commit in milliseconds.
        commit_ms: f64,
    },
    /// Job (or its containing batch) failed.
    Err {
        /// Height of the failing block.
        height: u32,
        /// Error message.
        error: String,
    },
}

/// Handle to the background persist thread.
///
/// The main thread sends `PersistJob`s and optionally checks for results.
pub struct PersistPipeline {
    tx: Option<Sender<PersistJob>>,
    result_rx: Receiver<PersistResult>,
    thread: Option<thread::JoinHandle<()>>,
    /// Shared with the worker. Authoritative source of "have N jobs
    /// committed" — independent of the bounded `result_rx`, so silent
    /// channel drops cannot break the flush barrier.
    commit_watch: Arc<CommitWatch>,
    /// Total number of jobs ever passed to `send()`. Used by `flush()`
    /// as the count the worker must reach before we return. Counting
    /// (not heights) is what keeps the barrier correct across rollback
    /// and reorg branch swaps where heights re-decrease.
    sent_count: AtomicU64,
}

/// Maximum number of `PersistJob`s coalesced into a single redb write
/// transaction. Larger values amortize btree-rebalance and commit
/// overhead across more blocks at the cost of bounded crash-recovery
/// loss (any uncommitted batch is replayed from chain state on restart —
/// same semantics as today's `ibd_flush_interval`).
///
/// Profiling at h=505k showed the persist thread dominates CPU time
/// because every block triggers a full btree-mutate / page-write /
/// commit cycle. Batching shifts that cycle from per-block to per-batch.
///
/// Crash-recovery invariant: a batch commit either lands all N blocks
/// atomically or none of them. On restart, sync resumes from the last
/// committed CHAIN_STATE_META height — re-downloads + re-applies any
/// blocks that were in flight during the crash. Identical recovery
/// path to the existing `ibd_flush_interval` durability strategy.
pub(crate) const MAX_BATCH_BLOCKS: usize = 50;

impl PersistPipeline {
    /// Spawn the persist thread with a bounded job queue.
    ///
    /// `queue_depth`: max in-flight jobs before backpressure blocks the sender.
    /// Larger values let the persist thread coalesce more jobs into one
    /// redb txn (see `MAX_BATCH_BLOCKS`). 64-128 is a good range.
    pub fn new(
        db: Arc<Database>,
        queue_depth: usize,
        voting_length: u32,
        blocks_to_keep: i32,
    ) -> Self {
        let (tx, rx) = bounded::<PersistJob>(queue_depth);
        let (result_tx, result_rx) = bounded::<PersistResult>(queue_depth + 1);
        let commit_watch = CommitWatch::new();
        let worker_watch = Arc::clone(&commit_watch);

        let handle = thread::Builder::new()
            .name("persist".into())
            .spawn(move || {
                let _guard = WorkerWatchGuard(Arc::clone(&worker_watch));
                Self::persist_loop(
                    db,
                    rx,
                    result_tx,
                    worker_watch,
                    voting_length,
                    blocks_to_keep,
                );
            })
            .expect("failed to spawn persist thread");

        Self {
            tx: Some(tx),
            result_rx,
            thread: Some(handle),
            commit_watch,
            sent_count: AtomicU64::new(0),
        }
    }

    /// Send a job. Blocks if the queue is full (backpressure).
    ///
    /// Returns `StateError::InvalidPrecondition` if the pipeline has
    /// been shut down (`tx` cleared via `shutdown_pipeline`) — that
    /// case is a caller-lifecycle misuse. Returns
    /// `StateError::InternalInvariant` if the worker thread died
    /// (channel closed). Both are recoverable at the caller
    /// (typically: log + initiate a clean node shutdown).
    ///
    /// `sent_count` is incremented BEFORE the send. On a closed
    /// channel the count is one ahead of what the worker observed —
    /// `flush_to_count` then surfaces the bumped count via the
    /// commit_watch's terminal-error path rather than waiting
    /// forever on an unreachable target.
    pub(crate) fn send(&self, job: PersistJob) -> Result<(), StateError> {
        self.sent_count.fetch_add(1, Ordering::AcqRel);
        let tx = self.tx.as_ref().ok_or(StateError::InvalidPrecondition {
            what: "persist pipeline already shut down",
        })?;
        tx.send(job).map_err(|_| StateError::InternalInvariant {
            what: "persist worker thread died (channel closed)",
        })
    }

    /// Drain any completed results without blocking.
    /// Returns the latest error if any job failed.
    pub fn drain_results(&self) -> Option<PersistResult> {
        let mut last_err = None;
        for result in self.drain_all_results() {
            if matches!(&result, PersistResult::Err { .. }) {
                last_err = Some(result);
            }
        }
        last_err
    }

    /// Drain all completed results without blocking.
    pub fn drain_all_results(&self) -> Vec<PersistResult> {
        let mut out = Vec::new();
        while let Ok(result) = self.result_rx.try_recv() {
            out.push(result);
        }
        out
    }

    /// Block until every job sent so far has committed to redb.
    ///
    /// Real barrier: reads `sent_count` and waits on the `CommitWatch`
    /// until the worker reports `committed_count >= target` or surfaces
    /// an error. Independent of the bounded `result_rx`, so silent
    /// channel drops (which happen routinely when `MAX_BATCH_BLOCKS >
    /// queue_depth + 1`) do not break this barrier. **Count-based, not
    /// height-based** — heights re-decrease across rollback and would
    /// false-pass on a stale watermark from a previous branch.
    ///
    /// Scope: this proves redb has committed every queued job. It does
    /// NOT prove the OS has fsync'd those pages — `Durability::Eventual`
    /// defers fsync to OS writeback. The `force_durable_flush` path on
    /// `StateStore` is the OS-fsync barrier.
    ///
    /// Returns `None` on success; `Some(PersistResult::Err)` if any job
    /// since pipeline start failed (sticky — a single failure persists
    /// until the pipeline is reconstructed).
    pub fn flush(&self) -> Option<PersistResult> {
        let target = self.sent_count.load(Ordering::Acquire);
        if target == 0 {
            // Nothing was ever queued; barrier is vacuously satisfied.
            return None;
        }
        match self.commit_watch.wait_for(target) {
            Ok(()) => None,
            Err((height, error)) => Some(PersistResult::Err { height, error }),
        }
    }

    fn persist_loop(
        db: Arc<Database>,
        rx: Receiver<PersistJob>,
        result_tx: Sender<PersistResult>,
        watch: Arc<CommitWatch>,
        voting_length: u32,
        blocks_to_keep: i32,
    ) {
        loop {
            // Block on first job. Channel close ends the loop.
            let first = match rx.recv() {
                Ok(j) => j,
                Err(_) => return,
            };

            // Drain additional queued jobs without blocking. Batches
            // naturally degrade to size 1 when no other jobs are pending
            // (tip-sync), and grow up to MAX_BATCH_BLOCKS during IBD when
            // the main thread is feeding faster than redb commits.
            let mut batch = Vec::with_capacity(MAX_BATCH_BLOCKS);
            batch.push(first);
            while batch.len() < MAX_BATCH_BLOCKS {
                match rx.try_recv() {
                    Ok(j) => batch.push(j),
                    Err(_) => break,
                }
            }

            // Capture per-job heights / write counts before consuming the batch.
            let heights: Vec<u32> = batch.iter().map(|j| j.height).collect();
            let total_writes: u32 = batch
                .iter()
                .map(|j| (j.avl_writes.len() + j.avl_deletes.len()) as u32)
                .sum();
            let batch_size = batch.len();

            match Self::execute_batch(&db, batch, voting_length, blocks_to_keep) {
                Ok(commit_ms) => {
                    if batch_size > 1 {
                        debug!(
                            n = batch_size,
                            h_lo = heights.first().copied().unwrap_or(0),
                            h_hi = heights.last().copied().unwrap_or(0),
                            writes = total_writes,
                            commit_ms,
                            "persist batch",
                        );
                    }
                    // Authoritative commit barrier: bump the watch FIRST,
                    // then emit per-job result events. Any waiter in
                    // `flush()` unblocks as soon as the watch advances,
                    // regardless of whether the bounded `result_rx`
                    // accepts the events that follow. Increment by
                    // batch size — the count tracks "jobs successfully
                    // committed" so heights re-decreasing across
                    // rollback / reorg cannot false-pass an old
                    // watermark.
                    watch.record_committed_jobs(batch_size as u64);

                    // Send one Ok per job — preserves the result API
                    // for any other consumers. `try_send` may drop
                    // events when the batch exceeds `result_rx`'s
                    // capacity; that is fine because `watch` is the
                    // barrier source of truth.
                    let last_idx = heights.len().saturating_sub(1);
                    for (i, h) in heights.into_iter().enumerate() {
                        let _ = result_tx.try_send(PersistResult::Ok {
                            height: h,
                            avl_writes: if i == last_idx { total_writes } else { 0 },
                            commit_ms: if i == last_idx { commit_ms } else { 0.0 },
                        });
                    }
                }
                Err(e) => {
                    let last_h = *heights.last().unwrap_or(&0);
                    warn!(n = batch_size, last_h, error = %e, "persist batch error");
                    // Bump the watch's error state FIRST so any waiter
                    // in `flush()` unblocks even if the result channel
                    // is full.
                    watch.record_error(last_h, e.clone());

                    // Surface the error against every job in the batch —
                    // none of them landed (atomic commit failed for all).
                    for h in heights {
                        let _ = result_tx.try_send(PersistResult::Err {
                            height: h,
                            error: e.clone(),
                        });
                    }
                }
            }
        }
    }

    /// Execute one or more `PersistJob`s in a single redb write transaction.
    ///
    /// Atomicity: all jobs commit together or none. AVL inserts are
    /// applied in job order so a node touched by two consecutive blocks
    /// reflects the later block's value. CHAIN_STATE_META, STATE_META,
    /// and AllocMeta are written ONCE from the LAST job — earlier per-block
    /// snapshots are dominated by the final state. UNDO_LOG receives one
    /// entry per job (kept for rollback granularity). HEADER_CHAIN_INDEX
    /// is rewritten ONCE if any job bumped best_header, walking back from
    /// the LAST bumping job's tip to the FIRST bumping job's old base.
    /// Pruning uses the LAST job's `prune_below` (pruning is monotonic).
    /// Durability: Immediate iff ANY job in the batch is durable.
    fn execute_batch(
        db: &Database,
        jobs: Vec<PersistJob>,
        voting_length: u32,
        blocks_to_keep: i32,
    ) -> Result<f64, String> {
        if jobs.is_empty() {
            return Ok(0.0);
        }

        let mut write_txn = crate::begin_write_qr(db).map_err(|e| e.to_string())?;

        // Durability mode per batch:
        //   - `None`     : pure-memory commit, queued for next durable flush.
        //                  Used between IBD durable points.
        //   - `Eventual` : data is queued to OS pagecache and a durable commit
        //                  marker is written, but NO synchronous fsync.
        //                  redb stays consistent (CoW B-tree) and the OS
        //                  writeback (~30s on Linux) flushes to disk in the
        //                  background. This is the IBD periodic-flush mode —
        //                  it gives durability across normal restarts without
        //                  the 1-3s fsync stall that `Immediate` produces
        //                  on a busy DB. Hard-crash window is the OS
        //                  writeback delay (~30s) plus the IBD flush
        //                  interval (~100 blocks); both are acceptable
        //                  during catchup.
        //
        // Once IBD ends and `set_ibd_mode(false, ...)` flips, every commit
        // is durable; the synchronous-fsync `Immediate` mode then applies
        // (we use `Eventual` here because it's still safer than `None` —
        // tip-sync should be configured to call this with all-immediate
        // semantics if zero-loss durability is required).
        let any_durable = jobs.iter().any(|j| j.durable);
        let durability = if any_durable {
            redb::Durability::Eventual
        } else {
            redb::Durability::None
        };
        write_txn.set_durability(durability);

        // 1. AVL_NODES — apply in job order so later blocks overwrite
        //    earlier writes on the same node id (redb insert is upsert).
        {
            let mut avl_table = write_txn.open_table(AVL_NODES).map_err(|e| e.to_string())?;
            for job in &jobs {
                for (id, bytes) in &job.avl_writes {
                    avl_table
                        .insert(*id, bytes.as_slice())
                        .map_err(|e| e.to_string())?;
                }
                for id in &job.avl_deletes {
                    avl_table.remove(*id).map_err(|e| e.to_string())?;
                }
            }
        }

        // 2. UNDO_LOG — one entry per job. Required for rollback granularity:
        //    rollback_to(target) walks undo entries by height, so each block
        //    needs its own entry even when batched.
        {
            let mut undo_table = write_txn.open_table(UNDO_LOG).map_err(|e| e.to_string())?;
            for job in &jobs {
                undo_table
                    .insert(job.undo_key.as_slice(), job.undo_bytes.as_slice())
                    .map_err(|e| e.to_string())?;
            }
        }

        // 3. STATE_META — only the LAST job's snapshot matters; earlier ones
        //    are intermediate states the batch txn collapses.
        let last = jobs.last().expect("non-empty checked above");
        {
            let mut meta_table = write_txn
                .open_table(STATE_META)
                .map_err(|e| e.to_string())?;
            meta_table
                .insert("root", last.state_meta_bytes.as_slice())
                .map_err(|e| e.to_string())?;
            meta_table
                .insert("allocator", last.alloc_meta_bytes.as_slice())
                .map_err(|e| e.to_string())?;
            meta_table
                .insert(
                    crate::store::NODE_FORMAT_VERSION_KEY,
                    crate::store::NODE_FORMAT_V2,
                )
                .map_err(|e| e.to_string())?;
        }

        // 4. CHAIN_INDEX — one entry per job (height → header_id), so range
        //    lookups still work for every applied block.
        {
            let mut chain_table = write_txn
                .open_table(CHAIN_INDEX)
                .map_err(|e| e.to_string())?;
            for job in &jobs {
                chain_table
                    .insert(job.height as u64, job.header_id.as_slice())
                    .map_err(|e| e.to_string())?;
            }
        }

        // 5. CHAIN_STATE_META — only the LAST job's snapshot. Mid-batch
        //    chain states would be observable to readers but are not
        //    consistent with the in-memory state until the batch lands;
        //    storing only the final state matches the atomicity contract.
        {
            let mut cs_table = write_txn
                .open_table(CHAIN_STATE_META)
                .map_err(|e| e.to_string())?;
            cs_table
                .insert("chain_state", last.chain_state_bytes.as_slice())
                .map_err(|e| e.to_string())?;
        }

        // 6. HEADER_CHAIN_INDEX — rewrite once if any job in the batch
        //    bumped best_header. Use the FIRST bumping job's old base
        //    (walk-back lower bound) and the LAST bumping job's tip
        //    (walk-back start). Intermediate bumps are subsumed.
        if let Some(first_bump) = jobs.iter().find(|j| j.best_header_bumped) {
            let last_bump = jobs
                .iter()
                .rev()
                .find(|j| j.best_header_bumped)
                .expect("first_bump exists, so rev().find() also finds one");

            // Test-only: harnesses driving apply_block_unchecked_for_test bump
            // best_header without writing HEADER_META, so synthesize minimal
            // rows for every bumping job in the batch, linking each block's
            // parent_id to the previous bumping job's header_id. Mirrors the
            // synchronous persist_apply path; production always populates
            // HEADER_META via header_proc before apply_block, so this is a
            // no-op there.
            #[cfg(feature = "test-helpers")]
            {
                let mut m_table = write_txn
                    .open_table(HEADER_META)
                    .map_err(|e| e.to_string())?;
                // Track each just-synthesized header so the next bump in
                // the same batch links to it. The first bump links to the
                // job's `parent_header_id` (which captures the pre-batch
                // best_header_id from the source `chain_state`).
                let mut prev_header_id: Option<[u8; 32]> = None;
                for job in jobs.iter().filter(|j| j.best_header_bumped) {
                    let present = m_table
                        .get(job.header_id.as_slice())
                        .map_err(|e| e.to_string())?
                        .is_some();
                    if !present {
                        let parent_id = prev_header_id.unwrap_or(job.parent_header_id);
                        let meta = crate::chain::HeaderMeta {
                            parent_id,
                            height: job.height,
                            cumulative_score: vec![job.height as u8],
                            pow_validity: 1,
                            timestamp: 1_700_000_000 + job.height as u64,
                        };
                        m_table
                            .insert(job.header_id.as_slice(), meta.serialize().as_slice())
                            .map_err(|e| e.to_string())?;
                    }
                    prev_header_id = Some(job.header_id);
                }
            }

            let m_table = write_txn
                .open_table(HEADER_META)
                .map_err(|e| e.to_string())?;
            let mut idx_table = write_txn
                .open_table(HEADER_CHAIN_INDEX)
                .map_err(|e| e.to_string())?;
            crate::store::rewrite_best_chain_into_index(
                &mut idx_table,
                &m_table,
                last_bump.header_id,
                last_bump.height,
                first_bump.old_best_header_height,
            )
            .map_err(|e| e.to_string())?;
        }

        // 7. Undo prune — use the LAST job's `prune_below`. Pruning is
        //    monotonic: a higher prune_below subsumes any earlier value.
        if let Some(prune_below) = last.prune_below {
            let prune_upper = (prune_below + 1).to_be_bytes();
            let mut undo_table = write_txn.open_table(UNDO_LOG).map_err(|e| e.to_string())?;
            let mut to_delete: Vec<Vec<u8>> = Vec::new();
            {
                let range = undo_table
                    .range::<&[u8]>(..prune_upper.as_slice())
                    .map_err(|e| e.to_string())?;
                for entry in range {
                    let (key, _) = entry.map_err(|e| e.to_string())?;
                    to_delete.push(key.value().to_vec());
                }
            }
            for key in &to_delete {
                undo_table
                    .remove(key.as_slice())
                    .map_err(|e| e.to_string())?;
            }
        }

        // 7b. Mode 3 Phase 2b — block-section eviction at the
        // pipeline-batch seam. Iterates PER-JOB so the
        // sentinel-advance and prune-range exactly match what
        // the synchronous-seam would do if the batch were
        // applied block-by-block. Each job's `diff = job.height -
        // job.old_best_full_block_height` (typically 1 for
        // contiguous forward apply) drives a single-block range
        // `[max(1, new_min - diff), new_min)` per the Scala
        // formula. Across a voting-epoch snap, the per-job
        // iteration preserves the snap-skip behavior (sync seam
        // leaves some sub-sentinel heights on disk by design);
        // a batch-wide range would over-evict those heights and
        // diverge from sync semantics. Co-committed with all
        // other batch writes in the existing write_txn.
        // No-op for archive / Mode 6 / `blocks_to_keep <= 0`.
        if blocks_to_keep > 0 {
            // Read the current sentinel once inside the write_txn;
            // track in-memory across per-job iterations so the
            // final advance covers all increments.
            let mut current_min: u32 = {
                let meta = write_txn
                    .open_table(crate::store::STATE_META)
                    .map_err(|e| e.to_string())?;
                let bytes_opt = meta
                    .get(crate::store::MINIMAL_FULL_BLOCK_HEIGHT_KEY)
                    .map_err(|e| e.to_string())?
                    .map(|g| g.value().to_vec());
                drop(meta);
                match bytes_opt {
                    Some(bytes) => {
                        if bytes.len() != 4 {
                            return Err(format!(
                                "minimal_full_block_height payload has unexpected length: {}",
                                bytes.len()
                            ));
                        }
                        let mut buf = [0u8; 4];
                        buf.copy_from_slice(&bytes);
                        u32::from_le_bytes(buf)
                    }
                    None => 1,
                }
            };
            let mut sentinel_advanced = false;
            for job in &jobs {
                let new_min = crate::store::compute_minimal_full_block_height(
                    current_min,
                    job.height,
                    blocks_to_keep,
                    voting_length,
                );
                if new_min > current_min {
                    let diff = job
                        .height
                        .saturating_sub(job.old_best_full_block_height)
                        .max(1);
                    let prune_from = new_min.saturating_sub(diff).max(1);
                    for h in prune_from..new_min {
                        crate::store::StateStore::delete_block_sections_at_height_in_txn(
                            &write_txn, h,
                        )
                        .map_err(|e| e.to_string())?;
                    }
                    current_min = new_min;
                    sentinel_advanced = true;
                }
            }
            if sentinel_advanced {
                crate::store::StateStore::advance_minimal_full_block_height_in_txn(
                    &write_txn,
                    current_min,
                )
                .map_err(|e| e.to_string())?;
            }
        }

        // 8. VOTED_PARAMS — write at most one row per job at the job's
        //    `epoch_start_height`. `voted_params_row` is `Some` only on
        //    epoch-start blocks (h%1024==0, h>0), so most jobs are no-ops
        //    here. Two epoch-starts in one batch is impossible at the
        //    current MAX_BATCH_BLOCKS, but the loop tolerates it: keys
        //    are distinct, no conflict.
        //
        //    Defensive: validate the same invariants enforced in the
        //    synchronous persist_apply (epoch-aligned height, matching
        //    embedded epoch_start_height). The async path is the IBD
        //    hot path and must not be the weakest link.
        {
            let mut t = write_txn
                .open_table(crate::active_params::VOTED_PARAMS)
                .map_err(|e| e.to_string())?;
            for job in &jobs {
                if let Some(p) = &job.voted_params_row {
                    if !(job.height.is_multiple_of(voting_length) && job.height > 0) {
                        return Err(format!(
                            "voted_params_row supplied for non-epoch-start height {} \
                             (voting_length={voting_length})",
                            job.height
                        ));
                    }
                    if p.epoch_start_height != job.height {
                        return Err(format!(
                            "voted_params_row.epoch_start_height ({}) != block height ({})",
                            p.epoch_start_height, job.height
                        ));
                    }
                    let bytes = p
                        .serialize()
                        .map_err(|e| format!("voted_params at h={}: {e}", job.height))?;
                    t.insert(p.epoch_start_height as u64, bytes.as_slice())
                        .map_err(|e| e.to_string())?;
                }
            }
        }

        // 9. WALLET — apply each job's wallet payload inside this
        //    batch's write_txn (M5 final-slice atomicity). Chain +
        //    wallet now commit together on the pipeline path too,
        //    matching the synchronous-path guarantee from
        //    `persist_apply`. Maturity promotion at each height is
        //    part of the same atomic unit. A failure here aborts
        //    the entire batch via the `?` propagation (redb txn
        //    dropped without commit).
        //
        //    Per-job ordering matters: wallet apply at height N
        //    must observe inputs from heights <N as already-spent,
        //    so the loop runs the payloads in batch order — same
        //    order chain mutations were applied above.
        for job in &jobs {
            if let Some(payload) = &job.wallet_payload {
                let bound = crate::store::owned_to_block_txs(&payload.block_txs_owned);
                let btxs = bound.as_block_txs();
                // Scan-only payloads (no tracked trees/pubkeys) bypass wallet
                // apply + maturity-promotion so they don't advance
                // WALLET_SCAN_HEIGHT for blocks the wallet never classified
                // (which would surface as a bogus walletHeight in /wallet/status).
                if payload.has_wallet_tracking() {
                    crate::wallet::apply::apply_block_to_wallet(
                        &write_txn,
                        &payload.tracked_p2pk_trees,
                        &payload.cached_pubkeys,
                        job.height,
                        &job.header_id,
                        &btxs,
                    )
                    .map_err(|e| format!("wallet apply at h={}: {e}", job.height))?;
                    crate::wallet::maturity::promote_matured_boxes(&write_txn, job.height)
                        .map_err(|e| format!("wallet maturity at h={}: {e}", job.height))?;
                }
                // Only when scans are registered — skips opening/creating the
                // scan tables and the per-input spend-index probe otherwise.
                if payload.has_registered_scans {
                    crate::wallet::apply::apply_block_to_scans(
                        &write_txn,
                        &payload.scan_matches,
                        &btxs,
                        job.height,
                        &job.header_id,
                    )
                    .map_err(|e| format!("scan apply at h={}: {e}", job.height))?;
                }
            }
        }

        let commit_start = std::time::Instant::now();
        write_txn.commit().map_err(|e| e.to_string())?;
        Ok(commit_start.elapsed().as_secs_f64() * 1000.0)
    }
}

/// Panic-safe stderr write. `eprintln!` panics when stderr is broken
/// (closed pipe). This Drop runs on the shutdown path — if it panics,
/// the redb clean-shutdown commit is skipped and the database needs
/// repair on restart. Swallow write errors here so the join always
/// completes.
macro_rules! shutdown_log {
    ($($arg:tt)*) => {{
        use ::std::io::Write;
        let _ = ::std::writeln!(::std::io::stderr().lock(), $($arg)*);
    }};
}

impl Drop for PersistPipeline {
    fn drop(&mut self) {
        // Closing the sender causes `for job in rx` in persist_loop to
        // exit once the queue drains, releasing the Arc<Database> so redb
        // can write its clean-shutdown marker.
        let pending = self.tx.as_ref().map(|tx| tx.len()).unwrap_or(0);
        shutdown_log!(
            "[persist] shutdown: closing channel, {pending} job(s) queued + any in flight"
        );
        drop(self.tx.take());
        if let Some(handle) = self.thread.take() {
            let t0 = std::time::Instant::now();
            // Drain result events while waiting so we can surface per-job
            // commit times during the shutdown path.
            while !handle.is_finished() {
                std::thread::sleep(std::time::Duration::from_millis(500));
                while let Ok(r) = self.result_rx.try_recv() {
                    match r {
                        PersistResult::Ok { height, avl_writes, commit_ms } => shutdown_log!(
                            "[persist] drained h={height} writes={avl_writes} commit={commit_ms:.1}ms"
                        ),
                        PersistResult::Err { height, error } => shutdown_log!(
                            "[persist] drain ERROR at h={height}: {error}"
                        ),
                    }
                }
                let elapsed = t0.elapsed().as_secs_f64();
                shutdown_log!("[persist] still draining… {elapsed:.1}s elapsed");
            }
            if let Err(e) = handle.join() {
                shutdown_log!("[persist] thread join failed: {e:?}");
            } else {
                shutdown_log!(
                    "[persist] thread joined cleanly after {:.1}s",
                    t0.elapsed().as_secs_f64(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ----- helpers -----

    /// Build a minimal `PersistJob` at `height` whose execute_batch path
    /// writes only the redb tables that always populate (no AVL changes,
    /// no best-header bump, no voted params, no prune).
    fn minimal_job(height: u32) -> PersistJob {
        let mut undo_key = (height).to_be_bytes().to_vec();
        undo_key.extend_from_slice(&[height as u8; 32]);
        PersistJob {
            height,
            header_id: [height as u8; 32],
            avl_writes: Vec::new(),
            avl_deletes: Vec::new(),
            undo_key,
            undo_bytes: vec![0u8; 1],
            state_meta_bytes: vec![0u8; 1],
            alloc_meta_bytes: vec![0u8; 1],
            chain_state_bytes: vec![0u8; 1],
            best_header_bumped: false,
            old_best_header_height: 0,
            old_best_full_block_height: 0,
            durable: false,
            prune_below: None,
            parent_header_id: [0u8; 32],
            voted_params_row: None,
            wallet_payload: None,
        }
    }

    /// Build a `PersistJob` carrying a wallet payload with one
    /// tracked output. Used by the M5 atomic-pipeline test.
    fn job_with_tracked_output(
        height: u32,
        tracked_tree_bytes: Vec<u8>,
        output_box_id: [u8; 32],
        output_value: u64,
    ) -> PersistJob {
        let mut j = minimal_job(height);
        let mut trees = std::collections::BTreeSet::new();
        trees.insert(tracked_tree_bytes.clone());
        let tx = crate::store::OwnedBlockTxData {
            tx_id: [height as u8; 32],
            inputs: Vec::new(),
            outputs: vec![crate::store::OwnedBlockOutput {
                box_id: output_box_id,
                output_index: 0,
                ergo_tree_bytes: tracked_tree_bytes,
                value: output_value,
                assets: Vec::new(),
                miner_reward_pubkey: None,
                box_bytes: Vec::new(),
            }],
        };
        j.wallet_payload = Some(crate::store::WalletApplyPayload {
            tracked_p2pk_trees: trees,
            cached_pubkeys: std::collections::BTreeMap::new(),
            block_txs_owned: vec![tx],
            scan_matches: Vec::new(),
            has_registered_scans: false,
        });
        j
    }

    fn fresh_pipeline(queue_depth: usize) -> (tempfile::TempDir, PersistPipeline) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("persist.redb");
        let db = Arc::new(Database::create(&path).expect("create db"));
        // Tests don't exercise the per-epoch voted_params gate, so mainnet
        // voting_length is a safe default — the gate only fires on jobs
        // that carry `voted_params_row = Some(_)`, which the unit tests
        // here don't synthesize.
        let p = PersistPipeline::new(db, queue_depth, 1024, -1);
        (dir, p)
    }

    // ----- happy path -----

    #[test]
    fn flush_with_no_jobs_returns_immediately() {
        let (_d, p) = fresh_pipeline(1);
        // Vacuous barrier: nothing was ever queued.
        assert!(p.flush().is_none(), "flush of empty pipeline should be Ok");
    }

    #[test]
    fn flush_blocks_until_worker_commits() {
        let (_d, p) = fresh_pipeline(8);
        for h in 1..=4u32 {
            p.send(minimal_job(h)).expect("test pipeline alive");
        }
        // Real barrier: returns only after redb has committed all 4 jobs.
        assert!(p.flush().is_none());
        assert_eq!(p.sent_count.load(Ordering::Acquire), 4);
        let s = p.commit_watch.state.lock().unwrap();
        assert_eq!(
            s.committed_count, 4,
            "watch should reflect 4 committed jobs, got {}",
            s.committed_count
        );
    }

    /// M5 final-slice atomic-pipeline test: a `PersistJob` carrying
    /// `Some(wallet_payload)` lands wallet writes inside the same
    /// redb write_txn as chain mutations. The test sends a job
    /// with one tracked output, flushes, then opens the database
    /// and reads `WALLET_BOXES` directly to assert the entry
    /// committed atomically with the chain batch.
    ///
    /// Forcing function: if the worker dropped the payload (the
    /// pre-M5-final-slice behavior), `WALLET_BOXES` would be
    /// empty after flush. The assertion catches that regression
    /// without needing fixture-heavy CheckedBlock construction.
    #[test]
    fn worker_applies_wallet_payload_inside_batch_txn() {
        use crate::wallet::tables::WALLET_BOXES;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("persist.redb");
        let db = Arc::new(Database::create(&path).unwrap());
        let p = PersistPipeline::new(Arc::clone(&db), 4, 1024, -1);

        let tracked_tree = vec![0x00, 0x08, 0xCDu8, 0x02, 0xAA, 0xBB];
        let box_id = [0xA1u8; 32];
        let job = job_with_tracked_output(1, tracked_tree.clone(), box_id, 5_000_000_000);

        p.send(job).expect("send job");
        assert!(p.flush().is_none(), "flush succeeds, batch committed");
        drop(p);

        // Read WALLET_BOXES directly via a fresh read txn — the
        // worker's batch must have committed the wallet entry
        // atomically with the chain mutation.
        let read_txn = db.begin_read().unwrap();
        let tbl = read_txn
            .open_table(WALLET_BOXES)
            .expect("wallet table exists");
        let entry = tbl.get(box_id).expect("read box_id").map(|g| g.value());
        assert!(
            entry.is_some(),
            "WALLET_BOXES must contain the tracked output box_id after pipeline flush — \
             chain + wallet committed together inside the batch write_txn",
        );
    }

    // ----- error paths -----

    #[test]
    fn flush_target_already_drained_returns_immediately() {
        // Codex-third-pass regression: flush() must be honest even when
        // the result channel was drained before it was called. The
        // pre-fix implementation could block forever on `wait_for_height`
        // because the completion events had already been consumed. The
        // new commit-watch barrier does not depend on result-channel
        // state.
        let (_d, p) = fresh_pipeline(8);
        for h in 1..=3u32 {
            p.send(minimal_job(h)).expect("test pipeline alive");
        }
        // First flush waits for the worker.
        assert!(p.flush().is_none());
        // Drain the result channel so any subsequent recv() would block.
        let _ = p.drain_all_results();
        // Second flush must return immediately — the barrier is the
        // commit watch, not the result channel.
        let start = std::time::Instant::now();
        assert!(p.flush().is_none());
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "second flush blocked unexpectedly: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn wait_for_returns_error_when_closed_before_target_reached() {
        // `wait_for` must NOT return Ok(()) when `closed` is set if the
        // target wasn't reached and no error was recorded — otherwise
        // flush_persist_pipeline would lie to rollback_to and let the
        // database mutate against a stale durable tip. The Err for
        // close-without-commit is the contract this test pins.
        let watch = CommitWatch::new();
        let watch_signal = Arc::clone(&watch);
        let waiter = thread::spawn(move || watch.wait_for(5));
        // Tiny sleep to let the waiter park on the condvar.
        std::thread::sleep(Duration::from_millis(50));
        watch_signal.record_closed();
        let result = waiter.join().expect("waiter thread panicked");
        match result {
            Err((_, msg)) => {
                assert!(
                    msg.contains("persist worker exited"),
                    "unexpected error message: {msg}"
                );
            }
            Ok(()) => panic!("wait_for must NOT return Ok on close-without-target"),
        }
    }

    #[test]
    fn flush_honest_after_rollback_branch_swap() {
        // A height-based watermark from branch A would false-pass on any
        // branch-B target ≤ A's high-water — letting flush() return
        // before B's jobs commit and breaking the rollback/reorg
        // precondition. Count-based tracking is immune.
        //
        // We exercise the simulated branch swap directly on
        // `CommitWatch`: branch A "commits" 5 jobs at heights 96..=100,
        // then branch B sends 3 jobs (the producer would queue these
        // after a rollback). The watch tracks counts, so the new target
        // is 8 — branch A's 5 do NOT satisfy a target of 8.
        let watch = CommitWatch::new();
        watch.record_committed_jobs(5); // branch A
        let watch_clone = Arc::clone(&watch);
        let waiter = thread::spawn(move || watch_clone.wait_for(8));
        // Branch B is still in flight; waiter should be blocked.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiter.is_finished(),
            "wait_for(8) must block when committed_count is 5 — \
             a height-based barrier would have false-passed here"
        );
        // Worker commits branch B.
        watch.record_committed_jobs(3);
        // Now waiter must complete promptly.
        let result = waiter.join().expect("waiter thread panicked");
        assert!(
            result.is_ok(),
            "wait_for(8) should succeed once 8 jobs are committed"
        );
    }

    #[test]
    fn flush_honest_when_batch_overflows_result_channel() {
        // Codex-third-pass regression: smallest legal queue_depth is 1
        // (so result_rx capacity = 2). Submit a batch larger than that
        // capacity AND do NOT drain `result_rx` between submissions, so
        // the worker's per-job `try_send` silently drops completion
        // events. The pre-fix `flush()` had no way to know those drops
        // happened; the new commit-watch barrier records every
        // committed batch regardless of channel state.
        //
        // Note: queue_depth=1 backpressures the producer between sends,
        // so we get separate batches of size 1 — each commit increments
        // the watch but the result channel can still drop the second
        // and third events if try_recv doesn't keep pace.
        let (_d, p) = fresh_pipeline(1);
        for h in 1..=5u32 {
            p.send(minimal_job(h)).expect("test pipeline alive");
        }
        // No drain of result_rx between sends; events may have been
        // silently dropped on the worker side. flush() must still
        // return promptly with no error.
        assert!(p.flush().is_none());
        let s = p.commit_watch.state.lock().unwrap();
        assert_eq!(
            s.committed_count, 5,
            "watch should reflect every committed batch, got {}",
            s.committed_count
        );
    }

    // ----- poison recovery -----

    #[test]
    fn poisoned_mutex_does_not_panic_and_surfaces_closed_via_wait_for() {
        // Poison `CommitWatch.state` by panicking inside a thread that
        // is holding the lock. After the thread joins, the mutex is
        // poisoned — subsequent `.lock()` calls return Err(PoisonError).
        // The hardening contract is: every `CommitWatch` method must
        // recover via `into_inner()` instead of `.expect()`-panicking,
        // because callers (`flush_persist_pipeline` → `wait_for`) sit
        // on the rollback/reorg path and turning a poison into a panic
        // there is strictly worse than continuing with the prior state.
        let watch = CommitWatch::new();
        let w = Arc::clone(&watch);
        let _ = std::thread::spawn(move || {
            let _g = w.state.lock().expect("not poisoned yet");
            panic!("intentionally poisoning the mutex for test");
        })
        .join();
        assert!(
            watch.state.is_poisoned(),
            "thread panic should have poisoned the watch mutex",
        );

        // record_closed (called from WorkerWatchGuard::Drop) must not
        // panic on a poisoned mutex.
        watch.record_closed();

        // wait_for must surface the closed-with-zero-commits as the
        // designed error path, not panic on the lock.
        let r = watch.wait_for(1);
        assert!(
            matches!(r, Err((0, ref msg)) if msg.contains("persist worker exited")),
            "wait_for on poisoned+closed watch should return the worker-exited error, got {r:?}",
        );
    }

    #[test]
    fn poisoned_mutex_record_error_surfaces_via_wait_for() {
        let watch = CommitWatch::new();
        let w = Arc::clone(&watch);
        let _ = std::thread::spawn(move || {
            let _g = w.state.lock().expect("not poisoned yet");
            panic!("intentionally poisoning the mutex for test");
        })
        .join();
        assert!(watch.state.is_poisoned());

        // record_error on a poisoned mutex must not panic and must
        // still let wait_for surface the recorded error.
        watch.record_error(42, "test error".to_string());
        let r = watch.wait_for(1);
        assert!(
            matches!(r, Err((42, ref e)) if e == "test error"),
            "wait_for should surface the recorded error, got {r:?}",
        );
    }

    #[test]
    fn send_after_tx_taken_yields_invalid_precondition() {
        // Pins the post-shutdown classification: clearing `tx` is a
        // caller-lifecycle event, so `send()` must report it as a
        // precondition violation rather than as an internal failure.
        let (_d, mut p) = fresh_pipeline(1);
        // Simulate the Drop-time `self.tx.take()` step. Dropping the
        // taken sender closes the channel and lets the spawned worker
        // exit cleanly so the test's later Drop joins quickly.
        let _closed = p.tx.take();
        let err = p
            .send(minimal_job(1))
            .expect_err("send after tx.take() must error");
        match err {
            StateError::InvalidPrecondition { what } => {
                assert!(
                    what.contains("persist pipeline already shut down"),
                    "unexpected `what`: {what}"
                );
            }
            other => panic!("expected InvalidPrecondition, got {other:?}"),
        }
    }

    #[test]
    fn send_after_receiver_dropped_yields_internal_invariant() {
        // Pins the worker-died classification. We splice in a sender
        // whose receiver has been dropped; the real worker has already
        // exited (its rx closed when we replaced the original tx).
        let (_d, mut p) = fresh_pipeline(1);
        let (orphan_tx, orphan_rx) = bounded::<PersistJob>(1);
        drop(orphan_rx);
        p.tx = Some(orphan_tx);
        let err = p
            .send(minimal_job(1))
            .expect_err("send to closed channel must error");
        match err {
            StateError::InternalInvariant { what } => {
                assert!(
                    what.contains("persist worker thread died"),
                    "unexpected `what`: {what}"
                );
            }
            other => panic!("expected InternalInvariant, got {other:?}"),
        }
    }
}

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
//! either applies one block, rolls one block back, sleeps when caught
//! up, or surfaces a halt/race condition. The async [`IndexerTask::run`]
//! driver loop turns those outcomes into a long-running task — backing
//! off on section-missing (5 × 1 s), tight-looping while behind, and
//! idling on `Idle`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ergo_ser::transaction::Transaction;

use crate::apply::{apply_block_with_scratch, IndexerBlock};
use crate::error::{HeightOverflowContext, IndexerError};
use crate::handle::IndexerHandle;
use crate::rollback::rollback_one_block;
use crate::scratch::BlockApplyScratch;
use crate::store::{IndexerMeta, IndexerStore};
use crate::HeaderId;
use ergo_indexer_types::{IndexerHaltReason, IndexerStatus};

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
pub trait IndexerChainSource: Send + Sync {
    /// Committed tip as `(height, header_id)`. Must be a single atomic
    /// snapshot — two reads from the same poll may otherwise see
    /// different values (the chain reader opens a fresh redb txn per
    /// call, so callers cannot count on snapshot stability).
    fn committed_tip(&self) -> ChainTip;

    /// Canonical header_id at `height`, or `None` if past the tip / no
    /// chain has been written / the height has been pruned.
    fn header_id_at(&self, height: u32) -> Option<HeaderId>;

    /// Block (height + header_id + parsed transactions) by header_id.
    /// `None` when the chain has the header but section bytes haven't
    /// landed yet — driver retries with bounded backoff.
    fn full_block(&self, header_id: &HeaderId) -> Option<IndexerFullBlock>;
}

/// Outcome of one `step` iteration. The async [`IndexerTask::run`]
/// driver maps each variant to a sleep / retry / halt decision.
#[derive(Debug)]
pub enum IndexerPoll {
    /// Caught up. Status was set to `CaughtUp`.
    Idle,
    /// Forward-applied the block at this height.
    Applied(u64),
    /// Rolled back the tip; the height in the variant is the height
    /// that was rolled back (post-rollback tip is `height - 1`).
    RolledBack(u64),
    /// Header is canonical but section bytes are missing — chain crash
    /// window. Driver retries with bounded backoff.
    SectionRetry { header_id: HeaderId, height: u64 },
    /// Mid-load fork flip: header_id at the target height changed
    /// between the "load" and "re-verify" reads. Retry next iteration.
    Race,
    /// Indexer halted with this error. Terminal — driver exits.
    Halted(IndexerError),
}

/// Polling task. Holds the indexer handle (status + height mirror), an
/// `Arc` to a chain source, and a long-lived `BlockApplyScratch` reused
/// across every `apply_block_with_scratch` call so per-block / per-tx
/// allocations amortize over the run.
pub struct IndexerTask<C: IndexerChainSource> {
    handle: IndexerHandle,
    chain: Arc<C>,
    scratch: BlockApplyScratch,
}

impl<C: IndexerChainSource> IndexerTask<C> {
    pub fn new(handle: IndexerHandle, chain: Arc<C>) -> Self {
        Self {
            handle,
            chain,
            scratch: BlockApplyScratch::new(),
        }
    }

    /// One poll iteration. Synchronous — does no sleeping itself.
    ///
    /// Order: reorg check → caught-up check → forward
    /// load+verify+apply.
    pub fn step(&mut self) -> IndexerPoll {
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

        let tip = self.chain.committed_tip();

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
            match self.chain.header_id_at(our_h) {
                None => return self.do_rollback(&store, &meta, prev_id),
                Some(id) if id != prev_id => {
                    return self.do_rollback(&store, &meta, prev_id);
                }
                Some(_) => {}
            }
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

        let header_id = match self.chain.header_id_at(next_h32) {
            Some(id) => id,
            None => return IndexerPoll::Race,
        };

        let block = match self.chain.full_block(&header_id) {
            Some(b) => b,
            None => {
                return IndexerPoll::SectionRetry {
                    header_id,
                    height: next_height,
                };
            }
        };

        if self.chain.header_id_at(next_h32) != Some(header_id) {
            return IndexerPoll::Race;
        }

        let indexer_block = IndexerBlock {
            height: block.height,
            header_id: block.header_id,
            transactions: &block.transactions,
        };
        match apply_block_with_scratch(&store, &meta, &indexer_block, &mut self.scratch) {
            Ok(next_meta) => {
                self.handle.set_indexed_height(next_meta.indexed_height);
                IndexerPoll::Applied(next_meta.indexed_height)
            }
            Err(e) => IndexerPoll::Halted(e),
        }
    }

    fn do_rollback(
        &self,
        store: &IndexerStore,
        meta: &IndexerMeta,
        prev_id: HeaderId,
    ) -> IndexerPoll {
        self.handle.set_status(IndexerStatus::Syncing);

        let block = match self.chain.full_block(&prev_id) {
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
        match rollback_one_block(store, meta, &indexer_block) {
            Ok(next_meta) => {
                self.handle.set_indexed_height(next_meta.indexed_height);
                IndexerPoll::RolledBack(prev_height)
            }
            Err(e) => IndexerPoll::Halted(e),
        }
    }

    /// Long-running driver loop. Exits cleanly when `cancel` flips to
    /// `true`, halts on terminal errors (sets `IndexerStatus::Halted`
    /// and returns).
    ///
    /// Sleeping policy:
    /// - `Idle`: sleep `poll_idle`.
    /// - `Applied` / `RolledBack`: tight loop (no sleep — backfill
    ///   throughput is bound by I/O, not wall clock).
    /// - `Race`: tight loop (the chain just raced under us).
    /// - `SectionRetry`: 1 s backoff per attempt; halt
    ///   `SectionMissing` after [`MAX_SECTION_RETRIES`].
    /// - `Halted`: set status, exit.
    pub async fn run(mut self, cancel: Arc<AtomicBool>, poll_idle: Duration) {
        let mut section_retry_count: u32 = 0;
        loop {
            if cancel.load(Ordering::Acquire) {
                return;
            }
            match self.step() {
                IndexerPoll::Idle => {
                    section_retry_count = 0;
                    if !sleep_or_cancel(poll_idle, &cancel).await {
                        return;
                    }
                }
                IndexerPoll::Applied(_) | IndexerPoll::RolledBack(_) | IndexerPoll::Race => {
                    section_retry_count = 0;
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
                    if !sleep_or_cancel(SECTION_RETRY_DELAY, &cancel).await {
                        return;
                    }
                }
                IndexerPoll::Halted(e) => {
                    let reason = e.halt_reason();
                    tracing::error!(error = %e, reason = ?reason, "indexer halted in-loop");
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

/// Returns `true` if the sleep elapsed; `false` if the cancel flag
/// flipped during sleep. Used by the driver loop to exit promptly on
/// shutdown.
async fn sleep_or_cancel(d: Duration, cancel: &AtomicBool) -> bool {
    tokio::time::sleep(d).await;
    !cancel.load(Ordering::Acquire)
}

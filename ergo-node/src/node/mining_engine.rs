//! The off-loop mining-candidate engine task.
//!
//! Runs on its own tokio task, fed `BuildIntent`s by the action loop over a
//! `watch` channel and driving [`ergo_mining::engine::build_and_publish`] off
//! the single-writer loop. Each build opens one committed redb snapshot and
//! CAS-publishes the result into the served cache; the action loop owns tip
//! invalidation (`MiningHandle::set_best_tip`) and the API serves the cache
//! only (`MiningHandle::cached_work_if_synced`).
//!
//! The `watch` channel coalesces, so the task always builds the *latest*
//! intent — rapid tip/mempool churn collapses to one build, never a backlog.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ergo_mining::engine::{build_and_publish, BuildOutcome};
use ergo_mining::handle::MiningHandle;
use ergo_ser::ergo_box::ErgoBox;
use ergo_state::reader::ChainStoreReader;
use ergo_state::store::CommittedSnapshot;
use ergo_validation::UtxoView;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Storage-rent period in blocks (≈ 4 years). Non-votable protocol
/// constant; mirrors `ergo-validation`'s `storage_period`. A box is
/// rent-eligible at height `H` when its `creationHeight <= H - this`.
const STORAGE_PERIOD_BLOCKS: u32 = 1_051_200;

/// Enumerate storage-rent-eligible boxes for the miner self-claim:
/// oldest-first, capped at `max_claims`, each resolved to a full `ErgoBox`
/// from the SAME committed snapshot the candidate builds against (the
/// indexer DTO carries no script/tokens/registers). Boxes the snapshot
/// cannot return (spent since the index scan, or a reorg) are skipped —
/// never claimed blind. Degrades to empty (build without a rent claim)
/// when no indexer is attached, the chain is younger than one storage
/// period, or the index query fails — rent is policy, and a policy
/// failure must never block candidate production.
fn resolve_eligible_rent_boxes(
    indexer: Option<&ergo_indexer::IndexerHandle>,
    snapshot: &CommittedSnapshot,
    candidate_height: u32,
    max_claims: u32,
) -> Vec<ErgoBox> {
    let Some(store_idx) = indexer.and_then(|h| h.store()) else {
        return Vec::new();
    };
    let Some(height_cutoff) = candidate_height.checked_sub(STORAGE_PERIOD_BLOCKS) else {
        return Vec::new();
    };
    let rows = match store_idx.read_storage_rent_eligible_paged(
        height_cutoff,
        0,
        max_claims,
        ergo_indexer::SortDir::Asc,
    ) {
        Ok(rows) => rows,
        Err(e) => {
            warn!(
                error = ?e,
                "mining: storage-rent resolution failed; building without rent self-claim",
            );
            return Vec::new();
        }
    };
    let mut boxes = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(b) = snapshot.get_box(&row.box_id) {
            boxes.push(b);
        }
    }
    boxes
}

/// Backoff between commit-visibility retries (the committed redb tip trailing
/// the in-memory tip the loop signalled). Short: persist-pipeline lag clears
/// in well under a tick in the common case.
const VIS_BACKOFF: Duration = Duration::from_millis(25);

/// Cap on commit-visibility retries for a single intent (~1s worst case at
/// [`VIS_BACKOFF`]). On exhaustion the task stops retrying and waits for the
/// next intent rather than spinning on a stalled persist pipeline.
const MAX_VIS_RETRIES: u32 = 40;

/// `build_ms` at or above this logs the build-complete line at `warn!` instead
/// of `info!`: a build this slow leaves the new tip unservable for its whole
/// duration (the 503 window the two-phase publish bounds), so it is
/// operator-actionable, not routine.
const SLOW_BUILD_WARN_MS: u64 = 2_000;

/// Drive the off-loop candidate engine until cancelled.
///
/// Blocks on the intent channel; on each new (coalesced) intent, runs the
/// build to a terminal [`BuildOutcome`] with bounded commit-visibility retry.
/// `TipNotVisible` (committed tip behind the intent's expected parent) retries
/// after a short backoff, re-reading the latest intent each attempt so a newer
/// intent supersedes the current one (latest-wins). All other outcomes are
/// terminal for the intent.
///
/// `indexer` is forwarded into the rent resolver closure passed to
/// `build_and_publish`; storage-rent boxes are resolved against the same
/// committed snapshot the candidate builds from.
///
/// Exits when `cancel_rx` flips to `true` (clean shutdown) or the producer
/// (action loop) drops the intent sender.
pub(super) async fn run_mining_engine(
    reader: ChainStoreReader,
    handle: MiningHandle,
    indexer: Option<ergo_indexer::IndexerHandle>,
    mut intent_rx: watch::Receiver<Option<ergo_mining::engine::BuildIntent>>,
    mut cancel_rx: watch::Receiver<bool>,
) {
    loop {
        // Wait for a new intent (or cancellation). `watch` retains the latest
        // value, so an intent published before this await is picked up below.
        tokio::select! {
            biased;
            _ = cancel_rx.changed() => break,
            changed = intent_rx.changed() => {
                if changed.is_err() {
                    break; // producer gone (action loop exited) → shut down
                }
            }
        }
        if *cancel_rx.borrow() {
            break;
        }

        let mut attempts = 0u32;
        loop {
            // Re-borrow each attempt: a newer intent that arrived mid-retry
            // supersedes this one (latest-wins).
            let intent = match intent_rx.borrow_and_update().clone() {
                Some(i) => i,
                None => break,
            };
            // Wall-clock closure, sampled by the engine core at the publish
            // step so the stamped time is when the template is actually
            // published (not when this possibly-retried build started). Kept in
            // the async task, not the engine core, so the core stays clock-free
            // and deterministic under test.
            let now_ms = || {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            };
            // Time the build itself (excludes the inter-retry backoff sleeps),
            // so `build_ms` is the candidate-assembly latency — the headline
            // observability metric (and the trigger for the deferred per-tip
            // base-cache decision). `outcome` doubles as the CAS-drop counter
            // (`DroppedStale`) and `attempts` as the commit-visibility retry
            // count.
            let build_start = Instant::now();
            let result = build_and_publish(&reader, &handle, &intent, now_ms, |snapshot, h| {
                resolve_eligible_rent_boxes(
                    indexer.as_ref(),
                    snapshot,
                    h,
                    handle.max_storage_rent_claims(),
                )
            });
            let build_ms = build_start.elapsed().as_millis() as u64;
            match result {
                Ok(BuildOutcome::TipNotVisible) if attempts < MAX_VIS_RETRIES => {
                    attempts += 1;
                    tokio::select! {
                        biased;
                        _ = cancel_rx.changed() => return,
                        _ = tokio::time::sleep(VIS_BACKOFF) => {}
                    }
                }
                Ok(BuildOutcome::Published { timings: t }) => {
                    // One message key for fast and slow builds: the level carries
                    // the slow/fast dimension, so a scraper aggregating build_ms
                    // by message template sees the whole population.
                    // tracing 0.1 requires a const-level callsite, so we branch
                    // on the two concrete macros while keeping the message
                    // template identical.
                    macro_rules! emit_build_complete {
                        ($mac:ident) => {
                            $mac!(
                                attempts,
                                build_ms,
                                emission_ms = t.emission.as_millis() as u64,
                                rent_ms = t.rent.as_millis() as u64,
                                select_ms = t.select.as_millis() as u64,
                                dryrun_ms = t.dryrun.as_millis() as u64,
                                roots_ms = t.roots.as_millis() as u64,
                                reason = ?intent.reason,
                                "mining engine: build complete",
                            )
                        };
                    }
                    if build_ms >= SLOW_BUILD_WARN_MS {
                        emit_build_complete!(warn);
                    } else {
                        emit_build_complete!(info);
                    }
                    break;
                }
                Ok(BuildOutcome::TipNotVisible) => {
                    // The guarded arm above exhausted MAX_VIS_RETRIES: the
                    // committed tip never caught up to the intent's parent
                    // (persist pipeline stalled or badly lagging). Surfaced at
                    // warn! — candidates stop refreshing for this tip until the
                    // next intent.
                    warn!(
                        attempts,
                        build_ms,
                        reason = ?intent.reason,
                        "mining engine: commit-visibility retries exhausted; awaiting next intent",
                    );
                    break;
                }
                Ok(outcome) => {
                    debug!(
                        ?outcome,
                        attempts,
                        build_ms,
                        reason = ?intent.reason,
                        "mining engine: build not published",
                    );
                    break;
                }
                Err(e) => {
                    warn!(
                        error = ?e,
                        build_ms,
                        reason = ?intent.reason,
                        "mining engine: build failed",
                    );
                    break;
                }
            }
        }
    }
    debug!("mining engine task exiting");
}

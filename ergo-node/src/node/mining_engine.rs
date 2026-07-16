//! The off-loop mining-candidate engine.
//!
//! Split into an async **coordinator** and a synchronous build **worker**:
//!
//! - The coordinator runs on its own tokio task, fed `BuildIntent`s by the
//!   action loop over a `watch` channel. It owns all sequencing — mode probe,
//!   minimal→full refresh rule, the commit-visibility retry budget, cancel
//!   handling, and every build-complete/failure log line. It holds only the
//!   `mpsc::Sender<BuildRequest>` end of the build channel, never the worker
//!   thread.
//! - The worker is a dedicated [`std::thread`] that owns the
//!   [`ChainStoreReader`], the [`MiningHandle`] clone, and the indexer handle.
//!   It receives [`BuildRequest`]s over a `std::sync::mpsc` channel, runs the
//!   synchronous [`ergo_mining::engine::build_and_publish`] for each, and
//!   returns the result over the request's `oneshot`.
//!
//! ## Lifecycle: spawner owns the thread, the future owns the sender
//!
//! The build worker is spawned by [`boot`](super::boot) (production) or by the
//! engine tests, *not* by [`run_mining_engine`]. The spawner keeps the worker's
//! [`JoinHandle`](std::thread::JoinHandle); the coordinator future owns only the
//! `mpsc::Sender<BuildRequest>`. This split is load-bearing for shutdown.
//!
//! `RunHandle::shutdown` awaits the coordinator task under a bounded timeout and
//! then `abort()`s it. At rest the coordinator is parked at `reply_rx.await` — an
//! abort point — so an abort drops the future. Because the future owns the
//! sender (not the thread), dropping it on *any* exit — cooperative return or
//! abort-drop — closes the channel; the worker's `recv()` then errs, it drains
//! its at-most-one in-flight build, and exits. Shutdown joins the worker thread
//! *after* the coordinator is gone, via the `JoinHandle` it kept, so a worker
//! still finishing a build can never detach and keep reading/publishing past
//! shutdown. Pre-split the worker handle lived inside the future and was dropped
//! (detached) on abort — exactly the regression this ownership inversion closes.
//!
//! The worker is a plain OS thread, not a tokio task, by design: it will own
//! the per-tip dry-run base cache — an `Rc<RefCell<Node>>` AVL graph that is
//! `!Send` and therefore cannot live in a tokio-spawned (`Send`-bound) future.
//! Keeping the build on a single owning thread is what lets that graph be
//! reused across same-tip builds. With no cache yet (this phase) the thread is
//! pure topology: every build full-hydrates exactly as the inline build did.
//!
//! Each build opens one committed redb snapshot and CAS-publishes the result
//! into the served cache; the action loop owns tip invalidation
//! (`MiningHandle::set_best_tip`) and the API serves the cache only
//! (`MiningHandle::cached_work_if_synced`).
//!
//! The `watch` channel coalesces, so the coordinator always builds the
//! *latest* intent — rapid tip/mempool churn collapses to one build, never a
//! backlog. Builds are serial: the coordinator awaits each reply before
//! issuing the next request, so at most one build is ever in flight.
//!
//! Two-phase publish per tip: a full candidate build can take seconds, during
//! which `/mining/candidate` 503s for the new tip. So on a tip's *first* build
//! the engine publishes a minimal, emission-only template
//! ([`BuildMode::Minimal`] — consensus-complete; it forfeits only the fees for
//! the few seconds until the refresh), then immediately rebuilds enriched
//! ([`BuildMode::Full`] — rent self-claim + mempool selection + fee tx) as a
//! same-parent refresh that the serve path's newest-matching-parent scan
//! supersedes the minimal one with. The mode is chosen by probing the served
//! ring for the parent ([`MiningHandle::has_template_for_parent`]), so the
//! decision stays correct across superseded intents and ABA reorgs. `clean_jobs`
//! fires once, on the minimal publish (it derives from `chain_seq`, which the
//! refresh leaves unchanged). A quiet pool with rent disabled makes the full
//! build byte-equivalent to the minimal one (modulo timestamp), so that
//! redundant refresh is skipped — one publish per tip, no template-ring churn.
//!
//! A build in flight is never preempted — a tip arriving mid-build is observed
//! at the next loop iteration (the stale build's publish CAS-drops), so the
//! worst-case serve gap for a new tip is the in-flight build's remainder plus
//! the new tip's minimal build.

use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ergo_indexer::StorageRentEligibleDto;
use ergo_mining::candidate::BuildMode;
use ergo_mining::engine::{build_and_publish, BuildIntent, BuildOutcome};
use ergo_mining::error::MiningError;
use ergo_mining::handle::MiningHandle;
use ergo_ser::ergo_box::ErgoBox;
use ergo_state::reader::ChainStoreReader;
use ergo_state::store::{BaseDisposition, CommittedSnapshot, DryRunBase};
use ergo_validation::UtxoView;
use tokio::sync::{oneshot, watch};
use tracing::{debug, error, info, warn};

/// Storage-rent period in blocks (≈ 4 years). Non-votable protocol
/// constant; mirrors `ergo-validation`'s `storage_period`. A box is
/// rent-eligible at height `H` when its `creationHeight <= H - this`.
const STORAGE_PERIOD_BLOCKS: u32 = 1_051_200;

/// Hard bound on indexer pages fetched per build. Stale rows (indexer lag or
/// a recent reorg) are filtered against the build snapshot and backfilled
/// from subsequent pages; this caps the worst-case scan when the index is
/// badly behind so a build never stalls on unbounded indexer reads.
///
/// Page size is `max_storage_rent_claims`, so the worst-case scan is
/// `MAX_RENT_PAGES * max_claims` rows: a small claim cap also shrinks the
/// stale-row recovery window. That is acceptable — rent is opt-in policy, and
/// a build that under-collects under heavy index lag still produces a valid
/// candidate (the missed boxes stay eligible for the next build once the
/// index catches up). Correctness never depends on collecting every box.
const MAX_RENT_PAGES: u32 = 4;

/// Enumerate storage-rent-eligible boxes for the miner self-claim:
/// oldest-first, capped at `max_claims`, each materialized to a full
/// `ErgoBox` from the committed snapshot the candidate builds against (the
/// indexer DTO carries no script/tokens/registers).
///
/// The eligible-id *page* comes from the indexer's own eventually-consistent
/// extra-index, which can trail the build snapshot by some apply/reorg lag.
/// Box materialization, though, uses the committed snapshot: rows the
/// snapshot cannot return (spent since the index scan, or rolled back by a
/// reorg) are skipped, and their cap slots backfilled from later pages, so
/// index staleness costs retries rather than claim slots. Boxes are never
/// claimed blind off the index alone.
///
/// Degrades to empty (build without a rent claim) when the indexer store is
/// unavailable, the chain is younger than one storage period, or the index
/// query fails — rent is policy, and a policy failure must never block
/// candidate production.
fn resolve_eligible_rent_boxes(
    indexer: Option<&ergo_indexer::IndexerHandle>,
    snapshot: &CommittedSnapshot,
    candidate_height: u32,
    max_claims: u32,
) -> Vec<ErgoBox> {
    let Some(store_idx) = indexer.and_then(|h| h.store()) else {
        // Boot-time config validation requires the indexer when rent claiming
        // is enabled, so an absent store here means the indexer halted —
        // surfaced so "rent stopped working" is distinguishable from "no
        // eligible boxes".
        warn!(
            "mining: rent claiming enabled but indexer store unavailable; building without rent self-claim"
        );
        return Vec::new();
    };
    // Silent: a chain younger than one storage period simply has no eligible
    // boxes yet — normal on young chains, not operator-actionable.
    let Some(height_cutoff) = candidate_height.checked_sub(STORAGE_PERIOD_BLOCKS) else {
        return Vec::new();
    };
    page_rent_boxes(
        |off, lim| {
            store_idx.read_storage_rent_eligible_paged(
                height_cutoff,
                off,
                lim,
                ergo_indexer::SortDir::Asc,
            )
        },
        |id| snapshot.get_box(id),
        max_claims,
    )
}

/// Page through eligible-box rows, materializing each against the build
/// snapshot, until `max_claims` boxes resolve or the index runs dry.
///
/// Rows the snapshot cannot materialize (spent since the index scan, or a
/// reorg) are skipped and their cap slots backfilled from later pages, so
/// indexer staleness costs retries, not claim slots. A fetch error degrades
/// the whole resolution to empty (build without a rent claim) — a partial
/// set is economically fine, but inconsistent-on-error is harder to reason
/// about, so the contract is all-or-nothing. Generic over the page fetcher
/// so the backfill/degrade logic is unit-testable without an indexer store.
///
/// Each page is a separate indexer read transaction
/// (`read_storage_rent_eligible_paged` opens its own) and `offset` is a
/// skip-by-row-count cursor, so a rollback/apply landing between two reads can
/// shift the ordered row set under the offset. Two consequences, both bounded
/// to under-collection (never a wrong or blind claim, never a build abort):
///
/// - A `box_id` already taken can re-surface on a later page. The rent-claim
///   builder does not dedup its inputs, so an undeduped repeat would produce a
///   within-tx double-spend that fails the build — the `seen` set drops the
///   repeat so the race costs a skipped row, not the candidate.
/// - Front rows deleted between reads shift later rows left, under the
///   advanced `offset`, so a live box can be stepped over and missed this
///   build. It stays eligible and is collected on a later build once the index
///   settles. Backfill therefore covers stale rows *within* a page, not rows
///   that move across the page boundary mid-scan; the worst case is collecting
///   fewer boxes than `max_claims`, which is fine — rent is opt-in policy and
///   correctness never depends on collecting every eligible box.
fn page_rent_boxes<E: std::fmt::Debug>(
    mut fetch_page: impl FnMut(u32, u32) -> Result<Vec<StorageRentEligibleDto>, E>,
    resolve_box: impl Fn(&ergo_primitives::digest::Digest32) -> Option<ErgoBox>,
    max_claims: u32,
) -> Vec<ErgoBox> {
    // A zero claim cap collects nothing — short-circuit before issuing any
    // (zero-limit) indexer reads.
    if max_claims == 0 {
        return Vec::new();
    }
    let mut boxes = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut offset = 0u32;
    for _ in 0..MAX_RENT_PAGES {
        let rows = match fetch_page(offset, max_claims) {
            Ok(rows) => rows,
            Err(e) => {
                warn!(
                    error = ?e,
                    "mining: storage-rent resolution failed; building without rent self-claim",
                );
                return Vec::new();
            }
        };
        let page_len = rows.len() as u32;
        for row in rows {
            // Skip a `box_id` already claimed — a duplicate from the
            // moving-index race (see fn doc), never a second claim of the
            // same box.
            if !seen.insert(row.box_id) {
                continue;
            }
            if let Some(b) = resolve_box(&row.box_id) {
                boxes.push(b);
                if boxes.len() as u32 == max_claims {
                    return boxes;
                }
            }
        }
        if page_len < max_claims {
            break; // index exhausted (short page)
        }
        offset += page_len;
    }
    boxes
}

/// Whether the enriched (Full) refresh after a minimal publish would add
/// nothing: an empty frozen pool with rent claiming off makes the full build
/// byte-equivalent to the minimal one (modulo timestamp), so a second publish
/// is pure template-ring churn.
fn full_refresh_adds_nothing(
    intent: &ergo_mining::engine::BuildIntent,
    handle: &MiningHandle,
) -> bool {
    intent.mempool.is_empty() && !handle.claim_storage_rent()
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

/// One build job handed from the coordinator to the build worker. The
/// coordinator owns every sequencing decision (mode probe, retry budget,
/// minimal→full refresh); the worker only executes the build serially and
/// returns the result over `reply`.
///
/// `pub(super)` because the request channel is created by the spawner (boot or
/// the engine tests) — it owns the worker thread, the coordinator future owns
/// only the `Sender<BuildRequest>` — so the type must be nameable there even
/// though only `run_mining_engine` ever constructs a `BuildRequest`.
pub(super) struct BuildRequest {
    intent: BuildIntent,
    mode: BuildMode,
    /// Response channel. The coordinator awaits exactly one reply per request,
    /// so the request→reply protocol stays strictly serial (≤1 in flight).
    ///
    /// The reply carries the build result plus the dry-run base-cache
    /// disposition string for the build-complete log line:
    /// `"off"` (cache disabled), `"primed"` (tip hit), `"advanced"` (single-step
    /// advance succeeded), `"cold"` (full rehydrate), or `"cold_fallback"`
    /// (advance attempted, failed, fell back to rehydrate). The disposition is
    /// computed on the worker — the only place that can observe the cache slot
    /// state after the build — and threaded back here because the log lines live
    /// on the coordinator.
    reply: oneshot::Sender<(Result<BuildOutcome, MiningError>, &'static str)>,
}

/// Run the build worker loop until the request channel closes.
///
/// Owns the redb [`ChainStoreReader`], the [`MiningHandle`] clone, and the
/// indexer handle for the engine's lifetime, executing one
/// [`build_and_publish`] per [`BuildRequest`]. The wall-clock `now_ms` closure
/// and the storage-rent resolver both live here (they capture only `Send`
/// things — the indexer and mining handles) so the coordinator stays clock-
/// and indexer-free, exactly as the inline build did.
///
/// `reply` send errors are ignored: a dropped receiver means the coordinator
/// has gone, in which case the next `recv()` returns `Err` and the loop exits.
///
/// Spawned by [`boot`](super::boot) (production) or directly by the engine
/// tests, never by [`run_mining_engine`]: the spawner owns the worker
/// [`JoinHandle`](std::thread::JoinHandle) so shutdown can join it *after* the
/// coordinator future is gone, whereas the future owns only the `req_tx`. That
/// ownership split is what lets the worker drain its in-flight build and exit
/// even when `RunHandle::shutdown` aborts the coordinator at an await point.
/// `use_base_cache` enables the per-tip dry-run base cache
/// (`[mining] candidate_base_cache`, threaded from boot). When on, the worker
/// owns a single [`DryRunBase`] slot across requests and passes it into each
/// build, so same-tip rebuilds reuse the memoized pristine AVL tree instead of
/// re-hydrating the whole UTXO graph; on a tip change or any mid-apply failure
/// the slot self-invalidates (the `ergo-state` poison contract). The slot is
/// `!Send`, which is exactly why the worker is a plain OS thread and not a
/// tokio task. Off (the default), the slot stays `None` and every build
/// full-hydrates — bit-for-bit today's behaviour.
pub(super) fn run_build_worker(
    reader: ChainStoreReader,
    handle: MiningHandle,
    indexer: Option<ergo_indexer::IndexerHandle>,
    use_base_cache: bool,
    req_rx: mpsc::Receiver<BuildRequest>,
) {
    // The per-tip pristine dry-run base, owned across requests so a same-tip
    // rebuild reuses it. `!Send` (an `Rc<RefCell<Node>>` graph) — sound here
    // because this worker is the single serial consumer. `None` when the cache
    // is disabled; then every build full-hydrates exactly as before.
    let mut base: Option<DryRunBase> = None;
    while let Ok(BuildRequest {
        intent,
        mode,
        reply,
    }) = req_rx.recv()
    {
        // Wall-clock closure, sampled by the engine core at the publish step so
        // the stamped time is when the template is actually published (not when
        // this possibly-retried build started). Lives on the worker, not the
        // engine core, so the core stays clock-free and deterministic under
        // test.
        let now_ms = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        };
        // Base-cache disposition, set by `build_and_publish` when the build
        // actually ran (i.e. `generate_candidate` was called). When the cache
        // is disabled (no `base` slot), or when the build returns an early
        // outcome (TipNotVisible / IntentSuperseded / NotSynced / NoState),
        // the disposition stays `None` and we fall back to a sensible wire
        // label.
        let mut raw_disposition: Option<BaseDisposition> = None;
        let result = build_and_publish(
            &reader,
            &handle,
            &intent,
            mode,
            use_base_cache.then_some(&mut base),
            now_ms,
            |snapshot, h| {
                resolve_eligible_rent_boxes(
                    indexer.as_ref(),
                    snapshot,
                    h,
                    handle.max_storage_rent_claims(),
                )
            },
            &mut raw_disposition,
        );
        // Map the returned disposition to the wire string the coordinator logs.
        // `"off"` when the cache is disabled; `"advanced"` / `"primed"` /
        // `"cold"` / `"cold_fallback"` from the actual path taken.
        // Non-building outcomes (TipNotVisible etc.) leave `raw_disposition`
        // `None`; we keep `"off"` when the cache is disabled and `"cold"` as
        // the fallback for the non-building paths (the slot is unaffected, so
        // its pre-call state is the nearest truth).
        let base_cache: &'static str = if !use_base_cache {
            "off"
        } else {
            match raw_disposition {
                Some(BaseDisposition::Hit) => "primed",
                Some(BaseDisposition::Advanced) => "advanced",
                Some(BaseDisposition::Rehydrated) => "cold",
                Some(BaseDisposition::RehydratedAfterFailedAdvance) => "cold_fallback",
                // Cache enabled but no build ran (early-return outcome): keep
                // the pre-call slot state as an approximation.
                None => {
                    if base.as_ref().map(DryRunBase::tip_id) == Some(intent.expected_parent) {
                        "primed"
                    } else {
                        "cold"
                    }
                }
            }
        };
        // Coordinator gone (receiver dropped) ⇒ ignore; the next `recv()` errs
        // and the loop exits.
        let _ = reply.send((result, base_cache));
    }
}

/// Drive the off-loop candidate engine until cancelled.
///
/// The async coordinator: blocks on the intent channel; on each new (coalesced)
/// intent, drives the build to a terminal [`BuildOutcome`] with bounded
/// commit-visibility retry. Each build is dispatched over `req_tx` to the
/// dedicated build worker thread — spawned by the caller
/// ([`boot`](super::boot) or the engine tests), which keeps its `JoinHandle` —
/// and the coordinator awaits the reply. `TipNotVisible` (committed tip behind
/// the intent's expected parent) retries after a short backoff, re-reading the
/// latest intent each attempt so a newer intent supersedes the current one
/// (latest-wins). All other outcomes are terminal for the intent.
///
/// The coordinator keeps `handle` for the mode probe and refresh predicate; the
/// `reader`/`indexer`/worker-`handle` live in the worker thread the caller
/// spawned ([`run_build_worker`]). The future owns *only* `req_tx`: on any exit
/// — clean cancel, producer-drop, OR a `shutdown`-driven `abort()` at the
/// `reply_rx.await` point — `req_tx` drops, the worker's `recv()` errs, and it
/// drains its in-flight build then exits. The caller joins the worker thread
/// after this future is gone; the future never joins a handle it does not own.
///
/// Exits when `cancel_rx` flips to `true` (clean shutdown) or the producer
/// (action loop) drops the intent sender.
pub(super) async fn run_mining_engine(
    handle: MiningHandle,
    req_tx: mpsc::Sender<BuildRequest>,
    mut intent_rx: watch::Receiver<Option<BuildIntent>>,
    mut cancel_rx: watch::Receiver<bool>,
) {
    'outer: loop {
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
        // Parent the retry budget is charged against: a re-borrow that lands
        // on a NEW tip gets a fresh budget (its persist lag is its own), while
        // the same-parent Minimal→Full pass deliberately shares one budget —
        // a published minimal proves that parent is already commit-visible.
        // This reset also covers a mid-retry parent switch (new tip arriving
        // during TipNotVisible backoff); the fresh budget is per-parent, so
        // every tip gets its full MAX_VIS_RETRIES regardless of prior history.
        let mut budget_parent: Option<[u8; 32]> = None;
        loop {
            // Re-borrow each attempt: a newer intent that arrived mid-retry
            // supersedes this one (latest-wins).
            let intent = match intent_rx.borrow_and_update().clone() {
                Some(i) => i,
                None => break,
            };
            if budget_parent != Some(intent.expected_parent) {
                attempts = 0;
                budget_parent = Some(intent.expected_parent);
            }
            // First build for a tip publishes a minimal (emission-only)
            // template so the serve gap is the minimal build's cost, not the
            // full build's; once anything serves this parent, build enriched.
            // Probing the ring (not per-intent state) keeps the decision
            // correct across superseded intents and ABA reorgs for free.
            let mode = if handle.has_template_for_parent(&intent.expected_parent) {
                BuildMode::Full
            } else {
                BuildMode::Minimal
            };
            // Build-start marker, paired with the build-complete line below. A
            // start with no timely complete is the signature of a stuck/slow
            // build starving the served cache — visible at the log's default
            // level (the complete line is already WARN when slow), so an
            // operator can spot starvation without correlating against an
            // external clock.
            info!(
                reason = ?intent.reason,
                ?mode,
                attempts,
                expected_height = intent.expected_height,
                "mining engine: build start",
            );
            // Dispatch the build to the worker and await its reply. `build_ms`
            // times the request→reply round-trip — the wall time of the build
            // itself (the worker runs it synchronously and replies immediately),
            // preserving the metric's meaning across the thread hop. It excludes
            // the inter-retry backoff sleeps, so `build_ms` stays the
            // candidate-assembly latency — the headline observability metric and
            // the slow-build warn trigger. `outcome` doubles as the CAS-drop
            // counter (`DroppedStale`) and `attempts` as the commit-visibility
            // retry count.
            //
            // We deliberately do NOT `select!` cancel against the reply: a build
            // in flight is never preempted (the worker shares one serial
            // request→reply protocol with this loop, and abandoning a reply
            // mid-build would desync it — and later dirty the dry-run base). A
            // cancel that arrives mid-build is observed at the next loop
            // boundary, exactly as when the build ran inline.
            let build_start = Instant::now();
            let (reply_tx, reply_rx) = oneshot::channel();
            if req_tx
                .send(BuildRequest {
                    intent: intent.clone(),
                    mode,
                    reply: reply_tx,
                })
                .is_err()
            {
                // Worker thread gone (panicked or already joined). The engine
                // can no longer build — treat it like the producer-gone path
                // and shut the coordinator down cleanly (no panic).
                error!("mining engine: build worker thread is gone; stopping engine");
                break 'outer;
            }
            let (result, base_cache) = match reply_rx.await {
                Ok(r) => r,
                Err(_) => {
                    // The worker dropped the reply sender without replying ⇒ it
                    // died mid-build. Same handling as a missing worker.
                    error!("mining engine: build worker dropped the reply; stopping engine");
                    break 'outer;
                }
            };
            let build_ms = build_start.elapsed().as_millis() as u64;
            match result {
                Ok(BuildOutcome::TipNotVisible) if attempts < MAX_VIS_RETRIES => {
                    attempts += 1;
                    tokio::select! {
                        biased;
                        _ = cancel_rx.changed() => break 'outer,
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
                                mode = ?mode,
                                base_cache,
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
                    if mode == BuildMode::Minimal {
                        // The enriched same-parent refresh — skipped when it
                        // would add nothing (quiet pool + rent disabled).
                        if full_refresh_adds_nothing(&intent, &handle) {
                            break;
                        }
                        // Re-borrows the latest intent; the ring now holds this
                        // parent's minimal template, so the probe yields Full
                        // (no infinite Minimal loop — this task is the only
                        // publisher and set_best_tip never evicts).
                        continue;
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
                        mode = ?mode,
                        base_cache,
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
                        mode = ?mode,
                        base_cache,
                        reason = ?intent.reason,
                        "mining engine: build not published",
                    );
                    break;
                }
                Err(e) => {
                    warn!(
                        error = ?e,
                        build_ms,
                        mode = ?mode,
                        base_cache,
                        reason = ?intent.reason,
                        "mining engine: build failed",
                    );
                    break;
                }
            }
        }
    }
    // Drop the request sender so the worker's `recv()` errs and it exits. The
    // future owns ONLY `req_tx`, not the worker `JoinHandle`, so this drop runs
    // on every exit path — cooperative return here, OR a `shutdown`-driven
    // `abort()` that drops this future while it is parked at `reply_rx.await`.
    // Either way the worker drains its (≤1) in-flight build and exits; the
    // caller joins the thread afterward. We deliberately do NOT join here: the
    // handle lives with the spawner (see this module's lifecycle doc).
    drop(req_tx);
    debug!("mining engine task exiting");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashMap;

    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;

    // ----- helpers -----

    fn id(seed: u8) -> Digest32 {
        Digest32::from_bytes([seed; 32])
    }

    fn trivial_tree() -> ErgoTree {
        ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        }
    }

    fn box_with_seed(seed: u8) -> ErgoBox {
        let cand = ErgoBoxCandidate::new(
            1_000_000,
            trivial_tree(),
            1,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap();
        ErgoBox {
            candidate: cand,
            transaction_id: ModifierId::from_bytes([seed; 32]),
            index: 0,
        }
    }

    /// One eligible-id row naming the box with the given `seed`. The other
    /// DTO fields are immaterial to paging — only `box_id` is read.
    fn row(seed: u8) -> StorageRentEligibleDto {
        StorageRentEligibleDto {
            creation_height: 1,
            global_box_index: seed as i64,
            box_id: id(seed),
            box_value: 1_000_000,
            box_bytes_len: 0,
        }
    }

    /// A snapshot resolver backed by a `seed -> ErgoBox` map. Seeds absent
    /// from the map model rows the build snapshot cannot materialize (spent
    /// since the index scan, or rolled back by a reorg).
    fn resolver(live: &[u8]) -> impl Fn(&Digest32) -> Option<ErgoBox> + '_ {
        let map: HashMap<Digest32, ErgoBox> =
            live.iter().map(|&s| (id(s), box_with_seed(s))).collect();
        move |q: &Digest32| map.get(q).cloned()
    }

    /// Pageable fetcher over a flat row list with an Asc row-index offset,
    /// mirroring `read_storage_rent_eligible_paged`'s skip-`offset` semantics.
    /// `fetches` counts page reads so tests can assert the scan bound.
    fn pager<'a>(
        rows: &'a [StorageRentEligibleDto],
        fetches: &'a Cell<u32>,
    ) -> impl FnMut(u32, u32) -> Result<Vec<StorageRentEligibleDto>, std::convert::Infallible> + 'a
    {
        move |offset: u32, limit: u32| {
            fetches.set(fetches.get() + 1);
            let start = offset as usize;
            let end = (start + limit as usize).min(rows.len());
            let page = if start >= rows.len() {
                Vec::new()
            } else {
                rows[start..end].to_vec()
            };
            Ok(page)
        }
    }

    // ----- happy path -----

    #[test]
    fn page_all_rows_resolve_single_page_within_cap() {
        let rows = [row(1), row(2), row(3)];
        let fetches = Cell::new(0);
        let out = page_rent_boxes(pager(&rows, &fetches), resolver(&[1, 2, 3]), 4);
        // Short page (3 < cap 4) exhausts the index in one fetch.
        assert_eq!(out.len(), 3);
        assert_eq!(fetches.get(), 1);
    }

    #[test]
    fn page_zero_cap_short_circuits_without_fetching() {
        // A zero claim cap collects nothing and must not issue any
        // (zero-limit) indexer reads.
        let rows = [row(1), row(2)];
        let fetches = Cell::new(0);
        let out = page_rent_boxes(pager(&rows, &fetches), resolver(&[1, 2]), 0);
        assert!(out.is_empty());
        assert_eq!(fetches.get(), 0);
    }

    #[test]
    fn page_stale_first_page_backfills_from_second() {
        // Cap 4, page 1 has 4 rows but 3 are stale; only the valid ones must
        // count against the cap, with the rest backfilled from page 2 — so a
        // lagging index costs retries, not claim slots.
        let rows = [
            row(1),
            row(2),
            row(3),
            row(4), // page 1: only seed 4 is live
            row(5),
            row(6),
            row(7),
            row(8), // page 2: all live
        ];
        let fetches = Cell::new(0);
        // Live: one box on page 1 (seed 4), three on page 2 (5,6,7) → 4 total.
        let out = page_rent_boxes(pager(&rows, &fetches), resolver(&[4, 5, 6, 7]), 4);
        assert_eq!(out.len(), 4);
        assert_eq!(fetches.get(), 2, "needed a second page to backfill the cap");
    }

    #[test]
    fn page_cap_reached_mid_page_stops_fetching() {
        // A full first page already satisfies the cap → no second fetch.
        let rows = [row(1), row(2), row(3), row(4), row(5), row(6)];
        let fetches = Cell::new(0);
        let out = page_rent_boxes(pager(&rows, &fetches), resolver(&[1, 2, 3, 4, 5, 6]), 4);
        assert_eq!(out.len(), 4);
        assert_eq!(fetches.get(), 1);
    }

    #[test]
    fn page_index_exhausted_short_page_returns_resolved_no_extra_fetch() {
        // Fewer rows than the cap, all live → return them all, one fetch.
        let rows = [row(1), row(2)];
        let fetches = Cell::new(0);
        let out = page_rent_boxes(pager(&rows, &fetches), resolver(&[1, 2]), 4);
        assert_eq!(out.len(), 2);
        assert_eq!(fetches.get(), 1);
    }

    #[test]
    fn page_all_stale_respects_max_rent_pages_bound() {
        // Every row is stale and every page is full, so backfill never
        // satisfies the cap; the scan must still stop at MAX_RENT_PAGES.
        let rows: Vec<StorageRentEligibleDto> = (0..64u8).map(row).collect();
        let fetches = Cell::new(0);
        let out = page_rent_boxes(pager(&rows, &fetches), resolver(&[]), 4);
        assert!(out.is_empty());
        assert_eq!(fetches.get(), MAX_RENT_PAGES);
    }

    #[test]
    fn page_duplicate_box_id_across_pages_resolved_once() {
        // Each page is a separate indexer read txn, so a rollback/apply
        // between reads can shift the row set under the offset and re-surface
        // a box already taken. The seen-set must drop the repeat — the
        // rent-claim builder does not dedup, so a duplicate would otherwise
        // become a within-tx double-spend and abort the build.
        let fetches = Cell::new(0);
        let fetch = |offset: u32,
                     _limit: u32|
         -> Result<Vec<StorageRentEligibleDto>, std::convert::Infallible> {
            fetches.set(fetches.get() + 1);
            // Page 1 (offset 0): full page of 4 (== cap), but seed 2 is stale,
            // so it resolves only [1,3,4] — cap not reached, so page 2 is
            // fetched. Page 2 re-surfaces seed 1 (shifted under the offset by
            // a between-read apply) then a fresh seed 5. Dedup must skip the
            // repeated seed 1 and fill the last slot with seed 5.
            if offset == 0 {
                Ok(vec![row(1), row(2), row(3), row(4)])
            } else {
                Ok(vec![row(1), row(5)])
            }
        };
        let out = page_rent_boxes(fetch, resolver(&[1, 3, 4, 5]), 4);
        let mut ids: Vec<_> = out
            .iter()
            .map(|b| b.transaction_id.as_bytes().to_vec())
            .collect();
        ids.sort();
        ids.dedup();
        // Four distinct boxes (1,3,4,5), no repeat of seed 1.
        assert_eq!(out.len(), 4);
        assert_eq!(ids.len(), 4, "no box_id resolved twice");
        assert_eq!(
            fetches.get(),
            2,
            "needed page 2 to backfill past the stale + duplicate rows"
        );
    }

    #[test]
    fn page_front_deletion_between_reads_under_collects_not_aborts() {
        // Pins the known limitation of skip-by-row-count paging over a
        // mutating table: if front rows are deleted between page reads, later
        // live rows shift under the advanced offset and are stepped over. The
        // contract is under-collection (the missed box stays eligible for the
        // next build), never a wrong/blind claim or a build abort.
        //
        // Page 1 (offset 0): a full page [1,2,3,4] (== cap), all stale, so it
        // resolves nothing; offset advances to 4. Between reads the four stale
        // front rows are deleted, so the live boxes 5..8 — which were at index
        // 4..8 — are now at index 0..4, i.e. entirely under the advanced
        // offset. Page 2 (offset 4) sees only what remains past index 4:
        // empty. The scan under-collects (0 boxes) rather than erroring.
        let fetches = Cell::new(0);
        let fetch = |offset: u32,
                     _limit: u32|
         -> Result<Vec<StorageRentEligibleDto>, std::convert::Infallible> {
            fetches.set(fetches.get() + 1);
            if offset == 0 {
                Ok(vec![row(1), row(2), row(3), row(4)]) // all stale
            } else {
                // Post-deletion table is [5,6,7,8] (len 4); offset 4 skips
                // all of it.
                Ok(Vec::new())
            }
        };
        // Boxes 5..8 are live, but the offset stepped over them.
        let out = page_rent_boxes(fetch, resolver(&[5, 6, 7, 8]), 4);
        assert!(
            out.is_empty(),
            "front-deletion gap under-collects; missed boxes stay eligible for the next build"
        );
        assert_eq!(fetches.get(), 2);
    }

    // ----- full_refresh_adds_nothing predicate -----

    fn minimal_intent(
        mempool: ergo_mempool::MempoolReadSnapshot,
    ) -> ergo_mining::engine::BuildIntent {
        ergo_mining::engine::BuildIntent {
            expected_parent: [0u8; 32],
            expected_height: 0,
            mempool: std::sync::Arc::new(mempool),
            miner_pk: [0x02u8; 33],
            reason: ergo_mining::engine::BuildReason::Startup,
        }
    }

    fn plain_handle() -> MiningHandle {
        MiningHandle::new(
            [0x02u8; 33],
            ergo_mining::emission_rules::MonetarySettings::mainnet(),
            None,
            ergo_crypto::difficulty::DifficultyParams::mainnet(),
            ergo_validation::VotingSettings::mainnet(),
        )
    }

    fn synth_entry(seed: u8) -> ergo_mempool::Entry {
        ergo_mempool::Entry::new(
            ergo_primitives::digest::Digest32::from_bytes([seed; 32]),
            std::sync::Arc::from(Vec::<u8>::new().into_boxed_slice()),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            1,
            0,
            0,
            ergo_mempool::TxSource::Api,
        )
    }

    #[test]
    fn full_refresh_skipped_when_pool_empty_and_rent_off() {
        let intent = minimal_intent(ergo_mempool::MempoolReadSnapshot::empty());
        let handle = plain_handle(); // rent off by default
        assert!(
            full_refresh_adds_nothing(&intent, &handle),
            "empty pool + rent off means the full build would add nothing",
        );
    }

    #[test]
    fn full_refresh_not_skipped_when_pool_non_empty() {
        let snap = ergo_mempool::MempoolReadSnapshot::from_entries(vec![synth_entry(1)]);
        let intent = minimal_intent(snap);
        let handle = plain_handle(); // rent off
        assert!(
            !full_refresh_adds_nothing(&intent, &handle),
            "non-empty pool means the full build would add fee txs",
        );
    }

    #[test]
    fn full_refresh_not_skipped_when_rent_on() {
        let intent = minimal_intent(ergo_mempool::MempoolReadSnapshot::empty());
        let handle = plain_handle().with_rent_config(true, 4);
        assert!(
            !full_refresh_adds_nothing(&intent, &handle),
            "rent on means the full build may add a rent self-claim tx",
        );
    }

    // ----- error paths -----

    #[test]
    fn page_fetch_error_first_page_degrades_to_empty() {
        let fetches = Cell::new(0);
        let fetch = |_off: u32, _lim: u32| -> Result<Vec<StorageRentEligibleDto>, &'static str> {
            fetches.set(fetches.get() + 1);
            Err("indexer read failed")
        };
        let out = page_rent_boxes(fetch, resolver(&[1, 2, 3]), 4);
        assert!(out.is_empty());
        assert_eq!(fetches.get(), 1);
    }

    #[test]
    fn page_fetch_error_second_page_degrades_whole_to_empty() {
        // Page 1 resolves boxes, then page 2 errors. The contract is
        // all-or-nothing: a mid-scan error discards even the already-resolved
        // page-1 boxes rather than serving an inconsistent partial set.
        let rows = [row(1), row(2), row(3), row(4)]; // full first page (cap 4)
        let fetches = Cell::new(0);
        let map: HashMap<Digest32, ErgoBox> = [1u8, 2, 3]
            .iter()
            .map(|&s| (id(s), box_with_seed(s)))
            .collect();
        let fetch =
            |offset: u32, limit: u32| -> Result<Vec<StorageRentEligibleDto>, &'static str> {
                fetches.set(fetches.get() + 1);
                if offset == 0 {
                    let end = (limit as usize).min(rows.len());
                    Ok(rows[..end].to_vec())
                } else {
                    Err("indexer read failed on page 2")
                }
            };
        // Only 3 of the 4 page-1 rows are live, so page 1 does not fill the
        // cap → a second fetch is attempted and errors.
        let out = page_rent_boxes(fetch, move |q: &Digest32| map.get(q).cloned(), 4);
        assert!(
            out.is_empty(),
            "mid-scan error degrades the whole resolution"
        );
        assert_eq!(fetches.get(), 2);
    }
}

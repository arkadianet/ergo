//! The action loop body — owned by the spawned task returned in
//! [`super::RunHandle::loop_handle`]. Drives the four timers (dial,
//! sync, mempool, memory), inbound event coalescing, API submission
//! drain, and mining-request dispatch; runs the in-loop persist
//! shutdown when the `shutdown_rx` arm fires.
//!
//! `handle_mempool_tick` lives here because it's only called from
//! this file's mempool-tick arm.

use std::time::{Duration, Instant};

use ergo_mempool::ErgoValidator;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::api_bridge::SubmitRequest;
use crate::notifier::PollOutcome;
use crate::peer_loop::PeerEvent;

use super::admission::{admit_api_transaction, route_mempool_actions};
use super::events::handle_event_batch;
use super::memory_sampler::sample_memory;
use super::mining_dispatch::{
    decide_mining_signal, handle_mining_request, signal_mining_engine, MiningProducerState,
    MiningTipSnapshot, MiningWiring,
};
use super::peer_actions::{connect_to_address, flush_actions, try_dial_peers};
use super::sync_tick::handle_sync_tick;
use super::tip_context::build_tip_context;
use super::{NodeError, NodeState};

use ergo_mining::engine::BuildReason;
use ergo_mining::handle::MiningHandle;

/// Mirrors the pre-refactor inline loop one-for-one: signal arms are
/// replaced by a single `shutdown_rx` arm, and the cleanup runs inside
/// this function so the task's terminal state still closes the store
/// before yielding.
#[allow(clippy::too_many_arguments)] // task spawn-point: channels unpacked straight into the select loop
pub(super) async fn action_loop(
    mut state: NodeState,
    mut event_rx: mpsc::Receiver<PeerEvent>,
    mut submit_rx: mpsc::Receiver<SubmitRequest>,
    mut mining_submit_rx: mpsc::Receiver<crate::mining_bridge::MiningRequest>,
    // Operator /peers/connect dial requests from the REST admin handle.
    mut peer_connect_rx: mpsc::Receiver<std::net::SocketAddr>,
    // Operator vote changes (POST /api/v1/votes) — each `()` forces an
    // immediate same-tip mining candidate rebuild so the new votes take effect.
    mut votes_changed_rx: mpsc::Receiver<()>,
    // Mining wiring (handle + off-loop engine intent channel). `Some` exactly
    // when mining is configured on. The loop dispatches mining requests
    // against the handle and publishes a `BuildIntent` on tip change, a
    // throttled recovery retry while synced-but-uncovered, and a debounced
    // same-parent refresh when the mempool advanced.
    mining: Option<MiningWiring>,
    mut shutdown_rx: oneshot::Receiver<()>,
    mempool_tick_ms: u64,
) -> Result<(), NodeError> {
    // Tick every 5s so cold-start fills the outbound pool quickly.
    // The slow-mode gate inside `try_dial_peers` enforces the
    // original 30s cadence once the deficit is small (see
    // `DIAL_SLOW_PERIOD`).
    let mut dial_tick = tokio::time::interval(Duration::from_secs(5));
    // Outer cadence for `handle_sync_tick`: dispatch SyncInfo, run
    // delivery-timeout checks, advance block apply, refresh missing-
    // section requests, emit the [sync] heartbeat. 1s is the
    // empirical sweet spot — both 500ms and 250ms attempts dropped
    // sustained throughput by fragmenting per-batch coalescing. The
    // per-peer Lever 1 throttle (250ms) plus immediate-after-Modifier
    // dispatch handle per-peer reactivity; the outer tick exists for
    // periodic catch-up of unresponsive peers and unconditional
    // heartbeat emission.
    let mut sync_tick = tokio::time::interval(Duration::from_secs(1));
    let mut mempool_tick = tokio::time::interval(Duration::from_millis(mempool_tick_ms));
    // Memory observability: enabled by `ERGO_MEM_CSV=<path>`. When
    // unset the tick still fires but `sample_memory` is a no-op,
    // keeping overhead negligible. Path captured once at loop start;
    // changing the env var mid-run requires a node restart
    // (acceptable for an observability knob).
    let mut mem_tick = tokio::time::interval(Duration::from_secs(5));
    let mem_csv_path: Option<std::path::PathBuf> =
        std::env::var_os("ERGO_MEM_CSV").map(std::path::PathBuf::from);
    let mut mem_csv_file: Option<std::fs::File> = None;
    if let Some(p) = mem_csv_path.as_deref() {
        info!(path = %p.display(), interval_secs = 5, "mem-csv: writing samples");
    }

    // --- Off-loop mining engine producer state ---
    // After every state-mutating select arm we recompute the tip; on a tip
    // change we re-signal the engine (`Tip`), and while synced-but-uncovered we
    // retry (`WalletReady`). On an unchanged synced tip whose mempool advanced,
    // a debounced `MempoolRefresh` re-signals with the same parent and a fresh
    // pool snapshot. The tip starts at the zeroed sentinel so the startup prime
    // below always fires.
    let mut mining_chain_seq: u64 = 0;
    let mut mining_last_tip = MiningTipSnapshot::default();
    // Throttle for the synced-but-uncovered recovery retry below: a build is
    // already in flight right after a tip signal, so we must NOT re-resolve the
    // reward key / re-snapshot the mempool on every post-arm pass until it
    // publishes. Retry at most once per interval (≈ the sync-tick cadence),
    // which both recovers promptly after a wallet unlock and keeps the loop
    // from doing redundant build-input resolution while a build is outstanding.
    const MINING_RECOVERY_RETRY: Duration = Duration::from_secs(1);
    let mut mining_last_recovery: Option<Instant> = None;
    // Mempool-refresh tracking: the candidate-visible pool revision the last
    // signalled build reflected, and when the last mempool-refresh fired. A
    // same-parent refresh is due only when the revision advanced AND the
    // debounce window (`refresh_debounce`) has elapsed, coalescing a burst of
    // pool mutations into one rebuild. Tip and recovery signals reset both so
    // the fresh build's pool snapshot isn't immediately re-refreshed.
    let mut mining_last_revision = state.mempool.revision();
    let mut mining_last_mempool_signal: Option<Instant> = None;
    // Set by the votes-changed arm; consumed in the post-arm mining block to
    // force a same-tip rebuild this iteration (so a vote change applies now).
    let mut mining_votes_dirty = false;
    // Startup priming: publish the initial BestTip + (if already synced) the
    // first BuildIntent, so an idle already-synced node serves a candidate
    // without waiting for an unrelated state change.
    if let Some(wiring) = mining.as_ref() {
        let prev = mining_last_tip.best_full_id();
        mining_last_tip = signal_mining_engine(
            &state,
            wiring,
            &mut mining_chain_seq,
            &prev,
            BuildReason::Startup,
        );
        mining_last_recovery = Some(Instant::now());
    }

    loop {
        tokio::select! {
            biased;
            // Shutdown ordering matches the pre-refactor signal arms:
            // checked first each iteration so a pending shutdown wins
            // against a ready timer or channel.
            _ = &mut shutdown_rx => {
                shutdown_log!("[node] shutdown requested, exiting loop...");
                break;
            }
            _ = sync_tick.tick() => {
                handle_sync_tick(&mut state);
            }
            _ = dial_tick.tick() => {
                try_dial_peers(&mut state);
            }
            Some(addr) = peer_connect_rx.recv() => {
                connect_to_address(&mut state, addr);
            }
            Some(()) = votes_changed_rx.recv() => {
                // Operator changed votes; coalesce any queued updates and force
                // ONE same-tip rebuild below — each rebuild reads the latest
                // shared target map, so extra queued notifications add nothing.
                while votes_changed_rx.try_recv().is_ok() {}
                mining_votes_dirty = true;
            }
            _ = mempool_tick.tick() => {
                handle_mempool_tick(&mut state, mining.as_ref().map(|w| &w.handle));
            }
            Some(first) = event_rx.recv() => {
                // INGEST COALESCE: drain additional queued events
                // without yielding so consecutive header-Modifier
                // messages from different peers can be folded into
                // ONE `execute_all` call. The executor's batch path
                // (rayon pre-validate + sequential finalize + one
                // redb txn) amortizes its per-batch overhead over
                // however many headers we hand it. With 60 peers
                // each shipping ~400 IDs every RTT, several Modifier
                // messages routinely queue while one is being
                // processed; coalescing them saves N × per-batch
                // overhead.
                //
                // Cap drain at MAX_COALESCE so the other timer arms
                // (sync_tick, dial_tick, mempool_tick) aren't starved
                // during high-throughput periods.
                //
                // **Outbound serving is unchanged.** This only
                // affects how *we ingest* incoming Modifier messages
                // from other peers; we still respond to inbound Inv /
                // RequestModifier messages individually with the
                // per-request semantics Scala expects.
                const MAX_COALESCE: usize = 64;
                let mut events = Vec::with_capacity(MAX_COALESCE);
                events.push(first);
                while events.len() < MAX_COALESCE {
                    match event_rx.try_recv() {
                        Ok(e) => events.push(e),
                        Err(_) => break,
                    }
                }
                handle_event_batch(&mut state, events);
            }
            // API submissions cross from the axum task into the main
            // loop via this channel. Each request carries a oneshot
            // reply; we drain one per iteration to keep per-
            // submission latency bounded by one tick of the loop.
            // The reply send may fail if the handler timed out and
            // dropped its oneshot — that's fine, the outcome is
            // still recorded in the mempool's anti-DoS state per
            // invariant #7.
            Some(req) = submit_rx.recv() => {
                let now = Instant::now();
                let result = admit_api_transaction(&mut state, &req.bytes, req.mode, now);
                let _ = req.reply.send(result);
            }
            // Mining requests (candidate fetch / solution submit).
            // One request drained per iteration matches the
            // submit_rx ordering: each request is single-shot and
            // replies through its own oneshot, so back-to-back
            // drains are still bounded by one tick of the loop.
            //
            // When mining is disabled at startup, `mining_handle`
            // is `None` and `handle_mining_request` rejects with
            // `Unavailable`. The sender side of the channel is only
            // exposed through the `MiningBridge` (which is also
            // only constructed when enabled), so the disabled path
            // is unreachable in practice — the rejection is defense
            // in depth.
            Some(req) = mining_submit_rx.recv() => {
                handle_mining_request(&mut state, mining.as_ref().map(|m| &m.handle), req);
            }
            _ = mem_tick.tick() => {
                if let Some(path) = mem_csv_path.as_deref() {
                    sample_memory(&state, path, &mut mem_csv_file);
                }
            }
        }

        // Post-arm mining-engine signal. The `shutdown_rx` arm `break`s above
        // and never reaches here; every other arm may have advanced the tip
        // (block apply, mined-block submit, sync catch-up) or mutated the
        // mempool (admission, eviction, reorg). One centralized check after
        // the select keeps the wiring in a single place rather than threaded
        // through events.rs / sync_tick.rs.
        if let Some(wiring) = mining.as_ref() {
            let now = Instant::now();
            let tip_now = MiningTipSnapshot::capture(&state);
            let revision_now = state.mempool.revision();
            let has_cached = wiring.handle.cached_work_if_synced().is_some();
            // Tip preempts recovery preempts refresh; recovery is throttled to
            // `MINING_RECOVERY_RETRY`, refresh to the configured debounce. The
            // precedence + gating is the pure `decide_mining_signal` (unit-
            // tested in mining_dispatch.rs); this arm only carries out the
            // chosen signal and advances the producer trackers.
            let producer = MiningProducerState {
                last_tip: mining_last_tip,
                last_revision: mining_last_revision,
                last_recovery: mining_last_recovery,
                last_mempool_signal: mining_last_mempool_signal,
            };
            // A vote change forces a same-tip rebuild even when the tip/mempool
            // are unchanged. A tip/recovery/mempool signal (if any) takes its
            // own reason — those rebuilds already read the latest votes — so
            // `VotesChanged` only fires when nothing else would.
            let decided = decide_mining_signal(
                &producer,
                tip_now,
                has_cached,
                revision_now,
                now,
                MINING_RECOVERY_RETRY,
                wiring.refresh_debounce,
            );
            let signal = decided.or(mining_votes_dirty.then_some(BuildReason::VotesChanged));
            mining_votes_dirty = false;
            if let Some(reason) = signal {
                let prev = mining_last_tip.best_full_id();
                mining_last_tip =
                    signal_mining_engine(&state, wiring, &mut mining_chain_seq, &prev, reason);
                match reason {
                    // A fresh build (tip change or recovery) already snapshots the
                    // latest pool, so realign the refresh trackers to "current" —
                    // don't immediately re-fire a same-parent refresh for the pool
                    // we just captured — and reset the recovery clock so the build
                    // gets a full interval to publish before any retry.
                    BuildReason::Tip | BuildReason::WalletReady => {
                        mining_last_revision = state.mempool.revision();
                        mining_last_mempool_signal = Some(now);
                        mining_last_recovery = Some(now);
                    }
                    // A same-parent refresh: advance the pool tracker to the
                    // revision we just rebuilt against and stamp the debounce.
                    // `VotesChanged` is the same shape — a forced same-tip
                    // rebuild against the current pool.
                    BuildReason::MempoolRefresh | BuildReason::VotesChanged => {
                        mining_last_revision = revision_now;
                        mining_last_mempool_signal = Some(now);
                    }
                    // Startup is only used at the prime call above, never here.
                    BuildReason::Startup => {}
                }
            }
        }
    }

    let t_shutdown = Instant::now();
    // Drop the submission receiver immediately so any axum handlers
    // still alive (e.g. when the embedder dropped `RunHandle`
    // without calling `shutdown()`, so we can't pre-abort the API
    // task) see their `try_send` fail with `Closed` →
    // `shutting_down`. Without this, queued submissions sit
    // unprocessed for the duration of the persist-pipeline drain
    // below and eventually surface as `timeout`, which is the wrong
    // reason code for a stopping node. Defense in depth alongside
    // the abort-API-first ordering in `RunHandle::shutdown()`.
    drop(submit_rx);
    drop(mining_submit_rx);
    let cs_shutdown = state.store.chain_state_meta();
    shutdown_log!(
        "[node] tip at shutdown: h={} bh={}, peers={}",
        cs_shutdown.best_full_block_height,
        cs_shutdown.best_header_height,
        state.registry.peers.len(),
    );
    shutdown_log!("[node] closing peer channels");
    state.registry.peers.clear();
    shutdown_log!("[node] draining persist pipeline and forcing durable DB close…");
    // Surface, don't swallow: if the persist pipeline fails to
    // drain or the final durable flush errors, the consensus state
    // on disk is potentially inconsistent (atomic-commit invariant
    // covers undo_log + AVL + chain_index + state_meta). A "clean
    // shutdown succeeded" log line followed by silent data loss on
    // next start is the worst possible failure mode.
    let shutdown_result = state.store.shutdown_cleanly();
    shutdown_log!("[node] dropping state");
    drop(state);
    shutdown_log!(
        "[node] shutdown complete in {:.1}s",
        t_shutdown.elapsed().as_secs_f64(),
    );
    shutdown_result.map_err(|e| Box::new(e) as NodeError)
}

fn handle_mempool_tick(state: &mut NodeState, mining_handle: Option<&MiningHandle>) {
    if !state.mempool.config().enabled {
        return;
    }
    // Single poll of committed-state tip identity. `MempoolNotifier`
    // returns NoChange when nothing's moved — the normal case
    // between block applications — so this path is cheap on the hot
    // loop.
    let outcome = state.mempool_notifier.poll(
        state
            .store
            .as_utxo()
            .expect("utxo-only: mempool subsystem is gated off in digest mode"),
    );
    let tip_changed = match outcome {
        PollOutcome::Initialized(_) | PollOutcome::NoChange => false,
        PollOutcome::Emit(state_diff) => {
            // Workstream C: a rollback (non-empty `demoted`) captures its
            // enrichment HERE — the only place the returned-tx set and the
            // winning tip meet — for the event differ to attach by tip id.
            if !state_diff.demoted.is_empty() {
                let cap = crate::node::state::ReorgEnrichment::RETURNED_IDS_CAP;
                state.last_reorg_enrichment = Some(crate::node::state::ReorgEnrichment {
                    tip_id: hex::encode(state_diff.new_tip.header_id),
                    returned_tx_ids: state_diff
                        .demoted
                        .iter()
                        .take(cap)
                        .map(|d| hex::encode(d.tx_id))
                        .collect(),
                    returned_txs_total: state_diff.demoted.len() as u32,
                    delivered_by: state
                        .first_deliverer_ring
                        .get(&state_diff.new_tip.header_id)
                        .map(|f| f.peer.to_string()),
                });
            }
            let mempool_diff: ergo_mempool::types::TxDiff = state_diff.into();
            let mempool_actions = state.mempool.on_tip_change(&mempool_diff);
            let routed = route_mempool_actions(state, mempool_actions);
            flush_actions(state, routed);

            // Epoch-boundary / reorg revalidation hook. After
            // processing the per-block mempool diff, check whether
            // the active voted parameters or validation settings
            // have moved (epoch-start apply, or post-reorg cache
            // change). If either changed, prior admission decisions
            // are invalid; demote every active tx into the
            // revalidation queue so they re-run admission against
            // the new rules.
            let now_active = state.store.active_params();
            let now_settings = state.store.validation_settings();
            if now_active != &state.last_seen_active_params
                || now_settings != &state.last_seen_validation_settings
            {
                let dropped = state.mempool.demote_all_for_revalidation();
                if dropped > 0 {
                    info!(
                        dropped = dropped,
                        "mempool epoch-boundary revalidation: demoted active pool, dropped from queue cap",
                    );
                }
                state.last_seen_active_params = now_active.clone();
                state.last_seen_validation_settings = now_settings.clone();
            }
            true
        }
        PollOutcome::Error { tip, error } => {
            reconcile_on_diff_error(&mut state.mempool, tip, &error);
            return;
        }
    };

    // Proactive mempool maintenance, all gated on FULLY SYNCED (header tip ==
    // full-block tip, same height AND id): during catch-up the applied tip lags
    // the header tip, so validating against a stale intermediate tip could
    // wrongly evict (A/B) or re-admit against a UTXO view many blocks behind
    // (the drain) — Scala only audits/at-tip. `build_tip_context` (below)
    // additionally returns `None` in the cold pre-first-block window.
    let cs = state.store.chain_state_meta();
    let fully_synced = cs.best_full_block_height > 0
        && cs.best_header_height == cs.best_full_block_height
        && cs.best_header_id == cs.best_full_block_id;
    if !fully_synced {
        return;
    }

    // Always drain the off-loop builder's suspect slot so it never goes stale.
    // On a TIP CHANGE we discard it: Component A's full `recheck_and_evict`
    // re-validates the WHOLE pool (the suspect set is a subset), so a separate
    // suspect pass would be redundant. BETWEEN blocks (no tip change) A does not
    // run, so that is where Component B earns its keep.
    let suspects = mining_handle.map(|h| h.take_suspects()).unwrap_or_default();

    // Three independent maintenance passes this tick:
    //  - recheck (A): full-pool recheck-and-evict on a tip change.
    //  - suspects (B): re-validate the off-loop build's flagged ids between blocks.
    //  - drain: re-admit demoted/rolled-back txs from the revalidation
    //    queue. Gated on the QUEUE being non-empty, NOT the pool — an epoch
    //    `demote_all` empties the pool INTO the queue, so the drain must run with
    //    `pool.size() == 0`.
    let need_recheck = tip_changed && state.mempool.size() > 0;
    let need_suspects = !tip_changed && !suspects.is_empty();
    let need_drain = state.mempool.revalidation_pending() > 0;
    if !(need_recheck || need_suspects || need_drain) {
        return;
    }

    let Some(owned) = build_tip_context(state) else {
        return;
    };
    let now = Instant::now();
    let actions = {
        let tip_ctx = owned.as_mempool_ctx(
            state
                .store
                .as_utxo()
                .expect("utxo-only: mempool subsystem is gated off in digest mode"),
        );
        let mut actions = Vec::new();
        // A or B first (clean the existing pool)...
        if need_recheck {
            // Component A: full-pool recheck-and-evict — the Scala
            // `MempoolAuditor`/`CleanupWorker` end-result via a per-block full
            // pass (anti-DoS cost-capped) instead of Scala's 30s throttle.
            actions.extend(
                state
                    .mempool
                    .recheck_and_evict(now, &tip_ctx, &ErgoValidator),
            );
        } else if need_suspects {
            // Component B: re-validate just the off-loop build's suspects.
            actions.extend(
                state
                    .mempool
                    .recheck_ids(now, &tip_ctx, &ErgoValidator, &suspects),
            );
        }
        // ...THEN drain the revalidation queue, re-admitting demoted/rolled-back
        // txs. After A so A never re-validates freshly re-admitted txs (no
        // double work, no broadcast-then-revoke on the same id within a tick).
        // Bounded per call by `revalidation_per_tick`; a large epoch-demoted
        // pool refills over several ticks. Re-admission resolves a child against
        // its already-re-admitted parent's pool output (demote order is
        // topological — see `demote_all_for_revalidation`).
        if need_drain {
            actions.extend(
                state
                    .mempool
                    .tick_revalidation(now, &tip_ctx, &ErgoValidator),
            );
        }
        actions
    };
    if !actions.is_empty() {
        let routed = route_mempool_actions(state, actions);
        flush_actions(state, routed);
    }
}

/// Reconcile the mempool when a tip-change diff could not be computed.
///
/// `TooFarBehind` / `ReorgTooDeep` (a forward catch-up jump or a reorg wider
/// than the rollback window) and `MissingSections` (a chain-index gap) all
/// leave us unable to identify which pooled txs were confirmed in the skipped
/// blocks. Scala's `updateMemPool` removes confirmed txs on every accepted tip
/// change; to preserve that invariant when the exact set is uncomputable, we
/// quarantine the WHOLE active pool into the revalidation queue, so no
/// possibly-confirmed/stale tx is served (`MempoolSnapshot::capture`) or
/// relayed. (This is intentionally conservative: a benign forward jump may
/// quarantine still-valid txs, which the revalidation-queue drain in
/// `handle_mempool_tick` re-admits on a later fully-synced tick — strictly
/// safer than serving confirmed txs.)
///
/// Returns the number of txs quarantined (0 when the pool was empty — the
/// common IBD case, since the pool is IBD-gated).
fn reconcile_on_diff_error(
    mempool: &mut ergo_mempool::Mempool,
    tip: ergo_state::diff::TipPointer,
    error: &ergo_state::diff::TxDiffError,
) -> usize {
    use ergo_state::diff::TxDiffError;
    // Per-variant cause logging:
    //   - `TooFarBehind` / `ReorgTooDeep` are expected during IBD when blocks
    //     land faster than the notifier cadence — debug, to keep IBD readable.
    //   - `MissingSections` is a chain-index gap (chain_index entry without
    //     persisted section bytes) — a real consistency issue, stays at warn.
    match error {
        TxDiffError::TooFarBehind | TxDiffError::ReorgTooDeep => {
            debug!(
                height = tip.height,
                header_id = %hex::encode(tip.header_id),
                error = ?error,
                "mempool notifier skipped (catch-up gap)",
            );
        }
        TxDiffError::MissingSections { .. } => {
            warn!(
                height = tip.height,
                header_id = %hex::encode(tip.header_id),
                error = ?error,
                "mempool notifier error at tip",
            );
        }
    }
    // `size()` is the active-pool count; capture it before demoting so we can
    // report what was quarantined (the method itself returns the queue-cap
    // overflow count, not the quarantine count). Carry `error` so the cause is
    // visible at warn level whenever real txs are dropped — the per-variant
    // logging above is debug for the benign catch-up gaps. The message is
    // variant-neutral: any diff error (not only a rollback-window overflow) can
    // reach here, e.g. `MissingSections`.
    let quarantined = mempool.size();
    let overflow = mempool.demote_all_for_revalidation();
    if quarantined > 0 {
        warn!(
            quarantined,
            overflow,
            height = tip.height,
            error = ?error,
            "mempool diff error: quarantined active pool for revalidation",
        );
    }
    quarantined
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_mempool::types::MempoolConfig;
    use ergo_mempool::{weight, Entry, Mempool, TxSource};
    use ergo_primitives::digest::Digest32;
    use ergo_state::diff::{TipPointer, TxDiffError};
    use std::sync::Arc;

    fn dig(b: u8) -> Digest32 {
        Digest32::from_bytes([b; 32])
    }

    fn seed(mempool: &mut Mempool, b: u8) {
        let bytes: Arc<[u8]> = Arc::from(vec![b; 20].into_boxed_slice());
        let entry = Entry::new(
            dig(b),
            bytes,
            vec![dig(b ^ 0x10)],
            vec![dig(b ^ 0x20)],
            vec![],
            1_000_000,
            100,
            20,
            50_000,
            TxSource::Api,
        );
        mempool.pool_mut().insert(entry).unwrap();
    }

    /// XC-1: when the tip-change diff is unrecoverable (a forward catch-up jump
    /// or reorg wider than the rollback window), the Error-arm reconciliation
    /// must quarantine the whole active pool so no possibly-confirmed/stale tx
    /// keeps being served or relayed — matching Scala's invariant that no
    /// confirmed tx survives in the pool after an accepted tip change.
    #[test]
    fn reconcile_on_diff_error_quarantines_active_pool() {
        let mut mempool = Mempool::new(
            MempoolConfig::default(),
            weight::from_config("cost").unwrap(),
        );
        seed(&mut mempool, 1);
        seed(&mut mempool, 2);
        seed(&mut mempool, 3);
        assert_eq!(mempool.size(), 3);

        let tip = TipPointer {
            height: 500,
            header_id: [0xFF; 32],
        };
        let quarantined = reconcile_on_diff_error(&mut mempool, tip, &TxDiffError::ReorgTooDeep);

        assert_eq!(quarantined, 3, "all three active txs quarantined");
        assert_eq!(
            mempool.size(),
            0,
            "active pool emptied — no stale/confirmed tx is served or relayed",
        );
    }
}

//! The action loop body — owned by the spawned task returned in
//! [`super::RunHandle::loop_handle`]. Drives the four timers (dial,
//! sync, mempool, memory), inbound event coalescing, API submission
//! drain, and mining-request dispatch; runs the in-loop persist
//! shutdown when the `shutdown_rx` arm fires.
//!
//! `handle_mempool_tick` lives here because it's only called from
//! this file's mempool-tick arm.

use std::time::{Duration, Instant};

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
use super::{NodeError, NodeState};

use ergo_mining::engine::BuildReason;

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
    // Startup priming: publish the initial BestTip + (if already synced) the
    // first BuildIntent, so an idle already-synced node serves a candidate
    // without waiting for an unrelated state change (Codex plan finding).
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
            _ = mempool_tick.tick() => {
                handle_mempool_tick(&mut state);
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
            if let Some(reason) = decide_mining_signal(
                &producer,
                tip_now,
                has_cached,
                revision_now,
                now,
                MINING_RECOVERY_RETRY,
                wiring.refresh_debounce,
            ) {
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
                    BuildReason::MempoolRefresh => {
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

fn handle_mempool_tick(state: &mut NodeState) {
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
    match outcome {
        PollOutcome::Initialized(_) | PollOutcome::NoChange => {}
        PollOutcome::Emit(state_diff) => {
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
        }
        PollOutcome::Error { tip, error } => {
            // `TooFarBehind` / `MissingSections` / `ReorgTooDeep`.
            // The notifier already advanced `last_seen` to `tip`;
            // next poll yields NoChange. Consumer semantics: the
            // pool currently self-heals on the next sync_tick —
            // pending-revalidation state is drained per tick, so a
            // stale notifier error here only ever costs one tick of
            // throughput, not correctness.
            //
            // Severity split:
            //   - `TooFarBehind` / `ReorgTooDeep` are the expected
            //     outcome during IBD when blocks land faster than
            //     the notifier polling cadence. The mempool is
            //     already IBD-gated, so the diff would have been
            //     thrown away anyway. Log at debug to keep IBD
            //     output readable.
            //   - `MissingSections` indicates a gap in the chain
            //     index (chain_index entry without persisted section
            //     bytes) — a real consistency issue. Stay at warn.
            use ergo_state::diff::TxDiffError;
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
        }
    }
}

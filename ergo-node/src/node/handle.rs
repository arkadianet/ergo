//! `RunHandle` — live, owned interface to a running node, returned by
//! [`super::run_inner`]. Bundles the submit handle, the lock-free
//! read-snapshot, the action-loop join handle, the API task join
//! handle, and the shutdown channel.
//!
//! [`Drop`] aborts every background task we own (inbound listener,
//! indexer task, address-book persistence, snapshot publisher, anchor
//! scheduler) so a partially-constructed `RunHandle` never leaks
//! tasks on early failure.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use super::NodeError;

/// Live handle to a running node returned by [`run_inner`].
///
/// Exposes the production surface tests and embedders need to drive the
/// node without going through HTTP or signal handling:
/// - `api_addr`: the kernel-resolved bind address when the API server
///   was enabled (`config.api_bind = Some(_)`); `None` otherwise.
/// - `submit`: in-process submission boundary that bypasses the HTTP
///   layer. Always `Some(_)` in production — matches the always-on
///   submission posture (Scala parity). The option type stays so
///   future read-only modes can null it out without churning embedder
///   callsites.
/// - `read`: lock-free snapshot reader, identical to the one the API's
///   read routes serve. Always present — read access is unconditional.
/// - `shutdown` / `join`: control-plane handles. Send the oneshot to
///   ask the action loop to exit cleanly, then await the join handle
///   to learn the loop's terminal status. [`RunHandle::shutdown`] does
///   both in one call.
pub struct RunHandle {
    pub api_addr: Option<SocketAddr>,
    pub submit: Option<Arc<dyn ergo_api::NodeSubmit>>,
    pub read: Arc<dyn ergo_api::NodeReadState>,
    /// `Option` so [`Drop`] can take the sender to fire a best-effort
    /// shutdown signal when the embedder drops the handle without
    /// calling [`shutdown`](Self::shutdown).
    pub(super) shutdown_tx: Option<oneshot::Sender<()>>,
    /// Graceful-shutdown channel for the API task. `Some` only when
    /// the API was actually bound. Sending (or dropping) triggers
    /// axum's `with_graceful_shutdown` so in-flight HTTP handlers
    /// drain naturally instead of seeing a TCP RST.
    pub(super) api_shutdown_tx: Option<oneshot::Sender<()>>,
    pub(crate) loop_handle: JoinHandle<Result<(), NodeError>>,
    pub(crate) api_handle: Option<JoinHandle<()>>,
    /// Handle to the inbound P2P listener task spawned when
    /// `[peers] bind_addr` is set. Aborted on shutdown so the bound
    /// port releases instead of staying parked in `accept()` until the
    /// next inbound connection bumps the closed event channel.
    /// `pub` so integration tests can assert the tracking happened
    /// (regression guard against silent task leaks).
    pub inbound_handle: Option<JoinHandle<()>>,
    /// Cancel flag wired into the indexer polling task — `IndexerTask::run`
    /// exits cleanly when it observes `cancel.load(Acquire) == true`.
    /// Always allocated — `None`
    /// would mean "no flag exists", which is wrong; the flag exists
    /// and is simply unused when no indexer task was spawned.
    pub(super) indexer_cancel: Arc<AtomicBool>,
    /// Polling task handle. `Some` when the indexer is enabled in
    /// config AND boot succeeded with a wired store (the
    /// `Halted` boot path returns a handle but no task). Awaited
    /// during shutdown so the task observes the cancel flag and
    /// drops its `IndexerStore` (releasing the redb file lock)
    /// before this future returns.
    pub(super) indexer_task_handle: Option<JoinHandle<()>>,
    /// JoinHandle for the Step B anchor-map background builder.
    /// Aborted on shutdown so the task doesn't outlive the action
    /// loop. `Option` so `Drop` can take it without double-awaiting.
    pub(super) anchor_builder_handle: Option<JoinHandle<()>>,
    /// Latched-cancellation sender shared with the anchor-map
    /// builder. `send(true)` flips the watch value (durable — the
    /// builder observes it on its next check whether or not it was
    /// awaiting). Used by both `shutdown()` and `Drop` so a
    /// forgotten `shutdown()` doesn't leak the builder.
    pub(super) anchor_builder_cancel_tx: tokio::sync::watch::Sender<bool>,
    /// JoinHandle for the off-loop mining-candidate engine task. `Some` only
    /// when mining is enabled. Awaited on shutdown so the engine — which holds
    /// a `ChainStoreReader` over the same redb database — does not outlive the
    /// action loop that runs the final durable `shutdown_cleanly()`.
    pub(super) mining_engine_handle: Option<JoinHandle<()>>,
    /// JoinHandle for the mining build-worker OS thread (the
    /// `ChainStoreReader`/`MiningHandle`/`IndexerHandle` owner). `Some` only
    /// when mining is enabled. Boot spawns the thread and the coordinator
    /// future owns only the request `Sender`, so on shutdown — even when the
    /// coordinator task is `abort()`ed at an await point — dropping the future
    /// closes the channel and the worker drains its in-flight build and exits.
    /// `shutdown()` joins this AFTER the coordinator await/abort so a worker
    /// still finishing a build can never detach and keep reading/publishing
    /// past shutdown. `Option` so `Drop`/`shutdown` can `take()` it.
    pub(super) mining_worker_handle: Option<std::thread::JoinHandle<()>>,
    /// Latched-cancellation sender for the mining engine (`watch<bool>`).
    /// `send(true)` flips the value so the engine leaves its `select!`/backoff
    /// promptly. Always allocated (cheap); fired by both `shutdown()` and
    /// `Drop` so a forgotten `shutdown()` can't leak the task.
    pub(super) mining_engine_cancel_tx: tokio::sync::watch::Sender<bool>,
    /// Shared notify fired by the `POST /node/shutdown` REST handler.
    /// `run()` waits on this alongside Ctrl+C / SIGTERM so an admin
    /// can request a clean shutdown over HTTP — useful when the node
    /// is launched headless / backgrounded with stdio redirected,
    /// where console-signal delivery is unreliable.
    pub shutdown_notify: Arc<tokio::sync::Notify>,
}

impl RunHandle {
    /// Send the shutdown signal and await loop termination.
    ///
    /// **Contract.** Best-effort graceful drain of in-flight HTTP
    /// requests with a 5-second cap, then forced abort. Requests that
    /// complete within the cap return a structured response (typically
    /// `503 shutting_down` for write handlers, the last cached snapshot
    /// for reads). Requests that exceed the cap — pathologically slow
    /// clients, deliberately stalled bodies — are force-cancelled and
    /// will see TCP RST. This is intentional: bounding shutdown is the
    /// load-bearing requirement for atomic-commit durability via
    /// `StateStore::shutdown_cleanly()` in step 5.
    ///
    /// Ordering, in detail:
    ///
    /// 1. Fire `shutdown_tx` — action loop breaks out of `select!`
    ///    and enters cleanup. First thing in cleanup is
    ///    `drop(submit_rx)`, which closes the submission channel; any
    ///    write handler still parked on its oneshot reply observes the
    ///    closed channel via `bridge.rs` → `shutting_down`. This is
    ///    the right reason code for a stopping node, distinct from
    ///    `timeout`. Firing the loop signal first means in-flight
    ///    write handlers learn their reason *before* axum starts
    ///    draining them, so they emit the structured `shutting_down`
    ///    response rather than waiting on a dropped oneshot during
    ///    axum drain.
    /// 2. Fire `api_shutdown_tx` (inside `drain_api_and_inbound`) —
    ///    axum's `with_graceful_shutdown` future resolves, the listener
    ///    stops accepting new connections, and in-flight handlers are
    ///    allowed to finish. Read handlers complete with whatever
    ///    snapshot they already captured. Write handlers complete via
    ///    the closed channel from step 1.
    /// 3. Abort inbound listener — no graceful drain meaningful here,
    ///    it's a bare `accept()` loop with no per-connection state.
    /// 4. Await `api_handle` with a 5-second timeout fallback. Axum
    ///    typically drains in milliseconds once the channel closes;
    ///    the timeout protects against pathologically slow clients
    ///    holding a handler open. If the timeout fires we abort the
    ///    task and await its termination so the bound port is actually
    ///    released before `shutdown()` returns.
    /// 5. Await `loop_handle` and surface its result — that result
    ///    encodes whether `StateStore::shutdown_cleanly()` succeeded,
    ///    which is the load-bearing signal for the
    ///    AVL+undo_log+chain_index+state_meta atomic-commit invariant.
    ///
    /// Background-task teardown (anchor builder, mining engine + its build
    /// worker, indexer) is interleaved between steps 1 and 2: each is
    /// cancelled and awaited under its own bounded timeout before the API
    /// drain, so a stuck background task can't block the API/loop shutdown.
    /// The mining build worker is awaited to completion (unbounded): shutdown
    /// completes only when the worker is quiescent. The in-flight build bounds
    /// the wait (~20 s worst case today, milliseconds once the per-tip base
    /// cache serves same-tip builds). This is the truthful contract — tokio's
    /// runtime drop waits for `spawn_blocking` tasks anyway, so a
    /// proceed-on-timeout design only makes the API lie while process exit
    /// still blocks. Awaiting here also prevents `DatabaseAlreadyOpen` on a
    /// restart before the worker drops its `Arc<Database>` read snapshot.
    ///
    /// Also releases bound ports promptly — important for tests that
    /// spin up many nodes back-to-back.
    pub async fn shutdown(mut self) -> Result<(), NodeError> {
        let shutdown_started = std::time::Instant::now();
        info!("shutdown initiated");
        // Action-loop shutdown — taken so Drop can't double-fire if
        // this future is cancelled mid-await.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // Indexer-task cancel — flipped before draining so the polling
        // loop can observe it during its next `step` boundary or
        // mid-sleep wake. Idempotent (Arc<AtomicBool>), Drop will set
        // it again safely if the await below is cancelled.
        // `IndexerTask::run` exits cleanly when `cancel.load(Acquire)`
        // is true; release here pairs with the loop's acquire.
        self.indexer_cancel.store(true, Ordering::Release);
        // Anchor builder cancel — flip the latched watch value and
        // bound the wait. The builder checks the latched flag at
        // every loop boundary and inside its sleeps, so this
        // returns within milliseconds in the common case. 5 s
        // timeout protects against a stuck task; abort + await
        // ensures the spawned future is fully torn down before this
        // method returns. Send-error is ignored: it just means the
        // receiver was already dropped (the builder already exited
        // for another reason).
        let _ = self.anchor_builder_cancel_tx.send(true);
        if let Some(mut h) = self.anchor_builder_handle.take() {
            if tokio::time::timeout(Duration::from_secs(5), &mut h)
                .await
                .is_err()
            {
                warn!(
                    timeout_s = 5,
                    "anchor builder did not stop within timeout; aborting"
                );
                h.abort();
                let _ = h.await;
            }
        }
        // Mining engine cancel — latched watch + bounded await, same pattern.
        // The coordinator checks the cancel flag at every await (between builds
        // and during backoff), so it exits within at most one candidate build of
        // the signal. `abort()` cannot preempt an in-flight build on the worker
        // thread, but the coordinator future owns only the request `Sender`:
        // aborting it (or its cooperative return) drops the future, closes the
        // build channel, and the worker drains its in-flight build then exits.
        // send-error ignored (the engine may already have exited when its intent
        // sender dropped).
        let _ = self.mining_engine_cancel_tx.send(true);
        if let Some(mut h) = self.mining_engine_handle.take() {
            if tokio::time::timeout(Duration::from_secs(5), &mut h)
                .await
                .is_err()
            {
                warn!(
                    timeout_s = 5,
                    "mining engine did not stop within timeout; aborting"
                );
                h.abort();
                let _ = h.await;
            }
        }
        // Join the build-worker thread — AFTER the coordinator future is gone
        // (returned or aborted above), so its request `Sender` has dropped and
        // the worker's `recv()` has erred. The worker then drains its (≤1)
        // in-flight build and exits. The blocking `thread::join` runs off the
        // runtime via `spawn_blocking` (it must not block a tokio worker).
        //
        // Shutdown completes only when the worker is quiescent. The in-flight
        // build bounds the wait (~20 s worst case today, milliseconds once the
        // per-tip base cache serves same-tip builds). This is the truthful
        // contract: tokio's runtime drop in `#[tokio::main]` waits for started
        // `spawn_blocking` tasks anyway (see tokio src/task/blocking.rs), so a
        // bounded-await-then-proceed strategy only makes the API lie — process
        // exit still blocks on the orphaned join task. Awaiting to completion
        // here also prevents `redb::DatabaseAlreadyOpen` on a restart/reopen
        // that happens before the still-running worker drops its `Arc<Database>`
        // read snapshot.
        //
        // Slow-path observability: a 5 s race emits one info line if the build
        // takes longer than usual; the join future continues to completion in
        // all branches. On worker panic: log + proceed (unchanged tolerance).
        if let Some(worker) = self.mining_worker_handle.take() {
            let joined = tokio::task::spawn_blocking(move || worker.join());
            // Pin the future so we can poll it in both select! arms.
            tokio::pin!(joined);
            tokio::select! {
                biased;
                result = &mut joined => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => {
                            // The worker panicked (a build path crashed). Surface
                            // it rather than swallowing it, then proceed.
                            error!("mining build worker thread panicked");
                        }
                        Err(_) => {
                            // The `spawn_blocking` task itself failed (runtime
                            // shutting down). Nothing more to do; proceed.
                            warn!("mining build worker join task did not complete; proceeding");
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    info!(
                        "waiting for in-flight candidate build to finish before shutdown completes"
                    );
                    // Continue awaiting — the join must complete before we
                    // proceed so the worker's Arc<Database> snapshot drops
                    // before the store is reopened or the process exits.
                    match joined.await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => {
                            error!("mining build worker thread panicked");
                        }
                        Err(_) => {
                            warn!("mining build worker join task did not complete; proceeding");
                        }
                    }
                }
            }
        }
        // Drain the API + inbound surfaces with graceful semantics.
        self.drain_api_and_inbound().await;
        // Indexer task — bounded await so a stuck task can't block
        // shutdown indefinitely. The loop sleeps at most `poll_idle`
        // (config default 1 s) between cancel checks, so 5 s is
        // generous; abort fallback releases the indexer DB lock so
        // the next boot can reopen the redb file cleanly.
        if let Some(mut h) = self.indexer_task_handle.take() {
            if tokio::time::timeout(Duration::from_secs(5), &mut h)
                .await
                .is_err()
            {
                warn!(
                    timeout_s = 5,
                    "indexer task did not stop within timeout; aborting"
                );
                h.abort();
                let _ = h.await;
            }
        }
        // Loop completion — surfaces shutdown_cleanly result.
        let result = match (&mut self.loop_handle).await {
            Ok(r) => r,
            Err(join_err) => Err(Box::new(join_err) as NodeError),
        };
        let elapsed_ms = shutdown_started.elapsed().as_millis() as u64;
        match &result {
            Ok(()) => info!(elapsed_ms, "shutdown complete"),
            Err(e) => warn!(elapsed_ms, error = %e, "shutdown completed with error"),
        }
        result
    }

    /// Drain the API (graceful, with bounded abort fallback) and
    /// inbound listener (immediate abort — no per-connection state
    /// worth draining for `accept()`-only).
    ///
    /// Shared between [`Self::shutdown`] (the normal explicit path)
    /// and the supervisor's abnormal-loop-exit branch in [`run`] so
    /// both paths honor the same TCP-RST-free shutdown contract for
    /// in-flight HTTP requests. The shared helper exists because the
    /// supervisor branch (action-loop-died-unexpectedly) and the
    /// caller-driven shutdown branch must not drift on this contract:
    /// the API handle MUST be requested to drain (not aborted) so
    /// in-flight requests get a clean response rather than a TCP RST.
    ///
    /// Caller is responsible for the action-loop side of shutdown
    /// (signalling `shutdown_tx` if applicable, and awaiting
    /// `loop_handle` afterwards or skipping it if already polled).
    pub(super) async fn drain_api_and_inbound(&mut self) {
        if let Some(tx) = self.api_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.inbound_handle.take() {
            h.abort();
        }
        if let Some(mut h) = self.api_handle.take() {
            // Race graceful drain against a 5-second cap. Axum
            // typically drains in milliseconds once the channel
            // closes; the timeout protects against pathologically
            // slow clients holding a handler open. We pass `&mut h`
            // (not `h`) so the JoinHandle survives a timeout — on
            // elapse we abort and then await the handle so the task
            // is actually torn down (and the bound port released)
            // before this future returns. Without the post-abort
            // await, `abort()` only signals cancellation and the
            // listener socket can outlive `RunHandle::shutdown()`.
            // (A prior version dropped the JoinHandle inside `timeout`,
            // leaving no way to observe termination on the slow-client
            // path.)
            if tokio::time::timeout(Duration::from_secs(5), &mut h)
                .await
                .is_err()
            {
                h.abort();
                let _ = h.await;
            }
        }
    }
}

/// Best-effort cleanup when an embedder drops the handle without calling
/// [`RunHandle::shutdown`]. We can't await the loop join here, but we
/// can fire the shutdown signal so the action loop exits cleanly and
/// abort the API + inbound-listener tasks so their bound ports release.
/// Without this Drop, a forgotten `shutdown()` would leak the API task,
/// the inbound P2P listener (parked in `accept()`), and leave the
/// store's persist pipeline to run-to-completion via field drop order
/// — without this, a forgotten `shutdown()` would leak background
/// tasks and bound ports.
///
/// **Persistence guarantee — IMPORTANT for embedders.** This `Drop` is
/// best-effort: it signals the action loop to exit, but the loop's
/// task continues to run in the background until the persist pipeline
/// drains and `StateStore::shutdown_cleanly()` returns. The caller
/// receives no completion signal. **If you need to know that the
/// AVL/undo_log/chain_index/state_meta atomic-commit invariant has
/// been honored before reopening the same `data_dir`, you must call
/// `RunHandle::shutdown().await` instead of letting the handle drop
/// implicitly.** Drop covers bound-port release but cannot wait for
/// the persist pipeline; durable close requires an explicit
/// `shutdown().await`.
impl Drop for RunHandle {
    fn drop(&mut self) {
        // Drop runs synchronously and cannot await — the
        // `with_graceful_shutdown` future on the API side gets no
        // guaranteed time to drain before we abort the task. Sending
        // `api_shutdown_tx` is still useful: if axum's task happens
        // to be polled before its abort lands (e.g. on a multi-thread
        // runtime where another worker is free), the graceful path
        // wins; otherwise the abort wins and any in-flight HTTP
        // request is force-cancelled. Embedders who need the
        // graceful contract must call `shutdown().await` instead of
        // dropping. (There is no yield between send and abort here —
        // whether axum's task wins is purely a runtime-scheduling
        // race.)
        //
        // If the handle was already drained by `shutdown().await`,
        // every `take()` returns `None` and this is a no-op.
        if let Some(tx) = self.api_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.api_handle.take() {
            h.abort();
        }
        if let Some(h) = self.inbound_handle.take() {
            h.abort();
        }
        // Indexer task: signal cancel + abort. Same persistence caveat
        // as the action loop — we can't await the join here, so the
        // indexer's redb file lock release isn't observable from this
        // path. Embedders who need clean indexer shutdown call
        // `RunHandle::shutdown().await` instead of dropping.
        self.indexer_cancel.store(true, Ordering::Release);
        if let Some(h) = self.indexer_task_handle.take() {
            h.abort();
        }
        // Step B anchor builder: latched cancel + abort. We can't
        // await the JoinHandle here (Drop is sync); the task is
        // observation-only and the runtime will tear it down on
        // its own when this `RunHandle` is dropped, but explicitly
        // aborting releases its resources promptly. send-error is
        // ignored — receivers may already be gone if the task
        // exited before drop.
        let _ = self.anchor_builder_cancel_tx.send(true);
        if let Some(h) = self.anchor_builder_handle.take() {
            h.abort();
        }
        // Mining engine: latched cancel + abort (Drop is sync, can't await).
        // Aborting the coordinator drops its future and the build-request
        // `Sender`, so the worker's `recv()` errs and it drains its in-flight
        // build then exits. We can't join the worker thread here (Drop is sync
        // and must not block), so we just detach it by dropping its handle —
        // same best-effort, no-durable-close caveat as the action loop and
        // indexer above. Embedders needing a clean join call `shutdown().await`.
        let _ = self.mining_engine_cancel_tx.send(true);
        if let Some(h) = self.mining_engine_handle.take() {
            h.abort();
        }
        drop(self.mining_worker_handle.take());
    }
}

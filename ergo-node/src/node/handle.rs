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
use tracing::{info, warn};

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
        // The engine checks the cancel flag at every await (between builds and
        // during backoff), so it exits within at most one candidate build of
        // the signal. `abort()` cannot preempt that synchronous build, but a
        // single build is bounded (one block's worth of work) and far under the
        // 5 s timeout; the abort fallback covers only a pathological stall. The
        // engine's `ChainStoreReader` holds an MVCC read view that does not
        // block the action loop's final durable `shutdown_cleanly`. send-error
        // ignored (the engine may already have exited when its intent sender
        // dropped).
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
        let _ = self.mining_engine_cancel_tx.send(true);
        if let Some(h) = self.mining_engine_handle.take() {
            h.abort();
        }
    }
}

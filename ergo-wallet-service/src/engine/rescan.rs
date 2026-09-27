//! Rescan coordination: the per-wallet replacement for the node's former
//! process-global rescan flags.
//!
//! One [`RescanCoordinator`] is shared (by `Arc`) between the wallet engine,
//! the chain-apply hook and the chain-rollback [`WalletRescanGuard`]. It owns
//! the rescan fence flags and the transition lock that serializes every
//! multi-flag transition, so the engine, the hook and the guard always agree
//! on whether a rescan is running, whether live wallet apply must be
//! quiesced, and whether the wallet is failed closed.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use redb::WriteTransaction;

use crate::wallet::scan::{RescanError, WalletScanService};
use crate::wallet::tables::WALLET_SCAN_INVALIDATED;
use crate::wallet::{RescanGuard, WalletStore};

/// Why [`RescanCoordinator::begin_rescan`] refused to start a rescan.
#[derive(Debug, Clone)]
pub enum BeginRescanError {
    /// The wallet is failed closed; only a full (`fromHeight = 0`) rescan
    /// may recover it.
    FullRescanRequired,
    /// A destructive rescan task is already running.
    AlreadyInProgress,
    /// The owning node session is shutting down.
    Shutdown,
    /// A positive start height the wallet cursor cannot resume from.
    InvalidStart { requested: u32, cursor: Option<u32> },
    /// The start could not be validated against the wallet store.
    Store(String),
}

/// Rescan fence state for one wallet instance.
///
/// Flag meanings (all `SeqCst`):
///
/// - `in_progress`: set when a rescan starts; read by the chain-apply hook
///   (`allow_non_contiguous_wallet_apply`) and by the command fences. Cleared
///   on normal completion; retained when rescan invalidation or outcome
///   persistence fails closed.
/// - `cancel_requested`: set by rollback or shutdown while a rescan task is
///   active. The task observes it independently of the fence flag.
/// - `task_active`: true only while a destructive rescan task is running. A
///   boot or fail-closed fence sets `in_progress` without setting it.
/// - `fail_closed`: latch for a rescan whose invalidation or outcome could
///   not be persisted. Distinct from normal full-rescan activity.
/// - `from_height`: start height of the in-flight rescan, set alongside
///   `in_progress`; only meaningful while `in_progress` is true.
/// - `scan_rebuild`: set for a full rebuild (`fromHeight == 0`) that rebuilds
///   the registered `/scan/*` tables, and forced on when a rescan fails
///   closed. The hook's scan path no-ops while it is set, quiescing live scan
///   apply for the rebuild's duration: the rebuild clears and repopulates the
///   scan tables block by block, so a concurrent live write would race it. A
///   partial rescan normally does not set it, so live scan tracking continues.
/// - `shutdown_requested`: the owning node session is shutting down; no new
///   rescan may start.
///
/// Every multi-flag transition runs under the coordinator's transition lock.
/// Nothing here is persisted: a restart starts from a fresh coordinator and
/// the durable `WALLET_SCAN_INVALIDATED` / rescan-state rows decide recovery.
#[derive(Debug, Default)]
pub struct RescanCoordinator {
    transition: Mutex<()>,
    in_progress: AtomicBool,
    cancel_requested: AtomicBool,
    task_active: AtomicBool,
    fail_closed: AtomicBool,
    from_height: AtomicU32,
    scan_rebuild: AtomicBool,
    shutdown_requested: AtomicBool,
}

impl RescanCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    fn transition(&self) -> MutexGuard<'_, ()> {
        self.transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn latch_fail_closed_locked(&self) {
        self.fail_closed.store(true, Ordering::SeqCst);
        self.in_progress.store(true, Ordering::SeqCst);
        self.scan_rebuild.store(true, Ordering::SeqCst);
    }

    fn finish_task_locked(&self) {
        self.cancel_requested.store(false, Ordering::SeqCst);
        self.task_active.store(false, Ordering::SeqCst);
    }

    fn clear_state_locked(&self) {
        self.fail_closed.store(false, Ordering::SeqCst);
        self.in_progress.store(false, Ordering::SeqCst);
        self.scan_rebuild.store(false, Ordering::SeqCst);
    }

    /// Rescan fence: a rescan is running or the wallet is failed closed.
    pub fn in_progress(&self) -> bool {
        self.in_progress.load(Ordering::SeqCst)
    }

    /// Cancellation requested for the active rescan task.
    pub fn cancel_requested(&self) -> bool {
        self.cancel_requested.load(Ordering::SeqCst)
    }

    /// A destructive rescan task is running.
    pub fn task_active(&self) -> bool {
        self.task_active.load(Ordering::SeqCst)
    }

    /// The wallet is failed closed until a full rescan succeeds.
    pub fn fail_closed(&self) -> bool {
        self.fail_closed.load(Ordering::SeqCst)
    }

    /// Start height of the in-flight rescan (meaningful only while
    /// [`Self::in_progress`] is true).
    pub fn from_height(&self) -> u32 {
        self.from_height.load(Ordering::SeqCst)
    }

    /// A full rebuild (or a fail-closed latch) is quiescing live scan apply.
    pub fn scan_rebuild_in_progress(&self) -> bool {
        self.scan_rebuild.load(Ordering::SeqCst)
    }

    /// The owning session is shutting down.
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// The command fence: normal wallet operations are refused while the
    /// wallet is failed closed, a rescan is running, or a scan rebuild is
    /// in flight.
    pub fn operations_fenced(&self) -> bool {
        self.fail_closed() || self.in_progress() || self.scan_rebuild_in_progress()
    }

    /// Cancellation predicate polled by a running rescan: cancellation was
    /// requested, or the rescan fence was cleared underneath it.
    pub fn rescan_cancelled(&self) -> bool {
        self.cancel_requested() || !self.in_progress()
    }

    /// Latch the fail-closed fence (and the rescan + scan-rebuild fences).
    pub fn latch_fail_closed(&self) {
        let _transition = self.transition();
        self.latch_fail_closed_locked();
    }

    /// Clear every fence and the task/cancel flags.
    pub fn clear_guards(&self) {
        let _transition = self.transition();
        self.clear_state_locked();
        self.finish_task_locked();
    }

    /// A new node session took ownership of this wallet: clear the shutdown
    /// and cancellation requests left by a previous session.
    pub fn begin_session(&self) {
        let _transition = self.transition();
        self.shutdown_requested.store(false, Ordering::SeqCst);
        self.cancel_requested.store(false, Ordering::SeqCst);
    }

    /// Atomically validate and claim a rescan starting at `start_h`.
    pub fn begin_rescan(
        &self,
        start_h: u32,
        store: &dyn WalletStore,
        tip_height: u32,
    ) -> Result<(), BeginRescanError> {
        let _transition = self.transition();
        if self.shutdown_requested() {
            return Err(BeginRescanError::Shutdown);
        }
        if start_h > 0 {
            match WalletScanService::validate_rescan_start(store, start_h, tip_height) {
                Ok(()) => {}
                Err(RescanError::InvalidStart { requested, cursor }) => {
                    return Err(BeginRescanError::InvalidStart { requested, cursor })
                }
                Err(error) => return Err(BeginRescanError::Store(error.to_string())),
            }
        }
        let was_fail_closed = self.fail_closed();
        if was_fail_closed && start_h != 0 {
            return Err(BeginRescanError::FullRescanRequired);
        }
        if self.task_active() {
            return Err(BeginRescanError::AlreadyInProgress);
        }
        self.task_active.store(true, Ordering::SeqCst);
        let full_rebuild = start_h == 0;
        if was_fail_closed {
            self.fail_closed.store(false, Ordering::SeqCst);
        }
        self.cancel_requested.store(false, Ordering::SeqCst);
        self.in_progress.store(true, Ordering::SeqCst);
        self.from_height.store(start_h, Ordering::SeqCst);
        self.scan_rebuild.store(full_rebuild, Ordering::SeqCst);
        Ok(())
    }

    /// A claimed rescan could not start: fail closed and release the task.
    pub fn fail_rescan_start(&self) {
        let _transition = self.transition();
        self.latch_fail_closed_locked();
        self.finish_task_locked();
    }

    /// The owning session is shutting down: refuse new rescans, cancel the
    /// running one, and fail closed if a task was active.
    pub fn request_shutdown(&self) {
        let _transition = self.transition();
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.cancel_requested.store(true, Ordering::SeqCst);
        if self.task_active() {
            self.latch_fail_closed_locked();
        }
    }

    /// A rescan task finished: keep the wallet fenced when it must stay
    /// blocked (or the task is unwinding), otherwise clear the fences; the
    /// task slot is released either way.
    pub fn finish_rescan(&self, keep_blocked: bool, panicking: bool) {
        let _transition = self.transition();
        if keep_blocked || panicking {
            self.latch_fail_closed_locked();
        } else {
            self.clear_state_locked();
        }
        self.finish_task_locked();
    }

    /// Test support: force the rescan fence flag alone.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_in_progress_for_test(&self, value: bool) {
        self.in_progress.store(value, Ordering::SeqCst);
    }

    /// Test support: force the scan-rebuild quiesce flag alone.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_scan_rebuild_for_test(&self, value: bool) {
        self.scan_rebuild.store(value, Ordering::SeqCst);
    }
}

/// The chain-rollback [`RescanGuard`] for one wallet: aborts the wallet's
/// in-progress rescan atomically with a chain rollback.
///
/// - `abort_in_progress`: called by `rollback_block_from_wallet` on every
///   rollback (success or failure). Invalidates (`WALLET_SCAN_INVALIDATED =
///   true`, queued on the caller's write transaction) and fails closed ONLY
///   if a rescan task was actually running — a successful rollback without an
///   active rescan stays consistent with the rolled-back chain.
/// - `force_invalidate`: called by `StateStore::rollback_to`'s failure
///   branches (missing block section, block-section read error). Always
///   invalidates and fails closed.
///
/// The flags are process-local, not persisted; the invalidation row is
/// durable once the caller commits, and an operator-driven rescan completing
/// successfully is the only path that clears it.
#[derive(Debug, Clone)]
pub struct WalletRescanGuard {
    coordinator: Arc<RescanCoordinator>,
}

impl WalletRescanGuard {
    pub fn new(coordinator: Arc<RescanCoordinator>) -> Self {
        Self { coordinator }
    }

    pub fn coordinator(&self) -> &Arc<RescanCoordinator> {
        &self.coordinator
    }
}

impl RescanGuard for WalletRescanGuard {
    /// Abort an in-progress rescan if one is active. A rollback that races a
    /// rescan invalidates because the rescan was working against a chain
    /// state that's now gone.
    fn abort_in_progress(&self, txn: &WriteTransaction) -> Result<(), redb::Error> {
        if self.coordinator.task_active() {
            self.coordinator
                .cancel_requested
                .store(true, Ordering::SeqCst);
            self.coordinator.latch_fail_closed();
            txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), true)?;
        }
        Ok(())
    }

    /// Unconditionally invalidate: wallet history cannot be replayed on the
    /// failure branches that call this, whether or not a rescan was active.
    fn force_invalidate(&self, txn: &WriteTransaction) -> Result<(), redb::Error> {
        if self.coordinator.task_active() {
            self.coordinator
                .cancel_requested
                .store(true, Ordering::SeqCst);
        }
        self.coordinator.latch_fail_closed();
        txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), true)?;
        Ok(())
    }
}

//! Rescan coordination and orchestration.
//!
//! One [`RescanCoordinator`] per wallet (the replacement for the node's
//! former process-global rescan flags) is shared by `Arc` between the wallet
//! engine, the chain-apply hook and the chain-rollback [`WalletRescanGuard`].
//! It owns the rescan fence flags and the transition lock that serializes
//! every multi-flag transition, so the engine, the hook and the guard always
//! agree on whether a rescan is running, whether live wallet apply must be
//! quiesced, and whether the wallet is failed closed.
//!
//! [`WalletEngine::prepare_rescan`] validates and claims a `/wallet/rescan`
//! and returns a [`RescanJob`] whose blocking [`RescanJob::run`] performs
//! it; [`recover_interrupted_rescan`] is the boot-time recovery of a rescan
//! (or cursor) a restart interrupted.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use ergo_wallet_protocol::WalletAdminError;
use redb::WriteTransaction;

use crate::runtime::WalletService;
use crate::wallet::scan::{RescanError, RescanReadError, ScanRescanMatcher, WalletScanService};
use crate::wallet::tables::WALLET_SCAN_INVALIDATED;
use crate::wallet::{RescanGuard, RescanState, WalletStore, WalletStoreError};

use super::scan::{
    build_rescan_matcher_from_store, empty_rescan_matcher, RescanScanMatcher, ScanRegistryLoadError,
};
use super::{WalletChainAccess, WalletEngine};

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

    /// This crate's tests only: force the scan-rebuild quiesce flag alone,
    /// bypassing the transition lock.
    #[cfg(test)]
    pub(crate) fn set_scan_rebuild_for_test(&self, value: bool) {
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
///
/// Obtained from its [`WalletStateHook`](super::WalletStateHook)
/// (`rescan_guard()` / `wiring()`), so it always shares the hook's — and so
/// the engine's — coordinator.
#[derive(Debug, Clone)]
pub struct WalletRescanGuard {
    coordinator: Arc<RescanCoordinator>,
}

impl WalletRescanGuard {
    pub(crate) fn new(coordinator: Arc<RescanCoordinator>) -> Self {
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

/// A prepared `/wallet/rescan`: validated, claimed on the coordinator and
/// recorded as `Running`, ready to execute on a blocking thread.
///
/// [`WalletEngine::prepare_rescan`] does every check and state transition
/// that can refuse the rescan; [`RescanJob::run`] performs the replay and
/// persists its outcome. The embedding process decides where `run` executes
/// (the node spawns it with `tokio::task::spawn_blocking` and tracks the task
/// with its wallet session).
///
/// The job's fence guard is armed when the job is built, failed closed by
/// default: a job dropped without running (a blocking task that never
/// started) releases the task slot and leaves the wallet failed closed, as a
/// failed rescan start does, so a full (`fromHeight = 0`) rescan can recover
/// it.
pub struct RescanJob {
    kind: RescanJobKind,
    flags: RescanFlagsGuard,
}

enum RescanJobKind {
    /// Full / partial rebuild straight from the chain accessor.
    Rebuild(RebuildRescan),
    /// Bounded replay through the service runtime's chain client.
    Service(ServiceRescan),
}

struct RebuildRescan {
    chain: Arc<dyn WalletChainAccess>,
    store: Arc<dyn WalletStore>,
    rescan: Arc<RescanCoordinator>,
    trees: BTreeSet<Vec<u8>>,
    pks: BTreeMap<u64, [u8; 33]>,
    start_h: u32,
    tip_h: u32,
    scan_matcher: Option<RescanScanMatcher>,
}

struct ServiceRescan {
    service: WalletService,
    store: Arc<dyn WalletStore>,
    rescan: Arc<RescanCoordinator>,
    from_height: u32,
}

impl RescanJob {
    /// A claimed rescan, with its fence guard armed failed closed.
    fn new(kind: RescanJobKind, rescan: Arc<RescanCoordinator>) -> Self {
        Self {
            kind,
            flags: RescanFlagsGuard::armed(rescan),
        }
    }

    /// True when the job replays through the service runtime (the embedded
    /// node's configuration) rather than the chain accessor.
    pub fn uses_service(&self) -> bool {
        matches!(self.kind, RescanJobKind::Service(_))
    }

    /// Run the rescan to completion on the calling (blocking) thread and
    /// persist its outcome. The coordinator's fences are released, or kept
    /// failed closed, when this returns (or unwinds).
    pub fn run(self) {
        let RescanJob { kind, flags } = self;
        match kind {
            RescanJobKind::Rebuild(job) => job.run(flags),
            RescanJobKind::Service(job) => job.run(flags),
        }
    }
}

impl RebuildRescan {
    fn run(self, flags: RescanFlagsGuard) {
        let RebuildRescan {
            chain,
            store,
            rescan,
            trees,
            pks,
            start_h,
            tip_h,
            scan_matcher,
        } = self;
        let reached_height = Arc::new(AtomicU32::new(start_h));
        let reached_for_block = reached_height.clone();
        let reached_for_tip = reached_height.clone();
        let mut flags = flags;
        flags.start();
        let result = WalletScanService::rescan_full_rebuild_store(
            store.as_ref(),
            trees,
            pks,
            start_h,
            tip_h,
            |height| {
                let result = chain.read_block_at(height);
                if matches!(&result, Ok(Some(_))) {
                    reached_for_block.store(height, Ordering::SeqCst);
                }
                result
            },
            || {
                chain.tip_height().map_err(|e| RescanReadError::Storage {
                    height: reached_for_tip.load(Ordering::SeqCst),
                    source: WalletStoreError::decode(e.to_string()),
                })
            },
            || rescan.rescan_cancelled(),
            scan_matcher
                .as_ref()
                .map(|matcher| matcher as &dyn ScanRescanMatcher),
        );
        let state = match &result {
            Ok(_) => RescanState::Idle,
            Err(error) => rescan_failure_state(start_h, error),
        };
        let state_result = persist_rescan_state(store.as_ref(), &state);
        let scan_invalidated = if state_result.is_ok() {
            store
                .read()
                .and_then(|read| read.scan_invalidated())
                .unwrap_or(true)
        } else {
            true
        };
        if rescan_should_stay_blocked(&result, state_result.is_ok(), scan_invalidated) {
            flags.block();
        }
        if let Err(error) = state_result {
            tracing::error!(%error, "failed to persist wallet rescan outcome");
        }
    }
}

impl ServiceRescan {
    fn run(self, flags: RescanFlagsGuard) {
        let ServiceRescan {
            service,
            store,
            rescan,
            from_height,
        } = self;
        let mut flags = flags;
        flags.start();
        let result =
            service.rescan_to_tip_with_cancellation(from_height, || rescan.rescan_cancelled());
        if let Err(error) = &result {
            let already_failed = store
                .read()
                .and_then(|read| read.rescan_state())
                .map(|state| matches!(state, RescanState::Failed { .. }))
                .unwrap_or(false);
            if !already_failed {
                let _ = persist_rescan_state(
                    store.as_ref(),
                    &RescanState::Failed {
                        height: from_height,
                        reason: error.to_string(),
                    },
                );
            }
            flags.block();
        } else if store
            .read()
            .and_then(|read| read.scan_invalidated())
            .unwrap_or(true)
        {
            flags.block();
        }
    }
}

impl WalletEngine {
    /// `/wallet/rescan`: validate and claim a rescan from `from_height`
    /// (clamped to the tip) and record it as `Running`, returning the job
    /// that performs the replay. Every refusal — unsupported or pruned
    /// backend, scan-registry failure, a start the coordinator rejects, a
    /// state row that cannot be persisted — is returned here, before any job
    /// exists.
    #[allow(clippy::result_large_err)]
    pub fn prepare_rescan(&mut self, from_height: u32) -> Result<RescanJob, WalletAdminError> {
        let tip_h = rescan_tip(self.chain.as_ref())?;
        if let Some(service) = self.service.as_deref() {
            return self.prepare_service_rescan(service, from_height.min(tip_h), tip_h);
        }
        let start_h = from_height.min(tip_h);
        let mut registry_recovered = false;
        let scan_matcher = if start_h == 0 {
            match build_rescan_matcher_from_store(self.store.as_ref()) {
                Ok(Some(matcher)) => Some(matcher),
                Ok(None) => Some(empty_rescan_matcher()),
                Err(ScanRegistryLoadError::Read(error)) => {
                    tracing::error!(%error, "scan registry read failed; preserving registry");
                    return Err(WalletAdminError::Internal(format!(
                        "scan registry read failed: {error}"
                    )));
                }
                Err(ScanRegistryLoadError::Corrupt(error)) => {
                    tracing::error!(%error, "scan registry is corrupt; discarding scan registry and scan tracking for recovery");
                    if let Err(recovery_error) = recover_corrupt_scan_registry(self.store.as_ref())
                    {
                        fail_closed_after_scan_recovery_error(self.store.as_ref(), &self.rescan);
                        return Err(WalletAdminError::Internal(format!(
                            "scan registry is corrupt and recovery failed: {recovery_error}"
                        )));
                    }
                    registry_recovered = true;
                    Some(empty_rescan_matcher())
                }
            }
        } else {
            None
        };
        if let Err(error) = begin_rescan_process(&self.rescan, start_h, self.store.as_ref(), tip_h)
        {
            if registry_recovered {
                fail_closed_after_scan_recovery_error(self.store.as_ref(), &self.rescan);
            }
            return Err(error);
        }
        if let Err(error) = persist_rescan_state(
            self.store.as_ref(),
            &RescanState::Running {
                from_height: start_h,
            },
        ) {
            fail_rescan_start_with_invalidation(self.store.as_ref(), &self.rescan);
            return Err(WalletAdminError::Internal(error.to_string()));
        }

        let (trees, pks) = {
            let state = self.state.read();
            (
                state.tracked_p2pk_trees().iter().cloned().collect(),
                state.cached_pubkeys().clone(),
            )
        };
        Ok(RescanJob::new(
            RescanJobKind::Rebuild(RebuildRescan {
                chain: self.chain.clone(),
                store: self.store.clone(),
                rescan: self.rescan.clone(),
                trees,
                pks,
                start_h,
                tip_h,
                scan_matcher,
            }),
            self.rescan.clone(),
        ))
    }

    #[allow(clippy::result_large_err)]
    fn prepare_service_rescan(
        &self,
        service: &WalletService,
        from_height: u32,
        tip_h: u32,
    ) -> Result<RescanJob, WalletAdminError> {
        if from_height == 0 {
            match build_rescan_matcher_from_store(self.store.as_ref()) {
                Ok(_) => {}
                Err(ScanRegistryLoadError::Read(error)) => {
                    return Err(WalletAdminError::Internal(format!(
                        "scan registry read failed: {error}"
                    )));
                }
                Err(ScanRegistryLoadError::Corrupt(error)) => {
                    tracing::error!(%error, "scan registry is corrupt; discarding registry before service rescan");
                    if let Err(recovery_error) = recover_corrupt_scan_registry(self.store.as_ref())
                    {
                        fail_closed_after_scan_recovery_error(self.store.as_ref(), &self.rescan);
                        return Err(WalletAdminError::Internal(format!(
                            "scan registry is corrupt and recovery failed: {recovery_error}"
                        )));
                    }
                }
            }
        }
        begin_rescan_process(&self.rescan, from_height, self.store.as_ref(), tip_h)?;
        if let Err(error) =
            persist_rescan_state(self.store.as_ref(), &RescanState::Running { from_height })
        {
            fail_rescan_start_with_invalidation(self.store.as_ref(), &self.rescan);
            return Err(WalletAdminError::Internal(error.to_string()));
        }
        if from_height == 0 {
            if let Err(error) = self.store.as_ref().persist_scan_invalidation(true) {
                fail_rescan_start_with_invalidation(self.store.as_ref(), &self.rescan);
                return Err(WalletAdminError::Internal(error.to_string()));
            }
        }
        Ok(RescanJob::new(
            RescanJobKind::Service(ServiceRescan {
                service: service.clone(),
                store: self.store.clone(),
                rescan: self.rescan.clone(),
                from_height,
            }),
            self.rescan.clone(),
        ))
    }
}

fn begin_rescan_process(
    rescan: &RescanCoordinator,
    start_h: u32,
    store: &dyn WalletStore,
    tip_height: u32,
) -> Result<(), WalletAdminError> {
    match rescan.begin_rescan(start_h, store, tip_height) {
        Ok(rescan_start) => Ok(rescan_start),
        Err(BeginRescanError::FullRescanRequired) => Err(WalletAdminError::RescanUnavailable(
            "full rescan required to recover wallet state".to_string(),
        )),
        Err(BeginRescanError::AlreadyInProgress) => Err(WalletAdminError::RescanUnavailable(
            "rescan already in progress".to_string(),
        )),
        Err(BeginRescanError::Shutdown) => Err(WalletAdminError::RescanUnavailable(
            "wallet is shutting down".to_string(),
        )),
        Err(BeginRescanError::InvalidStart { requested, cursor }) => {
            let cursor = cursor
                .map(|height| height.to_string())
                .unwrap_or_else(|| "none".to_string());
            Err(WalletAdminError::RescanUnavailable(format!(
                "full rescan required: use fromHeight=0 (requested {requested}, cursor {cursor})"
            )))
        }
        Err(BeginRescanError::Store(error)) => Err(WalletAdminError::Internal(error)),
    }
}

#[allow(clippy::result_large_err)]
fn rescan_tip(chain: &dyn WalletChainAccess) -> Result<u32, WalletAdminError> {
    if !chain
        .read_block_at_supported()
        .map_err(map_rescan_read_error)?
    {
        return Err(WalletAdminError::RescanUnavailable(
            "chain block-read not available on this backend".to_string(),
        ));
    }
    if chain.is_pruned() {
        return Err(WalletAdminError::RestorePruningUnsupported);
    }
    chain
        .tip_height()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))
}

fn recover_corrupt_scan_registry(store: &dyn WalletStore) -> Result<(), WalletStoreError> {
    store.persist_scan_invalidation(true)?;
    clear_scan_registry_for_recovery(store)
}

fn fail_rescan_start_with_invalidation(store: &dyn WalletStore, rescan: &RescanCoordinator) {
    rescan.fail_rescan_start();
    if let Err(error) = store.persist_scan_invalidation(true) {
        tracing::error!(%error, "failed to persist invalidation after rescan start failure");
    }
}

fn fail_closed_after_scan_recovery_error(store: &dyn WalletStore, rescan: &RescanCoordinator) {
    rescan.latch_fail_closed();
    if let Err(error) = store.persist_scan_invalidation(true) {
        tracing::error!(%error, "failed to reassert scan invalidation after scan recovery failure");
    }
}

fn clear_scan_registry_for_recovery(store: &dyn WalletStore) -> Result<(), WalletStoreError> {
    let mut write = store.begin_write()?;
    write.clear_scan_registry()?;
    write.commit()
}

fn persist_rescan_state(
    store: &dyn WalletStore,
    state: &RescanState,
) -> Result<(), WalletStoreError> {
    let mut write = store.begin_write()?;
    write.set_rescan_state(state)?;
    write.commit()
}

fn rescan_failure_state(from_height: u32, error: &RescanError) -> RescanState {
    let height = match error {
        RescanError::Read(RescanReadError::Missing { height })
        | RescanError::Read(RescanReadError::Corrupt { height, .. })
        | RescanError::Read(RescanReadError::Storage { height, .. })
        | RescanError::Read(RescanReadError::Chain { height, .. })
        | RescanError::Cancelled { height }
        | RescanError::Matcher { height, .. } => *height,
        RescanError::TipChanged { expected, .. } => expected.height,
        RescanError::Storage(_)
        | RescanError::InvalidStart { .. }
        | RescanError::Invalidation { .. } => from_height,
    };
    RescanState::Failed {
        height,
        reason: error.to_string(),
    }
}

fn rescan_should_stay_blocked(
    result: &Result<u32, RescanError>,
    outcome_persisted: bool,
    scan_invalidated: bool,
) -> bool {
    result.is_err() || !outcome_persisted || scan_invalidated
}

/// Releases (or keeps failed closed) the coordinator's fences when a rescan
/// job ends, including by unwinding or by being dropped without running.
struct RescanFlagsGuard {
    rescan: Arc<RescanCoordinator>,
    keep_blocked: bool,
}

impl RescanFlagsGuard {
    /// Armed failed closed: dropped before [`Self::start`], it releases the
    /// task slot and keeps the wallet failed closed, like
    /// [`RescanCoordinator::fail_rescan_start`].
    fn armed(rescan: Arc<RescanCoordinator>) -> Self {
        Self {
            rescan,
            keep_blocked: true,
        }
    }

    /// The job is running: from here on its outcome decides whether the
    /// wallet stays blocked ([`Self::block`]).
    fn start(&mut self) {
        self.keep_blocked = false;
    }

    fn block(&mut self) {
        self.keep_blocked = true;
        self.rescan.latch_fail_closed();
    }
}

impl Drop for RescanFlagsGuard {
    fn drop(&mut self) {
        self.rescan
            .finish_rescan(self.keep_blocked, std::thread::panicking());
    }
}

fn map_rescan_read_error(error: RescanReadError) -> WalletAdminError {
    match error {
        RescanReadError::Missing { height } => {
            WalletAdminError::RescanUnavailable(format!("block missing at height {height}"))
        }
        other => WalletAdminError::Internal(other.to_string()),
    }
}

/// Boot-time recovery for a wallet whose last run may have been interrupted.
///
/// A `Running` or `Failed` rescan state, a persisted scan invalidation, or a
/// scan cursor that disagrees with the committed tip while wallet data exists
/// leaves the wallet failed closed with a durable `Failed` rescan state (and
/// scan invalidation) that tells the operator to rescan. A clean store clears
/// any stale fences on `rescan`. Any read or write failure also leaves the
/// wallet failed closed.
pub fn recover_interrupted_rescan(
    store: &dyn WalletStore,
    rescan: &RescanCoordinator,
) -> Result<(), WalletStoreError> {
    let result = (|| {
        let read = store.read()?;
        let state = read.rescan_state()?;
        let invalidated = read.scan_invalidated()?;
        let cursor = read.scan_cursor()?;
        let committed_tip = read.committed_tip()?.map(|(height, _)| height);
        let tracked_count = read.tracked_pubkeys_with_paths()?.len();
        let box_count = read.all_boxes()?.len();
        let transaction_count = read.all_transactions()?.len();
        let registered_scan_count = read.registered_scan_count()?;
        let has_wallet_facts = tracked_count > 0
            || box_count > 0
            || transaction_count > 0
            || registered_scan_count > 0;
        let cursor_behind = has_wallet_facts
            && cursor.is_some_and(|cursor| {
                committed_tip.is_some_and(|tip_height| cursor.height < tip_height)
            });
        let cursor_ahead = has_wallet_facts
            && cursor.is_some_and(|cursor| {
                committed_tip.is_some_and(|tip_height| cursor.height > tip_height)
            });
        let cursor_missing_with_facts = has_wallet_facts
            && cursor.is_none()
            && committed_tip.is_some_and(|tip_height| tip_height > 0);
        let unsafe_state = match &state {
            RescanState::Running { .. } | RescanState::Failed { .. } => true,
            RescanState::Idle => {
                invalidated || cursor_behind || cursor_ahead || cursor_missing_with_facts
            }
        };
        if !unsafe_state {
            rescan.clear_guards();
            return Ok(());
        }

        rescan.latch_fail_closed();
        let failed = match state {
            RescanState::Running { from_height } => RescanState::Failed {
                height: from_height,
                reason: "interrupted by restart".to_string(),
            },
            RescanState::Failed { height, reason } => RescanState::Failed { height, reason },
            RescanState::Idle => {
                let height = cursor.map(|cursor| cursor.height).unwrap_or(0);
                let reason = if cursor_behind {
                    "wallet cursor behind committed tip on boot".to_string()
                } else if cursor_ahead {
                    "wallet cursor ahead of committed tip on boot".to_string()
                } else if cursor_missing_with_facts {
                    "wallet cursor missing with existing wallet data on boot".to_string()
                } else {
                    "wallet scan invalidated on boot".to_string()
                };
                RescanState::Failed { height, reason }
            }
        };
        let mut write = store.begin_write()?;
        write.set_scan_invalidated(true)?;
        write.set_rescan_state(&failed)?;
        write.commit()?;
        rescan.latch_fail_closed();
        Ok(())
    })();
    if result.is_err() {
        rescan.latch_fail_closed();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::RedbWalletStore;

    fn store_with_cursor_zero() -> (tempfile::TempDir, RedbWalletStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::new(Arc::new(
            redb::Database::create(dir.path().join("state.redb")).unwrap(),
        ));
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(0, None).unwrap();
        write.commit().unwrap();
        (dir, store)
    }

    #[test]
    fn shutdown_requests_active_rescan_cancellation() {
        let rescan = RescanCoordinator::new();
        let (_dir, store) = store_with_cursor_zero();
        rescan.begin_rescan(1, &store, 1).unwrap();
        rescan.request_shutdown();
        assert!(rescan.cancel_requested());
        assert!(rescan.fail_closed());
        assert!(rescan.task_active());
        assert!(rescan.shutdown_requested());
        assert!(matches!(
            rescan.begin_rescan(0, &store, 0),
            Err(BeginRescanError::Shutdown)
        ));
    }

    #[test]
    fn begin_session_clears_shutdown_and_cancel_requests() {
        let rescan = RescanCoordinator::new();
        let (_dir, store) = store_with_cursor_zero();
        rescan.request_shutdown();
        assert!(rescan.shutdown_requested());
        assert!(rescan.cancel_requested());
        assert!(matches!(
            rescan.begin_rescan(0, &store, 0),
            Err(BeginRescanError::Shutdown)
        ));

        rescan.begin_session();
        assert!(!rescan.shutdown_requested());
        assert!(!rescan.cancel_requested());
        rescan.begin_rescan(0, &store, 0).unwrap();
        assert!(rescan.task_active());
    }

    #[test]
    fn rollback_requests_cancellation_for_active_rescan() {
        let rescan = Arc::new(RescanCoordinator::new());
        let (_cursor_dir, cursor_store) = store_with_cursor_zero();
        rescan.begin_rescan(1, &cursor_store, 1).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
        let txn = db.begin_write().unwrap();
        RescanGuard::abort_in_progress(&WalletRescanGuard::new(rescan.clone()), &txn).unwrap();
        txn.commit().unwrap();
        assert!(rescan.cancel_requested());
        assert!(rescan.task_active());
        assert!(rescan.in_progress());
    }

    /// A chain whose blocks are all "unavailable" but whose block reads are
    /// supported, at tip `tip`: enough for `prepare_rescan` to claim a
    /// rescan (the tests below never run the job).
    struct TipChain {
        tip: u32,
    }

    impl WalletChainAccess for TipChain {
        fn wallet_scan_height(&self) -> Result<u32, super::super::ChainAccessError> {
            Ok(0)
        }

        fn tip_height(&self) -> Result<u32, super::super::ChainAccessError> {
            Ok(self.tip)
        }

        fn is_pruned(&self) -> bool {
            false
        }

        fn read_block_at(
            &self,
            _height: u32,
        ) -> Result<Option<crate::wallet::scan::RescanBlock>, RescanReadError> {
            Ok(None)
        }

        fn read_block_at_supported(&self) -> Result<bool, RescanReadError> {
            Ok(true)
        }
    }

    struct NoSubmit;

    #[async_trait::async_trait]
    impl super::super::TxSubmitter for NoSubmit {
        async fn submit_transaction(
            &self,
            _tx_bytes: Vec<u8>,
        ) -> Result<String, super::super::TxSubmitError> {
            unreachable!("rescan tests never submit")
        }
    }

    /// An engine over a store whose cursor sits at 0 and a chain at tip 1.
    fn engine_at_tip_one() -> (tempfile::TempDir, WalletEngine) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(RedbWalletStore::new(Arc::new(
            redb::Database::create(dir.path().join("state.redb")).unwrap(),
        )));
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(0, None).unwrap();
        write.commit().unwrap();
        let engine = WalletEngine::new(super::super::WalletEngineParts {
            storage: Arc::new(parking_lot::RwLock::new(
                ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet")),
            )),
            state: Arc::new(parking_lot::RwLock::new(crate::state::WalletState::empty(
                false,
            ))),
            store,
            chain: Arc::new(TipChain { tip: 1 }),
            config: super::super::WalletEngineConfig {
                network: ergo_ser::address::NetworkPrefix::Mainnet,
                expose_private_keys: false,
                reemission: None,
                min_relay_fee_nano_erg: 1_000_000,
                max_tx_size_bytes: 98_304,
            },
            submitter: Arc::new(NoSubmit),
            mempool: Arc::new(super::super::NoopMempoolOverlay::new()),
            service: None,
            rescan: Arc::new(RescanCoordinator::new()),
        });
        (dir, engine)
    }

    #[test]
    fn a_prepared_job_dropped_unrun_fails_closed_and_frees_the_task_slot() {
        let (_dir, mut engine) = engine_at_tip_one();
        let rescan = engine.rescan_coordinator().clone();
        let job = engine.prepare_rescan(1).unwrap();
        assert!(rescan.task_active());
        assert!(!rescan.fail_closed());

        drop(job);
        assert!(!rescan.task_active());
        assert!(rescan.fail_closed());
        assert!(rescan.in_progress());
        assert!(rescan.scan_rebuild_in_progress());

        // Failed closed: a partial rescan is refused, a full one recovers.
        assert!(matches!(
            engine.prepare_rescan(1),
            Err(WalletAdminError::RescanUnavailable(message))
                if message == "full rescan required to recover wallet state"
        ));
        let recovery = engine.prepare_rescan(0).unwrap();
        assert!(rescan.task_active());
        assert!(!rescan.fail_closed());
        drop(recovery);
    }

    #[test]
    fn rescan_storage_failure_preserves_reached_height() {
        let state = rescan_failure_state(
            0,
            &crate::wallet::scan::RescanError::Read(
                crate::wallet::scan::RescanReadError::Storage {
                    height: 42,
                    source: crate::wallet::WalletStoreError::decode("boom".to_string()),
                },
            ),
        );
        assert!(matches!(
            state,
            crate::wallet::RescanState::Failed { height: 42, .. }
        ));
    }

    #[test]
    fn explicit_rescan_clears_stale_fail_closed_guards() {
        let rescan = RescanCoordinator::new();
        rescan.latch_fail_closed();
        let (_dir, store) = tempfile::tempdir()
            .map(|dir| {
                let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
                (dir, RedbWalletStore::new(db))
            })
            .unwrap();
        assert!(begin_rescan_process(&rescan, 5, &store, 5).is_err());
        begin_rescan_process(&rescan, 0, &store, 0).unwrap();
        assert!(rescan.scan_rebuild_in_progress());
        assert!(!rescan.fail_closed());
        assert!(rescan.in_progress());
        assert!(rescan.scan_rebuild_in_progress());
    }

    #[test]
    fn invalidation_persistence_failure_keeps_rescan_blocked() {
        let error = crate::wallet::scan::RescanError::Invalidation {
            source: crate::wallet::WalletStoreError::Decode("injected".to_string()),
        };
        let state = rescan_failure_state(17, &error);
        assert!(matches!(
            state,
            crate::wallet::RescanState::Failed { height: 17, .. }
        ));
        assert!(rescan_should_stay_blocked(&Err(error), true, false));
        assert!(!rescan_should_stay_blocked(&Ok(0), true, false));
        assert!(rescan_should_stay_blocked(&Ok(0), false, false));
        assert!(rescan_should_stay_blocked(
            &Err(crate::wallet::scan::RescanError::Cancelled { height: 1 }),
            true,
            false,
        ));
        assert!(rescan_should_stay_blocked(&Ok(0), true, true));
    }
}

#[cfg(test)]
mod scan_recovery_tests {
    use super::super::scan::{build_rescan_matcher_from_store, ScanRegistryLoadError};
    use super::{fail_rescan_start_with_invalidation, recover_corrupt_scan_registry};
    use crate::wallet::{RedbWalletStore, WalletRead, WalletStore, WalletStoreError, WalletWrite};
    use std::sync::{Arc, Mutex};

    struct RecordingStore {
        inner: RedbWalletStore,
        events: Arc<Mutex<Vec<&'static str>>>,
        fail_invalidation: bool,
    }

    impl WalletStore for RecordingStore {
        fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
            self.inner.begin_read()
        }

        fn persist_scan_invalidation(&self, invalidated: bool) -> Result<(), WalletStoreError> {
            self.events.lock().unwrap().push("persist_invalidation");
            if self.fail_invalidation {
                return Err(WalletStoreError::Decode("injected".to_string()));
            }
            self.inner.persist_scan_invalidation(invalidated)
        }

        fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
            self.events.lock().unwrap().push("begin_write");
            self.inner.begin_write()
        }
    }

    struct TransientReadStore {
        inner: RedbWalletStore,
    }

    impl WalletStore for TransientReadStore {
        fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
            Err(WalletStoreError::Database(Box::new(redb::Error::Io(
                std::io::Error::other("injected transient read failure"),
            ))))
        }

        fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
            self.inner.begin_write()
        }
    }

    fn recording_store(fail_invalidation: bool) -> (tempfile::TempDir, RecordingStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = RecordingStore {
            inner: RedbWalletStore::new(db),
            events: events.clone(),
            fail_invalidation,
        };
        (dir, store)
    }

    #[test]
    fn rescan_start_failure_persists_invalidation() {
        let rescan = crate::engine::RescanCoordinator::new();
        let (_dir, store) = recording_store(false);
        fail_rescan_start_with_invalidation(&store, &rescan);
        assert!(store.read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn transient_registry_read_error_preserves_valid_registry() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
        let inner = RedbWalletStore::new(db);
        let mut write = inner.begin_write().unwrap();
        write.put_scan(11, b"{\"scanId\":11}".to_vec(), 11).unwrap();
        write.commit().unwrap();
        let store = TransientReadStore { inner };
        assert!(matches!(
            build_rescan_matcher_from_store(&store),
            Err(ScanRegistryLoadError::Read(_))
        ));
        assert_eq!(
            store
                .inner
                .read()
                .unwrap()
                .scan_registry()
                .unwrap()
                .scans
                .len(),
            1
        );
    }

    #[test]
    fn corrupt_registry_recovery_persists_invalidation_before_cleanup() {
        let (_dir, store) = recording_store(false);
        recover_corrupt_scan_registry(&store).unwrap();
        assert_eq!(
            *store.events.lock().unwrap(),
            vec!["persist_invalidation", "begin_write"]
        );
        assert!(store.read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn corrupt_registry_recovery_does_not_clear_when_invalidation_fails() {
        let (_dir, store) = recording_store(true);
        assert!(recover_corrupt_scan_registry(&store).is_err());
        assert_eq!(*store.events.lock().unwrap(), vec!["persist_invalidation"]);
    }
}

#[cfg(test)]
mod boot_recovery_tests {
    use super::{recover_interrupted_rescan, RescanCoordinator};
    use crate::wallet::{RedbWalletStore, RescanState, WalletStore};
    use std::sync::Arc;

    fn new_store() -> (tempfile::TempDir, RedbWalletStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbWalletStore::new(Arc::new(
            redb::Database::create(dir.path().join("state.redb")).unwrap(),
        ));
        (dir, store)
    }

    #[test]
    fn recover_interrupted_rescan_marks_failed_and_reasserts_invalidation() {
        let rescan = RescanCoordinator::new();
        let (_dir, store) = new_store();
        let mut write = store.begin_write().unwrap();
        write
            .set_rescan_state(&RescanState::Running { from_height: 7 })
            .unwrap();
        write.commit().unwrap();

        recover_interrupted_rescan(&store, &rescan).unwrap();

        assert_eq!(
            store.begin_read().unwrap().rescan_state().unwrap(),
            RescanState::Failed {
                height: 7,
                reason: "interrupted by restart".to_string(),
            }
        );
        assert!(store.begin_read().unwrap().scan_invalidated().unwrap());
        assert!(rescan.fail_closed());
        assert!(rescan.in_progress());
        assert!(rescan.scan_rebuild_in_progress());
    }

    #[test]
    fn recover_failed_or_invalidated_state_is_unsafe_on_boot() {
        let rescan = RescanCoordinator::new();
        let (_dir, store) = new_store();
        let mut write = store.begin_write().unwrap();
        write
            .set_rescan_state(&RescanState::Failed {
                height: 9,
                reason: "prior failure".to_string(),
            })
            .unwrap();
        write.set_scan_invalidated(false).unwrap();
        write.commit().unwrap();

        recover_interrupted_rescan(&store, &rescan).unwrap();
        assert_eq!(
            store.begin_read().unwrap().rescan_state().unwrap(),
            RescanState::Failed {
                height: 9,
                reason: "prior failure".to_string(),
            }
        );
        assert!(store.begin_read().unwrap().scan_invalidated().unwrap());
        rescan.clear_guards();

        let (_dir, store) = new_store();
        let mut write = store.begin_write().unwrap();
        write.set_scan_invalidated(true).unwrap();
        write.commit().unwrap();
        recover_interrupted_rescan(&store, &rescan).unwrap();
        assert!(matches!(
            store.begin_read().unwrap().rescan_state().unwrap(),
            RescanState::Failed { .. }
        ));
        assert!(store.begin_read().unwrap().scan_invalidated().unwrap());
    }

    #[test]
    fn clean_idle_store_clears_stale_process_guards() {
        let rescan = RescanCoordinator::new();
        let (_dir, store) = new_store();
        rescan.latch_fail_closed();
        recover_interrupted_rescan(&store, &rescan).unwrap();
        assert_eq!(
            store.begin_read().unwrap().rescan_state().unwrap(),
            RescanState::Idle
        );
        assert!(!store.begin_read().unwrap().scan_invalidated().unwrap());
        assert!(!rescan.fail_closed());
        assert!(!rescan.in_progress());
        assert!(!rescan.scan_rebuild_in_progress());
    }
}

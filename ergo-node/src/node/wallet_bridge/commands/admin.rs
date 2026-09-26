//! Admin + read-side handlers for `WalletCommand`.
//!
//! See `super::mod` for the WriterContext design and grouping rationale.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use ergo_api::wallet::types::{
    Page, TokenBalance, WalletAddressList, WalletBalances, WalletBoxesPage, WalletStatus,
    WalletTransactionEntry, WalletTransactionsPage,
};
use ergo_api::wallet::WalletAdminError;

use super::WriterContext;

/// Failed-attempt budget for a sensitive wallet operation, enforced in the
/// writer task so every surface (compat `/wallet/unlock`, native
/// `/api/v1/wallet/unlock`, future callers) shares one choke point.
///
/// Policy: at most [`Self::MAX_FAILURES`] failures inside
/// [`Self::WINDOW`]; exceeding the budget locks the operation for
/// [`Self::LOCKOUT`]. A success (or an unrelated error) resets the
/// window. Lockout trips produce [`WalletAdminError::RateLimited`] →
/// HTTP 429 — the variant existed for exactly this purpose but was never
/// constructed (audit finding M-4: unlimited online password guessing
/// against `/wallet/unlock`, each guess still costing a PBKDF2 run).
///
/// Instances live in the wallet writer loop (single logical owner); the
/// inner state sits behind a mutex only because the async handlers hold
/// `&Self` across await points, which requires `Sync`. Time is injected
/// (`*_at(now)`) so tests can drive the clock without sleeping.
pub(crate) struct AttemptLimiter {
    inner: std::sync::Mutex<AttemptLimiterState>,
}

#[derive(Default)]
struct AttemptLimiterState {
    window_start: Option<std::time::Instant>,
    failures: u32,
    locked_until: Option<std::time::Instant>,
}

impl AttemptLimiter {
    pub(crate) const MAX_FAILURES: u32 = 5;
    pub(crate) const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
    pub(crate) const LOCKOUT: std::time::Duration = std::time::Duration::from_secs(300);

    pub(crate) const fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(AttemptLimiterState {
                window_start: None,
                failures: 0,
                locked_until: None,
            }),
        }
    }

    /// `Ok(())` when the operation may proceed; `Err(())` while locked out.
    pub(crate) fn gate_at(&self, now: std::time::Instant) -> Result<(), ()> {
        let mut st = self.inner.lock().expect("attempt limiter poisoned");
        if let Some(until) = st.locked_until {
            if now < until {
                return Err(());
            }
            // Lockout expired — start fresh.
            *st = AttemptLimiterState::default();
        }
        Ok(())
    }

    pub(crate) fn record_failure_at(&self, now: std::time::Instant) {
        let mut st = self.inner.lock().expect("attempt limiter poisoned");
        let in_window = match st.window_start {
            Some(start) => now.duration_since(start) <= Self::WINDOW,
            None => false,
        };
        if !in_window {
            st.window_start = Some(now);
            st.failures = 0;
        }
        st.failures += 1;
        if st.failures >= Self::MAX_FAILURES {
            st.locked_until = Some(now + Self::LOCKOUT);
        }
    }

    pub(crate) fn record_success(&self) {
        let mut st = self.inner.lock().expect("attempt limiter poisoned");
        *st = AttemptLimiterState::default();
    }
}

pub(crate) async fn status(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<WalletStatus, WalletAdminError>>,
) {
    let result = (|| -> Result<WalletStatus, WalletAdminError> {
        let storage = ctx.storage.read();
        let state = ctx.state.read();
        let change_address = if state.is_unlocked() {
            state.change_address().unwrap_or("").to_string()
        } else {
            String::new()
        };
        let read = ctx
            .store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let invalidated = read
            .scan_invalidated()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let rescan_state = read
            .rescan_state()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        Ok(WalletStatus {
            is_initialized: !matches!(
                storage.lock_state(),
                ergo_wallet::storage::LockState::Uninitialized
            ),
            is_unlocked: state.is_unlocked(),
            change_address,
            wallet_height: ctx
                .chain
                .wallet_scan_height()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
            error: match rescan_state {
                ergo_state::wallet::RescanState::Failed { reason, .. } => {
                    format!("rescan_failed: {reason}")
                }
                ergo_state::wallet::RescanState::Running { .. } => "rescan_running".to_string(),
                ergo_state::wallet::RescanState::Idle if invalidated => {
                    "scan_invalidated".to_string()
                }
                ergo_state::wallet::RescanState::Idle => String::new(),
            },
        })
    })();
    let _ = reply.send(result);
}

pub(crate) async fn init(
    ctx: &WriterContext<'_>,
    pass: String,
    mnemonic_pass: String,
    strength: u8,
    reply: oneshot::Sender<Result<String, WalletAdminError>>,
) {
    let mut storage = ctx.storage.write();
    // Refuse to overwrite an existing wallet: `init` on an initialized
    // wallet would persist a second secret file. Return a typed `WalletExists`
    // (native 409 wallet_exists / compat 400) instead of clobbering the seed.
    if !matches!(
        storage.lock_state(),
        ergo_wallet::storage::LockState::Uninitialized
    ) {
        let _ = reply.send(Err(WalletAdminError::WalletExists));
        return;
    }
    let strength_enum = match strength {
        12 => ergo_wallet::mnemonic::MnemonicStrength::Words12,
        15 => ergo_wallet::mnemonic::MnemonicStrength::Words15,
        18 => ergo_wallet::mnemonic::MnemonicStrength::Words18,
        21 => ergo_wallet::mnemonic::MnemonicStrength::Words21,
        24 => ergo_wallet::mnemonic::MnemonicStrength::Words24,
        n => {
            let _ = reply.send(Err(WalletAdminError::Internal(format!(
                "unsupported strength {n}"
            ))));
            return;
        }
    };
    let result = storage
        .init(strength_enum, &pass, &mnemonic_pass)
        .map_err(|e| match e {
            ergo_wallet::error::WalletError::InvalidMnemonic(_) => {
                WalletAdminError::InvalidMnemonic
            }
            _ => WalletAdminError::Internal(e.to_string()),
        });
    let _ = reply.send(result);
}

pub(crate) async fn restore(
    ctx: &WriterContext<'_>,
    mnemonic: String,
    mnemonic_pass: String,
    pass: String,
    use_pre_1627: bool,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    if ctx.chain.is_pruned() {
        let _ = reply.send(Err(WalletAdminError::RestorePruningUnsupported));
        return;
    }
    let mut storage = ctx.storage.write();
    // Refuse to overwrite an existing wallet (same safety guard as `init`).
    if !matches!(
        storage.lock_state(),
        ergo_wallet::storage::LockState::Uninitialized
    ) {
        let _ = reply.send(Err(WalletAdminError::WalletExists));
        return;
    }
    let result = storage
        .restore(&mnemonic, &mnemonic_pass, &pass, use_pre_1627)
        .map_err(|e| match e {
            ergo_wallet::error::WalletError::InvalidMnemonic(_) => {
                WalletAdminError::InvalidMnemonic
            }
            _ => WalletAdminError::Internal(e.to_string()),
        });
    let _ = reply.send(result);
}

fn begin_rescan_process(
    start_h: u32,
    store: &dyn ergo_state::wallet::WalletStore,
    tip_height: u32,
) -> Result<crate::wallet_boot::RescanProcessStart, WalletAdminError> {
    match crate::wallet_boot::begin_rescan_process(start_h, store, tip_height) {
        Ok(rescan_start) => Ok(rescan_start),
        Err(crate::wallet_boot::BeginRescanError::FullRescanRequired) => {
            Err(WalletAdminError::RescanUnavailable(
                "full rescan required to recover wallet state".to_string(),
            ))
        }
        Err(crate::wallet_boot::BeginRescanError::AlreadyInProgress) => Err(
            WalletAdminError::RescanUnavailable("rescan already in progress".to_string()),
        ),
        Err(crate::wallet_boot::BeginRescanError::FinalizationInProgress) => {
            Err(WalletAdminError::RescanUnavailable(
                "wallet rescan finalization in progress".to_string(),
            ))
        }
        Err(crate::wallet_boot::BeginRescanError::Shutdown) => Err(
            WalletAdminError::RescanUnavailable("wallet is shutting down".to_string()),
        ),
        Err(crate::wallet_boot::BeginRescanError::InvalidStart { requested, cursor }) => {
            let cursor = cursor
                .map(|height| height.to_string())
                .unwrap_or_else(|| "none".to_string());
            Err(WalletAdminError::RescanUnavailable(format!(
                "full rescan required: use fromHeight=0 (requested {requested}, cursor {cursor})"
            )))
        }
        Err(crate::wallet_boot::BeginRescanError::Store(error)) => {
            Err(WalletAdminError::Internal(error))
        }
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn rescan_tip(ctx: &WriterContext<'_>) -> Result<u32, WalletAdminError> {
    if !ctx
        .chain
        .read_block_at_supported()
        .map_err(map_rescan_read_error)?
    {
        return Err(WalletAdminError::RescanUnavailable(
            "chain block-read not available on this backend".to_string(),
        ));
    }
    if ctx.chain.is_pruned() {
        return Err(WalletAdminError::RestorePruningUnsupported);
    }
    ctx.chain
        .tip_height()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))
}

#[allow(clippy::result_large_err)]
pub(crate) async fn rescan(
    ctx: &WriterContext<'_>,
    from_height: u32,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    let tip_h = match rescan_tip(ctx) {
        Ok(height) => height,
        Err(error) => {
            let _ = reply.send(Err(error));
            return;
        }
    };
    if let Some(service) = ctx.service {
        rescan_via_service(ctx, service, from_height, tip_h, reply).await;
        return;
    }
    let start_h = from_height;
    let mut registry_recovered = false;
    let scan_matcher = if start_h == 0 {
        match super::scan::build_rescan_matcher_from_store(ctx.store.as_ref()) {
            Ok(Some(matcher)) => Some(matcher),
            Ok(None) => Some(super::scan::empty_rescan_matcher()),
            Err(super::scan::ScanRegistryLoadError::Read(error)) => {
                tracing::error!(%error, "scan registry read failed; preserving registry");
                let _ = reply.send(Err(WalletAdminError::Internal(format!(
                    "scan registry read failed: {error}"
                ))));
                return;
            }
            Err(super::scan::ScanRegistryLoadError::Corrupt(error)) => {
                tracing::error!(%error, "scan registry is corrupt; discarding scan registry and scan tracking for recovery");
                if let Err(recovery_error) = recover_corrupt_scan_registry(ctx.store.as_ref()) {
                    fail_closed_after_scan_recovery_error(ctx.store.as_ref());
                    let _ = reply.send(Err(WalletAdminError::Internal(format!(
                        "scan registry is corrupt and recovery failed: {recovery_error}"
                    ))));
                    return;
                }
                registry_recovered = true;
                Some(super::scan::empty_rescan_matcher())
            }
        }
    } else {
        None
    };
    let rescan_start = match begin_rescan_process(start_h, ctx.store.as_ref(), tip_h) {
        Ok(rescan_start) => rescan_start,
        Err(error) => {
            if registry_recovered {
                fail_closed_after_scan_recovery_error(ctx.store.as_ref());
            }
            let _ = reply.send(Err(error));
            return;
        }
    };
    let rescan_generation = ergo_state::wallet::wallet_apply_generation();
    if let Err(error) = persist_rescan_state(
        ctx.store.as_ref(),
        &ergo_state::wallet::RescanState::Running {
            from_height: start_h,
        },
    ) {
        fail_rescan_start_with_invalidation(ctx.store.as_ref());
        let _ = reply.send(Err(WalletAdminError::Internal(error.to_string())));
        return;
    }

    let (trees, pks) = {
        let state = ctx.state.read();
        (
            state.tracked_p2pk_trees().iter().cloned().collect(),
            state.cached_pubkeys().clone(),
        )
    };
    let chain = ctx.chain.clone();
    let store = ctx.store.clone();
    let reached_height = std::sync::Arc::new(AtomicU32::new(start_h));
    let reached_for_block = reached_height.clone();
    let reached_for_tip = reached_height.clone();
    let task = tokio::task::spawn_blocking(move || {
        let mut flags = RescanFlagsGuard::new(
            rescan_generation,
            rescan_start.fenced_wallet_apply,
            store.clone(),
        );
        let result = ergo_state::wallet::scan::WalletScanService::rescan_full_rebuild_store(
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
                chain
                    .tip_height()
                    .map_err(|e| ergo_state::wallet::scan::RescanReadError::Storage {
                        height: reached_for_tip.load(Ordering::SeqCst),
                        source: ergo_state::wallet::WalletStoreError::decode(e.to_string()),
                    })
            },
            || {
                crate::wallet_boot::RESCAN_CANCEL_REQUESTED.load(Ordering::SeqCst)
                    || !crate::wallet_boot::RESCAN_IN_PROGRESS.load(Ordering::SeqCst)
            },
            scan_matcher
                .as_ref()
                .map(|matcher| matcher as &dyn ergo_state::wallet::scan::ScanRescanMatcher),
        );
        let state = match &result {
            Ok(_) => ergo_state::wallet::RescanState::Idle,
            Err(error) => rescan_failure_state(start_h, error),
        };
        let state_result = persist_rescan_state(store.as_ref(), &state);
        let generation_changed = ergo_state::wallet::wallet_apply_generation() != rescan_generation;
        let reassert_result = if generation_changed {
            store.persist_scan_invalidation(true)
        } else {
            Ok(())
        };
        if let Err(error) = &reassert_result {
            tracing::error!(%error, "failed to reassert scan invalidation after rescan generation change");
        }
        let scan_invalidated =
            if state_result.is_ok() && reassert_result.is_ok() && !generation_changed {
                store
                    .read()
                    .and_then(|read| read.scan_invalidated())
                    .unwrap_or(true)
            } else {
                true
            };
        if rescan_should_stay_blocked(
            &result,
            state_result.is_ok(),
            scan_invalidated,
            generation_changed,
        ) {
            flags.block();
        }
        if let Err(error) = state_result {
            tracing::error!(%error, "failed to persist wallet rescan outcome");
        }
    });
    if let Err(error) = crate::wallet_boot::track_wallet_task(ctx.wallet_session_id, task).await {
        tracing::error!(%error, "wallet rescan task failed");
        let _ = reply.send(Err(WalletAdminError::Internal(format!(
            "wallet rescan task failed: {error}"
        ))));
        return;
    }
    let _ = reply.send(Ok(()));
}

async fn rescan_via_service(
    ctx: &WriterContext<'_>,
    service: &ergo_wallet_service::runtime::WalletService,
    from_height: u32,
    _tip_h: u32,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    if from_height == 0 {
        match super::scan::build_rescan_matcher_from_store(ctx.store.as_ref()) {
            Ok(_) => {}
            Err(super::scan::ScanRegistryLoadError::Read(error)) => {
                let _ = reply.send(Err(WalletAdminError::Internal(format!(
                    "scan registry read failed: {error}"
                ))));
                return;
            }
            Err(super::scan::ScanRegistryLoadError::Corrupt(error)) => {
                tracing::error!(%error, "scan registry is corrupt; discarding registry before service rescan");
                if let Err(recovery_error) = recover_corrupt_scan_registry(ctx.store.as_ref()) {
                    fail_closed_after_scan_recovery_error(ctx.store.as_ref());
                    let _ = reply.send(Err(WalletAdminError::Internal(format!(
                        "scan registry is corrupt and recovery failed: {recovery_error}"
                    ))));
                    return;
                }
            }
        }
    }
    let rescan_start = match begin_rescan_process(from_height, ctx.store.as_ref(), _tip_h) {
        Ok(rescan_start) => rescan_start,
        Err(error) => {
            let _ = reply.send(Err(error));
            return;
        }
    };
    if let Err(error) = persist_rescan_state(
        ctx.store.as_ref(),
        &ergo_state::wallet::RescanState::Running { from_height },
    ) {
        fail_rescan_start_with_invalidation(ctx.store.as_ref());
        let _ = reply.send(Err(WalletAdminError::Internal(error.to_string())));
        return;
    }
    if from_height == 0 {
        if let Err(error) = ctx.store.as_ref().persist_scan_invalidation(true) {
            fail_rescan_start_with_invalidation(ctx.store.as_ref());
            let _ = reply.send(Err(WalletAdminError::Internal(error.to_string())));
            return;
        }
    }
    let generation = ergo_state::wallet::wallet_apply_generation();
    let service = service.clone();
    let store = ctx.store.clone();
    let task = tokio::task::spawn_blocking(move || {
        let mut flags =
            RescanFlagsGuard::new(generation, rescan_start.fenced_wallet_apply, store.clone());
        let result = service.rescan_to_tip_with_cancellation(from_height, || {
            crate::wallet_boot::RESCAN_CANCEL_REQUESTED.load(Ordering::SeqCst)
                || !crate::wallet_boot::RESCAN_IN_PROGRESS.load(Ordering::SeqCst)
        });
        if let Err(error) = &result {
            let already_failed = store
                .read()
                .and_then(|read| read.rescan_state())
                .map(|state| matches!(state, ergo_state::wallet::RescanState::Failed { .. }))
                .unwrap_or(false);
            if !already_failed {
                let _ = persist_rescan_state(
                    store.as_ref(),
                    &ergo_state::wallet::RescanState::Failed {
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
    });
    if let Err(error) = crate::wallet_boot::track_wallet_task(ctx.wallet_session_id, task).await {
        tracing::error!(%error, "wallet service rescan task failed");
        let _ = reply.send(Err(WalletAdminError::Internal(format!(
            "wallet rescan task failed: {error}"
        ))));
        return;
    }
    let _ = reply.send(Ok(()));
}

fn recover_corrupt_scan_registry(
    store: &dyn ergo_state::wallet::WalletStore,
) -> Result<(), ergo_state::wallet::WalletStoreError> {
    store.persist_scan_invalidation(true)?;
    clear_scan_registry_for_recovery(store)
}

fn fail_rescan_start_with_invalidation(store: &dyn ergo_state::wallet::WalletStore) {
    crate::wallet_boot::fail_rescan_start();
    if let Err(error) = store.persist_scan_invalidation(true) {
        tracing::error!(%error, "failed to persist invalidation after rescan start failure");
    }
}

fn fail_closed_after_scan_recovery_error(store: &dyn ergo_state::wallet::WalletStore) {
    crate::wallet_boot::latch_rescan_fail_closed();
    if let Err(error) = store.persist_scan_invalidation(true) {
        tracing::error!(%error, "failed to reassert scan invalidation after scan recovery failure");
    }
}

fn clear_scan_registry_for_recovery(
    store: &dyn ergo_state::wallet::WalletStore,
) -> Result<(), ergo_state::wallet::WalletStoreError> {
    let mut write = store.begin_write()?;
    write.clear_scan_registry()?;
    write.commit()
}

fn persist_rescan_state(
    store: &dyn ergo_state::wallet::WalletStore,
    state: &ergo_state::wallet::RescanState,
) -> Result<(), ergo_state::wallet::WalletStoreError> {
    let mut write = store.begin_write()?;
    write.set_rescan_state(state)?;
    write.commit()
}

fn rescan_failure_state(
    from_height: u32,
    error: &ergo_state::wallet::scan::RescanError,
) -> ergo_state::wallet::RescanState {
    use ergo_state::wallet::scan::{RescanError, RescanReadError};
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
    ergo_state::wallet::RescanState::Failed {
        height,
        reason: error.to_string(),
    }
}

fn rescan_should_stay_blocked(
    result: &Result<u32, ergo_state::wallet::scan::RescanError>,
    outcome_persisted: bool,
    scan_invalidated: bool,
    generation_changed: bool,
) -> bool {
    result.is_err() || !outcome_persisted || scan_invalidated || generation_changed
}

struct RescanFlagsGuard {
    start_generation: u64,
    fenced_wallet_apply: bool,
    store: Arc<dyn ergo_state::wallet::WalletStore>,
    keep_blocked: bool,
}

impl RescanFlagsGuard {
    fn new(
        start_generation: u64,
        fenced_wallet_apply: bool,
        store: Arc<dyn ergo_state::wallet::WalletStore>,
    ) -> Self {
        Self {
            start_generation,
            fenced_wallet_apply,
            store,
            keep_blocked: false,
        }
    }

    fn block(&mut self) {
        self.keep_blocked = true;
        crate::wallet_boot::latch_rescan_fail_closed();
    }
}

impl Drop for RescanFlagsGuard {
    fn drop(&mut self) {
        crate::wallet_boot::finalize_rescan_guard(
            self.start_generation,
            self.fenced_wallet_apply,
            self.store.as_ref(),
            self.keep_blocked,
            std::thread::panicking(),
        );
    }
}

fn map_rescan_read_error(error: ergo_state::wallet::scan::RescanReadError) -> WalletAdminError {
    match error {
        ergo_state::wallet::scan::RescanReadError::Missing { height } => {
            WalletAdminError::RescanUnavailable(format!("block missing at height {height}"))
        }
        other => WalletAdminError::Internal(other.to_string()),
    }
}

pub(crate) async fn unlock(
    ctx: &WriterContext<'_>,
    limiter: &AttemptLimiter,
    pass: String,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    if limiter.gate_at(std::time::Instant::now()).is_err() {
        tracing::warn!("wallet unlock rejected: failed-attempt budget exhausted");
        let _ = reply.send(Err(WalletAdminError::RateLimited));
        return;
    }
    let mut storage = ctx.storage.write();
    let mut state = ctx.state.write();
    let result = crate::wallet_boot::WalletBootService::unlock_and_sync(
        &mut storage,
        &mut state,
        ctx.store.as_ref(),
        ctx.cfg.network,
        &pass,
    )
    .map_err(|e| match e {
        ergo_wallet::error::WalletError::WalletUninitialized => WalletAdminError::Uninitialized,
        ergo_wallet::error::WalletError::Decryption => WalletAdminError::WrongPassword,
        ergo_wallet::error::WalletError::ChangeAddressUntracked => {
            WalletAdminError::ChangeAddressUntracked
        }
        other => WalletAdminError::Internal(other.to_string()),
    });
    drop(storage);
    drop(state);
    match &result {
        Ok(()) => {
            limiter.record_success();
            info!("wallet unlocked");
        }
        Err(WalletAdminError::WrongPassword) => {
            limiter.record_failure_at(std::time::Instant::now());
            warn!("wallet unlock failed: wrong password");
        }
        // Uninitialized / internal errors are not guess feedback — leave
        // the budget untouched.
        Err(_) => {}
    }
    let _ = reply.send(result);
}

pub(crate) async fn lock(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    let mut storage = ctx.storage.write();
    let mut state = ctx.state.write();
    storage.lock();
    state.set_unlocked(false);
    info!("wallet locked");
    let _ = reply.send(Ok(()));
}

pub(crate) async fn check(
    ctx: &WriterContext<'_>,
    limiter: &AttemptLimiter,
    mnemonic: String,
    mnemonic_pass: String,
    reply: oneshot::Sender<Result<bool, WalletAdminError>>,
) {
    // `check` is a yes/no oracle over the recovery phrase — the same
    // brute-force surface as unlock, so it shares the failed-attempt
    // budget (a mismatch counts as a failure; a match resets it).
    if limiter.gate_at(std::time::Instant::now()).is_err() {
        tracing::warn!("wallet check rejected: failed-attempt budget exhausted");
        let _ = reply.send(Err(WalletAdminError::RateLimited));
        return;
    }
    let storage = ctx.storage.read();
    let matched = storage.check_seed(&mnemonic, &mnemonic_pass);
    drop(storage);
    if matched {
        limiter.record_success();
    } else {
        limiter.record_failure_at(std::time::Instant::now());
    }
    debug!(matched, "wallet seed check completed");
    let _ = reply.send(Ok(matched));
}

pub(crate) async fn update_change_address(
    ctx: &WriterContext<'_>,
    address: String,
    reply: oneshot::Sender<Result<(), WalletAdminError>>,
) {
    if ctx.storage.read().unlocked().is_none() {
        let _ = reply.send(Err(WalletAdminError::Locked));
        return;
    }
    // Decode address → pubkey; reject if not a valid P2PK address for
    // this node's network (the same keys are tracked on every network,
    // so without the prefix check a testnet address would pass the
    // tracked-pubkey membership test on a mainnet node).
    let pubkey = match ergo_ser::address::decode_p2pk_address(&address, ctx.cfg.network) {
        Ok(pk) => pk,
        Err(_) => {
            let _ = reply.send(Err(WalletAdminError::ChangeAddressUntracked));
            return;
        }
    };
    // Tracking is not proof of ownership. Derive the recorded path with the
    // active master key and compare its public key before persisting anything.
    let owned = (|| -> Result<bool, WalletAdminError> {
        let storage = ctx.storage.read();
        let unlocked = storage.unlocked().ok_or(WalletAdminError::Locked)?;
        let read = ctx
            .store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let tracked = read
            .tracked_pubkeys_with_paths()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        for (_, pk, path) in tracked {
            if pk == pubkey {
                let path = ergo_wallet::derivation::DerivationPath::from_components(path);
                let derived = unlocked
                    .master
                    .derive_pubkey_at_path(&path)
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                if derived == pubkey {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })();
    match owned {
        Ok(true) => {}
        Ok(false) => {
            let _ = reply.send(Err(WalletAdminError::ChangeAddressUntracked));
            return;
        }
        Err(e) => {
            let _ = reply.send(Err(e));
            return;
        }
    }
    // Persist to WALLET_CHANGE_ADDRESS.
    let result: Result<(), WalletAdminError> = (|| -> Result<(), WalletAdminError> {
        let mut write = ctx
            .store
            .begin_write()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        write
            .set_change_address(pubkey)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        write
            .commit()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))
    })();
    if result.is_ok() {
        let mut s = ctx.state.write();
        s.set_change_address(address);
    }
    let _ = reply.send(result);
}

pub(crate) async fn balances(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<WalletBalances, WalletAdminError>>,
) {
    let result: Result<WalletBalances, WalletAdminError> =
        (|| -> Result<WalletBalances, WalletAdminError> {
            let balance = if let Some(service) = ctx.service {
                service
                    .confirmed_balance()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                let read = ctx
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.balance()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            };
            let assets = balance
                .tokens
                .iter()
                .map(|(id, amt)| TokenBalance {
                    token_id: hex::encode(id),
                    amount: *amt,
                })
                .collect();
            Ok(WalletBalances {
                height: ctx
                    .chain
                    .wallet_scan_height()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
                balance: balance.confirmed_nano_ergs,
                assets,
            })
        })();
    let _ = reply.send(result);
}

/// `GET /wallet/balances/withUnconfirmed`: confirmed balance with a
/// single-hop mempool overlay folded in:
///
/// - ADD every pool output paying a tracked wallet tree (incoming pending).
/// - SUBTRACT every CONFIRMED wallet box spent by a pool tx (outgoing
///   pending — e.g. the inputs of a send we just submitted).
///
/// Accumulated in `i128` so a transient pool state where subtractions
/// outweigh the confirmed seed (snapshot rebuilt mid-iteration) can't
/// underflow; the net is clamped at zero before narrowing to `u64`.
///
/// SCOPE / divergence from Scala `OffChainRegistry`: this is a single-hop
/// overlay, NOT a full off-chain registry. It nets pool outputs to the
/// wallet and pool spends of *confirmed* wallet boxes, but does NOT net
/// chains within the pool — a pool output to the wallet that is itself
/// spent by a *later* pool tx still counts as incoming (and an unconfirmed
/// box spent before it ever confirmed is not subtracted, since only
/// confirmed boxes are checked against the pool). For the common case
/// (a pending receipt, or the inputs of one just-submitted send) the figure
/// is exact; under chained mempool activity it can overstate. This matches
/// the additive `/blockchain/balance` overlay's scope. Full chained netting
/// (a real OffChainRegistry tracking pool-created boxes as spendable inputs)
/// is a tracked follow-up.
pub(crate) async fn balances_with_unconfirmed(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<WalletBalances, WalletAdminError>>,
) {
    use ergo_primitives::digest::Digest32;

    let result: Result<WalletBalances, WalletAdminError> =
        (|| -> Result<WalletBalances, WalletAdminError> {
            let read = ctx
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

            let confirmed = read
                .balance()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

            // Outgoing pending: confirmed wallet boxes a pool tx already spends.
            let mut subtract: Vec<UnconfirmedDelta> = Vec::new();
            for wb in read
                .unspent_boxes()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            {
                if ctx
                    .mempool
                    .is_spent_by_pool(&Digest32::from_bytes(wb.box_id))
                {
                    subtract.push(UnconfirmedDelta {
                        nano: wb.value,
                        tokens: wb.assets.clone(),
                    });
                }
            }

            // Incoming pending: pool outputs paying a tracked wallet tree.
            let mut add: Vec<UnconfirmedDelta> = Vec::new();
            {
                let state = ctx.state.read();
                for out in ctx.mempool.pool_outputs().values() {
                    if !state.is_tracked_tree(out.candidate.ergo_tree_bytes()) {
                        continue;
                    }
                    add.push(UnconfirmedDelta {
                        nano: out.candidate.value,
                        tokens: out
                            .candidate
                            .tokens
                            .iter()
                            .map(|t| (*t.token_id.as_bytes(), t.amount))
                            .collect(),
                    });
                }
            }

            let (balance, assets) = overlay_unconfirmed_balance(&confirmed, &add, &subtract);
            Ok(WalletBalances {
                height: ctx
                    .chain
                    .wallet_scan_height()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
                balance,
                assets,
            })
        })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/balance` — the native EIP-27-aware breakdown.
///
/// All figures come from ONE wallet read txn (`height` = its scan height). The
/// re-emission `reserved` holdback is the shared consensus helper
/// [`ergo_validation::reemission_obligation_core`] applied to the wallet's whole
/// confirmed box set at the CANDIDATE height `tip+1` (the height a spend is
/// validated at), so the wallet never over-reports spendable ERG relative to
/// what the validator would force a spend to burn. `reserved` is never clamped:
/// when it exceeds `confirmed`, `available` floors at 0 and
/// `reservedExceedsConfirmed` flags it.
pub(crate) async fn native_balance(
    ctx: &WriterContext<'_>,
    include_unconfirmed: bool,
    reply: oneshot::Sender<
        Result<ergo_api::wallet::native::dto::WalletBalanceDto, WalletAdminError>,
    >,
) {
    use ergo_api::wallet::native::dto::{
        NanoErgBreakdownDto, ReemissionInfoDto, ScopeDto, UnconfirmedDeltaDto, WalletAssetDto,
        WalletBalanceDto,
    };
    use ergo_primitives::digest::Digest32;

    // Uninitialized wallet → 409 (distinct from an empty-but-initialized wallet's
    // zero balance), per the design.
    if matches!(
        ctx.storage.read().lock_state(),
        ergo_wallet::storage::LockState::Uninitialized
    ) {
        let _ = reply.send(Err(WalletAdminError::Uninitialized));
        return;
    }

    let result: Result<WalletBalanceDto, WalletAdminError> =
        (|| -> Result<WalletBalanceDto, WalletAdminError> {
            let read = ctx
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

            let height = read
                .scan_cursor()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|cursor| cursor.height)
                .unwrap_or(0);

            let bal = read
                .balance()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let confirmed = bal.confirmed_nano_ergs;
            let immature = bal.immature_nano_ergs;

            // Confirmed (unspent) boxes — fetched once, reused for the EIP-27
            // reserve and the outgoing leg of the unconfirmed overlay.
            let need_boxes = ctx.cfg.reemission.is_some() || include_unconfirmed;
            let confirmed_boxes = if need_boxes {
                read.unspent_boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                Vec::new()
            };

            // EIP-27 reserve via the shared obligation core at candidate height
            // `tip+1`. The `reemission` block is present whenever EIP-27 is active
            // on this net at the next-spend height (cfg.reemission Some AND
            // tip+1 > activation), even if this wallet holds no reward boxes.
            let reemission_token_id = ctx.cfg.reemission.as_ref().map(|r| r.reemission_token_id);
            let mut reserved: u64 = 0;
            let mut reemission: Option<ReemissionInfoDto> = None;
            if let Some(rules) = ctx.cfg.reemission.as_ref() {
                let candidate_height = ctx
                    .chain
                    .tip_height()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                    .saturating_add(1);
                if candidate_height > rules.activation_height {
                    let token_id = rules.reemission_token_id;
                    let obl = ergo_validation::reemission_obligation_core(
                        confirmed_boxes.iter().map(|wb| {
                            let tok = wb
                                .assets
                                .iter()
                                .filter(|(id, _)| *id == token_id)
                                .map(|(_, amt)| *amt)
                                .fold(0u64, u64::saturating_add);
                            (wb.value, tok)
                        }),
                        candidate_height,
                        rules.activation_height,
                    );
                    reserved = obl.to_burn;
                    reemission = Some(ReemissionInfoDto {
                        token_id: hex::encode(token_id),
                        reserved_token_amount: obl.to_burn.to_string(),
                        reserved_box_count: u32::try_from(obl.box_count).unwrap_or(u32::MAX),
                        reserved_exceeds_confirmed: obl.to_burn > confirmed,
                    });
                }
            }
            let available = confirmed.saturating_sub(reserved);

            // Confirmed token balances, omitting the re-emission token (accounted
            // for solely by `reserved`/`reemission`).
            let assets = bal
                .tokens
                .iter()
                .filter(|(id, _)| reemission_token_id.is_none_or(|rt| **id != rt))
                .map(|(id, amt)| WalletAssetDto {
                    token_id: hex::encode(id),
                    amount: amt.to_string(),
                })
                .collect();

            // Labeled single-hop mempool delta (only when requested); NEVER folded
            // into confirmed/available. Incoming = pool outputs to tracked trees;
            // outgoing = confirmed wallet boxes a pool tx already spends.
            let unconfirmed = if include_unconfirmed {
                let mut outgoing: u128 = 0;
                for wb in &confirmed_boxes {
                    if ctx
                        .mempool
                        .is_spent_by_pool(&Digest32::from_bytes(wb.box_id))
                    {
                        outgoing = outgoing.saturating_add(wb.value as u128);
                    }
                }
                let mut incoming: u128 = 0;
                {
                    let state = ctx.state.read();
                    for out in ctx.mempool.pool_outputs().values() {
                        if state.is_tracked_tree(out.candidate.ergo_tree_bytes()) {
                            incoming = incoming.saturating_add(out.candidate.value as u128);
                        }
                    }
                }
                let net = incoming as i128 - outgoing as i128;
                Some(UnconfirmedDeltaDto {
                    scope: ScopeDto::SingleHop,
                    incoming_nano_erg: incoming.to_string(),
                    outgoing_nano_erg: outgoing.to_string(),
                    net_nano_erg: net.to_string(),
                })
            } else {
                None
            };

            Ok(WalletBalanceDto {
                height,
                nano_erg: NanoErgBreakdownDto {
                    confirmed: confirmed.to_string(),
                    available: available.to_string(),
                    reserved: reserved.to_string(),
                    immature: immature.to_string(),
                },
                assets,
                reemission,
                unconfirmed,
            })
        })();
    let _ = reply.send(result);
}

/// One side of the unconfirmed overlay: a box's value + tokens to add or
/// subtract from the confirmed balance.
struct UnconfirmedDelta {
    nano: u64,
    tokens: Vec<([u8; 32], u64)>,
}

/// Pure overlay arithmetic for `balances_with_unconfirmed`, split out so it
/// is unit-testable without redb / mempool / wallet-state wiring.
///
/// Net = confirmed + sum(add) − sum(subtract), accumulated in `i128` so a
/// transient pool state where subtractions outweigh the confirmed seed
/// (snapshot rebuilt mid-iteration) can't underflow; each total is clamped
/// at zero before narrowing to the wire `u64`. Zero-amount tokens are
/// dropped. Returns `(nano_ergs, sorted-by-token-id assets)`.
fn overlay_unconfirmed_balance(
    confirmed: &ergo_state::wallet::types::Balance,
    add: &[UnconfirmedDelta],
    subtract: &[UnconfirmedDelta],
) -> (u64, Vec<TokenBalance>) {
    let mut nano: i128 = confirmed.confirmed_nano_ergs as i128;
    let mut tokens: std::collections::BTreeMap<[u8; 32], i128> = confirmed
        .tokens
        .iter()
        .map(|(id, amt)| (*id, *amt as i128))
        .collect();

    for d in add {
        nano += d.nano as i128;
        for (id, amt) in &d.tokens {
            *tokens.entry(*id).or_insert(0) += *amt as i128;
        }
    }
    for d in subtract {
        nano -= d.nano as i128;
        for (id, amt) in &d.tokens {
            *tokens.entry(*id).or_insert(0) -= *amt as i128;
        }
    }

    let balance = nano.max(0) as u64;
    let assets = tokens
        .into_iter()
        .filter_map(|(id, amt)| {
            let amt = amt.max(0) as u64;
            (amt > 0).then(|| TokenBalance {
                token_id: hex::encode(id),
                amount: amt,
            })
        })
        .collect();
    (balance, assets)
}

pub(crate) async fn addresses(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<Result<WalletAddressList, WalletAdminError>>,
) {
    let state = ctx.state.read();
    let addrs = state.visible_addresses().to_vec();
    let _ = reply.send(Ok(WalletAddressList(addrs)));
}

pub(crate) async fn boxes(
    ctx: &WriterContext<'_>,
    page: Page,
    reply: oneshot::Sender<Result<WalletBoxesPage, WalletAdminError>>,
) {
    let result: Result<WalletBoxesPage, WalletAdminError> =
        (|| -> Result<WalletBoxesPage, WalletAdminError> {
            let all = if let Some(service) = ctx.service {
                service
                    .boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                let read = ctx
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.all_boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            };
            Ok(super::paginate_boxes(all, page))
        })();
    let _ = reply.send(result);
}

pub(crate) async fn boxes_unspent(
    ctx: &WriterContext<'_>,
    page: Page,
    reply: oneshot::Sender<Result<WalletBoxesPage, WalletAdminError>>,
) {
    let result: Result<WalletBoxesPage, WalletAdminError> =
        (|| -> Result<WalletBoxesPage, WalletAdminError> {
            let unspent = if let Some(service) = ctx.service {
                service
                    .confirmed_boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                let read = ctx
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.unspent_boxes()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            };
            Ok(super::paginate_boxes(unspent, page))
        })();
    let _ = reply.send(result);
}

pub(crate) async fn transactions(
    ctx: &WriterContext<'_>,
    page: Page,
    reply: oneshot::Sender<Result<WalletTransactionsPage, WalletAdminError>>,
) {
    let result: Result<WalletTransactionsPage, WalletAdminError> =
        (|| -> Result<WalletTransactionsPage, WalletAdminError> {
            let all = if let Some(service) = ctx.service {
                service
                    .transactions()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            } else {
                let read = ctx
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.all_transactions()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            };
            Ok(super::paginate_transactions(all, page))
        })();
    let _ = reply.send(result);
}

pub(crate) async fn transaction_by_id(
    ctx: &WriterContext<'_>,
    tx_id_hex: String,
    reply: oneshot::Sender<Result<Option<WalletTransactionEntry>, WalletAdminError>>,
) {
    let result: Result<Option<WalletTransactionEntry>, WalletAdminError> =
        (|| -> Result<Option<WalletTransactionEntry>, WalletAdminError> {
            let tx_bytes = hex::decode(&tx_id_hex)
                .map_err(|_| WalletAdminError::Internal("tx_id_hex is not valid hex".to_string()))
                .and_then(|v| {
                    v.try_into().map_err(|_| {
                        WalletAdminError::Internal("tx_id must be 32 bytes".to_string())
                    })
                })?;
            let entry = if let Some(service) = ctx.service {
                service
                    .transaction_by_id(&tx_bytes)
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                    .map(super::wallet_tx_to_entry)
            } else {
                let read = ctx
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                read.transaction_by_id(&tx_bytes)
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                    .map(super::wallet_tx_to_entry)
            };
            Ok(entry)
        })();
    let _ = reply.send(result);
}

pub(crate) async fn transactions_by_scan_id(
    ctx: &WriterContext<'_>,
    scan_id: u32,
    page: Page,
    reply: oneshot::Sender<Result<WalletTransactionsPage, WalletAdminError>>,
) {
    // Payments scan (10): the wallet's own transactions, served from
    // WALLET_TXS. (Approximate Scala parity: Scala filters by per-tx scan
    // tags, where pure miner-reward receipts carry MiningScanId (9), not 10 —
    // our wallet rows carry no tags, so the id-10 listing includes them.)
    // Anything else routes to the scan-tx rows written at block apply (user
    // scans; reserved 9 + unknown ids read as empty — Scala serves mining-scan
    // txs at id 9, a documented parity gap).
    let result: Result<WalletTransactionsPage, WalletAdminError> =
        if scan_id == u32::from(ergo_wallet_service::scan::PAYMENTS_SCAN_ID) {
            (|| -> Result<WalletTransactionsPage, WalletAdminError> {
                let read = ctx
                    .store
                    .read()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                let all = read
                    .all_transactions()
                    .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                Ok(super::paginate_transactions(all, page))
            })()
        } else {
            match u16::try_from(scan_id) {
                Ok(id) => super::scan::scan_transactions_impl(ctx.store.as_ref(), id, page),
                // Scan ids are u16 (Scala Short); anything larger can't match.
                Err(_) => Ok(WalletTransactionsPage::default()),
            }
        };
    let _ = reply.send(result);
}

// ----- native (/api/v1/wallet) reads -----

/// `GET /api/v1/wallet/status`.
pub(crate) async fn native_status(
    ctx: &WriterContext<'_>,
    reply: oneshot::Sender<
        Result<ergo_api::wallet::native::dto::WalletStatusDto, WalletAdminError>,
    >,
) {
    use ergo_api::wallet::native::dto::{NetworkDto, RescanStateDto, WalletStatusDto};
    let result: Result<WalletStatusDto, WalletAdminError> =
        (|| -> Result<WalletStatusDto, WalletAdminError> {
            let initialized = !matches!(
                ctx.storage.read().lock_state(),
                ergo_wallet::storage::LockState::Uninitialized
            );
            let locked = !ctx.state.read().is_unlocked();
            // Scan height + scan-invalidated + change address from ONE read txn.
            let read = ctx
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let scan_height = read
                .scan_cursor()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|cursor| cursor.height)
                .unwrap_or(0);
            let scan_invalidated = read
                .scan_invalidated()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let change_address = read
                .change_address_pubkey()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|pk| ergo_wallet::address::pubkey_to_p2pk_address(&pk, ctx.cfg.network))
                .transpose()
                .map_err(|e| WalletAdminError::Internal(format!("change address encode: {e}")))?;
            let tip_height = ctx
                .chain
                .tip_height()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let eip27_active = match &ctx.cfg.reemission {
                Some(rules) => tip_height.saturating_add(1) > rules.activation_height,
                None => false,
            };
            let network = match ctx.cfg.network {
                ergo_ser::address::NetworkPrefix::Mainnet => NetworkDto::Mainnet,
                ergo_ser::address::NetworkPrefix::Testnet => NetworkDto::Testnet,
            };
            let rescan_state = read
                .rescan_state()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let rescan = match rescan_state {
                ergo_state::wallet::RescanState::Running { from_height } => {
                    RescanStateDto::Running { from_height }
                }
                ergo_state::wallet::RescanState::Failed { height, reason } => {
                    RescanStateDto::Failed { height, reason }
                }
                ergo_state::wallet::RescanState::Idle if ctx.chain.is_pruned() => {
                    RescanStateDto::Unavailable {
                        detail: "node is pruned; block replay unavailable".to_string(),
                    }
                }
                ergo_state::wallet::RescanState::Idle => RescanStateDto::Idle,
            };
            Ok(WalletStatusDto {
                initialized,
                locked,
                scan_height,
                tip_height,
                change_address,
                network,
                eip27_active,
                rescan,
                scan_invalidated,
            })
        })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/addresses` (paged). Renders each tracked pubkey to its
/// P2PK address; `total` + the page slice come from one read snapshot.
pub(crate) async fn native_addresses(
    ctx: &WriterContext<'_>,
    offset: u32,
    limit: u32,
    reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::AddressPage, WalletAdminError>>,
) {
    use ergo_api::wallet::native::dto::{AddressPage, WalletAddressDto};
    let network = ctx.cfg.network;
    let result: Result<AddressPage, WalletAdminError> =
        (|| -> Result<AddressPage, WalletAdminError> {
            let read = ctx
                .store
                .read()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let as_of = read
                .scan_cursor()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|cursor| cursor.height)
                .unwrap_or(0);
            // Ordered by path_idx ASC (the reader's contract).
            let metas = read
                .tracked_addresses_with_meta()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            let total = u32::try_from(metas.len()).unwrap_or(u32::MAX);
            let items = metas
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|m| {
                    let address = ergo_wallet::address::pubkey_to_p2pk_address(&m.pubkey, network)
                        .map_err(|e| WalletAdminError::Internal(format!("address encode: {e}")))?;
                    Ok(WalletAddressDto {
                        address,
                        derivation_path: super::render_derivation_path(&m.derivation_path),
                        // `index` is `u64` (matches `path_idx`) — no narrowing, so
                        // distinct addresses never alias past `u32::MAX`.
                        index: m.path_idx,
                        label: (!m.label.is_empty()).then_some(m.label),
                        added_at_height: m.added_at_height,
                    })
                })
                .collect::<Result<Vec<_>, WalletAdminError>>()?;
            Ok(AddressPage {
                items,
                total,
                as_of,
            })
        })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/boxes` (paged). All wallet boxes (any status), ordered
/// `(creationHeight desc, boxId asc)` — sorted before paging.
pub(crate) async fn native_boxes(
    ctx: &WriterContext<'_>,
    offset: u32,
    limit: u32,
    reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::BoxPage, WalletAdminError>>,
) {
    use ergo_api::wallet::native::dto::BoxPage;
    let result: Result<BoxPage, WalletAdminError> = (|| -> Result<BoxPage, WalletAdminError> {
        let read = ctx
            .store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let as_of = read
            .scan_cursor()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            .map(|cursor| cursor.height)
            .unwrap_or(0);
        let mut boxes = read
            .all_boxes()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        boxes.sort_by(|a, b| {
            b.creation_height
                .cmp(&a.creation_height)
                .then_with(|| a.box_id.cmp(&b.box_id))
        });
        let total = u32::try_from(boxes.len()).unwrap_or(u32::MAX);
        let items = boxes
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(box_to_summary)
            .collect::<Result<Vec<_>, WalletAdminError>>()?;
        Ok(BoxPage {
            items,
            total,
            as_of,
        })
    })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/boxes/{boxId}` — O(1) lookup; `None` if not tracked.
pub(crate) async fn native_box_by_id(
    ctx: &WriterContext<'_>,
    box_id_hex: String,
    reply: oneshot::Sender<
        Result<Option<ergo_api::wallet::native::dto::WalletBoxSummary>, WalletAdminError>,
    >,
) {
    let result = (|| {
        let box_id = decode_hex32(&box_id_hex)?;
        let read = ctx
            .store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let wb = read
            .box_by_id(&box_id)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        wb.map(box_to_summary).transpose()
    })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/transactions` (paged). Ordered `(blockHeight desc, txId
/// asc)` — sorted before paging.
pub(crate) async fn native_transactions(
    ctx: &WriterContext<'_>,
    offset: u32,
    limit: u32,
    reply: oneshot::Sender<Result<ergo_api::wallet::native::dto::TxPage, WalletAdminError>>,
) {
    use ergo_api::wallet::native::dto::TxPage;
    let result: Result<TxPage, WalletAdminError> = (|| -> Result<TxPage, WalletAdminError> {
        let read = ctx
            .store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let as_of = read
            .scan_cursor()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            .map(|cursor| cursor.height)
            .unwrap_or(0);
        let mut txs = read
            .all_transactions()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        txs.sort_by(|a, b| {
            b.block_height
                .cmp(&a.block_height)
                .then_with(|| a.tx_id.cmp(&b.tx_id))
        });
        let total = u32::try_from(txs.len()).unwrap_or(u32::MAX);
        let items = txs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(tx_to_summary)
            .collect();
        Ok(TxPage {
            items,
            total,
            as_of,
        })
    })();
    let _ = reply.send(result);
}

/// `GET /api/v1/wallet/transactions/{txId}` — `None` if not found.
pub(crate) async fn native_transaction_by_id(
    ctx: &WriterContext<'_>,
    tx_id_hex: String,
    reply: oneshot::Sender<
        Result<Option<ergo_api::wallet::native::dto::WalletTransactionSummary>, WalletAdminError>,
    >,
) {
    let result = (|| {
        let tx_id = decode_hex32(&tx_id_hex)?;
        let read = ctx
            .store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let wt = read
            .transaction_by_id(&tx_id)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        Ok(wt.map(tx_to_summary))
    })();
    let _ = reply.send(result);
}

// ----- native read helpers -----

/// Decode a 64-char hex id into a 32-byte array (the handler pre-validates the
/// shape; this is the defensive decode at the bridge boundary).
fn decode_hex32(s: &str) -> Result<[u8; 32], WalletAdminError> {
    let v =
        hex::decode(s).map_err(|_| WalletAdminError::BadRequest("invalid hex id".to_string()))?;
    v.try_into()
        .map_err(|_| WalletAdminError::BadRequest("id must be 32 bytes".to_string()))
}

/// Map a stored [`ergo_state::wallet::types::WalletBox`] to the lean native
/// summary. Fallible only on the (invariant-impossible) scan-id overflow — a
/// scan id that does not fit `u16` is corrupt storage, surfaced as `internal`
/// rather than silently truncated to `65535`.
fn box_to_summary(
    wb: ergo_state::wallet::types::WalletBox,
) -> Result<ergo_api::wallet::native::dto::WalletBoxSummary, WalletAdminError> {
    use ergo_api::wallet::native::dto::{
        BoxProvenanceDto, BoxStatusDto, WalletAssetDto, WalletBoxSummary,
    };
    use ergo_state::wallet::types::{BoxProvenance, BoxStatus};
    let status = match wb.status {
        BoxStatus::Confirmed => BoxStatusDto::Confirmed,
        BoxStatus::Immature { matures_at } => BoxStatusDto::Immature {
            matures_at_height: matures_at,
        },
        BoxStatus::Spent {
            spent_in_tx,
            spent_at,
        } => BoxStatusDto::Spent {
            tx_id: hex::encode(spent_in_tx),
            height: spent_at,
        },
    };
    let provenance = match wb.provenance {
        BoxProvenance::Owned => BoxProvenanceDto::Owned,
        BoxProvenance::MinerReward => BoxProvenanceDto::MinerReward,
        // Storage carries a u32 scan id; native ids are u16. The registry only
        // ever allocates u16 ids, so this always fits — but fail loudly rather
        // than truncate if that invariant is ever violated.
        BoxProvenance::Custom { scan_id } => BoxProvenanceDto::Custom {
            scan_id: u16::try_from(scan_id).map_err(|_| {
                WalletAdminError::Internal(format!("custom scan id {scan_id} exceeds u16"))
            })?,
        },
    };
    Ok(WalletBoxSummary {
        box_id: hex::encode(wb.box_id),
        value: wb.value.to_string(),
        assets: wb
            .assets
            .iter()
            .map(|(id, amt)| WalletAssetDto {
                token_id: hex::encode(id),
                amount: amt.to_string(),
            })
            .collect(),
        creation_tx_id: hex::encode(wb.creation_tx_id),
        creation_output_index: wb.creation_output_index,
        creation_height: wb.creation_height,
        status,
        provenance,
    })
}

/// Map a stored [`ergo_state::wallet::types::WalletTransaction`] to the lean summary.
pub(crate) fn tx_to_summary(
    wt: ergo_state::wallet::types::WalletTransaction,
) -> ergo_api::wallet::native::dto::WalletTransactionSummary {
    use ergo_api::wallet::native::dto::WalletTransactionSummary;
    WalletTransactionSummary {
        tx_id: hex::encode(wt.tx_id),
        block_id: hex::encode(wt.block_id),
        block_height: wt.block_height,
        wallet_input_box_ids: wt.wallet_inputs.iter().map(hex::encode).collect(),
        wallet_output_box_ids: wt.wallet_outputs.iter().map(hex::encode).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::{overlay_unconfirmed_balance, UnconfirmedDelta};
    use ergo_state::wallet::types::Balance;

    // ----- helpers -----

    const TOK_A: [u8; 32] = [0xAA; 32];
    const TOK_B: [u8; 32] = [0xBB; 32];

    fn confirmed(nano: u64, tokens: &[([u8; 32], u64)]) -> Balance {
        Balance {
            confirmed_nano_ergs: nano,
            immature_nano_ergs: 0,
            tokens: tokens.iter().copied().collect(),
        }
    }

    fn delta(nano: u64, tokens: &[([u8; 32], u64)]) -> UnconfirmedDelta {
        UnconfirmedDelta {
            nano,
            tokens: tokens.to_vec(),
        }
    }

    // ----- happy path -----

    #[test]
    fn overlay_no_mempool_returns_confirmed_unchanged() {
        let (nano, assets) =
            overlay_unconfirmed_balance(&confirmed(5_000_000, &[(TOK_A, 7)]), &[], &[]);
        assert_eq!(nano, 5_000_000);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].amount, 7);
        assert_eq!(assets[0].token_id, hex::encode(TOK_A));
    }

    #[test]
    fn overlay_incoming_pool_output_adds_to_balance() {
        // A pending receipt of 2 ERG + 3 of TOK_A on top of a 5 ERG / 7 TOK_A
        // confirmed balance.
        let (nano, assets) = overlay_unconfirmed_balance(
            &confirmed(5_000_000, &[(TOK_A, 7)]),
            &[delta(2_000_000, &[(TOK_A, 3)])],
            &[],
        );
        assert_eq!(nano, 7_000_000);
        assert_eq!(assets[0].amount, 10);
    }

    #[test]
    fn overlay_outgoing_pool_spend_subtracts_spent_box() {
        // We just submitted a send spending our only 5 ERG / 7 TOK_A box;
        // the pending change/receipt of 4 ERG + 7 TOK_A comes back to us.
        let (nano, assets) = overlay_unconfirmed_balance(
            &confirmed(5_000_000, &[(TOK_A, 7)]),
            &[delta(4_000_000, &[(TOK_A, 7)])],
            &[delta(5_000_000, &[(TOK_A, 7)])],
        );
        assert_eq!(nano, 4_000_000, "5 - 5 + 4");
        assert_eq!(assets.len(), 1, "tokens fully returned as change");
        assert_eq!(assets[0].amount, 7);
    }

    // ----- error paths -----

    #[test]
    fn overlay_subtraction_below_zero_clamps_to_zero() {
        // Transient snapshot where a spend is visible but its change output
        // is not yet — net must clamp, never underflow/wrap.
        let (nano, assets) = overlay_unconfirmed_balance(
            &confirmed(1_000_000, &[(TOK_A, 1)]),
            &[],
            &[delta(5_000_000, &[(TOK_A, 9)])],
        );
        assert_eq!(nano, 0);
        assert!(
            assets.is_empty(),
            "negative token total dropped, not wrapped"
        );
    }

    #[test]
    fn overlay_zero_net_token_is_dropped_from_assets() {
        // TOK_A nets to zero (spent == confirmed); TOK_B remains.
        let (_, assets) = overlay_unconfirmed_balance(
            &confirmed(10_000_000, &[(TOK_A, 4), (TOK_B, 2)]),
            &[],
            &[delta(0, &[(TOK_A, 4)])],
        );
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].token_id, hex::encode(TOK_B));
        assert_eq!(assets[0].amount, 2);
    }
}

#[cfg(test)]
mod attempt_limiter_tests {
    use super::AttemptLimiter;
    use ergo_state::wallet::{RedbWalletStore, WalletStore};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::wallet_boot::GLOBAL_RESCAN_TEST_GUARD as RESCAN_GUARD;

    #[test]
    fn allows_below_budget_and_locks_at_max_failures() {
        let limiter = AttemptLimiter::new();
        let t0 = Instant::now();
        for i in 0..AttemptLimiter::MAX_FAILURES {
            assert!(
                limiter.gate_at(t0 + Duration::from_secs(i.into())).is_ok(),
                "attempt {i} inside budget must pass the gate"
            );
            limiter.record_failure_at(t0 + Duration::from_secs(i.into()));
        }
        // Budget exhausted → locked, even immediately.
        assert!(limiter.gate_at(t0 + Duration::from_secs(10)).is_err());
    }

    #[test]
    fn lockout_expires_and_state_resets() {
        let limiter = AttemptLimiter::new();
        let t0 = Instant::now();
        for i in 0..AttemptLimiter::MAX_FAILURES {
            limiter.record_failure_at(t0 + Duration::from_secs(i.into()));
        }
        // Lockout runs from the LAST failure (t0+4s), not the first.
        let last_failure = t0 + Duration::from_secs(AttemptLimiter::MAX_FAILURES as u64 - 1);
        assert!(limiter
            .gate_at(last_failure + Duration::from_secs(1))
            .is_err());
        let unlock_at = last_failure + AttemptLimiter::LOCKOUT + Duration::from_secs(1);
        assert!(limiter.gate_at(unlock_at).is_ok(), "lockout must expire");
        // Fresh window after expiry: a single new failure must not lock.
        limiter.record_failure_at(unlock_at);
        assert!(limiter.gate_at(unlock_at + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn success_resets_the_window() {
        let limiter = AttemptLimiter::new();
        let t0 = Instant::now();
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            limiter.record_failure_at(t0 + Duration::from_secs(i.into()));
        }
        limiter.record_success();
        // Full fresh budget available again.
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            limiter.record_failure_at(t0 + Duration::from_secs(30 + i as u64));
        }
        assert!(limiter.gate_at(t0 + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn rescan_storage_failure_preserves_reached_height() {
        let state = super::rescan_failure_state(
            0,
            &ergo_state::wallet::scan::RescanError::Read(
                ergo_state::wallet::scan::RescanReadError::Storage {
                    height: 42,
                    source: ergo_state::wallet::WalletStoreError::decode("boom".to_string()),
                },
            ),
        );
        assert!(matches!(
            state,
            ergo_state::wallet::RescanState::Failed { height: 42, .. }
        ));
    }

    #[test]
    fn explicit_rescan_clears_stale_fail_closed_guards() {
        let _guard = RESCAN_GUARD.blocking_lock();
        crate::wallet_boot::begin_wallet_session();
        crate::wallet_boot::latch_rescan_fail_closed();
        let (_dir, store) = tempfile::tempdir()
            .map(|dir| {
                let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
                (dir, RedbWalletStore::new(db))
            })
            .unwrap();
        assert!(super::begin_rescan_process(5, &store, 5).is_err());
        let rescan_start = super::begin_rescan_process(0, &store, 0).unwrap();
        assert!(rescan_start.fenced_wallet_apply);
        assert!(!crate::wallet_boot::RESCAN_FAIL_CLOSED.load(Ordering::SeqCst));
        assert!(crate::wallet_boot::RESCAN_IN_PROGRESS.load(Ordering::SeqCst));
        assert!(crate::wallet_boot::SCAN_REBUILD_IN_PROGRESS.load(Ordering::SeqCst));
        crate::wallet_boot::clear_rescan_guards();
        crate::wallet_boot::begin_wallet_session();
    }

    #[test]
    fn partial_rescan_does_not_fence_wallet_apply_generation() {
        let _guard = RESCAN_GUARD.blocking_lock();
        crate::wallet_boot::begin_wallet_session();
        crate::wallet_boot::clear_rescan_guards();
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
        let store: Arc<dyn WalletStore> = Arc::new(RedbWalletStore::new(db));
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(0, None).unwrap();
        write.commit().unwrap();
        let generation_before = ergo_state::wallet::wallet_apply_generation();
        let start = (0..1000)
            .find_map(|_| {
                crate::wallet_boot::clear_rescan_guards();
                super::begin_rescan_process(1, store.as_ref(), 1).ok()
            })
            .expect("partial rescan start should be available");
        assert!(!start.fenced_wallet_apply);
        let generation = ergo_state::wallet::wallet_apply_generation();
        assert!(generation > generation_before);
        let guard = super::RescanFlagsGuard::new(generation, false, store);
        drop(guard);
        crate::wallet_boot::clear_rescan_guards();
        crate::wallet_boot::begin_wallet_session();
    }

    #[test]
    fn invalidation_persistence_failure_keeps_rescan_blocked() {
        let error = ergo_state::wallet::scan::RescanError::Invalidation {
            source: ergo_state::wallet::WalletStoreError::Decode("injected".to_string()),
        };
        let state = super::rescan_failure_state(17, &error);
        assert!(matches!(
            state,
            ergo_state::wallet::RescanState::Failed { height: 17, .. }
        ));
        assert!(super::rescan_should_stay_blocked(
            &Err(error),
            true,
            false,
            false
        ));
        assert!(!super::rescan_should_stay_blocked(
            &Ok(0),
            true,
            false,
            false
        ));
        assert!(super::rescan_should_stay_blocked(
            &Ok(0),
            false,
            false,
            false
        ));
        assert!(super::rescan_should_stay_blocked(
            &Err(ergo_state::wallet::scan::RescanError::Cancelled { height: 1 }),
            true,
            false,
            false,
        ));
        assert!(super::rescan_should_stay_blocked(&Ok(0), true, true, false));
        assert!(super::rescan_should_stay_blocked(&Ok(0), true, false, true));
    }

    #[test]
    fn rescan_generation_change_latches_and_reasserts_invalidation() {
        let _guard = RESCAN_GUARD.blocking_lock();
        crate::wallet_boot::clear_rescan_guards();
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
        let store: Arc<dyn WalletStore> = Arc::new(RedbWalletStore::new(db));
        let start_generation = ergo_state::wallet::wallet_apply_generation();
        let guard = super::RescanFlagsGuard::new(start_generation, true, store.clone());
        ergo_state::wallet::advance_wallet_apply_generation();
        drop(guard);

        assert!(crate::wallet_boot::RESCAN_FAIL_CLOSED.load(Ordering::SeqCst));
        assert!(crate::wallet_boot::RESCAN_IN_PROGRESS.load(Ordering::SeqCst));
        assert!(store.read().unwrap().scan_invalidated().unwrap());
        crate::wallet_boot::clear_rescan_guards();
    }

    #[test]
    fn failures_outside_the_window_do_not_accumulate() {
        let limiter = AttemptLimiter::new();
        let t0 = Instant::now();
        for i in 0..(AttemptLimiter::MAX_FAILURES - 1) {
            limiter.record_failure_at(t0 + Duration::from_secs(i.into()));
        }
        // Past WINDOW since the first failure: a new window starts, so
        // this failure is #1 of a fresh budget — no lockout.
        limiter.record_failure_at(t0 + AttemptLimiter::WINDOW + Duration::from_secs(1));
        assert!(limiter
            .gate_at(t0 + AttemptLimiter::WINDOW + Duration::from_secs(2))
            .is_ok());
    }
}

#[cfg(test)]
mod scan_recovery_tests {
    use super::super::scan::{build_rescan_matcher_from_store, ScanRegistryLoadError};
    use super::recover_corrupt_scan_registry;
    use ergo_state::wallet::{
        RedbWalletStore, WalletRead, WalletStore, WalletStoreError, WalletWrite,
    };
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
        let _guard = crate::wallet_boot::GLOBAL_RESCAN_TEST_GUARD.blocking_lock();
        let (_dir, store) = recording_store(false);
        super::fail_rescan_start_with_invalidation(&store);
        assert!(store.read().unwrap().scan_invalidated().unwrap());
        crate::wallet_boot::clear_rescan_guards();
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

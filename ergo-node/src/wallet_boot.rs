//! Production wallet boot orchestrator. Single unlock+hydrate+persist
//! path shared by the production boot and integration tests.

use ergo_state::wallet::tables::*;
use ergo_state::wallet::types::TrackedPubkeyMeta;
use ergo_wallet::error::WalletError;
use ergo_wallet::state::WalletState;
use ergo_wallet::storage::{LockState, SecretStorage};
use redb::WriteTransaction;
use std::sync::{Mutex, MutexGuard};
use tokio::task::{JoinError, JoinHandle};

/// Rescan-in-progress flag. Set by `NodeWalletAdmin`'s Rescan dispatch;
/// read by the chain-apply hook (via `WalletApplyHook` impl) and by
/// rollback (via `ProdRescanGuard`). Cleared on normal completion; retained
/// when rescan invalidation or outcome persistence fails closed.
pub static RESCAN_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
/// Cancellation request set by rollback while an actual rescan task is active.
/// The task observes this independently of the process-fence flag.
pub static RESCAN_CANCEL_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
/// True only while a destructive rescan task is running. A boot or fail-closed
/// fence sets `RESCAN_IN_PROGRESS` without setting this flag.
pub static RESCAN_TASK_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Fail-closed latch for a rescan whose invalidation or outcome could not be
/// persisted. It is distinct from normal full-rescan activity.
pub static RESCAN_FAIL_CLOSED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Start height of the in-flight rescan, set alongside [`RESCAN_IN_PROGRESS`].
/// Read by the native `/api/v1/wallet/status` handler to surface
/// `rescan: {type:"running", fromHeight}`. Only meaningful while
/// `RESCAN_IN_PROGRESS` is `true`.
pub static RESCAN_FROM_HEIGHT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Scan-rebuild-in-progress flag. Set by the Rescan dispatch for a full
/// rebuild (`fromHeight == 0`) that rebuilds the registered `/scan/*` tables;
/// it is also forced on when a rescan fails closed. The chain-apply hook's scan
/// path reads it (`registered_scan_count` / `match_boxes`) and no-ops while it
/// is set. This quiesces live scan apply for the rebuild's duration: the
/// rebuild clears and repopulates the scan tables block-by-block, so a
/// concurrent live write would race it (miss a spend against the cleared
/// reverse index, or stale that index).
///
/// A partial rescan normally does not set it, so live scan tracking continues;
/// a persistence failure may force it on to prevent writes over incomplete
/// state. Cleared on normal task completion (process-local; reads `false`
/// after a restart).
pub static SCAN_REBUILD_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

static RESCAN_TRANSITION_LOCK: Mutex<()> = Mutex::new(());
struct WalletTaskSession {
    closing: bool,
    handles: Vec<JoinHandle<()>>,
}

struct WalletTaskState {
    sessions: Vec<(u64, WalletTaskSession)>,
}

static WALLET_TASKS: Mutex<WalletTaskState> = Mutex::new(WalletTaskState {
    sessions: Vec::new(),
});
static WALLET_SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static WALLET_SESSION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn begin_wallet_session() -> u64 {
    let _transition = rescan_transition_lock();
    let session_id = WALLET_SESSION_ID
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        .wrapping_add(1);
    {
        let mut tasks = WALLET_TASKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !tasks.sessions.iter().any(|(id, _)| *id == session_id) {
            tasks.sessions.push((
                session_id,
                WalletTaskSession {
                    closing: false,
                    handles: Vec::new(),
                },
            ));
        }
    }
    WALLET_SHUTDOWN_REQUESTED.store(false, std::sync::atomic::Ordering::SeqCst);
    RESCAN_CANCEL_REQUESTED.store(false, std::sync::atomic::Ordering::SeqCst);
    ergo_state::wallet::set_wallet_finalization_owned(false);
    session_id
}

pub(crate) fn wallet_session_id() -> u64 {
    WALLET_SESSION_ID.load(std::sync::atomic::Ordering::SeqCst)
}

pub(crate) fn wallet_shutdown_requested() -> bool {
    WALLET_SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::SeqCst)
}

fn task_session_index(state: &WalletTaskState, session_id: u64) -> Option<usize> {
    state.sessions.iter().position(|(id, _)| *id == session_id)
}

pub(crate) async fn track_wallet_task(
    session_id: u64,
    handle: JoinHandle<()>,
) -> Result<(), JoinError> {
    let late_handle = {
        let mut tasks = WALLET_TASKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let index = match task_session_index(&tasks, session_id) {
            Some(index) => index,
            None => {
                tasks.sessions.push((
                    session_id,
                    WalletTaskSession {
                        closing: false,
                        handles: Vec::new(),
                    },
                ));
                tasks.sessions.len() - 1
            }
        };
        let session = &mut tasks.sessions[index].1;
        if session.closing {
            Some(handle)
        } else {
            session.handles.push(handle);
            None
        }
    };
    match late_handle {
        Some(handle) => match handle.await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => {
                tracing::info!("wallet task cancelled during shutdown");
                Ok(())
            }
            Err(error) => Err(error),
        },
        None => Ok(()),
    }
}

async fn join_wallet_handles(handles: Vec<JoinHandle<()>>, first_error: &mut Option<JoinError>) {
    for handle in handles {
        if let Err(error) = handle.await {
            if error.is_cancelled() {
                tracing::info!("wallet task cancelled during shutdown");
            } else if first_error.is_none() {
                *first_error = Some(error);
            } else {
                tracing::error!(%error, "wallet task join failed");
            }
        }
    }
}

pub(crate) async fn await_wallet_tasks(session_id: u64) -> Result<(), JoinError> {
    {
        let mut tasks = WALLET_TASKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(index) = task_session_index(&tasks, session_id) else {
            return Ok(());
        };
        tasks.sessions[index].1.closing = true;
    }
    let mut first_error = None;
    loop {
        let handles = {
            let mut tasks = WALLET_TASKS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(index) = task_session_index(&tasks, session_id) else {
                return first_error.map_or(Ok(()), Err);
            };
            std::mem::take(&mut tasks.sessions[index].1.handles)
        };
        join_wallet_handles(handles, &mut first_error).await;
        let empty = WALLET_TASKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sessions
            .iter()
            .find(|(id, _)| *id == session_id)
            .map(|(_, session)| session.handles.is_empty())
            .unwrap_or(true);
        if empty {
            return first_error.map_or(Ok(()), Err);
        }
    }
}

fn rescan_transition_lock() -> MutexGuard<'static, ()> {
    RESCAN_TRANSITION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn latch_rescan_fail_closed_locked() {
    ergo_state::wallet::advance_wallet_apply_generation();
    ergo_state::wallet::fence_wallet_apply();
    RESCAN_FAIL_CLOSED.store(true, std::sync::atomic::Ordering::SeqCst);
    RESCAN_IN_PROGRESS.store(true, std::sync::atomic::Ordering::SeqCst);
    SCAN_REBUILD_IN_PROGRESS.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn finish_rescan_task_locked() {
    RESCAN_CANCEL_REQUESTED.store(false, std::sync::atomic::Ordering::SeqCst);
    RESCAN_TASK_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
}

fn clear_rescan_state_locked(fenced_wallet_apply: bool) {
    if fenced_wallet_apply {
        ergo_state::wallet::advance_wallet_apply_generation();
        ergo_state::wallet::unfence_wallet_apply();
    }
    RESCAN_FAIL_CLOSED.store(false, std::sync::atomic::Ordering::SeqCst);
    RESCAN_IN_PROGRESS.store(false, std::sync::atomic::Ordering::SeqCst);
    SCAN_REBUILD_IN_PROGRESS.store(false, std::sync::atomic::Ordering::SeqCst);
}

fn clear_rescan_guards_locked(fenced_wallet_apply: bool) {
    clear_rescan_state_locked(fenced_wallet_apply);
    finish_rescan_task_locked();
}

pub(crate) fn latch_rescan_fail_closed() {
    let _transition = rescan_transition_lock();
    latch_rescan_fail_closed_locked();
}

pub(crate) fn clear_rescan_guards() {
    let _transition = rescan_transition_lock();
    clear_rescan_guards_locked(true);
}

#[derive(Debug, Clone)]
pub(crate) enum BeginRescanError {
    FullRescanRequired,
    AlreadyInProgress,
    FinalizationInProgress,
    Shutdown,
    InvalidStart { requested: u32, cursor: Option<u32> },
    Store(String),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RescanProcessStart {
    pub fenced_wallet_apply: bool,
}

pub(crate) fn begin_rescan_process(
    start_h: u32,
    store: &dyn ergo_state::wallet::WalletStore,
    tip_height: u32,
) -> Result<RescanProcessStart, BeginRescanError> {
    let _chain_apply_guard = ergo_state::wallet::chain_apply_read_guard();
    let _transition = rescan_transition_lock();
    if wallet_shutdown_requested() {
        return Err(BeginRescanError::Shutdown);
    }
    if ergo_state::wallet::wallet_finalization_in_progress() {
        return Err(BeginRescanError::FinalizationInProgress);
    }
    if start_h > 0 {
        match ergo_state::wallet::scan::WalletScanService::validate_rescan_start(
            store, start_h, tip_height,
        ) {
            Ok(()) => {}
            Err(ergo_state::wallet::scan::RescanError::InvalidStart { requested, cursor }) => {
                return Err(BeginRescanError::InvalidStart { requested, cursor })
            }
            Err(error) => return Err(BeginRescanError::Store(error.to_string())),
        }
    }
    let was_fail_closed = RESCAN_FAIL_CLOSED.load(std::sync::atomic::Ordering::SeqCst);
    if was_fail_closed && start_h != 0 {
        return Err(BeginRescanError::FullRescanRequired);
    }
    if RESCAN_TASK_ACTIVE.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(BeginRescanError::AlreadyInProgress);
    }
    RESCAN_TASK_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    ergo_state::wallet::set_wallet_finalization_owned(true);
    let fenced_wallet_apply = start_h == 0;
    ergo_state::wallet::advance_wallet_apply_generation();
    if fenced_wallet_apply {
        ergo_state::wallet::fence_wallet_apply();
    }
    if was_fail_closed {
        RESCAN_FAIL_CLOSED.store(false, std::sync::atomic::Ordering::SeqCst);
    }
    RESCAN_CANCEL_REQUESTED.store(false, std::sync::atomic::Ordering::SeqCst);
    RESCAN_IN_PROGRESS.store(true, std::sync::atomic::Ordering::SeqCst);
    RESCAN_FROM_HEIGHT.store(start_h, std::sync::atomic::Ordering::SeqCst);
    SCAN_REBUILD_IN_PROGRESS.store(fenced_wallet_apply, std::sync::atomic::Ordering::SeqCst);
    Ok(RescanProcessStart {
        fenced_wallet_apply,
    })
}

pub(crate) fn fail_rescan_start() {
    let _transition = rescan_transition_lock();
    latch_rescan_fail_closed_locked();
    finish_rescan_task_locked();
    ergo_state::wallet::set_wallet_finalization_owned(false);
}

fn request_rescan_shutdown_locked() {
    WALLET_SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
    RESCAN_CANCEL_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
    if RESCAN_TASK_ACTIVE.load(std::sync::atomic::Ordering::SeqCst) {
        latch_rescan_fail_closed_locked();
    }
}

#[cfg(test)]
pub(crate) fn request_rescan_shutdown() {
    let _transition = rescan_transition_lock();
    request_rescan_shutdown_locked();
}

pub(crate) fn request_rescan_shutdown_for(session_id: u64) {
    let _transition = rescan_transition_lock();
    if wallet_session_id() != session_id {
        return;
    }
    request_rescan_shutdown_locked();
}

pub(crate) fn finalize_rescan_guard(
    start_generation: u64,
    fenced_wallet_apply: bool,
    store: &dyn ergo_state::wallet::WalletStore,
    keep_blocked: bool,
    panicking: bool,
) {
    let generation_changed = {
        let _transition = rescan_transition_lock();
        let changed = ergo_state::wallet::wallet_apply_generation() != start_generation;
        if !changed {
            if keep_blocked || panicking {
                latch_rescan_fail_closed_locked();
            } else {
                clear_rescan_state_locked(fenced_wallet_apply);
            }
        }
        changed
    };

    if generation_changed {
        if let Err(error) = store.persist_scan_invalidation(true) {
            tracing::error!(%error, "failed to reassert scan invalidation during rescan finalization");
        }
        let _transition = rescan_transition_lock();
        latch_rescan_fail_closed_locked();
    }
    let _transition = rescan_transition_lock();
    ergo_state::wallet::set_wallet_finalization_in_progress(false);
    ergo_state::wallet::set_wallet_finalization_owned(false);
    finish_rescan_task_locked();
}

/// Test-only fault-injection flag for the atomic-commit test.
/// When `true`, `unlock_and_sync` panics AFTER inserting the
/// `WALLET_TRACKED_PUBKEYS` rows but BEFORE inserting the
/// `WALLET_VISIBLE_ADDRESSES` rows. The atomic-commit invariant
/// (one redb write txn for both tables) holds iff post-panic both
/// tables are empty.
#[cfg(test)]
pub static FAULT_INJECT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub struct WalletBootService;

impl WalletBootService {
    /// Single production unlock+hydrate+persist path. The 6-step lifecycle:
    ///
    /// 1. `storage.load_metadata()` reads the `use_pre_1627` flag (pre-unlock).
    /// 2. Update `state.use_pre_1627` to match.
    /// 3. `storage.unlock(password)` loads the master key into memory.
    /// 4. Open a wallet-store read snapshot to check if tracked keys exist.
    ///    - Non-empty: hydrate state from the store snapshot.
    ///    - Empty: auto-derive master + EIP-3 first child, persist both tables in ONE write txn.
    /// 5. Validate the change address: if `WALLET_CHANGE_ADDRESS` points at an
    ///    untracked pubkey, return `ChangeAddressUntracked` and roll back the unlock.
    pub fn unlock_and_sync(
        storage: &mut SecretStorage,
        state: &mut WalletState,
        store: &dyn ergo_state::wallet::WalletStore,
        network: ergo_ser::address::NetworkPrefix,
        password: &str,
    ) -> Result<(), WalletError> {
        // Step 1: Read use_pre_1627 from secret file metadata (no decrypt yet).
        let use_pre_1627 = match storage.lock_state() {
            LockState::Uninitialized => return Err(WalletError::WalletUninitialized),
            LockState::Locked | LockState::Unlocked => {
                if storage.cached_file().is_none() {
                    storage.load_metadata()?
                } else {
                    storage.cached_file().unwrap().use_pre_1627_key_derivation
                }
            }
        };

        // Step 2: Update state's flag.
        state.set_use_pre_1627(use_pre_1627);

        // Step 3: Unlock (decrypts master key into memory).
        storage.unlock(password)?;
        // Reflect the successful unlock in WalletState immediately so
        // is_unlocked() returns true even if the subsequent steps fail
        // and we roll back — the rollback paths below reset this to false.
        state.set_unlocked(true);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (|| -> Result<(), WalletError> {
                // Step 4: Check if tables have entries.
                let read = store
                    .read()
                    .map_err(|e| WalletError::SecretFile(format!("wallet store read: {e}")))?;
                let already_persisted = !read
                    .tracked_pubkeys_with_paths()
                    .map_err(|e| {
                        WalletError::SecretFile(format!("wallet store tracked keys: {e}"))
                    })?
                    .is_empty();

                if already_persisted {
                    read.visible_pubkeys().map_err(|e| {
                        WalletError::SecretFile(format!("wallet store visible addresses: {e}"))
                    })?;
                    read.change_address_pubkey().map_err(|e| {
                        WalletError::SecretFile(format!("wallet store change address: {e}"))
                    })?;
                    // Step 5a: hydrate from the store snapshot (the persisted state is the source of truth).
                    state.hydrate_from_reader(read.as_ref(), network)?;
                    drop(read);
                } else {
                    drop(read);
                    // Step 5b: Fresh wallet — auto-derive master + EIP-3 first child + persist.
                    Self::auto_derive_and_persist(storage, state, store, network)?;
                }

                // Step 5.5: Change-address backfill. A wallet that
                // was created before the change address became a persisted default
                // (or restored from a mnemonic) reaches here with no
                // WALLET_CHANGE_ADDRESS row; without a change address every send
                // fails with "no change address set". Backfill with the EIP-3
                // first-address key (falling back to the root key), matching Scala
                // `ErgoWalletSupport.scala:154-168`. Skipped when one is already set.
                if state.change_address().is_none() {
                    Self::backfill_change_address(storage, state, store, network)?;
                }

                // Step 6: Change-address validation. (The change
                // address is persisted as a pubkey and re-rendered with the
                // current network prefix at hydrate, so the decoder's network
                // check always passes here; it is load-bearing only on the
                // user-supplied-string paths.)
                if let Some(addr_str) = state.change_address() {
                    match ergo_ser::address::decode_p2pk_address(addr_str, network) {
                        Ok(pk) => {
                            if !state
                                .cached_pubkeys()
                                .values()
                                .any(|tracked| *tracked == pk)
                            {
                                return Err(WalletError::ChangeAddressUntracked);
                            }
                        }
                        Err(_) => {
                            return Err(WalletError::ChangeAddressUntracked);
                        }
                    }
                }

                Ok(())
            })()
        }));
        let result = match result {
            Ok(result) => result,
            Err(payload) => {
                storage.lock();
                state.set_prover(None);
                state.set_unlocked(false);
                std::panic::resume_unwind(payload);
            }
        };
        if result.is_err() {
            storage.lock();
            state.set_prover(None);
            state.set_unlocked(false);
        }
        result
    }

    fn auto_derive_and_persist(
        storage: &mut SecretStorage,
        state: &mut WalletState,
        store: &dyn ergo_state::wallet::WalletStore,
        network: ergo_ser::address::NetworkPrefix,
    ) -> Result<(), WalletError> {
        let unlocked = storage.unlocked().ok_or_else(|| {
            WalletError::SecretFile("must be unlocked at auto_derive".to_string())
        })?;

        // Derive master pubkey + EIP-3 first child.
        let master_pk = unlocked.master.master_pubkey()?;
        let eip3_path = ergo_wallet::derivation::DerivationPath::eip3_first_address();
        let child_pk = unlocked.master.derive_pubkey_at_path(&eip3_path)?;

        // Persist both tracked entries, the visible-address entry, and the
        // change address in one wallet-store write transaction.
        let master_meta = TrackedPubkeyMeta {
            derivation_path: vec![],
            derivation_path_label: String::new(),
            added_at_height: 0,
        };
        let child_meta = TrackedPubkeyMeta {
            derivation_path: vec![44 | 0x8000_0000, 429 | 0x8000_0000, 0x8000_0000, 0, 0],
            derivation_path_label: String::new(),
            added_at_height: 0,
        };
        let mut write = store
            .begin_write()
            .map_err(|e| WalletError::SecretFile(format!("wallet store begin_write: {e}")))?;
        write
            .insert_tracked_pubkey(0, master_pk, &master_meta)
            .map_err(|e| WalletError::SecretFile(format!("insert master tracked: {e}")))?;

        #[cfg(test)]
        if FAULT_INJECT.load(std::sync::atomic::Ordering::SeqCst) {
            panic!("fault injection: unlock_and_sync panic between tracked + visible writes");
        }

        write
            .insert_tracked_pubkey(1, child_pk, &child_meta)
            .map_err(|e| WalletError::SecretFile(format!("insert child tracked: {e}")))?;
        write
            .rebuild_visible_addresses()
            .map_err(|e| WalletError::SecretFile(format!("rebuild visible addresses: {e}")))?;
        write
            .set_change_address(child_pk)
            .map_err(|e| WalletError::SecretFile(format!("insert change_address: {e}")))?;
        write
            .commit()
            .map_err(|e| WalletError::SecretFile(format!("wallet store commit: {e}")))?;

        // Mirror persistence into in-memory state.
        state.insert_tracked_pubkey(0, master_pk, network)?;
        state.insert_tracked_pubkey(1, child_pk, network)?;
        state.set_change_address(ergo_wallet::address::pubkey_to_p2pk_address(
            &child_pk, network,
        )?);
        Ok(())
    }

    /// Backfill `WALLET_CHANGE_ADDRESS` for an already-persisted wallet that
    /// has no change address. Mirrors `auto_derive_and_persist`:
    /// the change target is the EIP-3 first-address key derived from the
    /// unlocked master, which is guaranteed to be in the tracked set (it was
    /// persisted at init). Falls back to the master (root) key if EIP-3
    /// derivation is unavailable. Requires an unlocked wallet (caller invokes
    /// this only after `storage.unlock`).
    fn backfill_change_address(
        storage: &mut SecretStorage,
        state: &mut WalletState,
        store: &dyn ergo_state::wallet::WalletStore,
        network: ergo_ser::address::NetworkPrefix,
    ) -> Result<(), WalletError> {
        let unlocked = storage.unlocked().ok_or_else(|| {
            WalletError::SecretFile("must be unlocked at backfill_change_address".to_string())
        })?;

        // EIP-3 first-address key, with the root key as the fallback.
        let eip3_path = ergo_wallet::derivation::DerivationPath::eip3_first_address();
        let change_pk = match unlocked.master.derive_pubkey_at_path(&eip3_path) {
            Ok(pk) => pk,
            Err(_) => unlocked.master.master_pubkey()?,
        };

        // Persist the pubkey, then mirror the rendered address into state.
        let mut write = store
            .begin_write()
            .map_err(|e| WalletError::SecretFile(format!("wallet store begin_write: {e}")))?;
        write
            .set_change_address(change_pk)
            .map_err(|e| WalletError::SecretFile(format!("insert change_address: {e}")))?;
        write
            .commit()
            .map_err(|e| WalletError::SecretFile(format!("wallet store commit: {e}")))?;

        state.set_change_address(ergo_wallet::address::pubkey_to_p2pk_address(
            &change_pk, network,
        )?);
        Ok(())
    }
}

/// Production `RescanGuard` impl. Two methods with distinct semantics:
///
/// - `abort_in_progress`: called by `rollback_block_from_wallet` on
///   every rollback (success or failure). Clears `RESCAN_IN_PROGRESS`
///   only when the fail-closed latch is not set, and writes `WALLET_SCAN_INVALIDATED = true` ONLY if a rescan was
///   actually running — successful rollback without an active rescan
///   stays consistent with the rolled-back chain and does not need
///   invalidation.
/// - `force_invalidate`: called by `StateStore::rollback_to`'s
///   failure branches (missing block section, block-section read
///   error). Writes `WALLET_SCAN_INVALIDATED = true` and preserves
///   fail-closed process guards when they are already set.
///
/// Operational notes:
/// - `RESCAN_IN_PROGRESS` is a process-local atomic, not persisted;
///   normal rollback clears it unless `RESCAN_FAIL_CLOSED` is
///   holding the process closed after a persistence failure.
/// - `WALLET_SCAN_INVALIDATED` is durable. The insert queues on the
///   caller's `&WriteTransaction`, becoming effective only on
///   commit. While set, live wallet apply no-ops; an operator-driven
///   rescan completing successfully is the only path that clears it.
pub struct ProdRescanGuard;

impl ergo_state::wallet::apply::RescanGuard for ProdRescanGuard {
    /// Abort an in-progress rescan if one is active. Conditional
    /// invalidation matches the semantics
    /// `rollback_block_from_wallet` needs on the success path:
    /// a successful rollback without an active rescan keeps wallet
    /// state consistent with the rolled-back chain (no
    /// invalidation needed); a rollback that races with a rescan
    /// invalidates because the rescan was working against a chain
    /// state that's now gone.
    fn abort_in_progress(&self, txn: &WriteTransaction) -> Result<(), redb::Error> {
        if RESCAN_TASK_ACTIVE.load(std::sync::atomic::Ordering::SeqCst) {
            RESCAN_CANCEL_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
            latch_rescan_fail_closed();
            txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), true)?;
        }
        Ok(())
    }

    /// Unconditionally invalidate. Called from
    /// `StateStore::rollback_to`'s failure branches where wallet
    /// history cannot be replayed — invalidation IS warranted
    /// regardless of whether a rescan was active.
    fn force_invalidate(&self, txn: &WriteTransaction) -> Result<(), redb::Error> {
        if RESCAN_TASK_ACTIVE.load(std::sync::atomic::Ordering::SeqCst) {
            RESCAN_CANCEL_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        latch_rescan_fail_closed();
        txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), true)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_state::wallet::{
        RedbWalletStore, WalletRead, WalletStore, WalletStoreError, WalletWrite,
    };
    use redb::ReadableTableMetadata;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    /// Serializes the tests in this module that touch the process-global
    /// `FAULT_INJECT` flag (directly, or indirectly via `auto_derive_and_persist`
    /// which reads it). Cargo runs tests within a binary in parallel, so without
    /// this guard the fault-injection test's armed flag can race another test's
    /// auto-derive and make it panic spuriously.
    static FAULT_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    struct FailingReadStore;

    impl WalletStore for FailingReadStore {
        fn begin_read(&self) -> Result<Box<dyn WalletRead>, WalletStoreError> {
            Err(WalletStoreError::Decode(
                "injected read failure".to_string(),
            ))
        }

        fn begin_write(&self) -> Result<Box<dyn WalletWrite>, WalletStoreError> {
            Err(WalletStoreError::Decode(
                "injected write failure".to_string(),
            ))
        }
    }

    #[test]
    fn unlock_store_read_failure_clears_unlocked_state() {
        let _guard = FAULT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .expect("init");
        let mut state = ergo_wallet::state::WalletState::empty(false);
        let result = WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &FailingReadStore,
            ergo_ser::address::NetworkPrefix::Mainnet,
            "pw",
        );
        assert!(result.is_err());
        assert!(matches!(storage.lock_state(), LockState::Locked));
        assert!(!state.is_unlocked());
    }

    #[tokio::test]
    async fn wallet_task_join_errors_are_reported() {
        let task = tokio::spawn(async {
            panic!("injected wallet task panic");
        });
        let mut first_error = None;
        join_wallet_handles(vec![task], &mut first_error).await;
        assert!(first_error.is_some());
    }

    #[test]
    fn shutdown_requests_active_rescan_cancellation() {
        let _guard = FAULT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        begin_wallet_session();
        clear_rescan_guards();
        let (_dir, store) = store_with_cursor_zero();
        let _ = begin_rescan_process(1, &store, 1).unwrap();
        request_rescan_shutdown();
        assert!(RESCAN_CANCEL_REQUESTED.load(Ordering::SeqCst));
        assert!(RESCAN_FAIL_CLOSED.load(Ordering::SeqCst));
        assert!(RESCAN_TASK_ACTIVE.load(Ordering::SeqCst));
        assert!(wallet_shutdown_requested());
        assert!(matches!(
            begin_rescan_process(0, &store, 0),
            Err(BeginRescanError::Shutdown)
        ));
        clear_rescan_guards();
        begin_wallet_session();
    }

    #[test]
    fn finalization_blocks_successor_until_ownership_clears() {
        let _guard = FAULT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        begin_wallet_session();
        clear_rescan_guards();
        let (_dir, store) = store_with_cursor_zero();
        ergo_state::wallet::set_wallet_finalization_in_progress(true);
        ergo_state::wallet::set_wallet_finalization_owned(true);
        RESCAN_TASK_ACTIVE.store(true, Ordering::SeqCst);

        assert!(matches!(
            begin_rescan_process(0, &store, 0),
            Err(BeginRescanError::FinalizationInProgress)
        ));
        finalize_rescan_guard(
            ergo_state::wallet::wallet_apply_generation(),
            true,
            &store,
            false,
            false,
        );
        assert!(!ergo_state::wallet::wallet_finalization_in_progress());
        assert!(!ergo_state::wallet::wallet_finalization_owned());
        assert!(!RESCAN_TASK_ACTIVE.load(Ordering::SeqCst));
        begin_wallet_session();
    }

    #[test]
    fn rollback_requests_cancellation_for_active_rescan() {
        let _guard = FAULT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        begin_wallet_session();
        clear_rescan_guards();
        let (_cursor_dir, cursor_store) = store_with_cursor_zero();
        let _ = begin_rescan_process(1, &cursor_store, 1).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
        let txn = db.begin_write().unwrap();
        ergo_state::wallet::RescanGuard::abort_in_progress(&ProdRescanGuard, &txn).unwrap();
        txn.commit().unwrap();
        assert!(RESCAN_CANCEL_REQUESTED.load(Ordering::SeqCst));
        assert!(RESCAN_TASK_ACTIVE.load(Ordering::SeqCst));
        assert!(RESCAN_IN_PROGRESS.load(Ordering::SeqCst));
        clear_rescan_guards();
        begin_wallet_session();
    }

    /// Exercises the `WalletBootService` write path under fault
    /// injection: `FAULT_INJECT` makes `unlock_and_sync` panic AFTER
    /// inserting into `WALLET_TRACKED_PUBKEYS` but BEFORE the
    /// `WALLET_VISIBLE_ADDRESSES` insert. Post-panic both tables must
    /// be empty, proving the two inserts share one redb write txn
    /// that aborts atomically on panic.
    #[test]
    fn production_writer_fault_injection_leaves_no_partial_write() {
        // Hold the guard for the whole arm→panic→disarm window so no parallel
        // test's auto-derive sees FAULT_INJECT armed. Recover from a poisoned
        // lock (a prior panicking test still ran inside the guard by design).
        let _guard = FAULT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .expect("init");
        let mut state = ergo_wallet::state::WalletState::empty(false);

        // Arm the fault-injection.
        FAULT_INJECT.store(true, Ordering::SeqCst);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            WalletBootService::unlock_and_sync(
                &mut storage,
                &mut state,
                &db,
                ergo_ser::address::NetworkPrefix::Mainnet,
                "pw",
            )
        }));
        assert!(result.is_err(), "fault injection must trigger panic");

        // Disarm so subsequent tests aren't affected.
        FAULT_INJECT.store(false, Ordering::SeqCst);

        // Verify BOTH tables are empty (write txn dropped without commit).
        let txn = db.begin_read().unwrap();
        if let Ok(t) = txn.open_table(ergo_state::wallet::tables::WALLET_TRACKED_PUBKEYS) {
            assert_eq!(
                t.len().unwrap(),
                0,
                "panic in unlock_and_sync must leave WALLET_TRACKED_PUBKEYS empty",
            );
        }
        if let Ok(t) = txn.open_table(ergo_state::wallet::tables::WALLET_VISIBLE_ADDRESSES) {
            assert_eq!(t.len().unwrap(), 0);
        }
    }

    /// Change-address backfill: a wallet persisted BEFORE the change address became
    /// a default (or restored) reaches `unlock_and_sync` with tracked keys but
    /// no `WALLET_CHANGE_ADDRESS` row. The unlock must backfill it (to the
    /// EIP-3 first key) so the send path has a change target — its absence is
    /// what made every send fail with "no change address set".
    #[test]
    fn unlock_backfills_missing_change_address_for_old_wallet() {
        // Serialize against the fault-injection test: this test's first unlock
        // runs auto_derive_and_persist, which reads FAULT_INJECT.
        let _guard = FAULT_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .expect("init");

        // First unlock: persists tracked keys + a default change address.
        let mut state = ergo_wallet::state::WalletState::empty(false);
        WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &db,
            ergo_ser::address::NetworkPrefix::Mainnet,
            "pw",
        )
        .expect("first unlock");
        assert!(
            state.change_address().is_some(),
            "fresh wallet must get a default change address"
        );

        // Simulate an OLD wallet: delete the change-address row, keeping the
        // tracked keys (so `already_persisted` is true and we hit the hydrate
        // path, not auto-derive).
        {
            let wtxn = db.begin_write().unwrap();
            {
                let mut tbl = wtxn
                    .open_table(ergo_state::wallet::tables::WALLET_CHANGE_ADDRESS)
                    .unwrap();
                tbl.remove(()).unwrap();
            }
            wtxn.commit().unwrap();
        }

        // Re-unlock with fresh in-memory state (mirrors a node restart): the
        // hydrated state has no change address, and Step 5.5 must backfill it.
        storage.lock();
        let mut state2 = ergo_wallet::state::WalletState::empty(false);
        WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state2,
            &db,
            ergo_ser::address::NetworkPrefix::Mainnet,
            "pw",
        )
        .expect("re-unlock must backfill, not fail");

        let backfilled = state2
            .change_address()
            .expect("change address must be backfilled on unlock of an old wallet");
        assert!(
            backfilled.starts_with('9'),
            "backfilled mainnet change address must be a P2PK ('9'), got {backfilled:?}"
        );

        // And it must be durably persisted (survives the next restart).
        let rtxn = db.begin_read().unwrap();
        let tbl = rtxn
            .open_table(ergo_state::wallet::tables::WALLET_CHANGE_ADDRESS)
            .unwrap();
        assert!(
            tbl.get(()).unwrap().is_some(),
            "backfilled change address must be committed to WALLET_CHANGE_ADDRESS"
        );
    }
}

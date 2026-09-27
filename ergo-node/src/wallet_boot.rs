//! Production wallet boot orchestrator. Single unlock+hydrate+persist
//! path shared by the production boot and integration tests, plus the
//! node-runtime wallet session lifecycle (session ids, tracked wallet tasks,
//! and routing a node shutdown to the session's rescan coordinator).
//!
//! The rescan fence flags themselves are per-wallet state owned by
//! [`RescanCoordinator`]; this module only remembers which coordinator
//! belongs to which session so shutdown can cancel that wallet's rescan.

use std::sync::{Arc, Mutex};

use ergo_wallet::error::WalletError;
use ergo_wallet::storage::{LockState, SecretStorage};
use ergo_wallet_service::engine::RescanCoordinator;
use ergo_wallet_service::state::WalletState;
use ergo_wallet_service::wallet::types::TrackedPubkeyMeta;
use tokio::task::{JoinError, JoinHandle};

struct WalletTaskSession {
    closing: bool,
    handles: Vec<JoinHandle<()>>,
    /// The session's rescan coordinator; a shutdown of this session cancels
    /// its rescan through it.
    rescan: Option<Arc<RescanCoordinator>>,
}

struct WalletTaskState {
    sessions: Vec<(u64, WalletTaskSession)>,
}

static WALLET_TASKS: Mutex<WalletTaskState> = Mutex::new(WalletTaskState {
    sessions: Vec::new(),
});
static WALLET_SESSION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn wallet_tasks() -> std::sync::MutexGuard<'static, WalletTaskState> {
    WALLET_TASKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Begin a new wallet session owned by `rescan`: allocate the session id,
/// register the session, and clear the shutdown/cancel requests a previous
/// session may have left on the coordinator.
pub(crate) fn begin_wallet_session(rescan: Arc<RescanCoordinator>) -> u64 {
    let mut tasks = wallet_tasks();
    let session_id = WALLET_SESSION_ID
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        .wrapping_add(1);
    match task_session_index(&tasks, session_id) {
        Some(index) => tasks.sessions[index].1.rescan = Some(rescan.clone()),
        None => tasks.sessions.push((
            session_id,
            WalletTaskSession {
                closing: false,
                handles: Vec::new(),
                rescan: Some(rescan.clone()),
            },
        )),
    }
    rescan.begin_session();
    session_id
}

pub(crate) fn wallet_session_id() -> u64 {
    WALLET_SESSION_ID.load(std::sync::atomic::Ordering::SeqCst)
}

fn task_session_index(state: &WalletTaskState, session_id: u64) -> Option<usize> {
    state.sessions.iter().position(|(id, _)| *id == session_id)
}

pub(crate) async fn track_wallet_task(
    session_id: u64,
    handle: JoinHandle<()>,
) -> Result<(), JoinError> {
    let late_handle = {
        let mut tasks = wallet_tasks();
        let index = match task_session_index(&tasks, session_id) {
            Some(index) => index,
            None => {
                tasks.sessions.push((
                    session_id,
                    WalletTaskSession {
                        closing: false,
                        handles: Vec::new(),
                        rescan: None,
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
        let mut tasks = wallet_tasks();
        let Some(index) = task_session_index(&tasks, session_id) else {
            return Ok(());
        };
        tasks.sessions[index].1.closing = true;
    }
    let mut first_error = None;
    loop {
        let handles = {
            let mut tasks = wallet_tasks();
            let Some(index) = task_session_index(&tasks, session_id) else {
                return first_error.map_or(Ok(()), Err);
            };
            std::mem::take(&mut tasks.sessions[index].1.handles)
        };
        join_wallet_handles(handles, &mut first_error).await;
        let empty = wallet_tasks()
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

/// Node shutdown for `session_id`: when it is still the current session,
/// ask its rescan coordinator to refuse new rescans, cancel the running
/// one, and fail closed if a rescan task is active.
pub(crate) fn request_rescan_shutdown_for(session_id: u64) {
    let tasks = wallet_tasks();
    if wallet_session_id() != session_id {
        return;
    }
    if let Some(rescan) = task_session_index(&tasks, session_id)
        .and_then(|index| tasks.sessions[index].1.rescan.as_ref())
    {
        rescan.request_shutdown();
    }
}

/// Test-only fault-injection flag for the atomic-commit test.
/// When `true`, `unlock_and_sync` panics AFTER inserting the
/// `WALLET_TRACKED_PUBKEYS` rows but BEFORE inserting the
/// `WALLET_VISIBLE_ADDRESSES` rows. The atomic-commit invariant
/// (one redb write txn for both tables) holds iff post-panic both
/// tables are empty.
#[cfg(test)]
pub static FAULT_INJECT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Serialize unit tests that touch the process-global [`FAULT_INJECT`] flag
/// (directly, or through `auto_derive_and_persist`, which reads it).
#[cfg(test)]
pub(crate) static GLOBAL_RESCAN_TEST_GUARD: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

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
        store: &dyn ergo_wallet_service::wallet::WalletStore,
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
                let hydration =
                    ergo_wallet_service::wallet::hydration::HydrationSnapshot::load(read.as_ref())
                        .map_err(|e| {
                            WalletError::SecretFile(format!("wallet store hydration: {e}"))
                        })?;

                if !hydration.is_empty() {
                    // Step 5a: hydrate only after all persisted data has been read successfully.
                    state.hydrate_from_reader(&hydration, network)?;
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
        store: &dyn ergo_wallet_service::wallet::WalletStore,
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
        store: &dyn ergo_wallet_service::wallet::WalletStore,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wallet_service::wallet::{
        RedbWalletStore, WalletRead, WalletStore, WalletStoreError, WalletWrite,
    };
    use redb::ReadableTableMetadata;
    use std::sync::atomic::Ordering;

    /// Serializes the tests in this module that touch the process-global
    /// `FAULT_INJECT` flag (directly, or indirectly via `auto_derive_and_persist`
    /// which reads it). Cargo runs tests within a binary in parallel, so without
    /// this guard the fault-injection test's armed flag can race another test's
    /// auto-derive and make it panic spuriously.
    use super::GLOBAL_RESCAN_TEST_GUARD as FAULT_GUARD;

    #[test]
    fn unlock_at_height_500_tracks_the_next_block_without_invalidation() {
        let _guard = FAULT_GUARD.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        let chain = ergo_state::store::StateStore::open(&dir.path().join("state.redb")).unwrap();
        let db = chain.db_arc();
        let meta = ergo_state::chain::ChainStateMeta {
            best_header_id: [5; 32],
            best_header_height: 500,
            best_header_score: vec![],
            best_full_block_id: [5; 32],
            best_full_block_height: 500,
            header_availability: ergo_state::chain::HeaderAvailability::Dense,
        };
        let txn = db.begin_write().unwrap();
        txn.open_table(redb::TableDefinition::<&str, &[u8]>::new(
            "chain_state_meta",
        ))
        .unwrap()
        .insert("chain_state", meta.serialize().as_slice())
        .unwrap();
        txn.open_table(redb::TableDefinition::<u64, &[u8]>::new("chain_index"))
            .unwrap()
            .insert(500, [5u8; 32].as_slice())
            .unwrap();
        txn.commit().unwrap();
        let store = RedbWalletStore::new(db.clone());
        let mut storage = SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .unwrap();
        let mut state = WalletState::empty(false);
        WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &store,
            ergo_ser::address::NetworkPrefix::Mainnet,
            "pw",
        )
        .unwrap();
        assert_eq!(
            store.read().unwrap().scan_cursor().unwrap().unwrap().height,
            500
        );
        let txn = db.begin_write().unwrap();
        txn.open_table(redb::TableDefinition::<u64, &[u8]>::new("chain_index"))
            .unwrap()
            .insert(501, [6u8; 32].as_slice())
            .unwrap();
        txn.commit().unwrap();
        let mut write = store.begin_write().unwrap();
        write
            .apply_block(
                501,
                &[6; 32],
                &ergo_wallet_service::wallet::WalletApplyPayload {
                    tracked_p2pk_trees: state.tracked_p2pk_trees().clone(),
                    cached_pubkeys: state.cached_pubkeys().clone(),
                    block_txs_owned: vec![],
                    scan_matches: vec![],
                    has_registered_scans: false,
                    allow_non_contiguous_wallet: false,
                },
            )
            .unwrap();
        write.commit().unwrap();
        let read = store.read().unwrap();
        assert!(!read.scan_invalidated().unwrap());
        assert_eq!(
            read.scan_cursor().unwrap().unwrap(),
            ergo_wallet_service::wallet::WalletScanCursor {
                height: 501,
                header_id: Some([6; 32]),
            }
        );
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
        let _guard = FAULT_GUARD.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .expect("init");
        let mut state = ergo_wallet_service::state::WalletState::empty(false);
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
        let _guard = FAULT_GUARD.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .expect("init");
        let mut state = ergo_wallet_service::state::WalletState::empty(false);

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
        if let Ok(t) = txn.open_table(ergo_wallet_service::wallet::tables::WALLET_TRACKED_PUBKEYS) {
            assert_eq!(
                t.len().unwrap(),
                0,
                "panic in unlock_and_sync must leave WALLET_TRACKED_PUBKEYS empty",
            );
        }
        if let Ok(t) = txn.open_table(ergo_wallet_service::wallet::tables::WALLET_VISIBLE_ADDRESSES)
        {
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
        let _guard = FAULT_GUARD.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .expect("init");

        // First unlock: persists tracked keys + a default change address.
        let mut state = ergo_wallet_service::state::WalletState::empty(false);
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
                    .open_table(ergo_wallet_service::wallet::tables::WALLET_CHANGE_ADDRESS)
                    .unwrap();
                tbl.remove(()).unwrap();
            }
            wtxn.commit().unwrap();
        }

        // Re-unlock with fresh in-memory state (mirrors a node restart): the
        // hydrated state has no change address, and Step 5.5 must backfill it.
        storage.lock();
        let mut state2 = ergo_wallet_service::state::WalletState::empty(false);
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
            .open_table(ergo_wallet_service::wallet::tables::WALLET_CHANGE_ADDRESS)
            .unwrap();
        assert!(
            tbl.get(()).unwrap().is_some(),
            "backfilled change address must be committed to WALLET_CHANGE_ADDRESS"
        );
    }
}

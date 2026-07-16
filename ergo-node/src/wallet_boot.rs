//! Production wallet boot orchestrator. Single unlock+hydrate+persist
//! path shared by the production boot and integration tests.

use ergo_state::wallet::tables::*;
use ergo_state::wallet::types::TrackedPubkeyMeta;
use ergo_wallet::error::WalletError;
use ergo_wallet::state::WalletState;
use ergo_wallet::storage::{LockState, SecretStorage};
use redb::{Database, ReadableTableMetadata, WriteTransaction};

/// Rescan-in-progress flag. Set by `NodeWalletAdmin`'s Rescan dispatch;
/// read by the chain-apply hook (via `WalletApplyHook` impl) and by
/// rollback (via `ProdRescanGuard`). Cleared on rescan completion.
pub static RESCAN_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Start height of the in-flight rescan, set alongside [`RESCAN_IN_PROGRESS`].
/// Read by the native `/api/v1/wallet/status` handler to surface
/// `rescan: {type:"running", fromHeight}`. Only meaningful while
/// `RESCAN_IN_PROGRESS` is `true`.
pub static RESCAN_FROM_HEIGHT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Scan-rebuild-in-progress flag. Set by the Rescan dispatch ONLY for a
/// full rebuild (`fromHeight == 0`) that rebuilds the registered `/scan/*`
/// tables; read by the chain-apply hook's scan path (`registered_scan_count`
/// / `match_boxes`), which no-ops while it is set. This quiesces live scan
/// apply for the rebuild's duration: the rebuild clears and repopulates the
/// scan tables block-by-block, so a concurrent live write would race it
/// (miss a spend against the cleared reverse index, or stale that index).
///
/// Distinct from [`RESCAN_IN_PROGRESS`] on purpose: a PARTIAL rescan
/// (`fromHeight > 0`) sets `RESCAN_IN_PROGRESS` but does NOT rebuild scans,
/// so live scan tracking must keep running across it. Cleared when the
/// rescan task finishes (process-local; reads `false` after a restart).
pub static SCAN_REBUILD_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
    /// 4. Open a redb read txn to check if `WALLET_TRACKED_PUBKEYS` has entries.
    ///    - Non-empty: hydrate state from `WalletReader` (redb is source of truth).
    ///    - Empty: auto-derive master + EIP-3 first child, persist both tables in ONE write txn.
    /// 5. Validate the change address: if `WALLET_CHANGE_ADDRESS` points at an
    ///    untracked pubkey, return `ChangeAddressUntracked` and roll back the unlock.
    pub fn unlock_and_sync(
        storage: &mut SecretStorage,
        state: &mut WalletState,
        db: &Database,
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

        // Step 4: Check if tables have entries.
        let already_persisted = {
            let read_txn = db
                .begin_read()
                .map_err(|e| WalletError::SecretFile(format!("redb begin_read: {e}")))?;
            match read_txn.open_table(WALLET_TRACKED_PUBKEYS) {
                Ok(tbl) => {
                    tbl.len()
                        .map_err(|e| WalletError::SecretFile(format!("redb len: {e}")))?
                        > 0
                }
                Err(redb::TableError::TableDoesNotExist(_)) => false,
                Err(e) => return Err(WalletError::SecretFile(format!("redb open_table: {e}"))),
            }
        };

        if already_persisted {
            // Step 5a: hydrate from redb (the persisted state is the source of truth).
            let read_txn = db
                .begin_read()
                .map_err(|e| WalletError::SecretFile(format!("redb begin_read: {e}")))?;
            let reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
            state.hydrate_from_reader(&reader, network)?;
        } else {
            // Step 5b: Fresh wallet — auto-derive master + EIP-3 first child + persist.
            Self::auto_derive_and_persist(storage, state, db, network)?;
        }

        // Step 5.5: Change-address backfill. A wallet that
        // was created before the change address became a persisted default
        // (or restored from a mnemonic) reaches here with no
        // WALLET_CHANGE_ADDRESS row; without a change address every send
        // fails with "no change address set". Backfill with the EIP-3
        // first-address key (falling back to the root key), matching Scala
        // `ErgoWalletSupport.scala:154-168`. Skipped when one is already set.
        if state.change_address().is_none() {
            Self::backfill_change_address(storage, state, db, network)?;
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
                        // Rollback: drop master key, clear unlock flag.
                        storage.lock();
                        state.set_prover(None);
                        state.set_unlocked(false);
                        return Err(WalletError::ChangeAddressUntracked);
                    }
                }
                Err(_) => {
                    // Persisted address doesn't decode — corruption signal.
                    storage.lock();
                    state.set_prover(None);
                    state.set_unlocked(false);
                    return Err(WalletError::ChangeAddressUntracked);
                }
            }
        }

        Ok(())
    }

    fn auto_derive_and_persist(
        storage: &mut SecretStorage,
        state: &mut WalletState,
        db: &Database,
        network: ergo_ser::address::NetworkPrefix,
    ) -> Result<(), WalletError> {
        let unlocked = storage.unlocked().ok_or_else(|| {
            WalletError::SecretFile("must be unlocked at auto_derive".to_string())
        })?;

        // Derive master pubkey + EIP-3 first child.
        let master_pk = unlocked.master.master_pubkey()?;
        let eip3_path = ergo_wallet::derivation::DerivationPath::eip3_first_address();
        let child_pk = unlocked.master.derive_pubkey_at_path(&eip3_path)?;

        // Persist BOTH WALLET_TRACKED_PUBKEYS entries + WALLET_VISIBLE_ADDRESSES entry in ONE write txn.
        let write_txn = db
            .begin_write()
            .map_err(|e| WalletError::SecretFile(format!("redb begin_write: {e}")))?;
        {
            let mut tracked = write_txn.open_table(WALLET_TRACKED_PUBKEYS).map_err(|e| {
                WalletError::SecretFile(format!("open WALLET_TRACKED_PUBKEYS: {e}"))
            })?;
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
            let master_bytes = bincode::serialize(&master_meta)
                .map_err(|e| WalletError::SecretFile(format!("bincode master_meta: {e}")))?;
            let child_bytes = bincode::serialize(&child_meta)
                .map_err(|e| WalletError::SecretFile(format!("bincode child_meta: {e}")))?;
            tracked
                .insert(tracked_pubkey_key(0, &master_pk), master_bytes)
                .map_err(|e| WalletError::SecretFile(format!("insert master tracked: {e}")))?;

            // Fault-injection point: panic AFTER first insert, BEFORE
            // the EIP-3 insert + visible_addresses insert.
            #[cfg(test)]
            if FAULT_INJECT.load(std::sync::atomic::Ordering::SeqCst) {
                panic!("fault injection: unlock_and_sync panic between tracked + visible writes");
            }

            tracked
                .insert(tracked_pubkey_key(1, &child_pk), child_bytes)
                .map_err(|e| WalletError::SecretFile(format!("insert child tracked: {e}")))?;

            // WALLET_VISIBLE_ADDRESSES: only the EIP-3 first child (master hidden
            // per WalletCache.publicKeyAddresses when shape is master + first-child).
            let mut visible = write_txn
                .open_table(WALLET_VISIBLE_ADDRESSES)
                .map_err(|e| {
                    WalletError::SecretFile(format!("open WALLET_VISIBLE_ADDRESSES: {e}"))
                })?;
            visible
                .insert(0u32, child_pk)
                .map_err(|e| WalletError::SecretFile(format!("insert visible_address: {e}")))?;

            // Change address defaults to the EIP-3 first-address key (the
            // backfill rule). Persisted in the SAME txn as the tracked/visible
            // rows so a fresh wallet is never left without a spendable change
            // target — its absence is what made every send fail with
            // "no change address set".
            let mut change = write_txn
                .open_table(WALLET_CHANGE_ADDRESS)
                .map_err(|e| WalletError::SecretFile(format!("open WALLET_CHANGE_ADDRESS: {e}")))?;
            change
                .insert((), child_pk)
                .map_err(|e| WalletError::SecretFile(format!("insert change_address: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WalletError::SecretFile(format!("redb commit: {e}")))?;

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
        db: &Database,
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
        let write_txn = db
            .begin_write()
            .map_err(|e| WalletError::SecretFile(format!("redb begin_write: {e}")))?;
        {
            let mut change = write_txn
                .open_table(WALLET_CHANGE_ADDRESS)
                .map_err(|e| WalletError::SecretFile(format!("open WALLET_CHANGE_ADDRESS: {e}")))?;
            change
                .insert((), change_pk)
                .map_err(|e| WalletError::SecretFile(format!("insert change_address: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WalletError::SecretFile(format!("redb commit: {e}")))?;

        state.set_change_address(ergo_wallet::address::pubkey_to_p2pk_address(
            &change_pk, network,
        )?);
        Ok(())
    }
}

/// Production `RescanGuard` impl. Two methods with distinct semantics:
///
/// - `abort_in_progress`: called by `rollback_block_from_wallet` on
///   every rollback (success or failure). Swaps `RESCAN_IN_PROGRESS`
///   to `false` and writes `WALLET_SCAN_INVALIDATED = true` ONLY if
///   a rescan was actually running — successful rollback without an
///   active rescan stays consistent with the rolled-back chain and
///   does not need invalidation.
/// - `force_invalidate`: called by `StateStore::rollback_to`'s
///   failure branches (missing block section, block-section read
///   error). Unconditionally clears the rescan-in-progress flag and
///   writes `WALLET_SCAN_INVALIDATED = true` — wallet history cannot
///   be replayed against the rolled-back chain, so invalidation IS
///   warranted regardless of whether a rescan was active.
///
/// Operational notes:
/// - `RESCAN_IN_PROGRESS` is a process-local atomic, not persisted;
///   the swap runs immediately and is not coupled to the caller's
///   `&WriteTransaction`. A later commit failure leaves the flag
///   cleared. Reads as `false` after a process restart.
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
        let was_in_progress = RESCAN_IN_PROGRESS.swap(false, std::sync::atomic::Ordering::SeqCst);
        if was_in_progress {
            txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), true)?;
        }
        Ok(())
    }

    /// Unconditionally invalidate. Called from
    /// `StateStore::rollback_to`'s failure branches where wallet
    /// history cannot be replayed — invalidation IS warranted
    /// regardless of whether a rescan was active.
    fn force_invalidate(&self, txn: &WriteTransaction) -> Result<(), redb::Error> {
        RESCAN_IN_PROGRESS.store(false, std::sync::atomic::Ordering::SeqCst);
        txn.open_table(WALLET_SCAN_INVALIDATED)?.insert((), true)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Serializes the tests in this module that touch the process-global
    /// `FAULT_INJECT` flag (directly, or indirectly via `auto_derive_and_persist`
    /// which reads it). Cargo runs tests within a binary in parallel, so without
    /// this guard the fault-injection test's armed flag can race another test's
    /// auto-derive and make it panic spuriously.
    static FAULT_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

//! Shared helper module for wallet integration tests. Uses a REAL
//! redb file (`state.redb` in the temp dir) so the round-trip
//! through `WALLET_TRACKED_PUBKEYS` + `WALLET_VISIBLE_ADDRESSES` +
//! `WALLET_CHANGE_ADDRESS` is exercised end-to-end. A
//! purely-in-memory variant would bypass the persistence contract
//! the production boot path depends on.

use ergo_state::wallet::reader::WalletReader;
use ergo_wallet::state::WalletState;
use ergo_wallet::storage::SecretStorage;
use redb::Database;

/// A test wallet that lives in a temporary directory. Owns:
/// - a redb file at `<dir>/state.redb` for wallet tables
/// - a SecretStorage at `<dir>/wallet/`
/// - the in-memory WalletState
///
/// Persists tracked pubkeys + visible addresses to redb on every
/// `auto_derive`, then hydrates from redb on `reopen` — this is
/// the persistence contract the production boot path enforces.
pub struct TestWallet {
    pub dir: tempfile::TempDir,
    pub db: Database,
    pub storage: SecretStorage,
    pub state: WalletState,
}

impl TestWallet {
    /// Fresh wallet at strength + password, mnemonic_pass = empty.
    /// Does NOT pre-unlock — defers to WalletBootService::unlock_and_sync
    /// (called inside auto_derive_and_persist below) which owns the
    /// unlock path.
    pub fn init(strength_words: u8, password: &str) -> (Self, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("state.redb")).unwrap();
        let mut storage = SecretStorage::open(dir.path().join("wallet"));
        let strength = match strength_words {
            12 => ergo_wallet::mnemonic::MnemonicStrength::Words12,
            24 => ergo_wallet::mnemonic::MnemonicStrength::Words24,
            _ => panic!("unsupported strength {strength_words}"),
        };
        let mnemonic = storage.init(strength, password, "").expect("init");
        let mut state = WalletState::empty(false);
        Self::auto_derive_and_persist(&db, &mut storage, &mut state, password)
            .expect("auto-derive + persist");
        (
            Self {
                dir,
                db,
                storage,
                state,
            },
            mnemonic,
        )
    }

    /// Restore a wallet at the given mnemonic. Uses post-1627 by
    /// default; pass `use_pre_1627 = true` for legacy.
    /// Does NOT pre-unlock — see comment on init().
    #[allow(dead_code)] // reserved for advanced HD-key tests
    pub fn restore(mnemonic: &str, password: &str, use_pre_1627: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::create(dir.path().join("state.redb")).unwrap();
        let mut storage = SecretStorage::open(dir.path().join("wallet"));
        storage
            .restore(mnemonic, "", password, use_pre_1627)
            .expect("restore");
        let mut state = WalletState::empty(use_pre_1627);
        Self::auto_derive_and_persist(&db, &mut storage, &mut state, password)
            .expect("auto-derive + persist");
        Self {
            dir,
            db,
            storage,
            state,
        }
    }

    /// Re-open the wallet from disk (simulates restart). Hydrates
    /// WalletState from the redb tables (NOT by re-deriving in
    /// memory) AND reads the secret file's `use_pre_1627` metadata
    /// so `WalletState::empty()` is constructed with the correct
    /// flag. The master key is NOT loaded until `unlock_and_sync`
    /// is called.
    pub fn reopen(dir: tempfile::TempDir) -> Self {
        let db = Database::open(dir.path().join("state.redb")).unwrap();
        let mut storage = SecretStorage::open(dir.path().join("wallet"));
        // Pre-unlock metadata load (spec §7.3 lifecycle step 1).
        let use_pre_1627 = storage
            .load_metadata()
            .expect("secret file must exist for reopen");
        let mut state = WalletState::empty(use_pre_1627);
        // Hydrate from redb tables. This is the boot-path contract.
        let txn = db.begin_read().unwrap();
        let reader = WalletReader::new(&txn);
        state
            .hydrate_from_reader(&reader, ergo_ser::address::NetworkPrefix::Mainnet)
            .expect("hydrate from redb");
        drop(txn);
        Self {
            dir,
            db,
            storage,
            state,
        }
    }

    /// Re-open + unlock master key via the PRODUCTION boot path.
    /// After this call, the wallet state is fully hydrated AND the
    /// prover is loaded. The unlock + maybe-auto-derive + persist
    /// logic runs once through `WalletBootService::unlock_and_sync`
    /// — the same code path `ergo-node` uses at boot. If pubkeys
    /// already exist in redb (the common case after the first
    /// init), `unlock_and_sync` is idempotent: it unlocks and
    /// hydrates from existing tables without re-deriving. If
    /// pubkeys are absent (corruption / mid-boot crash recovery),
    /// it re-derives + persists. Either way, in-memory state ==
    /// on-disk state after the call.
    pub fn reopen_and_unlock(dir: tempfile::TempDir, password: &str) -> Self {
        let mut t = Self::reopen(dir);
        ergo_node::wallet_boot::WalletBootService::unlock_and_sync(
            &mut t.storage,
            &mut t.state,
            &t.db,
            ergo_ser::address::NetworkPrefix::Mainnet,
            password,
        )
        .expect("WalletBootService::unlock_and_sync");
        t
    }

    /// Auto-derive master + EIP-3 first child into the wallet state,
    /// AND persist to redb in a single write transaction. Delegates
    /// to the production `WalletBootService::unlock_and_sync` so the
    /// test exercises the same code path as `ergo-node` boot — a
    /// parallel test-only implementation could not catch
    /// duplicate-re-add regressions in the boot path.
    fn auto_derive_and_persist(
        db: &Database,
        storage: &mut SecretStorage,
        state: &mut WalletState,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        ergo_node::wallet_boot::WalletBootService::unlock_and_sync(
            storage,
            state,
            db,
            ergo_ser::address::NetworkPrefix::Mainnet,
            password,
        )?;
        Ok(())
    }
}

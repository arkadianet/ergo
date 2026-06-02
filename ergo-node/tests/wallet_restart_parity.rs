//! Restart-parity tests per spec §9.4.1. Cover the
//! auto-derive-at-unlock path (deriveKey is exercised by the
//! advanced HD-key tests). Each test must EXERCISE redb persistence
//! via WalletReader::hydrate_from_reader on reopen, not just
//! re-derive in memory.

use redb::{ReadableTable, ReadableTableMetadata};

mod wallet_e2e_helpers;
use wallet_e2e_helpers::TestWallet;

#[test]
fn restart_loads_pubkeys_from_redb_not_via_rederive() {
    // 1. init + auto-derive + persist to redb.
    let (t, _mnemonic) = TestWallet::init(24, "test-pw");
    let pubkeys_before: Vec<[u8; 33]> = t.state.cached_pubkeys().values().copied().collect();
    let addresses_before: Vec<String> = t.state.visible_addresses().to_vec();
    assert_eq!(
        pubkeys_before.len(),
        2,
        "auto-derive must produce 2 pubkeys"
    );
    assert!(!addresses_before.is_empty());

    // 2. Drop everything (including the WalletState — no in-memory
    //    leakage).
    // Destructure to avoid partial-move on `t.dir; drop(t)`.
    let TestWallet {
        dir,
        db,
        storage,
        state,
    } = t;
    drop(db);
    drop(storage);
    drop(state);
    // `dir` is now solely owned by us; the tempdir lives until we drop it.

    // 3. Re-open. CRITICAL: this calls hydrate_from_reader against
    //    the redb file; pubkeys come from disk, NOT from re-deriving
    //    via the master key (which is still locked at this point).
    let t2 = TestWallet::reopen(dir);

    // Wallet is locked but state IS hydrated.
    assert!(
        !t2.state.is_unlocked(),
        "after reopen-without-unlock, prover must be None"
    );
    let pubkeys_after: Vec<[u8; 33]> = t2.state.cached_pubkeys().values().copied().collect();
    let addresses_after: Vec<String> = t2.state.visible_addresses().to_vec();

    // 4. Pin: redb-hydrated state matches the persisted state
    //    (proves WALLET_TRACKED_PUBKEYS round-trip).
    assert_eq!(
        pubkeys_after, pubkeys_before,
        "redb-hydrated pubkeys must match what was written"
    );
    assert_eq!(
        addresses_after, addresses_before,
        "redb-hydrated visible_addresses must match what was written"
    );
}

#[test]
fn restart_then_unlock_does_not_re_add_existing_pubkeys() {
    // After restart, the master key is locked. Operator unlocks.
    // The unlock path must NOT re-add the already-tracked pubkeys
    // (auto-derive runs only on FIRST unlock of an uninitialized
    // wallet — subsequent unlocks find the pubkeys already in
    // redb and skip re-derivation).
    let (t, _) = TestWallet::init(24, "pw");
    let n_before = t.state.cached_pubkeys().len();
    // Destructure to avoid partial-move on `t.dir; drop(t)`.
    let TestWallet {
        dir,
        db,
        storage,
        state,
    } = t;
    drop(db);
    drop(storage);
    drop(state);
    // `dir` is now solely owned by us; the tempdir lives until we drop it.
    let t2 = TestWallet::reopen_and_unlock(dir, "pw");
    let n_after = t2.state.cached_pubkeys().len();
    assert_eq!(
        n_after, n_before,
        "unlock-after-restart must NOT duplicate pubkeys (n_before={n_before}, n_after={n_after})"
    );
}

#[test]
fn first_tracked_pubkey_stable_across_restart() {
    // Per spec §9.4.1: "GetMiningPubKey head-order behavior is
    // stable" — the first tracked pubkey doesn't change across
    // restart. With auto-derive (master at index 0), the head
    // is always the master.
    let (t, _) = TestWallet::init(24, "pw");
    let head_before = *t.state.cached_pubkeys().iter().next().unwrap().1;
    // Destructure to avoid partial-move on `t.dir; drop(t)`.
    let TestWallet {
        dir,
        db,
        storage,
        state,
    } = t;
    drop(db);
    drop(storage);
    drop(state);
    // `dir` is now solely owned by us; the tempdir lives until we drop it.
    let t2 = TestWallet::reopen_and_unlock(dir, "pw");
    let head_after = *t2.state.cached_pubkeys().iter().next().unwrap().1;
    assert_eq!(head_after, head_before, "head pubkey must be stable");
}

#[test]
fn tracked_pubkeys_and_visible_addresses_rebuild_atomically() {
    // Setup: a fresh wallet directory.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test_wallet.redb");

    // Open a fresh redb at the path and begin a write txn that
    // inserts a tracked pubkey but is dropped BEFORE inserting the
    // matching visible_address. Goal: verify both tables are empty
    // after the dropped txn (atomic abort).
    {
        let db = redb::Database::create(&db_path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut tracked_tbl = txn
                .open_table(ergo_state::wallet::tables::WALLET_TRACKED_PUBKEYS)
                .unwrap();
            let pk = [0xAB; 33];
            let meta = ergo_state::wallet::types::TrackedPubkeyMeta {
                derivation_path: vec![],
                derivation_path_label: String::new(),
                added_at_height: 0,
            };
            let meta_bytes = bincode::serialize(&meta).unwrap();
            tracked_tbl
                .insert(
                    ergo_state::wallet::tables::tracked_pubkey_key(0, &pk),
                    meta_bytes,
                )
                .unwrap();
            // NOTE: we deliberately do NOT touch WALLET_VISIBLE_ADDRESSES
            // here. The txn is then dropped without commit, simulating
            // a panic between the two writes.
        }
        drop(txn); // No commit — full abort.
    }

    // Re-open and verify: NEITHER table has data.
    let db = redb::Database::open(&db_path).unwrap();
    let txn = db.begin_read().unwrap();
    if let Ok(t) = txn.open_table(ergo_state::wallet::tables::WALLET_TRACKED_PUBKEYS) {
        assert_eq!(
            t.len().unwrap(),
            0,
            "dropped txn must leave WALLET_TRACKED_PUBKEYS empty"
        );
    }
    if let Ok(t) = txn.open_table(ergo_state::wallet::tables::WALLET_VISIBLE_ADDRESSES) {
        assert_eq!(t.len().unwrap(), 0);
    }
}

#[test]
fn production_writer_advances_both_tables_or_neither() {
    // Verify the production writer (not a synthetic redb txn).
    // Call WalletBootService::unlock_and_sync on a fresh
    // wallet; observe BOTH WALLET_TRACKED_PUBKEYS and
    // WALLET_VISIBLE_ADDRESSES advanced together; row counts match
    // expected (2 tracked + 1 visible with master hidden); entries
    // cross-reference (visible_addresses[0] == tracked_pubkeys[1]).
    let (t, _) = TestWallet::init(24, "pw");
    let txn = t.db.begin_read().unwrap();
    let tracked = txn
        .open_table(ergo_state::wallet::tables::WALLET_TRACKED_PUBKEYS)
        .unwrap();
    let visible = txn
        .open_table(ergo_state::wallet::tables::WALLET_VISIBLE_ADDRESSES)
        .unwrap();
    assert_eq!(
        tracked.len().unwrap(),
        2,
        "auto-derive must add master + EIP-3 first child"
    );
    assert_eq!(
        visible.len().unwrap(),
        1,
        "visible must hide master when shape is master+first-child"
    );

    // Cross-reference: the single visible-addresses entry must be the
    // pubkey from tracked-pubkeys index 1 (the EIP-3 first child).
    let mut tracked_iter = tracked.iter().unwrap();
    let (_, _meta0) = tracked_iter.next().unwrap().unwrap(); // master
    let (k1_guard, _meta1) = tracked_iter.next().unwrap().unwrap();
    let k1_bytes: [u8; 41] = k1_guard.value();
    let (_, pk_from_tracked_index_1) =
        ergo_state::wallet::tables::parse_tracked_pubkey_key(&k1_bytes);

    let visible_entry = visible.iter().unwrap().next().unwrap().unwrap();
    let (_, pk_from_visible) = visible_entry;
    assert_eq!(
        pk_from_visible.value(), pk_from_tracked_index_1,
        "visible-addresses must reference the same pubkey as tracked-pubkeys index 1 (cross-reference invariant)",
    );
}

#[test]
fn legacy_wallet_restart_preserves_use_pre_1627_flag_before_unlock() {
    // Verify the pre-unlock boot path correctly hydrates the
    // use_pre_1627 flag from the secret file's metadata.
    // Without this, a legacy wallet restart would default to
    // post-1627 derivation, silently corrupting the wallet view.
    use ergo_wallet::storage::SecretStorage;

    let dir = tempfile::tempdir().unwrap();
    let _db = redb::Database::create(dir.path().join("state.redb")).unwrap();
    let mut storage = SecretStorage::open(dir.path().join("wallet"));
    let phrase = "race relax argue hair sorry riot there spirit ready \
                  fetch food hedgehog hybrid mobile pretty";
    storage
        .restore(phrase, "", "pw", /* use_pre_1627 */ true)
        .expect("restore legacy wallet");

    // Drop storage (locked, never unlocked).
    drop(storage);

    // Re-open. The pre-unlock metadata read MUST surface use_pre_1627=true.
    let mut storage_reopened = SecretStorage::open(dir.path().join("wallet"));
    let use_pre_1627 = storage_reopened
        .load_metadata()
        .expect("metadata load must succeed for existing wallet");
    assert!(
        use_pre_1627,
        "legacy wallet's use_pre_1627 flag must be visible BEFORE unlock",
    );
    assert!(
        storage_reopened.unlocked().is_none(),
        "load_metadata must NOT unlock — that's a separate step"
    );
}

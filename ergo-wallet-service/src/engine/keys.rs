//! Key management: `deriveKey` / `deriveNextKey` / `getPrivateKey`, and the
//! unlock-time key derivation and change-address backfill
//! ([`WalletBootService`]).

use ergo_wallet::error::WalletError;
use ergo_wallet::storage::{LockState, SecretStorage};
use ergo_wallet_protocol::scala::admin_advanced::{
    DeriveKeyRequest, DeriveKeyResponse, DeriveNextKeyResponse, GetPrivateKeyRequest,
    GetPrivateKeyResponse,
};
use ergo_wallet_protocol::WalletAdminError;
use parking_lot::RwLock;

use crate::engine::{WalletChainAccess, WalletEngine, WalletEngineConfig};
use crate::state::WalletState;
use crate::wallet::types::TrackedPubkeyMeta;

fn next_tracked_index(existing: &[(u64, [u8; 33], Vec<u32>)]) -> Result<u64, WalletAdminError> {
    existing
        .iter()
        .map(|(index, _, _)| *index)
        .max()
        .map_or(Ok(0), |index| {
            index
                .checked_add(1)
                .ok_or_else(|| WalletAdminError::Internal("tracked key index exhausted".into()))
        })
}

/// Reconcile the native EIP-3 external-address counter with manually tracked
/// paths in the same account, retaining the existing fixed-account policy.
fn next_eip3_address_index(
    head: u64,
    existing: &[(u64, [u8; 33], Vec<u32>)],
) -> Result<u32, WalletAdminError> {
    use ergo_wallet::derivation::HARDENED_OFFSET;
    let prefix = [
        HARDENED_OFFSET | 44,
        HARDENED_OFFSET | 429,
        HARDENED_OFFSET,
        0,
    ];
    let tracked_head = existing
        .iter()
        .filter_map(|(_, _, path)| {
            if path.len() == 5 && path.starts_with(&prefix) && path[4] < HARDENED_OFFSET {
                Some(u64::from(path[4]))
            } else {
                None
            }
        })
        .max()
        .unwrap_or(0);
    let next = head
        .max(tracked_head)
        .checked_add(1)
        .filter(|next| *next < u64::from(HARDENED_OFFSET))
        .ok_or_else(|| {
            WalletAdminError::BadRequest("non-hardened EIP-3 address index space exhausted".into())
        })?;
    Ok(next as u32)
}

/// Render a BIP32 path (raw u32 component slice) as a `m/...` string.
/// Mirrors `DerivationPath::Display` without constructing the struct.
pub(crate) fn render_derivation_path(components: &[u32]) -> String {
    use ergo_wallet::derivation::HARDENED_OFFSET;
    if components.is_empty() {
        return "m/".to_string();
    }
    let mut s = "m".to_string();
    for &c in components {
        if c >= HARDENED_OFFSET {
            s.push('/');
            s.push_str(&(c - HARDENED_OFFSET).to_string());
            s.push('\'');
        } else {
            s.push('/');
            s.push_str(&c.to_string());
        }
    }
    s
}

/// Shared write path: persist a new tracked pubkey + rebuild WALLET_VISIBLE_ADDRESSES,
/// optionally advancing WALLET_DERIVATION_HEAD in the SAME transaction. Returns
/// the new `derivation_path_index` used for the entry.
///
/// The write is atomic (single redb write transaction) — including the head
/// advance when `new_derivation_head` is `Some`. This matters for
/// `derive_next_key_impl`: folding the head advance into this same commit
/// means a crash can never leave a tracked pubkey persisted without its
/// corresponding head advance. The next-key path also reconciles the head
/// with manually tracked paths in the same account. `derive_key_impl` passes
/// `None` because it may derive an unrelated path.
///
/// Visibility is rebuilt in Scala's path storage order, hiding the master
/// only when the next entry has the EIP-3 account prefix.
pub(crate) fn persist_tracked_pubkey(
    store: &dyn crate::wallet::WalletStore,
    path_idx: u64,
    pubkey: &[u8; 33],
    meta: &crate::wallet::types::TrackedPubkeyMeta,
    new_derivation_head: Option<u64>,
) -> Result<(), WalletAdminError> {
    let mut write = store
        .begin_write()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    write
        .insert_tracked_pubkey(path_idx, *pubkey, meta)
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    write
        .rebuild_visible_addresses()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    if let Some(head) = new_derivation_head {
        write
            .set_derivation_head(head)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    }
    write
        .commit()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))
}

/// `POST /wallet/deriveKey` writer-task implementation.
pub(crate) fn derive_key_impl(
    request: &ergo_wallet_protocol::scala::admin_advanced::DeriveKeyRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<crate::state::WalletState>,
    store: &dyn crate::wallet::WalletStore,
    chain: &dyn WalletChainAccess,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<ergo_wallet_protocol::scala::admin_advanced::DeriveKeyResponse, WalletAdminError> {
    use ergo_wallet::derivation::DerivationPath;
    use ergo_wallet_protocol::scala::admin_advanced::DeriveKeyResponse;

    // Require unlocked.
    let storage_guard = storage.read();
    let unlocked = storage_guard.unlocked().ok_or(WalletAdminError::Locked)?;

    // Parse the requested path. A malformed path is a client error (400), not 500.
    let path: DerivationPath =
        request
            .derivation_path
            .parse()
            .map_err(|e: ergo_wallet::error::WalletError| {
                WalletAdminError::BadRequest(format!("invalid derivation path: {e}"))
            })?;

    // Dedup: compare against every existing tracked path via tracked_pubkeys_with_paths.
    let read = store
        .read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let existing: Vec<(u64, [u8; 33], Vec<u32>)> = read
        .tracked_pubkeys_with_paths()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    // Path-component comparison. An already-tracked path is a 409 precondition,
    // not a 500 — surfaced as the typed `DerivationPathExists`.
    for (_, _, existing_path) in &existing {
        if existing_path.as_slice() == path.components() {
            return Err(WalletAdminError::DerivationPathExists);
        }
    }

    // Compute next derivation_path_index = max existing + 1.
    let next_idx = next_tracked_index(&existing)?;

    // Derive the pubkey.
    let pubkey = unlocked
        .master
        .derive_pubkey_at_path(&path)
        .map_err(|e| WalletAdminError::Internal(format!("deriveKey: derivation failed: {e}")))?;

    drop(read);

    // Build metadata.
    let meta = crate::wallet::types::TrackedPubkeyMeta {
        derivation_path: path.components().to_vec(),
        derivation_path_label: String::new(),
        added_at_height: chain
            .tip_height()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
    };

    // Persist atomically (WALLET_TRACKED_PUBKEYS + WALLET_VISIBLE_ADDRESSES).
    persist_tracked_pubkey(store, next_idx, &pubkey, &meta, None)?;
    drop(storage_guard);

    // Update in-memory WalletState.
    {
        let mut s = state.write();
        let read = store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let hydration = crate::wallet::hydration::HydrationSnapshot::load(read.as_ref())
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        s.hydrate_from_reader(&hydration, network)
            .map_err(|e| WalletAdminError::Internal(format!("deriveKey: state update: {e}")))?;
    }

    // Encode to address string.
    let address = ergo_wallet::address::pubkey_to_p2pk_address(&pubkey, network)
        .map_err(|e| WalletAdminError::Internal(format!("deriveKey: address encode: {e}")))?;

    Ok(DeriveKeyResponse { address })
}

/// `GET /wallet/deriveNextKey` writer-task implementation.
///
/// Shares its persist step with [`derive_key_impl`] via
/// [`persist_tracked_pubkey`] (tracked pubkey + `WALLET_VISIBLE_ADDRESSES`
/// rebuild), passing `Some(new_head)` so the `WALLET_DERIVATION_HEAD` advance
/// commits in the SAME transaction — a crash can never persist the tracked
/// pubkey without also advancing the head. Manually tracked paths in the same
/// native EIP-3 account are included when choosing the next index.
pub(crate) fn derive_next_key_impl(
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<crate::state::WalletState>,
    store: &dyn crate::wallet::WalletStore,
    chain: &dyn WalletChainAccess,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<ergo_wallet_protocol::scala::admin_advanced::DeriveNextKeyResponse, WalletAdminError> {
    use ergo_wallet::derivation::{DerivationPath, HARDENED_OFFSET};
    use ergo_wallet_protocol::scala::admin_advanced::DeriveNextKeyResponse;

    // Require unlocked.
    let storage_guard = storage.read();
    let unlocked = storage_guard.unlocked().ok_or(WalletAdminError::Locked)?;

    // Read WALLET_DERIVATION_HEAD singleton (default 0 if missing).
    let head: u64 = store
        .read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?
        .derivation_head()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    // Manual derivation can advance the native external-address account.
    // Reconcile it with the persisted sequential counter before choosing a path.
    let read = store
        .read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let existing = read
        .tracked_pubkeys_with_paths()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let new_head = next_eip3_address_index(head, &existing)?;
    let path_components = vec![
        HARDENED_OFFSET | 44,
        HARDENED_OFFSET | 429,
        HARDENED_OFFSET,
        0,
        new_head,
    ];
    let path = DerivationPath::from_components(path_components);
    let path_str = render_derivation_path(path.components());

    for (_, _, existing_path) in &existing {
        if existing_path.as_slice() == path.components() {
            return Err(WalletAdminError::DerivationPathExists);
        }
    }

    let next_idx = next_tracked_index(&existing)?;

    // Derive the pubkey.
    let pubkey = unlocked.master.derive_pubkey_at_path(&path).map_err(|e| {
        WalletAdminError::Internal(format!("deriveNextKey: derivation failed: {e}"))
    })?;

    drop(read);

    let meta = crate::wallet::types::TrackedPubkeyMeta {
        derivation_path: path.components().to_vec(),
        derivation_path_label: String::new(),
        added_at_height: chain
            .tip_height()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
    };

    // Persist WALLET_TRACKED_PUBKEYS + WALLET_VISIBLE_ADDRESSES, shared with
    // derive_key_impl so the two paths can never drift on this logic.
    persist_tracked_pubkey(store, next_idx, &pubkey, &meta, Some(u64::from(new_head)))?;
    drop(storage_guard);

    // Update in-memory WalletState.
    {
        let mut s = state.write();
        let read = store
            .read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let hydration = crate::wallet::hydration::HydrationSnapshot::load(read.as_ref())
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        s.hydrate_from_reader(&hydration, network)
            .map_err(|e| WalletAdminError::Internal(format!("deriveNextKey: state update: {e}")))?;
    }

    let address = ergo_wallet::address::pubkey_to_p2pk_address(&pubkey, network)
        .map_err(|e| WalletAdminError::Internal(format!("deriveNextKey: address encode: {e}")))?;

    Ok(DeriveNextKeyResponse {
        derivation_path: path_str,
        address,
    })
}

/// `POST /wallet/getPrivateKey` writer-task implementation.
///
/// Operator-flag gated by `cfg.expose_private_keys` (resolved from
/// `[wallet] expose_private_keys` at config-load): when `false`,
/// returns `Forbidden` immediately; when `true`, derives the scalar
/// for the requested address and returns it as 32-byte big-endian
/// hex.
pub(crate) fn get_private_key_impl(
    request: &ergo_wallet_protocol::scala::admin_advanced::GetPrivateKeyRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    store: &dyn crate::wallet::WalletStore,
    cfg: &WalletEngineConfig,
) -> Result<ergo_wallet_protocol::scala::admin_advanced::GetPrivateKeyResponse, WalletAdminError> {
    use ergo_wallet::derivation::DerivationPath;
    use ergo_wallet_protocol::scala::admin_advanced::GetPrivateKeyResponse;

    if !cfg.expose_private_keys {
        return Err(WalletAdminError::Forbidden(
            "getPrivateKey disabled — set [wallet] expose_private_keys = true in config".into(),
        ));
    }

    // Require unlocked.
    let storage_guard = storage.read();
    let unlocked = storage_guard.unlocked().ok_or(WalletAdminError::Locked)?;

    // Decode address → pubkey.
    let pubkey =
        ergo_ser::address::decode_p2pk_address(&request.address, cfg.network).map_err(|e| {
            WalletAdminError::BadRequest(format!("bad address {}: {e}", request.address))
        })?;

    // Look up derivation path for this pubkey in WALLET_TRACKED_PUBKEYS.
    let read = store
        .read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let tracked = read
        .tracked_pubkeys_with_paths()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

    let path_components = tracked
        .into_iter()
        .find(|(_, pk, _)| pk == &pubkey)
        .map(|(_, _, path)| path)
        .ok_or_else(|| {
            WalletAdminError::Internal(format!(
                "getPrivateKey: address {} not in tracked keys",
                request.address
            ))
        })?;

    let path = DerivationPath::from_components(path_components);

    // Derive the scalar.
    let scalar = unlocked
        .master
        .derive_scalar_for_pubkey(&path, &pubkey)
        .map_err(|e| WalletAdminError::Internal(format!("getPrivateKey: {e}")))?;

    // Encode as 32-byte big-endian hex.
    let scalar_bytes: [u8; 32] = scalar.to_bytes().into();
    let w = hex::encode(scalar_bytes);

    Ok(GetPrivateKeyResponse { w })
}

impl WalletEngine {
    pub fn derive_key(
        &mut self,
        request: DeriveKeyRequest,
    ) -> Result<DeriveKeyResponse, WalletAdminError> {
        super::keys::derive_key_impl(
            &request,
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.config.network,
        )
    }

    pub fn derive_next_key(&mut self) -> Result<DeriveNextKeyResponse, WalletAdminError> {
        super::keys::derive_next_key_impl(
            &self.storage,
            &self.state,
            self.store.as_ref(),
            self.chain.as_ref(),
            self.config.network,
        )
    }

    pub fn get_private_key(
        &self,
        request: GetPrivateKeyRequest,
    ) -> Result<GetPrivateKeyResponse, WalletAdminError> {
        super::keys::get_private_key_impl(
            &request,
            &self.storage,
            self.store.as_ref(),
            &self.config,
        )
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only fault-injection flag for the atomic-commit test.
    /// When `true`, `unlock_and_sync` panics AFTER inserting the
    /// `WALLET_TRACKED_PUBKEYS` rows but BEFORE inserting the
    /// `WALLET_VISIBLE_ADDRESSES` rows. The atomic-commit invariant
    /// (one redb write txn for both tables) holds iff post-panic both
    /// tables are empty. Thread-local, so arming it on one test thread can
    /// never make another test's auto-derive panic.
    static FAULT_INJECT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The single production unlock + hydrate + persist path, shared by the
/// wallet engine's `unlock` and the node's integration tests. Owns the
/// unlock-time key derivation: a fresh wallet's master + EIP-3 first child
/// are derived and persisted here, and a missing change address is
/// backfilled.
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
        store: &dyn crate::wallet::WalletStore,
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

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (|| -> Result<(), WalletError> {
                // Step 4: Check if tables have entries.
                let read = store
                    .read()
                    .map_err(|e| WalletError::SecretFile(format!("wallet store read: {e}")))?;
                let hydration = crate::wallet::hydration::HydrationSnapshot::load(read.as_ref())
                    .map_err(|e| WalletError::SecretFile(format!("wallet store hydration: {e}")))?;

                if !hydration.is_empty() {
                    let rows = read.tracked_pubkeys_with_paths().map_err(|e| {
                        WalletError::SecretFile(format!("wallet tracked keys: {e}"))
                    })?;
                    let visible = read.visible_pubkeys().map_err(|e| {
                        WalletError::SecretFile(format!("wallet visible keys: {e}"))
                    })?;
                    let tracked: Vec<_> = rows
                        .iter()
                        .map(|(_, pubkey, path)| (*pubkey, path.clone()))
                        .collect();
                    if storage.bind_tracked_keys(&tracked)?
                        == ergo_wallet::storage::MasterDerivation::LegacyRustTrimmed
                    {
                        tracing::warn!("wallet keys use the earlier Rust legacy master encoding; signing and new addresses retain that derivation");
                    }
                    let ordered = crate::state::visible_pubkeys_with_paths(&rows);
                    let repair_visibility =
                        !visible.iter().map(|(_, pubkey)| pubkey).eq(ordered.iter());
                    drop(read);
                    if repair_visibility {
                        let mut write = store.begin_write().map_err(|e| {
                            WalletError::SecretFile(format!("wallet store begin_write: {e}"))
                        })?;
                        write
                            .rebuild_visible_addresses()
                            .map_err(|e| WalletError::SecretFile(format!("visible keys: {e}")))?;
                        write.commit().map_err(|e| {
                            WalletError::SecretFile(format!("wallet store commit: {e}"))
                        })?;
                    }
                    let read = store
                        .read()
                        .map_err(|e| WalletError::SecretFile(format!("wallet store read: {e}")))?;
                    let hydration = crate::wallet::hydration::HydrationSnapshot::load(
                        read.as_ref(),
                    )
                    .map_err(|e| WalletError::SecretFile(format!("wallet store hydration: {e}")))?;
                    state.hydrate_from_reader(&hydration, network)?;
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

                state.set_unlocked(true);
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
        store: &dyn crate::wallet::WalletStore,
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
        if FAULT_INJECT.with(std::cell::Cell::get) {
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

        // Hydrate the committed visibility/change snapshot, exactly as on reopen.
        let read = store
            .read()
            .map_err(|e| WalletError::SecretFile(e.to_string()))?;
        let hydration = crate::wallet::hydration::HydrationSnapshot::load(read.as_ref())
            .map_err(|e| WalletError::SecretFile(e.to_string()))?;
        state.hydrate_from_reader(&hydration, network)?;
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
        store: &dyn crate::wallet::WalletStore,
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
    use crate::wallet::{RedbWalletStore, WalletRead, WalletStore, WalletStoreError, WalletWrite};
    use redb::ReadableTableMetadata;
    use std::sync::Arc;

    #[test]
    fn tracked_key_mutation_tracks_forward_without_invalidating() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
        let store = RedbWalletStore::new(db);
        let pubkey = [7u8; 33];
        let meta = crate::wallet::types::TrackedPubkeyMeta {
            derivation_path: vec![44, 0],
            derivation_path_label: String::new(),
            added_at_height: 0,
        };

        persist_tracked_pubkey(&store, 0, &pubkey, &meta, Some(1)).unwrap();

        assert!(!store.read().unwrap().scan_invalidated().unwrap());
        store.persist_scan_invalidation(false).unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .expect("init");
        let mut state = crate::state::WalletState::empty(false);
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

    /// Exercises the `WalletBootService` write path under fault
    /// injection: `FAULT_INJECT` makes `unlock_and_sync` panic AFTER
    /// inserting into `WALLET_TRACKED_PUBKEYS` but BEFORE the
    /// `WALLET_VISIBLE_ADDRESSES` insert. Post-panic both tables must
    /// be empty, proving the two inserts share one redb write txn
    /// that aborts atomically on panic.
    #[test]
    fn production_writer_fault_injection_leaves_no_partial_write() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .expect("init");
        let mut state = crate::state::WalletState::empty(false);

        // Arm the fault-injection.
        FAULT_INJECT.with(|armed| armed.set(true));

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
        assert!(
            storage.unlocked().is_none(),
            "unwinding must relock decrypted storage"
        );
        assert!(!state.is_unlocked());

        // Disarm so subsequent tests aren't affected.
        FAULT_INJECT.with(|armed| armed.set(false));

        // Verify BOTH tables are empty (write txn dropped without commit).
        let txn = redb::ReadableDatabase::begin_read(&db).unwrap();
        if let Ok(t) = txn.open_table(crate::wallet::tables::WALLET_TRACKED_PUBKEYS) {
            assert_eq!(
                t.len().unwrap(),
                0,
                "panic in unlock_and_sync must leave WALLET_TRACKED_PUBKEYS empty",
            );
        }
        if let Ok(t) = txn.open_table(crate::wallet::tables::WALLET_VISIBLE_ADDRESSES) {
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
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .expect("init");

        // First unlock: persists tracked keys + a default change address.
        let mut state = crate::state::WalletState::empty(false);
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
                    .open_table(crate::wallet::tables::WALLET_CHANGE_ADDRESS)
                    .unwrap();
                tbl.remove(()).unwrap();
            }
            wtxn.commit().unwrap();
        }

        // Re-unlock with fresh in-memory state (mirrors a node restart): the
        // hydrated state has no change address, and Step 5.5 must backfill it.
        storage.lock();
        let mut state2 = crate::state::WalletState::empty(false);
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
        let rtxn = redb::ReadableDatabase::begin_read(&db).unwrap();
        let tbl = rtxn
            .open_table(crate::wallet::tables::WALLET_CHANGE_ADDRESS)
            .unwrap();
        assert!(
            tbl.get(()).unwrap().is_some(),
            "backfilled change address must be committed to WALLET_CHANGE_ADDRESS"
        );
    }
}

#[cfg(test)]
mod key_management_tests {
    use super::*;
    use crate::wallet::hydration::HydrationSource;

    struct EmptyChain;
    impl WalletChainAccess for EmptyChain {
        fn wallet_scan_height(&self) -> Result<u32, crate::engine::ChainAccessError> {
            Ok(0)
        }
        fn tip_height(&self) -> Result<u32, crate::engine::ChainAccessError> {
            Ok(0)
        }
        fn is_pruned(&self) -> bool {
            false
        }
        fn read_block_at(
            &self,
            _: u32,
        ) -> Result<Option<crate::wallet::scan::RescanBlock>, crate::wallet::scan::RescanReadError>
        {
            Ok(None)
        }
    }

    fn leading_zero_vector(mode: &str, path: &str) -> ([u8; 33], String) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/wallet/leading-zero-master/scala_6_0_6.json"
        )))
        .unwrap();
        let vector = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["mode"] == mode && v["path"] == path)
            .unwrap()
            .clone();
        let public_key = hex::decode(vector["publicKey"].as_str().unwrap()).unwrap();
        (
            public_key.try_into().unwrap(),
            vector["secret"].as_str().unwrap().to_owned(),
        )
    }

    /// Legacy secret file for the public leading-zero-master seed.
    fn leading_zero_legacy_storage(directory: &std::path::Path) -> ergo_wallet::SecretStorage {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/wallet/leading-zero-master/scala_6_0_6.json"
        )))
        .unwrap();
        let seed = hex::decode(fixture["seed"].as_str().unwrap()).unwrap();
        let (salt, iv) = ([0x29; 32], [0x39; 12]);
        let key = ergo_wallet::encryption::derive_key_pbkdf2(b"pw", &salt, 128_000);
        let (ciphertext, tag) = ergo_wallet::encryption::encrypt(&key, &iv, &seed).unwrap();
        let encrypted = serde_json::json!({
            "cipherText": hex::encode(ciphertext), "salt": hex::encode(salt),
            "iv": hex::encode(iv), "authTag": hex::encode(tag),
            "cipherParams": { "prf": "HmacSHA512", "c": 128000, "dkLen": 256 },
            "usePre1627KeyDerivation": true
        });
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(directory.join("secret.json"), encrypted.to_string()).unwrap();
        ergo_wallet::SecretStorage::open(directory.to_path_buf())
    }

    fn track(db: &redb::Database, index: u64, pubkey: &[u8; 33], path: Vec<u32>) {
        let meta = crate::wallet::types::TrackedPubkeyMeta {
            derivation_path: path,
            derivation_path_label: String::new(),
            added_at_height: 0,
        };
        persist_tracked_pubkey(db, index, pubkey, &meta, None).unwrap();
    }

    fn private_key_config() -> WalletEngineConfig {
        WalletEngineConfig {
            network: ergo_ser::address::NetworkPrefix::Mainnet,
            expose_private_keys: true,
            reemission: None,
            min_relay_fee_nano_erg: 1_000_000,
            max_tx_size_bytes: 98_304,
        }
    }

    #[test]
    fn earlier_rust_legacy_wallet_signs_exports_and_derives_its_persisted_tree() {
        use crate::wallet::tables::WALLET_CHANGE_ADDRESS;
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        // Tables as the earlier Rust node wrote them for this legacy seed:
        // root key, trimmed-master EIP-3 key and that key as change address.
        let mode = "legacy-rust-trimmed-master";
        let eip3 = ergo_wallet::DerivationPath::eip3_first_address();
        let (root, _) = leading_zero_vector(mode, "m");
        let (first, first_secret) = leading_zero_vector(mode, &eip3.to_string());
        track(&db, 0, &root, vec![]);
        track(&db, 1, &first, eip3.components().to_vec());
        let write = db.begin_write().unwrap();
        write
            .open_table(WALLET_CHANGE_ADDRESS)
            .unwrap()
            .insert((), first)
            .unwrap();
        write.commit().unwrap();

        let mut storage = leading_zero_legacy_storage(&dir.path().join("secret"));
        let mut state = crate::state::WalletState::empty(true);
        let network = ergo_ser::address::NetworkPrefix::Mainnet;
        WalletBootService::unlock_and_sync(&mut storage, &mut state, &db, network, "pw").unwrap();
        let storage = RwLock::new(storage);
        let address = ergo_wallet::address::pubkey_to_p2pk_address(&first, network).unwrap();
        let request = ergo_wallet_protocol::scala::admin_advanced::GetPrivateKeyRequest { address };
        let exported =
            get_private_key_impl(&request, &storage, &db, &private_key_config()).unwrap();
        assert_eq!(exported.w, first_secret);

        let tracked: std::collections::BTreeMap<u64, ([u8; 33], Vec<u32>)> = [
            (0, (root, vec![])),
            (1, (first, eip3.components().to_vec())),
        ]
        .into();
        let registry = ergo_wallet::proving::secrets::SecretRegistry::from_master_key(
            &storage.read().unlocked().unwrap().master,
            &tracked,
        )
        .unwrap();
        assert_eq!(
            hex::encode(registry.dlog_secret(&first).unwrap().to_bytes()),
            first_secret
        );

        let state = RwLock::new(state);
        let next = derive_next_key_impl(&storage, &state, &db, &EmptyChain, network).unwrap();
        let seed = {
            let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test-vectors/wallet/leading-zero-master/scala_6_0_6.json"
            )))
            .unwrap();
            hex::decode(fixture["seed"].as_str().unwrap()).unwrap()
        };
        let path: ergo_wallet::DerivationPath = next.derivation_path.parse().unwrap();
        let expected = ergo_wallet::ExtendedSecretKeyLegacy::derive_master_key_legacy_rust(&seed)
            .unwrap()
            .derive_at_path(&path)
            .unwrap()
            .public_key()
            .unwrap()
            .compressed_bytes();
        assert_eq!(
            next.address,
            ergo_wallet::address::pubkey_to_p2pk_address(&expected, network).unwrap()
        );
    }

    #[test]
    fn private_key_export_refuses_a_stored_key_the_secret_does_not_control() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        let eip3 = ergo_wallet::DerivationPath::eip3_first_address();
        let (root, _) = leading_zero_vector("legacy", "m");
        let (first, _) = leading_zero_vector("legacy", &eip3.to_string());
        track(&db, 0, &root, vec![]);
        track(&db, 1, &first, eip3.components().to_vec());
        let mut storage = leading_zero_legacy_storage(&dir.path().join("secret"));
        let network = ergo_ser::address::NetworkPrefix::Mainnet;
        let mut state = crate::state::WalletState::empty(true);
        WalletBootService::unlock_and_sync(&mut storage, &mut state, &db, network, "pw").unwrap();
        // A row that changed after unlock: another tree's key recorded at m/1.
        let (foreign, _) = leading_zero_vector("legacy-rust-trimmed-master", "m/0'");
        track(&db, 7, &foreign, vec![1]);
        let address = ergo_wallet::address::pubkey_to_p2pk_address(&foreign, network).unwrap();
        let request = ergo_wallet_protocol::scala::admin_advanced::GetPrivateKeyRequest { address };
        let error =
            get_private_key_impl(&request, &RwLock::new(storage), &db, &private_key_config())
                .unwrap_err();
        assert!(
            matches!(&error, WalletAdminError::Internal(detail) if detail.contains("tracked key at m/1")),
            "{error:?}"
        );
    }

    #[test]
    fn addresses_follow_scala_storage_order_live_after_reopen_and_on_upgrade() {
        use crate::wallet::tables::WALLET_VISIBLE_ADDRESSES;
        let address = |path: &str| {
            let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../test-vectors/wallet/leading-zero-master/scala_6_0_6.json"
            )))
            .unwrap();
            fixture["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["mode"] == "legacy" && v["path"] == path)
                .unwrap()["address"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let eip3 = ergo_wallet::DerivationPath::eip3_first_address();
        // Scala after a restart or unlock: master, m/1, then the EIP-3 key.
        let scala = vec![address("m"), address("m/1"), address(&eip3.to_string())];
        let network = ergo_ser::address::NetworkPrefix::Mainnet;
        let unlock = |db: &redb::Database, directory: &std::path::Path| {
            let mut storage = leading_zero_legacy_storage(directory);
            let mut state = crate::state::WalletState::empty(true);
            WalletBootService::unlock_and_sync(&mut storage, &mut state, db, network, "pw")
                .unwrap();
            (RwLock::new(storage), RwLock::new(state))
        };

        // Live: deriving m/1 after the EIP-3 key re-sorts the list.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.redb");
        let db = redb::Database::create(&path).unwrap();
        track(&db, 0, &leading_zero_vector("legacy", "m").0, vec![]);
        let first = leading_zero_vector("legacy", &eip3.to_string()).0;
        track(&db, 1, &first, eip3.components().to_vec());
        let (storage, state) = unlock(&db, &dir.path().join("secret"));
        let request = ergo_wallet_protocol::scala::admin_advanced::DeriveKeyRequest {
            derivation_path: "m/1".into(),
        };
        derive_key_impl(&request, &storage, &state, &db, &EmptyChain, network).unwrap();
        assert_eq!(state.read().visible_addresses(), scala);
        drop(db);
        let db = redb::Database::open(&path).unwrap();
        assert_eq!(
            unlock(&db, &dir.path().join("secret"))
                .1
                .read()
                .visible_addresses(),
            scala
        );

        // Upgrade: a list persisted in insertion order is rebuilt at unlock.
        let write = db.begin_write().unwrap();
        {
            let mut visible = write.open_table(WALLET_VISIBLE_ADDRESSES).unwrap();
            visible.retain(|_, _| false).unwrap();
            visible.insert(0, first).unwrap();
            visible
                .insert(1, leading_zero_vector("legacy", "m/1").0)
                .unwrap();
        }
        write.commit().unwrap();
        assert_eq!(
            unlock(&db, &dir.path().join("secret"))
                .1
                .read()
                .visible_addresses(),
            scala
        );
        let read = redb::ReadableDatabase::begin_read(&db).unwrap();
        let reader = crate::wallet::reader::WalletReader::new(&read);
        assert_eq!(reader.visible_pubkeys().unwrap().len(), 3);
    }

    #[test]
    fn derivation_indices_reject_exhaustion_without_wrapping_or_hardening() {
        let prefix = vec![
            44 | 0x8000_0000,
            429 | 0x8000_0000,
            0x8000_0000,
            0,
            0x7fff_ffff,
        ];
        assert!(next_eip3_address_index(0, &[(1, [0; 33], prefix)]).is_err());
        assert!(next_eip3_address_index(u64::MAX, &[]).is_err());
        assert!(next_tracked_index(&[(u64::MAX, [0; 33], vec![])]).is_err());
    }

    #[test]
    fn manual_eip3_derivation_reconciles_next_key_across_reopen() {
        let reference: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/wallet/path-visibility/scala_6_0_6.json"
        )))
        .unwrap();
        let case = reference["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "master-eip3-three")
            .unwrap();
        let expected = case["nextPath"].as_str().unwrap();
        assert_eq!(expected, "m/44'/429'/0'/0/2");
        let dir = tempfile::tempdir().unwrap();
        let database_path = dir.path().join("wallet.redb");
        let db = redb::Database::create(&database_path).unwrap();
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("secret"));
        storage.restore("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", "pw", false).unwrap();
        let mut state = crate::state::WalletState::empty(false);
        let network = ergo_ser::address::NetworkPrefix::Mainnet;
        WalletBootService::unlock_and_sync(&mut storage, &mut state, &db, network, "pw").unwrap();
        let storage = RwLock::new(storage);
        let state = RwLock::new(state);
        let request = ergo_wallet_protocol::scala::admin_advanced::DeriveKeyRequest {
            derivation_path: "m/44'/429'/0'/0/1".into(),
        };
        let manual =
            derive_key_impl(&request, &storage, &state, &db, &EmptyChain, network).unwrap();
        let next = derive_next_key_impl(&storage, &state, &db, &EmptyChain, network).unwrap();
        assert_eq!(next.derivation_path, expected);
        assert_ne!(manual.address, next.address);
        assert_eq!(state.read().visible_addresses().len(), 3);
        let addresses = state.read().visible_addresses().to_vec();
        drop(db);
        let reopened = redb::Database::open(&database_path).unwrap();
        let mut after = crate::state::WalletState::empty(false);
        WalletBootService::unlock_and_sync(
            &mut storage.write(),
            &mut after,
            &reopened,
            network,
            "pw",
        )
        .unwrap();
        assert_eq!(after.visible_addresses(), addresses);
        let after = RwLock::new(after);
        let next = derive_next_key_impl(&storage, &after, &reopened, &EmptyChain, network).unwrap();
        assert_eq!(next.derivation_path, "m/44'/429'/0'/0/3");
    }

    #[test]
    fn persisted_visibility_and_live_hydration_follow_pinned_paths() {
        let reference: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/wallet/path-visibility/scala_6_0_6.json"
        )))
        .unwrap();
        // WalletCache.scala v6.0.5's ordered shape rule, independently of key
        // count: only master followed by an EIP-3 path hides the first key.
        let visible_starts = [0, 0, 1, 1, 0, 1];
        for (case, start) in reference["cases"]
            .as_array()
            .unwrap()
            .iter()
            .zip(visible_starts)
        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("wallet.redb");
            let db = redb::Database::create(&path).unwrap();
            let keys = case["keys"].as_array().unwrap();
            for (index, key) in keys.iter().enumerate() {
                let public_key: [u8; 33] = hex::decode(key["publicKey"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let meta = crate::wallet::types::TrackedPubkeyMeta {
                    derivation_path: key["components"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| u32::try_from(x.as_u64().unwrap()).unwrap())
                        .collect(),
                    derivation_path_label: String::new(),
                    added_at_height: 0,
                };
                // The master need not have storage index zero.
                persist_tracked_pubkey(&db, index as u64 + 10, &public_key, &meta, None).unwrap();
            }
            let expected: Vec<String> = keys
                .iter()
                .skip(start)
                .map(|x| x["address"].as_str().unwrap().to_owned())
                .collect();
            let mut live = crate::state::WalletState::empty(false);
            {
                let read = redb::ReadableDatabase::begin_read(&db).unwrap();
                let reader = crate::wallet::reader::WalletReader::new(&read);
                assert_eq!(reader.visible_pubkeys().unwrap().len(), expected.len());
                live.hydrate_from_reader(&reader, ergo_ser::address::NetworkPrefix::Mainnet)
                    .unwrap();
            }
            assert_eq!(live.visible_addresses(), expected, "{}", case["name"]);
            drop(db);
            let reopened = redb::Database::open(path).unwrap();
            let read = redb::ReadableDatabase::begin_read(&reopened).unwrap();
            let reader = crate::wallet::reader::WalletReader::new(&read);
            let mut after = crate::state::WalletState::empty(false);
            after
                .hydrate_from_reader(&reader, ergo_ser::address::NetworkPrefix::Mainnet)
                .unwrap();
            assert_eq!(after.visible_addresses(), live.visible_addresses());
        }
    }
}

#[cfg(test)]
mod unlock_failure_tests {
    use super::*;
    use crate::wallet::tables::*;
    #[test]
    fn post_decryption_table_and_hydration_errors_relock_the_wallet() {
        for malformed_table in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
            let mut storage = SecretStorage::open(dir.path().join("wallet"));
            storage.restore("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", "pw", false).unwrap();
            let write = db.begin_write().unwrap();
            if malformed_table {
                write
                    .open_table(redb::TableDefinition::<u32, u32>::new(
                        "wallet_tracked_pubkeys",
                    ))
                    .unwrap();
            } else {
                let pk: [u8; 33] = hex::decode(
                    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
                )
                .unwrap()
                .try_into()
                .unwrap();
                write
                    .open_table(WALLET_TRACKED_PUBKEYS)
                    .unwrap()
                    .insert(tracked_pubkey_key(0, &pk), vec![])
                    .unwrap();
                write
                    .open_table(WALLET_VISIBLE_ADDRESSES)
                    .unwrap()
                    .insert(0, [0u8; 33])
                    .unwrap();
            }
            write.commit().unwrap();
            let mut state = WalletState::empty(false);
            let result = WalletBootService::unlock_and_sync(
                &mut storage,
                &mut state,
                &db,
                ergo_ser::address::NetworkPrefix::Mainnet,
                "pw",
            );
            assert!(
                result.is_err(),
                "a post-decryption synchronization step must fail"
            );
            assert!(storage.unlocked().is_none());
            assert_eq!(storage.lock_state(), LockState::Locked);
            assert!(!state.is_unlocked());
        }
    }

    #[test]
    fn unlock_refuses_persisted_keys_the_secret_does_not_derive() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("state.redb")).unwrap();
        let mut storage = SecretStorage::open(dir.path().join("wallet"));
        storage.restore("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", "pw", false).unwrap();
        // Another seed's EIP-3 key (BIP32 vector 1 master) at the EIP-3 path.
        let foreign: [u8; 33] =
            hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
                .unwrap()
                .try_into()
                .unwrap();
        let meta = TrackedPubkeyMeta {
            derivation_path: ergo_wallet::DerivationPath::eip3_first_address()
                .components()
                .to_vec(),
            derivation_path_label: String::new(),
            added_at_height: 0,
        };
        let write = db.begin_write().unwrap();
        write
            .open_table(WALLET_TRACKED_PUBKEYS)
            .unwrap()
            .insert(
                tracked_pubkey_key(1, &foreign),
                bincode::serialize(&meta).unwrap(),
            )
            .unwrap();
        write
            .open_table(WALLET_CHANGE_ADDRESS)
            .unwrap()
            .insert((), foreign)
            .unwrap();
        write.commit().unwrap();
        let mut state = WalletState::empty(false);
        let result = WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &db,
            ergo_ser::address::NetworkPrefix::Mainnet,
            "pw",
        );
        assert!(
            matches!(&result, Err(WalletError::TrackedKeyMismatch(path)) if path == "m/44'/429'/0'/0/0"),
            "{result:?}"
        );
        assert_eq!(storage.lock_state(), LockState::Locked);
        assert!(!state.is_unlocked());
    }

    // ----- error paths -----
}

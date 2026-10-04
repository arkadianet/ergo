//! Derive-key + get-private-key helpers.

use parking_lot::RwLock;
use redb::ReadableDatabase;

use crate::node::wallet_bridge::{ChainStateAccessor, WalletAdminError, WriterConfig};

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
/// corresponding head advance. The next-key path also reconciles that counter
/// with manually tracked paths in the same account. `derive_key_impl` passes
/// `None` because it may derive an unrelated path.
///
/// WALLET_VISIBLE_ADDRESSES is rebuilt using the ordered paths: hide the master
/// only when the next tracked entry has the EIP-3 account prefix.
pub(crate) fn persist_tracked_pubkey(
    db: &redb::Database,
    path_idx: u64,
    pubkey: &[u8; 33],
    meta: &ergo_state::wallet::types::TrackedPubkeyMeta,
    new_derivation_head: Option<u64>,
) -> Result<(), WalletAdminError> {
    use ergo_state::wallet::tables::{
        tracked_pubkey_key, WALLET_TRACKED_PUBKEYS, WALLET_VISIBLE_ADDRESSES,
    };
    use redb::ReadableTable;

    let meta_bytes = bincode::serialize(meta)
        .map_err(|e| WalletAdminError::Internal(format!("bincode TrackedPubkeyMeta: {e}")))?;

    let write_txn =
        ergo_state::begin_write_qr(db).map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    {
        // Insert the new tracked pubkey.
        let mut tracked = write_txn
            .open_table(WALLET_TRACKED_PUBKEYS)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        tracked
            .insert(tracked_pubkey_key(path_idx, pubkey), meta_bytes)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

        // Rebuild visibility from the ordered derivation metadata.
        // We clear first, then reinsert all visible entries. The table is
        // small (typically < 1000 keys), so a full rebuild is safe.
        let all_tracked: Vec<(u64, [u8; 33], Vec<u32>)> = {
            let mut rows = Vec::new();
            for entry in tracked
                .iter()
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            {
                let (k, v) = entry.map_err(|e| WalletAdminError::Internal(e.to_string()))?;
                let key_bytes: [u8; 41] = k.value();
                let (idx, pk) = ergo_state::wallet::tables::parse_tracked_pubkey_key(&key_bytes);
                let row_meta: ergo_state::wallet::types::TrackedPubkeyMeta =
                    bincode::deserialize(v.value().as_slice()).map_err(|e| {
                        WalletAdminError::Internal(format!("bincode TrackedPubkeyMeta read: {e}"))
                    })?;
                rows.push((idx, pk, row_meta.derivation_path));
            }
            rows
        };

        let mut visible = write_txn
            .open_table(WALLET_VISIBLE_ADDRESSES)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

        // Clear all existing visible entries.
        let existing_keys: Vec<u32> = visible
            .iter()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?
            .map(|entry| entry.map(|(k, _)| k.value()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e: redb::StorageError| WalletAdminError::Internal(e.to_string()))?;
        for key in existing_keys {
            visible
                .remove(key)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        }

        for (index, pk) in ergo_wallet::state::visible_pubkeys_with_paths(&all_tracked)
            .into_iter()
            .enumerate()
        {
            let index = u32::try_from(index).map_err(|_| {
                WalletAdminError::Internal("visible wallet index exceeds u32".into())
            })?;
            visible
                .insert(index, pk)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        }

        if let Some(new_head) = new_derivation_head {
            use ergo_state::wallet::tables::WALLET_DERIVATION_HEAD;
            let mut head_tbl = write_txn
                .open_table(WALLET_DERIVATION_HEAD)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
            head_tbl
                .insert((), new_head)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    Ok(())
}

/// `POST /wallet/deriveKey` writer-task implementation.
pub(crate) async fn derive_key_impl(
    request: &ergo_api::wallet::admin_advanced::DeriveKeyRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<ergo_api::wallet::admin_advanced::DeriveKeyResponse, WalletAdminError> {
    use ergo_api::wallet::admin_advanced::DeriveKeyResponse;
    use ergo_wallet::derivation::DerivationPath;

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
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let existing: Vec<(u64, [u8; 33], Vec<u32>)> = wallet_reader
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

    drop(read_txn);

    // Build metadata.
    let meta = ergo_state::wallet::types::TrackedPubkeyMeta {
        derivation_path: path.components().to_vec(),
        derivation_path_label: String::new(),
        added_at_height: chain
            .tip_height()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
    };

    // Persist atomically (WALLET_TRACKED_PUBKEYS + WALLET_VISIBLE_ADDRESSES).
    persist_tracked_pubkey(db, next_idx, &pubkey, &meta, None)?;
    drop(storage_guard);

    // Update in-memory WalletState.
    {
        let mut s = state.write();
        let read = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let reader = ergo_state::wallet::reader::WalletReader::new(&read);
        s.hydrate_from_reader(&reader, network)
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
pub(crate) async fn derive_next_key_impl(
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<ergo_api::wallet::admin_advanced::DeriveNextKeyResponse, WalletAdminError> {
    use ergo_api::wallet::admin_advanced::DeriveNextKeyResponse;
    use ergo_state::wallet::tables::WALLET_DERIVATION_HEAD;
    use ergo_wallet::derivation::{DerivationPath, HARDENED_OFFSET};

    // Require unlocked.
    let storage_guard = storage.read();
    let unlocked = storage_guard.unlocked().ok_or(WalletAdminError::Locked)?;

    // Read WALLET_DERIVATION_HEAD singleton (default 0 if missing).
    let head: u64 = {
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        match read_txn.open_table(WALLET_DERIVATION_HEAD) {
            Ok(tbl) => tbl
                .get(())
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .map(|g| g.value())
                .unwrap_or(0),
            Err(redb::TableError::TableDoesNotExist(_)) => 0,
            Err(e) => return Err(WalletAdminError::Internal(e.to_string())),
        }
    };

    // Read tracked paths before choosing the next address so manual derivation
    // cannot leave the persisted sequential counter behind an existing path.
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let existing: Vec<(u64, [u8; 33], Vec<u32>)> = wallet_reader
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
    let path = DerivationPath::from_components(path_components.clone());
    let path_str = render_derivation_path(&path_components);
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

    drop(read_txn);

    let meta = ergo_state::wallet::types::TrackedPubkeyMeta {
        derivation_path: path.components().to_vec(),
        derivation_path_label: String::new(),
        added_at_height: chain
            .tip_height()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?,
    };

    // Persist WALLET_TRACKED_PUBKEYS + WALLET_VISIBLE_ADDRESSES, shared with
    // derive_key_impl so the two paths can never drift on this logic.
    persist_tracked_pubkey(db, next_idx, &pubkey, &meta, Some(u64::from(new_head)))?;
    drop(storage_guard);

    // Update in-memory WalletState.
    {
        let mut s = state.write();
        let read = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let reader = ergo_state::wallet::reader::WalletReader::new(&read);
        s.hydrate_from_reader(&reader, network)
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
pub(crate) async fn get_private_key_impl(
    request: &ergo_api::wallet::admin_advanced::GetPrivateKeyRequest,
    storage: &RwLock<ergo_wallet::storage::SecretStorage>,
    db: &redb::Database,
    cfg: &WriterConfig,
) -> Result<ergo_api::wallet::admin_advanced::GetPrivateKeyResponse, WalletAdminError> {
    use ergo_api::wallet::admin_advanced::GetPrivateKeyResponse;
    use ergo_wallet::derivation::DerivationPath;

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
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let tracked = wallet_reader
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

    // Derive the scalar; never export one that does not control the address.
    let scalar = unlocked
        .master
        .derive_scalar_for_pubkey(&path, &pubkey)
        .map_err(|e| WalletAdminError::Internal(format!("getPrivateKey: {e}")))?;

    // Encode as 32-byte big-endian hex.
    let scalar_bytes: [u8; 32] = scalar.to_bytes().into();
    let w = hex::encode(scalar_bytes);

    Ok(GetPrivateKeyResponse { w })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_state::wallet::hydration::HydrationSource;

    struct EmptyChain;
    impl ChainStateAccessor for EmptyChain {
        fn wallet_scan_height(&self) -> Result<u32, ergo_state::store::StateError> {
            Ok(0)
        }
        fn tip_height(&self) -> Result<u32, ergo_state::store::StateError> {
            Ok(0)
        }
        fn is_pruned(&self) -> bool {
            false
        }
        fn read_block_at(
            &self,
            _: u32,
        ) -> Result<
            Option<ergo_state::wallet::scan::RescanBlock>,
            ergo_state::wallet::scan::RescanReadError,
        > {
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
        let meta = ergo_state::wallet::types::TrackedPubkeyMeta {
            derivation_path: path,
            derivation_path_label: String::new(),
            added_at_height: 0,
        };
        persist_tracked_pubkey(db, index, pubkey, &meta, None).unwrap();
    }

    fn private_key_config() -> WriterConfig {
        WriterConfig {
            network: ergo_ser::address::NetworkPrefix::Mainnet,
            expose_private_keys: true,
            reemission: None,
            min_relay_fee_nano_erg: 1_000_000,
            max_tx_size_bytes: 98_304,
        }
    }

    #[tokio::test]
    async fn earlier_rust_legacy_wallet_signs_exports_and_derives_its_persisted_tree() {
        use ergo_state::wallet::tables::WALLET_CHANGE_ADDRESS;
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
        let mut state = ergo_wallet::state::WalletState::empty(true);
        let network = ergo_ser::address::NetworkPrefix::Mainnet;
        crate::wallet_boot::WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &db,
            network,
            "pw",
        )
        .unwrap();
        let storage = RwLock::new(storage);
        let address = ergo_wallet::address::pubkey_to_p2pk_address(&first, network).unwrap();
        let request = ergo_api::wallet::admin_advanced::GetPrivateKeyRequest { address };
        let exported = get_private_key_impl(&request, &storage, &db, &private_key_config())
            .await
            .unwrap();
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
        let next = derive_next_key_impl(&storage, &state, &db, &EmptyChain, network)
            .await
            .unwrap();
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

    #[tokio::test]
    async fn private_key_export_refuses_a_stored_key_the_secret_does_not_control() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        let eip3 = ergo_wallet::DerivationPath::eip3_first_address();
        let (root, _) = leading_zero_vector("legacy", "m");
        let (first, _) = leading_zero_vector("legacy", &eip3.to_string());
        track(&db, 0, &root, vec![]);
        track(&db, 1, &first, eip3.components().to_vec());
        let mut storage = leading_zero_legacy_storage(&dir.path().join("secret"));
        let network = ergo_ser::address::NetworkPrefix::Mainnet;
        let mut state = ergo_wallet::state::WalletState::empty(true);
        crate::wallet_boot::WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &db,
            network,
            "pw",
        )
        .unwrap();
        // A row that changed after unlock: another tree's key recorded at m/1.
        let (foreign, _) = leading_zero_vector("legacy-rust-trimmed-master", "m/0'");
        track(&db, 7, &foreign, vec![1]);
        let address = ergo_wallet::address::pubkey_to_p2pk_address(&foreign, network).unwrap();
        let request = ergo_api::wallet::admin_advanced::GetPrivateKeyRequest { address };
        let error =
            get_private_key_impl(&request, &RwLock::new(storage), &db, &private_key_config())
                .await
                .unwrap_err();
        assert!(
            matches!(&error, WalletAdminError::Internal(detail) if detail.contains("tracked key at m/1")),
            "{error:?}"
        );
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

    #[tokio::test]
    async fn manual_eip3_derivation_reconciles_next_key_across_reopen() {
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
        let mut state = ergo_wallet::state::WalletState::empty(false);
        let network = ergo_ser::address::NetworkPrefix::Mainnet;
        crate::wallet_boot::WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &db,
            network,
            "pw",
        )
        .unwrap();
        let storage = RwLock::new(storage);
        let state = RwLock::new(state);
        let request = ergo_api::wallet::admin_advanced::DeriveKeyRequest {
            derivation_path: "m/44'/429'/0'/0/1".into(),
        };
        let manual = derive_key_impl(&request, &storage, &state, &db, &EmptyChain, network)
            .await
            .unwrap();
        let next = derive_next_key_impl(&storage, &state, &db, &EmptyChain, network)
            .await
            .unwrap();
        assert_eq!(next.derivation_path, expected);
        assert_ne!(manual.address, next.address);
        assert_eq!(state.read().visible_addresses().len(), 3);
        let addresses = state.read().visible_addresses().to_vec();
        drop(db);
        let reopened = redb::Database::open(&database_path).unwrap();
        let mut after = ergo_wallet::state::WalletState::empty(false);
        crate::wallet_boot::WalletBootService::unlock_and_sync(
            &mut storage.write(),
            &mut after,
            &reopened,
            network,
            "pw",
        )
        .unwrap();
        assert_eq!(after.visible_addresses(), addresses);
        let after = RwLock::new(after);
        let next = derive_next_key_impl(&storage, &after, &reopened, &EmptyChain, network)
            .await
            .unwrap();
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
                let meta = ergo_state::wallet::types::TrackedPubkeyMeta {
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
            let mut live = ergo_wallet::state::WalletState::empty(false);
            {
                let read = db.begin_read().unwrap();
                let reader = ergo_state::wallet::reader::WalletReader::new(&read);
                assert_eq!(reader.visible_pubkeys().unwrap().len(), expected.len());
                live.hydrate_from_reader(&reader, ergo_ser::address::NetworkPrefix::Mainnet)
                    .unwrap();
            }
            assert_eq!(live.visible_addresses(), expected, "{}", case["name"]);
            drop(db);
            let reopened = redb::Database::open(path).unwrap();
            let read = reopened.begin_read().unwrap();
            let reader = ergo_state::wallet::reader::WalletReader::new(&read);
            let mut after = ergo_wallet::state::WalletState::empty(false);
            after
                .hydrate_from_reader(&reader, ergo_ser::address::NetworkPrefix::Mainnet)
                .unwrap();
            assert_eq!(after.visible_addresses(), live.visible_addresses());
        }
    }
}

//! Derive-key + get-private-key helpers.

use parking_lot::RwLock;
use redb::ReadableDatabase;

use crate::node::wallet_bridge::{ChainStateAccessor, WalletAdminError, WriterConfig};

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
/// corresponding head advance (which would otherwise wedge future
/// `deriveNextKey` calls permanently, since the head is the sole source for
/// the next path and is never independently reconciled against the tracked
/// set). `derive_key_impl` passes `None` — it has no head to advance.
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

    let write_txn = db
        .begin_write()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
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
    let next_idx = existing
        .iter()
        .map(|(idx, _, _)| *idx)
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);

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
/// pubkey without also advancing the head (which would otherwise wedge every
/// future call, since the head is the sole source for the next path).
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

    let new_head = head + 1;

    // Build path: m/44'/429'/0'/0/{new_head}
    // new_head is the non-hardened address index (sequential counter).
    let path_components = vec![
        HARDENED_OFFSET | 44,
        HARDENED_OFFSET | 429,
        HARDENED_OFFSET,
        0u32,
        new_head as u32,
    ];
    let path = DerivationPath::from_components(path_components.clone());
    let path_str = render_derivation_path(&path_components);

    // Dedup check (same as derive_key).
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let existing: Vec<(u64, [u8; 33], Vec<u32>)> = wallet_reader
        .tracked_pubkeys_with_paths()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    for (_, _, existing_path) in &existing {
        if existing_path.as_slice() == path.components() {
            return Err(WalletAdminError::DerivationPathExists);
        }
    }

    let next_idx = existing
        .iter()
        .map(|(idx, _, _)| *idx)
        .max()
        .map(|m| m + 1)
        .unwrap_or(0);

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
    persist_tracked_pubkey(db, next_idx, &pubkey, &meta, Some(new_head))?;
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

    // Derive the scalar.
    let scalar = unlocked.master.derive_scalar_at_path(&path).map_err(|e| {
        WalletAdminError::Internal(format!("getPrivateKey: derivation failed: {e}"))
    })?;

    // Encode as 32-byte big-endian hex.
    let scalar_bytes: [u8; 32] = scalar.to_bytes().into();
    let w = hex::encode(scalar_bytes);

    Ok(GetPrivateKeyResponse { w })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_state::wallet::hydration::HydrationSource;

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

//! Complete master bytes and descendant addresses from pinned Scala 6.0.6.
use ergo_ser::address::NetworkPrefix;
use ergo_wallet::proving::secrets::SecretRegistry;
use ergo_wallet::storage::MasterDerivation;
use ergo_wallet::{DerivationPath, ExtendedSecretKey, ExtendedSecretKeyLegacy, WalletError};

// ----- helpers -----

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../test-vectors/wallet/leading-zero-master/scala_6_0_6.json"
    ))
    .unwrap()
}

/// Unlocked storage for the fixture seed in an encrypted secret file.
fn unlocked_storage(directory: &std::path::Path, use_pre_1627: bool) -> ergo_wallet::SecretStorage {
    let seed = hex::decode(fixture()["seed"].as_str().unwrap()).unwrap();
    let salt = [0x29; 32];
    let iv = [0x39; 12];
    let password = "public-leading-zero-seed-test";
    let key = ergo_wallet::encryption::derive_key_pbkdf2(password.as_bytes(), &salt, 128_000);
    let (ciphertext, tag) = ergo_wallet::encryption::encrypt(&key, &iv, &seed).unwrap();
    let encrypted = serde_json::json!({
        "cipherText": hex::encode(ciphertext), "salt": hex::encode(salt), "iv": hex::encode(iv), "authTag": hex::encode(tag),
        "cipherParams": { "prf": "HmacSHA512", "c": 128000, "dkLen": 256 }, "usePre1627KeyDerivation": use_pre_1627
    });
    std::fs::write(directory.join("public-vector.json"), encrypted.to_string()).unwrap();
    let mut storage = ergo_wallet::SecretStorage::open(directory.to_path_buf());
    storage.unlock(password).unwrap();
    storage
}

/// `(publicKey, secret)` of the fixture vector for `mode` at `path`.
fn vector(mode: &str, path: &str) -> ([u8; 33], String) {
    let fixture = fixture();
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

fn tracked(entries: &[(&str, &str)]) -> Vec<([u8; 33], Vec<u32>)> {
    entries
        .iter()
        .map(|(mode, path)| {
            let parsed: DerivationPath = path.parse().unwrap();
            (vector(mode, path).0, parsed.components().to_vec())
        })
        .collect()
}

// ----- oracle parity -----

#[test]
fn public_master_types_match_scala_leading_zero_seed_and_complete_paths() {
    let fixture = fixture();
    let seed = hex::decode(fixture["seed"].as_str().unwrap()).unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let path: DerivationPath = vector["path"].as_str().unwrap().parse().unwrap();
        let (secret, chain_code, public_key) = match vector["mode"].as_str().unwrap() {
            "modern" => {
                let key = ExtendedSecretKey::derive_master_key(&seed)
                    .unwrap()
                    .derive_at_path(&path)
                    .unwrap();
                (
                    hex::encode(key.secret_bytes()),
                    hex::encode(key.public_key().chain_code()),
                    key.public_key().compressed_bytes(),
                )
            }
            mode => {
                let master = match mode {
                    "legacy" => ExtendedSecretKeyLegacy::derive_master_key(&seed),
                    "legacy-rust-trimmed-master" => {
                        ExtendedSecretKeyLegacy::derive_master_key_legacy_rust(&seed)
                    }
                    _ => panic!("unrecognized fixture mode"),
                }
                .unwrap();
                let key = master.derive_at_path(&path).unwrap();
                (
                    hex::encode(key.secret_bytes()),
                    hex::encode(key.chain_code()),
                    key.public_key().unwrap().compressed_bytes(),
                )
            }
        };
        assert_eq!(secret, vector["secret"], "{vector}");
        assert_eq!(chain_code, vector["chainCode"], "{vector}");
        assert_eq!(hex::encode(public_key), vector["publicKey"], "{vector}");
        assert_eq!(
            ergo_wallet::address::pubkey_to_p2pk_address(&public_key, NetworkPrefix::Mainnet)
                .unwrap(),
            vector["address"],
            "{vector}"
        );
    }
}

#[test]
fn encrypted_legacy_seed_unlock_uses_complete_master_before_eip3_derivation() {
    let temporary = tempfile::tempdir().unwrap();
    let storage = unlocked_storage(temporary.path(), true);
    let path = DerivationPath::eip3_first_address();
    let public_key = storage
        .unlocked()
        .unwrap()
        .master
        .derive_pubkey_at_path(&path)
        .unwrap();
    assert_eq!(public_key, vector("legacy", &path.to_string()).0);
}

// ----- persisted key binding -----

#[test]
fn keys_written_by_earlier_rust_legacy_master_keep_their_derivation() {
    let temporary = tempfile::tempdir().unwrap();
    let mut storage = unlocked_storage(temporary.path(), true);
    let mode = "legacy-rust-trimmed-master";
    let eip3 = DerivationPath::eip3_first_address();
    assert_eq!(
        storage
            .bind_tracked_keys(&tracked(&[(mode, "m"), (mode, "m/44'/429'/0'/0/0")]))
            .unwrap(),
        MasterDerivation::LegacyRustTrimmed
    );
    let master = &storage.unlocked().unwrap().master;
    let (public_key, secret) = vector(mode, &eip3.to_string());
    let scalar = master.derive_scalar_for_pubkey(&eip3, &public_key).unwrap();
    assert_eq!(hex::encode(scalar.to_bytes()), secret);
    let hardened: DerivationPath = "m/0'".parse().unwrap();
    assert_eq!(
        master.derive_pubkey_at_path(&hardened).unwrap(),
        vector(mode, "m/0'").0
    );
    // New addresses continue the same tree.
    let next: DerivationPath = "m/44'/429'/0'/0/1".parse().unwrap();
    let earlier = ExtendedSecretKeyLegacy::derive_master_key_legacy_rust(
        &hex::decode(fixture()["seed"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        master.derive_pubkey_at_path(&next).unwrap(),
        earlier
            .derive_at_path(&next)
            .unwrap()
            .public_key()
            .unwrap()
            .compressed_bytes()
    );
}

#[test]
fn scala_legacy_keys_bind_to_the_complete_master() {
    let temporary = tempfile::tempdir().unwrap();
    let mut storage = unlocked_storage(temporary.path(), true);
    let keys = tracked(&[("legacy", "m"), ("legacy", "m/44'/429'/0'/0/0")]);
    assert_eq!(
        storage.bind_tracked_keys(&keys).unwrap(),
        MasterDerivation::Standard
    );
    let eip3 = DerivationPath::eip3_first_address();
    assert_eq!(
        storage
            .unlocked()
            .unwrap()
            .master
            .derive_pubkey_at_path(&eip3)
            .unwrap(),
        keys[1].0
    );
}

#[test]
fn keys_no_single_derivation_reproduces_are_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let mut storage = unlocked_storage(temporary.path(), true);
    let mixed = tracked(&[
        ("legacy-rust-trimmed-master", "m/44'/429'/0'/0/0"),
        ("legacy", "m/0'"),
    ]);
    assert!(matches!(
        storage.bind_tracked_keys(&mixed),
        Err(WalletError::TrackedKeyMismatch(path)) if path == "m/44'/429'/0'/0/0"
    ));
    let modern = tempfile::tempdir().unwrap();
    let mut storage = unlocked_storage(modern.path(), false);
    let earlier = tracked(&[("legacy-rust-trimmed-master", "m/44'/429'/0'/0/0")]);
    assert!(matches!(
        storage.bind_tracked_keys(&earlier),
        Err(WalletError::TrackedKeyMismatch(_))
    ));
}

#[test]
fn registry_refuses_secrets_that_do_not_control_stored_keys() {
    let temporary = tempfile::tempdir().unwrap();
    let storage = unlocked_storage(temporary.path(), true);
    let master = &storage.unlocked().unwrap().master;
    let mut stored = std::collections::BTreeMap::new();
    let (pubkey, path) = tracked(&[("legacy-rust-trimmed-master", "m/44'/429'/0'/0/0")])
        .pop()
        .unwrap();
    stored.insert(1, (pubkey, path));
    assert!(matches!(
        SecretRegistry::from_master_key(master, &stored),
        Err(WalletError::TrackedKeyMismatch(path)) if path == "m/44'/429'/0'/0/0"
    ));
    let eip3 = DerivationPath::eip3_first_address();
    let (legacy, secret) = vector("legacy", &eip3.to_string());
    stored.insert(1, (legacy, eip3.components().to_vec()));
    let registry = SecretRegistry::from_master_key(master, &stored).unwrap();
    assert_eq!(
        hex::encode(registry.dlog_secret(&legacy).unwrap().to_bytes()),
        secret
    );
}

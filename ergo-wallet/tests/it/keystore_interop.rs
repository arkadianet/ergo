//! Published Appkit 6.0.1 AES/JsonSecretStorage oracle; see the regeneration script.

use ergo_wallet::encryption::{derive_key_pbkdf2_with_prf, encrypt, Pbkdf2Prf};
use ergo_wallet::error::WalletError;
use ergo_wallet::storage::{EncryptedSecret, SecretStorage};
use serde::Deserialize;

#[derive(Deserialize)]
struct Oracle {
    mnemonic: String,
    password: String,
    seed: String,
    eip3_public_key: String,
    legacy_eip3_public_key: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    prf: String,
    derived_key: String,
    master_public_key: String,
    encrypted_secret: EncryptedSecret,
}

// ----- helpers -----

fn oracle() -> Oracle {
    serde_json::from_str(include_str!(
        "../../../test-vectors/scala/wallet/keystore_appkit_6_0_1.json"
    ))
    .unwrap()
}

fn write_secret(secret: &EncryptedSecret) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oracle.json");
    std::fs::write(&path, serde_json::to_vec(secret).unwrap()).unwrap();
    (dir, path)
}

// ----- error paths -----

#[test]
fn keystore_wrong_password_and_tampering_fail_authentication() {
    let oracle = oracle();
    for vector in oracle.vectors {
        for corruption in ["password", "cipherText", "authTag"] {
            let mut secret = vector.encrypted_secret.clone();
            let password = if corruption == "password" {
                "incorrect password"
            } else {
                let field = if corruption == "cipherText" {
                    &mut secret.cipher_text
                } else {
                    &mut secret.auth_tag
                };
                let mut bytes = hex::decode(&*field).unwrap();
                bytes[0] ^= 1;
                *field = hex::encode(bytes);
                &oracle.password
            };
            let (dir, path) = write_secret(&secret);
            let before = std::fs::read(&path).unwrap();
            let mut storage = SecretStorage::open(dir.path().to_path_buf());
            assert!(matches!(
                storage.unlock(password),
                Err(WalletError::Decryption)
            ));
            assert!(storage.unlocked().is_none());
            assert_eq!(std::fs::read(path).unwrap(), before);
        }
    }
}

#[test]
fn keystore_unsupported_cipher_parameters_are_rejected() {
    let oracle = oracle();
    for parameter in ["prf", "dkLen", "c", "algorithm", "mode"] {
        let mut secret = oracle.vectors[0].encrypted_secret.clone();
        match parameter {
            "prf" => secret.cipher_params.prf = "HmacSHA1".to_string(),
            "dkLen" => secret.cipher_params.dk_len = 128,
            "c" => secret.cipher_params.c = 0,
            "algorithm" => secret.cipher_params.encryption_algorithm = "DES".to_string(),
            "mode" => secret.cipher_params.encryption_mode = "CBC".to_string(),
            _ => unreachable!(),
        }
        let (dir, _) = write_secret(&secret);
        let mut storage = SecretStorage::open(dir.path().to_path_buf());
        assert!(matches!(
            storage.unlock(&oracle.password),
            Err(WalletError::SecretFile(_))
        ));
        assert!(storage.unlocked().is_none());
    }
}

// ----- oracle parity -----

#[test]
fn pbkdf2_both_prfs_match_jvm_unicode_password_vectors() {
    let oracle = oracle();
    for vector in &oracle.vectors {
        let salt = hex::decode(&vector.encrypted_secret.salt).unwrap();
        let key = derive_key_pbkdf2_with_prf(
            oracle.password.as_bytes(),
            &salt,
            vector.encrypted_secret.cipher_params.c,
            Pbkdf2Prf::from_name(&vector.prf).unwrap(),
        );
        assert_eq!(hex::encode(key.as_slice()), vector.derived_key);
    }
}

#[test]
fn scala_keystore_field_layout_matches_reference_aes_output() {
    let oracle = oracle();
    let seed = hex::decode(&oracle.seed).unwrap();
    for vector in &oracle.vectors {
        let secret = &vector.encrypted_secret;
        let salt = hex::decode(&secret.salt).unwrap();
        let iv: [u8; 12] = hex::decode(&secret.iv).unwrap().try_into().unwrap();
        let key = derive_key_pbkdf2_with_prf(
            oracle.password.as_bytes(),
            &salt,
            secret.cipher_params.c,
            Pbkdf2Prf::from_name(&vector.prf).unwrap(),
        );
        let (ciphertext, prefix) = encrypt(&key, &iv, &seed).unwrap();
        assert_eq!(hex::encode(ciphertext), secret.cipher_text);
        assert_eq!(hex::encode(prefix), secret.auth_tag);
    }
}

#[test]
fn scala_wallet_imports_both_prfs_without_modifying_the_file() {
    let oracle = oracle();
    for vector in &oracle.vectors {
        // Preserve the reference JSON, which has no algorithm/mode fields.
        let raw: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/scala/wallet/keystore_appkit_6_0_1.json"
        ))
        .unwrap();
        let reference = raw["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["prf"] == vector.prf)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reference.json");
        let bytes = serde_json::to_vec(&reference["encrypted_secret"]).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let mut storage = SecretStorage::open(dir.path().to_path_buf());
        storage.unlock(&oracle.password).unwrap();
        assert!(storage.check_seed(&oracle.mnemonic, ""));
        assert_eq!(
            hex::encode(storage.unlocked().unwrap().master.master_pubkey().unwrap()),
            vector.master_public_key
        );
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn legacy_rust_sha512_wallet_remains_readable_without_rewriting() {
    let oracle = oracle();
    let vector = oracle
        .vectors
        .iter()
        .find(|v| v.prf == "HmacSHA512")
        .unwrap();
    let mut secret = vector.encrypted_secret.clone();
    // Repartition the independently produced JVM GCM output into the
    // trailing-tag layout written by older Rust versions.
    let mut output = hex::decode(&secret.auth_tag).unwrap();
    output.extend_from_slice(&hex::decode(&secret.cipher_text).unwrap());
    secret.cipher_text = hex::encode(&output[..output.len() - 16]);
    secret.auth_tag = hex::encode(&output[output.len() - 16..]);
    let (dir, path) = write_secret(&secret);
    let before = std::fs::read(&path).unwrap();
    let mut storage = SecretStorage::open(dir.path().to_path_buf());
    storage.unlock(&oracle.password).unwrap();
    assert!(storage.check_seed(&oracle.mnemonic, ""));
    assert_eq!(
        hex::encode(storage.unlocked().unwrap().master.master_pubkey().unwrap()),
        vector.master_public_key
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn new_wallet_uses_appkit_defaults_and_reference_seed() {
    let oracle = oracle();
    let dir = tempfile::tempdir().unwrap();
    let mut storage = SecretStorage::open(dir.path().to_path_buf());
    storage
        .restore(&oracle.mnemonic, "", &oracle.password, false)
        .unwrap();
    let path = SecretStorage::find_secret_file(dir.path()).unwrap();
    let secret: EncryptedSecret = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(secret.cipher_params.prf, "HmacSHA256");
    assert_eq!(secret.cipher_params.c, 128000);
    assert_eq!(secret.cipher_params.dk_len, 256);
    let key = derive_key_pbkdf2_with_prf(
        oracle.password.as_bytes(),
        &hex::decode(secret.salt).unwrap(),
        secret.cipher_params.c,
        Pbkdf2Prf::HmacSha256,
    );
    let iv = hex::decode(secret.iv).unwrap().try_into().unwrap();
    let prefix = hex::decode(secret.auth_tag).unwrap().try_into().unwrap();
    let seed = ergo_wallet::encryption::decrypt(
        &key,
        &iv,
        &hex::decode(secret.cipher_text).unwrap(),
        &prefix,
    )
    .unwrap();
    assert_eq!(hex::encode(seed.as_slice()), oracle.seed);
}

#[test]
fn legacy_export_preserves_seed_derivation_mode_and_source_bytes() {
    let oracle = oracle();
    let legacy = oracle
        .vectors
        .iter()
        .find(|v| v.prf == "HmacSHA512")
        .unwrap();
    for pre_1627 in [false, true] {
        let mut secret = legacy.encrypted_secret.clone();
        let mut output = hex::decode(&secret.auth_tag).unwrap();
        output.extend_from_slice(&hex::decode(&secret.cipher_text).unwrap());
        secret.cipher_text = hex::encode(&output[..output.len() - 16]);
        secret.auth_tag = hex::encode(&output[output.len() - 16..]);
        secret.use_pre_1627_key_derivation = pre_1627;
        let (source_dir, source) = write_secret(&secret);
        let source_before = std::fs::read(&source).unwrap();
        let mut original = SecretStorage::open(source_dir.path().to_path_buf());
        original.unlock(&oracle.password).unwrap();
        let path = ergo_wallet::DerivationPath::eip3_first_address();
        let expected_pk = original
            .unlocked()
            .unwrap()
            .master
            .derive_pubkey_at_path(&path)
            .unwrap();
        assert_eq!(
            hex::encode(expected_pk),
            if pre_1627 {
                &oracle.legacy_eip3_public_key
            } else {
                &oracle.eip3_public_key
            }
            .as_str()
        );
        let output_dir = tempfile::tempdir().unwrap();
        let exported =
            SecretStorage::export_for_appkit(&source, output_dir.path(), &oracle.password).unwrap();
        let copy: EncryptedSecret =
            serde_json::from_slice(&std::fs::read(&exported).unwrap()).unwrap();
        assert_eq!(copy.cipher_params.prf, "HmacSHA256");
        assert_eq!(copy.use_pre_1627_key_derivation, pre_1627);
        assert_ne!(copy.salt, secret.salt);
        assert_ne!(copy.iv, secret.iv);
        let mut restored = SecretStorage::open(output_dir.path().to_path_buf());
        restored.unlock(&oracle.password).unwrap();
        assert!(restored.check_seed(&oracle.mnemonic, ""));
        assert_eq!(
            restored
                .unlocked()
                .unwrap()
                .master
                .derive_pubkey_at_path(&path)
                .unwrap(),
            expected_pk
        );
        assert_eq!(std::fs::read(&source).unwrap(), source_before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(exported).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn keystore_export_wrong_password_or_nonempty_destination_leaves_files_unchanged() {
    let oracle = oracle();
    let (source_dir, source) = write_secret(&oracle.vectors[0].encrypted_secret);
    let before = std::fs::read(&source).unwrap();
    let destination = source_dir.path().join("new-wallet");
    assert!(matches!(
        SecretStorage::export_for_appkit(&source, &destination, "wrong"),
        Err(WalletError::Decryption)
    ));
    assert!(!destination.exists());
    assert!(matches!(
        SecretStorage::export_for_appkit(&source, source_dir.path(), &oracle.password),
        Err(WalletError::SecretFile(_))
    ));
    assert_eq!(std::fs::read(&source).unwrap(), before);
}

#[cfg(feature = "cli")]
#[test]
fn cli_export_keystore_reads_password_from_stdin_and_retains_reference_key() {
    let oracle = oracle();
    let legacy = oracle
        .vectors
        .iter()
        .find(|v| v.prf == "HmacSHA512")
        .unwrap();
    let (source_dir, source) = write_secret(&legacy.encrypted_secret);
    let output_dir = source_dir.path().join("appkit");
    assert_cmd::Command::cargo_bin("ergo-wallet")
        .unwrap()
        .args(["export-keystore", "--keystore"])
        .arg(&source)
        .arg("--output-dir")
        .arg(&output_dir)
        .args(["--password-file", "-"])
        .write_stdin(format!("{}\n", oracle.password))
        .assert()
        .success();
    let mut exported = SecretStorage::open(output_dir);
    exported.unlock(&oracle.password).unwrap();
    assert_eq!(
        hex::encode(exported.unlocked().unwrap().master.master_pubkey().unwrap()),
        legacy.master_public_key
    );
}

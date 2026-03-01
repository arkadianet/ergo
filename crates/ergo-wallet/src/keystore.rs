//! Encrypted keystore for wallet mnemonic phrases.
//!
//! Stores a BIP-39 mnemonic encrypted with AES-256-GCM. The AES key is derived
//! from the user's password via PBKDF2-HMAC-SHA256 (128 000 iterations).

use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ergo_lib::wallet::mnemonic_generator::{Language, MnemonicGenerator};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PBKDF2 iteration count.
const PBKDF2_ITERATIONS: u32 = 128_000;

/// Derived key length in bytes (AES-256).
const DK_LEN: usize = 32;

/// Salt length in bytes.
const SALT_LEN: usize = 32;

/// AES-GCM nonce (IV) length in bytes.
const NONCE_LEN: usize = 12;

/// BIP-39 entropy strength for 24-word mnemonics.
const MNEMONIC_STRENGTH_256: u32 = 256;

/// Keystore file name inside the wallet directory.
const KEYSTORE_FILE: &str = "wallet.json";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by [`Keystore`] operations.
#[derive(Error, Debug)]
pub enum KeystoreError {
    /// The keystore file already exists.
    #[error("keystore file already exists")]
    AlreadyExists,

    /// The keystore file was not found.
    #[error("keystore file not found")]
    NotFound,

    /// Decryption failed (wrong password or corrupted data).
    #[error("decryption failed (wrong password or corrupted data)")]
    DecryptionFailed,

    /// Mnemonic generation failed.
    #[error("mnemonic generation error: {0}")]
    MnemonicGeneration(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization / deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Hex decoding error.
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

// ---------------------------------------------------------------------------
// On-disk JSON schema
// ---------------------------------------------------------------------------

/// Parameters stored alongside the ciphertext so the file is self-describing.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct CipherParams {
    prf: String,
    c: u32,
    dk_len: u32,
}

/// Top-level JSON written to `wallet.json`.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct KeystoreFile {
    cipher_text: String,
    salt: String,
    iv: String,
    cipher_params: CipherParams,
}

// ---------------------------------------------------------------------------
// Keystore
// ---------------------------------------------------------------------------

/// An encrypted keystore backed by a JSON file on disk.
///
/// The keystore encrypts a BIP-39 mnemonic phrase using AES-256-GCM.
/// The AES key is derived from the user's password with PBKDF2-HMAC-SHA256.
pub struct Keystore {
    path: PathBuf,
}

impl Keystore {
    /// Create a new `Keystore` that will read / write `{dir}/wallet.json`.
    pub fn new(dir: &Path) -> Self {
        Self {
            path: dir.join(KEYSTORE_FILE),
        }
    }

    /// Returns `true` if the keystore file exists on disk.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Initialise the keystore with a freshly generated 24-word BIP-39 mnemonic.
    ///
    /// The mnemonic is encrypted with `password` and persisted to disk.
    /// Returns the generated mnemonic phrase.
    ///
    /// # Errors
    /// - [`KeystoreError::AlreadyExists`] if the keystore file already exists.
    pub fn init(&self, password: &str) -> Result<String, KeystoreError> {
        if self.exists() {
            return Err(KeystoreError::AlreadyExists);
        }

        let generator = MnemonicGenerator::new(Language::English, MNEMONIC_STRENGTH_256)
            .map_err(|e| KeystoreError::MnemonicGeneration(e.to_string()))?;
        let mnemonic = generator.generate();

        self.save_encrypted(password, &mnemonic)?;
        Ok(mnemonic)
    }

    /// Restore the keystore from an existing mnemonic phrase.
    ///
    /// The mnemonic is encrypted with `password` and persisted to disk.
    ///
    /// # Errors
    /// - [`KeystoreError::AlreadyExists`] if the keystore file already exists.
    pub fn restore(&self, password: &str, mnemonic: &str) -> Result<(), KeystoreError> {
        if self.exists() {
            return Err(KeystoreError::AlreadyExists);
        }

        self.save_encrypted(password, mnemonic)?;
        Ok(())
    }

    /// Unlock the keystore: decrypt and return the mnemonic phrase.
    ///
    /// # Errors
    /// - [`KeystoreError::NotFound`] if the keystore file does not exist.
    /// - [`KeystoreError::DecryptionFailed`] if the password is wrong.
    pub fn unlock(&self, password: &str) -> Result<String, KeystoreError> {
        if !self.exists() {
            return Err(KeystoreError::NotFound);
        }

        let data = std::fs::read_to_string(&self.path)?;
        let file: KeystoreFile = serde_json::from_str(&data)?;

        let salt = hex::decode(&file.salt)?;
        let nonce_bytes = hex::decode(&file.iv)?;
        let ciphertext_with_tag = hex::decode(&file.cipher_text)?;

        // Derive AES key from password + salt.
        let key = derive_key(password, &salt);

        // Decrypt.
        let cipher = Aes256Gcm::new_from_slice(&key).expect("key length is always 32 bytes");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext_with_tag.as_ref())
            .map_err(|_| KeystoreError::DecryptionFailed)?;

        String::from_utf8(plaintext).map_err(|_| KeystoreError::DecryptionFailed)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Encrypt `mnemonic` with `password` and write the keystore file.
    fn save_encrypted(&self, password: &str, mnemonic: &str) -> Result<(), KeystoreError> {
        let mut rng = rand::thread_rng();

        // Random salt.
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);

        // Random nonce.
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);

        // Derive AES key.
        let key = derive_key(password, &salt);

        // Encrypt.
        let cipher = Aes256Gcm::new_from_slice(&key).expect("key length is always 32 bytes");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext_with_tag = cipher
            .encrypt(nonce, mnemonic.as_bytes())
            .expect("encryption should not fail with valid key/nonce");

        // Build the JSON structure.
        let keystore_file = KeystoreFile {
            cipher_text: hex::encode(&ciphertext_with_tag),
            salt: hex::encode(salt),
            iv: hex::encode(nonce_bytes),
            cipher_params: CipherParams {
                prf: "HmacSHA256".to_string(),
                c: PBKDF2_ITERATIONS,
                dk_len: DK_LEN as u32,
            },
        };

        let json = serde_json::to_string_pretty(&keystore_file)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }
}

/// Derive a 32-byte AES key from a password and salt using PBKDF2-HMAC-SHA256.
fn derive_key(password: &str, salt: &[u8]) -> [u8; DK_LEN] {
    let mut key = [0u8; DK_LEN];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_creates_keystore_file() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path());

        assert!(!ks.exists());
        let mnemonic = ks.init("test-password").unwrap();
        assert!(ks.exists());

        // BIP-39 24-word mnemonic.
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(
            word_count, 24,
            "expected 24-word mnemonic, got {word_count}"
        );
    }

    #[test]
    fn init_fails_if_already_exists() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path());

        ks.init("pw").unwrap();
        let err = ks.init("pw").unwrap_err();
        assert!(
            matches!(err, KeystoreError::AlreadyExists),
            "expected AlreadyExists, got {err:?}"
        );
    }

    #[test]
    fn unlock_returns_mnemonic() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path());

        let mnemonic = ks.init("secret").unwrap();
        let unlocked = ks.unlock("secret").unwrap();
        assert_eq!(mnemonic, unlocked);
    }

    #[test]
    fn unlock_wrong_password_fails() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path());

        ks.init("correct-password").unwrap();
        let err = ks.unlock("wrong-password").unwrap_err();
        assert!(
            matches!(err, KeystoreError::DecryptionFailed),
            "expected DecryptionFailed, got {err:?}"
        );
    }

    #[test]
    fn restore_and_unlock() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path());

        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon art";

        ks.restore("pw", phrase).unwrap();
        assert!(ks.exists());

        let unlocked = ks.unlock("pw").unwrap();
        assert_eq!(unlocked, phrase);
    }

    #[test]
    fn unlock_nonexistent_fails() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path());

        let err = ks.unlock("any-password").unwrap_err();
        assert!(
            matches!(err, KeystoreError::NotFound),
            "expected NotFound, got {err:?}"
        );
    }

    #[test]
    fn restore_fails_if_already_exists() {
        let dir = TempDir::new().unwrap();
        let ks = Keystore::new(dir.path());

        ks.init("pw").unwrap();
        let err = ks.restore("pw", "some mnemonic").unwrap_err();
        assert!(
            matches!(err, KeystoreError::AlreadyExists),
            "expected AlreadyExists, got {err:?}"
        );
    }
}

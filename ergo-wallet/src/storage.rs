//! Encrypted secret-file storage (Scala-compatible).
//!
//! On-disk format at `<data_dir>/wallet/<uuid>.json` exactly matches
//! Scala `JsonSecretStorage`:
//! - filename: `UUID.nameUUIDFromBytes(cipherText).toString + ".json"`
//!   (deterministic; two wallets with the same ciphertext produce the
//!   same filename — impossible in practice given random IVs)
//! - directory-scan rule: if exactly one file in `<data_dir>/wallet/`,
//!   load any name; if multiple files, filter to `.json` and load first.
//! - wire shape: see `EncryptedSecret` struct below.
//! - `usePre1627KeyDerivation` defaults to `true` when MISSING (tier-1
//!   wallet-import compatibility for pre-Sigma-5.0 secret files).

use serde::{Deserialize, Serialize};

/// AES-GCM cipher parameters embedded in the encrypted secret file.
/// Field names match Scala `EncryptedSecret.scala:37-42` camelCase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    /// PRF used for PBKDF2 — always `"HmacSHA512"` for Scala parity.
    pub prf: String,
    /// PBKDF2 iteration count. Scala default = 128_000.
    pub c: u32,
    /// Derived-key length in BITS (not bytes). Scala = 256.
    #[serde(rename = "dkLen")]
    pub dk_len: u32,
    /// Cipher algorithm. Always `"AES"`.
    #[serde(rename = "encryptionAlgorithm")]
    pub encryption_algorithm: String,
    /// Cipher mode. Always `"GCM"`.
    #[serde(rename = "encryptionMode")]
    pub encryption_mode: String,
}

impl CipherParams {
    /// Scala-default parameters: PBKDF2-HMAC-SHA512 128k iterations,
    /// AES-256-GCM.
    pub fn scala_default() -> Self {
        Self {
            prf: "HmacSHA512".to_string(),
            c: 128_000,
            dk_len: 256,
            encryption_algorithm: "AES".to_string(),
            encryption_mode: "GCM".to_string(),
        }
    }
}

/// The on-disk encrypted secret file. All byte fields hex-encoded
/// (base16 lowercase, matching Scala `Base16.encode` / `Hex.encode`).
///
/// Field name order matters for stable JSON serialization across
/// Scala / Rust implementations: serde respects struct field order
/// by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    /// AES-256-GCM ciphertext (excluding auth tag). Hex-encoded.
    #[serde(rename = "cipherText")]
    pub cipher_text: String,
    /// PBKDF2 salt. Hex-encoded.
    pub salt: String,
    /// AES-GCM IV (96 bits / 12 bytes). Hex-encoded.
    pub iv: String,
    /// AES-GCM authentication tag (128 bits / 16 bytes). Hex-encoded.
    #[serde(rename = "authTag")]
    pub auth_tag: String,
    /// PBKDF2 + AES-GCM parameters.
    #[serde(rename = "cipherParams")]
    pub cipher_params: CipherParams,
    /// Pre-1627 derivation switch (tier-1 wallet-import compatibility).
    /// Missing field deserializes to `true` — matching Scala
    /// `JsonSecretStorageSpec.scala:80` ("legacy wallets predate the
    /// field; defaulting to `true` is the only safe option").
    #[serde(rename = "usePre1627KeyDerivation", default = "default_use_pre_1627")]
    pub use_pre_1627_key_derivation: bool,
}

/// Default for missing `usePre1627KeyDerivation` field. Tier-1
/// invariant: legacy wallets predate the field, so `true` is the safe
/// default. Anyone restoring from a pre-2021 Scala wallet file relies
/// on this.
fn default_use_pre_1627() -> bool {
    true
}

/// Compute the filename UUID for an encrypted secret file. Matches
/// Java `UUID.nameUUIDFromBytes(cipherText)` (NOT RFC 4122 v3 — Java's
/// helper does raw MD5 over the input with version/variant patching,
/// without prefixing a namespace UUID). Scala
/// `JsonSecretStorage.scala:102-105` uses this exact form.
///
/// Reference: OpenJDK UUID.java:155 (nameUUIDFromBytes implementation).
///
/// The deterministic naming is a Scala convention; two wallets with
/// the same ciphertext would produce the same filename (impossible
/// in practice given random IVs make ciphertexts statistically
/// unique).
pub fn uuid_from_ciphertext(cipher_text: &[u8]) -> uuid::Uuid {
    // md5 v0.7 exposes `md5::compute(&[u8]) -> md5::Digest` where
    // `Digest` derefs to `[u8; 16]`.
    let mut bytes: [u8; 16] = *md5::compute(cipher_text);
    // Java UUID.nameUUIDFromBytes post-processing:
    bytes[6] &= 0x0f; // clear version
    bytes[6] |= 0x30; // set version = 3
    bytes[8] &= 0x3f; // clear variant
    bytes[8] |= 0x80; // set variant = 10 (IETF)
    uuid::Uuid::from_bytes(bytes)
}

/// Convenience: build the `<uuid>.json` filename for an encrypted
/// secret with the given ciphertext.
pub fn filename_for_ciphertext(cipher_text: &[u8]) -> String {
    format!("{}.json", uuid_from_ciphertext(cipher_text))
}

use crate::error::WalletError;
use crate::extended_key::ExtendedSecretKey;
use std::path::{Path, PathBuf};

/// In-memory state of the secret storage. The transition diagram:
///
/// ```text
/// Uninitialized -- init() / restore() --> Locked
/// Locked        -- unlock(password)   --> Unlocked
/// Unlocked      -- lock()             --> Locked
/// ```
///
/// (No transition back to `Uninitialized` — once the file is on disk,
/// the only ways to "uninitialize" are to delete the file or move it
/// out of `secret_dir`. Both are administrative actions outside the
/// wallet's API.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// No secret file exists at `secret_dir`.
    Uninitialized,
    /// Secret file exists; master key NOT loaded in memory.
    Locked,
    /// Secret file exists; master key IS loaded (kept in `SecretStorage::unlocked`).
    Unlocked,
}

/// Persistent wallet secret storage. Owns the secret-file directory
/// and the in-memory unlocked secret (if any).
///
/// Single-instance pattern: one `SecretStorage` per node process.
/// Concurrent access is mediated by a `Mutex<SecretStorage>` at the
/// integration layer (`ergo-node`).
pub struct SecretStorage {
    /// Directory holding `<uuid>.json` secret files. Per Scala
    /// `JsonSecretStorage.scala:133-144`: load the first `.json` file
    /// in this dir when multiple exist; load any file when one exists.
    secret_dir: PathBuf,
    /// The in-memory unlocked master key (when `LockState::Unlocked`).
    /// `Zeroizing` ensures the secret bytes are zeroed when this field
    /// gets replaced (e.g., on `lock()` setting back to `None`).
    unlocked: Option<UnlockedSecret>,
    /// The most-recently-seen secret file. Cached at boot to short-
    /// circuit repeated directory scans.
    cached_secret_file: Option<EncryptedSecret>,
}

/// Variant of the in-memory unlocked master key. Pre-1627 wallets
/// MUST use the legacy variant: `ExtendedSecretKeyLegacy` stores
/// the secret as variable-length bytes (matching Scala's
/// `BigIntegers.asUnsignedByteArray` behavior), which is
/// load-bearing for descendant derivations per Ergo issue #1627.
/// Modern wallets use the fixed-width post-1627 type.
#[derive(zeroize::ZeroizeOnDrop)]
pub enum UnlockedMaster {
    Modern(ExtendedSecretKey),
    Legacy(crate::extended_key::ExtendedSecretKeyLegacy),
}

impl UnlockedMaster {
    /// Walk a [`DerivationPath`] in the appropriate mode. Returns
    /// the leaf's compressed-SEC1 public key bytes.
    pub fn derive_pubkey_at_path(
        &self,
        path: &crate::derivation::DerivationPath,
    ) -> Result<[u8; 33], WalletError> {
        match self {
            Self::Modern(m) => Ok(m.derive_at_path(path)?.public_key().compressed_bytes()),
            Self::Legacy(m) => Ok(m.derive_at_path(path)?.public_key()?.compressed_bytes()),
        }
    }

    /// The master pubkey (root of the derivation tree).
    pub fn master_pubkey(&self) -> Result<[u8; 33], WalletError> {
        match self {
            Self::Modern(m) => Ok(m.public_key().compressed_bytes()),
            Self::Legacy(m) => Ok(m.public_key()?.compressed_bytes()),
        }
    }

    /// Derive the secp256k1 scalar (secret) at the given path.
    ///
    /// Used by `SecretRegistry::from_master_key` to pre-derive each tracked
    /// pubkey's leaf secret at unlock time. The returned scalar is the
    /// private key — treat as secret material.
    pub fn derive_scalar_at_path(
        &self,
        path: &crate::derivation::DerivationPath,
    ) -> Result<k256::Scalar, WalletError> {
        use k256::elliptic_curve::ops::Reduce;
        let bytes: [u8; 32] = match self {
            UnlockedMaster::Modern(esk) => {
                let leaf = esk.derive_at_path(path)?;
                leaf.secret_bytes()
            }
            UnlockedMaster::Legacy(esk) => {
                let leaf = esk.derive_at_path(path)?;
                // Variable-length secret: left-pad to 32 bytes.
                let mut padded = [0u8; 32];
                let sb = leaf.secret_bytes();
                let offset = 32 - sb.len().min(32);
                padded[offset..].copy_from_slice(&sb[sb.len().saturating_sub(32)..]);
                padded
            }
        };
        let wide = k256::U256::from_be_slice(&bytes);
        Ok(<k256::Scalar as Reduce<k256::U256>>::reduce(wide))
    }
}

/// In-memory unlocked secret state. Held only while `LockState ==
/// Unlocked`. Contains the master extended secret key (in either
/// post-1627 or pre-1627 form) plus the `usePre1627KeyDerivation`
/// flag for routing.
///
/// `ZeroizeOnDrop` wipes the master key bytes when this struct is
/// dropped (which happens on `SecretStorage::lock()` setting
/// `unlocked = None`).
#[derive(zeroize::ZeroizeOnDrop)]
pub struct UnlockedSecret {
    pub master: UnlockedMaster,
    #[zeroize(skip)]
    pub use_pre_1627: bool,
}

impl std::fmt::Debug for UnlockedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedSecret")
            .field("master", &"[REDACTED]")
            .field("use_pre_1627", &self.use_pre_1627)
            .finish()
    }
}

impl SecretStorage {
    /// Open the storage at the given secret directory. Does NOT load
    /// or unlock the secret file — call [`Self::load_metadata`]
    /// to peek at the encrypted secret file's `use_pre_1627` flag
    /// before unlock, or [`Self::unlock`] to bring the master key
    /// into memory (which also loads the file).
    pub fn open(secret_dir: PathBuf) -> Self {
        Self {
            secret_dir,
            unlocked: None,
            cached_secret_file: None,
        }
    }

    /// Load the encrypted secret file's metadata (WITHOUT decrypting
    /// the seed). Populates `cached_secret_file` so subsequent
    /// `unlock()` doesn't re-read the file, AND returns the
    /// `use_pre_1627` flag so the caller can construct
    /// `WalletState::empty(use_pre_1627)` correctly at boot —
    /// BEFORE the operator unlocks.
    ///
    /// Returns `WalletUninitialized` if no secret file exists.
    pub fn load_metadata(&mut self) -> Result<bool, WalletError> {
        let path = Self::find_secret_file(&self.secret_dir)?;
        let json = std::fs::read_to_string(&path)
            .map_err(|e| WalletError::SecretFile(format!("read {path:?}: {e}")))?;
        let secret: EncryptedSecret = serde_json::from_str(&json)
            .map_err(|e| WalletError::SecretFile(format!("parse: {e}")))?;
        let use_pre_1627 = secret.use_pre_1627_key_derivation;
        self.cached_secret_file = Some(secret);
        Ok(use_pre_1627)
    }

    /// Current lock state derived from on-disk presence + in-memory
    /// unlocked-secret presence.
    pub fn lock_state(&self) -> LockState {
        if self.unlocked.is_some() {
            return LockState::Unlocked;
        }
        if self.secret_file_exists() {
            return LockState::Locked;
        }
        LockState::Uninitialized
    }

    /// True if a secret file is present in `secret_dir`.
    fn secret_file_exists(&self) -> bool {
        Self::find_secret_file(&self.secret_dir).is_ok()
    }

    /// Scala-parity directory scan rule per
    /// `JsonSecretStorage.scala:133-144`:
    /// - If exactly one file in `secret_dir`, load it regardless of
    ///   extension.
    /// - If multiple files, filter to `.json` and load the first match.
    /// - If zero files, return an error.
    pub fn find_secret_file(secret_dir: &Path) -> Result<PathBuf, WalletError> {
        if !secret_dir.exists() {
            return Err(WalletError::WalletUninitialized);
        }
        let entries: Vec<PathBuf> = std::fs::read_dir(secret_dir)
            .map_err(|e| WalletError::SecretFile(format!("read_dir {secret_dir:?}: {e}")))?
            .filter_map(|r| r.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        match entries.len() {
            0 => Err(WalletError::WalletUninitialized),
            1 => Ok(entries.into_iter().next().unwrap()),
            _ => entries
                .into_iter()
                .find(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                .ok_or_else(|| {
                    WalletError::SecretFile(format!(
                        "multiple files in {secret_dir:?} but none have .json extension"
                    ))
                }),
        }
    }

    /// Generate a fresh wallet at the given strength + wallet password.
    /// `mnemonic_pass` is the BIP39 passphrase (mixed into the seed
    /// at `to_seed` time; not needed at unlock time because the seed
    /// is what gets encrypted). Creates `secret_dir` if it doesn't
    /// exist; writes `<uuid>.json` containing the encrypted BIP39
    /// SEED (NOT the phrase — Scala parity).
    ///
    /// Post-conditions:
    /// - Exactly one file in `secret_dir`.
    /// - `lock_state() == LockState::Locked` (operator must unlock
    ///   with the same `password` to access the master key).
    /// - The plaintext mnemonic is NOT retained anywhere — caller
    ///   must use the return value (the human-readable mnemonic
    ///   phrase) immediately or it's gone forever.
    pub fn init(
        &mut self,
        strength: crate::mnemonic::MnemonicStrength,
        password: &str,
        mnemonic_pass: &str,
    ) -> Result<String, WalletError> {
        let mnemonic = crate::mnemonic::Mnemonic::generate(strength)?;
        let phrase = mnemonic.phrase();
        let seed = mnemonic.to_seed(mnemonic_pass);
        self.persist_seed(&seed, password, /* use_pre_1627 */ false)?;
        Ok(phrase)
    }

    /// Restore an existing wallet from a known mnemonic + BIP39
    /// passphrase + wallet password. The mnemonic's BIP39 checksum
    /// is validated; if invalid, no secret file is written. The
    /// BIP39 passphrase is mixed into the seed here and discarded —
    /// you don't need it at unlock time because the seed is what
    /// gets encrypted.
    pub fn restore(
        &mut self,
        mnemonic_phrase: &str,
        mnemonic_pass: &str,
        password: &str,
        use_pre_1627: bool,
    ) -> Result<(), WalletError> {
        let mnemonic = crate::mnemonic::Mnemonic::import(mnemonic_phrase)?;
        let seed = mnemonic.to_seed(mnemonic_pass);
        self.persist_seed(&seed, password, use_pre_1627)
    }

    /// Unlock the wallet using the given password. Loads + decrypts
    /// the secret file, recovers the BIP39 seed bytes, derives the
    /// master key, stores it in memory for later use. No
    /// `mnemonic_pass` argument — the passphrase was mixed into the
    /// seed at `init`/`restore` time and is "baked in".
    pub fn unlock(&mut self, password: &str) -> Result<(), WalletError> {
        // Load the secret file if not cached.
        if self.cached_secret_file.is_none() {
            let path = Self::find_secret_file(&self.secret_dir)?;
            let json = std::fs::read_to_string(&path)
                .map_err(|e| WalletError::SecretFile(format!("read {path:?}: {e}")))?;
            let secret: EncryptedSecret = serde_json::from_str(&json)
                .map_err(|e| WalletError::SecretFile(format!("parse: {e}")))?;
            self.cached_secret_file = Some(secret);
        }
        let secret = self.cached_secret_file.as_ref().unwrap();

        // Enforce the full Scala cipherParams contract — any divergence
        // means we'd read a wallet file we don't fully understand and
        // could silently use wrong parameters.
        if secret.cipher_params.prf != "HmacSHA512" {
            return Err(WalletError::SecretFile(format!(
                "unsupported PRF {:?} (expected HmacSHA512)",
                secret.cipher_params.prf
            )));
        }
        if secret.cipher_params.dk_len != 256 {
            return Err(WalletError::SecretFile(format!(
                "unsupported dkLen {} (expected 256)",
                secret.cipher_params.dk_len
            )));
        }
        if secret.cipher_params.encryption_algorithm != "AES" {
            return Err(WalletError::SecretFile(format!(
                "unsupported encryptionAlgorithm {:?} (expected AES)",
                secret.cipher_params.encryption_algorithm
            )));
        }
        if secret.cipher_params.encryption_mode != "GCM" {
            return Err(WalletError::SecretFile(format!(
                "unsupported encryptionMode {:?} (expected GCM)",
                secret.cipher_params.encryption_mode
            )));
        }

        // Decode hex fields.
        let salt = hex::decode(&secret.salt)
            .map_err(|e| WalletError::SecretFile(format!("salt hex: {e}")))?;
        let iv: [u8; 12] = hex::decode(&secret.iv)
            .map_err(|e| WalletError::SecretFile(format!("iv hex: {e}")))?
            .try_into()
            .map_err(|_| WalletError::SecretFile("iv must be 12 bytes".to_string()))?;
        let ciphertext = hex::decode(&secret.cipher_text)
            .map_err(|e| WalletError::SecretFile(format!("cipherText hex: {e}")))?;
        let auth_tag: [u8; 16] = hex::decode(&secret.auth_tag)
            .map_err(|e| WalletError::SecretFile(format!("authTag hex: {e}")))?
            .try_into()
            .map_err(|_| WalletError::SecretFile("authTag must be 16 bytes".to_string()))?;

        let iterations = secret.cipher_params.c;
        let key = crate::encryption::derive_key_pbkdf2(password.as_bytes(), &salt, iterations);

        // Decrypt the SEED bytes (64 bytes). Validate length explicitly
        // — anything else means corrupt or wrong-format file.
        let seed_bytes = crate::encryption::decrypt(&key, &iv, &ciphertext, &auth_tag)?;
        let seed: [u8; 64] = seed_bytes.as_slice().try_into().map_err(|_| {
            WalletError::SecretFile(format!(
                "decrypted seed must be 64 bytes, got {}",
                seed_bytes.len(),
            ))
        })?;

        // Derive the master key directly from the seed bytes — no
        // mnemonic involvement at unlock time. Branch on use_pre_1627
        // to construct the correct master-key variant.
        let use_pre_1627 = secret.use_pre_1627_key_derivation;
        let master = if use_pre_1627 {
            UnlockedMaster::Legacy(
                crate::extended_key::ExtendedSecretKeyLegacy::derive_master_key(&seed)?,
            )
        } else {
            UnlockedMaster::Modern(ExtendedSecretKey::derive_master_key(&seed, false)?)
        };

        self.unlocked = Some(UnlockedSecret {
            master,
            use_pre_1627,
        });
        Ok(())
    }

    /// Drop the in-memory master key. Idempotent; calling lock() on
    /// an already-locked wallet is a no-op.
    pub fn lock(&mut self) {
        // ZeroizeOnDrop inside UnlockedSecret means dropping it zeroes
        // the backing memory automatically when we set `unlocked = None`.
        self.unlocked = None;
    }

    /// Verify the given (mnemonic, mnemonicPass) pair matches the
    /// currently-unlocked wallet by re-deriving the seed and comparing
    /// against the in-memory master key. Returns false if the wallet
    /// is locked (Scala `JsonSecretStorage.scala:44` parity — NOT an
    /// error).
    ///
    /// The `mnemonic_pass` argument is required so callers can
    /// validate a passphrase-protected mnemonic; pass `""` for
    /// mnemonics created without a BIP39 passphrase.
    pub fn check_seed(&self, mnemonic_phrase: &str, mnemonic_pass: &str) -> bool {
        let Some(unlocked) = self.unlocked.as_ref() else {
            // Locked → false (Scala parity, NOT an error).
            return false;
        };
        let Ok(mnemonic) = crate::mnemonic::Mnemonic::import(mnemonic_phrase) else {
            return false;
        };
        let seed = mnemonic.to_seed(mnemonic_pass);
        let Ok(candidate_pk) = (if unlocked.use_pre_1627 {
            crate::extended_key::ExtendedSecretKeyLegacy::derive_master_key(&seed)
                .and_then(|m| m.public_key().map(|p| p.compressed_bytes()))
        } else {
            ExtendedSecretKey::derive_master_key(&seed, false)
                .map(|m| m.public_key().compressed_bytes())
        }) else {
            return false;
        };
        let Ok(expected_pk) = unlocked.master.master_pubkey() else {
            return false;
        };
        candidate_pk == expected_pk
    }

    /// Borrow the in-memory unlocked secret, if any.
    pub fn unlocked(&self) -> Option<&UnlockedSecret> {
        self.unlocked.as_ref()
    }

    /// Access the cached secret file metadata (the JSON struct read
    /// from disk; doesn't expose the decrypted master). Useful for
    /// reading the `use_pre_1627` flag without unlocking.
    pub fn cached_file(&self) -> Option<&EncryptedSecret> {
        self.cached_secret_file.as_ref()
    }

    /// Internal: encrypt the BIP39 seed bytes (64 bytes) and write to
    /// disk. Matches Scala `JsonSecretStorage` which stores the
    /// encrypted seed — NOT the mnemonic phrase.
    fn persist_seed(
        &mut self,
        seed: &[u8; 64],
        password: &str,
        use_pre_1627: bool,
    ) -> Result<(), WalletError> {
        std::fs::create_dir_all(&self.secret_dir)
            .map_err(|e| WalletError::SecretFile(format!("create_dir_all: {e}")))?;

        // Generate random 32-byte salt + 12-byte IV. Salt size matches
        // Scala `AES.encrypt` (32 bytes).
        let mut salt = [0u8; 32];
        let mut iv = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);

        // Derive key + encrypt the seed bytes. Scala uses
        // `password.getBytes(StandardCharsets.UTF_8)` for the PBKDF2
        // password input; Rust's `str.as_bytes()` is already UTF-8.
        let key = crate::encryption::derive_key_pbkdf2(password.as_bytes(), &salt, 128_000);
        let (ciphertext, auth_tag) = crate::encryption::encrypt(&key, &iv, seed)?;

        // Build the EncryptedSecret JSON struct.
        let secret = EncryptedSecret {
            cipher_text: hex::encode(&ciphertext),
            salt: hex::encode(salt),
            iv: hex::encode(iv),
            auth_tag: hex::encode(auth_tag),
            cipher_params: CipherParams::scala_default(),
            use_pre_1627_key_derivation: use_pre_1627,
        };

        // Compute filename = nameUUIDFromBytes(ciphertext).json
        let filename = filename_for_ciphertext(&ciphertext);
        let path = self.secret_dir.join(&filename);
        let json = serde_json::to_string_pretty(&secret)
            .map_err(|e| WalletError::SecretFile(format!("serialize: {e}")))?;
        std::fs::write(&path, json)
            .map_err(|e| WalletError::SecretFile(format!("write {path:?}: {e}")))?;

        // chmod 0o600 on Unix; restricted ACL on Windows is more involved,
        // skip for now.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perm)
                .map_err(|e| WalletError::SecretFile(format!("chmod 0o600 {path:?}: {e}")))?;
        }

        // Cache so subsequent unlock() doesn't re-read the file.
        self.cached_secret_file = Some(secret);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn scala_default_cipher_params_serialize_correctly() {
        let cp = CipherParams::scala_default();
        let json = serde_json::to_string(&cp).unwrap();
        // Field order: prf, c, dkLen, encryptionAlgorithm, encryptionMode
        assert_eq!(
            json,
            r#"{"prf":"HmacSHA512","c":128000,"dkLen":256,"encryptionAlgorithm":"AES","encryptionMode":"GCM"}"#,
        );
    }

    // ----- round-trips -----

    /// Round-trip: serialize a known EncryptedSecret to JSON, parse
    /// it back, verify all fields match.
    #[test]
    fn encrypted_secret_round_trips_through_json() {
        let original = EncryptedSecret {
            cipher_text: "deadbeef".to_string(),
            salt: "0011223344556677".to_string(),
            iv: "aabbccddeeff001122334455".to_string(),
            auth_tag: "ffeeddccbbaa99887766554433221100".to_string(),
            cipher_params: CipherParams::scala_default(),
            use_pre_1627_key_derivation: false,
        };
        let json = serde_json::to_string(&original).unwrap();
        let parsed: EncryptedSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cipher_text, original.cipher_text);
        assert_eq!(parsed.salt, original.salt);
        assert_eq!(parsed.iv, original.iv);
        assert_eq!(parsed.auth_tag, original.auth_tag);
        assert_eq!(
            parsed.use_pre_1627_key_derivation,
            original.use_pre_1627_key_derivation
        );
    }

    /// Tier-1 wallet-import compatibility: parsing a Scala-generated
    /// JSON file that PREDATES the `usePre1627KeyDerivation` field
    /// MUST default that field to `true`. Spec §5.1.
    #[test]
    fn missing_use_pre_1627_field_defaults_to_true() {
        // Note: no usePre1627KeyDerivation field.
        let legacy_json = r#"{
            "cipherText": "deadbeef",
            "salt": "0011223344556677",
            "iv": "aabbccddeeff001122334455",
            "authTag": "ffeeddccbbaa99887766554433221100",
            "cipherParams": {
                "prf": "HmacSHA512",
                "c": 128000,
                "dkLen": 256,
                "encryptionAlgorithm": "AES",
                "encryptionMode": "GCM"
            }
        }"#;
        let parsed: EncryptedSecret = serde_json::from_str(legacy_json).unwrap();
        assert!(
            parsed.use_pre_1627_key_derivation,
            "missing field MUST default to true (legacy wallet safe default)",
        );
    }

    /// Modern wallets explicitly set `usePre1627KeyDerivation = false`;
    /// the parser MUST honour that value (not silently treat false as
    /// missing-then-default-true).
    #[test]
    fn explicit_false_use_pre_1627_is_honoured() {
        let modern_json = r#"{
            "cipherText": "deadbeef",
            "salt": "0011223344556677",
            "iv": "aabbccddeeff001122334455",
            "authTag": "ffeeddccbbaa99887766554433221100",
            "cipherParams": {
                "prf": "HmacSHA512",
                "c": 128000,
                "dkLen": 256,
                "encryptionAlgorithm": "AES",
                "encryptionMode": "GCM"
            },
            "usePre1627KeyDerivation": false
        }"#;
        let parsed: EncryptedSecret = serde_json::from_str(modern_json).unwrap();
        assert!(!parsed.use_pre_1627_key_derivation);
    }

    /// Filename is `UUID.nameUUIDFromBytes(cipherText).toString +
    /// ".json"` — deterministic from the ciphertext. Matches Scala
    /// `JsonSecretStorage.scala:102-105`.
    #[test]
    fn uuid_from_ciphertext_matches_java_nameuuidfrombytes() {
        // Java UUID.nameUUIDFromBytes(bytes) = raw MD5 over `bytes`
        // (no namespace prefix), then patch version field (high 4
        // bits of byte 6) to 3 and variant field (high 2 bits of
        // byte 8) to 10 (IETF). This is NOT equivalent to Rust's
        // `uuid::Uuid::new_v3(&Uuid::nil(), bytes)` — that prefixes
        // the nil namespace bytes before hashing and produces a
        // different UUID.
        //
        // Reference: OpenJDK UUID.java:155 (nameUUIDFromBytes impl).
        //
        // Known vector: MD5("hello") = 5d41402abc4b2a76b9719d911017c592
        // Format as UUID 8-4-4-4-12:
        //   5d41402a-bc4b-2a76-b971-9d911017c592
        // Patching:
        //   byte[6] = 0x2a → (0x2a & 0x0f) | 0x30 = 0x3a  (3rd group: 3a76)
        //   byte[8] = 0xb9 → (0xb9 & 0x3f) | 0x80 = 0xb9  (top bits already 10)
        // Result: 5d41402a-bc4b-3a76-b971-9d911017c592
        let uuid = uuid_from_ciphertext(b"hello");
        assert_eq!(
            uuid.to_string(),
            "5d41402a-bc4b-3a76-b971-9d911017c592",
            "must match Java UUID.nameUUIDFromBytes(b\"hello\") byte-for-byte",
        );
    }

    // ----- directory scan -----

    use std::fs;

    #[test]
    fn find_secret_file_empty_dir_returns_uninitialized() {
        let tmp = tempfile::tempdir().unwrap();
        let err = SecretStorage::find_secret_file(tmp.path()).unwrap_err();
        assert!(matches!(err, WalletError::WalletUninitialized));
    }

    #[test]
    fn find_secret_file_single_file_loads_regardless_of_extension() {
        // Scala: one file, no extension filter applied. Load it.
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("any-name.no-extension");
        fs::write(&p, b"placeholder").unwrap();
        let found = SecretStorage::find_secret_file(tmp.path()).unwrap();
        assert_eq!(found, p);
    }

    #[test]
    fn find_secret_file_multiple_files_filters_to_json() {
        // Two files, only one .json. Load the .json one.
        let tmp = tempfile::tempdir().unwrap();
        let p_non_json = tmp.path().join("not-this-one.txt");
        let p_json = tmp.path().join("uuid-here.json");
        fs::write(&p_non_json, b"x").unwrap();
        fs::write(&p_json, b"x").unwrap();
        let found = SecretStorage::find_secret_file(tmp.path()).unwrap();
        assert_eq!(found, p_json);
    }

    #[test]
    fn find_secret_file_multiple_without_json_errors() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("a.txt"), b"x").unwrap();
        fs::write(tmp.path().join("b.dat"), b"x").unwrap();
        let err = SecretStorage::find_secret_file(tmp.path()).unwrap_err();
        assert!(matches!(err, WalletError::SecretFile(_)));
    }

    // ----- init / unlock / lock -----

    #[test]
    fn init_creates_secret_file_in_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());
        assert_eq!(storage.lock_state(), LockState::Uninitialized);

        storage
            .init(
                crate::mnemonic::MnemonicStrength::Words24,
                "test-password",
                "",
            )
            .expect("init must succeed");

        assert_eq!(
            storage.lock_state(),
            LockState::Locked,
            "init leaves the wallet LOCKED (operator must unlock with the same password)"
        );

        // Exactly one .json file in the dir, named <uuid>.json.
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        let name = entries[0].file_name();
        let name_str = name.to_string_lossy();
        assert!(
            name_str.ends_with(".json"),
            "filename {name_str:?} must end in .json"
        );
        // The basename is a v3 UUID hash of the ciphertext — we don't
        // know it in advance, but it should be 36 chars (UUID format).
        assert_eq!(name_str.len(), 36 + ".json".len());
    }

    #[test]
    fn restore_from_known_mnemonic_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());
        let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon about";
        storage
            .restore(
                mnemonic_phrase,
                /* mnemonic_pass */ "",
                "test-password",
                /* use_pre_1627 */ false,
            )
            .expect("restore must succeed");

        assert_eq!(storage.lock_state(), LockState::Locked);

        // Now unlock with the same password — must succeed.
        storage
            .unlock("test-password")
            .expect("unlock with correct password");
        assert_eq!(storage.lock_state(), LockState::Unlocked);
    }

    #[test]
    fn restore_with_invalid_mnemonic_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());
        // Bad checksum (last word changed).
        let bad_phrase = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon";
        let err = storage
            .restore(bad_phrase, "", "pw", false)
            .expect_err("bad checksum");
        assert!(matches!(err, WalletError::InvalidMnemonic(_)));
        assert_eq!(storage.lock_state(), LockState::Uninitialized);
    }

    #[test]
    fn restore_with_mnemonic_pass_changes_derived_master() {
        // BIP39 passphrase is baked into the seed at restore time.
        // Restoring the same mnemonic with different passphrases must
        // produce different stored encryptions AND different unlocked
        // master keys.
        let tmp_a = tempfile::tempdir().unwrap();
        let tmp_b = tempfile::tempdir().unwrap();
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";

        let mut a = SecretStorage::open(tmp_a.path().to_path_buf());
        a.restore(phrase, /* mnemonic_pass */ "", "pw", false)
            .unwrap();
        a.unlock("pw").unwrap();

        let mut b = SecretStorage::open(tmp_b.path().to_path_buf());
        b.restore(phrase, /* mnemonic_pass */ "TREZOR", "pw", false)
            .unwrap();
        b.unlock("pw").unwrap();

        assert_ne!(
            a.unlocked().unwrap().master.master_pubkey().unwrap(),
            b.unlocked().unwrap().master.master_pubkey().unwrap(),
            "mnemonic_pass must change the derived master key — if equal, \
             the passphrase is being dropped (the r1 storage-phrase bug)",
        );
    }

    #[test]
    fn restore_non_ascii_wallet_password_round_trips() {
        // Wallet password handling: Scala uses
        // `password.getBytes(StandardCharsets.UTF_8)`. Rust's
        // `str.as_bytes()` is UTF-8 by definition, so non-ASCII
        // passwords round-trip if both sides agree on UTF-8.
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());
        let pw = "пароль-тест-🔑"; // Cyrillic + emoji
        storage
            .init(crate::mnemonic::MnemonicStrength::Words12, pw, "")
            .unwrap();
        storage
            .unlock(pw)
            .expect("non-ASCII UTF-8 password must round-trip");
        assert_eq!(storage.lock_state(), LockState::Unlocked);
    }

    #[test]
    fn unlock_with_wrong_password_fails_and_stays_locked() {
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());
        storage
            .init(crate::mnemonic::MnemonicStrength::Words12, "correct", "")
            .unwrap();

        let err = storage
            .unlock("wrong")
            .expect_err("wrong password must fail");
        assert!(matches!(err, WalletError::Decryption));
        assert_eq!(
            storage.lock_state(),
            LockState::Locked,
            "after failed unlock, wallet must remain locked"
        );
    }

    #[test]
    fn lock_drops_in_memory_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());
        storage
            .init(crate::mnemonic::MnemonicStrength::Words12, "pw", "")
            .unwrap();
        storage.unlock("pw").unwrap();
        assert_eq!(storage.lock_state(), LockState::Unlocked);

        storage.lock();
        assert_eq!(storage.lock_state(), LockState::Locked);
        assert!(storage.unlocked().is_none());
    }

    #[test]
    fn check_seed_locked_wallet_returns_false() {
        // Scala parity: JsonSecretStorage.scala:44 — locked checkSeed
        // returns false rather than erroring.
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());
        storage
            .init(crate::mnemonic::MnemonicStrength::Words12, "pw", "")
            .unwrap();
        // Wallet is locked.
        assert!(!storage.check_seed(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
            "",
        ));
    }

    #[test]
    fn check_seed_unlocked_wallet_validates_correct_mnemonic() {
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        storage.restore(phrase, "", "pw", false).unwrap();
        storage.unlock("pw").unwrap();

        assert!(
            storage.check_seed(phrase, ""),
            "the right mnemonic must validate"
        );
        assert!(
            !storage.check_seed(
                "ahead abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon about",
                "",
            ),
            "wrong mnemonic must NOT validate"
        );
    }

    #[test]
    fn check_seed_requires_correct_mnemonic_pass() {
        // The mnemonic alone is not enough — the same mnemonic with a
        // different passphrase MUST NOT validate, because the stored
        // seed has the passphrase baked in.
        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        storage.restore(phrase, "TREZOR", "pw", false).unwrap();
        storage.unlock("pw").unwrap();

        assert!(
            storage.check_seed(phrase, "TREZOR"),
            "right mnemonic + right pass → match"
        );
        assert!(
            !storage.check_seed(phrase, ""),
            "right mnemonic + wrong pass → no match"
        );
        assert!(
            !storage.check_seed(phrase, "wrong-pass"),
            "right mnemonic + wrong pass → no match"
        );
    }
}

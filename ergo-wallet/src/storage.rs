//! Encrypted secret-file storage (Scala-compatible).
//!
//! New files use version 2: Argon2id key derivation and AES-256-GCM whose
//! associated data authenticates every parameter ([`EncryptedSecretV2`]).
//! Version-1 files ([`EncryptedSecret`]) remain readable and are rewritten as
//! version 2 by the first successful unlock. [`SecretStorage::export_for_appkit`]
//! writes a version-1 copy for JVM tools.
//!
//! The version-1 format at `<data_dir>/wallet/<uuid>.json` exactly matches
//! Scala `JsonSecretStorage`:
//! - filename: `UUID.nameUUIDFromBytes(cipherText).toString + ".json"`
//!   (deterministic; two wallets with the same ciphertext produce the
//!   same filename — impossible in practice given random IVs)
//! - directory-scan rule: if exactly one file in `<data_dir>/wallet/`,
//!   load any name; if multiple files, filter to `.json` and load first.
//! - wire shape: see `EncryptedSecret` struct below.
//! - `usePre1627KeyDerivation` defaults to `true` when missing or null (tier-1
//!   wallet-import compatibility for pre-Sigma-5.0 secret files).

use serde::{Deserialize, Serialize};

/// AES-GCM cipher parameters embedded in the encrypted secret file.
/// Field names match Scala `EncryptedSecret.scala:37-42` camelCase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    /// PRF used for PBKDF2: Scala/Appkit's `"HmacSHA256"` or legacy `"HmacSHA512"`.
    pub prf: String,
    /// PBKDF2 iteration count. Scala default = 128_000.
    pub c: u32,
    /// Derived-key length in BITS (not bytes). Scala = 256.
    #[serde(rename = "dkLen")]
    pub dk_len: u32,
    /// Cipher algorithm. Defaults to `"AES"` for Scala files that omit it.
    #[serde(rename = "encryptionAlgorithm", default = "default_algorithm")]
    pub encryption_algorithm: String,
    /// Cipher mode. Defaults to `"GCM"` for Scala files that omit it.
    #[serde(rename = "encryptionMode", default = "default_mode")]
    pub encryption_mode: String,
}

impl CipherParams {
    /// Scala/Appkit-default parameters: PBKDF2-HMAC-SHA256 128k iterations,
    /// AES-256-GCM.
    pub fn scala_default() -> Self {
        Self {
            prf: "HmacSHA256".to_string(),
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
/// JSON field order is not significant to either implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    /// Encrypted stream after its first 16 bytes, including the GCM tag.
    /// Scala's historical field split is preserved. Hex-encoded.
    #[serde(rename = "cipherText")]
    pub cipher_text: String,
    /// PBKDF2 salt. Hex-encoded.
    pub salt: String,
    /// AES-GCM IV (96 bits / 12 bytes). Hex-encoded.
    pub iv: String,
    /// First 16 bytes of the encrypted stream; despite its historical name,
    /// this is not the cryptographic GCM tag. Hex-encoded.
    #[serde(rename = "authTag")]
    pub auth_tag: String,
    /// PBKDF2 + AES-GCM parameters.
    #[serde(rename = "cipherParams")]
    pub cipher_params: CipherParams,
    /// Pre-1627 derivation switch (tier-1 wallet-import compatibility).
    /// Missing or null field deserializes to `true` — matching Scala
    /// `JsonSecretStorageSpec.scala:80` ("legacy wallets predate the
    /// field; defaulting to `true` is the only safe option").
    #[serde(
        rename = "usePre1627KeyDerivation",
        default = "default_use_pre_1627",
        deserialize_with = "deserialize_use_pre_1627"
    )]
    pub use_pre_1627_key_derivation: bool,
}

/// Version-2 key-derivation block: Argon2id with an explicit salt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfV2 {
    /// Always `"argon2id"`.
    pub algorithm: String,
    /// Memory cost in KiB.
    #[serde(rename = "memoryKiB")]
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
    /// Salt. Hex-encoded, 32 bytes.
    pub salt: String,
}

/// Version-2 cipher block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherV2 {
    /// Always `"AES-256-GCM"`.
    pub algorithm: String,
    /// Nonce. Hex-encoded, 12 bytes.
    pub iv: String,
}

/// Version-2 encrypted secret file: Argon2id key derivation and AES-256-GCM
/// whose associated data authenticates every parameter and the derivation
/// mode. Not readable by Scala, Appkit or earlier Rust releases; use
/// [`SecretStorage::export_for_appkit`] for a version-1 copy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSecretV2 {
    /// Always 2.
    pub version: u32,
    /// Key derivation.
    pub kdf: KdfV2,
    /// Cipher.
    pub cipher: CipherV2,
    /// Ciphertext followed by the 16-byte GCM tag. Hex-encoded.
    #[serde(rename = "cipherText")]
    pub cipher_text: String,
    /// Pre-1627 derivation switch. Required in version 2.
    #[serde(rename = "usePre1627KeyDerivation")]
    pub use_pre_1627_key_derivation: bool,
}

impl EncryptedSecretV2 {
    const ALGORITHM: &'static str = "argon2id";
    const CIPHER: &'static str = "AES-256-GCM";
    const AAD_DOMAIN: &'static [u8] = b"ergo-wallet keystore v2\0";

    fn params(&self) -> crate::encryption::Argon2idParams {
        crate::encryption::Argon2idParams {
            memory_kib: self.kdf.memory_kib,
            iterations: self.kdf.iterations,
            parallelism: self.kdf.parallelism,
        }
    }

    /// Associated data binding the version, every KDF and cipher parameter,
    /// and the derivation mode to the ciphertext.
    fn aad(
        params: crate::encryption::Argon2idParams,
        salt: &[u8],
        iv: &[u8; 12],
        pre: bool,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(Self::AAD_DOMAIN.len() + 64);
        aad.extend_from_slice(Self::AAD_DOMAIN);
        aad.extend_from_slice(&2u32.to_be_bytes());
        aad.extend_from_slice(&params.memory_kib.to_be_bytes());
        aad.extend_from_slice(&params.iterations.to_be_bytes());
        aad.extend_from_slice(&params.parallelism.to_be_bytes());
        aad.extend_from_slice(&(salt.len() as u32).to_be_bytes());
        aad.extend_from_slice(salt);
        aad.extend_from_slice(iv);
        aad.push(u8::from(pre));
        aad
    }

    fn encrypt(
        seed: &[u8; 64],
        password: &str,
        use_pre_1627: bool,
        params: crate::encryption::Argon2idParams,
    ) -> Result<Self, WalletError> {
        let mut salt = [0u8; 32];
        let mut iv = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);
        let key = crate::encryption::derive_key_argon2id(password.as_bytes(), &salt, params)?;
        let sealed = crate::encryption::seal(
            &key,
            &iv,
            seed,
            &Self::aad(params, &salt, &iv, use_pre_1627),
        )?;
        Ok(Self {
            version: 2,
            kdf: KdfV2 {
                algorithm: Self::ALGORITHM.to_string(),
                memory_kib: params.memory_kib,
                iterations: params.iterations,
                parallelism: params.parallelism,
                salt: hex::encode(salt),
            },
            cipher: CipherV2 {
                algorithm: Self::CIPHER.to_string(),
                iv: hex::encode(iv),
            },
            cipher_text: hex::encode(sealed),
            use_pre_1627_key_derivation: use_pre_1627,
        })
    }

    fn decrypt(&self, password: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, WalletError> {
        let invalid = |message: String| WalletError::SecretFile(message);
        if self.version != 2 {
            return Err(invalid(format!(
                "unsupported keystore version {}",
                self.version
            )));
        }
        if self.kdf.algorithm != Self::ALGORITHM {
            return Err(invalid(format!("unsupported KDF {:?}", self.kdf.algorithm)));
        }
        if self.cipher.algorithm != Self::CIPHER {
            return Err(invalid(format!(
                "unsupported cipher {:?}",
                self.cipher.algorithm
            )));
        }
        let params = self.params();
        params.validate()?;
        let salt = hex::decode(&self.kdf.salt).map_err(|e| invalid(format!("salt hex: {e}")))?;
        if !(16..=64).contains(&salt.len()) {
            return Err(invalid("salt must be 16 to 64 bytes".to_string()));
        }
        let iv: [u8; 12] = hex::decode(&self.cipher.iv)
            .map_err(|e| invalid(format!("iv hex: {e}")))?
            .try_into()
            .map_err(|_| invalid("iv must be 12 bytes".to_string()))?;
        let sealed =
            hex::decode(&self.cipher_text).map_err(|e| invalid(format!("cipherText hex: {e}")))?;
        let key = crate::encryption::derive_key_argon2id(password.as_bytes(), &salt, params)?;
        crate::encryption::open(
            &key,
            &iv,
            &sealed,
            &Self::aad(params, &salt, &iv, self.use_pre_1627_key_derivation),
        )
    }
}

/// A parsed secret file of either supported version. Serializes to the
/// file's own JSON shape.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum KeystoreFile {
    /// Scala/Appkit-compatible PBKDF2 file.
    V1(EncryptedSecret),
    /// Argon2id file with authenticated parameters.
    V2(EncryptedSecretV2),
}

impl KeystoreFile {
    /// Parse a secret file. A `version` field selects version 2; files
    /// without one are the Scala-compatible version 1.
    pub fn parse(bytes: &[u8]) -> Result<Self, WalletError> {
        let parse_error = |e: serde_json::Error| WalletError::SecretFile(format!("parse: {e}"));
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(parse_error)?;
        match value.get("version") {
            None => serde_json::from_value(value)
                .map(Self::V1)
                .map_err(parse_error),
            Some(serde_json::Value::Number(number)) if number.as_u64() == Some(2) => {
                serde_json::from_value(value)
                    .map(Self::V2)
                    .map_err(parse_error)
            }
            Some(other) => Err(WalletError::SecretFile(format!(
                "unsupported keystore version {other}"
            ))),
        }
    }

    /// The file's derivation-mode flag. Readable without the password.
    pub fn use_pre_1627(&self) -> bool {
        match self {
            Self::V1(secret) => secret.use_pre_1627_key_derivation,
            Self::V2(secret) => secret.use_pre_1627_key_derivation,
        }
    }

    /// Format version: 1 or 2.
    pub fn version(&self) -> u32 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
        }
    }

    /// Ciphertext bytes, for the Scala filename convention.
    fn cipher_text_bytes(&self) -> Result<Vec<u8>, WalletError> {
        let text = match self {
            Self::V1(secret) => &secret.cipher_text,
            Self::V2(secret) => &secret.cipher_text,
        };
        hex::decode(text).map_err(|e| WalletError::SecretFile(format!("cipherText hex: {e}")))
    }

    fn decrypt_seed(&self, password: &str) -> Result<zeroize::Zeroizing<[u8; 64]>, WalletError> {
        let bytes = match self {
            Self::V1(secret) => return SecretStorage::decrypt_seed(secret, password),
            Self::V2(secret) => secret.decrypt(password)?,
        };
        let seed: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
            WalletError::SecretFile(format!(
                "decrypted seed must be 64 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(zeroize::Zeroizing::new(seed))
    }

    /// True when unlock should rewrite this file with the current parameters.
    fn needs_upgrade(&self) -> bool {
        match self {
            Self::V1(_) => true,
            Self::V2(secret) => secret.params().weaker_than(&new_keystore_kdf()),
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
static TEST_KDF: std::sync::OnceLock<crate::encryption::Argon2idParams> =
    std::sync::OnceLock::new();

/// Argon2id parameters for newly written keystore files.
pub fn new_keystore_kdf() -> crate::encryption::Argon2idParams {
    #[cfg(any(test, feature = "test-utils"))]
    if let Some(params) = TEST_KDF.get() {
        return *params;
    }
    // This crate's own unit tests create many wallets; they use the fast
    // cost unless a test asks otherwise.
    #[cfg(test)]
    return FAST_TEST_KDF;
    #[cfg(not(test))]
    crate::encryption::Argon2idParams::keystore_default()
}

#[cfg(any(test, feature = "test-utils"))]
const FAST_TEST_KDF: crate::encryption::Argon2idParams = crate::encryption::Argon2idParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

/// Test builds only: write new keystores with minimal Argon2id cost so
/// suites that create many wallets stay fast. Absent from production builds.
#[cfg(any(test, feature = "test-utils"))]
pub fn use_fast_keystore_kdf_for_tests() {
    let _ = TEST_KDF.set(FAST_TEST_KDF);
}

/// Result of the automatic keystore upgrade attempted by a successful unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreUpgrade {
    /// The file was rewritten in the current version-2 format.
    Upgraded { from_version: u32 },
    /// The rewrite failed; the original file is unchanged and still unlocks.
    Failed(String),
}

/// Default for missing `usePre1627KeyDerivation` field. Tier-1
/// invariant: legacy wallets predate the field, so `true` is the safe
/// default. Anyone restoring from a pre-2021 Scala wallet file relies
/// on this.
fn default_use_pre_1627() -> bool {
    true
}

fn deserialize_use_pre_1627<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<bool, D::Error> {
    Option::<bool>::deserialize(deserializer).map(|flag| flag.unwrap_or(true))
}

fn default_algorithm() -> String {
    "AES".into()
}
fn default_mode() -> String {
    "GCM".into()
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
    cached_secret_file: Option<KeystoreFile>,
    /// Path the cached file was read from; an upgrade replaces it in place.
    cached_secret_path: Option<PathBuf>,
    /// Outcome of the last automatic format upgrade, until taken.
    upgrade: Option<KeystoreUpgrade>,
}

pub use crate::master::{UnlockedMaster, UnlockedSecret};

/// Master encoding that derives a wallet's persisted keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterDerivation {
    /// The secret file's mode with the complete master, as Scala derives.
    Standard,
    /// Pre-1627 derivation from a master whose leading zero bytes the earlier
    /// Rust node dropped. Its addresses differ from Scala's for the same file.
    LegacyRustTrimmed,
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
            cached_secret_path: None,
            upgrade: None,
        }
    }

    fn read_secret_file(path: &Path) -> Result<KeystoreFile, WalletError> {
        let bytes = std::fs::read(path)
            .map_err(|e| WalletError::SecretFile(format!("read {path:?}: {e}")))?;
        KeystoreFile::parse(&bytes)
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
        let secret = Self::read_secret_file(&path)?;
        let use_pre_1627 = secret.use_pre_1627();
        self.cached_secret_file = Some(secret);
        self.cached_secret_path = Some(path);
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

    fn require_uninitialized(&self) -> Result<(), WalletError> {
        if self.unlocked.is_some() || self.cached_secret_file.is_some() {
            return Err(WalletError::WalletAlreadyInitialized);
        }
        match Self::find_secret_file(&self.secret_dir) {
            Err(WalletError::WalletUninitialized) => Ok(()),
            Ok(_) => Err(WalletError::WalletAlreadyInitialized),
            Err(error) => Err(error),
        }
    }

    /// Scala-parity directory scan rule per
    /// `JsonSecretStorage.scala:133-144`:
    /// - If exactly one file in `secret_dir`, load it regardless of
    ///   extension.
    /// - If multiple files, filter to `.json` and load the first match.
    /// - If zero files, return an error.
    pub fn find_secret_file(secret_dir: &Path) -> Result<PathBuf, WalletError> {
        if !secret_dir
            .try_exists()
            .map_err(|e| WalletError::SecretFile(format!("inspect {secret_dir:?}: {e}")))?
        {
            return Err(WalletError::WalletUninitialized);
        }
        let entries: Vec<PathBuf> = std::fs::read_dir(secret_dir)
            .map_err(|e| WalletError::SecretFile(format!("read_dir {secret_dir:?}: {e}")))?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| WalletError::SecretFile(format!("read_dir entry {secret_dir:?}: {e}")))?
            .into_iter()
            .filter(|p| p.is_file())
            .filter(|p| {
                !p.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".ergo-wallet-pending-"))
            })
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
    /// Requires uninitialized storage; existing on-disk, cached, or unlocked
    /// state is never replaced. Callers must exclusively own this directory
    /// while initializing; this handle does not provide a cross-process lock.
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
        self.require_uninitialized()?;
        let mnemonic = crate::mnemonic::Mnemonic::generate(strength)?;
        let phrase = zeroize::Zeroizing::new(mnemonic.phrase());
        let seed = mnemonic.to_seed(mnemonic_pass);
        self.persist_seed(&seed, password, /* use_pre_1627 */ false)?;
        Ok(phrase.to_string())
    }

    /// Restore an existing wallet from a known mnemonic + BIP39
    /// passphrase + wallet password. The mnemonic's BIP39 checksum
    /// is validated; if invalid, no secret file is written. The
    /// BIP39 passphrase is mixed into the seed here and discarded —
    /// you don't need it at unlock time because the seed is what
    /// gets encrypted.
    /// Requires uninitialized storage under the same ownership contract as init.
    pub fn restore(
        &mut self,
        mnemonic_phrase: &str,
        mnemonic_pass: &str,
        password: &str,
        use_pre_1627: bool,
    ) -> Result<(), WalletError> {
        self.require_uninitialized()?;
        let mnemonic = crate::mnemonic::Mnemonic::import(mnemonic_phrase)?;
        let seed = mnemonic.to_seed(mnemonic_pass);
        self.persist_seed(&seed, password, use_pre_1627)
    }

    /// Write a separate Appkit-compatible copy of an existing encrypted wallet.
    /// Authenticates the original password and preserves its seed, password,
    /// and key-derivation mode. The source, version 1 or 2, is never modified;
    /// the copy is the Scala/Appkit version-1 PBKDF2 format, which is weaker
    /// against password guessing than version 2. The destination directory
    /// must be empty. No mnemonic or private key is returned.
    pub fn export_for_appkit(
        source_file: &Path,
        output_dir: &Path,
        password: &str,
    ) -> Result<PathBuf, WalletError> {
        let secret = Self::read_secret_file(source_file)?;
        let seed = secret.decrypt_seed(password)?;
        if output_dir.exists() {
            let mut entries = std::fs::read_dir(output_dir)
                .map_err(|e| WalletError::SecretFile(format!("read output directory: {e}")))?;
            if entries.next().is_some() {
                return Err(WalletError::SecretFile(
                    "output directory must be empty".to_string(),
                ));
            }
        }
        let mut output = Self::open(output_dir.to_path_buf());
        output.persist_seed_v1(&seed, password, secret.use_pre_1627())?;
        Self::find_secret_file(output_dir)
    }

    fn decrypt_seed(
        secret: &EncryptedSecret,
        password: &str,
    ) -> Result<zeroize::Zeroizing<[u8; 64]>, WalletError> {
        // Enforce the full Scala cipherParams contract — any divergence
        // means we'd read a wallet file we don't fully understand and
        // could silently use wrong parameters.
        let prf = crate::encryption::Pbkdf2Prf::from_name(&secret.cipher_params.prf).ok_or_else(
            || {
                WalletError::SecretFile(format!(
                    "unsupported PRF {:?} (expected HmacSHA256 or HmacSHA512)",
                    secret.cipher_params.prf
                ))
            },
        )?;
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
        if iterations == 0 {
            return Err(WalletError::SecretFile(
                "PBKDF2 iteration count must be positive".to_string(),
            ));
        }
        if iterations > crate::encryption::MAX_PBKDF2_ITERATIONS {
            return Err(WalletError::SecretFile(format!(
                "PBKDF2 iteration count {iterations} exceeds {}",
                crate::encryption::MAX_PBKDF2_ITERATIONS
            )));
        }
        let key = crate::encryption::derive_key_pbkdf2_with_prf(
            password.as_bytes(),
            &salt,
            iterations,
            prf,
        );

        // Decrypt the SEED bytes (64 bytes). Validate length explicitly
        // — anything else means corrupt or wrong-format file.
        let seed_bytes = crate::encryption::decrypt(&key, &iv, &ciphertext, &auth_tag)?;
        let seed: zeroize::Zeroizing<[u8; 64]> =
            zeroize::Zeroizing::new(seed_bytes.as_slice().try_into().map_err(|_| {
                WalletError::SecretFile(format!(
                    "decrypted seed must be 64 bytes, got {}",
                    seed_bytes.len(),
                ))
            })?);

        Ok(seed)
    }

    /// Unlock the wallet using the given password. Loads + decrypts
    /// the secret file, recovers the BIP39 seed bytes, derives the
    /// master key, stores it in memory for later use. No
    /// `mnemonic_pass` argument — the passphrase was mixed into the
    /// seed at `init`/`restore` time and is "baked in".
    ///
    /// A successful unlock of a version-1 file, or of a version-2 file
    /// weaker than [`new_keystore_kdf`], rewrites it in place in the current
    /// version-2 format. The rewrite is atomic: the directory always holds
    /// exactly one complete secret file. A failed rewrite does not fail the
    /// unlock; [`Self::take_keystore_upgrade`] reports either outcome.
    pub fn unlock(&mut self, password: &str) -> Result<(), WalletError> {
        // Load the secret file if not cached.
        if self.cached_secret_file.is_none() {
            let path = Self::find_secret_file(&self.secret_dir)?;
            self.cached_secret_file = Some(Self::read_secret_file(&path)?);
            self.cached_secret_path = Some(path);
        }
        let secret = self.cached_secret_file.as_ref().unwrap();

        let seed = secret.decrypt_seed(password)?;

        // Derive the master key directly from the seed bytes — no
        // mnemonic involvement at unlock time. Branch on use_pre_1627
        // to construct the correct master-key variant.
        let use_pre_1627 = secret.use_pre_1627();
        let upgrade_from = secret.needs_upgrade().then(|| secret.version());
        let master = if use_pre_1627 {
            UnlockedMaster::Legacy(
                crate::extended_key::ExtendedSecretKeyLegacy::derive_master_key(seed.as_slice())?,
            )
        } else {
            UnlockedMaster::Modern(ExtendedSecretKey::derive_master_key(seed.as_slice())?)
        };

        self.unlocked = Some(UnlockedSecret {
            master,
            use_pre_1627,
        });
        if let Some(from_version) = upgrade_from {
            self.upgrade = Some(match self.rewrite_current(&seed, password, use_pre_1627) {
                Ok(()) => KeystoreUpgrade::Upgraded { from_version },
                Err(error) => KeystoreUpgrade::Failed(error.to_string()),
            });
        }
        Ok(())
    }

    /// Take the outcome of the automatic upgrade attempted by the last unlock.
    pub fn take_keystore_upgrade(&mut self) -> Option<KeystoreUpgrade> {
        self.upgrade.take()
    }

    /// Re-encrypt the unlocked seed in the current format and atomically
    /// replace the cached file at its path.
    fn rewrite_current(
        &mut self,
        seed: &[u8; 64],
        password: &str,
        use_pre_1627: bool,
    ) -> Result<(), WalletError> {
        let path = self
            .cached_secret_path
            .clone()
            .ok_or_else(|| WalletError::SecretFile("secret file path unknown".to_string()))?;
        let secret = EncryptedSecretV2::encrypt(seed, password, use_pre_1627, new_keystore_kdf())?;
        let json = serde_json::to_vec_pretty(&secret)
            .map_err(|e| WalletError::SecretFile(format!("serialize: {e}")))?;
        replace_secret_file(&path, &json)?;
        self.cached_secret_file = Some(KeystoreFile::V2(secret));
        Ok(())
    }

    /// Bind the unlocked master to the wallet's persisted `(pubkey, path)`
    /// keys before anything derives from it. The complete-master derivation is
    /// used when it reproduces every key. A legacy wallet whose keys were all
    /// written by the earlier Rust trimmed-master derivation keeps that
    /// derivation for this unlock, so signing, key export and new addresses
    /// stay on the tree that holds its funds. The persisted keys determine the
    /// choice at every unlock. Any other mismatch is
    /// [`WalletError::TrackedKeyMismatch`].
    pub fn bind_tracked_keys(
        &mut self,
        tracked: &[([u8; 33], Vec<u32>)],
    ) -> Result<MasterDerivation, WalletError> {
        let unlocked = self.unlocked.as_mut().ok_or(WalletError::WalletLocked)?;
        let Some(mismatch) = unlocked.master.first_mismatch(tracked)? else {
            return Ok(MasterDerivation::Standard);
        };
        if let Some(trimmed) = unlocked.master.legacy_rust_trimmed() {
            if trimmed.first_mismatch(tracked)?.is_none() {
                unlocked.master = trimmed;
                return Ok(MasterDerivation::LegacyRustTrimmed);
            }
        }
        Err(WalletError::TrackedKeyMismatch(mismatch.to_string()))
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
            crate::extended_key::ExtendedSecretKeyLegacy::derive_master_key(&seed[..])
                .and_then(|m| m.public_key().map(|p| p.compressed_bytes()))
        } else {
            ExtendedSecretKey::derive_master_key(&seed[..])
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
    pub fn cached_file(&self) -> Option<&KeystoreFile> {
        self.cached_secret_file.as_ref()
    }

    /// Internal: encrypt the BIP39 seed bytes (64 bytes) in the current
    /// version-2 format and write to disk. Like Scala `JsonSecretStorage`,
    /// the file holds the encrypted seed — NOT the mnemonic phrase.
    fn persist_seed(
        &mut self,
        seed: &[u8; 64],
        password: &str,
        use_pre_1627: bool,
    ) -> Result<(), WalletError> {
        self.require_uninitialized()?;
        create_secret_directory(&self.secret_dir)
            .map_err(|e| WalletError::SecretFile(format!("create secret directory: {e}")))?;
        let secret = EncryptedSecretV2::encrypt(seed, password, use_pre_1627, new_keystore_kdf())?;
        let json = serde_json::to_string_pretty(&secret)
            .map_err(|e| WalletError::SecretFile(format!("serialize: {e}")))?;
        let secret = KeystoreFile::V2(secret);
        let path = self
            .secret_dir
            .join(filename_for_ciphertext(&secret.cipher_text_bytes()?));
        publish_secret_file(&path, json.as_bytes())?;
        self.cached_secret_file = Some(secret);
        self.cached_secret_path = Some(path);
        Ok(())
    }

    /// Internal: write the seed in the Scala/Appkit version-1 format
    /// (PBKDF2-HMAC-SHA256, 128,000 iterations). Used only for exports.
    fn persist_seed_v1(
        &mut self,
        seed: &[u8; 64],
        password: &str,
        use_pre_1627: bool,
    ) -> Result<(), WalletError> {
        // Recheck after seed derivation, before touching the directory or cache.
        self.require_uninitialized()?;
        create_secret_directory(&self.secret_dir)
            .map_err(|e| WalletError::SecretFile(format!("create secret directory: {e}")))?;

        // Generate random 32-byte salt + 12-byte IV. Salt size matches
        // Scala `AES.encrypt` (32 bytes).
        let mut salt = [0u8; 32];
        let mut iv = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut iv);

        // Java PBEKeySpec encodes the password as UTF-8 for these PRFs.
        let key = crate::encryption::derive_key_pbkdf2_with_prf(
            password.as_bytes(),
            &salt,
            128_000,
            crate::encryption::Pbkdf2Prf::HmacSha256,
        );
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
        publish_secret_file(&path, json.as_bytes())?;

        // Cache so subsequent unlock() doesn't re-read the file.
        self.cached_secret_file = Some(KeystoreFile::V1(secret));
        self.cached_secret_path = Some(path);
        Ok(())
    }
}

/// Newly created parent names need their own durability barriers; syncing
/// only the final wallet directory would not persist its entry in its parent.
fn create_secret_directory(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    let missing: Vec<_> = dir
        .ancestors()
        .take_while(|ancestor| !ancestor.as_os_str().is_empty() && !ancestor.exists())
        .map(Path::to_path_buf)
        .collect();
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    #[cfg(unix)]
    for created in missing.iter().rev() {
        std::fs::File::open(created)?.sync_all()?;
        let parent = created
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Publish only complete encrypted files. NamedTempFile creates owner-only
/// files on Unix; persist_noclobber never overwrites an existing wallet.
/// The file is synced before publication and the containing directory is
/// synced on Unix. Windows retains file sync + no-replace publication; Rust does
/// not expose a portable directory durability barrier there.
fn publish_secret_file(path: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    publish_secret_file_with(path, bytes, |_| Ok(()))
}

/// Atomically replace an existing secret file with complete new contents.
/// The replacement is written and synced beside the original and renamed
/// over it, so a crash leaves either the old or the new complete file.
fn replace_secret_file(path: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    use std::io::Write;
    let replace = || -> std::io::Result<()> {
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("missing secret directory"))?;
        let mut pending = tempfile::Builder::new()
            .prefix(".ergo-wallet-pending-")
            .tempfile_in(dir)?;
        pending.write_all(bytes)?;
        pending.as_file().sync_all()?;
        let replaced = pending.persist(path).map_err(|error| error.error)?;
        replaced.sync_all()?;
        #[cfg(unix)]
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    };
    replace().map_err(|error| WalletError::SecretFile(format!("replace {path:?}: {error}")))
}

fn publish_secret_file_with(
    path: &Path,
    bytes: &[u8],
    mut checkpoint: impl FnMut(&str) -> std::io::Result<()>,
) -> Result<(), WalletError> {
    use std::io::Write;
    let mut publish = || -> std::io::Result<()> {
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("missing secret directory"))?;
        let mut pending = tempfile::Builder::new()
            .prefix(".ergo-wallet-pending-")
            .tempfile_in(dir)?;
        pending.write_all(bytes)?;
        checkpoint("write")?;
        pending.as_file().sync_all()?;
        checkpoint("sync")?;
        let published = pending
            .persist_noclobber(path)
            .map_err(|error| error.error)?;
        published.sync_all()?;
        checkpoint("publish")?;
        #[cfg(unix)]
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    };
    publish().map_err(|error| WalletError::SecretFile(format!("publish {path:?}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn new_secret_directory_parents_are_private_and_wallet_reopens() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("new-parent");
        let path = parent.join("wallet");
        let mut storage = SecretStorage::open(path.clone());
        storage
            .restore(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "",
                "test-password",
                false,
            )
            .unwrap();
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        SecretStorage::open(path).unlock("test-password").unwrap();
    }

    // ----- helpers -----

    #[test]
    fn secret_publication_failures_before_publish_leave_retryable_directory() {
        for failed_stage in ["write", "sync"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("complete.json");
            let result = publish_secret_file_with(&path, b"complete encrypted wallet", |stage| {
                if stage == failed_stage {
                    Err(std::io::Error::other("injected publication failure"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err());
            assert!(!path.exists());
            assert!(matches!(
                SecretStorage::find_secret_file(directory.path()),
                Err(WalletError::WalletUninitialized)
            ));
            publish_secret_file(&path, b"complete encrypted wallet").unwrap();
            assert_eq!(std::fs::read(path).unwrap(), b"complete encrypted wallet");
        }
    }

    #[test]
    fn secret_publication_never_replaces_existing_file_or_discovers_pending_files() {
        let directory = tempfile::tempdir().unwrap();
        let pending = directory.path().join(".ergo-wallet-pending-crashed-writer");
        std::fs::write(&pending, b"partial").unwrap();
        assert!(matches!(
            SecretStorage::find_secret_file(directory.path()),
            Err(WalletError::WalletUninitialized)
        ));
        let path = directory.path().join("wallet.json");
        publish_secret_file(&path, b"first wallet").unwrap();
        assert!(publish_secret_file(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first wallet");
        assert_eq!(
            SecretStorage::find_secret_file(directory.path()).unwrap(),
            path
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn secret_publication_failure_after_publish_retains_complete_recoverable_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.json");
        assert!(
            publish_secret_file_with(&path, b"complete wallet", |stage| {
                if stage == "publish" {
                    Err(std::io::Error::other("injected directory sync failure"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(std::fs::read(path).unwrap(), b"complete wallet");
    }

    // ----- happy path -----

    #[test]
    fn scala_default_cipher_params_serialize_correctly() {
        let cp = CipherParams::scala_default();
        let json = serde_json::to_string(&cp).unwrap();
        // Field order: prf, c, dkLen, encryptionAlgorithm, encryptionMode
        assert_eq!(
            json,
            r#"{"prf":"HmacSHA256","c":128000,"dkLen":256,"encryptionAlgorithm":"AES","encryptionMode":"GCM"}"#,
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
    fn repeated_init_and_restore_preserve_locked_unlocked_and_reopened_wallets() {
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        for mode in ["locked", "unlocked", "reopened"] {
            let dir = tempfile::tempdir().unwrap();
            let mut storage = SecretStorage::open(dir.path().to_path_buf());
            storage
                .restore(PHRASE, "", "original-password", false)
                .unwrap();
            let path = SecretStorage::find_secret_file(dir.path()).unwrap();
            let original_bytes = fs::read(&path).unwrap();
            if mode == "unlocked" {
                storage.unlock("original-password").unwrap();
            } else if mode == "reopened" {
                storage = SecretStorage::open(dir.path().to_path_buf());
            }
            let original_state = storage.lock_state();
            let cached_before = storage
                .cached_file()
                .map(|s| serde_json::to_string(s).unwrap());
            assert!(matches!(
                storage.init(
                    crate::mnemonic::MnemonicStrength::Words12,
                    "new-password",
                    ""
                ),
                Err(WalletError::WalletAlreadyInitialized)
            ));
            assert!(matches!(
                storage.restore(PHRASE, "different-seed", "new-password", true),
                Err(WalletError::WalletAlreadyInitialized)
            ));
            assert_eq!(storage.lock_state(), original_state);
            assert_eq!(
                storage
                    .cached_file()
                    .map(|s| serde_json::to_string(s).unwrap()),
                cached_before
            );
            assert_eq!(fs::read(&path).unwrap(), original_bytes);
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
            if mode == "unlocked" {
                assert!(
                    storage.check_seed(PHRASE, ""),
                    "the original unlocked master survives refusal"
                );
            }
            storage.lock();
            SecretStorage::open(dir.path().to_path_buf())
                .unlock("original-password")
                .unwrap();
        }
    }

    #[test]
    fn initialization_refuses_corrupt_existing_files_and_directory_read_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.json");
        fs::write(&path, b"existing malformed wallet").unwrap();
        let mut storage = SecretStorage::open(dir.path().to_path_buf());
        assert!(matches!(
            storage.init(crate::mnemonic::MnemonicStrength::Words12, "pw", ""),
            Err(WalletError::WalletAlreadyInitialized)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"existing malformed wallet");

        let mut wrong_directory = SecretStorage::open(path.clone());
        assert!(matches!(
            wrong_directory.init(crate::mnemonic::MnemonicStrength::Words12, "pw", ""),
            Err(WalletError::SecretFile(_))
        ));
        assert_eq!(fs::read(path).unwrap(), b"existing malformed wallet");
    }

    #[cfg(unix)]
    #[test]
    fn init_creates_secret_file_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let mut storage = SecretStorage::open(tmp.path().to_path_buf());

        storage
            .init(
                crate::mnemonic::MnemonicStrength::Words24,
                "test-password",
                "",
            )
            .expect("init must succeed");

        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        let mode = entries[0].metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "secret file must be created with 0o600, never a wider default"
        );
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
             the passphrase is being dropped",
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

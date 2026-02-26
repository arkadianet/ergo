//! HD key derivation for Ergo wallets (BIP-32 / EIP-3).
//!
//! Wraps `ergo_lib::wallet::ext_secret_key::ExtSecretKey` to derive child keys
//! following the EIP-3 derivation path: `m/44'/429'/0'/0/{index}`.

use ergo_lib::wallet::derivation_path::DerivationPath;
use ergo_lib::wallet::ext_secret_key::ExtSecretKey;
use ergo_lib::wallet::mnemonic::Mnemonic;
use ergo_lib::wallet::secret_key::SecretKey;
use ergotree_ir::chain::address::{Address, NetworkAddress, NetworkPrefix};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by [`WalletKeys`] operations.
#[derive(Error, Debug)]
pub enum KeysError {
    /// Key derivation failed.
    #[error("key derivation error: {0}")]
    Derivation(String),

    /// Invalid derivation path string.
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),
}

// ---------------------------------------------------------------------------
// DerivedKey
// ---------------------------------------------------------------------------

/// A derived child key with its index, full derivation path, and encoded address.
pub struct DerivedKey {
    /// The derivation index (the final component of the path).
    pub index: u32,
    /// The full BIP-32 derivation path string (e.g. `m/44'/429'/0'/0/0`).
    pub path: String,
    /// The base58-encoded P2PK Ergo address (mainnet).
    pub address: String,
}

// ---------------------------------------------------------------------------
// WalletKeys
// ---------------------------------------------------------------------------

/// EIP-3 prefix: `m/44'/429'/0'/0`
const EIP3_PREFIX: &str = "m/44'/429'/0'/0";

/// HD key manager. Holds the master `ExtSecretKey` and derives child keys.
pub struct WalletKeys {
    master: ExtSecretKey,
}

impl WalletKeys {
    /// Derive the master extended secret key from a BIP-39 mnemonic phrase.
    ///
    /// `mnemonic_pass` is the optional mnemonic passphrase (often empty).
    pub fn from_mnemonic(mnemonic: &str, mnemonic_pass: &str) -> Result<Self, KeysError> {
        let seed = Mnemonic::to_seed(mnemonic, mnemonic_pass);
        let master = ExtSecretKey::derive_master(seed)
            .map_err(|e| KeysError::Derivation(e.to_string()))?;
        Ok(Self { master })
    }

    /// Derive a child key at EIP-3 index: `m/44'/429'/0'/0/{index}`.
    pub fn derive_at(&self, index: u32) -> Result<DerivedKey, KeysError> {
        let path_str = format!("{}/{}", EIP3_PREFIX, index);
        self.derive_path(&path_str)
    }

    /// Derive a child key from an arbitrary BIP-32 path string (e.g. `"m/44'/429'/0'/0/5"`).
    pub fn derive_path(&self, path_str: &str) -> Result<DerivedKey, KeysError> {
        let dp: DerivationPath = path_str
            .parse()
            .map_err(|e| KeysError::InvalidPath(format!("{}: {}", path_str, e)))?;

        let child = self
            .master
            .derive(dp)
            .map_err(|e| KeysError::Derivation(e.to_string()))?;

        let ext_pub = child
            .public_key()
            .map_err(|e| KeysError::Derivation(e.to_string()))?;

        let address: Address = ext_pub.into();
        let net_addr = NetworkAddress::new(NetworkPrefix::Mainnet, &address);

        // Extract the last path component as the index, defaulting to 0.
        let index = path_str
            .rsplit('/')
            .next()
            .and_then(|s| s.trim_end_matches('\'').parse::<u32>().ok())
            .unwrap_or(0);

        Ok(DerivedKey {
            index,
            path: path_str.to_string(),
            address: net_addr.to_base58(),
        })
    }

    /// Return secret keys for the given EIP-3 derivation indices.
    ///
    /// This is used when signing transactions — each index maps to
    /// `m/44'/429'/0'/0/{index}`.
    pub fn secret_keys(&self, indices: &[u32]) -> Result<Vec<SecretKey>, KeysError> {
        indices
            .iter()
            .map(|&idx| {
                let path_str = format!("{}/{}", EIP3_PREFIX, idx);
                let dp: DerivationPath = path_str
                    .parse()
                    .map_err(|e| KeysError::InvalidPath(format!("{}: {}", path_str, e)))?;
                let child = self
                    .master
                    .derive(dp)
                    .map_err(|e| KeysError::Derivation(e.to_string()))?;
                Ok(child.secret_key())
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-known test mnemonic (the "slow silly start" vector from ergo-lib tests).
    const TEST_MNEMONIC: &str =
        "slow silly start wash bundle suffer bulb ancient height spin express remind today effort helmet";

    #[test]
    fn from_mnemonic_derives_master() {
        let keys = WalletKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        // Master key should have derivation path depth 0 (root).
        assert_eq!(keys.master.path().depth(), 0);
    }

    #[test]
    fn derive_at_produces_address() {
        let keys = WalletKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let dk = keys.derive_at(0).unwrap();

        // Must be a non-empty base58 string starting with '9' (mainnet P2PK prefix).
        assert!(!dk.address.is_empty());
        assert!(
            dk.address.starts_with('9'),
            "expected mainnet P2PK address starting with '9', got: {}",
            dk.address
        );
        assert_eq!(dk.index, 0);
        assert_eq!(dk.path, "m/44'/429'/0'/0/0");

        // Cross-check with the known test vector from ergo-lib.
        assert_eq!(dk.address, "9eatpGQdYNjTi5ZZLK7Bo7C3ms6oECPnxbQTRn6sDcBNLMYSCa8");
    }

    #[test]
    fn derive_different_indices_different_addresses() {
        let keys = WalletKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let dk0 = keys.derive_at(0).unwrap();
        let dk1 = keys.derive_at(1).unwrap();

        assert_ne!(dk0.address, dk1.address);
        assert_eq!(dk0.index, 0);
        assert_eq!(dk1.index, 1);

        // Cross-check index 1 with known test vector.
        assert_eq!(dk1.address, "9iBhwkjzUAVBkdxWvKmk7ab7nFgZRFbGpXA9gP6TAoakFnLNomk");
    }

    #[test]
    fn derive_path_custom() {
        let keys = WalletKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let dk = keys.derive_path("m/44'/429'/0'/0/0").unwrap();

        assert!(dk.address.starts_with('9'));
        assert_eq!(dk.path, "m/44'/429'/0'/0/0");
    }

    #[test]
    fn secret_keys_returns_correct_count() {
        let keys = WalletKeys::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let sks = keys.secret_keys(&[0, 1, 2]).unwrap();
        assert_eq!(sks.len(), 3);

        // Each secret key should be distinct.
        let bytes: Vec<Vec<u8>> = sks.iter().map(|sk| sk.to_bytes()).collect();
        assert_ne!(bytes[0], bytes[1]);
        assert_ne!(bytes[1], bytes[2]);
        assert_ne!(bytes[0], bytes[2]);
    }
}

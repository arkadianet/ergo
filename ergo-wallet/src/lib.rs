//! Ergo HD wallet.
//!
//! Covers BIP-39 mnemonics and EIP-3 key derivation (post- and
//! pre-1627), AES-GCM / PBKDF2 encrypted secret storage, sigma
//! proving (single- and multi-sig with hint-bag inputs),
//! transaction building, and box selection. Convenience re-exports
//! (`Mnemonic`, `ExtendedSecretKey`, `DerivationPath`, `SecretKey`,
//! `WalletError`) live at the crate root.

pub mod address;
pub mod box_selector;
pub mod derivation;
pub mod encryption;
pub mod error;
pub mod extended_key;
pub mod mnemonic;
pub mod proving;
pub mod scan;
pub mod secret;
pub mod state;
pub mod storage;
pub mod tx_builder;
pub mod tx_context;

pub use derivation::DerivationPath;
pub use error::WalletError;
pub use extended_key::{ExtendedPublicKey, ExtendedSecretKey};
pub use mnemonic::Mnemonic;
pub use secret::SecretKey;
pub use state::WalletState;
pub use storage::{
    EncryptedSecret, LockState as WalletLockState, SecretStorage, UnlockedMaster, UnlockedSecret,
};

/// Derive the standard EIP-3 first-address public key
/// (`m/44'/429'/0'/0/0`) from a BIP39 seed using post-1627
/// (modern Ergo) derivation. Returns the 33-byte compressed SEC1
/// pubkey — exactly what `[mining] miner_public_key_hex` expects
/// (hex-encoded).
///
/// Always uses post-1627 (modern) derivation; the legacy
/// pre-Sigma-5.0 path is exposed via
/// `ExtendedSecretKey::derive_master_key(seed, true)` for callers
/// importing pre-1627 wallets.
pub fn miner_pubkey_for_seed(seed: &[u8]) -> Result<[u8; 33], error::WalletError> {
    let master = extended_key::ExtendedSecretKey::derive_master_key(seed, false)?;
    let leaf = master.derive_at_path(&derivation::DerivationPath::eip3_first_address())?;
    Ok(leaf.public_key().compressed_bytes())
}

#[cfg(test)]
mod lib_tests {
    use super::miner_pubkey_for_seed;
    use crate::Mnemonic;

    // ----- happy path -----

    #[test]
    fn miner_pubkey_for_known_mnemonic_is_33_bytes_compressed() {
        let m = Mnemonic::import(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed = m.to_seed("");
        let pk = miner_pubkey_for_seed(&seed).unwrap();
        let hex = hex::encode(pk);
        assert_eq!(hex.len(), 66, "33 bytes hex = 66 chars");
        assert!(
            hex.starts_with("02") || hex.starts_with("03"),
            "compressed SEC1 starts with 02 or 03, got {hex:?}",
        );
    }
}

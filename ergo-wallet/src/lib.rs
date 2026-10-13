//! Ergo HD wallet.
//!
//! Covers BIP-39 mnemonics and EIP-3 key derivation (post- and
//! pre-1627), AES-GCM / PBKDF2 encryption, transaction selection/building, and
//! Sigma proving with full contract reduction against an explicit signing
//! context, and a conservative gate for synthetic contexts. File-backed secret
//! storage requires `keystore`; the command-line binary requires `cli`.
//! Orchestration modules live in `ergo-wallet-service`. Convenience
//! re-exports (`Mnemonic`, `ExtendedSecretKey`, `DerivationPath`, `SecretKey`,
//! `WalletError`) live at the crate root.

pub mod address;
pub mod box_selector;
pub mod derivation;
pub mod encryption;
pub mod error;
pub mod extended_key;
pub mod master;
pub mod mnemonic;
pub mod proving;
pub mod reduced;
mod reduced_message;
pub mod secret;
#[cfg(feature = "keystore")]
pub mod storage;
pub mod tx_builder;
pub mod tx_context;

pub use derivation::DerivationPath;
pub use error::WalletError;
pub use extended_key::{ExtendedPublicKey, ExtendedSecretKey, ExtendedSecretKeyLegacy};
pub use master::{UnlockedMaster, UnlockedSecret};
pub use mnemonic::Mnemonic;
pub use reduced::{ReducedInput, ReducedTransaction};
pub use secret::SecretKey;
#[cfg(feature = "keystore")]
pub use storage::{EncryptedSecret, LockState as WalletLockState, SecretStorage};

/// Derive the standard EIP-3 first-address public key
/// (`m/44'/429'/0'/0/0`) from a BIP39 seed using post-1627
/// (modern Ergo) derivation. Returns the 33-byte compressed SEC1
/// pubkey — exactly what `[mining] miner_public_key_hex` expects
/// (hex-encoded).
///
/// Always uses post-1627 (modern) derivation; the legacy
/// pre-Sigma-5.0 path is exposed via
/// [`ExtendedSecretKeyLegacy::derive_master_key`] for callers importing
/// pre-1627 wallets. The key type retains the selected child derivation mode.
pub fn miner_pubkey_for_seed(seed: &[u8]) -> Result<[u8; 33], error::WalletError> {
    let master = extended_key::ExtendedSecretKey::derive_master_key(seed)?;
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
        let pk = miner_pubkey_for_seed(&seed[..]).unwrap();
        let hex = hex::encode(pk);
        assert_eq!(hex.len(), 66, "33 bytes hex = 66 chars");
        assert!(
            hex.starts_with("02") || hex.starts_with("03"),
            "compressed SEC1 starts with 02 or 03, got {hex:?}",
        );
    }
}

//! BIP39 mnemonic — generation, import, seed derivation.
//!
//! Uses the `bip39` crate for the wordlist and checksum (standardised
//! cryptographic primitive; not worth re-implementing). Adds an
//! Ergo-side wrapper so callers get a `Mnemonic` newtype that won't
//! `Display` the words accidentally and that integrates with our
//! `WalletError` type.

use crate::error::WalletError;
use bip39::Mnemonic as Bip39Mnemonic;

/// Allowed mnemonic strengths per BIP39. Words12 / Words15 / Words18 /
/// Words21 / Words24 correspond to entropy sizes 128 / 160 / 192 / 224 /
/// 256 bits. Most Ergo wallets use 15 or 24 — both are widely supported
/// by external wallets we want to be import/export-compatible with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicStrength {
    Words12,
    Words15,
    Words18,
    Words21,
    Words24,
}

impl MnemonicStrength {
    /// Entropy size in bytes corresponding to this strength.
    fn entropy_bytes(self) -> usize {
        match self {
            Self::Words12 => 16,
            Self::Words15 => 20,
            Self::Words18 => 24,
            Self::Words21 => 28,
            Self::Words24 => 32,
        }
    }
}

/// BIP39 mnemonic phrase. Wraps the underlying `bip39::Mnemonic` so
/// callers can't accidentally print the words via `Debug` (the inner
/// type's `Debug` IS the phrase — we hide it).
pub struct Mnemonic {
    inner: Bip39Mnemonic,
}

impl Mnemonic {
    /// Generate a fresh mnemonic from the OS RNG.
    pub fn generate(strength: MnemonicStrength) -> Result<Self, WalletError> {
        let entropy_len = strength.entropy_bytes();
        let mut entropy = vec![0u8; entropy_len];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);
        let inner = Bip39Mnemonic::from_entropy(&entropy)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Import an existing mnemonic phrase. Validates BIP39 checksum.
    /// Whitespace is normalised (single space between words).
    pub fn import(phrase: &str) -> Result<Self, WalletError> {
        let inner = Bip39Mnemonic::parse(phrase)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        Ok(Self { inner })
    }

    /// The mnemonic phrase as a space-separated string. CAUTION: do not
    /// log or display this in production code — it IS the wallet seed
    /// material.
    pub fn phrase(&self) -> String {
        self.inner.to_string()
    }

    /// Derive the 64-byte BIP39 seed from this mnemonic, with an
    /// optional passphrase. BIP39 spec mandates NFKD normalisation on
    /// the passphrase; the `bip39` crate handles that internally so
    /// we don't need to re-implement it here.
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        self.inner.to_seed(passphrase)
    }
}

// Custom Debug that does NOT print the phrase, to prevent accidental
// leaks via `dbg!()`, `println!("{m:?}")`, or `tracing::debug!`.
impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mnemonic")
            .field("phrase", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn generate_24_word_mnemonic_has_24_words() {
        let m = Mnemonic::generate(MnemonicStrength::Words24).expect("generate");
        let word_count = m.phrase().split_whitespace().count();
        assert_eq!(word_count, 24, "24-word mnemonic must produce 24 words");
    }

    #[test]
    fn import_known_mnemonic_round_trips_phrase() {
        // BIP39 English vector 1 — entropy 0x00000000000000000000000000000000.
        let words = "abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon about";
        let m = Mnemonic::import(words).expect("known-valid mnemonic must import");
        // Phrase normalisation should be idempotent.
        let normalised: String = words.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(m.phrase(), normalised);
    }

    #[test]
    fn import_bad_checksum_returns_invalid_mnemonic() {
        // Same as above but last word swapped to break the checksum.
        let words = "abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon";
        let err = Mnemonic::import(words).expect_err("bad checksum must fail");
        assert!(matches!(err, WalletError::InvalidMnemonic(_)));
    }
}

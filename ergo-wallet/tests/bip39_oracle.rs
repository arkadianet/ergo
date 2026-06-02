//! BIP39 standard English test vectors.
//!
//! Source: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
//! These are the canonical multi-language test vectors used by every
//! BIP39 implementation in production. We pin one pre-published
//! canonical case (12-word zero-entropy) plus NFKD + RNG guards.
//!
//! Provenance: BIP39 spec test vectors, ENGLISH wordlist. NOT a
//! self-oracle — these are external standardised vectors.

use ergo_wallet::mnemonic::Mnemonic;

// ----- oracle parity -----

/// BIP39 vector: entropy 00000000000000000000000000000000 (128 bits) →
/// "abandon abandon abandon abandon abandon abandon abandon abandon
///  abandon abandon abandon about" → known 64-byte seed with passphrase "TREZOR".
#[test]
fn bip39_vector_12_words_zero_entropy() {
    let words = "abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon about";
    let m = Mnemonic::import(words).expect("vector mnemonic must import");
    let seed = m.to_seed("TREZOR");
    let expected_seed_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531\
         f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    assert_eq!(
        hex::encode(seed),
        expected_seed_hex,
        "BIP39 12-word zero-entropy seed must match the canonical vector",
    );
}

/// BIP39 requires NFKD normalisation on the passphrase before the
/// PBKDF2 seed derivation. The `bip39` crate handles this internally;
/// this test confirms that contract by feeding a passphrase that
/// differs from its NFKD form only in unicode normalisation and
/// asserting the seed equals the seed for the NFKD-normalised form.
///
/// Specifically: U+00E9 (é, single code point) and U+0065 U+0301
/// (e + combining acute accent) MUST produce the same seed after NFKD.
#[test]
fn passphrase_nfkd_normalisation_holds() {
    let words = "abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon about";
    let m = Mnemonic::import(words).expect("vector mnemonic must import");
    let seed_precomposed = m.to_seed("café"); // é = U+00E9
    let seed_decomposed = m.to_seed("cafe\u{0301}"); // e + combining acute
    assert_eq!(
        hex::encode(seed_precomposed),
        hex::encode(seed_decomposed),
        "BIP39 passphrase must be NFKD-normalised before PBKDF2; \
         precomposed and decomposed forms of 'café' must yield the \
         same seed",
    );
}

/// Two `Mnemonic::generate` calls in succession must produce
/// different mnemonics. Catches a wallet bug where the RNG source
/// is accidentally seeded with a constant (e.g., `rand::SeedableRng`
/// from a fixed seed) or where the entropy fill is a no-op.
/// Probability of legitimate collision: ~2^-256.
#[test]
fn generate_uses_os_entropy_not_deterministic_rng() {
    use ergo_wallet::mnemonic::MnemonicStrength;
    let a = Mnemonic::generate(MnemonicStrength::Words24).unwrap();
    let b = Mnemonic::generate(MnemonicStrength::Words24).unwrap();
    assert_ne!(
        a.phrase(),
        b.phrase(),
        "two generate() calls must produce different mnemonics — \
         if equal, the RNG is deterministic and every wallet ever \
         created by this code shares the same seed",
    );
}

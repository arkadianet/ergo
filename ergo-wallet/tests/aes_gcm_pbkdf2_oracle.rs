//! Scala-parity oracle for the AES-256-GCM + PBKDF2-HMAC-SHA512
//! pipeline. Vectors extracted by running Scala
//! `AES.encrypt(plaintext, password, salt, iv)` and capturing the
//! resulting `(ciphertext, authTag)` pair.
//!
//! IMPORTANT: These tests are #[ignore]'d because they require
//! engineer-time extraction of (ciphertext, authTag) values from a
//! running Scala v6.0.3+ node. Per spec §15 Tier-1 rules: "no
//! shipping without external test vectors". An engineer must extract
//! the vectors and replace the `<EXTRACT_FROM_SCALA>` placeholders
//! before this oracle can pass.
//!
//! Extraction approach:
//! 1. Run Scala `org.ergoplatform.wallet.crypto.AESSpec` with
//!    verbose logging, OR
//! 2. Write a one-shot Scala script calling
//!    `AES.encrypt(plaintext, password, salt, iv)` with the inputs
//!    below and capture (ciphertext_hex, auth_tag_hex).
//!
//! Once vectors are populated, REMOVE the `#[ignore]` attributes.

use ergo_wallet::encryption::{decrypt, derive_key_pbkdf2, encrypt};

// ----- oracle parity -----

/// Vector 1: short ASCII plaintext, ASCII password, 16-byte salt,
/// 12-byte IV. Captures the small-input edge case.
#[test]
#[ignore = "needs Scala-extracted (ciphertext, authTag) — see file header"]
fn scala_aes_gcm_vector_1_short_ascii() {
    let password = b"correct horse battery staple";
    let salt: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
        .unwrap()
        .try_into()
        .unwrap();
    let iv: [u8; 12] = hex::decode("0a0b0c0d0e0f000102030405")
        .unwrap()
        .try_into()
        .unwrap();
    let plaintext = b"hello, scala parity test";

    let expected_ciphertext_hex: &str = "<EXTRACT_FROM_SCALA>";
    let expected_auth_tag_hex: &str = "<EXTRACT_FROM_SCALA>";

    let key = derive_key_pbkdf2(password, &salt, 128000);
    let (ct, tag) = encrypt(&key, &iv, plaintext).unwrap();
    assert_eq!(
        hex::encode(&ct),
        expected_ciphertext_hex,
        "ciphertext drift from Scala AES.encrypt vector 1",
    );
    assert_eq!(
        hex::encode(tag),
        expected_auth_tag_hex,
        "auth tag drift from Scala AES.encrypt vector 1",
    );

    // Sanity: decrypt produces plaintext.
    let recovered = decrypt(&key, &iv, &ct, &tag).unwrap();
    assert_eq!(recovered.as_slice(), plaintext);
}

/// Vector 2: longer plaintext (a realistic-sized ErgoTree + extras).
#[test]
#[ignore = "needs Scala-extracted (ciphertext, authTag) — see file header"]
fn scala_aes_gcm_vector_2_long_payload() {
    let password = b"another password";
    let salt: [u8; 16] = hex::decode("ffeeddccbbaa99887766554433221100")
        .unwrap()
        .try_into()
        .unwrap();
    let iv: [u8; 12] = hex::decode("aabbccddeeff001122334455")
        .unwrap()
        .try_into()
        .unwrap();
    let plaintext_hex = "deadbeef".repeat(40);
    let plaintext = hex::decode(&plaintext_hex).unwrap();

    let expected_ciphertext_hex: &str = "<EXTRACT_FROM_SCALA>";
    let expected_auth_tag_hex: &str = "<EXTRACT_FROM_SCALA>";

    let key = derive_key_pbkdf2(password, &salt, 128000);
    let (ct, tag) = encrypt(&key, &iv, &plaintext).unwrap();
    assert_eq!(hex::encode(&ct), expected_ciphertext_hex);
    assert_eq!(hex::encode(tag), expected_auth_tag_hex);
}

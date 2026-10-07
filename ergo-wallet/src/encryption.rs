//! Encryption primitives for the encrypted-secret-file format.
//!
//! Scala parity: `AES.scala:62` defines the cipher parameters we
//! match byte-for-byte. PBKDF2-HMAC-SHA512 with 128,000 iterations
//! produces a 32-byte key; AES-256-GCM with a fresh 96-bit IV per
//! encryption produces ciphertext followed by a 16-byte GCM tag. Scala's
//! JSON format calls the first 16 bytes of that stream `authTag` and the
//! remainder `cipherText`; these historical names do not describe the GCM
//! components. Imports also accept the layout written by earlier Rust releases.
//!
//! Owned derived keys and decrypted plaintext are wrapped in
//! `zeroize::Zeroizing` and wiped on drop, including error paths. This does
//! not prevent copies in cryptographic implementations, registers, swap or
//! process dumps while values are alive; plaintext input remains caller-owned.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use zeroize::Zeroizing;

/// PBKDF2-HMAC-SHA512 password → key derivation. Matches Scala
/// `AES.scala:62` parameters: 128,000 iterations (typically), 32-byte
/// output. The caller passes the iteration count explicitly so this
/// helper is reusable for both encryption (uses 128k) and the
/// `cipherParams.c` field of the encrypted secret file (which the
/// loader respects).
///
/// Returns a `Zeroizing<[u8; 32]>` so the derived key is zeroed when
/// it goes out of scope. Callers MUST NOT copy this out into a plain
/// `[u8; 32]` without re-wrapping.
pub fn derive_key_pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha512>(password, salt, iterations, key.as_mut());
    key
}

/// Encrypt under AES-256-GCM. Returns `(ciphertext, auth_tag)` as
/// separate byte vectors with Scala's historical JSON field split: `auth_tag`
/// contains the first 16 bytes of the encrypted stream, and `ciphertext` the
/// remainder, including the cryptographic GCM tag. Decrypt concatenates these
/// fields in the opposite order from their return tuple.
///
/// **IV reuse warning**: the caller MUST pass a freshly random 96-bit
/// IV. AES-256-GCM under IV reuse leaks plaintext correlations and
/// can reveal the authentication key. Use `OsRng.fill_bytes` to
/// generate the IV right before encryption; never store and reuse.
pub fn encrypt(
    key: &Zeroizing<[u8; 32]>,
    iv: &[u8; 12],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), crate::error::WalletError> {
    // Borrow the fixed-size key without copying it out of Zeroizing.
    let key_array: &Key<Aes256Gcm> = (&**key).into();
    let cipher = Aes256Gcm::new(key_array);
    let nonce: &Nonce<_> = iv.into();

    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|e| crate::error::WalletError::Encryption(format!("{e:?}")))?;

    if ciphertext_with_tag.len() < 16 {
        return Err(crate::error::WalletError::Encryption(
            "internal: ciphertext shorter than auth tag".to_string(),
        ));
    }
    // Scala AES.encrypt names the first 16 bytes `authTag` and the
    // remaining bytes `cipherText`, then concatenates in that order on
    // decrypt. Preserve this historical field layout rather than assuming
    // that the JSON authTag contains the cryptographic GCM tag.
    let (tag, ct) = ciphertext_with_tag.split_at(16);
    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(tag);
    Ok((ct.to_vec(), tag_arr))
}

/// Decrypt under AES-256-GCM. Returns the plaintext wrapped in
/// `Zeroizing` so callers can't accidentally retain it past use.
///
/// Failure modes (wrong password, tampered ciphertext, tampered tag)
/// are all indistinguishable from the caller's perspective — that's
/// the GCM authentication contract. Any failure → `WalletError::Decryption`.
pub fn decrypt(
    key: &Zeroizing<[u8; 32]>,
    iv: &[u8; 12],
    ciphertext: &[u8],
    auth_tag: &[u8; 16],
) -> Result<Zeroizing<Vec<u8>>, crate::error::WalletError> {
    let key_array: &Key<Aes256Gcm> = (&**key).into();
    let cipher = Aes256Gcm::new(key_array);
    let nonce: &Nonce<_> = iv.into();

    let mut combined = Vec::with_capacity(ciphertext.len() + 16);
    combined.extend_from_slice(auth_tag);
    combined.extend_from_slice(ciphertext);

    let result = cipher.decrypt(
        nonce,
        Payload {
            msg: &combined,
            aad: &[],
        },
    );
    if let Ok(plaintext) = result {
        return Ok(Zeroizing::new(plaintext));
    }
    // Older Rust releases wrote conventional ciphertext/tag fields. Retain
    // authenticated import compatibility without rewriting those files.
    combined.clear();
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(auth_tag);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: &[],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| crate::error::WalletError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn random_salt_iv() -> ([u8; 16], [u8; 12]) {
        use rand::RngCore;
        let mut salt = [0u8; 16];
        let mut iv = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut iv);
        (salt, iv)
    }

    // ----- happy path -----

    #[test]
    fn pbkdf2_known_vector_matches_scala() {
        // Standards-compliance vector: PBKDF2-HMAC-SHA512 (password="password",
        // salt="salt", iterations=128000, dkLen=32 bytes).
        //
        // Computed via:
        //   python -c "import hashlib; print(hashlib.pbkdf2_hmac('sha512', b'password', b'salt', 128000, 32).hex())"
        let key = derive_key_pbkdf2(b"password", b"salt", 128000);
        let expected_hex = "308b054cc369ac25e6cdbe5bbad860d24e4f714482b5a289c2d1df76c0ace970";
        assert_eq!(hex::encode(key.as_ref()), expected_hex);
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let password = b"correct horse battery staple";
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let (salt, iv) = random_salt_iv();
        let key = derive_key_pbkdf2(password, &salt, 128000);
        let (ciphertext, auth_tag) = encrypt(&key, &iv, plaintext)
            .expect("encrypt under fresh key + random IV must succeed");
        let recovered = decrypt(&key, &iv, &ciphertext, &auth_tag)
            .expect("decrypt with correct key/iv/auth_tag must succeed");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    // ----- error paths -----

    #[test]
    fn decrypt_with_wrong_password_fails() {
        let plaintext = b"hello";
        let (salt, iv) = random_salt_iv();
        let key_correct = derive_key_pbkdf2(b"correct", &salt, 128000);
        let key_wrong = derive_key_pbkdf2(b"wrong", &salt, 128000);
        let (ct, tag) = encrypt(&key_correct, &iv, plaintext).unwrap();
        let err = decrypt(&key_wrong, &iv, &ct, &tag).expect_err("wrong password must fail");
        assert!(matches!(err, crate::error::WalletError::Decryption));
    }

    #[test]
    fn decrypt_with_tampered_ciphertext_fails() {
        let plaintext = b"hello";
        let (salt, iv) = random_salt_iv();
        let key = derive_key_pbkdf2(b"pw", &salt, 128000);
        let (mut ct, tag) = encrypt(&key, &iv, plaintext).unwrap();
        ct[0] ^= 0x01;
        let err = decrypt(&key, &iv, &ct, &tag).expect_err("tampered ct must fail");
        assert!(matches!(err, crate::error::WalletError::Decryption));
    }

    #[test]
    fn decrypt_with_tampered_auth_tag_fails() {
        let plaintext = b"hello";
        let (salt, iv) = random_salt_iv();
        let key = derive_key_pbkdf2(b"pw", &salt, 128000);
        let (ct, mut tag) = encrypt(&key, &iv, plaintext).unwrap();
        tag[0] ^= 0x01;
        let err = decrypt(&key, &iv, &ct, &tag).expect_err("tampered tag must fail");
        assert!(matches!(err, crate::error::WalletError::Decryption));
    }
}

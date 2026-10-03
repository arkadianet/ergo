//! Encryption primitives for the encrypted-secret-file format.
//!
//! Scala/Appkit defaults use PBKDF2-HMAC-SHA256 with 128,000 iterations
//! and a 32-byte key. HMAC-SHA512 remains supported for existing Rust
//! wallets. AES-256-GCM uses a fresh 96-bit IV per encryption.
//!
//! All intermediate buffers (derived key, plaintext while encrypted,
//! plaintext after decrypt) are wrapped in `zeroize::Zeroizing` so
//! the OS doesn't leak them via swap or crash dumps.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// Supported PBKDF2 pseudorandom functions in encrypted wallet files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pbkdf2Prf {
    HmacSha256,
    HmacSha512,
}

impl Pbkdf2Prf {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "HmacSHA256" => Some(Self::HmacSha256),
            "HmacSHA512" => Some(Self::HmacSha512),
            _ => None,
        }
    }
}

/// PBKDF2-HMAC-SHA512 password → key derivation for legacy Rust callers.
/// New keystore files use [`derive_key_pbkdf2_with_prf`] with HMAC-SHA256.
///
/// Returns a `Zeroizing<[u8; 32]>` so the derived key is zeroed when
/// it goes out of scope. Callers MUST NOT copy this out into a plain
/// `[u8; 32]` without re-wrapping.
pub fn derive_key_pbkdf2(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    derive_key_pbkdf2_with_prf(password, salt, iterations, Pbkdf2Prf::HmacSha512)
}

/// Derive the 256-bit AES key using the file's PBKDF2 PRF and iteration count.
pub fn derive_key_pbkdf2_with_prf(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    prf: Pbkdf2Prf,
) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    match prf {
        Pbkdf2Prf::HmacSha256 => pbkdf2_hmac::<Sha256>(password, salt, iterations, key.as_mut()),
        Pbkdf2Prf::HmacSha512 => pbkdf2_hmac::<Sha512>(password, salt, iterations, key.as_mut()),
    }
    key
}

/// Encrypt under AES-256-GCM. Returns `(ciphertext, auth_tag)` as
/// separate byte vectors in the conventional trailing-tag layout.
/// Scala keystore files use [`encrypt_scala`] instead.
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
    let key_array: &Key<Aes256Gcm> = key.as_ref().into();
    let cipher = Aes256Gcm::new(key_array);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(iv);

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
    let (ct, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);
    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(tag);
    Ok((ct.to_vec(), tag_arr))
}

/// Encrypt using Scala `AES.encrypt`'s keystore field layout: `authTag`
/// holds the first 16 bytes of the JVM GCM output, and `cipherText` holds
/// the remainder (including the actual trailing GCM authentication tag).
pub fn encrypt_scala(
    key: &Zeroizing<[u8; 32]>,
    iv: &[u8; 12],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), crate::error::WalletError> {
    let (mut ciphertext, tag) = encrypt(key, iv, plaintext)?;
    ciphertext.extend_from_slice(&tag);
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&ciphertext[..16]);
    Ok((ciphertext[16..].to_vec(), prefix))
}

/// Decrypt Scala's keystore layout, reconstructing the JVM GCM output
/// as `authTag ++ cipherText` before authenticating it.
pub fn decrypt_scala(
    key: &Zeroizing<[u8; 32]>,
    iv: &[u8; 12],
    ciphertext: &[u8],
    prefix: &[u8; 16],
) -> Result<Zeroizing<Vec<u8>>, crate::error::WalletError> {
    let mut combined = Vec::with_capacity(ciphertext.len() + 16);
    combined.extend_from_slice(prefix);
    combined.extend_from_slice(ciphertext);
    let (ct, tag) = combined.split_at(combined.len() - 16);
    let tag: &[u8; 16] = tag.try_into().expect("split off exactly 16 bytes");
    decrypt(key, iv, ct, tag)
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
    let key_array: &Key<Aes256Gcm> = key.as_ref().into();
    let cipher = Aes256Gcm::new(key_array);
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(iv);

    let mut combined = Vec::with_capacity(ciphertext.len() + 16);
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

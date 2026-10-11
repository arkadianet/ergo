//! Encryption primitives for the encrypted-secret-file format.
//!
//! Scala parity: `AES.scala:62` defines the cipher parameters we
//! match byte-for-byte. Scala/Appkit defaults use PBKDF2-HMAC-SHA256 with
//! 128,000 iterations and a 32-byte key; HMAC-SHA512 remains supported for
//! existing Rust wallets. AES-256-GCM with a fresh 96-bit IV per
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

/// Argon2id cost parameters for version-2 keystore files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl Argon2idParams {
    /// Largest memory cost accepted from a file: 4 GiB.
    pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
    /// Largest pass count accepted from a file.
    pub const MAX_ITERATIONS: u32 = 16;
    /// Largest lane count accepted from a file.
    pub const MAX_PARALLELISM: u32 = 16;

    /// Parameters for newly written keystores: 256 MiB, 3 passes, 1 lane.
    pub const fn keystore_default() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }

    /// Reject parameters that are malformed or whose cost would let a
    /// tampered file stall unlock. A low cost is the writer's choice and is
    /// not rejected: an attacker able to rewrite the file could replace it.
    pub fn validate(&self) -> Result<(), crate::error::WalletError> {
        let invalid = |message: &str| crate::error::WalletError::SecretFile(message.to_string());
        if self.parallelism == 0 || self.parallelism > Self::MAX_PARALLELISM {
            return Err(invalid("Argon2id parallelism is out of range"));
        }
        if self.iterations == 0 || self.iterations > Self::MAX_ITERATIONS {
            return Err(invalid("Argon2id iteration count is out of range"));
        }
        if self.memory_kib < 8 * self.parallelism || self.memory_kib > Self::MAX_MEMORY_KIB {
            return Err(invalid("Argon2id memory cost is out of range"));
        }
        Ok(())
    }

    /// True when this cost is below `other` in memory or passes.
    pub fn weaker_than(&self, other: &Self) -> bool {
        self.memory_kib < other.memory_kib || self.iterations < other.iterations
    }
}

/// Largest PBKDF2 iteration count accepted from a version-1 file. Scala and
/// Appkit write 128,000; the bound stops a tampered file from stalling unlock.
pub const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;

/// Derive a 256-bit key with Argon2id (version 0x13).
pub fn derive_key_argon2id(
    password: &[u8],
    salt: &[u8],
    params: Argon2idParams,
) -> Result<Zeroizing<[u8; 32]>, crate::error::WalletError> {
    params.validate()?;
    let argon_params = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|error| crate::error::WalletError::SecretFile(format!("Argon2id: {error}")))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|error| crate::error::WalletError::SecretFile(format!("Argon2id: {error}")))?;
    Ok(key)
}

/// AES-256-GCM with associated data. Returns the conventional
/// ciphertext-then-tag stream. Callers must use a fresh random 96-bit IV.
pub fn seal(
    key: &Zeroizing<[u8; 32]>,
    iv: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, crate::error::WalletError> {
    let key_array: &Key<Aes256Gcm> = (&**key).into();
    Aes256Gcm::new(key_array)
        .encrypt(
            iv.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| crate::error::WalletError::Encryption(format!("{e:?}")))
}

/// Open a [`seal`] stream. Any failure, including a wrong key or changed
/// associated data, is [`crate::error::WalletError::Decryption`].
pub fn open(
    key: &Zeroizing<[u8; 32]>,
    iv: &[u8; 12],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, crate::error::WalletError> {
    let key_array: &Key<Aes256Gcm> = (&**key).into();
    Aes256Gcm::new(key_array)
        .decrypt(iv.into(), Payload { msg: sealed, aad })
        .map(Zeroizing::new)
        .map_err(|_| crate::error::WalletError::Decryption)
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

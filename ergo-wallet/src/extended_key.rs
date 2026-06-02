//! BIP32 extended keys + child derivation.
//!
//! Custom implementation over `k256` (secp256k1 scalar/point ops) and
//! `hmac-sha512` (chain-code derivation). We DON'T use a generic `bip32`
//! crate because we want full control over the algorithm and to keep
//! the door open for the pre-1627 Scala-compat path without restructuring
//! around a generic crate's API surface.

use crate::derivation::{DerivationPath, HARDENED_OFFSET};
use crate::error::WalletError;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar, SecretKey};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// 32-byte secp256k1 private scalar + 32-byte BIP32 chain code.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ExtendedSecretKey {
    /// Raw secp256k1 scalar. Treated as opaque secret material; never logged.
    /// k256::SecretKey already handles its own zeroize internally.
    #[zeroize(skip)]
    pub(crate) secret: SecretKey,
    /// BIP32 chain code — 32 bytes of entropy used to derive child chain codes.
    pub(crate) chain_code: [u8; 32],
}

impl std::fmt::Debug for ExtendedSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedSecretKey")
            .field("secret", &"[REDACTED]")
            .field("chain_code", &"[REDACTED]")
            .finish()
    }
}

impl ExtendedSecretKey {
    /// Borrow the raw secret bytes. Use sparingly — prefer
    /// [`Self::public_key`] for downstream consumers.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes().into()
    }

    /// Derive the BIP32 master key from a BIP39 seed using standard
    /// post-1627 derivation (the modern Ergo / BIP32 spec — what
    /// fresh wallets use).
    ///
    /// Algorithm: HMAC-SHA512(key=b"Bitcoin seed", data=seed); left
    /// 32 bytes = secret, right 32 bytes = chain code. If the secret
    /// is 0 or >= curve order n (cosmologically improbable from a
    /// 64-byte HMAC output), returns `Err(InvalidDerivedScalar)` —
    /// there is no "next index" to advance to at the master level.
    /// (Child derivation does have retry semantics; see
    /// `derive_child`.)
    ///
    /// Importing a wallet created before Ergo block 417,792 /
    /// Sigma 5.0 requires the `usePre1627KeyDerivation` flag from
    /// the secret-file metadata, which the encrypted secret-file
    /// loader handles.
    pub fn derive_master_key(seed: &[u8], use_pre_1627: bool) -> Result<Self, WalletError> {
        // Master derivation is identical in both modes per Ergo issue
        // #1627; the divergence is in CHILD derivation.
        let _ = use_pre_1627;
        // Standard BIP32: HMAC-SHA512 with key "Bitcoin seed".
        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC accepts any key length");
        mac.update(seed);
        let result = mac.finalize().into_bytes();
        let (left, right) = result.split_at(32);

        let secret = SecretKey::from_slice(left).map_err(|_| WalletError::InvalidDerivedScalar)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(right);

        Ok(Self { secret, chain_code })
    }

    /// BIP32 child key derivation (CKD-priv).
    ///
    /// For hardened indices (>= 2^31): HMAC-SHA512(key=chain_code,
    /// data = 0x00 || serialize_secret(secret) || ser32(index)).
    /// For non-hardened: HMAC-SHA512(key=chain_code, data =
    /// serialize_public(secret) || ser32(index)).
    /// In both cases: left 32 = (k_par + I_L) mod n = new secret;
    /// right 32 = new chain code.
    ///
    /// **BIP32 retry semantics**: the spec says that when `parse256(IL) >= n`
    /// or `ki = 0`, the resulting key is invalid and the implementation
    /// should proceed with the next value for `i`. This implementation
    /// recursively advances `index` to the next index **within the same
    /// child-class** (hardened or non-hardened) in both cases.
    /// The retry is cosmologically rare (~2^-127 per derivation), but
    /// we honour it for exact parity with Scala (`ExtendedSecretKey.scala`)
    /// and sigma-rust (`ext_secret_key.rs:145-155`,
    /// `derivation_path.rs::ChildIndex::next()`).
    ///
    /// **Class-preserving advance**: a raw `index + 1` would cross
    /// from `0x7fff_ffff` (last non-hardened) into `0x8000_0000`
    /// (first hardened), silently changing the HMAC input shape
    /// (non-hardened uses pubkey, hardened uses secret) mid-retry.
    /// The helper `next_index_same_class` increments only the
    /// 31-bit payload while preserving the hardened bit, returning
    /// `Err(InvalidDerivedScalar)` only when the entire class is
    /// exhausted (which never happens in practice).
    pub fn derive_child(&self, index: u32) -> Result<Self, WalletError> {
        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC accepts any key length");

        if index >= HARDENED_OFFSET {
            // Hardened: include the secret with a 0x00 prefix.
            mac.update(&[0u8]);
            mac.update(&self.secret.to_bytes());
        } else {
            // Non-hardened: include the compressed public key.
            let pubkey = self.secret.public_key();
            let encoded = pubkey.to_encoded_point(/* compressed: */ true);
            mac.update(encoded.as_bytes());
        }
        mac.update(&index.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let (il, ir) = result.split_at(32);

        // BIP32 retry: if I_L >= n, advance to next-same-class index.
        let il_secret = match SecretKey::from_slice(il) {
            Ok(sk) => sk,
            Err(_) => return self.derive_child(Self::next_index_same_class(index)?),
        };

        // child_secret = (parent_secret + I_L) mod n
        let parent_scalar: Scalar = *self.secret.to_nonzero_scalar().as_ref();
        let il_scalar = *il_secret.to_nonzero_scalar().as_ref();
        let child_scalar = parent_scalar + il_scalar;
        // BIP32 retry: if child_scalar == 0, advance to next-same-class index.
        if child_scalar == Scalar::ZERO {
            return self.derive_child(Self::next_index_same_class(index)?);
        }
        let child_secret = SecretKey::new(child_scalar.into());

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(ir);

        Ok(Self {
            secret: child_secret,
            chain_code: child_chain_code,
        })
    }

    /// Increment `index` to the next index within the SAME child-class
    /// (hardened or non-hardened). Preserves the hardened bit (`0x8000_0000`)
    /// so a retry can't silently change the HMAC input shape from
    /// "include pubkey" to "include secret" or vice versa.
    ///
    /// Returns `Err(InvalidDerivedScalar)` only when the 31-bit payload
    /// wraps to zero — i.e., the entire class has been exhausted. In
    /// practice this never happens (probability ~ 2^-(31 * 2^127)).
    fn next_index_same_class(index: u32) -> Result<u32, WalletError> {
        let hardened_bit = index & HARDENED_OFFSET;
        let payload = index & !HARDENED_OFFSET;
        let next_payload = payload
            .checked_add(1)
            .filter(|&p| p < HARDENED_OFFSET)
            .ok_or(WalletError::InvalidDerivedScalar)?;
        Ok(hardened_bit | next_payload)
    }

    /// Walk a [`DerivationPath`] from this key, returning the leaf.
    /// Each component is fed to [`Self::derive_child`] in order.
    pub fn derive_at_path(&self, path: &DerivationPath) -> Result<Self, WalletError> {
        let mut current = self.clone();
        for &component in path.components() {
            current = current.derive_child(component)?;
        }
        Ok(current)
    }
}

/// BIP32 extended public key — 33-byte compressed secp256k1 pubkey
/// plus 32-byte BIP32 chain code. Derivable from an
/// [`ExtendedSecretKey`] without exposing the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPublicKey {
    pubkey: ProjectivePoint,
    chain_code: [u8; 32],
}

impl ExtendedPublicKey {
    /// 33-byte SEC1 compressed pubkey encoding (matches what the
    /// node's `[mining] miner_public_key_hex` config field expects).
    pub fn compressed_bytes(&self) -> [u8; 33] {
        let affine = self.pubkey.to_affine();
        let encoded = affine.to_encoded_point(/* compressed: */ true);
        let bytes = encoded.as_bytes();
        debug_assert_eq!(
            bytes.len(),
            33,
            "SEC1 compressed pubkey is exactly 33 bytes"
        );
        let mut out = [0u8; 33];
        out.copy_from_slice(bytes);
        out
    }

    /// Borrow the chain code (used for non-hardened child derivation
    /// from an xpub).
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }
}

impl ExtendedSecretKey {
    /// Derive the matching [`ExtendedPublicKey`] without exposing the
    /// secret scalar.
    pub fn public_key(&self) -> ExtendedPublicKey {
        let scalar: Scalar = *self.secret.to_nonzero_scalar().as_ref();
        let pubkey = ProjectivePoint::GENERATOR * scalar;
        ExtendedPublicKey {
            pubkey,
            chain_code: self.chain_code,
        }
    }
}

/// Pre-1627 legacy extended secret key. The secret is stored as a
/// VARIABLE-LENGTH unsigned byte array (matching Scala's
/// `BigIntegers.asUnsignedByteArray` behavior), NOT the fixed-width
/// 32-byte form. This is load-bearing for descendant derivations:
/// the next HMAC iteration consumes these variable-length bytes
/// as `parentKey.keyBytes`, and the leading-zero-stripped shape
/// changes the HMAC output. The post-1627 fix left-pads to 32 bytes.
///
/// Used only for pre-1627 derivation. Modern (post-1627) wallets
/// use the fixed-width `ExtendedSecretKey`.
///
/// `Zeroize` + `ZeroizeOnDrop` ensure the variable-length
/// `secret_bytes` and the chain code are wiped on drop.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ExtendedSecretKeyLegacy {
    /// Variable-length unsigned big-endian secret bytes (1..=32 bytes).
    /// MAY be shorter than 32 bytes when the underlying scalar has
    /// leading zero bytes — this is the "31 bit child key" condition
    /// that the post-1627 fix corrected by left-padding.
    pub(crate) secret_bytes: Vec<u8>,
    /// BIP32 chain code (always 32 bytes).
    pub(crate) chain_code: [u8; 32],
}

impl std::fmt::Debug for ExtendedSecretKeyLegacy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedSecretKeyLegacy")
            .field("secret_bytes", &"[REDACTED]")
            .field("chain_code", &"[REDACTED]")
            .finish()
    }
}

impl ExtendedSecretKeyLegacy {
    /// Borrow the variable-length secret bytes (1..=32 bytes).
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret_bytes
    }

    /// Borrow the chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Derive the BIP32 master key in pre-1627 mode. The master
    /// derivation is IDENTICAL to post-1627 mode — the 1627 bug is
    /// strictly in CHILD derivation. We strip leading zeros from the
    /// 32-byte secret to match Scala's `BigIntegers.asUnsignedByteArray`
    /// convention.
    pub fn derive_master_key(seed: &[u8]) -> Result<Self, WalletError> {
        let post = ExtendedSecretKey::derive_master_key(seed, false)?;
        let mut bytes: Vec<u8> = post.secret_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        Ok(Self {
            secret_bytes: bytes,
            chain_code: post.chain_code,
        })
    }

    /// Convert to a post-1627-shape `ExtendedSecretKey` for public-key
    /// extraction or scalar arithmetic. The secret bytes are LEFT-PADDED
    /// to 32 bytes so `k256::SecretKey` can parse them. The scalar
    /// value is unchanged — only the byte-shape differs. Use this ONLY
    /// at API boundaries (pubkey extraction, scalar ops); never feed the
    /// result back into a pre-1627 derivation chain.
    pub fn to_post_1627_for_pubkey(&self) -> Result<ExtendedSecretKey, WalletError> {
        if self.secret_bytes.len() > 32 {
            return Err(WalletError::InvalidDerivedScalar);
        }
        let mut padded = [0u8; 32];
        let offset = 32 - self.secret_bytes.len();
        padded[offset..].copy_from_slice(&self.secret_bytes);
        let secret =
            SecretKey::from_slice(&padded).map_err(|_| WalletError::InvalidDerivedScalar)?;
        Ok(ExtendedSecretKey {
            secret,
            chain_code: self.chain_code,
        })
    }

    /// Extract the compressed SEC1 public key (33 bytes) via left-padding.
    /// The scalar value is unchanged, so the pubkey is identical to what
    /// the equivalent post-1627 key would produce.
    pub fn public_key(&self) -> Result<ExtendedPublicKey, WalletError> {
        Ok(self.to_post_1627_for_pubkey()?.public_key())
    }

    /// Pre-1627 child derivation, matching Scala's `deriveChildSecretKey`
    /// (the pre-fix branch). The 1627 bug: the resulting child scalar is
    /// stored as variable-length bytes (leading zeros stripped via Java's
    /// `BigIntegers.asUnsignedByteArray`), and the next iteration's HMAC
    /// consumes those variable-length bytes directly — the leading-zero
    /// stripping changes the HMAC output for all descendant keys.
    ///
    /// Retry on `I_L >= n` or `child_scalar == 0` recurses with raw
    /// `idx + 1` (NOT class-preserving — class-preserving advance is
    /// the post-1627 design decision and does NOT apply here).
    pub fn derive_child(&self, index: u32) -> Result<Self, WalletError> {
        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC accepts any key length");

        if index >= HARDENED_OFFSET {
            // Hardened: 0x00 prefix + variable-length secret bytes.
            // CRITICAL: pre-1627 feeds the variable-length bytes as-is,
            // NOT left-padded to 32. This is the load-bearing bug.
            mac.update(&[0u8]);
            mac.update(&self.secret_bytes);
        } else {
            // Non-hardened: compressed pubkey (always 33 bytes regardless
            // of secret_bytes length — left-pad only for curve math here).
            let post = self.to_post_1627_for_pubkey()?;
            let pubkey = post.secret.public_key();
            let encoded = pubkey.to_encoded_point(true);
            mac.update(encoded.as_bytes());
        }
        mac.update(&index.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let (il, ir) = result.split_at(32);

        // Try to parse I_L as a curve scalar. On `>= n`, recurse with
        // raw idx + 1 (the pre-1627 behavior; class-preserving is post-1627).
        let il_secret = match SecretKey::from_slice(il) {
            Ok(sk) => sk,
            Err(_) => {
                let next = index
                    .checked_add(1)
                    .ok_or(WalletError::InvalidDerivedScalar)?;
                return self.derive_child(next);
            }
        };

        // child_scalar = (parent_scalar + I_L) mod n
        // Left-pad variable-length bytes for k256 arithmetic only.
        let post = self.to_post_1627_for_pubkey()?;
        let parent_scalar: Scalar = *post.secret.to_nonzero_scalar().as_ref();
        let il_scalar: Scalar = *il_secret.to_nonzero_scalar().as_ref();
        let child_scalar = parent_scalar + il_scalar;
        if child_scalar == Scalar::ZERO {
            let next = index
                .checked_add(1)
                .ok_or(WalletError::InvalidDerivedScalar)?;
            return self.derive_child(next);
        }

        // CRITICAL: store child secret as VARIABLE-LENGTH bytes, matching
        // `BigIntegers.asUnsignedByteArray(childScalar)`. k256 gives 32
        // bytes; strip leading zeros to reproduce the pre-1627 bug.
        let scalar_bytes_32: [u8; 32] = child_scalar.to_bytes().into();
        let mut variable_length: Vec<u8> = scalar_bytes_32.to_vec();
        while variable_length.len() > 1 && variable_length[0] == 0 {
            variable_length.remove(0);
        }

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(ir);

        Ok(Self {
            secret_bytes: variable_length,
            chain_code: child_chain_code,
        })
    }

    /// Walk a [`DerivationPath`] using pre-1627 child derivation.
    pub fn derive_at_path(&self, path: &DerivationPath) -> Result<Self, WalletError> {
        let mut current = self.clone();
        for &component in path.components() {
            current = current.derive_child(component)?;
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity -----

    /// BIP32 Test Vector 1, master key. Source:
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    /// Seed: 000102030405060708090a0b0c0d0e0f
    /// Expected master secret: e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
    /// Expected master chain code: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
    #[test]
    fn bip32_vector_1_master_key_post_1627() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let xsk = ExtendedSecretKey::derive_master_key(&seed, false)
            .expect("standard BIP32 master key must derive");
        assert_eq!(
            hex::encode(xsk.secret_bytes()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            "BIP32 vector 1 master secret",
        );
        assert_eq!(
            hex::encode(xsk.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
            "BIP32 vector 1 master chain code",
        );
    }

    /// BIP32 Vector 1, first hardened child m/0'. Expected:
    /// secret: edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
    /// chain code: 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
    #[test]
    fn bip32_vector_1_first_hardened_child() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
        // m/0' = hardened index 0 = HARDENED_OFFSET | 0
        let child = master
            .derive_child(HARDENED_OFFSET)
            .expect("vector 1 m/0' must derive");
        assert_eq!(
            hex::encode(child.secret_bytes()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            "BIP32 vector 1 m/0' secret",
        );
        assert_eq!(
            hex::encode(child.chain_code),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            "BIP32 vector 1 m/0' chain code",
        );
    }

    /// BIP32 Vector 1, m/0'/1 (two-step derivation). Expected:
    /// secret: 3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368
    #[test]
    fn bip32_vector_1_two_step_derive_at_path() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
        // m/0'/1
        let path: DerivationPath = "m/0'/1".parse().unwrap();
        let leaf = master
            .derive_at_path(&path)
            .expect("vector 1 m/0'/1 must derive");
        assert_eq!(
            hex::encode(leaf.secret_bytes()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            "BIP32 vector 1 m/0'/1 secret",
        );
    }

    #[test]
    fn extended_pubkey_from_xsk_returns_compressed_secp256k1_pubkey() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
        let xpub = master.public_key();
        // BIP32 Vector 1, master pubkey (compressed sec1):
        // 0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
        assert_eq!(
            hex::encode(xpub.compressed_bytes()),
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
        );
    }

    // ----- oracle parity (pre-1627 legacy) -----

    /// Pre-1627 derivation oracle (full address path).
    /// Source: ExtendedSecretKeySpec.scala:76 — the "1627 BIP32 key
    /// derivation fix" property test, pre-fix branch.
    #[test]
    fn pre_1627_derivation_produces_scala_documented_pubkey() {
        use crate::derivation::DerivationPath;
        use crate::mnemonic::Mnemonic;
        let mnemonic = Mnemonic::import(
            "race relax argue hair sorry riot there spirit ready \
             fetch food hedgehog hybrid mobile pretty",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedSecretKeyLegacy::derive_master_key(&seed).unwrap();
        let path: DerivationPath = "m/44'/429'/0'/0/0".parse().unwrap();
        let leaf = master.derive_at_path(&path).unwrap();
        let pk = leaf.public_key().unwrap().compressed_bytes();
        let expected_pubkey_hex =
            "02387003b02747904c5aec88f2de54872c60fca0880661f3449727314b10267338";
        assert_eq!(
            hex::encode(pk),
            expected_pubkey_hex,
            "pre-1627 derivation must match Scala ExtendedSecretKeySpec.scala:76 vector",
        );
    }

    /// The pre-1627 legacy addition MUST NOT regress post-1627 derivation.
    #[test]
    fn post_1627_derivation_matches_oracle_vector() {
        use crate::derivation::DerivationPath;
        use crate::mnemonic::Mnemonic;
        let mnemonic = Mnemonic::import(
            "race relax argue hair sorry riot there spirit ready \
             fetch food hedgehog hybrid mobile pretty",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedSecretKey::derive_master_key(&seed, false).unwrap();
        let path: DerivationPath = "m/44'/429'/0'/0/0".parse().unwrap();
        let leaf = master.derive_at_path(&path).unwrap();
        let pk = leaf.public_key().compressed_bytes();
        let expected_pubkey_hex =
            "0202f2b96aa59e6f37fc978883f78e54fd319fa37dcf971d8e69f9e9225376bcf1";
        assert_eq!(hex::encode(pk), expected_pubkey_hex);
    }

    /// Pre-1627 intermediate values — must come from Scala oracle.
    /// Currently #[ignore]'d pending engineer extraction.
    #[test]
    #[ignore = "intermediate vectors must be Scala-extracted before un-ignoring"]
    fn pre_1627_intermediate_vectors_match_scala() {
        use crate::derivation::DerivationPath;
        use crate::mnemonic::Mnemonic;
        let mnemonic = Mnemonic::import(
            "race relax argue hair sorry riot there spirit ready \
             fetch food hedgehog hybrid mobile pretty",
        )
        .unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedSecretKeyLegacy::derive_master_key(&seed).unwrap();
        let expected_master_hex: &str = "<EXTRACT_FROM_SCALA>";
        let expected_master_chain_hex: &str = "<EXTRACT_FROM_SCALA>";
        assert_eq!(hex::encode(master.secret_bytes()), expected_master_hex);
        assert_eq!(hex::encode(master.chain_code()), expected_master_chain_hex);
        // Suppress unused variable warning — path would be used after Scala extraction.
        let _path: DerivationPath = "m/44'/429'/0'/0/0".parse().unwrap();
    }
}

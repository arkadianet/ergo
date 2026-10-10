//! Portable unlocked master keys; no filesystem or keystore dependency.

use crate::{error::WalletError, extended_key::ExtendedSecretKey};

/// Variant of the in-memory unlocked master key. Pre-1627 wallets
/// MUST use the legacy variant: `ExtendedSecretKeyLegacy` stores
/// the secret as variable-length bytes (matching Scala's
/// `BigIntegers.asUnsignedByteArray` behavior), which is
/// load-bearing for descendant derivations per Ergo issue #1627.
/// Modern wallets use the fixed-width post-1627 type.
#[derive(zeroize::ZeroizeOnDrop)]
pub enum UnlockedMaster {
    Modern(ExtendedSecretKey),
    Legacy(crate::extended_key::ExtendedSecretKeyLegacy),
}

impl UnlockedMaster {
    /// Walk a [`crate::DerivationPath`] in the appropriate mode. Returns
    /// the leaf's compressed-SEC1 public key bytes.
    pub fn derive_pubkey_at_path(
        &self,
        path: &crate::derivation::DerivationPath,
    ) -> Result<[u8; 33], WalletError> {
        match self {
            Self::Modern(m) => Ok(m.derive_at_path(path)?.public_key().compressed_bytes()),
            Self::Legacy(m) => Ok(m.derive_at_path(path)?.public_key()?.compressed_bytes()),
        }
    }

    /// The master pubkey (root of the derivation tree).
    pub fn master_pubkey(&self) -> Result<[u8; 33], WalletError> {
        match self {
            Self::Modern(m) => Ok(m.public_key().compressed_bytes()),
            Self::Legacy(m) => Ok(m.public_key()?.compressed_bytes()),
        }
    }

    /// Derive the secp256k1 scalar (secret) at the given path.
    ///
    /// Used by `SecretRegistry::from_master_key` to pre-derive each tracked
    /// pubkey's leaf secret at unlock time. The returned scalar is the
    /// private key — treat as secret material.
    pub fn derive_scalar_at_path(
        &self,
        path: &crate::derivation::DerivationPath,
    ) -> Result<k256::Scalar, WalletError> {
        use k256::elliptic_curve::ops::Reduce;
        let bytes: zeroize::Zeroizing<[u8; 32]> = match self {
            UnlockedMaster::Modern(esk) => {
                let leaf = esk.derive_at_path(path)?;
                leaf.secret_bytes()
            }
            UnlockedMaster::Legacy(esk) => {
                let leaf = esk.derive_at_path(path)?;
                // Variable-length secret: left-pad to 32 bytes.
                let mut padded = zeroize::Zeroizing::new([0u8; 32]);
                let sb = leaf.secret_bytes();
                let offset = 32 - sb.len().min(32);
                padded[offset..].copy_from_slice(&sb[sb.len().saturating_sub(32)..]);
                padded
            }
        };
        let wide = k256::U256::from_be_slice(bytes.as_slice());
        Ok(<k256::Scalar as Reduce<k256::U256>>::reduce(wide))
    }

    /// Derive the scalar at `path` and require that it controls `pubkey`.
    /// Persisted keys can come from another derivation, so every pairing of
    /// a stored public key with a derived secret goes through this check.
    pub fn derive_scalar_for_pubkey(
        &self,
        path: &crate::derivation::DerivationPath,
        pubkey: &[u8; 33],
    ) -> Result<k256::Scalar, WalletError> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let scalar = self.derive_scalar_at_path(path)?;
        let derived = (k256::ProjectivePoint::GENERATOR * scalar)
            .to_affine()
            .to_encoded_point(true);
        if derived.as_bytes() != pubkey.as_slice() {
            return Err(WalletError::TrackedKeyMismatch(path.to_string()));
        }
        Ok(scalar)
    }

    /// The earlier Rust legacy encoding of this master, when it derives
    /// different keys (a legacy master beginning with a zero byte).
    #[cfg(feature = "keystore")]
    pub(crate) fn legacy_rust_trimmed(&self) -> Option<Self> {
        match self {
            Self::Modern(_) => None,
            Self::Legacy(master) => master.legacy_rust_trimmed_master().map(Self::Legacy),
        }
    }

    /// Path of the first `(pubkey, path)` entry this master does not derive.
    #[cfg(feature = "keystore")]
    pub(crate) fn first_mismatch(
        &self,
        tracked: &[([u8; 33], Vec<u32>)],
    ) -> Result<Option<crate::derivation::DerivationPath>, WalletError> {
        for (pubkey, components) in tracked {
            let path = crate::derivation::DerivationPath::from_components(components.clone());
            if self.derive_pubkey_at_path(&path)? != *pubkey {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }
}

/// In-memory unlocked secret state. Held only while `LockState ==
/// Unlocked`. Contains the master extended secret key (in either
/// post-1627 or pre-1627 form) plus the `usePre1627KeyDerivation`
/// flag for routing.
///
/// `ZeroizeOnDrop` wipes the master key bytes when this struct is
/// dropped (which happens on `SecretStorage::lock()` setting
/// `unlocked = None`).
#[derive(zeroize::ZeroizeOnDrop)]
pub struct UnlockedSecret {
    pub master: UnlockedMaster,
    #[zeroize(skip)]
    pub use_pre_1627: bool,
}

impl std::fmt::Debug for UnlockedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedSecret")
            .field("master", &"[REDACTED]")
            .field("use_pre_1627", &self.use_pre_1627)
            .finish()
    }
}

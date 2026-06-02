//! Wallet-internal external-secret type (post-decoding from API DTO).
//!
//! The wire DTO with hex strings lives in `ergo-api/src/wallet/sending.rs`.
//! This type carries the decoded scalar — NOT serializable, never crosses
//! the wire boundary.

use k256::Scalar;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A secret supplied externally for the lock-matrix signing path.
/// Enables `/wallet/transaction/sign` to work while the wallet is
/// locked: the caller decodes the API DTO's hex strings into scalars
/// and passes this enum to `SecretRegistry::merge_external_secrets`.
///
/// `scalar` fields are wrapped in [`Zeroizing<Scalar>`] so the raw key
/// bytes are wiped when this enum drops. The `pk` / `g` / `h` / `u` /
/// `v` byte arrays are public-key data, not secrets — `#[zeroize(skip)]`
/// keeps them out of the wipe.
#[derive(ZeroizeOnDrop)]
pub enum ProverExternalSecret {
    /// Discrete-log (ProveDlog) secret: `scalar` such that `g^scalar = pk`.
    Dlog {
        /// 33-byte compressed SEC1 public key.
        #[zeroize(skip)]
        pk: [u8; 33],
        scalar: Zeroizing<Scalar>,
    },
    /// DH-tuple (ProveDHTuple) secret: `scalar` such that `u = g^scalar` and `v = h^scalar`.
    DhTuple {
        #[zeroize(skip)]
        g: [u8; 33],
        #[zeroize(skip)]
        h: [u8; 33],
        #[zeroize(skip)]
        u: [u8; 33],
        #[zeroize(skip)]
        v: [u8; 33],
        scalar: Zeroizing<Scalar>,
    },
}

//! Custody of multisig signing nonces.
//!
//! `generateCommitments` produces, for each of the wallet's own keys, a secret
//! nonce `r` and its public commitment. The Scala-compatible wire form returns
//! `r` to the caller, who must hand it back when signing; anyone who sees `r`
//! together with the final signature can recover the signing key, and reusing
//! one `r` for two messages reveals it outright. With a custodian the host
//! keeps `r` and returns an opaque single-use handle in its place.
use zeroize::Zeroizing;

/// Prefix of a custody handle in a hint's `secret` field.
pub const NONCE_HANDLE_PREFIX: &str = "custody:";

/// Holds secret nonces between `generateCommitments` and signing.
pub trait NonceCustody: Send + Sync {
    /// Keep `nonce` and return its handle (which starts with
    /// [`NONCE_HANDLE_PREFIX`]).
    fn deposit(&self, nonce: Zeroizing<[u8; 32]>) -> String;
    /// Remove and return the nonce for `handle`. A handle works once.
    fn withdraw(&self, handle: &str) -> Option<Zeroizing<[u8; 32]>>;
}

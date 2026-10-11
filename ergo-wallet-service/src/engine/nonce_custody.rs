//! Custody of multisig signing nonces.
//!
//! `generateCommitments` produces, for each of the wallet's own keys, a secret
//! nonce `r` and its public commitment. The Scala-compatible wire form returns
//! `r` to the caller, who must hand it back when signing; anyone who sees `r`
//! together with the final signature can recover the signing key, and reusing
//! one `r` for two messages reveals it outright. With a custodian the host
//! keeps `r` and returns an opaque single-use handle in its place.
//!
//! A handle is bound to the input index and the public commitment it was
//! issued for, so it cannot be moved to another leaf or input. It works once:
//! the first sign request that presents it removes it, whether that request
//! then succeeds or not.
use ergo_wallet::proving::hints::RealCommitment;
use zeroize::Zeroizing;

/// Prefix of a custody handle in a hint's `secret` field.
pub const NONCE_HANDLE_PREFIX: &str = "custody:";

/// Public data a nonce was issued for: the input index and the commitment
/// (image, first prover message and tree position).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceBinding {
    pub input: u32,
    pub commitment: RealCommitment,
}

/// Why a handle could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceRefusal {
    /// Never issued, already used, evicted, expired or wiped by a lock.
    Unavailable,
    /// Issued for another input or commitment. The handle is consumed anyway.
    WrongCommitment,
}

/// Holds secret nonces between `generateCommitments` and signing.
pub trait NonceCustody: Send + Sync {
    /// Keep `nonce` for `binding` and return its handle (which starts with
    /// [`NONCE_HANDLE_PREFIX`]).
    fn deposit(&self, nonce: Zeroizing<[u8; 32]>, binding: NonceBinding) -> String;
    /// Remove the nonce for `handle` and return it when it was issued for
    /// `binding`. The handle is gone afterwards in every case.
    fn withdraw(
        &self,
        handle: &str,
        binding: &NonceBinding,
    ) -> Result<Zeroizing<[u8; 32]>, NonceRefusal>;
    /// Wipe every held nonce.
    fn clear(&self);
}

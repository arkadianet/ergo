//! Error types for write paths.
//!
//! `ergo_primitives::writer::VlqWriter` is infallible — every `put_*`
//! method returns nothing — so write-side errors are exclusively the
//! semantic / shape constraints enforced by the codecs in this crate
//! (e.g., a transaction output references a token id that is missing
//! from the per-transaction token-id table; a register-value tuple's
//! type / value lengths disagree).
//!
//! Distinct from [`ergo_primitives::reader::ReadError`] so the static
//! type of a write function reads as "writer rejected the data" rather
//! than "I/O failed". A [`From`] impl back to `ReadError` is provided
//! so callers whose enclosing `Result<_, ReadError>` predates the
//! split keep working through `?` without touching their signatures.

use ergo_primitives::reader::ReadError;

/// Failure decoding a write-time invariant. The string carries
/// per-call-site context (which structural rule was violated).
///
/// `Display` text is byte-identical to `ReadError::InvalidData(...)`
/// so operator-visible diagnostics (REST error envelopes, log lines)
/// stay stable across the read/write split.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    /// Programmer-supplied data violates a wire-format constraint
    /// (length too large, missing table reference, type/value shape
    /// mismatch). Same `Display` text as `ReadError::InvalidData`.
    #[error("invalid data: {0}")]
    InvalidData(String),
}

impl From<WriteError> for ReadError {
    fn from(e: WriteError) -> Self {
        match e {
            WriteError::InvalidData(msg) => ReadError::InvalidData(msg),
        }
    }
}

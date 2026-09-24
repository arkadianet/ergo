//! Typed errors for the Scala-compat encoder layer.
//!
//! Replaces the workspace pattern of returning `Result<T, String>` from
//! parser/encoder helpers and rebuilding the message via
//! `format!("…: {e}")` at every call site. The variants preserve the
//! upstream typed source (`ReadError` / `WriteError`) so log aggregators
//! can group on `error.kind` rather than substring-matching the
//! flattened message.
//!
//! Scope is intentionally narrow: this is the encoder boundary that
//! materializes Scala REST JSON from canonical bytes. Application-edge
//! errors (config load, CLI parse, HTTP fetch) keep their existing
//! `String` shape — those have a single termination point and no typed
//! source to preserve.

use ergo_primitives::reader::ReadError;
use ergo_ser::WriteError;
use ergo_state::store::StateError;

/// Failure inside the api_bridge encoder layer. `what` is a stable
/// short tag (e.g. `"header"`, `"block_transactions"`, `"tx_id"`)
/// that names the structural element under construction; the
/// `#[source]` field carries the upstream typed error so callers
/// retain access to the original variant without parsing the
/// `Display` message.
#[derive(Debug, thiserror::Error)]
pub(super) enum BridgeError {
    /// Failed to deserialize a canonical wire structure (header,
    /// block transactions, extension, ad-proofs, ergo-box).
    #[error("parse {what}: {source}")]
    Parse {
        what: &'static str,
        #[source]
        source: ReadError,
    },
    /// Failed to compute or serialize a derived structure
    /// (`tx_id`, `box_id`, transaction wire bytes).
    #[error("encode {what}: {source}")]
    Encode {
        what: &'static str,
        #[source]
        source: WriteError,
    },
    /// Bytes parsed cleanly but `remaining` bytes were left over —
    /// a wire-integrity failure that has no typed source to chain.
    #[error("{remaining} leftover bytes after parsing {what}")]
    LeftoverBytes {
        what: &'static str,
        remaining: usize,
    },
    /// Stored data, or a structure derived from it, failed a consistency
    /// check that has no typed source (e.g. an unknown modifier type tag,
    /// or a Merkle proof that does not verify against its header root).
    #[error("inconsistent {what}: {detail}")]
    Inconsistent { what: &'static str, detail: String },
    /// Underlying storage read failed (chain-store / block-section
    /// fetch). Fallible chain reads report a failed read as `Unavailable`
    /// (v1 503) and a stored record the store itself rejects as malformed
    /// as `Corrupt` (v1 500). Compat Option/Vec wrappers remain best-effort.
    #[error("storage read failed: {0}")]
    Storage(#[from] StateError),
}

impl From<BridgeError> for ergo_api::compat::ChainReadError {
    fn from(error: BridgeError) -> Self {
        match error {
            // The store read the row but rejected its contents: retrying
            // cannot help, so this is corruption, not unavailability.
            BridgeError::Storage(
                StateError::DbCorruption { .. } | StateError::Serialization(_),
            ) => Self::Corrupt(error.to_string()),
            BridgeError::Storage(_) => Self::Unavailable(error.to_string()),
            BridgeError::Parse { .. }
            | BridgeError::Encode { .. }
            | BridgeError::LeftoverBytes { .. }
            | BridgeError::Inconsistent { .. } => Self::Corrupt(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_api::compat::ChainReadError;

    // ----- error paths -----

    #[test]
    fn chain_read_error_from_storage_error_is_unavailable() {
        let error = BridgeError::Storage(StateError::StorageError(Box::new(
            redb::StorageError::Io(std::io::Error::other("read failed")),
        )));
        let detail = error.to_string();
        let actual = ChainReadError::from(error);
        assert_eq!(actual.to_string(), detail);
        assert_eq!(actual, ChainReadError::Unavailable(detail));
    }

    #[test]
    fn chain_read_error_from_parse_error_is_corrupt() {
        let error = BridgeError::Parse {
            what: "header",
            source: ReadError::UnexpectedEnd { pos: 1, needed: 1 },
        };
        let detail = error.to_string();
        let actual = ChainReadError::from(error);
        assert_eq!(actual.to_string(), detail);
        assert_eq!(actual, ChainReadError::Corrupt(detail));
    }

    #[test]
    fn chain_read_error_from_store_db_corruption_is_corrupt() {
        let error = BridgeError::Storage(StateError::DbCorruption {
            table: "HEADER_CHAIN",
            key: "7".into(),
            reason: "expected 32-byte header id".into(),
        });
        let detail = error.to_string();
        assert_eq!(ChainReadError::from(error), ChainReadError::Corrupt(detail));
    }

    #[test]
    fn chain_read_error_from_store_serialization_error_is_corrupt() {
        let error = BridgeError::Storage(StateError::Serialization("bad row".into()));
        let detail = error.to_string();
        assert_eq!(ChainReadError::from(error), ChainReadError::Corrupt(detail));
    }

    #[test]
    fn chain_read_error_from_inconsistent_is_corrupt() {
        let error = BridgeError::Inconsistent {
            what: "modifier type tag",
            detail: "unknown type byte 7".into(),
        };
        let detail = error.to_string();
        assert_eq!(ChainReadError::from(error), ChainReadError::Corrupt(detail));
    }
}

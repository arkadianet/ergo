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
    /// Underlying storage read failed (chain-store / block-section
    /// fetch). The reassembly layer doesn't act on this beyond
    /// logging it — the trait wrapper translates it to `Ok(None)` —
    /// but preserving the source keeps the typed `StateError` variant
    /// available for future log-aggregator grouping.
    #[error("storage read failed: {0}")]
    Storage(#[from] StateError),
}

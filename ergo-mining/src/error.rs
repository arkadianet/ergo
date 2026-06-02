//! Error type surfaced by the `ergo-mining` crate.

use thiserror::Error;

/// Errors produced while assembling a mining candidate or accepting a
/// solution.
///
/// Variant taxonomy (operators triage by class, not by free-text):
///
/// * [`MiningError::InvalidConfig`] — operator-supplied configuration
///   was rejected at parse time, or a runtime height/regime gate was
///   crossed (mining off-tip, post-EIP-27 helper called pre-activation,
///   etc.).
/// * [`MiningError::HexDecode`] — a hex-encoded byte string from the
///   solution JSON or chain wire bytes failed to decode.
/// * [`MiningError::WrongLength`] — a byte string decoded but the
///   length disagreed with its protocol slot (nonce, pk, etc.).
/// * [`MiningError::IdComputation`] — a deterministic id /
///   bytes-to-sign / box-clone computation failed mid-assembly.
/// * [`MiningError::Decode`] — chain bytes pulled from storage failed
///   to deserialize (header, BlockTransactions, extension).
/// * [`MiningError::EmissionInvariant`] — an emission / reemission
///   protocol invariant was violated by the input box shape or value
///   (token count, NFT placement, stash underflow).
/// * [`MiningError::StateRead`] — a storage read inside candidate
///   assembly returned an error (redb-level fault, not a logical
///   absence).
/// * [`MiningError::InvalidMinerPublicKey`] — the miner's configured
///   public key could not be parsed as a 33-byte compressed secp256k1
///   point.
/// * [`MiningError::HeaderSerialization`] — re-serializing a parent
///   header for interlinks computation failed.
#[derive(Debug, Error)]
pub enum MiningError {
    /// Configuration was rejected at parse time, or a runtime regime
    /// gate refused to assemble. Includes the human-readable reason.
    #[error("invalid mining configuration: {0}")]
    InvalidConfig(String),

    /// Hex decode failed on a config-supplied or wire byte string.
    #[error("hex decode failed for {field}: {source}")]
    HexDecode {
        /// Caller-supplied label for the field whose bytes failed to
        /// decode (e.g. `"nonce"`, `"pk"`).
        field: &'static str,
        /// Underlying `hex` crate error.
        #[source]
        source: hex::FromHexError,
    },

    /// A byte string decoded but had the wrong length for its
    /// protocol slot.
    #[error("{field} must be {expected} bytes, got {got}")]
    WrongLength {
        /// Caller-supplied label for the offending field.
        field: &'static str,
        /// Required byte length.
        expected: usize,
        /// Actual length received.
        got: usize,
    },

    /// A deterministic computation in the candidate / coinbase /
    /// reemission assembly path failed. Covers id and bytes-to-sign
    /// computation (the original audit-1 motivation) plus the
    /// neighbouring numerical conversions, intermediate tx assembly
    /// (build / serialize / validate of the candidate's own coinbase),
    /// and difficulty / cost retargeting that share the same "honest
    /// flow shouldn't reach here, but if it does we surface the
    /// failure typed" semantics. Distinct from [`Decode`] (on-disk
    /// bytes refused to parse), [`StateRead`] (storage `None`/I/O
    /// fault), and [`EmissionInvariant`] (emission protocol contract
    /// violated by chain data).
    #[error("{op} failed: {reason}")]
    IdComputation {
        /// Short operation tag (e.g. `"emission_box_id"`,
        /// `"bytes_to_sign"`, `"validate_emission_tx"`,
        /// `"difficulty_retarget"`).
        op: &'static str,
        /// Free-text detail from the underlying computation.
        reason: String,
    },

    /// Chain bytes pulled from storage failed to deserialize during
    /// candidate assembly. Distinct from `IdComputation` because the
    /// failure points at on-disk data, not at logic flow.
    #[error("decode failed during {op}: {reason}")]
    Decode {
        /// Short operation tag (e.g. `"parent_header"`, `"extension"`,
        /// `"BlockTransactions"`).
        op: &'static str,
        /// Free-text detail from the underlying parser.
        reason: String,
    },

    /// An emission / reemission protocol invariant was violated by
    /// the input box shape or computed value.
    #[error("emission invariant violated in {op}: {reason}")]
    EmissionInvariant {
        /// Short operation tag (e.g.
        /// `"build_activation_emission_tx"`,
        /// `"build_post_eip27_emission_tx"`).
        op: &'static str,
        /// Detail describing which invariant tripped.
        reason: String,
    },

    /// A storage read inside candidate assembly either returned a
    /// backend I/O error (`Err`) or surfaced a logical absence
    /// (`Ok(None)` where the chain-state pointer required the row to
    /// be present). Both signals are fail-loud at the same severity:
    /// `Ok(None)` reaching this point means `best_full_block_id` /
    /// `chain_index` referenced storage that isn't there, which is
    /// state corruption equivalent to a redb-level fault. Distinct
    /// from [`Decode`] (bytes present but parse failed) and from
    /// [`EmissionInvariant`] (data present and decoded but violated
    /// the emission protocol contract).
    #[error("state read failed during {op}: {reason}")]
    StateRead {
        /// Short operation tag identifying the read.
        op: &'static str,
        /// Backend error rendered, or a `"<table> not in <store>"`
        /// description for the logical-absence path.
        reason: String,
    },

    /// Failed to decode the miner public key from its configured hex
    /// representation.
    #[error("invalid miner public key hex: {0}")]
    InvalidMinerPublicKey(String),

    /// Parent header could not be re-serialized while building a
    /// candidate's extension (interlinks computation). Unreachable in
    /// honest flow — the parent header was accepted into the chain
    /// before reaching this code path — but surfaced as a typed error
    /// so the caller can fail the candidate cleanly instead of aborting.
    #[error("failed to serialize parent header while computing interlinks: {0}")]
    HeaderSerialization(#[from] ergo_ser::error::WriteError),
}

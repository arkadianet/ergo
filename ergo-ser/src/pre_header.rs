//! Portable script-visible candidate pre-header.

/// Header fields fixed before mining starts. Mirrors Scala's
/// `PreHeader` (`PreHeader.scala`) minus the AutolykosV2 fields, which
/// only get set after the miner solves the puzzle.
///
/// A mining candidate's `votes` are always `[0, 0, 0]` in v1: automatic
/// voting bit selection is not yet implemented. Scala's mempool prediction
/// has none ([`PreHeaderVotes::Empty`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePreHeader {
    /// Block version. Comes from active protocol parameters
    /// (`active_params.block_version`).
    pub version: u8,
    /// Parent header id at the moment generation started. The
    /// post-dry-run guard compares this against the state's
    /// `best_full_block_id` to catch tip-flip races.
    pub parent_id: [u8; 32],
    /// Candidate height (`parent_header.height + 1`).
    pub height: u32,
    /// Candidate timestamp in milliseconds. Computed as
    /// `max(now_ms, parent_header.timestamp + 1)` so the chain time is
    /// monotonic.
    pub timestamp: u64,
    /// Difficulty target encoded as `nBits`. Either the parent's
    /// `n_bits` (non-retarget heights) or the recomputed retarget
    /// at epoch boundaries.
    pub n_bits: u32,
    /// Voting bits: `[0, 0, 0]` for a v1 mining candidate, none for the
    /// mempool prediction.
    pub votes: PreHeaderVotes,
    /// 33-byte compressed secp256k1 miner pubkey.
    pub miner_pubkey: [u8; 33],
}

/// `CONTEXT.preHeader.votes`.
///
/// A header or block candidate carries three vote bytes. Scala's mempool
/// context (`ErgoStateContext.simplifiedUpcoming`) predicts the next block
/// with `votes = Array.emptyByteArray`, which scripts see as an empty
/// `Coll[Byte]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreHeaderVotes {
    /// Three vote bytes.
    Bytes([u8; 3]),
    /// No vote bytes.
    Empty,
}

impl PreHeaderVotes {
    /// The vote bytes scripts read: three, or none.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::Empty => &[],
        }
    }

    /// The three vote bytes of a header or candidate; `None` when empty.
    pub fn bytes(&self) -> Option<[u8; 3]> {
        match self {
            Self::Bytes(bytes) => Some(*bytes),
            Self::Empty => None,
        }
    }
}

impl From<[u8; 3]> for PreHeaderVotes {
    fn from(bytes: [u8; 3]) -> Self {
        Self::Bytes(bytes)
    }
}

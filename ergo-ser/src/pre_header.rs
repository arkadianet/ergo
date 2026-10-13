//! Portable script-visible candidate pre-header.

/// Header fields fixed before mining starts. Mirrors Scala's
/// `PreHeader` (`PreHeader.scala`) minus the AutolykosV2 fields, which
/// only get set after the miner solves the puzzle.
///
/// `votes` is always `[0, 0, 0]` in v1 — automatic voting bit selection
/// is not yet implemented.
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
    /// Voting bits. Always `[0, 0, 0]` in v1.
    pub votes: [u8; 3],
    /// 33-byte compressed secp256k1 miner pubkey.
    pub miner_pubkey: [u8; 33],
}

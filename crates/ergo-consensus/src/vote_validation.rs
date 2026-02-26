//! Header vote validation (rules 212-215).
//!
//! Each Ergo block header contains a 3-byte `votes` array where miners can
//! cast up to 2 parameter change votes plus an optional soft-fork vote.
//! This module validates those vote bytes according to the Ergo consensus
//! rules:
//!
//! - **Rule 212 (hdrVotesNumber)**: At most `PARAM_VOTES_COUNT` (2) non-zero,
//!   non-soft-fork parameter votes.
//! - **Rule 213 (hdrVotesDuplicates)**: No duplicate vote bytes.
//! - **Rule 214 (hdrVotesContradictory)**: No contradictory votes (a vote
//!   for +N and -N simultaneously). Negation uses two's complement:
//!   the negation of vote byte `v` is `(256 - v) as u8`.
//! - **Rule 215 (hdrVotesUnknown)**: At epoch start, only known parameter
//!   IDs may appear.

use crate::parameters::KNOWN_PARAM_IDS;

const SOFT_FORK: u8 = 120;
const NO_PARAMETER: u8 = 0;
const PARAM_VOTES_COUNT: usize = 2;

/// Errors from header vote validation.
#[derive(Debug, thiserror::Error)]
pub enum VoteValidationError {
    /// More than `PARAM_VOTES_COUNT` non-zero, non-soft-fork parameter votes.
    #[error("too many parameter votes: {count} (max {PARAM_VOTES_COUNT})")]
    TooManyVotes { count: usize },

    /// The same vote byte appears more than once.
    #[error("duplicate vote byte: {vote}")]
    DuplicateVote { vote: u8 },

    /// A vote for +N and -N (two's complement negation) appear simultaneously.
    #[error("contradictory votes: {vote} and its negation")]
    ContradictoryVotes { vote: u8 },

    /// An unrecognized parameter ID was voted on at an epoch boundary.
    #[error("unknown parameter vote {vote} at epoch start")]
    UnknownVoteAtEpochStart { vote: u8 },
}

/// Validate the 3-byte vote array in a block header.
///
/// `epoch_starts` is true when `height % epoch_length == 0 && height > 0`.
pub fn validate_votes(
    votes: &[u8; 3],
    epoch_starts: bool,
) -> Result<(), VoteValidationError> {
    // Filter out zero (no-op) votes.
    let active: Vec<u8> = votes
        .iter()
        .copied()
        .filter(|&v| v != NO_PARAMETER)
        .collect();

    // Rule 212 (hdrVotesNumber): at most PARAM_VOTES_COUNT non-zero,
    // non-SoftFork parameter votes. The soft-fork vote (120) and its
    // negation (136 = 256-120) are excluded from the count.
    let soft_fork_negated = (256u16 - SOFT_FORK as u16) as u8;
    let param_count = active
        .iter()
        .filter(|&&v| v != SOFT_FORK && v != soft_fork_negated)
        .count();
    if param_count > PARAM_VOTES_COUNT {
        return Err(VoteValidationError::TooManyVotes { count: param_count });
    }

    for i in 0..active.len() {
        let v = active[i];

        // Rule 213 (hdrVotesDuplicates): no duplicate vote bytes.
        for other in &active[(i + 1)..] {
            if *other == v {
                return Err(VoteValidationError::DuplicateVote { vote: v });
            }
        }

        // Rule 214 (hdrVotesContradictory): no +N and -N simultaneously.
        // In Scala: vote and (256 - vote).toByte are contradictory.
        let negated = (256u16 - v as u16) as u8;
        if v != negated && active.contains(&negated) {
            return Err(VoteValidationError::ContradictoryVotes { vote: v });
        }
    }

    // Rule 215 (hdrVotesUnknown): at epoch start, only known parameter IDs.
    if epoch_starts {
        for &v in &active {
            // Get the base parameter ID (strip negation if present).
            // Negated votes have value > 128 (i.e., the signed byte is negative).
            let base_id = if (v as i8) < 0 {
                (256u16 - v as u16) as u8
            } else {
                v
            };
            if !KNOWN_PARAM_IDS.contains(&base_id) && base_id != 0 {
                return Err(VoteValidationError::UnknownVoteAtEpochStart { vote: v });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_votes_pass() {
        assert!(validate_votes(&[3, 0, 0], false).is_ok());
        assert!(validate_votes(&[3, 5, 120], false).is_ok()); // 2 params + softfork
        assert!(validate_votes(&[0, 0, 0], false).is_ok());
    }

    #[test]
    fn too_many_param_votes() {
        // 3 param votes (not counting softfork) exceeds limit of 2
        assert!(validate_votes(&[1, 2, 3], false).is_err());
    }

    #[test]
    fn duplicate_votes_rejected() {
        assert!(validate_votes(&[3, 3, 0], false).is_err());
    }

    #[test]
    fn contradictory_votes_rejected() {
        // 3 and (256-3)=253 are contradictory
        assert!(validate_votes(&[3, 253, 0], false).is_err());
    }

    #[test]
    fn unknown_vote_at_epoch_start() {
        assert!(validate_votes(&[99, 0, 0], true).is_err()); // 99 not in KNOWN_PARAM_IDS
        assert!(validate_votes(&[99, 0, 0], false).is_ok()); // mid-epoch is fine
    }

    #[test]
    fn known_votes_at_epoch_start() {
        assert!(validate_votes(&[3, 0, 0], true).is_ok()); // MaxBlockSize
        assert!(validate_votes(&[120, 0, 0], true).is_ok()); // SoftFork
    }

    #[test]
    fn negated_known_vote_at_epoch_start() {
        // Negation of param 3 is 253 (= 256 - 3). The base ID is 3 which is known.
        assert!(validate_votes(&[253, 0, 0], true).is_ok());
        // Negation of softfork 120 is 136 (= 256 - 120). The base ID is 120 which is known.
        assert!(validate_votes(&[136, 0, 0], true).is_ok());
    }

    #[test]
    fn negated_unknown_vote_at_epoch_start() {
        // Negation of unknown param 99 is 157 (= 256 - 99). The base ID is 99 which is unknown.
        assert!(validate_votes(&[157, 0, 0], true).is_err());
    }

    #[test]
    fn all_zeros_at_epoch_start() {
        assert!(validate_votes(&[0, 0, 0], true).is_ok());
    }

    #[test]
    fn softfork_does_not_count_as_param_vote() {
        // 2 param votes + softfork = fine (softfork is excluded from count)
        assert!(validate_votes(&[1, 2, 120], false).is_ok());
        // Negated softfork also excluded from count
        assert!(validate_votes(&[1, 2, 136], false).is_ok());
    }
}

use ergo_ser::header::Header;

use super::error::BlockValidationError;
use super::SoftForkState;

/// Scala `exCheckForkVote` (rule 407) — when the header casts a
/// SoftFork vote (parameter byte 120, see `KNOWN_VOTE_IDS` in
/// `header.rs`), reject if `header.height` falls inside the
/// previous soft-fork's prohibited window. `None` soft_fork_state
/// means no fork in progress — Scala's
/// `softForkStartingHeight.isEmpty` case — and the check is a
/// trivial pass.
/// Scala `ErgoStateContext.checkForkVote` reads `softForkVotesCollected.get`
/// immediately after `softForkStartingHeight.nonEmpty`. A hostile parameter
/// table carrying a soft-fork *start height* (id 122) but NO *votes-collected*
/// entry (id 121) makes that `.get` throw `NoSuchElementException`, which
/// `validateNoThrow(exCheckForkVote, ...)` surfaces as a rule-407 reject — but
/// ONLY when the header casts the SoftFork vote (Scala runs `checkForkVote`
/// `if (forkVote)`). The `Option<SoftForkState>` handed to [`validate_fork_vote`]
/// collapses this case to `None` (indistinguishable from "no soft fork in
/// progress"), so the block path must enforce it separately, here, from the raw
/// `softForkStartingHeight` / `softForkVotesCollected` params. Height-independent:
/// Scala throws at the `.get`, before the prohibited-window check, so the sign of
/// the starting height is irrelevant (matching `nonEmpty`).
pub fn check_fork_vote_votes_collected_present(
    header: &Header,
    soft_fork_starting_height: Option<i32>,
    soft_fork_votes_collected: Option<i32>,
    rule_407_disabled: bool,
) -> Result<(), BlockValidationError> {
    if rule_407_disabled {
        // Scala enforces this via `validateNoThrow(exCheckForkVote, ...)`, which
        // is disableable: a disabled rule 407 skips `checkForkVote` entirely, so
        // the `softForkVotesCollected.get` throw is never evaluated.
        return Ok(());
    }
    const SOFT_FORK_VOTE_BYTE: u8 = 120;
    if !header.votes.contains(&SOFT_FORK_VOTE_BYTE) {
        // Scala only evaluates `checkForkVote` `if (forkVote)`.
        return Ok(());
    }
    if soft_fork_starting_height.is_some() && soft_fork_votes_collected.is_none() {
        return Err(BlockValidationError::ForkVoteVotesCollectedMissing {
            height: header.height,
        });
    }
    Ok(())
}

pub fn validate_fork_vote(
    header: &Header,
    soft_fork_state: Option<&SoftForkState>,
) -> Result<(), BlockValidationError> {
    // Scala `Parameters.SoftFork: Byte = 120`. We match the
    // unsigned byte directly so the check is decoupled from i8/u8
    // sign-extension quirks.
    const SOFT_FORK_VOTE_BYTE: u8 = 120;
    let casts_fork_vote = header.votes.contains(&SOFT_FORK_VOTE_BYTE);
    if !casts_fork_vote {
        return Ok(());
    }
    let Some(state) = soft_fork_state else {
        return Ok(());
    };
    let (lo, hi) = state.prohibited_window();
    if header.height >= lo && header.height < hi {
        return Err(BlockValidationError::ForkVoteInProhibitedWindow {
            height: header.height,
            window_lo: lo,
            window_hi: hi,
        });
    }
    Ok(())
}

#[cfg(test)]
mod fork_vote_tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;

    fn test_header(height: u32, n_bits: u32) -> Header {
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 0,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0; 8],
            },
        }
    }

    #[test]
    fn fork_vote_no_state_passes_even_with_softfork_byte() {
        // No soft-fork in progress (ctx.soft_fork_state is None);
        // rule 407 is a trivial pass.
        let mut h = test_header(100, 0x20000000);
        h.votes = [120, 0, 0]; // SoftFork = 120
        validate_fork_vote(&h, None).unwrap();
    }

    // ---- rule 407: hostile 122-without-121 table (Scala checkForkVote .get) ----

    #[test]
    fn fork_vote_hostile_votes_collected_missing_rejects() {
        // Hostile parameter table: soft-fork START height present (id 122) but NO
        // votes-collected (id 121). Scala `checkForkVote` reads
        // `softForkVotesCollected.get` -> NoSuchElementException -> rule-407 reject,
        // when the header casts the SoftFork vote. Height-independent (the throw is
        // before the prohibited-window check).
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        let err = check_fork_vote_votes_collected_present(&h, Some(100), None, false).unwrap_err();
        assert!(
            matches!(
                err,
                BlockValidationError::ForkVoteVotesCollectedMissing { height: 2_000 }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn fork_vote_votes_collected_missing_disabled_rule_passes() {
        // Rule 407 disabled by an activated settings update: Scala's
        // `validateNoThrow(exCheckForkVote, ...)` skips `checkForkVote` entirely,
        // so the hostile table is accepted even with the SoftFork vote.
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        check_fork_vote_votes_collected_present(&h, Some(100), None, true).unwrap();
    }

    #[test]
    fn fork_vote_votes_collected_missing_without_softfork_vote_passes() {
        // Same hostile table but the header does NOT cast the SoftFork vote: Scala
        // only runs `checkForkVote` `if (forkVote)`, so no throw.
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [0, 0, 0];
        check_fork_vote_votes_collected_present(&h, Some(100), None, false).unwrap();
    }

    #[test]
    fn fork_vote_no_starting_height_passes_even_missing_votes() {
        // No soft-fork start height (id 122 absent): `softForkStartingHeight.nonEmpty`
        // is false, so `checkForkVote` does nothing -> pass even with vote 120.
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        check_fork_vote_votes_collected_present(&h, None, None, false).unwrap();
    }

    #[test]
    fn fork_vote_both_present_defers_to_window_check() {
        // (Some, Some) is well-formed: this guard passes (no `.get` throw); the
        // prohibited-window decision belongs to `validate_fork_vote`.
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        check_fork_vote_votes_collected_present(&h, Some(100), Some(0), false).unwrap();
    }

    #[test]
    fn fork_vote_outside_window_passes() {
        let mut h = test_header(2_000, 0x20000000);
        h.votes = [120, 0, 0];
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false,
        };
        // finishing = 100 + 1024*32 = 32868
        // rejected window: 32868..(32868+1024) = 32868..33892
        // height 2_000 is well below window → pass
        validate_fork_vote(&h, Some(&state)).unwrap();
    }

    #[test]
    fn fork_vote_inside_rejected_window_rejects() {
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false, // rejected
        };
        let (lo, _hi) = state.prohibited_window();
        let mut h = test_header(lo + 10, 0x20000000);
        h.votes = [120, 0, 0];
        let err = validate_fork_vote(&h, Some(&state)).unwrap_err();
        match err {
            BlockValidationError::ForkVoteInProhibitedWindow {
                height,
                window_lo,
                window_hi,
            } => {
                assert_eq!(height, lo + 10);
                assert_eq!(window_lo, lo);
                // Rejected window: hi = lo + voting_length
                assert_eq!(window_hi, lo + 1024);
            }
            other => panic!("expected ForkVoteInProhibitedWindow, got {other:?}"),
        }
    }

    #[test]
    fn fork_vote_inside_approved_extended_window_rejects() {
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 100_000,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: true,
        };
        let (lo, hi) = state.prohibited_window();
        // Approved window: hi = lo + voting_length * (activation_epochs + 1)
        // = lo + 1024 * 33
        assert_eq!(hi, lo + 1024 * 33);

        // Pick a height inside the extended window but outside the
        // rejected window (lo + voting_length + 1 onwards).
        let mut h = test_header(lo + 1024 + 5, 0x20000000);
        h.votes = [120, 0, 0];
        let err = validate_fork_vote(&h, Some(&state)).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::ForkVoteInProhibitedWindow { .. }
        ));
    }

    #[test]
    fn fork_vote_at_window_upper_bound_passes_exclusive() {
        // window_hi is exclusive: a vote at exactly window_hi passes.
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false,
        };
        let (_lo, hi) = state.prohibited_window();
        let mut h = test_header(hi, 0x20000000);
        h.votes = [120, 0, 0];
        validate_fork_vote(&h, Some(&state)).unwrap();
    }

    #[test]
    fn fork_vote_inside_window_without_softfork_byte_passes() {
        // No SoftFork (120) in votes → check doesn't fire even
        // inside the window.
        let state = SoftForkState {
            starting_height: 100,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false,
        };
        let (lo, _hi) = state.prohibited_window();
        let mut h = test_header(lo + 10, 0x20000000);
        h.votes = [3, 5, 0]; // not the soft-fork byte
        validate_fork_vote(&h, Some(&state)).unwrap();
    }

    #[test]
    fn fork_vote_window_arithmetic_saturates_on_extreme_starting_height() {
        // Adversarial starting_height near u32::MAX: window
        // calculation must saturate, not wrap.
        let state = SoftForkState {
            starting_height: u32::MAX - 1000,
            votes_collected: 0,
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            approved: false,
        };
        let (lo, hi) = state.prohibited_window();
        assert_eq!(lo, u32::MAX); // saturated
        assert_eq!(hi, u32::MAX); // saturated
                                  // Empty window: header.height < u32::MAX is below `lo` so passes.
        let mut h = test_header(100, 0x20000000);
        h.votes = [120, 0, 0];
        validate_fork_vote(&h, Some(&state)).unwrap();
    }
}

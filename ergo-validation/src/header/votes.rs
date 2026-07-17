use ergo_ser::header::Header;

use super::HeaderValidationError;

/// Scala `Parameters.SoftFork` (`settings/Parameters.scala`): the vote
/// byte (120) reserved for soft-fork signalling, excluded from the
/// rule-212 `votesCount`.
const SOFT_FORK_VOTE: i8 = 120;

/// Scala `Parameters.ParamVotesCount` (`settings/Parameters.scala`): the
/// maximum number of non-soft-fork parameter votes a header may cast.
const PARAM_VOTES_COUNT: usize = 2;

/// `Parameters.parametersDescs` keys from
/// `reference/ergo/.../settings/Parameters.scala:332-342`. The
/// Increase variants (1-8) for the eight votable parameters plus
/// `SoftFork = 120`. Decrease variants and the future
/// `SubblocksPerBlockIncrease = 9` (v6.0) are intentionally
/// absent — matches the captured Scala source we mirror.
const KNOWN_VOTE_IDS: [i8; 9] = [
    1,   // StorageFeeFactorIncrease
    2,   // MinValuePerByteIncrease
    3,   // MaxBlockSizeIncrease
    4,   // MaxBlockCostIncrease
    5,   // TokenAccessCostIncrease
    6,   // InputCostIncrease
    7,   // DataInputCostIncrease
    8,   // OutputCostIncrease
    120, // SoftFork
];

/// Scala `hdrVotesNumber` (rule 212) — reject when a header casts more
/// than `Parameters.ParamVotesCount` (2) non-`SoftFork` votes.
///
/// Mirrors `ErgoStateContext.validateVotes`
/// (`reference/ergo-core/.../nodeView/state/ErgoStateContext.scala:330-339`):
/// `votes = header.votes.filter(_ != NoParameter)` (drop 0 slots), then
/// `votesCount = votes.count(_ != SoftFork)` must be `<= ParamVotesCount`.
/// `NoParameter = 0`, `SoftFork = 120`, `ParamVotesCount = 2`
/// (`Parameters.scala`). The header carries only three vote slots, so the
/// count is at most 3 and only `[a, b, c]` with three distinct non-zero
/// non-120 bytes can trip it.
pub fn check_votes_number(header: &Header) -> Result<(), HeaderValidationError> {
    // Scala: `votes = header.votes.filter(_ != NoParameter)` then
    // `votesCount = votes.count(_ != SoftFork)`; reject when it exceeds
    // ParamVotesCount. NoParameter = 0, SoftFork = 120, ParamVotesCount = 2.
    let count = header
        .votes
        .iter()
        .map(|b| *b as i8)
        .filter(|v| *v != 0 && *v != SOFT_FORK_VOTE)
        .count();
    if count > PARAM_VOTES_COUNT {
        return Err(HeaderValidationError::VotesNumber { count });
    }
    Ok(())
}

/// Rule 212 (`hdrVotesNumber`) gated by its soft-fork deactivation status.
/// Scala marks this rule `mayBeDisabled = true`, so an activated
/// `ErgoValidationSettingsUpdate` can switch it off (after which a header
/// casting three distinct non-soft-fork votes is accepted). When the
/// activated settings disable the rule, Scala's `ValidationState` never runs
/// it; we mirror that by skipping the check. `rule_disabled` is supplied by
/// the caller from `ErgoValidationSettings::is_rule_disabled(212)` — invoked
/// at block-validation time (`ergo-sync::block_proc`), the same layer that
/// gates rule 215, because header-only validation cannot see the settings.
pub fn check_votes_number_active(
    header: &Header,
    rule_disabled: bool,
) -> Result<(), HeaderValidationError> {
    if rule_disabled {
        return Ok(());
    }
    check_votes_number(header)
}

/// Scala `hdrVotesDuplicates` (rule 213) — reject when two non-zero
/// vote bytes reference the same parameter id in the same direction.
///
/// Header vote slots carry an `i8` per slot: positive byte = vote to
/// increase the param, negative = vote to decrease, zero = no vote.
/// "Duplicate" means two slots with the same byte value (same param
/// id AND same direction); two slots with the same id but opposite
/// signs is `VotesContradictory` (rule 214).
pub fn check_votes_no_duplicates(header: &Header) -> Result<(), HeaderValidationError> {
    for first in 0..header.votes.len() {
        let a = header.votes[first];
        if a == 0 {
            continue;
        }
        for second in (first + 1)..header.votes.len() {
            let b = header.votes[second];
            if a == b {
                return Err(HeaderValidationError::VotesDuplicate {
                    param_id: (a as i8).unsigned_abs(),
                    first,
                    second,
                    byte: a as i8,
                });
            }
        }
    }
    Ok(())
}

/// Scala `hdrVotesContradictory` (rule 214) — reject when two
/// non-zero vote bytes reference the same parameter id with
/// opposite signs (one vote to increase, one to decrease — the
/// tally cancels to zero, so the header carries a deliberately
/// neutral vote that has no effect, which Scala treats as
/// malformed input rather than silently no-oping).
///
/// Untrusted-input guard: we use `wrapping_neg` instead of the raw `-`
/// operator because vote bytes arrive from the network as `u8` and
/// reinterpret as `i8` includes the value `-128` (`i8::MIN`). The
/// negation `-(-128_i8)` overflows: debug builds panic, release builds
/// wrap silently. `wrapping_neg` is exactly the JVM's `(-v).toByte`
/// (`ErgoStateContext.validateVotes:333`): `wrapping_neg(i8::MIN) ==
/// i8::MIN`, so a lone `0x80` is its OWN negation — `reverseVotes`
/// holds `-128` at its own index, `contains(-128)` is true, and rule
/// 214 REJECTS. The earlier `checked_neg`/`continue` swallowed that
/// case (accepting a header the JVM rejects); `wrapping_neg` plus the
/// explicit self-match below restores parity and never panics.
pub fn check_votes_no_contradictions(header: &Header) -> Result<(), HeaderValidationError> {
    for first in 0..header.votes.len() {
        let a = header.votes[first] as i8;
        if a == 0 {
            continue;
        }
        // The JVM's `reverseVotes = votes.map(v => (-v).toByte)` then
        // `!reverseVotes.contains(v)`. `wrapping_neg` IS `(-v).toByte`.
        let want = a.wrapping_neg();
        // Self-negation: only `i8::MIN` satisfies `want == a`. The JVM's
        // `reverseVotes` holds `a` at a's own index, so `contains(a)` is
        // true -> contradiction. (A non-i8::MIN value never equals its
        // own wrapping negation, so this arm is exactly the lone-0x80
        // case the old `checked_neg`/`continue` wrongly accepted.)
        if want == a {
            return Err(HeaderValidationError::VotesContradictory {
                param_id: a.unsigned_abs(),
                first,
                first_byte: a,
                second: first,
                second_byte: a,
            });
        }
        for second in (first + 1)..header.votes.len() {
            let b = header.votes[second] as i8;
            if b != 0 && b == want {
                return Err(HeaderValidationError::VotesContradictory {
                    param_id: a.unsigned_abs(),
                    first,
                    first_byte: a,
                    second,
                    second_byte: b,
                });
            }
        }
    }
    Ok(())
}

/// Scala `hdrVotesUnknown` (rule 215) — at an epoch-start header,
/// every non-zero vote byte must reference an id in
/// `Parameters.parametersDescs`. Scala source pin:
/// `reference/ergo/.../nodeView/state/ErgoStateContext.scala:344`
/// — the check is `epochStarts &&
/// !Parameters.parametersDescs.contains(v)`.
///
/// `parametersDescs` is keyed by the **Increase** parameter ids
/// (positive bytes) plus `SoftFork`. Concretely, the known set is:
/// `{1, 2, 3, 4, 5, 6, 7, 8, 120}`. Notably the **Decrease**
/// variants (`-1..=-8`) are NOT keys, so a decrease vote at an
/// epoch start would fire this rule — that's literal Scala
/// behavior (Decrease votes go through within an epoch's tally,
/// but the first header of a new epoch is treated as a
/// "proposal" slot and only increases / soft-fork are accepted).
///
/// Off-epoch headers (`height % voting_length != 0` or
/// `height == 0`) are unaffected; the check is a no-op on those.
///
/// Called separately at the network ingress site rather than
/// folded into `validate_header_after_pow` because it requires
/// `voting_length` from the chain config (Scala
/// `votingSettings.votingLength`).
pub fn check_votes_known(header: &Header, voting_length: u32) -> Result<(), HeaderValidationError> {
    // Scala `header.votingStarts(votingLength)`:
    //   height % votingLength == 0 && height > 0
    if voting_length == 0 || header.height == 0 || !header.height.is_multiple_of(voting_length) {
        return Ok(());
    }
    for (index, byte) in header.votes.iter().enumerate() {
        let v = *byte as i8;
        if v == 0 {
            continue;
        }
        if !KNOWN_VOTE_IDS.contains(&v) {
            return Err(HeaderValidationError::VotesUnknown {
                height: header.height,
                index,
                vote: v,
            });
        }
    }
    Ok(())
}

/// Rule 215 (`hdrVotesUnknown`) gated by its soft-fork deactivation
/// status. Scala marks this rule `mayBeDisabled = true`; mainnet's
/// v6.0 activation disabled it (its `ErgoValidationSettingsUpdate`
/// carries `rules_to_disable = [215, 409]`) so the new
/// `SubblocksPerBlock` parameter (id 9, absent from
/// `Parameters.parametersDescs`) — and downward parameter proposals
/// such as `MaxBlockCostDecrease` (-4) — can be voted on at an epoch
/// start. When the activated validation settings disable the rule,
/// Scala's `ValidationState` never runs it; we mirror that by skipping
/// the check entirely. `rule_disabled` is supplied by the caller from
/// `ErgoValidationSettings::is_rule_disabled(215)`.
pub fn check_votes_known_active(
    header: &Header,
    voting_length: u32,
    rule_disabled: bool,
) -> Result<(), HeaderValidationError> {
    if rule_disabled {
        return Ok(());
    }
    check_votes_known(header, voting_length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;

    // ----- helpers -----

    fn test_header(votes: [u8; 3], timestamp: u64) -> Header {
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 0x20000000,
            height: 1,
            votes,
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0; 8],
            },
        }
    }

    // ----- check_votes_no_duplicates (rule 213) -----

    #[test]
    fn votes_no_duplicates_accepts_zero_filled() {
        assert!(check_votes_no_duplicates(&test_header([0, 0, 0], 0)).is_ok());
    }

    #[test]
    fn votes_no_duplicates_accepts_unique_ids() {
        assert!(check_votes_no_duplicates(&test_header([3, 5, 7], 0)).is_ok());
    }

    #[test]
    fn votes_no_duplicates_accepts_opposite_signs() {
        // [3, -3, 0] is a contradiction (rule 214), NOT a duplicate
        // (rule 213). The duplicate check must let it pass so the
        // contradiction check fires with the right error variant.
        let votes = [3u8, (-3i8) as u8, 0u8];
        assert!(check_votes_no_duplicates(&test_header(votes, 0)).is_ok());
    }

    #[test]
    fn votes_no_duplicates_rejects_same_byte_repeat() {
        let err = check_votes_no_duplicates(&test_header([3, 3, 0], 0)).unwrap_err();
        match err {
            HeaderValidationError::VotesDuplicate {
                param_id,
                first,
                second,
                byte,
            } => {
                assert_eq!(param_id, 3);
                assert_eq!(first, 0);
                assert_eq!(second, 1);
                assert_eq!(byte, 3);
            }
            other => panic!("expected VotesDuplicate, got {other:?}"),
        }
    }

    #[test]
    fn votes_no_duplicates_rejects_same_negative_repeat() {
        let votes = [(-5i8) as u8, 0u8, (-5i8) as u8];
        let err = check_votes_no_duplicates(&test_header(votes, 0)).unwrap_err();
        match err {
            HeaderValidationError::VotesDuplicate {
                param_id,
                first,
                second,
                byte,
            } => {
                assert_eq!(param_id, 5);
                assert_eq!(first, 0);
                assert_eq!(second, 2);
                assert_eq!(byte, -5);
            }
            other => panic!("expected VotesDuplicate, got {other:?}"),
        }
    }

    // ----- check_votes_no_contradictions (rule 214) -----

    #[test]
    fn votes_no_contradictions_accepts_zero_filled() {
        assert!(check_votes_no_contradictions(&test_header([0, 0, 0], 0)).is_ok());
    }

    #[test]
    fn votes_no_contradictions_accepts_unique_ids() {
        assert!(check_votes_no_contradictions(&test_header([3, 5, 7], 0)).is_ok());
    }

    #[test]
    fn votes_no_contradictions_accepts_same_sign_duplicate() {
        // [3, 3, 0] is a duplicate (rule 213), not a contradiction.
        // Contradiction check must let it pass.
        assert!(check_votes_no_contradictions(&test_header([3, 3, 0], 0)).is_ok());
    }

    #[test]
    fn votes_no_contradictions_rejects_plus_minus_pair() {
        let votes = [3u8, (-3i8) as u8, 0u8];
        let err = check_votes_no_contradictions(&test_header(votes, 0)).unwrap_err();
        match err {
            HeaderValidationError::VotesContradictory {
                param_id,
                first_byte,
                second_byte,
                ..
            } => {
                assert_eq!(param_id, 3);
                assert_eq!(first_byte, 3);
                assert_eq!(second_byte, -3);
            }
            other => panic!("expected VotesContradictory, got {other:?}"),
        }
    }

    #[test]
    fn votes_no_contradictions_rejects_when_pair_is_split_by_zero() {
        // Zero slot between contradiction shouldn't hide it.
        let votes = [7u8, 0u8, (-7i8) as u8];
        assert!(check_votes_no_contradictions(&test_header(votes, 0)).is_err());
    }

    #[test]
    fn votes_no_contradictions_rejects_lone_i8_min_self_negation() {
        // Vote byte 0x80 = i8::MIN (-128) is its own negation under the
        // wrapping `(-v).toByte` the JVM uses: `reverseVotes` for a lone
        // -128 is `[-128]`, so `reverseVotes.contains(-128)` is true and
        // `hdrVotesContradictory` (rule 214) REJECTS. A naive `a == -b`
        // would panic in debug / wrap silently in release; the impl must
        // use `wrapping_neg` and treat the self-match as a contradiction.
        let votes = [0x80_u8, 0u8, 0u8];
        let err = check_votes_no_contradictions(&test_header(votes, 0))
            .expect_err("lone 0x80 self-negates -> rule 214 contradiction");
        assert!(
            matches!(err, HeaderValidationError::VotesContradictory { .. }),
            "expected VotesContradictory for lone 0x80, got {err:?}",
        );
    }

    #[test]
    fn votes_no_contradictions_triple_i8_min_does_not_panic() {
        // [0x80, 0x80, 0x80] must not panic on negation. At the header
        // level the duplicate pass (rule 213) fires first; the
        // contradiction pass also flags it (self-negation) but never
        // panics on the adversarial i8::MIN input.
        let votes = [0x80_u8, 0x80_u8, 0x80_u8];
        let dup_err = check_votes_no_duplicates(&test_header(votes, 0)).unwrap_err();
        assert!(matches!(
            dup_err,
            HeaderValidationError::VotesDuplicate { .. }
        ));
        // Contradiction pass: no panic (result is Err, the self-negation).
        let _ = check_votes_no_contradictions(&test_header(votes, 0));
    }

    // ----- check_votes_number (rule 212) -----

    #[test]
    fn votes_number_accepts_zero_filled() {
        assert!(check_votes_number(&test_header([0, 0, 0], 0)).is_ok());
    }

    #[test]
    fn votes_number_accepts_two_non_softfork() {
        // Two distinct parameter votes is the maximum the JVM allows.
        assert!(check_votes_number(&test_header([3, 5, 0], 0)).is_ok());
    }

    #[test]
    fn votes_number_softfork_byte_is_not_counted() {
        // SoftFork (120) is excluded from votesCount, so [120, 3, 5]
        // has only TWO counted votes and is accepted.
        let votes = [120u8, 3u8, 5u8];
        assert!(check_votes_number(&test_header(votes, 0)).is_ok());
    }

    #[test]
    fn votes_number_rejects_three_non_softfork() {
        // Three distinct non-soft-fork votes: votesCount = 3 > 2 -> the
        // JVM `hdrVotesNumber` (rule 212) rejects. This is the chain-tier
        // `count-three-nonfork-reject` coal (we currently ACCEPT it).
        let err = check_votes_number(&test_header([1, 2, 3], 0))
            .expect_err("three non-soft-fork votes exceed ParamVotesCount=2");
        match err {
            HeaderValidationError::VotesNumber { count } => assert_eq!(count, 3),
            other => panic!("expected VotesNumber{{count:3}}, got {other:?}"),
        }
    }

    #[test]
    fn votes_number_rejects_three_with_negatives() {
        // Decrease votes (negative bytes) count too: [-1, -2, -3] -> 3.
        let votes = [(-1i8) as u8, (-2i8) as u8, (-3i8) as u8];
        let err = check_votes_number(&test_header(votes, 0))
            .expect_err("three negative votes also exceed the cap");
        assert!(matches!(
            err,
            HeaderValidationError::VotesNumber { count: 3 }
        ));
    }

    #[test]
    fn votes_number_active_skips_when_rule_212_disabled() {
        // Rule 212 is soft-fork-deactivatable: when disabled, a header with
        // three distinct non-soft-fork votes must be ACCEPTED (Scala stops
        // running the rule); when enabled, it rejects.
        let three = test_header([1, 2, 3], 0);
        assert!(check_votes_number_active(&three, true).is_ok());
        let err = check_votes_number_active(&three, false).unwrap_err();
        assert!(matches!(
            err,
            HeaderValidationError::VotesNumber { count: 3 }
        ));
    }

    #[test]
    fn votes_no_contradictions_no_panic_on_adversarial_input() {
        // Sweep every (a, b) pair across the full u8 domain to
        // ensure the contradiction check never panics on
        // adversarial input. Catches any regression that
        // re-introduces the `-b` arithmetic.
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let votes = [a, b, 0];
                // Just calling — both checks must return without panic.
                let _ = check_votes_no_contradictions(&test_header(votes, 0));
                let _ = check_votes_no_duplicates(&test_header(votes, 0));
            }
        }
    }

    // ----- integration: validate_header_after_pow wires votes checks -----
    //
    // We cannot easily integration-test this without a real PoW
    // solution, but the wire-up via `check_votes_no_duplicates` /
    // `check_votes_no_contradictions` is one-liner; the unit tests
    // above are the regression guards. A bad-vote regression in a
    // real block would surface as `Validation(VotesDuplicate)` or
    // `Validation(VotesContradictory)` from `header_proc.rs`.

    // ----- check_votes_known (rule 215) -----

    fn header_with_height(height: u32, votes: [u8; 3]) -> Header {
        let mut h = test_header(votes, 0);
        h.height = height;
        h
    }

    const MAINNET_VOTING_LENGTH: u32 = 1024;

    #[test]
    fn votes_known_passes_off_epoch_with_unknown_id() {
        // h=100 isn't an epoch start (100 % 1024 != 0), so the rule
        // is a no-op even if a vote byte is bogus.
        let h = header_with_height(100, [200, 0, 0]);
        assert!(check_votes_known(&h, MAINNET_VOTING_LENGTH).is_ok());
    }

    #[test]
    fn votes_known_passes_at_genesis() {
        // h=0 is explicitly excluded by `votingStarts`.
        let h = header_with_height(0, [200, 0, 0]);
        assert!(check_votes_known(&h, MAINNET_VOTING_LENGTH).is_ok());
    }

    #[test]
    fn votes_known_passes_zero_voting_length() {
        // Defensive guard: voting_length=0 would divide-by-zero
        // without the early return. Treat as "no voting epoch" and
        // skip the rule.
        let h = header_with_height(1024, [200, 0, 0]);
        assert!(check_votes_known(&h, 0).is_ok());
    }

    /// SAFETY NET for the candidate-vote selector: every `[u8;3]`
    /// `select_candidate_votes` produces — across diverse operator configs, at
    /// off-epoch and epoch-start heights, under BOTH rule-215 regimes — must
    /// PASS the real header-votes validators (rules 212/213/214/215). If the
    /// selector ever emitted a vote the header validator rejects, our mined
    /// block would be rejected by peers; this pins that it can't, in lockstep
    /// with the exact rule-215 status the selector was told to assume.
    #[test]
    fn selected_candidate_votes_always_pass_header_validators() {
        use crate::active_params::scala_launch;
        use crate::voting::select_candidate_votes;
        use std::collections::BTreeMap;

        let mut active = scala_launch();
        active.subblocks_per_block = Some(4); // id 9 active so it's a candidate vote

        let cfg = |pairs: &[(u8, i64)]| -> BTreeMap<u8, i64> { pairs.iter().copied().collect() };
        let configs = [
            cfg(&[]),                               // neutral
            cfg(&[(1, 2_000_000), (4, 9_000_000)]), // two increases
            cfg(&[(1, 2_000_000), (3, 100_000)]),   // increase + decrease
            cfg(&[(9, 8)]),                         // id 9 increase (active)
            cfg(&[(3, 100_000)]),                   // decrease only
            // four increases — must cap to two:
            cfg(&[
                (1, 9_000_000),
                (2, 9_000_000),
                (3, 9_000_000),
                (4, 9_000_000),
            ]),
        ];

        for targets in &configs {
            for (height, is_epoch_start) in [(100u32, false), (MAINNET_VOTING_LENGTH, true)] {
                // The selector is handed a rule-215 status; rule 215 must be
                // checked with that SAME status (`check_votes_known_active`),
                // since a disabled rule 215 is exactly what makes a decrease /
                // id-9 vote valid at an epoch start.
                for rule_215_disabled in [false, true] {
                    let votes =
                        select_candidate_votes(&active, targets, is_epoch_start, rule_215_disabled);
                    let h = header_with_height(height, votes);
                    assert!(
                        check_votes_number_active(&h, false).is_ok(),
                        "rule 212: votes={votes:?} @ h={height} r215d={rule_215_disabled}"
                    );
                    assert!(
                        check_votes_no_duplicates(&h).is_ok(),
                        "rule 213: votes={votes:?} @ h={height} r215d={rule_215_disabled}"
                    );
                    assert!(
                        check_votes_no_contradictions(&h).is_ok(),
                        "rule 214: votes={votes:?} @ h={height} r215d={rule_215_disabled}"
                    );
                    assert!(
                        check_votes_known_active(&h, MAINNET_VOTING_LENGTH, rule_215_disabled)
                            .is_ok(),
                        "rule 215: votes={votes:?} @ h={height} r215d={rule_215_disabled}"
                    );
                }
            }
        }
    }

    #[test]
    fn votes_known_passes_epoch_start_all_known_votes() {
        // h=1024 IS an epoch start. Votes 3 (MaxBlockSize), 5
        // (TokenAccessCost), 120 (SoftFork) are all in
        // `parametersDescs`.
        let h = header_with_height(1024, [3, 5, 120]);
        assert!(check_votes_known(&h, MAINNET_VOTING_LENGTH).is_ok());
    }

    #[test]
    fn votes_known_passes_epoch_start_all_no_vote() {
        // h=2048 epoch start, all zeros (NoParameter) — accepted.
        let h = header_with_height(2048, [0, 0, 0]);
        assert!(check_votes_known(&h, MAINNET_VOTING_LENGTH).is_ok());
    }

    #[test]
    fn votes_known_rejects_epoch_start_unknown_id() {
        // h=1024 + vote byte 200 (not in known set).
        let h = header_with_height(1024, [3, 200, 0]);
        let err = check_votes_known(&h, MAINNET_VOTING_LENGTH).unwrap_err();
        match err {
            HeaderValidationError::VotesUnknown {
                height,
                index,
                vote,
            } => {
                assert_eq!(height, 1024);
                assert_eq!(index, 1);
                // 200 as u8 → as i8 → -56 (sign-extended). Verify
                // the variant carries the original signed byte
                // for log triage.
                assert_eq!(vote, 200u8 as i8);
            }
            other => panic!("expected VotesUnknown, got {other:?}"),
        }
    }

    #[test]
    fn votes_known_rejects_epoch_start_decrease_vote() {
        // Literal Scala behavior pin: Decrease variants (-1..=-8)
        // are NOT in `parametersDescs`. At epoch start the rule
        // fires even on a "legitimate" downward proposal.
        let votes_decrease: [u8; 3] = [(-3i8) as u8, 0, 0]; // MaxBlockSizeDecrease
        let h = header_with_height(1024, votes_decrease);
        let err = check_votes_known(&h, MAINNET_VOTING_LENGTH).unwrap_err();
        match err {
            HeaderValidationError::VotesUnknown { vote, .. } => {
                assert_eq!(vote, -3);
            }
            other => panic!("expected VotesUnknown for Decrease vote, got {other:?}"),
        }
    }

    #[test]
    fn votes_known_first_offender_index_pinned() {
        // Multiple unknowns — the rule reports the first slot index.
        let h = header_with_height(1024, [200, 201, 0]);
        match check_votes_known(&h, MAINNET_VOTING_LENGTH).unwrap_err() {
            HeaderValidationError::VotesUnknown { index, .. } => assert_eq!(index, 0),
            other => panic!("expected VotesUnknown at index 0, got {other:?}"),
        }
    }

    #[test]
    fn votes_known_testnet_epoch_length_128() {
        // Testnet voting_length=128. h=256 IS an epoch start at
        // that cadence; same height is OFF-epoch at mainnet's 1024.
        let unknown = header_with_height(256, [200, 0, 0]);
        assert!(check_votes_known(&unknown, MAINNET_VOTING_LENGTH).is_ok());
        let err = check_votes_known(&unknown, 128).unwrap_err();
        assert!(matches!(err, HeaderValidationError::VotesUnknown { .. }));
    }

    #[test]
    fn votes_known_active_skips_when_rule_215_disabled() {
        // Real mainnet block 1802240 — an epoch start (1802240 % 1024
        // == 0) whose header votes are `fc0000`: slot 0 = -4
        // (MaxBlockCostDecrease), slots 1-2 = no-vote. Mainnet's v6.0
        // soft-fork disabled rule 215 (alongside 409) so the new
        // SubblocksPerBlock param id 9 — and downward proposals — are
        // votable at an epoch start; the canonical chain contains this
        // block. Scala's `ValidationState` never runs a disabled rule,
        // so the node must skip rule 215 when the activated validation
        // settings disable it. Enforcing it unconditionally is what
        // stalled the node at 1802240.
        let h = header_with_height(1802240, [(-4i8) as u8, 0, 0]);

        // Rule active (not disabled): still rejected, identical to the
        // raw rule — regression guard that the gate never loosens the
        // active path.
        match check_votes_known_active(&h, MAINNET_VOTING_LENGTH, false).unwrap_err() {
            HeaderValidationError::VotesUnknown {
                height,
                index,
                vote,
            } => {
                assert_eq!(height, 1802240);
                assert_eq!(index, 0);
                assert_eq!(vote, -4);
            }
            other => panic!("expected VotesUnknown when rule active, got {other:?}"),
        }

        // Rule disabled by an activated soft-fork: accepted, matching
        // the canonical mainnet chain and Scala.
        assert!(check_votes_known_active(&h, MAINNET_VOTING_LENGTH, true).is_ok());
    }
}

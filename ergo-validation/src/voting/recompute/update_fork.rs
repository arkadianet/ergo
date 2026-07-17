use crate::active_params::ActiveProtocolParameters;
use crate::voting::validation_settings::ErgoValidationSettingsUpdate;

use super::{
    RecomputeError, VotingSettings, SOFT_FORK_ID, SOFT_FORK_STARTING_HEIGHT_ID,
    SOFT_FORK_VOTES_COLLECTED_ID,
};

/// `Parameters.updateFork` (`Parameters.scala:98-155`). Six height-
/// equation triggers, evaluated in order. Mutates the soft-fork state
/// keys 121, 122, and the BlockVersion key 123.
///
/// All six triggers stay in this one function deliberately: each reads
/// `starting_height_opt` — the PRE-mutation snapshot of the soft-fork
/// starting height — rather than the table any earlier trigger in this
/// same call may have just written, and the inline comments on
/// Triggers 2/3/4 explicitly cross-reference each other to explain why
/// (e.g. Trigger 4 must NOT re-read a height Trigger 3 just wrote, or
/// a fresh round's `votesCollected = 0` gets clobbered by this epoch's
/// tally). Splitting the triggers into separate functions would
/// scatter that shared context and invite exactly the bug the
/// comments warn against.
pub(super) fn update_fork(
    prev: &ActiveProtocolParameters,
    fork_vote: bool,
    epoch_votes: &[(i8, i32)],
    proposed_update: &ErgoValidationSettingsUpdate,
    height: u32,
    vs: &VotingSettings,
) -> Result<(ActiveProtocolParameters, ErgoValidationSettingsUpdate), RecomputeError> {
    let mut next = prev.clone();
    let mut activated = ErgoValidationSettingsUpdate::empty();

    let voting_epoch_length = vs.voting_length as i32;
    let voting_epochs = vs.soft_fork_epochs as i32;
    let activation_epochs = vs.activation_epochs as i32;

    // Soft-fork accumulator state. Scala's `votes` is a LAZY val
    // `votesInPrevEpoch + parametersTable(SoftForkVotesCollected)`
    // (`Parameters.scala:108`): the `Map.apply` THROWS when id 121 is absent,
    // but only if `votes` is actually evaluated by a firing trigger (all
    // votes-reading triggers are guarded by `softForkStartingHeight.nonEmpty`
    // / a height equality). We mirror the laziness with a closure called
    // `votes()?` at exactly those sites — faulting (accept-invalid parity)
    // on a hostile 122-without-121 table, while a table that never reaches a
    // votes-reading trigger (the common 122-absent case) never faults.
    let votes_in_prev_epoch = epoch_votes
        .iter()
        .find_map(|(id, n)| (*id == SOFT_FORK_ID).then_some(*n))
        .unwrap_or(0);
    let collected = prev.soft_fork_votes_collected();
    let votes = || -> Result<i32, RecomputeError> {
        collected
            .map(|c| votes_in_prev_epoch + c)
            .ok_or(RecomputeError::SoftForkVotesCollectedMissing)
    };

    // Scala reads `softForkStartingHeight` from the INPUT `parametersTable`
    // once and every trigger keys on that original value — never on the
    // mutated output table. Re-reading the height a prior trigger just
    // wrote (e.g. Trigger 3 starting a new round) makes Trigger 4's
    // `height <= startingHeight + L*votingEpochs` spuriously true and
    // clobbers the fresh `votesCollected = 0` with this epoch's tally — a
    // reject-valid divergence on every soft-fork round start/restart.
    let starting_height_opt = prev.soft_fork_starting_height();

    // Trigger 1: successful voting cleanup.
    if let Some(starting_height) = starting_height_opt {
        if height as i32
            == starting_height + voting_epoch_length * (voting_epochs + activation_epochs + 1)
            && vs.soft_fork_approved(votes()?)
        {
            next = remove_extra(&next, SOFT_FORK_STARTING_HEIGHT_ID);
            next = remove_extra(&next, SOFT_FORK_VOTES_COLLECTED_ID);
        }
    }

    // Trigger 2: unsuccessful voting cleanup. (Keyed on the original
    // `starting_height_opt`, like Scala — not the post-Trigger-1 table.)
    if let Some(starting_height) = starting_height_opt {
        if height as i32 == starting_height + voting_epoch_length * (voting_epochs + 1)
            && !vs.soft_fork_approved(votes()?)
        {
            next = remove_extra(&next, SOFT_FORK_STARTING_HEIGHT_ID);
            next = remove_extra(&next, SOFT_FORK_VOTES_COLLECTED_ID);
        }
    }

    // Trigger 3: new voting starts.
    let starts_new = if fork_vote {
        match starting_height_opt {
            None => height.is_multiple_of(vs.voting_length),
            Some(starting_height) => {
                let post_activation = height as i32
                    == starting_height
                        + voting_epoch_length * (voting_epochs + activation_epochs + 1);
                let post_failed = height as i32
                    == starting_height + voting_epoch_length * (voting_epochs + 1)
                    && !vs.soft_fork_approved(votes()?);
                post_activation || post_failed
            }
        }
    } else {
        false
    };
    if starts_new {
        next = upsert_extra(&next, SOFT_FORK_STARTING_HEIGHT_ID, height as i32);
        next = upsert_extra(&next, SOFT_FORK_VOTES_COLLECTED_ID, 0);
    }

    // Trigger 4: vote tallying during active voting. Keyed on the ORIGINAL
    // starting height: if Trigger 3 just opened a new round, the original
    // was either empty (fresh start) or an older, now-cleaned round whose
    // tally window has passed — so this trigger correctly does NOT re-tally
    // and the round's `votesCollected` stays 0.
    if let Some(starting_height) = starting_height_opt {
        if (height as i32) <= starting_height + voting_epoch_length * voting_epochs {
            next = upsert_extra(&next, SOFT_FORK_VOTES_COLLECTED_ID, votes()?);
        }
    }

    // Trigger 5: activation.
    if let Some(starting_height) = starting_height_opt {
        if height as i32
            == starting_height + voting_epoch_length * (voting_epochs + activation_epochs)
            && vs.soft_fork_approved(votes()?)
        {
            next.block_version = next.block_version.saturating_add(1);
            activated = proposed_update.clone();
        }
    }

    // Trigger 6: forced v2 activation. Networks whose genesis already
    // carries a v2-or-later block version (Interpreter60Version on the
    // new public testnet) leave `version2_activation = None`, so this
    // branch never fires.
    if let Some(activation_height) = vs.version2_activation {
        if height == activation_height && next.block_version == 1 {
            next.block_version = 2;
        }
    }

    Ok((next, activated))
}

// ----- Helpers: extras manipulation -----

fn upsert_extra(p: &ActiveProtocolParameters, id: u8, value: i32) -> ActiveProtocolParameters {
    let mut next = p.clone();
    let mut found = false;
    for entry in next.extra.iter_mut() {
        if entry.0 == id {
            entry.1 = value;
            found = true;
            break;
        }
    }
    if !found {
        next.extra.push((id, value));
        next.extra.sort_by_key(|(eid, _)| *eid);
    }
    next
}

fn remove_extra(p: &ActiveProtocolParameters, id: u8) -> ActiveProtocolParameters {
    let mut next = p.clone();
    next.extra.retain(|(eid, _)| *eid != id);
    next
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_params::scala_launch;
    use crate::voting::recompute::RULE_EX_MATCH_PARAMETERS;

    fn launch_at(height: u32) -> ActiveProtocolParameters {
        let mut p = scala_launch();
        p.epoch_start_height = height;
        p
    }

    fn vs() -> VotingSettings {
        VotingSettings::mainnet()
    }

    // ----- Threshold sanity (soft-fork approval) -----

    #[test]
    fn threshold_soft_fork_approved_29492_passes() {
        assert!(vs().soft_fork_approved(29_492));
    }

    #[test]
    fn threshold_soft_fork_approved_29491_fails() {
        assert!(!vs().soft_fork_approved(29_491));
    }

    // ----- updateFork: state machine triggers -----

    #[test]
    fn fork_trigger_3_starts_new_voting_when_no_prior() {
        let prev = launch_at(0);
        let height = 1024; // % 1024 == 0
        let (next, activated) = update_fork(
            &prev,
            true, /* fork_vote */
            &[],
            &ErgoValidationSettingsUpdate::empty(),
            height,
            &vs(),
        )
        .unwrap();
        assert_eq!(next.soft_fork_starting_height(), Some(1024));
        assert_eq!(next.soft_fork_votes_collected(), Some(0));
        assert!(activated.rules_to_disable.is_empty());
    }

    #[test]
    fn fork_trigger_4_accumulates_votes() {
        // softForkStartingHeight set, no activation/cleanup yet, fork
        // vote tally accumulates.
        let mut prev = launch_at(0);
        prev = upsert_extra(&prev, SOFT_FORK_STARTING_HEIGHT_ID, 1024);
        prev = upsert_extra(&prev, SOFT_FORK_VOTES_COLLECTED_ID, 100);

        let votes = vec![(SOFT_FORK_ID, 50)];
        let height = 2048; // <= 1024 + 1024*32
        let (next, _activated) = update_fork(
            &prev,
            false,
            &votes,
            &ErgoValidationSettingsUpdate::empty(),
            height,
            &vs(),
        )
        .unwrap();
        assert_eq!(next.soft_fork_votes_collected(), Some(150));
    }

    #[test]
    fn fork_trigger_4_skipped_when_round_just_started() {
        // A soft-fork round STARTS this epoch (no prior round). Trigger 3
        // sets startingHeight=height, votesCollected=0. Scala's trigger-4
        // condition reads the ORIGINAL softForkStartingHeight (None here),
        // so trigger 4 is SKIPPED and votesCollected stays 0. Re-reading
        // the just-written height (the bug) makes `height <= height + L*32`
        // true and clobbers 0 with the tally. SANTA: softfork-round-start.
        let prev = launch_at(0); // no soft-fork keys
        let votes = vec![(SOFT_FORK_ID, 50)];
        let (next, _) = update_fork(
            &prev,
            true, /* fork_vote */
            &votes,
            &ErgoValidationSettingsUpdate::empty(),
            1024,
            &vs(),
        )
        .unwrap();
        assert_eq!(next.soft_fork_starting_height(), Some(1024));
        assert_eq!(
            next.soft_fork_votes_collected(),
            Some(0),
            "votesCollected must reset to 0 on round start, not carry the tally",
        );
    }

    #[test]
    fn fork_trigger_4_skipped_on_failed_restart() {
        // Old round failed; this epoch is the failed-cleanup point AND a
        // new round restarts (trigger 2 cleans, trigger 3 restarts). The
        // restart height is `old + L*(votingEpochs+1)` which is strictly
        // greater than `old + L*votingEpochs`, so Scala's trigger-4
        // (keyed on the ORIGINAL starting height) is skipped → collected 0.
        // SANTA: softfork-round-failed-restart.
        let l = vs().voting_length as i32;
        let start = l; // 1024
        let mut prev = launch_at(0);
        prev = upsert_extra(&prev, SOFT_FORK_STARTING_HEIGHT_ID, start);
        prev = upsert_extra(&prev, SOFT_FORK_VOTES_COLLECTED_ID, 100); // not approved
        let height = (start + l * (vs().soft_fork_epochs as i32 + 1)) as u32;
        let votes = vec![(SOFT_FORK_ID, 10)]; // votes = 10 + 100 = 110, not approved
        let (next, _) = update_fork(
            &prev,
            true,
            &votes,
            &ErgoValidationSettingsUpdate::empty(),
            height,
            &vs(),
        )
        .unwrap();
        assert_eq!(next.soft_fork_starting_height(), Some(height as i32));
        assert_eq!(
            next.soft_fork_votes_collected(),
            Some(0),
            "votesCollected must reset to 0 on failed-restart, not carry 110",
        );
    }

    #[test]
    fn fork_trigger_5_activation_bumps_block_version() {
        let mut prev = launch_at(0);
        prev.block_version = 3;
        prev = upsert_extra(&prev, SOFT_FORK_STARTING_HEIGHT_ID, 1024);
        // Set collected high enough that votes pass softForkApproved.
        prev = upsert_extra(&prev, SOFT_FORK_VOTES_COLLECTED_ID, 30_000);

        let proposed = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![RULE_EX_MATCH_PARAMETERS],
            status_updates: vec![],
        };
        // Activation height: starting_height + 1024 * (32+32) = 1024 + 65536 = 66560
        let height = 66560;
        let (next, activated) = update_fork(&prev, false, &[], &proposed, height, &vs()).unwrap();
        assert_eq!(next.block_version, 4);
        assert_eq!(activated, proposed);
    }

    #[test]
    fn fork_trigger_6_forced_v2_activation() {
        let mut prev = launch_at(0);
        prev.block_version = 1;
        let height = vs()
            .version2_activation
            .expect("mainnet fixture has v2 activation height");
        let (next, activated) = update_fork(
            &prev,
            false,
            &[],
            &ErgoValidationSettingsUpdate::empty(),
            height,
            &vs(),
        )
        .unwrap();
        assert_eq!(next.block_version, 2);
        assert!(activated.rules_to_disable.is_empty());
    }

    #[test]
    fn fork_trigger_6_does_not_fire_if_block_version_not_1() {
        let mut prev = launch_at(0);
        prev.block_version = 2;
        let height = vs()
            .version2_activation
            .expect("mainnet fixture has v2 activation height");
        let (next, _) = update_fork(
            &prev,
            false,
            &[],
            &ErgoValidationSettingsUpdate::empty(),
            height,
            &vs(),
        )
        .unwrap();
        assert_eq!(next.block_version, 2); // unchanged
    }

    // ----- hostile-table eager-throw parity (accept-invalid) -----

    #[test]
    fn update_fork_faults_when_122_present_121_absent() {
        // Hostile table: soft-fork starting height (122) set but
        // votes-collected (121) absent. When a votes-reading trigger fires
        // (here Trigger 4, the active-voting tally window), Scala's
        // parametersTable(121) Map.apply throws; we must fault, not
        // unwrap_or(0). SANTA chain: hostile-122-without-121.
        let mut prev = launch_at(0);
        prev = upsert_extra(&prev, SOFT_FORK_STARTING_HEIGHT_ID, 1024);
        // deliberately NOT writing id 121
        let votes = vec![(SOFT_FORK_ID, 50)];
        let height = 2048; // <= 1024 + L*32 -> Trigger 4 reads votes
        let err = update_fork(
            &prev,
            false,
            &votes,
            &ErgoValidationSettingsUpdate::empty(),
            height,
            &vs(),
        )
        .unwrap_err();
        assert_eq!(err, RecomputeError::SoftForkVotesCollectedMissing);
    }

    #[test]
    fn update_fork_no_fault_when_122_absent() {
        // No soft-fork round (122 absent): no trigger reads `votes`, so the
        // missing 121 must NOT fault — faulting here would be reject-valid on
        // the overwhelmingly common case. (Guards against an eager fault.)
        let prev = launch_at(0); // no 121/122
        let votes = vec![(SOFT_FORK_ID, 50)];
        let (next, _) = update_fork(
            &prev,
            false,
            &votes,
            &ErgoValidationSettingsUpdate::empty(),
            1024,
            &vs(),
        )
        .expect("122 absent must not fault on missing 121");
        assert_eq!(next.soft_fork_votes_collected(), None);
    }
}

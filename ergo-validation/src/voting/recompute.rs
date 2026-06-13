//! Recompute pipeline for the next epoch's active protocol parameters.
//!
//! Mirrors `Parameters.update` (`Parameters.scala:82-96`):
//! `update_fork → update_params → apply_subblocks_injection`.
//!
//! Pure functions, no I/O.

use crate::active_params::ActiveProtocolParameters;
use crate::voting::validation_settings::ErgoValidationSettingsUpdate;

// ----- Voting parameter vote/rule constants -----

/// `Parameters.SoftFork = 120`. Vote id for soft-fork.
pub const SOFT_FORK_ID: i8 = 120;

/// `Parameters.SoftForkVotesCollected = 121`. Active-table key.
pub const SOFT_FORK_VOTES_COLLECTED_ID: u8 = 121;

/// `Parameters.SoftForkStartingHeight = 122`. Active-table key.
pub const SOFT_FORK_STARTING_HEIGHT_ID: u8 = 122;

/// `BlockVersion = 123` (`Parameters.scala:255`).
pub const BLOCK_VERSION_ID: u8 = 123;

/// Vote id 9: `SubblocksPerBlock`. Introduced in 6.0 / block v4.
pub const SUBBLOCKS_PER_BLOCK_ID: u8 = 9;

/// `SubblocksPerBlockDefault = 30` (`Parameters.scala:291`).
pub const SUBBLOCKS_PER_BLOCK_DEFAULT: i32 = 30;

/// Rule 409 — `exMatchParameters` (`ValidationRules.scala:298`).
pub const RULE_EX_MATCH_PARAMETERS: u16 = 409;

// ----- VotingSettings -----

/// Per-network voting epoch parameters (length, fork tally
/// thresholds, v2 hard-fork height). Re-exported from `ergo-chain-spec`
/// so existing consumers see the same name while the type lives in
/// the chain-spec crate.
pub use ergo_chain_spec::VotingParams as VotingSettings;

// ----- Errors -----

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecomputeError {
    #[error("recompute called for non-epoch-start height {0}")]
    NotEpochStart(u32),

    /// Scala `parametersTable(SoftForkVotesCollected)` (`Parameters.scala:108`)
    /// is a `Map.apply` that throws `NoSuchElementException` when the
    /// soft-fork starting-height (id 122) is set but votes-collected (id 121)
    /// is absent and a trigger evaluates the `votes` tally. Honest voting
    /// always co-writes 121 with 122 (Trigger 3); this fires only on a
    /// hostile/malformed table — accept-invalid parity with the JVM throw.
    #[error("soft-fork votes-collected (id 121) missing while starting-height (id 122) is set")]
    SoftForkVotesCollectedMissing,

    /// Scala `parametersTable(paramIdAbs)` (`Parameters.scala:167`) is a
    /// `Map.apply` that throws when an *approved* vote targets a parameter id
    /// absent from the active table. Honest votes never target unknown ids;
    /// this fires only on a hostile table — accept-invalid parity.
    #[error("approved vote for parameter id {id} absent from the active table")]
    ApprovedVoteForUnknownParam { id: u8 },
}

// ----- Public entry point -----

/// Recompute the active parameter set for an epoch-start block.
///
/// Mirrors Scala `Parameters.update(...)` (`Parameters.scala:82-96`):
/// 1. `update_fork` — soft-fork voting state machine.
/// 2. `update_params` — non-fork parameter updates from votes.
/// 3. `apply_subblocks_injection` — 6.0 / block-v4 inject of (9, 30)
///    if conditions met.
///
/// Returns `(next_active, activated_update)` where the second is the
/// `activatedUpdate` for `exMatchValidationSettings`.
pub fn compute_next_params(
    prev_active: &ActiveProtocolParameters,
    epoch_votes: &[(i8, i32)],
    fork_vote: bool,
    proposed_update: &ErgoValidationSettingsUpdate,
    height: u32,
    voting_settings: &VotingSettings,
) -> Result<(ActiveProtocolParameters, ErgoValidationSettingsUpdate), RecomputeError> {
    if height == 0 || !height.is_multiple_of(voting_settings.voting_length) {
        return Err(RecomputeError::NotEpochStart(height));
    }

    // Stage 1: updateFork.
    let (after_fork, activated_update) = update_fork(
        prev_active,
        fork_vote,
        epoch_votes,
        proposed_update,
        height,
        voting_settings,
    )?;

    // Stage 2: updateParams.
    let after_params = update_params(&after_fork, epoch_votes, voting_settings)?;

    // Stage 3: 6.0 / v4 subblocks injection.
    let final_params = apply_subblocks_injection(after_params, &activated_update);

    let mut result = final_params;
    result.epoch_start_height = height;
    // Mirror Scala `Parameters.update` returning
    // `Parameters(height, table3, proposedUpdate)` (Parameters.scala:95):
    // the recomputed params carry the INPUT proposed_update (from this
    // epoch's block extension), and the activated_update from the
    // state-machine outcome.
    result.proposed_update = proposed_update.clone();
    result.activated_update = activated_update.clone();
    Ok((result, activated_update))
}

// ----- Stage 1: updateFork -----

/// `Parameters.updateFork` (`Parameters.scala:98-155`). Six height-
/// equation triggers, evaluated in order. Mutates the soft-fork state
/// keys 121, 122, and the BlockVersion key 123.
fn update_fork(
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

// ----- Stage 2: updateParams -----

/// `Parameters.updateParams` (`Parameters.scala:157-183`). Folds
/// epoch_votes (filtered to non-soft-fork) over the prev table.
/// Crucially, `currentValue` is read from the ORIGINAL `prev` table
/// on each iteration — the same paramId can be moved both up and
/// down by symmetric votes, with the LATER write winning per fold
/// order.
fn update_params(
    prev: &ActiveProtocolParameters,
    epoch_votes: &[(i8, i32)],
    vs: &VotingSettings,
) -> Result<ActiveProtocolParameters, RecomputeError> {
    let mut next = prev.clone();
    for &(param_id, count) in epoch_votes {
        if param_id == SOFT_FORK_ID {
            continue; // Scala filters _ < SoftFork (=120). Sign-aware: <120.
        }
        // Scala uses `_._1 < Parameters.SoftFork`, treating the byte
        // as signed. `(120 as i8) == 120`. Negative ids (-1..-9) are
        // < 120 numerically as i8, so they pass the filter — same
        // as Scala. id 121, 122, 123 are unreachable from votes
        // (they're internal table keys, not vote ids).
        if param_id >= SOFT_FORK_ID {
            continue;
        }
        if !vs.change_approved(count) {
            continue;
        }
        let param_id_abs: u8 = if param_id < 0 {
            (-(param_id as i32)) as u8
        } else {
            param_id as u8
        };
        // Scala `parametersTable(paramIdAbs)` (Parameters.scala:167) is a
        // Map.apply INSIDE the `if (changeApproved)` branch: an APPROVED vote
        // for an id absent from the table throws (accept-invalid parity).
        // Honest votes never target unknown ids.
        let current_value = match read_param_by_id(prev, param_id_abs) {
            Some(v) => v,
            None => return Err(RecomputeError::ApprovedVoteForUnknownParam { id: param_id_abs }),
        };
        let max_value = max_value_for(param_id_abs, current_value);
        let min_value = min_value_for(param_id_abs);
        let step = step_for(param_id_abs, current_value);
        let new_value = if param_id > 0 {
            if current_value < max_value {
                current_value + step
            } else {
                current_value
            }
        } else if current_value > min_value {
            current_value - step
        } else {
            current_value
        };
        write_param_by_id(&mut next, param_id_abs, new_value);
    }
    Ok(next)
}

// ----- Stage 3: subblocks injection -----

/// `Parameters.scala:90-94`. After updateParams, if BlockVersion == 4
/// AND the current table has no key 9 AND the just-activated update
/// did NOT disable rule 409, inject (9, 30) into the table.
///
/// **Key:** the predicate is `activated_update.rules_to_disable
/// .contains(409)`, NOT cumulative settings. We read from the
/// `activated_update` argument returned by `update_fork`.
fn apply_subblocks_injection(
    params: ActiveProtocolParameters,
    activated_update: &ErgoValidationSettingsUpdate,
) -> ActiveProtocolParameters {
    let block_version = params.block_version as i32;
    if block_version == 4
        && params.subblocks_per_block.is_none()
        && !activated_update
            .rules_to_disable
            .contains(&RULE_EX_MATCH_PARAMETERS)
    {
        let mut next = params;
        next.subblocks_per_block = Some(SUBBLOCKS_PER_BLOCK_DEFAULT);
        next
    } else {
        params
    }
}

// ----- Helpers: read/write params by id -----

fn read_param_by_id(p: &ActiveProtocolParameters, id: u8) -> Option<i32> {
    match id {
        1 => Some(p.storage_fee_factor),
        2 => Some(p.min_value_per_byte),
        3 => Some(p.max_block_size),
        4 => Some(p.max_block_cost),
        5 => Some(p.token_access_cost),
        6 => Some(p.input_cost),
        7 => Some(p.data_input_cost),
        8 => Some(p.output_cost),
        9 => p.subblocks_per_block,
        123 => Some(p.block_version as i32),
        _ => p
            .extra
            .iter()
            .find_map(|(eid, v)| (*eid == id).then_some(*v)),
    }
}

fn write_param_by_id(p: &mut ActiveProtocolParameters, id: u8, value: i32) {
    match id {
        1 => p.storage_fee_factor = value,
        2 => p.min_value_per_byte = value,
        3 => p.max_block_size = value,
        4 => p.max_block_cost = value,
        5 => p.token_access_cost = value,
        6 => p.input_cost = value,
        7 => p.data_input_cost = value,
        8 => p.output_cost = value,
        9 => p.subblocks_per_block = Some(value),
        123 => p.block_version = value as u8,
        _ => {
            // Update or append in extras.
            for entry in p.extra.iter_mut() {
                if entry.0 == id {
                    entry.1 = value;
                    return;
                }
            }
            p.extra.push((id, value));
            p.extra.sort_by_key(|(eid, _)| *eid);
        }
    }
}

fn step_for(id: u8, current_value: i32) -> i32 {
    match id {
        1 => 25_000, // StorageFeeFactorStep
        2 => 10,     // MinValueStep
        SUBBLOCKS_PER_BLOCK_ID => 1,
        _ => std::cmp::max(1, current_value / 100),
    }
}

fn min_value_for(id: u8) -> i32 {
    match id {
        1 => 0,                      // StorageFeeFactorMin
        2 => 0,                      // MinValueMin
        3 => 16 * 1024,              // MaxBlockSizeMin
        4 => 16 * 1024,              // MaxBlockCostMin (Parameters.scala:354)
        SUBBLOCKS_PER_BLOCK_ID => 2, // SubblocksPerBlockMin
        _ => 0,
    }
}

fn max_value_for(id: u8, _current_value: i32) -> i32 {
    match id {
        1 => 2_500_000,                  // StorageFeeFactorMax
        2 => 10_000,                     // MinValueMax
        SUBBLOCKS_PER_BLOCK_ID => 2_048, // SubblocksPerBlockMax
        _ => i32::MAX / 2,               // == 1_073_741_823
    }
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

    fn launch_at(height: u32) -> ActiveProtocolParameters {
        let mut p = scala_launch();
        p.epoch_start_height = height;
        p
    }

    fn vs() -> VotingSettings {
        VotingSettings::mainnet()
    }

    // ----- Threshold + step + min/max sanity -----

    #[test]
    fn threshold_change_approved_513_passes() {
        assert!(vs().change_approved(513));
    }

    #[test]
    fn threshold_change_approved_512_fails() {
        assert!(!vs().change_approved(512));
    }

    #[test]
    fn threshold_soft_fork_approved_29492_passes() {
        assert!(vs().soft_fork_approved(29_492));
    }

    #[test]
    fn threshold_soft_fork_approved_29491_fails() {
        assert!(!vs().soft_fork_approved(29_491));
    }

    #[test]
    fn step_for_id_1_is_25000() {
        assert_eq!(step_for(1, 1_250_000), 25_000);
    }

    #[test]
    fn step_for_unsteepened_id_at_100() {
        assert_eq!(step_for(3, 100), 1);
    }

    #[test]
    fn step_for_unsteepened_id_at_10000() {
        assert_eq!(step_for(3, 10_000), 100);
    }

    // ----- updateParams: non-fork votes -----

    #[test]
    fn update_params_increments_when_above_threshold() {
        let prev = launch_at(0); // input_cost = 2000
        let votes = vec![(6, 600)]; // +id 6, count > 512
        let next = update_params(&prev, &votes, &vs()).unwrap();
        assert_eq!(next.input_cost, 2000 + 20); // step = max(1, 2000/100) = 20
    }

    #[test]
    fn update_params_skips_when_below_threshold() {
        let prev = launch_at(0);
        let votes = vec![(6, 100)];
        let next = update_params(&prev, &votes, &vs()).unwrap();
        assert_eq!(next.input_cost, prev.input_cost);
    }

    #[test]
    fn update_params_decrements_negative_id() {
        let prev = launch_at(0);
        let votes = vec![(-6, 600)];
        let next = update_params(&prev, &votes, &vs()).unwrap();
        assert_eq!(next.input_cost, 2000 - 20);
    }

    #[test]
    fn update_params_saturates_at_max() {
        let mut prev = launch_at(0);
        prev.storage_fee_factor = 2_500_000; // == max
        let votes = vec![(1, 600)];
        let next = update_params(&prev, &votes, &vs()).unwrap();
        assert_eq!(next.storage_fee_factor, 2_500_000); // unchanged
    }

    #[test]
    fn update_params_saturates_at_min() {
        let mut prev = launch_at(0);
        prev.min_value_per_byte = 0; // == min
        let votes = vec![(-2, 600)];
        let next = update_params(&prev, &votes, &vs()).unwrap();
        assert_eq!(next.min_value_per_byte, 0);
    }

    #[test]
    fn update_params_filters_softfork_id_120() {
        let prev = launch_at(0);
        let votes = vec![(SOFT_FORK_ID, 30_000)]; // tallied but not for params
        let next = update_params(&prev, &votes, &vs()).unwrap();
        // No param is updated.
        assert_eq!(next, prev);
    }

    #[test]
    fn update_params_insertion_order_later_wins() {
        // Both +3 and -3 pass threshold. Scala reads currentValue from
        // ORIGINAL prev table for each, then writes paramIdAbs=3
        // twice. Later write wins.
        let prev = launch_at(0); // max_block_size = 524_288
        let step = std::cmp::max(1, 524_288 / 100); // = 5242

        // Order [+3, -3]: +3 writes 524_288 + 5242, then -3 writes
        // 524_288 - 5242. Final: 519_046.
        let votes_a = vec![(3, 600), (-3, 600)];
        let next_a = update_params(&prev, &votes_a, &vs()).unwrap();
        assert_eq!(next_a.max_block_size, 524_288 - step);

        // Order [-3, +3]: reversed. Final: 529_530.
        let votes_b = vec![(-3, 600), (3, 600)];
        let next_b = update_params(&prev, &votes_b, &vs()).unwrap();
        assert_eq!(next_b.max_block_size, 524_288 + step);
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

    #[test]
    fn update_params_faults_on_approved_vote_for_unknown_id() {
        // An APPROVED vote (count > threshold) for an id absent from the
        // table: Scala parametersTable(id) Map.apply throws. SANTA chain:
        // hostile-unknown-id-approved.
        let prev = launch_at(0);
        let votes = vec![(10i8, 600)]; // id 10 not in table, 600 > 512 -> approved
        let err = update_params(&prev, &votes, &vs()).unwrap_err();
        assert_eq!(err, RecomputeError::ApprovedVoteForUnknownParam { id: 10 });
    }

    #[test]
    fn update_params_unapproved_unknown_id_does_not_fault() {
        // An UNAPPROVED vote (below threshold) for an unknown id must NOT
        // fault — Scala reads parametersTable only inside the changeApproved
        // branch. (Guards the throw to the exact JVM condition.)
        let prev = launch_at(0);
        let votes = vec![(10i8, 100)]; // 100 < 512 -> not approved
        let next =
            update_params(&prev, &votes, &vs()).expect("unapproved unknown id must not fault");
        assert_eq!(next, prev);
    }

    // ----- Subblocks injection -----

    #[test]
    fn subblocks_injects_when_v4_and_no_key_9_and_no_409_disable() {
        let mut p = launch_at(1024);
        p.block_version = 4;
        p.subblocks_per_block = None;
        let activated = ErgoValidationSettingsUpdate::empty();
        let result = apply_subblocks_injection(p, &activated);
        assert_eq!(result.subblocks_per_block, Some(30));
    }

    #[test]
    fn subblocks_skips_when_409_disabled_in_activated_update() {
        let mut p = launch_at(1024);
        p.block_version = 4;
        p.subblocks_per_block = None;
        let activated = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![RULE_EX_MATCH_PARAMETERS],
            status_updates: vec![],
        };
        let result = apply_subblocks_injection(p, &activated);
        assert_eq!(result.subblocks_per_block, None);
    }

    #[test]
    fn subblocks_skips_when_already_present() {
        let mut p = launch_at(1024);
        p.block_version = 4;
        p.subblocks_per_block = Some(50);
        let activated = ErgoValidationSettingsUpdate::empty();
        let result = apply_subblocks_injection(p, &activated);
        assert_eq!(result.subblocks_per_block, Some(50));
    }

    #[test]
    fn subblocks_skips_when_block_version_not_4() {
        let mut p = launch_at(1024);
        p.block_version = 3;
        p.subblocks_per_block = None;
        let activated = ErgoValidationSettingsUpdate::empty();
        let result = apply_subblocks_injection(p, &activated);
        assert_eq!(result.subblocks_per_block, None);
    }

    // ----- compute_next_params end-to-end -----

    #[test]
    fn compute_rejects_non_epoch_height() {
        let prev = launch_at(0);
        let err = compute_next_params(
            &prev,
            &[],
            false,
            &ErgoValidationSettingsUpdate::empty(),
            1500,
            &vs(),
        )
        .unwrap_err();
        assert_eq!(err, RecomputeError::NotEpochStart(1500));
    }

    #[test]
    fn compute_simple_passthrough_no_votes() {
        let prev = launch_at(0);
        let (next, activated) = compute_next_params(
            &prev,
            &[],
            false,
            &ErgoValidationSettingsUpdate::empty(),
            1024,
            &vs(),
        )
        .unwrap();
        // No votes → params unchanged except epoch_start_height.
        assert_eq!(next.input_cost, prev.input_cost);
        assert_eq!(next.epoch_start_height, 1024);
        assert!(activated.rules_to_disable.is_empty());
    }

    #[test]
    fn compute_simple_increments_input_cost() {
        let prev = launch_at(0);
        let votes = vec![(6, 600)];
        let (next, _) = compute_next_params(
            &prev,
            &votes,
            false,
            &ErgoValidationSettingsUpdate::empty(),
            1024,
            &vs(),
        )
        .unwrap();
        assert_eq!(next.input_cost, prev.input_cost + 20);
    }

    #[test]
    fn compute_v2_forced_activation_at_417792() {
        let mut prev = launch_at(0);
        prev.block_version = 1;
        let (next, _) = compute_next_params(
            &prev,
            &[],
            false,
            &ErgoValidationSettingsUpdate::empty(),
            vs().version2_activation
                .expect("mainnet fixture has v2 activation height"),
            &vs(),
        )
        .unwrap();
        assert_eq!(next.block_version, 2);
    }
}

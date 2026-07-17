//! Recompute pipeline for the next epoch's active protocol parameters.
//!
//! Mirrors `Parameters.update` (`Parameters.scala:82-96`):
//! `update_fork → update_params → apply_subblocks_injection`.
//!
//! Pure functions, no I/O.
//!
//! - [`update_fork`] — the soft-fork voting state machine (`update_fork`
//!   itself kept as one function: its six triggers all key on a shared
//!   pre-mutation snapshot, and the inline comments cross-reference each
//!   other to explain why).
//! - [`update_params`] — non-fork parameter updates from votes, plus the
//!   shared read/write-by-id and step/min/max tables `descriptors` also
//!   reads from.
//! - [`descriptors`] — `ParamDescriptor` / `votable_param_*`, the
//!   operator-facing view of the votable table.
//! - [`select_votes`] — `select_candidate_votes`, the miner-facing
//!   candidate-header vote selector.

mod descriptors;
mod select_votes;
mod update_fork;
mod update_params;

pub use descriptors::{
    votable_param_bounds, votable_param_description, votable_param_descriptors, votable_param_id,
    votable_param_name, ParamDescriptor,
};
pub use select_votes::select_candidate_votes;

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
    let (after_fork, activated_update) = update_fork::update_fork(
        prev_active,
        fork_vote,
        epoch_votes,
        proposed_update,
        height,
        voting_settings,
    )?;

    // Stage 2: updateParams.
    let after_params = update_params::update_params(&after_fork, epoch_votes, voting_settings)?;

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

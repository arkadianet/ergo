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

// ----- Public votable-parameter descriptors -----

/// A votable numeric protocol parameter, with the bounds a vote must respect.
/// Shared by the operator votes endpoint (display) and the candidate-vote
/// selector (range/votability gating), so both read the SAME table that
/// `compute_next_params` recomputes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamDescriptor {
    /// Parameter id (1..=8, or 9 when active).
    pub id: u8,
    /// Stable Scala-style camelCase name.
    pub name: &'static str,
    /// One-line operator-facing explanation of what the parameter governs and
    /// the implication of raising it (see [`votable_param_description`]).
    pub description: &'static str,
    /// Current value in the active table.
    pub current: i32,
    /// Per-vote step size at the current value.
    pub step: i32,
    /// Inclusive lower bound a vote may target. The recompute won't step a
    /// parameter that is already at/below this; a single approved step from just
    /// inside can still land up to one step below it (Scala parity — a gate, not
    /// a hard clamp).
    pub min: i32,
    /// Inclusive upper bound a vote may target. The recompute won't step a
    /// parameter that is already at/above this; a single approved step from just
    /// inside can still land up to one step above it (Scala parity — a gate, not
    /// a hard clamp).
    pub max: i32,
}

/// Inclusive `[min, max]` target bounds for a votable numeric parameter id, or
/// `None` for ids outside the votable set. The recompute's min/max gates do not
/// depend on a parameter's current value, so these bounds are constant per id —
/// callers that only need to validate a target (the runtime `POST /api/v1/votes`
/// write and the `[voting.targets]` config loader) can check it without an
/// active-parameter table. A target beyond the returned range can never be a
/// settling value (the recompute won't step the parameter past the bound), so
/// such a target is rejected rather than silently driving the parameter to the
/// bound forever.
pub fn votable_param_bounds(id: u8) -> Option<(i32, i32)> {
    votable_param_name(id).map(|_| (min_value_for(id), max_value_for(id, 0)))
}

/// Stable camelCase name for a votable numeric parameter id, or `None` for ids
/// outside the votable numeric set (e.g. 123 = blockVersion, which is soft-fork
/// driven, not operator-votable).
pub fn votable_param_name(id: u8) -> Option<&'static str> {
    Some(match id {
        1 => "storageFeeFactor",
        2 => "minValuePerByte",
        3 => "maxBlockSize",
        4 => "maxBlockCost",
        5 => "tokenAccessCost",
        6 => "inputCost",
        7 => "dataInputCost",
        8 => "outputCost",
        SUBBLOCKS_PER_BLOCK_ID => "subblocksPerBlock",
        _ => return None,
    })
}

/// One-line operator-facing description of a votable numeric parameter: what it
/// governs and the practical implication of raising it. Surfaced by the operator
/// votes endpoint / dashboard so an operator understands what a vote does before
/// casting it. `None` for ids outside the votable numeric set.
///
/// The implication claims were verified against the cost/economic model in
/// `dev-docs/protocol/{costing,emission-monetary}.md` and the validation code
/// (`ergo-validation/src/tx/{script,structural}.rs`); keep them accurate if the
/// model changes — operators cast real consensus votes based on this text.
pub fn votable_param_description(id: u8) -> Option<&'static str> {
    Some(match id {
        1 => {
            "Storage-rent fee in nanoErg per box byte, levied on boxes past the \
              ~4-year storage period; raising it increases the rent a miner can \
              claim from such dormant boxes."
        }
        2 => {
            "Dust floor in nanoErg per box byte: every output's value must be at \
              least its serialized size times this. Raising it forces higher \
              minimum box values and rejects more small outputs."
        }
        3 => {
            "Caps the serialized size, in bytes, of a block's transactions. \
              Raising it lets more transactions fit per block but enlarges \
              blocks, increasing bandwidth, storage, and validation load per node."
        }
        4 => {
            "Caps total transaction validation cost summed across a block; a \
              block over it is rejected. Raising it admits heavier blocks but \
              raises every node's worst-case per-block validation work."
        }
        5 => {
            "Block-cost units charged per token entry and per distinct token id \
              across a tx's inputs and outputs; raising it makes token-heavy \
              transactions consume more of the per-block cost budget."
        }
        6 => {
            "Block-cost units charged per transaction input in the init cost \
              tallied against maxBlockCost; raising it makes each input consume \
              more budget, so fewer inputs fit per block."
        }
        7 => {
            "Block-cost units charged per read-only data-input box in a \
              transaction's init cost. Raising it makes referencing boxes more \
              expensive, so fewer fit under the block cost cap."
        }
        8 => {
            "Block-cost units charged per output box a transaction creates, added \
              to its init cost against the block cost budget. Raising it makes \
              outputs pricier, so fewer fit per block."
        }
        SUBBLOCKS_PER_BLOCK_ID => {
            "Number of sub-blocks each block is split into \
              (active only after the 6.0 / block-v4 fork). Raising it divides each \
              block into more sub-blocks."
        }
        _ => return None,
    })
}

/// Reverse of [`votable_param_name`]: resolve a config-supplied parameter name
/// to its structurally-votable id (1..=9), or `None` for any name outside that
/// set (`blockVersion`, soft-fork, or a typo). Case-sensitive — the canonical
/// camelCase spelling is the only accepted form.
///
/// Used by the node's `[voting]` config loader to translate operator target
/// names to ids at startup; an unresolvable name is a startup config error.
/// Resolving id 9 here is purely structural — whether a `subblocksPerBlock`
/// target actually casts a vote is gated at build time by
/// [`votable_param_descriptors`] (present only once the active table carries
/// it), so a configured-but-not-yet-active id 9 simply no-ops.
pub fn votable_param_id(name: &str) -> Option<u8> {
    (1u8..=SUBBLOCKS_PER_BLOCK_ID).find(|&id| votable_param_name(id) == Some(name))
}

/// The operator-votable numeric parameters for the given active table: ids
/// 1..=8 always, plus id 9 (subblocksPerBlock) ONLY when it is present in the
/// active table. Excludes blockVersion (123). The candidate-vote selector and
/// the votes endpoint both build from this — never from a private copy of the
/// step/min/max constants.
pub fn votable_param_descriptors(active: &ActiveProtocolParameters) -> Vec<ParamDescriptor> {
    let mut out = Vec::new();
    for id in 1u8..=SUBBLOCKS_PER_BLOCK_ID {
        // `read_param_by_id` returns `None` for an absent id 9, which is exactly
        // the votability gate (`subblocks_per_block.is_some()`); 1..=8 are always
        // present. Any other id never reaches here (loop is 1..=9).
        let current = match read_param_by_id(active, id) {
            Some(v) => v,
            None => continue,
        };
        out.push(ParamDescriptor {
            id,
            name: votable_param_name(id).expect("1..=9 are named"),
            description: votable_param_description(id).expect("1..=9 are described"),
            current,
            step: step_for(id, current),
            min: min_value_for(id),
            max: max_value_for(id, current),
        });
    }
    out
}

/// Select a candidate header's `votes` (`[u8; 3]`) from the operator's
/// per-parameter target values, given the active parameter table and whether
/// the candidate sits at a voting-epoch start. Pure; produces votes that ALWAYS
/// pass the header-votes validator (rules 212/213/214/215) — pinned by the
/// validator-backed tests in `header.rs`.
///
/// - Only votable parameters are considered (ids 1..=8, plus id 9 when present
///   in the active table); `blockVersion` (123) and soft-fork (120) are never
///   emitted here (soft-fork voting is deferred until the epoch-boundary
///   extension encoding lands).
/// - For a target `!= current`: `+id` to increase, `-id` to decrease — but only
///   while the parameter can still move that way (`current < max` /
///   `current > min`; the recompute clamps to `[min, max]`). A target that
///   isn't `step`-aligned can oscillate by one step at the boundary — Scala's
///   `votingTargets` behaves the same; pick a step-aligned target to settle.
/// - At an epoch start where rule 215 (`hdrVotesUnknown`) is ACTIVE, the header
///   accepts only `{1..=8, 120}` (increases of the first eight params +
///   soft-fork), so decreases and id 9 are suppressed there. When rule 215 has
///   been soft-fork-disabled (mainnet 6.0 carries `rules_to_disable=[215,409]`),
///   decreases and id 9 ARE valid at an epoch start, so they are NOT suppressed
///   — letting an operator seed a downward or subblocks vote post-6.0.
///   `rule_215_disabled` is the live status (`prev_settings.is_rule_disabled(215)`)
///   and is only consulted at an epoch start.
/// - At most `ParamVotesCount` (2) parameter votes (rule 212), chosen in
///   ascending id order for determinism; one vote per id ⇒ never a duplicate
///   (rule 213) or contradictory (rule 214) pair.
/// - No configured targets (or none actionable) ⇒ `[0, 0, 0]` (no vote).
pub fn select_candidate_votes(
    active: &ActiveProtocolParameters,
    targets: &std::collections::BTreeMap<u8, i64>,
    is_epoch_start: bool,
    rule_215_disabled: bool,
) -> [u8; 3] {
    /// `Parameters.ParamVotesCount` — max non-soft-fork votes per header.
    const MAX_PARAM_VOTES: usize = 2;
    let mut chosen: Vec<i8> = Vec::new();
    // `votable_param_descriptors` yields the votable ids in ascending order, so
    // iteration order IS the deterministic priority.
    for d in votable_param_descriptors(active) {
        if chosen.len() >= MAX_PARAM_VOTES {
            break;
        }
        let target = match targets.get(&d.id) {
            Some(t) => *t,
            None => continue,
        };
        // Defence-in-depth: the operator-facing setters (`POST /api/v1/votes`
        // and the `[voting]` config loader) already reject any target outside
        // `[min, max]`, so a stored target is always in range. Re-check here so
        // the invariant does not rest solely on every writer remembering — an
        // out-of-range target is never cast as a vote, mirroring the setters'
        // rejection rather than driving the parameter at its bound forever.
        if target < d.min as i64 || target > d.max as i64 {
            continue;
        }
        let current = d.current as i64;
        if target == current {
            continue;
        }
        let increase = target > current;
        // Can the parameter still move that way? (recompute clamps to [min,max],
        // so a vote at the bound has no effect — don't cast it.)
        let can_move = if increase {
            d.current < d.max
        } else {
            d.current > d.min
        };
        if !can_move {
            continue;
        }
        // Epoch-start rule 215: while ACTIVE only increases of ids 1..=8 are
        // known-votable, so suppress decreases and id 9 (subblocksPerBlock). Once
        // rule 215 is soft-fork-disabled (mainnet 6.0) the header accepts them,
        // so don't suppress.
        if is_epoch_start && !rule_215_disabled && (!increase || d.id == SUBBLOCKS_PER_BLOCK_ID) {
            continue;
        }
        chosen.push(if increase { d.id as i8 } else { -(d.id as i8) });
    }
    let mut out = [0u8; 3];
    for (i, v) in chosen.into_iter().enumerate() {
        out[i] = v as u8;
    }
    out
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
    fn votable_descriptors_cover_1_to_8_gate_id9_and_exclude_block_version() {
        // scala_launch has subblocks_per_block = None → id 9 absent.
        let p = launch_at(1024);
        let d = votable_param_descriptors(&p);
        let ids: Vec<u8> = d.iter().map(|x| x.id).collect();
        assert_eq!(
            ids,
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            "1..=8, no id 9 (absent), no 123"
        );
        // storageFeeFactor descriptor matches the shared table.
        let sff = d.iter().find(|x| x.id == 1).unwrap();
        assert_eq!(sff.name, "storageFeeFactor");
        assert_eq!(sff.current, 1_250_000);
        assert_eq!(sff.step, 25_000);
        assert_eq!(sff.min, 0);
        assert_eq!(sff.max, 2_500_000);

        // When id 9 is active, it appears (votability gate = presence).
        let mut p9 = launch_at(1024);
        p9.subblocks_per_block = Some(4);
        let d9 = votable_param_descriptors(&p9);
        let sub = d9
            .iter()
            .find(|x| x.id == 9)
            .expect("id 9 present when active");
        assert_eq!(sub.name, "subblocksPerBlock");
        assert_eq!(sub.current, 4);
        assert_eq!((sub.min, sub.max, sub.step), (2, 2_048, 1));
        // blockVersion (123) is NEVER votable.
        assert!(d9.iter().all(|x| x.id != 123));
        assert!(votable_param_name(123).is_none());
    }

    #[test]
    fn votable_param_id_round_trips_names_and_rejects_non_votable() {
        // Every structurally-votable id (1..=9) round-trips name→id→name.
        for id in 1u8..=SUBBLOCKS_PER_BLOCK_ID {
            let name = votable_param_name(id).expect("1..=9 are named");
            assert_eq!(votable_param_id(name), Some(id), "round-trip id {id}");
        }
        // subblocksPerBlock (id 9) resolves structurally (runtime presence is
        // gated later by `votable_param_descriptors`).
        assert_eq!(votable_param_id("subblocksPerBlock"), Some(9));
        // blockVersion (123), soft-fork, and typos are NOT operator-votable.
        assert_eq!(votable_param_id("blockVersion"), None);
        assert_eq!(votable_param_id("softFork"), None);
        assert_eq!(votable_param_id("storagefeefactor"), None); // case-sensitive
        assert_eq!(votable_param_id(""), None);
    }

    #[test]
    fn select_votes_empty_targets_is_neutral() {
        use std::collections::BTreeMap;
        assert_eq!(
            select_candidate_votes(&launch_at(1024), &BTreeMap::new(), false, false),
            [0, 0, 0]
        );
    }

    #[test]
    fn select_votes_increase_and_decrease_off_epoch_in_id_order() {
        use std::collections::BTreeMap;
        let p = launch_at(1024); // storage_fee_factor 1_250_000, max_block_size 524_288
        let mut t = BTreeMap::new();
        t.insert(1u8, 2_000_000i64); // increase id 1 (current 1.25M < max 2.5M)
        t.insert(3u8, 200_000i64); // decrease id 3 (current 524288 > min 16384)
        let v = select_candidate_votes(&p, &t, false, false);
        assert_eq!(v, [1, (-3i8) as u8, 0], "ascending: +1 then -3");
    }

    #[test]
    fn select_votes_epoch_start_rule215_active_suppresses_decreases_and_id9() {
        use std::collections::BTreeMap;
        let mut p = launch_at(1024);
        p.subblocks_per_block = Some(4); // id 9 active
        let mut t = BTreeMap::new();
        t.insert(1u8, 2_000_000i64); // increase id 1 — allowed at epoch start
        t.insert(3u8, 100_000i64); // decrease id 3 — suppressed at epoch start
        t.insert(9u8, 8i64); // id 9 — suppressed at epoch start
        assert_eq!(
            select_candidate_votes(&p, &t, true, false),
            [1, 0, 0],
            "rule 215 active ⇒ only increases of 1..=8 at an epoch start",
        );
    }

    #[test]
    fn select_votes_epoch_start_rule215_disabled_allows_decreases_and_id9() {
        use std::collections::BTreeMap;
        // Post-6.0 mainnet disables rule 215, so an epoch-start header may seed
        // decreases and id 9 — the operator can initiate a downward / subblocks
        // vote. Cap-2 (rule 212) still applies in ascending id order.
        let mut p = launch_at(1024);
        p.subblocks_per_block = Some(4); // id 9 active
        let mut t = BTreeMap::new();
        t.insert(3u8, 100_000i64); // decrease id 3 — now allowed
        t.insert(9u8, 8i64); // id 9 increase — now allowed
        assert_eq!(
            select_candidate_votes(&p, &t, true, true),
            [(-3i8) as u8, 9, 0],
            "rule 215 disabled ⇒ decreases + id 9 seedable at an epoch start",
        );
    }

    #[test]
    fn select_votes_caps_at_two_param_votes() {
        use std::collections::BTreeMap;
        let p = launch_at(1024);
        // An in-range increase target for every param (the setters reject
        // out-of-range, so the cap test must use values they'd accept): id 1
        // 1_250_000→2_000_000 (≤2.5M), id 2 360→9_000 (≤10_000), and the rest
        // comfortably below their large default max.
        let targets = [
            (1u8, 2_000_000i64),
            (2, 9_000),
            (3, 600_000),
            (4, 2_000_000),
            (5, 1_000),
            (6, 9_000),
            (7, 1_000),
            (8, 1_000),
        ];
        let t: BTreeMap<u8, i64> = targets.into_iter().collect();
        // Only the first two in ascending id order (rule 212 ParamVotesCount=2).
        assert_eq!(select_candidate_votes(&p, &t, false, false), [1, 2, 0]);
    }

    #[test]
    fn select_votes_range_gated_at_bound() {
        use std::collections::BTreeMap;
        let mut p = launch_at(1024);
        p.storage_fee_factor = 2_500_000; // id 1 already at max
        let mut t = BTreeMap::new();
        t.insert(1u8, 9_000_000i64); // wants increase but can't move → no vote
        assert_eq!(select_candidate_votes(&p, &t, false, false), [0, 0, 0]);
    }

    #[test]
    fn select_votes_skips_target_above_max() {
        use std::collections::BTreeMap;
        // Defence-in-depth backstop. The POST and `[voting]` config setters
        // already reject an out-of-range target, but if one ever reached the
        // selector with the parameter's CURRENT value still inside the range,
        // the `can_move` gate alone (current < max) would cast a vote toward the
        // illegal target. The bound re-check must suppress it.
        let p = launch_at(1024); // storage_fee_factor 1_250_000, max 2_500_000
        let mut t = BTreeMap::new();
        t.insert(1u8, 3_000_000i64); // above StorageFeeFactorMax
        assert_eq!(select_candidate_votes(&p, &t, false, false), [0, 0, 0]);
    }

    #[test]
    fn select_votes_skips_target_below_min() {
        use std::collections::BTreeMap;
        let p = launch_at(1024); // storage_fee_factor 1_250_000, min 0
        let mut t = BTreeMap::new();
        t.insert(1u8, -5i64); // below StorageFeeFactorMin
        assert_eq!(select_candidate_votes(&p, &t, false, false), [0, 0, 0]);
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

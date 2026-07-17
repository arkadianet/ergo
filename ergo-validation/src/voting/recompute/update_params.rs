use crate::active_params::ActiveProtocolParameters;

use super::{RecomputeError, VotingSettings, SOFT_FORK_ID, SUBBLOCKS_PER_BLOCK_ID};

/// `Parameters.updateParams` (`Parameters.scala:157-183`). Folds
/// epoch_votes (filtered to non-soft-fork) over the prev table.
/// Crucially, `currentValue` is read from the ORIGINAL `prev` table
/// on each iteration — the same paramId can be moved both up and
/// down by symmetric votes, with the LATER write winning per fold
/// order.
pub(super) fn update_params(
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

// ----- Helpers: read/write params by id -----
//
// Shared with `descriptors.rs`, which builds `ParamDescriptor`s from
// the same current/step/min/max values this fold uses — both must
// read the SAME table so the operator votes endpoint and the
// candidate-vote selector never drift from what `compute_next_params`
// actually recomputes.

pub(super) fn read_param_by_id(p: &ActiveProtocolParameters, id: u8) -> Option<i32> {
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

pub(super) fn step_for(id: u8, current_value: i32) -> i32 {
    match id {
        1 => 25_000, // StorageFeeFactorStep
        2 => 10,     // MinValueStep
        SUBBLOCKS_PER_BLOCK_ID => 1,
        _ => std::cmp::max(1, current_value / 100),
    }
}

pub(super) fn min_value_for(id: u8) -> i32 {
    match id {
        1 => 0,                      // StorageFeeFactorMin
        2 => 0,                      // MinValueMin
        3 => 16 * 1024,              // MaxBlockSizeMin
        4 => 16 * 1024,              // MaxBlockCostMin (Parameters.scala:354)
        SUBBLOCKS_PER_BLOCK_ID => 2, // SubblocksPerBlockMin
        _ => 0,
    }
}

pub(super) fn max_value_for(id: u8, _current_value: i32) -> i32 {
    match id {
        1 => 2_500_000,                  // StorageFeeFactorMax
        2 => 10_000,                     // MinValueMax
        SUBBLOCKS_PER_BLOCK_ID => 2_048, // SubblocksPerBlockMax
        _ => i32::MAX / 2,               // == 1_073_741_823
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

    // ----- Threshold sanity (param change approval) -----

    #[test]
    fn threshold_change_approved_513_passes() {
        assert!(vs().change_approved(513));
    }

    #[test]
    fn threshold_change_approved_512_fails() {
        assert!(!vs().change_approved(512));
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
}

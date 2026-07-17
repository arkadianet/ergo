use crate::active_params::ActiveProtocolParameters;

use super::descriptors::votable_param_descriptors;
use super::SUBBLOCKS_PER_BLOCK_ID;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_params::scala_launch;

    fn launch_at(height: u32) -> ActiveProtocolParameters {
        let mut p = scala_launch();
        p.epoch_start_height = height;
        p
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
}

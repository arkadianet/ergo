use crate::active_params::ActiveProtocolParameters;

use super::update_params::{max_value_for, min_value_for, read_param_by_id, step_for};
use super::SUBBLOCKS_PER_BLOCK_ID;

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
/// settling value (recompute stops further movement once current is at/over the
/// gate; from just inside, one approved step may still overshoot by one step), so
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
/// The implication claims were verified against the validation code
/// (`ergo-validation/src/tx/{script,structural}.rs`); keep them accurate if the
/// cost/economic model changes — operators cast real consensus votes based on
/// this text.
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
}

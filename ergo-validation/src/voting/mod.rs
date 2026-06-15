//! Voted protocol parameters — recompute, extension validation, vote
//! tally, and validation-settings codec.
//!
//! The submodules are pure functions with no I/O. Storage integration
//! against the chain-state DB lives in `ergo-state`; this layer only
//! cares about transforming epoch boundary data into the next-epoch
//! active set.
//!
//! Sub-modules:
//!
//! * [`recompute`] — `compute_next_params` derives the next-epoch
//!   `ActiveProtocolParameters` from the previous epoch's votes and
//!   the per-network `VotingSettings`.
//! * [`votes`] — `compute_epoch_votes` walks `header.votes` across an
//!   epoch (via `ChainHeaderReader`) and tallies the count needed for
//!   `recompute`.
//! * [`extension_validation`] — `validate_epoch_extension` checks the
//!   first-block-of-epoch extension section against the recomputed
//!   active set, surfacing the `ExtensionValidationOutcome` that the
//!   block validator uses to gate apply.
//! * [`validation_settings`] — `ErgoValidationSettings` /
//!   `ErgoValidationSettingsUpdate` types and their codec.

pub mod extension_validation;
pub mod recompute;
pub mod validation_settings;
pub mod votes;

pub use extension_validation::{
    validate_epoch_extension, ExtensionValidationError, ExtensionValidationOutcome,
};
pub use recompute::{
    compute_next_params, select_candidate_votes, votable_param_descriptors, votable_param_id,
    votable_param_name, ParamDescriptor, RecomputeError, VotingSettings,
};
pub use validation_settings::{
    ErgoValidationSettings, ErgoValidationSettingsUpdate, RuleStatus, ValidationSettingsCodecError,
    FIRST_RULE_ID,
};
pub use votes::{compute_epoch_votes, ChainHeaderReader, ChainHeaderReaderError, HeaderView};

/// Neutral `header.votes` for a candidate that does not vote on any
/// parameter change. All three slots zeroed.
///
/// Used by mining when no voting policy is configured. A non-neutral
/// vote bit is at most one of the signed-i8 parameter ids defined by
/// `Parameters` in the Scala reference; zero means "no vote in this
/// slot".
pub const fn neutral_votes() -> [u8; 3] {
    [0, 0, 0]
}

/// Compute the script-evaluator version for a given `block_version`.
///
/// Mirrors Scala `Header.scriptFromBlockVersion(blockVersion) =
/// (blockVersion - 1).toByte` (`Header.scala:150-152` in the
/// ergoplatform/ergo reference). The relationship is purely a function
/// of `block_version`; the activated validation settings do NOT shift
/// the script version (that is handled separately via rule
/// replacements in `ErgoValidationSettings`).
///
/// `saturating_sub` matches the existing block-validation call sites
/// (`ergo-validation/src/block.rs:523,756`) — `block_version = 0` is
/// a synthetic value that never appears on mainnet, but saturating
/// avoids underflow if some pre-genesis test path constructs it.
pub const fn derive_activated_script_version(block_version: u8) -> u8 {
    block_version.saturating_sub(1)
}

#[cfg(test)]
mod mining_helper_tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn neutral_votes_is_three_zero_bytes() {
        assert_eq!(neutral_votes(), [0u8; 3]);
    }

    #[test]
    fn derive_activated_script_version_matches_existing_pattern() {
        // Mirror the existing call sites at
        // ergo-validation/src/block.rs:523,756 which spell out
        // `header.version.saturating_sub(1)`.
        for v in 0..=255u8 {
            assert_eq!(
                derive_activated_script_version(v),
                v.saturating_sub(1),
                "version {v}"
            );
        }
    }

    #[test]
    fn derive_activated_script_version_pinned_known_versions() {
        // Per Header.scala:130-148:
        //   InitialVersion       = 1  -> script v0 (default in 4.0 era)
        //   HardeningVersion     = 2  -> script v1 (Autolykos v2 + witnesses)
        //   Interpreter50Version = 3  -> script v2 (5.0 JITC + EIP-39)
        //   Interpreter60Version = 4  -> script v3 (6.0 / EIP-50)
        assert_eq!(derive_activated_script_version(1), 0);
        assert_eq!(derive_activated_script_version(2), 1);
        assert_eq!(derive_activated_script_version(3), 2);
        assert_eq!(derive_activated_script_version(4), 3);
    }

    // ----- saturation guard -----

    #[test]
    fn derive_activated_script_version_zero_saturates() {
        // block_version = 0 is synthetic (never on mainnet); saturating_sub
        // means no underflow. Pinned to document the guard exists.
        assert_eq!(derive_activated_script_version(0), 0);
    }
}

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
    compute_next_params, select_candidate_votes, votable_param_bounds, votable_param_description,
    votable_param_descriptors, votable_param_id, votable_param_name, ParamDescriptor,
    RecomputeError, VotingSettings,
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

/// Compute the script-evaluator version byte for a protocol `block_version`.
///
/// Deliberately match the JVM signed-byte arithmetic quirk for consensus:
/// Scala computes `(blockVersion - 1).toByte`. We retain the byte bits in `u8`;
/// consumers compare activation as `i8`. Thus 0 gives -1, 200 gives -57, and
/// 128 gives 127 (subtraction wraps at the signed boundary). Versions 0 and
/// 128..=255 cannot occur on mainnet today; versions 1..=127 are unchanged.
/// <https://github.com/ergoplatform/ergo/blob/v6.0.7/ergo-core/src/main/scala/org/ergoplatform/modifiers/history/header/Header.scala#L150-L156>
///
/// Block validation and mempool tip contexts use the active parameters'
/// `block_version`, never a header's own version byte. Candidate contexts use
/// the candidate's selected protocol version.
pub const fn derive_activated_script_version(block_version: u8) -> u8 {
    block_version.wrapping_sub(1)
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
    fn derive_activated_script_version_matches_scala_signed_byte_arithmetic() {
        // Scala promotes the signed byte to Int, subtracts, then narrows.
        for v in 0..=255u8 {
            let activated = derive_activated_script_version(v);
            assert_eq!(
                activated as i8,
                (i32::from(v as i8) - 1) as i8,
                "version {v}"
            );
            let ctx = crate::TransactionContext {
                height: 0,
                miner_pubkey: [0; 33],
                pre_header_timestamp: 0,
                activated_script_version: activated,
                pre_header_version: 4,
                pre_header_parent_id: [0; 32],
                pre_header_n_bits: 0,
                pre_header_votes: [0; 3],
            };
            assert_eq!(ctx.block_version(), v, "version round-trip {v}");
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

    #[test]
    fn derive_activated_script_version_signed_edges() {
        assert_eq!(derive_activated_script_version(0) as i8, -1);
        assert_eq!(derive_activated_script_version(127) as i8, 126);
        assert_eq!(derive_activated_script_version(128) as i8, 127);
        assert_eq!(derive_activated_script_version(129) as i8, -128);
        assert_eq!(derive_activated_script_version(200) as i8, -57);
        assert_eq!(derive_activated_script_version(255) as i8, -2);
    }
}

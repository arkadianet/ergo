//! On-chain consensus parameters parsed from Extension blocks.
//!
//! Ergo protocol parameters (block size, costs, fees, etc.) are stored on-chain
//! in Extension sections and can be changed via miner voting.

use std::collections::BTreeMap;

use ergo_types::extension::{Extension, SYSTEM_PARAMETERS_PREFIX};

// ---------------------------------------------------------------------------
// Parameter ID constants
// ---------------------------------------------------------------------------

/// No parameter (placeholder).
pub const NO_PARAMETER: u8 = 0;
/// Storage fee factor (nanoERG per byte per storage period).
pub const STORAGE_FEE_FACTOR_ID: u8 = 1;
/// Minimum value per byte of output (nanoERG).
pub const MIN_VALUE_PER_BYTE_ID: u8 = 2;
/// Maximum block size in bytes.
pub const MAX_BLOCK_SIZE_ID: u8 = 3;
/// Maximum computational cost of a block.
pub const MAX_BLOCK_COST_ID: u8 = 4;
/// Cost of token access in a script.
pub const TOKEN_ACCESS_COST_ID: u8 = 5;
/// Cost of an input in a script.
pub const INPUT_COST_ID: u8 = 6;
/// Cost of a data input in a script.
pub const DATA_INPUT_COST_ID: u8 = 7;
/// Cost of an output in a script.
pub const OUTPUT_COST_ID: u8 = 8;

// ---------------------------------------------------------------------------
// Special / soft-fork related IDs
// ---------------------------------------------------------------------------

/// Soft-fork activation status (0 = inactive, 1 = voting, 2 = active).
pub const SOFT_FORK_ID: u8 = 120;
/// Number of votes collected for a soft-fork proposal.
pub const SOFT_FORK_VOTES_COLLECTED_ID: u8 = 121;
/// Height at which a soft-fork started collecting votes.
pub const SOFT_FORK_STARTING_HEIGHT_ID: u8 = 122;
/// Current block version.
pub const BLOCK_VERSION_ID: u8 = 123;
/// ID used for disabling validation rules (excluded from extension fields).
pub const SOFT_FORK_DISABLING_RULES_ID: u8 = 124;

// ---------------------------------------------------------------------------
// Known votable parameter IDs
// ---------------------------------------------------------------------------

/// The set of known parameter IDs that can be voted on.
///
/// This includes all economic parameters (1-8) and the soft-fork parameter (120).
/// Used by vote validation rule 215 to reject unknown votes at epoch boundaries.
pub const KNOWN_PARAM_IDS: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 120];

// ---------------------------------------------------------------------------
// Soft-fork / activation constants
// ---------------------------------------------------------------------------

/// Mainnet height at which block version is forced to 2 (Autolykos v2 hard fork).
pub const VERSION2_ACTIVATION_HEIGHT: u32 = 417_792;

/// Default soft-fork voting epochs (how many epochs to accumulate votes).
pub const SOFT_FORK_EPOCHS: u32 = 32;

/// Default activation grace period (epochs after approval before version bump).
pub const ACTIVATION_EPOCHS: u32 = 32;

// ---------------------------------------------------------------------------
// Parameter bounds
// ---------------------------------------------------------------------------

/// Returns the bounds for a given parameter ID as
/// `(default, fixed_step_or_None, min, max)`.
///
/// If `fixed_step` is `None`, the step is computed as `max(1, current_value / 100)`.
pub fn param_bounds(id: u8) -> Option<(i32, Option<i32>, i32, i32)> {
    match id {
        STORAGE_FEE_FACTOR_ID => Some((1_250_000, Some(25_000), 0, 2_500_000)),
        MIN_VALUE_PER_BYTE_ID => Some((360, Some(10), 0, 10_000)),
        MAX_BLOCK_SIZE_ID => Some((524_288, None, 16_384, 1_048_576)),
        MAX_BLOCK_COST_ID => Some((1_000_000, None, 16_384, i32::MAX / 2)),
        TOKEN_ACCESS_COST_ID => Some((100, None, 0, i32::MAX / 2)),
        INPUT_COST_ID => Some((2_000, None, 0, i32::MAX / 2)),
        DATA_INPUT_COST_ID => Some((100, None, 0, i32::MAX / 2)),
        OUTPUT_COST_ID => Some((100, None, 0, i32::MAX / 2)),
        _ => None,
    }
}

/// Compute the voting step for a parameter given its current value.
///
/// If the parameter has a fixed step (e.g. storage fee), that step is returned.
/// Otherwise the step is `max(1, current_value / 100)` (a ~1 % change).
pub fn param_step(id: u8, current_value: i32) -> i32 {
    if let Some((_, Some(step), _, _)) = param_bounds(id) {
        return step;
    }
    // Percentage-based step.
    std::cmp::max(1, current_value / 100)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when parsing or validating parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParameterError {
    /// A parameter field in the extension has an unexpected value size.
    #[error("parameter {id} has invalid value size {size} (expected 4)")]
    InvalidValueSize { id: u8, size: usize },

    /// A declared parameter value does not match the computed value.
    #[error("parameter {id} mismatch: declared={declared}, computed={computed}")]
    Mismatch {
        id: u8,
        declared: i32,
        computed: i32,
    },
}

// ---------------------------------------------------------------------------
// Parameters struct
// ---------------------------------------------------------------------------

/// On-chain consensus parameters at a given height.
///
/// The `table` maps parameter IDs to their `i32` values. This matches the
/// Scala reference implementation's `Parameters` class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters {
    /// Block height at which these parameters are effective.
    pub height: u32,
    /// Parameter ID -> value mapping.
    pub table: BTreeMap<u8, i32>,
}

impl Default for Parameters {
    fn default() -> Self {
        Self::genesis()
    }
}

impl Parameters {
    /// Create the genesis (initial) parameter set with all default values.
    pub fn genesis() -> Self {
        let mut table = BTreeMap::new();
        // Economic parameters from bounds.
        for &id in &[
            STORAGE_FEE_FACTOR_ID,
            MIN_VALUE_PER_BYTE_ID,
            MAX_BLOCK_SIZE_ID,
            MAX_BLOCK_COST_ID,
            TOKEN_ACCESS_COST_ID,
            INPUT_COST_ID,
            DATA_INPUT_COST_ID,
            OUTPUT_COST_ID,
        ] {
            if let Some((default, _, _, _)) = param_bounds(id) {
                table.insert(id, default);
            }
        }
        // Soft-fork related defaults.
        table.insert(SOFT_FORK_ID, 0);
        table.insert(SOFT_FORK_VOTES_COLLECTED_ID, 0);
        table.insert(SOFT_FORK_STARTING_HEIGHT_ID, 0);
        table.insert(BLOCK_VERSION_ID, 1);

        Parameters { height: 0, table }
    }

    /// Parse parameters from an Extension at the given height.
    ///
    /// Only fields where key\[0\] == `SYSTEM_PARAMETERS_PREFIX` (0x00) and
    /// key\[1\] != `SOFT_FORK_DISABLING_RULES_ID` (124) are considered.
    /// Each value must be exactly 4 bytes (big-endian i32).
    pub fn from_extension(height: u32, ext: &Extension) -> Result<Self, ParameterError> {
        let mut table = BTreeMap::new();
        for (key, value) in &ext.fields {
            if key[0] != SYSTEM_PARAMETERS_PREFIX {
                continue;
            }
            let id = key[1];
            if id == SOFT_FORK_DISABLING_RULES_ID {
                continue;
            }
            if value.len() != 4 {
                return Err(ParameterError::InvalidValueSize {
                    id,
                    size: value.len(),
                });
            }
            let v = i32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            table.insert(id, v);
        }
        Ok(Parameters { height, table })
    }

    /// Serialize the parameter table as Extension key-value fields.
    ///
    /// Each entry becomes `([0x00, id], value.to_be_bytes())`.
    /// The `SOFT_FORK_DISABLING_RULES_ID` (124) is excluded.
    pub fn to_extension_fields(&self) -> Vec<([u8; 2], Vec<u8>)> {
        self.table
            .iter()
            .filter(|(&id, _)| id != SOFT_FORK_DISABLING_RULES_ID)
            .map(|(&id, &val)| ([SYSTEM_PARAMETERS_PREFIX, id], val.to_be_bytes().to_vec()))
            .collect()
    }

    /// Compute updated parameters after an epoch of voting.
    ///
    /// For each parameter vote where the vote count exceeds `epoch_length / 2`,
    /// the parameter value is adjusted by +/- step and clamped to its bounds.
    ///
    /// Vote IDs in `epoch_votes`:
    /// - `id` (the raw parameter ID) means *increase* the parameter.
    /// - `id + 128` (with high bit set) means *decrease* the parameter.
    ///   The map key is the vote byte as cast by miners.
    pub fn update_params(&self, epoch_votes: &BTreeMap<u8, u32>, epoch_length: u32) -> Parameters {
        let threshold = epoch_length / 2;
        let mut new_table = self.table.clone();

        for (&vote_id, &count) in epoch_votes {
            if count <= threshold {
                continue;
            }

            // Determine actual parameter ID and direction.
            let (param_id, increase) = if vote_id >= 128 {
                (vote_id - 128, false)
            } else {
                (vote_id, true)
            };

            if param_id == NO_PARAMETER {
                continue;
            }

            let current = match self.table.get(&param_id) {
                Some(&v) => v,
                None => continue,
            };

            let step = param_step(param_id, current);
            let new_val = if increase {
                current.saturating_add(step)
            } else {
                current.saturating_sub(step)
            };

            // Clamp to bounds if known.
            let clamped = if let Some((_, _, min, max)) = param_bounds(param_id) {
                new_val.clamp(min, max)
            } else {
                new_val
            };

            new_table.insert(param_id, clamped);
        }

        Parameters {
            height: self.height,
            table: new_table,
        }
    }

    /// Apply soft-fork state machine and forced v2 activation.
    ///
    /// Implements Scala's `Parameters.updateFork()` with 5 sequential phases
    /// at epoch boundaries, then the forced v2 hard-fork activation.
    pub fn update_fork(
        &mut self,
        height: u32,
        epoch_votes: &BTreeMap<u8, u32>,
        epoch_length: u32,
        soft_fork_epochs: u32,
        activation_epochs: u32,
    ) {
        // Helper: read the soft-fork starting height, treating 0 as "not set"
        // (genesis parameters insert 0 as a placeholder).
        let read_sf_start = |table: &BTreeMap<u8, i32>| -> Option<i32> {
            table
                .get(&SOFT_FORK_STARTING_HEIGHT_ID)
                .copied()
                .filter(|&h| h > 0)
        };

        let sf_starting_height = read_sf_start(&self.table);
        let sf_votes_collected = self
            .table
            .get(&SOFT_FORK_VOTES_COLLECTED_ID)
            .copied()
            .unwrap_or(0) as u32;

        let epoch_sf_votes = epoch_votes.get(&SOFT_FORK_ID).copied().unwrap_or(0);
        let total_votes = epoch_sf_votes + sf_votes_collected;

        let fork_vote = epoch_sf_votes > epoch_length / 2;

        let approved = |votes: u32| -> bool {
            (votes as u64) > epoch_length as u64 * soft_fork_epochs as u64 * 9 / 10
        };

        // Phase 1: Successful cleanup (after activation + 1 epoch).
        if let Some(starting) = sf_starting_height {
            let cleanup_height = starting as u64
                + epoch_length as u64 * (soft_fork_epochs as u64 + activation_epochs as u64 + 1);
            if height as u64 == cleanup_height && approved(total_votes) {
                self.table.remove(&SOFT_FORK_STARTING_HEIGHT_ID);
                self.table.remove(&SOFT_FORK_VOTES_COLLECTED_ID);
            }
        }

        // Phase 2: Unsuccessful cleanup (after voting + 1 epoch, not approved).
        if let Some(starting) = sf_starting_height {
            let fail_height = starting as u64 + epoch_length as u64 * (soft_fork_epochs as u64 + 1);
            if height as u64 == fail_height && !approved(total_votes) {
                self.table.remove(&SOFT_FORK_STARTING_HEIGHT_ID);
                self.table.remove(&SOFT_FORK_VOTES_COLLECTED_ID);
            }
        }

        // Re-read after potential cleanup.
        let sf_starting_height_now = read_sf_start(&self.table);

        // Phase 3: Start new voting (if fork vote passes this epoch).
        if fork_vote {
            let can_start = sf_starting_height_now.is_none() && height.is_multiple_of(epoch_length);
            let just_cleaned = sf_starting_height.is_some() && sf_starting_height_now.is_none();
            if can_start || just_cleaned {
                self.table
                    .insert(SOFT_FORK_STARTING_HEIGHT_ID, height as i32);
                self.table.insert(SOFT_FORK_VOTES_COLLECTED_ID, 0);
            }
        }

        // Phase 4: Vote accumulation (during voting period).
        if let Some(starting) = read_sf_start(&self.table) {
            let voting_end = starting as u64 + epoch_length as u64 * soft_fork_epochs as u64;
            if (height as u64) <= voting_end {
                self.table
                    .insert(SOFT_FORK_VOTES_COLLECTED_ID, total_votes as i32);
            }
        }

        // Phase 5: Activation (after voting + activation grace period, if approved).
        if let Some(starting) = sf_starting_height {
            let activation_height = starting as u64
                + epoch_length as u64 * (soft_fork_epochs as u64 + activation_epochs as u64);
            if height as u64 == activation_height && approved(total_votes) {
                let current_version = self.block_version();
                self.table
                    .insert(BLOCK_VERSION_ID, (current_version + 1) as i32);
            }
        }

        // Forced v2 activation (non-voted hard-fork).
        if height == VERSION2_ACTIVATION_HEIGHT && self.block_version() == 1 {
            self.table.insert(BLOCK_VERSION_ID, 2);
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Get the value for a parameter ID.
    pub fn get(&self, id: u8) -> Option<i32> {
        self.table.get(&id).copied()
    }

    /// Get the soft-fork starting height, if a soft-fork vote is active.
    ///
    /// Returns `None` if the parameter is absent or set to `0` (the genesis
    /// placeholder value that means "no soft-fork in progress").
    pub fn soft_fork_starting_height(&self) -> Option<u32> {
        self.table
            .get(&SOFT_FORK_STARTING_HEIGHT_ID)
            .copied()
            .filter(|&h| h > 0)
            .map(|h| h as u32)
    }

    /// Get the number of soft-fork votes collected so far.
    pub fn soft_fork_votes_collected(&self) -> Option<i32> {
        self.table.get(&SOFT_FORK_VOTES_COLLECTED_ID).copied()
    }

    /// Maximum block size in bytes.
    pub fn max_block_size(&self) -> i32 {
        self.table
            .get(&MAX_BLOCK_SIZE_ID)
            .copied()
            .unwrap_or(524_288)
    }

    /// Maximum computational cost of a block.
    pub fn max_block_cost(&self) -> i32 {
        self.table
            .get(&MAX_BLOCK_COST_ID)
            .copied()
            .unwrap_or(1_000_000)
    }

    /// Storage fee factor (nanoERG per byte per storage period).
    pub fn storage_fee_factor(&self) -> i32 {
        self.table
            .get(&STORAGE_FEE_FACTOR_ID)
            .copied()
            .unwrap_or(1_250_000)
    }

    /// Minimum value per byte of output (nanoERG).
    pub fn min_value_per_byte(&self) -> i32 {
        self.table
            .get(&MIN_VALUE_PER_BYTE_ID)
            .copied()
            .unwrap_or(360)
    }

    /// Expected block version from the parameters system.
    ///
    /// Defaults to `1` if the parameter is not present (genesis / pre-fork).
    pub fn block_version(&self) -> u8 {
        self.table.get(&BLOCK_VERSION_ID).copied().unwrap_or(1) as u8
    }
}

// ---------------------------------------------------------------------------
// Fork vote validation (rule 407)
// ---------------------------------------------------------------------------

/// Check that voting for a soft fork is not prohibited at the given height.
///
/// **Rule 407 (`exCheckForkVote`).**
///
/// When a soft-fork vote is already in progress (`softForkStartingHeight` is
/// set), there are windows during which a new soft-fork vote is prohibited:
///
/// * If the vote was **not approved**, voting is prohibited in the epoch
///   immediately after the voting period ends (`finishingHeight .. finishingHeight + epochLen`).
/// * If the vote **was approved**, voting is prohibited from `finishingHeight`
///   until after the activation grace period (`finishingHeight .. afterActivationHeight`).
///
/// This function should only be called when the block actually contains a
/// `SoftFork` vote (parameter ID 120).
pub fn check_fork_vote(
    height: u32,
    parameters: &Parameters,
    voting_epoch_length: u32,
    soft_fork_epochs: u32,
    activation_epochs: u32,
) -> Result<(), String> {
    if let Some(starting_height) = parameters.soft_fork_starting_height() {
        let finishing_height =
            starting_height as u64 + voting_epoch_length as u64 * soft_fork_epochs as u64;
        let after_activation_height =
            finishing_height + voting_epoch_length as u64 * (activation_epochs as u64 + 1);
        let votes_collected = parameters.soft_fork_votes_collected().unwrap_or(0);

        // softForkApproved: votesCount > votingLength * softForkEpochs * 9 / 10
        let approved = (votes_collected as u64)
            > voting_epoch_length as u64 * soft_fork_epochs as u64 * 9 / 10;

        let h = height as u64;
        #[allow(clippy::nonminimal_bool)]
        if (h >= finishing_height && h < finishing_height + voting_epoch_length as u64 && !approved)
            || (h >= finishing_height && h < after_activation_height && approved)
        {
            return Err(format!("Voting for fork is prohibited at height {height}"));
        }
    }
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::modifier_id::ModifierId;

    #[test]
    fn default_parameters_have_correct_values() {
        let p = Parameters::genesis();
        assert_eq!(p.height, 0);
        assert_eq!(p.get(STORAGE_FEE_FACTOR_ID), Some(1_250_000));
        assert_eq!(p.get(MIN_VALUE_PER_BYTE_ID), Some(360));
        assert_eq!(p.get(MAX_BLOCK_SIZE_ID), Some(524_288));
        assert_eq!(p.get(MAX_BLOCK_COST_ID), Some(1_000_000));
        assert_eq!(p.get(TOKEN_ACCESS_COST_ID), Some(100));
        assert_eq!(p.get(INPUT_COST_ID), Some(2_000));
        assert_eq!(p.get(DATA_INPUT_COST_ID), Some(100));
        assert_eq!(p.get(OUTPUT_COST_ID), Some(100));
        assert_eq!(p.get(SOFT_FORK_ID), Some(0));
        assert_eq!(p.get(SOFT_FORK_VOTES_COLLECTED_ID), Some(0));
        assert_eq!(p.get(SOFT_FORK_STARTING_HEIGHT_ID), Some(0));
        assert_eq!(p.get(BLOCK_VERSION_ID), Some(1));

        // Accessors.
        assert_eq!(p.max_block_size(), 524_288);
        assert_eq!(p.max_block_cost(), 1_000_000);
        assert_eq!(p.storage_fee_factor(), 1_250_000);
        assert_eq!(p.min_value_per_byte(), 360);
        assert_eq!(p.block_version(), 1);

        // Default trait.
        assert_eq!(Parameters::default(), p);
    }

    #[test]
    fn parse_extension_extracts_parameters() {
        // Build an extension with two system-parameter fields and one interlink noise field.
        let fields = vec![
            // MAX_BLOCK_SIZE = 600_000
            (
                [SYSTEM_PARAMETERS_PREFIX, MAX_BLOCK_SIZE_ID],
                600_000_i32.to_be_bytes().to_vec(),
            ),
            // Interlink noise — should be ignored.
            ([0x01, 0x00], vec![0xAA; 32]),
            // MIN_VALUE_PER_BYTE = 500
            (
                [SYSTEM_PARAMETERS_PREFIX, MIN_VALUE_PER_BYTE_ID],
                500_i32.to_be_bytes().to_vec(),
            ),
        ];
        let ext = Extension {
            header_id: ModifierId([0x11; 32]),
            fields,
        };

        let p = Parameters::from_extension(42, &ext).unwrap();
        assert_eq!(p.height, 42);
        assert_eq!(p.get(MAX_BLOCK_SIZE_ID), Some(600_000));
        assert_eq!(p.get(MIN_VALUE_PER_BYTE_ID), Some(500));
        // No other parameters.
        assert_eq!(p.table.len(), 2);
    }

    #[test]
    fn to_extension_fields_roundtrips() {
        let genesis = Parameters::genesis();
        let fields = genesis.to_extension_fields();

        let ext = Extension {
            header_id: ModifierId([0x00; 32]),
            fields,
        };
        let parsed = Parameters::from_extension(0, &ext).unwrap();
        assert_eq!(genesis.table, parsed.table);
    }

    #[test]
    fn parse_extension_rejects_wrong_value_size() {
        let fields = vec![(
            [SYSTEM_PARAMETERS_PREFIX, MAX_BLOCK_SIZE_ID],
            vec![0x01, 0x02], // 2 bytes instead of 4
        )];
        let ext = Extension {
            header_id: ModifierId([0x00; 32]),
            fields,
        };
        let err = Parameters::from_extension(1, &ext).unwrap_err();
        assert_eq!(
            err,
            ParameterError::InvalidValueSize {
                id: MAX_BLOCK_SIZE_ID,
                size: 2,
            }
        );
    }

    #[test]
    fn update_params_applies_approved_changes() {
        let p = Parameters::genesis();
        let epoch_length = 1024_u32;

        // 600 out of 1024 votes to increase MAX_BLOCK_SIZE — exceeds threshold of 512.
        let mut votes = BTreeMap::new();
        votes.insert(MAX_BLOCK_SIZE_ID, 600_u32);

        let updated = p.update_params(&votes, epoch_length);
        // Step = max(1, 524_288/100) = 5242
        let expected = 524_288 + 5242;
        assert_eq!(updated.get(MAX_BLOCK_SIZE_ID), Some(expected));

        // Other params unchanged.
        assert_eq!(
            updated.get(STORAGE_FEE_FACTOR_ID),
            p.get(STORAGE_FEE_FACTOR_ID)
        );
    }

    #[test]
    fn update_params_ignores_unapproved_changes() {
        let p = Parameters::genesis();
        let epoch_length = 1024_u32;

        // Only 100 out of 1024 votes — does not exceed threshold of 512.
        let mut votes = BTreeMap::new();
        votes.insert(MAX_BLOCK_SIZE_ID, 100_u32);

        let updated = p.update_params(&votes, epoch_length);
        assert_eq!(updated.get(MAX_BLOCK_SIZE_ID), p.get(MAX_BLOCK_SIZE_ID));
    }

    #[test]
    fn update_params_decrease() {
        let p = Parameters::genesis();
        let epoch_length = 1024_u32;

        // Vote to *decrease* STORAGE_FEE_FACTOR (vote id = 1 + 128 = 129).
        let mut votes = BTreeMap::new();
        votes.insert(STORAGE_FEE_FACTOR_ID + 128, 600_u32);

        let updated = p.update_params(&votes, epoch_length);
        // Fixed step = 25_000.
        let expected = 1_250_000 - 25_000;
        assert_eq!(updated.get(STORAGE_FEE_FACTOR_ID), Some(expected));
    }

    #[test]
    fn update_params_clamps_to_bounds() {
        // Start with MIN_VALUE_PER_BYTE very close to 0.
        let mut p = Parameters::genesis();
        p.table.insert(MIN_VALUE_PER_BYTE_ID, 5); // near min (0)

        let epoch_length = 1024_u32;
        // Vote to decrease (vote id = 2 + 128 = 130).
        let mut votes = BTreeMap::new();
        votes.insert(MIN_VALUE_PER_BYTE_ID + 128, 600_u32);

        let updated = p.update_params(&votes, epoch_length);
        // Fixed step = 10, so 5 - 10 = -5 → clamped to min (0).
        assert_eq!(updated.get(MIN_VALUE_PER_BYTE_ID), Some(0));
    }

    #[test]
    fn block_version_accessor_defaults_to_1() {
        // Genesis parameters should have block_version = 1.
        let p = Parameters::genesis();
        assert_eq!(p.block_version(), 1);
    }

    #[test]
    fn block_version_accessor_returns_custom_value() {
        // After a soft-fork, block_version parameter is bumped to 2.
        let mut p = Parameters::genesis();
        p.table.insert(BLOCK_VERSION_ID, 2);
        assert_eq!(p.block_version(), 2);
    }

    #[test]
    fn block_version_accessor_fallback_when_missing() {
        // If BLOCK_VERSION_ID is somehow absent, default to 1.
        let p = Parameters {
            height: 0,
            table: BTreeMap::new(),
        };
        assert_eq!(p.block_version(), 1);
    }

    // -----------------------------------------------------------------------
    // update_fork tests
    // -----------------------------------------------------------------------

    #[test]
    fn update_fork_v2_forced_activation() {
        let mut p = Parameters::genesis();
        let votes = BTreeMap::new();
        p.update_fork(VERSION2_ACTIVATION_HEIGHT, &votes, 1024, 32, 32);
        assert_eq!(p.block_version(), 2);
    }

    #[test]
    fn v2_activation_no_op_before_height() {
        let mut p = Parameters::genesis();
        let votes = BTreeMap::new();
        p.update_fork(VERSION2_ACTIVATION_HEIGHT - 1, &votes, 1024, 32, 32);
        assert_eq!(p.block_version(), 1);
    }

    #[test]
    fn v2_activation_no_op_after_height() {
        let mut p = Parameters::genesis();
        let votes = BTreeMap::new();
        p.update_fork(VERSION2_ACTIVATION_HEIGHT + 1, &votes, 1024, 32, 32);
        assert_eq!(p.block_version(), 1);
    }

    #[test]
    fn v2_activation_no_op_if_already_v2() {
        let mut p = Parameters::genesis();
        p.table.insert(BLOCK_VERSION_ID, 2);
        let votes = BTreeMap::new();
        p.update_fork(VERSION2_ACTIVATION_HEIGHT, &votes, 1024, 32, 32);
        assert_eq!(p.block_version(), 2);
    }

    #[test]
    fn update_fork_no_change_without_votes() {
        let mut p = Parameters::genesis();
        let votes = BTreeMap::new();
        p.update_fork(1024, &votes, 1024, 32, 32);
        assert_eq!(p.block_version(), 1);
        // Starting height 0 is treated as "not set".
        assert!(p
            .table
            .get(&SOFT_FORK_STARTING_HEIGHT_ID)
            .copied()
            .filter(|&h| h > 0)
            .is_none());
    }

    #[test]
    fn update_fork_starts_voting_on_majority() {
        let mut p = Parameters::genesis();
        let mut votes = BTreeMap::new();
        votes.insert(SOFT_FORK_ID, 600);
        p.update_fork(1024, &votes, 1024, 32, 32);
        assert_eq!(p.table.get(&SOFT_FORK_STARTING_HEIGHT_ID), Some(&1024));
        assert_eq!(p.table.get(&SOFT_FORK_VOTES_COLLECTED_ID), Some(&600));
    }

    #[test]
    fn update_fork_accumulates_votes_across_epochs() {
        let mut p = Parameters::genesis();
        let mut votes = BTreeMap::new();
        votes.insert(SOFT_FORK_ID, 600);
        p.update_fork(1024, &votes, 1024, 32, 32);

        let mut votes2 = BTreeMap::new();
        votes2.insert(SOFT_FORK_ID, 700);
        p.update_fork(2048, &votes2, 1024, 32, 32);
        assert_eq!(p.table.get(&SOFT_FORK_VOTES_COLLECTED_ID), Some(&1300));
    }

    #[test]
    fn update_fork_activation_on_approval() {
        let mut p = Parameters::genesis();
        p.table.insert(SOFT_FORK_STARTING_HEIGHT_ID, 1024);
        p.table.insert(SOFT_FORK_VOTES_COLLECTED_ID, 29000);
        let mut votes = BTreeMap::new();
        votes.insert(SOFT_FORK_ID, 500); // total = 500 + 29000 = 29500 > 29491
                                         // Activation height = 1024 + 1024 * (32 + 32) = 66560
        p.update_fork(66560, &votes, 1024, 32, 32);
        assert_eq!(p.block_version(), 2);
    }

    #[test]
    fn update_fork_unsuccessful_cleanup() {
        let mut p = Parameters::genesis();
        p.table.insert(SOFT_FORK_STARTING_HEIGHT_ID, 1024);
        p.table.insert(SOFT_FORK_VOTES_COLLECTED_ID, 100);
        let votes = BTreeMap::new();
        // Unsuccessful cleanup height = 1024 + 1024 * (32 + 1) = 34816
        p.update_fork(34816, &votes, 1024, 32, 32);
        assert!(p
            .table
            .get(&SOFT_FORK_STARTING_HEIGHT_ID)
            .copied()
            .filter(|&h| h > 0)
            .is_none());
        assert_eq!(p.block_version(), 1);
    }

    // -----------------------------------------------------------------------
    // check_fork_vote tests (rule 407)
    // -----------------------------------------------------------------------

    #[test]
    fn check_fork_vote_no_soft_fork_height_always_ok() {
        // Genesis parameters have starting height = 0, treated as "not set".
        let params = Parameters::default();
        assert!(check_fork_vote(1000, &params, 1024, 32, 32).is_ok());
    }

    #[test]
    fn check_fork_vote_prohibited_not_approved() {
        let mut params = Parameters::default();
        params.table.insert(SOFT_FORK_STARTING_HEIGHT_ID, 1000);
        params.table.insert(SOFT_FORK_VOTES_COLLECTED_ID, 100); // not enough for approval
                                                                // finishing_height = 1000 + 1024 * 32 = 33768
        let finishing_height = 1000 + 1024 * 32;
        // At finishing_height, should be prohibited (not approved, in cleanup epoch).
        assert!(check_fork_vote(finishing_height, &params, 1024, 32, 32).is_err());
    }

    #[test]
    fn check_fork_vote_not_approved_after_cleanup_epoch_ok() {
        let mut params = Parameters::default();
        params.table.insert(SOFT_FORK_STARTING_HEIGHT_ID, 1000);
        params.table.insert(SOFT_FORK_VOTES_COLLECTED_ID, 100); // not enough for approval
                                                                // finishing_height = 1000 + 1024 * 32 = 33768
        let finishing_height = 1000 + 1024 * 32;
        // After cleanup epoch (finishing_height + voting_epoch_length), should be ok.
        assert!(check_fork_vote(finishing_height + 1024, &params, 1024, 32, 32).is_ok());
    }

    #[test]
    fn check_fork_vote_prohibited_approved() {
        let mut params = Parameters::default();
        params.table.insert(SOFT_FORK_STARTING_HEIGHT_ID, 1000);
        // Approved threshold: votes > 1024 * 32 * 9 / 10 = 29491
        params.table.insert(SOFT_FORK_VOTES_COLLECTED_ID, 30000);
        // finishing_height = 1000 + 1024 * 32 = 33768
        let finishing_height = 1000 + 1024 * 32;
        // During activation window, should be prohibited (approved).
        assert!(check_fork_vote(finishing_height + 1024, &params, 1024, 32, 32).is_err());
    }

    #[test]
    fn check_fork_vote_approved_after_activation_ok() {
        let mut params = Parameters::default();
        params.table.insert(SOFT_FORK_STARTING_HEIGHT_ID, 1000);
        // Approved threshold: votes > 1024 * 32 * 9 / 10 = 29491
        params.table.insert(SOFT_FORK_VOTES_COLLECTED_ID, 30000);
        // after_activation_height = finishing + 1024 * (32 + 1) = 33768 + 33792 = 67560
        let finishing_height = 1000 + 1024 * 32;
        let after_activation_height = finishing_height + 1024 * (32 + 1);
        // At after_activation_height, prohibition window is past.
        assert!(check_fork_vote(after_activation_height, &params, 1024, 32, 32).is_ok());
    }

    #[test]
    fn check_fork_vote_allowed_before_finishing() {
        let mut params = Parameters::default();
        params.table.insert(SOFT_FORK_STARTING_HEIGHT_ID, 1000);
        params.table.insert(SOFT_FORK_VOTES_COLLECTED_ID, 100);
        // Before finishing_height (33768), should be allowed.
        assert!(check_fork_vote(1500, &params, 1024, 32, 32).is_ok());
    }
}

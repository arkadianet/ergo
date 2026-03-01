//! Voting state machine for epoch-based parameter evolution.
//!
//! Miners cast votes in each block header (3 bytes). Over an epoch, votes are
//! accumulated and, if a majority is reached, the corresponding parameter is
//! adjusted at the epoch boundary.

use std::collections::BTreeMap;

use ergo_types::extension::Extension;

use crate::parameters::{Parameters, ACTIVATION_EPOCHS, NO_PARAMETER, SOFT_FORK_EPOCHS};
use crate::validation_rules::ValidationSettings;

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Returns `true` if `count` exceeds strict majority of `epoch_length`.
///
/// A parameter change is approved when more than half the blocks in an epoch
/// vote for it: `count > epoch_length / 2`.
pub fn change_approved(count: u32, epoch_length: u32) -> bool {
    count > epoch_length / 2
}

/// Returns `true` if a soft-fork proposal has gathered enough total votes
/// across multiple epochs.
///
/// The threshold is 90 % of `epoch_length * soft_fork_epochs`:
/// `total_votes > epoch_length * soft_fork_epochs * 9 / 10`.
pub fn soft_fork_approved(total_votes: u32, epoch_length: u32, soft_fork_epochs: u32) -> bool {
    total_votes > epoch_length * soft_fork_epochs * 9 / 10
}

// ---------------------------------------------------------------------------
// VotingData
// ---------------------------------------------------------------------------

/// Per-epoch vote accumulator.
///
/// Tracks how many times each vote byte has been cast during the current
/// voting epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VotingData {
    /// Maps vote byte -> count of blocks that cast this vote.
    pub epoch_votes: BTreeMap<u8, u32>,
}

impl VotingData {
    /// Create a new, empty `VotingData`.
    pub fn new() -> Self {
        VotingData {
            epoch_votes: BTreeMap::new(),
        }
    }

    /// Record a single vote byte.
    ///
    /// `NO_PARAMETER` (0) votes are silently skipped.
    pub fn update(&mut self, vote: u8) {
        if vote == NO_PARAMETER {
            return;
        }
        *self.epoch_votes.entry(vote).or_insert(0) += 1;
    }

    /// Process the three vote bytes from a block header.
    pub fn process_header_votes(&mut self, votes: &[u8; 3]) {
        for &v in votes {
            self.update(v);
        }
    }

    /// Clear all accumulated votes (used at epoch boundaries).
    pub fn reset(&mut self) {
        self.epoch_votes.clear();
    }
}

impl Default for VotingData {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// VotingEpochInfo
// ---------------------------------------------------------------------------

/// Full epoch voting context: current parameters, accumulated votes, and
/// the height at which the current epoch started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VotingEpochInfo {
    /// The parameter set effective during (and possibly changed at the end of)
    /// this epoch.
    pub parameters: Parameters,
    /// Vote accumulator for the current epoch.
    pub voting_data: VotingData,
    /// Height of the first block in this epoch.
    pub epoch_start_height: u32,
    /// Soft-forkable validation rules (updated at epoch boundaries).
    pub validation_settings: ValidationSettings,
}

impl VotingEpochInfo {
    /// Create a new epoch info with the given parameters and start height.
    pub fn new(parameters: Parameters, epoch_start_height: u32) -> Self {
        VotingEpochInfo {
            parameters,
            voting_data: VotingData::new(),
            epoch_start_height,
            validation_settings: ValidationSettings::initial(),
        }
    }

    /// Record the three vote bytes from a block header.
    pub fn process_block_votes(&mut self, votes: &[u8; 3]) {
        self.voting_data.process_header_votes(votes);
    }

    /// At the epoch boundary, compute the updated parameter set by applying
    /// all approved vote changes and the soft-fork state machine.
    pub fn compute_epoch_result(&self, epoch_length: u32, boundary_height: u32) -> Parameters {
        let mut result = self
            .parameters
            .update_params(&self.voting_data.epoch_votes, epoch_length);
        result.height = boundary_height;
        result.update_fork(
            boundary_height,
            &self.voting_data.epoch_votes,
            epoch_length,
            SOFT_FORK_EPOCHS,
            ACTIVATION_EPOCHS,
        );
        result
    }

    /// Update validation settings from an Extension block at epoch boundary.
    ///
    /// Implements rules 411/412: parse settings from Extension, then verify
    /// they match the expected settings computed from vote-derived updates.
    /// For the first epoch (epoch_start_height == 0), accept parsed as-is.
    pub fn update_validation_settings(&mut self, ext: &Extension) -> Result<(), String> {
        let parsed = match ValidationSettings::from_extension(ext) {
            Ok(s) => s,
            Err(e) => return Err(format!("rule 411: cannot parse validation settings: {e}")),
        };

        if self.epoch_start_height == 0 {
            // First epoch: accept parsed settings without comparison.
            self.validation_settings = parsed;
            return Ok(());
        }

        // Compute expected settings from current settings + parameter state.
        let expected = self
            .validation_settings
            .expected_after_voting(&self.parameters);

        if parsed != expected {
            return Err(
                "rule 412: validation settings mismatch: parsed != computed from votes".to_string(),
            );
        }

        self.validation_settings = parsed;
        Ok(())
    }

    /// Transition to a new epoch: install new parameters, reset the vote
    /// accumulator, and record the new epoch start height.
    ///
    /// The `validation_settings` are intentionally preserved across epoch
    /// boundaries — they are updated separately via
    /// [`update_validation_settings`](Self::update_validation_settings).
    pub fn start_new_epoch(&mut self, params: Parameters, new_start_height: u32) {
        self.parameters = params;
        self.voting_data.reset();
        self.epoch_start_height = new_start_height;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::{MAX_BLOCK_SIZE_ID, STORAGE_FEE_FACTOR_ID};

    #[test]
    fn voting_data_new_is_empty() {
        let vd = VotingData::new();
        assert!(vd.epoch_votes.is_empty());
    }

    #[test]
    fn voting_data_accumulates_votes() {
        let mut vd = VotingData::new();
        // 2 votes for MAX_BLOCK_SIZE
        vd.update(MAX_BLOCK_SIZE_ID);
        vd.update(MAX_BLOCK_SIZE_ID);
        // 1 vote for STORAGE_FEE
        vd.update(STORAGE_FEE_FACTOR_ID);

        assert_eq!(vd.epoch_votes.get(&MAX_BLOCK_SIZE_ID), Some(&2));
        assert_eq!(vd.epoch_votes.get(&STORAGE_FEE_FACTOR_ID), Some(&1));
        assert_eq!(vd.epoch_votes.len(), 2);
    }

    #[test]
    fn voting_data_skips_no_parameter() {
        let mut vd = VotingData::new();
        vd.update(NO_PARAMETER);
        vd.update(NO_PARAMETER);
        assert!(vd.epoch_votes.is_empty());
    }

    #[test]
    fn process_header_votes_accumulates_all_three() {
        let mut vd = VotingData::new();
        vd.process_header_votes(&[MAX_BLOCK_SIZE_ID, STORAGE_FEE_FACTOR_ID, 0]);

        assert_eq!(vd.epoch_votes.get(&MAX_BLOCK_SIZE_ID), Some(&1));
        assert_eq!(vd.epoch_votes.get(&STORAGE_FEE_FACTOR_ID), Some(&1));
        // NO_PARAMETER (0) should have been skipped.
        assert_eq!(vd.epoch_votes.get(&NO_PARAMETER), None);
        assert_eq!(vd.epoch_votes.len(), 2);
    }

    #[test]
    fn change_approved_majority() {
        let epoch_length = 1024_u32;
        // threshold = 1024 / 2 = 512; count must be > 512.
        assert!(change_approved(600, epoch_length));
        assert!(change_approved(513, epoch_length));
        assert!(!change_approved(512, epoch_length));
        assert!(!change_approved(100, epoch_length));
    }

    #[test]
    fn soft_fork_approved_threshold() {
        let epoch_length = 1024_u32;
        let soft_fork_epochs = 32_u32;
        // threshold = 1024 * 32 * 9 / 10 = 29_491.2 → integer = 29_491
        // total_votes must be > 29_491.
        assert!(soft_fork_approved(29_492, epoch_length, soft_fork_epochs));
        assert!(!soft_fork_approved(29_491, epoch_length, soft_fork_epochs));
    }

    #[test]
    fn voting_epoch_info_process_block() {
        let params = Parameters::genesis();
        let mut info = VotingEpochInfo::new(params, 0);

        info.process_block_votes(&[MAX_BLOCK_SIZE_ID, 0, 0]);

        assert_eq!(
            info.voting_data.epoch_votes.get(&MAX_BLOCK_SIZE_ID),
            Some(&1)
        );
    }

    #[test]
    fn voting_epoch_info_has_initial_validation_settings() {
        use crate::validation_rules::{TX_DUST, TX_NO_INPUTS};
        let info = VotingEpochInfo::new(Parameters::genesis(), 0);
        assert!(info.validation_settings.is_active(TX_DUST));
        assert!(info.validation_settings.is_active(TX_NO_INPUTS));
    }

    #[test]
    fn update_validation_settings_from_extension() {
        use crate::validation_rules::{ValidationSettingsUpdate, TX_DUST, TX_NO_INPUTS};
        use ergo_types::extension::VALIDATION_RULES_PREFIX;
        use ergo_types::modifier_id::ModifierId;

        let mut info = VotingEpochInfo::new(Parameters::genesis(), 0);
        assert!(info.validation_settings.is_active(TX_DUST));

        // Build an Extension that disables TX_DUST.
        let update = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST],
            sigma_status_updates: vec![],
        };
        let bytes = update.serialize();
        let ext = ergo_types::extension::Extension {
            header_id: ModifierId([0u8; 32]),
            fields: vec![([VALIDATION_RULES_PREFIX, 0], bytes)],
        };

        info.update_validation_settings(&ext).unwrap();
        assert!(!info.validation_settings.is_active(TX_DUST));
        assert!(info.validation_settings.is_active(TX_NO_INPUTS));
    }

    #[test]
    fn start_new_epoch_preserves_validation_settings() {
        use crate::validation_rules::{ValidationSettingsUpdate, TX_DUST};
        use ergo_types::extension::VALIDATION_RULES_PREFIX;
        use ergo_types::modifier_id::ModifierId;

        let mut info = VotingEpochInfo::new(Parameters::genesis(), 0);

        // Disable TX_DUST via update_validation_settings.
        let update = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST],
            sigma_status_updates: vec![],
        };
        let bytes = update.serialize();
        let ext = ergo_types::extension::Extension {
            header_id: ModifierId([0u8; 32]),
            fields: vec![([VALIDATION_RULES_PREFIX, 0], bytes)],
        };
        info.update_validation_settings(&ext).unwrap();
        assert!(!info.validation_settings.is_active(TX_DUST));

        // Start new epoch — validation_settings should carry forward.
        info.start_new_epoch(Parameters::genesis(), 1024);
        assert!(!info.validation_settings.is_active(TX_DUST));
    }

    #[test]
    fn voting_epoch_info_at_epoch_boundary() {
        let epoch_length = 1024_u32;
        let params = Parameters::genesis();
        let mut info = VotingEpochInfo::new(params.clone(), 0);

        // 600 blocks vote to increase MAX_BLOCK_SIZE.
        for _ in 0..600 {
            info.process_block_votes(&[MAX_BLOCK_SIZE_ID, 0, 0]);
        }
        // 424 blocks with no-op votes (all zeros).
        for _ in 0..424 {
            info.process_block_votes(&[0, 0, 0]);
        }

        assert_eq!(
            info.voting_data.epoch_votes.get(&MAX_BLOCK_SIZE_ID),
            Some(&600)
        );

        let result = info.compute_epoch_result(epoch_length, epoch_length);
        // Step for MAX_BLOCK_SIZE = max(1, 524_288/100) = 5242.
        let expected = 524_288 + 5242;
        assert_eq!(result.get(MAX_BLOCK_SIZE_ID), Some(expected));

        // Other params unchanged.
        assert_eq!(
            result.get(STORAGE_FEE_FACTOR_ID),
            params.get(STORAGE_FEE_FACTOR_ID)
        );
    }

    #[test]
    fn update_validation_settings_first_epoch_accepts() {
        use ergo_types::modifier_id::ModifierId;

        let mut info = VotingEpochInfo::new(Parameters::genesis(), 0);
        let ext = ergo_types::extension::Extension {
            header_id: ModifierId([0u8; 32]),
            fields: vec![],
        };
        assert!(info.update_validation_settings(&ext).is_ok());
    }

    #[test]
    fn update_validation_settings_subsequent_epoch_matches() {
        use ergo_types::modifier_id::ModifierId;

        let mut info = VotingEpochInfo::new(Parameters::genesis(), 1024);
        // Empty extension parses as initial() settings, which matches the
        // expected settings (initial unchanged by voting).
        let ext = ergo_types::extension::Extension {
            header_id: ModifierId([0u8; 32]),
            fields: vec![],
        };
        assert!(info.update_validation_settings(&ext).is_ok());
    }

    #[test]
    fn update_validation_settings_subsequent_epoch_rejects_mismatch() {
        use crate::validation_rules::{ValidationSettingsUpdate, TX_DUST};
        use ergo_types::extension::VALIDATION_RULES_PREFIX;
        use ergo_types::modifier_id::ModifierId;

        // Start at a subsequent epoch so the comparison branch is exercised.
        let mut info = VotingEpochInfo::new(Parameters::genesis(), 1024);

        // Build an Extension that claims TX_DUST is disabled, but the node's
        // current validation_settings (initial) have TX_DUST active. Since no
        // votes occurred, the expected settings still have TX_DUST active.
        let update = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST],
            sigma_status_updates: vec![],
        };
        let bytes = update.serialize();
        let ext = ergo_types::extension::Extension {
            header_id: ModifierId([0u8; 32]),
            fields: vec![([VALIDATION_RULES_PREFIX, 0], bytes)],
        };

        let result = info.update_validation_settings(&ext);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("rule 412"));
    }
}

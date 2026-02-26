//! Soft-forkable validation rules system (mirrors Scala ErgoValidationSettings).
//!
//! Every consensus rule has a numeric ID and a [`RuleStatus`] describing its severity,
//! whether it may be disabled via soft-fork, and whether it is currently active.
//! [`ValidationSettings`] holds the full registry and can be patched at epoch
//! boundaries through [`ValidationSettingsUpdate`].

use std::collections::BTreeMap;

use ergo_types::extension::{Extension, VALIDATION_RULES_PREFIX};
use ergo_wire::vlq;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Whether a validation failure is consensus-critical or implementation-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Consensus-critical — must cause block rejection.
    Fatal,
    /// Implementation-specific — the modifier may be retried later.
    Recoverable,
}

/// Status of a single validation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleStatus {
    /// Severity of violations of this rule.
    pub severity: ErrorSeverity,
    /// Whether the rule may be disabled via a soft-fork vote.
    pub may_be_disabled: bool,
    /// Whether the rule is currently enforced.
    pub is_active: bool,
}

impl RuleStatus {
    /// Convenience constructor — all rules start active.
    fn new(severity: ErrorSeverity, may_be_disabled: bool) -> Self {
        Self {
            severity,
            may_be_disabled,
            is_active: true,
        }
    }

    /// Shorthand for a fatal, permanent (non-disableable) rule.
    fn fatal() -> Self {
        Self::new(ErrorSeverity::Fatal, false)
    }

    /// Shorthand for a fatal rule that *may* be disabled via soft-fork.
    fn fatal_soft() -> Self {
        Self::new(ErrorSeverity::Fatal, true)
    }

    /// Shorthand for a recoverable, permanent rule.
    fn recoverable() -> Self {
        Self::new(ErrorSeverity::Recoverable, false)
    }

    /// Shorthand for a recoverable rule that *may* be disabled via soft-fork.
    fn recoverable_soft() -> Self {
        Self::new(ErrorSeverity::Recoverable, true)
    }
}

/// Container for validation rules together with their current statuses.
///
/// Mirrors Scala `ErgoValidationSettings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationSettings {
    rules: BTreeMap<u16, RuleStatus>,
    /// The cumulative delta from [`initial()`](Self::initial) that produced
    /// the current rule map.
    pub update_from_initial: ValidationSettingsUpdate,
}

/// A patch that can be applied to [`ValidationSettings`] to disable rules
/// or update sigma-protocol statuses.
///
/// Mirrors Scala `ErgoValidationSettingsUpdate`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationSettingsUpdate {
    /// Rule IDs to disable.
    pub rules_to_disable: Vec<u16>,
    /// Sigma rule status updates (rule ID, opaque payload).
    pub sigma_status_updates: Vec<(u16, Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// Rule ID constants — Transaction rules (100–124)
// ---------------------------------------------------------------------------

/// A transaction should have at least one input.
pub const TX_NO_INPUTS: u16 = 100;
/// A transaction should have at least one output.
pub const TX_NO_OUTPUTS: u16 = 101;
/// Number of transaction inputs should not exceed `Short.MaxValue`.
pub const TX_MANY_INPUTS: u16 = 102;
/// Number of transaction data inputs should not exceed `Short.MaxValue`.
pub const TX_MANY_DATA_INPUTS: u16 = 103;
/// Number of transaction outputs should not exceed `Short.MaxValue`.
pub const TX_MANY_OUTPUTS: u16 = 104;
/// Erg amount for a transaction output should not be negative.
pub const TX_NEGATIVE_OUTPUT: u16 = 105;
/// Sum of transaction output values should not exceed `i64::MAX`.
pub const TX_OUTPUT_SUM: u16 = 106;
/// There should be no duplicate inputs.
pub const TX_INPUTS_UNIQUE: u16 = 107;
/// All token amounts of transaction outputs should be positive.
pub const TX_POSITIVE_ASSETS: u16 = 108;
/// Number of tokens within a box should not exceed the limit and sum should not overflow.
pub const TX_ASSETS_IN_ONE_BOX: u16 = 109;
// Note: 110 is not assigned.
/// Every output should contain at least `minValuePerByte * outputSize` nanoErgs (soft-forkable).
pub const TX_DUST: u16 = 111;
/// Transaction outputs should have `creationHeight` not exceeding block height.
pub const TX_FUTURE: u16 = 112;
/// Every input of the transaction should be in UTXO.
pub const TX_BOXES_TO_SPEND: u16 = 113;
/// Every data input of the transaction should be in UTXO.
pub const TX_DATA_BOXES: u16 = 114;
/// Sum of transaction inputs should not exceed `i64::MAX`.
pub const TX_INPUTS_SUM: u16 = 115;
/// Amount of Ergs in inputs should be equal to amount in outputs.
pub const TX_ERG_PRESERVATION: u16 = 116;
/// For every token, its amount in outputs should not exceed its amount in inputs.
pub const TX_ASSETS_PRESERVATION: u16 = 117;
/// Box id should match the input (soft-forkable).
pub const TX_BOX_TO_SPEND: u16 = 118;
/// Scripts of all transaction inputs should pass verification.
pub const TX_SCRIPT_VALIDATION: u16 = 119;
/// Box size should not exceed `MaxBoxSize` (soft-forkable).
pub const TX_BOX_SIZE: u16 = 120;
/// Box proposition size should not exceed `MaxPropositionBytes` (soft-forkable).
pub const TX_BOX_PROPOSITION_SIZE: u16 = 121;
/// Transaction outputs should have non-negative `creationHeight`.
pub const TX_NEG_HEIGHT: u16 = 122;
/// Transaction should conform to EIP-27 re-emission rules (soft-forkable).
pub const TX_REEMISSION: u16 = 123;
/// Creation height of any output should be non-decreasing (soft-forkable).
pub const TX_MONOTONIC_HEIGHT: u16 = 124;

// ---------------------------------------------------------------------------
// Rule ID constants — Header rules (200–216)
// ---------------------------------------------------------------------------

/// Genesis header should have the genesis parent id.
pub const HDR_GENESIS_PARENT: u16 = 200;
/// Genesis header id should equal the id from config.
pub const HDR_GENESIS_FROM_CONFIG: u16 = 201;
// Note: 202 is not assigned.
/// Genesis height should be the configured genesis height.
pub const HDR_GENESIS_HEIGHT: u16 = 203;
/// Parent header must be defined (Recoverable).
pub const HDR_PARENT: u16 = 204;
/// Header timestamp should be greater than the parent's.
pub const HDR_NON_INCREASING_TIMESTAMP: u16 = 205;
/// Header height should be greater by one than the parent's.
pub const HDR_HEIGHT: u16 = 206;
/// Header should contain correct PoW solution.
pub const HDR_POW: u16 = 207;
/// Header should contain correct required difficulty.
pub const HDR_REQUIRED_DIFFICULTY: u16 = 208;
/// Header height should not be older than `current_height - keepVersions`.
pub const HDR_TOO_OLD: u16 = 209;
/// Parent header should not be marked as invalid.
pub const HDR_PARENT_SEMANTICS: u16 = 210;
/// Header timestamp should not be more than 20 minutes in the future (Recoverable).
pub const HDR_FUTURE_TIMESTAMP: u16 = 211;
/// Number of non-zero votes should be <= `ParamVotesCount` (soft-forkable).
pub const HDR_VOTES_NUMBER: u16 = 212;
/// Header votes should contain no duplicates.
pub const HDR_VOTES_DUPLICATES: u16 = 213;
/// Header votes should contain no contradictory votes.
pub const HDR_VOTES_CONTRADICTORY: u16 = 214;
/// First header of an epoch should not contain a vote for an unknown parameter (soft-forkable).
pub const HDR_VOTES_UNKNOWN: u16 = 215;
/// Chain is failing checkpoint validation.
pub const HDR_CHECKPOINT: u16 = 216;

// ---------------------------------------------------------------------------
// Rule ID constants — Block section rules (300–307)
// ---------------------------------------------------------------------------

/// Double application of a modifier is prohibited.
pub const ALREADY_APPLIED: u16 = 300;
/// Header for a modifier is not defined (Recoverable).
pub const BS_NO_HEADER: u16 = 301;
/// Block sections should correspond to the declared header.
pub const BS_CORRESPONDS_TO_HEADER: u16 = 302;
/// Header for the block section should not be marked as invalid.
pub const BS_HEADER_VALID: u16 = 303;
/// Headers-chain is not synchronized yet (Recoverable).
pub const BS_HEADERS_CHAIN_SYNCED: u16 = 304;
/// Block section should correspond to a block header that is not pruned yet.
pub const BS_TOO_OLD: u16 = 305;
/// Size of block transactions section should not exceed `maxBlockSize` (soft-forkable).
pub const BS_BLOCK_TRANSACTIONS_SIZE: u16 = 306;
/// Accumulated cost of block transactions should not exceed `maxBlockCost`.
pub const BS_BLOCK_TRANSACTIONS_COST: u16 = 307;

// ---------------------------------------------------------------------------
// Rule ID constants — Extension rules (400–413)
// ---------------------------------------------------------------------------

/// Size of extension section should not exceed `MaxExtensionSize` (soft-forkable).
pub const EX_SIZE: u16 = 400;
/// Interlinks should be packed properly (soft-forkable).
pub const EX_IL_ENCODING: u16 = 401;
/// Interlinks should have the correct structure (soft-forkable).
pub const EX_IL_STRUCTURE: u16 = 402;
/// Extension fields key length should be `FieldKeySize`.
pub const EX_KEY_LENGTH: u16 = 403;
/// Extension field value length should be <= `FieldValueMaxSize` (soft-forkable).
pub const EX_VALUE_LENGTH: u16 = 404;
/// Extension should not contain duplicate keys (soft-forkable).
pub const EX_DUPLICATE_KEYS: u16 = 405;
/// Extension of non-genesis block should not be empty (soft-forkable).
pub const EX_EMPTY: u16 = 406;
/// Voting for fork could only start after activation period of a previous soft-fork (soft-forkable).
pub const EX_CHECK_FORK_VOTE: u16 = 407;
/// Epoch extension should contain correctly packed parameters (soft-forkable).
pub const EX_PARSE_PARAMETERS: u16 = 408;
/// Epoch extension should contain all system parameters (soft-forkable).
pub const EX_MATCH_PARAMETERS: u16 = 409;
/// Versions in header and parameters section should be equal (soft-forkable).
pub const EX_BLOCK_VERSION: u16 = 410;
/// Epoch extension should contain correctly packed validation settings (soft-forkable).
pub const EX_PARSE_VALIDATION_SETTINGS: u16 = 411;
/// Epoch extension should contain all validation settings (soft-forkable).
pub const EX_MATCH_VALIDATION_SETTINGS: u16 = 412;
/// Unable to validate interlinks (Recoverable, soft-forkable).
pub const EX_IL_UNABLE_TO_VALIDATE: u16 = 413;

// ---------------------------------------------------------------------------
// Rule ID constants — Full block rules (500–501)
// ---------------------------------------------------------------------------

/// Operations against the state AVL+ tree should be successful.
pub const FB_OPERATION_FAILED: u16 = 500;
/// Calculated AVL+ digest should equal the one written in the block header.
pub const FB_DIGEST_INCORRECT: u16 = 501;

// ---------------------------------------------------------------------------
// ValidationSettings implementation
// ---------------------------------------------------------------------------

impl ValidationSettings {
    /// Creates the initial validation settings with all 64 rules active.
    ///
    /// This is used during genesis state creation and for static checks that
    /// are not allowed to be deactivated via soft-forks.
    pub fn initial() -> Self {
        let mut rules = BTreeMap::new();

        // -- Transaction rules (100–124) --
        rules.insert(TX_NO_INPUTS, RuleStatus::fatal());
        rules.insert(TX_NO_OUTPUTS, RuleStatus::fatal());
        rules.insert(TX_MANY_INPUTS, RuleStatus::fatal());
        rules.insert(TX_MANY_DATA_INPUTS, RuleStatus::fatal());
        rules.insert(TX_MANY_OUTPUTS, RuleStatus::fatal());
        rules.insert(TX_NEGATIVE_OUTPUT, RuleStatus::fatal());
        rules.insert(TX_OUTPUT_SUM, RuleStatus::fatal());
        rules.insert(TX_INPUTS_UNIQUE, RuleStatus::fatal());
        rules.insert(TX_POSITIVE_ASSETS, RuleStatus::fatal());
        rules.insert(TX_ASSETS_IN_ONE_BOX, RuleStatus::fatal());
        rules.insert(TX_DUST, RuleStatus::fatal_soft());
        rules.insert(TX_FUTURE, RuleStatus::fatal());
        rules.insert(TX_BOXES_TO_SPEND, RuleStatus::fatal());
        rules.insert(TX_DATA_BOXES, RuleStatus::fatal());
        rules.insert(TX_INPUTS_SUM, RuleStatus::fatal());
        rules.insert(TX_ERG_PRESERVATION, RuleStatus::fatal());
        rules.insert(TX_ASSETS_PRESERVATION, RuleStatus::fatal());
        rules.insert(TX_BOX_TO_SPEND, RuleStatus::fatal_soft());
        rules.insert(TX_SCRIPT_VALIDATION, RuleStatus::fatal());
        rules.insert(TX_BOX_SIZE, RuleStatus::fatal_soft());
        rules.insert(TX_BOX_PROPOSITION_SIZE, RuleStatus::fatal_soft());
        rules.insert(TX_NEG_HEIGHT, RuleStatus::fatal());
        rules.insert(TX_REEMISSION, RuleStatus::fatal_soft());
        rules.insert(TX_MONOTONIC_HEIGHT, RuleStatus::fatal_soft());

        // -- Header rules (200–216) --
        rules.insert(HDR_GENESIS_PARENT, RuleStatus::fatal());
        rules.insert(HDR_GENESIS_FROM_CONFIG, RuleStatus::fatal());
        rules.insert(HDR_GENESIS_HEIGHT, RuleStatus::fatal());
        rules.insert(HDR_PARENT, RuleStatus::recoverable());
        rules.insert(HDR_NON_INCREASING_TIMESTAMP, RuleStatus::fatal());
        rules.insert(HDR_HEIGHT, RuleStatus::fatal());
        rules.insert(HDR_POW, RuleStatus::fatal());
        rules.insert(HDR_REQUIRED_DIFFICULTY, RuleStatus::fatal());
        rules.insert(HDR_TOO_OLD, RuleStatus::fatal());
        rules.insert(HDR_PARENT_SEMANTICS, RuleStatus::fatal());
        rules.insert(HDR_FUTURE_TIMESTAMP, RuleStatus::recoverable());
        rules.insert(HDR_VOTES_NUMBER, RuleStatus::fatal_soft());
        rules.insert(HDR_VOTES_DUPLICATES, RuleStatus::fatal());
        rules.insert(HDR_VOTES_CONTRADICTORY, RuleStatus::fatal());
        rules.insert(HDR_VOTES_UNKNOWN, RuleStatus::fatal_soft());
        rules.insert(HDR_CHECKPOINT, RuleStatus::fatal());

        // -- Block section rules (300–307) --
        rules.insert(ALREADY_APPLIED, RuleStatus::fatal());
        rules.insert(BS_NO_HEADER, RuleStatus::recoverable());
        rules.insert(BS_CORRESPONDS_TO_HEADER, RuleStatus::fatal());
        rules.insert(BS_HEADER_VALID, RuleStatus::fatal());
        rules.insert(BS_HEADERS_CHAIN_SYNCED, RuleStatus::recoverable());
        rules.insert(BS_TOO_OLD, RuleStatus::fatal());
        rules.insert(BS_BLOCK_TRANSACTIONS_SIZE, RuleStatus::fatal_soft());
        rules.insert(BS_BLOCK_TRANSACTIONS_COST, RuleStatus::fatal());

        // -- Extension rules (400–413) --
        rules.insert(EX_SIZE, RuleStatus::fatal_soft());
        rules.insert(EX_IL_ENCODING, RuleStatus::fatal_soft());
        rules.insert(EX_IL_STRUCTURE, RuleStatus::fatal_soft());
        rules.insert(EX_KEY_LENGTH, RuleStatus::fatal());
        rules.insert(EX_VALUE_LENGTH, RuleStatus::fatal_soft());
        rules.insert(EX_DUPLICATE_KEYS, RuleStatus::fatal_soft());
        rules.insert(EX_EMPTY, RuleStatus::fatal_soft());
        rules.insert(EX_CHECK_FORK_VOTE, RuleStatus::fatal_soft());
        rules.insert(EX_PARSE_PARAMETERS, RuleStatus::fatal_soft());
        rules.insert(EX_MATCH_PARAMETERS, RuleStatus::fatal_soft());
        rules.insert(EX_BLOCK_VERSION, RuleStatus::fatal_soft());
        rules.insert(EX_PARSE_VALIDATION_SETTINGS, RuleStatus::fatal_soft());
        rules.insert(EX_MATCH_VALIDATION_SETTINGS, RuleStatus::fatal_soft());
        rules.insert(EX_IL_UNABLE_TO_VALIDATE, RuleStatus::recoverable_soft());

        // -- Full block rules (500–501) --
        rules.insert(FB_OPERATION_FAILED, RuleStatus::fatal());
        rules.insert(FB_DIGEST_INCORRECT, RuleStatus::fatal());

        Self {
            rules,
            update_from_initial: ValidationSettingsUpdate::default(),
        }
    }

    /// Serialize the current validation settings (as the delta from initial).
    pub fn serialize(&self) -> Vec<u8> {
        self.update_from_initial.serialize()
    }

    /// Parse validation settings from wire bytes, applying the decoded update
    /// to the [`initial()`](Self::initial) settings.
    pub fn parse(data: &[u8]) -> Result<Self, vlq::CodecError> {
        let update = ValidationSettingsUpdate::parse(data)?;
        Ok(Self::initial().updated(&update))
    }

    /// Returns `true` if the rule is active.
    ///
    /// Unknown rule IDs are treated as active (mirrors Scala `forall` semantics).
    pub fn is_active(&self, rule_id: u16) -> bool {
        self.rules
            .get(&rule_id)
            .is_none_or(|status| status.is_active)
    }

    /// Returns a reference to the underlying rules map.
    pub fn rules(&self) -> &BTreeMap<u16, RuleStatus> {
        &self.rules
    }

    /// Produces a new `ValidationSettings` with the given update applied.
    ///
    /// Only rules marked `may_be_disabled = true` will actually be disabled.
    /// The cumulative `update_from_initial` is merged.
    pub fn updated(&self, update: &ValidationSettingsUpdate) -> Self {
        let mut new_rules = self.rules.clone();
        for &rule_id in &update.rules_to_disable {
            if let Some(status) = new_rules.get_mut(&rule_id) {
                if status.may_be_disabled {
                    status.is_active = false;
                }
            }
        }
        let total_update = self.update_from_initial.merge(update);
        Self {
            rules: new_rules,
            update_from_initial: total_update,
        }
    }

    /// Compute expected validation settings based on parameter/voting changes.
    ///
    /// In the current implementation, validation settings changes are driven by
    /// soft-fork votes encoded in the Extension itself, not by parameter values.
    /// This returns a clone of the current settings, serving as the baseline for
    /// epoch boundary verification (rule 412).
    pub fn expected_after_voting(&self, _parameters: &crate::parameters::Parameters) -> Self {
        self.clone()
    }

    /// Parse validation settings from an Extension block's fields.
    /// Returns `initial()` if no validation rules fields are present.
    pub fn from_extension(ext: &Extension) -> Result<Self, vlq::CodecError> {
        let mut chunks: Vec<(u8, &[u8])> = ext
            .fields
            .iter()
            .filter(|(key, _)| key[0] == VALIDATION_RULES_PREFIX)
            .map(|(key, val)| (key[1], val.as_slice()))
            .collect();

        if chunks.is_empty() {
            return Ok(Self::initial());
        }

        // Sort by chunk index and concatenate.
        chunks.sort_by_key(|(idx, _)| *idx);
        let concatenated: Vec<u8> = chunks
            .iter()
            .flat_map(|(_, data)| data.iter().copied())
            .collect();

        Self::parse(&concatenated)
    }

    /// Serialize to Extension field entries (split into 64-byte chunks).
    pub fn to_extension_fields(&self) -> Vec<([u8; 2], Vec<u8>)> {
        if self.update_from_initial.is_empty() {
            return Vec::new();
        }
        let bytes = self.serialize();
        bytes
            .chunks(64)
            .enumerate()
            .map(|(i, chunk)| ([VALIDATION_RULES_PREFIX, i as u8], chunk.to_vec()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ValidationSettingsUpdate implementation
// ---------------------------------------------------------------------------

impl ValidationSettingsUpdate {
    /// Serialize to the wire format matching Scala `ErgoValidationSettingsUpdateSerializer`.
    ///
    /// Wire layout:
    /// ```text
    /// [VLQ u32: disabled_count]
    ///   [VLQ u16: rule_id] * disabled_count
    /// [VLQ u32: sigma_updates_count]
    ///   [VLQ u16: sigma_rule_id]
    ///   [raw bytes: sigma RuleStatus serialized]
    ///   * sigma_updates_count
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        vlq::put_uint(&mut buf, self.rules_to_disable.len() as u32);
        for &id in &self.rules_to_disable {
            vlq::put_ushort(&mut buf, id);
        }
        vlq::put_uint(&mut buf, self.sigma_status_updates.len() as u32);
        for (id, data) in &self.sigma_status_updates {
            vlq::put_ushort(&mut buf, *id);
            buf.extend_from_slice(data);
        }
        buf
    }

    /// Parse from the wire format matching Scala `ErgoValidationSettingsUpdateSerializer`.
    pub fn parse(data: &[u8]) -> Result<Self, vlq::CodecError> {
        let mut reader = data;
        let disabled_count = vlq::get_uint(&mut reader)? as usize;
        let mut rules_to_disable = Vec::with_capacity(disabled_count);
        for _ in 0..disabled_count {
            rules_to_disable.push(vlq::get_ushort(&mut reader)?);
        }
        let sigma_count = vlq::get_uint(&mut reader)? as usize;
        let mut sigma_status_updates = Vec::with_capacity(sigma_count);
        if sigma_count > 0 {
            let id = vlq::get_ushort(&mut reader)?;
            // Store remaining bytes as opaque sigma data for this entry.
            // In practice sigma updates are rare; treat the rest as payload.
            sigma_status_updates.push((id, reader.to_vec()));
        }
        Ok(Self {
            rules_to_disable,
            sigma_status_updates,
        })
    }

    /// Returns `true` if this update carries no changes.
    pub fn is_empty(&self) -> bool {
        self.rules_to_disable.is_empty() && self.sigma_status_updates.is_empty()
    }

    /// Merges `other` into `self`, accumulating both rule-disable lists and
    /// sigma status updates.  Duplicate disable IDs are deduplicated; for
    /// sigma updates on the same rule ID the later value (`other`) wins.
    pub fn merge(&self, other: &Self) -> Self {
        // Combine rules_to_disable, dedup, sorted.
        let mut combined_disable: Vec<u16> = self.rules_to_disable.to_vec();
        for &id in &other.rules_to_disable {
            if !combined_disable.contains(&id) {
                combined_disable.push(id);
            }
        }
        combined_disable.sort_unstable();

        // Combine sigma_status_updates — other wins for same ID.
        let mut combined_sigma: Vec<(u16, Vec<u8>)> = self
            .sigma_status_updates
            .iter()
            .filter(|(id, _)| !other.sigma_status_updates.iter().any(|(oid, _)| oid == id))
            .cloned()
            .collect();
        combined_sigma.extend(other.sigma_status_updates.iter().cloned());
        combined_sigma.sort_by_key(|(id, _)| *id);

        Self {
            rules_to_disable: combined_disable,
            sigma_status_updates: combined_sigma,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_settings_all_active() {
        let settings = ValidationSettings::initial();
        // All 44 known rules should be active.
        for (&id, status) in settings.rules() {
            assert!(
                status.is_active,
                "Rule {id} should be active in initial settings"
            );
        }
        assert_eq!(settings.rules().len(), 64);
        // Unknown rule ID treated as active.
        assert!(settings.is_active(9999));
    }

    #[test]
    fn disable_soft_forkable_rule() {
        let initial = ValidationSettings::initial();
        assert!(initial.is_active(TX_DUST));

        let update = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST],
            sigma_status_updates: vec![],
        };
        let updated = initial.updated(&update);
        assert!(!updated.is_active(TX_DUST));
        // Other rules unaffected.
        assert!(updated.is_active(TX_NO_INPUTS));
        assert!(updated.is_active(TX_BOX_SIZE));
    }

    #[test]
    fn cannot_disable_permanent_rule() {
        let initial = ValidationSettings::initial();
        assert!(initial.is_active(TX_NO_INPUTS));

        let update = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_NO_INPUTS],
            sigma_status_updates: vec![],
        };
        let updated = initial.updated(&update);
        // TX_NO_INPUTS has may_be_disabled=false, so it stays active.
        assert!(updated.is_active(TX_NO_INPUTS));
    }

    #[test]
    fn update_merge_accumulates() {
        let u1 = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST],
            sigma_status_updates: vec![(1, vec![0x01])],
        };
        let u2 = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_BOX_SIZE],
            sigma_status_updates: vec![(2, vec![0x02])],
        };
        let merged = u1.merge(&u2);
        assert_eq!(merged.rules_to_disable, vec![TX_DUST, TX_BOX_SIZE]);
        assert_eq!(merged.sigma_status_updates.len(), 2);
        assert!(merged.sigma_status_updates.contains(&(1, vec![0x01])));
        assert!(merged.sigma_status_updates.contains(&(2, vec![0x02])));
    }

    #[test]
    fn update_merge_deduplicates() {
        let u1 = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST, TX_BOX_SIZE],
            sigma_status_updates: vec![(1, vec![0x01])],
        };
        let u2 = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST, TX_REEMISSION],
            sigma_status_updates: vec![(1, vec![0xFF])],
        };
        let merged = u1.merge(&u2);
        // TX_DUST appears only once.
        assert_eq!(
            merged.rules_to_disable,
            vec![TX_DUST, TX_BOX_SIZE, TX_REEMISSION]
        );
        // Sigma update for id 1: u2 wins.
        assert_eq!(merged.sigma_status_updates, vec![(1, vec![0xFF])]);
    }

    #[test]
    fn update_is_empty() {
        let empty = ValidationSettingsUpdate::default();
        assert!(empty.is_empty());

        let non_empty = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST],
            sigma_status_updates: vec![],
        };
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn severity_matches_scala() {
        let settings = ValidationSettings::initial();
        // Recoverable rules.
        assert_eq!(
            settings.rules().get(&HDR_PARENT).unwrap().severity,
            ErrorSeverity::Recoverable
        );
        assert_eq!(
            settings.rules().get(&HDR_FUTURE_TIMESTAMP).unwrap().severity,
            ErrorSeverity::Recoverable
        );
        assert_eq!(
            settings.rules().get(&BS_NO_HEADER).unwrap().severity,
            ErrorSeverity::Recoverable
        );
        assert_eq!(
            settings.rules().get(&BS_HEADERS_CHAIN_SYNCED).unwrap().severity,
            ErrorSeverity::Recoverable
        );
        assert_eq!(
            settings.rules().get(&EX_IL_UNABLE_TO_VALIDATE).unwrap().severity,
            ErrorSeverity::Recoverable
        );
        // A sampling of fatal rules.
        assert_eq!(
            settings.rules().get(&TX_NO_INPUTS).unwrap().severity,
            ErrorSeverity::Fatal
        );
        assert_eq!(
            settings.rules().get(&FB_OPERATION_FAILED).unwrap().severity,
            ErrorSeverity::Fatal
        );
    }

    #[test]
    fn settings_update_roundtrip() {
        let update = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST, TX_BOX_SIZE, EX_SIZE],
            sigma_status_updates: vec![],
        };
        let bytes = update.serialize();
        let parsed = ValidationSettingsUpdate::parse(&bytes).unwrap();
        assert_eq!(parsed.rules_to_disable, update.rules_to_disable);
    }

    #[test]
    fn empty_update_roundtrip() {
        let update = ValidationSettingsUpdate::default();
        let bytes = update.serialize();
        let parsed = ValidationSettingsUpdate::parse(&bytes).unwrap();
        assert!(parsed.rules_to_disable.is_empty());
        assert!(parsed.sigma_status_updates.is_empty());
    }

    #[test]
    fn settings_parse_applies_to_initial() {
        let update = ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST],
            sigma_status_updates: vec![],
        };
        let bytes = update.serialize();
        let settings = ValidationSettings::parse(&bytes).unwrap();
        assert!(!settings.is_active(TX_DUST));
        assert!(settings.is_active(TX_NO_INPUTS));
    }

    #[test]
    fn may_be_disabled_matches_scala() {
        let settings = ValidationSettings::initial();
        // Soft-forkable rules.
        let soft_forkable = [
            TX_DUST,
            TX_BOX_TO_SPEND,
            TX_BOX_SIZE,
            TX_BOX_PROPOSITION_SIZE,
            TX_REEMISSION,
            TX_MONOTONIC_HEIGHT,
            HDR_VOTES_NUMBER,
            HDR_VOTES_UNKNOWN,
            BS_BLOCK_TRANSACTIONS_SIZE,
            EX_SIZE,
            EX_IL_ENCODING,
            EX_IL_STRUCTURE,
            EX_VALUE_LENGTH,
            EX_DUPLICATE_KEYS,
            EX_EMPTY,
            EX_CHECK_FORK_VOTE,
            EX_PARSE_PARAMETERS,
            EX_MATCH_PARAMETERS,
            EX_BLOCK_VERSION,
            EX_PARSE_VALIDATION_SETTINGS,
            EX_MATCH_VALIDATION_SETTINGS,
            EX_IL_UNABLE_TO_VALIDATE,
        ];
        for &id in &soft_forkable {
            assert!(
                settings.rules().get(&id).unwrap().may_be_disabled,
                "Rule {id} should be soft-forkable"
            );
        }
        // Permanent rules (a sample).
        let permanent = [
            TX_NO_INPUTS,
            TX_NO_OUTPUTS,
            TX_SCRIPT_VALIDATION,
            HDR_POW,
            HDR_CHECKPOINT,
            ALREADY_APPLIED,
            EX_KEY_LENGTH,
            FB_OPERATION_FAILED,
            FB_DIGEST_INCORRECT,
        ];
        for &id in &permanent {
            assert!(
                !settings.rules().get(&id).unwrap().may_be_disabled,
                "Rule {id} should NOT be soft-forkable"
            );
        }
    }

    #[test]
    fn from_extension_empty_returns_initial() {
        use ergo_types::modifier_id::ModifierId;
        let ext = Extension {
            header_id: ModifierId([0u8; 32]),
            fields: vec![],
        };
        let settings = ValidationSettings::from_extension(&ext).unwrap();
        assert!(settings.is_active(TX_DUST));
    }

    #[test]
    fn from_extension_roundtrip() {
        use ergo_types::modifier_id::ModifierId;
        let settings = ValidationSettings::initial().updated(&ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST, TX_BOX_SIZE],
            sigma_status_updates: vec![],
        });
        let fields = settings.to_extension_fields();
        let ext = Extension {
            header_id: ModifierId([0u8; 32]),
            fields,
        };
        let parsed = ValidationSettings::from_extension(&ext).unwrap();
        assert!(!parsed.is_active(TX_DUST));
        assert!(!parsed.is_active(TX_BOX_SIZE));
        assert!(parsed.is_active(TX_NO_INPUTS));
    }
}

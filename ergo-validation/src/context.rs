use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;

/// Snapshot of protocol parameters at a given epoch.
/// These change at epoch boundaries via soft-fork voting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolParams {
    /// Activated Sigma statuses. Complete tip/target contexts use
    /// `from_active_with_settings` / `for_block`; `from_active` alone carries
    /// only the supplied row's status delta.
    pub validation_settings: ergo_sigma::evaluator::SigmaValidationSettings,
    /// Minimum nanoErg per byte of serialized box. Default: 360.
    pub min_value_per_byte: u64,
    /// Maximum cumulative cost for all scripts in a block. Default: 1,000,000.
    pub max_block_cost: u64,
    /// Maximum serialized `BlockTransactions` section size in bytes
    /// (voted parameter — Scala `maxBlockSize`). Default: 524_288.
    /// Used by rule 306 (`bsBlockTransactionsSize`).
    pub max_block_size: u32,
    /// Maximum serialized box size in bytes. Protocol-level: 4096.
    pub max_box_size: u32,
    /// Maximum tokens per box. Protocol-level: 122.
    pub max_tokens_per_box: u8,
    /// Cost per transaction input (votable). Default: 2,000.
    pub input_cost: u64,
    /// Cost per data input (votable). Default: 100.
    pub data_input_cost: u64,
    /// Cost per output candidate (votable). Default: 100.
    pub output_cost: u64,
    /// Cost per token access entry (votable). Default: 100.
    pub token_access_cost: u64,
    /// Storage fee factor: nanoErg per byte per storage period. Default: 1,250,000.
    /// Votable parameter. Used in storage rent calculation.
    pub storage_fee_factor: i32,
    /// Storage period in blocks (4 years). Default: 1,051,200.
    pub storage_period: u32,
    /// Protocol block version (voted parameter 123, Scala
    /// `Parameters.blockVersion`). Scala's `stateContext.blockVersion`:
    /// transaction rules and the activated script version (`blockVersion - 1`,
    /// `ErgoContext.activatedScriptVersion`) derive from it, not from the
    /// validated header's own version byte, which only rule 410 ties to it at
    /// epoch starts.
    pub block_version: u8,
}

impl ProtocolParams {
    /// Select parameters after validating the target block's epoch extension.
    /// Scala appends that extension before executing the target transactions.
    pub fn for_block(
        parent: &crate::active_params::ActiveProtocolParameters,
        voted: Option<&crate::active_params::ActiveProtocolParameters>,
        previous_settings: &crate::ErgoValidationSettings,
    ) -> Self {
        let settings = voted.map_or_else(
            || previous_settings.clone(),
            |target| previous_settings.updated(&target.activated_update),
        );
        Self::from_active_with_settings(voted.unwrap_or(parent), &settings)
    }

    /// Convert an active parameter row with the separately accumulated rule
    /// settings at the same tip. A row's `activated_update` is an epoch delta;
    /// it cannot reconstruct statuses activated in earlier epochs.
    pub fn from_active_with_settings(
        active: &crate::active_params::ActiveProtocolParameters,
        settings: &crate::ErgoValidationSettings,
    ) -> Self {
        let mut params = Self::from_active(active);
        params.validation_settings = sigma_settings(settings.status_updates());
        params
    }

    /// Mainnet defaults — frozen snapshot of the votable parameters at
    /// the time these were captured. The authoritative path is to derive
    /// `ProtocolParams` from a per-epoch [`crate::ActiveProtocolParameters`] via
    /// [`Self::from_active_with_settings`]; this constructor is a fallback when the
    /// per-epoch active set is not yet available.
    pub fn mainnet_default() -> Self {
        Self {
            validation_settings: Default::default(),
            min_value_per_byte: 360,
            // Mainnet value from blockchain parameters (adjusted via voting).
            // The authoritative source is the extension section of the
            // first block of each epoch — see `from_active` below.
            max_block_cost: 8_001_091,
            max_block_size: 524_288,
            max_box_size: 4096,
            max_tokens_per_box: 122,
            input_cost: 2_000,
            data_input_cost: 100,
            output_cost: 100,
            token_access_cost: 100,
            storage_fee_factor: 1_250_000,
            storage_period: 1_051_200,
            // Block version 2 (Hardening) in force with the votable values above
            // (e.g. mainnet height 700,000). Contexts for other heights must set
            // the version that was active there.
            block_version: 2,
        }
    }

    /// Convert numeric fields and this row's activated status delta from the
    /// per-epoch active set persisted in `voted_params`. Call
    /// [`Self::from_active_with_settings`] for a complete tip context or
    /// [`Self::for_block`] for a target block's validated epoch transition.
    /// Total and infallible: the parser / persisted-codec rejects
    /// out-of-range values up front, so by the time we reach
    /// `from_active` every cost-bearing field is already guaranteed
    /// `>= 0`. Widening `i32 → u64` is a pure type-level cast.
    ///
    /// The non-votable protocol constants (`max_box_size`,
    /// `max_tokens_per_box`, `storage_period`) are pulled from
    /// `mainnet_default`.
    pub fn from_active(active: &crate::active_params::ActiveProtocolParameters) -> Self {
        // Negativity guard lives at the parse / persisted-codec boundary
        // (`active_params::parse_active_params` and
        // `ActiveProtocolParameters::deserialize`); see
        // `ActiveParamsError::NegativeCostBearingParam`. Any negative
        // value reaching this constructor is a violated parser
        // invariant — `debug_assert!` surfaces the bug in tests without
        // taking down a production node, where the downstream
        // cost-parity test would still detect the resulting drift.
        debug_assert!(
            active.min_value_per_byte >= 0,
            "negative min_value_per_byte leaked past parse boundary"
        );
        debug_assert!(
            active.max_block_cost >= 0,
            "negative max_block_cost leaked past parse boundary"
        );
        debug_assert!(
            active.max_block_size >= 0,
            "negative max_block_size leaked past parse boundary"
        );
        debug_assert!(
            active.input_cost >= 0,
            "negative input_cost leaked past parse boundary"
        );
        debug_assert!(
            active.data_input_cost >= 0,
            "negative data_input_cost leaked past parse boundary"
        );
        debug_assert!(
            active.output_cost >= 0,
            "negative output_cost leaked past parse boundary"
        );
        debug_assert!(
            active.token_access_cost >= 0,
            "negative token_access_cost leaked past parse boundary"
        );
        Self {
            validation_settings: sigma_settings(&active.activated_update.status_updates),
            min_value_per_byte: active.min_value_per_byte as u64,
            max_block_cost: active.max_block_cost as u64,
            max_block_size: active.max_block_size as u32,
            max_box_size: 4096,
            max_tokens_per_box: 122,
            input_cost: active.input_cost as u64,
            data_input_cost: active.data_input_cost as u64,
            output_cost: active.output_cost as u64,
            token_access_cost: active.token_access_cost as u64,
            storage_fee_factor: active.storage_fee_factor,
            storage_period: 1_051_200,
            block_version: active.block_version,
        }
    }
}

fn sigma_settings(
    statuses: &[(u16, crate::voting::validation_settings::RuleStatus)],
) -> ergo_sigma::evaluator::SigmaValidationSettings {
    use crate::voting::validation_settings::RuleStatus as Voted;
    use ergo_sigma::evaluator::RuleStatus as Sigma;
    ergo_sigma::evaluator::SigmaValidationSettings(
        statuses
            .iter()
            .map(|(id, status)| {
                (
                    *id,
                    match status {
                        Voted::Enabled => Sigma::Enabled,
                        Voted::Disabled => Sigma::Disabled,
                        Voted::Replaced(id) => Sigma::Replaced(*id),
                        Voted::Changed(bytes) => Sigma::Changed(bytes.clone()),
                    },
                )
            })
            .collect(),
    )
}

/// Local node policy limits (not consensus rules).
/// A transaction violating these is rejected by this node but may be
/// valid on the network.
pub struct LocalPolicy {
    /// Maximum transaction byte size this node will accept.
    pub max_transaction_size: usize,
}

impl LocalPolicy {
    /// Default policy — 512 KiB max transaction size (matches the
    /// default max block size). Tightening below this is safe; raising
    /// it accepts transactions other nodes will silently drop.
    pub fn default_policy() -> Self {
        Self {
            max_transaction_size: 524_288, // 512KB — same as default max block size
        }
    }
}

/// Minimal trait for UTXO lookup during transaction validation.
///
/// Returns owned `ErgoBox` to avoid leaking storage lifetimes into the
/// validation layer. The extra clone cost is acceptable.
pub trait UtxoView {
    /// Look up an unspent box by id. Returns `None` when the box is
    /// not present in the active UTXO set.
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox>;
}

/// Block/chain context needed for transaction validation.
///
/// Per-input context extension values come from `Input.spending_proof.extension()`,
/// not from this struct — they are threaded per-input in script validation.
pub struct TransactionContext {
    /// Current block height being validated.
    pub height: u32,
    /// Miner public key (33-byte compressed SEC1) from the block being validated.
    pub miner_pubkey: [u8; 33],
    /// Block timestamp (milliseconds since epoch) from the pre-header.
    pub pre_header_timestamp: u64,
    /// Activated script version = protocol block version - 1 (Scala
    /// `ErgoContext.activatedScriptVersion = stateContext.blockVersion - 1`).
    /// Controls consensus-preserving behavior (e.g., selfBoxIndex bug in v4.x)
    /// and, through [`Self::block_version`], the version-gated transaction rules.
    /// Stored as byte bits; use `as i8` for Scala's signed activation comparisons.
    /// See [`crate::derive_activated_script_version`] for the matched JVM quirk.
    pub activated_script_version: u8,
    /// Pre-header version byte, script-visible as `CONTEXT.preHeader.version`
    /// (the validated header's own version for a block).
    pub pre_header_version: u8,
    /// Parent block header ID (32 bytes).
    pub pre_header_parent_id: [u8; 32],
    /// Encoded difficulty (nBits from header).
    pub pre_header_n_bits: u64,
    /// Miner votes (3 bytes from header).
    pub pre_header_votes: [u8; 3],
}

impl TransactionContext {
    /// Protocol block version gating transaction rules (Scala
    /// `stateContext.blockVersion`), recovered from
    /// [`Self::activated_script_version`], which Scala derives as
    /// `blockVersion - 1`. Never the pre-header's version byte.
    pub fn block_version(&self) -> u8 {
        self.activated_script_version.wrapping_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_params::ActiveProtocolParameters;

    fn baseline_active() -> ActiveProtocolParameters {
        ActiveProtocolParameters {
            epoch_start_height: 1024,
            block_version: 1,
            storage_fee_factor: 1_250_000,
            min_value_per_byte: 360,
            max_block_size: 524_288,
            max_block_cost: 1_000_000,
            token_access_cost: 100,
            input_cost: 2_000,
            data_input_cost: 100,
            output_cost: 100,
            subblocks_per_block: None,
            extra: vec![],
            proposed_update:
                crate::voting::validation_settings::ErgoValidationSettingsUpdate::empty(),
            activated_update:
                crate::voting::validation_settings::ErgoValidationSettingsUpdate::empty(),
        }
    }

    // ----- happy path -----

    #[test]
    fn from_active_accepts_baseline_voted_params() {
        let p = ProtocolParams::from_active(&baseline_active());
        assert_eq!(p.input_cost, 2_000);
        assert_eq!(p.max_block_cost, 1_000_000);
        assert_eq!(p.min_value_per_byte, 360);
    }

    #[test]
    fn cumulative_target_context_matches_all_pinned_jvm_observations() {
        use crate::{ErgoValidationSettings, ErgoValidationSettingsUpdate, RuleStatus};
        let parent = baseline_active();
        let mut first = parent.clone();
        first.activated_update = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![215],
            status_updates: vec![
                (1007, RuleStatus::Disabled),
                (1008, RuleStatus::Changed(vec![10, 11])),
            ],
        };
        let initial = ErgoValidationSettings::empty();
        let first_settings = initial.updated(&first.activated_update);
        let mut empty = first.clone();
        empty.activated_update = ErgoValidationSettingsUpdate::empty();
        let mut replaced = empty.clone();
        replaced.activated_update = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![
                (1007, RuleStatus::Replaced(1017)),
                (1011, RuleStatus::Disabled),
            ],
        };
        let observations =
            include_str!("../../test-vectors/ergo-validation/cumulative-context/observations.tsv");
        let mut settings_count = 0;
        let mut cap_count = 0;
        for line in observations.lines() {
            let columns: Vec<_> = line.split('\t').collect();
            match columns[0] {
                "settings" => {
                    assert_eq!(columns.len(), 4);
                    let (previous, target) = match columns[1] {
                        "first" => (&initial, &first),
                        "empty" => (&first_settings, &empty),
                        "replaced" => (&first_settings, &replaced),
                        other => panic!("unexpected settings observation {other}"),
                    };
                    let context = ProtocolParams::for_block(&parent, Some(target), previous);
                    let settings = previous.updated(&target.activated_update);
                    assert_eq!(
                        settings
                            .disabled_rules()
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                        columns[2]
                    );
                    use ergo_sigma::evaluator::RuleStatus as Sigma;
                    let statuses = context
                        .validation_settings
                        .0
                        .iter()
                        .map(|(id, status)| {
                            let status = match status {
                                Sigma::Enabled => "enabled".to_owned(),
                                Sigma::Disabled => "disabled".to_owned(),
                                Sigma::Replaced(id) => format!("replaced:{id}"),
                                Sigma::Changed(bytes) => format!("changed:{}", hex::encode(bytes)),
                            };
                            format!("{id}={status}")
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    assert_eq!(statuses, columns[3], "{} target context", columns[1]);
                    assert_eq!(
                        ProtocolParams::for_block(target, None, &settings).validation_settings,
                        context.validation_settings,
                        "following ordinary block retains target statuses"
                    );
                    settings_count += 1;
                }
                "jit-cap" => {
                    assert_eq!(columns.len(), 3);
                    let mut voted = parent.clone();
                    voted.max_block_cost = columns[1].parse().unwrap();
                    let context = ProtocolParams::for_block(&parent, Some(&voted), &initial);
                    let converted = crate::JitCost::from_block_cost(context.max_block_cost);
                    if columns[2] == "overflow" {
                        assert!(converted.is_err());
                    } else {
                        assert_eq!(
                            converted.unwrap().value(),
                            columns[2].parse::<u64>().unwrap()
                        );
                    }
                    cap_count += 1;
                }
                other => panic!("unexpected observation kind {other}"),
            }
        }
        assert_eq!(settings_count, 3);
        assert_eq!(cap_count, 4);
        assert_eq!(observations.lines().count(), 7);
    }

    #[test]
    fn target_voted_cost_limit_controls_accumulation() {
        let parent = baseline_active();
        let mut target = parent.clone();
        target.max_block_cost = parent.max_block_cost + 1;
        let settings = crate::ErgoValidationSettings::empty();
        let before = ProtocolParams::for_block(&parent, None, &settings);
        let after = ProtocolParams::for_block(&parent, Some(&target), &settings);
        let charge = crate::JitCost::from_block_cost(after.max_block_cost).unwrap();
        let mut before_cost = crate::CostAccumulator::new(
            crate::JitCost::from_block_cost(before.max_block_cost).unwrap(),
        );
        assert!(matches!(
            before_cost.add(charge),
            Err(crate::CostError::LimitExceeded { .. })
        ));
        let mut after_cost = crate::CostAccumulator::new(
            crate::JitCost::from_block_cost(after.max_block_cost).unwrap(),
        );
        after_cost.add(charge).unwrap();
        assert_eq!(after_cost.total_block_cost(), after.max_block_cost);
    }
}

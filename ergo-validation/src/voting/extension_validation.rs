//! Epoch-start extension validation: the four `ex*` rules from
//! `ErgoStateContext.processExtension` (`ErgoStateContext.scala:174-230`).
//!
//! Pure function — no I/O.

use ergo_ser::extension::Extension;
use ergo_ser::header::Header;

use crate::active_params::{parse_active_params, ActiveParamsError, ActiveProtocolParameters};
use crate::voting::recompute::{
    compute_next_params, RecomputeError, VotingSettings, RULE_EX_MATCH_PARAMETERS, SOFT_FORK_ID,
};
use crate::voting::validation_settings::{ErgoValidationSettings, ErgoValidationSettingsUpdate};

/// Outcome of `validate_epoch_extension`. Carries the freshly computed
/// active set (for use as `prev_active` at the next epoch boundary)
/// and the cumulative settings (`prev_settings.updated(activated_update)`)
/// for downstream rule gating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionValidationOutcome {
    /// Recomputed next-epoch active parameters.
    pub computed: ActiveProtocolParameters,
    /// Cumulative validation settings after applying `activated_update`.
    pub next_settings: ErgoValidationSettings,
    /// Validation-settings update activated this epoch.
    pub activated_update: ErgoValidationSettingsUpdate,
}

/// Failures raised by [`validate_epoch_extension`]. Variant names track
/// the Scala `ex*` rule ids so consensus rejection reasons can be
/// surfaced 1:1.
#[derive(Debug, thiserror::Error)]
pub enum ExtensionValidationError {
    /// `exParseParameters` (rule 408) — malformed `voted_params` blob.
    #[error("exParseParameters (rule 408): {0}")]
    ParseParameters(#[source] ActiveParamsError),
    /// `exParseValidationSettings` — malformed validation-settings blob.
    #[error("exParseValidationSettings: {0}")]
    ParseValidationSettings(
        #[source] crate::voting::validation_settings::ValidationSettingsCodecError,
    ),
    /// `exBlockVersion` (rule 410) — header version disagrees with the
    /// recomputed value.
    #[error("exBlockVersion (rule 410): computed={computed} != header={header}")]
    BlockVersion {
        /// Version derived from voting math.
        computed: u8,
        /// Version the header carried.
        header: u8,
    },
    /// `exMatchParameters` (rule 409) — a single parameter field
    /// disagrees with the recomputed value.
    #[error("exMatchParameters (rule 409): {field} differs ({parsed} vs {computed})")]
    MatchParameters {
        /// Name of the offending parameter.
        field: &'static str,
        /// Value carried by the extension.
        parsed: i64,
        /// Value the recompute derived.
        computed: i64,
    },
    /// `exMatchParameters` (rule 409) — parsed and computed parameter
    /// tables differ in size.
    #[error("exMatchParameters (rule 409): size differs (parsed={parsed} != computed={computed})")]
    MatchParametersSize {
        /// Size of the parsed table.
        parsed: usize,
        /// Size of the recomputed table.
        computed: usize,
    },
    /// `exMatchParameters60` (rule 414) — protocol-v60 parameter field
    /// mismatch.
    #[error("exMatchParameters60 (rule 414): {field} differs ({parsed} vs {computed})")]
    MatchParameters60 {
        /// Name of the offending parameter.
        field: &'static str,
        /// Value carried by the extension.
        parsed: i64,
        /// Value the recompute derived.
        computed: i64,
    },
    /// `exMatchParameters60` (rule 414) — parsed table is larger than
    /// the recomputed table.
    #[error(
        "exMatchParameters60 (rule 414): size violation (parsed={parsed} > computed={computed})"
    )]
    MatchParameters60Size {
        /// Size of the parsed table.
        parsed: usize,
        /// Size of the recomputed table.
        computed: usize,
    },
    /// `exMatchValidationSettings` — parsed settings disagree with
    /// `prev_settings.updated(activated_update)`.
    ///
    /// The payload carries both sides of the diff so the failure is
    /// debuggable from a single log line. `parsed_disabled` /
    /// `parsed_status_n` come from the block's extension; `computed_*`
    /// come from `prev_settings.updated(activated_update)`. Mode 2
    /// install can legitimately mismatch (parsed includes pre-snapshot
    /// cumulative; computed only has launch defaults) — that case is
    /// handled by the trust path in `validate_epoch_extension`.
    #[error(
        "exMatchValidationSettings at h={height}: parsed != prev.updated(activated_update) — \
             parsed_disabled={parsed_disabled:?} computed_disabled={computed_disabled:?} \
             parsed_status_n={parsed_status_n} computed_status_n={computed_status_n}"
    )]
    MatchValidationSettings {
        /// Block height under validation.
        height: u32,
        /// `parsed_settings_update.rules_to_disable` from the extension.
        parsed_disabled: Vec<u16>,
        /// `next_settings.update_from_initial.rules_to_disable` we computed.
        computed_disabled: Vec<u16>,
        /// Count of `parsed.status_updates` (full data omitted to keep
        /// the log line bounded; reconstruct from extension if needed).
        parsed_status_n: usize,
        /// Count of `computed.status_updates`.
        computed_status_n: usize,
    },
    /// `exMatchParameters` — `proposedUpdate` field differs from the
    /// recompute.
    #[error("exMatchParameters proposedUpdate differs")]
    ProposedUpdateMismatch,
    /// Underlying recompute math failed.
    #[error("recompute: {0}")]
    Recompute(#[from] RecomputeError),
}

/// Validate the extension at an epoch-start block.
///
/// Mirrors `ErgoStateContext.processExtension` (`ErgoStateContext.scala:174-230`).
/// Returns the next-epoch active set + cumulative settings +
/// activated_update on success.
///
/// `prev_active`: the active set in effect before this block.
/// `prev_settings`: cumulative validation settings before this block.
/// `epoch_votes`: tally of the just-finished epoch's votes (see
///   `crate::voting::votes::compute_epoch_votes`).
/// `voting_settings`: chain config (`VotingSettings::mainnet()` for
///   mainnet).
/// `trust_extension_settings`: Mode 2 install one-shot. When `true` and
///   `exMatchValidationSettings` would fail, the parsed cumulative is
///   accepted as `next_settings.update_from_initial` instead of being
///   rejected. Used exactly once at the first epoch-boundary block
///   after a UTXO snapshot install — at that point we lack pre-snapshot
///   history, so `prev_settings` is launch defaults while the chained
///   block legitimately carries the real cumulative settings. The
///   header chain we accepted the snapshot under already establishes
///   trust in this block; this just plumbs that trust to the
///   settings cache. Always `false` outside Mode 2 install.
pub fn validate_epoch_extension(
    extension: &Extension,
    header: &Header,
    prev_active: &ActiveProtocolParameters,
    prev_settings: &ErgoValidationSettings,
    epoch_votes: &[(i8, i32)],
    voting_settings: &VotingSettings,
    trust_extension_settings: bool,
) -> Result<ExtensionValidationOutcome, ExtensionValidationError> {
    // Step 1-2: parse params + settings from extension.
    // (Combined: parse_active_params extracts proposed_update from
    // the (0x00, 124) blob in the same pass; parse_validation_settings_update
    // pulls the cumulative `ErgoValidationSettings` blob from the
    // (0x02, *) entries — Scala's `parsedSettings`.)
    let parsed = parse_active_params(extension, header.height)
        .map_err(ExtensionValidationError::ParseParameters)?;
    let parsed_proposed = parsed.proposed_update.clone();
    let parsed_settings_update =
        crate::voting::validation_settings::parse_validation_settings_update(extension)
            .map_err(ExtensionValidationError::ParseValidationSettings)?;

    // fork_vote: this block's header.votes contains SoftFork (= 120).
    let fork_vote = header.votes.iter().any(|&v| v as i8 == SOFT_FORK_ID);

    // Step 3: compute path. Genesis-era bypass: if prev_active.height
    // == 0 (Scala `currentParameters.height == 0`,
    // ErgoStateContext.scala:198), Scala sets
    // `calculatedSettings = parsedSettings` so the exMatchValidationSettings
    // equality is trivially true. We mirror that by treating
    // `parsed_settings_update` (the cumulative parsed from extension)
    // as this row's `activated_update` — so when the fold runs
    // `prev_settings.updated(activated_update)` with prev=empty (true
    // under genesis bypass), it yields exactly `parsed_settings_update`.
    //
    // This is NOT the same as `parsed_proposed`: `proposed_update` is a
    // candidate awaiting soft-fork voting, whereas the cumulative
    // `validation_settings` reflects what is actually active. On chains
    // whose first epoch boundary carries a non-empty proposed_update
    // (e.g. testnet h=128 carries `[215, 409]` as a proposal, but its
    // cumulative settings are still empty since no soft fork has
    // activated), using `parsed_proposed` would prematurely activate
    // the proposed rules.
    let (computed, activated_update) = if prev_active.epoch_start_height == 0 {
        let mut c = parsed.clone();
        c.activated_update = parsed_settings_update.clone();
        (c, parsed_settings_update.clone())
    } else {
        compute_next_params(
            prev_active,
            epoch_votes,
            fork_vote,
            &parsed_proposed,
            header.height,
            voting_settings,
        )?
    };

    // Step 4: exBlockVersion (rule 410). Always runs, including under
    // genesis-era bypass — `ErgoStateContext.scala:222`.
    if computed.block_version != header.version {
        return Err(ExtensionValidationError::BlockVersion {
            computed: computed.block_version,
            header: header.version,
        });
    }

    // Steps 5/6: exMatchParameters (409) / exMatchParameters60 (414).
    // Skip 409 iff disabled in prev_settings.
    if !prev_settings.is_rule_disabled(RULE_EX_MATCH_PARAMETERS) {
        match_parameters(&parsed, &computed)?;
    }
    if header.version >= 4 {
        match_parameters_60(&parsed, &computed)?;
    }

    // Step 7: exMatchValidationSettings.
    //
    // Scala `ErgoStateContext.scala:225`:
    //     parsedSettings == calculatedSettings
    // where:
    //   parsedSettings    = ErgoValidationSettings.parseExtension(extension)
    //                       — cumulative-from-initial parsed from
    //                       extension entries with prefix 0x02.
    //   calculatedSettings = currentSettings.updated(activatedUpdate)
    //                       — cumulative-from-initial = previous
    //                       cumulative + this epoch's activated_update.
    //
    // Equality is via `updateFromInitial == updateFromInitial`
    // (`ErgoValidationSettings.scala:90`). We compare those cumulative
    // updates directly.
    let computed_next_settings = prev_settings.updated(&activated_update);
    // The trust path only fires when `prev_settings` is the launch
    // defaults (i.e. `update_from_initial == empty()`). This bounds the
    // bypass to the genuinely-uninformed state — once the trusted
    // cumulative has been seeded (after the first post-install apply),
    // the cache holds it and `prev_settings` is non-empty, so a
    // re-armed trust flag at later epoch boundaries falls through to
    // strict equality. Without this gate, a stale disk flag could
    // accept divergent extensions at any future epoch boundary.
    let trust_can_fire = trust_extension_settings
        && prev_settings.update_from_initial == ErgoValidationSettingsUpdate::empty();
    let next_settings = if parsed_settings_update == computed_next_settings.update_from_initial {
        computed_next_settings
    } else if trust_can_fire {
        // Mode 2 install: accept the parsed cumulative as authoritative
        // and seed the settings cache from it. Logged loudly so the
        // operator can see the one-time relaxation in the journal.
        tracing::warn!(
            height = header.height,
            parsed_disabled = ?parsed_settings_update.rules_to_disable,
            computed_disabled = ?computed_next_settings.update_from_initial.rules_to_disable,
            parsed_status_n = parsed_settings_update.status_updates.len(),
            computed_status_n = computed_next_settings.update_from_initial.status_updates.len(),
            "Mode 2 trust path: accepting parsed validation_settings as cumulative \
             (first post-install epoch boundary)",
        );
        ErgoValidationSettings {
            update_from_initial: parsed_settings_update,
        }
    } else {
        return Err(ExtensionValidationError::MatchValidationSettings {
            height: header.height,
            parsed_disabled: parsed_settings_update.rules_to_disable,
            computed_disabled: computed_next_settings.update_from_initial.rules_to_disable,
            parsed_status_n: parsed_settings_update.status_updates.len(),
            computed_status_n: computed_next_settings
                .update_from_initial
                .status_updates
                .len(),
        });
    };

    Ok(ExtensionValidationOutcome {
        computed,
        next_settings,
        activated_update,
    })
}

/// `Parameters.matchParameters(parsed, computed)`
/// (`Parameters.scala:399-413`). Rule 409: same height, same
/// proposedUpdate, same size, same per-key values.
fn match_parameters(
    parsed: &ActiveProtocolParameters,
    computed: &ActiveProtocolParameters,
) -> Result<(), ExtensionValidationError> {
    if parsed.epoch_start_height != computed.epoch_start_height {
        return Err(ExtensionValidationError::MatchParameters {
            field: "epoch_start_height",
            parsed: parsed.epoch_start_height as i64,
            computed: computed.epoch_start_height as i64,
        });
    }
    if parsed.proposed_update != computed.proposed_update {
        return Err(ExtensionValidationError::ProposedUpdateMismatch);
    }
    let parsed_size = field_count(parsed);
    let computed_size = field_count(computed);
    if parsed_size != computed_size {
        return Err(ExtensionValidationError::MatchParametersSize {
            parsed: parsed_size,
            computed: computed_size,
        });
    }
    check_named_fields(parsed, computed, mk_match_parameters)?;
    Ok(())
}

/// `Parameters.matchParameters60(parsed, computed, version)`
/// (`Parameters.scala:420-440`). Rule 414. Same as 409 but
/// `parsed.size <= computed.size`.
fn match_parameters_60(
    parsed: &ActiveProtocolParameters,
    computed: &ActiveProtocolParameters,
) -> Result<(), ExtensionValidationError> {
    if parsed.epoch_start_height != computed.epoch_start_height {
        return Err(ExtensionValidationError::MatchParameters60 {
            field: "epoch_start_height",
            parsed: parsed.epoch_start_height as i64,
            computed: computed.epoch_start_height as i64,
        });
    }
    if parsed.proposed_update != computed.proposed_update {
        return Err(ExtensionValidationError::ProposedUpdateMismatch);
    }
    let parsed_size = field_count(parsed);
    let computed_size = field_count(computed);
    if parsed_size > computed_size {
        return Err(ExtensionValidationError::MatchParameters60Size {
            parsed: parsed_size,
            computed: computed_size,
        });
    }
    check_named_fields(parsed, computed, mk_match_parameters_60)?;
    Ok(())
}

fn mk_match_parameters(
    field: &'static str,
    parsed: i64,
    computed: i64,
) -> ExtensionValidationError {
    ExtensionValidationError::MatchParameters {
        field,
        parsed,
        computed,
    }
}

fn mk_match_parameters_60(
    field: &'static str,
    parsed: i64,
    computed: i64,
) -> ExtensionValidationError {
    ExtensionValidationError::MatchParameters60 {
        field,
        parsed,
        computed,
    }
}

fn field_count(p: &ActiveProtocolParameters) -> usize {
    let mut n = 9; // ids 1..8 + 123 always present
    if p.subblocks_per_block.is_some() {
        n += 1;
    }
    n + p.extra.len()
}

fn check_named_fields(
    parsed: &ActiveProtocolParameters,
    computed: &ActiveProtocolParameters,
    mk_err: fn(&'static str, i64, i64) -> ExtensionValidationError,
) -> Result<(), ExtensionValidationError> {
    let pairs: &[(&'static str, i64, i64)] = &[
        (
            "storage_fee_factor",
            parsed.storage_fee_factor as i64,
            computed.storage_fee_factor as i64,
        ),
        (
            "min_value_per_byte",
            parsed.min_value_per_byte as i64,
            computed.min_value_per_byte as i64,
        ),
        (
            "max_block_size",
            parsed.max_block_size as i64,
            computed.max_block_size as i64,
        ),
        (
            "max_block_cost",
            parsed.max_block_cost as i64,
            computed.max_block_cost as i64,
        ),
        (
            "token_access_cost",
            parsed.token_access_cost as i64,
            computed.token_access_cost as i64,
        ),
        (
            "input_cost",
            parsed.input_cost as i64,
            computed.input_cost as i64,
        ),
        (
            "data_input_cost",
            parsed.data_input_cost as i64,
            computed.data_input_cost as i64,
        ),
        (
            "output_cost",
            parsed.output_cost as i64,
            computed.output_cost as i64,
        ),
        (
            "block_version",
            parsed.block_version as i64,
            computed.block_version as i64,
        ),
    ];
    for (field, p, c) in pairs {
        if p != c {
            return Err(mk_err(field, *p, *c));
        }
    }
    if parsed.subblocks_per_block != computed.subblocks_per_block {
        let p = parsed.subblocks_per_block.unwrap_or(-1) as i64;
        let c = computed.subblocks_per_block.unwrap_or(-1) as i64;
        return Err(mk_err("subblocks_per_block", p, c));
    }
    // Extras: every extra key in parsed must equal the same key in
    // computed. (Scala iterates parsed.parametersTable; in our model
    // extras are aligned by id.)
    for (id, parsed_val) in &parsed.extra {
        let computed_val = computed
            .extra
            .iter()
            .find(|(eid, _)| eid == id)
            .map(|(_, v)| *v);
        match computed_val {
            Some(c) if c == *parsed_val => {}
            Some(c) => {
                return Err(mk_err("extra", *parsed_val as i64, c as i64));
            }
            None => {
                return Err(mk_err("extra", *parsed_val as i64, 0));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_params::scala_launch;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;

    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::extension::{write_extension, ExtensionField};

    fn make_header(height: u32, version: u8, votes: [u8; 3]) -> Header {
        Header {
            version,
            parent_id: ModifierId::from_bytes([0u8; 32]),
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: 1_700_000_000,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 0x1234_5678,
            height,
            votes,
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0u8; 8],
            },
        }
    }

    fn launch_extension(
        height: u32,
        block_version: u8,
        proposed: &ErgoValidationSettingsUpdate,
    ) -> Extension {
        launch_extension_with_settings(height, block_version, proposed, None)
    }

    /// Build a synthetic extension. `cumulative_settings` (if `Some`)
    /// is serialized into a single (0x02, 0) entry, matching Scala's
    /// `ErgoValidationSettings.toExtensionCandidate` semantics for
    /// the small case (no chunking).
    fn launch_extension_with_settings(
        height: u32,
        block_version: u8,
        proposed: &ErgoValidationSettingsUpdate,
        cumulative_settings: Option<&ErgoValidationSettingsUpdate>,
    ) -> Extension {
        let p = scala_launch_with_overrides(height, block_version, proposed);
        let mut fields = vec![
            field_of(1, p.storage_fee_factor),
            field_of(2, p.min_value_per_byte),
            field_of(3, p.max_block_size),
            field_of(4, p.max_block_cost),
            field_of(5, p.token_access_cost),
            field_of(6, p.input_cost),
            field_of(7, p.data_input_cost),
            field_of(8, p.output_cost),
            field_of(123, p.block_version as i32),
        ];
        if let Some(v) = p.subblocks_per_block {
            fields.push(field_of(9, v));
        }
        // (0x00, 124): proposed_update blob (always present per Scala
        // `Parameters.toExtensionCandidate`).
        fields.push(ExtensionField {
            key: [0x00, 124],
            value: proposed.serialize(),
        });
        // (0x02, *): cumulative ErgoValidationSettings.updateFromInitial,
        // present only when non-empty per Scala
        // `ErgoValidationSettings.toExtensionCandidate`.
        if let Some(cumul) = cumulative_settings {
            if !cumul.rules_to_disable.is_empty() || !cumul.status_updates.is_empty() {
                fields.push(ExtensionField {
                    key: [0x02, 0],
                    value: cumul.serialize(),
                });
            }
        }
        Extension {
            header_id: ModifierId::from_bytes([0u8; 32]),
            fields,
        }
    }

    fn scala_launch_with_overrides(
        height: u32,
        block_version: u8,
        _proposed: &ErgoValidationSettingsUpdate,
    ) -> ActiveProtocolParameters {
        let mut p = scala_launch();
        p.epoch_start_height = height;
        p.block_version = block_version;
        p
    }

    fn field_of(id: u8, value: i32) -> ExtensionField {
        ExtensionField {
            key: [0x00, id],
            value: value.to_be_bytes().to_vec(),
        }
    }

    #[test]
    fn genesis_era_bypass_at_h_1024_runs_block_version_check() {
        // prev_active.epoch_start_height == 0 → bypass recompute.
        // exBlockVersion still fires.
        let prev_active = scala_launch();
        let prev_settings = ErgoValidationSettings::empty();
        let header = make_header(1024, 1, [0u8; 3]);
        let extension = launch_extension(1024, 1, &ErgoValidationSettingsUpdate::empty());
        let outcome = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        )
        .unwrap();
        assert_eq!(outcome.computed.block_version, 1);
    }

    /// End-to-end through `validate_epoch_extension`: a malformed
    /// extension carrying a negative cost-bearing param surfaces as
    /// `ExtensionValidationError::ParseParameters` wrapping
    /// `ActiveParamsError::NegativeProtocolParam`. Pins that the
    /// fail-closed contract at the codec boundary (spec §8.1) flows
    /// through the rule-409/414 dispatcher unchanged.
    #[test]
    fn validate_epoch_extension_rejects_negative_cost_bearing_param() {
        use crate::active_params::ActiveParamsError;
        let prev_active = scala_launch();
        let prev_settings = ErgoValidationSettings::empty();
        let header = make_header(1024, 1, [0u8; 3]);
        let mut extension = launch_extension(1024, 1, &ErgoValidationSettingsUpdate::empty());
        // Overwrite input_cost (id=6) with a negative i32.
        for f in extension.fields.iter_mut() {
            if f.key == [0x00, 6] {
                f.value = (-1i32).to_be_bytes().to_vec();
            }
        }
        let err = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        )
        .unwrap_err();
        match err {
            ExtensionValidationError::ParseParameters(
                ActiveParamsError::NegativeProtocolParam { id, value },
            ) => {
                assert_eq!(id, 6);
                assert_eq!(value, -1);
            }
            other => panic!("expected ParseParameters(NegativeProtocolParam), got {other:?}"),
        }
    }

    #[test]
    fn genesis_era_bypass_rejects_mismatched_block_version() {
        let prev_active = scala_launch();
        let prev_settings = ErgoValidationSettings::empty();
        // Header claims version 2 but extension says block_version 1.
        let header = make_header(1024, 2, [0u8; 3]);
        let extension = launch_extension(1024, 1, &ErgoValidationSettingsUpdate::empty());
        let err = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        )
        .unwrap_err();
        match err {
            ExtensionValidationError::BlockVersion {
                computed,
                header: h,
            } => {
                assert_eq!(computed, 1);
                assert_eq!(h, 2);
            }
            other => panic!("expected BlockVersion error, got {other:?}"),
        }
    }

    #[test]
    fn second_epoch_recompute_no_votes_passes() {
        // prev_active.epoch_start_height = 1024 (post genesis-era).
        // No votes → params unchanged, validate against extension that
        // matches.
        let mut prev_active = scala_launch();
        prev_active.epoch_start_height = 1024;
        let prev_settings = ErgoValidationSettings::empty();
        let header = make_header(2048, 1, [0u8; 3]);
        let extension = launch_extension(2048, 1, &ErgoValidationSettingsUpdate::empty());
        let outcome = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        )
        .unwrap();
        assert_eq!(outcome.computed.epoch_start_height, 2048);
        assert_eq!(outcome.computed.input_cost, prev_active.input_cost);
    }

    #[test]
    fn rule_409_skipped_when_disabled() {
        // prev_settings disables rule 409. exMatchParameters is a
        // no-op; on header.version < 4, exMatchParameters60 is also a
        // no-op. So a parsed/computed size mismatch (extension carries
        // an extra subblocks_per_block while computed has none) is
        // tolerated when 409 is off.
        let mut prev_active = scala_launch();
        prev_active.epoch_start_height = 1024;
        let cumul_settings_update = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![],
        };
        let prev_settings = ErgoValidationSettings::empty().updated(&cumul_settings_update);

        let header = make_header(2048, 1, [0u8; 3]);
        // Build extension with subblocks_per_block=30 in addition to
        // the required set. Computed (from launch params + no votes,
        // block_version=1) has subblocks_per_block=None. Size mismatch.
        let mut p = scala_launch();
        p.epoch_start_height = 2048;
        let mut fields = vec![
            field_of(1, p.storage_fee_factor),
            field_of(2, p.min_value_per_byte),
            field_of(3, p.max_block_size),
            field_of(4, p.max_block_cost),
            field_of(5, p.token_access_cost),
            field_of(6, p.input_cost),
            field_of(7, p.data_input_cost),
            field_of(8, p.output_cost),
            field_of(123, 1),
            field_of(9, 30), // <-- size mismatch trigger
        ];
        fields.push(ExtensionField {
            key: [0x00, 124],
            value: ErgoValidationSettingsUpdate::empty().serialize(),
        });
        // Cumulative settings carry forward unchanged (no new
        // activation), so the extension's (0x02, 0) entry must still
        // include rule 409 disabled to match prev_settings.
        fields.push(ExtensionField {
            key: [0x02, 0],
            value: cumul_settings_update.serialize(),
        });
        let extension = Extension {
            header_id: ModifierId::from_bytes([0u8; 32]),
            fields,
        };
        let outcome = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        );
        assert!(
            outcome.is_ok(),
            "rule 409 disabled should let mismatched-size pass: {outcome:?}"
        );
    }

    #[test]
    fn proposed_update_mismatch_rejected() {
        let mut prev_active = scala_launch();
        prev_active.epoch_start_height = 1024;
        let prev_settings = ErgoValidationSettings::empty();
        let header = make_header(2048, 1, [0u8; 3]);
        // Extension claims a cumulative validation_settings update
        // (rules_to_disable=[409]) via (0x02, *), but no soft-fork
        // is active, so computed activated_update = empty and
        // computed cumulative settings = prev (empty). Mismatch on
        // exMatchValidationSettings.
        let claimed_cumulative = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![],
        };
        let extension = launch_extension_with_settings(
            2048,
            1,
            &ErgoValidationSettingsUpdate::empty(),
            Some(&claimed_cumulative),
        );
        let err = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        )
        .unwrap_err();
        // Either ProposedUpdateMismatch (caught in match_parameters)
        // or MatchValidationSettings (caught at step 7) — both are
        // valid rejection paths for this scenario.
        assert!(
            matches!(
                err,
                ExtensionValidationError::ProposedUpdateMismatch
                    | ExtensionValidationError::MatchValidationSettings { .. }
            ),
            "expected proposed_update or settings mismatch; got {err:?}"
        );
    }

    #[test]
    fn soft_fork_vote_byte_120_lifts_fork_vote_flag() {
        let mut prev_active = scala_launch();
        prev_active.epoch_start_height = 1024;
        let prev_settings = ErgoValidationSettings::empty();
        // 120 in header.votes — at this height with no prior soft-fork
        // start, trigger 3 fires: starts new voting. computed gets
        // (122, 2048) and (121, 0) added in extras.
        let header = make_header(2048, 1, [120, 0, 0]);
        // For successful exMatchParameters60: extension must include
        // those (122, 2048) + (121, 0) entries.
        let mut p = scala_launch();
        p.epoch_start_height = 2048;
        p.block_version = 1;
        let mut fields = vec![
            field_of(1, p.storage_fee_factor),
            field_of(2, p.min_value_per_byte),
            field_of(3, p.max_block_size),
            field_of(4, p.max_block_cost),
            field_of(5, p.token_access_cost),
            field_of(6, p.input_cost),
            field_of(7, p.data_input_cost),
            field_of(8, p.output_cost),
            field_of(123, p.block_version as i32),
            field_of(121, 0),
            field_of(122, 2048),
        ];
        fields.push(ExtensionField {
            key: [0x00, 124],
            value: ErgoValidationSettingsUpdate::empty().serialize(),
        });
        let extension = Extension {
            header_id: ModifierId::from_bytes([0u8; 32]),
            fields,
        };
        let outcome = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        );
        assert!(
            outcome.is_ok(),
            "fork-vote at non-genesis epoch should populate state: {outcome:?}"
        );
        let _ = write_extension; // silence unused-import warning
    }

    // ----- mode 2 install trust path -----

    /// Build the genesis-bypass scenario: prev_settings = launch
    /// defaults, prev_active = scala_launch, and an extension that
    /// carries an arbitrary `claimed_cumulative` via the (0x02, *)
    /// validation-rules block. Used by the trust-mode tests below to
    /// model what happens at the first post-snapshot epoch boundary.
    fn first_post_install_extension(
        claimed_cumulative: &ErgoValidationSettingsUpdate,
    ) -> (Header, Extension) {
        // Pick height 1024 so the genesis-era bypass fires
        // (prev_active.epoch_start_height == 0 below). 1024 is the
        // smallest valid epoch-start that exercises the same path
        // taken by Mode 2 at h = snapshot_height + 1.
        let header = make_header(1024, 1, [0u8; 3]);
        // Extension matches scala_launch params exactly so
        // exMatchParameters60 doesn't fire on a numeric field.
        let extension = launch_extension_with_settings(
            1024,
            1,
            &ErgoValidationSettingsUpdate::empty(),
            Some(claimed_cumulative),
        );
        (header, extension)
    }

    #[test]
    fn trust_mode_off_rejects_cumulative_mismatch_with_diagnostic_payload() {
        // Without trust mode: a non-empty cumulative in the extension
        // disagrees with prev(empty).updated(activated_update=empty
        // from no-vote recompute) and surfaces with the full diff in
        // the error payload. We avoid the genesis-era bypass
        // (epoch_start_height == 0) so the recompute path actually
        // runs — the bypass would trivially accept whatever cumulative
        // the extension carries.
        let mut prev_active = scala_launch();
        prev_active.epoch_start_height = 1;
        let prev_settings = ErgoValidationSettings::empty();
        let pre_snapshot_cumulative = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![215, 409],
            status_updates: vec![(
                1007,
                crate::voting::validation_settings::RuleStatus::Replaced(1017),
            )],
        };
        let (header, extension) = first_post_install_extension(&pre_snapshot_cumulative);
        let err = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        )
        .unwrap_err();
        match err {
            ExtensionValidationError::MatchValidationSettings {
                height,
                parsed_disabled,
                computed_disabled,
                parsed_status_n,
                computed_status_n,
            } => {
                assert_eq!(height, 1024);
                assert_eq!(parsed_disabled, vec![215, 409]);
                assert!(computed_disabled.is_empty());
                assert_eq!(parsed_status_n, 1);
                assert_eq!(computed_status_n, 0);
            }
            other => panic!("expected MatchValidationSettings, got {other:?}"),
        }
    }

    #[test]
    fn trust_mode_on_accepts_cumulative_mismatch_and_returns_parsed() {
        // With trust mode armed (Mode 2 install): the same mismatch is
        // accepted, and `outcome.next_settings.update_from_initial` is
        // the parsed cumulative — that's what the cache will be
        // overwritten with after apply_block in block_proc.rs. As in
        // the rejection test, we step prev_active.epoch_start_height
        // off zero so the recompute path runs.
        let mut prev_active = scala_launch();
        prev_active.epoch_start_height = 1;
        let prev_settings = ErgoValidationSettings::empty();
        let pre_snapshot_cumulative = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![215, 409],
            status_updates: vec![
                (
                    1007,
                    crate::voting::validation_settings::RuleStatus::Replaced(1017),
                ),
                (
                    1008,
                    crate::voting::validation_settings::RuleStatus::Replaced(1018),
                ),
                (
                    1011,
                    crate::voting::validation_settings::RuleStatus::Replaced(1016),
                ),
            ],
        };
        let (header, extension) = first_post_install_extension(&pre_snapshot_cumulative);
        let outcome = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            true,
        )
        .unwrap();
        assert_eq!(
            outcome.next_settings.update_from_initial, pre_snapshot_cumulative,
            "trust path must seed next_settings.update_from_initial from the parsed cumulative",
        );
        // activated_update is still the genesis-bypass value
        // (parsed.proposed_update), independent of the trust path.
        assert_eq!(
            outcome.activated_update,
            ErgoValidationSettingsUpdate::empty(),
        );
    }

    #[test]
    fn trust_mode_on_with_nonempty_prev_settings_falls_through_to_strict_reject() {
        // Stricter trust gate: even when `trust_extension_settings=true`,
        // if `prev_settings` is non-empty (post-first-trust state, or
        // any normally-synced node) the trust path is bypassed and the
        // strict equality check applies. Bounds the bypass to the
        // genuinely-uninformed launch-defaults state and prevents a
        // stale on-disk trust flag from accepting divergent extensions
        // at later epoch boundaries.
        let mut prev_active = scala_launch();
        prev_active.epoch_start_height = 1024;
        // Non-empty prev_settings — the kind of state every normally-
        // synced node holds.
        let prev_settings =
            ErgoValidationSettings::empty().updated(&ErgoValidationSettingsUpdate {
                rules_to_disable: vec![409],
                status_updates: vec![],
            });
        let header = make_header(2048, 1, [0u8; 3]);
        let divergent_cumulative = ErgoValidationSettingsUpdate {
            rules_to_disable: vec![215, 409, 410],
            status_updates: vec![],
        };
        let extension = launch_extension_with_settings(
            2048,
            1,
            &ErgoValidationSettingsUpdate::empty(),
            Some(&divergent_cumulative),
        );
        let err = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            true, // trust armed but gate should keep it closed
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionValidationError::MatchValidationSettings { .. }
        ));
    }

    #[test]
    fn trust_mode_on_matching_cumulative_falls_through_to_strict_path() {
        // Trust mode is a one-way relaxation — when parsed/computed
        // already match, behavior is identical to trust-off (no log,
        // no override). Pins that the trust path doesn't accidentally
        // mutate the strict-equality result.
        let prev_active = scala_launch();
        let prev_settings = ErgoValidationSettings::empty();
        let (header, extension) =
            first_post_install_extension(&ErgoValidationSettingsUpdate::empty());
        let strict = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            false,
        )
        .unwrap();
        let trusted = validate_epoch_extension(
            &extension,
            &header,
            &prev_active,
            &prev_settings,
            &[],
            &VotingSettings::mainnet(),
            true,
        )
        .unwrap();
        assert_eq!(strict.next_settings, trusted.next_settings);
        assert_eq!(strict.activated_update, trusted.activated_update);
    }
}

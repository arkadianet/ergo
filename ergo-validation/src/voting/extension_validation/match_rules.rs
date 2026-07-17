use crate::active_params::ActiveProtocolParameters;

use super::ExtensionValidationError;

/// `Parameters.matchParameters(parsed, computed)`
/// (`Parameters.scala:399-413`). Rule 409: same height, same
/// proposedUpdate, same size, same per-key values.
pub(super) fn match_parameters(
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
pub(super) fn match_parameters_60(
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

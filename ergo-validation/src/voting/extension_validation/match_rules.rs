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
    // subblocks (id 9): enforce only when the PARSED extension actually
    // carries it — mirroring the `extra` handling below and rule 414's
    // `parsed.size <= computed.size` subset contract. A computed-only
    // subblocks (parsed None, computed Some) is a legitimate subset
    // omission that rule 414 must accept (v6.0 injects id 9 while a
    // parsed extension may omit it). Rule 409 stays strict: when
    // subblocks presence differs, `field_count` differs, so 409's
    // size-equality gate rejects that case before this runs — this
    // relaxation is a provable no-op for 409.
    if let Some(parsed_sub) = parsed.subblocks_per_block {
        if computed.subblocks_per_block != Some(parsed_sub) {
            let c = computed.subblocks_per_block.unwrap_or(-1) as i64;
            return Err(mk_err("subblocks_per_block", parsed_sub as i64, c));
        }
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

    fn params_at(height: u32, subblocks: Option<i32>) -> ActiveProtocolParameters {
        let mut p = scala_launch();
        p.epoch_start_height = height;
        p.subblocks_per_block = subblocks;
        p
    }

    #[test]
    fn rule_414_accepts_computed_only_subblocks() {
        // Rule 414 (`matchParameters60`) allows `parsed.size <= computed.size`:
        // a parsed extension that omits subblocks (id 9) while computed
        // injected it (v6.0 / block-v4) is a legitimate subset omission and
        // must be accepted.
        let parsed = params_at(2048, None);
        let computed = params_at(2048, Some(30));
        assert!(
            match_parameters_60(&parsed, &computed).is_ok(),
            "rule 414 must accept computed-only subblocks (subset omission)",
        );
    }

    #[test]
    fn rule_409_rejects_computed_only_subblocks() {
        // Rule 409 (`matchParameters`) requires exact equality: the same
        // computed-only subblocks is a size mismatch and must reject (via the
        // size-equality gate, before the per-field walk).
        let parsed = params_at(2048, None);
        let computed = params_at(2048, Some(30));
        let err = match_parameters(&parsed, &computed).unwrap_err();
        assert!(
            matches!(err, ExtensionValidationError::MatchParametersSize { .. }),
            "rule 409 must reject computed-only subblocks via the size gate, got {err:?}",
        );
    }

    #[test]
    fn rule_414_still_rejects_differing_subblocks_value() {
        // The 414 relaxation is subset-only, not value-blind: when BOTH sides
        // carry subblocks but the values differ, 414 must still reject.
        let parsed = params_at(2048, Some(10));
        let computed = params_at(2048, Some(30));
        let err = match_parameters_60(&parsed, &computed).unwrap_err();
        assert!(
            matches!(
                err,
                ExtensionValidationError::MatchParameters60 {
                    field: "subblocks_per_block",
                    ..
                }
            ),
            "rule 414 must reject a differing subblocks value, got {err:?}",
        );
    }

    #[test]
    fn both_rules_accept_matching_subblocks() {
        // Regression guard: when parsed and computed agree (both Some, equal;
        // or both None) neither rule is affected by the relaxation.
        let a = params_at(2048, Some(30));
        let b = params_at(2048, Some(30));
        assert!(match_parameters(&a, &b).is_ok());
        assert!(match_parameters_60(&a, &b).is_ok());
        let c = params_at(2048, None);
        let d = params_at(2048, None);
        assert!(match_parameters(&c, &d).is_ok());
        assert!(match_parameters_60(&c, &d).is_ok());
    }
}

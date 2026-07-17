use ergo_ser::extension::Extension;

use super::{
    ids, ActiveParamsError, ActiveProtocolParameters, SOFT_FORK_DISABLING_RULES_ID,
    SYSTEM_PARAMETERS_PREFIX,
};
use crate::voting::validation_settings::ErgoValidationSettingsUpdate;

/// Parse the active protocol parameter set from a block's extension at
/// an epoch-start height.
///
/// Mirrors Scala `Parameters.parseExtension` (`Parameters.scala:372-390`):
/// numeric params from `key[0] == 0x00 && key[1] != 124` (4-byte BE
/// int values); `proposed_update` from `key == (0x00, 124)` decoded as
/// `ErgoValidationSettingsUpdate`. Rejects an empty map.
pub fn parse_active_params(
    extension: &Extension,
    epoch_start_height: u32,
) -> Result<ActiveProtocolParameters, ActiveParamsError> {
    let mut by_id: std::collections::BTreeMap<u8, i32> = std::collections::BTreeMap::new();
    let mut proposed_update = ErgoValidationSettingsUpdate::empty();
    let mut saw_proposed_update = false;

    for field in &extension.fields {
        if field.key[0] != SYSTEM_PARAMETERS_PREFIX {
            continue;
        }
        let id = field.key[1];
        if id == SOFT_FORK_DISABLING_RULES_ID {
            // Scala `Parameters.parseExtension` decodes this via
            // `ErgoValidationSettingsUpdateSerializer.parseBytesTry`
            // and silently uses `empty` on parse failure
            // (`Parameters.scala:382-387`). We surface the parse
            // error instead — this is consensus state.
            if saw_proposed_update {
                return Err(ActiveParamsError::DuplicateId(id));
            }
            saw_proposed_update = true;
            proposed_update = ErgoValidationSettingsUpdate::deserialize(&field.value)?;
            continue;
        }
        if field.value.len() != 4 {
            return Err(ActiveParamsError::BadValueLength(id, field.value.len()));
        }
        let v = i32::from_be_bytes(
            field.value[..]
                .try_into()
                .expect("len == 4 verified by the BadValueLength guard above"),
        );
        if by_id.insert(id, v).is_some() {
            return Err(ActiveParamsError::DuplicateId(id));
        }
    }

    if by_id.is_empty() {
        return Err(ActiveParamsError::EmptyMap);
    }

    let take_required = |m: &mut std::collections::BTreeMap<u8, i32>, id: u8| {
        m.remove(&id).ok_or(ActiveParamsError::MissingRequired(id))
    };
    // Non-negativity-constrained fields: parser fail-closes so
    // `ProtocolParams::from_active` stays infallible. Scala emits only
    // non-negative values for these ids; a negative here can only come
    // from storage corruption or a producer bug.
    let take_required_nonneg = |m: &mut std::collections::BTreeMap<u8, i32>, id: u8| {
        let v = m
            .remove(&id)
            .ok_or(ActiveParamsError::MissingRequired(id))?;
        if v < 0 {
            return Err(ActiveParamsError::NegativeProtocolParam { id, value: v });
        }
        Ok(v)
    };

    let storage_fee_factor = take_required_nonneg(&mut by_id, ids::STORAGE_FEE_FACTOR)?;
    let min_value_per_byte = take_required_nonneg(&mut by_id, ids::MIN_VALUE_PER_BYTE)?;
    let max_block_size = take_required_nonneg(&mut by_id, ids::MAX_BLOCK_SIZE)?;
    let max_block_cost = take_required_nonneg(&mut by_id, ids::MAX_BLOCK_COST)?;
    let token_access_cost = take_required_nonneg(&mut by_id, ids::TOKEN_ACCESS_COST)?;
    let input_cost = take_required_nonneg(&mut by_id, ids::INPUT_COST)?;
    let data_input_cost = take_required_nonneg(&mut by_id, ids::DATA_INPUT_COST)?;
    let output_cost = take_required_nonneg(&mut by_id, ids::OUTPUT_COST)?;
    let block_version_i32 = take_required(&mut by_id, ids::BLOCK_VERSION)?;
    let subblocks_per_block = by_id.remove(&ids::SUBBLOCKS_PER_BLOCK);

    let extra: Vec<(u8, i32)> = by_id.into_iter().collect();

    Ok(ActiveProtocolParameters {
        epoch_start_height,
        block_version: block_version_i32 as u8,
        storage_fee_factor,
        min_value_per_byte,
        max_block_size,
        max_block_cost,
        token_access_cost,
        input_cost,
        data_input_cost,
        output_cost,
        subblocks_per_block,
        extra,
        proposed_update,
        // The state machine sets this; parser leaves it empty.
        activated_update: ErgoValidationSettingsUpdate::empty(),
    })
}

/// Serialize an active parameter set into its block-extension fields — the
/// exact inverse of [`parse_active_params`], mirroring Scala
/// `Parameters.toExtensionCandidate` (`Parameters.scala:351-370`).
///
/// Emits, with the [`SYSTEM_PARAMETERS_PREFIX`] (`0x00`) prefix:
/// * the eight required numeric params (ids 1..=8) and `block_version`
///   (id 123) as 4-byte big-endian `i32`;
/// * `subblocks_per_block` (id 9) when present (post-EIP37 epochs);
/// * every `extra` `(id, value)` pair (e.g. soft-fork state ids 121/122);
/// * `proposed_update` at id 124 ([`SOFT_FORK_DISABLING_RULES_ID`]) as a
///   serialized `ErgoValidationSettingsUpdate` — ALWAYS present, even when
///   empty (`0x0000`), matching Scala.
///
/// Fields are emitted in a fixed, deterministic order (ids 1..=8, 9, 123,
/// extras ascending, 124) so two builds of the same epoch produce byte-
/// identical extensions (required for the off-loop/on-loop candidate parity).
/// Field order does not affect consensus validity — peers re-parse the set
/// order-independently — but determinism is required for the parity guarantee.
pub fn active_params_to_extension_fields(
    params: &ActiveProtocolParameters,
) -> Vec<([u8; 2], Vec<u8>)> {
    let p = SYSTEM_PARAMETERS_PREFIX;
    let be = |v: i32| v.to_be_bytes().to_vec();
    let mut out: Vec<([u8; 2], Vec<u8>)> = vec![
        ([p, ids::STORAGE_FEE_FACTOR], be(params.storage_fee_factor)),
        ([p, ids::MIN_VALUE_PER_BYTE], be(params.min_value_per_byte)),
        ([p, ids::MAX_BLOCK_SIZE], be(params.max_block_size)),
        ([p, ids::MAX_BLOCK_COST], be(params.max_block_cost)),
        ([p, ids::TOKEN_ACCESS_COST], be(params.token_access_cost)),
        ([p, ids::INPUT_COST], be(params.input_cost)),
        ([p, ids::DATA_INPUT_COST], be(params.data_input_cost)),
        ([p, ids::OUTPUT_COST], be(params.output_cost)),
    ];
    if let Some(v) = params.subblocks_per_block {
        out.push(([p, ids::SUBBLOCKS_PER_BLOCK], be(v)));
    }
    out.push(([p, ids::BLOCK_VERSION], be(params.block_version as i32)));
    // `extra` carries non-numeric-but-i32 keys the parser preserved (soft-fork
    // state 121/122, any forward-compatible ids). Ascending for determinism.
    let mut extras = params.extra.clone();
    extras.sort_by_key(|(id, _)| *id);
    for (id, value) in extras {
        out.push(([p, id], be(value)));
    }
    out.push((
        [p, SOFT_FORK_DISABLING_RULES_ID],
        params.proposed_update.serialize(),
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::extension::ExtensionField;

    fn ext_with(fields: Vec<([u8; 2], Vec<u8>)>) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes([0u8; 32]),
            fields: fields
                .into_iter()
                .map(|(k, v)| ExtensionField { key: k, value: v })
                .collect(),
        }
    }

    fn be_i32(v: i32) -> Vec<u8> {
        v.to_be_bytes().to_vec()
    }

    fn full_required_set() -> Vec<([u8; 2], Vec<u8>)> {
        vec![
            ([0x00, 1], be_i32(1_250_000)),
            ([0x00, 2], be_i32(360)),
            ([0x00, 3], be_i32(524_288)),
            ([0x00, 4], be_i32(1_000_000)),
            ([0x00, 5], be_i32(100)),
            ([0x00, 6], be_i32(2_000)),
            ([0x00, 7], be_i32(100)),
            ([0x00, 8], be_i32(100)),
            ([0x00, 123], be_i32(1)),
        ]
    }

    #[test]
    fn parse_required_only() {
        let ext = ext_with(full_required_set());
        let p = parse_active_params(&ext, 1024).unwrap();
        assert_eq!(p.epoch_start_height, 1024);
        assert_eq!(p.block_version, 1);
        assert_eq!(p.storage_fee_factor, 1_250_000);
        assert_eq!(p.min_value_per_byte, 360);
        assert_eq!(p.max_block_size, 524_288);
        assert_eq!(p.max_block_cost, 1_000_000);
        assert_eq!(p.token_access_cost, 100);
        assert_eq!(p.input_cost, 2_000);
        assert_eq!(p.data_input_cost, 100);
        assert_eq!(p.output_cost, 100);
        assert!(p.subblocks_per_block.is_none());
        assert!(p.extra.is_empty());
    }

    #[test]
    fn parse_with_subblocks_post_eip37() {
        let mut fields = full_required_set();
        fields.push(([0x00, 9], be_i32(30)));
        let p = parse_active_params(&ext_with(fields), 1_772_544).unwrap();
        assert_eq!(p.subblocks_per_block, Some(30));
    }

    #[test]
    fn parse_lifts_softfork_disabling_rules_into_proposed_update() {
        // Key (0x00, 124) is parsed as ErgoValidationSettingsUpdate
        // rather than filtered. An empty update (0x00 0x00 → 0
        // disabled_rules + 0 status_updates) round-trips to
        // `proposed_update == empty`.
        let mut fields = full_required_set();
        fields.push(([0x00, 124], vec![0x00, 0x00]));
        let p = parse_active_params(&ext_with(fields), 1024).unwrap();
        assert!(p.extra.is_empty());
        assert_eq!(
            p.proposed_update,
            crate::voting::validation_settings::ErgoValidationSettingsUpdate::empty()
        );
    }

    #[test]
    fn parse_lifts_rule_409_disabled_into_proposed_update() {
        let mut fields = full_required_set();
        let update = crate::voting::validation_settings::ErgoValidationSettingsUpdate {
            rules_to_disable: vec![409],
            status_updates: vec![],
        };
        fields.push(([0x00, 124], update.serialize()));
        let p = parse_active_params(&ext_with(fields), 1024).unwrap();
        assert!(p.proposed_update.rules_to_disable.contains(&409));
    }

    #[test]
    fn parse_rejects_malformed_softfork_disabling_rules_value() {
        let mut fields = full_required_set();
        // Bytes that don't decode as ErgoValidationSettingsUpdate
        // (continuation bit set without termination).
        fields.push(([0x00, 124], vec![0xCA, 0xFE]));
        let err = parse_active_params(&ext_with(fields), 1024).unwrap_err();
        assert!(matches!(err, ActiveParamsError::ValidationSettings(_)));
    }

    #[test]
    fn parse_preserves_softfork_voting_keys_as_extra() {
        let mut fields = full_required_set();
        fields.push(([0x00, 120], be_i32(7))); // SoftFork
        fields.push(([0x00, 121], be_i32(42))); // SoftForkVotesCollected
        fields.push(([0x00, 122], be_i32(900_000))); // SoftForkStartingHeight
        let p = parse_active_params(&ext_with(fields), 700_416).unwrap();
        assert_eq!(p.extra, vec![(120, 7), (121, 42), (122, 900_000)]);
    }

    #[test]
    fn parse_ignores_non_system_prefix() {
        let mut fields = full_required_set();
        fields.push(([0x01, 1], be_i32(99))); // wrong prefix → not a param
        let p = parse_active_params(&ext_with(fields), 1024).unwrap();
        assert!(p.extra.is_empty());
    }

    #[test]
    fn parse_rejects_bad_value_length() {
        let mut fields = full_required_set();
        // Replace storage_fee_factor with a 3-byte value
        fields[0] = ([0x00, 1], vec![0x00, 0x01, 0x02]);
        let err = parse_active_params(&ext_with(fields), 1024).unwrap_err();
        assert_eq!(err, ActiveParamsError::BadValueLength(1, 3));
    }

    #[test]
    fn parse_rejects_duplicate_id() {
        let mut fields = full_required_set();
        fields.push(([0x00, 1], be_i32(99)));
        let err = parse_active_params(&ext_with(fields), 1024).unwrap_err();
        assert_eq!(err, ActiveParamsError::DuplicateId(1));
    }

    #[test]
    fn parse_rejects_missing_required() {
        let mut fields = full_required_set();
        fields.remove(0); // drop storage_fee_factor (id=1)
        let err = parse_active_params(&ext_with(fields), 1024).unwrap_err();
        assert_eq!(err, ActiveParamsError::MissingRequired(1));
    }

    #[test]
    fn parse_rejects_empty_map() {
        let ext = ext_with(vec![]);
        let err = parse_active_params(&ext, 1024).unwrap_err();
        assert_eq!(err, ActiveParamsError::EmptyMap);
    }

    #[test]
    fn parse_active_params_rejects_negative_cost_bearing_param() {
        // Same shape but on the extension-parse path: a `(0x00, id=6)`
        // entry whose 4-byte BE value is negative must be rejected at
        // the parse boundary, not silently widened to a u64 downstream.
        let mut fields = full_required_set();
        for (key, value) in fields.iter_mut() {
            if *key == [SYSTEM_PARAMETERS_PREFIX, ids::INPUT_COST] {
                *value = (-7i32).to_be_bytes().to_vec();
            }
        }
        let ext = ext_with(fields);
        let err = parse_active_params(&ext, 1024).unwrap_err();
        assert_eq!(
            err,
            ActiveParamsError::NegativeProtocolParam {
                id: ids::INPUT_COST,
                value: -7
            },
        );
    }

    #[test]
    fn parse_truncates_block_version_to_low_byte_matching_scala() {
        // Scala stores Int but reduces to .toByte; mirror that on parse.
        let mut fields = full_required_set();
        // Replace block_version entry with 0x00000102 — low byte = 2
        fields.last_mut().unwrap().1 = be_i32(0x0000_0102);
        let p = parse_active_params(&ext_with(fields), 1024).unwrap();
        assert_eq!(p.block_version, 2);
    }

    /// Real Scala-validated epoch-start fixture.
    ///
    /// Block 417792 (epoch 408 * 1024) lives in
    /// `test-vectors/mainnet/blocks_417785_417800.json`. Its extension
    /// carries the parameter set Scala reports for that epoch.
    /// Hand-decoded values from the fixture's hex blobs:
    /// - id 1 (storage_fee_factor) = 0x001312D0 = 1_250_000
    /// - id 2 (min_value_per_byte) = 0x00000168 =       360
    /// - id 3 (max_block_size)     = 0x001364E1 = 1_271_009
    /// - id 4 (max_block_cost)     = 0x0048C570 = 4_769_136
    /// - id 5 (token_access_cost)  = 0x00000064 =       100
    /// - id 6 (input_cost)         = 0x000007D0 =     2_000
    /// - id 7 (data_input_cost)    = 0x00000064 =       100
    /// - id 8 (output_cost)        = 0x00000064 =       100
    /// - id 123 (block_version)    = 0x00000002 =         2
    /// - id 124 (validation-settings update) → filtered out (2-byte value)
    ///
    /// No id 9 (pre-EIP37). No soft-fork voting keys (120-122).
    #[test]
    fn parse_real_fixture_block_417792() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test-vectors/mainnet/blocks_417785_417800.json"
        ))
        .expect("missing test fixture; rerun cost-vector extraction");
        let blocks: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let block = blocks
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["height"].as_u64() == Some(417_792))
            .expect("block 417792 not in fixture");

        let mut fields: Vec<ExtensionField> = Vec::new();
        for f in block["extension"]["fields"].as_array().unwrap() {
            let key_hex = f[0].as_str().unwrap();
            let val_hex = f[1].as_str().unwrap();
            let key_bytes = hex::decode(key_hex).unwrap();
            let value = hex::decode(val_hex).unwrap();
            fields.push(ExtensionField {
                key: [key_bytes[0], key_bytes[1]],
                value,
            });
        }
        let ext = Extension {
            header_id: ModifierId::from_bytes([0u8; 32]),
            fields,
        };

        let p = parse_active_params(&ext, 417_792).unwrap();

        assert_eq!(p.epoch_start_height, 417_792);
        assert_eq!(p.storage_fee_factor, 1_250_000);
        assert_eq!(p.min_value_per_byte, 360);
        assert_eq!(p.max_block_size, 1_271_009);
        assert_eq!(p.max_block_cost, 4_769_136);
        assert_eq!(p.token_access_cost, 100);
        assert_eq!(p.input_cost, 2_000);
        assert_eq!(p.data_input_cost, 100);
        assert_eq!(p.output_cost, 100);
        assert_eq!(p.block_version, 2);
        assert!(p.subblocks_per_block.is_none());
        assert!(
            p.extra.is_empty(),
            "expected no soft-fork voting keys at h=417792, got {:?}",
            p.extra
        );

        // Round-trip through our codec.
        let bytes = p.serialize().unwrap();
        let back = ActiveProtocolParameters::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }
}

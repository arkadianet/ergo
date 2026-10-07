//! Extension settings encoded by ergo-core 6.0.7.
use ergo_validation::voting::validation_settings::{
    validation_settings_update_to_extension_fields, ErgoValidationSettingsUpdate,
};

#[derive(serde::Deserialize)]
struct Field {
    key: String,
    value: String,
}
#[derive(serde::Deserialize)]
struct ChunkCase {
    size: usize,
    update: String,
    fields: Vec<Field>,
}
#[derive(serde::Deserialize)]
struct Oracle {
    chunks: Vec<ChunkCase>,
    statuses: Vec<StatusCase>,
    disableable: Vec<u16>,
    initial_sigma_ids: Vec<u16>,
    soft_fork_1016: bool,
    core_soft_fork_1016: bool,
}

#[test]
fn settings_extension_chunks_match_reference() {
    let oracle: Oracle = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/validation-settings/settings.json"
    ))
    .unwrap();
    for case in oracle.chunks {
        let update =
            ErgoValidationSettingsUpdate::deserialize(&hex::decode(case.update).unwrap()).unwrap();
        let expected: Vec<([u8; 2], Vec<u8>)> = case
            .fields
            .into_iter()
            .map(|f| {
                (
                    hex::decode(f.key).unwrap().try_into().unwrap(),
                    hex::decode(f.value).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            validation_settings_update_to_extension_fields(&update),
            expected,
            "serialized size {}",
            case.size
        );
    }
}

#[derive(serde::Deserialize)]
struct StatusCase {
    id: u16,
    update: String,
    update_accept: bool,
    settings_accept: bool,
}

#[test]
fn cumulative_sigma_status_ids_match_reference() {
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::extension::{Extension, ExtensionField};
    use ergo_validation::voting::validation_settings::parse_validation_settings_update;
    let oracle: Oracle = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/validation-settings/settings.json"
    ))
    .unwrap();
    let mut disagreements = vec![];
    for case in oracle.statuses {
        let bytes = hex::decode(&case.update).unwrap();
        assert_eq!(
            ErgoValidationSettingsUpdate::deserialize(&bytes).is_ok(),
            case.update_accept
        );
        let extension = Extension {
            header_id: ModifierId::from_bytes([0; 32]),
            fields: vec![ExtensionField {
                key: [2, 0],
                value: bytes,
            }],
        };
        let accepted = parse_validation_settings_update(&extension).is_ok();
        println!(
            "sigma status {}: Rust={} JVM={}",
            case.id, accepted, case.settings_accept
        );
        if accepted != case.settings_accept {
            disagreements.push(case.id);
        }
    }
    assert!(
        disagreements.is_empty(),
        "status disagreements: {disagreements:?}"
    );
}

#[test]
fn registered_rules_match_reference() {
    use ergo_validation::voting::validation_settings::{DISABLEABLE_RULES, INITIAL_SIGMA_RULES};
    let oracle: Oracle = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/validation-settings/settings.json"
    ))
    .unwrap();
    assert_eq!(DISABLEABLE_RULES.as_slice(), oracle.disableable);
    assert_eq!(INITIAL_SIGMA_RULES.as_slice(), oracle.initial_sigma_ids);
    let mut settings = ergo_validation::ErgoValidationSettings::empty();
    settings.update_from_initial.rules_to_disable =
        DISABLEABLE_RULES.into_iter().chain([414, 999]).collect();
    for id in DISABLEABLE_RULES {
        assert!(settings.is_rule_disabled(id));
    }
    for id in [403, 414, 999] {
        assert!(!settings.is_rule_disabled(id));
    }
    let status = ergo_sigma::evaluator::SigmaValidationSettings(
        [(1016, ergo_sigma::evaluator::RuleStatus::Replaced(1000))].into(),
    );
    assert_eq!(
        ergo_sigma::evaluator::SigmaValidationSettings::default().is_soft_fork(1016, &[], 3),
        oracle.soft_fork_1016
    );
    assert_eq!(
        status.is_soft_fork(1016, &[], 3),
        oracle.core_soft_fork_1016
    );
}

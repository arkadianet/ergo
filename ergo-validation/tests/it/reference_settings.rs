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

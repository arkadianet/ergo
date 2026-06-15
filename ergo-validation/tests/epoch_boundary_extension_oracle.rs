//! Oracle parity for the epoch-boundary extension SERIALIZERS.
//!
//! The candidate builder must reproduce, byte-for-byte, the `0x00`
//! (system-parameter) and `0x02` (validation-settings) extension fields that
//! real mainnet epoch-boundary blocks carry — otherwise a block this node mines
//! would be rejected by peers. The fixtures are real mainnet epoch-start blocks
//! (`height % 1024 == 0`) captured from a synced node:
//!
//!   * h=1499136 (block-version 3): params + empty proposed-update, no `0x02`.
//!   * h=1806336 (block-version 4): params incl. subblocksPerBlock, a non-empty
//!     proposed-update, and a non-empty cumulative validation-settings block.
//!
//! The serializers are the exact inverse of `parse_active_params` /
//! `parse_validation_settings_update`, so the test parses each real extension,
//! re-serializes, and asserts the produced `0x00`/`0x02` field set matches the
//! real one key-for-key (order-independent — the extension Merkle root is over
//! whatever order the miner emits, and peers re-parse order-independently).

use std::collections::BTreeMap;

use ergo_primitives::digest::ModifierId;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_validation::active_params::{active_params_to_extension_fields, parse_active_params};
use ergo_validation::voting::validation_settings::{
    parse_validation_settings_update, validation_settings_update_to_extension_fields,
};
use serde_json::Value;

fn load_fixtures() -> Vec<Value> {
    // Anchor to the crate dir so the fixture loads regardless of the test
    // runner's cwd (matches the repo's other vector-loading tests).
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-vectors/mainnet/epoch_boundary_extensions.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    serde_json::from_str(&text).expect("parse fixture json")
}

fn ext_from_fields(fields: &[([u8; 2], Vec<u8>)]) -> Extension {
    Extension {
        header_id: ModifierId::from_bytes([0u8; 32]),
        fields: fields
            .iter()
            .map(|(k, v)| ExtensionField {
                key: *k,
                value: v.clone(),
            })
            .collect(),
    }
}

/// Real extension system fields (every non-interlinks entry) as `(key, value)`
/// byte pairs.
fn real_system_fields(entry: &Value) -> Vec<([u8; 2], Vec<u8>)> {
    entry["system_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let arr = f.as_array().unwrap();
            let key = hex::decode(arr[0].as_str().unwrap()).unwrap();
            (
                <[u8; 2]>::try_from(key.as_slice()).expect("2-byte key"),
                hex::decode(arr[1].as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

/// Subset of `fields` whose key prefix is `prefix`, as a key→value map.
fn fields_with_prefix(fields: &[([u8; 2], Vec<u8>)], prefix: u8) -> BTreeMap<[u8; 2], Vec<u8>> {
    fields
        .iter()
        .filter(|(k, _)| k[0] == prefix)
        .map(|(k, v)| (*k, v.clone()))
        .collect()
}

#[test]
fn active_params_serializer_reproduces_real_mainnet_param_fields() {
    for entry in load_fixtures() {
        let height = entry["height"].as_u64().unwrap() as u32;
        let real = real_system_fields(&entry);
        let parsed = parse_active_params(&ext_from_fields(&real), height)
            .unwrap_or_else(|e| panic!("parse real params at h={height}: {e:?}"));

        let mine = active_params_to_extension_fields(&parsed);

        // The 0x00 set my serializer produces must match the real 0x00 set
        // byte-for-byte, key-for-key (order-independent).
        let real_00 = fields_with_prefix(&real, 0x00);
        let mine_00 = fields_with_prefix(&mine, 0x00);
        assert_eq!(
            mine_00, real_00,
            "0x00 param fields must match the real mainnet block at h={height}",
        );
        // My serializer must emit ONLY 0x00 fields (settings are separate).
        assert!(
            mine.iter().all(|(k, _)| k[0] == 0x00),
            "active-params serializer must emit only 0x00 fields",
        );
    }
}

#[test]
fn validation_settings_serializer_reproduces_real_mainnet_settings_fields() {
    for entry in load_fixtures() {
        let height = entry["height"].as_u64().unwrap() as u32;
        let real = real_system_fields(&entry);
        let cumulative = parse_validation_settings_update(&ext_from_fields(&real))
            .unwrap_or_else(|e| panic!("parse real settings at h={height}: {e:?}"));

        let mine = validation_settings_update_to_extension_fields(&cumulative);

        // Compare the FULL 0x02 (key, value) field set, not just the
        // concatenation: the extension Merkle root commits to each field
        // individually, so a chunk-boundary / key[1]-index divergence that
        // re-concatenates to the same bytes would still produce a different
        // `extension_root` and be rejected on-chain. Sort by key so field
        // ordering doesn't matter.
        let sys_02 = |fields: &[([u8; 2], Vec<u8>)]| -> Vec<([u8; 2], Vec<u8>)> {
            let mut v: Vec<([u8; 2], Vec<u8>)> = fields
                .iter()
                .filter(|(k, _)| k[0] == 0x02)
                .cloned()
                .collect();
            v.sort_by_key(|(k, _)| *k);
            v
        };
        assert_eq!(
            sys_02(&mine),
            sys_02(&real),
            "0x02 settings (key, value) fields must match the real mainnet block at h={height}",
        );
        // Round-trip: my fields re-parse to the same cumulative update.
        let reparsed = parse_validation_settings_update(&ext_from_fields(&mine)).unwrap();
        assert_eq!(reparsed, cumulative, "settings round-trip at h={height}");
    }
}

#[test]
fn full_extension_fields_round_trip_through_the_parsers() {
    // The combined (params + settings) serializer output must re-parse to the
    // exact same params and cumulative settings — the inverse property the
    // candidate builder relies on for the validator to accept its block.
    for entry in load_fixtures() {
        let height = entry["height"].as_u64().unwrap() as u32;
        let real = real_system_fields(&entry);
        let ext = ext_from_fields(&real);
        let params = parse_active_params(&ext, height).unwrap();
        let cumulative = parse_validation_settings_update(&ext).unwrap();

        let mut my_fields = active_params_to_extension_fields(&params);
        my_fields.extend(validation_settings_update_to_extension_fields(&cumulative));
        let my_ext = ext_from_fields(&my_fields);

        assert_eq!(
            parse_active_params(&my_ext, height).unwrap(),
            params,
            "params round-trip at h={height}",
        );
        assert_eq!(
            parse_validation_settings_update(&my_ext).unwrap(),
            cumulative,
            "settings round-trip at h={height}",
        );
    }
}

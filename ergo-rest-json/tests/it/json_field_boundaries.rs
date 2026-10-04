//! Independent evaluated-value fields retain their pinned consumed prefixes.

use std::collections::BTreeMap;

use ergo_rest_json::{decode_context_extension_with_mode, decode_registers_with_mode, DecodeMode};
use indexmap::IndexMap;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    values: Vec<ValueCase>,
}

#[derive(Deserialize)]
struct ValueCase {
    input: String,
    canonical: Option<String>,
    consumed: Option<usize>,
}

#[test]
fn independent_field_consumption_and_writes_match_every_pinned_sdk_value() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-rest-json/json-contracts/cases.json"
    ))
    .unwrap();
    assert_eq!(fixture.values.len(), 12);
    for case in fixture.values {
        let registers = BTreeMap::from([("R4".to_owned(), case.input.clone())]);
        let context = IndexMap::from([("2".to_owned(), case.input.clone())]);
        for mode in [DecodeMode::Submit, DecodeMode::Preserve] {
            let register = decode_registers_with_mode(&registers, mode);
            let extension = decode_context_extension_with_mode(&context, mode);
            assert_eq!(
                register.is_ok(),
                case.canonical.is_some(),
                "register {}",
                case.input
            );
            assert_eq!(
                extension.is_ok(),
                case.canonical.is_some(),
                "context {}",
                case.input
            );
            if let Some(canonical) = &case.canonical {
                let raw = hex::decode(&case.input).unwrap();
                let expected = match mode {
                    DecodeMode::Submit => hex::decode(canonical).unwrap(),
                    DecodeMode::Preserve => raw[..case.consumed.unwrap()].to_vec(),
                };
                let register = register.unwrap().1;
                let extension = extension.unwrap().1;
                assert_eq!(register[0], 1);
                assert_eq!(&register[1..], expected);
                assert_eq!(&extension[..2], &[1, 2]);
                assert_eq!(&extension[2..], expected);
            }
        }
    }
}

#[test]
fn individually_truncated_neighbors_cannot_borrow_bytes_from_a_valid_suffix() {
    for mode in [DecodeMode::Submit, DecodeMode::Preserve] {
        let registers = BTreeMap::from([
            ("R4".to_owned(), "010101".to_owned()),
            ("R5".to_owned(), "01".to_owned()),
        ]);
        let error = decode_registers_with_mode(&registers, mode).unwrap_err();
        assert!(error.1.contains("R5"), "{error:?}");
        let context = IndexMap::from([
            ("1".to_owned(), "010101".to_owned()),
            ("2".to_owned(), "01".to_owned()),
        ]);
        let error = decode_context_extension_with_mode(&context, mode).unwrap_err();
        assert!(error.1.contains("extension[2]"), "{error:?}");
    }
}

#[test]
fn tolerated_suffixes_cannot_replace_context_keys_or_register_values() {
    for mode in [DecodeMode::Submit, DecodeMode::Preserve] {
        let registers = BTreeMap::from([
            ("R4".to_owned(), "010101".to_owned()),
            ("R5".to_owned(), "0100".to_owned()),
        ]);
        let (_, wire) = decode_registers_with_mode(&registers, mode).unwrap();
        assert_eq!(hex::encode(wire), "0201010100");
        let context = IndexMap::from([
            ("1".to_owned(), "010101".to_owned()),
            ("2".to_owned(), "0100".to_owned()),
        ]);
        let (parsed, wire) = decode_context_extension_with_mode(&context, mode).unwrap();
        assert_eq!(parsed.values.keys().copied().collect::<Vec<_>>(), [1, 2]);
        assert_eq!(hex::encode(wire), "02010101020100");
    }
}

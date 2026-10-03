//! Exact JSON numeric domains checked against the pinned SDK decoder capture.

use ergo_rest_json::mining::{AutolykosSolutionJson, WorkMessageJson};
use ergo_rest_json::{
    decode_output_with_mode, DecodeMode, ScalaAsset, ScalaOutput, ScalaOutputInput,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    numeric: Vec<NumberCase>,
    boundaries: Vec<BoundaryCase>,
}

#[derive(Deserialize)]
struct NumberCase {
    input: String,
    bigint: Option<String>,
    long: Option<String>,
}

#[derive(Deserialize)]
struct BoundaryCase {
    input: String,
    digits: Option<usize>,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-rest-json/json-contracts/cases.json"
    ))
    .unwrap()
}

fn candidate_json(value: &str, amount: &str) -> String {
    format!(
        r#"{{"value":{value},"ergoTree":"1000d10101","assets":[{{"tokenId":"{}","amount":{amount}}}],"creationHeight":1,"additionalRegisters":{{}}}}"#,
        "00".repeat(32)
    )
}

#[test]
fn mining_bigint_fields_match_all_pinned_exact_nonnegative_values() {
    let fixture = fixture();
    assert_eq!(fixture.numeric.len(), 33);
    for case in fixture.numeric {
        let expected = case.bigint.filter(|s| !s.starts_with('-'));
        let work = serde_json::from_str::<WorkMessageJson>(&format!(
            r#"{{"msg":"aa","b":{},"pk":"bb"}}"#,
            case.input
        ));
        let solution = serde_json::from_str::<AutolykosSolutionJson>(&format!(
            r#"{{"pk":"bb","n":"cc","d":{}}}"#,
            case.input
        ));
        assert_eq!(work.is_ok(), expected.is_some(), "b: {}", case.input);
        assert_eq!(solution.is_ok(), expected.is_some(), "d: {}", case.input);
        if let Some(expected) = expected {
            assert_eq!(work.unwrap().b.to_str_radix(10), expected, "{}", case.input);
            assert_eq!(
                solution.unwrap().d.unwrap().to_str_radix(10),
                expected,
                "{}",
                case.input
            );
        }
    }
}

#[test]
fn every_output_and_asset_dto_enforces_the_nonnegative_scala_long_domain() {
    let fixture = fixture();
    assert_eq!(fixture.numeric.len(), 33);
    for case in fixture.numeric {
        let expected = case.long.filter(|s| !s.starts_with('-'));
        let candidate = candidate_json(&case.input, "1");
        let output_json = format!(
            "{},\"boxId\":\"aa\",\"transactionId\":\"bb\",\"index\":0}}",
            candidate.strip_suffix('}').unwrap()
        );
        let input = serde_json::from_str::<ScalaOutputInput>(&candidate);
        let output = serde_json::from_str::<ScalaOutput>(&output_json);
        let asset = serde_json::from_str::<ScalaAsset>(&format!(
            r#"{{"tokenId":"aa","amount":{}}}"#,
            case.input
        ));
        for (name, accepted) in [
            ("candidate", input.is_ok()),
            ("output", output.is_ok()),
            ("asset", asset.is_ok()),
        ] {
            assert_eq!(accepted, expected.is_some(), "{name}: {}", case.input);
        }
        if let Some(expected) = expected {
            let expected: u64 = expected.parse().unwrap();
            assert_eq!(input.unwrap().value, expected);
            assert_eq!(output.unwrap().value, expected);
            assert_eq!(asset.unwrap().amount, expected);
        }
    }
}

#[test]
fn programmatically_built_outputs_cannot_bypass_signed_long_conversion() {
    let mut candidate: ScalaOutputInput = serde_json::from_str(&candidate_json("1", "1")).unwrap();
    for mode in [DecodeMode::Submit, DecodeMode::Preserve] {
        for value in [i64::MAX as u64 - 1, i64::MAX as u64] {
            candidate.value = value;
            candidate.assets[0].amount = value;
            decode_output_with_mode(&candidate, mode).unwrap();
        }
        candidate.value = i64::MAX as u64 + 1;
        candidate.assets[0].amount = 1;
        assert!(decode_output_with_mode(&candidate, mode).is_err());
        candidate.value = 1;
        candidate.assets[0].amount = i64::MAX as u64 + 1;
        assert!(decode_output_with_mode(&candidate, mode).is_err());
    }
}

#[test]
fn exponent_digit_bounds_and_zero_match_the_actual_reference_decoder() {
    let fixture = fixture();
    assert_eq!(fixture.boundaries.len(), 5);
    for case in fixture.boundaries {
        let result = serde_json::from_str::<WorkMessageJson>(&format!(
            r#"{{"msg":"aa","b":{},"pk":"bb"}}"#,
            case.input
        ));
        assert_eq!(result.is_ok(), case.digits.is_some(), "{}", case.input);
        if let Some(digits) = case.digits {
            let integer = result.unwrap().b.to_str_radix(10);
            assert_eq!(integer.len(), digits);
            if case.input.starts_with("1e") {
                assert!(integer.starts_with('1'));
                assert!(integer[1..].bytes().all(|b| b == b'0'));
            } else {
                assert_eq!(integer, "0");
            }
        }
    }
}

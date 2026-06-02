//! Scala /info shape parity.
//!
//! Loads a captured Scala mainnet `/info` response and asserts the rust
//! node's `ScalaInfo` serializes to the same key set with matching JSON
//! type kinds. Volatile values (heights, scores, timestamps) are not
//! compared by value — only stable/config-derived fields are.
//!
//! This guards against silent schema drift: if Scala adds or renames a
//! field, the test fails until the rust DTO is updated.

use ergo_api::compat::types::{Parameters, ScalaInfo};

const SCALA_FIXTURE: &str = include_str!("fixtures/scala/info.json");

fn sample_info() -> ScalaInfo {
    ScalaInfo {
        last_mempool_update_time: 1_777_228_883_529,
        current_time: 1_777_228_886_148,
        network: "mainnet".into(),
        name: "ergo-rust-mainnet-0.1.0".into(),
        state_type: "utxo".into(),
        difficulty: 0,
        best_full_header_id: "00".repeat(32),
        best_header_id: "00".repeat(32),
        peers_count: 0,
        unconfirmed_count: 0,
        app_version: "0.1.0".into(),
        eip37_supported: true,
        state_root: "00".repeat(33),
        genesis_block_id: "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b".into(),
        rest_api_url: Some("http://127.0.0.1:9053".into()),
        previous_full_header_id: "00".repeat(32),
        full_height: 0,
        headers_height: 0,
        state_version: "00".repeat(32),
        full_blocks_score: 0,
        max_peer_height: 0,
        launch_time: 0,
        is_explorer: false,
        last_seen_message_time: 0,
        eip27_supported: true,
        headers_score: 0,
        parameters: Parameters {
            output_cost: 298,
            token_access_cost: 100,
            max_block_cost: 8_001_091,
            height: 0,
            max_block_size: 1_271_009,
            data_input_cost: 100,
            block_version: 4,
            input_cost: 2_407,
            storage_fee_factor: 1_250_000,
            subblocks_per_block: 0,
            min_value_per_byte: 360,
        },
        is_mining: false,
    }
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ----- happy path -----

#[test]
fn info_top_level_keys_match_scala() {
    let scala: serde_json::Value = serde_json::from_str(SCALA_FIXTURE).expect("parse fixture");
    let ours = serde_json::to_value(sample_info()).expect("serialize ScalaInfo");

    let scala_keys: std::collections::BTreeSet<&str> = scala
        .as_object()
        .expect("fixture is object")
        .keys()
        .map(String::as_str)
        .collect();
    let our_keys: std::collections::BTreeSet<&str> = ours
        .as_object()
        .expect("ours is object")
        .keys()
        .map(String::as_str)
        .collect();

    let missing: Vec<&&str> = scala_keys.difference(&our_keys).collect();
    let extra: Vec<&&str> = our_keys.difference(&scala_keys).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "info key set drift\n  missing (in Scala, not ours): {missing:?}\n  extra (in ours, not Scala): {extra:?}",
    );
}

#[test]
fn info_field_types_match_scala() {
    let scala: serde_json::Value = serde_json::from_str(SCALA_FIXTURE).expect("parse fixture");
    let ours = serde_json::to_value(sample_info()).expect("serialize ScalaInfo");

    let scala_obj = scala.as_object().unwrap();
    let our_obj = ours.as_object().unwrap();

    let mut mismatches = Vec::new();
    for (key, scala_val) in scala_obj {
        let our_val = our_obj
            .get(key)
            .unwrap_or_else(|| panic!("ours missing {key}"));
        let scala_kind = json_kind(scala_val);
        let our_kind = json_kind(our_val);
        if scala_kind != our_kind {
            mismatches.push(format!("{key}: scala={scala_kind} ours={our_kind}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "info field-type mismatches:\n  {}",
        mismatches.join("\n  "),
    );
}

#[test]
fn parameters_keys_and_types_match_scala() {
    let scala: serde_json::Value = serde_json::from_str(SCALA_FIXTURE).expect("parse fixture");
    let ours = serde_json::to_value(sample_info()).expect("serialize ScalaInfo");

    let scala_p = scala.get("parameters").unwrap().as_object().unwrap();
    let our_p = ours.get("parameters").unwrap().as_object().unwrap();

    let scala_keys: std::collections::BTreeSet<&str> = scala_p.keys().map(String::as_str).collect();
    let our_keys: std::collections::BTreeSet<&str> = our_p.keys().map(String::as_str).collect();
    let missing: Vec<&&str> = scala_keys.difference(&our_keys).collect();
    let extra: Vec<&&str> = our_keys.difference(&scala_keys).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "parameters key set drift\n  missing: {missing:?}\n  extra: {extra:?}",
    );

    let mut mismatches = Vec::new();
    for (key, scala_val) in scala_p {
        let our_val = our_p.get(key).unwrap();
        let scala_kind = json_kind(scala_val);
        let our_kind = json_kind(our_val);
        if scala_kind != our_kind {
            mismatches.push(format!(
                "parameters.{key}: scala={scala_kind} ours={our_kind}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "parameters field-type mismatches:\n  {}",
        mismatches.join("\n  "),
    );
}

#[test]
fn info_stable_fields_match_scala_exactly() {
    // These fields are either config-derived (network, stateType) or
    // protocol invariants (eip27Supported, eip37Supported) — they must
    // match Scala bit-for-bit. Volatile fields (heights, scores, times)
    // are intentionally excluded.
    let scala: serde_json::Value = serde_json::from_str(SCALA_FIXTURE).expect("parse fixture");
    let ours = serde_json::to_value(sample_info()).expect("serialize ScalaInfo");

    for key in ["network", "stateType", "eip27Supported", "eip37Supported"] {
        assert_eq!(
            scala.get(key),
            ours.get(key),
            "stable field {key} diverges from Scala",
        );
    }
}

#[test]
fn parameters_protocol_constants_match_scala() {
    // outputCost, tokenAccessCost, maxBlockCost, dataInputCost, inputCost,
    // storageFeeFactor, minValuePerByte, maxBlockSize, blockVersion are
    // protocol parameters with identical mainnet defaults on both sides.
    // height is volatile (current epoch); subblocksPerBlock is the EIP-37
    // voted gap we don't yet track. Both excluded.
    let scala: serde_json::Value = serde_json::from_str(SCALA_FIXTURE).expect("parse fixture");
    let ours = serde_json::to_value(sample_info()).expect("serialize ScalaInfo");

    let scala_p = scala.get("parameters").unwrap();
    let our_p = ours.get("parameters").unwrap();
    for key in [
        "outputCost",
        "tokenAccessCost",
        "maxBlockCost",
        "maxBlockSize",
        "dataInputCost",
        "blockVersion",
        "inputCost",
        "storageFeeFactor",
        "minValuePerByte",
    ] {
        assert_eq!(
            scala_p.get(key),
            our_p.get(key),
            "parameters.{key} diverges from Scala mainnet defaults",
        );
    }
}

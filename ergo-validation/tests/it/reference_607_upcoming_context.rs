//! Oracle: scripts/reference_evaluator_oracle/UpcomingContextOracle.scala
//! (ergo-core 6.0.7), test-vectors/reference-6.0.7/upcoming-context/.
//!
//! `TransactionContext::mempool_upcoming` and `UPCOMING_LAST_HEADERS` against
//! what Scala's mempool context (`simplifiedUpcoming()`) and a mining
//! candidate (`upcoming(...)`) expose to scripts for the block after a tip.

use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, serialize_header, Header};
use ergo_validation::{TransactionContext, UPCOMING_LAST_HEADERS};
use serde_json::Value;

// ----- helpers -----

fn cases() -> Vec<(Vec<Header>, Value)> {
    let input: Value = serde_json::from_str(include_str!(
        "../../../test-vectors/reference-6.0.7/upcoming-context/cases.json"
    ))
    .unwrap();
    let outputs: Vec<Value> =
        include_str!("../../../test-vectors/reference-6.0.7/upcoming-context/cases.jvm.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    let cases = input["cases"].as_array().unwrap();
    assert_eq!(cases.len(), outputs.len());
    cases
        .iter()
        .zip(outputs)
        .map(|(case, output)| {
            assert_eq!(case["name"], output["name"]);
            let headers = case["headers_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    let bytes = hex::decode(h.as_str().unwrap()).unwrap();
                    read_header(&mut VlqReader::new(&bytes)).unwrap()
                })
                .collect();
            (headers, output)
        })
        .collect()
}

fn heights(headers: &[Header]) -> Value {
    headers.iter().map(|h| h.height).collect::<Vec<_>>().into()
}

// ----- oracle parity -----

#[test]
fn mempool_context_matches_scala_simplified_upcoming() {
    for (headers, jvm) in cases() {
        let name = &jvm["name"];
        let tip = &headers[0];
        let (_, tip_id) = serialize_header(tip).unwrap();
        assert_eq!(hex::encode(tip_id.as_bytes()), jvm["tip_id"], "{name}");
        let expected = &jvm["mempool"];
        let context = TransactionContext::mempool_upcoming(tip, tip_id.as_bytes(), tip.version);
        assert_eq!(
            context.height,
            expected["height"].as_u64().unwrap() as u32,
            "{name}"
        );
        assert_eq!(
            hex::encode(context.pre_header_parent_id),
            expected["parent_id"],
            "{name}"
        );
        assert_eq!(
            context.pre_header_timestamp,
            expected["timestamp"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            context.pre_header_n_bits,
            expected["n_bits"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            u64::from(context.pre_header_version),
            expected["version"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(context.pre_header_votes.as_slice()),
            expected["votes"],
            "{name}"
        );
        assert_eq!(
            hex::encode(context.miner_pubkey),
            expected["miner_pk"],
            "{name}"
        );
        assert_eq!(
            heights(&headers[..UPCOMING_LAST_HEADERS]),
            expected["last_header_heights"],
            "{name}"
        );
    }
}

/// A mining candidate's transactions see the same nine newest headers.
#[test]
fn candidate_context_exposes_the_same_nine_headers() {
    for (headers, jvm) in cases() {
        assert_eq!(
            heights(&headers[..UPCOMING_LAST_HEADERS]),
            jvm["candidate"]["last_header_heights"],
            "{}",
            jvm["name"]
        );
    }
}

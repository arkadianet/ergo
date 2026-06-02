//! `SBigInt` 32-byte cap oracle parity test.
//!
//! Loads the byte vectors committed under
//! `test-vectors/scala/sigma/sbigint_cap_parity/golden_vectors.json`
//! and asserts our `ergo-ser` writer + reader match Scala's
//! `CoreDataSerializer.deserializeBigInt` cap behavior at the
//! boundary. Audit-2.md M12 / line 283.
//!
//! The bytes themselves are derived from the Scala `DataSerializer`
//! wire format spec (`putUShort` VLQ length || signed two's-complement
//! payload), not from our writer's output — asserting that our writer
//! reproduces them is the byte-level oracle proof for this phase.

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{read_value, write_value, SigmaValue};
use num_bigint::BigInt;
use serde_json::Value as JsonValue;

const VECTORS_PATH: &str = "../test-vectors/scala/sigma/sbigint_cap_parity/golden_vectors.json";

fn load_vectors() -> JsonValue {
    let raw = std::fs::read_to_string(VECTORS_PATH)
        .unwrap_or_else(|e| panic!("read {VECTORS_PATH}: {e}"));
    serde_json::from_str(&raw).expect("parse golden_vectors.json")
}

fn two_pow_255() -> BigInt {
    BigInt::from(1) << 255
}

fn bigint_for(label: &str) -> BigInt {
    match label {
        "0" => BigInt::from(0),
        "-1" => BigInt::from(-1),
        "minus_two_pow_255" => {
            let pos = two_pow_255();
            -pos
        }
        "two_pow_255_minus_one" => two_pow_255() - 1,
        "two_pow_255" => two_pow_255(),
        other => panic!("no fixture for label {other}"),
    }
}

#[test]
fn golden_round_trip_vectors_match_scala_wire_format() {
    let vectors = load_vectors();
    let arr = vectors["vectors"].as_array().expect("vectors is array");
    for v in arr {
        let label = v["value"].as_str().unwrap();
        let wire_hex = v["wire_hex"].as_str().unwrap();
        let should_rt = v["should_round_trip"].as_bool().unwrap();
        if !should_rt {
            continue;
        }
        let expected_wire = hex::decode(wire_hex)
            .unwrap_or_else(|e| panic!("hex decode for {label}: {e} (input: {wire_hex})"));
        let n = bigint_for(label);

        // Write: our bytes must match Scala-spec-derived wire bytes.
        let mut w = VlqWriter::new();
        write_value(&mut w, &SigmaType::SBigInt, &SigmaValue::BigInt(n.clone()))
            .unwrap_or_else(|e| panic!("write {label}: {e}"));
        let actual_wire = w.result();
        assert_eq!(
            actual_wire, expected_wire,
            "{label}: writer output must match Scala DataSerializer golden wire bytes"
        );

        // Read: the same bytes must decode to the same BigInt.
        let mut r = VlqReader::new(&actual_wire);
        let decoded =
            read_value(&mut r, &SigmaType::SBigInt).unwrap_or_else(|e| panic!("read {label}: {e}"));
        assert_eq!(decoded, SigmaValue::BigInt(n), "{label}: round-trip");
    }
}

#[test]
fn write_rejections_match_oracle() {
    let vectors = load_vectors();
    let arr = vectors["write_rejections"]
        .as_array()
        .expect("write_rejections is array");
    for v in arr {
        let label = v["value"].as_str().unwrap();
        let expected_sub = v["expected_error_substring"].as_str().unwrap();
        let n = bigint_for(label);
        let mut w = VlqWriter::new();
        let err = write_value(&mut w, &SigmaType::SBigInt, &SigmaValue::BigInt(n))
            .expect_err("write_rejections entries must error");
        let msg = format!("{err}");
        assert!(
            msg.contains(expected_sub),
            "{label}: expected error substring {expected_sub:?}, got {msg}"
        );
    }
}

#[test]
fn read_rejections_fire_before_payload_alloc() {
    // The `wire_hex_prefix` is the bytes the reader sees BEFORE the
    // payload — for `len=65535` (`ffff03`), no payload follows. If
    // the cap fires before `get_bytes(len)`, we see InvalidData. If
    // it fires after, we'd see UnexpectedEnd from `get_bytes`
    // overrunning EOF. The test pins the cap-fires-first ordering.
    let vectors = load_vectors();
    let arr = vectors["read_rejections"]
        .as_array()
        .expect("read_rejections is array");
    for v in arr {
        let desc = v["description"].as_str().unwrap();
        let prefix_hex = v["wire_hex_prefix"].as_str().unwrap();
        let expected_sub = v["expected_error_substring"].as_str().unwrap();
        let prefix = hex::decode(prefix_hex).unwrap_or_else(|e| panic!("{desc}: hex decode {e}"));
        let mut r = VlqReader::new(&prefix);
        let err = read_value(&mut r, &SigmaType::SBigInt).expect_err("{desc}: read must error");
        let msg = format!("{err}");
        assert!(
            msg.contains(expected_sub),
            "{desc}: expected {expected_sub:?}, got {msg}"
        );
    }
}

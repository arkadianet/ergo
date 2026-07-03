//! Round-trip oracle for `decode_scala_header`.
//!
//! Loads real mainnet header bytes from `headers_1_10.json`,
//! parses to internal `Header`, builds a `ScalaHeader` JSON DTO
//! from the parsed fields (replicating Scala's `Header.jsonEncoder`
//! shape), then decodes via `decode_scala_header` and asserts the
//! result is byte-identical to the input.
//!
//! Coverage: v1 headers (Autolykos v1 PoW solution with `w` + `d`)
//! from heights 1..=5; v2 headers (Autolykos v2, `w`/`d` ignored)
//! from `headers_700000_700010.json` or similar.
//!
//! v1 headers are the harder case — `d` is a BigInt that Scala
//! emits as a decimal-stringified JSON value. Our decoder reads
//! the string and reconstructs the big-endian length-prefixed
//! byte representation; this test pins that the round-trip is
//! lossless across the BigInt boundary.

use ergo_primitives::reader::VlqReader;
use ergo_rest_json::decode_scala_header;
use ergo_rest_json::types::{ScalaHeader, ScalaPowSolutions};
use serde::Deserialize;
use serde_json::Value as JsonValue;

#[derive(Deserialize)]
struct HeaderVec {
    height: u32,
    id: String,
    bytes: String,
}

fn fixture_path(rel: &str) -> String {
    format!(
        "{}/../test-vectors/mainnet/{}",
        env!("CARGO_MANIFEST_DIR"),
        rel
    )
}

fn load_headers(filename: &str) -> Vec<HeaderVec> {
    let raw = std::fs::read_to_string(fixture_path(filename)).unwrap();
    serde_json::from_str(&raw).unwrap()
}

/// Build a `ScalaHeader` JSON DTO from a parsed internal `Header`,
/// replicating Scala's `Header.jsonEncoder` shape exactly. This is
/// the read-side encoder logic the production bridge uses, replayed
/// here so the test is self-contained (the production encoder is
/// `pub(super)` in `ergo-node::api_bridge::compat`).
fn header_to_scala(h: &ergo_ser::header::Header, id: &str) -> ScalaHeader {
    let pow_solutions = match &h.solution {
        ergo_ser::autolykos::AutolykosSolution::V1 { pk, w, nonce, d } => ScalaPowSolutions {
            pk: hex::encode(pk.as_bytes()),
            w: hex::encode(w.as_bytes()),
            n: hex::encode(nonce),
            // v1 d: decimal-stringified BigInt (SIGNED two's-complement
            // big-endian wire form, matching the production encoder at
            // ergo-node::api_bridge::compat::encode_pow_solutions).
            d: JsonValue::String(num_bigint::BigInt::from_signed_bytes_be(d).to_string()),
        },
        ergo_ser::autolykos::AutolykosSolution::V2 { pk, nonce } => ScalaPowSolutions {
            pk: hex::encode(pk.as_bytes()),
            // Scala emits a zero-byte placeholder for w on v2; our
            // decoder ignores the field for v2 so any value is fine.
            w: "00".repeat(33),
            n: hex::encode(nonce),
            d: JsonValue::Number(0u32.into()),
        },
    };
    ScalaHeader {
        extension_id: String::new(),
        difficulty: "0".to_string(),
        votes: hex::encode(h.votes),
        timestamp: h.timestamp,
        size: 0,
        unparsed_bytes: hex::encode(&h.unparsed_bytes),
        state_root: hex::encode(h.state_root.as_bytes()),
        height: h.height,
        n_bits: h.n_bits as u64,
        version: h.version,
        id: id.to_string(),
        ad_proofs_root: hex::encode(h.ad_proofs_root.as_bytes()),
        transactions_root: hex::encode(h.transactions_root.as_bytes()),
        extension_hash: hex::encode(h.extension_root.as_bytes()),
        pow_solutions,
        ad_proofs_id: String::new(),
        transactions_id: String::new(),
        parent_id: hex::encode(h.parent_id.as_bytes()),
    }
}

#[test]
fn decode_scala_header_v1_roundtrips_mainnet_h1_through_h5() {
    let headers = load_headers("headers_1_10.json");
    let mut tested = 0;
    for hv in headers.iter().take(5) {
        let raw = hex::decode(&hv.bytes).unwrap();
        let mut r = VlqReader::new(&raw);
        let parsed = ergo_ser::header::read_header(&mut r).unwrap();
        assert_eq!(parsed.version, 1, "h={}: expected v1 header", hv.height);

        let scala = header_to_scala(&parsed, &hv.id);
        let (decoded_bytes, decoded_id) = decode_scala_header(&scala)
            .unwrap_or_else(|e| panic!("h={}: decode_scala_header failed: {:?}", hv.height, e));

        assert_eq!(
            decoded_bytes, raw,
            "h={}: decoded bytes differ from original",
            hv.height,
        );
        assert_eq!(
            hex::encode(decoded_id.as_bytes()),
            hv.id,
            "h={}: decoded header_id differs from claimed id",
            hv.height,
        );
        tested += 1;
    }
    assert_eq!(tested, 5);
}

#[test]
fn decode_scala_header_v2_roundtrips_mainnet_700k() {
    let headers = load_headers("headers_1761792_1761795_eip37_curated.json");
    // Pick a few v2 headers — anything past h=417_792 is v2.
    let mut tested = 0;
    for hv in headers.iter().take(3) {
        let raw = hex::decode(&hv.bytes).unwrap();
        let mut r = VlqReader::new(&raw);
        let parsed = ergo_ser::header::read_header(&mut r).unwrap();
        assert!(parsed.version >= 2, "h={}: expected v2+ header", hv.height);

        let scala = header_to_scala(&parsed, &hv.id);
        let (decoded_bytes, decoded_id) = decode_scala_header(&scala)
            .unwrap_or_else(|e| panic!("h={}: decode_scala_header failed: {:?}", hv.height, e));

        assert_eq!(decoded_bytes, raw, "h={}: bytes differ", hv.height);
        assert_eq!(
            hex::encode(decoded_id.as_bytes()),
            hv.id,
            "h={}: header_id differs",
            hv.height,
        );
        tested += 1;
    }
    assert_eq!(tested, 3);
}

#[test]
fn decode_scala_header_rejects_bad_state_root_length() {
    let headers = load_headers("headers_1_10.json");
    let hv = &headers[0];
    let raw = hex::decode(&hv.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let parsed = ergo_ser::header::read_header(&mut r).unwrap();

    let mut scala = header_to_scala(&parsed, &hv.id);
    scala.state_root = "aabb".to_string(); // 2 bytes, not 33

    let err = decode_scala_header(&scala).unwrap_err();
    assert_eq!(err.0, "deserialize");
    assert!(err.1.contains("stateRoot"), "unexpected detail: {}", err.1);
}

#[test]
fn decode_scala_header_rejects_oversized_n_bits() {
    let headers = load_headers("headers_1_10.json");
    let hv = &headers[0];
    let raw = hex::decode(&hv.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let parsed = ergo_ser::header::read_header(&mut r).unwrap();

    let mut scala = header_to_scala(&parsed, &hv.id);
    scala.n_bits = (u32::MAX as u64) + 1;

    let err = decode_scala_header(&scala).unwrap_err();
    assert!(err.1.contains("nBits"), "unexpected detail: {}", err.1);
}

/// Codex §12(a) regression pin: the signed two's-complement
/// `BigInt::from_signed_bytes_be(d).to_string()` ↔ `parse →
/// to_signed_bytes_be()` round-trip must be lossless across all
/// mainnet v1 `d` values, including the case where the high bit
/// of the leading byte is set (the case the prior unsigned
/// `BigUint::to_bytes_be()` got wrong by dropping the leading
/// `0x00` disambiguator).
///
/// Loops the first ten v1 mainnet headers; for each, encodes via
/// the production `BigInt::from_signed_bytes_be(d).to_string()`,
/// then parses back via our decoder's
/// `parse::<BigInt>().to_signed_bytes_be()`, and asserts byte
/// equality. Logs whether the high-bit case actually got
/// exercised by the fixture corpus.
#[test]
fn decode_scala_header_v1_d_signed_bigint_roundtrip_is_lossless() {
    use ergo_ser::autolykos::AutolykosSolution;
    let headers = load_headers("headers_1_10.json");
    let mut tested_high_bit = false;
    for hv in headers.iter().take(10) {
        let raw = hex::decode(&hv.bytes).unwrap();
        let mut r = VlqReader::new(&raw);
        let parsed = ergo_ser::header::read_header(&mut r).unwrap();
        if let AutolykosSolution::V1 { d, .. } = &parsed.solution {
            let signed_str = num_bigint::BigInt::from_signed_bytes_be(d).to_string();
            let round_d = signed_str
                .parse::<num_bigint::BigInt>()
                .unwrap()
                .to_signed_bytes_be();
            assert_eq!(
                round_d, *d,
                "h={}: signed BigInt round-trip failed",
                hv.height,
            );
            if d.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
                tested_high_bit = true;
            }
        }
    }
    eprintln!(
        "[§12(a) d-signed-bigint round-trip pin] high-bit case observed in fixtures: {tested_high_bit}",
    );
}

/// Codex §12(a) follow-up: bind the high-bit-disambiguator invariant
/// explicitly with a synthetic `d`, so the regression pin holds even
/// if the fixture corpus ever drifts away from values whose leading
/// byte has the high bit set.
///
/// Builds a real v1 mainnet header, swaps its `d` for `[0x00, 0x80, ..]`
/// (a positive value whose magnitude's leading byte requires the
/// `0x00` two's-complement disambiguator), runs the
/// `header_to_scala` → `decode_scala_header` → `read_header` chain,
/// and asserts the final `d` bytes are byte-identical to the
/// synthetic input. The prior unsigned `BigUint::to_bytes_be()` path
/// would have dropped the leading `0x00`, mutating the header bytes
/// and the header_id.
#[test]
fn decode_scala_header_v1_synthetic_high_bit_d_end_to_end_roundtrips() {
    use ergo_ser::autolykos::AutolykosSolution;
    let headers = load_headers("headers_1_10.json");
    let hv = &headers[0];
    let raw = hex::decode(&hv.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let parsed = ergo_ser::header::read_header(&mut r).unwrap();
    assert_eq!(parsed.version, 1);

    let synthetic_d: Vec<u8> = vec![0x00, 0x80, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
    let mut mutated = parsed.clone();
    mutated.solution = match parsed.solution {
        AutolykosSolution::V1 { pk, w, nonce, .. } => AutolykosSolution::V1 {
            pk,
            w,
            nonce,
            d: synthetic_d.clone(),
        },
        AutolykosSolution::V2 { .. } => unreachable!("h=1 is v1"),
    };

    let scala = header_to_scala(&mutated, &hv.id);
    let (decoded_bytes, _id) = decode_scala_header(&scala).unwrap();
    let mut r2 = VlqReader::new(&decoded_bytes);
    let reparsed = ergo_ser::header::read_header(&mut r2).unwrap();
    match reparsed.solution {
        AutolykosSolution::V1 { d, .. } => {
            assert_eq!(
                d, synthetic_d,
                "high-bit d disambiguator dropped during JSON round-trip",
            );
        }
        _ => panic!("expected v1 solution after decode"),
    }
}

#[test]
fn decode_scala_header_rejects_v1_with_non_string_d() {
    let headers = load_headers("headers_1_10.json");
    let hv = &headers[0];
    let raw = hex::decode(&hv.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let parsed = ergo_ser::header::read_header(&mut r).unwrap();
    assert_eq!(parsed.version, 1);

    let mut scala = header_to_scala(&parsed, &hv.id);
    scala.pow_solutions.d = JsonValue::Number(42u32.into());

    let err = decode_scala_header(&scala).unwrap_err();
    assert!(
        err.1.contains("powSolutions.d"),
        "unexpected detail: {}",
        err.1
    );
}

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
            // v1 d: Scala renders it as a bare JSON NUMBER (circe BigInt)
            // — the UNSIGNED magnitude of the PoW distance. Mirrors the
            // production encoder at
            // ergo-node::api_bridge::compat::encode_pow_solutions,
            // which round-trips via `BigUint::from_bytes_be(d)`.
            d: JsonValue::Number(
                num_bigint::BigUint::from_bytes_be(d)
                    .to_string()
                    .parse()
                    .expect("unsigned decimal parses as arbitrary-precision Number"),
            ),
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

/// Regression pin: v1 `d` round-trips byte-identically through the
/// production-shaped encoder (`header_to_scala`, which emits the bare
/// JSON NUMBER Scala serves) and our decoder, across all mainnet v1
/// fixtures. Scala encodes `d` as the UNSIGNED magnitude of the PoW
/// distance (circe BigInt -> bare number; wire bytes are
/// `BigIntegers.asUnsignedByteArray`), so a high-bit value stays
/// POSITIVE. A signed two's-complement decode would flip it negative
/// (live repro h=28662: Scala serves +5624...573; the old signed path
/// served -652...) and invent a spurious `0x00` disambiguator; both
/// diverge from Scala and mutate the header bytes. This pin would
/// catch either. Logs whether a high-bit case was exercised.
#[test]
fn decode_scala_header_v1_d_roundtrips_as_unsigned_number() {
    use ergo_ser::autolykos::AutolykosSolution;
    let headers = load_headers("headers_1_10.json");
    let mut tested_high_bit = false;
    for hv in headers.iter().take(10) {
        let raw = hex::decode(&hv.bytes).unwrap();
        let mut r = VlqReader::new(&raw);
        let parsed = ergo_ser::header::read_header(&mut r).unwrap();
        let original_d = match &parsed.solution {
            AutolykosSolution::V1 { d, .. } => d.clone(),
            _ => continue,
        };

        let scala = header_to_scala(&parsed, &hv.id);
        let dec = match &scala.pow_solutions.d {
            JsonValue::Number(n) => n.to_string(),
            other => panic!(
                "h={}: v1 d encoded as {other:?}, expected Number",
                hv.height
            ),
        };
        assert!(
            !dec.starts_with('-'),
            "h={}: v1 d encoded as negative {dec:?}; expected unsigned magnitude",
            hv.height,
        );

        let (decoded_bytes, _id) =
            decode_scala_header(&scala).expect("v1 header round-trip must decode");
        let mut r2 = VlqReader::new(&decoded_bytes);
        let reparsed = ergo_ser::header::read_header(&mut r2).unwrap();
        match reparsed.solution {
            AutolykosSolution::V1 { d, .. } => assert_eq!(
                d, original_d,
                "h={}: v1 d mutated across the JSON round-trip",
                hv.height,
            ),
            _ => panic!("h={}: expected v1 after decode", hv.height),
        }

        if original_d.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
            tested_high_bit = true;
        }
    }
    eprintln!("[v1 d round-trip pin] high-bit case observed in fixtures: {tested_high_bit}",);
}

/// Bind the high-bit invariant explicitly with a synthetic `d`, so the
/// pin holds regardless of fixture drift: a v1 `d` whose magnitude's
/// leading byte has the high bit set (the form real mainnet `d` takes
/// once difficulty rises, e.g. h=28662) must serialize as a POSITIVE
/// JSON number and round-trip byte-identically. The old signed
/// two's-complement decode flipped such values negative and invented a
/// spurious `0x00` disambiguator; both diverge from Scala.
#[test]
fn decode_scala_header_v1_synthetic_high_bit_d_end_to_end_roundtrips() {
    use ergo_ser::autolykos::AutolykosSolution;
    let headers = load_headers("headers_1_10.json");
    let hv = &headers[0];
    let raw = hex::decode(&hv.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let parsed = ergo_ser::header::read_header(&mut r).unwrap();
    assert_eq!(parsed.version, 1);

    // Canonical high-bit magnitude: leading byte >= 0x80, NO leading
    // 0x00 (real Scala `asUnsignedByteArray` carries no sign byte).
    let synthetic_d: Vec<u8> = vec![0x80, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
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
    match &scala.pow_solutions.d {
        JsonValue::Number(n) => assert!(
            !n.to_string().starts_with('-'),
            "high-bit d encoded negative; expected positive unsigned magnitude",
        ),
        other => panic!("v1 d encoded as {other:?}, expected Number"),
    }
    let (decoded_bytes, _id) = decode_scala_header(&scala).unwrap();
    let mut r2 = VlqReader::new(&decoded_bytes);
    let reparsed = ergo_ser::header::read_header(&mut r2).unwrap();
    match reparsed.solution {
        AutolykosSolution::V1 { d, .. } => {
            assert_eq!(d, synthetic_d, "high-bit d mutated during JSON round-trip",);
        }
        _ => panic!("expected v1 solution after decode"),
    }
}

/// Scala encodes v1 `d` as a bare JSON NUMBER. Confirm the decoder
/// accepts that form (it previously rejected anything but a string)
/// and reconstructs the correct UNSIGNED magnitude bytes. The value
/// below is the live Scala response for mainnet h=28662 -- the case
/// that exposed the old signed path serving a negative number.
#[test]
fn decode_scala_header_accepts_v1_numeric_d() {
    use ergo_ser::autolykos::AutolykosSolution;
    let headers = load_headers("headers_1_10.json");
    let hv = &headers[0];
    let raw = hex::decode(&hv.bytes).unwrap();
    let mut r = VlqReader::new(&raw);
    let parsed = ergo_ser::header::read_header(&mut r).unwrap();
    assert_eq!(parsed.version, 1);

    // Live Scala value for h=28662: a positive bare number whose
    // magnitude's first byte is 0x80 (high bit) -- exactly the form
    // the old signed decoder mishandled.
    const H28662_SCALA_D: &str = "5624587765342653314291518590252587439323333907522825303573";
    let expected_d = num_bigint::BigUint::parse_bytes(H28662_SCALA_D.as_bytes(), 10)
        .unwrap()
        .to_bytes_be();

    let mut scala = header_to_scala(&parsed, &hv.id);
    scala.pow_solutions.d = JsonValue::Number(
        H28662_SCALA_D
            .parse::<serde_json::Number>()
            .expect("arbitrary_precision holds big numbers"),
    );

    let (decoded_bytes, _id) = decode_scala_header(&scala).unwrap();
    let mut r2 = VlqReader::new(&decoded_bytes);
    let reparsed = ergo_ser::header::read_header(&mut r2).unwrap();
    match reparsed.solution {
        AutolykosSolution::V1 { d, .. } => assert_eq!(
            d, expected_d,
            "numeric v1 d did not reconstruct the unsigned magnitude",
        ),
        _ => panic!("expected v1 solution after decode"),
    }
}

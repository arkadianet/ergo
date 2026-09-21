//! Scala-node JSON → `Header` parity oracle.
//!
//! Two fixtures, both captured VERBATIM from live Scala nodes — nothing
//! re-serialized or hand-edited, so every derived field is an EXTERNAL
//! oracle:
//!
//! - `test-vectors/testnet/headers_json/scala_headers_442325_442334.json`:
//!   10 CONSECUTIVE header bodies from `arks-testnet-node` 6.0.3
//!   (`GET http://127.0.0.1:9062/blocks/{id}/header`, heights
//!   442325-442334, captured 2026-07-12). That chain carries version-4
//!   headers from genesis, i.e. the Autolykos **v2** solution layout.
//! - `test-vectors/mainnet/headers_json/scala_headers_v1_mainnet.json`:
//!   10 header bodies from a live mainnet node
//!   (`GET http://127.0.0.1:9053/blocks/{id}/header`, heights 1-9 and
//!   15, captured 2026-09-03) — the Autolykos **v1** layout, which the
//!   testnet chain cannot cover because it has no v1 headers.
//!
//! For both, the same contract holds:
//!
//! - `id` is the Scala node's `blake2b256(consensus_header_bytes)`.
//!   Decoding the JSON and re-serializing through
//!   `ergo_ser::header::serialize_header` must reproduce exactly that
//!   id — which proves the decoded `Header` is byte-identical to the
//!   consensus header, field by field (a single wrong byte anywhere
//!   changes the digest).
//! - The header is a real mined block, so the decoded struct must
//!   satisfy its own Autolykos PoW equation
//!   (`ergo_crypto::pow::verify_pow_solution`).
//!
//! Why the v1 fixture picks those heights: Scala serializes the v1 PoW
//! distance `d` with `BigIntegers.asUnsignedByteArray` — an UNSIGNED
//! big-endian magnitude that never carries a leading sign byte — and
//! circe renders it as a bare JSON number. Decoding that number as a
//! SIGNED two's-complement integer prepends a spurious `0x00` whenever
//! the magnitude's top bit is set, lengthening the header by one byte
//! and changing its id. Seven of the ten committed v1 headers (3, 4, 5,
//! 7, 8, 9, 15) have a high-bit `d` — mainnet height 3 is the first
//! such block on the chain — while heights 1, 2 and 6 have a low top
//! byte, where signed and unsigned agree. The fixture therefore
//! DISCRIMINATES the two decodes rather than merely exercising one.

use ergo_crypto::pow::verify_pow_solution;
use ergo_rest_json::types::ScalaHeader;
use ergo_rest_json::{
    decode_header_json, decode_scala_header, decode_scala_header_struct, DESERIALIZE,
};
use serde::Deserialize;

// ----- helpers -----

const FIXTURE: &str = "scala_headers_442325_442334.json";
const FIXTURE_HEIGHTS: std::ops::RangeInclusive<u32> = 442_325..=442_334;

const V1_FIXTURE: &str = "headers_json/scala_headers_v1_mainnet.json";
const V1_FIXTURE_HEIGHTS: [u32; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 15];
/// Fixture heights whose `d` magnitude has its top bit set — exactly
/// the headers a signed decode would corrupt.
const V1_HIGH_BIT_D_HEIGHTS: [u32; 7] = [3, 4, 5, 7, 8, 9, 15];

fn fixture_raw() -> String {
    let path = format!(
        "{}/../test-vectors/testnet/headers_json/{}",
        env!("CARGO_MANIFEST_DIR"),
        FIXTURE
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn mainnet_fixture_path(rel: &str) -> String {
    format!(
        "{}/../test-vectors/mainnet/{}",
        env!("CARGO_MANIFEST_DIR"),
        rel
    )
}

fn v1_fixture_raw() -> String {
    let path = mainnet_fixture_path(V1_FIXTURE);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Split a fixture array back into the verbatim per-header JSON
/// bodies, so `decode_header_json` is exercised on exactly the bytes
/// the node served (modulo the enclosing `[ , ]` scaffolding).
fn elements_of(raw: &str) -> Vec<serde_json::Value> {
    serde_json::from_str::<Vec<serde_json::Value>>(raw).expect("fixture parses as array")
}

fn dtos_of(raw: &str) -> Vec<ScalaHeader> {
    serde_json::from_str::<Vec<ScalaHeader>>(raw).expect("fixture parses as Vec<ScalaHeader>")
}

fn fixture_elements() -> Vec<serde_json::Value> {
    elements_of(&fixture_raw())
}

fn fixture_dtos() -> Vec<ScalaHeader> {
    dtos_of(&fixture_raw())
}

fn v1_fixture_elements() -> Vec<serde_json::Value> {
    elements_of(&v1_fixture_raw())
}

fn v1_fixture_dtos() -> Vec<ScalaHeader> {
    dtos_of(&v1_fixture_raw())
}

/// Mainnet consensus bytes for heights 1..=10, captured independently
/// of the header-JSON fixture — a second oracle for the v1 decode.
#[derive(Deserialize)]
struct HeaderVec {
    height: u32,
    id: String,
    bytes: String,
}

fn mainnet_wire_bytes() -> Vec<HeaderVec> {
    let raw = std::fs::read_to_string(mainnet_fixture_path("headers_1_10.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

/// The `d` magnitude of a decoded Autolykos v1 solution.
fn solution_d(header: &ergo_ser::header::Header) -> &[u8] {
    match &header.solution {
        ergo_ser::autolykos::AutolykosSolution::V1 { d, .. } => d,
        other => panic!("expected an Autolykos v1 solution, got {other:?}"),
    }
}

// ----- happy path -----

#[test]
fn json_header_fixture_is_consecutive_run_of_ten() {
    let dtos = fixture_dtos();
    assert_eq!(dtos.len(), 10, "expected 10 committed headers");
    let heights: Vec<u32> = dtos.iter().map(|h| h.height).collect();
    let expected: Vec<u32> = FIXTURE_HEIGHTS.collect();
    assert_eq!(heights, expected, "heights must be consecutive ascending");
    for (dto, next) in dtos.iter().zip(dtos.iter().skip(1)) {
        assert_eq!(
            next.parent_id, dto.id,
            "h={}: parentId must chain to the previous header's id",
            next.height,
        );
    }
}

#[test]
fn json_header_v1_fixture_is_ten_mainnet_v1_headers() {
    let dtos = v1_fixture_dtos();
    let heights: Vec<u32> = dtos.iter().map(|h| h.height).collect();
    assert_eq!(heights, V1_FIXTURE_HEIGHTS, "unexpected fixture heights");
    for dto in &dtos {
        assert_eq!(dto.version, 1, "h={}: expected a v1 header", dto.height);
    }
    // Heights 1-9 are a consecutive run, so each chains to the last.
    for (dto, next) in dtos.iter().zip(dtos.iter().skip(1)).take(8) {
        assert_eq!(
            next.parent_id, dto.id,
            "h={}: parentId must chain to the previous header's id",
            next.height,
        );
    }
}

#[test]
fn json_header_decode_populates_struct_fields_from_json() {
    let dto = &fixture_dtos()[0];
    let header = decode_scala_header_struct(dto).expect("real node JSON decodes");
    assert_eq!(header.version, dto.version);
    assert_eq!(header.height, dto.height);
    assert_eq!(header.timestamp, dto.timestamp);
    assert_eq!(header.n_bits as u64, dto.n_bits);
    assert_eq!(hex::encode(header.parent_id.as_bytes()), dto.parent_id);
    assert_eq!(
        hex::encode(header.ad_proofs_root.as_bytes()),
        dto.ad_proofs_root
    );
    assert_eq!(
        hex::encode(header.transactions_root.as_bytes()),
        dto.transactions_root
    );
    assert_eq!(hex::encode(header.state_root.as_bytes()), dto.state_root);
    assert_eq!(
        hex::encode(header.extension_root.as_bytes()),
        dto.extension_hash
    );
    assert_eq!(hex::encode(header.votes), dto.votes);
    assert!(header.unparsed_bytes.is_empty(), "v4 unparsedBytes is ''");
}

#[test]
fn json_header_v1_decode_populates_solution_fields_from_json() {
    let dto = &v1_fixture_dtos()[0];
    let header = decode_scala_header_struct(dto).expect("real node JSON decodes");
    match &header.solution {
        ergo_ser::autolykos::AutolykosSolution::V1 { pk, w, nonce, d } => {
            assert_eq!(hex::encode(pk.as_bytes()), dto.pow_solutions.pk);
            assert_eq!(hex::encode(w.as_bytes()), dto.pow_solutions.w);
            assert_eq!(hex::encode(nonce), dto.pow_solutions.n);
            assert_eq!(
                num_bigint::BigUint::from_bytes_be(d).to_string(),
                dto.pow_solutions.d.to_string(),
                "d magnitude must equal the served decimal",
            );
        }
        other => panic!("h=1: expected a v1 solution, got {other:?}"),
    }
}

// ----- round-trips -----

#[test]
fn json_header_str_and_dto_entry_points_agree() {
    for element in fixture_elements().into_iter().chain(v1_fixture_elements()) {
        let raw = element.to_string();
        let via_str = decode_header_json(&raw).expect("string entry point decodes");
        let dto: ScalaHeader = serde_json::from_value(element).expect("DTO parses");
        let via_dto = decode_scala_header_struct(&dto).expect("DTO entry point decodes");
        assert_eq!(via_str, via_dto, "h={}: entry points diverge", dto.height);
    }
}

#[test]
fn json_header_decoded_struct_matches_bytes_decoder_output() {
    // The struct decoder and the (bytes, id) decoder must describe the
    // same header: re-reading the serialized bytes through the
    // consensus bytes decoder reproduces the JSON-decoded struct.
    for dto in fixture_dtos().into_iter().chain(v1_fixture_dtos()) {
        let header = decode_scala_header_struct(&dto).expect("decode");
        let (bytes, _id) = decode_scala_header(&dto).expect("decode to bytes");
        let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
        let reread = ergo_ser::header::read_header(&mut r).expect("bytes re-decode");
        assert!(r.is_empty(), "h={}: trailing bytes", dto.height);
        assert_eq!(
            header, reread,
            "h={}: JSON-decoded struct != bytes-decoded struct",
            dto.height,
        );
    }
}

#[test]
fn json_header_v1_reencoded_d_matches_served_decimal() {
    // The encode direction (`ergo-node::api_bridge::compat::encode_pow_solutions`
    // emits `BigUint::from_bytes_be(d)`) must reproduce the node's own
    // decimal for every header — including the high-bit ones, where a
    // signed re-encode would emit a negative number.
    for element in v1_fixture_elements() {
        let height = element["height"].as_u64().expect("height field");
        let served = element["powSolutions"]["d"].to_string();
        let header = decode_header_json(&element.to_string()).expect("decode");
        let reencoded = num_bigint::BigUint::from_bytes_be(solution_d(&header)).to_string();
        assert_eq!(
            reencoded, served,
            "h={height}: re-encoded d decimal != the decimal Scala served",
        );
    }
}

// ----- error paths -----

#[test]
fn json_header_malformed_json_errors_with_deserialize_reason() {
    let err = decode_header_json("{ not json").unwrap_err();
    assert_eq!(err.0, DESERIALIZE);
    assert!(
        err.1.contains("header JSON parse"),
        "unexpected detail: {}",
        err.1
    );
}

#[test]
fn json_header_corrupted_hex_field_errors() {
    let mut dto = fixture_dtos()[0].clone();
    dto.parent_id = "zz".repeat(32);
    let err = decode_scala_header_struct(&dto).unwrap_err();
    assert_eq!(err.0, DESERIALIZE);
    assert!(err.1.contains("parentId"), "unexpected detail: {}", err.1);
}

#[test]
fn json_header_v1_negative_d_errors() {
    // Scala never serves a negative `d` (the magnitude is unsigned), so
    // a decoder that accepted one would be silently reinterpreting the
    // field rather than reading it.
    let mut element = v1_fixture_elements()[2].clone();
    element["powSolutions"]["d"] = serde_json::json!(-1);
    let err = decode_header_json(&element.to_string()).unwrap_err();
    assert_eq!(err.0, DESERIALIZE);
    assert!(
        err.1.contains("powSolutions.d"),
        "unexpected detail: {}",
        err.1
    );
}

#[test]
fn json_header_v1_short_w_errors() {
    let mut element = v1_fixture_elements()[2].clone();
    element["powSolutions"]["w"] = serde_json::json!("00");
    let err = decode_header_json(&element.to_string()).unwrap_err();
    assert_eq!(err.0, DESERIALIZE);
    assert!(
        err.1.contains("powSolutions.w"),
        "unexpected detail: {}",
        err.1
    );
}

// ----- oracle parity -----

/// THE oracle: for every committed real header, decoding the Scala
/// node's JSON and re-serializing through the consensus codec must
/// reproduce the Scala node's own `id` (`blake2b256` of the consensus
/// bytes). This proves the JSON decode is byte-faithful end to end —
/// any wrong field, ordering, or encoding changes the digest.
#[test]
fn json_header_v4_serialize_id_matches_scala_oracle_all_ten() {
    let mut checked = 0;
    for element in fixture_elements() {
        let claimed_id = element["id"].as_str().expect("id field").to_owned();
        let height = element["height"].as_u64().expect("height field");
        let header = decode_header_json(&element.to_string())
            .unwrap_or_else(|e| panic!("h={height}: decode failed: {e:?}"));
        let (_bytes, id) =
            ergo_ser::header::serialize_header(&header).expect("decoded header serializes");
        assert_eq!(
            hex::encode(id.as_bytes()),
            claimed_id,
            "h={height}: serialize(json_decode(json)).id != json.id — unfaithful decode",
        );
        checked += 1;
    }
    assert_eq!(checked, 10);
}

/// The same oracle over mainnet Autolykos v1 headers. A spurious `0x00`
/// sign byte on `d` lengthens the header and changes this digest, so
/// this test alone fails on a signed decode for the seven high-bit
/// heights (3, 4, 5, 7, 8, 9, 15).
#[test]
fn json_header_v1_serialize_id_matches_scala_oracle_all_ten() {
    let mut checked = 0;
    for element in v1_fixture_elements() {
        let claimed_id = element["id"].as_str().expect("id field").to_owned();
        let height = element["height"].as_u64().expect("height field");
        let header = decode_header_json(&element.to_string())
            .unwrap_or_else(|e| panic!("h={height}: decode failed: {e:?}"));
        let (_bytes, id) =
            ergo_ser::header::serialize_header(&header).expect("decoded header serializes");
        assert_eq!(
            hex::encode(id.as_bytes()),
            claimed_id,
            "h={height}: serialize(json_decode(json)).id != json.id — unfaithful decode",
        );
        checked += 1;
    }
    assert_eq!(checked, 10);
}

/// A second, independent oracle for the v1 decode: the decoded bytes
/// must equal the mainnet consensus bytes captured separately in
/// `headers_1_10.json`, not merely hash to the same id.
#[test]
fn json_header_v1_decoded_bytes_match_mainnet_wire_bytes() {
    let wire = mainnet_wire_bytes();
    let mut checked = 0;
    for dto in v1_fixture_dtos() {
        let Some(expected) = wire.iter().find(|w| w.height == dto.height) else {
            continue; // h=15 is outside the 1..=10 bytes fixture.
        };
        let (bytes, id) = decode_scala_header(&dto)
            .unwrap_or_else(|e| panic!("h={}: decode failed: {e:?}", dto.height));
        assert_eq!(
            hex::encode(&bytes),
            expected.bytes,
            "h={}: decoded bytes differ from the mainnet consensus bytes",
            dto.height,
        );
        assert_eq!(hex::encode(id.as_bytes()), expected.id, "h={}", dto.height);
        checked += 1;
    }
    assert_eq!(checked, 9, "expected heights 1..=9 to be cross-checked");
}

/// The regression pin, stated directly: a high-bit magnitude decodes to
/// bytes starting at its own top byte (>= 0x80) with no leading `0x00`.
/// Scala's `asUnsignedByteArray` is minimal-length, so any leading zero
/// byte would be our own invention.
#[test]
fn json_header_v1_high_bit_d_decodes_without_sign_byte() {
    let mut high_bit = Vec::new();
    for dto in v1_fixture_dtos() {
        let header = decode_scala_header_struct(&dto).expect("decode");
        let d = solution_d(&header);
        assert!(!d.is_empty(), "h={}: empty d", dto.height);
        assert_ne!(
            d[0], 0x00,
            "h={}: leading 0x00 in d — a sign byte Scala never emits",
            dto.height,
        );
        if d[0] >= 0x80 {
            high_bit.push(dto.height);
        }
    }
    assert_eq!(
        high_bit,
        V1_HIGH_BIT_D_HEIGHTS.to_vec(),
        "fixture no longer discriminates signed from unsigned decoding",
    );
}

/// Every committed header is a real mined block: the decoded struct
/// must satisfy its own Autolykos (v2 equation, header version 4) PoW.
/// This binds the PoW-message path (`serialize_header_without_pow`) and
/// the solution fields (`pk`, `n`) independently of the id digest.
#[test]
fn json_header_v4_pow_solution_verifies_all_ten() {
    for dto in fixture_dtos() {
        let header = decode_scala_header_struct(&dto).expect("decode");
        verify_pow_solution(&header)
            .unwrap_or_else(|e| panic!("h={}: PoW verification failed: {e}", dto.height));
    }
}

/// The v1 counterpart: the Autolykos v1 equation consumes `w` and `d`
/// directly, so it binds exactly the fields the id digest is least
/// specific about.
#[test]
fn json_header_v1_pow_solution_verifies_all_ten() {
    for dto in v1_fixture_dtos() {
        let header = decode_scala_header_struct(&dto).expect("decode");
        verify_pow_solution(&header)
            .unwrap_or_else(|e| panic!("h={}: PoW verification failed: {e}", dto.height));
    }
}

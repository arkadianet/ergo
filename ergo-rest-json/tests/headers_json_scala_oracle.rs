//! Scala-node JSON → `Header` parity oracle.
//!
//! The fixture `test-vectors/testnet/headers_json/scala_headers_442325_442334.json`
//! is a JSON array of 10 CONSECUTIVE header bodies captured VERBATIM
//! from the live Scala testnet node (`arks-testnet-node` 6.0.3,
//! `GET http://127.0.0.1:9062/blocks/{id}/header`, heights
//! 442325-442334, captured 2026-07-12). Each element is the exact
//! byte-for-byte Scala emission — nothing was re-serialized or
//! hand-edited, so every derived field is an EXTERNAL oracle:
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
//! Coverage note: this testnet chain carries version-4 headers from
//! genesis (Autolykos v2 solution layout, `version >= 2`); it has no
//! v1 headers, so live-JSON v1 (Autolykos v1 `w`/`d`) coverage is not
//! possible here. v1 JSON decoding stays pinned by the mainnet-bytes
//! round-trip suite in `decode_scala_header_roundtrip.rs`.

use ergo_crypto::pow::verify_pow_solution;
use ergo_rest_json::types::ScalaHeader;
use ergo_rest_json::{decode_header_json, decode_scala_header_struct, DESERIALIZE};

// ----- helpers -----

const FIXTURE: &str = "scala_headers_442325_442334.json";
const FIXTURE_HEIGHTS: std::ops::RangeInclusive<u32> = 442_325..=442_334;

fn fixture_raw() -> String {
    let path = format!(
        "{}/../test-vectors/testnet/headers_json/{}",
        env!("CARGO_MANIFEST_DIR"),
        FIXTURE
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Split the fixture array back into the verbatim per-header JSON
/// bodies, so `decode_header_json` is exercised on exactly the bytes
/// the node served (modulo the enclosing `[ , ]` scaffolding).
fn fixture_elements() -> Vec<serde_json::Value> {
    serde_json::from_str::<Vec<serde_json::Value>>(&fixture_raw()).expect("fixture parses as array")
}

fn fixture_dtos() -> Vec<ScalaHeader> {
    serde_json::from_str::<Vec<ScalaHeader>>(&fixture_raw())
        .expect("fixture parses as Vec<ScalaHeader>")
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

// ----- round-trips -----

#[test]
fn json_header_str_and_dto_entry_points_agree() {
    for element in fixture_elements() {
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
    for dto in fixture_dtos() {
        let header = decode_scala_header_struct(&dto).expect("decode");
        let (bytes, _id) = ergo_rest_json::decode_scala_header(&dto).expect("decode to bytes");
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

//! Field-exact JSON parity for the NiPoPoW DTOs against fixtures
//! captured live from the Scala reference node (:9053, mainnet,
//! 2026-07-05): `test-vectors/mainnet/nipopow/`.
//!
//! Each test deserializes a captured response into the typed DTO,
//! re-serializes it, and requires `serde_json::Value` equality with the
//! original. Any field the DTO drops (unknown on deserialize), renames,
//! or retypes shows up as a mismatch — this is the shape oracle for the
//! `/nipopow/*` REST surface.

use ergo_rest_json::types::{ScalaNipopowProof, ScalaPopowHeader};

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/../test-vectors/mainnet/nipopow/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn assert_roundtrip<T: serde::de::DeserializeOwned + serde::Serialize>(name: &str) {
    let raw = fixture(name);
    let original: serde_json::Value = serde_json::from_str(&raw).expect("fixture is valid JSON");
    let typed: T = serde_json::from_str(&raw).expect("fixture deserializes into DTO");
    let reserialized = serde_json::to_value(&typed).expect("DTO serializes");
    assert_eq!(
        original, reserialized,
        "{name}: DTO round-trip diverged from the captured Scala response"
    );
}

#[test]
fn popow_header_by_height_roundtrips() {
    assert_roundtrip::<ScalaPopowHeader>("popowHeaderByHeight_1000.json");
}

#[test]
fn popow_header_by_id_roundtrips() {
    assert_roundtrip::<ScalaPopowHeader>("popowHeaderById_h1000.json");
}

#[test]
fn nipopow_proof_tip_roundtrips() {
    assert_roundtrip::<ScalaNipopowProof>("proof_m6_k10.json");
}

// ----- JSON → binary decode (oracle parity) -----

/// The strongest possible oracle for `decode_nipopow_proof_json`: the
/// mainnet fixture pair is the SAME proof captured twice from the
/// Scala reference node — once as REST JSON (`proof_m6_k10.json`) and
/// once re-emitted through Scala's own `NipopowProofSerializer`
/// (`proof_m6_k10.scala.bin`, genuine Scala wire bytes). Decoding the
/// JSON must produce exactly the struct the wire deserializer produces
/// from the Scala bytes — every header field, interlink id,
/// batch-Merkle-proof byte, and the `continuous` flag.
#[test]
fn nipopow_proof_json_decode_equals_scala_wire_bytes() {
    let from_json = ergo_rest_json::decode_nipopow_proof_json(&fixture("proof_m6_k10.json"))
        .expect("captured Scala JSON decodes");
    let bin_path = format!(
        "{}/../test-vectors/mainnet/nipopow/proof_m6_k10.scala.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    let scala_bytes = std::fs::read(&bin_path).unwrap_or_else(|e| panic!("read {bin_path}: {e}"));
    let from_wire = ergo_ser::popow_proof::deserialize_nipopow_proof(&scala_bytes)
        .expect("Scala wire bytes deserialize");
    assert_eq!(
        from_json, from_wire,
        "JSON-decoded NipopowProof diverged from the Scala-wire-bytes proof"
    );
    // And re-serializing the JSON-decoded proof must reproduce the
    // genuine Scala wire bytes exactly.
    let reserialized = ergo_ser::popow_proof::serialize_nipopow_proof(&from_json)
        .expect("decoded proof re-serializes");
    assert_eq!(
        reserialized, scala_bytes,
        "re-serialized proof is not byte-identical to Scala's NipopowProofSerializer output"
    );
}

/// Single-PoPowHeader decode: the JSON's own `id` (Scala's
/// `blake2b256(header_bytes)`) must be reproduced by re-serializing
/// the decoded embedded header — proving the header decode is
/// byte-exact — and the interlinks-proof blob must survive a
/// deserialize → re-serialize round-trip (i.e. it is a structurally
/// valid `BatchMerkleProof` wire blob, not just opaque bytes).
#[test]
fn popow_header_json_decode_reproduces_header_id() {
    let raw = fixture("popowHeaderByHeight_1000.json");
    let dto: ScalaPopowHeader = serde_json::from_str(&raw).unwrap();
    let ph = ergo_rest_json::decode_scala_popow_header(&dto).expect("captured JSON decodes");
    let (_bytes, id) = ergo_ser::header::serialize_header(&ph.header).expect("header serializes");
    assert_eq!(hex::encode(id.as_bytes()), dto.header.id);
    assert_eq!(ph.interlinks.len(), dto.interlinks.len());
    let bmp = ergo_ser::batch_merkle_proof::deserialize_batch_merkle_proof(&ph.interlinks_proof)
        .expect("decoded interlinks proof is a valid BatchMerkleProof blob");
    assert_eq!(bmp.indices.len(), dto.interlinks_proof.indices.len());
    assert_eq!(bmp.proofs.len(), dto.interlinks_proof.proofs.len());
}

// ----- error paths -----

/// A side byte outside {0, 1} must be rejected, not leniently
/// collapsed to `Right` the way the wire deserializer's
/// `Side::from_byte` does — a collapsed side would re-serialize to
/// different bytes than the node emitted.
#[test]
fn popow_header_bad_proof_side_errors() {
    let raw = fixture("popowHeaderByHeight_1000.json");
    let mut dto: ScalaPopowHeader = serde_json::from_str(&raw).unwrap();
    dto.interlinks_proof.proofs[0].side = 2;
    let err = ergo_rest_json::decode_scala_popow_header(&dto).unwrap_err();
    assert_eq!(err.0, ergo_rest_json::DESERIALIZE);
    assert!(err.1.contains("side"), "error names the field: {}", err.1);
}

/// The odd-trailing empty sibling must serialize as `""`, not as 64
/// zero hex chars (that form is wire-only). Pinned independently of the
/// full fixtures so a regression names the exact trap.
#[test]
fn empty_sibling_digest_is_empty_string() {
    let raw = fixture("popowHeaderByHeight_1000.json");
    let ph: ScalaPopowHeader = serde_json::from_str(&raw).unwrap();
    assert!(
        ph.interlinks_proof
            .proofs
            .iter()
            .any(|p| p.digest.is_empty()),
        "fixture is expected to contain at least one empty-sibling entry"
    );
    let v = serde_json::to_value(&ph).unwrap();
    let digests: Vec<&str> = v["interlinksProof"]["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["digest"].as_str().unwrap())
        .collect();
    assert!(digests.contains(&""));
    assert!(!digests.contains(&"0".repeat(64).as_str()));
}

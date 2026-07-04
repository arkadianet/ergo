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
fn nipopow_proof_anchored_roundtrips() {
    assert_roundtrip::<ScalaNipopowProof>("proof_m6_k10_at_h1000.json");
}

#[test]
fn nipopow_proof_tip_roundtrips() {
    assert_roundtrip::<ScalaNipopowProof>("proof_m6_k10.json");
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

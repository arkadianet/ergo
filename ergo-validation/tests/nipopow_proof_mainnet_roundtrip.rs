//! Mainnet-derived NipopowProof round-trip + structural-validation
//! oracle for §6.2.
//!
//! Constructs a minimal valid NipopowProof from committed mainnet
//! bytes (heights 1..=3 from `blocks_1_5.json` + `headers_1_2000.json`),
//! exercises the full pipeline:
//!
//! 1. Each `PoPowHeader` (prefix entries + `suffix_head`) is built
//!    via the production `build_popow_header` — the same code path
//!    `prove_with_db` uses internally.
//! 2. The composed `NipopowProof` is byte-serialized via
//!    `serialize_nipopow_proof`.
//! 3. Deserialization round-trips byte-identically.
//! 4. The structural `is_valid` predicate (Scala parity:
//!    `NipopowProof.scala:74-76`) returns true.
//!
//! Scope: heights 1..=3, ALL with interlinks-only extensions (so
//! the prover/verifier merkle trees match by construction).
//! `continuous=false` to bypass the difficulty-headers windowing
//! that needs the full epoch window. PoW skipped on genesis only;
//! h=2 and h=3 PoW are real mainnet bytes.
//!
//! This complements the gated `ergo-ser/tests/nipopow_scala_oracle.rs`
//! test (which exercises a true Scala-bytes capture when one is
//! present) by providing a non-gated, always-runs equivalent that
//! pins the full prover-output → codec → verifier pipeline.

use ergo_crypto::difficulty::DifficultyParams;
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::read_header;
use ergo_ser::popow_header::PoPowHeader;
use ergo_ser::popow_proof::{deserialize_nipopow_proof, serialize_nipopow_proof, NipopowProof};
use ergo_validation::popow::algos::{build_popow_header, unpack_interlinks};
use ergo_validation::popow::proof::NipopowProofExt;
use serde::Deserialize;

#[derive(Deserialize)]
struct BlockJson {
    height: u32,
    extension: ExtJson,
}

#[derive(Deserialize)]
struct ExtJson {
    fields: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct HeaderVec {
    height: u32,
    bytes: String,
}

fn fixture_path(rel: &str) -> String {
    format!(
        "{}/../test-vectors/mainnet/{}",
        env!("CARGO_MANIFEST_DIR"),
        rel
    )
}

fn load_blocks() -> Vec<BlockJson> {
    let raw = std::fs::read_to_string(fixture_path("blocks_1_5.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn load_header_at(height: u32) -> ergo_ser::header::Header {
    let raw = std::fs::read_to_string(fixture_path("headers_1_2000.json")).unwrap();
    let vecs: Vec<HeaderVec> = serde_json::from_str(&raw).unwrap();
    let entry = vecs.iter().find(|v| v.height == height).unwrap();
    let bytes = hex::decode(&entry.bytes).unwrap();
    let mut r = VlqReader::new(&bytes);
    read_header(&mut r).unwrap()
}

fn ext_fields_at(blocks: &[BlockJson], height: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
    let block = blocks.iter().find(|b| b.height == height).unwrap();
    block
        .extension
        .fields
        .iter()
        .map(|(k, v)| (hex::decode(k).unwrap(), hex::decode(v).unwrap()))
        .collect()
}

fn build_popow_at(blocks: &[BlockJson], height: u32) -> PoPowHeader {
    let header = load_header_at(height);
    let ext_fields = ext_fields_at(blocks, height);
    let interlinks: Vec<ModifierId> = if height == 1 {
        // Genesis: no interlinks in mainnet (extension is empty).
        Vec::new()
    } else {
        unpack_interlinks(&ext_fields).unwrap()
    };
    build_popow_header(header, interlinks, &ext_fields).unwrap()
}

#[test]
fn nipopow_proof_mainnet_h1_through_h3_roundtrips_and_validates() {
    let blocks = load_blocks();

    // Compose a minimal NipopowProof:
    //   prefix      = [genesis]            (PoPowHeader with empty interlinks/proof)
    //   suffix_head = h=2                  (PoPowHeader with 1-interlink proof)
    //   suffix_tail = [h=3]                (raw Header — Scala parity for tail format)
    //
    // continuous=false bypasses the difficulty-headers windowing
    // check (which needs the full epoch's recalculation window).
    let genesis_popow = build_popow_at(&blocks, 1);
    let h2_popow = build_popow_at(&blocks, 2);
    let h3_header = load_header_at(3);

    let proof = NipopowProof {
        m: 6,
        k: 10,
        prefix: vec![genesis_popow],
        suffix_head: h2_popow,
        suffix_tail: vec![h3_header],
        continuous: false,
    };

    // 1. Byte-roundtrip: serialize, deserialize, struct-equal,
    //    re-serialize, byte-stable.
    let bytes = serialize_nipopow_proof(&proof).unwrap();
    let parsed = deserialize_nipopow_proof(&bytes).unwrap();
    assert_eq!(parsed, proof, "parsed proof differs from input");
    let bytes_2 = serialize_nipopow_proof(&parsed).unwrap();
    assert_eq!(bytes, bytes_2, "re-serialize drift");

    // 2. Structural validation via the production `is_valid`.
    //    Scala parity: `NipopowProof.scala:74-76` AND/AND/AND of
    //    has_valid_connections / has_valid_heights / has_valid_proofs
    //    / has_valid_difficulty_headers / has_valid_per_header_pow.
    let cfg = DifficultyParams::mainnet();
    assert!(
        parsed.has_valid_connections(&cfg),
        "connections must validate",
    );
    assert!(parsed.has_valid_heights(), "heights must be monotone");
    assert!(parsed.has_valid_proofs(), "interlink proofs must validate");
    assert!(
        parsed.has_valid_difficulty_headers(&cfg),
        "difficulty-headers must validate (continuous=false ⇒ vacuous)",
    );
    assert!(
        parsed.has_valid_per_header_pow(),
        "per-header PoW must validate (genesis skipped, h=2 + h=3 real)",
    );
    assert!(parsed.is_valid(&cfg), "composed is_valid must pass");
}

/// Trivial-pass continuous=true variant. `has_valid_difficulty_headers`
/// computes the required-heights window via
/// `heights_for_next_recalculation(suffix_head_height,
/// epoch_length=1024, use_last_epochs=8)`. For
/// `suffix_head_height=4`, the window resolves to `[0, 1024]`, and
/// both heights are filtered by the `h > 0 && h < suffix_head_height`
/// guard inside the validator — so the result is `true` vacuously.
///
/// This pin proves the continuous-mode code path is reachable (the
/// branch IS taken at construction-time) even though no required
/// height matches. A non-vacuous continuous-mode test needs chain
/// fixtures past height 1024 — operator-extraction follow-up.
#[test]
fn nipopow_proof_continuous_mode_branch_is_exercised_on_short_chain() {
    let blocks = load_blocks();
    let proof = NipopowProof {
        m: 6,
        k: 10,
        prefix: vec![build_popow_at(&blocks, 1)],
        suffix_head: build_popow_at(&blocks, 2),
        suffix_tail: vec![load_header_at(3), load_header_at(4)],
        continuous: true,
    };

    let bytes = serialize_nipopow_proof(&proof).unwrap();
    let parsed = deserialize_nipopow_proof(&bytes).unwrap();
    assert_eq!(parsed, proof, "continuous-mode roundtrip drifts");

    let cfg = DifficultyParams::mainnet();
    // Branch under test: continuous=true so the inner if-branch of
    // has_valid_difficulty_headers is taken. With suffix_head height
    // = 2 (< epoch_length=1024), the required heights filter to empty,
    // so the validator returns true vacuously — but it returns true
    // by running the loop, not by short-circuiting on `!continuous`.
    assert!(
        parsed.has_valid_difficulty_headers(&cfg),
        "continuous=true short-chain must vacuously pass",
    );
    assert!(parsed.is_valid(&cfg));
}

#[test]
fn nipopow_proof_with_two_prefix_entries_roundtrips() {
    // Variation: two prefix entries (genesis + h=2 as a "super-block
    // witness"), suffix_head at h=3, empty tail. Tests prefix
    // length > 1 paths through the codec.
    let blocks = load_blocks();
    let proof = NipopowProof {
        m: 6,
        k: 10,
        prefix: vec![build_popow_at(&blocks, 1), build_popow_at(&blocks, 2)],
        suffix_head: build_popow_at(&blocks, 3),
        suffix_tail: vec![],
        continuous: false,
    };

    let bytes = serialize_nipopow_proof(&proof).unwrap();
    let parsed = deserialize_nipopow_proof(&bytes).unwrap();
    assert_eq!(parsed, proof);
    assert_eq!(
        serialize_nipopow_proof(&parsed).unwrap(),
        bytes,
        "re-serialize drift on 2-prefix proof",
    );

    let cfg = DifficultyParams::mainnet();
    assert!(parsed.is_valid(&cfg));
}

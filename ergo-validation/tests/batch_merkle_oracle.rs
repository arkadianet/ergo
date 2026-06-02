//! Scala-anchored byte-equality oracle for batch Merkle multiproofs.
//!
//! For every fixture in
//! `test-vectors/ergo-crypto/batch-merkle/fixtures.json` (output of
//! `BatchMerkleProofSerializer` over scrypto 2.3.0, the version
//! pinned in `reference/ergo/avldb/build.sbt`):
//!
//! 1. The codec roundtrips: `deserialize(captured) → parsed`,
//!    `serialize(parsed) == captured`.
//! 2. The parsed shape matches the fixture's expected indices and
//!    proof-entry count.
//! 3. The verifier returns `true` against `expected_root` and `false`
//!    when one sibling byte is flipped.
//! 4. The Rust constructor `merkle_proof_by_indices` produces the
//!    same wire bytes when its output is mapped through the wire
//!    types — drift in pair-iteration order, `in_set` dedup, or
//!    side-byte assignment fails this check, even when verification
//!    would still pass.
//!
//! Drift here breaks NiPoPoW interlinks-proof validation: the
//! `BatchMerkleProof` inside each `PoPowHeader` is the artifact
//! `check_popow_header_interlinks_proof` consumes. That path is
//! the logarithmic-time bootstrap surface (optional per the
//! checklist's "one mode first" rule, but still load-bearing once
//! NiPoPoW sync is wired) — `header_id` itself does not consult
//! this proof.

use ergo_crypto::merkle::{merkle_proof_by_indices, BatchProofEntry, IndexedBatchProof};
use ergo_ser::batch_merkle_proof::{
    deserialize_batch_merkle_proof, serialize_batch_merkle_proof, BatchMerkleProof, ProofEntry,
    Side,
};
use ergo_validation::popow::merkle::verify_batch_merkle_proof;

// ----- helpers -----

#[derive(serde::Deserialize)]
struct Fixture {
    label: String,
    leaves: Vec<String>,
    indices: Vec<u32>,
    expected_root: String,
    expected_bytes: String,
    expected_proof_indices: Vec<u32>,
    expected_proof_count: u32,
    #[allow(dead_code)]
    note: String,
}

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .join("test-vectors/ergo-crypto/batch-merkle/fixtures.json")
}

fn load_fixtures() -> Vec<Fixture> {
    let raw = std::fs::read_to_string(fixture_path()).expect("read fixtures.json");
    serde_json::from_str(&raw).expect("parse fixtures.json")
}

fn find(label: &str) -> Fixture {
    load_fixtures()
        .into_iter()
        .find(|f| f.label == label)
        .unwrap_or_else(|| panic!("fixture {label} not found"))
}

fn hex_decode_32(s: &str) -> [u8; 32] {
    hex::decode(s)
        .expect("hex decode")
        .try_into()
        .expect("32 bytes")
}

/// Map the in-memory `IndexedBatchProof` from `ergo-crypto` into the
/// wire-form `BatchMerkleProof` from `ergo-ser`. The conversion is
/// the same one `algos.rs::build_interlinks_proof` performs in
/// production: byte 0 → `Side::Left`, byte 1 → `Side::Right`.
fn to_wire(p: IndexedBatchProof) -> BatchMerkleProof {
    let (indices, entries) = p;
    let proofs = entries
        .into_iter()
        .map(|BatchProofEntry { digest, side }| ProofEntry {
            digest,
            side: Side::from_byte(side),
        })
        .collect();
    BatchMerkleProof { indices, proofs }
}

fn assert_roundtrip(fx: &Fixture) {
    let captured = hex::decode(&fx.expected_bytes).expect("expected_bytes hex");
    let expected_root = hex_decode_32(&fx.expected_root);

    let parsed = deserialize_batch_merkle_proof(&captured)
        .unwrap_or_else(|e| panic!("[{}] deserialize: {e}", fx.label));

    let got_indices: Vec<u32> = parsed.indices.iter().map(|(i, _)| *i).collect();
    assert_eq!(
        got_indices, fx.expected_proof_indices,
        "[{}] sorted proof indices",
        fx.label,
    );
    assert_eq!(
        parsed.proofs.len() as u32,
        fx.expected_proof_count,
        "[{}] proof entry count",
        fx.label,
    );

    assert!(
        verify_batch_merkle_proof(&parsed, &expected_root),
        "[{}] verify against Scala root",
        fx.label,
    );

    let re_serialized = serialize_batch_merkle_proof(&parsed);
    assert_eq!(
        re_serialized, captured,
        "[{}] serialize(deserialize(x)) == x",
        fx.label,
    );
}

// ----- oracle parity (per-shape) -----

/// 1-leaf tree, prove the only leaf. Exercises the
/// always-reduce-at-least-once invariant and the `None`-digest
/// sibling marker.
#[test]
fn single_leaf_prove_all_roundtrips_scala_vector() {
    assert_roundtrip(&find("single_leaf_prove_all"));
}

/// 4-leaf tree, prove an adjacent pair. Both siblings of the
/// bottom-level pair are in the proven set, so the `in_set` dedup
/// path fires.
#[test]
fn adjacent_pair_4leaf_roundtrips_scala_vector() {
    assert_roundtrip(&find("adjacent_pair_4leaf"));
}

/// 8-leaf tree, prove [0, 3, 5]. Mixed `Side::Left` and
/// `Side::Right` non-empty siblings — fails on a left/right
/// inversion bug that the symmetric-tree shapes can't catch.
#[test]
fn sparse_3_of_8_roundtrips_scala_vector() {
    assert_roundtrip(&find("sparse_3_of_8"));
}

/// 4-leaf tree, every leaf proven — `proofs.len() == 0`. Pins
/// the empty-proofs codec path: 8-byte header followed by only
/// the indices section.
#[test]
fn full_4leaf_all_indices_roundtrips_scala_vector() {
    assert_roundtrip(&find("full_4leaf_all_indices"));
}

/// 5-leaf tree, prove only the trailing leaf. Forces a 32-zero
/// `EmptyByteArray` sibling marker above the leaf level — exercises
/// the `None`-digest decode ambiguity (zero bytes → `None`).
#[test]
fn odd_count_5leaf_prove_last_roundtrips_scala_vector() {
    assert_roundtrip(&find("odd_count_5leaf_prove_last"));
}

/// 32-leaf tree, prove a sparse 4-leaf subset across 5 reduction
/// levels. Catches level-counter bugs that surface only beyond the
/// 3 internal levels the toy shapes exercise.
#[test]
fn deep_32leaf_sparse_proof_roundtrips_scala_vector() {
    assert_roundtrip(&find("deep_32leaf_sparse_proof"));
}

/// Unsorted, duplicate-bearing index input. Both Scala
/// `proofByIndices` and Rust `merkle_proof_by_indices` normalize
/// (sort + dedup) before constructing the proof; this fixture pins
/// byte-identity after that normalization.
#[test]
fn unsorted_dup_indices_4_of_8_roundtrips_scala_vector() {
    assert_roundtrip(&find("unsorted_dup_indices_4_of_8"));
}

// ----- builder cross-check -----

/// For every fixture, build the proof from `leaves` via
/// `merkle_proof_by_indices`, serialize through the wire codec, and
/// assert byte-identity with the Scala fixture. The strong drift
/// catch: a Rust builder that emits the right *semantic* proof in
/// a different order, with the wrong side bytes, or with the wrong
/// `None`/`Some(zeros)` discrimination silently fails this check
/// even when verification would still succeed.
#[test]
fn merkle_proof_by_indices_matches_scala_construction() {
    let mut failures = Vec::new();
    for fx in load_fixtures() {
        let leaves: Vec<Vec<u8>> = fx
            .leaves
            .iter()
            .map(|s| hex::decode(s).expect("leaf hex"))
            .collect();
        let leaf_refs: Vec<&[u8]> = leaves.iter().map(|v| v.as_slice()).collect();

        let built = merkle_proof_by_indices(&leaf_refs, &fx.indices)
            .unwrap_or_else(|| panic!("[{}] merkle_proof_by_indices returned None", fx.label));

        let wire = to_wire(built);
        let serialized = serialize_batch_merkle_proof(&wire);
        let expected = hex::decode(&fx.expected_bytes).expect("expected_bytes hex");
        if serialized != expected {
            failures.push(format!(
                "[{}] Rust-built bytes diverge from Scala fixture\n  rust:  {}\n  scala: {}",
                fx.label,
                hex::encode(&serialized),
                fx.expected_bytes,
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "Rust constructor diverges from Scala on {} fixture(s):\n{}",
        failures.len(),
        failures.join("\n"),
    );
}

// ----- cryptographic binding -----

/// Flip a single byte inside the second proof entry's digest of
/// the `sparse_3_of_8` fixture and assert verification fails. Pins
/// that the proof is genuinely Merkle-bound, not accepted on
/// shape alone.
#[test]
fn flipped_sibling_byte_fails_verify() {
    let fx = find("sparse_3_of_8");
    let mut bytes = hex::decode(&fx.expected_bytes).expect("expected_bytes hex");
    let expected_root = hex_decode_32(&fx.expected_root);

    // First proof-entry digest sits at offset `8 + num_indices*36`;
    // flipping a byte in the *second* proof-entry digest (offset
    // `+ 33 + 0`) lands inside a non-empty sibling for this fixture.
    let num_indices = fx.expected_proof_indices.len();
    let second_proof_digest_start = 8 + num_indices * 36 + 33;
    bytes[second_proof_digest_start] ^= 0xFF;

    let parsed = deserialize_batch_merkle_proof(&bytes)
        .expect("flipped-byte fixture still decodes (only digest bytes touched)");
    assert!(
        !verify_batch_merkle_proof(&parsed, &expected_root),
        "corrupted-sibling proof must NOT verify against the original root",
    );
}

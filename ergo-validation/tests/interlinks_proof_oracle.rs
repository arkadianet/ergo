//! End-to-end PoPowHeader interlinks-proof oracle.
//!
//! For every fixture in
//! `test-vectors/ergo-crypto/batch-merkle/popow_interlinks.json`,
//! constructs a `PoPowHeader` whose `interlinks` + `interlinks_proof`
//! fields carry the Scala-emitted values and drives the production
//! `check_popow_header_interlinks_proof` path end-to-end.
//!
//! Coverage:
//! * Per-fixture happy path: the Scala proof validates against
//!   `interlinks` through Rust's `pack_interlinks` ->
//!   `kv_to_leaf` -> `merkle_tree_root` -> `verify_batch_merkle_proof`
//!   chain.
//! * Per-fixture interlinks-root assertion: the root the Rust path
//!   reconstructs from `interlinks` matches the Scala fixture's
//!   `expected_root` byte-for-byte.
//! * Negative test: flipping one byte in one interlinks `ModifierId`
//!   shifts the reconstructed tree root, and the proof no longer
//!   verifies. Pins that the proof is genuinely Merkle-bound to the
//!   interlinks vector, not accepted on shape alone.
//!
//! The synthetic `Header` field on the constructed `PoPowHeader` is
//! ignored by `check_popow_header_interlinks_proof` (it consults
//! only `p.interlinks` and `p.interlinks_proof`), so any zero-filled
//! shell suffices.

use ergo_crypto::merkle::merkle_tree_root;
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::Header;
use ergo_ser::popow_header::PoPowHeader;
use ergo_validation::popow::proof::check_popow_header_interlinks_proof;

// ----- helpers -----

#[derive(serde::Deserialize)]
struct Fixture {
    label: String,
    interlinks: Vec<String>,
    expected_root: String,
    expected_proof_bytes: String,
    expected_proof_indices_count: u32,
    expected_proof_entry_count: u32,
    #[allow(dead_code)]
    note: String,
}

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .join("test-vectors/ergo-crypto/batch-merkle/popow_interlinks.json")
}

fn load_fixtures() -> Vec<Fixture> {
    let raw = std::fs::read_to_string(fixture_path()).expect("read popow_interlinks.json");
    serde_json::from_str(&raw).expect("parse popow_interlinks.json")
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

/// Zero-filled `Header` shell. `check_popow_header_interlinks_proof`
/// only reads `interlinks` and `interlinks_proof`, so the header
/// contents are irrelevant to the test.
fn dummy_header() -> Header {
    Header {
        version: 1,
        parent_id: ModifierId::from_bytes([0; 32]),
        ad_proofs_root: Digest32::from_bytes([0; 32]),
        transactions_root: Digest32::from_bytes([0; 32]),
        state_root: ADDigest::from_bytes([0; 33]),
        timestamp: 0,
        extension_root: Digest32::from_bytes([0; 32]),
        n_bits: 0,
        height: 1,
        votes: [0; 3],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x02; 33]),
            nonce: [0; 8],
        },
    }
}

fn build_popow_header(fx: &Fixture) -> PoPowHeader {
    let interlinks: Vec<ModifierId> = fx
        .interlinks
        .iter()
        .map(|s| ModifierId::from_bytes(hex_decode_32(s)))
        .collect();
    let interlinks_proof = hex::decode(&fx.expected_proof_bytes).expect("proof hex");
    PoPowHeader {
        header: dummy_header(),
        interlinks,
        interlinks_proof,
    }
}

fn assert_happy(fx: &Fixture) {
    let popow = build_popow_header(fx);

    // The Rust-reconstructed interlinks-subtree root must match the
    // Scala fixture exactly. This is the strong drift catch: a Rust
    // `pack_interlinks`/`kv_to_leaf` divergence would shift this
    // root and ALSO make verification fail, but the explicit equality
    // assertion names the divergence directly.
    let fields = ergo_validation::popow::algos::pack_interlinks(&popow.interlinks);
    let leaves: Vec<Vec<u8>> = fields
        .iter()
        .map(|(k, v)| ergo_validation::popow::algos::kv_to_leaf(k, v))
        .collect();
    let leaf_refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let rust_root = merkle_tree_root(&leaf_refs);
    let scala_root = hex_decode_32(&fx.expected_root);
    assert_eq!(
        rust_root, scala_root,
        "[{}] Rust-reconstructed interlinks-subtree root differs from Scala",
        fx.label,
    );

    assert!(
        check_popow_header_interlinks_proof(&popow),
        "[{}] production check_popow_header_interlinks_proof must accept the Scala-emitted proof",
        fx.label,
    );
}

// ----- oracle parity (per-shape) -----

/// Single-interlink vector. `packInterlinks` produces one kv-pair;
/// the interlinks-subtree tree has a single leaf and the proof is
/// the degenerate single-index form (one empty-sibling marker).
#[test]
fn popow_single_interlink_validates_end_to_end() {
    let fx = find("popow_single_interlink");
    assert_eq!(fx.expected_proof_indices_count, 1);
    assert_eq!(fx.expected_proof_entry_count, 1);
    assert_happy(&fx);
}

/// 3-element interlinks vector with all-unique entries. Each becomes
/// its own kv-pair (idx 0/1/2, dup=1). Tree has 3 leaves.
#[test]
fn popow_three_unique_interlinks_validates_end_to_end() {
    let fx = find("popow_three_unique_interlinks");
    assert_eq!(fx.expected_proof_indices_count, 3);
    assert_happy(&fx);
}

/// Run-of-duplicates vector: three consecutive copies of one id
/// then a unique id. `packInterlinks` collapses the run into a
/// single kv-pair (idx=0, dup=3) plus the trailing (idx=3, dup=1)
/// pair. Tree has 2 leaves — pins the dup-run encoding parity in
/// the end-to-end path, not just the codec layer.
#[test]
fn popow_run_of_duplicates_validates_end_to_end() {
    let fx = find("popow_run_of_duplicates");
    // packInterlinks collapses the 3-run into 1 kv-pair, so the
    // proof has 2 indices for the 4-element interlinks vector.
    assert_eq!(fx.expected_proof_indices_count, 2);
    assert_eq!(fx.expected_proof_entry_count, 0);
    assert_happy(&fx);
}

/// 8-element interlinks vector with all-unique entries. Tree has
/// 8 leaves across 3 internal levels.
#[test]
fn popow_eight_unique_interlinks_validates_end_to_end() {
    let fx = find("popow_eight_unique_interlinks");
    assert_eq!(fx.expected_proof_indices_count, 8);
    assert_eq!(fx.expected_proof_entry_count, 0);
    assert_happy(&fx);
}

// ----- real mainnet captures -----

/// Real mainnet interlinks at height 700000 (21 raw entries, 12
/// unique kv-pairs after dup-run encoding). Pins parity on
/// realistic cardinality and on-chain dup patterns rather than
/// synthetic shapes.
///
/// Cross-references the fixture's interlinks vector against the
/// tracked extension corpus at
/// `test-vectors/mainnet/extensions_700000_700200.json` to confirm
/// the vector came from the on-chain extension fields, not
/// fabricated.
#[test]
fn mainnet_h700000_interlinks_validates_end_to_end() {
    let fx = find("mainnet_h700000_interlinks");
    assert_eq!(fx.interlinks.len(), 21);
    assert_eq!(fx.expected_proof_indices_count, 12);
    assert_provenance(
        &fx,
        "test-vectors/mainnet/extensions_700000_700200.json",
        700000,
    );
    assert_happy(&fx);
}

/// Real mainnet interlinks at height 1500000 (21 raw entries, 10
/// unique kv-pairs). Different epoch from h=700000 — pins parity
/// across chain depth.
///
/// Cross-references the fixture's interlinks vector against the
/// tracked extension corpus at `test-vectors/mainnet/extensions_1500000.json`
/// to confirm the vector came from the on-chain extension fields,
/// not fabricated.
#[test]
fn mainnet_h1500000_interlinks_validates_end_to_end() {
    let fx = find("mainnet_h1500000_interlinks");
    assert_eq!(fx.interlinks.len(), 21);
    assert_eq!(fx.expected_proof_indices_count, 10);
    assert_provenance(&fx, "test-vectors/mainnet/extensions_1500000.json", 1500000);
    assert_happy(&fx);
}

/// Cross-reference a `mainnet_*_interlinks` fixture's interlinks
/// vector against the tracked extension corpus at the named height.
/// Decodes the corpus's interlinks kv-fields (key prefix `0x01`),
/// expands the dup-count run encoding, and asserts the result is
/// byte-identical to the fixture's vector. Fails loudly if the
/// fixture provenance has drifted from the on-chain bytes the
/// corpus snapshot captured.
fn assert_provenance(fx: &Fixture, corpus_path: &str, target_height: u32) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .join(corpus_path);
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let corpus: serde_json::Value = serde_json::from_str(&raw).expect("extension json");
    let entries = corpus.as_array().expect("extension corpus is an array");
    let target = entries
        .iter()
        .find(|e| e["height"].as_u64() == Some(target_height as u64))
        .unwrap_or_else(|| panic!("{} has no entry for height {}", corpus_path, target_height,));
    let fields = target["fields"].as_array().expect("fields array");
    let mut unpacked: Vec<String> = Vec::new();
    for kv in fields {
        let k = kv[0].as_str().expect("field key");
        let v = kv[1].as_str().expect("field value");
        if k.starts_with("01") {
            let dup_count = u8::from_str_radix(&v[..2], 16).expect("dup hex");
            let mod_id = v[2..].to_string();
            for _ in 0..dup_count {
                unpacked.push(mod_id.clone());
            }
        }
    }
    assert_eq!(
        unpacked, fx.interlinks,
        "[{}] fixture interlinks diverge from tracked extension corpus at h={} — \
         fixture provenance is broken",
        fx.label, target_height,
    );
}

// ----- cryptographic binding (negative) -----

/// Flip one byte in the first interlink id; the reconstructed
/// interlinks-subtree root shifts, and `check_popow_header_interlinks_proof`
/// MUST return `false`. Pins that the proof is bound to the exact
/// interlinks vector, not accepted on shape alone.
#[test]
fn perturbed_interlinks_fails_end_to_end_validation() {
    let mut fx = find("popow_three_unique_interlinks");
    // Mutate the first interlink id's first byte.
    let mut bytes = hex::decode(&fx.interlinks[0]).expect("hex");
    bytes[0] ^= 0xFF;
    fx.interlinks[0] = hex::encode(&bytes);

    let popow = build_popow_header(&fx);
    assert!(
        !check_popow_header_interlinks_proof(&popow),
        "perturbed interlinks vector MUST fail the integrity check",
    );
}

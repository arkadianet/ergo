//! Oracle resolution for `ad_proofs_root` computation.
//!
//! Three hypotheses (H1, H2, H3) existed for how mainnet computes
//! `Header.adProofsRoot` from the raw `BatchAVLProver` proof bytes;
//! this test pins the resolution empirically against real mainnet
//! vectors.
//!
//! **Resolution: H1 wins.** `ad_proofs_root = blake2b256(raw_proof_bytes)`.
//! No length prefix, no header_id wrapper, no domain separation.
//!
//! Verified against 10 mainnet vectors captured from a Scala 6.0.2
//! node at height range 1,670,000–1,786,188, with block versions 4
//! (current protocol). Vectors live at
//! `test-vectors/mining/ad_proofs_root_corpus/{height}.json` and are
//! re-extractable from any Scala node REST: drive `/blocks/at/{h}` →
//! `/blocks/{id}` and read `header.adProofsRoot` plus
//! `adProofs.proofBytes`. The proof-byte hex string is passed verbatim
//! through hex-decode, then through `blake2b256`, and the result is
//! checked against the header's `adProofsRoot`.

use ergo_primitives::digest::blake2b256;
use serde::Deserialize;

#[derive(Deserialize)]
#[allow(dead_code)] // `transactions_root` / `state_root` / `n_transactions`
                    // are captured for Phase 1c (candidate_dry_run byte
                    // parity vs Scala). They aren't read by the AD-proof
                    // root oracle test itself but live in the vector files
                    // so the corpus doesn't have to be re-extracted later.
struct OracleVector {
    height: u32,
    header_id: String,
    ad_proofs_root: String,
    transactions_root: String,
    state_root: String,
    version: u8,
    n_transactions: u32,
    proof_bytes_hex: String,
}

const CORPUS_HEIGHTS: &[u32] = &[
    1_670_000, 1_700_000, 1_750_000, 1_780_000, 1_785_000, 1_786_000, 1_786_100, 1_786_180,
    1_786_185, 1_786_188,
];

fn load_vector(height: u32) -> OracleVector {
    let path = format!(
        "{}/../test-vectors/mining/ad_proofs_root_corpus/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        height
    );
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

#[test]
fn h1_blake2b256_of_raw_proof_bytes_matches_header_ad_proofs_root_corpus() {
    let mut matched = 0usize;
    for &h in CORPUS_HEIGHTS {
        let v = load_vector(h);
        assert_eq!(
            v.height, h,
            "vector file at height {h} reports inconsistent height {}",
            v.height
        );
        assert_eq!(v.version, 4, "corpus is block-version 4 only");

        let proof_bytes = hex::decode(&v.proof_bytes_hex)
            .unwrap_or_else(|e| panic!("decode proof hex at h={h}: {e}"));
        let expected_root = hex::decode(&v.ad_proofs_root)
            .unwrap_or_else(|e| panic!("decode root hex at h={h}: {e}"));
        assert_eq!(expected_root.len(), 32, "adProofsRoot must be 32 bytes");

        let computed_root = blake2b256(&proof_bytes);

        assert_eq!(
            computed_root.as_bytes(),
            &expected_root[..],
            "Block {} ({}): blake2b256(proofBytes) != header.adProofsRoot. \
             H1 hypothesis falsified.",
            v.height,
            v.header_id,
        );
        matched += 1;
    }
    assert_eq!(matched, CORPUS_HEIGHTS.len(), "corpus coverage incomplete");
}

#[test]
fn h2_length_prefix_falsification_negative_control() {
    // Sanity check: applying the wrong hypothesis (H2 = blake2b256 over
    // length-prefixed bytes) MUST disagree with the header's adProofsRoot.
    // This is a negative control so a future change to the H1 path
    // doesn't silently start matching the wrong formula.
    let v = load_vector(1_786_000);
    let proof_bytes = hex::decode(&v.proof_bytes_hex).expect("hex");
    let expected_root = hex::decode(&v.ad_proofs_root).expect("hex");

    let mut framed = Vec::with_capacity(4 + proof_bytes.len());
    framed.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&proof_bytes);
    let h2_root = blake2b256(&framed);

    assert_ne!(
        h2_root.as_bytes(),
        &expected_root[..],
        "H2 (length-prefixed) MUST disagree with header.adProofsRoot at h={}, \
         else the H1 conclusion is unsafe",
        v.height,
    );
}

//! Scala-oracle parity test for the NipopowProof + PoPowHeader +
//! BatchMerkleProof codecs. Loads a captured Scala-served proof
//! (real bytes from a mainnet peer) and asserts:
//!
//! 1. Deserialization succeeds.
//! 2. Re-serialization is byte-identical (the proof bytes we hold
//!    in memory round-trip back to the wire form Scala emitted).
//! 3. Every PoPowHeader's inner header parses as a valid Ergo
//!    header.
//! 4. Every PoPowHeader's interlinks_proof bytes parse as a valid
//!    BatchMerkleProof.
//!
//! The fixture lives at
//! `test-vectors/mainnet/nipopow_proof_capture.bin` (gitignored
//! filename pattern — operators capture once per dev workstation;
//! we may commit a curated version later if licensing/Scala-node
//! provenance allows).
//!
//! Capture procedure:
//! ```pwsh
//! $env:ERGO_CAPTURE_NIPOPOW_PROOF = "test-vectors/mainnet/nipopow_proof_capture.bin"
//! ./target/release/ergo-node.exe --config ergo-node/ergo-node.toml --data-dir ./ergo-data-capture
//! # Wait ~2 seconds for the first BetterChain log line, then Ctrl+C.
//! # The capture file is now populated.
//! ```
//!
//! When the fixture is absent the test passes vacuously — CI does
//! NOT require a capture, but a captured run on a developer
//! workstation surfaces wire-format drift instantly.

use std::path::Path;

const CAPTURE_PATH: &str = "../test-vectors/mainnet/nipopow_proof_capture.bin";

#[test]
fn captured_scala_proof_roundtrips_byte_identical() {
    let path = Path::new(CAPTURE_PATH);
    if !path.exists() {
        // Vacuous pass: no operator capture available yet. The
        // test surfaces nothing useful until a fixture is dropped
        // in — but doesn't fail CI. Re-run after capturing per
        // the docstring procedure.
        eprintln!(
            "[skipped] no Scala-oracle proof capture at {CAPTURE_PATH}; \
             see test docstring for capture procedure"
        );
        return;
    }

    let proof_bytes = std::fs::read(path).expect("capture file readable");
    let proof = ergo_ser::popow_proof::deserialize_nipopow_proof(&proof_bytes)
        .expect("captured Scala proof deserializes");

    // Re-serialize and compare byte-for-byte. Any drift indicates
    // a codec regression against Scala's wire format.
    let re_bytes =
        ergo_ser::popow_proof::serialize_nipopow_proof(&proof).expect("re-serialize succeeds");
    assert_eq!(
        re_bytes, proof_bytes,
        "re-serialized bytes must match Scala wire form byte-identically"
    );

    // Every prefix + suffix_head PoPowHeader's interlinks_proof
    // bytes must decode as a valid BatchMerkleProof. Skip the
    // suffix_tail entries — they are raw Header bytes, not
    // PoPowHeaders.
    for (i, popow_header) in proof.prefix.iter().enumerate() {
        if popow_header.interlinks_proof.is_empty() && popow_header.interlinks.is_empty() {
            continue; // Vacuous (e.g. genesis)
        }
        if !popow_header.interlinks_proof.is_empty() {
            ergo_ser::batch_merkle_proof::deserialize_batch_merkle_proof(
                &popow_header.interlinks_proof,
            )
            .unwrap_or_else(|e| panic!("prefix[{i}].interlinks_proof decode: {e}"));
        }
    }
    if !proof.suffix_head.interlinks_proof.is_empty() {
        ergo_ser::batch_merkle_proof::deserialize_batch_merkle_proof(
            &proof.suffix_head.interlinks_proof,
        )
        .unwrap_or_else(|e| panic!("suffix_head.interlinks_proof decode: {e}"));
    }

    eprintln!(
        "[scala-oracle] captured proof OK: m={}, k={}, prefix.len={}, suffix_tail.len={}, continuous={}",
        proof.m,
        proof.k,
        proof.prefix.len(),
        proof.suffix_tail.len(),
        proof.continuous,
    );
}

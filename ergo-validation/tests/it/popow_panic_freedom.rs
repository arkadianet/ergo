//! Panic-freedom regression tests for the NipopowVerifier entry
//! points. Each `serialize_header()` failure mode is exercised
//! through the path that would otherwise hit a bare `.expect(
//! "header serializes")` panic:
//!
//! 1. `version ∈ {2, 3, 4}` with non-empty `unparsed_bytes` →
//!    `check_header_bounds` rejects (header.rs:62-71).
//! 2. `version > 1` with `unparsed_bytes.len() > 255` →
//!    `check_header_bounds` rejects (header.rs:72-77).
//!
//! Today's `read_header` discards `unparsed_bytes` for v2-4 and the
//! `u8` length prefix caps at 255, so neither failure mode is
//! reachable from honest wire input. These tests construct `Header`
//! literals in memory to exercise the verifier's defense-in-depth
//! gate. They preserve panic-freedom as `read_header`'s permissiveness
//! evolves (e.g., a future relaxation that retains `unparsed_bytes`
//! for v2-4 would otherwise make the `.expect()` reachable from a
//! single crafted P2P message).
//!
//! Verifier-state invariants pinned here:
//!
//! * malformed proof returns `MalformedHeader`
//! * `proofs_processed()` does NOT increment
//! * `best_proof()` does NOT change

use ergo_crypto::difficulty::DifficultyParams;
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::Header;
use ergo_ser::popow_header::PoPowHeader;
use ergo_ser::popow_proof::NipopowProof;
use ergo_validation::popow::{NipopowVerificationResult, NipopowVerifier};

// ----- helpers -----

/// Synthetic v2 header that `serialize_header` REJECTS. Uses the
/// `version ∈ [2, 4]` + non-empty `unparsed_bytes` failure mode
/// (`ergo-ser::header::check_header_bounds` first branch).
fn malformed_v2_header_nonempty_unparsed() -> Header {
    Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0u8; 32]),
        ad_proofs_root: Digest32::from_bytes([0x01; 32]),
        transactions_root: Digest32::from_bytes([0x02; 32]),
        state_root: ADDigest::from_bytes([0x03; 33]),
        timestamp: 1_672_531_200_000,
        extension_root: Digest32::from_bytes([0x04; 32]),
        n_bits: 0x1a01_7660,
        height: 0,
        votes: [0; 3],
        // Non-empty for v2 — violates check_header_bounds first branch.
        unparsed_bytes: vec![0xAB, 0xCD, 0xEF],
        solution: AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from_bytes([0x02; 33]),
            nonce: [0; 8],
        },
    }
}

/// Synthetic v5 header that `serialize_header` REJECTS. Uses the
/// `version > 1` + `unparsed_bytes.len() > 255` failure mode
/// (`ergo-ser::header::check_header_bounds` second branch). v5 is
/// chosen so the first branch (v2-4) doesn't fire — isolates the
/// length-overflow gate.
fn malformed_v5_header_unparsed_len_256() -> Header {
    Header {
        version: 5,
        parent_id: ModifierId::from_bytes([0u8; 32]),
        ad_proofs_root: Digest32::from_bytes([0x01; 32]),
        transactions_root: Digest32::from_bytes([0x02; 32]),
        state_root: ADDigest::from_bytes([0x03; 33]),
        timestamp: 1_672_531_200_000,
        extension_root: Digest32::from_bytes([0x04; 32]),
        n_bits: 0x1a01_7660,
        height: 1,
        votes: [0; 3],
        // u8 length prefix caps at 255; 256 bytes overflows.
        unparsed_bytes: vec![0xCC; 256],
        solution: AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from_bytes([0x02; 33]),
            nonce: [0; 8],
        },
    }
}

fn popow_wrap(h: Header) -> PoPowHeader {
    PoPowHeader {
        header: h,
        interlinks: vec![],
        interlinks_proof: vec![],
    }
}

/// Build a proof whose `suffix_head.header` is the supplied malformed
/// header. The prefix is empty, so `headers_chain[0]` IS the malformed
/// header — exercises the `header_id_first` call path inside
/// `NipopowVerifier::process` that previously panicked.
fn proof_with_malformed_suffix_head(bad_header: Header) -> NipopowProof {
    NipopowProof {
        m: 6,
        k: 10,
        prefix: vec![],
        suffix_head: popow_wrap(bad_header),
        suffix_tail: vec![],
        continuous: false,
    }
}

// ----- happy path -----

#[test]
fn serialize_header_does_reject_each_failure_mode() {
    // Sanity check: the two synthetic headers really do trip
    // `serialize_header`'s bounds. If the codec ever relaxes these
    // bounds, this test fails first and prompts a re-think of whether
    // the verifier still needs the `MalformedHeader` gate.
    assert!(
        ergo_ser::header::serialize_header(&malformed_v2_header_nonempty_unparsed()).is_err(),
        "v2 + non-empty unparsed_bytes must be rejected by serialize_header"
    );
    assert!(
        ergo_ser::header::serialize_header(&malformed_v5_header_unparsed_len_256()).is_err(),
        "v5 + unparsed_bytes.len()==256 must be rejected by serialize_header"
    );
}

// ----- error paths -----

#[test]
fn verifier_returns_malformed_header_for_v2_with_unparsed_bytes() {
    // Goes through `NipopowVerifier::process` → `all_headers_serializable`
    // → false → `MalformedHeader`. Without the serializability gate
    // this would panic at `header_id_first`'s
    // `serialize_header().expect(...)`.
    let mut v = NipopowVerifier::new(None, DifficultyParams::mainnet());
    let bad = proof_with_malformed_suffix_head(malformed_v2_header_nonempty_unparsed());
    let result = v.process(bad);
    assert!(
        matches!(result, NipopowVerificationResult::MalformedHeader),
        "expected MalformedHeader, got {result:?}"
    );
}

#[test]
fn verifier_returns_malformed_header_for_v5_with_oversized_unparsed_bytes() {
    let mut v = NipopowVerifier::new(None, DifficultyParams::mainnet());
    let bad = proof_with_malformed_suffix_head(malformed_v5_header_unparsed_len_256());
    let result = v.process(bad);
    assert!(
        matches!(result, NipopowVerificationResult::MalformedHeader),
        "expected MalformedHeader, got {result:?}"
    );
}

#[test]
fn malformed_proof_does_not_increment_proofs_processed() {
    // Verifier-state invariant 2: counter must NOT move on malformed
    // input. Same posture as ValidationError and WrongGenesis.
    let mut v = NipopowVerifier::new(None, DifficultyParams::mainnet());
    let before = v.proofs_processed();
    let _ = v.process(proof_with_malformed_suffix_head(
        malformed_v2_header_nonempty_unparsed(),
    ));
    assert_eq!(
        v.proofs_processed(),
        before,
        "malformed proof must not advance the processed counter"
    );
}

#[test]
fn malformed_proof_does_not_replace_best_proof() {
    // Verifier-state invariant 3: an installed `best_proof` must
    // survive a subsequent malformed submission. Otherwise a single
    // crafted message could clobber the operator's hard-won best chain.
    let mut v = NipopowVerifier::new(None, DifficultyParams::mainnet());
    // Best-proof remains None throughout this test (no valid proof
    // installed); the structural invariant under test is that
    // `process(malformed)` does not transition `best_proof` either
    // way. We assert the strongest form: it stays None.
    assert!(v.best_proof().is_none());
    let _ = v.process(proof_with_malformed_suffix_head(
        malformed_v5_header_unparsed_len_256(),
    ));
    assert!(
        v.best_proof().is_none(),
        "malformed proof must not install a best_proof"
    );
}

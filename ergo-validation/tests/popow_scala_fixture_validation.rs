//! Full `is_valid` verification of the committed Scala-oracle proof
//! fixtures — REAL mainnet proofs, genuine Scala-serializer bytes (see
//! `scripts/jvm_nipopow_oracle/NipopowCapture.scala`).
//!
//! This is the recon's Risk-1 mitigation running in CI: every
//! BatchMerkleProof in a real 122-header prefix must verify against its
//! header's extension digest through our scrypto-parity reduction
//! (`verify_batch_merkle_proof`), the per-header PoW/level checks must
//! pass, and the continuous-mode difficulty-header window must be
//! satisfied — on proofs the Scala node actually served for mainnet.

use ergo_validation::popow::NipopowProofExt;

#[test]
fn committed_scala_fixtures_pass_full_validation() {
    let params = ergo_chain_spec::DifficultyParams::mainnet();
    let name = "../test-vectors/mainnet/nipopow/proof_m6_k10.scala.bin";
    let bytes = std::fs::read(name).unwrap_or_else(|e| panic!("read {name}: {e}"));
    let proof = ergo_ser::popow_proof::deserialize_nipopow_proof(&bytes)
        .unwrap_or_else(|e| panic!("{name}: deserialize: {e}"));
    assert!(
        proof.is_valid(&params),
        "{name}: a genuine Scala-served mainnet proof must pass our full validation"
    );
    eprintln!(
        "[fixture-validation] {name}: VALID (prefix={}, suffix_tail={})",
        proof.prefix.len(),
        proof.suffix_tail.len()
    );
}

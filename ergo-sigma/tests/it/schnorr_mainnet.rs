use ergo_sigma::schnorr::{verify_schnorr, SchnorrError};
use serde::Deserialize;

#[derive(Deserialize)]
struct SchnorrVector {
    tx_id: String,
    input_index: usize,
    pk: String,
    proof: String,
    bytes_to_sign: String,
    height: u32,
}

fn load_vectors(path: &str) -> Vec<SchnorrVector> {
    let data = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&data).unwrap()
}

// --- Positive corpus ---

#[test]
fn schnorr_verify_mainnet_proofs() {
    let vectors = load_vectors("../test-vectors/mainnet/schnorr_proofs_700000.json");
    assert!(vectors.len() >= 50, "need at least 50 vectors");

    let mut passed = 0;
    let mut failed = 0;

    for v in &vectors {
        let pk_bytes: [u8; 33] = hex::decode(&v.pk).unwrap().try_into().unwrap();
        let proof_bytes = hex::decode(&v.proof).unwrap();
        let message = hex::decode(&v.bytes_to_sign).unwrap();

        match verify_schnorr(&pk_bytes, &proof_bytes, &message) {
            Ok(()) => passed += 1,
            Err(e) => {
                eprintln!(
                    "FAIL: tx={} input={} height={} error={}",
                    v.tx_id, v.input_index, v.height, e
                );
                failed += 1;
            }
        }
    }

    assert_eq!(
        failed,
        0,
        "{failed}/{} proofs failed verification",
        vectors.len()
    );
    eprintln!("{passed}/{} Schnorr proofs verified", vectors.len());
}

// --- Negative corpus ---

#[test]
fn schnorr_reject_bad_challenge() {
    let vectors = load_vectors("../test-vectors/mainnet/schnorr_proofs_700000.json");
    for v in vectors.iter().take(10) {
        let pk_bytes: [u8; 33] = hex::decode(&v.pk).unwrap().try_into().unwrap();
        let mut proof = hex::decode(&v.proof).unwrap();
        let message = hex::decode(&v.bytes_to_sign).unwrap();

        proof[0] ^= 0xFF; // corrupt challenge
        assert!(
            verify_schnorr(&pk_bytes, &proof, &message).is_err(),
            "bad challenge should be rejected"
        );
    }
}

#[test]
fn schnorr_reject_bad_response() {
    let vectors = load_vectors("../test-vectors/mainnet/schnorr_proofs_700000.json");
    for v in vectors.iter().take(10) {
        let pk_bytes: [u8; 33] = hex::decode(&v.pk).unwrap().try_into().unwrap();
        let mut proof = hex::decode(&v.proof).unwrap();
        let message = hex::decode(&v.bytes_to_sign).unwrap();

        proof[24] ^= 0xFF; // corrupt response (first byte after challenge)
        assert!(
            verify_schnorr(&pk_bytes, &proof, &message).is_err(),
            "bad response should be rejected"
        );
    }
}

#[test]
fn schnorr_reject_wrong_pubkey() {
    let vectors = load_vectors("../test-vectors/mainnet/schnorr_proofs_700000.json");
    for v in vectors.iter().take(10) {
        let proof = hex::decode(&v.proof).unwrap();
        let message = hex::decode(&v.bytes_to_sign).unwrap();

        // Use a different valid public key (the generator)
        use k256::elliptic_curve::group::GroupEncoding;
        let g = k256::ProjectivePoint::GENERATOR;
        let g_bytes: [u8; 33] = g.to_affine().to_bytes().into();

        assert!(
            verify_schnorr(&g_bytes, &proof, &message).is_err(),
            "wrong pubkey should be rejected"
        );
    }
}

#[test]
fn schnorr_reject_wrong_message() {
    let vectors = load_vectors("../test-vectors/mainnet/schnorr_proofs_700000.json");
    for v in vectors.iter().take(10) {
        let pk_bytes: [u8; 33] = hex::decode(&v.pk).unwrap().try_into().unwrap();
        let proof = hex::decode(&v.proof).unwrap();
        let mut message = hex::decode(&v.bytes_to_sign).unwrap();

        message[0] ^= 0xFF; // corrupt message
        assert!(
            verify_schnorr(&pk_bytes, &proof, &message).is_err(),
            "wrong message should be rejected"
        );
    }
}

#[test]
fn schnorr_reject_truncated_proof() {
    let vectors = load_vectors("../test-vectors/mainnet/schnorr_proofs_700000.json");
    let v = &vectors[0];
    let pk_bytes: [u8; 33] = hex::decode(&v.pk).unwrap().try_into().unwrap();
    let proof = hex::decode(&v.proof).unwrap();
    let message = hex::decode(&v.bytes_to_sign).unwrap();

    let result = verify_schnorr(&pk_bytes, &proof[..55], &message);
    assert!(matches!(result, Err(SchnorrError::ProofTooShort { .. })));
}

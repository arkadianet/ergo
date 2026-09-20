use ergo_sigma::blake2b256;
use ergo_sigma::dht::{verify_dht, DhtError};
use ergo_sigma::{GROUP_SIZE, SOUNDNESS_BYTES};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use num_bigint::BigUint;

type DhtProofFixture = ([u8; 33], [u8; 33], [u8; 33], [u8; 33], Vec<u8>);

/// Generate a synthetic DHT proof for testing.
/// Prover knows `w` such that `u = g^w` and `v = h^w`.
fn generate_dht_proof(
    w: &Scalar,
    g: &ProjectivePoint,
    h: &ProjectivePoint,
    message: &[u8],
) -> DhtProofFixture {
    let u = g * w;
    let v = h * w;

    let g_bytes = point_to_33(g);
    let h_bytes = point_to_33(h);
    let u_bytes = point_to_33(&u);
    let v_bytes = point_to_33(&v);

    // Prover: pick random r, compute a = g^r, b = h^r
    let r = Scalar::from_repr(k256::FieldBytes::from([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
        0x32, 0x10,
    ]))
    .unwrap();

    let a = g * &r;
    let b = h * &r;
    let a_bytes = point_to_33(&a);
    let b_bytes = point_to_33(&b);

    // Build Fiat-Shamir input (matching the verifier's reconstruction)
    let prop_bytes = build_dht_prop_bytes(&g_bytes, &h_bytes, &u_bytes, &v_bytes);
    let mut commitment = Vec::with_capacity(66);
    commitment.extend_from_slice(&a_bytes);
    commitment.extend_from_slice(&b_bytes);

    let mut fs = Vec::new();
    fs.push(1u8); // leaf prefix
    fs.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
    fs.extend_from_slice(&prop_bytes);
    fs.extend_from_slice(&(commitment.len() as i16).to_be_bytes());
    fs.extend_from_slice(&commitment);

    let mut hash_input = fs;
    hash_input.extend_from_slice(message);
    let hash = blake2b256(&hash_input);
    let challenge = &hash[..SOUNDNESS_BYTES];

    // z = r + e*w mod q
    let e = challenge_to_scalar(challenge);
    let z = r + e * w;

    // Proof = challenge || z
    let mut proof = Vec::with_capacity(SOUNDNESS_BYTES + GROUP_SIZE);
    proof.extend_from_slice(challenge);
    let z_bytes = scalar_to_32(&z);
    proof.extend_from_slice(&z_bytes);

    (g_bytes, h_bytes, u_bytes, v_bytes, proof)
}

fn build_dht_prop_bytes(g: &[u8; 33], h: &[u8; 33], u: &[u8; 33], v: &[u8; 33]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(138);
    bytes.push(0x10);
    bytes.push(1);
    bytes.push(0x08);
    bytes.push(0xCE);
    bytes.extend_from_slice(g);
    bytes.extend_from_slice(h);
    bytes.extend_from_slice(u);
    bytes.extend_from_slice(v);
    bytes.push(0x73);
    bytes.push(0x00);
    bytes
}

fn point_to_33(p: &ProjectivePoint) -> [u8; 33] {
    p.to_affine().to_bytes().into()
}

fn scalar_to_32(s: &Scalar) -> [u8; 32] {
    s.to_repr().into()
}

fn challenge_to_scalar(challenge: &[u8]) -> Scalar {
    let e = BigUint::from_bytes_be(challenge);
    let mut out = [0u8; 32];
    let bytes = e.to_bytes_be();
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Scalar::from_repr(k256::FieldBytes::from(out)).unwrap()
}

// --- Positive tests ---

#[test]
fn dht_verify_synthetic_proof() {
    let w = Scalar::from_repr(k256::FieldBytes::from([
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0xBB, 0xCC,
    ]))
    .unwrap();

    let g = ProjectivePoint::GENERATOR;
    // Use a different generator h = g * some_scalar
    let h_scalar = Scalar::from_repr(k256::FieldBytes::from([
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
        0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
        0xDE, 0xF0,
    ]))
    .unwrap();
    let h = ProjectivePoint::mul_by_generator(&h_scalar);

    let message = b"test message for DHT proof verification";

    let (g_b, h_b, u_b, v_b, proof) = generate_dht_proof(&w, &g, &h, message);
    verify_dht(&g_b, &h_b, &u_b, &v_b, &proof, message).expect("valid DHT proof should verify");
}

#[test]
fn dht_verify_multiple_secrets() {
    // Verify with different secrets
    for seed in 1u8..=10 {
        let mut w_bytes = [0u8; 32];
        w_bytes[31] = seed;
        w_bytes[0] = seed.wrapping_mul(37);
        let w = Scalar::from_repr(k256::FieldBytes::from(w_bytes)).unwrap();

        let g = ProjectivePoint::GENERATOR;
        let mut h_seed = [0u8; 32];
        h_seed[31] = seed.wrapping_add(100);
        let h = ProjectivePoint::mul_by_generator(
            &Scalar::from_repr(k256::FieldBytes::from(h_seed)).unwrap(),
        );

        let message = format!("DHT test {seed}");
        let (g_b, h_b, u_b, v_b, proof) = generate_dht_proof(&w, &g, &h, message.as_bytes());
        verify_dht(&g_b, &h_b, &u_b, &v_b, &proof, message.as_bytes())
            .unwrap_or_else(|e| panic!("DHT proof {seed} failed: {e}"));
    }
}

// --- Negative tests ---

#[test]
fn dht_reject_bad_challenge() {
    let w = Scalar::from_repr(k256::FieldBytes::from([0x42u8; 32])).unwrap();
    let g = ProjectivePoint::GENERATOR;
    let h = ProjectivePoint::mul_by_generator(
        &Scalar::from_repr(k256::FieldBytes::from([0x77u8; 32])).unwrap(),
    );
    let message = b"bad challenge test";
    let (g_b, h_b, u_b, v_b, mut proof) = generate_dht_proof(&w, &g, &h, message);
    proof[0] ^= 0xFF;
    assert!(verify_dht(&g_b, &h_b, &u_b, &v_b, &proof, message).is_err());
}

#[test]
fn dht_reject_bad_response() {
    let w = Scalar::from_repr(k256::FieldBytes::from([0x42u8; 32])).unwrap();
    let g = ProjectivePoint::GENERATOR;
    let h = ProjectivePoint::mul_by_generator(
        &Scalar::from_repr(k256::FieldBytes::from([0x77u8; 32])).unwrap(),
    );
    let message = b"bad response test";
    let (g_b, h_b, u_b, v_b, mut proof) = generate_dht_proof(&w, &g, &h, message);
    proof[24] ^= 0xFF;
    assert!(verify_dht(&g_b, &h_b, &u_b, &v_b, &proof, message).is_err());
}

#[test]
fn dht_reject_wrong_tuple() {
    let w = Scalar::from_repr(k256::FieldBytes::from([0x42u8; 32])).unwrap();
    let g = ProjectivePoint::GENERATOR;
    let h = ProjectivePoint::mul_by_generator(
        &Scalar::from_repr(k256::FieldBytes::from([0x77u8; 32])).unwrap(),
    );
    let message = b"wrong tuple test";
    let (g_b, h_b, _u_b, v_b, proof) = generate_dht_proof(&w, &g, &h, message);
    // Use wrong u (the generator instead)
    let wrong_u: [u8; 33] = ProjectivePoint::GENERATOR.to_affine().to_bytes().into();
    assert!(verify_dht(&g_b, &h_b, &wrong_u, &v_b, &proof, message).is_err());
}

#[test]
fn dht_reject_wrong_message() {
    let w = Scalar::from_repr(k256::FieldBytes::from([0x42u8; 32])).unwrap();
    let g = ProjectivePoint::GENERATOR;
    let h = ProjectivePoint::mul_by_generator(
        &Scalar::from_repr(k256::FieldBytes::from([0x77u8; 32])).unwrap(),
    );
    let message = b"correct message";
    let (g_b, h_b, u_b, v_b, proof) = generate_dht_proof(&w, &g, &h, message);
    assert!(verify_dht(&g_b, &h_b, &u_b, &v_b, &proof, b"wrong message").is_err());
}

#[test]
fn dht_reject_truncated() {
    let w = Scalar::from_repr(k256::FieldBytes::from([0x42u8; 32])).unwrap();
    let g = ProjectivePoint::GENERATOR;
    let h = ProjectivePoint::mul_by_generator(
        &Scalar::from_repr(k256::FieldBytes::from([0x77u8; 32])).unwrap(),
    );
    let message = b"truncated test";
    let (g_b, h_b, u_b, v_b, proof) = generate_dht_proof(&w, &g, &h, message);
    assert!(matches!(
        verify_dht(&g_b, &h_b, &u_b, &v_b, &proof[..55], message),
        Err(DhtError::ProofTooShort { .. })
    ));
}

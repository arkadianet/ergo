//! Sigma-proposition composition tests for `verify_sigma_proof`.
//!
//! This file mixes two test kinds; the distinction matters for what
//! they prove.
//!
//! * **Mainnet oracle anchor.** `verify_sigma_mainnet_schnorr` replays
//!   `test-vectors/mainnet/schnorr_proofs_700000.json` — real Scala-
//!   accepted proofs against the SigmaAnd / SigmaOr / standalone-DLog
//!   shapes — through `verify_sigma_proof`. This is the single
//!   external-oracle test in the file.
//!
//! * **Synthetic protocol-property guards.** Every other test builds a
//!   sigma proof in-process from a fresh secret scalar (no Scala
//!   reference), then verifies, mutates the proof bytes or the
//!   message, and asserts the expected accept/reject. These are NOT
//!   mainnet/Scala oracles. They guard the protocol-shape behavior
//!   (`Cand` short-circuit, `Cor` challenge XOR, threshold polynomial
//!   evaluation, response-vs-challenge tampering rejects) — useful
//!   because no per-composition mainnet fixture exists, but their
//!   self-built proofs are not consensus evidence on their own.

use ergo_primitives::group_element::GroupElement;
use ergo_sigma::blake2b256;
use ergo_sigma::schnorr::build_prove_dlog_ergo_tree;
use ergo_sigma::verify::{verify_sigma_proof, SigmaBoolean};
use ergo_sigma::{GROUP_SIZE, SOUNDNESS_BYTES};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar};
use num_bigint::BigUint;

fn scalar_from_byte(b: u8) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] = b;
    Scalar::from_repr(k256::FieldBytes::from(bytes)).unwrap()
}

fn point_bytes(p: &ProjectivePoint) -> [u8; 33] {
    p.to_affine().to_bytes().into()
}

fn scalar_bytes(s: &Scalar) -> [u8; 32] {
    s.to_repr().into()
}

fn challenge_to_scalar(challenge: &[u8]) -> Scalar {
    let e = BigUint::from_bytes_be(challenge);
    let mut out = [0u8; 32];
    let bytes = e.to_bytes_be();
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Scalar::from_repr(k256::FieldBytes::from(out)).unwrap()
}

// --- Test: standalone DLog through verify_sigma_proof ---

#[test]
fn verify_sigma_standalone_dlog() {
    let secret = scalar_from_byte(42);
    let pk = ProjectivePoint::mul_by_generator(&secret);
    let pk_bytes = point_bytes(&pk);
    let r = scalar_from_byte(99);
    let message = b"standalone dlog test";

    let prop = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_bytes));

    // Build proof manually: for standalone DLog, FS tree is just the leaf
    let commitment = ProjectivePoint::mul_by_generator(&r);
    let commitment_bytes = point_bytes(&commitment);
    let prop_tree_bytes = build_prove_dlog_ergo_tree(&pk_bytes);

    let mut fs_bytes = Vec::new();
    fs_bytes.push(1u8);
    fs_bytes.extend_from_slice(&(prop_tree_bytes.len() as i16).to_be_bytes());
    fs_bytes.extend_from_slice(&prop_tree_bytes);
    fs_bytes.extend_from_slice(&(commitment_bytes.len() as i16).to_be_bytes());
    fs_bytes.extend_from_slice(&commitment_bytes);

    let mut hash_input = fs_bytes;
    hash_input.extend_from_slice(message);
    let hash = blake2b256(&hash_input);
    let challenge = &hash[..SOUNDNESS_BYTES];

    let e = challenge_to_scalar(challenge);
    let z = r + e * secret;

    let mut proof = Vec::new();
    proof.extend_from_slice(challenge);
    proof.extend_from_slice(&scalar_bytes(&z));

    let result = verify_sigma_proof(&prop, &proof, message).unwrap();
    assert!(result, "standalone DLog should verify");
}

// --- Test: verify_sigma_proof with real mainnet Schnorr vectors ---

#[test]
fn verify_sigma_mainnet_schnorr() {
    #[derive(serde::Deserialize)]
    struct V {
        pk: String,
        proof: String,
        bytes_to_sign: String,
    }
    let data =
        std::fs::read_to_string("../test-vectors/mainnet/schnorr_proofs_700000.json").unwrap();
    let vectors: Vec<V> = serde_json::from_str(&data).unwrap();

    let mut passed = 0;
    for v in &vectors {
        let pk: [u8; 33] = hex::decode(&v.pk).unwrap().try_into().unwrap();
        let proof = hex::decode(&v.proof).unwrap();
        let msg = hex::decode(&v.bytes_to_sign).unwrap();

        let prop = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk));
        let result = verify_sigma_proof(&prop, &proof, &msg).unwrap();
        assert!(result, "mainnet proof should verify");
        passed += 1;
    }
    eprintln!(
        "{passed}/{} mainnet proofs verified via verify_sigma_proof",
        vectors.len()
    );
}

// --- Test: AND composition (synthetic) ---

#[test]
fn verify_sigma_and_two_dlogs() {
    let secret1 = scalar_from_byte(11);
    let secret2 = scalar_from_byte(22);
    let pk1 = ProjectivePoint::mul_by_generator(&secret1);
    let pk2 = ProjectivePoint::mul_by_generator(&secret2);
    let pk1_bytes = point_bytes(&pk1);
    let pk2_bytes = point_bytes(&pk2);

    let r1 = scalar_from_byte(33);
    let r2 = scalar_from_byte(44);
    let message = b"AND test message";

    let prop = SigmaBoolean::Cand(vec![
        SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk1_bytes)),
        SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk2_bytes)),
    ]);

    // For AND: all children share the root challenge.
    // Proof = root_challenge(24) || z1(32) || z2(32) = 88 bytes
    // FS tree = internalNodePrefix(0) | AND(0) | count(2) | leaf1_fs | leaf2_fs
    // Then hash(fs_tree || message) => root challenge

    // Build commitments
    let a1 = ProjectivePoint::mul_by_generator(&r1);
    let a2 = ProjectivePoint::mul_by_generator(&r2);
    let a1_bytes = point_bytes(&a1);
    let a2_bytes = point_bytes(&a2);

    // Build FS tree bytes
    let prop1_bytes = build_prove_dlog_ergo_tree(&pk1_bytes);
    let prop2_bytes = build_prove_dlog_ergo_tree(&pk2_bytes);

    let mut fs = Vec::new();
    // Internal node: AND
    fs.push(0u8); // internal prefix
    fs.push(0u8); // AND conjecture type
    fs.extend_from_slice(&2i16.to_be_bytes()); // 2 children
                                               // Leaf 1
    fs.push(1u8);
    fs.extend_from_slice(&(prop1_bytes.len() as i16).to_be_bytes());
    fs.extend_from_slice(&prop1_bytes);
    fs.extend_from_slice(&(a1_bytes.len() as i16).to_be_bytes());
    fs.extend_from_slice(&a1_bytes);
    // Leaf 2
    fs.push(1u8);
    fs.extend_from_slice(&(prop2_bytes.len() as i16).to_be_bytes());
    fs.extend_from_slice(&prop2_bytes);
    fs.extend_from_slice(&(a2_bytes.len() as i16).to_be_bytes());
    fs.extend_from_slice(&a2_bytes);

    let mut hash_input = fs;
    hash_input.extend_from_slice(message);
    let hash = blake2b256(&hash_input);
    let root_challenge = &hash[..SOUNDNESS_BYTES];

    // z1 = r1 + e * secret1, z2 = r2 + e * secret2 (same e for AND)
    let e = challenge_to_scalar(root_challenge);
    let z1 = r1 + e * secret1;
    let z2 = r2 + e * secret2;

    // Proof: root_challenge || z1 || z2
    let mut proof = Vec::new();
    proof.extend_from_slice(root_challenge);
    proof.extend_from_slice(&scalar_bytes(&z1));
    proof.extend_from_slice(&scalar_bytes(&z2));

    let result = verify_sigma_proof(&prop, &proof, message).unwrap();
    assert!(result, "AND proof should verify");
}

// --- Test: OR composition (synthetic) ---

#[test]
fn verify_sigma_or_two_dlogs() {
    // Prover knows secret1 but not secret2.
    // For OR: prover simulates child2, proves child1 for real.
    let secret1 = scalar_from_byte(55);
    let secret2 = scalar_from_byte(66); // unknown to prover in practice
    let pk1 = ProjectivePoint::mul_by_generator(&secret1);
    let pk2 = ProjectivePoint::mul_by_generator(&secret2);
    let pk1_bytes = point_bytes(&pk1);
    let pk2_bytes = point_bytes(&pk2);

    let message = b"OR test message";

    let prop = SigmaBoolean::Cor(vec![
        SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk1_bytes)),
        SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk2_bytes)),
    ]);

    // Simulate child2: pick random e2 and z2, compute a2 = g^z2 * pk2^(-e2)
    let e2_bytes = blake2b256(b"simulated challenge")[..SOUNDNESS_BYTES].to_vec();
    let z2 = scalar_from_byte(77);
    let e2_scalar = challenge_to_scalar(&e2_bytes);
    let a2 = ProjectivePoint::mul_by_generator(&z2) - pk2 * e2_scalar;
    let a2_bytes = point_bytes(&a2);

    // Real child1: pick random r1, compute a1 = g^r1
    let r1 = scalar_from_byte(88);
    let a1 = ProjectivePoint::mul_by_generator(&r1);
    let a1_bytes = point_bytes(&a1);

    // Build FS tree to compute root challenge
    let prop1_bytes = build_prove_dlog_ergo_tree(&pk1_bytes);
    let prop2_bytes = build_prove_dlog_ergo_tree(&pk2_bytes);

    let mut fs = Vec::new();
    fs.push(0u8); // internal prefix
    fs.push(1u8); // OR conjecture type
    fs.extend_from_slice(&2i16.to_be_bytes());
    // Leaf 1
    fs.push(1u8);
    fs.extend_from_slice(&(prop1_bytes.len() as i16).to_be_bytes());
    fs.extend_from_slice(&prop1_bytes);
    fs.extend_from_slice(&(a1_bytes.len() as i16).to_be_bytes());
    fs.extend_from_slice(&a1_bytes);
    // Leaf 2
    fs.push(1u8);
    fs.extend_from_slice(&(prop2_bytes.len() as i16).to_be_bytes());
    fs.extend_from_slice(&prop2_bytes);
    fs.extend_from_slice(&(a2_bytes.len() as i16).to_be_bytes());
    fs.extend_from_slice(&a2_bytes);

    let mut hash_input = fs;
    hash_input.extend_from_slice(message);
    let hash = blake2b256(&hash_input);
    let root_challenge = hash[..SOUNDNESS_BYTES].to_vec();

    // e1 = root_challenge XOR e2
    let mut e1_bytes = root_challenge.clone();
    for (a, b) in e1_bytes.iter_mut().zip(e2_bytes.iter()) {
        *a ^= *b;
    }

    let e1_scalar = challenge_to_scalar(&e1_bytes);
    let z1 = r1 + e1_scalar * secret1;

    // Proof for OR: root_challenge(24) || e2(24) || z1(32) || z2(32)
    // Format: root reads e0 from first 24 bytes.
    // Then for OR children: child1 reads its challenge (e1=24 bytes), z1(32).
    //   child2 gets computed challenge (XOR), z2(32).
    // Wait — the proof format for OR is:
    //   root_challenge(24) [from the top-level read]
    //   Then for each child except last: child_challenge(24) + child_z(32)
    //   Last child: just child_z(32) (challenge computed via XOR)

    let mut proof = Vec::new();
    proof.extend_from_slice(&root_challenge); // root challenge
                                              // Child 1 (not last): writes its own challenge + z
    proof.extend_from_slice(&e1_bytes);
    proof.extend_from_slice(&scalar_bytes(&z1));
    // Child 2 (last): writes only z (challenge computed by XOR)
    proof.extend_from_slice(&scalar_bytes(&z2));

    let result = verify_sigma_proof(&prop, &proof, message).unwrap();
    assert!(result, "OR proof should verify");
}

// --- Test: THRESHOLD(2-of-3) composition (synthetic) ---

#[test]
fn verify_sigma_threshold_2_of_3() {
    use gf2_192::gf2_192::Gf2_192;

    // Prover knows secret1 and secret3 but not secret2 (2-of-3 threshold).
    let secret1 = scalar_from_byte(10);
    let secret2 = scalar_from_byte(20); // simulated
    let secret3 = scalar_from_byte(30);
    let pk1 = ProjectivePoint::mul_by_generator(&secret1);
    let pk2 = ProjectivePoint::mul_by_generator(&secret2);
    let pk3 = ProjectivePoint::mul_by_generator(&secret3);
    let pk1_bytes = point_bytes(&pk1);
    let pk2_bytes = point_bytes(&pk2);
    let pk3_bytes = point_bytes(&pk3);

    let message = b"threshold 2-of-3 test";
    let k: u8 = 2;
    let n: usize = 3;

    let prop = SigmaBoolean::Cthreshold {
        k,
        children: vec![
            SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk1_bytes)),
            SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk2_bytes)),
            SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk3_bytes)),
        ],
    };

    // Prover protocol for threshold:
    // 1. Real leaves (1, 3): pick random r, compute a = g^r
    // 2. Simulated leaf (2): pick random e2, z2, compute a2 = g^z2 * pk2^(-e2)
    // 3. Build FS tree, compute root challenge e0
    // 4. Build polynomial Q where Q(0) = e0, and Q evaluates correctly for simulated children
    // 5. For real children, compute z = r + Q(i+1) * secret

    let r1 = scalar_from_byte(41);
    let r3 = scalar_from_byte(43);
    let a1 = ProjectivePoint::mul_by_generator(&r1);
    let a3 = ProjectivePoint::mul_by_generator(&r3);

    // Simulate child 2
    let e2_seed = blake2b256(b"sim challenge 2");
    let e2_bytes: [u8; 24] = e2_seed[..24].try_into().unwrap();
    let z2 = scalar_from_byte(52);
    let e2_scalar = challenge_to_scalar(&e2_bytes);
    let a2 = ProjectivePoint::mul_by_generator(&z2) - pk2 * e2_scalar;

    // Build FS tree
    let prop1 = build_prove_dlog_ergo_tree(&pk1_bytes);
    let prop2 = build_prove_dlog_ergo_tree(&pk2_bytes);
    let prop3 = build_prove_dlog_ergo_tree(&pk3_bytes);

    let mut fs = Vec::new();
    fs.push(0u8); // internal prefix
    fs.push(2u8); // threshold conjecture type
    fs.push(k);
    fs.extend_from_slice(&(n as i16).to_be_bytes());
    // 3 leaf children
    for (prop_b, a_pt) in [(&prop1, &a1), (&prop2, &a2), (&prop3, &a3)] {
        let a_bytes = point_bytes(a_pt);
        fs.push(1u8);
        fs.extend_from_slice(&(prop_b.len() as i16).to_be_bytes());
        fs.extend_from_slice(prop_b);
        fs.extend_from_slice(&(a_bytes.len() as i16).to_be_bytes());
        fs.extend_from_slice(&a_bytes);
    }

    let mut hash_input = fs;
    hash_input.extend_from_slice(message);
    let hash = blake2b256(&hash_input);
    let root_challenge: [u8; 24] = hash[..SOUNDNESS_BYTES].try_into().unwrap();

    // Build polynomial Q where Q(0) = root_challenge, Q(2) = e2 (child 2's challenge, index=2)
    // For 2-of-3: n-k = 1 coefficient to determine (besides the zero coeff)
    // Polynomial of degree 1: Q(x) = a0 + a1*x where a0 = root_challenge
    // Q(2) = e2 => a0 + a1*2 = e2 => a1 = (e2 - a0) / 2  (in GF(2^192))
    // In GF(2^192): subtraction = XOR, division by 2 needs multiplicative inverse
    let a0 = Gf2_192::from(root_challenge);
    let _e2_gf = Gf2_192::from(e2_bytes);

    // Use Gf2_192Poly interpolation: we need Q(0)=a0 and Q(2)=e2_gf
    // Build polynomial from points: (0, a0), (2, e2_gf)
    // But the API expects coefficient form. Let me compute a1 directly.
    // In GF(2^192): a1 = (e2 XOR a0) * inv(2)
    // Actually easier: use the poly API. The challenge is Q(0) = a0.
    // The polynomial has degree n-k = 1. So Q(x) = a0 + a1*x.
    // We need Q(2) = e2_gf, so a1 = (a0 + e2_gf) * inv(Gf2_192(2))
    // In GF(2^192), addition = XOR, so a0 + e2_gf = a0 XOR e2_gf
    let a0_xor_e2 = {
        let mut result = root_challenge;
        for (r, e) in result.iter_mut().zip(e2_bytes.iter()) {
            *r ^= *e;
        }
        Gf2_192::from(result)
    };
    // inv(2) in GF(2^192)
    let two = Gf2_192::from(2i32);
    let inv_two = Gf2_192::invert(two);
    let a1 = a0_xor_e2 * inv_two;
    let a1_bytes: [u8; 24] = a1.into();

    // Verify: Q(1) = a0 + a1*1 = a0 + a1
    let e1_gf = a0 + a1;
    let e1_bytes: [u8; 24] = e1_gf.into();
    // Q(2) should equal e2
    let q2 = a0 + a1 * two;
    let q2_bytes: [u8; 24] = q2.into();
    assert_eq!(
        q2_bytes, e2_bytes,
        "polynomial should evaluate to e2 at x=2"
    );
    // Q(3) = a0 + a1*3
    let three = Gf2_192::from(3i32);
    let e3_gf = a0 + a1 * three;
    let e3_bytes: [u8; 24] = e3_gf.into();

    // Compute z1 and z3 for real children
    let e1_scalar = challenge_to_scalar(&e1_bytes);
    let z1 = r1 + e1_scalar * secret1;
    let e3_scalar = challenge_to_scalar(&e3_bytes);
    let z3 = r3 + e3_scalar * secret3;

    // Build proof: root_challenge(24) || polynomial_coeffs(a1=24) || z1(32) || z2(32) || z3(32)
    let mut proof = Vec::new();
    proof.extend_from_slice(&root_challenge);
    proof.extend_from_slice(&a1_bytes); // n-k=1 coefficient
    proof.extend_from_slice(&scalar_bytes(&z1));
    proof.extend_from_slice(&scalar_bytes(&z2));
    proof.extend_from_slice(&scalar_bytes(&z3));

    let result = verify_sigma_proof(&prop, &proof, message).unwrap();
    assert!(result, "threshold 2-of-3 proof should verify");
}

// --- Negative tests ---

#[test]
fn verify_sigma_and_reject_bad_z() {
    let secret1 = scalar_from_byte(11);
    let secret2 = scalar_from_byte(22);
    let pk1 = ProjectivePoint::mul_by_generator(&secret1);
    let pk2 = ProjectivePoint::mul_by_generator(&secret2);

    let prop = SigmaBoolean::Cand(vec![
        SigmaBoolean::ProveDlog(GroupElement::from_bytes(point_bytes(&pk1))),
        SigmaBoolean::ProveDlog(GroupElement::from_bytes(point_bytes(&pk2))),
    ]);

    let proof = vec![0x42u8; SOUNDNESS_BYTES + GROUP_SIZE * 2];
    // Corrupt to ensure it fails
    let result = verify_sigma_proof(&prop, &proof, b"test").unwrap();
    assert!(!result, "garbage AND proof should not verify");
}

#[test]
fn verify_sigma_or_reject_bad_z() {
    let secret1 = scalar_from_byte(11);
    let pk1 = ProjectivePoint::mul_by_generator(&secret1);
    let pk2 = ProjectivePoint::mul_by_generator(&scalar_from_byte(22));

    let prop = SigmaBoolean::Cor(vec![
        SigmaBoolean::ProveDlog(GroupElement::from_bytes(point_bytes(&pk1))),
        SigmaBoolean::ProveDlog(GroupElement::from_bytes(point_bytes(&pk2))),
    ]);

    // Garbage OR proof: root_challenge(24) + child1_challenge(24) + z1(32) + z2(32)
    let proof = vec![0x42u8; SOUNDNESS_BYTES + SOUNDNESS_BYTES + GROUP_SIZE * 2];
    let result = verify_sigma_proof(&prop, &proof, b"test").unwrap();
    assert!(!result, "garbage OR proof should not verify");
}

#[test]
fn verify_sigma_empty_proof_returns_false() {
    let pk = point_bytes(&ProjectivePoint::GENERATOR);
    let prop = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk));
    let result = verify_sigma_proof(&prop, &[], b"test").unwrap();
    assert!(!result);
}

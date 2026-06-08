//! Schnorr + DHT prover/verifier internal-consistency tests.
//!
//! These tests confirm that our prover produces proofs that our `ergo_sigma`
//! verifier accepts. They are NOT a Scala oracle — they prove the round-trip
//! is internally consistent, not that the bytes match what Scala would
//! produce. Byte-level Scala interoperability lives in
//! `proving_scala_oracle.rs`.
//!
//! Fixture secret: BIP32 Vector 1 master secret key
//!   `e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35`
//! Corresponding public key is derived in each test via `g^secret`.

use ergo_primitives::group_element::GroupElement;
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::verify::verify_sigma_proof;
use ergo_wallet::proving::dht::prove_dht;
use ergo_wallet::proving::hints::{FirstProverMessage, Hint, HintsBag, OwnCommitment};
use ergo_wallet::proving::node_position::NodePosition;
use ergo_wallet::proving::randomness::{ProvingRng, Sha256DerivedRng};
use ergo_wallet::proving::schnorr::prove_schnorr;
use ergo_wallet::proving::secrets::SecretRegistry;
use ergo_wallet::proving::sigma::prove_sigma;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::{MulByGenerator, Reduce};
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, Scalar, U256};

/// BIP32 Vector 1 master secret (32 bytes, big-endian).
const SECRET_HEX: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";

fn bip32_v1_secret() -> Scalar {
    let bytes = hex::decode(SECRET_HEX).unwrap();
    let arr: [u8; 32] = bytes.try_into().unwrap();
    Scalar::from_repr(FieldBytes::from(arr)).expect("known valid scalar")
}

fn pubkey_from_scalar(s: &Scalar) -> [u8; 33] {
    let pt = ProjectivePoint::mul_by_generator(s);
    pt.to_affine().to_bytes().into()
}

fn dlog_proposition(pk: &[u8; 33]) -> SigmaBoolean {
    SigmaBoolean::ProveDlog(GroupElement::from_bytes(*pk))
}

fn deterministic_rng(label: &[u8]) -> Sha256DerivedRng {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"proving_self_oracle:");
    h.update(label);
    let seed: [u8; 32] = h.finalize().into();
    Sha256DerivedRng::from_seed(seed)
}

/// Derive a secp256k1 scalar deterministically from a seed byte.
/// Used to create independent test secrets beyond the BIP32 V1 fixture.
fn test_scalar(seed: u8) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[1] = 0x42;
    bytes[2] = 0xAB;
    bytes[31] = seed.wrapping_mul(7).wrapping_add(3);
    <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into())
}

// ----- helpers -----

/// Build a DHT proposition for secret `x`:
///   g = secp256k1 generator, h = h_scalar*G (fixed), u = x*g, v = x*h.
fn dht_proposition(x: &Scalar) -> (SigmaBoolean, Scalar) {
    let g_pt = ProjectivePoint::GENERATOR;
    let h_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&[0xABu8; 32].into());
    let h_pt = ProjectivePoint::mul_by_generator(&h_scalar);
    let u_pt = g_pt * x;
    let v_pt = h_pt * x;

    let g_bytes: [u8; 33] = g_pt.to_affine().to_bytes().into();
    let h_bytes: [u8; 33] = h_pt.to_affine().to_bytes().into();
    let u_bytes: [u8; 33] = u_pt.to_affine().to_bytes().into();
    let v_bytes: [u8; 33] = v_pt.to_affine().to_bytes().into();

    let prop = SigmaBoolean::ProveDHTuple {
        g: GroupElement::from_bytes(g_bytes),
        h: GroupElement::from_bytes(h_bytes),
        u: GroupElement::from_bytes(u_bytes),
        v: GroupElement::from_bytes(v_bytes),
    };
    (prop, h_scalar)
}

/// Build a registry containing a single DLog secret.
fn registry_with_dlog(pk: &[u8; 33], secret: Scalar) -> SecretRegistry {
    let mut reg = SecretRegistry::empty();
    // Use merge_external_secrets via the ProverExternalSecret path.
    use ergo_wallet::proving::external::ProverExternalSecret;
    reg = reg
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: *pk,
            scalar: secret.into(),
        }])
        .unwrap();
    reg
}

/// Build a registry containing multiple DLog secrets.
fn registry_with_dlogs(pairs: &[([u8; 33], Scalar)]) -> SecretRegistry {
    use ergo_wallet::proving::external::ProverExternalSecret;
    let externals: Vec<_> = pairs
        .iter()
        .map(|(pk, s)| ProverExternalSecret::Dlog {
            pk: *pk,
            scalar: (*s).into(),
        })
        .collect();
    SecretRegistry::empty()
        .merge_external_secrets(&externals)
        .unwrap()
}

/// Build a registry containing a single DHT secret.
fn registry_with_dht(prop: &SigmaBoolean, secret: Scalar) -> SecretRegistry {
    use ergo_wallet::proving::external::ProverExternalSecret;
    match prop {
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            let ext = ProverExternalSecret::DhTuple {
                g: *g.as_bytes(),
                h: *h.as_bytes(),
                u: *u.as_bytes(),
                v: *v.as_bytes(),
                scalar: secret.into(),
            };
            SecretRegistry::empty()
                .merge_external_secrets(&[ext])
                .unwrap()
        }
        _ => panic!("expected ProveDHTuple"),
    }
}

fn cand(children: Vec<SigmaBoolean>) -> SigmaBoolean {
    SigmaBoolean::Cand(children)
}

fn cor(children: Vec<SigmaBoolean>) -> SigmaBoolean {
    SigmaBoolean::Cor(children)
}

fn cthreshold(k: u8, children: Vec<SigmaBoolean>) -> SigmaBoolean {
    SigmaBoolean::Cthreshold { k, children }
}

// ----- happy path -----

#[test]
fn schnorr_proof_self_verifies() {
    let secret = bip32_v1_secret();
    let pk = pubkey_from_scalar(&secret);
    let prop = dlog_proposition(&pk);
    let message = b"test message for schnorr self-oracle";
    let mut rng = deterministic_rng(b"happy_path");

    let proof = prove_schnorr(
        &prop,
        &secret,
        message,
        &HintsBag::empty(),
        NodePosition::crypto_tree_prefix(),
        &mut rng,
    )
    .expect("prove_schnorr should succeed");

    assert_eq!(
        proof.len(),
        56,
        "proof must be 56 bytes (24 challenge + 32 z)"
    );
    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "proof must verify");
}

// ----- error paths -----

#[test]
fn schnorr_proof_rejects_wrong_message() {
    let secret = bip32_v1_secret();
    let pk = pubkey_from_scalar(&secret);
    let prop = dlog_proposition(&pk);
    let message = b"correct message";
    let mut rng = deterministic_rng(b"wrong_message");

    let proof = prove_schnorr(
        &prop,
        &secret,
        message,
        &HintsBag::empty(),
        NodePosition::crypto_tree_prefix(),
        &mut rng,
    )
    .expect("prove_schnorr should succeed");

    let bad_message = b"wrong message";
    let ok = verify_sigma_proof(&prop, &proof, bad_message).expect("verify should not error");
    assert!(!ok, "proof against wrong message must not verify");
}

#[test]
fn schnorr_proof_rejects_wrong_pubkey() {
    let secret = bip32_v1_secret();
    let pk = pubkey_from_scalar(&secret);
    let prop = dlog_proposition(&pk);
    let message = b"message";
    let mut rng = deterministic_rng(b"wrong_pubkey");

    let proof = prove_schnorr(
        &prop,
        &secret,
        message,
        &HintsBag::empty(),
        NodePosition::crypto_tree_prefix(),
        &mut rng,
    )
    .expect("prove_schnorr should succeed");

    // Different scalar → different pubkey → different proposition
    let other_secret = <Scalar as Reduce<U256>>::reduce_bytes(&[0x42u8; 32].into());
    let other_pk = pubkey_from_scalar(&other_secret);
    let other_prop = dlog_proposition(&other_pk);

    let ok = verify_sigma_proof(&other_prop, &proof, message).expect("verify should not error");
    assert!(!ok, "proof under wrong pubkey must not verify");
}

#[test]
fn schnorr_rejects_non_dlog_proposition() {
    use ergo_wallet::WalletError;

    let secret = bip32_v1_secret();
    let message = b"message";
    let prop = SigmaBoolean::TrivialProp(true);
    let mut rng = deterministic_rng(b"non_dlog");

    let result = prove_schnorr(
        &prop,
        &secret,
        message,
        &HintsBag::empty(),
        NodePosition::crypto_tree_prefix(),
        &mut rng,
    );
    assert!(
        matches!(result, Err(WalletError::MissingSecret(_))),
        "non-Dlog proposition must return MissingSecret, got {result:?}",
    );
}

// ----- DHT happy path -----

#[test]
fn dht_proof_self_verifies() {
    let secret = bip32_v1_secret();
    let (prop, _) = dht_proposition(&secret);
    let message = b"test message for dht self-oracle";
    let mut rng = deterministic_rng(b"dht_happy_path");

    let proof = prove_dht(
        &prop,
        &secret,
        message,
        &HintsBag::empty(),
        NodePosition::crypto_tree_prefix(),
        &mut rng,
    )
    .expect("prove_dht should succeed");

    assert_eq!(
        proof.len(),
        56,
        "DHT proof must be 56 bytes (24 challenge + 32 z)"
    );
    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "DHT proof must verify");
}

// ----- DHT error paths -----

#[test]
fn dht_proof_rejects_wrong_message() {
    let secret = bip32_v1_secret();
    let (prop, _) = dht_proposition(&secret);
    let message = b"correct message for dht";
    let mut rng = deterministic_rng(b"dht_wrong_message");

    let proof = prove_dht(
        &prop,
        &secret,
        message,
        &HintsBag::empty(),
        NodePosition::crypto_tree_prefix(),
        &mut rng,
    )
    .expect("prove_dht should succeed");

    let bad_message = b"wrong message for dht";
    let ok = verify_sigma_proof(&prop, &proof, bad_message).expect("verify should not error");
    assert!(!ok, "DHT proof against wrong message must not verify");
}

#[test]
fn dht_rejects_non_dht_proposition() {
    use ergo_wallet::WalletError;

    let secret = bip32_v1_secret();
    let pk = pubkey_from_scalar(&secret);
    let dlog_prop = dlog_proposition(&pk);
    let message = b"message";
    let mut rng = deterministic_rng(b"dht_non_dht");

    let result = prove_dht(
        &dlog_prop,
        &secret,
        message,
        &HintsBag::empty(),
        NodePosition::crypto_tree_prefix(),
        &mut rng,
    );
    assert!(
        matches!(result, Err(WalletError::MissingSecret(_))),
        "non-DHT proposition must return MissingSecret, got {result:?}",
    );
}

// ----- DHT multi-sig path -----

#[test]
fn dht_uses_own_commitment_from_bag() {
    let secret = bip32_v1_secret();
    let (prop, _) = dht_proposition(&secret);
    let message = b"dht multi-sig path message";

    // Pre-generate r deterministically and supply it as OwnCommitment.
    // OwnCommitment now stores the full DhTuple commitment (A, B) = (g^r, h^r)
    // so prove_dht uses the stored points verbatim rather than recomputing from r.
    let mut rng_for_r = deterministic_rng(b"dht_multi_sig_r");
    let r_scalar = rng_for_r.sample_scalar();
    let r_bytes: [u8; 32] = r_scalar.to_bytes().into();

    // Extract g and h from the proposition to compute both commitment points.
    let (g_bytes_prop, h_bytes_prop) = match &prop {
        SigmaBoolean::ProveDHTuple { g, h, .. } => (*g.as_bytes(), *h.as_bytes()),
        _ => panic!("expected ProveDHTuple"),
    };
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let g_pt_prop = {
        let ep = k256::EncodedPoint::from_bytes(g_bytes_prop).unwrap();
        k256::AffinePoint::from_encoded_point(&ep).unwrap()
    };
    let h_pt_prop = {
        let ep = k256::EncodedPoint::from_bytes(h_bytes_prop).unwrap();
        k256::AffinePoint::from_encoded_point(&ep).unwrap()
    };
    let a_bytes: [u8; 33] = (ProjectivePoint::from(g_pt_prop) * r_scalar)
        .to_affine()
        .to_bytes()
        .into();
    let b_bytes: [u8; 33] = (ProjectivePoint::from(h_pt_prop) * r_scalar)
        .to_affine()
        .to_bytes()
        .into();

    let mut bag = HintsBag::empty();
    bag.add(Hint::OwnCommitment(OwnCommitment {
        image: prop.clone(),
        secret_randomness: r_bytes,
        commitment: FirstProverMessage::DhTuple {
            a: a_bytes,
            b: b_bytes,
        },
        position: NodePosition::crypto_tree_prefix(),
    }));

    let mut rng = deterministic_rng(b"dht_multi_sig_main");
    let proof = prove_dht(
        &prop,
        &secret,
        message,
        &bag,
        NodePosition::crypto_tree_prefix(),
        &mut rng,
    )
    .expect("prove_dht with OwnCommitment should succeed");

    assert_eq!(proof.len(), 56);
    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "DHT proof using hints-bag OwnCommitment must verify");

    // Same bag → same r → same proof bytes (deterministic Fiat-Shamir).
    let mut rng2 = deterministic_rng(b"dht_multi_sig_main2");
    let proof2 = prove_dht(
        &prop,
        &secret,
        message,
        &bag,
        NodePosition::crypto_tree_prefix(),
        &mut rng2,
    )
    .expect("prove_dht should succeed");
    assert_eq!(
        proof, proof2,
        "same OwnCommitment → identical DHT proof bytes"
    );
}

// ----- multi-sig path -----

#[test]
fn schnorr_uses_own_commitment_from_hints_bag() {
    let secret = bip32_v1_secret();
    let pk = pubkey_from_scalar(&secret);
    let prop = dlog_proposition(&pk);
    let message = b"multi-sig path message";

    // Pre-generate a real commitment (r, R) deterministically.
    let mut rng_for_r = deterministic_rng(b"multi_sig_r");
    let r_scalar = rng_for_r.sample_scalar();
    use k256::elliptic_curve::group::GroupEncoding;
    let r_point: [u8; 33] = ProjectivePoint::mul_by_generator(&r_scalar)
        .to_affine()
        .to_bytes()
        .into();
    let r_bytes: [u8; 32] = r_scalar.to_bytes().into();

    let mut bag = HintsBag::empty();
    bag.add(Hint::OwnCommitment(OwnCommitment {
        image: prop.clone(),
        secret_randomness: r_bytes,
        commitment: FirstProverMessage::Schnorr(r_point),
        position: NodePosition::crypto_tree_prefix(),
    }));

    // RNG should not be called for r since OwnCommitment supplies it.
    // Use a second deterministic RNG to confirm reproducibility.
    let mut rng = deterministic_rng(b"multi_sig_main");
    let proof = prove_schnorr(
        &prop,
        &secret,
        message,
        &bag,
        NodePosition::crypto_tree_prefix(),
        &mut rng,
    )
    .expect("prove_schnorr should succeed");

    assert_eq!(proof.len(), 56);
    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "proof using hints-bag OwnCommitment must verify");

    // Prove again with same bag — must produce identical proof (deterministic r).
    let mut rng2 = deterministic_rng(b"multi_sig_main2");
    let proof2 = prove_schnorr(
        &prop,
        &secret,
        message,
        &bag,
        NodePosition::crypto_tree_prefix(),
        &mut rng2,
    )
    .expect("prove_schnorr should succeed");
    assert_eq!(
        proof, proof2,
        "same OwnCommitment → identical proof bytes (deterministic Fiat-Shamir)"
    );
}

// ----- compound sigma proofs (Group C.4) -----

#[test]
fn and_two_dlogs_self_verifies() {
    let s0 = test_scalar(0x10);
    let s1 = test_scalar(0x20);
    let pk0 = pubkey_from_scalar(&s0);
    let pk1 = pubkey_from_scalar(&s1);
    let prop = cand(vec![dlog_proposition(&pk0), dlog_proposition(&pk1)]);
    let reg = registry_with_dlogs(&[(pk0, s0), (pk1, s1)]);
    let message = b"and-two-dlogs";
    let mut rng = deterministic_rng(b"and_two_dlogs");

    let (proof, _cost) = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng)
        .expect("prove_sigma AND(2) should succeed");

    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "AND(2 DLogs) proof must verify");
}

#[test]
fn and_three_dlogs_self_verifies() {
    let s0 = test_scalar(0x10);
    let s1 = test_scalar(0x20);
    let s2 = test_scalar(0x30);
    let pk0 = pubkey_from_scalar(&s0);
    let pk1 = pubkey_from_scalar(&s1);
    let pk2 = pubkey_from_scalar(&s2);
    let prop = cand(vec![
        dlog_proposition(&pk0),
        dlog_proposition(&pk1),
        dlog_proposition(&pk2),
    ]);
    let reg = registry_with_dlogs(&[(pk0, s0), (pk1, s1), (pk2, s2)]);
    let message = b"and-three-dlogs";
    let mut rng = deterministic_rng(b"and_three_dlogs");

    let (proof, _cost) = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng)
        .expect("prove_sigma AND(3) should succeed");

    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "AND(3 DLogs) proof must verify");
}

#[test]
fn or_two_dlogs_real_first_branch() {
    // Prover knows secret for child 0; child 1 is simulated.
    let s0 = test_scalar(0x10);
    let pk0 = pubkey_from_scalar(&s0);
    // child 1 has no corresponding secret in the registry
    let s1_pub = test_scalar(0x20);
    let pk1 = pubkey_from_scalar(&s1_pub);
    let prop = cor(vec![dlog_proposition(&pk0), dlog_proposition(&pk1)]);
    // Registry only has s0 — s1 is not provable
    let reg = registry_with_dlog(&pk0, s0);
    let message = b"or-two-dlogs-real-first";
    let mut rng = deterministic_rng(b"or_two_dlogs_real_first");

    let (proof, _cost) = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng)
        .expect("prove_sigma OR(2, real first) should succeed");

    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "OR(2 DLogs, real first branch) proof must verify");
}

#[test]
fn or_two_dlogs_real_second_branch() {
    // Prover knows secret for child 1; child 0 is simulated.
    let s0_pub = test_scalar(0x10);
    let pk0 = pubkey_from_scalar(&s0_pub);
    let s1 = test_scalar(0x20);
    let pk1 = pubkey_from_scalar(&s1);
    let prop = cor(vec![dlog_proposition(&pk0), dlog_proposition(&pk1)]);
    // Registry only has s1 — s0 is not provable
    let reg = registry_with_dlog(&pk1, s1);
    let message = b"or-two-dlogs-real-second";
    let mut rng = deterministic_rng(b"or_two_dlogs_real_second");

    let (proof, _cost) = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng)
        .expect("prove_sigma OR(2, real second) should succeed");

    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "OR(2 DLogs, real second branch) proof must verify");
}

#[test]
fn or_three_dlogs_real_middle_branch() {
    // Prover knows secret for child 1 (index 1); 0 and 2 are simulated.
    let s0_pub = test_scalar(0x10);
    let pk0 = pubkey_from_scalar(&s0_pub);
    let s1 = test_scalar(0x20);
    let pk1 = pubkey_from_scalar(&s1);
    let s2_pub = test_scalar(0x30);
    let pk2 = pubkey_from_scalar(&s2_pub);
    let prop = cor(vec![
        dlog_proposition(&pk0),
        dlog_proposition(&pk1),
        dlog_proposition(&pk2),
    ]);
    let reg = registry_with_dlog(&pk1, s1);
    let message = b"or-three-dlogs-real-middle";
    let mut rng = deterministic_rng(b"or_three_dlogs_real_middle");

    let (proof, _cost) = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng)
        .expect("prove_sigma OR(3, real middle) should succeed");

    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "OR(3 DLogs, real middle branch) proof must verify");
}

#[test]
fn mixed_dlog_and_dht_in_and_self_verifies() {
    // AND(ProveDlog(pk), ProveDHTuple(g,h,u,v)) — heterogeneous leaves.
    let dlog_secret = test_scalar(0x10);
    let pk = pubkey_from_scalar(&dlog_secret);
    let dht_secret = test_scalar(0x20);
    let (dht_prop, _) = dht_proposition(&dht_secret);

    let prop = cand(vec![dlog_proposition(&pk), dht_prop.clone()]);

    let dlog_reg = registry_with_dlog(&pk, dlog_secret);
    let dht_reg = registry_with_dht(&dht_prop, dht_secret);
    // Merge both registries via external secrets
    use ergo_wallet::proving::external::ProverExternalSecret;
    let (g_b, h_b, u_b, v_b) = match &dht_prop {
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            (*g.as_bytes(), *h.as_bytes(), *u.as_bytes(), *v.as_bytes())
        }
        _ => panic!("expected DHT"),
    };
    let reg = dlog_reg
        .merge_external_secrets(&[ProverExternalSecret::DhTuple {
            g: g_b,
            h: h_b,
            u: u_b,
            v: v_b,
            scalar: dht_secret.into(),
        }])
        .unwrap();
    let _ = dht_reg; // dht_reg was just for illustration; merged above

    let message = b"mixed-dlog-dht-and";
    let mut rng = deterministic_rng(b"mixed_dlog_dht_and");

    let (proof, _cost) = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng)
        .expect("prove_sigma AND(DLog, DHT) should succeed");

    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "AND(ProveDlog, ProveDHTuple) proof must verify");
}

// ----- threshold (k-of-n) sigma proofs (Group C.5) -----

#[test]
fn threshold_2_of_3_self_verifies() {
    // Prover knows secrets for children 0 and 2; child 1 is simulated.
    let s0 = test_scalar(0x10);
    let s1_pub = test_scalar(0x20); // no secret in registry
    let s2 = test_scalar(0x30);
    let pk0 = pubkey_from_scalar(&s0);
    let pk1 = pubkey_from_scalar(&s1_pub);
    let pk2 = pubkey_from_scalar(&s2);

    let prop = cthreshold(
        2,
        vec![
            dlog_proposition(&pk0),
            dlog_proposition(&pk1),
            dlog_proposition(&pk2),
        ],
    );
    let reg = registry_with_dlogs(&[(pk0, s0), (pk2, s2)]);
    let message = b"threshold-2-of-3";
    let mut rng = deterministic_rng(b"threshold_2_of_3");

    let (proof, _cost) = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng)
        .expect("prove_sigma threshold(2,3) should succeed");

    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "threshold(2-of-3) proof must verify");
}

#[test]
fn threshold_2_of_5_self_verifies() {
    // Prover knows secrets for children 1 and 4; others simulated.
    let secrets: Vec<_> = (0u8..5).map(test_scalar).collect();
    let pks: Vec<_> = secrets.iter().map(pubkey_from_scalar).collect();

    let prop = cthreshold(2, pks.iter().map(dlog_proposition).collect());
    // Registry holds only secrets for indices 1 and 4.
    let reg = registry_with_dlogs(&[(pks[1], secrets[1]), (pks[4], secrets[4])]);
    let message = b"threshold-2-of-5";
    let mut rng = deterministic_rng(b"threshold_2_of_5");

    let (proof, _cost) = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng)
        .expect("prove_sigma threshold(2,5) should succeed");

    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "threshold(2-of-5) proof must verify");
}

#[test]
fn threshold_3_of_5_self_verifies() {
    // Prover knows secrets for children 0, 2, 4; others simulated.
    let secrets: Vec<_> = (0u8..5).map(test_scalar).collect();
    let pks: Vec<_> = secrets.iter().map(pubkey_from_scalar).collect();

    let prop = cthreshold(3, pks.iter().map(dlog_proposition).collect());
    let reg = registry_with_dlogs(&[
        (pks[0], secrets[0]),
        (pks[2], secrets[2]),
        (pks[4], secrets[4]),
    ]);
    let message = b"threshold-3-of-5";
    let mut rng = deterministic_rng(b"threshold_3_of_5");

    let (proof, _cost) = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng)
        .expect("prove_sigma threshold(3,5) should succeed");

    let ok = verify_sigma_proof(&prop, &proof, message).expect("verify should not error");
    assert!(ok, "threshold(3-of-5) proof must verify");
}

#[test]
fn threshold_unprovable_fails() {
    // Prover has only 1 of 3 secrets when k=2 → MissingSecret.
    let s0 = test_scalar(0x10);
    let s1_pub = test_scalar(0x20);
    let s2_pub = test_scalar(0x30);
    let pk0 = pubkey_from_scalar(&s0);
    let pk1 = pubkey_from_scalar(&s1_pub);
    let pk2 = pubkey_from_scalar(&s2_pub);

    let prop = cthreshold(
        2,
        vec![
            dlog_proposition(&pk0),
            dlog_proposition(&pk1),
            dlog_proposition(&pk2),
        ],
    );
    let reg = registry_with_dlog(&pk0, s0); // only 1 secret, need 2
    let message = b"threshold-unprovable";
    let mut rng = deterministic_rng(b"threshold_unprovable");

    use ergo_wallet::WalletError;
    let result = prove_sigma(&prop, &reg, message, &HintsBag::empty(), &mut rng);
    assert!(
        matches!(result, Err(WalletError::MissingSecret(_))),
        "threshold(2-of-3) with only 1 secret must fail with MissingSecret, got {result:?}",
    );
}

// ===== Group C.6 — Prover orchestrator tests =====

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::{ADDigest, ModifierId};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::input::{ContextExtension, DataInput, UnsignedInput};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::UnsignedTransaction;
use ergo_sigma::reduce::verify_spending_proof_with_context_and_cost;
use ergo_validation::pre_header::CandidatePreHeader;
use ergo_wallet::proving::hints::TransactionHintsBag;
use ergo_wallet::proving::prover::Prover;
use ergo_wallet::tx_context::{BlockchainParameters, BlockchainStateContext};

/// Parse a P2PK ErgoTree from the raw bytes produced by
/// `ergo_sigma::schnorr::build_prove_dlog_ergo_tree`.
fn ergo_tree_from_bytes(bytes: Vec<u8>) -> ErgoTree {
    let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
    ergo_ser::ergo_tree::read_ergo_tree(&mut r).expect("build_prove_dlog_ergo_tree must parse")
}

/// Build a minimal `ErgoBox` for use as a spending input in prover tests.
fn make_spend_box(ergo_tree: ErgoTree, value: u64, creation_height: u32) -> ErgoBox {
    let candidate = ErgoBoxCandidate::new(
        value,
        ergo_tree,
        creation_height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .expect("test candidate must build");
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([0xAAu8; 32]),
        index: 0,
    }
}

/// Build a simple output candidate (used as transaction output).
fn make_output_candidate(value: u64) -> ErgoBoxCandidate {
    // Minimal P2PK tree for the output (doesn't matter for proving tests).
    let pk_bytes = [0x02u8; 33];
    let tree_bytes = ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&pk_bytes);
    let ergo_tree = ergo_tree_from_bytes(tree_bytes);
    ErgoBoxCandidate::new(value, ergo_tree, 1, vec![], AdditionalRegisters::empty())
        .expect("test output candidate must build")
}

/// Build a `BlockchainStateContext` with synthetic values sufficient for
/// the evaluator to reduce a simple P2PK / ProveDlog script. No real
/// chain state is required — just a plausible shape.
fn synthetic_state_context(height: u32) -> BlockchainStateContext {
    BlockchainStateContext {
        sigma_last_headers: vec![], // No headers needed for bare P2PK
        sigma_pre_header: CandidatePreHeader {
            version: 3,
            parent_id: [0u8; 32],
            height,
            timestamp: 1_700_000_000_000,
            n_bits: 0x1a01_7660,
            votes: [0, 0, 0],
            miner_pubkey: [0x02u8; 33],
        },
        previous_state_digest: ADDigest::from_bytes([0u8; 33]),
    }
}

/// Build `BlockchainParameters` with conservative values for tests.
/// `max_block_cost` is set high enough not to interfere unless overridden.
/// `max_block_cost` must stay within Scala Int.MaxValue (2_147_483_647).
fn test_params(max_block_cost: u64) -> BlockchainParameters {
    BlockchainParameters {
        max_block_cost,
        input_cost: 2_000,
        data_input_cost: 100,
        output_cost: 100,
        token_access_cost: 100,
        interpreter_init_cost: 1_000,
        block_version: 4,
    }
}

/// Build an `UnsignedTransaction` that spends exactly the given boxes.
fn make_unsigned_tx(
    boxes: &[&ErgoBox],
    data_input_ids: &[ModifierId],
    outputs: Vec<ErgoBoxCandidate>,
) -> UnsignedTransaction {
    let inputs: Vec<UnsignedInput> = boxes
        .iter()
        .map(|b| UnsignedInput {
            box_id: b.box_id().expect("box_id must be computable"),
            extension: ContextExtension::empty(),
        })
        .collect();
    let data_inputs: Vec<DataInput> = data_input_ids
        .iter()
        .map(|id| DataInput {
            box_id: ergo_primitives::digest::Digest32::from_bytes(*id.as_bytes()),
        })
        .collect();
    UnsignedTransaction {
        inputs,
        data_inputs,
        output_candidates: outputs,
    }
}

// ----- happy path -----

/// Build a `BlockchainStateContext` with a verification-compatible context.
/// Computes actual EvalBoxes so the verifier's context matches the prover's.
fn make_verifier_context<'a>(
    height: u32,
    eval_inputs: &'a [ergo_sigma::evaluator::EvalBox],
    eval_outputs: &'a [ergo_sigma::evaluator::EvalBox],
    eval_data_inputs: &'a [ergo_sigma::evaluator::EvalBox],
    self_idx: usize,
) -> ergo_sigma::evaluator::ReductionContext<'a> {
    ergo_sigma::evaluator::ReductionContext {
        height,
        self_box: Some(&eval_inputs[self_idx]),
        self_creation_height: eval_inputs[self_idx].creation_height,
        outputs: eval_outputs,
        inputs: eval_inputs,
        data_inputs: eval_data_inputs,
        miner_pubkey: [0x02u8; 33],
        pre_header_timestamp: 1_700_000_000_000,
        pre_header_version: 3,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0x1a01_7660u64,
        pre_header_votes: [0, 0, 0],
        extension: indexmap::IndexMap::new(),
        input_extensions: &[],
        last_headers: &[],
        last_block_utxo_root: None,
        activated_script_version: 2, // block_version 3 - 1
        ergo_tree_version: 2,
    }
}

/// Build a minimal `EvalBox` from an `ErgoBox` without the ergo-validation dep.
fn eval_box_from_ergo(b: &ErgoBox) -> ergo_sigma::evaluator::EvalBox {
    let id = b.box_id().map(|id| *id.as_bytes()).unwrap_or([0u8; 32]);
    ergo_sigma::evaluator::EvalBox {
        creation_height: b.candidate.creation_height,
        script_bytes: b.candidate.ergo_tree_bytes().to_vec(),
        value: b.candidate.value as i64,
        id,
        transaction_id: *b.transaction_id.as_bytes(),
        output_index: b.index,
        registers: [None, None, None, None, None, None],
        tokens: vec![],
        raw_bytes: vec![],
    }
}

/// Build a minimal `EvalBox` from an output candidate.
fn eval_box_from_candidate(c: &ErgoBoxCandidate, index: usize) -> ergo_sigma::evaluator::EvalBox {
    ergo_sigma::evaluator::EvalBox {
        creation_height: c.creation_height,
        script_bytes: c.ergo_tree_bytes().to_vec(),
        value: c.value as i64,
        id: [0u8; 32],
        transaction_id: [0u8; 32],
        output_index: index as u16,
        registers: [None, None, None, None, None, None],
        tokens: vec![],
        raw_bytes: vec![],
    }
}

#[test]
fn prover_signs_tx_with_one_dlog_input_self_verifies() {
    let secret = bip32_v1_secret();
    let pk = pubkey_from_scalar(&secret);
    let ergo_tree = ergo_tree_from_bytes(ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&pk));
    let input_box = make_spend_box(ergo_tree, 1_000_000_000, 100);

    let output = make_output_candidate(999_000_000);
    let unsigned_tx = make_unsigned_tx(&[&input_box], &[], vec![output.clone()]);

    let reg = registry_with_dlog(&pk, secret);
    let prover = Prover::new(reg, test_params(2_000_000_000));
    let state_ctx = synthetic_state_context(1000);

    let signed_tx = prover
        .sign(
            &unsigned_tx,
            std::slice::from_ref(&input_box),
            &[],
            &state_ctx,
            &TransactionHintsBag::empty(),
        )
        .expect("single DLog input must sign");

    assert_eq!(signed_tx.inputs.len(), 1);

    // Reconstruct message and verify.
    let message =
        ergo_ser::transaction::bytes_to_sign(&signed_tx).expect("bytes_to_sign must work");

    let eval_inputs = vec![eval_box_from_ergo(&input_box)];
    let eval_outputs = vec![eval_box_from_candidate(&output, 0)];
    let verifier_ctx = make_verifier_context(1000, &eval_inputs, &eval_outputs, &[], 0);
    let ergo_tree = input_box.candidate.ergo_tree();
    let mut cost_acc = CostAccumulator::new(JitCost::from_jit(2_000_000_000));
    let ok = verify_spending_proof_with_context_and_cost(
        ergo_tree,
        &signed_tx.inputs[0].spending_proof.proof,
        &message,
        &verifier_ctx,
        &mut cost_acc,
    )
    .expect("verify must not error");
    assert!(ok, "single DLog proof must self-verify");
}

#[test]
fn prover_signs_tx_with_two_inputs_self_verifies() {
    let s0 = bip32_v1_secret();
    let s1 = test_scalar(0x77);
    let pk0 = pubkey_from_scalar(&s0);
    let pk1 = pubkey_from_scalar(&s1);

    let tree0 = ergo_tree_from_bytes(ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&pk0));
    let tree1 = ergo_tree_from_bytes(ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&pk1));
    let box0 = make_spend_box(tree0, 1_000_000_000, 100);
    let box1 = make_spend_box(tree1, 2_000_000_000, 200);

    let output = make_output_candidate(2_999_000_000);
    let unsigned_tx = make_unsigned_tx(&[&box0, &box1], &[], vec![output.clone()]);

    let reg = registry_with_dlogs(&[(pk0, s0), (pk1, s1)]);
    let prover = Prover::new(reg, test_params(2_000_000_000));
    let state_ctx = synthetic_state_context(1000);

    let signed_tx = prover
        .sign(
            &unsigned_tx,
            &[box0.clone(), box1.clone()],
            &[],
            &state_ctx,
            &TransactionHintsBag::empty(),
        )
        .expect("two DLog inputs must sign");

    assert_eq!(signed_tx.inputs.len(), 2);

    let message =
        ergo_ser::transaction::bytes_to_sign(&signed_tx).expect("bytes_to_sign must work");

    let eval_inputs = vec![eval_box_from_ergo(&box0), eval_box_from_ergo(&box1)];
    let eval_outputs = vec![eval_box_from_candidate(&output, 0)];

    for (i, input_box) in [&box0, &box1].iter().enumerate() {
        let verifier_ctx = make_verifier_context(1000, &eval_inputs, &eval_outputs, &[], i);
        let ergo_tree = input_box.candidate.ergo_tree();
        let mut cost_acc = CostAccumulator::new(JitCost::from_jit(2_000_000_000));
        let ok = verify_spending_proof_with_context_and_cost(
            ergo_tree,
            &signed_tx.inputs[i].spending_proof.proof,
            &message,
            &verifier_ctx,
            &mut cost_acc,
        )
        .expect("verify must not error");
        assert!(ok, "input {i} proof must self-verify");
    }
}

#[test]
fn prover_signs_tx_with_dht_input_self_verifies() {
    let secret = bip32_v1_secret();
    let (dht_prop, _h_scalar) = dht_proposition(&secret);

    // Build an ErgoTree for ProveDHTuple.
    let (g_b, h_b, u_b, v_b) = match &dht_prop {
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            (*g.as_bytes(), *h.as_bytes(), *u.as_bytes(), *v.as_bytes())
        }
        _ => panic!("expected ProveDHTuple"),
    };
    let tree_bytes = ergo_sigma::dht::build_prove_dht_ergo_tree(&g_b, &h_b, &u_b, &v_b);
    let ergo_tree = ergo_tree_from_bytes(tree_bytes);

    let input_box = make_spend_box(ergo_tree, 1_000_000_000, 100);
    let output = make_output_candidate(999_000_000);
    let unsigned_tx = make_unsigned_tx(&[&input_box], &[], vec![output.clone()]);

    let reg = registry_with_dht(&dht_prop, secret);
    let prover = Prover::new(reg, test_params(2_000_000_000));
    let state_ctx = synthetic_state_context(1000);

    let signed_tx = prover
        .sign(
            &unsigned_tx,
            std::slice::from_ref(&input_box),
            &[],
            &state_ctx,
            &TransactionHintsBag::empty(),
        )
        .expect("DHT input must sign");

    assert_eq!(signed_tx.inputs.len(), 1);

    let message =
        ergo_ser::transaction::bytes_to_sign(&signed_tx).expect("bytes_to_sign must work");
    let eval_inputs = vec![eval_box_from_ergo(&input_box)];
    let eval_outputs = vec![eval_box_from_candidate(&output, 0)];
    let verifier_ctx = make_verifier_context(1000, &eval_inputs, &eval_outputs, &[], 0);
    let ergo_tree = input_box.candidate.ergo_tree();
    let mut cost_acc = CostAccumulator::new(JitCost::from_jit(2_000_000_000));
    let ok = verify_spending_proof_with_context_and_cost(
        ergo_tree,
        &signed_tx.inputs[0].spending_proof.proof,
        &message,
        &verifier_ctx,
        &mut cost_acc,
    )
    .expect("verify must not error");
    assert!(ok, "DHT proof must self-verify");
}

// ----- error paths -----

#[test]
fn prover_rejects_input_count_mismatch() {
    let secret = bip32_v1_secret();
    let pk = pubkey_from_scalar(&secret);
    let ergo_tree = ergo_tree_from_bytes(ergo_sigma::schnorr::build_prove_dlog_ergo_tree(&pk));
    let input_box = make_spend_box(ergo_tree, 1_000_000_000, 100);

    // Unsigned tx has 1 input but we pass 0 boxes_to_spend.
    let output = make_output_candidate(999_000_000);
    let unsigned_tx = make_unsigned_tx(&[&input_box], &[], vec![output]);

    let reg = registry_with_dlog(&pk, secret);
    let prover = Prover::new(reg, test_params(2_000_000_000));
    let state_ctx = synthetic_state_context(1000);

    let err = prover
        .sign(
            &unsigned_tx,
            &[], // wrong: 0 boxes but tx has 1 input
            &[],
            &state_ctx,
            &TransactionHintsBag::empty(),
        )
        .expect_err("mismatched input count must fail");

    assert!(
        matches!(err, ergo_wallet::WalletError::TxBuild(_)),
        "expected TxBuild, got {err:?}",
    );
}

// Cost enforcement was removed from Prover::sign (the gate was unit-wrong:
// it mixed JIT-cost values with block-cost initial_cost, then compared the
// mixed total against params.max_block_cost). The authoritative cost gate
// is the bridge self-verify (self_verify_signed_tx in wallet_bridge.rs),
// which uses chain-parity accounting. Integration-level cost coverage lives
// there. prover_enforces_max_block_cost was deleted here accordingly.

// ----- script gate -----

/// Build an unsupported-family ErgoTree: a non-trivially-reducible body (not
/// a bare SigmaProp constant and not a miner-reward wrapper).
///
/// Uses an `Expr::Op` with opcode 0x91 (HEIGHT — returns Int, not SigmaProp).
/// `trivial_reduce` returns `NotTriviallyReducible` for any `Op` node; the
/// miner-reward detector won't match the short byte prefix. Together these
/// ensure the script gate fires, independently of what the evaluator would do.
fn non_p2pk_ergo_tree() -> ErgoTree {
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::{IrNode, Payload};
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: ergo_ser::opcode::Expr::Op(IrNode {
            opcode: 0x91, // HEIGHT opcode (Int, not SigmaProp) — non-trivially reducible
            payload: Payload::Zero,
        }),
    }
}

#[test]
fn prover_refuses_unsupported_script() {
    // Build an input box whose ErgoTree is not in the supported set:
    // it's a non-trivially-reducible script (HEIGHT opcode body) and doesn't
    // match the miner-reward wrapper pattern.
    let non_p2pk_tree = non_p2pk_ergo_tree();
    let input_box = make_spend_box(non_p2pk_tree, 1_000_000_000, 100);

    let output = make_output_candidate(999_000_000);
    let unsigned_tx = make_unsigned_tx(&[&input_box], &[], vec![output]);

    let reg = SecretRegistry::empty();
    let prover = Prover::new(reg, test_params(2_000_000_000));
    let state_ctx = synthetic_state_context(1000);

    let err = prover
        .sign(
            &unsigned_tx,
            &[input_box],
            &[],
            &state_ctx,
            &TransactionHintsBag::empty(),
        )
        .expect_err("unsupported-family script must be refused");

    assert!(
        matches!(err, ergo_wallet::WalletError::TxBuild(_)),
        "expected TxBuild rejection for unsupported-family script, got {err:?}",
    );
}

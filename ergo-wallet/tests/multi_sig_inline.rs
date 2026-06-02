//! Multi-sig primitive inline tests: single-prover round-trip +
//! hint-consumption forcing function. Full 2-of-3 + dApp multi-party
//! flows are not yet covered here. Scala-extracted byte-parity oracle
//! for single-prover primitives lives in multi_sig_oracle.rs.

use ergo_primitives::group_element::GroupElement;
use ergo_ser::sigma_value::SigmaBoolean;
use ergo_wallet::proving::commitments::generate_commitments_for;
use ergo_wallet::proving::extract::bag_for_multisig;
use ergo_wallet::proving::hints::{Hint, HintsBag};
use ergo_wallet::proving::randomness::OsRngBackend;

fn dummy_dlog(seed: u8) -> SigmaBoolean {
    let mut pk = [0u8; 33];
    pk[0] = 0x02;
    pk[1] = seed;
    SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk))
}

fn compressed_pk(point: k256::ProjectivePoint) -> [u8; 33] {
    use k256::elliptic_curve::group::GroupEncoding;
    let bytes = k256::AffinePoint::from(point).to_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes);
    out
}

// ----- happy path -----

#[test]
fn generates_commitment_for_single_known_leaf() {
    let pk_a = dummy_dlog(0xA);
    let bag =
        generate_commitments_for(&pk_a, std::slice::from_ref(&pk_a), &mut OsRngBackend).unwrap();

    // Expect exactly 2 hints: OwnCommitment + RealCommitment.
    assert_eq!(bag.hints.len(), 2);
    assert!(matches!(bag.hints[0], Hint::OwnCommitment(_)));
    assert!(matches!(bag.hints[1], Hint::RealCommitment(_)));
}

#[test]
fn generates_no_commitment_for_unknown_leaf() {
    let pk_a = dummy_dlog(0xA);
    let pk_b = dummy_dlog(0xB);
    // generate_for has pk_b, but tree is pk_a → no commitments.
    let bag = generate_commitments_for(&pk_a, &[pk_b], &mut OsRngBackend).unwrap();
    assert_eq!(bag.hints.len(), 0);
}

#[test]
fn generates_commitments_only_for_known_branches_of_compound() {
    let pk_a = dummy_dlog(0xA);
    let pk_b = dummy_dlog(0xB);
    let pk_c = dummy_dlog(0xC);
    // AND(pk_a, pk_b, pk_c). generate_for has only pk_a + pk_c.
    let tree = SigmaBoolean::Cand(vec![pk_a.clone(), pk_b.clone(), pk_c.clone()]);
    let bag = generate_commitments_for(&tree, &[pk_a, pk_c], &mut OsRngBackend).unwrap();
    // 2 leaves × 2 hints each = 4 hints.
    assert_eq!(bag.hints.len(), 4);
}

#[test]
fn positions_distinguish_compound_children() {
    let pk_a = dummy_dlog(0xA);
    // AND(pk_a, pk_a) — duplicate leaf.
    let tree = SigmaBoolean::Cand(vec![pk_a.clone(), pk_a.clone()]);
    let bag =
        generate_commitments_for(&tree, std::slice::from_ref(&pk_a), &mut OsRngBackend).unwrap();
    // 2 leaves × 2 hints each = 4. The two OwnCommitments must
    // have DISTINCT positions (otherwise they're indistinguishable).
    let positions: Vec<_> = bag
        .hints
        .iter()
        .filter_map(|h| match h {
            Hint::OwnCommitment(oc) => Some(oc.position.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(positions.len(), 2);
    assert_ne!(positions[0], positions[1]);
}

// ----- round-trips -----

#[test]
fn single_prover_generate_sign_extract_round_trip() {
    // Holds both secrets; signs a 2-leaf AND tree; extracts RealSecretProofs
    // for both leaves; verifies proof. Exercises generate_commitments_for ->
    // prove_sigma (with populated bag) -> bag_for_multisig end-to-end.
    // This is NOT the distributed multi-sig flow.
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    let alice_secret = Scalar::from(7u64);
    let bob_secret = Scalar::from(11u64);
    let alice_pk = compressed_pk(ProjectivePoint::GENERATOR * alice_secret);
    let bob_pk = compressed_pk(ProjectivePoint::GENERATOR * bob_secret);

    let alice_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(alice_pk));
    let bob_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(bob_pk));
    let tree = SigmaBoolean::Cand(vec![alice_image.clone(), bob_image.clone()]);

    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[
            ProverExternalSecret::Dlog {
                pk: alice_pk,
                scalar: alice_secret.into(),
            },
            ProverExternalSecret::Dlog {
                pk: bob_pk,
                scalar: bob_secret.into(),
            },
        ])
        .unwrap();

    let message = b"primitive round-trip";

    // Step 1: generate_commitments_for produces OwnCommitment + RealCommitment for each leaf.
    let bag = generate_commitments_for(
        &tree,
        &[alice_image.clone(), bob_image.clone()],
        &mut OsRngBackend,
    )
    .unwrap();
    assert_eq!(bag.hints.len(), 4, "2 leaves × 2 hints each");

    // Step 2: sign with the populated bag — the hint-consumption rule
    // requires the prover to use the supplied OwnCommitment instead of resampling.
    let (proof, _cost) = prove_sigma(&tree, &registry, message, &bag, &mut OsRngBackend).unwrap();

    // Step 3: extract RealSecretProof for both leaves.
    let extracted = bag_for_multisig(
        &tree,
        &proof,
        &[alice_image.clone(), bob_image.clone()],
        &[],
    )
    .unwrap();

    let real_proofs: Vec<_> = extracted
        .hints
        .iter()
        .filter(|h| matches!(h, Hint::RealSecretProof(_)))
        .collect();
    assert_eq!(
        real_proofs.len(),
        2,
        "both leaves must have RealSecretProof"
    );

    // Step 4: proof must verify.
    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &proof, message).unwrap();
    assert!(ok, "single-prover signed proof must verify");
}

#[test]
fn prover_consumes_own_commitment_from_bag_deterministic() {
    // STRICT forcing function: if prove_sigma ignores the bag's
    // OwnCommitment and samples fresh, the proof's R bytes won't equal
    // the bag's OwnCommitment.commitment value → assertion fails.
    //
    // Mechanism: bag built with seed A; OwnCommitment.commitment.Schnorr(R_bag)
    // captured. prove_sigma called with a DIFFERENT seed B. A hint-ignoring
    // prover samples from seed B → R_fresh ≠ R_bag. The correct prover reuses
    // the bag's R regardless of seed B.
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::hints::FirstProverMessage;
    use ergo_wallet::proving::randomness::Sha256DerivedRng;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    let secret = Scalar::from(42u64);
    let pk = compressed_pk(ProjectivePoint::GENERATOR * secret);
    let image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk));

    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk,
            scalar: secret.into(),
        }])
        .unwrap();

    let message = b"hint-consumption forcing function";

    // Build bag deterministically with seed A.
    let mut rng_a = Sha256DerivedRng::from_seed([0x42; 32]);
    let bag = generate_commitments_for(&image, std::slice::from_ref(&image), &mut rng_a).unwrap();

    // Capture R from the bag's OwnCommitment.
    let r_bag: [u8; 33] = match bag.hints.iter().find_map(|h| match h {
        Hint::OwnCommitment(oc) => match oc.commitment {
            FirstProverMessage::Schnorr(r) => Some(r),
            _ => None,
        },
        _ => None,
    }) {
        Some(r) => r,
        None => panic!("bag must contain OwnCommitment with Schnorr commitment"),
    };

    // Sign with a DIFFERENT seed B. A prover that ignores the bag samples fresh
    // from seed B → proof R ≠ r_bag. A correct prover reuses the bag's R.
    let mut rng_b = Sha256DerivedRng::from_seed([0x99; 32]);
    let (proof, _cost) = prove_sigma(&image, &registry, message, &bag, &mut rng_b).unwrap();

    // Recompute R from the proof bytes: R = g^z - pk*e.
    let proof_r = recompute_schnorr_commitment_from_proof(&proof, &pk);

    assert_eq!(
        proof_r, r_bag,
        "FORCING FUNCTION: prover MUST consume bag's OwnCommitment — \
         proof R (from seed B if bag ignored) must equal bag's R (from seed A). \
         Mismatch means the hint-consumption rule is not in effect."
    );

    // Structural validity sanity check.
    let ok = ergo_sigma::verify::verify_sigma_proof(&image, &proof, message).unwrap();
    assert!(ok, "proof must verify structurally");
}

/// Recompute R = g^z - pk*e from a bare Schnorr proof's bytes.
/// Proof wire format for ProveDlog: challenge(24B) || z(32B).
fn recompute_schnorr_commitment_from_proof(proof: &[u8], pk: &[u8; 33]) -> [u8; 33] {
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::{ProjectivePoint, Scalar};

    let challenge_bytes: [u8; 24] = proof[..24].try_into().unwrap();
    let z_bytes: [u8; 32] = proof[24..56].try_into().unwrap();

    let mut padded = [0u8; 32];
    padded[8..].copy_from_slice(&challenge_bytes);
    let e = <Scalar as Reduce<k256::U256>>::reduce_bytes(&padded.into());
    let z = <Scalar as Reduce<k256::U256>>::reduce_bytes(&z_bytes.into());

    let encoded = k256::EncodedPoint::from_bytes(pk.as_slice()).unwrap();
    let pk_point = ProjectivePoint::from(k256::AffinePoint::from_encoded_point(&encoded).unwrap());
    let big_r = ProjectivePoint::GENERATOR * z - pk_point * e;

    let affine_bytes = k256::AffinePoint::from(big_r).to_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(&affine_bytes);
    out
}

// ----- compound RealSecretProof consumption -----

/// Forcing function for `RealSecretProof` consumption: the compound
/// prover MUST take secrets from the hints bag's `RealSecretProof`
/// entries rather than failing with `MissingSecret`.
///
/// Flow: full prover signs AND(Alice, Bob), extracts ALL proof hints (both
/// RealSecretProof + RealCommitment for each leaf). A prover with an EMPTY
/// secret registry then reconstructs the proof from the hint bag alone.
/// Commitments are taken from RealCommitment hints → same FS hash → same
/// root challenge → the reconstructed proof is byte-identical to the
/// original. Without the RealSecretProof consumption path this fails with
/// `MissingSecret`.
#[test]
fn compound_prover_consumes_real_secret_proof_from_bag() {
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::hints::RealSecretProof;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    let alice_secret = Scalar::from(13u64);
    let bob_secret = Scalar::from(17u64);
    let alice_pk = compressed_pk(ProjectivePoint::GENERATOR * alice_secret);
    let bob_pk = compressed_pk(ProjectivePoint::GENERATOR * bob_secret);

    let alice_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(alice_pk));
    let bob_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(bob_pk));
    let tree = SigmaBoolean::Cand(vec![alice_image.clone(), bob_image.clone()]);

    // Step 1: Full registry signs the AND tree.
    let full_registry = SecretRegistry::empty()
        .merge_external_secrets(&[
            ProverExternalSecret::Dlog {
                pk: alice_pk,
                scalar: alice_secret.into(),
            },
            ProverExternalSecret::Dlog {
                pk: bob_pk,
                scalar: bob_secret.into(),
            },
        ])
        .unwrap();

    let message = b"compound-proof-hint-consumption";
    let (original_proof, _) = prove_sigma(
        &tree,
        &full_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .unwrap();

    // Step 2: Extract ALL real proof hints (both Alice + Bob).
    let all_hints = bag_for_multisig(
        &tree,
        &original_proof,
        &[alice_image.clone(), bob_image.clone()],
        &[],
    )
    .unwrap();

    let alice_rsp: RealSecretProof = all_hints
        .hints
        .iter()
        .find_map(|h| match h {
            Hint::RealSecretProof(rsp) if rsp.image == alice_image => Some(rsp.clone()),
            _ => None,
        })
        .expect("bag_for_multisig must emit RealSecretProof for alice");
    let bob_rsp: RealSecretProof = all_hints
        .hints
        .iter()
        .find_map(|h| match h {
            Hint::RealSecretProof(rsp) if rsp.image == bob_image => Some(rsp.clone()),
            _ => None,
        })
        .expect("bag_for_multisig must emit RealSecretProof for bob");

    // Step 3: Empty registry + full hint bag → prove_sigma MUST succeed.
    // Without RealSecretProof consumption this returns Err(MissingSecret)
    // because no secrets are in the registry and build_tree falls back
    // before checking the hint bag.
    let empty_registry = SecretRegistry::empty();
    let (reconstructed_proof, _) = prove_sigma(
        &tree,
        &empty_registry,
        message,
        &all_hints,
        &mut OsRngBackend,
    )
    .expect(
        "compound prover with ALL RealSecretProof hints MUST succeed — \
         without that path this returns MissingSecret",
    );

    // Step 4: The reconstructed proof must verify.
    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &reconstructed_proof, message).unwrap();
    assert!(
        ok,
        "proof reconstructed from RealSecretProof hints must verify"
    );

    // Step 5: The reconstructed proof must be byte-identical to the original.
    // RealCommitment hints give the same commitments → same FS hash → same
    // root challenge → same z values emitted verbatim from RealSecretProof.
    assert_eq!(
        reconstructed_proof, original_proof,
        "reconstructed proof must be byte-identical to the original — \
         mismatch means build_tree regenerated commitments instead of using hints"
    );

    // Step 6: z bytes in the proof must equal the supplied responses.
    // AND layout after root_challenge(24B): [alice_z(32B)][bob_z(32B)].
    let alice_z: [u8; 32] = reconstructed_proof[24..56].try_into().unwrap();
    let bob_z: [u8; 32] = reconstructed_proof[56..88].try_into().unwrap();
    assert_eq!(
        alice_z, alice_rsp.response,
        "Alice's z must equal supplied RealSecretProof response"
    );
    assert_eq!(
        bob_z, bob_rsp.response,
        "Bob's z must equal supplied RealSecretProof response"
    );
}

#[test]
fn generate_then_sign_then_extract_real_secret() {
    // 2-leaf AND tree, single prover with both secrets.
    // Sign, then extract the real secret for alice only.
    // Confirms: bag has RealSecretProof for alice, nothing for bob.
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::Scalar;

    let alice_secret = Scalar::from(7u64);
    let bob_secret = Scalar::from(11u64);
    let alice_pk = compressed_pk(k256::ProjectivePoint::GENERATOR * alice_secret);
    let bob_pk = compressed_pk(k256::ProjectivePoint::GENERATOR * bob_secret);

    let alice_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(alice_pk));
    let bob_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(bob_pk));
    let tree = SigmaBoolean::Cand(vec![alice_image.clone(), bob_image.clone()]);

    // Single prover holds both secrets.
    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[
            ProverExternalSecret::Dlog {
                pk: alice_pk,
                scalar: alice_secret.into(),
            },
            ProverExternalSecret::Dlog {
                pk: bob_pk,
                scalar: bob_secret.into(),
            },
        ])
        .unwrap();

    let message = b"multi-sig round-trip";
    let (proof, _cost) = prove_sigma(
        &tree,
        &registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .unwrap();

    // Extract real secret for alice only; bob is neither real nor simulated.
    let bag = bag_for_multisig(&tree, &proof, std::slice::from_ref(&alice_image), &[]).unwrap();

    let has_alice_real = bag.hints.iter().any(|h| match h {
        Hint::RealSecretProof(rsp) => rsp.image == alice_image,
        _ => false,
    });
    assert!(has_alice_real, "bag must contain RealSecretProof for alice");

    let has_bob = bag.hints.iter().any(|h| match h {
        Hint::RealSecretProof(rsp) => rsp.image == bob_image,
        _ => false,
    });
    assert!(
        !has_bob,
        "bag must NOT contain bob's secret (not in real_secrets)"
    );
}

// ----- priority ordering -----

/// Regression: registry secret must take priority over SimulatedSecretProof.
///
/// Tree: Dlog(a). Registry: has a's secret. Bag: ALSO has SimulatedSecretProof
/// for Dlog(a) at crypto_tree_prefix.
///
/// Before fix: build_tree reached the SimulatedSecretProof branch BEFORE the
/// registry-secret branch → leaf materialized as simulated (SuppliedProof with
/// supplied_challenge) → root assigned real challenge → finalize_leaf emitted
/// supplied z against wrong challenge → SelfVerifyFailed.
///
/// After fix: registry-secret branch runs BEFORE SimulatedSecretProof →
/// real prove path → proof verifies.
#[test]
fn registry_secret_takes_precedence_over_simulated_hint() {
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::hints::{Hint, SimulatedSecretProof};
    use ergo_wallet::proving::node_position::NodePosition;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret = Scalar::from(0xABCDu64);
    let pk_pt = ProjectivePoint::GENERATOR * secret;
    let pk: [u8; 33] = {
        let affine = k256::AffinePoint::from(pk_pt);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk));

    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk,
            scalar: secret.into(),
        }])
        .unwrap();

    // Bag also contains a SimulatedSecretProof for the same (image, position).
    // This is a multi-party coordination hint for branches the prover lacks the
    // secret for — it must NOT override the real local secret.
    let mut bag = HintsBag::empty();
    bag.add(Hint::SimulatedSecretProof(SimulatedSecretProof {
        image: image.clone(),
        challenge: [0xAA; 24],
        response: [0xBB; 32],
        position: NodePosition::crypto_tree_prefix(),
    }));

    let message = b"registry secret priority test";
    let (proof, _cost) = prove_sigma(&image, &registry, message, &bag, &mut OsRngBackend)
        .expect("prove_sigma with registry secret + sim hint must succeed via real path");

    let ok = ergo_sigma::verify::verify_sigma_proof(&image, &proof, message)
        .expect("verify must not error");
    assert!(
        ok,
        "proof from real-secret path must verify — sim hint should have been ignored"
    );
}

/// Regression: registry secret must override a stale RealSecretProof hint extracted
/// from a DIFFERENT message's proof.
///
/// Flow:
///   1. Sign message_1 with the registry secret → proof_1.
///   2. Extract RealSecretProof from proof_1 (bytes valid only for message_1's challenge).
///   3. Sign message_2 with the SAME registry + the stale bag from step 2.
///
/// Before fix (7f7ac55): build_tree consumed the stale RealSecretProof first →
/// leaf materialized as SuppliedProof with stale z → root challenge differs for
/// message_2 → finalize_leaf emitted stale z against wrong challenge →
/// SelfVerifyFailed.
///
/// After fix: registry-secret branch runs first → real prove path → fresh
/// commitment + response for message_2 → proof verifies.
#[test]
fn registry_secret_ignores_stale_real_secret_proof_hint() {
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    let secret = Scalar::from(0x1234u64);
    let pk = compressed_pk(ProjectivePoint::GENERATOR * secret);
    let image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk));

    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk,
            scalar: secret.into(),
        }])
        .unwrap();

    // Step 1: sign message_1, extract bag (stale for message_2).
    let (proof_1, _) = prove_sigma(
        &image,
        &registry,
        b"message_1",
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("first sign");
    let stale_bag = bag_for_multisig(&image, &proof_1, std::slice::from_ref(&image), &[])
        .expect("extract from message_1 proof");

    // Step 2: sign message_2 with the same registry + stale bag.
    // Before fix: SelfVerifyFailed because stale z was consumed.
    // After fix: registry-secret wins → fresh sign for message_2 → verifies.
    let (proof_2, _) = prove_sigma(
        &image,
        &registry,
        b"message_2",
        &stale_bag,
        &mut OsRngBackend,
    )
    .expect("registry-secret must override stale hint for message_2");

    let ok = ergo_sigma::verify::verify_sigma_proof(&image, &proof_2, b"message_2")
        .expect("verify shouldn't error");
    assert!(
        ok,
        "proof_2 must verify (registry-secret priority means stale hint ignored)"
    );
}

// ----- error paths -----

/// Regression: SimulatedSecretProof in the bag must NOT count as a real branch
/// for threshold preselection.
///
/// Before the fix: can_prove() returned true for a SimulatedSecretProof-at-position,
/// so atLeast(2, [Dlog(a), Dlog(b)]) with SimulatedSecretProof for both leaves and
/// an empty registry preselected 2 "real" branches. build_tree then materialized
/// both as SIMULATED (SuppliedProof with supplied_challenge), assigned the same
/// challenge to both real slots, and the final self-verify failed.
///
/// After the fix: can_prove rejects SimulatedSecretProof (only registry secrets
/// and RealSecretProof are valid provability signals) → real_count = 0 < k=2 →
/// clean MissingSecret.
#[test]
fn threshold_simulated_secret_proof_does_not_count_as_real() {
    use ergo_wallet::error::WalletError;
    use ergo_wallet::proving::hints::SimulatedSecretProof;
    use ergo_wallet::proving::node_position::NodePosition;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    // Two distinct real pubkeys — secrets are NOT in the registry.
    let a_secret = Scalar::from(3u64);
    let b_secret = Scalar::from(5u64);
    let a_pk = compressed_pk(ProjectivePoint::GENERATOR * a_secret);
    let b_pk = compressed_pk(ProjectivePoint::GENERATOR * b_secret);
    let a_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(a_pk));
    let b_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(b_pk));

    // atLeast(2, [Dlog(a), Dlog(b)])
    let tree = SigmaBoolean::Cthreshold {
        k: 2,
        children: vec![a_image.clone(), b_image.clone()],
    };

    // Empty registry — no backing secrets.
    let empty_registry = SecretRegistry::empty();

    let pos_child0 = NodePosition::crypto_tree_prefix().child(0);
    let pos_child1 = NodePosition::crypto_tree_prefix().child(1);

    // SimulatedSecretProofs for both leaves. These are MATERIALIZATION hints
    // (build_tree uses them to fill simulated branches), not real-branch signals.
    let ssp_a = SimulatedSecretProof {
        image: a_image.clone(),
        challenge: [0xAA; 24],
        response: [0x11; 32],
        position: pos_child0,
    };
    let ssp_b = SimulatedSecretProof {
        image: b_image.clone(),
        challenge: [0xBB; 24],
        response: [0x22; 32],
        position: pos_child1,
    };

    let mut bag = HintsBag::empty();
    bag.add(Hint::SimulatedSecretProof(ssp_a));
    bag.add(Hint::SimulatedSecretProof(ssp_b));

    let message = b"threshold-simulated-secret-proof-not-real";
    let result = prove_sigma(&tree, &empty_registry, message, &bag, &mut OsRngBackend);

    match result {
        Err(WalletError::MissingSecret(_)) => {
            // Correct: SimulatedSecretProof is not a real signal → real_count = 0 < k=2.
        }
        Err(WalletError::SelfVerifyFailed) => {
            panic!(
                "REGRESSION: got SelfVerifyFailed instead of MissingSecret — \
                 can_prove still counted SimulatedSecretProof as provable. \
                 Threshold preselected both leaves as real, build_tree \
                 materialized both as SIMULATED (SuppliedProof with \
                 supplied_challenge), and the mismatch produced SelfVerifyFailed. \
                 Fix: remove SimulatedSecretProof from can_prove's positive case."
            );
        }
        Ok(_) => {
            panic!(
                "REGRESSION: prove_sigma succeeded with only SimulatedSecretProofs \
                 and no secrets — the prover shipped an invalid proof."
            );
        }
        Err(other) => {
            panic!("unexpected error variant: {other:?}");
        }
    }
}

/// Regression test: OwnCommitment without a backing secret must NOT be treated
/// as provable. Before the fix, can_prove() counted Hint::OwnCommitment at
/// matching (image, position) as making a leaf provable. build_tree() only
/// consumes OwnCommitment INSIDE the `secrets.dlog_secret.is_some()` branch, so
/// when the registry is empty and both leaves have OwnCommitment hints,
/// can_prove returned true for both → threshold preselected 2 real branches →
/// build_tree fell through to simulation (no secret) → produced simulated z for
/// "real" branches → final challenge assignment produced SelfVerifyFailed instead
/// of a clean MissingSecret.
///
/// After the fix: OwnCommitment is removed from can_prove's positive case.
/// can_prove returns false for both leaves → real_count = 0 < k=2 → MissingSecret.
#[test]
fn threshold_own_commitment_without_secret_rejects() {
    use ergo_wallet::error::WalletError;
    use ergo_wallet::proving::hints::{FirstProverMessage, OwnCommitment};
    use ergo_wallet::proving::node_position::NodePosition;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::ops::MulByGenerator;
    use k256::{ProjectivePoint, Scalar};

    // Two distinct real pubkeys — we will NOT put their secrets in the registry.
    let a_secret = Scalar::from(7u64);
    let b_secret = Scalar::from(11u64);
    let a_pk = compressed_pk(ProjectivePoint::GENERATOR * a_secret);
    let b_pk = compressed_pk(ProjectivePoint::GENERATOR * b_secret);
    let a_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(a_pk));
    let b_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(b_pk));

    // atLeast(2, [Dlog(a), Dlog(b)])
    let tree = SigmaBoolean::Cthreshold {
        k: 2,
        children: vec![a_image.clone(), b_image.clone()],
    };

    // Empty registry — no secrets.
    let empty_registry = SecretRegistry::empty();

    // Build OwnCommitment for each leaf with fake randomness r=1 and r=2.
    // The OwnCommitment exists in the bag but there is no backing secret.
    let r_a = Scalar::from(1u64);
    let r_b = Scalar::from(2u64);

    let r_bytes_a: [u8; 32] = r_a.to_bytes().into();
    let r_bytes_b: [u8; 32] = r_b.to_bytes().into();

    use k256::elliptic_curve::group::GroupEncoding;

    let r_pt_a: [u8; 33] = {
        let pt = ProjectivePoint::mul_by_generator(&r_a);
        let bytes = k256::AffinePoint::from(pt).to_bytes();
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes);
        out
    };
    let r_pt_b: [u8; 33] = {
        let pt = ProjectivePoint::mul_by_generator(&r_b);
        let bytes = k256::AffinePoint::from(pt).to_bytes();
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes);
        out
    };

    let pos_child0 = NodePosition::crypto_tree_prefix().child(0);
    let pos_child1 = NodePosition::crypto_tree_prefix().child(1);

    let oc_a = OwnCommitment {
        image: a_image.clone(),
        secret_randomness: r_bytes_a,
        commitment: FirstProverMessage::Schnorr(r_pt_a),
        position: pos_child0,
    };
    let oc_b = OwnCommitment {
        image: b_image.clone(),
        secret_randomness: r_bytes_b,
        commitment: FirstProverMessage::Schnorr(r_pt_b),
        position: pos_child1,
    };

    let mut bag = ergo_wallet::proving::hints::HintsBag::empty();
    bag.add(Hint::OwnCommitment(oc_a));
    bag.add(Hint::OwnCommitment(oc_b));

    let message = b"threshold-own-commitment-without-secret";
    let result = prove_sigma(&tree, &empty_registry, message, &bag, &mut OsRngBackend);

    match result {
        Err(WalletError::MissingSecret(_)) => {
            // Correct: OwnCommitment alone is not provable → real_count = 0 < k=2.
        }
        Err(WalletError::SelfVerifyFailed) => {
            panic!(
                "REGRESSION: got SelfVerifyFailed instead of MissingSecret — \
                 can_prove still counted OwnCommitment as provable. Threshold \
                 preselected both leaves as real, build_tree fell to simulation \
                 (no secret), and the mismatched z produced SelfVerifyFailed. \
                 Fix: remove OwnCommitment from can_prove's positive case."
            );
        }
        Ok(_) => {
            panic!(
                "REGRESSION: prove_sigma succeeded with only OwnCommitments and \
                 no secrets — the prover shipped an invalid proof."
            );
        }
        Err(other) => {
            panic!("unexpected error variant: {other:?}");
        }
    }
}

/// Regression test for position-blind can_prove in threshold trees.
///
/// atLeast(2, [Dlog(a), Dlog(a)]) — same pubkey at two different positions.
/// SecretRegistry is empty (prover has no DLog secret for `a`).
/// HintsBag has ONE RealSecretProof for image=Dlog(a), position=[0, 0]
/// (first child only).
///
/// Before the fix: image-only can_prove counted BOTH leaves as provable →
/// threshold preselected both as real → build_tree consumed the hint for
/// pos [0,0] and silently simulated pos [0,1] → invalid proof (or
/// SelfVerifyFailed at prove_sigma's final check).
///
/// After the fix: can_prove is position-aware → only child 0 counts as
/// provable → real_count=1 < k=2 → Err(MissingSecret).
#[test]
fn threshold_duplicate_leaf_with_single_hint_rejects() {
    use ergo_wallet::error::WalletError;
    use ergo_wallet::proving::hints::{FirstProverMessage, RealCommitment, RealSecretProof};
    use ergo_wallet::proving::node_position::NodePosition;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    // Real pubkey from a known scalar (but we won't put it in the registry).
    let a_secret = Scalar::from(99u64);
    let a_pk = compressed_pk(ProjectivePoint::GENERATOR * a_secret);
    let a_image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(a_pk));

    // atLeast(2, [Dlog(a), Dlog(a)])
    let tree = SigmaBoolean::Cthreshold {
        k: 2,
        children: vec![a_image.clone(), a_image.clone()],
    };

    // Empty registry — this prover has no DLog secret for `a`.
    let empty_registry = SecretRegistry::empty();

    // Build a fake RealSecretProof for child 0 only (position [0, 0]).
    // We don't need cryptographically valid bytes — can_prove is a
    // structural probe, and the test should fail before build_tree
    // would ever try to use them.
    let pos_child0 = NodePosition::crypto_tree_prefix().child(0);
    let rsp_child0 = RealSecretProof {
        image: a_image.clone(),
        challenge: [0u8; 24],
        response: [0u8; 32],
        position: pos_child0,
    };

    // Also provide a RealCommitment for child 0 so build_tree has a
    // commitment to use (avoids back-derivation arithmetic on zero bytes).
    let pos_child0_for_commit = NodePosition::crypto_tree_prefix().child(0);
    let rc_child0 = RealCommitment {
        image: a_image.clone(),
        commitment: FirstProverMessage::Schnorr({
            // Compressed SEC1 point: just use the generator's encoding.
            use k256::elliptic_curve::group::GroupEncoding;
            let bytes = k256::AffinePoint::from(ProjectivePoint::GENERATOR).to_bytes();
            let mut out = [0u8; 33];
            out.copy_from_slice(&bytes);
            out
        }),
        position: pos_child0_for_commit,
    };

    use ergo_wallet::proving::hints::Hint;
    let mut bag = ergo_wallet::proving::hints::HintsBag::empty();
    bag.add(Hint::RealSecretProof(rsp_child0));
    bag.add(Hint::RealCommitment(rc_child0));

    let message = b"threshold-duplicate-leaf-regression";
    let result = prove_sigma(&tree, &empty_registry, message, &bag, &mut OsRngBackend);

    match result {
        Err(WalletError::MissingSecret(_)) => {
            // Correct: position-aware can_prove counted only 1 real branch
            // for k=2 → rejected cleanly.
        }
        Err(WalletError::SelfVerifyFailed) => {
            panic!(
                "REGRESSION: got SelfVerifyFailed instead of MissingSecret — \
                 can_prove is still image-only: threshold preselected both \
                 duplicate leaves as real, build_tree simulated the second, \
                 and the resulting proof failed self-verify. Fix: make \
                 can_prove position-aware."
            );
        }
        Ok(_) => {
            panic!(
                "REGRESSION: prove_sigma succeeded with only 1 hint for k=2 \
                 threshold — can_prove is still image-only and the prover \
                 shipped an invalid proof."
            );
        }
        Err(other) => {
            panic!("unexpected error variant: {other:?}");
        }
    }
}

// ----- top-level bare-leaf hint-only regression -----

/// Regression: prove_sigma top-level bare-leaf must delegate to the three-phase
/// algorithm (build_tree → complete_tree → serialize) when the registry is empty
/// but the hints bag contains a RealSecretProof for the leaf.
///
/// Before fix: the top-level ProveDlog/ProveDHTuple match arm required a local
/// secret, returning MissingSecret before reaching build_tree's hint-aware logic.
///
/// After fix: the top-level match arm is removed; all bare leaves go through
/// build_tree which checks RealSecretProof first.
#[test]
fn top_level_bare_leaf_proves_from_hint_only() {
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::hints::{Hint, HintsBag, RealSecretProof};
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    // A keypair whose secret will NOT be in the target registry.
    let secret = Scalar::from(0xC0DEu64);
    let pk = compressed_pk(ProjectivePoint::GENERATOR * secret);
    let image = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk));
    let message = b"top-level hint-only proof";

    // Source prover (HAS the secret) produces a proof.
    let source_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk,
            scalar: secret.into(),
        }])
        .unwrap();
    let (source_proof, _) = prove_sigma(
        &image,
        &source_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("source prover must succeed");

    // Extract RealSecretProof from the source proof.
    let extracted = ergo_wallet::proving::extract::bag_for_multisig(
        &image,
        &source_proof,
        std::slice::from_ref(&image),
        &[],
    )
    .expect("bag_for_multisig must not error");

    let supplied_rsp: RealSecretProof = extracted
        .hints
        .iter()
        .find_map(|h| match h {
            Hint::RealSecretProof(rsp) if rsp.image == image => Some(rsp.clone()),
            _ => None,
        })
        .expect("bag has RealSecretProof for the leaf");

    // Target prover: empty registry, hint bag only.
    let target_registry = SecretRegistry::empty();
    let mut hint_bag = HintsBag::empty();
    hint_bag.add(Hint::RealSecretProof(supplied_rsp));

    // Before fix: MissingSecret. After fix: succeeds.
    let (reconstructed_proof, _) = prove_sigma(
        &image,
        &target_registry,
        message,
        &hint_bag,
        &mut OsRngBackend,
    )
    .expect(
        "prove_sigma with hint-only top-level bare leaf MUST succeed — \
         before fix: top-level match arm returned MissingSecret before \
         delegating to build_tree's hint-aware logic",
    );

    // Proof must verify.
    let ok = ergo_sigma::verify::verify_sigma_proof(&image, &reconstructed_proof, message)
        .expect("verify_sigma_proof must not error");
    assert!(ok, "hint-only top-level leaf proof must verify");
}

// ----- oracle parity -----

/// Regression: simulated OR inside a threshold must derive the last child's
/// challenge via XOR so it matches the verifier's reconstruction rule.
///
/// Tree: atLeast(1, [OR(Dlog(a), Dlog(b)), Dlog(c)])
/// Registry: ONLY c's secret. OR(a, b) is fully simulated.
///
/// Before the fix: build_tree_simulated assigned parent_challenge to all OR
/// children. The verifier reconstructs child[1].challenge = parent XOR
/// child[0].challenge = parent XOR parent = 0, but the commitment was built
/// against parent_challenge → mismatch → SelfVerifyFailed.
///
/// After the fix: child[0] gets a fresh random challenge; child[1] gets
/// parent XOR child[0].challenge → verifier reconstruction agrees →
/// proof verifies.
#[test]
fn nested_simulated_or_inside_threshold_proves_correctly() {
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    // Valid EC points via small scalars. Secrets for a and b are NOT in the registry.
    let secret_a = Scalar::from(2u64);
    let secret_b = Scalar::from(3u64);
    let secret_c = Scalar::from(0xC0DEu64);
    let pk_a = compressed_pk(ProjectivePoint::GENERATOR * secret_a);
    let pk_b = compressed_pk(ProjectivePoint::GENERATOR * secret_b);
    let pk_c = compressed_pk(ProjectivePoint::GENERATOR * secret_c);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));

    // atLeast(1, [OR(a, b), c])  — c alone satisfies k=1.
    let or_subtree = SigmaBoolean::Cor(vec![img_a, img_b]);
    let tree = SigmaBoolean::Cthreshold {
        k: 1,
        children: vec![or_subtree, img_c],
    };

    // Only c's secret in the registry; OR(a, b) must be fully simulated.
    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_c,
            scalar: secret_c.into(),
        }])
        .unwrap();

    let message = b"nested OR simulation";
    let (proof, _cost) = prove_sigma(
        &tree,
        &registry,
        message,
        &ergo_wallet::proving::hints::HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("prove with c's secret + simulated OR must succeed");

    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &proof, message)
        .expect("verify_sigma_proof must not error");
    assert!(ok, "nested simulated OR proof must verify");
}

/// Regression: OR with an unprovable compound child must route that child through
/// build_tree_simulated instead of erroring.
///
/// Tree: OR(OR(Dlog(a), Dlog(b)), Dlog(c))
/// Registry: ONLY c's secret.
///
/// Before the fix: build_tree's Cor arm built all children with build_tree first,
/// then checked tree_is_real. The recursive call for inner OR(a,b) had no provable
/// child → returned MissingSecret before the outer OR could treat it as a simulated
/// sibling.
///
/// After the fix: Cor arm probes can_prove for each child, picks the first provable
/// (c) as real, and routes all unprovable children (inner OR(a,b)) through
/// build_tree_simulated with fresh challenges. The outer OR can then produce a
/// valid proof with one real branch and one simulated compound branch.
#[test]
fn or_with_unprovable_compound_child_routes_to_simulated() {
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    // Valid EC points via small scalars. Secrets for a and b are NOT in the registry.
    let secret_c = Scalar::from(0xC0DEu64);
    let secret_a = Scalar::from(2u64);
    let secret_b = Scalar::from(3u64);
    let pk_c = compressed_pk(ProjectivePoint::GENERATOR * secret_c);
    let pk_a = compressed_pk(ProjectivePoint::GENERATOR * secret_a);
    let pk_b = compressed_pk(ProjectivePoint::GENERATOR * secret_b);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));

    // OR(OR(a, b), c) — only c's secret is available.
    let inner_or = SigmaBoolean::Cor(vec![img_a, img_b]);
    let outer_or = SigmaBoolean::Cor(vec![inner_or, img_c]);

    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_c,
            scalar: secret_c.into(),
        }])
        .unwrap();

    let message = b"OR with unprovable compound child";
    let (proof, _cost) = prove_sigma(
        &outer_or,
        &registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect(
        "OR with at-least-one-provable-leaf must succeed — \
         before fix: build_tree on inner OR(a,b) returned MissingSecret",
    );

    let ok = ergo_sigma::verify::verify_sigma_proof(&outer_or, &proof, message)
        .expect("verify_sigma_proof must not error");
    assert!(
        ok,
        "OR with simulated compound child must produce a verifying proof"
    );
}

/// Regression: nested simulated OR-of-OR inside a threshold must correctly
/// propagate each simulated OR's root challenge, not its first leaf's challenge.
///
/// Tree: atLeast(1, [OR(OR(Dlog(a), Dlog(b)), Dlog(c)), Dlog(d)])
/// Registry: ONLY d's secret. OR(OR(a,b), c) is fully simulated.
///
/// Before the fix: get_sim_challenge for a compound ProverTree::Or recurse-called
/// children[0], returning the first leaf's challenge rather than the OR's root
/// challenge. The outer OR's XOR-derive then used the wrong value as the
/// representative for the inner-OR child → outer OR's last-child challenge computed
/// incorrectly → commitment mismatch → SelfVerifyFailed.
///
/// After the fix: get_sim_challenge returns sim_root_challenge (the value
/// build_tree_simulated received as its `challenge` argument), which is the OR's
/// true root challenge → outer OR's XOR-derive is correct → proof verifies.
#[test]
fn nested_simulated_or_of_or_inside_threshold_proves_correctly() {
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::{ProjectivePoint, Scalar};

    // d's secret is known; a, b, c are not in the registry.
    let secret_d = Scalar::from(0xDEADu64);
    let secret_a = Scalar::from(2u64);
    let secret_b = Scalar::from(3u64);
    let secret_c = Scalar::from(5u64);
    let pk_d = compressed_pk(ProjectivePoint::GENERATOR * secret_d);
    let pk_a = compressed_pk(ProjectivePoint::GENERATOR * secret_a);
    let pk_b = compressed_pk(ProjectivePoint::GENERATOR * secret_b);
    let pk_c = compressed_pk(ProjectivePoint::GENERATOR * secret_c);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let img_d = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_d));

    // atLeast(1, [OR(OR(a, b), c), d])  — d alone satisfies k=1.
    // OR(OR(a,b), c) is fully simulated (no secret for a, b, or c).
    let inner_or = SigmaBoolean::Cor(vec![img_a, img_b]);
    let outer_or = SigmaBoolean::Cor(vec![inner_or, img_c]);
    let tree = SigmaBoolean::Cthreshold {
        k: 1,
        children: vec![outer_or, img_d],
    };

    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_d,
            scalar: secret_d.into(),
        }])
        .unwrap();

    let message = b"nested OR-of-OR simulation";
    let (proof, _cost) = prove_sigma(
        &tree,
        &registry,
        message,
        &ergo_wallet::proving::hints::HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("prove with d's secret + nested simulated OR must succeed");

    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &proof, message)
        .expect("verify_sigma_proof must not error");
    assert!(ok, "nested simulated OR-of-OR proof must verify");
}

// ----- compound hint-only reconstruction + multi-sig acceptance flows -----

/// `OR(A, B)` with empty registry + full bag (RealSecretProof for A,
/// SimulatedSecretProof for B) must reconstruct a byte-identical verifying
/// proof.
///
/// Contract: when the reconstructor has no registry secret for either branch,
/// A is built from the bag's RealSecretProof + RealCommitment (preserving the
/// original signer's r-point), B is built from the bag's SimulatedSecretProof +
/// SimulatedCommitment. Identical commitments → identical Fiat-Shamir input
/// → identical root_challenge → identical proof bytes.
#[test]
fn or_hint_only_reconstruction_byte_identical() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    // Two distinct secret keys.
    let secret_a = Scalar::from(0xAAAAu64);
    let secret_b = Scalar::from(0xBBBBu64);
    let pk_a: [u8; 33] = {
        let p = ProjectivePoint::GENERATOR * secret_a;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_b: [u8; 33] = {
        let p = ProjectivePoint::GENERATOR * secret_b;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let tree = SigmaBoolean::Cor(vec![img_a.clone(), img_b.clone()]);
    let message = b"or hint-only reconstruction";

    // Step 1: original signer has only A's secret; signs OR(A, B).
    // A is real, B is simulated.
    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (original_proof, _cost) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("original sign");

    // Step 2: extract full bag — Real* for A, Sim* for B.
    let bag = bag_for_multisig(
        &tree,
        &original_proof,
        std::slice::from_ref(&img_a),
        std::slice::from_ref(&img_b),
    )
    .expect("extract full bag");

    // Sanity: bag has both halves.
    use ergo_wallet::proving::hints::Hint;
    let has_real_a = bag
        .hints
        .iter()
        .any(|h| matches!(h, Hint::RealSecretProof(rsp) if rsp.image == img_a));
    let has_sim_b = bag
        .hints
        .iter()
        .any(|h| matches!(h, Hint::SimulatedSecretProof(ssp) if ssp.image == img_b));
    assert!(has_real_a, "bag must contain RealSecretProof for A");
    assert!(has_sim_b, "bag must contain SimulatedSecretProof for B");

    // Step 3: reconstructor has EMPTY registry; reconstructs from bag only.
    let recon_registry = SecretRegistry::empty();
    let (reconstructed_proof, _cost) =
        prove_sigma(&tree, &recon_registry, message, &bag, &mut OsRngBackend)
            .expect("OR hint-only reconstruction must succeed");

    // Step 4: reconstructed proof verifies.
    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &reconstructed_proof, message)
        .expect("verify must not error");
    assert!(ok, "reconstructed OR proof must verify");

    // Step 5: byte-identical to original. This is the strict pin — any drift
    // in commit/challenge/z bytes would diverge from the original.
    assert_eq!(
        reconstructed_proof, original_proof,
        "reconstructed proof must be byte-identical to the original (full hint-only reconstruction)"
    );
}

/// `OR(A, B)` with BOTH secrets in the registry and an empty bag must
/// produce a verifying proof.
///
/// Contract: with no Sim* hints in the subtree, the non-real OR sibling is
/// fresh-simulated with a sampled challenge (not built as Real from the
/// registry, which would collapse both OR children to the same challenge and
/// break the verifier's XOR-derive of the last child's challenge).
#[test]
fn or_both_provable_empty_bag_verifies() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xA11u64);
    let secret_b = Scalar::from(0xB22u64);
    let pk_a: [u8; 33] = {
        let p = ProjectivePoint::GENERATOR * secret_a;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_b: [u8; 33] = {
        let p = ProjectivePoint::GENERATOR * secret_b;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let tree = SigmaBoolean::Cor(vec![img_a, img_b]);
    let message = b"or both provable empty bag";

    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[
            ProverExternalSecret::Dlog {
                pk: pk_a,
                scalar: secret_a.into(),
            },
            ProverExternalSecret::Dlog {
                pk: pk_b,
                scalar: secret_b.into(),
            },
        ])
        .unwrap();

    let (proof, _cost) = prove_sigma(
        &tree,
        &registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("OR(both-provable) sign must succeed");

    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &proof, message)
        .expect("verify must not error");
    assert!(ok, "OR(both-provable) proof must verify");
}

/// `OR(A, B)` where the reconstructor's registry has BOTH secrets AND the
/// bag carries Real(A) + Sim(B): proof must still verify, and B's z must come
/// from the bag's Sim(B) hint (not from a fresh registry-driven simulation).
///
/// Contract: when the bag carries SimulatedSecretProof for a non-real OR
/// sibling's leaf, the simulated leaf is built directly from the bag —
/// bypassing the registry-first leaf precedence. Otherwise both OR siblings
/// would build as Real, collapsing them to the same challenge and breaking
/// the verifier's XOR-derive of the last child's challenge.
#[test]
fn or_non_real_sibling_with_bag_sim_hint_and_overlapping_registry() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xA1A1u64);
    let secret_b = Scalar::from(0xB2B2u64);
    let pk_a: [u8; 33] = {
        let p = ProjectivePoint::GENERATOR * secret_a;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_b: [u8; 33] = {
        let p = ProjectivePoint::GENERATOR * secret_b;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let tree = SigmaBoolean::Cor(vec![img_a.clone(), img_b.clone()]);
    let message = b"or sim-bag with overlapping registry";

    // Step 1: original signer has only A's secret; signs OR(A, B) — A real, B simulated.
    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (original_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("original sign");

    // Step 2: extract bag — Real(A) + Sim(B).
    let bag = bag_for_multisig(
        &tree,
        &original_proof,
        std::slice::from_ref(&img_a),
        std::slice::from_ref(&img_b),
    )
    .expect("extract full bag");

    // Step 3: reconstructor has BOTH A's and B's secrets in registry.
    let recon_registry = SecretRegistry::empty()
        .merge_external_secrets(&[
            ProverExternalSecret::Dlog {
                pk: pk_a,
                scalar: secret_a.into(),
            },
            ProverExternalSecret::Dlog {
                pk: pk_b,
                scalar: secret_b.into(),
            },
        ])
        .unwrap();
    let (reconstructed_proof, _) =
        prove_sigma(&tree, &recon_registry, message, &bag, &mut OsRngBackend)
            .expect("OR reconstruction with overlapping registry must succeed");

    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &reconstructed_proof, message)
        .expect("verify must not error");
    assert!(ok, "reconstructed proof must verify");

    // B's z (last 32 bytes of the OR proof, per the layout
    //   root_ch(24) || ch0(24) || z0(32) || z1(32)
    // for two leaf children) must come from the bag's Sim(B).response —
    // confirming the bag's simulated leaf was authoritative rather than the
    // registry secret freshly re-simulating B.
    assert_eq!(reconstructed_proof.len(), original_proof.len());
    let recon_z1 = &reconstructed_proof[reconstructed_proof.len() - 32..];
    let orig_z1 = &original_proof[original_proof.len() - 32..];
    assert_eq!(
        recon_z1, orig_z1,
        "B's z must equal the bag-supplied Sim(B).response"
    );

    // Full byte-identity is not guaranteed when the registry overlaps the
    // bag's RealSecretProof leaf: A's Real-leaf path samples a fresh
    // r-commitment from the registry rather than adopting the bag's
    // RealCommitment(A), so the Fiat-Shamir input and root_challenge differ
    // from the original. Adopting the bag's RealCommitment for A would
    // require flipping the registry-first precedence for RealSecretProof,
    // which conflicts with the local "registry > hint" invariant pinned by
    // [`registry_secret_ignores_stale_real_secret_proof_hint`].
}

/// `OR(A, AND(B, C))` with empty registry + bag carrying Real(A) + Sim(B) + Sim(C):
/// the non-real OR sibling is a compound AND subtree, and hint-only
/// reconstruction must still produce a verifying byte-identical proof.
///
/// Contract: the simulated AND subtree is rebuilt from the bag's
/// SimulatedSecretProof leaves, and its sim_root_challenge is set to the
/// unanimous child challenge (build_tree_simulated's AND case propagates the
/// parent's challenge to every child, so the original signer's bag entries
/// for B and C must share a single challenge by construction).
#[test]
fn or_with_and_sibling_hint_only_reconstruction_byte_identical() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xABCDu64);
    let secret_b = Scalar::from(0xDEADu64);
    let secret_c = Scalar::from(0xBEEFu64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);
    let pk_c = pk_for(&secret_c);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let tree = SigmaBoolean::Cor(vec![
        img_a.clone(),
        SigmaBoolean::Cand(vec![img_b.clone(), img_c.clone()]),
    ]);
    let message = b"or-with-and-sibling hint-only";

    // Original signer: only A's secret. A real, AND(B,C) fully simulated.
    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (original_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("original sign");

    // Full bag: Real(A) + Sim(B) + Sim(C).
    let real_secrets = [img_a.clone()];
    let sim_secrets = [img_b.clone(), img_c.clone()];
    let bag = bag_for_multisig(&tree, &original_proof, &real_secrets, &sim_secrets)
        .expect("extract full bag");

    // Reconstructor: empty registry, full bag.
    let recon_registry = SecretRegistry::empty();
    let (reconstructed_proof, _) =
        prove_sigma(&tree, &recon_registry, message, &bag, &mut OsRngBackend)
            .expect("OR(A, AND(B,C)) hint-only reconstruction must succeed");

    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &reconstructed_proof, message)
        .expect("verify must not error");
    assert!(ok, "reconstructed proof must verify");

    // Byte-identity: with no registry overlap, all leaves come from the bag —
    // RealCommitment(A), SimulatedCommitment(B), SimulatedCommitment(C) —
    // so the Fiat-Shamir input matches the original signer's exactly.
    assert_eq!(
        reconstructed_proof, original_proof,
        "compound non-real OR sibling reconstruction must be byte-identical"
    );
}

/// `OR(A, OR(B, C))` where the bag carries Real(A) + Sim(B) but no Sim(C):
/// reconstruction must error cleanly rather than emit a non-verifying proof.
///
/// Contract: partial SimulatedSecretProof coverage of a non-real OR sibling
/// subtree means the bag is incomplete for byte-identical reconstruction.
/// Mixing bag-supplied and fresh-simulated leaves would change the derived
/// compound challenge and invalidate any bag-supplied RealSecretProof on the
/// sibling OR branch.
#[test]
fn or_with_partial_sim_coverage_in_compound_sibling_errors() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::error::WalletError;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::{Hint, HintsBag};
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xA1u64);
    let secret_b = Scalar::from(0xB2u64);
    let secret_c = Scalar::from(0xC3u64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);
    let pk_c = pk_for(&secret_c);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let tree = SigmaBoolean::Cor(vec![
        img_a.clone(),
        SigmaBoolean::Cor(vec![img_b.clone(), img_c.clone()]),
    ]);
    let message = b"or(a, or(b, c)) partial-bag";

    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (original_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("original sign");

    // Build a partial bag: Real(A) + Sim(B) only (no Sim(C)).
    let full_bag =
        bag_for_multisig(&tree, &original_proof, &[img_a], &[img_b.clone(), img_c]).unwrap();
    let mut partial = HintsBag::empty();
    for h in &full_bag.hints {
        let drop = matches!(
            h,
            Hint::SimulatedSecretProof(ssp) if ssp.image != img_b
        ) || matches!(
            h,
            Hint::SimulatedCommitment(sc) if sc.image != img_b
        );
        if !drop {
            partial.add(h.clone());
        }
    }

    let recon_registry = SecretRegistry::empty();
    let res = prove_sigma(&tree, &recon_registry, message, &partial, &mut OsRngBackend);
    match res {
        Err(WalletError::MissingSecret(msg)) => {
            assert!(
                msg.contains("cannot be byte-identically reconstructed"),
                "expected partial-coverage error, got: {msg}"
            );
        }
        other => panic!(
            "expected MissingSecret(partial coverage) error, got: {:?}",
            other.as_ref().map(|_| "Ok(proof)")
        ),
    }
}

/// `OR(A, OR(B, C))` where the reconstructor's registry HAS A and the bag
/// carries only Sim(B) (partial coverage of the sibling subtree): must
/// succeed by fresh-simulating the sibling.
///
/// Contract: partial Sim* coverage on a non-real OR sibling is recoverable
/// when the chosen real OR branch is registry-backed — A's z is computed
/// locally against whatever derived challenge the fresh simulation
/// produces, so the bag's partial Sim(B) hint can simply be discarded.
/// The hard error only applies when the real branch is bag-supplied and so
/// carries a stale fixed z.
#[test]
fn or_with_partial_sim_coverage_and_registry_real_branch_signs() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::{Hint, HintsBag};
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xAAu64);
    let secret_b = Scalar::from(0xBBu64);
    let secret_c = Scalar::from(0xCCu64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);
    let pk_c = pk_for(&secret_c);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let tree = SigmaBoolean::Cor(vec![
        img_a.clone(),
        SigmaBoolean::Cor(vec![img_b.clone(), img_c.clone()]),
    ]);
    let message = b"partial bag, registry-backed real branch";

    // Construct a bag that carries a partial Sim* (Sim(B) only, no Sim(C))
    // — extract from an original signer's proof and prune Sim(C).
    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (orig_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .unwrap();
    let full_bag = bag_for_multisig(&tree, &orig_proof, &[img_a], &[img_b.clone(), img_c]).unwrap();
    let mut partial = HintsBag::empty();
    for h in &full_bag.hints {
        let drop = matches!(
            h,
            Hint::SimulatedSecretProof(ssp) if ssp.image != img_b
        ) || matches!(
            h,
            Hint::SimulatedCommitment(sc) if sc.image != img_b
        );
        if !drop {
            partial.add(h.clone());
        }
    }

    // Reconstructor has A in its registry — real branch is registry-backed.
    let recon_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (proof, _) = prove_sigma(&tree, &recon_registry, message, &partial, &mut OsRngBackend)
        .expect("registry-backed real branch should absorb fresh-simulated sibling");
    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &proof, message)
        .expect("verify must not error");
    assert!(ok, "proof must verify");
}

/// `OR(OR(A, B), OR(C, D))` with registry `{B}` and bag `{Real(A), Sim(C)}`:
/// the outer OR picks the left subtree as real, but the inner OR picks A
/// (the first provable child) — and A is bag-supplied. Partial-coverage
/// classification must follow the same path build_tree actually takes; a
/// naive "any descendant is registry-provable" check would mistakenly
/// classify the left subtree as registry-backed and fresh-simulate
/// OR(C, D), invalidating A's bag-supplied z.
#[test]
fn or_partial_sibling_with_compound_real_picking_bag_leaf_errors() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::error::WalletError;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::{Hint, HintsBag};
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xA0u64);
    let secret_b = Scalar::from(0xB0u64);
    let secret_c = Scalar::from(0xC0u64);
    let secret_d = Scalar::from(0xD0u64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);
    let pk_c = pk_for(&secret_c);
    let pk_d = pk_for(&secret_d);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let img_d = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_d));
    let tree = SigmaBoolean::Cor(vec![
        SigmaBoolean::Cor(vec![img_a.clone(), img_b]),
        SigmaBoolean::Cor(vec![img_c.clone(), img_d.clone()]),
    ]);
    let message = b"OR(OR(A,B), OR(C,D)) compound-real bag-picked";

    // Original signer holds only A — outer real_idx=0, inner OR(A,B) real_idx=0,
    // OR(C,D) fully simulated.
    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (orig_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .unwrap();
    // Extract Real(A) + Sim(C) (drop Sim(D)).
    let full_bag = bag_for_multisig(&tree, &orig_proof, &[img_a], &[img_c.clone(), img_d]).unwrap();
    let mut partial = HintsBag::empty();
    for h in &full_bag.hints {
        let drop = matches!(
            h,
            Hint::SimulatedSecretProof(ssp) if ssp.image != img_c
        ) || matches!(
            h,
            Hint::SimulatedCommitment(sc) if sc.image != img_c
        );
        if !drop {
            partial.add(h.clone());
        }
    }

    // Reconstructor has only B in registry. Inner OR(A,B) picks A (the first
    // provable, since both Real(A) hint and registry B are provable) — that
    // is bag-supplied, so the outer real path is NOT registry-backed.
    let recon_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_b,
            scalar: secret_b.into(),
        }])
        .unwrap();
    let res = prove_sigma(&tree, &recon_registry, message, &partial, &mut OsRngBackend);
    match res {
        Err(WalletError::MissingSecret(msg)) => {
            assert!(
                msg.contains("cannot be byte-identically reconstructed"),
                "expected partial-coverage error, got: {msg}"
            );
        }
        other => panic!(
            "expected MissingSecret(partial coverage) error, got: {:?}",
            other.as_ref().map(|_| "Ok(proof)")
        ),
    }
}

/// `OR(A, atLeast(2, [B, C, D]))` with empty registry + bag carrying
/// Real(A) + Sim(B) + Sim(C) + Sim(D): the non-real OR sibling is a
/// threshold subtree whose original signer simulated it via
/// `build_tree_simulated`'s threshold pattern (pre-sample (n-k) sim
/// challenges, derive the remaining k from Q evaluation). Hint-only
/// reconstruction must recover `sim_root_challenge` from the bag's leaf
/// challenges and produce a byte-identical verifying proof.
#[test]
fn or_with_threshold_sibling_hint_only_reconstruction_byte_identical() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xAAAA_u64);
    let secret_b = Scalar::from(0xBBBB_u64);
    let secret_c = Scalar::from(0xCCCC_u64);
    let secret_d = Scalar::from(0xDDDD_u64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);
    let pk_c = pk_for(&secret_c);
    let pk_d = pk_for(&secret_d);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let img_d = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_d));
    let tree = SigmaBoolean::Cor(vec![
        img_a.clone(),
        SigmaBoolean::Cthreshold {
            k: 2,
            children: vec![img_b.clone(), img_c.clone(), img_d.clone()],
        },
    ]);
    let message = b"OR(A, atLeast(2, [B,C,D])) hint-only";

    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (orig_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("original sign of OR(A, threshold) must succeed");
    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &orig_proof, message)
        .expect("orig verify must not error");
    assert!(ok, "original proof must verify");

    let bag = bag_for_multisig(&tree, &orig_proof, &[img_a], &[img_b, img_c, img_d]).unwrap();

    let recon_registry = SecretRegistry::empty();
    let (recon_proof, _) = prove_sigma(&tree, &recon_registry, message, &bag, &mut OsRngBackend)
        .expect("OR(A, threshold) hint-only reconstruction must succeed");
    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &recon_proof, message)
        .expect("recon verify must not error");
    assert!(ok, "reconstructed proof must verify");
    assert_eq!(
        recon_proof, orig_proof,
        "threshold-sibling reconstruction must be byte-identical"
    );
}

/// `OR(A, atLeast(3, [B, C, D]))` (k = n: every threshold child required)
/// with empty registry + full bag: reconstruction must recover
/// `sim_root_challenge` from the constant Q(x) = sim_root and produce a
/// byte-identical proof.
#[test]
fn or_with_threshold_k_equals_n_sibling_hint_only_reconstruction_byte_identical() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xAAA1_u64);
    let secret_b = Scalar::from(0xBBB1_u64);
    let secret_c = Scalar::from(0xCCC1_u64);
    let secret_d = Scalar::from(0xDDD1_u64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);
    let pk_c = pk_for(&secret_c);
    let pk_d = pk_for(&secret_d);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let img_d = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_d));
    let tree = SigmaBoolean::Cor(vec![
        img_a.clone(),
        SigmaBoolean::Cthreshold {
            k: 3,
            children: vec![img_b.clone(), img_c.clone(), img_d.clone()],
        },
    ]);
    let message = b"OR(A, atLeast(3, [B,C,D])) hint-only";

    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (orig_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("original sign of OR(A, k=n threshold) must succeed");
    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &orig_proof, message)
        .expect("orig verify must not error");
    assert!(ok, "original proof must verify");

    let bag = bag_for_multisig(&tree, &orig_proof, &[img_a], &[img_b, img_c, img_d]).unwrap();

    let recon_registry = SecretRegistry::empty();
    let (recon_proof, _) = prove_sigma(&tree, &recon_registry, message, &bag, &mut OsRngBackend)
        .expect("OR(A, k=n threshold) hint-only reconstruction must succeed");
    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &recon_proof, message)
        .expect("recon verify must not error");
    assert!(ok, "reconstructed proof must verify");
    assert_eq!(
        recon_proof, orig_proof,
        "k=n threshold-sibling reconstruction must be byte-identical"
    );
}

/// `OR(A, atLeast(0, [B, C]))` (k = 0: degenerate trivially-satisfied
/// threshold) with registry holding A + full bag: reconstruction must
/// SUCCEED (verifying, not byte-identical) by fresh-simulating the k=0
/// sibling. The k=0 threshold's `sim_root_challenge` is not recoverable
/// from leaf hints (degree-n polynomial has Q(0) as a free coefficient),
/// but a registry-backed real branch can recompute z against any final
/// challenge — so the OR arm falls back to fresh simulation for the
/// sibling.
#[test]
fn or_with_threshold_k_equals_zero_sibling_and_registry_real_branch_signs() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xA0A0_u64);
    let secret_b = Scalar::from(0xB0B0_u64);
    let secret_c = Scalar::from(0xC0C0_u64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);
    let pk_c = pk_for(&secret_c);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let tree = SigmaBoolean::Cor(vec![
        img_a.clone(),
        SigmaBoolean::Cthreshold {
            k: 0,
            children: vec![img_b.clone(), img_c.clone()],
        },
    ]);
    let message = b"OR(A, atLeast(0, [B,C])) registry-backed real";

    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (orig_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("original sign of OR(A, k=0 threshold) must succeed");
    let _ = ergo_sigma::verify::verify_sigma_proof(&tree, &orig_proof, message)
        .expect("orig verify must not error");

    let bag = bag_for_multisig(&tree, &orig_proof, &[img_a], &[img_b, img_c]).unwrap();
    let recon_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (proof, _) = prove_sigma(&tree, &recon_registry, message, &bag, &mut OsRngBackend)
        .expect("registry-backed real branch must allow fresh-simulating the k=0 sibling");
    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &proof, message)
        .expect("verify must not error");
    assert!(ok, "reconstructed proof must verify");
}

/// Same proposition with empty registry (bag-backed real branch via
/// RealSecretProof on A): reconstruction must error cleanly. Fresh-
/// simulating the k=0 sibling would change the outer OR's XOR-derived
/// challenge for A, invalidating A's bag-supplied z.
#[test]
fn or_with_threshold_k_equals_zero_sibling_and_bag_backed_real_branch_errors() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::error::WalletError;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xA0A0_u64);
    let secret_b = Scalar::from(0xB0B0_u64);
    let secret_c = Scalar::from(0xC0C0_u64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);
    let pk_c = pk_for(&secret_c);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let tree = SigmaBoolean::Cor(vec![
        img_a.clone(),
        SigmaBoolean::Cthreshold {
            k: 0,
            children: vec![img_b.clone(), img_c.clone()],
        },
    ]);
    let message = b"OR(A, atLeast(0, [B,C])) bag-backed real errors";

    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (orig_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .unwrap();
    let bag = bag_for_multisig(&tree, &orig_proof, &[img_a], &[img_b, img_c]).unwrap();
    let recon_registry = SecretRegistry::empty();
    let res = prove_sigma(&tree, &recon_registry, message, &bag, &mut OsRngBackend);
    match res {
        Err(WalletError::MissingSecret(msg)) => {
            assert!(
                msg.contains("cannot be byte-identically reconstructed"),
                "expected k=0 + bag-backed real error, got: {msg}"
            );
        }
        other => panic!(
            "expected MissingSecret(k=0 not supported) error, got: {:?}",
            other.as_ref().map(|_| "Ok(proof)")
        ),
    }
}

/// `OR(A, B)` with empty registry and a bag carrying only `RealSecretProof(A)`
/// (no Sim* for B): reconstruction must error cleanly. The real branch A is
/// bag-backed, so fresh-simulating B would change the OR's XOR-derived
/// challenge for A and invalidate A's bag-supplied z. The previous routing
/// fresh-simulated B unconditionally on None coverage, resulting in
/// SelfVerifyFailed; the fix gates fresh-simulation on a registry-backed
/// real branch.
#[test]
fn or_with_no_sim_coverage_and_bag_backed_real_branch_errors() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::error::WalletError;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::extract::bag_for_multisig;
    use ergo_wallet::proving::hints::{Hint, HintsBag};
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xAFAF_u64);
    let secret_b = Scalar::from(0xBFBF_u64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let tree = SigmaBoolean::Cor(vec![img_a.clone(), img_b.clone()]);
    let message = b"OR(A, B) bag-backed A, no Sim(B)";

    let signer_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: pk_a,
            scalar: secret_a.into(),
        }])
        .unwrap();
    let (orig_proof, _) = prove_sigma(
        &tree,
        &signer_registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .unwrap();
    let full_bag = bag_for_multisig(
        &tree,
        &orig_proof,
        std::slice::from_ref(&img_a),
        std::slice::from_ref(&img_b),
    )
    .unwrap();
    // Keep only Real(A) and the Real/Own commitments for A — drop all Sim* entries for B.
    let mut bag = HintsBag::empty();
    for h in &full_bag.hints {
        let drop = matches!(h, Hint::SimulatedSecretProof(ssp) if ssp.image == img_b)
            || matches!(h, Hint::SimulatedCommitment(sc) if sc.image == img_b);
        if !drop {
            bag.add(h.clone());
        }
    }

    let recon_registry = SecretRegistry::empty();
    let res = prove_sigma(&tree, &recon_registry, message, &bag, &mut OsRngBackend);
    match res {
        Err(WalletError::MissingSecret(msg)) => {
            assert!(
                msg.contains("cannot be byte-identically reconstructed"),
                "expected stale-z error, got: {msg}"
            );
        }
        other => panic!(
            "expected MissingSecret(stale-z) error, got: {:?}",
            other.as_ref().map(|_| "Ok(proof)")
        ),
    }
}

/// 2-of-3 multi-sig acceptance: a single assembler holding 2 of 3 secrets
/// (k=2 satisfied locally; C's slot is simulated) signs the threshold tree.
/// This is the canonical "all-secrets-in-one-prover" reduction of the
/// distributed protocol; the full distributed flow (each party signs alone
/// with foreign commits) is not yet implemented.
#[test]
fn two_of_three_threshold_with_combined_registry() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let secret_a = Scalar::from(0xA001u64);
    let secret_b = Scalar::from(0xB002u64);
    let secret_c = Scalar::from(0xC003u64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_a = pk_for(&secret_a);
    let pk_b = pk_for(&secret_b);
    let pk_c = pk_for(&secret_c);

    let img_a = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_a));
    let img_b = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_b));
    let img_c = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_c));
    let tree = SigmaBoolean::Cthreshold {
        k: 2,
        children: vec![img_a, img_b, img_c],
    };

    // Assembler has A's and B's secrets (not C's). This is k=2 satisfied.
    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[
            ProverExternalSecret::Dlog {
                pk: pk_a,
                scalar: secret_a.into(),
            },
            ProverExternalSecret::Dlog {
                pk: pk_b,
                scalar: secret_b.into(),
            },
        ])
        .unwrap();

    let message = b"2-of-3 threshold cooperative sign";
    let (proof, _cost) = prove_sigma(
        &tree,
        &registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("2-of-3 sign must succeed with k=2 secrets present");

    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &proof, message)
        .expect("verify must not error");
    assert!(ok, "2-of-3 threshold proof must verify");
}

/// dApp commitment-exchange acceptance: `AND(wallet_key, dApp_key)` signed
/// by an assembler holding both secrets locally. Pins the
/// AND-with-both-secrets path — the single-party reduction of the dApp
/// coordination. The fully distributed flow (wallet and dApp each sign
/// alone, combining partial proofs without sharing secrets) is not yet
/// implemented.
#[test]
fn dapp_and_with_combined_registry() {
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::external::ProverExternalSecret;
    use ergo_wallet::proving::hints::HintsBag;
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet::proving::sigma::prove_sigma;
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Scalar};

    let wallet_secret = Scalar::from(0xA11_u64);
    let dapp_secret = Scalar::from(0xDAFFu64);
    let pk_for = |s: &Scalar| -> [u8; 33] {
        let p = ProjectivePoint::GENERATOR * s;
        let affine = k256::AffinePoint::from(p);
        let mut out = [0u8; 33];
        out.copy_from_slice(&affine.to_bytes());
        out
    };
    let pk_wallet = pk_for(&wallet_secret);
    let pk_dapp = pk_for(&dapp_secret);

    let img_w = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_wallet));
    let img_d = SigmaBoolean::ProveDlog(GroupElement::from_bytes(pk_dapp));
    let tree = SigmaBoolean::Cand(vec![img_w, img_d]);

    let registry = SecretRegistry::empty()
        .merge_external_secrets(&[
            ProverExternalSecret::Dlog {
                pk: pk_wallet,
                scalar: wallet_secret.into(),
            },
            ProverExternalSecret::Dlog {
                pk: pk_dapp,
                scalar: dapp_secret.into(),
            },
        ])
        .unwrap();

    let message = b"dApp AND cooperative sign";
    let (proof, _cost) = prove_sigma(
        &tree,
        &registry,
        message,
        &HintsBag::empty(),
        &mut OsRngBackend,
    )
    .expect("dApp AND sign must succeed with both secrets");

    let ok = ergo_sigma::verify::verify_sigma_proof(&tree, &proof, message)
        .expect("verify must not error");
    assert!(ok, "dApp AND proof must verify");
}

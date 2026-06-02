//! Schnorr (ProveDlog) proof production.
//!
//! Mirrors Scala `DLogProver` + `ErgoProvingInterpreter.prove`.
//!
//! Fiat-Shamir challenge derivation is grounded against
//! `ergo_sigma::verify::verify_sigma_proof`:
//!   hash_input = fiat_shamir_tree_to_bytes(leaf) || message
//!   challenge  = blake2b256(hash_input)[0..24]
//!
//! For a DLog leaf the FS bytes are:
//!   LEAF_PREFIX(1) | prop_len(2 BE) | prop_bytes(39) | commit_len(2 BE) | R(33)
//! where prop_bytes = build_prove_dlog_ergo_tree(pk) and R = g^r.

use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::schnorr::build_prove_dlog_ergo_tree;
use ergo_sigma::SOUNDNESS_BYTES;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::{MulByGenerator, Reduce};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, U256};

use crate::error::WalletError;
use crate::proving::hints::{
    FirstProverMessage, Hint, HintsBag, OwnCommitment, RealSecretProof, SimulatedSecretProof,
};
use crate::proving::node_position::NodePosition;
use crate::proving::randomness::ProvingRng;

/// Produce a Schnorr proof for a `ProveDlog(pk)` proposition.
///
/// Steps (matching Scala `DLogProver`):
/// 1. Extract pk from proposition.
/// 2. Obtain commitment (r, R): reuse `OwnCommitment` from hints if present
///    (matched by image AND position), otherwise generate fresh with `rng`.
/// 3. Compute Fiat-Shamir challenge: `blake2b256(fs_bytes || message)[0..24]`.
/// 4. Compute response: `z = r + e * x mod q`.
/// 5. Encode proof: `challenge(24B) || z(32B)`.
/// 6. Self-verify — panics in debug; returns `Err(SelfVerifyFailed)` in release.
///
/// `position` is the leaf's location in the proposition tree (depth-first).
/// For bare top-level invocations pass `NodePosition::crypto_tree_prefix()`.
pub fn prove_schnorr(
    proposition: &SigmaBoolean,
    secret: &Scalar,
    message: &[u8],
    hints: &HintsBag,
    position: NodePosition,
    rng: &mut dyn ProvingRng,
) -> Result<Vec<u8>, WalletError> {
    // Step 1: extract pk
    let pk_bytes = match proposition {
        SigmaBoolean::ProveDlog(ge) => *ge.as_bytes(),
        _ => {
            return Err(WalletError::MissingSecret(
                "prove_schnorr called with non-ProveDlog proposition".into(),
            ))
        }
    };

    // Step 2: check hints bag for a pre-computed proof at this (image, position).
    // RealSecretProof: another party already proved this leaf and shared it;
    // use their (challenge, z) directly (self-verify will confirm correctness).
    if let Some(rsp) = find_real_secret_proof(proposition, &position, hints) {
        let mut proof = Vec::with_capacity(SOUNDNESS_BYTES + 32);
        proof.extend_from_slice(&rsp.challenge);
        proof.extend_from_slice(&rsp.response);
        return match ergo_sigma::verify::verify_sigma_proof(proposition, &proof, message) {
            Ok(true) => Ok(proof),
            _ => Err(WalletError::SelfVerifyFailed),
        };
    }
    // SimulatedSecretProof: use the supplied simulation bytes.
    if let Some(ssp) = find_simulated_secret_proof(proposition, &position, hints) {
        let mut proof = Vec::with_capacity(SOUNDNESS_BYTES + 32);
        proof.extend_from_slice(&ssp.challenge);
        proof.extend_from_slice(&ssp.response);
        return match ergo_sigma::verify::verify_sigma_proof(proposition, &proof, message) {
            Ok(true) => Ok(proof),
            _ => Err(WalletError::SelfVerifyFailed),
        };
    }

    // Step 2: commitment (r, R)
    let (r_scalar, r_point_bytes) = find_own_commitment(proposition, &position, hints)
        .unwrap_or_else(|| {
            let r = rng.sample_scalar();
            let r_pt = ProjectivePoint::mul_by_generator(&r);
            let r_bytes: [u8; 33] = r_pt.to_affine().to_bytes().into();
            (r, r_bytes)
        });

    // Step 3: Fiat-Shamir challenge
    // fs_bytes = LEAF_PREFIX(1) | prop_len(2BE) | prop_bytes | commit_len(2BE) | R(33)
    let prop_bytes = build_prove_dlog_ergo_tree(&pk_bytes);
    let fs_bytes = build_fs_leaf_bytes(&prop_bytes, &r_point_bytes);
    let mut hash_input = Vec::with_capacity(fs_bytes.len() + message.len());
    hash_input.extend_from_slice(&fs_bytes);
    hash_input.extend_from_slice(message);
    let hash = ergo_sigma::blake2b256(&hash_input);
    let challenge: [u8; SOUNDNESS_BYTES] = hash[..SOUNDNESS_BYTES].try_into().unwrap();

    // Step 4: z = r + e * x mod q  (additive notation; verifier checks g^z - pk*e = R)
    let e_scalar = challenge_to_scalar(&challenge);
    let z_scalar = r_scalar + e_scalar * secret;

    // Step 5: encode proof
    let z_bytes: [u8; 32] = z_scalar.to_bytes().into();
    let mut proof = Vec::with_capacity(SOUNDNESS_BYTES + 32);
    proof.extend_from_slice(&challenge);
    proof.extend_from_slice(&z_bytes);

    // Step 6: mandatory self-verify
    match ergo_sigma::verify::verify_sigma_proof(proposition, &proof, message) {
        Ok(true) => Ok(proof),
        _ => Err(WalletError::SelfVerifyFailed),
    }
}

/// Build Fiat-Shamir leaf bytes matching `fiat_shamir_tree_to_bytes` in the verifier.
fn build_fs_leaf_bytes(prop_bytes: &[u8], commitment_bytes: &[u8; 33]) -> Vec<u8> {
    const LEAF_PREFIX: u8 = 1;
    let mut buf = Vec::with_capacity(1 + 2 + prop_bytes.len() + 2 + 33);
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
    buf.extend_from_slice(prop_bytes);
    buf.extend_from_slice(&(33i16).to_be_bytes());
    buf.extend_from_slice(commitment_bytes);
    buf
}

/// Convert a 24-byte challenge to a scalar (big-endian, zero-padded to 32 bytes).
/// Matches `challenge_to_scalar` in the verifier.
fn challenge_to_scalar(challenge: &[u8; SOUNDNESS_BYTES]) -> Scalar {
    // Zero-pad on the left: challenge(24B) → [0u8; 8] || challenge(24B) = [u8; 32].
    // Challenge is at most 2^192, well below the secp256k1 group order (~2^256),
    // so from_repr never fails.
    let mut padded = [0u8; 32];
    padded[32 - SOUNDNESS_BYTES..].copy_from_slice(challenge);
    Scalar::from_repr(FieldBytes::from(padded)).expect("challenge < group order by construction")
}

/// Find an `OwnCommitment` hint matching both the proposition and position.
/// Returns `(r_scalar, R_point_bytes)` if found, otherwise `None`.
fn find_own_commitment(
    proposition: &SigmaBoolean,
    position: &NodePosition,
    hints: &HintsBag,
) -> Option<(Scalar, [u8; 33])> {
    for hint in &hints.hints {
        if let Hint::OwnCommitment(OwnCommitment {
            image,
            secret_randomness,
            commitment,
            position: hint_pos,
        }) = hint
        {
            if image == proposition && hint_pos == position {
                if let FirstProverMessage::Schnorr(r_point) = commitment {
                    let r = scalar_from_bytes(secret_randomness)?;
                    return Some((r, *r_point));
                }
            }
        }
    }
    None
}

/// Find a `RealSecretProof` hint matching both the proposition and position.
fn find_real_secret_proof<'a>(
    proposition: &SigmaBoolean,
    position: &NodePosition,
    hints: &'a HintsBag,
) -> Option<&'a RealSecretProof> {
    for hint in &hints.hints {
        if let Hint::RealSecretProof(rsp) = hint {
            if &rsp.image == proposition && &rsp.position == position {
                return Some(rsp);
            }
        }
    }
    None
}

/// Find a `SimulatedSecretProof` hint matching both the proposition and position.
fn find_simulated_secret_proof<'a>(
    proposition: &SigmaBoolean,
    position: &NodePosition,
    hints: &'a HintsBag,
) -> Option<&'a SimulatedSecretProof> {
    for hint in &hints.hints {
        if let Hint::SimulatedSecretProof(ssp) = hint {
            if &ssp.image == proposition && &ssp.position == position {
                return Some(ssp);
            }
        }
    }
    None
}

/// Decode 32 bytes as a secp256k1 scalar (big-endian, reduced mod q).
fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let s = <Scalar as Reduce<U256>>::reduce_bytes(&(*bytes).into());
    if s == Scalar::ZERO {
        None
    } else {
        Some(s)
    }
}

/// Decode a compressed SEC1 point (33 bytes) as a `ProjectivePoint`.
#[allow(dead_code)]
fn decode_point(bytes: &[u8; 33]) -> Option<ProjectivePoint> {
    if bytes[0] == 0x00 {
        return Some(ProjectivePoint::IDENTITY);
    }
    let ep = EncodedPoint::from_bytes(bytes).ok()?;
    let affine = AffinePoint::from_encoded_point(&ep);
    if affine.is_some().into() {
        Some(ProjectivePoint::from(affine.unwrap()))
    } else {
        None
    }
}

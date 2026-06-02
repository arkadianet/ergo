//! DH-tuple (ProveDHTuple) proof production.
//!
//! Mirrors Scala `DiffieHellmanTupleProver` + `ErgoProvingInterpreter.prove`.
//!
//! Fiat-Shamir challenge derivation is grounded against
//! `ergo_sigma::verify::verify_sigma_proof`:
//!   hash_input = fiat_shamir_tree_to_bytes(leaf) || message
//!   challenge  = blake2b256(hash_input)[0..24]
//!
//! For a DHT leaf the FS bytes are:
//!   LEAF_PREFIX(1) | prop_len(2 BE) | prop_bytes(138) | commit_len(2 BE) | A(33) | B(33)
//! where prop_bytes = build_prove_dht_ergo_tree(g,h,u,v) and (A,B) = (g^r, h^r).

use ergo_ser::sigma_value::SigmaBoolean;
use ergo_sigma::dht::build_prove_dht_ergo_tree;
use ergo_sigma::SOUNDNESS_BYTES;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, U256};

use crate::error::WalletError;
use crate::proving::hints::{
    FirstProverMessage, Hint, HintsBag, OwnCommitment, RealSecretProof, SimulatedSecretProof,
};
use crate::proving::node_position::NodePosition;
use crate::proving::randomness::ProvingRng;

/// Produce a DH-tuple proof for a `ProveDHTuple { g, h, u, v }` proposition.
///
/// Steps (matching Scala `DiffieHellmanTupleProver`):
/// 1. Extract (g, h, u, v) from proposition.
/// 2. Obtain r: reuse `OwnCommitment` from hints if present (matched by image AND
///    position), storing both A and B; otherwise generate fresh.
/// 3. Compute commitment pair: `(A, B) = (g^r, h^r)`.
/// 4. Compute Fiat-Shamir challenge: `blake2b256(fs_bytes || message)[0..24]`.
/// 5. Compute response: `z = r + e * x mod q`.
/// 6. Encode proof: `challenge(24B) || z(32B)`.
/// 7. Self-verify — returns `Err(SelfVerifyFailed)` on mismatch.
///
/// `position` is the leaf's location in the proposition tree (depth-first).
/// For bare top-level invocations pass `NodePosition::crypto_tree_prefix()`.
pub fn prove_dht(
    proposition: &SigmaBoolean,
    secret_x: &Scalar,
    message: &[u8],
    hints: &HintsBag,
    position: NodePosition,
    rng: &mut dyn ProvingRng,
) -> Result<Vec<u8>, WalletError> {
    // Step 1: extract group elements
    let (g_bytes, h_bytes, u_bytes, v_bytes) = match proposition {
        SigmaBoolean::ProveDHTuple { g, h, u, v } => {
            (*g.as_bytes(), *h.as_bytes(), *u.as_bytes(), *v.as_bytes())
        }
        _ => {
            return Err(WalletError::MissingSecret(
                "prove_dht called with non-ProveDHTuple proposition".into(),
            ))
        }
    };

    let g_pt = decode_point(&g_bytes)
        .ok_or_else(|| WalletError::MissingSecret("invalid g point in ProveDHTuple".into()))?;
    let h_pt = decode_point(&h_bytes)
        .ok_or_else(|| WalletError::MissingSecret("invalid h point in ProveDHTuple".into()))?;

    // Step 2: check hints bag for a pre-computed proof at this (image, position).
    // RealSecretProof: use the supplied (challenge, z) directly.
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

    // Step 2 + 3: commitment pair (A, B) = (g^r, h^r).
    // Reuse OwnCommitment hint if present (matched by image + position).
    // OwnCommitment stores both A and B directly (DhTuple variant), so
    // we use them verbatim instead of recomputing from r.
    let (r_scalar, a_bytes, b_bytes) =
        find_own_commitment_full(proposition, &position, hints, &g_pt, &h_pt).unwrap_or_else(
            || {
                let r = rng.sample_scalar();
                let a: [u8; 33] = (g_pt * r).to_affine().to_bytes().into();
                let b: [u8; 33] = (h_pt * r).to_affine().to_bytes().into();
                (r, a, b)
            },
        );

    // Commitment bytes = A(33) ++ B(33) = 66 bytes
    let mut commitment_bytes = Vec::with_capacity(66);
    commitment_bytes.extend_from_slice(&a_bytes);
    commitment_bytes.extend_from_slice(&b_bytes);

    // Step 4: Fiat-Shamir challenge
    // fs_bytes = LEAF_PREFIX(1) | prop_len(2 BE) | prop_bytes | commit_len(2 BE) | A(33) | B(33)
    let prop_bytes = build_prove_dht_ergo_tree(&g_bytes, &h_bytes, &u_bytes, &v_bytes);
    let fs_bytes = build_fs_leaf_bytes(&prop_bytes, &commitment_bytes);
    let mut hash_input = Vec::with_capacity(fs_bytes.len() + message.len());
    hash_input.extend_from_slice(&fs_bytes);
    hash_input.extend_from_slice(message);
    let hash = ergo_sigma::blake2b256(&hash_input);
    let challenge: [u8; SOUNDNESS_BYTES] = hash[..SOUNDNESS_BYTES].try_into().unwrap();

    // Step 5: z = r + e * x mod q
    let e_scalar = challenge_to_scalar(&challenge);
    let z_scalar = r_scalar + e_scalar * secret_x;

    // Step 6: encode proof: challenge(24B) || z(32B)
    let z_bytes: [u8; 32] = z_scalar.to_bytes().into();
    let mut proof = Vec::with_capacity(SOUNDNESS_BYTES + 32);
    proof.extend_from_slice(&challenge);
    proof.extend_from_slice(&z_bytes);

    // Step 7: mandatory self-verify
    match ergo_sigma::verify::verify_sigma_proof(proposition, &proof, message) {
        Ok(true) => Ok(proof),
        _ => Err(WalletError::SelfVerifyFailed),
    }
}

/// Build Fiat-Shamir leaf bytes matching `fiat_shamir_tree_to_bytes` in the verifier.
fn build_fs_leaf_bytes(prop_bytes: &[u8], commitment_bytes: &[u8]) -> Vec<u8> {
    const LEAF_PREFIX: u8 = 1;
    let commit_len = commitment_bytes.len() as i16;
    let mut buf = Vec::with_capacity(1 + 2 + prop_bytes.len() + 2 + commitment_bytes.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
    buf.extend_from_slice(prop_bytes);
    buf.extend_from_slice(&commit_len.to_be_bytes());
    buf.extend_from_slice(commitment_bytes);
    buf
}

/// Convert a 24-byte challenge to a scalar (big-endian, zero-padded to 32 bytes).
fn challenge_to_scalar(challenge: &[u8; SOUNDNESS_BYTES]) -> Scalar {
    let mut padded = [0u8; 32];
    padded[32 - SOUNDNESS_BYTES..].copy_from_slice(challenge);
    Scalar::from_repr(FieldBytes::from(padded)).expect("challenge < group order by construction")
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

/// Find an `OwnCommitment` hint matching both proposition and position.
///
/// Returns `(r, a_bytes, b_bytes)` using the stored `DhTuple` commitment
/// so the caller uses the same (A, B) the commitment-generation step emitted
/// rather than recomputing from r and (g, h). Falls back to recomputing from
/// `secret_randomness` if the commitment variant is `Schnorr` (shouldn't happen
/// in correct usage, but avoids a panic).
fn find_own_commitment_full(
    proposition: &SigmaBoolean,
    position: &NodePosition,
    hints: &HintsBag,
    g_pt: &ProjectivePoint,
    h_pt: &ProjectivePoint,
) -> Option<(Scalar, [u8; 33], [u8; 33])> {
    use k256::elliptic_curve::group::GroupEncoding;
    for hint in &hints.hints {
        if let Hint::OwnCommitment(OwnCommitment {
            image,
            secret_randomness,
            commitment,
            position: hint_pos,
        }) = hint
        {
            if image == proposition && hint_pos == position {
                let r = scalar_from_bytes(secret_randomness)?;
                let (a, b) = match commitment {
                    FirstProverMessage::DhTuple { a, b } => (*a, *b),
                    FirstProverMessage::Schnorr(_) => {
                        // Unexpected variant — recompute from r as fallback.
                        let a: [u8; 33] = (*g_pt * r).to_affine().to_bytes().into();
                        let b: [u8; 33] = (*h_pt * r).to_affine().to_bytes().into();
                        (a, b)
                    }
                };
                return Some((r, a, b));
            }
        }
    }
    None
}

/// Decode a compressed SEC1 point (33 bytes) as a `ProjectivePoint`.
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

/// Decode 32 bytes as a secp256k1 scalar (big-endian, reduced mod q).
fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let s = <Scalar as Reduce<U256>>::reduce_bytes(&(*bytes).into());
    if s == Scalar::ZERO {
        None
    } else {
        Some(s)
    }
}

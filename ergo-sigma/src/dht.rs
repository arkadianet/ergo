use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use num_bigint::BigUint;
use thiserror::Error;

use super::{GROUP_SIZE, SOUNDNESS_BYTES};
use crate::blake2b256;

/// Failure modes for [`verify_dht`] / `compute_dht_commitment`.
#[derive(Debug, Error)]
pub enum DhtError {
    /// Proof bytes are shorter than `SOUNDNESS_BYTES + GROUP_SIZE`.
    #[error("proof too short: expected {expected} bytes, got {actual}")]
    ProofTooShort {
        /// Required length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// One of the four group elements (`g`, `h`, `u`, `v`) is not on
    /// the curve. The contained name identifies which one.
    #[error("invalid group element: {which}")]
    InvalidPoint {
        /// Name of the offending input (`"g"`, `"h"`, `"u"`, or `"v"`).
        which: &'static str,
    },
    /// Response scalar `z` could not be decoded as a valid `Scalar`
    /// modulo the group order.
    #[error("invalid response scalar")]
    InvalidResponse,
    /// Recomputed Fiat-Shamir challenge does not match the proof's.
    #[error("challenge mismatch")]
    ChallengeMismatch,
}

/// Verify a standalone ProveDHTuple (Diffie-Hellman tuple) proof.
///
/// Proves knowledge of `x` such that `u = g^x` and `v = h^x`.
///
/// Algorithm (from DiffieHellmanTupleProver.computeCommitment):
/// 1. Parse proof: challenge e (24 bytes) || response z (32 bytes)
/// 2. Reconstruct commitments:
///    a = g^z * u^(-e)
///    b = h^z * v^(-e)
/// 3. Serialize Fiat-Shamir leaf with ProveDHTuple proposition
/// 4. expected_e = Blake2b256(fs_bytes || message)[0..24]
/// 5. Verify expected_e == e
pub fn verify_dht(
    g_bytes: &[u8; 33],
    h_bytes: &[u8; 33],
    u_bytes: &[u8; 33],
    v_bytes: &[u8; 33],
    proof_bytes: &[u8],
    message: &[u8],
) -> Result<(), DhtError> {
    if proof_bytes.len() < SOUNDNESS_BYTES + GROUP_SIZE {
        return Err(DhtError::ProofTooShort {
            expected: SOUNDNESS_BYTES + GROUP_SIZE,
            actual: proof_bytes.len(),
        });
    }

    let challenge = &proof_bytes[..SOUNDNESS_BYTES];
    let z_bytes = &proof_bytes[SOUNDNESS_BYTES..SOUNDNESS_BYTES + GROUP_SIZE];

    let g = decode_point(g_bytes).ok_or(DhtError::InvalidPoint { which: "g" })?;
    let h = decode_point(h_bytes).ok_or(DhtError::InvalidPoint { which: "h" })?;
    let u = decode_point(u_bytes).ok_or(DhtError::InvalidPoint { which: "u" })?;
    let v = decode_point(v_bytes).ok_or(DhtError::InvalidPoint { which: "v" })?;

    let z_scalar = bytes_to_scalar(z_bytes).ok_or(DhtError::InvalidResponse)?;
    let e_scalar = challenge_to_scalar(challenge);

    // a = g^z * u^(-e)
    let commitment_a = g * z_scalar - u * e_scalar;
    // b = h^z * v^(-e)
    let commitment_b = h * z_scalar - v * e_scalar;

    let a_bytes = point_to_bytes(&commitment_a);
    let b_bytes = point_to_bytes(&commitment_b);

    // Commitment bytes = a(33) ++ b(33) = 66 bytes
    let mut commitment_bytes = Vec::with_capacity(66);
    commitment_bytes.extend_from_slice(&a_bytes);
    commitment_bytes.extend_from_slice(&b_bytes);

    let fs_bytes =
        fiat_shamir_dht_leaf_bytes(g_bytes, h_bytes, u_bytes, v_bytes, &commitment_bytes);

    let mut hash_input = Vec::with_capacity(fs_bytes.len() + message.len());
    hash_input.extend_from_slice(&fs_bytes);
    hash_input.extend_from_slice(message);
    let hash = blake2b256(&hash_input);
    let expected_challenge = &hash[..SOUNDNESS_BYTES];

    if challenge == expected_challenge {
        Ok(())
    } else {
        Err(DhtError::ChallengeMismatch)
    }
}

/// Compute DHT commitment points from challenge and response.
/// Returns concatenated a(33) ++ b(33) = 66 bytes.
/// a = g^z * u^(-e), b = h^z * v^(-e)
pub(crate) fn compute_dht_commitment(
    g_bytes: &[u8; 33],
    h_bytes: &[u8; 33],
    u_bytes: &[u8; 33],
    v_bytes: &[u8; 33],
    challenge: &[u8],
    z_bytes: &[u8],
) -> Result<Vec<u8>, DhtError> {
    let g = decode_point(g_bytes).ok_or(DhtError::InvalidPoint { which: "g" })?;
    let h = decode_point(h_bytes).ok_or(DhtError::InvalidPoint { which: "h" })?;
    let u = decode_point(u_bytes).ok_or(DhtError::InvalidPoint { which: "u" })?;
    let v = decode_point(v_bytes).ok_or(DhtError::InvalidPoint { which: "v" })?;
    let z_scalar = bytes_to_scalar(z_bytes).ok_or(DhtError::InvalidResponse)?;
    let e_scalar = challenge_to_scalar(challenge);

    let a = g * z_scalar - u * e_scalar;
    let b = h * z_scalar - v * e_scalar;

    let mut commitment = Vec::with_capacity(66);
    commitment.extend_from_slice(&point_to_bytes(&a));
    commitment.extend_from_slice(&point_to_bytes(&b));
    Ok(commitment)
}

/// Build Fiat-Shamir leaf bytes for ProveDHTuple.
fn fiat_shamir_dht_leaf_bytes(
    g: &[u8; 33],
    h: &[u8; 33],
    u: &[u8; 33],
    v: &[u8; 33],
    commitment_bytes: &[u8],
) -> Vec<u8> {
    const LEAF_PREFIX: u8 = 1;
    let prop_bytes = build_prove_dht_ergo_tree(g, h, u, v);

    let mut result = Vec::with_capacity(1 + 2 + prop_bytes.len() + 2 + commitment_bytes.len());
    result.push(LEAF_PREFIX);
    result.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
    result.extend_from_slice(&prop_bytes);
    result.extend_from_slice(&(commitment_bytes.len() as i16).to_be_bytes());
    result.extend_from_slice(commitment_bytes);
    result
}

/// Build ErgoTree bytes for ProveDHTuple(g,h,u,v) with constant segregation.
pub fn build_prove_dht_ergo_tree(
    g: &[u8; 33],
    h: &[u8; 33],
    u: &[u8; 33],
    v: &[u8; 33],
) -> Vec<u8> {
    // header=0x10 (v0 + segregation), count=1
    // Constant: type=0x08 (SSigmaProp), value=SigmaBoolean(ProveDHTuple)
    // ProveDHTuple tag=0xCE, then g(33) h(33) u(33) v(33)
    // Body: ConstantPlaceholder(0) = 0x73 0x00
    let mut bytes = Vec::with_capacity(1 + 1 + 1 + 1 + 4 * 33 + 2);
    bytes.push(0x10); // header
    bytes.push(1); // 1 constant
    bytes.push(0x08); // SSigmaProp
    bytes.push(0xCE); // ProveDHTuple tag
    bytes.extend_from_slice(g);
    bytes.extend_from_slice(h);
    bytes.extend_from_slice(u);
    bytes.extend_from_slice(v);
    bytes.push(0x73); // ConstantPlaceholder opcode
    bytes.push(0x00); // index 0
    bytes
}

fn decode_point(bytes: &[u8; 33]) -> Option<ProjectivePoint> {
    // SEC1: 0x00 prefix = identity (point at infinity).
    if bytes[0] == 0x00 {
        return Some(ProjectivePoint::IDENTITY);
    }
    let encoded = EncodedPoint::from_bytes(bytes).ok()?;
    let affine = AffinePoint::from_encoded_point(&encoded);
    if affine.is_some().into() {
        Some(ProjectivePoint::from(affine.unwrap()))
    } else {
        None
    }
}

fn point_to_bytes(point: &ProjectivePoint) -> [u8; 33] {
    use k256::elliptic_curve::group::GroupEncoding;
    point.to_affine().to_bytes().into()
}

fn bytes_to_scalar(bytes: &[u8]) -> Option<Scalar> {
    let mut padded = [0u8; 32];
    if bytes.len() > 32 {
        return None;
    }
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    let field_bytes = k256::FieldBytes::from(padded);
    let scalar = Scalar::from_repr(field_bytes);
    if scalar.is_some().into() {
        Some(scalar.unwrap())
    } else {
        None
    }
}

fn challenge_to_scalar(challenge: &[u8]) -> Scalar {
    let e = BigUint::from_bytes_be(challenge);
    let mut out = [0u8; 32];
    let bytes = e.to_bytes_be();
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    let field_bytes = k256::FieldBytes::from(out);
    // Challenge is at most SOUNDNESS_BYTES (24) bytes wide, i.e. < 2^192,
    // and the secp256k1 group order q ≈ 2^256, so the scalar always
    // reduces in-range.
    Scalar::from_repr(field_bytes).expect("challenge < group order by construction")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-shape pin for the `SigmaPropConstant(ProveDHTuple(g,h,u,v))`
    /// ErgoTree encoding. Uses a dummy `[0x02; 33]` point in every
    /// slot — this is NOT a proof-verification oracle, only an
    /// encoding-layout guard. Drift in the surrounding bytes would
    /// silently change the Fiat-Shamir leaf bytes that
    /// `verify_sigma_proof` hashes, so the layout must stay
    /// byte-stable.
    #[test]
    fn build_dht_ergo_tree_emits_known_layout() {
        let g = [0x02u8; 33];
        let tree = build_prove_dht_ergo_tree(&g, &g, &g, &g);
        // header(1) + count(1) + type(1) + tag(1) + 4*pk(132) + opcode(1) + index(1) = 138
        assert_eq!(tree.len(), 138);
        assert_eq!(tree[0], 0x10);
        assert_eq!(tree[1], 1);
        assert_eq!(tree[2], 0x08);
        assert_eq!(tree[3], 0xCE);
    }
}

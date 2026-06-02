use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use num_bigint::BigUint;
use thiserror::Error;

use super::{GROUP_SIZE, SOUNDNESS_BYTES};
use crate::blake2b256;

/// Failure modes for [`verify_schnorr`] / `compute_dlog_commitment`.
#[derive(Debug, Error)]
pub enum SchnorrError {
    /// Proof bytes are shorter than `SOUNDNESS_BYTES + GROUP_SIZE`.
    #[error("proof too short: expected {expected} bytes, got {actual}")]
    ProofTooShort {
        /// Required length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// Public key bytes are not a valid SEC1-compressed secp256k1 point.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Response scalar `z` could not be decoded as a valid `Scalar`
    /// modulo the group order.
    #[error("invalid response scalar")]
    InvalidResponse,
    /// Recomputed Fiat-Shamir challenge does not match the proof's.
    #[error("challenge mismatch")]
    ChallengeMismatch,
}

/// Verify a standalone proveDlog (Schnorr) proof.
///
/// Algorithm (from Scala Interpreter.verifySignature / DLogProtocol):
/// 1. Parse proof: e (24 bytes) || z (32 bytes)
/// 2. Compute commitment: a = g^z * h^(-e) where h = public key
/// 3. Serialize Fiat-Shamir tree bytes for the leaf
/// 4. expected_e = Blake2b256(fiat_shamir_bytes || message)[0..24]
/// 5. Verify expected_e == e
pub fn verify_schnorr(
    pk_bytes: &[u8; 33],
    proof_bytes: &[u8],
    message: &[u8],
) -> Result<(), SchnorrError> {
    if proof_bytes.len() < SOUNDNESS_BYTES + GROUP_SIZE {
        return Err(SchnorrError::ProofTooShort {
            expected: SOUNDNESS_BYTES + GROUP_SIZE,
            actual: proof_bytes.len(),
        });
    }

    // Step 1: Parse challenge and response
    let challenge = &proof_bytes[..SOUNDNESS_BYTES];
    let z_bytes = &proof_bytes[SOUNDNESS_BYTES..SOUNDNESS_BYTES + GROUP_SIZE];

    // Decode public key
    let pk = decode_point(pk_bytes).ok_or(SchnorrError::InvalidPublicKey)?;

    // Decode response z as a scalar
    let z_scalar = bytes_to_scalar(z_bytes).ok_or(SchnorrError::InvalidResponse)?;

    // Step 2: Compute commitment a = g^z * h^(-e)
    let e_scalar = challenge_to_scalar(challenge);
    let g_z = ProjectivePoint::mul_by_generator(&z_scalar);
    let h_e = pk * e_scalar;
    let commitment = g_z - h_e; // g^z * h^(-e) = g^z - h^e in additive notation

    // Step 3: Serialize Fiat-Shamir tree bytes
    let commitment_bytes = point_to_bytes(&commitment);
    let fs_bytes = fiat_shamir_leaf_bytes(pk_bytes, &commitment_bytes);

    // Step 4: Compute expected challenge
    let mut hash_input = Vec::with_capacity(fs_bytes.len() + message.len());
    hash_input.extend_from_slice(&fs_bytes);
    hash_input.extend_from_slice(message);
    let hash = blake2b256(&hash_input);
    let expected_challenge = &hash[..SOUNDNESS_BYTES];

    // Step 5: Verify
    if challenge == expected_challenge {
        Ok(())
    } else {
        Err(SchnorrError::ChallengeMismatch)
    }
}

/// Serialize Fiat-Shamir tree bytes for a DLog leaf.
///
/// Format (from FiatShamirTree.toBytes):
/// leafPrefix(1) | propBytesLen(2 BE) | propBytes | commitmentLen(2 BE) | commitmentBytes
///
/// propBytes = ErgoTree(v0, segregation, SigmaPropConstant(ProveDlog(pk)))
fn fiat_shamir_leaf_bytes(pk_bytes: &[u8; 33], commitment_bytes: &[u8]) -> Vec<u8> {
    const LEAF_PREFIX: u8 = 1;

    // propBytes = canonical ErgoTree for `SigmaPropConstant(ProveDlog(pk))`
    // with constant-segregation enabled (Scala's `withSegregation(ZeroHeader, expr)`):
    //   header (0x10)
    //     | constant_count (VLQ = 1)
    //     | constants[0] = SSigmaProp(0x08) || ProveDlog tag(0xCD) || pk(33B)
    //     | body = ConstantPlaceholder(0xC1) || index(VLQ = 0)
    // The actual byte construction is delegated to the shared
    // `build_prove_dlog_ergo_tree` so this function and the parser stay
    // in lock-step.
    let prop_bytes = build_prove_dlog_ergo_tree(pk_bytes);

    let mut result = Vec::with_capacity(1 + 2 + prop_bytes.len() + 2 + commitment_bytes.len());
    result.push(LEAF_PREFIX);
    result.extend_from_slice(&(prop_bytes.len() as i16).to_be_bytes());
    result.extend_from_slice(&prop_bytes);
    result.extend_from_slice(&(commitment_bytes.len() as i16).to_be_bytes());
    result.extend_from_slice(commitment_bytes);
    result
}

/// Compute the DLog commitment point from challenge and response.
/// Returns the compressed point bytes (33 bytes).
/// a = g^z * h^(-e) where h = public key
pub(crate) fn compute_dlog_commitment(
    pk_bytes: &[u8; 33],
    challenge: &[u8],
    z_bytes: &[u8],
) -> Result<Vec<u8>, SchnorrError> {
    let pk = decode_point(pk_bytes).ok_or(SchnorrError::InvalidPublicKey)?;
    let z_scalar = bytes_to_scalar(z_bytes).ok_or(SchnorrError::InvalidResponse)?;
    let e_scalar = challenge_to_scalar(challenge);
    let commitment = ProjectivePoint::mul_by_generator(&z_scalar) - pk * e_scalar;
    Ok(point_to_bytes(&commitment))
}

/// Build ErgoTree bytes for ProveDlog(pk) with constant segregation.
/// Matches: ErgoTree.withSegregation(ZeroHeader, SigmaPropConstant(ProveDlog(pk)))
pub fn build_prove_dlog_ergo_tree(pk_bytes: &[u8; 33]) -> Vec<u8> {
    // Header: version 0 + segregation flag (0x10)
    let header: u8 = 0x10;

    // Constants: count=1, then the constant
    // Constant format: type_code(SSigmaProp=0x08) + value
    // SSigmaProp value = SigmaBoolean serialized
    // ProveDlog SigmaBoolean: tag=0xCD + pk_bytes(33)
    let const_type = 0x08u8; // SSigmaProp
    let sigma_tag = 0xCDu8; // ProveDlog tag

    // Body: ConstantPlaceholder(index=0, tpe=SSigmaProp)
    // Serialized as: opcode 0x73 + index (VLQ encoded, 0 = 0x00)
    let placeholder_opcode = 0x73u8;
    let placeholder_index = 0x00u8;

    let mut bytes = Vec::with_capacity(1 + 1 + 1 + 1 + 33 + 2);
    bytes.push(header);
    bytes.push(1); // constant count
    bytes.push(const_type);
    bytes.push(sigma_tag);
    bytes.extend_from_slice(pk_bytes);
    bytes.push(placeholder_opcode);
    bytes.push(placeholder_index);
    bytes
}

fn decode_point(bytes: &[u8; 33]) -> Option<ProjectivePoint> {
    // SEC1: 0x00 prefix = identity (point at infinity).
    // k256's AffinePoint can't represent infinity, but ProjectivePoint can.
    // BouncyCastle's ECPoint.decodePoint handles this the same way.
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

fn point_to_bytes(point: &ProjectivePoint) -> Vec<u8> {
    let affine = point.to_affine();
    let encoded: [u8; 33] = affine.to_bytes().into();
    encoded.to_vec()
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

/// Convert a 24-byte challenge to a scalar by interpreting as unsigned big-endian.
fn challenge_to_scalar(challenge: &[u8]) -> Scalar {
    let e = BigUint::from_bytes_be(challenge);
    let bytes = biguint_to_32bytes(&e);
    let field_bytes = k256::FieldBytes::from(bytes);
    // Challenge is at most SOUNDNESS_BYTES (24) bytes wide, i.e. < 2^192,
    // and the secp256k1 group order q ≈ 2^256, so the scalar always
    // reduces in-range.
    Scalar::from_repr(field_bytes).expect("challenge < group order by construction")
}

fn biguint_to_32bytes(val: &BigUint) -> [u8; 32] {
    let bytes = val.to_bytes_be();
    let mut out = [0u8; 32];
    if bytes.len() >= 32 {
        out.copy_from_slice(&bytes[bytes.len() - 32..]);
    } else {
        out[32 - bytes.len()..].copy_from_slice(&bytes);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-shape pin for the `SigmaPropConstant(ProveDlog(pk))`
    /// ErgoTree encoding. Uses a dummy `[0x02; 33]` point — this is
    /// NOT a proof-verification oracle, only an encoding-layout
    /// guard. Drift in the surrounding bytes would silently change
    /// the Fiat-Shamir leaf bytes that `verify_sigma_proof` hashes,
    /// so the layout must stay byte-stable.
    #[test]
    fn build_prove_dlog_ergo_tree_emits_known_layout() {
        let pk = [0x02u8; 33]; // dummy compressed point
        let tree = build_prove_dlog_ergo_tree(&pk);
        // header(1) + count(1) + type(1) + tag(1) + pk(33) + opcode(1) + index(1) = 39
        assert_eq!(tree.len(), 39);
        assert_eq!(tree[0], 0x10); // header
        assert_eq!(tree[1], 1); // 1 constant
        assert_eq!(tree[2], 0x08); // SSigmaProp
        assert_eq!(tree[3], 0xCD); // ProveDlog tag
        assert_eq!(&tree[4..37], &pk);
        assert_eq!(tree[37], 0x73); // ConstantPlaceholder opcode
        assert_eq!(tree[38], 0x00); // index 0
    }
}

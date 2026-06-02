//! Cryptographic helpers shared across the build / finalize / serialize
//! phases. Pure functions over secp256k1 group elements and 24-byte
//! soundness challenges; no RNG, no `SigmaBoolean` walking.

use ergo_sigma::SOUNDNESS_BYTES;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};

use crate::error::WalletError;

/// Back-derive a simulated Schnorr commitment.
/// Verifier checks `g^z = R + pk*e`, so `R = g^z - pk*e`.
pub(super) fn sim_schnorr_commit(
    pk: &[u8; 33],
    challenge: &[u8; SOUNDNESS_BYTES],
    z: &Scalar,
) -> Result<[u8; 33], WalletError> {
    let pk_pt = pt(pk)?;
    let e = challenge_to_scalar(challenge);
    let r_pt = ProjectivePoint::mul_by_generator(z) - pk_pt * e;
    Ok(r_pt.to_affine().to_bytes().into())
}

/// Back-derive a simulated DHT commitment.
/// Verifier checks `g^z = A + u*e` and `h^z = B + v*e`,
/// so `A = g^z - u*e` and `B = h^z - v*e`.
pub(super) fn sim_dht_commit(
    g: &[u8; 33],
    h: &[u8; 33],
    u: &[u8; 33],
    v: &[u8; 33],
    challenge: &[u8; SOUNDNESS_BYTES],
    z: &Scalar,
) -> Result<([u8; 33], [u8; 33]), WalletError> {
    let g_pt = pt(g)?;
    let h_pt = pt(h)?;
    let u_pt = pt(u)?;
    let v_pt = pt(v)?;
    let e = challenge_to_scalar(challenge);
    let a = (g_pt * z) - u_pt * e;
    let b = (h_pt * z) - v_pt * e;
    Ok((
        a.to_affine().to_bytes().into(),
        b.to_affine().to_bytes().into(),
    ))
}

/// Convert 24-byte challenge to a secp256k1 scalar (zero-padded big-endian).
pub(super) fn challenge_to_scalar(ch: &[u8; SOUNDNESS_BYTES]) -> Scalar {
    let mut padded = [0u8; 32];
    padded[32 - SOUNDNESS_BYTES..].copy_from_slice(ch);
    Scalar::from_repr(FieldBytes::from(padded)).expect("24-byte challenge < group order")
}

/// Decode a compressed SEC1 point.
pub(super) fn pt(bytes: &[u8; 33]) -> Result<ProjectivePoint, WalletError> {
    if bytes[0] == 0x00 {
        return Ok(ProjectivePoint::IDENTITY);
    }
    let ep = EncodedPoint::from_bytes(bytes)
        .map_err(|_| WalletError::MissingSecret("invalid compressed point encoding".into()))?;
    let affine = AffinePoint::from_encoded_point(&ep);
    if affine.is_some().into() {
        Ok(ProjectivePoint::from(affine.unwrap()))
    } else {
        Err(WalletError::MissingSecret(
            "point not on secp256k1 curve".into(),
        ))
    }
}

/// XOR `other` into `buf` in place (both are SOUNDNESS_BYTES long).
pub(super) fn xor_bytes(buf: &mut [u8; SOUNDNESS_BYTES], other: &[u8; SOUNDNESS_BYTES]) {
    for (a, b) in buf.iter_mut().zip(other.iter()) {
        *a ^= *b;
    }
}

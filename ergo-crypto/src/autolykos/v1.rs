use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::MulByGenerator;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use num_bigint::BigUint;

use super::common::{biguint_to_32bytes, blake2b256, gen_indexes, AUTOLYKOS_N_BASE, M_BYTES};

/// secp256k1 group order q (FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).
/// Used in v1 for hashModQ and the EC equation, and in both v1/v2 for target: b = q / difficulty.
pub fn secp256k1_order() -> BigUint {
    BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ])
}

/// hashModQ: rejection-sampling Blake2b256 hash that returns a value in [0, q).
/// Matches Scala `ModQHash.hash`:
/// - Hash input, if result < validRange (largest multiple of q <= 2^256), return result mod q.
/// - Otherwise, append a counter byte and retry.
pub fn hash_mod_q(input: &[u8]) -> BigUint {
    let q = secp256k1_order();
    // valid_range = (2^256 / q) * q — the largest multiple of q fitting in 256 bits
    let two_256 = BigUint::from(1u32) << 256;
    let valid_range = &two_256 / &q * &q;

    // Scala ModQHash.hash: if hash(input) >= validRange, recurse with hash(input) as new input.
    let mut current = blake2b256(input);
    loop {
        let val = BigUint::from_bytes_be(&current);
        if val < valid_range {
            return val % &q;
        }
        current = blake2b256(&current);
    }
}

/// Autolykos v1 genElement: hashModQ(index_bytes ++ M ++ pk_bytes ++ msg ++ w_bytes)
fn gen_element_v1(
    index_bytes: &[u8; 4],
    pk_bytes: &[u8],
    msg: &[u8; 32],
    w_bytes: &[u8],
) -> BigUint {
    let mut input = Vec::with_capacity(4 + M_BYTES.len() + pk_bytes.len() + 32 + w_bytes.len());
    input.extend_from_slice(index_bytes);
    input.extend_from_slice(&M_BYTES);
    input.extend_from_slice(pk_bytes);
    input.extend_from_slice(msg);
    input.extend_from_slice(w_bytes);
    hash_mod_q(&input)
}

/// Decode a 33-byte compressed SEC1 point into a ProjectivePoint.
fn decode_point(bytes: &[u8; 33]) -> Option<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes).ok()?;
    let affine = AffinePoint::from_encoded_point(&encoded);
    if affine.is_some().into() {
        Some(ProjectivePoint::from(affine.unwrap()))
    } else {
        None
    }
}

/// Convert a BigUint to a secp256k1 Scalar (mod q).
fn biguint_to_scalar(val: &BigUint) -> Option<Scalar> {
    let q = secp256k1_order();
    let reduced = val % &q;
    let bytes = biguint_to_32bytes(&reduced);
    let field_bytes = k256::FieldBytes::from(bytes);
    let scalar = Scalar::from_repr(field_bytes);
    if scalar.is_some().into() {
        Some(scalar.unwrap())
    } else {
        None
    }
}

/// Full Autolykos v1 PoW check.
///
/// Matches Scala `checkPoWForVersion1`:
/// 1. b = q / decode_compact_bits(nBits) — target
/// 2. Require d < b
/// 3. Require pk and w are valid secp256k1 points (not infinity)
/// 4. seed = msg ++ nonce
/// 5. indexes = genIndexes(seed, NBase)
/// 6. f = sum(genElement_v1(index_j, pk, msg, w) for j in indexes) mod q
/// 7. Verify: w^f == g^d * pk
pub fn check_pow_v1(
    msg: &[u8; 32],
    nonce: &[u8; 8],
    pk_bytes: &[u8; 33],
    w_bytes: &[u8; 33],
    d_bytes: &[u8],
    target: &BigUint,
) -> bool {
    let q = secp256k1_order();
    let d = BigUint::from_bytes_be(d_bytes);

    // d must be < target
    if d >= *target {
        return false;
    }

    // Decode pk and w as EC points
    let pk = match decode_point(pk_bytes) {
        Some(p) => p,
        None => return false,
    };
    let w = match decode_point(w_bytes) {
        Some(p) => p,
        None => return false,
    };

    // Check neither is the identity (infinity)
    if bool::from(pk.is_identity()) || bool::from(w.is_identity()) {
        return false;
    }

    // seed = msg ++ nonce
    let mut seed = [0u8; 40];
    seed[..32].copy_from_slice(msg);
    seed[32..40].copy_from_slice(nonce);

    // Generate indexes and compute f = sum of genElement results mod q
    let indexes = gen_indexes(&seed, AUTOLYKOS_N_BASE);
    let mut f_sum = BigUint::ZERO;
    for &idx in &indexes {
        let idx_bytes = idx.to_be_bytes();
        f_sum += gen_element_v1(&idx_bytes, pk_bytes, msg, w_bytes);
    }
    let f = f_sum % &q;

    // Convert f and d to Scalars for EC operations
    let f_scalar = match biguint_to_scalar(&f) {
        Some(s) => s,
        None => return false,
    };
    let d_scalar = match biguint_to_scalar(&d) {
        Some(s) => s,
        None => return false,
    };

    // left = w^f
    let left = w * f_scalar;
    // right = g^d * pk
    let right = ProjectivePoint::mul_by_generator(&d_scalar) + pk;

    left == right
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- oracle parity -----

    #[test]
    fn secp256k1_order_matches_sec1_constant() {
        // SEC2 v2 §2.4.1, also Bitcoin Core's `SECP256K1_N`. Pinning the
        // exact 32-byte value guards against any accidental drift in the
        // BigUint construction at the top of this file.
        let q = secp256k1_order();
        assert_eq!(
            hex::encode(q.to_bytes_be()),
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        );
    }

    // ----- round-trips -----

    #[test]
    fn decode_point_roundtrips_secp256k1_generator() {
        use k256::elliptic_curve::group::GroupEncoding;
        let g = ProjectivePoint::GENERATOR;
        let g_bytes: [u8; 33] = g.to_affine().to_bytes().into();
        let decoded = decode_point(&g_bytes).unwrap();
        assert_eq!(decoded, g);
    }
}

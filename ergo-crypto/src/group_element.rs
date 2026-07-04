//! GroupElement (secp256k1 point) decompression and on-curve validation.
//!
//! Bridges the compressed SEC1 wire format (`[u8; 33]` — the source-of-truth
//! representation `ergo-compiler`'s typed AST stores for `GroupElement`
//! constants) to the decompressed affine `(x, y)` coordinate pair the Scala
//! reference prints via `Ecp.toString` — `(x_hex,y_hex,1)` — for the
//! ErgoScript typed-tree s-expression printer (`ergo-compiler/src/typed_print.rs`).
//!
//! Mirrors the on-curve decision in
//! `ergo-sigma/src/evaluator/opcodes/sigma.rs::decode_group_element` (same
//! `k256::EncodedPoint::from_bytes` → `AffinePoint::from_encoded_point`
//! sequence) WITHOUT duplicating its error type — that helper is eval-time
//! (`EvalError`); this one is compile-time (`GroupElementError`).
//!
//! # Identity policy
//!
//! `ergo-sigma`'s eval-time `decode_group_element` treats `bytes[0] == 0x00`
//! as a shortcut for the group identity (`ProjectivePoint::IDENTITY`) — valid
//! at RUN time. At COMPILE time, an `env::lift`ed `GroupElement` literal is
//! always a JVM-constructed curve point (`decodePoint` is never
//! constant-folded — golden_seed.txt §23(e)) and cannot be off-curve or
//! identity by construction, so a `0x00`-prefixed or off-curve 33-byte
//! literal has no faithful Scala counterpart to mirror. We reject both as a
//! bounded, reject-side-safe deviation (see the D-T5 ledger note in
//! `ergo-compiler/src/lib.rs`).

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};

/// Compile-time GroupElement literal validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GroupElementError {
    /// `bytes[0] == 0x00` — the group-identity sentinel. No JVM-constructed
    /// env value can ever be the identity point; see the module doc.
    #[error("GroupElement literal is the identity point (0x00 prefix)")]
    Identity,
    /// A well-formed SEC1 prefix (`0x02`/`0x03`) whose x-coordinate has no
    /// valid y on the secp256k1 curve.
    #[error("GroupElement literal is not on the secp256k1 curve")]
    NotOnCurve,
}

/// Decompress a 33-byte SEC1-compressed secp256k1 point to its affine `(x, y)`
/// hex coordinates — lowercase, 64 hex chars each (32 bytes), matching the
/// oracle's `Ecp @(x,y,1)` fields.
///
/// Errors on the identity sentinel (`bytes[0] == 0x00`) or an off-curve point.
pub fn decompress_to_affine_hex(bytes: &[u8; 33]) -> Result<(String, String), GroupElementError> {
    if bytes[0] == 0x00 {
        return Err(GroupElementError::Identity);
    }
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| GroupElementError::NotOnCurve)?;
    let affine_opt = AffinePoint::from_encoded_point(&encoded);
    if !bool::from(affine_opt.is_some()) {
        return Err(GroupElementError::NotOnCurve);
    }
    let affine = affine_opt.unwrap();
    let uncompressed = affine.to_encoded_point(false);
    let x = uncompressed
        .x()
        .expect("uncompressed encoding always carries x");
    let y = uncompressed
        .y()
        .expect("uncompressed encoding always carries y");
    Ok((to_hex(x), to_hex(y)))
}

/// `true` iff `bytes` decodes to a valid, non-identity secp256k1 point.
pub fn is_on_curve(bytes: &[u8; 33]) -> bool {
    decompress_to_affine_hex(bytes).is_ok()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// secp256k1 generator G, SEC1-compressed (parity 0x02, even y).
    fn generator_bytes() -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        bytes
    }

    /// `g3 = 7*G`, a fixed non-generator point (Task-2 `env.rs`/
    /// `typer_oracle_parity.rs` `non_generator_ge`; oracle-captured
    /// golden_seed.txt §23(c)).
    fn g3_bytes() -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let x = hex::decode("5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
            .expect("valid hex");
        bytes[1..].copy_from_slice(&x);
        bytes
    }

    /// A well-formed SEC1 prefix (`0x02`) whose x-coordinate (`5`) has no
    /// valid y on secp256k1 — `x^3 + 7 mod p` is not a quadratic residue
    /// (independently verified: `pow(5**3 + 7, (p-1)//2, p) == p-1`, i.e. a
    /// quadratic non-residue, for secp256k1's field prime
    /// `p = 2**256 - 2**32 - 977`).
    fn off_curve_bytes() -> [u8; 33] {
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        bytes[32] = 0x05;
        bytes
    }

    // ----- happy path -----

    #[test]
    fn decompress_generator_matches_golden_seed_l52_l124() {
        // Oracle: test-vectors/ergoscript/typer/golden_seed.txt L54 (g1.negate)
        // and L126 (PK(...) — same generator key), both embedding
        // `(79be667e...f81798,483ada77...0d4b8,1)`.
        let (x, y) = decompress_to_affine_hex(&generator_bytes()).expect("on-curve");
        assert_eq!(
            x,
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(
            y,
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
    }

    #[test]
    fn decompress_g3_matches_golden_seed_23c() {
        // Oracle: golden_seed.txt §23(c) L493-494 — `tce g3` /
        // `tce proveDlog(g3)`, both `(5cbdf064...c4f9bc,6aebca40...87264da,1)`.
        let (x, y) = decompress_to_affine_hex(&g3_bytes()).expect("on-curve");
        assert_eq!(
            x,
            "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
        );
        assert_eq!(
            y,
            "6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da"
        );
    }

    #[test]
    fn is_on_curve_true_for_generator_and_g3() {
        assert!(is_on_curve(&generator_bytes()));
        assert!(is_on_curve(&g3_bytes()));
    }

    // ----- error paths -----

    #[test]
    fn decompress_off_curve_point_errors() {
        let err = decompress_to_affine_hex(&off_curve_bytes()).unwrap_err();
        assert_eq!(err, GroupElementError::NotOnCurve);
        assert!(!is_on_curve(&off_curve_bytes()));
    }

    #[test]
    fn decompress_identity_prefix_errors() {
        // bytes[0] == 0x00 — the group-identity sentinel (see module doc's
        // identity policy: never JVM-constructible, so this is a reject not
        // an accept-as-identity like the eval-time `decode_group_element`).
        let bytes = [0u8; 33];
        let err = decompress_to_affine_hex(&bytes).unwrap_err();
        assert_eq!(err, GroupElementError::Identity);
        assert!(!is_on_curve(&bytes));
    }
}

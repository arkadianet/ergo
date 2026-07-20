//! BabyBear prime-field Montgomery-decode boundary for the EIP-0045 raw-seal
//! transport. Faithful port of sigmastate `sigma.stark.BabyBear` (@9372697).
//!
//! RISC0 stores digest words as raw Montgomery residues (`R = 2^32`);
//! [`from_raw`] converts a wire word back to its canonical value, and
//! [`to_raw`] is its inverse (used only to build test vectors). Consensus-
//! critical: every accepted seal word is decoded through here, and the values
//! are pinned by the raw-seal KATs (`raw_seal::tests`).

/// Field modulus, `p = 15 * 2^27 + 1 = 2_013_265_921`.
pub const P: u32 = 2_013_265_921;

/// `a * b mod P` for canonical operands (`< P`). Carried in `u64`, which cannot
/// overflow for 31-bit operands.
const fn mul(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % P as u64) as u32
}

/// `a^e mod P` by square-and-multiply (`const` so the Montgomery constants are
/// resolved at compile time, not carried as unexplained magic numbers).
const fn pow(mut base: u32, mut exp: u64) -> u32 {
    let mut acc: u32 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mul(acc, base);
        }
        base = mul(base, base);
        exp >>= 1;
    }
    acc
}

/// Multiplicative inverse by Fermat: `a^(P-2) mod P`. Undefined for zero.
const fn inv(a: u32) -> u32 {
    pow(a, P as u64 - 2)
}

/// `R = 2^32 mod P` — the Montgomery radix (== 268_435_454).
const MONT_R: u32 = ((1u64 << 32) % P as u64) as u32;

/// `R^-1 mod P` (== 943_718_400).
const MONT_R_INV: u32 = inv(MONT_R);

/// Canonical value of a raw (Montgomery) RISC0 digest word: `w * R^-1 mod P`.
pub const fn from_raw(w: u32) -> u32 {
    mul(w, MONT_R_INV)
}

/// Raw (Montgomery) RISC0 digest word of a canonical value: `x * R mod P`. The
/// inverse of [`from_raw`]; used to synthesize seal words in tests.
pub const fn to_raw(x: u32) -> u32 {
    mul(x, MONT_R)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn mont_constants_match_reference() {
        // Pinned against sigmastate `BabyBear.MontR` / `MontRInv` (@9372697).
        assert_eq!(MONT_R, 268_435_454);
        assert_eq!(MONT_R_INV, 943_718_400);
    }

    // ----- round-trips -----

    #[test]
    fn from_raw_to_raw_roundtrips_over_sampled_field() {
        for x in [0u32, 1, 2, 18, 65_535, 65_536, P - 1, P / 2, 123_456_789] {
            assert_eq!(from_raw(to_raw(x)), x);
            assert_eq!(to_raw(from_raw(x)), x);
        }
    }

    // ----- oracle parity -----

    #[test]
    fn mont_r_inv_is_the_inverse_of_mont_r() {
        assert_eq!(mul(MONT_R, MONT_R_INV), 1);
    }
}

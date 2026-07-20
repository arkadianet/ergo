//! The BabyBear prime field, `p = 15·2^27 + 1 = 2013265921` — the base field
//! of the RISC0 STARK verifier profile proposed for EIP-0045 (`verifyStark`).
//!
//! Elements are canonical `u32`s in `[0, P)`; all intermediate arithmetic is
//! carried in `u64`, which cannot overflow for 31-bit operands. This is a
//! straightforward reference port of the sigmastate `BabyBear` object:
//! correctness is pinned by Known Answer Tests taken from RISC0's own field
//! implementation (`test-vectors/ergo-stark/babybear_ops.tsv`), per the
//! oracle-parity rule.

/// Namespace for BabyBear field arithmetic over canonical `u32` values in
/// `[0, P)`. A zero-sized type used purely to mirror the reference's
/// `BabyBear.add`/`BabyBear.mul` call style.
pub struct BabyBear;

impl BabyBear {
    /// Field modulus, `15·2^27 + 1`.
    pub const P: u32 = 2013265921;

    /// `a + b mod P` for canonical operands.
    #[inline]
    pub const fn add(a: u32, b: u32) -> u32 {
        let s = a as u64 + b as u64;
        (if s >= Self::P as u64 {
            s - Self::P as u64
        } else {
            s
        }) as u32
    }

    /// `a - b mod P` for canonical operands.
    #[inline]
    pub const fn sub(a: u32, b: u32) -> u32 {
        // Compute in i64 so the borrow is exact, mirroring the reference.
        let d = a as i64 - b as i64;
        (if d < 0 { d + Self::P as i64 } else { d }) as u32
    }

    /// `a * b mod P` for canonical operands.
    #[inline]
    pub const fn mul(a: u32, b: u32) -> u32 {
        ((a as u64 * b as u64) % Self::P as u64) as u32
    }

    /// `-a mod P` for a canonical operand.
    #[inline]
    pub const fn neg(a: u32) -> u32 {
        if a == 0 {
            0
        } else {
            Self::P - a
        }
    }

    /// `a^e mod P` by square-and-multiply.
    pub const fn pow(a: u32, e: u64) -> u32 {
        let mut base = a;
        let mut exp = e;
        let mut acc: u32 = 1;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = Self::mul(acc, base);
            }
            base = Self::mul(base, base);
            exp >>= 1;
        }
        acc
    }

    /// Multiplicative inverse by Fermat: `a^(P-2)`.
    ///
    /// # Panics
    /// Panics if `a == 0` (zero has no inverse), matching the reference's
    /// `require`.
    pub const fn inv(a: u32) -> u32 {
        assert!(a != 0, "zero has no inverse");
        Self::pow(a, (Self::P - 2) as u64)
    }

    /// `2^32 mod P` — risc0-core stores BabyBear elements in Montgomery form
    /// (`R = 2^32`), and RISC0 digest WORDS are raw Montgomery residues
    /// (`Elem::new_raw` / `as_words`). [`from_raw`](Self::from_raw) and
    /// [`to_raw`](Self::to_raw) convert between that wire form and this
    /// implementation's canonical values at the digest boundary.
    pub const MONT_R: u32 = ((1u64 << 32) % Self::P as u64) as u32;

    /// `R^{-1} mod P`.
    pub const MONT_R_INV: u32 = Self::inv(Self::MONT_R);

    /// Canonical value of a raw (Montgomery) RISC0 digest word.
    #[inline]
    pub const fn from_raw(w: u32) -> u32 {
        Self::mul(w, Self::MONT_R_INV)
    }

    /// Raw (Montgomery) RISC0 digest word of a canonical value.
    #[inline]
    pub const fn to_raw(x: u32) -> u32 {
        Self::mul(x, Self::MONT_R)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    /// One BabyBear op-vector row: operands and every expected output.
    struct Row {
        a: u32,
        b: u32,
        add: u32,
        sub: u32,
        mul: u32,
        neg_a: u32,
        inv_a: Option<u32>,
        pow_a_b: u32,
    }

    fn load_rows() -> Vec<Row> {
        let tsv = include_str!("../../test-vectors/ergo-stark/babybear_ops.tsv");
        tsv.lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let c: Vec<&str> = l.split('\t').collect();
                Row {
                    a: c[0].parse().unwrap(),
                    b: c[1].parse().unwrap(),
                    add: c[2].parse().unwrap(),
                    sub: c[3].parse().unwrap(),
                    mul: c[4].parse().unwrap(),
                    neg_a: c[5].parse().unwrap(),
                    inv_a: if c[6] == "-" {
                        None
                    } else {
                        Some(c[6].parse().unwrap())
                    },
                    pow_a_b: c[7].parse().unwrap(),
                }
            })
            .collect()
    }

    // ----- happy path -----

    #[test]
    fn modulus_and_montgomery_constants_match_reference() {
        assert_eq!(BabyBear::P, 2013265921);
        // 2^32 mod P.
        assert_eq!(BabyBear::MONT_R, 268435454);
        // R * R^{-1} == 1.
        assert_eq!(BabyBear::mul(BabyBear::MONT_R, BabyBear::MONT_R_INV), 1);
    }

    #[test]
    fn raw_canonical_roundtrips() {
        for x in [0u32, 1, 2, 12345, BabyBear::P - 1] {
            assert_eq!(BabyBear::from_raw(BabyBear::to_raw(x)), x);
        }
    }

    // ----- oracle parity -----

    #[test]
    fn babybear_ops_match_risc0_oracle() {
        let rows = load_rows();
        assert!(
            rows.len() >= 60,
            "expected the full op vector, got {}",
            rows.len()
        );
        for r in &rows {
            assert_eq!(BabyBear::add(r.a, r.b), r.add, "add({},{})", r.a, r.b);
            assert_eq!(BabyBear::sub(r.a, r.b), r.sub, "sub({},{})", r.a, r.b);
            assert_eq!(BabyBear::mul(r.a, r.b), r.mul, "mul({},{})", r.a, r.b);
            assert_eq!(BabyBear::neg(r.a), r.neg_a, "neg({})", r.a);
            assert_eq!(
                BabyBear::pow(r.a, r.b as u64),
                r.pow_a_b,
                "pow({},{})",
                r.a,
                r.b
            );
            if let Some(inv) = r.inv_a {
                assert_eq!(BabyBear::inv(r.a), inv, "inv({})", r.a);
                assert_eq!(BabyBear::mul(r.a, inv), 1, "a*inv(a) for a={}", r.a);
            }
        }
    }

    // ----- error paths -----

    #[test]
    #[should_panic(expected = "zero has no inverse")]
    fn inv_of_zero_panics() {
        let _ = BabyBear::inv(0);
    }
}

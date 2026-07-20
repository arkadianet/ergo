//! The degree-4 extension of BabyBear used by the RISC0 STARK verifier
//! profile (EIP-0045): `F_p[x] / (x^4 + 11)` with coefficients
//! `c0 + c1·x + c2·x^2 + c3·x^3` (matching risc0-core's `BabyBearExtElem`
//! coefficient order).
//!
//! Reduction uses `x^4 = -11 (= P - 11)`. Correctness — including the sign
//! convention of the irreducible polynomial — is pinned by Known Answer Tests
//! taken from risc0-core's own `ExtElem` (`test-vectors/ergo-stark/ext4_ops.tsv`);
//! inversion goes through Fermat in the extension (`a^(p^4 - 2)`), a
//! reference-simplicity choice pinned by the same vectors.

use crate::baby_bear::BabyBear as F;

/// An element of `F_p[x]/(x^4 + 11)` in coefficient order `c0 + c1·x + c2·x^2 + c3·x^3`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ext4 {
    pub c0: u32,
    pub c1: u32,
    pub c2: u32,
    pub c3: u32,
}

impl Ext4 {
    /// `x^4 = NBETA`, i.e. `-11 mod P` (irreducible `x^4 + 11`).
    pub const NBETA: u32 = F::P - 11;

    /// The additive identity.
    pub const ZERO: Ext4 = Ext4 {
        c0: 0,
        c1: 0,
        c2: 0,
        c3: 0,
    };
    /// The multiplicative identity.
    pub const ONE: Ext4 = Ext4 {
        c0: 1,
        c1: 0,
        c2: 0,
        c3: 0,
    };

    /// `p^4 - 2`, the Fermat inversion exponent of the extension field.
    /// `p^4 ≈ 1.6·10^37` fits comfortably in a `u128`.
    pub const FERMAT_EXP: u128 = (F::P as u128).pow(4) - 2;

    /// Constructs `Ext4` with the given coefficients.
    #[inline]
    pub const fn new(c0: u32, c1: u32, c2: u32, c3: u32) -> Ext4 {
        Ext4 { c0, c1, c2, c3 }
    }

    /// Embeds a base-field element as `a + 0·x + 0·x^2 + 0·x^3`.
    #[inline]
    pub const fn from_base(a: u32) -> Ext4 {
        Ext4 {
            c0: a,
            c1: 0,
            c2: 0,
            c3: 0,
        }
    }

    /// Coefficient-wise addition.
    #[inline]
    pub const fn add(self, that: Ext4) -> Ext4 {
        Ext4 {
            c0: F::add(self.c0, that.c0),
            c1: F::add(self.c1, that.c1),
            c2: F::add(self.c2, that.c2),
            c3: F::add(self.c3, that.c3),
        }
    }

    /// Coefficient-wise subtraction.
    #[inline]
    pub const fn sub(self, that: Ext4) -> Ext4 {
        Ext4 {
            c0: F::sub(self.c0, that.c0),
            c1: F::sub(self.c1, that.c1),
            c2: F::sub(self.c2, that.c2),
            c3: F::sub(self.c3, that.c3),
        }
    }

    /// Coefficient-wise negation.
    #[inline]
    pub const fn neg(self) -> Ext4 {
        Ext4 {
            c0: F::neg(self.c0),
            c1: F::neg(self.c1),
            c2: F::neg(self.c2),
            c3: F::neg(self.c3),
        }
    }

    /// Extension multiplication: schoolbook product then fold degrees 4..6 with
    /// `x^4 = NBETA (= -11)`. Accumulation order mirrors the reference exactly.
    #[inline]
    pub const fn mul(self, that: Ext4) -> Ext4 {
        let (c0, c1, c2, c3) = (self.c0, self.c1, self.c2, self.c3);
        let p0 = F::mul(c0, that.c0);
        let p1 = F::add(F::mul(c0, that.c1), F::mul(c1, that.c0));
        let p2 = F::add(
            F::add(F::mul(c0, that.c2), F::mul(c1, that.c1)),
            F::mul(c2, that.c0),
        );
        let p3 = F::add(
            F::add(
                F::add(F::mul(c0, that.c3), F::mul(c1, that.c2)),
                F::mul(c2, that.c1),
            ),
            F::mul(c3, that.c0),
        );
        let p4 = F::add(
            F::add(F::mul(c1, that.c3), F::mul(c2, that.c2)),
            F::mul(c3, that.c1),
        );
        let p5 = F::add(F::mul(c2, that.c3), F::mul(c3, that.c2));
        let p6 = F::mul(c3, that.c3);

        Ext4 {
            c0: F::add(p0, F::mul(p4, Ext4::NBETA)),
            c1: F::add(p1, F::mul(p5, Ext4::NBETA)),
            c2: F::add(p2, F::mul(p6, Ext4::NBETA)),
            c3: p3,
        }
    }

    /// True iff every coefficient is zero.
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.c0 == 0 && self.c1 == 0 && self.c2 == 0 && self.c3 == 0
    }

    /// `self^e` by square-and-multiply over a non-negative exponent.
    pub const fn pow(self, e: u128) -> Ext4 {
        let mut base = self;
        let mut exp = e;
        let mut acc = Ext4::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        acc
    }

    /// Multiplicative inverse by Fermat in the extension: `a^(p^4 - 2)`.
    ///
    /// # Panics
    /// Panics if `self` is zero, matching the reference's `require`.
    pub const fn inv(self) -> Ext4 {
        assert!(!self.is_zero(), "zero has no inverse");
        self.pow(Ext4::FERMAT_EXP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn parse_ext(s: &str) -> Ext4 {
        let v: Vec<u32> = s.split(',').map(|x| x.parse().unwrap()).collect();
        Ext4::new(v[0], v[1], v[2], v[3])
    }

    struct Row {
        a: Ext4,
        b: Ext4,
        add: Ext4,
        mul: Ext4,
        inv_a: Option<Ext4>,
    }

    fn load_rows() -> Vec<Row> {
        let tsv = include_str!("../../test-vectors/ergo-stark/ext4_ops.tsv");
        tsv.lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let c: Vec<&str> = l.split('\t').collect();
                Row {
                    a: parse_ext(c[0]),
                    b: parse_ext(c[1]),
                    add: parse_ext(c[2]),
                    mul: parse_ext(c[3]),
                    inv_a: if c[4] == "-" {
                        None
                    } else {
                        Some(parse_ext(c[4]))
                    },
                }
            })
            .collect()
    }

    // ----- happy path -----

    #[test]
    fn identities_and_nbeta() {
        assert_eq!(Ext4::NBETA, 2013265910);
        let x = Ext4::new(1, 2, 3, 4);
        assert_eq!(x.mul(Ext4::ONE), x);
        assert_eq!(x.add(Ext4::ZERO), x);
        assert_eq!(x.sub(x), Ext4::ZERO);
        assert_eq!(x.add(x.neg()), Ext4::ZERO);
        // p^4 - 2 sanity: p^4 = (p^2)^2.
        let p = F::P as u128;
        assert_eq!(Ext4::FERMAT_EXP, p * p * p * p - 2);
    }

    // ----- oracle parity -----

    #[test]
    fn ext4_ops_match_risc0_oracle() {
        let rows = load_rows();
        assert!(
            rows.len() >= 40,
            "expected the full op vector, got {}",
            rows.len()
        );
        for r in &rows {
            assert_eq!(r.a.add(r.b), r.add, "add {:?} {:?}", r.a, r.b);
            assert_eq!(r.a.mul(r.b), r.mul, "mul {:?} {:?}", r.a, r.b);
            if let Some(inv) = r.inv_a {
                assert_eq!(r.a.inv(), inv, "inv {:?}", r.a);
                assert_eq!(r.a.mul(inv), Ext4::ONE, "a*inv(a) {:?}", r.a);
            }
        }
    }

    // ----- error paths -----

    #[test]
    #[should_panic(expected = "zero has no inverse")]
    fn inv_of_zero_panics() {
        let _ = Ext4::ZERO.inv();
    }
}

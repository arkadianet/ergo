use num_bigint::BigUint;

use super::{Rational, ReferencePrice, SpectrumN2TPool};

pub fn reference_spot(pool: &SpectrumN2TPool, token_decimals: u32) -> ReferencePrice {
    let erg = BigUint::from(pool.effective_erg_reserve);
    let token = BigUint::from(pool.token_y_reserve);
    let token_scale = BigUint::from(10u8).pow(token_decimals);
    let nanoerg_scale = BigUint::from(1_000_000_000u64);
    let raw = Rational::new(erg * token_scale, token * nanoerg_scale)
        .expect("decoded pool has a positive token reserve");
    let display = raw.display_truncated_9();

    ReferencePrice {
        display,
        raw,
        token_decimals,
    }
}

#[cfg(test)]
mod tests {
    use crate::v1::decode::decoders::spectrum::{SpectrumN2TPool, N2T_NON_TRADABLE_NANOERG};
    use ergo_primitives::digest::Digest32;
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_traits::Zero;
    use proptest::prelude::*;

    use super::*;

    // ----- helpers -----

    fn pool_with_reserves(erg_reserve: u64, token_y_reserve: u64) -> SpectrumN2TPool {
        SpectrumN2TPool {
            pool_box_id: Digest32::from_bytes([1; 32]),
            pool_nft: Digest32::from_bytes([2; 32]),
            lp_token: Digest32::from_bytes([3; 32]),
            token_y: Digest32::from_bytes([4; 32]),
            token_y_reserve,
            erg_reserve,
            effective_erg_reserve: erg_reserve - N2T_NON_TRADABLE_NANOERG,
            fee_numerator: 997,
        }
    }

    fn reduced_parts(numerator: BigUint, denominator: BigUint) -> (String, String) {
        let gcd = numerator.gcd(&denominator);
        (
            (numerator / &gcd).to_str_radix(10),
            (denominator / gcd).to_str_radix(10),
        )
    }

    fn truncated_9(numerator: BigUint, denominator: BigUint) -> String {
        let (integer, mut remainder) = numerator.div_rem(&denominator);
        let mut display = integer.to_str_radix(10);
        if remainder.is_zero() {
            return display;
        }

        display.push('.');
        for _ in 0..9 {
            remainder *= 10u8;
            let (digit, next_remainder) = remainder.div_rem(&denominator);
            display.push_str(&digit.to_str_radix(10));
            remainder = next_remainder;
            if remainder.is_zero() {
                break;
            }
        }
        while display.ends_with('0') {
            display.pop();
        }
        if display.ends_with('.') {
            display.pop();
        }
        display
    }

    // ----- happy path -----

    #[test]
    fn spot_returns_reduced_whole_token_erg_ratio() {
        let pool = pool_with_reserves(34_583_910, 1_000_000);
        let price = reference_spot(&pool, 6);

        assert_eq!(
            price.raw.parts_decimal(),
            ("2458391".to_string(), "100000000".to_string())
        );
        assert_eq!(price.display, "0.02458391");
        assert_eq!(price.token_decimals, 6);
    }

    #[test]
    fn spot_converts_u64_reserves_before_multiplication() {
        let pool = pool_with_reserves(u64::MAX, 1);
        let price = reference_spot(&pool, 19);
        let numerator =
            BigUint::from(u64::MAX - N2T_NON_TRADABLE_NANOERG) * BigUint::from(10u8).pow(19);
        let denominator = BigUint::from(1_000_000_000u64);

        assert_eq!(
            price.raw.parts_decimal(),
            reduced_parts(numerator, denominator)
        );
    }

    #[test]
    fn spot_accepts_max_u64_reserves() {
        let pool = SpectrumN2TPool {
            erg_reserve: u64::MAX,
            effective_erg_reserve: u64::MAX - N2T_NON_TRADABLE_NANOERG,
            token_y_reserve: u64::MAX,
            ..pool_with_reserves(N2T_NON_TRADABLE_NANOERG + 1, 1)
        };
        let price = reference_spot(&pool, 255);
        let numerator =
            BigUint::from(u64::MAX - N2T_NON_TRADABLE_NANOERG) * BigUint::from(10u8).pow(255);
        let denominator = BigUint::from(u64::MAX) * BigUint::from(1_000_000_000u64);

        assert_eq!(
            price.raw.parts_decimal(),
            reduced_parts(numerator.clone(), denominator.clone())
        );
        assert_eq!(price.display, truncated_9(numerator, denominator));
        assert_eq!(price.token_decimals, 255);
    }

    #[test]
    fn spot_accepts_decimal_boundary_255() {
        let pool = pool_with_reserves(N2T_NON_TRADABLE_NANOERG + 1, 1);
        let price = reference_spot(&pool, 255);

        assert_eq!(price.token_decimals, 255);
        assert_eq!(price.raw.numerator(), &BigUint::from(10u8).pow(246));
        assert_eq!(price.raw.denominator(), &BigUint::from(1u8));
    }

    // ----- round-trips -----

    proptest! {
        #[test]
        fn spot_display_agrees_with_raw_for_every_emitted_digit(
            erg_reserve in (N2T_NON_TRADABLE_NANOERG + 1)..=u64::MAX,
            token_y_reserve in 1u64..=u64::MAX,
            token_decimals in 0u32..=18,
        ) {
            let pool = pool_with_reserves(erg_reserve, token_y_reserve);
            let price = reference_spot(&pool, token_decimals);
            let numerator = BigUint::from(erg_reserve - N2T_NON_TRADABLE_NANOERG)
                * BigUint::from(10u8).pow(token_decimals);
            let denominator =
                BigUint::from(token_y_reserve) * BigUint::from(1_000_000_000u64);

            prop_assert_eq!(price.display, truncated_9(numerator, denominator));
        }
    }

    // ----- error paths -----

    // ----- oracle parity -----
}

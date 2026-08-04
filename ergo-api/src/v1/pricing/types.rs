use std::fmt;

use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::register::RegisterId;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rational {
    numerator: BigUint,
    denominator: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferencePrice {
    pub display: String,
    pub raw: Rational,
    pub token_decimals: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RationalError {
    ZeroDenominator,
}

impl fmt::Display for RationalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("rational denominator cannot be zero")
    }
}

impl std::error::Error for RationalError {}

impl Rational {
    pub fn new(numerator: BigUint, denominator: BigUint) -> Result<Self, RationalError> {
        if denominator.is_zero() {
            return Err(RationalError::ZeroDenominator);
        }
        if numerator.is_zero() {
            return Ok(Self {
                numerator,
                denominator: BigUint::from(1u8),
            });
        }

        let gcd = numerator.gcd(&denominator);
        Ok(Self {
            numerator: numerator / &gcd,
            denominator: denominator / gcd,
        })
    }

    pub fn numerator(&self) -> &BigUint {
        &self.numerator
    }

    pub fn denominator(&self) -> &BigUint {
        &self.denominator
    }

    pub fn display_truncated_9(&self) -> String {
        let (integer, mut remainder) = self.numerator.div_rem(&self.denominator);
        let mut display = integer.to_str_radix(10);
        if remainder.is_zero() {
            return display;
        }

        display.push('.');
        for _ in 0..9 {
            remainder *= 10u8;
            let (digit, next_remainder) = remainder.div_rem(&self.denominator);
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

    pub fn parts_decimal(&self) -> (String, String) {
        (
            self.numerator.to_str_radix(10),
            self.denominator.to_str_radix(10),
        )
    }
}

pub fn token_decimals_from_r6(box_data: &ErgoBox) -> Option<u32> {
    let register = box_data
        .candidate
        .additional_registers
        .get(RegisterId::R6)?;
    let parsed_i32 = match (&register.tpe, &register.value) {
        (SigmaType::SColl(inner), SigmaValue::Coll(CollValue::Bytes(bytes)))
            if inner.as_ref() == &SigmaType::SByte =>
        {
            std::str::from_utf8(bytes).ok()?.parse::<i32>().ok()?
        }
        (SigmaType::SInt, SigmaValue::Int(value)) => *value,
        _ => return None,
    };
    let decimals = u32::try_from(parsed_i32).ok()?;
    (decimals <= 255).then_some(decimals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{CollValue, SigmaValue};

    // ----- helpers -----

    fn box_with_r6(register: Option<RegisterValue>) -> ErgoBox {
        let tree_bytes = hex::decode(
            include_str!("../../../tests/fixtures/spectrum_n2t_v1_ergo_tree.hex").trim(),
        )
        .unwrap();
        let mut reader = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut reader).unwrap();
        let mut registers = Vec::new();
        if let Some(register) = register {
            registers.extend([
                RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(0),
                },
                RegisterValue {
                    tpe: SigmaType::SInt,
                    value: SigmaValue::Int(0),
                },
                register,
            ]);
        }
        let candidate = ErgoBoxCandidate::new(
            1_000_000,
            ergo_tree,
            700_000,
            Vec::new(),
            AdditionalRegisters { registers },
        )
        .unwrap();

        ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([0xAA; 32]),
            index: 0,
        }
    }

    fn box_with_r6_bytes(bytes: &[u8]) -> ErgoBox {
        box_with_r6(Some(RegisterValue {
            tpe: SigmaType::SColl(Box::new(SigmaType::SByte)),
            value: SigmaValue::Coll(CollValue::Bytes(bytes.to_vec())),
        }))
    }

    fn box_with_r6_int(value: i32) -> ErgoBox {
        box_with_r6(Some(RegisterValue {
            tpe: SigmaType::SInt,
            value: SigmaValue::Int(value),
        }))
    }

    // ----- happy path -----

    #[test]
    fn rational_reduces_by_gcd() {
        let rational = Rational::new(42u32.into(), 56u32.into()).unwrap();

        assert_eq!(rational.parts_decimal(), ("3".to_string(), "4".to_string()));
    }

    #[test]
    fn rational_zero_is_canonical_zero_over_one() {
        assert_eq!(
            Rational::new(0u32.into(), 99u32.into())
                .unwrap()
                .parts_decimal(),
            ("0".to_string(), "1".to_string())
        );
    }

    #[test]
    fn display_integer_has_no_decimal_point() {
        assert_eq!(
            Rational::new(42u32.into(), 2u32.into())
                .unwrap()
                .display_truncated_9(),
            "21"
        );
    }

    #[test]
    fn display_truncates_after_nine_digits_without_rounding() {
        assert_eq!(
            Rational::new(1u32.into(), 3u32.into())
                .unwrap()
                .display_truncated_9(),
            "0.333333333"
        );
        assert_eq!(
            Rational::new(1u32.into(), 2_000_000_000u64.into())
                .unwrap()
                .display_truncated_9(),
            "0"
        );
    }

    #[test]
    fn display_trims_trailing_fractional_zeroes() {
        assert_eq!(
            Rational::new(2_458_391u32.into(), 100_000_000u32.into())
                .unwrap()
                .display_truncated_9(),
            "0.02458391"
        );
    }

    #[test]
    fn display_preserves_leading_fractional_zeroes() {
        assert_eq!(
            Rational::new(1u32.into(), 100_000u32.into())
                .unwrap()
                .display_truncated_9(),
            "0.00001"
        );
    }

    #[test]
    fn r6_utf8_i32_is_primary_decimal_encoding() {
        assert_eq!(token_decimals_from_r6(&box_with_r6_bytes(b"09")), Some(9));
    }

    #[test]
    fn r6_sint_is_fallback_decimal_encoding() {
        assert_eq!(token_decimals_from_r6(&box_with_r6_int(9)), Some(9));
    }

    #[test]
    fn r6_zero_is_known() {
        assert_eq!(token_decimals_from_r6(&box_with_r6_int(0)), Some(0));
    }

    #[test]
    fn r6_two_hundred_fifty_five_is_known() {
        assert_eq!(token_decimals_from_r6(&box_with_r6_int(255)), Some(255));
    }

    // ----- round-trips -----

    // ----- error paths -----

    #[test]
    fn rational_rejects_zero_denominator() {
        assert_eq!(
            Rational::new(1u32.into(), 0u32.into()),
            Err(RationalError::ZeroDenominator)
        );
    }

    #[test]
    fn r6_negative_is_unknown() {
        assert_eq!(token_decimals_from_r6(&box_with_r6_int(-1)), None);
    }

    #[test]
    fn r6_two_hundred_fifty_six_is_unknown() {
        assert_eq!(token_decimals_from_r6(&box_with_r6_int(256)), None);
    }

    #[test]
    fn r6_invalid_utf8_is_unknown() {
        assert_eq!(token_decimals_from_r6(&box_with_r6_bytes(&[0xff])), None);
    }

    #[test]
    fn r6_non_numeric_utf8_is_unknown() {
        assert_eq!(token_decimals_from_r6(&box_with_r6_bytes(b"nine")), None);
    }

    #[test]
    fn r6_wrong_sigma_type_is_unknown() {
        let box_data = box_with_r6(Some(RegisterValue {
            tpe: SigmaType::SLong,
            value: SigmaValue::Long(9),
        }));

        assert_eq!(token_decimals_from_r6(&box_data), None);
    }

    #[test]
    fn r6_missing_is_unknown() {
        assert_eq!(token_decimals_from_r6(&box_with_r6(None)), None);
    }

    // ----- oracle parity -----
}

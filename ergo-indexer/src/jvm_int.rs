//! Scala 2.12 signed-Int parsing with the captured JDK 17 BMP digit table.
//!
//! Integer parsing is used only for token register metadata. The reference
//! iterates UTF-16 code units, so supplementary digits must be rejected.
//! Exact runtime observations are in test-vectors/ergo-indexer/token-text.

// Character.digit(char, 10) groups from the complete captured BMP scan. Every
// group contains exactly the decimal digits 0 through 9; no numeric symbols
// outside these groups are accepted by the captured runtime.
const DIGIT_ZEROES: [u32; 37] = [
    0x0030, 0x0660, 0x06f0, 0x07c0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0be6, 0x0c66, 0x0ce6,
    0x0d66, 0x0de6, 0x0e50, 0x0ed0, 0x0f20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80,
    0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0,
    0xff10,
];

pub(crate) fn parse_i32(text: &str) -> Option<i32> {
    let (negative, digits) = if let Some(rest) = text.strip_prefix('-') {
        (true, rest)
    } else {
        (false, text.strip_prefix('+').unwrap_or(text))
    };
    if digits.is_empty() {
        return None;
    }
    // Accumulate negatively to represent i32::MIN without an intermediate
    // positive value outside the domain. Positive overflow is checked at exit.
    let mut value = 0i32;
    for digit in digits.chars() {
        let code = u32::from(digit);
        let zero = DIGIT_ZEROES
            .iter()
            .find(|&&zero| code >= zero && code - zero < 10)?;
        value = value.checked_mul(10)?.checked_sub((code - zero) as i32)?;
    }
    if negative {
        Some(value)
    } else {
        value.checked_neg()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn single_bmp_characters_match_complete_jvm_digit_observation() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../test-vectors/ergo-indexer/token-text/stdout.json"
        ))
        .unwrap();
        let digits: BTreeMap<u32, i32> = fixture["bmp_digits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    pair[0].as_u64().unwrap() as u32,
                    pair[1].as_i64().unwrap() as i32,
                )
            })
            .collect();
        assert_eq!(digits.len(), 370);
        for code in 0..=u16::MAX as u32 {
            if let Some(character) = char::from_u32(code) {
                assert_eq!(
                    parse_i32(&character.to_string()),
                    digits.get(&code).copied(),
                    "U+{code:04X}"
                );
            } else {
                assert!(!digits.contains_key(&code), "surrogate is not a digit");
            }
        }
    }
}

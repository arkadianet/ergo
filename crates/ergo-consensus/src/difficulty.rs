//! Bitcoin-style compact difficulty encoding/decoding (nBits).
//!
//! Ports `DifficultySerializer.scala` from the Ergo reference implementation.

use num_bigint::BigUint;

/// Decode a compact `nBits` value into a full difficulty target.
///
/// This implements the same algorithm as `DifficultySerializer.decodeCompactBits`
/// in the Scala reference. The compact format stores a size byte in the top 8 bits
/// and up to 3 mantissa bytes in the lower 24 bits.
pub fn decode_compact_bits(compact: u64) -> BigUint {
    let size = ((compact >> 24) & 0xFF) as usize;

    // Build the MPI-encoded byte array: 4-byte big-endian length prefix + `size` data bytes.
    let mut bytes = vec![0u8; 4 + size];

    // Write `size` as the 4th byte (big-endian u32 where only the low byte matters here).
    bytes[3] = size as u8;

    if size >= 1 {
        bytes[4] = ((compact >> 16) & 0xFF) as u8;
    }
    if size >= 2 {
        bytes[5] = ((compact >> 8) & 0xFF) as u8;
    }
    if size >= 3 {
        bytes[6] = (compact & 0xFF) as u8;
    }

    decode_mpi(&bytes)
}

/// Encode a difficulty value into the compact `nBits` representation.
///
/// This implements the same algorithm as `DifficultySerializer.encodeCompactBits`
/// in the Scala reference. Ergo difficulties are always positive.
///
/// **Important:** Java's `BigInteger.toByteArray()` returns a signed 2's complement
/// representation that includes a leading 0x00 byte when the MSB is set. Rust's
/// `BigUint::to_bytes_be()` does not add this leading zero. We add it manually to
/// match the Scala behavior.
pub fn encode_compact_bits(value: &BigUint) -> u64 {
    // Get big-endian bytes, matching Java BigInteger.toByteArray() behavior:
    // add a leading 0x00 if the high bit is set.
    let raw = value.to_bytes_be();
    let value_bytes = if !raw.is_empty() && (raw[0] & 0x80) != 0 {
        let mut padded = Vec::with_capacity(raw.len() + 1);
        padded.push(0x00);
        padded.extend_from_slice(&raw);
        padded
    } else if raw.is_empty() {
        vec![0x00]
    } else {
        raw
    };

    let mut size = value_bytes.len();

    let mut result: u64 = if size <= 3 {
        // Fit the value into the low 24 bits, shifted left to fill 3 bytes.
        let mut v = 0u64;
        for &b in &value_bytes {
            v = (v << 8) | (b as u64);
        }
        v << (8 * (3 - size))
    } else {
        // Take the top 3 bytes.
        let mut v = 0u64;
        for &b in &value_bytes[..3] {
            v = (v << 8) | (b as u64);
        }
        v
    };

    // If the sign bit (0x00800000) would be set, shift right and increase size.
    if (result & 0x0080_0000) != 0 {
        result >>= 8;
        size += 1;
    }

    result |= (size as u64) << 24;

    // Ergo difficulty is always positive (BigUint), so the sign bit (0x00800000)
    // is never set. The Scala code has:
    //   val a: Int = if (value.signum == -1) 0x00800000 else 0
    // Since BigUint cannot be negative, `a` is always 0.

    result
}

/// Decode an MPI-encoded byte array into a `BigUint`.
///
/// The first 4 bytes are a big-endian length, followed by `length` data bytes.
/// The high bit of the first data byte indicates sign (cleared, then interpreted
/// as unsigned big-endian). Since Ergo difficulties are always positive, we just
/// clear the sign bit and construct an unsigned value.
fn decode_mpi(mpi: &[u8]) -> BigUint {
    if mpi.len() < 4 {
        return BigUint::ZERO;
    }

    // Read the 4-byte big-endian length.
    let length = u32::from_be_bytes([mpi[0], mpi[1], mpi[2], mpi[3]]) as usize;

    if length == 0 || mpi.len() < 4 + length {
        return BigUint::ZERO;
    }

    // Copy the data bytes.
    let mut buf = mpi[4..4 + length].to_vec();

    if buf.is_empty() {
        return BigUint::ZERO;
    }

    // The high bit of buf[0] is the sign bit in MPI format. Clear it.
    // (For Ergo, difficulty is always positive, but we follow the Scala logic.)
    let _is_negative = (buf[0] & 0x80) == 0x80;
    if _is_negative {
        buf[0] &= 0x7F;
    }

    // Ergo difficulties are always positive, so we skip the Scala negate logic.
    BigUint::from_bytes_be(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn decode_compact_bits_basic() {
        let diff = decode_compact_bits(0x1A01E7F0);
        assert!(diff > BigUint::ZERO);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = BigUint::from(1_000_000u64);
        let compact = encode_compact_bits(&original);
        let decoded = decode_compact_bits(compact);
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_compact_bits_one() {
        let diff = decode_compact_bits(0x01010000);
        assert_eq!(diff, BigUint::from(1u32));
    }

    #[test]
    fn encode_compact_bits_known_value() {
        let diff = BigUint::from(1u32);
        let compact = encode_compact_bits(&diff);
        let decoded = decode_compact_bits(compact);
        assert_eq!(decoded, diff);
    }

    #[test]
    fn decode_large_difficulty() {
        let diff = decode_compact_bits(0x1903842e);
        assert!(diff > BigUint::from(1_000_000u64));
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn compact_bits_roundtrip(difficulty in 1u64..=u64::MAX) {
            let big = num_bigint::BigUint::from(difficulty);
            let encoded = encode_compact_bits(&big);
            let decoded = decode_compact_bits(encoded);
            // Compact encoding may lose precision for large values,
            // so we verify the re-encode roundtrips
            let re_encoded = encode_compact_bits(&decoded);
            prop_assert_eq!(encoded, re_encoded);
        }
    }
}

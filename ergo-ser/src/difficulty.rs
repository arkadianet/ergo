use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

/// Serialize `nBits` as 4 raw big-endian bytes. Unlike most Ergo
/// integers on the wire, `nBits` is **not** VLQ-encoded — the format
/// matches Bitcoin's compact-target representation byte-for-byte.
pub fn write_nbits(w: &mut VlqWriter, nbits: u32) {
    w.put_bytes(&nbits.to_be_bytes());
}

/// Decode a 4-byte big-endian `nBits` value from `r`.
pub fn read_nbits(r: &mut VlqReader) -> Result<u32, ReadError> {
    Ok(u32::from_be_bytes(r.get_array::<4>()?))
}

/// Decode the compact-bits representation into the full 256-bit target.
///
/// The high byte of `nbits` is the byte length of the encoded target.
/// The low 23 bits hold the mantissa (the sign bit at `0x00800000` is
/// reserved and must be zero for valid Ergo targets). The target is
/// reconstructed as `mantissa * 256^(size - 3)`.
pub fn decode_compact_bits(nbits: u32) -> num_bigint::BigUint {
    use num_bigint::BigUint;
    let size = (nbits >> 24) as usize;
    let mantissa = nbits & 0x007FFFFF;
    if size <= 3 {
        BigUint::from(mantissa >> (8 * (3 - size)))
    } else {
        BigUint::from(mantissa) << (8 * (size - 3))
    }
}

/// Encode a difficulty value back into compact `nBits` form. Inverse of
/// [`decode_compact_bits`]; matches Scala's
/// `DifficultySerializer.encodeCompactBits`.
pub fn encode_compact_bits(value: &num_bigint::BigUint) -> u32 {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() || (bytes.len() == 1 && bytes[0] == 0) {
        return 0;
    }

    let mut size = bytes.len();

    let mut result: u64 = if size <= 3 {
        let val_u64 = biguint_to_u64(value);
        val_u64 << (8 * (3 - size))
    } else {
        let shifted = value >> (8 * (size - 3));
        biguint_to_u64(&shifted)
    };

    // Bit 0x00800000 is the sign bit. Targets are always positive, so if
    // the mantissa happens to land with that bit set, shift one more
    // byte right and bump `size` so the encoded value stays positive.
    if (result & 0x0080_0000) != 0 {
        result >>= 8;
        size += 1;
    }

    result |= (size as u64) << 24;
    result as u32
}

fn biguint_to_u64(value: &num_bigint::BigUint) -> u64 {
    value.to_u64_digits().first().copied().unwrap_or(0)
}

/// Round-trip a difficulty value through encode/decode. Equivalent to
/// `decode_compact_bits(encode_compact_bits(value))` and matches Scala's
/// behaviour for `decodeCompactBits(encodeCompactBits(value))`. Used
/// when the in-memory difficulty must be aligned to the on-wire
/// precision before further computation.
pub fn normalize_difficulty(value: &num_bigint::BigUint) -> num_bigint::BigUint {
    decode_compact_bits(encode_compact_bits(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn decode_compact_bits_known_nbits_is_positive() {
        let target = decode_compact_bits(0x1a_01_76_5e);
        assert!(target > num_bigint::BigUint::from(0u32));
    }

    // ----- round-trips -----

    #[test]
    fn nbits_roundtrips() {
        let values: Vec<u32> = vec![0x01_00_00_00, 0x1a_01_76_5e, 0x18_06_7e_61];
        for &v in &values {
            let mut w = VlqWriter::new();
            write_nbits(&mut w, v);
            let data = w.result();
            assert_eq!(data.len(), 4);
            let mut r = VlqReader::new(&data);
            assert_eq!(read_nbits(&mut r).unwrap(), v);
        }
    }

    #[test]
    fn compact_bits_encode_decode_roundtrips() {
        let test_nbits: Vec<u32> = vec![0x1a_01_76_5e, 0x18_06_7e_61, 0x1d_00_ff_ff];
        for &nbits in &test_nbits {
            let decoded = decode_compact_bits(nbits);
            let re_encoded = encode_compact_bits(&decoded);
            assert_eq!(re_encoded, nbits, "roundtrip failed for {:#010x}", nbits);
        }
    }

    #[test]
    fn normalize_difficulty_is_idempotent() {
        let big = num_bigint::BigUint::from(12345678u64);
        let normalized = normalize_difficulty(&big);
        let re_normalized = normalize_difficulty(&normalized);
        assert_eq!(normalized, re_normalized);
    }
}

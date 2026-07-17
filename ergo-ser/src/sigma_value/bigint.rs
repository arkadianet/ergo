//! `SBigInt` / `SUnsignedBigInt` value codecs — DataSerializer convention:
//! VLQ-`u16` length prefix + big-endian payload, 32-byte cap.

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::error::WriteError;

// -- BigInt (DataSerializer convention: u16 length prefix) --

pub(super) fn write_bigint_value(
    w: &mut VlqWriter,
    value: &num_bigint::BigInt,
) -> Result<(), WriteError> {
    let bytes = value.to_signed_bytes_be();
    // Scala DataSerializer encodes BigInt as `putUShort(len) + bytes`,
    // gated by `MaxBigIntSizeInBytes = 32` at CoreDataSerializer.
    // Writing a value that needs >32 signed bytes (e.g., +2^255 needs
    // 33 bytes because the sign bit forces a leading 0x00) would
    // produce wire bytes Scala rejects on read — emit-side parity
    // requires the same cap as the reader. Returning a typed error
    // beats the previous `assert!` which panicked above u16::MAX
    // (and silently accepted 33..65535).
    if bytes.len() > BIGINT_VALUE_MAX_BYTES {
        return Err(WriteError::InvalidData(format!(
            "SBigInt value too long: {} bytes (max {BIGINT_VALUE_MAX_BYTES})",
            bytes.len(),
        )));
    }
    w.put_u16(bytes.len() as u16);
    w.put_bytes(&bytes);
    Ok(())
}

pub(super) fn read_bigint_value(r: &mut VlqReader) -> Result<num_bigint::BigInt, ReadError> {
    let len = r.get_u16()? as usize;
    if len == 0 {
        return Ok(num_bigint::BigInt::from(0));
    }
    // Mirrors `read_unsigned_bigint_value`'s gate at the same const.
    // Scala's `CoreDataSerializer.deserializeBigInt` rejects `len > 32`.
    // The cap fires BEFORE `get_bytes(len)` so a hostile `len=65535`
    // payload can't trigger a 65 KiB allocation before reading any
    // bytes.
    if len > BIGINT_VALUE_MAX_BYTES {
        return Err(ReadError::InvalidData(format!(
            "SBigInt value too long: {len} bytes (max {BIGINT_VALUE_MAX_BYTES})",
        )));
    }
    let bytes = r.get_bytes(len)?;
    Ok(num_bigint::BigInt::from_signed_bytes_be(bytes))
}

/// Per-spec maximum byte length for `SBigInt` and `SUnsignedBigInt`
/// on-wire values. Mirrors Scala's `CoreDataSerializer`
/// `MaxBigIntSizeInBytes = 32` (256 bits unsigned, or signed in range
/// `[-2^255, 2^255)`). Note the asymmetry: the signed encoding of
/// `+2^255` requires 33 bytes (a leading 0x00 to keep the sign bit
/// clear), so this cap rejects positive `2^255` and accepts negative
/// `-2^255` — matching Scala.
const BIGINT_VALUE_MAX_BYTES: usize = 32;

/// `SUnsignedBigInt` wire reader. Mirrors Scala's
/// `CoreDataSerializer.scala:36` which uses
/// `BigIntegers.fromUnsignedByteArray` — bytes are interpreted as a
/// non-negative big-endian magnitude with no sign bit.
///
/// Distinct from [`read_bigint_value`] (signed two's-complement) so
/// values with the top bit set decode as the intended positive
/// integer rather than as a negative number with magnitude
/// `2^(8·len) - value`. Length is range-checked to
/// [`BIGINT_VALUE_MAX_BYTES`] so a malformed wire payload can't
/// expand the unsigned value past Scala's 256-bit bound.
pub(super) fn read_unsigned_bigint_value(
    r: &mut VlqReader,
) -> Result<num_bigint::BigInt, ReadError> {
    let len = r.get_u16()? as usize;
    if len == 0 {
        return Ok(num_bigint::BigInt::from(0));
    }
    if len > BIGINT_VALUE_MAX_BYTES {
        return Err(ReadError::InvalidData(format!(
            "SUnsignedBigInt value too long: {len} bytes (max {BIGINT_VALUE_MAX_BYTES})",
        )));
    }
    let bytes = r.get_bytes(len)?;
    Ok(num_bigint::BigInt::from_bytes_be(
        num_bigint::Sign::Plus,
        bytes,
    ))
}

/// `SUnsignedBigInt` wire writer — round-trip counterpart to
/// [`read_unsigned_bigint_value`]. Emits unsigned magnitude bytes
/// with no leading sign-extension zero byte; Scala's
/// `BigIntegers.asUnsignedByteArray` does the same.
///
/// Refuses negative values up front. A negative `SUnsignedBigInt`
/// is a caller bug (type-system invariant violated) — the alternative
/// would be silently treating it as `value + 2^256`, which would
/// re-introduce the very class of bug the unsigned decoder fixes.
pub(super) fn write_unsigned_bigint_value(
    w: &mut VlqWriter,
    value: &num_bigint::BigInt,
) -> Result<(), WriteError> {
    if value.sign() == num_bigint::Sign::Minus {
        return Err(WriteError::InvalidData(format!(
            "SUnsignedBigInt cannot serialize a negative value: {value}",
        )));
    }
    let (_sign, bytes) = value.to_bytes_be();
    // `to_bytes_be` for zero returns `[0]` (one byte), but the wire
    // format encodes zero as `len=0` with no payload — matches the
    // reader's early-return for `len == 0`.
    let bytes: &[u8] = if value.sign() == num_bigint::Sign::NoSign {
        &[]
    } else {
        &bytes
    };
    if bytes.len() > BIGINT_VALUE_MAX_BYTES {
        return Err(WriteError::InvalidData(format!(
            "SUnsignedBigInt value too long: {} bytes (max {BIGINT_VALUE_MAX_BYTES})",
            bytes.len(),
        )));
    }
    w.put_u16(bytes.len() as u16);
    w.put_bytes(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::{read_value, write_value, SigmaValue};
    use num_bigint::BigInt;

    // ----- helpers -----

    fn roundtrip_value(tpe: &SigmaType, val: &SigmaValue) {
        let mut w = VlqWriter::new();
        write_value(&mut w, tpe, val).unwrap();
        let data = w.result();
        let mut r = VlqReader::new(&data);
        let decoded = read_value(&mut r, tpe).unwrap();
        assert!(r.is_empty(), "leftover bytes for {tpe:?}");
        assert_eq!(&decoded, val);
    }

    #[test]
    fn roundtrip_bigint() {
        roundtrip_value(&SigmaType::SBigInt, &SigmaValue::BigInt(BigInt::from(0)));
        roundtrip_value(
            &SigmaType::SBigInt,
            &SigmaValue::BigInt(BigInt::from(i64::MAX)),
        );
        roundtrip_value(
            &SigmaType::SBigInt,
            &SigmaValue::BigInt(BigInt::from(i64::MIN)),
        );
        // Large value beyond i64 range
        let big = BigInt::parse_bytes(b"123456789012345678901234567890123456789", 10).unwrap();
        roundtrip_value(&SigmaType::SBigInt, &SigmaValue::BigInt(big));
    }

    #[test]
    fn roundtrip_unsigned_bigint() {
        // Zero — wire shape `len=0`, no payload bytes.
        roundtrip_value(
            &SigmaType::SUnsignedBigInt,
            &SigmaValue::BigInt(BigInt::from(0)),
        );
        // Small magnitude (fits in one wire byte).
        roundtrip_value(
            &SigmaType::SUnsignedBigInt,
            &SigmaValue::BigInt(BigInt::from(1)),
        );
        // High-bit-set magnitude — the case the old signed reader
        // misinterpreted as negative.
        let n_hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        let n = BigInt::parse_bytes(n_hex.as_bytes(), 16).unwrap();
        roundtrip_value(&SigmaType::SUnsignedBigInt, &SigmaValue::BigInt(n));
        // 2^256 - 1 — the maximum permitted unsigned magnitude.
        let max_u256 = (BigInt::from(1) << 256) - 1;
        roundtrip_value(&SigmaType::SUnsignedBigInt, &SigmaValue::BigInt(max_u256));
    }

    #[test]
    fn unsigned_bigint_rejects_negative_on_write() {
        let mut w = VlqWriter::new();
        let err = write_value(
            &mut w,
            &SigmaType::SUnsignedBigInt,
            &SigmaValue::BigInt(BigInt::from(-1)),
        )
        .expect_err("writing a negative SUnsignedBigInt must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("negative"),
            "error should explain the negative-value violation: {msg}",
        );
    }

    #[test]
    fn unsigned_bigint_rejects_oversize_on_read() {
        // Construct a wire payload with len=33 (one over the 32-byte
        // unsigned bound). The reader must refuse it loudly.
        let mut w = VlqWriter::new();
        w.put_u16(33);
        w.put_bytes(&[0xffu8; 33]);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = read_value(&mut r, &SigmaType::SUnsignedBigInt)
            .expect_err("33-byte unsigned magnitude must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("too long"),
            "error should explain the length violation: {msg}",
        );
    }

    // ----- SBigInt 32-byte length cap -----
    //
    // Oracle: Scala's `CoreDataSerializer.deserializeBigInt` rejects
    // `len > MaxBigIntSizeInBytes = 32`. Mirrors the gate already
    // present on the unsigned twin (`read_unsigned_bigint_value`).

    #[test]
    fn bigint_accepts_32_byte_signed_value_with_top_bit_set_as_negative() {
        // 32 bytes with top bit set encodes a negative signed value
        // near -2^255. This is the largest legal signed payload AND
        // tests the boundary-byte sign handling. Pin via round-trip.
        let mut bytes = vec![0u8; 32];
        bytes[0] = 0x80; // sign bit set → negative in two's complement
        let n = BigInt::from_signed_bytes_be(&bytes);
        assert!(n < BigInt::from(0), "0x80 0x00... must decode as negative");
        roundtrip_value(&SigmaType::SBigInt, &SigmaValue::BigInt(n));
    }

    #[test]
    fn bigint_rejects_oversize_on_read() {
        // Construct a wire payload with len=33 (one over the 32-byte
        // signed bound). Mirrors `unsigned_bigint_rejects_oversize_on_read`
        // for the signed twin.
        let mut w = VlqWriter::new();
        w.put_u16(33);
        w.put_bytes(&[0xffu8; 33]);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = read_value(&mut r, &SigmaType::SBigInt)
            .expect_err("33-byte signed BigInt must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("SBigInt") && msg.contains("too long"),
            "error should cite SBigInt + length: {msg}",
        );
    }

    #[test]
    fn bigint_rejects_huge_size_on_read_before_alloc() {
        // Hostile payload: len=65535 (the old wire-cap). The new gate
        // must fire BEFORE `get_bytes(65535)` so a single message can't
        // trigger 65 KiB allocation. The test supplies only 4 bytes —
        // if the cap is correctly placed before the alloc, we see
        // `InvalidData("SBigInt ... too long")`. If misplaced, we'd
        // see `UnexpectedEnd` from `get_bytes` running past EOF.
        let mut w = VlqWriter::new();
        w.put_u16(65535);
        w.put_bytes(&[0u8; 4]);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = read_value(&mut r, &SigmaType::SBigInt).expect_err("len=65535 must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("too long"),
            "cap must fire before get_bytes; got {msg}",
        );
    }

    #[test]
    fn bigint_rejects_33_byte_value_on_write() {
        // Off-by-one trap: `+2^255` requires 33 bytes in signed
        // encoding (leading 0x00 to keep the sign bit clear). The
        // writer must reject with `InvalidData` at write time so a
        // programmatic caller can't produce Scala-invalid bytes.
        let two_to_255: BigInt = BigInt::from(1) << 255;
        // Confirm the test premise: signed encoding really takes 33 bytes.
        assert_eq!(
            two_to_255.to_signed_bytes_be().len(),
            33,
            "test premise: +2^255 signed encoding is 33 bytes"
        );
        let mut w = VlqWriter::new();
        let err = write_value(&mut w, &SigmaType::SBigInt, &SigmaValue::BigInt(two_to_255))
            .expect_err("writing +2^255 (33 signed bytes) must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("SBigInt") && msg.contains("too long"),
            "error should cite SBigInt + length: {msg}",
        );
    }

    #[test]
    fn bigint_accepts_32_byte_value_on_write() {
        // Boundary positive case: largest positive that fits in 32
        // signed bytes is `2^255 - 1` (top byte 0x7F, sign bit clear).
        // Must round-trip; pairs with the `+2^255` reject test above
        // to fully specify the writer boundary.
        let max_signed_32: BigInt = (BigInt::from(1) << 255) - 1;
        assert_eq!(
            max_signed_32.to_signed_bytes_be().len(),
            32,
            "test premise: 2^255 - 1 signed encoding is 32 bytes"
        );
        roundtrip_value(&SigmaType::SBigInt, &SigmaValue::BigInt(max_signed_32));
    }

    #[test]
    fn bigint_golden_wire_bytes_for_minus_two_pow_255() {
        // Golden-byte parity test. The Scala `CoreDataSerializer`
        // SBigInt wire format is exactly
        // `putUShort(len) | bytes`, where `putUShort` is Scorex's
        // VLQ-encoded unsigned short and `bytes` is Scala's
        // `BigInteger.toByteArray` (signed two's-complement big-endian).
        //
        // For `-2^255`, the signed payload is `0x80 0x00 ... 0x00`
        // (32 bytes). The VLQ encoding of length 32 is the single
        // byte `0x20` (any value < 128 VLQ-encodes to a single byte
        // with no continuation bit). The full wire bytes are:
        //   0x20  0x80  0x00 (x31)   — 33 bytes total
        //
        // These bytes are derived from the Scala DataSerializer
        // contract, not from our writer's output. Asserting that our
        // writer produces them is an external oracle proof of byte
        // parity at the cap-boundary.
        let pos: BigInt = BigInt::from(1) << 255;
        let n: BigInt = -pos;
        let mut w = VlqWriter::new();
        write_value(&mut w, &SigmaType::SBigInt, &SigmaValue::BigInt(n.clone()))
            .expect("-2^255 fits in 32 signed bytes; writer must accept");
        let bytes = w.result();
        let mut expected = vec![0x20u8, 0x80];
        expected.extend(std::iter::repeat_n(0u8, 31));
        assert_eq!(
            bytes, expected,
            "wire bytes for -2^255 must match the Scala DataSerializer \
             golden value derived from CoreDataSerializer.scala (VLQ \
             length 0x20 || signed two's-complement payload [0x80, 0; 31])"
        );
        // Round-trip back from the golden bytes to pin the reader.
        let mut r = VlqReader::new(&bytes);
        let decoded =
            read_value(&mut r, &SigmaType::SBigInt).expect("golden wire bytes must decode");
        assert_eq!(decoded, SigmaValue::BigInt(n));
    }
}

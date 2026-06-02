/// Encode an unsigned 64-bit integer as VLQ bytes (little-endian, 7
/// bits per byte). MSB of each byte is the continuation bit: 1 =
/// more bytes, 0 = last byte. Allocates a fresh `Vec`; for hot
/// paths that already have a buffer, prefer [`encode_vlq_into`].
pub fn encode_vlq(value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    encode_vlq_into(value, &mut buf);
    buf
}

/// Append the VLQ encoding of `value` to `buf` in place, no
/// intermediate allocation. Hot-path variant used by
/// `VlqWriter::put_u32` / `put_u64` to avoid the per-call
/// `Vec::extend(encode_vlq(v))` alloc-copy-drop cycle that
/// dominated serializer cost.
pub fn encode_vlq_into(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a VLQ-encoded unsigned 64-bit integer from a byte slice.
/// Returns (decoded_value, bytes_consumed).
pub fn decode_vlq(bytes: &[u8]) -> Result<(u64, usize), VlqError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        if shift >= 63 && (byte & 0x7F) > 1 {
            return Err(VlqError::Overflow);
        }
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
        if shift > 63 {
            return Err(VlqError::Overflow);
        }
    }
    Err(VlqError::UnexpectedEnd)
}

/// Errors produced by [`decode_vlq`].
#[derive(Debug, thiserror::Error)]
pub enum VlqError {
    /// Continuation bit was set on the final byte of the slice — the encoded
    /// value was truncated.
    #[error("unexpected end of input")]
    UnexpectedEnd,
    /// The decoded value would not fit in a `u64`. Fires when an 11th
    /// byte is encountered (>70 payload bits) or when the 10th byte
    /// carries a payload greater than `1` (the only payload values
    /// that fit in the remaining high bit). Valid 10-byte encodings
    /// — `u64::MAX` itself encodes to 10 bytes with a final-byte
    /// payload of exactly `1` — are accepted; this error fires only
    /// past that boundary.
    #[error("VLQ value exceeds u64")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ----- happy path -----

    #[test]
    fn encode_zero_is_single_zero_byte() {
        assert_eq!(encode_vlq(0), vec![0x00]);
    }

    #[test]
    fn encode_small_values_fit_one_byte() {
        assert_eq!(encode_vlq(1), vec![0x01]);
        assert_eq!(encode_vlq(127), vec![0x7F]);
    }

    #[test]
    fn encode_boundary_at_128_uses_two_bytes() {
        assert_eq!(encode_vlq(128), vec![0x80, 0x01]);
        assert_eq!(encode_vlq(300), vec![0xAC, 0x02]);
    }

    // ----- oracle parity (unsigned LEB128 / Protocol Buffers varint) -----

    /// Scorex's VLQ encoding is byte-identical to **unsigned LEB128** (DWARF,
    /// WebAssembly) and to the unsigned **Protocol Buffers varint** wire
    /// format — same continuation-bit convention, same 7-bit-payload
    /// little-endian order. Asserting against vectors from those specs is
    /// an implementation-independent oracle, not a self-oracle.
    ///
    /// Each row is labeled with its source: either the value pair appears
    /// **literally** in the cited spec text, or it is **derived per** the
    /// published encoding rule (same rule, that specific value not quoted
    /// in the source). The distinction matters so that future readers
    /// don't read "published" off any row that is in fact only formula-
    /// equivalent to a published example.
    ///
    /// Sources:
    /// - Protocol Buffers Varints: <https://protobuf.dev/programming-guides/encoding/#varints>
    /// - Unsigned LEB128 (Wikipedia, DWARF v5 §7.6):
    ///   <https://en.wikipedia.org/wiki/LEB128#Unsigned_LEB128>
    #[test]
    fn encode_vlq_matches_published_varint_byte_pattern() {
        // (input, expected_bytes, provenance_label).
        let rows: &[(u64, &[u8], &str)] = &[
            // Protobuf spec literal example: `1` → 0x01 (a single byte
            // containing only the value `1`, with the MSB clear).
            (1, &[0x01], "literal: Protobuf Varints — example `1`"),
            // Protobuf spec canonical worked example for multi-byte
            // varints: `150` decomposes as 10010110 00000001 → two
            // bytes 0x96 0x01 little-endian-group-of-7-bits.
            (
                150,
                &[0x96, 0x01],
                "literal: Protobuf Varints — example `150`",
            ),
            // Unsigned LEB128 canonical worked example (DWARF v5 §7.6 /
            // Wikipedia LEB128 unsigned section): `624485` → three
            // bytes 0xE5 0x8E 0x26.
            (
                624_485,
                &[0xE5, 0x8E, 0x26],
                "literal: LEB128 — Wikipedia/DWARF v5 §7.6 canonical example",
            ),
            // Derived per the published unsigned LEB128 / Protobuf
            // varint encoding rule (1-byte / 2-byte boundary).
            (0, &[0x00], "derived per LEB128 / Protobuf varint rule"),
            (127, &[0x7F], "derived per LEB128 / Protobuf varint rule"),
            (
                128,
                &[0x80, 0x01],
                "derived per LEB128 / Protobuf varint rule",
            ),
            // Derived per rule (2-byte / 3-byte boundary).
            (
                16_383,
                &[0xFF, 0x7F],
                "derived per LEB128 / Protobuf varint rule",
            ),
            (
                16_384,
                &[0x80, 0x80, 0x01],
                "derived per LEB128 / Protobuf varint rule",
            ),
            // Derived per rule (5-byte u32::MAX).
            (
                u32::MAX as u64,
                &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F],
                "derived per LEB128 / Protobuf varint rule",
            ),
            // Derived per rule (10-byte u64::MAX — the longest legal
            // varint encoding).
            (
                u64::MAX,
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
                "derived per LEB128 / Protobuf varint rule",
            ),
        ];
        for (v, expected, prov) in rows {
            let encoded = encode_vlq(*v);
            assert_eq!(
                encoded.as_slice(),
                *expected,
                "encode_vlq({v}) mismatch against {prov}: got {:02x?}, expected {:02x?}",
                encoded,
                expected,
            );
        }
    }

    // ----- properties -----

    proptest! {
        /// Algebraic property: every u64 round-trips through encode → decode,
        /// and `consumed` equals the encoded length. Catches regressions in
        /// the codec that named-boundary tests miss for arbitrary values.
        #[test]
        fn proptest_vlq_u64_roundtrip(v in any::<u64>()) {
            let encoded = encode_vlq(v);
            let (decoded, consumed) = decode_vlq(&encoded).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert_eq!(consumed, encoded.len());
        }

        /// Wire-format termination contract: the final byte has its MSB
        /// clear (no continuation), every non-final byte has its MSB set
        /// (continuation), and encoded length is in `1..=10` for any
        /// `u64`. Currently this is only inferred indirectly from the
        /// round-trip property; pinning it directly catches a regression
        /// where the encoder emits a missing or extra terminator.
        #[test]
        fn proptest_vlq_encoded_length_and_terminator_bit(v in any::<u64>()) {
            let encoded = encode_vlq(v);
            prop_assert!(!encoded.is_empty() && encoded.len() <= 10,
                "encoded length out of range [1, 10] for v={v}: got {}", encoded.len());
            // Final byte: MSB = 0.
            prop_assert_eq!(encoded.last().unwrap() & 0x80, 0,
                "final byte has continuation bit set for v={}: {:02x?}", v, encoded);
            // Non-final bytes: MSB = 1.
            for (i, byte) in encoded[..encoded.len() - 1].iter().enumerate() {
                prop_assert_eq!(byte & 0x80, 0x80,
                    "non-final byte {} missing continuation bit for v={}: {:02x?}", i, v, encoded);
            }
        }

        /// Parity property: `encode_vlq_into(v, &mut buf)` appends
        /// exactly the bytes that `encode_vlq(v)` produces. This is
        /// the contract that lets `VlqWriter::put_*` switch from the
        /// allocating form to the in-place form without changing
        /// any wire bytes.
        #[test]
        fn proptest_encode_vlq_into_matches_encode_vlq(v in any::<u64>()) {
            let allocated = encode_vlq(v);
            let mut buf = Vec::new();
            encode_vlq_into(v, &mut buf);
            prop_assert_eq!(allocated, buf);
        }

        /// Parity property: `encode_vlq_into` only appends — it
        /// does not touch existing prefix bytes. Critical because
        /// `VlqWriter` calls it repeatedly into the same buffer.
        #[test]
        fn proptest_encode_vlq_into_preserves_prefix(
            v in any::<u64>(),
            prefix in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let mut buf = prefix.clone();
            encode_vlq_into(v, &mut buf);
            let appended = encode_vlq(v);
            prop_assert_eq!(&buf[..prefix.len()], &prefix[..]);
            prop_assert_eq!(&buf[prefix.len()..], &appended[..]);
        }
    }

    // ----- error paths -----

    #[test]
    fn decode_empty_buffer_errors() {
        assert!(matches!(decode_vlq(&[]), Err(VlqError::UnexpectedEnd)));
    }

    #[test]
    fn decode_truncated_continuation_errors() {
        // Continuation bit set with no follow-up byte — payload was cut short.
        assert!(matches!(decode_vlq(&[0x80]), Err(VlqError::UnexpectedEnd)));
    }

    #[test]
    fn decode_overflow_10_byte_continuation_errors() {
        let bad = vec![0x80u8; 10];
        assert!(matches!(decode_vlq(&bad), Err(VlqError::Overflow)));
    }

    // ----- pinned current behavior -----

    #[test]
    fn decode_accepts_non_canonical_zero_encoding() {
        // [0x80, 0x00] is a non-canonical encoding of 0 (the canonical form
        // is just [0x00]). Scala's VLQ decoder accepts non-canonical
        // encodings; we mirror that behavior. Pinning so any change to
        // strict-canonical decoding fails this test loudly.
        let (decoded, consumed) = decode_vlq(&[0x80, 0x00]).unwrap();
        assert_eq!(decoded, 0);
        assert_eq!(consumed, 2);
    }
}

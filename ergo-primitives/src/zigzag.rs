use crate::vlq::{self, VlqError};

pub fn zigzag_encode_i32(n: i32) -> u32 {
    ((n << 1) ^ (n >> 31)) as u32
}

pub fn zigzag_decode_i32(n: u32) -> i32 {
    ((n >> 1) as i32) ^ (-((n & 1) as i32))
}

pub fn zigzag_encode_i64(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

pub fn zigzag_decode_i64(n: u64) -> i64 {
    ((n >> 1) as i64) ^ (-((n & 1) as i64))
}

/// Encode a signed 32-bit integer as ZigZag + VLQ bytes.
///
/// Mirrors Scala's `putInt(x: Int) = putLong(x)` — Scala-on-JVM
/// sign-extends Int→Long before VLQ-encoding, so the wire form
/// of any Int with the post-zigzag top bit set is a 10-byte VLQ
/// (sign-extension fills the top 32 bits with 1s). Casting
/// `u32 as u64` in Rust ZERO-extends and produces a shorter VLQ;
/// that breaks byte-fidelity round-trips with Scala-produced
/// wire bytes (live mainnet block 555672 / `tx[2]` / `output[0]` R4
/// register `04a48bb099f9ffffffff01` is a witness — the
/// post-truncation zigzag-decoded i32 has bit 31 set, so the
/// canonical wire form needs sign-extension to round-trip).
///
/// Allocating wrapper used only by this module's round-trip tests;
/// production code (`VlqWriter::put_i32`) uses the in-place
/// `encode_signed_i32_into` helper directly to avoid the per-call alloc.
#[cfg(test)]
fn encode_signed_i32(value: i32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    encode_signed_i32_into(value, &mut buf);
    buf
}

/// In-place variant of [`encode_signed_i32`]. Crate-private because
/// the only caller is `VlqWriter::put_i32`; downstream callers go
/// through the allocating wrapper.
pub(crate) fn encode_signed_i32_into(value: i32, buf: &mut Vec<u8>) {
    let zz = zigzag_encode_i32(value);
    // Sign-extend through i32 → i64 → u64 (matches Scala
    // `(Long) int`). For zz with bit 31 clear this is identical
    // to `as u64`; for zz with bit 31 set, top 32 bits become 1.
    vlq::encode_vlq_into((zz as i32) as i64 as u64, buf);
}

/// Decode a ZigZag + VLQ encoded signed 32-bit integer.
pub fn decode_signed_i32(bytes: &[u8]) -> Result<(i32, usize), VlqError> {
    let (unsigned, consumed) = vlq::decode_vlq(bytes)?;
    Ok((zigzag_decode_i32(unsigned as u32), consumed))
}

/// Encode a signed 64-bit integer as ZigZag + VLQ bytes. Allocating
/// wrapper used only by this module's round-trip tests; production code
/// (`VlqWriter::put_i64`) uses the in-place `encode_signed_i64_into`
/// helper directly to avoid the per-call alloc.
#[cfg(test)]
fn encode_signed_i64(value: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    encode_signed_i64_into(value, &mut buf);
    buf
}

/// In-place variant of [`encode_signed_i64`]. Crate-private because
/// the only caller is `VlqWriter::put_i64`; downstream callers go
/// through the allocating wrapper.
pub(crate) fn encode_signed_i64_into(value: i64, buf: &mut Vec<u8>) {
    vlq::encode_vlq_into(zigzag_encode_i64(value), buf);
}

/// Decode a ZigZag + VLQ encoded signed 64-bit integer.
pub fn decode_signed_i64(bytes: &[u8]) -> Result<(i64, usize), VlqError> {
    let (unsigned, consumed) = vlq::decode_vlq(bytes)?;
    Ok((zigzag_decode_i64(unsigned), consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ----- happy path -----

    /// Each row in this test appears **literally** in the Protocol Buffers
    /// signed-int zigzag table (sint32):
    /// <https://protobuf.dev/programming-guides/encoding/#signed-ints>.
    /// The published table reproduces these exact six rows:
    ///
    /// | Signed Original | Encoded As |
    /// |---|---|
    /// | 0 | 0 |
    /// | -1 | 1 |
    /// | 1 | 2 |
    /// | -2 | 3 |
    /// | 2147483647 | 4294967294 |
    /// | -2147483648 | 4294967295 |
    ///
    /// The `(2, 4)` row below is **derived per** the same zigzag rule
    /// (`(n << 1) ^ (n >> 31)`) — that specific row is not in the
    /// published table but follows the same bijection.
    #[test]
    fn zigzag_encode_i32_known_pairs() {
        assert_eq!(zigzag_encode_i32(0), 0);
        assert_eq!(zigzag_encode_i32(-1), 1);
        assert_eq!(zigzag_encode_i32(1), 2);
        assert_eq!(zigzag_encode_i32(-2), 3);
        // Derived per the published zigzag rule — not in the Protobuf table.
        assert_eq!(zigzag_encode_i32(2), 4);
        assert_eq!(zigzag_encode_i32(i32::MAX), 0xFFFFFFFE);
        assert_eq!(zigzag_encode_i32(i32::MIN), 0xFFFFFFFF);
    }

    #[test]
    fn zigzag_negatives_map_to_odd_unsigned_positives_to_even() {
        // The defining property of zigzag: negatives → odd, non-negatives → even.
        // Pin so any change to the bit-twiddling that breaks this property is loud.
        for v in [-128i32, -2, -1, 0, 1, 2, 127] {
            let z = zigzag_encode_i32(v);
            if v < 0 {
                assert_eq!(z & 1, 1, "negative {v} must encode to odd, got {z}");
            } else {
                assert_eq!(z & 1, 0, "non-negative {v} must encode to even, got {z}");
            }
        }
    }

    // ----- oracle parity (Protocol Buffers zigzag — i64 derived per formula) -----

    /// Protocol Buffers' published zigzag table (see the `sint32` rows on
    /// `zigzag_encode_i32_known_pairs`) only quotes i32 values. The
    /// `sint64` zigzag bijection is defined by the same documented
    /// formula `(n << 1) ^ (n >> 63)` (see
    /// <https://protobuf.dev/programming-guides/encoding/#signed-ints>),
    /// but the spec text does not enumerate i64 rows. All rows below
    /// are therefore **derived per the published formula**, not literal
    /// quoted vectors.
    #[test]
    fn zigzag_encode_i64_derived_per_protobuf_formula() {
        // Mirror of the i32 published shape, extended to i64:
        assert_eq!(zigzag_encode_i64(0), 0);
        assert_eq!(zigzag_encode_i64(-1), 1);
        assert_eq!(zigzag_encode_i64(1), 2);
        assert_eq!(zigzag_encode_i64(-2), 3);
        assert_eq!(zigzag_encode_i64(2), 4);
        // 64-bit extremes — beyond i32 range:
        assert_eq!(zigzag_encode_i64(i64::MAX), u64::MAX - 1);
        assert_eq!(zigzag_encode_i64(i64::MIN), u64::MAX);
        // Boundary just past i32::MAX (relevant because the i32→i64
        // bijection differs from the i32-only bijection beyond this point):
        assert_eq!(zigzag_encode_i64(i32::MAX as i64 + 1), 4_294_967_296);
        assert_eq!(zigzag_encode_i64(i32::MIN as i64 - 1), 4_294_967_297);
    }

    /// Explicit `i32::MIN`, `i32::MAX`, `-1`, `0` pin. Proptest's default
    /// 256-iteration sample over the 4-billion-input i32 space cannot
    /// statistically guarantee these specific values are tested; this
    /// table guarantees they are.
    ///
    /// For `i32::MIN` and `i32::MAX`, the test additionally asserts the
    /// 10-byte VLQ length resulting from JVM `Int→Long` sign-extension
    /// (the same property the Scala mainnet oracle pins for the
    /// general post-zigzag-bit-31-set case).
    #[test]
    fn signed_vlq_i32_extremes_roundtrip() {
        for &v in &[0i32, -1, i32::MAX, i32::MIN] {
            let encoded = encode_signed_i32(v);
            let (decoded, consumed) = decode_signed_i32(&encoded).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {v}");
            assert_eq!(consumed, encoded.len());
            // Encoded-length expectations for the named extremes:
            let expected_len = match v {
                0 | -1 => 1,
                i32::MAX | i32::MIN => 10, // sign-extension → 10-byte VLQ
                _ => unreachable!(),
            };
            assert_eq!(
                encoded.len(),
                expected_len,
                "encode_signed_i32({v}) length mismatch: got {} bytes ({:02x?}), expected {}",
                encoded.len(),
                encoded,
                expected_len,
            );
        }
    }

    // ----- properties -----

    proptest! {
        /// Algebraic property: every i64 round-trips through encode → decode.
        #[test]
        fn proptest_zigzag_i64_roundtrip(v in any::<i64>()) {
            let encoded = encode_signed_i64(v);
            let (decoded, _) = decode_signed_i64(&encoded).unwrap();
            prop_assert_eq!(decoded, v);
        }

        /// Algebraic property: every i32 round-trips through encode →
        /// decode. The i32 path goes through `encode_signed_i32_into`'s
        /// JVM sign-extension chain (`(zz as i32) as i64 as u64`), which
        /// is distinct from the i64 path — so the i64 proptest does not
        /// subsume this one.
        #[test]
        fn proptest_signed_vlq_i32_roundtrip(v in any::<i32>()) {
            let encoded = encode_signed_i32(v);
            let (decoded, consumed) = decode_signed_i32(&encoded).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert_eq!(consumed, encoded.len());
        }
    }

    // ----- oracle parity (mainnet) -----

    /// Pin byte-level fidelity with Scala's wire form for SInt
    /// values whose post-zigzag bit 31 is set. Witness: live
    /// mainnet block 555672 / tx[2] / output[0] register R4
    /// (`04a48bb099f9ffffffff01` — type tag `04` SInt + 10-byte
    /// VLQ payload). Without sign-extension, `encode_signed_i32`
    /// would produce a 5-byte VLQ for negative-bit values; Scala
    /// produces 10 bytes because Int→Long sign-extends on the JVM.
    /// This test fails loudly if `_into` ever switches back to
    /// zero-extension.
    #[test]
    fn encode_signed_i32_matches_scala_sign_extension() {
        // Block 555672 R4 payload (after the type tag `04`).
        let scala_wire: &[u8] = &[0xa4, 0x8b, 0xb0, 0x99, 0xf9, 0xff, 0xff, 0xff, 0xff, 0x01];
        let (decoded, consumed) = decode_signed_i32(scala_wire).unwrap();
        assert_eq!(consumed, 10);
        let re_encoded = encode_signed_i32(decoded);
        assert_eq!(
            re_encoded.as_slice(),
            scala_wire,
            "encode_signed_i32 must produce byte-identical wire form to Scala for sign-extended values: \
             decoded={decoded} (i32 = {decoded:#x})"
        );

        // i32::MIN edge: Scala writes 10-byte VLQ
        // (zigzag(MIN)=0xFFFFFFFF as Int → Long sign-extends to
        // 0xFFFFFFFFFFFFFFFF → max VLQ length). Zero-extension would
        // wrongly produce 5 bytes.
        let min_encoded = encode_signed_i32(i32::MIN);
        assert_eq!(
            min_encoded.len(),
            10,
            "i32::MIN must encode to 10-byte VLQ (got {} bytes: {:02x?})",
            min_encoded.len(),
            min_encoded
        );

        // i32::MAX: zigzag(MAX) = 0xFFFFFFFE (top bit set) →
        // also 10 bytes after sign-extension.
        let max_encoded = encode_signed_i32(i32::MAX);
        assert_eq!(
            max_encoded.len(),
            10,
            "i32::MAX must encode to 10-byte VLQ (got {} bytes: {:02x?})",
            max_encoded.len(),
            max_encoded
        );
    }
}

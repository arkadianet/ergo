use crate::vlq::{self, VlqError};
use crate::zigzag;

/// Deserialization reader consuming bytes using Scorex VLQ encoding.
pub struct VlqReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Optional absolute byte position the reader must not begin a read past.
    /// `None` (the default) means unbounded. Mirrors Scala's
    /// `Reader.positionLimit` + `CheckPositionLimit` (validation rule 1014):
    /// each consuming read checks `position <= positionLimit` BEFORE advancing,
    /// so a single read may overrun the limit but the NEXT read past it fails.
    /// Set only for scoped sub-parses (e.g. an SBox candidate body bounded to
    /// `start + MaxBoxSize`); leaves all other parsing unaffected.
    position_limit: Option<usize>,
    /// Sideband: every group-element encoding (raw 33 bytes) seen during the
    /// parse. Crypto-free — just bytes. The Scala reference curve-checks each
    /// group element while deserializing; this crate is crypto-free, so the
    /// higher layer (`ergo-validation` via `ergo-sigma`) drains and validates
    /// these after parsing. Collected here rather than by walking the parsed
    /// AST so that soft-fork-wrapped trees and opaque SBox bodies — which lose
    /// the points in the AST — are still covered. See
    /// [`record_group_element`](Self::record_group_element).
    group_elements: Vec<[u8; 33]>,
}

/// Errors produced while decoding a Scorex-style byte stream.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The reader needed more bytes than were present.
    #[error("unexpected end of input at position {pos}, needed {needed} bytes")]
    UnexpectedEnd { pos: usize, needed: usize },
    /// The underlying VLQ decoder rejected the bytes (overflow or truncation).
    #[error("VLQ decoding error: {0}")]
    Vlq(#[from] VlqError),
    /// VLQ decoded successfully but the value does not fit in the
    /// caller-requested integer width. Mirrors Scala's
    /// `getUIntExact` / `getUShortExact` (`toIntExact` throws
    /// `ArithmeticException`) and sigma-rust's
    /// `u32::try_from(u64)` / `u16::try_from(u64)`.
    #[error("VLQ value {got} too large for {type_name}")]
    ValueTooLarge {
        /// Name of the requested integer type (`"u32"` / `"u16"`).
        type_name: &'static str,
        /// The decoded `u64` that failed the narrowing check.
        got: u64,
    },
    /// Bytes were structurally readable but semantically invalid for the
    /// caller's wire format — supply a short context string.
    #[error("invalid data: {0}")]
    InvalidData(String),
    /// Nested value/expression deserialization exceeded the maximum tree depth
    /// (Scala `SigmaConstants.MaxTreeDepth`). Scala raises this as a
    /// `SerializerException` (`DeserializeCallDepthExceeded`), which is NOT in
    /// the set its `ErgoTreeSerializer.deserializeErgoTree` catches, so it is
    /// never wrapped into an `UnparsedErgoTree` (soft fork) even for
    /// size-delimited trees — it must propagate as a HARD rejection.
    #[error("deserialization depth exceeds maximum ({max})")]
    DepthLimitExceeded {
        /// The depth bound that was exceeded.
        max: usize,
    },
    /// A hard, NON-soft-forkable deserialization rejection that must propagate
    /// even out of a size-delimited tree — the Rust analog of a Scala
    /// `SerializerException` (as opposed to a soft-forkable `ValidationException`,
    /// which `ErgoTreeSerializer.deserializeErgoTree` catches and turns into an
    /// `UnparsedErgoTree`). Used for rejections that occur while deserializing a
    /// NESTED box script (an `SBox` constant's inner ErgoTree): a sizeless
    /// pre-v3 tree carrying a v6/EIP-50 method, or a `version != 0` tree with no
    /// size bit (`CheckHeaderSizeBit`, rule 1012). Scala re-raises these as
    /// `SerializerException`, which the enclosing tree's deserialize does NOT
    /// catch, so the whole (outer) tree is rejected rather than wrapped.
    /// [`read_ergo_tree_tracking_wrap`](crate) must re-raise it like
    /// [`Self::DepthLimitExceeded`], never soft-fork-wrap it.
    #[error("hard deserialization rejection: {0}")]
    HardReject(String),
}

impl<'a> VlqReader<'a> {
    /// Wrap a byte slice for sequential decoding. The reader borrows `data`
    /// for its full lifetime.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            position_limit: None,
            group_elements: Vec::new(),
        }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    /// Record a group-element encoding seen during the parse (the raw 33 bytes,
    /// exactly as on the wire). Called by the deserializers at every point the
    /// Scala reference would curve-check a group element.
    pub fn record_group_element(&mut self, ge: [u8; 33]) {
        self.group_elements.push(ge);
    }

    /// All group-element encodings seen so far.
    pub fn group_elements(&self) -> &[[u8; 33]] {
        &self.group_elements
    }

    /// Take the recorded group elements, leaving the sideband empty.
    pub fn take_group_elements(&mut self) -> Vec<[u8; 33]> {
        std::mem::take(&mut self.group_elements)
    }

    /// Current position limit (`None` = unbounded). Save before setting a scoped
    /// limit so it can be restored afterwards (Scala `previousPositionLimit`).
    pub fn position_limit(&self) -> Option<usize> {
        self.position_limit
    }

    /// Set (or clear with `None`) the absolute position limit. Each consuming
    /// read then errors if it would BEGIN past this position.
    pub fn set_position_limit(&mut self, limit: Option<usize>) {
        self.position_limit = limit;
    }

    /// Scala `CheckPositionLimit`: error if the cursor is already past the
    /// limit before a read begins (strict `>`; a read starting exactly at the
    /// limit is allowed and may overrun it).
    #[inline]
    fn check_position_limit(&self) -> Result<(), ReadError> {
        if let Some(limit) = self.position_limit {
            if self.pos > limit {
                return Err(ReadError::InvalidData(format!(
                    "position {} exceeds limit {limit} (CheckPositionLimit, rule 1014)",
                    self.pos
                )));
            }
        }
        Ok(())
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Set the reader position. Panics if pos > data.len().
    pub fn set_position(&mut self, pos: usize) {
        assert!(pos <= self.data.len(), "position out of bounds");
        self.pos = pos;
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn peek_u8(&self) -> Result<u8, ReadError> {
        if self.pos >= self.data.len() {
            return Err(ReadError::UnexpectedEnd {
                pos: self.pos,
                needed: 1,
            });
        }
        Ok(self.data[self.pos])
    }

    pub fn get_u8(&mut self) -> Result<u8, ReadError> {
        self.check_position_limit()?;
        if self.pos >= self.data.len() {
            return Err(ReadError::UnexpectedEnd {
                pos: self.pos,
                needed: 1,
            });
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Consume `n` raw bytes and return them as a borrowed slice.
    pub fn get_bytes(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        self.check_position_limit()?;
        if self.pos + n > self.data.len() {
            return Err(ReadError::UnexpectedEnd {
                pos: self.pos,
                needed: n,
            });
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Consume `N` raw bytes and return them as a fixed-size array.
    ///
    /// Typed wrapper around [`Self::get_bytes`] for the very common
    /// "read a digest / pubkey / nonce of compile-time-known length"
    /// pattern. Failure semantics are identical: returns
    /// [`ReadError::UnexpectedEnd`] without advancing the cursor when
    /// fewer than `N` bytes remain, so upstream framing recovery is
    /// unchanged.
    pub fn get_array<const N: usize>(&mut self) -> Result<[u8; N], ReadError> {
        // Length is fixed by `get_bytes(N)?`, so the conversion cannot fail.
        Ok(self
            .get_bytes(N)?
            .try_into()
            .expect("get_bytes(N) returned slice of length N"))
    }

    /// Decode a VLQ-encoded `u32` using Scala `getUIntExact`
    /// semantics: VLQ-decode as `u64`, then narrow to `Int` via
    /// `toIntExact` (rejects any value above `i32::MAX`). The
    /// `_exact` suffix mirrors Scala's name so the i32-narrowing
    /// is visible at every callsite.
    ///
    /// **Bound:** `[0, i32::MAX]` (= `[0, 0x7FFF_FFFF]`). Stricter
    /// than `u32::try_from(u64)` (which accepts up to `u32::MAX`);
    /// matches Scala because that is the bound the reference node
    /// actually enforces at this codec position.
    ///
    /// If a caller genuinely needs values up to `u64::MAX`
    /// (mirroring Scala's `getUInt -> Long`), call [`Self::get_u64`]
    /// directly and keep the value at the wider type.
    pub fn get_u32_exact(&mut self) -> Result<u32, ReadError> {
        self.check_position_limit()?;
        let (val, consumed) = vlq::decode_vlq(&self.data[self.pos..])?;
        if val > i32::MAX as u64 {
            return Err(ReadError::ValueTooLarge {
                type_name: "u32 (Scala getUIntExact bound, i32::MAX)",
                got: val,
            });
        }
        self.pos += consumed;
        Ok(val as u32)
    }

    /// Decode a VLQ-encoded unsigned int with Scala `getUInt().toInt`
    /// semantics: VLQ-decode bounded to the full `u32` range
    /// (`[0, 0xFFFF_FFFF]`, matching `getUInt`'s `Long` range), then narrow
    /// to `i32` with two's-complement WRAP (Scala `.toInt`). A value above
    /// `i32::MAX` becomes negative (e.g. `0x8000_0000` -> `i32::MIN`).
    ///
    /// Unlike [`Self::get_u32_exact`] this does NOT reject values in
    /// `(i32::MAX, u32::MAX]` — it wraps them, exactly as the reference node
    /// does for `AvlTreeData.{keyLength, valueLengthOpt}` ("the deserializer
    /// succeeds with invalid AvlTreeData" when those wrap negative).
    pub fn get_uint_to_i32(&mut self) -> Result<i32, ReadError> {
        self.check_position_limit()?;
        let (val, consumed) = vlq::decode_vlq(&self.data[self.pos..])?;
        if val > u32::MAX as u64 {
            return Err(ReadError::ValueTooLarge {
                type_name: "u32 (Scala getUInt bound, u32::MAX)",
                got: val,
            });
        }
        self.pos += consumed;
        Ok(val as u32 as i32)
    }

    pub fn get_u64(&mut self) -> Result<u64, ReadError> {
        self.check_position_limit()?;
        let (val, consumed) = vlq::decode_vlq(&self.data[self.pos..])?;
        self.pos += consumed;
        Ok(val)
    }

    pub fn get_i32(&mut self) -> Result<i32, ReadError> {
        self.check_position_limit()?;
        let (val, consumed) = zigzag::decode_signed_i32(&self.data[self.pos..])?;
        self.pos += consumed;
        Ok(val)
    }

    pub fn get_i64(&mut self) -> Result<i64, ReadError> {
        self.check_position_limit()?;
        let (val, consumed) = zigzag::decode_signed_i64(&self.data[self.pos..])?;
        self.pos += consumed;
        Ok(val)
    }

    /// Decode a VLQ-encoded `u16`. Returns
    /// [`ReadError::ValueTooLarge`] if the VLQ-decoded `u64` does
    /// not fit in `u16` — matches Scala `getUShortExact` and
    /// sigma-rust `u16::try_from(u64)`.
    pub fn get_u16(&mut self) -> Result<u16, ReadError> {
        self.check_position_limit()?;
        let (val, consumed) = vlq::decode_vlq(&self.data[self.pos..])?;
        let narrowed = u16::try_from(val).map_err(|_| ReadError::ValueTooLarge {
            type_name: "u16",
            got: val,
        })?;
        self.pos += consumed;
        Ok(narrowed)
    }

    /// Read a raw 2-byte big-endian `u16` (non-VLQ). Mirrors Scala's
    /// `putBytes(short.toByteArray)` style fixed-width writes used in
    /// header fields.
    ///
    /// **Not the same as [`Self::get_u16`]**, which is VLQ-decoded
    /// (Scala-parity with `getUShortExact`). A caller reaching for raw
    /// BE here when they wanted VLQ — or vice versa — silently
    /// corrupts the wire format.
    ///
    /// Bounds-check delegates to [`Self::get_array`]: on a truncated
    /// slice this returns `ReadError::UnexpectedEnd { pos: <start>,
    /// needed: 2 }` without advancing the cursor, so upstream framing
    /// recovery is preserved.
    pub fn get_short_be(&mut self) -> Result<u16, ReadError> {
        Ok(u16::from_be_bytes(self.get_array::<2>()?))
    }

    /// Return a view of the original data between two byte positions.
    /// Useful for capturing raw bytes after structurally advancing the reader.
    pub fn data_slice(&self, from: usize, to: usize) -> &'a [u8] {
        &self.data[from..to]
    }

    /// Decode a VLQ-`u32` length followed by that many raw bytes.
    pub fn get_length_prefixed_bytes(&mut self) -> Result<&'a [u8], ReadError> {
        let len = self.get_u32_exact()? as usize;
        self.get_bytes(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vlq::encode_vlq;
    use crate::writer::VlqWriter;

    // ----- helpers -----

    /// Encode a u64 as VLQ bytes, useful for crafting payloads larger than
    /// the typed reader (`get_u32`/`get_u16`) accepts.
    fn vlq(v: u64) -> Vec<u8> {
        encode_vlq(v)
    }

    // ----- happy path -----

    #[test]
    fn get_short_be_decodes_big_endian_byte_order() {
        // [0x12, 0x34] is unambiguously 0x1234 in big-endian.
        // Pin against a regression to little-endian (which would yield 0x3412).
        let mut r = VlqReader::new(&[0x12, 0x34]);
        assert_eq!(r.get_short_be().unwrap(), 0x1234);
        assert!(r.is_empty());
    }

    #[test]
    fn get_short_be_truncated_input_unexpected_end_no_advance() {
        // Pin the delegated get_array<2>() failure contract: truncated input
        // must not advance the cursor.
        let mut r = VlqReader::new(&[0xAA]);
        let pre = r.position();
        match r.get_short_be() {
            Err(ReadError::UnexpectedEnd { pos, needed }) => {
                assert_eq!(pos, 0);
                assert_eq!(needed, 2);
            }
            other => panic!("expected UnexpectedEnd, got {other:?}"),
        }
        assert_eq!(
            r.position(),
            pre,
            "failed get_short_be must not advance the cursor"
        );
    }

    #[test]
    fn get_bytes_zero_length_returns_empty_no_advance() {
        let mut r = VlqReader::new(&[0xAA, 0xBB]);
        let pre = r.position();
        let slice = r.get_bytes(0).unwrap();
        assert!(slice.is_empty());
        assert_eq!(
            r.position(),
            pre,
            "zero-length read must not advance cursor"
        );
    }

    #[test]
    fn get_array_reads_fixed_size_into_array_and_advances() {
        let mut r = VlqReader::new(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let arr: [u8; 4] = r.get_array().unwrap();
        assert_eq!(arr, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(r.is_empty(), "cursor must advance past the consumed array");
    }

    #[test]
    fn position_advances_correctly_across_mixed_reads() {
        let mut w = VlqWriter::new();
        w.put_u8(0x01); // 1 byte
        w.put_u32(128); // VLQ → 2 bytes (0x80, 0x01)
        w.put_bytes(&[0xAA, 0xBB, 0xCC]); // 3 bytes
        let data = w.result();
        let total = data.len();

        let mut r = VlqReader::new(&data);
        assert_eq!(r.position(), 0);
        r.get_u8().unwrap();
        assert_eq!(r.position(), 1);
        r.get_u32_exact().unwrap();
        assert_eq!(r.position(), 3);
        r.get_bytes(3).unwrap();
        assert_eq!(r.position(), total);
        assert!(r.is_empty());
    }

    #[test]
    fn peek_u8_does_not_advance_position() {
        let mut r = VlqReader::new(&[0xAA, 0xBB]);
        let pre = r.position();
        let peeked = r.peek_u8().unwrap();
        assert_eq!(peeked, 0xAA);
        assert_eq!(r.position(), pre, "peek must not advance");
        // Subsequent get_u8 must still see byte 0.
        assert_eq!(r.get_u8().unwrap(), 0xAA);
    }

    #[test]
    fn set_position_at_len_is_valid() {
        let mut r = VlqReader::new(&[0xAA, 0xBB]);
        r.set_position(2);
        assert!(
            r.is_empty(),
            "position == len is the well-defined end-of-stream cursor"
        );
    }

    #[test]
    #[should_panic(expected = "position out of bounds")]
    fn set_position_beyond_len_panics() {
        let mut r = VlqReader::new(&[0xAA, 0xBB]);
        r.set_position(3);
    }

    // ----- Scala-parity rejection boundaries -----

    #[test]
    fn vlq_u32_above_i32_max_through_u32_max_is_rejected() {
        // Scala-parity boundary cases: values that fit in u32 but
        // exceed i32::MAX (the JVM Int.MaxValue) must be rejected to
        // match Scala getUIntExact.
        for &v in &[(i32::MAX as u32) + 1, u32::MAX] {
            let mut w = VlqWriter::new();
            w.put_u32(v);
            let mut r = VlqReader::new(w.as_slice());
            assert!(
                matches!(r.get_u32_exact(), Err(ReadError::ValueTooLarge { .. })),
                "u32 value {v} (above i32::MAX) must be rejected"
            );
        }
    }

    // ----- error paths -----

    #[test]
    fn get_u8_empty_buffer_returns_unexpected_end() {
        let mut r = VlqReader::new(&[]);
        match r.get_u8() {
            Err(ReadError::UnexpectedEnd { pos, needed }) => {
                assert_eq!(pos, 0);
                assert_eq!(needed, 1);
            }
            other => panic!("expected UnexpectedEnd, got {other:?}"),
        }
        assert_eq!(r.position(), 0, "failed read must not advance cursor");
    }

    #[test]
    fn get_bytes_oversized_request_returns_unexpected_end_no_advance() {
        let mut r = VlqReader::new(&[0xAA]);
        let pre = r.position();
        assert!(r.get_bytes(2).is_err());
        assert_eq!(r.position(), pre, "failed read must not advance cursor");
    }

    #[test]
    fn get_array_truncated_input_returns_unexpected_end_no_advance() {
        let mut r = VlqReader::new(&[0xAA]);
        let pre = r.position();
        let res: Result<[u8; 3], _> = r.get_array();
        match res {
            Err(ReadError::UnexpectedEnd { pos, needed }) => {
                assert_eq!(pos, pre);
                assert_eq!(needed, 3);
            }
            other => panic!("expected UnexpectedEnd, got {other:?}"),
        }
        assert_eq!(
            r.position(),
            pre,
            "failed get_array must not advance cursor"
        );
    }

    #[test]
    fn get_length_prefixed_bytes_oversized_length_errors() {
        // VLQ-encode length=99, but supply only 3 trailing bytes.
        let mut payload = encode_vlq(99);
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let mut r = VlqReader::new(&payload);
        assert!(r.get_length_prefixed_bytes().is_err());
    }

    #[test]
    fn truncated_vlq_continuation_errors_and_does_not_advance() {
        // [0x80] sets the continuation bit but provides no follow-up byte.
        // get_u32 must return an error and the cursor must NOT have advanced
        // past the bad byte (a partial advance would corrupt downstream
        // recovery — e.g. the demoted-to-revalidation path).
        let mut r = VlqReader::new(&[0x80]);
        let pre = r.position();
        assert!(r.get_u32_exact().is_err());
        assert_eq!(
            r.position(),
            pre,
            "truncated VLQ must leave cursor at start so upstream can recover"
        );
    }

    #[test]
    fn vlq_overflow_10_byte_continuation_errors_and_does_not_advance() {
        // 10 continuation bytes — value would not fit in u64.
        let bad = [0x80u8; 10];
        let mut r = VlqReader::new(&bad);
        let pre = r.position();
        assert!(r.get_u64().is_err());
        assert_eq!(r.position(), pre, "VLQ overflow must not partially advance");
    }

    // Universal cursor-recovery property for **single-step** typed reads.
    // `get_length_prefixed_bytes` is deliberately **excluded** because it
    // is a two-step composite (length-prefix decode followed by payload
    // read) whose mid-step partial-advance behavior is distinct — that
    // contract is pinned separately by
    // `get_length_prefixed_bytes_two_phase_cursor_contract` below.
    //
    // This proptest complements (does not replace) the named point
    // pins above: it catches failure-cursor regressions on inputs the
    // named tests don't enumerate. The named pins remain the
    // human-readable contract documentation.
    proptest::proptest! {
        #[test]
        fn proptest_cursor_does_not_advance_on_failed_typed_read(
            data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..16),
            op_idx in 0u8..9,
        ) {
            let mut r = VlqReader::new(&data);
            let pre = r.position();
            let failed = match op_idx {
                0 => r.get_u8().is_err(),
                1 => r.get_bytes(5).is_err(),
                2 => r.get_array::<5>().is_err(),
                3 => r.get_u32_exact().is_err(),
                4 => r.get_u16().is_err(),
                5 => r.get_u64().is_err(),
                6 => r.get_i32().is_err(),
                7 => r.get_i64().is_err(),
                8 => r.get_short_be().is_err(),
                _ => unreachable!(),
            };
            if failed {
                proptest::prop_assert_eq!(
                    r.position(),
                    pre,
                    "failed typed read advanced cursor (op_idx={})",
                    op_idx
                );
            }
        }
    }

    /// `get_length_prefixed_bytes` is a two-step read (VLQ length decode
    /// → raw byte read) with two distinct failure modes and matching
    /// cursor contracts:
    ///
    /// **Phase-1 failure** (VLQ length decode fails): cursor must remain
    /// at its starting position — same all-or-nothing contract as the
    /// single-step reads.
    ///
    /// **Phase-2 failure** (length decodes successfully but the payload
    /// is truncated): cursor advances **exactly past the length-prefix
    /// bytes** and stops — it does NOT advance into the partial
    /// payload. Callers that recover from framing errors downstream can
    /// rely on `position()` being the offset of the byte just after the
    /// length prefix in this case.
    #[test]
    fn get_length_prefixed_bytes_two_phase_cursor_contract() {
        // Phase 1: VLQ length decode fails (truncated continuation byte).
        // No advance.
        let mut r = VlqReader::new(&[0x80]);
        assert!(r.get_length_prefixed_bytes().is_err());
        assert_eq!(
            r.position(),
            0,
            "Phase-1 failure (VLQ decode) must leave cursor at start"
        );

        // Phase 2: VLQ length decodes successfully (encodes 99) but the
        // payload supplies only 3 bytes. Cursor advances past the
        // length-prefix bytes (and only that far).
        let prefix = encode_vlq(99);
        let prefix_len = prefix.len();
        let mut payload = prefix;
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let mut r = VlqReader::new(&payload);
        assert!(r.get_length_prefixed_bytes().is_err());
        assert_eq!(
            r.position(),
            prefix_len,
            "Phase-2 failure (payload truncation) must leave cursor exactly past the length prefix"
        );
    }

    // ----- oracle parity (Scala getUIntExact / getUShortExact) -----

    #[test]
    fn get_u32_above_i32_max_returns_value_too_large_no_advance() {
        // Smallest value above the Scala getUIntExact bound. Must
        // reject and leave the cursor untouched so framing recovery
        // upstream can rewind correctly.
        let oversize: u64 = (i32::MAX as u64) + 1; // 0x8000_0000
        let bytes = vlq(oversize);
        let mut r = VlqReader::new(&bytes);
        let pre = r.position();
        match r.get_u32_exact() {
            Err(ReadError::ValueTooLarge { type_name, got }) => {
                assert!(
                    type_name.starts_with("u32"),
                    "expected u32 type tag, got {type_name}"
                );
                assert_eq!(got, oversize);
            }
            other => panic!("expected ValueTooLarge, got {other:?}"),
        }
        assert_eq!(
            r.position(),
            pre,
            "failed get_u32 must not advance cursor (so upstream framing recovers)"
        );
    }

    #[test]
    fn get_u32_far_above_u32_max_also_rejected() {
        // Defense-in-depth: catches any future regression that would
        // accept "anything that fits in u32 after truncation".
        let oversize: u64 = (u32::MAX as u64) + 1; // 0x1_0000_0000
        let bytes = vlq(oversize);
        let mut r = VlqReader::new(&bytes);
        let pre = r.position();
        assert!(matches!(
            r.get_u32_exact(),
            Err(ReadError::ValueTooLarge { .. })
        ));
        assert_eq!(r.position(), pre);
    }

    #[test]
    fn get_u16_oversize_vlq_returns_value_too_large_error() {
        let oversize: u64 = (u16::MAX as u64) + 1; // 0x1_0000
        let bytes = vlq(oversize);
        let mut r = VlqReader::new(&bytes);
        let pre = r.position();
        match r.get_u16() {
            Err(ReadError::ValueTooLarge { type_name, got }) => {
                assert_eq!(type_name, "u16");
                assert_eq!(got, oversize);
            }
            other => panic!("expected ValueTooLarge, got {other:?}"),
        }
        assert_eq!(r.position(), pre, "failed get_u16 must not advance cursor");
    }

    #[test]
    fn put_u32_then_get_u32_asymmetry_documented() {
        // The writer accepts the full u32 range (mirroring Scala
        // `putUInt(v: Long)`); the reader applies `getUIntExact`
        // semantics and rejects values above `i32::MAX`. Bytes a
        // Rust caller could write via `put_u32` for `v > i32::MAX`
        // are NOT round-trippable through `get_u32` — they must be
        // read with `get_u64`. Pin the asymmetry so any future
        // caller surprised by it can find the documented contract
        // through this test.
        let mut w = VlqWriter::new();
        w.put_u32(0x8000_0000); // exactly i32::MAX + 1
        let bytes = w.result();

        // get_u32 rejects.
        let mut r = VlqReader::new(&bytes);
        assert!(matches!(
            r.get_u32_exact(),
            Err(ReadError::ValueTooLarge { .. })
        ));

        // get_u64 accepts and returns the original value.
        let mut r2 = VlqReader::new(&bytes);
        assert_eq!(r2.get_u64().unwrap(), 0x8000_0000);
    }
}

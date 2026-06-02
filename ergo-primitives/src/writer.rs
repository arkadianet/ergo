use crate::vlq;
use crate::zigzag;

/// Serialization writer that produces bytes using Scorex VLQ encoding.
pub struct VlqWriter {
    buf: Vec<u8>,
}

impl VlqWriter {
    /// Create an empty writer with no preallocated capacity.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create an empty writer with pre-reserved capacity, useful when the
    /// emitted size is known approximately ahead of time.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn put_u8(&mut self, b: u8) {
        self.buf.push(b);
    }

    pub fn put_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Append a VLQ-encoded `u32`. Mirrors Scala
    /// `putUInt(v: Long)` — accepts the full `u32` value range
    /// without bound checks.
    ///
    /// **Asymmetry with [`crate::reader::VlqReader::get_u32_exact`]**:
    /// the reader narrows to the `i32::MAX` band (`getUIntExact`
    /// semantics), so `put_u32(0x8000_0000)` produces wire bytes
    /// that this crate's reader will reject. Callers that need
    /// the full u32 range round-trip should use [`Self::put_u64`]
    /// plus [`crate::reader::VlqReader::get_u64`].
    pub fn put_u32(&mut self, v: u32) {
        vlq::encode_vlq_into(v as u64, &mut self.buf);
    }

    pub fn put_u64(&mut self, v: u64) {
        vlq::encode_vlq_into(v, &mut self.buf);
    }

    pub fn put_i32(&mut self, v: i32) {
        zigzag::encode_signed_i32_into(v, &mut self.buf);
    }

    pub fn put_i64(&mut self, v: i64) {
        zigzag::encode_signed_i64_into(v, &mut self.buf);
    }

    pub fn put_u16(&mut self, v: u16) {
        vlq::encode_vlq_into(v as u64, &mut self.buf);
    }

    /// Write a raw 2-byte big-endian `u16` (non-VLQ). Mirrors Scala's
    /// `putBytes(short.toByteArray)` style fixed-width writes used in
    /// header fields.
    ///
    /// **Not the same as [`Self::put_u16`]**, which is VLQ-encoded
    /// (Scala-parity with `putUShort`). A caller reaching for raw BE
    /// here when they wanted VLQ — or vice versa — silently corrupts
    /// the wire format.
    pub fn put_short_be(&mut self, v: u16) {
        self.put_bytes(&v.to_be_bytes());
    }

    /// Emit a VLQ-`u32` length prefix followed by the raw bytes.
    ///
    /// # Panics
    ///
    /// Panics if `bytes.len()` exceeds `i32::MAX` (~2 GiB), matching the
    /// reader's `getUIntExact` rejection bound. A payload that large
    /// would silently wrap the length prefix on the wire and produce a
    /// frame the reader can't decode; the assert turns that programmer-
    /// error path into a loud panic at the construction site rather
    /// than a corrupted-wire-format bug downstream. Consistent with the
    /// length-bound asserts in `ergo-ser`'s write_* paths.
    pub fn put_length_prefixed_bytes(&mut self, bytes: &[u8]) {
        assert!(
            bytes.len() <= i32::MAX as usize,
            "put_length_prefixed_bytes: payload {} bytes exceeds Scala \
             getUIntExact bound (i32::MAX = {}); reader would reject",
            bytes.len(),
            i32::MAX
        );
        self.put_u32(bytes.len() as u32);
        self.put_bytes(bytes);
    }

    pub fn result(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Empty the buffer while preserving its capacity. Used for scratch
    /// reuse across multiple emits — the capacity-preservation contract
    /// is what makes `as_slice()` + `clear()` cheaper than constructing
    /// a fresh writer per call.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Borrow the currently-written bytes without consuming the writer.
    /// Intended for callers that copy synchronously (e.g. `redb::Table::insert`,
    /// `blake2b256`) and then call `clear()` for the next emit.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

impl Default for VlqWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn put_u8_then_bytes_then_u32_writes_in_order() {
        let mut w = VlqWriter::new();
        w.put_u8(0x01);
        w.put_bytes(&[0x02, 0x03]);
        w.put_u32(128);
        let result = w.result();
        assert_eq!(&result[0..3], &[0x01, 0x02, 0x03]);
        assert_eq!(&result[3..5], &[0x80, 0x01]);
    }

    #[test]
    fn put_short_be_writes_big_endian_byte_order() {
        // Pin against accidental switch to little-endian (would yield 0x34, 0x12).
        let mut w = VlqWriter::new();
        w.put_short_be(0x1234);
        assert_eq!(w.result(), vec![0x12, 0x34]);
    }

    #[test]
    fn put_length_prefixed_bytes_emits_vlq_length_then_payload() {
        let mut w = VlqWriter::new();
        w.put_length_prefixed_bytes(&[0xAA, 0xBB, 0xCC]);
        let result = w.result();
        assert_eq!(result, vec![0x03, 0xAA, 0xBB, 0xCC]);
    }

    // ----- round-trips / scratch-reuse invariants -----

    #[test]
    fn clear_then_reuse_is_byte_identical_to_fresh_writer() {
        // Writing payload A, then clear(), then writing payload B must produce
        // bytes byte-identical to a fresh writer that wrote only payload B.
        // This is the foundational invariant that lets callers reuse a single
        // VlqWriter as scratch across many emits without allocating.
        let mut reused = VlqWriter::new();
        // Payload A — exercise every encoding path so a residual would show up.
        reused.put_u8(0x7F);
        reused.put_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
        reused.put_u32(123_456);
        reused.put_u64(u64::MAX);
        reused.put_i32(-42);
        reused.put_i64(i64::MIN);
        reused.put_u16(0xCAFE);
        reused.put_short_be(0xBABE);
        reused.put_length_prefixed_bytes(&[0x01, 0x02]);
        let cap_before_clear = reused.as_slice().len();
        assert!(cap_before_clear > 0, "payload A should be non-empty");

        reused.clear();
        assert!(reused.is_empty(), "buffer must be empty after clear");
        let empty: &[u8] = &[];
        assert_eq!(reused.as_slice(), empty, "as_slice empty after clear");

        // Payload B — different encodings, intentionally chosen to be SHORTER
        // than payload A so any residual tail bytes from A would be visible.
        reused.put_u8(0x01);
        reused.put_i64(7);
        reused.put_u16(3);

        let mut fresh = VlqWriter::new();
        fresh.put_u8(0x01);
        fresh.put_i64(7);
        fresh.put_u16(3);

        assert_eq!(
            reused.as_slice(),
            fresh.as_slice(),
            "reused writer must be byte-identical to fresh writer after clear()",
        );
        // Result of consuming the reused writer also matches fresh.
        let reused_bytes = reused.result();
        let fresh_bytes = fresh.result();
        assert_eq!(reused_bytes, fresh_bytes);
    }

    #[test]
    fn as_slice_matches_result_for_same_writes() {
        // as_slice() must reflect exactly what result() would consume — proves
        // the writer has no hidden header/footer state and that callers using
        // as_slice() (then clear()) see the same bytes as `result()` callers.
        let writes = |w: &mut VlqWriter| {
            w.put_u8(9);
            w.put_bytes(&[0xAA, 0xBB]);
            w.put_u32(1024);
            w.put_i32(-1);
        };
        let mut a = VlqWriter::new();
        writes(&mut a);
        let snapshot: Vec<u8> = a.as_slice().to_vec();
        let consumed = a.result();
        assert_eq!(snapshot, consumed);

        let mut b = VlqWriter::new();
        writes(&mut b);
        assert_eq!(b.as_slice(), consumed.as_slice());
    }
}

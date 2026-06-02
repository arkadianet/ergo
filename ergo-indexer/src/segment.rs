//! Segment body wire format. Mirrors Scala
//! `Segment.scala:411-429`'s `SegmentSerializer.serialize / parse`.
//!
//! A `Segment` is the shared body shared by `IndexedErgoAddress`,
//! `IndexedContractTemplate`, and `IndexedToken` parent records, plus
//! every standalone spill-segment row stored under `SEGMENTS`. It
//! holds two arrays of signed `i64` global indexes (one for txs, one
//! for boxes) and two `i32` counters that track how many spill segments
//! each list has produced so far.
//!
//! The signed-i64 entries on the boxes list use the sign bit as a
//! "spent" flag (`-globalIndex` after a spend, `+globalIndex` while
//! unspent). Tx entries are always positive.
//!
//! Wire layout (all integers are Scorex VLQ-zigzag):
//! ```text
//! [txs.len:           i32]
//! [txs[0..len]:       i64 each]
//! [boxes.len:         i32]
//! [boxes[0..len]:     i64 each]
//! [box_segment_count: i32]
//! [tx_segment_count:  i32]
//! ```
//! For spill segments (the rows under `SEGMENTS` keyed by the derived
//! segment id) `box_segment_count` and `tx_segment_count` are always
//! `0` (spills don't recurse). For parent records (the head buffer)
//! both arrays are bounded by `SEGMENT_THRESHOLD = 512` post-spill.

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

/// Mirrors `IndexedErgoAddressSerializer.segmentTreshold = 512`.
///
/// A head buffer spills when its length is *strictly greater than* 512.
/// The spill takes the oldest 512 entries from the head and writes them
/// as a new spill segment; the head retains `len - 512` entries. Note
/// the Scala typo "Treshold" — the constant is 512, not the spelling.
pub const SEGMENT_THRESHOLD: usize = 512;

/// Body of any segment record (parent head buffer or spill row).
///
/// `txs` and `boxes` carry signed-i64 global indexes (the sign on
/// box entries encodes spent vs unspent — see the `//!` header).
/// `box_segment_count` and `tx_segment_count` are the number of spill
/// segments already produced for the corresponding list (`0` on a
/// fresh parent, monotonically incrementing thereafter).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Segment {
    pub txs: Vec<i64>,
    pub boxes: Vec<i64>,
    pub box_segment_count: i32,
    pub tx_segment_count: i32,
}

impl Segment {
    pub fn empty() -> Self {
        Self::default()
    }

    /// True if the head buffer exceeds the spill threshold and must be
    /// split — `len > 512`, matching Scala's
    /// `while(_.length > segmentTreshold)` (`Segment.scala:110-122`).
    pub fn boxes_need_spill(&self) -> bool {
        self.boxes.len() > SEGMENT_THRESHOLD
    }

    pub fn txs_need_spill(&self) -> bool {
        self.txs.len() > SEGMENT_THRESHOLD
    }
}

/// Serialize a `Segment` body. Order and types match
/// `SegmentSerializer.serialize` in Scala
/// (`Segment.scala:411-418`).
pub fn write_segment(w: &mut VlqWriter, s: &Segment) {
    w.put_i32(s.txs.len() as i32);
    for &t in &s.txs {
        w.put_i64(t);
    }
    w.put_i32(s.boxes.len() as i32);
    for &b in &s.boxes {
        w.put_i64(b);
    }
    w.put_i32(s.box_segment_count);
    w.put_i32(s.tx_segment_count);
}

/// Parse a `Segment` body. Inverse of [`write_segment`].
///
/// Returns `InvalidData` if the wire format declares a negative array
/// length — Scala uses signed `Int` for these counts and a malicious
/// or corrupted record could carry a negative value, which would
/// otherwise underflow a `usize` cast.
pub fn read_segment(r: &mut VlqReader) -> Result<Segment, ReadError> {
    let txs_len = r.get_i32()?;
    if txs_len < 0 {
        return Err(ReadError::InvalidData(format!(
            "segment txs length is negative: {txs_len}"
        )));
    }
    let mut txs = Vec::with_capacity(txs_len as usize);
    for _ in 0..txs_len {
        txs.push(r.get_i64()?);
    }

    let boxes_len = r.get_i32()?;
    if boxes_len < 0 {
        return Err(ReadError::InvalidData(format!(
            "segment boxes length is negative: {boxes_len}"
        )));
    }
    let mut boxes = Vec::with_capacity(boxes_len as usize);
    for _ in 0..boxes_len {
        boxes.push(r.get_i64()?);
    }

    let box_segment_count = r.get_i32()?;
    let tx_segment_count = r.get_i32()?;

    Ok(Segment {
        txs,
        boxes,
        box_segment_count,
        tx_segment_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(s: &Segment) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_segment(&mut w, s);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let parsed = read_segment(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after segment roundtrip");
        assert_eq!(&parsed, s, "segment roundtrip diverged");
        bytes
    }

    // ----- happy path -----

    #[test]
    fn empty_segment_roundtrips() {
        let s = Segment::empty();
        let bytes = roundtrip(&s);
        // 0 txs (i32 zigzag 0 = 0x00) + 0 boxes (0x00) + bsc 0 + tsc 0 = 4 bytes
        assert_eq!(bytes, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn segment_with_positive_and_negative_box_entries_roundtrips() {
        // Box entries can be negative (spent).
        let s = Segment {
            txs: vec![1, 2, 3],
            boxes: vec![10, -42, 1024, -i64::MAX],
            box_segment_count: 0,
            tx_segment_count: 0,
        };
        roundtrip(&s);
    }

    #[test]
    fn segment_with_segment_counts_roundtrips() {
        let s = Segment {
            txs: vec![],
            boxes: vec![],
            box_segment_count: 7,
            tx_segment_count: 3,
        };
        roundtrip(&s);
    }

    #[test]
    fn segment_at_threshold_size_roundtrips() {
        // Head buffer at exactly 512 entries — the spill trigger fires
        // at >512, so a 512-entry segment is a valid pre-spill state.
        let s = Segment {
            txs: (0..SEGMENT_THRESHOLD as i64).collect(),
            boxes: (0..SEGMENT_THRESHOLD as i64)
                .map(|i| if i % 2 == 0 { i } else { -i })
                .collect(),
            box_segment_count: 5,
            tx_segment_count: 2,
        };
        assert!(!s.boxes_need_spill());
        assert!(!s.txs_need_spill());
        roundtrip(&s);
    }

    #[test]
    fn segment_just_above_threshold_signals_spill() {
        let mut s = Segment::empty();
        s.boxes = (0..(SEGMENT_THRESHOLD + 1) as i64).collect();
        s.txs = vec![];
        assert!(s.boxes_need_spill());
        assert!(!s.txs_need_spill());
        // Even an over-threshold segment must still roundtrip — the
        // serializer doesn't enforce the spill invariant; the apply
        // path does, just before persisting.
        roundtrip(&s);
    }

    #[test]
    fn segment_extreme_i64_values_roundtrip() {
        let s = Segment {
            txs: vec![0, i64::MAX, 1, i64::MIN + 1],
            boxes: vec![i64::MIN + 1, -1, 0, 1, i64::MAX],
            box_segment_count: i32::MAX,
            tx_segment_count: i32::MIN,
        };
        roundtrip(&s);
    }

    #[test]
    fn negative_txs_length_rejected() {
        // A wire-level negative length is a corruption signal — make
        // sure we don't blindly cast it to usize.
        let mut w = VlqWriter::new();
        w.put_i32(-1);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = read_segment(&mut r).unwrap_err();
        match err {
            ReadError::InvalidData(msg) => assert!(msg.contains("negative")),
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }
}

//! `SEGMENTS` table I/O. One redb row per spill-segment id (see
//! `crate::segment_id::box_segment_id` / `tx_segment_id`) carrying
//! the serialized `Segment` body.
//!
//! Spill segments are flat — no per-type prefix, no `BalanceInfo`.
//! All segments (address / template / token) share this single table
//! because their derived ids are 32-byte hashes that collide only with
//! astronomically-low probability.

use redb::ReadTransaction;
#[cfg(test)]
use redb::WriteTransaction;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
#[cfg(test)]
use ergo_primitives::writer::VlqWriter;

use crate::error::IndexerError;
#[cfg(test)]
use crate::segment::write_segment;
use crate::segment::{read_segment, Segment};
use crate::store::tables::SEGMENTS;

/// Test-only helper. Apply path writes `SEGMENTS` rows directly via the
/// redb table API in `apply.rs`; this wrapper backs the inline
/// roundtrip test and crate-level fixture builders in `handle.rs::tests`.
#[cfg(test)]
pub(crate) fn write_spill(
    write_txn: &WriteTransaction,
    segment_id: &Digest32,
    rec: &Segment,
) -> Result<(), IndexerError> {
    let mut w = VlqWriter::new();
    write_segment(&mut w, rec);
    let bytes = w.result();
    let mut table = write_txn.open_table(SEGMENTS)?;
    table.insert(segment_id.as_bytes().as_slice(), bytes.as_slice())?;
    Ok(())
}

/// Test-only helper. Rollback merge-back removes `SEGMENTS` rows
/// directly via the redb table API in `rollback.rs`; this wrapper backs
/// the inline read-after-delete test.
#[cfg(test)]
pub(crate) fn delete_spill(
    write_txn: &WriteTransaction,
    segment_id: &Digest32,
) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(SEGMENTS)?;
    table.remove(segment_id.as_bytes().as_slice())?;
    Ok(())
}

pub(crate) fn read_spill_in(
    read_txn: &ReadTransaction,
    segment_id: &Digest32,
) -> Result<Option<Segment>, IndexerError> {
    let table = read_txn.open_table(SEGMENTS)?;
    let Some(guard) = table.get(segment_id.as_bytes().as_slice())? else {
        return Ok(None);
    };
    let bytes = guard.value();
    let total = bytes.len();
    let mut r = VlqReader::new(bytes);
    let rec = read_segment(&mut r).map_err(|source| IndexerError::DbDecode {
        context: "segment",
        source,
    })?;
    if !r.is_empty() {
        // Trailing-byte framing check: ergo-ser read_segment succeeded,
        // but the row carries extra bytes. This is a length mismatch,
        // not a decode failure inside ergo-ser.
        return Err(IndexerError::DbRowLength {
            context: "segment",
            expected: total - r.remaining(),
            got: total,
        });
    }
    Ok(Some(rec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment_id::{box_segment_id, tx_segment_id};
    use crate::store::IndexerStore;
    use tempfile::TempDir;

    fn open_store() -> (IndexerStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("indexer.redb");
        let (store, _) = IndexerStore::open(&path).unwrap();
        (store, tmp)
    }

    fn full_segment(tag: u8) -> Segment {
        // 512-entry head buffer at the spill threshold — the typical
        // shape of a segment about to be written as a spill. Using
        // `tag` differentiates the contents per-test so collisions
        // surface as wrong values, not as silent overwrites.
        Segment {
            txs: (0..512_i64).map(|i| i + tag as i64 * 1_000_000).collect(),
            boxes: (0..512_i64)
                .map(|i| {
                    let v = i + tag as i64 * 1_000_000;
                    if i % 3 == 0 {
                        -v
                    } else {
                        v
                    }
                })
                .collect(),
            box_segment_count: 0,
            tx_segment_count: 0,
        }
    }

    // ----- happy path -----

    #[test]
    fn write_then_read_spill_roundtrips_full_segment() {
        let (store, _tmp) = open_store();
        let parent = Digest32::from_bytes([0xAB; 32]);
        let seg_id = box_segment_id(&parent, 0);
        let rec = full_segment(0xAB);

        let write_txn = store.begin_write().unwrap();
        write_spill(&write_txn, &seg_id, &rec).unwrap();
        write_txn.commit().unwrap();

        let got = store.read_spill_segment(&seg_id).unwrap().expect("present");
        assert_eq!(got, rec);
    }

    #[test]
    fn distinct_segment_ids_for_box_vs_tx_dont_collide() {
        let (store, _tmp) = open_store();
        let parent = Digest32::from_bytes([0xAB; 32]);
        let box_id = box_segment_id(&parent, 0);
        let tx_id = tx_segment_id(&parent, 0);
        assert_ne!(box_id, tx_id);

        let box_rec = full_segment(1);
        let tx_rec = full_segment(2);

        let write_txn = store.begin_write().unwrap();
        write_spill(&write_txn, &box_id, &box_rec).unwrap();
        write_spill(&write_txn, &tx_id, &tx_rec).unwrap();
        write_txn.commit().unwrap();

        // Each id resolves to its own segment, neither bled into the other.
        assert_eq!(store.read_spill_segment(&box_id).unwrap().unwrap(), box_rec);
        assert_eq!(store.read_spill_segment(&tx_id).unwrap().unwrap(), tx_rec);
    }

    #[test]
    fn read_missing_spill_returns_none() {
        let (store, _tmp) = open_store();
        let nonexistent = box_segment_id(&Digest32::ZERO, 999);
        assert!(store.read_spill_segment(&nonexistent).unwrap().is_none());
    }

    #[test]
    fn delete_spill_removes_row() {
        let (store, _tmp) = open_store();
        let parent = Digest32::from_bytes([0xCC; 32]);
        let seg_id = box_segment_id(&parent, 0);
        let rec = full_segment(0xCC);

        let write_txn = store.begin_write().unwrap();
        write_spill(&write_txn, &seg_id, &rec).unwrap();
        write_txn.commit().unwrap();
        assert!(store.read_spill_segment(&seg_id).unwrap().is_some());

        let write_txn = store.begin_write().unwrap();
        delete_spill(&write_txn, &seg_id).unwrap();
        write_txn.commit().unwrap();
        assert!(store.read_spill_segment(&seg_id).unwrap().is_none());
    }

    #[test]
    fn raw_byte_fixture_segment_roundtrip() {
        // Pin canonical wire format for SEGMENTS rows: encode → decode →
        // re-encode produces the same bytes. A stale-byte regression in
        // the shared writer used by spill flushes would show up here or
        // in the trailing-garbage test below.
        let rec = Segment {
            txs: vec![1, 2, 3, 4],
            boxes: vec![-100, 200, -300, 400, -500],
            box_segment_count: 0, // spills always carry zero counters
            tx_segment_count: 0,
        };
        let mut w = VlqWriter::new();
        write_segment(&mut w, &rec);
        let bytes = w.result();
        assert!(!bytes.is_empty());

        let mut r = VlqReader::new(&bytes);
        let decoded = read_segment(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after read_segment");
        assert_eq!(decoded, rec);

        let mut w2 = VlqWriter::new();
        write_segment(&mut w2, &decoded);
        assert_eq!(
            w2.result(),
            bytes,
            "segment: re-serialization is not byte-identical to original"
        );
    }

    #[test]
    fn read_spill_in_rejects_trailing_garbage() {
        // EOF guard: extra trailing bytes on a SEGMENTS row must be
        // rejected — safety net for the shared-writer flush path
        // (`flush_staged_spills`).
        let (store, _tmp) = open_store();
        let parent = Digest32::from_bytes([0xDE; 32]);
        let seg_id = box_segment_id(&parent, 0);
        let rec = Segment {
            txs: vec![1, 2],
            boxes: vec![-3, 4],
            box_segment_count: 0,
            tx_segment_count: 0,
        };

        let mut w = VlqWriter::new();
        write_segment(&mut w, &rec);
        let mut bytes = w.result();
        bytes.extend_from_slice(&[0x00, 0x01, 0x02]); // 3 garbage bytes

        let write_txn = store.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(SEGMENTS).unwrap();
            table
                .insert(seg_id.as_bytes().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        let err = store.read_spill_segment(&seg_id).unwrap_err();
        match err {
            IndexerError::DbRowLength {
                context,
                expected,
                got,
            } => {
                assert_eq!(context, "segment");
                assert!(
                    got > expected,
                    "expected got>expected (trailing bytes), got expected={expected} got={got}"
                );
            }
            other => panic!("expected DbRowLength, got {other:?}"),
        }
    }

    #[test]
    fn read_spill_in_rejects_single_trailing_byte() {
        let (store, _tmp) = open_store();
        let parent = Digest32::from_bytes([0xAD; 32]);
        let seg_id = box_segment_id(&parent, 0);
        let rec = Segment::empty();

        let mut w = VlqWriter::new();
        write_segment(&mut w, &rec);
        let mut bytes = w.result();
        bytes.push(0xFF);

        let write_txn = store.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(SEGMENTS).unwrap();
            table
                .insert(seg_id.as_bytes().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        store
            .read_spill_segment(&seg_id)
            .expect_err("single trailing 0xFF must be rejected");
    }

    #[test]
    fn segments_for_different_seg_nums_dont_collide() {
        // Rollback re-reads spills by (parent, segNum) so each (parent,
        // n) tuple must produce a distinct, stable id.
        let (store, _tmp) = open_store();
        let parent = Digest32::from_bytes([0x77; 32]);

        let write_txn = store.begin_write().unwrap();
        for n in 0..5 {
            let id = box_segment_id(&parent, n);
            let rec = Segment {
                txs: vec![],
                boxes: vec![n as i64; 1],
                box_segment_count: 0,
                tx_segment_count: 0,
            };
            write_spill(&write_txn, &id, &rec).unwrap();
        }
        write_txn.commit().unwrap();

        for n in 0..5 {
            let id = box_segment_id(&parent, n);
            let got = store.read_spill_segment(&id).unwrap().unwrap();
            assert_eq!(got.boxes, vec![n as i64]);
        }
    }
}

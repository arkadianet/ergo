//! `INDEXED_ADDRESS` table I/O. One redb row per `tree_hash` carrying
//! the serialized `IndexedAddress` parent record.
//!
//! Spill segments under the same parent live under `SEGMENTS` (see
//! `store::segment`), keyed by `box_segment_id` / `tx_segment_id`.

use redb::ReadTransaction;
#[cfg(test)]
use redb::WriteTransaction;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
#[cfg(test)]
use ergo_primitives::writer::VlqWriter;

#[cfg(test)]
use crate::address::write_indexed_address;
use crate::address::{read_indexed_address, IndexedAddress};
use crate::error::IndexerError;
use crate::segment::SEGMENT_THRESHOLD;
use crate::segment_id::{box_segment_id, tx_segment_id};
use crate::store::segment::read_spill_in;
use crate::store::tables::INDEXED_ADDRESS;

/// Test-only helper. Apply path writes the row directly via the
/// `INDEXED_ADDRESS` table API in `apply.rs`; this wrapper exists so
/// crate-internal tests can populate fixture rows without re-deriving
/// the serializer + table-open dance at every call site.
#[cfg(test)]
pub(crate) fn write_address(
    write_txn: &WriteTransaction,
    tree_hash: &Digest32,
    rec: &IndexedAddress,
) -> Result<(), IndexerError> {
    let mut w = VlqWriter::new();
    write_indexed_address(&mut w, rec);
    let bytes = w.result();
    let mut table = write_txn.open_table(INDEXED_ADDRESS)?;
    table.insert(tree_hash.as_bytes().as_slice(), bytes.as_slice())?;
    Ok(())
}

/// Test-only helper. Rollback removes the row directly via the
/// `INDEXED_ADDRESS` table API in `rollback.rs`; this wrapper is used
/// by inline tests that exercise the read-after-delete path.
#[cfg(test)]
pub(crate) fn delete_address(
    write_txn: &WriteTransaction,
    tree_hash: &Digest32,
) -> Result<(), IndexerError> {
    let mut table = write_txn.open_table(INDEXED_ADDRESS)?;
    table.remove(tree_hash.as_bytes().as_slice())?;
    Ok(())
}

pub(crate) fn read_address_in(
    read_txn: &ReadTransaction,
    tree_hash: &Digest32,
) -> Result<Option<IndexedAddress>, IndexerError> {
    let table = read_txn.open_table(INDEXED_ADDRESS)?;
    let Some(guard) = table.get(tree_hash.as_bytes().as_slice())? else {
        return Ok(None);
    };
    let bytes = guard.value();
    let total = bytes.len();
    let mut r = VlqReader::new(bytes);
    let rec = read_indexed_address(&mut r).map_err(|source| IndexerError::DbDecode {
        context: "indexed_address",
        source,
    })?;
    if !r.is_empty() {
        // Trailing-byte framing check: ergo-ser read_indexed_address
        // succeeded, but the row carries extra bytes. This is a length
        // mismatch, not a decode failure inside ergo-ser.
        return Err(IndexerError::DbRowLength {
            context: "indexed_address",
            expected: total - r.remaining(),
            got: total,
        });
    }
    Ok(Some(rec))
}

/// Concatenate every box-segment entry under `tree_hash` in oldest-first
/// order: `spill_0 ++ spill_1 ++ ... ++ spill_(N-1) ++ head.boxes`.
///
/// Reads the parent record and all `box_segment_count` spills inside a
/// single `ReadTransaction` so the result is a consistent snapshot.
/// `Ok(None)` means the address has never been indexed; an
/// `Err(IndexerError::SpillMissingFromParent)` is returned only when a
/// spill row referenced by the parent's segment count is missing on
/// disk (a consistency bug — apply writes the parent + spills
/// atomically).
pub(crate) fn read_address_box_entries_in(
    read_txn: &ReadTransaction,
    tree_hash: &Digest32,
) -> Result<Option<Vec<i64>>, IndexerError> {
    let Some(addr) = read_address_in(read_txn, tree_hash)? else {
        return Ok(None);
    };
    let count = addr.segment.box_segment_count.max(0) as usize;
    let mut entries = Vec::with_capacity(count * SEGMENT_THRESHOLD + addr.segment.boxes.len());
    for seg_num in 0..addr.segment.box_segment_count {
        let seg_id = box_segment_id(tree_hash, seg_num);
        let spill = read_spill_in(read_txn, &seg_id)?.ok_or_else(|| {
            IndexerError::SpillMissingFromParent {
                parent_id: hex::encode(tree_hash.as_bytes()),
                seg_num,
                parent_kind: crate::error::SpillParentKind::Address,
            }
        })?;
        entries.extend(spill.boxes);
    }
    entries.extend(addr.segment.boxes);
    Ok(Some(entries))
}

/// Concatenate every tx-segment entry under `tree_hash` in oldest-first
/// order. Same semantics as [`read_address_box_entries_in`] but for tx
/// segments (always positive — no spent flag).
pub(crate) fn read_address_tx_entries_in(
    read_txn: &ReadTransaction,
    tree_hash: &Digest32,
) -> Result<Option<Vec<i64>>, IndexerError> {
    let Some(addr) = read_address_in(read_txn, tree_hash)? else {
        return Ok(None);
    };
    let count = addr.segment.tx_segment_count.max(0) as usize;
    let mut entries = Vec::with_capacity(count * SEGMENT_THRESHOLD + addr.segment.txs.len());
    for seg_num in 0..addr.segment.tx_segment_count {
        let seg_id = tx_segment_id(tree_hash, seg_num);
        let spill = read_spill_in(read_txn, &seg_id)?.ok_or_else(|| {
            IndexerError::SpillMissingFromParent {
                parent_id: hex::encode(tree_hash.as_bytes()),
                seg_num,
                parent_kind: crate::error::SpillParentKind::Address,
            }
        })?;
        entries.extend(spill.txs);
    }
    entries.extend(addr.segment.txs);
    Ok(Some(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::BalanceInfo;
    use crate::segment::Segment;
    use crate::store::IndexerStore;
    use tempfile::TempDir;

    fn open_store() -> (IndexerStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("indexer.redb");
        let (store, _) = IndexerStore::open(&path).unwrap();
        (store, tmp)
    }

    fn d(seed: u8) -> Digest32 {
        Digest32::from_bytes([seed; 32])
    }

    // ----- happy path -----

    #[test]
    fn write_then_read_address_roundtrips() {
        let (store, _tmp) = open_store();
        let tree_hash = d(0xAA);
        let rec = IndexedAddress {
            tree_hash,
            balance: Some(BalanceInfo {
                nano_ergs: 12_345,
                tokens: vec![(d(0xCC), 7), (d(0xDD), 13)],
            }),
            segment: Segment {
                txs: vec![1, 2, 3],
                boxes: vec![10, -20],
                box_segment_count: 0,
                tx_segment_count: 0,
            },
        };

        // write
        let write_txn = store.begin_write().unwrap();
        write_address(&write_txn, &tree_hash, &rec).unwrap();
        write_txn.commit().unwrap();

        // read back
        let got = store.read_address(&tree_hash).unwrap().expect("present");
        assert_eq!(got, rec);
    }

    #[test]
    fn read_missing_address_returns_none() {
        let (store, _tmp) = open_store();
        assert!(store.read_address(&d(0x99)).unwrap().is_none());
    }

    #[test]
    fn delete_address_removes_row() {
        let (store, _tmp) = open_store();
        let tree_hash = d(0xBB);
        let rec = IndexedAddress::empty(tree_hash);

        let write_txn = store.begin_write().unwrap();
        write_address(&write_txn, &tree_hash, &rec).unwrap();
        write_txn.commit().unwrap();
        assert!(store.read_address(&tree_hash).unwrap().is_some());

        let write_txn = store.begin_write().unwrap();
        delete_address(&write_txn, &tree_hash).unwrap();
        write_txn.commit().unwrap();
        assert!(store.read_address(&tree_hash).unwrap().is_none());
    }

    #[test]
    fn raw_byte_fixture_address_roundtrip() {
        // Pin canonical wire format: encode → decode → re-encode produces
        // the same bytes. Any change to write_indexed_address or
        // read_indexed_address that breaks this invariant fails here.
        // The shared-writer reuse path hits the same write/read path,
        // so a stale-byte regression would surface either here (wrong
        // bytes) or in the trailing-garbage test below (extra bytes).
        let rec = IndexedAddress {
            tree_hash: d(0x42),
            balance: Some(BalanceInfo {
                nano_ergs: 100_000,
                tokens: vec![(d(0x01), 5), (d(0x02), 999)],
            }),
            segment: Segment {
                txs: vec![1, 2, 3],
                boxes: vec![-10, 20, -30],
                box_segment_count: 2,
                tx_segment_count: 1,
            },
        };
        let mut w = VlqWriter::new();
        write_indexed_address(&mut w, &rec);
        let bytes = w.result();
        assert!(!bytes.is_empty());

        // Decode → identity.
        let mut r = VlqReader::new(&bytes);
        let decoded = read_indexed_address(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after read_indexed_address");
        assert_eq!(decoded, rec);

        // Re-encode → same bytes. Locks the wire format byte-for-byte.
        let mut w2 = VlqWriter::new();
        write_indexed_address(&mut w2, &decoded);
        assert_eq!(
            w2.result(),
            bytes,
            "address: re-serialization is not byte-identical to original"
        );
    }

    #[test]
    fn read_address_in_rejects_trailing_garbage() {
        // EOF guard: a row with extra trailing bytes must be rejected. This
        // is the safety net for the shared-writer reuse path — a buggy
        // shared writer that fails to clear() would prepend stale bytes
        // from the previous emit, making the row longer than expected.
        let (store, _tmp) = open_store();
        let tree_hash = d(0xAA);
        let rec = IndexedAddress::empty(tree_hash);

        let mut w = VlqWriter::new();
        write_indexed_address(&mut w, &rec);
        let mut bytes = w.result();
        bytes.extend_from_slice(&[0xFF, 0xEE]); // 2 garbage bytes

        // Inject directly via the table so the trailing bytes survive.
        let write_txn = store.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(INDEXED_ADDRESS).unwrap();
            table
                .insert(tree_hash.as_bytes().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        let err = store.read_address(&tree_hash).unwrap_err();
        match err {
            IndexerError::DbRowLength {
                context,
                expected,
                got,
            } => {
                assert_eq!(context, "indexed_address");
                assert!(
                    got > expected,
                    "expected got>expected (trailing bytes), got expected={expected} got={got}"
                );
            }
            other => panic!("expected DbRowLength, got {other:?}"),
        }
    }

    #[test]
    fn read_address_in_rejects_single_trailing_byte() {
        // Tightest variant: even ONE extra byte must be rejected. Pins
        // that the EOF check is `!is_empty()`, not a tolerance for slack.
        let (store, _tmp) = open_store();
        let tree_hash = d(0xBC);
        let rec = IndexedAddress::empty(tree_hash);

        let mut w = VlqWriter::new();
        write_indexed_address(&mut w, &rec);
        let mut bytes = w.result();
        bytes.push(0x00);

        let write_txn = store.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(INDEXED_ADDRESS).unwrap();
            table
                .insert(tree_hash.as_bytes().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        store
            .read_address(&tree_hash)
            .expect_err("single trailing 0x00 must be rejected");
    }

    #[test]
    fn write_address_overwrites_existing_row() {
        // The apply path will replace the parent record on every block
        // that touches the address — confirm `insert` is upsert-style.
        let (store, _tmp) = open_store();
        let tree_hash = d(0xEE);

        let v1 = IndexedAddress {
            tree_hash,
            balance: Some(BalanceInfo {
                nano_ergs: 100,
                tokens: vec![],
            }),
            segment: Segment::empty(),
        };
        let v2 = IndexedAddress {
            tree_hash,
            balance: Some(BalanceInfo {
                nano_ergs: 200,
                tokens: vec![(d(0x01), 50)],
            }),
            segment: Segment {
                txs: vec![5],
                boxes: vec![],
                box_segment_count: 0,
                tx_segment_count: 0,
            },
        };

        let write_txn = store.begin_write().unwrap();
        write_address(&write_txn, &tree_hash, &v1).unwrap();
        write_txn.commit().unwrap();
        let write_txn = store.begin_write().unwrap();
        write_address(&write_txn, &tree_hash, &v2).unwrap();
        write_txn.commit().unwrap();

        assert_eq!(store.read_address(&tree_hash).unwrap().unwrap(), v2);
    }
}

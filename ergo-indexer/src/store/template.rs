//! `INDEXED_TEMPLATE` table I/O. One redb row per `template_hash`
//! carrying the serialized `IndexedTemplate` parent record. Spill
//! segments under the same parent live under `SEGMENTS` (see
//! `store::segment`), keyed by `box_segment_id`.
//!
//! Templates carry only a box-segment — no `BalanceInfo` and no
//! tx-segment, so this module is leaner than `store::address`.

use redb::ReadTransaction;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;

use crate::error::{IndexerError, SpillParentKind};
use crate::segment::SEGMENT_THRESHOLD;
use crate::segment_id::box_segment_id;
use crate::store::segment::read_spill_in;
use crate::store::tables::INDEXED_TEMPLATE;
use crate::template::{read_indexed_template, IndexedTemplate};

pub(crate) fn read_template_in(
    read_txn: &ReadTransaction,
    template_hash: &Digest32,
) -> Result<Option<IndexedTemplate>, IndexerError> {
    let table = read_txn.open_table(INDEXED_TEMPLATE)?;
    let Some(guard) = table.get(template_hash.as_bytes().as_slice())? else {
        return Ok(None);
    };
    let bytes = guard.value();
    let total = bytes.len();
    let mut r = VlqReader::new(bytes);
    let rec = read_indexed_template(&mut r).map_err(|source| IndexerError::DbDecode {
        context: "indexed_template",
        source,
    })?;
    if !r.is_empty() {
        return Err(IndexerError::DbRowLength {
            context: "indexed_template",
            expected: total - r.remaining(),
            got: total,
        });
    }
    Ok(Some(rec))
}

/// Concatenate every box-segment entry under `template_hash` in
/// oldest-first order: `spill_0 ++ spill_1 ++ ... ++ spill_(N-1) ++
/// head.boxes`. Mirrors `address::read_address_box_entries_in` —
/// templates have no tx-segment so there is no analogous tx helper.
pub(crate) fn read_template_box_entries_in(
    read_txn: &ReadTransaction,
    template_hash: &Digest32,
) -> Result<Option<Vec<i64>>, IndexerError> {
    let Some(t) = read_template_in(read_txn, template_hash)? else {
        return Ok(None);
    };
    let count = t.segment.box_segment_count.max(0) as usize;
    let mut entries = Vec::with_capacity(count * SEGMENT_THRESHOLD + t.segment.boxes.len());
    for seg_num in 0..t.segment.box_segment_count {
        let seg_id = box_segment_id(template_hash, seg_num);
        let spill = read_spill_in(read_txn, &seg_id)?.ok_or_else(|| {
            IndexerError::SpillMissingFromParent {
                parent_id: hex::encode(template_hash.as_bytes()),
                seg_num,
                parent_kind: SpillParentKind::Template,
            }
        })?;
        entries.extend(spill.boxes);
    }
    entries.extend(t.segment.boxes);
    Ok(Some(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::Segment;
    use crate::store::IndexerStore;
    use crate::template::write_indexed_template;
    use ergo_primitives::writer::VlqWriter;
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

    #[test]
    fn raw_byte_fixture_template_roundtrip() {
        // Pin canonical wire format: encode → decode → re-encode produces
        // the same bytes. Templates have no BalanceInfo flag, so the layout
        // is `tree_hash || segment` — any drift here breaks INDEXED_TEMPLATE
        // compatibility with already-indexed databases.
        let rec = IndexedTemplate {
            template_hash: d(0x55),
            segment: Segment {
                txs: vec![], // templates conventionally keep txs empty
                boxes: vec![10, 20, -30, 40],
                box_segment_count: 1,
                tx_segment_count: 0,
            },
        };
        let mut w = VlqWriter::new();
        write_indexed_template(&mut w, &rec);
        let bytes = w.result();
        assert!(!bytes.is_empty());

        let mut r = VlqReader::new(&bytes);
        let decoded = read_indexed_template(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after read_indexed_template");
        assert_eq!(decoded, rec);

        let mut w2 = VlqWriter::new();
        write_indexed_template(&mut w2, &decoded);
        assert_eq!(
            w2.result(),
            bytes,
            "template: re-serialization is not byte-identical to original"
        );
    }

    #[test]
    fn read_template_in_rejects_trailing_garbage() {
        // EOF guard: trailing bytes on an INDEXED_TEMPLATE row must be
        // rejected — safety net for the template-flush path.
        let (store, _tmp) = open_store();
        let template_hash = d(0x66);
        let rec = IndexedTemplate::empty(template_hash);

        let mut w = VlqWriter::new();
        write_indexed_template(&mut w, &rec);
        let mut bytes = w.result();
        bytes.extend_from_slice(&[0xCA, 0xFE]); // 2 garbage bytes

        let write_txn = store.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(INDEXED_TEMPLATE).unwrap();
            table
                .insert(template_hash.as_bytes().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        let err = store.read_template(&template_hash).unwrap_err();
        assert!(
            matches!(
                err,
                IndexerError::DbRowLength {
                    context: "indexed_template",
                    ..
                }
            ),
            "expected DbRowLength for indexed_template, got: {err:?}"
        );
    }

    #[test]
    fn read_template_in_rejects_single_trailing_byte() {
        let (store, _tmp) = open_store();
        let template_hash = d(0x77);
        let rec = IndexedTemplate::empty(template_hash);

        let mut w = VlqWriter::new();
        write_indexed_template(&mut w, &rec);
        let mut bytes = w.result();
        bytes.push(0x42);

        let write_txn = store.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(INDEXED_TEMPLATE).unwrap();
            table
                .insert(template_hash.as_bytes().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        store
            .read_template(&template_hash)
            .expect_err("single trailing 0x42 must be rejected");
    }
}

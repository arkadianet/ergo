//! `INDEXED_TOKEN` table I/O. One redb row per token, keyed by
//! `token_unique_id(token_id) = blake2b256(utf8(hex(token_id)) ‖ utf8("token"))`
//! (see [`crate::segment_id::token_unique_id`]). Spill segments under
//! the same parent live under `SEGMENTS`, keyed by
//! `box_segment_id(unique_id, n)`.
//!
//! Tokens carry only a box-segment — no `BalanceInfo` and no
//! tx-segment — so this module mirrors `store::template` rather than
//! `store::address`.

use redb::ReadTransaction;

use ergo_primitives::reader::VlqReader;

use crate::error::{IndexerError, SpillParentKind};
use crate::segment::SEGMENT_THRESHOLD;
use crate::segment_id::{box_segment_id, token_unique_id};
use crate::store::segment::read_spill_in;
use crate::store::tables::INDEXED_TOKEN;
use crate::token::{read_indexed_token, IndexedToken};
use crate::TokenId;

pub(crate) fn read_token_in(
    read_txn: &ReadTransaction,
    token_id: &TokenId,
) -> Result<Option<IndexedToken>, IndexerError> {
    let table = read_txn.open_table(INDEXED_TOKEN)?;
    let key = token_unique_id(token_id);
    let Some(guard) = table.get(key.as_bytes().as_slice())? else {
        return Ok(None);
    };
    let bytes = guard.value();
    let total = bytes.len();
    let mut r = VlqReader::new(bytes);
    let rec = read_indexed_token(&mut r).map_err(|source| IndexerError::DbDecode {
        context: "indexed_token",
        source,
    })?;
    if !r.is_empty() {
        return Err(IndexerError::DbRowLength {
            context: "indexed_token",
            expected: total - r.remaining(),
            got: total,
        });
    }
    Ok(Some(rec))
}

/// Concatenate every box-segment entry under `token_id` in oldest-first
/// order: `spill_0 ++ spill_1 ++ ... ++ spill_(N-1) ++ head.boxes`.
/// Mirrors `template::read_template_box_entries_in` — tokens have no
/// tx-segment so there is no analogous tx helper.
pub(crate) fn read_token_box_entries_in(
    read_txn: &ReadTransaction,
    token_id: &TokenId,
) -> Result<Option<Vec<i64>>, IndexerError> {
    let Some(t) = read_token_in(read_txn, token_id)? else {
        return Ok(None);
    };
    let unique_id = token_unique_id(token_id);
    let count = t.segment.box_segment_count.max(0) as usize;
    let mut entries = Vec::with_capacity(count * SEGMENT_THRESHOLD + t.segment.boxes.len());
    for seg_num in 0..t.segment.box_segment_count {
        let seg_id = box_segment_id(&unique_id, seg_num);
        let spill = read_spill_in(read_txn, &seg_id)?.ok_or_else(|| {
            IndexerError::SpillMissingFromParent {
                parent_id: hex::encode(token_id.as_bytes()),
                seg_num,
                parent_kind: SpillParentKind::Token,
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
    use crate::token::write_indexed_token;
    use ergo_primitives::digest::Digest32;
    use ergo_primitives::writer::VlqWriter;
    use tempfile::TempDir;

    fn open_store() -> (IndexerStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("indexer.redb");
        let (store, _) = IndexerStore::open(&path).unwrap();
        (store, tmp)
    }

    fn tid(seed: u8) -> TokenId {
        TokenId::from_bytes([seed; 32])
    }

    fn d(seed: u8) -> Digest32 {
        Digest32::from_bytes([seed; 32])
    }

    #[test]
    fn raw_byte_fixture_token_roundtrip() {
        // Pin canonical wire format for INDEXED_TOKEN: the Option<...> fields
        // (creating_box_id, emission_amount, name, description, decimals)
        // each carry a 1-byte presence flag + payload-if-Some. Round-trip
        // tests both arms: Some-arm via the rec below, None-arm via the
        // empty fixture in the trailing-garbage test.
        let rec = IndexedToken {
            token_id: tid(0x77),
            creating_box_id: Some(d(0x88)),
            emission_amount: Some(1_000_000),
            name: Some("TEST".to_string()),
            description: Some("a test token".to_string()),
            decimals: Some(2),
            segment: Segment {
                txs: vec![], // tokens conventionally keep txs empty
                boxes: vec![5, -10, 15],
                box_segment_count: 0,
                tx_segment_count: 0,
            },
        };
        let mut w = VlqWriter::new();
        write_indexed_token(&mut w, &rec);
        let bytes = w.result();
        assert!(!bytes.is_empty());

        let mut r = VlqReader::new(&bytes);
        let decoded = read_indexed_token(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after read_indexed_token");
        assert_eq!(decoded, rec);

        let mut w2 = VlqWriter::new();
        write_indexed_token(&mut w2, &decoded);
        assert_eq!(
            w2.result(),
            bytes,
            "token: re-serialization is not byte-identical to original"
        );
    }

    #[test]
    fn raw_byte_fixture_token_all_options_none() {
        // Tokens get persisted with `IndexedToken::from_box` (all Some) in
        // production, but the wire format also supports all-None (the
        // `empty()` placeholder). Pin that this shape round-trips too —
        // catches a future writer that conflates None vs Some(empty).
        let rec = IndexedToken::empty(tid(0xAB));

        let mut w = VlqWriter::new();
        write_indexed_token(&mut w, &rec);
        let bytes = w.result();

        let mut r = VlqReader::new(&bytes);
        let decoded = read_indexed_token(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after read_indexed_token");
        assert_eq!(decoded, rec);
    }

    #[test]
    fn read_token_in_rejects_trailing_garbage() {
        // EOF guard: trailing bytes on an INDEXED_TOKEN row must be
        // rejected — safety net for the token-flush path.
        let (store, _tmp) = open_store();
        let token_id = tid(0x99);
        let rec = IndexedToken::empty(token_id);

        let mut w = VlqWriter::new();
        write_indexed_token(&mut w, &rec);
        let mut bytes = w.result();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // 4 garbage bytes

        let key = token_unique_id(&token_id);
        let write_txn = store.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(INDEXED_TOKEN).unwrap();
            table
                .insert(key.as_bytes().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        let err = store.read_token(&token_id).unwrap_err();
        assert!(
            matches!(
                err,
                IndexerError::DbRowLength {
                    context: "indexed_token",
                    ..
                }
            ),
            "expected DbRowLength for indexed_token, got: {err:?}"
        );
    }

    #[test]
    fn read_token_in_rejects_single_trailing_byte() {
        let (store, _tmp) = open_store();
        let token_id = tid(0xBE);
        let rec = IndexedToken::empty(token_id);

        let mut w = VlqWriter::new();
        write_indexed_token(&mut w, &rec);
        let mut bytes = w.result();
        bytes.push(0x01);

        let key = token_unique_id(&token_id);
        let write_txn = store.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(INDEXED_TOKEN).unwrap();
            table
                .insert(key.as_bytes().as_slice(), bytes.as_slice())
                .unwrap();
        }
        write_txn.commit().unwrap();

        store
            .read_token(&token_id)
            .expect_err("single trailing 0x01 must be rejected");
    }
}

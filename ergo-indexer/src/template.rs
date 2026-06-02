//! `IndexedContractTemplate` parent record. Mirrors Scala
//! `IndexedContractTemplate.scala`.
//!
//! A template record is keyed by `templateHash =
//! blake2b256(tree.template)` under
//! `VersionContext.withVersions(MaxSupportedScriptVersion = 3, ...)`.
//! Like `IndexedErgoAddress`, it is one record per *template-hash*,
//! grouping every output whose tree shares that body — irrespective of
//! the constants table values. Unlike addresses, templates carry no
//! `BalanceInfo` and no transaction list: only a box-segment that
//! tracks every output spent or unspent under the template.
//!
//! Wire layout:
//! ```text
//! [serializedId (templateHash): 32 bytes raw]
//! [segment body]                              // see `crate::segment`
//! ```
//! The absence of a `BalanceInfo` Option flag is what distinguishes
//! the template body from an address body byte-for-byte; aside from
//! that single byte (and the constraint that `segment.txs` is always
//! empty in practice), the two records share their on-disk shape.

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{template_hash_from_bytes, TemplateHashError};
use redb::{ReadableTable, Table};

use crate::error::IndexerError;
use crate::segment::{read_segment, write_segment, Segment};

/// Parent record under `INDEXED_TEMPLATE`, keyed by `template_hash`.
///
/// `template_hash` is the same value used as the redb key — it is
/// also stored in the body so Scala's
/// `IndexedContractTemplate.parse` can read the 32-byte prefix back.
/// We preserve the redundancy for byte-for-byte parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedTemplate {
    pub template_hash: Digest32,
    /// Box-segment for this template. The `txs` field is unused for
    /// templates (Scala tracks only boxes here) and apply paths must
    /// keep it empty; the wire format still permits non-empty `txs`
    /// for symmetry with the `Segment` shared shape.
    pub segment: Segment,
}

impl IndexedTemplate {
    /// New empty parent record — empty segment buffers, zero spill
    /// counters. Mirrors Scala's `new IndexedContractTemplate` before
    /// the first `add`.
    pub fn empty(template_hash: Digest32) -> Self {
        Self {
            template_hash,
            segment: Segment::empty(),
        }
    }
}

/// Serialize an `IndexedContractTemplate` parent record.
pub fn write_indexed_template(w: &mut VlqWriter, t: &IndexedTemplate) {
    w.put_bytes(t.template_hash.as_bytes());
    write_segment(w, &t.segment);
}

/// Parse an `IndexedContractTemplate` parent record. Inverse of
/// [`write_indexed_template`].
pub fn read_indexed_template(r: &mut VlqReader) -> Result<IndexedTemplate, ReadError> {
    let hash_bytes = r.get_bytes(32)?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(hash_bytes);
    let template_hash = Digest32::from_bytes(hash_arr);
    let segment = read_segment(r)?;
    Ok(IndexedTemplate {
        template_hash,
        segment,
    })
}

/// Derive the template hash for a box's `ergo_tree` bytes for indexer use.
///
/// Returns:
/// - `Ok(Some(hash))` when the tree parses cleanly and the template is
///   well-defined. The indexer must record this output / input under
///   the returned `template_hash`.
/// - `Ok(None)` when the tree was wrapped by the soft-fork unparseable
///   path (`TemplateHashError::Unparseable`). The indexer must skip
///   template recording for this output rather than emit a hash that
///   would collide across all unparseable trees — Scala's
///   `IndexedContractTemplate.scala` simply throws on these, so
///   unparsed outputs are never recorded under a template.
/// - `Err(IndexerError::HashDerivation)` when the parsed tree's body
///   fails to reserialize. The same bytes already round-tripped at box
///   decode/encode, so a write failure here implies a serializer bug,
///   not row corruption.
/// - `Err(IndexerError::DbDecode)` when the bytes fail to re-parse
///   under the wrap-tracking reader. Carries the underlying
///   `ergo_primitives::reader::ReadError` — same divergence class as
///   any other row-decode mismatch.
pub(crate) fn template_hash_for_box_bytes(
    tree_bytes: &[u8],
) -> Result<Option<Digest32>, IndexerError> {
    match template_hash_from_bytes(tree_bytes) {
        Ok(arr) => Ok(Some(Digest32::from_bytes(arr))),
        Err(TemplateHashError::Unparseable) => Ok(None),
        Err(TemplateHashError::Write(source)) => Err(IndexerError::HashDerivation {
            context: "template_hash",
            source,
        }),
        Err(TemplateHashError::Parse(source)) => Err(IndexerError::DbDecode {
            context: "template_hash_tree_bytes",
            source,
        }),
    }
}

/// Lazy-load helper mirroring `apply::load_address_into_map`. On first
/// touch of `template_hash` in this block, read the persisted
/// `IndexedTemplate` (or build an empty one if absent) and stash it in
/// `map`. Returns a mutable reference for in-place segment edits.
pub(crate) fn load_template_into_map<'a>(
    template_table: &Table<&[u8], &[u8]>,
    map: &'a mut HashMap<Digest32, IndexedTemplate>,
    template_hash: Digest32,
) -> Result<&'a mut IndexedTemplate, IndexerError> {
    use std::collections::hash_map::Entry;
    match map.entry(template_hash) {
        Entry::Occupied(e) => Ok(e.into_mut()),
        Entry::Vacant(e) => {
            let loaded = match template_table.get(template_hash.as_bytes().as_slice())? {
                Some(g) => {
                    let mut r = VlqReader::new(g.value());
                    let parsed =
                        read_indexed_template(&mut r).map_err(|source| IndexerError::DbDecode {
                            context: "indexed_template",
                            source,
                        })?;
                    if !r.is_empty() {
                        return Err(IndexerError::DbRowLength {
                            context: "indexed_template",
                            expected: r.position(),
                            got: g.value().len(),
                        });
                    }
                    parsed
                }
                None => IndexedTemplate::empty(template_hash),
            };
            Ok(e.insert(loaded))
        }
    }
}

/// Flush every touched `IndexedTemplate` back to the table in a single
/// pass. Mirrors `apply::flush_addresses` — called once per block at the
/// end of the apply / rollback inner scope.
///
/// `writer` is cleared before every row via `write_then_insert`, so a
/// caller passing a long-lived shared writer cannot leak bytes from a
/// prior emit into the first row, and an early `?` from any row cannot
/// leak into the next.
pub(crate) fn flush_templates(
    template_table: &mut Table<&[u8], &[u8]>,
    writer: &mut VlqWriter,
    map: &HashMap<Digest32, IndexedTemplate>,
) -> Result<(), IndexerError> {
    for (template_hash, t) in map {
        crate::apply::write_then_insert(
            template_table,
            writer,
            template_hash.as_bytes().as_slice(),
            |w| {
                write_indexed_template(w, t);
                Ok(())
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(hex_str: &str) -> Digest32 {
        let bytes = hex::decode(hex_str).expect("valid hex");
        let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
        Digest32::from_bytes(arr)
    }

    fn roundtrip(t: &IndexedTemplate) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_indexed_template(&mut w, t);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let parsed = read_indexed_template(&mut r).unwrap();
        assert!(
            r.is_empty(),
            "leftover bytes after IndexedTemplate roundtrip"
        );
        assert_eq!(&parsed, t);
        bytes
    }

    // ----- happy path -----

    #[test]
    fn empty_template_roundtrips() {
        let t = IndexedTemplate::empty(Digest32::ZERO);
        let bytes = roundtrip(&t);
        // 32B template_hash + 4B empty Segment (no Option flag — the
        // critical structural difference from IndexedAddress) = 36B
        assert_eq!(bytes.len(), 32 + 4);
    }

    #[test]
    fn template_with_boxes_only_roundtrips() {
        let t = IndexedTemplate {
            template_hash: d("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            segment: Segment {
                txs: vec![],
                boxes: vec![10, -20, 30, -40],
                box_segment_count: 0,
                tx_segment_count: 0,
            },
        };
        roundtrip(&t);
    }

    #[test]
    fn template_with_box_spill_count_roundtrips() {
        let t = IndexedTemplate {
            template_hash: d("c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"),
            segment: Segment {
                txs: vec![],
                boxes: (0..100i64).collect(),
                box_segment_count: 3,
                tx_segment_count: 0,
            },
        };
        roundtrip(&t);
    }

    #[test]
    fn template_starts_with_hash_then_segment_body() {
        // Defensive: confirm there is NO Option flag between hash and
        // segment — the wire byte at offset 32 must be the segment's
        // first field (txs.len), not a 0x00/0x01 presence byte.
        let t = IndexedTemplate::empty(Digest32::from_bytes([0xCC; 32]));
        let mut w = VlqWriter::new();
        write_indexed_template(&mut w, &t);
        let bytes = w.result();
        assert_eq!(&bytes[..32], &[0xCC; 32], "template_hash prefix");
        // Segment::empty() serializes as four VLQ zeros (txs.len,
        // boxes.len, box_segment_count, tx_segment_count). The first
        // is at offset 32, immediately after the hash.
        assert_eq!(bytes[32], 0x00, "segment.txs.len at offset 32");
        assert_eq!(bytes.len(), 36);
    }

    #[test]
    fn template_hash_for_box_bytes_returns_some_for_parseable_emission_contract() {
        // Emission contract — well-formed v1 segregated tree.
        let hex = "101004020e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a7017300730110010204020404040004c0fd4f05808c82f5f6030580b8c9e5ae040580f882ad16040204c0944004c0f407040004000580f882ad16d19683030191a38cc7a7019683020193c2b2a57300007473017302830108cdeeac93a38cc7b2a573030001978302019683040193b1a5730493c2a7c2b2a573050093958fa3730673079973089c73097e9a730a9d99a3730b730c0599c1a7c1b2a5730d00938cc7b2a5730e0001a390c1a7730f";
        let bytes = hex::decode(hex).unwrap();
        let result = template_hash_for_box_bytes(&bytes).unwrap();
        assert!(result.is_some(), "parseable tree must yield Some(hash)");
    }

    #[test]
    fn template_hash_for_box_bytes_returns_none_for_block_1702686_unparseable() {
        // Block 1,702,686 size-flagged non-SigmaProp tree — the
        // soft-fork wrap path. Indexer must skip template recording
        // rather than emit a colliding hash.
        let hex = "092f0204a00b08cd021dde34603426402615658f1d970cfa7c7bd92ac81a8b16ee20427901040404040004020504040402";
        let bytes = hex::decode(hex).unwrap();
        let result = template_hash_for_box_bytes(&bytes).unwrap();
        assert!(
            result.is_none(),
            "unparseable soft-fork tree must yield None for skip"
        );
    }

    #[test]
    fn template_hash_for_box_bytes_returns_none_for_v4_softfork_tree() {
        // Tree header 0x0C declares v4 + has_size; current code only
        // supports v1-v3, so the bytes path must surface Unparseable
        // (mapped to None for the indexer skip contract).
        let bytes = hex::decode("0C0100").unwrap();
        let result = template_hash_for_box_bytes(&bytes).unwrap();
        assert!(result.is_none(), "v4 tree must yield None");
    }

    // ----- error paths -----

    /// The hot path reading `INDEXED_TEMPLATE` rows enforces the same
    /// trailing-bytes guard the public `store::template::read_template_in`
    /// reader uses.
    #[test]
    fn load_template_into_map_rejects_trailing_bytes() {
        use crate::segment::Segment;
        use crate::store::tables::INDEXED_TEMPLATE;
        use crate::IndexerError;
        use redb::Database;
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let db = Database::create(tmp.path().join("hotpath_tpl.redb")).unwrap();

        let template_hash = Digest32::from_bytes([0xBC; 32]);
        let mut w = VlqWriter::new();
        write_indexed_template(
            &mut w,
            &IndexedTemplate {
                template_hash,
                segment: Segment {
                    txs: vec![],
                    boxes: vec![],
                    box_segment_count: 0,
                    tx_segment_count: 0,
                },
            },
        );
        let mut corrupted = w.result();
        corrupted.extend_from_slice(&[0xFF, 0xFF, 0xFF]);

        let wtxn = db.begin_write().unwrap();
        {
            let mut table = wtxn.open_table(INDEXED_TEMPLATE).unwrap();
            table
                .insert(template_hash.as_bytes().as_slice(), corrupted.as_slice())
                .unwrap();
            let mut map = std::collections::HashMap::new();
            let result = load_template_into_map(&table, &mut map, template_hash);
            assert!(
                matches!(
                    result,
                    Err(IndexerError::DbRowLength {
                        context: "indexed_template",
                        ..
                    })
                ),
                "hot path must reject trailing bytes via DbRowLength, got {result:?}",
            );
        }
    }
}

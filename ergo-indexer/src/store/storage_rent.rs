//! `UNSPENT_BY_CREATION_HEIGHT` table I/O for the storage-rent
//! eligibility index.
//!
//! Holds only currently-unspent boxes keyed by the box's own
//! `creationHeight` field (R3-related metadata stamped at creation
//! time — *not* the block inclusion height). Apply inserts on output
//! creation and deletes on input consumption inside the same redb
//! write transaction as `INDEXED_BOX`. Rollback re-derives the (key,
//! value) tuples from the unchanged `IndexedErgoBox` rows; the
//! `INDEXER_UNDO` payload is intentionally not extended.
//!
//! Compound key `(creation_height: u32, global_box_index: i64)`: redb
//! tuple keys order lexicographically by component, so an ascending
//! range scan yields `creation_height ASC, global_box_index ASC`.
//!
//! Value layout (44 bytes, big-endian):
//! `box_id (32) || box_value (u64) || box_bytes_len (i32)`.
//! `box_value` matches `ErgoBoxCandidate::value` (`u64`).
//! `box_bytes_len` is the canonical serialized `ErgoBox` length
//! (`ergo_ser::ergo_box::serialize_ergo_box(b)?.len()`) stored as
//! `i32` so it composes directly with the i32-typed
//! `storage_fee_factor` voted parameter without re-cast. The
//! serializer always returns a non-negative length, so the on-disk
//! `i32` is in `[0, i32::MAX]`.

use redb::{Table, TableDefinition};

use crate::error::IndexerError;
use crate::BoxId;

pub(crate) const UNSPENT_BY_CREATION_HEIGHT: TableDefinition<'static, (u32, i64), &'static [u8]> =
    TableDefinition::new("unspent_by_creation_height");

/// Decoded shape of one row: `(creation_height, global_box_index,
/// box_id, box_value, box_bytes_len)`. Returned by the read API in
/// the order the spec presents the columns.
pub type StorageRentRow = (u32, i64, BoxId, u64, i32);

/// Encoded value width: 32-byte box id + 8-byte u64 value + 4-byte i32
/// serialized-bytes length.
pub(crate) const VALUE_LEN: usize = 32 + 8 + 4;

/// Encode the value column for the storage-rent eligibility table.
///
/// All multi-byte integers are big-endian for ordered hex inspection
/// in dumps; the table's natural key order does not depend on the
/// value column.
pub(crate) fn encode_value(box_id: &BoxId, box_value: u64, box_bytes_len: i32) -> [u8; VALUE_LEN] {
    let mut out = [0u8; VALUE_LEN];
    out[..32].copy_from_slice(box_id.as_bytes().as_slice());
    out[32..40].copy_from_slice(&box_value.to_be_bytes());
    out[40..44].copy_from_slice(&box_bytes_len.to_be_bytes());
    out
}

/// Decode a row value back to its three components. Off the apply
/// hot path — used by tests and the read-side scan.
pub(crate) fn decode_value(bytes: &[u8]) -> Result<(BoxId, u64, i32), IndexerError> {
    if bytes.len() != VALUE_LEN {
        return Err(IndexerError::DbRowLength {
            context: "storage_rent_value",
            expected: VALUE_LEN,
            got: bytes.len(),
        });
    }
    let mut id_arr = [0u8; 32];
    id_arr.copy_from_slice(&bytes[..32]);
    let box_id = BoxId::from_bytes(id_arr);

    let mut val_arr = [0u8; 8];
    val_arr.copy_from_slice(&bytes[32..40]);
    let box_value = u64::from_be_bytes(val_arr);

    let mut len_arr = [0u8; 4];
    len_arr.copy_from_slice(&bytes[40..44]);
    let box_bytes_len = i32::from_be_bytes(len_arr);

    Ok((box_id, box_value, box_bytes_len))
}

/// Insert an unspent-box row keyed by `(creation_height, global_box_index)`.
/// Caller is responsible for not inserting boxes that are spent in the
/// same block (apply.rs handles intra-block create-then-spend by issuing
/// the matching `remove_unspent` after this insert when the box is
/// later consumed in a subsequent transaction of the same block).
pub(crate) fn insert_unspent(
    table: &mut Table<(u32, i64), &'static [u8]>,
    creation_height: u32,
    global_box_index: i64,
    box_id: &BoxId,
    box_value: u64,
    box_bytes_len: i32,
) -> Result<(), IndexerError> {
    let value = encode_value(box_id, box_value, box_bytes_len);
    table.insert((creation_height, global_box_index), value.as_slice())?;
    Ok(())
}

/// Delete the unspent-box row for a box being consumed. Returns
/// `IndexerError::StorageRentDesync` if the key is unexpectedly missing
/// — that signals a desync between `INDEXED_BOX` and the storage-rent
/// index, which is a bug rather than a silent no-op.
pub(crate) fn remove_unspent(
    table: &mut Table<(u32, i64), &'static [u8]>,
    creation_height: u32,
    global_box_index: i64,
) -> Result<(), IndexerError> {
    let removed = table.remove((creation_height, global_box_index))?;
    if removed.is_none() {
        return Err(IndexerError::StorageRentDesync {
            creation_height,
            global_box_index,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;

    fn id(seed: u8) -> BoxId {
        Digest32::from_bytes([seed; 32])
    }

    #[test]
    fn value_roundtrip_44_bytes() {
        let box_id = id(0xAB);
        let bytes = encode_value(&box_id, 1_000_000_000, 76);
        assert_eq!(bytes.len(), VALUE_LEN);
        let (decoded_id, decoded_value, decoded_len) = decode_value(&bytes).unwrap();
        assert_eq!(decoded_id, box_id);
        assert_eq!(decoded_value, 1_000_000_000);
        assert_eq!(decoded_len, 76);
    }

    #[test]
    fn value_roundtrip_negative_box_bytes_len_is_rejected_by_serializer_only() {
        // The serializer never produces a negative length, but the
        // on-disk i32 representation roundtrips negatives faithfully —
        // we don't want a defensive clamp in encode/decode that masks
        // serializer bugs.
        let box_id = id(0x01);
        let bytes = encode_value(&box_id, 0, -1);
        let (_, _, decoded_len) = decode_value(&bytes).unwrap();
        assert_eq!(decoded_len, -1);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let short = vec![0u8; VALUE_LEN - 1];
        assert!(decode_value(&short).is_err());
        let long = vec![0u8; VALUE_LEN + 1];
        assert!(decode_value(&long).is_err());
    }
}

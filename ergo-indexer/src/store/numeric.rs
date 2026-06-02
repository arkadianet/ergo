//! `NUMERIC_TX` and `NUMERIC_BOX` table I/O — global-index → id maps
//! used by `tx_by_global_index` / `box_by_global_index` and by
//! segment lookups that resolve `abs(globalIndex)` back to a 32-byte
//! id.
//!
//! The box record's `global_index` is **always non-negative** (the
//! spent-flag uses segment-side sign, not the box record's sign —
//! the first-indexed output, i.e. genesis, gets `0`). We therefore
//! key these tables by `u64` (8-byte big-endian — natural redb sort
//! order matches numerical order). Scala's keys are
//! `blake2b256(utf8("...")…)` derivations; those are the
//! external/observable identifiers and only matter when speaking the
//! Scala wire-key protocol. Inside our redb file we use the integer
//! directly because (a) redb is a separate file and (b) the
//! `IndexerQuery` reader takes `u64`, not a hash.

use redb::ReadTransaction;

use crate::error::IndexerError;
use crate::store::tables::{NUMERIC_BOX, NUMERIC_TX};
use crate::{BoxId, TxId};
use ergo_primitives::digest::Digest32;

fn key_bytes(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

pub(crate) fn read_numeric_box_in(
    read_txn: &ReadTransaction,
    n: u64,
) -> Result<Option<BoxId>, IndexerError> {
    let table = read_txn.open_table(NUMERIC_BOX)?;
    let key = key_bytes(n);
    let Some(guard) = table.get(key.as_slice())? else {
        return Ok(None);
    };
    decode_id(guard.value()).map(Some)
}

pub(crate) fn read_numeric_tx_in(
    read_txn: &ReadTransaction,
    n: u64,
) -> Result<Option<TxId>, IndexerError> {
    let table = read_txn.open_table(NUMERIC_TX)?;
    let key = key_bytes(n);
    let Some(guard) = table.get(key.as_slice())? else {
        return Ok(None);
    };
    decode_id(guard.value()).map(Some)
}

fn decode_id(bytes: &[u8]) -> Result<Digest32, IndexerError> {
    if bytes.len() != 32 {
        return Err(IndexerError::DbRowLength {
            context: "numeric_id",
            expected: 32,
            got: bytes.len(),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(Digest32::from_bytes(arr))
}

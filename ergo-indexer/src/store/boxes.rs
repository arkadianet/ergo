//! `INDEXED_BOX` table I/O. One redb row per `BoxId` carrying the
//! serialized `IndexedErgoBox`.
//!
//! Apply path writes `INDEXED_BOX` rows directly via the redb table
//! API in `apply.rs`; this module only exposes the read path.

use redb::ReadTransaction;

use crate::error::IndexerError;
use crate::ser::boxes::deserialize_indexed_box;
use crate::store::tables::INDEXED_BOX;
use crate::BoxId;
use ergo_indexer_types::IndexedErgoBox;

pub(crate) fn read_box_in(
    read_txn: &ReadTransaction,
    box_id: &BoxId,
) -> Result<Option<IndexedErgoBox>, IndexerError> {
    let table = read_txn.open_table(INDEXED_BOX)?;
    let Some(guard) = table.get(box_id.as_bytes().as_slice())? else {
        return Ok(None);
    };
    let rec = deserialize_indexed_box(guard.value()).map_err(|e| IndexerError::DbDecode {
        context: "indexed_box",
        source: e,
    })?;
    Ok(Some(rec))
}

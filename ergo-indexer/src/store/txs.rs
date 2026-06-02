//! `INDEXED_TX` table I/O. One redb row per `TxId` carrying the
//! serialized `IndexedErgoTransaction`.
//!
//! Apply path writes `INDEXED_TX` rows directly via the redb table
//! API in `apply.rs`; this module only exposes the read path.

use redb::ReadTransaction;

use crate::error::IndexerError;
use crate::ser::txs::deserialize_indexed_tx;
use crate::store::tables::INDEXED_TX;
use crate::TxId;
use ergo_indexer_types::IndexedErgoTransaction;

pub(crate) fn read_tx_in(
    read_txn: &ReadTransaction,
    tx_id: &TxId,
) -> Result<Option<IndexedErgoTransaction>, IndexerError> {
    let table = read_txn.open_table(INDEXED_TX)?;
    let Some(guard) = table.get(tx_id.as_bytes().as_slice())? else {
        return Ok(None);
    };
    let rec = deserialize_indexed_tx(guard.value()).map_err(|e| IndexerError::DbDecode {
        context: "indexed_tx",
        source: e,
    })?;
    Ok(Some(rec))
}

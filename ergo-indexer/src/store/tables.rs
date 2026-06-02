//! redb table definitions for the indexer.
//!
//! Every table is declared here so the schema-version check on open
//! catches a missing table as `DbCorruption`. Per-table read/write
//! helpers live in the sibling modules.

use redb::TableDefinition;

pub(crate) const INDEXED_BOX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("indexed_box");
pub(crate) const INDEXED_TX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("indexed_tx");
pub(crate) const INDEXED_ADDRESS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("indexed_address");
pub(crate) const INDEXED_TEMPLATE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("indexed_template");
pub(crate) const INDEXED_TOKEN: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("indexed_token");

pub(crate) const NUMERIC_BOX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("numeric_box");
pub(crate) const NUMERIC_TX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("numeric_tx");

pub(crate) const SEGMENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("segments");

pub(crate) const INDEXER_META: TableDefinition<&str, &[u8]> = TableDefinition::new("indexer_meta");
pub(crate) const INDEXER_UNDO: TableDefinition<u64, &[u8]> = TableDefinition::new("indexer_undo");

/// All tables created on a fresh DB. Used by the wipe/resume path in
/// `IndexerStore::open` to ensure schema parity — opening a DB whose
/// schema_version matches but is missing one of these is treated as
/// `DbCorruption`.
pub(crate) fn create_all(write_txn: &redb::WriteTransaction) -> Result<(), Box<redb::Error>> {
    write_txn
        .open_table(INDEXED_BOX)
        .map_err(|e| Box::new(e.into()))?;
    write_txn
        .open_table(INDEXED_TX)
        .map_err(|e| Box::new(e.into()))?;
    write_txn
        .open_table(INDEXED_ADDRESS)
        .map_err(|e| Box::new(e.into()))?;
    write_txn
        .open_table(INDEXED_TEMPLATE)
        .map_err(|e| Box::new(e.into()))?;
    write_txn
        .open_table(INDEXED_TOKEN)
        .map_err(|e| Box::new(e.into()))?;
    write_txn
        .open_table(NUMERIC_BOX)
        .map_err(|e| Box::new(e.into()))?;
    write_txn
        .open_table(NUMERIC_TX)
        .map_err(|e| Box::new(e.into()))?;
    write_txn
        .open_table(SEGMENTS)
        .map_err(|e| Box::new(e.into()))?;
    write_txn
        .open_table(INDEXER_META)
        .map_err(|e| Box::new(e.into()))?;
    write_txn
        .open_table(INDEXER_UNDO)
        .map_err(|e| Box::new(e.into()))?;
    Ok(())
}

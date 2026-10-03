//! Production [`IndexerChainSource`] adapter, wiring the indexer's
//! polling task against the real chain redb via [`ChainStoreReader`].
//!
//! Missing tip/header/sections retain normal genesis/race/retry behavior.
//! Read and decode failures remain typed errors and halt the indexer; they
//! cannot be reported as an empty chain or a healthy caught-up index.

use std::sync::Arc;

use ergo_indexer::{ChainTip, HeaderId, IndexerChainSource, IndexerError, IndexerFullBlock};
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_stored_block_transactions;
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_state::reader::ChainStoreReader;

/// Adapter implementing [`IndexerChainSource`] over a [`ChainStoreReader`].
///
/// `Arc<Self>` is the form `IndexerTask` consumes (the task wants a
/// single shared chain handle for the lifetime of the polling loop).
/// Cloning is cheap — `ChainStoreReader` is itself `Arc`-shared.
pub struct ChainReaderAdapter {
    reader: ChainStoreReader,
}

impl ChainReaderAdapter {
    pub fn new(reader: ChainStoreReader) -> Arc<Self> {
        Arc::new(Self { reader })
    }
}

fn source_error(
    operation: &'static str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> IndexerError {
    IndexerError::ChainRead {
        operation,
        source: Box::new(source),
    }
}

impl IndexerChainSource for ChainReaderAdapter {
    fn committed_tip(&self) -> Result<ChainTip, IndexerError> {
        // Only an actual absent committed tip represents pre-genesis.
        let tip = self
            .reader
            .committed_tip()
            .map_err(|e| source_error("committed tip", e))?;
        Ok(match tip {
            Some((height, header_id)) => ChainTip {
                height,
                header_id: Digest32::from_bytes(header_id),
            },
            None => ChainTip {
                height: 0,
                header_id: Digest32::ZERO,
            },
        })
    }

    fn header_id_at(&self, height: u32) -> Result<Option<HeaderId>, IndexerError> {
        self.reader
            .get_header_id_at_height(height)
            .map(|id| id.map(Digest32::from_bytes))
            .map_err(|e| source_error("canonical header ID", e))
    }

    fn full_block(&self, header_id: &HeaderId) -> Result<Option<IndexerFullBlock>, IndexerError> {
        let Some(header_bytes) = self
            .reader
            .get_header(header_id.as_bytes())
            .map_err(|e| source_error("header bytes", e))?
        else {
            return Ok(None);
        };
        let mut reader = VlqReader::new(&header_bytes);
        let header = read_header(&mut reader).map_err(|e| source_error("header decode", e))?;
        if !reader.is_empty() {
            return Err(source_error(
                "header decode",
                ergo_primitives::reader::ReadError::InvalidData(
                    "stored chain header has trailing bytes".into(),
                ),
            ));
        }
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            header_id.as_bytes(),
            header.transactions_root.as_bytes(),
        );
        let Some(section_bytes) = self
            .reader
            .get_block_section(&section_id)
            .map_err(|e| source_error("transaction section bytes", e))?
        else {
            return Ok(None);
        };
        let block_txs = read_stored_block_transactions(&section_bytes)
            .map_err(|e| source_error("transaction section decode", e))?;
        let height = i32::try_from(header.height).map_err(|_| IndexerError::CounterRange {
            field: "chain block height",
        })?;
        Ok(Some(IndexerFullBlock {
            height,
            header_id: *header_id,
            transactions: block_txs.transactions,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_distinguishes_absence_from_native_table_read_failure() {
        for table in ["chain_state_meta", "header_chain_index", "headers"] {
            let directory = tempfile::tempdir().unwrap();
            let db = Arc::new(redb::Database::create(directory.path().join("chain.redb")).unwrap());
            let adapter = ChainReaderAdapter::new(ChainStoreReader::new_from_db(db.clone()));
            assert_eq!(adapter.committed_tip().unwrap().height, 0);
            assert!(adapter.header_id_at(1).unwrap().is_none());
            assert!(adapter.full_block(&Digest32::ZERO).unwrap().is_none());
            let write = db.begin_write().unwrap();
            write
                .open_table(redb::TableDefinition::<u32, u32>::new(table))
                .unwrap();
            write.commit().unwrap();
            let error = match table {
                "chain_state_meta" => adapter.committed_tip().unwrap_err(),
                "header_chain_index" => adapter.header_id_at(1).unwrap_err(),
                _ => adapter.full_block(&Digest32::ZERO).unwrap_err(),
            };
            assert!(matches!(error, IndexerError::ChainRead { .. }));
            assert!(std::error::Error::source(&error).is_some());
        }
    }

    #[test]
    fn adapter_keeps_stored_header_decode_failure_distinct_from_missing_section() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(directory.path().join("chain.redb")).unwrap());
        let write = db.begin_write().unwrap();
        write
            .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("headers"))
            .unwrap()
            .insert(Digest32::ZERO.as_bytes().as_slice(), &[0u8][..])
            .unwrap();
        write.commit().unwrap();
        let adapter = ChainReaderAdapter::new(ChainStoreReader::new_from_db(db));
        assert!(matches!(
            adapter.full_block(&Digest32::ZERO),
            Err(IndexerError::ChainRead {
                operation: "header decode",
                ..
            })
        ));
    }
}

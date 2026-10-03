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

    // Header-only fork choice does not establish validated transaction bodies.
    // CHAIN_INDEX moves only with fully applied State, including rollback.
    fn header_id_at(&self, height: u32) -> Result<Option<HeaderId>, IndexerError> {
        self.reader
            .get_applied_header_id_at_height(height)
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
        for table in ["chain_state_meta", "chain_index", "headers"] {
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
                "chain_index" => adapter.header_id_at(1).unwrap_err(),
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

    /// Native read-table fixture isolates the indexer's branch ownership. These
    /// synthetic headers/transactions are not a consensus acceptance oracle.
    #[test]
    fn native_catchup_uses_applied_branch_through_header_fork_and_state_reorg() {
        use ergo_indexer::{
            apply_block, IndexerBlock, IndexerHandle, IndexerMeta, IndexerPoll, IndexerStore,
            IndexerTask,
        };
        use ergo_primitives::digest::ADDigest;
        use ergo_primitives::group_element::GroupElement;
        use ergo_primitives::writer::VlqWriter;
        use ergo_ser::autolykos::AutolykosSolution;
        use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
        use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
        use ergo_ser::ergo_tree::read_ergo_tree;
        use ergo_ser::header::{serialize_header, Header};
        use ergo_ser::input::{ContextExtension, Input, SpendingProof};
        use ergo_ser::register::AdditionalRegisters;
        use ergo_ser::transaction::{transaction_id, Transaction};
        use ergo_state::chain::{ChainStateMeta, HeaderAvailability};

        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(directory.path().join("chain.redb")).unwrap());
        let native = ChainStoreReader::new_from_db(db.clone());
        let common_id = Digest32::from_bytes([1; 32]);
        let old_tip = Digest32::from_bytes([3; 32]);
        let tree_bytes = hex::decode("1000d10101").unwrap();
        let tree = read_ergo_tree(&mut VlqReader::new(&tree_bytes)).unwrap();
        let candidate = |height| {
            ErgoBoxCandidate::new(
                1000,
                tree.clone(),
                height,
                vec![],
                AdditionalRegisters::empty(),
            )
            .unwrap()
        };
        let common = Transaction {
            inputs: vec![],
            data_inputs: vec![],
            output_candidates: vec![candidate(1)],
        };
        let common_box = ErgoBox {
            candidate: common.output_candidates[0].clone(),
            transaction_id: transaction_id(&common).unwrap(),
            index: 0,
        }
        .box_id()
        .unwrap();
        let child = Transaction {
            inputs: vec![Input {
                box_id: common_box,
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![candidate(2)],
        };
        let header = |height, parent_id| Header {
            version: 2,
            parent_id,
            ad_proofs_root: Digest32::ZERO,
            transactions_root: Digest32::ZERO,
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: u64::from(height),
            extension_root: Digest32::ZERO,
            n_bits: 0,
            height,
            votes: [0; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0; 33]),
                nonce: [0; 8],
            },
        };
        let (child_bytes, child_id) = serialize_header(&header(2, common_id.into())).unwrap();
        let mut old_child_header = header(2, common_id.into());
        old_child_header.timestamp = 20;
        let (old_child_bytes, old_child_id) = serialize_header(&old_child_header).unwrap();
        let old_child_id = *old_child_id.as_digest();
        let (_, new_tip) = serialize_header(&header(3, child_id)).unwrap();
        let child_id = *child_id.as_digest();
        let new_tip = *new_tip.as_digest();
        let mut writer = VlqWriter::new();
        write_block_transactions(
            &mut writer,
            &BlockTransactions {
                header_id: child_id.into(),
                transactions: vec![child.clone()],
            },
        )
        .unwrap();
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            child_id.as_bytes(),
            Digest32::ZERO.as_bytes(),
        );
        let mut chain_meta = ChainStateMeta {
            best_header_id: *new_tip.as_bytes(),
            best_header_height: 3,
            best_header_score: vec![3],
            best_full_block_id: *old_tip.as_bytes(),
            best_full_block_height: 3,
            header_availability: HeaderAvailability::Dense,
        };
        let write = db.begin_write().unwrap();
        {
            let mut headers = write
                .open_table(redb::TableDefinition::<u64, &[u8]>::new(
                    "header_chain_index",
                ))
                .unwrap();
            for (height, id) in [(1, common_id), (2, child_id), (3, new_tip)] {
                headers.insert(height, id.as_bytes().as_slice()).unwrap();
            }
            let mut applied = write
                .open_table(redb::TableDefinition::<u64, &[u8]>::new("chain_index"))
                .unwrap();
            applied.insert(1, common_id.as_bytes().as_slice()).unwrap();
            applied
                .insert(2, old_child_id.as_bytes().as_slice())
                .unwrap();
            applied.insert(3, old_tip.as_bytes().as_slice()).unwrap();
            write
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                    "chain_state_meta",
                ))
                .unwrap()
                .insert("chain_state", chain_meta.serialize().as_slice())
                .unwrap();
            write
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("headers"))
                .unwrap()
                .insert(child_id.as_bytes().as_slice(), child_bytes.as_slice())
                .unwrap();
            write
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("block_sections"))
                .unwrap()
                .insert(section_id.as_slice(), writer.as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        assert_eq!(
            native.get_applied_header_id_at_height(3).unwrap(),
            Some(*old_tip.as_bytes())
        );
        let (store, _) = IndexerStore::open(&directory.path().join("indexer.redb")).unwrap();
        let before = apply_block(
            &store,
            &IndexerMeta::empty(),
            &IndexerBlock {
                height: 1,
                header_id: common_id,
                transactions: &[common],
            },
        )
        .unwrap();
        let handle = IndexerHandle::with_store(store, 1);
        let store = handle.store().unwrap();
        let mut task = IndexerTask::new(handle, ChainReaderAdapter::new(native.clone()));
        assert!(matches!(
            task.step_batch(),
            IndexerPoll::SectionRetry { .. }
        ));
        assert_eq!(store.read_meta().unwrap(), before);
        assert!(store.read_undo(2).unwrap().is_none());
        assert!(store.read_numeric_box(1).unwrap().is_none());
        assert!(!store.read_box(&common_box).unwrap().unwrap().is_spent());
        // A header-only fork must not block indexing bodies already applied
        // on the old State branch. Supply that branch's previously absent body.
        writer.clear();
        write_block_transactions(
            &mut writer,
            &BlockTransactions {
                header_id: old_child_id.into(),
                transactions: vec![child],
            },
        )
        .unwrap();
        let old_section = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            old_child_id.as_bytes(),
            Digest32::ZERO.as_bytes(),
        );
        let write = db.begin_write().unwrap();
        {
            write
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("headers"))
                .unwrap()
                .insert(
                    old_child_id.as_bytes().as_slice(),
                    old_child_bytes.as_slice(),
                )
                .unwrap();
            write
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("block_sections"))
                .unwrap()
                .insert(old_section.as_slice(), writer.as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        assert!(matches!(task.step(), IndexerPoll::Applied(2)));
        assert_eq!(
            store.read_meta().unwrap().indexed_header_id,
            Some(old_child_id)
        );

        // Emulate the State commit that makes the winning branch fully applied.
        chain_meta.best_full_block_id = *new_tip.as_bytes();
        let write = db.begin_write().unwrap();
        {
            write
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                    "chain_state_meta",
                ))
                .unwrap()
                .insert("chain_state", chain_meta.serialize().as_slice())
                .unwrap();
            let mut applied = write
                .open_table(redb::TableDefinition::<u64, &[u8]>::new("chain_index"))
                .unwrap();
            applied.insert(2, child_id.as_bytes().as_slice()).unwrap();
            applied.insert(3, new_tip.as_bytes().as_slice()).unwrap();
        }
        write.commit().unwrap();
        assert_eq!(
            native.get_applied_header_id_at_height(3).unwrap(),
            Some(*new_tip.as_bytes())
        );
        assert!(matches!(task.step(), IndexerPoll::RolledBack(2)));
        assert!(!store.read_box(&common_box).unwrap().unwrap().is_spent());
        assert!(matches!(task.step(), IndexerPoll::Applied(2)));
        assert_eq!(store.read_meta().unwrap().indexed_header_id, Some(child_id));
        assert!(store.read_box(&common_box).unwrap().unwrap().is_spent());
    }
}

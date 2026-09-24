use std::sync::Arc;

use async_trait::async_trait;
use ergo_api_core::error::ServiceResult;
use ergo_api_core::id::TxId;
use ergo_api_core::transaction::{TransactionReader, TransactionRecord, TransactionState};
use ergo_indexer::IndexerQuery;
use ergo_primitives::digest::Digest32;

use crate::snapshot::SnapshotHandle;

pub struct CoreTransactionReader {
    snapshot: SnapshotHandle,
    indexer: Option<Arc<dyn IndexerQuery>>,
}

impl CoreTransactionReader {
    pub fn new(snapshot: SnapshotHandle, indexer: Option<Arc<dyn IndexerQuery>>) -> Self {
        Self { snapshot, indexer }
    }
}

#[async_trait]
impl TransactionReader for CoreTransactionReader {
    async fn get(&self, id: TxId) -> ServiceResult<Option<TransactionRecord>> {
        let digest = Digest32::from_bytes(id.into_bytes());
        if let Some(indexer) = &self.indexer {
            if let Some(transaction) = indexer.tx_by_id(&digest) {
                let height = u32::try_from(transaction.height).ok();
                let confirmations = height.map(|height| {
                    indexer
                        .indexed_height()
                        .saturating_sub(u64::from(height))
                        .min(u64::from(u32::MAX)) as u32
                });
                return Ok(Some(TransactionRecord {
                    id,
                    state: TransactionState::Confirmed,
                    inclusion_height: height,
                    index_in_block: u32::try_from(transaction.index_in_block).ok(),
                    size_bytes: u32::try_from(transaction.size).unwrap_or(u32::MAX),
                    confirmations,
                }));
            }
        }
        let snapshot = self.snapshot.load();
        let id_hex = id.to_string();
        let pending = snapshot
            .mempool_transactions
            .transactions
            .iter()
            .find(|transaction| transaction.tx_id.eq_ignore_ascii_case(&id_hex));
        if let Some(transaction) = pending {
            return Ok(Some(TransactionRecord {
                id,
                state: TransactionState::Pending,
                inclusion_height: None,
                index_in_block: None,
                size_bytes: transaction.size_bytes,
                confirmations: None,
            }));
        }
        Ok(None)
    }
}

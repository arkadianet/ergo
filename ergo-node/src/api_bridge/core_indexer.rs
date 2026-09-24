use std::sync::Arc;

use ergo_api_core::indexer::{
    IndexerRepair, IndexerStatus, IndexerStatusSnapshot, IndexerStatusSource, IndexerTotals,
};
use ergo_indexer::{IndexerQuery, IndexerStatus as LegacyIndexerStatus};

pub struct IndexerStatusAdapter {
    indexer: Arc<dyn IndexerQuery>,
}

impl IndexerStatusAdapter {
    pub fn new(indexer: Arc<dyn IndexerQuery>) -> Self {
        Self { indexer }
    }
}

impl IndexerStatusSource for IndexerStatusAdapter {
    fn snapshot(&self) -> IndexerStatusSnapshot {
        let status = self.indexer.status();
        let health = self.indexer.health();
        let (status, halt_reason) = match status {
            LegacyIndexerStatus::Syncing => (IndexerStatus::Syncing, None),
            LegacyIndexerStatus::CaughtUp => (IndexerStatus::CaughtUp, None),
            LegacyIndexerStatus::Halted(reason) => (
                IndexerStatus::Halted,
                Some(reason.as_kebab_case().to_string()),
            ),
        };
        IndexerStatusSnapshot {
            status,
            halt_reason,
            indexed_height: self.indexer.indexed_height(),
            repair: IndexerRepair {
                pending: health.repair_pending,
                next_gi: health.repair_next_gi,
                skipped: health.repair_skipped,
                drift_skips: health.drift_skips,
            },
            totals: IndexerTotals {
                boxes: health.global_boxes,
                txs: health.global_txs,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_indexer::{
        BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerHaltReason,
        IndexerHealthDto, Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
    };

    struct StubIndexer {
        status: LegacyIndexerStatus,
        indexed_height: u64,
        health: IndexerHealthDto,
    }

    impl IndexerQuery for StubIndexer {
        fn indexed_height(&self) -> u64 {
            self.indexed_height
        }

        fn status(&self) -> LegacyIndexerStatus {
            self.status.clone()
        }

        fn health(&self) -> IndexerHealthDto {
            self.health.clone()
        }

        fn box_by_id(&self, _: &BoxId) -> Option<IndexedBoxDto> {
            unreachable!()
        }

        fn box_by_global_index(&self, _: u64) -> Option<IndexedBoxDto> {
            unreachable!()
        }

        fn boxes_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedBoxDto> {
            unreachable!()
        }

        fn tx_by_id(&self, _: &TxId) -> Option<IndexedTxDto> {
            unreachable!()
        }

        fn tx_by_global_index(&self, _: u64) -> Option<IndexedTxDto> {
            unreachable!()
        }

        fn txs_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedTxDto> {
            unreachable!()
        }

        fn address_balance(&self, _: &TreeHash) -> Option<BalanceDto> {
            unreachable!()
        }

        fn address_txs_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedTxDto> {
            unreachable!()
        }

        fn address_boxes_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
            unreachable!()
        }

        fn address_unspent_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
            unreachable!()
        }

        fn address_total_txs(&self, _: &TreeHash) -> u64 {
            unreachable!()
        }

        fn address_total_boxes(&self, _: &TreeHash) -> u64 {
            unreachable!()
        }

        fn template_boxes_paged(&self, _: &TemplateHash, _: Page) -> Vec<IndexedBoxDto> {
            unreachable!()
        }

        fn template_unspent_paged(
            &self,
            _: &TemplateHash,
            _: Page,
            _: SortDir,
        ) -> Vec<IndexedBoxDto> {
            unreachable!()
        }

        fn template_total_boxes(&self, _: &TemplateHash) -> u64 {
            unreachable!()
        }

        fn token_by_id(&self, _: &TokenId) -> Option<IndexedTokenDto> {
            unreachable!()
        }

        fn tokens_by_ids(&self, _: &[TokenId]) -> Vec<IndexedTokenDto> {
            unreachable!()
        }

        fn token_boxes_paged(&self, _: &TokenId, _: Page) -> Vec<IndexedBoxDto> {
            unreachable!()
        }

        fn token_unspent_paged(&self, _: &TokenId, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
            unreachable!()
        }

        fn token_total_boxes(&self, _: &TokenId) -> u64 {
            unreachable!()
        }
    }

    #[test]
    fn maps_status_health_and_totals() {
        let source = Arc::new(StubIndexer {
            status: LegacyIndexerStatus::CaughtUp,
            indexed_height: 42,
            health: IndexerHealthDto {
                repair_pending: true,
                repair_next_gi: Some(7),
                repair_skipped: 3,
                drift_skips: 5,
                global_boxes: 11,
                global_txs: 13,
            },
        });
        let snapshot = IndexerStatusAdapter::new(source).snapshot();
        assert_eq!(
            snapshot,
            IndexerStatusSnapshot {
                status: IndexerStatus::CaughtUp,
                halt_reason: None,
                indexed_height: 42,
                repair: IndexerRepair {
                    pending: true,
                    next_gi: Some(7),
                    skipped: 3,
                    drift_skips: 5,
                },
                totals: IndexerTotals { boxes: 11, txs: 13 },
            }
        );
    }

    #[test]
    fn maps_halt_reason() {
        let source = Arc::new(StubIndexer {
            status: LegacyIndexerStatus::Halted(IndexerHaltReason::DbCorruption),
            indexed_height: 9,
            health: IndexerHealthDto::default(),
        });
        let snapshot = IndexerStatusAdapter::new(source).snapshot();
        assert_eq!(snapshot.status, IndexerStatus::Halted);
        assert_eq!(snapshot.halt_reason.as_deref(), Some("db-corruption"));
        assert_eq!(snapshot.indexed_height, 9);
    }
}

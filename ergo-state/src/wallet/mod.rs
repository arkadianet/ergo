pub mod apply;
pub mod error;
pub mod hydration;
pub mod maturity;
pub mod mining_jobs;
pub mod reader;
pub mod scan;
pub mod store;
pub mod tables;
pub mod types;
pub mod utxo_scan;

pub use ergo_wallet_service::state::HydrationSource;
pub use ergo_wallet_service::wallet::{
    owned_to_block_txs, Balance, BlockOutput, BlockTx, BoundBlockTxs, BoxProvenance, BoxStatus,
    OwnedBlockOutput, OwnedBlockTxData, RedbWalletStore, RedbWalletWrite, RescanGuard,
    RescanReadError, RescanState, RewardKeyResolution, ScanBoxStatus, ScanMatchRecord,
    ScanRegistrySnapshot, ScanRescanMatcher, ScanTrackedBox, ScanTxRecord, StoredScan,
    TrackedPubkeyMeta, WalletApplyHook, WalletApplyPayload, WalletBox, WalletRead, WalletReader,
    WalletScanCursor, WalletScanMatcher, WalletScanService, WalletStore, WalletStoreError,
    WalletTransaction, WalletWiring, WalletWrite, WALLET_SCHEMA_VERSION,
};

pub fn migrate_schema(db: &std::sync::Arc<redb::Database>) -> Result<(), WalletStoreError> {
    ergo_wallet_service::wallet::migrate_schema_with_anchor(db, &|txn, height| {
        utxo_scan::committed_discovery_anchor(txn, height).map_err(|error| match error {
            crate::store::StateError::Db(error) => WalletStoreError::Database(error),
            crate::store::StateError::DatabaseError(error) => (*error).into(),
            crate::store::StateError::StorageError(error) => (*error).into(),
            crate::store::StateError::TransactionError(error) => (*error).into(),
            crate::store::StateError::TableError(error) => (*error).into(),
            crate::store::StateError::CommitError(error) => (*error).into(),
            error => WalletStoreError::Decode(error.to_string()),
        })
    })
}

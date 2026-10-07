//! Offline wallet-job journal compatibility facade.

use crate::store::StateError;
use redb::{Database, ReadTransaction};

pub use ergo_wallet_service::wallet::mining_jobs::{JOURNAL, META, QUARANTINE};

fn state_error(error: crate::wallet::WalletStoreError) -> StateError {
    match error {
        crate::wallet::WalletStoreError::Decode(reason) => StateError::DbCorruption {
            table: "wallet_mining_jobs_v1",
            key: String::new(),
            reason,
        },
        error => error.into(),
    }
}

pub fn pending_jobs(txn: &ReadTransaction) -> Result<Vec<u64>, StateError> {
    ergo_wallet_service::wallet::mining_jobs::pending_jobs(txn).map_err(state_error)
}

pub fn quarantine(db: &Database) -> Result<u64, StateError> {
    ergo_wallet_service::wallet::mining_jobs::quarantine(db).map_err(state_error)
}

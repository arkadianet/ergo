//! Shared gate for engine commands that consume wallet scan results.

use ergo_wallet_protocol::WalletAdminError;

use crate::wallet::WalletStore;

pub(super) fn require_valid_scan(store: &dyn WalletStore) -> Result<(), WalletAdminError> {
    let invalidated = store
        .read()
        .and_then(|read| read.scan_invalidated())
        .map_err(|error| WalletAdminError::Internal(format!("scan_invalidated read: {error}")))?;
    if invalidated {
        return Err(WalletAdminError::ScanInvalidated);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_gate_unreadable_flag_refuses_command() {
        let directory = tempfile::tempdir().unwrap();
        let db = redb::Database::create(directory.path().join("wallet.redb")).unwrap();
        let wrong_type: redb::TableDefinition<(), u64> =
            redb::TableDefinition::new("wallet_scan_invalidated");
        let transaction = db.begin_write().unwrap();
        transaction
            .open_table(wrong_type)
            .unwrap()
            .insert((), 0)
            .unwrap();
        transaction.commit().unwrap();
        let store = crate::wallet::RedbWalletStore::new(std::sync::Arc::new(db));
        assert!(matches!(
            require_valid_scan(&store),
            Err(WalletAdminError::Internal(_))
        ));
    }
}

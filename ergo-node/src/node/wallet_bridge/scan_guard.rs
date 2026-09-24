//! Shared gate for commands that consume wallet scan results.

use ergo_api::wallet::WalletAdminError;
use ergo_state::wallet::tables::WALLET_SCAN_INVALIDATED;

use super::WalletCommand;

pub(super) fn scan_invalidated(txn: &redb::ReadTransaction) -> Result<bool, WalletAdminError> {
    match txn.open_table(WALLET_SCAN_INVALIDATED) {
        Ok(table) => table
            .get(())
            .map(|value| value.is_some_and(|value| value.value()))
            .map_err(|e| WalletAdminError::Internal(format!("scan_invalidated read: {e}"))),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
        Err(e) => Err(WalletAdminError::Internal(format!(
            "scan_invalidated table: {e}"
        ))),
    }
}

pub(super) fn require_valid_scan(db: &redb::Database) -> Result<(), WalletAdminError> {
    let txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(format!("scan_invalidated transaction: {e}")))?;
    if scan_invalidated(&txn)? {
        return Err(WalletAdminError::ScanInvalidated);
    }
    Ok(())
}

/// Wallet, scan, and watch-only HTTP surfaces dispatch through this gate.
/// Recovery, status, keys, and registry administration stay available
/// independently of wallet history.
pub(super) fn gate(command: WalletCommand, db: &redb::Database) -> Option<WalletCommand> {
    // Each reply has its own result type; expand one arm per command so the
    // common precondition can return the same typed error to every caller.
    macro_rules! gated_commands {
        ($($variant:ident),+ $(,)?) => {
            match command {
                $(command @ WalletCommand::$variant { .. } => {
                    match require_valid_scan(db) {
                        Ok(()) => Some(command),
                        Err(error) => {
                            if let WalletCommand::$variant { reply, .. } = command {
                                let _ = reply.send(Err(error));
                            }
                            None
                        }
                    }
                },)+
                command @ (WalletCommand::Status { .. }
                    | WalletCommand::NativeStatus { .. }
                    | WalletCommand::Init { .. }
                    | WalletCommand::Restore { .. }
                    | WalletCommand::Unlock { .. }
                    | WalletCommand::Lock { .. }
                    | WalletCommand::Check { .. }
                    | WalletCommand::Rescan { .. }
                    | WalletCommand::UpdateChangeAddress { .. }
                    | WalletCommand::Addresses { .. }
                    | WalletCommand::NativeAddresses { .. }
                    | WalletCommand::DeriveKey { .. }
                    | WalletCommand::DeriveNextKey { .. }
                    | WalletCommand::GetPrivateKey { .. }
                    | WalletCommand::RegisterScan { .. }
                    | WalletCommand::DeregisterScan { .. }
                    | WalletCommand::ListScans { .. }
                    | WalletCommand::ScanStopTracking { .. }
                    | WalletCommand::ScanAddBox { .. }
                    | WalletCommand::ScanP2sRule { .. }) => Some(command),
            }
        };
    }
    gated_commands!(
        Balances,
        BalancesWithUnconfirmed,
        NativeBalance,
        Boxes,
        BoxesUnspent,
        NativeBoxes,
        NativeBoxById,
        Transactions,
        TransactionById,
        TransactionsByScanId,
        NativeTransactions,
        NativeTransactionById,
        PaymentSend,
        RetrieveRewards,
        TransactionGenerate,
        TransactionGenerateUnsigned,
        TransactionSign,
        TransactionSend,
        BoxesCollect,
        NativeSelectBoxes,
        NativeBuildTransaction,
        NativeSignTransaction,
        NativeSendTransaction,
        GenerateCommitments,
        ExtractHints,
        ScanUnspentBoxes,
        ScanSpentBoxes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- error paths -----

    #[test]
    fn scan_gate_unreadable_flag_refuses_command() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wallet.redb")).unwrap();
        let wrong_type: redb::TableDefinition<(), u64> =
            redb::TableDefinition::new("wallet_scan_invalidated");
        let txn = db.begin_write().unwrap();
        txn.open_table(wrong_type).unwrap().insert((), 0).unwrap();
        txn.commit().unwrap();
        let (reply, mut received) = tokio::sync::oneshot::channel();
        assert!(gate(WalletCommand::Balances { reply }, &db).is_none());
        assert!(matches!(
            received.try_recv().unwrap(),
            Err(WalletAdminError::Internal(_))
        ));
    }
}

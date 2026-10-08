//! Node-host regression harnesses for the service-owned job engine.

use ergo_wallet_protocol::native::dto::{
    WalletJob, WalletJobRequest, WalletJobState, WalletJobTask,
};
use ergo_wallet_protocol::WalletAdminError;
use ergo_wallet_service::engine::jobs::{
    cancel, create, create_owned, list, records, reserved_inputs, save, tick, transition,
    MAX_SCHEDULE_BLOCKS, MINED_IN_WALLET, PINNED_INPUT_UNAVAILABLE,
};
use ergo_wallet_service::engine::{
    ChainAccessError, RescanCoordinator, TxSubmitError, TxSubmitter, WalletChainAccess,
    WalletEngine, WalletEngineConfig, WalletEngineParts,
};
use redb::ReadableTable;
use std::collections::BTreeMap;

mod sign_submit {
    use ergo_wallet_protocol::WalletAdminError;
    pub(super) fn serialize_signed_tx(
        tx: &ergo_ser::transaction::Transaction,
    ) -> Result<Vec<u8>, WalletAdminError> {
        let mut writer = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::transaction::write_transaction(&mut writer, tx)
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        Ok(writer.result())
    }
    pub(super) fn signed_tx_id_hex(bytes: &[u8]) -> Result<String, WalletAdminError> {
        let tx = ergo_ser::transaction::read_transaction(
            &mut ergo_primitives::reader::VlqReader::new(bytes),
        )
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        Ok(hex::encode(
            ergo_ser::transaction::transaction_id(&tx)
                .map_err(|e| WalletAdminError::Internal(e.to_string()))?
                .as_bytes(),
        ))
    }
}
#[path = "jobs/prepare_tests.rs"]
mod prepare_tests;
#[path = "jobs/scheduler_tests.rs"]
mod scheduler_tests;

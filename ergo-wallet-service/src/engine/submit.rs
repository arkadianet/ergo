//! Submission seam for the wallet engine.
//!
//! The engine hands signed transaction bytes to a [`TxSubmitter`] and maps
//! the typed [`TxSubmitError`] at its own boundary. The trait is `async`
//! (runtime-agnostic futures via `async-trait`): the engine methods that
//! submit are `async fn`s that await it directly, with no blocking bridge.

use async_trait::async_trait;
use ergo_wallet_protocol::WalletAdminError;

/// Typed submission failure: the admission `reason` code plus an optional
/// human-readable `detail`. Kept structured — NOT collapsed to a string — so
/// callers can distinguish a `duplicate` admission (an idempotent success on
/// the native send path) from a real rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSubmitError {
    pub reason: String,
    pub detail: Option<String>,
}

/// Submits signed transactions on the engine's behalf. The embedded node
/// implements it over its admission pipeline; tests inject stubs.
#[async_trait]
pub trait TxSubmitter: Send + Sync {
    /// Submit signed tx bytes; returns the tx id on admission. The error is
    /// the typed [`TxSubmitError`] `{reason, detail}` so each caller maps it
    /// intentionally: the native send path maps `duplicate` → `200 accepted`;
    /// the compat callers map every failure to `WalletAdminError::Internal`.
    async fn submit_transaction(&self, tx_bytes: Vec<u8>) -> Result<String, TxSubmitError>;

    /// Whether the backend can accept new private mining work in this process.
    fn private_mining_configured(&self) -> bool {
        false
    }

    /// Admit only to the durable private queue, without public relay.
    async fn submit_private_transaction(
        &self,
        _tx_bytes: Vec<u8>,
        _options: ergo_wallet_protocol::mining::PrivateTransactionOptions,
    ) -> Result<String, TxSubmitError> {
        Err(private_mining_unavailable())
    }

    /// One bounded queue snapshot used to reconcile approved wallet jobs.
    async fn private_transactions(
        &self,
    ) -> Result<Vec<ergo_wallet_protocol::mining::PrivateTransactionEntry>, TxSubmitError> {
        Err(private_mining_unavailable())
    }

    async fn private_transaction_status(
        &self,
        tx_id: String,
    ) -> Result<Option<ergo_wallet_protocol::mining::PrivateTransactionEntry>, TxSubmitError> {
        self.private_transactions()
            .await
            .map(|entries| entries.into_iter().find(|entry| entry.tx_id == tx_id))
    }

    async fn cancel_private_transaction(&self, _tx_id: String) -> Result<(), TxSubmitError> {
        Err(private_mining_unavailable())
    }

    /// Background-job RPCs have bounded latency supplied by the embedding
    /// runtime. Ordinary interactive delivery keeps its existing contract.
    async fn job_private_transactions(
        &self,
    ) -> Result<Vec<ergo_wallet_protocol::mining::PrivateTransactionEntry>, TxSubmitError> {
        self.private_transactions().await
    }
    async fn job_private_transaction_status(
        &self,
        tx_id: String,
    ) -> Result<Option<ergo_wallet_protocol::mining::PrivateTransactionEntry>, TxSubmitError> {
        self.private_transaction_status(tx_id).await
    }
    async fn job_submit_private_transaction(
        &self,
        tx_bytes: Vec<u8>,
        options: ergo_wallet_protocol::mining::PrivateTransactionOptions,
    ) -> Result<String, TxSubmitError> {
        self.submit_private_transaction(tx_bytes, options).await
    }
    async fn job_cancel_private_transaction(&self, tx_id: String) -> Result<(), TxSubmitError> {
        self.cancel_private_transaction(tx_id).await
    }
}

fn private_mining_unavailable() -> TxSubmitError {
    TxSubmitError {
        reason: "private_mining_unavailable".into(),
        detail: None,
    }
}

/// Map a submit error to a native [`WalletAdminError`]. A `duplicate` reason is the
/// caller's concern (handled as idempotent-accepted upstream); other reasons are a
/// client-correctable rejection (`bad_request` carrying the typed reason).
pub fn map_submit_error(e: TxSubmitError) -> WalletAdminError {
    WalletAdminError::BadRequest(match e.detail {
        Some(d) => format!("submit rejected ({}): {d}", e.reason),
        None => format!("submit rejected: {}", e.reason),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `duplicate` submit reason is handled as idempotent-accept upstream; any
    /// other submit reason maps to a client `bad_request` carrying the typed reason.
    #[test]
    fn map_submit_error_carries_reason() {
        let e = map_submit_error(TxSubmitError {
            reason: "too_big".into(),
            detail: Some("size 1234 > max".into()),
        });
        match e {
            WalletAdminError::BadRequest(m) => {
                assert!(m.contains("too_big") && m.contains("size 1234"));
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }
}

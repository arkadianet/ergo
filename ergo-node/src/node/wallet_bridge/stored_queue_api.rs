//! Operator access to a persisted queue when candidate mining is disabled.

use std::sync::Arc;

use async_trait::async_trait;
use ergo_api::mining::{MiningApiError, NodeMining, PrivateTransactionEntry};
use ergo_mining::private_queue::{PrivateQueueError, PrivateTransactionQueue};
use ergo_rest_json::mining::{AutolykosSolutionJson, WorkMessageJson};

/// Reads and durably withdraws retained work without enabling new admissions.
pub struct StoredPrivateQueueBridge {
    queue: Arc<PrivateTransactionQueue>,
}

impl StoredPrivateQueueBridge {
    pub fn new(queue: Arc<PrivateTransactionQueue>) -> Self {
        Self { queue }
    }
}

fn disabled() -> MiningApiError {
    MiningApiError::Unavailable("candidate mining is disabled".into())
}

#[async_trait]
impl NodeMining for StoredPrivateQueueBridge {
    async fn candidate(
        &self,
        _: Option<String>,
    ) -> Result<Option<WorkMessageJson>, MiningApiError> {
        Err(disabled())
    }
    async fn submit_solution(&self, _: AutolykosSolutionJson) -> Result<(), MiningApiError> {
        Err(disabled())
    }
    async fn reward_address(&self) -> Result<String, MiningApiError> {
        Err(disabled())
    }
    async fn reward_pubkey(&self) -> Result<String, MiningApiError> {
        Err(disabled())
    }
    async fn private_transactions(&self) -> Result<Vec<PrivateTransactionEntry>, MiningApiError> {
        let queue = self.queue.clone();
        tokio::task::spawn_blocking(move || {
            queue
                .list()
                .into_iter()
                .map(|entry| super::super::private_mining::api_entry(entry, false))
                .collect()
        })
        .await
        .map_err(|_| MiningApiError::Internal("private queue worker failed".into()))
    }
    async fn cancel_private_transaction(
        &self,
        tx_id: String,
    ) -> Result<PrivateTransactionEntry, MiningApiError> {
        let queue = self.queue.clone();
        tokio::task::spawn_blocking(move || {
            let result = queue.cancel(&tx_id).map_err(|error| match error {
                PrivateQueueError::Rejected(detail) => MiningApiError::BadRequest(detail),
                PrivateQueueError::Storage(detail) => MiningApiError::Internal(detail),
            });
            super::super::private_mining::log_unsynced(&queue);
            result.map(|entry| super::super::private_mining::api_entry(entry, false))
        })
        .await
        .map_err(|_| MiningApiError::Internal("private queue worker failed".into()))?
    }
}

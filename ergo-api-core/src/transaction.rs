use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use crate::error::{BackendFailure, ServiceResult};
use crate::id::HeaderId;
use crate::id::TxId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionMode {
    Broadcast,
    Validate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSubmission {
    pub bytes: Arc<[u8]>,
    pub mode: SubmissionMode,
}

impl TransactionSubmission {
    pub fn new(bytes: Arc<[u8]>, mode: SubmissionMode) -> Self {
        Self { bytes, mode }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDisposition {
    Admitted,
    WouldAdmit,
    AlreadyKnown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionAdmission {
    pub tx_id: TxId,
    pub disposition: AdmissionDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransactionRejection {
    #[error("transaction encoding is invalid")]
    InvalidEncoding,
    #[error("transaction is not canonical")]
    NonCanonical,
    #[error("transaction encoding is invalid")]
    KnownInvalid,
    #[error("transaction structure is invalid")]
    Structural,
    #[error("transaction is already known")]
    Duplicate,
    #[error("transaction exceeds the configured size limit")]
    SizeLimit,
    #[error("transaction fee is below the configured minimum")]
    FeeTooLow,
    #[error("transaction execution cost exceeds the configured limit")]
    CostLimit,
    #[error("transaction has an unresolved input")]
    UnresolvedInput,
    #[error("transaction has an unresolved data input")]
    UnresolvedDataInput,
    #[error("transaction double-spends a mempool input")]
    DoubleSpend,
    #[error("transaction script validation failed")]
    ScriptValidation,
    #[error("transaction violates a monetary invariant")]
    MonetaryInvariant,
    #[error("transaction violates the reemission policy")]
    ReemissionPolicy,
    #[error("transaction validation failed")]
    ValidationFailed,
    #[error("transaction replacement was rejected by the double-spend policy")]
    DoubleSpendReplacement,
    #[error("transaction insertion collided with an existing entry")]
    InsertionCollision,
    #[error("transaction is stale")]
    Stale,
    #[error("mempool admission is paused during initial block download")]
    IbdGated,
    #[error("transaction tip is not ready")]
    TipUnready,
    #[error("transaction exceeds the global admission budget")]
    GlobalBudget,
    #[error("transaction exceeds the peer admission budget")]
    PeerBudget,
    #[error("mempool is full")]
    PoolFull,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransactionError {
    #[error(transparent)]
    Rejected(#[from] TransactionRejection),
    #[error("mempool submission is disabled")]
    Disabled,
    #[error("submission service is unavailable")]
    Unavailable,
    #[error("submission service is overloaded")]
    Overloaded,
    #[error("submission service is shutting down")]
    ShuttingDown,
    #[error("submission timed out")]
    TimedOut,
    #[error("submission failed internally: {0}")]
    Internal(BackendFailure),
}

#[async_trait]
pub trait TransactionSubmitter: Send + Sync + 'static {
    async fn submit(
        &self,
        request: TransactionSubmission,
    ) -> Result<TransactionAdmission, TransactionError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Confirmed,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRecord {
    pub id: TxId,
    pub state: TransactionState,
    pub inclusion_height: Option<u32>,
    pub index_in_block: Option<u32>,
    pub size_bytes: u32,
    pub confirmations: Option<u32>,
}

#[async_trait]
#[allow(clippy::result_large_err)]
pub trait TransactionReader: Send + Sync + 'static {
    async fn get(&self, id: TxId) -> ServiceResult<Option<TransactionRecord>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBlockSections {
    pub header: Arc<[u8]>,
    pub block_transactions: Arc<[u8]>,
    pub extension: Arc<[u8]>,
    pub ad_proofs: Option<Arc<[u8]>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockAdmissionDisposition {
    AcceptedIntoPipeline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockAdmission {
    pub header_id: HeaderId,
    pub disposition: BlockAdmissionDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BlockSubmitError {
    #[error("local block submission is disabled")]
    Disabled,
    #[error("local block submission is unavailable")]
    Unavailable,
    #[error("local block submission is overloaded")]
    Overloaded,
    #[error("local block submission is shutting down")]
    ShuttingDown,
    #[error("local block submission timed out")]
    TimedOut,
    #[error("local block submission failed internally: {0}")]
    Internal(BackendFailure),
}

#[async_trait]
pub trait LocalBlockSubmitter: Send + Sync + 'static {
    async fn submit(
        &self,
        sections: CanonicalBlockSections,
    ) -> Result<BlockAdmission, BlockSubmitError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationRequest {
    pub bytes: Arc<[u8]>,
    pub assume_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Simulation {
    pub tx_id: TxId,
    pub valid: bool,
    pub cost_units: u64,
    pub size_bytes: u32,
    pub warnings: Vec<String>,
}

#[async_trait]
pub trait TransactionSimulator: Send + Sync + 'static {
    async fn simulate(&self, request: SimulationRequest) -> Result<Simulation, TransactionError>;
}

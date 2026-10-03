//! Approved, finite wallet maintenance jobs. Jobs submit only to private mining.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::TxIntent;

/// The exact operation approved by the wallet owner. Input lists are pinned;
/// maintenance never silently expands to newly received wallet funds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum WalletJobTask {
    /// A fixed payment or token transfer using the ordinary intent builder.
    Send { intent: TxIntent },
    /// Move selected owned boxes into one tracked wallet output, preserving tokens.
    #[serde(rename_all = "camelCase")]
    Consolidate {
        box_ids: Vec<String>,
        destination: String,
    },
    /// Recreate selected owned boxes, preserving their recipients, value,
    /// tokens and registers while advancing their creation height.
    #[serde(rename_all = "camelCase")]
    Renew { box_ids: Vec<String> },
    /// Retrieve an approved set of mining rewards after they mature. Required
    /// re-emission obligations remain paid even with a zero miner fee.
    #[serde(rename_all = "camelCase")]
    Rewards {
        box_ids: Vec<String>,
        destination: String,
    },
}

/// Schedule one approved operation. A job prepares at most one signed
/// transaction: retries resubmit its durable bytes, never send a second payment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletJobRequest {
    pub label: String,
    pub task: WalletJobTask,
    /// Earliest applied block height at which preparation may begin.
    pub not_before_height: u32,
    /// Stop trying after this height and retire any unpublished private work.
    pub expires_at_height: u32,
    /// Maximum preparation/submission attempts (1..=100).
    pub max_attempts: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum WalletJobState {
    Waiting,
    WaitingForWallet,
    Preparing,
    Prepared,
    Queued,
    InCandidate,
    Mined,
    Conflicted,
    Cancelled,
    Expired,
    Failed,
}

impl WalletJobState {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Mined | Self::Conflicted | Self::Cancelled | Self::Expired | Self::Failed
        )
    }
}

/// Owner-only job status. Signed transaction bytes stay in the durable journal;
/// the job API exposes its transaction ID, never its secret signing material.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletJob {
    /// Monotonic durable ID, represented as a decimal string.
    pub id: String,
    pub request: WalletJobRequest,
    pub state: WalletJobState,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub attempts: u32,
    pub tx_id: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletJobs {
    pub items: Vec<WalletJob>,
    pub max_jobs: u32,
}

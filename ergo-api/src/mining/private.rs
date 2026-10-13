//! Authenticated private mining queue contract, separate from public admission.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Queue policy. A deadline is local policy, not a transaction script expiry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateTransactionOptions {
    pub expires_at_ms: Option<u64>,
    pub expires_at_height: Option<u32>,
    #[serde(default)]
    pub priority: i32,
    pub label: Option<String>,
}

/// Owner-only queue metadata; signed bytes never appear in public snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PrivateTransactionEntry {
    pub tx_id: String,
    pub state: String,
    pub reason: Option<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub expires_at_height: Option<u32>,
    pub priority: i32,
    pub label: Option<String>,
    pub input_ids: Vec<String>,
    pub fee_nano_erg: String,
    pub size_bytes: u32,
    pub validation_cost: u64,
    pub mined_block_id: Option<String>,
    pub mined_height: Option<u32>,
}

/// Import a signed transaction for this miner without network announcement.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateTransactionRequest {
    pub signed_transaction_hex: String,
    #[serde(default)]
    pub options: PrivateTransactionOptions,
}

impl From<PrivateTransactionOptions> for ergo_wallet_protocol::mining::PrivateTransactionOptions {
    fn from(value: PrivateTransactionOptions) -> Self {
        Self {
            expires_at_ms: value.expires_at_ms,
            expires_at_height: value.expires_at_height,
            priority: value.priority,
            label: value.label,
        }
    }
}

impl From<ergo_wallet_protocol::mining::PrivateTransactionOptions> for PrivateTransactionOptions {
    fn from(value: ergo_wallet_protocol::mining::PrivateTransactionOptions) -> Self {
        Self {
            expires_at_ms: value.expires_at_ms,
            expires_at_height: value.expires_at_height,
            priority: value.priority,
            label: value.label,
        }
    }
}

impl From<PrivateTransactionEntry> for ergo_wallet_protocol::mining::PrivateTransactionEntry {
    fn from(value: PrivateTransactionEntry) -> Self {
        Self {
            tx_id: value.tx_id,
            state: value.state,
            reason: value.reason,
            created_at_ms: value.created_at_ms,
            expires_at_ms: value.expires_at_ms,
            expires_at_height: value.expires_at_height,
            priority: value.priority,
            label: value.label,
            input_ids: value.input_ids,
            fee_nano_erg: value.fee_nano_erg,
            size_bytes: value.size_bytes,
            validation_cost: value.validation_cost,
            mined_block_id: value.mined_block_id,
            mined_height: value.mined_height,
        }
    }
}

impl From<ergo_wallet_protocol::mining::PrivateTransactionEntry> for PrivateTransactionEntry {
    fn from(value: ergo_wallet_protocol::mining::PrivateTransactionEntry) -> Self {
        Self {
            tx_id: value.tx_id,
            state: value.state,
            reason: value.reason,
            created_at_ms: value.created_at_ms,
            expires_at_ms: value.expires_at_ms,
            expires_at_height: value.expires_at_height,
            priority: value.priority,
            label: value.label,
            input_ids: value.input_ids,
            fee_nano_erg: value.fee_nano_erg,
            size_bytes: value.size_bytes,
            validation_cost: value.validation_cost,
            mined_block_id: value.mined_block_id,
            mined_height: value.mined_height,
        }
    }
}

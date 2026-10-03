//! Approved bounded direct swaps, submitted only to private mining.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::WalletJobState;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum MiningSwapDirection {
    ErgToToken,
    TokenToErg,
}

/// Explicit approval pins the pool identity, owned funding and price bounds.
/// Amounts are raw asset units; ERG amounts are nanoERG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MiningSwapRequest {
    pub label: String,
    pub pool_box_id: String,
    pub pool_nft: String,
    pub pool_tree_hash: String,
    pub funding_box_ids: Vec<String>,
    pub receiving_address: String,
    pub direction: MiningSwapDirection,
    pub input_amount: String,
    pub max_input_amount: String,
    pub min_output_amount: String,
    /// Quote explicitly approved by the owner. Refreshes must remain within
    /// maxSlippageBasisPoints of this value AND the explicit minimum output.
    pub approved_quote_output: String,
    pub max_slippage_basis_points: u16,
    pub not_before_height: u32,
    /// Last allowed containing-block height, enforced by the private queue.
    pub expires_at_height: u32,
    pub max_attempts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MiningSwapPreview {
    pub pool_box_id: String,
    pub pool_nft: String,
    pub pool_tree_hash: String,
    pub trade_token_id: String,
    pub direction: MiningSwapDirection,
    pub input_amount: String,
    pub quoted_output_amount: String,
    pub effective_min_output_amount: String,
    pub fee_numerator: u32,
    pub snapshot_height: u32,
    /// Complete unsigned transaction for inspection; it is not submitted.
    pub unsigned_transaction: super::TxRepr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MiningSwap {
    pub id: String,
    pub request: MiningSwapRequest,
    pub state: WalletJobState,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub attempts: u32,
    pub generation: u32,
    pub current_pool_box_id: String,
    pub quoted_output_amount: Option<String>,
    pub tx_id: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MiningSwaps {
    pub items: Vec<MiningSwap>,
    pub max_swaps: u32,
}

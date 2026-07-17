//! Wallet-transaction DTOs for `GET /api/v1/wallet/transactions`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ----- transactions -----

/// A lean wallet-transaction summary — references only (no full IO/fee/bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletTransactionSummary {
    pub tx_id: String,
    pub block_id: String,
    pub block_height: u32,
    pub wallet_input_box_ids: Vec<String>,
    pub wallet_output_box_ids: Vec<String>,
}

/// Paged wallet-transaction list, ordered `(blockHeight desc, txId asc)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TxPage {
    pub items: Vec<WalletTransactionSummary>,
    pub total: u32,
    pub as_of: u32,
}

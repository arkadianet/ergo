//! REST response DTOs (Scala camelCase via serde rename).

use serde::{Deserialize, Serialize};

/// Response returned by routes that submit a transaction to the mempool.
/// `txId` matches the Scala node's wire key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxIdResponse {
    pub tx_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WalletStatus {
    pub is_initialized: bool,
    pub is_unlocked: bool,
    pub change_address: String,
    pub wallet_height: u32,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WalletBalances {
    pub height: u32,
    pub balance: u64,
    pub assets: Vec<TokenBalance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBalance {
    pub token_id: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WalletAddressList(pub Vec<String>);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Page {
    pub offset: u32,
    pub limit: u32,
}

impl Default for Page {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WalletBoxesPage {
    pub total: u32,
    pub items: Vec<WalletBoxEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletBoxEntry {
    pub box_id: String,
    pub value: u64,
    pub creation_height: u32,
    pub status: String,
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WalletTransactionsPage {
    pub total: u32,
    pub items: Vec<WalletTransactionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletTransactionEntry {
    pub tx_id: String,
    pub block_height: u32,
    pub block_id: String,
    pub wallet_outputs: Vec<String>,
    pub wallet_inputs: Vec<String>,
    /// Scans this tx is associated with (the Scala `WalletTransaction.scanIds`
    /// class field; Scala's wire key is `scans` — this lean shape uses
    /// `scanIds`). Filled by `/wallet/transactionsByScanId` for user scans;
    /// omitted on the wallet's own tx listings (whose rows carry no scan
    /// tagging), keeping their wire shape unchanged.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub scan_ids: Vec<u16>,
}

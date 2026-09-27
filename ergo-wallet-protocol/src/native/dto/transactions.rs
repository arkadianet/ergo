use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletTransactionSummary {
    pub tx_id: String,
    pub block_id: String,
    pub block_height: u32,
    pub wallet_input_box_ids: Vec<String>,
    pub wallet_output_box_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxPage {
    pub items: Vec<WalletTransactionSummary>,
    pub total: u32,
    pub as_of: u32,
}

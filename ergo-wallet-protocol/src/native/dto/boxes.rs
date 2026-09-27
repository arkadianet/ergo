use serde::{Deserialize, Serialize};

use super::balance::WalletAssetDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BoxStatusDto {
    Confirmed,
    #[serde(rename_all = "camelCase")]
    Immature {
        matures_at_height: u32,
    },
    #[serde(rename_all = "camelCase")]
    Spent {
        tx_id: String,
        height: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BoxProvenanceDto {
    Owned,
    MinerReward,
    #[serde(rename_all = "camelCase")]
    Custom {
        scan_id: u16,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletBoxSummary {
    pub box_id: String,
    pub value: String,
    pub assets: Vec<WalletAssetDto>,
    pub creation_tx_id: String,
    pub creation_output_index: u16,
    pub creation_height: u32,
    pub status: BoxStatusDto,
    pub provenance: BoxProvenanceDto,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxPage {
    pub items: Vec<WalletBoxSummary>,
    pub total: u32,
    pub as_of: u32,
}

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetrieveRewardsRequest {
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub fee: Option<String>,
    #[serde(default)]
    pub box_ids: Option<Vec<String>>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SweptTokenDto {
    pub token_id: String,
    pub amount: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveRewardsResultDto {
    pub box_count: u32,
    pub box_ids: Vec<String>,
    pub remaining: u32,
    pub gross_erg: String,
    pub reemission_paid: String,
    pub fee: String,
    pub net_to_destination: String,
    pub other_tokens: Vec<SweptTokenDto>,
    pub destination: String,
    pub tx_id: Option<String>,
}

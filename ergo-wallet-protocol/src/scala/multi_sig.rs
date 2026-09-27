use serde::{Deserialize, Serialize};

use super::sending::{ExternalSecretDto, TxHintsBagDto};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateCommitmentsRequest {
    pub unsigned_tx: String,
    #[serde(default)]
    pub external_secrets: Option<Vec<ExternalSecretDto>>,
    #[serde(default)]
    pub inputs: Option<Vec<String>>,
    #[serde(default)]
    pub data_inputs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateCommitmentsResponse {
    pub hints: TxHintsBagDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HintExtractionRequest {
    pub tx: String,
    pub real: Vec<String>,
    pub simulated: Vec<String>,
    #[serde(default)]
    pub inputs: Option<Vec<String>>,
    #[serde(default)]
    pub data_inputs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HintExtractionResponse {
    pub hints: TxHintsBagDto,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetDto {
    pub token_id: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequestDto {
    pub address: String,
    pub value: u64,
    #[serde(default)]
    pub assets: Vec<AssetDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTxDto {
    pub bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedTxDto {
    pub bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExternalSecretDto {
    Dlog {
        dlog: String,
    },
    DhTuple {
        g: String,
        h: String,
        u: String,
        v: String,
        x: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TxHintsBagDto {
    #[serde(default)]
    pub secret_hints: std::collections::BTreeMap<String, Vec<HintDto>>,
    #[serde(default)]
    pub public_hints: std::collections::BTreeMap<String, Vec<HintDto>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "hint", rename_all = "camelCase")]
pub enum HintDto {
    #[serde(rename = "cmtReal")]
    RealCommitment {
        image: SigmaBooleanJson,
        commitment: FirstProverMessageJson,
        position: String,
    },
    #[serde(rename = "cmtSimulated")]
    SimulatedCommitment {
        image: SigmaBooleanJson,
        commitment: FirstProverMessageJson,
        challenge: String,
        position: String,
    },
    #[serde(rename = "cmtWithSecret")]
    OwnCommitment {
        image: SigmaBooleanJson,
        secret: String,
        commitment: FirstProverMessageJson,
        position: String,
    },
    #[serde(rename = "proofReal")]
    RealSecretProof {
        image: SigmaBooleanJson,
        challenge: String,
        response: String,
        position: String,
    },
    #[serde(rename = "proofSimulated")]
    SimulatedSecretProof {
        image: SigmaBooleanJson,
        challenge: String,
        response: String,
        position: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum FirstProverMessageJson {
    #[serde(rename = "dlogA")]
    Dlog { a: String },
    #[serde(rename = "dhtABab")]
    DhTuple { a: String, b: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigmaBooleanJson {
    #[serde(flatten)]
    pub inner: serde_json::Value,
}

pub fn node_position_to_str(positions: &[u32]) -> String {
    positions
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn node_position_from_str(s: &str) -> Result<Vec<u32>, String> {
    s.split('-')
        .map(|seg| {
            seg.parse::<u32>()
                .map_err(|_| format!("invalid position segment: {seg:?}"))
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionGenerateRequest {
    pub requests: Vec<PaymentRequestDto>,
    pub inputs: Option<Vec<String>>,
    pub data_inputs: Option<Vec<String>>,
    pub fee: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionGenerateResponse {
    pub transaction: SignedTxDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionGenerateUnsignedRequest {
    pub requests: Vec<PaymentRequestDto>,
    pub inputs: Option<Vec<String>>,
    pub data_inputs: Option<Vec<String>>,
    pub fee: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionGenerateUnsignedResponse {
    pub unsigned_tx: UnsignedTxDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignRequest {
    pub unsigned_tx: UnsignedTxDto,
    pub external_secrets: Option<Vec<ExternalSecretDto>>,
    pub hints: Option<TxHintsBagDto>,
    pub inputs: Option<Vec<String>>,
    pub data_inputs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignResponse {
    pub transaction: SignedTxDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSendRequest {
    pub requests: Vec<PaymentRequestDto>,
    pub inputs: Option<Vec<String>>,
    pub data_inputs: Option<Vec<String>>,
    pub fee: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxesCollectRequest {
    pub target_assets: Vec<AssetDto>,
    pub target_balance: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxesCollectResponse {
    pub boxes: Vec<String>,
    pub change_boxes: Vec<String>,
}

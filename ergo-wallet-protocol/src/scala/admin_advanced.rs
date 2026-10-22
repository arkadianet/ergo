use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveKeyRequest {
    pub derivation_path: String,
    /// The caller states the key has never been used on chain. A fresh key is
    /// tracked from the current tip with no rescan. Absent means unknown: the
    /// wallet then checks the node's address index, and rescans if the node
    /// has none.
    #[serde(default)]
    pub fresh: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveKeyResponse {
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveNextKeyResponse {
    pub derivation_path: String,
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPrivateKeyRequest {
    pub address: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPrivateKeyResponse {
    pub w: String,
}

impl std::fmt::Debug for GetPrivateKeyResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetPrivateKeyResponse")
            .field("w", &"<redacted>")
            .finish()
    }
}

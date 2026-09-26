use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitBody {
    pub pass: String,
    #[serde(default)]
    pub mnemonic_pass: String,
    #[serde(default = "default_strength")]
    pub strength: u8,
}

fn default_strength() -> u8 {
    24
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitResponse {
    pub mnemonic: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreBody {
    pub mnemonic: String,
    #[serde(default)]
    pub mnemonic_pass: String,
    pub pass: String,
    #[serde(default = "default_use_pre_1627_true")]
    pub use_pre_1627_key_derivation: bool,
}

fn default_use_pre_1627_true() -> bool {
    true
}

#[derive(Deserialize)]
pub struct UnlockBody {
    pub pass: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckBody {
    pub mnemonic: String,
    #[serde(default)]
    pub mnemonic_pass: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResponse {
    pub matched: bool,
}

use serde::{Deserialize, Serialize};

use super::status::DerivationMode;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnlockRequest {
    pub pass: String,
}

impl std::fmt::Debug for UnlockRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockRequest")
            .field("pass", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MnemonicVerifyRequest {
    pub mnemonic: String,
    #[serde(default)]
    pub mnemonic_pass: String,
}

impl std::fmt::Debug for MnemonicVerifyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MnemonicVerifyRequest")
            .field("mnemonic", &"<redacted>")
            .field("mnemonic_pass", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicVerifyResult {
    pub matched: bool,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InitRequest {
    pub pass: String,
    #[serde(default)]
    pub mnemonic_pass: String,
    #[serde(default = "default_strength")]
    pub strength: u16,
}

impl std::fmt::Debug for InitRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitRequest")
            .field("pass", &"<redacted>")
            .field("mnemonic_pass", &"<redacted>")
            .field("strength", &self.strength)
            .finish()
    }
}

fn default_strength() -> u16 {
    24
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitResponse {
    pub mnemonic: String,
}

impl std::fmt::Debug for InitResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitResponse")
            .field("mnemonic", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreRequest {
    pub mnemonic: String,
    #[serde(default)]
    pub mnemonic_pass: String,
    pub pass: String,
    pub derivation: DerivationMode,
}

impl std::fmt::Debug for RestoreRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreRequest")
            .field("mnemonic", &"<redacted>")
            .field("mnemonic_pass", &"<redacted>")
            .field("pass", &"<redacted>")
            .field("derivation", &self.derivation)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedAddress {
    pub address: String,
    pub derivation_path: String,
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeAddressDto {
    pub address: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetChangeAddressRequest {
    pub address: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescanRequest {
    #[serde(default)]
    pub from_height: u32,
}

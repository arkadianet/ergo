use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletAddressDto {
    pub address: String,
    pub derivation_path: String,
    pub index: u64,
    pub label: Option<String>,
    pub added_at_height: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressPage {
    pub items: Vec<WalletAddressDto>,
    pub total: u32,
    pub as_of: u32,
}

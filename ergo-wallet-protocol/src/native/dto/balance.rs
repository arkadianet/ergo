use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletAssetDto {
    pub token_id: String,
    pub amount: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NanoErgBreakdownDto {
    pub confirmed: String,
    pub available: String,
    pub reserved: String,
    pub immature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReemissionInfoDto {
    pub token_id: String,
    pub reserved_token_amount: String,
    pub reserved_box_count: u32,
    pub reserved_exceeds_confirmed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ScopeDto {
    SingleHop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnconfirmedDeltaDto {
    pub scope: ScopeDto,
    pub incoming_nano_erg: String,
    pub outgoing_nano_erg: String,
    pub net_nano_erg: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletBalanceDto {
    pub height: u32,
    pub nano_erg: NanoErgBreakdownDto,
    pub assets: Vec<WalletAssetDto>,
    pub reemission: Option<ReemissionInfoDto>,
    pub unconfirmed: Option<UnconfirmedDeltaDto>,
}

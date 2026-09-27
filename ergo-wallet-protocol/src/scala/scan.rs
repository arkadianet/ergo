use serde::{Deserialize, Serialize};

use crate::error::WalletAdminError;

pub const MINING_SCAN_ID: u16 = 9;
pub const PAYMENTS_SCAN_ID: u16 = 10;
pub const FIRST_USER_SCAN_ID: u16 = 11;

pub fn validate_user_scan_id(scan_id: u16) -> Result<(), WalletAdminError> {
    if (FIRST_USER_SCAN_ID..=u16::MAX).contains(&scan_id) {
        Ok(())
    } else {
        Err(WalletAdminError::BadRequest(format!(
            "scan id {scan_id} is reserved (1..={PAYMENTS_SCAN_ID})"
        )))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ScanRequestDto {
    #[serde(rename = "scanName")]
    pub scan_name: String,
    #[serde(rename = "trackingRule")]
    pub tracking_rule: serde_json::Value,
    #[serde(rename = "walletInteraction", default)]
    pub wallet_interaction: Option<String>,
    #[serde(rename = "removeOffchain", default)]
    pub remove_offchain: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ScanDto {
    #[serde(rename = "scanId")]
    pub scan_id: u16,
    #[serde(rename = "scanName")]
    pub scan_name: String,
    #[serde(rename = "trackingRule")]
    pub tracking_rule: serde_json::Value,
    #[serde(rename = "walletInteraction")]
    pub wallet_interaction: String,
    #[serde(rename = "removeOffchain")]
    pub remove_offchain: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ScanIdJson {
    #[serde(rename = "scanId")]
    pub scan_id: u16,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ScanIdBoxIdDto {
    #[serde(rename = "scanId")]
    pub scan_id: u16,
    #[serde(rename = "boxId")]
    pub box_id: String,
}

#[derive(Deserialize)]
pub struct AddBoxRequestDto {
    #[serde(rename = "scanIds")]
    pub scan_ids: Vec<u16>,
    #[serde(rename = "box")]
    pub box_json: serde_json::Value,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanBoxEntry {
    pub box_id: String,
    pub value: u64,
    pub inclusion_height: Option<u32>,
    pub confirmations_num: Option<i64>,
    pub spent: bool,
    pub bytes: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanBoxFilter {
    #[serde(default)]
    pub min_confirmations: i32,
    #[serde(default = "neg_one")]
    pub max_confirmations: i32,
    #[serde(default)]
    pub min_inclusion_height: i32,
    #[serde(default = "neg_one")]
    pub max_inclusion_height: i32,
    #[serde(default = "default_limit")]
    pub limit: i32,
    #[serde(default)]
    pub offset: i32,
}

fn neg_one() -> i32 {
    -1
}

fn default_limit() -> i32 {
    500
}

impl ScanBoxFilter {
    pub fn validate(&self) -> Result<(), WalletAdminError> {
        if self.limit < 1 || self.limit > 2500 {
            return Err(WalletAdminError::BadRequest(format!(
                "limit must be in 1..=2500, got {}",
                self.limit
            )));
        }
        if self.offset < 0 {
            return Err(WalletAdminError::BadRequest(format!(
                "offset must be >= 0, got {}",
                self.offset
            )));
        }
        if self.min_inclusion_height < 0 {
            return Err(WalletAdminError::BadRequest(format!(
                "minInclusionHeight must be >= 0, got {}",
                self.min_inclusion_height
            )));
        }
        if self.min_confirmations < -1 {
            return Err(WalletAdminError::BadRequest(format!(
                "minConfirmations must be >= -1, got {}",
                self.min_confirmations
            )));
        }
        if self.min_confirmations == -1 && self.max_inclusion_height != -1 {
            return Err(WalletAdminError::BadRequest(
                "maxInclusionHeight cannot be specified when minConfirmations=-1 (unconfirmed)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

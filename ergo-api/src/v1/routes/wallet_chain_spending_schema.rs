//! OpenAPI mirrors of the portable, versioned spending wire contract.

use utoipa::ToSchema;

use super::{WalletChainBlock, WalletChainHeader, WalletChainTip};

#[derive(ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletChainBlockAtResponse {
    pub tip: WalletChainTip,
    pub block: WalletChainBlock,
}

#[derive(ToSchema)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum WalletChainAdmissionResponse {
    Accepted {
        #[schema(rename = "txId")]
        tx_id: String,
    },
    Duplicate {
        #[schema(rename = "txId")]
        tx_id: String,
    },
    Rejected {
        reason: String,
        detail: Option<String>,
    },
}

#[derive(ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletSpendingParameters {
    pub missing_core_parameters: u16,
    pub epoch_start_height: u32,
    pub block_version: u8,
    pub storage_fee_factor: i32,
    pub min_value_per_byte: i32,
    pub max_block_size: i32,
    pub max_block_cost: i32,
    pub token_access_cost: i32,
    pub input_cost: i32,
    pub data_input_cost: i32,
    pub output_cost: i32,
    pub subblocks_per_block: Option<i32>,
    pub extra: Vec<(u8, i32)>,
    pub proposed_update: String,
    pub activated_update: String,
    pub announced_settings: Option<String>,
}

#[derive(ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletSpendingPreHeader {
    pub version: u8,
    pub parent_id: String,
    pub height: u32,
    pub timestamp: u64,
    pub n_bits: u32,
    pub votes: [u8; 3],
    pub miner_pubkey: String,
}

#[derive(ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum WalletSpendingPreHeaderSource {
    SyntheticCommittedTip,
}

#[derive(ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletSpendingMonetaryParameters {
    pub fixed_rate: u64,
    pub fixed_rate_period: u32,
    pub epoch_length: u32,
    pub one_epoch_reduction: u64,
    pub founders_initial_reward: u64,
    pub miner_reward_delay: u32,
}

#[derive(ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletSpendingEmissionRules {
    pub monetary: WalletSpendingMonetaryParameters,
    pub emission_nft_id: String,
    pub emission_tree: String,
}

#[derive(ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletSpendingReemissionRules {
    pub check_rules: bool,
    pub emission: Option<WalletSpendingEmissionRules>,
    pub activation_height: u32,
    pub reemission_token_id: String,
    pub pay_to_reemission_tree: String,
}

#[derive(ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WalletSpendingContext {
    pub version: u16,
    pub network: String,
    pub tip: WalletChainTip,
    pub headers: Vec<WalletChainHeader>,
    pub pre_header: WalletSpendingPreHeader,
    pub pre_header_source: WalletSpendingPreHeaderSource,
    pub previous_state_digest: String,
    pub parameters: WalletSpendingParameters,
    pub validation_settings: String,
    pub reemission: Option<WalletSpendingReemissionRules>,
    pub pruned: bool,
    pub minimum_history_height: Option<u32>,
    pub min_relay_fee_nano_erg: u64,
    pub max_tx_size_bytes: u32,
    pub mempool_sequence: u64,
    pub mempool_transactions: Vec<String>,
    pub private_mining_configured: bool,
    pub private_queue_revision: Option<u64>,
    pub private_reserved_inputs: Vec<String>,
}

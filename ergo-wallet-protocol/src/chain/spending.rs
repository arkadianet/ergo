//! Versioned inputs for an owned, operation-scoped wallet signing context.
//!
//! Headers and mempool transactions carry their original consensus bytes.
//! Adopted settings use the consensus validation-settings codec; parameter
//! fields are explicit, rather than exposing the node's internal database codec.

use serde::{Deserialize, Serialize};

use super::{ChainBlock, ChainHeader, ChainTip};

pub const SPENDING_CONTEXT_VERSION: u16 = 1;
pub const MAX_SPENDING_CONTEXT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockAtResponse {
    pub tip: ChainTip,
    pub block: ChainBlock,
}

/// Exact node admission outcome; rejection reason codes remain structured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum AdmissionResponse {
    Accepted {
        #[serde(rename = "txId")]
        tx_id: String,
    },
    Duplicate {
        #[serde(rename = "txId")]
        tx_id: String,
    },
    Rejected {
        reason: String,
        detail: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendingParameters {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendingPreHeader {
    pub version: u8,
    pub parent_id: String,
    pub height: u32,
    pub timestamp: u64,
    pub n_bits: u32,
    pub votes: [u8; 3],
    pub miner_pubkey: String,
}

/// Explicit provenance: the embedded wallet currently signs using a synthetic
/// successor of the committed tip, not an advertised mining candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SpendingPreHeaderSource {
    SyntheticCommittedTip,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendingMonetaryParameters {
    pub fixed_rate: u64,
    pub fixed_rate_period: u32,
    pub epoch_length: u32,
    pub one_epoch_reduction: u64,
    pub founders_initial_reward: u64,
    pub miner_reward_delay: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendingEmissionRules {
    pub monetary: SpendingMonetaryParameters,
    pub emission_nft_id: String,
    pub emission_tree: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendingReemissionRules {
    pub check_rules: bool,
    pub emission: Option<SpendingEmissionRules>,
    pub activation_height: u32,
    pub reemission_token_id: String,
    pub pay_to_reemission_tree: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendingContext {
    pub version: u16,
    pub network: String,
    pub tip: ChainTip,
    pub headers: Vec<ChainHeader>,
    pub pre_header: SpendingPreHeader,
    pub pre_header_source: SpendingPreHeaderSource,
    /// The committed AVL+ digest, including its height byte (33 bytes).
    pub previous_state_digest: String,
    pub parameters: SpendingParameters,
    /// Complete adopted update from initial settings, not a proposed delta.
    pub validation_settings: String,
    pub reemission: Option<SpendingReemissionRules>,
    pub pruned: bool,
    pub minimum_history_height: Option<u32>,
    pub min_relay_fee_nano_erg: u64,
    pub max_tx_size_bytes: u32,
    /// Monotonic publication number within this node process. The full pool
    /// below belongs to this publication and its committed full-block tip.
    pub mempool_sequence: u64,
    /// Complete canonical admitted transactions, including spending proofs.
    /// The receiver derives pool outputs and input reservations from these.
    pub mempool_transactions: Vec<String>,
    pub private_mining_configured: bool,
    pub private_queue_revision: Option<u64>,
    pub private_reserved_inputs: Vec<String>,
}

//! Exact-template operator inspection. All monetary/token amounts are decimal
//! strings, preserving precision in browser clients. These DTOs must only be
//! served behind the operator API-key gate.

use crate::mining::CandidateMetricsJson;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateDetailsJson {
    pub msg: String,
    pub template_seq: u64,
    pub parent_id: String,
    pub height: u32,
    /// `current`, `superseded`, `stale_parent`, or `withdrawn`.
    pub status: String,
    pub published_at_ms: u64,
    pub age_ms: u64,
    pub build_reason: String,
    pub build_mode: String,
    pub metrics: CandidateMetricsJson,
    pub votes: [u8; 3],
    pub extensions: Vec<ExtensionPreviewJson>,
    pub transactions: Vec<CandidateTransactionJson>,
    pub rewards: RewardBreakdownJson,
    pub rent: RentBreakdownJson,
    pub exclusions: Vec<CandidateExclusionJson>,
    pub policy_revision: u64,
    pub operator_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionPreviewJson {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateTransactionJson {
    pub index: usize,
    pub id: String,
    pub category: String,
    pub fee_nano_erg: String,
    pub size_bytes: usize,
    /// Null on old/uninstrumented fixtures, never presented as measured zero.
    pub validation_cost: Option<u64>,
    pub input_ids: Vec<String>,
    pub data_input_ids: Vec<String>,
    pub outputs: Vec<CandidateOutputJson>,
    /// Canonical signed bytes for offline inspection/export.
    pub bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateOutputJson {
    pub index: usize,
    pub box_id: String,
    pub value_nano_erg: String,
    pub creation_height: u32,
    pub ergo_tree: String,
    pub assets: Vec<MiningAssetJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MiningAssetJson {
    pub token_id: String,
    pub amount: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardBreakdownJson {
    pub emission_nano_erg: String,
    pub fees_nano_erg: String,
    pub rent_nano_erg: String,
    pub total_nano_erg: String,
    pub outputs: Vec<MinerProceedsJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MinerProceedsJson {
    pub category: String,
    pub transaction_id: String,
    pub output_index: usize,
    pub box_id: String,
    pub value_nano_erg: String,
    pub address: String,
    pub assets: Vec<MiningAssetJson>,
    pub spendable_at_height: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RentBreakdownJson {
    /// A bounded build scan, not the global eligible backlog.
    pub scanned_boxes: usize,
    pub selected_boxes: usize,
    pub recreated_boxes: usize,
    pub consumed_boxes: usize,
    pub skipped_to_preserve_tokens: usize,
    pub collected_nano_erg: String,
    pub recovered_tokens: Vec<MiningAssetJson>,
    pub burned_tokens: Vec<MiningAssetJson>,
    pub claims: Vec<RentInputJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RentInputJson {
    pub box_id: String,
    pub creation_height: u32,
    pub age_blocks: u32,
    pub input_value_nano_erg: String,
    pub collected_nano_erg: String,
    pub branch: String,
    pub recreated_output_index: Option<usize>,
    pub input_assets: Vec<MiningAssetJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateExclusionJson {
    pub transaction_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MiningHistoryJson {
    pub retention: usize,
    pub retained_templates: Vec<TemplateSummaryJson>,
    pub outcomes: Vec<MiningOutcomeJson>,
    pub resets_on_restart: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateSummaryJson {
    pub msg: String,
    pub template_seq: u64,
    pub parent_id: String,
    pub height: u32,
    pub published_at_ms: u64,
    pub status: String,
    pub build_reason: String,
    pub build_mode: String,
    pub transaction_count: u32,
    pub fees_nano_erg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MiningOutcomeJson {
    pub msg: Option<String>,
    pub template_seq: Option<u64>,
    pub block_id: Option<String>,
    pub at_ms: u64,
    pub outcome: String,
    pub detail: Option<String>,
}

/// Public freshness contains no transaction IDs, values, or wallet contents.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MiningFreshnessJson {
    pub mining_started: bool,
    pub last_template_msg: Option<String>,
    pub last_template_height: Option<u32>,
    pub last_template_age_ms: Option<u64>,
    pub template_seq: Option<u64>,
}

//! JSON deserialization types for the block API response (`POST /blocks/headerIds`).
//!
//! These are the *inbound* counterparts of the `*Response` types in `api/mod.rs`
//! (which are `Serialize`-only for outbound). We keep them separate so that
//! future wire-conversion code can live alongside these types without touching
//! the API module.

use serde::Deserialize;

/// Top-level block returned by `POST /blocks/headerIds`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonFullBlock {
    pub header: JsonBlockHeader,
    pub block_transactions: Option<JsonBlockTransactions>,
    pub extension: Option<JsonExtension>,
    pub ad_proofs: Option<serde_json::Value>,
    pub size: usize,
}

/// Minimal block header fields needed for wire conversion.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonBlockHeader {
    pub id: String,
    pub height: u32,
    pub version: u8,
}

/// Block transactions section.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonBlockTransactions {
    pub header_id: String,
    pub transactions: Vec<JsonTransaction>,
    pub block_version: u8,
}

/// A single transaction.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonTransaction {
    pub id: String,
    pub inputs: Vec<JsonInput>,
    pub data_inputs: Vec<JsonDataInput>,
    pub outputs: Vec<JsonOutput>,
}

/// Transaction input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonInput {
    pub box_id: String,
    pub spending_proof: JsonSpendingProof,
}

/// Spending proof attached to an input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonSpendingProof {
    pub proof_bytes: String,
    pub extension: serde_json::Value,
}

/// Data input (read-only box reference).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonDataInput {
    pub box_id: String,
}

/// Transaction output (box).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonOutput {
    pub box_id: Option<String>,
    pub value: u64,
    pub ergo_tree: String,
    pub creation_height: u32,
    pub assets: Vec<JsonAsset>,
    pub additional_registers: serde_json::Value,
    pub transaction_id: Option<String>,
    pub index: Option<u16>,
}

/// Token asset inside an output.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonAsset {
    pub token_id: String,
    pub amount: u64,
}

/// Extension section of a block.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonExtension {
    pub header_id: String,
    pub fields: Vec<(String, String)>,
}

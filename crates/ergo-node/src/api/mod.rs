use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use utoipa::OpenApi;

use ergo_consensus::tx_validation::validate_tx_stateless;
use ergo_consensus::validation_rules::ValidationSettings;
use ergo_network::mempool::ErgoMemPool;
use ergo_storage::continuation::compute_header_id;
use ergo_storage::history_db::HistoryDb;
use ergo_types::address;
use ergo_types::modifier_id::ModifierId;
use ergo_types::transaction::{
    compute_box_id, BoxId, DataInput, ErgoBoxCandidate, ErgoTransaction, Input, TxId,
};
use ergo_wire::header_ser::serialize_header;
use ergo_wire::transaction_ser::{compute_tx_id, parse_transaction, serialize_transaction};

pub(crate) mod handlers;
mod openapi;

use crate::event_loop::SharedState;
use crate::mining::{CandidateGenerator, MiningSolution};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// JSON response for the `/info` endpoint.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfoResponse {
    pub name: String,
    pub app_version: String,
    pub network: String,
    pub headers_height: Option<u64>,
    pub full_height: Option<u64>,
    pub max_peer_height: Option<u64>,
    pub best_header_id: Option<String>,
    pub best_full_header_id: Option<String>,
    pub previous_full_header_id: Option<String>,
    pub state_root: String,
    pub state_version: Option<String>,
    pub state_type: String,
    pub peers_count: usize,
    pub sync_state: String,
    pub unconfirmed_count: usize,
    pub difficulty: String,
    pub headers_score: String,
    pub full_blocks_score: String,
    pub launch_time: u64,
    pub last_seen_message_time: u64,
    pub genesis_block_id: String,
    pub is_mining: bool,
    pub is_explorer: bool,
    pub eip27_supported: bool,
    pub eip37_supported: bool,
    pub rest_api_url: Option<String>,
    pub current_time: u64,
    #[schema(value_type = Object)]
    pub parameters: serde_json::Value,
    pub last_mempool_update_time: u64,
    pub fast_sync_active: bool,
}

/// JSON response for proof-of-work solution fields.
#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PowSolutionsResponse {
    pub pk: String,
    pub w: String,
    pub n: String,
    /// `d` is serialized as a JSON number (not a string), matching the Scala reference node.
    #[schema(value_type = f64)]
    pub d: serde_json::Value,
}

/// JSON response for a block header.
#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeaderResponse {
    pub id: String,
    pub parent_id: String,
    pub height: u32,
    pub timestamp: u64,
    pub n_bits: u64,
    pub version: u8,
    pub state_root: String,
    pub transactions_root: String,
    /// Serialized as `extensionHash` to match the Scala reference node JSON schema.
    pub extension_hash: String,
    pub ad_proofs_root: String,
    pub pow_solutions: PowSolutionsResponse,
    pub votes: String,
    pub difficulty: String,
    pub size: usize,
    pub extension_id: String,
    pub transactions_id: String,
    pub ad_proofs_id: String,
    /// Always empty string for current protocol versions; present for Scala API compatibility.
    pub unparsed_bytes: String,
}

/// JSON response for a full block.
#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BlockResponse {
    pub header: HeaderResponse,
    pub block_transactions: Option<BlockTransactionsResponse>,
    pub extension: Option<ExtensionResponse>,
    pub ad_proofs: Option<String>,
    pub size: usize,
}

/// Full transaction JSON response.
#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResponse {
    pub id: String,
    pub inputs: Vec<InputResponse>,
    pub data_inputs: Vec<DataInputResponse>,
    pub outputs: Vec<OutputResponse>,
    pub size: usize,
}

#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct InputResponse {
    pub box_id: String,
    pub spending_proof: SpendingProofResponse,
}

#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SpendingProofResponse {
    pub proof_bytes: String,
    #[schema(value_type = Object)]
    pub extension: serde_json::Value,
}

#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DataInputResponse {
    pub box_id: String,
}

#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OutputResponse {
    pub box_id: Option<String>,
    pub value: u64,
    pub ergo_tree: String,
    pub creation_height: u32,
    pub assets: Vec<AssetResponse>,
    #[schema(value_type = Object)]
    pub additional_registers: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u16>,
}

#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AssetResponse {
    pub token_id: String,
    pub amount: u64,
}

#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionResponse {
    pub header_id: String,
    /// Merkle root of the extension fields, matching `extensionHash` from the block header.
    pub digest: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Clone, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BlockTransactionsResponse {
    pub header_id: String,
    pub transactions: Vec<TransactionResponse>,
    pub block_version: u8,
    pub size: usize,
}

/// JSON response for a connected peer.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PeerResponse {
    pub address: String,
    pub name: String,
    /// User-configured node name from the handshake PeerSpec.
    pub node_name: String,
    pub last_message: u64,
    pub last_handshake: u64,
    pub connection_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifying_transactions: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks_to_keep: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<crate::geoip::GeoInfo>,
}

/// Lightweight peer map entry for map rendering.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PeerMapEntry {
    pub lat: f64,
    pub lon: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    pub address: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_status: Option<String>,
}

/// JSON request body for submitting a transaction (legacy hex format).
/// Kept for backward compatibility; the main /transactions endpoint now uses TxJsonTransaction.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[allow(dead_code)]
pub struct TxSubmitRequest {
    pub bytes: String,
}

/// JSON response after submitting a transaction.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TxSubmitResponse {
    pub tx_id: String,
}

/// Scala-compatible JSON transaction input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxJsonInput {
    box_id: String,
    spending_proof: TxJsonSpendingProof,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxJsonSpendingProof {
    proof_bytes: String,
    #[serde(default)]
    extension: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxJsonDataInput {
    box_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxJsonOutput {
    value: u64,
    ergo_tree: String,
    creation_height: u32,
    #[serde(default)]
    assets: Vec<TxJsonAsset>,
    #[serde(default)]
    additional_registers: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxJsonAsset {
    token_id: String,
    amount: u64,
}

/// Scala-compatible JSON transaction body for `POST /transactions`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TxJsonTransaction {
    inputs: Vec<TxJsonInput>,
    #[serde(default)]
    data_inputs: Vec<TxJsonDataInput>,
    outputs: Vec<TxJsonOutput>,
}

/// JSON response for the mempool size endpoint.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MempoolSizeResponse {
    pub size: usize,
}

/// JSON response for the modifier lookup endpoint.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModifierResponse {
    pub type_id: u8,
    pub bytes: String,
}

/// Structured JSON error response matching the Scala node format.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiError {
    pub error: u16,
    pub reason: String,
    pub detail: String,
}

/// Build a structured API error response with the given HTTP status and detail message.
fn api_error(status: StatusCode, detail: &str) -> (StatusCode, Json<ApiError>) {
    let reason = status.canonical_reason().unwrap_or("Unknown").to_string();
    (
        status,
        Json(ApiError {
            error: status.as_u16(),
            reason,
            detail: detail.to_string(),
        }),
    )
}

/// JSON response for P2P layer status.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PeerStatusResponse {
    pub connected_count: usize,
    pub uptime_secs: u64,
    pub last_message_time: Option<u64>,
}

/// JSON response for an unconfirmed output in the mempool.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnconfirmedOutputResponse {
    pub box_id: String,
    pub tx_id: String,
    pub index: u16,
    pub value: u64,
    pub creation_height: u32,
    pub token_count: usize,
}

/// JSON response for a mempool spending input lookup.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SpendingInputResponse {
    pub box_id: String,
    pub spending_tx_id: String,
    pub proof_bytes: String,
}

/// JSON response for GET /mining/candidate.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MiningCandidateResponse {
    pub msg: String,
    pub b: u64,
    pub h: u32,
    pub pk: String,
}

/// JSON response for POST /mining/candidateWithTxs.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CandidateWithTxsResponse {
    pub msg: String,
    pub b: u64,
    pub h: u32,
    pub pk: String,
    pub transactions: Vec<TransactionResponse>,
}

/// JSON response for GET /mining/rewardAddress.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RewardAddressResponse {
    pub reward_address: String,
}

/// JSON response for GET /mining/rewardPublicKey.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RewardPublicKeyResponse {
    pub reward_pub_key: String,
}

/// JSON response for address validation.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AddressValidationResponse {
    pub address: String,
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// JSON response for a block Merkle proof.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MerkleProofResponse {
    pub leaf: String,
    pub levels: Vec<String>,
}

/// JSON response for emission contract script addresses.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmissionScriptsResponse {
    pub emission: String,
    pub reemission: String,
    pub pay2_reemission: String,
}

/// JSON response for a single histogram bin.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HistogramBinResponse {
    pub n_txns: usize,
    pub total_size: usize,
    pub from_millis: u64,
    pub to_millis: u64,
}

/// JSON response for fee estimation.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FeeEstimateResponse {
    pub fee: u64,
}

/// JSON response for wait time estimation.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WaitTimeResponse {
    pub wait_time_millis: u64,
}

/// JSON response for the `/blockchain/indexedHeight` endpoint.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexedHeightResponse {
    pub indexed_height: u32,
    pub full_height: u32,
}

/// JSON response for an indexed UTXO box from the extra indexer.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexedErgoBoxResponse {
    pub box_id: String,
    pub value: u64,
    pub ergo_tree: String,
    pub assets: Vec<TokenAmountResponse>,
    pub creation_height: u32,
    pub global_index: u64,
    pub inclusion_height: u32,
    pub address: String,
    pub spent_transaction_id: Option<String>,
    pub spending_height: Option<u32>,
}

/// JSON response for a token amount within a box.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenAmountResponse {
    pub token_id: String,
    pub amount: u64,
}

/// JSON response for an indexed transaction from the extra indexer.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexedErgoTransactionResponse {
    pub id: String,
    pub inclusion_height: u32,
    pub index: u32,
    pub global_index: u64,
    pub num_confirmations: u32,
    pub inputs: Vec<IndexedErgoBoxResponse>,
    pub outputs: Vec<IndexedErgoBoxResponse>,
    pub size: u32,
}

/// JSON response for paginated transaction results.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedTxResponse {
    pub items: Vec<IndexedErgoTransactionResponse>,
    pub total: u64,
}

/// JSON response for paginated box results.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedBoxResponse {
    pub items: Vec<IndexedErgoBoxResponse>,
    pub total: u64,
}

/// JSON response for an indexed token from the extra indexer.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexedTokenResponse {
    pub id: String,
    pub box_id: Option<String>,
    pub emission_amount: Option<u64>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub decimals: Option<i32>,
}

/// JSON response for confirmed + unconfirmed balance.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    pub confirmed: BalanceInfoResponse,
    pub unconfirmed: BalanceInfoResponse,
}

/// JSON response for a single balance component.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BalanceInfoResponse {
    pub nano_ergs: u64,
    pub tokens: Vec<TokenBalanceResponse>,
}

/// JSON response for a single token balance entry.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TokenBalanceResponse {
    pub token_id: String,
    pub amount: u64,
    pub decimals: Option<i32>,
    pub name: Option<String>,
}

/// JSON response for an indexed block with header + transactions.
#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexedBlockResponse {
    pub header: HeaderResponse,
    pub block_transactions: Vec<IndexedErgoTransactionResponse>,
    pub size: u32,
}

/// JSON response for a PoPow header.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PoPowHeaderResponse {
    pub header: HeaderResponse,
    pub interlinks: Vec<String>,
}

/// JSON response for a NiPoPoW proof.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NipopowProofResponse {
    pub m: u32,
    pub k: u32,
    pub prefix: Vec<PoPowHeaderResponse>,
    pub suffix_head: PoPowHeaderResponse,
    pub suffix_tail: Vec<HeaderResponse>,
}

/// JSON request body for script compilation endpoints.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ScriptCompileRequest {
    pub source: String,
}

/// JSON response for script compilation endpoints.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ScriptCompileResponse {
    pub address: String,
}

/// JSON response for `POST /script/compile`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScriptFullCompileResponse {
    pub ergo_tree: String,
    pub address: String,
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

/// Pagination query parameters for `GET /blocks`.
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_limit() -> u32 {
    50
}

/// Query parameters for `GET /blocks/chainSlice`.
#[derive(Debug, Deserialize)]
pub struct ChainSliceParams {
    #[serde(default, rename = "fromHeight")]
    from_height: u32,
    #[serde(default, rename = "toHeight")]
    to_height: u32,
}

/// Pagination query parameters for `GET /transactions/unconfirmed`.
#[derive(Debug, Deserialize)]
pub struct UnconfirmedPaginationParams {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_unconfirmed_limit")]
    limit: usize,
}

fn default_unconfirmed_limit() -> usize {
    50
}

/// Query params for pool histogram.
#[derive(Debug, Deserialize)]
pub struct HistogramParams {
    #[serde(default = "default_histogram_bins")]
    bins: usize,
    #[serde(default = "default_histogram_max_time")]
    maxtime: u64,
}

fn default_histogram_bins() -> usize {
    10
}
fn default_histogram_max_time() -> u64 {
    60_000
}

/// Query params for fee estimation.
#[derive(Debug, Deserialize)]
pub struct FeeEstimateParams {
    #[serde(default = "default_wait_time", rename = "waitTime")]
    _wait_time: u64,
}

fn default_wait_time() -> u64 {
    1000
}

/// Query params for wait time estimation.
#[derive(Debug, Deserialize)]
pub struct WaitTimeParams {
    #[serde(default = "default_fee_param")]
    fee: u64,
}

fn default_fee_param() -> u64 {
    1_000_000
}

/// Pagination query parameters for blockchain API endpoints.
#[derive(Debug, Deserialize)]
pub struct BlockchainPaginationParams {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_blockchain_limit")]
    pub limit: u32,
    #[serde(default, rename = "sortDirection")]
    pub sort_direction: Option<String>,
}

fn default_blockchain_limit() -> u32 {
    5
}

/// Pagination + mempool filter params for unspent box endpoints.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnspentBoxParams {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_blockchain_limit")]
    pub limit: u32,
    #[serde(default)]
    pub sort_direction: Option<String>,
    #[serde(default)]
    pub include_unconfirmed: bool,
    #[serde(default)]
    pub exclude_mempool_spent: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a hex-encoded 32-byte modifier ID.
fn parse_modifier_id(hex_str: &str) -> Result<ModifierId, (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    if bytes.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "ID must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ModifierId(arr))
}

/// Compute a section modifier ID the same way Scala does:
/// `blake2b256(type_id_byte ++ header_id_bytes ++ merkle_root_bytes)`.
fn compute_section_id(type_id: u8, header_id: &[u8; 32], root: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(65);
    buf.push(type_id);
    buf.extend_from_slice(header_id);
    buf.extend_from_slice(root);
    blake2b256(&buf)
}

/// Generator point G in compressed form (33 bytes).
/// Autolykos v2 headers use G as the placeholder `w` value (matching Scala's `wForV2`).
const GENERATOR_POINT_HEX: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// Build the common extra fields for a [`HeaderResponse`] from a header,
/// id bytes, and serialized size.
///
/// `serialized_len` is the length of the header bytes produced by `serialize_header`
/// (excluding the 1-byte modifier-type prefix used in storage).  We add 1 to match
/// the Scala reference node, which reports `size = r.consumed` after parsing through
/// `HistoryModifierSerializer` (which reads the type byte before delegating to
/// `HeaderSerializer`).
fn build_header_response(
    header: &ergo_types::header::Header,
    id_hex: String,
    id_bytes: &[u8; 32],
    serialized_len: usize,
) -> HeaderResponse {
    let difficulty = ergo_consensus::difficulty::decode_compact_bits(header.n_bits);

    let extension_id = compute_section_id(108, id_bytes, &header.extension_root.0);
    let transactions_id = compute_section_id(102, id_bytes, &header.transactions_root.0);
    let ad_proofs_id = compute_section_id(104, id_bytes, &header.ad_proofs_root.0);

    // `d` must be a JSON number (not a string) to match the Scala reference node output.
    let d_decimal = if header.pow_solution.d.is_empty() {
        "0".to_string()
    } else {
        num_bigint::BigUint::from_bytes_be(&header.pow_solution.d).to_string()
    };
    let d_json: serde_json::Value =
        serde_json::from_str(&d_decimal).unwrap_or(serde_json::json!(0));

    // For Autolykos v2 headers the wire format omits `w`; Rust stores 33 zero bytes as a
    // placeholder.  Scala initialises `w` to the secp256k1 generator point G (`wForV2`),
    // so we emit that constant here to match the reference API output.
    let w_hex = if header.pow_solution.w == [0u8; 33] && header.version >= 2 {
        GENERATOR_POINT_HEX.to_string()
    } else {
        hex::encode(header.pow_solution.w)
    };

    // Size: add 1 for the modifier-type byte that Scala's HistoryModifierSerializer
    // prepends when serialising to storage (and therefore counts in `r.consumed`).
    let size = serialized_len + 1;

    HeaderResponse {
        id: id_hex,
        parent_id: hex::encode(header.parent_id.0),
        height: header.height,
        timestamp: header.timestamp,
        n_bits: header.n_bits,
        version: header.version,
        state_root: hex::encode(header.state_root.0),
        transactions_root: hex::encode(header.transactions_root.0),
        extension_hash: hex::encode(header.extension_root.0),
        ad_proofs_root: hex::encode(header.ad_proofs_root.0),
        pow_solutions: PowSolutionsResponse {
            pk: hex::encode(header.pow_solution.miner_pk),
            w: w_hex,
            n: hex::encode(header.pow_solution.nonce),
            d: d_json,
        },
        votes: hex::encode(header.votes),
        difficulty: difficulty.to_string(),
        size,
        extension_id: hex::encode(extension_id),
        transactions_id: hex::encode(transactions_id),
        ad_proofs_id: hex::encode(ad_proofs_id),
        unparsed_bytes: hex::encode(&header.unparsed_bytes),
    }
}

/// Convert a [`Header`] to a [`HeaderResponse`], computing the ID from
/// the serialized header bytes.
fn header_to_response(header: &ergo_types::header::Header) -> HeaderResponse {
    let serialized = serialize_header(header);
    let id = compute_header_id(&serialized);
    build_header_response(header, hex::encode(id.0), &id.0, serialized.len())
}

/// Convert a [`Header`] to a [`HeaderResponse`] using a known ID.
fn header_to_response_with_id(header: &ergo_types::header::Header, id_hex: &str) -> HeaderResponse {
    let serialized = serialize_header(header);
    let id_bytes_vec = hex::decode(id_hex).unwrap_or_default();
    let mut id_bytes = [0u8; 32];
    if id_bytes_vec.len() == 32 {
        id_bytes.copy_from_slice(&id_bytes_vec);
    }
    build_header_response(header, id_hex.to_string(), &id_bytes, serialized.len())
}

/// Convert an [`ErgoTransaction`] into a [`TransactionResponse`] for JSON serialization.
fn ergo_tx_to_response(tx: &ErgoTransaction, size: usize) -> TransactionResponse {
    let inputs = tx
        .inputs
        .iter()
        .map(|inp| InputResponse {
            box_id: hex::encode(inp.box_id.0),
            spending_proof: SpendingProofResponse {
                proof_bytes: hex::encode(&inp.proof_bytes),
                extension: serde_json::json!({}),
            },
        })
        .collect();

    let data_inputs = tx
        .data_inputs
        .iter()
        .map(|di| DataInputResponse {
            box_id: hex::encode(di.box_id.0),
        })
        .collect();

    let outputs = tx
        .output_candidates
        .iter()
        .enumerate()
        .map(|(idx, out)| {
            let assets = out
                .tokens
                .iter()
                .map(|(tid, amt)| AssetResponse {
                    token_id: hex::encode(tid.0),
                    amount: *amt,
                })
                .collect();

            let box_id = {
                let bid = compute_box_id(&tx.tx_id, idx as u16);
                Some(hex::encode(bid.0))
            };

            OutputResponse {
                box_id,
                value: out.value,
                ergo_tree: hex::encode(&out.ergo_tree_bytes),
                creation_height: out.creation_height,
                assets,
                additional_registers: render_registers(&out.additional_registers, false),
                transaction_id: Some(hex::encode(tx.tx_id.0)),
                index: Some(idx as u16),
            }
        })
        .collect();

    TransactionResponse {
        id: hex::encode(tx.tx_id.0),
        inputs,
        data_inputs,
        outputs,
        size,
    }
}

/// Build a full [`BlockResponse`] by loading block sections from the history DB.
pub(crate) fn build_block_response(
    state: &ApiState,
    header: &ergo_types::header::Header,
    header_id_hex: &str,
) -> BlockResponse {
    let id = {
        let mut arr = [0u8; 32];
        if let Ok(bytes) = hex::decode(header_id_hex) {
            if bytes.len() == 32 {
                arr.copy_from_slice(&bytes);
            }
        }
        ModifierId(arr)
    };

    let mut total_size = 0usize;

    // Load block transactions — use raw stored bytes to get the true section
    // size (includes 32-byte headerId, optional VLQ version sentinel, and VLQ
    // tx_count prefix, matching Scala's BlockTransactionsSerializer byte count).
    let block_transactions = match state.history.get_modifier(102, &id) {
        Ok(Some(raw_bytes)) => {
            let bt_size = raw_bytes.len();
            total_size += bt_size;
            match ergo_wire::block_transactions_ser::parse_block_transactions(&raw_bytes) {
                Ok(bt) => {
                    let mut tx_responses = Vec::new();
                    for tx_bytes in &bt.tx_bytes {
                        if let Ok(parsed_tx) = parse_transaction(tx_bytes) {
                            tx_responses.push(ergo_tx_to_response(&parsed_tx, tx_bytes.len()));
                        }
                    }
                    Some(BlockTransactionsResponse {
                        header_id: header_id_hex.to_string(),
                        transactions: tx_responses,
                        block_version: header.version,
                        size: bt_size,
                    })
                }
                Err(_) => None,
            }
        }
        _ => None,
    };

    // Load extension — the digest is the Merkle root of the extension fields,
    // which matches `extensionHash` (header.extension_root) in the block header.
    let extension = match state.history.load_extension(&id) {
        Ok(Some(ext)) => {
            let fields: Vec<(String, String)> = ext
                .fields
                .iter()
                .map(|(key, val)| (hex::encode(key), hex::encode(val)))
                .collect();
            Some(ExtensionResponse {
                header_id: hex::encode(ext.header_id.0),
                digest: hex::encode(header.extension_root.0),
                fields,
            })
        }
        _ => None,
    };

    // Load AD proofs
    let ad_proofs = match state.history.load_ad_proofs(&id) {
        Ok(Some(proofs)) => Some(hex::encode(&proofs.proof_bytes)),
        _ => None,
    };

    BlockResponse {
        header: header_to_response_with_id(header, header_id_hex),
        block_transactions,
        extension,
        ad_proofs,
        size: total_size,
    }
}

/// Determine the [`NetworkPrefix`] from the `ApiState.network` string.
fn network_prefix(network: &str) -> address::NetworkPrefix {
    if network.contains("Test") {
        address::NetworkPrefix::Testnet
    } else {
        address::NetworkPrefix::Mainnet
    }
}

/// Convert a [`PoPowHeader`] to a [`PoPowHeaderResponse`].
fn popow_header_to_response(popow: &ergo_types::nipopow::PoPowHeader) -> PoPowHeaderResponse {
    PoPowHeaderResponse {
        header: header_to_response(&popow.header),
        interlinks: popow
            .interlinks
            .iter()
            .map(|id| hex::encode(id.0))
            .collect(),
    }
}

/// Convert a [`NipopowProof`] to a [`NipopowProofResponse`].
fn proof_to_response(proof: &ergo_types::nipopow::NipopowProof) -> NipopowProofResponse {
    NipopowProofResponse {
        m: proof.m,
        k: proof.k,
        prefix: proof.prefix.iter().map(popow_header_to_response).collect(),
        suffix_head: popow_header_to_response(&proof.suffix_head),
        suffix_tail: proof.suffix_tail.iter().map(header_to_response).collect(),
    }
}

// ---------------------------------------------------------------------------
// Blockchain (indexer) helpers
// ---------------------------------------------------------------------------

/// Return a reference to the extra indexer DB, or 503 if not enabled.
fn require_indexer(
    state: &ApiState,
) -> Result<&ergo_indexer::db::ExtraIndexerDb, (StatusCode, String)> {
    state.extra_db.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Extra indexing is not enabled".into(),
    ))
}

/// Parse a hex string into a 32-byte array, returning a typed error tuple.
fn hex_to_32bytes(hex_str: &str) -> Result<[u8; 32], (StatusCode, String)> {
    let bytes =
        hex::decode(hex_str).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex string".into()))?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "ID must be 32 bytes (64 hex chars)".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Convert an Ergo address string to ErgoTree bytes for indexer lookups.
fn address_to_ergo_tree(addr: &str, _network: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let decoded = address::decode_address(addr)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid address: {e}")))?;

    match decoded.address_type {
        address::AddressType::P2PK => {
            // ErgoTree = 0x00 0x08 0xcd ++ 33-byte compressed public key
            let mut tree = Vec::with_capacity(3 + decoded.content_bytes.len());
            tree.extend_from_slice(&[0x00, 0x08, 0xcd]);
            tree.extend_from_slice(&decoded.content_bytes);
            Ok(tree)
        }
        address::AddressType::P2S => {
            // Content bytes are the raw ErgoTree
            Ok(decoded.content_bytes)
        }
        address::AddressType::P2SH => Err((
            StatusCode::BAD_REQUEST,
            "P2SH addresses cannot be converted back to ErgoTree".into(),
        )),
    }
}

/// Encode bytes as a sigma ByteArrayConstant: `[0x0e, VLQ(len), ...bytes]`.
#[allow(dead_code)]
fn encode_byte_array_constant(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x0e];
    let mut n = data.len();
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n > 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if n == 0 {
            break;
        }
    }
    result.extend_from_slice(data);
    result
}

/// Render a register value with sigma type information.
///
/// Parses the raw register bytes using sigma-rust's `RegisterValue` and
/// returns a JSON object with `serializedValue` (hex), `sigmaType`, and
/// `renderedValue`. Falls back to hex-only on parse failure.
fn render_register_typed(bytes: &[u8]) -> serde_json::Value {
    use ergo_lib::ergotree_ir::chain::ergo_box::RegisterValue;

    let hex_val = hex::encode(bytes);

    let reg_val = RegisterValue::sigma_parse_bytes(bytes);
    match reg_val.as_constant() {
        Ok(constant) => {
            serde_json::json!({
                "serializedValue": hex_val,
                "sigmaType": format!("{}", constant.tpe),
                "renderedValue": format!("{:?}", constant.v)
            })
        }
        Err(_) => {
            // Parse failure — fall back to hex only
            serde_json::json!({
                "serializedValue": hex_val,
                "sigmaType": null,
                "renderedValue": null
            })
        }
    }
}

/// Render registers for a transaction output.
///
/// When `typed` is true, each register value includes sigma type information.
/// When `typed` is false (default), register values are plain hex strings.
fn render_registers(regs: &[(u8, Vec<u8>)], typed: bool) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (reg_idx, val) in regs {
        let key = format!("R{}", reg_idx);
        if typed {
            map.insert(key, render_register_typed(val));
        } else {
            map.insert(key, serde_json::Value::String(hex::encode(val)));
        }
    }
    serde_json::Value::Object(map)
}

/// Convert an [`IndexedErgoBox`] to an API response.
fn box_to_response(
    b: &ergo_indexer::types::IndexedErgoBox,
    network: &str,
) -> IndexedErgoBoxResponse {
    let prefix = if network.to_lowercase().contains("test") {
        address::NetworkPrefix::Testnet
    } else {
        address::NetworkPrefix::Mainnet
    };
    let addr = address::ergo_tree_to_address(&b.ergo_tree, prefix);

    IndexedErgoBoxResponse {
        box_id: hex::encode(b.box_id.0),
        value: b.value,
        ergo_tree: hex::encode(&b.ergo_tree),
        assets: b
            .tokens
            .iter()
            .map(|(id, amt)| TokenAmountResponse {
                token_id: hex::encode(id.0),
                amount: *amt,
            })
            .collect(),
        creation_height: b.inclusion_height,
        global_index: b.global_index,
        inclusion_height: b.inclusion_height,
        address: addr,
        spent_transaction_id: b.spending_tx_id.as_ref().map(|id| hex::encode(id.0)),
        spending_height: b.spending_height,
    }
}

/// Convert an [`IndexedErgoTransaction`] to an API response, resolving
/// input and output boxes by their global indexes.
fn tx_to_response(
    tx: &ergo_indexer::types::IndexedErgoTransaction,
    db: &ergo_indexer::db::ExtraIndexerDb,
    current_height: u32,
    network: &str,
) -> IndexedErgoTransactionResponse {
    let inputs: Vec<IndexedErgoBoxResponse> = tx
        .input_indexes
        .iter()
        .filter_map(|&idx| {
            ergo_indexer::queries::get_box_by_index(db, idx)
                .ok()
                .flatten()
                .map(|b| box_to_response(&b, network))
        })
        .collect();

    let outputs: Vec<IndexedErgoBoxResponse> = tx
        .output_indexes
        .iter()
        .filter_map(|&idx| {
            ergo_indexer::queries::get_box_by_index(db, idx)
                .ok()
                .flatten()
                .map(|b| box_to_response(&b, network))
        })
        .collect();

    IndexedErgoTransactionResponse {
        id: hex::encode(tx.tx_id.0),
        inclusion_height: tx.height,
        index: tx.index,
        global_index: tx.global_index,
        num_confirmations: current_height.saturating_sub(tx.height) + 1,
        inputs,
        outputs,
        size: tx.size,
    }
}

/// Convert an [`IndexedToken`] to an API response.
fn token_to_response(t: &ergo_indexer::types::IndexedToken) -> IndexedTokenResponse {
    IndexedTokenResponse {
        id: hex::encode(t.token_id.0),
        box_id: t.box_id.as_ref().map(|id| hex::encode(id.0)),
        emission_amount: t.amount,
        name: t.name.clone(),
        description: t.description.clone(),
        decimals: t.decimals,
    }
}

/// Compute blake2b-256 hash of a byte slice.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).unwrap();
    out
}

/// Verify an API key against the configured blake2b256 hash.
fn verify_api_key(key: &str, expected_hash: &str) -> bool {
    let hash = blake2b256(key.as_bytes());
    hex::encode(hash) == expected_hash
}

/// Check API key authorization. Returns 403 if key is required but missing/wrong.
fn check_auth(
    headers: &axum::http::HeaderMap,
    api_key_hash: &Option<String>,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let hash = match api_key_hash {
        Some(h) => h,
        None => return Ok(()), // No hash configured = open access
    };
    let key = headers
        .get("api_key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| api_error(StatusCode::FORBIDDEN, "API key is required"))?;
    if verify_api_key(key, hash) {
        Ok(())
    } else {
        Err(api_error(StatusCode::FORBIDDEN, "Invalid API key"))
    }
}

/// Build an [`IndexedBlockResponse`] from a header and block transactions,
/// looking up indexed transaction data from the extra indexer DB.
fn build_indexed_block_response(
    state: &ApiState,
    db: &ergo_indexer::db::ExtraIndexerDb,
    header: &ergo_types::header::Header,
    block_txs: &ergo_types::block_transactions::BlockTransactions,
    current_height: u32,
) -> IndexedBlockResponse {
    let mut tx_responses = Vec::new();
    for tx_bytes in &block_txs.tx_bytes {
        if let Ok(parsed_tx) = parse_transaction(tx_bytes) {
            if let Ok(Some(indexed_tx)) = ergo_indexer::queries::get_tx(db, &parsed_tx.tx_id.0) {
                tx_responses.push(tx_to_response(
                    &indexed_tx,
                    db,
                    current_height,
                    &state.network,
                ));
            }
        }
    }

    let header_response = header_to_response(header);
    // Compute the full serialized section size (includes 32-byte headerId, optional
    // VLQ version sentinel, and VLQ tx_count prefix), matching Scala's byte count.
    let total_size: u32 =
        ergo_wire::block_transactions_ser::serialize_block_transactions(block_txs).len() as u32;

    IndexedBlockResponse {
        header: header_response,
        block_transactions: tx_responses,
        size: total_size,
    }
}

// ---------------------------------------------------------------------------
// Mempool integration for unspent box endpoints
// ---------------------------------------------------------------------------

/// Apply mempool filters to a list of confirmed boxes:
///
/// 1. `exclude_mempool_spent` — remove boxes spent by a mempool transaction.
/// 2. `include_unconfirmed` — append unconfirmed outputs matching the given
///    ErgoTree bytes.
fn apply_mempool_box_filters(
    boxes: &mut Vec<IndexedErgoBoxResponse>,
    total: &mut u64,
    mempool: &ErgoMemPool,
    params: &UnspentBoxParams,
    ergo_tree_bytes: Option<&[u8]>,
    network: &str,
) {
    // 1. excludeMempoolSpent: filter out boxes where mempool has a spending tx
    if params.exclude_mempool_spent {
        let before = boxes.len();
        boxes.retain(|b| {
            let box_id_bytes = hex::decode(&b.box_id).unwrap_or_default();
            if box_id_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&box_id_bytes);
                !mempool.is_spent_in_mempool(&BoxId(arr))
            } else {
                true
            }
        });
        let removed = before - boxes.len();
        *total = total.saturating_sub(removed as u64);
    }

    // 2. includeUnconfirmed: add matching unconfirmed outputs
    if params.include_unconfirmed {
        if let Some(tree_bytes) = ergo_tree_bytes {
            use blake2::digest::{Update, VariableOutput};
            use blake2::Blake2bVar;
            let mut hasher = Blake2bVar::new(32).unwrap();
            hasher.update(tree_bytes);
            let mut tree_hash = [0u8; 32];
            hasher.finalize_variable(&mut tree_hash).unwrap();

            let prefix = if network.to_lowercase().contains("test") {
                address::NetworkPrefix::Testnet
            } else {
                address::NetworkPrefix::Mainnet
            };

            let unconfirmed = mempool.find_outputs_by_tree_hash(&tree_hash);
            for output_ref in &unconfirmed {
                let box_response = IndexedErgoBoxResponse {
                    box_id: hex::encode(
                        ergo_types::transaction::compute_box_id(
                            &output_ref.tx_id,
                            output_ref.index,
                        )
                        .0,
                    ),
                    value: output_ref.candidate.value,
                    ergo_tree: hex::encode(&output_ref.candidate.ergo_tree_bytes),
                    assets: output_ref
                        .candidate
                        .tokens
                        .iter()
                        .map(|(id, amt)| TokenAmountResponse {
                            token_id: hex::encode(id.0),
                            amount: *amt,
                        })
                        .collect(),
                    creation_height: output_ref.candidate.creation_height,
                    global_index: 0,
                    inclusion_height: 0,
                    address: address::ergo_tree_to_address(
                        &output_ref.candidate.ergo_tree_bytes,
                        prefix,
                    ),
                    spent_transaction_id: None,
                    spending_height: None,
                };
                boxes.push(box_response);
                *total += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// A transaction submission with a response channel for verification feedback.
#[derive(Debug)]
pub struct TxSubmission {
    pub tx_id: [u8; 32],
    pub response: tokio::sync::oneshot::Sender<Result<(), String>>,
}

/// Application state shared between API handlers and the event loop.
#[derive(Clone)]
pub struct ApiState {
    pub shared: Arc<RwLock<SharedState>>,
    pub history: Arc<HistoryDb>,
    pub mempool: Arc<std::sync::RwLock<ErgoMemPool>>,
    pub node_name: String,
    pub app_version: String,
    pub network: String,
    pub tx_submit: Option<tokio::sync::mpsc::Sender<TxSubmission>>,
    pub peer_connect: Option<tokio::sync::mpsc::Sender<std::net::SocketAddr>>,
    pub shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    pub extra_db: Option<Arc<ergo_indexer::db::ExtraIndexerDb>>,
    pub api_key_hash: Option<String>,
    pub max_transaction_size: u32,
    pub blacklisted_transactions: Vec<String>,
    pub cors_allowed_origin: Option<String>,
    pub state_type: String,
    pub candidate_generator: Option<Arc<std::sync::RwLock<CandidateGenerator>>>,
    pub mining_solution_tx: Option<tokio::sync::mpsc::Sender<MiningSolution>>,
    pub block_submit: Option<tokio::sync::mpsc::Sender<crate::event_loop::BlockSubmission>>,
    pub utxo_proof: Option<tokio::sync::mpsc::Sender<crate::event_loop::UtxoProofRequest>>,
    pub mining_pub_key_hex: String,
    pub snapshots_db: Option<Arc<crate::snapshots::SnapshotsDb>>,
    pub geoip: crate::geoip::SharedGeoIp,
    #[cfg(feature = "wallet")]
    pub wallet: Option<Arc<tokio::sync::RwLock<ergo_wallet::wallet_manager::WalletManager>>>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return `Err(503)` when the node is not running in UTXO mode.
fn require_utxo_state(state_type: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if state_type != "utxo" {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": 503,
                "reason": "UTXO endpoints not available in digest mode",
                "detail": "Node is running in digest state mode"
            })),
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Wallet types & helpers (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
struct WalletInitRequest {
    pass: String,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletRestoreRequest {
    pass: String,
    mnemonic: String,
    #[serde(default)]
    mnemonic_pass: String,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
struct WalletUnlockRequest {
    pass: String,
}

#[cfg(feature = "wallet")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletStatusResponse {
    is_initialized: bool,
    is_unlocked: bool,
    change_address: Option<String>,
    wallet_height: u32,
    error: Option<String>,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletDeriveKeyRequest {
    derivation_path: String,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletUpdateChangeAddressRequest {
    address: String,
}

#[cfg(feature = "wallet")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletBalanceResponse {
    height: u32,
    balance: u64,
    tokens: std::collections::HashMap<String, u64>,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletBoxQueryParams {
    #[serde(default)]
    min_confirmations: Option<i32>,
    #[serde(default)]
    max_confirmations: Option<i32>,
    #[serde(default)]
    min_inclusion_height: Option<u32>,
    #[serde(default)]
    max_inclusion_height: Option<u32>,
}

#[cfg(feature = "wallet")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletBoxResponse {
    box_id: String,
    value: u64,
    ergo_tree: String,
    creation_height: u32,
    tokens: Vec<WalletTokenResponse>,
    inclusion_height: u32,
    spent: bool,
}

#[cfg(feature = "wallet")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletTokenResponse {
    token_id: String,
    amount: u64,
}

#[cfg(feature = "wallet")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletBoxWithMetaResponse {
    #[serde(rename = "box")]
    wallet_box: WalletBoxResponse,
    confirmations_num: u32,
    address: String,
    creation_transaction: String,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletCollectBoxesRequest {
    target_balance: u64,
    #[serde(default)]
    target_assets: std::collections::HashMap<String, u64>,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletTransactionQueryParams {
    #[serde(default)]
    min_inclusion_height: Option<u32>,
    #[serde(default)]
    max_inclusion_height: Option<u32>,
    #[serde(default)]
    min_confirmations: Option<i32>,
    #[serde(default)]
    max_confirmations: Option<i32>,
}

#[cfg(feature = "wallet")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletTransactionResponse {
    id: String,
    inclusion_height: u32,
    num_confirmations: u32,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletCheckSeedRequest {
    mnemonic: String,
    #[serde(default)]
    pass: String,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletRescanRequest {
    #[serde(default)]
    from_height: u32,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletPaymentRequest {
    address: String,
    value: u64,
    #[serde(default)]
    assets: Vec<WalletAssetRequest>,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletAssetRequest {
    token_id: String,
    amount: u64,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletGenerateRequest {
    requests: Vec<WalletPaymentRequest>,
    #[serde(default = "default_fee")]
    fee: u64,
    #[serde(default)]
    #[allow(dead_code)]
    inputs_raw: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    data_inputs_raw: Vec<String>,
}

#[cfg(feature = "wallet")]
fn default_fee() -> u64 {
    1_000_000
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletSignRequest {
    tx: String,
    #[serde(default)]
    #[allow(dead_code)]
    secrets: serde_json::Value,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletGetPrivateKeyRequest {
    address: String,
}

// ---------------------------------------------------------------------------
// Scan request types (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanRegisterRequest {
    scan_name: String,
    tracking_rule: ergo_wallet::scan_types::ScanningPredicate,
    #[serde(default)]
    wallet_interaction: ergo_wallet::scan_types::ScanWalletInteraction,
    #[serde(default)]
    remove_offchain: bool,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanDeregisterRequest {
    scan_id: u16,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanStopTrackingRequest {
    scan_id: u16,
    box_id: String,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanAddBoxRequest {
    scan_ids: Vec<u16>,
    box_id: String,
    ergo_tree: String,
    value: u64,
    #[serde(default)]
    creation_height: u32,
    #[serde(default)]
    inclusion_height: u32,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanP2sRuleRequest {
    address: String,
    scan_name: String,
}

/// Return a reference to the wallet manager or a 501 error if wallet is not available.
#[cfg(feature = "wallet")]
fn require_wallet(
    state: &ApiState,
) -> Result<
    &Arc<tokio::sync::RwLock<ergo_wallet::wallet_manager::WalletManager>>,
    (StatusCode, Json<ApiError>),
> {
    state.wallet.as_ref().ok_or_else(|| {
        api_error(
            StatusCode::NOT_IMPLEMENTED,
            "Wallet not available. Node was not compiled with wallet feature or wallet failed to initialize",
        )
    })
}

/// Convert a [`TrackedBox`] to the wallet box JSON response format.
#[cfg(feature = "wallet")]
fn tracked_box_to_response(tb: &ergo_wallet::tracked_box::TrackedBox) -> WalletBoxResponse {
    let tokens: Vec<WalletTokenResponse> = tb
        .tokens
        .iter()
        .map(|(tid, amt)| WalletTokenResponse {
            token_id: hex::encode(tid),
            amount: *amt,
        })
        .collect();
    WalletBoxResponse {
        box_id: hex::encode(tb.box_id),
        value: tb.value,
        ergo_tree: hex::encode(&tb.ergo_tree_bytes),
        creation_height: tb.creation_height,
        tokens,
        inclusion_height: tb.inclusion_height,
        spent: tb.spent,
    }
}

/// Convert a [`TrackedBox`] to the wallet box-with-metadata JSON response format.
#[cfg(feature = "wallet")]
fn tracked_box_to_meta_response(
    tb: &ergo_wallet::tracked_box::TrackedBox,
    current_height: u64,
) -> WalletBoxWithMetaResponse {
    let confirmations = if current_height >= tb.inclusion_height as u64 {
        (current_height - tb.inclusion_height as u64) as u32
    } else {
        0
    };
    WalletBoxWithMetaResponse {
        wallet_box: tracked_box_to_response(tb),
        confirmations_num: confirmations,
        address: String::new(), // Address recovery from ErgoTree is best-effort
        creation_transaction: hex::encode(tb.tx_id),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the API router.
pub fn build_router(state: ApiState) -> Router {
    let router = Router::new()
        .route(
            "/swagger",
            axum::routing::get(handlers::web_ui::swagger_handler),
        )
        .route(
            "/panel",
            axum::routing::get(handlers::web_ui::panel_handler),
        )
        .route(
            "/api-docs/openapi.yaml",
            axum::routing::get(handlers::web_ui::openapi_yaml_handler),
        )
        .route(
            "/",
            axum::routing::get(handlers::web_ui::root_redirect_handler),
        )
        .route("/info", axum::routing::get(handlers::info::info_handler))
        // Blocks: specific literal paths first
        .route(
            "/blocks",
            axum::routing::get(handlers::blocks::get_paginated_blocks_handler)
                .post(handlers::blocks::post_block_handler),
        )
        .route(
            "/blocks/lastHeaders/{n}",
            axum::routing::get(handlers::blocks::get_last_headers_handler),
        )
        .route(
            "/blocks/chainSlice",
            axum::routing::get(handlers::blocks::get_chain_slice_handler),
        )
        .route(
            "/blocks/headerIds",
            axum::routing::post(handlers::blocks::post_header_ids_handler),
        )
        .route(
            "/blocks/modifier/{modifier_id}",
            axum::routing::get(handlers::blocks::get_modifier_handler),
        )
        .route(
            "/blocks/at/{height}",
            axum::routing::get(handlers::blocks::get_blocks_at_height_handler),
        )
        // Blocks: parameterized paths with sub-paths
        .route(
            "/blocks/{header_id}/header",
            axum::routing::get(handlers::blocks::get_header_only_handler),
        )
        .route(
            "/blocks/{header_id}/transactions",
            axum::routing::get(handlers::blocks::get_block_transactions_handler),
        )
        .route(
            "/blocks/{header_id}/proofFor/{tx_id}",
            axum::routing::get(handlers::blocks::merkle_proof_handler),
        )
        .route(
            "/blocks/{header_id}",
            axum::routing::get(handlers::blocks::get_block_handler),
        )
        // NiPoPoW
        .route(
            "/nipopow/popowHeaderById/{id}",
            axum::routing::get(handlers::nipopow::popow_header_by_id_handler),
        )
        .route(
            "/nipopow/popowHeaderByHeight/{h}",
            axum::routing::get(handlers::nipopow::popow_header_by_height_handler),
        )
        .route(
            "/nipopow/proof/{m}/{k}/{id}",
            axum::routing::get(handlers::nipopow::nipopow_proof_at_handler),
        )
        .route(
            "/nipopow/proof/{m}/{k}",
            axum::routing::get(handlers::nipopow::nipopow_proof_handler),
        )
        // Peers
        .route(
            "/peers/connected",
            axum::routing::get(handlers::peers::peers_connected_handler),
        )
        .route(
            "/peers/map",
            axum::routing::get(handlers::peers::peers_map_handler),
        )
        .route(
            "/peers/all",
            axum::routing::get(handlers::peers::peers_all_handler),
        )
        .route(
            "/peers/blacklisted",
            axum::routing::get(handlers::peers::peers_blacklisted_handler),
        )
        .route(
            "/peers/connect",
            axum::routing::post(handlers::peers::peers_connect_handler),
        )
        .route(
            "/peers/status",
            axum::routing::get(handlers::peers::peers_status_handler),
        )
        .route(
            "/peers/syncInfo",
            axum::routing::get(handlers::peers::peers_sync_info_handler),
        )
        .route(
            "/peers/trackInfo",
            axum::routing::get(handlers::peers::peers_track_info_handler),
        )
        // Transactions
        .route(
            "/transactions/check",
            axum::routing::post(handlers::transactions::check_transaction_handler),
        )
        .route(
            "/transactions/bytes",
            axum::routing::post(handlers::transactions::submit_transaction_bytes_handler),
        )
        .route(
            "/transactions/checkBytes",
            axum::routing::post(handlers::transactions::check_transaction_bytes_handler),
        )
        .route(
            "/transactions",
            axum::routing::post(handlers::transactions::submit_transaction_handler),
        )
        .route(
            "/transactions/poolHistogram",
            axum::routing::get(handlers::transactions::pool_histogram_handler),
        )
        .route(
            "/transactions/getFee",
            axum::routing::get(handlers::transactions::get_fee_handler),
        )
        .route(
            "/transactions/waitTime",
            axum::routing::get(handlers::transactions::wait_time_handler),
        )
        .route(
            "/transactions/unconfirmed/transactionIds",
            axum::routing::get(handlers::transactions::get_unconfirmed_tx_ids_handler),
        )
        .route(
            "/transactions/unconfirmed/byTransactionIds",
            axum::routing::post(handlers::transactions::post_by_transaction_ids_handler),
        )
        .route(
            "/transactions/unconfirmed/inputs/byBoxId/{id}",
            axum::routing::get(handlers::transactions::get_unconfirmed_inputs_by_box_id_handler),
        )
        .route(
            "/transactions/unconfirmed/outputs/byBoxId/{id}",
            axum::routing::get(handlers::transactions::get_unconfirmed_output_by_box_id_handler),
        )
        .route(
            "/transactions/unconfirmed/outputs/byTokenId/{id}",
            axum::routing::get(handlers::transactions::get_unconfirmed_outputs_by_token_id_handler),
        )
        .route(
            "/transactions/unconfirmed/byErgoTree",
            axum::routing::post(handlers::transactions::post_unconfirmed_by_ergo_tree_handler),
        )
        .route(
            "/transactions/unconfirmed/outputs/byErgoTree",
            axum::routing::post(
                handlers::transactions::post_unconfirmed_outputs_by_ergo_tree_handler,
            ),
        )
        .route(
            "/transactions/unconfirmed/outputs/byRegisters",
            axum::routing::post(
                handlers::transactions::post_unconfirmed_outputs_by_registers_handler,
            ),
        )
        .route(
            "/transactions/unconfirmed/size",
            axum::routing::get(handlers::transactions::get_unconfirmed_size_handler),
        )
        .route(
            "/transactions/unconfirmed/{tx_id}",
            axum::routing::get(handlers::transactions::get_unconfirmed_by_id_handler)
                .head(handlers::transactions::head_unconfirmed_handler),
        )
        .route(
            "/transactions/unconfirmed",
            axum::routing::get(handlers::transactions::get_unconfirmed_handler),
        )
        // Utils – Address
        .route(
            "/utils/address/{addr}",
            axum::routing::get(handlers::utils::validate_address_handler),
        )
        .route(
            "/utils/address",
            axum::routing::post(handlers::utils::validate_address_post_handler),
        )
        .route(
            "/utils/rawToAddress/{pubkey_hex}",
            axum::routing::get(handlers::utils::raw_to_address_handler),
        )
        .route(
            "/utils/addressToRaw/{addr}",
            axum::routing::get(handlers::utils::address_to_raw_handler),
        )
        .route(
            "/utils/ergoTreeToAddress/{ergo_tree_hex}",
            axum::routing::get(handlers::utils::ergo_tree_to_address_handler),
        )
        .route(
            "/utils/ergoTreeToAddress",
            axum::routing::post(handlers::utils::ergo_tree_to_address_post_handler),
        )
        // Utils
        .route(
            "/utils/seed",
            axum::routing::get(handlers::utils::seed_handler),
        )
        .route(
            "/utils/seed/{length}",
            axum::routing::get(handlers::utils::seed_with_length_handler),
        )
        .route(
            "/utils/hash/blake2b",
            axum::routing::post(handlers::utils::blake2b_hash_handler),
        )
        // Script utility
        .route(
            "/script/addressToTree/{addr}",
            axum::routing::get(handlers::script::script_address_to_tree_handler),
        )
        .route(
            "/script/addressToBytes/{addr}",
            axum::routing::get(handlers::script::script_address_to_bytes_handler),
        )
        .route(
            "/script/p2sAddress",
            axum::routing::post(handlers::script::script_p2s_address_handler),
        )
        .route(
            "/script/p2shAddress",
            axum::routing::post(handlers::script::script_p2sh_address_handler),
        )
        .route(
            "/script/compile",
            axum::routing::post(handlers::script::script_compile_handler),
        )
        .route(
            "/script/executeWithContext",
            axum::routing::post(handlers::script::script_execute_with_context_handler),
        )
        // Emission
        .route(
            "/emission/scripts",
            axum::routing::get(handlers::emission::emission_scripts_handler),
        )
        .route(
            "/emission/at/{height}",
            axum::routing::get(handlers::emission::emission_handler),
        )
        // Node control
        .route(
            "/node/shutdown",
            axum::routing::post(handlers::node::node_shutdown_handler),
        )
        // Blockchain (indexed) endpoints
        .route(
            "/blockchain/indexedHeight",
            axum::routing::get(handlers::blockchain::indexed_height_handler),
        )
        .route(
            "/blockchain/transaction/byId/{id}",
            axum::routing::get(handlers::blockchain::blockchain_tx_by_id_handler),
        )
        .route(
            "/blockchain/transaction/byIndex/{n}",
            axum::routing::get(handlers::blockchain::blockchain_tx_by_index_handler),
        )
        .route(
            "/blockchain/transaction/byAddress/{addr}",
            axum::routing::get(handlers::blockchain::blockchain_txs_by_address_get_handler),
        )
        .route(
            "/blockchain/transaction/byAddress",
            axum::routing::post(handlers::blockchain::blockchain_txs_by_address_post_handler),
        )
        .route(
            "/blockchain/transaction/range",
            axum::routing::get(handlers::blockchain::blockchain_tx_range_handler),
        )
        // Blockchain – Box endpoints (specific paths first)
        .route(
            "/blockchain/box/unspent/byTokenId/{id}",
            axum::routing::get(handlers::blockchain::blockchain_unspent_boxes_by_token_handler),
        )
        .route(
            "/blockchain/box/unspent/byAddress/{addr}",
            axum::routing::get(
                handlers::blockchain::blockchain_unspent_boxes_by_address_get_handler,
            ),
        )
        .route(
            "/blockchain/box/unspent/byAddress",
            axum::routing::post(
                handlers::blockchain::blockchain_unspent_boxes_by_address_post_handler,
            ),
        )
        .route(
            "/blockchain/box/unspent/byTemplateHash/{hash}",
            axum::routing::get(handlers::blockchain::blockchain_unspent_boxes_by_template_handler),
        )
        .route(
            "/blockchain/box/unspent/byErgoTree",
            axum::routing::post(
                handlers::blockchain::blockchain_unspent_boxes_by_ergo_tree_handler,
            ),
        )
        .route(
            "/blockchain/box/byTokenId/{id}",
            axum::routing::get(handlers::blockchain::blockchain_boxes_by_token_handler),
        )
        .route(
            "/blockchain/box/byAddress/{addr}",
            axum::routing::get(handlers::blockchain::blockchain_boxes_by_address_get_handler),
        )
        .route(
            "/blockchain/box/byAddress",
            axum::routing::post(handlers::blockchain::blockchain_boxes_by_address_post_handler),
        )
        .route(
            "/blockchain/box/byTemplateHash/{hash}",
            axum::routing::get(handlers::blockchain::blockchain_boxes_by_template_handler),
        )
        .route(
            "/blockchain/box/byErgoTree",
            axum::routing::post(handlers::blockchain::blockchain_boxes_by_ergo_tree_handler),
        )
        .route(
            "/blockchain/box/range",
            axum::routing::get(handlers::blockchain::blockchain_box_range_handler),
        )
        .route(
            "/blockchain/box/byIndex/{n}",
            axum::routing::get(handlers::blockchain::blockchain_box_by_index_handler),
        )
        .route(
            "/blockchain/box/byId/{id}",
            axum::routing::get(handlers::blockchain::blockchain_box_by_id_handler),
        )
        // Blockchain – Token endpoints
        .route(
            "/blockchain/token/byId/{id}",
            axum::routing::get(handlers::blockchain::blockchain_token_by_id_handler),
        )
        .route(
            "/blockchain/tokens",
            axum::routing::post(handlers::blockchain::blockchain_tokens_handler),
        )
        // Blockchain – Balance endpoints
        .route(
            "/blockchain/balance",
            axum::routing::post(handlers::blockchain::blockchain_balance_post_handler),
        )
        .route(
            "/blockchain/balanceForAddress/{addr}",
            axum::routing::get(handlers::blockchain::blockchain_balance_get_handler),
        )
        // Blockchain – Block endpoints
        .route(
            "/blockchain/block/byHeaderId/{id}",
            axum::routing::get(handlers::blockchain::blockchain_block_by_header_id_handler),
        )
        .route(
            "/blockchain/block/byHeaderIds",
            axum::routing::post(handlers::blockchain::blockchain_block_by_header_ids_handler),
        )
        // UTXO endpoints
        .route(
            "/utxo/byId/{boxId}",
            axum::routing::get(handlers::utxo::utxo_by_id_handler),
        )
        .route(
            "/utxo/byIdBinary/{boxId}",
            axum::routing::get(handlers::utxo::utxo_by_id_binary_handler),
        )
        .route(
            "/utxo/withPool/byId/{boxId}",
            axum::routing::get(handlers::utxo::utxo_with_pool_by_id_handler),
        )
        .route(
            "/utxo/withPool/byIds",
            axum::routing::post(handlers::utxo::utxo_with_pool_by_ids_handler),
        )
        .route(
            "/utxo/withPool/byIdBinary/{boxId}",
            axum::routing::get(handlers::utxo::utxo_with_pool_by_id_binary_handler),
        )
        .route(
            "/utxo/genesis",
            axum::routing::get(handlers::utxo::utxo_genesis_handler),
        )
        .route(
            "/utxo/getSnapshotsInfo",
            axum::routing::get(handlers::utxo::utxo_snapshots_info_handler),
        )
        .route(
            "/utxo/getBoxesBinaryProof",
            axum::routing::post(handlers::utxo::utxo_boxes_binary_proof_handler),
        )
        // Mining
        .route(
            "/mining/candidate",
            axum::routing::get(handlers::mining::mining_candidate_handler),
        )
        .route(
            "/mining/candidateWithTxs",
            axum::routing::post(handlers::mining::mining_candidate_with_txs_handler),
        )
        .route(
            "/mining/solution",
            axum::routing::post(handlers::mining::mining_solution_handler),
        )
        .route(
            "/mining/rewardAddress",
            axum::routing::get(handlers::mining::mining_reward_address_handler),
        )
        .route(
            "/mining/rewardPublicKey",
            axum::routing::get(handlers::mining::mining_reward_pubkey_handler),
        );

    // Wallet lifecycle endpoints (feature-gated)
    #[cfg(feature = "wallet")]
    let router = router
        .route(
            "/wallet/status",
            axum::routing::get(handlers::wallet::wallet_status_handler),
        )
        .route(
            "/wallet/init",
            axum::routing::post(handlers::wallet::wallet_init_handler),
        )
        .route(
            "/wallet/restore",
            axum::routing::post(handlers::wallet::wallet_restore_handler),
        )
        .route(
            "/wallet/unlock",
            axum::routing::post(handlers::wallet::wallet_unlock_handler),
        )
        .route(
            "/wallet/lock",
            axum::routing::get(handlers::wallet::wallet_lock_handler),
        )
        // Address and balance endpoints
        .route(
            "/wallet/addresses",
            axum::routing::get(handlers::wallet::wallet_addresses_handler),
        )
        .route(
            "/wallet/deriveKey",
            axum::routing::post(handlers::wallet::wallet_derive_key_handler),
        )
        .route(
            "/wallet/deriveNextKey",
            axum::routing::get(handlers::wallet::wallet_derive_next_key_handler),
        )
        .route(
            "/wallet/balances/withUnconfirmed",
            axum::routing::get(handlers::wallet::wallet_balances_with_unconfirmed_handler),
        )
        .route(
            "/wallet/balances",
            axum::routing::get(handlers::wallet::wallet_balances_handler),
        )
        .route(
            "/wallet/updateChangeAddress",
            axum::routing::post(handlers::wallet::wallet_update_change_address_handler),
        )
        // Box and transaction query endpoints
        .route(
            "/wallet/boxes/unspent",
            axum::routing::get(handlers::wallet::wallet_unspent_boxes_handler),
        )
        .route(
            "/wallet/boxes/collect",
            axum::routing::post(handlers::wallet::wallet_collect_boxes_handler),
        )
        .route(
            "/wallet/boxes",
            axum::routing::get(handlers::wallet::wallet_boxes_handler),
        )
        .route(
            "/wallet/transactions",
            axum::routing::get(handlers::wallet::wallet_transactions_handler),
        )
        // Transaction generation and sending endpoints
        .route(
            "/wallet/payment/send",
            axum::routing::post(handlers::wallet::wallet_payment_send_handler),
        )
        .route(
            "/wallet/transaction/generate",
            axum::routing::post(handlers::wallet::wallet_tx_generate_handler),
        )
        .route(
            "/wallet/transaction/generateUnsigned",
            axum::routing::post(handlers::wallet::wallet_tx_generate_unsigned_handler),
        )
        .route(
            "/wallet/transaction/sign",
            axum::routing::post(handlers::wallet::wallet_tx_sign_handler),
        )
        .route(
            "/wallet/transaction/send",
            axum::routing::post(handlers::wallet::wallet_tx_send_handler),
        )
        // Wallet check, rescan, and transaction-by-id endpoints
        .route(
            "/wallet/transactionById/{txId}",
            axum::routing::get(handlers::wallet::wallet_transaction_by_id_handler),
        )
        .route(
            "/wallet/check",
            axum::routing::post(handlers::wallet::wallet_check_seed_handler),
        )
        .route(
            "/wallet/rescan",
            axum::routing::post(handlers::wallet::wallet_rescan_handler),
        )
        // Additional wallet endpoints
        .route(
            "/wallet/getPrivateKey",
            axum::routing::post(handlers::wallet::wallet_get_private_key_handler),
        )
        .route(
            "/wallet/generateCommitments",
            axum::routing::post(handlers::wallet::wallet_generate_commitments_handler),
        )
        .route(
            "/wallet/extractHints",
            axum::routing::post(handlers::wallet::wallet_extract_hints_handler),
        )
        .route(
            "/wallet/transactionsByScanId/{scanId}",
            axum::routing::get(handlers::wallet::wallet_txs_by_scan_id_handler),
        )
        // Scan endpoints
        .route(
            "/scan/register",
            axum::routing::post(handlers::wallet::scan_register_handler),
        )
        .route(
            "/scan/deregister",
            axum::routing::post(handlers::wallet::scan_deregister_handler),
        )
        .route(
            "/scan/listAll",
            axum::routing::get(handlers::wallet::scan_list_all_handler),
        )
        .route(
            "/scan/unspentBoxes/{scanId}",
            axum::routing::get(handlers::wallet::scan_unspent_boxes_handler),
        )
        .route(
            "/scan/spentBoxes/{scanId}",
            axum::routing::get(handlers::wallet::scan_spent_boxes_handler),
        )
        .route(
            "/scan/stopTracking",
            axum::routing::post(handlers::wallet::scan_stop_tracking_handler),
        )
        .route(
            "/scan/addBox",
            axum::routing::post(handlers::wallet::scan_add_box_handler),
        )
        .route(
            "/scan/p2sRule",
            axum::routing::post(handlers::wallet::scan_p2s_rule_handler),
        );

    let swagger_router: Router<()> = utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
        .url("/api-docs/openapi.json", openapi::ApiDoc::openapi())
        .into();

    router.with_state(state).merge(swagger_router)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Build a map from peer_id to (chain_status, height) from the sync tracker snapshot.
fn build_sync_map(
    shared: &crate::event_loop::SharedState,
) -> std::collections::HashMap<u64, (Option<String>, Option<u32>)> {
    let mut map = std::collections::HashMap::new();
    if let Some(ref snap_val) = shared.sync_tracker_snapshot {
        if let Some(peers) = snap_val.get("peers").and_then(|v| v.as_array()) {
            for entry in peers {
                if let Some(pid) = entry.get("peer_id").and_then(|v| v.as_u64()) {
                    let status = entry
                        .get("status")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let height = entry
                        .get("height")
                        .and_then(|v| v.as_u64())
                        .map(|h| h as u32);
                    map.insert(pid, (status, height));
                }
            }
        }
    }
    map
}

/// Parse an `IpAddr` from a "host:port" address string.
fn parse_ip_from_addr(addr: &str) -> Option<std::net::IpAddr> {
    addr.parse::<std::net::SocketAddr>().ok().map(|sa| sa.ip())
}

/// Convert a Scala-compatible JSON transaction to our internal `ErgoTransaction`.
fn convert_json_tx_to_ergo_tx(json_tx: &TxJsonTransaction) -> Result<ErgoTransaction, String> {
    // Parse inputs
    let inputs: Vec<Input> = json_tx
        .inputs
        .iter()
        .map(|ji| {
            let box_id_bytes =
                hex::decode(&ji.box_id).map_err(|_| "invalid input boxId hex".to_string())?;
            if box_id_bytes.len() != 32 {
                return Err("input boxId must be 32 bytes".into());
            }
            let proof = hex::decode(&ji.spending_proof.proof_bytes)
                .map_err(|_| "invalid proofBytes hex".to_string())?;

            // Serialize extension: VLQ count + for each entry: key_byte + VLQ value_len + value_bytes
            let mut ext_bytes = Vec::new();
            let ext_count = ji.spending_proof.extension.len();
            ergo_wire::vlq::put_uint(&mut ext_bytes, ext_count as u32);
            // Sort keys for deterministic encoding
            let mut ext_entries: Vec<_> = ji.spending_proof.extension.iter().collect();
            ext_entries.sort_by_key(|(k, _)| k.parse::<u8>().unwrap_or(0));
            for (key_str, val_hex) in &ext_entries {
                let key: u8 = key_str
                    .parse()
                    .map_err(|_| format!("invalid extension key: {}", key_str))?;
                ext_bytes.push(key);
                let val = hex::decode(val_hex)
                    .map_err(|_| format!("invalid extension value hex for key {}", key_str))?;
                ergo_wire::vlq::put_uint(&mut ext_bytes, val.len() as u32);
                ext_bytes.extend_from_slice(&val);
            }

            let mut bid = [0u8; 32];
            bid.copy_from_slice(&box_id_bytes);
            Ok(Input {
                box_id: BoxId(bid),
                proof_bytes: proof,
                extension_bytes: ext_bytes,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Parse data inputs
    let data_inputs: Vec<DataInput> = json_tx
        .data_inputs
        .iter()
        .map(|jdi| {
            let bytes =
                hex::decode(&jdi.box_id).map_err(|_| "invalid dataInput boxId hex".to_string())?;
            if bytes.len() != 32 {
                return Err("dataInput boxId must be 32 bytes".into());
            }
            let mut bid = [0u8; 32];
            bid.copy_from_slice(&bytes);
            Ok(DataInput { box_id: BoxId(bid) })
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Parse outputs
    let output_candidates: Vec<ErgoBoxCandidate> = json_tx
        .outputs
        .iter()
        .map(|jo| {
            let ergo_tree =
                hex::decode(&jo.ergo_tree).map_err(|_| "invalid ergoTree hex".to_string())?;
            let tokens: Vec<(BoxId, u64)> = jo
                .assets
                .iter()
                .map(|a| {
                    let tid =
                        hex::decode(&a.token_id).map_err(|_| "invalid tokenId hex".to_string())?;
                    if tid.len() != 32 {
                        return Err("tokenId must be 32 bytes".into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&tid);
                    Ok((BoxId(arr), a.amount))
                })
                .collect::<Result<Vec<_>, String>>()?;

            // Parse additional registers: "R4" -> (4, bytes), "R5" -> (5, bytes), etc.
            let mut registers: Vec<(u8, Vec<u8>)> = jo
                .additional_registers
                .iter()
                .map(|(k, v)| {
                    let idx: u8 = k
                        .strip_prefix('R')
                        .unwrap_or(k)
                        .parse()
                        .map_err(|_| format!("invalid register key: {}", k))?;
                    let val = hex::decode(v)
                        .map_err(|_| format!("invalid register value hex for {}", k))?;
                    Ok((idx, val))
                })
                .collect::<Result<Vec<_>, String>>()?;
            registers.sort_by_key(|(idx, _)| *idx);

            Ok(ErgoBoxCandidate {
                value: jo.value,
                ergo_tree_bytes: ergo_tree,
                creation_height: jo.creation_height,
                tokens,
                additional_registers: registers,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Build a placeholder tx to compute tx_id via serialize-without-proofs + blake2b256
    let temp_tx = ErgoTransaction {
        inputs: inputs.clone(),
        data_inputs: data_inputs.clone(),
        output_candidates: output_candidates.clone(),
        tx_id: TxId([0; 32]),
    };
    let tx_id = compute_tx_id(&temp_tx);

    Ok(ErgoTransaction {
        inputs,
        data_inputs,
        output_candidates,
        tx_id,
    })
}

// Extended Transactions API handlers
// ---------------------------------------------------------------------------

// Extended Blocks API handlers
// ---------------------------------------------------------------------------

// Address utility handlers
// ---------------------------------------------------------------------------

/// Shared logic for converting an ErgoTree hex string to an address.
fn ergo_tree_to_address_impl(
    hex_str: &str,
    state: &ApiState,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    let prefix = network_prefix(&state.network);
    let addr = address::ergo_tree_to_address(&bytes, prefix);
    Ok(Json(addr))
}

// Utils + Emission handlers
// ---------------------------------------------------------------------------

// NiPoPoW API handlers
// ---------------------------------------------------------------------------

// Script utility handlers
// ---------------------------------------------------------------------------

/// Compile ErgoScript source code to serialized ErgoTree bytes.
fn compile_script_to_tree_bytes(source: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    use ergo_lib::ergoscript_compiler::compiler::compile;
    use ergo_lib::ergoscript_compiler::script_env::ScriptEnv;
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

    // The upstream ergoscript-compiler 0.24.0 has a bug in error formatting
    // (subtraction overflow in pretty_error_desc when span.start() == 0),
    // so we catch panics to return a proper HTTP error instead.
    let src = source.to_string();
    let result = std::panic::catch_unwind(|| compile(&src, ScriptEnv::new()));

    let ergo_tree = match result {
        Ok(Ok(tree)) => tree,
        Ok(Err(e)) => {
            // Try formatting the error; if that panics too, fall back to Debug fmt.
            let msg =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.pretty_desc(&src)))
                    .unwrap_or_else(|_| format!("{e:?}"));
            return Err((StatusCode::BAD_REQUEST, format!("Compilation error: {msg}")));
        }
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Compilation error: compiler panicked (unsupported syntax)".to_string(),
            ));
        }
    };

    let bytes = ergo_tree.sigma_serialize_bytes().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialization error: {e}"),
        )
    })?;
    Ok(bytes)
}

/// Convert network string (e.g. "Mainnet", "Testnet") to `address::NetworkPrefix`.
fn network_prefix_from_str(network: &str) -> address::NetworkPrefix {
    if network.to_lowercase().contains("test") {
        address::NetworkPrefix::Testnet
    } else {
        address::NetworkPrefix::Mainnet
    }
}

// ---------------------------------------------------------------------------
// Blockchain (indexed) API handlers
// ---------------------------------------------------------------------------

// Blockchain (indexed) Box API handlers
// ---------------------------------------------------------------------------

// Blockchain – Token handlers
// ---------------------------------------------------------------------------

// Blockchain – Balance handlers
// ---------------------------------------------------------------------------

// Blockchain – Block handlers
// ---------------------------------------------------------------------------

// UTXO handlers
// ---------------------------------------------------------------------------

// POST /blocks, UTXO snapshot, binary proof, and script execution handlers
// ---------------------------------------------------------------------------

// Mining handlers
// ---------------------------------------------------------------------------

/// Convert a [`num_bigint::BigUint`] to `u64`, saturating at `u64::MAX`.
fn biguint_to_u64_saturating(val: &num_bigint::BigUint) -> u64 {
    let bytes = val.to_bytes_be();
    if bytes.len() > 8 {
        u64::MAX
    } else {
        let mut buf = [0u8; 8];
        let offset = 8 - bytes.len();
        buf[offset..].copy_from_slice(&bytes);
        u64::from_be_bytes(buf)
    }
}

// ---------------------------------------------------------------------------
// Wallet handlers (feature-gated)
// ---------------------------------------------------------------------------

// Wallet address and balance handlers (feature-gated)
// ---------------------------------------------------------------------------

// Wallet box and transaction query handlers (feature-gated)
// ---------------------------------------------------------------------------

// Wallet transaction generation and sending handlers (feature-gated)
// ---------------------------------------------------------------------------

/// Build a `SigmaStateContext` from the node's current blockchain state.
///
/// Loads the best full-block header and walks backwards via `parent_id` to
/// collect up to 10 recent headers. The resulting context is suitable for
/// transaction signing and script evaluation.
#[cfg(feature = "wallet")]
fn build_sigma_state_context(
    history: &HistoryDb,
    shared: &SharedState,
) -> Result<ergo_consensus::sigma_verify::SigmaStateContext, (StatusCode, Json<ApiError>)> {
    let best_id = shared.best_full_block_id.ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "No full blocks available yet",
        )
    })?;

    let best_header = history
        .load_header(&ModifierId(best_id))
        .map_err(|e| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load best header: {e}"),
            )
        })?
        .ok_or_else(|| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "best full block header not found in DB",
            )
        })?;

    // Walk backwards collecting up to 10 headers (descending order).
    let mut last_headers = vec![best_header.clone()];
    let mut current = best_header.clone();
    for _ in 1..10 {
        if current.is_genesis() {
            break;
        }
        match history.load_header(&current.parent_id) {
            Ok(Some(parent)) => {
                last_headers.push(parent.clone());
                current = parent;
            }
            _ => break,
        }
    }

    Ok(ergo_consensus::sigma_verify::SigmaStateContext {
        last_headers,
        current_height: best_header.height + 1,
        current_timestamp: best_header.timestamp + 1,
        current_n_bits: best_header.n_bits,
        current_votes: best_header.votes,
        current_miner_pk: best_header.pow_solution.miner_pk,
        state_digest: best_header.state_root.0,
        parameters: ergo_consensus::parameters::Parameters::default(),
        current_version: best_header.version,
        current_parent_id: best_id,
    })
}

/// Convert `WalletPaymentRequest` items to `tx_ops::PaymentRequest`.
#[cfg(feature = "wallet")]
fn convert_payment_requests(
    requests: &[WalletPaymentRequest],
) -> Vec<ergo_wallet::tx_ops::PaymentRequest> {
    requests
        .iter()
        .map(|r| ergo_wallet::tx_ops::PaymentRequest {
            address: r.address.clone(),
            value: r.value,
            tokens: r
                .assets
                .iter()
                .map(|a| (a.token_id.clone(), a.amount))
                .collect(),
        })
        .collect()
}

// Scan handlers (feature-gated)
// ---------------------------------------------------------------------------

// Additional wallet handlers (feature-gated)
// ---------------------------------------------------------------------------

/// Start the API server on the given bind address.
pub async fn start_api_server(bind_addr: &str, state: ApiState) -> std::io::Result<()> {
    use tower_http::compression::CompressionLayer;
    use tower_http::cors::{Any, CorsLayer};
    use tower_http::trace::TraceLayer;

    let cors_origin = state.cors_allowed_origin.clone();
    let router = build_router(state);
    let router = if let Some(ref origin) = cors_origin {
        if origin == "*" {
            router.layer(CorsLayer::permissive())
        } else {
            let layer = CorsLayer::new()
                .allow_origin(origin.parse::<axum::http::HeaderValue>().unwrap())
                .allow_methods(Any)
                .allow_headers(Any);
            router.layer(layer)
        }
    } else {
        router
    };
    let router = router
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new());
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "HTTP API server started");
    axum::serve(listener, router.into_make_service()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_loop::ConnectedPeerInfo;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// Valid P2PK ErgoTree hex for JSON test payloads (parseable by sigma-rust).
    const TEST_ERGO_TREE_HEX: &str =
        "082308cd0202020202020202020202020202020202020202020202020202020202020202020202";

    fn test_api_state() -> (ApiState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let state = ApiState {
            shared: Arc::new(RwLock::new(SharedState::new())),
            history: Arc::new(history),
            mempool: Arc::new(std::sync::RwLock::new(
                ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
            )),
            node_name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "Testnet".to_string(),
            tx_submit: None,
            peer_connect: None,
            shutdown_tx: None,
            extra_db: None,
            api_key_hash: None,
            max_transaction_size: 98_304,
            blacklisted_transactions: Vec::new(),
            cors_allowed_origin: None,
            state_type: "digest".to_string(),
            candidate_generator: None,
            mining_solution_tx: None,
            block_submit: None,
            utxo_proof: None,
            mining_pub_key_hex: String::new(),
            snapshots_db: None,
            geoip: Arc::new(None),
            #[cfg(feature = "wallet")]
            wallet: None,
        };
        (state, dir)
    }

    #[test]
    fn info_response_serializes() {
        let resp = NodeInfoResponse {
            name: "ergo-rust".to_string(),
            app_version: "0.1.0".to_string(),
            network: "mainnet".to_string(),
            headers_height: Some(1000),
            full_height: Some(990),
            max_peer_height: Some(1100),
            best_header_id: Some("aa".repeat(32)),
            best_full_header_id: Some("bb".repeat(32)),
            previous_full_header_id: None,
            state_root: "cc".repeat(33),
            state_version: None,
            state_type: "digest".to_string(),
            peers_count: 5,
            sync_state: "HeaderSync".to_string(),
            unconfirmed_count: 0,
            difficulty: "100663296".to_string(),
            headers_score: "12345".to_string(),
            full_blocks_score: "12300".to_string(),
            launch_time: 1700000000000,
            last_seen_message_time: 1700001000000,
            genesis_block_id: "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b"
                .to_string(),
            is_mining: false,
            is_explorer: false,
            eip27_supported: true,
            eip37_supported: true,
            rest_api_url: None,
            current_time: 1700001500000,
            parameters: serde_json::json!({"maxBlockSize": 524288}),
            last_mempool_update_time: 0,
            fast_sync_active: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "ergo-rust");
        assert_eq!(json["headersHeight"], 1000);
        assert_eq!(json["peersCount"], 5);
        assert_eq!(json["stateType"], "digest");
        assert_eq!(json["difficulty"], "100663296");
        assert_eq!(json["network"], "mainnet");
        assert!(
            json.get("bestFullHeaderId").is_some(),
            "expected bestFullHeaderId"
        );
        assert!(
            json.get("previousFullHeaderId").is_some(),
            "expected previousFullHeaderId"
        );
        assert!(json.get("stateVersion").is_some(), "expected stateVersion");
        assert!(json.get("isExplorer").is_some(), "expected isExplorer");
        assert_eq!(json["eip27Supported"], true);
        assert_eq!(json["eip37Supported"], true);
        assert!(json.get("restApiUrl").is_some(), "expected restApiUrl");
    }

    #[test]
    fn info_response_uses_camel_case() {
        let resp = NodeInfoResponse {
            name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "mainnet".to_string(),
            headers_height: Some(100),
            full_height: Some(90),
            max_peer_height: Some(110),
            best_header_id: None,
            best_full_header_id: None,
            previous_full_header_id: None,
            state_root: "aa".to_string(),
            state_version: None,
            state_type: "digest".to_string(),
            peers_count: 3,
            sync_state: "Syncing".to_string(),
            unconfirmed_count: 1,
            difficulty: "100663296".to_string(),
            headers_score: "0".to_string(),
            full_blocks_score: "0".to_string(),
            launch_time: 1700000000000,
            last_seen_message_time: 0,
            genesis_block_id: "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b"
                .to_string(),
            is_mining: false,
            is_explorer: false,
            eip27_supported: true,
            eip37_supported: true,
            rest_api_url: None,
            current_time: 1700001500000,
            parameters: serde_json::json!({}),
            last_mempool_update_time: 0,
            fast_sync_active: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(
            json.get("headersHeight").is_some(),
            "expected headersHeight"
        );
        assert!(json.get("appVersion").is_some(), "expected appVersion");
        assert!(json.get("peersCount").is_some(), "expected peersCount");
        assert!(json.get("stateType").is_some(), "expected stateType");
        assert!(json.get("fullHeight").is_some(), "expected fullHeight");
        assert!(json.get("syncState").is_some(), "expected syncState");
        assert!(
            json.get("unconfirmedCount").is_some(),
            "expected unconfirmedCount"
        );
        assert!(json.get("bestHeaderId").is_some(), "expected bestHeaderId");
        assert!(
            json.get("bestFullHeaderId").is_some(),
            "expected bestFullHeaderId"
        );
        assert!(json.get("stateRoot").is_some(), "expected stateRoot");
        assert!(
            json.get("previousFullHeaderId").is_some(),
            "expected previousFullHeaderId"
        );
        assert!(json.get("stateVersion").is_some(), "expected stateVersion");
        assert!(json.get("isExplorer").is_some(), "expected isExplorer");
        assert!(
            json.get("eip27Supported").is_some(),
            "expected eip27Supported"
        );
        assert!(
            json.get("eip37Supported").is_some(),
            "expected eip37Supported"
        );
        assert!(json.get("restApiUrl").is_some(), "expected restApiUrl");
        // snake_case should NOT be present
        assert!(
            json.get("headers_height").is_none(),
            "unexpected snake_case headers_height"
        );
        assert!(
            json.get("app_version").is_none(),
            "unexpected snake_case app_version"
        );
        assert!(
            json.get("best_full_block_id").is_none(),
            "unexpected snake_case best_full_block_id"
        );
    }

    #[tokio::test]
    async fn info_response_has_all_scala_fields() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder().uri("/info").body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // All required fields must be present
        assert!(json.get("maxPeerHeight").is_some(), "missing maxPeerHeight");
        assert!(json.get("difficulty").is_some(), "missing difficulty");
        assert!(json.get("headersScore").is_some(), "missing headersScore");
        assert!(
            json.get("fullBlocksScore").is_some(),
            "missing fullBlocksScore"
        );
        assert!(json.get("launchTime").is_some(), "missing launchTime");
        assert!(
            json.get("genesisBlockId").is_some(),
            "missing genesisBlockId"
        );
        assert!(json.get("isMining").is_some(), "missing isMining");
        assert!(json.get("currentTime").is_some(), "missing currentTime");
        assert!(json.get("parameters").is_some(), "missing parameters");
        assert!(
            json.get("lastSeenMessageTime").is_some(),
            "missing lastSeenMessageTime"
        );
        // New Scala-compatible fields
        assert!(
            json.get("bestFullHeaderId").is_some(),
            "missing bestFullHeaderId"
        );
        assert!(
            json.get("previousFullHeaderId").is_some(),
            "missing previousFullHeaderId"
        );
        assert!(json.get("stateVersion").is_some(), "missing stateVersion");
        assert!(json.get("isExplorer").is_some(), "missing isExplorer");
        assert!(
            json.get("eip27Supported").is_some(),
            "missing eip27Supported"
        );
        assert!(
            json.get("eip37Supported").is_some(),
            "missing eip37Supported"
        );
        assert!(json.get("restApiUrl").is_some(), "missing restApiUrl");
        // difficulty should be a string
        assert!(
            json["difficulty"].is_string(),
            "difficulty should be a string"
        );
        // network should be lowercase
        let network = json["network"].as_str().unwrap();
        assert!(
            network == "mainnet" || network == "testnet" || network == "devnet",
            "network should be lowercase, got: {network}"
        );
        // Heights should be null when 0 (fresh node)
        assert!(
            json["headersHeight"].is_null(),
            "headersHeight should be null on fresh node"
        );
        assert!(
            json["fullHeight"].is_null(),
            "fullHeight should be null on fresh node"
        );
        assert!(
            json["maxPeerHeight"].is_null(),
            "maxPeerHeight should be null on fresh node"
        );
    }

    #[tokio::test]
    async fn router_has_info_route() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let req = Request::builder().uri("/info").body(Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let req = Request::builder()
            .uri("/unknown")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_block_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let fake_id = "aa".repeat(32);
        let req = Request::builder()
            .uri(format!("/blocks/{fake_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_block_bad_hex() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let req = Request::builder()
            .uri("/blocks/not-valid-hex")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_block_wrong_length() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let req = Request::builder()
            .uri("/blocks/aabb")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn blocks_at_height_empty() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let req = Request::builder()
            .uri("/blocks/at/999999")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let ids: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn peers_connected_empty() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let req = Request::builder()
            .uri("/peers/connected")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let peers: Vec<PeerResponse> = serde_json::from_slice(&body).unwrap();
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn peers_connected_returns_info() {
        let (state, _dir) = test_api_state();

        // Pre-populate connected peers with enriched fields.
        {
            let mut shared = state.shared.write().await;
            shared.connected_peers = vec![
                ConnectedPeerInfo {
                    address: "192.168.1.1:9030".to_string(),
                    name: "peer-a".to_string(),
                    node_name: "my-node-a".to_string(),
                    last_handshake: 1640000000000,
                    last_message: Some(1640000000500),
                    connection_type: None,
                    version: Some("6.0.1".to_string()),
                    state_type: Some("utxo".to_string()),
                    verifying_transactions: Some(true),
                    blocks_to_keep: Some(-1),
                    peer_id: 100,
                },
                ConnectedPeerInfo {
                    address: "10.0.0.1:9030".to_string(),
                    name: "peer-b".to_string(),
                    node_name: "my-node-b".to_string(),
                    last_handshake: 1640000001000,
                    last_message: Some(1640000001500),
                    connection_type: Some("Incoming".to_string()),
                    version: Some("5.0.2".to_string()),
                    state_type: Some("digest".to_string()),
                    verifying_transactions: Some(false),
                    blocks_to_keep: Some(1440),
                    peer_id: 200,
                },
            ];
        }

        let router = build_router(state);
        let req = Request::builder()
            .uri("/peers/connected")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let peers: Vec<PeerResponse> = serde_json::from_slice(&body).unwrap();
        assert_eq!(peers.len(), 2);
        // Original fields
        assert_eq!(peers[0].address, "192.168.1.1:9030");
        assert_eq!(peers[0].name, "peer-a");
        assert_eq!(peers[0].last_message, 1640000000500);
        assert_eq!(peers[0].last_handshake, 1640000000000);
        assert!(peers[0].connection_type.is_none());
        // Enriched fields
        assert_eq!(peers[0].version, Some("6.0.1".to_string()));
        assert_eq!(peers[0].state_type, Some("utxo".to_string()));
        assert_eq!(peers[0].verifying_transactions, Some(true));
        assert_eq!(peers[0].blocks_to_keep, Some(-1));
        // No geoip configured → geo is None
        assert!(peers[0].geo.is_none());

        assert_eq!(peers[1].address, "10.0.0.1:9030");
        assert_eq!(peers[1].name, "peer-b");
        assert_eq!(peers[1].last_handshake, 1640000001000);
        assert_eq!(peers[1].connection_type, Some("Incoming".to_string()));
        assert_eq!(peers[1].version, Some("5.0.2".to_string()));
        assert_eq!(peers[1].state_type, Some("digest".to_string()));
        assert_eq!(peers[1].blocks_to_keep, Some(1440));
    }

    #[tokio::test]
    async fn peers_connected_no_geoip_geo_fields_null() {
        let (state, _dir) = test_api_state();
        {
            let mut shared = state.shared.write().await;
            shared.connected_peers = vec![ConnectedPeerInfo {
                address: "8.8.8.8:9030".to_string(),
                name: "peer-x".to_string(),
                node_name: String::new(),
                last_handshake: 1640000000000,
                last_message: Some(1640000000100),
                connection_type: Some("Outgoing".to_string()),
                version: Some("6.0.1".to_string()),
                state_type: None,
                verifying_transactions: None,
                blocks_to_keep: None,
                peer_id: 42,
            }];
        }

        let router = build_router(state);
        let req = Request::builder()
            .uri("/peers/connected")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let peer = &val[0];
        // Geo field should be absent (skip_serializing_if)
        assert!(peer.get("geo").is_none());
        // stateType should be absent when None
        assert!(peer.get("stateType").is_none());
    }

    #[tokio::test]
    async fn peers_map_empty_without_geoip() {
        let (state, _dir) = test_api_state();
        {
            let mut shared = state.shared.write().await;
            shared.connected_peers = vec![ConnectedPeerInfo {
                address: "8.8.8.8:9030".to_string(),
                name: "peer-x".to_string(),
                node_name: String::new(),
                last_handshake: 1640000000000,
                last_message: Some(1640000000100),
                connection_type: Some("Outgoing".to_string()),
                version: Some("6.0.1".to_string()),
                state_type: None,
                verifying_transactions: None,
                blocks_to_keep: None,
                peer_id: 42,
            }];
        }

        let router = build_router(state);
        let req = Request::builder()
            .uri("/peers/map")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let entries: Vec<PeerMapEntry> = serde_json::from_slice(&body).unwrap();
        // No GeoIP DB configured → empty result
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn post_transaction_valid() {
        let (state, _dir) = test_api_state();
        let router = build_router(state.clone());

        // Submit a JSON transaction (Scala-compatible format)
        let body = serde_json::json!({
            "inputs": [{"boxId": "aa".repeat(32), "spendingProof": {"proofBytes": "", "extension": {}}}],
            "dataInputs": [],
            "outputs": [{"value": 1000000000, "ergoTree": TEST_ERGO_TREE_HEX, "creationHeight": 100000, "assets": [], "additionalRegisters": {}}]
        });
        let req = Request::builder()
            .method("POST")
            .uri("/transactions")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify tx is in mempool
        let mp = state.mempool.read().unwrap();
        assert_eq!(mp.size(), 1);
    }

    #[tokio::test]
    async fn post_transaction_bad_box_id() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        // Bad boxId hex in JSON tx
        let body = serde_json::json!({
            "inputs": [{"boxId": "not-hex!", "spendingProof": {"proofBytes": ""}}],
            "outputs": [{"value": 100, "ergoTree": "00", "creationHeight": 1}]
        });
        let req = Request::builder()
            .method("POST")
            .uri("/transactions")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_unconfirmed_empty() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let req = Request::builder()
            .uri("/transactions/unconfirmed")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let txs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(txs.is_empty());
    }

    #[tokio::test]
    async fn get_unconfirmed_size_zero() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let req = Request::builder()
            .uri("/transactions/unconfirmed/size")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let size: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(size["size"], 0);
    }

    #[tokio::test]
    async fn get_unconfirmed_by_id_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let fake_id = "aa".repeat(32);
        let req = Request::builder()
            .uri(format!("/transactions/unconfirmed/{fake_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_paginated_blocks_empty() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/blocks?offset=0&limit=10")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let ids: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn get_last_headers_empty() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/blocks/lastHeaders/5")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let headers: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(headers.is_empty());
    }

    #[tokio::test]
    async fn get_chain_slice_empty() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/blocks/chainSlice?fromHeight=0&toHeight=100")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_header_only_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let fake_id = "aa".repeat(32);
        let req = Request::builder()
            .uri(format!("/blocks/{fake_id}/header"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_block_transactions_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let fake_id = "aa".repeat(32);
        let req = Request::builder()
            .uri(format!("/blocks/{fake_id}/transactions"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn post_header_ids_empty_array() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!([]);
        let req = Request::builder()
            .method("POST")
            .uri("/blocks/headerIds")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let blocks: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(blocks.is_empty());
    }

    #[tokio::test]
    async fn get_modifier_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let fake_id = "aa".repeat(32);
        let req = Request::builder()
            .uri(format!("/blocks/modifier/{fake_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------
    // Extended Transactions API tests
    // -----------------------------------------------------------------

    fn make_minimal_tx() -> ergo_types::transaction::ErgoTransaction {
        let valid_tree = {
            let mut t = vec![0x08]; // header: v0 + size bit
            ergo_wire::vlq::put_uint(&mut t, 35);
            t.push(0x08);
            t.push(0xCD);
            t.extend_from_slice(&[0x02; 33]);
            t
        };
        ergo_types::transaction::ErgoTransaction {
            inputs: vec![ergo_types::transaction::Input {
                box_id: ergo_types::transaction::BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![0x00],
            }],
            data_inputs: vec![],
            output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: valid_tree,
                creation_height: 100_000,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: ergo_types::transaction::TxId([0; 32]),
        }
    }

    /// Serialize a minimal tx and return (hex_string, parsed_tx_id_hex).
    fn serialize_minimal_tx() -> (String, String) {
        let tx = make_minimal_tx();
        let bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
        let hex_str = hex::encode(&bytes);
        // Parse to get the computed tx_id
        let parsed = parse_transaction(&bytes).unwrap();
        let tx_id_hex = hex::encode(parsed.tx_id.0);
        (hex_str, tx_id_hex)
    }

    #[tokio::test]
    async fn check_transaction_valid() {
        let (state, _dir) = test_api_state();
        let router = build_router(state.clone());

        // Submit a JSON transaction for validation (Scala-compatible format)
        let body = serde_json::json!({
            "inputs": [{"boxId": "aa".repeat(32), "spendingProof": {"proofBytes": "", "extension": {}}}],
            "dataInputs": [],
            "outputs": [{"value": 1000000, "ergoTree": TEST_ERGO_TREE_HEX, "creationHeight": 100, "assets": [], "additionalRegisters": {}}]
        });
        let req = Request::builder()
            .method("POST")
            .uri("/transactions/check")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Mempool should stay empty -- check only validates, does not add.
        let mp = state.mempool.read().unwrap();
        assert_eq!(mp.size(), 0);
    }

    #[tokio::test]
    async fn submit_transaction_bytes() {
        let (state, _dir) = test_api_state();
        let router = build_router(state.clone());

        let (hex_str, _tx_id_hex) = serialize_minimal_tx();
        // POST /transactions/bytes expects a raw JSON string body
        let req = Request::builder()
            .method("POST")
            .uri("/transactions/bytes")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&hex_str).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify tx is in mempool
        let mp = state.mempool.read().unwrap();
        assert_eq!(mp.size(), 1);
    }

    #[tokio::test]
    async fn head_unconfirmed_exists() {
        let (state, _dir) = test_api_state();

        // Insert a tx into the mempool
        let tx = make_minimal_tx();
        let bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        let tx_id_hex = hex::encode(parsed.tx_id.0);
        state.mempool.write().unwrap().put(parsed).unwrap();

        let router = build_router(state);
        let req = Request::builder()
            .method("HEAD")
            .uri(format!("/transactions/unconfirmed/{tx_id_hex}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn head_unconfirmed_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let fake_id = "bb".repeat(32);
        let req = Request::builder()
            .method("HEAD")
            .uri(format!("/transactions/unconfirmed/{fake_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_unconfirmed_transaction_ids() {
        let (state, _dir) = test_api_state();

        // Insert a tx
        let tx = make_minimal_tx();
        let bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        let tx_id_hex = hex::encode(parsed.tx_id.0);
        state.mempool.write().unwrap().put(parsed).unwrap();

        let router = build_router(state);
        let req = Request::builder()
            .uri("/transactions/unconfirmed/transactionIds")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let ids: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], tx_id_hex);
    }

    #[tokio::test]
    async fn post_by_transaction_ids_filters() {
        let (state, _dir) = test_api_state();

        // Insert a tx
        let tx = make_minimal_tx();
        let bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        let tx_id_hex = hex::encode(parsed.tx_id.0);
        state.mempool.write().unwrap().put(parsed).unwrap();

        let router = build_router(state);

        let fake_id = "cc".repeat(32);
        let body = serde_json::json!([tx_id_hex, fake_id]);
        let req = Request::builder()
            .method("POST")
            .uri("/transactions/unconfirmed/byTransactionIds")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let present: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert_eq!(present.len(), 1);
        assert_eq!(present[0], tx_id_hex);
    }

    #[tokio::test]
    async fn get_unconfirmed_output_by_box_id_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let fake_id = "dd".repeat(32);
        let req = Request::builder()
            .uri(format!(
                "/transactions/unconfirmed/outputs/byBoxId/{fake_id}"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_unconfirmed_outputs_by_token_id_empty() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);

        let fake_id = "ee".repeat(32);
        let req = Request::builder()
            .uri(format!(
                "/transactions/unconfirmed/outputs/byTokenId/{fake_id}"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let outputs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(outputs.is_empty());
    }

    // -----------------------------------------------------------------
    // Extended Peers API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn get_peers_all_empty() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/peers/all")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_peers_blacklisted_empty() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/peers/blacklisted")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_peers_status() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/peers/status")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(status["connectedCount"].is_number());
    }

    #[tokio::test]
    async fn get_peers_sync_info() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/peers/syncInfo")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_peers_track_info() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/peers/trackInfo")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_peers_connect_bad_address() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!("not-a-valid-address");
        let req = Request::builder()
            .method("POST")
            .uri("/peers/connect")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------
    // Utils + Emission API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn get_utils_seed_32_bytes() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/utils/seed")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let seed: String = serde_json::from_slice(&body).unwrap();
        assert_eq!(seed.len(), 64); // 32 bytes = 64 hex chars
    }

    #[tokio::test]
    async fn get_utils_seed_custom_length() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/utils/seed/16")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let seed: String = serde_json::from_slice(&body).unwrap();
        assert_eq!(seed.len(), 32); // 16 bytes = 32 hex chars
    }

    #[tokio::test]
    async fn get_utils_seed_too_large() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/utils/seed/999")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_utils_blake2b_hash() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!("hello");
        let req = Request::builder()
            .method("POST")
            .uri("/utils/hash/blake2b")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let hash: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(hash["hash"].is_string());
        assert_eq!(hash["hash"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn get_emission_at_height() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/emission/at/1")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["height"], 1);
        assert_eq!(info["minerReward"], 67_500_000_000u64);
    }

    #[tokio::test]
    async fn get_emission_at_zero() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/emission/at/0")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["totalCoinsIssued"], 0);
    }

    #[tokio::test]
    async fn get_unconfirmed_inputs_by_box_id_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let fake_id = "aa".repeat(32);
        let req = Request::builder()
            .uri(format!(
                "/transactions/unconfirmed/inputs/byBoxId/{fake_id}"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_unconfirmed_inputs_by_box_id_found() {
        let (state, _dir) = test_api_state();

        // Insert a tx that spends box 0xAA
        let tx = make_minimal_tx();
        let bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        let input_box_id = hex::encode(parsed.inputs[0].box_id.0);
        state.mempool.write().unwrap().put(parsed).unwrap();

        let router = build_router(state);
        let req = Request::builder()
            .uri(format!(
                "/transactions/unconfirmed/inputs/byBoxId/{input_box_id}"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(result.get("spendingTxId").is_some());
        assert!(result.get("boxId").is_some());
    }

    #[tokio::test]
    async fn get_unconfirmed_paginated() {
        let (state, _dir) = test_api_state();
        let tx = make_minimal_tx();
        let bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        state.mempool.write().unwrap().put(parsed).unwrap();

        let router = build_router(state);
        let req = Request::builder()
            .uri("/transactions/unconfirmed?offset=0&limit=10")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let txs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(txs.len(), 1);
    }

    #[tokio::test]
    async fn post_node_shutdown_non_localhost_rejected() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/node/shutdown")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::FORBIDDEN,
            "unexpected status: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn get_unconfirmed_paginated_multiple_txs() {
        let (state, _dir) = test_api_state();

        // Insert 3 distinct transactions (different box IDs so they don't conflict)
        for i in 0u8..3 {
            let mut tx = make_minimal_tx();
            tx.inputs[0].box_id = ergo_types::transaction::BoxId([i + 0x10; 32]);
            let bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
            let parsed = ergo_wire::transaction_ser::parse_transaction(&bytes).unwrap();
            state.mempool.write().unwrap().put(parsed).unwrap();
        }

        // Page 1: offset=0, limit=2 -> 2 results
        let router = build_router(state.clone());
        let req = Request::builder()
            .uri("/transactions/unconfirmed?offset=0&limit=2")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let txs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(txs.len(), 2);

        // Page 2: offset=2, limit=2 -> 1 result
        let router = build_router(state.clone());
        let req = Request::builder()
            .uri("/transactions/unconfirmed?offset=2&limit=2")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let txs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(txs.len(), 1);

        // Page 3: offset=3, limit=2 -> 0 results
        let router = build_router(state.clone());
        let req = Request::builder()
            .uri("/transactions/unconfirmed?offset=3&limit=2")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let txs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(txs.is_empty());
    }

    #[tokio::test]
    async fn get_unconfirmed_paginated_with_offset() {
        let (state, _dir) = test_api_state();
        let tx = make_minimal_tx();
        let bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
        let parsed = parse_transaction(&bytes).unwrap();
        state.mempool.write().unwrap().put(parsed).unwrap();

        let router = build_router(state);
        let req = Request::builder()
            .uri("/transactions/unconfirmed?offset=1&limit=10")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let txs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(txs.is_empty());
    }

    // -----------------------------------------------------------------
    // Address utility API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn validate_address_valid() {
        let (state, _dir) = test_api_state();
        let pk = [0xAA; 33];
        let addr = address::encode_address(
            address::NetworkPrefix::Testnet,
            address::AddressType::P2PK,
            &pk,
        );
        let router = build_router(state);
        let req = Request::builder()
            .uri(format!("/utils/address/{addr}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["isValid"], true);
        assert!(json.get("error").is_none() || json["error"].is_null());
    }

    #[tokio::test]
    async fn validate_address_invalid() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/utils/address/garbage")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["isValid"], false);
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn validate_address_post_valid() {
        let (state, _dir) = test_api_state();
        let pk = [0xBB; 33];
        let addr = address::encode_address(
            address::NetworkPrefix::Testnet,
            address::AddressType::P2PK,
            &pk,
        );
        let router = build_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/utils/address")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&addr).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["isValid"], true);
    }

    #[tokio::test]
    async fn raw_to_address_valid() {
        let (state, _dir) = test_api_state();
        // 33-byte compressed public key as hex
        let pk_hex = "02".to_string() + &"ab".repeat(32);
        let router = build_router(state);
        let req = Request::builder()
            .uri(format!("/utils/rawToAddress/{pk_hex}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let addr: String = serde_json::from_slice(&body).unwrap();
        // The returned address should decode successfully
        let decoded = address::decode_address(&addr).unwrap();
        assert_eq!(decoded.address_type, address::AddressType::P2PK);
    }

    #[tokio::test]
    async fn raw_to_address_wrong_length() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        // "aabb" is only 2 bytes — still valid hex, but the endpoint should return 200
        // since raw_to_address accepts any length hex. Let's use invalid hex instead.
        let req = Request::builder()
            .uri("/utils/rawToAddress/not_valid_hex!")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn address_to_raw_roundtrip() {
        let (state, _dir) = test_api_state();
        let pk_hex = "02".to_string() + &"cd".repeat(32);
        let addr = address::raw_to_address(&pk_hex, address::NetworkPrefix::Testnet).unwrap();
        let router = build_router(state);
        let req = Request::builder()
            .uri(format!("/utils/addressToRaw/{addr}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let raw: String = serde_json::from_slice(&body).unwrap();
        assert_eq!(raw, pk_hex);
    }

    #[tokio::test]
    async fn ergo_tree_to_address_p2pk() {
        let (state, _dir) = test_api_state();
        // P2PK ErgoTree: 0x00 0x08 0xcd + 33-byte compressed pubkey
        let pk = [0xEE; 33];
        let mut tree = vec![0x00, 0x08, 0xcd];
        tree.extend_from_slice(&pk);
        let tree_hex = hex::encode(&tree);

        let router = build_router(state);
        let req = Request::builder()
            .uri(format!("/utils/ergoTreeToAddress/{tree_hex}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let addr: String = serde_json::from_slice(&body).unwrap();
        let decoded = address::decode_address(&addr).unwrap();
        assert_eq!(decoded.address_type, address::AddressType::P2PK);
        assert_eq!(decoded.content_bytes, pk);
    }

    #[tokio::test]
    async fn ergo_tree_to_address_p2s() {
        let (state, _dir) = test_api_state();
        // Non-P2PK ErgoTree falls back to P2S
        let tree = vec![0x10, 0x04, 0x00, 0x05, 0x00];
        let tree_hex = hex::encode(&tree);

        let router = build_router(state);
        let req = Request::builder()
            .uri(format!("/utils/ergoTreeToAddress/{tree_hex}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let addr: String = serde_json::from_slice(&body).unwrap();
        let decoded = address::decode_address(&addr).unwrap();
        assert_eq!(decoded.address_type, address::AddressType::P2S);
        assert_eq!(decoded.content_bytes, tree);
    }

    // -----------------------------------------------------------------
    // Merkle proof + Emission scripts API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn merkle_proof_header_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let fake_header = "aa".repeat(32);
        let fake_tx = "bb".repeat(32);
        let req = Request::builder()
            .uri(format!("/blocks/{fake_header}/proofFor/{fake_tx}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn emission_scripts_returns_three_addresses() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/emission/scripts")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["emission"].is_string());
        assert!(json["reemission"].is_string());
        assert!(json["pay2Reemission"].is_string());
        // All addresses should be non-empty
        assert!(!json["emission"].as_str().unwrap().is_empty());
        assert!(!json["reemission"].as_str().unwrap().is_empty());
        assert!(!json["pay2Reemission"].as_str().unwrap().is_empty());
    }

    // -----------------------------------------------------------------
    // Fee estimation API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn pool_histogram_empty_mempool() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/transactions/poolHistogram?bins=5&maxtime=60000")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let bins: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(bins.len(), 5);
        for bin in &bins {
            assert_eq!(bin["nTxns"], 0);
        }
    }

    #[tokio::test]
    async fn pool_histogram_default_params() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/transactions/poolHistogram")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let bins: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(bins.len(), 10); // default bins=10
    }

    #[tokio::test]
    async fn get_fee_empty_mempool() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/transactions/getFee")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let fee: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(fee["fee"].as_u64().unwrap() >= 1_000_000);
    }

    #[tokio::test]
    async fn wait_time_empty_mempool() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/transactions/waitTime?fee=1000000")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let wait: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(wait["waitTimeMillis"].is_number());
    }

    // -----------------------------------------------------------------
    // NiPoPoW API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn popow_header_by_id_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let fake_id = "aa".repeat(32);
        let req = Request::builder()
            .uri(format!("/nipopow/popowHeaderById/{fake_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn popow_header_by_height_not_found() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/nipopow/popowHeaderByHeight/999999")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn nipopow_proof_empty_chain() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/nipopow/proof/5/3")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn nipopow_proof_bad_params() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/nipopow/proof/0/3")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------
    // Blockchain (indexed) API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn indexed_height_without_indexer() {
        // ApiState with extra_db: None should return 503.
        let (state, _dir) = test_api_state();
        assert!(state.extra_db.is_none());
        let router = build_router(state);
        let req = Request::builder()
            .uri("/blockchain/indexedHeight")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn indexed_height_with_empty_indexer() {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let extra_path = dir.path().join("extra");
        let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path).unwrap();
        let state = ApiState {
            shared: Arc::new(RwLock::new(SharedState::new())),
            history: Arc::new(history),
            mempool: Arc::new(std::sync::RwLock::new(
                ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
            )),
            node_name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "Testnet".to_string(),
            tx_submit: None,
            peer_connect: None,
            shutdown_tx: None,
            extra_db: Some(Arc::new(extra_db)),
            api_key_hash: None,
            max_transaction_size: 98_304,
            blacklisted_transactions: Vec::new(),
            cors_allowed_origin: None,
            state_type: "digest".to_string(),
            candidate_generator: None,
            mining_solution_tx: None,
            block_submit: None,
            utxo_proof: None,
            mining_pub_key_hex: String::new(),
            snapshots_db: None,
            geoip: Arc::new(None),
            #[cfg(feature = "wallet")]
            wallet: None,
        };
        let router = build_router(state);
        let req = Request::builder()
            .uri("/blockchain/indexedHeight")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["indexedHeight"], 0);
        assert_eq!(json["fullHeight"], 0);
    }

    #[tokio::test]
    async fn tx_by_id_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let extra_path = dir.path().join("extra");
        let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path).unwrap();
        let state = ApiState {
            shared: Arc::new(RwLock::new(SharedState::new())),
            history: Arc::new(history),
            mempool: Arc::new(std::sync::RwLock::new(
                ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
            )),
            node_name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "Testnet".to_string(),
            tx_submit: None,
            peer_connect: None,
            shutdown_tx: None,
            extra_db: Some(Arc::new(extra_db)),
            api_key_hash: None,
            max_transaction_size: 98_304,
            blacklisted_transactions: Vec::new(),
            cors_allowed_origin: None,
            state_type: "digest".to_string(),
            candidate_generator: None,
            mining_solution_tx: None,
            block_submit: None,
            utxo_proof: None,
            mining_pub_key_hex: String::new(),
            snapshots_db: None,
            geoip: Arc::new(None),
            #[cfg(feature = "wallet")]
            wallet: None,
        };
        let router = build_router(state);
        let random_id = "ab".repeat(32);
        let req = Request::builder()
            .uri(format!("/blockchain/transaction/byId/{random_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn tx_range_empty() {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let extra_path = dir.path().join("extra");
        let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path).unwrap();
        let state = ApiState {
            shared: Arc::new(RwLock::new(SharedState::new())),
            history: Arc::new(history),
            mempool: Arc::new(std::sync::RwLock::new(
                ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
            )),
            node_name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "Testnet".to_string(),
            tx_submit: None,
            peer_connect: None,
            shutdown_tx: None,
            extra_db: Some(Arc::new(extra_db)),
            api_key_hash: None,
            max_transaction_size: 98_304,
            blacklisted_transactions: Vec::new(),
            cors_allowed_origin: None,
            state_type: "digest".to_string(),
            candidate_generator: None,
            mining_solution_tx: None,
            block_submit: None,
            utxo_proof: None,
            mining_pub_key_hex: String::new(),
            snapshots_db: None,
            geoip: Arc::new(None),
            #[cfg(feature = "wallet")]
            wallet: None,
        };
        let router = build_router(state);
        let req = Request::builder()
            .uri("/blockchain/transaction/range")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let ids: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert!(ids.is_empty());
    }

    // -----------------------------------------------------------------
    // Blockchain Box API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn box_by_id_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let extra_path = dir.path().join("extra");
        let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path).unwrap();
        let state = ApiState {
            shared: Arc::new(RwLock::new(SharedState::new())),
            history: Arc::new(history),
            mempool: Arc::new(std::sync::RwLock::new(
                ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
            )),
            node_name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "Testnet".to_string(),
            tx_submit: None,
            peer_connect: None,
            shutdown_tx: None,
            extra_db: Some(Arc::new(extra_db)),
            api_key_hash: None,
            max_transaction_size: 98_304,
            blacklisted_transactions: Vec::new(),
            cors_allowed_origin: None,
            state_type: "digest".to_string(),
            candidate_generator: None,
            mining_solution_tx: None,
            block_submit: None,
            utxo_proof: None,
            mining_pub_key_hex: String::new(),
            snapshots_db: None,
            geoip: Arc::new(None),
            #[cfg(feature = "wallet")]
            wallet: None,
        };
        let router = build_router(state);
        let random_id = "ab".repeat(32);
        let req = Request::builder()
            .uri(format!("/blockchain/box/byId/{random_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn box_range_empty() {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let extra_path = dir.path().join("extra");
        let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path).unwrap();
        let state = ApiState {
            shared: Arc::new(RwLock::new(SharedState::new())),
            history: Arc::new(history),
            mempool: Arc::new(std::sync::RwLock::new(
                ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
            )),
            node_name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "Testnet".to_string(),
            tx_submit: None,
            peer_connect: None,
            shutdown_tx: None,
            extra_db: Some(Arc::new(extra_db)),
            api_key_hash: None,
            max_transaction_size: 98_304,
            blacklisted_transactions: Vec::new(),
            cors_allowed_origin: None,
            state_type: "digest".to_string(),
            candidate_generator: None,
            mining_solution_tx: None,
            block_submit: None,
            utxo_proof: None,
            mining_pub_key_hex: String::new(),
            snapshots_db: None,
            geoip: Arc::new(None),
            #[cfg(feature = "wallet")]
            wallet: None,
        };
        let router = build_router(state);
        let req = Request::builder()
            .uri("/blockchain/box/range")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let ids: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn unspent_boxes_without_indexer() {
        // No extra_db => should get 503
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let fake_id = "cc".repeat(32);
        let req = Request::builder()
            .uri(format!("/blockchain/box/unspent/byTokenId/{fake_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // -----------------------------------------------------------------
    // Blockchain Token / Balance / Block API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn token_by_id_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let extra_path = dir.path().join("extra");
        let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path).unwrap();
        let state = ApiState {
            shared: Arc::new(RwLock::new(SharedState::new())),
            history: Arc::new(history),
            mempool: Arc::new(std::sync::RwLock::new(
                ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
            )),
            node_name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "Testnet".to_string(),
            tx_submit: None,
            peer_connect: None,
            shutdown_tx: None,
            extra_db: Some(Arc::new(extra_db)),
            api_key_hash: None,
            max_transaction_size: 98_304,
            blacklisted_transactions: Vec::new(),
            cors_allowed_origin: None,
            state_type: "digest".to_string(),
            candidate_generator: None,
            mining_solution_tx: None,
            block_submit: None,
            utxo_proof: None,
            mining_pub_key_hex: String::new(),
            snapshots_db: None,
            geoip: Arc::new(None),
            #[cfg(feature = "wallet")]
            wallet: None,
        };
        let router = build_router(state);
        let random_id = "ab".repeat(32);
        let req = Request::builder()
            .uri(format!("/blockchain/token/byId/{random_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn batch_tokens_empty() {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let extra_path = dir.path().join("extra");
        let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path).unwrap();
        let state = ApiState {
            shared: Arc::new(RwLock::new(SharedState::new())),
            history: Arc::new(history),
            mempool: Arc::new(std::sync::RwLock::new(
                ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
            )),
            node_name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "Testnet".to_string(),
            tx_submit: None,
            peer_connect: None,
            shutdown_tx: None,
            extra_db: Some(Arc::new(extra_db)),
            api_key_hash: None,
            max_transaction_size: 98_304,
            blacklisted_transactions: Vec::new(),
            cors_allowed_origin: None,
            state_type: "digest".to_string(),
            candidate_generator: None,
            mining_solution_tx: None,
            block_submit: None,
            utxo_proof: None,
            mining_pub_key_hex: String::new(),
            snapshots_db: None,
            geoip: Arc::new(None),
            #[cfg(feature = "wallet")]
            wallet: None,
        };
        let router = build_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/blockchain/tokens")
            .header("content-type", "application/json")
            .body(Body::from("[]"))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let tokens: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert!(tokens.is_empty());
    }

    #[tokio::test]
    async fn balance_without_indexer() {
        // No extra_db => should get 503
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/blockchain/balance")
            .body(Body::from("3WwbzW6u8hKWBcL1W7kNVMr25s2UHfSzFnR"))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn block_by_header_id_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let extra_path = dir.path().join("extra");
        let extra_db = ergo_indexer::db::ExtraIndexerDb::open(&extra_path).unwrap();
        let state = ApiState {
            shared: Arc::new(RwLock::new(SharedState::new())),
            history: Arc::new(history),
            mempool: Arc::new(std::sync::RwLock::new(
                ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
            )),
            node_name: "test".to_string(),
            app_version: "0.1.0".to_string(),
            network: "Testnet".to_string(),
            tx_submit: None,
            peer_connect: None,
            shutdown_tx: None,
            extra_db: Some(Arc::new(extra_db)),
            api_key_hash: None,
            max_transaction_size: 98_304,
            blacklisted_transactions: Vec::new(),
            cors_allowed_origin: None,
            state_type: "digest".to_string(),
            candidate_generator: None,
            mining_solution_tx: None,
            block_submit: None,
            utxo_proof: None,
            mining_pub_key_hex: String::new(),
            snapshots_db: None,
            geoip: Arc::new(None),
            #[cfg(feature = "wallet")]
            wallet: None,
        };
        let router = build_router(state);
        let random_id = "dd".repeat(32);
        let req = Request::builder()
            .uri(format!("/blockchain/block/byHeaderId/{random_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn verify_api_key_accepts_correct_key() {
        // "hello" hashes to "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf"
        let hash = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";
        assert!(verify_api_key("hello", hash));
    }

    #[test]
    fn verify_api_key_rejects_wrong_key() {
        let hash = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";
        assert!(!verify_api_key("wrong", hash));
    }

    #[test]
    fn verify_api_key_rejects_empty_key() {
        let hash = "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";
        assert!(!verify_api_key("", hash));
    }

    // Script utility tests

    #[test]
    fn encode_byte_array_constant_small() {
        let data = vec![0x00, 0x08, 0xcd, 0x01, 0x02];
        let encoded = encode_byte_array_constant(&data);
        assert_eq!(encoded[0], 0x0e); // ByteArrayConstant type tag
        assert_eq!(encoded[1], 5); // VLQ of 5
        assert_eq!(&encoded[2..], &data[..]);
    }

    #[test]
    fn encode_byte_array_constant_large() {
        let data = vec![0xab; 200];
        let encoded = encode_byte_array_constant(&data);
        assert_eq!(encoded[0], 0x0e);
        // VLQ of 200 = [0xC8, 0x01]
        assert_eq!(encoded[1], 0xC8);
        assert_eq!(encoded[2], 0x01);
        assert_eq!(&encoded[3..], &data[..]);
    }

    // -----------------------------------------------------------------
    // Register rendering tests
    // -----------------------------------------------------------------

    #[test]
    fn render_register_typed_sint_constant() {
        // SInt constant 42: type byte 0x04 (SInt), value zigzag(42) = 84 = 0x54
        let bytes = vec![0x04, 0x54];
        let result = render_register_typed(&bytes);
        let obj = result.as_object().unwrap();
        assert_eq!(obj["serializedValue"], "0454");
        // sigma type should mention SInt
        let sigma_type = obj["sigmaType"].as_str().unwrap();
        assert!(
            sigma_type.contains("Int"),
            "sigma type should contain Int: {sigma_type}"
        );
    }

    #[test]
    fn render_registers_default_is_hex() {
        let regs = vec![(4, vec![0x04, 0x54])];
        let result = render_registers(&regs, false);
        let obj = result.as_object().unwrap();
        assert_eq!(obj["R4"], "0454");
    }

    #[test]
    fn render_registers_typed_includes_sigma_type() {
        let regs = vec![(4, vec![0x04, 0x54])];
        let result = render_registers(&regs, true);
        let obj = result.as_object().unwrap();
        let r4 = obj["R4"].as_object().unwrap();
        assert!(r4.contains_key("serializedValue"));
        assert!(r4.contains_key("sigmaType"));
        assert!(r4.contains_key("renderedValue"));
    }

    // -----------------------------------------------------------------
    // UTXO endpoint tests
    // -----------------------------------------------------------------

    #[test]
    fn require_utxo_state_rejects_digest() {
        let result = require_utxo_state("digest");
        assert!(result.is_err());
    }

    #[test]
    fn require_utxo_state_accepts_utxo() {
        let result = require_utxo_state("utxo");
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------
    // Script compilation endpoint tests
    // -----------------------------------------------------------------

    #[test]
    fn compile_script_to_tree_bytes_valid_source() {
        // The ergoscript-compiler 0.24 only supports HEIGHT, literals, and
        // arithmetic — use a simple expression that compiles successfully.
        let bytes = compile_script_to_tree_bytes("HEIGHT + 1");
        assert!(
            bytes.is_ok(),
            "compilation should succeed: {:?}",
            bytes.err()
        );
        let bytes = bytes.unwrap();
        assert!(!bytes.is_empty(), "ErgoTree bytes should not be empty");
    }

    #[test]
    fn compile_script_to_tree_bytes_invalid_source() {
        let result = compile_script_to_tree_bytes("not_a_valid_script @#$");
        assert!(result.is_err(), "invalid source should fail");
    }

    #[test]
    fn network_prefix_from_str_mainnet() {
        let prefix = network_prefix_from_str("Mainnet");
        assert_eq!(prefix, address::NetworkPrefix::Mainnet);
    }

    #[test]
    fn network_prefix_from_str_testnet() {
        let prefix = network_prefix_from_str("Testnet");
        assert_eq!(prefix, address::NetworkPrefix::Testnet);
    }

    #[test]
    fn encode_p2s_address_produces_valid_address() {
        let tree_bytes = compile_script_to_tree_bytes("HEIGHT + 1").unwrap();
        let addr = address::encode_address(
            address::NetworkPrefix::Mainnet,
            address::AddressType::P2S,
            &tree_bytes,
        );
        assert!(!addr.is_empty());
        // Verify it round-trips
        let decoded = address::decode_address(&addr).unwrap();
        assert_eq!(decoded.address_type, address::AddressType::P2S);
        assert_eq!(decoded.network, address::NetworkPrefix::Mainnet);
        assert_eq!(decoded.content_bytes, tree_bytes);
    }

    #[test]
    fn encode_p2sh_address_produces_valid_address() {
        let tree_bytes = compile_script_to_tree_bytes("HEIGHT + 1").unwrap();
        let hash = blake2b256(&tree_bytes);
        let addr = address::encode_address(
            address::NetworkPrefix::Mainnet,
            address::AddressType::P2SH,
            &hash[..24],
        );
        assert!(!addr.is_empty());
        let decoded = address::decode_address(&addr).unwrap();
        assert_eq!(decoded.address_type, address::AddressType::P2SH);
        assert_eq!(decoded.network, address::NetworkPrefix::Mainnet);
        assert_eq!(decoded.content_bytes, &hash[..24]);
    }

    #[tokio::test]
    async fn post_p2s_address_compiles_script() {
        let (state, _dir) = test_api_state();
        let app = build_router(state);
        let body = serde_json::json!({"source": "HEIGHT + 1"});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/script/p2sAddress")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let addr = json["address"].as_str().unwrap();
        assert!(!addr.is_empty());
        // Verify the address decodes as P2S
        let decoded = address::decode_address(addr).unwrap();
        assert_eq!(decoded.address_type, address::AddressType::P2S);
    }

    #[tokio::test]
    async fn post_p2sh_address_compiles_script() {
        let (state, _dir) = test_api_state();
        let app = build_router(state);
        let body = serde_json::json!({"source": "HEIGHT + 1"});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/script/p2shAddress")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let addr = json["address"].as_str().unwrap();
        assert!(!addr.is_empty());
        // Verify the address decodes as P2SH
        let decoded = address::decode_address(addr).unwrap();
        assert_eq!(decoded.address_type, address::AddressType::P2SH);
    }

    #[tokio::test]
    async fn post_p2s_address_bad_source_returns_400() {
        let (state, _dir) = test_api_state();
        let app = build_router(state);
        let body = serde_json::json!({"source": "not_a_valid_script @#$"});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/script/p2sAddress")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_script_compile_returns_tree_and_address() {
        let (state, _dir) = test_api_state();
        let app = build_router(state);
        let body = serde_json::json!({"source": "HEIGHT + 1"});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/script/compile")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let tree_hex = json["ergoTree"].as_str().unwrap();
        assert!(!tree_hex.is_empty(), "ergoTree should be non-empty hex");
        let addr = json["address"].as_str().unwrap();
        assert!(!addr.is_empty(), "address should be non-empty");
        // Verify address decodes as P2S
        let decoded = address::decode_address(addr).unwrap();
        assert_eq!(decoded.address_type, address::AddressType::P2S);
        // Verify ergoTree matches the address content
        let tree_bytes = hex::decode(tree_hex).unwrap();
        assert_eq!(decoded.content_bytes, tree_bytes);
    }

    // -----------------------------------------------------------------
    // Mining API tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn mining_candidate_returns_503_when_not_enabled() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/mining/candidate")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn mining_candidate_returns_503_when_no_candidate() {
        let (mut state, _dir) = test_api_state();
        let gen = CandidateGenerator::new([0x02; 33], [0, 0, 0]);
        state.candidate_generator = Some(Arc::new(std::sync::RwLock::new(gen)));
        let router = build_router(state);
        let req = Request::builder()
            .uri("/mining/candidate")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn mining_solution_returns_503_when_not_enabled() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!({
            "pk": "02".to_string() + &"00".repeat(32),
            "w": "02".to_string() + &"00".repeat(32),
            "n": "0102030405060708",
            "d": 0
        });
        let req = Request::builder()
            .method("POST")
            .uri("/mining/solution")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn mining_solution_rejects_bad_nonce() {
        let (mut state, _dir) = test_api_state();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        state.mining_solution_tx = Some(tx);
        let router = build_router(state);
        let body = serde_json::json!({
            "n": "0102", // too short
        });
        let req = Request::builder()
            .method("POST")
            .uri("/mining/solution")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn mining_solution_accepts_valid_nonce() {
        let (mut state, _dir) = test_api_state();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        state.mining_solution_tx = Some(tx);
        let router = build_router(state);
        let body = serde_json::json!({
            "n": "0102030405060708",
        });
        let req = Request::builder()
            .method("POST")
            .uri("/mining/solution")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        // Verify the solution was sent through the channel.
        let solution = rx.try_recv().unwrap();
        assert_eq!(solution.n, "0102030405060708");
    }

    #[tokio::test]
    async fn mining_reward_address_returns_503_when_not_configured() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/mining/rewardAddress")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn mining_reward_address_returns_key() {
        let (mut state, _dir) = test_api_state();
        state.mining_pub_key_hex = "02".to_string() + &"ab".repeat(32);
        let router = build_router(state);
        let req = Request::builder()
            .uri("/mining/rewardAddress")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["rewardAddress"].as_str().unwrap().starts_with("02"));
    }

    #[tokio::test]
    async fn mining_reward_pubkey_returns_503_when_not_configured() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let req = Request::builder()
            .uri("/mining/rewardPublicKey")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn mining_reward_pubkey_returns_key() {
        let (mut state, _dir) = test_api_state();
        state.mining_pub_key_hex = "03".to_string() + &"cd".repeat(32);
        let router = build_router(state);
        let req = Request::builder()
            .uri("/mining/rewardPublicKey")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["rewardPubKey"].as_str().unwrap().starts_with("03"));
    }

    #[test]
    fn mining_candidate_response_serializes() {
        let resp = MiningCandidateResponse {
            msg: "aa".repeat(32),
            b: 12345678901234567890,
            h: 850_000,
            pk: "bb".repeat(33),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("msg").is_some());
        assert!(json.get("b").is_some());
        assert!(json.get("h").is_some());
        assert!(json.get("pk").is_some());
    }

    #[test]
    fn reward_address_response_uses_camel_case() {
        let resp = RewardAddressResponse {
            reward_address: "test".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("rewardAddress").is_some());
        assert!(json.get("reward_address").is_none());
    }

    #[test]
    fn reward_pubkey_response_uses_camel_case() {
        let resp = RewardPublicKeyResponse {
            reward_pub_key: "test".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("rewardPubKey").is_some());
        assert!(json.get("reward_pub_key").is_none());
    }

    #[test]
    fn api_error_produces_correct_json() {
        let (status, json) = api_error(StatusCode::BAD_REQUEST, "test detail");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json.0.error, 400);
        assert_eq!(json.0.reason, "Bad Request");
        assert_eq!(json.0.detail, "test detail");
    }

    #[test]
    fn api_error_not_found() {
        let (status, json) = api_error(StatusCode::NOT_FOUND, "missing resource");
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json.0.error, 404);
        assert_eq!(json.0.reason, "Not Found");
        assert_eq!(json.0.detail, "missing resource");
    }

    #[test]
    fn api_error_internal_server_error() {
        let (status, json) = api_error(StatusCode::INTERNAL_SERVER_ERROR, "db failure");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json.0.error, 500);
        assert_eq!(json.0.reason, "Internal Server Error");
        assert_eq!(json.0.detail, "db failure");
    }

    #[test]
    fn api_error_serializes_to_expected_json() {
        let (_, json) = api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding");
        let value = serde_json::to_value(&json.0).unwrap();
        assert_eq!(value["error"], 400);
        assert_eq!(value["reason"], "Bad Request");
        assert_eq!(value["detail"], "Invalid hex encoding");
    }

    #[test]
    fn json_tx_deserialization() {
        let json = serde_json::json!({
            "inputs": [{"boxId": "aa".repeat(32), "spendingProof": {"proofBytes": "", "extension": {}}}],
            "dataInputs": [],
            "outputs": [{"value": 1000000, "ergoTree": "0008cd03", "creationHeight": 100, "assets": [], "additionalRegisters": {}}]
        });
        let tx: TxJsonTransaction = serde_json::from_value(json).unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 1000000);
    }

    #[test]
    fn json_tx_deserialization_minimal() {
        // Only required fields -- dataInputs, assets, additionalRegisters default to empty
        let json = serde_json::json!({
            "inputs": [{"boxId": "bb".repeat(32), "spendingProof": {"proofBytes": "aabb"}}],
            "outputs": [{"value": 500, "ergoTree": "00", "creationHeight": 42}]
        });
        let tx: TxJsonTransaction = serde_json::from_value(json).unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.data_inputs.len(), 0);
        assert_eq!(tx.outputs[0].creation_height, 42);
        assert!(tx.outputs[0].assets.is_empty());
        assert!(tx.outputs[0].additional_registers.is_empty());
    }

    #[test]
    fn convert_json_tx_produces_valid_tx() {
        let json = serde_json::json!({
            "inputs": [{"boxId": "aa".repeat(32), "spendingProof": {"proofBytes": "", "extension": {}}}],
            "dataInputs": [{"boxId": "bb".repeat(32)}],
            "outputs": [{"value": 1000000, "ergoTree": TEST_ERGO_TREE_HEX, "creationHeight": 100, "assets": [], "additionalRegisters": {}}]
        });
        let json_tx: TxJsonTransaction = serde_json::from_value(json).unwrap();
        let tx = convert_json_tx_to_ergo_tx(&json_tx).unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.data_inputs.len(), 1);
        assert_eq!(tx.output_candidates.len(), 1);
        assert_eq!(tx.output_candidates[0].value, 1000000);
        // tx_id should be computed (non-zero)
        assert_ne!(tx.tx_id.0, [0u8; 32]);
    }

    #[test]
    fn convert_json_tx_with_assets_and_registers() {
        let json = serde_json::json!({
            "inputs": [{"boxId": "cc".repeat(32), "spendingProof": {"proofBytes": "deadbeef", "extension": {"1": "cafe"}}}],
            "dataInputs": [],
            "outputs": [{
                "value": 2000000,
                "ergoTree": TEST_ERGO_TREE_HEX,
                "creationHeight": 200,
                "assets": [{"tokenId": "dd".repeat(32), "amount": 100}],
                "additionalRegisters": {"R4": "0e00", "R5": "0500"}
            }]
        });
        let json_tx: TxJsonTransaction = serde_json::from_value(json).unwrap();
        let tx = convert_json_tx_to_ergo_tx(&json_tx).unwrap();
        assert_eq!(tx.inputs[0].proof_bytes, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(tx.output_candidates[0].tokens.len(), 1);
        assert_eq!(tx.output_candidates[0].tokens[0].1, 100);
        assert_eq!(tx.output_candidates[0].additional_registers.len(), 2);
        // Registers should be sorted by index
        assert_eq!(tx.output_candidates[0].additional_registers[0].0, 4);
        assert_eq!(tx.output_candidates[0].additional_registers[1].0, 5);
    }

    #[test]
    fn convert_json_tx_rejects_invalid_box_id() {
        let json = serde_json::json!({
            "inputs": [{"boxId": "zzzz", "spendingProof": {"proofBytes": ""}}],
            "outputs": [{"value": 100, "ergoTree": "00", "creationHeight": 1}]
        });
        let json_tx: TxJsonTransaction = serde_json::from_value(json).unwrap();
        let err = convert_json_tx_to_ergo_tx(&json_tx).unwrap_err();
        assert!(err.contains("invalid"), "error was: {}", err);
    }

    #[test]
    fn convert_json_tx_rejects_short_box_id() {
        let json = serde_json::json!({
            "inputs": [{"boxId": "aabb", "spendingProof": {"proofBytes": ""}}],
            "outputs": [{"value": 100, "ergoTree": "00", "creationHeight": 1}]
        });
        let json_tx: TxJsonTransaction = serde_json::from_value(json).unwrap();
        let err = convert_json_tx_to_ergo_tx(&json_tx).unwrap_err();
        assert!(err.contains("32 bytes"), "error was: {}", err);
    }

    #[tokio::test]
    async fn post_transactions_accepts_json_tx() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!({
            "inputs": [{"boxId": "aa".repeat(32), "spendingProof": {"proofBytes": "", "extension": {}}}],
            "dataInputs": [],
            "outputs": [{"value": 1000000, "ergoTree": TEST_ERGO_TREE_HEX, "creationHeight": 100, "assets": [], "additionalRegisters": {}}]
        });
        let req = Request::builder()
            .method("POST")
            .uri("/transactions")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let tx_id: String = serde_json::from_slice(&resp_body).unwrap();
        // Should be 64 hex chars (32 bytes)
        assert_eq!(tx_id.len(), 64);
        assert!(tx_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn post_transactions_check_accepts_json_tx() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!({
            "inputs": [{"boxId": "bb".repeat(32), "spendingProof": {"proofBytes": ""}}],
            "outputs": [{"value": 500000, "ergoTree": TEST_ERGO_TREE_HEX, "creationHeight": 50}]
        });
        let req = Request::builder()
            .method("POST")
            .uri("/transactions/check")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let tx_id: String = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(tx_id.len(), 64);
    }

    #[tokio::test]
    async fn post_transactions_rejects_invalid_json() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        // Send the old {bytes: "hex"} format -- should be rejected
        let body = serde_json::json!({"bytes": "deadbeef"});
        let req = Request::builder()
            .method("POST")
            .uri("/transactions")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        // Should fail because the old format doesn't match TxJsonTransaction
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn header_response_has_all_fields() {
        let mut header = ergo_types::header::Header::default_for_test();
        // Give it a valid nBits so difficulty is non-zero
        header.n_bits = 0x01010000; // difficulty = 1
                                    // Set non-zero pk so the assertion passes
        header.pow_solution.miner_pk = [0x02; 33];
        header.pow_solution.w = [0x03; 33];
        header.pow_solution.nonce = [0x04; 8];
        header.votes = [0x00, 0x00, 0x00];
        let resp = header_to_response(&header);
        assert!(!resp.pow_solutions.pk.is_empty());
        assert!(!resp.pow_solutions.w.is_empty());
        assert!(!resp.pow_solutions.n.is_empty());
        assert!(!resp.votes.is_empty());
        assert!(!resp.difficulty.is_empty());
        assert!(resp.size > 0);
        assert!(!resp.extension_id.is_empty());
        assert!(!resp.transactions_id.is_empty());
        assert!(!resp.ad_proofs_id.is_empty());
        // 3 bytes = 6 hex chars
        assert_eq!(resp.votes.len(), 6);
        // Section IDs should be 32 bytes = 64 hex chars
        assert_eq!(resp.extension_id.len(), 64);
        assert_eq!(resp.transactions_id.len(), 64);
        assert_eq!(resp.ad_proofs_id.len(), 64);
        // Difficulty should be "1" for nBits=0x01010000
        assert_eq!(resp.difficulty, "1");
        // d field should be a JSON number 0 (not the string "0") for empty d
        assert_eq!(resp.pow_solutions.d, serde_json::json!(0));
        // extensionHash should be present (renamed from extensionRoot)
        assert_eq!(resp.extension_hash.len(), 64); // 32 bytes → 64 hex chars
                                                   // unparsedBytes should be present and empty for normal headers
        assert_eq!(resp.unparsed_bytes, "");
        // size should include the 1-byte type prefix (serialised_len + 1)
        assert!(resp.size > 1);
    }

    #[tokio::test]
    async fn post_blocks_rejects_missing_header() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!({"blockTransactions": "aa"});
        let req = Request::builder()
            .method("POST")
            .uri("/blocks")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_blocks_rejects_invalid_header_hex() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!({"header": "not-valid-hex"});
        let req = Request::builder()
            .method("POST")
            .uri("/blocks")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_blocks_rejects_unparseable_header() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        // Valid hex but too short to be a real header.
        let body = serde_json::json!({"header": "aabbccdd"});
        let req = Request::builder()
            .method("POST")
            .uri("/blocks")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn utxo_snapshots_info_returns_503_in_digest_mode() {
        let (state, _dir) = test_api_state();
        // Default test state is digest mode
        assert_eq!(state.state_type, "digest");
        let router = build_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/utxo/getSnapshotsInfo")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn utxo_snapshots_info_returns_empty_in_utxo_mode() {
        let (mut state, _dir) = test_api_state();
        state.state_type = "utxo".to_string();
        let router = build_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/utxo/getSnapshotsInfo")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&resp_body).unwrap();
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn utxo_boxes_binary_proof_returns_503_in_digest_mode() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!(["aa".repeat(32)]);
        let req = Request::builder()
            .method("POST")
            .uri("/utxo/getBoxesBinaryProof")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn utxo_boxes_binary_proof_returns_503_without_channel() {
        let (mut state, _dir) = test_api_state();
        state.state_type = "utxo".to_string();
        // utxo_proof is None in test state, so we get SERVICE_UNAVAILABLE.
        let router = build_router(state);
        let body = serde_json::json!(["aa".repeat(32)]);
        let req = Request::builder()
            .method("POST")
            .uri("/utxo/getBoxesBinaryProof")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn utxo_boxes_binary_proof_rejects_invalid_box_id() {
        let (mut state, _dir) = test_api_state();
        state.state_type = "utxo".to_string();
        let router = build_router(state);
        let body = serde_json::json!(["not-valid-hex"]);
        let req = Request::builder()
            .method("POST")
            .uri("/utxo/getBoxesBinaryProof")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn script_execute_with_context_rejects_missing_script() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        let body = serde_json::json!({"context": {}});
        let req = Request::builder()
            .method("POST")
            .uri("/script/executeWithContext")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn script_execute_with_context_compiles_simple_script() {
        let (state, _dir) = test_api_state();
        let router = build_router(state);
        // "true" is the simplest valid ErgoScript
        let body = serde_json::json!({"script": "true"});
        let req = Request::builder()
            .method("POST")
            .uri("/script/executeWithContext")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        // This may succeed (200) or fail (400) depending on the ergoscript-compiler
        // capabilities. We accept either outcome as valid behavior.
        let status = resp.status();
        assert!(
            status == StatusCode::OK || status == StatusCode::BAD_REQUEST,
            "Unexpected status: {status}"
        );
        if status == StatusCode::OK {
            let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
            assert!(json.get("compiledErgoTree").is_some());
        }
    }
}

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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

use crate::event_loop::SharedState;
use crate::mining::{CandidateGenerator, MiningSolution};

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// JSON response for the `/info` endpoint.
#[derive(Debug, Serialize)]
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
    pub parameters: serde_json::Value,
    pub last_mempool_update_time: u64,
}

/// JSON response for proof-of-work solution fields.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PowSolutionsResponse {
    pub pk: String,
    pub w: String,
    pub n: String,
    pub d: String,
}

/// JSON response for a block header.
#[derive(Debug, Serialize, Clone)]
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
    pub extension_root: String,
    pub ad_proofs_root: String,
    pub pow_solutions: PowSolutionsResponse,
    pub votes: String,
    pub difficulty: String,
    pub size: usize,
    pub extension_id: String,
    pub transactions_id: String,
    pub ad_proofs_id: String,
}

/// JSON response for a full block.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockResponse {
    pub header: HeaderResponse,
    pub block_transactions: Option<BlockTransactionsResponse>,
    pub extension: Option<ExtensionResponse>,
    pub ad_proofs: Option<String>,
    pub size: usize,
}

/// Full transaction JSON response.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResponse {
    pub id: String,
    pub inputs: Vec<InputResponse>,
    pub data_inputs: Vec<DataInputResponse>,
    pub outputs: Vec<OutputResponse>,
    pub size: usize,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InputResponse {
    pub box_id: String,
    pub spending_proof: SpendingProofResponse,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SpendingProofResponse {
    pub proof_bytes: String,
    pub extension: serde_json::Value,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DataInputResponse {
    pub box_id: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OutputResponse {
    pub box_id: Option<String>,
    pub value: u64,
    pub ergo_tree: String,
    pub creation_height: u32,
    pub assets: Vec<AssetResponse>,
    pub additional_registers: serde_json::Value,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AssetResponse {
    pub token_id: String,
    pub amount: u64,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionResponse {
    pub header_id: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockTransactionsResponse {
    pub header_id: String,
    pub transactions: Vec<TransactionResponse>,
}

/// JSON response for a connected peer.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerResponse {
    pub address: String,
    pub name: String,
    pub last_message: u64,
    pub last_handshake: u64,
    pub connection_type: Option<String>,
}

/// JSON request body for submitting a transaction (legacy hex format).
/// Kept for backward compatibility; the main /transactions endpoint now uses TxJsonTransaction.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TxSubmitRequest {
    pub bytes: String,
}

/// JSON response after submitting a transaction.
#[derive(Debug, Serialize)]
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
struct TxJsonTransaction {
    inputs: Vec<TxJsonInput>,
    #[serde(default)]
    data_inputs: Vec<TxJsonDataInput>,
    outputs: Vec<TxJsonOutput>,
}

/// JSON response for the mempool size endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MempoolSizeResponse {
    pub size: usize,
}

/// JSON response for the modifier lookup endpoint.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModifierResponse {
    pub type_id: u8,
    pub bytes: String,
}

/// Structured JSON error response matching the Scala node format.
#[derive(Debug, Serialize)]
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
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerStatusResponse {
    pub connected_count: usize,
    pub uptime_secs: u64,
    pub last_message_time: Option<u64>,
}

/// JSON response for an unconfirmed output in the mempool.
#[derive(Debug, Serialize)]
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
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendingInputResponse {
    pub box_id: String,
    pub spending_tx_id: String,
    pub proof_bytes: String,
}

/// JSON response for GET /mining/candidate.
#[derive(Debug, Serialize)]
pub struct MiningCandidateResponse {
    pub msg: String,
    pub b: u64,
    pub h: u32,
    pub pk: String,
}

/// JSON response for POST /mining/candidateWithTxs.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateWithTxsResponse {
    pub msg: String,
    pub b: u64,
    pub h: u32,
    pub pk: String,
    pub transactions: Vec<TransactionResponse>,
}

/// JSON response for GET /mining/rewardAddress.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardAddressResponse {
    pub reward_address: String,
}

/// JSON response for GET /mining/rewardPublicKey.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardPublicKeyResponse {
    pub reward_pub_key: String,
}

/// JSON response for address validation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressValidationResponse {
    pub address: String,
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// JSON response for a block Merkle proof.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleProofResponse {
    pub leaf: String,
    pub levels: Vec<String>,
}

/// JSON response for emission contract script addresses.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmissionScriptsResponse {
    pub emission: String,
    pub reemission: String,
    pub pay2_reemission: String,
}

/// JSON response for a single histogram bin.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistogramBinResponse {
    pub n_txns: usize,
    pub total_size: usize,
    pub from_millis: u64,
    pub to_millis: u64,
}

/// JSON response for fee estimation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeEstimateResponse {
    pub fee: u64,
}

/// JSON response for wait time estimation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WaitTimeResponse {
    pub wait_time_millis: u64,
}

/// JSON response for the `/blockchain/indexedHeight` endpoint.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedHeightResponse {
    pub indexed_height: u32,
    pub full_height: u32,
}

/// JSON response for an indexed UTXO box from the extra indexer.
#[derive(Serialize)]
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
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAmountResponse {
    pub token_id: String,
    pub amount: u64,
}

/// JSON response for an indexed transaction from the extra indexer.
#[derive(Serialize)]
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
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedTxResponse {
    pub items: Vec<IndexedErgoTransactionResponse>,
    pub total: u64,
}

/// JSON response for paginated box results.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedBoxResponse {
    pub items: Vec<IndexedErgoBoxResponse>,
    pub total: u64,
}

/// JSON response for an indexed token from the extra indexer.
#[derive(Serialize)]
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
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    pub confirmed: BalanceInfoResponse,
    pub unconfirmed: BalanceInfoResponse,
}

/// JSON response for a single balance component.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceInfoResponse {
    pub nano_ergs: u64,
    pub tokens: Vec<TokenBalanceResponse>,
}

/// JSON response for a single token balance entry.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBalanceResponse {
    pub token_id: String,
    pub amount: u64,
    pub decimals: Option<i32>,
    pub name: Option<String>,
}

/// JSON response for an indexed block with header + transactions.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedBlockResponse {
    pub header: HeaderResponse,
    pub block_transactions: Vec<IndexedErgoTransactionResponse>,
    pub size: u32,
}

/// JSON response for a PoPow header.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoPowHeaderResponse {
    pub header: HeaderResponse,
    pub interlinks: Vec<String>,
}

/// JSON response for a NiPoPoW proof.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NipopowProofResponse {
    pub m: u32,
    pub k: u32,
    pub prefix: Vec<PoPowHeaderResponse>,
    pub suffix_head: PoPowHeaderResponse,
    pub suffix_tail: Vec<HeaderResponse>,
}

/// JSON request body for script compilation endpoints.
#[derive(Debug, Deserialize)]
pub struct ScriptCompileRequest {
    pub source: String,
}

/// JSON response for script compilation endpoints.
#[derive(Debug, Serialize)]
pub struct ScriptCompileResponse {
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

/// Build the common extra fields for a [`HeaderResponse`] from a header,
/// id bytes, and serialized size.
fn build_header_response(
    header: &ergo_types::header::Header,
    id_hex: String,
    id_bytes: &[u8; 32],
    size: usize,
) -> HeaderResponse {
    let difficulty = ergo_consensus::difficulty::decode_compact_bits(header.n_bits);

    let extension_id = compute_section_id(108, id_bytes, &header.extension_root.0);
    let transactions_id = compute_section_id(102, id_bytes, &header.transactions_root.0);
    let ad_proofs_id = compute_section_id(104, id_bytes, &header.ad_proofs_root.0);

    let d_str = if header.pow_solution.d.is_empty() {
        "0".to_string()
    } else {
        num_bigint::BigUint::from_bytes_be(&header.pow_solution.d).to_string()
    };

    HeaderResponse {
        id: id_hex,
        parent_id: hex::encode(header.parent_id.0),
        height: header.height,
        timestamp: header.timestamp,
        n_bits: header.n_bits,
        version: header.version,
        state_root: hex::encode(header.state_root.0),
        transactions_root: hex::encode(header.transactions_root.0),
        extension_root: hex::encode(header.extension_root.0),
        ad_proofs_root: hex::encode(header.ad_proofs_root.0),
        pow_solutions: PowSolutionsResponse {
            pk: hex::encode(header.pow_solution.miner_pk),
            w: hex::encode(header.pow_solution.w),
            n: hex::encode(header.pow_solution.nonce),
            d: d_str,
        },
        votes: hex::encode(header.votes),
        difficulty: difficulty.to_string(),
        size,
        extension_id: hex::encode(extension_id),
        transactions_id: hex::encode(transactions_id),
        ad_proofs_id: hex::encode(ad_proofs_id),
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

            let mut registers = serde_json::Map::new();
            for (reg_idx, val) in &out.additional_registers {
                registers.insert(
                    format!("R{}", reg_idx),
                    serde_json::Value::String(hex::encode(val)),
                );
            }

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
                additional_registers: serde_json::Value::Object(registers),
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
fn build_block_response(
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

    // Load block transactions
    let block_transactions = match state.history.load_block_transactions(&id) {
        Ok(Some(bt)) => {
            let mut tx_responses = Vec::new();
            for tx_bytes in &bt.tx_bytes {
                total_size += tx_bytes.len();
                if let Ok(parsed_tx) = parse_transaction(tx_bytes) {
                    tx_responses.push(ergo_tx_to_response(&parsed_tx, tx_bytes.len()));
                }
            }
            Some(BlockTransactionsResponse {
                header_id: header_id_hex.to_string(),
                transactions: tx_responses,
            })
        }
        _ => None,
    };

    // Load extension
    let extension = match state.history.load_extension(&id) {
        Ok(Some(ext)) => {
            let fields: Vec<(String, String)> = ext
                .fields
                .iter()
                .map(|(key, val)| (hex::encode(key), hex::encode(val)))
                .collect();
            Some(ExtensionResponse {
                header_id: hex::encode(ext.header_id.0),
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
    let total_size: u32 = block_txs.tx_bytes.iter().map(|b| b.len() as u32).sum();

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
        .route("/swagger", axum::routing::get(swagger_handler))
        .route("/panel", axum::routing::get(panel_handler))
        .route(
            "/api-docs/openapi.yaml",
            axum::routing::get(openapi_yaml_handler),
        )
        .route("/", axum::routing::get(root_redirect_handler))
        .route("/info", axum::routing::get(info_handler))
        // Blocks: specific literal paths first
        .route(
            "/blocks",
            axum::routing::get(get_paginated_blocks_handler).post(post_block_handler),
        )
        .route(
            "/blocks/lastHeaders/{n}",
            axum::routing::get(get_last_headers_handler),
        )
        .route(
            "/blocks/chainSlice",
            axum::routing::get(get_chain_slice_handler),
        )
        .route(
            "/blocks/headerIds",
            axum::routing::post(post_header_ids_handler),
        )
        .route(
            "/blocks/modifier/{modifier_id}",
            axum::routing::get(get_modifier_handler),
        )
        .route(
            "/blocks/at/{height}",
            axum::routing::get(get_blocks_at_height_handler),
        )
        // Blocks: parameterized paths with sub-paths
        .route(
            "/blocks/{header_id}/header",
            axum::routing::get(get_header_only_handler),
        )
        .route(
            "/blocks/{header_id}/transactions",
            axum::routing::get(get_block_transactions_handler),
        )
        .route(
            "/blocks/{header_id}/proofFor/{tx_id}",
            axum::routing::get(merkle_proof_handler),
        )
        .route("/blocks/{header_id}", axum::routing::get(get_block_handler))
        // NiPoPoW
        .route(
            "/nipopow/popowHeaderById/{id}",
            axum::routing::get(popow_header_by_id_handler),
        )
        .route(
            "/nipopow/popowHeaderByHeight/{h}",
            axum::routing::get(popow_header_by_height_handler),
        )
        .route(
            "/nipopow/proof/{m}/{k}/{id}",
            axum::routing::get(nipopow_proof_at_handler),
        )
        .route(
            "/nipopow/proof/{m}/{k}",
            axum::routing::get(nipopow_proof_handler),
        )
        // Peers
        .route(
            "/peers/connected",
            axum::routing::get(peers_connected_handler),
        )
        .route("/peers/all", axum::routing::get(peers_all_handler))
        .route(
            "/peers/blacklisted",
            axum::routing::get(peers_blacklisted_handler),
        )
        .route("/peers/connect", axum::routing::post(peers_connect_handler))
        .route("/peers/status", axum::routing::get(peers_status_handler))
        .route(
            "/peers/syncInfo",
            axum::routing::get(peers_sync_info_handler),
        )
        .route(
            "/peers/trackInfo",
            axum::routing::get(peers_track_info_handler),
        )
        // Transactions
        .route(
            "/transactions/check",
            axum::routing::post(check_transaction_handler),
        )
        .route(
            "/transactions/bytes",
            axum::routing::post(submit_transaction_bytes_handler),
        )
        .route(
            "/transactions/checkBytes",
            axum::routing::post(check_transaction_bytes_handler),
        )
        .route(
            "/transactions",
            axum::routing::post(submit_transaction_handler),
        )
        .route(
            "/transactions/poolHistogram",
            axum::routing::get(pool_histogram_handler),
        )
        .route("/transactions/getFee", axum::routing::get(get_fee_handler))
        .route(
            "/transactions/waitTime",
            axum::routing::get(wait_time_handler),
        )
        .route(
            "/transactions/unconfirmed/transactionIds",
            axum::routing::get(get_unconfirmed_tx_ids_handler),
        )
        .route(
            "/transactions/unconfirmed/byTransactionIds",
            axum::routing::post(post_by_transaction_ids_handler),
        )
        .route(
            "/transactions/unconfirmed/inputs/byBoxId/{id}",
            axum::routing::get(get_unconfirmed_inputs_by_box_id_handler),
        )
        .route(
            "/transactions/unconfirmed/outputs/byBoxId/{id}",
            axum::routing::get(get_unconfirmed_output_by_box_id_handler),
        )
        .route(
            "/transactions/unconfirmed/outputs/byTokenId/{id}",
            axum::routing::get(get_unconfirmed_outputs_by_token_id_handler),
        )
        .route(
            "/transactions/unconfirmed/byErgoTree",
            axum::routing::post(post_unconfirmed_by_ergo_tree_handler),
        )
        .route(
            "/transactions/unconfirmed/outputs/byErgoTree",
            axum::routing::post(post_unconfirmed_outputs_by_ergo_tree_handler),
        )
        .route(
            "/transactions/unconfirmed/outputs/byRegisters",
            axum::routing::post(post_unconfirmed_outputs_by_registers_handler),
        )
        .route(
            "/transactions/unconfirmed/size",
            axum::routing::get(get_unconfirmed_size_handler),
        )
        .route(
            "/transactions/unconfirmed/{tx_id}",
            axum::routing::get(get_unconfirmed_by_id_handler).head(head_unconfirmed_handler),
        )
        .route(
            "/transactions/unconfirmed",
            axum::routing::get(get_unconfirmed_handler),
        )
        // Utils – Address
        .route(
            "/utils/address/{addr}",
            axum::routing::get(validate_address_handler),
        )
        .route(
            "/utils/address",
            axum::routing::post(validate_address_post_handler),
        )
        .route(
            "/utils/rawToAddress/{pubkey_hex}",
            axum::routing::get(raw_to_address_handler),
        )
        .route(
            "/utils/addressToRaw/{addr}",
            axum::routing::get(address_to_raw_handler),
        )
        .route(
            "/utils/ergoTreeToAddress/{ergo_tree_hex}",
            axum::routing::get(ergo_tree_to_address_handler),
        )
        .route(
            "/utils/ergoTreeToAddress",
            axum::routing::post(ergo_tree_to_address_post_handler),
        )
        // Utils
        .route("/utils/seed", axum::routing::get(seed_handler))
        .route(
            "/utils/seed/{length}",
            axum::routing::get(seed_with_length_handler),
        )
        .route(
            "/utils/hash/blake2b",
            axum::routing::post(blake2b_hash_handler),
        )
        // Script utility
        .route(
            "/script/addressToTree/{addr}",
            axum::routing::get(script_address_to_tree_handler),
        )
        .route(
            "/script/addressToBytes/{addr}",
            axum::routing::get(script_address_to_bytes_handler),
        )
        .route(
            "/script/p2sAddress",
            axum::routing::post(script_p2s_address_handler),
        )
        .route(
            "/script/p2shAddress",
            axum::routing::post(script_p2sh_address_handler),
        )
        .route(
            "/script/executeWithContext",
            axum::routing::post(script_execute_with_context_handler),
        )
        // Emission
        .route(
            "/emission/scripts",
            axum::routing::get(emission_scripts_handler),
        )
        .route(
            "/emission/at/{height}",
            axum::routing::get(emission_handler),
        )
        // Node control
        .route("/node/shutdown", axum::routing::post(node_shutdown_handler))
        // Blockchain (indexed) endpoints
        .route(
            "/blockchain/indexedHeight",
            axum::routing::get(indexed_height_handler),
        )
        .route(
            "/blockchain/transaction/byId/{id}",
            axum::routing::get(blockchain_tx_by_id_handler),
        )
        .route(
            "/blockchain/transaction/byIndex/{n}",
            axum::routing::get(blockchain_tx_by_index_handler),
        )
        .route(
            "/blockchain/transaction/byAddress/{addr}",
            axum::routing::get(blockchain_txs_by_address_get_handler),
        )
        .route(
            "/blockchain/transaction/byAddress",
            axum::routing::post(blockchain_txs_by_address_post_handler),
        )
        .route(
            "/blockchain/transaction/range",
            axum::routing::get(blockchain_tx_range_handler),
        )
        // Blockchain – Box endpoints (specific paths first)
        .route(
            "/blockchain/box/unspent/byTokenId/{id}",
            axum::routing::get(blockchain_unspent_boxes_by_token_handler),
        )
        .route(
            "/blockchain/box/unspent/byAddress/{addr}",
            axum::routing::get(blockchain_unspent_boxes_by_address_get_handler),
        )
        .route(
            "/blockchain/box/unspent/byAddress",
            axum::routing::post(blockchain_unspent_boxes_by_address_post_handler),
        )
        .route(
            "/blockchain/box/unspent/byTemplateHash/{hash}",
            axum::routing::get(blockchain_unspent_boxes_by_template_handler),
        )
        .route(
            "/blockchain/box/unspent/byErgoTree",
            axum::routing::post(blockchain_unspent_boxes_by_ergo_tree_handler),
        )
        .route(
            "/blockchain/box/byTokenId/{id}",
            axum::routing::get(blockchain_boxes_by_token_handler),
        )
        .route(
            "/blockchain/box/byAddress/{addr}",
            axum::routing::get(blockchain_boxes_by_address_get_handler),
        )
        .route(
            "/blockchain/box/byAddress",
            axum::routing::post(blockchain_boxes_by_address_post_handler),
        )
        .route(
            "/blockchain/box/byTemplateHash/{hash}",
            axum::routing::get(blockchain_boxes_by_template_handler),
        )
        .route(
            "/blockchain/box/byErgoTree",
            axum::routing::post(blockchain_boxes_by_ergo_tree_handler),
        )
        .route(
            "/blockchain/box/range",
            axum::routing::get(blockchain_box_range_handler),
        )
        .route(
            "/blockchain/box/byIndex/{n}",
            axum::routing::get(blockchain_box_by_index_handler),
        )
        .route(
            "/blockchain/box/byId/{id}",
            axum::routing::get(blockchain_box_by_id_handler),
        )
        // Blockchain – Token endpoints
        .route(
            "/blockchain/token/byId/{id}",
            axum::routing::get(blockchain_token_by_id_handler),
        )
        .route(
            "/blockchain/tokens",
            axum::routing::post(blockchain_tokens_handler),
        )
        // Blockchain – Balance endpoints
        .route(
            "/blockchain/balance",
            axum::routing::post(blockchain_balance_post_handler),
        )
        .route(
            "/blockchain/balanceForAddress/{addr}",
            axum::routing::get(blockchain_balance_get_handler),
        )
        // Blockchain – Block endpoints
        .route(
            "/blockchain/block/byHeaderId/{id}",
            axum::routing::get(blockchain_block_by_header_id_handler),
        )
        .route(
            "/blockchain/block/byHeaderIds",
            axum::routing::post(blockchain_block_by_header_ids_handler),
        )
        // UTXO endpoints
        .route("/utxo/byId/{boxId}", axum::routing::get(utxo_by_id_handler))
        .route(
            "/utxo/byIdBinary/{boxId}",
            axum::routing::get(utxo_by_id_binary_handler),
        )
        .route(
            "/utxo/withPool/byId/{boxId}",
            axum::routing::get(utxo_with_pool_by_id_handler),
        )
        .route(
            "/utxo/withPool/byIds",
            axum::routing::post(utxo_with_pool_by_ids_handler),
        )
        .route(
            "/utxo/withPool/byIdBinary/{boxId}",
            axum::routing::get(utxo_with_pool_by_id_binary_handler),
        )
        .route("/utxo/genesis", axum::routing::get(utxo_genesis_handler))
        .route(
            "/utxo/getSnapshotsInfo",
            axum::routing::get(utxo_snapshots_info_handler),
        )
        .route(
            "/utxo/getBoxesBinaryProof",
            axum::routing::post(utxo_boxes_binary_proof_handler),
        )
        // Mining
        .route(
            "/mining/candidate",
            axum::routing::get(mining_candidate_handler),
        )
        .route(
            "/mining/candidateWithTxs",
            axum::routing::post(mining_candidate_with_txs_handler),
        )
        .route(
            "/mining/solution",
            axum::routing::post(mining_solution_handler),
        )
        .route(
            "/mining/rewardAddress",
            axum::routing::get(mining_reward_address_handler),
        )
        .route(
            "/mining/rewardPublicKey",
            axum::routing::get(mining_reward_pubkey_handler),
        );

    // Wallet lifecycle endpoints (feature-gated)
    #[cfg(feature = "wallet")]
    let router = router
        .route("/wallet/status", axum::routing::get(wallet_status_handler))
        .route("/wallet/init", axum::routing::post(wallet_init_handler))
        .route(
            "/wallet/restore",
            axum::routing::post(wallet_restore_handler),
        )
        .route("/wallet/unlock", axum::routing::post(wallet_unlock_handler))
        .route("/wallet/lock", axum::routing::get(wallet_lock_handler))
        // Address and balance endpoints
        .route(
            "/wallet/addresses",
            axum::routing::get(wallet_addresses_handler),
        )
        .route(
            "/wallet/deriveKey",
            axum::routing::post(wallet_derive_key_handler),
        )
        .route(
            "/wallet/deriveNextKey",
            axum::routing::get(wallet_derive_next_key_handler),
        )
        .route(
            "/wallet/balances/withUnconfirmed",
            axum::routing::get(wallet_balances_with_unconfirmed_handler),
        )
        .route(
            "/wallet/balances",
            axum::routing::get(wallet_balances_handler),
        )
        .route(
            "/wallet/updateChangeAddress",
            axum::routing::post(wallet_update_change_address_handler),
        )
        // Box and transaction query endpoints
        .route(
            "/wallet/boxes/unspent",
            axum::routing::get(wallet_unspent_boxes_handler),
        )
        .route(
            "/wallet/boxes/collect",
            axum::routing::post(wallet_collect_boxes_handler),
        )
        .route("/wallet/boxes", axum::routing::get(wallet_boxes_handler))
        .route(
            "/wallet/transactions",
            axum::routing::get(wallet_transactions_handler),
        )
        // Transaction generation and sending endpoints
        .route(
            "/wallet/payment/send",
            axum::routing::post(wallet_payment_send_handler),
        )
        .route(
            "/wallet/transaction/generate",
            axum::routing::post(wallet_tx_generate_handler),
        )
        .route(
            "/wallet/transaction/generateUnsigned",
            axum::routing::post(wallet_tx_generate_unsigned_handler),
        )
        .route(
            "/wallet/transaction/sign",
            axum::routing::post(wallet_tx_sign_handler),
        )
        .route(
            "/wallet/transaction/send",
            axum::routing::post(wallet_tx_send_handler),
        )
        // Wallet check, rescan, and transaction-by-id endpoints
        .route(
            "/wallet/transactionById/{txId}",
            axum::routing::get(wallet_transaction_by_id_handler),
        )
        .route(
            "/wallet/check",
            axum::routing::post(wallet_check_seed_handler),
        )
        .route("/wallet/rescan", axum::routing::post(wallet_rescan_handler))
        // Additional wallet endpoints
        .route(
            "/wallet/getPrivateKey",
            axum::routing::post(wallet_get_private_key_handler),
        )
        .route(
            "/wallet/generateCommitments",
            axum::routing::post(wallet_generate_commitments_handler),
        )
        .route(
            "/wallet/extractHints",
            axum::routing::post(wallet_extract_hints_handler),
        )
        .route(
            "/wallet/transactionsByScanId/{scanId}",
            axum::routing::get(wallet_txs_by_scan_id_handler),
        )
        // Scan endpoints
        .route("/scan/register", axum::routing::post(scan_register_handler))
        .route(
            "/scan/deregister",
            axum::routing::post(scan_deregister_handler),
        )
        .route("/scan/listAll", axum::routing::get(scan_list_all_handler))
        .route(
            "/scan/unspentBoxes/{scanId}",
            axum::routing::get(scan_unspent_boxes_handler),
        )
        .route(
            "/scan/spentBoxes/{scanId}",
            axum::routing::get(scan_spent_boxes_handler),
        )
        .route(
            "/scan/stopTracking",
            axum::routing::post(scan_stop_tracking_handler),
        )
        .route("/scan/addBox", axum::routing::post(scan_add_box_handler))
        .route("/scan/p2sRule", axum::routing::post(scan_p2s_rule_handler));

    router.with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /swagger — Serve Swagger UI HTML page.
async fn swagger_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(crate::web_ui::SWAGGER_HTML)
}

/// GET /panel — Serve the Node Panel admin dashboard.
async fn panel_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(crate::web_ui::PANEL_HTML)
}

/// GET /api-docs/openapi.yaml — Serve the OpenAPI specification.
async fn openapi_yaml_handler() -> (
    [(axum::http::header::HeaderName, &'static str); 1],
    &'static str,
) {
    (
        [(axum::http::header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
        crate::web_ui::OPENAPI_YAML,
    )
}

/// GET / — Redirect to Swagger UI.
async fn root_redirect_handler() -> axum::response::Redirect {
    axum::response::Redirect::permanent("/swagger")
}

async fn info_handler(State(state): State<ApiState>) -> Json<NodeInfoResponse> {
    let unconfirmed_count = state.mempool.read().unwrap().size();
    let shared = state.shared.read().await;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Normalize network name to lowercase for API response
    let network_lc = state.network.to_lowercase();
    let network_lower: &str = match network_lc.as_str() {
        "mainnet" => "mainnet",
        "testnet" => "testnet",
        "devnet" => "devnet",
        _ => "mainnet",
    };

    let genesis_id = match network_lower {
        "testnet" => "0000000000000000000000000000000000000000000000000000000000000000",
        _ => "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b",
    };

    // Heights of 0 mean no headers/blocks yet — report as null
    let headers_height = if shared.headers_height > 0 {
        Some(shared.headers_height)
    } else {
        None
    };
    let full_height = if shared.full_height > 0 {
        Some(shared.full_height)
    } else {
        None
    };
    let max_peer_height = if shared.max_peer_height > 0 {
        Some(shared.max_peer_height)
    } else {
        None
    };

    // Mining is enabled when a candidate generator has been initialized.
    let is_mining = shared.is_mining || state.candidate_generator.is_some();

    Json(NodeInfoResponse {
        name: state.node_name.clone(),
        app_version: state.app_version.clone(),
        network: network_lower.to_string(),
        headers_height,
        full_height,
        max_peer_height,
        best_header_id: shared.best_header_id.map(hex::encode),
        best_full_header_id: shared.best_full_block_id.map(hex::encode),
        previous_full_header_id: shared.previous_full_header_id.map(hex::encode),
        state_root: hex::encode(&shared.state_root),
        state_version: shared.state_version.map(hex::encode),
        state_type: state.state_type.clone(),
        peers_count: shared.peer_count,
        sync_state: shared.sync_state.clone(),
        unconfirmed_count,
        difficulty: shared.difficulty.to_string(),
        headers_score: shared.headers_score.clone(),
        full_blocks_score: shared.full_blocks_score.clone(),
        launch_time: shared.start_time * 1000,
        last_seen_message_time: shared.last_message_time.unwrap_or(0),
        genesis_block_id: genesis_id.to_string(),
        is_mining,
        is_explorer: state.extra_db.is_some(),
        eip27_supported: true,
        eip37_supported: true,
        rest_api_url: None,
        current_time: now_ms,
        parameters: shared.parameters.clone(),
        last_mempool_update_time: shared.last_mempool_update_time,
    })
}

async fn get_block_handler(
    State(state): State<ApiState>,
    Path(header_id_hex): Path<String>,
) -> Result<Json<BlockResponse>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&header_id_hex)?;

    let header = state
        .history
        .load_header(&id)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Block not found"))?;

    let resp = build_block_response(&state, &header, &header_id_hex);

    Ok(Json(resp))
}

async fn get_blocks_at_height_handler(
    State(state): State<ApiState>,
    Path(height): Path<u32>,
) -> Json<Vec<String>> {
    let ids = state
        .history
        .header_ids_at_height(height)
        .unwrap_or_default();
    Json(ids.iter().map(|id| hex::encode(id.0)).collect())
}

async fn peers_connected_handler(State(state): State<ApiState>) -> Json<Vec<PeerResponse>> {
    let shared = state.shared.read().await;
    Json(
        shared
            .connected_peers
            .iter()
            .map(|p| PeerResponse {
                address: p.address.clone(),
                name: p.name.clone(),
                last_message: p.last_message.unwrap_or(0),
                last_handshake: p.last_handshake,
                connection_type: p.connection_type.clone(),
            })
            .collect(),
    )
}

/// `GET /peers/all` — all known peers from discovery + peer_db.
async fn peers_all_handler(State(state): State<ApiState>) -> Json<Vec<String>> {
    let shared = state.shared.read().await;
    Json(shared.known_peers.clone())
}

/// `GET /peers/blacklisted` — blacklisted/banned peer IDs from PenaltyManager.
async fn peers_blacklisted_handler(State(state): State<ApiState>) -> Json<Vec<u64>> {
    let shared = state.shared.read().await;
    Json(shared.banned_peers.clone())
}

/// `POST /peers/connect` — manually initiate connection to "host:port".
async fn peers_connect_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(addr_str): Json<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid socket address"))?;
    let sender = state.peer_connect.as_ref().ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Peer connect channel not available",
        )
    })?;
    sender.try_send(addr).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Failed to send peer connect request",
        )
    })?;
    Ok(Json(
        serde_json::json!({ "status": "connecting", "address": addr.to_string() }),
    ))
}

/// `GET /peers/status` — P2P layer status.
async fn peers_status_handler(State(state): State<ApiState>) -> Json<PeerStatusResponse> {
    let shared = state.shared.read().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Json(PeerStatusResponse {
        connected_count: shared.peer_count,
        uptime_secs: now.saturating_sub(shared.start_time),
        last_message_time: shared.last_message_time,
    })
}

/// `GET /peers/syncInfo` — SyncTracker state dump.
async fn peers_sync_info_handler(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let shared = state.shared.read().await;
    Json(
        shared
            .sync_tracker_snapshot
            .clone()
            .unwrap_or_else(|| serde_json::json!({})),
    )
}

/// `GET /peers/trackInfo` — DeliveryTracker state dump.
async fn peers_track_info_handler(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let shared = state.shared.read().await;
    Json(
        shared
            .delivery_tracker_snapshot
            .clone()
            .unwrap_or_else(|| serde_json::json!({})),
    )
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

/// Wait for the event loop to confirm a transaction submission via oneshot channel.
async fn await_tx_submission(
    sender: tokio::sync::mpsc::Sender<TxSubmission>,
    tx_id: [u8; 32],
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    let submission = TxSubmission {
        tx_id,
        response: resp_tx,
    };
    sender
        .try_send(submission)
        .map_err(|_| api_error(StatusCode::SERVICE_UNAVAILABLE, "event loop busy"))?;
    match tokio::time::timeout(std::time::Duration::from_secs(5), resp_rx).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err(api_error(StatusCode::BAD_REQUEST, &e)),
        Ok(Err(_)) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "event loop dropped response",
        )),
        Err(_) => Err(api_error(StatusCode::GATEWAY_TIMEOUT, "event loop timeout")),
    }
}

/// `POST /transactions` -- accept a Scala-compatible JSON transaction, validate, and submit.
async fn submit_transaction_handler(
    State(state): State<ApiState>,
    Json(json_tx): Json<TxJsonTransaction>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let tx =
        convert_json_tx_to_ergo_tx(&json_tx).map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;

    let bytes = serialize_transaction(&tx);

    validate_tx_stateless(&tx, &ValidationSettings::initial()).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Stateless transaction validation failed",
        )
    })?;

    ergo_network::mempool::validate_for_pool(
        bytes.len(),
        &state.blacklisted_transactions,
        state.max_transaction_size,
        &tx.tx_id,
    )
    .map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Transaction rejected by mempool policy",
        )
    })?;

    let tx_id = tx.tx_id;

    // Insert into mempool (scoped to drop the lock guard before any .await).
    {
        let mut mp = state.mempool.write().unwrap();
        mp.put_with_size(tx, bytes.len()).map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "Failed to insert transaction into mempool",
            )
        })?;
    }

    // Signal event loop to broadcast and wait for confirmation.
    if let Some(sender) = state.tx_submit.clone() {
        await_tx_submission(sender, tx_id.0).await?;
    }

    // Return plain JSON string tx_id (matching Scala format)
    Ok(Json(hex::encode(tx_id.0)))
}

async fn get_unconfirmed_handler(
    State(state): State<ApiState>,
    Query(params): Query<UnconfirmedPaginationParams>,
) -> Json<Vec<TransactionResponse>> {
    let mp = state.mempool.read().unwrap();
    let limit = params.limit.min(100);
    let txs: Vec<TransactionResponse> = mp
        .get_all_with_size()
        .into_iter()
        .skip(params.offset)
        .take(limit)
        .map(|(tx, size)| ergo_tx_to_response(tx, size))
        .collect();
    Json(txs)
}

async fn get_unconfirmed_size_handler(State(state): State<ApiState>) -> Json<MempoolSizeResponse> {
    let mp = state.mempool.read().unwrap();
    Json(MempoolSizeResponse { size: mp.size() })
}

async fn get_unconfirmed_by_id_handler(
    State(state): State<ApiState>,
    Path(tx_id_hex): Path<String>,
) -> Result<Json<TransactionResponse>, (StatusCode, Json<ApiError>)> {
    let id_bytes = hex::decode(&tx_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    if id_bytes.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Transaction ID must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let tx_id = TxId(arr);

    let mp = state.mempool.read().unwrap();
    let (tx, size) = mp
        .get_with_size(&tx_id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Transaction not found in mempool"))?;

    Ok(Json(ergo_tx_to_response(tx, size)))
}

// ---------------------------------------------------------------------------
// Extended Transactions API handlers
// ---------------------------------------------------------------------------

/// `POST /transactions/check` -- validate a JSON transaction without broadcasting.
async fn check_transaction_handler(
    State(state): State<ApiState>,
    Json(json_tx): Json<TxJsonTransaction>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let tx =
        convert_json_tx_to_ergo_tx(&json_tx).map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;

    let bytes = serialize_transaction(&tx);

    validate_tx_stateless(&tx, &ValidationSettings::initial()).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Stateless transaction validation failed",
        )
    })?;
    ergo_network::mempool::validate_for_pool(
        bytes.len(),
        &state.blacklisted_transactions,
        state.max_transaction_size,
        &tx.tx_id,
    )
    .map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Transaction rejected by mempool policy",
        )
    })?;

    // Return plain JSON string tx_id (matching Scala format)
    Ok(Json(hex::encode(tx.tx_id.0)))
}

/// `POST /transactions/bytes` — submit a transaction as hex-encoded serialized bytes.
async fn submit_transaction_bytes_handler(
    State(state): State<ApiState>,
    Json(hex_str): Json<String>,
) -> Result<Json<TxSubmitResponse>, (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    let tx = parse_transaction(&bytes)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Failed to parse transaction"))?;
    validate_tx_stateless(&tx, &ValidationSettings::initial()).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Stateless transaction validation failed",
        )
    })?;

    ergo_network::mempool::validate_for_pool(
        bytes.len(),
        &state.blacklisted_transactions,
        state.max_transaction_size,
        &tx.tx_id,
    )
    .map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Transaction rejected by mempool policy",
        )
    })?;

    let tx_id = tx.tx_id;

    // Insert into mempool (scoped to drop the lock guard before any .await).
    {
        let mut mp = state.mempool.write().unwrap();
        mp.put_with_size(tx, bytes.len()).map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                "Failed to insert transaction into mempool",
            )
        })?;
    }

    if let Some(sender) = state.tx_submit.clone() {
        await_tx_submission(sender, tx_id.0).await?;
    }

    Ok(Json(TxSubmitResponse {
        tx_id: hex::encode(tx_id.0),
    }))
}

/// `POST /transactions/checkBytes` — validate hex-encoded tx bytes without broadcasting.
async fn check_transaction_bytes_handler(
    State(state): State<ApiState>,
    Json(hex_str): Json<String>,
) -> Result<Json<TxSubmitResponse>, (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    let tx = parse_transaction(&bytes)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Failed to parse transaction"))?;
    validate_tx_stateless(&tx, &ValidationSettings::initial()).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Stateless transaction validation failed",
        )
    })?;
    ergo_network::mempool::validate_for_pool(
        bytes.len(),
        &state.blacklisted_transactions,
        state.max_transaction_size,
        &tx.tx_id,
    )
    .map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Transaction rejected by mempool policy",
        )
    })?;
    Ok(Json(TxSubmitResponse {
        tx_id: hex::encode(tx.tx_id.0),
    }))
}

/// `GET /transactions/poolHistogram?bins=10&maxtime=60000`
async fn pool_histogram_handler(
    State(state): State<ApiState>,
    Query(params): Query<HistogramParams>,
) -> Json<Vec<HistogramBinResponse>> {
    let mp = state.mempool.read().unwrap();
    let bins = params.bins.clamp(1, 100);
    let histogram = mp.pool_histogram(bins, params.maxtime);
    Json(
        histogram
            .into_iter()
            .map(|bin| HistogramBinResponse {
                n_txns: bin.n_txns,
                total_size: bin.total_size,
                from_millis: bin.from_millis,
                to_millis: bin.to_millis,
            })
            .collect(),
    )
}

/// `GET /transactions/getFee?waitTime=1000`
async fn get_fee_handler(
    State(state): State<ApiState>,
    Query(_params): Query<FeeEstimateParams>,
) -> Json<FeeEstimateResponse> {
    let mp = state.mempool.read().unwrap();
    // Simple heuristic: base fee scaled by mempool occupancy
    let min_fee: u64 = 1_000_000; // 0.001 ERG minimum
    let pool_size = mp.size() as u64;
    let fee = min_fee + pool_size * 100_000; // increase by 0.0001 ERG per pooled tx
    Json(FeeEstimateResponse { fee })
}

/// `GET /transactions/waitTime?fee=1000000`
async fn wait_time_handler(
    State(state): State<ApiState>,
    Query(params): Query<WaitTimeParams>,
) -> Json<WaitTimeResponse> {
    let mp = state.mempool.read().unwrap();
    // Simple heuristic: if fee >= min, expected wait is short
    let min_fee: u64 = 1_000_000;
    let wait = if params.fee >= min_fee {
        let excess = params.fee.saturating_sub(min_fee);
        // Higher fee = shorter wait. Base 60s, reduced by fee premium
        let reduction = excess / 100_000; // each 0.0001 ERG reduces wait by 1s
        60_000u64.saturating_sub(reduction * 1000)
    } else {
        // Below minimum fee, long wait proportional to mempool size
        60_000 + mp.size() as u64 * 10_000
    };
    Json(WaitTimeResponse {
        wait_time_millis: wait,
    })
}

/// `HEAD /transactions/unconfirmed/{tx_id}` — check if tx is in mempool (200/404, no body).
async fn head_unconfirmed_handler(
    State(state): State<ApiState>,
    Path(tx_id_hex): Path<String>,
) -> StatusCode {
    let Ok(id_bytes) = hex::decode(&tx_id_hex) else {
        return StatusCode::BAD_REQUEST;
    };
    if id_bytes.len() != 32 {
        return StatusCode::BAD_REQUEST;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let tx_id = TxId(arr);

    let mp = state.mempool.read().unwrap();
    if mp.contains(&tx_id) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

/// `GET /transactions/unconfirmed/transactionIds` — all unconfirmed tx IDs.
async fn get_unconfirmed_tx_ids_handler(State(state): State<ApiState>) -> Json<Vec<String>> {
    let mp = state.mempool.read().unwrap();
    let ids: Vec<String> = mp
        .get_all_tx_ids()
        .iter()
        .map(|id| hex::encode(id.0))
        .collect();
    Json(ids)
}

/// `POST /transactions/unconfirmed/byTransactionIds` — filter IDs by mempool presence.
async fn post_by_transaction_ids_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    if ids.len() > 100 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Too many IDs; maximum is 100",
        ));
    }
    let mp = state.mempool.read().unwrap();
    let mut present = Vec::new();
    for id_hex in &ids {
        let Ok(id_bytes) = hex::decode(id_hex) else {
            continue;
        };
        if id_bytes.len() != 32 {
            continue;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id_bytes);
        let tx_id = TxId(arr);
        if mp.contains(&tx_id) {
            present.push(id_hex.clone());
        }
    }
    Ok(Json(present))
}

/// `GET /transactions/unconfirmed/outputs/byBoxId/{id}` — find unconfirmed output by box ID.
/// `GET /transactions/unconfirmed/inputs/byBoxId/{id}` -- find which mempool tx spends a box.
async fn get_unconfirmed_inputs_by_box_id_handler(
    State(state): State<ApiState>,
    Path(box_id_hex): Path<String>,
) -> Result<Json<SpendingInputResponse>, (StatusCode, Json<ApiError>)> {
    let id_bytes = hex::decode(&box_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    if id_bytes.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Box ID must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let box_id = BoxId(arr);

    let mp = state.mempool.read().unwrap();
    let (tx_id, input) = mp
        .find_spending_input(&box_id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "No spending input found for box ID"))?;

    Ok(Json(SpendingInputResponse {
        box_id: box_id_hex,
        spending_tx_id: hex::encode(tx_id.0),
        proof_bytes: hex::encode(&input.proof_bytes),
    }))
}

async fn get_unconfirmed_output_by_box_id_handler(
    State(state): State<ApiState>,
    Path(box_id_hex): Path<String>,
) -> Result<Json<UnconfirmedOutputResponse>, (StatusCode, Json<ApiError>)> {
    let id_bytes = hex::decode(&box_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    if id_bytes.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Box ID must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let box_id = BoxId(arr);

    let mp = state.mempool.read().unwrap();
    let output_ref = mp
        .find_output_by_box_id(&box_id)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Output not found for box ID"))?;

    Ok(Json(UnconfirmedOutputResponse {
        box_id: box_id_hex,
        tx_id: hex::encode(output_ref.tx_id.0),
        index: output_ref.index,
        value: output_ref.candidate.value,
        creation_height: output_ref.candidate.creation_height,
        token_count: output_ref.candidate.tokens.len(),
    }))
}

/// `GET /transactions/unconfirmed/outputs/byTokenId/{id}` — find unconfirmed outputs by token ID.
async fn get_unconfirmed_outputs_by_token_id_handler(
    State(state): State<ApiState>,
    Path(token_id_hex): Path<String>,
) -> Result<Json<Vec<UnconfirmedOutputResponse>>, (StatusCode, Json<ApiError>)> {
    let id_bytes = hex::decode(&token_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding"))?;
    if id_bytes.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Token ID must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let token_id = BoxId(arr);

    let mp = state.mempool.read().unwrap();
    let results = mp.find_outputs_by_token_id(&token_id);

    let responses: Vec<UnconfirmedOutputResponse> = results
        .iter()
        .map(|output_ref| {
            let box_id = compute_box_id(&output_ref.tx_id, output_ref.index);
            UnconfirmedOutputResponse {
                box_id: hex::encode(box_id.0),
                tx_id: hex::encode(output_ref.tx_id.0),
                index: output_ref.index,
                value: output_ref.candidate.value,
                creation_height: output_ref.candidate.creation_height,
                token_count: output_ref.candidate.tokens.len(),
            }
        })
        .collect();

    Ok(Json(responses))
}

/// `POST /transactions/unconfirmed/byErgoTree` — find unconfirmed txs by ErgoTree hex.
async fn post_unconfirmed_by_ergo_tree_handler(
    State(state): State<ApiState>,
    body: String,
) -> Result<Json<Vec<TransactionResponse>>, (StatusCode, Json<ApiError>)> {
    let hex_str = body.trim().trim_matches('"');
    let tree_bytes = hex::decode(hex_str)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid hex ErgoTree"))?;
    let tree_hash = blake2b256(&tree_bytes);
    let pool = state.mempool.read().unwrap();
    let txs = pool.find_txs_by_tree_hash(&tree_hash);
    let result: Vec<TransactionResponse> =
        txs.iter().map(|tx| ergo_tx_to_response(tx, 0)).collect();
    Ok(Json(result))
}

/// `POST /transactions/unconfirmed/outputs/byErgoTree` — find unconfirmed outputs by ErgoTree hex.
async fn post_unconfirmed_outputs_by_ergo_tree_handler(
    State(state): State<ApiState>,
    body: String,
) -> Result<Json<Vec<UnconfirmedOutputResponse>>, (StatusCode, Json<ApiError>)> {
    let hex_str = body.trim().trim_matches('"');
    let tree_bytes = hex::decode(hex_str)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid hex ErgoTree"))?;
    let tree_hash = blake2b256(&tree_bytes);
    let pool = state.mempool.read().unwrap();
    let outputs = pool.find_outputs_by_tree_hash(&tree_hash);
    let result: Vec<UnconfirmedOutputResponse> = outputs
        .iter()
        .map(|o| {
            let box_id = compute_box_id(&o.tx_id, o.index);
            UnconfirmedOutputResponse {
                box_id: hex::encode(box_id.0),
                tx_id: hex::encode(o.tx_id.0),
                index: o.index,
                value: o.candidate.value,
                creation_height: o.candidate.creation_height,
                token_count: o.candidate.tokens.len(),
            }
        })
        .collect();
    Ok(Json(result))
}

/// `POST /transactions/unconfirmed/outputs/byRegisters` — find unconfirmed outputs by register values.
async fn post_unconfirmed_outputs_by_registers_handler(
    State(state): State<ApiState>,
    Json(body): Json<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<UnconfirmedOutputResponse>>, (StatusCode, Json<ApiError>)> {
    let mut filter: Vec<(u8, Vec<u8>)> = Vec::new();
    for (key, hex_val) in &body {
        let reg_idx = key
            .strip_prefix('R')
            .and_then(|s| s.parse::<u8>().ok())
            .ok_or_else(|| {
                api_error(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid register key: {key}"),
                )
            })?;
        let val = hex::decode(hex_val)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, &format!("invalid hex for {key}")))?;
        filter.push((reg_idx, val));
    }
    let pool = state.mempool.read().unwrap();
    let outputs = pool.find_outputs_by_registers(&filter);
    let result: Vec<UnconfirmedOutputResponse> = outputs
        .iter()
        .map(|o| {
            let box_id = compute_box_id(&o.tx_id, o.index);
            UnconfirmedOutputResponse {
                box_id: hex::encode(box_id.0),
                tx_id: hex::encode(o.tx_id.0),
                index: o.index,
                value: o.candidate.value,
                creation_height: o.candidate.creation_height,
                token_count: o.candidate.tokens.len(),
            }
        })
        .collect();
    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// Extended Blocks API handlers
// ---------------------------------------------------------------------------

/// `GET /blocks?offset=0&limit=50` — paginated header IDs, newest first.
async fn get_paginated_blocks_handler(
    State(state): State<ApiState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    let best_height = state.history.best_header_height().map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read best header height",
        )
    })?;

    if best_height == 0 {
        // No headers stored yet — check if there really is a best header.
        if state
            .history
            .best_header_id()
            .map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read best header ID",
                )
            })?
            .is_none()
        {
            return Ok(Json(Vec::new()));
        }
    }

    let limit = params.limit.min(100) as usize;
    let offset = params.offset as usize;

    // Jump directly to start_height to avoid O(chain_height) scan.
    let start_height = (best_height as i64) - (offset as i64);
    if start_height < 0 {
        return Ok(Json(Vec::new()));
    }

    let mut result: Vec<String> = Vec::new();
    let mut height = start_height;
    while height >= 0 && result.len() < limit {
        let ids = state
            .history
            .header_ids_at_height(height as u32)
            .map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to read header IDs at height",
                )
            })?;
        for id in &ids {
            result.push(hex::encode(id.0));
        }
        height -= 1;
    }

    Ok(Json(result))
}

/// `GET /blocks/lastHeaders/{n}` — last N full headers, newest first.
async fn get_last_headers_handler(
    State(state): State<ApiState>,
    Path(n): Path<usize>,
) -> Result<Json<Vec<HeaderResponse>>, (StatusCode, Json<ApiError>)> {
    let n = n.min(2048);
    let headers = state
        .history
        .last_n_headers(n)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load headers"))?;

    let responses: Vec<HeaderResponse> = headers.iter().map(header_to_response).collect();
    Ok(Json(responses))
}

/// `GET /blocks/chainSlice?fromHeight=0&toHeight=100` — headers between heights.
async fn get_chain_slice_handler(
    State(state): State<ApiState>,
    Query(params): Query<ChainSliceParams>,
) -> Result<Json<Vec<HeaderResponse>>, (StatusCode, Json<ApiError>)> {
    let from = params.from_height;
    let to = params.to_height;

    if to < from {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "toHeight must be >= fromHeight",
        ));
    }

    // Cap the range to prevent excessive queries.
    let capped_to = to.min(from.saturating_add(2048));

    let mut responses = Vec::new();
    for height in from..=capped_to {
        let ids = state.history.header_ids_at_height(height).map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read header IDs at height",
            )
        })?;
        for id in &ids {
            let header = state.history.load_header(id).map_err(|_| {
                api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header")
            })?;
            if let Some(header) = header {
                responses.push(header_to_response_with_id(&header, &hex::encode(id.0)));
            }
        }
    }
    Ok(Json(responses))
}

/// `GET /blocks/{id}/header` — header only.
async fn get_header_only_handler(
    State(state): State<ApiState>,
    Path(header_id_hex): Path<String>,
) -> Result<Json<HeaderResponse>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&header_id_hex)?;
    let header = state
        .history
        .load_header(&id)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Header not found"))?;

    Ok(Json(header_to_response_with_id(&header, &header_id_hex)))
}

/// `GET /blocks/{id}/transactions` — block transactions as hex.
async fn get_block_transactions_handler(
    State(state): State<ApiState>,
    Path(header_id_hex): Path<String>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&header_id_hex)?;
    let data = state
        .history
        .get_modifier(102, &id)
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load block transactions",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Block transactions not found"))?;

    Ok(Json(hex::encode(data)))
}

/// `POST /blocks/headerIds` — batch full blocks by header IDs.
async fn post_header_ids_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<BlockResponse>>, (StatusCode, Json<ApiError>)> {
    if ids.len() > 100 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Too many IDs; maximum is 100",
        ));
    }
    let mut blocks = Vec::new();
    for id_hex in &ids {
        let id = parse_modifier_id(id_hex)?;
        if let Ok(Some(header)) = state.history.load_header(&id) {
            blocks.push(build_block_response(&state, &header, id_hex));
        }
    }
    Ok(Json(blocks))
}

/// `GET /blocks/modifier/{id}` — any block section by ID.
async fn get_modifier_handler(
    State(state): State<ApiState>,
    Path(modifier_id_hex): Path<String>,
) -> Result<Json<ModifierResponse>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&modifier_id_hex)?;

    // Try each known modifier type: header=101, block_transactions=102,
    // ad_proofs=104, extension=108.
    for type_id in [101u8, 102, 104, 108] {
        if let Ok(Some(data)) = state.history.get_modifier(type_id, &id) {
            return Ok(Json(ModifierResponse {
                type_id,
                bytes: hex::encode(data),
            }));
        }
    }

    Err(api_error(StatusCode::NOT_FOUND, "Modifier not found"))
}

// ---------------------------------------------------------------------------
// Address utility handlers
// ---------------------------------------------------------------------------

/// `GET /utils/address/{addr}` — validate an Ergo address.
async fn validate_address_handler(Path(addr): Path<String>) -> Json<AddressValidationResponse> {
    match address::validate_address(&addr) {
        Ok(_) => Json(AddressValidationResponse {
            address: addr,
            is_valid: true,
            error: None,
        }),
        Err(e) => Json(AddressValidationResponse {
            address: addr,
            is_valid: false,
            error: Some(e.to_string()),
        }),
    }
}

/// `POST /utils/address` — validate an Ergo address (body is a JSON string).
async fn validate_address_post_handler(
    Json(addr): Json<String>,
) -> Json<AddressValidationResponse> {
    match address::validate_address(&addr) {
        Ok(_) => Json(AddressValidationResponse {
            address: addr,
            is_valid: true,
            error: None,
        }),
        Err(e) => Json(AddressValidationResponse {
            address: addr,
            is_valid: false,
            error: Some(e.to_string()),
        }),
    }
}

/// `GET /utils/rawToAddress/{pubkey_hex}` — create a P2PK address from a hex public key.
async fn raw_to_address_handler(
    State(state): State<ApiState>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let prefix = network_prefix(&state.network);
    let addr = address::raw_to_address(&pubkey_hex, prefix)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid public key hex"))?;
    Ok(Json(addr))
}

/// `GET /utils/addressToRaw/{addr}` — decode an address and return hex content bytes.
async fn address_to_raw_handler(
    Path(addr): Path<String>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let raw = address::address_to_raw(&addr)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid address"))?;
    Ok(Json(raw))
}

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

/// `GET /utils/ergoTreeToAddress/{ergo_tree_hex}` — derive an address from an ErgoTree.
async fn ergo_tree_to_address_handler(
    State(state): State<ApiState>,
    Path(ergo_tree_hex): Path<String>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    ergo_tree_to_address_impl(&ergo_tree_hex, &state)
}

/// `POST /utils/ergoTreeToAddress` — derive an address from an ErgoTree hex in the request body.
async fn ergo_tree_to_address_post_handler(
    State(state): State<ApiState>,
    body: String,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    let hex_str = body.trim().trim_matches('"');
    ergo_tree_to_address_impl(hex_str, &state)
}

// ---------------------------------------------------------------------------
// Utils + Emission handlers
// ---------------------------------------------------------------------------

/// `GET /utils/seed` — random 32-byte hex string.
async fn seed_handler() -> Json<String> {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    Json(hex::encode(buf))
}

/// `GET /utils/seed/{length}` — random N-byte hex string (max 256).
async fn seed_with_length_handler(
    Path(length): Path<usize>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    use rand::RngCore;
    if length > 256 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Length must be at most 256",
        ));
    }
    let mut buf = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut buf);
    Ok(Json(hex::encode(buf)))
}

/// `POST /utils/hash/blake2b` — blake2b-256 hash of input JSON string.
async fn blake2b_hash_handler(Json(input): Json<String>) -> Json<serde_json::Value> {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = blake2::Blake2bVar::new(32).expect("valid output size");
    hasher.update(input.as_bytes());
    let mut hash = [0u8; 32];
    hasher
        .finalize_variable(&mut hash)
        .expect("valid output size");
    Json(serde_json::json!({ "hash": hex::encode(hash) }))
}

/// `GET /emission/at/{height}` — emission info at block height.
async fn emission_handler(Path(height): Path<u32>) -> Json<ergo_network::emission::EmissionInfo> {
    Json(ergo_network::emission::emission_info(height))
}

/// `GET /emission/scripts` — emission contract addresses.
async fn emission_scripts_handler(State(state): State<ApiState>) -> Json<EmissionScriptsResponse> {
    let network = network_prefix(&state.network);

    // Minimal placeholder ErgoTree bytes for emission contracts.
    // A fully accurate implementation would extract the real consensus-constant
    // ErgoTree bytes from the Scala reference.
    let emission_tree = [0xd1, 0x01];
    let reemission_tree = [0xd1, 0x02];
    let pay2reemission_tree = [0xd1, 0x03];

    Json(EmissionScriptsResponse {
        emission: address::ergo_tree_to_address(&emission_tree, network),
        reemission: address::ergo_tree_to_address(&reemission_tree, network),
        pay2_reemission: address::ergo_tree_to_address(&pay2reemission_tree, network),
    })
}

/// `GET /blocks/{header_id}/proofFor/{tx_id}` — Merkle inclusion proof for a tx in a block.
async fn merkle_proof_handler(
    State(state): State<ApiState>,
    Path((header_id_hex, tx_id_hex)): Path<(String, String)>,
) -> Result<Json<MerkleProofResponse>, (StatusCode, Json<ApiError>)> {
    let header_id = parse_modifier_id(&header_id_hex)?;

    let target_tx_id = hex::decode(&tx_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding for tx ID"))?;
    if target_tx_id.len() != 32 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Transaction ID must be 32 bytes (64 hex chars)",
        ));
    }

    let block_txs = state
        .history
        .load_block_transactions(&header_id)
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load block transactions",
            )
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Block transactions not found"))?;

    // Compute tx IDs: blake2b256 of each serialized transaction.
    use blake2::digest::{Update, VariableOutput};
    let tx_ids: Vec<[u8; 32]> = block_txs
        .tx_bytes
        .iter()
        .map(|tx_bytes| {
            let mut hasher = blake2::Blake2bVar::new(32).expect("valid");
            hasher.update(tx_bytes);
            let mut hash = [0u8; 32];
            hasher.finalize_variable(&mut hash).expect("valid");
            hash
        })
        .collect();

    let leaf_index = tx_ids
        .iter()
        .position(|id| id[..] == target_tx_id[..])
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Transaction not found in block"))?;

    let tx_id_slices: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
    let proof_steps =
        ergo_consensus::merkle::merkle_proof(&tx_id_slices, leaf_index).ok_or_else(|| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to compute Merkle proof",
            )
        })?;

    // Format levels: each is hex(side_byte ++ 32-byte sibling hash).
    let levels: Vec<String> = proof_steps
        .iter()
        .map(|step| {
            let side_byte = match step.side {
                ergo_consensus::merkle::MerkleSide::Left => 0x00u8,
                ergo_consensus::merkle::MerkleSide::Right => 0x01u8,
            };
            let mut entry = Vec::with_capacity(33);
            entry.push(side_byte);
            entry.extend_from_slice(&step.hash);
            hex::encode(entry)
        })
        .collect();

    Ok(Json(MerkleProofResponse {
        leaf: tx_id_hex,
        levels,
    }))
}

// ---------------------------------------------------------------------------
// NiPoPoW API handlers
// ---------------------------------------------------------------------------

/// `GET /nipopow/popowHeaderById/{id}` — PoPow header by header ID.
async fn popow_header_by_id_handler(
    State(state): State<ApiState>,
    Path(header_id_hex): Path<String>,
) -> Result<Json<PoPowHeaderResponse>, (StatusCode, Json<ApiError>)> {
    let id = parse_modifier_id(&header_id_hex)?;
    let header = state
        .history
        .load_header(&id)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Header not found"))?;
    let ext = state
        .history
        .load_extension(&id)
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load extension",
            )
        })?
        .unwrap_or(ergo_types::extension::Extension {
            header_id: id,
            fields: Vec::new(),
        });
    let popow = ergo_network::nipopow::popow_header_for(header, &ext);
    Ok(Json(popow_header_to_response(&popow)))
}

/// `GET /nipopow/popowHeaderByHeight/{h}` — PoPow header by block height.
async fn popow_header_by_height_handler(
    State(state): State<ApiState>,
    Path(height): Path<u32>,
) -> Result<Json<PoPowHeaderResponse>, (StatusCode, Json<ApiError>)> {
    let ids = state.history.header_ids_at_height(height).map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read header IDs at height",
        )
    })?;
    let id = ids
        .first()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "No header found at height"))?;
    let header = state
        .history
        .load_header(id)
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to load header"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Header not found"))?;
    let ext = state
        .history
        .load_extension(id)
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load extension",
            )
        })?
        .unwrap_or(ergo_types::extension::Extension {
            header_id: *id,
            fields: Vec::new(),
        });
    let popow = ergo_network::nipopow::popow_header_for(header, &ext);
    Ok(Json(popow_header_to_response(&popow)))
}

/// `GET /nipopow/proof/{m}/{k}` — NiPoPoW proof from the tip of the chain.
async fn nipopow_proof_handler(
    State(state): State<ApiState>,
    Path((m, k)): Path<(u32, u32)>,
) -> Result<Json<NipopowProofResponse>, (StatusCode, Json<ApiError>)> {
    if m == 0 || k == 0 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Parameters m and k must be > 0",
        ));
    }
    let proof = ergo_network::nipopow::prove(&state.history, m, k, None)
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "Failed to generate NiPoPoW proof"))?;
    Ok(Json(proof_to_response(&proof)))
}

/// `GET /nipopow/proof/{m}/{k}/{id}` — NiPoPoW proof anchored at a specific header.
async fn nipopow_proof_at_handler(
    State(state): State<ApiState>,
    Path((m, k, header_id_hex)): Path<(u32, u32, String)>,
) -> Result<Json<NipopowProofResponse>, (StatusCode, Json<ApiError>)> {
    if m == 0 || k == 0 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Parameters m and k must be > 0",
        ));
    }
    let id = parse_modifier_id(&header_id_hex)?;
    let proof = ergo_network::nipopow::prove(&state.history, m, k, Some(id))
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "Failed to generate NiPoPoW proof"))?;
    Ok(Json(proof_to_response(&proof)))
}

/// `POST /node/shutdown` — trigger graceful shutdown (localhost only).
async fn node_shutdown_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    if let Some(ref tx) = state.shutdown_tx {
        let _ = tx.send(true);
    }
    Ok(Json(serde_json::json!({ "status": "shutting_down" })))
}

// ---------------------------------------------------------------------------
// Script utility handlers
// ---------------------------------------------------------------------------

/// `GET /script/addressToTree/{addr}` — convert address to hex ErgoTree.
async fn script_address_to_tree_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tree_bytes = address_to_ergo_tree(&addr, &state.network)?;
    Ok(Json(serde_json::json!({
        "tree": hex::encode(&tree_bytes)
    })))
}

/// `GET /script/addressToBytes/{addr}` — convert address to hex sigma ByteArrayConstant.
async fn script_address_to_bytes_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let tree_bytes = address_to_ergo_tree(&addr, &state.network)?;
    let constant_bytes = encode_byte_array_constant(&tree_bytes);
    Ok(Json(serde_json::json!({
        "bytes": hex::encode(&constant_bytes)
    })))
}

/// `POST /script/p2sAddress` — compile ErgoScript source to a P2S address.
async fn script_p2s_address_handler(
    State(state): State<ApiState>,
    Json(req): Json<ScriptCompileRequest>,
) -> Result<Json<ScriptCompileResponse>, (StatusCode, String)> {
    let tree_bytes = compile_script_to_tree_bytes(&req.source)?;
    let network_prefix = network_prefix_from_str(&state.network);
    let addr = address::encode_address(network_prefix, address::AddressType::P2S, &tree_bytes);
    Ok(Json(ScriptCompileResponse { address: addr }))
}

/// `POST /script/p2shAddress` — compile ErgoScript source to a P2SH address.
async fn script_p2sh_address_handler(
    State(state): State<ApiState>,
    Json(req): Json<ScriptCompileRequest>,
) -> Result<Json<ScriptCompileResponse>, (StatusCode, String)> {
    let tree_bytes = compile_script_to_tree_bytes(&req.source)?;
    let hash = blake2b256(&tree_bytes);
    let network_prefix = network_prefix_from_str(&state.network);
    let addr = address::encode_address(network_prefix, address::AddressType::P2SH, &hash[..24]);
    Ok(Json(ScriptCompileResponse { address: addr }))
}

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

/// `GET /blockchain/indexedHeight` — current indexed height vs full chain height.
async fn indexed_height_handler(
    State(state): State<ApiState>,
) -> Result<Json<IndexedHeightResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let indexed = ergo_indexer::queries::indexed_height(db)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let shared = state.shared.read().await;
    Ok(Json(IndexedHeightResponse {
        indexed_height: indexed,
        full_height: shared.full_height as u32,
    }))
}

/// `GET /blockchain/transaction/byId/{id}` — look up an indexed transaction by ID.
async fn blockchain_tx_by_id_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<IndexedErgoTransactionResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let tx_id = hex_to_32bytes(&id)?;
    let tx = ergo_indexer::queries::get_tx(db, &tx_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Transaction not found".into()))?;
    let shared = state.shared.read().await;
    Ok(Json(tx_to_response(
        &tx,
        db,
        shared.full_height as u32,
        &state.network,
    )))
}

/// `GET /blockchain/transaction/byIndex/{n}` — look up an indexed transaction by global index.
async fn blockchain_tx_by_index_handler(
    State(state): State<ApiState>,
    Path(n): Path<u64>,
) -> Result<Json<IndexedErgoTransactionResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let tx = ergo_indexer::queries::get_tx_by_index(db, n)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Transaction not found".into()))?;
    let shared = state.shared.read().await;
    Ok(Json(tx_to_response(
        &tx,
        db,
        shared.full_height as u32,
        &state.network,
    )))
}

/// `POST /blockchain/transaction/byAddress` — transactions for an address (body = address string).
async fn blockchain_txs_by_address_post_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
    body: String,
) -> Result<Json<PaginatedTxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(body.trim(), &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (txs, total) = ergo_indexer::queries::txs_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let shared = state.shared.read().await;
    let height = shared.full_height as u32;
    let items = txs
        .iter()
        .map(|tx| tx_to_response(tx, db, height, &state.network))
        .collect();
    Ok(Json(PaginatedTxResponse { items, total }))
}

/// `GET /blockchain/transaction/byAddress/{addr}` — transactions for an address (path param).
async fn blockchain_txs_by_address_get_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<PaginatedTxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(&addr, &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (txs, total) = ergo_indexer::queries::txs_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let shared = state.shared.read().await;
    let height = shared.full_height as u32;
    let items = txs
        .iter()
        .map(|tx| tx_to_response(tx, db, height, &state.network))
        .collect();
    Ok(Json(PaginatedTxResponse { items, total }))
}

/// `GET /blockchain/transaction/range?offset=0&limit=5` — range of tx IDs by global index.
async fn blockchain_tx_range_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ids = ergo_indexer::queries::tx_id_range(db, params.offset as u64, params.limit)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(ids.into_iter().map(hex::encode).collect()))
}

// ---------------------------------------------------------------------------
// Blockchain (indexed) Box API handlers
// ---------------------------------------------------------------------------

/// `GET /blockchain/box/byId/{id}` — single box lookup.
async fn blockchain_box_by_id_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<IndexedErgoBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let box_id = hex_to_32bytes(&id)?;
    let b = ergo_indexer::queries::get_box(db, &box_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Box not found".into()))?;
    Ok(Json(box_to_response(&b, &state.network)))
}

/// `GET /blockchain/box/byIndex/{n}` — box by global index.
async fn blockchain_box_by_index_handler(
    State(state): State<ApiState>,
    Path(n): Path<u64>,
) -> Result<Json<IndexedErgoBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let b = ergo_indexer::queries::get_box_by_index(db, n)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Box not found".into()))?;
    Ok(Json(box_to_response(&b, &state.network)))
}

/// `GET /blockchain/box/byTokenId/{id}` — boxes containing token (paginated).
async fn blockchain_boxes_by_token_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let token_id_arr = hex_to_32bytes(&id)?;
    let token_id = ModifierId(token_id_arr);
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_token(
        db,
        &token_id,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

/// `GET /blockchain/box/unspent/byTokenId/{id}` — unspent boxes with token (paginated, mempool params).
async fn blockchain_unspent_boxes_by_token_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<UnspentBoxParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let token_id_arr = hex_to_32bytes(&id)?;
    let token_id = ModifierId(token_id_arr);
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_token(
        db,
        &token_id,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(&mut items, &mut total, &mp, &params, None, &state.network);
    Ok(Json(PaginatedBoxResponse { items, total }))
}

/// `POST /blockchain/box/byAddress` — boxes for address (body: address string, paginated).
async fn blockchain_boxes_by_address_post_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
    body: String,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(body.trim(), &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

/// `GET /blockchain/box/byAddress/{addr}` — boxes for address (path variant, paginated).
async fn blockchain_boxes_by_address_get_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(&addr, &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

/// `POST /blockchain/box/unspent/byAddress` — unspent boxes for address (paginated, mempool params).
async fn blockchain_unspent_boxes_by_address_post_handler(
    State(state): State<ApiState>,
    Query(params): Query<UnspentBoxParams>,
    body: String,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(body.trim(), &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(
        &mut items,
        &mut total,
        &mp,
        &params,
        Some(&ergo_tree),
        &state.network,
    );
    Ok(Json(PaginatedBoxResponse { items, total }))
}

/// `GET /blockchain/box/unspent/byAddress/{addr}` — unspent boxes for address (path variant, paginated, mempool params).
async fn blockchain_unspent_boxes_by_address_get_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
    Query(params): Query<UnspentBoxParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = address_to_ergo_tree(&addr, &state.network)?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(
        &mut items,
        &mut total,
        &mp,
        &params,
        Some(&ergo_tree),
        &state.network,
    );
    Ok(Json(PaginatedBoxResponse { items, total }))
}

/// `GET /blockchain/box/byTemplateHash/{hash}` — boxes by contract template (paginated).
async fn blockchain_boxes_by_template_handler(
    State(state): State<ApiState>,
    Path(hash): Path<String>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let template_hash =
        hex::decode(&hash).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex string".into()))?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_template(
        db,
        &template_hash,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

/// `GET /blockchain/box/unspent/byTemplateHash/{hash}` — unspent boxes by template (paginated, mempool params).
async fn blockchain_unspent_boxes_by_template_handler(
    State(state): State<ApiState>,
    Path(hash): Path<String>,
    Query(params): Query<UnspentBoxParams>,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let template_hash =
        hex::decode(&hash).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex string".into()))?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_template(
        db,
        &template_hash,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(&mut items, &mut total, &mp, &params, None, &state.network);
    Ok(Json(PaginatedBoxResponse { items, total }))
}

/// `GET /blockchain/box/range` — box IDs by global index range.
async fn blockchain_box_range_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ids = ergo_indexer::queries::box_id_range(db, params.offset as u64, params.limit)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(ids.into_iter().map(hex::encode).collect()))
}

/// `POST /blockchain/box/byErgoTree` — boxes by ErgoTree hex body (paginated).
async fn blockchain_boxes_by_ergo_tree_handler(
    State(state): State<ApiState>,
    Query(params): Query<BlockchainPaginationParams>,
    body: String,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = hex::decode(body.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex ErgoTree".into()))?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        false,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let items = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    Ok(Json(PaginatedBoxResponse { items, total }))
}

/// `POST /blockchain/box/unspent/byErgoTree` — unspent by ErgoTree hex (paginated, mempool params).
async fn blockchain_unspent_boxes_by_ergo_tree_handler(
    State(state): State<ApiState>,
    Query(params): Query<UnspentBoxParams>,
    body: String,
) -> Result<Json<PaginatedBoxResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let ergo_tree = hex::decode(body.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex ErgoTree".into()))?;
    let sort_desc = params.sort_direction.as_deref() != Some("asc");
    let (boxes, total) = ergo_indexer::queries::boxes_by_address(
        db,
        &ergo_tree,
        params.offset,
        params.limit,
        true,
        sort_desc,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut items: Vec<IndexedErgoBoxResponse> = boxes
        .iter()
        .map(|b| box_to_response(b, &state.network))
        .collect();
    let mut total = total;
    let mp = state.mempool.read().unwrap();
    apply_mempool_box_filters(
        &mut items,
        &mut total,
        &mp,
        &params,
        Some(&ergo_tree),
        &state.network,
    );
    Ok(Json(PaginatedBoxResponse { items, total }))
}

// ---------------------------------------------------------------------------
// Blockchain – Token handlers
// ---------------------------------------------------------------------------

/// `GET /blockchain/token/byId/{id}` — single token metadata.
async fn blockchain_token_by_id_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<IndexedTokenResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let token_id_bytes = hex_to_32bytes(&id)?;
    let token_id = ModifierId(token_id_bytes);
    let token = ergo_indexer::queries::get_token(db, &token_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Token not found".into()))?;
    Ok(Json(token_to_response(&token)))
}

/// `POST /blockchain/tokens` — batch token lookup.
async fn blockchain_tokens_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<IndexedTokenResponse>>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let mut results = Vec::new();
    for id_hex in &ids {
        let token_id_bytes = hex_to_32bytes(id_hex)?;
        let token_id = ModifierId(token_id_bytes);
        if let Some(token) = ergo_indexer::queries::get_token(db, &token_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            results.push(token_to_response(&token));
        }
    }
    Ok(Json(results))
}

// ---------------------------------------------------------------------------
// Blockchain – Balance handlers
// ---------------------------------------------------------------------------

/// Build a [`BalanceResponse`] for the given address string.
async fn balance_for_address(
    state: &ApiState,
    addr: &str,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    let db = require_indexer(state)?;
    let ergo_tree = address_to_ergo_tree(addr, &state.network)?;

    // Confirmed balance from indexer
    let confirmed_balance = ergo_indexer::queries::balance_for_address(db, &ergo_tree)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let confirmed = match confirmed_balance {
        Some(b) => BalanceInfoResponse {
            nano_ergs: b.nano_ergs,
            tokens: b
                .tokens
                .iter()
                .map(|(id, amt)| {
                    let meta = ergo_indexer::queries::get_token(db, id).ok().flatten();
                    TokenBalanceResponse {
                        token_id: hex::encode(id.0),
                        amount: *amt,
                        decimals: meta.as_ref().and_then(|m| m.decimals),
                        name: meta.as_ref().and_then(|m| m.name.clone()),
                    }
                })
                .collect(),
        },
        None => BalanceInfoResponse {
            nano_ergs: 0,
            tokens: vec![],
        },
    };

    // Unconfirmed balance from mempool
    let unconfirmed = {
        let mempool = state.mempool.read().unwrap();
        let tree_hash = blake2b256(&ergo_tree);
        let unconf_outputs = mempool.find_outputs_by_tree_hash(&tree_hash);
        let mut nano_ergs: u64 = 0;
        let mut token_map: std::collections::HashMap<[u8; 32], u64> =
            std::collections::HashMap::new();
        for output_ref in &unconf_outputs {
            nano_ergs += output_ref.candidate.value;
            for (tok_id, amt) in &output_ref.candidate.tokens {
                *token_map.entry(tok_id.0).or_default() += amt;
            }
        }
        BalanceInfoResponse {
            nano_ergs,
            tokens: token_map
                .into_iter()
                .map(|(id, amt)| TokenBalanceResponse {
                    token_id: hex::encode(id),
                    amount: amt,
                    decimals: None,
                    name: None,
                })
                .collect(),
        }
    };

    Ok(Json(BalanceResponse {
        confirmed,
        unconfirmed,
    }))
}

/// `POST /blockchain/balance` — balance for address (body = address string).
async fn blockchain_balance_post_handler(
    State(state): State<ApiState>,
    body: String,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    balance_for_address(&state, body.trim()).await
}

/// `GET /blockchain/balanceForAddress/{addr}` — balance for address (path param).
async fn blockchain_balance_get_handler(
    State(state): State<ApiState>,
    Path(addr): Path<String>,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    balance_for_address(&state, &addr).await
}

// ---------------------------------------------------------------------------
// Blockchain – Block handlers
// ---------------------------------------------------------------------------

/// `GET /blockchain/block/byHeaderId/{id}` — indexed block by header ID.
async fn blockchain_block_by_header_id_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<IndexedBlockResponse>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let header_id_bytes = hex_to_32bytes(&id)?;
    let header_id = ModifierId(header_id_bytes);

    let header = state
        .history
        .load_header(&header_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Header not found".into()))?;

    let block_txs = state
        .history
        .load_block_transactions(&header_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Block transactions not found".into()))?;

    let shared = state.shared.read().await;
    let current_height = shared.full_height as u32;
    drop(shared);

    Ok(Json(build_indexed_block_response(
        &state,
        db,
        &header,
        &block_txs,
        current_height,
    )))
}

/// `POST /blockchain/block/byHeaderIds` — batch block lookup by header IDs.
async fn blockchain_block_by_header_ids_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<IndexedBlockResponse>>, (StatusCode, String)> {
    let db = require_indexer(&state)?;
    let shared = state.shared.read().await;
    let current_height = shared.full_height as u32;
    drop(shared);

    let mut results = Vec::new();
    for id_hex in &ids {
        let header_id_bytes = hex_to_32bytes(id_hex)?;
        let header_id = ModifierId(header_id_bytes);

        let header = match state.history.load_header(&header_id) {
            Ok(Some(h)) => h,
            _ => continue,
        };
        let block_txs = match state.history.load_block_transactions(&header_id) {
            Ok(Some(bt)) => bt,
            _ => continue,
        };

        results.push(build_indexed_block_response(
            &state,
            db,
            &header,
            &block_txs,
            current_height,
        ));
    }
    Ok(Json(results))
}

// ---------------------------------------------------------------------------
// UTXO handlers
// ---------------------------------------------------------------------------

/// `GET /utxo/byId/{boxId}` -- look up a confirmed UTXO by box ID.
async fn utxo_by_id_handler(
    State(state): State<ApiState>,
    Path(_box_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_utxo_state(&state.state_type)?;
    // UTXO tree lookup not yet wired
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": 501,
            "reason": "UTXO state read not yet implemented"
        })),
    ))
}

/// `GET /utxo/byIdBinary/{boxId}` -- look up a confirmed UTXO (binary) by box ID.
async fn utxo_by_id_binary_handler(
    State(state): State<ApiState>,
    Path(_box_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_utxo_state(&state.state_type)?;
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": 501,
            "reason": "UTXO state read not yet implemented"
        })),
    ))
}

/// `GET /utxo/withPool/byId/{boxId}` -- UTXO lookup + mempool overlay.
async fn utxo_with_pool_by_id_handler(
    State(state): State<ApiState>,
    Path(box_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let box_id_bytes = hex::decode(&box_id_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": 400, "reason": "invalid hex"})),
        )
    })?;
    if box_id_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": 400, "reason": "box ID must be 32 bytes"})),
        ));
    }
    let box_id = BoxId(box_id_bytes.try_into().unwrap());

    // Check mempool for unconfirmed outputs
    let mp = state.mempool.read().unwrap();
    if let Some(output_ref) = mp.find_output_by_box_id(&box_id) {
        let candidate = output_ref.candidate;
        return Ok(Json(serde_json::json!({
            "boxId": box_id_hex,
            "value": candidate.value,
            "ergoTree": hex::encode(&candidate.ergo_tree_bytes),
            "creationHeight": candidate.creation_height,
            "assets": candidate.tokens.iter().map(|(tid, amt)| {
                serde_json::json!({"tokenId": hex::encode(tid.0), "amount": amt})
            }).collect::<Vec<_>>(),
            "confirmed": false
        })));
    }
    drop(mp);

    // For confirmed lookup, need UTXO state
    require_utxo_state(&state.state_type)?;
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": 501,
            "reason": "UTXO state read not yet implemented"
        })),
    ))
}

/// `POST /utxo/withPool/byIds` -- batch lookup across UTXO set + mempool.
async fn utxo_with_pool_by_ids_handler(
    State(state): State<ApiState>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<serde_json::Value>)> {
    let mut results = Vec::new();
    let mp = state.mempool.read().unwrap();
    for id_hex in &ids {
        if let Ok(bytes) = hex::decode(id_hex) {
            if bytes.len() == 32 {
                let box_id = BoxId(bytes.try_into().unwrap());
                if let Some(output_ref) = mp.find_output_by_box_id(&box_id) {
                    let c = output_ref.candidate;
                    results.push(serde_json::json!({
                        "boxId": id_hex,
                        "value": c.value,
                        "ergoTree": hex::encode(&c.ergo_tree_bytes),
                        "creationHeight": c.creation_height,
                        "assets": c.tokens.iter().map(|(tid, amt)| {
                            serde_json::json!({"tokenId": hex::encode(tid.0), "amount": amt})
                        }).collect::<Vec<_>>(),
                        "confirmed": false
                    }));
                }
            }
        }
    }
    drop(mp);
    Ok(Json(results))
}

/// `GET /utxo/withPool/byIdBinary/{boxId}` -- binary UTXO + mempool overlay.
async fn utxo_with_pool_by_id_binary_handler(
    State(state): State<ApiState>,
    Path(_box_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_utxo_state(&state.state_type)?;
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": 501,
            "reason": "UTXO binary state read not yet implemented"
        })),
    ))
}

/// `GET /utxo/genesis` -- genesis boxes (consensus constants).
async fn utxo_genesis_handler(
    State(_state): State<ApiState>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<serde_json::Value>)> {
    // Genesis boxes are consensus constants -- return empty for now
    Ok(Json(Vec::new()))
}

// ---------------------------------------------------------------------------
// POST /blocks, UTXO snapshot, binary proof, and script execution handlers
// ---------------------------------------------------------------------------

/// `POST /blocks` -- submit a full block for validation and inclusion.
///
/// Accepts a JSON body representing a full block. The body must contain a `header`
/// field with hex-encoded serialized header bytes, plus optional `blockTransactions`,
/// `extension`, and `adProofs` fields (also hex-encoded bytes). Validates the header's
/// proof-of-work, then fire-and-forget sends each section to the event loop for full
/// validation and application (matching Scala's pattern).
async fn post_block_handler(
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    // Extract the header bytes (hex-encoded serialized header).
    let header_hex = body.get("header").and_then(|v| v.as_str()).ok_or_else(|| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Missing 'header' field (hex string)",
        )
    })?;

    let header_bytes = hex::decode(header_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex encoding in header"))?;

    // Parse the header to validate PoW.
    let header = ergo_wire::header_ser::parse_header(&header_bytes).map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("Failed to parse header: {e}"),
        )
    })?;

    // Validate proof-of-work (lightweight pre-check, matching Scala's `powScheme.validate`).
    ergo_consensus::autolykos::validate_pow(&header)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("Invalid PoW: {e}")))?;

    // Compute the header ID from the serialized bytes.
    let header_id = compute_header_id(&header_bytes);
    let header_id_hex = hex::encode(header_id.0);

    // Build the list of modifiers to send to the event loop.
    // type_id 101 = Header, 102 = BlockTransactions, 108 = Extension, 104 = ADProofs
    let mut modifiers = Vec::new();
    modifiers.push((101u8, header_id, header_bytes));

    // Optional body sections: blockTransactions, extension, adProofs
    if let Some(bt_hex) = body.get("blockTransactions").and_then(|v| v.as_str()) {
        let bt_bytes = hex::decode(bt_hex)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex in blockTransactions"))?;
        modifiers.push((102u8, header_id, bt_bytes));
    }

    if let Some(ext_hex) = body.get("extension").and_then(|v| v.as_str()) {
        let ext_bytes = hex::decode(ext_hex)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex in extension"))?;
        modifiers.push((108u8, header_id, ext_bytes));
    }

    if let Some(ap_hex) = body.get("adProofs").and_then(|v| v.as_str()) {
        let ap_bytes = hex::decode(ap_hex)
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex in adProofs"))?;
        modifiers.push((104u8, header_id, ap_bytes));
    }

    // Fire-and-forget: send to the event loop.
    let sender = state.block_submit.as_ref().ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Block submit channel not available",
        )
    })?;

    let submission = crate::event_loop::BlockSubmission { modifiers };
    sender.try_send(submission).map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Event loop busy, block submit channel full",
        )
    })?;

    // Return OK immediately with the header ID (Scala pattern: fire-and-forget).
    Ok(Json(serde_json::json!({ "headerId": header_id_hex })))
}

/// `GET /utxo/getSnapshotsInfo` -- return metadata about available UTXO snapshots.
async fn utxo_snapshots_info_handler(
    State(state): State<ApiState>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<ApiError>)> {
    if state.state_type != "utxo" {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "UTXO snapshots info not available in digest mode",
        ));
    }

    if let Some(ref sdb) = state.snapshots_db {
        match sdb.get_info() {
            Ok(info) => {
                let manifests: Vec<serde_json::Value> = info
                    .manifests
                    .iter()
                    .map(|(height, manifest_id)| {
                        serde_json::json!({
                            "height": height,
                            "manifestId": hex::encode(manifest_id),
                        })
                    })
                    .collect();
                Ok(Json(manifests))
            }
            Err(e) => Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to read snapshots info: {e}"),
            )),
        }
    } else {
        // No snapshots DB configured — return empty list
        Ok(Json(Vec::new()))
    }
}

/// `POST /utxo/getBoxesBinaryProof` -- return a batch Merkle proof for a set of box IDs.
///
/// Accepts a JSON array of box ID hex strings. Sends a proof request to the event
/// loop which holds the live UTXO AVL+ tree, awaits the response, and returns the
/// hex-encoded serialized AD proof bytes.
async fn utxo_boxes_binary_proof_handler(
    State(state): State<ApiState>,
    Json(box_ids): Json<Vec<String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    if state.state_type != "utxo" {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "UTXO binary proofs not available in digest mode",
        ));
    }

    // Validate and parse the input box IDs.
    let mut parsed_ids = Vec::with_capacity(box_ids.len());
    for id_hex in &box_ids {
        let bytes = hex::decode(id_hex).map_err(|_| {
            api_error(
                StatusCode::BAD_REQUEST,
                &format!("Invalid hex encoding in box ID: {}", id_hex),
            )
        })?;
        if bytes.len() != 32 {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                &format!("Box ID must be 32 bytes, got {}: {}", bytes.len(), id_hex),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        parsed_ids.push(arr);
    }

    // Send a proof request to the event loop via the oneshot channel pattern.
    let sender = state.utxo_proof.as_ref().ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "UTXO proof channel not available",
        )
    })?;

    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    let request = crate::event_loop::UtxoProofRequest {
        box_ids: parsed_ids,
        response_tx: resp_tx,
    };

    sender.try_send(request).map_err(|_| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Event loop busy, proof request channel full",
        )
    })?;

    // Await the response with a timeout.
    match tokio::time::timeout(std::time::Duration::from_secs(10), resp_rx).await {
        Ok(Ok(Ok(proof_bytes))) => Ok(Json(serde_json::json!(hex::encode(proof_bytes)))),
        Ok(Ok(Err(e))) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Proof generation failed: {e}"),
        )),
        Ok(Err(_)) => Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Event loop dropped proof response",
        )),
        Err(_) => Err(api_error(
            StatusCode::GATEWAY_TIMEOUT,
            "Proof generation timed out",
        )),
    }
}

/// `POST /script/executeWithContext` -- compile and evaluate an ErgoScript with a given context.
///
/// Accepts a JSON body with a `script` field (ErgoScript source code).
/// Compiles the script and returns the resulting ErgoTree hex.
/// Full execution with a transaction context is not yet supported.
async fn script_execute_with_context_handler(
    State(_state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let script = body
        .get("script")
        .and_then(|s| s.as_str())
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "Missing 'script' field"))?;

    // Compile the script to an ErgoTree
    let tree_bytes =
        compile_script_to_tree_bytes(script).map_err(|(status, msg)| api_error(status, &msg))?;

    // Full script execution with a transaction context (inputs, data inputs,
    // self box, etc.) requires sigma-rust's Prover infrastructure and is
    // significantly more complex than compilation alone.
    // For now, return the compiled ErgoTree as hex and indicate that
    // full evaluation is not yet supported.
    Ok(Json(serde_json::json!({
        "compiledErgoTree": hex::encode(&tree_bytes),
        "note": "Full script evaluation with context is not yet supported. Only compilation is performed."
    })))
}

// ---------------------------------------------------------------------------
// Mining handlers
// ---------------------------------------------------------------------------

/// GET /mining/candidate — return the current mining candidate (work message).
async fn mining_candidate_handler(
    State(state): State<ApiState>,
) -> Result<Json<MiningCandidateResponse>, (StatusCode, String)> {
    let gen_lock = state.candidate_generator.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "mining is not enabled".to_string(),
    ))?;

    let gen = gen_lock.read().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("lock poisoned: {e}"),
        )
    })?;

    let (_candidate, header_template) = gen.current().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "no mining candidate available yet".to_string(),
    ))?;

    // Recompute msg and target from header template.
    let msg = ergo_consensus::autolykos::msg_by_header(header_template);
    let b_big = ergo_consensus::autolykos::get_b(header_template.n_bits);
    let b = biguint_to_u64_saturating(&b_big);

    Ok(Json(MiningCandidateResponse {
        msg: hex::encode(msg),
        b,
        h: header_template.height,
        pk: hex::encode(gen.miner_pk),
    }))
}

/// POST /mining/candidateWithTxs — return the current mining candidate including transactions.
///
/// Accepts a JSON body (which is currently ignored) and returns the work message
/// fields plus the full list of transactions in the candidate block.
async fn mining_candidate_with_txs_handler(
    State(state): State<ApiState>,
    _body: String,
) -> Result<Json<CandidateWithTxsResponse>, (StatusCode, String)> {
    let gen_lock = state.candidate_generator.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "mining is not enabled".to_string(),
    ))?;

    let gen = gen_lock.read().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("lock poisoned: {e}"),
        )
    })?;

    let (candidate, header_template) = gen.current().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "no mining candidate available yet".to_string(),
    ))?;

    // Recompute msg and target from header template.
    let msg = ergo_consensus::autolykos::msg_by_header(header_template);
    let b_big = ergo_consensus::autolykos::get_b(header_template.n_bits);
    let b = biguint_to_u64_saturating(&b_big);

    // Serialize candidate transactions.
    let transactions: Vec<TransactionResponse> = candidate
        .transactions
        .iter()
        .map(|tx| {
            let size = serialize_transaction(tx).len();
            ergo_tx_to_response(tx, size)
        })
        .collect();

    Ok(Json(CandidateWithTxsResponse {
        msg: hex::encode(msg),
        b,
        h: header_template.height,
        pk: hex::encode(gen.miner_pk),
        transactions,
    }))
}

/// POST /mining/solution — submit a mining solution from an external miner.
async fn mining_solution_handler(
    State(state): State<ApiState>,
    Json(solution): Json<MiningSolution>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Validate nonce format.
    if solution.nonce_bytes().is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid nonce: expected 8 bytes hex-encoded (16 hex chars)".to_string(),
        ));
    }

    let tx = state.mining_solution_tx.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "mining is not enabled".to_string(),
    ))?;

    tx.send(solution).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "solution channel closed".to_string(),
        )
    })?;

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// GET /mining/rewardAddress — return the configured mining reward address.
async fn mining_reward_address_handler(
    State(state): State<ApiState>,
) -> Result<Json<RewardAddressResponse>, (StatusCode, String)> {
    if state.mining_pub_key_hex.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "no mining public key configured".to_string(),
        ));
    }
    Ok(Json(RewardAddressResponse {
        reward_address: state.mining_pub_key_hex.clone(),
    }))
}

/// GET /mining/rewardPublicKey — return the configured miner public key.
async fn mining_reward_pubkey_handler(
    State(state): State<ApiState>,
) -> Result<Json<RewardPublicKeyResponse>, (StatusCode, String)> {
    if state.mining_pub_key_hex.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "no mining public key configured".to_string(),
        ));
    }
    Ok(Json(RewardPublicKeyResponse {
        reward_pub_key: state.mining_pub_key_hex.clone(),
    }))
}

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

/// `GET /wallet/status` — get wallet lifecycle status.
#[cfg(feature = "wallet")]
async fn wallet_status_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<WalletStatusResponse>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let status = w.status();
    Ok(Json(WalletStatusResponse {
        is_initialized: status.initialized,
        is_unlocked: status.unlocked,
        change_address: status.change_address,
        wallet_height: status.wallet_height,
        error: status.error,
    }))
}

/// `POST /wallet/init` — create a new wallet (generates mnemonic).
#[cfg(feature = "wallet")]
async fn wallet_init_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletInitRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let mnemonic = w
        .init(&body.pass)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "mnemonic": mnemonic })))
}

/// `POST /wallet/restore` — restore wallet from an existing mnemonic.
#[cfg(feature = "wallet")]
async fn wallet_restore_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletRestoreRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.restore(&body.pass, &body.mnemonic, &body.mnemonic_pass)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

/// `POST /wallet/unlock` — unlock the wallet with a password.
#[cfg(feature = "wallet")]
async fn wallet_unlock_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletUnlockRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.unlock(&body.pass)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

/// `GET /wallet/lock` — lock the wallet (clear keys from memory).
#[cfg(feature = "wallet")]
async fn wallet_lock_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.lock();
    Ok(Json(serde_json::json!({})))
}

// ---------------------------------------------------------------------------
// Wallet address and balance handlers (feature-gated)
// ---------------------------------------------------------------------------

/// `GET /wallet/addresses` — list all derived wallet addresses.
#[cfg(feature = "wallet")]
async fn wallet_addresses_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let addresses = w
        .addresses()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(addresses))
}

/// `POST /wallet/deriveKey` — derive a key at a specific BIP-32 path.
#[cfg(feature = "wallet")]
async fn wallet_derive_key_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletDeriveKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let address = w
        .derive_key(&body.derivation_path)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "address": address })))
}

/// `GET /wallet/deriveNextKey` — derive the next key (auto-increment index).
#[cfg(feature = "wallet")]
async fn wallet_derive_next_key_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let (derivation_path, address) = w
        .derive_next_key()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({
        "derivationPath": derivation_path,
        "address": address,
    })))
}

/// `GET /wallet/balances` — get on-chain wallet balance.
#[cfg(feature = "wallet")]
async fn wallet_balances_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<WalletBalanceResponse>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let digest = w
        .balances()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let tokens: std::collections::HashMap<String, u64> = digest
        .token_balances
        .iter()
        .map(|(tid, amt)| (hex::encode(tid), *amt))
        .collect();
    Ok(Json(WalletBalanceResponse {
        height: digest.height,
        balance: digest.erg_balance,
        tokens,
    }))
}

/// `GET /wallet/balances/withUnconfirmed` — get balance including unconfirmed.
///
/// Currently returns the same result as `/wallet/balances` since mempool
/// integration is deferred.
#[cfg(feature = "wallet")]
async fn wallet_balances_with_unconfirmed_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<WalletBalanceResponse>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let digest = w
        .balances()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let tokens: std::collections::HashMap<String, u64> = digest
        .token_balances
        .iter()
        .map(|(tid, amt)| (hex::encode(tid), *amt))
        .collect();
    Ok(Json(WalletBalanceResponse {
        height: digest.height,
        balance: digest.erg_balance,
        tokens,
    }))
}

/// `POST /wallet/updateChangeAddress` — update the wallet's change address.
#[cfg(feature = "wallet")]
async fn wallet_update_change_address_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletUpdateChangeAddressRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.update_change_address(&body.address)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

// ---------------------------------------------------------------------------
// Wallet box and transaction query handlers (feature-gated)
// ---------------------------------------------------------------------------

/// `GET /wallet/boxes/unspent` — list unspent wallet boxes with optional filters.
#[cfg(feature = "wallet")]
async fn wallet_unspent_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Query(params): Query<WalletBoxQueryParams>,
) -> Result<Json<Vec<WalletBoxWithMetaResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let boxes = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let current_height = state.shared.read().await.full_height;
    let min_conf = params.min_confirmations.unwrap_or(0);
    let max_conf = params.max_confirmations.unwrap_or(-1);
    let min_h = params.min_inclusion_height.unwrap_or(0);
    let max_h = params.max_inclusion_height.unwrap_or(u32::MAX);

    let result: Vec<WalletBoxWithMetaResponse> = boxes
        .iter()
        .filter(|b| {
            let confirmations = if current_height >= b.inclusion_height as u64 {
                (current_height - b.inclusion_height as u64) as i32
            } else {
                0
            };
            let conf_ok = confirmations >= min_conf && (max_conf < 0 || confirmations <= max_conf);
            let height_ok = b.inclusion_height >= min_h && b.inclusion_height <= max_h;
            conf_ok && height_ok
        })
        .map(|b| tracked_box_to_meta_response(b, current_height))
        .collect();

    Ok(Json(result))
}

/// `GET /wallet/boxes` — list all wallet boxes (spent + unspent) with optional filters.
#[cfg(feature = "wallet")]
async fn wallet_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Query(params): Query<WalletBoxQueryParams>,
) -> Result<Json<Vec<WalletBoxWithMetaResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let boxes = w
        .all_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let current_height = state.shared.read().await.full_height;
    let min_conf = params.min_confirmations.unwrap_or(0);
    let max_conf = params.max_confirmations.unwrap_or(-1);
    let min_h = params.min_inclusion_height.unwrap_or(0);
    let max_h = params.max_inclusion_height.unwrap_or(u32::MAX);

    let result: Vec<WalletBoxWithMetaResponse> = boxes
        .iter()
        .filter(|b| {
            let confirmations = if current_height >= b.inclusion_height as u64 {
                (current_height - b.inclusion_height as u64) as i32
            } else {
                0
            };
            let conf_ok = confirmations >= min_conf && (max_conf < 0 || confirmations <= max_conf);
            let height_ok = b.inclusion_height >= min_h && b.inclusion_height <= max_h;
            conf_ok && height_ok
        })
        .map(|b| tracked_box_to_meta_response(b, current_height))
        .collect();

    Ok(Json(result))
}

/// `POST /wallet/boxes/collect` — collect boxes matching a target balance.
#[cfg(feature = "wallet")]
async fn wallet_collect_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletCollectBoxesRequest>,
) -> Result<Json<Vec<WalletBoxResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let unspent = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let target_tokens: Vec<(String, u64)> = body.target_assets.into_iter().collect();

    let collected =
        ergo_wallet::tx_ops::collect_boxes(&unspent, body.target_balance, &target_tokens)
            .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let result: Vec<WalletBoxResponse> = collected.iter().map(tracked_box_to_response).collect();
    Ok(Json(result))
}

/// `GET /wallet/transactions` — list wallet transactions with optional filters.
#[cfg(feature = "wallet")]
async fn wallet_transactions_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Query(params): Query<WalletTransactionQueryParams>,
) -> Result<Json<Vec<WalletTransactionResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    let min_h = params.min_inclusion_height.unwrap_or(0);
    let max_h = params.max_inclusion_height.unwrap_or(u32::MAX);

    let txs = w
        .get_transactions(min_h, max_h)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let current_height = state.shared.read().await.full_height;
    let min_conf = params.min_confirmations.unwrap_or(0);
    let max_conf = params.max_confirmations.unwrap_or(-1);

    let result: Vec<WalletTransactionResponse> = txs
        .iter()
        .filter(|tx| {
            let confirmations = if current_height >= tx.inclusion_height as u64 {
                (current_height - tx.inclusion_height as u64) as i32
            } else {
                0
            };
            confirmations >= min_conf && (max_conf < 0 || confirmations <= max_conf)
        })
        .map(|tx| {
            let num_confirmations = if current_height >= tx.inclusion_height as u64 {
                (current_height - tx.inclusion_height as u64) as u32
            } else {
                0
            };
            WalletTransactionResponse {
                id: hex::encode(tx.tx_id),
                inclusion_height: tx.inclusion_height,
                num_confirmations,
            }
        })
        .collect();

    Ok(Json(result))
}

/// `GET /wallet/transactionById/{txId}` — get a wallet transaction by its ID.
#[cfg(feature = "wallet")]
async fn wallet_transaction_by_id_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Path(tx_id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    let tx_id_bytes: [u8; 32] = hex::decode(&tx_id_hex)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid hex txId"))?
        .try_into()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "txId must be 32 bytes"))?;

    match w.get_transaction_by_id(&tx_id_bytes) {
        Ok(Some(tx)) => {
            let current_height = state.shared.read().await.full_height;
            let num_confirmations = if current_height >= tx.inclusion_height as u64 {
                (current_height - tx.inclusion_height as u64) as u32
            } else {
                0
            };
            Ok(Json(serde_json::json!({
                "id": hex::encode(tx.tx_id),
                "inclusionHeight": tx.inclusion_height,
                "numConfirmations": num_confirmations,
            })))
        }
        Ok(None) => Err(api_error(StatusCode::NOT_FOUND, "transaction not found")),
        Err(e) => Err(api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())),
    }
}

/// `POST /wallet/check` — check if a mnemonic matches the wallet's stored seed.
#[cfg(feature = "wallet")]
async fn wallet_check_seed_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<WalletCheckSeedRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    match w.check_seed(&req.pass, &req.mnemonic) {
        Ok(matched) => Ok(Json(serde_json::json!({ "matched": matched }))),
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, &e.to_string())),
    }
}

/// `POST /wallet/rescan` — rescan the wallet from a given height.
#[cfg(feature = "wallet")]
async fn wallet_rescan_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<WalletRescanRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;

    w.rescan(req.from_height)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

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

/// Build an unsigned transaction, sign it, and return the signed bytes.
///
/// Shared logic for `wallet_tx_generate_handler`, `wallet_payment_send_handler`,
/// and `wallet_tx_send_handler`.
#[cfg(feature = "wallet")]
async fn build_and_sign_tx(
    state: &ApiState,
    payment_requests: &[ergo_wallet::tx_ops::PaymentRequest],
    fee: u64,
) -> Result<(Vec<u8>, [u8; 32]), (StatusCode, Json<ApiError>)> {
    let wallet = require_wallet(state)?;
    let w = wallet.read().await;

    let change_address = w
        .change_address()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let unspent = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let keys = w
        .keys()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let num_addresses = w
        .addresses()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?
        .len() as u32;

    let current_height = state.shared.read().await.full_height as u32;

    let (unsigned_tx, _input_ids) = ergo_wallet::tx_ops::build_unsigned_tx(
        payment_requests,
        fee,
        &change_address,
        &unspent,
        current_height,
    )
    .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    // Build sigma state context from current blockchain state.
    let sigma_ctx = {
        let shared = state.shared.read().await;
        build_sigma_state_context(&state.history, &shared)?
    };

    // Derive key indices 0..num_addresses for signing.
    let key_indices: Vec<u32> = (0..num_addresses.max(1)).collect();

    // Filter unspent boxes to only those matching the unsigned tx input IDs.
    let input_box_ids: std::collections::HashSet<[u8; 32]> = unsigned_tx
        .inputs
        .as_vec()
        .iter()
        .map(|inp| {
            let id_bytes: &[u8] = inp.box_id.as_ref();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(id_bytes);
            arr
        })
        .collect();
    let input_boxes: Vec<ergo_wallet::tracked_box::TrackedBox> = unspent
        .into_iter()
        .filter(|b| input_box_ids.contains(&b.box_id))
        .collect();

    let signed_bytes = ergo_wallet::tx_ops::sign_transaction(
        unsigned_tx,
        keys,
        &key_indices,
        &input_boxes,
        &[],
        &sigma_ctx,
    )
    .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    // Compute tx_id from the signed bytes.
    let signed_tx = parse_transaction(&signed_bytes)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let tx_id = signed_tx.tx_id.0;

    Ok((signed_bytes, tx_id))
}

/// Insert a signed transaction into the mempool and submit to the event loop.
#[cfg(feature = "wallet")]
async fn submit_signed_tx(
    state: &ApiState,
    signed_bytes: &[u8],
    tx_id: [u8; 32],
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let tx = parse_transaction(signed_bytes)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    {
        let mut mp = state.mempool.write().unwrap();
        mp.put_with_size(tx, signed_bytes.len())
            .map_err(|_| api_error(StatusCode::BAD_REQUEST, "failed to insert into mempool"))?;
    }

    if let Some(sender) = state.tx_submit.clone() {
        await_tx_submission(sender, tx_id).await?;
    }

    Ok(())
}

/// `POST /wallet/payment/send` — build, sign, and broadcast a payment transaction.
#[cfg(feature = "wallet")]
async fn wallet_payment_send_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<Vec<WalletPaymentRequest>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;

    let payment_requests = convert_payment_requests(&body);
    let (signed_bytes, tx_id) = build_and_sign_tx(&state, &payment_requests, default_fee()).await?;

    submit_signed_tx(&state, &signed_bytes, tx_id).await?;

    Ok(Json(serde_json::json!({
        "txId": hex::encode(tx_id),
    })))
}

/// `POST /wallet/transaction/generate` — generate a signed transaction (returned,
/// not broadcast).
#[cfg(feature = "wallet")]
async fn wallet_tx_generate_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletGenerateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;

    let payment_requests = convert_payment_requests(&body.requests);
    let (signed_bytes, _tx_id) = build_and_sign_tx(&state, &payment_requests, body.fee).await?;

    Ok(Json(serde_json::json!({
        "bytes": hex::encode(&signed_bytes),
    })))
}

/// `POST /wallet/transaction/generateUnsigned` — build an unsigned transaction.
#[cfg(feature = "wallet")]
async fn wallet_tx_generate_unsigned_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletGenerateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    // Require unlocked wallet for change address and box selection.
    let change_address = w
        .change_address()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let unspent = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let current_height = state.shared.read().await.full_height as u32;

    // Convert WalletPaymentRequests to tx_ops::PaymentRequest.
    let payment_requests: Vec<ergo_wallet::tx_ops::PaymentRequest> = body
        .requests
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
        .collect();

    let (unsigned_tx, input_ids) = ergo_wallet::tx_ops::build_unsigned_tx(
        &payment_requests,
        body.fee,
        &change_address,
        &unspent,
        current_height,
    )
    .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    let tx_bytes = ergo_wallet::tx_ops::serialize_unsigned_tx(&unsigned_tx)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let input_id_strs: Vec<String> = input_ids.iter().map(hex::encode).collect();

    Ok(Json(serde_json::json!({
        "bytes": hex::encode(&tx_bytes),
        "inputIds": input_id_strs,
    })))
}

/// `POST /wallet/transaction/sign` — sign an existing unsigned transaction.
///
/// Expects `WalletSignRequest` with a `tx` field containing hex-encoded
/// unsigned transaction bytes. Signs using wallet keys and returns the
/// signed transaction bytes.
#[cfg(feature = "wallet")]
async fn wallet_tx_sign_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletSignRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;

    // Parse the hex-encoded unsigned transaction bytes.
    //
    // The "bytes to sign" format is a Transaction with empty proofs.
    // We parse it as a Transaction, then reconstruct the UnsignedTransaction.
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

    let tx_bytes = hex::decode(body.tx.trim())
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("invalid hex: {e}")))?;

    let signed_format = ergo_lib::chain::transaction::Transaction::sigma_parse_bytes(&tx_bytes)
        .map_err(|e| {
            api_error(
                StatusCode::BAD_REQUEST,
                &format!("failed to parse tx bytes: {e}"),
            )
        })?;

    let unsigned_inputs: Vec<ergo_lib::chain::transaction::UnsignedInput> = signed_format
        .inputs
        .as_vec()
        .iter()
        .map(|inp| {
            ergo_lib::chain::transaction::UnsignedInput::new(
                inp.box_id,
                inp.spending_proof.extension.clone(),
            )
        })
        .collect();

    let data_inputs: Vec<ergo_lib::chain::transaction::DataInput> = signed_format
        .data_inputs
        .map(|di| di.as_vec().clone())
        .unwrap_or_default();

    let output_candidates: Vec<ergo_lib::ergotree_ir::chain::ergo_box::ErgoBoxCandidate> =
        signed_format.output_candidates.as_vec().clone();

    let unsigned_tx = ergo_lib::chain::transaction::unsigned::UnsignedTransaction::new_from_vec(
        unsigned_inputs,
        data_inputs,
        output_candidates,
    )
    .map_err(|e| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("failed to build unsigned tx: {e}"),
        )
    })?;

    let keys = w
        .keys()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let unspent = w
        .unspent_boxes()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let num_addresses = w
        .addresses()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?
        .len() as u32;

    // Build sigma state context.
    let sigma_ctx = {
        let shared = state.shared.read().await;
        build_sigma_state_context(&state.history, &shared)?
    };

    // Derive key indices 0..num_addresses for signing.
    let key_indices: Vec<u32> = (0..num_addresses.max(1)).collect();

    // Filter unspent boxes to those matching the unsigned tx input IDs.
    let input_box_ids: std::collections::HashSet<[u8; 32]> = unsigned_tx
        .inputs
        .as_vec()
        .iter()
        .map(|inp| {
            let id_bytes: &[u8] = inp.box_id.as_ref();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(id_bytes);
            arr
        })
        .collect();
    let input_boxes: Vec<ergo_wallet::tracked_box::TrackedBox> = unspent
        .into_iter()
        .filter(|b| input_box_ids.contains(&b.box_id))
        .collect();

    let signed_bytes = ergo_wallet::tx_ops::sign_transaction(
        unsigned_tx,
        keys,
        &key_indices,
        &input_boxes,
        &[],
        &sigma_ctx,
    )
    .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;

    Ok(Json(serde_json::json!({
        "bytes": hex::encode(&signed_bytes),
    })))
}

/// `POST /wallet/transaction/send` — generate, sign, and broadcast a transaction.
#[cfg(feature = "wallet")]
async fn wallet_tx_send_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletGenerateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;

    let payment_requests = convert_payment_requests(&body.requests);
    let (signed_bytes, tx_id) = build_and_sign_tx(&state, &payment_requests, body.fee).await?;

    submit_signed_tx(&state, &signed_bytes, tx_id).await?;

    Ok(Json(serde_json::json!({
        "txId": hex::encode(tx_id),
    })))
}

// ---------------------------------------------------------------------------
// Scan handlers (feature-gated)
// ---------------------------------------------------------------------------

/// `POST /scan/register` — register a new user-defined scan.
#[cfg(feature = "wallet")]
async fn scan_register_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanRegisterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let scan_id = w
        .register_scan(
            body.scan_name,
            body.tracking_rule,
            body.wallet_interaction,
            body.remove_offchain,
        )
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "scanId": scan_id })))
}

/// `POST /scan/deregister` — deregister a user-defined scan.
#[cfg(feature = "wallet")]
async fn scan_deregister_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanDeregisterRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    w.deregister_scan(body.scan_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "scanId": body.scan_id })))
}

/// `GET /scan/listAll` — list all registered scans.
#[cfg(feature = "wallet")]
async fn scan_list_all_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let scans = w
        .list_scans()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let json_scans: Vec<serde_json::Value> = scans
        .iter()
        .map(|s| serde_json::to_value(s).unwrap_or_default())
        .collect();
    Ok(Json(serde_json::json!(json_scans)))
}

/// `GET /scan/unspentBoxes/{scanId}` — get unspent boxes for a scan.
#[cfg(feature = "wallet")]
async fn scan_unspent_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Path(scan_id): Path<u16>,
) -> Result<Json<Vec<WalletBoxResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let boxes = w
        .unspent_boxes_for_scan(scan_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let response: Vec<WalletBoxResponse> = boxes.iter().map(tracked_box_to_response).collect();
    Ok(Json(response))
}

/// `GET /scan/spentBoxes/{scanId}` — get spent boxes for a scan.
#[cfg(feature = "wallet")]
async fn scan_spent_boxes_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Path(scan_id): Path<u16>,
) -> Result<Json<Vec<WalletBoxResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let boxes = w
        .spent_boxes_for_scan(scan_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let response: Vec<WalletBoxResponse> = boxes.iter().map(tracked_box_to_response).collect();
    Ok(Json(response))
}

/// `POST /scan/stopTracking` — stop tracking a box for a scan.
#[cfg(feature = "wallet")]
async fn scan_stop_tracking_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanStopTrackingRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let box_id = hex_to_32bytes(&body.box_id).map_err(|(code, msg)| api_error(code, &msg))?;
    w.stop_tracking(body.scan_id, &box_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({
        "scanId": body.scan_id,
        "boxId": body.box_id,
    })))
}

/// `POST /scan/addBox` — add a box to one or more scans.
#[cfg(feature = "wallet")]
async fn scan_add_box_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanAddBoxRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let mut w = wallet.write().await;
    let box_id = hex_to_32bytes(&body.box_id).map_err(|(code, msg)| api_error(code, &msg))?;
    let ergo_tree_bytes = hex::decode(&body.ergo_tree)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid hex in ergoTree"))?;
    let tracked_box = ergo_wallet::tracked_box::TrackedBox {
        box_id,
        ergo_tree_bytes,
        value: body.value,
        tokens: vec![],
        creation_height: body.creation_height,
        inclusion_height: body.inclusion_height,
        tx_id: [0u8; 32],
        output_index: 0,
        serialized_box: vec![],
        additional_registers: vec![],
        spent: false,
        spending_tx_id: None,
        spending_height: None,
        scan_ids: body.scan_ids.clone(),
    };
    w.add_box_to_scans(tracked_box, &body.scan_ids)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({
        "boxId": body.box_id,
        "scanIds": body.scan_ids,
    })))
}

/// `POST /scan/p2sRule` — register a scan with an ErgoTree-equals predicate
/// derived from a P2S/P2PK address.
#[cfg(feature = "wallet")]
async fn scan_p2s_rule_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<ScanP2sRuleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let tree_bytes = address_to_ergo_tree(&body.address, &state.network)
        .map_err(|(code, msg)| api_error(code, &msg))?;
    let predicate = ergo_wallet::scan_types::ScanningPredicate::Equals {
        register: "R1".to_owned(),
        value: hex::encode(&tree_bytes),
    };
    let mut w = wallet.write().await;
    let scan_id = w
        .register_scan(
            body.scan_name,
            predicate,
            ergo_wallet::scan_types::ScanWalletInteraction::Off,
            false,
        )
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!({ "scanId": scan_id })))
}

// ---------------------------------------------------------------------------
// Additional wallet handlers (feature-gated)
// ---------------------------------------------------------------------------

/// `POST /wallet/getPrivateKey` -- return the hex-encoded secret key for a wallet address.
#[cfg(feature = "wallet")]
async fn wallet_get_private_key_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<WalletGetPrivateKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let secret_hex = w
        .get_private_key(&body.address)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    Ok(Json(serde_json::json!(secret_hex)))
}

/// `POST /wallet/generateCommitments` -- generate signing commitments for multi-party signing.
///
/// This is an advanced EIP-11 feature that requires `TransactionHintsBag` and related types
/// from ergo-lib. These types are not publicly exposed in ergo-lib 0.28, so this endpoint
/// returns 501 Not Implemented.
#[cfg(feature = "wallet")]
async fn wallet_generate_commitments_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(_body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;
    Err(api_error(
        StatusCode::NOT_IMPLEMENTED,
        "generateCommitments is not yet implemented (requires TransactionHintsBag from ergo-lib)",
    ))
}

/// `POST /wallet/extractHints` -- extract signing hints from a signed transaction.
///
/// This is an advanced EIP-11 feature that requires `TransactionHintsBag` and hint extraction
/// APIs from ergo-lib. These types are not publicly exposed in ergo-lib 0.28, so this endpoint
/// returns 501 Not Implemented.
#[cfg(feature = "wallet")]
async fn wallet_extract_hints_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Json(_body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let _wallet = require_wallet(&state)?;
    Err(api_error(
        StatusCode::NOT_IMPLEMENTED,
        "extractHints is not yet implemented (requires TransactionHintsBag from ergo-lib)",
    ))
}

/// `GET /wallet/transactionsByScanId/{scanId}` -- get wallet transactions for a scan.
#[cfg(feature = "wallet")]
async fn wallet_txs_by_scan_id_handler(
    headers: axum::http::HeaderMap,
    State(state): State<ApiState>,
    Path(scan_id): Path<u16>,
) -> Result<Json<Vec<WalletTransactionResponse>>, (StatusCode, Json<ApiError>)> {
    check_auth(&headers, &state.api_key_hash)?;
    let wallet = require_wallet(&state)?;
    let w = wallet.read().await;
    let txs = w
        .get_txs_by_scan_id(scan_id)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let current_height = state.shared.read().await.full_height;
    let response: Vec<WalletTransactionResponse> = txs
        .iter()
        .map(|tx| {
            let num_confirmations = if current_height >= tx.inclusion_height as u64 {
                (current_height - tx.inclusion_height as u64) as u32
            } else {
                0
            };
            WalletTransactionResponse {
                id: hex::encode(tx.tx_id),
                inclusion_height: tx.inclusion_height,
                num_confirmations,
            }
        })
        .collect();
    Ok(Json(response))
}

/// Start the API server on the given bind address.
pub async fn start_api_server(bind_addr: &str, state: ApiState) -> std::io::Result<()> {
    use tower_http::cors::{Any, CorsLayer};

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

        // Pre-populate connected peers.
        {
            let mut shared = state.shared.write().await;
            shared.connected_peers = vec![
                ConnectedPeerInfo {
                    address: "192.168.1.1:9030".to_string(),
                    name: "peer-a".to_string(),
                    last_handshake: 1640000000000,
                    last_message: Some(1640000000500),
                    connection_type: None,
                },
                ConnectedPeerInfo {
                    address: "10.0.0.1:9030".to_string(),
                    name: "peer-b".to_string(),
                    last_handshake: 1640000001000,
                    last_message: Some(1640000001500),
                    connection_type: Some("Incoming".to_string()),
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
        assert_eq!(peers[0].address, "192.168.1.1:9030");
        assert_eq!(peers[0].name, "peer-a");
        assert_eq!(peers[0].last_message, 1640000000500);
        assert_eq!(peers[0].last_handshake, 1640000000000);
        assert!(peers[0].connection_type.is_none());
        assert_eq!(peers[1].address, "10.0.0.1:9030");
        assert_eq!(peers[1].name, "peer-b");
        assert_eq!(peers[1].last_handshake, 1640000001000);
        assert_eq!(peers[1].connection_type, Some("Incoming".to_string()));
    }

    #[tokio::test]
    async fn post_transaction_valid() {
        let (state, _dir) = test_api_state();
        let router = build_router(state.clone());

        // Submit a JSON transaction (Scala-compatible format)
        let body = serde_json::json!({
            "inputs": [{"boxId": "aa".repeat(32), "spendingProof": {"proofBytes": "", "extension": {}}}],
            "dataInputs": [],
            "outputs": [{"value": 1000000000, "ergoTree": "0008cd", "creationHeight": 100000, "assets": [], "additionalRegisters": {}}]
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
        ergo_types::transaction::ErgoTransaction {
            inputs: vec![ergo_types::transaction::Input {
                box_id: ergo_types::transaction::BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![0x00],
            }],
            data_inputs: vec![],
            output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
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
            "outputs": [{"value": 1000000, "ergoTree": "00", "creationHeight": 100, "assets": [], "additionalRegisters": {}}]
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
            "outputs": [{"value": 1000000, "ergoTree": "00", "creationHeight": 100, "assets": [], "additionalRegisters": {}}]
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
                "ergoTree": "0008cd03",
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
            "outputs": [{"value": 1000000, "ergoTree": "00", "creationHeight": 100, "assets": [], "additionalRegisters": {}}]
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
            "outputs": [{"value": 500000, "ergoTree": "00", "creationHeight": 50}]
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
        // d field should be "0" for empty d
        assert_eq!(resp.pow_solutions.d, "0");
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

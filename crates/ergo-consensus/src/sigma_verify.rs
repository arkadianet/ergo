//! Sigma-rust type conversion and ErgoScript verification wrapper.
//!
//! This module provides conversions between our internal node types
//! (ergo_types::transaction, ergo_types::header) and sigma-rust types
//! (ergo-lib, ergotree-ir, ergotree-interpreter), plus a verification
//! wrapper function for validating transaction scripts.

use std::collections::HashMap;
use std::convert::TryFrom;

use ergo_lib::chain::ergo_state_context::ErgoStateContext as SigmaErgoStateContext;
use ergo_lib::chain::parameters::Parameters as SigmaParameters;
use ergo_lib::chain::transaction::input::prover_result::ProverResult as SigmaProverResult;
use ergo_lib::chain::transaction::{DataInput as SigmaDataInput, Transaction as SigmaTransaction};
use ergo_lib::ergo_chain_types::{
    ADDigest as SigmaADDigest, BlockId as SigmaBlockId, Digest32 as SigmaDigest32,
    EcPoint as SigmaEcPoint, Header as SigmaHeader, PreHeader as SigmaPreHeader,
    Votes as SigmaVotes,
};
use ergo_lib::ergotree_interpreter::sigma_protocol::prover::ProofBytes as SigmaProofBytes;
use ergo_lib::ergotree_ir::chain::context_extension::ContextExtension as SigmaContextExtension;
use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue as SigmaBoxValue;
use ergo_lib::ergotree_ir::chain::ergo_box::RegisterValue as SigmaRegisterValue;
use ergo_lib::ergotree_ir::chain::ergo_box::{
    BoxId as SigmaBoxId, ErgoBox as SigmaErgoBox, ErgoBoxCandidate as SigmaErgoBoxCandidate,
    NonMandatoryRegisterId as SigmaNonMandatoryRegisterId,
    NonMandatoryRegisters as SigmaNonMandatoryRegisters,
};
use ergo_lib::ergotree_ir::chain::token::{Token as SigmaToken, TokenAmount, TokenId};
use ergo_lib::ergotree_ir::chain::tx_id::TxId as SigmaTxId;
use ergo_lib::ergotree_ir::ergo_tree::ErgoTree as SigmaErgoTree;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

use ergo_types::header::Header;
use ergo_types::transaction::{BoxId, ErgoBox, ErgoBoxCandidate, ErgoTransaction, Input, TxId};

use thiserror::Error;

// ── Error type ──────────────────────────────────────────────────────

/// Errors encountered during sigma verification.
#[derive(Error, Debug)]
pub enum SigmaVerifyError {
    /// Failed to parse an ErgoTree from raw bytes.
    #[error("ErgoTree parse error: {0}")]
    TreeParse(String),

    /// Failed to convert a box to sigma-rust ErgoBox.
    #[error("Box conversion error: {0}")]
    BoxConversion(String),

    /// Failed to convert a transaction to sigma-rust Transaction.
    #[error("Transaction conversion error: {0}")]
    TxConversion(String),

    /// Failed to convert context extension bytes.
    #[error("Context extension error: {0}")]
    ContextExtension(String),

    /// Failed to convert proof bytes.
    #[error("Proof bytes error: {0}")]
    Proof(String),

    /// Script verification returned false.
    #[error("Script reduced to false at input {0}")]
    ScriptFalse(usize),

    /// Script verification exceeded cost limit.
    #[error("Cost exceeded: total {0}")]
    CostExceeded(u64),

    /// Underlying verification error from sigma-rust.
    #[error("Verification error: {0}")]
    Verification(String),
}

// ── SigmaStateContext ───────────────────────────────────────────────

/// Contextual blockchain state needed for script evaluation.
pub struct SigmaStateContext {
    /// Recent block headers (up to 10, in descending order).
    pub last_headers: Vec<Header>,
    /// Height of the block being validated.
    pub current_height: u32,
    /// Timestamp of the block being validated (ms since epoch).
    pub current_timestamp: u64,
    /// Encoded difficulty of the current block.
    pub current_n_bits: u64,
    /// Current miner voting bytes.
    pub current_votes: [u8; 3],
    /// Compressed public key of the current block miner (33 bytes).
    pub current_miner_pk: [u8; 33],
    /// State digest after applying parent block (33 bytes).
    pub state_digest: [u8; 33],
    /// On-chain parameters for script cost evaluation.
    pub parameters: crate::parameters::Parameters,
    /// Block version of the block being validated.
    pub current_version: u8,
    /// Parent ID of the block being validated (32 bytes).
    pub current_parent_id: [u8; 32],
}

// ── Core conversions ────────────────────────────────────────────────

/// Convert our BoxId to sigma-rust BoxId.
pub fn convert_box_id(id: &BoxId) -> SigmaBoxId {
    SigmaDigest32::from(id.0).into()
}

/// Convert our TxId to sigma-rust TxId.
pub fn convert_tx_id(id: &TxId) -> SigmaTxId {
    SigmaTxId(SigmaDigest32::from(id.0))
}

/// Parse an ErgoTree from raw serialized bytes.
pub fn convert_ergo_tree(bytes: &[u8]) -> Result<SigmaErgoTree, SigmaVerifyError> {
    SigmaErgoTree::sigma_parse_bytes(bytes)
        .map_err(|e| SigmaVerifyError::TreeParse(format!("{e}")))
}

/// Convert our token list to sigma-rust tokens.
///
/// Our tokens are `Vec<(BoxId, u64)>` where BoxId is token_id and u64 is amount.
pub fn convert_tokens(tokens: &[(BoxId, u64)]) -> Result<Vec<SigmaToken>, SigmaVerifyError> {
    tokens
        .iter()
        .map(|(token_id, amount)| {
            let tid: TokenId = SigmaDigest32::from(token_id.0).into();
            let ta = TokenAmount::try_from(*amount)
                .map_err(|e| SigmaVerifyError::BoxConversion(format!("token amount: {e}")))?;
            Ok(SigmaToken {
                token_id: tid,
                amount: ta,
            })
        })
        .collect()
}

/// Convert our additional_registers `Vec<(u8, Vec<u8>)>` to sigma-rust NonMandatoryRegisters.
///
/// Registers must be densely packed starting from R4 (index 4).
pub fn convert_registers(
    regs: &[(u8, Vec<u8>)],
) -> Result<SigmaNonMandatoryRegisters, SigmaVerifyError> {
    if regs.is_empty() {
        return Ok(SigmaNonMandatoryRegisters::empty());
    }

    // Sort by register index and build a HashMap
    let mut sorted = regs.to_vec();
    sorted.sort_by_key(|(idx, _)| *idx);

    let mut map: HashMap<SigmaNonMandatoryRegisterId, SigmaRegisterValue> = HashMap::new();
    for (idx, bytes) in &sorted {
        let reg_id = match *idx {
            4 => SigmaNonMandatoryRegisterId::R4,
            5 => SigmaNonMandatoryRegisterId::R5,
            6 => SigmaNonMandatoryRegisterId::R6,
            7 => SigmaNonMandatoryRegisterId::R7,
            8 => SigmaNonMandatoryRegisterId::R8,
            9 => SigmaNonMandatoryRegisterId::R9,
            other => {
                return Err(SigmaVerifyError::BoxConversion(format!(
                    "invalid register index: {other}"
                )));
            }
        };
        let reg_value = SigmaRegisterValue::sigma_parse_bytes(bytes);
        map.insert(reg_id, reg_value);
    }

    SigmaNonMandatoryRegisters::try_from(map)
        .map_err(|e| SigmaVerifyError::BoxConversion(format!("registers: {e}")))
}

/// Convert our proof_bytes to sigma-rust ProofBytes.
pub fn convert_proof_bytes(bytes: &[u8]) -> SigmaProofBytes {
    SigmaProofBytes::from(bytes.to_vec())
}

/// Convert our extension_bytes to sigma-rust ContextExtension.
///
/// An empty slice yields an empty ContextExtension.
/// Non-empty bytes are deserialized via sigma parsing.
pub fn convert_context_extension(
    bytes: &[u8],
) -> Result<SigmaContextExtension, SigmaVerifyError> {
    if bytes.is_empty() {
        return Ok(SigmaContextExtension::empty());
    }
    SigmaContextExtension::sigma_parse_bytes(bytes)
        .map_err(|e| SigmaVerifyError::ContextExtension(format!("{e}")))
}

/// Convert our ErgoBoxCandidate to sigma-rust ErgoBoxCandidate.
pub fn convert_ergo_box_candidate(
    candidate: &ErgoBoxCandidate,
) -> Result<SigmaErgoBoxCandidate, SigmaVerifyError> {
    let value = SigmaBoxValue::try_from(candidate.value)
        .map_err(|e| SigmaVerifyError::BoxConversion(format!("box value: {e}")))?;
    let ergo_tree = convert_ergo_tree(&candidate.ergo_tree_bytes)?;
    let tokens_vec = convert_tokens(&candidate.tokens)?;
    let tokens = if tokens_vec.is_empty() {
        None
    } else {
        Some(
            ergo_lib::ergotree_ir::chain::ergo_box::BoxTokens::from_vec(tokens_vec)
                .map_err(|e| SigmaVerifyError::BoxConversion(format!("tokens: {e}")))?,
        )
    };
    let additional_registers = convert_registers(&candidate.additional_registers)?;

    Ok(SigmaErgoBoxCandidate {
        value,
        ergo_tree,
        tokens,
        additional_registers,
        creation_height: candidate.creation_height,
    })
}

/// Convert our ErgoBox to sigma-rust ErgoBox.
pub fn convert_ergo_box(our_box: &ErgoBox) -> Result<SigmaErgoBox, SigmaVerifyError> {
    let value = SigmaBoxValue::try_from(our_box.candidate.value)
        .map_err(|e| SigmaVerifyError::BoxConversion(format!("box value: {e}")))?;
    let ergo_tree = convert_ergo_tree(&our_box.candidate.ergo_tree_bytes)?;
    let tokens_vec = convert_tokens(&our_box.candidate.tokens)?;
    let tokens = if tokens_vec.is_empty() {
        None
    } else {
        Some(
            ergo_lib::ergotree_ir::chain::ergo_box::BoxTokens::from_vec(tokens_vec)
                .map_err(|e| SigmaVerifyError::BoxConversion(format!("tokens: {e}")))?,
        )
    };
    let additional_registers = convert_registers(&our_box.candidate.additional_registers)?;
    let transaction_id = convert_tx_id(&our_box.transaction_id);

    SigmaErgoBox::new(
        value,
        ergo_tree,
        tokens,
        additional_registers,
        our_box.candidate.creation_height,
        transaction_id,
        our_box.index,
    )
    .map_err(|e| SigmaVerifyError::BoxConversion(format!("ErgoBox::new: {e}")))
}

/// Convert a single Input to sigma-rust Input.
fn convert_input(
    input: &Input,
) -> Result<ergo_lib::chain::transaction::Input, SigmaVerifyError> {
    let box_id = convert_box_id(&input.box_id);
    let proof = convert_proof_bytes(&input.proof_bytes);
    let extension = convert_context_extension(&input.extension_bytes)?;
    let prover_result = SigmaProverResult { proof, extension };
    Ok(ergo_lib::chain::transaction::Input::new(
        box_id,
        prover_result,
    ))
}

/// Convert our ErgoTransaction to sigma-rust Transaction.
pub fn convert_transaction(
    tx: &ErgoTransaction,
) -> Result<SigmaTransaction, SigmaVerifyError> {
    let inputs: Vec<ergo_lib::chain::transaction::Input> = tx
        .inputs
        .iter()
        .map(convert_input)
        .collect::<Result<_, _>>()?;

    let data_inputs: Vec<SigmaDataInput> = tx
        .data_inputs
        .iter()
        .map(|di| SigmaDataInput::from(convert_box_id(&di.box_id)))
        .collect();

    let output_candidates: Vec<SigmaErgoBoxCandidate> = tx
        .output_candidates
        .iter()
        .map(convert_ergo_box_candidate)
        .collect::<Result<_, _>>()?;

    SigmaTransaction::new_from_vec(inputs, data_inputs, output_candidates)
        .map_err(|e| SigmaVerifyError::TxConversion(format!("{e}")))
}

// ── Header conversion ───────────────────────────────────────────────

/// Parse compressed EC point bytes (33 bytes) to sigma-rust EcPoint.
fn parse_ec_point(bytes: &[u8; 33]) -> Result<SigmaEcPoint, SigmaVerifyError> {
    use sigma_ser::ScorexSerializable;
    SigmaEcPoint::scorex_parse_bytes(bytes)
        .map_err(|e| SigmaVerifyError::Verification(format!("EC point parse: {e}")))
}

/// Convert our Header to sigma-rust Header.
pub fn convert_header(header: &Header) -> Result<SigmaHeader, SigmaVerifyError> {
    let miner_pk = parse_ec_point(&header.pow_solution.miner_pk)?;

    // For v2 (Autolykos v2), pow_onetime_pk and pow_distance are None
    let (pow_onetime_pk, pow_distance) = if header.version == 1 {
        let w = parse_ec_point(&header.pow_solution.w)?;
        let d = if header.pow_solution.d.is_empty() {
            None
        } else {
            Some(num_bigint::BigUint::from_bytes_be(
                &header.pow_solution.d,
            ))
        };
        (Some(Box::new(w)), d)
    } else {
        (None, None)
    };

    let autolykos_solution = ergo_lib::ergo_chain_types::AutolykosSolution {
        miner_pk: Box::new(miner_pk),
        pow_onetime_pk,
        nonce: header.pow_solution.nonce.to_vec(),
        pow_distance,
    };

    // Build the header with dummy id (it will be computed from serialization)
    let parent_id = SigmaBlockId(SigmaDigest32::from(header.parent_id.0));
    let ad_proofs_root = SigmaDigest32::from(header.ad_proofs_root.0);
    let transaction_root = SigmaDigest32::from(header.transactions_root.0);
    let state_root = SigmaADDigest::from(header.state_root.0);
    let extension_root = SigmaDigest32::from(header.extension_root.0);
    let votes = SigmaVotes(header.votes);

    // Compute the id by serializing and hashing
    let mut sigma_header = SigmaHeader {
        version: header.version,
        id: SigmaBlockId(SigmaDigest32::zero()),
        parent_id,
        ad_proofs_root,
        state_root,
        transaction_root,
        timestamp: header.timestamp,
        n_bits: header.n_bits as u32,
        height: header.height,
        extension_root,
        autolykos_solution,
        votes,
        unparsed_bytes: Box::new([]),
    };

    // Compute header id from serialization (like sigma-rust does)
    let mut id_bytes = sigma_header
        .serialize_without_pow()
        .map_err(|e| SigmaVerifyError::Verification(format!("header serialize: {e}")))?;
    let mut pow_bytes = Vec::new();
    sigma_header
        .autolykos_solution
        .serialize_bytes(header.version, &mut pow_bytes)
        .map_err(|e| SigmaVerifyError::Verification(format!("pow serialize: {e}")))?;
    id_bytes.extend(pow_bytes);
    let id = SigmaBlockId(ergo_lib::ergo_chain_types::blake2b256_hash(&id_bytes));
    sigma_header.id = id;

    Ok(sigma_header)
}

/// Convert our on-chain Parameters to sigma-rust Parameters.
///
/// Our parameter IDs map 1:1 to sigma-rust's `Parameter` enum discriminants.
/// Missing parameters use the same defaults as sigma-rust.
pub fn convert_parameters(params: &crate::parameters::Parameters) -> SigmaParameters {
    use crate::parameters::*;
    SigmaParameters::new(
        params.get(BLOCK_VERSION_ID).unwrap_or(1),
        params.get(STORAGE_FEE_FACTOR_ID).unwrap_or(1_250_000),
        params.get(MIN_VALUE_PER_BYTE_ID).unwrap_or(360),
        params.get(MAX_BLOCK_SIZE_ID).unwrap_or(524_288),
        params.get(MAX_BLOCK_COST_ID).unwrap_or(1_000_000),
        params.get(TOKEN_ACCESS_COST_ID).unwrap_or(100),
        params.get(INPUT_COST_ID).unwrap_or(2_000),
        params.get(DATA_INPUT_COST_ID).unwrap_or(100),
        params.get(OUTPUT_COST_ID).unwrap_or(100),
    )
}

/// Convert our SigmaStateContext to sigma-rust ErgoStateContext.
pub fn convert_state_context(
    ctx: &SigmaStateContext,
) -> Result<SigmaErgoStateContext, SigmaVerifyError> {
    // Build PreHeader from current block info
    let miner_pk = parse_ec_point(&ctx.current_miner_pk)?;

    let pre_header = SigmaPreHeader {
        version: ctx.current_version,
        parent_id: SigmaBlockId(SigmaDigest32::from(ctx.current_parent_id)),
        timestamp: ctx.current_timestamp,
        n_bits: ctx.current_n_bits as u32,
        height: ctx.current_height,
        miner_pk: Box::new(miner_pk),
        votes: SigmaVotes(ctx.current_votes),
    };

    // Convert last headers (need exactly 10, pad with defaults if fewer)
    let mut sigma_headers = Vec::with_capacity(10);
    for h in ctx.last_headers.iter().take(10) {
        sigma_headers.push(convert_header(h)?);
    }
    // Pad to 10 with dummy headers if needed
    while sigma_headers.len() < 10 {
        sigma_headers.push(make_dummy_sigma_header());
    }

    let headers: [SigmaHeader; 10] = sigma_headers
        .try_into()
        .map_err(|_| SigmaVerifyError::Verification("header array conversion".to_string()))?;

    let sigma_params = convert_parameters(&ctx.parameters);

    Ok(SigmaErgoStateContext::new(
        pre_header,
        headers,
        sigma_params,
    ))
}

/// Create a minimal dummy sigma-rust Header for padding.
fn make_dummy_sigma_header() -> SigmaHeader {
    SigmaHeader {
        version: 2,
        id: SigmaBlockId(SigmaDigest32::zero()),
        parent_id: SigmaBlockId(SigmaDigest32::zero()),
        ad_proofs_root: SigmaDigest32::zero(),
        state_root: SigmaADDigest::zero(),
        transaction_root: SigmaDigest32::zero(),
        timestamp: 0,
        n_bits: 0,
        height: 0,
        extension_root: SigmaDigest32::zero(),
        autolykos_solution: ergo_lib::ergo_chain_types::AutolykosSolution {
            miner_pk: Box::new(SigmaEcPoint::default()),
            pow_onetime_pk: None,
            nonce: vec![0u8; 8],
            pow_distance: None,
        },
        votes: SigmaVotes([0; 3]),
        unparsed_bytes: Box::new([]),
    }
}

// ── Storage rent ────────────────────────────────────────────────────
//
// Storage rent is fully handled by sigma-rust's `verify_tx_input_proof`
// (ergo-lib 0.28, `chain::transaction::storage_rent`). When our
// `verify_transaction` calls `tx_context.validate()`, each input is
// checked via `try_spend_storage_rent` before normal script verification.
//
// The storage rent logic:
//   1. If proof_bytes is empty AND the box is expired (age >= STORAGE_PERIOD),
//      the storage rent spending path is tried.
//   2. Context extension key 127 (STORAGE_INDEX_VAR_ID, Short type) holds the
//      output index of the replacement box.
//   3. If box.value <= storageFee (= storage_fee_factor * box_serialized_size),
//      the box can be fully consumed.
//   4. Otherwise, the output box must have: creation_height == currentHeight,
//      value >= box.value - storageFee, and all registers except R0 (value)
//      and R3 (creation info) preserved.
//   5. If storage rent conditions are not satisfied, normal script verification
//      is applied as a fallback.

/// Storage period in blocks (~4 years). Boxes older than this can be spent
/// via the storage rent mechanism. Handled by sigma-rust's ErgoInterpreter
/// automatically within `verify_tx_input_proof`.
pub const STORAGE_PERIOD: u32 = 1_051_200;

/// Context extension variable ID used by the storage rent mechanism.
/// The value at this key is a Short indicating the output index of the
/// replacement box. Equal to `i8::MAX` (127).
pub const STORAGE_INDEX_VAR_ID: u8 = 127;

/// Default storage fee factor (nanoERGs per byte of box serialized size).
/// Equal to 1,250,000 nanoERGs/byte (1.25 ERG/kilobyte).
/// This value may be changed by on-chain governance via the parameters system.
pub const DEFAULT_STORAGE_FEE_FACTOR: u64 = 1_250_000;

// ── Initial transaction cost ────────────────────────────────────────

/// Interpreter initialization cost (fixed per transaction).
pub const INTERPRETER_INIT_COST: u64 = 10_000;

/// Compute the initial computational cost of a transaction before script execution.
///
/// Formula: interpreter_init + inputs*inputCost + dataInputs*dataInputCost + outputs*outputCost
pub fn compute_initial_tx_cost(
    tx: &ErgoTransaction,
    parameters: &crate::parameters::Parameters,
) -> u64 {
    let input_cost = parameters.get(crate::parameters::INPUT_COST_ID)
        .unwrap_or(2000) as u64;
    let data_input_cost = parameters.get(crate::parameters::DATA_INPUT_COST_ID)
        .unwrap_or(100) as u64;
    let output_cost = parameters.get(crate::parameters::OUTPUT_COST_ID)
        .unwrap_or(100) as u64;

    INTERPRETER_INIT_COST
        + tx.inputs.len() as u64 * input_cost
        + tx.data_inputs.len() as u64 * data_input_cost
        + tx.output_candidates.len() as u64 * output_cost
}

/// Compute the token access cost for a transaction.
///
/// Matches Scala `ErgoBoxAssetExtractor.totalAssetsAccessCost`:
/// `(outAssetsNum + inAssetsNum) * tokenAccessCost + (inAssetsSize + outAssetsSize) * tokenAccessCost`
///
/// - `Num` = total token entries across all boxes (counting duplicates per box)
/// - `Size` = number of unique token IDs across all boxes
pub fn compute_token_access_cost(
    input_boxes: &[ErgoBox],
    output_candidates: &[ErgoBoxCandidate],
    parameters: &crate::parameters::Parameters,
) -> Result<u64, String> {
    let token_access_cost = parameters
        .get(crate::parameters::TOKEN_ACCESS_COST_ID)
        .unwrap_or(100) as u64;

    // Count total token entries (Num) and unique token IDs (Size) for inputs.
    let mut in_assets_num: u64 = 0;
    let mut in_unique = std::collections::HashSet::new();
    for b in input_boxes {
        in_assets_num = in_assets_num
            .checked_add(b.candidate.tokens.len() as u64)
            .ok_or_else(|| "input token count overflow".to_string())?;
        for (token_id, _) in &b.candidate.tokens {
            in_unique.insert(*token_id);
        }
    }
    let in_assets_size = in_unique.len() as u64;

    // Count total token entries (Num) and unique token IDs (Size) for outputs.
    let mut out_assets_num: u64 = 0;
    let mut out_unique = std::collections::HashSet::new();
    for c in output_candidates {
        out_assets_num = out_assets_num
            .checked_add(c.tokens.len() as u64)
            .ok_or_else(|| "output token count overflow".to_string())?;
        for (token_id, _) in &c.tokens {
            out_unique.insert(*token_id);
        }
    }
    let out_assets_size = out_unique.len() as u64;

    // totalAssetsAccessCost = (outNum + inNum) * cost + (inSize + outSize) * cost
    let total_num = out_assets_num
        .checked_add(in_assets_num)
        .ok_or_else(|| "assets num overflow".to_string())?;
    let total_size = in_assets_size
        .checked_add(out_assets_size)
        .ok_or_else(|| "assets size overflow".to_string())?;
    let num_cost = total_num
        .checked_mul(token_access_cost)
        .ok_or_else(|| "num * cost overflow".to_string())?;
    let size_cost = total_size
        .checked_mul(token_access_cost)
        .ok_or_else(|| "size * cost overflow".to_string())?;
    num_cost
        .checked_add(size_cost)
        .ok_or_else(|| "total token cost overflow".to_string())
}

// ── Verification ────────────────────────────────────────────────────

/// Verify all inputs of a transaction using sigma-rust script evaluation.
///
/// Storage rent is handled automatically: for each input, sigma-rust first
/// checks whether the box is expired and can be spent via storage rent
/// (see [`STORAGE_PERIOD`]). If the storage rent path does not apply, normal
/// ErgoScript verification is performed.
///
/// # Arguments
///
/// * `tx` - The signed transaction to verify.
/// * `input_boxes` - The boxes being spent (must match tx.inputs in order).
/// * `data_boxes` - Data input boxes referenced by the transaction.
/// * `state_context` - Blockchain state context for script evaluation.
/// * `checkpoint_height` - Skip verification for blocks at or below this height.
///
/// # Returns
///
/// * `Ok(0)` if below checkpoint height (verification skipped).
/// * `Ok(jit_cost)` — the real JIT execution cost from sigma-rust.
/// * `Err(SigmaVerifyError)` on any failure.
pub fn verify_transaction(
    tx: &ErgoTransaction,
    input_boxes: &[ErgoBox],
    data_boxes: &[ErgoBox],
    state_context: &SigmaStateContext,
    checkpoint_height: u32,
) -> Result<u64, SigmaVerifyError> {
    // Skip verification for historical blocks below checkpoint
    if state_context.current_height <= checkpoint_height {
        return Ok(0);
    }

    // Convert to sigma-rust types
    let sigma_tx = convert_transaction(tx)?;

    let sigma_input_boxes: Vec<SigmaErgoBox> = input_boxes
        .iter()
        .map(convert_ergo_box)
        .collect::<Result<_, _>>()?;

    let sigma_data_boxes: Vec<SigmaErgoBox> = data_boxes
        .iter()
        .map(convert_ergo_box)
        .collect::<Result<_, _>>()?;

    let sigma_state_ctx = convert_state_context(state_context)?;

    // Build TransactionContext and validate
    let tx_context = ergo_lib::wallet::tx_context::TransactionContext::new(
        sigma_tx,
        sigma_input_boxes,
        sigma_data_boxes,
    )
    .map_err(|e| SigmaVerifyError::Verification(format!("TransactionContext: {e}")))?;

    let cost = tx_context
        .validate(&sigma_state_ctx)
        .map_err(|e| match e {
            ergo_lib::chain::transaction::ergo_transaction::TxValidationError::ReducedToFalse(
                idx,
                _,
            ) => SigmaVerifyError::ScriptFalse(idx),
            other => SigmaVerifyError::Verification(format!("{other}")),
        })?;

    Ok(cost)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::transaction::{BoxId, DataInput, ErgoBoxCandidate, Input, TxId};

    /// Helper: create a minimal ErgoBox for testing.
    fn make_test_box(value: u64, tree_bytes: Vec<u8>, tx_id: TxId, index: u16) -> ErgoBox {
        let candidate = ErgoBoxCandidate {
            value,
            ergo_tree_bytes: tree_bytes,
            creation_height: 0,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };
        let box_id = ergo_types::transaction::compute_box_id(&tx_id, index);
        ErgoBox {
            candidate,
            transaction_id: tx_id,
            index,
            box_id,
        }
    }

    /// A valid P2PK ErgoTree for the generator point.
    /// This is `0008cd` + 33-byte compressed generator point of secp256k1.
    fn p2pk_tree_bytes() -> Vec<u8> {
        let gen_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let gen_bytes = base16::decode(gen_hex).unwrap();
        let mut bytes = vec![0x00, 0x08, 0xcd];
        bytes.extend_from_slice(&gen_bytes);
        bytes
    }

    #[test]
    fn test_convert_box_id_roundtrip() {
        let our_id = BoxId([0xab; 32]);
        let sigma_id = convert_box_id(&our_id);
        // The underlying bytes should be the same
        let sigma_bytes: &[u8] = sigma_id.as_ref();
        assert_eq!(sigma_bytes, &[0xab; 32]);
    }

    #[test]
    fn test_convert_tx_id_roundtrip() {
        let our_id = TxId([0xcd; 32]);
        let sigma_id = convert_tx_id(&our_id);
        let sigma_bytes: &[u8] = sigma_id.as_ref();
        assert_eq!(sigma_bytes, &[0xcd; 32]);
    }

    #[test]
    fn test_convert_empty_context_extension() {
        let ext = convert_context_extension(&[]).unwrap();
        assert_eq!(ext, SigmaContextExtension::empty());
    }

    #[test]
    fn test_convert_empty_proof() {
        let proof = convert_proof_bytes(&[]);
        assert_eq!(proof, SigmaProofBytes::Empty);
    }

    #[test]
    fn test_convert_nonempty_proof() {
        let bytes = vec![0x01, 0x02, 0x03];
        let proof = convert_proof_bytes(&bytes);
        match proof {
            SigmaProofBytes::Some(b) => assert_eq!(b, vec![0x01, 0x02, 0x03]),
            SigmaProofBytes::Empty => panic!("expected non-empty proof"),
        }
    }

    #[test]
    fn test_verify_skips_below_checkpoint() {
        let tx = ErgoTransaction {
            inputs: vec![],
            data_inputs: vec![],
            output_candidates: vec![],
            tx_id: TxId([0x00; 32]),
        };
        let ctx = SigmaStateContext {
            last_headers: vec![],
            current_height: 100,
            current_timestamp: 0,
            current_n_bits: 0,
            current_votes: [0; 3],
            current_miner_pk: [0; 33],
            state_digest: [0; 33],
            parameters: crate::parameters::Parameters::genesis(),
            current_version: 2,
            current_parent_id: [0; 32],
        };
        // checkpoint = 100, current_height = 100, so should skip
        let result = verify_transaction(&tx, &[], &[], &ctx, 100);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        // checkpoint = 200, current_height = 100, so should skip
        let result = verify_transaction(&tx, &[], &[], &ctx, 200);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_convert_ergo_tree() {
        let tree_bytes = p2pk_tree_bytes();
        let result = convert_ergo_tree(&tree_bytes);
        assert!(
            result.is_ok(),
            "Failed to parse P2PK ErgoTree: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_convert_ergo_tree_invalid() {
        // In the jit-costing branch, sigma_parse_bytes returns an error
        // for clearly invalid bytes instead of storing them in an Unparsed variant.
        let result = convert_ergo_tree(&[0xFF, 0xFF]);
        assert!(result.is_err(), "invalid ErgoTree bytes should produce a parse error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("ErgoTree parse error"),
            "error should be a TreeParse variant: {err_msg}"
        );
    }

    #[test]
    fn test_convert_ergo_box() {
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xAA; 32]);
        let our_box = make_test_box(1_000_000_000, tree_bytes, tx_id, 0);
        let result = convert_ergo_box(&our_box);
        assert!(
            result.is_ok(),
            "Failed to convert ErgoBox: {:?}",
            result.err()
        );
        let sigma_box = result.unwrap();
        assert_eq!(*sigma_box.value.as_u64(), 1_000_000_000);
        assert_eq!(sigma_box.creation_height, 0);
        assert_eq!(sigma_box.index, 0);
    }

    #[test]
    fn test_convert_ergo_box_with_tokens() {
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xBB; 32]);
        let token_id = BoxId([0x11; 32]);
        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: tree_bytes,
            creation_height: 500,
            tokens: vec![(token_id, 100)],
            additional_registers: vec![],
        };
        let box_id = ergo_types::transaction::compute_box_id(&tx_id, 0);
        let our_box = ErgoBox {
            candidate,
            transaction_id: tx_id,
            index: 0,
            box_id,
        };
        let result = convert_ergo_box(&our_box);
        assert!(result.is_ok());
        let sigma_box = result.unwrap();
        assert!(sigma_box.tokens.is_some());
        let tokens = sigma_box.tokens.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(*tokens.first().amount.as_u64(), 100);
    }

    #[test]
    fn test_convert_ergo_box_with_registers() {
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xCC; 32]);
        // R4 = SInt constant 42: type byte 0x04 (SInt), value zigzag(42) = 84 = 0x54
        let r4_bytes = vec![0x04, 0x54];
        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: tree_bytes,
            creation_height: 0,
            tokens: vec![],
            additional_registers: vec![(4, r4_bytes)],
        };
        let box_id = ergo_types::transaction::compute_box_id(&tx_id, 0);
        let our_box = ErgoBox {
            candidate,
            transaction_id: tx_id,
            index: 0,
            box_id,
        };
        let result = convert_ergo_box(&our_box);
        assert!(result.is_ok());
        let sigma_box = result.unwrap();
        assert!(!sigma_box.additional_registers.is_empty());
    }

    #[test]
    fn test_convert_transaction() {
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xDD; 32]);
        let input_box_id = BoxId([0xEE; 32]);

        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: input_box_id,
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: tree_bytes,
                creation_height: 0,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id,
        };

        let result = convert_transaction(&tx);
        assert!(
            result.is_ok(),
            "Failed to convert transaction: {:?}",
            result.err()
        );
        let sigma_tx = result.unwrap();
        assert_eq!(sigma_tx.inputs.len(), 1);
        assert_eq!(sigma_tx.outputs.len(), 1);
    }

    #[test]
    fn test_convert_transaction_with_data_inputs() {
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xDD; 32]);

        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xEE; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![DataInput {
                box_id: BoxId([0xFF; 32]),
            }],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: tree_bytes,
                creation_height: 0,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id,
        };

        let result = convert_transaction(&tx);
        assert!(result.is_ok());
        let sigma_tx = result.unwrap();
        assert!(sigma_tx.data_inputs.is_some());
        assert_eq!(sigma_tx.data_inputs.unwrap().len(), 1);
    }

    #[test]
    fn test_convert_empty_registers() {
        let result = convert_registers(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_convert_tokens_empty() {
        let result = convert_tokens(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_convert_tokens_single() {
        let tokens = vec![(BoxId([0x11; 32]), 42u64)];
        let result = convert_tokens(&tokens);
        assert!(result.is_ok());
        let sigma_tokens = result.unwrap();
        assert_eq!(sigma_tokens.len(), 1);
        assert_eq!(*sigma_tokens[0].amount.as_u64(), 42);
    }

    #[test]
    fn test_make_dummy_sigma_header() {
        let h = make_dummy_sigma_header();
        assert_eq!(h.height, 0);
        assert_eq!(h.version, 2);
    }

    // ── New comprehensive tests ─────────────────────────────────────

    #[test]
    fn test_sigma_verify_error_display() {
        // Verify that all error variants format correctly via Display
        let tree_err = SigmaVerifyError::TreeParse("bad tree".to_string());
        assert_eq!(tree_err.to_string(), "ErgoTree parse error: bad tree");

        let box_err = SigmaVerifyError::BoxConversion("bad box".to_string());
        assert_eq!(box_err.to_string(), "Box conversion error: bad box");

        let tx_err = SigmaVerifyError::TxConversion("bad tx".to_string());
        assert_eq!(tx_err.to_string(), "Transaction conversion error: bad tx");

        let ctx_err = SigmaVerifyError::ContextExtension("bad ext".to_string());
        assert_eq!(ctx_err.to_string(), "Context extension error: bad ext");

        let proof_err = SigmaVerifyError::Proof("bad proof".to_string());
        assert_eq!(proof_err.to_string(), "Proof bytes error: bad proof");

        let script_false = SigmaVerifyError::ScriptFalse(3);
        assert_eq!(script_false.to_string(), "Script reduced to false at input 3");

        let cost_err = SigmaVerifyError::CostExceeded(99999);
        assert_eq!(cost_err.to_string(), "Cost exceeded: total 99999");

        let verify_err = SigmaVerifyError::Verification("sigma fail".to_string());
        assert_eq!(verify_err.to_string(), "Verification error: sigma fail");
    }

    #[test]
    fn test_convert_ergo_tree_p2pk_known_good() {
        // Test with a well-known valid P2PK ErgoTree using the secp256k1 generator point.
        // The tree should parse successfully and its proposition should be extractable.
        let tree_bytes = p2pk_tree_bytes();
        let tree = convert_ergo_tree(&tree_bytes).expect("valid P2PK tree should parse");
        // A valid P2PK tree should have an extractable proposition
        let prop = tree.proposition();
        assert!(
            prop.is_ok(),
            "valid P2PK tree proposition should be extractable: {:?}",
            prop.err()
        );
    }

    #[test]
    fn test_convert_ergo_box_minimum_value() {
        // sigma-rust BoxValue accepts values >= 1 nanoERG.
        // Our MIN_BOX_VALUE is 10_800. Test that sigma-rust accepts it.
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xA1; 32]);
        let our_box = make_test_box(10_800, tree_bytes, tx_id, 0);
        let result = convert_ergo_box(&our_box);
        assert!(
            result.is_ok(),
            "MIN_BOX_VALUE (10800) should be accepted: {:?}",
            result.err()
        );
        let sigma_box = result.unwrap();
        assert_eq!(*sigma_box.value.as_u64(), 10_800);
    }

    #[test]
    fn test_convert_ergo_box_zero_value_rejected() {
        // BoxValue(0) is invalid in sigma-rust, it should error.
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xA2; 32]);
        let our_box = make_test_box(0, tree_bytes, tx_id, 0);
        let result = convert_ergo_box(&our_box);
        assert!(result.is_err(), "zero value box should be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("box value"),
            "error should mention box value: {err_msg}"
        );
    }

    #[test]
    fn test_convert_ergo_box_max_tokens() {
        // Test a box with multiple tokens (up to the max of 255 tokens).
        // sigma-rust BoxTokens max is 255.
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xA3; 32]);

        // Create 4 distinct tokens
        let mut tokens = Vec::new();
        for i in 0u8..4 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = i;
            id_bytes[31] = i.wrapping_add(1);
            tokens.push((BoxId(id_bytes), (i as u64 + 1) * 1000));
        }

        let candidate = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: tree_bytes,
            creation_height: 100,
            tokens,
            additional_registers: vec![],
        };
        let box_id = ergo_types::transaction::compute_box_id(&tx_id, 0);
        let our_box = ErgoBox {
            candidate,
            transaction_id: tx_id,
            index: 0,
            box_id,
        };
        let result = convert_ergo_box(&our_box);
        assert!(
            result.is_ok(),
            "box with 4 tokens should convert: {:?}",
            result.err()
        );
        let sigma_box = result.unwrap();
        let sigma_tokens = sigma_box.tokens.expect("should have tokens");
        assert_eq!(sigma_tokens.len(), 4);
        // Verify amounts are correct
        assert_eq!(*sigma_tokens.get(0).unwrap().amount.as_u64(), 1000);
        assert_eq!(*sigma_tokens.get(1).unwrap().amount.as_u64(), 2000);
        assert_eq!(*sigma_tokens.get(2).unwrap().amount.as_u64(), 3000);
        assert_eq!(*sigma_tokens.get(3).unwrap().amount.as_u64(), 4000);
    }

    #[test]
    fn test_convert_transaction_empty_data_inputs() {
        // Transaction with explicitly empty data_inputs should produce None in sigma-rust.
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xA4; 32]);

        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xB4; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![], // explicitly empty
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: tree_bytes,
                creation_height: 0,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id,
        };

        let result = convert_transaction(&tx);
        assert!(result.is_ok(), "tx with no data inputs should convert");
        let sigma_tx = result.unwrap();
        // sigma-rust represents empty data inputs as None
        assert!(
            sigma_tx.data_inputs.is_none(),
            "empty data inputs should be None in sigma-rust"
        );
    }

    #[test]
    fn test_sigma_state_context_default_values() {
        // Verify that a SigmaStateContext can be created with default/zero values
        // and that convert_state_context succeeds (padding with dummy headers).
        let ctx = SigmaStateContext {
            last_headers: vec![],
            current_height: 1,
            current_timestamp: 1000,
            current_n_bits: 100,
            current_votes: [0; 3],
            // Use the identity point (point at infinity) as miner pk:
            // 33-byte compressed format, 0x00 prefix = identity
            current_miner_pk: {
                // sigma-rust EcPoint::default() is the identity; we need a valid
                // compressed point for scorex_parse_bytes. Use generator point instead.
                let gen_hex =
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
                let gen_bytes = base16::decode(gen_hex).unwrap();
                let mut arr = [0u8; 33];
                arr.copy_from_slice(&gen_bytes);
                arr
            },
            state_digest: [0; 33],
            parameters: crate::parameters::Parameters::genesis(),
            current_version: 2,
            current_parent_id: [0; 32],
        };
        let result = convert_state_context(&ctx);
        assert!(
            result.is_ok(),
            "default state context should convert: {:?}",
            result.err()
        );
        let sigma_ctx = result.unwrap();
        // The pre_header height should match
        assert_eq!(sigma_ctx.pre_header.height, 1);
    }

    #[test]
    fn test_verify_at_checkpoint_boundary() {
        // Edge case: height == checkpoint should return Ok(0) (verification skipped).
        let tx = ErgoTransaction {
            inputs: vec![],
            data_inputs: vec![],
            output_candidates: vec![],
            tx_id: TxId([0xA5; 32]),
        };
        let ctx = SigmaStateContext {
            last_headers: vec![],
            current_height: 500_000,
            current_timestamp: 0,
            current_n_bits: 0,
            current_votes: [0; 3],
            current_miner_pk: [0; 33],
            state_digest: [0; 33],
            parameters: crate::parameters::Parameters::genesis(),
            current_version: 2,
            current_parent_id: [0; 32],
        };
        // Checkpoint exactly equals current height
        let result = verify_transaction(&tx, &[], &[], &ctx, 500_000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0, "at checkpoint boundary should skip");
    }

    #[test]
    fn test_verify_above_checkpoint_no_inputs() {
        // When height > checkpoint, verification proceeds. With no inputs, the
        // transaction conversion should fail (sigma-rust requires >= 1 input).
        let tx = ErgoTransaction {
            inputs: vec![], // no inputs
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: p2pk_tree_bytes(),
                creation_height: 0,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId([0xA6; 32]),
        };
        let ctx = SigmaStateContext {
            last_headers: vec![],
            current_height: 1000,
            current_timestamp: 0,
            current_n_bits: 0,
            current_votes: [0; 3],
            current_miner_pk: [0; 33],
            state_digest: [0; 33],
            parameters: crate::parameters::Parameters::genesis(),
            current_version: 2,
            current_parent_id: [0; 32],
        };
        // Checkpoint is below current height, so verification runs
        let result = verify_transaction(&tx, &[], &[], &ctx, 999);
        assert!(
            result.is_err(),
            "tx with no inputs above checkpoint should fail"
        );
    }

    #[test]
    fn test_convert_registers_invalid_index() {
        // Register index outside the valid range 4..=9 should error
        let regs = vec![(10, vec![0x04, 0x54])]; // R10 doesn't exist
        let result = convert_registers(&regs);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid register index: 10"),
            "error should mention invalid register index: {err_msg}"
        );
    }

    #[test]
    fn test_convert_registers_all_valid_indices() {
        // Registers R4 through R9 should all be accepted
        // Use SInt constants with different values
        let regs: Vec<(u8, Vec<u8>)> = (4..=9)
            .map(|idx| {
                // SInt constant: type 0x04, value zigzag(idx) = idx*2
                (idx, vec![0x04, idx * 2])
            })
            .collect();
        let result = convert_registers(&regs);
        assert!(
            result.is_ok(),
            "all valid register indices should work: {:?}",
            result.err()
        );
        let sigma_regs = result.unwrap();
        assert!(!sigma_regs.is_empty());
    }

    #[test]
    fn test_convert_tokens_zero_amount_rejected() {
        // Token amount of 0 should be rejected by sigma-rust
        let tokens = vec![(BoxId([0x22; 32]), 0u64)];
        let result = convert_tokens(&tokens);
        assert!(result.is_err(), "zero token amount should be rejected");
    }

    #[test]
    fn test_convert_ergo_box_candidate() {
        // Test the convert_ergo_box_candidate function directly
        let tree_bytes = p2pk_tree_bytes();
        let candidate = ErgoBoxCandidate {
            value: 500_000_000,
            ergo_tree_bytes: tree_bytes,
            creation_height: 12345,
            tokens: vec![],
            additional_registers: vec![],
        };
        let result = convert_ergo_box_candidate(&candidate);
        assert!(
            result.is_ok(),
            "candidate conversion should succeed: {:?}",
            result.err()
        );
        let sigma_candidate = result.unwrap();
        assert_eq!(*sigma_candidate.value.as_u64(), 500_000_000);
        assert_eq!(sigma_candidate.creation_height, 12345);
        assert!(sigma_candidate.tokens.is_none());
    }

    #[test]
    fn test_convert_context_extension_invalid_bytes() {
        // Non-empty but invalid extension bytes should fail during sigma parsing
        let result = convert_context_extension(&[0xFF, 0xFF, 0xFF]);
        assert!(
            result.is_err(),
            "invalid context extension bytes should fail"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Context extension error"),
            "should be ContextExtension error variant: {err_msg}"
        );
    }

    #[test]
    fn test_convert_box_id_zero() {
        // Zero box ID should convert without issue
        let our_id = BoxId([0x00; 32]);
        let sigma_id = convert_box_id(&our_id);
        let sigma_bytes: &[u8] = sigma_id.as_ref();
        assert_eq!(sigma_bytes, &[0x00; 32]);
    }

    #[test]
    fn test_convert_tx_id_zero() {
        // Zero tx ID should convert without issue
        let our_id = TxId([0x00; 32]);
        let sigma_id = convert_tx_id(&our_id);
        let sigma_bytes: &[u8] = sigma_id.as_ref();
        assert_eq!(sigma_bytes, &[0x00; 32]);
    }

    #[test]
    fn test_convert_ergo_box_preserves_index() {
        // Verify that non-zero output index is preserved through conversion
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xA7; 32]);
        let our_box = make_test_box(1_000_000_000, tree_bytes, tx_id, 5);
        let sigma_box = convert_ergo_box(&our_box).unwrap();
        assert_eq!(sigma_box.index, 5);
    }

    #[test]
    fn test_convert_transaction_multiple_outputs() {
        // Transaction with multiple outputs
        let tree_bytes = p2pk_tree_bytes();
        let tx_id = TxId([0xA8; 32]);

        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xB8; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![],
            }],
            data_inputs: vec![],
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: 500_000_000,
                    ergo_tree_bytes: tree_bytes.clone(),
                    creation_height: 0,
                    tokens: vec![],
                    additional_registers: vec![],
                },
                ErgoBoxCandidate {
                    value: 300_000_000,
                    ergo_tree_bytes: tree_bytes.clone(),
                    creation_height: 0,
                    tokens: vec![],
                    additional_registers: vec![],
                },
                ErgoBoxCandidate {
                    value: 200_000_000,
                    ergo_tree_bytes: tree_bytes,
                    creation_height: 0,
                    tokens: vec![],
                    additional_registers: vec![],
                },
            ],
            tx_id,
        };

        let result = convert_transaction(&tx);
        assert!(result.is_ok());
        let sigma_tx = result.unwrap();
        assert_eq!(sigma_tx.outputs.len(), 3);
    }

    #[test]
    fn test_compute_initial_tx_cost_defaults() {
        use crate::parameters::Parameters;
        let params = Parameters::genesis();
        let tx = ErgoTransaction {
            inputs: vec![
                Input { box_id: BoxId([0; 32]), proof_bytes: vec![], extension_bytes: vec![] },
                Input { box_id: BoxId([1; 32]), proof_bytes: vec![], extension_bytes: vec![] },
            ],
            data_inputs: vec![DataInput { box_id: BoxId([2; 32]) }],
            output_candidates: vec![
                ErgoBoxCandidate { value: 1_000_000, ergo_tree_bytes: vec![0x00], creation_height: 1, tokens: vec![], additional_registers: vec![] },
                ErgoBoxCandidate { value: 1_000_000, ergo_tree_bytes: vec![0x00], creation_height: 1, tokens: vec![], additional_registers: vec![] },
                ErgoBoxCandidate { value: 1_000_000, ergo_tree_bytes: vec![0x00], creation_height: 1, tokens: vec![], additional_registers: vec![] },
            ],
            tx_id: TxId([0; 32]),
        };
        // 10000 + 2*2000 + 1*100 + 3*100 = 14400
        assert_eq!(compute_initial_tx_cost(&tx, &params), 14400);
    }

    // ── Storage rent constants tests ────────────────────────────────

    #[test]
    fn test_storage_period_constant() {
        // Storage period is ~4 years of blocks (1 block per ~2 minutes).
        // 1,051,200 blocks * 2 min/block = 2,102,400 min ~ 1,460 days ~ 4 years.
        assert_eq!(STORAGE_PERIOD, 1_051_200);
    }

    #[test]
    fn test_storage_index_var_id_constant() {
        // The context extension key for storage rent output index is i8::MAX = 127.
        assert_eq!(STORAGE_INDEX_VAR_ID, 127);
        assert_eq!(STORAGE_INDEX_VAR_ID, i8::MAX as u8);
    }

    #[test]
    fn test_default_storage_fee_factor() {
        // Default storage fee factor is 1,250,000 nanoERGs per byte.
        // This matches the Ergo reference client default.
        assert_eq!(DEFAULT_STORAGE_FEE_FACTOR, 1_250_000);
    }

    #[test]
    fn test_storage_rent_constants_consistency() {
        // sigma-rust's storage_rent module (pub(crate)) defines:
        //   STORAGE_PERIOD = 1_051_200
        //   STORAGE_EXTENSION_INDEX = i8::MAX as u8 = 127
        // Our constants must stay in sync with the reference Ergo protocol spec.
        // These values are also defined in the Scala reference:
        //   org.ergoplatform.settings.Constants.StoragePeriod = 1051200
        //   ErgoInterpreter.StorageIndexVarId = 127
        assert_eq!(STORAGE_PERIOD, 1_051_200);
        assert_eq!(STORAGE_INDEX_VAR_ID, i8::MAX as u8);
        assert_eq!(DEFAULT_STORAGE_FEE_FACTOR, 1_250_000);

        // Verify the storage fee factor matches sigma-rust's default Parameters.
        let default_params = SigmaParameters::default();
        assert_eq!(
            DEFAULT_STORAGE_FEE_FACTOR,
            default_params.storage_fee_factor() as u64,
            "Our DEFAULT_STORAGE_FEE_FACTOR must match sigma-rust's default"
        );
    }

    // ── Parameter conversion tests ─────────────────────────────────

    #[test]
    fn test_convert_parameters_genesis_defaults() {
        let params = crate::parameters::Parameters::genesis();
        let sigma = convert_parameters(&params);
        assert_eq!(sigma.storage_fee_factor(), 1_250_000);
        assert_eq!(sigma.min_value_per_byte(), 360);
        assert_eq!(sigma.max_block_size(), 524_288);
        assert_eq!(sigma.max_block_cost(), 1_000_000);
        assert_eq!(sigma.token_access_cost(), 100);
        assert_eq!(sigma.input_cost(), 2_000);
        assert_eq!(sigma.data_input_cost(), 100);
        assert_eq!(sigma.output_cost(), 100);
        assert_eq!(sigma.block_version(), 1);
    }

    #[test]
    fn test_convert_parameters_custom_values() {
        use crate::parameters::*;
        let mut params = Parameters::genesis();
        params.table.insert(INPUT_COST_ID, 5_000);
        params.table.insert(MAX_BLOCK_COST_ID, 2_000_000);
        params.table.insert(BLOCK_VERSION_ID, 3);

        let sigma = convert_parameters(&params);
        assert_eq!(sigma.input_cost(), 5_000);
        assert_eq!(sigma.max_block_cost(), 2_000_000);
        assert_eq!(sigma.block_version(), 3);
        // Non-modified values should remain at genesis defaults
        assert_eq!(sigma.storage_fee_factor(), 1_250_000);
        assert_eq!(sigma.output_cost(), 100);
    }

    #[test]
    fn test_convert_parameters_empty_table_uses_defaults() {
        use crate::parameters::Parameters;
        let params = Parameters {
            height: 0,
            table: std::collections::BTreeMap::new(),
        };
        let sigma = convert_parameters(&params);
        // All values should be the hardcoded defaults
        assert_eq!(sigma.storage_fee_factor(), 1_250_000);
        assert_eq!(sigma.min_value_per_byte(), 360);
        assert_eq!(sigma.max_block_size(), 524_288);
        assert_eq!(sigma.max_block_cost(), 1_000_000);
        assert_eq!(sigma.token_access_cost(), 100);
        assert_eq!(sigma.input_cost(), 2_000);
        assert_eq!(sigma.data_input_cost(), 100);
        assert_eq!(sigma.output_cost(), 100);
        assert_eq!(sigma.block_version(), 1);
    }

    #[test]
    fn test_sigma_state_context_with_parameters() {
        // Verify that convert_state_context uses the parameters field
        // instead of SigmaParameters::default().
        use crate::parameters::*;
        let mut params = Parameters::genesis();
        params.table.insert(MAX_BLOCK_COST_ID, 5_000_000);

        let gen_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let gen_bytes = base16::decode(gen_hex).unwrap();
        let mut miner_pk = [0u8; 33];
        miner_pk.copy_from_slice(&gen_bytes);

        let ctx = SigmaStateContext {
            last_headers: vec![],
            current_height: 1,
            current_timestamp: 1000,
            current_n_bits: 100,
            current_votes: [0; 3],
            current_miner_pk: miner_pk,
            state_digest: [0; 33],
            parameters: params,
            current_version: 2,
            current_parent_id: [0; 32],
        };
        let sigma_ctx = convert_state_context(&ctx).expect("should convert");
        assert_eq!(sigma_ctx.parameters.max_block_cost(), 5_000_000);
    }

    #[test]
    fn preheader_uses_actual_block_version() {
        // Create SigmaStateContext with version=3 and verify convert_state_context
        // propagates it to the PreHeader instead of hardcoding 2.
        let gen_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let gen_bytes = base16::decode(gen_hex).unwrap();
        let mut miner_pk = [0u8; 33];
        miner_pk.copy_from_slice(&gen_bytes);

        let ctx = SigmaStateContext {
            last_headers: vec![],
            current_height: 1,
            current_timestamp: 1000,
            current_n_bits: 100,
            current_votes: [0; 3],
            current_miner_pk: miner_pk,
            state_digest: [0; 33],
            parameters: crate::parameters::Parameters::genesis(),
            current_version: 3,
            current_parent_id: [0; 32],
        };

        let sigma_ctx = convert_state_context(&ctx).expect("should convert");
        assert_eq!(
            sigma_ctx.pre_header.version, 3,
            "PreHeader version should be 3, not hardcoded 2"
        );
    }

    #[test]
    fn preheader_uses_correct_parent_id() {
        // Create SigmaStateContext with a specific current_parent_id and
        // last_headers containing a header with a DIFFERENT parent_id.
        // Verify convert_state_context uses current_parent_id.
        let gen_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let gen_bytes = base16::decode(gen_hex).unwrap();
        let mut miner_pk = [0u8; 33];
        miner_pk.copy_from_slice(&gen_bytes);

        // The parent_id we expect the PreHeader to use
        let expected_parent_id = [0xAA; 32];

        // A header with a completely different parent_id (which the old buggy code
        // would have used instead of current_parent_id).
        // Must set version >= 2 so Autolykos v2 path is taken (no pow_distance needed).
        let mut decoy_header = ergo_types::header::Header::default_for_test();
        decoy_header.version = 2;
        decoy_header.parent_id = ergo_types::modifier_id::ModifierId([0xBB; 32]);

        let ctx = SigmaStateContext {
            last_headers: vec![decoy_header],
            current_height: 100,
            current_timestamp: 2000,
            current_n_bits: 200,
            current_votes: [0; 3],
            current_miner_pk: miner_pk,
            state_digest: [0; 33],
            parameters: crate::parameters::Parameters::genesis(),
            current_version: 2,
            current_parent_id: expected_parent_id,
        };

        let sigma_ctx = convert_state_context(&ctx).expect("should convert");

        // The PreHeader parent_id should be current_parent_id (0xAA...),
        // NOT the first header's parent_id (0xBB...).
        let pre_header_parent_bytes: &[u8] = sigma_ctx.pre_header.parent_id.0.as_ref();
        assert_eq!(
            pre_header_parent_bytes,
            &[0xAA; 32],
            "PreHeader parent_id should use current_parent_id, not last_headers[0].parent_id"
        );
    }

    // ── Token access cost tests ─────────────────────────────────────

    #[test]
    fn token_access_cost_no_tokens() {
        let params = crate::parameters::Parameters::genesis();
        let cost = compute_token_access_cost(&[], &[], &params).unwrap();
        assert_eq!(cost, 0);
    }

    #[test]
    fn token_access_cost_basic() {
        let params = crate::parameters::Parameters::genesis();
        let token_cost = params
            .get(crate::parameters::TOKEN_ACCESS_COST_ID)
            .unwrap_or(100) as u64;

        // 1 input box with 2 token entries (same token ID).
        let token_id = BoxId([1u8; 32]);
        let tx_id = TxId([0xF0; 32]);
        let input = ErgoBox {
            candidate: ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00],
                tokens: vec![(token_id, 100), (token_id, 50)],
                creation_height: 1,
                additional_registers: vec![],
            },
            transaction_id: tx_id,
            index: 0,
            box_id: BoxId([0xF1; 32]),
        };

        // 1 output with 1 token entry (different token ID).
        let token_id_2 = BoxId([2u8; 32]);
        let output = ErgoBoxCandidate {
            value: 1_000_000,
            ergo_tree_bytes: vec![0x00],
            tokens: vec![(token_id_2, 150)],
            creation_height: 1,
            additional_registers: vec![],
        };

        let cost = compute_token_access_cost(&[input], &[output], &params).unwrap();
        // inAssetsNum=2, outAssetsNum=1, inAssetsSize=1 (1 unique), outAssetsSize=1 (1 unique)
        // (1 + 2) * 100 + (1 + 1) * 100 = 300 + 200 = 500
        assert_eq!(cost, (1 + 2) * token_cost + (1 + 1) * token_cost);
    }
}

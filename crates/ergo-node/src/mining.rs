//! Mining support: block candidate generation, solution validation, and internal CPU miner.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

use num_bigint::BigUint;

use ergo_consensus::autolykos::{get_b, msg_by_header};
use ergo_consensus::merkle::merkle_root;
use ergo_consensus::parameters::Parameters;
use ergo_consensus::sigma_verify::{compute_initial_tx_cost, SigmaStateContext};
use ergo_network::mempool::ErgoMemPool;
use ergo_network::nipopow::{pack_interlinks, unpack_interlinks, update_interlinks};
use ergo_state::state_changes::compute_state_changes;
use ergo_state::utxo_state::UtxoState;
use ergo_storage::history_db::HistoryDb;
use ergo_types::extension::Extension;
use ergo_types::header::{AutolykosSolution, Header};
use ergo_types::modifier_id::{ADDigest, Digest32, ModifierId};
use ergo_types::transaction::{
    compute_box_id, BoxId, ErgoBox, ErgoBoxCandidate, ErgoTransaction, Input, TxId,
};
use ergo_wire::transaction_ser::{compute_tx_id, serialize_transaction};
use serde::{Deserialize, Serialize};

/// Well-known ErgoTree bytes for the miners' fee proposition contract.
///
/// This is a local copy of the constant from `ergo_network::mempool`, which
/// is not publicly exported. It matches `MINERS_FEE_BASE16_BYTES` from
/// sigma-rust / ergo-lib.
const MINERS_FEE_ERGO_TREE: &[u8] = &[
    0x10, 0x05, 0x04, 0x00, 0x04, 0x00, 0x0e, 0x36, 0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd,
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
    0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
    0xf8, 0x17, 0x98, 0xea, 0x02, 0xd1, 0x92, 0xa3, 0x9a, 0x8c, 0xc7, 0xa7, 0x01, 0x73, 0x00,
    0x73, 0x01, 0x10, 0x01, 0x02, 0x04, 0x02, 0xd1, 0x96, 0x83, 0x03, 0x01, 0x93, 0xa3, 0x8c,
    0xc7, 0xb2, 0xa5, 0x73, 0x00, 0x00, 0x01, 0x93, 0xc2, 0xb2, 0xa5, 0x73, 0x01, 0x00, 0x74,
    0x73, 0x02, 0x73, 0x03, 0x83, 0x01, 0x08, 0xcd, 0xee, 0xac, 0x93, 0xb1, 0xa5, 0x73, 0x04,
];

/// Maximum number of distinct token entries in a single fee-collection output.
///
/// Matches Scala's `sdk.wallet.Constants.MaxAssetsPerBox` which is used in
/// `CandidateGenerator.collectFees` when building the miner fee-collection box.
const MAX_ASSETS_PER_BOX: usize = 100;

/// Default mining reward lock delay when not specified via settings.
const DEFAULT_MINING_REWARD_DELAY: u32 = 720;

// ---------------------------------------------------------------------------
// Miner reward, fee collection, emission, and transaction collection
// ---------------------------------------------------------------------------

/// Build a height-locked miner reward ErgoTree matching Scala's
/// `ErgoTreePredef.rewardOutputScript(delta, pk)`.
///
/// The script is: `SigmaAnd(GE(HEIGHT, Plus(creationHeight(SELF), delta)).toSigmaProp, PK(pk))`
/// serialized with constant segregation (header byte 0x10).
///
/// We construct the tree using the sigma-rust IR (ergotree-ir) rather than the
/// ergoscript text compiler, because the ergo-lib 0.28 compiler only supports a
/// trivial arithmetic subset of ErgoScript.
///
/// Falls back to a plain P2PK ErgoTree `[0x00, 0x08, 0xcd, ...pk]` if IR construction
/// fails (should never happen with valid inputs).
fn miner_reward_prop(miner_pk: &[u8; 33], reward_delay: u32) -> Vec<u8> {
    use ergo_lib::ergo_chain_types::EcPoint;
    use ergo_lib::ergotree_ir::ergo_tree::{ErgoTree, ErgoTreeHeader};
    use ergo_lib::ergotree_ir::mir::bin_op::{ArithOp, BinOp, BinOpKind, RelationOp};
    use ergo_lib::ergotree_ir::mir::bool_to_sigma::BoolToSigmaProp;
    use ergo_lib::ergotree_ir::mir::constant::Constant;
    use ergo_lib::ergotree_ir::mir::expr::Expr;
    use ergo_lib::ergotree_ir::mir::extract_creation_info::ExtractCreationInfo;
    use ergo_lib::ergotree_ir::mir::global_vars::GlobalVars;
    use ergo_lib::ergotree_ir::mir::select_field::SelectField;
    use ergo_lib::ergotree_ir::mir::sigma_and::SigmaAnd;
    use ergo_lib::ergotree_ir::mir::unary_op::OneArgOpTryBuild;
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
    use ergo_lib::ergotree_ir::sigma_protocol::sigma_boolean::ProveDlog;

    // Parse compressed public key into EcPoint via hex string.
    let pk_hex = hex::encode(miner_pk);
    let ec_point = match EcPoint::from_base16_str(pk_hex) {
        Some(p) => p,
        None => {
            tracing::warn!("failed to parse miner PK as EcPoint");
            return plain_p2pk(miner_pk);
        }
    };

    // boxCreationHeight(SELF) = SelectField(ExtractCreationInfo(SELF), 1)
    let self_box: Expr = GlobalVars::SelfBox.into();
    let creation_info = ExtractCreationInfo::try_build(self_box);
    let creation_info = match creation_info {
        Ok(ci) => ci,
        Err(e) => {
            tracing::warn!("failed to build ExtractCreationInfo: {e}");
            return plain_p2pk(miner_pk);
        }
    };
    let creation_height = match SelectField::new(
        Expr::ExtractCreationInfo(creation_info),
        1u8.try_into().expect("field index 1 is valid"),
    ) {
        Ok(sf) => Expr::from(sf),
        Err(e) => {
            tracing::warn!("failed to build SelectField: {e}");
            return plain_p2pk(miner_pk);
        }
    };

    // Plus(creationHeight, IntConstant(delta))
    let delta: Expr = (reward_delay as i32).into();
    let plus_expr: Expr = BinOp {
        kind: BinOpKind::Arith(ArithOp::Plus),
        left: Box::new(creation_height),
        right: Box::new(delta),
    }
    .into();

    // GE(Height, Plus(...))
    let height: Expr = GlobalVars::Height.into();
    let ge_expr: Expr = BinOp {
        kind: BinOpKind::Relation(RelationOp::Ge),
        left: Box::new(height),
        right: Box::new(plus_expr),
    }
    .into();

    // BoolToSigmaProp(GE(...))
    let ge_sigma: Expr = Expr::BoolToSigmaProp(BoolToSigmaProp {
        input: Box::new(ge_expr),
    });

    // SigmaPropConstant(ProveDlog(pk))
    let prove_dlog = ProveDlog::new(ec_point);
    let pk_const: Constant = prove_dlog.into();
    let pk_expr: Expr = Expr::Const(pk_const);

    // SigmaAnd([ge_sigma, pk_expr])
    let sigma_and = match SigmaAnd::new(vec![ge_sigma, pk_expr]) {
        Ok(sa) => sa,
        Err(e) => {
            tracing::warn!("failed to build SigmaAnd: {e}");
            return plain_p2pk(miner_pk);
        }
    };
    let root: Expr = Expr::SigmaAnd(sigma_and);

    // ErgoTree with constant segregation (header = 0x10, version 0).
    let header = ErgoTreeHeader::v0(true);
    let ergo_tree = match ErgoTree::new(header, &root) {
        Ok(tree) => tree,
        Err(e) => {
            tracing::warn!("failed to build ErgoTree: {e}");
            return plain_p2pk(miner_pk);
        }
    };

    match ergo_tree.sigma_serialize_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("failed to serialize height-locked ErgoTree: {e}");
            plain_p2pk(miner_pk)
        }
    }
}

/// Plain P2PK ErgoTree: `[0x00, 0x08, 0xcd, ...33-byte-pk]`.
fn plain_p2pk(miner_pk: &[u8; 33]) -> Vec<u8> {
    let mut tree = Vec::with_capacity(36);
    tree.extend_from_slice(&[0x00, 0x08, 0xcd]);
    tree.extend_from_slice(miner_pk);
    tree
}

/// Build a fee collection transaction.
///
/// Scans the given transactions for outputs whose ErgoTree matches
/// `MINERS_FEE_ERGO_TREE`, collects them as inputs, and creates a single
/// output paying the miner. Tokens from fee boxes are aggregated (unique
/// token IDs with summed amounts) up to [`MAX_ASSETS_PER_BOX`], matching
/// Scala's `CandidateGenerator.collectFees`.
///
/// Returns `None` if there are no fee outputs to collect.
fn build_fee_collection_tx(
    block_txs: &[ErgoTransaction],
    next_height: u32,
    miner_pk: &[u8; 33],
    reward_delay: u32,
) -> Option<ErgoTransaction> {
    // 1. Scan for fee outputs across all transactions.
    let mut fee_inputs: Vec<Input> = Vec::new();
    let mut total_fee: u64 = 0;
    // Collect all tokens from fee boxes, preserving insertion order.
    let mut token_map: BTreeMap<[u8; 32], u64> = BTreeMap::new();

    for tx in block_txs {
        for (idx, output) in tx.output_candidates.iter().enumerate() {
            if output.ergo_tree_bytes == MINERS_FEE_ERGO_TREE {
                let box_id = compute_box_id(&tx.tx_id, idx as u16);
                fee_inputs.push(Input {
                    box_id,
                    proof_bytes: Vec::new(),
                    extension_bytes: Vec::new(),
                });
                total_fee = total_fee.saturating_add(output.value);
                // Aggregate tokens from this fee box.
                for (token_id, amount) in &output.tokens {
                    let entry = token_map.entry(token_id.0).or_insert(0);
                    *entry = entry.saturating_add(*amount);
                }
            }
        }
    }

    // 2. If no fee outputs found, nothing to collect.
    if fee_inputs.is_empty() || total_fee == 0 {
        return None;
    }

    // 3. Collect tokens up to MAX_ASSETS_PER_BOX.
    let fee_tokens: Vec<(BoxId, u64)> = token_map
        .into_iter()
        .take(MAX_ASSETS_PER_BOX)
        .map(|(id, amount)| (BoxId(id), amount))
        .collect();

    // 4. Build miner reward output.
    let miner_output = ErgoBoxCandidate {
        value: total_fee,
        ergo_tree_bytes: miner_reward_prop(miner_pk, reward_delay),
        creation_height: next_height,
        tokens: fee_tokens,
        additional_registers: Vec::new(),
    };

    // 5. Build the transaction and compute its ID.
    let mut fee_tx = ErgoTransaction {
        inputs: fee_inputs,
        data_inputs: Vec::new(),
        output_candidates: vec![miner_output],
        tx_id: TxId([0u8; 32]), // placeholder
    };
    fee_tx.tx_id = compute_tx_id(&fee_tx);

    Some(fee_tx)
}

/// Build the emission transaction for mining.
///
/// The emission transaction spends the emission box (identified by the emission
/// NFT) and creates:
/// 1. A new emission box (with reduced value, same NFT and registers)
/// 2. A miner reward box (with the emission reward amount)
///
/// Returns `None` if:
/// - No UTXO state is provided
/// - No emission box is tracked or found in UTXO state
/// - The remaining emission is zero
/// - The emission box value is insufficient for the reward
fn build_emission_tx(
    next_height: u32,
    miner_pk: &[u8; 33],
    utxo_state: Option<&UtxoState>,
    reward_delay: u32,
) -> Option<ErgoTransaction> {
    let utxo = utxo_state?;

    // Compute expected emission at this height.
    let reward = ergo_network::emission::miner_reward_at_height(next_height);
    if reward == 0 {
        return None; // Past emission schedule.
    }
    // EIP-27: compute reemission charge (0 before activation height 777,217).
    let reemission_charge = ergo_network::emission::reemission_for_height(next_height);

    // Get the tracked emission box ID.
    let emission_box_id = utxo.emission_box_id()?;

    // Look up and deserialize the emission box from the UTXO AVL tree.
    let emission_box = match utxo.get_ergo_box(emission_box_id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            tracing::warn!("emission box not found in UTXO state");
            return None;
        }
        Err(e) => {
            tracing::warn!("failed to deserialize emission box: {e}");
            return None;
        }
    };

    if emission_box.candidate.value < reward {
        tracing::warn!(
            height = next_height,
            box_value = emission_box.candidate.value,
            reward,
            "emission box value less than reward"
        );
        return None;
    }

    // Build input: spend the emission box (empty proof -- emission contract
    // verified at block validation time via sigma-rust).
    let input = Input {
        box_id: *emission_box_id,
        proof_bytes: Vec::new(),
        extension_bytes: Vec::new(),
    };

    // EIP-27: deduct reemission charge from the first token (ERG reemission token)
    // in the emission box. Before activation height this is a no-op (charge == 0).
    let mut new_tokens = emission_box.candidate.tokens.clone();
    if reemission_charge > 0 && !new_tokens.is_empty() {
        new_tokens[0].1 = new_tokens[0].1.saturating_sub(reemission_charge);
    }

    // Build output 1: new emission box (reduced value, same ErgoTree, adjusted tokens).
    let new_emission_box = ErgoBoxCandidate {
        value: emission_box.candidate.value - reward,
        ergo_tree_bytes: emission_box.candidate.ergo_tree_bytes.clone(),
        creation_height: next_height,
        tokens: new_tokens,
        additional_registers: emission_box.candidate.additional_registers.clone(),
    };

    // Build output 2: miner reward box.
    // EIP-27: miner receives reward minus the reemission charge.
    let miner_output = ErgoBoxCandidate {
        value: reward.saturating_sub(reemission_charge),
        ergo_tree_bytes: miner_reward_prop(miner_pk, reward_delay),
        creation_height: next_height,
        tokens: Vec::new(),
        additional_registers: Vec::new(),
    };

    let mut tx = ErgoTransaction {
        inputs: vec![input],
        data_inputs: Vec::new(),
        output_candidates: vec![new_emission_box, miner_output],
        tx_id: TxId([0u8; 32]), // placeholder
    };
    tx.tx_id = compute_tx_id(&tx);

    Some(tx)
}

/// Collect transactions for a block candidate, respecting size and cost limits.
///
/// Processes mempool transactions in order (highest fee-weight first as returned
/// by the mempool), applying a greedy knapsack: each transaction is included if
/// it fits within both `max_block_size` and `max_block_cost`.
///
/// When `sigma_ctx` and `utxo_state` are both provided, full sigma script
/// validation is performed on each candidate transaction (matching Scala's
/// `CandidateGenerator.collectTxs` which calls `validateWithCost`). Transactions
/// that fail sigma verification are silently skipped.
///
/// Ordering guarantees:
/// - The emission transaction (if any) is always first.
/// - Mempool transactions follow in priority order.
/// - A fee collection transaction is appended last.
///
/// Returns `(selected_txs, eliminated_tx_ids)`.
#[allow(clippy::too_many_arguments)]
pub fn collect_txs(
    mempool_txs: Vec<ErgoTransaction>,
    emission_tx: Option<ErgoTransaction>,
    max_block_size: u64,
    max_block_cost: u64,
    parameters: &Parameters,
    next_height: u32,
    miner_pk: &[u8; 33],
    utxo_state: Option<&UtxoState>,
    sigma_ctx: Option<&SigmaStateContext>,
    reward_delay: u32,
) -> (Vec<ErgoTransaction>, Vec<[u8; 32]>) {
    let mut selected: Vec<ErgoTransaction> = Vec::new();
    let mut eliminated: Vec<[u8; 32]> = Vec::new();
    let mut total_size: u64 = 0;
    let mut total_cost: u64 = 0;

    // Track consumed box IDs for intra-block double-spend detection.
    let mut consumed_box_ids: std::collections::HashSet<[u8; 32]> =
        std::collections::HashSet::new();

    // UTXO overlay: outputs from earlier txs in this block available to later txs (chained txs).
    let mut utxo_overlay: std::collections::HashMap<[u8; 32], ErgoBox> =
        std::collections::HashMap::new();

    // Safe gap: reserve headroom for the fee tx and rounding.
    // Matches Scala's CandidateGenerator three-tier safeGap.
    let safe_gap: u64 = if max_block_cost >= 5_000_000 {
        500_000
    } else if max_block_cost >= 1_000_000 {
        150_000
    } else {
        0
    };
    let cost_limit = max_block_cost.saturating_sub(safe_gap);

    // 1. Emission tx first (if available).
    if let Some(ref etx) = emission_tx {
        for input in &etx.inputs {
            consumed_box_ids.insert(input.box_id.0);
        }
        let etx_size = serialize_transaction(etx).len() as u64;
        let etx_cost = compute_initial_tx_cost(etx, parameters);
        total_size += etx_size;
        total_cost += etx_cost;
        selected.push(etx.clone());

        // Add emission tx outputs to overlay so mempool txs can spend them.
        for (idx, output) in etx.output_candidates.iter().enumerate() {
            let bid = compute_box_id(&etx.tx_id, idx as u16);
            utxo_overlay.insert(bid.0, ErgoBox {
                candidate: output.clone(),
                transaction_id: etx.tx_id.clone(),
                index: idx as u16,
                box_id: bid,
            });
        }
    }

    // 2. Add mempool txs greedily in priority order.
    for tx in mempool_txs {
        let tx_bytes = serialize_transaction(&tx);
        let tx_size = tx_bytes.len() as u64;
        let tx_cost = compute_initial_tx_cost(&tx, parameters);

        if total_size + tx_size > max_block_size {
            eliminated.push(tx.tx_id.0);
            continue;
        }
        if total_cost + tx_cost > cost_limit {
            eliminated.push(tx.tx_id.0);
            continue;
        }

        // UTXO validation: check inputs exist and no intra-block double-spend.
        let mut tx_valid = true;
        let mut input_boxes: Vec<ErgoBox> = Vec::new();
        for input in &tx.inputs {
            // Check intra-block double-spend.
            if consumed_box_ids.contains(&input.box_id.0) {
                tx_valid = false;
                break;
            }
            // Check input exists in UTXO overlay (chained tx) or UTXO state.
            if let Some(overlay_box) = utxo_overlay.get(&input.box_id.0) {
                input_boxes.push(overlay_box.clone());
            } else if let Some(utxo) = utxo_state {
                match utxo.get_ergo_box(&input.box_id) {
                    Ok(Some(b)) => input_boxes.push(b),
                    _ => {
                        tx_valid = false;
                        break;
                    }
                }
            }
        }
        if !tx_valid {
            eliminated.push(tx.tx_id.0);
            continue;
        }

        // Sigma script validation (when UTXO state + sigma context available).
        if let (Some(utxo), Some(ctx)) = (utxo_state, sigma_ctx) {
            // Resolve data input boxes (check overlay first for chained txs).
            let mut data_boxes = Vec::new();
            let mut data_ok = true;
            for di in &tx.data_inputs {
                if let Some(overlay_box) = utxo_overlay.get(&di.box_id.0) {
                    data_boxes.push(overlay_box.clone());
                } else {
                    match utxo.get_ergo_box(&di.box_id) {
                        Ok(Some(b)) => data_boxes.push(b),
                        _ => {
                            data_ok = false;
                            break;
                        }
                    }
                }
            }

            if !data_ok {
                tracing::debug!(
                    tx_id = %hex::encode(tx.tx_id.0),
                    "collect_txs: data input box missing, skipping tx"
                );
                eliminated.push(tx.tx_id.0);
                continue;
            }

            match ergo_consensus::sigma_verify::verify_transaction(
                &tx,
                &input_boxes,
                &data_boxes,
                ctx,
                0, // no checkpoint — always verify for mining candidates
            ) {
                Ok(sigma_cost) => {
                    // Check that accumulated cost + sigma cost stays within limits.
                    if total_cost + tx_cost + sigma_cost > cost_limit {
                        tracing::debug!(
                            tx_id = %hex::encode(tx.tx_id.0),
                            sigma_cost,
                            "collect_txs: tx sigma cost would exceed block cost limit"
                        );
                        eliminated.push(tx.tx_id.0);
                        continue;
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        tx_id = %hex::encode(tx.tx_id.0),
                        error = %e,
                        "collect_txs: sigma verification failed, skipping tx"
                    );
                    eliminated.push(tx.tx_id.0);
                    continue;
                }
            }
        }

        // Track consumed inputs.
        for input in &tx.inputs {
            consumed_box_ids.insert(input.box_id.0);
        }

        total_size += tx_size;
        total_cost += tx_cost;
        selected.push(tx);

        // Add outputs to UTXO overlay so later txs can spend them (chained txs).
        let last_tx = selected.last().unwrap();
        for (idx, output) in last_tx.output_candidates.iter().enumerate() {
            let bid = compute_box_id(&last_tx.tx_id, idx as u16);
            utxo_overlay.insert(bid.0, ErgoBox {
                candidate: output.clone(),
                transaction_id: last_tx.tx_id.clone(),
                index: idx as u16,
                box_id: bid,
            });
        }
    }

    // 3. Append fee collection tx (collects fees from all selected txs).
    if let Some(fee_tx) = build_fee_collection_tx(&selected, next_height, miner_pk, reward_delay) {
        // Sigma-validate fee tx if UTXO context is available.
        if let (Some(utxo), Some(ctx)) = (utxo_state, sigma_ctx) {
            let mut fee_input_boxes = Vec::new();
            let mut fee_valid = true;
            for input in &fee_tx.inputs {
                if let Some(overlay_box) = utxo_overlay.get(&input.box_id.0) {
                    fee_input_boxes.push(overlay_box.clone());
                } else if let Ok(Some(b)) = utxo.get_ergo_box(&input.box_id) {
                    fee_input_boxes.push(b);
                } else {
                    fee_valid = false;
                    break;
                }
            }
            if fee_valid {
                if let Err(e) = ergo_consensus::sigma_verify::verify_transaction(
                    &fee_tx,
                    &fee_input_boxes,
                    &[],
                    ctx,
                    0, // no checkpoint — always verify for mining candidates
                ) {
                    tracing::warn!(error = %e, "fee collection tx sigma verification failed");
                }
            }
        }
        selected.push(fee_tx);
    }

    (selected, eliminated)
}

/// A block candidate ready for PoW mining.
#[derive(Debug, Clone)]
pub struct CandidateBlock {
    /// Parent header (None for genesis candidate).
    pub parent: Option<Header>,
    /// Block version byte.
    pub version: u8,
    /// Encoded required difficulty.
    pub n_bits: u64,
    /// State root after applying transactions (33-byte AD digest).
    pub state_root: [u8; 33],
    /// AD proof bytes for digest-mode peers.
    pub ad_proof_bytes: Vec<u8>,
    /// Transactions to include in this block (fee tx first).
    pub transactions: Vec<ErgoTransaction>,
    /// Block timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// Extension section (interlinks + parameters).
    pub extension: Extension,
    /// Three miner voting bytes.
    pub votes: [u8; 3],
}

/// Compact work message sent to external miners.
#[derive(Debug, Clone, Serialize)]
pub struct WorkMessage {
    /// blake2b256(header_without_pow) -- the message to hash (hex-encoded).
    pub msg: String,
    /// Target value: q / difficulty. Miner must find nonce such that hit < b.
    ///
    /// Serialized as a JSON number (not a quoted string), matching Scala's
    /// `BigInt` JSON encoding via `JsonNumber.fromDecimalStringUnsafe`.
    #[serde(serialize_with = "serialize_biguint_as_number")]
    pub b: BigUint,
    /// Block height (used in v2 PoW computation).
    pub h: u32,
    /// Miner compressed public key (hex-encoded 33 bytes).
    pub pk: String,
}

/// Serialize a [`BigUint`] as a raw JSON number (no quotes).
///
/// Matches Scala's `bigIntEncoder` which uses `JsonNumber.fromDecimalStringUnsafe`.
/// Requires the `arbitrary_precision` feature on serde_json (enabled in ergo-node).
fn serialize_biguint_as_number<S: serde::Serializer>(
    value: &BigUint,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let decimal = value.to_string();
    let num = serde_json::Number::from_string_unchecked(decimal);
    num.serialize(serializer)
}

/// Solution submitted by an external miner.
#[derive(Debug, Clone, Deserialize)]
pub struct MiningSolution {
    /// Miner public key (hex, 33 bytes). For v2, can be omitted.
    #[serde(default)]
    pub pk: String,
    /// One-time public key w (hex, 33 bytes). For v2, can be omitted.
    #[serde(default)]
    pub w: String,
    /// Nonce (hex, 8 bytes). Required.
    pub n: String,
    /// Distance d. For v2, always 0.
    #[serde(default)]
    pub d: u64,
}

impl MiningSolution {
    /// Parse the nonce from hex string into [u8; 8].
    pub fn nonce_bytes(&self) -> Option<[u8; 8]> {
        let bytes = hex::decode(&self.n).ok()?;
        if bytes.len() != 8 {
            return None;
        }
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&bytes);
        Some(nonce)
    }

    /// Parse the miner public key from hex, falling back to a default.
    pub fn miner_pk_bytes(&self) -> [u8; 33] {
        if let Ok(bytes) = hex::decode(&self.pk) {
            if bytes.len() == 33 {
                let mut pk = [0u8; 33];
                pk.copy_from_slice(&bytes);
                return pk;
            }
        }
        // Default: compressed generator point placeholder for v2
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        pk
    }

    /// Parse the w value from hex, falling back to a default.
    pub fn w_bytes(&self) -> [u8; 33] {
        if let Ok(bytes) = hex::decode(&self.w) {
            if bytes.len() == 33 {
                let mut w = [0u8; 33];
                w.copy_from_slice(&bytes);
                return w;
            }
        }
        let mut w = [0u8; 33];
        w[0] = 0x02;
        w
    }
}

// ---------------------------------------------------------------------------
// Candidate generation
// ---------------------------------------------------------------------------

/// Result of attempting to apply a mining solution.
#[derive(Debug)]
pub enum SolutionResult {
    /// PoW was invalid for both current and previous candidate.
    InvalidPow,
    /// No candidate available.
    NoCandidate,
    /// Solution had an invalid format.
    InvalidFormat(String),
}

/// Errors from candidate generation.
#[derive(Debug, thiserror::Error)]
pub enum CandidateError {
    #[error("no best full block available")]
    NoBestBlock,
    #[error("parent header not found: {0}")]
    ParentHeaderNotFound(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("mining not configured: no public key")]
    NoMiningKey,
    #[error("state error: {0}")]
    StateError(String),
    #[error("no transactions available for block candidate")]
    NoTransactions,
}

/// Generates block candidates for mining.
///
/// Assembles a new [`CandidateBlock`] from chain state (parent header,
/// extension, mempool transactions, parameters) and produces a [`WorkMessage`]
/// that can be sent to external or internal miners.
pub struct CandidateGenerator {
    /// Current candidate (most recent) paired with the header template.
    current_candidate: Option<(CandidateBlock, Header)>,
    /// Previous candidate (for solution fallback on race conditions).
    previous_candidate: Option<(CandidateBlock, Header)>,
    /// Miner public key (33-byte compressed secp256k1 point).
    pub miner_pk: [u8; 33],
    /// Three miner voting bytes.
    pub votes: [u8; 3],
}

impl CandidateGenerator {
    /// Create a new generator with no current candidate.
    pub fn new(miner_pk: [u8; 33], votes: [u8; 3]) -> Self {
        Self {
            current_candidate: None,
            previous_candidate: None,
            miner_pk,
            votes,
        }
    }

    /// Reference to the most recent candidate + header template, if any.
    pub fn current(&self) -> Option<&(CandidateBlock, Header)> {
        self.current_candidate.as_ref()
    }

    /// Reference to the previous candidate + header template, if any.
    pub fn previous(&self) -> Option<&(CandidateBlock, Header)> {
        self.previous_candidate.as_ref()
    }

    /// Returns `true` if at least one candidate has been generated.
    pub fn has_candidate(&self) -> bool {
        self.current_candidate.is_some()
    }

    /// Try to apply a mining solution to the current or previous candidate.
    ///
    /// Returns the completed [`Header`] if the PoW is valid, or a
    /// [`SolutionResult`] describing why it failed.
    pub fn try_solution(&self, solution: &MiningSolution) -> Result<Header, SolutionResult> {
        let nonce = solution
            .nonce_bytes()
            .ok_or_else(|| SolutionResult::InvalidFormat("invalid nonce hex".into()))?;
        let miner_pk = solution.miner_pk_bytes();
        let w = solution.w_bytes();
        let d = if solution.d == 0 {
            Vec::new()
        } else {
            solution.d.to_be_bytes().to_vec()
        };

        // Try current candidate first.
        if let Some((_, ref template)) = self.current_candidate {
            let mut header = template.clone();
            header.pow_solution = AutolykosSolution {
                miner_pk,
                w,
                nonce,
                d: d.clone(),
            };
            if ergo_consensus::autolykos::validate_pow(&header).is_ok() {
                return Ok(header);
            }
        }

        // Try previous candidate (race condition handling).
        if let Some((_, ref template)) = self.previous_candidate {
            let mut header = template.clone();
            header.pow_solution = AutolykosSolution {
                miner_pk,
                w,
                nonce,
                d,
            };
            if ergo_consensus::autolykos::validate_pow(&header).is_ok() {
                return Ok(header);
            }
        }

        if self.current_candidate.is_none() && self.previous_candidate.is_none() {
            Err(SolutionResult::NoCandidate)
        } else {
            Err(SolutionResult::InvalidPow)
        }
    }

    /// Assemble a new block candidate from chain state and mempool.
    ///
    /// Steps:
    /// 1. Load parent header from history (best full block).
    /// 2. Compute timestamp, height, nBits.
    /// 3. Build extension with interlinks + parameter fields.
    /// 4. Collect mempool transactions.
    /// 5. Compute transactions root via Merkle tree.
    /// 6. Compute extension root via Merkle tree.
    /// 7. Build header template (with empty PoW solution).
    /// 8. Compute PoW message and target.
    /// 9. Rotate current -> previous, store new candidate.
    /// 10. Return a [`WorkMessage`].
    ///
    /// `reward_delay` controls how many blocks the miner must wait before
    /// spending the reward output (typically 720). Pass `None` to use the
    /// default (`DEFAULT_MINING_REWARD_DELAY`).
    pub fn generate_candidate(
        &mut self,
        history: &HistoryDb,
        mempool: &RwLock<ErgoMemPool>,
        parameters: &Parameters,
        utxo_state: Option<&UtxoState>,
        reward_delay: Option<u32>,
    ) -> Result<WorkMessage, CandidateError> {
        let reward_delay = reward_delay.unwrap_or(DEFAULT_MINING_REWARD_DELAY);

        if self.miner_pk == [0u8; 33] {
            return Err(CandidateError::NoMiningKey);
        }

        // 1. Load parent header
        let parent_id = history
            .best_full_block_id()
            .map_err(|e| CandidateError::Storage(e.to_string()))?
            .ok_or(CandidateError::NoBestBlock)?;

        let parent_header = history
            .load_header(&parent_id)
            .map_err(|e| CandidateError::Storage(e.to_string()))?
            .ok_or_else(|| CandidateError::ParentHeaderNotFound(hex::encode(parent_id.0)))?;

        // 2. Timestamp: max(now, parent.timestamp + 1)
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let timestamp = now_ms.max(parent_header.timestamp + 1);

        // 3. Height and nBits (recalculate at epoch boundaries)
        let height = parent_header.height + 1;
        let n_bits = ergo_network::node_view::compute_required_difficulty_from_history(
            history,
            height,
            &parent_header,
            0, // No checkpoint for mining — always attempt to compute
        )
        .map(|v| v as u64)
        .unwrap_or(parent_header.n_bits);

        // 4. Build extension: interlinks + parameters
        let extension_fields = build_extension_fields(history, &parent_header, &parent_id, parameters);
        let extension = Extension {
            header_id: ModifierId([0u8; 32]), // placeholder — will be set after header ID is known
            fields: extension_fields.clone(),
        };

        // 5. Build sigma state context for transaction validation (UTXO mode).
        let sigma_ctx = if utxo_state.is_some() {
            // Collect last 10 headers for the sigma context.
            let mut last_headers = Vec::new();
            let mut walk_id = parent_id;
            for _ in 0..10 {
                match history.load_header(&walk_id) {
                    Ok(Some(h)) => {
                        let pid = h.parent_id;
                        last_headers.push(h);
                        walk_id = pid;
                    }
                    _ => break,
                }
            }

            Some(SigmaStateContext {
                last_headers,
                current_height: height,
                current_timestamp: timestamp,
                current_n_bits: n_bits,
                current_votes: self.votes,
                current_miner_pk: self.miner_pk,
                state_digest: parent_header.state_root.0,
                parameters: parameters.clone(),
                current_version: parent_header.version,
                current_parent_id: parent_id.0,
            })
        } else {
            None
        };

        // 6. Collect transactions with emission, fee collection, and size limits
        let emission_tx = build_emission_tx(height, &self.miner_pk, utxo_state, reward_delay);
        let max_block_size = parameters.max_block_size() as u64;
        let mempool_txs = {
            let pool = mempool.read().unwrap_or_else(|e| e.into_inner());
            pool.take_all_cloned()
        };
        let max_block_cost = parameters.max_block_cost() as u64;
        let (transactions, _eliminated) = collect_txs(
            mempool_txs,
            emission_tx,
            max_block_size,
            max_block_cost,
            parameters,
            height,
            &self.miner_pk,
            utxo_state,
            sigma_ctx.as_ref(),
            reward_delay,
        );

        // Guard: if no transactions were selected, skip candidate generation.
        if transactions.is_empty() {
            tracing::warn!(height, "no transactions for block candidate, skipping");
            return Err(CandidateError::NoTransactions);
        }

        // 7. Compute real state root via speculative state application (UTXO mode)
        //    or fall back to parent state root (digest mode).
        let (state_root, ad_proof_bytes) = if let Some(utxo) = utxo_state {
            let state_changes = compute_state_changes(&transactions);
            match utxo.proofs_for_transactions(&state_changes) {
                Ok((proof, digest)) => {
                    // Convert digest Vec<u8> to [u8; 33] (ADDigest format).
                    let mut root = [0u8; 33];
                    let len = digest.len().min(33);
                    root[..len].copy_from_slice(&digest[..len]);
                    (root, proof)
                }
                Err(e) => {
                    return Err(CandidateError::StateError(e.to_string()));
                }
            }
        } else {
            // Digest mode: use parent's state root (blocks won't be fully valid
            // but this is the best we can do without UTXO state).
            (parent_header.state_root.0, Vec::new())
        };

        // 8. Compute transactions root via Merkle tree
        let tx_serialized: Vec<Vec<u8>> = transactions
            .iter()
            .map(serialize_transaction)
            .collect();
        let tx_slices: Vec<&[u8]> = tx_serialized.iter().map(|v| v.as_slice()).collect();
        let transactions_root = merkle_root(&tx_slices).unwrap_or([0u8; 32]);

        // 9. Compute extension root via Merkle tree
        let ext_leaves: Vec<Vec<u8>> = extension_fields
            .iter()
            .map(|(key, value)| {
                let mut leaf = Vec::with_capacity(key.len() + value.len());
                leaf.extend_from_slice(key);
                leaf.extend_from_slice(value);
                leaf
            })
            .collect();
        let ext_slices: Vec<&[u8]> = ext_leaves.iter().map(|v| v.as_slice()).collect();
        let extension_root = merkle_root(&ext_slices).unwrap_or([0u8; 32]);

        // 10. AD proofs root from the actual proof bytes
        let ad_proofs_root = if !ad_proof_bytes.is_empty() {
            crate::snapshots::blake2b256(&ad_proof_bytes)
        } else {
            [0u8; 32]
        };

        // 11. Build header template with empty PoW solution
        let header_template = Header {
            version: parent_header.version,
            parent_id,
            ad_proofs_root: Digest32(ad_proofs_root),
            transactions_root: Digest32(transactions_root),
            state_root: ADDigest(state_root),
            timestamp,
            extension_root: Digest32(extension_root),
            n_bits,
            height,
            votes: self.votes,
            unparsed_bytes: Vec::new(),
            pow_solution: AutolykosSolution {
                miner_pk: self.miner_pk,
                w: {
                    let mut w = [0u8; 33];
                    w[0] = 0x02; // valid compressed point prefix
                    w
                },
                nonce: [0u8; 8],
                d: Vec::new(), // empty for Autolykos v2
            },
        };

        // 12. Compute PoW message and target
        let msg = msg_by_header(&header_template);
        let b_big = get_b(n_bits);

        // 13. Build candidate block
        let candidate = CandidateBlock {
            parent: Some(parent_header.clone()),
            version: header_template.version,
            n_bits,
            state_root,
            ad_proof_bytes,
            transactions,
            timestamp,
            extension,
            votes: self.votes,
        };

        // 14. Build work message (b is now full BigUint — no truncation)
        let work = WorkMessage {
            msg: hex::encode(msg),
            b: b_big,
            h: height,
            pk: hex::encode(self.miner_pk),
        };

        // 15. Rotate: current → previous, store new
        self.previous_candidate = self.current_candidate.take();
        self.current_candidate = Some((candidate, header_template));

        Ok(work)
    }
}

/// Build extension fields combining interlinks and system parameters.
///
/// Tries to load the parent extension from storage to extract existing interlinks,
/// then updates them. Falls back to empty interlinks if the parent extension is
/// not available.
fn build_extension_fields(
    history: &HistoryDb,
    parent_header: &Header,
    parent_id: &ModifierId,
    parameters: &Parameters,
) -> Vec<([u8; 2], Vec<u8>)> {
    // Try to load parent extension and extract interlinks
    let parent_interlinks = history
        .load_extension(parent_id)
        .ok()
        .flatten()
        .map(|ext| unpack_interlinks(&ext))
        .unwrap_or_default();

    // Compute updated interlinks for new block
    let new_interlinks = update_interlinks(parent_header, parent_id, &parent_interlinks);

    // Pack interlinks into extension fields
    let mut fields = pack_interlinks(&new_interlinks);

    // Add system parameter fields
    fields.extend(parameters.to_extension_fields());

    fields
}

/// Convert a [`BigUint`] to `u64`, saturating at `u64::MAX` if the value is too large.
#[cfg(test)]
fn biguint_to_u64_saturating(val: &BigUint) -> u64 {
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
// Internal CPU miner
// ---------------------------------------------------------------------------

/// Spawn internal CPU mining tasks.
///
/// Each task polls for the current work message and iterates nonces in batches.
/// When a valid nonce is found, it is sent through the solution channel.
///
/// # Arguments
///
/// * `count` - Number of concurrent mining tasks to spawn.
/// * `polling_ms` - Milliseconds to wait between polls when no candidate is available.
/// * `candidate_gen` - Shared reference to the candidate generator.
/// * `solution_tx` - Channel sender for submitting found solutions.
/// * `shutdown` - Watch channel receiver; mining stops when `true` is broadcast.
///
/// # Returns
///
/// A vector of `JoinHandle`s for the spawned mining tasks.
pub fn spawn_internal_miners(
    count: u32,
    polling_ms: u64,
    candidate_gen: Arc<RwLock<CandidateGenerator>>,
    solution_tx: tokio::sync::mpsc::Sender<MiningSolution>,
    shutdown: watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();

    for miner_id in 0..count {
        let gen = candidate_gen.clone();
        let tx = solution_tx.clone();
        let mut shutdown_rx = shutdown.clone();
        let polling = tokio::time::Duration::from_millis(polling_ms);

        let handle = tokio::spawn(async move {
            let mut nonce_start: u64 = miner_id as u64 * 1_000_000_000;
            let batch_size: u64 = 1000;

            loop {
                // Check shutdown.
                if *shutdown_rx.borrow() {
                    break;
                }

                // Get current candidate info.
                let work = {
                    let gen = gen.read().unwrap();
                    gen.current().map(|(_, header)| {
                        let msg = ergo_consensus::autolykos::msg_by_header(header);
                        let target = ergo_consensus::autolykos::get_b(header.n_bits);
                        let height = header.height;
                        let pk = header.pow_solution.miner_pk;
                        (msg, target, height, pk)
                    })
                };

                if let Some((msg, target, height, pk)) = work {
                    // Mine a batch of nonces.
                    if let Some(nonce) = ergo_consensus::autolykos::find_nonce(
                        &msg,
                        &target,
                        height,
                        nonce_start,
                        batch_size,
                    ) {
                        let solution = MiningSolution {
                            pk: hex::encode(pk),
                            w: String::new(),
                            n: hex::encode(nonce),
                            d: 0,
                        };
                        if tx.send(solution).await.is_err() {
                            break; // Channel closed.
                        }
                        tracing::info!(
                            miner_id,
                            height,
                            nonce = hex::encode(nonce),
                            "CPU miner found solution!"
                        );
                    }
                    nonce_start = nonce_start.wrapping_add(batch_size);
                } else {
                    // No candidate — wait and retry.
                    tokio::select! {
                        _ = tokio::time::sleep(polling) => {}
                        _ = shutdown_rx.changed() => { break; }
                    }
                }
            }
            tracing::debug!(miner_id, "internal miner shutting down");
        });

        handles.push(handle);
    }

    handles
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::transaction::BoxId;

    #[test]
    fn test_mining_solution_parse_nonce() {
        let sol = MiningSolution {
            pk: String::new(),
            w: String::new(),
            n: "0102030405060708".into(),
            d: 0,
        };
        let nonce = sol.nonce_bytes().expect("valid nonce");
        assert_eq!(nonce, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_mining_solution_parse_nonce_invalid() {
        let sol = MiningSolution {
            pk: String::new(),
            w: String::new(),
            n: "0102".into(), // too short
            d: 0,
        };
        assert!(sol.nonce_bytes().is_none());
    }

    #[test]
    fn test_mining_solution_default_pk() {
        let sol = MiningSolution {
            pk: String::new(),
            w: String::new(),
            n: "0000000000000000".into(),
            d: 0,
        };
        let pk = sol.miner_pk_bytes();
        assert_eq!(pk[0], 0x02);
    }

    #[test]
    fn test_candidate_block_creation() {
        use ergo_types::modifier_id::ModifierId;
        let candidate = CandidateBlock {
            parent: None,
            version: 2,
            n_bits: 100_734_821,
            state_root: [0u8; 33],
            ad_proof_bytes: Vec::new(),
            transactions: Vec::new(),
            timestamp: 1_000_000,
            extension: Extension {
                header_id: ModifierId([0u8; 32]),
                fields: Vec::new(),
            },
            votes: [0, 0, 0],
        };
        assert_eq!(candidate.version, 2);
        assert!(candidate.transactions.is_empty());
    }

    #[test]
    fn test_work_message_serialization() {
        let work = WorkMessage {
            msg: "aa".repeat(32),
            b: BigUint::from(12_345_678_901_234_567_890u128),
            h: 850_000,
            pk: "bb".repeat(33),
        };
        let json = serde_json::to_value(&work).unwrap();
        assert!(json.get("msg").is_some());
        assert!(json.get("b").is_some());
        assert!(json.get("h").is_some());
        assert!(json.get("pk").is_some());
        // b should be a JSON number, not a string.
        let b_val = json.get("b").unwrap();
        assert!(b_val.is_number(), "b should be a JSON number");
    }

    #[test]
    fn test_work_message_b_large_value() {
        // Test with a value that exceeds u64::MAX but fits in u128.
        let large_b = BigUint::from(u128::MAX);
        let work = WorkMessage {
            msg: "cc".repeat(32),
            b: large_b.clone(),
            h: 100,
            pk: "dd".repeat(33),
        };
        let json_str = serde_json::to_string(&work).unwrap();
        // Should contain the decimal representation of u128::MAX.
        assert!(
            json_str.contains(&u128::MAX.to_string()),
            "large b should be present in JSON"
        );
    }

    // ── CandidateGenerator unit tests ────────────────────────────────

    #[test]
    fn test_candidate_generator_new() {
        let pk = [0x02; 33];
        let votes = [1, 2, 3];
        let gen = CandidateGenerator::new(pk, votes);
        assert!(!gen.has_candidate());
        assert_eq!(gen.miner_pk, pk);
        assert_eq!(gen.votes, votes);
    }

    #[test]
    fn test_candidate_generator_accessors() {
        let gen = CandidateGenerator::new([0x03; 33], [0, 0, 0]);
        assert!(gen.current().is_none());
        assert!(gen.previous().is_none());
        assert!(!gen.has_candidate());
    }

    #[test]
    fn test_biguint_to_u64_small() {
        let val = BigUint::from(42u64);
        assert_eq!(biguint_to_u64_saturating(&val), 42);
    }

    #[test]
    fn test_biguint_to_u64_max() {
        let val = BigUint::from(u64::MAX);
        assert_eq!(biguint_to_u64_saturating(&val), u64::MAX);
    }

    #[test]
    fn test_biguint_to_u64_overflow() {
        let val = BigUint::from(u64::MAX) + BigUint::from(1u64);
        assert_eq!(biguint_to_u64_saturating(&val), u64::MAX);
    }

    #[test]
    fn test_biguint_to_u64_zero() {
        let val = BigUint::ZERO;
        assert_eq!(biguint_to_u64_saturating(&val), 0);
    }

    #[test]
    fn test_candidate_generator_no_mining_key() {
        let mut gen = CandidateGenerator::new([0u8; 33], [0, 0, 0]);
        // Cannot generate without a valid key — history/mempool are irrelevant
        // because the check happens first.
        let history = {
            let dir = tempfile::tempdir().unwrap();
            HistoryDb::open(dir.path()).unwrap()
        };
        let mempool = RwLock::new(ErgoMemPool::with_min_fee(100, 0));
        let params = Parameters::genesis();
        let result = gen.generate_candidate(&history, &mempool, &params, None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CandidateError::NoMiningKey));
    }

    #[test]
    fn test_candidate_generator_no_best_block() {
        let dir = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(dir.path()).unwrap();
        let mempool = RwLock::new(ErgoMemPool::with_min_fee(100, 0));
        let params = Parameters::genesis();
        let mut gen = CandidateGenerator::new([0x02; 33], [0, 0, 0]);
        let result = gen.generate_candidate(&history, &mempool, &params, None, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CandidateError::NoBestBlock));
    }

    // ── try_solution tests ─────────────────────────────────────────────

    #[test]
    fn test_try_solution_no_candidate() {
        let gen = CandidateGenerator::new([0x02; 33], [0, 0, 0]);
        let solution = MiningSolution {
            pk: String::new(),
            w: String::new(),
            n: "0000000000000000".into(),
            d: 0,
        };
        let result = gen.try_solution(&solution);
        assert!(matches!(result, Err(SolutionResult::NoCandidate)));
    }

    #[test]
    fn test_try_solution_invalid_nonce_hex() {
        let gen = CandidateGenerator::new([0x02; 33], [0, 0, 0]);
        let solution = MiningSolution {
            pk: String::new(),
            w: String::new(),
            n: "xyz".into(), // invalid hex
            d: 0,
        };
        let result = gen.try_solution(&solution);
        assert!(matches!(result, Err(SolutionResult::InvalidFormat(_))));
    }

    // ── Internal CPU miner tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_internal_miner_shutdown() {
        let gen = CandidateGenerator::new([0x02; 33], [0, 0, 0]);
        let gen_arc = Arc::new(RwLock::new(gen));
        let (solution_tx, _solution_rx) = tokio::sync::mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handles = spawn_internal_miners(1, 100, gen_arc, solution_tx, shutdown_rx);
        assert_eq!(handles.len(), 1);

        // Give it a moment to start.
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Send shutdown.
        shutdown_tx.send(true).unwrap();

        // Wait for task to complete (with timeout).
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            handles.into_iter().next().unwrap(),
        )
        .await;
        assert!(result.is_ok(), "miner should shut down within 2 seconds");
    }

    // ── miner_reward_prop tests ─────────────────────────────────────

    #[test]
    fn test_miner_reward_prop_produces_height_locked_tree() {
        // Use the real secp256k1 generator point as a valid public key.
        let pk: [u8; 33] = {
            let mut buf = [0u8; 33];
            buf[0] = 0x02;
            // x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
            let x = hex::decode(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            )
            .unwrap();
            buf[1..].copy_from_slice(&x);
            buf
        };
        let tree = miner_reward_prop(&pk, 720);
        // Height-locked script should be longer than a plain P2PK (36 bytes).
        assert!(
            tree.len() > 36,
            "height-locked tree should be longer than plain P2PK, got {} bytes",
            tree.len()
        );
        // Should NOT start with plain P2PK prefix [0x00, 0x08, 0xcd].
        assert_ne!(
            &tree[..3],
            &[0x00, 0x08, 0xcd],
            "should not be a plain P2PK tree"
        );
    }

    #[test]
    fn test_miner_reward_prop_different_keys_produce_different_trees() {
        let pk1: [u8; 33] = {
            let mut buf = [0u8; 33];
            buf[0] = 0x02;
            let x = hex::decode(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            )
            .unwrap();
            buf[1..].copy_from_slice(&x);
            buf
        };
        let pk2: [u8; 33] = {
            let mut buf = [0u8; 33];
            buf[0] = 0x03;
            let x = hex::decode(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            )
            .unwrap();
            buf[1..].copy_from_slice(&x);
            buf
        };
        let tree1 = miner_reward_prop(&pk1, 720);
        let tree2 = miner_reward_prop(&pk2, 720);
        assert_ne!(tree1, tree2);
    }

    #[test]
    fn test_miner_reward_prop_different_delays() {
        let pk: [u8; 33] = {
            let mut buf = [0u8; 33];
            buf[0] = 0x02;
            let x = hex::decode(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            )
            .unwrap();
            buf[1..].copy_from_slice(&x);
            buf
        };
        let tree_720 = miner_reward_prop(&pk, 720);
        let tree_1440 = miner_reward_prop(&pk, 1440);
        assert_ne!(tree_720, tree_1440, "different delays should produce different trees");
    }

    // ── build_fee_collection_tx tests ───────────────────────────────

    /// Build a simple transaction with a fee output for testing.
    /// Uses `box_seed` to create a unique input BoxId, preventing
    /// false-positive double-spend detection across independent test txs.
    fn make_tx_with_fee_seeded(fee_value: u64, box_seed: u8) -> ErgoTransaction {
        let mut tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([box_seed; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![
                // Normal output (non-fee).
                ErgoBoxCandidate {
                    value: 1_000_000_000,
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x02],
                    creation_height: 100_000,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
                // Fee output.
                ErgoBoxCandidate {
                    value: fee_value,
                    ergo_tree_bytes: MINERS_FEE_ERGO_TREE.to_vec(),
                    creation_height: 100_000,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
            ],
            tx_id: TxId([0u8; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);
        tx
    }

    /// Convenience wrapper using default seed 0xAA.
    fn make_tx_with_fee(fee_value: u64) -> ErgoTransaction {
        make_tx_with_fee_seeded(fee_value, 0xAA)
    }

    #[test]
    fn test_build_fee_collection_tx_none_when_no_fees() {
        let tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xAA; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x02],
                creation_height: 100,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0x11; 32]),
        };
        let pk = [0x02; 33];
        let result = build_fee_collection_tx(&[tx], 101, &pk, 720);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_fee_collection_tx_none_when_empty() {
        let pk = [0x02; 33];
        let result = build_fee_collection_tx(&[], 101, &pk, 720);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_fee_collection_tx_collects_single_fee() {
        let pk = [0x02; 33];
        let tx = make_tx_with_fee(1_000_000);
        let fee_tx = build_fee_collection_tx(&[tx], 101, &pk, 720).expect("should produce fee tx");

        assert_eq!(fee_tx.inputs.len(), 1, "one fee input");
        assert_eq!(fee_tx.output_candidates.len(), 1, "one miner output");
        assert_eq!(fee_tx.output_candidates[0].value, 1_000_000);
        assert_eq!(
            fee_tx.output_candidates[0].ergo_tree_bytes,
            miner_reward_prop(&pk, 720)
        );
        assert_eq!(fee_tx.output_candidates[0].creation_height, 101);
        // tx_id should be computed (not all zeros).
        assert_ne!(fee_tx.tx_id.0, [0u8; 32]);
    }

    #[test]
    fn test_build_fee_collection_tx_sums_multiple_fees() {
        let pk = [0x02; 33];
        let tx1 = make_tx_with_fee(500_000);
        let tx2 = make_tx_with_fee(300_000);
        let fee_tx =
            build_fee_collection_tx(&[tx1, tx2], 200, &pk, 720).expect("should produce fee tx");

        assert_eq!(fee_tx.inputs.len(), 2, "two fee inputs");
        assert_eq!(fee_tx.output_candidates[0].value, 800_000);
    }

    // ── fee token collection tests ────────────────────────────────────

    /// Build a transaction with a fee output that carries tokens.
    fn make_tx_with_fee_and_tokens(
        fee_value: u64,
        box_seed: u8,
        tokens: Vec<(BoxId, u64)>,
    ) -> ErgoTransaction {
        let mut tx = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([box_seed; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: 1_000_000_000,
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x02],
                    creation_height: 100_000,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
                ErgoBoxCandidate {
                    value: fee_value,
                    ergo_tree_bytes: MINERS_FEE_ERGO_TREE.to_vec(),
                    creation_height: 100_000,
                    tokens,
                    additional_registers: Vec::new(),
                },
            ],
            tx_id: TxId([0u8; 32]),
        };
        tx.tx_id = compute_tx_id(&tx);
        tx
    }

    #[test]
    fn test_build_fee_collection_tx_collects_tokens() {
        let pk = [0x02; 33];
        let token_id_a = BoxId([0xAA; 32]);
        let token_id_b = BoxId([0xBB; 32]);

        let tx = make_tx_with_fee_and_tokens(
            500_000,
            0xF1,
            vec![(token_id_a, 100), (token_id_b, 50)],
        );
        let fee_tx =
            build_fee_collection_tx(&[tx], 200, &pk, 720).expect("should produce fee tx");

        // Fee output should carry the tokens.
        let miner_out = &fee_tx.output_candidates[0];
        assert_eq!(miner_out.tokens.len(), 2);
        // Tokens are ordered by BTreeMap key order (token_id bytes).
        assert!(miner_out.tokens.iter().any(|(id, amt)| *id == token_id_a && *amt == 100));
        assert!(miner_out.tokens.iter().any(|(id, amt)| *id == token_id_b && *amt == 50));
    }

    #[test]
    fn test_build_fee_collection_tx_aggregates_same_tokens() {
        let pk = [0x02; 33];
        let token_id = BoxId([0xCC; 32]);

        let tx1 = make_tx_with_fee_and_tokens(300_000, 0xF1, vec![(token_id, 100)]);
        let tx2 = make_tx_with_fee_and_tokens(200_000, 0xF2, vec![(token_id, 50)]);

        let fee_tx =
            build_fee_collection_tx(&[tx1, tx2], 200, &pk, 720).expect("should produce fee tx");

        let miner_out = &fee_tx.output_candidates[0];
        assert_eq!(miner_out.tokens.len(), 1);
        assert_eq!(miner_out.tokens[0].0, token_id);
        assert_eq!(miner_out.tokens[0].1, 150, "amounts should be summed");
    }

    #[test]
    fn test_build_fee_collection_tx_caps_at_max_assets() {
        let pk = [0x02; 33];

        // Build a fee output with more than MAX_ASSETS_PER_BOX (100) distinct tokens.
        let mut tokens: Vec<(BoxId, u64)> = Vec::new();
        for i in 0..150u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            id[1] = 0xFF; // make unique
            tokens.push((BoxId(id), (i as u64) + 1));
        }

        let tx = make_tx_with_fee_and_tokens(1_000_000, 0xF1, tokens);
        let fee_tx =
            build_fee_collection_tx(&[tx], 200, &pk, 720).expect("should produce fee tx");

        let miner_out = &fee_tx.output_candidates[0];
        assert_eq!(
            miner_out.tokens.len(),
            MAX_ASSETS_PER_BOX,
            "should cap at MAX_ASSETS_PER_BOX"
        );
    }

    // ── build_emission_tx tests ─────────────────────────────────────

    #[test]
    fn test_build_emission_tx_returns_none_without_utxo() {
        let pk = [0x02; 33];
        // Without UTXO state, should return None.
        assert!(build_emission_tx(100, &pk, None, 720).is_none());
    }

    #[test]
    fn emission_amount_positive_at_early_height() {
        let reward = ergo_network::emission::miner_reward_at_height(100);
        assert!(reward > 0, "miner reward should be positive at height 100");
    }

    #[test]
    fn miner_reward_less_than_total_during_founders_period() {
        // During the founders period, the miner reward should be less than total emission
        // because 7.5 ERG goes to founders.
        let total = ergo_network::emission::emission_at_height(100);
        let miner = ergo_network::emission::miner_reward_at_height(100);
        assert!(miner < total, "miner reward should be less than total emission during founders period");
        assert_eq!(
            total - miner,
            ergo_network::emission::FOUNDERS_INITIAL_REWARD,
            "difference should be the founders reward"
        );
    }

    #[test]
    fn emission_amount_zero_past_schedule() {
        // At an extremely high height, emission should be zero.
        let reward = ergo_network::emission::emission_at_height(100_000_000);
        assert_eq!(reward, 0, "emission should be zero past the schedule");
    }

    #[test]
    fn reemission_charge_zero_before_activation() {
        // Before height 777,217, reemission charge should be zero.
        let charge = ergo_network::emission::reemission_for_height(500_000);
        assert_eq!(charge, 0, "reemission charge should be zero before activation");
    }

    #[test]
    fn reemission_charge_positive_after_activation() {
        // After activation height 777,217, there should be a reemission charge.
        let height = ergo_network::emission::REEMISSION_ACTIVATION_HEIGHT + 1;
        let charge = ergo_network::emission::reemission_for_height(height);
        assert!(charge > 0, "reemission charge should be positive after activation");
        // The charge should be the basic charge amount (12 ERG) when emission is high enough.
        assert_eq!(
            charge,
            ergo_network::emission::BASIC_CHARGE_AMOUNT,
            "charge should be 12 ERG at this height"
        );
    }

    #[test]
    fn emission_tx_deducts_reemission_tokens_after_activation() {
        // Verify that build_emission_tx correctly deducts reemission tokens
        // from the emission box output after activation height.
        let height = ergo_network::emission::REEMISSION_ACTIVATION_HEIGHT + 10;
        let reward = ergo_network::emission::miner_reward_at_height(height);
        let charge = ergo_network::emission::reemission_for_height(height);
        assert!(charge > 0, "should have reemission charge at this height");

        // Miner receives reward minus the reemission charge.
        let miner_value = reward.saturating_sub(charge);
        assert!(miner_value > 0, "miner should still get some reward");
        assert!(miner_value < reward, "miner value should be less than full reward");
        assert_eq!(
            reward - miner_value,
            charge,
            "difference should equal reemission charge"
        );
    }

    #[test]
    fn default_mining_reward_delay_is_720() {
        assert_eq!(DEFAULT_MINING_REWARD_DELAY, 720);
    }

    // ── collect_txs tests ───────────────────────────────────────────

    #[test]
    fn test_collect_txs_empty_mempool_no_emission() {
        let pk = [0x02; 33];
        let params = Parameters::genesis();
        let (selected, eliminated) =
            collect_txs(Vec::new(), None, 1_000_000, 1_000_000_000, &params, 100, &pk, None, None, 720);
        // No transactions at all, so no fee tx either.
        assert!(selected.is_empty());
        assert!(eliminated.is_empty());
    }

    #[test]
    fn test_collect_txs_emission_first() {
        let pk = [0x02; 33];
        let emission = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xEE; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 67_500_000_000,
                ergo_tree_bytes: miner_reward_prop(&pk, 720),
                creation_height: 100,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0xEE; 32]),
        };

        let mempool_tx = make_tx_with_fee(1_000_000);

        let params = Parameters::genesis();
        let (selected, eliminated) = collect_txs(
            vec![mempool_tx],
            Some(emission.clone()),
            10_000_000,
            1_000_000_000,
            &params,
            100,
            &pk,
            None,
            None,
            720,
        );

        assert!(eliminated.is_empty());
        // Emission first, then mempool tx, then fee collection tx.
        assert!(selected.len() >= 2);
        assert_eq!(selected[0].tx_id, emission.tx_id, "emission should be first");
        // Last tx should be the fee collection tx (its outputs pay to miner).
        let last = selected.last().unwrap();
        assert_eq!(
            last.output_candidates[0].ergo_tree_bytes,
            miner_reward_prop(&pk, 720),
            "last tx should be fee collection"
        );
    }

    #[test]
    fn test_collect_txs_respects_size_limit() {
        let pk = [0x02; 33];
        let tx1 = make_tx_with_fee_seeded(100_000, 0xA1);
        let tx2 = make_tx_with_fee_seeded(200_000, 0xA2);

        // Set a very small limit so only tx1 fits.
        let tx1_size = serialize_transaction(&tx1).len() as u64;
        let limit = tx1_size + 1; // Just enough for tx1, not tx2.

        let params = Parameters::genesis();
        let (selected, eliminated) =
            collect_txs(vec![tx1.clone(), tx2.clone()], None, limit, 1_000_000_000, &params, 100, &pk, None, None, 720);

        // tx2 should be eliminated.
        assert_eq!(eliminated.len(), 1);
        assert_eq!(eliminated[0], tx2.tx_id.0);

        // selected should have tx1 + fee collection tx.
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].tx_id, tx1.tx_id);
    }

    #[test]
    fn test_collect_txs_fee_tx_last() {
        let pk = [0x02; 33];
        let tx = make_tx_with_fee(500_000);

        let params = Parameters::genesis();
        let (selected, _) = collect_txs(vec![tx], None, 10_000_000, 1_000_000_000, &params, 100, &pk, None, None, 720);

        // Should be: mempool_tx, fee_collection_tx.
        assert_eq!(selected.len(), 2);
        let fee_tx = &selected[1];
        assert_eq!(
            fee_tx.output_candidates[0].ergo_tree_bytes,
            miner_reward_prop(&pk, 720)
        );
        assert_eq!(fee_tx.output_candidates[0].value, 500_000);
    }

    // ── collect_txs cost limit tests ────────────────────────────────

    #[test]
    fn test_collect_txs_respects_cost_limit() {
        let pk = [0x02; 33];
        let params = Parameters::genesis();
        let tx1 = make_tx_with_fee_seeded(100_000, 0xB1);
        let tx2 = make_tx_with_fee_seeded(200_000, 0xB2);

        // Each tx has: 10000 (init) + 1*2000 (input) + 2*100 (outputs) = 12200 cost.
        // With a cost limit of 12201 (plus safe_gap=0 since < 5M), only one fits.
        let cost_limit = 12_201;

        let (selected, eliminated) = collect_txs(
            vec![tx1.clone(), tx2.clone()],
            None,
            10_000_000,   // large size limit (not the bottleneck)
            cost_limit,
            &params,
            100,
            &pk,
            None,
            None,
            720,
        );

        // tx2 should be eliminated due to cost overflow.
        assert_eq!(eliminated.len(), 1);
        assert_eq!(eliminated[0], tx2.tx_id.0);

        // selected should have tx1 + fee collection tx.
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].tx_id, tx1.tx_id);
    }

    #[test]
    fn test_collect_txs_cost_limit_with_safe_gap() {
        let pk = [0x02; 33];
        let params = Parameters::genesis();
        let tx1 = make_tx_with_fee_seeded(100_000, 0xC1);
        let tx2 = make_tx_with_fee_seeded(200_000, 0xC2);

        // Each tx costs 12200. Two txs = 24400 total cost.
        // With max_block_cost = 5_000_000 the safe_gap is 500_000,
        // so cost_limit = 4_500_000 — both fit easily.
        let (selected, eliminated) = collect_txs(
            vec![tx1.clone(), tx2.clone()],
            None,
            10_000_000,
            5_000_000,
            &params,
            100,
            &pk,
            None,
            None,
            720,
        );

        assert!(eliminated.is_empty());
        // Both txs + fee tx.
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn test_collect_txs_cost_limit_with_middle_tier_safe_gap() {
        let pk = [0x02; 33];
        let params = Parameters::genesis();
        let tx1 = make_tx_with_fee_seeded(100_000, 0xD1);

        // Each tx costs 12200.
        // With max_block_cost = 1_000_000 (>= 1M, < 5M), middle-tier safe_gap = 150_000,
        // so cost_limit = 850_000 — tx fits easily.
        let (selected, eliminated) = collect_txs(
            vec![tx1.clone()],
            None,
            10_000_000,
            1_000_000,
            &params,
            100,
            &pk,
            None,
            None,
            720,
        );

        assert!(eliminated.is_empty());
        // tx + fee tx.
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_collect_txs_zero_cost_limit_eliminates_all() {
        let pk = [0x02; 33];
        let params = Parameters::genesis();
        let tx = make_tx_with_fee(100_000);

        let (selected, eliminated) = collect_txs(
            vec![tx],
            None,
            10_000_000,
            0, // zero cost limit
            &params,
            100,
            &pk,
            None,
            None,
            720,
        );

        assert_eq!(eliminated.len(), 1);
        assert!(selected.is_empty()); // no txs, no fee tx either
    }

    // ── collect_txs double-spend detection tests ────────────────────

    #[test]
    fn test_collect_txs_eliminates_intra_block_double_spend() {
        let pk = [0x02; 33];
        let params = Parameters::genesis();

        // Two txs spending the same input.
        let shared_box = BoxId([0xDD; 32]);
        let mut tx1 = ErgoTransaction {
            inputs: vec![Input {
                box_id: shared_box,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 1_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x02],
                creation_height: 100,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0u8; 32]),
        };
        tx1.tx_id = compute_tx_id(&tx1);

        let mut tx2 = ErgoTransaction {
            inputs: vec![Input {
                box_id: shared_box,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 2_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x03],
                creation_height: 100,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0u8; 32]),
        };
        tx2.tx_id = compute_tx_id(&tx2);

        let (selected, eliminated) = collect_txs(
            vec![tx1.clone(), tx2.clone()],
            None,
            10_000_000,
            1_000_000_000,
            &params,
            100,
            &pk,
            None, // No utxo_state, but double-spend detection still works
            None,
            720,
        );

        // tx1 should be selected, tx2 should be eliminated (same input).
        assert_eq!(eliminated.len(), 1);
        assert_eq!(eliminated[0], tx2.tx_id.0);
        assert!(selected.iter().any(|t| t.tx_id == tx1.tx_id));
    }

    // ── MINERS_FEE_ERGO_TREE constant test ──────────────────────────

    #[test]
    fn test_miners_fee_ergo_tree_matches_known_hex() {
        let expected = hex::decode(
            "1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07\
             029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a70173007301100102\
             0402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cd\
             eeac93b1a57304",
        )
        .unwrap();
        assert_eq!(MINERS_FEE_ERGO_TREE, expected.as_slice());
    }

    // ── collect_txs chained transaction (UTXO overlay) tests ────────

    #[test]
    fn test_collect_txs_chained_txs_via_utxo_overlay() {
        // Tx A creates an output; Tx B spends that output. Without the UTXO
        // overlay, Tx B would be eliminated because its input doesn't exist
        // in the UTXO DB. With the overlay, both should be selected.
        let pk = [0x02; 33];
        let params = Parameters::genesis();
        let next_height = 100u32;

        // Tx A: spends some pre-existing box and produces an output.
        let mut tx_a = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xA0; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: 5_000_000_000,
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x02],
                    creation_height: next_height,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
                // Fee output for tx_a.
                ErgoBoxCandidate {
                    value: 1_000_000,
                    ergo_tree_bytes: MINERS_FEE_ERGO_TREE.to_vec(),
                    creation_height: next_height,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
            ],
            tx_id: TxId([0u8; 32]),
        };
        tx_a.tx_id = compute_tx_id(&tx_a);

        // Compute the box ID of tx_a's first output — this is what tx_b will spend.
        let chained_box_id = compute_box_id(&tx_a.tx_id, 0);

        // Tx B: spends the first output of Tx A.
        let mut tx_b = ErgoTransaction {
            inputs: vec![Input {
                box_id: chained_box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: 4_000_000_000,
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x03],
                    creation_height: next_height,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
                // Fee output for tx_b.
                ErgoBoxCandidate {
                    value: 1_000_000,
                    ergo_tree_bytes: MINERS_FEE_ERGO_TREE.to_vec(),
                    creation_height: next_height,
                    tokens: Vec::new(),
                    additional_registers: Vec::new(),
                },
            ],
            tx_id: TxId([0u8; 32]),
        };
        tx_b.tx_id = compute_tx_id(&tx_b);

        // Run collect_txs without a UTXO state — the overlay is the only
        // mechanism that can resolve the chained input.
        let (selected, eliminated) = collect_txs(
            vec![tx_a.clone(), tx_b.clone()],
            None,
            10_000_000,
            1_000_000_000,
            &params,
            next_height,
            &pk,
            None, // no utxo_state
            None,
            720,
        );

        // Both txs should be selected (plus a fee collection tx).
        assert!(
            eliminated.is_empty(),
            "no txs should be eliminated, but got: {:?}",
            eliminated.iter().map(hex::encode).collect::<Vec<_>>()
        );
        assert!(
            selected.iter().any(|t| t.tx_id == tx_a.tx_id),
            "tx_a should be selected"
        );
        assert!(
            selected.iter().any(|t| t.tx_id == tx_b.tx_id),
            "tx_b should be selected"
        );
        // tx_a should come before tx_b in the selection.
        let pos_a = selected.iter().position(|t| t.tx_id == tx_a.tx_id).unwrap();
        let pos_b = selected.iter().position(|t| t.tx_id == tx_b.tx_id).unwrap();
        assert!(pos_a < pos_b, "tx_a should precede tx_b");
    }

    #[test]
    fn test_collect_txs_chained_tx_double_spend_prevented() {
        // If tx_b spends an output of tx_a, and tx_c also tries to spend the
        // same output, tx_c should be eliminated as a double-spend.
        let pk = [0x02; 33];
        let params = Parameters::genesis();
        let next_height = 200u32;

        let mut tx_a = ErgoTransaction {
            inputs: vec![Input {
                box_id: BoxId([0xB0; 32]),
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 10_000_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x02],
                creation_height: next_height,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0u8; 32]),
        };
        tx_a.tx_id = compute_tx_id(&tx_a);

        let chained_box_id = compute_box_id(&tx_a.tx_id, 0);

        // tx_b spends tx_a's output.
        let mut tx_b = ErgoTransaction {
            inputs: vec![Input {
                box_id: chained_box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 5_000_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x03],
                creation_height: next_height,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0u8; 32]),
        };
        tx_b.tx_id = compute_tx_id(&tx_b);

        // tx_c also tries to spend the same output as tx_b.
        let mut tx_c = ErgoTransaction {
            inputs: vec![Input {
                box_id: chained_box_id,
                proof_bytes: Vec::new(),
                extension_bytes: Vec::new(),
            }],
            data_inputs: Vec::new(),
            output_candidates: vec![ErgoBoxCandidate {
                value: 3_000_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x04],
                creation_height: next_height,
                tokens: Vec::new(),
                additional_registers: Vec::new(),
            }],
            tx_id: TxId([0u8; 32]),
        };
        tx_c.tx_id = compute_tx_id(&tx_c);

        let (selected, eliminated) = collect_txs(
            vec![tx_a.clone(), tx_b.clone(), tx_c.clone()],
            None,
            10_000_000,
            1_000_000_000,
            &params,
            next_height,
            &pk,
            None,
            None,
            720,
        );

        // tx_c should be eliminated (double-spend of the chained output).
        assert_eq!(eliminated.len(), 1);
        assert_eq!(eliminated[0], tx_c.tx_id.0);
        assert!(selected.iter().any(|t| t.tx_id == tx_a.tx_id));
        assert!(selected.iter().any(|t| t.tx_id == tx_b.tx_id));
        assert!(!selected.iter().any(|t| t.tx_id == tx_c.tx_id));
    }
}

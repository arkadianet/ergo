pub mod ge;
pub mod heights;
pub mod monetary;
pub mod reemission;
pub(crate) mod script;
pub mod structural;

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::{bytes_to_sign, read_transaction, write_transaction, Transaction};

use ergo_primitives::cost::JitCost;

use crate::context::{LocalPolicy, ProtocolParams, TransactionContext, UtxoView};
use crate::cost::CostAccumulator;
use crate::error::ValidationError;

/// Bundle of per-tx validation borrows threaded through
/// [`validate_transaction`], [`validate_transaction_parsed`], and the
/// internal [`script::validate_scripts`]. Replaces the four-positional-
/// arg pattern (ctx, params, cost, last_headers) that the script and
/// composable-parsed entry points used to require.
///
/// Construction is at the validation boundary (block apply, mempool
/// admission, oracle test harness) and the bundle is consumed by a
/// single tx-validation call. `cost` is a mutable borrow because the
/// accumulator must thread across all evaluator opcodes; the other
/// fields are shared immutable refs.
pub struct TxValidationCtx<'a> {
    /// Per-tx context: height, miner_pubkey, pre-header fields. The
    /// same `TransactionContext` is shared across all txs in a block.
    pub ctx: &'a TransactionContext,
    /// Mainnet protocol parameters at the validating height.
    pub params: &'a ProtocolParams,
    /// JIT cost accumulator. Mutated by every opcode that charges cost.
    pub cost: &'a mut CostAccumulator,
    /// Last 10 block headers for evaluator `CONTEXT.headers`.
    pub last_headers: &'a [ergo_ser::header::Header],
}

/// A transaction that has passed all validation checks.
///
/// Fields are private — construction only through `validate_transaction()`
/// or `validate_transaction_parsed()`. This makes it unforgeable from
/// outside ergo-validation, so downstream crates can trust it as a
/// validated artifact.
///
/// `tx_id` is computed internally during validation (blake2b256 of
/// bytes_to_sign). It is NOT accepted as a parameter from callers.
/// State apply uses `checked.tx_id()` to avoid recomputing it.
#[derive(Debug)]
pub struct CheckedTransaction {
    transaction: Transaction,
    resolved_inputs: Vec<ErgoBox>,
    resolved_data_inputs: Vec<ErgoBox>,
    tx_id: [u8; 32],
}

impl CheckedTransaction {
    /// Borrow the validated [`Transaction`].
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
    /// Borrow the resolved input boxes (one per `transaction.inputs`,
    /// in declaration order).
    pub fn resolved_inputs(&self) -> &[ErgoBox] {
        &self.resolved_inputs
    }
    /// Borrow the resolved data-input boxes (one per
    /// `transaction.data_inputs`, in declaration order).
    pub fn resolved_data_inputs(&self) -> &[ErgoBox] {
        &self.resolved_data_inputs
    }
    /// 32-byte transaction id (`Blake2b256(bytes_to_sign(tx))`),
    /// computed once during validation and reused by state apply.
    pub fn tx_id(&self) -> &[u8; 32] {
        &self.tx_id
    }
}

/// Full validation pipeline from raw bytes.
///
/// Stages (cheapest first, matching spec Section 1):
/// 0. Local policy size check (not consensus)
/// 1. Deserialize (reject malformed bytes)
/// 2. Structural validation (stateless — size limits, no duplicates)
/// 3. Canonical encoding (re-serialize and compare — consensus-critical)
/// 4. Resolve inputs from UTXO set
/// 5. Monetary validation (ERG + token conservation)
/// 6. Script validation (per-input ErgoTree eval + proof verify)
pub fn validate_transaction(
    tx_bytes: &[u8],
    utxo: &dyn UtxoView,
    policy: &LocalPolicy,
    cx: &mut TxValidationCtx<'_>,
) -> Result<CheckedTransaction, ValidationError> {
    // Stage 0: local policy size check (not consensus)
    if tx_bytes.len() > policy.max_transaction_size {
        return Err(ValidationError::Deserialization(format!(
            "transaction size {} exceeds local policy limit {}",
            tx_bytes.len(),
            policy.max_transaction_size,
        )));
    }

    // Stage 1: deserialize (also collects every group element seen on the wire)
    let (tx, group_elements) = deserialize_transaction(tx_bytes)?;

    // Stage 1.5: every group element must be on-curve. Scala rejects an off-curve
    // / bad-prefix point while deserializing the transaction; the node's
    // deserialize is crypto-free, so we curve-check the collected points here
    // (earliest stateless stage) to match that deserialize-time rejection.
    ge::validate_group_elements(&group_elements)?;

    // Stage 2: structural (stateless — cheaper than canonical re-serialization)
    structural::validate_structural(&tx, cx.params)?;

    // Stage 3: canonical encoding check
    check_canonical(&tx, tx_bytes)?;

    // Stage 4: resolve inputs
    let resolved_inputs = resolve_inputs(&tx, utxo)?;
    let resolved_data_inputs = resolve_data_inputs(&tx, utxo)?;

    // Stage 4.5: per-output height constraints (Scala rules 112 + 124).
    // Runs after structural so we know we have outputs to walk, and
    // before monetary because a future-output rejection should
    // surface even on otherwise-conserved txs. Rule 124 is soft-fork-
    // gated to `block_version >= 3`; v1/v2 blocks treat it as a no-op.
    //
    // Order vs monetary mirrors Scala
    // (`ergo-core/.../mempool/ErgoTransaction.scala:424-433`): the
    // `validateSeq(outputs) { verifyOutput }` call (firing rules
    // 111, 112, 124, 120, 121 per output) runs BEFORE
    // `txInputsSum` (115) → `txErgPreservation` (116) →
    // `verifyAssets` (117). Our stage 4.5 → stage 5 matches that
    // relative position: on a multi-violation tx where both rule 124
    // and rule 116/117 would fire, Scala surfaces rule 124 first and
    // so do we.
    // Rule 108 (txPositiveAssets) — Scala fires this in validateStateful
    // before the per-output verifyOutput loop (112/124); it is stateless
    // (output token amounts only), so it runs here, ahead of the height loop.
    monetary::check_positive_assets(&tx)?;
    heights::validate_output_heights(&tx, cx.ctx)?;
    heights::validate_monotonic_heights(&tx, &resolved_inputs, cx.ctx.pre_header_version)?;

    // Stage 5: monetary
    monetary::validate_monetary(&tx, &resolved_inputs)?;

    // Stage 5.5: transaction init cost
    let init_cost = script::compute_tx_init_cost(&tx, &resolved_inputs, cx.params);
    let init_jit = JitCost::from_block_cost(init_cost)
        .map_err(|e| ValidationError::JitCostOverflow(e.to_string()))?;
    cx.cost.add(init_jit).map_err(|e| match e {
        ergo_primitives::cost::CostError::LimitExceeded { current, limit } => {
            ValidationError::CostExceeded { current, limit }
        }
        ergo_primitives::cost::CostError::Overflow(je) => {
            ValidationError::JitCostOverflow(je.to_string())
        }
    })?;

    // Compute bytes_to_sign + tx_id once. Passed to validate_scripts to avoid
    // recomputation there. tx_id is stored on CheckedTransaction for state apply.
    let message = bytes_to_sign(&tx)
        .map_err(|e| ValidationError::Deserialization(format!("bytes_to_sign: {e}")))?;
    let tx_id = *blake2b256(&message).as_bytes();

    // Stage 6: script (receives precomputed message)
    script::validate_scripts(&tx, &resolved_inputs, &resolved_data_inputs, &message, cx)?;

    Ok(CheckedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_data_inputs,
        tx_id,
    })
}

/// Composable validation for callers that already have parsed Transaction
/// and resolved inputs (e.g. block validation with batch UTXO resolution).
///
/// Defensively verifies that `resolved_inputs` match the transaction's
/// input box IDs and lengths. This prevents constructing a CheckedTransaction
/// from mismatched state.
pub fn validate_transaction_parsed(
    tx: Transaction,
    original_bytes: &[u8],
    resolved_inputs: Vec<ErgoBox>,
    resolved_data_inputs: Vec<ErgoBox>,
    skip_scripts: bool,
    cx: &mut TxValidationCtx<'_>,
) -> Result<CheckedTransaction, ValidationError> {
    // Callers without pre-collected group elements (single-tx validation, the
    // sequential block path, tests): re-collect the points from `original_bytes`
    // and delegate. The production block validator uses the variant below to
    // skip this re-parse — it already collected the points at the one
    // authoritative deserialize.
    let group_elements = {
        let mut r = VlqReader::new(original_bytes);
        read_transaction(&mut r).map_err(|e| ValidationError::Deserialization(e.to_string()))?;
        r.take_group_elements()
    };
    validate_transaction_parsed_with_group_elements(
        tx,
        original_bytes,
        &group_elements,
        resolved_inputs,
        resolved_data_inputs,
        skip_scripts,
        cx,
    )
}

/// Same as [`validate_transaction_parsed`], but the caller supplies this
/// transaction's group-element points instead of having the function re-parse
/// `original_bytes` to re-collect them.
///
/// `group_elements` MUST be exactly this `tx`'s points. The block validator
/// guarantees that by collecting them in the same deserialize that produced
/// `tx` (index-aligned), so a tx cannot dodge the on-curve check via mismatched
/// points. The on-curve rule is otherwise identical — Scala curve-checks group
/// elements at deserialize.
pub fn validate_transaction_parsed_with_group_elements(
    tx: Transaction,
    original_bytes: &[u8],
    group_elements: &[[u8; 33]],
    resolved_inputs: Vec<ErgoBox>,
    resolved_data_inputs: Vec<ErgoBox>,
    skip_scripts: bool,
    cx: &mut TxValidationCtx<'_>,
) -> Result<CheckedTransaction, ValidationError> {
    // Verify resolved inputs match transaction
    verify_resolved_inputs_match(&tx, &resolved_inputs)?;
    verify_resolved_data_inputs_match(&tx, &resolved_data_inputs)?;

    // Canonical check against original bytes
    check_canonical(&tx, original_bytes)?;

    // Structural
    structural::validate_structural(&tx, cx.params)?;

    // Group elements on-curve (Scala curve-checks them at deserialize).
    ge::validate_group_elements(group_elements)?;

    // Rule 108 (txPositiveAssets) — before the per-output 112/124 loop.
    monetary::check_positive_assets(&tx)?;
    // Per-output height constraints (Scala rules 112 + 124)
    heights::validate_output_heights(&tx, cx.ctx)?;
    heights::validate_monotonic_heights(&tx, &resolved_inputs, cx.ctx.pre_header_version)?;

    // Monetary
    monetary::validate_monetary(&tx, &resolved_inputs)?;

    // Compute bytes_to_sign + tx_id once. Always needed (tx_id is stored
    // on CheckedTransaction for state apply, regardless of script
    // skipping). Below the checkpoint we still derive tx_id the same way
    // so AVL/UTXO mutations land at identical box_ids — the per-block
    // state-root verification depends on it.
    let message = bytes_to_sign(&tx)
        .map_err(|e| ValidationError::Deserialization(format!("bytes_to_sign: {e}")))?;
    let tx_id = *blake2b256(&message).as_bytes();

    if !skip_scripts {
        // Transaction init cost — only meaningful when scripts run.
        // Skipping init_cost below the checkpoint matches Scala: cost
        // accounting is paired with script evaluation; both are off
        // when scripts are skipped.
        let init_cost = script::compute_tx_init_cost(&tx, &resolved_inputs, cx.params);
        let init_jit = JitCost::from_block_cost(init_cost)
            .map_err(|e| ValidationError::JitCostOverflow(e.to_string()))?;
        cx.cost.add(init_jit).map_err(|e| match e {
            ergo_primitives::cost::CostError::LimitExceeded { current, limit } => {
                ValidationError::CostExceeded { current, limit }
            }
            ergo_primitives::cost::CostError::Overflow(je) => {
                ValidationError::JitCostOverflow(je.to_string())
            }
        })?;

        script::validate_scripts(&tx, &resolved_inputs, &resolved_data_inputs, &message, cx)?;
    }

    Ok(CheckedTransaction {
        transaction: tx,
        resolved_inputs,
        resolved_data_inputs,
        tx_id,
    })
}

/// Returns the parsed transaction and every group element seen during the parse
/// (collected on the reader's sideband), so the caller can curve-check them —
/// matching Scala's deserialize-time `GroupElementSerializer.parse`.
fn deserialize_transaction(
    tx_bytes: &[u8],
) -> Result<(Transaction, Vec<[u8; 33]>), ValidationError> {
    let mut r = VlqReader::new(tx_bytes);
    let tx =
        read_transaction(&mut r).map_err(|e| ValidationError::Deserialization(e.to_string()))?;
    if !r.is_empty() {
        return Err(ValidationError::Deserialization(format!(
            "{} trailing bytes after transaction",
            r.remaining(),
        )));
    }
    Ok((tx, r.take_group_elements()))
}

fn check_canonical(tx: &Transaction, expected_bytes: &[u8]) -> Result<(), ValidationError> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, tx).map_err(|e| ValidationError::Deserialization(e.to_string()))?;
    if w.result() != expected_bytes {
        return Err(ValidationError::NonCanonical);
    }
    Ok(())
}

fn resolve_inputs(tx: &Transaction, utxo: &dyn UtxoView) -> Result<Vec<ErgoBox>, ValidationError> {
    tx.inputs
        .iter()
        .map(|input| {
            utxo.get_box(&input.box_id)
                .ok_or_else(|| ValidationError::InputBoxNotFound {
                    box_id: hex::encode(input.box_id.as_bytes()),
                })
        })
        .collect()
}

fn resolve_data_inputs(
    tx: &Transaction,
    utxo: &dyn UtxoView,
) -> Result<Vec<ErgoBox>, ValidationError> {
    tx.data_inputs
        .iter()
        .map(|di| {
            utxo.get_box(&di.box_id)
                .ok_or_else(|| ValidationError::DataInputBoxNotFound {
                    box_id: hex::encode(di.box_id.as_bytes()),
                })
        })
        .collect()
}

fn verify_resolved_inputs_match(
    tx: &Transaction,
    resolved: &[ErgoBox],
) -> Result<(), ValidationError> {
    if tx.inputs.len() != resolved.len() {
        return Err(ValidationError::ResolvedInputsMismatch {
            expected: tx.inputs.len(),
            got: resolved.len(),
        });
    }
    for (i, (input, b)) in tx.inputs.iter().zip(resolved).enumerate() {
        let box_id = b.box_id().map_err(|e| ValidationError::ScriptError {
            index: i,
            reason: format!("box_id computation failed: {e}"),
        })?;
        if input.box_id != box_id {
            return Err(ValidationError::ResolvedInputIdMismatch {
                index: i,
                expected: hex::encode(input.box_id.as_bytes()),
            });
        }
    }
    Ok(())
}

fn verify_resolved_data_inputs_match(
    tx: &Transaction,
    resolved: &[ErgoBox],
) -> Result<(), ValidationError> {
    if tx.data_inputs.len() != resolved.len() {
        return Err(ValidationError::ResolvedDataInputsMismatch {
            expected: tx.data_inputs.len(),
            got: resolved.len(),
        });
    }
    for (i, (di, b)) in tx.data_inputs.iter().zip(resolved).enumerate() {
        let box_id = b.box_id().map_err(|e| ValidationError::ScriptError {
            index: i,
            reason: format!("box_id computation failed: {e}"),
        })?;
        if di.box_id != box_id {
            return Err(ValidationError::ResolvedDataInputIdMismatch {
                index: i,
                expected: hex::encode(di.box_id.as_bytes()),
            });
        }
    }
    Ok(())
}

//! Script validation: ErgoTree evaluation + spending proof verification.
//!
//! ## JIT cost model
//!
//! Per-opcode cost accumulation matching Scala's sigmastate-interpreter JIT model.
//! Transaction init cost (interpreterInitCost + per-input/output/data-input +
//! tokenAccessCost) is computed here and added to the caller's CostAccumulator.
//! Per-opcode and crypto verification costs are accumulated inside the evaluator.
//!
//! ## Interpreter coverage
//!
//! Covers every opcode observed on mainnet by the validator's recent-block
//! corpus (heights 1.76M+), including GetVar (0xE3), DeserializeContext
//! (0xD4), FuncValue/FuncApply, and collection lambdas (Fold, Map, Filter,
//! ForAll, Exists). Authoritative coverage signal lives in
//! `tests/recent_block_validation.rs` rather than this comment.
//!
//! - [`cost`] — the JIT init-cost formula (`compute_tx_init_cost*`) and its
//!   token-counting helpers.
//! - [`storage_rent_check`] — the storage-rent eligibility predicate and
//!   `checkExpiredBox` port. Named `storage_rent_check.rs`, not
//!   `storage_rent.rs`, since the crate already has a top-level
//!   `src/storage_rent.rs` for the (different) fee-computation concern.
//! - [`eval_box`] — `ErgoBox`/`ErgoBoxCandidate` → evaluator `EvalBox`
//!   conversion.
//!
//! [`validate_scripts`]'s per-input loop body stays as one function
//! deliberately: it mirrors Scala's `ErgoInterpreter.verify` fallback
//! structure (storage-rent short-circuit, then normal script
//! verification) end to end.

mod cost;
mod eval_box;
mod storage_rent_check;

pub use cost::{compute_tx_init_cost, compute_tx_init_cost_with_costs, INTERPRETER_INIT_COST};

// Re-exported at the exact path the lib.rs `test_helpers` shim already
// calls (`crate::tx::script::ergo_box_to_eval_box` /
// `crate::tx::script::candidate_to_eval_box`), so moving these functions
// out to eval_box.rs doesn't require touching that call site.
pub(crate) use eval_box::{candidate_to_eval_box, ergo_box_to_eval_box};

use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::transaction::Transaction;
use ergo_sigma::evaluator::{EvalBox, EvalError, EvalHeader, ReductionContext};
use ergo_sigma::reduce::{verify_spending_proof_with_context_and_cost, VerifySpendingError};

use crate::error::ValidationError;
use crate::tx::TxValidationCtx;
use storage_rent_check::{
    check_storage_rent, is_storage_rent_eligible, STORAGE_CONTRACT_COST, STORAGE_INDEX_VAR_ID,
};

/// Map a `VerifySpendingError` from the script evaluator onto the
/// validation envelope, preserving JitCost arithmetic overflow as a
/// distinct category (`ValidationError::JitCostOverflow`) so it does
/// not get hidden inside the generic `ScriptError` bucket.
///
/// `EvalError::CostExceeded` (the honest cost-limit-hit path) still
/// surfaces as `ScriptError`, matching the pre-existing classifier.
/// Only `EvalError::JitCostOverflow` — the typed surfacing of a
/// `JitCostError` from `ergo_primitives::cost` — gets the structured
/// route. See `EvalError::JitCostOverflow` doc for the unreachability
/// argument from honest mainnet input.
pub(crate) fn classify_verify_error(
    err: VerifySpendingError,
    input_index: usize,
) -> ValidationError {
    match err {
        VerifySpendingError::Eval(EvalError::JitCostOverflow(je)) => {
            ValidationError::JitCostOverflow(je.to_string())
        }
        other => ValidationError::ScriptError {
            index: input_index,
            reason: other.to_string(),
        },
    }
}

/// Run script validation across every input of `tx`. Each input's
/// `ErgoTree` is reduced (with full evaluator access to the supplied
/// context, last headers, and resolved boxes), then the per-input
/// spending proof is verified against `message` (= `bytes_to_sign(tx)`).
/// Per-opcode and crypto verification costs accumulate into `cost`;
/// the caller is responsible for the transaction-init cost.
///
pub fn validate_scripts(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
    resolved_data_inputs: &[ErgoBox],
    message: &[u8],
    cx: &mut TxValidationCtx<'_>,
) -> Result<(), ValidationError> {
    let eval_headers: Vec<EvalHeader> = cx
        .last_headers
        .iter()
        .map(|h| {
            let (_, hid) = ergo_ser::header::serialize_header(h).map_err(|e| {
                ValidationError::Deserialization(format!("last_headers serialize: {e}"))
            })?;
            Ok(EvalHeader::from_header(h, *hid.as_bytes()))
        })
        .collect::<Result<Vec<_>, ValidationError>>()?;

    let tx_id = ModifierId::from_bytes(*blake2b256(message).as_bytes());

    let eval_inputs: Vec<EvalBox> = resolved_inputs
        .iter()
        .enumerate()
        .map(|(i, b)| ergo_box_to_eval_box(b, i))
        .collect::<Result<_, _>>()?;

    let eval_outputs: Vec<EvalBox> = tx
        .output_candidates
        .iter()
        .enumerate()
        .map(|(i, c)| candidate_to_eval_box(c, &tx_id, i as u16))
        .collect::<Result<_, _>>()?;

    let eval_data_inputs: Vec<EvalBox> = resolved_data_inputs
        .iter()
        .enumerate()
        .map(|(i, b)| ergo_box_to_eval_box(b, i))
        .collect::<Result<_, _>>()?;

    // Per-input extensions, indexed by input position. Built once
    // before the per-input loop so each input's eval can resolve
    // `CONTEXT.getVarFromInput[T](otherIndex, varId)` without
    // reaching back into `tx.inputs`. Empty BTreeMap for an input
    // whose spending proof has no extension entries.
    let input_extensions: Vec<
        indexmap::IndexMap<
            u8,
            (
                ergo_ser::sigma_type::SigmaType,
                ergo_ser::sigma_value::SigmaValue,
            ),
        >,
    > = tx
        .inputs
        .iter()
        .map(|i| i.spending_proof.extension().values.clone())
        .collect();
    for (i, (input, resolved)) in tx.inputs.iter().zip(resolved_inputs).enumerate() {
        // Storage rent path: if the box is old enough, proof is empty,
        // and context extension contains the output index variable,
        // check storage rent rules instead of script verification.
        // Matches Scala ErgoInterpreter.verify() fallback logic.
        let box_age = cx
            .ctx
            .height
            .saturating_sub(resolved.candidate.creation_height);
        let proof_empty = input.spending_proof.proof.is_empty();
        let has_storage_var = input
            .spending_proof
            .extension()
            .values
            .contains_key(&STORAGE_INDEX_VAR_ID);

        if is_storage_rent_eligible(
            box_age,
            cx.params.storage_period,
            proof_empty,
            has_storage_var,
        ) {
            let rent_ok = check_storage_rent(
                resolved,
                input.spending_proof.extension(),
                tx,
                cx.ctx.height,
                cx.params,
            );
            if rent_ok {
                // Storage rent check passed — skip script/proof verification.
                // Charge the fixed storage contract cost.
                cx.cost
                    .add(ergo_primitives::cost::JitCost::from_jit(
                        STORAGE_CONTRACT_COST,
                    ))
                    .map_err(|e| match e {
                        ergo_primitives::cost::CostError::LimitExceeded { current, limit } => {
                            ValidationError::CostExceeded { current, limit }
                        }
                        ergo_primitives::cost::CostError::Overflow(je) => {
                            ValidationError::JitCostOverflow(je.to_string())
                        }
                    })?;
                continue;
            }
            // Storage rent check failed — fall through to normal verification.
            // Scala does: `.recoverWith { case _ => super.verify(...) }`
        }

        // Mainnet populates LastBlockUtxoRootHash from the previous state
        // digest via ErgoInterpreter.avlTreeFromDigest — digest from the
        // parent header (eval_headers[0]), AllOperationsAllowed flags,
        // keyLength = 32, no value-length constraint. See
        // ergo-master/ergo-wallet/…/ErgoInterpreter.scala:103.
        let last_block_utxo_root =
            eval_headers
                .first()
                .map(|h| ergo_ser::sigma_value::AvlTreeData {
                    digest: h.state_root.to_vec(),
                    insert_allowed: true,
                    update_allowed: true,
                    remove_allowed: true,
                    key_length: 32,
                    value_length_opt: None,
                });
        let ergo_tree = resolved.candidate.ergo_tree();

        let reduction_ctx = ReductionContext {
            height: cx.ctx.height,
            self_box: Some(&eval_inputs[i]),
            self_creation_height: resolved.candidate.creation_height,
            outputs: &eval_outputs,
            inputs: &eval_inputs,
            data_inputs: &eval_data_inputs,
            miner_pubkey: cx.ctx.miner_pubkey,
            pre_header_timestamp: cx.ctx.pre_header_timestamp,
            pre_header_version: cx.ctx.pre_header_version,
            pre_header_parent_id: cx.ctx.pre_header_parent_id,
            pre_header_n_bits: cx.ctx.pre_header_n_bits,
            pre_header_votes: cx.ctx.pre_header_votes,
            extension: input.spending_proof.extension().values.clone(),
            input_extensions: &input_extensions,
            last_headers: &eval_headers,
            last_block_utxo_root,
            activated_script_version: cx.ctx.activated_script_version,
            // ErgoTree HEADER version (low 3 bits of the tree's header byte),
            // distinct from activatedScriptVersion. Scala keys
            // isV3OrLaterErgoTreeVersion on this for the v6 SHeader data
            // serialization gate.
            ergo_tree_version: ergo_tree.version,
        };

        let verified = verify_spending_proof_with_context_and_cost(
            ergo_tree,
            &input.spending_proof.proof,
            message,
            &reduction_ctx,
            cx.cost,
        )
        .map_err(|e| classify_verify_error(e, i))?;

        if !verified {
            return Err(ValidationError::ProofFailed { index: i });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::cost::JitCostError;

    // ----- helpers -----

    fn jit_overflow() -> JitCostError {
        JitCostError::Overflow {
            operation: "checked_add",
            value: i32::MAX as u64 + 1,
        }
    }

    // ----- error paths -----

    #[test]
    fn jit_cost_overflow_inside_eval_routes_to_typed_validation_variant() {
        // The load-bearing claim of the typed-error pass: a JitCost
        // arithmetic overflow that surfaces from the evaluator must
        // land in `ValidationError::JitCostOverflow`, NOT in the
        // generic `ScriptError` bucket. Pre-pass the boundary
        // collapsed both into ScriptError, hiding overflow under
        // script-failure telemetry.
        let je = jit_overflow();
        let envelope = VerifySpendingError::Eval(EvalError::JitCostOverflow(je));
        match classify_verify_error(envelope, 7) {
            ValidationError::JitCostOverflow(reason) => {
                assert!(
                    reason.contains("checked_add"),
                    "expected the typed JitCostError detail to survive the boundary, got {reason}"
                );
            }
            other => panic!("JitCost overflow must surface as JitCostOverflow, got {other:?}"),
        }
    }

    #[test]
    fn ordinary_cost_exceeded_inside_eval_still_routes_to_script_error() {
        // Negative-space pin: only JitCost overflow gets the typed
        // route; the honest "cost limit hit" case keeps the existing
        // ScriptError envelope so we don't change classification for
        // the common path.
        let envelope =
            VerifySpendingError::Eval(EvalError::CostExceeded("100 > 10 (JitCost units)".into()));
        match classify_verify_error(envelope, 3) {
            ValidationError::ScriptError { index, reason } => {
                assert_eq!(index, 3);
                assert!(reason.contains("100 > 10"), "reason was {reason}");
            }
            other => panic!("ordinary CostExceeded must stay ScriptError, got {other:?}"),
        }
    }

    #[test]
    fn non_eval_verify_error_routes_to_script_error() {
        // Reduction / verification-phase errors retain the legacy
        // ScriptError mapping. Only the Eval(JitCostOverflow) case is
        // promoted by this pass.
        let envelope = VerifySpendingError::Eval(EvalError::DepthLimitExceeded(99));
        assert!(matches!(
            classify_verify_error(envelope, 0),
            ValidationError::ScriptError { .. }
        ));
    }
}

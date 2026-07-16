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

use std::collections::HashSet;

use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::register::RegisterValue;
use ergo_ser::token::TokenId;
use ergo_ser::transaction::Transaction;
use ergo_sigma::evaluator::{EvalBox, EvalError, EvalHeader, ReductionContext};
use ergo_sigma::reduce::{verify_spending_proof_with_context_and_cost, VerifySpendingError};

use crate::context::ProtocolParams;
use crate::error::ValidationError;
use crate::tx::TxValidationCtx;

/// Fixed interpreter initialization cost (not votable).
///
/// Exported so wallet self-verify can use the same value as the validator
/// without a cross-crate dependency cycle. Not a voted parameter.
pub const INTERPRETER_INIT_COST: u64 = 10_000;

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

/// Compute the transaction-level initialization cost before per-input script validation.
///
/// Matches Scala's `ReducingInterpreter.calcInitCost`:
/// - Fixed interpreter init cost
/// - Per-input, per-data-input, per-output structural cost
/// - Token access cost: `(totalEntries + distinctIds) * tokenAccessCost`
///   for both inputs and output candidates
pub fn compute_tx_init_cost(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
    params: &ProtocolParams,
) -> u64 {
    compute_tx_init_cost_with_costs(
        tx,
        resolved_inputs,
        INTERPRETER_INIT_COST,
        params.input_cost,
        params.data_input_cost,
        params.output_cost,
        params.token_access_cost,
    )
}

/// The [`compute_tx_init_cost`] formula keyed on the raw cost constants, so a
/// caller holding a different parameter shape (the wallet's
/// `BlockchainParameters`) shares one implementation instead of re-deriving
/// the Scala `calcInitCost` formula. Saturating arithmetic: the result is
/// monotone and the structural / token counts are bounded by structural
/// validation before this runs, so for an accepted tx it is bit-identical to
/// the plain-arithmetic form — but a single source can't drift between call
/// sites and can't panic on adversarial counts.
pub fn compute_tx_init_cost_with_costs(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
    interpreter_init_cost: u64,
    input_cost: u64,
    data_input_cost: u64,
    output_cost: u64,
    token_access_cost: u64,
) -> u64 {
    let structural = interpreter_init_cost
        .saturating_add((tx.inputs.len() as u64).saturating_mul(input_cost))
        .saturating_add((tx.data_inputs.len() as u64).saturating_mul(data_input_cost))
        .saturating_add((tx.output_candidates.len() as u64).saturating_mul(output_cost));

    let (in_entries, in_distinct) = count_tokens_in_boxes(resolved_inputs);
    let (out_entries, out_distinct) = count_tokens_in_candidates(&tx.output_candidates);
    let token_cost = in_entries
        .saturating_add(out_entries)
        .saturating_add(in_distinct)
        .saturating_add(out_distinct)
        .saturating_mul(token_access_cost);

    structural.saturating_add(token_cost)
}

/// Count total token entries and distinct token IDs across resolved input boxes.
fn count_tokens_in_boxes(boxes: &[ErgoBox]) -> (u64, u64) {
    let mut total_entries = 0u64;
    let mut distinct: HashSet<TokenId> = HashSet::new();
    for b in boxes {
        for t in &b.candidate.tokens {
            total_entries += 1;
            distinct.insert(t.token_id);
        }
    }
    (total_entries, distinct.len() as u64)
}

/// Count total token entries and distinct token IDs across output candidates.
fn count_tokens_in_candidates(candidates: &[ErgoBoxCandidate]) -> (u64, u64) {
    let mut total_entries = 0u64;
    let mut distinct: HashSet<TokenId> = HashSet::new();
    for c in candidates {
        for t in &c.tokens {
            total_entries += 1;
            distinct.insert(t.token_id);
        }
    }
    (total_entries, distinct.len() as u64)
}

/// Storage rent variable ID in context extension (Scala: Constants.StorageIndexVarId).
const STORAGE_INDEX_VAR_ID: u8 = 127;

/// JIT cost charged for a storage rent check (Scala: Constants.StorageContractCost).
const STORAGE_CONTRACT_COST: u64 = 50;

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
        .map(|i| i.spending_proof.extension.values.clone())
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
            .extension
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
                &input.spending_proof.extension,
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
            extension: input.spending_proof.extension.values.clone(),
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

/// Predicate: a spending input opts into the storage-rent path
/// when ALL three conditions hold simultaneously. Scala parity:
/// `ErgoInterpreter.verify` (`ergo-wallet/.../ErgoInterpreter.scala`)
/// — the `hasEnoughTimeToBeSpent && proof.length == 0 &&
/// extension.values.contains(varId)` triple inside the `verify`
/// branch.
///
/// The eligibility threshold is **inclusive at the boundary**:
/// `box_age == storage_period` is sufficient (Scala uses `>=`),
/// so a box created at height 0 becomes eligible at exactly height
/// `storage_period` (mainnet: 1_051_200, ≈ 4 years at 2 min/block).
///
/// Multiple consecutive periods are all eligible — Scala does not
/// reset eligibility after the first rent collection because
/// `box_age` is monotone in the on-chain UTXO state (the rent
/// re-creates the box with `creation_height = current_height`,
/// which immediately drops `box_age` to zero in the recreated UTXO,
/// not in the about-to-be-spent input).
fn is_storage_rent_eligible(
    box_age: u32,
    storage_period: u32,
    proof_empty: bool,
    has_storage_var: bool,
) -> bool {
    box_age >= storage_period && proof_empty && has_storage_var
}

/// Check if a storage-rent spend is valid.
///
/// Matches Scala's `ErgoInterpreter.checkExpiredBox`. The storage fee
/// calculation uses i32 wrapping multiplication to replicate Scala's
/// Int overflow behavior (see ergoplatform/ergo#2251).
fn check_storage_rent(
    input_box: &ErgoBox,
    extension: &ergo_ser::input::ContextExtension,
    tx: &Transaction,
    current_height: u32,
    params: &ProtocolParams,
) -> bool {
    // Get output index from context extension variable 127
    let output_idx = match extension.values.get(&STORAGE_INDEX_VAR_ID) {
        Some((_, ergo_ser::sigma_value::SigmaValue::Short(idx))) => *idx as usize,
        Some((_, ergo_ser::sigma_value::SigmaValue::Int(idx))) => *idx as usize,
        _ => return false,
    };

    let output = match tx.output_candidates.get(output_idx) {
        Some(o) => o,
        None => return false,
    };

    // Compute box size (serialized bytes length)
    let box_bytes_len = match ergo_ser::ergo_box::serialize_ergo_box(input_box) {
        Ok(bytes) => bytes.len() as i32,
        Err(e) => {
            tracing::warn!(error = ?e, "storage rent: input box serialization failed; treating as not rent-eligible");
            return false;
        }
    };

    // i32 wrapping multiplication to match Scala's Int overflow —
    // consensus-critical for boxes whose serialized length exceeds the
    // i32 wrap point (~1,718 bytes at the default factor 1,250,000).
    let storage_fee =
        crate::storage_rent::compute_storage_fee(box_bytes_len, params.storage_fee_factor);

    // If box value doesn't cover the fee, the entire box is consumed.
    // Any output is acceptable in this case.
    let storage_fee_not_covered = (input_box.candidate.value as i64) - (storage_fee as i64) <= 0;
    if storage_fee_not_covered {
        return true;
    }

    // Otherwise the output must preserve the box's properties:
    let correct_creation_height = output.creation_height == current_height;
    let correct_value =
        output.value as i64 >= (input_box.candidate.value as i64) - (storage_fee as i64);

    // All registers except R0 (value) and R3 (creation height/reference) must match.
    // R0 and R3 are not in additionalRegisters (they're value and creationHeight fields).
    // R1 (script/ergoTree) and R2 (tokens) are checked via ergoTree and tokens fields.
    let correct_script = output.ergo_tree_bytes() == input_box.candidate.ergo_tree_bytes();
    let correct_tokens = output.tokens == input_box.candidate.tokens;
    let correct_registers = output.additional_registers == input_box.candidate.additional_registers;

    correct_creation_height
        && correct_value
        && correct_script
        && correct_tokens
        && correct_registers
}

/// Convert a resolved ErgoBox to the evaluator's EvalBox format.
/// pub(crate) for test_helpers re-export; not part of the public API.
pub(crate) fn ergo_box_to_eval_box(b: &ErgoBox, index: usize) -> Result<EvalBox, ValidationError> {
    let id = b.box_id().map_err(|e| ValidationError::ScriptError {
        index,
        reason: format!("box_id computation failed: {e}"),
    })?;

    // ExtractBytes (0xC3) reads `EvalBox.raw_bytes` at script-eval time;
    // a silent fallback to empty bytes here would silently change script
    // semantics. Surface the write failure as a structured ScriptError.
    let raw_bytes = {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::ergo_box::write_ergo_box(&mut w, b).map_err(|e| {
            ValidationError::ScriptError {
                index,
                reason: format!("ErgoBox serialization for ExtractBytes failed: {e}"),
            }
        })?;
        w.result()
    };

    Ok(EvalBox {
        creation_height: b.candidate.creation_height,
        script_bytes: b.candidate.ergo_tree_bytes().to_vec(),
        value: b.candidate.value as i64,
        id: *id.as_bytes(),
        transaction_id: *b.transaction_id.as_bytes(),
        output_index: b.index,
        registers: copy_registers(&b.candidate.additional_registers),
        tokens: b
            .candidate
            .tokens
            .iter()
            .map(|t| (*t.token_id.as_bytes(), t.amount))
            .collect(),
        raw_bytes,
        register_bytes: b.candidate.register_bytes().to_vec(),
    })
}

/// Convert an output candidate to EvalBox with its real box ID.
/// pub(crate) for test_helpers re-export; not part of the public API.
pub(crate) fn candidate_to_eval_box(
    c: &ErgoBoxCandidate,
    tx_id: &ModifierId,
    index: u16,
) -> Result<EvalBox, ValidationError> {
    let temp_box = ErgoBox {
        candidate: c.clone(),
        transaction_id: *tx_id,
        index,
    };
    let id = temp_box
        .box_id()
        .map_err(|e| ValidationError::ScriptError {
            index: index as usize,
            reason: format!("output box_id computation failed: {e}"),
        })?;

    // See `ergo_box_to_eval_box`: ExtractBytes reads raw_bytes; failures
    // here would silently corrupt script semantics.
    let raw_bytes = {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::ergo_box::write_ergo_box(&mut w, &temp_box).map_err(|e| {
            ValidationError::ScriptError {
                index: index as usize,
                reason: format!("output ErgoBox serialization for ExtractBytes failed: {e}"),
            }
        })?;
        w.result()
    };

    Ok(EvalBox {
        creation_height: c.creation_height,
        script_bytes: c.ergo_tree_bytes().to_vec(),
        value: c.value as i64,
        id: *id.as_bytes(),
        transaction_id: *tx_id.as_bytes(),
        output_index: index,
        registers: copy_registers(&c.additional_registers),
        tokens: c
            .tokens
            .iter()
            .map(|t| (*t.token_id.as_bytes(), t.amount))
            .collect(),
        raw_bytes,
        register_bytes: c.register_bytes().to_vec(),
    })
}

/// Copy raw register data into the evaluator's lazy register slots.
/// Conversion to Value happens on demand in the evaluator via sigma_to_value.
fn copy_registers(regs: &ergo_ser::register::AdditionalRegisters) -> [Option<RegisterValue>; 6] {
    let mut result: [Option<RegisterValue>; 6] = [None, None, None, None, None, None];
    for (i, reg) in regs.registers.iter().enumerate() {
        if i < 6 {
            result[i] = Some(reg.clone());
        }
    }
    result
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

    // ----- storage rent: check_storage_rent boundary semantics -----
    //
    // Pin the per-output validation contract of
    // `check_storage_rent` against Scala's `checkExpiredBox` at
    // `ergo-wallet/.../ErgoInterpreter.scala`. The eligibility
    // threshold (`box_age >= storage_period`) is enforced at the
    // call site in `validate_scripts`; these tests focus on the
    // output-preservation contract given that eligibility passed.

    mod storage_rent {
        use super::*;
        use ergo_primitives::digest::{Digest32, ModifierId};
        use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate as Cand};
        use ergo_ser::ergo_tree::ErgoTree;
        use ergo_ser::input::{ContextExtension, Input, SpendingProof};
        use ergo_ser::opcode::Expr;
        use ergo_ser::register::{AdditionalRegisters, RegisterValue};
        use ergo_ser::sigma_type::SigmaType;
        use ergo_ser::sigma_value::SigmaValue;
        use ergo_ser::token::Token;

        // ----- helpers -----

        fn simple_tree() -> ErgoTree {
            ErgoTree {
                version: 0,
                has_size: true,
                constant_segregation: true,
                constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
                body: Expr::Const {
                    tpe: SigmaType::SBoolean,
                    val: SigmaValue::Boolean(true),
                },
            }
        }

        fn alt_tree() -> ErgoTree {
            // Distinct from `simple_tree()` by `version` so the
            // serialized bytes differ — exercises the "script
            // changed" rejection path.
            ErgoTree {
                version: 1,
                has_size: true,
                constant_segregation: true,
                constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
                body: Expr::Const {
                    tpe: SigmaType::SBoolean,
                    val: SigmaValue::Boolean(true),
                },
            }
        }

        fn empty_regs() -> AdditionalRegisters {
            AdditionalRegisters::empty()
        }

        fn regs_with_r4(byte_val: i8) -> AdditionalRegisters {
            AdditionalRegisters {
                registers: vec![RegisterValue {
                    tpe: SigmaType::SByte,
                    value: SigmaValue::Byte(byte_val),
                }],
            }
        }

        fn make_input_box(
            value: u64,
            creation_height: u32,
            tree: ErgoTree,
            tokens: Vec<Token>,
            regs: AdditionalRegisters,
        ) -> ErgoBox {
            let candidate = Cand::new(value, tree, creation_height, tokens, regs).unwrap();
            ErgoBox {
                candidate,
                transaction_id: ModifierId::from_bytes([0xAA; 32]),
                index: 0,
            }
        }

        fn make_output(
            value: u64,
            creation_height: u32,
            tree: ErgoTree,
            tokens: Vec<Token>,
            regs: AdditionalRegisters,
        ) -> Cand {
            Cand::new(value, tree, creation_height, tokens, regs).unwrap()
        }

        fn ctx_ext_with_output_idx(idx: i16) -> ContextExtension {
            let mut ext = ContextExtension::empty();
            ext.values.insert(
                super::STORAGE_INDEX_VAR_ID,
                (SigmaType::SShort, SigmaValue::Short(idx)),
            );
            ext
        }

        fn make_tx_with_one_input_and_outputs(outputs: Vec<Cand>) -> Transaction {
            Transaction {
                inputs: vec![Input {
                    box_id: Digest32::from_bytes([1; 32]),
                    spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
                }],
                data_inputs: vec![],
                output_candidates: outputs,
            }
        }

        fn params_with_factor(factor: i32) -> ProtocolParams {
            let mut p = ProtocolParams::mainnet_default();
            p.storage_fee_factor = factor;
            p
        }

        // ----- happy path -----

        #[test]
        fn fee_not_covered_accepts_any_output() {
            // Tiny-value box can't pay the rent → entire box is
            // consumed; ANY output is acceptable. Pins the
            // Scala `storageFeeNotCovered ||` short-circuit.
            let in_box = make_input_box(1, 100, simple_tree(), vec![], empty_regs());
            // Wildly different output: alt tree, different value,
            // wrong creation height, etc. Must still pass because
            // fee > input value.
            let out = make_output(0, 999, alt_tree(), vec![], regs_with_r4(7));
            let tx = make_tx_with_one_input_and_outputs(vec![out]);
            let ext = ctx_ext_with_output_idx(0);
            let p = params_with_factor(1_250_000);

            assert!(
                super::check_storage_rent(&in_box, &ext, &tx, 200, &p),
                "fee-not-covered branch must accept any output",
            );
        }

        #[test]
        fn fee_covered_preserved_output_accepts() {
            // Large-value box: input.value ≫ fee. Output must
            // preserve script/tokens/registers AND have
            // creation_height == current_height AND
            // value ≥ input.value - fee.
            let in_value: u64 = 10_000_000_000;
            let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
            let current_height = 200;
            // fee = factor * box_bytes_len (i32 wrap). Compute via
            // the helper so we don't drift from the production
            // formula.
            let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
                .unwrap()
                .len() as i32;
            let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
            let preserved = make_output(
                (in_value as i64 - fee) as u64,
                current_height,
                simple_tree(),
                vec![],
                empty_regs(),
            );
            let tx = make_tx_with_one_input_and_outputs(vec![preserved]);
            let ext = ctx_ext_with_output_idx(0);
            let p = params_with_factor(1_250_000);

            assert!(super::check_storage_rent(
                &in_box,
                &ext,
                &tx,
                current_height,
                &p
            ));
        }

        // ----- per-property rejection paths -----

        #[test]
        fn wrong_creation_height_rejects() {
            let in_value: u64 = 10_000_000_000;
            let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
            let current_height = 200;
            let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
                .unwrap()
                .len() as i32;
            let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
            // Output creation_height = current_height - 1 (one block off).
            let bad = make_output(
                (in_value as i64 - fee) as u64,
                current_height - 1,
                simple_tree(),
                vec![],
                empty_regs(),
            );
            let tx = make_tx_with_one_input_and_outputs(vec![bad]);
            let ext = ctx_ext_with_output_idx(0);
            let p = params_with_factor(1_250_000);

            assert!(
                !super::check_storage_rent(&in_box, &ext, &tx, current_height, &p),
                "creation_height != current_height must reject",
            );
        }

        #[test]
        fn insufficient_output_value_rejects() {
            let in_value: u64 = 10_000_000_000;
            let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
            let current_height = 200;
            let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
                .unwrap()
                .len() as i32;
            let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
            // One nanoErg below the required floor.
            let short = make_output(
                ((in_value as i64 - fee) - 1) as u64,
                current_height,
                simple_tree(),
                vec![],
                empty_regs(),
            );
            let tx = make_tx_with_one_input_and_outputs(vec![short]);
            let ext = ctx_ext_with_output_idx(0);
            let p = params_with_factor(1_250_000);

            assert!(
                !super::check_storage_rent(&in_box, &ext, &tx, current_height, &p),
                "output.value < input.value - fee must reject",
            );
        }

        #[test]
        fn changed_script_rejects() {
            let in_value: u64 = 10_000_000_000;
            let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
            let current_height = 200;
            let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
                .unwrap()
                .len() as i32;
            let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
            // Different ergo_tree (alt_tree() differs in version).
            let bad_tree = make_output(
                (in_value as i64 - fee) as u64,
                current_height,
                alt_tree(),
                vec![],
                empty_regs(),
            );
            let tx = make_tx_with_one_input_and_outputs(vec![bad_tree]);
            let ext = ctx_ext_with_output_idx(0);
            let p = params_with_factor(1_250_000);

            assert!(
                !super::check_storage_rent(&in_box, &ext, &tx, current_height, &p),
                "ergo_tree change must reject",
            );
        }

        #[test]
        fn changed_tokens_rejects() {
            // Token-preservation branch: output must carry the same
            // `tokens` vector as the input box. Adding a token to the
            // output → reject.
            let in_value: u64 = 10_000_000_000;
            let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
            let current_height = 200;
            let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
                .unwrap()
                .len() as i32;
            let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
            // Input has zero tokens; output adds one.
            let extra_token = Token {
                token_id: Digest32::from_bytes([0xAB; 32]),
                amount: 1,
            };
            let bad_tokens = make_output(
                (in_value as i64 - fee) as u64,
                current_height,
                simple_tree(),
                vec![extra_token],
                empty_regs(),
            );
            let tx = make_tx_with_one_input_and_outputs(vec![bad_tokens]);
            let ext = ctx_ext_with_output_idx(0);
            let p = params_with_factor(1_250_000);

            assert!(
                !super::check_storage_rent(&in_box, &ext, &tx, current_height, &p),
                "tokens change must reject",
            );
        }

        #[test]
        fn changed_registers_rejects() {
            let in_value: u64 = 10_000_000_000;
            let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
            let current_height = 200;
            let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
                .unwrap()
                .len() as i32;
            let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
            // Output adds an R4 register; input has none.
            let bad_regs = make_output(
                (in_value as i64 - fee) as u64,
                current_height,
                simple_tree(),
                vec![],
                regs_with_r4(42),
            );
            let tx = make_tx_with_one_input_and_outputs(vec![bad_regs]);
            let ext = ctx_ext_with_output_idx(0);
            let p = params_with_factor(1_250_000);

            assert!(
                !super::check_storage_rent(&in_box, &ext, &tx, current_height, &p),
                "additional_registers change must reject",
            );
        }

        // ----- context-extension edge cases -----

        #[test]
        fn missing_output_index_in_extension_rejects() {
            let in_box = make_input_box(1_000_000_000, 100, simple_tree(), vec![], empty_regs());
            let tx = make_tx_with_one_input_and_outputs(vec![make_output(
                1,
                200,
                simple_tree(),
                vec![],
                empty_regs(),
            )]);
            // ContextExtension is empty — no entry at var 127.
            let ext = ContextExtension::empty();
            let p = params_with_factor(1_250_000);

            assert!(
                !super::check_storage_rent(&in_box, &ext, &tx, 200, &p),
                "missing output-index var must reject (no fallback)",
            );
        }

        #[test]
        fn output_index_out_of_bounds_rejects() {
            let in_box = make_input_box(1_000_000_000, 100, simple_tree(), vec![], empty_regs());
            // Tx has 1 output; extension references index 5.
            let tx = make_tx_with_one_input_and_outputs(vec![make_output(
                1,
                200,
                simple_tree(),
                vec![],
                empty_regs(),
            )]);
            let ext = ctx_ext_with_output_idx(5);
            let p = params_with_factor(1_250_000);

            assert!(
                !super::check_storage_rent(&in_box, &ext, &tx, 200, &p),
                "out-of-bounds output index must reject",
            );
        }

        // ----- 4-year-boundary eligibility edges -----

        #[test]
        fn eligibility_just_below_storage_period_rejected() {
            // `box_age == storage_period - 1` is one block short of
            // the 4-year mark. Eligibility fails; normal script
            // verification path applies.
            assert!(
                !super::is_storage_rent_eligible(1_051_199, 1_051_200, true, true),
                "one block below threshold must fail eligibility",
            );
        }

        #[test]
        fn eligibility_at_storage_period_accepted() {
            // Boundary case: Scala uses `>=`, so `box_age ==
            // storage_period` (1_051_200) is sufficient.
            assert!(
                super::is_storage_rent_eligible(1_051_200, 1_051_200, true, true),
                "at-threshold box_age must enter rent path",
            );
        }

        #[test]
        fn eligibility_well_past_storage_period_accepted() {
            // Multiple consecutive periods are all eligible — Scala
            // doesn't reset eligibility per period. 8 years
            // (2 × storage_period) still triggers rent.
            assert!(super::is_storage_rent_eligible(
                2 * 1_051_200,
                1_051_200,
                true,
                true,
            ));
            // 16 years
            assert!(super::is_storage_rent_eligible(
                4 * 1_051_200,
                1_051_200,
                true,
                true,
            ));
        }

        #[test]
        fn eligibility_requires_empty_proof() {
            // Eligible by age + var, but spending proof non-empty
            // — must NOT enter rent path. Scala's
            // `proof.length == 0` predicate.
            assert!(
                !super::is_storage_rent_eligible(2_000_000, 1_051_200, false, true),
                "non-empty proof must disable rent path",
            );
        }

        #[test]
        fn eligibility_requires_storage_var() {
            // Eligible by age + empty proof, but no var #127 in
            // context extension — must NOT enter rent path.
            assert!(
                !super::is_storage_rent_eligible(2_000_000, 1_051_200, true, false),
                "missing storage-index var must disable rent path",
            );
        }

        #[test]
        fn eligibility_fresh_box_rejected() {
            // box_age == 0 (just created): nowhere near eligibility.
            assert!(!super::is_storage_rent_eligible(0, 1_051_200, true, true));
        }

        #[test]
        fn eligibility_zero_storage_period_degenerate_accepts_any_age() {
            // Defensive corner: a testnet/dev config with
            // storage_period=0 makes EVERY non-fresh box eligible.
            // Pin this so a future refactor doesn't accidentally
            // hard-code mainnet's 1_051_200 into the predicate.
            assert!(super::is_storage_rent_eligible(0, 0, true, true));
            assert!(super::is_storage_rent_eligible(1, 0, true, true));
        }

        #[test]
        fn output_index_int_variant_also_accepted() {
            // Scala accepts both Short and Int as the variable
            // type. Our code path matches: ensure an Int-typed
            // entry resolves the same output as a Short-typed one.
            let in_value: u64 = 10_000_000_000;
            let in_box = make_input_box(in_value, 100, simple_tree(), vec![], empty_regs());
            let current_height = 200;
            let bytes_len = ergo_ser::ergo_box::serialize_ergo_box(&in_box)
                .unwrap()
                .len() as i32;
            let fee = crate::storage_rent::compute_storage_fee(bytes_len, 1_250_000) as i64;
            let preserved = make_output(
                (in_value as i64 - fee) as u64,
                current_height,
                simple_tree(),
                vec![],
                empty_regs(),
            );
            let tx = make_tx_with_one_input_and_outputs(vec![preserved]);
            let mut ext = ContextExtension::empty();
            ext.values.insert(
                super::STORAGE_INDEX_VAR_ID,
                (SigmaType::SInt, SigmaValue::Int(0)),
            );
            let p = params_with_factor(1_250_000);

            assert!(super::check_storage_rent(
                &in_box,
                &ext,
                &tx,
                current_height,
                &p
            ));
        }
    }
}

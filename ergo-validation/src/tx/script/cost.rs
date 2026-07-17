use std::collections::HashSet;

use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::token::TokenId;
use ergo_ser::transaction::Transaction;

use crate::context::ProtocolParams;

/// Fixed interpreter initialization cost (not votable).
///
/// Exported so wallet self-verify can use the same value as the validator
/// without a cross-crate dependency cycle. Not a voted parameter.
pub const INTERPRETER_INIT_COST: u64 = 10_000;

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

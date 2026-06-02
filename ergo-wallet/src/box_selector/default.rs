//! DefaultBoxSelector port from Scala's `DefaultBoxSelector.scala`.
//!
//! Algorithm: greedy, sort candidates by ERG value DESC, accumulate until
//! the target ERG and all required tokens are covered. When the natural
//! change would fall below `min_change_value`, continue accumulating until
//! change reaches zero (exact) or >= min_change_value (acceptable change box).

use super::{BoxSelector, BoxSummary, SelectionResult, SelectionTarget};
use crate::error::WalletError;
use std::cmp::Reverse;
use std::collections::BTreeMap;

pub struct DefaultBoxSelector;

impl BoxSelector for DefaultBoxSelector {
    fn select(
        &self,
        candidates: &[BoxSummary],
        target: &SelectionTarget,
    ) -> Result<SelectionResult, WalletError> {
        // Sort by value DESC (greedy pick largest first — minimises input count).
        let mut sorted: Vec<&BoxSummary> = candidates.iter().collect();
        sorted.sort_by_key(|b| Reverse(b.value));

        let mut selected_ids: Vec<[u8; 32]> = Vec::new();
        let mut total_erg: u64 = 0;
        let mut total_tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();

        for candidate in sorted {
            selected_ids.push(candidate.box_id);
            total_erg = total_erg.saturating_add(candidate.value);
            for (token_id, amount) in &candidate.tokens {
                *total_tokens.entry(*token_id).or_insert(0) = total_tokens
                    .get(token_id)
                    .unwrap_or(&0)
                    .saturating_add(*amount);
            }

            if is_covered(total_erg, &total_tokens, target) {
                let change_erg = total_erg - target.erg_amount;
                let change_tokens = compute_change_tokens(&total_tokens, &target.tokens);
                return Ok(SelectionResult {
                    selected_ids,
                    change_erg,
                    change_tokens,
                });
            }
        }

        // All candidates consumed. If the target ERG and every required token
        // are actually covered, the only reason `is_covered` never fired is a
        // sub-minimum (dead-zone) change: 0 < change < min_change_value with no
        // further box to close the gap. Scala's selector has no min-change gate
        // at all (it stops at coverage); the minimum is enforced later by the
        // builder, which folds token-less sub-minimum change into the miner fee
        // (TransactionBuilder.buildUnsignedTx `changeGoesToFee`). So returning
        // the selection here — rather than erroring — is the parity-correct
        // behavior; the builder decides whether the dust becomes a change box
        // or fee. Erroring would fail a genuinely fundable send.
        let tokens_covered = target
            .tokens
            .iter()
            .all(|(id, req)| total_tokens.get(id).copied().unwrap_or(0) >= *req);
        if total_erg >= target.erg_amount && tokens_covered {
            return Ok(SelectionResult {
                selected_ids,
                change_erg: total_erg - target.erg_amount,
                change_tokens: compute_change_tokens(&total_tokens, &target.tokens),
            });
        }

        // Genuine shortfall: not enough ERG and/or missing required tokens.
        Err(WalletError::BoxSelection(format!(
            "insufficient funds: needed {} nanoERG, only {} available",
            target.erg_amount, total_erg
        )))
    }
}

/// True when the accumulated totals satisfy the target, considering the
/// min_change_value constraint.
///
/// Coverage requires:
/// 1. All required tokens are fully accumulated.
/// 2. ERG satisfies one of:
///    - `total_erg == target.erg_amount` (exact, zero change)
///    - `total_erg >= target.erg_amount + min_change_value` (change box viable)
fn is_covered(
    total_erg: u64,
    total_tokens: &BTreeMap<[u8; 32], u64>,
    target: &SelectionTarget,
) -> bool {
    // Check every required token is fully covered.
    for (token_id, required) in &target.tokens {
        if total_tokens.get(token_id).copied().unwrap_or(0) < *required {
            return false;
        }
    }

    // Check ERG coverage respecting min_change_value.
    if total_erg < target.erg_amount {
        return false;
    }
    let change = total_erg - target.erg_amount;
    change == 0 || change >= target.min_change_value
}

/// Returns the token surplus after spending `target_tokens` from `accumulated`.
fn compute_change_tokens(
    accumulated: &BTreeMap<[u8; 32], u64>,
    target_tokens: &BTreeMap<[u8; 32], u64>,
) -> BTreeMap<[u8; 32], u64> {
    let mut change = BTreeMap::new();
    for (token_id, &total) in accumulated {
        let spent = target_tokens.get(token_id).copied().unwrap_or(0);
        if total > spent {
            change.insert(*token_id, total - spent);
        }
    }
    change
}

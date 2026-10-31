//! DefaultBoxSelector port from Scala's `DefaultBoxSelector.scala`.
//!
//! Algorithm: sort candidates by ERG value DESC. First take the boxes that
//! hold a token the target still needs, until every required token is
//! covered; then take the largest remaining boxes until the target ERG is
//! covered. Scala takes ERG boxes first and token boxes after; taking token
//! boxes first counts their ERG toward the target, and never sweeps every box
//! larger than a low-value token box to reach it. When the natural change
//! would fall below `min_change_value`, prefer additional inputs until change
//! reaches zero or the minimum. If all inputs still leave dust, return the
//! funded selection for the transaction builder to handle. A selection never
//! holds more than [`MAX_SELECTED_INPUTS`] boxes.

use super::{BoxSelector, BoxSummary, SelectionResult, SelectionTarget, MAX_SELECTED_INPUTS};
use crate::error::WalletError;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

pub struct DefaultBoxSelector;

impl BoxSelector for DefaultBoxSelector {
    fn select(
        &self,
        candidates: &[BoxSummary],
        target: &SelectionTarget,
    ) -> Result<SelectionResult, WalletError> {
        // A summary identifies one spendable box. Check the entire input before
        // an early funded return can hide repeated or conflicting summaries.
        let mut unique_ids = BTreeSet::new();
        for candidate in candidates {
            if !unique_ids.insert(candidate.box_id) {
                return Err(WalletError::BoxSelection(
                    "duplicate candidate box id".into(),
                ));
            }
        }
        // Sort by value DESC (greedy pick largest first — minimises input count).
        let mut sorted: Vec<&BoxSummary> = candidates.iter().collect();
        sorted.sort_by_key(|b| Reverse(b.value));

        let mut picked = Picked::default();
        let mut used = vec![false; sorted.len()];

        // 1. Boxes holding a token the target still needs. A box without one
        //    only adds ERG, which step 2 takes from the largest boxes instead.
        for (index, candidate) in sorted.iter().enumerate() {
            if picked.tokens_covered(target) {
                break;
            }
            if !picked.still_needs_token_of(candidate, target) {
                continue;
            }
            if picked.ids.len() == MAX_SELECTED_INPUTS {
                return at_input_limit(picked, candidates, target);
            }
            picked.add(candidate)?;
            used[index] = true;
        }
        if !picked.tokens_covered(target) {
            // Step 1 took every box holding a token that is still short.
            return Err(candidate_shortfall(candidates, target)
                .expect("a required token is short across all candidates"));
        }

        // 2. The largest remaining boxes until the ERG target is covered.
        for (index, candidate) in sorted.iter().enumerate() {
            if picked.covered(target) {
                return Ok(picked.into_result(target));
            }
            if used[index] {
                continue;
            }
            if picked.ids.len() == MAX_SELECTED_INPUTS {
                return at_input_limit(picked, candidates, target);
            }
            picked.add(candidate)?;
        }

        // All candidates consumed. A funded selection is returned even with a
        // sub-minimum (dead-zone) change: 0 < change < min_change_value with no
        // further box to close the gap. Scala's selector has no min-change gate
        // at all (it stops at coverage); the minimum is enforced later by the
        // builder, which folds token-less sub-minimum change into the miner fee
        // (TransactionBuilder.buildUnsignedTx `changeGoesToFee`). So returning
        // the selection here — rather than erroring — is the parity-correct
        // behavior; the builder decides whether the dust becomes a change box
        // or fee. Erroring would fail a genuinely fundable send.
        if picked.funded(target) {
            return Ok(picked.into_result(target));
        }

        // Genuine shortfall: not enough ERG and/or missing required tokens.
        Err(shortfall(picked.erg, &picked.tokens, target)
            .expect("an unfunded selection of every candidate is a shortfall"))
    }
}

/// Boxes taken so far, with their exact ERG and token totals.
#[derive(Default)]
struct Picked {
    ids: Vec<[u8; 32]>,
    erg: u64,
    tokens: BTreeMap<[u8; 32], u64>,
}

impl Picked {
    fn add(&mut self, candidate: &BoxSummary) -> Result<(), WalletError> {
        self.ids.push(candidate.box_id);
        self.erg = self
            .erg
            .checked_add(candidate.value)
            .ok_or_else(|| WalletError::BoxSelection("selected ERG total exceeds u64".into()))?;
        for (token_id, amount) in &candidate.tokens {
            let total = self.tokens.entry(*token_id).or_insert(0);
            *total = total.checked_add(*amount).ok_or_else(|| {
                WalletError::BoxSelection("selected token total exceeds u64".into())
            })?;
        }
        Ok(())
    }

    fn tokens_covered(&self, target: &SelectionTarget) -> bool {
        target
            .tokens
            .iter()
            .all(|(id, required)| self.tokens.get(id).copied().unwrap_or(0) >= *required)
    }

    /// Whether `candidate` holds a required token not yet fully covered.
    fn still_needs_token_of(&self, candidate: &BoxSummary, target: &SelectionTarget) -> bool {
        candidate.tokens.keys().any(|id| {
            target
                .tokens
                .get(id)
                .is_some_and(|required| self.tokens.get(id).copied().unwrap_or(0) < *required)
        })
    }

    /// The target ERG and every required token are covered, whatever the change.
    fn funded(&self, target: &SelectionTarget) -> bool {
        self.erg >= target.erg_amount && self.tokens_covered(target)
    }

    /// Funded, and the change is either zero or at least `min_change_value`.
    fn covered(&self, target: &SelectionTarget) -> bool {
        if !self.funded(target) {
            return false;
        }
        let change = self.erg - target.erg_amount;
        change == 0 || change >= target.min_change_value
    }

    fn into_result(self, target: &SelectionTarget) -> SelectionResult {
        SelectionResult {
            change_erg: self.erg - target.erg_amount,
            change_tokens: compute_change_tokens(&self.tokens, &target.tokens),
            selected_ids: self.ids,
        }
    }
}

/// The selection holds [`MAX_SELECTED_INPUTS`] boxes and needs another. A
/// funded selection lacks only a viable change amount, so it is returned as
/// when every candidate is used. Otherwise this is a shortfall if all the
/// candidates together cannot fund the target, and the input limit if they can.
fn at_input_limit(
    picked: Picked,
    candidates: &[BoxSummary],
    target: &SelectionTarget,
) -> Result<SelectionResult, WalletError> {
    if picked.funded(target) {
        return Ok(picked.into_result(target));
    }
    Err(candidate_shortfall(candidates, target).unwrap_or_else(|| {
        WalletError::InputLimit(format!(
            "covering the target takes more than {MAX_SELECTED_INPUTS} inputs; \
             consolidate the wallet's boxes or name the inputs explicitly"
        ))
    }))
}

/// [`shortfall`] over the totals of every candidate. Saturating: a total past
/// u64::MAX covers any target.
fn candidate_shortfall(candidates: &[BoxSummary], target: &SelectionTarget) -> Option<WalletError> {
    let mut erg: u64 = 0;
    let mut tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for candidate in candidates {
        erg = erg.saturating_add(candidate.value);
        for (token_id, amount) in &candidate.tokens {
            let total = tokens.entry(*token_id).or_insert(0);
            *total = total.saturating_add(*amount);
        }
    }
    shortfall(erg, &tokens, target)
}

/// The insufficient-funds error when `erg` and `tokens` cannot fund `target`.
fn shortfall(
    erg: u64,
    tokens: &BTreeMap<[u8; 32], u64>,
    target: &SelectionTarget,
) -> Option<WalletError> {
    if erg < target.erg_amount {
        return Some(WalletError::BoxSelection(format!(
            "insufficient funds: needed {} nanoERG, only {erg} available",
            target.erg_amount
        )));
    }
    target.tokens.iter().find_map(|(id, &required)| {
        let available = tokens.get(id).copied().unwrap_or(0);
        (available < required).then(|| {
            WalletError::BoxSelection(format!(
                "insufficient funds: needed {required} of token {}, only {available} available",
                hex::encode(id)
            ))
        })
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: u8, value: u64, token: u64) -> BoxSummary {
        BoxSummary {
            box_id: [id; 32],
            value,
            tokens: if token == 0 {
                BTreeMap::new()
            } else {
                BTreeMap::from([([7; 32], token)])
            },
        }
    }

    fn target(erg_amount: u64) -> SelectionTarget {
        SelectionTarget {
            erg_amount,
            tokens: BTreeMap::new(),
            min_change_value: 0,
        }
    }

    #[test]
    fn duplicate_candidate_ids_reject_even_after_an_early_funded_prefix() {
        for second in [candidate(1, 10, 0), candidate(1, 5, 2)] {
            let error = DefaultBoxSelector
                .select(&[candidate(1, 10, 0), second], &target(1))
                .unwrap_err();
            assert!(matches!(error, WalletError::BoxSelection(_)));
            assert!(error.to_string().contains("duplicate candidate"));
        }
    }

    #[test]
    fn selected_erg_and_token_totals_must_be_exactly_representable() {
        let error = DefaultBoxSelector
            .select(
                &[candidate(1, u64::MAX - 1, 0), candidate(2, 2, 0)],
                &target(u64::MAX),
            )
            .unwrap_err();
        assert!(error.to_string().contains("ERG total exceeds"));

        let error = DefaultBoxSelector
            .select(
                &[candidate(1, 10, u64::MAX - 1), candidate(2, 5, 2)],
                &target(15),
            )
            .unwrap_err();
        assert!(error.to_string().contains("token total exceeds"));
    }

    #[test]
    fn distinct_candidates_retain_greedy_selection_and_exact_change() {
        let mut target = target(12);
        target.tokens.insert([7; 32], 3);
        let result = DefaultBoxSelector
            .select(&[candidate(2, 5, 2), candidate(1, 10, 2)], &target)
            .unwrap();
        assert_eq!(result.selected_ids, vec![[1; 32], [2; 32]]);
        assert_eq!(result.change_erg, 3);
        assert_eq!(result.change_tokens, BTreeMap::from([([7; 32], 1)]));
    }

    /// `count` token-less boxes worth `value` each, ids from 1.
    fn plain_boxes(count: usize, value: u64) -> Vec<BoxSummary> {
        (1..=count)
            .map(|n| {
                let mut box_id = [0; 32];
                box_id[..8].copy_from_slice(&(n as u64).to_be_bytes());
                BoxSummary {
                    box_id,
                    value,
                    tokens: BTreeMap::new(),
                }
            })
            .collect()
    }

    #[test]
    fn a_low_value_token_box_is_taken_without_sweeping_larger_boxes() {
        // Thousands of larger ERG boxes and one minimum-value NFT box: the
        // selection is the NFT box plus one ERG box, not every larger box.
        let mut candidates = plain_boxes(5_000, 50_000_000);
        candidates.push(candidate(0xAA, 1_000_000, 1));
        let mut target = target(1_000_000_000 + 1_000_000);
        target.tokens.insert([7; 32], 1);
        target.min_change_value = 1_000_000;

        let result = DefaultBoxSelector.select(&candidates, &target).unwrap();
        assert_eq!(result.selected_ids.first(), Some(&[0xAA; 32]));
        // 1 ERG + fee: the NFT box's 0.001 ERG and 20 boxes of 0.05 ERG.
        assert_eq!(result.selected_ids.len(), 21);
        assert_eq!(result.change_erg, 0);
        assert!(result.change_tokens.is_empty());
    }

    #[test]
    fn token_boxes_count_toward_the_erg_target() {
        let mut target = target(50);
        target.tokens.insert([7; 32], 1);
        let result = DefaultBoxSelector
            .select(&[candidate(1, 100, 0), candidate(2, 60, 1)], &target)
            .unwrap();
        assert_eq!(result.selected_ids, vec![[2; 32]]);
        assert_eq!(result.change_erg, 10);
    }

    #[test]
    fn a_target_needing_more_than_the_input_cap_is_an_input_limit_error() {
        let candidates = plain_boxes(MAX_SELECTED_INPUTS + 50, 10);
        let error = DefaultBoxSelector
            .select(&candidates, &target(10 * (MAX_SELECTED_INPUTS as u64 + 20)))
            .unwrap_err();
        assert!(matches!(error, WalletError::InputLimit(_)), "{error}");

        // Spread tokens hit the same cap in the token step.
        let mut target = target(1);
        target
            .tokens
            .insert([7; 32], MAX_SELECTED_INPUTS as u64 + 20);
        let candidates: Vec<_> = (1..=MAX_SELECTED_INPUTS as u8 + 50)
            .map(|id| candidate(id, 10, 1))
            .collect();
        let error = DefaultBoxSelector.select(&candidates, &target).unwrap_err();
        assert!(matches!(error, WalletError::InputLimit(_)), "{error}");
    }

    #[test]
    fn a_shortfall_at_the_input_cap_is_still_insufficient_funds() {
        let candidates = plain_boxes(MAX_SELECTED_INPUTS + 50, 10);
        let error = DefaultBoxSelector
            .select(&candidates, &target(10 * (MAX_SELECTED_INPUTS as u64 + 51)))
            .unwrap_err();
        assert!(error.to_string().contains("insufficient funds"), "{error}");

        let mut target = target(1);
        target.tokens.insert([7; 32], 5);
        let candidates: Vec<_> = (1..=MAX_SELECTED_INPUTS as u8 + 50)
            .map(|id| candidate(id, 10, 0))
            .collect();
        let error = DefaultBoxSelector.select(&candidates, &target).unwrap_err();
        assert!(error.to_string().contains("needed 5 of token"), "{error}");
    }

    #[test]
    fn a_funded_selection_at_the_input_cap_keeps_its_dust_change() {
        // Funded at the cap with 1 of change, below the minimum of 5: return
        // it for the builder rather than exceed the cap.
        let candidates = plain_boxes(MAX_SELECTED_INPUTS + 1, 10);
        let mut target = target(10 * MAX_SELECTED_INPUTS as u64 - 1);
        target.min_change_value = 5;
        let result = DefaultBoxSelector.select(&candidates, &target).unwrap();
        assert_eq!(result.selected_ids.len(), MAX_SELECTED_INPUTS);
        assert_eq!(result.change_erg, 1);
    }
}

//! Box selector integration tests.
//!
//! Tests cover: DefaultBoxSelector greedy logic, token coverage, insufficient-
//! funds errors, exact-target zero-change, min_change_value consolidation,
//! missing-token errors, and ReplaceCompactCollectBoxSelector delegation.
//! One #[ignore]'d scaffold for Scala-oracle fixtures (extraction pending).

use ergo_wallet::box_selector::{
    default::DefaultBoxSelector, replace_compact::ReplaceCompactCollectBoxSelector, BoxSelector,
    BoxSummary, SelectionTarget,
};
use ergo_wallet::error::WalletError;
use std::collections::BTreeMap;

// ----- helpers -----

fn summary(box_id: u8, value: u64) -> BoxSummary {
    BoxSummary {
        box_id: [box_id; 32],
        value,
        tokens: BTreeMap::new(),
    }
}

fn summary_with_token(box_id: u8, value: u64, token_id: u8, token_amount: u64) -> BoxSummary {
    let mut tokens = BTreeMap::new();
    tokens.insert([token_id; 32], token_amount);
    BoxSummary {
        box_id: [box_id; 32],
        value,
        tokens,
    }
}

fn target_erg(erg_amount: u64) -> SelectionTarget {
    SelectionTarget {
        erg_amount,
        tokens: BTreeMap::new(),
        min_change_value: 0,
    }
}

fn target_erg_min_change(erg_amount: u64, min_change_value: u64) -> SelectionTarget {
    SelectionTarget {
        erg_amount,
        tokens: BTreeMap::new(),
        min_change_value,
    }
}

fn target_with_token(erg_amount: u64, token_id: u8, token_amount: u64) -> SelectionTarget {
    let mut tokens = BTreeMap::new();
    tokens.insert([token_id; 32], token_amount);
    SelectionTarget {
        erg_amount,
        tokens,
        min_change_value: 0,
    }
}

// ----- happy path -----

#[test]
fn default_selector_covers_erg_target_greedy() {
    // Three candidates: 300M, 200M, 100M. Target: 250M.
    // Greedy picks 300M first → covered. Second box should NOT be included.
    let candidates = vec![
        summary(1, 100_000_000),
        summary(2, 300_000_000),
        summary(3, 200_000_000),
    ];
    let result = DefaultBoxSelector
        .select(&candidates, &target_erg(250_000_000))
        .unwrap();

    assert_eq!(result.selected_ids.len(), 1);
    assert_eq!(
        result.selected_ids[0], [2u8; 32],
        "largest box selected first"
    );
    assert_eq!(result.change_erg, 50_000_000);
    assert!(result.change_tokens.is_empty());
}

#[test]
fn default_selector_covers_token_target_after_erg() {
    // Two candidates: box A has 500M ERG + 10 tokens; box B has 100M + 5 tokens.
    // Target: 50M ERG + 8 tokens. Box A alone covers both.
    let candidates = vec![
        summary_with_token(1, 100_000_000, 42, 5),
        summary_with_token(2, 500_000_000, 42, 10),
    ];
    let result = DefaultBoxSelector
        .select(&candidates, &target_with_token(50_000_000, 42, 8))
        .unwrap();

    assert_eq!(result.selected_ids.len(), 1);
    assert_eq!(result.selected_ids[0], [2u8; 32]);
    assert_eq!(result.change_erg, 450_000_000);
    assert_eq!(result.change_tokens[&[42u8; 32]], 2);
}

// ----- error paths -----

#[test]
fn default_selector_insufficient_funds_errors() {
    let candidates = vec![summary(1, 100_000_000), summary(2, 50_000_000)];
    let err = DefaultBoxSelector
        .select(&candidates, &target_erg(500_000_000))
        .unwrap_err();

    match err {
        WalletError::BoxSelection(msg) => {
            assert!(msg.contains("insufficient funds"), "msg: {msg}");
            assert!(
                msg.contains("500000000"),
                "should mention required amount: {msg}"
            );
        }
        other => panic!("expected BoxSelection, got {other:?}"),
    }
}

#[test]
fn default_selector_exact_target_zero_change() {
    // Candidate exactly equals target → change_erg = 0, change_tokens empty.
    let candidates = vec![summary(1, 200_000_000)];
    let result = DefaultBoxSelector
        .select(&candidates, &target_erg(200_000_000))
        .unwrap();

    assert_eq!(result.selected_ids, vec![[1u8; 32]]);
    assert_eq!(result.change_erg, 0);
    assert!(result.change_tokens.is_empty());
}

#[test]
fn default_selector_change_below_min_value_consolidates() {
    // 2 candidates of 100M each. Target = 99M with min_change = 10M.
    // First candidate gives change = 1M < 10M → must continue accumulating.
    // After both: total = 200M, change = 101M >= 10M → covered.
    let candidates = vec![summary(1, 100_000_000), summary(2, 100_000_000)];
    let result = DefaultBoxSelector
        .select(&candidates, &target_erg_min_change(99_000_000, 10_000_000))
        .unwrap();

    assert_eq!(result.selected_ids.len(), 2, "must accumulate both boxes");
    assert_eq!(result.change_erg, 101_000_000);
}

#[test]
fn default_selector_deadzone_change_succeeds_when_no_box_can_consolidate() {
    // Regression: a SINGLE 100M box, target 99M, min_change 10M. The leftover
    // change is 1M — in the dead zone (0 < 1M < 10M) — and there is no further
    // box to push change to zero or above the minimum. Previously this errored
    // "insufficient funds" even though payment + fee are fully covered. Scala's
    // selector has no min-change gate (it stops at coverage); the builder folds
    // the token-less sub-minimum change into the miner fee. So selection must
    // SUCCEED here, returning the sub-minimum change for the builder to fold.
    let candidates = vec![summary(1, 100_000_000)];
    let result = DefaultBoxSelector
        .select(&candidates, &target_erg_min_change(99_000_000, 10_000_000))
        .expect("fundable send must not fail on dead-zone change");
    assert_eq!(result.selected_ids, vec![[1u8; 32]]);
    assert_eq!(
        result.change_erg, 1_000_000,
        "sub-minimum change returned as-is"
    );
    assert!(result.change_tokens.is_empty());
}

#[test]
fn default_selector_token_not_present_errors() {
    // Candidates carry no tokens at all. Target requires a token.
    let candidates = vec![summary(1, 1_000_000_000)];
    let err = DefaultBoxSelector
        .select(&candidates, &target_with_token(100_000_000, 99, 1))
        .unwrap_err();

    match err {
        WalletError::BoxSelection(_) => {}
        other => panic!("expected BoxSelection, got {other:?}"),
    }
}

// ----- round-trips -----

#[test]
fn replace_compact_falls_back_to_default() {
    // ReplaceCompactCollectBoxSelector must produce the same result as
    // DefaultBoxSelector while the full compaction optimization is unimplemented.
    let candidates = vec![
        summary(1, 100_000_000),
        summary(2, 500_000_000),
        summary(3, 300_000_000),
    ];
    let t = target_erg_min_change(200_000_000, 5_000_000);

    let default_result = DefaultBoxSelector.select(&candidates, &t).unwrap();
    let compact_result = ReplaceCompactCollectBoxSelector
        .select(&candidates, &t)
        .unwrap();

    assert_eq!(compact_result.selected_ids, default_result.selected_ids);
    assert_eq!(compact_result.change_erg, default_result.change_erg);
    assert_eq!(compact_result.change_tokens, default_result.change_tokens);
}

// ----- oracle parity -----

/// Placeholder: Scala-extracted (inputs, target, expected_outputs) fixtures.
/// Un-ignore once vectors are extracted from the Scala node.
#[test]
#[ignore = "Scala oracle fixture extraction pending"]
fn replace_compact_oracle_against_scala_fixtures() {
    // TODO: extract from Scala DefaultBoxSelector + ReplaceCompactCollectBoxSelector
    // unit tests under reference/ergo and populate test-vectors/box_selection/.
    // Each fixture: candidates JSON → expected selected_ids + change.
    todo!("populate from Scala oracle extraction");
}

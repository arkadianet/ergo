//! UnsignedTxBuilder integration tests.
//!
//! Tests verify the builder's payment-to-unsigned-tx pipeline using
//! synthetic `BoxSummary` fixtures. Full ErgoBox lookup (for signing) is
//! intentionally out of scope here — that lives in the writer task.
//!
//! ErgoTree fixtures: minimal always-true tree (header=0x00, body=0x01 0x01).
//! This is the simplest valid script and avoids pulling in sigma-rust or
//! Scala-oracle extraction for builder-level tests.

use ergo_wallet::box_selector::{default::DefaultBoxSelector, BoxSummary};
use ergo_wallet::error::WalletError;
use ergo_wallet::tx_builder::{PaymentRequest, UnsignedTxBuilder};
use std::collections::BTreeMap;

// ----- helpers -----

/// Minimal valid ErgoTree bytes: version=0, no flags, body=Const(SBoolean=true).
/// Wire: [0x00 header][0x01 type=SBoolean][0x01 value=true]
fn always_true_ergo_tree() -> Vec<u8> {
    vec![0x00, 0x01, 0x01]
}

/// Build a BoxSummary with only ERG (no tokens).
fn erg_summary(box_id: u8, value: u64) -> BoxSummary {
    BoxSummary {
        box_id: [box_id; 32],
        value,
        tokens: BTreeMap::new(),
    }
}

/// Build a BoxSummary carrying one token.
fn token_summary(box_id: u8, value: u64, token_id: u8, token_amount: u64) -> BoxSummary {
    let mut tokens = BTreeMap::new();
    tokens.insert([token_id; 32], token_amount);
    BoxSummary {
        box_id: [box_id; 32],
        value,
        tokens,
    }
}

/// Payment request for ERG only.
fn erg_request(value: u64) -> PaymentRequest {
    PaymentRequest {
        to_ergo_tree: always_true_ergo_tree(),
        value,
        assets: BTreeMap::new(),
    }
}

/// Payment request carrying one token.
fn token_request(value: u64, token_id: u8, token_amount: u64) -> PaymentRequest {
    let mut assets = BTreeMap::new();
    assets.insert([token_id; 32], token_amount);
    PaymentRequest {
        to_ergo_tree: always_true_ergo_tree(),
        value,
        assets,
    }
}

/// Construct a builder with the given summaries and selector.
fn builder<'a>(available: &'a [BoxSummary], fee: u64, min_box_value: u64) -> UnsignedTxBuilder<'a> {
    UnsignedTxBuilder {
        available_summaries: available,
        selector: &DefaultBoxSelector,
        fee,
        fee_ergo_tree: always_true_ergo_tree(),
        change_ergo_tree: always_true_ergo_tree(),
        current_height: 1_000,
        min_box_value,
        data_inputs: vec![],
    }
}

// ----- happy path -----

/// Simple single-payment ERG transaction with sufficient input.
///
/// Available: 2 ERG. Payment: 1 ERG. Fee: 0.001 ERG.
/// Expect: 2 outputs (payment + fee) and 1 change output,
///         1 selected input, no errors.
#[test]
fn builder_creates_simple_payment_tx() {
    const ERG: u64 = 1_000_000_000;
    const FEE: u64 = 1_000_000;

    let available = vec![erg_summary(1, 2 * ERG)];
    let requests = [erg_request(ERG)];

    let tx = builder(&available, FEE, 0)
        .build(&requests)
        .expect("build must succeed");

    // One input selected.
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(*tx.inputs[0].box_id.as_bytes(), [1u8; 32]);

    // Payment output + fee output + change output.
    assert_eq!(tx.output_candidates.len(), 3);
    assert_eq!(tx.output_candidates[0].value, ERG, "payment output");
    assert_eq!(tx.output_candidates[1].value, FEE, "fee output");

    let expected_change = 2 * ERG - ERG - FEE;
    assert_eq!(
        tx.output_candidates[2].value, expected_change,
        "change output"
    );
    assert!(tx.data_inputs.is_empty());
}

/// When total input ERG exactly equals target + fee, no change output is emitted.
#[test]
fn builder_omits_change_output_for_exact_payment() {
    const PAYMENT: u64 = 900_000_000;
    const FEE: u64 = 100_000_000;

    // Box value equals PAYMENT + FEE exactly.
    let available = vec![erg_summary(2, PAYMENT + FEE)];
    let requests = [erg_request(PAYMENT)];

    let tx = builder(&available, FEE, 0)
        .build(&requests)
        .expect("exact-value build must succeed");

    assert_eq!(tx.inputs.len(), 1);
    // Exactly payment + fee — no change output.
    assert_eq!(
        tx.output_candidates.len(),
        2,
        "no change output on exact match"
    );
    assert_eq!(tx.output_candidates[0].value, PAYMENT);
    assert_eq!(tx.output_candidates[1].value, FEE);
}

/// When the available boxes hold more ERG than needed, a change output is included.
#[test]
fn builder_includes_change_output_when_remainder_positive() {
    const PAYMENT: u64 = 500_000_000;
    const FEE: u64 = 10_000_000;
    const INPUT_VALUE: u64 = 2_000_000_000; // 2 ERG available

    let available = vec![erg_summary(3, INPUT_VALUE)];
    let requests = [erg_request(PAYMENT)];

    let tx = builder(&available, FEE, 0)
        .build(&requests)
        .expect("build with remainder must succeed");

    // payment + fee + change
    assert_eq!(tx.output_candidates.len(), 3);
    let change = tx.output_candidates[2].value;
    assert_eq!(
        change,
        INPUT_VALUE - PAYMENT - FEE,
        "change must equal surplus"
    );
    assert!(change > 0);
}

/// Builder returns `WalletError::BoxSelection` when inputs cannot cover the target.
#[test]
fn builder_fails_on_insufficient_funds() {
    const PAYMENT: u64 = 5_000_000_000; // 5 ERG
    const FEE: u64 = 1_000_000; // 0.001 ERG
    const AVAILABLE: u64 = 1_000_000_000; // only 1 ERG available

    let available = vec![erg_summary(4, AVAILABLE)];
    let requests = [erg_request(PAYMENT)];

    let err = builder(&available, FEE, 0)
        .build(&requests)
        .expect_err("must fail with insufficient funds");

    assert!(
        matches!(err, WalletError::BoxSelection(_)),
        "expected BoxSelection error, got {err:?}"
    );
}

/// When inputs carry more tokens than the payment requests need, token change
/// is included in the change output.
#[test]
fn builder_preserves_token_change() {
    const ERG: u64 = 1_000_000_000;
    const FEE: u64 = 1_000_000;
    const TOKEN_ID: u8 = 0xAA;
    const TOKEN_SUPPLY: u64 = 1_000;
    const TOKEN_SEND: u64 = 300;

    // Box holds 2 ERG + 1000 tokens.
    let available = vec![token_summary(5, 2 * ERG, TOKEN_ID, TOKEN_SUPPLY)];
    // Send 300 tokens + 1 ERG to recipient.
    let requests = [token_request(ERG, TOKEN_ID, TOKEN_SEND)];

    let tx = builder(&available, FEE, 0)
        .build(&requests)
        .expect("build with token change must succeed");

    // payment + fee + change
    assert_eq!(tx.output_candidates.len(), 3);

    // Payment output carries the requested tokens.
    let payment_out = &tx.output_candidates[0];
    assert_eq!(payment_out.tokens.len(), 1);
    assert_eq!(payment_out.tokens[0].amount, TOKEN_SEND);
    assert_eq!(payment_out.tokens[0].token_id.as_bytes(), &[TOKEN_ID; 32]);

    // Change output carries token remainder.
    let change_out = &tx.output_candidates[2];
    let token_change_amount: u64 = change_out
        .tokens
        .iter()
        .filter(|t| t.token_id.as_bytes() == &[TOKEN_ID; 32])
        .map(|t| t.amount)
        .sum();
    assert_eq!(
        token_change_amount,
        TOKEN_SUPPLY - TOKEN_SEND,
        "token change must be token_supply - token_send"
    );
}

/// Dead-zone change with NO tokens is folded into the miner fee — no dust
/// change box is emitted. Mirrors Scala `TransactionBuilder` `changeGoesToFee`.
#[test]
fn builder_folds_token_less_subminimum_change_into_fee() {
    const PAYMENT: u64 = 99_000_000;
    const FEE: u64 = 1_000_000;
    const MIN_BOX: u64 = 10_000_000;
    // Single 100M box: change = 100M - 99M - 1M = 0... so make input 100.5M to
    // leave 500_000 change (< MIN_BOX, token-less, no further box).
    let available = vec![erg_summary(7, 100_500_000)];
    let requests = [erg_request(PAYMENT)];

    let tx = builder(&available, FEE, MIN_BOX)
        .build(&requests)
        .expect("dead-zone token-less send must succeed");

    // payment + fee only — the 500_000 dust was folded into the fee.
    assert_eq!(
        tx.output_candidates.len(),
        2,
        "no dust change box — folded into fee"
    );
    assert_eq!(tx.output_candidates[0].value, PAYMENT, "payment output");
    assert_eq!(
        tx.output_candidates[1].value,
        FEE + 500_000,
        "fee absorbs the sub-minimum change"
    );
    // Conservation: outputs sum to the single input's value.
    let out_sum: u64 = tx.output_candidates.iter().map(|o| o.value).sum();
    assert_eq!(out_sum, 100_500_000, "no ERG created or destroyed");
}

/// Sub-minimum change that CARRIES TOKENS is kept as a change box (tokens must
/// live somewhere), never folded into the fee — also mirrors Scala.
#[test]
fn builder_keeps_subminimum_change_box_when_it_carries_tokens() {
    const PAYMENT: u64 = 99_000_000;
    const FEE: u64 = 1_000_000;
    const MIN_BOX: u64 = 10_000_000;
    const TOKEN_ID: u8 = 0xBB;

    // Input: 100.5M ERG + 1000 tokens; send 99M ERG + 400 tokens. Change ERG is
    // 500_000 (< MIN_BOX) but it must carry the 600 token remainder.
    let available = vec![token_summary(8, 100_500_000, TOKEN_ID, 1_000)];
    let requests = [token_request(PAYMENT, TOKEN_ID, 400)];

    let tx = builder(&available, FEE, MIN_BOX)
        .build(&requests)
        .expect("token-bearing change build must succeed");

    // payment + fee + change (kept despite sub-minimum ERG, because of tokens).
    assert_eq!(
        tx.output_candidates.len(),
        3,
        "token-bearing change kept as a box, not folded into fee"
    );
    assert_eq!(tx.output_candidates[1].value, FEE, "fee unchanged");
    let change_out = &tx.output_candidates[2];
    assert_eq!(change_out.value, 500_000, "sub-minimum change box retained");
    let token_change: u64 = change_out
        .tokens
        .iter()
        .filter(|t| t.token_id.as_bytes() == &[TOKEN_ID; 32])
        .map(|t| t.amount)
        .sum();
    assert_eq!(token_change, 600, "token remainder preserved on change box");
}

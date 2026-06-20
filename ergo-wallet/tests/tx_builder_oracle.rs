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
        reemission: None,
        reemission_height: 0,
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

// ----- EIP-27 re-emission burn (auto-selection branch) -----

/// Re-emission token id used by the burn fixtures.
const REEMISSION_TOKEN: u8 = 0xCC;
/// A distinct, valid ErgoTree used as the pay-to-reemission contract so the burn
/// output is identifiable: version=0, body=Const(SBoolean=false) → `[0x00,0x01,0x00]`.
/// Different from `always_true_ergo_tree` (`[0x00,0x01,0x01]`), which the payment,
/// fee, and change outputs use, so the pay-to-reemission output stands out.
fn pay_to_reemission_tree() -> Vec<u8> {
    vec![0x00, 0x01, 0x00]
}

/// EIP-27 rules with activation at height 100.
fn reemission_rules() -> ergo_validation::ReemissionRuleInputs {
    ergo_validation::ReemissionRuleInputs {
        activation_height: 100,
        reemission_token_id: [REEMISSION_TOKEN; 32],
        pay_to_reemission_tree: pay_to_reemission_tree(),
    }
}

/// A burn-aware builder: re-emission rules present, obligation evaluated at
/// `reemission_height`.
fn burn_builder<'a>(
    available: &'a [BoxSummary],
    rules: &'a ergo_validation::ReemissionRuleInputs,
    fee: u64,
    min_box_value: u64,
    reemission_height: u32,
) -> UnsignedTxBuilder<'a> {
    UnsignedTxBuilder {
        available_summaries: available,
        selector: &DefaultBoxSelector,
        fee,
        fee_ergo_tree: always_true_ergo_tree(),
        change_ergo_tree: always_true_ergo_tree(),
        current_height: 1_000,
        min_box_value,
        data_inputs: vec![],
        reemission: Some(rules),
        reemission_height,
    }
}

/// Total re-emission tokens carried across all outputs (must be zero after a burn).
fn reemission_token_on_outputs(tx: &ergo_ser::transaction::UnsignedTransaction) -> u64 {
    tx.output_candidates
        .iter()
        .flat_map(|o| o.tokens.iter())
        .filter(|t| t.token_id.as_bytes() == &[REEMISSION_TOKEN; 32])
        .map(|t| t.amount)
        .sum()
}

/// nanoErg paid to the pay-to-reemission contract (outputs whose tree is the
/// pay-to-reemission tree).
fn paid_to_reemission(tx: &ergo_ser::transaction::UnsignedTransaction) -> u64 {
    let pay2r = pay_to_reemission_tree();
    tx.output_candidates
        .iter()
        .filter(|o| o.ergo_tree_bytes() == pay2r.as_slice())
        .map(|o| o.value)
        .sum()
}

/// ORACLE: auto-selecting a reward box (value <= the emission floor, carrying the
/// re-emission token) past activation must BURN the token (no output keeps it) and
/// pay exactly `to_burn` nanoErg to the pay-to-reemission contract — the structure
/// the consensus validator (`verify_reemission_spending`) requires. Mirrors the
/// explicit-input oracle in `wallet_bridge`, here through `UnsignedTxBuilder`.
#[test]
fn auto_select_reward_box_burns_and_pays_reemission() {
    const PAYMENT: u64 = 1_000_000_000; // 1 ERG
    const FEE: u64 = 1_000_000;
    const MIN_BOX: u64 = 1_000_000;
    // 15 ERG reward box (<= 100k ERG floor) carrying 12e9 re-emission tokens.
    const REWARD_VALUE: u64 = 15_000_000_000;
    const TOKEN_AMOUNT: u64 = 12_000_000_000; // → to_burn = 12e9 nanoErg

    let available = vec![token_summary(
        1,
        REWARD_VALUE,
        REEMISSION_TOKEN,
        TOKEN_AMOUNT,
    )];
    let rules = reemission_rules();
    // height 200 > activation 100 → burn triggers.
    let tx = burn_builder(&available, &rules, FEE, MIN_BOX, 200)
        .build(&[erg_request(PAYMENT)])
        .expect("burn-aware auto-select build must succeed");

    // (a) The token is burned: no output carries it.
    assert_eq!(
        reemission_token_on_outputs(&tx),
        0,
        "no output may keep the re-emission token"
    );
    // (b) Exactly `to_burn` nanoErg is paid to pay-to-reemission.
    assert_eq!(
        paid_to_reemission(&tx),
        TOKEN_AMOUNT,
        "must pay exactly to_burn nanoErg to pay-to-reemission"
    );
    // (c) Value is conserved: every input nanoErg lands on an output.
    let out_total: u64 = tx.output_candidates.iter().map(|o| o.value).sum();
    assert_eq!(out_total, REWARD_VALUE, "tx must conserve value");
}

/// Below/at activation the re-emission spending branch does NOT fire (Scala
/// `height > activationHeight` is strict): the surplus token is ordinary change,
/// kept on a change box, and nothing is paid to pay-to-reemission.
#[test]
fn auto_select_reward_box_at_activation_keeps_token_no_burn() {
    const PAYMENT: u64 = 1_000_000_000;
    const FEE: u64 = 1_000_000;
    const MIN_BOX: u64 = 1_000_000;
    const REWARD_VALUE: u64 = 15_000_000_000;
    const TOKEN_AMOUNT: u64 = 12_000_000_000;

    let available = vec![token_summary(
        1,
        REWARD_VALUE,
        REEMISSION_TOKEN,
        TOKEN_AMOUNT,
    )];
    let rules = reemission_rules();
    // height == activation 100 → NOT strictly above → no burn.
    let tx = burn_builder(&available, &rules, FEE, MIN_BOX, 100)
        .build(&[erg_request(PAYMENT)])
        .expect("build must succeed");

    assert_eq!(
        paid_to_reemission(&tx),
        0,
        "no burn at/below activation: nothing paid to pay-to-reemission"
    );
    assert_eq!(
        reemission_token_on_outputs(&tx),
        TOKEN_AMOUNT,
        "the surplus token is kept as ordinary change when the rule does not fire"
    );
}

/// Fixed-point reselection: when the burn-blind first selection leaves too little
/// change to fund the owed burn, the builder reserves the burn and reselects,
/// pulling in another input. The token:value ratio here is deliberately
/// exaggerated (5e8 tokens on a 1-ERG box) to force this path; real reward boxes
/// carry far fewer tokens than nanoErg and fund the burn from the first
/// selection's change.
#[test]
fn auto_select_burn_reselects_when_change_cannot_fund_it() {
    const PAYMENT: u64 = 900_000_000; // 0.9 ERG
    const FEE: u64 = 1_000_000;
    const MIN_BOX: u64 = 1_000_000;
    // Box A: 1 ERG reward box carrying 5e8 re-emission tokens (→ 5e8 nanoErg burn,
    // more than the 99e6 change the first A-only selection would leave).
    // Box B: 1 ERG ordinary box (no re-emission token) to cover the shortfall.
    let available = vec![
        token_summary(1, 1_000_000_000, REEMISSION_TOKEN, 500_000_000),
        erg_summary(2, 1_000_000_000),
    ];
    let rules = reemission_rules();
    let tx = burn_builder(&available, &rules, FEE, MIN_BOX, 200)
        .build(&[erg_request(PAYMENT)])
        .expect("build must reselect and succeed");

    // Reselection pulled in the second input to fund the burn.
    assert_eq!(
        tx.inputs.len(),
        2,
        "the burn reservation must reselect to cover the shortfall"
    );
    assert_eq!(reemission_token_on_outputs(&tx), 0, "token burned");
    assert_eq!(
        paid_to_reemission(&tx),
        500_000_000,
        "the full owed burn is paid to pay-to-reemission"
    );
    let in_total: u64 = 2_000_000_000;
    let out_total: u64 = tx.output_candidates.iter().map(|o| o.value).sum();
    assert_eq!(
        out_total, in_total,
        "tx must conserve value across both inputs"
    );
}

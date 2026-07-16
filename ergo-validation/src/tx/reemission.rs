//! EIP-27 re-emission spending validation.
//!
//! Port of the non-emission-box branch of the Scala reference's
//! `ErgoTransaction.verifyReemissionSpending`
//! (`ergo-core/.../mempool/ErgoTransaction.scala:225-331`), which runs
//! inside `validateStateful` — i.e. on both mempool admission and block
//! transaction validation.
//!
//! EIP-27 (re-emission) unlocks one re-emission token per block into the
//! mining-reward boxes after the activation height. When those reward
//! boxes are later spent, consensus requires the re-emission tokens to be
//! **burned** (carried on no output) and `1` nanoErg per burned token to
//! be paid to the pay-to-reemission contract. A node that does not enforce
//! this accepts transactions the Scala reference rejects — an
//! accept-invalid divergence (fork risk).
//!
//! Scope: this module enforces the **reemission-spending** branch (the
//! `else if` arm in the Scala source: an ordinary reward box, value
//! `<= 100_000` ERG, carrying re-emission tokens). The emission-box branch
//! (spending the emission box itself, value `> 100_000` ERG with the
//! emission NFT) is guarded by the emission contract during script
//! evaluation and needs the emission-curve math; it is intentionally not
//! reimplemented here. The value floor below means this check never
//! *triggers* on an emission-box spend, so omitting that branch cannot
//! cause a reject-valid divergence.

use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::transaction::Transaction;

use crate::error::ValidationError;

/// Coins (nanoErg) in one ERG. Scala `EmissionRules.CoinsInOneErgo`.
const COINS_IN_ONE_ERGO: u64 = 1_000_000_000;

/// Value floor (nanoErg) above which an input is treated as a candidate
/// emission box and routed to the emission-box branch rather than the
/// reemission-burn branch. Scala:
/// `box.value > 100000 * EmissionRules.CoinsInOneErgo`. The emission box
/// holds far more than 100K ERG until emission is nearly exhausted, so this
/// cleanly separates it from ordinary reward boxes without inspecting the
/// emission NFT.
const EMISSION_BOX_VALUE_FLOOR: u64 = 100_000 * COINS_IN_ONE_ERGO;

/// Network constants needed to enforce EIP-27 re-emission spending.
///
/// Sourced from [`ergo_chain_spec::ReemissionParams`] plus the
/// pay-to-reemission contract tree
/// (`ChainSpec::emission_script_trees().pay_to_reemission`). On networks
/// without EIP-27 (the public testnet, where `ChainSpec::reemission` is
/// `None`) no value is supplied and the rule is not enforced — matching
/// Scala's `checkReemissionRules` being effectively off there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReemissionRuleInputs {
    /// EIP-27 activation height. Scala `reemission.activationHeight`. The
    /// re-emission **spending** branch triggers strictly *above* this height
    /// (`height > activation_height`) — see [`reemission_obligation_core`] and
    /// [`verify_reemission_spending`]. (Reward boxes first carry the token from
    /// the activation height onward, but a *spend* of one is only constrained
    /// once `height` exceeds it.)
    pub activation_height: u32,
    /// 32-byte re-emission token id. Scala `reemission.reemissionTokenId`.
    pub reemission_token_id: [u8; 32],
    /// Serialized `ErgoTree` of the pay-to-reemission contract. Scala
    /// `reemissionRules.payToReemission`. Pay-to-reemission outputs are
    /// matched by `ErgoTree` structural equality against this (not by raw
    /// bytes) — see [`verify_reemission_spending`].
    pub pay_to_reemission_tree: Vec<u8>,
}

/// Enforce the EIP-27 re-emission burning condition on `tx`.
///
/// Mirrors the non-emission-box branch of Scala
/// `verifyReemissionSpending`. Returns `Ok(())` when the rule does not
/// apply (below activation, or no re-emission tokens spent from reward
/// boxes) and when the burning condition is satisfied.
///
/// The transaction is "spending re-emission tokens" when, at a height
/// strictly above the activation height, any spent input that is *not* an
/// emission box (value `<= 100_000` ERG) carries the re-emission token.
/// In that case consensus requires:
///
/// 1. **Burn:** no output carries the re-emission token, and
/// 2. **Pay-to-reemission:** the summed value of outputs whose `ergo_tree`
///    equals the pay-to-reemission contract equals the total re-emission
///    tokens summed across *all* inputs (1 nanoErg per token).
///
/// Pay-to-reemission outputs are matched the way Scala does — by `ErgoTree`
/// structural equality (`ErgoTree.equals`: raw header byte + constants +
/// root), **not** by serialized bytes. A non-canonically-encoded output that
/// parses to the same tree must still count (byte comparison would
/// reject-valid); conversely an output whose header byte differs only in a
/// reserved bit must NOT count (Scala keeps the raw header byte, which the
/// parsed form drops — so it is matched explicitly).
///
/// `resolved_inputs` must be index-aligned with `tx.inputs` (the validator
/// guarantees this upstream). `height` is the height of the block / tip the
/// transaction is being validated against (Scala `stateContext.currentHeight`).
pub fn verify_reemission_spending(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
    height: u32,
    rules: &ReemissionRuleInputs,
) -> Result<(), ValidationError> {
    let token_id = &rules.reemission_token_id;

    // Trigger + burn obligation via the shared [`reemission_obligation_core`], so
    // consensus and the wallet (builder + balance) compute the burn identically.
    // Triggered iff, strictly above activation, a non-emission input (value <=
    // 100K ERG floor) carries the re-emission token; once triggered, `to_burn`
    // sums the token across ALL inputs. The core subsumes the old
    // `height < activation_height` short-circuit (it returns not-triggered at or
    // below activation). Scala's emission-box branch (value > 100K ERG) never sets
    // the trigger; an emission box's re-emission tokens are governed there instead.
    let obligation = reemission_obligation_core(
        resolved_inputs.iter().map(|b| {
            (
                b.candidate.value,
                candidate_token_amount(&b.candidate, token_id),
            )
        }),
        height,
        rules.activation_height,
    );

    if !obligation.triggered {
        return Ok(());
    }

    // Total re-emission tokens across ALL inputs must be burned (paid out as
    // nanoErg to the pay-to-reemission contract).
    let to_burn: u64 = obligation.to_burn;

    // Parse the canonical pay-to-reemission contract once, so outputs can be
    // matched by `ErgoTree` structural equality (Scala semantics) rather than
    // serialized bytes. The tree is an oracle-pinned chain-spec constant that
    // always parses (asserted by `mainnet_pay_to_reemission_tree_parses`); a
    // parse failure here would mean a corrupt constant, surfaced as an error
    // rather than silently disabling the rule.
    let pay2r_tree =
        read_ergo_tree(&mut VlqReader::new(&rules.pay_to_reemission_tree)).map_err(|e| {
            ValidationError::ReemissionRulesViolated(format!(
                "pay-to-reemission contract tree failed to parse \
                 (corrupt chain-spec constant): {e}"
            ))
        })?;
    let pay2r_header = rules.pay_to_reemission_tree.first().copied();

    // Single pass over outputs: reject any output still carrying the
    // re-emission token (Scala's `require(!out.tokens.contains(...))` fires
    // for every output, before the burn-condition check), and accumulate the
    // ERG paid to the pay-to-reemission contract.
    let mut sent_to_reemission: u64 = 0;
    for out in &tx.output_candidates {
        if candidate_token_amount(out, token_id) > 0 {
            return Err(ValidationError::ReemissionRulesViolated(
                "an output carries the re-emission token (it must be burned)".to_string(),
            ));
        }
        // Scala mainnet: `out.ergoTree == payToReemissionContract`, where
        // `ErgoTree.equals` compares the raw header byte + constants + root.
        // The parsed-tree `==` covers (version/has_size/cseg, constants,
        // root); the raw-header-byte guard additionally distinguishes reserved
        // header bits, which the parsed form drops but Scala's header equality
        // keeps.
        if out.ergo_tree_bytes().first().copied() == pay2r_header && *out.ergo_tree() == pay2r_tree
        {
            sent_to_reemission = sent_to_reemission.saturating_add(out.value);
        }
    }

    if sent_to_reemission != to_burn {
        return Err(ValidationError::ReemissionRulesViolated(format!(
            "burning condition violated: {sent_to_reemission} nanoErg paid to \
             pay-to-reemission, but {to_burn} re-emission token(s) are being spent \
             (1 nanoErg per token is required)"
        )));
    }

    Ok(())
}

/// Sum the amount of `token_id` held by a box candidate. Within a valid box
/// token ids are unique, so this is a single matching entry's amount; the
/// sum is defensive against a degenerate duplicate-id box.
fn candidate_token_amount(c: &ErgoBoxCandidate, token_id: &[u8; 32]) -> u64 {
    c.tokens
        .iter()
        .filter(|t| t.token_id.as_bytes() == token_id)
        .map(|t| t.amount)
        .fold(0u64, |acc, v| acc.saturating_add(v))
}

/// The EXACT EIP-27 re-emission burn obligation over a set of boxes — the single
/// source of truth shared by the consensus validator
/// ([`verify_reemission_spending`]), the wallet transaction builder, and the
/// wallet balance surface. Each caller maps its boxes to
/// `(box_value_nanoerg, reemission_token_amount_in_box)` (token amount extracted
/// against [`ReemissionRuleInputs::reemission_token_id`]) and gets back the same
/// obligation, so the wallet figures can never drift from consensus.
///
/// Mirrors Scala `verifyReemissionSpending` exactly:
/// * **Triggered** when, at a height *strictly* above `activation_height`, ANY
///   non-emission input (value `<= EMISSION_BOX_VALUE_FLOOR`) carries the
///   re-emission token.
/// * Once triggered, `to_burn` is the re-emission token amount summed across
///   **ALL** input boxes — not only the floor boxes that triggered it (a
///   non-floor input co-spent with a triggering reward box still has its tokens
///   burned). 1 nanoErg per token is owed to the pay-to-reemission contract.
///
/// The balance surface uses the obligation over the wallet's whole confirmed box
/// set ("if you swept everything in one spend") so spendable ERG is never
/// over-reported; the builder uses it over the inputs a real spend selects.
pub fn reemission_obligation_core(
    boxes: impl IntoIterator<Item = (u64, u64)>,
    height: u32,
    activation_height: u32,
) -> ReemissionObligation {
    // Single pass: a non-emission floor box carrying the token sets the trigger;
    // every box's token amount accumulates into the would-be burn (summed
    // unconditionally, mirroring the validator's all-inputs `to_burn`).
    let mut triggered_by_floor_box = false;
    let mut total_tokens: u64 = 0;
    let mut token_box_count: u64 = 0;
    for (value, token_amount) in boxes {
        if token_amount > 0 {
            total_tokens = total_tokens.saturating_add(token_amount);
            token_box_count = token_box_count.saturating_add(1);
            if value <= EMISSION_BOX_VALUE_FLOOR {
                triggered_by_floor_box = true;
            }
        }
    }
    let triggered = height > activation_height && triggered_by_floor_box;
    if !triggered {
        return ReemissionObligation::default();
    }
    ReemissionObligation {
        triggered: true,
        to_burn: total_tokens,
        box_count: token_box_count,
    }
}

/// Result of [`reemission_obligation_core`]: the exact EIP-27 burn obligation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReemissionObligation {
    /// Whether the re-emission burn rule fires for this input set.
    pub triggered: bool,
    /// Re-emission token amount summed across ALL inputs (only meaningful when
    /// `triggered`). Equals the nanoErg owed to the pay-to-reemission contract
    /// (1 nanoErg per token). Zero when not triggered.
    pub to_burn: u64,
    /// Number of input boxes carrying the re-emission token (when triggered).
    pub box_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::token::Token;
    use ergo_ser::transaction::Transaction;

    // ----- helpers -----

    const ACTIVATION: u32 = 777_217;
    const REEMISSION_TOKEN: [u8; 32] = [0x11; 32];

    // ----- obligation core (shared validator/wallet helper) -----

    #[test]
    fn obligation_core_sums_triggering_reward_boxes() {
        // Two reward boxes (<= floor) with tokens + one ordinary box (no tokens):
        // triggered, to_burn = 4 + 6, box_count = 2.
        let boxes = [
            (2_000_000_000u64, 4u64),
            (1_000_000_000, 6),
            (5_000_000_000, 0),
        ];
        let o = reemission_obligation_core(boxes, ACTIVATION + 1, ACTIVATION);
        assert!(o.triggered);
        assert_eq!(o.to_burn, 10);
        assert_eq!(o.box_count, 2);
    }

    #[test]
    fn obligation_core_sums_all_inputs_including_non_floor_once_triggered() {
        // A floor reward box (value <= floor) carrying the token TRIGGERS the rule;
        // once triggered, the burn sums the token across ALL inputs — including the
        // non-floor box's tokens, mirroring the validator's all-inputs `to_burn`.
        // 12 + 5 = 17, two token-carrying boxes.
        let boxes = [
            (EMISSION_BOX_VALUE_FLOOR + 1, 12u64),
            (EMISSION_BOX_VALUE_FLOOR, 5),
        ];
        let o = reemission_obligation_core(boxes, ACTIVATION + 1, ACTIVATION);
        assert!(o.triggered);
        assert_eq!(o.to_burn, 17);
        assert_eq!(o.box_count, 2);
    }

    #[test]
    fn obligation_core_not_triggered_without_a_floor_token_box() {
        // Only a non-floor box carries the token (no floor reward box) → the rule
        // does NOT fire, so nothing is burned (matches the validator: no input at
        // or below the floor sets `reemissionSpending`).
        let boxes = [(EMISSION_BOX_VALUE_FLOOR + 1, 12u64)];
        assert_eq!(
            reemission_obligation_core(boxes, ACTIVATION + 1, ACTIVATION),
            ReemissionObligation::default()
        );
    }

    #[test]
    fn obligation_core_zero_at_or_below_activation() {
        // Strict `height > activation`: at exactly activation and below, not triggered.
        let boxes = [(1_000_000_000u64, 7u64)];
        assert_eq!(
            reemission_obligation_core(boxes, ACTIVATION, ACTIVATION),
            ReemissionObligation::default()
        );
        assert_eq!(
            reemission_obligation_core([(1u64, 7u64)], ACTIVATION - 1, ACTIVATION),
            ReemissionObligation::default()
        );
    }
    /// Real mainnet pay-to-reemission contract tree (valid; header byte 0x19).
    const PAY2R_HEX: &str = "193c03040004000e20d3feeffa87f2df63a7a15b4905e618ae3ce4c69a7975f171bd314d0b877927b8d1938cb2e4c6b2a5730000020c4d0e730100017302";
    /// A distinct, valid P2PK ErgoTree (header byte 0x00).
    const OTHER_HEX: &str =
        "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn pay2r_bytes() -> Vec<u8> {
        hex::decode(PAY2R_HEX).unwrap()
    }

    fn other_bytes() -> Vec<u8> {
        hex::decode(OTHER_HEX).unwrap()
    }

    fn rules() -> ReemissionRuleInputs {
        ReemissionRuleInputs {
            activation_height: ACTIVATION,
            reemission_token_id: REEMISSION_TOKEN,
            pay_to_reemission_tree: pay2r_bytes(),
        }
    }

    fn reemission_token(amount: u64) -> Token {
        Token {
            token_id: Digest32::from_bytes(REEMISSION_TOKEN),
            amount,
        }
    }

    /// Build an output candidate whose parsed `ergo_tree` and verbatim bytes
    /// both come from `tree_bytes` (so structural and byte views agree, as on
    /// a real box). `tree_bytes` MUST be a valid serialized ErgoTree.
    fn candidate(value: u64, tree_bytes: &[u8], tokens: Vec<Token>) -> ErgoBoxCandidate {
        let tree = read_ergo_tree(&mut VlqReader::new(tree_bytes)).expect("test tree must parse");
        ErgoBoxCandidate::from_trusted_raw_parts(
            value,
            tree,
            tree_bytes.to_vec(),
            0,
            tokens,
            AdditionalRegisters::empty(),
            vec![0u8],
        )
    }

    fn input_box(value: u64, tokens: Vec<Token>) -> ErgoBox {
        ErgoBox {
            candidate: candidate(value, &other_bytes(), tokens),
            transaction_id: ModifierId::from(Digest32::from_bytes([0x22; 32])),
            index: 0,
        }
    }

    fn tx(outputs: Vec<ErgoBoxCandidate>) -> Transaction {
        Transaction {
            inputs: vec![Input {
                box_id: Digest32::from_bytes([0x33; 32]),
                spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: outputs,
        }
    }

    // ----- happy path -----

    #[test]
    fn below_activation_height_is_noop() {
        // Reward box with re-emission tokens, but height below activation:
        // the rule does not apply even though tokens are kept on an output.
        let inputs = vec![input_box(2_000_000_000, vec![reemission_token(5)])];
        let t = tx(vec![candidate(
            1_000_000_000,
            &other_bytes(),
            vec![reemission_token(5)],
        )]);
        assert!(verify_reemission_spending(&t, &inputs, ACTIVATION - 1, &rules()).is_ok());
    }

    #[test]
    fn at_activation_height_is_noop() {
        // The reemission-spending branch requires height STRICTLY greater
        // than activation (Scala `height > activationHeight`). At exactly the
        // activation height the reward-box branch does not fire.
        let inputs = vec![input_box(2_000_000_000, vec![reemission_token(5)])];
        let t = tx(vec![candidate(
            1_000_000_000,
            &other_bytes(),
            vec![reemission_token(5)],
        )]);
        assert!(verify_reemission_spending(&t, &inputs, ACTIVATION, &rules()).is_ok());
    }

    #[test]
    fn no_reemission_tokens_spent_is_noop() {
        // Ordinary transfer above activation, no re-emission tokens anywhere.
        let inputs = vec![input_box(2_000_000_000, vec![])];
        let t = tx(vec![candidate(2_000_000_000, &other_bytes(), vec![])]);
        assert!(verify_reemission_spending(&t, &inputs, ACTIVATION + 1000, &rules()).is_ok());
    }

    #[test]
    fn correct_burn_and_payment_accepts() {
        // Reward box holding 7 re-emission tokens spent above activation:
        // burned (no output keeps them) and exactly 7 nanoErg paid to the
        // pay-to-reemission contract.
        let inputs = vec![input_box(3_000_000_000, vec![reemission_token(7)])];
        let t = tx(vec![
            candidate(2_999_999_993, &other_bytes(), vec![]),
            candidate(7, &pay2r_bytes(), vec![]),
        ]);
        assert!(verify_reemission_spending(&t, &inputs, ACTIVATION + 1, &rules()).is_ok());
    }

    #[test]
    fn correct_burn_summed_across_multiple_inputs() {
        // Two reward boxes (4 + 6 tokens) → 10 nanoErg owed to pay2reemission.
        let inputs = vec![
            input_box(1_000_000_000, vec![reemission_token(4)]),
            input_box(1_000_000_000, vec![reemission_token(6)]),
        ];
        let t = tx(vec![
            candidate(1_999_999_990, &other_bytes(), vec![]),
            candidate(10, &pay2r_bytes(), vec![]),
        ]);
        assert!(verify_reemission_spending(&t, &inputs, ACTIVATION + 5, &rules()).is_ok());
    }

    #[test]
    fn correct_burn_includes_non_floor_token_input() {
        // Regression at the CONSENSUS entry point (not just the helper): a
        // floor reward box (5 tokens, value == floor) TRIGGERS the rule; once
        // triggered, a co-spent NON-floor box also carrying the token (12,
        // value > floor) has its tokens burned too → 17 owed. Paying only the
        // floor box's 5 must reject; paying the full 17 must accept.
        let inputs = vec![
            input_box(EMISSION_BOX_VALUE_FLOOR, vec![reemission_token(5)]),
            input_box(EMISSION_BOX_VALUE_FLOOR + 1, vec![reemission_token(12)]),
        ];
        let underpaid = tx(vec![
            candidate(1_000, &other_bytes(), vec![]),
            candidate(5, &pay2r_bytes(), vec![]),
        ]);
        assert!(matches!(
            verify_reemission_spending(&underpaid, &inputs, ACTIVATION + 1, &rules()).unwrap_err(),
            ValidationError::ReemissionRulesViolated(_)
        ));
        let full = tx(vec![
            candidate(1_000, &other_bytes(), vec![]),
            candidate(17, &pay2r_bytes(), vec![]),
        ]);
        assert!(verify_reemission_spending(&full, &inputs, ACTIVATION + 1, &rules()).is_ok());
    }

    #[test]
    fn testnet_style_no_rules_means_caller_skips() {
        // When EIP-27 is disabled (no ReemissionRuleInputs) the caller never
        // invokes this function; sanity-check that a high activation height
        // (Scala testnet uses 100_000_001) makes any real height a no-op.
        let disabled = ReemissionRuleInputs {
            activation_height: 100_000_001,
            reemission_token_id: REEMISSION_TOKEN,
            pay_to_reemission_tree: pay2r_bytes(),
        };
        let inputs = vec![input_box(2_000_000_000, vec![reemission_token(5)])];
        let t = tx(vec![candidate(
            2_000_000_000,
            &other_bytes(),
            vec![reemission_token(5)],
        )]);
        assert!(verify_reemission_spending(&t, &inputs, 1_000_000, &disabled).is_ok());
    }

    // ----- error paths -----

    #[test]
    fn output_keeps_reemission_token_rejects() {
        // The exact double-violation shape of the witnessed mainnet tx: a
        // reward box is spent but an output keeps the re-emission token.
        let inputs = vec![input_box(3_000_000_000, vec![reemission_token(7)])];
        let t = tx(vec![
            candidate(2_999_999_993, &other_bytes(), vec![reemission_token(7)]),
            candidate(7, &pay2r_bytes(), vec![]),
        ]);
        let err = verify_reemission_spending(&t, &inputs, ACTIVATION + 1, &rules()).unwrap_err();
        assert!(matches!(err, ValidationError::ReemissionRulesViolated(_)));
    }

    #[test]
    fn underpayment_to_reemission_rejects() {
        // 7 tokens spent but only 6 nanoErg paid to pay-to-reemission.
        let inputs = vec![input_box(3_000_000_000, vec![reemission_token(7)])];
        let t = tx(vec![
            candidate(2_999_999_994, &other_bytes(), vec![]),
            candidate(6, &pay2r_bytes(), vec![]),
        ]);
        let err = verify_reemission_spending(&t, &inputs, ACTIVATION + 1, &rules()).unwrap_err();
        assert!(matches!(err, ValidationError::ReemissionRulesViolated(_)));
    }

    #[test]
    fn no_payment_to_reemission_rejects() {
        // Tokens burned (off all outputs) but nothing paid to pay2reemission.
        let inputs = vec![input_box(3_000_000_000, vec![reemission_token(7)])];
        let t = tx(vec![candidate(3_000_000_000, &other_bytes(), vec![])]);
        let err = verify_reemission_spending(&t, &inputs, ACTIVATION + 1, &rules()).unwrap_err();
        assert!(matches!(err, ValidationError::ReemissionRulesViolated(_)));
    }

    #[test]
    fn overpayment_to_reemission_rejects() {
        // Paying MORE than the burned token count is also a violation
        // (Scala requires exact equality).
        let inputs = vec![input_box(3_000_000_000, vec![reemission_token(7)])];
        let t = tx(vec![
            candidate(2_999_999_985, &other_bytes(), vec![]),
            candidate(15, &pay2r_bytes(), vec![]),
        ]);
        let err = verify_reemission_spending(&t, &inputs, ACTIVATION + 1, &rules()).unwrap_err();
        assert!(matches!(err, ValidationError::ReemissionRulesViolated(_)));
    }

    #[test]
    fn emission_box_value_input_does_not_trigger_reward_branch() {
        // An input above the 100K ERG floor carrying re-emission tokens is an
        // emission-box spend: it must NOT trigger the reward-box burn branch
        // (that branch is the emission contract's job). With no sub-100K-ERG
        // reward box also present, the rule is a no-op here.
        let inputs = vec![input_box(
            EMISSION_BOX_VALUE_FLOOR + 1,
            vec![reemission_token(5)],
        )];
        // Output keeps the token — would be rejected by the reward branch,
        // but the emission-box branch is out of scope, so this is accepted.
        let t = tx(vec![candidate(
            EMISSION_BOX_VALUE_FLOOR + 1,
            &other_bytes(),
            vec![reemission_token(5)],
        )]);
        assert!(verify_reemission_spending(&t, &inputs, ACTIVATION + 1, &rules()).is_ok());
    }

    #[test]
    fn reward_box_at_value_floor_triggers_branch() {
        // A box at exactly the floor (value <= floor) IS a reward box and
        // triggers the burn branch; keeping the token must be rejected.
        let inputs = vec![input_box(
            EMISSION_BOX_VALUE_FLOOR,
            vec![reemission_token(3)],
        )];
        let t = tx(vec![candidate(
            EMISSION_BOX_VALUE_FLOOR,
            &other_bytes(),
            vec![reemission_token(3)],
        )]);
        let err = verify_reemission_spending(&t, &inputs, ACTIVATION + 1, &rules()).unwrap_err();
        assert!(matches!(err, ValidationError::ReemissionRulesViolated(_)));
    }

    #[test]
    fn pay_to_reemission_matched_structurally_not_by_bytes() {
        // GENUINE byte-distinct-but-structurally-equal pay-to-reemission output.
        // The pay2r tree carries the size bit; the declared body size is an
        // upper bound, and both Scala and our reader accept trailing slack
        // inside the size region. So bumping the size by one and appending a
        // slack byte yields DIFFERENT bytes that parse to the IDENTICAL
        // ErgoTree (same header byte, constants, root). Scala counts it
        // (`out.ergoTree == payToReemissionContract`); a raw-byte comparison
        // would not, wrongly rejecting a tx Scala accepts (reject-valid). The
        // structural match must accept it.
        let mut p2r = pay2r_bytes();
        assert_eq!(p2r[0], 0x19, "pay2r canonical header has the size bit");
        assert!(p2r[1] < 0x7f, "single-byte size VLQ assumed");
        p2r[1] += 1; // declared body size + 1
        p2r.push(0x00); // trailing slack byte inside the size region

        let inputs = vec![input_box(3_000_000_000, vec![reemission_token(7)])];
        let t = tx(vec![
            candidate(2_999_999_993, &other_bytes(), vec![]),
            candidate(7, &p2r, vec![]),
        ]);
        // Sanity: the slack encoding is genuinely byte-distinct from canonical.
        assert_ne!(p2r, pay2r_bytes());
        assert!(verify_reemission_spending(&t, &inputs, ACTIVATION + 1, &rules()).is_ok());
    }

    #[test]
    fn reserved_header_bit_output_not_counted_as_pay2reemission() {
        // An output carrying the pay-to-reemission body but with a RESERVED
        // header bit set (0x19 -> 0x39) parses to the same ErgoTree (our reader
        // masks reserved bits) yet has a different raw header byte. Scala's
        // `ErgoTree.equals` compares the raw header byte, so it does NOT count
        // this output. We must match: the burn payment then falls short and the
        // tx is rejected — proving the raw-header-byte guard. A parsed-only
        // comparison would wrongly ACCEPT here (an accept-invalid divergence).
        let mut p2r = pay2r_bytes();
        assert_eq!(p2r[0], 0x19, "pay2r canonical header");
        p2r[0] = 0x39; // set reserved bit 0x20; version/size/cseg unchanged
        let inputs = vec![input_box(3_000_000_000, vec![reemission_token(7)])];
        let t = tx(vec![
            candidate(2_999_999_993, &other_bytes(), vec![]),
            candidate(7, &p2r, vec![]),
        ]);
        let err = verify_reemission_spending(&t, &inputs, ACTIVATION + 1, &rules()).unwrap_err();
        assert!(matches!(err, ValidationError::ReemissionRulesViolated(_)));
    }

    // ----- oracle parity -----

    #[test]
    fn mainnet_pay_to_reemission_tree_parses() {
        // The production rule parses `rules.pay_to_reemission_tree` once and
        // would surface a parse failure as a (reject-valid) error. Guard that
        // dead branch: the oracle-pinned mainnet chain-spec constant must always
        // parse, and the hardcoded test hex must match it.
        let trees = ergo_chain_spec::ChainSpec::mainnet()
            .emission_script_trees()
            .expect("mainnet emission trees");
        assert_eq!(
            trees.pay_to_reemission,
            pay2r_bytes(),
            "test PAY2R_HEX drifted from the chain-spec mainnet pay-to-reemission tree"
        );
        read_ergo_tree(&mut VlqReader::new(&trees.pay_to_reemission))
            .expect("mainnet pay-to-reemission tree must parse");
    }
}

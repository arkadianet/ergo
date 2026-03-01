//! Stateful transaction validation.
//!
//! Checks that require access to the input boxes from the UTXO set,
//! such as ERG preservation, token preservation, dust limits, and
//! creation height constraints.  Script execution is **not** performed
//! here (deferred to Phase 5).

use std::collections::HashMap;

use ergo_types::transaction::{
    BoxId, ErgoBox, ErgoTransaction, DEFAULT_MIN_VALUE_PER_BYTE, MAX_BOX_SIZE, MIN_BOX_VALUE,
};

use crate::validation_rules::{
    ValidationSettings, TX_BOX_PROPOSITION_SIZE, TX_BOX_SIZE, TX_DUST, TX_MONOTONIC_HEIGHT,
};

/// Errors produced by stateful transaction validation.
#[derive(Debug, thiserror::Error)]
pub enum TxStatefulError {
    #[error("ERG not preserved: inputs={inputs}, outputs={outputs}")]
    ErgNotPreserved { inputs: u64, outputs: u64 },

    #[error("token {token_id} not preserved: input={input_amount}, output={output_amount}")]
    TokenNotPreserved {
        token_id: BoxId,
        input_amount: u64,
        output_amount: u64,
    },

    #[error("output {idx} below dust limit: value={value}, min={min}")]
    DustOutput { idx: usize, value: u64, min: u64 },

    #[error("output {idx} total serialized size {size} bytes exceeds max {max}")]
    BoxTooLarge { idx: usize, size: usize, max: usize },

    #[error("output {idx} ergo_tree too large: {size} bytes")]
    ErgoTreeTooLarge { idx: usize, size: usize },

    #[error("output {idx} creation_height {height} exceeds block height {block_height}")]
    FutureCreationHeight {
        idx: usize,
        height: u32,
        block_height: u32,
    },

    #[error("output {idx} creation_height {output_height} below max input creation_height {max_input_height} (EIP-39)")]
    MonotonicHeightViolation {
        idx: usize,
        output_height: u32,
        max_input_height: u32,
    },

    #[error("input box {box_id} not found")]
    InputBoxNotFound { box_id: BoxId },

    #[error("input ERG sum overflow")]
    InputSumOverflow,

    #[error("output ERG sum overflow")]
    OutputSumOverflow,
}

/// Validate a transaction against the UTXO set (no script execution).
///
/// `input_boxes` must contain one [`ErgoBox`] for each input in the
/// transaction, in the same order as `tx.inputs`.
///
/// `min_value_per_byte` is the on-chain parameter (ID 2) that sets the
/// minimum nanoERG per serialized byte of output. Pass `0` or
/// [`DEFAULT_MIN_VALUE_PER_BYTE`] (360) if the parameter is not available.
pub fn validate_tx_stateful(
    tx: &ErgoTransaction,
    input_boxes: &[ErgoBox],
    block_height: u32,
    block_version: u8,
    min_value_per_byte: u64,
    settings: &ValidationSettings,
) -> Result<(), TxStatefulError> {
    // Verify that we have the right number of input boxes and they match.
    if input_boxes.len() != tx.inputs.len() {
        // If the lengths differ, find the first missing one.
        for input in &tx.inputs {
            if !input_boxes.iter().any(|b| b.box_id == input.box_id) {
                return Err(TxStatefulError::InputBoxNotFound {
                    box_id: input.box_id,
                });
            }
        }
    }

    // 1. txErgPreservation: sum(input values) == sum(output values)
    let input_erg_sum: u64 = input_boxes
        .iter()
        .try_fold(0u64, |acc, b| acc.checked_add(b.candidate.value))
        .ok_or(TxStatefulError::InputSumOverflow)?;
    let output_erg_sum: u64 = tx
        .output_candidates
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or(TxStatefulError::OutputSumOverflow)?;
    if input_erg_sum != output_erg_sum {
        return Err(TxStatefulError::ErgNotPreserved {
            inputs: input_erg_sum,
            outputs: output_erg_sum,
        });
    }

    // 2. txAssetsPreservation: for each token, output <= input.
    //    New tokens may only be minted with token_id == first input's box_id.
    let first_input_box_id = input_boxes[0].box_id;

    // Collect input token totals.
    let mut input_tokens: HashMap<BoxId, u64> = HashMap::new();
    for b in input_boxes {
        for &(ref token_id, amount) in &b.candidate.tokens {
            *input_tokens.entry(*token_id).or_insert(0) += amount;
        }
    }

    // Collect output token totals.
    let mut output_tokens: HashMap<BoxId, u64> = HashMap::new();
    for out in &tx.output_candidates {
        for &(ref token_id, amount) in &out.tokens {
            *output_tokens.entry(*token_id).or_insert(0) += amount;
        }
    }

    // Check each output token is covered by inputs (or is newly minted from first input).
    for (&token_id, &output_amount) in &output_tokens {
        let input_amount = input_tokens.get(&token_id).copied().unwrap_or(0);
        if output_amount > input_amount {
            // Allow minting only if token_id == first input's box_id.
            if token_id == first_input_box_id {
                // New token minting is allowed — skip this token.
                continue;
            }
            return Err(TxStatefulError::TokenNotPreserved {
                token_id,
                input_amount,
                output_amount,
            });
        }
    }

    // 3. txDust (rule 111, soft-forkable): each output value >= max(serialized_size * min_value_per_byte, MIN_BOX_VALUE)
    //
    // The Scala reference computes: box.bytes.length * Parameters.MinValuePerByte
    // We use the estimated serialized size of the box candidate to compute the
    // dynamic minimum, floored at MIN_BOX_VALUE (the absolute minimum for any box).
    if settings.is_active(TX_DUST) {
        let effective_mvpb = if min_value_per_byte == 0 {
            DEFAULT_MIN_VALUE_PER_BYTE
        } else {
            min_value_per_byte
        };
        for (idx, out) in tx.output_candidates.iter().enumerate() {
            let serialized_size = out.estimated_serialized_size() as u64;
            let dynamic_min = serialized_size.saturating_mul(effective_mvpb);
            let min_value = dynamic_min.max(MIN_BOX_VALUE);
            if out.value < min_value {
                return Err(TxStatefulError::DustOutput {
                    idx,
                    value: out.value,
                    min: min_value,
                });
            }
        }
    }

    // 4a. txBoxSize (rule 120, soft-forkable): total serialized box <= MAX_BOX_SIZE
    if settings.is_active(TX_BOX_SIZE) {
        for (idx, out) in tx.output_candidates.iter().enumerate() {
            let total_size = out.estimated_serialized_size();
            if total_size > MAX_BOX_SIZE {
                return Err(TxStatefulError::BoxTooLarge {
                    idx,
                    size: total_size,
                    max: MAX_BOX_SIZE,
                });
            }
        }
    }

    // 4b. txBoxPropositionSize (rule 121, soft-forkable): each ergo_tree_bytes.len() <= MAX_BOX_SIZE
    if settings.is_active(TX_BOX_PROPOSITION_SIZE) {
        for (idx, out) in tx.output_candidates.iter().enumerate() {
            if out.ergo_tree_bytes.len() > MAX_BOX_SIZE {
                return Err(TxStatefulError::ErgoTreeTooLarge {
                    idx,
                    size: out.ergo_tree_bytes.len(),
                });
            }
        }
    }

    // 5. txFuture: each creation_height <= block_height
    for (idx, out) in tx.output_candidates.iter().enumerate() {
        if out.creation_height > block_height {
            return Err(TxStatefulError::FutureCreationHeight {
                idx,
                height: out.creation_height,
                block_height,
            });
        }
    }

    // 6. txMonotonicHeight (rule 124, EIP-39): for block version >= 3,
    // each output's creation_height must be >= max(input creation heights).
    if settings.is_active(TX_MONOTONIC_HEIGHT) && block_version >= 3 {
        let max_input_creation_height = input_boxes
            .iter()
            .map(|b| b.candidate.creation_height)
            .max()
            .unwrap_or(0);

        for (idx, out) in tx.output_candidates.iter().enumerate() {
            if out.creation_height < max_input_creation_height {
                return Err(TxStatefulError::MonotonicHeightViolation {
                    idx,
                    output_height: out.creation_height,
                    max_input_height: max_input_creation_height,
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation_rules::ValidationSettings;
    use ergo_types::transaction::{ErgoBoxCandidate, Input, TxId};

    /// Shorthand for initial validation settings (all rules active).
    fn vs() -> ValidationSettings {
        ValidationSettings::initial()
    }

    /// Create a `BoxId` where every byte is `fill`.
    fn box_id(fill: u8) -> BoxId {
        BoxId([fill; 32])
    }

    /// Create a minimal `Input` with a given `BoxId`.
    fn make_input(id: BoxId) -> Input {
        Input {
            box_id: id,
            proof_bytes: Vec::new(),
            extension_bytes: Vec::new(),
        }
    }

    /// Create a minimal valid `ErgoBoxCandidate` with the given value.
    fn make_candidate(value: u64) -> ErgoBoxCandidate {
        ErgoBoxCandidate {
            value,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        }
    }

    /// Create an `ErgoBox` from a candidate, tx_id, index, and box_id.
    fn make_ergo_box(value: u64, bid: BoxId) -> ErgoBox {
        ErgoBox {
            candidate: make_candidate(value),
            transaction_id: TxId([0x00; 32]),
            index: 0,
            box_id: bid,
        }
    }

    /// Build a minimal valid transaction + matching input boxes.
    fn valid_tx_and_boxes() -> (ErgoTransaction, Vec<ErgoBox>) {
        let bid = box_id(0x01);
        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![make_candidate(1_000_000_000)],
            tx_id: TxId([0xaa; 32]),
        };
        let input_boxes = vec![make_ergo_box(1_000_000_000, bid)];
        (tx, input_boxes)
    }

    // ── Test 1: valid tx passes (ERG preserved, no tokens) ────────────

    #[test]
    fn valid_tx_no_tokens_passes() {
        let (tx, boxes) = valid_tx_and_boxes();
        assert!(
            validate_tx_stateful(&tx, &boxes, 200_000, 1, DEFAULT_MIN_VALUE_PER_BYTE, &vs())
                .is_ok()
        );
    }

    // ── Test 2: ERG not preserved → ErgNotPreserved ───────────────────

    #[test]
    fn erg_not_preserved() {
        let (mut tx, boxes) = valid_tx_and_boxes();
        // Output more than input
        tx.output_candidates[0].value = 2_000_000_000;
        let err = validate_tx_stateful(&tx, &boxes, 200_000, 1, DEFAULT_MIN_VALUE_PER_BYTE, &vs())
            .unwrap_err();
        assert!(
            matches!(
                err,
                TxStatefulError::ErgNotPreserved {
                    inputs: 1_000_000_000,
                    outputs: 2_000_000_000,
                }
            ),
            "expected ErgNotPreserved, got {err:?}"
        );
    }

    // ── Test 3: token not preserved (more output than input) ──────────

    #[test]
    fn token_not_preserved() {
        let bid1 = box_id(0x01);
        let bid2 = box_id(0x02);
        let token_id = box_id(0xAA);

        let mut box1 = make_ergo_box(500_000_000, bid1);
        box1.candidate.tokens = vec![(token_id, 100)];

        let box2 = make_ergo_box(500_000_000, bid2);

        let mut out = make_candidate(1_000_000_000);
        out.tokens = vec![(token_id, 200)]; // 200 > 100 input

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid1), make_input(bid2)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xbb; 32]),
        };

        let err = validate_tx_stateful(
            &tx,
            &[box1, box2],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &vs(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                TxStatefulError::TokenNotPreserved {
                    input_amount: 100,
                    output_amount: 200,
                    ..
                }
            ),
            "expected TokenNotPreserved, got {err:?}"
        );
    }

    // ── Test 4: new token minted from first input's box_id → passes ──

    #[test]
    fn new_token_minted_from_first_input_passes() {
        let bid1 = box_id(0x01);
        let box1 = make_ergo_box(1_000_000_000, bid1);

        // Mint a new token with token_id == first input's box_id
        let mut out = make_candidate(1_000_000_000);
        out.tokens = vec![(bid1, 1000)];

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid1)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xcc; 32]),
        };

        assert!(
            validate_tx_stateful(&tx, &[box1], 200_000, 1, DEFAULT_MIN_VALUE_PER_BYTE, &vs())
                .is_ok()
        );
    }

    // ── Test 5: new token minted from non-first input → error ─────────

    #[test]
    fn new_token_minted_from_non_first_input_fails() {
        let bid1 = box_id(0x01);
        let bid2 = box_id(0x02);

        let box1 = make_ergo_box(500_000_000, bid1);
        let box2 = make_ergo_box(500_000_000, bid2);

        // Try to mint a token with token_id == second input's box_id
        let mut out = make_candidate(1_000_000_000);
        out.tokens = vec![(bid2, 500)];

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid1), make_input(bid2)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xdd; 32]),
        };

        let err = validate_tx_stateful(
            &tx,
            &[box1, box2],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &vs(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                TxStatefulError::TokenNotPreserved {
                    input_amount: 0,
                    output_amount: 500,
                    ..
                }
            ),
            "expected TokenNotPreserved, got {err:?}"
        );
    }

    // ── Test 6: dust output ───────────────────────────────────────────

    #[test]
    fn dust_output_rejected() {
        let bid = box_id(0x01);
        let box1 = make_ergo_box(1_000_000_000, bid);

        let dust_value = MIN_BOX_VALUE - 1; // 10_799
        let remaining = 1_000_000_000 - dust_value;

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![make_candidate(remaining), make_candidate(dust_value)],
            tx_id: TxId([0xee; 32]),
        };

        // Fix the creation_height to be valid
        let err = validate_tx_stateful(&tx, &[box1], 200_000, 1, DEFAULT_MIN_VALUE_PER_BYTE, &vs())
            .unwrap_err();
        assert!(
            matches!(
                err,
                TxStatefulError::DustOutput {
                    idx: 1,
                    value,
                    min,
                } if value == dust_value && min == MIN_BOX_VALUE
            ),
            "expected DustOutput, got {err:?}"
        );
    }

    // ── Test 7: ErgoTree too large ────────────────────────────────────

    #[test]
    fn ergo_tree_too_large_rejected() {
        use crate::validation_rules::{ValidationSettingsUpdate, TX_BOX_SIZE};

        let bid = box_id(0x01);
        let box1 = make_ergo_box(1_000_000_000, bid);

        let mut out = make_candidate(1_000_000_000);
        out.ergo_tree_bytes = vec![0x00; MAX_BOX_SIZE + 1];

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xff; 32]),
        };

        // Disable rule 120 (total box size) so rule 121 (proposition size) fires.
        // With both active, rule 120 fires first since the total box is also too large.
        let settings_no_120 = ValidationSettings::initial().updated(&ValidationSettingsUpdate {
            rules_to_disable: vec![TX_BOX_SIZE, TX_DUST],
            ..Default::default()
        });

        let err = validate_tx_stateful(
            &tx,
            &[box1],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &settings_no_120,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                TxStatefulError::ErgoTreeTooLarge {
                    idx: 0,
                    size,
                } if size == MAX_BOX_SIZE + 1
            ),
            "expected ErgoTreeTooLarge, got {err:?}"
        );
    }

    // ── Test 8: future creation height ────────────────────────────────

    #[test]
    fn future_creation_height_rejected() {
        let bid = box_id(0x01);
        let box1 = make_ergo_box(1_000_000_000, bid);

        let mut out = make_candidate(1_000_000_000);
        out.creation_height = 300_000; // exceeds block_height of 200_000

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0x11; 32]),
        };

        let err = validate_tx_stateful(&tx, &[box1], 200_000, 1, DEFAULT_MIN_VALUE_PER_BYTE, &vs())
            .unwrap_err();
        assert!(
            matches!(
                err,
                TxStatefulError::FutureCreationHeight {
                    idx: 0,
                    height: 300_000,
                    block_height: 200_000,
                }
            ),
            "expected FutureCreationHeight, got {err:?}"
        );
    }

    // ── Test 9: valid tx with tokens passes ───────────────────────────

    #[test]
    fn valid_tx_with_tokens_passes() {
        let bid1 = box_id(0x01);
        let bid2 = box_id(0x02);
        let token_a = box_id(0xA0);
        let token_b = box_id(0xB0);

        let mut box1 = make_ergo_box(600_000_000, bid1);
        box1.candidate.tokens = vec![(token_a, 1000), (token_b, 500)];

        let mut box2 = make_ergo_box(400_000_000, bid2);
        box2.candidate.tokens = vec![(token_a, 200)];

        // Outputs: split ERG, preserve tokens (can output less than input)
        let mut out1 = make_candidate(500_000_000);
        out1.tokens = vec![(token_a, 800)]; // 800 <= 1200

        let mut out2 = make_candidate(500_000_000);
        out2.tokens = vec![(token_a, 400), (token_b, 300)]; // a: 400 (total 1200), b: 300 <= 500

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid1), make_input(bid2)],
            data_inputs: Vec::new(),
            output_candidates: vec![out1, out2],
            tx_id: TxId([0x22; 32]),
        };

        assert!(validate_tx_stateful(
            &tx,
            &[box1, box2],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &vs()
        )
        .is_ok());
    }

    // ── Test 10: multiple token types all preserved → passes ──────────

    #[test]
    fn multiple_token_types_all_preserved_passes() {
        let bid = box_id(0x01);
        let token_a = box_id(0xA1);
        let token_b = box_id(0xB1);
        let token_c = box_id(0xC1);

        let mut input_box = make_ergo_box(1_000_000_000, bid);
        input_box.candidate.tokens = vec![(token_a, 10_000), (token_b, 5_000), (token_c, 1)];

        // Distribute all three token types across two outputs
        let mut out1 = make_candidate(700_000_000);
        out1.tokens = vec![(token_a, 6_000), (token_b, 3_000)];

        let mut out2 = make_candidate(300_000_000);
        out2.tokens = vec![(token_a, 4_000), (token_b, 2_000), (token_c, 1)];

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out1, out2],
            tx_id: TxId([0x33; 32]),
        };

        assert!(validate_tx_stateful(
            &tx,
            &[input_box],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &vs()
        )
        .is_ok());
    }

    // ── Test 11: dynamic dust — large box needs more than MIN_BOX_VALUE ──

    #[test]
    fn dynamic_dust_large_box_rejected() {
        let bid = box_id(0x01);

        // Create a large output box (big ergo_tree) that requires more than MIN_BOX_VALUE.
        // A 200-byte ergo_tree at 360 nanoERGs/byte ~ 200 * 360 = ~72,000+ dynamic min.
        let large_tree = vec![0x00; 200];
        let large_out = ErgoBoxCandidate {
            value: 15_000, // above MIN_BOX_VALUE but below dynamic min
            ergo_tree_bytes: large_tree,
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };

        // Compute expected dynamic minimum for this output.
        let expected_size = large_out.estimated_serialized_size() as u64;
        let expected_min = (expected_size * DEFAULT_MIN_VALUE_PER_BYTE).max(MIN_BOX_VALUE);
        assert!(
            expected_min > MIN_BOX_VALUE,
            "expected dynamic min ({expected_min}) > floor ({MIN_BOX_VALUE})"
        );
        assert!(
            large_out.value < expected_min,
            "value ({}) should be below dynamic min ({expected_min})",
            large_out.value
        );

        let input_total = large_out.value;
        let box1 = make_ergo_box(input_total, bid);

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![large_out],
            tx_id: TxId([0xf1; 32]),
        };

        let err = validate_tx_stateful(&tx, &[box1], 200_000, 1, DEFAULT_MIN_VALUE_PER_BYTE, &vs())
            .unwrap_err();
        assert!(
            matches!(
                err,
                TxStatefulError::DustOutput {
                    idx: 0,
                    value: 15_000,
                    min,
                } if min == expected_min
            ),
            "expected DustOutput with dynamic min={expected_min}, got {err:?}"
        );
    }

    // ── Test 12: dynamic dust — large box with sufficient value passes ──

    #[test]
    fn dynamic_dust_large_box_sufficient_value_passes() {
        let bid = box_id(0x01);

        // Use a generous value first to compute the size at realistic VLQ encoding.
        let large_tree = vec![0x00; 200];
        let mut out = ErgoBoxCandidate {
            value: 1_000_000_000, // placeholder, will be replaced
            ergo_tree_bytes: large_tree,
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };

        // Compute the dynamic minimum using the estimated size at realistic value.
        let estimated_size = out.estimated_serialized_size() as u64;
        let dynamic_min = (estimated_size * DEFAULT_MIN_VALUE_PER_BYTE).max(MIN_BOX_VALUE);

        // Set value to generously above the dynamic minimum.
        out.value = dynamic_min + 10_000;

        let box1 = make_ergo_box(out.value, bid);

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xf2; 32]),
        };

        assert!(
            validate_tx_stateful(&tx, &[box1], 200_000, 1, DEFAULT_MIN_VALUE_PER_BYTE, &vs())
                .is_ok()
        );
    }

    // ── Test 13: dynamic dust — box with tokens needs higher min ──

    #[test]
    fn dynamic_dust_box_with_tokens_rejected() {
        let bid = box_id(0x01);
        let token_a = box_id(0xA0);
        let token_b = box_id(0xB0);

        // A box with 2 tokens is significantly larger than a bare box.
        // Each token adds 32+VLQ bytes. At 360/byte this can be substantial.
        let out_with_tokens = ErgoBoxCandidate {
            value: MIN_BOX_VALUE, // bare floor, but too small for this larger box
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: vec![(token_a, 1000), (token_b, 500)],
            additional_registers: Vec::new(),
        };

        let expected_size = out_with_tokens.estimated_serialized_size() as u64;
        let dynamic_min = (expected_size * DEFAULT_MIN_VALUE_PER_BYTE).max(MIN_BOX_VALUE);

        // If dynamic_min > MIN_BOX_VALUE, the box is too cheap.
        if dynamic_min > MIN_BOX_VALUE {
            let mut input_box = make_ergo_box(MIN_BOX_VALUE, bid);
            input_box.candidate.tokens = vec![(token_a, 1000), (token_b, 500)];

            let tx = ErgoTransaction {
                inputs: vec![make_input(bid)],
                data_inputs: Vec::new(),
                output_candidates: vec![out_with_tokens],
                tx_id: TxId([0xf3; 32]),
            };

            let err = validate_tx_stateful(
                &tx,
                &[input_box],
                200_000,
                1,
                DEFAULT_MIN_VALUE_PER_BYTE,
                &vs(),
            )
            .unwrap_err();
            assert!(
                matches!(err, TxStatefulError::DustOutput { idx: 0, .. }),
                "expected DustOutput for box with tokens, got {err:?}"
            );
        }
    }

    // ── Test 14: min_value_per_byte=0 uses default ──

    #[test]
    fn min_value_per_byte_zero_uses_default() {
        // When 0 is passed, we should use the default (360).
        let bid = box_id(0x01);
        let large_tree = vec![0x00; 200];
        let large_out = ErgoBoxCandidate {
            value: 15_000,
            ergo_tree_bytes: large_tree,
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        };

        let box1 = make_ergo_box(15_000, bid);

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![large_out],
            tx_id: TxId([0xf4; 32]),
        };

        // min_value_per_byte = 0 should behave same as DEFAULT_MIN_VALUE_PER_BYTE.
        let err = validate_tx_stateful(&tx, &[box1], 200_000, 1, 0, &vs()).unwrap_err();
        assert!(
            matches!(err, TxStatefulError::DustOutput { idx: 0, .. }),
            "expected DustOutput when min_value_per_byte=0, got {err:?}"
        );
    }

    // ── Test 15: disabled dust rule allows tiny output ──

    #[test]
    fn disabled_dust_rule_allows_tiny_output() {
        use crate::validation_rules::{ValidationSettingsUpdate, TX_DUST};

        // Create ValidationSettings with TX_DUST disabled.
        let disabled_vs = ValidationSettings::initial().updated(&ValidationSettingsUpdate {
            rules_to_disable: vec![TX_DUST],
            ..Default::default()
        });
        // Verify is_active returns false.
        assert!(!disabled_vs.is_active(TX_DUST));

        // Build a transaction with a dust output (below MIN_BOX_VALUE).
        let bid = box_id(0x01);
        let box1 = make_ergo_box(1_000_000_000, bid);

        let dust_value = MIN_BOX_VALUE - 1; // 10_799
        let remaining = 1_000_000_000 - dust_value;

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![make_candidate(remaining), make_candidate(dust_value)],
            tx_id: TxId([0xd0; 32]),
        };

        // With TX_DUST active, this should fail.
        let err = validate_tx_stateful(
            &tx,
            &[box1.clone()],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &vs(),
        );
        assert!(
            matches!(err, Err(TxStatefulError::DustOutput { .. })),
            "expected DustOutput with active TX_DUST, got {err:?}"
        );

        // With TX_DUST disabled, this should pass.
        let result = validate_tx_stateful(
            &tx,
            &[box1],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &disabled_vs,
        );
        assert!(
            result.is_ok(),
            "expected Ok with disabled TX_DUST, got {result:?}"
        );
    }

    // ── Test 16: disabled proposition size rule allows oversized tree ──

    #[test]
    fn disabled_proposition_size_rule_allows_oversized_tree() {
        use crate::validation_rules::{
            ValidationSettingsUpdate, TX_BOX_PROPOSITION_SIZE, TX_BOX_SIZE,
        };

        let bid = box_id(0x01);
        let box1 = make_ergo_box(1_000_000_000, bid);

        let mut out = make_candidate(1_000_000_000);
        out.ergo_tree_bytes = vec![0x00; MAX_BOX_SIZE + 1];

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xd1; 32]),
        };

        // With all rules active, rule 120 (total box size) fires first since the
        // total box is also oversized when the ErgoTree exceeds MAX_BOX_SIZE.
        let err = validate_tx_stateful(
            &tx,
            &[box1.clone()],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &vs(),
        );
        assert!(
            matches!(err, Err(TxStatefulError::BoxTooLarge { .. })),
            "expected BoxTooLarge with active rules, got {err:?}"
        );

        // With TX_BOX_SIZE disabled, rule 121 (proposition size) should fire.
        let only_121 = ValidationSettings::initial().updated(&ValidationSettingsUpdate {
            rules_to_disable: vec![TX_BOX_SIZE, TX_DUST],
            ..Default::default()
        });
        let err = validate_tx_stateful(
            &tx,
            &[box1.clone()],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &only_121,
        );
        assert!(
            matches!(err, Err(TxStatefulError::ErgoTreeTooLarge { .. })),
            "expected ErgoTreeTooLarge with rule 120 disabled, got {err:?}"
        );

        // With both rules disabled (120 + 121 + dust), the oversized box should pass.
        let all_disabled = ValidationSettings::initial().updated(&ValidationSettingsUpdate {
            rules_to_disable: vec![TX_BOX_SIZE, TX_BOX_PROPOSITION_SIZE, TX_DUST],
            ..Default::default()
        });
        let result = validate_tx_stateful(
            &tx,
            &[box1],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &all_disabled,
        );
        assert!(
            result.is_ok(),
            "expected Ok with both box size rules disabled, got {result:?}"
        );
    }

    // ── Test 17: estimated_serialized_size sanity ──

    #[test]
    fn estimated_serialized_size_sanity() {
        // Verify that the estimated size is reasonable.
        let tiny_box = make_candidate(1_000_000);
        let size = tiny_box.estimated_serialized_size();
        // A minimal box with 3-byte tree, no tokens, no registers should be small.
        assert!(
            (8..=20).contains(&size),
            "tiny box estimated size {size} out of expected range [8, 20]"
        );

        // A box with large tree should be proportionally larger.
        let big_tree_box = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00; 500],
            creation_height: 100_000,
            tokens: vec![(box_id(0xAA), 1000)],
            additional_registers: Vec::new(),
        };
        let big_size = big_tree_box.estimated_serialized_size();
        assert!(
            big_size > 530,
            "big-tree box estimated size {big_size} should be > 530"
        );
    }

    // ── Test: box too large (total size, rule 120) ──────────────────

    #[test]
    fn box_too_large_total_size_rejected() {
        let settings = ValidationSettings::initial();
        let bid = box_id(0x01);

        // Build a box with small ErgoTree but many tokens to inflate total
        // serialized size past MAX_BOX_SIZE (4096).
        // Each token adds ~34 bytes (32-byte ID + VLQ amount ~2 bytes).
        // 130 tokens × ~34 bytes ≈ 4420 + base overhead > 4096.
        let many_tokens: Vec<(BoxId, u64)> = (0..130u32)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = (i & 0xFF) as u8;
                id[1] = ((i >> 8) & 0xFF) as u8;
                (BoxId(id), 1000)
            })
            .collect();

        let out = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd], // small ErgoTree (3 bytes)
            creation_height: 100_000,
            tokens: many_tokens.clone(),
            additional_registers: Vec::new(),
        };

        // Verify our assumption: total size exceeds MAX_BOX_SIZE but ErgoTree does not.
        assert!(
            out.estimated_serialized_size() > MAX_BOX_SIZE,
            "expected estimated size {} > MAX_BOX_SIZE {MAX_BOX_SIZE}",
            out.estimated_serialized_size()
        );
        assert!(
            out.ergo_tree_bytes.len() <= MAX_BOX_SIZE,
            "ErgoTree should be small"
        );

        // Give the input box enough tokens to cover output tokens.
        let mut input_box = make_ergo_box(1_000_000_000, bid);
        input_box.candidate.tokens = many_tokens;

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xF5; 32]),
        };

        let result = validate_tx_stateful(
            &tx,
            &[input_box],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &settings,
        );
        assert!(
            matches!(result, Err(TxStatefulError::BoxTooLarge { idx: 0, .. })),
            "expected BoxTooLarge, got {result:?}"
        );
    }

    #[test]
    fn box_normal_size_passes_rule_120() {
        // A normal transaction should pass both rule 120 and rule 121.
        let (tx, boxes) = valid_tx_and_boxes();
        let settings = ValidationSettings::initial();
        let result = validate_tx_stateful(
            &tx,
            &boxes,
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &settings,
        );
        assert!(
            result.is_ok(),
            "expected Ok for normal-sized box, got {result:?}"
        );
    }

    #[test]
    fn disabled_box_size_rule_allows_oversized_box() {
        use crate::validation_rules::{ValidationSettingsUpdate, TX_BOX_SIZE};

        let bid = box_id(0x01);

        // Build an oversized box (many tokens).
        let many_tokens: Vec<(BoxId, u64)> = (0..130u32)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = (i & 0xFF) as u8;
                id[1] = ((i >> 8) & 0xFF) as u8;
                (BoxId(id), 1000)
            })
            .collect();

        let out = ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: many_tokens.clone(),
            additional_registers: Vec::new(),
        };

        let mut input_box = make_ergo_box(1_000_000_000, bid);
        input_box.candidate.tokens = many_tokens;

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xF6; 32]),
        };

        // With TX_BOX_SIZE active → BoxTooLarge
        let settings = ValidationSettings::initial();
        let result = validate_tx_stateful(
            &tx,
            &[input_box.clone()],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &settings,
        );
        assert!(
            matches!(result, Err(TxStatefulError::BoxTooLarge { .. })),
            "expected BoxTooLarge with active rule, got {result:?}"
        );

        // With TX_BOX_SIZE disabled → passes rule 120 (but dust check still fires,
        // so disable TX_DUST as well).
        let disabled_vs = ValidationSettings::initial().updated(&ValidationSettingsUpdate {
            rules_to_disable: vec![TX_BOX_SIZE, TX_DUST],
            ..Default::default()
        });
        let result = validate_tx_stateful(
            &tx,
            &[input_box],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &disabled_vs,
        );
        assert!(
            result.is_ok(),
            "expected Ok with disabled TX_BOX_SIZE, got {result:?}"
        );
    }

    // ── Test 18: monotonic height not enforced for v2 ────────────────

    #[test]
    fn monotonic_height_not_enforced_for_v2() {
        let settings = ValidationSettings::initial();
        let bid = box_id(0x01);

        // Input box with creation_height=200
        let mut input_box = make_ergo_box(1_000_000_000, bid);
        input_box.candidate.creation_height = 200;

        // Output with creation_height=100 (below input's 200)
        let mut out = make_candidate(1_000_000_000);
        out.creation_height = 100;

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xE1; 32]),
        };

        // For v2, monotonic height is NOT enforced → should pass
        let result = validate_tx_stateful(
            &tx,
            &[input_box],
            5000,
            2,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &settings,
        );
        assert!(
            result.is_ok(),
            "expected Ok for v2 (monotonic not enforced), got {result:?}"
        );
    }

    // ── Test 19: monotonic height enforced for v3 ────────────────────

    #[test]
    fn monotonic_height_enforced_for_v3() {
        let settings = ValidationSettings::initial();
        let bid = box_id(0x01);

        // Input box with creation_height=200
        let mut input_box = make_ergo_box(1_000_000_000, bid);
        input_box.candidate.creation_height = 200;

        // Output with creation_height=100 (below input's 200) → rejected for v3
        let mut out = make_candidate(1_000_000_000);
        out.creation_height = 100;

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xE2; 32]),
        };

        let result = validate_tx_stateful(
            &tx,
            &[input_box],
            5000,
            3,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &settings,
        );
        assert!(
            matches!(
                result,
                Err(TxStatefulError::MonotonicHeightViolation {
                    idx: 0,
                    output_height: 100,
                    max_input_height: 200
                })
            ),
            "expected MonotonicHeightViolation for v3, got {result:?}"
        );
    }

    // ── Test 20: monotonic height passes when equal ──────────────────

    #[test]
    fn monotonic_height_passes_when_equal() {
        let settings = ValidationSettings::initial();
        let bid = box_id(0x01);

        // Input box with creation_height=300
        let mut input_box = make_ergo_box(1_000_000_000, bid);
        input_box.candidate.creation_height = 300;

        // Output with creation_height=300 (equal to input) → OK
        let mut out = make_candidate(1_000_000_000);
        out.creation_height = 300;

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xE3; 32]),
        };

        let result = validate_tx_stateful(
            &tx,
            &[input_box],
            5000,
            3,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &settings,
        );
        assert!(
            result.is_ok(),
            "expected Ok when creation_height == max_input_height, got {result:?}"
        );
    }

    // ── Test 21: monotonic height passes when higher ─────────────────

    #[test]
    fn monotonic_height_passes_when_higher() {
        let settings = ValidationSettings::initial();
        let bid = box_id(0x01);

        // Input box with creation_height=300
        let mut input_box = make_ergo_box(1_000_000_000, bid);
        input_box.candidate.creation_height = 300;

        // Output with creation_height=500 (above input's 300) → OK
        let mut out = make_candidate(1_000_000_000);
        out.creation_height = 500;

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out],
            tx_id: TxId([0xE4; 32]),
        };

        let result = validate_tx_stateful(
            &tx,
            &[input_box],
            5000,
            3,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &settings,
        );
        assert!(
            result.is_ok(),
            "expected Ok when creation_height > max_input_height, got {result:?}"
        );
    }

    // ── Test 22: input sum overflow → InputSumOverflow ──────────────

    #[test]
    fn input_sum_overflow_rejected() {
        let bid1 = box_id(0x01);
        let bid2 = box_id(0x02);
        let box1 = make_ergo_box(u64::MAX, bid1);
        let box2 = make_ergo_box(1, bid2);

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid1), make_input(bid2)],
            data_inputs: Vec::new(),
            output_candidates: vec![make_candidate(1_000_000_000)],
            tx_id: TxId([0xF0; 32]),
        };

        let err = validate_tx_stateful(
            &tx,
            &[box1, box2],
            200_000,
            1,
            DEFAULT_MIN_VALUE_PER_BYTE,
            &vs(),
        )
        .unwrap_err();
        assert!(
            matches!(err, TxStatefulError::InputSumOverflow),
            "expected InputSumOverflow, got {err:?}"
        );
    }

    // ── Test 23: output sum overflow → OutputSumOverflow ────────────

    #[test]
    fn output_sum_overflow_rejected() {
        let bid = box_id(0x01);
        let box1 = make_ergo_box(u64::MAX, bid);

        let mut out1 = make_candidate(u64::MAX);
        let mut out2 = make_candidate(1);
        // Ensure creation_height is valid
        out1.creation_height = 100_000;
        out2.creation_height = 100_000;

        let tx = ErgoTransaction {
            inputs: vec![make_input(bid)],
            data_inputs: Vec::new(),
            output_candidates: vec![out1, out2],
            tx_id: TxId([0xF1; 32]),
        };

        let err = validate_tx_stateful(&tx, &[box1], 200_000, 1, DEFAULT_MIN_VALUE_PER_BYTE, &vs())
            .unwrap_err();
        assert!(
            matches!(err, TxStatefulError::OutputSumOverflow),
            "expected OutputSumOverflow, got {err:?}"
        );
    }
}

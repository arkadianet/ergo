//! Stateless transaction validation.
//!
//! Checks that are purely structural and do not require access to
//! blockchain state (UTXO set, headers, etc.).

use std::collections::HashSet;

use ergo_types::transaction::{
    BoxId, ErgoTransaction, MAX_DATA_INPUTS, MAX_INPUTS, MAX_OUTPUTS, MAX_TOKENS_PER_BOX,
};

use crate::validation_rules::ValidationSettings;

/// Errors produced by stateless transaction validation.
#[derive(Debug, thiserror::Error)]
pub enum TxValidationError {
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("too many inputs: {0}")]
    TooManyInputs(usize),
    #[error("too many data inputs: {0}")]
    TooManyDataInputs(usize),
    #[error("too many outputs: {0}")]
    TooManyOutputs(usize),
    #[error("zero output value at index {0}")]
    ZeroOutputValue(usize),
    #[error("output sum overflow")]
    OutputSumOverflow,
    #[error("duplicate input box_id: {0}")]
    DuplicateInput(BoxId),
    #[error("too many tokens in box at index {output_idx}: {count}")]
    TooManyTokensInBox { output_idx: usize, count: usize },
    #[error("non-positive token amount at output index {0}")]
    NonPositiveTokenAmount(usize),
    #[error("token amount overflow")]
    TokenAmountOverflow,
}

/// Validate a transaction without any blockchain state.
///
/// This performs the following checks in order:
/// 1. Transaction must have at least one input.
/// 2. Transaction must have at least one output.
/// 3. Number of inputs must not exceed `MAX_INPUTS`.
/// 4. Number of data inputs must not exceed `MAX_DATA_INPUTS`.
/// 5. Number of outputs must not exceed `MAX_OUTPUTS`.
/// 6. Every output must have a non-zero value.
/// 7. The sum of output values must not overflow or exceed `i64::MAX`.
/// 8. All input box IDs must be unique.
/// 9. Each output box must not carry more than `MAX_TOKENS_PER_BOX` tokens.
/// 10. Every token amount in every output must be non-zero.
pub fn validate_tx_stateless(
    tx: &ErgoTransaction,
    _settings: &ValidationSettings,
) -> Result<(), TxValidationError> {
    // 1. txNoInputs
    if tx.inputs.is_empty() {
        return Err(TxValidationError::NoInputs);
    }
    // 2. txNoOutputs
    if tx.output_candidates.is_empty() {
        return Err(TxValidationError::NoOutputs);
    }
    // 3. txManyInputs
    if tx.inputs.len() > MAX_INPUTS {
        return Err(TxValidationError::TooManyInputs(tx.inputs.len()));
    }
    // 4. txManyDataInputs
    if tx.data_inputs.len() > MAX_DATA_INPUTS {
        return Err(TxValidationError::TooManyDataInputs(tx.data_inputs.len()));
    }
    // 5. txManyOutputs
    if tx.output_candidates.len() > MAX_OUTPUTS {
        return Err(TxValidationError::TooManyOutputs(
            tx.output_candidates.len(),
        ));
    }
    // 6. txNegativeOutput (zero value is invalid since u64 can't be negative)
    for (i, out) in tx.output_candidates.iter().enumerate() {
        if out.value == 0 {
            return Err(TxValidationError::ZeroOutputValue(i));
        }
    }
    // 7. txOutputSum — sum must not overflow and must fit in i64
    let mut sum: u64 = 0;
    for out in &tx.output_candidates {
        sum = sum
            .checked_add(out.value)
            .ok_or(TxValidationError::OutputSumOverflow)?;
    }
    if sum > i64::MAX as u64 {
        return Err(TxValidationError::OutputSumOverflow);
    }
    // 8. txInputsUnique
    let mut seen = HashSet::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        if !seen.insert(input.box_id) {
            return Err(TxValidationError::DuplicateInput(input.box_id));
        }
    }
    // 9. txAssetsInOneBox + 10. txPositiveAssets
    for (i, out) in tx.output_candidates.iter().enumerate() {
        if out.tokens.len() > MAX_TOKENS_PER_BOX {
            return Err(TxValidationError::TooManyTokensInBox {
                output_idx: i,
                count: out.tokens.len(),
            });
        }
        for &(_, amount) in &out.tokens {
            if amount == 0 {
                return Err(TxValidationError::NonPositiveTokenAmount(i));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation_rules::ValidationSettings;
    use ergo_types::transaction::{
        DataInput, ErgoBoxCandidate, Input, TxId,
    };

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

    /// Create a minimal valid `ErgoBoxCandidate` with the given value and no tokens.
    fn make_output(value: u64) -> ErgoBoxCandidate {
        ErgoBoxCandidate {
            value,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        }
    }

    /// Build a minimal valid transaction (1 input, 1 output).
    fn valid_tx() -> ErgoTransaction {
        ErgoTransaction {
            inputs: vec![make_input(box_id(0x01))],
            data_inputs: Vec::new(),
            output_candidates: vec![make_output(1_000_000_000)],
            tx_id: TxId([0xaa; 32]),
        }
    }

    /// Create a `BoxId` from two bytes (high, low) with the remaining bytes zeroed.
    /// This allows creating up to 65536 distinct IDs efficiently.
    fn sequential_box_id(index: u16) -> BoxId {
        let mut bytes = [0u8; 32];
        bytes[0] = (index >> 8) as u8;
        bytes[1] = (index & 0xff) as u8;
        BoxId(bytes)
    }

    // ── Test 1: valid transaction passes ────────────────────────────────

    #[test]
    fn valid_transaction_passes() {
        assert!(validate_tx_stateless(&valid_tx(), &vs()).is_ok());
    }

    // ── Test 2: no inputs ───────────────────────────────────────────────

    #[test]
    fn no_inputs_rejected() {
        let mut tx = valid_tx();
        tx.inputs.clear();
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(err, TxValidationError::NoInputs),
            "expected NoInputs, got {err:?}"
        );
    }

    // ── Test 3: no outputs ──────────────────────────────────────────────

    #[test]
    fn no_outputs_rejected() {
        let mut tx = valid_tx();
        tx.output_candidates.clear();
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(err, TxValidationError::NoOutputs),
            "expected NoOutputs, got {err:?}"
        );
    }

    // ── Test 4: too many inputs ─────────────────────────────────────────

    #[test]
    fn too_many_inputs_rejected() {
        let count = MAX_INPUTS + 1; // 32768
        let inputs: Vec<Input> = (0..count as u16)
            .map(|i| make_input(sequential_box_id(i)))
            .collect();
        let tx = ErgoTransaction {
            inputs,
            data_inputs: Vec::new(),
            output_candidates: vec![make_output(1_000_000)],
            tx_id: TxId([0xaa; 32]),
        };
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(err, TxValidationError::TooManyInputs(n) if n == count),
            "expected TooManyInputs({count}), got {err:?}"
        );
    }

    // ── Test 5: too many data inputs ────────────────────────────────────

    #[test]
    fn too_many_data_inputs_rejected() {
        let count = MAX_DATA_INPUTS + 1;
        let data_inputs: Vec<DataInput> = (0..count as u16)
            .map(|i| DataInput {
                box_id: sequential_box_id(i),
            })
            .collect();
        let tx = ErgoTransaction {
            inputs: vec![make_input(box_id(0x01))],
            data_inputs,
            output_candidates: vec![make_output(1_000_000)],
            tx_id: TxId([0xaa; 32]),
        };
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(err, TxValidationError::TooManyDataInputs(n) if n == count),
            "expected TooManyDataInputs({count}), got {err:?}"
        );
    }

    // ── Test 6: too many outputs ────────────────────────────────────────

    #[test]
    fn too_many_outputs_rejected() {
        let count = MAX_OUTPUTS + 1;
        let outputs: Vec<ErgoBoxCandidate> = (0..count).map(|_| make_output(1_000)).collect();
        let tx = ErgoTransaction {
            inputs: vec![make_input(box_id(0x01))],
            data_inputs: Vec::new(),
            output_candidates: outputs,
            tx_id: TxId([0xaa; 32]),
        };
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(err, TxValidationError::TooManyOutputs(n) if n == count),
            "expected TooManyOutputs({count}), got {err:?}"
        );
    }

    // ── Test 7: zero output value ───────────────────────────────────────

    #[test]
    fn zero_output_value_rejected() {
        let mut tx = valid_tx();
        tx.output_candidates[0].value = 0;
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(err, TxValidationError::ZeroOutputValue(0)),
            "expected ZeroOutputValue(0), got {err:?}"
        );
    }

    // ── Test 8: output sum overflow ─────────────────────────────────────

    #[test]
    fn output_sum_overflow_rejected() {
        let tx = ErgoTransaction {
            inputs: vec![make_input(box_id(0x01))],
            data_inputs: Vec::new(),
            output_candidates: vec![
                make_output(i64::MAX as u64),
                make_output(1), // pushes past i64::MAX
            ],
            tx_id: TxId([0xaa; 32]),
        };
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(err, TxValidationError::OutputSumOverflow),
            "expected OutputSumOverflow, got {err:?}"
        );
    }

    // ── Test 9: duplicate input box_id ──────────────────────────────────

    #[test]
    fn duplicate_input_rejected() {
        let dup_id = box_id(0x42);
        let tx = ErgoTransaction {
            inputs: vec![make_input(dup_id), make_input(dup_id)],
            data_inputs: Vec::new(),
            output_candidates: vec![make_output(1_000_000)],
            tx_id: TxId([0xaa; 32]),
        };
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(err, TxValidationError::DuplicateInput(id) if id == dup_id),
            "expected DuplicateInput, got {err:?}"
        );
    }

    // ── Test 10: too many tokens in one box ─────────────────────────────

    #[test]
    fn too_many_tokens_in_box_rejected() {
        let token_count = 123; // exceeds MAX_TOKENS_PER_BOX (122)
        let tokens: Vec<(BoxId, u64)> = (0..token_count)
            .map(|i| (sequential_box_id(i as u16), 1))
            .collect();
        let mut tx = valid_tx();
        tx.output_candidates[0].tokens = tokens;
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(
                err,
                TxValidationError::TooManyTokensInBox {
                    output_idx: 0,
                    count: 123,
                }
            ),
            "expected TooManyTokensInBox, got {err:?}"
        );
    }

    // ── Test 11: zero token amount ──────────────────────────────────────

    #[test]
    fn zero_token_amount_rejected() {
        let mut tx = valid_tx();
        tx.output_candidates[0].tokens = vec![(box_id(0x01), 0)];
        let err = validate_tx_stateless(&tx, &vs()).unwrap_err();
        assert!(
            matches!(err, TxValidationError::NonPositiveTokenAmount(0)),
            "expected NonPositiveTokenAmount(0), got {err:?}"
        );
    }

    // ── Test 12: valid tx with tokens, data inputs, multiple outputs ────

    #[test]
    fn valid_tx_with_tokens_data_inputs_multiple_outputs_passes() {
        let tx = ErgoTransaction {
            inputs: vec![
                make_input(box_id(0x01)),
                make_input(box_id(0x02)),
            ],
            data_inputs: vec![
                DataInput {
                    box_id: box_id(0x10),
                },
                DataInput {
                    box_id: box_id(0x11),
                },
            ],
            output_candidates: vec![
                ErgoBoxCandidate {
                    value: 1_000_000_000,
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                    creation_height: 100_000,
                    tokens: vec![
                        (box_id(0xa0), 500),
                        (box_id(0xa1), 1_000_000),
                    ],
                    additional_registers: Vec::new(),
                },
                ErgoBoxCandidate {
                    value: 500_000,
                    ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
                    creation_height: 100_001,
                    tokens: vec![(box_id(0xb0), 1)],
                    additional_registers: vec![(4, vec![0x05, 0x00])],
                },
                make_output(10_800),
            ],
            tx_id: TxId([0xcc; 32]),
        };
        assert!(validate_tx_stateless(&tx, &vs()).is_ok());
    }
}

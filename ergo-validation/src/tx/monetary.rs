use std::collections::HashMap;

use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::token::TokenId;
use ergo_ser::transaction::Transaction;

use crate::error::ValidationError;

/// Validate ERG and token conservation for a transaction.
/// Requires resolved input boxes.
pub fn validate_monetary(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
) -> Result<(), ValidationError> {
    check_erg_conservation(tx, resolved_inputs)?;
    check_token_conservation(tx, resolved_inputs)?;
    Ok(())
}

fn check_erg_conservation(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
) -> Result<(), ValidationError> {
    let input_sum: u64 = resolved_inputs
        .iter()
        .map(|b| b.candidate.value)
        .try_fold(0u64, |acc, v| acc.checked_add(v))
        .ok_or(ValidationError::ErgNotConserved {
            inputs: u64::MAX,
            outputs: 0,
        })?;

    let output_sum: u64 = tx
        .output_candidates
        .iter()
        .map(|c| c.value)
        .try_fold(0u64, |acc, v| acc.checked_add(v))
        .ok_or(ValidationError::ErgNotConserved {
            inputs: input_sum,
            outputs: u64::MAX,
        })?;

    if input_sum < output_sum {
        return Err(ValidationError::ErgNotConserved {
            inputs: input_sum,
            outputs: output_sum,
        });
    }
    Ok(())
}

fn check_token_conservation(
    tx: &Transaction,
    resolved_inputs: &[ErgoBox],
) -> Result<(), ValidationError> {
    let mut input_tokens: HashMap<TokenId, u64> = HashMap::new();
    for b in resolved_inputs {
        for token in &b.candidate.tokens {
            let entry = input_tokens.entry(token.token_id).or_insert(0);
            *entry = entry.checked_add(token.amount).ok_or_else(|| {
                ValidationError::TokenNotConserved {
                    token_id: hex::encode(token.token_id.as_bytes()),
                    input: u64::MAX,
                    output: 0,
                }
            })?;
        }
    }

    let mut output_tokens: HashMap<TokenId, u64> = HashMap::new();
    for out in &tx.output_candidates {
        for token in &out.tokens {
            let entry = output_tokens.entry(token.token_id).or_insert(0);
            *entry = entry.checked_add(token.amount).ok_or_else(|| {
                ValidationError::TokenNotConserved {
                    token_id: hex::encode(token.token_id.as_bytes()),
                    input: 0,
                    output: u64::MAX,
                }
            })?;
        }
    }

    // Token minting: first input's box ID can be used as a new token ID
    let minting_token_id = resolved_inputs.first().and_then(|b| match b.box_id() {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::warn!(error = ?e, "monetary: failed to compute minting token id from first input");
            None
        }
    });

    for (token_id, output_amount) in &output_tokens {
        match input_tokens.get(token_id) {
            Some(input_amount) if output_amount <= input_amount => {}
            Some(input_amount) => {
                return Err(ValidationError::TokenNotConserved {
                    token_id: hex::encode(token_id.as_bytes()),
                    input: *input_amount,
                    output: *output_amount,
                });
            }
            None => {
                let is_minting = minting_token_id.as_ref().is_some_and(|mid| mid == token_id);
                if !is_minting {
                    return Err(ValidationError::InvalidMinting {
                        token_id: hex::encode(token_id.as_bytes()),
                    });
                }
            }
        }
    }

    Ok(())
}

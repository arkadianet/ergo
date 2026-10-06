//! Scala 6.0.7 `txDataInputsUnique` (rule 110).
//!
//! From the activation height a transaction may repeat at most one data
//! input: Scala accepts `distinct == n` or `distinct + 1 == n`, where `n` is
//! the number of data inputs. `DataInput` equality compares the box id bytes.
//! <https://github.com/ergoplatform/ergo/blob/v6.0.7/ergo-core/src/main/scala/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala#L427-L435>
//! <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/org/ergoplatform/Input.scala#L15-L24>

use std::collections::HashSet;

use ergo_ser::transaction::Transaction;

use crate::error::ValidationError;

/// Scala 6.0.7 `ErgoTransaction.DataInputsUniquenessHeight`. The same height
/// applies on every network. It is compared with the height of the block that
/// contains the transaction (the predicted next height for the mempool).
/// <https://github.com/ergoplatform/ergo/blob/v6.0.7/ergo-core/src/main/scala/org/ergoplatform/modifiers/mempool/ErgoTransaction.scala#L515-L519>
pub const DATA_INPUTS_UNIQUENESS_HEIGHT: u32 = 1_885_000;

/// Rule 110: reject more than one repeated data input once active.
pub fn validate_data_inputs_unique(tx: &Transaction, height: u32) -> Result<(), ValidationError> {
    if height < DATA_INPUTS_UNIQUENESS_HEIGHT {
        return Ok(());
    }
    let count = tx.data_inputs.len();
    let distinct = tx
        .data_inputs
        .iter()
        .map(|d| d.box_id)
        .collect::<HashSet<_>>()
        .len();
    if distinct + 1 >= count {
        Ok(())
    } else {
        Err(ValidationError::DuplicateDataInputs { count, distinct })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::Digest32;
    use ergo_ser::input::DataInput;

    fn tx(ids: &[u8]) -> Transaction {
        Transaction {
            inputs: vec![],
            data_inputs: ids
                .iter()
                .map(|&b| DataInput {
                    box_id: Digest32::from_bytes([b; 32]),
                })
                .collect(),
            output_candidates: vec![],
        }
    }

    // ----- activation -----

    #[test]
    fn any_repetition_passes_below_activation() {
        let tx = tx(&[1, 1, 1, 2, 2]);
        assert!(validate_data_inputs_unique(&tx, DATA_INPUTS_UNIQUENESS_HEIGHT - 1).is_ok());
        assert!(validate_data_inputs_unique(&tx, DATA_INPUTS_UNIQUENESS_HEIGHT).is_err());
    }

    // ----- Scala's distinct + 1 bound -----

    #[test]
    fn at_most_one_repeated_data_input_after_activation() {
        let height = DATA_INPUTS_UNIQUENESS_HEIGHT;
        for ok in [
            &[][..],
            &[1],
            &[1, 2, 3],
            &[1, 1],
            &[1, 2, 1],
            &[3, 1, 2, 2],
        ] {
            assert!(
                validate_data_inputs_unique(&tx(ok), height).is_ok(),
                "{ok:?}"
            );
        }
        for (bad, distinct) in [
            (&[1, 1, 1][..], 1),
            (&[1, 1, 2, 2], 2),
            (&[1, 2, 1, 2, 3], 3),
        ] {
            assert!(
                matches!(
                    validate_data_inputs_unique(&tx(bad), height + 1),
                    Err(ValidationError::DuplicateDataInputs { count, distinct: d })
                        if count == bad.len() && d == distinct
                ),
                "{bad:?}"
            );
        }
    }
}

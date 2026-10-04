use super::*;
use ergo_ser::transaction::Transaction;
use ergo_validation::ValidationError;

// ----- helpers -----

fn transaction() -> Transaction {
    Transaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![],
    }
}

// ----- happy path -----

#[test]
fn failed_tx_indexed_cost_error_resolves_transaction_id() {
    let tx = transaction();
    let expected = *ergo_ser::transaction::transaction_id(&tx)
        .unwrap()
        .as_bytes();
    let error = BlockProcessError::with_transactions(
        BlockValidationError::Transaction {
            index: 0,
            error: ValidationError::CostExceeded {
                current: 2,
                limit: 1,
            },
        },
        &[tx],
    );
    assert!(
        matches!(error, BlockProcessError::TransactionValidation { tx_id, .. } if tx_id == expected)
    );
}

// ----- round-trips -----

// ----- error paths -----

#[test]
fn failed_tx_out_of_range_index_retains_unnamed_verdict() {
    let error = BlockProcessError::with_transactions(
        BlockValidationError::Transaction {
            index: 1,
            error: ValidationError::NoInputs,
        },
        &[transaction()],
    );
    assert!(matches!(
        error,
        BlockProcessError::Validation(BlockValidationError::Transaction { index: 1, .. })
    ));
}

#[test]
fn failed_tx_unserializable_transaction_retains_unnamed_verdict() {
    let mut tx = transaction();
    tx.data_inputs = vec![
        ergo_ser::input::DataInput {
            box_id: ergo_primitives::digest::Digest32::from_bytes([0; 32]),
        };
        usize::from(u16::MAX) + 1
    ];
    let error = BlockProcessError::with_transactions(
        BlockValidationError::Transaction {
            index: 0,
            error: ValidationError::NoInputs,
        },
        &[tx],
    );
    assert!(matches!(error, BlockProcessError::Validation(_)));
}

// ----- oracle parity -----

#[test]
fn failed_tx_aggregate_block_cost_does_not_name_transaction() {
    let error = BlockProcessError::with_transactions(
        BlockValidationError::BlockCostExceeded { total: 2, limit: 1 },
        &[transaction()],
    );
    assert!(matches!(
        error,
        BlockProcessError::Validation(BlockValidationError::BlockCostExceeded { .. })
    ));
}

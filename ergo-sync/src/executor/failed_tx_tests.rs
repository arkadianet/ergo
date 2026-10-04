use super::*;
use ergo_validation::block::BlockValidationError;
use ergo_validation::ValidationError;

// ----- helpers -----

fn executor() -> SyncExecutor {
    SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    )
}

// ----- happy path -----

#[test]
fn failed_tx_batch_drain_preserves_every_named_transaction() {
    let mut executor = executor();
    for tx_id in [[1; 32], [2; 32]] {
        executor.record_failed_transaction(&BlockProcessError::TransactionValidation {
            tx_id,
            source: BlockValidationError::Transaction {
                index: 0,
                error: ValidationError::NoInputs,
            },
        });
    }
    assert_eq!(executor.take_failed_transactions(), vec![[1; 32], [2; 32]]);
    assert!(executor.take_failed_transactions().is_empty());
}

// ----- round-trips -----

// ----- error paths -----

#[test]
fn failed_tx_unnamed_block_failure_emits_nothing() {
    let mut executor = executor();
    executor.record_failed_transaction(&BlockProcessError::AdProofsHashMismatch {
        header_id: [1; 32],
        declared_root: [2; 32],
        computed_root: [3; 32],
    });
    assert!(executor.take_failed_transactions().is_empty());
}

// ----- oracle parity -----

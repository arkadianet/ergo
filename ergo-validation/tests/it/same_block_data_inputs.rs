//! Same-block box visibility in UTXO-mode full-block validation.
//!
//! Scala's `UtxoState.applyTransactions` resolves inputs and data inputs
//! through `createdOutputs = transactions.flatMap(_.outputs)` before the
//! pre-block state, and `StateChanges.operations` runs every data-input
//! lookup first, where a lookup never fails. A data input may therefore name
//! an output of a later transaction in the same block. A forward spend still
//! fails, because its removal runs before the producing insertion.

use ergo_validation::block::BlockValidationError;
use ergo_validation::context::ProtocolParams;
use ergo_validation::error::ValidationError;

use super::synthetic_block::{first_output_id, pre_block_box, tx, validate_both, MapUtxo};

fn v1_params() -> ProtocolParams {
    ProtocolParams {
        block_version: 1,
        ..ProtocolParams::mainnet_default()
    }
}

#[test]
fn data_input_may_name_a_later_transactions_output() {
    let a = pre_block_box(1, 0, 100);
    let b = pre_block_box(2, 0, 100);
    let utxo = MapUtxo::of(&[&a, &b]);
    let producer = tx(vec![b.box_id().unwrap()], vec![], 100);
    let reader = tx(
        vec![a.box_id().unwrap()],
        vec![first_output_id(&producer)],
        100,
    );

    for result in validate_both(vec![reader, producer], &utxo, 1, &v1_params()) {
        assert!(
            result.is_ok(),
            "a forward data read must validate: {result:?}"
        );
    }
}

#[test]
fn input_may_not_spend_a_later_transactions_output() {
    let a = pre_block_box(1, 0, 100);
    let b = pre_block_box(2, 0, 100);
    let utxo = MapUtxo::of(&[&a, &b]);
    let producer = tx(vec![b.box_id().unwrap()], vec![], 100);
    let produced = first_output_id(&producer);
    let spender = tx(vec![a.box_id().unwrap(), produced], vec![], 100);

    for result in validate_both(vec![spender, producer], &utxo, 1, &v1_params()) {
        match result {
            Err(BlockValidationError::Transaction {
                index: 0,
                error: ValidationError::InputBoxNotFound { box_id },
            }) => assert_eq!(box_id, hex::encode(produced.as_bytes())),
            other => panic!("a forward spend must not resolve: {other:?}"),
        }
    }
}

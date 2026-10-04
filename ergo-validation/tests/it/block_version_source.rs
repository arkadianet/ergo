//! Which version gates a block's transaction rules.
//!
//! Scala validates a block's transactions against
//! `stateContext.blockVersion = currentParameters.blockVersion`: the
//! activated script version is `blockVersion - 1` (`ErgoContext`) and
//! `txMonotonicHeight` keys on the same value (`ErgoTransaction`).
//! `exBlockVersion` (rule 410) ties those parameters to `header.version` only
//! at epoch starts, so a mid-epoch header may carry another version byte.

use ergo_validation::block::BlockValidationError;
use ergo_validation::context::ProtocolParams;
use ergo_validation::error::ValidationError;

use super::synthetic_block::{pre_block_box, tx, validate_both, MapUtxo, HEIGHT};

fn params(block_version: u8) -> ProtocolParams {
    ProtocolParams {
        block_version,
        ..ProtocolParams::mainnet_default()
    }
}

#[test]
fn monotonic_height_rule_follows_the_parameters_block_version() {
    // The output is created below its input's creation height.
    let input = pre_block_box(1, 0, HEIGHT - 10);
    let utxo = MapUtxo::of(&[&input]);
    let lowered = || vec![tx(vec![input.box_id().unwrap()], vec![], 100)];

    // Parameters at version 3 enforce the rule although the header says 2.
    for result in validate_both(lowered(), &utxo, 2, &params(3)) {
        assert!(
            matches!(
                result,
                Err(BlockValidationError::Transaction {
                    index: 0,
                    error: ValidationError::OutputCreationHeightBelowInputs { .. },
                })
            ),
            "version-3 parameters must enforce txMonotonicHeight: {result:?}"
        );
    }
    // Version-2 parameters leave the rule inactive, even under a version-3 header.
    for result in validate_both(lowered(), &utxo, 3, &params(2)) {
        assert!(result.is_ok(), "{result:?}");
    }
}

#[test]
fn activated_script_version_follows_the_parameters_block_version() {
    // A version-2 ErgoTree needs activated script version 2 (block version 3).
    let input = pre_block_box(1, 2, 100);
    let utxo = MapUtxo::of(&[&input]);
    let spend = || vec![tx(vec![input.box_id().unwrap()], vec![], 100)];

    for result in validate_both(spend(), &utxo, 2, &params(3)) {
        assert!(
            result.is_ok(),
            "version-3 parameters activate ErgoTree v2: {result:?}"
        );
    }
    for result in validate_both(spend(), &utxo, 3, &params(2)) {
        assert!(
            result.is_err(),
            "version-2 parameters must not activate ErgoTree v2 under a version-3 header"
        );
    }
}

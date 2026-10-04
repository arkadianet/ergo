//! Target-block parameter selection shared by the UTXO and digest processors.

use ergo_state::store::StateStore;
use ergo_validation::context::ProtocolParams;
use ergo_validation::{
    scala_launch, ActiveProtocolParameters, ErgoValidationSettings, ErgoValidationSettingsUpdate,
    RuleStatus,
};

use super::target_block_params;

const VOTING_LENGTH: u32 = 1024;

fn synthetic_header_id(height: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[28..].copy_from_slice(&height.to_be_bytes());
    id
}

fn epoch_row(height: u32, activated: ErgoValidationSettingsUpdate) -> ActiveProtocolParameters {
    let mut row = scala_launch();
    row.epoch_start_height = height;
    row.activated_update = activated;
    row
}

fn status_update(rule: u16, status: RuleStatus) -> ErgoValidationSettingsUpdate {
    ErgoValidationSettingsUpdate {
        rules_to_disable: vec![],
        status_updates: vec![(rule, status)],
    }
}

/// Apply empty blocks up to `through`, persisting an epoch row at each
/// listed boundary.
fn apply_empty_blocks(
    store: &mut StateStore,
    through: u32,
    rows: &[(u32, ErgoValidationSettingsUpdate)],
) {
    for height in store.height() + 1..=through {
        let row = rows
            .iter()
            .find(|(boundary, _)| *boundary == height)
            .map(|(boundary, update)| epoch_row(*boundary, update.clone()));
        let root = store.root_digest();
        store
            .apply_block_unchecked_for_test_with_voted_params(
                height,
                &synthetic_header_id(height),
                &root,
                &[],
                row,
            )
            .unwrap();
    }
}

#[test]
fn target_block_params_keep_earlier_epoch_rule_statuses() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    store
        .initialize_genesis(&[([1u8; 32], vec![0xAA; 32])])
        .unwrap();
    store.set_ibd_mode(true, 4 * VOTING_LENGTH).unwrap();

    // Epoch one activates a status; epoch two activates nothing.
    let changed = status_update(1007, RuleStatus::Changed(vec![0x42]));
    apply_empty_blocks(
        &mut store,
        2 * VOTING_LENGTH + 1,
        &[
            (VOTING_LENGTH, changed.clone()),
            (2 * VOTING_LENGTH, ErgoValidationSettingsUpdate::empty()),
        ],
    );
    let cumulative = ErgoValidationSettings::empty().updated(&changed);
    assert_eq!(*store.validation_settings(), cumulative);

    // The tip row carries only its own empty epoch delta.
    let row_only = ProtocolParams::from_active(store.active_params()).validation_settings;
    let expected = ProtocolParams::from_active_with_settings(store.active_params(), &cumulative)
        .validation_settings;
    assert_ne!(row_only, expected);

    // A mid-epoch block keeps the status activated two epochs earlier.
    assert_eq!(
        target_block_params(&store, None).validation_settings,
        expected
    );

    // An epoch-start block adds its voted delta to the cumulative statuses
    // and takes its numeric parameters from the voted row.
    let replaced = status_update(1011, RuleStatus::Replaced(1016));
    let mut voted = epoch_row(3 * VOTING_LENGTH, replaced.clone());
    voted.input_cost += 1;
    let target = target_block_params(&store, Some(&voted));
    assert_eq!(
        target.validation_settings,
        ProtocolParams::from_active_with_settings(&voted, &cumulative.updated(&replaced))
            .validation_settings
    );
    assert_eq!(target.input_cost, voted.input_cost as u64);
}

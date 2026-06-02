//! Maturity-gating + reorg edge cases per spec §B-2.

use ergo_state::wallet::apply::{
    apply_block_to_wallet, rollback_block_from_wallet, BlockOutput, BlockTx, RescanGuard,
    REWARD_MATURITY_MAINNET,
};
use ergo_state::wallet::maturity::{promote_matured_boxes, unpromote_matured_boxes};
use ergo_state::wallet::tables::*;
use ergo_state::wallet::types::{BoxStatus, WalletBox};
use ergo_wallet::state::WalletState;
use redb::Database;

struct NoopRescanGuard;
impl RescanGuard for NoopRescanGuard {
    fn abort_in_progress(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
        Ok(())
    }
    fn force_invalidate(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
        Ok(())
    }
}

fn tracked_pk() -> [u8; 33] {
    hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
        .unwrap()
        .try_into()
        .unwrap()
}

fn wallet_with_one_tracked() -> WalletState {
    let mut s = WalletState::empty(false);
    s.insert_tracked_pubkey(0, tracked_pk(), ergo_ser::address::NetworkPrefix::Mainnet)
        .unwrap();
    s
}

/// `apply_block_to_wallet` takes raw data (tracked_p2pk_trees +
/// cached_pubkeys) instead of a `WalletState` reference. This helper
/// extracts both from a `WalletState` for test ergonomics — each
/// test does `let (trees, pks) = wallet_data(&w);` then calls
/// `apply_block_to_wallet(&txn, &trees, &pks, ...)`.
fn wallet_data(
    w: &WalletState,
) -> (
    std::collections::BTreeSet<Vec<u8>>,
    std::collections::BTreeMap<u64, [u8; 33]>,
) {
    let trees: std::collections::BTreeSet<Vec<u8>> = w
        .cached_pubkeys()
        .values()
        .map(|pk| ergo_ser::address::build_p2pk_tree_bytes(pk).unwrap())
        .collect();
    let pks: std::collections::BTreeMap<u64, [u8; 33]> =
        w.cached_pubkeys().iter().map(|(k, v)| (*k, *v)).collect();
    (trees, pks)
}

fn read_status(db: &Database, box_id: [u8; 32]) -> BoxStatus {
    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    let raw = tbl.get(box_id).unwrap().unwrap();
    let wb: WalletBox = bincode::deserialize(raw.value().as_slice()).unwrap();
    wb.status
}

#[test]
fn miner_reward_box_promotes_at_exact_maturity_height() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = ergo_ser::address::build_p2pk_tree_bytes(&tracked_pk()).unwrap();

    let creation_height = 100u32;
    let outputs = [BlockOutput {
        box_id: [0x01; 32],
        output_index: 0,
        ergo_tree_bytes: &tree,
        value: 67_500_000_000,
        assets: vec![],
        miner_reward_pubkey: Some(tracked_pk()),
    }];
    let txs = [BlockTx {
        tx_id: [0xAA; 32],
        inputs: &[],
        outputs: &outputs,
    }];

    // Apply at creation height.
    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, creation_height, &[0xBB; 32], &txs).unwrap();
    }
    promote_matured_boxes(&txn, creation_height).unwrap();
    txn.commit().unwrap();
    assert!(matches!(
        read_status(&db, [0x01; 32]),
        BoxStatus::Immature { .. }
    ));

    // Apply empty blocks up to maturity - 1: still immature.
    let maturity = creation_height + REWARD_MATURITY_MAINNET;
    for h in (creation_height + 1)..maturity {
        let txn = db.begin_write().unwrap();
        promote_matured_boxes(&txn, h).unwrap();
        txn.commit().unwrap();
        assert!(
            matches!(read_status(&db, [0x01; 32]), BoxStatus::Immature { .. }),
            "at height {h}, must still be immature (maturity = {maturity})",
        );
    }

    // Apply the maturity block: now Confirmed.
    let txn = db.begin_write().unwrap();
    promote_matured_boxes(&txn, maturity).unwrap();
    txn.commit().unwrap();
    assert!(matches!(read_status(&db, [0x01; 32]), BoxStatus::Confirmed));

    // One block past maturity: still Confirmed.
    let txn = db.begin_write().unwrap();
    promote_matured_boxes(&txn, maturity + 1).unwrap();
    txn.commit().unwrap();
    assert!(matches!(read_status(&db, [0x01; 32]), BoxStatus::Confirmed));
}

#[test]
fn rollback_unpromotes_box_back_to_immature() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = ergo_ser::address::build_p2pk_tree_bytes(&tracked_pk()).unwrap();

    let creation_height = 100u32;
    let outputs = [BlockOutput {
        box_id: [0x01; 32],
        output_index: 0,
        ergo_tree_bytes: &tree,
        value: 67_500_000_000,
        assets: vec![],
        miner_reward_pubkey: Some(tracked_pk()),
    }];
    let txs = [BlockTx {
        tx_id: [0xAA; 32],
        inputs: &[],
        outputs: &outputs,
    }];

    // Apply through maturity.
    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, creation_height, &[0xBB; 32], &txs).unwrap();
    }
    txn.commit().unwrap();
    let maturity = creation_height + REWARD_MATURITY_MAINNET;
    let txn = db.begin_write().unwrap();
    promote_matured_boxes(&txn, maturity).unwrap();
    txn.commit().unwrap();
    assert!(matches!(read_status(&db, [0x01; 32]), BoxStatus::Confirmed));

    // Rollback to height = maturity - 1; un-promote.
    let txn = db.begin_write().unwrap();
    unpromote_matured_boxes(&txn, maturity - 1).unwrap();
    txn.commit().unwrap();
    match read_status(&db, [0x01; 32]) {
        BoxStatus::Immature { matures_at } => assert_eq!(matures_at, maturity),
        other => panic!("expected Immature, got {other:?}"),
    }
}

#[test]
fn reorg_across_maturity_boundary_removes_box() {
    // Apply through maturity, then rollback past creation height.
    // Box must be REMOVED, not just unpromoted.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = ergo_ser::address::build_p2pk_tree_bytes(&tracked_pk()).unwrap();

    let creation_height = 100u32;
    let outputs = [BlockOutput {
        box_id: [0x01; 32],
        output_index: 0,
        ergo_tree_bytes: &tree,
        value: 67_500_000_000,
        assets: vec![],
        miner_reward_pubkey: Some(tracked_pk()),
    }];
    let txs = [BlockTx {
        tx_id: [0xAA; 32],
        inputs: &[],
        outputs: &outputs,
    }];

    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, creation_height, &[0xBB; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let maturity = creation_height + REWARD_MATURITY_MAINNET;
    let txn = db.begin_write().unwrap();
    promote_matured_boxes(&txn, maturity).unwrap();
    txn.commit().unwrap();
    assert!(matches!(read_status(&db, [0x01; 32]), BoxStatus::Confirmed));

    // Reorg: rollback the creation block.
    let txn = db.begin_write().unwrap();
    rollback_block_from_wallet(&txn, creation_height, &txs, &NoopRescanGuard).unwrap();
    txn.commit().unwrap();

    // Box must no longer exist.
    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    assert!(
        tbl.get([0x01u8; 32]).unwrap().is_none(),
        "reorg past creation_height must remove the box entirely",
    );
}

#[test]
fn reorg_after_spend_returns_box_to_confirmed() {
    // Scenario:
    // 1. Apply miner reward at h=100.
    // 2. Promote to Confirmed at h=820 (maturity).
    // 3. Apply spend tx at h=821 (input references box, now Spent).
    // 4. Reorg: rollback h=821 (the spend) on a chain that doesn't
    //    include the spend.
    // 5. Box must return to Confirmed (un-Spent), and on the new
    //    chain that doesn't include the spend, the spend is gone.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let wrapper_tree_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x10];

    let creation_height = 100u32;
    let outputs_create = [BlockOutput {
        box_id: [0x01; 32],
        output_index: 0,
        ergo_tree_bytes: &wrapper_tree_bytes,
        value: 67_500_000_000,
        assets: vec![],
        miner_reward_pubkey: Some(tracked_pk()),
    }];
    let txs_create = [BlockTx {
        tx_id: [0xAA; 32],
        inputs: &[],
        outputs: &outputs_create,
    }];

    // 1. Apply creation.
    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(
            &txn,
            &trees,
            &pks,
            creation_height,
            &[0xBB; 32],
            &txs_create,
        )
        .unwrap();
    }
    txn.commit().unwrap();

    // 2. Promote to Confirmed at maturity.
    let maturity = creation_height + REWARD_MATURITY_MAINNET;
    let txn = db.begin_write().unwrap();
    promote_matured_boxes(&txn, maturity).unwrap();
    txn.commit().unwrap();
    assert!(matches!(read_status(&db, [0x01; 32]), BoxStatus::Confirmed));

    // 3. Apply a spend tx referencing the matured box.
    let spend_height = maturity + 1;
    let inputs_spend = [[0x01u8; 32]];
    let outputs_spend: [BlockOutput; 0] = [];
    let txs_spend = [BlockTx {
        tx_id: [0xCC; 32],
        inputs: &inputs_spend,
        outputs: &outputs_spend,
    }];
    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, spend_height, &[0xDD; 32], &txs_spend).unwrap();
    }
    txn.commit().unwrap();
    assert!(matches!(
        read_status(&db, [0x01; 32]),
        BoxStatus::Spent { .. }
    ));

    // 4. Reorg: rollback the spend block.
    let txn = db.begin_write().unwrap();
    rollback_block_from_wallet(&txn, spend_height, &txs_spend, &NoopRescanGuard).unwrap();
    txn.commit().unwrap();

    // 5. Box must return to Confirmed (not Spent, not Immature —
    //    maturity already happened, and the spend that took it out
    //    has been reverted).
    let status = read_status(&db, [0x01; 32]);
    assert!(
        matches!(status, BoxStatus::Confirmed),
        "rollback of the spend block must return box to Confirmed, got {:?}",
        status,
    );
}

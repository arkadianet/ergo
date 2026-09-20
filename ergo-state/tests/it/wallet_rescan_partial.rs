//! Partial rescan regression tests. Each scenario exercises the
//! range-scoped clear + rewind + replay path in
//! WalletScanService::rescan_full_rebuild for start_height > 0.

#![allow(clippy::result_large_err)] // redb::Error is large; test closures can't avoid it

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ergo_state::wallet::apply::{
    apply_block_to_wallet, BlockOutput, BlockTx, REWARD_MATURITY_MAINNET,
};
use ergo_state::wallet::maturity::promote_matured_boxes;
use ergo_state::wallet::scan::{OwnedBlockOutput, RescanBlock, RescanTx, WalletScanService};
use ergo_state::wallet::tables::WALLET_BOXES;
use ergo_state::wallet::types::{BoxStatus, WalletBox};
use ergo_wallet::state::WalletState;
use redb::Database;

// ----- helpers -----

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

fn wallet_data(w: &WalletState) -> (BTreeSet<Vec<u8>>, BTreeMap<u64, [u8; 33]>) {
    let trees: BTreeSet<Vec<u8>> = w
        .cached_pubkeys()
        .values()
        .map(|pk| ergo_ser::address::build_p2pk_tree_bytes(pk).unwrap())
        .collect();
    let pks: BTreeMap<u64, [u8; 33]> = w.cached_pubkeys().iter().map(|(k, v)| (*k, *v)).collect();
    (trees, pks)
}

fn read_box(db: &Database, box_id: [u8; 32]) -> Option<WalletBox> {
    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    tbl.get(box_id)
        .unwrap()
        .map(|g| bincode::deserialize::<WalletBox>(g.value().as_slice()).unwrap())
}

// ----- happy path -----

#[test]
fn partial_rescan_removes_stale_spent_when_spend_disappears_on_replay() {
    // Setup: box created at h=99 (Owned/Confirmed), spent at h=105
    // (becomes Spent). Then rescan from N=100 with read_block returning
    // empty blocks for h=100..=105 (simulates reorg that removed the spend).
    // Expected: box returns to Confirmed after rescan — rewind un-spent it
    // and replay didn't re-spend it.
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("test.redb")).unwrap());
    let wallet = wallet_with_one_tracked();
    let tree = ergo_ser::address::build_p2pk_tree_bytes(&tracked_pk()).unwrap();
    let box_id = [0x42; 32];

    // Apply h=99: create box.
    let outputs = [BlockOutput {
        box_id,
        output_index: 0,
        ergo_tree_bytes: &tree,
        value: 1_000_000_000,
        assets: vec![],
        miner_reward_pubkey: None,
        box_bytes: &[],
    }];
    let txs = [BlockTx {
        tx_id: [0xAA; 32],
        inputs: &[],
        outputs: &outputs,
    }];
    {
        let (trees, pks) = wallet_data(&wallet);
        let txn = db.begin_write().unwrap();
        apply_block_to_wallet(&txn, &trees, &pks, 99, &[0xBB; 32], &txs).unwrap();
        txn.commit().unwrap();
    }

    // Apply h=105: spend box.
    let spend_inputs = [box_id];
    let spend_outputs: [BlockOutput; 0] = [];
    let spend_txs = [BlockTx {
        tx_id: [0xCC; 32],
        inputs: &spend_inputs,
        outputs: &spend_outputs,
    }];
    {
        let (trees, pks) = wallet_data(&wallet);
        let txn = db.begin_write().unwrap();
        apply_block_to_wallet(&txn, &trees, &pks, 105, &[0xDD; 32], &spend_txs).unwrap();
        txn.commit().unwrap();
    }

    // Confirm box is Spent.
    let wb = read_box(&db, box_id).expect("box must exist");
    assert!(matches!(wb.status, BoxStatus::Spent { .. }));

    // Partial rescan from N=100. Empty blocks — spend tx is gone (reorg).
    let (trees, pks) = wallet_data(&wallet);
    let read_block = |_h: u32| -> Result<Option<RescanBlock>, redb::Error> {
        Ok(Some(RescanBlock {
            block_id: [0xEE; 32],
            txs: vec![],
        }))
    };
    let read_tip = || -> Result<u32, redb::Error> { Ok(105) };
    let is_cancelled = || false;
    WalletScanService::rescan_full_rebuild(
        &db,
        trees,
        pks,
        100,
        105,
        read_block,
        read_tip,
        is_cancelled,
        None,
    )
    .unwrap();

    // Expected: box is back to Confirmed (rewind un-spent it; replay didn't re-spend).
    let wb = read_box(&db, box_id).expect("box must survive");
    assert!(
        matches!(wb.status, BoxStatus::Confirmed),
        "after rescan-without-spend, box must return to Confirmed; got {:?}",
        wb.status
    );
}

#[test]
fn partial_rescan_downgrades_matured_reward_when_maturity_above_n() {
    // Setup: miner reward at h=100, matures at h=820. Apply through
    // h=820 (promoted to Confirmed). Then partial rescan from N=500
    // (< 820). Expected: rewind downgrades box back to Immature{820};
    // replay from N=500..tip re-promotes at h=820.
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("test.redb")).unwrap());
    let wallet = wallet_with_one_tracked();
    let wrapper_tree = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x10];
    let box_id = [0x42; 32];

    let outputs = [BlockOutput {
        box_id,
        output_index: 0,
        ergo_tree_bytes: &wrapper_tree,
        value: 67_500_000_000,
        assets: vec![],
        miner_reward_pubkey: Some(tracked_pk()),
        box_bytes: &[],
    }];
    let txs = [BlockTx {
        tx_id: [0xAA; 32],
        inputs: &[],
        outputs: &outputs,
    }];
    {
        let (trees, pks) = wallet_data(&wallet);
        let txn = db.begin_write().unwrap();
        apply_block_to_wallet(&txn, &trees, &pks, 100, &[0xBB; 32], &txs).unwrap();
        txn.commit().unwrap();
    }

    // Promote at maturity (h=820).
    {
        let txn = db.begin_write().unwrap();
        promote_matured_boxes(&txn, 820).unwrap();
        txn.commit().unwrap();
    }

    // Confirm box is Confirmed.
    let wb = read_box(&db, box_id).expect("box must exist");
    assert!(matches!(wb.status, BoxStatus::Confirmed));

    // Two-step assertion.
    // STEP A: partial rescan from N=500 through h=819 (one below maturity).
    // Rewind should downgrade box to Immature{820}; replay through 819 doesn't re-promote.
    {
        let (trees, pks) = wallet_data(&wallet);
        let read_block = |_h: u32| -> Result<Option<RescanBlock>, redb::Error> {
            Ok(Some(RescanBlock {
                block_id: [0xEE; 32],
                txs: vec![],
            }))
        };
        let read_tip = || -> Result<u32, redb::Error> { Ok(819) };
        let is_cancelled = || false;
        WalletScanService::rescan_full_rebuild(
            &db,
            trees,
            pks,
            500,
            819,
            read_block,
            read_tip,
            is_cancelled,
            None,
        )
        .unwrap();
    }
    let wb = read_box(&db, box_id).expect("box must exist after STEP A");
    match wb.status {
        BoxStatus::Immature { matures_at } => {
            assert_eq!(
                matures_at, 820,
                "rewind must restore matures_at=820 (creation_height=100 + REWARD_MATURITY_MAINNET={})",
                REWARD_MATURITY_MAINNET
            );
        }
        other => panic!(
            "STEP A: after rescan-from-500-through-819, box must be Immature{{matures_at:820}}; got {:?}",
            other,
        ),
    }

    // STEP B: advance replay one more block to h=820 (maturity).
    // promote_matured_boxes_rescan inside the replay loop must re-promote.
    {
        let (trees, pks) = wallet_data(&wallet);
        let read_block = |_h: u32| -> Result<Option<RescanBlock>, redb::Error> {
            Ok(Some(RescanBlock {
                block_id: [0xEE; 32],
                txs: vec![],
            }))
        };
        let read_tip = || -> Result<u32, redb::Error> { Ok(820) };
        let is_cancelled = || false;
        WalletScanService::rescan_full_rebuild(
            &db,
            trees,
            pks,
            820,
            820,
            read_block,
            read_tip,
            is_cancelled,
            None,
        )
        .unwrap();
    }
    let wb = read_box(&db, box_id).expect("box must exist after STEP B");
    assert!(
        matches!(wb.status, BoxStatus::Confirmed),
        "STEP B: after replay through h=820, box must be Confirmed; got {:?}",
        wb.status
    );
}

#[test]
fn partial_rescan_restores_spend_when_replay_includes_it() {
    // Same setup as test 1 BUT replay DOES include the spend tx.
    // Expected: box ends Spent (rewind+replay is a stable no-op for
    // unchanged history).
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("test.redb")).unwrap());
    let wallet = wallet_with_one_tracked();
    let tree = ergo_ser::address::build_p2pk_tree_bytes(&tracked_pk()).unwrap();
    let box_id = [0x42; 32];

    // Apply h=99: create box.
    let outputs = [BlockOutput {
        box_id,
        output_index: 0,
        ergo_tree_bytes: &tree,
        value: 1_000_000_000,
        assets: vec![],
        miner_reward_pubkey: None,
        box_bytes: &[],
    }];
    let txs = [BlockTx {
        tx_id: [0xAA; 32],
        inputs: &[],
        outputs: &outputs,
    }];
    {
        let (trees, pks) = wallet_data(&wallet);
        let txn = db.begin_write().unwrap();
        apply_block_to_wallet(&txn, &trees, &pks, 99, &[0xBB; 32], &txs).unwrap();
        txn.commit().unwrap();
    }

    // Apply h=105: spend box.
    let spend_inputs = [box_id];
    let spend_outputs: [BlockOutput; 0] = [];
    let spend_txs = [BlockTx {
        tx_id: [0xCC; 32],
        inputs: &spend_inputs,
        outputs: &spend_outputs,
    }];
    {
        let (trees, pks) = wallet_data(&wallet);
        let txn = db.begin_write().unwrap();
        apply_block_to_wallet(&txn, &trees, &pks, 105, &[0xDD; 32], &spend_txs).unwrap();
        txn.commit().unwrap();
    }

    // Partial rescan from N=100 with read_block returning the spend tx at h=105.
    let (trees, pks) = wallet_data(&wallet);
    let spend_inputs_vec: Vec<[u8; 32]> = vec![box_id];
    let read_block = move |h: u32| -> Result<Option<RescanBlock>, redb::Error> {
        Ok(Some(RescanBlock {
            block_id: [0xEE; 32],
            txs: if h == 105 {
                vec![RescanTx {
                    tx_id: [0xCC; 32],
                    inputs: spend_inputs_vec.clone(),
                    outputs: vec![],
                }]
            } else {
                vec![]
            },
        }))
    };
    let read_tip = || -> Result<u32, redb::Error> { Ok(105) };
    let is_cancelled = || false;
    WalletScanService::rescan_full_rebuild(
        &db,
        trees,
        pks,
        100,
        105,
        read_block,
        read_tip,
        is_cancelled,
        None,
    )
    .unwrap();

    // Expected: box is Spent again (rewind un-spent; replay re-spent).
    let wb = read_box(&db, box_id).expect("box must exist");
    assert!(
        matches!(wb.status, BoxStatus::Spent { .. }),
        "rewind+replay must be stable: box must end Spent; got {:?}",
        wb.status
    );
}

// Suppress unused-import warning for OwnedBlockOutput in case it's
// only used via the public API surface of scan.rs.
#[allow(dead_code)]
fn _use_owned_block_output() {
    let _ = OwnedBlockOutput {
        box_id: [0; 32],
        output_index: 0,
        ergo_tree_bytes: vec![],
        value: 0,
        assets: vec![],
        miner_reward_pubkey: None,
        box_bytes: vec![],
    };
}

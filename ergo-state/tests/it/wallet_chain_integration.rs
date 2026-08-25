//! Integration test: wallet hook wiring between StateStore helpers and
//! wallet apply / rollback functions.
//!
//! Tests the production path used in `StateStore::apply_block` and the
//! post-apply wallet hook in `sync_tick.rs`:
//! - `build_wallet_block_txs_checked` constructs `OwnedBlockTxData` from a
//!   synthetic CheckedTransaction-equivalent
//! - `owned_to_block_txs` produces `BlockTx<'_>` slices with correct borrows
//! - `apply_block_to_wallet` populates WALLET_BOXES for tracked outputs
//! - `rollback_block_from_wallet` undoes the population
//!
//! Uses synthetic data only — no fixture files required.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ergo_state::store::{owned_to_block_txs, OwnedBlockOutput, OwnedBlockTxData};
use ergo_state::wallet::apply::{
    apply_block_to_wallet, rollback_block_from_wallet, BlockTx, RescanGuard,
};
use ergo_state::wallet::tables::WALLET_BOXES;
use ergo_state::wallet::types::{BoxStatus, WalletBox};
use ergo_wallet::state::WalletState;
use redb::Database;

// ----- helpers -----

fn tracked_pk() -> [u8; 33] {
    // BIP32 Vector 1 master pubkey — known-valid compressed SEC1.
    hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
        .unwrap()
        .try_into()
        .unwrap()
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

fn wallet_with_one_tracked() -> WalletState {
    let mut s = WalletState::empty(false);
    s.insert_tracked_pubkey(0, tracked_pk(), ergo_ser::address::NetworkPrefix::Mainnet)
        .unwrap();
    s
}

struct NoopRescanGuard;
impl RescanGuard for NoopRescanGuard {
    fn abort_in_progress(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
        Ok(())
    }
    fn force_invalidate(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
        Ok(())
    }
}

fn read_box(db: &Database, box_id: [u8; 32]) -> Option<WalletBox> {
    let txn = db.begin_read().unwrap();
    match txn.open_table(WALLET_BOXES) {
        Ok(tbl) => tbl
            .get(box_id)
            .unwrap()
            .map(|g| bincode::deserialize::<WalletBox>(g.value().as_slice()).unwrap()),
        Err(_) => None,
    }
}

// ----- happy path -----

/// Verify that `OwnedBlockTxData` → `owned_to_block_txs` → `apply_block_to_wallet`
/// populates WALLET_BOXES for a tracked output, and that
/// `rollback_block_from_wallet` removes it again.
#[test]
fn owned_block_txs_apply_then_rollback_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("test.redb")).unwrap());
    let wallet = wallet_with_one_tracked();
    let (trees, pks) = wallet_data(&wallet);

    let tree_bytes = ergo_ser::address::build_p2pk_tree_bytes(&tracked_pk()).unwrap();
    let box_id = [0x77u8; 32];
    let tx_id = [0xCCu8; 32];
    let header_id = [0xBBu8; 32];
    let height: u32 = 200;

    // Build OwnedBlockTxData — this mirrors what build_wallet_block_txs_checked
    // produces from real CheckedTransactions inside StateStore::apply_block.
    let owned = vec![OwnedBlockTxData {
        tx_id,
        inputs: vec![],
        outputs: vec![OwnedBlockOutput {
            box_id,
            output_index: 0,
            ergo_tree_bytes: tree_bytes.clone(),
            value: 5_000_000_000,
            assets: vec![],
            miner_reward_pubkey: None,
            box_bytes: Vec::new(),
        }],
    }];

    // owned_to_block_txs: two-step lifetime bridge.
    let bound = owned_to_block_txs(&owned);
    let btxs: Vec<BlockTx<'_>> = bound.as_block_txs();

    // Verify the bridge produced the expected structure.
    assert_eq!(btxs.len(), 1);
    assert_eq!(btxs[0].tx_id, tx_id);
    assert_eq!(btxs[0].outputs.len(), 1);
    assert_eq!(btxs[0].outputs[0].box_id, box_id);
    assert_eq!(btxs[0].outputs[0].ergo_tree_bytes, tree_bytes.as_slice());

    // Apply to wallet tables.
    {
        let write_txn = db.begin_write().unwrap();
        apply_block_to_wallet(&write_txn, &trees, &pks, height, &header_id, &btxs).unwrap();
        write_txn.commit().unwrap();
    }

    // WALLET_BOXES should now contain the output as Confirmed.
    let wb = read_box(&db, box_id).expect("expected wallet box after apply");
    assert_eq!(wb.value, 5_000_000_000);
    assert!(
        matches!(wb.status, BoxStatus::Confirmed),
        "expected Confirmed status, got {:?}",
        wb.status
    );

    // Rollback: should remove the box.
    {
        let write_txn = db.begin_write().unwrap();
        rollback_block_from_wallet(&write_txn, height, &btxs, &NoopRescanGuard).unwrap();
        write_txn.commit().unwrap();
    }

    // WALLET_BOXES should no longer contain the entry.
    assert!(
        read_box(&db, box_id).is_none(),
        "wallet box should be removed after rollback"
    );
}

/// Verify that `owned_to_block_txs` handles an empty block (no transactions)
/// without panicking and produces an empty BlockTx slice.
#[test]
fn owned_to_block_txs_empty_block_noop() {
    let owned: Vec<OwnedBlockTxData> = vec![];
    let bound = owned_to_block_txs(&owned);
    let btxs = bound.as_block_txs();
    assert!(btxs.is_empty());
}

/// Verify multiple txs produce correctly indexed BlockTx slices,
/// each with independent output slices borrowing from owned.
#[test]
fn owned_to_block_txs_multi_tx_structure() {
    let tree1 = vec![0x00u8, 0xec, 0x01, 0x08, 0xcd, 0x02]; // dummy P2PK prefix
    let tree2 = vec![0x00u8, 0xec, 0x01, 0x08, 0xcd, 0x03];

    let owned = vec![
        OwnedBlockTxData {
            tx_id: [0x01u8; 32],
            inputs: vec![[0xF0u8; 32]],
            outputs: vec![OwnedBlockOutput {
                box_id: [0xA1u8; 32],
                output_index: 0,
                ergo_tree_bytes: tree1.clone(),
                value: 1_000,
                assets: vec![],
                miner_reward_pubkey: None,
                box_bytes: Vec::new(),
            }],
        },
        OwnedBlockTxData {
            tx_id: [0x02u8; 32],
            inputs: vec![[0xF1u8; 32], [0xF2u8; 32]],
            outputs: vec![
                OwnedBlockOutput {
                    box_id: [0xA2u8; 32],
                    output_index: 0,
                    ergo_tree_bytes: tree2.clone(),
                    value: 2_000,
                    assets: vec![],
                    miner_reward_pubkey: None,
                    box_bytes: Vec::new(),
                },
                OwnedBlockOutput {
                    box_id: [0xA3u8; 32],
                    output_index: 1,
                    ergo_tree_bytes: tree2.clone(),
                    value: 3_000,
                    assets: vec![],
                    miner_reward_pubkey: None,
                    box_bytes: Vec::new(),
                },
            ],
        },
    ];

    let bound = owned_to_block_txs(&owned);
    let btxs = bound.as_block_txs();

    assert_eq!(btxs.len(), 2);

    // First tx.
    assert_eq!(btxs[0].tx_id, [0x01u8; 32]);
    assert_eq!(btxs[0].inputs, &[[0xF0u8; 32]]);
    assert_eq!(btxs[0].outputs.len(), 1);
    assert_eq!(btxs[0].outputs[0].box_id, [0xA1u8; 32]);
    assert_eq!(btxs[0].outputs[0].value, 1_000);

    // Second tx: two outputs.
    assert_eq!(btxs[1].tx_id, [0x02u8; 32]);
    assert_eq!(btxs[1].inputs, &[[0xF1u8; 32], [0xF2u8; 32]]);
    assert_eq!(btxs[1].outputs.len(), 2);
    assert_eq!(btxs[1].outputs[0].box_id, [0xA2u8; 32]);
    assert_eq!(btxs[1].outputs[0].value, 2_000);
    assert_eq!(btxs[1].outputs[1].box_id, [0xA3u8; 32]);
    assert_eq!(btxs[1].outputs[1].value, 3_000);
}

// ----- error paths -----

/// Verify that an untracked output (ergo_tree not in tracked set) is silently
/// ignored — no wallet box created.
#[test]
fn untracked_output_not_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("test.redb")).unwrap());
    let wallet = wallet_with_one_tracked();
    let (trees, pks) = wallet_data(&wallet);

    // Untracked ergo_tree: all-zero bytes (not a valid P2PK tree).
    let untracked_tree = vec![0x00u8; 6];
    let box_id = [0xDDu8; 32];

    let owned = vec![OwnedBlockTxData {
        tx_id: [0xEEu8; 32],
        inputs: vec![],
        outputs: vec![OwnedBlockOutput {
            box_id,
            output_index: 0,
            ergo_tree_bytes: untracked_tree,
            value: 1_000_000,
            assets: vec![],
            miner_reward_pubkey: None,
            box_bytes: Vec::new(),
        }],
    }];

    let bound = owned_to_block_txs(&owned);
    let btxs = bound.as_block_txs();

    let write_txn = db.begin_write().unwrap();
    apply_block_to_wallet(&write_txn, &trees, &pks, 10, &[0xAAu8; 32], &btxs).unwrap();
    write_txn.commit().unwrap();

    assert!(
        read_box(&db, box_id).is_none(),
        "untracked output must not appear in WALLET_BOXES"
    );
}

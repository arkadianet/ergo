//! Integration tests for the wallet apply hook. Synthetic blocks
//! exercise the classification + same-block-create-then-spend +
//! rollback paths.

use ergo_state::wallet::apply::{
    apply_block_to_wallet, rollback_block_from_wallet, BlockOutput, BlockTx, RescanGuard,
    REWARD_MATURITY_MAINNET,
};
use ergo_state::wallet::tables::*;
use ergo_state::wallet::types::{BoxProvenance, BoxStatus, WalletBox};
use ergo_wallet::state::WalletState;
use redb::{Database, ReadableTableMetadata};

fn tracked_pk() -> [u8; 33] {
    // BIP32 Vector 1 master pubkey — known-valid compressed SEC1.
    hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
        .unwrap()
        .try_into()
        .unwrap()
}

/// No-op RescanGuard used by apply/maturity/rollback tests that
/// don't exercise the rescan-abort interaction. Production code in
/// `ergo-node/src/wallet_boot.rs` uses the real guard that flips
/// `RESCAN_IN_PROGRESS = false` and writes `WALLET_SCAN_INVALIDATED
/// = true` atomically.
struct NoopRescanGuard;
impl RescanGuard for NoopRescanGuard {
    fn abort_in_progress(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
        Ok(())
    }
    fn force_invalidate(&self, _txn: &redb::WriteTransaction) -> Result<(), redb::Error> {
        Ok(())
    }
}

fn tracked_tree() -> Vec<u8> {
    ergo_ser::address::build_p2pk_tree_bytes(&tracked_pk()).unwrap()
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

// ----- happy path -----

#[test]
fn apply_block_with_owned_output_records_confirmed_box() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = tracked_tree();

    let outputs = [BlockOutput {
        box_id: [0x01; 32],
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

    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 100, &[0xBB; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    let raw = tbl.get([0x01u8; 32]).unwrap().unwrap();
    let wb: WalletBox = bincode::deserialize(raw.value().as_slice()).unwrap();
    assert_eq!(wb.value, 1_000_000_000);
    assert!(matches!(wb.status, BoxStatus::Confirmed));
    assert!(matches!(wb.provenance, BoxProvenance::Owned));
}

#[test]
fn apply_block_with_miner_reward_records_immature_with_correct_maturity() {
    // Mining reward: ergo_tree_bytes are the WRAPPER script (NOT the
    // bare tracked P2PK tree). The embedded pubkey is what classifies
    // the output. This test verifies that:
    // (a) the wrapper-tree bytes are NOT in tracked_p2pk_trees (so
    //     the Owned path correctly DOES NOT match), and
    // (b) the miner_reward_pubkey IS in cached_pubkeys (so the
    //     MinerReward path matches via the pubkey).
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();

    // Deliberately distinct from tracked_tree(): a wrapper-script
    // placeholder. In production, this is `{ HEIGHT >= unlock_h &&
    // proveDlog(pk) }` serialized; for the test the bytes can be
    // any non-tracked byte sequence — what matters is that
    // miner_reward_pubkey is set to the tracked pubkey.
    let wrapper_tree_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x10];

    let outputs = [BlockOutput {
        box_id: [0x02; 32],
        output_index: 0,
        ergo_tree_bytes: &wrapper_tree_bytes,
        value: 67_500_000_000, // 67.5 ERG block reward
        assets: vec![],
        miner_reward_pubkey: Some(tracked_pk()),
        box_bytes: &[],
    }];
    let txs = [BlockTx {
        tx_id: [0xCC; 32],
        inputs: &[],
        outputs: &outputs,
    }];
    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 1_000, &[0xDD; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    let raw = tbl.get([0x02u8; 32]).unwrap().unwrap();
    let wb: WalletBox = bincode::deserialize(raw.value().as_slice()).unwrap();
    assert!(matches!(wb.provenance, BoxProvenance::MinerReward));
    match wb.status {
        BoxStatus::Immature { matures_at } => {
            assert_eq!(matures_at, 1_000 + REWARD_MATURITY_MAINNET);
        }
        _ => panic!("expected Immature, got {:?}", wb.status),
    }
}

#[test]
fn miner_reward_to_untracked_pubkey_is_ignored() {
    // If the miner-reward path naively matched tracked_tree(), real
    // mining rewards to untracked pubkeys would be silently
    // classified. This test pins the opposite: a wrapper-script
    // output with an UNTRACKED embedded pubkey must be ignored.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();

    let untracked_pk: [u8; 33] =
        hex::decode("0202f2b96aa59e6f37fc978883f78e54fd319fa37dcf971d8e69f9e9225376bcf1")
            .unwrap()
            .try_into()
            .unwrap();
    let wrapper_tree_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x10];

    let outputs = [BlockOutput {
        box_id: [0x05; 32],
        output_index: 0,
        ergo_tree_bytes: &wrapper_tree_bytes,
        value: 67_500_000_000,
        assets: vec![],
        miner_reward_pubkey: Some(untracked_pk),
        box_bytes: &[],
    }];
    let txs = [BlockTx {
        tx_id: [0xCC; 32],
        inputs: &[],
        outputs: &outputs,
    }];
    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 1_000, &[0xDD; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    assert!(
        tbl.get([0x05u8; 32]).unwrap().is_none(),
        "miner reward to an untracked pubkey must NOT be recorded",
    );
}

#[test]
fn untracked_output_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();

    let untracked_tree = vec![0x10, 0x00, 0x00];
    let outputs = [BlockOutput {
        box_id: [0x03; 32],
        output_index: 0,
        ergo_tree_bytes: &untracked_tree,
        value: 5_000_000_000,
        assets: vec![],
        miner_reward_pubkey: None,
        box_bytes: &[],
    }];
    let txs = [BlockTx {
        tx_id: [0xEE; 32],
        inputs: &[],
        outputs: &outputs,
    }];
    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 200, &[0xFF; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    assert!(
        tbl.get([0x03u8; 32]).unwrap().is_none(),
        "untracked outputs must not be recorded"
    );
}

#[test]
fn same_block_create_then_spend_box_ends_spent() {
    // Tx_A creates a tracked box. Tx_B (same block, later in order)
    // spends it. End state: box is Spent, not Confirmed.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = tracked_tree();

    let tx_a_id = [0xAA; 32];
    let tx_b_id = [0xBB; 32];
    let box_id = [0x42; 32];

    let outputs_a = [BlockOutput {
        box_id,
        output_index: 0,
        ergo_tree_bytes: &tree,
        value: 1_000_000_000,
        assets: vec![],
        miner_reward_pubkey: None,
        box_bytes: &[],
    }];
    let inputs_b = [box_id];
    let outputs_b: [BlockOutput; 0] = [];

    let txs = [
        BlockTx {
            tx_id: tx_a_id,
            inputs: &[],
            outputs: &outputs_a,
        },
        BlockTx {
            tx_id: tx_b_id,
            inputs: &inputs_b,
            outputs: &outputs_b,
        },
    ];

    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 500, &[0xEE; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    let raw = tbl
        .get(box_id)
        .unwrap()
        .expect("box must exist after create");
    let wb: WalletBox = bincode::deserialize(raw.value().as_slice()).unwrap();
    match wb.status {
        BoxStatus::Spent {
            spent_in_tx,
            spent_at,
        } => {
            assert_eq!(spent_in_tx, tx_b_id);
            assert_eq!(spent_at, 500);
        }
        _ => panic!("expected Spent, got {:?}", wb.status),
    }
}

// ----- rollback -----

#[test]
fn rollback_after_apply_restores_pre_apply_state() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = tracked_tree();

    let outputs = [BlockOutput {
        box_id: [0x01; 32],
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

    // Apply.
    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 100, &[0xBB; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    // Rollback.
    let txn = db.begin_write().unwrap();
    rollback_block_from_wallet(&txn, 100, &txs, &NoopRescanGuard).unwrap();
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    assert!(
        tbl.get([0x01u8; 32]).unwrap().is_none(),
        "rollback must remove the box that was inserted by apply"
    );
}

#[test]
fn rollback_after_same_block_spend_restores_pre_apply_state() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = tracked_tree();
    let box_id = [0x42; 32];
    let outputs_a = [BlockOutput {
        box_id,
        output_index: 0,
        ergo_tree_bytes: &tree,
        value: 1_000_000_000,
        assets: vec![],
        miner_reward_pubkey: None,
        box_bytes: &[],
    }];
    let inputs_b = [box_id];
    let outputs_b: [BlockOutput; 0] = [];
    let txs = [
        BlockTx {
            tx_id: [0xAA; 32],
            inputs: &[],
            outputs: &outputs_a,
        },
        BlockTx {
            tx_id: [0xBB; 32],
            inputs: &inputs_b,
            outputs: &outputs_b,
        },
    ];

    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 500, &[0xEE; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_write().unwrap();
    rollback_block_from_wallet(&txn, 500, &txs, &NoopRescanGuard).unwrap();
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOXES).unwrap();
    assert!(
        tbl.get(box_id).unwrap().is_none(),
        "rollback must remove a box created+spent in the same block"
    );
}

// ----- box-bytes capture (reserved-id reads) -----

#[test]
fn apply_populates_box_bytes_table_for_owned_output() {
    // Reserved-id reads (/scan/{unspent,spent}Boxes/9|10) need the
    // full serialized box bytes, which WalletBox does not carry. The
    // apply path captures them into WALLET_BOX_BYTES keyed by box_id.
    // This pins that an owned output with non-empty box_bytes lands a
    // row with the EXACT bytes that were passed in.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = tracked_tree();

    let serialized_box = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03];
    let outputs = [BlockOutput {
        box_id: [0x01; 32],
        output_index: 0,
        ergo_tree_bytes: &tree,
        value: 1_000_000_000,
        assets: vec![],
        miner_reward_pubkey: None,
        box_bytes: &serialized_box,
    }];
    let txs = [BlockTx {
        tx_id: [0xAA; 32],
        inputs: &[],
        outputs: &outputs,
    }];

    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 100, &[0xBB; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOX_BYTES).unwrap();
    let raw = tbl
        .get([0x01u8; 32])
        .unwrap()
        .expect("box bytes row must exist after apply");
    assert_eq!(
        raw.value(),
        serialized_box,
        "stored box bytes must match the bytes passed to apply"
    );
}

#[test]
fn apply_skips_box_bytes_row_when_bytes_empty() {
    // Graceful degradation: an owned output applied with empty
    // box_bytes (e.g. a code path that has no bytes to capture) must
    // NOT write a WALLET_BOX_BYTES row — reserved-id reads then fall
    // back to empty bytes rather than persisting a useless empty row.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = tracked_tree();

    let outputs = [BlockOutput {
        box_id: [0x07; 32],
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

    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 100, &[0xBB; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    // WALLET_BOXES must still record the box...
    let boxes = txn.open_table(WALLET_BOXES).unwrap();
    assert!(boxes.get([0x07u8; 32]).unwrap().is_some());
    // ...but no box-bytes row for it.
    let tbl = txn.open_table(WALLET_BOX_BYTES).unwrap();
    assert!(
        tbl.get([0x07u8; 32]).unwrap().is_none(),
        "empty box_bytes must not create a WALLET_BOX_BYTES row"
    );
}

#[test]
fn rollback_removes_box_bytes_row() {
    // The box-bytes row must be cleaned up on rollback alongside the
    // WALLET_BOXES entry, so a reorg leaves no orphaned bytes.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::create(dir.path().join("test.redb")).unwrap();
    let wallet = wallet_with_one_tracked();
    let tree = tracked_tree();

    let serialized_box = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let outputs = [BlockOutput {
        box_id: [0x01; 32],
        output_index: 0,
        ergo_tree_bytes: &tree,
        value: 1_000_000_000,
        assets: vec![],
        miner_reward_pubkey: None,
        box_bytes: &serialized_box,
    }];
    let txs = [BlockTx {
        tx_id: [0xAA; 32],
        inputs: &[],
        outputs: &outputs,
    }];

    let txn = db.begin_write().unwrap();
    {
        let (trees, pks) = wallet_data(&wallet);
        apply_block_to_wallet(&txn, &trees, &pks, 100, &[0xBB; 32], &txs).unwrap();
    }
    txn.commit().unwrap();

    let txn = db.begin_write().unwrap();
    rollback_block_from_wallet(&txn, 100, &txs, &NoopRescanGuard).unwrap();
    txn.commit().unwrap();

    let txn = db.begin_read().unwrap();
    let tbl = txn.open_table(WALLET_BOX_BYTES).unwrap();
    assert!(
        tbl.get([0x01u8; 32]).unwrap().is_none(),
        "rollback must remove the box-bytes row"
    );
}

// ----- atomic-commit guarantee -----

#[test]
fn mid_apply_failure_leaves_no_partial_write() {
    // Synthetic failure: we begin a write txn, do half the work,
    // then DROP the txn without committing. The redb contract is
    // that dropped-without-commit = full abort. Verify: an
    // apply that wrote one box but was dropped before scan_height
    // advance must leave the table empty after a fresh read.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    {
        let db = Database::create(&db_path).unwrap();
        let wallet = wallet_with_one_tracked();
        let tree = tracked_tree();
        let outputs = [BlockOutput {
            box_id: [0x01; 32],
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

        let txn = db.begin_write().unwrap();
        {
            let (trees, pks) = wallet_data(&wallet);
            apply_block_to_wallet(&txn, &trees, &pks, 100, &[0xBB; 32], &txs).unwrap();
        }
        // Deliberately drop without committing — simulates a panic
        // between apply and commit.
        drop(txn);
    }

    // Re-open and verify: nothing was persisted.
    let db = Database::open(&db_path).unwrap();
    let txn = db.begin_read().unwrap();
    let scan = txn.open_table(WALLET_SCAN_HEIGHT);
    // Either the table doesn't exist OR it exists with no entries.
    if let Ok(t) = scan {
        assert!(
            t.get(()).unwrap().is_none(),
            "scan height must be empty after dropped txn"
        );
    }
    let boxes = txn.open_table(WALLET_BOXES);
    if let Ok(t) = boxes {
        assert_eq!(t.len().unwrap(), 0, "no boxes after dropped txn");
    }
}

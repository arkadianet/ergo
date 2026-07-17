//! Unit tests for the `/scan/*` block-apply tracking and the wallet
//! rollback scan-height regression. Moved verbatim from the former
//! inline `mod scan_tests` block of `wallet/apply.rs`.

#![cfg(test)]

use super::*;
use crate::store::ScanMatchRecord;
use crate::wallet::types::{ScanBoxStatus, ScanTrackedBox, ScanTxRecord};

fn temp_db() -> (tempfile::TempDir, redb::Database) {
    let dir = tempfile::tempdir().unwrap();
    let db = redb::Database::create(dir.path().join("scan.redb")).unwrap();
    (dir, db)
}

fn match_rec(box_fill: u8, scan_ids: Vec<u16>, h: u32) -> ScanMatchRecord {
    ScanMatchRecord {
        box_id: [box_fill; 32],
        scan_ids,
        box_bytes: vec![0xAB, 0xCD],
        inclusion_height: h,
        creation_out_index: 0,
    }
}

fn out(box_fill: u8, tree: &[u8]) -> BlockOutput<'_> {
    BlockOutput {
        box_id: [box_fill; 32],
        output_index: 0,
        ergo_tree_bytes: tree,
        value: 0,
        assets: Vec::new(),
        miner_reward_pubkey: None,
        box_bytes: &[],
    }
}

/// Fixed block id for all scan-test applies (the record's `block_id`
/// field is asserted against this).
const TEST_BLOCK_ID: [u8; 32] = [0xE0; 32];

fn apply(db: &redb::Database, matches: &[ScanMatchRecord], txs: &[BlockTx<'_>], h: u32) {
    let w = db.begin_write().unwrap();
    apply_block_to_scans(&w, matches, txs, h, &TEST_BLOCK_ID).unwrap();
    w.commit().unwrap();
}

/// Every `WALLET_SCAN_TXS` row, in table (height, tx_id) order.
fn scan_txs(db: &redb::Database) -> Vec<ScanTxRecord> {
    let r = db.begin_read().unwrap();
    let t = match r.open_table(WALLET_SCAN_TXS) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    t.iter()
        .unwrap()
        .map(|e| bincode::deserialize(&e.unwrap().1.value()).unwrap())
        .collect()
}

fn rollback(db: &redb::Database, txs: &[BlockTx<'_>], h: u32) {
    let w = db.begin_write().unwrap();
    rollback_scans_from_block(&w, txs, h).unwrap();
    w.commit().unwrap();
}

fn tracked(db: &redb::Database, scan_id: u16, box_fill: u8) -> Option<ScanTrackedBox> {
    let r = db.begin_read().unwrap();
    let t = match r.open_table(WALLET_SCAN_BOXES) {
        Ok(t) => t,
        Err(_) => return None,
    };
    t.get(scan_box_key(scan_id, &[box_fill; 32]))
        .unwrap()
        .map(|g| bincode::deserialize(&g.value()).unwrap())
}

#[test]
fn live_scan_apply_skips_while_invalidated_but_rescan_does_not() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    let outs = vec![out(0xA1, &tree)];
    let no_in: Vec<[u8; 32]> = vec![];
    let txs = vec![BlockTx {
        tx_id: [1u8; 32],
        inputs: &no_in,
        outputs: &outs,
    }];
    let matches = [match_rec(0xA1, vec![11], 100)];

    // Mark the wallet invalidated (a scan-registry read failure / reorg).
    {
        let w = db.begin_write().unwrap();
        w.open_table(WALLET_SCAN_INVALIDATED)
            .unwrap()
            .insert((), true)
            .unwrap();
        w.commit().unwrap();
    }
    // Live apply must be a no-op while invalidated (mirrors apply_block_to_wallet).
    {
        let w = db.begin_write().unwrap();
        apply_block_to_scans(&w, &matches, &txs, 100, &TEST_BLOCK_ID).unwrap();
        w.commit().unwrap();
    }
    assert!(
        tracked(&db, 11, 0xA1).is_none(),
        "live scan apply skipped while invalidated"
    );
    // The privileged rescan variant writes regardless of the flag.
    {
        let w = db.begin_write().unwrap();
        apply_block_to_scans_rescan(&w, &matches, &txs, 100, &TEST_BLOCK_ID).unwrap();
        w.commit().unwrap();
    }
    assert!(
        tracked(&db, 11, 0xA1).is_some(),
        "rescan variant bypasses the invalidated gate"
    );
}

#[test]
fn apply_creates_one_unspent_row_per_matching_scan() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    let outs = vec![out(0xA1, &tree)];
    let inputs: Vec<[u8; 32]> = vec![];
    let txs = vec![BlockTx {
        tx_id: [1u8; 32],
        inputs: &inputs,
        outputs: &outs,
    }];
    apply(&db, &[match_rec(0xA1, vec![11, 12], 100)], &txs, 100);

    let b11 = tracked(&db, 11, 0xA1).expect("scan 11 tracks the box");
    assert!(matches!(b11.status, ScanBoxStatus::Unspent));
    assert_eq!(b11.inclusion_height, 100);
    assert!(matches!(
        tracked(&db, 12, 0xA1).unwrap().status,
        ScanBoxStatus::Unspent
    ));
    assert!(tracked(&db, 13, 0xA1).is_none(), "non-matching scan absent");
}

#[test]
fn input_spending_a_tracked_box_marks_it_spent_for_all_scans() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    // Block 100: create box A for scans 11 + 12.
    let outs1 = vec![out(0xA1, &tree)];
    let in1: Vec<[u8; 32]> = vec![];
    apply(
        &db,
        &[match_rec(0xA1, vec![11, 12], 100)],
        &[BlockTx {
            tx_id: [1u8; 32],
            inputs: &in1,
            outputs: &outs1,
        }],
        100,
    );
    // Block 101: a tx spends box A.
    let in2: Vec<[u8; 32]> = vec![[0xA1; 32]];
    let outs2: Vec<BlockOutput<'_>> = vec![];
    apply(
        &db,
        &[],
        &[BlockTx {
            tx_id: [2u8; 32],
            inputs: &in2,
            outputs: &outs2,
        }],
        101,
    );

    for sid in [11u16, 12] {
        assert!(
            matches!(
                tracked(&db, sid, 0xA1).unwrap().status,
                ScanBoxStatus::Spent { spent_at: 101, .. }
            ),
            "scan {sid} box marked spent at 101"
        );
    }
}

#[test]
fn same_block_create_then_spend_ends_spent() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    let outs = vec![out(0xA1, &tree)];
    // tx1 creates A (matched); tx2 spends A — same block.
    let in1: Vec<[u8; 32]> = vec![];
    let in2: Vec<[u8; 32]> = vec![[0xA1; 32]];
    let empty: Vec<BlockOutput<'_>> = vec![];
    let txs = vec![
        BlockTx {
            tx_id: [1u8; 32],
            inputs: &in1,
            outputs: &outs,
        },
        BlockTx {
            tx_id: [2u8; 32],
            inputs: &in2,
            outputs: &empty,
        },
    ];
    apply(&db, &[match_rec(0xA1, vec![11], 100)], &txs, 100);
    assert!(matches!(
        tracked(&db, 11, 0xA1).unwrap().status,
        ScanBoxStatus::Spent { spent_at: 100, .. }
    ));
}

#[test]
fn rollback_removes_boxes_created_in_the_block() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    let outs = vec![out(0xA1, &tree)];
    let inputs: Vec<[u8; 32]> = vec![];
    let txs = vec![BlockTx {
        tx_id: [1u8; 32],
        inputs: &inputs,
        outputs: &outs,
    }];
    apply(&db, &[match_rec(0xA1, vec![11], 100)], &txs, 100);
    assert!(tracked(&db, 11, 0xA1).is_some());

    rollback(&db, &txs, 100);
    assert!(tracked(&db, 11, 0xA1).is_none(), "created box removed");
    // index entry gone too.
    let r = db.begin_read().unwrap();
    let idx = r.open_table(WALLET_SCAN_BOX_INDEX).unwrap();
    assert!(idx.get([0xA1u8; 32]).unwrap().is_none());
}

#[test]
fn clear_scan_tracking_drops_all_scan_rows() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    let outs = vec![out(0xA1, &tree)];
    let inputs: Vec<[u8; 32]> = vec![];
    apply(
        &db,
        &[match_rec(0xA1, vec![11, 12], 100)],
        &[BlockTx {
            tx_id: [1u8; 32],
            inputs: &inputs,
            outputs: &outs,
        }],
        100,
    );
    assert!(tracked(&db, 11, 0xA1).is_some());

    let w = db.begin_write().unwrap();
    clear_scan_tracking(&w).unwrap();
    w.commit().unwrap();

    assert!(tracked(&db, 11, 0xA1).is_none(), "all scan boxes cleared");
    assert!(tracked(&db, 12, 0xA1).is_none());
    // Clearing an already-empty/absent set is a no-op (idempotent).
    let w = db.begin_write().unwrap();
    clear_scan_tracking(&w).unwrap();
    w.commit().unwrap();
}

#[test]
fn rollback_unspends_inputs_spent_in_the_block() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    // Block 100 creates A; block 101 spends A.
    let outs1 = vec![out(0xA1, &tree)];
    let in1: Vec<[u8; 32]> = vec![];
    apply(
        &db,
        &[match_rec(0xA1, vec![11], 100)],
        &[BlockTx {
            tx_id: [1u8; 32],
            inputs: &in1,
            outputs: &outs1,
        }],
        100,
    );
    let in2: Vec<[u8; 32]> = vec![[0xA1; 32]];
    let empty: Vec<BlockOutput<'_>> = vec![];
    let txs2 = vec![BlockTx {
        tx_id: [2u8; 32],
        inputs: &in2,
        outputs: &empty,
    }];
    apply(&db, &[], &txs2, 101);
    assert!(matches!(
        tracked(&db, 11, 0xA1).unwrap().status,
        ScanBoxStatus::Spent { .. }
    ));

    // Roll back block 101: A goes back to Unspent (it was created in 100).
    rollback(&db, &txs2, 101);
    assert!(
        matches!(
            tracked(&db, 11, 0xA1).unwrap().status,
            ScanBoxStatus::Unspent
        ),
        "input un-spent on rollback; box still tracked"
    );
}

// ----- rollback_block_from_wallet: WALLET_SCAN_HEIGHT regression -----

struct NoopGuard;
impl RescanGuard for NoopGuard {
    fn abort_in_progress(&self, _txn: &WriteTransaction) -> Result<(), redb::Error> {
        Ok(())
    }
    fn force_invalidate(&self, _txn: &WriteTransaction) -> Result<(), redb::Error> {
        Ok(())
    }
}

fn read_scan_height(db: &redb::Database) -> Option<u32> {
    let r = db.begin_read().unwrap();
    match r.open_table(WALLET_SCAN_HEIGHT) {
        Ok(t) => t.get(()).unwrap().map(|g| g.value()),
        Err(_) => None,
    }
}

fn set_scan_height(db: &redb::Database, h: u32) {
    let w = db.begin_write().unwrap();
    {
        let mut t = w.open_table(WALLET_SCAN_HEIGHT).unwrap();
        t.insert((), h).unwrap();
    }
    w.commit().unwrap();
}

fn rollback_wallet(db: &redb::Database, h: u32) {
    let w = db.begin_write().unwrap();
    let txs: Vec<BlockTx<'_>> = vec![];
    rollback_block_from_wallet(&w, h, &txs, &NoopGuard).unwrap();
    w.commit().unwrap();
}

#[test]
fn rollback_does_not_create_scan_height_for_keyless_wallet() {
    // A keyless / scan-only wallet never advanced WALLET_SCAN_HEIGHT at
    // apply (the has_wallet_tracking gate). A reorg must not conjure a row,
    // which would make /wallet/status + /wallet/balances report a bogus
    // walletHeight for a wallet that never scanned anything.
    let (_d, db) = temp_db();
    rollback_wallet(&db, 100);
    assert_eq!(read_scan_height(&db), None, "no scan-height row created");
}

#[test]
fn rollback_lowers_existing_scan_height_to_h_minus_1() {
    // A keyed wallet scanned to 100; rolling back block 100 regresses it.
    let (_d, db) = temp_db();
    set_scan_height(&db, 100);
    rollback_wallet(&db, 100);
    assert_eq!(read_scan_height(&db), Some(99));
}

#[test]
fn rollback_never_raises_scan_height() {
    // Wallet frozen behind the tip (e.g. mid-rescan) at 50; rolling back a
    // higher block must not raise its scan height to 99.
    let (_d, db) = temp_db();
    set_scan_height(&db, 50);
    rollback_wallet(&db, 100);
    assert_eq!(read_scan_height(&db), Some(50), "rollback never raises");
}

// ----- WALLET_SCAN_TXS (per-tx scan tagging, Scala WalletScanLogic) -----

#[test]
fn apply_records_scan_tx_with_union_of_created_and_spent_scans() {
    let (_d, db) = temp_db();
    let tree = Vec::new();

    // Block 100: tx1 creates A (scans 11+12); tx2 has no scan involvement.
    let outs_a = vec![out(0xA1, &tree)];
    let outs_n = vec![out(0xD0, &tree)];
    let no_in: Vec<[u8; 32]> = vec![];
    apply(
        &db,
        &[match_rec(0xA1, vec![11, 12], 100)],
        &[
            BlockTx {
                tx_id: [1u8; 32],
                inputs: &no_in,
                outputs: &outs_a,
            },
            BlockTx {
                tx_id: [2u8; 32],
                inputs: &no_in,
                outputs: &outs_n,
            },
        ],
        100,
    );
    let rows = scan_txs(&db);
    assert_eq!(rows.len(), 1, "only the scan-involved tx gets a row");
    assert_eq!(rows[0].tx_id, [1u8; 32]);
    assert_eq!(rows[0].block_height, 100);
    assert_eq!(rows[0].block_id, TEST_BLOCK_ID);
    assert_eq!(rows[0].scan_ids, vec![11, 12]);
    assert_eq!(rows[0].created, vec![[0xA1; 32]]);
    assert!(rows[0].spent.is_empty());

    // Block 101: tx3 spends A AND creates C (scan 13) — the row carries
    // the UNION over spent + created (Scala WalletScanLogic:157).
    let outs_c = vec![out(0xC1, &tree)];
    let in_a: Vec<[u8; 32]> = vec![[0xA1; 32]];
    apply(
        &db,
        &[match_rec(0xC1, vec![13], 101)],
        &[BlockTx {
            tx_id: [3u8; 32],
            inputs: &in_a,
            outputs: &outs_c,
        }],
        101,
    );
    let rows = scan_txs(&db);
    assert_eq!(rows.len(), 2);
    let tx3 = &rows[1]; // (height, tx_id) order: block 101 row is second
    assert_eq!(tx3.tx_id, [3u8; 32]);
    assert_eq!(tx3.scan_ids, vec![11, 12, 13], "union, ascending, deduped");
    assert_eq!(tx3.created, vec![[0xC1; 32]]);
    assert_eq!(tx3.spent, vec![[0xA1; 32]]);
}

#[test]
fn same_block_create_then_spend_tags_both_txs() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    let outs_a = vec![out(0xA1, &tree)];
    let no_in: Vec<[u8; 32]> = vec![];
    let in_a: Vec<[u8; 32]> = vec![[0xA1; 32]];
    let no_out: Vec<BlockOutput<'_>> = vec![];
    apply(
        &db,
        &[match_rec(0xA1, vec![11], 100)],
        &[
            BlockTx {
                tx_id: [1u8; 32],
                inputs: &no_in,
                outputs: &outs_a,
            },
            BlockTx {
                tx_id: [2u8; 32],
                inputs: &in_a,
                outputs: &no_out,
            },
        ],
        100,
    );
    let rows = scan_txs(&db);
    assert_eq!(rows.len(), 2, "creator and same-block spender both tagged");
    assert_eq!(rows[0].created, vec![[0xA1; 32]]);
    assert_eq!(rows[1].spent, vec![[0xA1; 32]]);
    assert_eq!(rows[1].scan_ids, vec![11]);
}

#[test]
fn rollback_removes_scan_tx_rows_at_that_height_only() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    let outs_a = vec![out(0xA1, &tree)];
    let outs_b = vec![out(0xB1, &tree)];
    let no_in: Vec<[u8; 32]> = vec![];
    apply(
        &db,
        &[match_rec(0xA1, vec![11], 100)],
        &[BlockTx {
            tx_id: [1u8; 32],
            inputs: &no_in,
            outputs: &outs_a,
        }],
        100,
    );
    apply(
        &db,
        &[match_rec(0xB1, vec![11], 101)],
        &[BlockTx {
            tx_id: [2u8; 32],
            inputs: &no_in,
            outputs: &outs_b,
        }],
        101,
    );
    assert_eq!(scan_txs(&db).len(), 2);

    rollback(
        &db,
        &[BlockTx {
            tx_id: [2u8; 32],
            inputs: &no_in,
            outputs: &outs_b,
        }],
        101,
    );
    let rows = scan_txs(&db);
    assert_eq!(rows.len(), 1, "only the rolled-back height's row removed");
    assert_eq!(rows[0].block_height, 100);
}

#[test]
fn clear_scan_tracking_drops_scan_tx_rows() {
    let (_d, db) = temp_db();
    let tree = Vec::new();
    let outs = vec![out(0xA1, &tree)];
    let no_in: Vec<[u8; 32]> = vec![];
    apply(
        &db,
        &[match_rec(0xA1, vec![11], 100)],
        &[BlockTx {
            tx_id: [1u8; 32],
            inputs: &no_in,
            outputs: &outs,
        }],
        100,
    );
    assert_eq!(scan_txs(&db).len(), 1);

    let w = db.begin_write().unwrap();
    clear_scan_tracking(&w).unwrap();
    w.commit().unwrap();
    assert!(scan_txs(&db).is_empty(), "scan-tx rows cleared");
}

//! Scan participation in `WalletScanService::rescan_full_rebuild` (PR 6 of
//! `/scan/*`). A full rebuild (start_height == 0) with a `ScanRescanMatcher`
//! must rebuild the scan tables (`WALLET_SCAN_BOXES` / `_INDEX` / `_TXS`)
//! from the replayed blocks — mirroring the live block-apply path so a
//! rescan reproduces exactly what live tracking would have produced.

#![allow(clippy::result_large_err)] // RescanReadError is large; test closures can't avoid it

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_state::store::{block_txs_for_wallet_at_height, StateError, StateStore};
use ergo_state::wallet::reader::WalletReader;
use ergo_state::wallet::scan::{
    OwnedBlockOutput, RescanBlock, RescanError, RescanReadError, RescanTx, ScanRescanMatcher,
    WalletScanService,
};
use ergo_state::wallet::tables::{
    scan_box_key, WALLET_SCAN_BOXES, WALLET_SCAN_HEIGHT, WALLET_SCAN_INVALIDATED, WALLET_SCAN_TXS,
};
use ergo_state::wallet::types::{ScanBoxStatus, ScanTrackedBox, ScanTxRecord};
use redb::{Database, ReadableTable};

/// Fake matcher: maps a box's full serialized bytes to the scan ids that
/// "match" it (stands in for the `ergo-wallet` predicate matcher that runs
/// in `ergo-node` at live apply).
struct FakeMatcher {
    by_box_bytes: HashMap<Vec<u8>, Vec<u16>>,
}

impl ScanRescanMatcher for FakeMatcher {
    fn match_boxes(&self, boxes: &[&[u8]]) -> Result<Vec<Vec<u16>>, String> {
        Ok(boxes
            .iter()
            .map(|b| self.by_box_bytes.get(*b).cloned().unwrap_or_default())
            .collect())
    }
}

fn out(box_fill: u8, box_bytes: Vec<u8>) -> OwnedBlockOutput {
    OwnedBlockOutput {
        box_id: [box_fill; 32],
        output_index: 0,
        ergo_tree_bytes: vec![0x00], // wallet path ignores (no tracked pks)
        value: 1_000_000,
        assets: vec![],
        miner_reward_pubkey: None,
        box_bytes,
    }
}

fn read_tracked(db: &Database, scan_id: u16, box_fill: u8) -> Option<ScanTrackedBox> {
    let txn = db.begin_read().unwrap();
    let t = match txn.open_table(WALLET_SCAN_BOXES) {
        Ok(t) => t,
        Err(_) => return None,
    };
    t.get(scan_box_key(scan_id, &[box_fill; 32]))
        .unwrap()
        .map(|g| bincode::deserialize(&g.value()).unwrap())
}

fn scan_txs(db: &Database) -> Vec<ScanTxRecord> {
    let txn = db.begin_read().unwrap();
    let t = match txn.open_table(WALLET_SCAN_TXS) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    t.iter()
        .unwrap()
        .map(|e| bincode::deserialize(&e.unwrap().1.value()).unwrap())
        .collect()
}

#[test]
fn full_rescan_from_zero_replays_applied_blocks_without_genesis_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).unwrap();
    store.initialize_genesis(&[]).unwrap();
    let mut parent = ModifierId::from_bytes([0; 32]);
    let mut header_ids = Vec::new();
    for height in 1..=3 {
        let header = Header {
            version: 2,
            parent_id: parent,
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: store.root_digest(),
            timestamp: 1_000_000 + height as u64,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 16842752,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
                nonce: [0; 8],
            },
        };
        let (header_bytes, header_id) = serialize_header(&header).unwrap();
        let header_id_bytes: [u8; 32] = *header_id.as_bytes();
        store.store_header(&header_id_bytes, &header_bytes).unwrap();
        let mut writer = VlqWriter::new();
        write_block_transactions(
            &mut writer,
            &BlockTransactions {
                header_id,
                transactions: Vec::new(),
            },
        )
        .unwrap();
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &header_id_bytes,
            header.transactions_root.as_bytes(),
        );
        store
            .store_block_section(&section_id, &writer.result())
            .unwrap();
        let expected = store.root_digest();
        store
            .apply_block_unchecked_for_test(height, &header_id_bytes, &expected, &[])
            .unwrap();
        parent = header_id;
        header_ids.push(header_id_bytes);
    }

    let db = store.db_arc();
    let read_db = db.clone();
    WalletScanService::rescan_full_rebuild(
        &db,
        BTreeSet::new(),
        BTreeMap::new(),
        0,
        3,
        move |height| {
            block_txs_for_wallet_at_height(&read_db, height).map(|block| {
                block.map(|(block_id, txs)| RescanBlock {
                    block_id,
                    txs: txs
                        .into_iter()
                        .map(|tx| RescanTx {
                            tx_id: tx.tx_id,
                            inputs: tx.inputs,
                            outputs: tx
                                .outputs
                                .into_iter()
                                .map(|output| OwnedBlockOutput {
                                    box_id: output.box_id,
                                    output_index: output.output_index,
                                    ergo_tree_bytes: output.ergo_tree_bytes,
                                    value: output.value,
                                    assets: output.assets,
                                    miner_reward_pubkey: output.miner_reward_pubkey,
                                    box_bytes: output.box_bytes,
                                })
                                .collect(),
                        })
                        .collect(),
                })
            })
        },
        || Ok(3),
        || false,
        None,
    )
    .unwrap();

    let read = db.begin_read().unwrap();
    let cursor = WalletReader::new(&read).scan_cursor().unwrap().unwrap();
    assert_eq!(cursor.height, 3);
    assert_eq!(cursor.header_id, Some(header_ids[2]));
}

#[test]
fn full_rescan_rebuilds_scan_tables_with_create_and_spend() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("t.redb")).unwrap());

    // Box A's serialized bytes match scan 11; box B matches nothing.
    let a_bytes = vec![0xA1, 0xA1, 0xA1];
    let b_bytes = vec![0xB1, 0xB1, 0xB1];
    let matcher = FakeMatcher {
        by_box_bytes: HashMap::from([(a_bytes.clone(), vec![11u16])]),
    };

    // h=1: tx1 creates A. h=2: tx2 spends A and creates B.
    let block1 = RescanBlock {
        block_id: [0xE1; 32],
        txs: vec![RescanTx {
            tx_id: [0x01; 32],
            inputs: vec![],
            outputs: vec![out(0xA1, a_bytes)],
        }],
    };
    let block2 = RescanBlock {
        block_id: [0xE2; 32],
        txs: vec![RescanTx {
            tx_id: [0x02; 32],
            inputs: vec![[0xA1; 32]],
            outputs: vec![out(0xB1, b_bytes)],
        }],
    };

    let read_block = move |h: u32| -> Result<Option<RescanBlock>, RescanReadError> {
        Ok(match h {
            1 => Some(block1.clone()),
            2 => Some(block2.clone()),
            _ => None,
        })
    };
    let read_tip = || -> Result<u32, RescanReadError> { Ok(2) };

    WalletScanService::rescan_full_rebuild(
        &db,
        BTreeSet::new(), // no tracked pubkeys — exercise scans only
        BTreeMap::new(),
        0,
        2,
        read_block,
        read_tip,
        || false,
        Some(&matcher),
    )
    .unwrap();

    // A is tracked by scan 11, created at h=1, then Spent at h=2.
    let a = read_tracked(&db, 11, 0xA1).expect("scan 11 tracks box A after rescan");
    assert_eq!(a.inclusion_height, 1);
    assert!(
        matches!(
            a.status,
            ScanBoxStatus::Spent {
                spent_at: 2,
                spent_in_tx,
            } if spent_in_tx == [0x02; 32]
        ),
        "A must be Spent at h=2 by tx2; got {:?}",
        a.status
    );
    // B matched nothing → not tracked.
    assert!(read_tracked(&db, 11, 0xB1).is_none());

    // Both txs are tagged: tx1 (creates A) and tx2 (spends A) — union {11}.
    let rows = scan_txs(&db);
    assert_eq!(rows.len(), 2, "create-tx + spend-tx both tagged");
    assert_eq!(rows[0].block_height, 1);
    assert_eq!(rows[0].scan_ids, vec![11]);
    assert_eq!(rows[0].created, vec![[0xA1; 32]]);
    assert_eq!(rows[1].block_height, 2);
    assert_eq!(rows[1].scan_ids, vec![11]);
    assert_eq!(rows[1].spent, vec![[0xA1; 32]]);
}

#[test]
fn full_rescan_clears_stale_scan_rows_before_rebuilding() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("t.redb")).unwrap());

    // Pre-seed a stale tracked row that the rebuild must NOT keep (it would
    // be orphaned from a prior chain — e.g. after a non-replayable reorg).
    {
        let stale = ScanTrackedBox {
            scan_id: 11,
            box_id: [0xCC; 32],
            inclusion_height: 999,
            creation_out_index: 0,
            box_bytes: vec![0xCC],
            status: ScanBoxStatus::Unspent,
        };
        let w = db.begin_write().unwrap();
        {
            let mut t = w.open_table(WALLET_SCAN_BOXES).unwrap();
            t.insert(
                scan_box_key(11, &[0xCC; 32]),
                bincode::serialize(&stale).unwrap(),
            )
            .unwrap();
        }
        w.commit().unwrap();
    }

    let a_bytes = vec![0xA1, 0xA1];
    let matcher = FakeMatcher {
        by_box_bytes: HashMap::from([(a_bytes.clone(), vec![11u16])]),
    };
    let block1 = RescanBlock {
        block_id: [0xE1; 32],
        txs: vec![RescanTx {
            tx_id: [0x01; 32],
            inputs: vec![],
            outputs: vec![out(0xA1, a_bytes)],
        }],
    };
    let read_block = move |h: u32| -> Result<Option<RescanBlock>, RescanReadError> {
        Ok(match h {
            1 => Some(block1.clone()),
            _ => None,
        })
    };

    WalletScanService::rescan_full_rebuild(
        &db,
        BTreeSet::new(),
        BTreeMap::new(),
        0,
        1,
        read_block,
        || Ok(1),
        || false,
        Some(&matcher),
    )
    .unwrap();

    assert!(
        read_tracked(&db, 11, 0xCC).is_none(),
        "stale pre-rescan row must be cleared by the full rebuild"
    );
    assert!(
        read_tracked(&db, 11, 0xA1).is_some(),
        "the replayed box is tracked"
    );
}

#[test]
fn rescan_without_a_matcher_leaves_scan_tables_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("t.redb")).unwrap());

    let block1 = RescanBlock {
        block_id: [0xE1; 32],
        txs: vec![RescanTx {
            tx_id: [0x01; 32],
            inputs: vec![],
            outputs: vec![out(0xA1, vec![0xA1])],
        }],
    };
    let read_block = move |h: u32| -> Result<Option<RescanBlock>, RescanReadError> {
        Ok(match h {
            1 => Some(block1.clone()),
            _ => None,
        })
    };

    // None matcher: the no-scans node path — scans never touched.
    WalletScanService::rescan_full_rebuild(
        &db,
        BTreeSet::new(),
        BTreeMap::new(),
        0,
        1,
        read_block,
        || Ok(1),
        || false,
        None,
    )
    .unwrap();

    assert!(
        scan_txs(&db).is_empty(),
        "no scan-tx rows without a matcher"
    );
    assert!(read_tracked(&db, 11, 0xA1).is_none());
}

/// A matcher that violates the trait contract (one result per input box):
/// returns an empty Vec regardless of input count.
struct BadCountMatcher;
impl ScanRescanMatcher for BadCountMatcher {
    fn match_boxes(&self, _boxes: &[&[u8]]) -> Result<Vec<Vec<u16>>, String> {
        Ok(Vec::new())
    }
}

fn read_invalidated(db: &Database) -> Option<bool> {
    let txn = db.begin_read().unwrap();
    let t = match txn.open_table(WALLET_SCAN_INVALIDATED) {
        Ok(t) => t,
        Err(_) => return None,
    };
    t.get(()).unwrap().map(|g| g.value())
}

fn read_scan_height(db: &Database) -> Option<u32> {
    let txn = db.begin_read().unwrap();
    let t = match txn.open_table(WALLET_SCAN_HEIGHT) {
        Ok(t) => t,
        Err(_) => return None,
    };
    t.get(()).unwrap().map(|g| g.value())
}

#[test]
fn rescan_missing_block_stops_before_advancing_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("t.redb")).unwrap());
    let result = WalletScanService::rescan_full_rebuild(
        &db,
        BTreeSet::new(),
        BTreeMap::new(),
        0,
        2,
        |height| {
            if height == 0 {
                Ok(Some(RescanBlock {
                    block_id: [0; 32],
                    txs: vec![],
                }))
            } else {
                Ok(None)
            }
        },
        || Ok(2),
        || false,
        None,
    );

    assert!(matches!(
        result,
        Err(RescanError::Read(RescanReadError::Missing { height: 1 }))
    ));
    assert_eq!(read_scan_height(&db), Some(0));
    assert_eq!(read_invalidated(&db), Some(true));
}

#[test]
fn rescan_storage_error_is_distinct_and_keeps_cursor_before_hole() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("t.redb")).unwrap());
    let result = WalletScanService::rescan_full_rebuild(
        &db,
        BTreeSet::new(),
        BTreeMap::new(),
        0,
        2,
        |height| {
            if height == 0 {
                Ok(Some(RescanBlock {
                    block_id: [0; 32],
                    txs: vec![],
                }))
            } else {
                Err(RescanReadError::Storage {
                    height,
                    source: StateError::Serialization("synthetic read failure".to_string()),
                })
            }
        },
        || Ok(2),
        || false,
        None,
    );

    assert!(matches!(
        result,
        Err(RescanError::Read(RescanReadError::Storage {
            height: 1,
            ..
        }))
    ));
    assert_eq!(read_scan_height(&db), Some(0));
    assert_eq!(read_invalidated(&db), Some(true));
}

#[test]
fn count_mismatch_leaves_wallet_invalidated_not_falsely_complete() {
    // A buggy matcher that returns the wrong result count must NOT let the
    // rebuild advertise success: the scan tables are incomplete, so
    // WALLET_SCAN_INVALIDATED must remain set (the full-rebuild clear at the
    // end is skipped) rather than being cleared to false. Otherwise an
    // operator sees "rescan complete" over a silently-truncated scan set.
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::create(dir.path().join("t.redb")).unwrap());

    let block1 = RescanBlock {
        block_id: [0xE1; 32],
        txs: vec![RescanTx {
            tx_id: [0x01; 32],
            inputs: vec![],
            outputs: vec![out(0xA1, vec![0xA1])], // 1 box; matcher returns 0 results
        }],
    };
    let read_block = move |h: u32| -> Result<Option<RescanBlock>, RescanReadError> {
        Ok(match h {
            1 => Some(block1.clone()),
            _ => None,
        })
    };

    let result = WalletScanService::rescan_full_rebuild(
        &db,
        BTreeSet::new(),
        BTreeMap::new(),
        0,
        1,
        read_block,
        || Ok(1),
        || false,
        Some(&BadCountMatcher),
    );
    assert!(matches!(
        result,
        Err(RescanError::Matcher { height: 1, .. })
    ));

    assert_eq!(
        read_invalidated(&db),
        Some(true),
        "a count-mismatch block must leave WALLET_SCAN_INVALIDATED set"
    );
}

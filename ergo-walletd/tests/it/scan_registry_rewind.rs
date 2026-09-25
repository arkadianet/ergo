//! Real scan-registry rewind, through the daemon's own sync loop.
//!
//! `rewind_scans_from_height` (reached via `WalletWrite::rewind_to_ancestor`)
//! is the range-rewind counterpart to `rollback_scans_from_block`: on a
//! retained-history reorg the orphaned block transactions are gone, so the
//! rewind has to work from the *persisted* rows instead. It touches all three
//! scan tables — `WALLET_SCAN_BOXES`, `WALLET_SCAN_BOX_INDEX`, and
//! `WALLET_SCAN_TXS` — and the daemon's sync path only populates them while a
//! scan registry is non-empty (`sync::scan_records` returns `None` when
//! `matcher.registry().is_empty()`).
//!
//! Every other `tests/it/sync.rs` case runs with an empty registry, so
//! `rewind_scans_from_height` was previously only ever reached against empty
//! tables — effectively unexercised. This module registers a real scan through
//! the store's `put_scan` write API (the same call the node's `/scan/register`
//! handler makes), so the daemon's forward path populates the tables for real,
//! and then drives an ancestor rewind and asserts the surviving rows, the
//! restored statuses, and the reverse index.
//!
//! **Why the test can register a scan when the daemon cannot.** The standalone
//! daemon's only scan input is the descriptor file, whose strict
//! `deny_unknown_fields` schema admits public keys, paths, and labels only — so
//! in production the registry is always empty and `/api/v1/scans` always
//! returns `[]` (pinned by `daemon_boot.rs`). Scan registration is a *node*
//! capability, not a daemon one. The row layout and the `WalletStore` write API
//! are the same either way, so seeding the registry through `put_scan`
//! exercises exactly the code a node-registered scan would, without widening the
//! daemon's descriptor schema or its dependency boundary.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::Token;
use ergo_wallet_service::scan::predicate::ScanningPredicate;
use ergo_wallet_service::wallet::scan::{RescanBlock, RescanTx, WalletScanMatcher};
use ergo_wallet_service::wallet::tables::{
    scan_box_key, WALLET_SCAN_BOXES, WALLET_SCAN_BOX_INDEX, WALLET_SCAN_TXS,
};
use ergo_wallet_service::wallet::types::ScanBoxStatus;
use ergo_wallet_service::wallet::ScanRescanMatcher;
use ergo_wallet_service::{
    AncestorBlocksSince, BlocksSinceRequest, BlocksSinceResponse, ChainBlock, ChainClient,
    ChainClientError, ChainCursor, ChainInput, ChainOutput, ChainSnapshot, ChainTransaction,
    CommittedTip, ForwardBlocksSince, OwnedBlockOutput, RedbWalletStore, Scan, ScanTrackedBox,
    ScanTxRecord, SubmitRequest, SubmitResponse, UtxoLookup, WalletInteraction, WalletService,
    WalletStore,
};
use redb::ReadableTable;

use ergo_walletd::sync::{StandaloneSyncer, SyncConfig};
use ergo_walletd::tip::CachedNodeTip;

/// The asset the registered scan tracks.
const ASSET_ID: [u8; 32] = [0xAB; 32];
/// The first user-allocatable scan id (`PAYMENTS_SCAN_ID + 1`). Ids 1..=10 are
/// reserved and `WalletScanMatcher::from_store` rejects anything at or below
/// them.
const SCAN_ID: u16 = 11;
/// Tag for the original fork's blocks. The replacement fork uses
/// `FORK_REPLACEMENT` for heights 2 and 3 and shares height 1 with the
/// original — that shared block is the common ancestor.
const FORK_ORIGINAL: u8 = 0x10;
const FORK_REPLACEMENT: u8 = 0x20;

// ----- fixtures: real boxes the matcher actually evaluates -----

fn proposition_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: true,
        constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        },
    }
}

/// A real serialized box with the identity the chain wire must agree with. The
/// daemon's `convert_block` re-derives the box id from these bytes and rejects
/// any mismatch, so the fixture cannot cheat.
fn output_box(tx: u8, index: u16, creation_height: u32, tracked: bool) -> ChainOutput {
    let tokens = if tracked {
        vec![Token {
            token_id: Digest32::from_bytes(ASSET_ID),
            amount: 1_000,
        }]
    } else {
        Vec::new()
    };
    let candidate = ErgoBoxCandidate::new(
        1_000_000,
        proposition_tree(),
        creation_height,
        tokens,
        AdditionalRegisters::empty(),
    )
    .unwrap();
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id(tx)),
        index,
    };
    ChainOutput {
        box_id: *ergo_box.box_id().unwrap().as_bytes(),
        index,
        bytes: serialize_ergo_box(&ergo_box).unwrap(),
    }
}

fn tx_id(tag: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = 0x77;
    id[1] = tag;
    id
}

fn input(box_id: [u8; 32]) -> ChainInput {
    ChainInput { box_id, index: 0 }
}

fn transaction(tx: u8, inputs: Vec<ChainInput>, outputs: Vec<ChainOutput>) -> ChainTransaction {
    ChainTransaction {
        tx_id: tx_id(tx),
        inputs,
        outputs,
    }
}

/// Block ids are derived from `(height, fork tag)`, so a replacement block at
/// the same height always has a different id — which is what the sync loop's
/// parent-mismatch check and the node's ancestor walk both key on.
fn block_id(height: u32, fork: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = fork;
    id[1] = height as u8;
    id
}

fn chain_block(height: u32, fork: u8, transactions: Vec<ChainTransaction>) -> ChainBlock {
    ChainBlock {
        block_id: block_id(height, fork),
        height,
        parent_id: block_id(height.saturating_sub(1), fork),
        transactions,
    }
}

/// A block whose parent is named explicitly — the replacement fork's blocks hang
/// off the *original* height-1 block, which is the common ancestor, so the
/// daemon's parent-mismatch check has a real ancestor to agree with.
fn forked_block(
    height: u32,
    fork: u8,
    parent: [u8; 32],
    transactions: Vec<ChainTransaction>,
) -> ChainBlock {
    ChainBlock {
        block_id: block_id(height, fork),
        height,
        parent_id: parent,
        transactions,
    }
}

/// The three blocks a fixture shares, so both forks agree on what they are
/// tracking.
struct Boxes {
    a: ChainOutput,
    b: ChainOutput,
    c: ChainOutput,
    d: ChainOutput,
    e: ChainOutput,
    f: ChainOutput,
}

fn boxes() -> Boxes {
    Boxes {
        a: output_box(1, 0, 1, true),
        b: output_box(2, 0, 2, true),
        c: output_box(2, 1, 2, false),
        d: output_box(3, 0, 3, true),
        e: output_box(4, 0, 2, true),
        f: output_box(5, 0, 3, true),
    }
}

/// The original fork, heights 1..=3:
///
/// * 1 — creates `A` (tracked asset) → matched, `Unspent`.
/// * 2 — spends `A`; creates `B` (tracked) and `C` (untracked) → `A` becomes
///   `Spent` at height 2, and the tx is stored with the scan-id union.
/// * 3 — spends `B`; creates `D` (tracked) → `B` becomes `Spent` at height 3.
fn original_fork(boxes: &Boxes) -> Vec<ChainBlock> {
    vec![
        chain_block(
            1,
            FORK_ORIGINAL,
            vec![transaction(1, Vec::new(), vec![boxes.a.clone()])],
        ),
        chain_block(
            2,
            FORK_ORIGINAL,
            vec![transaction(
                2,
                vec![input(boxes.a.box_id)],
                vec![boxes.b.clone(), boxes.c.clone()],
            )],
        ),
        chain_block(
            3,
            FORK_ORIGINAL,
            vec![transaction(
                3,
                vec![input(boxes.b.box_id)],
                vec![boxes.d.clone()],
            )],
        ),
    ]
}

/// The replacement fork, heights 1..=3. Height 1 is byte-identical to the
/// original (the common ancestor); heights 2 and 3 are different blocks that
/// never spend `A`, so after the rewind `A` must stay `Unspent` and the new
/// boxes must be the ones that end up tracked.
fn replacement_fork(boxes: &Boxes) -> Vec<ChainBlock> {
    vec![
        chain_block(
            1,
            FORK_ORIGINAL,
            vec![transaction(1, Vec::new(), vec![boxes.a.clone()])],
        ),
        forked_block(
            2,
            FORK_REPLACEMENT,
            block_id(1, FORK_ORIGINAL),
            vec![transaction(4, Vec::new(), vec![boxes.e.clone()])],
        ),
        forked_block(
            3,
            FORK_REPLACEMENT,
            block_id(2, FORK_REPLACEMENT),
            vec![transaction(
                5,
                vec![input(boxes.e.box_id)],
                vec![boxes.f.clone()],
            )],
        ),
    ]
}

fn original_tip() -> CommittedTip {
    CommittedTip::new(3, block_id(3, FORK_ORIGINAL))
}

fn replacement_tip() -> CommittedTip {
    CommittedTip::new(3, block_id(3, FORK_REPLACEMENT))
}

// ----- the node -----

/// A scripted node: an ordered queue of `blocks-since` answers, then a
/// deterministic forward generator over a fixed fork. The tip is fixed, so both
/// the daemon's tip check and its rewind target are pinned by the fixture.
struct ScriptedNode {
    tip: CommittedTip,
    answers: Mutex<VecDeque<BlocksSinceResponse>>,
    fork: Vec<ChainBlock>,
}

impl ScriptedNode {
    fn new(
        tip: CommittedTip,
        fork: Vec<ChainBlock>,
        answers: impl IntoIterator<Item = BlocksSinceResponse>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tip,
            answers: Mutex::new(answers.into_iter().collect()),
            fork,
        })
    }

    /// A node that has only its forward pages left to answer.
    fn at_tip(tip: CommittedTip, fork: Vec<ChainBlock>) -> Arc<Self> {
        Self::new(tip, fork, [])
    }
}

impl ChainClient for ScriptedNode {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
        Ok(self.tip.clone())
    }

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn blocks_since(
        &self,
        request: BlocksSinceRequest,
    ) -> Result<BlocksSinceResponse, ChainClientError> {
        if let Some(answer) = self.answers.lock().expect("answers lock").pop_front() {
            return Ok(answer);
        }
        let first = request.cursor.height.saturating_add(1);
        let last = self
            .tip
            .height
            .min(first.saturating_add(request.limit.saturating_sub(1)));
        Ok(BlocksSinceResponse::Forward(ForwardBlocksSince {
            tip: self.tip.clone(),
            blocks: (first..=last)
                .filter_map(|height| self.fork.get(height as usize - 1).cloned())
                .collect(),
        }))
    }

    fn lookup_utxo(
        &self,
        _box_id: [u8; 32],
        _expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }

    fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }
}

// ----- the store under test -----

/// A standalone store plus the `Database` handle the test keeps, because
/// `RedbWalletStore` exposes no accessor for `WALLET_SCAN_BOX_INDEX`.
struct Wallet {
    store: Arc<RedbWalletStore>,
    database: Arc<redb::Database>,
}

fn open_wallet(dir: &Path) -> Wallet {
    let database = Arc::new(redb::Database::create(dir.join("wallet.redb")).unwrap());
    let store = Arc::new(RedbWalletStore::from_standalone_db(database.clone()).unwrap());
    // Start from a genesis cursor with nothing invalidated, exactly like a
    // freshly created standalone wallet.
    let mut write = store.begin_write().unwrap();
    write.set_scan_cursor(0, None).unwrap();
    write.commit().unwrap();
    Wallet { store, database }
}

/// Register scan `SCAN_ID` (a `containsAsset` rule) the way the node's
/// `/scan/register` handler does, so `WalletScanMatcher::from_store` — and
/// therefore the daemon's sync path — sees a real rule.
fn register_scan(wallet: &Wallet) {
    let scan = Scan {
        scan_id: SCAN_ID,
        scan_name: "walletd-rewind-fixture".to_string(),
        tracking_rule: ScanningPredicate::ContainsAsset { asset_id: ASSET_ID },
        wallet_interaction: WalletInteraction::Shared,
        remove_offchain: true,
    };
    let mut write = wallet.store.begin_write().unwrap();
    write
        .put_scan(SCAN_ID, serde_json::to_vec(&scan).unwrap(), SCAN_ID)
        .unwrap();
    write.commit().unwrap();
    assert_eq!(
        wallet
            .store
            .read()
            .unwrap()
            .registered_scan_count()
            .unwrap(),
        1,
        "the registry must be non-empty, or the daemon never writes scan rows"
    );
}

fn syncer(chain: Arc<dyn ChainClient>, store: Arc<RedbWalletStore>) -> StandaloneSyncer {
    let tip = Arc::new(CachedNodeTip::new(chain.clone()));
    let service = Arc::new(WalletService::new(store, chain));
    StandaloneSyncer::new(
        service,
        SyncConfig {
            batch: 16,
            page: 16,
            retry_delay: Duration::ZERO,
            max_retry_delay: Duration::ZERO,
        },
        tip,
    )
}

/// `WALLET_SCAN_BOXES` rows for `SCAN_ID`, in `(inclusion_height, box_id)`
/// order. Iterating the `scan_id` key prefix is what the store's own reads do,
/// so this sees exactly the rows the rewind rewrites.
fn scan_box_rows(wallet: &Wallet) -> Vec<ScanTrackedBox> {
    let txn = wallet.database.begin_read().unwrap();
    let Ok(rows) = txn.open_table(WALLET_SCAN_BOXES) else {
        return Vec::new();
    };
    let prefix = scan_box_key(SCAN_ID, &[0; 32]);
    let mut out: Vec<ScanTrackedBox> = rows
        .range(prefix..)
        .unwrap()
        .take_while(|entry| match entry {
            Ok((key, _)) => key.value()[..2] == prefix[..2],
            Err(_) => false,
        })
        .map(|entry| bincode::deserialize(entry.unwrap().1.value().as_slice()).unwrap())
        .collect();
    out.sort_by_key(|tracked| (tracked.inclusion_height, tracked.box_id));
    out
}

/// One row, read by its `(scan_id, box_id)` key, so a *missing* row is
/// reported as missing rather than as an empty scan.
fn scan_box_row(wallet: &Wallet, box_id: [u8; 32]) -> Option<ScanTrackedBox> {
    let txn = wallet.database.begin_read().unwrap();
    let rows = match txn.open_table(WALLET_SCAN_BOXES) {
        Ok(rows) => rows,
        Err(_) => return None,
    };
    let row = rows.get(scan_box_key(SCAN_ID, &box_id)).unwrap()?;
    Some(bincode::deserialize(row.value().as_slice()).unwrap())
}

fn scan_tx_rows(wallet: &Wallet) -> Vec<ScanTxRecord> {
    let txn = wallet.database.begin_read().unwrap();
    let Ok(rows) = txn.open_table(WALLET_SCAN_TXS) else {
        return Vec::new();
    };
    let mut out: Vec<ScanTxRecord> = rows
        .iter()
        .unwrap()
        .map(|entry| bincode::deserialize(entry.unwrap().1.value().as_slice()).unwrap())
        .collect();
    out.sort_by_key(|record| (record.block_height, record.tx_id));
    out
}

/// The raw `WALLET_SCAN_BOX_INDEX` reverse index. A stale row here is the bug a
/// behavioural assertion can miss: a removed box would still look "already
/// applied" to the spend path of a later block.
fn reverse_index(wallet: &Wallet) -> BTreeMap<[u8; 32], Vec<u16>> {
    let txn = wallet.database.begin_read().unwrap();
    let Ok(index) = txn.open_table(WALLET_SCAN_BOX_INDEX) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for entry in index.iter().unwrap() {
        let (key, value) = entry.unwrap();
        let box_id = key.value();
        out.insert(
            box_id,
            bincode::deserialize::<Vec<u16>>(value.value().as_slice()).unwrap(),
        );
    }
    out
}

fn ids(rows: &[ScanTrackedBox]) -> Vec<([u8; 32], u32)> {
    rows.iter()
        .map(|tracked| (tracked.box_id, tracked.inclusion_height))
        .collect()
}

// ----- tests -----

/// The rewind contract, end to end through the daemon's sync loop:
///
/// 1. sync the three blocks of the original fork, so all three scan tables are
///    non-empty and `WALLET_SCAN_BOXES` holds both `Unspent` and `Spent` rows;
/// 2. the node then reports a reorg to the height-1 common ancestor, so the
///    rewind runs with `start_height = 2`;
/// 3. assert the surviving rows, the restored statuses, and the reverse index,
///    then assert the replacement fork is what gets replayed.
#[test]
fn ancestor_rewind_drops_post_boundary_rows_and_restores_spent_statuses() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = open_wallet(dir.path());
    register_scan(&wallet);
    let boxes = boxes();
    let original = original_fork(&boxes);
    let replacement = replacement_fork(&boxes);

    let tip = original_tip();
    let chain = ScriptedNode::new(
        tip.clone(),
        original.clone(),
        [BlocksSinceResponse::Forward(ForwardBlocksSince {
            tip: tip.clone(),
            blocks: original.clone(),
        })],
    );
    let first_pass = syncer(chain, wallet.store.clone());

    // --- step 1: forward sync the original fork ---
    let first = first_pass.sync_once().unwrap();
    assert!(first.completed, "{first:?}");
    assert_eq!(first.wallet_height, 3);
    assert_eq!(first.blocks_processed, 3);

    // Pre-rewind baseline: every table is populated and the statuses differ.
    assert_eq!(
        ids(&scan_box_rows(&wallet)),
        vec![
            (boxes.a.box_id, 1),
            (boxes.b.box_id, 2),
            (boxes.d.box_id, 3)
        ],
        "A, B and D carry the tracked asset; C does not"
    );
    assert_eq!(
        scan_box_row(&wallet, boxes.a.box_id).unwrap().status,
        ScanBoxStatus::Spent {
            spent_in_tx: tx_id(2),
            spent_at: 2
        }
    );
    assert_eq!(
        scan_box_row(&wallet, boxes.b.box_id).unwrap().status,
        ScanBoxStatus::Spent {
            spent_in_tx: tx_id(3),
            spent_at: 3
        }
    );
    assert_eq!(
        scan_box_row(&wallet, boxes.d.box_id).unwrap().status,
        ScanBoxStatus::Unspent
    );
    // The untracked box has no row and no index entry, and the index holds
    // exactly the tracked boxes.
    assert!(scan_box_row(&wallet, boxes.c.box_id).is_none());
    assert_eq!(
        reverse_index(&wallet),
        BTreeMap::from([
            (boxes.a.box_id, vec![SCAN_ID]),
            (boxes.b.box_id, vec![SCAN_ID]),
            (boxes.d.box_id, vec![SCAN_ID]),
        ])
    );
    let txs = scan_tx_rows(&wallet);
    assert_eq!(
        txs.iter()
            .map(|record| (record.block_height, record.tx_id))
            .collect::<Vec<_>>(),
        vec![(1, tx_id(1)), (2, tx_id(2)), (3, tx_id(3))],
        "every tx that created or spent a tracked box is stored, keyed by height"
    );
    assert_eq!(txs[0].created, vec![boxes.a.box_id]);
    assert!(txs[0].spent.is_empty());
    assert_eq!(txs[1].created, vec![boxes.b.box_id]);
    assert_eq!(txs[1].spent, vec![boxes.a.box_id]);
    assert_eq!(txs[2].created, vec![boxes.d.box_id]);
    assert_eq!(txs[2].spent, vec![boxes.b.box_id]);
    assert!(txs.iter().all(|record| record.scan_ids == vec![SCAN_ID]));

    // --- steps 2 + 3: the node reorgs, the daemon rewinds and replays ---
    let new_tip = replacement_tip();
    assert_ne!(new_tip.header_id, tip.header_id);
    let reorged = ScriptedNode::new(
        new_tip.clone(),
        replacement.clone(),
        [BlocksSinceResponse::Ancestor(AncestorBlocksSince {
            tip: new_tip.clone(),
            ancestor: ChainCursor {
                height: 1,
                header_id: block_id(1, FORK_ORIGINAL),
            },
        })],
    );
    let report = syncer(reorged, wallet.store.clone()).sync_once().unwrap();
    assert!(report.completed, "{report:?}");
    assert_eq!(report.wallet_height, 3);
    assert_eq!(report.tip, new_tip);

    // `A` was created below the boundary, so its row survives — and its spend
    // at height 2 is rewound, so it is `Unspent` again.
    let a = scan_box_row(&wallet, boxes.a.box_id).expect("A is below the boundary");
    assert_eq!(a.status, ScanBoxStatus::Unspent);
    assert_eq!(a.inclusion_height, 1);
    // `B` and `D` were created at or above the boundary, so both are gone from
    // the box table and from the reverse index.
    assert!(
        scan_box_row(&wallet, boxes.b.box_id).is_none(),
        "B was created at the boundary and must be removed"
    );
    assert!(
        scan_box_row(&wallet, boxes.d.box_id).is_none(),
        "D was created above the boundary and must be removed"
    );
    // The replacement fork — not the old one — is what got replayed: its boxes
    // are tracked, the old ones are not, and the two height-2/3 txs are stored
    // afresh.
    assert_eq!(
        ids(&scan_box_rows(&wallet)),
        vec![
            (boxes.a.box_id, 1),
            (boxes.e.box_id, 2),
            (boxes.f.box_id, 3)
        ]
    );
    let mut indexed: Vec<[u8; 32]> = reverse_index(&wallet).keys().copied().collect();
    indexed.sort();
    let mut expected_index = vec![boxes.a.box_id, boxes.e.box_id, boxes.f.box_id];
    expected_index.sort();
    assert_eq!(
        indexed, expected_index,
        "the reverse index must hold exactly the replayed fork's boxes"
    );
    // The height-1 tx row is below the boundary and survives untouched; the
    // two rows at or above it are the replacement fork's, not the old ones
    // merged with them.
    assert_eq!(
        scan_tx_rows(&wallet)
            .iter()
            .map(|record| (record.block_height, record.tx_id))
            .collect::<Vec<_>>(),
        vec![(1, tx_id(1)), (2, tx_id(4)), (3, tx_id(5))],
    );
    assert_eq!(
        scan_box_row(&wallet, boxes.e.box_id).unwrap().status,
        ScanBoxStatus::Spent {
            spent_in_tx: tx_id(5),
            spent_at: 3
        }
    );
    assert_eq!(
        scan_box_row(&wallet, boxes.f.box_id).unwrap().status,
        ScanBoxStatus::Unspent
    );

    // The wallet cursor is the replacement tip, and a range rewind (as opposed
    // to a full rebuild) does not invalidate the wallet.
    let read = wallet.store.read().unwrap();
    let cursor = read.scan_cursor().unwrap().unwrap();
    assert_eq!(cursor.height, 3);
    assert_eq!(cursor.header_id, Some(new_tip.header_id));
    assert!(!read.scan_invalidated().unwrap());
}

/// The narrower claim the rewind exists for: a *range* rewind must not clear
/// rows below the boundary, must not clear the reverse index wholesale, and
/// must leave a store that replays the replacement fork into a self-consistent
/// state. A `clear_scan_tracking` shortcut would also satisfy a shape-only
/// assertion, so the surviving row, its restored status, and its index entry
/// are all pinned.
#[test]
fn range_rewind_keeps_pre_boundary_rows_and_their_index_entries() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = open_wallet(dir.path());
    register_scan(&wallet);
    let boxes = boxes();
    let original = original_fork(&boxes);

    // Seed the post-forward state directly through the write API, so a failure
    // names the rewind rather than the sync loop wrapped around it. The scan
    // records are computed by the *production* matcher, so the rows are the
    // ones a node-registered scan would produce.
    seed_applied_fork(&wallet, &original);

    assert_eq!(
        ids(&scan_box_rows(&wallet)),
        vec![
            (boxes.a.box_id, 1),
            (boxes.b.box_id, 2),
            (boxes.d.box_id, 3)
        ]
    );
    assert_eq!(reverse_index(&wallet).len(), 3);
    assert_eq!(scan_tx_rows(&wallet).len(), 3);

    {
        let mut write = wallet.store.begin_write().unwrap();
        write
            .rewind_to_ancestor(1, Some(&block_id(1, FORK_ORIGINAL)))
            .unwrap();
        write.commit().unwrap();
    }

    // The rewind keeps exactly the pre-boundary row, restored to `Unspent`, and
    // keeps its reverse-index entry so a later spend of `A` still finds it.
    assert_eq!(
        scan_box_row(&wallet, boxes.a.box_id).map(|tracked| tracked.status),
        Some(ScanBoxStatus::Unspent),
        "A is below the boundary and its height-2 spend is rewound"
    );
    assert!(scan_box_row(&wallet, boxes.b.box_id).is_none());
    assert!(scan_box_row(&wallet, boxes.d.box_id).is_none());
    let index = reverse_index(&wallet);
    assert_eq!(index.len(), 1, "only A survives the rewind: {index:?}");
    assert_eq!(index[&boxes.a.box_id], vec![SCAN_ID]);
    // `WALLET_SCAN_TXS` is keyed by height, so only the at-or-above rows go.
    assert_eq!(
        scan_tx_rows(&wallet)
            .iter()
            .map(|record| (record.block_height, record.tx_id))
            .collect::<Vec<_>>(),
        vec![(1, tx_id(1))],
        "only the height-1 tx row is below the boundary"
    );
    let read = wallet.store.read().unwrap();
    assert_eq!(read.scan_cursor().unwrap().unwrap().height, 1);
    // A *range* rewind is not a full rebuild: `WALLET_SCAN_INVALIDATED` stays
    // clear, because everything below the boundary is still valid. Only
    // `prepare_rescan(0, ..)` sets it.
    assert!(!read.scan_invalidated().unwrap());
    drop(read);

    // Replaying the replacement fork converges, and now *does* spend the
    // restored `A` — which only works because the rewind kept its index entry.
    let chain = ScriptedNode::at_tip(replacement_tip(), replacement_fork(&boxes));
    let report = syncer(chain, wallet.store.clone()).sync_once().unwrap();
    assert!(report.completed, "{report:?}");
    assert_eq!(report.wallet_height, 3);
    assert_eq!(
        scan_box_row(&wallet, boxes.a.box_id).unwrap().status,
        ScanBoxStatus::Unspent,
        "the replacement fork never spends A"
    );
    assert_eq!(
        scan_box_row(&wallet, boxes.e.box_id).unwrap().status,
        ScanBoxStatus::Spent {
            spent_in_tx: tx_id(5),
            spent_at: 3
        }
    );
    assert_eq!(
        scan_box_row(&wallet, boxes.f.box_id).unwrap().status,
        ScanBoxStatus::Unspent
    );
    assert_eq!(reverse_index(&wallet).len(), 3);
    assert_eq!(scan_tx_rows(&wallet).len(), 3);
}

/// A range rewind immediately followed by one that spends the restored box
/// proves the reverse index is usable after the rewind: `apply_block_to_scans`
/// looks the box up by id, so a missing index row would silently leave the
/// restored box `Unspent` forever.
#[test]
fn a_restored_box_is_still_reachable_through_the_reverse_index() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = open_wallet(dir.path());
    register_scan(&wallet);
    let boxes = boxes();
    let original = original_fork(&boxes);
    seed_applied_fork(&wallet, &original);

    {
        let mut write = wallet.store.begin_write().unwrap();
        write
            .rewind_to_ancestor(1, Some(&block_id(1, FORK_ORIGINAL)))
            .unwrap();
        write.commit().unwrap();
    }
    assert_eq!(
        scan_box_row(&wallet, boxes.a.box_id).map(|t| t.status),
        Some(ScanBoxStatus::Unspent)
    );

    // Apply one block that spends `A` and creates a tracked box, through the
    // production apply path with production-computed match records.
    let height = 2u32;
    let new_box = output_box(6, 0, height, true);
    let block = RescanBlock {
        block_id: block_id(height, FORK_REPLACEMENT),
        txs: vec![RescanTx {
            tx_id: tx_id(6),
            inputs: vec![boxes.a.box_id],
            outputs: vec![OwnedBlockOutput {
                box_id: new_box.box_id,
                output_index: 0,
                ergo_tree_bytes: vec![0x00],
                value: 1_000_000,
                assets: vec![(ASSET_ID, 1_000)],
                miner_reward_pubkey: None,
                box_bytes: new_box.bytes.clone(),
            }],
        }],
    };
    let records = vec![ergo_wallet_service::ScanMatchRecord {
        box_id: new_box.box_id,
        scan_ids: vec![SCAN_ID],
        box_bytes: new_box.bytes.clone(),
        inclusion_height: height,
        creation_out_index: 0,
    }];
    {
        let mut write = wallet.store.begin_write().unwrap();
        write
            .apply_rescan_block(
                height,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &block,
                Some(records.as_slice()),
            )
            .unwrap();
        write.finish_rescan(0).unwrap();
        write.commit().unwrap();
    }

    // `A` is back to `Spent`, which can only happen through the index.
    assert_eq!(
        scan_box_row(&wallet, boxes.a.box_id).unwrap().status,
        ScanBoxStatus::Spent {
            spent_in_tx: tx_id(6),
            spent_at: height
        }
    );
    assert_eq!(
        scan_box_row(&wallet, new_box.box_id).unwrap().status,
        ScanBoxStatus::Unspent
    );
    assert_eq!(reverse_index(&wallet).len(), 2);
}

/// The guard rails on the same entry point. Both matter for a registry: a
/// wrongly-accepted boundary would delete live rows.
#[test]
fn rewind_refuses_a_forward_boundary_and_is_a_no_op_at_the_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = open_wallet(dir.path());
    register_scan(&wallet);
    let original = original_fork(&boxes());
    seed_applied_fork(&wallet, &original);
    assert_eq!(scan_box_rows(&wallet).len(), 3);

    // An ancestor ahead of the cursor is refused: the registry is untouched.
    let mut write = wallet.store.begin_write().unwrap();
    assert!(
        write
            .rewind_to_ancestor(4, Some(&block_id(4, FORK_ORIGINAL)))
            .is_err(),
        "an ancestor ahead of the cursor must be refused"
    );
    // A wrong identity at the cursor height is refused too.
    assert!(
        write
            .rewind_to_ancestor(3, Some(&block_id(3, FORK_REPLACEMENT)))
            .is_err(),
        "a mismatched identity at the cursor height must be refused"
    );
    write.commit().unwrap();
    assert_eq!(scan_box_rows(&wallet).len(), 3);

    // At the cursor, with a matching identity, the rewind is a no-op.
    let mut write = wallet.store.begin_write().unwrap();
    write
        .rewind_to_ancestor(3, Some(&block_id(3, FORK_ORIGINAL)))
        .unwrap();
    write.commit().unwrap();
    let read = wallet.store.read().unwrap();
    assert_eq!(read.scan_cursor().unwrap().unwrap().height, 3);
    assert!(!read.scan_invalidated().unwrap());
    drop(read);
    assert_eq!(
        scan_box_row(&wallet, boxes().a.box_id).map(|tracked| tracked.status),
        Some(ScanBoxStatus::Spent {
            spent_in_tx: tx_id(2),
            spent_at: 2
        })
    );
    assert_eq!(reverse_index(&wallet).len(), 3);
    assert_eq!(scan_tx_rows(&wallet).len(), 3);
}

// ----- helpers -----

/// Apply `blocks` to a standalone wallet the way the daemon's sync loop does —
/// including the production scan matcher — so the persisted scan rows are the
/// ones the real path writes. The wallet is expected to be at the genesis
/// cursor.
fn seed_applied_fork(wallet: &Wallet, blocks: &[ChainBlock]) {
    let mut write = wallet.store.begin_write().unwrap();
    write.prepare_rescan(0, true).unwrap();
    let matcher = WalletScanMatcher::from_store(wallet.store.as_ref()).unwrap();
    assert!(
        !matcher.registry().is_empty(),
        "an empty registry would skip the scan path entirely"
    );
    for block in blocks {
        let rescan = RescanBlock {
            block_id: block.block_id,
            txs: block
                .transactions
                .iter()
                .map(|transaction| RescanTx {
                    tx_id: transaction.tx_id,
                    inputs: transaction.inputs.iter().map(|i| i.box_id).collect(),
                    outputs: transaction
                        .outputs
                        .iter()
                        .map(|output| OwnedBlockOutput {
                            box_id: output.box_id,
                            output_index: output.index,
                            ergo_tree_bytes: vec![0x00],
                            value: 1_000_000,
                            assets: vec![(ASSET_ID, 1_000)],
                            miner_reward_pubkey: None,
                            box_bytes: output.bytes.clone(),
                        })
                        .collect(),
                })
                .collect(),
        };
        let mut bytes: Vec<&[u8]> = Vec::new();
        let mut meta: Vec<([u8; 32], u16)> = Vec::new();
        for transaction in &rescan.txs {
            for output in &transaction.outputs {
                bytes.push(output.box_bytes.as_slice());
                meta.push((output.box_id, output.output_index));
            }
        }
        let matches = matcher.match_boxes(&bytes).unwrap();
        assert_eq!(matches.len(), bytes.len());
        let records: Vec<ergo_wallet_service::ScanMatchRecord> = meta
            .into_iter()
            .zip(matches)
            .zip(bytes)
            .filter(|((_, scan_ids), _)| !scan_ids.is_empty())
            .map(
                |(((box_id, index), scan_ids), box_bytes)| ergo_wallet_service::ScanMatchRecord {
                    box_id,
                    scan_ids,
                    box_bytes: box_bytes.to_vec(),
                    inclusion_height: block.height,
                    creation_out_index: index,
                },
            )
            .collect();
        write
            .apply_rescan_block(
                block.height,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &rescan,
                (!records.is_empty()).then_some(records.as_slice()),
            )
            .unwrap();
    }
    write.finish_rescan(0).unwrap();
    write.commit().unwrap();
}

//! Integration tests for `IndexerTask::step`.
//!
//! Each test scripts a `ScriptedChain` to drive a single `step` call and
//! asserts the right `IndexerPoll` variant came out, plus any handle /
//! store side effects (status flip, indexed_height advance, on-disk
//! mutations).
//!
//! Step tests are synchronous. Worker tests also exercise the driver on its
//! dedicated thread while a single-threaded host runtime remains responsive.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::{Body, Expr};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::transaction::{transaction_id, Transaction};
use tempfile::TempDir;

use ergo_indexer::{
    apply_block, ChainTip, IndexerBlock, IndexerChainSource, IndexerFullBlock, IndexerHaltReason,
    IndexerHandle, IndexerMeta, IndexerPoll, IndexerStatus, IndexerStore, IndexerTask,
};

// ---- ScriptedChain ----------------------------------------------------

struct ScriptedChain {
    tip: Mutex<ChainTip>,
    /// Atomic tip observations queued for a source change between reads.
    tip_reads: Mutex<Vec<ChainTip>>,
    chain: Mutex<HashMap<u32, Digest32>>,
    /// Best-header chain rows, read only as reorg evidence.
    best: Mutex<HashMap<u32, Digest32>>,
    blocks: Mutex<HashMap<Digest32, IndexerFullBlock>>,
    /// Optional override list of header_ids to return for successive
    /// header_id_at() calls — used to simulate a fork flip mid-poll.
    flip_at: Mutex<HashMap<u32, Vec<Digest32>>>,
}

impl ScriptedChain {
    fn new() -> Self {
        Self {
            tip: Mutex::new(ChainTip {
                height: 0,
                header_id: Digest32::from_bytes([0u8; 32]),
            }),
            tip_reads: Mutex::new(Vec::new()),
            chain: Mutex::new(HashMap::new()),
            best: Mutex::new(HashMap::new()),
            blocks: Mutex::new(HashMap::new()),
            flip_at: Mutex::new(HashMap::new()),
        }
    }

    fn set_tip(&self, height: u32, header_id: Digest32) {
        *self.tip.lock().unwrap() = ChainTip { height, header_id };
    }

    fn queue_tip_reads(&self, tips: Vec<ChainTip>) {
        *self.tip_reads.lock().unwrap() = tips;
    }

    fn put_canonical(&self, height: u32, header_id: Digest32) {
        self.chain.lock().unwrap().insert(height, header_id);
    }

    fn put_best_header(&self, height: u32, header_id: Digest32) {
        self.best.lock().unwrap().insert(height, header_id);
    }

    fn put_block(&self, block: IndexerFullBlock) {
        self.blocks.lock().unwrap().insert(block.header_id, block);
    }

    /// Queue a sequence of return values for `header_id_at(height)`.
    /// Each call pops the front; falls back to `chain` when the queue
    /// empties. Used to simulate a canonical flip between the load and
    /// re-verify reads in `step`.
    fn queue_header_at(&self, height: u32, ids: Vec<Digest32>) {
        self.flip_at.lock().unwrap().insert(height, ids);
    }
}

impl IndexerChainSource for ScriptedChain {
    fn committed_tip(&self) -> Result<ChainTip, ergo_indexer::IndexerError> {
        let mut tips = self.tip_reads.lock().unwrap();
        if !tips.is_empty() {
            return Ok(tips.remove(0));
        }
        Ok(*self.tip.lock().unwrap())
    }

    fn header_id_at(&self, height: u32) -> Result<Option<Digest32>, ergo_indexer::IndexerError> {
        let mut flips = self.flip_at.lock().unwrap();
        if let Some(queue) = flips.get_mut(&height) {
            if !queue.is_empty() {
                return Ok(Some(queue.remove(0)));
            }
        }
        Ok(self.chain.lock().unwrap().get(&height).copied())
    }

    fn best_header_id_at(
        &self,
        height: u32,
    ) -> Result<Option<Digest32>, ergo_indexer::IndexerError> {
        Ok(self.best.lock().unwrap().get(&height).copied())
    }

    fn full_block(
        &self,
        header_id: &Digest32,
    ) -> Result<Option<IndexerFullBlock>, ergo_indexer::IndexerError> {
        Ok(self.blocks.lock().unwrap().get(header_id).cloned())
    }
}

// ---- Block fixtures ---------------------------------------------------

fn size_delimited_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
        reserved_header_bits: 0,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        } as Body,
    }
}

fn candidate(value: u64, height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        size_delimited_tree(),
        height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn fake_input(box_id_seed: u8) -> Input {
    Input {
        box_id: Digest32::from_bytes([box_id_seed; 32]),
        spending_proof: SpendingProof::new(vec![0xAB, 0xCD, 0xEF], ContextExtension::empty())
            .unwrap(),
    }
}

fn sealed_box_id(tx: &Transaction, output_idx: u16) -> Digest32 {
    let tx_id = transaction_id(tx).unwrap();
    let sealed = ErgoBox {
        candidate: tx.output_candidates[output_idx as usize].clone(),
        transaction_id: tx_id,
        index: output_idx,
    };
    sealed.box_id().unwrap()
}

fn genesis_tx() -> Transaction {
    Transaction {
        inputs: vec![fake_input(0xAA)],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000, 1), candidate(2_000_000, 1)],
    }
}

fn genesis_block(header_id: Digest32) -> IndexerFullBlock {
    IndexerFullBlock {
        height: 1,
        header_id,
        transactions: vec![genesis_tx()],
    }
}

/// Block at height 2 that consumes the first output of `prev_genesis_tx`.
fn child_block(prev_genesis_tx: &Transaction, header_id: Digest32) -> IndexerFullBlock {
    let consumed = sealed_box_id(prev_genesis_tx, 0);
    let tx = Transaction {
        inputs: vec![Input {
            box_id: consumed,
            spending_proof: SpendingProof::new(vec![0x12, 0x34], ContextExtension::empty())
                .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(900_000, 2)],
    };
    IndexerFullBlock {
        height: 2,
        header_id,
        transactions: vec![tx],
    }
}

fn block_id(seed: u8, height: u32) -> Digest32 {
    let mut bytes = [seed; 32];
    bytes[28..].copy_from_slice(&height.to_be_bytes());
    Digest32::from_bytes(bytes)
}

/// Blocks 1..=n, each spending the first output of its predecessor.
fn linear_chain(n: u32, seed: u8) -> Vec<IndexerFullBlock> {
    let mut blocks = vec![genesis_block(block_id(seed, 1))];
    for height in 2..=n {
        let previous = &blocks.last().unwrap().transactions[0];
        let mut block = child_block(previous, block_id(seed, height));
        block.height = height as i32;
        blocks.push(block);
    }
    blocks
}

fn open_handle() -> (IndexerHandle, TempDir) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();
    let handle = IndexerHandle::with_store(store, 0);
    (handle, tmp)
}

/// Apply a block through the handle's store and return the new meta height.
fn apply_via_handle(handle: &IndexerHandle, block: &IndexerFullBlock) -> u64 {
    let store = handle.store().unwrap();
    let meta = store.read_meta().unwrap();
    let ib = IndexerBlock {
        height: block.height,
        header_id: block.header_id,
        transactions: &block.transactions,
    };
    let next = apply_block(&store, &meta, &ib).unwrap();
    handle.set_indexed_height(next.indexed_height);
    next.indexed_height
}

// ---- Tests ------------------------------------------------------------

// ----- happy path -----

#[test]
fn step_with_halted_handle_returns_halted() {
    let handle = IndexerHandle::halted(IndexerHaltReason::DbCorruption);
    let chain = Arc::new(ScriptedChain::new());
    let mut task = IndexerTask::new(handle, chain);

    match task.step() {
        IndexerPoll::Halted(_) => {}
        other => panic!("expected Halted, got {other:?}"),
    }
}

#[test]
fn step_with_empty_meta_and_empty_chain_returns_idle_and_caught_up() {
    let (handle, _tmp) = open_handle();
    let chain = Arc::new(ScriptedChain::new());
    // tip stays at default (height=0). meta also at 0. next_height=1 > 0 → idle.
    let mut task = IndexerTask::new(handle.clone(), chain);

    match task.step() {
        IndexerPoll::Idle => {}
        other => panic!("expected Idle, got {other:?}"),
    }
    assert_eq!(handle_status(&handle), IndexerStatus::CaughtUp);
}

#[test]
fn step_applies_first_block_and_advances_indexed_height() {
    let (handle, _tmp) = open_handle();
    let chain = Arc::new(ScriptedChain::new());
    let header_id = Digest32::from_bytes([0x11; 32]);
    let block = genesis_block(header_id);

    chain.put_canonical(1, header_id);
    chain.put_block(block.clone());
    chain.set_tip(1, header_id);

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    match task.step() {
        IndexerPoll::Applied(1) => {}
        other => panic!("expected Applied(1), got {other:?}"),
    }

    let store = handle.store().unwrap();
    let meta = store.read_meta().unwrap();
    assert_eq!(meta.indexed_height, 1);
    assert_eq!(meta.indexed_header_id, Some(header_id));
    assert_eq!(handle_status(&handle), IndexerStatus::Syncing);

    // Re-stepping with no further chain advancement → CaughtUp.
    match task.step() {
        IndexerPoll::Idle => {}
        other => panic!("expected Idle on second step, got {other:?}"),
    }
    assert_eq!(handle_status(&handle), IndexerStatus::CaughtUp);
}

#[test]
fn step_rolls_back_when_canonical_diverges_at_our_height() {
    let (handle, _tmp) = open_handle();

    // Apply genesis under header A.
    let header_a = Digest32::from_bytes([0x11; 32]);
    let block_a = genesis_block(header_a);
    apply_via_handle(&handle, &block_a);

    // Chain now reports a different canonical header B at h=1; tip is on B.
    let header_b = Digest32::from_bytes([0x22; 32]);
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(1, header_b);
    chain.set_tip(1, header_b);
    // Indexer must fetch block A by prev_id to invert it.
    chain.put_block(block_a);

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    match task.step() {
        IndexerPoll::RolledBack(1) => {}
        other => panic!("expected RolledBack(1), got {other:?}"),
    }

    let store = handle.store().unwrap();
    let meta = store.read_meta().unwrap();
    assert_eq!(meta.indexed_height, 0);
    assert_eq!(meta.indexed_header_id, None);
}

/// The rollback trigger keys off the best-HEADER chain index, which flips
/// before (or even without) the state layer reorging. When the state's
/// committed tip is NOT on the canonical chain — a reorg in progress, or a
/// deep-fork wedge where the state can never follow — the indexer must HOLD
/// instead of unwinding: chasing the raw flip is what shredded 201 index
/// heights and halted on UndoMissing in the testnet 431,366 bystander wedge.
#[test]
fn step_holds_rollback_while_state_tip_off_canonical() {
    let (handle, _tmp) = open_handle();

    let header_a = Digest32::from_bytes([0x11; 32]);
    let block_a = genesis_block(header_a);
    apply_via_handle(&handle, &block_a);

    // Canonical headers flipped to B, but the STATE tip still sits on A —
    // the state has not (or cannot) reorg.
    let header_b = Digest32::from_bytes([0x22; 32]);
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(1, header_b);
    chain.set_tip(1, header_a);
    chain.put_block(block_a.clone());

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    for _ in 0..3 {
        match task.step() {
            IndexerPoll::Idle => {}
            other => panic!("expected Idle hold, got {other:?}"),
        }
    }
    let store = handle.store().unwrap();
    let meta = store.read_meta().unwrap();
    assert_eq!(meta.indexed_height, 1, "index must not unwind on a hold");
    assert_eq!(meta.indexed_header_id, Some(header_a));

    // The state reorgs (tip now on canonical B): the hold releases and the
    // deferred rollback proceeds.
    chain.set_tip(1, header_b);
    match task.step() {
        IndexerPoll::RolledBack(1) => {}
        other => panic!("expected RolledBack(1) after state reorg, got {other:?}"),
    }
    let meta = store.read_meta().unwrap();
    assert_eq!(meta.indexed_height, 0);
}

#[test]
fn step_rolls_back_when_chain_truncates_below_indexed_tip() {
    let (handle, _tmp) = open_handle();

    let header_a = Digest32::from_bytes([0x11; 32]);
    let block_a = genesis_block(header_a);
    apply_via_handle(&handle, &block_a);

    let header_b = Digest32::from_bytes([0x22; 32]);
    let block_b = child_block(&block_a.transactions[0], header_b);
    let h2_height = apply_via_handle(&handle, &block_b);
    assert_eq!(h2_height, 2);

    // State unwound h=2 for a competing branch: no applied entry at h=2, tip
    // at h=1 on A, and the best-header chain selects another block at h=2.
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(1, header_a);
    chain.put_best_header(1, header_a);
    chain.put_best_header(2, Digest32::from_bytes([0x33; 32]));
    chain.set_tip(1, header_a);
    // Indexer needs block_b to invert h=2 (prev_id is header_b).
    chain.put_block(block_b);

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    match task.step() {
        IndexerPoll::RolledBack(2) => {}
        other => panic!("expected RolledBack(2), got {other:?}"),
    }

    let store = handle.store().unwrap();
    let meta = store.read_meta().unwrap();
    assert_eq!(meta.indexed_height, 1);
    assert_eq!(meta.indexed_header_id, Some(header_a));
}

#[test]
fn step_batch_rolls_back_to_a_coherent_pre_genesis_tip() {
    let (handle, _tmp) = open_handle();
    let store = handle.store().unwrap();
    let empty = store.read_meta().unwrap();
    let first = genesis_block(Digest32::from_bytes([0x11; 32]));
    let second = child_block(&first.transactions[0], Digest32::from_bytes([0x22; 32]));
    apply_via_handle(&handle, &first);
    apply_via_handle(&handle, &second);
    let transactions = [&first.transactions[0], &second.transactions[0]];
    let box_ids: Vec<_> = transactions
        .iter()
        .flat_map(|tx| (0..tx.output_candidates.len()).map(|index| sealed_box_id(tx, index as u16)))
        .collect();
    assert!(store.read_box(&box_ids[0]).unwrap().unwrap().is_spent());

    // The fully applied chain is empty because a branch forked at genesis won
    // the best-header chain. Retained bodies provide inverse data; there is
    // deliberately no synthetic header row at height zero.
    let chain = Arc::new(ScriptedChain::new());
    chain.put_best_header(1, Digest32::from_bytes([0x33; 32]));
    chain.put_best_header(2, Digest32::from_bytes([0x44; 32]));
    chain.put_block(first.clone());
    chain.put_block(second.clone());
    let mut task = IndexerTask::new(handle.clone(), chain);
    assert!(matches!(task.step_batch(), IndexerPoll::RolledBack(2)));
    assert_eq!(store.read_meta().unwrap().indexed_height, 1);
    assert!(!store.read_box(&box_ids[0]).unwrap().unwrap().is_spent());
    assert!(store.read_undo(2).unwrap().is_none());
    assert!(matches!(task.step_batch(), IndexerPoll::RolledBack(1)));
    assert_eq!(store.read_meta().unwrap(), empty);
    assert!(store.read_undo(1).unwrap().is_none());
    for box_id in box_ids {
        assert!(store.read_box(&box_id).unwrap().is_none());
    }
    for tx in transactions {
        assert!(store
            .read_tx(&Digest32::from_bytes(
                *transaction_id(tx).unwrap().as_bytes()
            ))
            .unwrap()
            .is_none());
    }
    assert!(matches!(task.step_batch(), IndexerPoll::Idle));
    assert_eq!(handle_status(&handle), IndexerStatus::CaughtUp);
}

#[test]
fn step_batch_holds_when_pre_genesis_tip_changes_between_reads() {
    let (handle, _tmp) = open_handle();
    let first = genesis_block(Digest32::from_bytes([0x11; 32]));
    apply_via_handle(&handle, &first);
    let store = handle.store().unwrap();
    let before = store.read_meta().unwrap();
    let undo = store.read_undo(1).unwrap();
    let chain = Arc::new(ScriptedChain::new());
    // Branch evidence reaches the pre-genesis tip coherence check.
    chain.put_best_header(1, Digest32::from_bytes([0x33; 32]));
    chain.put_block(first.clone());
    chain.queue_tip_reads(vec![
        ChainTip {
            height: 0,
            header_id: Digest32::ZERO,
        },
        ChainTip {
            height: 1,
            header_id: first.header_id,
        },
    ]);
    let mut task = IndexerTask::new(handle, chain);
    assert!(matches!(task.step_batch(), IndexerPoll::Idle));
    assert_eq!(store.read_meta().unwrap(), before);
    assert_eq!(store.read_undo(1).unwrap(), undo);
    assert!(store
        .read_tx(&Digest32::from_bytes(
            *transaction_id(&first.transactions[0]).unwrap().as_bytes(),
        ))
        .unwrap()
        .is_some());
    for index in 0..first.transactions[0].output_candidates.len() {
        assert!(!store
            .read_box(&sealed_box_id(&first.transactions[0], index as u16))
            .unwrap()
            .unwrap()
            .is_spent());
    }
}

#[test]
fn step_batch_holds_when_height_zero_has_a_nonzero_tip_id() {
    let (handle, _tmp) = open_handle();
    let first = genesis_block(Digest32::from_bytes([0x11; 32]));
    apply_via_handle(&handle, &first);
    let store = handle.store().unwrap();
    let before = store.read_meta().unwrap();
    let undo = store.read_undo(1).unwrap();
    let chain = Arc::new(ScriptedChain::new());
    chain.put_best_header(1, Digest32::from_bytes([0x33; 32]));
    chain.set_tip(0, first.header_id);
    chain.put_block(first);
    let mut task = IndexerTask::new(handle, chain);
    assert!(matches!(task.step_batch(), IndexerPoll::Idle));
    assert_eq!(store.read_meta().unwrap(), before);
    assert_eq!(store.read_undo(1).unwrap(), undo);
}

/// A coherent pre-genesis tip alone is no reorg either: a chain database
/// recreated under a kept index has no best-header rows yet, and one that
/// crashed before its first durable State commit still selects our blocks.
#[test]
fn coherent_pre_genesis_tip_without_branch_evidence_keeps_the_index() {
    let (handle, _tmp) = open_handle();
    let first = genesis_block(Digest32::from_bytes([0x11; 32]));
    apply_via_handle(&handle, &first);
    let store = handle.store().unwrap();
    let before = store.read_meta().unwrap();
    let undo = store.read_undo(1).unwrap();
    let chain = Arc::new(ScriptedChain::new());
    chain.put_block(first.clone());
    let mut task = IndexerTask::new(handle, Arc::clone(&chain));
    assert!(matches!(task.step_batch(), IndexerPoll::Idle));
    chain.put_best_header(1, first.header_id);
    assert!(matches!(task.step_batch(), IndexerPoll::Idle));
    assert_eq!(store.read_meta().unwrap(), before);
    assert_eq!(store.read_undo(1).unwrap(), undo);
}

/// IBD commits State without durability. After a hard crash, State restarts
/// at its last durable block while the index keeps the lost blocks, which the
/// durable best-header chain still selects. Unwinding them would empty this
/// two-block undo window and halt on `UndoMissing`; the index must wait for
/// State to re-apply them instead.
#[test]
fn index_ahead_of_crashed_applied_tip_waits_for_state_to_reapply() {
    let tmp = TempDir::new().unwrap();
    let (mut store, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
    store.set_rollback_window(2);
    let handle = IndexerHandle::with_store(store, 0);
    let blocks = linear_chain(7, 0x50);
    for block in &blocks[..6] {
        apply_via_handle(&handle, block);
    }
    let store = handle.store().unwrap();
    let before = store.read_meta().unwrap();
    let undo: Vec<_> = (1..=6).map(|h| store.read_undo(h).unwrap()).collect();

    let chain = Arc::new(ScriptedChain::new());
    for block in &blocks[..6] {
        chain.put_block(block.clone());
        chain.put_best_header(block.height as u32, block.header_id);
    }
    for block in &blocks[..2] {
        chain.put_canonical(block.height as u32, block.header_id);
    }
    chain.set_tip(2, blocks[1].header_id);
    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    for _ in 0..3 {
        assert!(matches!(task.step_batch(), IndexerPoll::Idle));
    }
    assert_eq!(store.read_meta().unwrap(), before);
    for (height, row) in (1..=6).zip(&undo) {
        assert_eq!(&store.read_undo(height).unwrap(), row);
    }
    assert_eq!(handle_status(&handle), IndexerStatus::CaughtUp);

    // State re-applies the same blocks and then extends the chain.
    chain.put_block(blocks[6].clone());
    for block in &blocks[2..] {
        chain.put_canonical(block.height as u32, block.header_id);
        chain.put_best_header(block.height as u32, block.header_id);
    }
    chain.set_tip(6, blocks[5].header_id);
    assert!(matches!(task.step_batch(), IndexerPoll::Idle));
    chain.set_tip(7, blocks[6].header_id);
    assert!(matches!(task.step_batch(), IndexerPoll::Applied(7)));
}

/// Absent applied rows still unwind where the best-header chain moved: a
/// reorg inside the lost window unwinds exactly to the fork point.
#[test]
fn absent_applied_rows_unwind_only_where_best_header_chain_moved() {
    let (handle, _tmp) = open_handle();
    let blocks = linear_chain(4, 0x50);
    for block in &blocks {
        apply_via_handle(&handle, block);
    }
    let chain = Arc::new(ScriptedChain::new());
    for block in &blocks {
        chain.put_block(block.clone());
    }
    for block in &blocks[..2] {
        chain.put_canonical(block.height as u32, block.header_id);
        chain.put_best_header(block.height as u32, block.header_id);
    }
    chain.put_best_header(3, block_id(0x60, 3));
    chain.put_best_header(4, block_id(0x60, 4));
    chain.set_tip(2, blocks[1].header_id);
    let mut task = IndexerTask::new(handle.clone(), chain);
    assert!(matches!(task.step_batch(), IndexerPoll::RolledBack(4)));
    assert!(matches!(task.step_batch(), IndexerPoll::RolledBack(3)));
    assert!(matches!(task.step_batch(), IndexerPoll::Idle));
    let meta = handle.store().unwrap().read_meta().unwrap();
    assert_eq!(meta.indexed_height, 2);
    assert_eq!(meta.indexed_header_id, Some(blocks[1].header_id));
}

/// A UTXO-snapshot store's applied index starts at its anchor. A height
/// missing below a tip that stays anchored is permanent missing data, not a
/// fork race to retry forever; a tip that moves between the reads is a race.
#[test]
fn applied_gap_below_anchored_tip_is_missing_data_not_a_race() {
    let (handle, _tmp) = open_handle();
    let anchor = Digest32::from_bytes([0x50; 32]);
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(50, anchor);
    chain.set_tip(50, anchor);
    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    assert!(matches!(task.step(), IndexerPoll::AppliedGap { height: 1 }));
    assert_eq!(handle_status(&handle), IndexerStatus::Syncing);
    chain.queue_header_at(50, vec![anchor, Digest32::from_bytes([0x51; 32])]);
    assert!(matches!(task.step(), IndexerPoll::Race));
    assert_eq!(
        handle.store().unwrap().read_meta().unwrap(),
        IndexerMeta::empty()
    );
}

#[test]
fn worker_halts_section_missing_on_a_persistent_applied_gap() {
    let (handle, _tmp) = open_handle();
    let anchor = Digest32::from_bytes([0x50; 32]);
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(50, anchor);
    chain.set_tip(50, anchor);
    let worker = IndexerTask::new(handle.clone(), chain)
        .spawn(Arc::new(AtomicBool::new(false)), Duration::from_secs(60))
        .unwrap();
    // Five attempts with one-second back-offs between them.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while handle_status(&handle) != IndexerStatus::Halted(IndexerHaltReason::SectionMissing) {
        assert!(
            std::time::Instant::now() < deadline,
            "{:?}",
            handle_status(&handle)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    worker.join().unwrap();
}

#[test]
fn step_returns_section_retry_when_block_bytes_missing() {
    let (handle, _tmp) = open_handle();
    let chain = Arc::new(ScriptedChain::new());
    let header_id = Digest32::from_bytes([0x11; 32]);

    // Header is canonical at h=1, tip says h=1, but no block bytes are staged.
    chain.put_canonical(1, header_id);
    chain.set_tip(1, header_id);

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    match task.step() {
        IndexerPoll::SectionRetry {
            header_id: hid,
            height: 1,
        } => {
            assert_eq!(hid, header_id);
        }
        other => panic!("expected SectionRetry, got {other:?}"),
    }

    // No mutation: meta still empty.
    let store = handle.store().unwrap();
    assert_eq!(store.read_meta().unwrap().indexed_height, 0);
}

#[test]
fn step_returns_section_retry_when_rollback_block_bytes_missing() {
    let (handle, _tmp) = open_handle();
    let header_a = Digest32::from_bytes([0x11; 32]);
    let block_a = genesis_block(header_a);
    apply_via_handle(&handle, &block_a);

    // Divergence at h=1: canonical now header_b. But block bytes for
    // prev_id (header_a) are NOT staged → do_rollback emits SectionRetry.
    let header_b = Digest32::from_bytes([0x22; 32]);
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(1, header_b);
    chain.set_tip(1, header_b);
    // Note: no put_block — block_a bytes are missing.
    let _ = block_a; // keep the binding for clarity of intent

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    match task.step() {
        IndexerPoll::SectionRetry {
            header_id: hid,
            height: 1,
        } => {
            assert_eq!(hid, header_a);
        }
        other => panic!("expected SectionRetry on rollback path, got {other:?}"),
    }

    // No mutation: applied state is still on header_a at h=1.
    let store = handle.store().unwrap();
    let meta = store.read_meta().unwrap();
    assert_eq!(meta.indexed_height, 1);
    assert_eq!(meta.indexed_header_id, Some(header_a));
}

#[test]
fn step_returns_race_when_canonical_disappears_during_load() {
    let (handle, _tmp) = open_handle();
    let chain = Arc::new(ScriptedChain::new());

    // Tip says h=1 on header_x — but we never seed the canonical table,
    // so header_id_at(1) returns None even though tip claims height=1.
    let header_x = Digest32::from_bytes([0x33; 32]);
    chain.set_tip(1, header_x);

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    match task.step() {
        IndexerPoll::Race => {}
        other => panic!("expected Race (no canonical), got {other:?}"),
    }
}

#[test]
fn step_returns_race_when_canonical_flips_between_load_and_verify() {
    let (handle, _tmp) = open_handle();
    let chain = Arc::new(ScriptedChain::new());
    let header_a = Digest32::from_bytes([0x11; 32]);
    let header_b = Digest32::from_bytes([0x22; 32]);

    let block_a = genesis_block(header_a);
    chain.put_block(block_a);
    chain.set_tip(1, header_a);
    // First call returns A (load); second call returns B (re-verify).
    chain.queue_header_at(1, vec![header_a, header_a, header_b]);

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    match task.step() {
        IndexerPoll::Race => {}
        other => panic!("expected Race (flip), got {other:?}"),
    }

    // No mutation: meta still empty.
    let store = handle.store().unwrap();
    assert_eq!(store.read_meta().unwrap().indexed_height, 0);
}

#[test]
fn step_applies_two_blocks_across_back_to_back_calls() {
    let (handle, _tmp) = open_handle();
    let header_a = Digest32::from_bytes([0x11; 32]);
    let header_b = Digest32::from_bytes([0x22; 32]);
    let block_a = genesis_block(header_a);
    let block_b = child_block(&block_a.transactions[0], header_b);

    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(1, header_a);
    chain.put_canonical(2, header_b);
    chain.put_block(block_a);
    chain.put_block(block_b);
    chain.set_tip(2, header_b);

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    assert!(matches!(task.step(), IndexerPoll::Applied(1)));
    assert!(matches!(task.step(), IndexerPoll::Applied(2)));
    assert!(matches!(task.step(), IndexerPoll::Idle));

    let store = handle.store().unwrap();
    let meta = store.read_meta().unwrap();
    assert_eq!(meta.indexed_height, 2);
    assert_eq!(meta.indexed_header_id, Some(header_b));
    assert_eq!(handle_status(&handle), IndexerStatus::CaughtUp);
}

#[test]
fn step_rolls_back_then_forward_applies_a_new_fork() {
    let (handle, _tmp) = open_handle();
    let header_a = Digest32::from_bytes([0x11; 32]);
    let block_a = genesis_block(header_a);
    apply_via_handle(&handle, &block_a);

    // New fork starts at h=1 on header_b.
    let header_b = Digest32::from_bytes([0x22; 32]);
    let block_b = genesis_block(header_b);
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(1, header_b);
    chain.set_tip(1, header_b);
    chain.put_block(block_a); // for the rollback step
    chain.put_block(block_b.clone()); // for the forward apply

    let mut task = IndexerTask::new(handle.clone(), Arc::clone(&chain));
    assert!(matches!(task.step(), IndexerPoll::RolledBack(1)));
    assert!(matches!(task.step(), IndexerPoll::Applied(1)));

    let store = handle.store().unwrap();
    let meta = store.read_meta().unwrap();
    assert_eq!(meta.indexed_height, 1);
    assert_eq!(meta.indexed_header_id, Some(header_b));
}

// ---- helpers ----------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn worker_keeps_host_runtime_responsive_and_join_drains_step() {
    struct BlockingChain {
        started: Mutex<Option<tokio::sync::oneshot::Sender<std::thread::ThreadId>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl IndexerChainSource for BlockingChain {
        fn committed_tip(&self) -> Result<ChainTip, ergo_indexer::IndexerError> {
            if let Some(started) = self.started.lock().unwrap().take() {
                let _ = started.send(std::thread::current().id());
                // Bound the wait even if an assertion prevents release.
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            Ok(ChainTip {
                height: 0,
                header_id: Digest32::ZERO,
            })
        }
        fn header_id_at(&self, _: u32) -> Result<Option<Digest32>, ergo_indexer::IndexerError> {
            Ok(None)
        }
        fn best_header_id_at(
            &self,
            _: u32,
        ) -> Result<Option<Digest32>, ergo_indexer::IndexerError> {
            Ok(None)
        }
        fn full_block(
            &self,
            _: &Digest32,
        ) -> Result<Option<IndexerFullBlock>, ergo_indexer::IndexerError> {
            Ok(None)
        }
    }
    let (handle, tmp) = open_handle();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let chain = Arc::new(BlockingChain {
        started: Mutex::new(Some(started_tx)),
        release: Mutex::new(release_rx),
    });
    let worker = IndexerTask::new(handle, chain)
        .spawn(Arc::clone(&cancel), Duration::from_secs(60))
        .unwrap();
    let worker_id = tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(worker_id, std::thread::current().id());
    let joined = tokio::task::spawn_blocking(move || worker.join());
    // A timer on the host's ONLY runtime thread fires while the indexer's
    // synchronous read is blocked. Join must still wait for that read.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!joined.is_finished());
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), joined)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(cancel.load(Ordering::Acquire));
    // Worker exit releases its DB ownership before join returns.
    IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn worker_follows_reorg_and_cancels_long_idle_sleep() {
    let (handle, tmp) = open_handle();
    let header_a = Digest32::from_bytes([0x11; 32]);
    let header_b = Digest32::from_bytes([0x22; 32]);
    let block_a = genesis_block(header_a);
    apply_via_handle(&handle, &block_a);
    let chain = Arc::new(ScriptedChain::new());
    chain.put_block(block_a);
    chain.put_block(genesis_block(header_b));
    chain.put_canonical(1, header_b);
    chain.set_tip(1, header_b);
    let cancel = Arc::new(AtomicBool::new(false));
    let worker = IndexerTask::new(handle.clone(), chain)
        .spawn(Arc::clone(&cancel), Duration::from_secs(60))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle_status(&handle) == IndexerStatus::CaughtUp
                && handle
                    .store()
                    .unwrap()
                    .read_meta()
                    .unwrap()
                    .indexed_header_id
                    == Some(header_b)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // Cancellation must not wait out the 60-second idle interval.
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || worker.join()),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    drop(handle);
    let (reopened, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
    assert_eq!(
        reopened.read_meta().unwrap().indexed_header_id,
        Some(header_b)
    );
}

#[test]
fn dropping_worker_requests_cancellation() {
    let (handle, tmp) = open_handle();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker = IndexerTask::new(handle, Arc::new(ScriptedChain::new()))
        .spawn(Arc::clone(&cancel), Duration::from_secs(60))
        .unwrap();
    drop(worker);
    assert!(cancel.load(Ordering::Acquire));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match IndexerStore::open(&tmp.path().join("indexer.redb")) {
            Ok(_) => break,
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "worker did not release store: {error}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn handle_status(h: &IndexerHandle) -> IndexerStatus {
    use ergo_indexer::IndexerQuery;
    h.status()
}

#[tokio::test(flavor = "current_thread")]
async fn zero_idle_and_persistent_races_wait_between_polls_and_cancel_promptly() {
    struct Persistent {
        race: bool,
        cancel: Arc<AtomicBool>,
        observations: Mutex<Vec<std::time::Instant>>,
        done: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }
    impl IndexerChainSource for Persistent {
        fn committed_tip(&self) -> Result<ChainTip, ergo_indexer::IndexerError> {
            let mut times = self.observations.lock().unwrap();
            times.push(std::time::Instant::now());
            if times.len() == 2 {
                self.cancel.store(true, Ordering::Release);
                if let Some(done) = self.done.lock().unwrap().take() {
                    let _ = done.send(());
                }
            }
            Ok(ChainTip {
                height: u32::from(self.race),
                header_id: Digest32::ZERO,
            })
        }
        fn header_id_at(&self, _: u32) -> Result<Option<Digest32>, ergo_indexer::IndexerError> {
            Ok(None)
        }
        fn best_header_id_at(
            &self,
            _: u32,
        ) -> Result<Option<Digest32>, ergo_indexer::IndexerError> {
            Ok(None)
        }
        fn full_block(
            &self,
            _: &Digest32,
        ) -> Result<Option<IndexerFullBlock>, ergo_indexer::IndexerError> {
            Ok(None)
        }
    }
    for race in [false, true] {
        let (handle, _tmp) = open_handle();
        let cancel = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let source = Arc::new(Persistent {
            race,
            cancel: cancel.clone(),
            observations: Mutex::new(Vec::new()),
            done: Mutex::new(Some(done_tx)),
        });
        let worker = IndexerTask::new(handle, source.clone())
            .spawn(cancel, Duration::ZERO)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), done_rx)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || worker.join()),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        let times = source.observations.lock().unwrap();
        assert_eq!(times.len(), 2);
        assert!(times[1].duration_since(times[0]) >= Duration::from_millis(50));
    }
}

/// Separately observed applied-chain heights can disagree with the captured
/// tip during a State commit. Synthetic blocks exercise index ownership,
/// not consensus acceptance.
#[test]
fn forward_catchup_rejects_an_inconsistent_applied_tip_anchor() {
    let (handle, _tmp) = open_handle();
    let common = genesis_block(Digest32::from_bytes([1; 32]));
    apply_via_handle(&handle, &common);
    let store = handle.store().unwrap();
    let before = store.read_meta().unwrap();
    let child = child_block(&common.transactions[0], Digest32::from_bytes([2; 32]));
    let old_tip = Digest32::from_bytes([3; 32]);
    let new_tip = Digest32::from_bytes([4; 32]);
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(1, common.header_id);
    chain.put_canonical(2, child.header_id);
    chain.put_canonical(3, new_tip);
    chain.put_block(child);
    chain.set_tip(3, old_tip);
    let mut task = IndexerTask::new(handle.clone(), chain.clone());
    assert!(matches!(task.step_batch(), IndexerPoll::Race));
    assert_eq!(store.read_meta().unwrap(), before);
    assert!(store.read_undo(2).unwrap().is_none());
    assert!(store
        .read_numeric_box(before.global_box_index)
        .unwrap()
        .is_none());
    assert!(!store
        .read_box(&sealed_box_id(&common.transactions[0], 0))
        .unwrap()
        .unwrap()
        .is_spent());
    assert_eq!(handle_status(&handle), IndexerStatus::Syncing);
    chain.set_tip(3, new_tip);
    assert!(matches!(task.step(), IndexerPoll::Applied(2)));
}

#[test]
fn forward_batch_aborts_when_captured_applied_anchor_changes() {
    let (handle, _tmp) = open_handle();
    let common = genesis_block(Digest32::from_bytes([1; 32]));
    apply_via_handle(&handle, &common);
    let store = handle.store().unwrap();
    let before = store.read_meta().unwrap();
    let child = child_block(&common.transactions[0], Digest32::from_bytes([2; 32]));
    let old_tip = Digest32::from_bytes([3; 32]);
    let new_tip = Digest32::from_bytes([4; 32]);
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(1, common.header_id);
    chain.put_canonical(2, child.header_id);
    chain.put_canonical(3, old_tip);
    chain.put_block(child);
    chain.set_tip(3, old_tip);
    // Initial anchor check succeeds. The final check observes the fork while
    // the just-loaded child height itself still looks unchanged.
    chain.queue_header_at(3, vec![old_tip, new_tip]);
    let mut task = IndexerTask::new(handle, chain);
    assert!(matches!(task.step(), IndexerPoll::Race));
    assert_eq!(store.read_meta().unwrap(), before);
    assert!(store.read_undo(2).unwrap().is_none());
    assert!(!store
        .read_box(&sealed_box_id(&common.transactions[0], 0))
        .unwrap()
        .unwrap()
        .is_spent());
}

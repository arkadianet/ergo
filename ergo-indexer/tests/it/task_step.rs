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
    IndexerHandle, IndexerPoll, IndexerStatus, IndexerStore, IndexerTask,
};

// ---- ScriptedChain ----------------------------------------------------

struct ScriptedChain {
    tip: Mutex<ChainTip>,
    chain: Mutex<HashMap<u32, Digest32>>,
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
            chain: Mutex::new(HashMap::new()),
            blocks: Mutex::new(HashMap::new()),
            flip_at: Mutex::new(HashMap::new()),
        }
    }

    fn set_tip(&self, height: u32, header_id: Digest32) {
        *self.tip.lock().unwrap() = ChainTip { height, header_id };
    }

    fn put_canonical(&self, height: u32, header_id: Digest32) {
        self.chain.lock().unwrap().insert(height, header_id);
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
    fn committed_tip(&self) -> ChainTip {
        *self.tip.lock().unwrap()
    }

    fn header_id_at(&self, height: u32) -> Option<Digest32> {
        let mut flips = self.flip_at.lock().unwrap();
        if let Some(queue) = flips.get_mut(&height) {
            if !queue.is_empty() {
                return Some(queue.remove(0));
            }
        }
        self.chain.lock().unwrap().get(&height).copied()
    }

    fn full_block(&self, header_id: &Digest32) -> Option<IndexerFullBlock> {
        self.blocks.lock().unwrap().get(header_id).cloned()
    }
}

// ---- Block fixtures ---------------------------------------------------

fn size_delimited_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
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

    // Chain truncates: no canonical entry at h=2, tip stuck at h=1 on A.
    let chain = Arc::new(ScriptedChain::new());
    chain.put_canonical(1, header_a);
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
    chain.queue_header_at(1, vec![header_a, header_b]);

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
        fn committed_tip(&self) -> ChainTip {
            if let Some(started) = self.started.lock().unwrap().take() {
                let _ = started.send(std::thread::current().id());
                // Bounded even if a test assertion panics before releasing us.
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            ChainTip {
                height: 0,
                header_id: Digest32::from_bytes([0; 32]),
            }
        }
        fn header_id_at(&self, _: u32) -> Option<Digest32> {
            None
        }
        fn full_block(&self, _: &Digest32) -> Option<IndexerFullBlock> {
            None
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

//! Batching against the same real mainnet interval used by the backfill oracle.

use super::*;
use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use std::sync::Mutex;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use serde::Deserialize;

#[derive(Deserialize)]
struct TxVector {
    bytes: String,
    height: u32,
}
#[derive(Deserialize)]
struct HeaderVector {
    id: String,
    height: u32,
}

fn corpus() -> Vec<IndexerFullBlock> {
    let txs: Vec<TxVector> = serde_json::from_str(include_str!(
        "../../test-vectors/mainnet/transactions_1_200.json"
    ))
    .unwrap();
    let headers: Vec<HeaderVector> = serde_json::from_str(include_str!(
        "../../test-vectors/mainnet/headers_1_500.json"
    ))
    .unwrap();
    txs.into_iter()
        .map(|tx| {
            let header = headers.iter().find(|h| h.height == tx.height).unwrap();
            IndexerFullBlock {
                height: tx.height as i32,
                header_id: Digest32::from_bytes(
                    hex::decode(&header.id).unwrap().try_into().unwrap(),
                ),
                transactions: vec![ergo_ser::transaction::read_transaction(&mut VlqReader::new(
                    &hex::decode(tx.bytes).unwrap(),
                ))
                .unwrap()],
            }
        })
        .collect()
}

type LoadHook = Box<dyn Fn(u32) + Send + Sync>;
struct Chain {
    blocks: Mutex<HashMap<HeaderId, IndexerFullBlock>>,
    headers: Mutex<Vec<HeaderId>>,
    tip: AtomicU32,
    hook: Mutex<Option<LoadHook>>,
}
impl Chain {
    fn new(blocks: &[IndexerFullBlock]) -> Self {
        Self {
            blocks: Mutex::new(blocks.iter().map(|b| (b.header_id, b.clone())).collect()),
            headers: Mutex::new(blocks.iter().map(|b| b.header_id).collect()),
            tip: AtomicU32::new(blocks.len() as u32),
            hook: Mutex::new(None),
        }
    }
}
impl IndexerChainSource for Chain {
    fn committed_tip(&self) -> Result<ChainTip, crate::IndexerError> {
        let height = self.tip.load(Ordering::Relaxed);
        Ok(ChainTip {
            height,
            header_id: self.headers.lock().unwrap()[height as usize - 1],
        })
    }
    fn header_id_at(&self, h: u32) -> Result<Option<HeaderId>, crate::IndexerError> {
        Ok(h.checked_sub(1)
            .and_then(|index| self.headers.lock().unwrap().get(index as usize).copied()))
    }
    fn full_block(&self, id: &HeaderId) -> Result<Option<IndexerFullBlock>, crate::IndexerError> {
        let Some(block) = self.blocks.lock().unwrap().get(id).cloned() else {
            return Ok(None);
        };
        if let Some(hook) = &*self.hook.lock().unwrap() {
            hook(block.height as u32);
        }
        Ok(Some(block))
    }
}

fn setup(
    blocks: &[IndexerFullBlock],
) -> (
    tempfile::TempDir,
    IndexerHandle,
    Arc<Chain>,
    IndexerTask<Chain>,
) {
    let tmp = tempfile::tempdir().unwrap();
    let (store, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
    let handle = IndexerHandle::with_store(store, 0);
    let chain = Arc::new(Chain::new(blocks));
    let task = IndexerTask::new(handle.clone(), chain.clone());
    (tmp, handle, chain, task)
}

fn unlimited_time(task: &mut IndexerTask<Chain>, count: usize) -> IndexerPoll {
    task.step_with_budget(count, Duration::from_secs(60), u64::MAX)
}

struct CommitObserver {
    handle: IndexerHandle,
    seen: Mutex<Vec<crate::events::BlockChanges>>,
}

impl crate::events::IndexerObserver for CommitObserver {
    fn on_committed(&self, changes: crate::events::BlockChanges) {
        let durable = self.handle.store().unwrap().read_meta().unwrap();
        assert_eq!(self.handle.indexed_height(), durable.indexed_height);
        if changes.boxes.iter().any(|change| {
            matches!(
                change.kind,
                crate::events::BoxChangeKind::Unspent | crate::events::BoxChangeKind::Reverted
            )
        }) {
            assert_eq!(durable.indexed_height, u64::from(changes.height - 1));
        } else {
            assert!(durable.indexed_height >= u64::from(changes.height));
            assert!(self
                .handle
                .store()
                .unwrap()
                .read_undo(u64::from(changes.height))
                .unwrap()
                .is_some());
        }
        self.seen.lock().unwrap().push(changes);
    }
}

fn commit_observer(handle: &IndexerHandle) -> Arc<CommitObserver> {
    Arc::new(CommitObserver {
        handle: handle.clone(),
        seen: Mutex::new(Vec::new()),
    })
}

#[test]
fn observed_mainnet_batch_and_rollback_publish_only_committed_row_changes() {
    use crate::events::BoxChangeKind;
    let blocks = corpus();
    let (_tmp, handle, chain, task) = setup(&blocks[..3]);
    let observer = commit_observer(&handle);
    let mut task = task.with_observer(observer.clone());
    let pending = observer.clone();
    *chain.hook.lock().unwrap() = Some(Box::new(move |_| {
        assert!(
            pending.seen.lock().unwrap().is_empty(),
            "no event before batch commit"
        );
    }));
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Applied(3)
    ));
    *chain.hook.lock().unwrap() = None;
    let reference: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../test-vectors/mainnet/transactions_1_200.json"
    ))
    .unwrap();
    {
        let observed = observer.seen.lock().unwrap();
        assert_eq!(
            observed.iter().map(|b| b.height).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        for (i, block) in observed.iter().enumerate() {
            assert_eq!(block.header_id, blocks[i].header_id);
            let reference_tx = &reference[i]["id"];
            for change in &block.boxes {
                assert_eq!(
                    hex::encode(change.tx_id.as_bytes()),
                    reference_tx.as_str().unwrap()
                );
                assert_eq!(change.record.box_data.box_id().unwrap(), change.box_id);
                match change.kind {
                    BoxChangeKind::Created => assert!(change.record.spending_tx_id.is_none()),
                    BoxChangeKind::Spent => {
                        assert_eq!(change.record.spending_tx_id, Some(change.tx_id))
                    }
                    _ => panic!("inverse event on forward apply"),
                }
            }
        }
    }
    chain.tip.store(2, Ordering::Relaxed);
    chain.headers.lock().unwrap().truncate(2);
    assert!(matches!(task.step(), IndexerPoll::RolledBack(3)));
    let observed = observer.seen.lock().unwrap();
    let inverse = &observed[3];
    assert_eq!(inverse.header_id, observed[2].header_id);
    assert_eq!(inverse.boxes.len(), observed[2].boxes.len());
    for (backward, forward) in inverse.boxes.iter().zip(observed[2].boxes.iter().rev()) {
        assert_eq!(backward.box_id, forward.box_id);
        assert_eq!(backward.tx_id, forward.tx_id);
        assert_eq!(backward.record.box_data, forward.record.box_data);
        match (backward.kind, forward.kind) {
            (BoxChangeKind::Reverted, BoxChangeKind::Created) => {}
            (BoxChangeKind::Unspent, BoxChangeKind::Spent) => {
                assert!(backward.record.spending_tx_id.is_none())
            }
            kinds => panic!("wrong rollback order/kinds: {kinds:?}"),
        }
    }
}

#[test]
fn observed_failed_batch_and_failed_rollback_emit_nothing() {
    let blocks = corpus();
    let (_tmp, handle, chain, task) = setup(&blocks[..3]);
    let observer = commit_observer(&handle);
    let mut task = task.with_observer(observer.clone());
    chain
        .blocks
        .lock()
        .unwrap()
        .get_mut(&blocks[1].header_id)
        .unwrap()
        .transactions[0]
        .inputs[0]
        .box_id = Digest32::from_bytes([0xab; 32]);
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Halted(_)
    ));
    assert!(observer.seen.lock().unwrap().is_empty());
    chain
        .blocks
        .lock()
        .unwrap()
        .insert(blocks[1].header_id, blocks[1].clone());
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Applied(3)
    ));
    assert_eq!(
        observer.seen.lock().unwrap().len(),
        3,
        "retry emits each committed block once"
    );
    let before = handle.store().unwrap().read_meta().unwrap();
    let mut broken = blocks[2].clone();
    broken.transactions[0].output_candidates[0].value += 1;
    chain
        .blocks
        .lock()
        .unwrap()
        .insert(broken.header_id, broken);
    chain.tip.store(2, Ordering::Relaxed);
    chain.headers.lock().unwrap().truncate(2);
    assert!(matches!(task.step(), IndexerPoll::Halted(_)));
    assert_eq!(handle.store().unwrap().read_meta().unwrap(), before);
    assert_eq!(
        observer.seen.lock().unwrap().len(),
        3,
        "rollback abort emits no partial inverses"
    );
}

#[test]
fn batched_mainnet_interval_matches_single_commits_and_rolls_back_per_height() {
    let blocks = corpus();
    let (_a, ha, _ca, mut single) = setup(&blocks);
    let (_b, hb, cb, mut batched) = setup(&blocks);
    for _ in &blocks {
        assert!(matches!(single.step(), IndexerPoll::Applied(_)));
    }
    while hb.indexed_height() < blocks.len() as u64 {
        assert!(matches!(
            unlimited_time(&mut batched, 16),
            IndexerPoll::Applied(_)
        ));
    }
    let a = ha.store().unwrap();
    let b = hb.store().unwrap();
    assert_eq!(a.read_meta().unwrap(), b.read_meta().unwrap());
    assert_eq!(
        a.read_storage_rent_entries().unwrap(),
        b.read_storage_rent_entries().unwrap()
    );
    let meta = a.read_meta().unwrap();
    for n in 0..meta.global_box_index {
        let id = a.read_numeric_box(n).unwrap().unwrap();
        assert_eq!(a.read_box(&id).unwrap(), b.read_box(&id).unwrap());
        let indexed = a.read_box(&id).unwrap().unwrap();
        let owner =
            crate::segment_id::tree_hash_from_bytes(indexed.box_data.candidate.ergo_tree_bytes());
        assert_eq!(
            a.read_address(&owner).unwrap(),
            b.read_address(&owner).unwrap()
        );
        assert_eq!(
            a.read_address_box_entries(&owner).unwrap(),
            b.read_address_box_entries(&owner).unwrap()
        );
    }
    for n in 0..meta.global_tx_index {
        let id = a.read_numeric_tx(n).unwrap().unwrap();
        assert_eq!(a.read_tx(&id).unwrap(), b.read_tx(&id).unwrap());
    }
    for h in 1..=meta.indexed_height {
        assert_eq!(a.read_undo(h).unwrap(), b.read_undo(h).unwrap());
    }
    // State has rolled back ten blocks. Indexer must retain every undo within
    // each committed batch, not only an undo at the batch boundary.
    cb.tip.store(190, Ordering::Relaxed);
    cb.headers.lock().unwrap().truncate(190);
    for height in (191..=200).rev() {
        assert!(matches!(batched.step_batch(), IndexerPoll::RolledBack(h) if h == height));
    }
    let (_c, hc, _cc, mut reference) = setup(&blocks[..190]);
    while hc.indexed_height() < 190 {
        assert!(matches!(
            unlimited_time(&mut reference, 16),
            IndexerPoll::Applied(_)
        ));
    }
    assert_eq!(
        b.read_meta().unwrap(),
        hc.store().unwrap().read_meta().unwrap()
    );
    assert_eq!(
        b.read_storage_rent_entries().unwrap(),
        hc.store().unwrap().read_storage_rent_entries().unwrap()
    );
}

#[test]
fn readers_see_only_committed_batch_checkpoints() {
    let blocks = corpus();
    let (_tmp, handle, chain, mut task) = setup(&blocks[..5]);
    let observer = handle.clone();
    *chain.hook.lock().unwrap() = Some(Box::new(move |height| {
        if height > 1 {
            assert_eq!(observer.indexed_height(), 0);
            assert_eq!(
                observer
                    .store()
                    .unwrap()
                    .read_meta()
                    .unwrap()
                    .indexed_height,
                0
            );
            assert!(observer.store().unwrap().read_undo(1).unwrap().is_none());
        }
    }));
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Applied(5)
    ));
    assert_eq!(handle.indexed_height(), 5);
    assert_eq!(
        handle.store().unwrap().read_meta().unwrap().indexed_height,
        5
    );
}

#[test]
fn failed_batch_aborts_all_rows_reopens_and_reuses_scratch() {
    let blocks = corpus();
    let (tmp, handle, chain, mut task) = setup(&blocks[..3]);
    chain
        .blocks
        .lock()
        .unwrap()
        .get_mut(&blocks[1].header_id)
        .unwrap()
        .transactions[0]
        .inputs[0]
        .box_id = Digest32::from_bytes([0xAB; 32]);
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Halted(IndexerError::InputMissing { .. })
    ));
    assert_eq!(handle.indexed_height(), 0);
    let store = handle.store().unwrap();
    assert_eq!(store.read_meta().unwrap(), IndexerMeta::empty());
    assert!(store.read_numeric_tx(0).unwrap().is_none());
    assert!(store.read_undo(1).unwrap().is_none());
    assert!(store.read_storage_rent_entries().unwrap().is_empty());
    chain
        .blocks
        .lock()
        .unwrap()
        .insert(blocks[1].header_id, blocks[1].clone());
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Applied(3)
    ));
    let expected = store.read_meta().unwrap();
    drop(store);
    drop(task);
    drop(handle);
    let (reopened, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
    assert_eq!(reopened.read_meta().unwrap(), expected);
    assert!(reopened.read_undo(2).unwrap().is_some());
}

#[test]
fn aborted_batch_remains_absent_after_reopen() {
    let blocks = corpus();
    let (tmp, handle, chain, mut task) = setup(&blocks[..3]);
    chain
        .blocks
        .lock()
        .unwrap()
        .get_mut(&blocks[1].header_id)
        .unwrap()
        .transactions[0]
        .inputs[0]
        .box_id = Digest32::from_bytes([0xAB; 32]);
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Halted(_)
    ));
    drop(task);
    drop(handle);
    let (store, _) = IndexerStore::open(&tmp.path().join("indexer.redb")).unwrap();
    assert_eq!(store.read_meta().unwrap(), IndexerMeta::empty());
    assert!(store.read_undo(1).unwrap().is_none());
    assert!(store.read_numeric_tx(0).unwrap().is_none());
    assert!(store.read_numeric_box(0).unwrap().is_none());
    assert!(store.read_storage_rent_entries().unwrap().is_empty());
}

#[test]
fn secondary_drift_stops_batch_until_repair_finishes() {
    let blocks = corpus();
    let (_tmp, handle, chain, mut task) = setup(&blocks[..5]);
    assert!(matches!(
        unlimited_time(&mut task, 2),
        IndexerPoll::Applied(2)
    ));
    let store = handle.store().unwrap();
    let spent = store
        .read_box(&blocks[2].transactions[0].inputs[0].box_id)
        .unwrap()
        .unwrap();
    let template =
        crate::template::template_hash_for_box_bytes(spent.box_data.candidate.ergo_tree_bytes())
            .unwrap()
            .unwrap();
    // Simulate a lost derived segment, leaving primary box/address rows intact.
    let write = store.begin_write().unwrap();
    {
        let mut table = write
            .open_table(crate::store::tables::INDEXED_TEMPLATE)
            .unwrap();
        assert!(table
            .remove(template.as_bytes().as_slice())
            .unwrap()
            .is_some());
    }
    write.commit().unwrap();
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Applied(3)
    ));
    assert!(store.secondary_repair_pending().unwrap());
    assert_eq!(handle.indexed_height(), 3);
    let observer = store.clone();
    *chain.hook.lock().unwrap() = Some(Box::new(move |height| {
        if height > 3 {
            assert!(!observer.secondary_repair_pending().unwrap());
        }
    }));
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Applied(5)
    ));
    assert!(!store.secondary_repair_pending().unwrap());
    let (_reference_tmp, reference_handle, _, mut reference) = setup(&blocks[..5]);
    assert!(matches!(
        unlimited_time(&mut reference, 16),
        IndexerPoll::Applied(5)
    ));
    assert_eq!(
        store.read_template_box_entries(&template).unwrap(),
        reference_handle
            .store()
            .unwrap()
            .read_template_box_entries(&template)
            .unwrap()
    );
}

#[test]
fn mid_batch_reorg_discards_uncommitted_progress() {
    let blocks = corpus();
    let (_tmp, handle, chain, mut task) = setup(&blocks[..3]);
    let weak = Arc::downgrade(&chain);
    *chain.hook.lock().unwrap() = Some(Box::new(move |height| {
        if height == 2 {
            weak.upgrade().unwrap().headers.lock().unwrap()[0] = Digest32::from_bytes([0xAB; 32]);
        }
    }));
    assert!(matches!(unlimited_time(&mut task, 16), IndexerPoll::Race));
    assert_eq!(handle.indexed_height(), 0);
    assert_eq!(
        handle.store().unwrap().read_meta().unwrap(),
        IndexerMeta::empty()
    );
}

#[test]
fn cancellation_and_budgets_commit_only_completed_prefix() {
    let blocks = corpus();
    for (max, time, bytes, expected) in [
        (3, Duration::from_secs(60), u64::MAX, 3),
        (16, Duration::ZERO, u64::MAX, 1),
        (16, Duration::from_secs(60), 1, 1),
    ] {
        let (_tmp, handle, _chain, mut task) = setup(&blocks[..5]);
        assert!(
            matches!(task.step_with_budget(max, time, bytes), IndexerPoll::Applied(h) if h == expected)
        );
        assert_eq!(
            handle.store().unwrap().read_meta().unwrap().indexed_height,
            expected
        );
    }
    let (_tmp, handle, chain, mut task) = setup(&blocks[..5]);
    let cancel = task.cancel.clone();
    *chain.hook.lock().unwrap() = Some(Box::new(move |height| {
        if height == 2 {
            cancel.store(true, Ordering::Release);
        }
    }));
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Applied(1)
    ));
    assert_eq!(handle.indexed_height(), 1);
}

#[test]
fn missing_section_after_progress_commits_prefix_then_uses_normal_retry() {
    let blocks = corpus();
    let (_tmp, handle, chain, mut task) = setup(&blocks[..3]);
    chain.blocks.lock().unwrap().remove(&blocks[1].header_id);
    assert!(matches!(
        unlimited_time(&mut task, 16),
        IndexerPoll::Applied(1)
    ));
    assert!(matches!(
        task.step_batch(),
        IndexerPoll::SectionRetry { height: 2, .. }
    ));
    assert_eq!(handle.indexed_height(), 1);
}

#[test]
#[ignore = "manual mainnet index catch-up benchmark"]
fn benchmark_mainnet_index_batches() {
    let blocks = corpus();
    for batch in [1, 4, 16] {
        let mut samples = Vec::new();
        let mut commits = 0;
        for iteration in 0..6 {
            let (_tmp, handle, _chain, mut task) = setup(&blocks);
            let start = Instant::now();
            commits = 0;
            while handle.indexed_height() < 200 {
                assert!(matches!(
                    task.step_with_budget(batch, Duration::from_millis(50), 8 * 1024 * 1024),
                    IndexerPoll::Applied(_)
                ));
                commits += 1;
            }
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            if iteration > 0 {
                samples.push(ms);
            }
        }
        samples.sort_by(f64::total_cmp);
        println!(
            "blocks=200 batch_limit={batch} commits_last_sample={commits} median_ms={:.3}",
            samples[2]
        );
    }
}

struct FailingChain {
    inner: Arc<Chain>,
    operation: &'static str,
    fail_at: usize,
    calls: std::sync::atomic::AtomicUsize,
}

impl FailingChain {
    fn check(&self, operation: &'static str) -> Result<(), crate::IndexerError> {
        if operation == self.operation
            && self.calls.fetch_add(1, Ordering::Relaxed) + 1 == self.fail_at
        {
            return Err(crate::IndexerError::ChainRead {
                operation,
                source: Box::new(std::io::Error::other("controlled source read failure")),
            });
        }
        Ok(())
    }
}

impl IndexerChainSource for FailingChain {
    fn committed_tip(&self) -> Result<ChainTip, crate::IndexerError> {
        self.check("tip")?;
        self.inner.committed_tip()
    }
    fn header_id_at(&self, height: u32) -> Result<Option<HeaderId>, crate::IndexerError> {
        self.check("header")?;
        self.inner.header_id_at(height)
    }
    fn full_block(&self, id: &HeaderId) -> Result<Option<IndexerFullBlock>, crate::IndexerError> {
        self.check("block")?;
        self.inner.full_block(id)
    }
}

#[test]
fn every_batch_source_error_aborts_all_uncommitted_rows() {
    let blocks: Vec<_> = corpus().into_iter().take(2).collect();
    for (operation, fail_at) in [
        ("tip", 1),
        ("header", 1),
        ("block", 1),
        ("header", 2),
        ("header", 3),
        ("block", 2),
        ("header", 4),
        ("header", 5),
        ("header", 6),
        ("header", 7),
        ("header", 8),
    ] {
        let (_tmp, handle, chain, _) = setup(&blocks);
        let source = Arc::new(FailingChain {
            inner: chain,
            operation,
            fail_at,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut task = IndexerTask::new(handle.clone(), source);
        let outcome = task.step_with_budget(2, Duration::from_secs(60), u64::MAX);
        assert!(
            matches!(
                outcome,
                IndexerPoll::Halted(crate::IndexerError::ChainRead { .. })
            ),
            "{operation}#{fail_at}: {outcome:?}"
        );
        let store = handle.store().unwrap();
        assert_eq!(store.read_meta().unwrap(), IndexerMeta::empty());
        assert!(store.read_numeric_box(0).unwrap().is_none());
        assert!(store.read_numeric_tx(0).unwrap().is_none());
        assert!(store.read_undo(1).unwrap().is_none());
        assert_eq!(handle.indexed_height(), 0);
        // An explicit retry after the controlled failure uses a clean scratch
        // and checkpoint, rather than leaked in-memory batch progress.
        assert!(matches!(
            task.step_with_budget(2, Duration::from_secs(60), u64::MAX),
            IndexerPoll::Applied(2)
        ));
    }
}

#[test]
fn public_step_reports_chain_failure_as_halted_not_caught_up() {
    let blocks: Vec<_> = corpus().into_iter().take(1).collect();
    let (_tmp, handle, chain, _) = setup(&blocks);
    handle.set_status(IndexerStatus::CaughtUp);
    let source = Arc::new(FailingChain {
        inner: chain,
        operation: "tip",
        fail_at: 1,
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut task = IndexerTask::new(handle.clone(), source);
    assert!(matches!(
        task.step(),
        IndexerPoll::Halted(crate::IndexerError::ChainRead { .. })
    ));
    assert_eq!(
        handle.status(),
        IndexerStatus::Halted(IndexerHaltReason::DbCorruption)
    );
}

#[test]
fn rollback_source_failure_preserves_the_committed_checkpoint_and_undo() {
    let blocks: Vec<_> = corpus().into_iter().take(2).collect();
    let (_tmp, handle, chain, mut task) = setup(&blocks);
    assert!(matches!(task.step(), IndexerPoll::Applied(1)));
    let store = handle.store().unwrap();
    let before = store.read_meta().unwrap();
    let undo = store.read_undo(1).unwrap();
    let first_box = store.read_numeric_box(0).unwrap();
    // The committed tip still agrees with its canonical height, while the
    // indexed height belongs to the old fork and needs one rollback.
    chain.headers.lock().unwrap()[0] = Digest32::from_bytes([0x42; 32]);
    let source = Arc::new(FailingChain {
        inner: chain,
        operation: "block",
        fail_at: 1,
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut task = IndexerTask::new(handle.clone(), source);
    assert!(matches!(
        task.step(),
        IndexerPoll::Halted(crate::IndexerError::ChainRead { .. })
    ));
    assert_eq!(store.read_meta().unwrap(), before);
    assert_eq!(store.read_undo(1).unwrap(), undo);
    assert_eq!(store.read_numeric_box(0).unwrap(), first_box);
    assert_eq!(handle.indexed_height(), 1);
    assert_eq!(
        handle.status(),
        IndexerStatus::Halted(IndexerHaltReason::DbCorruption)
    );
}

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
    fn committed_tip(&self) -> ChainTip {
        let height = self.tip.load(Ordering::Relaxed);
        ChainTip {
            height,
            header_id: self.headers.lock().unwrap()[height as usize - 1],
        }
    }
    fn header_id_at(&self, h: u32) -> Option<HeaderId> {
        self.headers
            .lock()
            .unwrap()
            .get(h.checked_sub(1)? as usize)
            .copied()
    }
    fn full_block(&self, id: &HeaderId) -> Option<IndexerFullBlock> {
        let block = self.blocks.lock().unwrap().get(id).cloned()?;
        if let Some(hook) = &*self.hook.lock().unwrap() {
            hook(block.height as u32);
        }
        Some(block)
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

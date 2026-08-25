//! Reorg equivalence tests at depths 1, 3, and 10.
//!
//! Each test runs the same shape:
//!   1. Apply a genesis block. Snapshot the indexer state — call it S0.
//!   2. Apply fork-A (N synthetic blocks at heights 2..=N+1) and assert
//!      the state advanced.
//!   3. Roll back fork-A one block at a time, top-down. Snapshot again
//!      and assert byte-for-byte equality with S0 (the core
//!      rollback-idempotence invariant).
//!   4. Apply fork-B (a different fork, with N blocks at the same
//!      heights but different proofs / output values, so different
//!      tx_ids and box_ids). Snapshot — call it S_via_reorg.
//!   5. Build a fresh DB, apply genesis + fork-B directly. Snapshot —
//!      call it S_fresh.
//!   6. Assert S_via_reorg == S_fresh: the indexer that walked through
//!      fork-A and rolled it back must end up indistinguishable from
//!      one that only ever saw fork-B.

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
    apply_block, rollback_one_block, BoxId, HeaderId, IndexerBlock, IndexerMeta, IndexerStore,
    TxId, UndoEntry,
};
use ergo_indexer_types::{IndexedErgoBox, IndexedErgoTransaction};

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

fn open_store() -> (IndexerStore, TempDir) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();
    (store, tmp)
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

/// Pre-built block ready to feed into `apply_block` / `rollback_one_block`.
struct ChainBlock {
    height: i32,
    header_id: HeaderId,
    txs: Vec<Transaction>,
}

impl ChainBlock {
    fn as_indexer(&self) -> IndexerBlock<'_> {
        IndexerBlock {
            height: self.height,
            header_id: self.header_id,
            transactions: &self.txs,
        }
    }
}

/// Genesis block: spends a fake input (skipped at height 1),
/// emits one funding output the fork blocks chain off of.
fn build_genesis() -> (ChainBlock, BoxId) {
    let tx = Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes([0xFF; 32]),
            spending_proof: SpendingProof::new(vec![0x00], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![candidate(1_000_000_000, 1)],
    };
    let funding_id = sealed_box_id(&tx, 0);
    let block = ChainBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x01; 32]),
        txs: vec![tx],
    };
    (block, funding_id)
}

/// Build a fork of `depth` blocks chaining off `parent_output`. Each
/// block has one tx that spends the previous block's sole output and
/// creates one new output. `tag` differentiates fork-A from fork-B by
/// going into both the spending proof and the output value, so tx_ids
/// (and box_ids) differ between forks.
fn build_fork(tag: u8, depth: usize, parent_output: BoxId) -> Vec<ChainBlock> {
    let mut blocks = Vec::with_capacity(depth);
    let mut prev_output = parent_output;
    for i in 0..depth {
        let height = (i + 2) as i32;
        let value = 100_000 + (tag as u64) * 1_000_000 + i as u64;
        let tx = Transaction {
            inputs: vec![Input {
                box_id: prev_output,
                spending_proof: SpendingProof::new(
                    vec![tag, tag, tag, i as u8],
                    ContextExtension::empty(),
                )
                .unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![candidate(value, height as u32)],
        };
        let next_output = sealed_box_id(&tx, 0);
        // Header id mixes tag and height so all headers are distinct
        // across forks and within one fork.
        let mut hdr = [tag; 32];
        hdr[0] = tag;
        hdr[1] = i as u8;
        let block = ChainBlock {
            height,
            header_id: Digest32::from_bytes(hdr),
            txs: vec![tx],
        };
        blocks.push(block);
        prev_output = next_output;
    }
    blocks
}

fn apply_chain(
    store: &IndexerStore,
    blocks: &[ChainBlock],
    start_meta: &IndexerMeta,
) -> IndexerMeta {
    let mut meta = start_meta.clone();
    for block in blocks {
        meta = apply_block(store, &meta, &block.as_indexer()).unwrap();
    }
    meta
}

/// Roll back `blocks` from the top down (matches the polling task's
/// reorg walk: from current tip back to the divergence point).
fn rollback_chain(
    store: &IndexerStore,
    blocks: &[ChainBlock],
    top_meta: &IndexerMeta,
) -> IndexerMeta {
    let mut meta = top_meta.clone();
    for block in blocks.iter().rev() {
        meta = rollback_one_block(store, &meta, &block.as_indexer()).unwrap();
    }
    meta
}

/// Captures every reachable indexer row in a comparable form. Two
/// snapshots being `==` means the underlying redb tables are
/// byte-for-byte identical for boxes/txs/numeric/meta/undo (which is
/// the entire P1 surface).
#[derive(Debug, PartialEq)]
struct IndexerSnapshot {
    meta: IndexerMeta,
    num_boxes: Vec<BoxId>,
    num_txs: Vec<TxId>,
    boxes: Vec<IndexedErgoBox>,
    txs: Vec<IndexedErgoTransaction>,
    undos: Vec<(u64, UndoEntry)>,
}

fn snapshot(store: &IndexerStore) -> IndexerSnapshot {
    let meta = store.read_meta().unwrap();

    let mut num_boxes = Vec::with_capacity(meta.global_box_index as usize);
    let mut boxes = Vec::with_capacity(meta.global_box_index as usize);
    for n in 0..meta.global_box_index {
        let id = store
            .read_numeric_box(n)
            .unwrap()
            .unwrap_or_else(|| panic!("NUMERIC_BOX[{n}] missing"));
        let row = store
            .read_box(&id)
            .unwrap()
            .unwrap_or_else(|| panic!("INDEXED_BOX missing for NUMERIC_BOX[{n}]"));
        num_boxes.push(id);
        boxes.push(row);
    }

    let mut num_txs = Vec::with_capacity(meta.global_tx_index as usize);
    let mut txs = Vec::with_capacity(meta.global_tx_index as usize);
    for n in 0..meta.global_tx_index {
        let id = store
            .read_numeric_tx(n)
            .unwrap()
            .unwrap_or_else(|| panic!("NUMERIC_TX[{n}] missing"));
        let row = store
            .read_tx(&id)
            .unwrap()
            .unwrap_or_else(|| panic!("INDEXED_TX missing for NUMERIC_TX[{n}]"));
        num_txs.push(id);
        txs.push(row);
    }

    let mut undos = Vec::new();
    for h in 1..=meta.indexed_height {
        if let Some(u) = store.read_undo(h).unwrap() {
            undos.push((h, u));
        }
    }

    IndexerSnapshot {
        meta,
        num_boxes,
        num_txs,
        boxes,
        txs,
        undos,
    }
}

fn run_reorg_at_depth(depth: usize) {
    // --- Test DB: walks through fork-A then rolls it back, then applies fork-B.
    let (store, _tmp) = open_store();
    let (genesis, funding_id) = build_genesis();

    // Step 1: apply genesis, snapshot.
    let meta_genesis = apply_chain(
        &store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    assert_eq!(meta_genesis.indexed_height, 1);
    let snap_after_genesis = snapshot(&store);

    // Step 2: apply fork-A.
    let fork_a = build_fork(0xAA, depth, funding_id);
    let meta_fork_a = apply_chain(&store, &fork_a, &meta_genesis);
    assert_eq!(meta_fork_a.indexed_height, (depth + 1) as u64);

    // Step 3: roll back fork-A, snapshot again, compare to genesis snap.
    let meta_back = rollback_chain(&store, &fork_a, &meta_fork_a);
    assert_eq!(meta_back, meta_genesis);
    let snap_after_rollback = snapshot(&store);
    assert_eq!(
        snap_after_rollback, snap_after_genesis,
        "post-rollback state must equal post-genesis state byte-for-byte at depth {depth}"
    );

    // Step 4: apply fork-B from the rolled-back state.
    let fork_b = build_fork(0xBB, depth, funding_id);
    let meta_fork_b = apply_chain(&store, &fork_b, &meta_back);
    let snap_via_reorg = snapshot(&store);

    // --- Reference DB: never sees fork-A, only genesis + fork-B.
    let (ref_store, _ref_tmp) = open_store();
    let ref_meta_genesis = apply_chain(
        &ref_store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let ref_meta_fork_b = apply_chain(&ref_store, &fork_b, &ref_meta_genesis);
    assert_eq!(meta_fork_b, ref_meta_fork_b);
    let snap_fresh = snapshot(&ref_store);

    // Topology-equality invariant: end state equals fresh-DB control
    // byte-for-byte.
    assert_eq!(
        snap_via_reorg, snap_fresh,
        "post-reorg state must equal fresh fork-B state byte-for-byte at depth {depth}"
    );
}

#[test]
fn reorg_depth_1_yields_state_identical_to_fresh_fork_b() {
    run_reorg_at_depth(1);
}

#[test]
fn reorg_depth_3_yields_state_identical_to_fresh_fork_b() {
    run_reorg_at_depth(3);
}

#[test]
fn reorg_depth_10_yields_state_identical_to_fresh_fork_b() {
    run_reorg_at_depth(10);
}

/// Asymmetric depth: fork-A has 5 blocks, fork-B has 10. Catches any
/// off-by-one in the walk that depths-1/3/10 (where forks are equal
/// length) would mask.
#[test]
fn reorg_depth_5_then_10_yields_state_identical_to_fresh_fork_b() {
    let (store, _tmp) = open_store();
    let (genesis, funding_id) = build_genesis();

    let meta_genesis = apply_chain(
        &store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );

    let fork_a = build_fork(0xAA, 5, funding_id);
    let meta_a = apply_chain(&store, &fork_a, &meta_genesis);
    let meta_back = rollback_chain(&store, &fork_a, &meta_a);
    assert_eq!(meta_back, meta_genesis);

    let fork_b = build_fork(0xBB, 10, funding_id);
    let meta_b = apply_chain(&store, &fork_b, &meta_back);
    let snap_via_reorg = snapshot(&store);

    let (ref_store, _ref_tmp) = open_store();
    let ref_meta_genesis = apply_chain(
        &ref_store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let ref_meta_b = apply_chain(&ref_store, &fork_b, &ref_meta_genesis);
    assert_eq!(meta_b, ref_meta_b);
    let snap_fresh = snapshot(&ref_store);

    assert_eq!(snap_via_reorg, snap_fresh);
}

//! Reorg tests crossing the 512-segment threshold — the
//! pre-apply-vs-post-rollback topology-equality invariant.
//!
//! These tests exercise the address-spill code paths that the
//! depth-only reorg tests can't reach: a single fork-A block produces
//! enough outputs to one address to trigger one or more head-buffer
//! spills. Shape mirrors `reorg_depth.rs` — apply genesis (a small
//! pre-state so the spill-tracked address already has a row), run
//! fork-A (the fat block), roll it back, assert state equals the
//! pre-fork snapshot, then apply fork-B and assert state equals a
//! fresh DB that only ever saw genesis + fork-B.
//!
//! The snapshot here is wider than P1's: it also captures the
//! `IndexedAddress` parent record and every box/tx spill segment
//! under each tracked tree-hash, so any drift in head buffer, spill
//! counters, or spill bytes shows up as a `==` mismatch.

use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::{Body, Expr};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::transaction::{transaction_id, Transaction};
use tempfile::TempDir;

use ergo_indexer::address::IndexedAddress;
use ergo_indexer::segment::{Segment, SEGMENT_THRESHOLD};
use ergo_indexer::segment_id::{box_segment_id, tx_segment_id};
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

fn tree_hash_of(tree: &ErgoTree) -> Digest32 {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, tree).unwrap();
    ergo_primitives::digest::blake2b256(&w.result())
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

/// One block, one tx, one input (spending the genesis funding output)
/// and `n_outputs` outputs that all go to the size-delimited true tree.
/// `tag` differentiates fork-A from fork-B by perturbing spending proof
/// bytes and output values, which gives different tx_ids / box_ids
/// across forks (so the byte-for-byte equality check has distinct
/// shapes to compare).
fn build_fat_block(tag: u8, n_outputs: u32, parent_output: BoxId) -> ChainBlock {
    let outputs: Vec<ErgoBoxCandidate> = (0..n_outputs)
        .map(|i| candidate(1_000 + (tag as u64) * 10_000 + i as u64, 2))
        .collect();
    let tx = Transaction {
        inputs: vec![Input {
            box_id: parent_output,
            spending_proof: SpendingProof::new(vec![tag, tag, tag, tag], ContextExtension::empty())
                .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: outputs,
    };
    let mut hdr = [tag; 32];
    hdr[0] = tag;
    hdr[1] = 0xFA;
    ChainBlock {
        height: 2,
        header_id: Digest32::from_bytes(hdr),
        txs: vec![tx],
    }
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

/// Wider snapshot than P1's: P1 covers boxes/txs/numeric/meta/undo.
/// P2 must additionally pin down `IndexedAddress` parent records and
/// every spill segment under each tracked tree hash. `tracked_trees`
/// is the list of tree hashes the test uses — for these tests, just
/// the size-delimited true tree.
#[derive(Debug, PartialEq)]
struct IndexerSnapshot {
    meta: IndexerMeta,
    num_boxes: Vec<BoxId>,
    num_txs: Vec<TxId>,
    boxes: Vec<IndexedErgoBox>,
    txs: Vec<IndexedErgoTransaction>,
    undos: Vec<(u64, UndoEntry)>,
    addresses: Vec<(Digest32, Option<IndexedAddress>)>,
    box_spills: Vec<(Digest32, i32, Option<Segment>)>,
    tx_spills: Vec<(Digest32, i32, Option<Segment>)>,
}

fn snapshot(store: &IndexerStore, tracked_trees: &[Digest32]) -> IndexerSnapshot {
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

    // Walk each tracked tree's parent record, then every spill
    // segment up to its `box_segment_count` / `tx_segment_count`,
    // plus one slot past the count to confirm it's empty (catches a
    // counter-decrement bug that leaves a stale spill row behind).
    let mut addresses = Vec::with_capacity(tracked_trees.len());
    let mut box_spills = Vec::new();
    let mut tx_spills = Vec::new();
    for th in tracked_trees {
        let addr_opt = store.read_address(th).unwrap();
        let (box_count, tx_count) = match &addr_opt {
            Some(a) => (a.segment.box_segment_count, a.segment.tx_segment_count),
            None => (0, 0),
        };
        addresses.push((*th, addr_opt));

        for n in 0..=box_count {
            let sid = box_segment_id(th, n);
            let seg = store.read_spill_segment(&sid).unwrap();
            box_spills.push((sid, n, seg));
        }
        for n in 0..=tx_count {
            let sid = tx_segment_id(th, n);
            let seg = store.read_spill_segment(&sid).unwrap();
            tx_spills.push((sid, n, seg));
        }
    }

    IndexerSnapshot {
        meta,
        num_boxes,
        num_txs,
        boxes,
        txs,
        undos,
        addresses,
        box_spills,
        tx_spills,
    }
}

/// Drives a fat-block reorg test.
///
/// Genesis emits 1 output to the size-delimited true tree; fork-A's
/// fat block at height 2 spends that output (sign-flipping its head
/// entry) and appends `n_outputs` new outputs to the same tree. Total
/// entries appended/flipped to the head is `1 + n_outputs`, which is
/// what determines the spill count.
fn run_fat_reorg(n_outputs: u32, expected_box_spills: i32) {
    let trees = [tree_hash_of(&size_delimited_tree())];
    let total_head_entries = 1 + n_outputs as usize;
    let expected_head_len = total_head_entries - SEGMENT_THRESHOLD * expected_box_spills as usize;

    let (store, _tmp) = open_store();
    let (genesis, funding_id) = build_genesis();

    let meta_genesis = apply_chain(
        &store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let snap_after_genesis = snapshot(&store, &trees);

    let fork_a = vec![build_fat_block(0xAA, n_outputs, funding_id)];
    let meta_fork_a = apply_chain(&store, &fork_a, &meta_genesis);

    // Sanity: the apply path actually triggered the expected number
    // of spills on the tracked tree. If the threshold logic regresses
    // this catches it before the reorg-equality assertions.
    let addr_after_a = store.read_address(&trees[0]).unwrap().unwrap();
    assert_eq!(
        addr_after_a.segment.box_segment_count, expected_box_spills,
        "fork-A with {n_outputs} outputs should produce exactly {expected_box_spills} box spills"
    );
    assert_eq!(
        addr_after_a.segment.boxes.len(),
        expected_head_len,
        "head buffer length after fork-A apply (1 sign-flipped genesis entry + {n_outputs} appends, {expected_box_spills} spills)"
    );

    let meta_back = rollback_chain(&store, &fork_a, &meta_fork_a);
    assert_eq!(meta_back, meta_genesis);
    let snap_after_rollback = snapshot(&store, &trees);
    assert_eq!(
        snap_after_rollback, snap_after_genesis,
        "post-rollback state must equal post-genesis state byte-for-byte ({n_outputs} outputs, {expected_box_spills} spills)"
    );

    let fork_b = vec![build_fat_block(0xBB, n_outputs, funding_id)];
    let meta_fork_b = apply_chain(&store, &fork_b, &meta_back);
    let snap_via_reorg = snapshot(&store, &trees);

    let (ref_store, _ref_tmp) = open_store();
    let ref_meta_genesis = apply_chain(
        &ref_store,
        std::slice::from_ref(&genesis),
        &IndexerMeta::empty(),
    );
    let ref_meta_fork_b = apply_chain(&ref_store, &fork_b, &ref_meta_genesis);
    assert_eq!(meta_fork_b, ref_meta_fork_b);
    let snap_fresh = snapshot(&ref_store, &trees);

    assert_eq!(
        snap_via_reorg, snap_fresh,
        "post-reorg state must equal fresh fork-B state byte-for-byte ({n_outputs} outputs, {expected_box_spills} spills)"
    );
}

/// 512 outputs to one address (plus the one sign-flipped genesis
/// entry already in the head) total 513 head entries, triggering
/// exactly one spill: 512 entries move to spill[0] and the head
/// retains a single entry. After rolling fork-A back the parent
/// record's `box_segment_count` must return to 0 and
/// `SEGMENTS[box_segment_id(_, 0)]` must be gone — proven by the
/// extended snapshot's `==` against the pre-fork-A snapshot.
#[test]
fn reorg_with_single_spill_yields_state_identical_to_fresh_fork_b() {
    run_fat_reorg(SEGMENT_THRESHOLD as u32, 1);
}

/// 1024 outputs in a single block plus the genesis sign-flip total
/// 1025 head entries, triggering two spills on the *same parent in
/// the same block* — the high-risk multi-spill rollback path. After
/// applying fork-A,
/// `box_segment_count == 2` and head length is 1; after rollback both
/// spill segments must be removed and the counter must drop back to 0.
#[test]
fn reorg_with_multi_spill_one_block_yields_state_identical_to_fresh_fork_b() {
    run_fat_reorg(SEGMENT_THRESHOLD as u32 * 2, 2);
}

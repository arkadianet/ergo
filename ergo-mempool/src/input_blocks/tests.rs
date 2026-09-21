use super::*;
use crate::validator::MAINNET_FEE_PROPOSITION_BYTES;
use crate::weight::ByCost;
use crate::MempoolConfig;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::write_transaction;
use std::collections::HashMap;

// ----- helpers -----

fn d(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

fn ord_tree() -> ergo_ser::ergo_tree::ErgoTree {
    let bytes = vec![0x00u8, 0x08, 0xd3];
    let mut r = VlqReader::new(&bytes);
    read_ergo_tree(&mut r).unwrap()
}

fn fee_tree() -> ergo_ser::ergo_tree::ErgoTree {
    let bytes = MAINNET_FEE_PROPOSITION_BYTES.to_vec();
    let mut r = VlqReader::new(&bytes);
    read_ergo_tree(&mut r).unwrap()
}

fn fee_candidate(value: u64) -> ErgoBoxCandidate {
    ErgoBoxCandidate::from_trusted_raw_parts(
        value,
        fee_tree(),
        MAINNET_FEE_PROPOSITION_BYTES.to_vec(),
        0,
        vec![],
        AdditionalRegisters::empty(),
        vec![0u8],
    )
}

fn ord_candidate(value: u64) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(value, ord_tree(), 0, vec![], AdditionalRegisters::empty()).unwrap()
}

fn input_with_proof(box_id: Digest32, proof: &[u8]) -> Input {
    Input {
        box_id,
        spending_proof: SpendingProof::new(proof.to_vec(), ContextExtension::empty()).unwrap(),
    }
}

/// Build a real, canonically-serialized transaction spending `inputs` (empty
/// spending proofs) and paying `fee` via the canonical mainnet miner-fee
/// output, plus one ordinary output. Returns the parsed `Transaction`, its
/// canonical bytes, and its real tx id.
fn build_tx(inputs: &[Digest32], fee: u64) -> (Transaction, Arc<[u8]>, TxId) {
    let tx = Transaction {
        inputs: inputs.iter().map(|id| input_with_proof(*id, &[])).collect(),
        data_inputs: vec![],
        output_candidates: vec![fee_candidate(fee), ord_candidate(1_000_000)],
    };
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).unwrap();
    let bytes: Arc<[u8]> = Arc::from(w.result().into_boxed_slice());
    let tx_id = *transaction_id(&tx).unwrap().as_digest();
    (tx, bytes, tx_id)
}

/// Build a transaction with a distinguishing spending-proof byte so its
/// canonical bytes (and hence `witness_id`) differ from an all-empty-proof
/// sibling built from the same inputs.
fn build_tx_with_proof(
    inputs: &[Digest32],
    fee: u64,
    proof_byte: u8,
) -> (Transaction, Arc<[u8]>, TxId) {
    let tx = Transaction {
        inputs: inputs
            .iter()
            .map(|id| input_with_proof(*id, &[proof_byte]))
            .collect(),
        data_inputs: vec![],
        output_candidates: vec![fee_candidate(fee), ord_candidate(1_000_000)],
    };
    let mut w = VlqWriter::new();
    write_transaction(&mut w, &tx).unwrap();
    let bytes: Arc<[u8]> = Arc::from(w.result().into_boxed_slice());
    let tx_id = *transaction_id(&tx).unwrap().as_digest();
    (tx, bytes, tx_id)
}

fn dummy_box(id_byte: u8) -> ErgoBox {
    let tree_bytes = vec![0x00u8, 0x01, 0x01];
    let mut r = VlqReader::new(&tree_bytes);
    let tree = read_ergo_tree(&mut r).expect("parse tree");
    let candidate = ErgoBoxCandidate::new(1_000_000, tree, 0, vec![], AdditionalRegisters::empty())
        .expect("candidate");
    ErgoBox {
        candidate,
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes([id_byte; 32]),
        index: 0,
    }
}

struct FakeUtxo {
    boxes: HashMap<Digest32, ErgoBox>,
}
impl FakeUtxo {
    fn empty() -> Self {
        Self {
            boxes: HashMap::new(),
        }
    }
    fn with_box(mut self, id: Digest32, b: ErgoBox) -> Self {
        self.boxes.insert(id, b);
        self
    }
}
impl UtxoView for FakeUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.boxes.get(box_id).cloned()
    }
}

#[allow(clippy::too_many_arguments)]
fn seed_entry(
    pool: &mut OrderedPool,
    tx_id: TxId,
    inputs: Vec<Digest32>,
    outputs: Vec<Digest32>,
    parents: Vec<TxId>,
    weight: u64,
) {
    let bytes: Arc<[u8]> = Arc::from(vec![0xEEu8; 8].into_boxed_slice());
    let entry = Entry::new(
        tx_id,
        bytes,
        inputs,
        outputs,
        parents,
        1_000_000,
        weight,
        8,
        50_000,
        TxSource::Api,
    );
    pool.insert(entry).unwrap();
}

// ----- happy path -----

#[test]
fn overlay_exposes_input_block_outputs_and_hides_input_block_spent_boxes() {
    let committed_input = d(1);
    let committed = FakeUtxo::empty().with_box(committed_input, dummy_box(1));
    let pool_outputs: HashMap<Digest32, ErgoBox> = HashMap::new();

    let (tx, _bytes, _tx_id) = build_tx(&[committed_input], 100);
    let created_output_id = ErgoBox {
        candidate: tx.output_candidates[0].clone(),
        transaction_id: transaction_id(&tx).unwrap(),
        index: 0,
    }
    .box_id()
    .unwrap();

    let overlay = InputBlockOverlay::new(&committed, &pool_outputs, std::slice::from_ref(&tx))
        .expect("overlay builds from valid txs");

    assert!(
        overlay.get_box(&committed_input).is_none(),
        "box spent by an input-block tx must be hidden"
    );
    assert!(
        overlay.get_box(&created_output_id).is_some(),
        "box created by an input-block tx must be visible"
    );
}

#[test]
fn overlay_keeps_pool_spent_boxes_visible() {
    // A committed box that some pool tx has already spent is tracked
    // separately (mempool `by_input`), not by this overlay — the overlay
    // must never hide it on its own account. With no input-block txs at
    // all, every committed/pool box stays visible.
    let box_id = d(9);
    let committed = FakeUtxo::empty().with_box(box_id, dummy_box(9));
    let pool_outputs: HashMap<Digest32, ErgoBox> = HashMap::new();
    let overlay = InputBlockOverlay::new(&committed, &pool_outputs, &[])
        .expect("overlay builds with no ib txs");
    assert!(
        overlay.get_box(&box_id).is_some(),
        "pool-spent (or any non-ib-spent) committed box stays visible"
    );
}

#[test]
fn find_by_weak_id_returns_all_colliding_entries() {
    // Two pool entries whose stored bytes are the SAME real transaction
    // (hence the same weak id) but distinct pool keys/spends — a stand-in
    // for a genuine 48-bit weak-id collision between two DIFFERENT
    // transactions, which is what the filter logic must handle: never
    // collapse to a single match.
    let (_tx, bytes, _tx_id) = build_tx(&[d(0x50)], 100);
    let mut pool = OrderedPool::with_capacity(8);
    let e1 = Entry::new(
        d(1),
        bytes.clone(),
        vec![d(0x10)],
        vec![d(0x11)],
        vec![],
        1_000_000,
        100,
        bytes.len() as u32,
        50_000,
        TxSource::Api,
    );
    let e2 = Entry::new(
        d(2),
        bytes.clone(),
        vec![d(0x20)],
        vec![d(0x21)],
        vec![],
        1_000_000,
        200,
        bytes.len() as u32,
        50_000,
        TxSource::Api,
    );
    pool.insert(e1).unwrap();
    pool.insert(e2).unwrap();

    let mut r = VlqReader::new(&bytes);
    let tx = read_transaction(&mut r).unwrap();
    let weak = weak_id_of(&tx).unwrap();

    let found = find_by_weak_id(&pool, &weak);
    let ids: HashSet<TxId> = found.iter().map(|e| e.tx_id).collect();
    assert_eq!(
        ids,
        HashSet::from([d(1), d(2)]),
        "both colliding entries returned, never a single-value map"
    );
}

#[test]
fn apply_input_block_txs_removes_txs_and_input_conflicts_and_returns_entries() {
    let mut pool = OrderedPool::with_capacity(8);
    let config = MempoolConfig::default();

    // A previously-pooled tx that IS one of the applied input-block txs.
    let (tx_seen, _bytes_seen, id_seen) = build_tx(&[d(0x30)], 111);
    seed_entry(
        &mut pool,
        id_seen,
        vec![d(0x30)],
        vec![d(0x31)],
        vec![],
        500,
    );

    // A previously-pooled tx that conflicts on an input with the applied
    // (never-before-seen) tx below.
    seed_entry(&mut pool, d(200), vec![d(0x20)], vec![d(0x99)], vec![], 300);

    // Untouched pool tx sharing no input with anything above.
    seed_entry(&mut pool, d(201), vec![d(0x77)], vec![d(0x78)], vec![], 400);

    // Applied tx never seen by this pool before; conflicts on 0x20.
    let (tx_apply, _bytes_apply, _id_apply) = build_tx(&[d(0x10), d(0x20)], 222);

    let (removed, actions) = apply_input_block_txs(&mut pool, &config, &[tx_apply, tx_seen]);

    let removed_ids: HashSet<TxId> = removed.iter().map(|e| e.tx_id).collect();
    assert_eq!(
        removed_ids,
        HashSet::from([id_seen, d(200)]),
        "both the applied pooled tx and its conflicting sibling are removed"
    );
    assert!(!pool.contains(&id_seen));
    assert!(!pool.contains(&d(200)));
    assert!(pool.contains(&d(201)), "unrelated tx survives");

    assert!(actions.iter().any(|a| matches!(
        a,
        MempoolAction::RevokeBroadcast { tx_ids } if tx_ids.len() == 2
    )));
    assert!(actions.iter().any(|a| matches!(
        a,
        MempoolAction::Observe {
            event: ObservedEvent::Evicted {
                reason: EvictionReason::InputConflict,
                ..
            }
        }
    )));
    pool.check_invariants();
}

#[test]
fn apply_input_block_txs_does_not_touch_tip_or_revalidation_queue() {
    let mut mempool = crate::Mempool::new(MempoolConfig::default(), Box::new(ByCost));
    let tip = crate::types::TipPointer {
        height: 42,
        header_id: d(0xAA),
    };
    let diff = crate::types::TxDiff {
        new_tip: tip,
        applied: vec![],
        demoted: vec![],
        applied_spent_inputs: HashSet::new(),
    };
    mempool.on_tip_change(&diff);
    assert_eq!(mempool.tip(), Some(&tip));

    let (tx, _bytes, _id) = build_tx(&[d(0x10)], 100);
    let _ = mempool.apply_input_block_txs(&[tx]);
    assert_eq!(
        mempool.tip(),
        Some(&tip),
        "apply_input_block_txs must not move the tip pointer"
    );
}

#[test]
fn restore_reinserts_without_validation_and_uses_fake_cost_when_unknown() {
    let mut pool = OrderedPool::with_capacity(8);
    let config = MempoolConfig::default();
    let weight_fn = ByCost;
    let (_tx, bytes, tx_id) = build_tx(&[d(0x40)], 1_500_000);

    let bodies = vec![(tx_id, bytes, None)];
    let outcomes = restore_input_block_txs(&mut pool, &config, &weight_fn, &bodies, Instant::now());

    assert_eq!(outcomes, vec![RestoreOutcome::Restored(tx_id)]);
    let entry = pool.get(&tx_id).expect("restored entry present");
    assert_eq!(entry.fee, 1_500_000);
    assert_eq!(
        entry.cost, FAKE_COST,
        "unknown cost falls back to FAKE_COST"
    );
    pool.check_invariants();
}

#[test]
fn restore_uses_retained_cost_when_given() {
    let mut pool = OrderedPool::with_capacity(8);
    let config = MempoolConfig::default();
    let weight_fn = ByCost;
    let (_tx, bytes, tx_id) = build_tx(&[d(0x41)], 1_500_000);

    let bodies = vec![(tx_id, bytes, Some(12_345u64))];
    let outcomes = restore_input_block_txs(&mut pool, &config, &weight_fn, &bodies, Instant::now());

    assert_eq!(outcomes, vec![RestoreOutcome::Restored(tx_id)]);
    let entry = pool.get(&tx_id).expect("restored entry present");
    assert_eq!(entry.cost, 12_345, "retained cost is used verbatim");
}

// ----- error paths -----

#[test]
fn restore_drops_input_conflict_with_pooled_tx() {
    let mut pool = OrderedPool::with_capacity(8);
    let config = MempoolConfig::default();
    let weight_fn = ByCost;

    // Already-pooled tx spends 0x10.
    seed_entry(&mut pool, d(1), vec![d(0x10)], vec![d(0x11)], vec![], 100);

    // Restored body ALSO spends 0x10 — Scala's `put` would admit both
    // (D1); `OrderedPool::insert` refuses the input collision.
    let (_tx, bytes, tx_id) = build_tx(&[d(0x10)], 1_500_000);
    let bodies = vec![(tx_id, bytes, None)];
    let outcomes = restore_input_block_txs(&mut pool, &config, &weight_fn, &bodies, Instant::now());

    assert_eq!(outcomes, vec![RestoreOutcome::Conflict(tx_id)]);
    assert!(pool.contains(&d(1)), "original pooled tx untouched");
    assert!(!pool.contains(&tx_id), "conflicting restore body dropped");
}

#[test]
fn restore_respects_capacity_eviction() {
    let mut pool = OrderedPool::with_capacity(4);
    let config = MempoolConfig {
        max_pool_size: 1,
        ..MempoolConfig::default()
    };
    let weight_fn = ByCost;

    let (_tx1, bytes1, tx_id1) = build_tx(&[d(0x50)], 500_000);
    let outcomes1 = restore_input_block_txs(
        &mut pool,
        &config,
        &weight_fn,
        &[(tx_id1, bytes1, None)],
        Instant::now(),
    );
    assert_eq!(outcomes1, vec![RestoreOutcome::Restored(tx_id1)]);
    assert!(pool.contains(&tx_id1));

    // Second restore has a higher fee (hence higher ByCost weight at the
    // same FAKE_COST) — it must survive and evict the lower-weight tx1.
    let (_tx2, bytes2, tx_id2) = build_tx_with_proof(&[d(0x51)], 5_000_000, 0x01);
    let outcomes2 = restore_input_block_txs(
        &mut pool,
        &config,
        &weight_fn,
        &[(tx_id2, bytes2, None)],
        Instant::now(),
    );

    assert!(outcomes2.contains(&RestoreOutcome::Restored(tx_id2)));
    assert!(outcomes2.contains(&RestoreOutcome::CapacityEvicted(tx_id1)));
    assert!(pool.contains(&tx_id2));
    assert!(
        !pool.contains(&tx_id1),
        "lowest-weight tx evicted over capacity"
    );
    assert_eq!(pool.len(), 1);
}

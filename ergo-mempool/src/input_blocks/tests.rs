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
use ergo_ser::transaction::read_transaction;
use ergo_ser::transaction::write_transaction;
use ergo_ser::weak_id::weak_id_of;
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

// Two real, DISTINCT transactions whose weak ids collide: found by a
// birthday search over the mainnet miner-fee output value, holding each
// tx's spending proof empty (so both share the same witness_id — a
// single degree of freedom is enough to also collide on tx_id[0..3] in a
// tractable search: ~2^12 candidates for 50% odds over a 24-bit space).
// Search performed once with `cargo test --release -- --ignored`
// (`zzz_brute_force_*`, deleted after the pair was found); these are its
// output, hard-coded so the test itself does not re-search on every run.
// tx_id a = dd31c4dd82d9be23fabb4fc3f86f3c180bf7f38196f541729e72d737dc6fee93
// tx_id b = dd31c4745061ce03b532b6daedb0dff2ad83f11ca4cbfedb5ff0440f7c0fd9db
// (equal tx_id[0..3] = dd31c4; both txs use an empty spending proof so
// witness_id — hence weak_id[3..6] — is identical too.)
const WEAK_COLLISION_TX_A_HEX: &str = "0177777777777777777777777777777777777777777777777777777777777777770000000002ad091005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304000000c0843d0008d3000000";
const WEAK_COLLISION_TX_B_HEX: &str = "018888888888888888888888888888888888888888888888888888888888888888000000000280131005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304000000c0843d0008d3000000";

fn decode_hex_tx(hex_str: &str) -> (Transaction, Arc<[u8]>) {
    let bytes: Arc<[u8]> = Arc::from(hex::decode(hex_str).unwrap().into_boxed_slice());
    let mut r = VlqReader::new(&bytes);
    (read_transaction(&mut r).unwrap(), bytes)
}

/// Build a pool `Entry` for a real, parsed transaction, deriving every
/// tx-shaped field (inputs, output ids, fee, size) from `tx`/`bytes`
/// itself rather than fabricating them — required so a fixture built this
/// way actually stands in for a genuinely admitted transaction (see
/// findings-2-r2 #2 / findings-2-r3, `find_by_weak_id_returns_all_colliding_entries`'s
/// non-matching fixture).
fn entry_from_tx(tx_id: TxId, tx: &Transaction, bytes: Arc<[u8]>, weight: u64, cost: u64) -> Entry {
    let inputs: Vec<Digest32> = tx.inputs.iter().map(|i| i.box_id).collect();
    let tx_id_modifier = transaction_id(tx).unwrap();
    let outputs: Vec<Digest32> = tx
        .output_candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            ErgoBox {
                candidate: candidate.clone(),
                transaction_id: tx_id_modifier,
                index: idx as u16,
            }
            .box_id()
            .unwrap()
        })
        .collect();
    let fee: u64 = tx
        .output_candidates
        .iter()
        .filter(|c| c.ergo_tree_bytes() == MAINNET_FEE_PROPOSITION_BYTES)
        .map(|c| c.value)
        .sum();
    let size_bytes = bytes.len() as u32;
    Entry::new(
        tx_id,
        bytes,
        inputs,
        outputs,
        vec![],
        fee,
        weight,
        size_bytes,
        cost,
        TxSource::Api,
    )
}

#[test]
fn find_by_weak_id_returns_all_colliding_entries() {
    // Two DISTINCT real transactions whose weak id genuinely collides (see
    // the fixture comment above) — the filter logic must return BOTH, never
    // collapse to a single match. A third, unrelated pooled entry with a
    // different weak id must be excluded.
    let (tx_a, bytes_a) = decode_hex_tx(WEAK_COLLISION_TX_A_HEX);
    let (tx_b, bytes_b) = decode_hex_tx(WEAK_COLLISION_TX_B_HEX);
    let weak_a = weak_id_of(&tx_a).unwrap();
    let weak_b = weak_id_of(&tx_b).unwrap();
    assert_eq!(weak_a, weak_b, "fixture must actually collide");
    let tx_id_a = *transaction_id(&tx_a).unwrap().as_digest();
    let tx_id_b = *transaction_id(&tx_b).unwrap().as_digest();
    assert_ne!(
        tx_id_a, tx_id_b,
        "fixture must be two DISTINCT transactions"
    );

    // Third pooled entry: a REAL, valid, non-colliding transaction — not a
    // malformed placeholder. A malformed entry is excluded via the
    // parse-error/skip branch regardless of weak-id equality (see
    // `find_by_weak_id_skips_unreadable_entries` below), so it would prove
    // nothing about the `w == weak` comparison itself; this fixture must
    // reach that comparison and lose on it (findings-2-r2 #2).
    let (tx_c, bytes_c, tx_id_c) = build_tx(&[d(0x50)], 100);
    assert_ne!(
        weak_id_of(&tx_c).unwrap(),
        weak_a,
        "non-matching fixture must not accidentally collide too"
    );

    let mut pool = OrderedPool::with_capacity(8);
    pool.insert(entry_from_tx(tx_id_a, &tx_a, bytes_a, 100, 50_000))
        .unwrap();
    pool.insert(entry_from_tx(tx_id_b, &tx_b, bytes_b, 200, 50_000))
        .unwrap();
    pool.insert(entry_from_tx(tx_id_c, &tx_c, bytes_c, 300, 50_000))
        .unwrap();

    let found = find_by_weak_id(&pool, &weak_a);
    let ids: HashSet<TxId> = found.iter().map(|e| e.tx_id).collect();
    assert_eq!(
        ids,
        HashSet::from([tx_id_a, tx_id_b]),
        "both colliding entries returned, never a single-value map"
    );
    assert!(
        !ids.contains(&tx_id_c),
        "a real, valid, non-colliding pooled transaction must not be returned"
    );
}

#[test]
fn find_by_weak_id_skips_unreadable_entries() {
    // A pooled entry whose stored bytes do not deserialize must be skipped
    // (logged via `tracing::warn!`, never a match, never a panic) — kept as
    // its own test, separate from the collision fixture above, per
    // findings-2-r2 #2.
    let mut pool = OrderedPool::with_capacity(8);
    seed_entry(&mut pool, d(1), vec![d(0x10)], vec![d(0x11)], vec![], 100);
    let weak: WeakId = [0u8; 6];
    assert!(
        find_by_weak_id(&pool, &weak).is_empty(),
        "an unreadable entry must never match, whatever weak id is queried"
    );
}

#[test]
fn weak_id_scala_oracle_same_tx_id_different_witness_is_not_a_collision() {
    // Scala-derived case from test-vectors/weak-blocks/weak_ids.json
    // (`tx1` vs `tx1_other_witness`, ergo commit 31a8de80): the SAME tx_id
    // with a DIFFERENT witness must NOT be reported as a weak-id match —
    // `find_by_weak_id` (and the underlying `weak_id_of`) must resolve the
    // full 6-byte id, not just the tx_id half.
    const TX1_HEX: &str = "0166666666666666666666666666666666666666666666666666666666666666660309090900000001c0843d0008d3010000";
    const TX1_OTHER_WITNESS_HEX: &str = "01666666666666666666666666666666666666666666666666666666666666666602080800000001c0843d0008d3010000";
    const TX1_TX_ID_HEX: &str = "6fdaadfff20bc29cb3c47ffd867639132cbed67f0ca32696c1bd70ac3fe26575";
    const TX1_WEAK_ID_HEX: &str = "6fdaadc40cf0";
    const TX1_OTHER_WITNESS_WEAK_ID_HEX: &str = "6fdaadd18bdd";

    let (tx1, _b1) = decode_hex_tx(TX1_HEX);
    let (tx1_ow, _b2) = decode_hex_tx(TX1_OTHER_WITNESS_HEX);

    let tx1_id = transaction_id(&tx1).unwrap();
    let tx1_ow_id = transaction_id(&tx1_ow).unwrap();
    assert_eq!(
        hex::encode(tx1_id.as_bytes()),
        TX1_TX_ID_HEX,
        "tx1 id matches the Scala oracle"
    );
    assert_eq!(
        tx1_id, tx1_ow_id,
        "same tx_id by construction (fixture premise)"
    );

    let weak1 = weak_id_of(&tx1).unwrap();
    let weak1_ow = weak_id_of(&tx1_ow).unwrap();
    assert_eq!(
        hex::encode(weak1),
        TX1_WEAK_ID_HEX,
        "tx1 weak id matches the Scala oracle"
    );
    assert_eq!(
        hex::encode(weak1_ow),
        TX1_OTHER_WITNESS_WEAK_ID_HEX,
        "tx1_other_witness weak id matches the Scala oracle"
    );
    assert_ne!(
        weak1, weak1_ow,
        "same tx_id, different witness must NOT be the same weak id"
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

    let (removed, actions) =
        apply_input_block_txs(&mut pool, &config, &[tx_apply, tx_seen]).unwrap();

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
    let _ = mempool.apply_input_block_txs(&[tx]).unwrap();
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

#[test]
fn restore_reconnects_pooled_children_and_reconciles_family_weight_before_eviction() {
    // apply-P -> restore-P -> evict-P must not orphan C: restoring P
    // reconnects the already-pooled spender of P's output as P's child
    // again, crediting the same family-weight boost C's presence would
    // have contributed had P never left the pool, and a later cascading
    // eviction of the restored P must take C down with it (findings-2-r1
    // #1: without reconnection, `children_of[P]` stays empty after
    // restore, so a cascade would remove only P and strand C spending a
    // box that no longer exists).
    let mut pool = OrderedPool::with_capacity(8);
    let config = MempoolConfig::default();
    let weight_fn = ByCost;
    let bounds = FamilyBounds::new(
        config.max_family_depth,
        config.max_family_ops,
        config.max_family_update_ms,
    );

    // P spends external input X, creates output O.
    let (p_tx, p_bytes, p_id) = build_tx(&[d(0x10)], 500_000);
    let o_id = ErgoBox {
        candidate: p_tx.output_candidates[0].clone(),
        transaction_id: transaction_id(&p_tx).unwrap(),
        index: 0,
    }
    .box_id()
    .unwrap();

    // C spends P's output O.
    let (_c_tx, c_bytes, c_id) = build_tx(&[o_id], 700_000);

    let p_weight_raw = weight_fn.compute(WeightInputs {
        tx_id: &p_id,
        fee: 500_000,
        size_bytes: p_bytes.len() as u32,
        cost: FAKE_COST,
    });
    let c_weight = weight_fn.compute(WeightInputs {
        tx_id: &c_id,
        fee: 700_000,
        size_bytes: c_bytes.len() as u32,
        cost: FAKE_COST,
    });

    pool.insert(Entry::new(
        p_id,
        p_bytes.clone(),
        vec![d(0x10)],
        vec![o_id],
        vec![],
        500_000,
        p_weight_raw,
        p_bytes.len() as u32,
        FAKE_COST,
        TxSource::Api,
    ))
    .unwrap();
    pool.insert(Entry::new(
        c_id,
        c_bytes.clone(),
        vec![o_id],
        vec![d(0x60)],
        vec![p_id],
        700_000,
        c_weight,
        c_bytes.len() as u32,
        FAKE_COST,
        TxSource::Api,
    ))
    .unwrap();
    // Mirror the family credit a real admission of C (while P was already
    // pooled) would have applied.
    pool.update_family(&[o_id], i128::from(c_weight), bounds);
    assert_eq!(pool.get(&p_id).unwrap().weight, p_weight_raw + c_weight);

    // apply-P: P leaves the pool (removed as an applied input-block tx); C
    // survives with its parent edge detached (existing, unchanged behavior).
    let (removed, _actions) =
        apply_input_block_txs(&mut pool, &config, std::slice::from_ref(&p_tx)).unwrap();
    assert_eq!(removed.len(), 1);
    assert!(!pool.contains(&p_id));
    assert!(
        pool.contains(&c_id),
        "child survives the parent's applied removal"
    );
    assert!(
        pool.get(&c_id).unwrap().parents_in_pool.is_empty(),
        "parent edge detached by apply step 4"
    );

    // restore-P: P comes back with a freshly-derived weight that starts
    // from scratch (no memory of the prior C-boost)...
    let outcomes = restore_input_block_txs(
        &mut pool,
        &config,
        &weight_fn,
        &[(p_id, p_bytes, None)],
        Instant::now(),
    );
    assert_eq!(outcomes, vec![RestoreOutcome::Restored(p_id)]);

    // ...but restore must reconnect C as P's child and reconcile the
    // family credit, so P ends up exactly as boosted as before removal.
    assert!(
        pool.get(&c_id).unwrap().parents_in_pool.contains(&p_id),
        "restore reconnects the already-pooled spender of P's output"
    );
    assert_eq!(
        pool.get(&p_id).unwrap().weight,
        p_weight_raw + c_weight,
        "family weight reconciled through the reconnected edge"
    );

    // evict-P: cascading removal (the same primitive capacity/conflict
    // eviction both use) must take C down with it — no orphan left
    // spending a box that no longer exists.
    let evicted = pool.remove_with_descendants_debiting(&p_id, config.max_family_depth, bounds);
    let evicted_ids: HashSet<TxId> = evicted.iter().map(|e| e.tx_id).collect();
    assert_eq!(evicted_ids, HashSet::from([p_id, c_id]));
    assert!(!pool.contains(&p_id));
    assert!(
        !pool.contains(&c_id),
        "reconnected child must not be left orphaned"
    );
    pool.check_invariants();
}

#[test]
fn apply_aborts_with_no_partial_removal_when_tx_id_uncomputable() {
    // Fail-closed contract (findings-2-r1 #4): if ANY tx's id cannot be
    // computed, the whole apply call must return an error and the pool
    // must be untouched — no partial removal from txs enumerated before
    // the failing one.
    let mut pool = OrderedPool::with_capacity(8);
    let config = MempoolConfig::default();

    // A separate, ordinary applied tx that WOULD succeed in isolation, and
    // is ordered BEFORE the malformed one so a buggy skip-and-continue
    // implementation would have already removed it.
    let (ok_tx, _ok_bytes, ok_id) = build_tx(&[d(0x10)], 100);
    seed_entry(&mut pool, ok_id, vec![d(0x10)], vec![d(0x11)], vec![], 500);

    // A malformed tx whose `transaction_id` computation fails: more
    // inputs than the wire format's u16 count field can express.
    let huge_input = input_with_proof(d(0x99), &[]);
    let bad_tx = Transaction {
        inputs: vec![huge_input; (u16::MAX as usize) + 1],
        data_inputs: vec![],
        output_candidates: vec![ord_candidate(1)],
    };
    assert!(
        transaction_id(&bad_tx).is_err(),
        "test fixture must actually fail id computation"
    );

    let result = apply_input_block_txs(&mut pool, &config, &[ok_tx, bad_tx]);
    assert!(
        result.is_err(),
        "apply must fail closed on an uncomputable tx id"
    );
    assert!(
        pool.contains(&ok_id),
        "no partial removal: the earlier, otherwise-valid tx must remain pooled"
    );
    pool.check_invariants();
}

#[test]
fn restore_credits_only_the_reconnected_parent_not_a_surviving_co_parent() {
    // C spends outputs of BOTH P and Q. apply-P removes only P (Q survives
    // untouched, keeping the family credit it already has). Restoring P
    // must credit ONLY the newly reconnected P edge — Q's weight must be
    // unchanged, even across repeated apply/restore cycles (findings-2-r2
    // #1: reconnecting P must not re-walk ALL of C's inputs, which would
    // re-credit Q a second time through an edge that was never broken).
    let mut pool = OrderedPool::with_capacity(8);
    let config = MempoolConfig::default();
    let weight_fn = ByCost;
    let bounds = FamilyBounds::new(
        config.max_family_depth,
        config.max_family_ops,
        config.max_family_update_ms,
    );

    // P spends external X1, creates output O_p (its fee output, index 0).
    let (p_tx, p_bytes, p_id) = build_tx(&[d(0x10)], 500_000);
    let o_p = ErgoBox {
        candidate: p_tx.output_candidates[0].clone(),
        transaction_id: transaction_id(&p_tx).unwrap(),
        index: 0,
    }
    .box_id()
    .unwrap();

    // Q spends external X2, creates output O_q (its fee output, index 0).
    let (_q_tx, q_bytes, q_id) = build_tx(&[d(0x20)], 600_000);
    let o_q = ErgoBox {
        candidate: _q_tx.output_candidates[0].clone(),
        transaction_id: transaction_id(&_q_tx).unwrap(),
        index: 0,
    }
    .box_id()
    .unwrap();

    // C spends both O_p and O_q.
    let (_c_tx, c_bytes, c_id) = build_tx(&[o_p, o_q], 700_000);

    let p_weight_raw = weight_fn.compute(WeightInputs {
        tx_id: &p_id,
        fee: 500_000,
        size_bytes: p_bytes.len() as u32,
        cost: FAKE_COST,
    });
    let q_weight_raw = weight_fn.compute(WeightInputs {
        tx_id: &q_id,
        fee: 600_000,
        size_bytes: q_bytes.len() as u32,
        cost: FAKE_COST,
    });
    let c_weight = weight_fn.compute(WeightInputs {
        tx_id: &c_id,
        fee: 700_000,
        size_bytes: c_bytes.len() as u32,
        cost: FAKE_COST,
    });

    pool.insert(Entry::new(
        p_id,
        p_bytes.clone(),
        vec![d(0x10)],
        vec![o_p],
        vec![],
        500_000,
        p_weight_raw,
        p_bytes.len() as u32,
        FAKE_COST,
        TxSource::Api,
    ))
    .unwrap();
    pool.insert(Entry::new(
        q_id,
        q_bytes,
        vec![d(0x20)],
        vec![o_q],
        vec![],
        600_000,
        q_weight_raw,
        8,
        FAKE_COST,
        TxSource::Api,
    ))
    .unwrap();
    pool.insert(Entry::new(
        c_id,
        c_bytes,
        vec![o_p, o_q],
        vec![d(0x71)],
        vec![p_id, q_id],
        700_000,
        c_weight,
        8,
        FAKE_COST,
        TxSource::Api,
    ))
    .unwrap();
    // Mirror the family credit a real admission of C would have applied:
    // walking from ALL of C's inputs credits both P and Q by c_weight.
    pool.update_family(&[o_p, o_q], i128::from(c_weight), bounds);
    let q_weight_before_apply = pool.get(&q_id).unwrap().weight;
    assert_eq!(q_weight_before_apply, q_weight_raw + c_weight);

    for cycle in 1..=2 {
        let (removed, _actions) =
            apply_input_block_txs(&mut pool, &config, std::slice::from_ref(&p_tx)).unwrap();
        assert_eq!(removed.len(), 1, "cycle {cycle}: only P removed");
        assert!(pool.contains(&c_id), "cycle {cycle}: C survives");
        assert!(
            pool.contains(&q_id),
            "cycle {cycle}: Q untouched by P's removal"
        );

        let outcomes = restore_input_block_txs(
            &mut pool,
            &config,
            &weight_fn,
            &[(p_id, p_bytes.clone(), None)],
            Instant::now(),
        );
        assert_eq!(outcomes, vec![RestoreOutcome::Restored(p_id)]);

        assert_eq!(
            pool.get(&q_id).unwrap().weight,
            q_weight_before_apply,
            "cycle {cycle}: Q's family weight must not drift — restoring P must credit \
             only the P edge, never re-credit the untouched Q edge"
        );
        assert_eq!(
            pool.get(&p_id).unwrap().weight,
            p_weight_raw + c_weight,
            "cycle {cycle}: P is credited exactly once through the reconnected edge"
        );
    }
    pool.check_invariants();
}

// ----- weak-id index -----

/// The index must answer exactly what a full scan would, and must stay
/// correct across removals — otherwise the O(1) lookup is a silent
/// behaviour change rather than a speed-up.
///
/// This is the throughput fix for the M2 devnet smoke: the node used to
/// rebuild a `WeakId -> bodies` map by parsing EVERY pooled transaction
/// on EVERY input-block frame, with roughly one input block per second
/// arriving from the miner.
#[test]
fn weak_id_index_answers_exactly_what_a_scan_would() {
    let (tx_a, bytes_a) = decode_hex_tx(WEAK_COLLISION_TX_A_HEX);
    let (tx_b, bytes_b) = decode_hex_tx(WEAK_COLLISION_TX_B_HEX);
    let weak = weak_id_of(&tx_a).unwrap();
    assert_eq!(weak, weak_id_of(&tx_b).unwrap(), "fixture must collide");
    let tx_id_a = *transaction_id(&tx_a).unwrap().as_digest();
    let tx_id_b = *transaction_id(&tx_b).unwrap().as_digest();
    let (tx_c, bytes_c, tx_id_c) = build_tx(&[d(0x51)], 100);
    let weak_c = weak_id_of(&tx_c).unwrap();
    assert_ne!(weak_c, weak);

    let mut pool = OrderedPool::with_capacity(8);
    pool.insert(entry_from_tx(tx_id_a, &tx_a, bytes_a, 100, 50_000))
        .unwrap();
    pool.insert(entry_from_tx(tx_id_b, &tx_b, bytes_b, 200, 50_000))
        .unwrap();
    pool.insert(entry_from_tx(tx_id_c, &tx_c, bytes_c, 300, 50_000))
        .unwrap();

    let indexed: Vec<TxId> = pool.tx_ids_by_weak_id(&weak).to_vec();
    assert_eq!(indexed.len(), 2, "both colliding entries, never collapsed");
    assert!(indexed.contains(&tx_id_a) && indexed.contains(&tx_id_b));
    assert_eq!(pool.tx_ids_by_weak_id(&weak_c), &[tx_id_c]);
    assert!(pool.tx_ids_by_weak_id(&[0xFF; 6]).is_empty());

    // The index is what `find_by_weak_id` answers from, so the two must
    // agree entry for entry.
    let found: Vec<TxId> = find_by_weak_id(&pool, &weak)
        .iter()
        .map(|e| e.tx_id)
        .collect();
    assert_eq!(found.len(), 2);
    assert!(found.contains(&tx_id_a) && found.contains(&tx_id_b));

    // Removing one collider leaves the other reachable; removing both
    // drops the bucket entirely rather than leaving a stale id behind.
    pool.remove(&tx_id_a).expect("pooled");
    assert_eq!(pool.tx_ids_by_weak_id(&weak), &[tx_id_b]);
    assert_eq!(find_by_weak_id(&pool, &weak).len(), 1);
    pool.remove(&tx_id_b).expect("pooled");
    assert!(
        pool.tx_ids_by_weak_id(&weak).is_empty(),
        "an emptied bucket must not linger"
    );
    assert!(find_by_weak_id(&pool, &weak).is_empty());
    assert_eq!(pool.tx_ids_by_weak_id(&weak_c), &[tx_id_c]);
}

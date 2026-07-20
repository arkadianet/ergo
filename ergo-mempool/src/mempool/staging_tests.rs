//! P2 integration tests for the staging pool wired into `Mempool::process`
//! / `on_tip_change`: orphan hold (child-before-parent), resolve-on-parent-
//! arrival + cascade, block-advance pruning, the min-fee floor, "defer not
//! drop" under the per-trigger budget, and the `/check`-never-stages and
//! staging-never-gossips invariants.

use super::*;
use crate::admission::{PeekedStructure, PeekedTx, Validated, ValidationErr, Validator};
use crate::types::{AppliedTx, TxDiff};
use crate::weight::ByCost;
use ergo_primitives::cost::JitCost;
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::AdditionalRegisters;
use ergo_validation::{ProtocolParams, TransactionContext, TxValidationCtx, UtxoView};
use std::collections::HashMap;
use std::time::Instant;

fn d(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

fn tx_bytes(b: u8) -> Vec<u8> {
    vec![b; 20]
}

/// A materialized `ErgoBox` whose identity is irrelevant — only its
/// presence in the overlay matters (the probe keys resolution on the
/// explicit `output_box_ids`, not the box contents).
fn dummy_box(id_byte: u8) -> ErgoBox {
    let tree_bytes = vec![0x00u8, 0x01, 0x01];
    let mut r = VlqReader::new(&tree_bytes);
    let tree = read_ergo_tree(&mut r).expect("parse tree");
    let candidate = ErgoBoxCandidate::new(1_000_000, tree, 0, vec![], AdditionalRegisters::empty())
        .expect("candidate");
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([id_byte; 32]),
        index: 0,
    }
}

/// Committed UTXO view over an explicit box map.
struct FakeUtxo {
    boxes: HashMap<Digest32, ErgoBox>,
}
impl FakeUtxo {
    fn with(ids: &[u8]) -> Self {
        let mut boxes = HashMap::new();
        for id in ids {
            boxes.insert(d(*id), dummy_box(*id));
        }
        Self { boxes }
    }
}
impl UtxoView for FakeUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.boxes.get(box_id).cloned()
    }
}

/// A pool-AWARE validator: `validate` actually resolves regular inputs
/// against the supplied overlay (committed + pool), so the SAME bytes flip
/// from `UnresolvedInput` (parent absent) to `Ok` (parent in pool) — which
/// `MockValidator` (state-blind) cannot express. This is what lets us test
/// child-before-parent promotion end-to-end.
#[derive(Clone)]
struct ProbePlan {
    tx_id: TxId,
    fee: u64,
    inputs: Vec<Digest32>,
    outputs: Vec<Digest32>,
    output_boxes: Vec<ErgoBox>,
    charge: u64,
}

struct PoolAwareProbe {
    plans: HashMap<Vec<u8>, ProbePlan>,
}
impl PoolAwareProbe {
    fn new() -> Self {
        Self {
            plans: HashMap::new(),
        }
    }
    /// `tx` byte, `fee`, `inputs`, `outputs` (created box ids). Output boxes
    /// are materialized so the overlay can resolve a child's input.
    fn plan(mut self, tx: u8, fee: u64, inputs: &[u8], outputs: &[u8]) -> Self {
        self.plans.insert(
            tx_bytes(tx),
            ProbePlan {
                tx_id: d(tx),
                fee,
                inputs: inputs.iter().map(|b| d(*b)).collect(),
                outputs: outputs.iter().map(|b| d(*b)).collect(),
                output_boxes: outputs.iter().map(|b| dummy_box(*b)).collect(),
                charge: 10_000,
            },
        );
        self
    }
}
impl Validator for PoolAwareProbe {
    fn peek_fee(&self, tx_bytes: &[u8]) -> Result<PeekedTx, ValidationErr> {
        let p = self.plans.get(tx_bytes).ok_or(ValidationErr::Deserialize)?;
        Ok(PeekedTx {
            tx_id: p.tx_id,
            fee: p.fee,
        })
    }
    fn peek_structure(&self, tx_bytes: &[u8]) -> Result<PeekedStructure, ValidationErr> {
        let p = self.plans.get(tx_bytes).ok_or(ValidationErr::Deserialize)?;
        Ok(PeekedStructure {
            tx_id: p.tx_id,
            fee: p.fee,
            input_box_ids: p.inputs.clone(),
            output_box_ids: p.outputs.clone(),
        })
    }
    fn validate(
        &self,
        tx_bytes: &[u8],
        input_view: &dyn UtxoView,
        _data_input_view: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr> {
        let p = self.plans.get(tx_bytes).ok_or(ValidationErr::Deserialize)?;
        if let Ok(jc) = JitCost::from_block_cost(p.charge) {
            let _ = cx.cost.add(jc);
        }
        // Real resolution: any input absent from the overlay ⇒ orphan.
        for i in &p.inputs {
            if input_view.get_box(i).is_none() {
                return Err(ValidationErr::UnresolvedInput);
            }
        }
        Ok(Validated {
            tx_id: p.tx_id,
            input_box_ids: p.inputs.clone(),
            output_box_ids: p.outputs.clone(),
            outputs: p.output_boxes.clone(),
            fee: p.fee,
            size_bytes: tx_bytes.len() as u32,
            consumed_cost: p.charge,
        })
    }
}

fn tx_context(height: u32) -> TransactionContext {
    TransactionContext {
        height,
        miner_pubkey: [0u8; 33],
        pre_header_timestamp: 0,
        activated_script_version: 2,
        pre_header_version: 3,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
    }
}

struct TestTip {
    tx_context: TransactionContext,
    params: ProtocolParams,
}
impl TestTip {
    fn new() -> Self {
        Self {
            tx_context: tx_context(1000),
            params: ProtocolParams::mainnet_default(),
        }
    }
    fn with_max_block_cost(mut self, c: u64) -> Self {
        self.params.max_block_cost = c;
        self
    }
    fn view<'a>(&'a self, utxo: &'a dyn UtxoView) -> admission::TipContext<'a> {
        admission::TipContext {
            tip: TipPointer {
                height: 1000,
                header_id: d(0xFF),
            },
            best_header_height: 1000,
            best_full_block_height: 1000,
            utxo,
            tx_context: &self.tx_context,
            params: &self.params,
            last_headers: &[],
            reemission: None,
        }
    }
}

fn mempool() -> Mempool {
    Mempool::new(MempoolConfig::default(), Box::new(ByCost))
}

fn broadcasts(actions: &[MempoolAction]) -> Vec<TxId> {
    actions
        .iter()
        .filter_map(|a| match a {
            MempoolAction::BroadcastInv { tx_id, .. } => Some(*tx_id),
            _ => None,
        })
        .collect()
}

fn diff_at(height: u32, applied: Vec<(u8, Vec<u8>)>) -> TxDiff {
    let applied_spent_inputs = applied
        .iter()
        .flat_map(|(_, ins)| ins.iter().map(|b| d(*b)))
        .collect();
    TxDiff {
        new_tip: TipPointer {
            height,
            header_id: d(0xEE),
        },
        applied: applied
            .into_iter()
            .map(|(tx, ins)| AppliedTx {
                tx_id: d(tx),
                spent_inputs: ins.into_iter().map(d).collect(),
            })
            .collect(),
        demoted: vec![],
        applied_spent_inputs,
    }
}

// ----- child-before-parent -----

#[test]
fn child_before_parent_promotes_on_parent_arrival() {
    // P spends committed 0x50, creates 0xAA. C spends 0xAA (pool-created).
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[0x50]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan(1, 5_000_000, &[0x50], &[0xAA]) // P
        .plan(2, 5_000_000, &[0xAA], &[0xBB]); // C
    let now = Instant::now();

    // Child arrives first → orphan, staged, NOT gossiped, NOT pooled.
    let (co, ca) = mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(
        co,
        AdmissionOutcome::Rejected {
            reason: RejectReason::UnresolvedInput
        }
    ));
    assert_eq!(mp.staging_len(), 1, "child held as orphan");
    assert!(!mp.contains(&d(2)));
    assert!(broadcasts(&ca).is_empty(), "staging never gossips");

    // Parent arrives → admitted, and the child promotes on the same call.
    let (po, pa) = mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(po, AdmissionOutcome::Admitted { .. }));
    assert!(mp.contains(&d(1)), "parent admitted");
    assert!(mp.contains(&d(2)), "child promoted out of staging");
    assert_eq!(mp.staging_len(), 0, "staging drained");
    // Both parent and promoted child are advertised.
    let inv = broadcasts(&pa);
    assert!(
        inv.contains(&d(1)) && inv.contains(&d(2)),
        "both gossiped: {inv:?}"
    );
    mp.pool().check_invariants();
}

#[test]
fn cascade_grandparent_parent_child() {
    // GP: 0x50 -> 0xAA. P: 0xAA -> 0xBB. C: 0xBB -> 0xCC. Deliver C, then P
    // (both orphan), then GP — one GP admission cascades to all three.
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[0x50]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan(3, 5_000_000, &[0x50], &[0xAA]) // GP
        .plan(2, 5_000_000, &[0xAA], &[0xBB]) // P
        .plan(1, 5_000_000, &[0xBB], &[0xCC]); // C
    let now = Instant::now();

    mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v); // C orphan (waits 0xBB)
    mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v); // P orphan (waits 0xAA)
    assert_eq!(mp.staging_len(), 2);

    let (o, a) = mp.process(&tx_bytes(3), TxSource::Api, now, &tip.view(&utxo), &v); // GP
    assert!(matches!(o, AdmissionOutcome::Admitted { .. }));
    assert!(
        mp.contains(&d(1)) && mp.contains(&d(2)) && mp.contains(&d(3)),
        "whole chain admitted"
    );
    assert_eq!(mp.staging_len(), 0, "staging fully drained by cascade");
    let inv = broadcasts(&a);
    assert!(inv.contains(&d(1)) && inv.contains(&d(2)) && inv.contains(&d(3)));
    mp.pool().check_invariants();
}

// ----- invariants -----

#[test]
fn check_never_stages() {
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[0x50]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new().plan(2, 5_000_000, &[0xAA], &[0xBB]); // orphan
    let now = Instant::now();

    let (co, _) = mp.check(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(
        co,
        CheckOutcome::Rejected {
            reason: RejectReason::UnresolvedInput
        }
    ));
    assert_eq!(mp.staging_len(), 0, "/check must never stage");
}

#[test]
fn min_fee_floor_blocks_staging() {
    // A would-be orphan with fee below the relay floor is rejected at the
    // peek gate BEFORE validation, so it is never staged.
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[0x50]);
    let tip = TestTip::new();
    let low = mp.config().min_relay_fee_nano_erg - 1;
    let v = PoolAwareProbe::new().plan(2, low, &[0xAA], &[0xBB]);
    let now = Instant::now();

    let (o, _) = mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(
        o,
        AdmissionOutcome::Rejected {
            reason: RejectReason::BelowMinFee
        }
    ));
    assert_eq!(
        mp.staging_len(),
        0,
        "dust-fee tx cannot consume a staging slot"
    );
}

// ----- block-advance pruning -----

#[test]
fn block_advance_prunes_spent_input_orphan() {
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[0x50]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new().plan(2, 5_000_000, &[0xAA], &[0xBB]); // orphan waits 0xAA
    let now = Instant::now();
    mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert_eq!(mp.staging_len(), 1);

    // A block confirms some tx that consumes 0xAA — the orphan can never be
    // admitted, so it is pruned on tip advance.
    let diff = diff_at(1001, vec![(0x99, vec![0xAA])]);
    mp.on_tip_change(&diff);
    assert_eq!(
        mp.staging_len(),
        0,
        "orphan whose input was consumed is pruned"
    );
}

#[test]
fn block_advance_prunes_orphan_past_block_horizon() {
    let mut mp = mempool(); // staging_max_blocks = 4
    let utxo = FakeUtxo::with(&[0x50]);
    let tip = TestTip::new(); // stages at height 1000
    let v = PoolAwareProbe::new().plan(2, 5_000_000, &[0xAA], &[0xBB]);
    let now = Instant::now();
    mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert_eq!(mp.staging_len(), 1);

    // Under the horizon: kept.
    mp.on_tip_change(&diff_at(1003, vec![]));
    assert_eq!(mp.staging_len(), 1, "3 blocks < horizon 4 → kept");
    // At the horizon (1004 - 1000 = 4): pruned.
    mp.on_tip_change(&diff_at(1004, vec![]));
    assert_eq!(mp.staging_len(), 0, "4-block horizon reached → pruned");
}

// ----- defer, not drop, under the per-trigger budget -----

#[test]
fn per_trigger_budget_defers_remaining_orphans_not_dropped() {
    // P creates 0xA1 and 0xA2; C1 waits 0xA1, C2 waits 0xA2. A tiny per-
    // trigger budget (mult=6 × max_block_cost=1 = 6, vs max_tx_cost≈4.9M)
    // admits exactly ONE child; the other is DEFERRED (still staged), never
    // dropped.
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[0x50]);
    let tip = TestTip::new().with_max_block_cost(1);
    let v = PoolAwareProbe::new()
        .plan(1, 5_000_000, &[0x50], &[0xA1, 0xA2]) // P (two outputs)
        .plan(2, 5_000_000, &[0xA1], &[0xB1]) // C1
        .plan(3, 5_000_000, &[0xA2], &[0xB2]); // C2
    let now = Instant::now();

    mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v); // C1 orphan
    mp.process(&tx_bytes(3), TxSource::Api, now, &tip.view(&utxo), &v); // C2 orphan
    assert_eq!(mp.staging_len(), 2);

    mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v); // P
    assert!(mp.contains(&d(1)), "parent admitted");
    let promoted = mp.contains(&d(2)) as usize + mp.contains(&d(3)) as usize;
    assert_eq!(
        promoted, 1,
        "exactly one child promoted under the tiny budget"
    );
    assert_eq!(
        mp.staging_len(),
        1,
        "the other child is deferred, not dropped"
    );
    mp.pool().check_invariants();
}

// ----- P3: held parents (parent-first, lost-the-gate rescue) -----

#[test]
fn held_parent_staged_on_double_spend_loss() {
    // X (high fee) and Y (low fee) both spend committed 0x60. X wins; Y loses
    // the double-spend contest but is FULLY VALIDATED, so it is HELD (a booster
    // child could later win the same conflict as a package).
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[0x60]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan(1, 5_000_000, &[0x60], &[0xA1]) // X — wins
        .plan(2, 2_000_000, &[0x60], &[0xA2]); // Y — same input, lower fee, loses
    let now = Instant::now();

    let (xo, _) = mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(xo, AdmissionOutcome::Admitted { .. }));

    let (yo, ya) = mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(
        yo,
        AdmissionOutcome::Rejected {
            reason: RejectReason::DoubleSpendLoser
        }
    ));
    assert!(mp.contains(&d(1)), "winner stays pooled");
    assert!(!mp.contains(&d(2)), "loser not pooled");
    assert_eq!(mp.staging_len(), 1, "double-spend loser held, not dropped");
    assert!(broadcasts(&ya).is_empty(), "a held tx is never gossiped");
}

#[test]
fn held_parent_staged_on_pool_full() {
    // A single-slot pool holds a high-weight X. A lower-weight Y (no conflict)
    // cannot displace it (PoolFull), but it fully validated, so it is HELD.
    let cfg = MempoolConfig {
        max_pool_size: 1,
        ..MempoolConfig::default()
    };
    let mut mp = Mempool::new(cfg, Box::new(ByCost));
    let utxo = FakeUtxo::with(&[0x60, 0x61]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan(1, 5_000_000, &[0x60], &[0xA1]) // X — high weight, fills the pool
        .plan(2, 2_000_000, &[0x61], &[0xA2]); // Y — low weight, no conflict
    let now = Instant::now();

    mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v);
    let (yo, ya) = mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(
        yo,
        AdmissionOutcome::Rejected {
            reason: RejectReason::PoolFull
        }
    ));
    assert!(mp.contains(&d(1)) && !mp.contains(&d(2)));
    assert_eq!(mp.staging_len(), 1, "underpriced-for-full-pool tx held");
    assert!(broadcasts(&ya).is_empty(), "a held tx is never gossiped");
}

#[test]
fn check_never_stages_held_candidate() {
    // The `/check` path must not stage even a held-eligible rejection.
    let cfg = MempoolConfig {
        max_pool_size: 1,
        ..MempoolConfig::default()
    };
    let mut mp = Mempool::new(cfg, Box::new(ByCost));
    let utxo = FakeUtxo::with(&[0x60, 0x61]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan(1, 5_000_000, &[0x60], &[0xA1])
        .plan(2, 2_000_000, &[0x61], &[0xA2]);
    let now = Instant::now();

    mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v); // fills the pool
    let (co, _) = mp.check(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(
        co,
        CheckOutcome::Rejected {
            reason: RejectReason::PoolFull
        }
    ));
    assert_eq!(
        mp.staging_len(),
        0,
        "/check must never stage a held candidate"
    );
}

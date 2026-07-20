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
use std::sync::Arc;
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
    data_inputs: Vec<Digest32>,
    outputs: Vec<Digest32>,
    output_boxes: Vec<ErgoBox>,
    charge: u64,
    /// If `Some(h)`, the tx only validates at tip height `h` (a stand-in for a
    /// `HEIGHT`-gated script); at any other height it fails `ScriptFailed`.
    valid_at_height: Option<u32>,
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
    /// are materialized so the overlay can resolve a child's input. Fixed
    /// validation cost of 10_000.
    fn plan(self, tx: u8, fee: u64, inputs: &[u8], outputs: &[u8]) -> Self {
        self.plan_cost(tx, fee, 10_000, inputs, outputs)
    }

    /// Like [`plan`] but with an explicit validation `cost`, so tests can
    /// build a low-feerate / high-absolute-fee incumbent (the pinning case).
    fn plan_cost(self, tx: u8, fee: u64, cost: u64, inputs: &[u8], outputs: &[u8]) -> Self {
        self.plan_full(tx, fee, cost, inputs, &[], outputs, None)
    }

    /// Like [`plan`] but with DATA inputs (resolved against the committed view).
    fn plan_data(
        self,
        tx: u8,
        fee: u64,
        inputs: &[u8],
        data_inputs: &[u8],
        outputs: &[u8],
    ) -> Self {
        self.plan_full(tx, fee, 10_000, inputs, data_inputs, outputs, None)
    }

    /// Like [`plan`] but the tx only validates at tip height `height` (a
    /// height-gated script stand-in) — used to prove a stale held parent is
    /// re-validated (and rejected) when the tip moves.
    fn plan_height_gated(
        self,
        tx: u8,
        fee: u64,
        height: u32,
        inputs: &[u8],
        outputs: &[u8],
    ) -> Self {
        self.plan_full(tx, fee, 10_000, inputs, &[], outputs, Some(height))
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_full(
        mut self,
        tx: u8,
        fee: u64,
        cost: u64,
        inputs: &[u8],
        data_inputs: &[u8],
        outputs: &[u8],
        valid_at_height: Option<u32>,
    ) -> Self {
        self.plans.insert(
            tx_bytes(tx),
            ProbePlan {
                tx_id: d(tx),
                fee,
                inputs: inputs.iter().map(|b| d(*b)).collect(),
                data_inputs: data_inputs.iter().map(|b| d(*b)).collect(),
                outputs: outputs.iter().map(|b| d(*b)).collect(),
                output_boxes: outputs.iter().map(|b| dummy_box(*b)).collect(),
                charge: cost,
                valid_at_height,
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
            data_input_box_ids: p.data_inputs.clone(),
            output_box_ids: p.outputs.clone(),
        })
    }
    fn validate(
        &self,
        tx_bytes: &[u8],
        input_view: &dyn UtxoView,
        data_input_view: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr> {
        let p = self.plans.get(tx_bytes).ok_or(ValidationErr::Deserialize)?;
        if let Ok(jc) = JitCost::from_block_cost(p.charge) {
            let _ = cx.cost.add(jc);
        }
        // Real resolution: any regular input absent from the overlay ⇒ orphan.
        for i in &p.inputs {
            if input_view.get_box(i).is_none() {
                return Err(ValidationErr::UnresolvedInput);
            }
        }
        // Data inputs resolve against the committed-only view.
        for di in &p.data_inputs {
            if data_input_view.get_box(di).is_none() {
                return Err(ValidationErr::UnresolvedDataInput);
            }
        }
        // Height-gated script stand-in.
        if let Some(h) = p.valid_at_height {
            if cx.ctx.height != h {
                return Err(ValidationErr::ScriptFailed);
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
    height: u32,
}
impl TestTip {
    fn new() -> Self {
        Self::at_height(1000)
    }
    fn at_height(height: u32) -> Self {
        Self {
            tx_context: tx_context(height),
            params: ProtocolParams::mainnet_default(),
            height,
        }
    }
    fn with_max_block_cost(mut self, c: u64) -> Self {
        self.params.max_block_cost = c;
        self
    }
    fn view<'a>(&'a self, utxo: &'a dyn UtxoView) -> admission::TipContext<'a> {
        admission::TipContext {
            tip: TipPointer {
                height: self.height,
                header_id: d(0xFF),
            },
            best_header_height: self.height,
            best_full_block_height: self.height,
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

// ----- P4: package admission + package RBF (R1 ∧ R2) -----

#[test]
fn package_admitted_when_child_completes_held_parent_threshold() {
    // A 2-slot pool full of L (low) + M (mid). P (low fee) is held on PoolFull.
    // Its child C (high fee) completes the package {P, C}, whose aggregate
    // feerate beats the pool's lowest, so BOTH enter — evicting L and M.
    let cfg = MempoolConfig {
        max_pool_size: 2,
        ..MempoolConfig::default()
    };
    let mut mp = Mempool::new(cfg, Box::new(ByCost));
    let utxo = FakeUtxo::with(&[0x90, 0x91, 0x70]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan(10, 1_000_000, &[0x90], &[0x9A]) // L — low
        .plan(11, 3_000_000, &[0x91], &[0x9B]) // M — mid
        .plan(1, 1_000_000, &[0x70], &[0x71]) // P — held (low fee)
        .plan(2, 10_000_000, &[0x71], &[0x72]); // C — high fee, spends P's output
    let now = Instant::now();

    mp.process(&tx_bytes(10), TxSource::Api, now, &tip.view(&utxo), &v);
    mp.process(&tx_bytes(11), TxSource::Api, now, &tip.view(&utxo), &v);
    assert_eq!(mp.size(), 2, "pool full");

    let (po, _) = mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(
        po,
        AdmissionOutcome::Rejected {
            reason: RejectReason::PoolFull
        }
    ));
    assert_eq!(mp.staging_len(), 1, "parent held");

    let (_co, ca) = mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(
        mp.contains(&d(1)) && mp.contains(&d(2)),
        "P and C admitted together as a package"
    );
    assert!(
        !mp.contains(&d(10)) && !mp.contains(&d(11)),
        "the two lower-priority incumbents were evicted"
    );
    assert_eq!(mp.staging_len(), 0, "held parent drained from staging");
    let inv = broadcasts(&ca);
    assert!(
        inv.contains(&d(1)) && inv.contains(&d(2)),
        "both package members advertised: {inv:?}"
    );
    mp.pool().check_invariants();
}

#[test]
fn package_rbf_accepts_when_r1_and_r2_both_hold() {
    // Incumbent I spends box 0x80 (fee 2M). P also spends 0x80 (fee 1M) and
    // loses the double-spend → held. Child C (fee 5M) spends P's output. The
    // package {P, C} beats I on BOTH aggregate feerate (R1) and aggregate
    // absolute fee (R2), so it displaces I via package RBF.
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[0x80]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan(9, 2_000_000, &[0x80], &[0x8A]) // I — incumbent
        .plan(1, 1_000_000, &[0x80], &[0x81]) // P — double-spend loser, held
        .plan(2, 5_000_000, &[0x81], &[0x8C]); // C — booster child
    let now = Instant::now();

    mp.process(&tx_bytes(9), TxSource::Api, now, &tip.view(&utxo), &v);
    let (po, _) = mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(
        po,
        AdmissionOutcome::Rejected {
            reason: RejectReason::DoubleSpendLoser
        }
    ));

    let (_co, ca) = mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(
        mp.contains(&d(1)) && mp.contains(&d(2)),
        "package displaced the incumbent and entered the pool"
    );
    assert!(!mp.contains(&d(9)), "incumbent evicted by package RBF");
    assert_eq!(mp.staging_len(), 0, "held parent drained");
    // The evicted incumbent is un-advertised; the members are advertised.
    let revoked: Vec<TxId> = ca
        .iter()
        .filter_map(|a| match a {
            MempoolAction::RevokeBroadcast { tx_ids } => Some(tx_ids.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(revoked.contains(&d(9)), "incumbent revoked: {revoked:?}");
    mp.pool().check_invariants();
}

#[test]
fn package_rbf_rejects_pin_higher_feerate_but_lower_absolute_fee() {
    // Anti-pinning: incumbent I has a HIGH absolute fee (10M) but LOW feerate
    // (cost 100_000 → weight 102400). P (fee 1M, cost 10_000 → weight 102400)
    // ties and is held. The package {P, C} (fees 1M + 2M = 3M) has a HIGHER
    // feerate (R1 holds) but a LOWER absolute fee than I (R2 FAILS), so it must
    // NOT displace I — the miner earns more absolute fee keeping the incumbent.
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[0x80]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan_cost(9, 10_000_000, 100_000, &[0x80], &[0x8A]) // I — high abs fee, low feerate
        .plan(1, 1_000_000, &[0x80], &[0x81]) // P — ties I's feerate, loses, held
        .plan(2, 2_000_000, &[0x81], &[0x8C]); // C — booster
    let now = Instant::now();

    mp.process(&tx_bytes(9), TxSource::Api, now, &tip.view(&utxo), &v);
    let (po, _) = mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(matches!(
        po,
        AdmissionOutcome::Rejected {
            reason: RejectReason::DoubleSpendLoser
        }
    ));

    let (_co, ca) = mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(
        mp.contains(&d(9)),
        "incumbent survives — R2 (absolute fee) rejects the pinning package"
    );
    assert!(
        !mp.contains(&d(1)) && !mp.contains(&d(2)),
        "neither package member entered the pool"
    );
    assert!(
        broadcasts(&ca).is_empty(),
        "a rejected package gossips nothing"
    );
    // P stays held; C is now held too (validated, package lost).
    assert_eq!(
        mp.staging_len(),
        2,
        "parent and child both held for a future try"
    );
    mp.pool().check_invariants();
}

// ----- FIX 1 (B1): intra-package double-spend must never be seated -----

#[test]
fn package_rejects_intra_package_double_spend_child_and_parent() {
    // Single-slot pool full of high-weight X. P (underpriced) spends box 0x80
    // and is held. A malicious child C spends BOTH P's output 0x81 AND the same
    // box 0x80 — so the package [P, C] would double-spend 0x80. It must be
    // rejected wholesale, the live pool left untouched, and no double-spend or
    // index corruption seated.
    let cfg = MempoolConfig {
        max_pool_size: 1,
        ..MempoolConfig::default()
    };
    let mut mp = Mempool::new(cfg, Box::new(ByCost));
    let utxo = FakeUtxo::with(&[0x90, 0x80]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan(9, 9_000_000, &[0x90], &[0x9A]) // X — fills the 1-slot pool
        .plan(1, 1_000_000, &[0x80], &[0x81]) // P — underpriced, held
        .plan(2, 10_000_000, &[0x81, 0x80], &[0x82]); // C — spends P.out AND 0x80
    let now = Instant::now();

    mp.process(&tx_bytes(9), TxSource::Api, now, &tip.view(&utxo), &v);
    mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v); // P held
    assert_eq!(mp.staging_len(), 1);

    let (_co, ca) = mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(
        !mp.contains(&d(1)) && !mp.contains(&d(2)),
        "the double-spending package must not be admitted"
    );
    assert!(mp.contains(&d(9)), "the live pool is untouched");
    assert!(
        broadcasts(&ca).is_empty(),
        "a rejected double-spend package gossips nothing"
    );
    mp.pool().check_invariants();
}

#[test]
fn package_rejects_intra_package_double_spend_two_held_parents() {
    // Two held parents P1, P2 BOTH spend box 0x80 (each was held while the pool
    // was full). A child C spends both their outputs, pulling both into one
    // package [P1, P2, C] — a double-spend of 0x80. Must be rejected wholesale.
    let cfg = MempoolConfig {
        max_pool_size: 1,
        ..MempoolConfig::default()
    };
    let mut mp = Mempool::new(cfg, Box::new(ByCost));
    let utxo = FakeUtxo::with(&[0x90, 0x80]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new()
        .plan(9, 9_000_000, &[0x90], &[0x9A]) // X — fills the pool
        .plan(1, 1_000_000, &[0x80], &[0x81]) // P1 — held, spends 0x80
        .plan(2, 1_000_000, &[0x80], &[0x82]) // P2 — held, spends 0x80 too
        .plan(3, 10_000_000, &[0x81, 0x82], &[0x83]); // C — spends both outputs
    let now = Instant::now();

    mp.process(&tx_bytes(9), TxSource::Api, now, &tip.view(&utxo), &v);
    mp.process(&tx_bytes(1), TxSource::Api, now, &tip.view(&utxo), &v); // P1 held
    mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v); // P2 held
    assert_eq!(mp.staging_len(), 2);

    let (_co, ca) = mp.process(&tx_bytes(3), TxSource::Api, now, &tip.view(&utxo), &v);
    assert!(
        !mp.contains(&d(1)) && !mp.contains(&d(2)) && !mp.contains(&d(3)),
        "no member of the double-spending package is admitted"
    );
    assert!(mp.contains(&d(9)), "live pool untouched");
    assert!(broadcasts(&ca).is_empty());
    mp.pool().check_invariants();
}

#[test]
fn pool_insert_rejects_input_collision() {
    // Defense-in-depth: OrderedPool::insert refuses a tx whose input is already
    // spent by a pooled tx, so no path can ever seat a double-spend.
    let mut pool = OrderedPool::with_capacity(4);
    let e1 = Entry::new(
        d(1),
        Arc::from(vec![1u8; 10].into_boxed_slice()),
        vec![d(0x80)],
        vec![d(0x81)],
        vec![],
        1_000_000,
        100,
        10,
        10_000,
        TxSource::Api,
    );
    pool.insert(e1).unwrap();
    let e2 = Entry::new(
        d(2),
        Arc::from(vec![2u8; 10].into_boxed_slice()),
        vec![d(0x80)], // same input as e1
        vec![d(0x82)],
        vec![],
        1_000_000,
        200,
        10,
        10_000,
        TxSource::Api,
    );
    let err = pool.insert(e2).unwrap_err();
    assert!(
        matches!(err, crate::pool::PoolError::InputCollision(_)),
        "second spender of a box must be rejected: {err:?}"
    );
    pool.check_invariants();
}

// ----- FIX 2 (M1): held members re-validated at the current tip -----

#[test]
fn stale_held_parent_revalidated_and_rejected_at_new_tip() {
    // Pool full at height 1000. P is height-gated: valid ONLY at height 1000, so
    // it is held there. The tip then advances to 1001 and child C arrives.
    // Because P's staged_height (1000) != the current tip (1001), try_package
    // RE-VALIDATES P at 1001 — it now fails, is evicted, and the package is
    // aborted. The stale parent must NOT be laundered into the pool on its
    // cached outputs.
    let cfg = MempoolConfig {
        max_pool_size: 1,
        ..MempoolConfig::default()
    };
    let mut mp = Mempool::new(cfg, Box::new(ByCost));
    let utxo = FakeUtxo::with(&[0x90, 0x70]);
    let tip1000 = TestTip::at_height(1000);
    let v = PoolAwareProbe::new()
        .plan(9, 9_000_000, &[0x90], &[0x9A]) // X — fills the pool
        .plan_height_gated(1, 1_000_000, 1000, &[0x70], &[0x71]) // P — valid only @1000
        .plan(2, 10_000_000, &[0x71], &[0x72]); // C — spends P's output
    let now = Instant::now();

    mp.process(&tx_bytes(9), TxSource::Api, now, &tip1000.view(&utxo), &v);
    let (po, _) = mp.process(&tx_bytes(1), TxSource::Api, now, &tip1000.view(&utxo), &v);
    assert!(matches!(
        po,
        AdmissionOutcome::Rejected {
            reason: RejectReason::PoolFull
        }
    ));
    assert_eq!(mp.staging_len(), 1, "P held at height 1000");

    // Tip advances; the child arrives at height 1001.
    let tip1001 = TestTip::at_height(1001);
    let (_co, ca) = mp.process(&tx_bytes(2), TxSource::Api, now, &tip1001.view(&utxo), &v);
    assert!(
        !mp.contains(&d(1)) && !mp.contains(&d(2)),
        "stale height-gated parent not laundered; child not admitted"
    );
    assert!(mp.contains(&d(9)), "live pool untouched");
    assert!(broadcasts(&ca).is_empty(), "nothing gossiped");
    assert_eq!(
        mp.staging_len(),
        0,
        "the stale held parent is evicted from staging on failed re-validation"
    );
    mp.pool().check_invariants();
}

#[test]
fn block_advance_prunes_orphan_with_spent_data_input() {
    // An orphan (regular input 0xAA missing) that also READS data-input box
    // 0xDD. When a block confirms a tx consuming 0xDD, the orphan can never be
    // admitted, so block-advance pruning drops it (data inputs are pruned, not
    // just regular inputs).
    let mut mp = mempool();
    let utxo = FakeUtxo::with(&[]);
    let tip = TestTip::new();
    let v = PoolAwareProbe::new().plan_data(2, 5_000_000, &[0xAA], &[0xDD], &[0xBB]);
    let now = Instant::now();
    mp.process(&tx_bytes(2), TxSource::Api, now, &tip.view(&utxo), &v);
    assert_eq!(
        mp.staging_len(),
        1,
        "orphan staged with its data input tracked"
    );

    let diff = diff_at(1001, vec![(0x99, vec![0xDD])]); // block spends 0xDD
    mp.on_tip_change(&diff);
    assert_eq!(
        mp.staging_len(),
        0,
        "orphan whose DATA input was confirmed-and-consumed is pruned"
    );
}

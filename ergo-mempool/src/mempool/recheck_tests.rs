//! Unit tests for `Mempool::recheck_and_evict` (proactive tip-revalidation).
//!
//! These pin the Scala `CleanupWorker`/`MempoolAuditor` *end-result*
//! (the pool ends each block holding only currently-valid txs; invalid
//! ones are evicted and stop being relayed), reached via the Rust full
//! pass — a policy surface, so expected behavior is derived from the
//! recheck semantics, not from mainnet bytes.

use super::*;
use crate::admission::{MockPlan, MockValidator, PeekedTx, Validated, ValidationErr};
use crate::pool::Entry;
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
use std::time::{Duration, Instant};

// ----- helpers -----

/// Committed UTXO view backed by an explicit box map (empty by default).
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

fn d(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

/// Canonical bytes for the seeded tx `b`. A `MockValidator` plan keyed
/// on this exact slice matches the entry during the recheck.
fn tx_bytes(b: u8) -> Vec<u8> {
    vec![b; 20]
}

/// Minimal ErgoBox (contents immaterial — only identity matters here).
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

fn dummy_tx_context(height: u32) -> TransactionContext {
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

/// Owns the tip-context backing storage so a borrowed `TipContext` can
/// be re-derived per call (mirrors the node's `OwnedTipContext`).
struct TestTip {
    tx_context: TransactionContext,
    params: ProtocolParams,
}
impl TestTip {
    fn new() -> Self {
        Self::at_height(1000)
    }
    /// Tip context whose validation height (tip+1) is `height` — lets a
    /// test model a height-dependent tx going stale as the tip advances.
    fn at_height(height: u32) -> Self {
        Self {
            tx_context: dummy_tx_context(height),
            params: ProtocolParams::mainnet_default(),
        }
    }
    /// Override the per-pass cap denominator (`mult × max_block_cost`).
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

fn mempool_with(cfg: MempoolConfig) -> Mempool {
    Mempool::new(cfg, Box::new(ByCost))
}

/// Seed a standalone pool entry whose canonical bytes are `tx_bytes(b)`.
fn seed(mp: &mut Mempool, b: u8, input: u8, output: u8, weight: u64, parents: Vec<TxId>) {
    let entry = Entry::new(
        d(b),
        Arc::from(tx_bytes(b).into_boxed_slice()),
        vec![d(input)],
        vec![d(output)],
        parents,
        1_000_000,
        weight,
        20,
        50_000,
        TxSource::Api,
    );
    mp.pool_mut().insert(entry).unwrap();
}

/// Force a deterministic `last_checked_at` on a seeded entry so the
/// oldest-first visit order is reproducible (the real method injects
/// `now`; tests inject the seed instants).
fn set_checked(mp: &mut Mempool, b: u8, at: Instant) {
    mp.pool_mut().touch_rechecked(&d(b), at);
}

fn ok_plan(b: u8, charge: u64) -> (Vec<u8>, MockPlan) {
    (
        tx_bytes(b),
        MockPlan {
            result: Ok(Validated {
                tx_id: d(b),
                input_box_ids: vec![],
                output_box_ids: vec![],
                outputs: vec![],
                fee: 1_000_000,
                size_bytes: 20,
                consumed_cost: charge,
            }),
            charge,
            peek_fee: None,
            peek_tx_id: None,
        },
    )
}

fn err_plan(b: u8, charge: u64) -> (Vec<u8>, MockPlan) {
    (
        tx_bytes(b),
        MockPlan {
            result: Err(ValidationErr::ScriptFailed),
            charge,
            peek_fee: None,
            peek_tx_id: None,
        },
    )
}

fn validator(plans: Vec<(Vec<u8>, MockPlan)>) -> MockValidator {
    let mut v = MockValidator::new();
    for (bytes, plan) in plans {
        v = v.plan(bytes, plan);
    }
    v
}

/// True if any action is an eviction signal (`RevokeBroadcast` or an
/// `Evicted` observe). The full recheck pass also emits `BroadcastInv`
/// re-broadcasts for survivors, so "no eviction happened" can no longer be
/// expressed as "no actions at all".
fn no_evictions(actions: &[MempoolAction]) -> bool {
    !actions.iter().any(|a| {
        matches!(
            a,
            MempoolAction::RevokeBroadcast { .. }
                | MempoolAction::Observe {
                    event: ObservedEvent::Evicted { .. },
                }
        )
    })
}

fn evicted_ids(actions: &[MempoolAction]) -> Vec<TxId> {
    actions
        .iter()
        .find_map(|a| match a {
            MempoolAction::Observe {
                event:
                    ObservedEvent::Evicted {
                        tx_ids,
                        reason: EvictionReason::TipInvalid,
                    },
            } => Some(tx_ids.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

// ----- happy path: still-valid txs are kept -----

#[test]
fn recheck_keeps_still_valid_tx_and_refreshes_last_checked() {
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]); // seeded cost=50_000, weight=100
    let base = Instant::now();
    set_checked(&mut mp, 1, base);

    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    // Deliberately charge a DIFFERENT cost than the seeded 50_000 to prove
    // the recheck does not re-price the surviving entry.
    let v = validator(vec![ok_plan(1, 77_000)]);

    let now = base + Duration::from_secs(10);
    let actions = mp.recheck_and_evict(now, &tip.view(&utxo), &v);

    assert!(mp.contains(&d(1)), "valid tx must survive the recheck");
    assert!(
        no_evictions(&actions),
        "no eviction actions for an all-valid pool"
    );
    // The lone survivor is re-broadcast (default rebroadcast_count = 3).
    assert_eq!(broadcast_ids(&actions), vec![d(1)]);
    assert!(
        !mp.is_invalidated(&d(1)),
        "valid tx must not be blacklisted"
    );
    let e = mp.pool().get(&d(1)).unwrap();
    assert_eq!(
        e.last_checked_at, now,
        "surviving tx has its last_checked_at refreshed to the pass clock"
    );
    assert_eq!(
        e.cost, 50_000,
        "recheck must NOT re-price cost (would desync the ByCost weight key)"
    );
    assert_eq!(
        e.weight, 100,
        "priority weight unchanged by a validity check"
    );
    mp.pool().check_invariants();
}

#[test]
fn recheck_small_pool_full_pass_visits_every_tx() {
    // A pool well under the cost cap is rechecked completely in one pass.
    let mut mp = mempool_with(MempoolConfig::default());
    for b in 1..=4u8 {
        seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
    }
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator((1..=4u8).map(|b| ok_plan(b, 10_000)).collect());

    let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

    assert_eq!(v.validate_call_count(), 4, "every tx visited in one pass");
    assert_eq!(mp.size(), 4, "all valid txs retained");
    assert!(no_evictions(&actions), "all valid: nothing evicted");
    // 4 survivors > rebroadcast_count(3) -> exactly 3 re-broadcast.
    assert_eq!(broadcast_ids(&actions).len(), 3);
    mp.pool().check_invariants();
}

#[test]
fn recheck_empty_pool_is_noop() {
    let mut mp = mempool_with(MempoolConfig::default());
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator(vec![]);
    let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);
    assert!(actions.is_empty());
    assert_eq!(v.validate_call_count(), 0, "no validation on an empty pool");
}

// ----- error paths: tip-invalid txs are evicted -----

#[test]
fn recheck_evicts_stale_rent_recreate_claim_and_blacklists() {
    // A storage-rent recreate claim is valid ONLY at the block whose height
    // equals the box's creation height (creationHeight == currentHeight).
    // Model that height-dependence directly with a validator that passes
    // only when the validating height matches: the claim was valid at
    // H=999, but the tip has advanced so the recheck (validating at the
    // tip+1 height = 1000) sees it as invalid and must evict + blacklist it.
    const CLAIM_HEIGHT: u32 = 999;

    // Negative: tip advanced past the creation height -> evicted + blacklisted.
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    let utxo = FakeUtxo::empty();
    let advanced_tip = TestTip::at_height(1000);
    let v = HeightGatedValidator {
        valid_at: CLAIM_HEIGHT,
        charge: 30_000,
    };
    let actions = mp.recheck_and_evict(Instant::now(), &advanced_tip.view(&utxo), &v);
    assert!(
        !mp.contains(&d(1)),
        "stale recreate claim evicted once the tip advanced past its creation height"
    );
    assert!(
        mp.is_invalidated(&d(1)),
        "evicted claim blacklisted so it is not re-relayed"
    );
    assert_eq!(evicted_ids(&actions), vec![d(1)]);
    mp.pool().check_invariants();

    // Positive control: validating AT the claim's creation height -> the
    // very same claim is still valid and survives. This is what makes the
    // negative case a height-transition test, not a generic failure.
    let mut mp_ok = mempool_with(MempoolConfig::default());
    seed(&mut mp_ok, 1, 0x10, 0x11, 100, vec![]);
    let utxo_ok = FakeUtxo::empty();
    let at_claim = TestTip::at_height(CLAIM_HEIGHT);
    let v_ok = HeightGatedValidator {
        valid_at: CLAIM_HEIGHT,
        charge: 30_000,
    };
    let actions_ok = mp_ok.recheck_and_evict(Instant::now(), &at_claim.view(&utxo_ok), &v_ok);
    assert!(
        mp_ok.contains(&d(1)),
        "claim valid at its own creation height survives the recheck"
    );
    assert!(no_evictions(&actions_ok), "survivor: nothing evicted");
    assert_eq!(
        broadcast_ids(&actions_ok),
        vec![d(1)],
        "survivor re-broadcast"
    );
    assert!(!mp_ok.is_invalidated(&d(1)));
}

#[test]
fn recheck_evicts_generic_tip_invalid_tx() {
    // Same eviction for a non-rent tx — proves the pass is general,
    // not rent-specific.
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 9, 0x10, 0x11, 100, vec![]);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator(vec![err_plan(9, 20_000)]);

    let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

    assert!(!mp.contains(&d(9)));
    assert!(mp.is_invalidated(&d(9)));
    assert_eq!(evicted_ids(&actions), vec![d(9)]);
    mp.pool().check_invariants();
}

#[test]
fn recheck_eviction_emits_revoke_before_evicted_event() {
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator(vec![err_plan(1, 10_000)]);

    let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

    let revoke_pos = actions.iter().position(
        |a| matches!(a, MempoolAction::RevokeBroadcast { tx_ids } if tx_ids.contains(&d(1))),
    );
    let evicted_pos = actions.iter().position(|a| {
        matches!(
            a,
            MempoolAction::Observe {
                event: ObservedEvent::Evicted {
                    reason: EvictionReason::TipInvalid,
                    ..
                }
            }
        )
    });
    assert!(
        matches!((revoke_pos, evicted_pos), (Some(r), Some(e)) if r < e),
        "RevokeBroadcast must precede Observe(Evicted::TipInvalid); \
         got revoke={revoke_pos:?} evicted={evicted_pos:?}"
    );
}

#[test]
fn recheck_eviction_debits_ancestor_family_weight() {
    // P (weight carries a child boost) <- C. Evicting C must de-propagate
    // its weight from the surviving ancestor P (family-weight debiting).
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 900, vec![]); // P (boosted)
    seed(&mut mp, 2, 0x11, 0x22, 100, vec![d(1)]); // C spends P's output 0x11
                                                   // Visit P first (valid), then C (invalid → evicted, debits P).
    let base = Instant::now();
    set_checked(&mut mp, 1, base);
    set_checked(&mut mp, 2, base + Duration::from_millis(1));

    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator(vec![ok_plan(1, 10_000), err_plan(2, 10_000)]);

    mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

    assert!(mp.contains(&d(1)), "ancestor survives");
    assert!(!mp.contains(&d(2)), "tip-invalid child evicted");
    assert_eq!(
        mp.pool().get(&d(1)).unwrap().weight,
        800,
        "surviving ancestor debited by the evicted child's weight (900 - 100)"
    );
    mp.pool().check_invariants();
}

#[test]
fn recheck_cascade_descendant_not_blacklisted() {
    // Evicting a tip-invalid parent cascades to its descendant, but only
    // the parent's id enters the invalidation cache — the descendant is
    // dependency-evicted and remains re-admittable if later valid.
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 200, vec![]); // parent (tip-invalid)
    seed(&mut mp, 2, 0x11, 0x22, 100, vec![d(1)]); // child of parent
    let base = Instant::now();
    set_checked(&mut mp, 1, base);
    set_checked(&mut mp, 2, base + Duration::from_millis(1));

    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    // Only the parent has an Err plan; the child is never validated
    // (it is cascade-removed before its turn).
    let v = validator(vec![err_plan(1, 10_000), ok_plan(2, 10_000)]);

    let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

    assert!(!mp.contains(&d(1)) && !mp.contains(&d(2)), "both removed");
    assert!(mp.is_invalidated(&d(1)), "failed parent is blacklisted");
    assert!(
        !mp.is_invalidated(&d(2)),
        "cascade descendant must NOT be blacklisted"
    );
    assert_eq!(v.validate_call_count(), 1, "child not separately validated");
    let mut evicted = evicted_ids(&actions);
    evicted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(evicted, vec![d(1), d(2)], "both ids reported in the action");
    mp.pool().check_invariants();
}

#[test]
fn recheck_hard_invalid_cascade_evicts_full_subtree_past_depth_cap() {
    // Chain 1→2→3→4→5 with max_family_depth = 2. tx 1 is hard-invalid; the
    // single-op cascade only removes cap-many ({1,2}), but the truncation
    // frontier is carried into a bounded follow-up drain the SAME pass, so the
    // ENTIRE invalid subtree is evicted. Descendants carry `ok_plan`s (a real
    // validator would report UnresolvedInput once their ancestor is gone, which
    // the recheck policy RETAINS) — the point is they are removed structurally
    // as dependents of the hard-invalid root, not on their own verdict. Before
    // the frontier fix, {3,4,5} lingered in the pool.
    let cfg = MempoolConfig {
        max_family_depth: 2,
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    let base = Instant::now();
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    seed(&mut mp, 2, 0x11, 0x12, 100, vec![d(1)]);
    seed(&mut mp, 3, 0x12, 0x13, 100, vec![d(2)]);
    seed(&mut mp, 4, 0x13, 0x14, 100, vec![d(3)]);
    seed(&mut mp, 5, 0x14, 0x15, 100, vec![d(4)]);
    for b in 1..=5u8 {
        set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
    }

    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let mut plans = vec![err_plan(1, 10_000)];
    for b in 2..=5u8 {
        plans.push(ok_plan(b, 10_000));
    }
    let v = validator(plans);

    let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

    for b in 1..=5u8 {
        assert!(
            !mp.contains(&d(b)),
            "tx {b} must be evicted (full invalid subtree)"
        );
    }
    assert!(
        mp.is_invalidated(&d(1)),
        "only the hard-invalid root is blacklisted"
    );
    for b in 2..=5u8 {
        assert!(
            !mp.is_invalidated(&d(b)),
            "descendant {b} is dependency-evicted, not blacklisted"
        );
    }
    assert_eq!(
        evicted_ids(&actions).len(),
        5,
        "all five ids reported evicted"
    );
    mp.pool().check_invariants();
}

// ----- anti-DoS cost cap + rotation -----

#[test]
fn recheck_cost_cap_caps_one_pass_and_defers_the_rest() {
    // cap = mult(1) × max_block_cost(100_000) = 100_000; each tx charges
    // 60_000, so the second visit pushes the accumulator to 120_000 and
    // the third tx is deferred.
    let cfg = MempoolConfig {
        mempool_cleanup_cost_mult: 1,
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    let base = Instant::now();
    for b in 1..=5u8 {
        seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
        set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
    }
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new().with_max_block_cost(100_000);
    let v = validator((1..=5u8).map(|b| ok_plan(b, 60_000)).collect());

    mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

    assert_eq!(
        v.validate_call_count(),
        2,
        "cost cap binds the pass to two txs"
    );
    // The two oldest (d(1), d(2)) were visited; the rest were deferred.
    let now = base + Duration::from_secs(10);
    assert_eq!(mp.pool().get(&d(1)).unwrap().last_checked_at, now);
    assert_eq!(mp.pool().get(&d(2)).unwrap().last_checked_at, now);
    for b in 3..=5u8 {
        assert_eq!(
            mp.pool().get(&d(b)).unwrap().last_checked_at,
            base + Duration::from_millis(u64::from(b)),
            "deferred tx d({b}) untouched this pass"
        );
    }
}

#[test]
fn recheck_failing_txs_consume_budget_and_defer_rest() {
    // Even failing txs charge their actual consumed cost, so the cap
    // cannot be over-run by an all-invalid pool.
    let cfg = MempoolConfig {
        mempool_cleanup_cost_mult: 1,
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    let base = Instant::now();
    for b in 1..=5u8 {
        seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
        set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
    }
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new().with_max_block_cost(100_000);
    let v = validator((1..=5u8).map(|b| err_plan(b, 60_000)).collect());

    let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

    assert_eq!(v.validate_call_count(), 2, "cap binds even for failing txs");
    assert_eq!(mp.size(), 3, "only the two budgeted txs were evicted");
    let mut evicted = evicted_ids(&actions);
    evicted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(evicted, vec![d(1), d(2)]);
    mp.pool().check_invariants();
}

#[test]
fn recheck_eventual_coverage_deterministic_order_no_starvation() {
    // A pool exceeding the per-pass cap is fully covered across passes,
    // visited in (last_checked_at, tx_id) order; a tip-invalid tx that
    // is not the oldest is still reached and evicted within a bounded
    // number of passes (not starved).
    let cfg = MempoolConfig {
        mempool_cleanup_cost_mult: 1,
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    let base = Instant::now();
    for b in 1..=5u8 {
        seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
        set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
    }
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new().with_max_block_cost(100_000);
    // d(3) is tip-invalid; the rest are valid. Cap allows two per pass.
    let v = validator(
        (1..=5u8)
            .map(|b| {
                if b == 3 {
                    err_plan(b, 60_000)
                } else {
                    ok_plan(b, 60_000)
                }
            })
            .collect(),
    );

    // Pass 1 visits the two oldest, d(1) and d(2).
    let now1 = base + Duration::from_secs(10);
    mp.recheck_and_evict(now1, &tip.view(&utxo), &v);
    assert_eq!(v.validate_call_count(), 2);
    assert!(mp.contains(&d(3)), "tip-invalid tx not yet reached");
    assert_eq!(mp.pool().get(&d(1)).unwrap().last_checked_at, now1);
    assert_eq!(mp.pool().get(&d(2)).unwrap().last_checked_at, now1);

    // Pass 2 visits the next-oldest pair d(3), d(4); d(3) is evicted.
    let now2 = now1 + Duration::from_secs(10);
    mp.recheck_and_evict(now2, &tip.view(&utxo), &v);
    assert!(
        !mp.contains(&d(3)),
        "tip-invalid tx evicted on a later pass"
    );
    assert!(mp.is_invalidated(&d(3)));
    assert_eq!(mp.pool().get(&d(4)).unwrap().last_checked_at, now2);

    // Pass 3 reaches the remaining least-recently-checked txs.
    let now3 = now2 + Duration::from_secs(10);
    mp.recheck_and_evict(now3, &tip.view(&utxo), &v);
    // Every surviving tx has now been visited at least once.
    for b in [1u8, 2, 4, 5] {
        assert!(
            mp.pool().get(&d(b)).unwrap().last_checked_at >= now1,
            "tx d({b}) covered within the bounded pass count"
        );
    }
    mp.pool().check_invariants();
}

// ----- re-broadcast of surviving unconfirmed txs (MempoolAuditor parity) -----

/// `BroadcastInv` tx ids in emission order, for re-broadcast assertions.
fn broadcast_ids(actions: &[MempoolAction]) -> Vec<TxId> {
    actions
        .iter()
        .filter_map(|a| match a {
            MempoolAction::BroadcastInv {
                tx_id,
                except: None,
            } => Some(*tx_id),
            _ => None,
        })
        .collect()
}

#[test]
fn recheck_rebroadcasts_up_to_count_survivors() {
    // Pool of 5 valid txs > rebroadcast_count(3); all survive a full pass,
    // so exactly min(3, 5) = 3 BroadcastInv actions are emitted, each for a
    // still-pooled survivor id, with except: None (fan-out to all peers).
    let cfg = MempoolConfig {
        rebroadcast_count: 3,
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    let base = Instant::now();
    for b in 1..=5u8 {
        seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
        set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
    }
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator((1..=5u8).map(|b| ok_plan(b, 10_000)).collect());

    let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

    let bcast = broadcast_ids(&actions);
    assert_eq!(bcast.len(), 3, "exactly min(rebroadcast_count, survivors)");
    for id in &bcast {
        assert!(
            mp.contains(id),
            "re-broadcast id must be a still-pooled survivor"
        );
    }
    // Oldest-first rotation: the three least-recently-checked are chosen.
    assert_eq!(bcast, vec![d(1), d(2), d(3)]);
    mp.pool().check_invariants();
}

#[test]
fn recheck_does_not_rebroadcast_evicted() {
    // d(3) is tip-invalid (evicted); the surviving valid txs are re-broadcast
    // but the evicted one is NOT — it is revoked instead.
    let cfg = MempoolConfig {
        rebroadcast_count: 3,
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    let base = Instant::now();
    for b in 1..=5u8 {
        seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
        set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
    }
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator(
        (1..=5u8)
            .map(|b| {
                if b == 3 {
                    err_plan(b, 10_000)
                } else {
                    ok_plan(b, 10_000)
                }
            })
            .collect(),
    );

    let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

    let bcast = broadcast_ids(&actions);
    assert!(
        !bcast.contains(&d(3)),
        "evicted tx must not be re-broadcast"
    );
    assert!(
        !mp.contains(&d(3)),
        "the tip-invalid tx was evicted from the pool"
    );
    // d(3) appears in the RevokeBroadcast (eviction) set instead.
    let revoked: Vec<TxId> = actions
        .iter()
        .find_map(|a| match a {
            MempoolAction::RevokeBroadcast { tx_ids } => Some(tx_ids.clone()),
            _ => None,
        })
        .unwrap_or_default();
    assert!(revoked.contains(&d(3)), "evicted tx is revoked");
    // Only survivors are re-broadcast: oldest-first d(1), d(2), then d(4)
    // (d(3) skipped as evicted), capped at rebroadcast_count = 3.
    assert_eq!(bcast, vec![d(1), d(2), d(4)]);
    for id in &bcast {
        assert!(mp.contains(id), "re-broadcast id is a survivor");
    }
    mp.pool().check_invariants();
}

#[test]
fn rebroadcast_count_zero_disables() {
    let cfg = MempoolConfig {
        rebroadcast_count: 0,
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    let base = Instant::now();
    for b in 1..=3u8 {
        seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
        set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
    }
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator((1..=3u8).map(|b| ok_plan(b, 10_000)).collect());

    let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

    assert!(
        broadcast_ids(&actions).is_empty(),
        "rebroadcast_count = 0 disables re-broadcast"
    );
    mp.pool().check_invariants();
}

#[test]
fn rebroadcast_rotates_by_last_checked_at() {
    // Selection is the oldest-`last_checked_at`-first rotation the recheck
    // pass already computes, so consecutive passes cover different survivors.
    // A per-pass cost cap (mult 1 × max_block_cost 100_000, each tx charging
    // 60_000) recks exactly two txs per pass; only the rechecked survivors
    // have their clocks refreshed, so the un-rechecked tail stays "oldest"
    // and rotates to the front on the next pass.
    let cfg = MempoolConfig {
        rebroadcast_count: 2,
        mempool_cleanup_cost_mult: 1,
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    let base = Instant::now();
    for b in 1..=4u8 {
        seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
        set_checked(&mut mp, b, base + Duration::from_millis(u64::from(b)));
    }
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new().with_max_block_cost(100_000);
    let v = validator((1..=4u8).map(|b| ok_plan(b, 60_000)).collect());

    // Pass 1: the two oldest survivors d(1), d(2) are rechecked (cap binds at
    // two) and re-broadcast, with last_checked_at refreshed to now1.
    let now1 = base + Duration::from_secs(10);
    let a1 = mp.recheck_and_evict(now1, &tip.view(&utxo), &v);
    assert_eq!(broadcast_ids(&a1), vec![d(1), d(2)]);

    // Pass 2: d(1)/d(2) are now the most-recently-checked; d(3), d(4) are
    // still on their older seed clocks, so they rotate to the front, get
    // rechecked, and are re-broadcast instead — different survivors covered.
    let now2 = now1 + Duration::from_secs(10);
    let a2 = mp.recheck_and_evict(now2, &tip.view(&utxo), &v);
    assert_eq!(broadcast_ids(&a2), vec![d(3), d(4)]);
    mp.pool().check_invariants();
}

// ----- view-content recording probe (overlay / pruning pins) -----

/// Validator that, for the `probe_tx`, RECORDS whether `box_id` resolves in
/// the regular input view and in the data-input view it was handed, then
/// passes. An optional `hard_fail_tx` returns `ScriptFailed` so a test can
/// evict that tx first and observe the downstream (pruned) overlay. This
/// observes the exact views the recheck feeds the validator, without relying
/// on the eviction policy.
struct ViewRecordingProbe {
    hard_fail_tx: Option<Vec<u8>>,
    probe_tx: Vec<u8>,
    box_id: Digest32,
    saw_input: std::cell::Cell<Option<bool>>,
    saw_data: std::cell::Cell<Option<bool>>,
}
impl ViewRecordingProbe {
    fn new(probe_tx: Vec<u8>, box_id: Digest32, hard_fail_tx: Option<Vec<u8>>) -> Self {
        Self {
            hard_fail_tx,
            probe_tx,
            box_id,
            saw_input: std::cell::Cell::new(None),
            saw_data: std::cell::Cell::new(None),
        }
    }
}
impl Validator for ViewRecordingProbe {
    fn peek_fee(&self, _: &[u8]) -> Result<PeekedTx, ValidationErr> {
        Err(ValidationErr::Deserialize)
    }
    fn validate(
        &self,
        tx_bytes: &[u8],
        input_view: &dyn UtxoView,
        data_input_view: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr> {
        if let Ok(jc) = JitCost::from_block_cost(10_000) {
            let _ = cx.cost.add(jc);
        }
        if self.hard_fail_tx.as_deref() == Some(tx_bytes) {
            return Err(ValidationErr::ScriptFailed);
        }
        if tx_bytes == self.probe_tx.as_slice() {
            self.saw_input
                .set(Some(input_view.get_box(&self.box_id).is_some()));
            self.saw_data
                .set(Some(data_input_view.get_box(&self.box_id).is_some()));
        }
        Ok(Validated {
            tx_id: Digest32::from_bytes(tx_bytes.first().map(|b| [*b; 32]).unwrap_or([0u8; 32])),
            input_box_ids: vec![],
            output_box_ids: vec![],
            outputs: vec![],
            fee: 1_000_000,
            size_bytes: 20,
            consumed_cost: 10_000,
        })
    }
}

#[test]
fn recheck_data_input_uses_committed_only_view() {
    // [R1-6] P creates box 0xCC into the pool overlay; Q is rechecked. The
    // recheck feeds REGULAR inputs the PoolUtxoOverlay (which carries 0xCC)
    // but DATA inputs the CommittedOnly view (which does NOT) — admission
    // parity. Observe both views directly: the same box is visible to Q's
    // regular-input view and invisible to its data-input view.
    let mut mp = mempool_with(MempoolConfig::default());
    let p = Entry::new(
        d(1),
        Arc::from(tx_bytes(1).into_boxed_slice()),
        vec![d(0x10)],
        vec![d(0xCC)],
        vec![],
        1_000_000,
        100,
        20,
        50_000,
        TxSource::Api,
    )
    .with_output_boxes(vec![dummy_box(0xCC)]);
    mp.pool_mut().insert(p).unwrap();
    seed(&mut mp, 2, 0x20, 0x21, 100, vec![]); // Q

    // Sanity: 0xCC IS in the pool overlay (committed view is empty).
    assert!(
        mp.pool().output_map().contains_key(&d(0xCC)),
        "precondition: pool overlay carries the box"
    );

    let tip = TestTip::new();
    let empty = FakeUtxo::empty();
    let probe = ViewRecordingProbe::new(tx_bytes(2), d(0xCC), None);
    let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&empty), &probe);

    assert_eq!(
        probe.saw_input.get(),
        Some(true),
        "regular inputs see the pool overlay (0xCC present)"
    );
    assert_eq!(
        probe.saw_data.get(),
        Some(false),
        "data inputs use the committed-only view (pool-created 0xCC invisible)"
    );
    assert!(no_evictions(&actions), "both txs valid, nothing evicted");
    assert!(mp.contains(&d(1)) && mp.contains(&d(2)));

    // Contrapositive: when 0xCC is a COMMITTED box, the data-input view DOES
    // resolve it — the committed-only view isn't blind, it just excludes the
    // pool overlay.
    let mut mp2 = mempool_with(MempoolConfig::default());
    seed(&mut mp2, 2, 0x20, 0x21, 100, vec![]);
    let committed = FakeUtxo::empty().with_box(d(0xCC), dummy_box(0xCC));
    let probe2 = ViewRecordingProbe::new(tx_bytes(2), d(0xCC), None);
    mp2.recheck_and_evict(Instant::now(), &tip.view(&committed), &probe2);
    assert_eq!(
        probe2.saw_data.get(),
        Some(true),
        "data inputs resolve COMMITTED boxes (committed-only view is not pool-blind)"
    );
}

// ----- failure classification (shared with admission) -----

/// Validator that fails every tx with a fixed `ValidationErr` (charging a
/// fixed cost), so a test can pin how each error class is cached.
struct AlwaysErr {
    err: ValidationErr,
}
impl Validator for AlwaysErr {
    fn peek_fee(&self, _: &[u8]) -> Result<PeekedTx, ValidationErr> {
        Err(ValidationErr::Deserialize)
    }
    fn validate(
        &self,
        _tx_bytes: &[u8],
        _input_view: &dyn UtxoView,
        _data_input_view: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr> {
        if let Ok(jc) = JitCost::from_block_cost(10_000) {
            let _ = cx.cost.add(jc);
        }
        Err(self.err.clone())
    }
}

#[test]
fn recheck_unresolved_input_left_in_pool_not_evicted() {
    // An UnresolvedInput failure at recheck is NOT proof of invalidity: the
    // input may be a transient reorg-dependency (a demoted parent pending
    // re-admission). The tx must be LEFT in the pool — not evicted, not
    // cached — so it is not dropped before its parent returns; only its
    // rotation clock advances. (A genuine confirmed double-spend is handled
    // by on_tip_change's input-conflict cascade, not here.)
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    let base = Instant::now();
    set_checked(&mut mp, 1, base);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = AlwaysErr {
        err: ValidationErr::UnresolvedInput,
    };

    let now = base + Duration::from_secs(10);
    let actions = mp.recheck_and_evict(now, &tip.view(&utxo), &v);

    assert!(
        mp.contains(&d(1)),
        "unresolved-input tx must be kept (could be a reorg-dependency)"
    );
    assert!(!mp.is_invalidated(&d(1)), "kept tx must not be blacklisted");
    assert!(actions.is_empty(), "no eviction action for a kept tx");
    assert_eq!(
        mp.pool().get(&d(1)).unwrap().last_checked_at,
        now,
        "rotation clock advances even when the tx is kept"
    );
    mp.pool().check_invariants();
}

#[test]
fn recheck_other_failure_left_in_pool_not_evicted() {
    // ValidationErr::Other(_) is the validator's catch-all for INTERNAL /
    // contract failures (resolved-inputs mismatch, internal-invariant
    // violation — see validator.rs map_validation_error), NOT a provable
    // consensus invalidity. The recheck must treat it like a non-resolution
    // failure: LEAVE the tx in the pool (not evicted, not blacklisted), only
    // advancing the rotation clock — matching the positive `is_hard_invalid`
    // allowlist {Structural, ScriptFailed, MonetaryFailed, CostExceeded}.
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    let base = Instant::now();
    set_checked(&mut mp, 1, base);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = AlwaysErr {
        err: ValidationErr::Other("validator catch-all".into()),
    };

    let now = base + Duration::from_secs(10);
    let actions = mp.recheck_and_evict(now, &tip.view(&utxo), &v);

    assert!(
        mp.contains(&d(1)),
        "Other(_) failure must keep the tx (not a provable invalidity)"
    );
    assert!(
        !mp.is_invalidated(&d(1)),
        "kept tx must NOT be blacklisted on an Other(_) failure"
    );
    assert!(
        actions.is_empty(),
        "no eviction/revoke action for an Other(_)-kept tx"
    );
    assert_eq!(
        mp.pool().get(&d(1)).unwrap().last_checked_at,
        now,
        "rotation clock advances even when the Other(_) tx is kept"
    );
    mp.pool().check_invariants();
}

#[test]
fn recheck_hard_invalid_evicts_and_blacklists() {
    // A hard-invalid failure (script/monetary/...) is evicted AND
    // blacklisted so the Inv path stops re-fetching it.
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = AlwaysErr {
        err: ValidationErr::MonetaryFailed,
    };

    mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

    assert!(!mp.contains(&d(1)));
    assert!(
        mp.is_invalidated(&d(1)),
        "hard-invalid tx must be blacklisted"
    );
    mp.pool().check_invariants();
}

#[test]
fn recheck_misconfigured_max_tx_cost_skips_pass_without_evicting() {
    // If `max_tx_cost` is set above the JitCost bound, the per-tx cap
    // cannot be built and every revalidation would return CostExceeded
    // with zero consumed cost — which, unguarded, would evict + blacklist
    // the WHOLE pool on a zero budget. The pass must instead refuse to run.
    let cfg = MempoolConfig {
        max_tx_cost: 1_000_000_000, // > JitCost bound (i32::MAX / 10)
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    // Even a would-fail validator must not get the chance to evict.
    let v = AlwaysErr {
        err: ValidationErr::ScriptFailed,
    };

    let actions = mp.recheck_and_evict(Instant::now(), &tip.view(&utxo), &v);

    // The would-fail validator never gets to evict: no actions, the tx is
    // retained, and it is not blacklisted — the guard short-circuited the
    // whole pass before any revalidation.
    assert!(actions.is_empty(), "misconfigured pass emits no actions");
    assert!(mp.contains(&d(1)), "no eviction on a misconfigured cap");
    assert!(!mp.is_invalidated(&d(1)), "no blacklisting on a misconfig");
}

// ----- overlay pruning across evictions in one pass -----

#[test]
fn recheck_prunes_overlay_when_a_producing_tx_is_evicted() {
    // P creates box 0xCC into the pool overlay. C spends 0xCC as a REGULAR
    // input but is intentionally NOT recorded as P's child (parents=[]), so
    // P's eviction does not cascade to it; C is rechecked on its own. After
    // P is evicted (hard-invalid) the pass overlay is pruned, so when C is
    // rechecked next 0xCC is no longer visible to its input view — proving
    // the once-per-pass overlay is pruned in lockstep with evictions.
    let mut mp = mempool_with(MempoolConfig::default());
    let p = Entry::new(
        d(1),
        Arc::from(tx_bytes(1).into_boxed_slice()),
        vec![d(0x10)],
        vec![d(0xCC)],
        vec![],
        1_000_000,
        100,
        20,
        50_000,
        TxSource::Api,
    )
    .with_output_boxes(vec![dummy_box(0xCC)]);
    mp.pool_mut().insert(p).unwrap();
    // C spends 0xCC but declares no in-pool parent, so it is not a cascade
    // descendant of P — it is rechecked independently, after P.
    let c = Entry::new(
        d(2),
        Arc::from(tx_bytes(2).into_boxed_slice()),
        vec![d(0xCC)],
        vec![d(0x22)],
        vec![],
        1_000_000,
        100,
        20,
        50_000,
        TxSource::Api,
    );
    mp.pool_mut().insert(c).unwrap();
    // Visit P (d(1)) before C (d(2)).
    let base = Instant::now();
    set_checked(&mut mp, 1, base);
    set_checked(&mut mp, 2, base + Duration::from_millis(1));

    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    // hard_fail P so it is evicted; record what C's input view sees afterward.
    let v = ViewRecordingProbe::new(tx_bytes(2), d(0xCC), Some(tx_bytes(1)));

    let actions = mp.recheck_and_evict(base + Duration::from_secs(10), &tip.view(&utxo), &v);

    assert!(!mp.contains(&d(1)), "producing tx P evicted (hard-invalid)");
    assert!(mp.is_invalidated(&d(1)), "P blacklisted");
    assert_eq!(
        v.saw_input.get(),
        Some(false),
        "after P's eviction, 0xCC is pruned from the pass overlay C is rechecked against"
    );
    // C itself fails no hard rule in this probe, so it survives; the point is
    // the overlay no longer resolves the evicted producer's output.
    assert_eq!(evicted_ids(&actions), vec![d(1)]);
    mp.pool().check_invariants();
}

// ----- deterministic rotation tie-break -----

#[test]
fn recheck_rotation_tie_breaks_on_tx_id() {
    // When last_checked_at ties, the visit order falls back to tx_id bytes
    // ascending, so the per-pass budget deterministically selects the
    // lowest tx_ids first (no reliance on map/iteration order).
    let cfg = MempoolConfig {
        mempool_cleanup_cost_mult: 1,
        ..MempoolConfig::default()
    };
    let mut mp = mempool_with(cfg);
    let base = Instant::now();
    for b in 1..=5u8 {
        seed(&mut mp, b, 0x10 + b, 0x40 + b, 100, vec![]);
        set_checked(&mut mp, b, base); // identical last_checked_at -> tie
    }
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new().with_max_block_cost(100_000);
    let v = validator((1..=5u8).map(|b| ok_plan(b, 60_000)).collect());

    let now = base + Duration::from_secs(10);
    mp.recheck_and_evict(now, &tip.view(&utxo), &v);

    assert_eq!(v.validate_call_count(), 2, "budget binds to two txs");
    // Tie broken by tx_id: the lowest bytes (d(1), d(2)) are visited first.
    assert_eq!(mp.pool().get(&d(1)).unwrap().last_checked_at, now);
    assert_eq!(mp.pool().get(&d(2)).unwrap().last_checked_at, now);
    for b in 3..=5u8 {
        assert_eq!(
            mp.pool().get(&d(b)).unwrap().last_checked_at,
            base,
            "higher tx_id d({b}) deferred under the tie-break"
        );
    }
}

// ----- suspect-targeted recheck (recheck_ids / Component B) -----

#[test]
fn recheck_ids_evicts_hard_invalid_suspect_and_scopes_to_the_list() {
    // A suspect that is hard-invalid at the live tip is evicted + blacklisted
    // through the same sink as the full pass. A hard-invalid tx NOT in the
    // suspect list is left untouched — `recheck_ids` is scoped to the ids it
    // is given (the full-pool sweep is `recheck_and_evict`'s job).
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    seed(&mut mp, 2, 0x20, 0x21, 100, vec![]);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator(vec![err_plan(1, 10_000), err_plan(2, 10_000)]);

    let actions = mp.recheck_ids(Instant::now(), &tip.view(&utxo), &v, &[d(1)]);

    assert!(!mp.contains(&d(1)), "hard-invalid suspect evicted");
    assert!(mp.is_invalidated(&d(1)), "and blacklisted");
    assert_eq!(evicted_ids(&actions), vec![d(1)]);
    assert!(
        mp.contains(&d(2)) && !mp.is_invalidated(&d(2)),
        "a tx not in the suspect list is never rechecked"
    );
    mp.pool().check_invariants();
}

#[test]
fn recheck_ids_keeps_suspect_valid_at_live_tip() {
    // Suspects are an ADVISORY hint from a possibly-stale build snapshot.
    // One that re-validates clean against the live tip must be KEPT — this
    // is the staleness guard (a tip advance/reorg between build and drain
    // collapses to a no-op).
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator(vec![ok_plan(1, 10_000)]);

    let actions = mp.recheck_ids(Instant::now(), &tip.view(&utxo), &v, &[d(1)]);

    assert!(mp.contains(&d(1)), "suspect valid at the live tip is kept");
    assert!(!mp.is_invalidated(&d(1)));
    assert!(actions.is_empty());
    mp.pool().check_invariants();
}

#[test]
fn recheck_ids_keeps_unresolved_suspect_not_blacklisted() {
    // The suspect path shares the full pass's hard-invalid-only policy: an
    // UnresolvedInput re-validation is not provable invalidity → kept, not
    // blacklisted (could be a reorg-dependency).
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = AlwaysErr {
        err: ValidationErr::UnresolvedInput,
    };

    let actions = mp.recheck_ids(Instant::now(), &tip.view(&utxo), &v, &[d(1)]);

    assert!(mp.contains(&d(1)), "unresolved suspect kept");
    assert!(!mp.is_invalidated(&d(1)));
    assert!(actions.is_empty());
}

#[test]
fn recheck_ids_skips_unpooled_suspect_and_empty_is_noop() {
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator(vec![ok_plan(1, 10_000)]);

    // A suspect id no longer in the pool (confirmed/already-evicted) is a
    // safe no-op, not a panic.
    let actions = mp.recheck_ids(Instant::now(), &tip.view(&utxo), &v, &[d(9)]);
    assert!(actions.is_empty(), "unpooled suspect is a no-op");
    assert!(mp.contains(&d(1)));

    // Empty suspect list is also a no-op.
    let actions = mp.recheck_ids(Instant::now(), &tip.view(&utxo), &v, &[]);
    assert!(actions.is_empty());
    assert!(mp.contains(&d(1)));
    mp.pool().check_invariants();
}

// ----- height-dependent validator (used by the recreate-claim test) -----

/// Validator that passes a tx ONLY when the validation context height
/// equals `valid_at` (charging `charge`), else returns `ScriptFailed`.
/// Models a tx whose validity is bound to a specific block height (e.g. a
/// storage-rent recreate claim with creationHeight == currentHeight).
struct HeightGatedValidator {
    valid_at: u32,
    charge: u64,
}
impl Validator for HeightGatedValidator {
    fn peek_fee(&self, _: &[u8]) -> Result<PeekedTx, ValidationErr> {
        Err(ValidationErr::Deserialize)
    }
    fn validate(
        &self,
        tx_bytes: &[u8],
        _input_view: &dyn UtxoView,
        _data_input_view: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr> {
        if let Ok(jc) = JitCost::from_block_cost(self.charge) {
            let _ = cx.cost.add(jc);
        }
        if cx.ctx.height != self.valid_at {
            return Err(ValidationErr::ScriptFailed);
        }
        Ok(Validated {
            tx_id: Digest32::from_bytes(tx_bytes.first().map(|b| [*b; 32]).unwrap_or([0u8; 32])),
            input_box_ids: vec![],
            output_box_ids: vec![],
            outputs: vec![],
            fee: 1_000_000,
            size_bytes: 20,
            consumed_cost: self.charge,
        })
    }
}

// ----- revalidation-queue drain (demote_all → tick) -----

#[test]
fn demote_all_then_tick_revalidation_restores_pool() {
    // An epoch-style demote_all empties the active pool
    // into the revalidation queue, and a subsequent tick_revalidation drains
    // it — re-admitting the demoted txs — restoring the pool. Without a
    // drainer the pool would stay empty.
    let mut mp = mempool_with(MempoolConfig::default());
    seed(&mut mp, 1, 0x10, 0x11, 100, vec![]);
    seed(&mut mp, 2, 0x20, 0x21, 200, vec![]);
    assert_eq!(mp.size(), 2);

    let dropped = mp.demote_all_for_revalidation();
    assert_eq!(dropped, 0);
    assert_eq!(mp.size(), 0, "demote_all empties the active pool");
    assert_eq!(mp.revalidation_pending(), 2, "...into the queue");

    let utxo = FakeUtxo::empty();
    let tip = TestTip::new();
    let v = validator(vec![ok_plan(1, 10_000), ok_plan(2, 10_000)]);
    let actions = mp.tick_revalidation(Instant::now(), &tip.view(&utxo), &v);

    assert_eq!(mp.size(), 2, "the drain re-admits the demoted txs");
    assert_eq!(mp.revalidation_pending(), 0, "queue fully drained");
    assert!(mp.contains(&d(1)) && mp.contains(&d(2)));
    let invs = actions
        .iter()
        .filter(|a| matches!(a, MempoolAction::BroadcastInv { .. }))
        .count();
    assert_eq!(invs, 2, "each re-admitted tx broadcasts an Inv");
    mp.pool().check_invariants();
}

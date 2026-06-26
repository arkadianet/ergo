//! `Mempool::on_tip_change` + `tick_revalidation` implementation.
//!
//! Ordering matters:
//!
//!   1. Snapshot each confirmed parent's surviving children **before**
//!      any index mutation. Otherwise step 2 drops the
//!      `parents_in_pool` edges and step 4 can't discover the children.
//!   2. Remove confirmed txs (no descendant cascade — the
//!      parent-confirmation case keeps children valid), debiting each
//!      removed tx's family weight out of its surviving ancestors.
//!   3. Evict pool txs by `applied_spent_inputs`: any pool tx whose
//!      inputs conflict with an applied block tx (including ones the
//!      pool never saw) must go, with CPFP descendants (debited too).
//!   4. Detach confirmed parents from surviving children (edge cleanup;
//!      survivors keep the family-weight boost from their own descendants).
//!   5. Enqueue demoted txs (raw bytes preserved).
//!   6. Reset `CostBudgets`.
//!   7. Initial drain of the revalidation queue, bounded per-tick.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use ergo_primitives::digest::Digest32;

#[cfg(test)]
use crate::admission::TipContext;
use crate::admission::{process, AdmissionCtx, Validator};
use crate::budget::CostBudgets;
use crate::pool::{FamilyBounds, OrderedPool};
use crate::revalidation::RevalidationQueue;
use crate::types::{
    EvictionReason, MempoolAction, MempoolConfig, ObservedEvent, TipPointer, TxDiff, TxId, TxSource,
};

/// Apply a state-change diff to the pool. Returns emitted actions
/// (broadcast revocations, observations) and updates `last_seen` to
/// `diff.new_tip`. Callers should follow up with `tick_revalidation`
/// on their usual cadence.
pub fn on_tip_change(
    diff: &TxDiff,
    config: &MempoolConfig,
    pool: &mut OrderedPool,
    budgets: &mut CostBudgets,
    revalidation: &mut RevalidationQueue,
) -> (TipPointer, Vec<MempoolAction>) {
    let mut actions: Vec<MempoolAction> = Vec::new();
    // Bounds for every family-weight debit in this tip change (Step 2/3).
    let bounds = FamilyBounds::new(
        config.max_family_depth,
        config.max_family_ops,
        config.max_family_update_ms,
    );

    // ── Step 1 — Snapshot each confirmed parent's surviving children BEFORE
    //    any removal (Step 2 drops the `parents_in_pool` edges). Entries carry
    //    no child list, so do a single pass over the pool grouping each tx
    //    under any in-pool confirmed parent it names.
    let confirmed_in_pool: HashSet<TxId> = diff
        .applied
        .iter()
        .map(|a| a.tx_id)
        .filter(|id| pool.contains(id))
        .collect();
    let mut confirmed_parent_children: HashMap<TxId, Vec<TxId>> = HashMap::new();
    if !confirmed_in_pool.is_empty() {
        for e in pool.iter_prioritized() {
            for parent in &e.parents_in_pool {
                if confirmed_in_pool.contains(parent) {
                    confirmed_parent_children
                        .entry(*parent)
                        .or_default()
                        .push(e.tx_id);
                }
            }
        }
    }

    // ── Step 2 — Remove confirmed txs (no descendant cascade), debiting
    //    each removed tx's weight out of its surviving ancestors (Scala
    //    `remove` → `updateFamily(-weight)`). For a confirmed root the
    //    debit is a no-op (its parents are on-chain, not in the pool).
    let mut removed_for_revoke: Vec<TxId> = Vec::new();
    for a in &diff.applied {
        if pool.contains(&a.tx_id) {
            if let Some(entry) = pool.remove_debiting(&a.tx_id, bounds) {
                removed_for_revoke.push(entry.tx_id);
            }
        }
    }
    if !removed_for_revoke.is_empty() {
        actions.push(MempoolAction::RevokeBroadcast {
            tx_ids: removed_for_revoke.clone(),
        });
        actions.push(MempoolAction::Observe {
            event: ObservedEvent::Evicted {
                tx_ids: removed_for_revoke.clone(),
                reason: EvictionReason::Confirmed,
            },
        });
    }

    // ── Step 3 — Evict pool txs by applied_spent_inputs. ──────────
    // A pool tx that shares an input with an applied block tx (even
    // when the applied tx itself was never in our pool) is now
    // spending a box that's already been consumed. Evict with CPFP
    // cascade.
    let mut conflict_evictions: Vec<TxId> = Vec::new();
    let spent_inputs_to_check: Vec<Digest32> = diff.applied_spent_inputs.iter().copied().collect();
    let mut already_evicted: HashSet<TxId> = conflict_evictions.iter().copied().collect();
    for box_id in spent_inputs_to_check {
        let maybe_tx = pool.conflicts_for_inputs(&[box_id]).into_iter().next();
        if let Some(tx_id) = maybe_tx {
            if already_evicted.contains(&tx_id) {
                continue;
            }
            let removed =
                pool.remove_with_descendants_debiting(&tx_id, config.max_family_depth, bounds);
            for e in removed {
                if already_evicted.insert(e.tx_id) {
                    conflict_evictions.push(e.tx_id);
                }
            }
        }
    }
    if !conflict_evictions.is_empty() {
        actions.push(MempoolAction::RevokeBroadcast {
            tx_ids: conflict_evictions.clone(),
        });
        actions.push(MempoolAction::Observe {
            event: ObservedEvent::Evicted {
                tx_ids: conflict_evictions.clone(),
                reason: EvictionReason::InputConflict,
            },
        });
    }

    // ── Step 4 — Detach confirmed parents from surviving children. ─
    // A surviving child of a now-confirmed parent KEEPS the family-weight
    // boost it earned from its own descendants — only its edge to the
    // confirmed parent is stale. The confirmed parent's own weight was
    // already de-propagated in Step 2 (`remove_debiting` debits the parent's
    // ancestors, not its children). So here we only strip the confirmed
    // parent from each surviving child's `parents_in_pool`; we do NOT reset
    // the child to its base weight (that would wrongly strip the boost it
    // earned from its grandchildren).
    for (confirmed_parent, child_ids) in &confirmed_parent_children {
        for child in child_ids {
            pool.detach_parent(child, confirmed_parent);
        }
    }

    // ── Step 5 — Enqueue demoted txs. ─────────────────────────────
    let dropped = revalidation.push_batch(diff.demoted.clone());
    if dropped > 0 {
        actions.push(MempoolAction::Observe {
            event: ObservedEvent::Evicted {
                tx_ids: Vec::new(), // demoted entries never reached pool
                reason: EvictionReason::Confirmed,
            },
        });
    }

    // ── Step 6 — Reset CostBudgets. ───────────────────────────────
    budgets.reset();

    (diff.new_tip, actions)
}

/// Drain up to `cx.config.revalidation_per_tick` demoted txs and
/// feed them back through admission with `TxSource::DemotedFromBlock`.
/// Returns the emitted actions for all admissions. Empty queue is a
/// fast path: returns an empty vec without touching anything else.
pub fn tick_revalidation<V: Validator>(
    now: Instant,
    cx: &mut AdmissionCtx<'_>,
    revalidation: &mut RevalidationQueue,
    validator: &V,
) -> Vec<MempoolAction> {
    let batch = revalidation.drain(cx.config.revalidation_per_tick);
    if batch.is_empty() {
        return Vec::new();
    }
    let mut all_actions = Vec::new();
    for tx in batch {
        let bytes = tx.bytes.to_vec();
        let (outcome, actions) = process(&bytes, TxSource::DemotedFromBlock, now, cx, validator);
        all_actions.extend(actions);
        // Observability: the admission pipeline emits the right
        // Observe events already, so no separate notification here.
        let _ = outcome;
    }
    all_actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{MockPlan, MockValidator, Validated};
    use crate::invalidation::InvalidationCache;
    use crate::pool::Entry;
    use crate::unresolved::UnresolvedCache;
    use crate::weight::ByCost;
    use ergo_primitives::digest::Digest32;
    use ergo_validation::{ProtocolParams, TransactionContext, UtxoView};
    use std::sync::Arc;
    use std::time::Duration;

    struct EmptyUtxo;
    impl UtxoView for EmptyUtxo {
        fn get_box(&self, _: &Digest32) -> Option<ergo_ser::ergo_box::ErgoBox> {
            None
        }
    }

    fn d(b: u8) -> Digest32 {
        Digest32::from_bytes([b; 32])
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

    struct TestCtx {
        tx_context: TransactionContext,
        params: ProtocolParams,
    }

    impl TestCtx {
        fn new() -> Self {
            Self {
                tx_context: dummy_tx_context(1000),
                params: ProtocolParams::mainnet_default(),
            }
        }
        fn view<'a>(&'a self, utxo: &'a dyn UtxoView) -> TipContext<'a> {
            TipContext {
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

    fn seed_entry(
        pool: &mut OrderedPool,
        tx_byte: u8,
        input_byte: u8,
        output_byte: u8,
        weight: u64,
        parents: Vec<TxId>,
    ) {
        let bytes: Arc<[u8]> = Arc::from(vec![tx_byte; 20].into_boxed_slice());
        let entry = Entry::new(
            d(tx_byte),
            bytes,
            vec![d(input_byte)],
            vec![d(output_byte)],
            parents,
            1_000_000,
            weight,
            20,
            50_000,
            TxSource::Api,
        );
        pool.insert(entry).unwrap();
    }

    fn mk_diff(
        new_tip: TipPointer,
        applied: Vec<(u8, Vec<u8>)>,
        demoted: Vec<(u8, Vec<u8>)>,
    ) -> TxDiff {
        let applied_spent_inputs = applied
            .iter()
            .flat_map(|(_, inputs)| inputs.iter().map(|b| d(*b)))
            .collect::<HashSet<_>>();
        TxDiff {
            new_tip,
            applied: applied
                .into_iter()
                .map(|(tx_byte, inputs)| crate::types::AppliedTx {
                    tx_id: d(tx_byte),
                    spent_inputs: inputs.into_iter().map(d).collect(),
                })
                .collect(),
            demoted: demoted
                .into_iter()
                .map(|(tx_byte, bytes)| crate::types::DemotedTx {
                    tx_id: d(tx_byte),
                    bytes: Arc::from(bytes.into_boxed_slice()),
                })
                .collect(),
            applied_spent_inputs,
        }
    }

    fn tip_100() -> TipPointer {
        TipPointer {
            height: 100,
            header_id: d(0xAA),
        }
    }

    // ----- happy path -----

    #[test]
    fn apply_removes_confirmed_pool_tx() {
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut rq = RevalidationQueue::new(100);
        seed_entry(&mut pool, 1, 0x10, 0x11, 100, vec![]);
        let cfg = MempoolConfig::default();

        let diff = mk_diff(tip_100(), vec![(1, vec![0x10])], vec![]);
        let (tip, actions) = on_tip_change(&diff, &cfg, &mut pool, &mut b, &mut rq);
        assert!(!pool.contains(&d(1)));
        assert_eq!(tip, tip_100());
        assert!(actions.iter().any(|a| matches!(
            a,
            MempoolAction::Observe {
                event: ObservedEvent::Evicted {
                    reason: EvictionReason::Confirmed,
                    ..
                }
            }
        )));
        // Confirmed removals also revoke relay state, like input-conflict
        // evictions do, so both signals stay in sync.
        assert!(actions.iter().any(|a| matches!(
            a,
            MempoolAction::RevokeBroadcast { tx_ids } if tx_ids.contains(&d(1))
        )));
        pool.check_invariants();
    }

    #[test]
    fn apply_with_spent_input_conflict_evicts_pool_tx() {
        // Pool tx spends input X; block tx (not in pool) also spends X.
        // The pool tx must be evicted.
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut rq = RevalidationQueue::new(100);
        seed_entry(&mut pool, 7, 0xAA, 0xBB, 100, vec![]);
        let cfg = MempoolConfig::default();

        // Applied tx with id 99 (not in pool) spent box 0xAA.
        let diff = mk_diff(tip_100(), vec![(99, vec![0xAA])], vec![]);
        let (_, actions) = on_tip_change(&diff, &cfg, &mut pool, &mut b, &mut rq);
        assert!(
            !pool.contains(&d(7)),
            "pool tx sharing an input with a block tx must be evicted"
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            MempoolAction::RevokeBroadcast { tx_ids } if tx_ids.contains(&d(7))
        )));
        pool.check_invariants();
    }

    #[test]
    fn parent_confirmed_child_retained() {
        // Parent tx 1 creates box 0x11. Child tx 2 spends 0x11.
        // When parent confirms: parent is removed from pool, child
        // STAYS — its spent-output-of-parent input is now committed
        // UTXO (conceptually).
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut rq = RevalidationQueue::new(100);
        seed_entry(&mut pool, 1, 0x10, 0x11, 100, vec![]);
        seed_entry(&mut pool, 2, 0x11, 0x22, 200, vec![d(1)]);
        let cfg = MempoolConfig::default();

        // Apply: tx 1 confirms, spending box 0x10. Note: box 0x11 is
        // NOT in applied_spent_inputs because the applied tx is the
        // parent — it spent 0x10, not 0x11.
        let diff = mk_diff(tip_100(), vec![(1, vec![0x10])], vec![]);
        on_tip_change(&diff, &cfg, &mut pool, &mut b, &mut rq);
        assert!(!pool.contains(&d(1)), "parent removed");
        assert!(pool.contains(&d(2)), "child retained");
        pool.check_invariants();
    }

    #[test]
    fn parent_confirmed_child_keeps_its_own_descendant_boost() {
        // P <- C <- GC. C carries a family-weight boost from GC. When P
        // confirms, C must KEEP that boost: Step 4 only strips the confirmed
        // parent edge; it must NOT reset C to its base weight (which would
        // wrongly discard GC's contribution — the pre-fix behavior).
        let mut pool = OrderedPool::with_capacity(8);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut rq = RevalidationQueue::new(100);
        // Seed the post-boost state directly. 777/333 are deliberately not the
        // ByCost recompute of these entries' fee/cost, so a reset-to-base
        // regression would visibly change them.
        seed_entry(&mut pool, 1, 0x10, 0x11, 900, vec![]); // P
        seed_entry(&mut pool, 2, 0x11, 0x22, 777, vec![d(1)]); // C (boosted by GC)
        seed_entry(&mut pool, 3, 0x22, 0x33, 333, vec![d(2)]); // GC
        let cfg = MempoolConfig::default();

        // Parent tx 1 confirms (spent box 0x10).
        let diff = mk_diff(tip_100(), vec![(1, vec![0x10])], vec![]);
        on_tip_change(&diff, &cfg, &mut pool, &mut b, &mut rq);

        assert!(!pool.contains(&d(1)), "confirmed parent removed");
        let c = pool.get(&d(2)).expect("child retained");
        assert_eq!(
            c.weight, 777,
            "child keeps its grandchild boost (no reset to base)"
        );
        assert!(
            !c.parents_in_pool.contains(&d(1)),
            "confirmed parent stripped from child's parents_in_pool"
        );
        assert_eq!(
            pool.get(&d(3)).expect("grandchild retained").weight,
            333,
            "grandchild untouched"
        );
        pool.check_invariants();
    }

    #[test]
    fn demoted_txs_enqueue() {
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut rq = RevalidationQueue::new(100);
        let cfg = MempoolConfig::default();
        let diff = mk_diff(
            tip_100(),
            vec![],
            vec![(50, vec![1, 2, 3]), (51, vec![4, 5, 6])],
        );
        on_tip_change(&diff, &cfg, &mut pool, &mut b, &mut rq);
        assert_eq!(rq.len(), 2);
    }

    #[test]
    fn budgets_reset_on_tip_change() {
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut rq = RevalidationQueue::new(100);
        b.charge(None, 500_000);
        assert_eq!(b.global_consumed(), 500_000);
        let cfg = MempoolConfig::default();
        let diff = mk_diff(tip_100(), vec![], vec![]);
        on_tip_change(&diff, &cfg, &mut pool, &mut b, &mut rq);
        assert_eq!(b.global_consumed(), 0);
    }

    #[test]
    fn revalidation_drain_resubmits_with_demoted_source() {
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut inv = InvalidationCache::new(32, Duration::from_secs(60), Duration::from_secs(1));
        let mut unr = UnresolvedCache::new(32, Duration::from_secs(60));
        let mut rq = RevalidationQueue::new(100);
        let cfg = MempoolConfig::default();

        // Enqueue one demoted tx.
        let bytes = vec![0xAB; 16];
        rq.push(crate::types::DemotedTx {
            tx_id: d(42),
            bytes: Arc::from(bytes.clone().into_boxed_slice()),
        });

        // Validator accepts the same bytes.
        let v = MockValidator::new().plan(
            bytes,
            MockPlan {
                result: Ok(Validated {
                    tx_id: d(42),
                    input_box_ids: vec![d(0xCA)],
                    output_box_ids: vec![d(0xDE)],
                    outputs: vec![],
                    fee: 5_000_000,
                    size_bytes: 16,
                    consumed_cost: 10_000,
                }),
                charge: 10_000,
                peek_fee: None,
                peek_tx_id: None,
            },
        );

        let utxo = EmptyUtxo;
        let ctx = TestCtx::new();
        let tip = ctx.view(&utxo);
        let mut cx = AdmissionCtx {
            tip_ctx: &tip,
            config: &cfg,
            pool: &mut pool,
            budgets: &mut b,
            invalidated: &mut inv,
            unresolved: &mut unr,
            weight_fn: &ByCost,
        };
        let actions = tick_revalidation(Instant::now(), &mut cx, &mut rq, &v);
        assert!(pool.contains(&d(42)), "demoted tx re-admitted into pool");
        assert!(rq.is_empty());
        assert!(!actions.is_empty(), "actions include broadcast + observe");
    }

    #[test]
    fn empty_queue_fast_path_returns_empty_actions() {
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut inv = InvalidationCache::new(32, Duration::from_secs(60), Duration::from_secs(1));
        let mut unr = UnresolvedCache::new(32, Duration::from_secs(60));
        let mut rq = RevalidationQueue::new(100);
        let cfg = MempoolConfig::default();
        let utxo = EmptyUtxo;
        let ctx = TestCtx::new();
        let v = MockValidator::new();
        let tip = ctx.view(&utxo);
        let mut cx = AdmissionCtx {
            tip_ctx: &tip,
            config: &cfg,
            pool: &mut pool,
            budgets: &mut b,
            invalidated: &mut inv,
            unresolved: &mut unr,
            weight_fn: &ByCost,
        };
        let actions = tick_revalidation(Instant::now(), &mut cx, &mut rq, &v);
        assert!(actions.is_empty());
    }

    #[test]
    fn drain_respects_per_tick_cap() {
        let mut pool = OrderedPool::with_capacity(100);
        let mut b = CostBudgets::new(10_000_000, 10_000_000);
        let mut inv = InvalidationCache::new(32, Duration::from_secs(60), Duration::from_secs(1));
        let mut unr = UnresolvedCache::new(32, Duration::from_secs(60));
        let mut rq = RevalidationQueue::new(100);
        let cfg = MempoolConfig {
            revalidation_per_tick: 3,
            ..MempoolConfig::default()
        };

        // Enqueue 10 demoted txs.
        let mut v_builder = MockValidator::new();
        for i in 0..10u8 {
            let bytes = vec![i; 16];
            rq.push(crate::types::DemotedTx {
                tx_id: d(i),
                bytes: Arc::from(bytes.clone().into_boxed_slice()),
            });
            v_builder = v_builder.plan(
                bytes,
                MockPlan {
                    result: Ok(Validated {
                        tx_id: d(i),
                        input_box_ids: vec![d(100 + i)],
                        output_box_ids: vec![d(200 + i)],
                        outputs: vec![],
                        fee: 5_000_000,
                        size_bytes: 16,
                        consumed_cost: 10_000,
                    }),
                    charge: 10_000,
                    peek_fee: None,
                    peek_tx_id: None,
                },
            );
        }

        let utxo = EmptyUtxo;
        let ctx = TestCtx::new();
        let tip = ctx.view(&utxo);
        let mut cx = AdmissionCtx {
            tip_ctx: &tip,
            config: &cfg,
            pool: &mut pool,
            budgets: &mut b,
            invalidated: &mut inv,
            unresolved: &mut unr,
            weight_fn: &ByCost,
        };
        let _ = tick_revalidation(Instant::now(), &mut cx, &mut rq, &v_builder);
        assert_eq!(pool.len(), 3, "only 3 re-admitted per tick");
        assert_eq!(rq.len(), 7, "7 still queued");
    }

    #[test]
    fn demoted_source_bypasses_ibd_gate() {
        // Simulate "we're behind tip" — normal admission would drop.
        // Demoted revalidation must still succeed.
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut inv = InvalidationCache::new(32, Duration::from_secs(60), Duration::from_secs(1));
        let mut unr = UnresolvedCache::new(32, Duration::from_secs(60));
        let mut rq = RevalidationQueue::new(100);
        let cfg = MempoolConfig::default();
        let bytes = vec![0xEF; 10];
        rq.push(crate::types::DemotedTx {
            tx_id: d(9),
            bytes: Arc::from(bytes.clone().into_boxed_slice()),
        });
        let v = MockValidator::new().plan(
            bytes,
            MockPlan {
                result: Ok(Validated {
                    tx_id: d(9),
                    input_box_ids: vec![d(50)],
                    output_box_ids: vec![d(60)],
                    outputs: vec![],
                    fee: 5_000_000,
                    size_bytes: 10,
                    consumed_cost: 5_000,
                }),
                charge: 5_000,
                peek_fee: None,
                peek_tx_id: None,
            },
        );
        let utxo = EmptyUtxo;
        // IBD-like context: best_full << best_header.
        let ctx = TestCtx::new();
        let lagging = TipContext {
            tip: TipPointer {
                height: 100,
                header_id: d(0xFF),
            },
            best_header_height: 200,
            best_full_block_height: 100, // gap = 100
            utxo: &utxo,
            tx_context: &ctx.tx_context,
            params: &ctx.params,
            last_headers: &[],
            reemission: None,
        };
        let mut cx = AdmissionCtx {
            tip_ctx: &lagging,
            config: &cfg,
            pool: &mut pool,
            budgets: &mut b,
            invalidated: &mut inv,
            unresolved: &mut unr,
            weight_fn: &ByCost,
        };
        let _ = tick_revalidation(Instant::now(), &mut cx, &mut rq, &v);
        assert!(
            pool.contains(&d(9)),
            "demoted tx admitted despite IBD-gated context"
        );
    }

    #[test]
    fn conflict_eviction_is_deduped_across_inputs() {
        // Pool tx spends two inputs, both appear in applied_spent_inputs.
        // It should be evicted once, not twice.
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut rq = RevalidationQueue::new(100);
        let bytes: Arc<[u8]> = Arc::from(vec![1u8; 20].into_boxed_slice());
        let entry = Entry::new(
            d(1),
            bytes,
            vec![d(0xAA), d(0xBB)],
            vec![d(0xCC)],
            vec![],
            1_000_000,
            100,
            20,
            50_000,
            TxSource::Api,
        );
        pool.insert(entry).unwrap();
        let cfg = MempoolConfig::default();
        let diff = mk_diff(tip_100(), vec![(99, vec![0xAA, 0xBB])], vec![]);
        let (_, actions) = on_tip_change(&diff, &cfg, &mut pool, &mut b, &mut rq);
        // tx 1 evicted exactly once.
        let revokes: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                MempoolAction::RevokeBroadcast { tx_ids } => Some(tx_ids.clone()),
                _ => None,
            })
            .collect();
        let total_evictions: usize = revokes.iter().map(|v| v.len()).sum();
        assert_eq!(total_evictions, 1);
    }

    #[test]
    fn reorg_end_to_end_demotes_and_revalidates() {
        // 1-block reorg: applied has tx B, demoted carries tx A (was
        // in the old chain). The pool never had B; A is re-enqueued
        // and on next tick_revalidation re-admitted.
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(10_000_000, 10_000_000);
        let mut inv = InvalidationCache::new(32, Duration::from_secs(60), Duration::from_secs(1));
        let mut unr = UnresolvedCache::new(32, Duration::from_secs(60));
        let mut rq = RevalidationQueue::new(100);
        let cfg = MempoolConfig::default();

        let a_bytes = vec![0xAA; 24];
        let diff = mk_diff(
            tip_100(),
            vec![(0xBB, vec![0x10])],
            vec![(0xAA, a_bytes.clone())],
        );
        on_tip_change(&diff, &cfg, &mut pool, &mut b, &mut rq);
        assert_eq!(rq.len(), 1);

        let v = MockValidator::new().plan(
            a_bytes,
            MockPlan {
                result: Ok(Validated {
                    tx_id: d(0xAA),
                    input_box_ids: vec![d(0x50)],
                    output_box_ids: vec![d(0x51)],
                    outputs: vec![],
                    fee: 5_000_000,
                    size_bytes: 24,
                    consumed_cost: 10_000,
                }),
                charge: 10_000,
                peek_fee: None,
                peek_tx_id: None,
            },
        );
        let utxo = EmptyUtxo;
        let ctx = TestCtx::new();
        let tip = ctx.view(&utxo);
        let mut cx = AdmissionCtx {
            tip_ctx: &tip,
            config: &cfg,
            pool: &mut pool,
            budgets: &mut b,
            invalidated: &mut inv,
            unresolved: &mut unr,
            weight_fn: &ByCost,
        };
        tick_revalidation(Instant::now(), &mut cx, &mut rq, &v);
        assert!(pool.contains(&d(0xAA)));
        assert!(rq.is_empty());
    }

    #[test]
    fn invalid_demoted_tx_dropped_without_pool_change() {
        let mut pool = OrderedPool::with_capacity(4);
        let mut b = CostBudgets::new(1_000_000, 100_000);
        let mut inv = InvalidationCache::new(32, Duration::from_secs(60), Duration::from_secs(1));
        let mut unr = UnresolvedCache::new(32, Duration::from_secs(60));
        let mut rq = RevalidationQueue::new(100);
        let cfg = MempoolConfig::default();
        let bytes = vec![0xF0; 10];
        rq.push(crate::types::DemotedTx {
            tx_id: d(0x77),
            bytes: Arc::from(bytes.clone().into_boxed_slice()),
        });
        // Validator rejects at ScriptFailed.
        let v = MockValidator::new().plan(
            bytes,
            MockPlan {
                result: Err(crate::admission::ValidationErr::ScriptFailed),
                charge: 7_000,
                peek_fee: None,
                peek_tx_id: None,
            },
        );
        let utxo = EmptyUtxo;
        let ctx = TestCtx::new();
        let tip = ctx.view(&utxo);
        let mut cx = AdmissionCtx {
            tip_ctx: &tip,
            config: &cfg,
            pool: &mut pool,
            budgets: &mut b,
            invalidated: &mut inv,
            unresolved: &mut unr,
            weight_fn: &ByCost,
        };
        tick_revalidation(Instant::now(), &mut cx, &mut rq, &v);
        assert!(pool.is_empty());
        assert!(rq.is_empty());
    }
}

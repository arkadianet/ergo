//! The [`Mempool`] handle: the crate's top-level, single-writer entry
//! point that bundles the ordered pool, anti-DoS budgets, invalidation /
//! unresolved caches, and the revalidation queue, and drives them via the
//! admission / reorg / revalidation free functions.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use tracing::{debug, info};

use ergo_primitives::digest::Digest32;

use crate::admission::{self, AdmissionOutcome, CheckOutcome, RejectReason, Validator};
use crate::budget::CostBudgets;
use crate::invalidation::InvalidationCache;
use crate::pool::{Entry, OrderedPool};
use crate::reorg;
use crate::revalidation::{topological_demote_order, RevalidationQueue};
use crate::staging::StagingPool;
use crate::telemetry::{
    emit_tracing_for_admission, emit_tracing_for_check, emit_tracing_for_pool_actions,
};
use crate::types::{
    EvictionReason, MempoolAction, MempoolConfig, ObservedEvent, PeerId, TipPointer, TxDiff, TxId,
    TxSource,
};
use crate::unresolved::UnresolvedCache;
use crate::weight::WeightFunction;
use crate::MempoolObserver;

/// Top-level mempool handle. Bundles all the sub-components so callers
/// don't thread six pieces through every call site. Production wiring
/// holds one `Mempool` on `NodeState` and drives it via the three
/// methods below (`process`, `on_tip_change`, `tick_revalidation`).
pub struct Mempool {
    pool: OrderedPool,
    config: MempoolConfig,
    weight_fn: Box<dyn WeightFunction>,
    tip: Option<TipPointer>,
    budgets: CostBudgets,
    invalidation: InvalidationCache,
    unresolved: UnresolvedCache,
    revalidation: RevalidationQueue,
    /// Optional telemetry tap (see [`MempoolObserver`]). `None` by default —
    /// every existing caller and test keeps working unchanged; the node
    /// wires a `Some(_)` after boot once the realtime bus exists.
    observer: Option<Arc<dyn MempoolObserver>>,
    /// Descendants left pooled when a hard-invalid recheck cascade truncated
    /// at `max_family_depth` (the [`OrderedPool::remove_with_descendants_frontier`]
    /// frontier). Their hard-invalid ancestor is gone, so they are orphaned and
    /// must be dependency-evicted — but doing the whole family in one op would
    /// reintroduce the O(family) cost the depth cap prevents, so they are
    /// drained under the per-pass budget across successive recheck passes.
    /// Only ever fed from the hard-invalid arm, so a transient
    /// unresolved-input (demoted-parent) tx is never enqueued here.
    pending_orphan_eviction: Vec<TxId>,
    /// Brief holding store for orphans (child-before-parent) and held
    /// parents/singles (parent-before-child) that cannot be admitted yet.
    /// A side effect of `process` alone — `check` (`/check`) never touches
    /// it — and it never gossips. See [`crate::staging`].
    staging: StagingPool,
}

impl Mempool {
    pub fn new(config: MempoolConfig, weight_fn: Box<dyn WeightFunction>) -> Self {
        let budgets = CostBudgets::new(config.global_cost_budget, config.per_peer_cost_budget);
        let invalidation = InvalidationCache::new(
            config.invalidation_cache_size,
            std::time::Duration::from_secs(config.invalidation_ttl_seconds),
            std::time::Duration::from_secs(60),
        );
        let unresolved = UnresolvedCache::new(
            config.unresolved_cache_size,
            std::time::Duration::from_secs(config.unresolved_cache_ttl_seconds),
        );
        let revalidation = RevalidationQueue::new(config.revalidation_max_depth);
        let staging = StagingPool::new(config.staging_caps());
        Self {
            pool: OrderedPool::with_capacity(config.max_pool_size),
            config,
            weight_fn,
            tip: None,
            budgets,
            invalidation,
            unresolved,
            revalidation,
            observer: None,
            pending_orphan_eviction: Vec::new(),
            staging,
        }
    }

    /// Number of transactions currently held in the staging pool
    /// (orphans + held). Read-only operator surface.
    pub fn staging_len(&self) -> usize {
        self.staging.len()
    }

    /// Total bytes held in the staging pool.
    pub fn staging_bytes(&self) -> usize {
        self.staging.total_bytes()
    }

    /// Install (or clear, with `None`) the telemetry observer. Cheap — one
    /// `Option<Arc<_>>` swap, no allocation on the hot path this feeds.
    pub fn set_observer(&mut self, observer: Option<Arc<dyn MempoolObserver>>) {
        self.observer = observer;
    }

    pub fn size(&self) -> usize {
        self.pool.len()
    }

    /// Total bytes occupied by pooled tx payloads. Mirrors
    /// `OrderedPool::total_bytes` for read-only operator surfaces.
    pub fn total_bytes(&self) -> usize {
        self.pool.total_bytes()
    }

    /// Monotonic candidate-visible pool revision (bumped on every pool
    /// mutation — admission, eviction, reorg removal, revalidation re-admit,
    /// and CPFP family-weight credits/debits — which route through
    /// `OrderedPool::insert`/`remove`/`rekey_weight`). The off-loop candidate
    /// engine compares this against the revision its last build reflected to
    /// decide whether a same-tip rebuild is due. A family-weight credit
    /// reweights ancestors *during* an admission (same tip), but that
    /// admission already advances the revision and warrants a rebuild, so the
    /// extra per-ancestor bumps coalesce into that one pending rebuild rather
    /// than triggering a spurious extra one.
    pub fn revision(&self) -> u64 {
        self.pool.revision()
    }

    /// Pooled transactions in relay priority order. This is the
    /// production read-only surface for operator snapshots; callers must
    /// not reach through the doc-hidden test pool accessor.
    pub fn iter_transactions(&self) -> impl Iterator<Item = &Entry> {
        self.pool.iter_prioritized()
    }

    pub fn contains(&self, tx_id: &TxId) -> bool {
        self.pool.contains(tx_id)
    }

    /// Canonical tx bytes for a pooled tx, or `None` if absent. Used
    /// by P2P to respond to a peer's `RequestModifier` for one of our
    /// pool entries.
    pub fn get_bytes(&self, tx_id: &TxId) -> Option<std::sync::Arc<[u8]>> {
        self.pool.get(tx_id).map(|e| e.bytes.clone())
    }

    /// `BoxId → ErgoBox` map over all pool-created outputs, for the
    /// `/utxo/withPool/*` overlay surface. Pool entries that don't
    /// carry materialized output boxes (e.g. in unit tests that seed
    /// the pool directly) contribute nothing. O(N) over pool size;
    /// the publisher calls this once per `sync_tick` and stores the
    /// result in the snapshot.
    pub fn pool_output_overlay(
        &self,
    ) -> std::collections::HashMap<ergo_primitives::digest::Digest32, ergo_ser::ergo_box::ErgoBox>
    {
        self.pool.output_map()
    }

    /// Spent committed-box id → pool tx that spends it, for the
    /// extra-index P5 overlay (`excludeMempoolSpent` filter and
    /// `spending_tx_id` surfacing on byErgoTree/byErgoTreeHash routes).
    /// O(N) clone over the pool's `by_input` index; the publisher
    /// calls this once per `sync_tick` and stores the result in the
    /// snapshot.
    pub fn pool_input_overlay(
        &self,
    ) -> std::collections::HashMap<ergo_primitives::digest::Digest32, TxId> {
        self.pool.input_map()
    }

    /// Is `tx_id` known to be invalid? Checked before requesting a tx
    /// a peer advertised via Inv so we don't re-fetch bytes we
    /// already rejected.
    pub fn is_invalidated(&self, tx_id: &TxId) -> bool {
        self.invalidation.contains(tx_id)
    }

    pub fn tip(&self) -> Option<&TipPointer> {
        self.tip.as_ref()
    }

    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    pub fn revalidation_pending(&self) -> usize {
        self.revalidation.len()
    }

    /// Admit a raw transaction. Returns `(outcome, actions)`.
    ///
    /// `tx_id` on the span is `Empty` until parsing succeeds; `admission::check`
    /// records it via `Span::current().record(...)` once `peek_fee` returns
    /// the canonical id. Pre-parse rejects (size cap, IBD gate, budget) thus
    /// have an empty tx_id field — by design, since no parsed id exists.
    #[tracing::instrument(
        name = "admit",
        level = "debug",
        skip_all,
        fields(
            source = ?source,
            bytes = tx_bytes.len(),
            tx_id = tracing::field::Empty,
        ),
    )]
    pub fn process<V: Validator>(
        &mut self,
        tx_bytes: &[u8],
        source: TxSource,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> (AdmissionOutcome, Vec<MempoolAction>) {
        if !self.config.enabled {
            let outcome = AdmissionOutcome::Rejected {
                reason: RejectReason::Disabled,
            };
            emit_tracing_for_admission(
                &outcome,
                &[],
                &source,
                self.pool.len(),
                self.pool.total_bytes(),
                self.observer.as_deref(),
                self.tip,
            );
            return (outcome, Vec::new());
        }
        let (outcome, mut actions) = {
            let mut cx = admission::AdmissionCtx {
                tip_ctx,
                config: &self.config,
                pool: &mut self.pool,
                budgets: &mut self.budgets,
                invalidated: &mut self.invalidation,
                unresolved: &mut self.unresolved,
                weight_fn: &*self.weight_fn,
            };
            admission::process(tx_bytes, source.clone(), now, &mut cx, validator)
        };
        // Emit the PARENT admission's tracing/observer BEFORE any staging
        // side effect, so resolution's own per-child tracing (emitted inside
        // `resolve_orphans`) is not double-counted against this outcome.
        emit_tracing_for_admission(
            &outcome,
            &actions,
            &source,
            self.pool.len(),
            self.pool.total_bytes(),
            self.observer.as_deref(),
            self.tip,
        );

        // ── Staging side effects — `process` ONLY (never `check`) ────────
        // Staging never gossips; the only `BroadcastInv` here come from
        // `resolve_orphans` promoting a child through the real commit path.
        if self.config.staging_enabled {
            match &outcome {
                AdmissionOutcome::Admitted { tx_id, .. } => {
                    // Parent arrived → resolve orphans waiting on its outputs.
                    let trigger_outputs = self
                        .pool
                        .get(tx_id)
                        .map(|e| e.outputs.clone())
                        .unwrap_or_default();
                    if !trigger_outputs.is_empty() {
                        let child_actions =
                            self.resolve_orphans(trigger_outputs, now, tip_ctx, validator);
                        actions.extend(child_actions);
                    }
                }
                AdmissionOutcome::Rejected {
                    reason: RejectReason::UnresolvedInput,
                } => {
                    // Child arrived before its parent → hold as an orphan.
                    self.stage_orphan(tx_bytes, &source, now, tip_ctx, validator);
                }
                _ => {}
            }
        }
        (outcome, actions)
    }

    /// Which regular inputs of `input_box_ids` are NOT yet resolvable — i.e.
    /// neither created by an in-pool tx (`by_output`) nor present in the
    /// committed UTXO view. This uses the pool's `by_output` INDEX (not a
    /// materialized overlay), so it is cheap and needs no `ErgoBox`es.
    fn missing_inputs(
        &self,
        input_box_ids: &[Digest32],
        utxo: &dyn ergo_validation::UtxoView,
    ) -> Vec<Digest32> {
        input_box_ids
            .iter()
            .filter(|b| self.pool.parent_for_output(b).is_none() && utxo.get_box(b).is_none())
            .copied()
            .collect()
    }

    /// Stage an incoming child (that just failed admission with
    /// `UnresolvedInput`) as an orphan, keyed by its still-missing inputs.
    /// Deserialize-only work (a `peek_structure`); no script validation, so
    /// no `CostBudgets` charge is owed here. A stage refusal (cap hit,
    /// duplicate) is non-fatal — the tx is simply not held.
    fn stage_orphan<V: Validator>(
        &mut self,
        tx_bytes: &[u8],
        source: &TxSource,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) {
        let Ok(s) = validator.peek_structure(tx_bytes) else {
            return; // unparseable — nothing to stage (admission already handled)
        };
        let missing = self.missing_inputs(&s.input_box_ids, tip_ctx.utxo);
        if missing.is_empty() {
            return; // resolvable now — not actually an orphan
        }
        let height = tip_ctx.tip.height;
        let _ = self.staging.stage_orphan(
            s.tx_id,
            Arc::from(tx_bytes),
            s.input_box_ids,
            s.output_box_ids,
            s.fee,
            tx_bytes.len() as u32,
            missing,
            source.clone(),
            now,
            height,
        );
    }

    /// A tx was admitted (or a cascade child was): its `trigger_outputs` are
    /// now spendable, so re-attempt any orphan waiting on them, cascading to
    /// deeper waiters. Bounded by a per-trigger cost budget
    /// (`mempool_cleanup_cost_mult × params.max_block_cost`); over-budget
    /// waiters are DEFERRED (left staged), never dropped. Each attempt is
    /// bounded work: a cheap resolvability pre-check (via the pool's
    /// `by_output` index) gates the full re-validation, and the actual script
    /// cost is charged to `CostBudgets` inside `admission::process` exactly
    /// like any admission (upholding the no-free-oracle invariant). Emits its
    /// OWN per-child tracing/observer and returns the child actions
    /// (`BroadcastInv` etc.) for the caller to route.
    fn resolve_orphans<V: Validator>(
        &mut self,
        trigger_outputs: Vec<Digest32>,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> Vec<MempoolAction> {
        let mut out_actions: Vec<MempoolAction> = Vec::new();
        if self.staging.is_empty() {
            return out_actions;
        }
        let cost_cap: u128 = u128::from(self.config.mempool_cleanup_cost_mult)
            .saturating_mul(u128::from(tip_ctx.params.max_block_cost));
        let max_tx_cost = self.config.max_tx_cost;
        let max_reevals = self.config.staging_max_reevals;
        let mut cost_acc: u128 = 0;

        // Seed the work-queue with the orphans waiting on the trigger outputs.
        let mut queued: HashSet<TxId> = HashSet::new();
        let mut work: VecDeque<TxId> = VecDeque::new();
        for out in &trigger_outputs {
            for w in self.staging.waiters_on(out) {
                if queued.insert(*w) {
                    work.push_back(*w);
                }
            }
        }

        while let Some(child_id) = work.pop_front() {
            if cost_acc >= cost_cap {
                break; // per-trigger budget spent; remainder deferred (still staged)
            }
            let Some(staged) = self.staging.get(&child_id).cloned() else {
                continue; // already promoted/pruned earlier this pass
            };
            // Cheap resolvability pre-check: every regular input must now be a
            // pool output or a committed box, else leave it staged (no attempt,
            // no reeval charge) — another parent has yet to arrive.
            let still_missing = self.missing_inputs(&staged.input_box_ids, tip_ctx.utxo);
            if !still_missing.is_empty() {
                continue;
            }
            // Attempt full admission. Charge the per-trigger budget up front
            // (bounded by max_tx_cost per attempt); the real script cost is
            // charged to CostBudgets inside admission::process.
            cost_acc = cost_acc.saturating_add(u128::from(max_tx_cost));
            let bytes = staged.bytes.clone();
            self.staging.remove(&child_id);
            // Lift the unresolved-cache suppression so the step-3 gate does
            // not short-circuit this re-validation as RecentlyUnresolved.
            self.unresolved.remove(&bytes);
            let (outcome, child_actions) = {
                let mut cx = admission::AdmissionCtx {
                    tip_ctx,
                    config: &self.config,
                    pool: &mut self.pool,
                    budgets: &mut self.budgets,
                    invalidated: &mut self.invalidation,
                    unresolved: &mut self.unresolved,
                    weight_fn: &*self.weight_fn,
                };
                admission::process(&bytes, staged.source.clone(), now, &mut cx, validator)
            };
            emit_tracing_for_admission(
                &outcome,
                &child_actions,
                &staged.source,
                self.pool.len(),
                self.pool.total_bytes(),
                self.observer.as_deref(),
                self.tip,
            );
            match &outcome {
                AdmissionOutcome::Admitted { tx_id, .. } => {
                    // Cascade: enqueue orphans waiting on this child's outputs.
                    let outs = self
                        .pool
                        .get(tx_id)
                        .map(|e| e.outputs.clone())
                        .unwrap_or_default();
                    for o in &outs {
                        for w in self.staging.waiters_on(o) {
                            if queued.insert(*w) {
                                work.push_back(*w);
                            }
                        }
                    }
                }
                AdmissionOutcome::Rejected { .. } => {
                    // Re-stage only if it is STILL an orphan (a deeper ancestor
                    // is missing); bounded by the reeval cap. A now-resolvable
                    // tx that lost a fee/capacity gate is a HELD case — dropped
                    // here in P2, retained by the P3 package path.
                    let missing = self.missing_inputs(&staged.input_box_ids, tip_ctx.utxo);
                    let next_reeval = staged.reeval_count.saturating_add(1);
                    if !missing.is_empty() && next_reeval < max_reevals {
                        let _ = self.staging.stage_orphan(
                            staged.tx_id,
                            bytes.clone(),
                            staged.input_box_ids.clone(),
                            staged.output_box_ids.clone(),
                            staged.fee,
                            staged.size_bytes,
                            missing,
                            staged.source.clone(),
                            staged.staged_at,
                            staged.staged_height,
                        );
                        // Preserve the accrued reeval count on the re-staged entry.
                        self.staging.bump_reeval(&staged.tx_id, next_reeval);
                    }
                }
            }
            out_actions.extend(child_actions);
        }
        out_actions
    }

    /// Run admission steps 0-14 on `tx_bytes` *without committing*.
    ///
    /// Drives REST `/transactions/check[Bytes]`: tells the caller
    /// whether the tx would be admitted as of now, but never inserts
    /// or evicts. Anti-DoS state (cost budgets, invalidation cache,
    /// unresolved cache) is still updated, otherwise `/check` becomes
    /// a free oracle for unmetered script execution. Returns the same
    /// `RejectReason` set as `process`.
    #[tracing::instrument(
        name = "admit_check",
        level = "debug",
        skip_all,
        fields(
            source = ?source,
            bytes = tx_bytes.len(),
            tx_id = tracing::field::Empty,
        ),
    )]
    pub fn check<V: Validator>(
        &mut self,
        tx_bytes: &[u8],
        source: TxSource,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> (CheckOutcome, Vec<MempoolAction>) {
        if !self.config.enabled {
            let outcome = CheckOutcome::Rejected {
                reason: RejectReason::Disabled,
            };
            emit_tracing_for_check(
                &outcome,
                &[],
                &source,
                self.pool.len(),
                self.pool.total_bytes(),
            );
            return (outcome, Vec::new());
        }
        let mut cx = admission::AdmissionCtx {
            tip_ctx,
            config: &self.config,
            pool: &mut self.pool,
            budgets: &mut self.budgets,
            invalidated: &mut self.invalidation,
            unresolved: &mut self.unresolved,
            weight_fn: &*self.weight_fn,
        };
        let (outcome, actions) = admission::check(tx_bytes, &source, now, &mut cx, validator);
        emit_tracing_for_check(
            &outcome,
            &actions,
            &source,
            self.pool.len(),
            self.pool.total_bytes(),
        );
        (outcome, actions)
    }

    /// Apply a state-change diff. Advances `tip` and returns emitted
    /// actions.
    pub fn on_tip_change(&mut self, diff: &TxDiff) -> Vec<MempoolAction> {
        let prev_tip = self.tip;
        let t0 = std::time::Instant::now();
        let (new_tip, actions) = reorg::on_tip_change(
            diff,
            &self.config,
            &mut self.pool,
            &mut self.budgets,
            &mut self.revalidation,
        );
        self.tip = Some(new_tip);

        // ── Block-advance staging prune ──────────────────────────────────
        // Drop staged txs whose input was confirmed-and-consumed on-chain
        // (can never be admitted) and any past their TTL / block-count
        // horizon. Staged entries were never gossiped or pooled, so this
        // emits no actions. `/check` never stages, so nothing here leaks.
        let staging_pruned = if self.config.staging_enabled {
            let mut pruned = self
                .staging
                .prune_spent_inputs(&diff.applied_spent_inputs)
                .len();
            pruned += self
                .staging
                .prune_expired(
                    t0,
                    new_tip.height,
                    std::time::Duration::from_secs(self.config.staging_ttl_seconds),
                    self.config.staging_max_blocks,
                )
                .len();
            pruned
        } else {
            0
        };

        // Per-action evictions log first so dashboards show the cause
        // before the summary.
        emit_tracing_for_pool_actions(&actions, self.observer.as_deref(), Some(new_tip));
        let evicted_count: usize = actions
            .iter()
            .filter_map(|a| match a {
                MempoolAction::Observe {
                    event: ObservedEvent::Evicted { tx_ids, .. },
                } => Some(tx_ids.len()),
                _ => None,
            })
            .sum();
        let prev_height = prev_tip.map(|t| t.height).unwrap_or(0);
        info!(
            event = "mempool_tip_change_processed",
            prev_height,
            new_height = new_tip.height,
            applied = diff.applied.len(),
            demoted = diff.demoted.len(),
            evicted_count,
            pool_size = self.pool.len(),
            pool_bytes = self.pool.total_bytes(),
            revalidation_pending = self.revalidation.len(),
            staging_pending = self.staging.len(),
            staging_pruned,
            duration_ms = t0.elapsed().as_millis() as u64,
            "mempool tip change processed",
        );
        actions
    }

    /// Drain up to `revalidation_per_tick` demoted txs through admission.
    pub fn tick_revalidation<V: Validator>(
        &mut self,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> Vec<MempoolAction> {
        let pending_before = self.revalidation.len();
        // Quiet fast path: empty queue means the call is a no-op (per
        // reorg::tick_revalidation's contract). Skip the start/complete
        // pair so a tick that does nothing produces zero log lines.
        if pending_before == 0 {
            return Vec::new();
        }

        let t0 = std::time::Instant::now();
        info!(
            event = "mempool_revalidation_started",
            pending_before, "mempool revalidation started",
        );

        let mut cx = admission::AdmissionCtx {
            tip_ctx,
            config: &self.config,
            pool: &mut self.pool,
            budgets: &mut self.budgets,
            invalidated: &mut self.invalidation,
            unresolved: &mut self.unresolved,
            weight_fn: &*self.weight_fn,
        };
        let actions = reorg::tick_revalidation(now, &mut cx, &mut self.revalidation, validator);

        // Per-action evictions (rare during revalidation but possible
        // if a demoted tx wins a double-spend conflict against an
        // already-pooled one).
        emit_tracing_for_pool_actions(&actions, self.observer.as_deref(), self.tip);

        // Counts derived from the action stream: each successful
        // re-admission emits exactly one `BroadcastInv`.
        let admitted_count = actions
            .iter()
            .filter(|a| matches!(a, MempoolAction::BroadcastInv { .. }))
            .count();
        let pending_after = self.revalidation.len();
        let drained = pending_before.saturating_sub(pending_after);
        let rejected_count = drained.saturating_sub(admitted_count);
        info!(
            event = "mempool_revalidation_completed",
            drained,
            admitted_count,
            rejected_count,
            pending_before,
            pending_after,
            duration_ms = t0.elapsed().as_millis() as u64,
            "mempool revalidation completed",
        );
        actions
    }

    /// Proactive tip-revalidation (recheck-and-evict). Re-validates pooled txs
    /// against the new tip and EVICTS those no longer valid — the Scala
    /// `MempoolAuditor`/`CleanupWorker` end-result, reached via a superior
    /// full-pass Rust path (no 30s throttle). It re-uses the node's OWN
    /// admission validation (`admission::revalidate_pooled`) so the pool stays
    /// consistent with admission (no admit-then-evict flapping).
    ///
    /// Bounding: a full pass by default, bounded only by an anti-DoS per-pass
    /// COST BUDGET (`mempool_cleanup_cost_mult × LIVE params.max_block_cost`).
    /// The budget is checked BEFORE each tx and the actual consumed cost is
    /// charged after — on BOTH the pass and fail paths — so an all-expensive
    /// pool cannot over-run it. It is a soft budget: the tx in flight when the
    /// budget is reached still completes, so a single pass can exceed the budget
    /// by at most one in-flight tx's consumed validation cost (one tx's
    /// accounting, ≈ `max_tx_cost`; a cost-exceeded tx is charged its
    /// post-limit consumed figure, which can edge slightly past the per-tx cap).
    /// Remaining txs are deferred to later blocks, oldest `last_checked_at` first
    /// (tie-break `tx_id`), so the tail is covered within a bounded number of
    /// passes and cannot starve.
    ///
    /// Eviction policy: a tx is evicted ONLY when it is PROVABLY invalid at the
    /// new tip — a hard consensus failure (script/monetary/structural/cost),
    /// per `admission::is_hard_invalid`. A non-resolution failure
    /// (`UnresolvedInput`/`UnresolvedDataInput`), a parse-class failure, or the
    /// validator's catch-all `Other(_)` (an internal/contract error — resolved-
    /// inputs mismatch / internal-invariant violation — not a consensus verdict)
    /// does NOT evict: an unresolved input can be a transient reorg-dependency (a
    /// demoted parent pending re-admission via the revalidation-queue drain), a
    /// genuine confirmed double-spend is already evicted by
    /// `on_tip_change`'s input-conflict cascade, and an `Other(_)` is not safe
    /// proof to drop an already-accepted tx — so such txs are left in place
    /// (rotation clock advanced) rather than dropped to the unresolved-bytes
    /// cache (a suppression filter, not a re-admit queue). Eviction goes through
    /// the family-weight debiting wrapper and routes the FAILED ROOT
    /// id through the shared `admission::record_failed_tx` classifier (here
    /// always the blacklist arm, since only hard-invalid failures reach it), so
    /// it stops being relayed. Cascade descendants are dependency-evicted only
    /// (never cached). A descendant BEYOND the `max_family_depth` cascade bound
    /// is not removed in the same op (the cap guards against an O(family) spike),
    /// but it is not abandoned either: the removal returns the truncation
    /// frontier, which is queued in `pending_orphan_eviction` and swept by
    /// [`Self::drain_orphan_evictions`] under this pass's cost budget, carrying
    /// the deeper frontier forward until the whole invalid subtree is gone. Only
    /// hard-invalid cascades feed that queue, so a transient `UnresolvedInput`
    /// (demoted-parent) tx is never swept.
    ///
    /// `now` is injected and stamps all per-tx bookkeeping (the rotation clock),
    /// so the pass is deterministic and unit-testable; the only wall-clock read
    /// is a single monotonic `Instant::now()` for the completion-log
    /// `duration_ms` metric (as in `tick_revalidation`), which feeds no
    /// bookkeeping or control flow. Returns the emitted `RevokeBroadcast`/
    /// `Evicted` actions for the caller to route.
    pub fn recheck_and_evict<V: Validator>(
        &mut self,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> Vec<MempoolAction> {
        let mut actions: Vec<MempoolAction> = Vec::new();
        if self.pool.is_empty() {
            return actions;
        }

        // Snapshot config-derived bounds before the mutating loop.
        let max_tx_cost = self.config.max_tx_cost;
        let max_family_depth = self.config.max_family_depth;

        // Misconfiguration guard: if `max_tx_cost` is set above the JitCost
        // bound the per-tx cap cannot be built, so EVERY revalidation would
        // return `CostExceeded` with zero consumed cost — the budget would
        // never trip and the WHOLE pool would be evicted + blacklisted. Refuse
        // to run rather than mass-evict on a bad config; admission already
        // surfaces the same misconfig per-tx.
        if ergo_primitives::cost::JitCost::from_block_cost(max_tx_cost).is_err() {
            debug!(
                max_tx_cost,
                "mempool recheck skipped: max_tx_cost exceeds the JitCost bound (misconfig)",
            );
            return actions;
        }
        let t0 = std::time::Instant::now();

        let bounds = crate::pool::FamilyBounds::new(
            self.config.max_family_depth,
            self.config.max_family_ops,
            self.config.max_family_update_ms,
        );
        // Anti-DoS per-pass budget = mult × LIVE max_block_cost (epoch-votable).
        let cost_cap: u128 = u128::from(self.config.mempool_cleanup_cost_mult)
            .saturating_mul(u128::from(tip_ctx.params.max_block_cost));

        // Build the pool-output overlay map ONCE (output_map is O(pool)); prune
        // it as evictions remove entries so it stays consistent within the pass.
        let mut pool_outputs = self.pool.output_map();

        // Visit oldest-checked first (tie-break tx id) so the per-pass cap
        // rotates coverage across blocks without starving the tail.
        let mut ids: Vec<(std::time::Instant, TxId)> = self
            .pool
            .iter_prioritized()
            .map(|e| (e.last_checked_at, e.tx_id))
            .collect();
        ids.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.as_bytes().cmp(b.1.as_bytes()))
        });

        let mut cost_acc: u128 = 0;
        let mut rechecked: usize = 0;
        let mut removed_for_actions: Vec<TxId> = Vec::new();
        // Ids that PASSED recheck this pass (verdict Ok — all inputs in place),
        // in visit (oldest-`last_checked_at` first) order. The re-broadcast
        // candidate set; filtered to those still pooled (not cascade-evicted by
        // a later tx) below.
        let mut passed_ids: Vec<TxId> = Vec::new();

        for (_, id) in ids {
            if cost_acc >= cost_cap {
                break; // per-pass budget spent; remainder deferred to next block
            }
            if !self.pool.contains(&id) {
                continue; // already cascade-evicted earlier this pass
            }
            rechecked += 1;
            cost_acc = cost_acc.saturating_add(u128::from(self.recheck_one(
                id,
                now,
                tip_ctx,
                validator,
                &mut pool_outputs,
                max_tx_cost,
                max_family_depth,
                bounds,
                &mut removed_for_actions,
                &mut passed_ids,
            )));
        }

        // Dependency-evict any descendants orphaned by this pass's hard-invalid
        // cascades that the depth cap left pooled (bounded by the remaining
        // budget; leftovers carry to the next pass).
        self.drain_orphan_evictions(
            max_family_depth,
            bounds,
            max_tx_cost,
            &mut pool_outputs,
            &mut removed_for_actions,
            &mut cost_acc,
            cost_cap,
        );

        let evicted = removed_for_actions.len();
        if !removed_for_actions.is_empty() {
            actions.push(MempoolAction::RevokeBroadcast {
                tx_ids: removed_for_actions.clone(),
            });
            actions.push(MempoolAction::Observe {
                event: ObservedEvent::Evicted {
                    tx_ids: removed_for_actions,
                    reason: EvictionReason::TipInvalid,
                },
            });
        }

        // Re-broadcast half of Scala `MempoolAuditor.rebroadcastTransactions`:
        // after the eviction pass, re-advertise up to `rebroadcast_count`
        // SURVIVORS — txs that PASSED recheck this pass (verdict Ok, so all
        // inputs resolve: the exact `inputIds.forall(boxById(_).isDefined)`
        // precondition Scala re-broadcasts under) and are still pooled. Scala
        // selects `random(rebroadcastCount)`; we reuse the pass's
        // oldest-`last_checked_at` visit order, which is functionally equivalent
        // for load-spreading and is deterministic/testable: a cost-capped pass
        // refreshes only its rechecked survivors' clocks, so coverage rotates
        // across blocks. Excluded: evicted txs (revoked above), kept-but-failed
        // txs (unresolved/Other — inputs NOT in place), and the budget-deferred
        // tail (never rechecked this pass). Reuses the survivor set the loop
        // already established — no extra validation pass.
        let rebroadcast_count = self.config.rebroadcast_count;
        if rebroadcast_count > 0 {
            let mut rebroadcast = 0usize;
            for id in passed_ids {
                if rebroadcast >= rebroadcast_count {
                    break;
                }
                // A passed id can still be cascade-evicted by a LATER tx's
                // hard-invalid removal; only still-pooled survivors are relayed.
                if self.pool.contains(&id) {
                    actions.push(MempoolAction::BroadcastInv {
                        tx_id: id,
                        except: None,
                    });
                    rebroadcast += 1;
                }
            }
        }

        emit_tracing_for_pool_actions(&actions, self.observer.as_deref(), self.tip);
        info!(
            event = "mempool_recheck_completed",
            rechecked,
            evicted,
            pool_size = self.pool.len(),
            duration_ms = t0.elapsed().as_millis() as u64,
            "mempool tip recheck completed",
        );
        actions
    }

    /// Re-validate ONE pooled tx (`id`) against `tip_ctx` and apply the recheck
    /// eviction policy. The single shared per-id core of both the full-pool pass
    /// (`recheck_and_evict`) and the targeted suspect pass (`recheck_ids`), so
    /// the two have byte-identical validity/eviction/debit/cache semantics.
    ///
    /// * `Ok` (still valid) → keep; refresh only the rotation clock
    ///   (`touch_rechecked`) — deliberately NOT cost/weight, since re-pricing on
    ///   a validity check would desync `Entry.cost` from the `ByCost` weight key.
    /// * `Err` that is NOT `is_hard_invalid` (non-resolution / parse-class /
    ///   validator catch-all `Other(_)`) → keep, only advancing the rotation
    ///   clock. Such a failure is not proof of invalidity: an unresolved input
    ///   can be a transient reorg-dependency, dropping it to the unresolved-bytes
    ///   cache (a suppression filter, not a re-admit queue) would lose a valid
    ///   tx; a confirmed double-spend is already evicted by `on_tip_change`'s
    ///   input-conflict cascade; an `Other(_)` is an internal/contract error,
    ///   not a consensus verdict.
    /// * hard-invalid `Err` (script/monetary/structural/cost) → evict it + its
    ///   now-orphaned descendants (debiting the surviving ancestor's family
    ///   weight), prune the pass
    ///   overlay so a later tx can't resolve a gone output, and route ONLY the
    ///   failed root through the shared `record_failed_tx` classifier (here
    ///   always the blacklist arm). Cascade descendants are dependency-evicted,
    ///   never cached.
    ///
    /// `pool_outputs` is the once-per-pass overlay map, pruned in place on
    /// eviction. Removed tx ids are appended to `removed_for_actions`; ids that
    /// PASSED cleanly (verdict Ok — all inputs in place) are appended to
    /// `passed_ids` for the full pass's re-broadcast selection (a kept-but-FAILED
    /// non-hard-invalid tx is NOT recorded). Returns the validation cost the
    /// caller charges to its per-pass budget. A no-op returning 0 if `id` is no
    /// longer pooled (already cascade-evicted).
    #[allow(clippy::too_many_arguments)]
    fn recheck_one<V: Validator>(
        &mut self,
        id: TxId,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
        pool_outputs: &mut std::collections::HashMap<
            ergo_primitives::digest::Digest32,
            ergo_ser::ergo_box::ErgoBox,
        >,
        max_tx_cost: u64,
        max_family_depth: usize,
        bounds: crate::pool::FamilyBounds,
        removed_for_actions: &mut Vec<TxId>,
        passed_ids: &mut Vec<TxId>,
    ) -> u64 {
        let Some(bytes) = self.pool.get(&id).map(|e| e.bytes.clone()) else {
            return 0; // already gone (cascade-evicted, or a stale suspect id)
        };
        let (consumed, verdict) =
            admission::revalidate_pooled(&bytes, tip_ctx, pool_outputs, max_tx_cost, validator);
        match verdict {
            Ok(()) => {
                self.pool.touch_rechecked(&id, now);
                // Passed cleanly (all inputs in place) — a re-broadcast candidate.
                // A kept-but-FAILED tx (non-hard-invalid: unresolved / Other) is
                // deliberately NOT recorded: Scala only re-broadcasts txs whose
                // inputs all resolve, which a non-resolution failure violates.
                passed_ids.push(id);
            }
            Err(ref err) if !admission::is_hard_invalid(err) => {
                self.pool.touch_rechecked(&id, now);
            }
            Err(err) => {
                let (removed, frontier) = self.pool.remove_with_descendants_debiting_frontier(
                    &id,
                    max_family_depth,
                    bounds,
                );
                // Descendants past the depth cap are orphaned by this eviction;
                // queue them for bounded dependency-eviction (drained under the
                // per-pass budget) rather than leaving them to linger as
                // retained UnresolvedInput.
                self.pending_orphan_eviction.extend(frontier);
                for e in &removed {
                    for out in &e.outputs {
                        pool_outputs.remove(out);
                    }
                }
                admission::record_failed_tx(
                    &mut self.invalidation,
                    &mut self.unresolved,
                    id,
                    &bytes,
                    &err,
                    now,
                );
                for e in removed {
                    removed_for_actions.push(e.tx_id);
                }
            }
        }
        consumed
    }

    /// Drain queued orphan evictions — descendants a hard-invalid cascade left
    /// pooled past the `max_family_depth` cap — bounded by the pass's remaining
    /// cost budget. Each is dependency-evicted with its own descendants; a
    /// removal that truncates again re-queues the deeper frontier, so a large
    /// orphan subtree is cleared over successive passes rather than in one
    /// O(family) spike. Orphans no longer pooled (confirmed / already swept) are
    /// skipped; those not reached this pass stay queued for the next. Appends
    /// removed ids to `removed_for_actions` and prunes `pool_outputs`; does NOT
    /// blacklist — this is dependency eviction, not a per-tx verdict. Charges
    /// `max_tx_cost` per removal op against `cost_acc` so the same anti-DoS
    /// budget that bounds the validation pass also bounds the sweep.
    #[allow(clippy::too_many_arguments)]
    fn drain_orphan_evictions(
        &mut self,
        max_family_depth: usize,
        bounds: crate::pool::FamilyBounds,
        max_tx_cost: u64,
        pool_outputs: &mut std::collections::HashMap<
            ergo_primitives::digest::Digest32,
            ergo_ser::ergo_box::ErgoBox,
        >,
        removed_for_actions: &mut Vec<TxId>,
        cost_acc: &mut u128,
        cost_cap: u128,
    ) {
        if self.pending_orphan_eviction.is_empty() {
            return;
        }
        // Work-queue: process queued orphans and any deeper frontier they
        // surface within this pass, until the queue drains or the budget is
        // hit. Whatever remains on a budget cutoff persists to the next pass.
        let mut work: std::collections::VecDeque<TxId> =
            std::mem::take(&mut self.pending_orphan_eviction).into();
        while let Some(id) = work.pop_front() {
            if *cost_acc >= cost_cap {
                work.push_front(id);
                break;
            }
            if !self.pool.contains(&id) {
                continue; // already gone (confirmed / swept by another cascade)
            }
            let (removed, frontier) =
                self.pool
                    .remove_with_descendants_debiting_frontier(&id, max_family_depth, bounds);
            *cost_acc = cost_acc.saturating_add(u128::from(max_tx_cost));
            for e in &removed {
                for out in &e.outputs {
                    pool_outputs.remove(out);
                }
                removed_for_actions.push(e.tx_id);
            }
            for f in frontier {
                work.push_back(f);
            }
        }
        self.pending_orphan_eviction = work.into();
    }

    /// Targeted recheck of a SPECIFIC set of pooled tx ids — Component B's
    /// suspect feed from off-loop mining candidate assembly. The candidate
    /// builder skips a tx whose consensus re-validation fails against the build
    /// snapshot; those ids are forwarded here so a tx that has gone tip-invalid
    /// is evicted THIS block instead of waiting for the next full
    /// `recheck_and_evict` pass — purely a latency win, since the full pass would
    /// catch the same txs on the next tip change.
    ///
    /// Suspects are an ADVISORY hint computed against a possibly-stale build
    /// snapshot, so every id is RE-VALIDATED against the live `tip_ctx` here
    /// (via the shared [`Self::recheck_one`]): a suspect that is valid at the
    /// current tip is kept; only still-hard-invalid ones are evicted, with the
    /// exact eviction/debit/blacklist semantics of the full pass. Ids no longer
    /// pooled (confirmed/already-evicted) are skipped. Bounded by the same
    /// anti-DoS per-pass cost budget. The caller must gate on fully-synced (as
    /// the `recheck_and_evict` hook does) so a catching-up node doesn't act on a
    /// stale tip. Returns the emitted actions for the caller to route.
    pub fn recheck_ids<V: Validator>(
        &mut self,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
        ids: &[TxId],
    ) -> Vec<MempoolAction> {
        let mut actions: Vec<MempoolAction> = Vec::new();
        if ids.is_empty() || self.pool.is_empty() {
            return actions;
        }

        let max_tx_cost = self.config.max_tx_cost;
        let max_family_depth = self.config.max_family_depth;
        // Same misconfig guard as the full pass (see `recheck_and_evict`): a
        // max_tx_cost above the JitCost bound would make every revalidation a
        // zero-cost CostExceeded and mass-evict; refuse to run instead.
        if ergo_primitives::cost::JitCost::from_block_cost(max_tx_cost).is_err() {
            debug!(
                max_tx_cost,
                "mempool suspect recheck skipped: max_tx_cost exceeds the JitCost bound (misconfig)",
            );
            return actions;
        }
        let t0 = std::time::Instant::now();

        let bounds = crate::pool::FamilyBounds::new(
            self.config.max_family_depth,
            self.config.max_family_ops,
            self.config.max_family_update_ms,
        );
        let cost_cap: u128 = u128::from(self.config.mempool_cleanup_cost_mult)
            .saturating_mul(u128::from(tip_ctx.params.max_block_cost));
        let mut pool_outputs = self.pool.output_map();

        let mut cost_acc: u128 = 0;
        let mut rechecked: usize = 0;
        let mut removed_for_actions: Vec<TxId> = Vec::new();
        // The targeted suspect pass (Component B) is eviction-only; it does NOT
        // re-broadcast (that is the full `MempoolAuditor` pass's job), so the
        // passed-id set is collected and discarded.
        let mut passed_ids: Vec<TxId> = Vec::new();

        for id in ids {
            if cost_acc >= cost_cap {
                break; // per-pass budget spent; suspects re-surface on the next build
            }
            if !self.pool.contains(id) {
                continue; // suspect already confirmed / evicted / never pooled
            }
            rechecked += 1;
            cost_acc = cost_acc.saturating_add(u128::from(self.recheck_one(
                *id,
                now,
                tip_ctx,
                validator,
                &mut pool_outputs,
                max_tx_cost,
                max_family_depth,
                bounds,
                &mut removed_for_actions,
                &mut passed_ids,
            )));
        }

        // Same orphan-cascade drain as the full pass (see `recheck_and_evict`).
        self.drain_orphan_evictions(
            max_family_depth,
            bounds,
            max_tx_cost,
            &mut pool_outputs,
            &mut removed_for_actions,
            &mut cost_acc,
            cost_cap,
        );

        let evicted = removed_for_actions.len();
        if !removed_for_actions.is_empty() {
            actions.push(MempoolAction::RevokeBroadcast {
                tx_ids: removed_for_actions.clone(),
            });
            actions.push(MempoolAction::Observe {
                event: ObservedEvent::Evicted {
                    tx_ids: removed_for_actions,
                    reason: EvictionReason::TipInvalid,
                },
            });
        }
        emit_tracing_for_pool_actions(&actions, self.observer.as_deref(), self.tip);
        info!(
            event = "mempool_suspect_recheck_completed",
            suspects = ids.len(),
            rechecked,
            evicted,
            pool_size = self.pool.len(),
            duration_ms = t0.elapsed().as_millis() as u64,
            "mempool suspect recheck completed",
        );
        actions
    }

    /// Peer disconnected — drop per-peer budget bookkeeping.
    pub fn on_peer_disconnected(&mut self, peer: &PeerId) {
        self.budgets.forget_peer(peer);
    }

    /// Demote every active tx into the revalidation queue. Used after
    /// a voted-params change at an epoch boundary (or post-reorg)
    /// invalidates prior admission decisions: txs admitted under the
    /// old `(active_params, validation_settings)` may no longer fit
    /// the new limits.
    ///
    /// Drains the active pool, clears cost budgets, and enqueues every
    /// tx with its preserved bytes so the next `tick_revalidation`
    /// re-runs admission against current params. Returns the number of
    /// oldest revalidation entries dropped (pathological case where
    /// the queue can't hold the entire pool).
    pub fn demote_all_for_revalidation(&mut self) -> usize {
        // Snapshot every active tx with its in-pool parent edges, in priority
        // order, then re-emit PARENT-BEFORE-CHILD. The drain
        // (`tick_revalidation`) re-admits in queue order and resolves a child's
        // inputs against its parent's now-pooled output, so the parent must be
        // re-admitted first; the raw weight order can place a high-fee child
        // ahead of its low-fee parent (which would then fail `UnresolvedInput`
        // and be dropped). See `topological_demote_order`.
        let snapshot: Vec<(TxId, Vec<TxId>, std::sync::Arc<[u8]>)> = self
            .pool
            .iter_prioritized()
            .map(|e| (e.tx_id, e.parents_in_pool.clone(), e.bytes.clone()))
            .collect();
        if snapshot.is_empty() {
            return 0;
        }
        let demoted = topological_demote_order(snapshot);
        // Drain the pool. Collect ids first to avoid borrow issues.
        let ids: Vec<TxId> = demoted.iter().map(|d| d.tx_id).collect();
        for id in &ids {
            self.pool.remove(id);
        }
        // Reset cost budgets (mirrors reorg::on_tip_change line 188).
        self.budgets.reset();
        // Enqueue for re-admission, parent-before-child. Truncate from the
        // TAIL when the whole pool exceeds `revalidation_max_depth`: dropping
        // the parent-first prefix (front-drop) would strand orphaned children
        // that then fail `UnresolvedInput` on drain.
        self.revalidation.push_batch_truncating(demoted)
    }

    /// Test-only: access the underlying pool for invariant checks.
    /// `#[doc(hidden)]` hides the symbol from rustdoc; the cfg-gate
    /// removes it from the production crate surface entirely so a
    /// future production caller can't accidentally bypass the
    /// method-level invariants (single-writer admission, anti-DoS
    /// budgeting) by reading raw pool state.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn pool(&self) -> &OrderedPool {
        &self.pool
    }

    /// Test-only: mutable pool access. Production code writes through
    /// the method surface above; this is for unit tests that seed
    /// state before exercising a specific transition. The cfg-gate
    /// matches the existing `MockValidator` pattern and forces
    /// non-test callers (e.g., future embedders or `ergo-node`
    /// imports) to either run with `cargo test` or opt into the
    /// `test-support` feature explicitly in `[dev-dependencies]` —
    /// closing the "any caller can skip the 17-step admission
    /// pipeline" hole.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn pool_mut(&mut self) -> &mut OrderedPool {
        &mut self.pool
    }

    pub fn weight_fn(&self) -> &dyn WeightFunction {
        &*self.weight_fn
    }
}

#[cfg(test)]
mod recheck_tests;
#[cfg(test)]
mod staging_tests;

//! The [`Mempool`] handle: the crate's top-level, single-writer entry
//! point that bundles the ordered pool, anti-DoS budgets, invalidation /
//! unresolved caches, and the revalidation queue, and drives them via the
//! admission / reorg / revalidation free functions.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use tracing::{debug, info};

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_validation::{TxValidationCtx, TxValidationRules};

use crate::admission::{
    self, AdmissionOutcome, CheckOutcome, RejectReason, Validated, ValidationErr, Validator,
};
use crate::budget::CostBudgets;
use crate::invalidation::InvalidationCache;
use crate::overlay::{CommittedOnly, PoolUtxoOverlay};
use crate::pool::{Entry, FamilyBounds, OrderedPool};
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
use crate::weight::WeightInputs;
use crate::MempoolObserver;

/// One member of an assembled package: a fully-validated transaction whose
/// facts (weight, cost, materialized outputs) are known, ready for the atomic
/// multi-insert in [`Mempool::commit_package`]. Held ancestors contribute
/// their retained `HeldFacts`; the arriving child contributes its just-
/// computed `Validated`.
struct PackageMember {
    tx_id: TxId,
    bytes: Arc<[u8]>,
    input_box_ids: Vec<Digest32>,
    output_box_ids: Vec<Digest32>,
    outputs: Vec<ErgoBox>,
    fee: u64,
    weight: u64,
    size_bytes: u32,
    cost: u64,
    source: TxSource,
}

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
        let mut held_out: Option<admission::HeldCandidate> = None;
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
            admission::process_capturing_held(
                tx_bytes,
                source.clone(),
                now,
                &mut cx,
                validator,
                &mut held_out,
            )
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
                    // The child's input(s) don't resolve against pool/committed
                    // state. First try to complete a PACKAGE: if a missing input
                    // is created by a HELD staged ancestor, assemble
                    // {held ancestors…, child} and run the package decision
                    // (P4). Only if that isn't applicable do we fall back to
                    // holding the child as a plain orphan (P2).
                    match self.try_package(tx_bytes, &source, now, tip_ctx, validator) {
                        Some(pkg_actions) => actions.extend(pkg_actions),
                        None => self.stage_orphan(tx_bytes, &source, now, tip_ctx, validator),
                    }
                }
                AdmissionOutcome::Rejected {
                    reason: RejectReason::DoubleSpendLoser | RejectReason::PoolFull,
                } => {
                    // A fully-validated parent that lost the fee/capacity or
                    // double-spend gate → hold it briefly so a booster child
                    // can complete an admissible package. `held_out` is `Some`
                    // exactly for these two boostable rejections (never for the
                    // oversize `PoolFull`, which a package cannot rescue).
                    if let Some(hc) = held_out.take() {
                        self.stage_held_candidate(hc, tx_bytes, &source, now, tip_ctx);
                    }
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

    /// Hold a fully-validated tx that lost the fee/capacity or double-spend
    /// gate (a [`HeldCandidate`]) in the staging pool. The tx was already
    /// validated with its cost charged, so this stages deserialize-derived
    /// facts only — no further validation, no `CostBudgets` charge owed. A
    /// stage refusal (cap hit, duplicate) is non-fatal — the tx is simply not
    /// held. Its materialized outputs are retained so a later descendant can
    /// resolve against them when assembling a package.
    fn stage_held_candidate(
        &mut self,
        hc: admission::HeldCandidate,
        tx_bytes: &[u8],
        source: &TxSource,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
    ) {
        let v = hc.validated;
        let _ = self.staging.stage_held(
            v.tx_id,
            Arc::from(tx_bytes),
            v.input_box_ids,
            v.output_box_ids,
            v.fee,
            v.size_bytes,
            hc.weight,
            v.consumed_cost,
            v.outputs,
            source.clone(),
            now,
            tip_ctx.tip.height,
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
            let mut held_out: Option<admission::HeldCandidate> = None;
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
                admission::process_capturing_held(
                    &bytes,
                    staged.source.clone(),
                    now,
                    &mut cx,
                    validator,
                    &mut held_out,
                )
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
                    let missing = self.missing_inputs(&staged.input_box_ids, tip_ctx.utxo);
                    let next_reeval = staged.reeval_count.saturating_add(1);
                    if !missing.is_empty() && next_reeval < max_reevals {
                        // Still an orphan (a deeper ancestor is missing) →
                        // re-stage, bounded by the reeval cap. Preserve the
                        // original `staged_at`/`staged_height` so TTL and the
                        // block horizon do not renew on retry.
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
                        self.staging.bump_reeval(&staged.tx_id, next_reeval);
                    } else if let Some(hc) = held_out.take() {
                        // Fully resolvable now, but lost the fee/capacity or
                        // double-spend gate → convert to a HELD entry so its own
                        // future descendant can complete a package. Preserve the
                        // original staging clock/height (no horizon renewal).
                        let v = hc.validated;
                        let _ = self.staging.stage_held(
                            v.tx_id,
                            bytes.clone(),
                            v.input_box_ids,
                            v.output_box_ids,
                            v.fee,
                            v.size_bytes,
                            hc.weight,
                            v.consumed_cost,
                            v.outputs,
                            staged.source.clone(),
                            staged.staged_at,
                            staged.staged_height,
                        );
                    }
                }
            }
            out_actions.extend(child_actions);
        }
        out_actions
    }

    /// A child failed single-tx admission with `UnresolvedInput`. Try to
    /// complete a PACKAGE around it: if each unresolved input is created by a
    /// HELD staged ancestor, assemble `{held ancestors…, child}`, validate the
    /// child against an overlay that includes those held outputs (cost charged
    /// to `CostBudgets` — no free oracle), score the package as a unit, and run
    /// the package admission / RBF decision.
    ///
    /// Returns:
    /// * `None` — not a package situation (no held ancestor, or a deeper
    ///   non-held ancestor is still missing). The caller falls back to holding
    ///   the child as a plain orphan.
    /// * `Some(actions)` — the package path handled the child. Either the
    ///   package was admitted (actions carry the members' `BroadcastInv` +
    ///   any incumbent `RevokeBroadcast`, plus cascade promotions), or it was
    ///   rejected and the child was itself held for a future descendant
    ///   (empty broadcast actions). In neither case is the child re-staged as
    ///   an orphan.
    fn try_package<V: Validator>(
        &mut self,
        c_bytes: &[u8],
        source: &TxSource,
        now: std::time::Instant,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> Option<Vec<MempoolAction>> {
        let s = validator.peek_structure(c_bytes).ok()?;
        // Walk up to the HELD staged ancestors, ancestors-first. `None` if a
        // missing input has no held creator (a plain orphan) or the walk
        // exceeds `max_package_txs` / `max_family_depth`.
        let held_order = self.collect_held_ancestors(&s.input_box_ids, tip_ctx)?;
        if held_order.is_empty() {
            return None;
        }

        // Overlay = committed + pool outputs + the held ancestors' materialized
        // outputs, so the child's input into a held parent resolves.
        let mut overlay: HashMap<Digest32, ErgoBox> = self.pool.output_map();
        for hid in &held_order {
            if let Some(st) = self.staging.get(hid) {
                if let Some(facts) = &st.validated {
                    for (i, oid) in st.output_box_ids.iter().enumerate() {
                        if let Some(b) = facts.outputs.get(i) {
                            overlay.insert(*oid, b.clone());
                        }
                    }
                }
            }
        }

        // Validate the child against the augmented overlay. This is script eval
        // — charged to CostBudgets regardless of verdict (no free oracle).
        let c_validated =
            match self.validate_package_child(c_bytes, &overlay, source, tip_ctx, validator) {
                Ok(v) => v,
                // A deeper ancestor is still genuinely missing → let the caller hold
                // the child as a plain orphan instead.
                Err(ValidationErr::UnresolvedInput) | Err(ValidationErr::UnresolvedDataInput) => {
                    return None
                }
                // Hard-invalid (or other) → drop the child; the held ancestors stay.
                Err(_) => return Some(Vec::new()),
            };
        let c_weight = self.weight_fn.compute(WeightInputs {
            tx_id: &c_validated.tx_id,
            fee: c_validated.fee,
            size_bytes: c_validated.size_bytes,
            cost: c_validated.consumed_cost,
        });

        // Build the package: held ancestors (facts known) ancestors-first, then
        // the child last.
        let mut members: Vec<PackageMember> = Vec::with_capacity(held_order.len() + 1);
        for hid in &held_order {
            let st = self.staging.get(hid)?;
            let facts = st.validated.as_ref()?;
            members.push(PackageMember {
                tx_id: st.tx_id,
                bytes: st.bytes.clone(),
                input_box_ids: st.input_box_ids.clone(),
                output_box_ids: st.output_box_ids.clone(),
                outputs: facts.outputs.clone(),
                fee: st.fee,
                weight: facts.weight,
                size_bytes: st.size_bytes,
                cost: facts.cost,
                source: st.source.clone(),
            });
        }
        members.push(PackageMember {
            tx_id: c_validated.tx_id,
            bytes: Arc::from(c_bytes),
            input_box_ids: c_validated.input_box_ids.clone(),
            output_box_ids: c_validated.output_box_ids.clone(),
            outputs: c_validated.outputs.clone(),
            fee: c_validated.fee,
            weight: c_weight,
            size_bytes: c_validated.size_bytes,
            cost: c_validated.consumed_cost,
            source: source.clone(),
        });

        // Per-member observability data captured before the vec is consumed.
        let member_meta: Vec<(TxId, u64, u32, u64)> = members
            .iter()
            .map(|m| (m.tx_id, m.fee, m.size_bytes, m.weight))
            .collect();

        match self.commit_package(members, tip_ctx) {
            Some(evicted) => {
                // Package admitted: the held ancestors are now pooled — drop
                // them from staging.
                for hid in &held_order {
                    self.staging.remove(hid);
                }
                let mut actions: Vec<MempoolAction> = Vec::new();
                if !evicted.is_empty() {
                    actions.push(MempoolAction::RevokeBroadcast {
                        tx_ids: evicted.clone(),
                    });
                    actions.push(MempoolAction::Observe {
                        event: ObservedEvent::Evicted {
                            tx_ids: evicted,
                            reason: EvictionReason::DoubleSpendWinner,
                        },
                    });
                }
                // Advertise every newly-pooled member and fire the admitted
                // observer/journal per member (staging itself never gossips —
                // these go out only because the package really entered the
                // pool via the atomic commit).
                for (tx_id, fee, size, weight) in &member_meta {
                    actions.push(MempoolAction::BroadcastInv {
                        tx_id: *tx_id,
                        except: None,
                    });
                    actions.push(MempoolAction::Observe {
                        event: ObservedEvent::Admitted {
                            tx_id: *tx_id,
                            weight: *weight,
                            fee: *fee,
                            size: *size,
                        },
                    });
                    if let Some(obs) = self.observer.as_deref() {
                        obs.on_admitted(*tx_id, *fee, *size);
                    }
                }
                emit_tracing_for_pool_actions(&actions, self.observer.as_deref(), self.tip);
                // Cascade: the newly-pooled members' outputs may resolve other
                // waiting orphans.
                let member_outputs: Vec<Digest32> = member_meta
                    .iter()
                    .filter_map(|(id, _, _, _)| self.pool.get(id).map(|e| e.outputs.clone()))
                    .flatten()
                    .collect();
                let cascade = self.resolve_orphans(member_outputs, now, tip_ctx, validator);
                actions.extend(cascade);
                Some(actions)
            }
            None => {
                // Package rejected. The child validated, so hold IT (so a future
                // descendant can complete a bigger/better package); the held
                // ancestors remain staged untouched.
                let _ = self.staging.stage_held(
                    c_validated.tx_id,
                    Arc::from(c_bytes),
                    c_validated.input_box_ids,
                    c_validated.output_box_ids,
                    c_validated.fee,
                    c_validated.size_bytes,
                    c_weight,
                    c_validated.consumed_cost,
                    c_validated.outputs,
                    source.clone(),
                    now,
                    tip_ctx.tip.height,
                );
                Some(Vec::new())
            }
        }
    }

    /// Walk up from `inputs` collecting the HELD staged ancestors that create
    /// them, in ancestors-first (post-order) order. Returns `None` if any input
    /// that isn't resolvable against pool/committed state has no held creator
    /// (i.e. the package can't be completed — the child is a plain orphan), or
    /// if the walk exceeds `staging_max_package_txs` / `max_family_depth`.
    fn collect_held_ancestors(
        &self,
        inputs: &[Digest32],
        tip_ctx: &admission::TipContext<'_>,
    ) -> Option<Vec<TxId>> {
        let mut order: Vec<TxId> = Vec::new();
        let mut seen: HashSet<TxId> = HashSet::new();
        for input in inputs {
            self.collect_held_rec(input, tip_ctx, &mut order, &mut seen, 0)?;
        }
        Some(order)
    }

    fn collect_held_rec(
        &self,
        input: &Digest32,
        tip_ctx: &admission::TipContext<'_>,
        order: &mut Vec<TxId>,
        seen: &mut HashSet<TxId>,
        depth: usize,
    ) -> Option<()> {
        // Resolvable against pool/committed → an external input, not part of
        // the package.
        if self.pool.parent_for_output(input).is_some() || tip_ctx.utxo.get_box(input).is_some() {
            return Some(());
        }
        if depth > self.config.max_family_depth {
            return None; // walk too deep
        }
        // Must be created by a HELD staged tx to be part of a package.
        let creator = self.staging.creator_of(input)?;
        let st = self.staging.get(&creator)?;
        if !st.is_held() {
            return None; // created by an orphan → package cannot be completed
        }
        if seen.contains(&creator) {
            return Some(()); // already collected (diamond) — keep first position
        }
        // Recurse into this ancestor's inputs FIRST (post-order → ancestors
        // land before dependents).
        let ancestor_inputs = st.input_box_ids.clone();
        for i in &ancestor_inputs {
            self.collect_held_rec(i, tip_ctx, order, seen, depth + 1)?;
        }
        if seen.insert(creator) {
            // Bound total members (held ancestors + the arriving child).
            if order.len() + 2 > self.config.staging_max_package_txs {
                return None;
            }
            order.push(creator);
        }
        Some(())
    }

    /// Validate a package child against an overlay that includes the held
    /// ancestors' outputs, charging the consumed cost to `CostBudgets` on BOTH
    /// the pass and fail paths (identical metering to normal admission — no
    /// free oracle).
    fn validate_package_child<V: Validator>(
        &mut self,
        c_bytes: &[u8],
        overlay: &HashMap<Digest32, ErgoBox>,
        source: &TxSource,
        tip_ctx: &admission::TipContext<'_>,
        validator: &V,
    ) -> Result<Validated, ValidationErr> {
        let cap = JitCost::from_block_cost(self.config.max_tx_cost)
            .map_err(|_| ValidationErr::CostExceeded)?;
        let mut cost = CostAccumulator::new(cap);
        let overlay_view = PoolUtxoOverlay::new(tip_ctx.utxo, overlay);
        let committed_view = CommittedOnly::new(tip_ctx.utxo);
        let mut tx_cx = TxValidationCtx {
            ctx: tip_ctx.tx_context,
            params: tip_ctx.params,
            cost: &mut cost,
            last_headers: tip_ctx.last_headers,
            rules: TxValidationRules {
                reemission: tip_ctx.reemission,
            },
        };
        let res = validator.validate(c_bytes, &overlay_view, &committed_view, &mut tx_cx);
        // Charge regardless of verdict — the invariant is that no staging
        // operation runs script validation without charging CostBudgets.
        self.budgets.charge(source.peer(), cost.consumed());
        res
    }

    /// Decide + atomically commit a package (members ancestors-first, each
    /// fully validated). Runs entirely on a `clone_for_staging` copy so a
    /// rejected package leaves the live pool untouched.
    ///
    /// Admission gate:
    /// * **Package RBF** (any member conflicts with a pooled tx): accept iff
    ///   **R1** the package's aggregate feerate > the conflict closure's AND
    ///   **R2** the package's aggregate absolute fee > the closure's. Both
    ///   required (anti-pinning). On accept the closure is evicted (debiting).
    /// * **Threshold** (no conflict): if the insert would overflow the pool,
    ///   the package's aggregate weight must beat the pool's current lowest.
    ///
    /// Then the members are inserted ancestors-first, each member's weight is
    /// CPFP-credited up its ancestors (descendants-first so a child lifts its
    /// parents), and the post-boost lowest is evicted until the budgets fit —
    /// but NEVER a package member (if a member would be the eviction victim the
    /// whole package is rejected). Returns the evicted incumbent ids on
    /// success, or `None` if the package can't be admitted.
    fn commit_package(
        &mut self,
        members: Vec<PackageMember>,
        _tip_ctx: &admission::TipContext<'_>,
    ) -> Option<Vec<TxId>> {
        let bounds = FamilyBounds::new(
            self.config.max_family_depth,
            self.config.max_family_ops,
            self.config.max_family_update_ms,
        );
        let max_depth = self.config.max_family_depth;

        let pkg_fee: u64 = members
            .iter()
            .map(|m| m.fee)
            .fold(0u64, |a, f| a.saturating_add(f));
        let pkg_size: usize = members.iter().map(|m| m.size_bytes as usize).sum();
        let pkg_cost: u64 = members
            .iter()
            .map(|m| m.cost)
            .fold(0u64, |a, c| a.saturating_add(c));
        let last_id = members.last().map(|m| m.tx_id)?;
        let pkg_weight = self.weight_fn.compute(WeightInputs {
            tx_id: &last_id,
            fee: pkg_fee,
            size_bytes: pkg_size.min(u32::MAX as usize) as u32,
            cost: pkg_cost,
        });

        // Conflict detection over the package's EXTERNAL inputs (inputs not
        // created within the package).
        let internal_outputs: HashSet<Digest32> = members
            .iter()
            .flat_map(|m| m.output_box_ids.iter().copied())
            .collect();
        let external_inputs: Vec<Digest32> = members
            .iter()
            .flat_map(|m| m.input_box_ids.iter().copied())
            .filter(|b| !internal_outputs.contains(b))
            .collect();
        let conflicts = self.pool.conflicts_for_inputs(&external_inputs);

        let mut staged = self.pool.clone_for_staging();
        let mut evicted: Vec<TxId> = Vec::new();

        if !conflicts.is_empty() {
            // ── Package RBF (R1 ∧ R2) ────────────────────────────────────
            // Measure the incumbent conflict closure on a throwaway probe so
            // the aggregates are known BEFORE we decide.
            let mut probe = self.pool.clone_for_staging();
            let mut inc_fee: u64 = 0;
            let mut inc_size: usize = 0;
            let mut inc_cost: u64 = 0;
            let mut inc_seen: HashSet<TxId> = HashSet::new();
            for c in &conflicts {
                for e in probe.remove_with_descendants_debiting(c, max_depth, bounds) {
                    if inc_seen.insert(e.tx_id) {
                        inc_fee = inc_fee.saturating_add(e.fee);
                        inc_size += e.size_bytes as usize;
                        inc_cost = inc_cost.saturating_add(e.cost);
                    }
                }
            }
            let inc_weight = self.weight_fn.compute(WeightInputs {
                tx_id: &conflicts[0],
                fee: inc_fee,
                size_bytes: inc_size.min(u32::MAX as usize) as u32,
                cost: inc_cost,
            });
            // R1: strictly higher aggregate feerate. R2: strictly higher
            // aggregate absolute fee (the anti-pinning teeth). BOTH required.
            if !(pkg_weight > inc_weight && pkg_fee > inc_fee) {
                return None;
            }
            // Accept: evict the incumbent closure from the real staged clone.
            for c in &conflicts {
                for e in staged.remove_with_descendants_debiting(c, max_depth, bounds) {
                    evicted.push(e.tx_id);
                }
            }
        } else {
            // ── Threshold case ───────────────────────────────────────────
            let would_overflow = staged.len() + members.len() > self.config.max_pool_size
                || staged.total_bytes() + pkg_size > self.config.max_pool_bytes;
            if would_overflow {
                if let Some(low) = staged.lowest_weight() {
                    if pkg_weight <= low {
                        return None; // package still underpriced as a unit
                    }
                }
            }
        }

        // Insert members ancestors-first, computing each one's in-pool parents
        // from the (already-inserted) earlier members + committed pool state.
        for m in &members {
            let mut parents: Vec<TxId> = Vec::new();
            let mut seen_p = HashSet::new();
            for input in &m.input_box_ids {
                if let Some(p) = staged.parent_for_output(input) {
                    if seen_p.insert(p) {
                        parents.push(p);
                    }
                }
            }
            let entry = Entry::new(
                m.tx_id,
                m.bytes.clone(),
                m.input_box_ids.clone(),
                m.output_box_ids.clone(),
                parents,
                m.fee,
                m.weight,
                m.size_bytes,
                m.cost,
                m.source.clone(),
            )
            .with_output_boxes(m.outputs.clone());
            if staged.insert(entry).is_err() {
                return None; // (unreachable) collision → reject, discard clone
            }
        }

        // CPFP credit: descendants-first so a child's weight lifts its parents,
        // exactly as single-tx admission credits an ancestor family.
        for m in members.iter().rev() {
            staged.update_family(&m.input_box_ids, i128::from(m.weight), bounds);
        }

        // Evict the post-boost lowest until the budgets fit — but a package
        // member must never be the victim (else the package didn't really fit).
        let member_ids: HashSet<TxId> = members.iter().map(|m| m.tx_id).collect();
        while staged.len() > self.config.max_pool_size
            || staged.total_bytes() > self.config.max_pool_bytes
        {
            let Some(low) = staged.lowest_tx_id() else {
                break;
            };
            if member_ids.contains(&low) {
                return None; // a member would be evicted → reject the package
            }
            for e in staged.remove_with_descendants_debiting(&low, max_depth, bounds) {
                evicted.push(e.tx_id);
            }
        }

        // Every member survived → adopt the staged pool atomically.
        self.pool = staged;
        Some(evicted)
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

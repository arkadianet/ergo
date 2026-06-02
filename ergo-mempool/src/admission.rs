//! Admission pipeline.
//!
//! Implements the 17-step admission sequence with a staging rule: no
//! `OrderedPool` mutation until step 15. Steps 0-14 are decision-only;
//! step 15 commits the decision atomically. This prevents double-spend
//! resolution from silently losing valid old txs when a later check
//! (budget, capacity) rejects the new candidate.
//!
//! Validation is behind the [`Validator`] trait for clean test
//! isolation. Production wires it to
//! `ergo_validation::validate_transaction_parsed`; the
//! [`MockValidator`] below is the unit-test counterpart.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_validation::{ProtocolParams, TransactionContext, TxValidationCtx, UtxoView};
use tracing::warn;

use crate::budget::{BudgetVerdict, CostBudgets};
use crate::invalidation::{InvalidationCache, InvalidationReason, LookupResult};
use crate::overlay::{CommittedOnly, PoolUtxoOverlay};
use crate::pool::{Entry, OrderedPool, PoolError};
use crate::types::{
    EvictionReason, MempoolAction, MempoolConfig, ObservedEvent, PenaltyKind, TipPointer, TxId,
    TxSource,
};
use crate::weight::{WeightFunction, WeightInputs};

/// Everything admission needs from the tip context. Assembled by the
/// node orchestrator and handed in by reference. Carries protocol
/// params and the recent-headers window because script evaluation
/// depends on them (`HEIGHT`, `CONTEXT.headers`, pre-header fields).
pub struct TipContext<'a> {
    pub tip: TipPointer,
    pub best_header_height: u32,
    pub best_full_block_height: u32,
    pub utxo: &'a dyn UtxoView,
    pub tx_context: &'a TransactionContext,
    pub params: &'a ProtocolParams,
    pub last_headers: &'a [Header],
}

impl TipContext<'_> {
    /// Block gap used for the IBD gate. We are "synced" when
    /// `best_header - best_full <= ibd_gate_block_lag`.
    pub fn block_gap(&self) -> u32 {
        self.best_header_height
            .saturating_sub(self.best_full_block_height)
    }
}

/// Bundle of borrows the admission pipeline (`process`, `check`,
/// `commit`) threads end-to-end. Replaces the 11-positional-arg
/// pattern that used to require `#[allow(too_many_arguments)]`.
///
/// `pool` is `&mut` because `commit` (which `process` runs after
/// `check`) inserts and evicts. `check` borrows the same bundle but
/// must NOT mutate `pool` — pool changes belong in `commit` per the
/// 17-step admission contract. The borrow-checker can't enforce
/// that distinction inside a single `&mut AdmissionCtx`, so the
/// invariant is documented and protected by the existing test
/// coverage.
pub struct AdmissionCtx<'a> {
    pub tip_ctx: &'a TipContext<'a>,
    pub config: &'a MempoolConfig,
    pub pool: &'a mut OrderedPool,
    pub budgets: &'a mut CostBudgets,
    pub invalidated: &'a mut InvalidationCache,
    pub unresolved: &'a mut crate::unresolved::UnresolvedCache,
    pub weight_fn: &'a dyn WeightFunction,
}

/// Result of a successful validation. Decoupled from `CheckedTransaction`
/// because the mempool only needs the extracted projection.
#[derive(Debug, Clone)]
pub struct Validated {
    pub tx_id: TxId,
    pub input_box_ids: Vec<Digest32>,
    pub output_box_ids: Vec<Digest32>,
    pub outputs: Vec<ErgoBox>,
    pub fee: u64,
    pub size_bytes: u32,
    pub consumed_cost: u64,
}

/// Validator error classification. Mempool translates each variant
/// into the corresponding admission outcome + peer penalty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationErr {
    /// Bytes did not deserialize into a well-formed transaction.
    Deserialize,
    /// Re-serialization produced different bytes.
    NonCanonical,
    /// Stateless structural violation (size, duplicates, fee output).
    Structural,
    /// An input box was not present in the supplied UTXO view.
    UnresolvedInput,
    /// A data input box was not present in the committed view.
    UnresolvedDataInput,
    /// Script execution rejected the proof.
    ScriptFailed,
    /// ERG/token conservation violated.
    MonetaryFailed,
    /// Cost accumulator exceeded its configured limit.
    CostExceeded,
    /// Anything else validator-defined. Carries a human string for
    /// logs only; admission does not branch on the payload.
    Other(String),
}

/// Pluggable tx validator. Production wires this to ergo-validation;
/// tests inject canned behavior. The validator owns the decision to
/// invoke script evaluation — admission has no opinion on internal
/// validation order, only on the outcome.
/// Cheap pre-validation digest of a parsed tx: just the identity +
/// miner fee. Returned by [`Validator::peek_fee`] so admission can
/// route DroppedBelowMinFee observations with a real tx_id and keep
/// event identity across the min-fee gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeekedTx {
    pub tx_id: TxId,
    pub fee: u64,
}

pub trait Validator {
    /// Cheap pre-check: deserialize `tx_bytes` and extract
    /// `(tx_id, declared miner fee)` without running scripts,
    /// resolving inputs, or touching a `CostAccumulator`. Both
    /// returned fields must match what `validate(..)` would later
    /// expose on its `Validated` for the same bytes; any divergence
    /// is a validator bug.
    ///
    /// Errors: `Deserialize` on malformed bytes. This is the only
    /// error variant `peek_fee` is allowed to return — every other
    /// classification belongs to full validation.
    ///
    /// Overflow policy: fee summation MUST saturate (not panic, not
    /// wrap). A peek_fee value of `u64::MAX` signals "suspiciously
    /// large, pass the gate and let full validation reject via
    /// monetary/structural rules" — cheap gate should never be the
    /// place a malicious tx terminates.
    fn peek_fee(&self, tx_bytes: &[u8]) -> Result<PeekedTx, ValidationErr>;

    /// Validate `tx_bytes` against the supplied UTXO views. The
    /// `input_view` is the `PoolUtxoOverlay` (committed + pool-created),
    /// the `data_input_view` is `CommittedOnly`. Charge consumed cost
    /// to `cx.cost` so the caller can read `cx.cost.consumed()`
    /// afterwards.
    fn validate(
        &self,
        tx_bytes: &[u8],
        input_view: &dyn UtxoView,
        data_input_view: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr>;
}

/// Test-only validator: returns canned decisions per (tx_id, bytes).
/// Exposed at the crate root behind `feature = "test-support"` so
/// integration tests can inject predictable outcomes without leaking
/// the mock into production builds.
#[cfg(any(test, feature = "test-support"))]
pub struct MockValidator {
    /// Responses keyed by raw bytes. If absent, validator errors with
    /// `ValidationErr::Deserialize` so callers can tell "unconfigured"
    /// from "canned success".
    plans: HashMap<Vec<u8>, MockPlan>,
    /// Counts calls to `validate(..)`. Used by tests that prove the
    /// admission pipeline short-circuited before full validation
    /// (e.g. below-min-fee gate).
    validate_calls: std::cell::Cell<usize>,
    /// Counts calls to `peek_fee(..)`. Useful for asserting the cheap
    /// gate runs exactly once per admission.
    peek_fee_calls: std::cell::Cell<usize>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct MockPlan {
    pub result: Result<Validated, ValidationErr>,
    /// Cost to charge into the accumulator before returning.
    pub charge: u64,
    /// Fee value returned from `peek_fee`. Independent of `result` so
    /// tests can stage scenarios like "fee passes min-fee gate but
    /// full validation rejects." If `None`, derived from the plan:
    /// successful `result.fee` or 0 for rejections.
    pub peek_fee: Option<u64>,
    /// Tx id returned from `peek_fee`. If `None`, derived from the
    /// plan: successful `result.tx_id` or `Digest32::ZERO` for
    /// rejections. Tests staging Err-result-with-passing-peek-fee
    /// should set this so the admission event carries a meaningful
    /// id.
    pub peek_tx_id: Option<TxId>,
}

#[cfg(any(test, feature = "test-support"))]
impl Default for MockValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl MockValidator {
    pub fn new() -> Self {
        Self {
            plans: HashMap::new(),
            validate_calls: std::cell::Cell::new(0),
            peek_fee_calls: std::cell::Cell::new(0),
        }
    }

    pub fn plan(mut self, bytes: impl Into<Vec<u8>>, plan: MockPlan) -> Self {
        self.plans.insert(bytes.into(), plan);
        self
    }

    pub fn validate_call_count(&self) -> usize {
        self.validate_calls.get()
    }

    pub fn peek_fee_call_count(&self) -> usize {
        self.peek_fee_calls.get()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Validator for MockValidator {
    fn peek_fee(&self, tx_bytes: &[u8]) -> Result<PeekedTx, ValidationErr> {
        self.peek_fee_calls.set(self.peek_fee_calls.get() + 1);
        // Mock reports (tx_id, fee) per the plan's overrides, or
        // falls back to the plan's result (successful validation's
        // values, or zeros on a planned error). Production
        // `ErgoValidator` deserializes + computes tx_id via
        // bytes_to_sign + matches fee proposition.
        let plan = self.plans.get(tx_bytes).ok_or(ValidationErr::Deserialize)?;
        let default_fee = match &plan.result {
            Ok(v) => v.fee,
            Err(_) => 0,
        };
        let default_tx_id = match &plan.result {
            Ok(v) => v.tx_id,
            Err(_) => ergo_primitives::digest::Digest32::ZERO,
        };
        Ok(PeekedTx {
            tx_id: plan.peek_tx_id.unwrap_or(default_tx_id),
            fee: plan.peek_fee.unwrap_or(default_fee),
        })
    }

    fn validate(
        &self,
        tx_bytes: &[u8],
        _input_view: &dyn UtxoView,
        _data_input_view: &dyn UtxoView,
        cx: &mut TxValidationCtx<'_>,
    ) -> Result<Validated, ValidationErr> {
        self.validate_calls.set(self.validate_calls.get() + 1);
        let plan = self
            .plans
            .get(tx_bytes)
            .cloned()
            .ok_or(ValidationErr::Deserialize)?;
        // Always charge; even on rejection the mempool must see the
        // consumed cost to apply partial-charge semantics. Test stub
        // tolerates JitCost overflow by silently skipping the charge —
        // tests exercising overflow set `plan.charge` themselves.
        if let Ok(jc) = JitCost::from_block_cost(plan.charge) {
            let _ = cx.cost.add(jc);
        }
        plan.result
    }
}

/// Outcome of a single `admission::process()` call. Actions are emitted
/// in parallel with the outcome so callers can route both at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// Tx admitted. May have triggered replacement or eviction — the
    /// accompanying actions list carries `RevokeBroadcast` entries.
    /// `fee` and `size` are echoed from the validated payload so
    /// callers (sync, API, log tailers) can record them without a
    /// second pool lookup.
    Admitted { tx_id: TxId, fee: u64, size: u32 },
    /// Tx rejected, no pool mutation, possibly with peer penalty in
    /// the actions list.
    Rejected { reason: RejectReason },
}

/// Outcome of a single `admission::check()` call. Same set of rejection
/// reasons as `AdmissionOutcome` but the success arm carries enough
/// state to drive a subsequent commit (used internally by `process`).
/// API `/check[Bytes]` callers ignore the commit-only fields.
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    /// Tx would be admitted: validation succeeded, all gates passed,
    /// the pool would accept it after evicting `replaced_ids`.
    WouldAdmit {
        validated: Validated,
        weight: u64,
        replaced_ids: Vec<TxId>,
    },
    /// Tx would be rejected, no pool mutation. `check` and `process`
    /// produce the same `RejectReason` for the same input — `check` is
    /// the decision phase of `process`.
    Rejected { reason: RejectReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    Disabled,
    IbdGated,
    /// Tip context could not be assembled (cold headers, no full block
    /// applied yet). Surfaced by API callers when `build_tip_context`
    /// returns `None`; admission itself does not produce this reason
    /// because it requires a `TipContext` argument. API translates this
    /// to `400 reason: "tip_unready"`.
    TipUnready,
    PeerBudgetExhausted,
    GlobalBudgetExhausted,
    SizeLimit,
    RecentlyUnresolved,
    Deserialize,
    NonCanonical,
    KnownInvalid,
    Duplicate,
    Structural,
    BelowMinFee,
    UnresolvedInput,
    UnresolvedDataInput,
    ValidationFailed {
        kind: ValidationErr,
    },
    DoubleSpendLoser,
    PoolFull,
    InsertCollision,
}

/// Pure-logic admission. No `&mut self` on the mempool here — callers
/// thread the individual pieces in. The top-level `Mempool::process()`
/// wraps this and supplies the components from its own fields.
///
/// Run the full admission pipeline (steps 0-17) and commit on success.
///
/// Thin wrapper over `check` + `commit`. Used by P2P inbound, JSON-RPC
/// `/transactions` (broadcast), and revalidation. For `/check[Bytes]`
/// callers that must not mutate the pool, call `check` directly.
pub fn process<V: Validator>(
    tx_bytes: &[u8],
    source: TxSource,
    now: Instant,
    cx: &mut AdmissionCtx<'_>,
    validator: &V,
) -> (AdmissionOutcome, Vec<MempoolAction>) {
    let (outcome, mut actions) = check(tx_bytes, &source, now, cx, validator);
    match outcome {
        CheckOutcome::Rejected { reason } => (AdmissionOutcome::Rejected { reason }, actions),
        CheckOutcome::WouldAdmit {
            validated,
            weight,
            replaced_ids,
        } => {
            let admit = commit(
                cx,
                tx_bytes,
                &source,
                validated,
                weight,
                replaced_ids,
                &mut actions,
            );
            (admit, actions)
        }
    }
}

/// Run admission steps 0-14 against the pool *without committing*.
///
/// Mutates anti-DoS state (`budgets`, `invalidated`, `unresolved`) per
/// mempool invariant #7 — failed validation must charge cost and
/// populate caches even on /check, otherwise the endpoint is a free
/// oracle for unmetered script execution. `check` reads the pool only;
/// pool mutations happen in `commit` per the staging contract on
/// [`AdmissionCtx`].
///
/// Returns `WouldAdmit` carrying the data `commit` needs to insert
/// (validated payload, weight, replacement set), or `Rejected` with the
/// classifying reason. The action list mirrors what `process` would
/// emit through step 14: observability events plus peer penalties.
/// `Inv`/`RevokeBroadcast` are commit-only and never appear here.
pub fn check<V: Validator>(
    tx_bytes: &[u8],
    source: &TxSource,
    now: Instant,
    cx: &mut AdmissionCtx<'_>,
    validator: &V,
) -> (CheckOutcome, Vec<MempoolAction>) {
    let mut actions: Vec<MempoolAction> = Vec::new();
    let peer = source.peer();

    // ── Step 0 — IBD gate (skipped for demoted revalidation) ─────────
    // Demoted txs are re-entering from our own rollback path; we are
    // by definition already at tip for them.
    if !matches!(source, TxSource::DemotedFromBlock)
        && cx.tip_ctx.block_gap() > cx.config.ibd_gate_block_lag
    {
        actions.push(MempoolAction::Observe {
            event: ObservedEvent::DroppedIbdGated,
        });
        return (
            CheckOutcome::Rejected {
                reason: RejectReason::IbdGated,
            },
            actions,
        );
    }

    // ── Step 1 — Pre-validation budget gate ──────────────────────────
    match cx.budgets.pre_admission_check(peer) {
        BudgetVerdict::Ok => {}
        BudgetVerdict::PeerExhausted => {
            return (
                CheckOutcome::Rejected {
                    reason: RejectReason::PeerBudgetExhausted,
                },
                actions,
            );
        }
        BudgetVerdict::GlobalExhausted => {
            return (
                CheckOutcome::Rejected {
                    reason: RejectReason::GlobalBudgetExhausted,
                },
                actions,
            );
        }
    }

    // ── Step 2 — Size cap ────────────────────────────────────────────
    if tx_bytes.len() > cx.config.max_tx_size_bytes {
        if let Some(p) = peer {
            actions.push(MempoolAction::Penalize {
                peer: p,
                kind: PenaltyKind::Misbehavior,
            });
        }
        return (
            CheckOutcome::Rejected {
                reason: RejectReason::SizeLimit,
            },
            actions,
        );
    }

    // ── Step 3 — Unresolved-input cache ──────────────────────────────
    if cx.unresolved.contains(tx_bytes, now) {
        return (
            CheckOutcome::Rejected {
                reason: RejectReason::RecentlyUnresolved,
            },
            actions,
        );
    }

    // ── Step 3.5 — Cheap fee peek + min-fee gate ─────────────────────
    // Matches Scala's `ErgoMemPool.process` ordering: reject below-min-
    // fee BEFORE UTXO resolution or script validation so a flood of
    // sub-min-fee txs cannot force us to burn script-eval cycles.
    // `peek_fee` only deserializes + sums canonical fee outputs; no
    // cost counter, no input resolution.
    let peek_fee_value = match validator.peek_fee(tx_bytes) {
        Ok(f) => f,
        Err(ValidationErr::Deserialize) => {
            if let Some(p) = peer {
                actions.push(MempoolAction::Penalize {
                    peer: p,
                    kind: PenaltyKind::Misbehavior,
                });
            }
            return (
                CheckOutcome::Rejected {
                    reason: RejectReason::Deserialize,
                },
                actions,
            );
        }
        Err(other) => {
            // `peek_fee` is contractually allowed to return only
            // Deserialize. Anything else is a validator bug — treat
            // as deserialize + note for debugging.
            warn!(error = ?other, "peek_fee returned unexpected error");
            if let Some(p) = peer {
                actions.push(MempoolAction::Penalize {
                    peer: p,
                    kind: PenaltyKind::Misbehavior,
                });
            }
            return (
                CheckOutcome::Rejected {
                    reason: RejectReason::Deserialize,
                },
                actions,
            );
        }
    };
    // Now that peek succeeded, the canonical tx_id is known. Record
    // it on the parent span so all subsequent events from this admission
    // (validation, classification, commit) carry the id automatically.
    tracing::Span::current().record(
        "tx_id",
        tracing::field::display(hex::encode(peek_fee_value.tx_id.as_bytes())),
    );

    if peek_fee_value.fee < cx.config.min_relay_fee_nano_erg {
        // Observability: carry the real tx_id computed during peek
        // so the event stream keeps per-tx identity across the gate.
        actions.push(MempoolAction::Observe {
            event: ObservedEvent::DroppedBelowMinFee {
                tx_id: peek_fee_value.tx_id,
                fee: peek_fee_value.fee,
            },
        });
        return (
            CheckOutcome::Rejected {
                reason: RejectReason::BelowMinFee,
            },
            actions,
        );
    }

    // Build overlay from the pool's materialized output boxes.
    // Empty for tests that don't exercise pool-chaining; populated in
    // production once admission threads `output_boxes` onto Entry.
    let pool_outputs: HashMap<Digest32, ErgoBox> = cx.pool.output_map();
    let overlay_view = PoolUtxoOverlay::new(cx.tip_ctx.utxo, &pool_outputs);
    let committed_view = CommittedOnly::new(cx.tip_ctx.utxo);

    // ── Steps 4–6 and 9–12 — validator handles deserialize, tx_id,
    //    canonical check, structural, monetary, script. Cost is charged
    //    into `cost` below regardless of outcome.
    //
    // `from_block_cost` overflow here is a config-level invariant
    // breach (max_tx_cost set above the JitCost SCALA_INT_MAX bound).
    // Unreachable from honest mainnet config (pin test in
    // ergo-primitives `cost.rs`), but route as `CostExceeded` rather
    // than panic so a misconfigured node rejects the tx cleanly.
    let cap = match JitCost::from_block_cost(cx.config.max_tx_cost) {
        Ok(c) => c,
        Err(_) => {
            return (
                CheckOutcome::Rejected {
                    reason: RejectReason::ValidationFailed {
                        kind: ValidationErr::CostExceeded,
                    },
                },
                actions,
            );
        }
    };
    let mut cost = CostAccumulator::new(cap);
    let mut tx_cx = TxValidationCtx {
        ctx: cx.tip_ctx.tx_context,
        params: cx.tip_ctx.params,
        cost: &mut cost,
        last_headers: cx.tip_ctx.last_headers,
    };
    let validated = match validator.validate(tx_bytes, &overlay_view, &committed_view, &mut tx_cx) {
        Ok(v) => v,
        Err(err) => {
            // Charge whatever cost the validator consumed.
            let consumed = cost.consumed();
            cx.budgets.charge(peer, consumed);

            // Classify the error for routing + peer penalty.
            let (reason, penalty) = classify(&err, cx.tip_ctx);
            if let (Some(p), Some(k)) = (peer, penalty) {
                actions.push(MempoolAction::Penalize { peer: p, kind: k });
            }
            // Record in invalidation cache so a resubmission is spam.
            // Exception: UnresolvedInput goes to the unresolved-bytes
            // cache, not invalidation (it may be resolvable later).
            match &err {
                ValidationErr::UnresolvedInput | ValidationErr::UnresolvedDataInput => {
                    cx.unresolved.insert(tx_bytes, now);
                }
                _ => {
                    // We need the tx_id to key the invalidation cache.
                    // For errors pre-dating tx_id computation (deserialize,
                    // non-canonical) we hash the bytes as a proxy. This
                    // matches our intent: the same bad bytes should not
                    // cost us validation cycles again.
                    let key = match &err {
                        ValidationErr::Deserialize | ValidationErr::NonCanonical => {
                            *ergo_primitives::digest::blake2b256(tx_bytes).as_bytes()
                        }
                        _ => {
                            // Post-tx_id errors would ideally use the
                            // actual tx_id. Validator contract here:
                            // errors past deserialize carry enough
                            // data for caller to reconstruct tx_id,
                            // but since we bail on err without a
                            // Validated payload, we fall back to
                            // bytes-hash. Acceptable: worst case a
                            // different encoding of the same tx with
                            // different bytes gets validated again.
                            *ergo_primitives::digest::blake2b256(tx_bytes).as_bytes()
                        }
                    };
                    cx.invalidated.insert(
                        ergo_primitives::digest::Digest32::from_bytes(key),
                        InvalidationReason::ValidationFailed,
                        now,
                    );
                }
            }
            return (CheckOutcome::Rejected { reason }, actions);
        }
    };

    // ── Step 5 — Invalidation cache (keyed on tx_id, now available) ──
    match cx.invalidated.record_hit(&validated.tx_id, now) {
        LookupResult::NotCached => {}
        LookupResult::FirstHit => {
            actions.push(MempoolAction::Observe {
                event: ObservedEvent::DroppedKnownInvalid {
                    tx_id: validated.tx_id,
                },
            });
            return (
                CheckOutcome::Rejected {
                    reason: RejectReason::KnownInvalid,
                },
                actions,
            );
        }
        LookupResult::RepeatHit { .. } => {
            if let Some(p) = peer {
                actions.push(MempoolAction::Penalize {
                    peer: p,
                    kind: PenaltyKind::Spam,
                });
            }
            return (
                CheckOutcome::Rejected {
                    reason: RejectReason::KnownInvalid,
                },
                actions,
            );
        }
    }

    // ── Step 8 — Duplicate ───────────────────────────────────────────
    if cx.pool.contains(&validated.tx_id) {
        return (
            CheckOutcome::Rejected {
                reason: RejectReason::Duplicate,
            },
            actions,
        );
    }

    // ── Step 10 — Min-fee consistency assert ─────────────────────────
    // Step 3.5 already gated on `peek_fee`; reaching here means we
    // admitted the tx past that gate. If `validated.fee` disagrees
    // with `peek_fee_value`, the validator has a bug (peek extracts
    // differently than validate). Surface this as a hard debug
    // assert: production builds fall through without a panic (the
    // decision is already made by peek_fee); debug builds crash so
    // the divergence is impossible to miss.
    debug_assert_eq!(
        validated.fee, peek_fee_value.fee,
        "validator disagreement: peek_fee returned fee={}, validate returned fee={}",
        peek_fee_value.fee, validated.fee,
    );
    debug_assert_eq!(
        validated.tx_id, peek_fee_value.tx_id,
        "validator disagreement: peek_fee returned tx_id={:?}, validate returned tx_id={:?}",
        peek_fee_value.tx_id, validated.tx_id,
    );

    // ── Step 12 (conflict collection) — read by_input for
    //    conflicting tx_ids the new candidate would replace.
    let conflicts = cx.pool.conflicts_for_inputs(&validated.input_box_ids);

    // ── Step 13 — Compute weight; decide double-spend resolution.
    let weight = cx.weight_fn.compute(WeightInputs {
        tx_id: &validated.tx_id,
        fee: validated.fee,
        size_bytes: validated.size_bytes,
        cost: validated.consumed_cost,
    });
    let replacement = if conflicts.is_empty() {
        ReplacementDecision::NoConflict
    } else {
        // avg = sum(conflict weights) / conflict count, in u128.
        let sum: u128 = conflicts
            .iter()
            .filter_map(|id| cx.pool.get(id).map(|e| e.weight as u128))
            .sum();
        let avg = sum / conflicts.len() as u128;
        if (weight as u128) > avg {
            ReplacementDecision::Replace(conflicts.clone())
        } else {
            // Losing the double-spend still charges cost.
            cx.budgets.charge(peer, validated.consumed_cost);
            actions.push(MempoolAction::Observe {
                event: ObservedEvent::DroppedDoubleSpendLoser {
                    tx_id: validated.tx_id,
                },
            });
            return (
                CheckOutcome::Rejected {
                    reason: RejectReason::DoubleSpendLoser,
                },
                actions,
            );
        }
    };

    // ── Step 14 — Charge cost, check capacity plan.
    cx.budgets.charge(peer, validated.consumed_cost);

    // Capacity plan: check whether the new tx can fit after replacements.
    // Commit step loops evictions until both budgets clear; this phase
    // only decides whether to proceed at all.
    let replaced_ids: Vec<TxId> = match &replacement {
        ReplacementDecision::NoConflict => Vec::new(),
        ReplacementDecision::Replace(ids) => ids.clone(),
    };
    let replaced_bytes: usize = replaced_ids
        .iter()
        .filter_map(|id| cx.pool.get(id).map(|e| e.bytes.len()))
        .sum();
    let capacity_after = cx
        .pool
        .len()
        .saturating_sub(replaced_ids.len())
        .saturating_add(1);
    let bytes_after = cx
        .pool
        .total_bytes()
        .saturating_sub(replaced_bytes)
        .saturating_add(validated.size_bytes as usize);
    let over_count = capacity_after > cx.config.max_pool_size;
    let over_bytes = bytes_after > cx.config.max_pool_bytes;
    if over_count || over_bytes {
        // Guard 1: new tx alone exceeds the byte cap — can never fit even
        // with an empty pool. Reject before the commit loop is entered.
        if validated.size_bytes as usize > cx.config.max_pool_bytes {
            actions.push(MempoolAction::Observe {
                event: ObservedEvent::DroppedPoolFull {
                    tx_id: validated.tx_id,
                },
            });
            return (
                CheckOutcome::Rejected {
                    reason: RejectReason::PoolFull,
                },
                actions,
            );
        }
        // Guard 2: new tx is not heavier than the current minimum and is
        // not a replacement — eviction would not improve the pool.
        if let Some(id) = cx.pool.lowest_tx_id() {
            let lowest_weight = cx.pool.get(&id).map(|e| e.weight).unwrap_or(0);
            if weight <= lowest_weight && replaced_ids.is_empty() {
                actions.push(MempoolAction::Observe {
                    event: ObservedEvent::DroppedPoolFull {
                        tx_id: validated.tx_id,
                    },
                });
                return (
                    CheckOutcome::Rejected {
                        reason: RejectReason::PoolFull,
                    },
                    actions,
                );
            }
        }
    }

    (
        CheckOutcome::WouldAdmit {
            validated,
            weight,
            replaced_ids,
        },
        actions,
    )
}

/// Steps 15 + 17 — apply the validated, capacity-cleared candidate to
/// the pool and emit `Inv`/`RevokeBroadcast`/`Observe` actions.
///
/// `commit` assumes its caller already charged cost via `check`; it
/// performs no anti-DoS bookkeeping. The pre-checks in `check` make
/// the eviction loop terminate (the new tx is heavier than the
/// remaining minimum and fits the byte cap on its own).
fn commit(
    cx: &mut AdmissionCtx<'_>,
    tx_bytes: &[u8],
    source: &TxSource,
    validated: Validated,
    weight: u64,
    replaced_ids: Vec<TxId>,
    actions: &mut Vec<MempoolAction>,
) -> AdmissionOutcome {
    let peer = source.peer();

    // ── Step 15 — Commit.
    let mut removed_for_actions: Vec<TxId> = Vec::new();
    // Capture per-loser weight before removal so the `Replaced`
    // observation can carry the weight delta without a second read.
    // Only direct conflicts (entries in `replaced_ids`) are losers in
    // the replacement decision; CPFP descendants are collateral and
    // surface via the `Evicted` event below.
    let mut replaced_losers: Vec<(TxId, u64)> = Vec::with_capacity(replaced_ids.len());
    for id in &replaced_ids {
        let loser_weight = cx.pool.get(id).map(|e| e.weight).unwrap_or(0);
        replaced_losers.push((*id, loser_weight));
        let removed = cx
            .pool
            .remove_with_descendants(id, cx.config.cpfp_max_family_depth);
        for e in removed {
            removed_for_actions.push(e.tx_id);
        }
    }
    // Evict lowest-priority entries until both count and byte budgets fit.
    // Replacements are already removed, so pool state is current. The
    // pre-checks above guarantee the new tx itself is <= max_pool_bytes
    // and is heavier than any remaining minimum, so this loop terminates.
    while cx.pool.len() + 1 > cx.config.max_pool_size
        || cx.pool.total_bytes() + validated.size_bytes as usize > cx.config.max_pool_bytes
    {
        if let Some(id) = cx.pool.lowest_tx_id() {
            let removed = cx
                .pool
                .remove_with_descendants(&id, cx.config.cpfp_max_family_depth);
            for e in removed {
                removed_for_actions.push(e.tx_id);
            }
        } else {
            break; // pool empty; new tx alone fits (pre-checked above)
        }
    }

    // Compute parents_in_pool now that removals are done.
    let parents_in_pool: Vec<TxId> = {
        let mut seen = std::collections::HashSet::new();
        let mut parents = Vec::new();
        for input in &validated.input_box_ids {
            if let Some(parent) = cx.pool.parent_for_output(input) {
                if seen.insert(parent) {
                    parents.push(parent);
                }
            }
        }
        parents
    };

    let entry = Entry::new(
        validated.tx_id,
        Arc::from(tx_bytes.to_vec().into_boxed_slice()),
        validated.input_box_ids.clone(),
        validated.output_box_ids.clone(),
        parents_in_pool,
        validated.fee,
        weight,
        validated.size_bytes,
        validated.consumed_cost,
        source.clone(),
    )
    .with_output_boxes(validated.outputs.clone());
    match cx.pool.insert(entry) {
        Ok(()) => {}
        Err(PoolError::Duplicate(_)) => {
            // Unreachable: step 8 checked. Fail safe.
            return AdmissionOutcome::Rejected {
                reason: RejectReason::Duplicate,
            };
        }
        Err(PoolError::OutputCollision(_)) => {
            return AdmissionOutcome::Rejected {
                reason: RejectReason::InsertCollision,
            };
        }
    }

    // ── Step 17 — Emit actions.
    if !removed_for_actions.is_empty() {
        actions.push(MempoolAction::RevokeBroadcast {
            tx_ids: removed_for_actions.clone(),
        });
        actions.push(MempoolAction::Observe {
            event: ObservedEvent::Evicted {
                tx_ids: removed_for_actions,
                reason: if !replaced_ids.is_empty() {
                    EvictionReason::DoubleSpendWinner
                } else {
                    EvictionReason::LowWeight
                },
            },
        });
    }
    // Per-loser `Replaced` observation for forensic logging. Fires only
    // for direct double-spend conflicts (CPFP descendants are folded
    // into the `Evicted` event above, not separately attributed).
    for (loser_id, weight_loser) in replaced_losers {
        actions.push(MempoolAction::Observe {
            event: ObservedEvent::Replaced {
                loser_id,
                winner_id: validated.tx_id,
                weight_loser,
                weight_winner: weight,
            },
        });
    }
    actions.push(MempoolAction::BroadcastInv {
        tx_id: validated.tx_id,
        except: peer,
    });
    actions.push(MempoolAction::Observe {
        event: ObservedEvent::Admitted {
            tx_id: validated.tx_id,
            weight,
            fee: validated.fee,
            size: validated.size_bytes,
        },
    });
    AdmissionOutcome::Admitted {
        tx_id: validated.tx_id,
        fee: validated.fee,
        size: validated.size_bytes,
    }
}

enum ReplacementDecision {
    NoConflict,
    Replace(Vec<TxId>),
}

fn classify(err: &ValidationErr, tip_ctx: &TipContext<'_>) -> (RejectReason, Option<PenaltyKind>) {
    let at_tip = tip_ctx.block_gap() == 0;
    match err {
        ValidationErr::Deserialize => (RejectReason::Deserialize, Some(PenaltyKind::Misbehavior)),
        ValidationErr::NonCanonical => (RejectReason::NonCanonical, Some(PenaltyKind::Misbehavior)),
        ValidationErr::Structural => (RejectReason::Structural, Some(PenaltyKind::Misbehavior)),
        ValidationErr::UnresolvedInput => (RejectReason::UnresolvedInput, None),
        ValidationErr::UnresolvedDataInput => (RejectReason::UnresolvedDataInput, None),
        ValidationErr::ScriptFailed => (
            RejectReason::ValidationFailed { kind: err.clone() },
            if at_tip {
                Some(PenaltyKind::Misbehavior)
            } else {
                None
            },
        ),
        ValidationErr::MonetaryFailed | ValidationErr::CostExceeded => (
            RejectReason::ValidationFailed { kind: err.clone() },
            if at_tip {
                Some(PenaltyKind::Misbehavior)
            } else {
                None
            },
        ),
        ValidationErr::Other(_) => (RejectReason::ValidationFailed { kind: err.clone() }, None),
    }
}

#[cfg(test)]
mod tests;

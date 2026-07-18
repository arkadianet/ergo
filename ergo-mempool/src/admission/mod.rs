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
use ergo_validation::{TxValidationCtx, TxValidationRules};
use tracing::warn;

use crate::budget::BudgetVerdict;
use crate::overlay::{CommittedOnly, PoolUtxoOverlay};
use crate::pool::{Entry, FamilyBounds, OrderedPool, PoolError};
use crate::types::{
    EvictionReason, MempoolAction, MempoolConfig, ObservedEvent, PenaltyKind, TxId, TxSource,
};
use crate::weight::WeightInputs;

mod context;
#[cfg(any(test, feature = "test-support"))]
mod mock;
mod outcome;
mod revalidate;

pub use context::{AdmissionCtx, PeekedTx, TipContext, Validated, ValidationErr, Validator};
#[cfg(any(test, feature = "test-support"))]
pub use mock::{MockPlan, MockValidator};
pub use outcome::{AdmissionOutcome, CheckOutcome, RejectReason};
pub use revalidate::revalidate_pooled;
pub(crate) use revalidate::{is_hard_invalid, record_failed_tx};

use outcome::{classify, ReplacementDecision};

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

    // Demoted txs (our OWN, re-admitted after a rollback / epoch-demote) bypass
    // the anti-DoS cost budget just as they bypass the IBD gate below: they are
    // not adversarial traffic, and the drain is already bounded by
    // `revalidation_per_tick`. For `DemotedFromBlock`, `peer` is `None`, so only
    // the GLOBAL cap ever applied — disabling that gate (and its charge) is what
    // keeps a multi-tick drain from tripping `GlobalExhausted` and stranding the
    // popped-but-not-re-admitted tail (those entries are already off the queue,
    // so a budget reject would silently lose a valid tx). Scoped to demoted
    // only: `Wallet` (also peer-less) stays gated — it's new local work a
    // rejection simply bounces back to the caller, not an irreversible drain.
    let budget_exempt = matches!(source, TxSource::DemotedFromBlock);

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

    // ── Step 1 — Pre-validation budget gate (skipped for demoted) ────
    if !budget_exempt {
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
        rules: TxValidationRules {
            reemission: cx.tip_ctx.reemission,
        },
    };
    let validated = match validator.validate(tx_bytes, &overlay_view, &committed_view, &mut tx_cx) {
        Ok(v) => v,
        Err(err) => {
            // Charge whatever cost the validator consumed (skipped for demoted
            // re-admission — see `budget_exempt`).
            if !budget_exempt {
                cx.budgets.charge(peer, cost.consumed());
            }

            // Classify the error for routing + peer penalty.
            let (reason, penalty) = classify(&err, cx.tip_ctx);
            if let (Some(p), Some(k)) = (peer, penalty) {
                actions.push(MempoolAction::Penalize { peer: p, kind: k });
            }
            // Route the failed tx into the right anti-DoS cache (blacklist
            // vs unresolved vs neither). Shared with the proactive recheck
            // so the two paths never diverge — the canonical tx_id is the
            // step-3.5 peek id, the same key the step-5 record_hit below and
            // the Inv-skip gate in ergo-node messaging look up.
            record_failed_tx(
                cx.invalidated,
                cx.unresolved,
                peek_fee_value.tx_id,
                tx_bytes,
                &err,
                now,
            );
            return (CheckOutcome::Rejected { reason }, actions);
        }
    };

    // No invalidation-cache check here, deliberately. The cache is a
    // FETCH filter, consumed only by `Mempool::is_invalidated` on the
    // Inv path (ergo-node messaging) — exactly Scala's sole use of
    // `invalidatedTxIds` (`ErgoNodeViewSynchronizer.scala:1119`).
    // Scala's `ErgoMemPool.process` never consults it: bytes that
    // arrive anyway are re-validated and accepted if they pass. That
    // matters for two real flows with the same proof-excluded tx_id:
    // a tx resubmitted with corrected proofs, and reorg-demoted txs
    // re-entering via `TxSource::DemotedFromBlock` — both must land
    // in the pool, not be held out for the cache TTL. It also caps
    // the proof-malleability poisoning surface: a third party
    // mangling a victim tx's proofs can suppress our Inv fetch (as
    // on Scala) but cannot block direct (re)submission.

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
            // Losing the double-spend still charges cost (skipped for demoted).
            if !budget_exempt {
                cx.budgets.charge(peer, validated.consumed_cost);
            }
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
    if !budget_exempt {
        cx.budgets.charge(peer, validated.consumed_cost);
    }

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

    // ── Step 15 — Commit. The new tx is inserted, its ancestors are
    //    family-credited, then the post-boost lowest is evicted if over budget
    //    (Scala `OrderedTxPool.put` evicts `orderedTransactions.last` only after
    //    `updateFamily`, so victim selection sees boosted weights). A commit
    //    that can evict — a replacement or an overflowing insert — runs on a
    //    clone and swaps into the live pool only if the new tx survives, so a
    //    rejected admission never mutates the pool; the common path mutates in
    //    place.
    let bounds = FamilyBounds::new(
        cx.config.max_family_depth,
        cx.config.max_family_ops,
        cx.config.max_family_update_ms,
    );
    let needs_staging = !replaced_ids.is_empty()
        || cx.pool.len().saturating_add(1) > cx.config.max_pool_size
        || cx
            .pool
            .total_bytes()
            .saturating_add(validated.size_bytes as usize)
            > cx.config.max_pool_bytes;

    let CommitOutcome {
        removed_for_actions,
        replaced_losers,
    } = if needs_staging {
        let mut staged = cx.pool.clone_for_staging();
        match apply_commit(
            &mut staged,
            &validated,
            weight,
            &replaced_ids,
            bounds,
            cx.config,
            tx_bytes,
            source,
        ) {
            Err(reason) => return AdmissionOutcome::Rejected { reason },
            Ok(outcome) if staged.contains(&validated.tx_id) => {
                *cx.pool = staged;
                outcome
            }
            Ok(_) => {
                // The new tx was its own post-boost eviction victim. Discard
                // the staged pool: a rejected admission must leave the live
                // pool untouched. (Scala would trim-and-report-Accepted; we
                // prefer a clean reject with no side effects.)
                actions.push(MempoolAction::Observe {
                    event: ObservedEvent::DroppedPoolFull {
                        tx_id: validated.tx_id,
                    },
                });
                return AdmissionOutcome::Rejected {
                    reason: RejectReason::PoolFull,
                };
            }
        }
    } else {
        // Fast path: no replacement and the insert cannot overflow, so no
        // eviction runs and the new tx always survives — mutate in place.
        match apply_commit(
            cx.pool,
            &validated,
            weight,
            &replaced_ids,
            bounds,
            cx.config,
            tx_bytes,
            source,
        ) {
            Err(reason) => return AdmissionOutcome::Rejected { reason },
            Ok(outcome) => outcome,
        }
    };

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

/// Result of [`apply_commit`]: ids removed (for `RevokeBroadcast`/`Evicted`)
/// and per-loser weights (for the `Replaced` observation).
struct CommitOutcome {
    removed_for_actions: Vec<TxId>,
    replaced_losers: Vec<(TxId, u64)>,
}

/// Apply the commit mutations to `pool`: remove double-spend losers (debiting
/// their ancestors), insert the new tx, family-credit its ancestors, then evict
/// the post-boost lowest until both budgets fit. Run on the live pool (fast
/// path) or on a clone the caller swaps in only if the new tx survives. Returns
/// `Err` on an (unreachable, fail-safe) insert collision — the caller maps it
/// to a rejection; on the staged path the clone is simply discarded.
#[allow(clippy::too_many_arguments)]
fn apply_commit(
    pool: &mut OrderedPool,
    validated: &Validated,
    weight: u64,
    replaced_ids: &[TxId],
    bounds: FamilyBounds,
    config: &MempoolConfig,
    tx_bytes: &[u8],
    source: &TxSource,
) -> Result<CommitOutcome, RejectReason> {
    let mut removed_for_actions: Vec<TxId> = Vec::new();

    // 15a — remove direct double-spend losers (+ their CPFP descendants),
    //       debiting each removed subtree out of its surviving ancestors.
    //       Capture per-loser weight first for the `Replaced` observation.
    //
    //       Losers are removed before the winner is inserted, whereas Scala
    //       `ErgoMemPool.process` removes them after (`put(new).remove(conflicts)`):
    //       `by_input` holds one spender per box, so the winner and a conflicting
    //       loser cannot coexist in the pool. With a full pool this keeps an
    //       unrelated lowest tx that Scala's pre-removal capacity eviction would
    //       drop — a one-tx mempool-membership difference, never a consensus one;
    //       ordering is unaffected.
    // Capture every loser's weight BEFORE any removal: one conflict can be a
    // descendant of another, and removing the first as a subtree would zero a
    // later loser's recorded weight.
    let replaced_losers: Vec<(TxId, u64)> = replaced_ids
        .iter()
        .map(|id| (*id, pool.get(id).map(|e| e.weight).unwrap_or(0)))
        .collect();
    for id in replaced_ids {
        for e in pool.remove_with_descendants_debiting(id, config.max_family_depth, bounds) {
            removed_for_actions.push(e.tx_id);
        }
    }

    // 15b — compute parents_in_pool now that loser removals are done.
    let parents_in_pool: Vec<TxId> = {
        let mut seen = std::collections::HashSet::new();
        let mut parents = Vec::new();
        for input in &validated.input_box_ids {
            if let Some(parent) = pool.parent_for_output(input) {
                if seen.insert(parent) {
                    parents.push(parent);
                }
            }
        }
        parents
    };

    let entry = Entry::new(
        validated.tx_id,
        Arc::<[u8]>::from(tx_bytes),
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
    match pool.insert(entry) {
        Ok(()) => {}
        // Unreachable: step 8 checked duplicates. Fail safe.
        Err(PoolError::Duplicate(_)) => return Err(RejectReason::Duplicate),
        Err(PoolError::OutputCollision(_)) => return Err(RejectReason::InsertCollision),
    }

    // 15c — CPFP family credit: propagate the new tx's own weight up to its
    //       in-pool ancestors (Scala `put` → `updateFamily(+weight)`).
    pool.update_family(&validated.input_box_ids, i128::from(weight), bounds);

    // 15d — evict the post-boost lowest until both budgets fit. Runs after
    //       insert+credit so a boosted parent is no longer the victim; each
    //       eviction debits its ancestors. The new tx may itself be the lowest
    //       (Scala parity); the caller's staging discards the commit if so.
    while pool.len() > config.max_pool_size || pool.total_bytes() > config.max_pool_bytes {
        let Some(id) = pool.lowest_tx_id() else {
            break; // pool empty; new tx alone fits (pre-checked in `check`)
        };
        for e in pool.remove_with_descendants_debiting(&id, config.max_family_depth, bounds) {
            removed_for_actions.push(e.tx_id);
        }
    }

    Ok(CommitOutcome {
        removed_for_actions,
        replaced_losers,
    })
}

#[cfg(test)]
mod tests;

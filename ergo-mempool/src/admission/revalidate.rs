//! The second entry point into validation: re-validating an
//! already-pooled tx (`revalidate_pooled`) for the proactive
//! recheck-and-evict pass, plus the shared failure-classification policy
//! (`record_failed_tx`, `is_hard_invalid`). Distinct from the admission
//! pipeline — these are driven from `Mempool::recheck_one` /
//! `recheck_and_evict` / `recheck_ids`, not from `process`/`check`.

use std::collections::HashMap;
use std::time::Instant;

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_validation::{TxValidationCtx, TxValidationRules};

use crate::invalidation::{InvalidationCache, InvalidationReason};
use crate::overlay::{CommittedOnly, PoolUtxoOverlay};
use crate::types::TxId;

use super::context::{TipContext, ValidationErr, Validator};

/// Re-validate an already-pooled tx against a tip+1 context for the proactive
/// recheck-and-evict pass (the mempool-tip-revalidation feature). Runs ONLY the
/// stateful validation — the same `Validator::validate` path `check` uses, with
/// the same `PoolUtxoOverlay` (regular inputs) + `CommittedOnly` (data inputs)
/// views — WITHOUT admission's duplicate/conflict/replacement/capacity/insert
/// machinery (the tx is already in the pool). Returns the cost the validator
/// actually consumed (available on BOTH the `Ok` and `Err` paths so the caller
/// charges it to its per-pass budget regardless of verdict) together with the
/// pass/fail verdict. `pool_outputs` is built ONCE per pass by the caller —
/// `OrderedPool::output_map` is O(pool), so it must not be rebuilt per tx.
pub fn revalidate_pooled<V: Validator>(
    tx_bytes: &[u8],
    tip_ctx: &TipContext<'_>,
    pool_outputs: &HashMap<Digest32, ErgoBox>,
    max_tx_cost: u64,
    validator: &V,
) -> (u64, Result<(), ValidationErr>) {
    let overlay_view = PoolUtxoOverlay::new(tip_ctx.utxo, pool_outputs);
    let committed_view = CommittedOnly::new(tip_ctx.utxo);
    let cap = match JitCost::from_block_cost(max_tx_cost) {
        Ok(c) => c,
        // Misconfig (max_tx_cost above the JitCost bound): treat as a cost
        // failure rather than panic — mirrors `check`'s handling.
        Err(_) => return (0, Err(ValidationErr::CostExceeded)),
    };
    let mut cost = CostAccumulator::new(cap);
    let mut tx_cx = TxValidationCtx {
        ctx: tip_ctx.tx_context,
        params: tip_ctx.params,
        cost: &mut cost,
        last_headers: tip_ctx.last_headers,
        rules: TxValidationRules {
            reemission: tip_ctx.reemission,
        },
    };
    let verdict = validator
        .validate(tx_bytes, &overlay_view, &committed_view, &mut tx_cx)
        .map(|_| ());
    (cost.consumed(), verdict)
}

/// Route a failed tx into the right anti-DoS CACHE. This is the classification
/// policy shared by admission (`check`) and the proactive recheck
/// (`Mempool::recheck_and_evict`) for the caching decision ("what does a failure
/// mean for relay"). The two paths agree on caching, with ONE deliberate
/// asymmetry on the separate EVICTION decision: a `ValidationErr::Other(_)` is
/// blacklisted here (so admission stops re-fetching a rejected new tx) but is
/// NOT a recheck eviction trigger (`is_recheck_evictable` excludes it), so an
/// already-pooled tx hitting an internal/contract `Other(_)` is kept rather than
/// dropped + blacklisted.
///
/// * `UnresolvedInput` / `UnresolvedDataInput` → the unresolved-bytes cache,
///   NOT the blacklist: the input may become resolvable later (a parent tx
///   arrives, or a reorg restores a spent box), so the tx stays re-admittable.
/// * `Deserialize` / `NonCanonical` → neither cache: the only id available is
///   computed from the *parsed* form, so a blacklist entry would also damn a
///   canonical re-encoding. Scala likewise skips `invalidatedTxIds` for
///   re-parse failures (`ErgoMemPool.process`).
/// * everything else (script/monetary/structural/cost, plus the validator's
///   catch-all `Other`) → the invalidation cache, keyed by the canonical
///   `tx_id`, so the Inv path stops re-fetching these bytes
///   (`Mempool::is_invalidated`). Mirrors Scala `OrderedTxPool.invalidate`.
///   NB: this set is NOT identical to `is_recheck_evictable` — it additionally
///   includes `Other` (which admission blacklists but recheck does not evict
///   on), and excludes `UnresolvedDataInput` (which recheck evicts on but keeps
///   re-admittable rather than blacklisting).
pub(crate) fn record_failed_tx(
    invalidated: &mut InvalidationCache,
    unresolved: &mut crate::unresolved::UnresolvedCache,
    tx_id: TxId,
    tx_bytes: &[u8],
    err: &ValidationErr,
    now: Instant,
) {
    match err {
        ValidationErr::UnresolvedInput | ValidationErr::UnresolvedDataInput => {
            unresolved.insert(tx_bytes, now);
        }
        ValidationErr::Deserialize | ValidationErr::NonCanonical => {}
        _ => {
            invalidated.insert(tx_id, InvalidationReason::ValidationFailed, now);
        }
    }
}

/// Is `err` a PROVABLE consensus invalidity — a hard rule failure the tx itself
/// caused (script/monetary/structural/cost), reproducible at any tip? Returns
/// true for exactly that set; false for everything else: non-resolution
/// failures (`UnresolvedInput`/`UnresolvedDataInput`), parse-class failures
/// (`Deserialize`/`NonCanonical`), AND the validator's catch-all `Other(_)`.
///
/// The proactive recheck (`Mempool::recheck_and_evict`) evicts on this set plus
/// `UnresolvedDataInput` — see [`is_recheck_evictable`], which is the predicate
/// that pass actually asks. The classes excluded from BOTH are not proof the tx
/// is invalid at the new tip:
/// * An unresolved SPEND input can be a transient reorg-dependency (a demoted
///   parent pending re-admission) — dropping such a tx to the unresolved-bytes
///   cache (a suppression filter, not a re-admit queue) would lose a valid tx —
///   or it is a confirmed double-spend already evicted by `on_tip_change`'s
///   input-conflict cascade. Parse-class failures cannot occur on
///   already-pooled canonical bytes.
/// * `Other(_)` is the validator's catch-all for INTERNAL/contract failures
///   (resolved-inputs mismatch, internal-invariant violation — see
///   `validator.rs` `map_validation_error`), not a consensus verdict on the tx,
///   so it is not safe proof to drop + blacklist an already-accepted pooled tx.
///
/// Enumerated as a positive allowlist (not a negation) so any future
/// `ValidationErr` variant is excluded — and thus NOT evicted on — until it is
/// explicitly judged a provable invalidity. This set is intentionally NARROWER
/// than `record_failed_tx`'s blacklist arm, which also blacklists `Other(_)` on
/// a rejected new tx in admission; see that fn for the (intentional) asymmetry.
pub(crate) fn is_hard_invalid(err: &ValidationErr) -> bool {
    matches!(
        err,
        ValidationErr::Structural
            | ValidationErr::ScriptFailed
            | ValidationErr::MonetaryFailed
            | ValidationErr::CostExceeded
    )
}

/// Should the proactive recheck EVICT a pooled tx that failed with `err`?
///
/// [`is_hard_invalid`] plus one case it deliberately excludes:
/// `UnresolvedDataInput`. Data inputs resolve against the COMMITTED view only
/// (`revalidate_pooled` passes `CommittedOnly`, never the pool overlay), so
/// unlike a regular `UnresolvedInput` — which can be a demoted parent still
/// waiting in the revalidation queue — an unresolved DATA input means the box
/// is simply not in the UTXO set at this tip. Nothing in the pool can ever
/// supply it, and `on_tip_change`'s input-conflict cascade does not cover it
/// (that indexes spend inputs, not data inputs), so without this the tx sits in
/// the pool until it is squeezed out by weight — for a low-weight tx, forever.
/// Scala evicts it: `CleanupWorker.validatePool` eliminates EVERY tx whose
/// re-validation fails (`CleanupWorker.scala:94-97` →
/// `EliminateTransactions` → `ErgoMemPool.invalidate`), and a missing
/// data-input box is such a failure.
///
/// A reorg that restores the spent box can make the tx valid again; that is why
/// `record_failed_tx` routes this class to the re-admittable unresolved-bytes
/// cache rather than the blacklist, so the tx can simply be re-submitted.
pub(crate) fn is_recheck_evictable(err: &ValidationErr) -> bool {
    is_hard_invalid(err) || matches!(err, ValidationErr::UnresolvedDataInput)
}

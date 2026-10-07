//! Admission outcomes + rejection taxonomy: `AdmissionOutcome`,
//! `CheckOutcome`, `RejectReason`, plus the internal
//! `ReplacementDecision` and the error->reason `classify` policy the
//! pipeline uses.

use crate::types::{PenaltyKind, TxId};

use super::context::{TipContext, Validated, ValidationErr};

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
    /// The single-transaction decision rejects, without pool mutation.
    /// `Mempool::process` can subsequently admit a package using staged
    /// ancestors; `Mempool::check` does not run that package path.
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
    /// Local relay policy; the transaction may still be valid in a block.
    StorageRentPolicy,
    UnresolvedInput,
    UnresolvedDataInput,
    ValidationFailed {
        kind: ValidationErr,
    },
    DoubleSpendLoser,
    PoolFull,
    InsertCollision,
}

pub(crate) enum ReplacementDecision {
    NoConflict,
    Replace(Vec<TxId>),
}

/// Payload captured when a fully-validated transaction loses the
/// fee/capacity gate (`PoolFull`) or a double-spend contest
/// (`DoubleSpendLoser`) but is a candidate to be HELD in the staging pool:
/// a booster child arriving later could complete an admissible package.
///
/// It is surfaced out-of-band from `check` / `process` via a
/// `&mut Option<HeldCandidate>`, NOT baked into `CheckOutcome` /
/// `AdmissionOutcome`, so the external rejection shape (and every existing
/// match site) is unchanged. It is consumed ONLY by `Mempool::process`;
/// `Mempool::check` (the `/check` path) passes a throwaway `&mut None` and
/// therefore can never stage. Because the tx was already fully validated
/// and its cost already charged to `CostBudgets`, holding it runs no extra
/// validation and opens no free-oracle hole.
#[derive(Debug, Clone)]
pub struct HeldCandidate {
    pub validated: Validated,
    pub weight: u64,
}

pub(crate) fn classify(
    err: &ValidationErr,
    tip_ctx: &TipContext<'_>,
) -> (RejectReason, Option<PenaltyKind>) {
    let at_tip = tip_ctx.block_gap() == 0;
    match err {
        ValidationErr::Deserialize => (RejectReason::Deserialize, Some(PenaltyKind::Misbehavior)),
        // A local encoding policy is not evidence of peer misbehaviour.
        ValidationErr::NonCanonical => (RejectReason::NonCanonical, None),
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
        ValidationErr::ReemissionPolicy => {
            (RejectReason::ValidationFailed { kind: err.clone() }, None)
        }
        ValidationErr::Other(_) => (RejectReason::ValidationFailed { kind: err.clone() }, None),
    }
}

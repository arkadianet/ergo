//! Ergo mempool: a Rust-native, single-writer, action-transcript mempool.
//!
//! Sits on top of [`ergo_primitives`], [`ergo_ser`], [`ergo_validation`],
//! and [`ergo_state`]. Provides the [`Mempool`] handle that bundles the
//! pool, anti-DoS budgets, invalidation / unresolved caches, and the
//! revalidation queue, plus the action transcript emitted to the
//! caller (P2P / RPC) on every state transition.
//!
//! Module map:
//!
//! * [`pool`] — `OrderedPool` ordered by `WeightFunction`, with
//!   per-input and per-output indexes for overlay / conflict checks.
//! * [`admission`] — admission pipeline: parse → structural →
//!   monetary → script → cost budget → insert. Drives [`Validator`]
//!   under the store's active protocol parameters.
//! * [`weight`] — weight functions that order the pool
//!   (`ByCost` / `ByMin` / `BySize`).
//! * [`budget`] — global + per-peer cost budgets with eviction.
//! * [`invalidation`] / [`unresolved`] — TTL'd caches: known-bad
//!   tx ids and unresolved-input tx bodies pending parents.
//! * [`overlay`] — `PoolUtxoOverlay` for `/utxo/withPool/*` reads.
//! * [`reorg`] — on-tip-change + revalidation tick handlers.
//! * [`revalidation`] — bounded-size queue of demoted-then-pending
//!   tx bodies driven by `tick_revalidation`.
//! * [`validator`] — `ErgoValidator` adapter that wires the pool's
//!   admission steps onto `ergo_validation::tx::validate_transaction`.
//! * [`types`] — shared types: `MempoolConfig`, `MempoolAction`,
//!   `TxId`, `TipPointer`, `TxDiff`, `TxSource`, etc.

pub mod admission;
pub mod budget;
pub mod invalidation;
mod mempool;
pub mod overlay;
pub mod pool;
pub mod reorg;
pub mod revalidation;
pub mod snapshot;
mod telemetry;
pub mod types;
pub mod unresolved;
pub mod validator;
pub mod weight;

pub use admission::{
    AdmissionOutcome, CheckOutcome, RejectReason, Validated, ValidationErr, Validator,
};
#[cfg(any(test, feature = "test-support"))]
pub use admission::{MockPlan, MockValidator};
pub use budget::{BudgetVerdict, CostBudgets};
pub use invalidation::{InvalidationCache, InvalidationReason, LookupResult};
pub use mempool::Mempool;
pub use overlay::{CommittedOnly, PoolUtxoOverlay};
pub use pool::{Entry, OrderedPool, PoolError};
pub use reorg::{on_tip_change, tick_revalidation};
pub use revalidation::RevalidationQueue;
pub use snapshot::MempoolReadSnapshot;
// `TxDiffError` is the state-crate type at its source location. The
// re-export keeps `ergo_mempool::TxDiffError` resolving to one shared
// definition, matching the spec at `tx_diff_since -> Result<TxDiff,
// TxDiffError>` while removing the in-tree duplicate.
pub use ergo_state::diff::TxDiffError;
pub use types::{
    AppliedTx, DemotedTx, EvictionReason, MempoolAction, MempoolConfig, ObservedEvent, PeerId,
    PenaltyKind, TipPointer, TxDiff, TxId, TxSource,
};
pub use unresolved::UnresolvedCache;
pub use validator::ErgoValidator;
pub use weight::{ByCost, ByMin, BySize, WeightFunction, WeightInputs, SCALE};

use ergo_primitives::digest::Digest32;

/// Sink for mempool admission/eviction telemetry — the tap the operator
/// WS/webhook surface (`ergo-api`'s realtime bus) hangs off of.
///
/// Defined here, not in `ergo-api`, so `ergo-mempool` never depends on
/// `ergo-api` types; the node/API layer implements this trait against
/// whatever it wants to feed (a `RealtimeBus`, a metrics counter, a test
/// spy) and hands `Mempool::set_observer` an `Arc<dyn MempoolObserver>`.
///
/// Calls happen inline on the admission hot path under `&mut Mempool` —
/// implementations must be cheap and non-blocking (no `.await`, no lock
/// contention with the WS fan-out). Fired from the same call sites as the
/// `mempool_tx_admitted` / `mempool_tx_evicted` / `mempool_tx_replaced`
/// tracing events, and ONLY for real state transitions: check-only
/// (`Mempool::check`) and would-admit outcomes never call this.
///
/// All callbacks describe **this node's pool under this node's policy /
/// tip** — not a network-wide mempool oracle.
pub trait MempoolObserver: Send + Sync {
    /// A tx was admitted to the pool.
    fn on_admitted(&self, tx_id: TxId, fee: u64, size_bytes: u32);
    /// A tx left the pool without confirming (policy eviction, tip-invalid,
    /// etc.). `reason` is `EvictionReason`'s `Debug` rendering — a short,
    /// stable tag. Never used for `EvictionReason::Confirmed` (see
    /// [`on_confirmed`]) or replacement losers (see [`on_replaced`]).
    fn on_evicted(&self, tx_id: TxId, reason: &str);
    /// A pooled tx was applied in our tip. Not a drop — confirmation.
    fn on_confirmed(&self, tx_id: TxId, height: u32, header_id: Digest32);
    /// Loser of a same-node replacement / weight fight. `winner_id` is the
    /// tx that stayed (or entered) the pool.
    fn on_replaced(&self, loser_id: TxId, winner_id: TxId);
}

/// Order demoted txs PARENT-BEFORE-CHILD for re-admission by `tick_revalidation`.
///
/// `snapshot` is `(tx_id, in_pool_parents, bytes)` for every demoted tx, in
/// priority (weight) order. `demote_all_for_revalidation` demotes the WHOLE
/// pool, so every parent edge points within the set. A child's inputs resolve
/// against its parent's pool output, so the drain must re-admit the parent
/// first; the raw weight order can place a high-fee child ahead of its low-fee
/// parent. Kahn's topological sort, sweeping in the input (priority) order so
/// independent txs keep their relative priority as a tie-break. The spend DAG is
/// acyclic; any entry left unemitted by an unexpected cycle is appended in input
/// order so nothing is dropped. O(N²) worst case (a deep chain), bounded by
/// `max_pool_size` and only run on the infrequent demote-all (epoch/reorg) path.
pub(crate) fn topological_demote_order(
    snapshot: Vec<(TxId, Vec<TxId>, std::sync::Arc<[u8]>)>,
) -> Vec<DemotedTx> {
    use std::collections::{HashMap, HashSet};
    let in_set: HashSet<TxId> = snapshot.iter().map(|(id, _, _)| *id).collect();
    // Remaining in-degree = count of in-set parents not yet emitted.
    let mut indeg: HashMap<TxId, usize> = HashMap::with_capacity(snapshot.len());
    let mut children: HashMap<TxId, Vec<TxId>> = HashMap::new();
    for (id, parents, _) in &snapshot {
        indeg.insert(*id, parents.iter().filter(|p| in_set.contains(p)).count());
        for p in parents {
            if in_set.contains(p) {
                children.entry(*p).or_default().push(*id);
            }
        }
    }
    let bytes_of: HashMap<TxId, std::sync::Arc<[u8]>> =
        snapshot.iter().map(|(id, _, b)| (*id, b.clone())).collect();
    let order: Vec<TxId> = snapshot.iter().map(|(id, _, _)| *id).collect();
    let mut emitted: HashSet<TxId> = HashSet::with_capacity(snapshot.len());
    let mut out: Vec<DemotedTx> = Vec::with_capacity(snapshot.len());
    loop {
        let mut progressed = false;
        for id in &order {
            if emitted.contains(id) || indeg.get(id).copied().unwrap_or(0) != 0 {
                continue;
            }
            emitted.insert(*id);
            out.push(DemotedTx {
                tx_id: *id,
                bytes: bytes_of[id].clone(),
            });
            progressed = true;
            if let Some(ch) = children.get(id) {
                for c in ch {
                    if let Some(d) = indeg.get_mut(c) {
                        *d = d.saturating_sub(1);
                    }
                }
            }
        }
        if !progressed {
            break;
        }
    }
    // Defensive: append any unemitted entries (only on an unexpected cycle) in
    // input order — never drop a demoted tx.
    if out.len() < order.len() {
        for id in &order {
            if !emitted.contains(id) {
                out.push(DemotedTx {
                    tx_id: *id,
                    bytes: bytes_of[id].clone(),
                });
            }
        }
    }
    out
}

//! Transaction selection: priority-order pruning under cost + size budgets.
//!
//! Mirrors the budget-tracking loop inside Scala
//! `CandidateGenerator.collectTxs` (`CandidateGenerator.scala:842-939`).
//! That function does three things in one pass:
//!
//! 1. Iterate mempool in priority order.
//! 2. Re-validate each tx against the upcoming state.
//! 3. Accumulate while under `max_block_cost - safety_gap` and
//!    `max_block_size`.
//!
//! This module implements the **budget-tracking** half (step 3) on a
//! pre-validated `MempoolReadSnapshot`. The candidate orchestrator
//! is responsible for the per-tx validator call (step 2), which
//! requires a `TxValidationCtx` we don't have at this layer.
//!
//! `Entry::cost` and `Entry::size_bytes` are populated during
//! mempool admission, so reading them here is free.

use ergo_mempool::pool::Entry;
use ergo_mempool::MempoolReadSnapshot;

/// Conservative gap between `max_block_cost` and the cost budget we
/// actually use during selection. Scala uses a `safe_cost_gap` ~150k
/// nanoERG (`CandidateGenerator.scala:584-590`) to absorb estimator
/// variance — a tx that passed admission at cost C may execute at
/// up to C + gap during block validation. Mining stops `gap` below
/// the real ceiling so a candidate it builds never trips the
/// post-validation cost-overrun reject.
pub const DEFAULT_COST_SAFETY_GAP: u64 = 150_000;

/// Selection outcome — owned entries plus the running totals.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    /// Transactions chosen for inclusion, in priority order.
    pub entries: Vec<Entry>,
    /// Sum of `entry.cost` across [`Selection::entries`].
    pub total_cost: u64,
    /// Sum of `entry.size_bytes` across [`Selection::entries`].
    pub total_size: u64,
}

impl Selection {
    /// Number of selected entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Select transactions in priority order, stopping at the first tx
/// whose addition would push either the cost or the size budget
/// past their limit.
///
/// `cost_budget` is treated as `max_block_cost - safety_gap`; the
/// caller is responsible for subtracting the gap. Mining
/// orchestration uses [`DEFAULT_COST_SAFETY_GAP`].
///
/// `size_budget` is the raw `max_block_size`. Block-level
/// serialization overhead is small; we don't reserve a separate gap.
pub fn select_by_budget(
    snapshot: &MempoolReadSnapshot,
    cost_budget: u64,
    size_budget: u64,
) -> Selection {
    let mut out = Selection::default();
    for entry in snapshot.iter() {
        let next_cost = out.total_cost.saturating_add(entry.cost);
        let next_size = out.total_size.saturating_add(u64::from(entry.size_bytes));
        if next_cost > cost_budget || next_size > size_budget {
            break;
        }
        out.entries.push(entry.clone());
        out.total_cost = next_cost;
        out.total_size = next_size;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_mempool::pool::Entry;
    use ergo_mempool::types::TxSource;
    use ergo_primitives::digest::Digest32;

    fn synth(weight: u64, cost: u64, size: u32, tx_id_seed: u8) -> Entry {
        let mut tx_id_bytes = [0u8; 32];
        tx_id_bytes[0] = tx_id_seed;
        Entry {
            tx_id: Digest32::from_bytes(tx_id_bytes),
            bytes: std::sync::Arc::from(Vec::<u8>::new().into_boxed_slice()),
            inputs: Vec::new(),
            outputs: Vec::new(),
            parents_in_pool: Vec::new(),
            fee: 0,
            weight,
            size_bytes: size,
            cost,
            created_at: std::time::Instant::now(),
            last_checked_at: std::time::Instant::now(),
            source: TxSource::Api,
            output_boxes: Vec::new(),
        }
    }

    // ----- happy path -----

    #[test]
    fn empty_snapshot_yields_empty_selection() {
        let snap = MempoolReadSnapshot::from_entries(Vec::new());
        let sel = select_by_budget(&snap, 1_000_000, 1_000_000);
        assert!(sel.is_empty());
        assert_eq!(sel.total_cost, 0);
        assert_eq!(sel.total_size, 0);
    }

    #[test]
    fn under_both_budgets_takes_all() {
        let snap = MempoolReadSnapshot::from_entries(vec![
            synth(100, 1000, 500, 1),
            synth(80, 2000, 600, 2),
            synth(50, 500, 200, 3),
        ]);
        let sel = select_by_budget(&snap, 10_000, 10_000);
        assert_eq!(sel.len(), 3);
        assert_eq!(sel.total_cost, 3500);
        assert_eq!(sel.total_size, 1300);
    }

    #[test]
    fn cost_overrun_stops_at_first_offender() {
        // tx[0] cost 800. tx[1] cost 500 -> 1300. Budget = 1000.
        // First tx fits; second overruns; stop. Sel = [tx[0]].
        let snap = MempoolReadSnapshot::from_entries(vec![
            synth(100, 800, 100, 1),
            synth(80, 500, 100, 2),
            synth(50, 100, 100, 3), // even though this fits standalone, we stopped
        ]);
        let sel = select_by_budget(&snap, 1000, 1_000_000);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel.entries[0].tx_id.as_bytes()[0], 1);
        assert_eq!(sel.total_cost, 800);
    }

    #[test]
    fn size_overrun_stops_at_first_offender() {
        let snap = MempoolReadSnapshot::from_entries(vec![
            synth(100, 100, 800, 1),
            synth(80, 100, 500, 2),
        ]);
        let sel = select_by_budget(&snap, 1_000_000, 1000);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel.entries[0].tx_id.as_bytes()[0], 1);
        assert_eq!(sel.total_size, 800);
    }

    #[test]
    fn zero_budget_takes_nothing() {
        let snap = MempoolReadSnapshot::from_entries(vec![synth(100, 1, 1, 1)]);
        assert!(select_by_budget(&snap, 0, 0).is_empty());
    }

    #[test]
    fn priority_order_is_preserved() {
        // Build entries; iterate; check we got them in input order
        // (the snapshot itself is already priority-ordered by the
        // mempool — this layer just respects that order).
        let snap = MempoolReadSnapshot::from_entries(vec![
            synth(100, 10, 10, 7),
            synth(99, 10, 10, 5),
            synth(98, 10, 10, 3),
        ]);
        let sel = select_by_budget(&snap, 100, 100);
        let ids: Vec<u8> = sel.entries.iter().map(|e| e.tx_id.as_bytes()[0]).collect();
        assert_eq!(ids, vec![7, 5, 3]);
    }
}

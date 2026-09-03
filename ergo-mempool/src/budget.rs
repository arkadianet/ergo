//! Global, per-peer, and local-reserve cost budgets.
//!
//! Budgets are charged post-validation (admission step 15) with
//! partial cost on validation failure. A pre-validation gate (step 1)
//! short-circuits when a budget is already exhausted so a malicious
//! peer cannot force script evaluation on an exhausted node. All
//! budgets reset on every `ApplyBlock` event.
//!
//! Remote and local traffic draw on SEPARATE pools. Peer-sourced txs
//! contend for `global_cap` among themselves; node-local submissions
//! (`TxSource::Api` / `TxSource::Wallet`) may additionally draw on
//! `local_reserved`, which no peer can ever touch. Without that split a
//! single flooding peer that spends the whole shared global budget also
//! blocks the operator's own `POST /transactions` submissions until the
//! next block. Scala has no cost budget on this path at all: a
//! `LocallyGeneratedTransaction` goes straight to `txModify`
//! (`ErgoNodeViewHolder.scala:659`), so reserving headroom for local
//! work moves us TOWARD the reference node, not away from it.

use std::collections::HashMap;

use crate::types::PeerId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetVerdict {
    /// Within budget; caller proceeds.
    Ok,
    /// Per-peer budget would be exceeded (or already is).
    PeerExhausted,
    /// Global budget would be exceeded (or already is).
    GlobalExhausted,
}

/// Which pool a transaction's validation cost is charged against.
///
/// `TxSource::DemotedFromBlock` has no variant here: demoted re-admission is
/// budget-exempt upstream in `admission::check_capturing_held` and never
/// reaches these counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetSource {
    /// Remote traffic from `peer`. Contends for `global_cap` with every
    /// other peer, and for `per_peer_cap` with itself.
    Peer(PeerId),
    /// Node-local submission (`TxSource::Api` / `TxSource::Wallet`), which
    /// may spend into `local_reserved` after `global_cap` is gone.
    Local,
}

pub struct CostBudgets {
    global_cap: u64,
    per_peer_cap: u64,
    local_reserved: u64,
    /// Cost charged by REMOTE sources since the last reset. Gated on
    /// `global_cap` alone, so local work never shrinks the peer allowance.
    remote_consumed: u64,
    /// Cost charged by LOCAL sources since the last reset.
    local_consumed: u64,
    per_peer_consumed: HashMap<PeerId, u64>,
}

impl CostBudgets {
    /// `local_reserved` is the extra headroom local submissions get ON TOP of
    /// `global_cap`; `0` restores the single shared pool.
    pub fn new(global_cap: u64, per_peer_cap: u64, local_reserved: u64) -> Self {
        Self {
            global_cap,
            per_peer_cap,
            local_reserved,
            remote_consumed: 0,
            local_consumed: 0,
            per_peer_consumed: HashMap::new(),
        }
    }

    /// Total cost charged this block across every source. Observational —
    /// no gate reads it (peers are gated on `remote_consumed`, locals on this
    /// total against `global_cap + local_reserved`).
    pub fn global_consumed(&self) -> u64 {
        self.remote_consumed.saturating_add(self.local_consumed)
    }

    /// Cost charged by remote peers this block — the figure the peer-facing
    /// global gate compares against `global_cap`.
    pub fn remote_consumed(&self) -> u64 {
        self.remote_consumed
    }

    pub fn peer_consumed(&self, peer: &PeerId) -> u64 {
        self.per_peer_consumed.get(peer).copied().unwrap_or(0)
    }

    /// The ceiling a local submission is gated on: the peer-contended cap
    /// plus the reserve peers cannot reach.
    fn local_cap(&self) -> u64 {
        self.global_cap.saturating_add(self.local_reserved)
    }

    /// Pre-validation gate. Returns whether a new tx of unknown cost
    /// is allowed to proceed at all. Rejects if the applicable budget is
    /// already exhausted — no validation cycles spent.
    pub fn pre_admission_check(&self, source: BudgetSource) -> BudgetVerdict {
        self.verdict(source)
    }

    /// Charge `cost` after admission step 12. Called on both success and
    /// validation failure. Saturating adds — a single runaway validation
    /// cannot wrap the counter.
    pub fn charge(&mut self, source: BudgetSource, cost: u64) {
        match source {
            BudgetSource::Peer(p) => {
                self.remote_consumed = self.remote_consumed.saturating_add(cost);
                let slot = self.per_peer_consumed.entry(p).or_insert(0);
                *slot = slot.saturating_add(cost);
            }
            BudgetSource::Local => {
                self.local_consumed = self.local_consumed.saturating_add(cost);
            }
        }
    }

    /// Post-charge check: after charging, did we exceed caps? Admission
    /// uses this for the step-15 decision that turns partial-cost
    /// rejection into a penalty signal.
    pub fn post_charge_verdict(&self, source: BudgetSource) -> BudgetVerdict {
        self.verdict(source)
    }

    /// Shared gate for the pre- and post-charge checks: both ask the same
    /// question ("is this source's budget gone?") and must never diverge.
    fn verdict(&self, source: BudgetSource) -> BudgetVerdict {
        match source {
            BudgetSource::Peer(p) => {
                if self.remote_consumed >= self.global_cap {
                    return BudgetVerdict::GlobalExhausted;
                }
                if self.peer_consumed(&p) >= self.per_peer_cap {
                    return BudgetVerdict::PeerExhausted;
                }
                BudgetVerdict::Ok
            }
            BudgetSource::Local => {
                if self.global_consumed() >= self.local_cap() {
                    return BudgetVerdict::GlobalExhausted;
                }
                BudgetVerdict::Ok
            }
        }
    }

    /// Reset counters. Called on every `ApplyBlock`.
    pub fn reset(&mut self) {
        self.remote_consumed = 0;
        self.local_consumed = 0;
        self.per_peer_consumed.clear();
    }

    /// Drop per-peer bookkeeping on disconnect. The remote and local running
    /// totals are unaffected — the work was still done this block.
    pub fn forget_peer(&mut self, peer: &PeerId) {
        self.per_peer_consumed.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // ----- helpers -----

    fn peer(n: u16) -> PeerId {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000 + n)
    }

    fn src(n: u16) -> BudgetSource {
        BudgetSource::Peer(peer(n))
    }

    /// global 1_000, per-peer 100, no local reserve — the pre-reserve shape,
    /// so these cases pin the unchanged peer-contention behaviour.
    fn budgets() -> CostBudgets {
        CostBudgets::new(1_000, 100, 0)
    }

    // ----- happy path -----

    #[test]
    fn new_budgets_admit_everything() {
        let b = budgets();
        assert_eq!(b.pre_admission_check(src(1)), BudgetVerdict::Ok);
        assert_eq!(
            b.pre_admission_check(BudgetSource::Local),
            BudgetVerdict::Ok
        );
    }

    #[test]
    fn charging_a_peer_only_affects_that_peer() {
        let mut b = budgets();
        b.charge(src(1), 50);
        assert_eq!(b.peer_consumed(&peer(1)), 50);
        assert_eq!(b.peer_consumed(&peer(2)), 0);
        assert_eq!(b.global_consumed(), 50);
        assert_eq!(b.remote_consumed(), 50);
    }

    #[test]
    fn local_charges_leave_the_peer_allowance_intact() {
        let mut b = budgets();
        b.charge(BudgetSource::Local, 500);
        assert_eq!(b.global_consumed(), 500);
        assert_eq!(b.remote_consumed(), 0, "local work is not peer work");
        assert!(b.per_peer_consumed.is_empty());
        assert_eq!(
            b.pre_admission_check(src(1)),
            BudgetVerdict::Ok,
            "peers keep their full global_cap regardless of local traffic"
        );
    }

    #[test]
    fn pre_admission_rejects_exhausted_peer() {
        let mut b = budgets();
        b.charge(src(1), 100);
        assert_eq!(b.pre_admission_check(src(1)), BudgetVerdict::PeerExhausted);
        // Other peer still OK.
        assert_eq!(b.pre_admission_check(src(2)), BudgetVerdict::Ok);
    }

    #[test]
    fn pre_admission_rejects_exhausted_global() {
        let mut b = budgets();
        b.charge(src(1), 1_000);
        assert_eq!(
            b.pre_admission_check(src(2)),
            BudgetVerdict::GlobalExhausted,
            "other peers blocked once the peer-contended global cap is gone"
        );
    }

    #[test]
    fn reset_clears_all_counters() {
        let mut b = budgets();
        b.charge(src(1), 50);
        b.charge(src(2), 80);
        b.charge(BudgetSource::Local, 30);
        b.reset();
        assert_eq!(b.global_consumed(), 0);
        assert_eq!(b.remote_consumed(), 0);
        assert_eq!(b.peer_consumed(&peer(1)), 0);
        assert_eq!(b.peer_consumed(&peer(2)), 0);
    }

    #[test]
    fn forget_peer_drops_per_peer_only() {
        let mut b = budgets();
        b.charge(src(1), 50);
        b.forget_peer(&peer(1));
        assert_eq!(b.peer_consumed(&peer(1)), 0);
        assert_eq!(
            b.global_consumed(),
            50,
            "forget_peer does not rewind the running totals"
        );
    }

    #[test]
    fn post_charge_verdict_flags_overflow() {
        let mut b = budgets();
        b.charge(src(1), 120);
        assert_eq!(b.post_charge_verdict(src(1)), BudgetVerdict::PeerExhausted);
    }

    #[test]
    fn saturating_arithmetic_never_wraps() {
        let mut b = CostBudgets::new(u64::MAX, u64::MAX, 0);
        b.charge(src(1), u64::MAX);
        b.charge(src(1), 1);
        // Saturating; doesn't panic and doesn't wrap.
        assert_eq!(b.peer_consumed(&peer(1)), u64::MAX);
        b.charge(BudgetSource::Local, u64::MAX);
        assert_eq!(
            b.global_consumed(),
            u64::MAX,
            "the remote+local sum saturates rather than wrapping"
        );
    }

    #[test]
    fn global_charge_after_reset() {
        let mut b = budgets();
        b.charge(src(1), 500);
        b.reset();
        assert_eq!(b.pre_admission_check(src(1)), BudgetVerdict::Ok);
    }

    // ----- local reserve -----

    #[test]
    fn flooding_peer_at_full_global_cap_still_leaves_local_headroom() {
        // The red-team scenario: one peer spends the entire peer-contended
        // budget. Peers (that one and every other) are shut out; a local
        // submission still has the reserve to spend.
        let mut b = CostBudgets::new(1_000, 1_000, 200);
        b.charge(src(1), 1_000);
        assert_eq!(
            b.pre_admission_check(src(1)),
            BudgetVerdict::GlobalExhausted
        );
        assert_eq!(
            b.pre_admission_check(src(2)),
            BudgetVerdict::GlobalExhausted
        );
        assert_eq!(
            b.pre_admission_check(BudgetSource::Local),
            BudgetVerdict::Ok,
            "the reserve is unreachable by peers"
        );
    }

    #[test]
    fn local_reserve_is_finite_and_exhausts() {
        // The reserve bounds local work too — it is headroom, not a bypass.
        let mut b = CostBudgets::new(1_000, 1_000, 200);
        b.charge(src(1), 1_000);
        b.charge(BudgetSource::Local, 200);
        assert_eq!(
            b.pre_admission_check(BudgetSource::Local),
            BudgetVerdict::GlobalExhausted
        );
    }

    #[test]
    fn zero_local_reserve_gates_local_at_the_global_cap() {
        // With the reserve off, a local submission is gated exactly at
        // global_cap, as it was before the reserve existed.
        let mut b = CostBudgets::new(1_000, 1_000, 0);
        b.charge(src(1), 1_000);
        assert_eq!(
            b.pre_admission_check(BudgetSource::Local),
            BudgetVerdict::GlobalExhausted
        );
    }

    #[test]
    fn local_spending_never_exhausts_the_peer_budget() {
        // Local work is charged to its own counter, so even a local burst far
        // past global_cap leaves peers their full allowance.
        let mut b = CostBudgets::new(1_000, 1_000, 200);
        b.charge(BudgetSource::Local, 1_200);
        assert_eq!(
            b.pre_admission_check(BudgetSource::Local),
            BudgetVerdict::GlobalExhausted
        );
        assert_eq!(b.pre_admission_check(src(1)), BudgetVerdict::Ok);
    }

    #[test]
    fn reserve_resets_with_the_rest_on_a_new_block() {
        let mut b = CostBudgets::new(1_000, 1_000, 200);
        b.charge(src(1), 1_000);
        b.charge(BudgetSource::Local, 200);
        b.reset();
        assert_eq!(
            b.pre_admission_check(BudgetSource::Local),
            BudgetVerdict::Ok
        );
        assert_eq!(b.pre_admission_check(src(1)), BudgetVerdict::Ok);
    }
}

//! Global and per-peer cost budgets.
//!
//! Budgets are charged post-validation (admission step 15) with
//! partial cost on validation failure. A pre-validation gate (step 1)
//! short-circuits when a budget is already exhausted so a malicious
//! peer cannot force script evaluation on an exhausted node. Both
//! budgets reset on every `ApplyBlock` event.

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

pub struct CostBudgets {
    global_cap: u64,
    per_peer_cap: u64,
    global_consumed: u64,
    per_peer_consumed: HashMap<PeerId, u64>,
}

impl CostBudgets {
    pub fn new(global_cap: u64, per_peer_cap: u64) -> Self {
        Self {
            global_cap,
            per_peer_cap,
            global_consumed: 0,
            per_peer_consumed: HashMap::new(),
        }
    }

    pub fn global_consumed(&self) -> u64 {
        self.global_consumed
    }

    pub fn peer_consumed(&self, peer: &PeerId) -> u64 {
        self.per_peer_consumed.get(peer).copied().unwrap_or(0)
    }

    /// Pre-validation gate. Returns whether a new tx of unknown cost
    /// is allowed to proceed at all. Rejects if either budget is
    /// already exhausted — no validation cycles spent.
    pub fn pre_admission_check(&self, source_peer: Option<PeerId>) -> BudgetVerdict {
        if self.global_consumed >= self.global_cap {
            return BudgetVerdict::GlobalExhausted;
        }
        if let Some(p) = source_peer {
            if self.peer_consumed(&p) >= self.per_peer_cap {
                return BudgetVerdict::PeerExhausted;
            }
        }
        BudgetVerdict::Ok
    }

    /// Charge `cost` to the budgets after admission step 12. Called on
    /// both success and validation failure. Saturating adds — a single
    /// runaway validation cannot wrap the counter.
    pub fn charge(&mut self, source_peer: Option<PeerId>, cost: u64) {
        self.global_consumed = self.global_consumed.saturating_add(cost);
        if let Some(p) = source_peer {
            let slot = self.per_peer_consumed.entry(p).or_insert(0);
            *slot = slot.saturating_add(cost);
        }
    }

    /// Post-charge check: after charging, did we exceed caps? Admission
    /// uses this for the step-15 decision that turns partial-cost
    /// rejection into a penalty signal.
    pub fn post_charge_verdict(&self, source_peer: Option<PeerId>) -> BudgetVerdict {
        if self.global_consumed >= self.global_cap {
            return BudgetVerdict::GlobalExhausted;
        }
        if let Some(p) = source_peer {
            if self.peer_consumed(&p) >= self.per_peer_cap {
                return BudgetVerdict::PeerExhausted;
            }
        }
        BudgetVerdict::Ok
    }

    /// Reset counters. Called on every `ApplyBlock`.
    pub fn reset(&mut self) {
        self.global_consumed = 0;
        self.per_peer_consumed.clear();
    }

    /// Drop per-peer bookkeeping on disconnect. Global cost unaffected.
    pub fn forget_peer(&mut self, peer: &PeerId) {
        self.per_peer_consumed.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn peer(n: u16) -> PeerId {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000 + n)
    }

    fn budgets() -> CostBudgets {
        CostBudgets::new(1_000, 100)
    }

    // ----- happy path -----

    #[test]
    fn new_budgets_admit_everything() {
        let b = budgets();
        assert_eq!(b.pre_admission_check(Some(peer(1))), BudgetVerdict::Ok);
        assert_eq!(b.pre_admission_check(None), BudgetVerdict::Ok);
    }

    #[test]
    fn charging_a_peer_only_affects_that_peer() {
        let mut b = budgets();
        b.charge(Some(peer(1)), 50);
        assert_eq!(b.peer_consumed(&peer(1)), 50);
        assert_eq!(b.peer_consumed(&peer(2)), 0);
        assert_eq!(b.global_consumed(), 50);
    }

    #[test]
    fn api_charges_affect_global_only() {
        let mut b = budgets();
        b.charge(None, 500);
        assert_eq!(b.global_consumed(), 500);
        assert!(b.per_peer_consumed.is_empty());
    }

    #[test]
    fn pre_admission_rejects_exhausted_peer() {
        let mut b = budgets();
        b.charge(Some(peer(1)), 100);
        assert_eq!(
            b.pre_admission_check(Some(peer(1))),
            BudgetVerdict::PeerExhausted
        );
        // Other peer still OK.
        assert_eq!(b.pre_admission_check(Some(peer(2))), BudgetVerdict::Ok);
    }

    #[test]
    fn pre_admission_rejects_exhausted_global() {
        let mut b = budgets();
        b.charge(Some(peer(1)), 1_000);
        assert_eq!(
            b.pre_admission_check(Some(peer(2))),
            BudgetVerdict::GlobalExhausted,
            "other peers blocked once global exhausted"
        );
    }

    #[test]
    fn reset_clears_all_counters() {
        let mut b = budgets();
        b.charge(Some(peer(1)), 50);
        b.charge(Some(peer(2)), 80);
        b.reset();
        assert_eq!(b.global_consumed(), 0);
        assert_eq!(b.peer_consumed(&peer(1)), 0);
        assert_eq!(b.peer_consumed(&peer(2)), 0);
    }

    #[test]
    fn forget_peer_drops_per_peer_only() {
        let mut b = budgets();
        b.charge(Some(peer(1)), 50);
        b.forget_peer(&peer(1));
        assert_eq!(b.peer_consumed(&peer(1)), 0);
        assert_eq!(
            b.global_consumed(),
            50,
            "forget_peer does not rewind global counter"
        );
    }

    #[test]
    fn post_charge_verdict_flags_overflow() {
        let mut b = budgets();
        b.charge(Some(peer(1)), 120);
        assert_eq!(
            b.post_charge_verdict(Some(peer(1))),
            BudgetVerdict::PeerExhausted
        );
    }

    #[test]
    fn saturating_arithmetic_never_wraps() {
        let mut b = CostBudgets::new(u64::MAX, u64::MAX);
        b.charge(Some(peer(1)), u64::MAX);
        b.charge(Some(peer(1)), 1);
        // Saturating; doesn't panic and doesn't wrap.
        assert_eq!(b.peer_consumed(&peer(1)), u64::MAX);
    }

    #[test]
    fn global_charge_after_reset() {
        let mut b = budgets();
        b.charge(Some(peer(1)), 500);
        b.reset();
        assert_eq!(b.pre_admission_check(Some(peer(1))), BudgetVerdict::Ok);
    }
}

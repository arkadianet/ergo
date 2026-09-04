//! Global, per-peer, and local-reserve cost budgets.
//!
//! Budgets are charged post-validation (admission step 15) with
//! partial cost on validation failure. A pre-validation gate (step 1)
//! short-circuits when a budget is already exhausted so a malicious
//! peer cannot force script evaluation on an exhausted node. All
//! budgets reset on every `ApplyBlock` event.
//!
//! There are two pools, not two independent budgets. `global_cap` is a
//! SHARED pool both peers and local submissions draw on; `local_reserved`
//! is an extra slice only node-local submissions (`TxSource::Api` /
//! `TxSource::Wallet`) can reach, and they spend it FIRST. So a single
//! flooding peer that drains the shared pool still cannot block the
//! operator's own `POST /transactions` (the reserve is untouched), while
//! the per-block total stays bounded at `global_cap + local_reserved` —
//! local traffic that spills past its reserve competes with peers for what
//! is left of the shared pool, exactly as it did before the reserve
//! existed. Gating each pool independently would instead grant a full
//! allowance to each side and inflate the real ceiling.
//!
//! `local_reserved` is reachable ONLY by traffic the node can actually
//! trust to be operator-initiated. `TxSource::Api` is that trusted case:
//! the `[api]` listener is bound loopback (the default), so only local
//! processes can reach it. Once the operator opts into `[api] public_bind
//! = true` — exposing the (unauthenticated-by-design) submission routes
//! to the network — a submission arriving on that bind is indistinguishable
//! from arbitrary internet traffic, so it is classified `TxSource::
//! PublicApi` / `BudgetSource::PublicApi` instead: it contends for
//! `global_cap` exactly like `Peer` traffic and can never touch the
//! reserve. See `ergo-node/src/node/admission.rs` for where that
//! classification is made.
//!
//! Scala has no cost budget on this path at all: a
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
/// budget-exempt at every charging site (`admission::check_capturing_held`,
/// `Mempool::validate_package_child`) and never reaches these counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetSource {
    /// Remote traffic from `peer`. Contends for `global_cap` with every
    /// other peer, and for `per_peer_cap` with itself.
    Peer(PeerId),
    /// Node-local submission (`TxSource::Api` / `TxSource::Wallet`), which
    /// may spend into `local_reserved` after `global_cap` is gone.
    Local,
    /// Unauthenticated API submission received while `[api] bind` is
    /// non-loopback (`TxSource::PublicApi`). No trustworthy per-caller
    /// identity exists for this path — the `api_key` gate never covers
    /// submission routes, so the HTTP layer carries no key, and the
    /// client IP is not (yet) plumbed through — so, unlike `Peer`, this
    /// bucket is unkeyed: every such submission contends for `global_cap`
    /// through the one shared `remote_consumed` counter, with no separate
    /// per-source cap. It NEVER reaches `local_reserved`.
    PublicApi,
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

    /// Cost charged by remote peers this block. Observational — the peer gate
    /// compares `shared_consumed()` (this plus local overflow) to `global_cap`.
    pub fn remote_consumed(&self) -> u64 {
        self.remote_consumed
    }

    pub fn peer_consumed(&self, peer: &PeerId) -> u64 {
        self.per_peer_consumed.get(peer).copied().unwrap_or(0)
    }

    /// How much of the SHARED pool has been spent: everything peers charged,
    /// plus whatever local work spilled past its reserve. Locals draw on the
    /// reserve first, so the first `local_reserved` of local cost is invisible
    /// here — that is what makes the reserve unreachable by peers. Both gates
    /// read this one figure, which is what bounds the per-block total at
    /// `global_cap + local_reserved` rather than letting the two pools grant a
    /// full allowance each.
    fn shared_consumed(&self) -> u64 {
        self.remote_consumed
            .saturating_add(self.local_consumed.saturating_sub(self.local_reserved))
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
            BudgetSource::PublicApi => {
                self.remote_consumed = self.remote_consumed.saturating_add(cost);
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
                if self.shared_consumed() >= self.global_cap {
                    return BudgetVerdict::GlobalExhausted;
                }
                if self.peer_consumed(&p) >= self.per_peer_cap {
                    return BudgetVerdict::PeerExhausted;
                }
                BudgetVerdict::Ok
            }
            BudgetSource::Local => {
                // The reserve, plus however much of the shared pool the peers
                // have left. Written against `local_consumed` (not the overflow)
                // so that a local source with its reserve still intact is
                // admitted even when peers have drained the shared pool.
                let shared_left = self.global_cap.saturating_sub(self.remote_consumed);
                if self.local_consumed >= self.local_reserved.saturating_add(shared_left) {
                    return BudgetVerdict::GlobalExhausted;
                }
                BudgetVerdict::Ok
            }
            BudgetSource::PublicApi => {
                // Same gate as `Peer`, minus the per-source cap: there is
                // no identity to key it on, so the only protection is the
                // shared ceiling every remote source contends for.
                if self.shared_consumed() >= self.global_cap {
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
    fn local_charges_within_the_reserve_leave_the_peer_pool_untouched() {
        // Locals spend the reserve FIRST, so reserve-sized local work is
        // invisible to the shared pool the peers draw on.
        let mut b = CostBudgets::new(1_000, 1_000, 500);
        b.charge(BudgetSource::Local, 500);
        assert_eq!(b.global_consumed(), 500);
        assert_eq!(b.remote_consumed(), 0, "local work is not peer work");
        assert!(b.per_peer_consumed.is_empty());
        assert_eq!(b.shared_consumed(), 0, "spent entirely out of the reserve");
        assert_eq!(b.pre_admission_check(src(1)), BudgetVerdict::Ok);
    }

    #[test]
    fn local_spending_past_the_reserve_draws_on_the_shared_pool() {
        // The reserve is a head start, not a second budget: once it is gone,
        // local work competes with peers for the shared pool, which is what
        // bounds the per-block total at global_cap + local_reserved.
        let mut b = CostBudgets::new(1_000, 1_000, 200);
        b.charge(BudgetSource::Local, 700);
        assert_eq!(
            b.shared_consumed(),
            500,
            "200 came from the reserve, 500 from the shared pool"
        );
        assert_eq!(b.pre_admission_check(src(1)), BudgetVerdict::Ok);
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

    #[test]
    fn public_api_charge_never_touches_the_reserve() {
        // The core security property: a `PublicApi` flood contends for the
        // shared pool exactly like a peer would, and cannot dip into
        // `local_reserved` the way `BudgetSource::Local` can.
        let mut b = CostBudgets::new(1_000, 1_000, 300);
        b.charge(BudgetSource::PublicApi, 1_000);
        assert_eq!(
            b.remote_consumed(),
            1_000,
            "public-api cost lands in the same bucket as peer cost"
        );
        assert_eq!(
            b.local_consumed, 0,
            "public-api never charges local_consumed"
        );
        assert_eq!(
            b.pre_admission_check(BudgetSource::Local),
            BudgetVerdict::Ok,
            "the untouched reserve still admits a genuinely-local submission"
        );
    }

    #[test]
    fn public_api_flood_exhausts_only_the_shared_pool() {
        let mut b = CostBudgets::new(1_000, 1_000, 0);
        b.charge(BudgetSource::PublicApi, 1_000);
        assert_eq!(
            b.pre_admission_check(BudgetSource::PublicApi),
            BudgetVerdict::GlobalExhausted
        );
        assert_eq!(
            b.pre_admission_check(src(1)),
            BudgetVerdict::GlobalExhausted,
            "a public-api flood exhausts the same shared cap peers contend for"
        );
    }

    #[test]
    fn public_api_and_peer_contend_for_the_same_shared_cap() {
        let mut b = CostBudgets::new(1_000, 1_000, 0);
        b.charge(src(1), 600);
        b.charge(BudgetSource::PublicApi, 300);
        assert_eq!(b.shared_consumed(), 900);
        assert_eq!(
            b.pre_admission_check(BudgetSource::PublicApi),
            BudgetVerdict::Ok
        );
        b.charge(BudgetSource::PublicApi, 100);
        assert_eq!(
            b.pre_admission_check(src(2)),
            BudgetVerdict::GlobalExhausted,
            "public-api spend counts toward the cap a peer is gated on"
        );
    }

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
    fn locals_first_then_peers_get_only_the_rest_of_the_shared_pool() {
        // Reverse order of the flood case: local work runs to exhaustion
        // FIRST. It may spend reserve + the whole shared pool, and a peer
        // arriving afterwards must NOT find a fresh global_cap — otherwise the
        // per-block validation work would be global_cap + reserve + global_cap.
        let mut b = CostBudgets::new(1_000, 1_000, 200);
        b.charge(BudgetSource::Local, 1_200);
        assert_eq!(
            b.pre_admission_check(BudgetSource::Local),
            BudgetVerdict::GlobalExhausted,
            "locals bounded at reserve + shared pool"
        );
        assert_eq!(
            b.shared_consumed(),
            1_000,
            "1_200 local = 200 reserve + the whole 1_000 shared pool"
        );
        assert_eq!(
            b.pre_admission_check(src(1)),
            BudgetVerdict::GlobalExhausted,
            "the shared pool is gone; a peer does not get a fresh allowance"
        );
        assert_eq!(
            b.global_consumed(),
            1_200,
            "total per-block work is capped at global_cap + local_reserved"
        );
    }

    #[test]
    fn partial_local_overflow_leaves_peers_only_the_remainder() {
        // 500 local against a 200 reserve spends 300 of the 1_000 shared pool;
        // a peer may then still spend the remaining 700, and no more.
        let mut b = CostBudgets::new(1_000, 1_000, 200);
        b.charge(BudgetSource::Local, 500);
        assert_eq!(b.pre_admission_check(src(1)), BudgetVerdict::Ok);
        b.charge(src(1), 700);
        assert_eq!(
            b.pre_admission_check(src(1)),
            BudgetVerdict::GlobalExhausted,
            "shared pool exactly spent by 300 local overflow + 700 peer"
        );
        assert_eq!(
            b.global_consumed(),
            1_200,
            "never more than global_cap + local_reserved"
        );
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

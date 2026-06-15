//! NiPoPoW bootstrap reducer (Part 2 sub-phase 14.6).
//!
//! Owns the state machine that:
//! 1. Tracks which peers we've asked for a NiPoPoW proof.
//! 2. Hands inbound proofs to the [`NipopowVerifier`] for validation
//!    + best-proof selection.
//! 3. Reports when quorum has been reached and the best proof is
//!    ready to be applied to history.
//! 4. Becomes terminal after the apply path runs (via
//!    [`PopowBootstrap::mark_applied`]); subsequent ticks no-op.
//!
//! Lifetime: constructed at node startup when
//! `[node] nipopow_bootstrap = true` AND the store is fresh
//! (`best_header_height == 0`). Terminal after `mark_applied` —
//! restart with a sparse store finds [`PopowBootstrap::is_active`]
//! returns `false` immediately so the reducer doesn't re-fetch.
//!
//! Scala parity:
//! - Verifier semantics: `NipopowVerifier.scala:31-58`.
//! - Quorum threshold: `mainnet.conf::p2p_nipopows = 2`
//!   (`NipopowSettings.scala:10`).
//! - m / k constants: `ErgoHistoryUtils.scala:29-34` (m=6, k=10).

use std::collections::BTreeSet;
use std::time::Instant;

use ergo_crypto::difficulty::DifficultyParams;
use ergo_p2p::peer::PeerId;
use ergo_ser::header::Header;
use ergo_ser::popow_proof::NipopowProof;
use ergo_validation::popow::{NipopowVerificationResult, NipopowVerifier};

/// State of the NiPoPoW bootstrap discovery + verification loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopowBootstrapState {
    /// Not started — no `GetNipopowProof` sent yet.
    Idle,
    /// One or more `GetNipopowProof` requests outstanding.
    Requesting,
    /// Quorum threshold reached AND a best proof has been verified.
    /// `take_best_chain` has not been called yet.
    BestSelected,
    /// `apply_popow_proof` succeeded and committed. Terminal.
    Applied,
}

/// State machine for the NiPoPoW bootstrap consume side.
///
/// All methods take `&mut self` — this reducer is owned by the
/// single-threaded sync layer (`NodeState`) and never crosses
/// thread boundaries.
pub struct PopowBootstrap {
    state: PopowBootstrapState,
    /// Number of valid proofs required before [`Self::quorum_reached`]
    /// returns `true`. Mainnet default = 2
    /// (`NipopowSettings.scala::p2p_nipopows`).
    quorum: u32,
    verifier: NipopowVerifier,
    /// Peers we've already sent `GetNipopowProof` to during the
    /// current bootstrap. Cleared per-peer on disconnect via
    /// [`Self::forget_peer`].
    requested_peers: BTreeSet<PeerId>,
    /// Peers we've received a proof from (regardless of validity). Gates
    /// [`Self::on_proof_received`]: a peer already in this set has its
    /// further proofs dropped before the verifier, so it cannot contribute
    /// more than one proof toward quorum (Scala parity). Also backs the
    /// dashboard `provider_count` observability surface.
    seen_providers: BTreeSet<PeerId>,
    started_at: Option<Instant>,
}

impl PopowBootstrap {
    /// Construct a fresh bootstrap reducer.
    ///
    /// * `quorum` — number of valid proofs required for
    ///   [`Self::quorum_reached`] to return `true`. Mainnet uses 2.
    /// * `genesis_id_opt` — R5 enforcement (Phase 0 §11). `Some(id)`
    ///   rejects proofs whose first header id does not match.
    ///   Production runs MUST pass `Some(_)`.
    /// * `chain_config` — chain settings needed for
    ///   [`NipopowVerifier`]'s `is_valid` / `is_better_than` calls.
    pub fn new(
        quorum: u32,
        genesis_id_opt: Option<[u8; 32]>,
        chain_config: DifficultyParams,
    ) -> Self {
        Self {
            state: PopowBootstrapState::Idle,
            quorum,
            verifier: NipopowVerifier::new(genesis_id_opt, chain_config),
            requested_peers: BTreeSet::new(),
            seen_providers: BTreeSet::new(),
            started_at: None,
        }
    }

    /// Current reducer state. Read-only — transitions happen via the
    /// other methods.
    pub fn state(&self) -> PopowBootstrapState {
        self.state
    }

    /// Whether the reducer should still drive any work this tick.
    /// Returns `false` once the apply path has completed AND on
    /// restart against a non-empty history (because the persisted
    /// store already reflects the applied proof).
    pub fn is_active(&self, history_is_empty: bool) -> bool {
        if !history_is_empty {
            return false;
        }
        !matches!(self.state, PopowBootstrapState::Applied)
    }

    /// Filter `eligible_peers` down to those we have NOT yet sent
    /// `GetNipopowProof` to during this bootstrap.
    pub fn pending_request_peers(&self, eligible_peers: &[PeerId]) -> Vec<PeerId> {
        eligible_peers
            .iter()
            .filter(|p| !self.requested_peers.contains(p))
            .copied()
            .collect()
    }

    /// Record that we sent `GetNipopowProof` to `peer`. Caller
    /// invokes after a successful send.
    pub fn mark_requested(&mut self, peer: PeerId, now: Instant) {
        self.requested_peers.insert(peer);
        if self.started_at.is_none() {
            self.started_at = Some(now);
        }
        if matches!(self.state, PopowBootstrapState::Idle) {
            self.state = PopowBootstrapState::Requesting;
        }
    }

    /// Drop a peer from our outstanding-request set so it can be
    /// re-queried on reconnect (matches the per-peer "discovery_queried"
    /// pattern in `SnapshotBootstrap`).
    pub fn forget_peer(&mut self, peer: PeerId) {
        self.requested_peers.remove(&peer);
    }

    /// Hand an inbound proof to the verifier. Returns `Some(result)` with
    /// the verification outcome so the caller can act on it (e.g., penalize
    /// on `ValidationError` or `WrongGenesis`), or `None` when the proof is
    /// dropped before the verifier because `peer` already contributed one.
    ///
    /// Per-peer dedup (Scala `ErgoNodeViewSynchronizer.scala:1066`): a peer
    /// may contribute at most one proof to the verifier. Without it the
    /// quorum (`proofs_processed >= quorum`) could be satisfied by a single
    /// peer sending `quorum` proofs — a Sybil/eclipse bypass. The duplicate
    /// is dropped with no penalty, matching Scala.
    ///
    /// If the verifier returns `BetterChain` or `NoBetterChain` AND
    /// the running counter has reached the quorum threshold, the
    /// reducer transitions to [`PopowBootstrapState::BestSelected`].
    pub fn on_proof_received(
        &mut self,
        peer: PeerId,
        proof: NipopowProof,
    ) -> Option<NipopowVerificationResult> {
        // `BTreeSet::insert` returns false when the peer was already present:
        // it has already contributed its one counted proof, so drop this one.
        if !self.seen_providers.insert(peer) {
            return None;
        }
        let result = self.verifier.process(proof);
        if matches!(
            result,
            NipopowVerificationResult::BetterChain { .. }
                | NipopowVerificationResult::NoBetterChain { .. }
        ) && self.verifier.proofs_processed() >= self.quorum
            && matches!(self.state, PopowBootstrapState::Requesting)
        {
            self.state = PopowBootstrapState::BestSelected;
        }
        Some(result)
    }

    /// `true` once the reducer has seen at least `quorum` valid
    /// proofs AND a best proof has been latched (state ==
    /// `BestSelected`).
    pub fn quorum_reached(&self) -> bool {
        matches!(self.state, PopowBootstrapState::BestSelected)
    }

    /// Read the current best chain (in ascending height order).
    /// Returns an empty vector if no best proof has been latched.
    pub fn best_chain(&self) -> Vec<Header> {
        self.verifier.best_chain()
    }

    /// Borrow the current best NiPoPoW proof, if any. The sync-layer
    /// `drive_popow_bootstrap` consumes this to call
    /// `StateStore::apply_popow_proof` directly.
    pub fn best_proof(&self) -> Option<&NipopowProof> {
        self.verifier.best_proof()
    }

    /// Mark the apply path as complete. After this call,
    /// [`Self::state`] returns `Applied` and
    /// [`Self::is_active`] returns `false`.
    pub fn mark_applied(&mut self) {
        self.state = PopowBootstrapState::Applied;
    }

    /// Number of distinct peers that have responded with a proof so
    /// far (regardless of validity). Used for the dashboard
    /// observability surface (`api_bridge::ApiBootstrapStatus`).
    pub fn provider_count(&self) -> u32 {
        self.seen_providers.len() as u32
    }

    /// Number of successfully-verified (valid) proofs received so
    /// far. Survives `verifier.reset()`.
    pub fn proofs_processed(&self) -> u32 {
        self.verifier.proofs_processed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;
    use ergo_ser::popow_header::PoPowHeader;

    // ----- helpers -----

    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";
    const HEIGHT_2_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

    fn header(s: &str) -> Header {
        let raw = hex::decode(s).unwrap();
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).unwrap()
    }

    fn popow_hdr(h: Header) -> PoPowHeader {
        PoPowHeader {
            header: h,
            interlinks: vec![],
            interlinks_proof: vec![],
        }
    }

    fn valid_proof() -> NipopowProof {
        NipopowProof {
            m: 6,
            k: 10,
            prefix: vec![popow_hdr(header(GENESIS_HEX))],
            suffix_head: popow_hdr(header(HEIGHT_2_HEX)),
            suffix_tail: vec![],
            // continuous=false so the difficulty-headers check is
            // skipped — this is a structural test, not a chain-shape
            // validation.
            continuous: false,
        }
    }

    fn peer(i: u8) -> PeerId {
        PeerId::from(std::net::SocketAddr::from(([127, 0, 0, i], 9030u16)))
    }

    fn fresh_bootstrap(quorum: u32) -> PopowBootstrap {
        PopowBootstrap::new(quorum, None, DifficultyParams::mainnet())
    }

    // ----- happy path -----

    #[test]
    fn idle_state_on_construction() {
        let b = fresh_bootstrap(2);
        assert_eq!(b.state(), PopowBootstrapState::Idle);
        assert!(b.is_active(true));
        assert!(!b.is_active(false));
    }

    #[test]
    fn mark_requested_transitions_to_requesting() {
        let mut b = fresh_bootstrap(2);
        b.mark_requested(peer(1), Instant::now());
        assert_eq!(b.state(), PopowBootstrapState::Requesting);
    }

    #[test]
    fn pending_request_peers_excludes_already_requested() {
        let mut b = fresh_bootstrap(2);
        b.mark_requested(peer(1), Instant::now());
        let pending = b.pending_request_peers(&[peer(1), peer(2)]);
        assert_eq!(pending, vec![peer(2)]);
    }

    #[test]
    fn quorum_reached_after_two_valid_proofs() {
        let mut b = fresh_bootstrap(2);
        b.mark_requested(peer(1), Instant::now());
        b.mark_requested(peer(2), Instant::now());
        let r1 = b.on_proof_received(peer(1), valid_proof());
        assert!(matches!(
            r1,
            Some(NipopowVerificationResult::BetterChain { .. })
        ));
        // After 1 valid proof, quorum not yet met (need 2).
        assert!(!b.quorum_reached());
        let _ = b.on_proof_received(peer(2), valid_proof());
        // After 2 valid proofs, quorum reached AND state == BestSelected.
        assert!(b.quorum_reached());
        assert_eq!(b.state(), PopowBootstrapState::BestSelected);
        assert!(!b.best_chain().is_empty());
    }

    #[test]
    fn mark_applied_is_terminal() {
        let mut b = fresh_bootstrap(1);
        b.mark_requested(peer(1), Instant::now());
        let _ = b.on_proof_received(peer(1), valid_proof());
        assert!(b.quorum_reached());
        b.mark_applied();
        assert_eq!(b.state(), PopowBootstrapState::Applied);
        // is_active is false even with history_is_empty=true.
        assert!(!b.is_active(true));
    }

    #[test]
    fn forget_peer_allows_re_request() {
        let mut b = fresh_bootstrap(2);
        b.mark_requested(peer(1), Instant::now());
        assert_eq!(b.pending_request_peers(&[peer(1)]).len(), 0);
        b.forget_peer(peer(1));
        assert_eq!(b.pending_request_peers(&[peer(1)]), vec![peer(1)]);
    }

    // ----- error paths -----

    /// Scala parity (ErgoNodeViewSynchronizer.scala:1066 + PopowProcessor
    /// .scala:141): a peer may contribute at most one proof to the verifier.
    /// A second proof from the same peer is dropped before the verifier and
    /// does not bump `proofs_processed`, so one peer can never reach quorum.
    #[test]
    fn second_proof_from_same_peer_is_dropped_and_does_not_count() {
        let mut b = fresh_bootstrap(2);
        b.mark_requested(peer(1), Instant::now());

        let r1 = b.on_proof_received(peer(1), valid_proof());
        assert!(matches!(
            r1,
            Some(NipopowVerificationResult::BetterChain { .. })
        ));
        assert_eq!(b.proofs_processed(), 1);

        // Same peer again: dropped before the verifier, no penalty.
        let r2 = b.on_proof_received(peer(1), valid_proof());
        assert!(r2.is_none(), "duplicate peer proof must be dropped");
        assert_eq!(
            b.proofs_processed(),
            1,
            "counter must not bump on a duplicate peer"
        );
        assert!(!b.quorum_reached(), "one peer can never reach quorum=2");
        assert_eq!(b.state(), PopowBootstrapState::Requesting);
    }

    /// Quorum counts DISTINCT peers: two proofs from one peer do not reach
    /// quorum=2; a second distinct peer does.
    #[test]
    fn quorum_requires_two_distinct_peers() {
        let mut b = fresh_bootstrap(2);
        b.mark_requested(peer(1), Instant::now());
        b.mark_requested(peer(2), Instant::now());

        let _ = b.on_proof_received(peer(1), valid_proof());
        let _ = b.on_proof_received(peer(1), valid_proof()); // dup → dropped
        assert!(
            !b.quorum_reached(),
            "two proofs from one peer must not reach quorum"
        );

        let r = b.on_proof_received(peer(2), valid_proof());
        assert!(matches!(
            r,
            Some(
                NipopowVerificationResult::BetterChain { .. }
                    | NipopowVerificationResult::NoBetterChain { .. }
            )
        ));
        assert!(b.quorum_reached(), "second distinct peer reaches quorum");
    }
}

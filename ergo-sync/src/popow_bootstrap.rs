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

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use ergo_crypto::difficulty::{previous_heights_for_recalculation, DifficultyParams};
use ergo_p2p::peer::PeerId;
use ergo_p2p::types::{P2P_NIPOPOW_PROOF_K, P2P_NIPOPOW_PROOF_M};
use ergo_ser::difficulty::encode_compact_bits;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::popow_proof::NipopowProof;
use ergo_validation::popow::{NipopowVerificationResult, NipopowVerifier};
use num_bigint::BigUint;

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

pub fn validate_bootstrap_response_profile(
    proof: &NipopowProof,
    expected_m: u32,
    expected_k: u32,
) -> bool {
    if proof.m != expected_m || proof.k != expected_k || !proof.continuous {
        return false;
    }

    let Ok(expected_k_usize) = usize::try_from(expected_k) else {
        return false;
    };
    let Some(suffix_len) = proof.suffix_tail.len().checked_add(1) else {
        return false;
    };
    if suffix_len != expected_k_usize {
        return false;
    }

    let mut previous_height = proof.suffix_head.header.height;
    for header in &proof.suffix_tail {
        let Some(next_height) = previous_height.checked_add(1) else {
            return false;
        };
        if header.height != next_height {
            return false;
        }
        previous_height = header.height;
    }

    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopowBootstrapDifficultyError {
    DuplicateProofHeight { height: u32 },
    MissingContext { height: u32 },
    InvalidHeader { height: u32 },
    ParentIdMismatch { height: u32 },
    NonIncreasingTimestamp { height: u32 },
    InitialDifficultyMismatch { height: u32 },
    ConsensusDifficultyMismatch { height: u32 },
    InvalidEpochLength,
}

pub fn validate_bootstrap_difficulty_context(
    proof: &NipopowProof,
    params: &DifficultyParams,
) -> Result<(), PopowBootstrapDifficultyError> {
    let headers = proof
        .prefix
        .iter()
        .map(|entry| &entry.header)
        .chain(std::iter::once(&proof.suffix_head.header))
        .chain(proof.suffix_tail.iter());
    let mut context = BTreeMap::<u32, &Header>::new();
    for header in headers {
        if context.insert(header.height, header).is_some() {
            return Err(PopowBootstrapDifficultyError::DuplicateProofHeight {
                height: header.height,
            });
        }
    }

    let genesis = context
        .get(&1)
        .ok_or(PopowBootstrapDifficultyError::MissingContext { height: 1 })?;
    let expected_initial_nbits =
        encode_compact_bits(&BigUint::from_bytes_be(&params.initial_difficulty));
    if genesis.n_bits != expected_initial_nbits {
        return Err(PopowBootstrapDifficultyError::InitialDifficultyMismatch {
            height: genesis.height,
        });
    }

    let epoch_length = params.eip37_epoch_length.unwrap_or(params.epoch_length);
    if epoch_length == 0 {
        return Err(PopowBootstrapDifficultyError::InvalidEpochLength);
    }

    for header in std::iter::once(&proof.suffix_head.header).chain(proof.suffix_tail.iter()) {
        if header.height == 1 {
            continue;
        }
        let parent_height = header
            .height
            .checked_sub(1)
            .filter(|height| *height > 0)
            .ok_or(PopowBootstrapDifficultyError::MissingContext {
                height: header.height,
            })?;
        let parent =
            context
                .get(&parent_height)
                .ok_or(PopowBootstrapDifficultyError::MissingContext {
                    height: parent_height,
                })?;
        let (_bytes, parent_id) =
            serialize_header(parent).map_err(|_| PopowBootstrapDifficultyError::InvalidHeader {
                height: parent.height,
            })?;
        if *header.parent_id.as_bytes() != *parent_id.as_bytes() {
            return Err(PopowBootstrapDifficultyError::ParentIdMismatch {
                height: header.height,
            });
        }
        if header.timestamp <= parent.timestamp {
            return Err(PopowBootstrapDifficultyError::NonIncreasingTimestamp {
                height: header.height,
            });
        }

        let required_heights = previous_heights_for_recalculation(header.height, epoch_length);
        let mut epoch_headers = Vec::with_capacity(required_heights.len());
        for height in required_heights {
            if height == 0 {
                continue;
            }
            let context_header = context
                .get(&height)
                .ok_or(PopowBootstrapDifficultyError::MissingContext { height })?;
            epoch_headers.push((*context_header).clone());
        }
        ergo_crypto::pow::verify_header_difficulty(header, &epoch_headers, params).map_err(
            |_| PopowBootstrapDifficultyError::ConsensusDifficultyMismatch {
                height: header.height,
            },
        )?;
    }

    Ok(())
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
    expected_m: u32,
    expected_k: u32,
    difficulty_params: DifficultyParams,
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
    /// Peer whose proof is currently latched as the verifier's best. Set
    /// whenever a proof replaces the best one (`BetterChain`) and cleared by
    /// [`Self::reject_best_proof`], so a proof rejected AFTER selection can
    /// still be attributed to the provider that supplied it.
    best_proof_peer: Option<PeerId>,
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
            expected_m: P2P_NIPOPOW_PROOF_M as u32,
            expected_k: P2P_NIPOPOW_PROOF_K as u32,
            difficulty_params: chain_config.clone(),
            verifier: NipopowVerifier::new(genesis_id_opt, chain_config),
            requested_peers: BTreeSet::new(),
            seen_providers: BTreeSet::new(),
            best_proof_peer: None,
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
        if !validate_bootstrap_response_profile(&proof, self.expected_m, self.expected_k) {
            return None;
        }
        if validate_bootstrap_difficulty_context(&proof, &self.difficulty_params).is_err() {
            return None;
        }
        // `BTreeSet::insert` returns false when the peer was already present:
        // it has already contributed its one counted proof, so drop this one.
        if !self.seen_providers.insert(peer) {
            return None;
        }
        let result = self.verifier.process(proof);
        if matches!(result, NipopowVerificationResult::BetterChain { .. }) {
            self.best_proof_peer = Some(peer);
        }
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

    /// Reject the latched best proof and return the peer that supplied it
    /// (for penalty), leaving the bootstrap RUNNING.
    ///
    /// Used when a proof passes NiPoPoW verification but is unacceptable for
    /// another reason — today, a header at the configured checkpoint height
    /// with the wrong id. The reducer must not go terminal here: marking it
    /// `Applied` when nothing was applied would let a single forged proof
    /// that won best-proof selection disable NiPoPoW bootstrap for the whole
    /// run. Instead:
    ///
    /// * `verifier.reset()` drops only the best proof. `proofs_processed`
    ///   survives (Scala `NipopowVerifier.reset` clears `bestProofOpt` only),
    ///   so honest proofs already counted toward quorum are NOT discarded and
    ///   the next valid proof re-selects immediately.
    /// * State returns to `Requesting`, so other providers still get asked
    ///   and their proofs still land.
    /// * The offending provider stays in `seen_providers`, so it cannot
    ///   re-supply a proof for this bootstrap.
    pub fn reject_best_proof(&mut self) -> Option<PeerId> {
        self.verifier.reset();
        self.state = PopowBootstrapState::Requesting;
        self.best_proof_peer.take()
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

/// Enforce the header-level checkpoint on every header carried by a NiPoPoW
/// proof, BEFORE `StateStore::apply_popow_proof` writes them.
///
/// The proof-apply path writes headers straight into `HEADERS` /
/// `HEADER_META` / `HEADER_CHAIN_INDEX` without going through
/// [`crate::header_proc::finalize_header`], so it would otherwise be the one
/// way a header at the checkpoint height enters the store unchecked.
///
/// DELIBERATE, STRICTER DIVERGENCE FROM SCALA. Scala has the same shortcut and
/// does not close it: `PopowProcessor.applyPopowProof` (~`:143-147`) calls
/// `process(h, nipopowMode = true)` per header directly, bypassing
/// `ErgoHistory.append` → `applicableTry` / `validate`, so `hdrCheckpoint`
/// never runs on nipopow-applied headers there either. Enforcing it here only
/// ever REJECTS chains Scala would have accepted at this seam, and only when
/// the operator has pinned an anchor the proof contradicts — it can never make
/// this node accept something Scala rejects, so consensus compatibility is
/// unaffected.
///
/// Only the header at exactly `checkpoint.height` is constrained; a proof
/// whose sparse prefix skips that height passes this check (it neither
/// confirms nor contradicts the anchor — the snapshot-install anchor check
/// in [`crate::snapshot_bootstrap::manifest`] is what refuses to *trust*
/// state above an unconfirmed anchor).
pub fn check_proof_against_checkpoint(
    proof: &NipopowProof,
    checkpoint: Option<crate::header_proc::HeaderCheckpoint>,
) -> Result<(), crate::header_proc::HeaderProcessError> {
    let Some(ckpt) = checkpoint else {
        return Ok(());
    };
    let headers = proof
        .prefix
        .iter()
        .map(|p| &p.header)
        .chain(std::iter::once(&proof.suffix_head.header))
        .chain(proof.suffix_tail.iter());
    for header in headers {
        if header.height != ckpt.height {
            continue;
        }
        let (_bytes, id) = ergo_ser::header::serialize_header(header).map_err(|e| {
            crate::header_proc::HeaderProcessError::Deserialize(format!(
                "popow proof header at checkpoint height: {e:?}"
            ))
        })?;
        ckpt.check(header.height, id.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::read_header;
    use ergo_ser::popow_header::PoPowHeader;
    use ergo_validation::popow::algos::{build_popow_header, pack_interlinks};

    // ----- helpers -----

    const GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";
    const HEIGHT_2_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

    fn header(s: &str) -> Header {
        let raw = hex::decode(s).unwrap();
        let mut r = VlqReader::new(&raw);
        read_header(&mut r).unwrap()
    }

    fn header_id_of(h: &Header) -> [u8; 32] {
        let (_bytes, id) = ergo_ser::header::serialize_header(h).unwrap();
        *id.as_bytes()
    }

    #[derive(serde::Deserialize)]
    struct HeaderRow {
        height: u32,
        bytes: String,
    }

    static MAINNET_HEADERS: OnceLock<Vec<Header>> = OnceLock::new();

    fn mainnet_headers() -> &'static [Header] {
        MAINNET_HEADERS.get_or_init(|| {
            let raw = include_str!("../../test-vectors/mainnet/headers_1_2000.json");
            let rows: Vec<HeaderRow> = serde_json::from_str(raw).unwrap();
            rows.into_iter()
                .enumerate()
                .map(|(index, row)| {
                    assert_eq!(row.height as usize, index + 1);
                    let bytes = hex::decode(row.bytes).unwrap();
                    read_header(&mut VlqReader::new(&bytes)).unwrap()
                })
                .collect()
        })
    }

    fn header_at(height: u32) -> &'static Header {
        &mainnet_headers()[(height - 1) as usize]
    }

    fn difficulty_popow_hdr(header: Header, interlink_header: Option<&Header>) -> PoPowHeader {
        if header.height == 1 {
            return build_popow_header(header, vec![], &[]).unwrap();
        }
        let interlink = interlink_header.expect("non-genesis PoPowHeader requires interlinks");
        let links = vec![ModifierId::from_bytes(header_id_of(interlink))];
        let fields = pack_interlinks(&links);
        build_popow_header(header, links, &fields).unwrap()
    }

    fn difficulty_proof() -> NipopowProof {
        let genesis = header_at(1);
        NipopowProof {
            m: P2P_NIPOPOW_PROOF_M as u32,
            k: P2P_NIPOPOW_PROOF_K as u32,
            prefix: vec![difficulty_popow_hdr(genesis.clone(), None)],
            suffix_head: difficulty_popow_hdr(header_at(2).clone(), Some(genesis)),
            suffix_tail: (3..=11).map(|height| header_at(height).clone()).collect(),
            continuous: true,
        }
    }

    fn boundary_proof() -> NipopowProof {
        let mut prefix_heights = vec![1];
        prefix_heights.extend((1..=8).map(|epoch| epoch * 128));
        prefix_heights.push(1151);
        let mut previous = None;
        let prefix = prefix_heights
            .into_iter()
            .map(|height| {
                let entry =
                    difficulty_popow_hdr(header_at(height).clone(), previous.map(header_at));
                previous = Some(height);
                entry
            })
            .collect();
        NipopowProof {
            m: P2P_NIPOPOW_PROOF_M as u32,
            k: P2P_NIPOPOW_PROOF_K as u32,
            prefix,
            suffix_head: difficulty_popow_hdr(header_at(1152).clone(), Some(header_at(1151))),
            suffix_tail: (1153..=1161)
                .map(|height| header_at(height).clone())
                .collect(),
            continuous: true,
        }
    }

    fn popow_hdr(h: Header) -> PoPowHeader {
        if h.height == 1 {
            return PoPowHeader {
                header: h,
                interlinks: vec![],
                interlinks_proof: vec![0u8; 8],
            };
        }
        let links = vec![ModifierId::from_bytes(header_id_of(&header(GENESIS_HEX)))];
        let fields = pack_interlinks(&links);
        build_popow_header(h, links, &fields).unwrap()
    }

    fn valid_proof() -> NipopowProof {
        NipopowProof {
            m: P2P_NIPOPOW_PROOF_M as u32,
            k: 1,
            prefix: vec![popow_hdr(header(GENESIS_HEX))],
            suffix_head: popow_hdr(header(HEIGHT_2_HEX)),
            suffix_tail: vec![],
            continuous: true,
        }
    }

    fn peer(i: u8) -> PeerId {
        PeerId::from(std::net::SocketAddr::from(([127, 0, 0, i], 9030u16)))
    }

    fn fresh_bootstrap(quorum: u32) -> PopowBootstrap {
        let mut bootstrap = PopowBootstrap::new(quorum, None, DifficultyParams::mainnet());
        bootstrap.expected_k = 1;
        bootstrap
    }

    #[test]
    fn response_profile_accepts_continuous_h1_to_h2_fixture() {
        assert!(validate_bootstrap_response_profile(
            &valid_proof(),
            P2P_NIPOPOW_PROOF_M as u32,
            1,
        ));
    }

    #[test]
    fn response_profile_rejects_wrong_m() {
        let mut proof = valid_proof();
        proof.m = 5;
        assert!(!validate_bootstrap_response_profile(
            &proof,
            P2P_NIPOPOW_PROOF_M as u32,
            1,
        ));
    }

    #[test]
    fn response_profile_rejects_wrong_k() {
        let mut proof = valid_proof();
        proof.k = 2;
        assert!(!validate_bootstrap_response_profile(
            &proof,
            P2P_NIPOPOW_PROOF_M as u32,
            1,
        ));
    }

    #[test]
    fn response_profile_rejects_non_continuous_proof() {
        let mut proof = valid_proof();
        proof.continuous = false;
        assert!(!validate_bootstrap_response_profile(
            &proof,
            P2P_NIPOPOW_PROOF_M as u32,
            1,
        ));
    }

    #[test]
    fn response_profile_rejects_short_suffix() {
        assert!(!validate_bootstrap_response_profile(
            &valid_proof(),
            P2P_NIPOPOW_PROOF_M as u32,
            2,
        ));
    }

    #[test]
    fn response_profile_rejects_oversized_suffix() {
        let mut proof = valid_proof();
        proof.suffix_tail.push(header(HEIGHT_2_HEX));
        assert!(!validate_bootstrap_response_profile(
            &proof,
            P2P_NIPOPOW_PROOF_M as u32,
            1,
        ));
    }

    #[test]
    fn response_profile_accepts_contiguous_suffix_heights() {
        let mut proof = valid_proof();
        proof.k = 2;
        let mut tail = header(HEIGHT_2_HEX);
        tail.height = 3;
        proof.suffix_tail.push(tail);
        assert!(validate_bootstrap_response_profile(
            &proof,
            P2P_NIPOPOW_PROOF_M as u32,
            2,
        ));
    }

    #[test]
    fn response_profile_rejects_suffix_height_gap() {
        let mut proof = valid_proof();
        proof.k = 2;
        let mut tail = header(HEIGHT_2_HEX);
        tail.height = 4;
        proof.suffix_tail.push(tail);
        assert!(!validate_bootstrap_response_profile(
            &proof,
            P2P_NIPOPOW_PROOF_M as u32,
            2,
        ));
    }

    #[test]
    fn invalid_profile_does_not_consume_provider() {
        let mut b = fresh_bootstrap(1);
        b.mark_requested(peer(1), Instant::now());
        let mut proof = valid_proof();
        proof.m = 5;
        assert!(b.on_proof_received(peer(1), proof).is_none());
        assert_eq!(b.provider_count(), 0);
        assert_eq!(b.proofs_processed(), 0);
    }

    #[test]
    fn profile_valid_retry_from_same_peer_counts() {
        let mut b = fresh_bootstrap(1);
        b.mark_requested(peer(1), Instant::now());
        let mut proof = valid_proof();
        proof.m = 5;
        assert!(b.on_proof_received(peer(1), proof).is_none());
        let result = b.on_proof_received(peer(1), valid_proof());
        assert!(matches!(
            result,
            Some(NipopowVerificationResult::BetterChain { .. })
        ));
        assert_eq!(b.provider_count(), 1);
        assert_eq!(b.proofs_processed(), 1);
    }

    #[test]
    fn production_defaults_use_p2p_popow_profile() {
        let b = PopowBootstrap::new(2, None, DifficultyParams::mainnet());
        assert_eq!(b.expected_m, P2P_NIPOPOW_PROOF_M as u32);
        assert_eq!(b.expected_k, P2P_NIPOPOW_PROOF_K as u32);
        assert_eq!(b.expected_m, 6);
        assert_eq!(b.expected_k, 10);
    }

    #[test]
    fn real_mainnet_h1_through_h11_context_validates() {
        let proof = difficulty_proof();
        assert_eq!(proof.prefix[0].header.height, 1);
        assert_eq!(proof.suffix_head.header.height, 2);
        assert_eq!(proof.suffix_tail.last().unwrap().height, 11);
        assert!(
            validate_bootstrap_difficulty_context(&proof, &DifficultyParams::mainnet()).is_ok()
        );
    }

    #[test]
    fn committed_scala_mainnet_proof_context_validates() {
        let bytes = include_bytes!("../../test-vectors/mainnet/nipopow/proof_m6_k10.scala.bin");
        let proof = ergo_ser::popow_proof::deserialize_nipopow_proof(bytes).unwrap();
        assert!(validate_bootstrap_response_profile(&proof, 6, 10));
        assert!(
            validate_bootstrap_difficulty_context(&proof, &DifficultyParams::mainnet()).is_ok()
        );
    }

    #[test]
    fn mutated_suffix_nbits_rejects() {
        let mut proof = difficulty_proof();
        proof.suffix_tail.last_mut().unwrap().n_bits ^= 1;
        assert_eq!(
            validate_bootstrap_difficulty_context(&proof, &DifficultyParams::mainnet()),
            Err(PopowBootstrapDifficultyError::ConsensusDifficultyMismatch { height: 11 })
        );
    }

    #[test]
    fn mutated_suffix_parent_rejects() {
        let mut proof = difficulty_proof();
        proof.suffix_tail.last_mut().unwrap().parent_id = ModifierId::from_bytes([0xee; 32]);
        assert_eq!(
            validate_bootstrap_difficulty_context(&proof, &DifficultyParams::mainnet()),
            Err(PopowBootstrapDifficultyError::ParentIdMismatch { height: 11 })
        );
    }

    #[test]
    fn non_increasing_suffix_timestamp_rejects() {
        let mut proof = difficulty_proof();
        proof.suffix_tail.last_mut().unwrap().timestamp = header_at(10).timestamp;
        assert_eq!(
            validate_bootstrap_difficulty_context(&proof, &DifficultyParams::mainnet()),
            Err(PopowBootstrapDifficultyError::NonIncreasingTimestamp { height: 11 })
        );
    }

    #[test]
    fn mutated_genesis_nbits_rejects() {
        let mut proof = difficulty_proof();
        proof.prefix[0].header.n_bits ^= 1;
        assert_eq!(
            validate_bootstrap_difficulty_context(&proof, &DifficultyParams::mainnet()),
            Err(PopowBootstrapDifficultyError::InitialDifficultyMismatch { height: 1 })
        );
    }

    #[test]
    fn missing_required_boundary_context_fails_closed() {
        let mut proof = boundary_proof();
        assert!(validate_bootstrap_response_profile(&proof, 6, 10));
        assert!(
            validate_bootstrap_difficulty_context(&proof, &DifficultyParams::mainnet()).is_ok()
        );
        let index = proof
            .prefix
            .iter()
            .position(|entry| entry.header.height == 1024)
            .unwrap();
        proof.prefix.remove(index);
        assert_eq!(
            validate_bootstrap_difficulty_context(&proof, &DifficultyParams::mainnet()),
            Err(PopowBootstrapDifficultyError::MissingContext { height: 1024 })
        );
    }

    #[test]
    fn duplicate_and_conflicting_proof_heights_reject() {
        let mut duplicate = difficulty_proof();
        duplicate
            .suffix_tail
            .push(duplicate.suffix_tail.last().unwrap().clone());
        assert_eq!(
            validate_bootstrap_difficulty_context(&duplicate, &DifficultyParams::mainnet()),
            Err(PopowBootstrapDifficultyError::DuplicateProofHeight { height: 11 })
        );

        let mut conflicting = difficulty_proof();
        let mut header = conflicting.suffix_tail.last().unwrap().clone();
        header.n_bits ^= 1;
        conflicting.suffix_tail.push(header);
        assert_eq!(
            validate_bootstrap_difficulty_context(&conflicting, &DifficultyParams::mainnet()),
            Err(PopowBootstrapDifficultyError::DuplicateProofHeight { height: 11 })
        );
    }

    #[test]
    fn missing_direct_parent_context_does_not_consume_provider() {
        let mut bootstrap = PopowBootstrap::new(1, None, DifficultyParams::mainnet());
        bootstrap.mark_requested(peer(1), Instant::now());
        let mut incomplete = difficulty_proof();
        incomplete.prefix.clear();
        assert!(validate_bootstrap_response_profile(&incomplete, 6, 10));
        assert!(bootstrap.on_proof_received(peer(1), incomplete).is_none());
        assert_eq!(bootstrap.provider_count(), 0);
        assert_eq!(bootstrap.proofs_processed(), 0);
        assert!(matches!(
            bootstrap.on_proof_received(peer(1), difficulty_proof()),
            Some(NipopowVerificationResult::BetterChain { .. })
        ));
        assert_eq!(bootstrap.provider_count(), 1);
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

    #[test]
    fn proof_checkpoint_absent_accepts_proof() {
        assert!(check_proof_against_checkpoint(&valid_proof(), None).is_ok());
    }

    #[test]
    fn proof_checkpoint_matching_id_accepts_proof() {
        let proof = valid_proof();
        let ckpt = crate::header_proc::HeaderCheckpoint {
            height: 2,
            block_id: header_id_of(&proof.suffix_head.header),
        };
        assert!(check_proof_against_checkpoint(&proof, Some(ckpt)).is_ok());
    }

    #[test]
    fn proof_checkpoint_height_absent_from_proof_accepts_proof() {
        // A sparse prefix that skips the checkpoint height neither confirms
        // nor contradicts the anchor; refusing to *trust* state above an
        // unconfirmed anchor is the snapshot-install check's job.
        let proof = valid_proof();
        let ckpt = crate::header_proc::HeaderCheckpoint {
            height: 500_000,
            block_id: [0x7f; 32],
        };
        assert!(check_proof_against_checkpoint(&proof, Some(ckpt)).is_ok());
    }

    // A proof that wins best-proof selection but is later found unacceptable
    // (wrong header at the checkpoint height) must NOT make the reducer
    // terminal: that would let one forged proof disable NiPoPoW for the
    // whole run while reporting a bootstrap that never happened. These two
    // tests are the happy-path illustration that rejection is recoverable;
    // the adversarial angle (rejected peer can't just try again) lives in
    // error paths below.
    #[test]
    fn reject_best_proof_returns_provider_and_keeps_bootstrap_running() {
        let mut b = fresh_bootstrap(1);
        b.mark_requested(peer(1), Instant::now());
        let _ = b.on_proof_received(peer(1), valid_proof());
        assert!(b.quorum_reached());

        let culprit = b.reject_best_proof();

        assert_eq!(culprit, Some(peer(1)), "the provider must be attributable");
        assert_eq!(b.state(), PopowBootstrapState::Requesting);
        assert!(b.is_active(true), "the bootstrap must still be active");
        assert!(b.best_proof().is_none(), "the bad proof must be dropped");
        assert_eq!(
            b.proofs_processed(),
            1,
            "honest proofs already counted toward quorum survive (Scala \
             NipopowVerifier.reset clears only bestProofOpt)",
        );
    }

    #[test]
    fn honest_proof_after_rejection_completes_bootstrap() {
        let mut b = fresh_bootstrap(1);
        b.mark_requested(peer(1), Instant::now());
        let _ = b.on_proof_received(peer(1), valid_proof());
        let _ = b.reject_best_proof();

        b.mark_requested(peer(2), Instant::now());
        let r = b.on_proof_received(peer(2), valid_proof());
        assert!(
            matches!(r, Some(NipopowVerificationResult::BetterChain { .. })),
            "a fresh provider's proof re-selects after a rejection: {r:?}",
        );
        assert!(b.quorum_reached(), "bootstrap must still be able to finish");
        assert!(b.best_proof().is_some());
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

    #[test]
    fn rejected_provider_cannot_resupply_a_proof() {
        // The offending peer stays in `seen_providers`, so it gets exactly
        // one shot at this bootstrap.
        let mut b = fresh_bootstrap(1);
        b.mark_requested(peer(1), Instant::now());
        let _ = b.on_proof_received(peer(1), valid_proof());
        let _ = b.reject_best_proof();
        assert!(
            b.on_proof_received(peer(1), valid_proof()).is_none(),
            "a rejected provider must not get a second proof counted",
        );
    }

    #[test]
    fn proof_checkpoint_wrong_id_at_checkpoint_height_rejects_proof() {
        let proof = valid_proof();
        let ckpt = crate::header_proc::HeaderCheckpoint {
            height: 2,
            block_id: [0x7f; 32],
        };
        let err = check_proof_against_checkpoint(&proof, Some(ckpt))
            .expect_err("proof header at the checkpoint height with a wrong id must be refused");
        assert!(
            matches!(
                err,
                crate::header_proc::HeaderProcessError::CheckpointMismatch { height: 2, .. }
            ),
            "expected CheckpointMismatch at height 2, got {err:?}"
        );
    }

    #[test]
    fn proof_checkpoint_checks_prefix_headers_too() {
        // The anchor must cover the sparse prefix, not just the suffix:
        // genesis sits in `prefix` at height 1.
        let proof = valid_proof();
        let ckpt = crate::header_proc::HeaderCheckpoint {
            height: 1,
            block_id: [0x7f; 32],
        };
        let err = check_proof_against_checkpoint(&proof, Some(ckpt))
            .expect_err("prefix header at the checkpoint height must be checked");
        assert!(
            matches!(
                err,
                crate::header_proc::HeaderProcessError::CheckpointMismatch { height: 1, .. }
            ),
            "expected CheckpointMismatch at height 1, got {err:?}"
        );
    }
}

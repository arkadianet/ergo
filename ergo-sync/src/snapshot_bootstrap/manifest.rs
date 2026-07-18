//! Manifest-discovery reducer for the Mode 2 UTXO snapshot
//! bootstrap: per-peer `SnapshotsInfo` vote tracking, quorum
//! selection, manifest request/timeout ownership, and trust
//! verification against the header chain's `state_root`. See the
//! parent module doc for the full protocol context.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ergo_p2p::peer::PeerId;
use ergo_primitives::digest::ADDigest;

/// How long a peer has to reply to `GetManifest` before we evict
/// their vote and rotate to another voter for the same selected
/// manifest. Matches Scala's snapshot-fetch timeout window. Short
/// enough that a wedged peer doesn't stall bootstrap; long enough
/// that a slow-but-honest peer gets a fair chance.
pub const MANIFEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Outcome of comparing a peer-supplied `manifest_id` against the
/// header chain's `state_root` at the snapshot height. `Ok(())`
/// means the peer's manifest is trustworthy — the trees the peer
/// will reconstruct from chunks will hash to a root the canonical
/// chain has already committed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestVerifyError {
    /// The manifest_id (32-byte AVL+ root label) does not match
    /// the first 32 bytes of the header's `state_root` (33-byte
    /// ADDigest). Possible causes: dishonest peer advertising a
    /// fabricated snapshot, peer on a different chain, or local
    /// chain index returning the wrong header for the snapshot
    /// height. The caller evicts the voter and recomputes
    /// selection in any case — wrong is wrong, regardless of
    /// motive.
    RootMismatch {
        expected_manifest_id: [u8; 32],
        actual_state_root_prefix: [u8; 32],
    },
}

/// Trust-check a `manifest_id` against a header's `state_root`.
///
/// Contract: the header MUST have been fetched from the canonical
/// best-header chain at the snapshot height (the caller is
/// responsible for the chain lookup; this function does not see
/// the chain index). On a reorg between selection and verification
/// the caller must re-fetch and re-verify.
///
/// Comparison rule: `manifest_id == state_root.as_bytes()[..32]`.
/// `ADDigest` is 33 bytes (32-byte AVL+ root label + 1-byte tree
/// height); we compare only the first 32 against the snapshot
/// codec's manifest_id (which is the root label by construction —
/// see `SnapshotServer::build` in `ergo-state`).
///
/// **Oracle gap — provisional:** the prefix-32 rule is the only
/// interpretation consistent with our own serve-side construction;
/// it has not yet been pinned against a Scala-produced manifest +
/// header pair. Consume-side trust verification stays PROVISIONAL
/// until a Scala mainnet snapshot's `manifest_id` and the matching
/// header `state_root` at the same height are captured and the byte
/// relationship is confirmed.
pub fn verify_manifest_against_state_root(
    manifest_id: &[u8; 32],
    state_root: &ADDigest,
) -> Result<(), ManifestVerifyError> {
    let prefix = &state_root.as_bytes()[..32];
    if prefix == manifest_id {
        Ok(())
    } else {
        let mut actual = [0u8; 32];
        actual.copy_from_slice(prefix);
        Err(ManifestVerifyError::RootMismatch {
            expected_manifest_id: *manifest_id,
            actual_state_root_prefix: actual,
        })
    }
}

/// Quorum threshold matching Scala `MinManifestVotes = 3`.
/// Configurable via [`SnapshotBootstrap::with_quorum`] for tests
/// that don't want to construct three distinct synthetic peers.
pub const MIN_MANIFEST_VOTES: usize = 3;

/// One peer's vote: the `(height, manifest_id)` they advertised as
/// their best snapshot. A peer that advertises an empty list has
/// no recorded vote (their entry is removed from the tally).
type PeerVote = (i32, [u8; 32]);

/// Public view of the reducer's selection state.
///
/// State progression for a Mode 2 consume-side bootstrap:
///
/// `Idle` → `Querying` → `Selected` → `ManifestRequested`
///                                  → `ManifestVerified`
///
/// `ManifestRequested` falls back to `Selected` (or further) when
/// the chosen voter times out or replies with a manifest that
/// fails the trust check — their vote is evicted and selection is
/// recomputed across the remaining quorum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapState {
    /// No peer responses recorded yet.
    Idle,
    /// At least one vote recorded but no quorum yet.
    Querying,
    /// Quorum reached — manifest is identified but not yet
    /// requested.
    Selected { height: i32, manifest_id: [u8; 32] },
    /// A `GetManifest` request is outstanding to `peer`. State
    /// stays here until the peer replies (and trust verification
    /// runs) or the request times out and we rotate to another
    /// voter.
    ManifestRequested {
        peer: PeerId,
        height: i32,
        manifest_id: [u8; 32],
    },
    /// The peer replied with a manifest that matched the header
    /// chain's `state_root` at `height` — bytes are stashed for
    /// hand-off to the chunk-download phase (part 2h) exactly
    /// once via [`SnapshotBootstrap::take_verified_manifest_bytes`].
    ManifestVerified { height: i32, manifest_id: [u8; 32] },
}

/// Discovery-phase reducer for the Mode 2 consume side.
pub struct SnapshotBootstrap {
    /// One vote per peer. Reinsertion replaces the prior vote
    /// (peers that change their advertisement during the discovery
    /// window get the new vote counted, the old one dropped).
    pub(super) votes: HashMap<PeerId, PeerVote>,
    /// Quorum threshold. Default = [`MIN_MANIFEST_VOTES`].
    quorum: usize,
    /// Cached result of the last [`Self::recompute_selection`] call.
    /// `None` means no quorum; `Some` means quorum was reached at
    /// the stored `(height, manifest_id)`.
    selected: Option<PeerVote>,
    /// Peers we've already sent `GetSnapshotsInfo` to during the
    /// current discovery epoch. The outbound fan-out (part 2f-3)
    /// consults this so each eligible peer is queried at most once
    /// per epoch. Cleared per-peer on disconnect (a reconnecting
    /// peer is re-queried).
    discovery_queried: HashSet<PeerId>,
    /// Outstanding `GetManifest` request. `Some` while we're
    /// waiting for a reply from `peer` that matches the selected
    /// `manifest_id`. Replies from any other peer or for any other
    /// manifest_id are ignored — strict request ownership.
    pending_request: Option<PendingManifestRequest>,
    /// Sticky marker set when trust verification succeeds. Stays
    /// `Some` for the rest of the bootstrap session (even after
    /// the chunk-download phase has taken the bytes) so the state
    /// machine never re-fires `GetManifest` for a manifest already
    /// verified. The inner `bytes` is what gets consumed by 2h.
    verified: Option<VerifiedManifest>,
}

/// Tracks an outstanding `GetManifest` request for timeout +
/// strict-ownership purposes.
#[derive(Debug, Clone, Copy)]
struct PendingManifestRequest {
    peer: PeerId,
    height: i32,
    manifest_id: [u8; 32],
    requested_at: Instant,
}

/// Latches a manifest that passed trust verification. `bytes` is
/// consumed exactly once by part 2h via
/// [`SnapshotBootstrap::take_verified_manifest_bytes`]; the
/// surrounding `(height, manifest_id)` stays so the reducer keeps
/// reporting `ManifestVerified` and never re-issues a request.
struct VerifiedManifest {
    height: i32,
    manifest_id: [u8; 32],
    bytes: Option<Vec<u8>>,
}

impl SnapshotBootstrap {
    /// Construct with the Scala-parity quorum threshold.
    pub fn new() -> Self {
        Self::with_quorum(MIN_MANIFEST_VOTES)
    }

    /// Construct with a custom quorum threshold. Test-only ergonomics —
    /// production callers should use [`Self::new`].
    pub fn with_quorum(quorum: usize) -> Self {
        Self {
            votes: HashMap::new(),
            quorum,
            selected: None,
            discovery_queried: HashSet::new(),
            pending_request: None,
            verified: None,
        }
    }

    /// Record a peer's `SnapshotsInfo` response. The peer's vote is
    /// the *highest-height* entry in `manifests`. An empty list
    /// removes any prior vote from this peer (they had something,
    /// then evicted it, then re-advertised). Recomputes selection.
    pub fn on_snapshots_info(&mut self, peer: PeerId, manifests: &[(i32, [u8; 32])]) {
        match manifests.iter().max_by_key(|(h, _)| *h) {
            Some(vote) => {
                self.votes.insert(peer, *vote);
            }
            None => {
                self.votes.remove(&peer);
            }
        }
        self.recompute_selection();
    }

    /// Forget a peer's vote on disconnect. Recomputes selection —
    /// if the disconnecting peer was the third (i.e., quorum-making)
    /// vote, the selection reverts to `Querying`. Also clears the
    /// peer from `discovery_queried` so a reconnect triggers a
    /// fresh `GetSnapshotsInfo`.
    pub fn on_peer_disconnect(&mut self, peer: &PeerId) {
        self.discovery_queried.remove(peer);
        if self.votes.remove(peer).is_some() {
            self.recompute_selection();
        }
    }

    /// True when the outbound fan-out should send `GetSnapshotsInfo`
    /// to this peer. Returns `false` once we've already queried them
    /// in this discovery epoch, or once we've reached `Selected`
    /// (no need to keep asking — manifest download phase takes over).
    pub fn should_query(&self, peer: &PeerId) -> bool {
        if matches!(self.state(), BootstrapState::Selected { .. }) {
            return false;
        }
        !self.discovery_queried.contains(peer)
    }

    /// Record that we've sent `GetSnapshotsInfo` to this peer.
    /// Pair with [`Self::should_query`] in the fan-out loop.
    pub fn mark_queried(&mut self, peer: PeerId) {
        self.discovery_queried.insert(peer);
    }

    /// Current selection state. Computes the public state from
    /// internal fields: verified > pending > selected > votes.
    pub fn state(&self) -> BootstrapState {
        if let Some(v) = &self.verified {
            return BootstrapState::ManifestVerified {
                height: v.height,
                manifest_id: v.manifest_id,
            };
        }
        if let Some(pending) = &self.pending_request {
            return BootstrapState::ManifestRequested {
                peer: pending.peer,
                height: pending.height,
                manifest_id: pending.manifest_id,
            };
        }
        match self.selected {
            Some((height, manifest_id)) => BootstrapState::Selected {
                height,
                manifest_id,
            },
            None if self.votes.is_empty() => BootstrapState::Idle,
            None => BootstrapState::Querying,
        }
    }

    /// Pick any peer whose vote matches the currently-selected
    /// manifest. Used by the outbound trigger to choose a target
    /// for `GetManifest`. Returns `None` when not Selected or when
    /// every voter has been evicted (selection should re-converge
    /// or fall back to lower-height quorum).
    pub fn voter_for_selected_manifest(&self) -> Option<PeerId> {
        let target = self.selected?;
        self.votes
            .iter()
            .find(|(_, vote)| **vote == target)
            .map(|(peer, _)| *peer)
    }

    /// All peers whose vote matches the currently-selected
    /// manifest. The chunk-download fan-out (part 2h-3) iterates
    /// this list to spread chunk requests across the quorum rather
    /// than hammer the single manifest responder. Returns an empty
    /// `Vec` when not Selected.
    ///
    /// Includes the peer that already served the manifest — they
    /// can serve chunks too. Excludes only peers we've explicitly
    /// evicted via `reject_manifest_and_evict_voter`.
    pub fn voters_for_selected_manifest(&self) -> Vec<PeerId> {
        let Some(target) = self.selected else {
            return Vec::new();
        };
        self.votes
            .iter()
            .filter(|(_, vote)| **vote == target)
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// True when the integration layer should send a fresh
    /// `GetManifest`. Returns the request triple to send. Returns
    /// `None` when:
    ///
    /// * not in `Selected` state,
    /// * a request is already pending,
    /// * already verified (the sticky `verified` latch suppresses
    ///   further requests even after bytes have been taken), or
    /// * no voter for the selected manifest is reachable.
    pub fn should_request_manifest(&self) -> Option<(PeerId, i32, [u8; 32])> {
        if self.pending_request.is_some() || self.verified.is_some() {
            return None;
        }
        let (height, manifest_id) = self.selected?;
        let peer = self.voter_for_selected_manifest()?;
        Some((peer, height, manifest_id))
    }

    /// Record that `GetManifest` was sent. Transitions `Selected`
    /// → `ManifestRequested`. Idempotent only at the
    /// (peer, manifest_id) level — calling with a different peer
    /// while one is pending is a programmer error and panics in
    /// debug builds.
    pub fn mark_manifest_requested(
        &mut self,
        peer: PeerId,
        height: i32,
        manifest_id: [u8; 32],
        now: Instant,
    ) {
        debug_assert!(
            self.pending_request.is_none(),
            "mark_manifest_requested called while another request is pending",
        );
        self.pending_request = Some(PendingManifestRequest {
            peer,
            height,
            manifest_id,
            requested_at: now,
        });
    }

    /// Inbound `Manifest` (code 79) bytes arrived. Returns:
    ///
    /// * `Some((height, manifest_id, bytes))` if the reply matches
    ///   our pending request (from the peer we asked) — caller MUST
    ///   now run the trust check using the returned height to look
    ///   up the canonical header, then call either
    ///   `accept_verified_manifest` or `reject_manifest_and_evict_voter`.
    /// * `None` if the reply is stale, unsolicited, or from the
    ///   wrong peer — caller silently drops the bytes.
    ///
    /// Returning the metadata alongside the bytes saves the caller a
    /// second state() lookup and avoids a window where state could
    /// change between calls.
    pub fn on_manifest_received(
        &mut self,
        from_peer: PeerId,
        bytes: Vec<u8>,
    ) -> Option<(i32, [u8; 32], Vec<u8>)> {
        let pending = self.pending_request.as_ref()?;
        if pending.peer == from_peer {
            Some((pending.height, pending.manifest_id, bytes))
        } else {
            None
        }
    }

    /// Caller's trust check succeeded — latch the verified bytes
    /// against `(height, manifest_id)` captured from the pending
    /// request. Clears the pending request. State transitions
    /// `ManifestRequested` → `ManifestVerified`.
    pub fn accept_verified_manifest(&mut self, bytes: Vec<u8>) {
        let pending = self
            .pending_request
            .take()
            .expect("accept_verified_manifest with no pending request");
        debug_assert!(
            self.verified.is_none(),
            "accept_verified_manifest called twice (verified already latched)",
        );
        self.verified = Some(VerifiedManifest {
            height: pending.height,
            manifest_id: pending.manifest_id,
            bytes: Some(bytes),
        });
    }

    /// Caller's trust check failed OR the manifest reply was
    /// missing — the chosen voter is dishonest about that height.
    /// Evicts their vote, recomputes selection, clears the pending
    /// request. State transitions back to `Selected` (different
    /// voter, same or new manifest) / `Querying` / `Idle` depending
    /// on what the remaining quorum supports.
    pub fn reject_manifest_and_evict_voter(&mut self, peer: PeerId) {
        self.pending_request = None;
        self.votes.remove(&peer);
        self.recompute_selection();
    }

    /// Time-out check. If the pending request has been outstanding
    /// longer than [`MANIFEST_REQUEST_TIMEOUT`], evict the
    /// non-responsive voter and recompute selection so the next
    /// `sync_tick` rotates to another voter (or falls back to
    /// `Querying` if the timeout dropped us below quorum).
    /// No-op when no request is pending.
    pub fn check_request_timeout(&mut self, now: Instant) {
        let Some(pending) = self.pending_request else {
            return;
        };
        if now.duration_since(pending.requested_at) >= MANIFEST_REQUEST_TIMEOUT {
            self.reject_manifest_and_evict_voter(pending.peer);
        }
    }

    /// Hand verified manifest bytes off to the chunk-download
    /// phase (part 2h). Consumes the bytes exactly once. The
    /// `verified` latch stays set, so the state machine continues
    /// to report `ManifestVerified` and never re-issues a
    /// `GetManifest` — even after bytes are gone. Returns `None`
    /// if no verified manifest is stashed or bytes were already
    /// taken.
    pub fn take_verified_manifest_bytes(&mut self) -> Option<Vec<u8>> {
        self.verified.as_mut()?.bytes.take()
    }

    /// Re-tally votes and pick the highest-height entry that has
    /// `>= self.quorum` agreement. Called whenever votes change.
    fn recompute_selection(&mut self) {
        let mut tally: HashMap<PeerVote, usize> = HashMap::new();
        for vote in self.votes.values() {
            *tally.entry(*vote).or_insert(0) += 1;
        }
        self.selected = tally
            .into_iter()
            .filter(|(_, count)| *count >= self.quorum)
            .map(|(vote, _)| vote)
            .max_by_key(|(h, _)| *h);
    }
}

impl Default for SnapshotBootstrap {
    fn default() -> Self {
        Self::new()
    }
}

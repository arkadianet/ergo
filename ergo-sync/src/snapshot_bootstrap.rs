//! Mode 2 (UTXO snapshot bootstrap) consume-side discovery reducer.
//!
//! Pure state machine: tracks per-peer `SnapshotsInfo` responses
//! and applies Scala's quorum selection rule — *the highest height
//! at which `>= MIN_MANIFEST_VOTES` peers agree on the same
//! manifest_id wins*.
//!
//! No I/O lives here. The ergo-node integration layer (sub-phase
//! 2f-2) calls [`SnapshotBootstrap::on_snapshots_info`] when an
//! inbound `SnapshotsInfo` (code 77) arrives, and queries
//! [`SnapshotBootstrap::state`] each tick to learn when a manifest
//! has been selected so it can transition to the manifest-download
//! phase (sub-phase 2g).
//!
//! **Eligibility filtering is the caller's responsibility.** The
//! reducer accepts every vote it's given; the integration layer
//! gates calls to peers that handshook as Mode 1/2/3 (peers with
//! UTXO state to serve). Votes from Mode 5/6 peers must not reach
//! the reducer.
//!
//! Scala parity reference:
//! * `MinManifestVotes = 3` (this crate's [`MIN_MANIFEST_VOTES`]).
//! * Highest *quorum* height wins — not the highest *advertised*
//!   height. A taller advertisement without supporting votes is
//!   ignored.
//!
//! Tie ambiguity (same height, two different manifest_ids both
//! reaching quorum) is intentionally left to natural iteration
//! order. Scala has no documented tie-break rule, and the part-2g
//! trust check against `header.state_root` at the snapshot height
//! rejects the wrong manifest_id regardless of which we pick, so
//! tie-breaking by hash here would be inventing policy.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ergo_p2p::peer::PeerId;
use ergo_primitives::digest::{ADDigest, Digest32};

/// How long a peer has to reply to `GetManifest` before we evict
/// their vote and rotate to another voter for the same selected
/// manifest. Matches Scala's snapshot-fetch timeout window. Short
/// enough that a wedged peer doesn't stall bootstrap; long enough
/// that a slow-but-honest peer gets a fair chance.
pub const MANIFEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum concurrent `GetUtxoSnapshotChunk` requests across all
/// peers. Caps memory + outbound bandwidth during bootstrap.
/// Scala default for snapshot chunk fetch. Sized so a single
/// peer-window TCP buffer doesn't bottleneck the inflight set.
pub const MAX_INFLIGHT_CHUNKS: usize = 16;

/// Per-chunk request timeout. Same intent as
/// [`MANIFEST_REQUEST_TIMEOUT`] but applied to each
/// `GetUtxoSnapshotChunk` independently. A silent peer's chunk
/// slot is freed and re-tried against another quorum voter.
pub const CHUNK_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
    votes: HashMap<PeerId, PeerVote>,
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

/// Chunk-assembly state machine. Owns the bounded-inflight
/// request set for a single bootstrap's chunk-download phase.
///
/// Lifecycle:
///
/// 1. Initialize with the expected chunk subtree IDs from
///    `ergo_state::avl::snapshot_codec::enumerate_expected_chunk_ids`
///    (DFS order from the verified manifest).
/// 2. Each tick: `next_to_request(now)` returns chunks the
///    integration layer should fan out (capped at
///    [`MAX_INFLIGHT_CHUNKS`] - currently-inflight). The caller
///    sends `GetUtxoSnapshotChunk` and pairs each with
///    `mark_requested`.
/// 3. `on_chunk_received(peer, subtree_id, bytes)` validates
///    strict ownership and bookkeeping; bytes are stashed only on
///    accept.
/// 4. `check_timeouts(now)` rolls back stalled chunk slots so
///    they re-enter the request queue (potentially against
///    another voter).
/// 5. When `is_complete()` returns true, `take_chunks()` hands
///    the map off to the reconstructor exactly once.
///
/// **Eligibility filtering is the caller's responsibility.** This
/// reducer accepts any peer the caller pairs with a request; the
/// integration layer must ensure that peer is in the quorum-voter
/// set for the selected `(height, manifest_id)`.
pub struct ChunkAssembly {
    /// All expected chunk subtree IDs. Order is preserved from the
    /// manifest DFS so the integration layer can fan out in the
    /// same order peers expect (irrelevant to consensus, but it
    /// keeps logs grep-friendly).
    expected: Vec<Digest32>,
    /// Set of expected IDs for O(1) authenticity checks on
    /// inbound chunks. Saves a linear scan of `expected` when a
    /// reply arrives.
    expected_set: HashSet<Digest32>,
    /// In-flight requests: subtree_id → (peer, when requested).
    inflight: HashMap<Digest32, ChunkRequestInflight>,
    /// Received bytes, validated by `on_chunk_received`.
    received: HashMap<Digest32, Vec<u8>>,
    /// True after `take_chunks` is called. Subsequent state
    /// transitions are forbidden (the chunk-set was handed off).
    consumed: bool,
}

#[derive(Debug, Clone, Copy)]
struct ChunkRequestInflight {
    peer: PeerId,
    requested_at: Instant,
}

/// Outcome of [`ChunkAssembly::on_chunk_received`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkReceiveOutcome {
    /// Bytes were accepted and stashed. The integration layer can
    /// continue fan-out for remaining chunks.
    Accepted,
    /// We weren't expecting a chunk with this subtree_id. Could
    /// be a peer pushing unsolicited data or a leftover from a
    /// previous bootstrap session. Silently drop.
    UnknownSubtreeId,
    /// We have this chunk in-flight but it's owned by a different
    /// peer. Silently drop — the rightful owner's response is
    /// still expected.
    WrongPeer,
    /// We already received this chunk. Idempotent drop — peers
    /// retransmitting on packet loss / TCP races don't replace
    /// already-stored bytes.
    Duplicate,
}

impl ChunkAssembly {
    /// Initialize the assembly with the expected chunk IDs from
    /// the verified manifest. Empty list = no chunks needed
    /// (entire tree fits in the manifest); `is_complete()`
    /// returns true immediately in that case.
    pub fn new(expected: Vec<Digest32>) -> Self {
        let expected_set = expected.iter().copied().collect();
        Self {
            expected,
            expected_set,
            inflight: HashMap::new(),
            received: HashMap::new(),
            consumed: false,
        }
    }

    /// Return up to `MAX_INFLIGHT_CHUNKS - current_inflight`
    /// chunk IDs that haven't been requested or received yet.
    /// Order matches `expected` (the manifest's DFS order).
    pub fn next_to_request(&self) -> Vec<Digest32> {
        if self.consumed {
            return Vec::new();
        }
        let slots = MAX_INFLIGHT_CHUNKS.saturating_sub(self.inflight.len());
        if slots == 0 {
            return Vec::new();
        }
        self.expected
            .iter()
            .filter(|id| !self.inflight.contains_key(id) && !self.received.contains_key(id))
            .copied()
            .take(slots)
            .collect()
    }

    /// Record that `GetUtxoSnapshotChunk(subtree_id)` was sent to
    /// `peer`. Pair with [`Self::next_to_request`] in the fan-out
    /// loop. Idempotent at the (peer, subtree_id) level — a
    /// repeated call updates `requested_at` so timeout-eviction
    /// uses the most recent send.
    pub fn mark_requested(&mut self, subtree_id: Digest32, peer: PeerId, now: Instant) {
        debug_assert!(
            !self.consumed,
            "mark_requested after take_chunks (consumed)",
        );
        debug_assert!(
            self.expected_set.contains(&subtree_id),
            "mark_requested for an unknown subtree_id — integration bug",
        );
        self.inflight.insert(
            subtree_id,
            ChunkRequestInflight {
                peer,
                requested_at: now,
            },
        );
    }

    /// Inbound `UtxoSnapshotChunk` (code 81) bytes for a peer-
    /// supplied `subtree_id`. Validates strict ownership against
    /// the inflight set. Returns [`ChunkReceiveOutcome`] reflecting
    /// what the caller should do.
    pub fn on_chunk_received(
        &mut self,
        from_peer: PeerId,
        subtree_id: Digest32,
        bytes: Vec<u8>,
    ) -> ChunkReceiveOutcome {
        if self.consumed {
            return ChunkReceiveOutcome::UnknownSubtreeId;
        }
        if !self.expected_set.contains(&subtree_id) {
            return ChunkReceiveOutcome::UnknownSubtreeId;
        }
        if self.received.contains_key(&subtree_id) {
            return ChunkReceiveOutcome::Duplicate;
        }
        let Some(inflight) = self.inflight.get(&subtree_id) else {
            // No request pending for this subtree_id — unsolicited.
            return ChunkReceiveOutcome::UnknownSubtreeId;
        };
        if inflight.peer != from_peer {
            return ChunkReceiveOutcome::WrongPeer;
        }
        self.inflight.remove(&subtree_id);
        self.received.insert(subtree_id, bytes);
        ChunkReceiveOutcome::Accepted
    }

    /// Roll back in-flight chunk slots whose request is older than
    /// [`CHUNK_REQUEST_TIMEOUT`]. Returns the freed subtree IDs so
    /// the caller can log / re-account (the IDs naturally re-enter
    /// the queue via `next_to_request`). Idempotent if no slots
    /// are stale.
    pub fn check_timeouts(&mut self, now: Instant) -> Vec<Digest32> {
        if self.consumed {
            return Vec::new();
        }
        let stale: Vec<Digest32> = self
            .inflight
            .iter()
            .filter_map(|(id, req)| {
                if now.duration_since(req.requested_at) >= CHUNK_REQUEST_TIMEOUT {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        for id in &stale {
            self.inflight.remove(id);
        }
        stale
    }

    /// Drop a specific peer's in-flight chunk requests (e.g. on
    /// peer disconnect). Returns the subtree IDs freed so they
    /// re-enter the request queue.
    pub fn drop_peer(&mut self, peer: &PeerId) -> Vec<Digest32> {
        if self.consumed {
            return Vec::new();
        }
        let dropped: Vec<Digest32> = self
            .inflight
            .iter()
            .filter_map(|(id, req)| if req.peer == *peer { Some(*id) } else { None })
            .collect();
        for id in &dropped {
            self.inflight.remove(id);
        }
        dropped
    }

    /// True when every expected chunk has been received.
    pub fn is_complete(&self) -> bool {
        !self.consumed && self.received.len() == self.expected.len()
    }

    /// Number of expected chunks. Useful for progress reporting.
    pub fn total_count(&self) -> usize {
        self.expected.len()
    }

    /// Number of chunks received so far.
    pub fn received_count(&self) -> usize {
        self.received.len()
    }

    /// Hand the received chunks off to the reconstructor exactly
    /// once. After this call the assembly is marked `consumed`;
    /// further state mutations are debug-asserted away. Returns
    /// `None` if not yet complete or already consumed.
    pub fn take_chunks(&mut self) -> Option<HashMap<Digest32, Vec<u8>>> {
        if self.consumed || !self.is_complete() {
            return None;
        }
        self.consumed = true;
        Some(std::mem::take(&mut self.received))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // ----- helpers -----

    fn peer(port: u16) -> PeerId {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn mid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // ----- happy path -----

    #[test]
    fn no_votes_is_idle() {
        let bs = SnapshotBootstrap::new();
        assert_eq!(bs.state(), BootstrapState::Idle);
    }

    #[test]
    fn single_vote_below_quorum_is_querying() {
        let mut bs = SnapshotBootstrap::new();
        bs.on_snapshots_info(peer(1), &[(100, mid(0xAA))]);
        assert_eq!(bs.state(), BootstrapState::Querying);
    }

    #[test]
    fn three_peers_same_manifest_advances_to_selected() {
        let mut bs = SnapshotBootstrap::new();
        for p in 1..=3 {
            bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
        }
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: 52_224,
                manifest_id: mid(0xAA),
            }
        );
    }

    #[test]
    fn highest_quorum_height_wins() {
        // Two heights both at quorum — higher height must win.
        let mut bs = SnapshotBootstrap::new();
        for p in 1..=3 {
            bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
        }
        for p in 4..=6 {
            bs.on_snapshots_info(peer(p), &[(104_448, mid(0xBB))]);
        }
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: 104_448,
                manifest_id: mid(0xBB),
            }
        );
    }

    #[test]
    fn higher_advertised_height_without_quorum_loses_to_lower_quorum_height() {
        // Critical rule: highest *quorum* height wins, not highest
        // *advertised* height. Two peers advertise a taller snapshot
        // but never reach quorum; three peers agree on a shorter
        // snapshot. Shorter must win.
        let mut bs = SnapshotBootstrap::new();
        bs.on_snapshots_info(peer(1), &[(200_000, mid(0xCC))]);
        bs.on_snapshots_info(peer(2), &[(200_000, mid(0xCC))]);
        for p in 3..=5 {
            bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
        }
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: 52_224,
                manifest_id: mid(0xAA),
            }
        );
    }

    #[test]
    fn peer_advertises_highest_of_their_list() {
        // A peer can advertise multiple manifests; their "vote" is
        // the highest-height entry. Tests use [(h_low, ..), (h_high, ..)]
        // to make sure we don't accidentally take the first or last.
        let mut bs = SnapshotBootstrap::new();
        for p in 1..=3 {
            bs.on_snapshots_info(
                peer(p),
                &[
                    (52_224, mid(0xAA)),
                    (104_448, mid(0xBB)),
                    (78_336, mid(0xCC)),
                ],
            );
        }
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: 104_448,
                manifest_id: mid(0xBB),
            }
        );
    }

    // ----- duplicate / vote-change handling -----

    #[test]
    fn duplicate_response_from_same_peer_does_not_double_count() {
        // Three calls from the same peer must not satisfy quorum=3.
        let mut bs = SnapshotBootstrap::new();
        for _ in 0..3 {
            bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
        }
        assert_eq!(
            bs.state(),
            BootstrapState::Querying,
            "one peer can never satisfy quorum=3 no matter how many \
             replies they send",
        );
    }

    #[test]
    fn peer_can_change_their_vote() {
        // Peer first advertises manifest A; later switches to B.
        // Only B counts in the tally afterwards.
        let mut bs = SnapshotBootstrap::with_quorum(2);
        bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
        bs.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: 52_224,
                manifest_id: mid(0xAA),
            }
        );

        // Peer 2 changes their advertisement; now A only has 1 vote.
        bs.on_snapshots_info(peer(2), &[(52_224, mid(0xBB))]);
        assert_eq!(
            bs.state(),
            BootstrapState::Querying,
            "A drops from 2 votes to 1; B has 1; neither reaches quorum=2",
        );
    }

    #[test]
    fn empty_manifests_list_drops_peer_vote() {
        // Peer first advertises, then later sends empty list (snapshot
        // was evicted from their SnapshotsDb). Their vote must be removed.
        let mut bs = SnapshotBootstrap::with_quorum(2);
        bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
        bs.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
        assert!(matches!(bs.state(), BootstrapState::Selected { .. }));

        bs.on_snapshots_info(peer(2), &[]);
        assert_eq!(
            bs.state(),
            BootstrapState::Querying,
            "peer 2 withdrew; A has 1 vote, no quorum",
        );
    }

    // ----- disconnect handling -----

    #[test]
    fn disconnect_removes_vote() {
        let mut bs = SnapshotBootstrap::with_quorum(2);
        bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
        bs.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
        assert!(matches!(bs.state(), BootstrapState::Selected { .. }));

        bs.on_peer_disconnect(&peer(2));
        assert_eq!(
            bs.state(),
            BootstrapState::Querying,
            "quorum was 2; disconnect drops to 1 vote",
        );
    }

    #[test]
    fn disconnect_of_unknown_peer_is_idempotent_noop() {
        let mut bs = SnapshotBootstrap::with_quorum(2);
        bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);

        // Disconnect a peer who never voted — no state change.
        bs.on_peer_disconnect(&peer(99));
        assert_eq!(bs.state(), BootstrapState::Querying);
        assert_eq!(bs.votes.len(), 1);
    }

    #[test]
    fn disconnect_of_dissenting_peer_can_raise_selection() {
        // Three peers vote for A; two peers vote for B at a higher
        // height (no quorum). One A-voter disconnects, but the other
        // two are still quorum=2 for A.
        let mut bs = SnapshotBootstrap::with_quorum(2);
        bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
        bs.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
        bs.on_snapshots_info(peer(3), &[(52_224, mid(0xAA))]);
        bs.on_snapshots_info(peer(4), &[(104_448, mid(0xBB))]);
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: 52_224,
                manifest_id: mid(0xAA),
            },
            "A has 3 votes at quorum=2, B has 1 — A wins",
        );

        // A second B-voter arrives. Now B is also quorum=2 at a
        // higher height — B must win.
        bs.on_snapshots_info(peer(5), &[(104_448, mid(0xBB))]);
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: 104_448,
                manifest_id: mid(0xBB),
            },
            "higher-height quorum wins once it exists",
        );
    }

    // ----- lifecycle invariants -----

    #[test]
    fn selection_is_stable_under_unrelated_lower_height_replies() {
        // Once selected at H, later responses at lower heights
        // must not unseat the selection (no oscillation).
        let mut bs = SnapshotBootstrap::with_quorum(2);
        bs.on_snapshots_info(peer(1), &[(104_448, mid(0xAA))]);
        bs.on_snapshots_info(peer(2), &[(104_448, mid(0xAA))]);
        let expected = BootstrapState::Selected {
            height: 104_448,
            manifest_id: mid(0xAA),
        };
        assert_eq!(bs.state(), expected);

        // A non-quorum lower-height response arrives — selection unchanged.
        bs.on_snapshots_info(peer(3), &[(52_224, mid(0xBB))]);
        assert_eq!(bs.state(), expected);
    }

    #[test]
    fn votes_below_quorum_threshold_never_select() {
        // Custom quorum=5; only 4 peers — must stay Querying.
        let mut bs = SnapshotBootstrap::with_quorum(5);
        for p in 1..=4 {
            bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
        }
        assert_eq!(bs.state(), BootstrapState::Querying);
    }

    // ----- outbound query tracking (2f-3) -----

    #[test]
    fn should_query_returns_true_for_unqueried_peer() {
        let bs = SnapshotBootstrap::new();
        assert!(bs.should_query(&peer(1)));
    }

    #[test]
    fn mark_queried_then_should_query_returns_false() {
        let mut bs = SnapshotBootstrap::new();
        bs.mark_queried(peer(1));
        assert!(!bs.should_query(&peer(1)));
        // Other peers still unqueried.
        assert!(bs.should_query(&peer(2)));
    }

    #[test]
    fn should_query_returns_false_in_selected_state_for_all_peers() {
        // Once quorum is reached, the outbound fan-out stops — no
        // matter which peer (queried or not), the discovery loop is
        // over.
        let mut bs = SnapshotBootstrap::new();
        for p in 1..=3u16 {
            bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
        }
        assert!(matches!(bs.state(), BootstrapState::Selected { .. }));
        assert!(
            !bs.should_query(&peer(99)),
            "Selected suppresses all queries"
        );
        assert!(!bs.should_query(&peer(1)), "even already-voted peers");
    }

    #[test]
    fn disconnect_clears_queried_mark_so_reconnect_is_requeried() {
        let mut bs = SnapshotBootstrap::new();
        bs.mark_queried(peer(1));
        assert!(!bs.should_query(&peer(1)));

        bs.on_peer_disconnect(&peer(1));
        assert!(
            bs.should_query(&peer(1)),
            "disconnect must clear queried-mark for reconnection",
        );
    }

    // ----- 2g state machine: ManifestRequested + ManifestVerified -----

    fn reach_selected(quorum: usize) -> SnapshotBootstrap {
        let mut bs = SnapshotBootstrap::with_quorum(quorum);
        for p in 1..=(quorum as u16) {
            bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
        }
        assert!(
            matches!(bs.state(), BootstrapState::Selected { .. }),
            "quorum reached → Selected",
        );
        bs
    }

    #[test]
    fn voter_for_selected_manifest_returns_a_quorum_voter() {
        let bs = reach_selected(3);
        let voter = bs.voter_for_selected_manifest().expect("a voter");
        assert!(
            [peer(1), peer(2), peer(3)].contains(&voter),
            "voter must be one of the actual voters; got {voter:?}",
        );
    }

    #[test]
    fn should_request_manifest_returns_some_when_selected() {
        let bs = reach_selected(3);
        let (peer_id, height, manifest_id) = bs
            .should_request_manifest()
            .expect("Selected → should request");
        assert!([peer(1), peer(2), peer(3)].contains(&peer_id));
        assert_eq!(height, 52_224);
        assert_eq!(manifest_id, mid(0xAA));
    }

    #[test]
    fn should_request_manifest_none_while_pending_request() {
        let mut bs = reach_selected(3);
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
        assert!(
            bs.should_request_manifest().is_none(),
            "no second request while one is pending",
        );
    }

    #[test]
    fn state_advances_to_manifest_requested_on_mark() {
        let mut bs = reach_selected(3);
        let now = Instant::now();
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), now);
        assert_eq!(
            bs.state(),
            BootstrapState::ManifestRequested {
                peer: peer(1),
                height: 52_224,
                manifest_id: mid(0xAA),
            }
        );
    }

    #[test]
    fn on_manifest_received_from_wrong_peer_returns_none() {
        let mut bs = reach_selected(3);
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());

        let result = bs.on_manifest_received(peer(2), vec![0xFF; 100]);
        assert!(
            result.is_none(),
            "reply from a non-pending peer must not surface bytes",
        );
        assert!(matches!(
            bs.state(),
            BootstrapState::ManifestRequested { .. }
        ));
    }

    #[test]
    fn on_manifest_received_with_no_pending_returns_none() {
        let mut bs = reach_selected(3);
        let result = bs.on_manifest_received(peer(1), vec![0xFF; 100]);
        assert!(
            result.is_none(),
            "unsolicited Manifest (no pending request) must not surface bytes",
        );
    }

    #[test]
    fn on_manifest_received_from_pending_peer_returns_request_triple() {
        let mut bs = reach_selected(3);
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
        let payload = vec![0xAA, 0xBB, 0xCC];
        let surfaced = bs.on_manifest_received(peer(1), payload.clone());
        let (height, manifest_id, bytes) = surfaced.expect("matching peer surfaces triple");
        assert_eq!(height, 52_224);
        assert_eq!(manifest_id, mid(0xAA));
        assert_eq!(bytes, payload);
        // State unchanged until accept/reject.
        assert!(matches!(
            bs.state(),
            BootstrapState::ManifestRequested { .. }
        ));
    }

    #[test]
    fn accept_verified_manifest_advances_to_manifest_verified() {
        let mut bs = reach_selected(3);
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
        let bytes = vec![0xAA, 0xBB, 0xCC];
        bs.accept_verified_manifest(bytes.clone());
        assert_eq!(
            bs.state(),
            BootstrapState::ManifestVerified {
                height: 52_224,
                manifest_id: mid(0xAA),
            }
        );
        // Bytes available for chunk-download phase.
        let mut bs2 = SnapshotBootstrap::with_quorum(3);
        bs2.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
        bs2.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
        bs2.on_snapshots_info(peer(3), &[(52_224, mid(0xAA))]);
        bs2.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
        bs2.accept_verified_manifest(bytes.clone());
        let taken = bs2.take_verified_manifest_bytes().expect("bytes available");
        assert_eq!(taken, bytes);
    }

    #[test]
    fn take_verified_manifest_bytes_is_idempotent_returns_none_after_first() {
        let mut bs = reach_selected(3);
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
        bs.accept_verified_manifest(vec![1, 2, 3]);
        assert!(bs.take_verified_manifest_bytes().is_some());
        assert!(
            bs.take_verified_manifest_bytes().is_none(),
            "second take returns None — bytes consumed exactly once",
        );
    }

    #[test]
    fn after_take_bytes_state_stays_manifest_verified() {
        // Critical: even after bytes are handed off to 2h, the
        // sticky `verified` latch keeps state at ManifestVerified
        // so the integration layer never re-fires GetManifest.
        let mut bs = reach_selected(3);
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
        bs.accept_verified_manifest(vec![1, 2, 3]);
        let _ = bs.take_verified_manifest_bytes();
        assert_eq!(
            bs.state(),
            BootstrapState::ManifestVerified {
                height: 52_224,
                manifest_id: mid(0xAA),
            },
            "verified latch must persist post-handoff",
        );
        assert!(
            bs.should_request_manifest().is_none(),
            "no re-request after handoff",
        );
    }

    #[test]
    fn reject_manifest_evicts_voter_and_recomputes_selection() {
        // Three peers vote for A; peer 1 gets the request, sends
        // bad bytes, gets evicted. Two voters remain — still quorum
        // for A if quorum=2; falls back to Querying if quorum=3.
        let mut bs = SnapshotBootstrap::with_quorum(3);
        for p in 1..=3u16 {
            bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
        }
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());

        bs.reject_manifest_and_evict_voter(peer(1));
        assert_eq!(
            bs.state(),
            BootstrapState::Querying,
            "evicting one of three voters drops below quorum=3",
        );
    }

    #[test]
    fn reject_with_remaining_quorum_falls_back_to_selected() {
        // Four peers vote for A; one gets evicted on bad manifest.
        // Quorum=3 is still satisfied with three voters → state
        // returns to Selected so a different voter is asked next.
        let mut bs = SnapshotBootstrap::with_quorum(3);
        for p in 1..=4u16 {
            bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
        }
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());

        bs.reject_manifest_and_evict_voter(peer(1));
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: 52_224,
                manifest_id: mid(0xAA),
            },
            "still 3 voters for A → reselects same manifest, different peer next",
        );
        // Next request goes to a voter that's NOT peer 1.
        let next = bs.should_request_manifest().expect("can request again");
        assert_ne!(next.0, peer(1), "evicted peer must not be re-chosen");
    }

    #[test]
    fn check_request_timeout_evicts_silent_voter() {
        let mut bs = SnapshotBootstrap::with_quorum(3);
        for p in 1..=4u16 {
            bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
        }
        let then = Instant::now();
        bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), then);

        // Within the timeout — no eviction.
        bs.check_request_timeout(then + Duration::from_secs(5));
        assert!(matches!(
            bs.state(),
            BootstrapState::ManifestRequested { .. }
        ));

        // Past the timeout — peer 1 evicted, state falls back.
        bs.check_request_timeout(then + MANIFEST_REQUEST_TIMEOUT + Duration::from_secs(1));
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: 52_224,
                manifest_id: mid(0xAA),
            },
        );
    }

    #[test]
    fn check_request_timeout_with_no_pending_is_noop() {
        let mut bs = reach_selected(3);
        bs.check_request_timeout(Instant::now() + Duration::from_secs(3600));
        // Selected state preserved.
        assert!(matches!(bs.state(), BootstrapState::Selected { .. }));
    }

    // ----- 2g-2 trust verification -----

    fn ad_digest_with_root(root: [u8; 32], height_byte: u8) -> ADDigest {
        let mut bytes = [0u8; 33];
        bytes[..32].copy_from_slice(&root);
        bytes[32] = height_byte;
        ADDigest::from_bytes(bytes)
    }

    #[test]
    fn verify_succeeds_when_prefix_matches() {
        // Same 32-byte root, different tree-height byte — must pass.
        let manifest_id = mid(0x42);
        let state_root = ad_digest_with_root(mid(0x42), 14); // mainnet manifest_depth
        assert!(verify_manifest_against_state_root(&manifest_id, &state_root).is_ok());
    }

    #[test]
    fn verify_succeeds_regardless_of_height_byte_value() {
        // The trailing byte of state_root is the AVL+ tree height,
        // not the manifest's height. It varies across snapshots
        // and does NOT participate in the manifest_id check.
        let manifest_id = mid(0xAB);
        for h in [0u8, 1, 14, 32, 255] {
            let state_root = ad_digest_with_root(mid(0xAB), h);
            assert!(
                verify_manifest_against_state_root(&manifest_id, &state_root).is_ok(),
                "height byte={h} should not affect verification",
            );
        }
    }

    #[test]
    fn verify_fails_when_prefix_differs() {
        let manifest_id = mid(0x42);
        let state_root = ad_digest_with_root(mid(0x99), 14);
        let err = verify_manifest_against_state_root(&manifest_id, &state_root).unwrap_err();
        match err {
            ManifestVerifyError::RootMismatch {
                expected_manifest_id,
                actual_state_root_prefix,
            } => {
                assert_eq!(expected_manifest_id, mid(0x42));
                assert_eq!(actual_state_root_prefix, mid(0x99));
            }
        }
    }

    #[test]
    fn verify_fails_when_one_byte_differs_in_prefix() {
        // Subtle: only byte 31 differs. Comparison must catch it.
        let manifest_id = mid(0x42);
        let mut bytes = [0u8; 33];
        bytes[..32].copy_from_slice(&mid(0x42));
        bytes[31] = 0xFF; // last byte of the 32-prefix corrupted
        bytes[32] = 14;
        let state_root = ADDigest::from_bytes(bytes);
        assert!(verify_manifest_against_state_root(&manifest_id, &state_root).is_err());
    }

    #[test]
    fn verify_zero_manifest_vs_zero_root_succeeds() {
        // Edge case: all-zero (e.g., test fixtures). Behaves like any
        // other equal pair — no special-casing of zero.
        let manifest_id = mid(0x00);
        let state_root = ad_digest_with_root(mid(0x00), 0);
        assert!(verify_manifest_against_state_root(&manifest_id, &state_root).is_ok());
    }

    #[test]
    fn verify_does_not_panic_on_extreme_inputs() {
        // Sanity: 0xFF-filled and 0x00-filled inputs in both
        // positions cover the byte-range edges. No panics, no
        // overflow paths in slice comparison.
        let cases = [
            (mid(0x00), mid(0xFF)),
            (mid(0xFF), mid(0x00)),
            (mid(0xFF), mid(0xFF)),
            (mid(0x00), mid(0x00)),
        ];
        for (m, r) in cases {
            let _ = verify_manifest_against_state_root(&m, &ad_digest_with_root(r, 0));
        }
    }

    // ----- 2h-2 chunk assembly -----

    fn cid(b: u8) -> Digest32 {
        Digest32::from_bytes([b; 32])
    }

    fn ca_three_chunks() -> ChunkAssembly {
        ChunkAssembly::new(vec![cid(0x01), cid(0x02), cid(0x03)])
    }

    #[test]
    fn chunk_assembly_empty_is_immediately_complete() {
        let mut ca = ChunkAssembly::new(Vec::new());
        assert!(ca.is_complete(), "no expected chunks → complete");
        let map = ca.take_chunks().expect("take from empty assembly");
        assert!(map.is_empty());
    }

    #[test]
    fn next_to_request_returns_all_when_idle_and_below_cap() {
        let ca = ca_three_chunks();
        let next = ca.next_to_request();
        assert_eq!(next.len(), 3);
        assert_eq!(next, vec![cid(0x01), cid(0x02), cid(0x03)]);
    }

    #[test]
    fn next_to_request_excludes_inflight_and_received() {
        let mut ca = ca_three_chunks();
        ca.mark_requested(cid(0x01), peer(1), Instant::now());
        // Inflight should be excluded.
        assert_eq!(ca.next_to_request(), vec![cid(0x02), cid(0x03)],);

        let _ = ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA]);
        // Now received; next_to_request still excludes it.
        ca.mark_requested(cid(0x02), peer(2), Instant::now());
        assert_eq!(ca.next_to_request(), vec![cid(0x03)]);
    }

    #[test]
    fn next_to_request_caps_at_max_inflight() {
        // 20 expected, cap is 16 → next batch is 16 max.
        let ids: Vec<Digest32> = (0..20u8).map(cid).collect();
        let ca = ChunkAssembly::new(ids);
        let next = ca.next_to_request();
        assert_eq!(next.len(), MAX_INFLIGHT_CHUNKS);
    }

    #[test]
    fn on_chunk_received_accepts_matching_peer() {
        let mut ca = ca_three_chunks();
        ca.mark_requested(cid(0x01), peer(1), Instant::now());
        let outcome = ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA, 0xBB]);
        assert_eq!(outcome, ChunkReceiveOutcome::Accepted);
        assert_eq!(ca.received_count(), 1);
    }

    #[test]
    fn on_chunk_received_rejects_wrong_peer() {
        let mut ca = ca_three_chunks();
        ca.mark_requested(cid(0x01), peer(1), Instant::now());
        let outcome = ca.on_chunk_received(peer(2), cid(0x01), vec![0xAA]);
        assert_eq!(outcome, ChunkReceiveOutcome::WrongPeer);
        assert_eq!(ca.received_count(), 0, "wrong-peer bytes must not stash");
    }

    #[test]
    fn on_chunk_received_drops_unknown_subtree_id() {
        let mut ca = ca_three_chunks();
        ca.mark_requested(cid(0x01), peer(1), Instant::now());
        let outcome = ca.on_chunk_received(peer(1), cid(0xFF), vec![0xAA]);
        assert_eq!(outcome, ChunkReceiveOutcome::UnknownSubtreeId);
    }

    #[test]
    fn on_chunk_received_drops_duplicate() {
        let mut ca = ca_three_chunks();
        ca.mark_requested(cid(0x01), peer(1), Instant::now());
        ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA]);

        // Re-request from same peer (e.g., resend) then receive again.
        ca.mark_requested(cid(0x01), peer(1), Instant::now());
        let outcome = ca.on_chunk_received(peer(1), cid(0x01), vec![0xBB]);
        assert_eq!(outcome, ChunkReceiveOutcome::Duplicate);
        assert_eq!(ca.received_count(), 1, "duplicate must not overwrite");
    }

    #[test]
    fn check_timeouts_frees_stale_slots() {
        let mut ca = ca_three_chunks();
        let t0 = Instant::now();
        ca.mark_requested(cid(0x01), peer(1), t0);
        ca.mark_requested(cid(0x02), peer(2), t0);

        // Within timeout: no slots freed.
        let freed = ca.check_timeouts(t0 + Duration::from_secs(5));
        assert!(freed.is_empty());

        // After timeout: both slots freed.
        let mut freed = ca.check_timeouts(t0 + CHUNK_REQUEST_TIMEOUT + Duration::from_secs(1));
        freed.sort_by_key(|d| *d.as_bytes());
        assert_eq!(freed, vec![cid(0x01), cid(0x02)]);

        // Freed slots re-enter next_to_request.
        let next = ca.next_to_request();
        assert!(next.contains(&cid(0x01)));
        assert!(next.contains(&cid(0x02)));
    }

    #[test]
    fn drop_peer_frees_their_inflight_slots() {
        let mut ca = ca_three_chunks();
        let t0 = Instant::now();
        ca.mark_requested(cid(0x01), peer(1), t0);
        ca.mark_requested(cid(0x02), peer(2), t0);
        ca.mark_requested(cid(0x03), peer(1), t0);

        let mut dropped = ca.drop_peer(&peer(1));
        dropped.sort_by_key(|d| *d.as_bytes());
        assert_eq!(dropped, vec![cid(0x01), cid(0x03)]);
        // Peer 2's slot untouched.
        assert_eq!(ca.next_to_request(), vec![cid(0x01), cid(0x03)]);
    }

    #[test]
    fn is_complete_only_when_every_chunk_received() {
        let mut ca = ca_three_chunks();
        let t0 = Instant::now();
        assert!(!ca.is_complete());

        ca.mark_requested(cid(0x01), peer(1), t0);
        ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA]);
        assert!(!ca.is_complete());

        ca.mark_requested(cid(0x02), peer(1), t0);
        ca.on_chunk_received(peer(1), cid(0x02), vec![0xBB]);
        assert!(!ca.is_complete());

        ca.mark_requested(cid(0x03), peer(1), t0);
        ca.on_chunk_received(peer(1), cid(0x03), vec![0xCC]);
        assert!(ca.is_complete());
    }

    #[test]
    fn take_chunks_handoff_is_exactly_once() {
        let mut ca = ca_three_chunks();
        let t0 = Instant::now();
        for (i, id) in [cid(0x01), cid(0x02), cid(0x03)].into_iter().enumerate() {
            ca.mark_requested(id, peer(1), t0);
            ca.on_chunk_received(peer(1), id, vec![i as u8]);
        }
        assert!(ca.is_complete());

        let first = ca.take_chunks().expect("first take succeeds");
        assert_eq!(first.len(), 3);

        let second = ca.take_chunks();
        assert!(
            second.is_none(),
            "second take returns None — consumed exactly once",
        );
        // After consume, next_to_request returns empty.
        assert!(ca.next_to_request().is_empty());
    }

    #[test]
    fn progress_counters_reflect_received_state() {
        let mut ca = ca_three_chunks();
        let t0 = Instant::now();
        assert_eq!(ca.total_count(), 3);
        assert_eq!(ca.received_count(), 0);

        ca.mark_requested(cid(0x01), peer(1), t0);
        ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA]);
        assert_eq!(ca.received_count(), 1);
    }
}

//! Manifest-discovery reducer for the Mode 2 UTXO snapshot
//! bootstrap: per-peer `SnapshotsInfo` vote tracking, quorum
//! selection, manifest request/timeout ownership, and trust
//! verification against the header chain's `state_root`. See the
//! parent module doc for the full protocol context.
//!
//! # Trust argument for a Mode 2 install
//!
//! Installing a UTXO snapshot means adopting, wholesale, a state the node
//! never computed. What makes that safe is a chain of two links:
//!
//! 1. **Manifest => header.** [`verify_manifest_against_state_root`] binds
//!    the manifest to `header.state_root` at `snapshot_height`, so the
//!    installed tree is the one the chain committed to at that height.
//! 2. **Header => operator anchor.** The header chain itself is only
//!    PoW-validated. PoW is a cost, not an identity: a sufficiently funded
//!    peer set can present a heavier-looking-enough header chain to a node
//!    that has never seen the real one. Scala closes this with the
//!    operator-supplied `ergo.node.checkpoint` — and closes it *in header
//!    validation* (`HeadersProcessor.checkpointCondition`,
//!    `HeadersProcessor.scala:437-443`), which is the only layer that fires
//!    on a Mode 2 bootstrap: no full block below `snapshot_height` is ever
//!    applied, so a full-block-level checkpoint never runs at all.
//!
//! [`snapshot_install_anchor_check`] is link 2 for the install decision: when
//! a checkpoint is configured and the snapshot sits AT OR ABOVE it, the node
//! refuses to install unless its own header chain materialises the checkpoint
//! height with the pinned id — i.e. unless the anchor was actually *passed*
//! and verified on the way up. A snapshot strictly below the checkpoint
//! height is not covered by the anchor and installs unconditionally; the
//! anchor still fires later, on the headers that reach it.
//!
//! A missing row (a NiPoPoW-sparse header chain that skips the checkpoint
//! height) is a refusal, not a pass: an anchor that was never observed proves
//! nothing about the chain that produced the manifest.

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
    HeightMismatch {
        manifest_height: u8,
        state_root_height: u8,
    },
}

/// Trust-check a manifest root against a header's `state_root`.
///
/// Contract: the header MUST have been fetched from the canonical
/// best-header chain at the snapshot height (the caller is
/// responsible for the chain lookup; this function does not see
/// the chain index). On a reorg between selection and verification
/// the caller must re-fetch and re-verify.
///
/// The 32-byte manifest ID is compared with the first 32 bytes of
/// `state_root`, and the manifest-declared AVL+ height is compared
/// with the trailing height byte of the 33-byte `ADDigest`.
pub fn verify_manifest_against_state_root(
    manifest_id: &[u8; 32],
    manifest_height: u8,
    state_root: &ADDigest,
) -> Result<(), ManifestVerifyError> {
    let state_root_height = state_root.tree_height_byte();
    if manifest_height != state_root_height {
        return Err(ManifestVerifyError::HeightMismatch {
            manifest_height,
            state_root_height,
        });
    }
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

/// Why a Mode 2 install was refused by the header-checkpoint anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotAnchorError {
    /// The node's own header chain has no header at the checkpoint height,
    /// so the anchor was never observed. Happens on a NiPoPoW-sparse header
    /// chain whose prefix skips that height, or when the header chain has
    /// not reached it yet.
    AnchorNotObserved { checkpoint_height: u32 },
    /// The node's header chain HAS a header at the checkpoint height and it
    /// is not the pinned one. The chain the manifest came from is not the
    /// operator's chain; nothing on it may be installed.
    AnchorMismatch {
        checkpoint_height: u32,
        expected: [u8; 32],
        got: [u8; 32],
    },
}

impl std::fmt::Display for SnapshotAnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotAnchorError::AnchorNotObserved { checkpoint_height } => write!(
                f,
                "header checkpoint at height {checkpoint_height} was never observed on this \
                 node's header chain"
            ),
            SnapshotAnchorError::AnchorMismatch {
                checkpoint_height,
                expected,
                got,
            } => write!(
                f,
                "header checkpoint mismatch at height {checkpoint_height}: expected {}, got {}",
                hex::encode(expected),
                hex::encode(got)
            ),
        }
    }
}

/// Decide whether a UTXO snapshot at `snapshot_height` may be installed given
/// the operator's header-level checkpoint. See the module doc's trust
/// argument.
///
/// `header_at_checkpoint` is the id the node's own best-header chain holds at
/// `checkpoint.height`, or `None` when that height is not materialised
/// (sparse gap, or above the header tip). Pure so the decision is testable
/// without a store; the caller does the chain lookup.
pub fn snapshot_install_anchor_check(
    snapshot_height: u32,
    checkpoint: Option<crate::header_proc::HeaderCheckpoint>,
    header_at_checkpoint: Option<[u8; 32]>,
) -> Result<(), SnapshotAnchorError> {
    let Some(ckpt) = checkpoint else {
        return Ok(());
    };
    if snapshot_height < ckpt.height {
        // Below the anchor: the anchor makes no claim about this state, and
        // it is still enforced on the headers that reach it later.
        return Ok(());
    }
    match header_at_checkpoint {
        None => Err(SnapshotAnchorError::AnchorNotObserved {
            checkpoint_height: ckpt.height,
        }),
        Some(id) if id == ckpt.block_id => Ok(()),
        Some(id) => Err(SnapshotAnchorError::AnchorMismatch {
            checkpoint_height: ckpt.height,
            expected: ckpt.block_id,
            got: id,
        }),
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
    /// Local failure requires operator intervention; no further downloads.
    Halted,
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
    rejected: HashSet<PeerVote>,
    /// Supplier exclusions survive reconnects and re-advertisements for this epoch.
    excluded_suppliers: HashMap<PeerVote, HashSet<PeerId>>,
    manifest_failures: HashMap<PeerVote, HashSet<PeerId>>,
    /// An authenticated epoch needs another supplier, not another quorum.
    retry_target: Option<PeerVote>,
    halted: bool,
    /// Cached result of the last [`Self::recompute_selection`] call.
    /// `Some` is the current quorum choice or the pinned authenticated retry
    /// target; the latter remains selected even with no remaining voters.
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
    /// `Some` after byte handoff until install, recovery, or halt.
    /// Supplier recovery clears this latch to request replacement metadata
    /// for the same authenticated epoch. The inner `bytes` is consumed by 2h.
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
    peer: PeerId,
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
            rejected: HashSet::new(),
            excluded_suppliers: HashMap::new(),
            manifest_failures: HashMap::new(),
            retry_target: None,
            halted: false,
            selected: None,
            discovery_queried: HashSet::new(),
            pending_request: None,
            verified: None,
        }
    }

    /// Record a peer's `SnapshotsInfo` response. The peer's vote is
    /// the highest eligible entry in `manifests`, preferring an authenticated
    /// retry target when present. An empty list
    /// removes any prior vote from this peer (they had something,
    /// then evicted it, then re-advertised). Recomputes selection.
    pub fn on_snapshots_info(&mut self, peer: PeerId, manifests: &[(i32, [u8; 32])]) {
        match manifests
            .iter()
            .filter(|vote| !self.rejected.contains(vote))
            .filter(|vote| {
                !self
                    .excluded_suppliers
                    .get(vote)
                    .is_some_and(|peers| peers.contains(&peer))
            })
            .max_by_key(|vote| (Some(**vote) == self.retry_target, vote.0))
        {
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
    ///
    /// If the departing peer owns the outstanding `GetManifest`, the
    /// request is dropped immediately (evict + recompute) rather than
    /// left to expire after [`MANIFEST_REQUEST_TIMEOUT`] — a dead peer
    /// will never reply, so waiting the full window only stalls the
    /// rotation to another voter.
    pub fn on_peer_disconnect(&mut self, peer: &PeerId) {
        self.discovery_queried.remove(peer);
        if self.pending_request.map(|p| p.peer) == Some(*peer) {
            // Owner of the pending request left: clear it, evict their
            // vote, and recompute so the next tick rotates to a new voter.
            self.reject_manifest_and_evict_voter(*peer);
        } else if self.votes.remove(peer).is_some() {
            self.recompute_selection();
            self.reopen_discovery_if_below_quorum();
        }
    }

    /// True when the outbound fan-out should send `GetSnapshotsInfo`
    /// to this peer. Returns `false` once we've already queried them
    /// in this discovery epoch, or once discovery has produced a
    /// selection — `Selected` **or beyond** (`ManifestRequested` /
    /// `ManifestVerified`). Past `Selected` the manifest download phase
    /// has taken over, so querying even a newly-seen peer would only
    /// re-open discovery for a decision already made. An authenticated retry
    /// with no remaining voters queries fresh suppliers while retaining its target.
    pub fn should_query(&self, peer: &PeerId) -> bool {
        if !self.halted
            && self.retry_target.is_some()
            && self.verified.is_none()
            && self.pending_request.is_none()
            && self.voter_for_selected_manifest().is_none()
        {
            return !self.supplier_excluded(peer) && !self.discovery_queried.contains(peer);
        }
        match self.state() {
            BootstrapState::Halted
            | BootstrapState::Selected { .. }
            | BootstrapState::ManifestRequested { .. }
            | BootstrapState::ManifestVerified { .. } => return false,
            BootstrapState::Idle | BootstrapState::Querying => {}
        }
        !self.discovery_queried.contains(peer)
    }

    /// Record that we've sent `GetSnapshotsInfo` to this peer.
    /// Pair with [`Self::should_query`] in the fan-out loop.
    pub fn mark_queried(&mut self, peer: PeerId) {
        self.discovery_queried.insert(peer);
    }

    pub fn reopen_discovery_if_below_quorum(&mut self) {
        if (self.selected.is_none()
            || (self.retry_target.is_some() && self.voter_for_selected_manifest().is_none()))
            && self.verified.is_none()
            && self.pending_request.is_none()
        {
            self.discovery_queried.clear();
        }
    }

    /// Current selection state. Computes the public state from
    /// internal fields: halted > verified > pending > selected > votes.
    pub fn state(&self) -> BootstrapState {
        if self.halted {
            return BootstrapState::Halted;
        }
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

    /// The manifest the reducer is committed to, latched against
    /// recomputation. Once a request is pending or a manifest is
    /// verified, that `(height, manifest_id)` is the target for the
    /// rest of the session — a later vote change must not silently
    /// repoint the chunk-download fan-out at a different manifest than
    /// the one whose bytes we verified. Precedence mirrors [`Self::state`]:
    /// verified > pending > selected.
    fn latched_target(&self) -> Option<PeerVote> {
        if let Some(v) = &self.verified {
            return Some((v.height, v.manifest_id));
        }
        if let Some(p) = &self.pending_request {
            return Some((p.height, p.manifest_id));
        }
        self.selected
    }

    /// All peers whose vote matches the manifest we're committed to.
    /// The chunk-download fan-out (part 2h-3) iterates this list to
    /// spread chunk requests across the quorum rather than hammer the
    /// single manifest responder. Returns an empty `Vec` before a
    /// selection exists.
    ///
    /// Targets the [`Self::latched_target`] (verified > pending >
    /// selected), not the live `selected` tally, so a vote change
    /// after verification cannot repoint chunk requests away from the
    /// verified manifest. Includes the peer that already served the
    /// manifest — they can serve chunks too. Bad suppliers are evicted and
    /// cannot re-advertise this epoch during the session.
    pub fn voters_for_selected_manifest(&self) -> Vec<PeerId> {
        let Some(target) = self.latched_target() else {
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
        if self.halted || self.pending_request.is_some() || self.verified.is_some() {
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
    ///   now recompute the body's root and compare it to the returned REQUESTED
    ///   id, then check root + AVL height against the canonical header at the
    ///   returned snapshot height, and call either
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
        if self.halted {
            return None;
        }
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
            peer: pending.peer,
            height: pending.height,
            manifest_id: pending.manifest_id,
            bytes: Some(bytes),
        });
    }

    /// Evict a failed or unavailable request owner and clear the request/latch.
    /// Other voters may still serve the authentic requested manifest, so this
    /// does not reject its epoch. Authenticated manifest metadata failures use
    /// [`Self::retry_verified_manifest`] to preserve the target with a retry cap.
    pub fn reject_manifest_and_evict_voter(&mut self, peer: PeerId) {
        self.pending_request = None;
        self.verified = None;
        self.votes.remove(&peer);
        self.recompute_selection();
        self.reopen_discovery_if_below_quorum();
    }

    /// Drop the verified latch while retaining votes and epoch eligibility.
    /// Recompute selection and reopen discovery if the quorum has disappeared.
    pub fn drop_verified_manifest(&mut self) {
        self.verified = None;
        self.retry_target = None;
        self.recompute_selection();
        self.reopen_discovery_if_below_quorum();
    }

    /// The server remains attributable after byte handoff and voter churn.
    pub fn verified_manifest_peer(&self) -> Option<PeerId> {
        self.verified.as_ref().map(|v| v.peer)
    }

    /// Whether the current target is an authenticated epoch awaiting new metadata.
    /// A changed canonical root during this retry is a reorg, not supplier misconduct.
    pub fn retrying_verified_manifest(&self) -> bool {
        self.retry_target.is_some()
    }

    /// Exclude a bad supplier from this epoch without clearing authenticated data.
    /// Both voter scheduling and the archive-peer fallback must honor this exclusion.
    pub fn evict_snapshot_supplier(&mut self, peer: PeerId) {
        if let Some(target) = self.latched_target() {
            self.excluded_suppliers
                .entry(target)
                .or_default()
                .insert(peer);
        }
        self.votes.remove(&peer);
        self.recompute_selection();
    }

    /// Whether this peer supplied bad data for the currently latched epoch.
    pub fn supplier_excluded(&self, peer: &PeerId) -> bool {
        self.latched_target()
            .and_then(|target| self.excluded_suppliers.get(&target))
            .is_some_and(|peers| peers.contains(peer))
    }

    /// Discard bad manifest metadata and retry the same authenticated epoch.
    /// Returns the recorded server and distinct-server failure count. Three
    /// failures reject the epoch to bound retries even if local validation is wrong.
    /// Chunk failures do not contribute to this count. No verified latch is a no-op.
    pub fn retry_verified_manifest(&mut self) -> Option<(PeerId, usize)> {
        let verified = self.verified.as_ref()?;
        let target = (verified.height, verified.manifest_id);
        let peer = verified.peer;
        let failures = self.manifest_failures.entry(target).or_default();
        failures.insert(peer);
        let count = failures.len();
        self.evict_snapshot_supplier(peer);
        if count >= 3 {
            self.reject_current_manifest(None);
        } else {
            self.retry_target = Some(target);
            self.verified = None;
            self.pending_request = None;
            self.discovery_queried.clear();
            self.recompute_selection();
        }
        Some((peer, count))
    }

    /// Reject an unusable epoch (or one whose supplier retry budget is exhausted)
    /// for the session so rediscovery cannot restart its download.
    /// Only a known supplier is evicted; other voters retain their votes.
    pub fn reject_current_manifest(&mut self, culprit: Option<PeerId>) {
        if let Some(target) = self.latched_target() {
            self.rejected.insert(target);
        }
        self.retry_target = None;
        self.pending_request = None;
        self.verified = None;
        if let Some(peer) = culprit {
            self.votes.remove(&peer);
        }
        self.recompute_selection();
        self.reopen_discovery_if_below_quorum();
    }

    /// Stop downloads after a local failure without rotating or blaming peers.
    pub fn halt(&mut self) {
        self.halted = true;
        self.pending_request = None;
        self.verified = None;
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

    /// Preserve an authenticated retry target, otherwise pick the highest-height
    /// entry with `>= self.quorum` agreement. Called whenever votes change.
    fn recompute_selection(&mut self) {
        if let Some(target) = self.retry_target {
            self.selected = Some(target);
            return;
        }
        let mut tally: HashMap<PeerVote, usize> = HashMap::new();
        for vote in self.votes.values() {
            *tally.entry(*vote).or_insert(0) += 1;
        }
        self.selected = tally
            .into_iter()
            .filter(|(vote, count)| *count >= self.quorum && !self.rejected.contains(vote))
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

    // ----- helpers -----

    fn peer(port: u16) -> PeerId {
        ([10, 0, 0, 1], port).into()
    }
    fn mid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    fn reach_selected(quorum: usize) -> SnapshotBootstrap {
        let mut bs = SnapshotBootstrap::with_quorum(quorum);
        for p in 1..=3 {
            bs.on_snapshots_info(peer(p), &[(100, mid(0xAA))]);
        }
        bs
    }

    // ----- error paths -----

    #[test]
    fn snapshot_supplier_eviction_preserves_verified_epoch() {
        let mut bs = reach_selected(3);
        bs.mark_manifest_requested(peer(1), 100, mid(0xAA), Instant::now());
        bs.accept_verified_manifest(vec![1]);
        bs.evict_snapshot_supplier(peer(2));
        assert!(matches!(
            bs.state(),
            BootstrapState::ManifestVerified { .. }
        ));
        assert!(!bs.rejected.contains(&(100, mid(0xAA))));
        assert_eq!(bs.take_verified_manifest_bytes(), Some(vec![1]));
        bs.on_peer_disconnect(&peer(2));
        bs.on_snapshots_info(peer(2), &[(100, mid(0xAA))]);
        assert!(!bs.votes.contains_key(&peer(2)));
        assert!(bs.supplier_excluded(&peer(2)));
        assert!(!bs.should_query(&peer(3)));
    }

    #[test]
    fn manifest_retry_voter_churn_preserves_authenticated_target() {
        let mut bs = reach_selected(3);
        bs.mark_manifest_requested(peer(1), 100, mid(0xAA), Instant::now());
        bs.accept_verified_manifest(vec![]);
        for p in 4..=6 {
            bs.on_snapshots_info(peer(p), &[(200, mid(0xBB))]);
        }
        assert_eq!(bs.retry_verified_manifest(), Some((peer(1), 1)));
        assert!(!bs.rejected.contains(&(100, mid(0xAA))));
        let (server, height, id) = bs.should_request_manifest().unwrap();
        assert_ne!(server, peer(1));
        assert_eq!((height, id), (100, mid(0xAA)));
        bs.mark_manifest_requested(server, height, id, Instant::now());
        bs.check_request_timeout(Instant::now() + MANIFEST_REQUEST_TIMEOUT);
        let (server, height, id) = bs.should_request_manifest().unwrap();
        assert_eq!((height, id), (100, mid(0xAA)));
        bs.on_peer_disconnect(&server);
        assert!(bs.should_request_manifest().is_none());
        assert!(bs.should_query(&peer(7)));
        assert!(!bs.should_query(&peer(1)));
        bs.on_snapshots_info(peer(7), &[(100, mid(0xAA)), (200, mid(0xBB))]);
        assert_eq!(
            bs.should_request_manifest(),
            Some((peer(7), 100, mid(0xAA)))
        );
    }

    #[test]
    fn manifest_retry_distinct_servers_bounds_only_current_epoch() {
        let mut bs = reach_selected(3);
        for p in [1, 1, 2, 3] {
            // Repeating an attribution must not consume another server's budget.
            bs.mark_manifest_requested(peer(p), 100, mid(0xAA), Instant::now());
            bs.accept_verified_manifest(vec![]);
            assert_eq!(
                bs.retry_verified_manifest(),
                Some((peer(p), usize::from(p)))
            );
            assert_eq!(bs.rejected.contains(&(100, mid(0xAA))), p == 3);
        }
        for p in 1..=3 {
            bs.on_snapshots_info(peer(p), &[(100, mid(0xAA)), (99, mid(0xBB))]);
        }
        let (server, height, id) = bs.should_request_manifest().unwrap();
        assert_eq!((height, id), (99, mid(0xBB)));
        bs.mark_manifest_requested(server, height, id, Instant::now());
        bs.accept_verified_manifest(vec![]);
        assert_eq!(bs.retry_verified_manifest(), Some((server, 1)));
        assert!(!bs.rejected.contains(&(height, id)));
    }

    #[test]
    fn verified_manifest_disconnect_preserves_discovery_epoch() {
        let mut bs = reach_selected(3);
        for p in 1..=3 {
            bs.mark_queried(peer(p));
        }
        let (server, height, id) = bs.should_request_manifest().unwrap();
        bs.mark_manifest_requested(server, height, id, Instant::now());
        bs.accept_verified_manifest(vec![]);
        bs.take_verified_manifest_bytes();
        bs.on_peer_disconnect(&server);
        assert_eq!(bs.verified_manifest_peer(), Some(server));
        assert!(matches!(
            bs.state(),
            BootstrapState::ManifestVerified { .. }
        ));
        for p in 1..=3 {
            if peer(p) != server {
                assert!(bs.discovery_queried.contains(&peer(p)));
                assert!(!bs.should_query(&peer(p)));
            }
        }
    }

    #[test]
    fn rejected_manifest_rediscovery_selects_only_new_epoch() {
        let mut bs = reach_selected(3);
        let (server, height, id) = bs.should_request_manifest().unwrap();
        bs.mark_manifest_requested(server, height, id, Instant::now());
        bs.accept_verified_manifest(vec![]);
        bs.reject_current_manifest(Some(server));
        for p in 1..=20 {
            bs.on_snapshots_info(peer(p), &[(height, id)]);
        }
        assert!(bs.should_request_manifest().is_none());
        for p in 1..=3 {
            bs.on_snapshots_info(peer(p), &[(height, id), (height - 1, mid(0xBB))]);
        }
        assert_eq!(
            bs.state(),
            BootstrapState::Selected {
                height: height - 1,
                manifest_id: mid(0xBB)
            }
        );
    }

    #[test]
    fn rejected_manifest_many_voters_evicts_only_recorded_server() {
        let mut bs = SnapshotBootstrap::new();
        for p in 1..=32 {
            bs.on_snapshots_info(peer(p), &[(100, mid(0xAA))]);
        }
        // Pick a server other than the HashMap's first voter, deterministically.
        let server = bs.voters_for_selected_manifest()[1];
        bs.mark_manifest_requested(server, 100, mid(0xAA), Instant::now());
        bs.accept_verified_manifest(vec![]);
        bs.take_verified_manifest_bytes();
        assert_eq!(bs.verified_manifest_peer(), Some(server));
        bs.reject_current_manifest(bs.verified_manifest_peer());
        assert!(!bs.votes.contains_key(&server));
        assert_eq!(bs.votes.len(), 31);
        for p in 1..=32 {
            if peer(p) != server {
                assert!(bs.votes.contains_key(&peer(p)));
            }
        }
    }

    #[test]
    fn halted_bootstrap_new_votes_do_not_restart_downloads() {
        let mut bs = reach_selected(3);
        let before = bs.votes.clone();
        bs.halt();
        for (peer, vote) in &before {
            bs.on_snapshots_info(*peer, &[*vote]);
        }
        assert_eq!(bs.state(), BootstrapState::Halted);
        assert_eq!(bs.votes, before);
        assert!(bs.should_request_manifest().is_none());
        assert!(!bs.should_query(&peer(99)));
    }
}

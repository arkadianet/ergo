//! Sync coordinator: the decision engine that drives header and block sync.
//!
//! Takes incoming events (messages received, timeouts, state changes) and
//! produces outgoing actions (send messages, persist data, validate headers).
//! Pure logic — no I/O or async beyond `tracing` diagnostics; every other
//! effect is an emitted `Action`. The caller (network loop) executes actions.
//!
//! Integrates: DeliveryTracker, AssemblyTracker, SyncState, PeerChainStatus.
//!
//! **Limitation**: fork choice currently uses height-based comparison for V1
//! and treats V2 peers as Older when they send headers. Cumulative-difficulty
//! comparison is queued for a follow-up pass; ChainView will need a method
//! exposing cumulative score when that work lands.

use ergo_p2p::assembly::AssemblyTracker;
use ergo_p2p::delivery::DeliveryTracker;
use ergo_p2p::peer::{PeerId, Penalty};
use ergo_p2p::sync::SyncState;

mod chain_view;
mod events;
mod scheduling;
mod section_verify;
mod transactions;

pub use events::build_sync_info_payload;
#[cfg(test)]
pub(crate) use events::find_continuation_header;
pub use section_verify::verify_section_modifier_id;

// ---- Actions emitted by the coordinator ----

/// An action for the network/state layer to execute.
///
/// Diagnostics are emitted directly via `tracing` macros at the call site,
/// deliberately *not* as a routed `Log` variant: a routed variant would
/// allocate a `String` eagerly even for suppressed (filtered-out) lines and
/// add a three-layer match just to reach the subscriber. Routed effects that
/// DO carry weight (ordering, channel-full recovery, executor fixed-point
/// drains) stay in the enum.
#[derive(Debug)]
pub enum Action {
    /// Send a message to a specific peer.
    SendToPeer {
        peer: PeerId,
        code: u8,
        payload: Vec<u8>,
    },
    /// Penalize a peer.
    Penalize { peer: PeerId, penalty: Penalty },
    /// Record a requested-modifier delivery outcome for download-quality
    /// tracking: `succeeded: false` on a delivery timeout, `true` on an
    /// accepted delivery. Consumed by the peer manager to deprioritize peers
    /// that repeatedly fail to deliver (see `peer::DELIVERY_DEGRADE_STREAK`).
    /// Distinct from `Penalize { NonDelivery }`, whose decaying score cannot
    /// catch a peer that only ever times out.
    NoteDeliveryOutcome { peer: PeerId, succeeded: bool },
    /// A header has been received and should be validated + persisted.
    /// The caller runs PoW check, chain linkage, difficulty adjustment.
    ValidateHeader { peer: PeerId, header_bytes: Vec<u8> },
    /// A block section has been received. Persist it.
    ///
    /// `section_type` is the wire `ModifierTypeId` byte (102 / 104 / 108)
    /// — preserved so the persist site can populate
    /// `MODIFIER_TYPE_INDEX` for `/blocks/modifier/{id}` dispatch.
    PersistSection {
        modifier_id: [u8; 32],
        section_bytes: Vec<u8>,
        section_type: u8,
    },
    /// A full block is ready: all required sections arrived. Assemble + validate + apply.
    AssembleBlock { header_id: [u8; 32] },
}

// ---- Chain state interface (trait for testability) ----

/// Minimal interface for querying chain state. Implemented by StateStore
/// in production, mockable in tests.
pub trait ChainView {
    fn best_header_id(&self) -> [u8; 32];
    fn best_header_height(&self) -> u32;
    fn best_full_block_height(&self) -> u32;
    /// Check if a header ID is on our best chain.
    fn is_on_best_chain(&self, header_id: &[u8; 32]) -> bool;
    /// Check if a header is known (validated, in our store).
    fn has_header(&self, header_id: &[u8; 32]) -> bool;
    /// Check if a block section is known (persisted in block_sections table).
    fn has_block_section(&self, modifier_id: &[u8; 32]) -> bool;
    /// Mode 3 — parent-header height of a section id, when the
    /// SECTION_HEIGHT_INDEX row exists. Returns `None` for
    /// unindexed sections. Used by the request-side prune gate
    /// in `on_inv` to skip sub-sentinel section advertisements.
    /// Default `None` keeps archive / Mode 6 / non-Mode-3
    /// ChainView implementations free of the lookup.
    fn get_section_height(&self, _modifier_id: &[u8; 32]) -> Option<u32> {
        None
    }
    /// Check if a header is marked invalid.
    fn is_invalid(&self, header_id: &[u8; 32]) -> bool;
    /// Recent header IDs on the best chain (newest first, for SyncInfo V1).
    fn recent_header_ids(&self, count: usize) -> Vec<[u8; 32]>;
    /// Recent serialized headers on the best chain (newest first, for SyncInfo V2).
    fn recent_header_bytes(&self, count: usize) -> Vec<Vec<u8>>;
    /// Header ID on the best chain at the given height, with sparse-
    /// mode awareness. Returns:
    /// * [`ergo_state::chain::HeightLookup::Dense`] when a row exists
    ///   in `HEADER_CHAIN_INDEX`.
    /// * [`ergo_state::chain::HeightLookup::SparseGap`] when the
    ///   height is canonical-but-not-locally-indexed
    ///   (`HeaderAvailability::PoPowSparse` mode, prefix region).
    ///   Callers must NOT treat this as fraud, "we've reached our
    ///   tip", or "not on best chain"; the height is real, we just
    ///   don't have a row for it. For continuation-extension callers
    ///   the safest behavior is `break` (we can't serve a header we
    ///   don't have locally — and sparse-mode nodes shouldn't be
    ///   header sources anyway).
    /// * [`ergo_state::chain::HeightLookup::AboveTip`] when `height >
    ///   best_header_height`. Continuation callers should break.
    fn header_id_at_height(&self, height: u32) -> ergo_state::chain::HeightLookup;
    /// Persisted height for a header ID we have, if present. Used to
    /// compute the height of a common ancestor when constructing a
    /// continuation extension.
    fn header_height_for(&self, header_id: &[u8; 32]) -> Option<u32>;
}

// ---- Coordinator ----

/// Per-tick observation counters for the request/response pipeline.
/// Drained by the heartbeat (`take_net_stats`) — same pattern as
/// AnchorCounters / SchedulerCounters. Used to break down where IDs
/// from inbound Inv messages get filtered (already-have / already-
/// inflight / already-received / per-peer cap) vs admitted to
/// RequestModifier flow.
#[derive(Debug, Default, Clone)]
pub struct NetStats {
    pub inv_msgs_received: u64,
    pub inv_ids_total: u64,
    pub inv_ids_already_have: u64,
    pub inv_ids_already_inflight: u64,
    pub inv_ids_already_received: u64,
    pub inv_ids_admitted: u64,
    pub inv_ids_capped_per_peer: u64,
    /// Distinct peers we received any header-payload from in this
    /// tick. If only a handful of 60 peers ever reply, the install
    /// pipeline starves between bursts even though we dispatch
    /// SyncInfo to every peer per Lever-1 cadence.
    pub peers_with_response: std::collections::HashSet<PeerId>,
    /// Distinct peers we sent any SyncInfo to in this tick. Compare
    /// with `peers_with_response` to detect silent peers.
    pub peers_dispatched_to: std::collections::HashSet<PeerId>,
    /// Per-peer Inv breakdown (sampled). Maps peer to
    /// (total_ids_offered, ids_admitted_to_request_flow). The ratio
    /// admitted/total per peer reveals whether different peers are
    /// shipping disjoint slices (high admit ratio per peer) or
    /// overlapping the same content (low admit ratio per peer
    /// because their slice was already installed by other peers).
    pub per_peer_inv: std::collections::HashMap<PeerId, (u64, u64)>,
    /// Per-peer count of non-tx Modifier messages received (any of
    /// Header/BlockTransactions/Extension). Lets the heartbeat surface
    /// peer skew during block sync — `peers_with_response.len()` only
    /// shows the distinct set, not the contribution distribution. If
    /// e.g. 5 peers ship 80% of modifiers, dispatch policy or peer
    /// rotation likely needs adjustment.
    pub per_peer_modifier: std::collections::HashMap<PeerId, u64>,
}

impl NetStats {
    pub fn is_active(&self) -> bool {
        self.inv_msgs_received > 0 || self.inv_ids_total > 0
    }
}

/// Snapshot of a peer's last-known sync state, recorded each time
/// the coordinator processes a SyncInfo message from that peer.
/// Drives `/peers/syncInfo` projection on the snapshot publisher.
#[derive(Debug, Clone)]
pub struct PeerSyncSnapshot {
    /// Chain-comparison classification from the latest SyncInfo.
    /// `Equal` / `Younger` / `Older` / `Fork` / `Unknown`.
    pub status: ergo_p2p::sync::PeerChainStatus,
    /// Peer's reported best-block height. V1 SyncInfo carries this
    /// directly; V2 SyncInfo (post-v4) sends raw headers instead and
    /// we infer the height by looking up the newest peer-header that
    /// sits on our best chain (None when no overlap or pre-handshake).
    pub peer_height: Option<u32>,
    /// Last update timestamp (monotonic). Lets observers age out
    /// stale entries after the peer disconnects.
    pub observed_at: std::time::Instant,
    /// Our best header id at the moment this status was computed. `Equal`
    /// means "peer tip == THIS id"; if our tip later advances/reorgs, the
    /// snapshot no longer confirms the current tip. The caught-up fallback
    /// uses this to discount stale `Equal` observations.
    pub observed_best_header_id: [u8; 32],
}

pub struct SyncCoordinator {
    delivery: DeliveryTracker,
    assembly: AssemblyTracker,
    sync_state: SyncState,
    /// Monotonic per-call counter for `request_missing_sections_bucketed`.
    /// Fed into `partition::distribute` as the rotation cursor so the
    /// first peer in the sorted list is not permanently the first
    /// assignee. Wraps at u64::MAX — billions of years at any realistic
    /// tick rate.
    download_round: u64,
    /// Pipeline-shape diagnostics (drained per heartbeat).
    net_stats: NetStats,
    /// Per-peer sync state, last-observed in `on_sync_info`. Bounded
    /// by connected-peer count; entries linger after disconnect until
    /// `on_peer_disconnected` evicts them. Drives `/peers/syncInfo`.
    peer_sync: std::collections::HashMap<PeerId, PeerSyncSnapshot>,
    /// Mode 6 (headers-only) flag — when true, `on_header_validated`
    /// returns early after updating sync state; no pending-block
    /// registration, no assembly tracking, no section RequestModifier
    /// sends. Mirrors Scala `ToDownloadProcessor` when
    /// `!nodeSettings.verifyTransactions`. Default `false` for full
    /// validation (Modes 1, 2, 3, 5).
    headers_only: bool,
    /// Mode 2 transient flag: while a fresh node is bootstrapping
    /// from a UTXO snapshot, the section-download pipeline must
    /// also be suppressed — otherwise the node tries to replay
    /// blocks from height 1 in parallel with the snapshot install,
    /// defeating the bootstrap. Same gates as `headers_only`, but
    /// flips off after `state_install` completes so normal block
    /// sync from `snapshot_height + 1` can proceed.
    bootstrap_in_progress: bool,
    /// First-deliverer observations accumulated since the last drain:
    /// `(header_id, delivering peer)` for each header `on_header_validated`
    /// accepted. Drained by the action loop via [`take_first_deliverers`]
    /// into the node's bounded first-deliverer ring. Pure observability —
    /// never read by sync. Bounded by the per-tick validated-header batch
    /// (drained every action-loop tick), same drain pattern as
    /// [`take_net_stats`].
    first_deliverers: Vec<([u8; 32], PeerId)>,
    /// Digest-verifier (Mode 5) flag: when true, block-section scheduling also
    /// requests/tracks the ADProofs section (type 104) — the UTXO-set
    /// transformation proofs a digest node needs to apply a block. Scala
    /// `ToDownloadProcessor.requiredModifiersForHeader` downloads `h.sectionIds`
    /// (all three) when `stateType.requireProofs`, vs `h.sectionIdsWithNoProof`
    /// otherwise. Default `false` (UTXO/full node) — set by the node at boot for
    /// the digest-verifier backend. Independent of `headers_only`.
    requires_proofs: bool,
}

impl SyncCoordinator {
    /// Construct with the default download window.
    pub fn new(best_full_block_height: u32) -> Self {
        Self::new_with_window(best_full_block_height, ergo_p2p::sync::DOWNLOAD_WINDOW)
    }

    /// Construct with an explicit download window (from TOML config).
    pub fn new_with_window(best_full_block_height: u32, download_window: usize) -> Self {
        Self::new_with_window_and_mode(best_full_block_height, download_window, false)
    }

    /// Construct with explicit download window AND headers-only mode.
    /// Mode 6 callers pass `headers_only = true` to disable block-section
    /// requests; everything else stays the same as
    /// [`Self::new_with_window`]. Uses the mainnet-default
    /// header-freshness threshold; testnet-aware production code should
    /// call [`Self::new_with_timing`] instead.
    pub fn new_with_window_and_mode(
        best_full_block_height: u32,
        download_window: usize,
        headers_only: bool,
    ) -> Self {
        Self {
            delivery: DeliveryTracker::new(),
            assembly: AssemblyTracker::new(),
            sync_state: SyncState::new_with_window(best_full_block_height, download_window),
            download_round: 0,
            net_stats: NetStats::default(),
            headers_only,
            bootstrap_in_progress: false,
            peer_sync: std::collections::HashMap::new(),
            first_deliverers: Vec::new(),
            requires_proofs: false,
        }
    }

    /// Construct with explicit download window, headers-only mode, AND
    /// a network-derived header-freshness threshold (typically
    /// `chain_spec.block_timing.header_freshness_threshold_ms()`).
    /// Mainnet callers can keep using [`Self::new_with_window_and_mode`];
    /// testnet startup must use this constructor so the synced-tip
    /// detector applies testnet's 45 s × 800 = 36_000_000 ms tolerance
    /// instead of mainnet's 12_000_000 ms.
    pub fn new_with_timing(
        best_full_block_height: u32,
        download_window: usize,
        headers_only: bool,
        header_freshness_threshold_ms: u64,
    ) -> Self {
        Self {
            delivery: DeliveryTracker::new(),
            assembly: AssemblyTracker::new(),
            sync_state: SyncState::with_timing(
                best_full_block_height,
                download_window,
                header_freshness_threshold_ms,
            ),
            download_round: 0,
            net_stats: NetStats::default(),
            headers_only,
            bootstrap_in_progress: false,
            peer_sync: std::collections::HashMap::new(),
            first_deliverers: Vec::new(),
            requires_proofs: false,
        }
    }

    /// Borrow the per-peer sync-state map for snapshot projection.
    /// Each entry is the most recent `PeerSyncSnapshot` recorded by
    /// `on_sync_info`. Empty when no SyncInfo has been processed yet.
    pub fn peer_sync_snapshots(&self) -> &std::collections::HashMap<PeerId, PeerSyncSnapshot> {
        &self.peer_sync
    }

    /// True when this coordinator is wired for Mode 6 (headers-only).
    /// Callers in the action loop can short-circuit block-related
    /// pipelines (mempool admission, block assembly) when this is set.
    pub fn is_headers_only(&self) -> bool {
        self.headers_only
    }

    /// True when this coordinator schedules the ADProofs section (digest-
    /// verifier / Mode 5). Read by the block-section scheduling paths.
    pub fn requires_proofs(&self) -> bool {
        self.requires_proofs
    }

    /// Enable ADProofs scheduling for a digest-verifier backend. Called once at
    /// boot for Mode 5; UTXO/full nodes leave it at the `false` default.
    pub fn set_requires_proofs(&mut self, flag: bool) {
        self.requires_proofs = flag;
    }

    /// Mode 2 transient gate. Set `true` at boot when
    /// `utxo_bootstrap = true` AND no UTXO state yet; the
    /// integration layer flips it to `false` after the snapshot
    /// install advances `best_full_block_height`. Behaves like
    /// `headers_only` while true — suppresses section requests,
    /// section-inv handling, section persistence — to keep the
    /// existing block pipeline out of the way of the bootstrap.
    pub fn set_bootstrap_in_progress(&mut self, flag: bool) {
        self.bootstrap_in_progress = flag;
    }

    /// Whether the section-download pipeline should be suppressed.
    /// Returns true when either Mode 6 (headers_only, permanent)
    /// or Mode 2 mid-bootstrap (bootstrap_in_progress, transient).
    /// Callers in the section path use this instead of
    /// `is_headers_only` so both modes share the suppression.
    pub fn should_skip_block_sections(&self) -> bool {
        self.headers_only || self.bootstrap_in_progress
    }

    /// Drain the per-tick pipeline counters for the heartbeat.
    pub fn take_net_stats(&mut self) -> NetStats {
        std::mem::take(&mut self.net_stats)
    }

    /// Drain the first-deliverer observations accumulated since the last
    /// call: `(header_id, delivering peer)` for each header accepted by
    /// `on_header_validated`. The action loop folds these into its bounded
    /// first-deliverer ring after each `execute_all`. Same drain pattern
    /// as [`take_net_stats`] — pure observability, never read by sync.
    pub fn take_first_deliverers(&mut self) -> Vec<([u8; 32], PeerId)> {
        std::mem::take(&mut self.first_deliverers)
    }

    /// Mark a peer as having sent us a non-tx Modifier in this tick.
    /// Caller is the action loop's Modifier handler. The optional `count`
    /// is the number of modifiers in the batch — used by the per-peer
    /// contribution counter so a peer that ships 50 sections at once
    /// is recognized as 50× more productive than one that ships 1.
    pub fn note_modifier_response(&mut self, peer: PeerId) {
        self.note_modifier_response_n(peer, 1);
    }

    /// Variant that records the actual modifier count from the batch.
    pub fn note_modifier_response_n(&mut self, peer: PeerId, count: u64) {
        self.net_stats.peers_with_response.insert(peer);
        *self.net_stats.per_peer_modifier.entry(peer).or_insert(0) += count;
    }

    /// Mark a peer as having received a SyncInfo from us in this tick.
    /// Caller is the action loop's dispatch sites.
    pub fn note_sync_info_dispatched(&mut self, peer: PeerId) {
        self.net_stats.peers_dispatched_to.insert(peer);
    }

    pub fn sync_state(&self) -> &SyncState {
        &self.sync_state
    }
    pub fn sync_state_mut(&mut self) -> &mut SyncState {
        &mut self.sync_state
    }

    pub fn delivery(&self) -> &DeliveryTracker {
        &self.delivery
    }
    /// Mutable delivery accessor for the hedged-request fanout
    /// (`register_hedge_peers`). The action loop uses this after
    /// `on_inv` has registered the primary peer's request, to
    /// also accept responses from K hedge peers we ALSO sent
    /// `RequestModifier` to.
    pub fn delivery_mut(&mut self) -> &mut DeliveryTracker {
        &mut self.delivery
    }
    pub fn assembly_mut(&mut self) -> &mut ergo_p2p::assembly::AssemblyTracker {
        &mut self.assembly
    }

    /// Clear a `Received` delivery marker for a payload the executor chose not
    /// to retain. This keeps future legitimate `Inv`s requestable.
    pub fn forget_received_modifier(&mut self, modifier_id: &[u8; 32]) -> bool {
        self.delivery.forget_received(modifier_id)
    }

    /// Test-only mutable accessor for the delivery tracker. Used to
    /// preload in-flight state for drain-watermark and partial-capacity
    /// coverage tests; not part of the production API surface.
    #[doc(hidden)]
    pub fn delivery_mut_for_test(&mut self) -> &mut DeliveryTracker {
        &mut self.delivery
    }
}

#[cfg(test)]
mod tests;

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

use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_state::store::StateStore;

use ergo_p2p::assembly::AssemblyTracker;
use ergo_p2p::delivery::{DeliveryAction, DeliveryTracker, ModifierStatus};
use ergo_p2p::message::{self, SyncInfo};
use ergo_p2p::peer::{PeerId, Penalty, SyncVersion};
use ergo_p2p::sync::{PeerChainStatus, SyncState};
use ergo_p2p::types::{InvData, ModifierTypeId};
use ergo_ser::modifier_id::{
    compute_section_id, ExpectedSections, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};

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
}

/// Minimum number of distinct peers that must report our exact tip
/// (`PeerChainStatus::Equal`, a header-id match in V2) before the
/// "caught up to peers" fallback flips the headers-synced latch. Requiring
/// more than one guards against a single stale or lying peer triggering the
/// flip. See [`SyncCoordinator::try_mark_caught_up_to_peers`].
const MIN_CAUGHT_UP_EQUAL_PEERS: usize = 2;

/// How recent a per-peer SyncInfo observation must be to count toward the
/// "caught up to peers" decision. Active peers refresh their entry on every
/// SyncInfo exchange, so a stale (silent) peer's `Equal`/`Older` status ages
/// out of the decision after this window instead of latching forever.
const CAUGHT_UP_PEER_FRESHNESS: Duration = Duration::from_secs(30);

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

    /// Level-triggered "caught up to peers" fallback for the headers-synced
    /// latch. **Deliberate, consensus-safe divergence from Scala** (whose
    /// latch — like ours in [`SyncState::check_headers_synced`] — flips ONLY
    /// on the edge of validating a header fresh per `header.isNew`).
    ///
    /// On an idle / stale tip (e.g. a quiet testnet synced from genesis) the
    /// chain tip header is older than `block_interval * header_chain_diff`, so
    /// the freshness edge never fires and block download never starts — the
    /// node sits at header-tip applying zero blocks. This fallback flips the
    /// latch when we have demonstrably caught up to the network instead:
    ///   * at least [`MIN_CAUGHT_UP_EQUAL_PEERS`] distinct peers report our
    ///     exact CURRENT tip (`Equal` whose `observed_best_header_id` equals
    ///     `current_best_header_id` — a header-id match under V2, not a bare
    ///     height compare, so forks/cumulative-difficulty ambiguity can't fake
    ///     it, and a stale `Equal` from before a tip advance/reorg doesn't
    ///     count), observed within [`CAUGHT_UP_PEER_FRESHNESS`], AND
    ///   * those `Equal` peers are a strict MAJORITY of all peers heard from
    ///     within that window.
    ///
    /// The majority test counts every non-`Equal` fresh peer against the flip,
    /// not just `Older`. V2 classification is lossy: a non-overlapping/forked/
    /// garbage SyncInfo defaults to `Older`, while a peer slightly ahead with
    /// an overlapping `[H+1, H, …]` SyncInfo is recorded as `Younger` — so
    /// neither status alone reliably means "ahead." Requiring `Equal` to be the
    /// majority (a) tolerates a minority of noisy/lying peers — fixing the
    /// single-peer DoS where one peer could veto forever — and (b) still defers
    /// the flip whenever most peers are NOT confirming our tip (real mid-IBD,
    /// whether they read as `Older` or overlapping-`Younger`). On the idle
    /// stall this fix targets, every peer sits at the same tip → all `Equal` →
    /// trivially a majority.
    ///
    /// Only block *download timing* is affected — every block is still fully
    /// validated, so a premature flip can at worst download valid blocks we
    /// already hold headers for. Returns `true` iff it flipped the latch this
    /// call (so the caller logs once). No-op once already synced.
    pub fn try_mark_caught_up_to_peers(
        &mut self,
        now: Instant,
        current_best_header_id: [u8; 32],
    ) -> bool {
        if self.sync_state.headers_chain_synced() {
            return false;
        }
        // Headers-only (Mode 6) and mid-bootstrap (Mode 2) deliberately
        // suppress block-section download. The fallback exists only to START
        // that download, so it must not open the latch for them — otherwise
        // the gated pipeline would register pending blocks and request
        // sections those modes are required to withhold. The latch reopens
        // naturally once bootstrap completes (`bootstrap_in_progress` clears).
        if self.should_skip_block_sections() {
            return false;
        }
        let mut fresh_equal = 0usize;
        let mut fresh_total = 0usize;
        for snap in self.peer_sync.values() {
            if now.duration_since(snap.observed_at) > CAUGHT_UP_PEER_FRESHNESS {
                continue;
            }
            fresh_total += 1;
            // Only an `Equal` observed against our CURRENT tip confirms it. A
            // stale `Equal` (our tip advanced/reorged since) still counts in
            // the denominator — a non-confirming vote — so it makes the
            // majority harder to reach, never easier.
            if snap.status == PeerChainStatus::Equal
                && snap.observed_best_header_id == current_best_header_id
            {
                fresh_equal += 1;
            }
        }
        if fresh_equal >= MIN_CAUGHT_UP_EQUAL_PEERS && 2 * fresh_equal > fresh_total {
            self.sync_state.mark_headers_chain_synced();
            true
        } else {
            false
        }
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

    // ---- Transaction flow ----
    //
    // The coordinator treats transactions as just another modifier
    // type for delivery bookkeeping — it doesn't parse or validate
    // them. The node-side handler filters against the mempool (pool
    // membership + invalidation cache) before asking the coordinator
    // to register a request; the coordinator then replies with the
    // set of IDs that were actually registered (after applying per-
    // peer inflight caps + dedup against in-flight/failed state) and
    // produces the corresponding `RequestModifier` payload.

    /// Register a RequestModifier for `tx_ids` to `peer`. Returns the
    /// `(actions, requested_count)` pair: `actions` holds the `SendToPeer`
    /// with the serialized RequestModifier (or is empty if every id was
    /// already in-flight / failed or the per-peer cap blocks further
    /// requests, or serialization fails), and `requested_count` is the
    /// number of ids ACTUALLY registered + emitted in that RequestModifier.
    /// Callers use the count for observability; it never exceeds the number
    /// of `tx_ids` passed in and reflects the post-dedupe/cap reality, not
    /// the advertised set. The count is `0` exactly when `actions` is empty.
    pub fn request_transactions(
        &mut self,
        peer: PeerId,
        tx_ids: &[[u8; 32]],
        now: Instant,
    ) -> (Vec<Action>, usize) {
        let type_id = ModifierTypeId::Transaction.as_byte();
        let registered = self.delivery.request(peer, type_id, tx_ids, now);
        if registered.is_empty() {
            return (Vec::new(), 0);
        }
        let requested_count = registered.len();
        let request = InvData {
            type_id,
            ids: registered,
        };
        match message::serialize_inv(&request) {
            Ok(payload) => (
                vec![Action::SendToPeer {
                    peer,
                    code: message::CODE_REQUEST_MODIFIER,
                    payload,
                }],
                requested_count,
            ),
            Err(e) => {
                warn!(error = %e, "failed to serialize tx RequestModifier");
                (Vec::new(), 0)
            }
        }
    }

    /// Check delivery ownership when a tx arrives. Caller dispatches
    /// on the returned verdict:
    ///   Accept  → mark received + hand off to the mempool
    ///   Ignore  → duplicate delivery, drop silently
    ///   Reject  → unsolicited modifier, penalize sender
    pub fn on_transaction_received(&mut self, peer: PeerId, tx_id: &[u8; 32]) -> DeliveryAction {
        let action = self.delivery.on_received(tx_id, &peer);
        if let DeliveryAction::Accept = action {
            self.delivery.mark_received(tx_id);
        }
        action
    }

    // ---- Event handlers ----

    /// Process an incoming SyncInfo message from a peer.
    /// Returns actions to execute.
    pub fn on_sync_info(
        &mut self,
        peer: PeerId,
        sync_version: SyncVersion,
        sync_info: &SyncInfo,
        chain: &dyn ChainView,
        now: Instant,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        let (peer_header_ids, peer_headers, peer_height) = match sync_info {
            SyncInfo::V1 { header_ids } => (header_ids.clone(), Vec::new(), None),
            SyncInfo::V2 { headers } => {
                // V2 carries raw headers. Compute IDs (blake2b256 of bytes)
                // for both classification and the commonPoint walk; heights
                // come from our own store via header_height_for once we
                // find a peer header that's on our best chain.
                let ids: Vec<[u8; 32]> =
                    headers.iter().map(|h| *blake2b256(h).as_bytes()).collect();
                (ids, headers.clone(), None)
            }
        };

        // Determine peer's chain status.
        //
        // V1 path uses the existing height-based heuristic with the
        // ID overlap predicate.
        //
        // V2 path: scan peer's headers (assumed newest-first per Scala
        // convention) and find the first ID on our best chain. That ID
        // is the common point (Scala's `commonPoint`). If the newest
        // peer header IS our best_header → Equal. If we find a common
        // point that's NOT our tip → peer is Younger (their tip lives
        // somewhere on our chain, below us). If no peer header is on
        // our chain → fall back to the existing Older path
        // (continuation-header shortcut + reciprocal SyncInfo) which
        // covers Older / Fork / Unknown without needing peer height.
        let status = if !peer_header_ids.is_empty() && peer_headers.is_empty() {
            // V1: ID-only comparison
            ergo_p2p::sync::compare_sync_info(
                &peer_header_ids,
                peer_height,
                chain.best_header_height(),
                |id| chain.is_on_best_chain(id),
            )
        } else if !peer_headers.is_empty() {
            let our_best = chain.best_header_id();
            let newest_id = peer_header_ids.first().copied().unwrap_or([0u8; 32]);
            if newest_id == our_best {
                PeerChainStatus::Equal
            } else if peer_header_ids.iter().any(|id| chain.is_on_best_chain(id)) {
                // Peer's newest is NOT our tip but at least one of their
                // headers IS on our chain — peer is behind us.
                PeerChainStatus::Younger
            } else {
                // Default to Older (existing reciprocal path handles
                // catchup; if peer is on a fork, find_continuation_header
                // returns None and the SyncInfo reply keeps the dance
                // going).
                PeerChainStatus::Older
            }
        } else {
            PeerChainStatus::Unknown
        };

        // Record the per-peer snapshot before dispatching actions.
        // Used by `/peers/syncInfo` projection on the snapshot
        // publisher — sourced from the same status decision the
        // action dispatch below uses, so the API surface always
        // reflects the last classification the coordinator acted
        // on. V2 peer_height inference: if the newest peer header
        // is on our chain, look up its height (peer's tip from
        // OUR view); otherwise leave None and let consumers treat
        // it as "no overlap yet". V1 carries peer_height directly
        // via `peer_height` already destructured above.
        let inferred_peer_height: Option<u32> = match peer_height {
            Some(h) => Some(h),
            None => {
                // V2 inference: find newest peer-header on our best
                // chain (assumed newest-first per Scala convention).
                peer_header_ids
                    .iter()
                    .find(|id| chain.is_on_best_chain(id))
                    .and_then(|id| chain.header_height_for(id))
            }
        };
        self.peer_sync.insert(
            peer,
            PeerSyncSnapshot {
                status,
                peer_height: inferred_peer_height,
                observed_at: now,
                observed_best_header_id: chain.best_header_id(),
            },
        );

        match status {
            PeerChainStatus::Younger | PeerChainStatus::Fork => {
                // Find commonPoint: newest peer header on our best chain.
                let common_id = peer_header_ids
                    .iter()
                    .find(|id| chain.is_on_best_chain(id))
                    .copied();
                if let Some(common_id) = common_id {
                    if let Some(common_h) = chain.header_height_for(&common_id) {
                        // Walk forward from common_h + 1 up to MAX_INV_OBJECTS
                        // header IDs from our best chain. Mirrors Scala
                        // continuationIdsV2 + sendExtension. Returns early
                        // when chain.header_id_at_height returns
                        // AboveTip (we've reached our tip) or
                        // SparseGap (sparse-mode prefix region — we
                        // don't have the row to serve). Sparse-mode
                        // nodes shouldn't be acting as header sources
                        // (ModePeerFeature.nipopow = Some(1) advertises
                        // this), but defensively break here so we never
                        // emit an Inv claiming headers we can't
                        // actually serve.
                        const MAX_INV_OBJECTS: usize = 400;
                        let our_tip_h = chain.best_header_height();
                        let mut ids: Vec<[u8; 32]> = Vec::with_capacity(MAX_INV_OBJECTS);
                        let mut h = common_h.saturating_add(1);
                        while h <= our_tip_h && ids.len() < MAX_INV_OBJECTS {
                            match chain.header_id_at_height(h) {
                                ergo_state::chain::HeightLookup::Dense(id) => ids.push(id),
                                ergo_state::chain::HeightLookup::SparseGap
                                | ergo_state::chain::HeightLookup::AboveTip => break,
                            }
                            h = h.saturating_add(1);
                        }
                        if !ids.is_empty() {
                            let inv = ergo_p2p::types::InvData {
                                type_id: ergo_p2p::types::ModifierTypeId::Header.as_byte(),
                                ids,
                            };
                            if let Ok(payload) = message::serialize_inv(&inv) {
                                actions.push(Action::SendToPeer {
                                    peer,
                                    code: message::CODE_INV,
                                    payload,
                                });
                            }
                        }
                    }
                }
            }
            PeerChainStatus::Older => {
                // Peer is ahead — we need headers from them.
                // V2 shortcut: find the continuation header — the first
                // header in the peer's list (newest-first) whose parent
                // we already have on our chain. This matches Scala's
                // continuationHeaderV2 logic.
                if !peer_headers.is_empty() {
                    let continuation = find_continuation_header(&peer_headers, chain);
                    if let Some(header_bytes) = continuation {
                        actions.push(Action::ValidateHeader { peer, header_bytes });
                    }
                }
                // Also request more headers if we need them. Per-peer
                // throttle: this only debounces our SyncInfo to *this*
                // peer; the broadcast loop in node.rs handles the
                // others independently.
                if self.sync_state.should_send_sync(peer, now) {
                    match build_sync_info_payload(sync_version, chain) {
                        Ok(our_sync) => {
                            actions.push(Action::SendToPeer {
                                peer,
                                code: message::CODE_SYNC_INFO,
                                payload: our_sync,
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to serialize SyncInfo; skipping send")
                        }
                    }
                    // Throttle regardless of the serialization outcome: an
                    // (unreachable-from-valid-state) failure must still back off
                    // to the next window rather than retry — and warn — every
                    // tick. Matches the original always-mark-after-attempt path.
                    self.sync_state.mark_sync_sent(peer, now);
                }
            }
            PeerChainStatus::Equal | PeerChainStatus::Unknown | PeerChainStatus::Nonsense => {
                // No-op: equal chains need no sync; Unknown/Nonsense are
                // handled by the peer_manager's penalty/disconnect paths,
                // not by Log-level tracing here.
            }
        }
        let _ = peer; // kept for future Log reintroduction if useful

        actions
    }

    /// Process an incoming Inv message listing available modifiers.
    pub fn on_inv(
        &mut self,
        peer: PeerId,
        inv: &InvData,
        chain: &dyn ChainView,
        now: Instant,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let is_header_inv = inv.type_id == ModifierTypeId::Header.as_byte();

        // Mode 6 (headers-only) AND Mode 2 (mid-bootstrap): drop
        // section Invs at the perimeter. Mode 6 never wants block
        // transactions, AD proofs, or extensions. Mode 2 also wants
        // them suppressed while the UTXO-snapshot install runs —
        // otherwise the executor would try to replay blocks from
        // height 1 in parallel with the snapshot install and
        // produce conflicting state. Header Invs still flow either
        // way — the header chain must keep advancing.
        //
        // Scala parity: `ToDownloadProcessor.toDownload` returns Nil
        // for both modes; the gate flips off post-bootstrap.
        if self.should_skip_block_sections() && !is_header_inv {
            return actions;
        }

        // Filter to IDs we don't already have. Headers and block sections
        // use different storage lookups. Count each rejection cause so the
        // heartbeat can show where Inv-throughput goes — without this the
        // pipeline collapses into a single "in vs out" number that hides
        // whether we're losing IDs to in-store dedup, in-flight dedup, or
        // received-set dedup. Header pipeline only — section Invs use a
        // different sizing budget and aren't the Step C+D bottleneck.
        if is_header_inv {
            self.net_stats.inv_msgs_received = self.net_stats.inv_msgs_received.saturating_add(1);
            self.net_stats.inv_ids_total = self
                .net_stats
                .inv_ids_total
                .saturating_add(inv.ids.len() as u64);
        }

        let mut filt_have: u64 = 0;
        let mut filt_inflight: u64 = 0;
        let mut filt_received: u64 = 0;
        let mut filt_pruned: u64 = 0;
        let sentinel = self.sync_state.prune_sentinel();
        let needed: Vec<[u8; 32]> = inv
            .ids
            .iter()
            .filter(|id| {
                let have = if is_header_inv {
                    chain.has_header(id) || chain.is_invalid(id)
                } else {
                    chain.has_block_section(id)
                };
                if have {
                    filt_have += 1;
                }
                !have
            })
            .filter(|id| {
                // Mode 3 Phase 3a — request-side gate on the
                // Inv-driven section path. Peers may advertise
                // ids we never indexed (unknown sections —
                // pass-through) or ids whose parent is below
                // our prune sentinel (skip; we'd just evict on
                // apply or refuse to serve later). Inert when
                // `sentinel == 0` (archive / Mode 6 / pre-
                // eviction store).
                if is_header_inv || sentinel == 0 {
                    return true;
                }
                // Fail-CLOSED on unknown / unreadable height.
                // The boot backfill gate makes SECTION_HEIGHT_INDEX
                // complete when sentinel > 1, so None here means
                // orphan id or read failure — requesting either
                // would resurrect bytes or amplify a partial-
                // failure state.
                match chain.get_section_height(id) {
                    Some(h) if h >= sentinel => true,
                    Some(_) | None => {
                        filt_pruned += 1;
                        false
                    }
                }
            })
            .filter(|id| {
                let inflight =
                    self.delivery.status(id) == ergo_p2p::delivery::ModifierStatus::Requested;
                if inflight {
                    filt_inflight += 1;
                }
                !inflight
            })
            .filter(|id| {
                let received =
                    self.delivery.status(id) == ergo_p2p::delivery::ModifierStatus::Received;
                if received {
                    filt_received += 1;
                }
                !received
            })
            .copied()
            .collect();

        if is_header_inv {
            self.net_stats.inv_ids_already_have = self
                .net_stats
                .inv_ids_already_have
                .saturating_add(filt_have);
            self.net_stats.inv_ids_already_inflight = self
                .net_stats
                .inv_ids_already_inflight
                .saturating_add(filt_inflight);
            self.net_stats.inv_ids_already_received = self
                .net_stats
                .inv_ids_already_received
                .saturating_add(filt_received);
        }

        if needed.is_empty() {
            return actions;
        }

        // Register and send request
        let candidate_count = needed.len() as u64;
        let registered = self.delivery.request(peer, inv.type_id, &needed, now);
        if is_header_inv {
            let admitted = registered.len() as u64;
            self.net_stats.inv_ids_admitted =
                self.net_stats.inv_ids_admitted.saturating_add(admitted);
            // Anything that got here but DIDN'T register hit the
            // per-peer cap (MAX_IN_FLIGHT_PER_PEER) inside delivery.
            let capped = candidate_count.saturating_sub(admitted);
            self.net_stats.inv_ids_capped_per_peer = self
                .net_stats
                .inv_ids_capped_per_peer
                .saturating_add(capped);
            let entry = self.net_stats.per_peer_inv.entry(peer).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(inv.ids.len() as u64);
            entry.1 = entry.1.saturating_add(admitted);
        }
        if !registered.is_empty() {
            let request = InvData {
                type_id: inv.type_id,
                ids: registered,
            };
            match message::serialize_inv(&request) {
                Ok(payload) => {
                    actions.push(Action::SendToPeer {
                        peer,
                        code: message::CODE_REQUEST_MODIFIER,
                        payload,
                    });
                }
                Err(e) => {
                    warn!(error = %e, "failed to serialize RequestModifier");
                }
            }
        }

        actions
    }

    /// Process a received modifier (header or block section) from a peer.
    pub fn on_modifier_received(
        &mut self,
        peer: PeerId,
        type_id: u8,
        modifier_id: [u8; 32],
        data: Vec<u8>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Check delivery ownership
        let action = self.delivery.on_received(&modifier_id, &peer);
        match action {
            DeliveryAction::Accept => {
                // Body-only streak reset: only an accepted block-BODY section
                // clears the download-failure streak. A header or mempool-tx
                // delivery must NOT reset it, or a peer that stalls on bodies
                // could dodge degradation by riding the constant header/tx
                // flow. Classify by the REQUESTED type (what we asked this
                // peer for, read before mark_received evicts the entry) — not
                // the peer's wire-claimed type_id — symmetric with the timeout
                // side and so the class can't be spoofed. The delivering peer
                // is reset (on a late/hedge win it may differ from the
                // original owner — correct attribution).
                let delivered_body = self
                    .delivery
                    .modifier_type(&modifier_id)
                    .is_some_and(ModifierTypeId::is_block_body_section);
                self.delivery.mark_received(&modifier_id);
                if delivered_body {
                    actions.push(Action::NoteDeliveryOutcome {
                        peer,
                        succeeded: true,
                    });
                }
            }
            DeliveryAction::Ignore => {
                return actions; // duplicate
            }
            DeliveryAction::RejectSpam => {
                actions.push(Action::Penalize {
                    peer,
                    penalty: Penalty::Spam,
                });
                return actions;
            }
        }

        if type_id == ModifierTypeId::Header.as_byte() {
            // Header received — validate it
            actions.push(Action::ValidateHeader {
                peer,
                header_bytes: data,
            });
        } else if ModifierTypeId::is_block_section(type_id) {
            // Mode 6 (headers-only) AND Mode 2 (mid-bootstrap):
            // drop section payloads even if they slip past the Inv
            // filter (peer push, race with a late-arriving request
            // from before the mode took effect). No persistence,
            // no assembly registration — the section never enters
            // the store, so the executor can't apply it.
            if self.should_skip_block_sections() {
                return actions;
            }
            // Note: receive-time bytes-hash-to-modifier_id check
            // (Scala parity, `ErgoNodeViewSynchronizer.parseModifiers`
            // line 801-813) lives at the production caller in
            // `ergo-node/src/node/messaging.rs` so coordinator tests
            // can drive the assembly flow with synthetic fixtures
            // without needing canonical wire bytes.
            actions.push(Action::PersistSection {
                modifier_id,
                section_bytes: data,
                section_type: type_id,
            });
            if let Some(header_id) = self.assembly.section_received(&modifier_id) {
                actions.push(Action::AssembleBlock { header_id });
            }
        }

        actions
    }

    /// Called after a header has been validated and persisted.
    /// Updates sync state. Only requests block sections once header chain
    /// is synced (matches Scala's isHeadersChainSynced gate).
    pub fn on_header_validated(
        &mut self,
        peer: PeerId,
        header_id: [u8; 32],
        height: u32,
        header_timestamp_ms: u64,
        expected_sections: ExpectedSections,
        now: Instant,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // First-deliverer observability: record the peer whose Modifier
        // carried this just-accepted header. Recorded BEFORE the
        // headers-synced / mode gates below (which only govern section
        // requests) so every accepted header is attributable, including
        // those validated during header-only sync. The node's bounded
        // ring keeps only the FIRST deliverer per id; pure observability.
        self.first_deliverers.push((header_id, peer));

        self.sync_state.set_best_known_header(height);
        self.sync_state.check_headers_synced(header_timestamp_ms);

        // Don't track pending blocks or request sections until headers are synced.
        // Scala: toDownload() returns Nil when !isHeadersChainSynced.
        if !self.sync_state.headers_chain_synced() {
            return actions;
        }

        // Mode 6 (headers-only) AND Mode 2 (mid-bootstrap): never
        // register pending blocks or request sections via the
        // header-validated pipeline. Mode 6: never (forever).
        // Mode 2: until the snapshot install advances
        // best_full_block_height, at which point the integration
        // layer flips `bootstrap_in_progress` off and this gate
        // releases.
        // Scala parity: `ToDownloadProcessor.toDownload` returns Nil
        // when `!nodeSettings.verifyTransactions` OR when running
        // utxoBootstrap mid-bootstrap
        // (ToDownloadProcessor.scala:111,131).
        if self.should_skip_block_sections() {
            return actions;
        }

        // Mode 3 — request-side gate. Headers below the prune sentinel
        // will have their sections evicted on apply, so requesting them
        // is wasted bandwidth + peer load. This is the third of three
        // drop points; the other two are the receive-side and serve-side
        // gates in the executor + messaging layer. Inert when
        // `prune_sentinel == 0` (archive / Mode 6 / fresh
        // pre-eviction store).
        let sentinel = self.sync_state.prune_sentinel();
        if sentinel > 0 && height < sentinel {
            return actions;
        }

        self.sync_state.add_pending_block(height, header_id);
        self.assembly.register_header(expected_sections.clone());

        // Request block sections if within download window.
        let within_window = height
            <= self
                .sync_state
                .best_full_block_height()
                .saturating_add(self.sync_state.download_window() as u32);

        if within_window {
            let section_requests = [
                (
                    ModifierTypeId::BlockTransactions.as_byte(),
                    expected_sections.transactions_id,
                ),
                (
                    ModifierTypeId::Extension.as_byte(),
                    expected_sections.extension_id,
                ),
            ];

            for (type_id, section_id) in section_requests {
                let registered = self.delivery.request(peer, type_id, &[section_id], now);
                if !registered.is_empty() {
                    let request = InvData {
                        type_id,
                        ids: registered,
                    };
                    if let Ok(payload) = message::serialize_inv(&request) {
                        actions.push(Action::SendToPeer {
                            peer,
                            code: message::CODE_REQUEST_MODIFIER,
                            payload,
                        });
                    }
                }
            }
        }

        actions
    }

    /// Called after a full block has been assembled and applied to state.
    pub fn on_block_applied(&mut self, header_id: [u8; 32], height: u32) {
        self.sync_state.set_best_full_block(height);
        self.assembly.remove(&header_id);
    }

    /// Drop pending block downloads that are no longer on the best-header
    /// chain after a full-block rollback/reorg.
    pub fn prune_pending_to_best_chain(&mut self, chain: &dyn ChainView) {
        self.sync_state
            .retain_pending_blocks(|b| chain.is_on_best_chain(&b.header_id));
    }

    /// Check for delivery timeouts and re-request from alternative peers.
    ///
    /// Re-check delivery timeouts and redistribute retried IDs across
    /// `eligible_peers`. All peers that just failed are excluded from the
    /// redistribution so retried IDs are spread across responsive peers
    /// using the same bucketed partitioner as `request_missing_sections_bucketed`.
    pub fn check_timeouts(&mut self, now: Instant, eligible_peers: &[PeerId]) -> Vec<Action> {
        let mut actions = Vec::new();
        let result = self.delivery.check_timeouts(now);

        let tx_type = ModifierTypeId::Transaction.as_byte();
        let mut all_retryable: Vec<[u8; 32]> = Vec::new();
        let mut failed_peers: Vec<PeerId> = Vec::new();
        for (failed_peer, ids) in &result.retryable {
            // Scala parity (checkDelivery, ErgoNodeViewSynchronizer.scala):
            // a timed-out MEMPOOL TRANSACTION is just forgotten — it may
            // legitimately have left the peer's mempool, so there is "no
            // reason to penalize the peer" and no re-request. Block sections
            // and headers keep the aggressive penalize + re-request path.
            // The just-timed-out ids sit in the tracker's recently-released
            // shadow, so `modifier_type` still resolves their requested class.
            let (tx_ids, block_ids): (Vec<[u8; 32]>, Vec<[u8; 32]>) = ids
                .iter()
                .partition(|id| self.delivery.modifier_type(id) == Some(tx_type));
            for tx_id in &tx_ids {
                // Fully drop the forgotten tx so the tracker stops tracking
                // it (no recently-released shadow, no retry count, no late
                // allowance) and never re-requests it.
                self.delivery.forget_timed_out(tx_id);
            }
            // If only txs timed out for this peer, there is nothing to
            // penalize or re-request — leave the peer untouched.
            if block_ids.is_empty() {
                continue;
            }
            actions.push(Action::Penalize {
                peer: *failed_peer,
                penalty: Penalty::NonDelivery,
            });
            // Body-only download-quality streak (separate from the decaying
            // score, which NonDelivery can't move past DEGRADED_THRESHOLD).
            // Only block-BODY section timeouts count: a peer that stalls on
            // bodies but keeps answering the constant header/mempool-tx flow
            // must still accrue toward degradation.
            if block_ids.iter().any(|id| {
                self.delivery
                    .modifier_type(id)
                    .is_some_and(ModifierTypeId::is_block_body_section)
            }) {
                actions.push(Action::NoteDeliveryOutcome {
                    peer: *failed_peer,
                    succeeded: false,
                });
            }
            info!(peer = %failed_peer, count = block_ids.len(), "modifier delivery timed out, retrying with other peers");
            all_retryable.extend_from_slice(&block_ids);
            failed_peers.push(*failed_peer);
        }

        if !all_retryable.is_empty() {
            let non_failed: Vec<PeerId> = eligible_peers
                .iter()
                .copied()
                .filter(|p| !failed_peers.contains(p))
                .collect();
            actions.extend(self.rerequest_modifiers_bucketed(&all_retryable, &non_failed, now));
        }

        if !result.exhausted.is_empty() {
            warn!(
                count = result.exhausted.len(),
                max_retries = ergo_p2p::delivery::MAX_RETRIES,
                "modifier delivery retries exhausted",
            );
        }

        actions
    }

    /// Called when a peer disconnects. Cancels in-flight requests and
    /// re-requests retryable ones from alternative peers using the bucketed
    /// partitioner so the load is spread across responsive peers.
    pub fn on_peer_disconnected(
        &mut self,
        peer: &PeerId,
        now: Instant,
        eligible_peers: &[PeerId],
    ) -> Vec<Action> {
        // Drop the per-peer SyncInfo timer entry so the map stays
        // bounded by live peers. Doing it here (not in the executor)
        // keeps cleanup co-located with the rest of the coordinator's
        // peer-state teardown.
        self.sync_state.forget_peer_sync(peer);
        // Drop the per-peer chain-state snapshot too — once the peer
        // is gone its last-observed status is no longer relevant for
        // `/peers/syncInfo` (which lists current peers).
        self.peer_sync.remove(peer);
        let result = self.delivery.cancel_peer(peer, now);
        let mut actions = Vec::new();
        if !result.retryable.is_empty() {
            info!(peer = %peer, count = result.retryable.len(), "reassigning in-flight requests from disconnected peer");
            let non_failed: Vec<PeerId> = eligible_peers
                .iter()
                .copied()
                .filter(|p| p != peer)
                .collect();
            actions.extend(self.rerequest_modifiers_bucketed(&result.retryable, &non_failed, now));
        }
        if !result.exhausted.is_empty() {
            warn!(
                peer = %peer,
                count = result.exhausted.len(),
                "modifiers permanently failed: disconnect exhausted retries",
            );
        }
        actions
    }

    /// Request sections for all pending blocks that are missing from the store.
    ///
    /// Used after restart (via recover_coordinator) or when the download
    /// window advances. For each pending block within the window, checks
    /// if its required sections are already delivered or in-flight; if not,
    /// requests them from an available peer.
    pub fn request_missing_sections(
        &mut self,
        chain: &dyn ChainView,
        now: Instant,
        select_peer: impl Fn(u8) -> Option<PeerId>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        // Mode 6 / Mode 2 defense-in-depth (see
        // `request_missing_sections_bucketed`).
        if self.should_skip_block_sections() {
            return actions;
        }
        let blocks_to_download = self.sync_state.blocks_to_download();

        // Collect section IDs by type, then send batched RequestModifier messages.
        // Sending one message per type (up to 400 IDs) instead of one per section
        // reduces P2P overhead and avoids overwhelming the peer.
        let mut tx_ids: Vec<[u8; 32]> = Vec::new();
        let mut ext_ids: Vec<[u8; 32]> = Vec::new();

        for pending in blocks_to_download {
            let section_ids = match self.assembly.expected_section_ids(&pending.header_id) {
                Some(ids) => ids,
                None => continue,
            };

            for (type_id, section_id) in section_ids {
                // Skip sections already inflight or received. Permanently
                // `Failed` sections (3 retries exhausted) ARE re-included
                // here and re-requested below via `request_force`, which
                // clears the failed entry before re-registering. Without
                // this revival path, a single section that all 3
                // randomly-chosen peers happen to be slow on becomes
                // permanently abandoned, and since block-apply is
                // sequential, that one abandoned section halts the entire
                // post-snapshot catch-up. Surfaced by Mode 2 part 2
                // live-test where the 7.6k-block post-install gap never
                // closed.
                let status = self.delivery.status(&section_id);
                if matches!(
                    status,
                    ergo_p2p::delivery::ModifierStatus::Requested
                        | ergo_p2p::delivery::ModifierStatus::Received
                ) {
                    continue;
                }
                if chain.has_block_section(&section_id) {
                    continue;
                }
                // Mode 3 request-side gate. Skip sections whose
                // parent header is below the prune sentinel —
                // we'd evict them on apply and the serve side
                // would refuse them anyway. Fail-CLOSED on
                // `None`: when the sentinel is active the boot
                // backfill gate makes SECTION_HEIGHT_INDEX
                // complete, so an unknown id is orphan or
                // attacker. Inert when
                // sync_state.prune_sentinel() == 0 (archive /
                // Mode 6 / pre-eviction store).
                let sentinel = self.sync_state.prune_sentinel();
                if sentinel > 0 {
                    match chain.get_section_height(&section_id) {
                        Some(h) if h >= sentinel => {}
                        Some(_) | None => continue,
                    }
                }
                if type_id == ModifierTypeId::BlockTransactions.as_byte() {
                    tx_ids.push(section_id);
                } else if type_id == ModifierTypeId::Extension.as_byte() {
                    ext_ids.push(section_id);
                }
            }
        }

        // Send batched requests — one message per type, up to 400 IDs each.
        // This matches how the Scala node batches RequestModifier.
        for (type_id, ids) in [
            (ModifierTypeId::BlockTransactions.as_byte(), &tx_ids),
            (ModifierTypeId::Extension.as_byte(), &ext_ids),
        ] {
            if ids.is_empty() {
                continue;
            }
            if let Some(peer) = select_peer(type_id) {
                // `request_force` allows previously-Failed IDs to be
                // re-requested (it clears the failed entry on revive).
                // Healthy Unknown IDs behave identically to a regular
                // `request` call.
                let registered = self.delivery.request_allow_failed(peer, type_id, ids, now);
                if !registered.is_empty() {
                    let request = InvData {
                        type_id,
                        ids: registered,
                    };
                    if let Ok(payload) = message::serialize_inv(&request) {
                        actions.push(Action::SendToPeer {
                            peer,
                            code: message::CODE_REQUEST_MODIFIER,
                            payload,
                        });
                    }
                }
            }
        }

        actions
    }

    /// Bucketed multi-peer variant of `request_missing_sections`.
    ///
    /// Ports Scala's `requestDownload` + `ElementPartitioner.distribute`,
    /// with two Rust-native adjustments documented inline below:
    ///   * Step 2.5 balances section types against actual per-peer
    ///     in-flight capacity instead of a static cap.
    ///   * Step 3 keeps Scala's 12/peer/round only when 3+ peers are
    ///     available; for 1–2 peers it derives `max_per_bucket` from the
    ///     balanced per-type budget so IBD doesn't stall waiting for
    ///     small Scala buckets to drain.
    ///
    /// Collects pending-section demand, groups by modifier type, then
    /// partitions across `peers` via `partition::distribute` and emits
    /// one `SendToPeer(RequestModifier)` per non-empty bucket.
    ///
    /// Caller responsibilities:
    /// - `peers` is pre-sorted (typically by `PeerManager::eligible_download_peers`).
    ///   Sort order determines bucket assignment; the `download_round`
    ///   counter advances each call so the first peer in the sorted
    ///   list isn't permanently the first assignee.
    /// - Empty `peers` is safe (no-op).
    ///
    /// Preserves these invariants from `request_missing_sections`:
    /// - Only pending sections whose tracker status is `Unknown` and
    ///   whose modifier is not in the store are requested.
    /// - Per-peer capacity (`MAX_IN_FLIGHT_PER_PEER`): if
    ///   `delivery.request` registers fewer IDs than the bucket
    ///   contains, only the registered IDs reach the wire. Truncated
    ///   IDs return to `Unknown` and will be picked up by a later
    ///   call (possibly against a different peer via rotation).
    ///
    /// Emitted-action shape (deterministic, oracle-testable):
    /// - Buckets iterate in (type_id asc, peer_index asc) order where
    ///   `peer_index` is the rotated position in `peers`.
    /// - Empty buckets (type with no pending, or peer whose
    ///   `delivery.request` returned empty) are omitted.
    pub fn request_missing_sections_bucketed(
        &mut self,
        chain: &dyn ChainView,
        now: Instant,
        peers: &[PeerId],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        // Mode 6 (headers-only) / Mode 2 (mid-bootstrap) defense-in-depth:
        // never request block sections while section download is suppressed,
        // regardless of how the headers-synced latch got set.
        if self.should_skip_block_sections() {
            return actions;
        }
        if peers.is_empty() {
            return actions;
        }

        // Step 1: collect pending demand grouped by type (filtered by
        // delivery status and store presence). Reuse the same gate as
        // the old method; keeping the two consistent simplifies
        // migration and lets parity tests compare outputs.
        let blocks_to_download = self.sync_state.blocks_to_download();
        let mut tx_ids: Vec<[u8; 32]> = Vec::new();
        let mut ext_ids: Vec<[u8; 32]> = Vec::new();
        for pending in blocks_to_download {
            let section_ids = match self.assembly.expected_section_ids(&pending.header_id) {
                Some(ids) => ids,
                None => continue,
            };
            for (type_id, section_id) in section_ids {
                // Same revival path as `request_missing_sections`: include
                // permanently-Failed IDs so they get re-requested via
                // `request_force` below. Without this the sequential
                // apply pipeline stalls on the first 3-times-unlucky
                // section.
                let status = self.delivery.status(&section_id);
                if matches!(
                    status,
                    ergo_p2p::delivery::ModifierStatus::Requested
                        | ergo_p2p::delivery::ModifierStatus::Received
                ) {
                    continue;
                }
                if chain.has_block_section(&section_id) {
                    continue;
                }
                // Mode 3 request-side gate (matches the
                // `request_missing_sections` path). Sub-sentinel
                // sections would just be evicted on apply and
                // refused on serve. Fail-CLOSED on `None` —
                // unindexed sections in sentinel-active mode
                // are orphan / attacker IDs.
                let sentinel = self.sync_state.prune_sentinel();
                if sentinel > 0 {
                    match chain.get_section_height(&section_id) {
                        Some(h) if h >= sentinel => {}
                        Some(_) | None => continue,
                    }
                }
                if type_id == ModifierTypeId::BlockTransactions.as_byte() {
                    tx_ids.push(section_id);
                } else if type_id == ModifierTypeId::Extension.as_byte() {
                    ext_ids.push(section_id);
                }
            }
        }

        if tx_ids.is_empty() && ext_ids.is_empty() {
            return actions;
        }

        // Step 2: filter to peers with in-flight capacity. A peer near
        // its `MAX_IN_FLIGHT_PER_PEER` cap contributes no usable bucket
        // anyway, and letting `distribute` assign it a bucket strands
        // the earliest IDs under it.
        let capacity_filtered: Vec<PeerId> = peers
            .iter()
            .copied()
            .filter(|p| self.delivery.peer_has_capacity(p))
            .collect();
        if capacity_filtered.is_empty() {
            return actions;
        }

        // Step 2.5: balance section types against each peer's
        // *actual* remaining in-flight capacity. Sum free slots across
        // peers, divide by the number of section types with actual
        // demand, and use `div_ceil` so:
        //   * tiny budgets (1 free slot) still emit a request,
        //   * one-sided demand (only tx or only ext) gets the full
        //     budget rather than half.
        const MAX_INV_OBJECTS: usize = 400;
        let total_available_slots: usize = capacity_filtered
            .iter()
            .map(|p| self.delivery.available_slots(p))
            .sum();
        let types_with_demand = (!tx_ids.is_empty() as usize) + (!ext_ids.is_empty() as usize);
        let per_type_total_cap = if types_with_demand == 0 {
            0
        } else {
            total_available_slots.div_ceil(types_with_demand)
        };
        tx_ids.truncate(per_type_total_cap);
        ext_ids.truncate(per_type_total_cap);

        // Step 3: adaptive bucket cap. Scala's 12/peer/round works
        // because Scala sees many peers. With 1-2 connected peers a
        // small cap (12) would take 16+ rounds to enqueue a full window.
        // With 3+ peers we fall back to Scala's 12 — the per-type cap
        // above already bounds total demand against real capacity.
        //
        // Tested 50 (2026-05-05): per-peer mod ship rate DROPPED from
        // 12-26 → 3-5 mods/heartbeat. Bigger batches starved the
        // dispatch — each peer "consumes" more demand per slot, so
        // fewer requests get issued total. Reverted to 12.
        let n_peers = capacity_filtered.len();
        let max_per_bucket = if n_peers >= 3 {
            12
        } else {
            // min_capacity would be fairer but peers have near-equal
            // budgets at IBD tip; use per-type total / peers rounded up.
            per_type_total_cap
                .div_ceil(n_peers.max(1))
                .clamp(1, MAX_INV_OBJECTS)
        };
        let cfg = ergo_p2p::partition::BucketConfig { max_per_bucket };

        // Step 4: partition. BTreeMap so types iterate ascending —
        // BlockTransactions(102) precedes Extension(108).
        let mut by_type = std::collections::BTreeMap::new();
        if !tx_ids.is_empty() {
            by_type.insert(ModifierTypeId::BlockTransactions.as_byte(), tx_ids);
        }
        if !ext_ids.is_empty() {
            by_type.insert(ModifierTypeId::Extension.as_byte(), ext_ids);
        }
        let buckets =
            ergo_p2p::partition::distribute(&capacity_filtered, &by_type, self.download_round, cfg);
        self.download_round = self.download_round.wrapping_add(1);

        // Step 5: register with DeliveryTracker per-peer, emit one
        // SendToPeer per bucket with ONLY the registered IDs
        // (capacity truncation — verified by the test below).
        // `request_force` revives previously-Failed IDs (Mode 2
        // catch-up gap fix) — Unknown IDs behave identically.
        for ((peer, type_id), ids) in buckets {
            let registered = self.delivery.request_allow_failed(peer, type_id, &ids, now);
            if registered.is_empty() {
                continue;
            }
            let request = InvData {
                type_id,
                ids: registered,
            };
            if let Ok(payload) = message::serialize_inv(&request) {
                actions.push(Action::SendToPeer {
                    peer,
                    code: message::CODE_REQUEST_MODIFIER,
                    payload,
                });
            }
        }

        actions
    }

    /// HOL (head-of-line) hedge: for every pending block within the download
    /// window whose body sections have been inflight longer than
    /// `hol_threshold`, early-reassign them to a different capable peer
    /// without waiting for the full `DELIVERY_TIMEOUT`. `reassign` keeps the
    /// slow peer late-acceptable, so the first valid delivery wins and the
    /// loser is never penalized — this composes cleanly with the body
    /// delivery-failure streak.
    ///
    /// Covers ALL in-window pending blocks, not just the head of line: a
    /// section several blocks deep still gates assembly once the tip catches
    /// up. Work is self-limiting — only sections actually stuck past
    /// `hol_threshold` are touched, and reassigns spread across `peers` by
    /// least in-flight count.
    ///
    /// Only block-section types (tx, extension) are hedged; headers use the
    /// normal timeout path. `peers` is expected to be the capability-filtered
    /// section-peer set (see the executor wrapper).
    pub fn check_hol_hedges(
        &mut self,
        best_full_block_height: u32,
        hol_threshold: Duration,
        now: Instant,
        peers: &[PeerId],
    ) -> Vec<Action> {
        // Snapshot in-window pending header ids first, releasing the
        // sync_state borrow before the delivery/assembly mutations below.
        let window = self.sync_state.download_window() as u32;
        let limit = best_full_block_height.saturating_add(window);
        let header_ids: Vec<[u8; 32]> = self
            .sync_state
            .pending_blocks_iter()
            .filter(|b| b.height > best_full_block_height && b.height <= limit)
            .map(|b| b.header_id)
            .collect();

        // Flatten every expected body section across those blocks.
        let mut section_ids: Vec<(u8, [u8; 32])> = Vec::new();
        for header_id in header_ids {
            if let Some(ids) = self.assembly.expected_section_ids(&header_id) {
                section_ids.extend(ids);
            }
        }
        if section_ids.is_empty() {
            return Vec::new();
        }

        let mut by_peer_type: std::collections::HashMap<(PeerId, u8), Vec<[u8; 32]>> =
            std::collections::HashMap::new();
        let mut hedged = 0usize;
        let mut revived_failed = 0usize;

        for (type_id, section_id) in section_ids {
            if type_id != ModifierTypeId::BlockTransactions.as_byte()
                && type_id != ModifierTypeId::Extension.as_byte()
            {
                continue;
            }
            match self.delivery.status(&section_id) {
                ModifierStatus::Requested => {
                    let (age, old_peer) = match self.delivery.inflight_age(&section_id, now) {
                        Some(v) => v,
                        None => continue,
                    };
                    if age <= hol_threshold {
                        continue;
                    }
                    let Some(new_peer) = peers
                        .iter()
                        .copied()
                        .filter(|p| *p != old_peer && self.delivery.peer_has_capacity(p))
                        .min_by_key(|p| self.delivery.inflight_count(p))
                    else {
                        continue;
                    };
                    if self.delivery.reassign(&section_id, new_peer, now) {
                        by_peer_type
                            .entry((new_peer, type_id))
                            .or_default()
                            .push(section_id);
                        hedged += 1;
                    }
                }
                ModifierStatus::Failed => {
                    let Some(peer) = peers
                        .iter()
                        .copied()
                        .filter(|p| self.delivery.peer_has_capacity(p))
                        .min_by_key(|p| self.delivery.inflight_count(p))
                    else {
                        continue;
                    };
                    let registered =
                        self.delivery
                            .request_allow_failed(peer, type_id, &[section_id], now);
                    if !registered.is_empty() {
                        by_peer_type
                            .entry((peer, type_id))
                            .or_default()
                            .extend(registered);
                        revived_failed += 1;
                    }
                }
                ModifierStatus::Unknown | ModifierStatus::Received => {}
            }
        }

        let mut actions = Vec::new();
        for ((peer, type_id), ids) in by_peer_type {
            let request = InvData { type_id, ids };
            if let Ok(payload) = message::serialize_inv(&request) {
                actions.push(Action::SendToPeer {
                    peer,
                    code: message::CODE_REQUEST_MODIFIER,
                    payload,
                });
            }
        }
        if hedged > 0 || revived_failed > 0 {
            debug!(hedged, revived_failed, "HOL repair");
        }
        actions
    }

    /// Internal: re-request a set of modifier IDs from an alternative peer.
    /// Redistribute `ids` across `peers` using the same bucketed partitioner
    /// as `request_missing_sections_bucketed`. Block-section types (tx, ext)
    /// are grouped and spread evenly; header IDs fall back to per-ID sends to
    /// the first available peer (rare — headers are synced before block IBD).
    fn rerequest_modifiers_bucketed(
        &mut self,
        ids: &[[u8; 32]],
        peers: &[PeerId],
        now: Instant,
    ) -> Vec<Action> {
        if peers.is_empty() || ids.is_empty() {
            return Vec::new();
        }

        let mut tx_ids: Vec<[u8; 32]> = Vec::new();
        let mut ext_ids: Vec<[u8; 32]> = Vec::new();
        let mut header_ids: Vec<[u8; 32]> = Vec::new();

        for id in ids {
            let type_id = self
                .delivery
                .modifier_type(id)
                .or_else(|| self.assembly.identify_section(id).map(|(t, _)| t))
                .unwrap_or(ModifierTypeId::Header.as_byte());
            if type_id == ModifierTypeId::BlockTransactions.as_byte() {
                tx_ids.push(*id);
            } else if type_id == ModifierTypeId::Extension.as_byte() {
                ext_ids.push(*id);
            } else {
                header_ids.push(*id);
            }
        }

        let mut actions = Vec::new();

        if !tx_ids.is_empty() || !ext_ids.is_empty() {
            const MAX_INV_OBJECTS: usize = 400;
            let n_peers = peers.len();
            let total = tx_ids.len().max(ext_ids.len());
            let max_per_bucket = if n_peers >= 3 {
                12
            } else {
                total.div_ceil(n_peers.max(1)).clamp(1, MAX_INV_OBJECTS)
            };

            let mut by_type = std::collections::BTreeMap::new();
            if !tx_ids.is_empty() {
                by_type.insert(ModifierTypeId::BlockTransactions.as_byte(), tx_ids);
            }
            if !ext_ids.is_empty() {
                by_type.insert(ModifierTypeId::Extension.as_byte(), ext_ids);
            }

            let cfg = ergo_p2p::partition::BucketConfig { max_per_bucket };
            let buckets =
                ergo_p2p::partition::distribute(peers, &by_type, self.download_round, cfg);
            self.download_round = self.download_round.wrapping_add(1);

            for ((peer, type_id), bucket_ids) in buckets {
                let registered = self.delivery.request(peer, type_id, &bucket_ids, now);
                if registered.is_empty() {
                    continue;
                }
                let request = InvData {
                    type_id,
                    ids: registered,
                };
                if let Ok(payload) = message::serialize_inv(&request) {
                    actions.push(Action::SendToPeer {
                        peer,
                        code: message::CODE_REQUEST_MODIFIER,
                        payload,
                    });
                }
            }
        }

        // Headers: send one message per ID to the first available peer.
        for id in header_ids {
            let type_id = ModifierTypeId::Header.as_byte();
            if let Some(&peer) = peers.first() {
                let registered = self.delivery.request(peer, type_id, &[id], now);
                if !registered.is_empty() {
                    let request = InvData {
                        type_id,
                        ids: registered,
                    };
                    if let Ok(payload) = message::serialize_inv(&request) {
                        actions.push(Action::SendToPeer {
                            peer,
                            code: message::CODE_REQUEST_MODIFIER,
                            payload,
                        });
                    }
                }
            }
        }

        actions
    }

    /// Whether the node is in Initial Block Download mode.
    pub fn is_ibd(&self) -> bool {
        self.sync_state.is_ibd()
    }

    /// Request header modifiers by id from a specific peer. Used to walk
    /// backwards from an orphan chain when a peer gave us headers whose
    /// ultimate parent isn't in our store (fork scenario — canonical
    /// reorg past our `best_header`). `finalize_header`'s cumulative-
    /// score comparison handles the actual fork-choice swap once the
    /// missing parents arrive, so this does nothing more than register
    /// the request with the delivery tracker and emit the wire message.
    ///
    /// Returns at most one `SendToPeer(RequestModifier, Header, ids)` action.
    /// Empty when all requested ids are already in-flight or received.
    /// Previously failed IDs are revived here: orphan roots are required to
    /// stitch a fork back to a known ancestor, and later peers may deliver
    /// headers that earlier peers timed out on.
    pub fn request_missing_header_parents(
        &mut self,
        peer: PeerId,
        parent_ids: &[[u8; 32]],
        now: Instant,
    ) -> Vec<Action> {
        if parent_ids.is_empty() {
            return Vec::new();
        }
        let type_id = ModifierTypeId::Header.as_byte();
        let registered = self
            .delivery
            .request_allow_failed(peer, type_id, parent_ids, now);
        if registered.is_empty() {
            return Vec::new();
        }
        let request = InvData {
            type_id,
            ids: registered,
        };
        match message::serialize_inv(&request) {
            Ok(payload) => vec![Action::SendToPeer {
                peer,
                code: message::CODE_REQUEST_MODIFIER,
                payload,
            }],
            Err(e) => {
                warn!(error = %e, "failed to serialize RequestModifier(Header, parents)");
                Vec::new()
            }
        }
    }
}

/// Find the continuation header from a V2 SyncInfo.
///
/// Scala's continuationHeaderV2 (ErgoHistoryReader.scala:299) inspects only
/// the FIRST header in the peer's list and accepts it only when:
/// 1. We don't already have it
/// 2. Its parent is our current best header
///
/// This is stricter than "any known parent" — it only advances the chain
/// by exactly one header from the tip.
fn find_continuation_header(peer_headers: &[Vec<u8>], chain: &dyn ChainView) -> Option<Vec<u8>> {
    let header_bytes = peer_headers.first()?;
    if header_bytes.len() < 33 {
        return None;
    }
    // Check we don't already have this header
    let header_id = *blake2b256(header_bytes).as_bytes();
    if chain.has_header(&header_id) {
        return None;
    }
    // Check parent is our best header (not just any known header)
    let mut parent_id = [0u8; 32];
    parent_id.copy_from_slice(&header_bytes[1..33]);
    if parent_id == chain.best_header_id() {
        Some(header_bytes.clone())
    } else {
        None
    }
}

/// Build a SyncInfo payload appropriate for the peer's sync version.
/// Uses ChainView to get actual recent headers from our best chain.
pub fn build_sync_info_payload(
    version: SyncVersion,
    chain: &dyn ChainView,
) -> Result<Vec<u8>, message::MessageError> {
    match version {
        SyncVersion::V2 => {
            let headers = chain.recent_header_bytes(50); // MaxHeadersAllowed = 50
            message::serialize_sync_info(&SyncInfo::V2 { headers })
        }
        SyncVersion::V1 => {
            let ids = chain.recent_header_ids(1000); // MaxBlockIds (parser tolerates +1, serializer sends ≤1000)
            message::serialize_sync_info(&SyncInfo::V1 { header_ids: ids })
        }
    }
}

// ---- ChainView impl for StateStore (production) ----
//
// Keeps the trait for unit-test mocking (MockChain below), but production
// code and integration tests pass `&StateStore` directly. The previous
// `StateChainView` wrapper type was deleted.

impl ChainView for ergo_state::store::StateStore {
    fn best_header_id(&self) -> [u8; 32] {
        self.chain_state().best_header_id
    }

    fn best_header_height(&self) -> u32 {
        self.chain_state().best_header_height
    }

    fn best_full_block_height(&self) -> u32 {
        self.chain_state().best_full_block_height
    }

    fn is_on_best_chain(&self, header_id: &[u8; 32]) -> bool {
        // Two-read lookup: header's height (HEADER_META) + best-chain id at
        // that height (HEADER_CHAIN_INDEX). Depth-independent.
        let target_height = match self.get_header_meta(header_id).ok().flatten() {
            Some(m) => m.height,
            None => return false,
        };
        if target_height > self.chain_state().best_header_height {
            return false;
        }
        match self.get_header_id_at_height(target_height).ok().flatten() {
            Some(best_at_h) => best_at_h == *header_id,
            None => false,
        }
    }

    fn has_header(&self, header_id: &[u8; 32]) -> bool {
        self.get_header(header_id).ok().flatten().is_some()
    }

    fn has_block_section(&self, modifier_id: &[u8; 32]) -> bool {
        self.get_block_section(modifier_id).ok().flatten().is_some()
    }

    fn get_section_height(&self, modifier_id: &[u8; 32]) -> Option<u32> {
        StateStore::get_section_height(self, modifier_id)
            .ok()
            .flatten()
    }

    fn is_invalid(&self, header_id: &[u8; 32]) -> bool {
        StateStore::is_invalid(self, header_id).unwrap_or(false)
    }

    fn recent_header_ids(&self, count: usize) -> Vec<[u8; 32]> {
        let mut ids = Vec::new();
        let mut current = self.chain_state().best_header_id;
        for _ in 0..count {
            if current == [0u8; 32] {
                break;
            }
            ids.push(current);
            match self.get_header_meta(&current).ok().flatten() {
                Some(meta) => current = meta.parent_id,
                None => break,
            }
        }
        ids
    }

    fn recent_header_bytes(&self, count: usize) -> Vec<Vec<u8>> {
        let mut headers = Vec::new();
        let mut current = self.chain_state().best_header_id;
        for _ in 0..count {
            if current == [0u8; 32] {
                break;
            }
            match self.get_header(&current).ok().flatten() {
                Some(bytes) => {
                    headers.push(bytes);
                    match self.get_header_meta(&current).ok().flatten() {
                        Some(meta) => current = meta.parent_id,
                        None => break,
                    }
                }
                None => break,
            }
        }
        headers
    }

    fn header_id_at_height(&self, height: u32) -> ergo_state::chain::HeightLookup {
        self.lookup_header_at_height(height)
            .unwrap_or(ergo_state::chain::HeightLookup::AboveTip)
    }

    fn header_height_for(&self, header_id: &[u8; 32]) -> Option<u32> {
        self.get_header_meta(header_id)
            .ok()
            .flatten()
            .map(|m| m.height)
    }
}

/// `ChainView` over the Mode 5 digest backend. Mirrors the
/// `StateStore` impl's semantics method-for-method, reading through the
/// `HeaderSectionStore` / `ChainStateRead` surface the digest store
/// shares. The digest store persists the same header + section tables,
/// so the sync coordinator drives header/section flow against a digest
/// node identically to a UTXO node — only the block-apply seam differs.
impl ChainView for ergo_state::DigestStateStore {
    fn best_header_id(&self) -> [u8; 32] {
        self.chain_state().best_header_id
    }

    fn best_header_height(&self) -> u32 {
        self.chain_state().best_header_height
    }

    fn best_full_block_height(&self) -> u32 {
        self.chain_state().best_full_block_height
    }

    fn is_on_best_chain(&self, header_id: &[u8; 32]) -> bool {
        use ergo_state::HeaderSectionStore;
        let target_height = match self.get_header_meta(header_id).ok().flatten() {
            Some(m) => m.height,
            None => return false,
        };
        if target_height > self.chain_state().best_header_height {
            return false;
        }
        match self.get_header_id_at_height(target_height).ok().flatten() {
            Some(best_at_h) => best_at_h == *header_id,
            None => false,
        }
    }

    fn has_header(&self, header_id: &[u8; 32]) -> bool {
        use ergo_state::HeaderSectionStore;
        self.get_header(header_id).ok().flatten().is_some()
    }

    fn has_block_section(&self, modifier_id: &[u8; 32]) -> bool {
        use ergo_state::HeaderSectionStore;
        self.get_block_section(modifier_id).ok().flatten().is_some()
    }

    fn get_section_height(&self, modifier_id: &[u8; 32]) -> Option<u32> {
        ergo_state::HeaderSectionStore::get_section_height(self, modifier_id)
            .ok()
            .flatten()
    }

    fn is_invalid(&self, header_id: &[u8; 32]) -> bool {
        ergo_state::HeaderSectionStore::is_invalid(self, header_id).unwrap_or(false)
    }

    fn recent_header_ids(&self, count: usize) -> Vec<[u8; 32]> {
        use ergo_state::HeaderSectionStore;
        let mut ids = Vec::new();
        let mut current = self.chain_state().best_header_id;
        for _ in 0..count {
            if current == [0u8; 32] {
                break;
            }
            ids.push(current);
            match self.get_header_meta(&current).ok().flatten() {
                Some(meta) => current = meta.parent_id,
                None => break,
            }
        }
        ids
    }

    fn recent_header_bytes(&self, count: usize) -> Vec<Vec<u8>> {
        use ergo_state::HeaderSectionStore;
        let mut headers = Vec::new();
        let mut current = self.chain_state().best_header_id;
        for _ in 0..count {
            if current == [0u8; 32] {
                break;
            }
            match self.get_header(&current).ok().flatten() {
                Some(bytes) => {
                    headers.push(bytes);
                    match self.get_header_meta(&current).ok().flatten() {
                        Some(meta) => current = meta.parent_id,
                        None => break,
                    }
                }
                None => break,
            }
        }
        headers
    }

    fn header_id_at_height(&self, height: u32) -> ergo_state::chain::HeightLookup {
        self.lookup_header_at_height(height)
            .unwrap_or(ergo_state::chain::HeightLookup::AboveTip)
    }

    fn header_height_for(&self, header_id: &[u8; 32]) -> Option<u32> {
        use ergo_state::HeaderSectionStore;
        self.get_header_meta(header_id)
            .ok()
            .flatten()
            .map(|m| m.height)
    }
}

/// `ChainView` over the runtime backend enum: match-forward every
/// method to the live `StateStore` or `DigestStateStore`. Lets the
/// sync coordinator and executor hold `&StateBackendKind` without a
/// type parameter or `dyn`.
impl ChainView for ergo_state::StateBackendKind {
    fn best_header_id(&self) -> [u8; 32] {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.best_header_id(),
            ergo_state::StateBackendKind::Digest(d) => d.best_header_id(),
        }
    }

    fn best_header_height(&self) -> u32 {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.best_header_height(),
            ergo_state::StateBackendKind::Digest(d) => d.best_header_height(),
        }
    }

    fn best_full_block_height(&self) -> u32 {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.best_full_block_height(),
            ergo_state::StateBackendKind::Digest(d) => d.best_full_block_height(),
        }
    }

    fn is_on_best_chain(&self, header_id: &[u8; 32]) -> bool {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.is_on_best_chain(header_id),
            ergo_state::StateBackendKind::Digest(d) => d.is_on_best_chain(header_id),
        }
    }

    fn has_header(&self, header_id: &[u8; 32]) -> bool {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.has_header(header_id),
            ergo_state::StateBackendKind::Digest(d) => d.has_header(header_id),
        }
    }

    fn has_block_section(&self, modifier_id: &[u8; 32]) -> bool {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.has_block_section(modifier_id),
            ergo_state::StateBackendKind::Digest(d) => d.has_block_section(modifier_id),
        }
    }

    fn get_section_height(&self, modifier_id: &[u8; 32]) -> Option<u32> {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => ChainView::get_section_height(s, modifier_id),
            ergo_state::StateBackendKind::Digest(d) => {
                ChainView::get_section_height(d, modifier_id)
            }
        }
    }

    fn is_invalid(&self, header_id: &[u8; 32]) -> bool {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => ChainView::is_invalid(s, header_id),
            ergo_state::StateBackendKind::Digest(d) => ChainView::is_invalid(d, header_id),
        }
    }

    fn recent_header_ids(&self, count: usize) -> Vec<[u8; 32]> {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.recent_header_ids(count),
            ergo_state::StateBackendKind::Digest(d) => d.recent_header_ids(count),
        }
    }

    fn recent_header_bytes(&self, count: usize) -> Vec<Vec<u8>> {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.recent_header_bytes(count),
            ergo_state::StateBackendKind::Digest(d) => d.recent_header_bytes(count),
        }
    }

    fn header_id_at_height(&self, height: u32) -> ergo_state::chain::HeightLookup {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.header_id_at_height(height),
            ergo_state::StateBackendKind::Digest(d) => d.header_id_at_height(height),
        }
    }

    fn header_height_for(&self, header_id: &[u8; 32]) -> Option<u32> {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.header_height_for(header_id),
            ergo_state::StateBackendKind::Digest(d) => d.header_height_for(header_id),
        }
    }
}

/// Verify that the bytes received for `modifier_id` actually re-hash to
/// that modifier_id. Mirrors Scala
/// `ErgoNodeViewSynchronizer.parseModifiers:801-813` — the receive-time
/// check that prevents a peer from claiming "here's the bytes for ID X"
/// while sending bytes whose canonical content recomputes a different
/// ID. Correctness at apply time would also catch this; doing it on
/// receive lets us penalize the lying peer immediately instead of
/// after we've persisted bad bytes and walked them through the
/// assembly path.
///
/// Returns `Ok(())` for unknown section types — those don't have a
/// canonical receive-time recomputation rule and are filtered out
/// upstream by the delivery tracker (unsolicited modifiers → Spam).
///
/// Caller is `ergo-node/src/node/messaging.rs`'s `CODE_MODIFIER` arm,
/// which invokes this before passing bytes to
/// [`SyncCoordinator::on_modifier_received`]. Kept out of the
/// coordinator path so coordinator tests can drive assembly flow with
/// synthetic fixtures without canonical wire bytes.
pub fn verify_section_modifier_id(
    type_id: u8,
    modifier_id: &[u8; 32],
    bytes: &[u8],
) -> Result<(), String> {
    let mut r = VlqReader::new(bytes);
    let candidates: Vec<[u8; 32]> = match type_id {
        TYPE_BLOCK_TRANSACTIONS => {
            let bt = ergo_ser::block_transactions::read_block_transactions(&mut r)
                .map_err(|e| format!("BlockTransactions parse: {e:?}"))?;
            if r.remaining() != 0 {
                return Err(format!(
                    "trailing bytes after BlockTransactions ({} extra)",
                    r.remaining(),
                ));
            }
            let tx_ids: Result<Vec<[u8; 32]>, _> = bt
                .transactions
                .iter()
                .map(|tx| ergo_ser::transaction::transaction_id(tx).map(|id| *id.as_bytes()))
                .collect();
            let tx_ids = tx_ids.map_err(|e| format!("transaction_id: {e:?}"))?;
            let tx_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
            // v1 (pre-Autolykos-v2, height < 417_792): merkle root over
            // tx_ids only. v2+: root over `tx_ids ++ witness_ids`, where
            // each witness_id is `blake2b256(concatenated_input_proofs)
            // .drop(1)` per `ergo-validation/src/block.rs:472-488`. The
            // parsed `BlockTransactions` struct doesn't expose the block
            // version (the v2+ wire marker is consumed by the reader),
            // so compute both candidate roots and accept whichever
            // matches — the alternative would require re-parsing the
            // version marker or threading the header version through
            // the caller. Cost is one extra merkle round on canonical
            // v1 sections, which haven't appeared since 2020.
            let v1_root = ergo_crypto::merkle::transactions_root(&tx_refs, None);
            let witness_data: Vec<Vec<u8>> = bt
                .transactions
                .iter()
                .map(|tx| {
                    let mut proofs = Vec::new();
                    for input in &tx.inputs {
                        proofs.extend_from_slice(&input.spending_proof.proof);
                    }
                    let h = ergo_crypto::autolykos::common::blake2b256(&proofs);
                    h[1..].to_vec()
                })
                .collect();
            let witness_refs: Vec<&[u8]> = witness_data.iter().map(|w| w.as_slice()).collect();
            let v2_root = ergo_crypto::merkle::transactions_root(&tx_refs, Some(&witness_refs));
            vec![
                compute_section_id(TYPE_BLOCK_TRANSACTIONS, bt.header_id.as_bytes(), &v1_root),
                compute_section_id(TYPE_BLOCK_TRANSACTIONS, bt.header_id.as_bytes(), &v2_root),
            ]
        }
        TYPE_EXTENSION => {
            let ext = ergo_ser::extension::read_extension(&mut r)
                .map_err(|e| format!("Extension parse: {e:?}"))?;
            if r.remaining() != 0 {
                return Err(format!(
                    "trailing bytes after Extension ({} extra)",
                    r.remaining(),
                ));
            }
            let kv: Vec<(&[u8], &[u8])> = ext
                .fields
                .iter()
                .map(|f| (f.key.as_slice(), f.value.as_slice()))
                .collect();
            let root = ergo_crypto::merkle::extension_root(&kv);
            vec![compute_section_id(
                TYPE_EXTENSION,
                ext.header_id.as_bytes(),
                &root,
            )]
        }
        TYPE_AD_PROOFS => {
            let ap = ergo_ser::ad_proofs::read_ad_proofs(&mut r)
                .map_err(|e| format!("ADProofs parse: {e:?}"))?;
            if r.remaining() != 0 {
                return Err(format!(
                    "trailing bytes after ADProofs ({} extra)",
                    r.remaining(),
                ));
            }
            let digest = *blake2b256(&ap.proof_bytes).as_bytes();
            vec![compute_section_id(
                TYPE_AD_PROOFS,
                ap.header_id.as_bytes(),
                &digest,
            )]
        }
        _ => {
            // Reject unknown section types so a peer can't escape the
            // receive-time check by claiming an arbitrary high
            // `type_id` that happens to pass `is_block_section`'s
            // `>= 50` floor. Caller is expected to gate this function
            // on {102, 104, 108} for canonical traffic.
            return Err(format!("unknown section type {type_id}"));
        }
    };
    if candidates.iter().any(|c| c == modifier_id) {
        Ok(())
    } else {
        Err(format!(
            "section_id mismatch: claimed {} recomputed candidates {:?}",
            hex::encode(modifier_id),
            candidates.iter().map(hex::encode).collect::<Vec<_>>(),
        ))
    }
}

#[cfg(test)]
mod tests;

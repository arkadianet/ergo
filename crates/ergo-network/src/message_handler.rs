//! Message dispatcher for incoming P2P messages.
//!
//! Routes [`RawMessage`]s from the connection pool to the correct handler
//! (sync, inventory, modifiers) and returns [`SyncAction`]s for the event
//! loop to execute.

use std::collections::HashMap;
use std::time::Instant;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ergo_consensus::autolykos::validate_pow;
use ergo_storage::history_db::HistoryDb;
use ergo_types::modifier_id::ModifierId;
use ergo_wire::codec::RawMessage;
use ergo_wire::header_ser::parse_header as wire_parse_header;
use ergo_wire::inv::{InvData, ModifiersData};
use ergo_wire::sync_info::ErgoSyncInfo;
use rayon::prelude::*;

use crate::connection_pool::PeerId;
use crate::delivery_tracker::{DeliveryTracker, ModifierStatus};
use crate::header_partitioner::{self, EligiblePeers, DEFAULT_MIN_PER_PEER};
use crate::node_view::NodeViewHolder;
use crate::penalty_manager::PenaltyType;
use crate::persistent_sync;
use crate::sync_manager::{SyncAction, SyncManager};
use crate::sync_metrics::SyncMetrics;
use crate::sync_tracker::{classify_peer, SyncTracker};

// ---------------------------------------------------------------------------
// Transaction cost rate limiting
// ---------------------------------------------------------------------------

/// Fallback cost assigned to a transaction when its actual validation cost
/// is not available (e.g., in digest mode).
const FALLBACK_TX_COST: u64 = 1000;

/// Default global cost limit per inter-block interval (Scala: `MempoolCostPerBlock = 12_000_000`).
pub const DEFAULT_MEMPOOL_COST_PER_BLOCK: u64 = 12_000_000;

/// Default per-peer cost limit per inter-block interval (Scala: `MempoolPeerCostPerBlock = 10_000_000`).
pub const DEFAULT_MEMPOOL_PEER_COST_PER_BLOCK: u64 = 10_000_000;

/// Tracks cumulative transaction processing cost since the last block was applied.
///
/// Matches Scala's `interblockCost` and `perPeerCost` accumulators in
/// `ErgoNodeViewSynchronizer`. When either the global or per-peer limit
/// is exceeded, new transactions are rejected until the counters are
/// reset by a new block application.
pub struct TxCostTracker {
    /// Total cost of all transactions processed since last block.
    pub interblock_cost: u64,
    /// Per-peer cost since last block.
    pub per_peer_cost: HashMap<PeerId, u64>,
    /// Global cost limit (default: 12_000_000).
    pub global_limit: u64,
    /// Per-peer cost limit (default: 10_000_000).
    pub peer_limit: u64,
}

impl Default for TxCostTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TxCostTracker {
    /// Create a new tracker with default limits matching Scala's constants.
    pub fn new() -> Self {
        Self {
            interblock_cost: 0,
            per_peer_cost: HashMap::new(),
            global_limit: DEFAULT_MEMPOOL_COST_PER_BLOCK,
            peer_limit: DEFAULT_MEMPOOL_PEER_COST_PER_BLOCK,
        }
    }

    /// Create a tracker with custom limits.
    pub fn with_limits(global_limit: u64, peer_limit: u64) -> Self {
        Self {
            interblock_cost: 0,
            per_peer_cost: HashMap::new(),
            global_limit,
            peer_limit,
        }
    }

    /// Check whether a transaction from the given peer can be processed
    /// within the current cost limits.
    pub fn can_accept(&self, peer_id: PeerId) -> bool {
        if self.interblock_cost >= self.global_limit {
            return false;
        }
        let peer_cost = self.per_peer_cost.get(&peer_id).copied().unwrap_or(0);
        peer_cost < self.peer_limit
    }

    /// Record the cost of a processed transaction (accepted, rejected, or invalidated).
    pub fn record_cost(&mut self, peer_id: PeerId, cost: u64) {
        self.interblock_cost = self.interblock_cost.saturating_add(cost);
        let entry = self.per_peer_cost.entry(peer_id).or_insert(0);
        *entry = entry.saturating_add(cost);
    }

    /// Reset all counters. Called when a new block is applied.
    pub fn reset(&mut self) {
        self.interblock_cost = 0;
        self.per_peer_cost.clear();
    }
}

/// Compute the blake2b-256 hash of the given data.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).unwrap();
    out
}

/// Header type ID.
const HEADER_TYPE_ID: u8 = 101;

/// Result of parallel header validation: either a successfully parsed and
/// PoW-verified header (with its index into the `requested` vec), or a
/// rejected modifier ID with a human-readable reason.
type HeaderValidationResult =
    Result<(usize, ModifierId, ergo_types::header::Header), (ModifierId, String)>;

// ---------------------------------------------------------------------------
// HandleResult
// ---------------------------------------------------------------------------

/// Result of handling a single incoming message.
#[derive(Debug)]
pub struct HandleResult {
    /// Actions the event loop should execute (send messages, request modifiers).
    pub actions: Vec<SyncAction>,
    /// New header IDs that were stored during this handling cycle.
    pub new_headers: Vec<ModifierId>,
    /// Penalties to apply to peers for misbehavior.
    pub penalties: Vec<(PenaltyType, PeerId)>,
    /// Block IDs that were validated and applied during this handling cycle.
    pub applied_blocks: Vec<ModifierId>,
}

impl HandleResult {
    /// Create an empty result with no actions or headers.
    pub fn empty() -> Self {
        Self {
            actions: Vec::new(),
            new_headers: Vec::new(),
            penalties: Vec::new(),
            applied_blocks: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Handle an incoming message from a peer.
///
/// Dispatches on the message code:
/// - **1** (GetPeers): respond with our connected peers.
/// - **2** (Peers): parse addresses and add them to the pool.
/// - **65** (SyncInfo): parse peer's sync state, respond with ours.
/// - **55** (Inv): filter unknown modifiers, request them from the peer.
/// - **33** (Modifiers): store sections, trigger block downloads.
/// - **22** (RequestModifier): serve known modifiers from the database.
/// - Everything else is silently ignored.
#[allow(clippy::too_many_arguments)]
pub fn handle_message(
    peer_id: PeerId,
    msg: &RawMessage,
    node_view: &mut NodeViewHolder,
    sync_mgr: &mut SyncManager,
    tracker: &mut DeliveryTracker,
    connected_peers: &[std::net::SocketAddr],
    sync_tracker: &mut SyncTracker,
    cache: &mut crate::modifiers_cache::ModifiersCache,
    last_sync_from: &mut HashMap<PeerId, Instant>,
    is_synced_for_txs: bool,
    last_sync_header_applied: &mut Option<u32>,
    tx_cost_tracker: &mut TxCostTracker,
    max_headers: u32,
    connected_peer_ids: &[PeerId],
    metrics: &mut SyncMetrics,
) -> HandleResult {
    match msg.code {
        1 => handle_get_peers(peer_id, connected_peers),
        2 => handle_peers(&msg.body),
        65 => {
            const PER_PEER_SYNC_LOCK_MS: u128 = 100;
            let now = Instant::now();
            if let Some(last) = last_sync_from.get(&peer_id) {
                if now.duration_since(*last).as_millis() < PER_PEER_SYNC_LOCK_MS {
                    return HandleResult::empty();
                }
            }
            last_sync_from.insert(peer_id, now);
            handle_sync_info(
                peer_id,
                &msg.body,
                &node_view.history,
                sync_tracker,
                tracker,
                last_sync_header_applied,
                max_headers,
            )
        }
        55 => {
            let mp = node_view.mempool.read().unwrap();
            handle_inv(
                peer_id,
                &msg.body,
                tracker,
                &node_view.history,
                &mp,
                is_synced_for_txs,
                sync_tracker,
                connected_peer_ids,
                metrics,
                false,
            )
        }
        33 => handle_modifiers(
            peer_id,
            &msg.body,
            node_view,
            sync_mgr,
            tracker,
            cache,
            is_synced_for_txs,
            tx_cost_tracker,
            max_headers,
        ),
        22 => {
            let mp = node_view.mempool.read().unwrap();
            handle_request_modifier(peer_id, &msg.body, &node_view.history, &mp)
        }
        _ => HandleResult::empty(),
    }
}

// ---------------------------------------------------------------------------
// GetPeers (code 1)
// ---------------------------------------------------------------------------

/// Respond to a GetPeers request by serializing our connected peers.
fn handle_get_peers(peer_id: PeerId, connected_peers: &[std::net::SocketAddr]) -> HandleResult {
    use ergo_wire::peer_spec::{serialize_peers, PeerAddr};

    let peers: Vec<PeerAddr> = connected_peers
        .iter()
        .take(30)
        .map(|addr| PeerAddr { address: *addr })
        .collect();

    let data = serialize_peers(&peers);

    HandleResult {
        actions: vec![SyncAction::SendPeers { peer_id, data }],
        new_headers: Vec::new(),
        penalties: Vec::new(),
        applied_blocks: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Peers (code 2)
// ---------------------------------------------------------------------------

/// Parse a Peers response and extract socket addresses for the peer pool.
fn handle_peers(body: &[u8]) -> HandleResult {
    let peers = match ergo_wire::peer_spec::parse_peers(body) {
        Ok(p) => p,
        Err(_) => return HandleResult::empty(),
    };

    let addresses: Vec<std::net::SocketAddr> = peers.into_iter().map(|p| p.address).collect();

    if addresses.is_empty() {
        return HandleResult::empty();
    }

    HandleResult {
        actions: vec![SyncAction::AddPeers { addresses }],
        new_headers: Vec::new(),
        penalties: Vec::new(),
        applied_blocks: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// SyncInfo (code 65)
// ---------------------------------------------------------------------------

/// Parse the peer's SyncInfo and respond based on chain comparison.
///
/// Classifies the peer based on comparing their best header height to ours
/// and stores the result in the [`SyncTracker`].
///
/// - **Older** (peer ahead of us): Send our SyncInfo to just that peer so
///   they know our state and can help us catch up.
/// - **Younger / Fork** (peer behind us or on a fork): Compute continuation
///   header IDs and send them as an `Inv` so the peer can request the actual
///   headers it is missing.
/// - **Equal / Unknown**: Broadcast our SyncInfo to all peers (existing
///   behavior).
fn handle_sync_info(
    peer_id: PeerId,
    body: &[u8],
    history: &HistoryDb,
    sync_tracker: &mut SyncTracker,
    tracker: &DeliveryTracker,
    last_sync_header_applied: &mut Option<u32>,
    max_headers: u32,
) -> HandleResult {
    let parsed = match ErgoSyncInfo::parse(body) {
        Ok(si) => si,
        Err(_) => return HandleResult::empty(),
    };

    let our_best_id = history.best_header_id().ok().flatten();

    let our_height = our_best_id
        .as_ref()
        .and_then(|id| history.load_header(id).ok().flatten())
        .map(|h| h.height)
        .unwrap_or(0);

    let their_height = match &parsed {
        ErgoSyncInfo::V2(v2) => v2.last_headers.first().map(|h| h.height).unwrap_or(0),
        ErgoSyncInfo::V1(_) => 0,
    };

    // Extract peer's best header ID from SyncInfo V2
    let their_best_id = match &parsed {
        ErgoSyncInfo::V2(v2) => v2.last_headers.first().map(|h| {
            // Compute header ID = blake2b256(serialized header with PoW)
            let serialized = ergo_wire::header_ser::serialize_header(h);
            ModifierId(blake2b256(&serialized))
        }),
        ErgoSyncInfo::V1(_) => None,
    };

    // Look up our header ID at the peer's height
    let our_id_at_their_height = if their_height > 0 {
        history
            .header_ids_at_height(their_height)
            .ok()
            .and_then(|ids| ids.into_iter().next())
    } else {
        None
    };

    let status = classify_peer(
        their_height,
        our_height,
        their_best_id.as_ref(),
        our_id_at_their_height.as_ref(),
    );
    sync_tracker.update_status(peer_id, status, Some(their_height));

    match status {
        crate::sync_tracker::PeerChainStatus::Older => {
            // Peer is ahead — send our SyncInfo so they know our state.
            let sync_info = match persistent_sync::build_sync_info_persistent(history, max_headers)
            {
                Ok(si) => si,
                Err(_) => return HandleResult::empty(),
            };
            let data = match sync_info {
                ErgoSyncInfo::V2(v2) => v2.serialize(),
                ErgoSyncInfo::V1(_) => return HandleResult::empty(),
            };
            let mut actions = vec![SyncAction::SendSyncInfo {
                peer_id: Some(peer_id),
                data,
            }];

            // Check for continuation header: if the peer's most recent
            // header (first in our newest-first ordering) has parent_id
            // equal to our best header ID, we can apply it directly.
            if let ErgoSyncInfo::V2(ref v2) = parsed {
                if let Some(continuation) = v2.last_headers.first() {
                    if let Some(ref best_id) = our_best_id {
                        if continuation.parent_id == *best_id {
                            let header_bytes =
                                ergo_wire::header_ser::serialize_header(continuation);
                            let header_id = ModifierId(blake2b256(&header_bytes));

                            // Only apply if the delivery tracker doesn't
                            // already know about this header and the height
                            // exceeds any previously applied sync header.
                            let is_unknown = tracker.status(HEADER_TYPE_ID, &header_id)
                                == ModifierStatus::Unknown;
                            let above_last =
                                continuation.height > last_sync_header_applied.unwrap_or(0);

                            if is_unknown && above_last {
                                tracing::info!(
                                    header_id = hex::encode(header_id.0),
                                    height = continuation.height,
                                    "applying continuation header from SyncInfoV2"
                                );
                                *last_sync_header_applied = Some(continuation.height);
                                actions.push(SyncAction::ApplyContinuationHeader {
                                    peer_id,
                                    header_bytes,
                                    header_id,
                                });
                            }
                        }
                    }
                }
            }

            HandleResult {
                actions,
                new_headers: Vec::new(),
                penalties: Vec::new(),
                applied_blocks: Vec::new(),
            }
        }
        crate::sync_tracker::PeerChainStatus::Younger
        | crate::sync_tracker::PeerChainStatus::Fork => {
            // Peer is behind or on a fork — compute continuation IDs and
            // send them as Inv so the peer can request the actual headers.
            let peer_headers = match &parsed {
                ErgoSyncInfo::V2(v2) => &v2.last_headers,
                ErgoSyncInfo::V1(_) => return HandleResult::empty(),
            };

            let continuation_ids = match history.continuation_ids_v2(peer_headers) {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to compute continuation IDs");
                    return HandleResult::empty();
                }
            };

            if continuation_ids.is_empty() {
                return HandleResult::empty();
            }

            HandleResult {
                actions: vec![SyncAction::SendInv {
                    peer_id,
                    type_id: 101,
                    ids: continuation_ids,
                }],
                new_headers: Vec::new(),
                penalties: Vec::new(),
                applied_blocks: Vec::new(),
            }
        }
        _ => {
            // Equal or Unknown — broadcast our SyncInfo (existing behavior).
            let sync_info = match persistent_sync::build_sync_info_persistent(history, max_headers)
            {
                Ok(si) => si,
                Err(_) => return HandleResult::empty(),
            };
            let data = match sync_info {
                ErgoSyncInfo::V2(v2) => v2.serialize(),
                ErgoSyncInfo::V1(_) => return HandleResult::empty(),
            };
            HandleResult {
                actions: vec![SyncAction::SendSyncInfo {
                    peer_id: None,
                    data,
                }],
                new_headers: Vec::new(),
                penalties: Vec::new(),
                applied_blocks: Vec::new(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Inv (code 55)
// ---------------------------------------------------------------------------

/// Filter out modifiers we already have or have already requested, then
/// request the unknown ones from the announcing peer.
///
/// For header requests (type_id 101), also detects stale requests that have
/// been pending from another peer for >1 second and reassigns them to this
/// announcing peer.  This prevents multi-second stalls when the original
/// peer is slow, because the natural Inv flood from multiple peers provides
/// near-instant recovery.
///
/// For transaction announcements (type_id 2), checks the mempool instead
/// of the history database since unconfirmed transactions live in memory.
#[allow(clippy::too_many_arguments)]
fn handle_inv(
    peer_id: PeerId,
    body: &[u8],
    tracker: &mut DeliveryTracker,
    history: &HistoryDb,
    mempool: &crate::mempool::ErgoMemPool,
    is_synced_for_txs: bool,
    sync_tracker: &SyncTracker,
    connected_peer_ids: &[PeerId],
    metrics: &mut SyncMetrics,
    force_single_peer: bool,
) -> HandleResult {
    use std::time::Duration;

    let inv = match InvData::parse(body) {
        Ok(inv) => inv,
        Err(_) => return HandleResult::empty(),
    };

    let type_id = inv.type_id as u8;

    if type_id == 2 && !is_synced_for_txs {
        return HandleResult::empty();
    }

    let total_inv_ids = inv.ids.len();
    let stale_threshold = Duration::from_secs(1);

    // Phase 1: Filter IDs preserving Inv order. DO NOT set_requested yet.
    let mut to_request: Vec<ModifierId> = Vec::new();
    let mut stale_ids: std::collections::HashSet<ModifierId> = std::collections::HashSet::new();
    let mut stale_count = 0u32;

    for id in &inv.ids {
        let status = tracker.status(type_id, id);
        match status {
            ModifierStatus::Unknown => {
                let already_have = if type_id == 2 {
                    mempool.contains(&ergo_types::transaction::TxId(id.0))
                } else if type_id == HEADER_TYPE_ID {
                    // Headers are stored by header_id — direct lookup works.
                    history.contains_modifier(type_id, id).unwrap_or(true)
                } else {
                    // Body sections use computed section_ids on the wire but
                    // are stored internally by header_id. We can't efficiently
                    // check by section_id here, so rely on the tracker's
                    // Requested/Received status to prevent duplicates.
                    false
                };
                if !already_have {
                    to_request.push(*id);
                } else {
                    metrics.record_dup_prevented();
                }
            }
            ModifierStatus::Requested if type_id == HEADER_TYPE_ID => {
                if let Some(age) = tracker.request_age(type_id, id) {
                    if age >= stale_threshold {
                        to_request.push(*id);
                        stale_ids.insert(*id);
                        stale_count += 1;
                    } else {
                        metrics.record_dup_prevented();
                    }
                }
            }
            _ => {
                metrics.record_dup_prevented();
            }
        }
    }

    if to_request.is_empty() {
        tracing::trace!(type_id, total_inv_ids, "handle_inv: all known");
        return HandleResult::empty();
    }

    // Phase 2: Non-header types — single peer, unchanged behavior
    if type_id != HEADER_TYPE_ID {
        for id in &to_request {
            tracker.set_requested(type_id, *id, peer_id);
        }
        tracing::info!(
            type_id,
            requested = to_request.len(),
            "handle_inv: requesting from announcing peer"
        );
        return HandleResult {
            actions: vec![SyncAction::RequestModifiers {
                peer_id,
                type_id,
                ids: to_request,
            }],
            new_headers: Vec::new(),
            penalties: Vec::new(),
            applied_blocks: Vec::new(),
        };
    }

    // Phase 3: Header-specific multi-peer partitioning
    const GLOBAL_OUTSTANDING_CAP: usize = 2400;
    const PER_PEER_OUTSTANDING_CAP: usize = 800;

    let global_outstanding = tracker.total_outstanding_headers();
    if global_outstanding >= GLOBAL_OUTSTANDING_CAP {
        tracing::warn!(
            global_outstanding,
            to_request_len = to_request.len(),
            "cap_backpressure: global outstanding cap exceeded, skipping batch"
        );
        return HandleResult::empty();
    }

    let batch_id = metrics.new_batch_id();

    tracing::info!(
        batch_id,
        peer = peer_id,
        inv_len = total_inv_ids,
        to_request_len = to_request.len(),
        stale_reassigned = stale_count,
        "inv_received"
    );

    // During HeaderSync with a targeted peer, skip multi-peer partitioning.
    // Partitioning fills the delivery tracker with in-flight IDs that overlap
    // with subsequent Inv responses from the targeted loop, reducing each
    // cycle's to_request_len from ~399 to ~26 and killing throughput.
    let eligible = if force_single_peer {
        EligiblePeers::SinglePeerFallback(peer_id, "force_single_peer (HeaderSync)")
    } else {
        header_partitioner::select_eligible_peers(peer_id, sync_tracker, connected_peer_ids)
    };

    let actions = match eligible {
        EligiblePeers::Partition(mut peers) => {
            peers.retain(|&pid| tracker.outstanding_header_count(pid) < PER_PEER_OUTSTANDING_CAP);
            if peers.is_empty() {
                tracing::warn!(
                    batch_id,
                    "cap_backpressure_all_peers: all eligible peers at outstanding cap"
                );
                return HandleResult::empty();
            }

            let assignments =
                header_partitioner::partition_header_ids(&to_request, &peers, DEFAULT_MIN_PER_PEER);

            let summary: Vec<(PeerId, usize)> = assignments
                .iter()
                .map(|(pid, chunk)| (*pid, chunk.len()))
                .collect();
            metrics.record_partition(batch_id, total_inv_ids, to_request.len(), &summary);

            let mut result_actions = Vec::with_capacity(assignments.len());
            let mut offset = 0;
            for (assigned_peer, chunk) in &assignments {
                for id in chunk {
                    if stale_ids.contains(id) {
                        tracker.reassign(type_id, id, *assigned_peer);
                    } else {
                        tracker.set_requested(type_id, *id, *assigned_peer);
                    }
                }

                metrics.record_requests_sent(
                    batch_id,
                    *assigned_peer,
                    chunk.len(),
                    offset,
                    offset + chunk.len().saturating_sub(1),
                );
                offset += chunk.len();

                result_actions.push(SyncAction::RequestModifiers {
                    peer_id: *assigned_peer,
                    type_id,
                    ids: chunk.clone(),
                });
            }

            result_actions
        }
        EligiblePeers::SinglePeerFallback(fallback_peer, reason) => {
            if tracker.outstanding_header_count(fallback_peer) >= PER_PEER_OUTSTANDING_CAP {
                tracing::warn!(
                    batch_id,
                    peer = fallback_peer,
                    reason,
                    "cap_backpressure_single_peer: fallback peer at outstanding cap"
                );
                return HandleResult::empty();
            }

            tracing::warn!(
                batch_id,
                peer = fallback_peer,
                reason,
                to_request_len = to_request.len(),
                "single_peer_fallback: partitioning skipped"
            );

            metrics.record_partition(
                batch_id,
                total_inv_ids,
                to_request.len(),
                &[(fallback_peer, to_request.len())],
            );

            for id in &to_request {
                if stale_ids.contains(id) {
                    tracker.reassign(type_id, id, fallback_peer);
                } else {
                    tracker.set_requested(type_id, *id, fallback_peer);
                }
            }

            metrics.record_requests_sent(
                batch_id,
                fallback_peer,
                to_request.len(),
                0,
                to_request.len().saturating_sub(1),
            );

            vec![SyncAction::RequestModifiers {
                peer_id: fallback_peer,
                type_id,
                ids: to_request,
            }]
        }
    };

    HandleResult {
        actions,
        new_headers: Vec::new(),
        penalties: Vec::new(),
        applied_blocks: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Modifiers (code 33)
// ---------------------------------------------------------------------------

/// Store received modifiers, notify the sync manager, and enqueue any
/// block body downloads triggered by new headers.
///
/// Transaction modifiers (type_id 2) are routed to [`handle_tx_modifiers`]
/// instead of being stored in the history DB.
#[allow(clippy::too_many_arguments)]
fn handle_modifiers(
    peer_id: PeerId,
    body: &[u8],
    node_view: &mut NodeViewHolder,
    sync_mgr: &mut SyncManager,
    tracker: &mut DeliveryTracker,
    cache: &mut crate::modifiers_cache::ModifiersCache,
    is_synced_for_txs: bool,
    tx_cost_tracker: &mut TxCostTracker,
    max_headers: u32,
) -> HandleResult {
    let mods = match ModifiersData::parse(body) {
        Ok(m) => m,
        Err(_) => return HandleResult::empty(),
    };

    let type_id = mods.type_id as u8;

    if type_id == 2 {
        if !is_synced_for_txs {
            return HandleResult::empty();
        }
        return handle_tx_modifiers(
            peer_id,
            &mods.modifiers,
            node_view,
            tracker,
            tx_cost_tracker,
        );
    }
    let mut new_headers = Vec::new();
    let mut blocks_to_download = Vec::new();
    let mut penalties = Vec::new();

    if type_id == HEADER_TYPE_ID {
        // ----- Header path: parallel PoW validation via rayon -----

        // Phase 1 — Sequential filter: skip invalid/already-received headers.
        let mut has_invalid = false;
        let accepted: Vec<(usize, &ModifierId, &Vec<u8>)> = mods
            .modifiers
            .iter()
            .enumerate()
            .filter(|(_idx, (id, _data))| {
                let mod_status = tracker.status(type_id, id);
                if mod_status == ModifierStatus::Invalid {
                    has_invalid = true;
                    false
                } else {
                    mod_status != ModifierStatus::Received
                }
            })
            .map(|(idx, (id, data))| (idx, id, data))
            .collect();
        if has_invalid {
            penalties.push((PenaltyType::SpamMessage, peer_id));
        }

        // Phase 2 — Parallel: verify ID, parse, and validate PoW.
        let validated: Vec<HeaderValidationResult> = accepted
            .par_iter()
            .map(|&(idx, id, data)| {
                let actual_id = ModifierId(blake2b256(data));
                if actual_id != *id {
                    return Err((
                        *id,
                        format!(
                            "ID mismatch: declared {} actual {}",
                            hex::encode(id.0),
                            hex::encode(actual_id.0),
                        ),
                    ));
                }
                let header =
                    wire_parse_header(data).map_err(|e| (*id, format!("parse failed: {e}")))?;
                validate_pow(&header).map_err(|e| (*id, format!("PoW invalid: {e}")))?;
                Ok((idx, *id, header))
            })
            .collect();

        // Phase 3 — Sequential: apply pre-validated headers.
        for result in validated {
            match result {
                Ok((idx, id, header)) => {
                    tracker.set_received(type_id, &id);
                    sync_mgr.on_section_received(type_id, &id, tracker);

                    match node_view.process_prevalidated_header(&id, &header) {
                        Ok(info) => {
                            new_headers.push(id);
                            for (_section_type, header_id) in &info.to_download {
                                if !blocks_to_download.contains(header_id) {
                                    blocks_to_download.push(*header_id);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::trace!(modifier_id = ?id, error = %e, "caching header for retry");
                            cache.put(id, HEADER_TYPE_ID, accepted[idx].2.clone(), None);
                        }
                    }
                }
                Err((id, reason)) => {
                    tracing::warn!(
                        modifier_id = hex::encode(id.0),
                        reason = %reason,
                        "header rejected during parallel validation"
                    );
                    penalties.push((PenaltyType::InvalidBlock, peer_id));
                    tracker.set_invalid(&id);
                }
            }
        }
    } else {
        // ----- Non-header path: sequential processing -----
        for (id, data) in &mods.modifiers {
            let mod_status = tracker.status(type_id, id);
            if mod_status == ModifierStatus::Invalid {
                penalties.push((PenaltyType::SpamMessage, peer_id));
                continue;
            }
            if mod_status == ModifierStatus::Received {
                continue;
            }

            match node_view.process_modifier(type_id, id, data) {
                Ok(info) => {
                    tracker.set_received(type_id, id);
                    sync_mgr.on_section_received(type_id, id, tracker);

                    for (_section_type, header_id) in &info.to_download {
                        if !blocks_to_download.contains(header_id) {
                            blocks_to_download.push(*header_id);
                        }
                    }
                }
                Err(e) => {
                    tracing::trace!(modifier_id = ?id, error = %e, "caching modifier for retry");
                    cache.put(*id, type_id, data.clone(), None);
                }
            }
        }
    }

    apply_from_cache(
        cache,
        node_view,
        sync_mgr,
        tracker,
        &mut new_headers,
        &mut blocks_to_download,
    );

    if !new_headers.is_empty() {
        let best_height = node_view
            .history
            .best_header_id()
            .ok()
            .flatten()
            .and_then(|id| node_view.history.load_header(&id).ok().flatten())
            .map(|h| h.height)
            .unwrap_or(0);
        tracing::info!(
            new = new_headers.len(),
            headers_height = best_height,
            "received headers"
        );
        sync_mgr.on_headers_received(&new_headers, &node_view.history);
    }
    if !blocks_to_download.is_empty() {
        sync_mgr.enqueue_block_downloads(blocks_to_download);
    }

    let applied_blocks = node_view.take_applied_blocks();
    if !applied_blocks.is_empty() {
        let best_full = node_view.history.best_full_block_height().unwrap_or(0);
        tracing::info!(
            new = applied_blocks.len(),
            full_height = best_full,
            "applied blocks"
        );
    }

    // Sync-after-headers fast path: when we receive headers from a peer,
    // immediately send them our updated SyncInfoV2. This creates a tight
    // request/response loop for fast header chain synchronization instead
    // of waiting for the next periodic sync tick.
    let mut actions = Vec::new();
    if !new_headers.is_empty() {
        if let Ok(ErgoSyncInfo::V2(v2)) =
            persistent_sync::build_sync_info_persistent(&node_view.history, max_headers)
        {
            actions.push(SyncAction::SendSyncInfo {
                peer_id: Some(peer_id),
                data: v2.serialize(),
            });
        }
    }

    HandleResult {
        actions,
        new_headers,
        penalties,
        applied_blocks,
    }
}

/// Try to apply cached modifiers to the node view.
fn apply_from_cache(
    cache: &mut crate::modifiers_cache::ModifiersCache,
    node_view: &mut NodeViewHolder,
    sync_mgr: &mut SyncManager,
    tracker: &mut DeliveryTracker,
    new_headers: &mut Vec<ModifierId>,
    blocks_to_download: &mut Vec<ModifierId>,
) {
    let max_iterations = 64;
    let mut applied_any = true;
    let mut iterations = 0;
    let mut total_applied = 0u32;

    while applied_any && iterations < max_iterations {
        if cache.is_empty() {
            break;
        }
        applied_any = false;
        iterations += 1;

        // Drain all headers from cache and try to apply them.
        let headers = cache.drain_all_headers();
        for (id, type_id, data) in headers {
            match node_view.process_modifier(type_id, &id, &data) {
                Ok(info) => {
                    applied_any = true;
                    total_applied += 1;
                    sync_mgr.on_section_received(type_id, &id, tracker);
                    new_headers.push(id);
                    for (_section_type, header_id) in &info.to_download {
                        if !blocks_to_download.contains(header_id) {
                            blocks_to_download.push(*header_id);
                        }
                    }
                }
                Err(_) => {
                    cache.put(id, type_id, data, None);
                }
            }
        }

        // Drain body sections and try to apply them.
        let body_sections = cache.drain_all_body_sections();
        for (id, type_id, data) in body_sections {
            match node_view.process_modifier(type_id, &id, &data) {
                Ok(info) => {
                    applied_any = true;
                    total_applied += 1;
                    for (_section_type, header_id) in &info.to_download {
                        if !blocks_to_download.contains(header_id) {
                            blocks_to_download.push(*header_id);
                        }
                    }
                }
                Err(_) => {
                    cache.put(id, type_id, data, None);
                }
            }
        }
    }

    if total_applied > 0 {
        tracing::debug!(
            iterations,
            applied = total_applied,
            "apply_from_cache completed"
        );
    }
}

// ---------------------------------------------------------------------------
// Transaction modifiers (type_id 2)
// ---------------------------------------------------------------------------

/// Handle received transaction modifiers: parse, validate stateless, add to mempool.
///
/// Transactions that pass validation are added to the mempool and a
/// [`SyncAction::BroadcastInvExcept`] is returned to relay the inventory
/// announcement to all peers except the sender.
///
/// Rate-limits transaction processing using the [`TxCostTracker`]:
/// if either the global or per-peer cost limit is exceeded, remaining
/// transactions in the batch are skipped.
fn handle_tx_modifiers(
    peer_id: PeerId,
    modifiers: &[(ModifierId, Vec<u8>)],
    node_view: &mut NodeViewHolder,
    tracker: &mut DeliveryTracker,
    tx_cost_tracker: &mut TxCostTracker,
) -> HandleResult {
    use ergo_consensus::tx_validation::validate_tx_stateless;
    use ergo_wire::transaction_ser::parse_transaction;

    let vs = node_view.validation_settings().clone();
    let mut accepted_ids = Vec::new();

    for (id, data) in modifiers {
        tracker.set_received(2, id);

        // Check rate limits before processing this transaction.
        if !tx_cost_tracker.can_accept(peer_id) {
            tracing::debug!(
                tx_id = ?id,
                peer_id,
                global_cost = tx_cost_tracker.interblock_cost,
                "tx rate-limited: cost limit exceeded"
            );
            continue;
        }

        let tx = match parse_transaction(data) {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!(tx_id = ?id, error = %e, "failed to parse transaction");
                tx_cost_tracker.record_cost(peer_id, FALLBACK_TX_COST);
                continue;
            }
        };

        if let Err(e) = validate_tx_stateless(&tx, &vs) {
            tracing::warn!(tx_id = ?id, error = %e, "stateless tx validation failed");
            tx_cost_tracker.record_cost(peer_id, FALLBACK_TX_COST);
            continue;
        }

        // Sigma proof verification (UTXO mode only; skipped in digest mode).
        if let Err(e) = node_view.try_sigma_verify_mempool_tx(&tx) {
            tracing::warn!(tx_id = ?id, error = %e, "mempool sigma verification failed");
            tx_cost_tracker.record_cost(peer_id, FALLBACK_TX_COST);
            continue;
        }

        let mut mp = node_view.mempool.write().unwrap();
        if let Err(e) = mp.put(tx) {
            tracing::debug!(tx_id = ?id, error = %e, "mempool rejected tx");
            tx_cost_tracker.record_cost(peer_id, FALLBACK_TX_COST);
            continue;
        }

        // Record cost for accepted transaction.
        tx_cost_tracker.record_cost(peer_id, FALLBACK_TX_COST);
        accepted_ids.push(*id);
    }

    let mut actions = Vec::new();
    if !accepted_ids.is_empty() {
        actions.push(SyncAction::BroadcastInvExcept {
            type_id: 2,
            ids: accepted_ids,
            exclude: peer_id,
        });
    }

    HandleResult {
        actions,
        new_headers: Vec::new(),
        penalties: Vec::new(),
        applied_blocks: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// RequestModifier (code 22)
// ---------------------------------------------------------------------------

/// Maximum total response size to avoid oversized messages (2 MB Scala limit).
const MAX_MODIFIERS_RESPONSE_SIZE: usize = 2 * 1024 * 1024;

/// Look up requested modifiers in the database and respond with those we have.
///
/// For transaction requests (type_id 2), the mempool is checked first since
/// unconfirmed transactions live in memory rather than the history database.
fn handle_request_modifier(
    peer_id: PeerId,
    body: &[u8],
    history: &HistoryDb,
    mempool: &crate::mempool::ErgoMemPool,
) -> HandleResult {
    let inv = match InvData::parse(body) {
        Ok(inv) => inv,
        Err(_) => return HandleResult::empty(),
    };

    let type_id = inv.type_id as u8;
    let mut found: Vec<(ModifierId, Vec<u8>)> = Vec::new();
    let mut total_size: usize = 0;

    for id in &inv.ids {
        let data_opt = if type_id == 2 {
            // Transaction: look up in mempool first, then history.
            let tx_id = ergo_types::transaction::TxId(id.0);
            if let Some(tx) = mempool.get(&tx_id) {
                Some(ergo_wire::transaction_ser::serialize_transaction(tx))
            } else {
                history.get_modifier(type_id, id).ok().flatten()
            }
        } else if type_id == HEADER_TYPE_ID {
            // Headers are stored by header_id — direct lookup.
            history.get_modifier(type_id, id).ok().flatten()
        } else {
            // Body sections: peer requests by computed section_id.
            // Our DB stores by header_id, so use the reverse mapping.
            if let Ok(Some(header_id)) = history.lookup_header_for_section(type_id, id) {
                history.get_modifier(type_id, &header_id).ok().flatten()
            } else {
                None
            }
        };

        if let Some(data) = data_opt {
            // 32 bytes for the modifier ID + up to 5 bytes for VLQ length + payload.
            total_size += 32 + 5 + data.len();
            if total_size > MAX_MODIFIERS_RESPONSE_SIZE {
                break;
            }
            found.push((*id, data));
        }
    }

    if found.is_empty() {
        return HandleResult::empty();
    }

    let response = ModifiersData {
        type_id: inv.type_id,
        modifiers: found,
    };
    let data = response.serialize();

    HandleResult {
        actions: vec![SyncAction::SendModifiers { peer_id, data }],
        new_headers: Vec::new(),
        penalties: Vec::new(),
        applied_blocks: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Refactored message handling for processor-thread architecture
// ---------------------------------------------------------------------------

/// Handle an incoming message from a peer, routing all codes except 33
/// (Modifiers) which the event loop handles separately.
///
/// This is the "event loop" entry point: it handles SyncInfo, Inv, GetPeers,
/// Peers, and RequestModifier using only a read-only `HistoryDb` and a shared
/// mempool Arc. Modifier messages (code 33) are not handled here; the event
/// loop dispatches those directly to the processor thread via channels.
#[allow(clippy::too_many_arguments)]
pub fn handle_message_without_modifiers(
    peer_id: PeerId,
    msg: &RawMessage,
    history: &HistoryDb,
    mempool: &std::sync::Arc<std::sync::RwLock<crate::mempool::ErgoMemPool>>,
    _sync_mgr: &mut SyncManager,
    tracker: &mut DeliveryTracker,
    connected_peers: &[std::net::SocketAddr],
    sync_tracker: &mut SyncTracker,
    last_sync_from: &mut HashMap<PeerId, Instant>,
    is_synced_for_txs: bool,
    last_sync_header_applied: &mut Option<u32>,
    _tx_cost_tracker: &mut TxCostTracker,
    max_headers: u32,
    connected_peer_ids: &[PeerId],
    metrics: &mut SyncMetrics,
    force_single_peer: bool,
) -> HandleResult {
    match msg.code {
        1 => handle_get_peers(peer_id, connected_peers),
        2 => handle_peers(&msg.body),
        65 => {
            const PER_PEER_SYNC_LOCK_MS: u128 = 100;
            let now = Instant::now();
            if let Some(last) = last_sync_from.get(&peer_id) {
                if now.duration_since(*last).as_millis() < PER_PEER_SYNC_LOCK_MS {
                    return HandleResult::empty();
                }
            }
            last_sync_from.insert(peer_id, now);
            handle_sync_info(
                peer_id,
                &msg.body,
                history,
                sync_tracker,
                tracker,
                last_sync_header_applied,
                max_headers,
            )
        }
        55 => {
            let mp = mempool.read().unwrap();
            handle_inv(
                peer_id,
                &msg.body,
                tracker,
                history,
                &mp,
                is_synced_for_txs,
                sync_tracker,
                connected_peer_ids,
                metrics,
                force_single_peer,
            )
        }
        22 => {
            let mp = mempool.read().unwrap();
            handle_request_modifier(peer_id, &msg.body, history, &mp)
        }
        33 => {
            // Modifiers are handled by the event loop directly (forwarded to processor).
            // If this function is called with code 33, return empty.
            HandleResult::empty()
        }
        _ => HandleResult::empty(),
    }
}

/// Handle transaction modifiers using a shared mempool reference instead of
/// going through `NodeViewHolder`.
///
/// This is used by the refactored event loop to process tx modifiers (type_id 2)
/// without needing `NodeViewHolder` on the event loop.
pub fn handle_tx_modifiers_shared(
    peer_id: PeerId,
    modifiers: &[(ModifierId, Vec<u8>)],
    mempool: &std::sync::Arc<std::sync::RwLock<crate::mempool::ErgoMemPool>>,
    tracker: &mut DeliveryTracker,
    tx_cost_tracker: &mut TxCostTracker,
) -> HandleResult {
    use ergo_consensus::tx_validation::validate_tx_stateless;
    use ergo_wire::transaction_ser::parse_transaction;

    let vs = ergo_consensus::validation_rules::ValidationSettings::initial();
    let mut accepted_ids = Vec::new();

    for (id, data) in modifiers {
        tracker.set_received(2, id);

        if !tx_cost_tracker.can_accept(peer_id) {
            tracing::debug!(
                tx_id = ?id,
                peer_id,
                global_cost = tx_cost_tracker.interblock_cost,
                "tx rate-limited: cost limit exceeded"
            );
            continue;
        }

        let tx = match parse_transaction(data) {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!(tx_id = ?id, error = %e, "failed to parse transaction");
                tx_cost_tracker.record_cost(peer_id, FALLBACK_TX_COST);
                continue;
            }
        };

        if let Err(e) = validate_tx_stateless(&tx, &vs) {
            tracing::warn!(tx_id = ?id, error = %e, "stateless tx validation failed");
            tx_cost_tracker.record_cost(peer_id, FALLBACK_TX_COST);
            continue;
        }

        // Sigma proof verification skipped in this path (no UTXO access on event loop).

        let mut mp = mempool.write().unwrap();
        if let Err(e) = mp.put(tx) {
            tracing::debug!(tx_id = ?id, error = %e, "mempool rejected tx");
            tx_cost_tracker.record_cost(peer_id, FALLBACK_TX_COST);
            continue;
        }

        tx_cost_tracker.record_cost(peer_id, FALLBACK_TX_COST);
        accepted_ids.push(*id);
    }

    let mut actions = Vec::new();
    if !accepted_ids.is_empty() {
        actions.push(SyncAction::BroadcastInvExcept {
            type_id: 2,
            ids: accepted_ids,
            exclude: peer_id,
        });
    }

    HandleResult {
        actions,
        new_headers: Vec::new(),
        penalties: Vec::new(),
        applied_blocks: Vec::new(),
    }
}

/// Validate header modifiers in parallel using rayon and return the results.
///
/// Returns a tuple of:
/// - `validated_headers`: Successfully validated headers with their modifier IDs and
///   serialized bytes (for forwarding to the processor).
/// - `penalties`: Penalties to apply for invalid/spam headers.
/// - `invalid_ids`: Modifier IDs that failed validation.
///
/// Headers are filtered to only include those with `Requested` status in the tracker.
/// The event loop can then forward validated headers to the processor thread.
#[allow(clippy::type_complexity)]
pub fn validate_headers_parallel(
    peer_id: PeerId,
    mods: &ModifiersData,
    tracker: &mut DeliveryTracker,
) -> (
    Vec<(ModifierId, ergo_types::header::Header, Vec<u8>)>,
    Vec<(PenaltyType, PeerId)>,
    Vec<ModifierId>,
) {
    let type_id = HEADER_TYPE_ID;
    let mut penalties = Vec::new();
    let mut invalid_ids = Vec::new();

    // Phase 1 -- Sequential filter: skip only previously-invalid headers.
    // Matching Scala: unrequested modifiers are processed normally (peers may
    // send extra headers from sync continuation). Only penalise for modifiers
    // we already validated and rejected.
    let mut has_invalid = false;
    let accepted: Vec<(usize, &ModifierId, &Vec<u8>)> = mods
        .modifiers
        .iter()
        .enumerate()
        .filter(|(_idx, (id, _data))| {
            let mod_status = tracker.status(type_id, id);
            if mod_status == ModifierStatus::Invalid {
                tracing::debug!(
                    modifier_id = hex::encode(id.0),
                    "skipping previously-invalid header"
                );
                has_invalid = true;
                false
            } else {
                mod_status != ModifierStatus::Received
            }
        })
        .map(|(idx, (id, data))| (idx, id, data))
        .collect();
    if has_invalid {
        penalties.push((PenaltyType::SpamMessage, peer_id));
    }

    // Phase 2 -- Parallel: verify ID, parse, and validate PoW.
    let validated: Vec<HeaderValidationResult> = accepted
        .par_iter()
        .map(|&(_idx, id, data)| {
            let actual_id = ModifierId(blake2b256(data));
            if actual_id != *id {
                return Err((
                    *id,
                    format!(
                        "ID mismatch: declared {} actual {}",
                        hex::encode(id.0),
                        hex::encode(actual_id.0),
                    ),
                ));
            }
            let header =
                wire_parse_header(data).map_err(|e| (*id, format!("parse failed: {e}")))?;
            validate_pow(&header).map_err(|e| (*id, format!("PoW invalid: {e}")))?;
            Ok((0, *id, header)) // index not needed in this path
        })
        .collect();

    // Phase 3 -- Collect results.
    let mut validated_headers = Vec::new();
    for (result, &(_idx, _id, data)) in validated.into_iter().zip(accepted.iter()) {
        match result {
            Ok((_idx2, mid, header)) => {
                tracker.set_received(type_id, &mid);
                validated_headers.push((mid, header, data.clone()));
            }
            Err((mid, reason)) => {
                tracing::warn!(
                    modifier_id = hex::encode(mid.0),
                    reason = %reason,
                    "header rejected during parallel validation"
                );
                penalties.push((PenaltyType::InvalidBlock, peer_id));
                tracker.set_invalid(&mid);
                invalid_ids.push(mid);
            }
        }
    }

    (validated_headers, penalties, invalid_ids)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modifiers_cache::ModifiersCache;
    use crate::sync_tracker::PeerChainStatus;
    use ergo_wire::inv::InvData;

    fn make_id(byte: u8) -> ModifierId {
        ModifierId([byte; 32])
    }

    fn open_test_node_view() -> (NodeViewHolder, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mempool = std::sync::Arc::new(std::sync::RwLock::new(
            crate::mempool::ErgoMemPool::with_min_fee(100, 0),
        ));
        let node_view = NodeViewHolder::new(history, mempool, true, vec![0u8; 33]);
        (node_view, dir)
    }

    #[test]
    fn handle_unknown_code_returns_empty() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let msg = RawMessage {
            code: 99,
            body: vec![],
        };
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        assert!(result.actions.is_empty());
        assert!(result.new_headers.is_empty());
    }

    #[test]
    fn handle_inv_requests_unknown() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let inv = InvData {
            type_id: 101,
            ids: vec![make_id(1), make_id(2)],
        };
        let msg = RawMessage {
            code: 55,
            body: inv.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        assert_eq!(result.actions.len(), 1);
        match &result.actions[0] {
            SyncAction::RequestModifiers {
                peer_id,
                type_id,
                ids,
            } => {
                assert_eq!(*peer_id, 1);
                assert_eq!(*type_id, 101);
                assert_eq!(ids.len(), 2);
            }
            _ => panic!("expected RequestModifiers"),
        }
    }

    #[test]
    fn handle_inv_filters_known_modifiers() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();

        let known_id = make_id(1);
        history.put_modifier(101, &known_id, &[0u8; 10]).unwrap();

        let mempool = std::sync::Arc::new(std::sync::RwLock::new(
            crate::mempool::ErgoMemPool::with_min_fee(100, 0),
        ));
        let mut node_view = NodeViewHolder::new(history, mempool, true, vec![0u8; 33]);
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let inv = InvData {
            type_id: 101,
            ids: vec![known_id, make_id(2)],
        };
        let msg = RawMessage {
            code: 55,
            body: inv.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        assert_eq!(result.actions.len(), 1);
        match &result.actions[0] {
            SyncAction::RequestModifiers { ids, .. } => {
                assert_eq!(ids.len(), 1);
                assert_eq!(ids[0], make_id(2));
            }
            _ => panic!("expected RequestModifiers"),
        }
    }

    #[test]
    fn handle_sync_info_responds() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let sync_info = ergo_wire::sync_info::ErgoSyncInfoV2 {
            last_headers: vec![],
        };
        let msg = RawMessage {
            code: 65,
            body: sync_info.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        assert!(!result.actions.is_empty());
        assert!(matches!(
            &result.actions[0],
            SyncAction::SendSyncInfo { .. }
        ));
    }

    #[test]
    fn handle_modifiers_stores_sections() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        // Body section data: first 32 bytes = header_id, rest = payload.
        let header_id = ModifierId([0xAA; 32]);
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&header_id.0);
        data.extend_from_slice(&[0u8; 20]); // payload
        let section_id = ModifierId(blake2b256(&data));
        // Mark as requested so spam detection allows processing.
        tracker.set_requested(108, section_id, 1);

        let mods = ModifiersData {
            type_id: 108,
            modifiers: vec![(section_id, data)],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Stored under header_id (extracted from data[0..32]), not section_id.
        assert!(node_view
            .history
            .contains_modifier(108, &header_id)
            .unwrap());
        assert!(result.new_headers.is_empty());
        assert!(result.penalties.is_empty());
    }

    #[test]
    fn handle_modifiers_does_not_panic_on_unknown_section() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let data = vec![1, 2, 3];
        let id = ModifierId(blake2b256(&data));
        // Mark as requested so spam detection allows processing.
        tracker.set_requested(108, id, 1);

        let mods = ModifiersData {
            type_id: 108,
            modifiers: vec![(id, data)],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let _result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        // If we get here without panicking, the flow is correct.
    }

    #[test]
    fn handle_result_default_no_penalties() {
        let result = HandleResult::empty();
        assert!(result.penalties.is_empty());
    }

    #[test]
    fn handle_result_with_penalties() {
        use crate::penalty_manager::PenaltyType;
        let result = HandleResult {
            actions: Vec::new(),
            new_headers: Vec::new(),
            penalties: vec![(PenaltyType::InvalidBlock, 42)],
            applied_blocks: Vec::new(),
        };
        assert_eq!(result.penalties.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Peers (code 2)
    // -----------------------------------------------------------------------

    #[test]
    fn handle_peers_extracts_addresses() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        use ergo_wire::peer_spec::{serialize_peers, PeerAddr};
        let peers = vec![
            PeerAddr {
                address: "10.0.0.1:9030".parse().unwrap(),
            },
            PeerAddr {
                address: "10.0.0.2:9031".parse().unwrap(),
            },
        ];
        let body = serialize_peers(&peers);

        let msg = RawMessage { code: 2, body };
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        assert_eq!(result.actions.len(), 1);
        match &result.actions[0] {
            SyncAction::AddPeers { addresses } => {
                assert_eq!(addresses.len(), 2);
            }
            _ => panic!("expected AddPeers"),
        }
    }

    #[test]
    fn handle_peers_empty_returns_empty() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let body = ergo_wire::peer_spec::serialize_peers(&[]);
        let msg = RawMessage { code: 2, body };
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(result.actions.is_empty());
    }

    #[test]
    fn handle_peers_malformed_returns_empty() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let msg = RawMessage {
            code: 2,
            body: vec![0xFF, 0xFF],
        };
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(result.actions.is_empty());
    }

    // -----------------------------------------------------------------------
    // GetPeers (code 1)
    // -----------------------------------------------------------------------

    #[test]
    fn handle_get_peers_responds_with_peers() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let connected: Vec<std::net::SocketAddr> = vec![
            "10.0.0.1:9030".parse().unwrap(),
            "10.0.0.2:9030".parse().unwrap(),
        ];

        let msg = RawMessage {
            code: 1,
            body: vec![],
        };
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &connected,
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        assert_eq!(result.actions.len(), 1);
        match &result.actions[0] {
            SyncAction::SendPeers { peer_id, data } => {
                assert_eq!(*peer_id, 1);
                let parsed = ergo_wire::peer_spec::parse_peers(data).unwrap();
                assert_eq!(parsed.len(), 2);
            }
            _ => panic!("expected SendPeers"),
        }
    }

    #[test]
    fn handle_get_peers_empty_pool() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let msg = RawMessage {
            code: 1,
            body: vec![],
        };
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        assert_eq!(result.actions.len(), 1);
        match &result.actions[0] {
            SyncAction::SendPeers { data, .. } => {
                let parsed = ergo_wire::peer_spec::parse_peers(data).unwrap();
                assert!(parsed.is_empty());
            }
            _ => panic!("expected SendPeers"),
        }
    }

    // -----------------------------------------------------------------------
    // RequestModifier (code 22)
    // -----------------------------------------------------------------------

    #[test]
    fn handle_request_modifier_serves_known() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();

        let header_id = make_id(1);
        let section_id = make_id(0xF1); // wire section_id (differs from header_id)
        let unknown_section_id = make_id(2);
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];

        // Store body section under header_id and add section_id mapping.
        history.put_modifier(108, &header_id, &payload).unwrap();
        history
            .store_section_mapping(108, &section_id, &header_id)
            .unwrap();

        let mempool = std::sync::Arc::new(std::sync::RwLock::new(
            crate::mempool::ErgoMemPool::with_min_fee(100, 0),
        ));
        let mut node_view = NodeViewHolder::new(history, mempool, true, vec![0u8; 33]);
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        // Peer requests by section_id (the wire format).
        let inv = InvData {
            type_id: 108,
            ids: vec![section_id, unknown_section_id],
        };
        let msg = RawMessage {
            code: 22,
            body: inv.serialize(),
        };
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        assert_eq!(result.actions.len(), 1);
        match &result.actions[0] {
            SyncAction::SendModifiers { peer_id, data } => {
                assert_eq!(*peer_id, 1);
                let mods = ModifiersData::parse(data).unwrap();
                assert_eq!(mods.type_id, 108);
                assert_eq!(mods.modifiers.len(), 1);
                // Response uses the section_id requested by the peer.
                assert_eq!(mods.modifiers[0].0, section_id);
                assert_eq!(mods.modifiers[0].1, payload);
            }
            _ => panic!("expected SendModifiers"),
        }
    }

    #[test]
    fn handle_request_modifier_none_found() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let inv = InvData {
            type_id: 101,
            ids: vec![make_id(99)],
        };
        let msg = RawMessage {
            code: 22,
            body: inv.serialize(),
        };
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        assert!(result.actions.is_empty());
    }

    #[test]
    fn handle_request_modifier_malformed() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let msg = RawMessage {
            code: 22,
            body: vec![0xFF],
        };
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(result.actions.is_empty());
    }

    // -----------------------------------------------------------------------
    // Inv tx filtering via mempool
    // -----------------------------------------------------------------------

    #[test]
    fn handle_inv_tx_filters_by_mempool() {
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
        let mempool = std::sync::Arc::new(std::sync::RwLock::new(
            crate::mempool::ErgoMemPool::with_min_fee(100, 0),
        ));

        // Put a tx in the mempool with tx_id = make_id(1).
        {
            let mut mp = mempool.write().unwrap();
            let tx = ergo_types::transaction::ErgoTransaction {
                inputs: vec![ergo_types::transaction::Input {
                    box_id: ergo_types::transaction::BoxId([0xAA; 32]),
                    proof_bytes: vec![],
                    extension_bytes: vec![],
                }],
                data_inputs: vec![],
                output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
                    value: 1_000_000,
                    ergo_tree_bytes: vec![0x00],
                    creation_height: 1,
                    tokens: vec![],
                    additional_registers: vec![],
                }],
                tx_id: ergo_types::transaction::TxId(make_id(1).0),
            };
            mp.put(tx).unwrap();
        }

        let mut node_view = NodeViewHolder::new(history, mempool, true, vec![0u8; 33]);
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        // Inv with type_id 2 (tx): id(1) known in mempool, id(2) unknown.
        let inv = InvData {
            type_id: 2,
            ids: vec![make_id(1), make_id(2)],
        };
        let msg = RawMessage {
            code: 55,
            body: inv.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            true,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Should only request id(2), since id(1) is in the mempool.
        assert_eq!(result.actions.len(), 1);
        match &result.actions[0] {
            SyncAction::RequestModifiers { type_id, ids, .. } => {
                assert_eq!(*type_id, 2);
                assert_eq!(ids.len(), 1);
                assert_eq!(ids[0], make_id(2));
            }
            _ => panic!("expected RequestModifiers"),
        }
    }

    // -----------------------------------------------------------------------
    // Applied blocks in HandleResult
    // -----------------------------------------------------------------------

    #[test]
    fn handle_result_has_applied_blocks_field() {
        let result = HandleResult {
            actions: Vec::new(),
            new_headers: Vec::new(),
            penalties: Vec::new(),
            applied_blocks: vec![make_id(1), make_id(2)],
        };
        assert_eq!(result.applied_blocks.len(), 2);
    }

    #[test]
    fn handle_result_empty_has_no_applied_blocks() {
        let result = HandleResult::empty();
        assert!(result.applied_blocks.is_empty());
    }

    // -----------------------------------------------------------------------
    // Transaction modifier handling (type_id 2)
    // -----------------------------------------------------------------------

    #[test]
    fn handle_tx_modifier_adds_to_mempool() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let valid_tree = {
            let mut t = vec![0x08];
            ergo_wire::vlq::put_uint(&mut t, 35);
            t.push(0x08);
            t.push(0xCD);
            t.extend_from_slice(&[0x02; 33]);
            t
        };
        let tx = ergo_types::transaction::ErgoTransaction {
            inputs: vec![ergo_types::transaction::Input {
                box_id: ergo_types::transaction::BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![0x00],
            }],
            data_inputs: vec![],
            output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: valid_tree,
                creation_height: 100_000,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: ergo_types::transaction::TxId([0; 32]),
        };
        let tx_bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
        let real_id = ergo_wire::transaction_ser::compute_tx_id(&tx);

        let mods = ModifiersData {
            type_id: 2,
            modifiers: vec![(ergo_types::modifier_id::ModifierId(real_id.0), tx_bytes)],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            true,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Transaction should be in mempool.
        let mp = node_view.mempool.read().unwrap();
        assert!(mp.contains(&real_id));
        drop(mp);

        // Should broadcast tx inv to all except sender.
        assert!(result.actions.iter().any(|a| matches!(
            a,
            SyncAction::BroadcastInvExcept {
                type_id: 2,
                exclude: 1,
                ..
            }
        )));
    }

    #[test]
    fn handle_tx_modifier_rejects_invalid_tx() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        // Garbage bytes that cannot be parsed as a transaction.
        let mods = ModifiersData {
            type_id: 2,
            modifiers: vec![(make_id(1), vec![0xFF, 0xFF])],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            true,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Mempool should be empty.
        let mp = node_view.mempool.read().unwrap();
        assert_eq!(mp.size(), 0);
        drop(mp);

        // No BroadcastInvExcept actions.
        assert!(!result
            .actions
            .iter()
            .any(|a| matches!(a, SyncAction::BroadcastInvExcept { .. })));
    }

    // -----------------------------------------------------------------------
    // SyncTracker classification via SyncInfo
    // -----------------------------------------------------------------------

    #[test]
    fn handle_sync_info_classifies_peer() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);
        let mut sync_tracker = SyncTracker::new();

        let sync_info = ergo_wire::sync_info::ErgoSyncInfoV2 {
            last_headers: vec![],
        };
        let msg = RawMessage {
            code: 65,
            body: sync_info.serialize(),
        };

        let _result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut sync_tracker,
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Peer should now be tracked (with Equal status since both heights are 0).
        let status = sync_tracker.status(1);
        assert!(status.is_some());
    }

    // -----------------------------------------------------------------------
    // Per-peer sync rate limiting
    // -----------------------------------------------------------------------

    #[test]
    fn sync_rate_limited_within_100ms() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);
        let mut sync_tracker = SyncTracker::new();
        let mut cache = ModifiersCache::with_default_capacities();
        let mut last_sync_from = HashMap::new();

        let sync_info = ergo_wire::sync_info::ErgoSyncInfoV2 {
            last_headers: vec![],
        };
        let msg = RawMessage {
            code: 65,
            body: sync_info.serialize(),
        };

        // First call should process normally.
        let r1 = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut sync_tracker,
            &mut cache,
            &mut last_sync_from,
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(!r1.actions.is_empty());

        // Second call within 100ms should be rate-limited.
        let r2 = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut sync_tracker,
            &mut cache,
            &mut last_sync_from,
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(r2.actions.is_empty());
    }

    #[test]
    fn sync_different_peers_not_limited() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);
        let mut sync_tracker = SyncTracker::new();
        let mut cache = ModifiersCache::with_default_capacities();
        let mut last_sync_from = HashMap::new();

        let sync_info = ergo_wire::sync_info::ErgoSyncInfoV2 {
            last_headers: vec![],
        };
        let msg = RawMessage {
            code: 65,
            body: sync_info.serialize(),
        };

        let r1 = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut sync_tracker,
            &mut cache,
            &mut last_sync_from,
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(!r1.actions.is_empty());

        // Different peer should not be rate-limited.
        let r2 = handle_message(
            2,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut sync_tracker,
            &mut cache,
            &mut last_sync_from,
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(!r2.actions.is_empty());
    }

    // -----------------------------------------------------------------------
    // Modifier spam detection
    // -----------------------------------------------------------------------

    #[test]
    fn handle_modifiers_penalises_previously_invalid() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let ext_id = make_id(42);
        // Mark as invalid — previously failed validation.
        tracker.set_invalid(&ext_id);

        let mods = ModifiersData {
            type_id: 108,
            modifiers: vec![(ext_id, vec![0u8; 20])],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Should have a SpamMessage penalty for the invalid modifier.
        assert!(!result.penalties.is_empty());
        assert!(matches!(result.penalties[0].0, PenaltyType::SpamMessage));

        // Modifier should NOT be stored in the history DB.
        assert!(!node_view.history.contains_modifier(108, &ext_id).unwrap());
    }

    #[test]
    fn handle_modifiers_accepts_requested() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        // Body section: first 32 bytes = header_id, rest = payload.
        let header_id = ModifierId([0xCC; 32]);
        let mut data = Vec::with_capacity(52);
        data.extend_from_slice(&header_id.0);
        data.extend_from_slice(&[0u8; 20]);
        let section_id = ModifierId(blake2b256(&data));
        // Mark as requested first — this should pass spam detection.
        tracker.set_requested(108, section_id, 1);

        let mods = ModifiersData {
            type_id: 108,
            modifiers: vec![(section_id, data)],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // No penalties — modifier was requested.
        assert!(result.penalties.is_empty());

        // Stored under header_id (extracted from data[0..32]).
        assert!(node_view
            .history
            .contains_modifier(108, &header_id)
            .unwrap());

        // Tracker should now show Received status for the section_id.
        assert_eq!(
            tracker.status(108, &section_id),
            crate::delivery_tracker::ModifierStatus::Received
        );
    }

    // -----------------------------------------------------------------------
    // Modifier ID verification
    // -----------------------------------------------------------------------

    #[test]
    fn handle_modifiers_rejects_mismatched_header_id() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        // Use a fake ID that does NOT match blake2b256 of the data.
        // ID verification is only performed for headers (type 101).
        let fake_id = make_id(99);
        let data = vec![0u8; 20];
        // Sanity: the real hash of `data` differs from make_id(99).
        assert_ne!(ModifierId(blake2b256(&data)), fake_id);

        tracker.set_requested(HEADER_TYPE_ID, fake_id, 1);

        let mods = ModifiersData {
            type_id: HEADER_TYPE_ID as i8,
            modifiers: vec![(fake_id, data)],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Should have an InvalidBlock penalty for ID mismatch.
        assert!(!result.penalties.is_empty());
        assert!(matches!(result.penalties[0].0, PenaltyType::InvalidBlock));

        // Modifier should NOT be stored in the history DB.
        assert!(!node_view
            .history
            .contains_modifier(HEADER_TYPE_ID, &fake_id)
            .unwrap());

        // Tracker should show Invalid status.
        assert_eq!(
            tracker.status(HEADER_TYPE_ID, &fake_id),
            crate::delivery_tracker::ModifierStatus::Invalid
        );
    }

    #[test]
    fn handle_modifiers_accepts_matching_id() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        // Body section: first 32 bytes = header_id, rest = payload.
        let header_id = ModifierId([0xDD; 32]);
        let mut data = Vec::with_capacity(52);
        data.extend_from_slice(&header_id.0);
        data.extend_from_slice(&[0u8; 20]);
        let section_id = ModifierId(blake2b256(&data));
        tracker.set_requested(108, section_id, 1);

        let mods = ModifiersData {
            type_id: 108,
            modifiers: vec![(section_id, data)],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // No penalties — modifier accepted.
        assert!(result.penalties.is_empty());

        // Stored under header_id (extracted from data[0..32]).
        assert!(node_view
            .history
            .contains_modifier(108, &header_id)
            .unwrap());

        // Tracker should now show Received status for section_id.
        assert_eq!(
            tracker.status(108, &section_id),
            crate::delivery_tracker::ModifierStatus::Received
        );
    }

    // -----------------------------------------------------------------------
    // Transaction acceptance filter during sync
    // -----------------------------------------------------------------------

    #[test]
    fn handle_inv_filters_tx_during_sync() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let inv = InvData {
            type_id: 2,
            ids: vec![make_id(1)],
        };
        let msg = RawMessage {
            code: 55,
            body: inv.serialize(),
        };

        // is_synced_for_txs = false -> should filter tx inv
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(result.actions.is_empty());
    }

    #[test]
    fn handle_inv_accepts_tx_when_synced() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let inv = InvData {
            type_id: 2,
            ids: vec![make_id(1)],
        };
        let msg = RawMessage {
            code: 55,
            body: inv.serialize(),
        };

        // is_synced_for_txs = true -> should process normally
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            true,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(!result.actions.is_empty());
    }

    #[test]
    fn handle_inv_non_tx_unaffected_by_sync_state() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let inv = InvData {
            type_id: 101,
            ids: vec![make_id(1)],
        };
        let msg = RawMessage {
            code: 55,
            body: inv.serialize(),
        };

        // Even with is_synced_for_txs = false, non-tx inv should process
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );
        assert!(!result.actions.is_empty());
    }

    #[test]
    fn handle_modifiers_filters_tx_during_sync() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        let valid_tree = {
            let mut t = vec![0x08];
            ergo_wire::vlq::put_uint(&mut t, 35);
            t.push(0x08);
            t.push(0xCD);
            t.extend_from_slice(&[0x02; 33]);
            t
        };
        let tx = ergo_types::transaction::ErgoTransaction {
            inputs: vec![ergo_types::transaction::Input {
                box_id: ergo_types::transaction::BoxId([0xAA; 32]),
                proof_bytes: vec![],
                extension_bytes: vec![0x00],
            }],
            data_inputs: vec![],
            output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: valid_tree,
                creation_height: 100_000,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: ergo_types::transaction::TxId([0; 32]),
        };
        let tx_bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
        let real_id = ergo_wire::transaction_ser::compute_tx_id(&tx);

        let mods = ModifiersData {
            type_id: 2,
            modifiers: vec![(ergo_types::modifier_id::ModifierId(real_id.0), tx_bytes)],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        // is_synced_for_txs = false -> should filter tx modifiers
        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Mempool should be empty - tx was filtered before processing.
        let mp = node_view.mempool.read().unwrap();
        assert_eq!(mp.size(), 0);
        drop(mp);

        // No actions should be produced.
        assert!(result.actions.is_empty());
    }

    // -----------------------------------------------------------------------
    // Continuation header from SyncInfoV2
    // -----------------------------------------------------------------------

    #[test]
    fn continuation_header_extracted_when_parent_matches() {
        // Set up a node with a stored genesis header so we have a best_header_id.
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();

        // Create and store a "genesis" header using store_header which
        // sets height index and best_header_id.
        let mut genesis = ergo_types::header::Header::default_for_test();
        genesis.height = 1;
        genesis.parent_id = ModifierId::GENESIS_PARENT;
        let genesis_bytes = ergo_wire::header_ser::serialize_header(&genesis);
        let genesis_id = ModifierId(blake2b256(&genesis_bytes));

        history.store_header(&genesis_id, &genesis).unwrap();
        // Also store the raw bytes as modifier so the header can be loaded.
        history
            .put_modifier(101, &genesis_id, &genesis_bytes)
            .unwrap();

        let mempool = std::sync::Arc::new(std::sync::RwLock::new(
            crate::mempool::ErgoMemPool::with_min_fee(100, 0),
        ));
        let mut node_view = NodeViewHolder::new(history, mempool, true, vec![0u8; 33]);
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);
        let mut sync_tracker = SyncTracker::new();
        let mut cache = ModifiersCache::with_default_capacities();
        let mut last_sync_from = HashMap::new();
        let mut last_sync_header_applied: Option<u32> = None;

        // Create a continuation header whose parent_id == genesis_id.
        let mut continuation = ergo_types::header::Header::default_for_test();
        continuation.height = 2;
        continuation.parent_id = genesis_id;
        continuation.timestamp = 1_700_000_000_000;

        // Build SyncInfoV2 with the continuation header (newest-first ordering,
        // so the continuation header is first = most recent).
        let sync_info = ergo_wire::sync_info::ErgoSyncInfoV2 {
            last_headers: vec![continuation.clone()],
        };
        let msg = RawMessage {
            code: 65,
            body: sync_info.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut sync_tracker,
            &mut cache,
            &mut last_sync_from,
            false,
            &mut last_sync_header_applied,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Should have at least 2 actions: SendSyncInfo + ApplyContinuationHeader.
        let has_continuation = result
            .actions
            .iter()
            .any(|a| matches!(a, SyncAction::ApplyContinuationHeader { .. }));
        assert!(
            has_continuation,
            "expected ApplyContinuationHeader action, got: {:?}",
            result
                .actions
                .iter()
                .map(|a| std::mem::discriminant(a))
                .collect::<Vec<_>>()
        );

        // last_sync_header_applied should be updated.
        assert_eq!(last_sync_header_applied, Some(2));
    }

    #[test]
    fn continuation_header_not_extracted_when_parent_differs() {
        // Set up a node with a stored genesis header.
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();

        let mut genesis = ergo_types::header::Header::default_for_test();
        genesis.height = 1;
        genesis.parent_id = ModifierId::GENESIS_PARENT;
        let genesis_bytes = ergo_wire::header_ser::serialize_header(&genesis);
        let genesis_id = ModifierId(blake2b256(&genesis_bytes));

        history.store_header(&genesis_id, &genesis).unwrap();
        history
            .put_modifier(101, &genesis_id, &genesis_bytes)
            .unwrap();

        let mempool = std::sync::Arc::new(std::sync::RwLock::new(
            crate::mempool::ErgoMemPool::with_min_fee(100, 0),
        ));
        let mut node_view = NodeViewHolder::new(history, mempool, true, vec![0u8; 33]);
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);
        let mut sync_tracker = SyncTracker::new();
        let mut cache = ModifiersCache::with_default_capacities();
        let mut last_sync_from = HashMap::new();
        let mut last_sync_header_applied: Option<u32> = None;

        // Create a header whose parent_id does NOT match our best header.
        let mut unrelated = ergo_types::header::Header::default_for_test();
        unrelated.height = 2;
        unrelated.parent_id = ModifierId([0xBB; 32]); // random, not genesis_id
        unrelated.timestamp = 1_700_000_000_000;

        let sync_info = ergo_wire::sync_info::ErgoSyncInfoV2 {
            last_headers: vec![unrelated],
        };
        let msg = RawMessage {
            code: 65,
            body: sync_info.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut sync_tracker,
            &mut cache,
            &mut last_sync_from,
            false,
            &mut last_sync_header_applied,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Should NOT have an ApplyContinuationHeader action.
        let has_continuation = result
            .actions
            .iter()
            .any(|a| matches!(a, SyncAction::ApplyContinuationHeader { .. }));
        assert!(
            !has_continuation,
            "should NOT have ApplyContinuationHeader when parent_id differs"
        );

        // last_sync_header_applied should remain None.
        assert_eq!(last_sync_header_applied, None);
    }

    #[test]
    fn continuation_header_not_extracted_when_already_applied() {
        // Set up a node with a stored genesis header.
        let dir = tempfile::tempdir().unwrap();
        let history = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();

        let mut genesis = ergo_types::header::Header::default_for_test();
        genesis.height = 1;
        genesis.parent_id = ModifierId::GENESIS_PARENT;
        let genesis_bytes = ergo_wire::header_ser::serialize_header(&genesis);
        let genesis_id = ModifierId(blake2b256(&genesis_bytes));

        history.store_header(&genesis_id, &genesis).unwrap();
        history
            .put_modifier(101, &genesis_id, &genesis_bytes)
            .unwrap();

        let mempool = std::sync::Arc::new(std::sync::RwLock::new(
            crate::mempool::ErgoMemPool::with_min_fee(100, 0),
        ));
        let mut node_view = NodeViewHolder::new(history, mempool, true, vec![0u8; 33]);
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);
        let mut sync_tracker = SyncTracker::new();
        let mut cache = ModifiersCache::with_default_capacities();
        let mut last_sync_from = HashMap::new();
        // Pre-set to height 2 to simulate already applied.
        let mut last_sync_header_applied: Option<u32> = Some(2);

        let mut continuation = ergo_types::header::Header::default_for_test();
        continuation.height = 2;
        continuation.parent_id = genesis_id;
        continuation.timestamp = 1_700_000_000_000;

        let sync_info = ergo_wire::sync_info::ErgoSyncInfoV2 {
            last_headers: vec![continuation],
        };
        let msg = RawMessage {
            code: 65,
            body: sync_info.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut sync_tracker,
            &mut cache,
            &mut last_sync_from,
            false,
            &mut last_sync_header_applied,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // Should NOT have ApplyContinuationHeader because height == last_applied.
        let has_continuation = result
            .actions
            .iter()
            .any(|a| matches!(a, SyncAction::ApplyContinuationHeader { .. }));
        assert!(
            !has_continuation,
            "should NOT re-apply continuation header at already-applied height"
        );
    }

    // -----------------------------------------------------------------------
    // TxCostTracker unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn tx_cost_tracker_new_defaults() {
        let t = TxCostTracker::new();
        assert_eq!(t.interblock_cost, 0);
        assert_eq!(t.global_limit, DEFAULT_MEMPOOL_COST_PER_BLOCK);
        assert_eq!(t.peer_limit, DEFAULT_MEMPOOL_PEER_COST_PER_BLOCK);
        assert!(t.per_peer_cost.is_empty());
    }

    #[test]
    fn tx_cost_tracker_with_limits() {
        let t = TxCostTracker::with_limits(100, 50);
        assert_eq!(t.global_limit, 100);
        assert_eq!(t.peer_limit, 50);
    }

    #[test]
    fn tx_cost_tracker_can_accept_initially() {
        let t = TxCostTracker::new();
        assert!(t.can_accept(1));
        assert!(t.can_accept(42));
    }

    #[test]
    fn tx_cost_tracker_record_and_check() {
        let mut t = TxCostTracker::with_limits(5000, 3000);
        t.record_cost(1, 1000);
        assert_eq!(t.interblock_cost, 1000);
        assert_eq!(t.per_peer_cost[&1], 1000);
        assert!(t.can_accept(1));

        // Record more for peer 1 to reach peer limit.
        t.record_cost(1, 2000);
        assert_eq!(t.per_peer_cost[&1], 3000);
        assert!(!t.can_accept(1)); // peer limit reached

        // Peer 2 should still be accepted (global not reached yet).
        assert!(t.can_accept(2));
    }

    #[test]
    fn tx_cost_tracker_global_limit() {
        let mut t = TxCostTracker::with_limits(2000, 10_000);
        t.record_cost(1, 1000);
        t.record_cost(2, 1000);
        assert_eq!(t.interblock_cost, 2000);
        // Global limit reached — no peer can submit.
        assert!(!t.can_accept(1));
        assert!(!t.can_accept(2));
        assert!(!t.can_accept(3));
    }

    #[test]
    fn tx_cost_tracker_reset_clears_all() {
        let mut t = TxCostTracker::with_limits(5000, 3000);
        t.record_cost(1, 2000);
        t.record_cost(2, 1500);
        assert_eq!(t.interblock_cost, 3500);
        assert_eq!(t.per_peer_cost.len(), 2);

        t.reset();
        assert_eq!(t.interblock_cost, 0);
        assert!(t.per_peer_cost.is_empty());
        assert!(t.can_accept(1));
        assert!(t.can_accept(2));
    }

    #[test]
    fn tx_cost_tracker_saturating_add() {
        let mut t = TxCostTracker::with_limits(u64::MAX, u64::MAX);
        t.record_cost(1, u64::MAX);
        t.record_cost(1, 1);
        // Should saturate, not overflow.
        assert_eq!(t.interblock_cost, u64::MAX);
        assert_eq!(t.per_peer_cost[&1], u64::MAX);
    }

    #[test]
    fn tx_cost_tracker_multiple_peers_independent() {
        let mut t = TxCostTracker::with_limits(100_000, 5000);
        t.record_cost(1, 4000);
        t.record_cost(2, 2000);
        t.record_cost(3, 3000);

        assert!(t.can_accept(1)); // 4000 < 5000
        assert!(t.can_accept(2)); // 2000 < 5000
        assert!(t.can_accept(3)); // 3000 < 5000

        t.record_cost(1, 1000); // peer 1 now at 5000
        assert!(!t.can_accept(1)); // 5000 >= 5000
        assert!(t.can_accept(2)); // still OK
    }

    // -----------------------------------------------------------------------
    // Parallel header PoW validation
    // -----------------------------------------------------------------------

    #[test]
    fn parallel_pow_rejects_bad_header() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);

        // Create a header with zeroed PoW — parse will succeed but
        // validate_pow will fail.
        let header = ergo_types::header::Header::default_for_test();
        let data = ergo_wire::header_ser::serialize_header(&header);
        let id = ModifierId(blake2b256(&data));

        tracker.set_requested(HEADER_TYPE_ID, id, 1);

        let mods = ModifiersData {
            type_id: HEADER_TYPE_ID as i8,
            modifiers: vec![(id, data)],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut ModifiersCache::with_default_capacities(),
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // PoW failure should produce an InvalidBlock penalty.
        assert!(!result.penalties.is_empty());
        assert!(matches!(result.penalties[0].0, PenaltyType::InvalidBlock));

        // Header should NOT be stored.
        assert!(!node_view
            .history
            .contains_modifier(HEADER_TYPE_ID, &id)
            .unwrap());

        // Tracker should show Invalid status.
        assert_eq!(
            tracker.status(HEADER_TYPE_ID, &id),
            crate::delivery_tracker::ModifierStatus::Invalid
        );
    }

    /// Build the real mainnet header at height 500,001 (Autolykos v2).
    /// This header has valid PoW and serialization.
    fn mainnet_header_500001() -> ergo_types::header::Header {
        use ergo_types::header::AutolykosSolution;
        use ergo_types::modifier_id::{ADDigest, Digest32};

        fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
            let bytes = hex::decode(s).unwrap();
            let mut arr = [0u8; N];
            arr.copy_from_slice(&bytes);
            arr
        }

        ergo_types::header::Header {
            version: 2,
            parent_id: ModifierId(hex_to_array(
                "0261b8bbe791aa26379c679e22359d21a92bda09abd369b938946d0128eed660",
            )),
            ad_proofs_root: Digest32(hex_to_array(
                "c8e78371ef52ae0662e97026a982af6aecce782e85d568f2dfd59efee606267c",
            )),
            transactions_root: Digest32(hex_to_array(
                "aebd3c318e1b0de0e1bcf1f9201bd0e99b5cb1418e8f877baefe332bd3548160",
            )),
            state_root: ADDigest(hex_to_array(
                "93c0a548ec4ee8a3596e02455adab35dae331e7c7defcadfc95a46788a9cb97715",
            )),
            timestamp: 1_622_316_376_238,
            extension_root: Digest32(hex_to_array(
                "5b1b7be58974721b508c7f7796f5fc7fca9b241449961e564429902554be6fc8",
            )),
            n_bits: 117_919_008,
            height: 500_001,
            votes: [0, 0, 0],
            unparsed_bytes: Vec::new(),
            pow_solution: AutolykosSolution {
                miner_pk: hex_to_array(
                    "02b3a06d6eaa8671431ba1db4dd427a77f75a5c2acbd71bfb725d38adc2b55f669",
                ),
                w: [0u8; 33],
                nonce: hex_to_array("906d3e6e46ac9ede"),
                d: Vec::new(),
            },
        }
    }

    #[test]
    fn parallel_pow_caches_orphan_header() {
        let (mut node_view, _dir) = open_test_node_view();
        let mut sync_mgr = SyncManager::new(10, 64);
        let mut tracker = DeliveryTracker::new(30, 3);
        let mut cache = ModifiersCache::with_default_capacities();

        // Use a real mainnet header — passes parse and PoW but its
        // parent is not in our empty test DB, so it will be orphaned.
        let header = mainnet_header_500001();
        let data = ergo_wire::header_ser::serialize_header(&header);
        let id = ModifierId(blake2b256(&data));

        tracker.set_requested(HEADER_TYPE_ID, id, 1);

        let mods = ModifiersData {
            type_id: HEADER_TYPE_ID as i8,
            modifiers: vec![(id, data.clone())],
        };
        let msg = RawMessage {
            code: 33,
            body: mods.serialize(),
        };

        let result = handle_message(
            1,
            &msg,
            &mut node_view,
            &mut sync_mgr,
            &mut tracker,
            &[],
            &mut SyncTracker::new(),
            &mut cache,
            &mut HashMap::new(),
            false,
            &mut None,
            &mut TxCostTracker::new(),
            10,
            &[],
            &mut SyncMetrics::new(10),
        );

        // No penalties — the header is valid, just orphaned.
        assert!(result.penalties.is_empty());

        // The orphan header should be cached for retry.
        assert!(
            !cache.is_empty(),
            "orphan header should be placed in the modifiers cache"
        );
    }

    #[test]
    fn handle_inv_header_single_peer_when_sender_not_older() {
        // When inv_sender is not classified Older, should fallback to single-peer
        let mut tracker = DeliveryTracker::new(60, 2);
        let mut sync_tracker = SyncTracker::new();
        sync_tracker.update_status(1, PeerChainStatus::Younger, Some(50));
        let mut metrics = SyncMetrics::new(10);
        let connected = vec![1u64];

        let ids: Vec<ModifierId> = (0..100u8)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                ModifierId(bytes)
            })
            .collect();

        let inv = InvData {
            type_id: HEADER_TYPE_ID as i8,
            ids,
        };
        let body = inv.serialize();

        let tmp = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(tmp.path()).unwrap();
        let mempool = crate::mempool::ErgoMemPool::new(1000);

        let result = handle_inv(
            1,
            &body,
            &mut tracker,
            &history,
            &mempool,
            false,
            &sync_tracker,
            &connected,
            &mut metrics,
            false,
        );

        // Should have exactly 1 RequestModifiers action to peer 1
        assert_eq!(result.actions.len(), 1);
        match &result.actions[0] {
            SyncAction::RequestModifiers {
                peer_id,
                type_id,
                ids,
            } => {
                assert_eq!(*peer_id, 1);
                assert_eq!(*type_id, HEADER_TYPE_ID);
                assert_eq!(ids.len(), 100);
            }
            _ => panic!("expected RequestModifiers"),
        }
    }

    #[test]
    fn handle_inv_header_multi_peer_partitioning() {
        // 3 Older peers: should partition across all 3
        let mut tracker = DeliveryTracker::new(60, 2);
        let mut sync_tracker = SyncTracker::new();
        sync_tracker.update_status(1, PeerChainStatus::Older, Some(1000));
        sync_tracker.update_status(2, PeerChainStatus::Older, Some(1000));
        sync_tracker.update_status(3, PeerChainStatus::Older, Some(1000));
        let mut metrics = SyncMetrics::new(10);
        let connected = vec![1u64, 2, 3];

        let ids: Vec<ModifierId> = (0..150u8)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                ModifierId(bytes)
            })
            .collect();

        let inv = InvData {
            type_id: HEADER_TYPE_ID as i8,
            ids,
        };
        let body = inv.serialize();

        let tmp = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(tmp.path()).unwrap();
        let mempool = crate::mempool::ErgoMemPool::new(1000);

        let result = handle_inv(
            1,
            &body,
            &mut tracker,
            &history,
            &mempool,
            false,
            &sync_tracker,
            &connected,
            &mut metrics,
            false,
        );

        // Should have 3 RequestModifiers actions
        assert_eq!(result.actions.len(), 3);
        let mut total_ids = 0;
        for action in &result.actions {
            match action {
                SyncAction::RequestModifiers { type_id, ids, .. } => {
                    assert_eq!(*type_id, HEADER_TYPE_ID);
                    assert_eq!(ids.len(), 50);
                    total_ids += ids.len();
                }
                _ => panic!("expected RequestModifiers"),
            }
        }
        assert_eq!(total_ids, 150);
    }

    #[test]
    fn handle_inv_global_cap_backpressure() {
        // Fill tracker to global cap, verify no new requests emitted
        let mut tracker = DeliveryTracker::new(60, 2);
        // Insert 2400 outstanding headers
        for i in 0..2400u32 {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_be_bytes());
            tracker.set_requested(101, ModifierId(bytes), 99);
        }

        let mut sync_tracker = SyncTracker::new();
        sync_tracker.update_status(1, PeerChainStatus::Older, Some(1000));
        let mut metrics = SyncMetrics::new(10);
        let connected = vec![1u64];

        let new_id = ModifierId([0xFF; 32]);
        let inv = InvData {
            type_id: HEADER_TYPE_ID as i8,
            ids: vec![new_id],
        };
        let body = inv.serialize();

        let tmp = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(tmp.path()).unwrap();
        let mempool = crate::mempool::ErgoMemPool::new(1000);

        let result = handle_inv(
            1,
            &body,
            &mut tracker,
            &history,
            &mempool,
            false,
            &sync_tracker,
            &connected,
            &mut metrics,
            false,
        );

        // Should emit nothing due to global cap
        assert!(result.actions.is_empty());
    }

    #[test]
    fn handle_inv_non_header_unchanged() {
        // Non-header type_id should use single-peer, no partitioning
        let mut tracker = DeliveryTracker::new(60, 2);
        let mut sync_tracker = SyncTracker::new();
        sync_tracker.update_status(1, PeerChainStatus::Older, Some(1000));
        sync_tracker.update_status(2, PeerChainStatus::Older, Some(1000));
        let mut metrics = SyncMetrics::new(10);
        let connected = vec![1u64, 2];

        let id = ModifierId([0xBB; 32]);
        let inv = InvData {
            type_id: 102,
            ids: vec![id],
        }; // block transactions
        let body = inv.serialize();

        let tmp = tempfile::tempdir().unwrap();
        let history = HistoryDb::open(tmp.path()).unwrap();
        let mempool = crate::mempool::ErgoMemPool::new(1000);

        let result = handle_inv(
            1,
            &body,
            &mut tracker,
            &history,
            &mempool,
            false,
            &sync_tracker,
            &connected,
            &mut metrics,
            false,
        );

        // Should have exactly 1 action to peer 1 (no partitioning for non-headers)
        assert_eq!(result.actions.len(), 1);
        match &result.actions[0] {
            SyncAction::RequestModifiers { peer_id, .. } => assert_eq!(*peer_id, 1),
            _ => panic!("expected RequestModifiers"),
        }
    }
}

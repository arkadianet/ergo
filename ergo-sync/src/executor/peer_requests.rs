//! Peer-facing request scheduling for [`SyncExecutor`].
//!
//! Delivery-timeout re-requests, head-of-line hedging, disconnect
//! recovery, and the bucketed missing-section request wiring — thin
//! peer-selection wrappers over the coordinator's scheduling entry
//! points.

use std::time::Instant;

use ergo_p2p::peer::PeerId;
use ergo_p2p::peer_manager::PeerManager;

use crate::coordinator::{Action, ChainView, SyncCoordinator};

use super::{SyncExecutor, DRAIN_WATERMARK, HOL_HEDGE_THRESHOLD};

impl SyncExecutor {
    /// Check for delivery timeouts and re-request from alternative peers.
    /// Uses PeerManager::select_peer_excluding to find a peer that is NOT
    /// the one that timed out.
    pub fn check_timeouts(
        &mut self,
        coordinator: &mut SyncCoordinator,
        peer_mgr: &PeerManager,
        now: Instant,
    ) -> Vec<Action> {
        let peers = peer_mgr.eligible_download_peers(now);
        coordinator.check_timeouts(now, &peers)
    }

    /// HOL hedge: early-reassign stuck sections for any in-window pending
    /// block (inflight longer than `HOL_HEDGE_THRESHOLD`) to a *capable*
    /// peer. Called every sync tick; acts only when a section is actually
    /// stuck.
    ///
    /// Hedge peers come from `block_section_capable_peers` (full archive), not
    /// the broader `eligible_download_peers`: capability is the hard filter,
    /// so we never reassign a section to a peer that can't serve it. That set
    /// prefers non-delivery-degraded archive peers but falls back to degraded
    /// archive peers rather than route sections to incapable peers.
    pub fn check_hol_hedges(
        &mut self,
        best_full_block_height: u32,
        coordinator: &mut SyncCoordinator,
        peer_mgr: &PeerManager,
        now: Instant,
    ) -> Vec<Action> {
        let peers = peer_mgr.block_section_capable_peers(now);
        coordinator.check_hol_hedges(best_full_block_height, HOL_HEDGE_THRESHOLD, now, &peers)
    }

    /// Handle peer disconnection: cancel requests and re-request from alternatives.
    pub fn on_peer_disconnected(
        &mut self,
        peer: &PeerId,
        coordinator: &mut SyncCoordinator,
        peer_mgr: &PeerManager,
        now: Instant,
    ) -> Vec<Action> {
        let peers = peer_mgr.eligible_download_peers(now);
        coordinator.on_peer_disconnected(peer, now, &peers)
    }

    /// Request sections for pending blocks that are missing from the store.
    /// Used after restart or when the download window advances.
    ///
    /// Sync-S1: now wires the bucketed multi-peer partitioner. Pending
    /// sections are distributed across ALL eligible download peers in
    /// per-peer buckets (Scala 8/12 parity), with a rotation cursor in
    /// the coordinator so the first peer in the sorted list isn't
    /// permanently the first assignee. Falls back to empty-action when
    /// no peer is eligible (caller sees the same no-op as before).
    pub fn request_missing_sections(
        &mut self,
        coordinator: &mut SyncCoordinator,
        chain: &dyn ChainView,
        peer_mgr: &PeerManager,
        now: Instant,
    ) -> Vec<Action> {
        // Prefer archive-mode peers (Scala parity, see
        // `VersionBasedPeerFilteringRule.scala:99-103`), but always
        // fall through to eligible peers as a secondary set so the
        // bucketed partitioner has enough fan-out. Attempt 6
        // demonstrated that strict-only-archive filtering left the
        // request loop with too few peers and stalled post-install
        // catch-up for 9+ minutes. With 2Q (no permanent Failed
        // state), the bucketed partitioner rotates across peers
        // naturally — sections eventually find a capable peer.
        let archive_peers = peer_mgr.block_section_capable_peers(now);
        let eligible = peer_mgr.eligible_download_peers(now);
        let peers: Vec<PeerId> = if archive_peers.is_empty() {
            eligible
        } else {
            // Archive peers first (they're guaranteed to have the
            // data), then everyone else (best-effort, may still
            // succeed for Mode 2 / Mode 3 peers that retain enough
            // history).
            let mut combined = archive_peers;
            for p in eligible {
                if !combined.contains(&p) {
                    combined.push(p);
                }
            }
            combined
        };
        coordinator.request_missing_sections_bucketed(chain, now, &peers)
    }

    /// Sync-S2: whether the delivery pipeline has drained below the
    /// low-watermark and should be refilled now instead of waiting for
    /// the next sync tick. Preserves the effect-transcript tenet — this
    /// is a pure query, the caller (node event loop) decides whether to
    /// invoke `request_missing_sections`.
    pub fn pipeline_needs_refill(&self, coordinator: &SyncCoordinator) -> bool {
        coordinator
            .delivery()
            .below_drain_watermark(DRAIN_WATERMARK)
    }
}

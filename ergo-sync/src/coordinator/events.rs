//! Event handlers for [`SyncCoordinator`].
//!
//! The inbound half of the sync protocol: SyncInfo and Inv
//! classification (`on_sync_info` / `on_inv` — the two halves of one
//! request/response dance, kept side by side), modifier receipt,
//! header-validated and block-applied feedback, delivery timeouts and
//! peer disconnects, plus the SyncInfo payload builders.

use std::time::Instant;

use tracing::{info, warn};

use ergo_p2p::delivery::DeliveryAction;
use ergo_p2p::message::{self, SyncInfo};
use ergo_p2p::peer::{PeerId, Penalty, SyncVersion};
use ergo_p2p::sync::PeerChainStatus;
use ergo_p2p::types::{InvData, ModifierTypeId};
use ergo_primitives::digest::blake2b256;
use ergo_ser::modifier_id::ExpectedSections;

use super::{Action, ChainView, PeerSyncSnapshot, SyncCoordinator};

impl SyncCoordinator {
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
pub(crate) fn find_continuation_header(
    peer_headers: &[Vec<u8>],
    chain: &dyn ChainView,
) -> Option<Vec<u8>> {
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

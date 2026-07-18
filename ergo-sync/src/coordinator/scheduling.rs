//! Download scheduling for [`SyncCoordinator`].
//!
//! The outbound half of block-section sync: single-peer and bucketed
//! multi-peer missing-section requests (`request_missing_sections` /
//! `request_missing_sections_bucketed` — the latter's invariants are
//! documented as preserved from the former, kept adjacent per the
//! split map), head-of-line hedging, bucketed re-requests, header
//! parent-walk requests, and the IBD / caught-up-to-peers latches.

use std::time::{Duration, Instant};

use tracing::{debug, warn};

use ergo_p2p::delivery::ModifierStatus;
use ergo_p2p::message;
use ergo_p2p::peer::PeerId;
use ergo_p2p::sync::PeerChainStatus;
use ergo_p2p::types::{InvData, ModifierTypeId};

use super::{Action, ChainView, SyncCoordinator};

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
        // Digest-verifier (Mode 5) only; empty and unused for a UTXO node.
        let mut ad_proofs_ids: Vec<[u8; 32]> = Vec::new();

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
                } else if self.requires_proofs && type_id == ModifierTypeId::ADProofs.as_byte() {
                    ad_proofs_ids.push(section_id);
                }
            }
        }

        // Send batched requests — one message per type, up to 400 IDs each.
        // This matches how the Scala node batches RequestModifier.
        let mut buckets: Vec<(u8, &Vec<[u8; 32]>)> = vec![
            (ModifierTypeId::BlockTransactions.as_byte(), &tx_ids),
            (ModifierTypeId::Extension.as_byte(), &ext_ids),
        ];
        if self.requires_proofs {
            buckets.push((ModifierTypeId::ADProofs.as_byte(), &ad_proofs_ids));
        }
        for (type_id, ids) in buckets {
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
        // Digest-verifier (Mode 5) only; empty and unused for a UTXO node.
        let mut ad_proofs_ids: Vec<[u8; 32]> = Vec::new();
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
                } else if self.requires_proofs && type_id == ModifierTypeId::ADProofs.as_byte() {
                    ad_proofs_ids.push(section_id);
                }
            }
        }

        if tx_ids.is_empty() && ext_ids.is_empty() && ad_proofs_ids.is_empty() {
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
        let types_with_demand = (!tx_ids.is_empty() as usize)
            + (!ext_ids.is_empty() as usize)
            + (!ad_proofs_ids.is_empty() as usize);
        let per_type_total_cap = if types_with_demand == 0 {
            0
        } else {
            total_available_slots.div_ceil(types_with_demand)
        };
        tx_ids.truncate(per_type_total_cap);
        ext_ids.truncate(per_type_total_cap);
        ad_proofs_ids.truncate(per_type_total_cap);

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
        // ADProofs(104) sorts before Extension(108) in the BTreeMap.
        if !ad_proofs_ids.is_empty() {
            by_type.insert(ModifierTypeId::ADProofs.as_byte(), ad_proofs_ids);
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
            let is_ad_proofs =
                self.requires_proofs && type_id == ModifierTypeId::ADProofs.as_byte();
            if type_id != ModifierTypeId::BlockTransactions.as_byte()
                && type_id != ModifierTypeId::Extension.as_byte()
                && !is_ad_proofs
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
    pub(super) fn rerequest_modifiers_bucketed(
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
        let mut ad_proofs_ids: Vec<[u8; 32]> = Vec::new();
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
            } else if self.requires_proofs && type_id == ModifierTypeId::ADProofs.as_byte() {
                // Preserve type 104 on retry — dropping it into the header
                // fallback would re-request an ADProof section as a Header.
                ad_proofs_ids.push(*id);
            } else {
                header_ids.push(*id);
            }
        }

        let mut actions = Vec::new();

        if !tx_ids.is_empty() || !ext_ids.is_empty() || !ad_proofs_ids.is_empty() {
            const MAX_INV_OBJECTS: usize = 400;
            let n_peers = peers.len();
            let total = tx_ids.len().max(ext_ids.len()).max(ad_proofs_ids.len());
            let max_per_bucket = if n_peers >= 3 {
                12
            } else {
                total.div_ceil(n_peers.max(1)).clamp(1, MAX_INV_OBJECTS)
            };

            let mut by_type = std::collections::BTreeMap::new();
            if !tx_ids.is_empty() {
                by_type.insert(ModifierTypeId::BlockTransactions.as_byte(), tx_ids);
            }
            if !ad_proofs_ids.is_empty() {
                by_type.insert(ModifierTypeId::ADProofs.as_byte(), ad_proofs_ids);
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

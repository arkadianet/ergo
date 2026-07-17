//! Peer manager: connection limits, peer selection, discovery, eviction.
//!
//! Manages the set of connected peers with anti-eclipse measures:
//! - Max 384 total connections by default
//! - Target 96 outbound, up to 256 inbound (decoupled — a full outbound
//!   set never reduces inbound capacity)
//! - 1 connection per IP
//! - Max 3 from same /16 subnet [inherited, relaxed]
//!
//! Peer selection currently sorts by most-recently-seen. Full bucketed
//! ranking with throughput metrics and randomization is queued for a
//! follow-up pass.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::address_book::AddressBook;
use crate::handshake::PeerSpec;
use crate::peer::{
    ConnectionState, Direction, PeerId, PeerInfo, PeerRejectReason, Penalty, PenaltyOutcome,
    DEGRADED_THRESHOLD, DELIVERY_DEGRADE_STREAK,
};

pub mod known_peer;
pub mod limits;
mod persistence;
pub mod routability;

// Re-export the public surface so existing call sites
// (`peer_manager::PeerLimits`, `peer_manager::ConnectError`,
// `peer_manager::declared_to_socket`, …) keep working without
// rewriting every importer.
pub use known_peer::{
    AddKnownOutcome, KnownPeer, PeerOrigin, GOSSIP_INTERVAL, MAX_KNOWN_ADDRESSES,
};
pub use limits::{
    ConnectError, PeerLimits, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_INBOUND, DEFAULT_PER_IP_LIMIT,
    DEFAULT_PER_SUBNET_LIMIT, DEFAULT_TARGET_OUTBOUND,
};
pub use routability::{declared_to_socket, is_routable_for_p2p};

use known_peer::{backoff_for, known_peer_keep_priority};

// ---- PeerManager ----

pub struct PeerManager {
    peers: HashMap<PeerId, PeerInfo>,
    /// Ban list: IP → ban expiry. Separate from peers so bans survive disconnection.
    bans: HashMap<IpAddr, BanEntry>,
    known_addresses: Vec<KnownPeer>,
    our_session_id: i64,
    limits: PeerLimits,
    /// Persistent address book. Optional so tests and callers that don't
    /// need disk persistence (e.g. unit tests, embedded uses) can omit it.
    /// Write-through fires on lifecycle hooks; errors are logged, not
    /// surfaced — the in-memory state remains authoritative for the
    /// session, persistence is best-effort restore-on-restart.
    book: Option<Arc<AddressBook>>,
}

#[derive(Debug, Clone)]
struct BanEntry {
    until: Instant,
    count: u32,
}

impl PeerManager {
    pub fn new(session_id: i64) -> Self {
        Self::new_with_limits(session_id, PeerLimits::default())
    }

    pub fn new_with_limits(session_id: i64, limits: PeerLimits) -> Self {
        Self {
            peers: HashMap::new(),
            bans: HashMap::new(),
            known_addresses: Vec::new(),
            our_session_id: session_id,
            limits,
            book: None,
        }
    }

    /// Attach a persistent address book. Subsequent lifecycle hooks
    /// (handshake, dial outcome, gossip ingest, ban) will write through.
    /// Idempotent: replaces any existing handle.
    pub fn set_address_book(&mut self, book: Arc<AddressBook>) {
        self.book = Some(book);
    }

    pub fn session_id(&self) -> i64 {
        self.our_session_id
    }

    pub fn limits(&self) -> PeerLimits {
        self.limits
    }

    // ---- Connection lifecycle ----

    /// Attempt to register a new outbound connection. Returns Err if limits prevent it.
    pub fn register_outbound(&mut self, addr: PeerId, now: Instant) -> Result<(), ConnectError> {
        self.check_can_connect(addr, now)?;
        self.peers.insert(addr, PeerInfo::new_outbound(addr, now));
        Ok(())
    }

    /// Attempt to register a new inbound connection. Returns Err if limits prevent it.
    /// Inbound is capped at its own `max_inbound` budget (decoupled from
    /// `target_outbound`, so a full outbound set never reduces inbound
    /// capacity). The `max_connections` total ceiling still applies on top
    /// via `check_can_connect`.
    pub fn register_inbound(&mut self, addr: PeerId, now: Instant) -> Result<(), ConnectError> {
        self.check_can_connect(addr, now)?;
        let inbound_count = self.count_by_direction(Direction::Inbound);
        let max_inbound = self.limits.max_inbound();
        if inbound_count >= max_inbound {
            return Err(ConnectError::TooManyInbound);
        }
        self.peers.insert(addr, PeerInfo::new_inbound(addr, now));
        Ok(())
    }

    /// Mark TCP connection established (transition Connecting → Handshaking).
    pub fn mark_tcp_connected(&mut self, addr: &PeerId) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.mark_tcp_connected();
        }
    }

    /// Complete handshake for a peer. Rejects peers with version < EIP37.
    /// Also checks for self-connection via session_id.
    /// On rejection, the peer is removed from the table and banned.
    pub fn complete_handshake(
        &mut self,
        addr: &PeerId,
        spec: PeerSpec,
        peer_session_id: Option<i64>,
        now: Instant,
    ) -> Result<(), ConnectError> {
        // Check for self-connection
        if let Some(sid) = peer_session_id {
            if sid == self.our_session_id {
                self.disconnect(addr);
                return Err(ConnectError::SelfConnection);
            }
        }

        let peer = self.peers.get_mut(addr).ok_or(ConnectError::UnknownPeer)?;
        let direction = peer.direction;
        let spec_for_book = spec.clone();
        match peer.complete_handshake(spec, now) {
            Ok(()) => {
                // Compare the address the peer declared in its handshake
                // spec against the address we observed on the TCP socket.
                // Mismatches are normal for NATted peers and peers behind
                // reverse proxies; log at info-level (not warn) so
                // operators can audit without alarming, and do not
                // penalize — declared addresses are advisory hints for
                // future dial reuse, never session-gating.
                let declared_socket = spec_for_book
                    .declared_address
                    .as_ref()
                    .and_then(declared_to_socket);
                if let Some(declared) = declared_socket {
                    if declared != *addr {
                        info!(
                            peer = %addr,
                            declared = %declared,
                            reason = "DeclaredAddressMismatch",
                            "declared address differs from observed",
                        );
                    }
                }
                self.persist_handshake(*addr, &spec_for_book, direction);
                // Inbound peers reach us from an ephemeral client port
                // (`addr`); their listening port lives in the declared
                // address. Record the declared socket in
                // `known_addresses` so a later dial cycle can reach
                // them after the current session ends. Outbound peers
                // already have their listening address in
                // `known_addresses` (that's how we got here).
                if direction == Direction::Inbound {
                    if let Some(declared) = declared_socket {
                        if declared != *addr && is_routable_for_p2p(&declared) {
                            self.add_known_address(declared, PeerOrigin::Gossip);
                        }
                    }
                }
                Ok(())
            }
            Err(PeerRejectReason::VersionTooOld(v)) => {
                warn!(peer = %addr, version = ?v, reason = "VersionTooOld", "peer removed: handshake reject");
                self.record_ban(addr.ip(), now, true);
                self.peers.remove(addr);
                Err(ConnectError::VersionTooOld(v))
            }
        }
    }

    /// Disconnect and remove a peer. Logs the removal reason.
    #[track_caller]
    pub fn disconnect(&mut self, addr: &PeerId) {
        let was_handshaked = self
            .peers
            .get(addr)
            .map(|p| p.state == ConnectionState::Active)
            .unwrap_or(false);
        if let Some(peer) = self.peers.get(addr) {
            let caller = std::panic::Location::caller();
            // Routine per-peer churn — DEBUG, not INFO. The connected-peer
            // count is surfaced once per heartbeat; bans/handshake-rejects
            // keep their own WARN lines.
            debug!(
                peer = %addr,
                state = ?peer.state,
                age_s = peer.connected_at.elapsed().as_secs(),
                score = peer.score.raw_score(),
                caller = %caller,
                reason = "DisconnectCall",
                "peer removed",
            );
        }
        self.peers.remove(addr);
        if was_handshaked {
            self.persist_touch(*addr);
        }
    }

    /// Apply a penalty to a peer. Returns the outcome (ok/degraded/banned).
    /// If banned, the peer is removed and the ban is recorded in the ban list.
    pub fn penalize(&mut self, addr: &PeerId, penalty: Penalty, now: Instant) -> PenaltyOutcome {
        let outcome = if let Some(peer) = self.peers.get_mut(addr) {
            peer.penalize(penalty, now)
        } else {
            return PenaltyOutcome::Ok;
        };
        if outcome == PenaltyOutcome::Banned {
            if let Some(peer) = self.peers.get(addr) {
                warn!(
                    peer = %addr,
                    state = ?peer.state,
                    score = peer.score.raw_score(),
                    reason = "PenaltyBan",
                    "peer banned and removed",
                );
            }
            self.record_ban(addr.ip(), now, false);
            self.peers.remove(addr);
        }
        outcome
    }

    /// Mark a peer as active (received valid message).
    pub fn touch(&mut self, addr: &PeerId, now: Instant) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.touch(now);
        }
    }

    /// Record a requested-modifier delivery outcome for a peer: `true`
    /// resets its consecutive-failure streak, `false` (a delivery timeout)
    /// increments it. Drives download deprioritization via
    /// [`DELIVERY_DEGRADE_STREAK`]. No-op for an unknown peer.
    pub fn note_delivery_outcome(&mut self, addr: &PeerId, succeeded: bool) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.note_delivery_outcome(succeeded);
        }
    }

    // ---- Queries ----

    pub fn get(&self, addr: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(addr)
    }

    pub fn connected_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_connected()).count()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Observability accessor: number of entries in the local
    /// known-addresses pool. Bounded by [`MAX_KNOWN_ADDRESSES`] —
    /// see `add_known_address` for the eviction rule.
    pub fn known_addresses_len(&self) -> usize {
        self.known_addresses.len()
    }

    /// All connected peers.
    pub fn connected_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values().filter(|p| p.is_connected())
    }

    /// Peers suitable for downloading (active, not degraded).
    pub fn active_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.state == ConnectionState::Active)
    }

    /// Check if an IP is currently banned (ban list, not peer table).
    pub fn is_banned(&self, addr: &SocketAddr, now: Instant) -> bool {
        if let Some(entry) = self.bans.get(&addr.ip()) {
            return now < entry.until;
        }
        false
    }

    /// Snapshot every IP currently in the ban list whose ban hasn't
    /// expired yet. Drives `/peers/blacklisted` on the Scala-compat
    /// surface (`ErgoPeersApiRoute.scala:98-102`) — the route emits
    /// each entry as Java `InetAddress.toString()` form, which the
    /// API bridge formats from these raw `IpAddr` values.
    ///
    /// Returns owned `IpAddr` values so the caller (snapshot
    /// publisher) can clone into an `Arc` without holding a
    /// reference into `self`. Expired entries are filtered out at
    /// the call site so a stale ban that has aged past `until`
    /// doesn't appear in the response — `is_banned` already does
    /// this for the inbound-admit gate; this method matches that
    /// behaviour for the read surface.
    pub fn currently_banned_ips(&self, now: Instant) -> Vec<IpAddr> {
        self.bans
            .iter()
            .filter_map(|(ip, entry)| if now < entry.until { Some(*ip) } else { None })
            .collect()
    }

    // ---- Peer selection ----

    /// Select a peer for downloading. Prefers active (non-degraded) peers,
    /// sorted by most-recently-seen. Full bucketed ranking with throughput
    /// metrics and randomization is queued for a follow-up pass.
    pub fn select_peer_for_download(&self, now: Instant) -> Option<PeerId> {
        self.select_peer_excluding(now, &[])
    }

    /// Select a random non-degraded connected peer for a `GetPeers`
    /// gossip round. Mirrors Scala's `PeerSynchronizer` (schedules
    /// `GetPeers` to a random peer every `getPeersInterval`) so a
    /// silent-but-connected peer cannot monopolize gossip rounds.
    ///
    /// `seed` is an arbitrary `u64` (caller typically passes
    /// `SystemTime::now()` nanos or a process-local counter); it's
    /// used modulo the eligible-peer count to pick an index over the
    /// address-sorted list. Tests pass explicit seeds for
    /// determinism; production callers pass a per-tick wall-clock
    /// value. The randomness floor is "caller chooses entropy" —
    /// good enough for non-cryptographic gossip rotation without
    /// pulling in a `rand` dependency.
    ///
    /// Returns `None` if no non-degraded connected peer exists. Caller
    /// is expected to space invocations by [`GOSSIP_INTERVAL`].
    pub fn select_peer_for_gossip(&self, now: Instant, seed: u64) -> Option<PeerId> {
        let mut eligible: Vec<PeerId> = self
            .peers
            .values()
            .filter(|p| p.is_connected() && p.score.effective_score(now) < DEGRADED_THRESHOLD)
            .map(|p| p.addr)
            .collect();
        if eligible.is_empty() {
            return None;
        }
        eligible.sort();
        let idx = (seed as usize) % eligible.len();
        Some(eligible[idx])
    }

    /// Select a peer for downloading, excluding specific peers.
    /// Used for reassignment after timeout or disconnect.
    pub fn select_peer_excluding(&self, now: Instant, exclude: &[PeerId]) -> Option<PeerId> {
        let mut candidates: Vec<&PeerInfo> = self
            .peers
            .values()
            .filter(|p| {
                p.is_connected()
                    && p.score.effective_score(now) < DEGRADED_THRESHOLD
                    && !exclude.contains(&p.addr)
            })
            .collect();

        if candidates.is_empty() {
            candidates = self
                .peers
                .values()
                .filter(|p| p.is_connected() && !exclude.contains(&p.addr))
                .collect();
        }

        if candidates.is_empty() {
            return None;
        }

        candidates.sort_by_key(|b| std::cmp::Reverse(b.last_seen));
        Some(candidates[0].addr)
    }

    /// Return ALL peers eligible for bucketed block-section download, in
    /// a deterministic order suitable for `partition::distribute`.
    ///
    /// Determinism: sort by `SocketAddr` (IP bytes, then port) so
    /// coordinator-level tests can assert exact peer-to-bucket mappings.
    ///
    /// Policy — bucketed by last-seen, with a degraded-peer fallback:
    /// 1. Prefer connected peers below `DEGRADED_THRESHOLD`.
    /// 2. Fall back to all connected peers (including degraded) only when
    ///    the preferred set is empty. Banned peers are never eligible.
    ///
    /// Returns empty vec if no connected peers exist; callers must not
    /// panic on that.
    pub fn eligible_download_peers(&self, now: Instant) -> Vec<PeerId> {
        let mut preferred: Vec<PeerId> = self
            .peers
            .values()
            .filter(|p| {
                p.is_connected()
                    && p.score.effective_score(now) < DEGRADED_THRESHOLD
                    && p.delivery_failure_streak() < DELIVERY_DEGRADE_STREAK
            })
            .map(|p| p.addr)
            .collect();
        if !preferred.is_empty() {
            preferred.sort();
            return preferred;
        }
        // Fallback: accept degraded peers rather than stall sync entirely
        // — bucketed by last-seen, falling back to degraded peers only
        // when no preferred peer is connected.
        let mut fallback: Vec<PeerId> = self
            .peers
            .values()
            .filter(|p| p.is_connected())
            .map(|p| p.addr)
            .collect();
        fallback.sort();
        fallback
    }

    /// Peers eligible to serve block sections (BlockTransactions,
    /// Extension, ADProofs).
    ///
    /// Scala parity (`VersionBasedPeerFilteringRule.scala:99-103`):
    /// ```scala
    /// object BlockSectionsDownloadFilter extends PeerFilteringRule {
    ///   override def condition(peer: ConnectedPeer): Boolean = {
    ///     peer.mode.exists(_.allBlocksAvailable)
    ///   }
    /// }
    /// ```
    /// where `allBlocksAvailable = blocksToKeep == -1` (full archive).
    ///
    /// Why this matters: `eligible_download_peers` returns ALL connected
    /// peers regardless of advertised capability. Mode 5/6 peers (digest,
    /// no block sections) and Mode 2 mid-bootstrap peers (no
    /// pre-snapshot blocks) silently ignore our RequestModifier because
    /// they don't have the data, but our delivery tracker still counts
    /// them as "request sent, awaiting reply" until timeout — stalling
    /// block application even with many otherwise-healthy peers
    /// connected.
    ///
    /// Filter: peer must be Active, have completed handshake, and have
    /// advertised `state_type=Utxo` + `verify_tx=true` + `blocks_to_keep
    /// == -1` (full archive — only mode that's guaranteed to have all
    /// historical sections).
    pub fn block_section_capable_peers(&self, now: Instant) -> Vec<PeerId> {
        // Capability (full archive) is a HARD requirement — only these peers
        // are guaranteed to hold every section. The delivery-failure streak
        // is a soft preference layered on top, WITH a fallback to all capable
        // peers: a delivery-degraded archive peer still beats a headers-only
        // peer that simply doesn't have the data, so a run of degraded
        // archives must never route sections to incapable peers.
        let capable: Vec<&PeerInfo> = self
            .peers
            .values()
            .filter(|p| p.is_connected() && p.score.effective_score(now) < DEGRADED_THRESHOLD)
            .filter(|p| match &p.peer_spec {
                Some(spec) => spec.features.iter().any(|f| {
                    matches!(
                        f,
                        crate::handshake::PeerFeature::Mode {
                            state_type: 0,
                            verify_tx: true,
                            blocks_to_keep: -1,
                            ..
                        }
                    )
                }),
                None => false,
            })
            .collect();

        let mut preferred: Vec<PeerId> = capable
            .iter()
            .copied()
            .filter(|p| p.delivery_failure_streak() < DELIVERY_DEGRADE_STREAK)
            .map(|p| p.addr)
            .collect();
        let mut out = if preferred.is_empty() {
            // Every capable peer is delivery-degraded — still prefer them
            // over incapable peers rather than stalling section download.
            capable.iter().map(|p| p.addr).collect::<Vec<_>>()
        } else {
            std::mem::take(&mut preferred)
        };
        out.sort();
        out
    }

    /// Peers eligible to serve a NiPoPoW proof (`GetNipopowProof`
    /// code 90). Scala parity: `VersionBasedPeerFilteringRule
    /// .NipopowSupportFilter` (`VersionBasedPeerFilteringRule.scala:79-91`).
    ///
    /// Filter:
    /// * Active + handshake completed + not degraded.
    /// * Protocol version >= `Version::NIPOPOW` (= 5.0.13).
    /// * `Mode.nipopow == None` — peer is NOT itself NiPoPoW-
    ///   bootstrapped. A peer that bootstrapped via NiPoPoW has no
    ///   extension/interlinks data for sparse prefix headers and so
    ///   cannot construct a fresh proof (Scala
    ///   `HeadersProcessor.scala:166-169`). Filtering them out
    ///   avoids fan-outs to peers that will never reply with usable
    ///   data.
    pub fn popow_capable_peers(&self, now: Instant) -> Vec<PeerId> {
        let mut peers: Vec<PeerId> = self
            .peers
            .values()
            .filter(|p| p.is_connected() && p.score.effective_score(now) < DEGRADED_THRESHOLD)
            .filter(|p| match &p.peer_spec {
                Some(spec) => {
                    spec.version >= crate::handshake::Version::NIPOPOW
                        && spec.features.iter().any(|f| {
                            matches!(f, crate::handshake::PeerFeature::Mode { nipopow: None, .. })
                        })
                }
                None => false,
            })
            .map(|p| p.addr)
            .collect();
        peers.sort();
        peers
    }

    // ---- Peer discovery ----

    /// Add a known peer address.
    ///
    /// `origin` distinguishes user-trusted entries (CLI `--peers`,
    /// TOML `[peers] known`, hardcoded mainnet bootstrap seeds — all
    /// `PeerOrigin::Seed`) from peers learnt via gossip
    /// (`PeerOrigin::Gossip`, from `Peers` message ingress).
    ///
    /// **Routability filter applies only to gossip.** The user might
    /// legitimately configure a loopback (`127.0.0.1:9030` for a
    /// co-located Scala node) or LAN address (`10.0.0.8:9030` for a
    /// dev/staging peer); silently dropping those would be a usability
    /// regression. For gossip ingress, the filter rejects RFC1918
    /// private, loopback, link-local, multicast, unspecified, port 0
    /// — without this, gossiped LAN-internal addresses like
    /// `10.0.0.8:9030` learnt from a NAT'd peer enter the dial pool
    /// and burn slots on every cycle.
    ///
    /// Returns the typed outcome so callers can distinguish "actually
    /// learned a new address" from "saw a known address again" — the
    /// gossip path is repetitive (peers re-emit the same address book
    /// every `GetPeers`) and counting every routable spec as "added"
    /// produces misleading dial-pool diagnostics.
    pub fn add_known_address(&mut self, addr: SocketAddr, origin: PeerOrigin) -> AddKnownOutcome {
        if !origin.is_seed() && !is_routable_for_p2p(&addr) {
            return AddKnownOutcome::FilteredNonRoutable;
        }
        if let Some(existing) = self.known_addresses.iter_mut().find(|k| k.addr == addr) {
            // Upgrade an existing gossip-learned entry to seed-trusted
            // when a seed claim arrives. Mirrors `AddressBook::add_known`
            // (`address_book.rs:395-407`). Without this the layer
            // contracts diverge: the in-memory row stays
            // `Gossip` even though the persisted row was
            // upgraded by the AddressBook on the same call.
            if origin.is_seed() && !existing.origin.is_seed() {
                existing.origin = PeerOrigin::Seed;
                self.persist_known(addr, PeerOrigin::Seed);
                return AddKnownOutcome::UpgradedToSeed;
            }
            return AddKnownOutcome::AlreadyKnown;
        }

        // Bound the dial pool. Without a cap a malicious peer can
        // flood us with `Peers` gossip and inflate this Vec without
        // bound. When at cap, evict the lowest-priority entry to make
        // room — except when the new entry is gossip and every
        // existing entry is a higher-priority seed, in which case we
        // drop the new entry rather than displace a seed.
        if self.known_addresses.len() >= MAX_KNOWN_ADDRESSES {
            let (worst_idx, worst_priority) = self
                .known_addresses
                .iter()
                .enumerate()
                .min_by_key(|(_, p)| known_peer_keep_priority(p))
                .map(|(i, p)| (i, known_peer_keep_priority(p)))
                .expect("len >= MAX_KNOWN_ADDRESSES > 0");
            let new_priority = (
                origin.is_seed(),
                false, // last_seen.is_some() — new entry has not been seen
                0i64,  // consecutive_failures = 0
            );
            if new_priority <= worst_priority {
                return AddKnownOutcome::DroppedPoolFull;
            }
            self.known_addresses.swap_remove(worst_idx);
        }

        self.known_addresses.push(KnownPeer {
            addr,
            last_seen: None,
            origin,
            last_failure: None,
            consecutive_failures: 0,
        });
        self.persist_known(addr, origin);
        AddKnownOutcome::Added
    }

    /// Restore a fully-populated `KnownPeer` from disk on startup. Skips
    /// the routability check (the entry was previously accepted on its
    /// original ingest) and does not write back through to the book —
    /// the caller is replaying state, not learning new addresses.
    pub fn restore_known_peer(&mut self, peer: KnownPeer) {
        if !self.known_addresses.iter().any(|k| k.addr == peer.addr) {
            self.known_addresses.push(peer);
        }
    }

    /// Restore a ban from disk. Idempotent — replaces any existing entry
    /// for the same IP. Does not write back through to the book.
    pub fn restore_ban(&mut self, ip: IpAddr, until: Instant, count: u32) {
        self.bans.insert(ip, BanEntry { until, count });
    }

    /// Record a dial failure against the known address. Increments the
    /// consecutive-failure counter and stamps `last_failure = now` so
    /// `addresses_to_connect` will skip this address until the backoff
    /// window elapses (see `DIAL_BACKOFF_SECS`). No-op for addresses
    /// not already known.
    pub fn mark_dial_failed(&mut self, addr: &SocketAddr, now: Instant) {
        if let Some(k) = self.known_addresses.iter_mut().find(|k| k.addr == *addr) {
            k.last_failure = Some(now);
            k.consecutive_failures = k.consecutive_failures.saturating_add(1);
        }
        self.persist_failure(*addr);
    }

    /// Record a successful handshake. Clears the backoff state so future
    /// failures start fresh from the shortest delay.
    pub fn mark_dial_succeeded(&mut self, addr: &SocketAddr, now: Instant) {
        if let Some(k) = self.known_addresses.iter_mut().find(|k| k.addr == *addr) {
            k.last_failure = None;
            k.consecutive_failures = 0;
            k.last_seen = Some(now);
        }
        self.persist_success(*addr);
    }

    /// Get addresses to share with peers (for Peers response).
    /// Returns up to `limit` connected peers' declared addresses.
    /// Filters out non-routable declared addresses so we do not
    /// propagate LAN-internal IPs (e.g. `10.0.0.8:9030` from a peer
    /// behind NAT) to the wider network. Without this filter, every
    /// recipient adds those addresses to its dial pool and burns slots.
    ///
    /// `seed` rotates the eligible set so different `GetPeers` callers
    /// don't all receive the same prefix of our peer list — mirrors
    /// Scala's `Random.shuffle` intent in `PeerManager.scala` without
    /// adding a `rand` dependency. The eligible set is first sorted
    /// by declared-address bytes for determinism, then the return is
    /// the rotation starting at `seed % len`.
    pub fn peers_for_sharing(&self, limit: usize, seed: u64) -> Vec<&PeerSpec> {
        let mut eligible: Vec<&PeerSpec> = self
            .peers
            .values()
            .filter(|p| p.is_connected() && p.peer_spec.is_some())
            .filter_map(|p| p.peer_spec.as_ref())
            .filter(|s| {
                let Some(declared) = s.declared_address.as_ref() else {
                    return false;
                };
                let Some(sock) = declared_to_socket(declared) else {
                    return false;
                };
                is_routable_for_p2p(&sock)
            })
            .collect();
        if eligible.is_empty() {
            return Vec::new();
        }
        eligible.sort_by(|a, b| {
            let aa = a.declared_address.as_ref().map(|d| d.addr.as_slice());
            let bb = b.declared_address.as_ref().map(|d| d.addr.as_slice());
            aa.cmp(&bb)
        });
        let start = (seed as usize) % eligible.len();
        let take = limit.min(eligible.len());
        (0..take)
            .map(|i| eligible[(start + i) % eligible.len()])
            .collect()
    }

    /// Get known addresses to attempt connecting to. Excludes
    /// already-connected, banned, back-off-suppressed, and addresses
    /// that would be rejected on per-IP / per-subnet / max-connections
    /// grounds at `register_outbound` time.
    ///
    /// The connectability gate (via `check_can_connect`) matters because
    /// gossip routinely surfaces alternate-port variants of an
    /// already-connected IP — e.g. we connected to `host:9030` and a
    /// later `Peers` reply mentions `host:9020`. Without the gate, that
    /// variant sits in `known_addresses` forever, gets reselected each
    /// dial cycle, fails the per-IP check at `register_outbound`, and
    /// never gets backed off (`mark_dial_failed` only fires on TCP /
    /// handshake failure, not on the upfront connectability check). The
    /// per-cycle dial budget then burns on guaranteed-failures and the
    /// outbound deficit never closes.
    ///
    /// Backoff: addresses with `consecutive_failures > 0` are skipped
    /// until `now - last_failure >= backoff_for(consecutive_failures)`
    /// (exponential schedule: 30s, 2min, 10min, 30min, 2hr cap). Without
    /// this, a handful of dead seeds dominate every dial cycle's small
    /// budget and starve gossiped alternatives — observed in production
    /// as peer count stuck at 3-4 despite an outbound target and successful
    /// gossip Peers replies adding 8+ addresses.
    pub fn addresses_to_connect(&self, now: Instant, limit: usize) -> Vec<SocketAddr> {
        self.known_addresses
            .iter()
            .filter(|k| {
                if let (Some(last), n) = (k.last_failure, k.consecutive_failures) {
                    if n > 0 && now.duration_since(last) < backoff_for(n) {
                        return false;
                    }
                }
                self.check_can_connect(k.addr, now).is_ok()
            })
            .take(limit)
            .map(|k| k.addr)
            .collect()
    }

    /// Whether we need more outbound connections.
    pub fn needs_outbound(&self) -> bool {
        self.count_by_direction(Direction::Outbound) < self.limits.target_outbound
    }

    /// How many more outbound connections we should attempt to meet
    /// the configured outbound target. Saturates at 0 when at or above
    /// the target; callers use this to size each dial cycle.
    pub fn outbound_deficit(&self) -> usize {
        self.limits
            .target_outbound
            .saturating_sub(self.count_by_direction(Direction::Outbound))
    }

    // ---- Eviction / cleanup ----

    /// Remove timed-out peers and return their addresses.
    pub fn evict_timed_out(&mut self, now: Instant) -> Vec<PeerId> {
        let to_remove: Vec<(PeerId, ConnectionState, u64, u64)> = self
            .peers
            .iter()
            .filter(|(_, p)| p.is_timed_out(now))
            .map(|(addr, p)| {
                (
                    *addr,
                    p.state,
                    p.connected_at.elapsed().as_secs(),
                    p.last_seen.elapsed().as_secs(),
                )
            })
            .collect();
        for (addr, state, age, last_seen) in &to_remove {
            // Per-peer detail at DEBUG; the caller logs a single INFO
            // `evicted stale peers` count summary for the batch.
            debug!(
                peer = %addr,
                state = ?state,
                age_s = age,
                last_seen_s = last_seen,
                reason = "TimeoutEvict",
                "peer removed: idle timeout",
            );
            self.peers.remove(addr);
        }
        let to_remove: Vec<PeerId> = to_remove.into_iter().map(|(a, _, _, _)| a).collect();
        to_remove
    }

    // ---- Internal helpers ----

    fn check_can_connect(&self, addr: PeerId, now: Instant) -> Result<(), ConnectError> {
        // Banned
        if self.is_banned(&addr, now) {
            return Err(ConnectError::Banned);
        }
        // Already connected
        if self.peers.contains_key(&addr) {
            return Err(ConnectError::AlreadyConnected);
        }
        // Total connection limit
        if self.peers.len() >= self.limits.max_connections {
            return Err(ConnectError::TooManyConnections);
        }
        // Per-IP limit
        let ip_count = self
            .peers
            .values()
            .filter(|p| p.addr.ip() == addr.ip())
            .count();
        if ip_count >= self.limits.per_ip_limit {
            return Err(ConnectError::PerIpLimitReached);
        }
        // Per-subnet limit (IPv4 /16)
        if let IpAddr::V4(ip) = addr.ip() {
            let subnet = [ip.octets()[0], ip.octets()[1]];
            let subnet_count = self
                .peers
                .values()
                .filter(|p| p.subnet() == Some(subnet))
                .count();
            if subnet_count >= self.limits.per_subnet_limit {
                return Err(ConnectError::PerSubnetLimitReached);
            }
        }
        Ok(())
    }

    /// Record a ban in the ban list (separate from peer table).
    fn record_ban(&mut self, ip: IpAddr, now: Instant, permanent: bool) {
        let existing_count = self.bans.get(&ip).map(|e| e.count).unwrap_or(0);
        let duration = if permanent {
            Duration::from_secs(365 * 24 * 60 * 60)
        } else {
            match existing_count {
                0 => Duration::from_secs(30 * 60),
                1 => Duration::from_secs(2 * 60 * 60),
                2 => Duration::from_secs(24 * 60 * 60),
                _ => Duration::from_secs(7 * 24 * 60 * 60),
            }
        };
        let count = existing_count + 1;
        self.bans.insert(
            ip,
            BanEntry {
                until: now + duration,
                count,
            },
        );
        self.persist_ban(ip, duration, count, permanent);
    }

    fn count_by_direction(&self, dir: Direction) -> usize {
        self.peers.values().filter(|p| p.direction == dir).count()
    }
}

#[cfg(test)]
mod tests;

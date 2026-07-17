//! Known-peer data model for peer discovery: address origins, dial-pool
//! entries, dial-backoff schedule, and eviction-priority helpers.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Origin of a known peer address — drives routability filtering,
/// dial-pool priority, and ban policy. `Seed` addresses come from the
/// operator-supplied bootstrap list (CLI / TOML) and bypass the
/// routability filter; `Gossip` addresses arrive via `Peers` messages
/// from other peers and are filtered. Two-state today; future origins
/// (e.g. persisted-on-restart) extend without breaking call-site
/// signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOrigin {
    /// Operator-supplied bootstrap address. Trusted enough to skip
    /// routability filtering and to be retained across the dial pool's
    /// gossip-flood eviction.
    Seed,
    /// Address learned from another peer's `Peers` gossip message.
    /// Subject to the routability filter and to dial-pool eviction
    /// when the pool is at capacity.
    Gossip,
}

impl PeerOrigin {
    /// `true` when the address came from the operator's seed list.
    pub fn is_seed(self) -> bool {
        matches!(self, PeerOrigin::Seed)
    }
}

/// Known peer address for discovery.
#[derive(Debug, Clone)]
pub struct KnownPeer {
    pub addr: SocketAddr,
    pub last_seen: Option<Instant>,
    pub origin: PeerOrigin,
    /// When the most recent dial attempt failed. None ⇒ never attempted
    /// or last attempt succeeded. Used by `addresses_to_connect` to apply
    /// exponential backoff so dead seeds don't dominate the dial cycle
    /// and starve gossiped alternatives.
    pub last_failure: Option<Instant>,
    /// Count of consecutive dial failures since the last success. Resets
    /// to 0 on successful handshake. Drives the backoff exponent.
    pub consecutive_failures: u32,
}

/// Outcome of an [`PeerManager::add_known_address`] call.
///
/// Lets the caller (gossip ingress, seed bootstrap) distinguish "this
/// address actually entered the dial pool" from "we already had it" so
/// log lines and metrics report real progress instead of just
/// per-spec arrival count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddKnownOutcome {
    /// New entry pushed onto the dial pool.
    Added,
    /// Address was already known and gossip-learned; a seed-trusted
    /// claim arrived, so we upgraded the origin to `Seed`.
    UpgradedToSeed,
    /// Address was already known; no change.
    AlreadyKnown,
    /// Gossip-ingested address rejected by the routability filter
    /// (loopback / RFC1918 / link-local / multicast / port 0). Seed
    /// entries skip this filter — see `origin` on
    /// [`PeerManager::add_known_address`].
    FilteredNonRoutable,
    /// Pool was at [`MAX_KNOWN_ADDRESSES`] and the new entry's
    /// priority did not beat the worst existing entry, so it was
    /// dropped. Mostly fires on gossip floods against a full,
    /// seed-dominated pool.
    DroppedPoolFull,
}

/// Cap on the in-memory `known_addresses` dial pool. Mirrors
/// [`crate::address_book::MAX_PEERS`] (5000) — disk persistence is
/// already capped at that value, so the in-memory mirror should match
/// rather than grow unbounded under gossip flood. A malicious peer
/// spamming `Peers` messages with thousands of declared addresses
/// would otherwise inflate this `Vec` without bound.
pub const MAX_KNOWN_ADDRESSES: usize = 5000;

/// Per-failure backoff schedule (seconds): 30s → 2min → 10min → 30min → 2hr.
/// Capped at the last entry. A dead seed becomes invisible to the dial
/// cycle within ~minutes, freeing the budget for gossiped peers.
const DIAL_BACKOFF_SECS: &[u64] = &[30, 120, 600, 1800, 7200];

/// Periodic peer-gossip interval. Matches Scala's
/// `scorexSettings.network.getPeersInterval` default of 2 minutes. The
/// orchestrator (ergo-node `sync_tick`) is expected to call
/// [`PeerManager::select_peer_for_gossip`] and send `CODE_GET_PEERS` to
/// the returned peer no more frequently than this interval.
pub const GOSSIP_INTERVAL: Duration = Duration::from_secs(120);

/// Eviction priority key for `known_addresses` overflow trim.
/// Lower keys are evicted first. Seed entries always rank top so
/// gossip floods can't displace them; among non-seeds, recently-seen
/// peers rank higher than never-seen, and never-failed rank higher
/// than failure-counted.
pub(super) fn known_peer_keep_priority(p: &KnownPeer) -> (bool, bool, i64) {
    (
        p.origin.is_seed(),
        p.last_seen.is_some(),
        -(p.consecutive_failures as i64),
    )
}

pub(super) fn backoff_for(failures: u32) -> std::time::Duration {
    let idx = (failures.saturating_sub(1) as usize).min(DIAL_BACKOFF_SECS.len() - 1);
    std::time::Duration::from_secs(DIAL_BACKOFF_SECS[idx])
}

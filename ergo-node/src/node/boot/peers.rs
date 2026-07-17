//! Boot phase: peer manager construction, address-book restore, and
//! known-peer seeding.

use ergo_p2p::address_book::AddressBook;
use ergo_p2p::peer_manager::{KnownPeer, PeerManager, PeerOrigin};

use super::super::util::{rand_session_id, wall_to_instant};
use crate::config::NodeConfig;

/// Build the peer manager: a fresh session id, restore of the persistent
/// address book (best-effort — a failure to open/load leaves the node
/// running with empty in-memory peer state rather than failing boot), and
/// seeding of `[peers] known_peers` from config.
///
/// Restore happens before configured-peer seeding so persisted dial state
/// (`last_seen`, backoff, `from_seed`) is preserved; configured seeds
/// re-asserting `from_seed = true` go through the normal write-through path
/// (`book.add_known`) only when novel.
pub(super) fn setup(config: &NodeConfig) -> (i64, PeerManager) {
    let session_id: i64 = rand_session_id();
    let mut peer_manager = PeerManager::new_with_limits(session_id, config.peer_limits);

    match AddressBook::open(&config.data_dir) {
        Ok(book) => {
            let book = std::sync::Arc::new(book);
            match book.load_all() {
                Ok(state) => {
                    let mono_now = std::time::Instant::now();
                    let wall_now = std::time::SystemTime::now();
                    for p in &state.peers {
                        peer_manager.restore_known_peer(KnownPeer {
                            addr: p.addr,
                            last_seen: p.last_seen.map(|t| wall_to_instant(t, mono_now, wall_now)),
                            origin: p.origin,
                            last_failure: p
                                .last_failure
                                .map(|t| wall_to_instant(t, mono_now, wall_now)),
                            consecutive_failures: p.consecutive_failures,
                        });
                    }
                    for b in &state.bans {
                        peer_manager.restore_ban(
                            b.ip,
                            wall_to_instant(b.until, mono_now, wall_now),
                            b.count,
                        );
                    }
                    tracing::info!(
                        peers = state.peers.len(),
                        bans = state.bans.len(),
                        stale_skipped = state.stale_skipped,
                        corrupt_skipped = state.corrupt_skipped,
                        expired_bans_purged = state.expired_bans_purged,
                        "address_book restored",
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "address_book load_all failed; starting with empty in-memory state");
                }
            }
            peer_manager.set_address_book(book);
        }
        Err(e) => {
            tracing::warn!(error = %e, "address_book open failed; running without persistence");
        }
    };

    for addr in &config.known_peers {
        peer_manager.add_known_address(*addr, PeerOrigin::Seed);
    }
    tracing::info!(
        known_peers = config.known_peers.len(),
        "known peers configured"
    );
    tracing::info!(
        max_connections = config.peer_limits.max_connections,
        target_outbound = config.peer_limits.target_outbound,
        max_inbound = config.peer_limits.max_inbound(),
        per_ip = config.peer_limits.per_ip_limit,
        per_subnet = config.peer_limits.per_subnet_limit,
        "peer limits",
    );

    (session_id, peer_manager)
}

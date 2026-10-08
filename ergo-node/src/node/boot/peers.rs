//! Boot phase: peer manager construction, address-book restore, and
//! known-peer seeding.

use ergo_p2p::address_book::{AddressBook, AddressBookError};
use ergo_p2p::peer_manager::{KnownPeer, PeerManager, PeerOrigin};

use super::super::util::{ban_expiry_to_instant, rand_session_id, wall_to_instant};
use crate::config::NodeConfig;
use crate::node::NodeError;

/// Build the peer manager: a fresh session id, restore of the persistent
/// address book (unsupported file formats fail boot; other open/load failures
/// keep the existing best-effort in-memory fallback), and
/// seeding of `[peers] known_peers` from config.
///
/// Restore happens before configured-peer seeding so persisted dial state
/// (`last_seen`, backoff, `from_seed`) is preserved; configured seeds
/// re-asserting `from_seed = true` go through the normal write-through path
/// (`book.add_known`) only when novel.
pub(super) fn setup(config: &NodeConfig) -> Result<(i64, PeerManager), NodeError> {
    let session_id: i64 = rand_session_id();
    let mut peer_manager = PeerManager::new_with_limits(session_id, config.peer_limits);
    // Set before any address is restored, learned, or dialed: it decides
    // which addresses the routability filter admits.
    peer_manager.set_allow_local(config.allow_local);

    match AddressBook::open_at_with_cache(
        &config.data_dir.join("peers.redb"),
        config.redb_cache_budgets.peers,
    ) {
        Ok(book) => {
            let book = std::sync::Arc::new(book);
            match book.load_all(config.allow_local) {
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
                            ban_expiry_to_instant(b.until, mono_now, wall_now),
                            b.count,
                        );
                    }
                    tracing::info!(
                        peers = state.peers.len(),
                        bans = state.bans.len(),
                        stale_skipped = state.stale_skipped,
                        corrupt_skipped = state.corrupt_skipped,
                        nonroutable_purged = state.nonroutable_purged,
                        expired_bans_purged = state.expired_bans_purged,
                        automatic_bans_purged = state.automatic_bans_purged,
                        "address_book restored",
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "address_book load_all failed; starting with empty in-memory state");
                }
            }
            peer_manager.set_address_book(book);
        }
        Err(e @ AddressBookError::UnsupportedFileFormat { .. }) => return Err(e.into()),
        Err(e) => {
            tracing::warn!(error = %e, "address_book open failed; running without persistence");
        }
    };

    for addr in &config.known_peers {
        peer_manager.add_known_address(*addr, PeerOrigin::Seed);
    }
    tracing::info!(
        known_peers = config.known_peers.len(),
        allow_local = config.allow_local,
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

    Ok((session_id, peer_manager))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::time::Instant;

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_startup_restores_persisted_backoff_and_dials_first_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let addrs: Vec<std::net::SocketAddr> = (1..=8)
            .map(|i| format!("127.{i}.0.1:1").parse().unwrap())
            .collect();
        {
            let book =
                std::sync::Arc::new(AddressBook::open_at(&dir.path().join("peers.redb")).unwrap());
            let mut manager = PeerManager::new(1);
            manager.set_address_book(book);
            for addr in &addrs {
                manager.add_known_address(*addr, PeerOrigin::Seed);
                for _ in 0..5 {
                    manager.mark_dial_failed(addr, Instant::now());
                }
            }
        }
        let cli = crate::config::Cli::try_parse_from([
            "ergo-node",
            "--data-dir",
            dir.path().to_str().unwrap(),
        ])
        .unwrap();
        let mut config = NodeConfig::load(cli).unwrap();
        config.known_peers = addrs.clone();
        config.peer_limits.target_outbound = 8;
        let (_, manager) = setup(&config).unwrap();
        assert!(manager.addresses_to_connect(Instant::now(), 32).is_empty());
        let mut state = crate::node::tests::make_state(&dir.path().join("state.redb"));
        state.peer_manager = manager;
        // last_dial_at is fresh, exercising startup even in slow mode.
        super::super::super::peer_actions::try_dial_peers(&mut state);
        assert_eq!(state.peer_manager.peer_count(), 4);
        assert!(state.last_recovery_dial_at.is_some());
        // No await: the spawned dial tasks are dropped without running.
    }
}

use super::*;
use std::net::Ipv4Addr;

fn addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

/// Trusted IPs are no-op for `penalize`. Even a permanent penalty must
/// not transition a trusted peer to `Banned` or remove it from the
/// peer table. Logged at info level; behavior matches Scala's
/// always-reconnect treatment of operator-supplied `knownPeers`.
/// `peers_for_sharing` must rotate the returned subset across calls so
/// every recipient of a `Peers` reply doesn't see the same prefix.
/// Mirrors Scala `PeerManager.scala`'s `Random.shuffle` intent —
/// without it, the gossip share is deterministic per-process and one
/// well-connected peer gets propagated more than others.
/// Inbound peers connect from an ephemeral client port; their listening
/// port is carried in the declared address. Verify that handshake
/// completion records the declared (listening) socket in
/// `known_addresses` so a later dial cycle can reach them after the
/// current session ends. Outbound peers already have their listening
/// address in the pool (that's how the dial found them); the test
/// asserts the inbound case specifically.
#[test]
fn inbound_handshake_persists_declared_for_redial() {
    use crate::handshake::DeclaredAddress;
    let mut mgr = PeerManager::new(42);
    let now = Instant::now();
    // Inbound peer: observed at ephemeral client port 52331, declared
    // at listening port 9030 on a routable address.
    let observed = addr(213, 239, 193, 208, 52331);
    let declared_listening = addr(213, 239, 193, 208, 9030);
    mgr.register_inbound(observed, now).unwrap();
    mgr.mark_tcp_connected(&observed);

    let known_before = mgr.known_addresses_len();
    let spec = PeerSpec {
        agent_name: "remote".into(),
        version: crate::handshake::Version::NIPOPOW,
        node_name: "r".into(),
        declared_address: Some(DeclaredAddress {
            addr: vec![213, 239, 193, 208],
            port: 9030,
        }),
        features: Vec::new(),
    };
    mgr.complete_handshake(&observed, spec, None, now).unwrap();

    let known_after = mgr.known_addresses_len();
    assert_eq!(
        known_after,
        known_before + 1,
        "inbound handshake should add declared listening address to pool",
    );

    // While still connected, the per-IP filter in `check_can_connect`
    // excludes the declared listening port from dial candidates (we're
    // already on that IP via the ephemeral client port). Post-disconnect,
    // the declared address must surface so a future dial cycle can
    // re-reach the peer at its listening port.
    mgr.disconnect(&observed);
    let candidates = mgr.addresses_to_connect(now, 10);
    assert!(
        candidates.contains(&declared_listening),
        "declared listening address must be a future dial candidate post-disconnect, got {candidates:?}",
    );
}

#[test]
fn peers_for_sharing_rotates_across_seeds() {
    use crate::handshake::DeclaredAddress;
    let mut mgr = PeerManager::new(7);
    let now = Instant::now();
    // Four routable peers — enough that limit=2 leaves two-out-of-four
    // combinations; rotation starts at `seed % 4` so different seeds
    // pick distinguishable subsets.
    let peers = [
        (addr(213, 239, 193, 208, 9030), [213u8, 239, 193, 208]),
        (addr(45, 33, 102, 17, 9030), [45, 33, 102, 17]),
        (addr(159, 65, 11, 55, 9030), [159, 65, 11, 55]),
        (addr(78, 47, 9, 200, 9030), [78, 47, 9, 200]),
    ];
    let mk_spec = |octets: [u8; 4]| PeerSpec {
        agent_name: "n".into(),
        version: crate::handshake::Version::NIPOPOW,
        node_name: "x".into(),
        declared_address: Some(DeclaredAddress {
            addr: octets.to_vec(),
            port: 9030,
        }),
        features: Vec::new(),
    };
    for (a, octets) in &peers {
        mgr.register_outbound(*a, now).unwrap();
        mgr.mark_tcp_connected(a);
        mgr.complete_handshake(a, mk_spec(*octets), None, now)
            .unwrap();
    }

    // Sort key is declared-address bytes: 45.33.102.17 < 78.47.9.200
    // < 159.65.11.55 < 213.239.193.208. seed=0 starts at index 0,
    // seed=1 at index 1, etc. Each rotation is contiguous-modulo-len.
    let s0 = mgr.peers_for_sharing(2, 0);
    let s1 = mgr.peers_for_sharing(2, 1);
    assert_eq!(s0.len(), 2);
    assert_eq!(s1.len(), 2);
    let first_addr_s0 = s0[0].declared_address.as_ref().unwrap().addr.clone();
    let first_addr_s1 = s1[0].declared_address.as_ref().unwrap().addr.clone();
    assert_ne!(
        first_addr_s0, first_addr_s1,
        "different seeds must pick different leading peers",
    );
}

#[test]
fn select_peer_for_gossip_rotates_with_seed() {
    // Different seeds modulo the eligible-peer count must select
    // different peers — pins the random-rotation contract so a
    // silent-but-connected peer can't monopolize gossip rounds.
    let mut mgr = PeerManager::new(12345);
    let a = addr(10, 0, 0, 10, 9030);
    let b = addr(10, 0, 0, 11, 9030);
    let now = Instant::now();
    mgr.register_outbound(a, now).unwrap();
    mgr.mark_tcp_connected(&a);
    mgr.complete_handshake(&a, spec(), None, now).unwrap();
    mgr.register_outbound(b, now).unwrap();
    mgr.mark_tcp_connected(&b);
    mgr.complete_handshake(&b, spec(), None, now).unwrap();

    // Eligible peers sorted by SocketAddr → [a, b]. seed=0 → a, seed=1 → b.
    assert_eq!(mgr.select_peer_for_gossip(now, 0), Some(a));
    assert_eq!(mgr.select_peer_for_gossip(now, 1), Some(b));
    assert_eq!(mgr.select_peer_for_gossip(now, 2), Some(a));
    assert_eq!(mgr.select_peer_for_gossip(now, 3), Some(b));
}

#[test]
fn select_peer_for_gossip_none_when_empty() {
    let mgr = PeerManager::new(12345);
    assert_eq!(mgr.select_peer_for_gossip(Instant::now(), 0), None);
}

#[test]
fn gossip_interval_matches_scala_default() {
    // Scala's `scorexSettings.network.getPeersInterval` defaults to
    // 2 minutes. Pin so a refactor that shortens the gate doesn't
    // silently triple our gossip traffic.
    assert_eq!(GOSSIP_INTERVAL, Duration::from_secs(120));
}

fn unique_addr(i: usize) -> SocketAddr {
    let n = i as u8;
    addr(1 + n, n, n, n, 9030)
}

fn spec() -> PeerSpec {
    PeerSpec {
        agent_name: "test".into(),
        version: crate::handshake::Version::NIPOPOW,
        node_name: "node".into(),
        declared_address: None,
        features: Vec::new(),
    }
}

#[test]
fn register_and_handshake() {
    let mut mgr = PeerManager::new(12345);
    let now = Instant::now();
    let a = addr(10, 0, 0, 1, 9030);

    mgr.register_outbound(a, now).unwrap();
    assert_eq!(mgr.peer_count(), 1);
    assert_eq!(mgr.connected_count(), 0); // not yet handshaked

    mgr.mark_tcp_connected(&a);
    mgr.complete_handshake(&a, spec(), None, now).unwrap();
    assert_eq!(mgr.connected_count(), 1);
}

#[test]
fn per_ip_limit_enforced() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a1 = addr(10, 0, 0, 1, 9030);
    let a2 = addr(10, 0, 0, 1, 9031); // same IP, different port

    mgr.register_outbound(a1, now).unwrap();
    let result = mgr.register_outbound(a2, now);
    assert_eq!(result, Err(ConnectError::PerIpLimitReached));
}

#[test]
fn per_subnet_limit_enforced() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    // Same /16 subnet: 10.0.x.x
    mgr.register_outbound(addr(10, 0, 0, 1, 9030), now).unwrap();
    mgr.register_outbound(addr(10, 0, 0, 2, 9030), now).unwrap();
    mgr.register_outbound(addr(10, 0, 0, 3, 9030), now).unwrap();
    let result = mgr.register_outbound(addr(10, 0, 0, 4, 9030), now);
    assert_eq!(result, Err(ConnectError::PerSubnetLimitReached));
}

#[test]
fn max_connections_enforced() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    for i in 0..DEFAULT_MAX_CONNECTIONS {
        mgr.register_outbound(unique_addr(i), now).unwrap();
    }
    let result = mgr.register_outbound(addr(200, 200, 200, 200, 9030), now);
    assert_eq!(result, Err(ConnectError::TooManyConnections));
}

#[test]
fn self_connection_rejected() {
    let mut mgr = PeerManager::new(42);
    let now = Instant::now();
    let a = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a, now).unwrap();
    mgr.mark_tcp_connected(&a);
    let result = mgr.complete_handshake(&a, spec(), Some(42), now);
    assert_eq!(result, Err(ConnectError::SelfConnection));
}

#[test]
fn version_too_old_rejected() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a, now).unwrap();
    mgr.mark_tcp_connected(&a);
    let old_spec = PeerSpec {
        version: crate::handshake::Version {
            major: 3,
            minor: 0,
            patch: 0,
        },
        ..spec()
    };
    let result = mgr.complete_handshake(&a, old_spec, None, now);
    assert!(matches!(result, Err(ConnectError::VersionTooOld(_))));
}

#[test]
fn penalize_and_ban() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a, now).unwrap();
    mgr.mark_tcp_connected(&a);
    mgr.complete_handshake(&a, spec(), None, now).unwrap();

    let mut t = now;
    // Push above Scala's 500-point ban threshold with spam penalties (+25 each).
    // Need enough to overcome decay (10 per 10min).
    for _ in 0..25 {
        t += crate::peer::SAFE_INTERVAL;
        mgr.penalize(&a, Penalty::Spam, t);
    }
    assert_eq!(mgr.peer_count(), 0, "peer should be removed after ban");
}

#[test]
fn evict_timed_out() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a, now).unwrap();
    // Still in Connecting state — times out after 5s
    let evicted =
        mgr.evict_timed_out(now + crate::peer::CONNECT_TIMEOUT + std::time::Duration::from_secs(1));
    assert_eq!(evicted, vec![a]);
    assert_eq!(mgr.peer_count(), 0);
}

#[test]
fn peer_selection_prefers_active() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a1 = addr(10, 0, 0, 1, 9030);
    let a2 = addr(10, 0, 1, 1, 9030);

    mgr.register_outbound(a1, now).unwrap();
    mgr.mark_tcp_connected(&a1);
    mgr.complete_handshake(&a1, spec(), None, now).unwrap();

    mgr.register_outbound(a2, now).unwrap();
    mgr.mark_tcp_connected(&a2);
    mgr.complete_handshake(&a2, spec(), None, now).unwrap();

    // Touch a2 more recently
    mgr.touch(&a2, now + std::time::Duration::from_secs(1));

    let selected = mgr.select_peer_for_download(now + std::time::Duration::from_secs(2));
    assert_eq!(selected, Some(a2));
}

#[test]
fn addresses_to_connect_skips_per_ip_collisions() {
    // Regression: gossip routinely surfaces alternate-port variants
    // of an already-connected IP. Pre-fix, those sat in the pool,
    // got reselected each dial cycle, and were rejected by
    // `register_outbound`'s per-IP gate without ever being backed
    // off — burning the per-cycle dial budget on guaranteed-failures.
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let primary = addr(203, 0, 113, 1, 9030);
    let alt_port = addr(203, 0, 113, 1, 9020); // same IP, different port
    let other = addr(203, 0, 113, 2, 9030);

    mgr.add_known_address(primary, PeerOrigin::Seed);
    mgr.add_known_address(alt_port, PeerOrigin::Seed);
    mgr.add_known_address(other, PeerOrigin::Seed);

    // Before any connection: all three are eligible.
    assert_eq!(
        mgr.addresses_to_connect(now, 10),
        vec![primary, alt_port, other]
    );

    // Connect to primary. `alt_port` shares its IP and would fail
    // `register_outbound` with `PerIpLimitReached`, so it must be
    // filtered out here.
    mgr.register_outbound(primary, now).unwrap();
    assert_eq!(mgr.addresses_to_connect(now, 10), vec![other]);
}

#[test]
fn addresses_to_connect_skips_per_subnet_saturation() {
    // The /16 subnet limit (default 3) is also enforced upfront so
    // dial-budget isn't wasted. With three peers in 203.0.113.0/16,
    // a fourth gossiped candidate from the same /16 must be filtered
    // before `register_outbound` sees it.
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    for i in 1..=3u8 {
        let a = addr(203, 0, 113, i, 9030);
        mgr.add_known_address(a, PeerOrigin::Seed);
        mgr.register_outbound(a, now).unwrap();
    }
    let fourth = addr(203, 0, 113, 4, 9030);
    mgr.add_known_address(fourth, PeerOrigin::Seed);

    // Subnet is full — the fourth candidate is filtered out, even
    // though it has a fresh IP.
    assert!(mgr.addresses_to_connect(now, 10).is_empty());
}

#[test]
fn known_addresses_for_discovery() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    // Use TEST-NET-3 (203.0.113/24) — reserved-for-documentation
    // routable IPs that pass the routability filter without being
    // real public hosts. Pre-routability-filter the test used 10/8.
    let a1 = addr(203, 0, 113, 1, 9030);
    let a2 = addr(203, 0, 113, 2, 9030);

    mgr.add_known_address(a1, PeerOrigin::Seed);
    mgr.add_known_address(a2, PeerOrigin::Gossip);
    mgr.add_known_address(a1, PeerOrigin::Seed); // duplicate — should not add

    let to_connect = mgr.addresses_to_connect(now, 10);
    assert_eq!(to_connect.len(), 2);

    // Connect to a1 — should not appear in to_connect list
    mgr.register_outbound(a1, now).unwrap();
    let to_connect = mgr.addresses_to_connect(now, 10);
    assert_eq!(to_connect.len(), 1);
    assert_eq!(to_connect[0], a2);
}

#[test]
fn add_known_address_caps_dial_pool_under_gossip_flood() {
    // Regression: an unbounded Vec under gossip flood is a memory
    // DoS vector. Cap is `MAX_KNOWN_ADDRESSES`; the eviction rule
    // protects seeds first, then by `(last_seen, -failures)`.
    let mut mgr = PeerManager::new(1);

    // Fill exactly to cap with synthetic gossip entries (RFC5737
    // TEST-NET-1 198.51.100/24 is documentation-routable; pad with
    // TEST-NET-3 203.0.113/24 for the second 256-entry block).
    // Use port to disambiguate within a /24 since
    // `add_known_address` keys on full SocketAddr.
    let mut count = 0usize;
    'outer: for octet in 1..=255u8 {
        for port in 9030u16..=u16::MAX {
            if count >= MAX_KNOWN_ADDRESSES {
                break 'outer;
            }
            mgr.add_known_address(addr(198, 51, 100, octet, port), PeerOrigin::Gossip);
            count += 1;
        }
    }
    assert_eq!(mgr.known_addresses_len(), MAX_KNOWN_ADDRESSES);

    // Pushing another gossip entry must NOT grow the pool.
    let extra_gossip = addr(203, 0, 113, 1, 9030);
    mgr.add_known_address(extra_gossip, PeerOrigin::Gossip);
    assert_eq!(
        mgr.known_addresses_len(),
        MAX_KNOWN_ADDRESSES,
        "gossip flood must not grow the pool past the cap"
    );
    // The drop-when-no-better rule: incoming gossip with no
    // seed/last_seen advantage is rejected outright, so the
    // extra address never appears.
    assert!(
        !mgr.known_addresses.iter().any(|k| k.addr == extra_gossip),
        "incoming gossip at cap must be dropped"
    );

    // A seed claim, however, must displace the lowest-priority
    // gossip entry to make room.
    let seed_addr = addr(203, 0, 113, 99, 9030);
    mgr.add_known_address(seed_addr, PeerOrigin::Seed);
    assert_eq!(
        mgr.known_addresses_len(),
        MAX_KNOWN_ADDRESSES,
        "seed insertion must evict + push, not grow the pool"
    );
    assert!(
        mgr.known_addresses
            .iter()
            .any(|k| k.addr == seed_addr && k.origin.is_seed()),
        "seed entry must be present after eviction"
    );
}

#[test]
fn add_known_address_upgrades_gossip_learned_to_seed_on_duplicate() {
    // Regression: previously a duplicate `add_known_address` call
    // returned silently regardless of `origin`, leaving an
    // entry first learned via gossip stuck at `Gossip`
    // even when the same address appeared in the configured seed
    // list. AddressBook (the persistence layer) already upgrades
    // on the same shape (`address_book.rs:395-407`); this fixes
    // the in-memory mirror to match.
    let mut mgr = PeerManager::new(1);
    let a = addr(203, 0, 113, 1, 9030);

    // First learned via gossip (origin=Gossip).
    mgr.add_known_address(a, PeerOrigin::Gossip);
    let entry = mgr
        .known_addresses
        .iter()
        .find(|k| k.addr == a)
        .expect("entry inserted");
    assert!(
        !entry.origin.is_seed(),
        "initial gossip ingest must keep origin=Gossip"
    );

    // Same address now appears in the seed list — must upgrade.
    mgr.add_known_address(a, PeerOrigin::Seed);
    let entry = mgr
        .known_addresses
        .iter()
        .find(|k| k.addr == a)
        .expect("entry still present");
    assert!(
        entry.origin.is_seed(),
        "duplicate add_known_address(_, Seed) must upgrade gossip → seed"
    );

    // No duplication.
    assert_eq!(
        mgr.known_addresses.iter().filter(|k| k.addr == a).count(),
        1,
        "upgrade must be in-place, not duplicate the entry"
    );

    // Reverse direction (seed → gossip claim) must NOT downgrade.
    mgr.add_known_address(a, PeerOrigin::Gossip);
    let entry = mgr
        .known_addresses
        .iter()
        .find(|k| k.addr == a)
        .expect("entry still present");
    assert!(
        entry.origin.is_seed(),
        "seed status must be sticky against later gossip claims"
    );
}

/// Pins the typed outcomes node-level diagnostics depend on. Every
/// branch of `add_known_address` must report itself accurately so
/// the `[peers] recv` counters distinguish real progress from
/// gossip echo.
#[test]
fn add_known_address_outcome_taxonomy_is_complete() {
    let mut mgr = PeerManager::new(1);
    let routable = addr(203, 0, 113, 1, 9030);

    assert_eq!(
        mgr.add_known_address(routable, PeerOrigin::Gossip),
        AddKnownOutcome::Added,
        "first-time gossip ingest of a routable address",
    );
    assert_eq!(
        mgr.add_known_address(routable, PeerOrigin::Gossip),
        AddKnownOutcome::AlreadyKnown,
        "duplicate gossip ingest must be reported as already-known",
    );
    assert_eq!(
        mgr.add_known_address(routable, PeerOrigin::Seed),
        AddKnownOutcome::UpgradedToSeed,
        "seed claim against an existing gossip entry must upgrade",
    );
    assert_eq!(
        mgr.add_known_address(routable, PeerOrigin::Seed),
        AddKnownOutcome::AlreadyKnown,
        "second seed claim against an already-seed entry is a no-op",
    );

    // Non-routable gossip — RFC1918 — must surface as filtered.
    let private_addr = addr(10, 0, 0, 5, 9030);
    assert_eq!(
        mgr.add_known_address(private_addr, PeerOrigin::Gossip),
        AddKnownOutcome::FilteredNonRoutable,
        "RFC1918 gossip must be reported as filtered, not silently dropped",
    );

    // Same RFC1918 address with `PeerOrigin::Seed` skips the filter
    // (the user might be running a local Scala dev peer) and is
    // accepted as Added.
    assert_eq!(
        mgr.add_known_address(private_addr, PeerOrigin::Seed),
        AddKnownOutcome::Added,
        "seed claim bypasses routability filter for legitimate local peers",
    );
}

#[test]
fn dial_failure_backoff_skips_recently_failed_until_window_elapses() {
    // Regression: dead seeds were dominating the dial cycle every
    // tick because addresses_to_connect returned them in insertion
    // order with no failure-aware filtering. Gossiped peers behind
    // them in the list never got a chance.
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let dead = addr(203, 0, 113, 1, 9030);
    let live = addr(203, 0, 113, 2, 9030);

    mgr.add_known_address(dead, PeerOrigin::Seed);
    mgr.add_known_address(live, PeerOrigin::Gossip);

    // Both visible initially.
    let candidates = mgr.addresses_to_connect(now, 10);
    assert_eq!(candidates, vec![dead, live]);

    // First failure: dead is suppressed for the first backoff window
    // (30s); live is still visible.
    mgr.mark_dial_failed(&dead, now);
    let after_first = mgr.addresses_to_connect(now, 10);
    assert_eq!(
        after_first,
        vec![live],
        "dead address suppressed during backoff, live still visible"
    );

    // Just before the window expires, dead is still suppressed.
    let almost = now + std::time::Duration::from_secs(29);
    assert_eq!(mgr.addresses_to_connect(almost, 10), vec![live]);

    // After the window, dead becomes eligible again.
    let elapsed = now + std::time::Duration::from_secs(31);
    let candidates = mgr.addresses_to_connect(elapsed, 10);
    assert_eq!(candidates, vec![dead, live]);

    // Another failure escalates the backoff (30s → 2min).
    mgr.mark_dial_failed(&dead, elapsed);
    assert_eq!(
        mgr.addresses_to_connect(elapsed + std::time::Duration::from_secs(60), 10),
        vec![live],
        "second failure → 2min backoff, 1min later still suppressed"
    );
    assert_eq!(
        mgr.addresses_to_connect(elapsed + std::time::Duration::from_secs(125), 10),
        vec![dead, live],
        "after 2min, retried"
    );
}

#[test]
fn dial_success_resets_backoff_state() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a = addr(203, 0, 113, 1, 9030);
    mgr.add_known_address(a, PeerOrigin::Seed);

    // Two failures escalate to a 2min backoff.
    mgr.mark_dial_failed(&a, now);
    mgr.mark_dial_failed(&a, now);
    assert!(
        mgr.addresses_to_connect(now + std::time::Duration::from_secs(60), 10)
            .is_empty(),
        "still suppressed at 1min into 2min backoff"
    );

    // Success resets — address is immediately eligible again on next attempt.
    mgr.mark_dial_succeeded(&a, now);
    assert_eq!(mgr.addresses_to_connect(now, 10), vec![a]);
}

#[test]
fn needs_outbound_tracks_target() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    assert!(mgr.needs_outbound());

    for i in 0..DEFAULT_TARGET_OUTBOUND {
        mgr.register_outbound(unique_addr(i), now).unwrap();
    }
    assert!(!mgr.needs_outbound());
}

#[test]
fn s4_outbound_deficit_matches_missing_outbound_count() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    assert_eq!(mgr.outbound_deficit(), DEFAULT_TARGET_OUTBOUND);

    // Each outbound register reduces deficit by one.
    for i in 0..(DEFAULT_TARGET_OUTBOUND - 2) {
        mgr.register_outbound(unique_addr(i), now).unwrap();
    }
    assert_eq!(mgr.outbound_deficit(), 2);

    // Fill to the target: deficit hits 0 and stays there even if
    // more outbound connections happen above the target.
    mgr.register_outbound(addr(250, 0, 0, 1, 9030), now)
        .unwrap();
    mgr.register_outbound(addr(250, 0, 0, 2, 9030), now)
        .unwrap();
    assert_eq!(mgr.outbound_deficit(), 0);
}

#[test]
fn inbound_slot_limit_reserves_outbound() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    // Fill inbound to the max (DEFAULT_MAX_CONNECTIONS - DEFAULT_TARGET_OUTBOUND).
    let max_inbound = DEFAULT_MAX_CONNECTIONS - DEFAULT_TARGET_OUTBOUND;
    assert_eq!(max_inbound, 20);
    for i in 0..max_inbound {
        mgr.register_inbound(unique_addr(i), now).unwrap();
    }
    // Next inbound should fail — outbound slots are reserved
    let result = mgr.register_inbound(addr(200, 200, 200, 200, 9030), now);
    assert_eq!(result, Err(ConnectError::TooManyInbound));
    // But outbound should still work
    let result = mgr.register_outbound(addr(201, 201, 201, 201, 9030), now);
    assert!(result.is_ok());
}

#[test]
fn custom_limits_drive_outbound_target_and_inbound_reserve() {
    let limits = PeerLimits {
        max_connections: 12,
        target_outbound: 7,
        per_ip_limit: 1,
        per_subnet_limit: 3,
    };
    let mut mgr = PeerManager::new_with_limits(1, limits);
    let now = Instant::now();

    assert_eq!(mgr.limits(), limits);
    assert_eq!(mgr.outbound_deficit(), 7);

    for i in 0..5 {
        mgr.register_inbound(unique_addr(i), now).unwrap();
    }
    assert_eq!(
        mgr.register_inbound(unique_addr(5), now),
        Err(ConnectError::TooManyInbound),
    );

    for i in 5..12 {
        mgr.register_outbound(unique_addr(i), now).unwrap();
    }
    assert_eq!(mgr.outbound_deficit(), 0);
}

#[test]
fn ban_survives_disconnect() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a, now).unwrap();
    mgr.mark_tcp_connected(&a);
    mgr.complete_handshake(&a, spec(), None, now).unwrap();

    // Push above Scala's 500-point ban threshold.
    let mut t = now;
    for _ in 0..25 {
        t += crate::peer::SAFE_INTERVAL;
        mgr.penalize(&a, Penalty::Spam, t);
    }
    // Peer removed from table
    assert_eq!(mgr.peer_count(), 0);
    // But still banned — can't reconnect
    assert!(mgr.is_banned(&a, t));
    let result = mgr.register_outbound(a, t);
    assert_eq!(result, Err(ConnectError::Banned));
    // Ban also excludes from discovery
    mgr.add_known_address(a, PeerOrigin::Gossip);
    assert!(mgr.addresses_to_connect(t, 10).is_empty());
}

#[test]
fn ban_expires_after_duration() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a, now).unwrap();
    mgr.mark_tcp_connected(&a);
    mgr.complete_handshake(&a, spec(), None, now).unwrap();

    let mut t = now;
    for _ in 0..25 {
        t += crate::peer::SAFE_INTERVAL;
        mgr.penalize(&a, Penalty::Spam, t);
    }
    assert!(mgr.is_banned(&a, t));
    // First ban is 30 minutes — should expire after that
    let after_ban = t + Duration::from_secs(31 * 60);
    assert!(!mgr.is_banned(&a, after_ban));
    // Can reconnect now
    assert!(mgr.register_outbound(a, after_ban).is_ok());
}

#[test]
fn version_too_old_frees_slot_and_bans() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a, now).unwrap();
    assert_eq!(mgr.peer_count(), 1);
    mgr.mark_tcp_connected(&a);
    let old_spec = PeerSpec {
        version: crate::handshake::Version {
            major: 3,
            minor: 0,
            patch: 0,
        },
        ..spec()
    };
    let _ = mgr.complete_handshake(&a, old_spec, None, now);
    // Slot freed
    assert_eq!(mgr.peer_count(), 0);
    // Permanently banned
    assert!(mgr.is_banned(&a, now));
    assert!(mgr.is_banned(&a, now + Duration::from_secs(86400))); // still banned after 24h
}

#[test]
fn select_peer_excluding_skips_excluded() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a1 = addr(10, 0, 0, 1, 9030);
    let a2 = addr(10, 0, 1, 1, 9030);

    mgr.register_outbound(a1, now).unwrap();
    mgr.mark_tcp_connected(&a1);
    mgr.complete_handshake(&a1, spec(), None, now).unwrap();

    mgr.register_outbound(a2, now).unwrap();
    mgr.mark_tcp_connected(&a2);
    mgr.complete_handshake(&a2, spec(), None, now).unwrap();

    // Without exclusion, returns top candidate
    let selected = mgr.select_peer_for_download(now);
    assert!(selected.is_some());

    // Excluding top candidate should return the other
    let top = selected.unwrap();
    let alt = mgr.select_peer_excluding(now, &[top]);
    assert!(alt.is_some());
    assert_ne!(alt.unwrap(), top, "should select a different peer");

    // Excluding both returns None
    let none = mgr.select_peer_excluding(now, &[a1, a2]);
    assert!(none.is_none());
}

// ---- Sync-S1: eligible_download_peers ----

#[test]
fn eligible_download_peers_empty_when_no_connected() {
    let mgr = PeerManager::new(1);
    let out = mgr.eligible_download_peers(Instant::now());
    assert!(out.is_empty(), "fresh manager → no eligible peers");
}

#[test]
fn eligible_download_peers_sorted_by_socket_addr() {
    // Deterministic ordering is the contract for bucketed distribution.
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    // Register out of sorted order.
    let a_high = addr(10, 0, 1, 1, 9030);
    let a_low = addr(10, 0, 0, 1, 9030);
    let a_mid = addr(10, 0, 0, 5, 9030);
    for a in [a_high, a_low, a_mid] {
        mgr.register_outbound(a, now).unwrap();
        mgr.mark_tcp_connected(&a);
        mgr.complete_handshake(&a, spec(), None, now).unwrap();
    }

    let out = mgr.eligible_download_peers(now);
    assert_eq!(
        out,
        vec![a_low, a_mid, a_high],
        "eligible_download_peers must sort by SocketAddr (IP bytes + port)"
    );
}

#[test]
fn eligible_download_peers_prefers_non_degraded() {
    // When at least one non-degraded peer is connected, degraded
    // peers are excluded from the download pool.
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a1 = addr(10, 0, 0, 1, 9030);
    let a2 = addr(10, 0, 1, 1, 9030);
    for a in [a1, a2] {
        mgr.register_outbound(a, now).unwrap();
        mgr.mark_tcp_connected(&a);
        mgr.complete_handshake(&a, spec(), None, now).unwrap();
    }

    // Push a2 over the Degraded threshold.
    let mut t = now;
    while mgr
        .connected_peers()
        .find(|p| p.addr == a2)
        .map(|p| p.score.effective_score(t))
        .unwrap_or(0)
        < DEGRADED_THRESHOLD
    {
        mgr.penalize(&a2, Penalty::Spam, t);
        t += Duration::from_secs(180);
    }

    let out = mgr.eligible_download_peers(t);
    assert_eq!(
        out,
        vec![a1],
        "non-degraded a1 preferred; a2 excluded, got {out:?}"
    );
}

#[test]
fn eligible_download_peers_falls_back_to_degraded_when_no_alternative() {
    // Checklist contract: "bucketed by last-seen, falls back to
    // degraded". When EVERY connected peer is degraded, return them
    // all rather than stalling sync.
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a1 = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a1, now).unwrap();
    mgr.mark_tcp_connected(&a1);
    mgr.complete_handshake(&a1, spec(), None, now).unwrap();

    let mut t = now;
    while mgr
        .connected_peers()
        .find(|p| p.addr == a1)
        .map(|p| p.score.effective_score(t))
        .unwrap_or(0)
        < DEGRADED_THRESHOLD
    {
        mgr.penalize(&a1, Penalty::Spam, t);
        t += Duration::from_secs(180);
    }

    let out = mgr.eligible_download_peers(t);
    assert_eq!(
        out,
        vec![a1],
        "degraded fallback must yield a1 when no alternative, got {out:?}"
    );
}

#[test]
fn eligible_download_peers_excludes_not_yet_handshaked() {
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a, now).unwrap();
    mgr.mark_tcp_connected(&a);
    // Skip complete_handshake — peer is TCP-connected but not
    // fully connected per is_connected()'s handshake gate.

    let out = mgr.eligible_download_peers(now);
    assert!(
        out.is_empty(),
        "pre-handshake peer must not be in download pool, got {out:?}"
    );
}

#[test]
fn eligible_download_peers_deprioritizes_delivery_degraded_peer() {
    // A peer that repeatedly times out on delivery (but never accrues
    // enough score to degrade) is dropped from the preferred pool once its
    // streak reaches DELIVERY_DEGRADE_STREAK, and restored the moment it
    // delivers. The same gate also fronts block_section_capable_peers.
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a1 = addr(10, 0, 0, 1, 9030);
    let a2 = addr(10, 0, 1, 1, 9030);
    for a in [a1, a2] {
        mgr.register_outbound(a, now).unwrap();
        mgr.mark_tcp_connected(&a);
        mgr.complete_handshake(&a, spec(), None, now).unwrap();
    }

    // a2 fails to deliver up to the streak threshold. Its score stays clear
    // of DEGRADED (no penalize call), so only the streak gate can exclude it.
    for _ in 0..DELIVERY_DEGRADE_STREAK {
        mgr.note_delivery_outcome(&a2, false);
    }
    assert_eq!(
        mgr.eligible_download_peers(now),
        vec![a1],
        "delivery-degraded a2 must be excluded from the preferred pool"
    );

    // One accepted delivery clears the streak and restores a2.
    mgr.note_delivery_outcome(&a2, true);
    assert_eq!(
        mgr.eligible_download_peers(now),
        vec![a1, a2],
        "a2 must rejoin the preferred pool after a successful delivery"
    );
}

#[test]
fn eligible_download_peers_falls_back_when_all_delivery_degraded() {
    // If every connected peer is delivery-degraded, fall back to using them
    // rather than stalling sync — mirrors the score-degraded fallback.
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a1 = addr(10, 0, 0, 1, 9030);
    mgr.register_outbound(a1, now).unwrap();
    mgr.mark_tcp_connected(&a1);
    mgr.complete_handshake(&a1, spec(), None, now).unwrap();

    for _ in 0..DELIVERY_DEGRADE_STREAK {
        mgr.note_delivery_outcome(&a1, false);
    }
    assert_eq!(
        mgr.eligible_download_peers(now),
        vec![a1],
        "delivery-degraded fallback must yield a1 when it's the only peer"
    );
}

#[test]
fn block_section_capable_peers_falls_back_to_delivery_degraded_archives() {
    // Capability (full archive) is a hard requirement; the streak is a soft
    // preference. When every archive peer is delivery-degraded we must still
    // return them — they're the only peers that have the sections — rather
    // than an empty set that would route requests to incapable peers.
    let archive_spec = || {
        let mut s = spec();
        s.features = vec![crate::handshake::PeerFeature::Mode {
            state_type: 0,
            verify_tx: true,
            nipopow: None,
            blocks_to_keep: -1,
        }];
        s
    };
    let mut mgr = PeerManager::new(1);
    let now = Instant::now();
    let a1 = addr(10, 0, 0, 1, 9030);
    let a2 = addr(10, 0, 1, 1, 9030);
    for a in [a1, a2] {
        mgr.register_outbound(a, now).unwrap();
        mgr.mark_tcp_connected(&a);
        mgr.complete_handshake(&a, archive_spec(), None, now)
            .unwrap();
    }

    // Both healthy archives → both preferred.
    assert_eq!(mgr.block_section_capable_peers(now), vec![a1, a2]);

    // Degrade a2 only → healthy a1 preferred, degraded a2 excluded.
    for _ in 0..DELIVERY_DEGRADE_STREAK {
        mgr.note_delivery_outcome(&a2, false);
    }
    assert_eq!(
        mgr.block_section_capable_peers(now),
        vec![a1],
        "healthy archive preferred; degraded archive excluded"
    );

    // Degrade a1 too → all archives degraded → fall back to ALL capable
    // peers (never empty, or sections would go to peers without the data).
    for _ in 0..DELIVERY_DEGRADE_STREAK {
        mgr.note_delivery_outcome(&a1, false);
    }
    assert_eq!(
        mgr.block_section_capable_peers(now),
        vec![a1, a2],
        "all archives degraded → fall back to all capable, not empty"
    );
}

// ---- Routability filter (tip-hardening) ----

#[test]
fn is_routable_rejects_rfc1918_and_private_categories() {
    // RFC1918 — the exact case from prod logs (10.0.0.8:9030 leak).
    assert!(!is_routable_for_p2p(&addr(10, 0, 0, 8, 9030)));
    assert!(!is_routable_for_p2p(&addr(192, 168, 1, 1, 9030)));
    assert!(!is_routable_for_p2p(&addr(172, 16, 5, 5, 9030)));
    // Loopback / unspecified / multicast.
    assert!(!is_routable_for_p2p(&addr(127, 0, 0, 1, 9030)));
    assert!(!is_routable_for_p2p(&addr(0, 0, 0, 0, 9030)));
    assert!(!is_routable_for_p2p(&addr(224, 0, 0, 1, 9030)));
    // Link-local.
    assert!(!is_routable_for_p2p(&addr(169, 254, 1, 1, 9030)));
    // Carrier-grade NAT.
    assert!(!is_routable_for_p2p(&addr(100, 64, 1, 1, 9030)));
    assert!(!is_routable_for_p2p(&addr(100, 127, 255, 254, 9030)));
    // Port 0 — not dialable.
    assert!(!is_routable_for_p2p(&addr(213, 239, 193, 208, 0)));

    // Real public seed addresses must pass.
    assert!(is_routable_for_p2p(&addr(213, 239, 193, 208, 9030)));
    assert!(is_routable_for_p2p(&addr(159, 65, 11, 55, 9030)));
    // 100.x outside the CGNAT band is fine.
    assert!(is_routable_for_p2p(&addr(100, 200, 1, 1, 9030)));
}

#[test]
fn is_routable_handles_ipv6_categories() {
    use std::net::Ipv6Addr;
    let v6 = |ip: &str, port: u16| -> SocketAddr {
        SocketAddr::new(IpAddr::V6(ip.parse::<Ipv6Addr>().unwrap()), port)
    };
    // Public IPv6 (one of our hardcoded seeds).
    assert!(is_routable_for_p2p(&v6("2001:41d0:700:6662::", 29031)));
    // Loopback / unspecified / link-local / unique-local.
    assert!(!is_routable_for_p2p(&v6("::1", 9030)));
    assert!(!is_routable_for_p2p(&v6("::", 9030)));
    assert!(!is_routable_for_p2p(&v6("fe80::1", 9030)));
    assert!(!is_routable_for_p2p(&v6("fc00::1", 9030)));
    assert!(!is_routable_for_p2p(&v6("fd12:3456:789a::1", 9030)));
    // Multicast.
    assert!(!is_routable_for_p2p(&v6("ff02::1", 9030)));
}

#[test]
fn add_known_address_drops_non_routable_from_gossip_only() {
    // Policy split: routability filter applies to GOSSIP ingress
    // (origin=Gossip), not to user-configured peers (origin=Seed).
    let mut mgr = PeerManager::new(1);

    // Routable bootstrap seed — accepted under either flag.
    mgr.add_known_address(addr(213, 239, 193, 208, 9030), PeerOrigin::Seed);

    // Gossiped non-routables — silently dropped.
    mgr.add_known_address(addr(10, 0, 0, 8, 9030), PeerOrigin::Gossip);
    mgr.add_known_address(addr(192, 168, 1, 1, 9030), PeerOrigin::Gossip);
    mgr.add_known_address(addr(127, 0, 0, 1, 9030), PeerOrigin::Gossip);
    mgr.add_known_address(addr(0, 0, 0, 0, 9030), PeerOrigin::Gossip);

    let pool = mgr.addresses_to_connect(Instant::now(), 100);
    assert_eq!(
        pool,
        vec![addr(213, 239, 193, 208, 9030)],
        "gossiped non-routable addresses must not enter the dial pool"
    );
}

#[test]
fn add_known_address_keeps_user_configured_loopback_and_lan() {
    // Regression: an earlier version of the routability filter
    // applied to all add_known_address callers, silently dropping
    // user-configured `127.0.0.1:9030` (co-located Scala node) and
    // dev/staging LAN peers like `10.0.0.8:9030`. Both must be
    // preserved when `origin=Seed`.
    let mut mgr = PeerManager::new(1);

    let cases = &[
        addr(127, 0, 0, 1, 9030),       // loopback Scala node
        addr(10, 0, 0, 8, 9030),        // LAN dev/staging peer
        addr(192, 168, 1, 50, 9030),    // home-LAN peer
        addr(213, 239, 193, 208, 9030), // public bootstrap seed
    ];
    for a in cases {
        mgr.add_known_address(*a, PeerOrigin::Seed);
    }

    let pool = mgr.addresses_to_connect(Instant::now(), 100);
    assert_eq!(
        pool.len(),
        cases.len(),
        "all user-configured peers must be retained, got pool {pool:?}"
    );
    for a in cases {
        assert!(pool.contains(a), "missing user-configured address {a}");
    }
}

#[test]
fn declared_to_socket_handles_ipv4_and_ipv6() {
    use crate::handshake::DeclaredAddress;
    // IPv4 — 4 bytes.
    let v4 = DeclaredAddress {
        addr: vec![10, 0, 0, 8],
        port: 9030,
    };
    assert_eq!(declared_to_socket(&v4), Some(addr(10, 0, 0, 8, 9030)));

    // IPv6 — 16 bytes. The pre-fix code coerced this to 0.0.0.0:port.
    // (Picking 2001:41d0:700:6662:: which is a real seed.)
    let v6_bytes = vec![
        0x20, 0x01, 0x41, 0xd0, 0x07, 0x00, 0x66, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let v6 = DeclaredAddress {
        addr: v6_bytes,
        port: 29031,
    };
    let parsed = declared_to_socket(&v6).expect("16-byte IPv6 must parse");
    assert!(
        parsed.is_ipv6(),
        "16-byte declared address must yield IPv6 SocketAddr, got {parsed:?}"
    );
    assert_eq!(parsed.port(), 29031);

    // Malformed — neither 4 nor 16 bytes.
    let weird = DeclaredAddress {
        addr: vec![1, 2, 3],
        port: 9030,
    };
    assert_eq!(declared_to_socket(&weird), None);

    // Out-of-range port (deserializer carries u32; we only accept u16).
    let bad_port = DeclaredAddress {
        addr: vec![1, 2, 3, 4],
        port: 70_000,
    };
    assert_eq!(declared_to_socket(&bad_port), None);
}

#[test]
fn peers_for_sharing_excludes_non_routable_declared_addresses() {
    use crate::handshake::DeclaredAddress;
    let mut mgr = PeerManager::new(42);
    let now = Instant::now();
    // Three peers: one routable, one with a leaked private addr, one
    // with no declared address. Only the first should be shared.
    let routable = addr(213, 239, 193, 208, 9030);
    let leaked = addr(10, 0, 0, 8, 9030);
    let undeclared = addr(159, 65, 11, 55, 9030);
    for a in &[routable, leaked, undeclared] {
        mgr.register_outbound(*a, now).unwrap();
        mgr.mark_tcp_connected(a);
    }

    let mk_spec = |declared: Option<DeclaredAddress>| PeerSpec {
        agent_name: "ergo-reference".into(),
        version: crate::handshake::Version::NIPOPOW,
        node_name: "n".into(),
        declared_address: declared,
        features: Vec::new(),
    };
    let v4 = |o: [u8; 4], p: u32| DeclaredAddress {
        addr: o.to_vec(),
        port: p,
    };
    mgr.complete_handshake(
        &routable,
        mk_spec(Some(v4([213, 239, 193, 208], 9030))),
        None,
        now,
    )
    .unwrap();
    mgr.complete_handshake(&leaked, mk_spec(Some(v4([10, 0, 0, 8], 9030))), None, now)
        .unwrap();
    mgr.complete_handshake(&undeclared, mk_spec(None), None, now)
        .unwrap();

    let shared = mgr.peers_for_sharing(100, 0);
    assert_eq!(
        shared.len(),
        1,
        "expected one shareable peer (routable only), got {shared:?}"
    );
    let sd = shared[0].declared_address.as_ref().unwrap();
    assert_eq!(sd.addr, vec![213, 239, 193, 208]);
    assert_eq!(sd.port, 9030);
}

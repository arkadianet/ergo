// ----- idle-peer progress gating (#247 item 9) -----

/// Register a handshaked, registry-backed peer so `evict_timed_out` and
/// `send_to_peer` both see it. The returned receiver must be held for the
/// duration of the test, otherwise the outbound channel reads as closed.
#[must_use]
pub(super) fn connect_test_peer(
    state: &mut NodeState,
    peer: SocketAddr,
    now: Instant,
) -> crate::peer_loop::outbound::Receiver {
    state.peer_manager.register_outbound(peer, now).unwrap();
    state.peer_manager.mark_tcp_connected(&peer);
    state
        .peer_manager
        .complete_handshake(&peer, state.our_handshake.peer_spec.clone(), None, now)
        .unwrap();
    let (tx, rx) = crate::peer_loop::outbound::channel(64);
    state.registry.peers.insert(
        peer,
        PeerRuntime {
            sync_version: SyncVersion::V2,
            outbound_tx: tx,
        },
    );
    rx
}

/// Mirror the `PeerEvent::Message` path in `events.rs`: every valid frame
/// touches, and `handle_message` decides whether it also counts as
/// progress.
fn deliver_frame(state: &mut NodeState, peer: SocketAddr, code: u8, payload: &[u8], now: Instant) {
    state.peer_manager.touch(&peer, now);
    let _ = handle_message(state, peer, code, payload, now);
}

/// Addresses evicted by `evict_timed_out`, dropping the state each was in.
fn evicted_addrs(state: &mut NodeState, now: Instant) -> Vec<SocketAddr> {
    state
        .peer_manager
        .evict_timed_out(now)
        .into_iter()
        .map(|(addr, _)| addr)
        .collect()
}

/// A `PeerSpec` that does or does not name an address we could dial.
fn peers_payload(with_declared_address: bool) -> Vec<u8> {
    let spec = PeerSpec {
        agent_name: "ergoref".to_string(),
        version: Version::NIPOPOW,
        node_name: "gossiped".to_string(),
        declared_address: with_declared_address.then(|| ergo_p2p::handshake::DeclaredAddress {
            addr: vec![203, 0, 113, 7],
            port: 9030,
        }),
        features: Vec::new(),
    };
    message::serialize_peers(&[spec])
}

/// Trickle `payload` at `every` for longer than the inactivity window,
/// then report whether the peer survived. One state per call so the cases
/// stay independent.
fn survives_trickle(dir: &Path, name: &str, code: u8, payload: &[u8], every: Duration) -> bool {
    let mut state = make_state(&dir.join(name));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let deadline = now + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(60);
    let mut t = now;
    while t < deadline {
        t += every;
        if code == message::CODE_PEERS {
            state.peer_manager.note_get_peers_sent(&peer, t);
        }
        deliver_frame(&mut state, peer, code, payload, t);
    }
    evicted_addrs(&mut state, t).is_empty()
}

/// A peer that trickles nothing but bare `GetPeers` keeps its `last_seen`
/// fresh yet makes no progress, so it must lose its slot once the
/// inactivity window elapses. Pre-fix this peer was immortal.
#[test]
fn keepalive_only_peer_is_evicted_after_inactive_window() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let mut t = now;
    let deadline = now + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(60);
    while t < deadline {
        t += Duration::from_secs(60);
        deliver_frame(&mut state, peer, message::CODE_GET_PEERS, &[], t);
    }

    assert_eq!(
        evicted_addrs(&mut state, t),
        vec![peer],
        "keepalive-only peer must be evicted",
    );
    assert_eq!(state.peer_manager.peer_count(), 0);
}

/// The honest-peer premise the whole change rests on: a Scala neighbour
/// sends `SyncInfo` to every connected peer at least once a minute
/// (`ErgoSyncTracker.scala:144-148`, `SyncThreshold = 1.minute`), so that
/// cadence alone must hold a slot indefinitely. This also pins the
/// interaction with the 100 ms per-peer sync lock time, whose early
/// `return` sits just above the `note_progress` call.
#[test]
fn sync_info_at_scala_cadence_keeps_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let payload = message::serialize_sync_info(&message::SyncInfo::V1 {
        header_ids: vec![mid(1)],
    })
    .unwrap();

    let mut t = now;
    let deadline = now + ergo_p2p::peer::INACTIVE_TIMEOUT * 3;
    while t < deadline {
        t += Duration::from_secs(60);
        deliver_frame(&mut state, peer, message::CODE_SYNC_INFO, &payload, t);
        assert!(
            evicted_addrs(&mut state, t).is_empty(),
            "a peer syncing at Scala's cadence must never be evicted",
        );
    }
}

/// ...but an *empty* `SyncInfo` is a legal 4-byte frame carrying no chain
/// information, so it must not hold the slot.
#[test]
fn empty_sync_info_is_not_progress() {
    let tmp = tempfile::tempdir().unwrap();
    let payload = message::serialize_sync_info(&message::SyncInfo::V1 {
        header_ids: Vec::new(),
    })
    .unwrap();
    assert!(
        !survives_trickle(
            tmp.path(),
            "state.redb",
            message::CODE_SYNC_INFO,
            &payload,
            Duration::from_secs(60),
        ),
        "an empty SyncInfo must not refresh the idle timer",
    );
}

/// `Peers` counts only when it gossips something dialable: an empty list
/// is as cheap as a keepalive, and so is a spec with no declared address.
#[test]
fn peers_reply_counts_only_with_a_dialable_entry() {
    let tmp = tempfile::tempdir().unwrap();

    assert!(
        !survives_trickle(
            tmp.path(),
            "empty.redb",
            message::CODE_PEERS,
            &message::serialize_peers(&[]),
            Duration::from_secs(60),
        ),
        "an empty Peers reply must not refresh the idle timer",
    );
    assert!(
        !survives_trickle(
            tmp.path(),
            "undialable.redb",
            message::CODE_PEERS,
            &peers_payload(false),
            Duration::from_secs(60),
        ),
        "a Peers entry with no declared address is not progress",
    );
    assert!(
        survives_trickle(
            tmp.path(),
            "dialable.redb",
            message::CODE_PEERS,
            &peers_payload(true),
            Duration::from_secs(60),
        ),
        "a Peers entry we could dial is progress",
    );
}

/// A `RequestModifier` counts only when we actually served something.
/// Asking costs the peer nothing; being served is the work.
#[test]
fn request_modifier_counts_only_when_served() {
    let tmp = tempfile::tempdir().unwrap();

    // Unserved: the header id is unknown to us.
    assert!(
        !survives_trickle(
            tmp.path(),
            "unserved.redb",
            message::CODE_REQUEST_MODIFIER,
            &req_modifier_payload(ModifierTypeId::Header.as_byte(), &[mid(1)]),
            Duration::from_secs(60),
        ),
        "requests we serve nothing for must not refresh the idle timer",
    );

    // Served: same request, but the header is in the store.
    let mut state = make_state(&tmp.path().join("served.redb"));
    let header_id = mid(1);
    state
        .store
        .store_header(&header_id, &[0xAAu8; 80])
        .expect("seed header");
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let payload = req_modifier_payload(ModifierTypeId::Header.as_byte(), &[header_id]);
    let mut t = now;
    let deadline = now + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(60);
    while t < deadline {
        t += Duration::from_secs(60);
        deliver_frame(
            &mut state,
            peer,
            message::CODE_REQUEST_MODIFIER,
            &payload,
            t,
        );
    }
    assert!(
        evicted_addrs(&mut state, t).is_empty(),
        "a request we served is progress",
    );
}

/// The clock restarts from the last progress frame, and only then does the
/// full window have to elapse.
#[test]
fn progress_frame_inside_window_keeps_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let payload = message::serialize_sync_info(&message::SyncInfo::V1 {
        header_ids: vec![mid(1)],
    })
    .unwrap();
    let progress_at = now + Duration::from_secs(500);
    deliver_frame(
        &mut state,
        peer,
        message::CODE_SYNC_INFO,
        &payload,
        progress_at,
    );

    assert!(
        evicted_addrs(&mut state, progress_at + ergo_p2p::peer::INACTIVE_TIMEOUT).is_empty(),
        "peer must be kept for a full window after its last progress",
    );
    assert_eq!(
        evicted_addrs(
            &mut state,
            progress_at + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(1),
        ),
        vec![peer],
        "and evicted once that window elapses with no further progress",
    );
}

/// A handshaked peer evicted for making no progress is NOT a dial
/// failure: the address answered, handshaked, and stayed reachable, so
/// counting it would bump `consecutive_failures` and push a perfectly
/// dialable address down the ranking. A pre-handshake timeout still is a
/// dial failure and must still take the backoff.
#[test]
fn no_progress_eviction_does_not_take_dial_backoff() {
    let tmp = tempfile::tempdir().unwrap();
    let peer = test_peer();

    // Handshaked, then silent for longer than the inactivity window.
    let mut state = make_state(&tmp.path().join("handshaked.redb"));
    state
        .peer_manager
        .add_known_address(peer, ergo_p2p::peer_manager::PeerOrigin::Seed);
    let base = Instant::now();
    let now = base + ergo_p2p::peer::INACTIVE_TIMEOUT + Duration::from_secs(100);
    state.peer_manager.register_outbound(peer, base).unwrap();
    state.peer_manager.mark_tcp_connected(&peer);
    state
        .peer_manager
        .complete_handshake(&peer, state.our_handshake.peer_spec.clone(), None, base)
        .unwrap();

    handle_sync_tick_at(&mut state, now);

    assert_eq!(
        state.peer_manager.peer_count(),
        0,
        "stalled handshaked peer should have been evicted",
    );
    assert!(
        state
            .peer_manager
            .addresses_to_connect(now, 10)
            .contains(&peer),
        "a no-progress eviction must leave the address immediately dialable",
    );

    // Same address, but it never got past `Connecting`.
    let mut state = make_state(&tmp.path().join("connecting.redb"));
    state
        .peer_manager
        .add_known_address(peer, ergo_p2p::peer_manager::PeerOrigin::Seed);
    let base = Instant::now();
    let now = base + ergo_p2p::peer::CONNECT_TIMEOUT + Duration::from_secs(10);
    state.peer_manager.register_outbound(peer, base).unwrap();

    handle_sync_tick_at(&mut state, now);

    assert_eq!(
        state.peer_manager.peer_count(),
        0,
        "stalled dial should have been evicted",
    );
    assert!(
        !state
            .peer_manager
            .addresses_to_connect(now, 10)
            .contains(&peer),
        "a pre-handshake timeout is a dial failure and must take the backoff",
    );
}

fn gossip_spec(ip: [u8; 4], port: u32) -> PeerSpec {
    PeerSpec {
        agent_name: "ergoref".to_string(),
        version: Version::NIPOPOW,
        node_name: "gossiped".to_string(),
        declared_address: Some(ergo_p2p::handshake::DeclaredAddress {
            addr: ip.to_vec(),
            port,
        }),
        features: Vec::new(),
    }
}

/// `Peers` is a reply to `GetPeers`. One that arrives without a recent
/// request from us is not taken into the address pool and is not progress.
#[test]
fn unsolicited_peers_are_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);
    let before = state.peer_manager.known_addresses_len();
    let payload = message::serialize_peers(&[gossip_spec([45, 79, 113, 7], 9030)]);

    let _ = handle_message(&mut state, peer, message::CODE_PEERS, &payload, now);
    assert_eq!(state.peer_manager.known_addresses_len(), before);

    // A solicited reply is accepted once.
    state.peer_manager.note_get_peers_sent(&peer, now);
    let _ = handle_message(&mut state, peer, message::CODE_PEERS, &payload, now);
    assert_eq!(state.peer_manager.known_addresses_len(), before + 1);
    let second = message::serialize_peers(&[gossip_spec([45, 79, 113, 8], 9030)]);
    let _ = handle_message(&mut state, peer, message::CODE_PEERS, &second, now);
    assert_eq!(
        state.peer_manager.known_addresses_len(),
        before + 1,
        "one GetPeers admits one Peers reply",
    );

    // A reply after the window has closed is ignored.
    state.peer_manager.note_get_peers_sent(&peer, now);
    let late = now + ergo_p2p::peer::PEERS_REPLY_WINDOW + Duration::from_secs(1);
    let _ = handle_message(&mut state, peer, message::CODE_PEERS, &second, late);
    assert_eq!(state.peer_manager.known_addresses_len(), before + 1);
}

/// A `Peers` reply is truncated to the protocol's 64-entry limit, duplicate
/// entries are counted once, and our own declared address is not learned.
#[test]
fn peers_reply_is_capped_deduplicated_and_skips_self() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let own: SocketAddr = "45.80.100.200:9030".parse().unwrap();
    state.peer_manager.set_self_addresses([own]);
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);
    let before = state.peer_manager.known_addresses_len();

    let mut specs = vec![gossip_spec([45, 80, 100, 200], 9030)];
    specs.push(gossip_spec([45, 79, 113, 50], 9030));
    specs.push(gossip_spec([45, 79, 113, 50], 9030));
    for i in 0..90u8 {
        specs.push(gossip_spec([45, 33, i, 1], 9030));
    }
    let payload = message::serialize_peers(&specs);
    state.peer_manager.note_get_peers_sent(&peer, now);
    let _ = handle_message(&mut state, peer, message::CODE_PEERS, &payload, now);
    // 64 entries taken: self (skipped), one duplicate pair (one add), and
    // 61 distinct addresses.
    assert_eq!(state.peer_manager.known_addresses_len(), before + 62);
    assert!(state
        .peer_manager
        .addresses_to_connect(now, 1000)
        .iter()
        .all(|a| *a != own));
}

fn served_ids(actions: &[Action]) -> Vec<[u8; 32]> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer { code, payload, .. } if *code == message::CODE_MODIFIER => {
                Some(message::deserialize_modifiers(payload).unwrap().modifiers)
            }
            _ => None,
        })
        .flatten()
        .map(|(id, _)| id)
        .collect()
}

/// A `RequestModifier` naming the same id many times is answered with that
/// modifier once; the store is read once per distinct id.
#[test]
fn request_modifier_serves_each_id_once() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let header_id = mid(1);
    state
        .store
        .store_header(&header_id, &[0xAAu8; 80])
        .expect("seed header");
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);

    let ids = vec![header_id; 400];
    let payload = req_modifier_payload(ModifierTypeId::Header.as_byte(), &ids);
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_REQUEST_MODIFIER,
        &payload,
        now,
    );
    assert_eq!(served_ids(&actions), vec![header_id]);
}

/// Bytes served to one peer are budgeted per window: once a peer has been
/// sent its budget, further requests go unanswered until the window moves.
#[test]
fn request_modifier_respects_per_peer_serve_budget() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let header_id = mid(1);
    state
        .store
        .store_header(&header_id, &[0xAAu8; 80])
        .expect("seed header");
    let peer = test_peer();
    let other: SocketAddr = "10.9.9.9:9030".parse().unwrap();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);
    let _rx2 = connect_test_peer(&mut state, other, now);
    let payload = req_modifier_payload(ModifierTypeId::Header.as_byte(), &[header_id]);

    let budget = ergo_p2p::throttle::SERVE_LIMITS.max_bytes_per_window;
    state.serve_throttle.record(peer, now, budget);
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_REQUEST_MODIFIER,
        &payload,
        now,
    );
    assert!(served_ids(&actions).is_empty(), "spent budget: no reply");

    // Other peers are unaffected, and the budget refills with the window.
    let actions = handle_message(
        &mut state,
        other,
        message::CODE_REQUEST_MODIFIER,
        &payload,
        now,
    );
    assert_eq!(served_ids(&actions), vec![header_id]);
    let later = now + ergo_p2p::throttle::SERVE_LIMITS.window + Duration::from_secs(1);
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_REQUEST_MODIFIER,
        &payload,
        later,
    );
    assert_eq!(served_ids(&actions), vec![header_id]);
}

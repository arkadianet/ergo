// ---- SyncInfo stamp = transport DISPATCH success (PR #251 follow-up) ----

fn register_connected_peer(
    state: &mut NodeState,
    peer: ergo_p2p::peer::PeerId,
) -> crate::peer_loop::outbound::Receiver {
    let (tx, rx) = crate::peer_loop::outbound::channel(8);
    state.registry.peers.insert(
        peer,
        super::state::PeerRuntime {
            sync_version: SyncVersion::V2,
            outbound_tx: tx,
        },
    );
    rx
}

#[test]
fn sync_info_dispatch_success_stamps_last_sync_sent() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 9, 1)), 9030);
    let mut rx = register_connected_peer(&mut state, peer);

    assert!(
        state
            .coordinator
            .sync_state_mut()
            .not_synced_or_outdated(peer, Instant::now()),
        "peer starts not-synced (never dispatched to)"
    );

    flush_actions(
        &mut state,
        vec![Action::SendToPeer {
            peer,
            code: message::CODE_SYNC_INFO,
            payload: vec![0x01],
        }],
    );

    // The frame was accepted by the channel; drain it to prove dispatch.
    let frame = rx.try_recv().expect("SyncInfo frame must be queued");
    assert_eq!(frame.code, message::CODE_SYNC_INFO);
    assert!(
        !state
            .coordinator
            .sync_state_mut()
            .not_synced_or_outdated(peer, Instant::now()),
        "successful dispatch must stamp last_sync_sent"
    );
}

#[test]
fn sync_info_failed_dispatch_does_not_stamp_last_sync_sent() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    // Peer NOT registered in the registry ⇒ try_send fails (closed/absent).
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 9, 2)), 9030);

    flush_actions(
        &mut state,
        vec![Action::SendToPeer {
            peer,
            code: message::CODE_SYNC_INFO,
            payload: vec![0x01],
        }],
    );

    assert!(
        state
            .coordinator
            .sync_state_mut()
            .not_synced_or_outdated(peer, Instant::now()),
        "failed dispatch must leave the timestamp untouched"
    );
}

// ----- throughput throttle: solicited deliveries are never dropped -----

/// Fill `peer`'s byte window until the NEXT frame of any size exceeds it,
/// whatever the peer has already spent. Drives the limiter's own accounting
/// rather than a hand-computed constant, so it stays correct if the default
/// budget changes.
fn saturate_byte_window(state: &mut NodeState, peer: SocketAddr, now: Instant) {
    use ergo_p2p::throttle::LimiterVerdict;
    let mut chunk = 1_000_000u32;
    // Shrink the fill frame as the window nears full so the last of the budget
    // is actually spent rather than left as an unreachable remainder.
    while chunk > 0 {
        match state.throttle.check_and_record(peer, now, chunk) {
            LimiterVerdict::Ok => {}
            LimiterVerdict::ByteRateExceeded => chunk /= 2,
            LimiterVerdict::MessageRateExceeded => {
                panic!("window fill must not hit the message cap")
            }
        }
    }
    assert_eq!(
        state.throttle.check_and_record(peer, now, 1),
        LimiterVerdict::ByteRateExceeded,
        "the window must now be saturated",
    );
}

/// A canonical ADProofs section of roughly `payload_len` bytes, paired with the
/// modifier id it actually hashes to. ADProofs is the cheapest section to
/// synthesize (its content digest is just `blake2b256(proof_bytes)`), and using
/// real bytes keeps the throttle assertion honest: the frame must survive the
/// downstream `verify_section_modifier_id` check too, so a `Penalize` in the
/// result can only have come from the throttle.
fn canonical_ad_proofs_section(payload_len: usize) -> ([u8; 32], Vec<u8>) {
    use ergo_primitives::digest::{blake2b256, ModifierId};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::modifier_id::{compute_section_id, TYPE_AD_PROOFS};

    let header_id = [0x42u8; 32];
    let proof_bytes = vec![0xAAu8; payload_len];
    let content_digest = *blake2b256(&proof_bytes).as_bytes();
    let section_id = compute_section_id(TYPE_AD_PROOFS, &header_id, &content_digest);
    let mut w = VlqWriter::new();
    ergo_ser::ad_proofs::write_ad_proofs(
        &mut w,
        &ergo_ser::ad_proofs::ADProofs {
            header_id: ModifierId::from_bytes(header_id),
            proof_bytes,
        },
    );
    (section_id, w.result())
}

/// The liveness property: a `Modifier` frame delivering something we requested
/// must not be dropped by the byte axis. Dropping it makes our own delivery
/// checker time the request out and charge the honest holder a `NonDelivery`
/// penalty for a drop we caused — self-inflicted eviction of the peer that was
/// serving us. Body catch-up from a single holder is exactly the traffic
/// pattern that saturates a 2 MB/s cap.
#[test]
fn byte_throttle_over_cap_modifier_frame_admitted_without_penalty() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let (section_id, section_bytes) = canonical_ad_proofs_section(4096);

    // Solicit it first, so the delivery below is one we actually asked this
    // peer for — the case the byte axis must never drop.
    let inv = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        ids: vec![section_id],
    })
    .expect("serialize inv");
    let requested = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
    assert!(
        requested.iter().any(|a| matches!(
            a,
            Action::SendToPeer { code, .. } if *code == message::CODE_REQUEST_MODIFIER
        )),
        "the section must actually be requested for this test to mean anything: {requested:?}",
    );

    saturate_byte_window(&mut state, peer, now);

    let payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        modifiers: vec![(section_id, section_bytes)],
    })
    .expect("serialize modifiers");
    let actions = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);

    assert!(
        !actions.iter().any(|a| matches!(a, Action::Penalize { .. })),
        "an over-cap delivery of a modifier we requested must not penalize the holder: \
         {actions:?}",
    );
}

/// The exemption is decided on the delivery tracker, not the opcode. A peer
/// re-sending a section we already received resolves to `DeliveryAction::Ignore`,
/// so it stays on the drop-and-penalize path — otherwise the byte cap would be
/// inoperative for `CODE_MODIFIER` and a peer could replay a legitimately
/// delivered 8 MB section at the message rate for free.
#[test]
fn byte_throttle_over_cap_replayed_modifier_frame_drops_and_penalizes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let (section_id, section_bytes) = canonical_ad_proofs_section(4096);

    // Request it, then deliver it once under the cap so it lands in the
    // tracker's received set.
    let inv = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        ids: vec![section_id],
    })
    .expect("serialize inv");
    let _ = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
    let payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        modifiers: vec![(section_id, section_bytes)],
    })
    .expect("serialize modifiers");
    let _ = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);
    assert_eq!(
        state.coordinator.delivery().status(&section_id),
        ergo_p2p::delivery::ModifierStatus::Received,
        "the first delivery must have been accepted for the replay to be a replay",
    );

    saturate_byte_window(&mut state, peer, now);
    let actions = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);

    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::Penalize {
                penalty: Penalty::Misbehavior,
                ..
            }
        )),
        "an over-cap replay of an already-received section must be dropped and penalized: \
         {actions:?}",
    );
}

/// Charge `peer`'s byte window up to `headroom` bytes short of the cap, so the
/// next frame larger than `headroom` is over-cap while a 1-byte probe still
/// fits. Lets a test tell "the exempt frame was charged" apart from "the
/// window was already full".
fn fill_byte_window_leaving(state: &mut NodeState, peer: SocketAddr, now: Instant, headroom: u64) {
    use ergo_p2p::throttle::LimiterVerdict;
    let mut remaining = state.throttle.limits().max_bytes_per_window - headroom;
    while remaining > 0 {
        let chunk = remaining.min(u32::MAX as u64) as u32;
        assert_eq!(
            state.throttle.check_and_record(peer, now, chunk),
            LimiterVerdict::Ok,
            "pre-fill must stay under the cap"
        );
        remaining -= chunk as u64;
    }
    assert_eq!(
        state.throttle.check_and_record(peer, now, 1),
        LimiterVerdict::Ok,
        "a 1-byte probe must still fit inside the headroom",
    );
}

/// The byte axis still charges the exempted frame, so a peer cannot mint free
/// bandwidth by sending only `Modifier` frames — its next non-exempt frame is
/// judged against the true window.
#[test]
fn byte_throttle_over_cap_modifier_frame_still_charged_to_the_window() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let budget = state.throttle.limits().max_bytes_per_window;
    let (section_id, section_bytes) = canonical_ad_proofs_section(4096);

    let inv = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        ids: vec![section_id],
    })
    .expect("serialize inv");
    let _ = handle_message(&mut state, peer, message::CODE_INV, &inv, now);

    // Leave a sliver of headroom: the 4 KiB delivery below is over-cap (and so
    // takes the exempt path), but a 1-byte probe fits UNLESS that delivery was
    // charged. Fully saturating the window here would make the final
    // assertion pass even if the exempt frame were never recorded.
    fill_byte_window_leaving(&mut state, peer, now, 64);

    let payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::ADProofs.as_byte(),
        modifiers: vec![(section_id, section_bytes)],
    })
    .expect("serialize modifiers");
    let _ = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);

    assert_eq!(
        state.throttle.check_and_record(peer, now, 1),
        ergo_p2p::throttle::LimiterVerdict::ByteRateExceeded,
        "the exempted delivery must remain charged (budget {budget})",
    );
}

/// Contrast case: the exemption is narrow. Any other over-cap frame still
/// drops and still penalizes — the byte axis keeps its teeth for traffic we
/// did not ask for.
#[test]
fn byte_throttle_over_cap_non_modifier_frame_drops_and_penalizes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    saturate_byte_window(&mut state, peer, now);

    let payload = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![mid(1)],
    })
    .expect("serialize inv");
    let actions = handle_message(&mut state, peer, message::CODE_INV, &payload, now);

    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::Penalize {
                penalty: Penalty::Misbehavior,
                ..
            }
        )),
        "an over-cap non-delivery frame must still be dropped and penalized: {actions:?}",
    );
}

#[test]
fn coalesced_over_throttle_header_is_penalized_without_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let _rx = connect_test_peer(&mut state, peer, now);
    let rejected_id = mid(1);
    // A real header: admission checks that the bytes hash to the requested
    // id, and a header that then fails validation has its delivery rolled
    // back, so only a genuine header stays `Received`.
    let admitted_bytes = hex::decode(POPOW_GENESIS_HEX).unwrap();
    let admitted_id = *ergo_primitives::digest::blake2b256(&admitted_bytes).as_bytes();
    let rejected_payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::Header.as_byte(),
        modifiers: vec![(rejected_id, vec![0u8; 1024])],
    })
    .unwrap();
    let admitted_payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: ModifierTypeId::Header.as_byte(),
        modifiers: vec![(admitted_id, admitted_bytes)],
    })
    .unwrap();
    let admitted_frame_bytes = (admitted_payload.len() + 9) as u64;
    fill_byte_window_leaving(&mut state, peer, now, admitted_frame_bytes + 2);
    assert_eq!(
        state.coordinator.delivery_mut().request(
            peer,
            ModifierTypeId::Header.as_byte(),
            &[admitted_id],
            now
        ),
        vec![admitted_id]
    );

    let rejected_event_payload =
        crate::peer_loop::MeteredPayload::for_test(rejected_payload, &state.event_byte_budget);
    let admitted_event_payload =
        crate::peer_loop::MeteredPayload::for_test(admitted_payload, &state.event_byte_budget);
    super::events::handle_event_batch(
        &mut state,
        vec![
            PeerEvent::Message {
                peer,
                code: message::CODE_MODIFIER,
                payload: rejected_event_payload,
            },
            PeerEvent::Message {
                peer,
                code: message::CODE_MODIFIER,
                payload: admitted_event_payload,
            },
        ],
    );

    assert_eq!(state.sections_received_total, 1);
    assert_eq!(
        state.coordinator.delivery().status(&rejected_id),
        ergo_p2p::delivery::ModifierStatus::Unknown
    );
    assert_eq!(
        state.coordinator.delivery().status(&admitted_id),
        ergo_p2p::delivery::ModifierStatus::Received
    );
    assert_eq!(state.peer_manager.get(&peer).unwrap().score.raw_score(), 10);
}

// ----- duplicate inbound drop (issue #293) -----

/// A `HandshakeComplete` for an address the registry already holds — a
/// late event from a previous dial, or an inbound connection from a
/// reused ephemeral port — leaves the existing runtime untouched and
/// drops the new connection. Replacing the runtime is not safe: both the
/// registry and `PeerEvent::Disconnected` are keyed by remote address
/// alone, so the old connection's teardown would then evict the peer we
/// had just swapped in. Scala drops the duplicate for the same reason
/// (`NetworkController.handleHandshake`, NetworkController.scala:417-424).
/// The branch now emits a `reason = "address_still_registered"` DEBUG
/// line so an operator can tell this drop from a network fault.
#[tokio::test]
async fn handshake_complete_for_registered_address_keeps_existing_runtime() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("dup.redb"));
    let peer = test_peer();

    // The incumbent runtime, whose channel must survive the duplicate.
    let (tx, mut rx) = crate::peer_loop::outbound::channel(4);
    state.registry.peers.insert(
        peer,
        PeerRuntime {
            sync_version: SyncVersion::V1,
            outbound_tx: tx,
        },
    );

    // A real socket for the duplicate connection: the drop must close it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let client = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
    let server = accept.await.unwrap();
    let conn = Box::new(ergo_p2p::connection::Connection::new(server, state.magic));

    super::events::handle_event_batch(
        &mut state,
        vec![PeerEvent::HandshakeComplete {
            addr: peer,
            peer_spec: PeerSpec {
                agent_name: "dup".into(),
                version: Version::NIPOPOW,
                node_name: "dup".into(),
                declared_address: None,
                features: Vec::new(),
            },
            time: 0,
            conn,
        }],
    );

    assert_eq!(
        state.registry.peers.len(),
        1,
        "the duplicate must not add or replace a registry entry",
    );
    assert!(
        state
            .registry
            .try_send(&peer, message::CODE_SYNC_INFO, Vec::new()),
        "the incumbent runtime's channel must still be usable",
    );
    assert_eq!(
        rx.try_recv().expect("frame reaches the incumbent").code,
        message::CODE_SYNC_INFO,
    );
    assert!(
        state.peer_manager.get(&peer).is_none(),
        "the dropped duplicate must not complete a handshake",
    );
    drop(client);
}

#[test]
fn penalty_ban_cleans_registry_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let now = Instant::now();

    state.peer_manager.register_outbound(peer, now).unwrap();
    state.peer_manager.mark_tcp_connected(&peer);
    state
        .peer_manager
        .complete_handshake(&peer, state.our_handshake.peer_spec.clone(), None, now)
        .unwrap();
    let (tx, _rx) = crate::peer_loop::outbound::channel(1);
    state.registry.peers.insert(
        peer,
        PeerRuntime {
            sync_version: SyncVersion::V2,
            outbound_tx: tx,
        },
    );

    let mut t = now;
    for _ in 0..30 {
        t += ergo_p2p::peer::SAFE_INTERVAL;
        state.peer_manager.penalize(&peer, Penalty::Spam, t);
    }

    flush_actions(
        &mut state,
        vec![Action::Penalize {
            peer,
            penalty: Penalty::Spam,
        }],
    );

    assert_eq!(state.peer_manager.peer_count(), 0);
    assert!(!state.registry.peers.contains_key(&peer));
}

#[test]
fn request_header_mixed_present_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    let h1 = mid(1);
    let h2 = mid(2);
    let missing = mid(99);
    state.store.store_header(&h1, &[0xAA; 80]).unwrap();
    state.store.store_header(&h2, &[0xBB; 80]).unwrap();

    let payload = req_modifier_payload(ModifierTypeId::Header.as_byte(), &[h1, missing, h2]);
    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_REQUEST_MODIFIER,
        &payload,
        Instant::now(),
    );

    assert_modifier_response(&actions, ModifierTypeId::Header.as_byte(), &[h1, h2]);
}

#[test]
fn request_block_section_mixed_present_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    let s1 = mid(1);
    let s2 = mid(2);
    let missing = mid(99);
    state
        .store
        .as_utxo()
        .expect("utxo-only: block-section store test runs in UTXO mode")
        .store_block_section(&s1, &[0xCC; 200])
        .unwrap();
    state
        .store
        .as_utxo()
        .expect("utxo-only: block-section store test runs in UTXO mode")
        .store_block_section(&s2, &[0xDD; 200])
        .unwrap();

    let payload = req_modifier_payload(
        ModifierTypeId::BlockTransactions.as_byte(),
        &[s1, missing, s2],
    );
    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_REQUEST_MODIFIER,
        &payload,
        Instant::now(),
    );

    assert_modifier_response(
        &actions,
        ModifierTypeId::BlockTransactions.as_byte(),
        &[s1, s2],
    );
}

/// P2 observability: an inbound tx-typed `Inv` advertising ids we don't
/// already have must (a) bump `mempool_tx_requested_total` by the number of
/// `unknown` (not-pooled, not-invalidated) ids and (b) emit a
/// `RequestModifier` for them. The counter is the always-on aggregate
/// surfaced via `/metrics`; this pins the increment seam in
/// `handle_message`'s tx-Inv→request branch.
#[test]
fn tx_inv_increments_requested_counter_and_requests_unknown() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    assert_eq!(state.mempool_tx_requested_total, 0);

    let ids = [mid(1), mid(2), mid(3)];
    let payload = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::Transaction.as_byte(),
        ids: ids.to_vec(),
    })
    .unwrap();

    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_INV,
        &payload,
        Instant::now(),
    );

    // All three ids are unknown (empty pool, nothing invalidated), so the
    // counter advances by 3 and a RequestModifier is emitted for them.
    assert_eq!(state.mempool_tx_requested_total, 3);
    assert_eq!(actions.len(), 1, "expected a RequestModifier action");
    let Action::SendToPeer { code, .. } = &actions[0] else {
        panic!("expected SendToPeer, got {:?}", actions[0]);
    };
    assert_eq!(*code, message::CODE_REQUEST_MODIFIER);
}

/// P2 (accuracy): re-advertising tx ids that are ALREADY in-flight must not
/// re-bump `mempool_tx_requested_total`. The coordinator dedupes the second
/// Inv's ids against in-flight delivery state and emits no RequestModifier,
/// so the counter — which is supposed to track ids ACTUALLY requested — must
/// stay put. Pins the fix where the increment uses the post-dedupe count
/// returned by `request_transactions`, not the advertised `unknown.len()`.
/// Fail-first against the old `unknown.len()` increment, which double-counted
/// the second Inv (counter would reach 6, not 3).
#[test]
fn tx_inv_does_not_recount_already_in_flight_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    assert_eq!(state.mempool_tx_requested_total, 0);

    let ids = [mid(1), mid(2), mid(3)];
    let payload = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::Transaction.as_byte(),
        ids: ids.to_vec(),
    })
    .unwrap();
    let now = Instant::now();

    // First Inv: all three ids are unknown and get registered + requested.
    let first = handle_message(&mut state, test_peer(), message::CODE_INV, &payload, now);
    assert_eq!(state.mempool_tx_requested_total, 3);
    assert_eq!(first.len(), 1, "first Inv emits a RequestModifier");

    // Second Inv (same ids, still in-flight from the first): the coordinator
    // dedupes them all away, so nothing new is requested. The counter must
    // NOT advance and no RequestModifier is emitted.
    let second = handle_message(&mut state, test_peer(), message::CODE_INV, &payload, now);
    assert_eq!(
        state.mempool_tx_requested_total, 3,
        "in-flight ids must not be re-counted as requested",
    );
    assert!(
        second.is_empty(),
        "no RequestModifier for already-in-flight ids",
    );
}

/// P2: with the mempool disabled the tx-Inv branch returns early before the
/// `unknown` filter, so a tx-typed `Inv` neither advances the request
/// counter nor emits a request. Pins that the counter is scoped to the
/// genuine request path, not bumped unconditionally on every tx Inv.
#[test]
fn tx_inv_does_not_count_when_mempool_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state_with_backend(
        ergo_state::StateBackendKind::Utxo(
            StateStore::open(&tmp.path().join("state.redb")).unwrap(),
        ),
        crate::config::StateType::Utxo,
        MempoolConfig {
            enabled: false,
            ..MempoolConfig::default()
        },
    );

    let payload = message::serialize_inv(&InvData {
        type_id: ModifierTypeId::Transaction.as_byte(),
        ids: vec![mid(1), mid(2)],
    })
    .unwrap();

    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_INV,
        &payload,
        Instant::now(),
    );

    assert_eq!(
        state.mempool_tx_requested_total, 0,
        "a disabled mempool must not advance the request counter",
    );
    assert!(actions.is_empty(), "disabled mempool serves no tx request");
}

/// P2: the peer-tx admit/reject counters live in `admit_transaction`,
/// AFTER its tip-context gate. On a cold tip (`build_tip_context == None`,
/// the default fixture state — no full block applied) the path drops the tx
/// silently and must NOT touch either counter: a tx the node can't even
/// evaluate is neither an admit nor a reject.
///
/// Driving a real `Admitted` / `Rejected` outcome through this seam needs a
/// populated `block_context_headers` (set only by the block-apply path) plus
/// valid/invalid tx bytes against live UTXO state, which a `make_state`
/// fixture can't synthesize. The increment itself is a single
/// `saturating_add(1)` on each branch of the same `match &outcome` that
/// already drives the per-tx `debug!` traces (admission.rs), and the
/// SnapshotParts→ApiStatus plumbing is covered by
/// `snapshot::build_snapshot_carries_mempool_tx_gossip_counters`. This test
/// pins the gate: the counters stay at the seam, behind the tip check.
#[test]
fn peer_admit_counters_untouched_on_cold_tip() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    assert_eq!(state.mempool_peer_tx_admitted_total, 0);
    assert_eq!(state.mempool_peer_tx_rejected_total, 0);

    // Garbage tx bytes; on a cold tip admit_transaction returns before it
    // ever reaches Mempool::process, so neither counter moves.
    let actions = super::admit_transaction(&mut state, test_peer(), &[0xDE, 0xAD], Instant::now());

    assert!(
        actions.is_empty(),
        "cold-tip admit drops silently with no actions",
    );
    assert_eq!(
        state.mempool_peer_tx_admitted_total, 0,
        "cold-tip drop is not an admit",
    );
    assert_eq!(
        state.mempool_peer_tx_rejected_total, 0,
        "cold-tip drop is not a reject",
    );
}

#[test]
fn request_all_missing_returns_no_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    let payload = req_modifier_payload(ModifierTypeId::Header.as_byte(), &[mid(1), mid(2)]);
    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_REQUEST_MODIFIER,
        &payload,
        Instant::now(),
    );

    assert!(actions.is_empty(), "expected no actions, got {:?}", actions);
}

#[test]
fn request_unknown_type_id_returns_no_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    // type_id=99 has no known ModifierTypeId mapping — return empty, not a peer penalize
    let payload = req_modifier_payload(99, &[mid(1)]);
    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_REQUEST_MODIFIER,
        &payload,
        Instant::now(),
    );

    assert!(actions.is_empty(), "expected no actions, got {:?}", actions);
}

#[test]
fn unknown_inv_type_is_rejected_before_request_registration() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let id = mid(1);
    let payload = message::serialize_inv(&InvData {
        type_id: 100,
        ids: vec![id],
    })
    .unwrap();

    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_INV,
        &payload,
        Instant::now(),
    );

    assert!(actions.iter().any(|action| matches!(
        action,
        Action::Penalize {
            peer: penalized_peer,
            penalty: Penalty::Misbehavior,
        } if *penalized_peer == peer
    )));
    assert_eq!(
        state.coordinator.delivery().status(&id),
        ergo_p2p::delivery::ModifierStatus::Unknown
    );
    assert!(!actions
        .iter()
        .any(|action| matches!(action, Action::SendToPeer { .. })));
}

#[test]
fn unknown_modifier_type_is_rejected_before_delivery_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let peer = test_peer();
    let id = mid(2);
    let now = Instant::now();
    assert_eq!(
        state
            .coordinator
            .delivery_mut()
            .request(peer, 100, &[id], now),
        vec![id]
    );
    let payload = message::serialize_modifiers(&ergo_p2p::types::ModifiersData {
        type_id: 100,
        modifiers: vec![(id, vec![1, 2, 3])],
    })
    .unwrap();

    let actions = handle_message(&mut state, peer, message::CODE_MODIFIER, &payload, now);

    assert!(actions.iter().any(|action| matches!(
        action,
        Action::Penalize {
            peer: penalized_peer,
            penalty: Penalty::Misbehavior,
        } if *penalized_peer == peer
    )));
    assert_eq!(
        state.coordinator.delivery().status(&id),
        ergo_p2p::delivery::ModifierStatus::Requested
    );
    assert!(!actions
        .iter()
        .any(|action| matches!(action, Action::PersistSection { .. })));
}

mod post_header_sync {
    use super::*;
    use ergo_p2p::delivery::ModifierStatus;
    use ergo_p2p::types::ModifiersData;
    use ergo_primitives::digest::blake2b256;
    use ergo_state::ChainStateRead;

    // ----- helpers -----

    fn deliver(state: &mut NodeState, peer: SocketAddr, payload: &[u8], coalesced: bool) {
        if coalesced {
            // Two frames exercise coalescing and per-peer deduplication.
            let events = (0..2)
                .map(|_| PeerEvent::Message {
                    peer,
                    code: message::CODE_MODIFIER,
                    payload: crate::peer_loop::MeteredPayload::for_test(
                        payload.to_vec(),
                        &state.event_byte_budget,
                    ),
                })
                .collect();
            super::super::events::handle_event_batch(state, events);
        } else {
            let actions =
                handle_message(state, peer, message::CODE_MODIFIER, payload, Instant::now());
            flush_actions(state, actions);
        }
    }

    fn assert_refresh(
        rx: &mut crate::peer_loop::outbound::Receiver,
        expected: usize,
        id: [u8; 32],
    ) {
        let mut syncs = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            if frame.code == message::CODE_SYNC_INFO {
                syncs.push(frame);
            }
        }
        assert_eq!(syncs.len(), expected);
        for frame in syncs {
            let message::SyncInfo::V2 { headers } =
                message::deserialize_sync_info(&frame.payload).unwrap()
            else {
                panic!("expected V2 SyncInfo");
            };
            assert_eq!(*blake2b256(&headers[0]).as_bytes(), id);
        }
    }

    fn scenario(coalesced: bool, requested: bool, already_applied: bool, duplicate: bool) {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let peer = test_peer();
        let now = Instant::now();
        let mut rx = connect_test_peer(&mut state, peer, now);
        let bytes = hex::decode(POPOW_GENESIS_HEX).unwrap();
        let id = *blake2b256(&bytes).as_bytes();
        if requested {
            let inv = message::serialize_inv(&InvData {
                type_id: ModifierTypeId::Header.as_byte(),
                ids: vec![id],
            })
            .unwrap();
            let actions = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
            flush_actions(&mut state, actions);
            let frame = rx.try_recv().expect("header must be requested from P");
            assert_eq!(frame.code, message::CODE_REQUEST_MODIFIER);
            assert_eq!(
                message::deserialize_inv(&frame.payload).unwrap().ids,
                vec![id]
            );
        }
        if already_applied {
            let (_, actions) = state
                .executor
                .process_local_header(&mut state.store, &mut state.coordinator, &bytes, now)
                .unwrap();
            flush_actions(&mut state, actions);
            assert_eq!(state.store.chain_state_meta().best_header_height, 1);
            assert_eq!(
                state.coordinator.delivery().status(&id),
                ModifierStatus::Requested
            );
        }
        let payload = message::serialize_modifiers(&ModifiersData {
            type_id: ModifierTypeId::Header.as_byte(),
            modifiers: vec![(id, bytes)],
        })
        .unwrap();
        deliver(&mut state, peer, &payload, coalesced);
        assert_refresh(&mut rx, usize::from(requested), id);
        if requested {
            assert_eq!(state.store.chain_state_meta().best_header_height, 1);
            assert!(!state
                .coordinator
                .sync_state_mut()
                .not_synced_or_outdated(peer, Instant::now()));
        }
        if duplicate {
            assert_eq!(
                state.coordinator.delivery().status(&id),
                ModifierStatus::Received
            );
            deliver(&mut state, peer, &payload, coalesced);
            assert_refresh(&mut rx, 0, id);
        }
    }

    // ----- happy path -----

    #[test]
    fn modifier_requested_already_applied_sends_one_sync_info() {
        scenario(false, true, true, false);
    }

    #[test]
    fn coalesced_requested_already_applied_sends_one_sync_info() {
        scenario(true, true, true, false);
    }

    #[test]
    fn modifier_requested_advancing_sends_one_sync_info() {
        scenario(false, true, false, false);
    }

    #[test]
    fn coalesced_requested_advancing_sends_one_sync_info() {
        scenario(true, true, false, false);
    }

    // ----- error paths -----

    #[test]
    fn modifier_unrequested_sends_no_sync_info() {
        scenario(false, false, false, false);
    }

    #[test]
    fn coalesced_unrequested_sends_no_sync_info() {
        scenario(true, false, false, false);
    }

    #[test]
    fn modifier_duplicate_held_sends_no_sync_info() {
        scenario(false, true, false, true);
    }

    #[test]
    fn coalesced_duplicate_held_sends_no_sync_info() {
        scenario(true, true, false, true);
    }

    #[test]
    fn coalesced_requested_and_unsolicited_refreshes_only_requested_peer() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_state(&dir.path().join("state.redb"));
        let peer = test_peer();
        let spammer = "127.0.0.2:9999".parse().unwrap();
        let now = Instant::now();
        let mut rx = connect_test_peer(&mut state, peer, now);
        let bytes = hex::decode(POPOW_GENESIS_HEX).unwrap();
        let id = *blake2b256(&bytes).as_bytes();
        let inv = message::serialize_inv(&InvData {
            type_id: ModifierTypeId::Header.as_byte(),
            ids: vec![id],
        })
        .unwrap();
        let actions = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
        flush_actions(&mut state, actions);
        assert_eq!(rx.try_recv().unwrap().code, message::CODE_REQUEST_MODIFIER);
        let payload = message::serialize_modifiers(&ModifiersData {
            type_id: ModifierTypeId::Header.as_byte(),
            modifiers: vec![(id, bytes)],
        })
        .unwrap();
        // Connect after the Inv so this peer was not included in request hedging.
        let mut spam_rx = connect_test_peer(&mut state, spammer, now);
        assert_eq!(
            state.coordinator.delivery().on_received(&id, &spammer),
            ergo_p2p::delivery::DeliveryAction::RejectSpam
        );
        // Wrong peer goes first while P still owns the request (RejectSpam).
        let events = [spammer, peer]
            .into_iter()
            .map(|peer| PeerEvent::Message {
                peer,
                code: message::CODE_MODIFIER,
                payload: crate::peer_loop::MeteredPayload::for_test(
                    payload.clone(),
                    &state.event_byte_budget,
                ),
            })
            .collect();
        super::super::events::handle_event_batch(&mut state, events);
        assert_refresh(&mut rx, 1, id);
        assert_refresh(&mut spam_rx, 0, id);
    }

    #[test]
    fn modifier_requested_malformed_sends_no_sync_info() {
        for coalesced in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut state = make_state(&dir.path().join("state.redb"));
            let peer = test_peer();
            let now = Instant::now();
            let mut rx = connect_test_peer(&mut state, peer, now);
            let bytes = vec![0];
            let id = *blake2b256(&bytes).as_bytes();
            let inv = message::serialize_inv(&InvData {
                type_id: ModifierTypeId::Header.as_byte(),
                ids: vec![id],
            })
            .unwrap();
            let actions = handle_message(&mut state, peer, message::CODE_INV, &inv, now);
            flush_actions(&mut state, actions);
            assert_eq!(rx.try_recv().unwrap().code, message::CODE_REQUEST_MODIFIER);
            let payload = message::serialize_modifiers(&ModifiersData {
                type_id: ModifierTypeId::Header.as_byte(),
                modifiers: vec![(id, bytes)],
            })
            .unwrap();
            deliver(&mut state, peer, &payload, coalesced);
            assert_refresh(&mut rx, 0, id);
        }
    }
}

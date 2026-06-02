use super::*;
use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::{GroupElement, GROUP_ELEMENT_LENGTH};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{write_header, Header};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn peer(port: u16) -> PeerId {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn open_initialized_store() -> StateStore {
    let mut store = StateStore::open(
        tempfile::tempdir()
            .unwrap()
            .path()
            .join("state.redb")
            .as_path(),
    )
    .unwrap();
    store.initialize_genesis(&[]).unwrap();
    store
}

/// Apply an empty block at `height` linked to `parent_id` and return
/// the resulting header id.
///
/// The strict hydration walk in `rebuild_block_context` reconstructs
/// each header through `CheckedHeader::from_persisted_parts`, which
/// (a) re-derives the id from bytes and (b) checks that the parsed
/// `Header` agrees with the persisted meta on `(height, parent_id,
/// timestamp)`. So the bytes have to actually parse and match the
/// synthesized meta written by `persist_apply` under the
/// `test-helpers` feature: timestamp = `1_700_000_000 + height`,
/// parent_id = previous `best_full_block_id`.
fn apply_empty_block(store: &mut StateStore, height: u32, parent_id: [u8; 32]) -> [u8; 32] {
    let header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent_id),
        ad_proofs_root: Digest32::ZERO,
        transactions_root: Digest32::ZERO,
        state_root: ADDigest::from_bytes([0u8; 33]),
        timestamp: 1_700_000_000 + height as u64,
        extension_root: Digest32::ZERO,
        n_bits: 0,
        height,
        votes: [0, 0, 0],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0u8; GROUP_ELEMENT_LENGTH]),
            nonce: [0u8; 8],
        },
    };
    let mut w = VlqWriter::new();
    write_header(&mut w, &header).expect("synthetic header fits wire bounds");
    let header_bytes = w.result();
    let header_id = *blake2b256(&header_bytes).as_bytes();

    let expected = store.root_digest();
    store
        .apply_block_unchecked_for_test(height, &header_id, &expected, &[])
        .unwrap();
    store.store_header(&header_id, &header_bytes).unwrap();
    header_id
}

// ----- happy path -----

#[test]
fn full_chain_fork_point_detects_best_header_branch_switch() {
    let mut store = open_initialized_store();
    let h2b = id(0x22);
    let h3b = id(0x33);

    let h1 = apply_empty_block(&mut store, 1, [0u8; 32]);
    let h2a = apply_empty_block(&mut store, 2, h1);
    let h3a = apply_empty_block(&mut store, 3, h2a);

    store
        .store_validated_header(
            &h2b,
            &[0x22; 8],
            &ergo_state::chain::HeaderMeta {
                parent_id: h1,
                height: 2,
                cumulative_score: vec![2],
                pow_validity: 1,
                timestamp: 2,
            },
            None,
        )
        .unwrap();
    store
        .store_validated_header(
            &h3b,
            &[0x33; 8],
            &ergo_state::chain::HeaderMeta {
                parent_id: h2b,
                height: 3,
                cumulative_score: vec![9],
                pow_validity: 1,
                timestamp: 3,
            },
            Some((3, vec![9])),
        )
        .unwrap();

    let executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );

    assert_eq!(store.chain_state().best_full_block_id, h3a);
    assert_eq!(store.chain_state().best_header_id, h3b);
    let store = ergo_state::StateBackendKind::Utxo(store);
    assert_eq!(
        executor.full_chain_fork_point(&store).unwrap(),
        Some((1, h1))
    );
}

#[test]
fn full_chain_reorg_rolls_back_without_marking_new_branch_invalid() {
    let mut store = open_initialized_store();
    let h2b = id(0x22);
    let h3b = id(0x33);

    let h1 = apply_empty_block(&mut store, 1, [0u8; 32]);
    let h2a = apply_empty_block(&mut store, 2, h1);
    let _h3a = apply_empty_block(&mut store, 3, h2a);

    store
        .store_validated_header(
            &h2b,
            &[0x22; 8],
            &ergo_state::chain::HeaderMeta {
                parent_id: h1,
                height: 2,
                cumulative_score: vec![2],
                pow_validity: 1,
                timestamp: 2,
            },
            None,
        )
        .unwrap();
    store
        .store_validated_header(
            &h3b,
            &[0x33; 8],
            &ergo_state::chain::HeaderMeta {
                parent_id: h2b,
                height: 3,
                cumulative_score: vec![9],
                pow_validity: 1,
                timestamp: 3,
            },
            Some((3, vec![9])),
        )
        .unwrap();

    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(1);
    coordinator.sync_state_mut().add_pending_block(2, h2a);
    coordinator.sync_state_mut().add_pending_block(2, h2b);

    let mut store = ergo_state::StateBackendKind::Utxo(store);
    assert!(executor
        .rollback_full_chain_to_best_header(&mut store, &mut coordinator, None)
        .unwrap());

    let cs = store.chain_state_meta();
    assert_eq!(cs.best_full_block_height, 1);
    assert_eq!(cs.best_full_block_id, h1);
    assert_eq!(cs.best_header_id, h3b);
    assert_eq!(coordinator.sync_state().best_full_block_height(), 1);
    assert!(!ergo_state::HeaderSectionStore::is_invalid(&store, &h2b).unwrap());
    assert!(!ergo_state::HeaderSectionStore::is_invalid(&store, &h3b).unwrap());

    let pending: Vec<[u8; 32]> = coordinator
        .sync_state()
        .pending_blocks_iter()
        .map(|b| b.header_id)
        .collect();
    assert!(
        !pending.contains(&h2a),
        "stale old-branch pending block must be pruned"
    );
    assert!(
        pending.contains(&h2b),
        "new best-branch pending block must be retained"
    );
}

#[test]
fn orphan_cap_preserves_root_side() {
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let p = peer(9030);

    let mut bytes_at_height: Vec<Vec<u8>> = Vec::new();
    for i in 0..(ORPHAN_HEADER_LIMIT + 3) {
        let mut bytes = vec![0u8; 37];
        bytes[33..37].copy_from_slice(&(i as u32).to_be_bytes());
        let mut header_id = [0u8; 32];
        header_id[28..32].copy_from_slice(&(i as u32).to_be_bytes());
        let pre =
            header_proc::PreValidatedHeader::for_test_unchecked(header_id, [0u8; 32], i as u32);
        bytes_at_height.push(bytes.clone());
        executor
            .orphan_headers
            .entry([0u8; 32])
            .or_default()
            .push((p, pre, bytes));
        executor.orphan_headers_len += 1;
    }
    let first = bytes_at_height[0].clone();
    let boundary = bytes_at_height[ORPHAN_HEADER_LIMIT - 1].clone();
    let dropped = bytes_at_height[ORPHAN_HEADER_LIMIT].clone();

    executor.cap_orphan_buffer();

    // cap_orphan_buffer drops the highest-height entries, so the
    // root side (lower heights, including `first` and `boundary`)
    // is preserved while `dropped` (above ORPHAN_HEADER_LIMIT-1)
    // is gone. Order within the remaining set is not guaranteed
    // (HashMap + swap_remove), so check by membership.
    let remaining: Vec<&Vec<u8>> = executor
        .orphan_headers
        .values()
        .flat_map(|v| v.iter())
        .map(|(_, _, b)| b)
        .collect();
    assert_eq!(executor.orphan_headers_len(), ORPHAN_HEADER_LIMIT);
    assert!(remaining.iter().any(|b| **b == first));
    assert!(remaining.iter().any(|b| **b == boundary));
    assert!(!remaining.iter().any(|b| **b == dropped));
}

#[test]
fn far_ahead_orphan_during_ibd_is_deferred_and_requestable_later() {
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let store = ergo_state::StateBackendKind::Utxo(
        StateStore::open(
            tempfile::tempdir()
                .unwrap()
                .path()
                .join("state.redb")
                .as_path(),
        )
        .unwrap(),
    );
    let mut coordinator = SyncCoordinator::new(0);
    let p = peer(9030);
    let header_id = [7u8; 32];

    coordinator.delivery_mut_for_test().request(
        p,
        ergo_p2p::types::ModifierTypeId::Header.as_byte(),
        &[header_id],
        Instant::now(),
    );
    coordinator
        .delivery_mut_for_test()
        .mark_received(&header_id);
    assert_eq!(
        coordinator.delivery().status(&header_id),
        ergo_p2p::delivery::ModifierStatus::Received,
    );

    let pre = header_proc::PreValidatedHeader::for_test_unchecked(
        header_id,
        [0u8; 32],
        ORPHAN_HEADER_IBD_LOOKAHEAD + 1,
    );
    let kept = executor.buffer_or_defer_orphan_header(
        p,
        pre,
        vec![1; 80],
        header_id,
        ORPHAN_HEADER_IBD_LOOKAHEAD + 1,
        &store,
        &mut coordinator,
    );

    assert!(!kept);
    assert!(executor.orphan_headers.is_empty());
    assert_eq!(
        coordinator.delivery().status(&header_id),
        ergo_p2p::delivery::ModifierStatus::Unknown,
        "deferred bytes were dropped, so the header must remain requestable later",
    );
}

#[test]
fn near_orphan_during_ibd_is_buffered_for_parent_walk() {
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let store = ergo_state::StateBackendKind::Utxo(
        StateStore::open(
            tempfile::tempdir()
                .unwrap()
                .path()
                .join("state.redb")
                .as_path(),
        )
        .unwrap(),
    );
    let mut coordinator = SyncCoordinator::new(0);
    let p = peer(9030);
    let header_id = [8u8; 32];
    let bytes = vec![2; 80];

    coordinator.delivery_mut_for_test().request(
        p,
        ergo_p2p::types::ModifierTypeId::Header.as_byte(),
        &[header_id],
        Instant::now(),
    );
    coordinator
        .delivery_mut_for_test()
        .mark_received(&header_id);

    let pre = header_proc::PreValidatedHeader::for_test_unchecked(
        header_id,
        [0u8; 32],
        ORPHAN_HEADER_IBD_LOOKAHEAD,
    );
    let kept = executor.buffer_or_defer_orphan_header(
        p,
        pre,
        bytes.clone(),
        header_id,
        ORPHAN_HEADER_IBD_LOOKAHEAD,
        &store,
        &mut coordinator,
    );

    assert!(kept);
    assert_eq!(executor.orphan_headers_len(), 1);
    let stored: Vec<_> = executor
        .orphan_headers
        .values()
        .flat_map(|v| v.iter())
        .collect();
    assert_eq!(stored[0].0, p);
    assert_eq!(stored[0].2, bytes);
    assert_eq!(
        coordinator.delivery().status(&header_id),
        ergo_p2p::delivery::ModifierStatus::Received,
    );
}

#[test]
fn far_ahead_orphan_after_header_sync_is_buffered_for_fork_recovery() {
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let store = ergo_state::StateBackendKind::Utxo(
        StateStore::open(
            tempfile::tempdir()
                .unwrap()
                .path()
                .join("state.redb")
                .as_path(),
        )
        .unwrap(),
    );
    let mut coordinator = SyncCoordinator::new(0);
    coordinator.sync_state_mut().set_headers_chain_synced();
    let p = peer(9030);
    let header_id = [9u8; 32];
    let bytes = vec![3; 80];

    let pre = header_proc::PreValidatedHeader::for_test_unchecked(
        header_id,
        [0u8; 32],
        ORPHAN_HEADER_IBD_LOOKAHEAD + 1_000_000,
    );
    let kept = executor.buffer_or_defer_orphan_header(
        p,
        pre,
        bytes.clone(),
        header_id,
        ORPHAN_HEADER_IBD_LOOKAHEAD + 1_000_000,
        &store,
        &mut coordinator,
    );

    assert!(kept);
    assert_eq!(executor.orphan_headers_len(), 1);
    let stored: Vec<_> = executor
        .orphan_headers
        .values()
        .flat_map(|v| v.iter())
        .collect();
    assert_eq!(stored[0].0, p);
    assert_eq!(stored[0].2, bytes);
}

#[test]
fn execute_penalize_returns_penalty() {
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut store = ergo_state::StateBackendKind::Utxo(
        StateStore::open(
            tempfile::tempdir()
                .unwrap()
                .path()
                .join("state.redb")
                .as_path(),
        )
        .unwrap(),
    );
    let mut coordinator = SyncCoordinator::new(0);

    let result = executor.execute(
        Action::Penalize {
            peer: peer(9030),
            penalty: Penalty::Spam,
        },
        &mut store,
        &mut coordinator,
        Instant::now(),
        None,
    );
    assert_eq!(result.len(), 1);
    assert!(matches!(
        result[0],
        Action::Penalize {
            penalty: Penalty::Spam,
            ..
        }
    ));
}

#[test]
fn execute_send_passes_through() {
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut store = ergo_state::StateBackendKind::Utxo(
        StateStore::open(
            tempfile::tempdir()
                .unwrap()
                .path()
                .join("state.redb")
                .as_path(),
        )
        .unwrap(),
    );
    let mut coordinator = SyncCoordinator::new(0);

    let result = executor.execute(
        Action::SendToPeer {
            peer: peer(9030),
            code: 55,
            payload: vec![1, 2],
        },
        &mut store,
        &mut coordinator,
        Instant::now(),
        None,
    );
    assert_eq!(result.len(), 1);
    assert!(matches!(result[0], Action::SendToPeer { .. }));
}

#[test]
fn s2_pipeline_needs_refill_on_empty_and_partial() {
    use ergo_p2p::delivery::MAX_IN_FLIGHT_PER_PEER;
    let executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(0);

    // Empty delivery tracker: needs refill (0 < DRAIN_WATERMARK).
    assert!(executor.pipeline_needs_refill(&coordinator));

    // Fill with DRAIN_WATERMARK-1 synthetic IDs on a single peer:
    // still below → still needs refill.
    let p = peer(9030);
    let ids: Vec<[u8; 32]> = (0..(DRAIN_WATERMARK as u16 - 1))
        .map(|i| {
            let mut b = [0u8; 32];
            b[..2].copy_from_slice(&i.to_be_bytes());
            b
        })
        .collect();
    let registered = coordinator
        .delivery_mut_for_test()
        .request(p, 101, &ids, Instant::now());
    assert_eq!(registered.len(), DRAIN_WATERMARK - 1);
    assert!(executor.pipeline_needs_refill(&coordinator));

    // Push over the watermark → no longer needs refill.
    let more: Vec<[u8; 32]> = (0..10u16)
        .map(|i| {
            let mut b = [0u8; 32];
            b[..2].copy_from_slice(&i.to_be_bytes());
            b[31] = 0xAA; // distinct from first batch
            b
        })
        .collect();
    coordinator
        .delivery_mut_for_test()
        .request(p, 101, &more, Instant::now());
    assert!(!executor.pipeline_needs_refill(&coordinator));

    // Sanity: we're well under per-peer cap.
    let total = coordinator.delivery().total_inflight();
    assert!(total < MAX_IN_FLIGHT_PER_PEER);
}

/// Helper: set up a PeerManager with two handshaked peers.
fn setup_two_peers(now: Instant) -> (PeerManager, PeerId, PeerId) {
    use ergo_p2p::handshake::{PeerSpec, Version};
    let mut mgr = PeerManager::new(12345);
    let p1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9030);
    let p2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 9030);
    let spec = PeerSpec {
        agent_name: "test".into(),
        version: Version::NIPOPOW,
        node_name: "n".into(),
        declared_address: None,
        features: Vec::new(),
    };
    mgr.register_outbound(p1, now).unwrap();
    mgr.mark_tcp_connected(&p1);
    mgr.complete_handshake(&p1, spec.clone(), None, now)
        .unwrap();
    mgr.register_outbound(p2, now).unwrap();
    mgr.mark_tcp_connected(&p2);
    mgr.complete_handshake(&p2, spec, None, now).unwrap();
    (mgr, p1, p2)
}

#[test]
fn executor_timeout_reassigns_via_peer_manager() {
    use ergo_p2p::types::{InvData, ModifierTypeId};

    let now = Instant::now();
    let (peer_mgr, p1, p2) = setup_two_peers(now);

    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(0);

    // Mock chain for on_inv
    struct EmptyChain;
    impl crate::coordinator::ChainView for EmptyChain {
        fn best_header_id(&self) -> [u8; 32] {
            [0; 32]
        }
        fn best_header_height(&self) -> u32 {
            0
        }
        fn best_full_block_height(&self) -> u32 {
            0
        }
        fn is_on_best_chain(&self, _: &[u8; 32]) -> bool {
            false
        }
        fn has_header(&self, _: &[u8; 32]) -> bool {
            false
        }
        fn has_block_section(&self, _: &[u8; 32]) -> bool {
            false
        }
        fn is_invalid(&self, _: &[u8; 32]) -> bool {
            false
        }
        fn recent_header_ids(&self, _: usize) -> Vec<[u8; 32]> {
            vec![]
        }
        fn recent_header_bytes(&self, _: usize) -> Vec<Vec<u8>> {
            vec![]
        }
        fn header_id_at_height(&self, _: u32) -> ergo_state::chain::HeightLookup {
            ergo_state::chain::HeightLookup::AboveTip
        }
        fn header_height_for(&self, _: &[u8; 32]) -> Option<u32> {
            None
        }
    }

    // Request modifier from p1
    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![[0xAA; 32]],
    };
    coordinator.on_inv(p1, &inv, &EmptyChain, now);

    // Advance past timeout
    let later = now + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let actions = executor.check_timeouts(&mut coordinator, &peer_mgr, later);

    // Should have penalty for p1 AND re-request to p2
    assert!(
        actions.iter().any(|a| matches!(a,
            Action::Penalize { peer, penalty: Penalty::NonDelivery } if *peer == p1)),
        "should penalize p1"
    );
    assert!(
        actions.iter().any(|a| matches!(a,
            Action::SendToPeer { peer, code: 22, .. } if *peer == p2)),
        "should re-request from p2 (not p1)"
    );
}

#[test]
fn executor_disconnect_reassigns_via_peer_manager() {
    use ergo_p2p::types::{InvData, ModifierTypeId};

    let now = Instant::now();
    let (peer_mgr, p1, p2) = setup_two_peers(now);

    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(0);

    struct EmptyChain;
    impl crate::coordinator::ChainView for EmptyChain {
        fn best_header_id(&self) -> [u8; 32] {
            [0; 32]
        }
        fn best_header_height(&self) -> u32 {
            0
        }
        fn best_full_block_height(&self) -> u32 {
            0
        }
        fn is_on_best_chain(&self, _: &[u8; 32]) -> bool {
            false
        }
        fn has_header(&self, _: &[u8; 32]) -> bool {
            false
        }
        fn has_block_section(&self, _: &[u8; 32]) -> bool {
            false
        }
        fn is_invalid(&self, _: &[u8; 32]) -> bool {
            false
        }
        fn recent_header_ids(&self, _: usize) -> Vec<[u8; 32]> {
            vec![]
        }
        fn recent_header_bytes(&self, _: usize) -> Vec<Vec<u8>> {
            vec![]
        }
        fn header_id_at_height(&self, _: u32) -> ergo_state::chain::HeightLookup {
            ergo_state::chain::HeightLookup::AboveTip
        }
        fn header_height_for(&self, _: &[u8; 32]) -> Option<u32> {
            None
        }
    }

    // Request 2 modifiers from p1
    let inv = InvData {
        type_id: ModifierTypeId::Header.as_byte(),
        ids: vec![[0xBB; 32], [0xCC; 32]],
    };
    coordinator.on_inv(p1, &inv, &EmptyChain, now);

    // p1 disconnects
    let actions = executor.on_peer_disconnected(&p1, &mut coordinator, &peer_mgr, now);

    // Should re-request both from p2
    let requests: Vec<_> = actions
        .iter()
        .filter(|a| matches!(a, Action::SendToPeer { peer, code: 22, .. } if *peer == p2))
        .collect();
    assert_eq!(
        requests.len(),
        2,
        "both cancelled requests should be reassigned to p2"
    );
}

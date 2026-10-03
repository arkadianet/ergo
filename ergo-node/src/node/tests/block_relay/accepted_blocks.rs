// ----- happy path -----

#[test]
fn locally_mined_block_same_parent_templates_without_recovery_accepts_newest() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    publish_candidate(&state, &handle);
    let older = solve(&state, &handle, 0);
    publish_candidate_after(&state, &handle, older.header.timestamp);
    let newer = solve(&state, &handle, 0);
    assert_eq!(older.nonce, newer.nonce);
    assert_ne!(older.id, newer.id);
    assert_eq!(older.header.parent_id, newer.header.parent_id);
    let result = submit_solution(&mut state, &handle, older.nonce);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(state.store.chain_state_meta().best_full_block_id, newer.id);
}

#[test]
fn remote_block_fresh_announces_each_id_to_every_handshaked_peer() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, sections) = prepare_block(&mut state, wall_clock_ms());
    let mut a = register_connected_peer(&mut state, "10.0.0.1:9001".parse().unwrap());
    let mut b = register_connected_peer(&mut state, "10.0.0.2:9001".parse().unwrap());
    state
        .peer_manager
        .register_inbound("10.0.0.3:9001".parse().unwrap(), Instant::now())
        .unwrap();
    let mut actions = apply(&mut state, id);
    actions.extend(super::super::block_relay::applied_block_announcements(
        &mut state, None,
    ));
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a, Action::SendToPeer { .. }))
            .count(),
        6
    );
    let peer_count = state.peer_manager.peer_count();
    flush_actions(&mut state, actions);
    assert_eq!(
        state.peer_manager.peer_count(),
        peer_count,
        "inbound-only peer must remain registered"
    );
    assert!(
        state
            .peer_manager
            .get(&"10.0.0.3:9001".parse().unwrap())
            .is_some(),
        "the inbound-only recipient must still be present after flush"
    );
    let expected = vec![
        (101, vec![id]),
        (102, vec![sections.transactions_id]),
        (108, vec![sections.extension_id]),
    ];
    assert_eq!(inventories(&mut a), expected);
    assert_eq!(inventories(&mut b), expected);
    flush_actions(&mut state, vec![]);
    assert!(inventories(&mut a).is_empty());
}

#[test]
fn remote_block_below_tip_window_sends_no_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, _) = prepare_block(&mut state, wall_clock_ms());
    let mut rx = register_connected_peer(&mut state, test_peer());
    let actions = apply(&mut state, id);
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .test_force_set_best_header_unsafe([77; 32], 18, vec![18])
        .unwrap();
    flush_actions(&mut state, actions);
    assert!(
        inventories(&mut rx).is_empty(),
        "fresh block 17 below best header must not relay"
    );
}

#[test]
fn relay_flush_pending_persist_failure_next_apply_still_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, _) = prepare_block(&mut state, wall_clock_ms());
    let _rx = register_connected_peer(&mut state, test_peer());
    let actions = apply(&mut state, id);
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .inject_pending_persist_failure_for_test(1);
    flush_actions(&mut state, actions);
    let store = state.store.as_utxo_mut().unwrap();
    let root = store.root_digest();
    let result = store.apply_block_unchecked_for_test(2, &[88; 32], &root, &[]);
    assert!(
        matches!(
            result,
            Err(ergo_state::store::StateError::PersistFailed { height: 1, .. })
        ),
        "next apply must see pending persist error, got {result:?}"
    );
}

#[test]
fn remote_block_sequential_apply_announces_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, _) = prepare_block(&mut state, wall_clock_ms());
    let mut rx = register_connected_peer(&mut state, test_peer());
    state.executor.try_apply_next_blocks(
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
    assert_eq!(state.store.chain_state_meta().best_full_block_id, id);
    flush_actions(&mut state, vec![]);
    assert_eq!(inventories(&mut rx).len(), 3);
    let actions = apply(&mut state, id);
    flush_actions(&mut state, actions);
    assert!(inventories(&mut rx).is_empty());
}

#[test]
fn mined_apply_failure_guard_any_applied_block_clears_it() {
    // The guard keys on the failed block's parent, so it matters again
    // only if the full tip returns to that parent; it is cleared once any
    // block applies, with no peer connected too.
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, _) = prepare_block(&mut state, wall_clock_ms());
    state.mined_apply_failed_parent = Some([9; 32]);
    flush_actions(&mut state, vec![]);
    assert_eq!(
        state.mined_apply_failed_parent,
        Some([9; 32]),
        "no block applied yet"
    );
    let actions = apply(&mut state, id);
    flush_actions(&mut state, actions);
    assert_eq!(state.mined_apply_failed_parent, None, "the full tip moved");
}

#[test]
fn locally_mined_first_block_applied_announces_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, root) = genesis_state(dir.path());
    let block = solved_block([0; 32], 1, wall_clock_ms(), root);
    let handle = mining_handle(&block);
    let mut rx = register_connected_peer(&mut state, test_peer());
    let result = submit_solution(&mut state, &handle, block.nonce);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(state.store.chain_state_meta().best_full_block_id, block.id);
    // One Inv set: announcing again from the applied-block drain would
    // repeat it here, before the handler returns.
    assert_eq!(inventories(&mut rx), full_inventory(&block));
    flush_actions(&mut state, vec![]);
    assert!(
        inventories(&mut rx).is_empty(),
        "nothing is left for a later flush"
    );
}

#[test]
fn locally_mined_block_non_genesis_apply_announces_once_before_apply() {
    // Height two runs the full non-genesis apply (height one goes through
    // the genesis apply): ADProofs regenerated and checked against the
    // header root, transaction and script validation, and the
    // regenerated proof re-stored. Both blocks come from the production
    // candidate engine over the devnet genesis state.
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    assert!(matches!(
        state.store.as_utxo().unwrap().ad_proofs_apply_policy(),
        ergo_state::store::AdProofsApplyPolicy::Regenerate
    ));
    let queue = register_shared_peer(&mut state);
    publish_candidate(&state, &handle);
    let mined = solve(&state, &handle, 0);
    let probed = submit_probing_apply(&mut state, &handle, mined.nonce, &queue);
    assert!(
        probed.result.is_ok(),
        "{:?}: {:?}",
        probed.result,
        state.executor.last_block_apply_error()
    );
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (chain.best_full_block_id, chain.best_full_block_height),
        (mined.id, 2)
    );
    assert_eq!(
        probed.before_apply,
        stored_inventory(&state, mined.id),
        "the whole Inv set is queued before apply starts"
    );
    assert!(
        probed.after_apply.is_empty(),
        "apply must not announce it again: {:?}",
        probed.after_apply
    );
    flush_actions(&mut state, vec![]);
    assert!(
        drain(&queue).is_empty(),
        "nothing is left for a later flush"
    );
    // An archive UTXO node serves every section; the ADProofs served now
    // is the proof apply regenerated and re-stored.
    assert_announced_ids_served(&mut state, &probed.before_apply);
}

#[test]
fn locally_mined_block_pruned_utxo_node_announces_once_before_apply() {
    // Keeping two blocks, every apply from height three on advances the
    // serving window and evicts the sections below it, so the blocks
    // below are mined while the window starts above height one.
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    state.store.as_utxo_mut().unwrap().set_blocks_to_keep(2);
    let first = mine_and_apply(&mut state, &handle);
    for _ in 2..=3 {
        mine_and_apply(&mut state, &handle);
    }
    let queue = register_shared_peer(&mut state);
    for height in 4..=8 {
        assert_eq!(
            state.store.read_minimal_full_block_height().unwrap(),
            height - 2,
            "pruning keeps the last two applied blocks"
        );
        mine_announced_before_apply(&mut state, &handle, &queue);
    }
    assert_eq!(state.store.chain_state_meta().best_full_block_height, 8);
    assert_eq!(state.store.read_minimal_full_block_height().unwrap(), 7);
    let first_sections = &stored_inventory(&state, first)[1..];
    assert_eq!(
        missing_from(state.store.as_utxo().unwrap(), first_sections).len(),
        3,
        "pruning evicted the first block's sections"
    );
    flush_actions(&mut state, vec![]);
    assert!(
        drain(&queue).is_empty(),
        "nothing is left for a later flush"
    );
}

#[test]
fn locally_mined_block_bootstrapped_utxo_node_announces_once_before_apply() {
    // A UTXO-snapshot or NiPoPoW bootstrap without pruning keeps every
    // block from its start height on: blocks_to_keep stays -1 while the
    // window starts above height one. It starts at the snapshot height
    // plus one, and the first candidate needs its parent's extension, so
    // production mines only above the window's first height; mining at
    // that height is the prune guard's boundary.
    const SENTINEL: u32 = 3;
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    for _ in 1..SENTINEL {
        mine_and_apply(&mut state, &handle);
    }
    state
        .store
        .as_utxo()
        .unwrap()
        .write_minimal_full_block_height(SENTINEL)
        .unwrap();
    let queue = register_shared_peer(&mut state);
    for _ in SENTINEL..=SENTINEL + 1 {
        mine_announced_before_apply(&mut state, &handle, &queue);
    }
    assert_eq!(
        state.store.read_minimal_full_block_height().unwrap(),
        SENTINEL,
        "the window does not move without pruning"
    );
    flush_actions(&mut state, vec![]);
    assert!(
        drain(&queue).is_empty(),
        "nothing is left for a later flush"
    );
}

#[test]
#[cfg_attr(
    windows,
    ignore = "copies the open redb file, which Windows locks while the store is open"
)]
fn locally_mined_block_crash_image_at_apply_holds_sections() {
    // No peer holds a mined block's sections before this node serves
    // them, so they must be on disk before apply starts: a node killed
    // during apply would otherwise restart with the header as its best
    // header and no body for it.
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    publish_candidate(&state, &handle);
    let mined = solve(&state, &handle, 0);
    let image = crash_image_at_apply(&mut state, dir.path(), |state| {
        assert!(submit_solution(state, &handle, mined.nonce).is_ok());
    });
    assert_eq!(
        missing_from(&image, &stored_inventory(&state, mined.id)),
        Vec::<[u8; 32]>::new(),
        "the header and every section are durable when apply starts"
    );
}

#[test]
#[cfg_attr(
    windows,
    ignore = "copies the open redb file, which Windows locks while the store is open"
)]
fn posted_block_crash_image_at_apply_holds_sections() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, root) = genesis_state(dir.path());
    let block = solved_block([0; 32], 1, wall_clock_ms(), root);
    let image = crash_image_at_apply(&mut state, dir.path(), |state| {
        assert!(post_block(state, &block));
    });
    assert_eq!(state.store.chain_state_meta().best_full_block_id, block.id);
    assert_eq!(
        missing_from(&image, &full_inventory(&block)),
        Vec::<[u8; 32]>::new(),
        "the header and every section are durable when apply starts"
    );
}

#[test]
fn locally_mined_block_known_header_without_sections_resubmission_applies() {
    // The state a section write failing after the header leaves: the
    // mined header is the best header and none of its sections is
    // stored. Resubmitting the solution stores them and applies it.
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    publish_candidate(&state, &handle);
    let mined = solve(&state, &handle, 0);
    process_header(&mut state, &serialize_header(&mined.header).unwrap().0);
    assert_eq!(state.store.chain_state_meta().best_header_id, mined.id);
    let queue = register_shared_peer(&mut state);
    let probed = submit_probing_apply(&mut state, &handle, mined.nonce, &queue);
    assert!(
        probed.result.is_ok(),
        "{:?}: {:?}",
        probed.result,
        state.executor.last_block_apply_error()
    );
    assert_eq!(state.store.chain_state_meta().best_full_block_id, mined.id);
    assert_eq!(
        probed.before_apply,
        stored_inventory(&state, mined.id),
        "announced once its sections are stored, before apply"
    );
    assert!(probed.after_apply.is_empty(), "{:?}", probed.after_apply);
    assert_announced_ids_served(&mut state, &probed.before_apply);
}

#[test]
fn locally_mined_block_known_header_resubmission_pending_persist_failure_reaches_apply() {
    // The resubmission's section-presence check must not drain the
    // persistence pipeline: a pending failure belongs to the apply that
    // follows, which must refuse the block instead of building on it.
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    publish_candidate(&state, &handle);
    let mined = solve(&state, &handle, 0);
    process_header(&mut state, &serialize_header(&mined.header).unwrap().0);
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .inject_pending_persist_failure_for_test(1);
    let queue = register_shared_peer(&mut state);
    let probed = submit_probing_apply(&mut state, &handle, mined.nonce, &queue);
    assert!(
        matches!(&probed.result, Err(ergo_api::MiningApiError::Internal(m)) if m.starts_with("block apply failed")),
        "{:?}",
        probed.result
    );
    assert_ne!(state.store.chain_state_meta().best_full_block_id, mined.id);
    let error = state.executor.last_block_apply_error();
    assert!(
        format!("{error:?}").contains("background persist failed at h=1"),
        "apply must see the pending persistence failure, got {error:?}"
    );
    // The resubmitted block is the best header, and it failed to apply,
    // so its parent's templates are withdrawn as after a first submission.
    assert!(probed.rebuild, "the failed apply asks for a rebuild");
    assert!(!handle.has_template_for_parent(&parent));
}

#[test]
fn locally_mined_block_tying_bodyless_best_header_applies_and_announces() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    publish_candidate(&state, &handle);
    let bodyless = solve(&state, &handle, 0);
    process_header(&mut state, &serialize_header(&bodyless.header).unwrap().0);
    let mut rx = register_connected_peer(&mut state, test_peer());
    let sibling = solve(&state, &handle, 1);
    let submitted = submit(&mut state, &handle, sibling.nonce);
    assert!(submitted.result.is_ok(), "{:?}", submitted.result);
    assert!(!submitted.rebuild);
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (
            chain.best_header_id,
            chain.best_full_block_id,
            chain.best_full_block_height
        ),
        (bodyless.id, sibling.id, 2)
    );
    flush_actions(&mut state, vec![]);
    let announced = inventories(&mut rx);
    assert_eq!(announced, stored_inventory(&state, sibling.id));
    assert_announced_ids_served(&mut state, &announced);
}

#[test]
fn locally_mined_block_after_failed_sibling_announces_once_after_apply() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    let queue = register_shared_peer(&mut state);
    publish_tampered_candidate(&state, &handle, replace_ad_proofs);
    let failed = solve(&state, &handle, 0);
    let result = submit_solution(&mut state, &handle, failed.nonce);
    assert!(apply_failed(&result), "{result:?}");
    assert_eq!(drain(&queue), stored_inventory(&state, failed.id));
    // A sound template on the same parent: its block applies and is
    // announced only then, exactly once.
    publish_candidate(&state, &handle);
    let mined = solve(&state, &handle, 0);
    assert_eq!(mined.header.parent_id.as_bytes(), &parent);
    let probed = submit_probing_apply(&mut state, &handle, mined.nonce, &queue);
    assert!(probed.result.is_ok(), "{:?}", probed.result);
    assert_eq!(state.store.chain_state_meta().best_full_block_id, mined.id);
    assert!(
        probed.before_apply.is_empty(),
        "not announced before apply on a parent whose announced child failed: {:?}",
        probed.before_apply
    );
    assert_eq!(probed.after_apply, stored_inventory(&state, mined.id));
    flush_actions(&mut state, vec![]);
    assert!(
        drain(&queue).is_empty(),
        "nothing is left for a later flush"
    );
    assert_announced_ids_served(&mut state, &probed.after_apply);
    // Pre-apply announcement resumes for the next block, on the new tip.
    // Its parent is never the guarded one, so this does not pin that the
    // guard clears; mined_apply_failure_guard_any_applied_block_clears_it
    // does.
    publish_candidate(&state, &handle);
    let next = solve(&state, &handle, 0);
    let probed = submit_probing_apply(&mut state, &handle, next.nonce, &queue);
    assert!(probed.result.is_ok(), "{:?}", probed.result);
    assert_eq!(probed.before_apply, stored_inventory(&state, next.id));
    assert!(probed.after_apply.is_empty(), "{:?}", probed.after_apply);
}

#[test]
fn locally_mined_fork_block_joining_best_chain_later_announced_once() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    publish_candidate(&state, &handle);
    let ours = solve(&state, &handle, 0);
    // An equal-score rival on the same parent reaches this node first.
    let rival = solve(&state, &handle, 1);
    process_header(&mut state, &serialize_header(&rival.header).unwrap().0);
    assert_eq!(state.store.chain_state_meta().best_header_id, rival.id);
    let mut rx = register_connected_peer(&mut state, test_peer());
    let submitted = submit(&mut state, &handle, ours.nonce);
    // Its full chain beats the applied tip despite tying the rival header.
    assert!(submitted.result.is_ok(), "{:?}", submitted.result);
    assert_eq!(state.store.chain_state_meta().best_full_block_id, ours.id);
    assert!(!submitted.rebuild);
    flush_actions(&mut state, vec![]);
    let announced = inventories(&mut rx);
    assert_eq!(announced, stored_inventory(&state, ours.id));
    assert_announced_ids_served(&mut state, &announced);
    // A child makes our already applied branch the best header chain.
    process_header(&mut state, &solved_child(&ours.header, ours.id));
    state.executor.try_apply_next_blocks(
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
    assert_eq!(state.store.chain_state_meta().best_full_block_id, ours.id);
    flush_actions(&mut state, vec![]);
    assert!(
        inventories(&mut rx).is_empty(),
        "the applied block is not announced twice"
    );
}

#[test]
fn posted_block_applied_announces_after_apply() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, root) = genesis_state(dir.path());
    let block = solved_block([0; 32], 1, wall_clock_ms(), root);
    let mut rx = register_connected_peer(&mut state, test_peer());
    assert!(post_block(&mut state, &block));
    assert_eq!(state.store.chain_state_meta().best_full_block_id, block.id);
    assert_eq!(inventories(&mut rx), full_inventory(&block));
    flush_actions(&mut state, vec![]);
    assert!(inventories(&mut rx).is_empty());
}

#[test]
fn remote_blocks_real_catch_up_flush_announces_only_near_tip() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let ids = prepare_mainnet_catch_up(state.store.as_utxo_mut().unwrap());
    state.executor.try_apply_next_blocks(
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
    assert_eq!(
        state.store.chain_state_meta().best_full_block_height,
        10,
        "all ten fixture blocks must actually apply: {:?}",
        state.executor.last_block_apply_error()
    );
    let applied = state.executor.take_applied_blocks();
    assert_eq!(
        applied, ids,
        "whole catch-up batch before a single relay flush"
    );
    let tip_bytes = state.store.get_header(&ids[9]).unwrap().unwrap();
    let now_ms = read_header(&mut VlqReader::new(&tip_bytes))
        .unwrap()
        .timestamp;
    // Deterministic historical wall time: all ten fixture blocks are fresh.
    for id in &ids {
        let bytes = state.store.get_header(id).unwrap().unwrap();
        assert!(now_ms - read_header(&mut VlqReader::new(&bytes)).unwrap().timestamp < 7_200_000);
    }
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .test_force_set_best_header_unsafe([77; 32], 25, vec![25])
        .unwrap();
    let (tx, mut rx) =
        crate::peer_loop::outbound::channel(crate::peer_loop::outbound::MAX_MESSAGES);
    state.registry.peers.insert(
        test_peer(),
        super::super::state::PeerRuntime {
            sync_version: SyncVersion::V2,
            outbound_tx: tx,
        },
    );
    let actions = super::super::block_relay::remote_announcements(&state, applied, now_ms);
    flush_actions(&mut state, actions);
    let announced: Vec<_> = inventories(&mut rx)
        .into_iter()
        .filter(|(kind, _)| *kind == 101)
        .map(|(_, ids)| ids[0])
        .collect();
    assert_eq!(
        announced,
        ids[8..],
        "only heights 9 and 10 are within 16 of header tip 25"
    );
    assert!(state.executor.take_applied_blocks().is_empty());
}

#[test]
fn remote_blocks_catch_up_only_tip_window_fits_queue() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let now = wall_clock_ms();
    let mut ids = Vec::new();
    // Simulate the drained feedback of a large catch-up batch. Executor
    // batch/reorg feedback itself is covered with real blocks in ergo-sync.
    for height in 1..=600 {
        let (_, bytes) = synthetic_header_with_state_root(
            height,
            ergo_primitives::digest::ADDigest::from_bytes([0; 33]),
        );
        let mut header = read_header(&mut VlqReader::new(&bytes)).unwrap();
        header.timestamp = now;
        let (bytes, id) = serialize_header(&header).unwrap();
        let id = *id.as_bytes();
        state.store.store_header(&id, &bytes).unwrap();
        let sections = ExpectedSections::from_header(&id, &[0; 32], &[0; 32], &[0; 32]);
        for (kind, section) in [
            (104, sections.ad_proofs_id),
            (102, sections.transactions_id),
            (108, sections.extension_id),
        ] {
            state
                .store
                .store_block_section_typed(&section, &[kind], kind)
                .unwrap();
        }
        ids.push(id);
    }
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .test_force_set_best_header_unsafe(ids[599], 600, vec![1])
        .unwrap();
    let (tx, mut rx) =
        crate::peer_loop::outbound::channel(crate::peer_loop::outbound::MAX_MESSAGES);
    state.registry.peers.insert(
        test_peer(),
        super::super::state::PeerRuntime {
            sync_version: SyncVersion::V2,
            outbound_tx: tx,
        },
    );
    let actions = super::super::block_relay::remote_announcements(&state, ids.clone(), now);
    assert_eq!(actions.len(), 17 * 4, "inclusive tip through tip-16");
    flush_actions(&mut state, actions);
    let announced = inventories(&mut rx);
    let headers: Vec<_> = announced
        .iter()
        .filter(|(kind, _)| *kind == 101)
        .map(|(_, ids)| ids[0])
        .collect();
    assert_eq!(headers, ids[583..], "only the last 17 heights may relay");
    let actions =
        super::super::block_relay::remote_announcements(&state, ids[584..].iter().copied(), now);
    assert_eq!(actions.len(), 16 * 4);
    assert!(
        actions.len() < crate::peer_loop::outbound::MAX_MESSAGES / 16,
        "16-block burst must leave ample queue headroom"
    );
}

#[test]
fn remote_block_freshness_boundary_matches_scala() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let timestamp = 10_000_000;
    let (id, _) = prepare_block(&mut state, timestamp);
    let _rx = register_connected_peer(&mut state, test_peer());
    assert_eq!(
        super::super::block_relay::block_announcements(&state, id, Announcement::Mined).len(),
        3
    );
    for (now, count) in [
        (0, 0),
        (timestamp - 1, 3),
        (timestamp + 7_199_999, 3),
        (timestamp + 7_200_000, 0),
    ] {
        let actions = super::super::block_relay::block_announcements(
            &state,
            id,
            Announcement::Remote {
                now_ms: now,
                best_header_height: 1,
            },
        );
        assert_eq!(actions.len(), count, "now={now}");
    }
}

#[test]
fn served_sections_storage_modes_match_request_modifier_handler() {
    // Includes proof-retaining UTXO, proof-less UTXO, digest, and the
    // prune/bootstrap sentinel at/below the stored header's height.
    for digest in [false, true] {
        for proofs in [false, true] {
            for sentinel in [1, 10, 11] {
                if digest && sentinel != 1 {
                    continue; // Digest has no configurable pruning window.
                }
                let dir = tempfile::tempdir().unwrap();
                let mut state = if digest {
                    make_digest_state(&dir.path().join("state.redb"))
                } else {
                    make_state(&dir.path().join("state.redb"))
                };
                let (id, bytes) = synthetic_header_with_state_root(
                    10,
                    ergo_primitives::digest::ADDigest::from_bytes([0; 33]),
                );
                state.store.store_header(&id, &bytes).unwrap();
                let sections = ExpectedSections::from_header(&id, &[0; 32], &[0; 32], &[0; 32]);
                let entries = [
                    (104, sections.ad_proofs_id),
                    (102, sections.transactions_id),
                    (108, sections.extension_id),
                ];
                for (kind, section_id) in entries {
                    if kind != 104 || proofs {
                        state
                            .store
                            .store_block_section_typed(&section_id, &[kind; 8], kind)
                            .unwrap();
                    }
                }
                let orphan = [99; 32];
                state
                    .store
                    .store_block_section_typed(&orphan, &[102; 8], 102)
                    .unwrap();
                if let Some(store) = state.store.as_utxo_mut() {
                    if sentinel > 1 {
                        store.set_blocks_to_keep(1000);
                    }
                    store.write_minimal_full_block_height(sentinel).unwrap();
                }
                let peer = test_peer();
                let mut rx = register_connected_peer(&mut state, peer);
                let actions =
                    super::super::block_relay::block_announcements(&state, id, Announcement::Mined);
                flush_actions(&mut state, actions);
                let advertised = inventories(&mut rx);
                let expected: Vec<_> = std::iter::once((101, vec![id]))
                    .chain(
                        entries
                            .into_iter()
                            .filter(|(kind, _)| sentinel <= 10 && (*kind != 104 || proofs))
                            .map(|(kind, id)| (kind, vec![id])),
                    )
                    .collect();
                assert_eq!(
                    advertised, expected,
                    "digest={digest} proofs={proofs} sentinel={sentinel}"
                );
                for (kind, section_id) in std::iter::once((101, id)).chain(entries) {
                    let request = message::serialize_inv(&InvData {
                        type_id: kind,
                        ids: vec![section_id],
                    })
                    .unwrap();
                    let actions = handle_message(
                        &mut state,
                        peer,
                        message::CODE_REQUEST_MODIFIER,
                        &request,
                        Instant::now(),
                    );
                    let advertised_id = advertised.contains(&(kind, vec![section_id]));
                    assert_eq!(
                        !actions.is_empty(),
                        advertised_id,
                        "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                    );
                    for action in actions {
                        let Action::SendToPeer { code, payload, .. } = action else {
                            panic!("expected served modifier: digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}")
                        };
                        assert_eq!(
                            code,
                            message::CODE_MODIFIER,
                            "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                        );
                        let served = message::deserialize_modifiers(&payload).unwrap();
                        assert_eq!(
                            served.type_id, kind,
                            "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                        );
                        assert_eq!(
                            served.modifiers.len(),
                            1,
                            "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                        );
                        assert_eq!(
                            served.modifiers[0].0, section_id,
                            "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                        );
                        let expected_bytes = if kind == 101 {
                            bytes.clone()
                        } else {
                            vec![kind; 8]
                        };
                        assert_eq!(
                            served.modifiers[0].1, expected_bytes,
                            "digest={digest} proofs={proofs} sentinel={sentinel} kind={kind}"
                        );
                    }
                }
                // A stored section without a header index fails closed when pruned.
                let request = message::serialize_inv(&InvData {
                    type_id: 102,
                    ids: vec![orphan],
                })
                .unwrap();
                let actions = handle_message(
                    &mut state,
                    peer,
                    message::CODE_REQUEST_MODIFIER,
                    &request,
                    Instant::now(),
                );
                assert_eq!(
                    actions.is_empty(),
                    sentinel > 1,
                    "digest={digest} proofs={proofs} sentinel={sentinel} orphan"
                );
                assert_eq!(
                    super::super::section_serving::servable_section(
                        &state.store,
                        &orphan,
                        sentinel
                    )
                    .is_none(),
                    sentinel > 1,
                    "digest={digest} proofs={proofs} sentinel={sentinel} orphan helper"
                );
            }
        }
    }
}

#[test]
fn served_sections_mixed_request_returns_only_retained_indexed_ids() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let mut ids = Vec::new();
    for height in [9, 10] {
        let (id, bytes) = synthetic_header_with_state_root(
            height,
            ergo_primitives::digest::ADDigest::from_bytes([0; 33]),
        );
        state.store.store_header(&id, &bytes).unwrap();
        ids.push(ExpectedSections::from_header(&id, &[0; 32], &[0; 32], &[0; 32]).transactions_id);
    }
    ids.push([99; 32]); // stored, unindexed orphan
    for id in &ids {
        state
            .store
            .store_block_section_typed(id, &[42], 102)
            .unwrap();
    }
    let store = state.store.as_utxo_mut().unwrap();
    store.set_blocks_to_keep(1000);
    store.write_minimal_full_block_height(10).unwrap();
    let request = message::serialize_inv(&InvData {
        type_id: 102,
        ids: ids.clone(),
    })
    .unwrap();
    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_REQUEST_MODIFIER,
        &request,
        Instant::now(),
    );
    assert_eq!(actions.len(), 1);
    let Action::SendToPeer { code, payload, .. } = &actions[0] else {
        panic!("expected modifier response")
    };
    assert_eq!(*code, message::CODE_MODIFIER);
    assert_eq!(
        message::deserialize_modifiers(payload).unwrap().modifiers,
        vec![(ids[1], vec![42])]
    );
}

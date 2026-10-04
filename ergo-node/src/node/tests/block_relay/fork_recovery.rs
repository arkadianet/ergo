#[test]
fn session_tie_marked_fork_below_applied_tip_never_rolls_back() {
    for stored in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, handle) = devnet_node(dir.path());
        mine_and_apply(&mut state, &handle);
        publish_tampered_candidate(&state, &handle, replace_state_root);
        let x1 = prepared_solution(&state, &handle);
        process_header(&mut state, &x1.header_bytes);
        ergo_mining::submit::store_mined_sections(state.store.as_utxo().unwrap(), &x1).unwrap();
        drain_prepared(&mut state);
        assert!(state.store.is_invalid(&x1.header_id).unwrap());
        let x2 = solved_child(
            &read_header(&mut VlqReader::new(&x1.header_bytes)).unwrap(),
            x1.header_id,
        );
        let a1 = mine_and_apply(&mut state, &handle);
        publish_tampered_candidate(&state, &handle, replace_state_root);
        let b = prepared_solution(&state, &handle);
        process_header(&mut state, &b.header_bytes);
        if stored {
            process_header(&mut state, &x2);
        }
        ergo_mining::submit::store_mined_sections(state.store.as_utxo().unwrap(), &b).unwrap();
        drain_prepared(&mut state);
        if !stored {
            process_header(&mut state, &x2);
        }
        assert_eq!(
            state.store.chain_state_meta().best_header_id,
            b.header_id,
            "stored={stored}"
        );
        drain_prepared(&mut state);
        assert_eq!(state.store.chain_state_meta().best_full_block_id, a1);
        mine_and_apply(&mut state, &handle);
        assert_eq!(state.store.chain_state_meta().best_full_block_height, 3);
    }
}

#[test]
fn session_promotion_ineligible_siblings_keep_failed_tip() {
    for (validity, marked, lower_score) in [
        (0, false, false),
        (2, false, false),
        (3, false, false),
        (1, true, false),
        (1, false, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (mut source, handle) = devnet_node(dir.path());
        let mut state = digest_peer(&mut source, dir.path());
        let parent = mine_and_apply(&mut source, &handle);
        copy_remote_block(&source, &mut state, parent);
        drain_prepared(&mut state);
        publish_candidate(&source, &handle);
        let sibling = prepared_solution(&source, &handle);
        publish_tampered_candidate(&source, &handle, replace_state_root);
        let bad = prepared_solution(&source, &handle);
        process_header(&mut source, &bad.header_bytes);
        ergo_mining::submit::store_mined_sections(source.store.as_utxo().unwrap(), &bad).unwrap();
        copy_remote_block(&source, &mut state, bad.header_id);
        process_header(&mut state, &sibling.header_bytes);
        let mut meta = state
            .store
            .get_header_meta(&sibling.header_id)
            .unwrap()
            .unwrap();
        meta.pow_validity = validity;
        let mut score = num_bigint::BigUint::from_bytes_be(
            &state
                .store
                .get_header_meta(&bad.header_id)
                .unwrap()
                .unwrap()
                .cumulative_score,
        );
        if lower_score {
            score -= num_bigint::BigUint::from(1u8);
        }
        meta.cumulative_score = score.to_bytes_be();
        state
            .store
            .store_validated_header(&sibling.header_id, &sibling.header_bytes, &meta, None)
            .unwrap();
        if marked {
            state.store.mark_session_invalid(sibling.header_id);
        }
        drain_prepared(&mut state);
        assert_eq!(
            state.store.chain_state_meta().best_header_id,
            bad.header_id,
            "validity={validity}, marked={marked}, score={score}"
        );
    }
}

#[test]
fn remote_header_batch_new_best_preserves_selected_downloads() {
    let dir = tempfile::tempdir().unwrap();
    let (mut source, handle) = devnet_node(dir.path());
    let path = dir.path().join("peer");
    std::fs::create_dir(&path).unwrap();
    let mut state = devnet_node(&path).0;
    let parent = mine_and_apply(&mut source, &handle);
    copy_remote_block(&source, &mut state, parent);
    drain_prepared(&mut state);
    let first = mine_and_apply(&mut source, &handle);
    let second = mine_and_apply(&mut source, &handle);
    let actions = [first, second]
        .into_iter()
        .map(|id| Action::ValidateHeader {
            peer: test_peer(),
            modifier_id: id,
            header_bytes: source.store.get_header(&id).unwrap().unwrap(),
        })
        .collect();
    state.executor.execute_all(
        actions,
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
    for id in [first, second] {
        assert!(state
            .coordinator
            .sync_state()
            .pending_blocks_iter()
            .any(|b| b.header_id == id));
        assert!(state
            .coordinator
            .assembly_mut()
            .expected_section_ids(&id)
            .is_some());
    }
}

#[test]
fn remote_tie_after_recovery_requests_ancestor_and_applies() {
    for delivery in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let (mut source, handle) = devnet_node(dir.path());
        let path = dir.path().join("peer");
        std::fs::create_dir(&path).unwrap();
        let mut state = devnet_node(&path).0;
        let parent = mine_and_apply(&mut source, &handle);
        copy_remote_block(&source, &mut state, parent);
        drain_prepared(&mut state);
        publish_tampered_candidate(&source, &handle, replace_state_root);
        let bad = prepared_solution(&source, &handle);
        remote_header(&mut state, &bad.header_bytes);
        let meta = state
            .store
            .get_header_meta(&bad.header_id)
            .unwrap()
            .unwrap();
        source
            .store
            .store_validated_header(&bad.header_id, &bad.header_bytes, &meta, None)
            .unwrap();
        ergo_mining::submit::store_mined_sections(source.store.as_utxo().unwrap(), &bad).unwrap();
        let sibling = mine_and_apply(&mut source, &handle);
        let child = mine_and_apply(&mut source, &handle);
        if delivery != 2 {
            remote_header(
                &mut state,
                &source.store.get_header(&sibling).unwrap().unwrap(),
            );
        }

        let blocked_child = solved_child(
            &read_header(&mut VlqReader::new(&bad.header_bytes)).unwrap(),
            bad.header_id,
        );
        remote_header(&mut state, &blocked_child);
        // Startup recovery retains only the selected B/C branch.
        state.coordinator = SyncCoordinator::new(1);
        remote_sections(&source, &mut state, bad.header_id, false);
        drain_prepared(&mut state);
        assert!(state.store.is_invalid(&bad.header_id).unwrap());
        assert!(!state
            .coordinator
            .sync_state()
            .pending_blocks_iter()
            .any(|b| b.header_id == sibling));
        let blocked_id = *ergo_primitives::digest::blake2b256(&blocked_child).as_bytes();
        state
            .coordinator
            .sync_state_mut()
            .add_pending_block(3, blocked_id);
        let blocked_header = read_header(&mut VlqReader::new(&blocked_child)).unwrap();
        state.coordinator.assembly_mut().register_header(
            ergo_ser::modifier_id::ExpectedSections::from_header(
                &blocked_id,
                blocked_header.transactions_root.as_bytes(),
                blocked_header.extension_root.as_bytes(),
                blocked_header.ad_proofs_root.as_bytes(),
            ),
            false,
        );
        let child_bytes = source.store.get_header(&child).unwrap().unwrap();
        match delivery {
            0 => remote_header(&mut state, &child_bytes),
            1 => {
                let actions = [sibling, child]
                    .into_iter()
                    .map(|id| Action::ValidateHeader {
                        peer: test_peer(),
                        modifier_id: id,
                        header_bytes: source.store.get_header(&id).unwrap().unwrap(),
                    })
                    .collect();
                state.executor.execute_all(
                    actions,
                    &mut state.store,
                    &mut state.coordinator,
                    Instant::now(),
                    None,
                );
            }
            3 => process_header(&mut state, &child_bytes),
            _ => {
                state.executor.execute(
                    Action::ValidateHeader {
                        peer: test_peer(),
                        modifier_id: child,
                        header_bytes: child_bytes,
                    },
                    &mut state.store,
                    &mut state.coordinator,
                    Instant::now(),
                    None,
                );
                remote_header(
                    &mut state,
                    &source.store.get_header(&sibling).unwrap().unwrap(),
                );
            }
        }

        assert!(!state
            .coordinator
            .sync_state()
            .pending_blocks_iter()
            .any(|b| b.header_id == bad.header_id || b.header_id == blocked_id));
        assert!(state
            .coordinator
            .assembly_mut()
            .expected_section_ids(&blocked_id)
            .is_none());
        drain_prepared(&mut state);
        let actions = state.coordinator.request_missing_sections_bucketed(
            &state.store,
            Instant::now(),
            &[test_peer()],
        );
        if delivery == 0 {
            assert!(
                actions.iter().any(|a| match a {
                    Action::SendToPeer { code, payload, .. }
                        if *code == message::CODE_REQUEST_MODIFIER =>
                    {
                        let inv = message::deserialize_inv(payload).unwrap();
                        stored_inventory(&source, sibling)
                            .iter()
                            .any(|(kind, ids)| {
                                *kind == inv.type_id && ids.iter().any(|id| inv.ids.contains(id))
                            })
                    }
                    _ => false,
                }),
                "ancestor section request missing: {actions:?}"
            );
        }
        remote_sections(&source, &mut state, sibling, true);
        remote_sections(&source, &mut state, child, true);
        drain_prepared(&mut state);
        assert_eq!(state.store.chain_state_meta().best_full_block_id, child);
    }
}

#[test]
fn remote_durable_verdict_stored_descendant_applies_both_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let (mut source, handle) = devnet_node(dir.path());
    let path = dir.path().join("peer");
    std::fs::create_dir(&path).unwrap();
    let mut state = devnet_node(&path).0;
    let parent = mine_and_apply(&mut source, &handle);
    copy_remote_block(&source, &mut state, parent);
    drain_prepared(&mut state);
    publish_tampered_candidate(&source, &handle, replace_ad_proofs);
    let bad = prepared_solution(&source, &handle);
    remote_header(&mut state, &bad.header_bytes);
    ergo_mining::submit::store_mined_sections(state.store.as_utxo().unwrap(), &bad).unwrap();
    let blocked_child = solved_child(
        &read_header(&mut VlqReader::new(&bad.header_bytes)).unwrap(),
        bad.header_id,
    );
    remote_header(&mut state, &blocked_child);
    let sibling = mine_and_apply(&mut source, &handle);
    let child = mine_and_apply(&mut source, &handle);
    for block in [sibling, child] {
        copy_remote_block(&source, &mut state, block);
    }
    state.executor.take_applied_blocks();
    drain_prepared(&mut state);
    assert!(state.store.is_durably_invalid(&bad.header_id).unwrap());
    drain_prepared(&mut state);
    assert_eq!(state.store.chain_state_meta().best_header_id, child);
    assert_eq!(state.store.chain_state_meta().best_full_block_id, child);
    assert_eq!(state.executor.take_applied_blocks(), vec![sibling, child]);
}

#[test]
fn digest_reorg_without_marks_applies_sibling_and_child() {
    let dir = tempfile::tempdir().unwrap();
    let (mut source, handle) = devnet_node(dir.path());
    let mut state = digest_peer(&mut source, dir.path());
    let parent = mine_and_apply(&mut source, &handle);
    copy_remote_block(&source, &mut state, parent);
    drain_prepared(&mut state);
    publish_candidate(&source, &handle);
    let x = prepared_solution(&source, &handle);
    remote_header(&mut state, &x.header_bytes);
    let meta = state.store.get_header_meta(&x.header_id).unwrap().unwrap();
    source
        .store
        .store_validated_header(&x.header_id, &x.header_bytes, &meta, None)
        .unwrap();
    ergo_mining::submit::store_mined_sections(source.store.as_utxo().unwrap(), &x).unwrap();
    remote_sections(&source, &mut state, x.header_id, false);
    drain_prepared(&mut state);
    assert_eq!(
        state.store.chain_state_meta().best_full_block_id,
        x.header_id
    );
    let y = mine_and_apply(&mut source, &handle);
    let z = mine_and_apply(&mut source, &handle);
    assert_ne!(x.header_id, y);
    copy_remote_block(&source, &mut state, y);
    copy_remote_block(&source, &mut state, z);
    state.executor.take_applied_blocks();
    drain_prepared(&mut state);
    assert_eq!(state.store.chain_state_meta().best_full_block_id, z);
    let applied = state.executor.take_applied_blocks();
    assert_eq!(applied, vec![y, z]);
    for id in [x.header_id, y, z] {
        assert!(!state.store.is_invalid(&id).unwrap());
    }
    assert_eq!(state.store.chain_state_meta().best_header_id, z);
}

#[test]
fn digest_block_session_failure_later_sibling_applies() {
    session_sibling(true, true, false);
}

#[test]
fn session_block_network_extension_keeps_heavier_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    publish_tampered_candidate(&state, &handle, replace_state_root);
    let bad = prepared_solution(&state, &handle);
    let header = read_header(&mut VlqReader::new(&bad.header_bytes)).unwrap();
    let child = solved_child(&header, bad.header_id);
    let child_id = *ergo_primitives::digest::blake2b256(&child).as_bytes();
    process_header(&mut state, &bad.header_bytes);
    process_header(&mut state, &child);
    ergo_mining::submit::store_mined_sections(state.store.as_utxo().unwrap(), &bad).unwrap();
    drain_prepared(&mut state);
    publish_candidate(&state, &handle);
    let sibling = prepared_solution(&state, &handle);
    process_header(&mut state, &sibling.header_bytes);
    assert_eq!(state.store.chain_state_meta().best_header_id, child_id);
    assert_eq!(state.store.chain_state_meta().best_full_block_id, parent);
    // A tie on another child of the blocked branch cannot escape the blockage.
    let mut blocked_parent = header.clone();
    blocked_parent.timestamp += 1;
    let blocked_tie = solved_child(&blocked_parent, bad.header_id);
    process_header(&mut state, &blocked_tie);
    assert_eq!(state.store.chain_state_meta().best_header_id, child_id);
    let mut other = read_header(&mut VlqReader::new(&child)).unwrap();
    other.timestamp += 1;
    let other = solved_child(&other, child_id);
    // A strictly heavier extension still wins even though its branch is blocked.
    process_header(&mut state, &other);
    assert_eq!(state.store.chain_state_meta().best_header_height, 4);
}

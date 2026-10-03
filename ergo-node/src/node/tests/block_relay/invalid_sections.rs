#[test]
fn failed_apply_invalidity_each_mark_reports_its_kind() {
    // The error log for an announced mined block that did not apply names
    // how apply left it.
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, _) = prepare_block(&mut state, wall_clock_ms());
    let invalidity =
        |state: &NodeState| super::super::mining_dispatch::failed_apply_invalidity(state, &id).0;
    assert_eq!(invalidity(&state), "none");
    state.store.mark_session_invalid(id);
    assert_eq!(invalidity(&state), "session");
    state.store.invalidate_validation_branch(id).unwrap();
    assert_eq!(invalidity(&state), "durable");
}

#[test]
fn locally_mined_block_section_root_mismatch_sends_no_inventory() {
    // A header root the stored section bytes do not hash to. A receiving
    // peer recomputes the section id from the bytes, rejects a mismatch
    // and penalizes the sender, so nothing is announced; apply rejects
    // the block too. The last case roots the transactions over their ids
    // alone, the version-one formula, while the bytes carry the header's
    // later version marker: this node's section check accepts either
    // formula, but Scala derives the id from the marker.
    let tampers: [(&str, Tamper); 4] = [
        ("transactions", |c| {
            c.header.transactions_root = ergo_primitives::digest::Digest32::from_bytes([0x55; 32])
        }),
        ("extension", |c| {
            c.header.extension_root = ergo_primitives::digest::Digest32::from_bytes([0x55; 32])
        }),
        ("ad_proofs", |c| {
            c.header.ad_proofs_root = ergo_primitives::digest::Digest32::from_bytes([0x55; 32])
        }),
        ("transactions_version_one_formula", |c| {
            assert!(c.header.version > 1, "{}", c.header.version);
            let tx_ids: Vec<_> = c
                .transactions
                .iter()
                .map(|tx| {
                    *ergo_ser::transaction::transaction_id(tx)
                        .unwrap()
                        .as_bytes()
                })
                .collect();
            let tx_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
            c.header.transactions_root = ergo_primitives::digest::Digest32::from_bytes(
                ergo_crypto::merkle::transactions_root(&tx_refs, None),
            );
        }),
    ];
    for (root, tamper) in tampers {
        let dir = tempfile::tempdir().unwrap();
        let (mut state, handle) = devnet_node(dir.path());
        mine_and_apply(&mut state, &handle);
        let mut rx = register_connected_peer(&mut state, test_peer());
        publish_tampered_candidate(&state, &handle, tamper);
        let mined = solve(&state, &handle, 0);
        let result = submit_solution(&mut state, &handle, mined.nonce);
        assert!(apply_failed(&result), "{root}: {result:?}");
        assert_eq!(
            state
                .store
                .get_header_meta(&mined.id)
                .unwrap()
                .unwrap()
                .pow_validity,
            3,
            "{root}: the header passed the pipeline and apply rejected the block"
        );
        flush_actions(&mut state, vec![]);
        assert!(inventories(&mut rx).is_empty(), "{root}");
    }
}

#[test]
fn posted_block_apply_failure_sends_no_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, _) = genesis_state(dir.path());
    let block = solved_block([0; 32], 1, wall_clock_ms(), ADDigest::from_bytes([7; 33]));
    let mut rx = register_connected_peer(&mut state, test_peer());
    assert!(
        post_block(&mut state, &block),
        "the stored header answers 200"
    );
    assert_ne!(state.store.chain_state_meta().best_full_block_id, block.id);
    flush_actions(&mut state, vec![]);
    assert!(
        inventories(&mut rx).is_empty(),
        "POST /blocks announces only after a successful apply"
    );
}

#[test]
fn served_sections_oversized_proof_is_not_announced() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, sections) = prepare_block(&mut state, wall_clock_ms());
    state
        .store
        .store_block_section_typed(&sections.ad_proofs_id, &vec![0; 9 * 1024 * 1024], 104)
        .unwrap();
    let peer = test_peer();
    let mut rx = register_connected_peer(&mut state, peer);
    let actions = super::super::block_relay::block_announcements(&state, id, Announcement::Mined);
    flush_actions(&mut state, actions);
    assert_eq!(
        inventories(&mut rx),
        vec![
            (101, vec![id]),
            (102, vec![sections.transactions_id]),
            (108, vec![sections.extension_id]),
        ]
    );
    let request = message::serialize_inv(&InvData {
        type_id: 104,
        ids: vec![sections.ad_proofs_id],
    })
    .unwrap();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_REQUEST_MODIFIER,
        &request,
        Instant::now(),
    );
    assert!(
        actions.is_empty(),
        "the serving encoder refuses this proof too"
    );
}

#[test]
fn remote_block_unreadable_clock_drains_without_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, _) = prepare_block(&mut state, wall_clock_ms());
    let _rx = register_connected_peer(&mut state, test_peer());
    apply(&mut state, id);
    let broken_clock = std::time::UNIX_EPOCH - Duration::from_secs(1);
    let actions =
        super::super::block_relay::applied_block_announcements_at(&mut state, None, broken_clock);
    assert!(actions.is_empty(), "unreadable clock must fail closed");
    assert!(
        state.executor.take_applied_blocks().is_empty(),
        "bad clock must not accumulate feedback"
    );
}

#[test]
fn remote_block_old_timestamp_sends_no_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, _) = prepare_block(&mut state, wall_clock_ms() - 7_200_001);
    let mut rx = register_connected_peer(&mut state, test_peer());
    let actions = apply(&mut state, id);
    flush_actions(&mut state, actions);
    assert!(inventories(&mut rx).is_empty());
}

#[test]
fn remote_block_unknown_header_sends_no_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let (id, _) = prepare_block(&mut state, wall_clock_ms());
    let _connected = register_connected_peer(&mut state, "10.0.0.8:9001".parse().unwrap());
    assert!(super::super::block_relay::block_announcements(
        &state,
        [99; 32],
        Announcement::Remote {
            now_ms: wall_clock_ms(),
            best_header_height: 1
        }
    )
    .is_empty());
    // Advertised id is not an applicable block: no success feedback.
    let mut rx = register_connected_peer(&mut state, test_peer());
    let actions = state.executor.execute(
        Action::AssembleBlock {
            header_id: [99; 32],
        },
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
    assert_ne!(state.store.chain_state_meta().best_full_block_id, id);
    flush_actions(&mut state, actions);
    assert!(inventories(&mut rx).is_empty());
}

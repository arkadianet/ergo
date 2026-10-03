// ----- error paths -----

#[test]
fn locally_mined_block_header_rejected_stores_no_sections() {
    // The header pipeline runs before any section is written, so a mined
    // block whose header it refuses leaves no section behind.
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    state
        .executor
        .set_header_checkpoint(Some(ergo_sync::header_proc::HeaderCheckpoint {
            height: 2,
            block_id: [0xAB; 32],
        }));
    let mut rx = register_connected_peer(&mut state, test_peer());
    publish_candidate(&state, &handle);
    let mined = solve(&state, &handle, 0);
    let result = submit_solution(&mut state, &handle, mined.nonce);
    assert!(
        matches!(
            &result,
            Err(ergo_api::MiningApiError::Internal(reason)) if reason.starts_with("process_header:")
        ),
        "{result:?}"
    );
    assert!(state.store.get_header(&mined.id).unwrap().is_none());
    let sections = ExpectedSections::from_header(
        &mined.id,
        mined.header.transactions_root.as_bytes(),
        mined.header.extension_root.as_bytes(),
        mined.header.ad_proofs_root.as_bytes(),
    );
    for id in [
        sections.transactions_id,
        sections.extension_id,
        sections.ad_proofs_id,
    ] {
        assert!(
            state.store.get_block_section(&id).unwrap().is_none(),
            "section {} was stored for a refused header",
            hex::encode(id)
        );
    }
    assert!(inventories(&mut rx).is_empty());
}

#[test]
fn locally_mined_block_section_store_failure_after_header_sends_no_inventory() {
    // The header is stored before the sections. Starting the serving
    // window above the mined height makes the prune guard refuse the
    // section write that follows, which production reaches only on a
    // storage failure: the header stays stored without its sections, and
    // nothing is announced.
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    state
        .store
        .as_utxo()
        .unwrap()
        .write_minimal_full_block_height(3)
        .unwrap();
    let mut rx = register_connected_peer(&mut state, test_peer());
    publish_candidate(&state, &handle);
    let mined = solve(&state, &handle, 0);
    let persist_failed = |result: &Result<(), ergo_api::MiningApiError>| {
        matches!(
            result,
            Err(ergo_api::MiningApiError::Internal(reason))
                if reason.starts_with("persist:") && reason.contains("sentinel")
        )
    };
    let (storage_errors, _) = ergo_state::storage_observability::storage_error_totals();
    let result = submit_solution(&mut state, &handle, mined.nonce);
    assert!(persist_failed(&result), "{result:?}");
    assert!(
        ergo_state::storage_observability::storage_error_totals().0 > storage_errors,
        "the failure is reported to storage health"
    );
    // The best header now has no body.
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (chain.best_header_id, chain.best_full_block_height),
        (mined.id, 1)
    );
    // Resubmitting the solution retries the section write, which the
    // guard refuses again.
    let resubmitted = submit_solution(&mut state, &handle, mined.nonce);
    assert!(persist_failed(&resubmitted), "{resubmitted:?}");
    flush_actions(&mut state, vec![]);
    assert!(inventories(&mut rx).is_empty());
}

#[test]
fn locally_mined_block_stored_sections_then_tip_build_accepts_newest() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    let window = state.store.read_minimal_full_block_height().unwrap();
    state
        .store
        .as_utxo()
        .unwrap()
        .write_minimal_full_block_height(3)
        .unwrap();
    publish_candidate(&state, &handle);
    let older = solve(&state, &handle, 0);
    let failed = submit_solution(&mut state, &handle, older.nonce);
    assert!(
        matches!(failed, Err(ergo_api::MiningApiError::Internal(ref reason))
        if reason.starts_with("persist:") && reason.contains("sentinel")),
        "{failed:?}"
    );
    let store = state.store.as_utxo().unwrap();
    store
        .test_force_set_minimal_full_block_height_unsafe(window)
        .unwrap();
    let solution = ergo_mining::work_message::MinerSolution {
        nonce: older.nonce,
        pk: None,
    };
    let ergo_mining::solution::SolutionOutcome::Accepted(block) =
        handle.verify_solution(&solution, store).unwrap()
    else {
        panic!("accepted")
    };
    let mined = ergo_mining::submit::prepare_mined_block(store, block).unwrap();
    ergo_mining::submit::store_mined_sections(store, &mined).unwrap();
    assert!(mined.sections_stored(store).unwrap());
    publish_candidate_after(&state, &handle, older.header.timestamp);
    let newer = solve(&state, &handle, 0);
    assert_eq!(older.nonce, newer.nonce);
    assert_ne!(older.id, newer.id);
    let result = submit_solution(&mut state, &handle, newer.nonce);
    assert!(
        matches!(&result, Err(ergo_api::MiningApiError::Internal(reason))
        if reason.starts_with("block apply failed (stored as a fork")),
        "{result:?}"
    );
    assert!(
        state
            .store
            .as_utxo()
            .unwrap()
            .get_header(&newer.id)
            .unwrap()
            .is_some(),
        "a complete older block does not take the newer solution"
    );
}

#[test]
fn locally_mined_block_section_write_failure_then_same_parent_refresh_recovers_original() {
    // A serving window above the mined height stands in for a section
    // storage fault. The original template remains offered for recovery.
    use super::super::mining_dispatch::{
        decide_mining_signal, MiningProducerState, MiningSignalIntervals, MiningTipSnapshot,
    };
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    let window = state.store.read_minimal_full_block_height().unwrap();
    state
        .store
        .as_utxo()
        .unwrap()
        .write_minimal_full_block_height(3)
        .unwrap();
    let queue = register_shared_peer(&mut state);
    publish_candidate(&state, &handle);
    let mined = solve(&state, &handle, 0);
    let mut serve = handle.subscribe_serve_changes();
    serve.borrow_and_update();
    let tip_before = MiningTipSnapshot::capture(&state);

    let failed = submit(&mut state, &handle, mined.nonce);
    assert!(
        matches!(
            &failed.result,
            Err(ergo_api::MiningApiError::Internal(reason))
                if reason.starts_with("persist:") && reason.contains("sentinel")
        ),
        "{:?}",
        failed.result
    );
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (chain.best_header_id, chain.best_full_block_id),
        (mined.id, parent),
        "the mined header is the best header, without its body"
    );
    assert!(
        !failed.rebuild,
        "a failed section write asks for no rebuild"
    );
    assert!(
        handle.has_template_for_parent(&parent),
        "the template the block came from stays offered"
    );
    assert!(
        !serve.has_changed().expect("sender alive"),
        "nothing was withdrawn"
    );
    flush_actions(&mut state, vec![]);
    assert!(drain(&queue).is_empty(), "nothing is announced");

    // A stored header without its body leaves the applied parent unchanged
    // and does not regenerate work. The retained template permits recovery.
    let now = Instant::now();
    let reason = decide_mining_signal(
        &MiningProducerState {
            last_tip: tip_before,
            last_revision: state.mempool.revision(),
            last_recovery: Some(now),
            last_mempool_signal: Some(now),
            rebuild_requested: failed.rebuild,
        },
        MiningTipSnapshot::capture(&state),
        handle.best_tip().synced,
        handle.cached_work_if_synced().is_some(),
        state.mempool.revision(),
        now,
        MiningSignalIntervals {
            recovery: Duration::from_secs(1),
            refresh_debounce: Duration::from_secs(1),
        },
    );
    assert_eq!(reason, None, "a header-only transition keeps current work");

    // Even if another refresh occurs before the storage fault clears, the
    // original template and incomplete header remain recoverable.
    publish_candidate_after(&state, &handle, mined.header.timestamp);
    let newer = solve(&state, &handle, 0);
    assert_eq!(newer.nonce, mined.nonce, "both templates accept the nonce");
    assert_ne!(
        newer.id, mined.id,
        "the same-parent refresh publishes a different header"
    );
    assert_eq!(newer.header.parent_id, mined.header.parent_id);

    // The fault clears, and the miner resubmits the same solution.
    state
        .store
        .as_utxo()
        .unwrap()
        .test_force_set_minimal_full_block_height_unsafe(window)
        .unwrap();
    let recovered = submit_probing_apply(&mut state, &handle, mined.nonce, &queue);
    assert!(
        recovered.result.is_ok(),
        "{:?}: {:?}",
        recovered.result,
        state.executor.last_block_apply_error()
    );
    assert!(!recovered.rebuild);
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (chain.best_full_block_id, chain.best_full_block_height),
        (mined.id, 2)
    );
    assert_eq!(
        recovered.before_apply,
        stored_inventory(&state, mined.id),
        "the header and every section are announced before apply"
    );
    assert!(
        recovered.after_apply.is_empty(),
        "{:?}",
        recovered.after_apply
    );
    assert_announced_ids_served(&mut state, &recovered.before_apply);
}

#[test]
fn block_failed_tx_local_evicts_and_rebuilds() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    let candidate = publish_failed_tx_candidate(&state, &handle);
    let (bad, unrelated) = seed_failed_tx_pool(&mut state, &candidate.transactions[0]);
    let queue = register_shared_peer(&mut state);
    let mined = solve(&state, &handle, 0);
    let failed = submit_probing_apply(&mut state, &handle, mined.nonce, &queue);
    assert!(apply_failed(&failed.result), "{:?}", failed.result);
    assert!(
        state
            .executor
            .last_block_apply_error()
            .unwrap()
            .reason
            .contains("transaction 1"),
        "{:?}",
        state.executor.last_block_apply_error()
    );
    assert!(
        !state.mempool.contains(&bad),
        "block-named transaction remains pooled"
    );
    assert!(state.mempool.contains(&unrelated));
    publish_candidate(&state, &handle);
    let next = solve(&state, &handle, 0);
    let solution =
        ergo_mining::work_message::MinerSolution::from_hex(&hex::encode(next.nonce), None).unwrap();
    let ergo_mining::solution::SolutionOutcome::Accepted(block) = handle
        .verify_solution(&solution, state.store.as_utxo().unwrap())
        .unwrap()
    else {
        panic!("rebuilt template rejected")
    };
    assert!(block
        .transactions
        .iter()
        .all(|tx| ergo_ser::transaction::transaction_id(tx)
            .unwrap()
            .as_bytes()
            != bad.as_bytes()));
}

#[test]
fn block_failed_tx_remote_evicts_only_named_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    let candidate = publish_failed_tx_candidate(&state, &handle);
    let (bad, unrelated) = seed_failed_tx_pool(&mut state, &candidate.transactions[0]);
    let mined = solve(&state, &handle, 0);
    process_header(&mut state, &serialize_header(&mined.header).unwrap().0);
    let expected = ExpectedSections::from_header(
        &mined.id,
        mined.header.transactions_root.as_bytes(),
        mined.header.extension_root.as_bytes(),
        mined.header.ad_proofs_root.as_bytes(),
    );
    let mut writer = VlqWriter::new();
    ergo_ser::block_transactions::write_block_transactions_with_version(
        &mut writer,
        &ergo_ser::block_transactions::BlockTransactions {
            header_id: ModifierId::from_bytes(mined.id),
            transactions: candidate.transactions,
        },
        mined.header.version,
    )
    .unwrap();
    state
        .store
        .store_block_section_typed(&expected.transactions_id, &writer.result(), 102)
        .unwrap();
    let mut writer = VlqWriter::new();
    ergo_ser::extension::write_extension(
        &mut writer,
        &ergo_ser::extension::Extension {
            header_id: ModifierId::from_bytes(mined.id),
            fields: candidate
                .extension_fields
                .into_iter()
                .map(|(key, value)| ergo_ser::extension::ExtensionField {
                    key: key.try_into().unwrap(),
                    value,
                })
                .collect(),
        },
    )
    .unwrap();
    state
        .store
        .store_block_section_typed(&expected.extension_id, &writer.result(), 108)
        .unwrap();
    state.executor.try_apply_next_blocks(
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
    flush_actions(&mut state, vec![]);
    assert!(
        state
            .executor
            .last_block_apply_error()
            .unwrap()
            .reason
            .contains("transaction 1"),
        "{:?}",
        state.executor.last_block_apply_error()
    );
    assert!(
        !state.mempool.contains(&bad),
        "block-named transaction remains pooled"
    );
    assert!(state.mempool.contains(&unrelated));
}

#[test]
fn block_failed_tx_ad_proofs_failure_keeps_pool() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    mine_and_apply(&mut state, &handle);
    let mut transaction = None;
    publish_tampered_candidate(&state, &handle, |candidate| {
        replace_ad_proofs(candidate);
        transaction = Some(candidate.transactions[0].clone());
    });
    let (bad, unrelated) = seed_failed_tx_pool(&mut state, &transaction.unwrap());
    let mined = solve(&state, &handle, 0);
    assert!(apply_failed(&submit_solution(
        &mut state,
        &handle,
        mined.nonce
    )));
    assert!(state
        .executor
        .last_block_apply_error()
        .unwrap()
        .reason
        .contains("ADProofs hash mismatch"));
    assert!(state.mempool.contains(&bad));
    assert!(state.mempool.contains(&unrelated));
    assert_eq!(state.mempool.size(), 2);
}

#[test]
fn locally_mined_block_apply_failure_already_announced_once() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, _) = genesis_state(dir.path());
    // Every header check passes; apply then rejects the state root.
    let block = solved_block([0; 32], 1, wall_clock_ms(), ADDigest::from_bytes([7; 33]));
    let handle = mining_handle(&block);
    let mut rx = register_connected_peer(&mut state, test_peer());
    let result = submit_solution(&mut state, &handle, block.nonce);
    assert!(
        apply_failed(&result),
        "apply failure is still reported to the miner: {result:?}"
    );
    assert_ne!(state.store.chain_state_meta().best_full_block_id, block.id);
    let announced = inventories(&mut rx);
    assert_eq!(
        announced,
        full_inventory(&block),
        "announced after header validation, before apply"
    );
    assert_announced_ids_served(&mut state, &announced);
    flush_actions(&mut state, vec![]);
    // The state-root mismatch is no validation verdict, so the block is
    // only session-marked and stays the best header. (A verdict
    // re-anchors the best header to the parent:
    // `locally_mined_block_failed_apply_resubmission_refused_before_known_header_check`.)
    assert_eq!(
        super::super::mining_dispatch::failed_apply_invalidity(&state, &block.id).0,
        "session"
    );
    assert_eq!(state.store.chain_state_meta().best_header_id, block.id);
    // Its template was withdrawn all the same, so the miner resubmitting
    // the same solution (say after a 504 while apply ran) is told its
    // candidate is stale before anything is stored, ahead of the
    // known-header check (which would stop it too: its sections are
    // stored).
    let resubmitted = submit_solution(&mut state, &handle, block.nonce);
    assert!(
        matches!(&resubmitted, Err(ergo_api::MiningApiError::StaleParent)),
        "{resubmitted:?}"
    );
    assert!(inventories(&mut rx).is_empty());
}

#[test]
fn locally_mined_block_durable_apply_failure_stops_pre_apply_announcement() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    let mut rx = register_connected_peer(&mut state, test_peer());
    publish_tampered_candidate(&state, &handle, replace_ad_proofs);
    let first = solve(&state, &handle, 0);
    let result = submit_solution(&mut state, &handle, first.nonce);
    assert!(apply_failed(&result), "{result:?}");
    assert!(
        state.executor.last_block_apply_error().is_some_and(
            |e| e.header_id == first.id && e.reason.starts_with("ADProofs hash mismatch")
        ),
        "{:?}",
        state.executor.last_block_apply_error()
    );
    let announced = inventories(&mut rx);
    assert_eq!(
        announced,
        stored_inventory(&state, first.id),
        "announced once, before apply"
    );
    assert_eq!(
        state
            .store
            .get_header_meta(&first.id)
            .unwrap()
            .unwrap()
            .pow_validity,
        3,
        "durably invalid"
    );
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (chain.best_header_id, chain.best_full_block_id),
        (parent, parent),
        "best header re-anchored to the parent"
    );
    // Serving the invalidated block is deliberate. Scala refuses Invalid
    // ids (ErgoHistoryReader.modifierTypeAndBytesById, v6.0.6 23aabead8
    // :80-85); this node keeps serving what it announced, so peers can
    // judge the block themselves and no request for it ends in a
    // non-delivery timeout.
    assert_announced_ids_served(&mut state, &announced);
    // The failed template was withdrawn. A builder/validator mismatch
    // that reproduces on the fresh template yields another block that
    // passes every header check as a new best header and fails apply the
    // same way.
    publish_tampered_candidate(&state, &handle, replace_ad_proofs);
    let second = solve(&state, &handle, 1);
    assert_ne!(second.id, first.id);
    let result = submit_solution(&mut state, &handle, second.nonce);
    assert!(apply_failed(&result), "{result:?}");
    assert_eq!(
        state
            .store
            .get_header_meta(&second.id)
            .unwrap()
            .unwrap()
            .pow_validity,
        3
    );
    assert_eq!(state.store.chain_state_meta().best_header_id, parent);
    flush_actions(&mut state, vec![]);
    assert!(
        inventories(&mut rx).is_empty(),
        "no pre-apply announcement on a parent whose announced child failed"
    );
}

#[test]
fn locally_mined_block_failed_apply_same_template_solution_refused() {
    // Scala's onSolvedBlockFailed drops both cached candidates once the
    // view holder rejects the solved block (CandidateGenerator.scala
    // :94-104 at v6.0.6 23aabead8), so no further solution on them makes
    // a block. Here the failed block's template is withdrawn.
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    let mut rx = register_connected_peer(&mut state, test_peer());
    publish_tampered_candidate(&state, &handle, replace_ad_proofs);
    let first = solve(&state, &handle, 0);
    let second = solve(&state, &handle, 1);
    let mut serve = handle.subscribe_serve_changes();
    serve.borrow_and_update();

    let failed = submit(&mut state, &handle, first.nonce);
    assert!(apply_failed(&failed.result), "{:?}", failed.result);
    assert_eq!(
        inventories(&mut rx),
        stored_inventory(&state, first.id),
        "the failed block was announced before apply"
    );

    // The nonce solves the withdrawn template, so the miner is told its
    // candidate is stale (400 stale_candidate), not that its PoW is
    // invalid.
    let refused = submit(&mut state, &handle, second.nonce);
    assert!(
        matches!(refused.result, Err(ergo_api::MiningApiError::StaleParent)),
        "a second solution on the failed template is refused, got {:?}",
        refused.result
    );
    assert!(
        state.store.get_header(&second.id).unwrap().is_none(),
        "the refused solution is never persisted"
    );
    assert_eq!(state.store.chain_state_meta().best_header_id, parent);
    flush_actions(&mut state, vec![]);
    assert!(inventories(&mut rx).is_empty(), "nothing more is announced");

    // The miner is pointed at fresh work: the failure asks the loop for a
    // rebuild, a longpoll parked on the withdrawn template wakes, and GET
    // /mining/candidate answers 503 until the rebuild publishes.
    assert!(failed.rebuild, "the failed apply asks for a rebuild");
    assert!(!refused.rebuild);
    assert!(
        serve.has_changed().expect("sender alive"),
        "a longpoll parked on the withdrawn template wakes"
    );
    let candidate = get_candidate(&mut state, &handle);
    assert!(
        matches!(
            &candidate,
            Err(ergo_api::MiningApiError::Unavailable(reason))
                if reason.starts_with("no candidate published for the current tip")
        ),
        "{candidate:?}"
    );
}

#[test]
fn locally_mined_block_failed_apply_resubmission_refused_before_known_header_check() {
    // The same solution resubmitted after its block became the best
    // header and failed to apply on a verdict (say after a 504 while
    // apply ran) is answered stale_candidate by the solution check, which
    // runs before the known-header check. A resubmission whose header is
    // known goes on past that check only while a section is missing, and
    // apply keeps the failed block's sections, so the known-header check
    // would stop it too; the withdrawal is what answers it stale.
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    let queue = register_shared_peer(&mut state);
    publish_tampered_candidate(&state, &handle, replace_ad_proofs);
    let mined = solve(&state, &handle, 0);

    let failed = submit_probing_apply(&mut state, &handle, mined.nonce, &queue);
    assert!(apply_failed(&failed.result), "{:?}", failed.result);
    assert!(failed.rebuild, "the failed apply asks for a rebuild");
    assert!(
        !handle.has_template_for_parent(&parent),
        "the failed block's template is withdrawn"
    );
    assert_eq!(
        failed.before_apply,
        stored_inventory(&state, mined.id),
        "the failed block was announced before apply"
    );
    assert_eq!(
        missing_from(
            state.store.as_utxo().unwrap(),
            &stored_inventory(&state, mined.id)
        ),
        Vec::<[u8; 32]>::new(),
        "the failed block's header and sections stay stored"
    );
    flush_actions(&mut state, vec![]);
    assert!(drain(&queue).is_empty());
    let chain = state.store.chain_state_meta();
    let before = (
        chain.best_header_id,
        chain.best_header_height,
        chain.best_full_block_id,
        chain.best_full_block_height,
    );
    assert_eq!(
        before,
        (parent, 1, parent, 1),
        "the verdict re-anchored the best header to the parent"
    );

    let (resubmitted, apply_started) = submit_armed(&mut state, &handle, mined.nonce, &queue);
    assert!(
        matches!(
            resubmitted.result,
            Err(ergo_api::MiningApiError::StaleParent)
        ),
        "the resubmission is refused as stale_candidate, got {:?}",
        resubmitted.result
    );
    assert!(!resubmitted.rebuild);
    assert_eq!(
        apply_started, None,
        "the refused resubmission never reaches apply"
    );
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (
            chain.best_header_id,
            chain.best_header_height,
            chain.best_full_block_id,
            chain.best_full_block_height,
        ),
        before,
        "nothing new is stored"
    );
    assert_eq!(
        super::super::mining_dispatch::failed_apply_invalidity(&state, &mined.id).0,
        "durable"
    );
    flush_actions(&mut state, vec![]);
    assert!(drain(&queue).is_empty(), "nothing more is announced");
}

#[tokio::test]
async fn locally_mined_block_failed_apply_rebuild_serves_fresh_template_that_applies() {
    use super::super::mining_dispatch::{
        decide_mining_signal, signal_mining_engine, MiningProducerState, MiningSignalIntervals,
        MiningTipSnapshot, MiningWiring,
    };
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    publish_tampered_candidate(&state, &handle, replace_ad_proofs);
    let withdrawn = handle.cached_work_if_synced().unwrap().msg;
    let first = solve(&state, &handle, 0);
    let tip_before = MiningTipSnapshot::capture(&state);
    let failed = submit(&mut state, &handle, first.nonce);
    assert!(apply_failed(&failed.result), "{:?}", failed.result);

    // The action loop's post-arm decision: the durable verdict left the
    // tip snapshot unchanged and the recovery retry has just run, so only
    // the handler's request makes the rebuild happen now.
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
    assert_eq!(reason, Some(BuildReason::SolvedBlockFailed));

    // Signal the production engine as the loop does and let it build.
    let (intent_tx, intent_rx) = tokio::sync::watch::channel(None);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let wiring = MiningWiring {
        handle: handle.clone(),
        intent_tx,
        request_tx: std::sync::mpsc::channel().0,
        refresh_debounce: Duration::from_secs(1),
        block_interval_ms: 120_000,
        offline_generation: false,
    };
    let mut serve = handle.subscribe_serve_changes();
    serve.borrow_and_update();
    let (engine, worker) = super::spawn_engine_with_worker(
        state.store.as_utxo().unwrap().reader_handle(),
        handle.clone(),
        None,
        intent_rx,
        cancel_rx,
    );
    let mut chain_seq = handle.best_tip().chain_seq;
    signal_mining_engine(
        &state,
        &wiring,
        &mut chain_seq,
        &parent,
        BuildReason::SolvedBlockFailed,
    );
    // Nothing is offered on the tip until the rebuild publishes, so the
    // first template seen is the rebuild's first publish. The pool is
    // empty and rent claims are off, so the engine publishes only the
    // minimal template (`full_refresh_adds_nothing`); with pooled
    // transactions an enriched same-parent refresh (clean_jobs false)
    // would follow it.
    let rebuilt = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some((_, identity)) = handle.cached_template_if_synced() {
                break identity;
            }
            serve.changed().await.expect("handle alive");
        }
    })
    .await
    .expect("the engine publishes a fresh template on the same tip");
    assert!(rebuilt.clean_jobs, "the rebuild is a clean job");
    assert_eq!(rebuilt.reason, BuildReason::SolvedBlockFailed);
    assert_ne!(rebuilt.template_id, withdrawn);

    let work = get_candidate(&mut state, &handle).expect("fresh work is served");
    assert_ne!(work.msg, hex::encode(withdrawn));
    let mined = solve(&state, &handle, 0);
    assert_eq!(mined.header.parent_id.as_bytes(), &parent);
    let applied = submit(&mut state, &handle, mined.nonce);
    assert!(
        applied.result.is_ok(),
        "{:?}: {:?}",
        applied.result,
        state.executor.last_block_apply_error()
    );
    assert!(!applied.rebuild);
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (chain.best_full_block_id, chain.best_full_block_height),
        (mined.id, 2)
    );

    cancel_tx.send(true).unwrap();
    drop(wiring);
    tokio::time::timeout(Duration::from_secs(5), engine)
        .await
        .expect("engine exits after cancel")
        .expect("engine does not panic");
    worker.join().expect("worker does not panic");
}

#[test]
fn locally_mined_block_session_marked_failure_rebuilt_sibling_applies() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    publish_tampered_candidate(&state, &handle, replace_state_root);
    let failed_block = solve(&state, &handle, 0);
    let failed = submit(&mut state, &handle, failed_block.nonce);
    assert!(apply_failed(&failed.result), "{:?}", failed.result);
    assert!(
        failed.rebuild,
        "the failure withdraws the parent's templates and asks for a rebuild"
    );
    assert_eq!(
        super::super::mining_dispatch::failed_apply_invalidity(&state, &failed_block.id).0,
        "session",
        "{:?}",
        state.executor.last_block_apply_error()
    );
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (chain.best_header_id, chain.best_full_block_id),
        (failed_block.id, parent),
        "the session-marked block stays the best header"
    );

    // The rebuild on the parent, as the engine publishes it.
    publish_candidate(&state, &handle);
    let sibling = solve(&state, &handle, 0);
    assert_eq!(sibling.header.parent_id.as_bytes(), &parent);
    let queue = register_shared_peer(&mut state);
    let submitted = submit_probing_apply(&mut state, &handle, sibling.nonce, &queue);
    assert!(submitted.result.is_ok(), "{:?}", submitted.result);
    assert!(submitted.before_apply.is_empty());
    assert_eq!(submitted.after_apply, stored_inventory(&state, sibling.id));
    flush_actions(&mut state, vec![]);
    assert!(drain(&queue).is_empty());
    assert_eq!(state.store.chain_state_meta().best_header_id, sibling.id);
    assert_eq!(
        state.store.chain_state_meta().best_full_block_id,
        sibling.id
    );
    let path = state.store.database_path().to_path_buf();
    drop(state);
    let spec = ergo_chain_spec::ChainSpec::devnet();
    let store = StateStore::open_with_cache_launch_voting(
        &path,
        StateStore::DEFAULT_CACHE_BYTES,
        ergo_validation::scala_launch_for_network(spec.network),
        spec.voting,
    )
    .unwrap();
    let mut state = make_state_with_store(store);
    state.executor = SyncExecutor::new(ProtocolParams::mainnet_default(), spec.difficulty);
    state.executor.load_header_index(&state.store).unwrap();
    state.executor.try_apply_next_blocks(
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
    assert_eq!(state.store.chain_state_meta().best_header_id, sibling.id);
    assert_eq!(
        state.store.chain_state_meta().best_full_block_id,
        sibling.id
    );
    mine_and_apply(&mut state, &handle);
    assert_eq!(state.store.chain_state_meta().best_full_block_height, 3);
}

#[test]
fn utxo_rebuild_two_ambiguous_failures_preserves_first_branch_blockage() {
    let dir = tempfile::tempdir().unwrap();
    let (mut state, handle) = devnet_node(dir.path());
    let parent = mine_and_apply(&mut state, &handle);
    let mut failures = Vec::new();
    for root in [7, 8] {
        publish_tampered_candidate(&state, &handle, |candidate| {
            candidate.header.state_root = ADDigest::from_bytes([root; 33]);
        });
        let bad = prepared_solution(&state, &handle);
        process_header(&mut state, &bad.header_bytes);
        assert_eq!(state.store.chain_state_meta().best_header_id, bad.header_id);
        ergo_mining::submit::store_mined_sections(state.store.as_utxo().unwrap(), &bad).unwrap();
        drain_prepared(&mut state);
        assert!(state.store.is_invalid(&bad.header_id).unwrap());
        assert!(!state.store.is_durably_invalid(&bad.header_id).unwrap());
        assert_eq!(state.store.chain_state_meta().best_full_block_id, parent);
        failures.push(bad);
    }
    assert!(
        state.store.is_invalid(&failures[0].header_id).unwrap(),
        "the second rebuild must retain the first session mark"
    );
    // A heavier extension selects the first failed branch; an equally
    // scored clean branch must still escape its first unapplied ancestor.
    let first = read_header(&mut VlqReader::new(&failures[0].header_bytes)).unwrap();
    let blocked_child = solved_child(&first, failures[0].header_id);
    process_header(&mut state, &blocked_child);
    let blocked_id = *ergo_primitives::digest::blake2b256(&blocked_child).as_bytes();
    assert_eq!(state.store.chain_state_meta().best_header_id, blocked_id);
    publish_candidate(&state, &handle);
    let clean = prepared_solution(&state, &handle);
    process_header(&mut state, &clean.header_bytes);
    let clean_header = read_header(&mut VlqReader::new(&clean.header_bytes)).unwrap();
    let clean_child = solved_child(&clean_header, clean.header_id);
    process_header(&mut state, &clean_child);
    assert_eq!(
        state.store.chain_state_meta().best_header_id,
        *ergo_primitives::digest::blake2b256(&clean_child).as_bytes()
    );
    let path = state.store.database_path().to_path_buf();
    drop(state);
    let reopened = StateStore::open(&path).unwrap();
    assert!(reopened.chain_state().session_invalids.is_empty());
    for bad in failures {
        // Ambiguous failures must never become durable verdicts.
        assert!(!reopened.is_durably_invalid(&bad.header_id).unwrap());
    }
}

#[test]
fn remote_block_session_failure_stored_sibling_promoted() {
    session_sibling(false, false, false);
}

#[test]
fn remote_block_session_failure_later_sibling_promoted() {
    session_sibling(true, false, false);
}

#[test]
fn digest_session_promotion_missing_sections_requests_and_applies() {
    session_sibling(false, true, false);
}

#[test]
fn remote_session_promotion_assemble_failure_requests_and_applies() {
    session_sibling(false, false, true);
    session_sibling(false, true, true);
}

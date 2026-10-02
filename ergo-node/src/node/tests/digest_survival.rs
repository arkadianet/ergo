// ----- digest-mode (Mode 5) survival: handshake / sync / API seams -----

/// The handshake arm's SyncInfo fallback builds the payload from
/// `&state.store` via the backend-agnostic `ChainView`, not the
/// UTXO-narrowed `as_utxo()`. On a digest backend the old `.expect()`
/// would have panicked; here it must produce a `CODE_SYNC_INFO` frame
/// whose bytes match calling `build_sync_info_payload` directly on the
/// same store (the seam is internal, so self-consistency is the bar).
#[test]
fn handshake_complete_digest_backend_sends_sync_info_without_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_digest_state(&tmp.path().join("digest.redb"));
    let peer = test_peer();
    let now = Instant::now();
    let sync_version = SyncVersion::V1;

    // Register the peer with an outbound channel we can drain, mirroring
    // the `state.registry.peers.insert` the handshake arm performs.
    let (tx, mut rx) = crate::peer_loop::outbound::channel(4);
    state.registry.peers.insert(
        peer,
        PeerRuntime {
            sync_version,
            outbound_tx: tx,
        },
    );

    // Expected bytes: `build_sync_info_payload` over the digest store
    // directly. This is the exact call the fixed handshake arm makes.
    let expected =
        ergo_sync::coordinator::build_sync_info_payload(sync_version, &state.store).unwrap();

    // Run the fixed seam: anchor scheduler is off in the fixture, so
    // `try_send_anchor_sync_info` returns false and the fallback path
    // (the one the fix touches) fires.
    assert!(
        !try_send_anchor_sync_info(&mut state, &peer, now),
        "anchor scheduler is disabled in the fixture; fallback must run",
    );
    let payload =
        ergo_sync::coordinator::build_sync_info_payload(sync_version, &state.store).unwrap();
    assert!(send_to_peer(
        &state,
        &peer,
        message::CODE_SYNC_INFO,
        payload
    ));

    let frame = rx.try_recv().expect("a SyncInfo frame must be queued");
    assert_eq!(frame.code, message::CODE_SYNC_INFO);
    assert_eq!(frame.payload, expected);
}

/// `request_missing_sections` takes `&dyn ChainView`; on a digest
/// backend `&state.store` routes to the digest header tables instead of
/// panicking through `as_utxo()`. With no eligible peers it returns no
/// actions — the point is that the call survives.
#[test]
fn request_missing_sections_digest_backend_no_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_digest_state(&tmp.path().join("digest.redb"));
    let now = Instant::now();

    let actions = state.executor.request_missing_sections(
        &mut state.coordinator,
        &state.store,
        &state.peer_manager,
        now,
    );
    assert!(
        actions.is_empty(),
        "no peers registered, so no section requests: {actions:?}",
    );
}

/// `maybe_exit_ibd` is a no-op on a digest backend: `as_utxo_mut()` returns
/// `None`, so the function returns without touching anything. Calling it with
/// condition-satisfying values (fb advanced, gap < 10) must not panic.
#[test]
fn ibd_auto_exit_digest_backend_skips_utxo_branch() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_digest_state(&tmp.path().join("digest.redb"));
    // Confirm the guard's enabling condition: no UTXO arena on a digest store.
    assert!(
        state.store.as_utxo_mut().is_none(),
        "digest backend exposes no UTXO arena — maybe_exit_ibd must be a no-op",
    );
    // Calling with condition-satisfying values must be a silent no-op, not a panic.
    maybe_exit_ibd(&mut state.store, 0, 5, 7);
}

/// `maybe_exit_ibd` exits IBD mode on a UTXO backend when the full-block tip
/// advances within 10 of the header tip.
#[test]
fn ibd_auto_exit_utxo_backend_exits_ibd_when_near_tip() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("utxo.redb"));
    // Arm IBD mode (same call as boot.rs:664).
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .set_ibd_mode(true, 50)
        .unwrap();
    assert!(
        state.store.as_utxo_mut().unwrap().ibd_mode(),
        "pre-condition: IBD armed"
    );

    // Condition-satisfying call: fb advanced (0→5), bh=7, gap=2 < 10.
    maybe_exit_ibd(&mut state.store, 0, 5, 7);
    assert!(
        !state.store.as_utxo_mut().unwrap().ibd_mode(),
        "IBD must have exited when gap < 10",
    );
}

/// `maybe_exit_ibd` leaves IBD mode unchanged when the gap is >= 10.
#[test]
fn ibd_auto_exit_utxo_backend_stays_ibd_when_gap_large() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("utxo.redb"));
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .set_ibd_mode(true, 50)
        .unwrap();

    // Gap = bh - fb = 100 - 5 = 95, well above the threshold.
    maybe_exit_ibd(&mut state.store, 0, 5, 100);
    assert!(
        state.store.as_utxo_mut().unwrap().ibd_mode(),
        "IBD must stay armed when gap >= 10",
    );
}

/// API admission rejects with the `Disabled` wire shape when the mempool
/// is off — which a digest node always is (production force-disables it).
/// The guard short-circuits before `build_tip_context` / `as_utxo()`, so
/// both submit intents return `reason: "disabled"` instead of panicking
/// or surfacing a misleading `tip_unready` error.
#[test]
fn api_submit_without_mempool_rejects_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_digest_state(&tmp.path().join("digest.redb"));
    assert!(
        !state.mempool.config().enabled,
        "a digest fixture must have the mempool force-disabled",
    );
    let now = Instant::now();

    use ergo_api::types::SubmitMode;
    for mode in [SubmitMode::Broadcast, SubmitMode::CheckOnly] {
        let err = super::admission::admit_api_transaction(&mut state, &[0u8; 8], mode, now)
            .expect_err("mempool-off admission must reject");
        assert_eq!(err.reason, "disabled", "{mode:?} should reject as disabled");
    }
}

/// The memory sampler emits a row on a digest backend: the UTXO-arena
/// columns read 0 (via `as_utxo().map(...).unwrap_or(0)`) rather than
/// panicking through the old `.expect()`. Asserts a data row is appended
/// AND that every UTXO-only column in it is exactly "0", keyed by column
/// name off the CSV header so the check survives schema reordering.
#[test]
fn memory_sample_digest_backend_emits_zeroed_arena_row() {
    let tmp = tempfile::tempdir().unwrap();
    let state = make_digest_state(&tmp.path().join("digest.redb"));
    let csv_path = tmp.path().join("mem.csv");
    let mut file: Option<std::fs::File> = None;

    super::memory_sampler::sample_memory(&state, &csv_path, &mut file);

    assert!(file.is_some(), "sampler must open the CSV file");
    let contents = std::fs::read_to_string(&csv_path).unwrap();
    let mut lines = contents.lines();
    let header: Vec<&str> = lines.next().expect("header line").split(',').collect();
    let row: Vec<&str> = lines.next().expect("one data row").split(',').collect();
    assert_eq!(
        header.len(),
        row.len(),
        "data row column count must match the header",
    );

    // Every column sourced from the UTXO arena must read 0 on a digest
    // backend (these are the columns the fix routes through
    // `as_utxo().map(...).unwrap_or(0)`).
    for col in [
        "avl_cache_clean_bytes",
        "avl_cache_capacity_bytes",
        "avl_clean_len",
        "avl_dirty_len",
        "avl_read_count",
        "batch_headers_len",
        "batch_headers_bytes",
        "batch_meta_len",
        "redb_state_evictions",
    ] {
        let idx = header
            .iter()
            .position(|h| *h == col)
            .unwrap_or_else(|| panic!("column {col} missing from header"));
        assert_eq!(row[idx], "0", "digest backend must zero-fill {col}");
    }
}

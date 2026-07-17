use super::*;
use ergo_p2p::peer::Penalty;
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
        ForkPoint::Found(1, h1)
    );
}

// ----- error paths -----

/// OBS-1 — a block-apply rejection is captured for observability: the latest
/// rejection is retained and the monotonic counter increments. The two genuine
/// invalid-block sinks call `record_block_apply_error`; this pins the recording
/// mechanism + accessors the snapshot/health/metrics surfaces read.
#[test]
fn record_block_apply_error_retains_latest_and_counts() {
    let mut ex = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    assert!(ex.last_block_apply_error().is_none());
    assert_eq!(ex.block_apply_error_count(), 0);

    ex.record_block_apply_error(id(0xAB), 1234, "bad merkle root".to_string());
    let e = ex.last_block_apply_error().expect("rejection recorded");
    assert_eq!(e.header_id, id(0xAB));
    assert_eq!(e.height, 1234);
    assert_eq!(e.reason, "bad merkle root");
    assert_eq!(ex.block_apply_error_count(), 1);

    // A DISTINCT rejected header replaces `last`; the counter is monotonic.
    ex.record_block_apply_error(id(0xCD), 1235, "tx invalid".to_string());
    let e = ex.last_block_apply_error().unwrap();
    assert_eq!(e.height, 1235);
    assert_eq!(e.reason, "tx invalid");
    assert_eq!(ex.block_apply_error_count(), 2);
    let at_after_cd = e.at;

    // Re-rejecting the SAME header (the per-tick retry of an invalid best-chain
    // block) is NOT a new event: the counter and timestamp are unchanged, so
    // the counter counts distinct rejections and `age_ms` ages honestly.
    ex.record_block_apply_error(id(0xCD), 1235, "tx invalid".to_string());
    assert_eq!(
        ex.block_apply_error_count(),
        2,
        "retry must not inflate count"
    );
    assert_eq!(
        ex.last_block_apply_error().unwrap().at,
        at_after_cd,
        "retry must not reset the timestamp"
    );
}

/// RD-02 — a best-header branch that forks more than `ROLLBACK_WINDOW` blocks
/// below the full-block tip must NOT yield a fork point. The state layer can
/// only roll back the last `ROLLBACK_WINDOW` blocks (its undo log is pruned
/// past that), so proposing the genesis fork would hand the executor a
/// `target_height` whose `rollback_to` is doomed (`StateError::ReorgTooDeep`)
/// and which it would re-attempt — and re-fail — every tick. The capped walk
/// declines with `ForkPoint::TooDeep` instead of walking to genesis and
/// returning `Found(0, [0; 32])`.
#[test]
fn full_chain_fork_point_caps_at_rollback_window() {
    use ergo_state::store::ROLLBACK_WINDOW;

    let mut store = open_initialized_store();
    let depth = ROLLBACK_WINDOW + 2; // 202: just past the window

    // Branch A — the applied full-block chain, tip at `depth`.
    let mut parent = [0u8; 32];
    for h in 1..=depth {
        parent = apply_empty_block(&mut store, h, parent);
    }
    assert_eq!(store.chain_state().best_full_block_height, depth);

    // Branch B — a header-only chain forking at genesis, so it diverges from
    // branch A at every height `1..=depth` (common ancestor = genesis, fork
    // depth == `depth` > ROLLBACK_WINDOW). Marking its tip best forces the
    // best-header chain index onto branch B, so `get_header_id_at_height`
    // resolves to branch B for the whole descent.
    let b_id = |h: u32| {
        let mut idb = [0xB0u8; 32];
        idb[0] = (h >> 8) as u8;
        idb[1] = h as u8;
        idb
    };
    let mut b_parent = [0u8; 32];
    for h in 1..=depth {
        let this = b_id(h);
        // `new_best = Some(..)` forces the best-header tip unconditionally
        // (no score comparison), so a trivial score suffices for the tip.
        let new_best = (h == depth).then(|| (depth, vec![0xFFu8; 8]));
        store
            .store_validated_header(
                &this,
                &[0xB0; 8],
                &ergo_state::chain::HeaderMeta {
                    parent_id: b_parent,
                    height: h,
                    cumulative_score: vec![1],
                    pow_validity: 1,
                    timestamp: h as u64,
                },
                new_best,
            )
            .unwrap();
        b_parent = this;
    }
    assert_eq!(store.chain_state().best_header_id, b_id(depth));
    assert_eq!(store.chain_state().best_full_block_height, depth);

    let executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let store = ergo_state::StateBackendKind::Utxo(store);
    assert_eq!(
        executor.full_chain_fork_point(&store).unwrap(),
        ForkPoint::TooDeep {
            // Guard fires when `original_height - height > window`, i.e. the
            // first height MORE than a full window below the 202-tip: 1.
            scanned_to: 1,
            max_depth: ROLLBACK_WINDOW,
        }
    );
}

/// The terminal decline is not just an absent fork point — it must set the
/// operator-visible wedge (with the stuck tip's identity) and clear it the
/// moment the chains agree again. This is the surface /health, /status and
/// the event feed read; without it the stall is invisible except as a
/// per-second parent-mismatch warn (the exact failure mode of the testnet
/// 431,366 bystander wedge at height 434,471).
#[test]
fn too_deep_fork_sets_wedge_and_reagreement_clears_it() {
    use ergo_state::store::ROLLBACK_WINDOW;

    let mut store = open_initialized_store();
    let depth = ROLLBACK_WINDOW + 2;

    // Branch A applied as full blocks; branch B header-only, forking at
    // genesis, promoted to best-header — same topology as the caps test.
    let mut parent = [0u8; 32];
    for h in 1..depth {
        parent = apply_empty_block(&mut store, h, parent);
    }
    let tip_parent = parent;
    let full_tip = apply_empty_block(&mut store, depth, tip_parent);
    let b_id = |h: u32| {
        let mut idb = [0xB0u8; 32];
        idb[0] = (h >> 8) as u8;
        idb[1] = h as u8;
        idb
    };
    let mut b_parent = [0u8; 32];
    for h in 1..=depth {
        let this = b_id(h);
        let new_best = (h == depth).then(|| (depth, vec![0xFFu8; 8]));
        store
            .store_validated_header(
                &this,
                &[0xB0; 8],
                &ergo_state::chain::HeaderMeta {
                    parent_id: b_parent,
                    height: h,
                    cumulative_score: vec![1],
                    pow_validity: 1,
                    timestamp: h as u64,
                },
                new_best,
            )
            .unwrap();
        b_parent = this;
    }

    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(1);
    let mut store = ergo_state::StateBackendKind::Utxo(store);

    assert!(executor.deep_fork_wedge().is_none());
    assert_eq!(
        executor
            .rollback_full_chain_to_best_header(&mut store, &mut coordinator, None)
            .unwrap(),
        ReorgOutcome::TooDeep
    );
    let w = executor.deep_fork_wedge().expect("wedge recorded");
    assert_eq!(w.best_full_id, full_tip);
    assert_eq!(w.best_full_height, depth);
    assert_eq!(w.scanned_to_height, 1);
    assert_eq!(w.max_rollback_depth, ROLLBACK_WINDOW);
    let since = w.since;

    // Re-detection on the SAME stuck tip refreshes nothing: `since` keeps
    // aging honestly (mirrors the block-apply-error dedup contract).
    assert_eq!(
        executor
            .rollback_full_chain_to_best_header(&mut store, &mut coordinator, None)
            .unwrap(),
        ReorgOutcome::TooDeep
    );
    assert_eq!(executor.deep_fork_wedge().unwrap().since, since);

    // The best-header chain returns to the applied chain (branch A tip
    // promoted back): the wedge clears on the next reorg check.
    if let ergo_state::StateBackendKind::Utxo(ref mut s) = store {
        s.store_validated_header(
            &full_tip,
            &[0xA0; 8],
            // Meta must round-trip the REAL branch-A linkage: the best-chain
            // index rewrite walks parent pointers from the promoted tip, so a
            // synthetic parent here would strand the walk on a missing row.
            &ergo_state::chain::HeaderMeta {
                parent_id: tip_parent,
                height: depth,
                cumulative_score: vec![0xFF, 0xFF],
                pow_validity: 1,
                timestamp: 1_700_000_000 + depth as u64,
            },
            Some((depth, vec![0xFF, 0xFF])),
        )
        .unwrap();
    }
    assert_eq!(
        executor
            .rollback_full_chain_to_best_header(&mut store, &mut coordinator, None)
            .unwrap(),
        ReorgOutcome::NotNeeded
    );
    assert!(
        executor.deep_fork_wedge().is_none(),
        "wedge must clear when the best-header chain is reachable again"
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
    assert_eq!(
        executor
            .rollback_full_chain_to_best_header(&mut store, &mut coordinator, None)
            .unwrap(),
        ReorgOutcome::Performed
    );

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

#[test]
fn recover_coordinator_marks_done_in_headers_only_mode() {
    // Permanent headers-only (Mode 6): recovery registers nothing, but must be
    // marked done so sync_tick (headers_chain_synced && !recovery_done) stops
    // re-calling it every tick and the API stops reporting recovery_done=false.
    let store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new_with_window_and_mode(0, 100, true);
    // Latch open, as it would be after the persisted-tip freshness detection.
    coordinator.sync_state_mut().mark_headers_chain_synced();

    assert!(!executor.recovery_done());
    let recovered = executor
        .recover_coordinator(&store, &mut coordinator)
        .unwrap();
    assert_eq!(recovered, 0, "headers-only must register no pending blocks");
    assert!(
        executor.recovery_done(),
        "headers-only recovery must be marked done so sync_tick stops re-calling it"
    );
}

#[test]
fn recover_coordinator_leaves_done_unset_during_bootstrap() {
    // Mid-bootstrap is transient: recovery_done must stay unset so a normal
    // recovery runs once the install path clears bootstrap (and resets it).
    let store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(0);
    coordinator.set_bootstrap_in_progress(true);
    coordinator.sync_state_mut().mark_headers_chain_synced();

    let recovered = executor
        .recover_coordinator(&store, &mut coordinator)
        .unwrap();
    assert_eq!(
        recovered, 0,
        "mid-bootstrap must register no pending blocks"
    );
    assert!(
        !executor.recovery_done(),
        "mid-bootstrap must leave recovery_done unset so it re-runs after the install resets it"
    );
}

// ----- branch-invalidation classifier -----
//
// `is_validation_verdict` gates the durable branch-invalidation path
// (Scala `reportModifierIsInvalid`). Only definitive consensus-rule
// verdicts may persist invalidity; transient / IO / consistency failures
// must stay session-scoped so a bug of ours or a stale local root can
// never permanently orphan a valid chain.

#[test]
fn is_validation_verdict_true_for_consensus_rule_failures() {
    let v = BlockProcessError::Validation(
        ergo_validation::block::BlockValidationError::TransactionsRootMismatch {
            expected: id(0x01),
            computed: id(0x02),
        },
    );
    assert!(is_validation_verdict(&v), "block validation is a verdict");
}

#[test]
fn is_validation_verdict_true_for_header_meta_and_epoch_extension() {
    // The other two documented verdict branches: a header-rule failure and an
    // extension/epoch-rule failure are both definitive consensus rejects.
    let header_meta = BlockProcessError::HeaderMeta(
        ergo_validation::header::HeaderValidationError::TimestampNotMonotonic {
            parent_ts: 100,
            child_ts: 99,
        },
    );
    assert!(
        is_validation_verdict(&header_meta),
        "header-rule failure is a verdict"
    );

    let epoch_ext = BlockProcessError::EpochExtension(
        ergo_validation::voting::extension_validation::ExtensionValidationError::BlockVersion {
            computed: 3,
            header: 2,
        },
    );
    assert!(
        is_validation_verdict(&epoch_ext),
        "extension/epoch-rule failure is a verdict"
    );
}

#[test]
fn is_validation_verdict_false_for_io_and_consistency_failures() {
    // A stored section that won't parse could be disk corruption, not a bad
    // block; a state-apply error is IO/DB; missing headers are data gaps;
    // DigestApply is session-scoped by contract (a stale local root and a bad
    // block are observationally identical in digest mode).
    let cases = [
        BlockProcessError::Deserialize("truncated section".to_string()),
        BlockProcessError::HeaderNotFound { id: id(0xAA) },
        BlockProcessError::ParentNotFound { id: id(0xBB) },
        BlockProcessError::State(ergo_state::store::StateError::InvalidPrecondition {
            what: "io-ish",
        }),
        BlockProcessError::DigestApply(ergo_state::DigestApplyError::AdProofsRootMismatch {
            computed: "aa".to_string(),
            expected: "bb".to_string(),
        }),
    ];
    for e in cases {
        assert!(
            !is_validation_verdict(&e),
            "non-verdict failure must NOT invalidate: {e}"
        );
    }
}

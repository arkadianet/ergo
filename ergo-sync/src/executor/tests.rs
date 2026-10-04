use super::*;
use ergo_p2p::peer::Penalty;
use ergo_p2p::peer_manager::PeerManager;
use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::{GroupElement, GROUP_ELEMENT_LENGTH};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{write_header, Header};
use ergo_state::store::StateStore;
use ergo_state::test_helpers::SharedBuf;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use std::io;
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

#[test]
fn persist_failed_propagation_does_not_duplicate_worker_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).unwrap();
    store.initialize_genesis(&[]).unwrap();
    let store = ergo_state::StateBackendKind::Utxo(store);
    let writer = SharedBuf::new();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_target(false)
        .with_writer(writer.clone())
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        ergo_state::storage_observability::report_storage_failure(
            &ergo_state::storage_observability::StorageFailureContext {
                subsystem: "state",
                component: "persist_worker",
                database_path: Some(&path),
                operation: "background_persist_commit",
                best_full_block_height: Some(100),
                best_header_height: Some(120),
                attempted_height: Some(101),
            },
            &io::Error::from_raw_os_error(13),
        );

        super::report_sync_storage_failure(
            &store,
            "section_persistence",
            "sync_read_section_height",
            &ergo_state::store::StateError::PersistFailed {
                height: 101,
                error: "already reported worker failure".to_string(),
            },
        );

        super::report_sync_storage_failure(
            &store,
            "section_persistence",
            "sync_store_block_section",
            &ergo_state::store::StateError::StorageError(Box::new(redb::StorageError::Io(
                io::Error::from_raw_os_error(28),
            ))),
        );
    });

    let output = String::from_utf8(writer.bytes()).unwrap();
    let events: Vec<serde_json::Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0]["fields"]["operation"],
        "background_persist_commit"
    );
    assert_eq!(events[1]["fields"]["operation"], "sync_store_block_section");
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
pub(super) fn apply_empty_block(
    store: &mut StateStore,
    height: u32,
    parent_id: [u8; 32],
) -> [u8; 32] {
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
fn header_only_reorg_keeps_applied_chain_and_registers_fork_downloads() {
    let mut store = open_initialized_store();
    let common = apply_empty_block(&mut store, 1, [0; 32]);
    let old2 = apply_empty_block(&mut store, 2, common);
    let old3 = apply_empty_block(&mut store, 3, old2);
    let mut raw = store.get_header(&old2).unwrap().unwrap();
    let mut header =
        ergo_ser::header::read_header(&mut ergo_primitives::reader::VlqReader::new(&raw)).unwrap();
    header.solution = AutolykosSolution::V2 {
        pk: GroupElement::from_bytes([0; 33]),
        nonce: [1; 8],
    };
    let mut writer = VlqWriter::new();
    write_header(&mut writer, &header).unwrap();
    raw = writer.result();
    let branch = *blake2b256(&raw).as_bytes();
    store
        .store_validated_header(
            &branch,
            &raw,
            &ergo_state::chain::HeaderMeta {
                parent_id: common,
                height: 2,
                cumulative_score: vec![9],
                pow_validity: 1,
                timestamp: header.timestamp,
            },
            Some((2, vec![9])),
        )
        .unwrap();
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(3);
    let mut store = ergo_state::StateBackendKind::Utxo(store);
    assert_eq!(
        executor.full_chain_fork_point(&store).unwrap(),
        ForkPoint::Found(1, common)
    );
    executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
    assert_eq!(store.chain_state_meta().best_full_block_id, old3);
    assert!(!store.is_invalid(&branch).unwrap());
    assert!(coordinator
        .sync_state()
        .blocks_to_download()
        .iter()
        .any(|block| block.header_id == branch));
    assert!(coordinator
        .assembly_mut()
        .expected_section_ids(&branch)
        .is_some());
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

    let evicted = executor.cap_orphan_buffer();

    // The 3-over-cap highest-height entries are returned so the caller can
    // forget_received_modifier them; the dropped entry's id is among them.
    assert_eq!(evicted.len(), 3, "3 entries over the cap were evicted");
    let mut dropped_id = [0u8; 32];
    dropped_id[28..32].copy_from_slice(&(ORPHAN_HEADER_LIMIT as u32).to_be_bytes());
    assert!(
        evicted.contains(&dropped_id),
        "the dropped high-height header id is reported evicted",
    );

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
fn batch_validation_rolls_back_hash_matching_malformed_headers() {
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
    let p = peer(9030);
    let now = Instant::now();
    let first_bytes = vec![1];
    let second_bytes = vec![2];
    let first_id = *blake2b256(&first_bytes).as_bytes();
    let second_id = *blake2b256(&second_bytes).as_bytes();
    assert_ne!(first_id, second_id);
    coordinator.delivery_mut_for_test().request(
        p,
        ergo_p2p::types::ModifierTypeId::Header.as_byte(),
        &[first_id, second_id],
        now,
    );
    coordinator.delivery_mut_for_test().mark_received(&first_id);
    coordinator
        .delivery_mut_for_test()
        .mark_received(&second_id);

    let actions = executor.execute_all(
        vec![
            Action::ValidateHeader {
                peer: p,
                modifier_id: first_id,
                header_bytes: first_bytes,
            },
            Action::ValidateHeader {
                peer: p,
                modifier_id: second_id,
                header_bytes: second_bytes,
            },
        ],
        &mut store,
        &mut coordinator,
        now,
        None,
    );

    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, Action::Penalize { .. }))
            .count(),
        2
    );
    assert_eq!(
        coordinator.delivery().status(&first_id),
        ergo_p2p::delivery::ModifierStatus::Unknown
    );
    assert_eq!(
        coordinator.delivery().status(&second_id),
        ergo_p2p::delivery::ModifierStatus::Unknown
    );
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

/// Empty chain view for delivery/reassign tests that only need Inv admission.
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
    fn best_header_score(&self) -> Vec<u8> {
        vec![0]
    }
    fn header_score_for(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
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

#[test]
fn recover_coordinator_anchors_the_walk_on_the_prune_sentinel_floor() {
    // Mode 3 tick order: the activation seed lands in `SyncState` before
    // recovery runs. A walk anchored at `best_full_block_height` (0 on a
    // node that has applied nothing) would register the bottom of the
    // chain — a range `blocks_to_download` discards wholesale, because it
    // anchors at `max(best_full_block_height, prune_sentinel - 1)` and
    // drops everything below the sentinel. Recovery must use the same
    // floor, or no section request ever goes out.
    use ergo_ser::header::serialize_header;
    use ergo_state::chain::HeaderMeta;

    const TIP: u32 = 40;
    const SENTINEL: u32 = 25;
    const WINDOW: usize = 10;

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    store.initialize_genesis(&[]).unwrap();
    // Linear chain 1..=TIP with a fresh tip timestamp, so the walk has
    // real parent links to follow and the headers-synced latch is
    // legitimately open. No full blocks — the state under test.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let base = now_ms - u64::from(TIP) * 120_000;
    let mut parent = store.chain_state_meta().best_header_id;
    for height in 1..=TIP {
        let ts = base + u64::from(height) * 120_000;
        // Height-derived roots keep each height's section ids distinct.
        let root = |seed: u8| {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&height.to_be_bytes());
            b[4] = seed;
            Digest32::from_bytes(b)
        };
        let header = Header {
            version: 2,
            parent_id: ModifierId::from_bytes(parent),
            ad_proofs_root: root(0xAD),
            transactions_root: root(0x77),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: ts,
            extension_root: root(0xEE),
            n_bits: 0x1d00ffff,
            height,
            votes: [0, 0, 0],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; GROUP_ELEMENT_LENGTH]),
                nonce: [0xAA; 8],
            },
        };
        let (bytes, hid) = serialize_header(&header).unwrap();
        let hid = *hid.as_bytes();
        let meta = HeaderMeta {
            parent_id: parent,
            height,
            cumulative_score: u64::from(height).to_be_bytes().to_vec(),
            pow_validity: 1,
            timestamp: ts,
        };
        store
            .store_validated_header(
                &hid,
                &bytes,
                &meta,
                Some((height, meta.cumulative_score.clone())),
            )
            .unwrap();
        parent = hid;
    }
    let store = ergo_state::StateBackendKind::Utxo(store);

    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    executor.load_header_index(&store).unwrap();
    let mut coordinator = SyncCoordinator::new_with_window(0, WINDOW);
    coordinator.sync_state_mut().set_prune_sentinel(SENTINEL);

    let recovered = executor
        .recover_coordinator(&store, &mut coordinator)
        .unwrap();
    assert_eq!(
        recovered, WINDOW,
        "the walk must fill one download window above the sentinel floor",
    );
    let queued: Vec<u32> = coordinator
        .sync_state()
        .blocks_to_download()
        .iter()
        .map(|b| b.height)
        .collect();
    assert_eq!(
        queued,
        (SENTINEL..SENTINEL + WINDOW as u32).collect::<Vec<_>>(),
        "recovered range must be exactly the window the download side \
         will request; an empty vec here is the Mode 3 sync stall",
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
fn is_validation_verdict_true_for_epoch_extension() {
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

    // Regenerated-proof-hash contradiction is Scala's "Regenerated proofHash
    // is not equal to the declared one" reject — definitive block invalidity,
    // so a mismatching block must take the durable invalidation path instead
    // of being retried forever.
    let ad_mismatch = BlockProcessError::AdProofsHashMismatch {
        header_id: id(0xCC),
        declared_root: id(0x01),
        computed_root: id(0x02),
    };
    assert!(
        is_validation_verdict(&ad_mismatch),
        "ADProofs hash mismatch is a verdict"
    );
}

#[test]
fn is_validation_verdict_false_for_io_and_consistency_failures() {
    // A stored section that won't parse could be disk corruption, not a bad
    // block; a state-apply error is IO/DB; missing headers are data gaps;
    // DigestApply is session-scoped by contract (a stale local root and a bad
    // block are observationally identical in digest mode).
    let cases = [
        BlockProcessError::HeaderMeta(
            ergo_validation::header::HeaderValidationError::MetaTimestampMismatch {
                meta: 100,
                header: 99,
            },
        ),
        BlockProcessError::HeaderMeta(
            ergo_validation::header::HeaderValidationError::HeaderIdMismatch {
                expected: id(1),
                computed: id(2),
            },
        ),
        BlockProcessError::HeaderMeta(
            ergo_validation::header::HeaderValidationError::PowNotValidated { pow_validity: 0 },
        ),
        BlockProcessError::HeaderMeta(
            ergo_validation::header::HeaderValidationError::HeaderParseFailed(
                "truncated local row".into(),
            ),
        ),
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

mod session_promotion {
    use super::*;
    use ergo_state::HeaderSectionStore;

    // ----- helpers -----

    fn header(
        store: &mut ergo_state::StateBackendKind,
        byte: u8,
        parent: u8,
        height: u32,
        score: u8,
        best: bool,
    ) {
        store
            .store_validated_header(
                &id(byte),
                &[byte; 8],
                &ergo_state::chain::HeaderMeta {
                    parent_id: if parent == 0 { [0; 32] } else { id(parent) },
                    height,
                    cumulative_score: vec![score],
                    pow_validity: 1,
                    timestamp: u64::from(height),
                },
                best.then_some((height, vec![score])),
            )
            .unwrap();
    }

    fn fail(store: &mut ergo_state::StateBackendKind, rejected: u8, height: u32) {
        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            DifficultyParams::mainnet(),
        );
        executor.invalidate_or_session_mark(
            store,
            &mut SyncCoordinator::new(0),
            id(rejected),
            height,
            &block_proc::BlockProcessError::State(ergo_state::store::StateError::DigestMismatch {
                computed: "local".to_owned(),
                expected: "header".to_owned(),
            }),
        );
    }

    // ----- happy path -----

    #[test]
    fn session_promotion_demoted_branch_prunes_pending_and_assembly() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 1, 2, 2, true);
        header(&mut store, 3, 0, 1, 1, false);
        header(&mut store, 4, 3, 2, 2, false);
        let mut coordinator = SyncCoordinator::new(0);
        coordinator.sync_state_mut().set_best_known_header(2);
        for (h, byte) in [(1, 1), (2, 2)] {
            coordinator.sync_state_mut().add_pending_block(h, id(byte));
            coordinator.assembly_mut().register_header(
                ergo_ser::modifier_id::ExpectedSections::from_header(
                    &id(byte),
                    &id(byte + 10),
                    &id(byte + 20),
                    &id(byte + 30),
                ),
                false,
            );
        }
        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            DifficultyParams::mainnet(),
        );
        executor.invalidate_or_session_mark(
            &mut store,
            &mut coordinator,
            id(1),
            1,
            &block_proc::BlockProcessError::Deserialize("local".into()),
        );
        assert_eq!(store.chain_state_meta().best_header_id, id(4));
        assert!(!coordinator
            .sync_state()
            .pending_blocks_iter()
            .any(|b| b.header_id == id(1) || b.header_id == id(2)));
        assert!(coordinator
            .assembly_mut()
            .expected_section_ids(&id(1))
            .is_none());
        assert!(coordinator
            .assembly_mut()
            .expected_section_ids(&id(2))
            .is_none());
    }

    #[test]
    fn durable_promotion_demoted_branch_prunes_pending_and_assembly() {
        for promote in [false, true] {
            let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
            header(&mut store, 1, 0, 1, 1, true);
            header(&mut store, 2, 1, 2, 2, true);
            if promote {
                header(&mut store, 3, 0, 1, 1, false);
                header(&mut store, 4, 3, 2, 2, false);
            }
            let mut coordinator = SyncCoordinator::new(0);
            coordinator.sync_state_mut().set_best_known_header(2);
            for (h, byte) in [(1, 1), (2, 2)] {
                coordinator.sync_state_mut().add_pending_block(h, id(byte));
                coordinator.assembly_mut().register_header(
                    ergo_ser::modifier_id::ExpectedSections::from_header(
                        &id(byte),
                        &id(byte + 10),
                        &id(byte + 20),
                        &id(byte + 30),
                    ),
                    false,
                );
            }
            let section_ids: Vec<_> = [id(1), id(2)]
                .iter()
                .flat_map(|id| coordinator.assembly_mut().expected_section_ids(id).unwrap())
                .collect();
            let mut executor = SyncExecutor::new(
                ProtocolParams::mainnet_default(),
                DifficultyParams::mainnet(),
            );
            executor.invalidate_or_session_mark(
                &mut store,
                &mut coordinator,
                id(1),
                1,
                &block_proc::BlockProcessError::AdProofsHashMismatch {
                    header_id: id(1),
                    declared_root: id(10),
                    computed_root: id(11),
                },
            );
            if promote {
                assert_eq!(store.chain_state_meta().best_header_id, id(4));
            } else {
                assert_eq!(store.chain_state_meta().best_header_height, 0);
            }
            for (_, section_id) in section_ids {
                assert!(coordinator
                    .assembly_mut()
                    .identify_section(&section_id)
                    .is_none());
            }
            assert!(!coordinator
                .sync_state()
                .pending_blocks_iter()
                .any(|b| b.header_id == id(1) || b.header_id == id(2)));
            assert!(coordinator
                .assembly_mut()
                .expected_section_ids(&id(1))
                .is_none());
            assert!(coordinator
                .assembly_mut()
                .expected_section_ids(&id(2))
                .is_none());
        }
    }

    #[test]
    fn session_promotion_multiple_candidates_selects_greatest_score() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 0, 1, 3, false);
        header(&mut store, 3, 0, 1, 2, false);
        fail(&mut store, 1, 1);
        assert_eq!(store.chain_state_meta().best_header_id, id(2));
        assert_eq!(store.get_header_id_at_height(1).unwrap(), Some(id(2)));
    }

    #[test]
    fn session_promotion_equal_candidates_keeps_first() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 0, 1, 1, false);
        header(&mut store, 3, 0, 1, 1, false);
        fail(&mut store, 1, 1);
        assert_eq!(store.chain_state_meta().best_header_id, id(2));
    }

    #[test]
    fn session_promotion_stored_descendant_selects_eligible_tip() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 1, 2, 2, true);
        header(&mut store, 3, 0, 1, 1, false);
        header(&mut store, 4, 3, 2, 2, false);
        fail(&mut store, 1, 1);
        assert_eq!(store.chain_state_meta().best_header_id, id(4));
        assert_eq!(store.get_header_id_at_height(1).unwrap(), Some(id(3)));
    }

    #[test]
    fn session_promotion_search_boundary_limits_configured_depth() {
        let depth = crate::header_proc::SESSION_PROMOTION_SEARCH_DEPTH as u8;
        for tip in [depth, depth + 1] {
            let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
            for h in 1..=tip {
                header(&mut store, h, h - 1, u32::from(h), h, true);
                header(
                    &mut store,
                    h + 32,
                    if h == 1 { 0 } else { h + 31 },
                    u32::from(h),
                    h,
                    false,
                );
            }
            fail(&mut store, 1, 1);
            assert_eq!(
                store.chain_state_meta().best_header_id,
                id(if tip == depth { tip + 32 } else { tip })
            );
        }
    }

    #[test]
    fn session_promotion_existing_mark_retries_selection() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 0, 1, 1, false);
        store.mark_session_invalid(id(1));
        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            DifficultyParams::mainnet(),
        );
        executor.try_apply_next_blocks(
            &mut store,
            &mut SyncCoordinator::new(0),
            Instant::now(),
            None,
        );
        assert_eq!(store.chain_state_meta().best_header_id, id(2));
    }

    #[test]
    fn durable_promotion_failed_header_read_retries_selection() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 0, 1, 1, false);
        let db = store.as_utxo().unwrap().db_arc();
        let txn = db.begin_write().unwrap();
        txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new("headers"))
            .unwrap()
            .remove(id(2).as_slice())
            .unwrap();
        txn.commit().unwrap();
        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            DifficultyParams::mainnet(),
        );
        let mut coordinator = SyncCoordinator::new(0);
        executor.invalidate_or_session_mark(
            &mut store,
            &mut coordinator,
            id(1),
            1,
            &block_proc::BlockProcessError::AdProofsHashMismatch {
                header_id: id(1),
                declared_root: id(10),
                computed_root: id(11),
            },
        );
        assert!(store.is_durably_invalid(&id(1)).unwrap());
        assert_ne!(store.chain_state_meta().best_header_id, id(2));
        header(&mut store, 2, 0, 1, 1, false);
        executor.try_apply_next_blocks(&mut store, &mut coordinator, Instant::now(), None);
        assert_eq!(store.chain_state_meta().best_header_id, id(2));
    }

    // ----- error paths -----

    #[test]
    fn session_promotion_different_parent_keeps_best() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 99, 1, 1, false);
        fail(&mut store, 1, 1);
        assert_eq!(store.chain_state_meta().best_header_id, id(1));
    }

    #[test]
    fn session_promotion_unrelated_failure_preserves_best() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 0, 1, 2, false);
        header(&mut store, 3, 0, 1, 3, false);
        fail(&mut store, 2, 1);
        assert_eq!(store.chain_state_meta().best_header_id, id(1));
    }

    #[test]
    fn session_promotion_durable_mark_retries_selection() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 0, 1, 1, false);
        let mut meta = store.get_header_meta(&id(1)).unwrap().unwrap();
        meta.pow_validity = 3;
        store
            .store_validated_header(&id(1), &[1; 8], &meta, None)
            .unwrap();
        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            DifficultyParams::mainnet(),
        );
        executor.try_apply_next_blocks(
            &mut store,
            &mut SyncCoordinator::new(0),
            Instant::now(),
            None,
        );
        assert_eq!(store.chain_state_meta().best_header_id, id(2));
    }

    #[test]
    fn session_promotion_non_tip_failure_preserves_best() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 0, 1, 1, false);
        header(&mut store, 3, 1, 2, 2, true);
        fail(&mut store, 1, 1);
        assert_eq!(store.chain_state_meta().best_header_id, id(3));
    }

    #[test]
    fn session_promotion_failure_above_next_height_preserves_best() {
        let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
        header(&mut store, 1, 0, 1, 1, true);
        header(&mut store, 2, 1, 2, 2, true);
        header(&mut store, 3, 1, 2, 3, false);
        header(&mut store, 4, 2, 3, 3, true);
        header(&mut store, 5, 3, 3, 4, false);
        fail(&mut store, 2, 2);
        assert_eq!(store.chain_state_meta().best_header_id, id(4));
    }
}

#[test]
fn queued_body_actions_obey_current_executor_mode() {
    let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let extension = ergo_ser::extension::Extension {
        header_id: ModifierId::from_bytes(id(9)),
        fields: vec![],
    };
    let mut writer = VlqWriter::new();
    ergo_ser::extension::write_extension(&mut writer, &extension).unwrap();
    let bytes = writer.result();
    let section_id = id(10);
    let now = Instant::now();
    for headers_only in [true, false] {
        let mut coordinator = SyncCoordinator::new_with_window_and_mode(0, 100, headers_only);
        coordinator.set_bootstrap_in_progress(!headers_only);
        assert!(executor
            .execute(
                Action::PersistSection {
                    modifier_id: section_id,
                    section_bytes: bytes.clone(),
                    section_type: 108
                },
                &mut store,
                &mut coordinator,
                now,
                None
            )
            .is_empty());
        assert!(executor
            .execute(
                Action::AssembleBlock { header_id: id(9) },
                &mut store,
                &mut coordinator,
                now,
                None
            )
            .is_empty());
        assert!(store.get_block_section(&section_id).unwrap().is_none());
        assert_eq!(store.chain_state_meta().best_full_block_height, 0);
        assert!(executor.last_block_apply_error().is_none());
    }
    let mut coordinator = SyncCoordinator::new(0);
    executor.execute(
        Action::PersistSection {
            modifier_id: section_id,
            section_bytes: bytes.clone(),
            section_type: 108,
        },
        &mut store,
        &mut coordinator,
        now,
        None,
    );
    assert_eq!(store.get_block_section(&section_id).unwrap(), Some(bytes));
}

#[test]
fn older_header_progress_retries_epoch_context_bucket_once() {
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let context_parent = id(8);
    let missing_parent = id(7);
    executor.context_retry_parents.insert(context_parent);
    assert!(executor.orphan_retry_parents(&HashSet::new()).is_empty());
    assert!(executor.context_retry_parents.contains(&context_parent));
    let older_ancestor = id(1);
    let eligible = executor.orphan_retry_parents(&HashSet::from([older_ancestor]));
    assert_eq!(eligible, HashSet::from([older_ancestor, context_parent]));
    assert!(!eligible.contains(&missing_parent));
    assert!(executor.context_retry_parents.is_empty());
    // Rebuffering after that attempt belongs to the next progress event.
    executor.context_retry_parents.insert(context_parent);
    assert!(executor.orphan_retry_parents(&HashSet::new()).is_empty());
}

fn install_header_cache_fixture(
    store: &mut ergo_state::StateBackendKind,
    header: Header,
    best: bool,
) -> (header_proc::ProcessedHeader, Vec<u8>) {
    let (bytes, id) = ergo_ser::header::serialize_header(&header).unwrap();
    let id = *id.as_bytes();
    let meta = ergo_state::chain::HeaderMeta {
        parent_id: *header.parent_id.as_bytes(),
        height: header.height,
        cumulative_score: header.height.to_be_bytes().to_vec(),
        pow_validity: 1,
        timestamp: header.timestamp,
    };
    store
        .store_validated_header(
            &id,
            &bytes,
            &meta,
            best.then_some((header.height, meta.cumulative_score.clone())),
        )
        .unwrap();
    let checked = CheckedHeader::from_persisted_parts(
        &bytes,
        id,
        1,
        meta.height,
        meta.parent_id,
        meta.timestamp,
    )
    .unwrap();
    (
        header_proc::ProcessedHeader {
            header_id: id,
            height: header.height,
            parent_id: meta.parent_id,
            is_new_best: best,
            transactions_root: *header.transactions_root.as_bytes(),
            extension_root: *header.extension_root.as_bytes(),
            ad_proofs_root: *header.ad_proofs_root.as_bytes(),
            header,
            checked,
        },
        bytes,
    )
}

#[test]
fn recent_header_cache_ignores_losing_forks_and_rebuilds_winning_ancestry() {
    // This is a cache/storage fixture: synthetic fork rows carry a trusted
    // test marker. It does not verify their PoW or execute peer admission.
    let rows: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/headers_1_10.json"
    ))
    .unwrap();
    let mut store = ergo_state::StateBackendKind::Utxo(open_initialized_store());
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut originals = Vec::new();
    let mut headers = Vec::new();
    for row in rows.as_array().unwrap().iter().take(3) {
        let bytes = hex::decode(row["bytes"].as_str().unwrap()).unwrap();
        let header =
            ergo_ser::header::read_header(&mut ergo_primitives::reader::VlqReader::new(&bytes))
                .unwrap();
        headers.push(header.clone());
        let (processed, bytes) = install_header_cache_fixture(&mut store, header, true);
        originals.push(processed.header_id);
        executor.push_validated_header(&processed, &bytes, &store);
    }
    let original_cache = executor.last_headers.clone();
    let mut fork2 = headers[1].clone();
    fork2.timestamp += 1;
    let (fork2, bytes2) = install_header_cache_fixture(&mut store, fork2, false);
    executor.push_validated_header(&fork2, &bytes2, &store);
    let mut fork3 = headers[2].clone();
    fork3.parent_id = ModifierId::from_bytes(fork2.header_id);
    let (fork3, bytes3) = install_header_cache_fixture(&mut store, fork3, false);
    executor.push_validated_header(&fork3, &bytes3, &store);
    assert_eq!(
        executor
            .last_headers
            .iter()
            .map(|(h, _)| *h.header_id())
            .collect::<Vec<_>>(),
        originals.iter().rev().copied().collect::<Vec<_>>()
    );
    assert_eq!(executor.header_index[&2], originals[1]);
    let mut fork4 = headers[2].clone();
    fork4.height = 4;
    fork4.timestamp += 1;
    fork4.parent_id = ModifierId::from_bytes(fork3.header_id);
    let (fork4, bytes4) = install_header_cache_fixture(&mut store, fork4, true);
    executor.push_validated_header(&fork4, &bytes4, &store);
    let expected = vec![
        fork4.header_id,
        fork3.header_id,
        fork2.header_id,
        originals[0],
    ];
    assert_eq!(
        executor
            .last_headers
            .iter()
            .map(|(h, _)| *h.header_id())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(executor.header_index[&2], fork2.header_id);
    assert_eq!(executor.header_index[&3], fork3.header_id);
    assert_eq!(executor.header_index[&4], fork4.header_id);
    assert_eq!(*original_cache[0].0.header_id(), originals[2]);
    let mut hydrated = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    hydrated.hydrate_from_store(&store).unwrap();
    assert_eq!(
        hydrated.cached_header_bytes(50),
        executor.cached_header_bytes(50)
    );
}

#[test]
fn winning_header_fork_repairs_index_below_applied_full_tip() {
    // Real in-process store commits establish an applied empty test chain.
    // Fork headers are trusted synthetic cache fixtures; no PoW or script
    // acceptance, peer admission, or full-block rollback is asserted here.
    let mut utxo = open_initialized_store();
    let mut applied_headers = Vec::new();
    let mut parent = [0; 32];
    for height in 1..=5 {
        parent = apply_empty_block(&mut utxo, height, parent);
        let bytes = utxo.get_header(&parent).unwrap().unwrap();
        let header =
            ergo_ser::header::read_header(&mut ergo_primitives::reader::VlqReader::new(&bytes))
                .unwrap();
        applied_headers.push(header);
    }
    let applied_tip = parent;
    let mut store = ergo_state::StateBackendKind::Utxo(utxo);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut originals = Vec::new();
    let mut template = applied_headers.last().unwrap().clone();
    for height in 1..=10 {
        let header = if height <= 5 {
            applied_headers[(height - 1) as usize].clone()
        } else {
            template.height = height;
            template.timestamp += 1;
            template.parent_id = ModifierId::from_bytes(*originals.last().unwrap());
            template.clone()
        };
        let (processed, bytes) = install_header_cache_fixture(&mut store, header, true);
        originals.push(processed.header_id);
        executor.push_validated_header(&processed, &bytes, &store);
    }
    assert_eq!(store.chain_state_meta().best_full_block_height, 5);
    assert_eq!(store.chain_state_meta().best_full_block_id, applied_tip);

    let mut fork_parent = originals[2];
    let mut fork_ids = Vec::new();
    for height in 4..=11 {
        let mut header = template.clone();
        header.height = height;
        header.timestamp = 1_700_000_001 + u64::from(height);
        header.parent_id = ModifierId::from_bytes(fork_parent);
        let winning = height == 11;
        let (processed, bytes) = install_header_cache_fixture(&mut store, header, winning);
        fork_parent = processed.header_id;
        fork_ids.push(processed.header_id);
        executor.push_validated_header(&processed, &bytes, &store);
        if !winning {
            assert_eq!(executor.header_index_get(4), Some(originals[3]));
            assert_eq!(executor.header_index_get(5), Some(originals[4]));
        }
    }
    for height in 1..=3 {
        assert_eq!(
            executor.header_index_get(height),
            Some(originals[(height - 1) as usize])
        );
    }
    for height in 4..=11 {
        let expected = fork_ids[(height - 4) as usize];
        // Check the cache before a storage-backed accessor could refresh it.
        assert_eq!(executor.header_index_get(height), Some(expected));
        assert_eq!(
            store.get_header_id_at_height(height).unwrap(),
            Some(expected)
        );
    }
    assert_eq!(executor.header_index_len(), 11);
    assert_eq!(store.chain_state_meta().best_full_block_id, applied_tip);
    assert_eq!(store.chain_state_meta().best_full_block_height, 5);
    let cached_ids = executor
        .last_headers
        .iter()
        .map(|(h, _)| *h.header_id())
        .collect::<Vec<_>>();
    let expected_ids = fork_ids
        .iter()
        .rev()
        .chain(originals[..3].iter().rev())
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(cached_ids, expected_ids);
}

fn mainnet_headers_1_10() -> Vec<(Vec<u8>, Header)> {
    let rows: serde_json::Value = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/headers_1_10.json"
    ))
    .unwrap();
    rows.as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let bytes = hex::decode(row["bytes"].as_str().unwrap()).unwrap();
            let header =
                ergo_ser::header::read_header(&mut ergo_primitives::reader::VlqReader::new(&bytes))
                    .unwrap();
            (bytes, header)
        })
        .collect()
}

/// Commit a NiPoPoW proof over mainnet headers whose stored chain is not
/// contiguous: `prefix` heights below a contiguous `suffix` of `k` headers.
/// Interlinks are left empty; `apply_popow_proof` trusts its caller.
fn sparse_popow_store(
    headers: &[(Vec<u8>, Header)],
    prefix: &[u32],
    suffix: std::ops::RangeInclusive<u32>,
) -> ergo_state::StateBackendKind {
    let popow = |height: u32| ergo_ser::popow_header::PoPowHeader {
        header: headers[height as usize - 1].1.clone(),
        interlinks: vec![],
        interlinks_proof: vec![],
    };
    let mut store = open_initialized_store();
    store
        .apply_popow_proof(&ergo_ser::popow_proof::NipopowProof {
            m: 1,
            k: suffix.end() - suffix.start() + 1,
            prefix: prefix.iter().map(|height| popow(*height)).collect(),
            suffix_head: popow(*suffix.start()),
            suffix_tail: (*suffix.start() + 1..=*suffix.end())
                .map(|height| headers[height as usize - 1].1.clone())
                .collect(),
            continuous: true,
        })
        .unwrap();
    ergo_state::StateBackendKind::Utxo(store)
}

fn validate_header_action(headers: &[(Vec<u8>, Header)], height: u32) -> Action {
    let bytes = headers[height as usize - 1].0.clone();
    Action::ValidateHeader {
        peer: peer(9030),
        modifier_id: *blake2b256(&bytes).as_bytes(),
        header_bytes: bytes,
    }
}

fn cached_heights(executor: &SyncExecutor) -> Vec<u32> {
    executor
        .last_headers
        .iter()
        .map(|(header, _)| header.height())
        .collect()
}

#[test]
fn sparse_popow_store_accepts_next_header_and_restarts() {
    // Real proof apply and real-PoW mainnet headers. The proof stores 1 and
    // 5 below its 6..=7 suffix, so 2..=4 are absent by construction.
    let headers = mainnet_headers_1_10();
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    // Boot hydration ran on the fresh store, before the proof arrived.
    executor
        .hydrate_from_store(&ergo_state::StateBackendKind::Utxo(open_initialized_store()))
        .unwrap();
    let mut store = sparse_popow_store(&headers, &[1, 5], 6..=7);
    assert!(matches!(
        store.chain_state_meta().header_availability,
        ergo_state::chain::HeaderAvailability::PoPowSparse {
            dense_from_height: 5,
            proof_suffix_height: 6,
        }
    ));
    let mut coordinator = SyncCoordinator::new(0);
    let actions = executor.execute(
        validate_header_action(&headers, 8),
        &mut store,
        &mut coordinator,
        Instant::now(),
        None,
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Penalize { .. })),
        "{actions:?}"
    );
    assert_eq!(store.chain_state_meta().best_header_height, 8);
    assert_eq!(cached_heights(&executor), vec![8]);

    // Restart: boot hydration ends at the proof's absent prefix ancestor.
    let mut restarted = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    restarted.hydrate_from_store(&store).unwrap();
    restarted.load_header_index(&store).unwrap();
    assert_eq!(cached_heights(&restarted), vec![8, 7, 6, 5]);
    assert_eq!(restarted.header_index_len(), 4);
    let mut coordinator = SyncCoordinator::new(0);
    restarted.execute(
        validate_header_action(&headers, 9),
        &mut store,
        &mut coordinator,
        Instant::now(),
        None,
    );
    assert_eq!(store.chain_state_meta().best_header_height, 9);
    assert_eq!(cached_heights(&restarted), vec![9, 8, 7, 6, 5]);
    assert_eq!(
        restarted.header_index_get(9),
        Some(*blake2b256(&headers[8].0).as_bytes())
    );
}

#[test]
fn sparse_popow_store_accepts_next_header_batch() {
    let headers = mainnet_headers_1_10();
    let mut store = sparse_popow_store(&headers, &[1, 5], 6..=7);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(0);
    let actions = executor.execute_all(
        vec![
            validate_header_action(&headers, 9),
            validate_header_action(&headers, 8),
        ],
        &mut store,
        &mut coordinator,
        Instant::now(),
        None,
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Penalize { .. })),
        "{actions:?}"
    );
    assert_eq!(store.chain_state_meta().best_header_height, 9);
    assert_eq!(cached_heights(&executor), vec![9, 8]);
}

#[test]
fn hydration_ends_below_the_proof_suffix_head_but_not_in_dense_ancestry() {
    // A Scala proof need not carry its suffix head's parent, which can sit at
    // or above `dense_from_height` (suffix head - k + 1, saturating).
    let headers = mainnet_headers_1_10();
    let store = sparse_popow_store(&headers, &[1], 4..=8);
    assert!(matches!(
        store.chain_state_meta().header_availability,
        ergo_state::chain::HeaderAvailability::PoPowSparse {
            dense_from_height: 0,
            proof_suffix_height: 4,
        }
    ));
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    executor.hydrate_from_store(&store).unwrap();
    assert_eq!(cached_heights(&executor), vec![8, 7, 6, 5, 4]);

    // The same hole in Dense ancestry remains a hydration failure.
    let mut dense = open_initialized_store();
    let (bytes, header) = &headers[3];
    let id = *blake2b256(bytes).as_bytes();
    dense.store_header(&id, bytes).unwrap();
    dense
        .store_header_meta(
            &id,
            &ergo_state::chain::HeaderMeta {
                parent_id: *header.parent_id.as_bytes(),
                height: header.height,
                cumulative_score: vec![4],
                pow_validity: 1,
                timestamp: header.timestamp,
            },
        )
        .unwrap();
    dense
        .test_force_set_best_header_unsafe(id, header.height, vec![4])
        .unwrap();
    let dense = ergo_state::StateBackendKind::Utxo(dense);
    match executor.hydrate_from_store(&dense) {
        Err(HydrationError::MissingPersistedRow {
            phase: "hydrate_from_store",
            kind: "header",
            id,
        }) => assert_eq!(id, hex::encode(blake2b256(&headers[2].0).as_bytes())),
        other => panic!("expected the Dense ancestor gap to fail, got {other:?}"),
    }
}

/// Startup as boot runs it: recent-header hydration, then the index loader.
fn restarted_executor(store: &ergo_state::StateBackendKind) -> SyncExecutor {
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    executor.hydrate_from_store(store).unwrap();
    executor.load_header_index(store).unwrap();
    executor
}

/// Install a trusted synthetic child of `parent` and feed it to the cache.
/// `salt` separates same-height siblings.
fn push_fork_header(
    executor: &mut SyncExecutor,
    store: &mut ergo_state::StateBackendKind,
    template: &Header,
    parent: [u8; 32],
    salt: u64,
    best: bool,
) -> [u8; 32] {
    let parent_height = store.get_header_meta(&parent).unwrap().unwrap().height;
    let mut header = template.clone();
    header.height = parent_height + 1;
    header.parent_id = ModifierId::from_bytes(parent);
    header.timestamp = template.timestamp + u64::from(header.height) + salt;
    let (processed, bytes) = install_header_cache_fixture(store, header, best);
    executor.push_validated_header(&processed, &bytes, store);
    processed.header_id
}

#[test]
fn restarted_header_fork_repairs_only_the_indexed_range() {
    // Real applied empty chain; fork rows are trusted synthetic fixtures.
    let mut utxo = open_initialized_store();
    let mut tip = [0; 32];
    for height in 1..=20 {
        tip = apply_empty_block(&mut utxo, height, tip);
    }
    let template = ergo_ser::header::read_header(&mut ergo_primitives::reader::VlqReader::new(
        &utxo.get_header(&tip).unwrap().unwrap(),
    ))
    .unwrap();
    let parent_of_tip = *template.parent_id.as_bytes();
    let mut store = ergo_state::StateBackendKind::Utxo(utxo);

    // A synced restart indexes nothing: every stored header is applied.
    let mut executor = restarted_executor(&store);
    assert_eq!(executor.header_index_len(), 0);
    let a = push_fork_header(&mut executor, &mut store, &template, tip, 0, true);
    let b = push_fork_header(&mut executor, &mut store, &template, tip, 1, false);
    let c = push_fork_header(&mut executor, &mut store, &template, b, 0, true);
    assert_ne!(a, b);
    assert_eq!(executor.header_index_len(), 2);
    assert_eq!(executor.header_index_get(21), Some(b));
    assert_eq!(executor.header_index_get(22), Some(c));
    assert_eq!(cached_heights(&executor)[..3], [22, 21, 20]);

    // A winning fork from below the tip with nothing indexed yet records only
    // the unapplied gap above the applied tip.
    let mut executor = restarted_executor(&store);
    let sibling = push_fork_header(
        &mut executor,
        &mut store,
        &template,
        parent_of_tip,
        2,
        false,
    );
    let winner = push_fork_header(&mut executor, &mut store, &template, sibling, 2, true);
    assert_eq!(store.chain_state_meta().best_full_block_height, 20);
    assert_eq!(executor.header_index_len(), 1);
    assert_eq!(executor.header_index_get(21), Some(winner));
}

#[test]
fn sparse_store_header_fork_repair_never_walks_into_the_proof_prefix() {
    // Proof prefix {1, 5} and suffix 6..=7, then real headers 8..=10.
    let headers = mainnet_headers_1_10();
    let store_through_10 = || {
        let mut store = sparse_popow_store(&headers, &[1, 5], 6..=7);
        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            DifficultyParams::mainnet(),
        );
        let mut coordinator = SyncCoordinator::new(0);
        for height in 8..=10 {
            executor.execute(
                validate_header_action(&headers, height),
                &mut store,
                &mut coordinator,
                Instant::now(),
                None,
            );
        }
        assert_eq!(store.chain_state_meta().best_header_height, 10);
        store
    };
    let tip = *blake2b256(&headers[9].0).as_bytes();
    let template = headers[9].1.clone();

    // Synced restart after a snapshot install: nothing is unapplied.
    let mut store = store_through_10();
    store
        .as_utxo_mut()
        .unwrap()
        .test_force_set_best_full_block_unsafe(tip, 10)
        .unwrap();
    let mut restarted = restarted_executor(&store);
    assert_eq!(cached_heights(&restarted), vec![10, 9, 8, 7, 6, 5]);
    push_fork_header(&mut restarted, &mut store, &template, tip, 0, true);
    let b = push_fork_header(&mut restarted, &mut store, &template, tip, 1, false);
    let c = push_fork_header(&mut restarted, &mut store, &template, b, 0, true);
    assert_eq!(restarted.header_index_len(), 2);
    assert_eq!(restarted.header_index_get(11), Some(b));
    assert_eq!(restarted.header_index_get(12), Some(c));

    // Attached without the startup index loader: the repair covers the
    // unapplied gap down to the proof's absent prefix, then stops.
    let mut store = store_through_10();
    let mut attached = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    attached.hydrate_from_store(&store).unwrap();
    let parent_of_tip = *template.parent_id.as_bytes();
    let sibling = push_fork_header(
        &mut attached,
        &mut store,
        &template,
        parent_of_tip,
        1,
        false,
    );
    let winner = push_fork_header(&mut attached, &mut store, &template, sibling, 1, true);
    assert_eq!(attached.header_index_get(11), Some(winner));
    assert_eq!(attached.header_index_get(10), Some(sibling));
    assert_eq!(
        attached.header_index_get(5),
        Some(*blake2b256(&headers[4].0).as_bytes())
    );
    assert_eq!(attached.header_index_len(), 7);
}

/// Mainnet header 1 as the stored best header. A nonzero `timestamp_skew`
/// makes its metadata contradict its bytes: local corruption, not peer data.
fn store_with_header_1(
    headers: &[(Vec<u8>, Header)],
    timestamp_skew: u64,
) -> ergo_state::StateBackendKind {
    let mut store = open_initialized_store();
    let (bytes, header) = &headers[0];
    let id = *blake2b256(bytes).as_bytes();
    store.store_header(&id, bytes).unwrap();
    store
        .store_header_meta(
            &id,
            &ergo_state::chain::HeaderMeta {
                parent_id: *header.parent_id.as_bytes(),
                height: header.height,
                cumulative_score: vec![1],
                pow_validity: 1,
                timestamp: header.timestamp + timestamp_skew,
            },
        )
        .unwrap();
    store
        .test_force_set_best_header_unsafe(id, header.height, vec![1])
        .unwrap();
    ergo_state::StateBackendKind::Utxo(store)
}

// Local failures must stop processing rather than penalize the peer that
// delivered a valid header (the `Penalize` these paths would otherwise send).

#[test]
#[should_panic(expected = "local header processing failure is fatal: stored header")]
fn local_header_failure_stops_single_header_validation() {
    let headers = mainnet_headers_1_10();
    let mut store = store_with_header_1(&headers, 1);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    executor.execute(
        validate_header_action(&headers, 2),
        &mut store,
        &mut SyncCoordinator::new(0),
        Instant::now(),
        None,
    );
}

#[test]
#[should_panic(expected = "local header processing failure is fatal: stored header")]
fn local_header_failure_stops_batch_validation() {
    let headers = mainnet_headers_1_10();
    let mut store = store_with_header_1(&headers, 1);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    executor.execute_all(
        vec![
            validate_header_action(&headers, 2),
            validate_header_action(&headers, 3),
        ],
        &mut store,
        &mut SyncCoordinator::new(0),
        Instant::now(),
        None,
    );
}

#[test]
#[should_panic(
    expected = "local header processing failure is fatal: header finalization bytes do not match"
)]
fn local_header_failure_stops_orphan_drain() {
    let headers = mainnet_headers_1_10();
    let mut store = store_with_header_1(&headers, 0);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut coordinator = SyncCoordinator::new(0);
    // A buffered orphan whose retained bytes no longer match its PoW-checked
    // header: the retained-byte contract is local, whoever sent it.
    let pre = header_proc::pre_validate_header(&headers[2].0).unwrap();
    let orphan_id = *pre.header_id();
    assert!(executor.buffer_or_defer_orphan_header(
        peer(9030),
        pre,
        headers[3].0.clone(),
        orphan_id,
        3,
        &store,
        &mut coordinator,
    ));
    // Installing the orphan's parent retries it in the orphan drain.
    executor.execute(
        validate_header_action(&headers, 2),
        &mut store,
        &mut coordinator,
        Instant::now(),
        None,
    );
}

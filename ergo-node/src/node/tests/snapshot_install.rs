// ----- mode 2 part 2f-2: inbound SnapshotsInfo + disconnect cleanup -----

fn snapshots_info_payload(manifests: &[(i32, [u8; 32])]) -> Vec<u8> {
    message::serialize_snapshots_info(&ergo_p2p::types::SnapshotsInfo {
        available_manifests: manifests.to_vec(),
    })
    .unwrap()
}

fn synthetic_peer(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}

#[test]
fn inbound_snapshots_info_below_quorum_keeps_bootstrap_querying() {
    use ergo_sync::snapshot_bootstrap::BootstrapState;
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let payload = snapshots_info_payload(&[(52_224, mid(0xAA))]);

    for p in 1..=2u16 {
        let actions = handle_message(
            &mut state,
            synthetic_peer(p),
            message::CODE_SNAPSHOTS_INFO,
            &payload,
            Instant::now(),
        );
        assert!(actions.is_empty(), "no outbound action on SnapshotsInfo");
    }

    assert_eq!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Querying,
        "2 votes < default quorum of 3 must stay Querying",
    );
}

#[test]
fn inbound_snapshots_info_at_quorum_advances_bootstrap_to_selected() {
    use ergo_sync::snapshot_bootstrap::BootstrapState;
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let payload = snapshots_info_payload(&[(52_224, mid(0xAA))]);

    for p in 1..=3u16 {
        handle_message(
            &mut state,
            synthetic_peer(p),
            message::CODE_SNAPSHOTS_INFO,
            &payload,
            Instant::now(),
        );
    }

    assert_eq!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Selected {
            height: 52_224,
            manifest_id: mid(0xAA),
        },
    );
}

#[test]
fn malformed_snapshots_info_emits_misbehavior_penalty() {
    // A SnapshotsInfo payload claiming N entries but truncated
    // mid-list must trip the deserializer and trigger a peer
    // penalty — keeps the reducer from being fed garbage.
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    // Claim 100 entries but provide only 1 byte. VlqReader will fail.
    // VLQ count = 100, then a single truncated body byte.
    let bad = vec![100u8, 0u8];

    let actions = handle_message(
        &mut state,
        test_peer(),
        message::CODE_SNAPSHOTS_INFO,
        &bad,
        Instant::now(),
    );
    assert!(
        actions.iter().any(
            |a| matches!(a, Action::Penalize { penalty, .. } if *penalty == Penalty::Misbehavior)
        ),
        "malformed payload must trigger Misbehavior penalty; got {actions:?}",
    );
}

#[test]
fn peer_disconnect_drops_snapshot_bootstrap_vote() {
    use ergo_sync::snapshot_bootstrap::BootstrapState;
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let payload = snapshots_info_payload(&[(52_224, mid(0xAA))]);

    for p in 1..=3u16 {
        handle_message(
            &mut state,
            synthetic_peer(p),
            message::CODE_SNAPSHOTS_INFO,
            &payload,
            Instant::now(),
        );
    }
    assert!(matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Selected { .. },
    ));

    // Disconnect one of the three voting peers — selection must
    // revert to Querying since quorum drops from 3 to 2.
    super::cleanup_disconnected_peer(&mut state, &synthetic_peer(3));
    assert_eq!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Querying,
        "disconnect of the 3rd voter must revoke quorum",
    );
}

#[test]
fn inbound_manifest_rejects_malformed_bytes_before_latch() {
    use ergo_sync::snapshot_bootstrap::BootstrapState;

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let height = 52_224i32;
    let manifest_id = mid(0xAA);
    for port in 1..=3u16 {
        state
            .snapshot_bootstrap
            .on_snapshots_info(synthetic_peer(port), &[(height, manifest_id)]);
    }
    let peer = synthetic_peer(1);
    state
        .snapshot_bootstrap
        .mark_manifest_requested(peer, height, manifest_id, Instant::now());

    let payload = message::serialize_manifest(&[0, 1]).unwrap();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_MANIFEST,
        &payload,
        Instant::now(),
    );

    assert!(
        matches!(actions.as_slice(), [Action::Penalize { peer: offender, .. }] if *offender == peer)
    );
    assert!(!matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));
    assert!(state.chunk_assembly.is_none());
    assert!(state.pending_manifest_bytes.is_none());
    assert!(state.reconstructed_tree.is_none());
    assert!(state.snapshot_bootstrap.should_query(&synthetic_peer(2)));
}

#[test]
fn inbound_manifest_rejects_duplicate_expected_ids_before_latch() {
    use ergo_state::avl::snapshot_codec::{SnapshotServer, KEY_SIZE, LABEL_SIZE};
    use ergo_state::avl::tree::AvlTree;
    use ergo_sync::snapshot_bootstrap::BootstrapState;

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let mut tree = AvlTree::new();
    for i in 0..8u8 {
        tree.insert([i + 0x10; 32], vec![i]);
    }
    let server = SnapshotServer::build(&tree, 52_224, 1).unwrap();
    let manifest_id = *server.manifest_id.as_bytes();
    let mut manifest = server.manifest_bytes.clone();
    let left_label = 2 + 1 + 1 + KEY_SIZE;
    let right_label = left_label + LABEL_SIZE;
    let left = manifest[left_label..left_label + LABEL_SIZE].to_vec();
    manifest[right_label..right_label + LABEL_SIZE].copy_from_slice(&left);

    for port in 1..=3u16 {
        state
            .snapshot_bootstrap
            .on_snapshots_info(synthetic_peer(port), &[(52_224, manifest_id)]);
    }
    let peer = synthetic_peer(1);
    state
        .snapshot_bootstrap
        .mark_manifest_requested(peer, 52_224, manifest_id, Instant::now());
    let payload = message::serialize_manifest(&manifest).unwrap();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_MANIFEST,
        &payload,
        Instant::now(),
    );

    assert!(
        matches!(actions.as_slice(), [Action::Penalize { peer: offender, .. }] if *offender == peer)
    );
    assert!(!matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));
}

#[test]
fn inbound_manifest_rejects_same_root_with_different_tree_height() {
    use ergo_primitives::digest::ADDigest;
    use ergo_state::avl::snapshot_codec::{SnapshotServer, MAINNET_MANIFEST_DEPTH};
    use ergo_state::avl::tree::AvlTree;
    use ergo_state::chain::HeaderMeta;
    use ergo_sync::snapshot_bootstrap::BootstrapState;

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    let snapshot_height = 5u32;
    let mut tree = AvlTree::new();
    tree.insert([0x10; 32], vec![0xAA]);
    let server = SnapshotServer::build(&tree, snapshot_height, MAINNET_MANIFEST_DEPTH).unwrap();
    let manifest_id = *server.manifest_id.as_bytes();
    let mut state_root_bytes = [0u8; 33];
    state_root_bytes[..32].copy_from_slice(&manifest_id);
    state_root_bytes[32] = server.manifest_bytes[0];
    let state_root = ADDigest::from_bytes(state_root_bytes);
    let (header_id, header_bytes) = synthetic_header_with_state_root(snapshot_height, state_root);

    {
        let store = state.store.as_utxo_mut().unwrap();
        store.store_header(&header_id, &header_bytes).unwrap();
        store
            .store_header_meta(
                &header_id,
                &HeaderMeta {
                    parent_id: [0u8; 32],
                    height: snapshot_height,
                    cumulative_score: vec![5],
                    pow_validity: 1,
                    timestamp: 1_700_000_005,
                },
            )
            .unwrap();
        store
            .test_force_set_best_header_unsafe(header_id, snapshot_height, vec![5])
            .unwrap();
        store
            .test_force_put_header_chain_index(snapshot_height, &header_id)
            .unwrap();
        store
            .test_force_put_headers_by_height(snapshot_height, &header_id)
            .unwrap();
    }

    for port in 1..=3u16 {
        state.snapshot_bootstrap.on_snapshots_info(
            synthetic_peer(port),
            &[(snapshot_height as i32, manifest_id)],
        );
    }
    let peer = synthetic_peer(1);
    state.snapshot_bootstrap.mark_manifest_requested(
        peer,
        snapshot_height as i32,
        manifest_id,
        Instant::now(),
    );
    let mut manifest = server.manifest_bytes.clone();
    manifest[0] = manifest[0].wrapping_add(1);
    let payload = message::serialize_manifest(&manifest).unwrap();

    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_MANIFEST,
        &payload,
        Instant::now(),
    );
    assert!(
        matches!(actions.as_slice(), [Action::Penalize { peer: offender, .. }] if *offender == peer)
    );
    assert!(!matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));

    state
        .snapshot_bootstrap
        .on_snapshots_info(peer, &[(snapshot_height as i32, manifest_id)]);
    state.snapshot_bootstrap.mark_manifest_requested(
        peer,
        snapshot_height as i32,
        manifest_id,
        Instant::now(),
    );
    let valid_payload = message::serialize_manifest(&server.manifest_bytes).unwrap();
    handle_message(
        &mut state,
        peer,
        message::CODE_MANIFEST,
        &valid_payload,
        Instant::now(),
    );
    assert!(matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));
}

// ----- mode 2 part 2i: install retry across a deferred checkpoint anchor -----

/// Round-trip an empty `AvlTree` through the manifest codec to get a real
/// (non-fabricated) `ReconstructedTree` — same shape `drive_chunk_download`
/// hands `install_reconstructed_snapshot`, just without the network/chunk
/// machinery.
fn empty_reconstructed_tree() -> ergo_state::avl::snapshot_codec::ReconstructedTree {
    use ergo_state::avl::snapshot_codec::{
        reconstruct_tree, serialize_manifest, MAINNET_MANIFEST_DEPTH,
    };
    use ergo_state::avl::tree::AvlTree;
    let tree = AvlTree::new();
    let manifest_bytes = serialize_manifest(&tree, MAINNET_MANIFEST_DEPTH).unwrap();
    reconstruct_tree(&manifest_bytes, &std::collections::HashMap::new()).unwrap()
}

/// A minimal synthetic header at `height` carrying `state_root`. Not
/// PoW-valid or otherwise consensus-checked — `install_reconstructed_snapshot`
/// only reads `(height, state_root)` off the persisted bytes via
/// `ergo_ser::header::read_header`, it never re-validates them.
pub(super) fn synthetic_header_with_state_root(
    height: u32,
    state_root: ergo_primitives::digest::ADDigest,
) -> ([u8; 32], Vec<u8>) {
    use ergo_primitives::digest::{blake2b256, Digest32, ModifierId};
    use ergo_primitives::group_element::{GroupElement, GROUP_ELEMENT_LENGTH};
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::{write_header, Header};

    let header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0u8; 32]),
        ad_proofs_root: Digest32::ZERO,
        transactions_root: Digest32::ZERO,
        state_root,
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
    let bytes = w.result();
    let id = *blake2b256(&bytes).as_bytes();
    (id, bytes)
}

/// CodeRabbit #313 (MAJOR, `sync_tick.rs:946`): `install_reconstructed_snapshot`
/// calls `state.reconstructed_tree.take()` up front. The anchor-not-observed
/// early return (checkpoint height not yet materialized on this node's
/// header chain — a `SparseGap`/store-corruption-shaped read from
/// `lookup_header_at_height`, same as a genuine PoPowSparse gap) dropped the
/// taken tree without putting it back, so a SECOND tick would silently
/// no-op forever: `state.reconstructed_tree` is `None` and can never be
/// rebuilt (`pending_manifest_bytes` was already consumed). Bootstrap would
/// be permanently stuck even after the anchor became observable. Fixed by
/// restoring `state.reconstructed_tree` before returning on that path (and
/// the `SparseGap`-defer path just above it).
#[test]
fn install_reconstructed_snapshot_retries_after_deferred_checkpoint_anchor_appears() {
    use ergo_state::chain::HeaderMeta;
    use ergo_sync::header_proc::HeaderCheckpoint;
    use ergo_sync::snapshot_bootstrap::BootstrapState;

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));

    let snapshot_height: u32 = 5;
    let checkpoint_height: u32 = 3;
    let checkpoint_block_id = [0xEEu8; 32];

    // An (empty-tree) reconstructed snapshot, its root embedded as a real
    // header's `state_root` so the install-time trust re-check passes.
    let reconstructed = empty_reconstructed_tree();
    let manifest_id = *reconstructed.root_label.as_bytes();
    let mut root_digest = [0u8; 33];
    root_digest[..32].copy_from_slice(&manifest_id);
    root_digest[32] = reconstructed.tree_height;
    let state_root = ergo_primitives::digest::ADDigest::from_bytes(root_digest);

    let (h5_id, h5_bytes) = synthetic_header_with_state_root(snapshot_height, state_root);

    {
        let store = state.store.as_utxo_mut().unwrap();
        store.store_header(&h5_id, &h5_bytes).unwrap();
        store
            .store_header_meta(
                &h5_id,
                &HeaderMeta {
                    parent_id: [0u8; 32],
                    height: snapshot_height,
                    cumulative_score: vec![5],
                    pow_validity: 1,
                    timestamp: 1_700_000_005,
                },
            )
            .unwrap();
        store
            .test_force_set_best_header_unsafe(h5_id, snapshot_height, vec![5])
            .unwrap();
        store
            .test_force_put_header_chain_index(snapshot_height, &h5_id)
            .unwrap();
        store
            .test_force_put_headers_by_height(snapshot_height, &h5_id)
            .unwrap();
        // Deliberately leave `checkpoint_height` unindexed: the operator's
        // anchor has not been observed on this node's header chain yet.
    }

    state.executor.set_header_checkpoint(Some(HeaderCheckpoint {
        height: checkpoint_height,
        block_id: checkpoint_block_id,
    }));

    // Drive the snapshot_bootstrap reducer to `ManifestVerified` — the gate
    // `install_reconstructed_snapshot` checks — without the real quorum/
    // chunk-download machinery, which is irrelevant to this regression.
    for p in 1..=3u16 {
        state
            .snapshot_bootstrap
            .on_snapshots_info(synthetic_peer(p), &[(snapshot_height as i32, manifest_id)]);
    }
    assert!(matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::Selected { .. }
    ));
    state.snapshot_bootstrap.mark_manifest_requested(
        synthetic_peer(1),
        snapshot_height as i32,
        manifest_id,
        Instant::now(),
    );
    state
        .snapshot_bootstrap
        .accept_verified_manifest(Vec::new());
    assert!(matches!(
        state.snapshot_bootstrap.state(),
        BootstrapState::ManifestVerified { .. }
    ));

    state.reconstructed_tree = Some(reconstructed);

    // Tick 1: anchor not yet observed — install must defer, not drop the
    // reconstructed tree.
    handle_sync_tick(&mut state);
    assert!(
        state.reconstructed_tree.is_some(),
        "a deferred (not-yet-observed) checkpoint anchor must NOT drop the \
         reconstructed tree — the install must be retryable next tick",
    );
    assert_eq!(
        state
            .store
            .as_utxo()
            .unwrap()
            .chain_state()
            .best_full_block_height,
        0,
        "install must not have proceeded while the anchor is unobserved",
    );

    // The anchor becomes observed: the operator's pinned id materializes at
    // the checkpoint height on this node's header chain.
    state
        .store
        .as_utxo()
        .unwrap()
        .test_force_put_header_chain_index(checkpoint_height, &checkpoint_block_id)
        .unwrap();

    // Tick 2: anchor now observed and matches — install must succeed using
    // the SAME reconstructed tree kept from tick 1.
    handle_sync_tick(&mut state);
    assert!(
        state.reconstructed_tree.is_none(),
        "a successful install must consume the reconstructed tree",
    );
    assert_eq!(
        state.installed_snapshot,
        Some((snapshot_height, manifest_id)),
        "install must complete once the anchor is observed",
    );
    assert_eq!(
        state
            .store
            .as_utxo()
            .unwrap()
            .chain_state()
            .best_full_block_height,
        snapshot_height,
    );
}

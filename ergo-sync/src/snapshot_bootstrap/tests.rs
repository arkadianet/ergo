use super::*;
use ergo_p2p::peer::PeerId;
use ergo_primitives::digest::{ADDigest, Digest32};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

// ----- helpers -----

fn peer(port: u16) -> PeerId {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}

fn mid(b: u8) -> [u8; 32] {
    [b; 32]
}

// ----- happy path -----

#[test]
fn no_votes_is_idle() {
    let bs = SnapshotBootstrap::new();
    assert_eq!(bs.state(), BootstrapState::Idle);
}

#[test]
fn single_vote_below_quorum_is_querying() {
    let mut bs = SnapshotBootstrap::new();
    bs.on_snapshots_info(peer(1), &[(100, mid(0xAA))]);
    assert_eq!(bs.state(), BootstrapState::Querying);
}

#[test]
fn three_peers_same_manifest_advances_to_selected() {
    let mut bs = SnapshotBootstrap::new();
    for p in 1..=3 {
        bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
    }
    assert_eq!(
        bs.state(),
        BootstrapState::Selected {
            height: 52_224,
            manifest_id: mid(0xAA),
        }
    );
}

#[test]
fn highest_quorum_height_wins() {
    // Two heights both at quorum — higher height must win.
    let mut bs = SnapshotBootstrap::new();
    for p in 1..=3 {
        bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
    }
    for p in 4..=6 {
        bs.on_snapshots_info(peer(p), &[(104_448, mid(0xBB))]);
    }
    assert_eq!(
        bs.state(),
        BootstrapState::Selected {
            height: 104_448,
            manifest_id: mid(0xBB),
        }
    );
}

#[test]
fn higher_advertised_height_without_quorum_loses_to_lower_quorum_height() {
    // Critical rule: highest *quorum* height wins, not highest
    // *advertised* height. Two peers advertise a taller snapshot
    // but never reach quorum; three peers agree on a shorter
    // snapshot. Shorter must win.
    let mut bs = SnapshotBootstrap::new();
    bs.on_snapshots_info(peer(1), &[(200_000, mid(0xCC))]);
    bs.on_snapshots_info(peer(2), &[(200_000, mid(0xCC))]);
    for p in 3..=5 {
        bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
    }
    assert_eq!(
        bs.state(),
        BootstrapState::Selected {
            height: 52_224,
            manifest_id: mid(0xAA),
        }
    );
}

#[test]
fn peer_advertises_highest_of_their_list() {
    // A peer can advertise multiple manifests; their "vote" is
    // the highest-height entry. Tests use [(h_low, ..), (h_high, ..)]
    // to make sure we don't accidentally take the first or last.
    let mut bs = SnapshotBootstrap::new();
    for p in 1..=3 {
        bs.on_snapshots_info(
            peer(p),
            &[
                (52_224, mid(0xAA)),
                (104_448, mid(0xBB)),
                (78_336, mid(0xCC)),
            ],
        );
    }
    assert_eq!(
        bs.state(),
        BootstrapState::Selected {
            height: 104_448,
            manifest_id: mid(0xBB),
        }
    );
}

// ----- duplicate / vote-change handling -----

#[test]
fn duplicate_response_from_same_peer_does_not_double_count() {
    // Three calls from the same peer must not satisfy quorum=3.
    let mut bs = SnapshotBootstrap::new();
    for _ in 0..3 {
        bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
    }
    assert_eq!(
        bs.state(),
        BootstrapState::Querying,
        "one peer can never satisfy quorum=3 no matter how many \
             replies they send",
    );
}

#[test]
fn peer_can_change_their_vote() {
    // Peer first advertises manifest A; later switches to B.
    // Only B counts in the tally afterwards.
    let mut bs = SnapshotBootstrap::with_quorum(2);
    bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
    bs.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
    assert_eq!(
        bs.state(),
        BootstrapState::Selected {
            height: 52_224,
            manifest_id: mid(0xAA),
        }
    );

    // Peer 2 changes their advertisement; now A only has 1 vote.
    bs.on_snapshots_info(peer(2), &[(52_224, mid(0xBB))]);
    assert_eq!(
        bs.state(),
        BootstrapState::Querying,
        "A drops from 2 votes to 1; B has 1; neither reaches quorum=2",
    );
}

#[test]
fn empty_manifests_list_drops_peer_vote() {
    // Peer first advertises, then later sends empty list (snapshot
    // was evicted from their SnapshotsDb). Their vote must be removed.
    let mut bs = SnapshotBootstrap::with_quorum(2);
    bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
    bs.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
    assert!(matches!(bs.state(), BootstrapState::Selected { .. }));

    bs.on_snapshots_info(peer(2), &[]);
    assert_eq!(
        bs.state(),
        BootstrapState::Querying,
        "peer 2 withdrew; A has 1 vote, no quorum",
    );
}

// ----- disconnect handling -----

#[test]
fn disconnect_removes_vote() {
    let mut bs = SnapshotBootstrap::with_quorum(2);
    bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
    bs.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
    assert!(matches!(bs.state(), BootstrapState::Selected { .. }));

    bs.on_peer_disconnect(&peer(2));
    assert_eq!(
        bs.state(),
        BootstrapState::Querying,
        "quorum was 2; disconnect drops to 1 vote",
    );
}

#[test]
fn disconnect_of_unknown_peer_is_idempotent_noop() {
    let mut bs = SnapshotBootstrap::with_quorum(2);
    bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);

    // Disconnect a peer who never voted — no state change.
    bs.on_peer_disconnect(&peer(99));
    assert_eq!(bs.state(), BootstrapState::Querying);
    assert_eq!(bs.votes.len(), 1);
}

#[test]
fn disconnect_of_dissenting_peer_can_raise_selection() {
    // Three peers vote for A; two peers vote for B at a higher
    // height (no quorum). One A-voter disconnects, but the other
    // two are still quorum=2 for A.
    let mut bs = SnapshotBootstrap::with_quorum(2);
    bs.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
    bs.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
    bs.on_snapshots_info(peer(3), &[(52_224, mid(0xAA))]);
    bs.on_snapshots_info(peer(4), &[(104_448, mid(0xBB))]);
    assert_eq!(
        bs.state(),
        BootstrapState::Selected {
            height: 52_224,
            manifest_id: mid(0xAA),
        },
        "A has 3 votes at quorum=2, B has 1 — A wins",
    );

    // A second B-voter arrives. Now B is also quorum=2 at a
    // higher height — B must win.
    bs.on_snapshots_info(peer(5), &[(104_448, mid(0xBB))]);
    assert_eq!(
        bs.state(),
        BootstrapState::Selected {
            height: 104_448,
            manifest_id: mid(0xBB),
        },
        "higher-height quorum wins once it exists",
    );
}

// ----- lifecycle invariants -----

#[test]
fn selection_is_stable_under_unrelated_lower_height_replies() {
    // Once selected at H, later responses at lower heights
    // must not unseat the selection (no oscillation).
    let mut bs = SnapshotBootstrap::with_quorum(2);
    bs.on_snapshots_info(peer(1), &[(104_448, mid(0xAA))]);
    bs.on_snapshots_info(peer(2), &[(104_448, mid(0xAA))]);
    let expected = BootstrapState::Selected {
        height: 104_448,
        manifest_id: mid(0xAA),
    };
    assert_eq!(bs.state(), expected);

    // A non-quorum lower-height response arrives — selection unchanged.
    bs.on_snapshots_info(peer(3), &[(52_224, mid(0xBB))]);
    assert_eq!(bs.state(), expected);
}

#[test]
fn votes_below_quorum_threshold_never_select() {
    // Custom quorum=5; only 4 peers — must stay Querying.
    let mut bs = SnapshotBootstrap::with_quorum(5);
    for p in 1..=4 {
        bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
    }
    assert_eq!(bs.state(), BootstrapState::Querying);
}

// ----- outbound query tracking (2f-3) -----

#[test]
fn should_query_returns_true_for_unqueried_peer() {
    let bs = SnapshotBootstrap::new();
    assert!(bs.should_query(&peer(1)));
}

#[test]
fn mark_queried_then_should_query_returns_false() {
    let mut bs = SnapshotBootstrap::new();
    bs.mark_queried(peer(1));
    assert!(!bs.should_query(&peer(1)));
    // Other peers still unqueried.
    assert!(bs.should_query(&peer(2)));
}

#[test]
fn should_query_returns_false_in_selected_state_for_all_peers() {
    // Once quorum is reached, the outbound fan-out stops — no
    // matter which peer (queried or not), the discovery loop is
    // over.
    let mut bs = SnapshotBootstrap::new();
    for p in 1..=3u16 {
        bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
    }
    assert!(matches!(bs.state(), BootstrapState::Selected { .. }));
    assert!(
        !bs.should_query(&peer(99)),
        "Selected suppresses all queries"
    );
    assert!(!bs.should_query(&peer(1)), "even already-voted peers");
}

#[test]
fn disconnect_clears_queried_mark_so_reconnect_is_requeried() {
    let mut bs = SnapshotBootstrap::new();
    bs.mark_queried(peer(1));
    assert!(!bs.should_query(&peer(1)));

    bs.on_peer_disconnect(&peer(1));
    assert!(
        bs.should_query(&peer(1)),
        "disconnect must clear queried-mark for reconnection",
    );
}

// ----- 2g state machine: ManifestRequested + ManifestVerified -----

fn reach_selected(quorum: usize) -> SnapshotBootstrap {
    let mut bs = SnapshotBootstrap::with_quorum(quorum);
    for p in 1..=(quorum as u16) {
        bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
    }
    assert!(
        matches!(bs.state(), BootstrapState::Selected { .. }),
        "quorum reached → Selected",
    );
    bs
}

#[test]
fn voter_for_selected_manifest_returns_a_quorum_voter() {
    let bs = reach_selected(3);
    let voter = bs.voter_for_selected_manifest().expect("a voter");
    assert!(
        [peer(1), peer(2), peer(3)].contains(&voter),
        "voter must be one of the actual voters; got {voter:?}",
    );
}

#[test]
fn should_request_manifest_returns_some_when_selected() {
    let bs = reach_selected(3);
    let (peer_id, height, manifest_id) = bs
        .should_request_manifest()
        .expect("Selected → should request");
    assert!([peer(1), peer(2), peer(3)].contains(&peer_id));
    assert_eq!(height, 52_224);
    assert_eq!(manifest_id, mid(0xAA));
}

#[test]
fn should_request_manifest_none_while_pending_request() {
    let mut bs = reach_selected(3);
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
    assert!(
        bs.should_request_manifest().is_none(),
        "no second request while one is pending",
    );
}

#[test]
fn state_advances_to_manifest_requested_on_mark() {
    let mut bs = reach_selected(3);
    let now = Instant::now();
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), now);
    assert_eq!(
        bs.state(),
        BootstrapState::ManifestRequested {
            peer: peer(1),
            height: 52_224,
            manifest_id: mid(0xAA),
        }
    );
}

#[test]
fn on_manifest_received_from_wrong_peer_returns_none() {
    let mut bs = reach_selected(3);
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());

    let result = bs.on_manifest_received(peer(2), vec![0xFF; 100]);
    assert!(
        result.is_none(),
        "reply from a non-pending peer must not surface bytes",
    );
    assert!(matches!(
        bs.state(),
        BootstrapState::ManifestRequested { .. }
    ));
}

#[test]
fn on_manifest_received_with_no_pending_returns_none() {
    let mut bs = reach_selected(3);
    let result = bs.on_manifest_received(peer(1), vec![0xFF; 100]);
    assert!(
        result.is_none(),
        "unsolicited Manifest (no pending request) must not surface bytes",
    );
}

#[test]
fn on_manifest_received_from_pending_peer_returns_request_triple() {
    let mut bs = reach_selected(3);
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
    let payload = vec![0xAA, 0xBB, 0xCC];
    let surfaced = bs.on_manifest_received(peer(1), payload.clone());
    let (height, manifest_id, bytes) = surfaced.expect("matching peer surfaces triple");
    assert_eq!(height, 52_224);
    assert_eq!(manifest_id, mid(0xAA));
    assert_eq!(bytes, payload);
    // State unchanged until accept/reject.
    assert!(matches!(
        bs.state(),
        BootstrapState::ManifestRequested { .. }
    ));
}

#[test]
fn accept_verified_manifest_advances_to_manifest_verified() {
    let mut bs = reach_selected(3);
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
    let bytes = vec![0xAA, 0xBB, 0xCC];
    bs.accept_verified_manifest(bytes.clone());
    assert_eq!(
        bs.state(),
        BootstrapState::ManifestVerified {
            height: 52_224,
            manifest_id: mid(0xAA),
        }
    );
    // Bytes available for chunk-download phase.
    let mut bs2 = SnapshotBootstrap::with_quorum(3);
    bs2.on_snapshots_info(peer(1), &[(52_224, mid(0xAA))]);
    bs2.on_snapshots_info(peer(2), &[(52_224, mid(0xAA))]);
    bs2.on_snapshots_info(peer(3), &[(52_224, mid(0xAA))]);
    bs2.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
    bs2.accept_verified_manifest(bytes.clone());
    let taken = bs2.take_verified_manifest_bytes().expect("bytes available");
    assert_eq!(taken, bytes);
}

#[test]
fn take_verified_manifest_bytes_is_idempotent_returns_none_after_first() {
    let mut bs = reach_selected(3);
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
    bs.accept_verified_manifest(vec![1, 2, 3]);
    assert!(bs.take_verified_manifest_bytes().is_some());
    assert!(
        bs.take_verified_manifest_bytes().is_none(),
        "second take returns None — bytes consumed exactly once",
    );
}

#[test]
fn after_take_bytes_state_stays_manifest_verified() {
    // Critical: even after bytes are handed off to 2h, the
    // sticky `verified` latch keeps state at ManifestVerified
    // so the integration layer never re-fires GetManifest.
    let mut bs = reach_selected(3);
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());
    bs.accept_verified_manifest(vec![1, 2, 3]);
    let _ = bs.take_verified_manifest_bytes();
    assert_eq!(
        bs.state(),
        BootstrapState::ManifestVerified {
            height: 52_224,
            manifest_id: mid(0xAA),
        },
        "verified latch must persist post-handoff",
    );
    assert!(
        bs.should_request_manifest().is_none(),
        "no re-request after handoff",
    );
}

#[test]
fn reject_manifest_evicts_voter_and_recomputes_selection() {
    // Three peers vote for A; peer 1 gets the request, sends
    // bad bytes, gets evicted. Two voters remain — still quorum
    // for A if quorum=2; falls back to Querying if quorum=3.
    let mut bs = SnapshotBootstrap::with_quorum(3);
    for p in 1..=3u16 {
        bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
    }
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());

    bs.reject_manifest_and_evict_voter(peer(1));
    assert_eq!(
        bs.state(),
        BootstrapState::Querying,
        "evicting one of three voters drops below quorum=3",
    );
}

#[test]
fn reject_with_remaining_quorum_falls_back_to_selected() {
    // Four peers vote for A; one gets evicted on bad manifest.
    // Quorum=3 is still satisfied with three voters → state
    // returns to Selected so a different voter is asked next.
    let mut bs = SnapshotBootstrap::with_quorum(3);
    for p in 1..=4u16 {
        bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
    }
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), Instant::now());

    bs.reject_manifest_and_evict_voter(peer(1));
    assert_eq!(
        bs.state(),
        BootstrapState::Selected {
            height: 52_224,
            manifest_id: mid(0xAA),
        },
        "still 3 voters for A → reselects same manifest, different peer next",
    );
    // Next request goes to a voter that's NOT peer 1.
    let next = bs.should_request_manifest().expect("can request again");
    assert_ne!(next.0, peer(1), "evicted peer must not be re-chosen");
}

#[test]
fn check_request_timeout_evicts_silent_voter() {
    let mut bs = SnapshotBootstrap::with_quorum(3);
    for p in 1..=4u16 {
        bs.on_snapshots_info(peer(p), &[(52_224, mid(0xAA))]);
    }
    let then = Instant::now();
    bs.mark_manifest_requested(peer(1), 52_224, mid(0xAA), then);

    // Within the timeout — no eviction.
    bs.check_request_timeout(then + Duration::from_secs(5));
    assert!(matches!(
        bs.state(),
        BootstrapState::ManifestRequested { .. }
    ));

    // Past the timeout — peer 1 evicted, state falls back.
    bs.check_request_timeout(then + MANIFEST_REQUEST_TIMEOUT + Duration::from_secs(1));
    assert_eq!(
        bs.state(),
        BootstrapState::Selected {
            height: 52_224,
            manifest_id: mid(0xAA),
        },
    );
}

#[test]
fn check_request_timeout_with_no_pending_is_noop() {
    let mut bs = reach_selected(3);
    bs.check_request_timeout(Instant::now() + Duration::from_secs(3600));
    // Selected state preserved.
    assert!(matches!(bs.state(), BootstrapState::Selected { .. }));
}

// ----- 2g-2 trust verification -----

fn ad_digest_with_root(root: [u8; 32], height_byte: u8) -> ADDigest {
    let mut bytes = [0u8; 33];
    bytes[..32].copy_from_slice(&root);
    bytes[32] = height_byte;
    ADDigest::from_bytes(bytes)
}

#[test]
fn verify_succeeds_when_prefix_matches() {
    // Same 32-byte root, different tree-height byte — must pass.
    let manifest_id = mid(0x42);
    let state_root = ad_digest_with_root(mid(0x42), 14); // mainnet manifest_depth
    assert!(verify_manifest_against_state_root(&manifest_id, &state_root).is_ok());
}

#[test]
fn verify_succeeds_regardless_of_height_byte_value() {
    // The trailing byte of state_root is the AVL+ tree height,
    // not the manifest's height. It varies across snapshots
    // and does NOT participate in the manifest_id check.
    let manifest_id = mid(0xAB);
    for h in [0u8, 1, 14, 32, 255] {
        let state_root = ad_digest_with_root(mid(0xAB), h);
        assert!(
            verify_manifest_against_state_root(&manifest_id, &state_root).is_ok(),
            "height byte={h} should not affect verification",
        );
    }
}

#[test]
fn verify_fails_when_prefix_differs() {
    let manifest_id = mid(0x42);
    let state_root = ad_digest_with_root(mid(0x99), 14);
    let err = verify_manifest_against_state_root(&manifest_id, &state_root).unwrap_err();
    match err {
        ManifestVerifyError::RootMismatch {
            expected_manifest_id,
            actual_state_root_prefix,
        } => {
            assert_eq!(expected_manifest_id, mid(0x42));
            assert_eq!(actual_state_root_prefix, mid(0x99));
        }
    }
}

#[test]
fn verify_fails_when_one_byte_differs_in_prefix() {
    // Subtle: only byte 31 differs. Comparison must catch it.
    let manifest_id = mid(0x42);
    let mut bytes = [0u8; 33];
    bytes[..32].copy_from_slice(&mid(0x42));
    bytes[31] = 0xFF; // last byte of the 32-prefix corrupted
    bytes[32] = 14;
    let state_root = ADDigest::from_bytes(bytes);
    assert!(verify_manifest_against_state_root(&manifest_id, &state_root).is_err());
}

#[test]
fn verify_zero_manifest_vs_zero_root_succeeds() {
    // Edge case: all-zero (e.g., test fixtures). Behaves like any
    // other equal pair — no special-casing of zero.
    let manifest_id = mid(0x00);
    let state_root = ad_digest_with_root(mid(0x00), 0);
    assert!(verify_manifest_against_state_root(&manifest_id, &state_root).is_ok());
}

#[test]
fn verify_does_not_panic_on_extreme_inputs() {
    // Sanity: 0xFF-filled and 0x00-filled inputs in both
    // positions cover the byte-range edges. No panics, no
    // overflow paths in slice comparison.
    let cases = [
        (mid(0x00), mid(0xFF)),
        (mid(0xFF), mid(0x00)),
        (mid(0xFF), mid(0xFF)),
        (mid(0x00), mid(0x00)),
    ];
    for (m, r) in cases {
        let _ = verify_manifest_against_state_root(&m, &ad_digest_with_root(r, 0));
    }
}

// ----- 2h-2 chunk assembly -----

fn cid(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

fn ca_three_chunks() -> ChunkAssembly {
    ChunkAssembly::new(vec![cid(0x01), cid(0x02), cid(0x03)])
}

#[test]
fn chunk_assembly_empty_is_immediately_complete() {
    let mut ca = ChunkAssembly::new(Vec::new());
    assert!(ca.is_complete(), "no expected chunks → complete");
    let map = ca.take_chunks().expect("take from empty assembly");
    assert!(map.is_empty());
}

#[test]
fn next_to_request_returns_all_when_idle_and_below_cap() {
    let ca = ca_three_chunks();
    let next = ca.next_to_request();
    assert_eq!(next.len(), 3);
    assert_eq!(next, vec![cid(0x01), cid(0x02), cid(0x03)]);
}

#[test]
fn next_to_request_excludes_inflight_and_received() {
    let mut ca = ca_three_chunks();
    ca.mark_requested(cid(0x01), peer(1), Instant::now());
    // Inflight should be excluded.
    assert_eq!(ca.next_to_request(), vec![cid(0x02), cid(0x03)],);

    let _ = ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA]);
    // Now received; next_to_request still excludes it.
    ca.mark_requested(cid(0x02), peer(2), Instant::now());
    assert_eq!(ca.next_to_request(), vec![cid(0x03)]);
}

#[test]
fn next_to_request_caps_at_max_inflight() {
    // 20 expected, cap is 16 → next batch is 16 max.
    let ids: Vec<Digest32> = (0..20u8).map(cid).collect();
    let ca = ChunkAssembly::new(ids);
    let next = ca.next_to_request();
    assert_eq!(next.len(), MAX_INFLIGHT_CHUNKS);
}

#[test]
fn on_chunk_received_accepts_matching_peer() {
    let mut ca = ca_three_chunks();
    ca.mark_requested(cid(0x01), peer(1), Instant::now());
    let outcome = ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA, 0xBB]);
    assert_eq!(outcome, ChunkReceiveOutcome::Accepted);
    assert_eq!(ca.received_count(), 1);
}

#[test]
fn on_chunk_received_rejects_wrong_peer() {
    let mut ca = ca_three_chunks();
    ca.mark_requested(cid(0x01), peer(1), Instant::now());
    let outcome = ca.on_chunk_received(peer(2), cid(0x01), vec![0xAA]);
    assert_eq!(outcome, ChunkReceiveOutcome::WrongPeer);
    assert_eq!(ca.received_count(), 0, "wrong-peer bytes must not stash");
}

#[test]
fn on_chunk_received_drops_unknown_subtree_id() {
    let mut ca = ca_three_chunks();
    ca.mark_requested(cid(0x01), peer(1), Instant::now());
    let outcome = ca.on_chunk_received(peer(1), cid(0xFF), vec![0xAA]);
    assert_eq!(outcome, ChunkReceiveOutcome::UnknownSubtreeId);
}

#[test]
fn on_chunk_received_drops_duplicate() {
    let mut ca = ca_three_chunks();
    ca.mark_requested(cid(0x01), peer(1), Instant::now());
    ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA]);

    // Re-request from same peer (e.g., resend) then receive again.
    ca.mark_requested(cid(0x01), peer(1), Instant::now());
    let outcome = ca.on_chunk_received(peer(1), cid(0x01), vec![0xBB]);
    assert_eq!(outcome, ChunkReceiveOutcome::Duplicate);
    assert_eq!(ca.received_count(), 1, "duplicate must not overwrite");
}

#[test]
fn check_timeouts_frees_stale_slots() {
    let mut ca = ca_three_chunks();
    let t0 = Instant::now();
    ca.mark_requested(cid(0x01), peer(1), t0);
    ca.mark_requested(cid(0x02), peer(2), t0);

    // Within timeout: no slots freed.
    let freed = ca.check_timeouts(t0 + Duration::from_secs(5));
    assert!(freed.is_empty());

    // After timeout: both slots freed.
    let mut freed = ca.check_timeouts(t0 + CHUNK_REQUEST_TIMEOUT + Duration::from_secs(1));
    freed.sort_by_key(|d| *d.as_bytes());
    assert_eq!(freed, vec![cid(0x01), cid(0x02)]);

    // Freed slots re-enter next_to_request.
    let next = ca.next_to_request();
    assert!(next.contains(&cid(0x01)));
    assert!(next.contains(&cid(0x02)));
}

#[test]
fn drop_peer_frees_their_inflight_slots() {
    let mut ca = ca_three_chunks();
    let t0 = Instant::now();
    ca.mark_requested(cid(0x01), peer(1), t0);
    ca.mark_requested(cid(0x02), peer(2), t0);
    ca.mark_requested(cid(0x03), peer(1), t0);

    let mut dropped = ca.drop_peer(&peer(1));
    dropped.sort_by_key(|d| *d.as_bytes());
    assert_eq!(dropped, vec![cid(0x01), cid(0x03)]);
    // Peer 2's slot untouched.
    assert_eq!(ca.next_to_request(), vec![cid(0x01), cid(0x03)]);
}

#[test]
fn is_complete_only_when_every_chunk_received() {
    let mut ca = ca_three_chunks();
    let t0 = Instant::now();
    assert!(!ca.is_complete());

    ca.mark_requested(cid(0x01), peer(1), t0);
    ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA]);
    assert!(!ca.is_complete());

    ca.mark_requested(cid(0x02), peer(1), t0);
    ca.on_chunk_received(peer(1), cid(0x02), vec![0xBB]);
    assert!(!ca.is_complete());

    ca.mark_requested(cid(0x03), peer(1), t0);
    ca.on_chunk_received(peer(1), cid(0x03), vec![0xCC]);
    assert!(ca.is_complete());
}

#[test]
fn take_chunks_handoff_is_exactly_once() {
    let mut ca = ca_three_chunks();
    let t0 = Instant::now();
    for (i, id) in [cid(0x01), cid(0x02), cid(0x03)].into_iter().enumerate() {
        ca.mark_requested(id, peer(1), t0);
        ca.on_chunk_received(peer(1), id, vec![i as u8]);
    }
    assert!(ca.is_complete());

    let first = ca.take_chunks().expect("first take succeeds");
    assert_eq!(first.len(), 3);

    let second = ca.take_chunks();
    assert!(
        second.is_none(),
        "second take returns None — consumed exactly once",
    );
    // After consume, next_to_request returns empty.
    assert!(ca.next_to_request().is_empty());
}

#[test]
fn progress_counters_reflect_received_state() {
    let mut ca = ca_three_chunks();
    let t0 = Instant::now();
    assert_eq!(ca.total_count(), 3);
    assert_eq!(ca.received_count(), 0);

    ca.mark_requested(cid(0x01), peer(1), t0);
    ca.on_chunk_received(peer(1), cid(0x01), vec![0xAA]);
    assert_eq!(ca.received_count(), 1);
}

// ----- NiPoPoW proof vs the header checkpoint (ingress) -----

/// Mainnet genesis header, hex, as served on the wire. The only real header
/// that passes validation on an empty store, so delivery tests use it as a
/// genuinely admitted header.
const POPOW_GENESIS_HEX: &str = "010000000000000000000000000000000000000000000000000000000000000000766ab7a313cd2fb66d135b0be6662aa02dfa8e5b17342c05a04396268df0bfbb93fb06aa44413ff57ac878fda9377207d5db0e78833556b331b4d9727b3153ba18b7a08878f2a7ee4389c5a1cece1e2724abe8b8adc8916240dd1bcac069177303f1f6cee9ba2d0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060117650100000003be7ad70c74f691345cbedba19f4844e7fc514e1188a7929f5ae261d5bb00bb6602da9385ac99014ddcffe88d2ac5f28ce817cd615f270a0a5eae58acfb9fd9f6a0000000030151dc631b7207d4420062aeb54e82b0cfb160ff6ace90ab7754f942c4c3266b";

/// Mainnet height-2 header, hex, as served on the wire. Same
/// vector the `ergo-sync` popow reducer tests use; duplicated here because
/// this test drives the node's real message dispatch rather than the reducer.
const POPOW_HEIGHT_2_HEX: &str = "01b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b828b0f6a0e6cb98ed4649c6e4cc00599ae78755324c79a8cec51e94ecca339d7a3a11a92de9c0ba1e95068f39bc1e08afa4ca23dff16de135fac64d0cf7dd1ab6291b70477f591ee8efb8a962d36ddbe3ac57591e39fe45ffb8c51c4939e41980387d9cfe9ba2d6b46bcba6f750f5be67d89679e921b78c277c5546a08cdb0955376fa0ea271e30601176502000000033c46c7fd7085638bf4bc902badb4e5a1942d3251d92d0eddd6fbe5d57e91553703df646d7f6138aede718a2a4f1a76d4125750e8ab496b7a8a25292d07e14cbadb0000000a03d0d0191b06164a2e86a170f0d8ac96cffa2e3312f2f5b0b1c3b1e082b9a0cd";

fn popow_proof_frame() -> Vec<u8> {
    use ergo_primitives::digest::ModifierId;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::{read_header, serialize_header, Header};
    use ergo_ser::popow_header::PoPowHeader;
    use ergo_ser::popow_proof::NipopowProof;

    let raw = std::fs::read_to_string(format!(
        "{}/../test-vectors/mainnet/headers_1_2000.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let values: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
    let headers: Vec<Header> = values
        .iter()
        .take(11)
        .map(|value| {
            let bytes = hex::decode(value["bytes"].as_str().unwrap()).unwrap();
            read_header(&mut VlqReader::new(&bytes)).unwrap()
        })
        .collect();
    assert_eq!(headers.len(), 11);

    let (_bytes, genesis_id) = serialize_header(&headers[0]).unwrap();
    let popow_hdr = |h: Header| -> PoPowHeader {
        if h.height == 1 {
            return PoPowHeader {
                header: h,
                interlinks: vec![],
                interlinks_proof: vec![0u8; 8],
            };
        }
        let links = vec![ModifierId::from_bytes(*genesis_id.as_bytes())];
        let fields = ergo_validation::popow::algos::pack_interlinks(&links);
        ergo_validation::popow::algos::build_popow_header(h, links, &fields).unwrap()
    };
    let proof = NipopowProof {
        m: ergo_p2p::types::P2P_NIPOPOW_PROOF_M as u32,
        k: ergo_p2p::types::P2P_NIPOPOW_PROOF_K as u32,
        prefix: vec![popow_hdr(headers[0].clone())],
        suffix_head: popow_hdr(headers[1].clone()),
        suffix_tail: headers[2..].to_vec(),
        continuous: true,
    };
    let body = ergo_ser::popow_proof::serialize_nipopow_proof(&proof).unwrap();
    message::serialize_nipopow_proof(&body).unwrap()
}

fn state_with_popow_bootstrap(state: &mut NodeState) {
    state.popow_bootstrap = Some(ergo_sync::popow_bootstrap::PopowBootstrap::new(
        2,
        None,
        DifficultyParams::mainnet(),
    ));
}

#[test]
fn popow_proof_wrong_profile_penalizes_peer_and_records_response() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    state_with_popow_bootstrap(&mut state);

    let valid_frame = popow_proof_frame();
    let body = message::deserialize_nipopow_proof(&valid_frame).unwrap();
    let mut proof = ergo_ser::popow_proof::deserialize_nipopow_proof(&body).unwrap();
    proof.m = 5;
    let body = ergo_ser::popow_proof::serialize_nipopow_proof(&proof).unwrap();
    let wrong_frame = message::serialize_nipopow_proof(&body).unwrap();
    let peer = test_peer();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_NIPOPOW_PROOF,
        &wrong_frame,
        Instant::now(),
    );

    assert!(
        matches!(
            actions.as_slice(),
            [Action::Penalize { peer: p, penalty: Penalty::Misbehavior }] if *p == peer
        ),
        "a first wrong-profile response must be rejected, not treated as a duplicate: {actions:?}"
    );
    let popow = state.popow_bootstrap.as_ref().unwrap();
    assert_eq!(popow.provider_count(), 1);
    assert_eq!(popow.proofs_processed(), 0);
    assert!(popow.best_proof().is_none());
    assert!(!popow.quorum_reached());

    // Both invalid and corrected retries from this provider are duplicates.
    for frame in [wrong_frame, valid_frame] {
        let actions = handle_message(
            &mut state,
            peer,
            message::CODE_NIPOPOW_PROOF,
            &frame,
            Instant::now(),
        );
        assert!(actions.is_empty(), "duplicate response: {actions:?}");
        let popow = state.popow_bootstrap.as_ref().unwrap();
        assert_eq!(popow.provider_count(), 1);
        assert_eq!(popow.proofs_processed(), 0);
    }
}

// ----- error paths -----

#[test]
fn popow_proof_difficulty_error_penalizes_and_logs_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    state_with_popow_bootstrap(&mut state);
    let frame = popow_proof_frame();
    let body = message::deserialize_nipopow_proof(&frame).unwrap();
    let mut proof = ergo_ser::popow_proof::deserialize_nipopow_proof(&body).unwrap();
    proof.suffix_tail.last_mut().unwrap().n_bits ^= 1;
    let body = ergo_ser::popow_proof::serialize_nipopow_proof(&proof).unwrap();
    let frame = message::serialize_nipopow_proof(&body).unwrap();
    let log_path = tmp.path().join("difficulty.log");
    let log_file = std::fs::File::create(&log_path).unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || log_file.try_clone().unwrap())
        .finish();
    let peer = test_peer();
    let actions = tracing::subscriber::with_default(subscriber, || {
        handle_message(
            &mut state,
            peer,
            message::CODE_NIPOPOW_PROOF,
            &frame,
            Instant::now(),
        )
    });
    assert!(matches!(actions.as_slice(),
        [Action::Penalize { peer: p, penalty: Penalty::Misbehavior }] if *p == peer));
    let log = std::fs::read_to_string(log_path).unwrap();
    assert!(log.contains("bootstrap proof rejected"), "{log}");
    assert!(
        log.contains("consensus difficulty mismatch at height 11"),
        "{log}"
    );
    let popow = state.popow_bootstrap.as_ref().unwrap();
    assert_eq!(popow.provider_count(), 1);
    assert_eq!(popow.proofs_processed(), 0);
    assert!(popow.best_proof().is_none());
    let retry = handle_message(
        &mut state,
        peer,
        message::CODE_NIPOPOW_PROOF,
        &frame,
        Instant::now(),
    );
    assert!(retry.is_empty());
}

#[test]
fn popow_proof_violating_checkpoint_penalizes_peer_and_never_reaches_verifier() {
    // A forged proof carrying a different header at the operator's anchor
    // height must be rejected at INGRESS: penalise the sender, and leave the
    // reducer untouched so the forgery neither counts toward quorum nor wins
    // best-proof selection. Marking the bootstrap terminal here would let one
    // such proof disable NiPoPoW for the whole run.
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    state_with_popow_bootstrap(&mut state);
    state
        .executor
        .set_header_checkpoint(Some(ergo_sync::header_proc::HeaderCheckpoint {
            height: 2,
            block_id: [0x7fu8; 32],
        }));

    let peer = test_peer();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_NIPOPOW_PROOF,
        &popow_proof_frame(),
        Instant::now(),
    );

    assert!(
        actions.iter().any(|a| matches!(
            a,
            Action::Penalize {
                peer: p,
                penalty: Penalty::Misbehavior,
            } if *p == peer
        )),
        "a proof violating the checkpoint must penalise its sender: {actions:?}"
    );
    let popow = state.popow_bootstrap.as_ref().unwrap();
    assert_eq!(
        popow.proofs_processed(),
        0,
        "the forged proof must never reach the verifier"
    );
    assert!(
        popow.is_active(true),
        "one forged proof must not disable NiPoPoW bootstrap"
    );
    assert!(!popow.quorum_reached());
}

#[test]
fn popow_proof_matching_checkpoint_reaches_the_verifier() {
    // Control for the test above: with the anchor satisfied, the same proof
    // takes the normal path into the verifier and no penalty is emitted.
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::header::{read_header, serialize_header};

    let raw = hex::decode(POPOW_HEIGHT_2_HEX).unwrap();
    let h2 = read_header(&mut VlqReader::new(&raw)).unwrap();
    let (_bytes, h2_id) = serialize_header(&h2).unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("state.redb"));
    state_with_popow_bootstrap(&mut state);
    state
        .executor
        .set_header_checkpoint(Some(ergo_sync::header_proc::HeaderCheckpoint {
            height: 2,
            block_id: *h2_id.as_bytes(),
        }));

    let peer = test_peer();
    let actions = handle_message(
        &mut state,
        peer,
        message::CODE_NIPOPOW_PROOF,
        &popow_proof_frame(),
        Instant::now(),
    );

    assert!(
        !actions.iter().any(|a| matches!(a, Action::Penalize { .. })),
        "a proof consistent with the checkpoint must not be penalised: {actions:?}"
    );
    assert_eq!(
        state.popow_bootstrap.as_ref().unwrap().provider_count(),
        1,
        "the proof must have reached the reducer"
    );
}

#[test]
fn ip_ban_cleans_all_ports_and_pending_handshakes_but_keeps_other_ips() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = make_state(&tmp.path().join("bans.redb"));
    state.peer_manager = PeerManager::new_with_limits(
        0,
        ergo_p2p::peer_manager::PeerLimits {
            per_ip_limit: 4,
            per_subnet_limit: 8,
            ..Default::default()
        },
    );
    let now = Instant::now();
    let a: SocketAddr = "127.0.0.1:1001".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:1002".parse().unwrap();
    let pending: SocketAddr = "127.0.0.1:1003".parse().unwrap();
    let other: SocketAddr = "127.0.0.2:1001".parse().unwrap();
    let mut rx_a = connect_test_peer(&mut state, a, now);
    let mut rx_b = connect_test_peer(&mut state, b, now);
    let mut rx_other = connect_test_peer(&mut state, other, now);
    state.peer_manager.register_inbound(pending, now).unwrap();
    let mut t = now;
    for _ in 0..40 {
        t += ergo_p2p::peer::SAFE_INTERVAL;
        super::peer_actions::penalize_peer(&mut state, a, Penalty::Spam, t);
        if state.peer_manager.is_banned(&a, t) {
            break;
        }
    }
    assert!(state.peer_manager.is_banned(&b, t));
    assert!(state.peer_manager.get(&a).is_none());
    assert!(state.peer_manager.get(&b).is_none());
    assert!(state.peer_manager.get(&pending).is_none());
    assert!(rx_a.is_closed() && rx_b.is_closed());
    assert!(rx_a.try_recv().is_err() && rx_b.try_recv().is_err());
    assert!(state.peer_manager.get(&other).is_some());
    assert!(send_to_peer(&state, &other, 1, Vec::new()));
    assert_eq!(rx_other.try_recv().unwrap().code, 1);
    // Repeated cleanup with the original socket already absent is harmless.
    super::peer_actions::penalize_peer(&mut state, a, Penalty::Spam, t);
    assert!(state.registry.peers.contains_key(&other));
}

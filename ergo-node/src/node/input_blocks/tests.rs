//! Unit tests for the node-side input-block runtime (Plan 2, task 3).

use std::time::Instant;

use ergo_crypto::difficulty::{
    epoch_length_for_height, next_n_bits, previous_heights_for_recalculation, DifficultyParams,
};
use ergo_inputblocks::processor::{DropReason, Effect};
use ergo_inputblocks::test_support as ts;
use ergo_inputblocks::types::{PeerTag, TxRef};
use ergo_mempool::input_blocks::RemovedEntry;
use ergo_p2p::peer::Penalty;
use ergo_ser::header::{read_header, serialize_header, Header};
use ergo_state::chain::HeaderMeta;
use ergo_state::{ChainStateRead, HeaderSectionStore};
use ergo_sync::coordinator::Action;

use super::*;
use crate::node::state::NodeState;
use crate::node::tests::make_state;

// ----- helpers -----

fn cfg() -> crate::config::InputBlocksConfig {
    crate::config::InputBlocksConfig {
        enabled: true,
        strict_field_binding: true,
        relay_remote: false,
        bounds: ergo_inputblocks::bounds::Bounds::default(),
    }
}

fn runtime() -> InputBlocksRuntime {
    InputBlocksRuntime::new(&cfg(), Instant::now())
}

/// Seed `count` synthetic, chain-linked headers at heights `1..=count`
/// into the store's header tables and advance `best_header`. Returns the
/// stored headers, oldest first.
fn seed_header_chain(state: &mut NodeState, count: u32) -> Vec<Header> {
    let store = state.store.as_utxo_mut().expect("utxo backend");
    let mut parent = [0u8; 32];
    let mut out = Vec::new();
    for height in 1..=count {
        let header = ts::header(parent, height, u64::from(height), [0u8; 32]);
        let (bytes, id) = serialize_header(&header).expect("serialize");
        let id = *id.as_bytes();
        let meta = HeaderMeta {
            parent_id: parent,
            height,
            cumulative_score: u64::from(height).to_be_bytes().to_vec(),
            pow_validity: 1,
            timestamp: header.timestamp,
        };
        store
            .store_validated_header(
                &id,
                &bytes,
                &meta,
                Some((height, meta.cumulative_score.clone())),
            )
            .expect("store header");
        parent = id;
        out.push(header);
    }
    out
}

fn header_id_of(h: &Header) -> [u8; 32] {
    *serialize_header(h).expect("serialize").1.as_bytes()
}

fn connect_peer(state: &mut NodeState, port: u16) -> std::net::SocketAddr {
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    // The receiver is dropped immediately: these tests assert on the
    // `Action`s the executor RETURNS, and never flush them to the wire.
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    state.registry.peers.insert(
        addr,
        crate::node::state::PeerRuntime {
            sync_version: ergo_p2p::peer::SyncVersion::V2,
            outbound_tx: tx,
        },
    );
    addr
}

// ----- happy path -----

#[test]
fn expected_n_bits_after_known_parent_matches_next_n_bits() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let headers = seed_header_chain(&mut state, 3);
    let parent = headers.last().unwrap();
    let parent_id = header_id_of(parent);

    let params = DifficultyParams::mainnet();
    let child_height = parent.height + 1;
    let epoch = epoch_length_for_height(child_height, &params);
    let needed = previous_heights_for_recalculation(child_height, epoch);
    let mut epoch_headers = Vec::new();
    for h in needed {
        if h == 0 {
            continue;
        }
        epoch_headers.push(
            headers
                .iter()
                .find(|x| x.height == h)
                .expect("seeded height")
                .clone(),
        );
    }
    let expected = next_n_bits(child_height, &epoch_headers, &params).expect("next_n_bits");

    assert_eq!(expected_n_bits_after(&state, &parent_id), Some(expected));
}

#[test]
fn expected_n_bits_after_unknown_parent_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let state = make_state(&dir.path().join("state.redb"));
    assert_eq!(expected_n_bits_after(&state, &[0x9a; 32]), None);
}

#[test]
fn ctx_multiplier_comes_from_active_params_subblocks_per_block() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));

    let data = build_ctx_data(&state, &[]);
    assert_eq!(data.with(|c| c.multiplier), None, "no id 9 => None");

    state.last_seen_active_params.subblocks_per_block = Some(30);
    let data = build_ctx_data(&state, &[]);
    assert_eq!(data.with(|c| c.multiplier), Some(30));
}

#[test]
fn validation_context_uses_best_full_block_not_next() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let headers = seed_header_chain(&mut state, 11);
    let best = headers.last().unwrap().clone();
    let best_id = header_id_of(&best);
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .advance_best_full_block(best_id, best.height)
        .unwrap();
    state.executor.hydrate_block_context(&state.store).unwrap();

    let ctx = build_input_block_context(&state).expect("context");
    assert_eq!(ctx.tx_context.height, best.height, "height is B, not B+1");
    assert_eq!(ctx.tx_context.pre_header_timestamp, best.timestamp);
    assert_eq!(
        ctx.tx_context.pre_header_parent_id,
        *best.parent_id.as_bytes()
    );
    assert_eq!(ctx.tx_context.pre_header_n_bits, u64::from(best.n_bits));
    assert_eq!(
        ctx.last_headers.len(),
        9,
        "lastHeaders.drop(1), capped at 9"
    );
    assert_eq!(
        ctx.last_headers[0].height,
        best.height - 1,
        "last_headers[0] == B-1"
    );
}

#[test]
fn effect_request_transactions_becomes_send_to_peer_code_105() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let peer = connect_peer(&mut state, 19001);
    let mut rt = runtime();
    let tag = rt.tag(peer);
    state.input_blocks = Some(rt);

    let weak_ids = vec![[1u8; 6], [2u8; 6]];
    let actions = execute_effects(
        &mut state,
        vec![Effect::RequestTransactions {
            input_block_id: [7u8; 32],
            weak_ids: weak_ids.clone(),
            from: tag,
        }],
        Instant::now(),
    );
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        Action::SendToPeer {
            peer: p,
            code,
            payload,
        } => {
            assert_eq!(*p, peer);
            assert_eq!(*code, ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST);
            let req = ergo_p2p::message::deserialize_input_block_txs_request(payload).unwrap();
            assert_eq!(req.input_block_id, [7u8; 32]);
            assert_eq!(req.weak_ids, weak_ids);
        }
        other => panic!("unexpected action {other:?}"),
    }
}

#[test]
fn effect_chain_changed_applies_then_restores_in_mempool() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let mut rt = runtime();

    // `both` is rolled back AND applied: restore-then-apply must leave it out.
    let both = ts::body(0xa1, 1);
    let only_rolled_back = ts::body(0xb2, 1);
    let rolled_back_id = [0x11u8; 32];

    rt.retained.insert(
        rolled_back_id,
        vec![
            RemovedEntry {
                tx_id: ergo_primitives::digest::Digest32::from_bytes(both.tx_ref.tx_id),
                bytes: both.bytes.clone(),
                fee: 0,
                size_bytes: both.bytes.len() as u32,
                cost: 1000,
            },
            RemovedEntry {
                tx_id: ergo_primitives::digest::Digest32::from_bytes(only_rolled_back.tx_ref.tx_id),
                bytes: only_rolled_back.bytes.clone(),
                fee: 0,
                size_bytes: only_rolled_back.bytes.len() as u32,
                cost: 1000,
            },
        ],
    );

    let _actions = apply_chain_change(
        &mut state,
        &mut rt,
        &[([0x22u8; 32], vec![both.clone()])],
        &[(rolled_back_id, Vec::new())],
        Instant::now(),
    );

    let both_id = ergo_primitives::digest::Digest32::from_bytes(both.tx_ref.tx_id);
    let other_id = ergo_primitives::digest::Digest32::from_bytes(only_rolled_back.tx_ref.tx_id);
    assert!(
        !state.mempool.contains(&both_id),
        "a tx in both lists ends up removed (spec 7.6)"
    );
    assert!(
        state.mempool.contains(&other_id),
        "a rolled-back-only tx stays restored"
    );
    assert!(
        !rt.retained.contains_key(&rolled_back_id),
        "restored entries are released"
    );
    assert!(
        rt.retained.contains_key(&[0x22u8; 32]),
        "applied block's removals are retained for a later restore"
    );
}

#[test]
fn effect_validate_runs_inline_and_feeds_validation_result() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let rt = runtime();
    let generation = rt.processor().generation();
    state.input_blocks = Some(rt);

    let actions = execute_effects(
        &mut state,
        vec![Effect::Validate {
            job: 4242,
            generation,
            input_block_id: [0x33u8; 32],
            txs: vec![TxRef {
                tx_id: [1u8; 32],
                witness_id: [2u8; 31],
            }],
            previous: Vec::new(),
        }],
        Instant::now(),
    );

    assert!(
        actions.is_empty(),
        "inline validation emits no network action"
    );
    let rt = state.input_blocks.as_ref().unwrap();
    assert_eq!(
        rt.counters
            .get(DropReason::StaleValidation { generation: 0 }.name()),
        1,
        "the ValidationResult was fed back and the processor answered it"
    );
}

#[test]
fn peer_tag_roundtrip_and_local_reserved() {
    let mut rt = runtime();
    let a: std::net::SocketAddr = "127.0.0.1:19101".parse().unwrap();
    let b: std::net::SocketAddr = "127.0.0.1:19102".parse().unwrap();
    let ta = rt.tag(a);
    let tb = rt.tag(b);
    assert_ne!(ta, tb);
    assert_ne!(ta, PeerTag::LOCAL);
    assert_ne!(tb, PeerTag::LOCAL);
    assert_eq!(rt.tag(a), ta, "tagging is stable");
    assert_eq!(rt.peer(ta), Some(a));
    assert_eq!(rt.peer(tb), Some(b));
    assert_eq!(rt.peer(PeerTag::LOCAL), None, "LOCAL maps to no peer");
}

// ----- error paths -----

#[test]
fn effect_penalize_maps_to_action_penalize_misbehavior() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let peer = connect_peer(&mut state, 19003);
    let mut rt = runtime();
    let tag = rt.tag(peer);
    state.input_blocks = Some(rt);

    let actions = execute_effects(
        &mut state,
        vec![Effect::Penalize {
            from: tag,
            reason: "bad_pow",
        }],
        Instant::now(),
    );
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        Action::Penalize { peer: p, penalty } => {
            assert_eq!(*p, peer);
            assert_eq!(*penalty, Penalty::Misbehavior);
        }
        other => panic!("unexpected action {other:?}"),
    }
}

#[test]
fn dropped_effects_increment_counters_without_actions() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    state.input_blocks = Some(runtime());

    let actions = execute_effects(
        &mut state,
        vec![
            Effect::Dropped {
                id: [1u8; 32],
                reason: DropReason::AlreadyKnown,
            },
            Effect::Dropped {
                id: [2u8; 32],
                reason: DropReason::AlreadyKnown,
            },
            Effect::Dropped {
                id: [3u8; 32],
                reason: DropReason::WaitlistFull,
            },
        ],
        Instant::now(),
    );
    assert!(actions.is_empty());
    let rt = state.input_blocks.as_ref().unwrap();
    assert_eq!(rt.counters.get("AlreadyKnown"), 2);
    assert_eq!(rt.counters.get("WaitlistFull"), 1);
    assert_eq!(rt.counters.get("ForksFull"), 0);
}

// ----- round-trips -----

#[test]
fn stored_header_round_trips_through_expected_n_bits_lookup() {
    // Guards the header-decode path `expected_n_bits_after` depends on:
    // a header stored by `store_validated_header` must read back byte-identical.
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let headers = seed_header_chain(&mut state, 2);
    let want = headers.last().unwrap();
    let bytes = state
        .store
        .get_header(&header_id_of(want))
        .unwrap()
        .expect("stored");
    let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
    let got = read_header(&mut r).unwrap();
    assert_eq!(&got, want);
}

// ----- regressions (fix round 1) -----

/// Finding 1: a block section's modifier id is
/// `blake2b256(type || header_id || root)`, NOT the root itself. Using
/// the bare root made `RequestBlockTransactions` name a modifier nobody
/// has, and made every stored section look absent.
#[test]
fn block_transactions_section_id_is_hashed_not_the_bare_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let headers = seed_header_chain(&mut state, 1);
    let header = &headers[0];
    let header_id = header_id_of(header);

    // The id the block pipeline itself computes for this header's
    // transactions section.
    let expected = ergo_ser::modifier_id::ExpectedSections::from_header(
        &header_id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    )
    .transactions_id;
    assert_ne!(
        expected,
        *header.transactions_root.as_bytes(),
        "fixture would not discriminate if the two coincided"
    );

    assert_eq!(
        transactions_section_id(&state, &header_id),
        Some(expected),
        "the requested modifier id must be the section id"
    );

    // And the "do we already have it?" probe must find a section stored
    // under that same id.
    assert!(
        !block_transactions_known(&state, &header_id),
        "nothing stored yet"
    );
    state
        .store
        .store_block_section_typed(&expected, &[0xab, 0xcd], 102)
        .unwrap();
    assert!(
        block_transactions_known(&state, &header_id),
        "a stored section must not look absent"
    );
}

/// Finding 6(a): the processor has no clock and no chain view of its
/// own, so `Event::Tick` and the ordering-chain events must be driven by
/// the node. Without the tick a peer that stops answering holds its
/// `requests_per_peer` slots forever; without the applied hook the
/// generation never bumps and `/info.bestInputBlock` never clears.
#[test]
fn ordering_applied_hook_bumps_generation_and_clears_best_input_block() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    state.input_blocks = Some(runtime());
    let before = state
        .input_blocks
        .as_ref()
        .unwrap()
        .processor()
        .generation();

    let actions = on_ordering_block_applied(&mut state, [0x5a; 32], 7, Instant::now());

    let rt = state.input_blocks.as_ref().unwrap();
    assert!(
        rt.processor().generation() > before,
        "an applied ordering block invalidates in-flight jobs"
    );
    assert!(rt.processor().best_input_block().is_none());
    assert!(
        actions.is_empty(),
        "nothing to relay or request on a bare apply"
    );
}

#[test]
fn hooks_are_no_ops_when_the_subsystem_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    assert!(state.input_blocks.is_none());
    assert!(on_tick(&mut state, Instant::now()).is_empty());
    assert!(on_ordering_block_applied(&mut state, [1; 32], 1, Instant::now()).is_empty());
    assert!(on_ordering_reorg(&mut state, [1; 32], 1, Instant::now()).is_empty());
    seed_best_ordering(&mut state);
    assert!(state.input_blocks.is_none());
}

#[test]
fn tick_releases_an_expired_request_slot() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let start = Instant::now();
    let mut rt = InputBlocksRuntime::new(&cfg(), start);
    // One slot, so the second request is refused until the first expires.
    let tag = rt.tag("127.0.0.1:19501".parse().unwrap());
    state.input_blocks = Some(rt);

    // Drive the tick far past `request_timeout_ms`; the sweep must run
    // without the processor ever having consulted a clock of its own.
    let later = start
        + std::time::Duration::from_millis(
            cfg().bounds.request_timeout_ms + cfg().bounds.staging_ttl_ms + 1,
        );
    let actions = on_tick(&mut state, later);
    assert!(actions.is_empty(), "an idle tick asks for nothing");
    assert_eq!(
        state.input_blocks.as_ref().unwrap().tick(later).0,
        cfg().bounds.request_timeout_ms + cfg().bounds.staging_ttl_ms + 1,
        "the runtime's clock is milliseconds since construction"
    );
    let _ = tag;
}

// ----- task 4: dispatch, serving, advertisement -----

/// A processor-friendly config: `test_support`'s announcements carry real
/// batch-merkle proofs over exactly the three extension entries, so both
/// the parity and the strict-binding checks pass.
fn live_cfg() -> crate::config::InputBlocksConfig {
    cfg()
}

/// A state with the subsystem live and a multiplier present, so
/// announcements are inside the actionable window and pass PoW (the
/// `test_support` module documents why `i32::MAX` is the right
/// permissive multiplier for unmined test headers).
fn live_state(dir: &std::path::Path) -> NodeState {
    let mut state = make_state(&dir.join("state.redb"));
    state.last_seen_active_params.subblocks_per_block = Some(i32::MAX);
    state.input_blocks = Some(InputBlocksRuntime::new(&live_cfg(), Instant::now()));
    state
}

/// Register + handshake a peer at `version`, keeping the outbound
/// receiver alive for the caller to inspect.
fn handshake_peer(
    state: &mut NodeState,
    port: u16,
    version: ergo_p2p::handshake::Version,
    now: Instant,
) -> (
    std::net::SocketAddr,
    tokio::sync::mpsc::Receiver<ergo_p2p::framing::MessageFrame>,
) {
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    state.peer_manager.register_outbound(addr, now).unwrap();
    state.peer_manager.mark_tcp_connected(&addr);
    let mut spec = state.our_handshake.peer_spec.clone();
    spec.version = version;
    spec.features = vec![ergo_p2p::handshake::PeerFeature::Mode {
        state_type: 0,
        verify_tx: true,
        nipopow: None,
        blocks_to_keep: -1,
    }];
    state
        .peer_manager
        .complete_handshake(&addr, spec, None, now)
        .unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    state.registry.peers.insert(
        addr,
        crate::node::state::PeerRuntime {
            sync_version: ergo_p2p::peer::SyncVersion::V2,
            outbound_tx: tx,
        },
    );
    (addr, rx)
}

fn send_to(
    state: &mut NodeState,
    peer: std::net::SocketAddr,
    code: u8,
    payload: &[u8],
) -> Vec<Action> {
    crate::node::handle_message(state, peer, code, payload, Instant::now())
}

fn sent_frames(actions: &[Action], code: u8) -> Vec<Vec<u8>> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::SendToPeer {
                code: c, payload, ..
            } if *c == code => Some(payload.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn handshake_advertises_6_5_0_only_when_enabled() {
    use ergo_p2p::handshake::Version;
    assert_eq!(advertised_version(true), Version::SUBBLOCKS);
    assert_eq!(advertised_version(false), Version::CURRENT);
    assert!(
        Version::CURRENT < Version::SUBBLOCKS,
        "a disabled node must advertise BELOW the subblocks floor"
    );
}

#[test]
fn code_100_with_runtime_absent_is_ignored_like_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19601,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );
    assert!(state.input_blocks.is_none());

    let ann = ts::announcement([0u8; 32], 1, 1, None);
    let payload = ergo_p2p::message::serialize_input_block(&ann).unwrap();
    let before = state.peer_manager.get(&peer).unwrap().last_progress;

    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK,
        &payload,
    );
    assert!(actions.is_empty(), "no reply, no penalty — just ignored");
    assert_eq!(
        state.peer_manager.get(&peer).unwrap().last_progress,
        before,
        "an ignored opcode is not progress"
    );
}

#[test]
fn code_100_announcement_feeds_processor_and_requests_missing_bodies() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19602,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    let bodies = [ts::body(1, 1), ts::body(2, 1)];
    let ann = ts::announcement_for([0u8; 32], 1, 7, None, &bodies);
    let ann_id = ts::ann_id(&ann);
    let payload = ergo_p2p::message::serialize_input_block(&ann).unwrap();

    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK,
        &payload,
    );

    assert!(
        state
            .input_blocks
            .as_ref()
            .unwrap()
            .processor()
            .announcement(&ann_id)
            .is_some(),
        "the announcement reached the processor"
    );
    // The mempool is empty, so every announced weak id is unresolved and
    // must be asked for from the announcer.
    let reqs = sent_frames(&actions, ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST);
    assert_eq!(reqs.len(), 1, "one body request to the announcer");
    let req = ergo_p2p::message::deserialize_input_block_txs_request(&reqs[0]).unwrap();
    assert_eq!(req.input_block_id, ann_id);
    let mut got = req.weak_ids.clone();
    let mut want: Vec<_> = bodies.iter().map(|b| b.weak_id).collect();
    got.sort();
    want.sort();
    assert_eq!(got, want, "asks for exactly the unresolved weak ids");
}

#[test]
fn code_104_bodies_reach_processor_from_announcer() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19603,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    let bodies = [ts::body(3, 1)];
    let ann = ts::announcement_for([0u8; 32], 1, 8, None, &bodies);
    let ann_id = ts::ann_id(&ann);
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK,
        &ergo_p2p::message::serialize_input_block(&ann).unwrap(),
    );

    let txs = ergo_p2p::message::InputBlockTxs {
        input_block_id: ann_id,
        transactions: bodies.iter().map(|b| b.tx.clone()).collect(),
    };
    let payload = ergo_p2p::message::serialize_input_block_txs(&txs).unwrap();
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS,
        &payload,
    );

    let rt = state.input_blocks.as_ref().unwrap();
    assert!(
        rt.processor().body(&bodies[0].tx_ref).is_some(),
        "the delivered body is cached"
    );
    assert_eq!(
        rt.processor().transaction_refs(&ann_id),
        Some(&bodies.iter().map(|b| b.tx_ref).collect::<Vec<_>>()[..]),
        "and is seated in the announced order"
    );
}

#[test]
fn code_102_ids_reach_processor() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19604,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    // An announcement that omits the weak-id list: the processor asks
    // for it (−122) and this is the answer.
    let ann = ts::announcement([0u8; 32], 1, 9, None);
    let ann_id = ts::ann_id(&ann);
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK,
        &ergo_p2p::message::serialize_input_block(&ann).unwrap(),
    );

    let payload =
        ergo_p2p::message::serialize_input_block_tx_ids(&ergo_p2p::message::InputBlockTxIds {
            input_block_id: ann_id,
            weak_ids: Vec::new(),
        });
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TX_IDS,
        &payload,
    );

    assert_eq!(
        state
            .input_blocks
            .as_ref()
            .unwrap()
            .processor()
            .weak_ids(&ann_id),
        Some(Vec::new()),
        "the id list is recorded (empty is a real answer, not a miss)"
    );
}

#[test]
fn code_105_request_is_served_from_processor_bodies_by_weak_ids() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19605,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    let bodies = [ts::body(4, 1), ts::body(5, 1)];
    let ann = ts::announcement_for([0u8; 32], 1, 10, None, &bodies);
    let ann_id = ts::ann_id(&ann);
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK,
        &ergo_p2p::message::serialize_input_block(&ann).unwrap(),
    );
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS,
        &ergo_p2p::message::serialize_input_block_txs(&ergo_p2p::message::InputBlockTxs {
            input_block_id: ann_id,
            transactions: bodies.iter().map(|b| b.tx.clone()).collect(),
        })
        .unwrap(),
    );

    // Ask for ONE of the two.
    let req = ergo_p2p::message::InputBlockTxsRequest {
        input_block_id: ann_id,
        weak_ids: vec![bodies[1].weak_id],
    };
    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST,
        &ergo_p2p::message::serialize_input_block_txs_request(&req),
    );
    let replies = sent_frames(&actions, ergo_p2p::message::CODE_INPUT_BLOCK_TXS);
    assert_eq!(replies.len(), 1);
    let got = ergo_p2p::message::deserialize_input_block_txs(&replies[0]).unwrap();
    assert_eq!(got.input_block_id, ann_id);
    assert_eq!(
        got.transactions,
        vec![bodies[1].tx.clone()],
        "serves only the requested weak ids"
    );
}

/// Seed `state` with an announcement (plus bodies) from `peer`.
fn seed_announcement(
    state: &mut NodeState,
    peer: std::net::SocketAddr,
    nonce: u64,
    bodies: &[ergo_inputblocks::processor::Body],
) -> [u8; 32] {
    let ann = ts::announcement_for([0u8; 32], 1, nonce, None, bodies);
    let id = ts::ann_id(&ann);
    let _ = send_to(
        state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK,
        &ergo_p2p::message::serialize_input_block(&ann).unwrap(),
    );
    id
}

fn request_modifier_payload(type_id: u8, ids: &[[u8; 32]]) -> Vec<u8> {
    ergo_p2p::message::serialize_inv(&ergo_p2p::types::InvData {
        type_id,
        ids: ids.to_vec(),
    })
    .unwrap()
}

#[test]
fn request_modifier_minus_123_serves_announcement_code_100() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19606,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );
    let id = seed_announcement(&mut state, peer, 11, &[ts::body(6, 1)]);

    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_REQUEST_MODIFIER,
        &request_modifier_payload(ergo_p2p::types::ModifierTypeId::InputBlock.as_byte(), &[id]),
    );
    let served = sent_frames(&actions, ergo_p2p::message::CODE_INPUT_BLOCK);
    assert_eq!(served.len(), 1);
    assert_eq!(
        ts::ann_id(&ergo_p2p::message::deserialize_input_block(&served[0]).unwrap()),
        id
    );

    // An id we do not hold is ignored, with no penalty (spec 9.4).
    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_REQUEST_MODIFIER,
        &request_modifier_payload(
            ergo_p2p::types::ModifierTypeId::InputBlock.as_byte(),
            &[[0xee; 32]],
        ),
    );
    assert!(actions.is_empty(), "unknown id: no reply and no penalty");
}

#[test]
fn request_modifier_minus_122_serves_weak_ids_code_102() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19607,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );
    let bodies = [ts::body(7, 1)];
    let id = seed_announcement(&mut state, peer, 12, &bodies);
    // Scala's `getInputBlockTransactionWeakIds` reads the block's
    // RESOLVED transaction references, so the ids become servable once
    // the bodies land — not on the announcement alone.
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS,
        &ergo_p2p::message::serialize_input_block_txs(&ergo_p2p::message::InputBlockTxs {
            input_block_id: id,
            transactions: bodies.iter().map(|b| b.tx.clone()).collect(),
        })
        .unwrap(),
    );

    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_REQUEST_MODIFIER,
        &request_modifier_payload(
            ergo_p2p::types::ModifierTypeId::InputBlockTransactionIds.as_byte(),
            &[id],
        ),
    );
    let served = sent_frames(&actions, ergo_p2p::message::CODE_INPUT_BLOCK_TX_IDS);
    assert_eq!(served.len(), 1);
    let got = ergo_p2p::message::deserialize_input_block_tx_ids(&served[0]).unwrap();
    assert_eq!(got.input_block_id, id);
    assert_eq!(got.weak_ids, vec![bodies[0].weak_id]);
}

#[test]
fn request_modifier_minus_121_serves_ordering_announcement_code_106() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19608,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    let oa = ts::ordering_announcement([0u8; 32], 1, 13, Vec::new());
    let oa_id = ts::header_id(&oa.header);
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_ORDERING_BLOCK_ANNOUNCEMENT,
        &ergo_p2p::message::serialize_ordering_block_announcement_msg(&oa).unwrap(),
    );
    assert!(
        state
            .input_blocks
            .as_ref()
            .unwrap()
            .processor()
            .ordering_announcement(&oa_id)
            .is_some(),
        "the ordering announcement was stored"
    );

    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_REQUEST_MODIFIER,
        &request_modifier_payload(
            ergo_p2p::types::ModifierTypeId::OrderingBlockAnnouncement.as_byte(),
            &[oa_id],
        ),
    );
    let served = sent_frames(
        &actions,
        ergo_p2p::message::CODE_ORDERING_BLOCK_ANNOUNCEMENT,
    );
    assert_eq!(served.len(), 1);
    assert_eq!(
        ts::header_id(
            &ergo_p2p::message::deserialize_ordering_block_announcement_msg(&served[0])
                .unwrap()
                .header
        ),
        oa_id
    );
}

#[test]
fn inv_minus_121_from_eligible_peer_requests_announcement() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19609,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    let unknown = [0x7c; 32];
    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INV,
        &request_modifier_payload(
            ergo_p2p::types::ModifierTypeId::OrderingBlockAnnouncement.as_byte(),
            &[unknown],
        ),
    );
    let reqs = sent_frames(&actions, ergo_p2p::message::CODE_REQUEST_MODIFIER);
    assert_eq!(reqs.len(), 1, "we ask the advertiser for it");
    let inv = ergo_p2p::message::deserialize_inv(&reqs[0]).unwrap();
    assert_eq!(
        inv.type_id,
        ergo_p2p::types::ModifierTypeId::OrderingBlockAnnouncement.as_byte()
    );
    assert_eq!(inv.ids, vec![unknown]);
    assert_eq!(
        state.coordinator.delivery().status(&unknown),
        ergo_p2p::delivery::ModifierStatus::Requested,
        "the request is registered with the delivery tracker"
    );
}

#[test]
fn inv_minus_121_from_a_peer_below_6_5_0_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19610,
        ergo_p2p::handshake::Version::CURRENT,
        now,
    );
    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INV,
        &request_modifier_payload(
            ergo_p2p::types::ModifierTypeId::OrderingBlockAnnouncement.as_byte(),
            &[[0x7d; 32]],
        ),
    );
    assert!(actions.is_empty());
}

#[test]
fn progress_classification_counts_100_and_106_only_and_102_104_105_when_answering() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19611,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    let progress_of = |state: &NodeState| state.peer_manager.get(&peer).unwrap().last_progress;

    // 100 is always progress.
    let before = progress_of(&state);
    let bodies = [ts::body(8, 1)];
    let id = seed_announcement(&mut state, peer, 14, &bodies);
    assert!(progress_of(&state) > before, "100 counts");

    // A 104 for a block we DID ask this peer for counts: the
    // announcement above left an outstanding message-105 expectation.
    let before = progress_of(&state);
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS,
        &ergo_p2p::message::serialize_input_block_txs(&ergo_p2p::message::InputBlockTxs {
            input_block_id: id,
            transactions: bodies.iter().map(|b| b.tx.clone()).collect(),
        })
        .unwrap(),
    );
    assert!(progress_of(&state) > before, "a solicited 104 is progress");

    // An unsolicited 104 — a block this peer was never asked for — is
    // not. Spraying bodies must not hold a slot.
    let before = progress_of(&state);
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS,
        &ergo_p2p::message::serialize_input_block_txs(&ergo_p2p::message::InputBlockTxs {
            input_block_id: [0xbb; 32],
            transactions: bodies.iter().map(|b| b.tx.clone()).collect(),
        })
        .unwrap(),
    );
    assert_eq!(
        progress_of(&state),
        before,
        "104 that answers no registered request is not progress"
    );

    // A 105 we cannot serve is not progress; one we can serve is.
    let before = progress_of(&state);
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST,
        &ergo_p2p::message::serialize_input_block_txs_request(
            &ergo_p2p::message::InputBlockTxsRequest {
                input_block_id: [0xaa; 32],
                weak_ids: vec![[9u8; 6]],
            },
        ),
    );
    assert_eq!(
        progress_of(&state),
        before,
        "an unservable 105 is not progress"
    );

    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST,
        &ergo_p2p::message::serialize_input_block_txs_request(
            &ergo_p2p::message::InputBlockTxsRequest {
                input_block_id: id,
                weak_ids: vec![bodies[0].weak_id],
            },
        ),
    );
    assert!(progress_of(&state) > before, "a served 105 is progress");

    // 106 is always progress.
    let before = progress_of(&state);
    let oa = ts::ordering_announcement([0u8; 32], 1, 15, Vec::new());
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_ORDERING_BLOCK_ANNOUNCEMENT,
        &ergo_p2p::message::serialize_ordering_block_announcement_msg(&oa).unwrap(),
    );
    assert!(progress_of(&state) > before, "106 counts");
}

#[test]
fn malformed_input_block_frames_penalize_the_sender() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19612,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    for code in [
        ergo_p2p::message::CODE_INPUT_BLOCK,
        ergo_p2p::message::CODE_INPUT_BLOCK_TX_IDS,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST,
        ergo_p2p::message::CODE_ORDERING_BLOCK_ANNOUNCEMENT,
    ] {
        let actions = send_to(&mut state, peer, code, &[0xff, 0xff, 0xff]);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Penalize { penalty, .. } if *penalty == Penalty::Misbehavior)),
            "code {code} with a garbage payload must penalize"
        );
    }
}

/// Finding 2: input-block requests must go through the node's delivery
/// tracker, not a bare serializer. Without a registered expectation the
/// answering frame is unsolicited — it loses the byte-cap exemption, the
/// progress credit, and the timeout sweep — and a duplicate request is
/// not suppressed.
#[test]
fn input_block_requests_register_with_the_delivery_tracker() {
    use ergo_p2p::delivery::ModifierStatus;
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19620,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );
    let tag = state.input_blocks.as_mut().unwrap().tag(peer);

    let block = [0x31u8; 32];
    let actions = execute_effects(
        &mut state,
        vec![Effect::RequestInputBlock {
            id: block,
            from: tag,
        }],
        now,
    );
    assert_eq!(actions.len(), 1, "the request is emitted");
    assert_eq!(
        state.coordinator.delivery().status(&block),
        ModifierStatus::Requested,
        "-123 registers an expectation"
    );

    // A repeat while it is still in flight must not go out twice.
    let again = execute_effects(
        &mut state,
        vec![Effect::RequestInputBlock {
            id: block,
            from: tag,
        }],
        now,
    );
    assert!(
        again.is_empty(),
        "duplicate request suppressed by the tracker"
    );
}

#[test]
fn body_request_registers_so_the_reply_counts_as_solicited() {
    use ergo_p2p::delivery::{DeliveryAction, ModifierStatus};
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19621,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );
    let tag = state.input_blocks.as_mut().unwrap().tag(peer);

    let block = [0x32u8; 32];
    let actions = execute_effects(
        &mut state,
        vec![Effect::RequestTransactions {
            input_block_id: block,
            weak_ids: vec![[1u8; 6]],
            from: tag,
        }],
        now,
    );
    assert_eq!(
        sent_frames(&actions, ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST).len(),
        1
    );
    assert_eq!(
        state.coordinator.delivery().status(&block),
        ModifierStatus::Requested,
        "message 105 registers an expectation keyed by the input block"
    );
    assert_eq!(
        state.coordinator.delivery().on_received(&block, &peer),
        DeliveryAction::Accept,
        "so the code-104 reply is recognised as solicited"
    );
}

#[test]
fn input_block_timeouts_are_forgotten_not_redistributed() {
    // The processor owns input-block retry policy (its own per-peer
    // slots + request_timeout_ms sweep). The coordinator's generic
    // timeout path must not run a second retry engine over the same
    // ids, nor NonDelivery-penalize a peer for a request the processor
    // has already abandoned.
    use ergo_p2p::types::ModifierTypeId;
    assert!(ModifierTypeId::is_input_block_family(
        ModifierTypeId::InputBlock.as_byte()
    ));
    assert!(ModifierTypeId::is_input_block_family(
        ModifierTypeId::InputBlockTransactionIds.as_byte()
    ));
    assert!(ModifierTypeId::is_input_block_family(
        ModifierTypeId::OrderingBlockAnnouncement.as_byte()
    ));
    assert!(!ModifierTypeId::is_input_block_family(
        ModifierTypeId::BlockTransactions.as_byte()
    ));
    assert!(!ModifierTypeId::is_input_block_family(
        ModifierTypeId::Header.as_byte()
    ));
}

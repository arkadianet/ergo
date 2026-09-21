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

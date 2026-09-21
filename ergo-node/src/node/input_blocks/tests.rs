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

use super::ctx::{block_transactions_known, build_ctx_data, expected_n_bits_after};
use super::effects::{apply_chain_change, execute_effects, relay_peers};
use super::hooks::{
    advertised_version, classify_tip_change, on_ordering_block_applied, on_ordering_reorg, on_tick,
    seed_best_ordering, TipChange, MAX_LINEAR_CATCHUP,
};
use super::runtime::InputBlocksRuntime;
use super::validate::build_input_block_context;
use crate::node::state::NodeState;
use crate::node::tests::make_state;

// ----- helpers -----

/// Count for one drop reason; `0` for a reason that never fired. Lives
/// here rather than on `DropCounters` because only tests ask about one
/// reason at a time — production reports the whole breakdown.
fn drops(rt: &InputBlocksRuntime, reason: &str) -> u64 {
    rt.counters
        .iter()
        .find(|(name, _)| *name == reason)
        .map(|(_, n)| n)
        .unwrap_or(0)
}

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

/// SUPPLEMENTAL loader-consistency check, NOT an oracle: the expected
/// value here is produced by the same `next_n_bits` the code under test
/// calls, so it proves the header LOADER (genesis skip, parent
/// substitution, epoch-window selection) feeds the difficulty function
/// the window it intends — and nothing about the difficulty function.
///
/// The consensus oracle is
/// `expected_n_bits_after_matches_mainnet_headers_across_an_epoch_boundary`,
/// whose expected values are real mainnet `nBits`.
#[test]
fn expected_n_bits_after_known_parent_matches_the_loaded_window() {
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
    assert_eq!(drops(rt, "AlreadyKnown"), 2);
    assert_eq!(drops(rt, "WaitlistFull"), 1);
    assert_eq!(drops(rt, "ForksFull"), 0);
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

/// A real mainnet block from the committed fixtures: its header bytes
/// (`headers_1_10.json`) and its transactions (`blocks_1_5.json`),
/// serialized into the canonical `BlockTransactions` section. Returns
/// `(header, header_id, section_bytes)`.
///
/// Anchored to mainnet independently of any id arithmetic: the header is
/// verified to be a real header (`id == blake2b256(bytes)`) and the
/// transactions are verified to reproduce that header's own
/// `transactions_root`, so the pair really is block `height`'s body.
fn real_block_with_transactions(height: u32) -> (Header, [u8; 32], Vec<u8>) {
    #[derive(serde::Deserialize)]
    struct BlockVector {
        #[serde(rename = "headerId")]
        header_id: String,
        height: u32,
        transactions: Vec<TxVector>,
    }
    #[derive(serde::Deserialize)]
    struct TxVector {
        bytes: String,
    }

    let (_, header_id, _, header) =
        load_mainnet_headers("../test-vectors/mainnet/headers_1_10.json")
            .into_iter()
            .find(|(h, ..)| *h == height)
            .expect("header fixture covers this height");

    let raw = std::fs::read_to_string("../test-vectors/mainnet/blocks_1_5.json").unwrap();
    let blocks: Vec<BlockVector> = serde_json::from_str(&raw).unwrap();
    let block = blocks
        .into_iter()
        .find(|b| b.height == height)
        .expect("block fixture covers this height");
    assert_eq!(
        block.header_id,
        hex::encode(header_id),
        "the block fixture and the header fixture must name the same block"
    );

    let txs: Vec<ergo_ser::transaction::Transaction> = block
        .transactions
        .iter()
        .map(|t| {
            let bytes = hex::decode(&t.bytes).unwrap();
            let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
            ergo_ser::transaction::read_transaction(&mut r).unwrap()
        })
        .collect();

    // Mainnet anchor: these transactions must reproduce the real
    // header's transactionsRoot, or the fixture is not this block's body.
    let tx_ids: Vec<[u8; 32]> = txs
        .iter()
        .map(|t| *ergo_ser::transaction::transaction_id(t).unwrap().as_bytes())
        .collect();
    let id_refs: Vec<&[u8]> = tx_ids.iter().map(|i| &i[..]).collect();
    assert_eq!(
        ergo_crypto::merkle::transactions_root(&id_refs, None),
        *header.transactions_root.as_bytes(),
        "fixture transactions do not reproduce the real header's transactionsRoot"
    );

    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::block_transactions::write_block_transactions(
        &mut w,
        &ergo_ser::block_transactions::BlockTransactions {
            header_id: ergo_primitives::digest::ModifierId::from_bytes(header_id),
            transactions: txs,
        },
    )
    .unwrap();
    (header, header_id, w.result())
}

/// Finding 1 (round 1 + round 2): a block section's modifier id is
/// `blake2b256(type ‖ header_id ‖ root)`, NOT the header's bare
/// `transactions_root`. Using the root made `RequestBlockTransactions`
/// name a modifier nobody has, and made every stored section look
/// absent.
///
/// Driven through the real effect executor against a real mainnet block
/// applied into the store: the id the `SendToPeer` payload actually
/// carries must be the id the store holds that block's
/// `BlockTransactions` section under.
#[test]
fn request_block_transactions_names_the_stored_section_id_of_a_real_block() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19650,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );
    let tag = state.input_blocks.as_mut().unwrap().tag(peer);

    let (header, header_id, section_bytes) = real_block_with_transactions(1);
    seed_mainnet_headers(
        &mut state,
        &[(
            header.height,
            header_id,
            {
                let (bytes, _) = serialize_header(&header).unwrap();
                bytes
            },
            header.clone(),
        )],
        true,
    );

    // Persist the section the way the block pipeline does: under the id
    // `ExpectedSections` derives for this header. That id — not the test
    // — is the authority the assertions below compare against.
    let stored_section_id = ergo_ser::modifier_id::ExpectedSections::from_header(
        &header_id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    )
    .transactions_id;
    assert_ne!(
        stored_section_id,
        *header.transactions_root.as_bytes(),
        "the fixture would not discriminate if the two coincided"
    );

    // Before the section exists the probe must say so, and the request
    // must still name the right id.
    assert!(
        !block_transactions_known(&state, &header_id),
        "nothing stored yet"
    );
    let actions = execute_effects(
        &mut state,
        vec![Effect::RequestBlockTransactions {
            header_id,
            from: tag,
        }],
        now,
    );
    let reqs = sent_frames(&actions, ergo_p2p::message::CODE_REQUEST_MODIFIER);
    assert_eq!(reqs.len(), 1, "the section request goes out");
    let inv = ergo_p2p::message::deserialize_inv(&reqs[0]).unwrap();
    assert_eq!(
        inv.type_id,
        ergo_p2p::types::ModifierTypeId::BlockTransactions.as_byte()
    );
    assert_eq!(
        inv.ids,
        vec![stored_section_id],
        "the requested modifier id must be the section id, not the bare root"
    );

    state
        .store
        .store_block_section_typed(&stored_section_id, &section_bytes, 102)
        .unwrap();
    assert_eq!(
        state
            .store
            .get_block_section(&inv.ids[0])
            .unwrap()
            .as_deref(),
        Some(&section_bytes[..]),
        "the id the request named is exactly the id the store holds the \
         real block's BlockTransactions section under"
    );
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

    // Serving a 105 is NOT progress on its own (round 2, finding 6):
    // spec 9.1 credits 105 only when it answers a request of OURS that
    // is still outstanding. A peer asking us for data tells us nothing
    // about whether that peer is useful to us.
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
    assert_eq!(
        progress_of(&state),
        before,
        "serving a 105 with nothing outstanding is not progress"
    );

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

// ----- relay eligibility (finding 3) -----

/// Teach the coordinator this peer's height by delivering a V2 SyncInfo
/// carrying one real header at that height — the same path a live peer
/// takes.
fn set_peer_height(state: &mut NodeState, peer: std::net::SocketAddr, height: u32) {
    let header = ts::header([0u8; 32], height, u64::from(height) + 900_000, [0u8; 32]);
    let (bytes, _) = serialize_header(&header).unwrap();
    let payload = ergo_p2p::message::serialize_sync_info(&ergo_p2p::message::SyncInfo::V2 {
        headers: vec![bytes],
    })
    .unwrap();
    let _ = send_to(state, peer, ergo_p2p::message::CODE_SYNC_INFO, &payload);
    assert_eq!(
        state
            .coordinator
            .peer_sync_snapshots()
            .get(&peer)
            .and_then(|s| s.peer_height),
        Some(height),
        "fixture must actually record a height"
    );
}

/// Register a peer with an explicit `Mode` feature (or none at all).
fn handshake_peer_with_mode(
    state: &mut NodeState,
    port: u16,
    version: ergo_p2p::handshake::Version,
    mode: Option<ergo_p2p::handshake::PeerFeature>,
    now: Instant,
) -> (
    std::net::SocketAddr,
    tokio::sync::mpsc::Receiver<ergo_p2p::framing::MessageFrame>,
) {
    // One peer per IP: the peer manager enforces a per-IP connection
    // limit, and this fixture needs several peers at once.
    // One peer per /16: the peer manager enforces per-IP and per-subnet
    // connection limits, and this fixture needs several peers at once.
    let addr: std::net::SocketAddr = format!("10.{}.0.1:9030", port % 256).parse().unwrap();
    state.peer_manager.register_outbound(addr, now).unwrap();
    state.peer_manager.mark_tcp_connected(&addr);
    let mut spec = state.our_handshake.peer_spec.clone();
    spec.version = version;
    spec.features = mode.into_iter().collect();
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

fn utxo_mode() -> ergo_p2p::handshake::PeerFeature {
    ergo_p2p::handshake::PeerFeature::Mode {
        state_type: 0,
        verify_tx: true,
        nipopow: None,
        blocks_to_keep: -1,
    }
}

fn digest_mode() -> ergo_p2p::handshake::PeerFeature {
    ergo_p2p::handshake::PeerFeature::Mode {
        state_type: 1,
        verify_tx: false,
        nipopow: None,
        blocks_to_keep: -1,
    }
}

/// Finding 3: relay eligibility must be AFFIRMATIVE. Degrading open
/// ("no Mode feature? probably fine") relays input blocks to nodes that
/// cannot use them and to peers whose chain position we do not know.
#[test]
fn relay_requires_affirmative_utxo_mode_version_and_in_window_height() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let our_height = state.store.chain_state_meta().best_full_block_height;

    let (good, _g) = handshake_peer_with_mode(
        &mut state,
        19630,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        Some(utxo_mode()),
        now,
    );
    set_peer_height(&mut state, good, our_height + 1);

    let (no_mode, _a) = handshake_peer_with_mode(
        &mut state,
        19631,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        None,
        now,
    );
    set_peer_height(&mut state, no_mode, our_height);

    let (digest, _b) = handshake_peer_with_mode(
        &mut state,
        19632,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        Some(digest_mode()),
        now,
    );
    set_peer_height(&mut state, digest, our_height);

    let (old, _c) = handshake_peer_with_mode(
        &mut state,
        19633,
        ergo_p2p::handshake::Version::CURRENT,
        Some(utxo_mode()),
        now,
    );
    set_peer_height(&mut state, old, our_height);

    // Height known but far away.
    let (far, _d) = handshake_peer_with_mode(
        &mut state,
        19634,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        Some(utxo_mode()),
        now,
    );
    set_peer_height(&mut state, far, our_height + 50);

    // Eligible in every respect except that we have never learned a height.
    let (unknown_height, _e) = handshake_peer_with_mode(
        &mut state,
        19635,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        Some(utxo_mode()),
        now,
    );

    assert_eq!(
        relay_peers(&state),
        vec![good],
        "only the affirmatively eligible peer is relayed to"
    );
    let _ = (no_mode, digest, old, far, unknown_height);
}

/// Finding 4: `retained` is released only by an explicit rollback, but
/// spec 7.6 says an applied ordering block emits an EMPTY ChainChanged —
/// the abandoned input chain's transactions are deliberately not restored
/// (F6 parity). Without a prune those entries, and the transaction bytes
/// they pin, live until the process restarts.
#[test]
fn ordering_turnover_releases_retained_entries_without_restoring_them() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let stranded = ts::body(0xc3, 1);
    let tx_id = ergo_primitives::digest::Digest32::from_bytes(stranded.tx_ref.tx_id);

    state.input_blocks.as_mut().unwrap().retained.insert(
        [0x41u8; 32],
        vec![RemovedEntry {
            tx_id,
            bytes: stranded.bytes.clone(),
            fee: 0,
            size_bytes: stranded.bytes.len() as u32,
            cost: 1000,
        }],
    );

    let _ = on_ordering_block_applied(&mut state, [0x42; 32], 1, Instant::now());

    assert!(
        state.input_blocks.as_ref().unwrap().retained.is_empty(),
        "entries for blocks no longer on the best input chain are released"
    );
    assert!(
        !state.mempool.contains(&tx_id),
        "released is NOT restored: an applied ordering block drops the \
         abandoned input chain's transactions (spec 7.6 / F6)"
    );
}

// ----- successful inline validation (finding 5) -----

/// `sigmaProp(true)` — `BoolToSigmaProp(Const(SBoolean, true))`.
///
/// A bare `Const(SBoolean, true)` root is NOT usable: rule 1001
/// (`CheckDeserializedScriptIsSigmaProp`) rejects a sizeless tree whose
/// root is not `SigmaProp`, and under `has_size` the same failure is
/// wrapped as an unparsed soft-fork tree that cannot be evaluated at all.
fn true_tree() -> ergo_ser::ergo_tree::ErgoTree {
    use ergo_ser::opcode::{Expr, IrNode, Payload};
    ergo_ser::ergo_tree::ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Op(IrNode {
            opcode: 0xD1,
            payload: Payload::One(Box::new(Expr::Const {
                tpe: ergo_ser::sigma_type::SigmaType::SBoolean,
                val: ergo_ser::sigma_value::SigmaValue::Boolean(true),
            })),
        }),
    }
}

/// Seed one spendable box paying to a trivially-true script, and return
/// its id. `creation_height` must not exceed the context height or the
/// spending transaction is rejected on the output-height rule.
fn seed_spendable_box(
    state: &mut NodeState,
    seed: u8,
    value: u64,
    creation_height: u32,
) -> ergo_primitives::digest::Digest32 {
    use ergo_ser::ergo_box::{write_ergo_box, ErgoBox, ErgoBoxCandidate};
    use ergo_ser::register::AdditionalRegisters;
    let candidate = ErgoBoxCandidate::new(
        value,
        true_tree(),
        creation_height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap();
    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes([seed; 32]),
        index: 0,
    };
    let id = ergo_box.box_id().unwrap();
    let mut w = ergo_primitives::writer::VlqWriter::new();
    write_ergo_box(&mut w, &ergo_box).unwrap();
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .tree_insert_for_test(*id.as_bytes(), w.result());
    id
}

/// A state with 11 chain-linked headers applied, the best full block
/// hydrated into the executor's context window, and the input-block
/// subsystem live. Returns `(state, best_header_id, best_height)`.
fn live_state_with_applied_tip(dir: &std::path::Path) -> (NodeState, [u8; 32], u32) {
    let mut state = live_state(dir);
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
    seed_best_ordering(&mut state);
    (state, best_id, best.height)
}

/// Finding 5: the inline-validation path needs a test that actually
/// VALIDATES. This drives a processor-issued job with real cached bodies
/// spending a real box, and asserts the whole chain: validation passes,
/// the generation is unchanged (nothing invalidated the job), the block
/// is applied to the input chain, and the mempool half ran.
#[test]
fn inline_validation_success_applies_the_block_and_updates_the_mempool() {
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::transaction::Transaction;

    let dir = tempfile::tempdir().unwrap();
    let (mut state, best_id, best_height) = live_state_with_applied_tip(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19640,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    // One box in, one box out, value conserved.
    let funded = seed_spendable_box(&mut state, 0xd1, 1_000_000, best_height);
    let tx = Transaction {
        inputs: vec![Input {
            box_id: funded,
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate::new(
            1_000_000,
            true_tree(),
            best_height,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()],
    };
    let body = ts::body_of(tx);
    let pooled_id = ergo_primitives::digest::Digest32::from_bytes(body.tx_ref.tx_id);
    // Seat the same transaction in the mempool, so the apply half of
    // ChainChanged has something to evict and the effect is observable.
    state
        .mempool
        .restore_input_block_txs(&[(pooled_id, body.bytes.clone(), None)], Instant::now());
    assert!(state.mempool.contains(&pooled_id), "fixture seats the tx");

    // Announce at best_height + 1 (the only actionable slot) under the
    // applied tip, so the block lands in that ordering block's tree.
    let ann = ts::announcement_for(
        best_id,
        best_height + 1,
        21,
        None,
        std::slice::from_ref(&body),
    );
    let ann_id = ts::ann_id(&ann);
    let generation_before = state
        .input_blocks
        .as_ref()
        .unwrap()
        .processor()
        .generation();

    // The body is already pooled, so spec 7.5 step 1 resolves every
    // announced weak id from the mempool: the block completes on the
    // announcement alone, the processor emits Validate, and the effect
    // executor answers it inline against the committed UTXO set.
    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK,
        &ergo_p2p::message::serialize_input_block(&ann).unwrap(),
    );
    assert!(
        !actions.iter().any(|a| matches!(a, Action::Penalize { .. })),
        "a valid announcement is not misbehaviour"
    );
    assert!(
        sent_frames(&actions, ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST).is_empty(),
        "nothing to request: every weak id resolved from the pool"
    );

    let rt = state.input_blocks.as_ref().unwrap();
    assert_eq!(
        drops(rt, "ValidationFailed"),
        0,
        "validation must not have been rejected"
    );
    assert_eq!(
        drops(rt, "CacheEvicted"),
        0,
        "the bodies were cached for the job"
    );
    assert_eq!(
        drops(rt, "StaleValidation"),
        0,
        "the job was not superseded: its result was APPLIED, not dropped"
    );
    // The generation bumps exactly once, and only because the chain
    // changed — spec 7.6 makes every ChainChanged a generation bump. A
    // second bump would mean something else invalidated the view while
    // the job was in flight.
    assert_eq!(
        rt.processor().generation(),
        generation_before + 1,
        "exactly one generation bump, from the successful application"
    );
    assert_eq!(
        rt.processor().best_input_chain(),
        vec![ann_id],
        "the validated block is the best input chain (drops: {:?})",
        rt.counters.iter().collect::<Vec<_>>()
    );
    assert!(
        rt.processor()
            .best_input_block()
            .is_some_and(|a| ts::ann_id(a) == ann_id),
        "and is the best input block"
    );
    assert_eq!(
        rt.retained.get(&ann_id).map(|v| v.len()),
        Some(1),
        "the mempool half ran: the applied block's eviction is retained \
         so a later fork switch can put it back"
    );
    assert!(
        !state.mempool.contains(&pooled_id),
        "an applied input-block transaction leaves the pool"
    );
}

/// The error-path counterpart, retained from the first round: a job the
/// processor never issued is answered and dropped as stale, proving the
/// ValidationResult really is fed back through `Processor::handle`.
#[test]
fn inline_validation_of_an_unissued_job_is_dropped_as_stale() {
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
    assert!(actions.is_empty());
    assert_eq!(
        drops(
            state.input_blocks.as_ref().unwrap(),
            DropReason::StaleValidation { generation: 0 }.name()
        ),
        1
    );
}

// ----- oracle parity (finding 7) -----

/// A mainnet header corpus row (`test-vectors/mainnet/headers_*.json`).
#[derive(serde::Deserialize)]
struct MainnetHeaderVector {
    height: u32,
    id: String,
    bytes: String,
}

/// Load a mainnet header corpus, verifying each row really is a mainnet
/// header (`id == blake2b256(bytes)`) so the oracle cannot be substituted.
fn load_mainnet_headers(path: &str) -> Vec<(u32, [u8; 32], Vec<u8>, Header)> {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let rows: Vec<MainnetHeaderVector> =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path}: {e}"));
    rows.into_iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let id = *ergo_primitives::digest::blake2b256(&bytes).as_bytes();
            assert_eq!(
                hex::encode(id),
                v.id,
                "corpus row at height {} is not a real mainnet header",
                v.height
            );
            let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
            let header = read_header(&mut r).unwrap();
            assert_eq!(header.height, v.height);
            (v.height, id, bytes, header)
        })
        .collect()
}

/// Seed real mainnet headers into the store at their real heights.
fn seed_mainnet_headers(
    state: &mut NodeState,
    rows: &[(u32, [u8; 32], Vec<u8>, Header)],
    index_best_chain: bool,
) {
    let store = state.store.as_utxo_mut().expect("utxo backend");
    store.begin_header_batch();
    for (height, id, bytes, header) in rows {
        let meta = HeaderMeta {
            parent_id: *header.parent_id.as_bytes(),
            height: *height,
            cumulative_score: u64::from(*height).to_be_bytes().to_vec(),
            pow_validity: 1,
            timestamp: header.timestamp,
        };
        store
            .store_validated_header(
                id,
                bytes,
                &meta,
                index_best_chain.then(|| (*height, meta.cumulative_score.clone())),
            )
            .unwrap_or_else(|e| panic!("store mainnet header h={height}: {e:?}"));
    }
    store.flush_header_batch().unwrap();
}

/// Finding 7: the difficulty surface is consensus, so the expected value
/// must come from Scala, not from re-running our own `next_n_bits`.
///
/// The oracle here is the mainnet chain itself: for a real header `C`,
/// the Scala node's answer to "what nBits must follow `C.parent`" is
/// exactly `C.n_bits` — that is what the network accepted. Loading a
/// contiguous mainnet run into a header store and asserting
/// `expected_n_bits_after(parent) == child.n_bits` therefore checks the
/// whole node-side path (header lookup, genesis skip, parent
/// substitution, epoch-window selection) against Scala-produced values.
///
/// `headers_1_2000.json` spans the epoch boundary at child height 1025
/// (`1024 % 1024 == 0`), so both the flat and the retarget path run.
#[test]
fn expected_n_bits_after_matches_mainnet_headers_across_an_epoch_boundary() {
    const TOP: u32 = 1100;
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));

    let mut rows = load_mainnet_headers("../test-vectors/mainnet/headers_1_2000.json");
    rows.retain(|(h, ..)| *h <= TOP);
    assert_eq!(rows.len() as u32, TOP, "corpus must be contiguous 1..=TOP");
    seed_mainnet_headers(&mut state, &rows, true);

    // The retarget boundary must be inside the window, or this test
    // only exercises the flat path.
    let boundary = 1025u32;
    assert!(
        ergo_crypto::difficulty::is_recalculation_height(boundary, &DifficultyParams::mainnet()),
        "1025 must be a mainnet recalculation height"
    );

    let mut checked = 0usize;
    let mut retargets = 0usize;
    for w in rows.windows(2) {
        let (parent_height, parent_id, ..) = &w[0];
        let (child_height, _, _, child) = &w[1];
        assert_eq!(*child_height, parent_height + 1);
        assert_eq!(
            expected_n_bits_after(&state, parent_id),
            Some(child.n_bits),
            "expected nBits after mainnet height {parent_height} must be the \
             nBits mainnet actually used at {child_height}"
        );
        checked += 1;
        if ergo_crypto::difficulty::is_recalculation_height(
            *child_height,
            &DifficultyParams::mainnet(),
        ) {
            retargets += 1;
        }
    }
    assert_eq!(checked, (TOP - 1) as usize, "every transition was checked");
    assert!(
        retargets >= 1,
        "at least one real retarget must be covered, got {retargets}"
    );
}

/// The EIP-37 boundary corpus is SPARSE: its 8-epoch lookback window is
/// nine heights 128 apart, and the store's best-chain height index is
/// built by walking parent pointers, so those heights cannot be indexed
/// without the ~1000 intervening headers. That makes this the right
/// place to pin the other half of the contract — the node-side lookup
/// FAILS CLOSED.
///
/// `expected_n_bits_after` must return `None` when it cannot assemble
/// the full window, never a value computed from the part of the window
/// it could find: a partial window yields a plausible-looking wrong
/// difficulty, and the announcement check would then reject valid input
/// blocks (or accept invalid ones). The retarget arithmetic itself is
/// pinned against mainnet at the EIP-37 boundary by
/// `ergo-crypto/tests/it/difficulty_mainnet.rs`.
#[test]
fn expected_n_bits_after_fails_closed_when_the_lookback_window_is_unindexed() {
    const BOUNDARY: u32 = 844_673;
    let dir = tempfile::tempdir().unwrap();
    let mut state = make_state(&dir.path().join("state.redb"));

    let rows = load_mainnet_headers("../test-vectors/mainnet/headers_eip37_curated.json");
    let heights: Vec<u32> = rows.iter().map(|(h, ..)| *h).collect();
    assert!(
        heights.contains(&BOUNDARY) && heights.contains(&(BOUNDARY - 1)),
        "corpus must carry the boundary and its parent, got {heights:?}"
    );
    // The lookback really is the sparse 8-epoch window, so the height
    // index genuinely cannot serve it.
    let needed = previous_heights_for_recalculation(
        BOUNDARY,
        epoch_length_for_height(BOUNDARY, &DifficultyParams::mainnet()),
    );
    assert_eq!(
        needed.len(),
        9,
        "EIP-37 looks back 8 epochs, got {needed:?}"
    );

    seed_mainnet_headers(&mut state, &rows, false);
    let (_, parent_id, ..) = rows
        .iter()
        .find(|(h, ..)| *h == BOUNDARY - 1)
        .expect("parent row");
    assert!(
        state.store.get_header(parent_id).unwrap().is_some(),
        "the parent header itself IS stored — only the window is missing"
    );
    assert_eq!(
        expected_n_bits_after(&state, parent_id),
        None,
        "an unassemblable window must yield no expectation, not a guess"
    );
}

/// Round 2, finding 3: a code-106 reply must acknowledge the tracked
/// −121 expectation it answers. Without it the request stays outstanding
/// forever, the peer gets no progress credit for serving us, and the
/// duplicate-suppression in `register_expectation` refuses to ask anyone
/// else for the same announcement.
#[test]
fn code_106_acknowledges_the_tracked_ordering_request() {
    use ergo_p2p::delivery::ModifierStatus;
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19660,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    let oa = ts::ordering_announcement([0u8; 32], 1, 31, Vec::new());
    let oa_id = ts::header_id(&oa.header);

    // Ask for it the way an Inv −121 does.
    let inv = ergo_p2p::message::serialize_inv(&ergo_p2p::types::InvData {
        type_id: ergo_p2p::types::ModifierTypeId::OrderingBlockAnnouncement.as_byte(),
        ids: vec![oa_id],
    })
    .unwrap();
    let _ = send_to(&mut state, peer, ergo_p2p::message::CODE_INV, &inv);
    assert_eq!(
        state.coordinator.delivery().status(&oa_id),
        ModifierStatus::Requested,
        "fixture leaves a −121 expectation outstanding"
    );

    let before = state.peer_manager.get(&peer).unwrap().last_progress;
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_ORDERING_BLOCK_ANNOUNCEMENT,
        &ergo_p2p::message::serialize_ordering_block_announcement_msg(&oa).unwrap(),
    );

    assert_eq!(
        state.coordinator.delivery().status(&oa_id),
        ModifierStatus::Received,
        "the reply clears the expectation it answered"
    );
    assert!(
        state.peer_manager.get(&peer).unwrap().last_progress > before,
        "106 is progress"
    );
}

/// Round 2, finding 3 (second half): the byte-cap exemption must cover
/// every solicited input-block reply, 106 included. A solicited reply
/// dropped on the byte axis would time out our own request and
/// NonDelivery-penalize the peer that was serving us — the exact
/// self-inflicted starvation the `CODE_MODIFIER` exemption exists to
/// prevent.
#[test]
fn solicited_input_block_replies_are_exempt_from_the_byte_cap() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19661,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    let oa = ts::ordering_announcement([0u8; 32], 1, 32, Vec::new());
    let oa_id = ts::header_id(&oa.header);
    let oa_payload = ergo_p2p::message::serialize_ordering_block_announcement_msg(&oa).unwrap();

    // Unsolicited: no exemption.
    assert!(
        !crate::node::messaging::input_block_frame_answers_our_request(
            &state,
            &peer,
            ergo_p2p::message::CODE_ORDERING_BLOCK_ANNOUNCEMENT,
            &oa_payload,
        ),
        "an unsolicited 106 keeps the ordinary byte cap"
    );

    // Register the expectation the Inv −121 path would.
    crate::node::register_expectation(
        &mut state,
        peer,
        ergo_p2p::types::ModifierTypeId::OrderingBlockAnnouncement.as_byte(),
        &[oa_id],
        now,
    );
    assert!(
        crate::node::messaging::input_block_frame_answers_our_request(
            &state,
            &peer,
            ergo_p2p::message::CODE_ORDERING_BLOCK_ANNOUNCEMENT,
            &oa_payload,
        ),
        "a solicited 106 is exempt"
    );

    // 105 is a request FROM the peer: serving it is our choice, so it
    // never earns the exemption.
    let req = ergo_p2p::message::serialize_input_block_txs_request(
        &ergo_p2p::message::InputBlockTxsRequest {
            input_block_id: oa_id,
            weak_ids: vec![[1u8; 6]],
        },
    );
    assert!(
        !crate::node::messaging::input_block_frame_answers_our_request(
            &state,
            &peer,
            ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST,
            &req,
        ),
        "an inbound 105 is never exempt"
    );
}

/// Round 2, finding 4: acknowledgement must match the PHASE that was
/// requested, not just the block id and peer.
///
/// A block walks announcement → weak-id list → bodies, and every phase
/// re-registers the SAME id. Acknowledging on id alone lets a replayed
/// code 100 clear an outstanding body expectation: the real code-104
/// reply then looks unsolicited, loses its byte-cap exemption and its
/// progress credit, and the peer serving us is charged for a request it
/// did answer.
#[test]
fn replayed_announcement_does_not_clear_an_outstanding_body_expectation() {
    use ergo_p2p::delivery::{DeliveryAction, ModifierStatus};
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19670,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    // Announce a block whose bodies we do not have: the node asks for
    // them with message 105, leaving a BODY expectation outstanding.
    let bodies = [ts::body(0x51, 1)];
    let ann = ts::announcement_for([0u8; 32], 1, 41, None, &bodies);
    let ann_id = ts::ann_id(&ann);
    let ann_payload = ergo_p2p::message::serialize_input_block(&ann).unwrap();
    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK,
        &ann_payload,
    );
    assert_eq!(
        sent_frames(&actions, ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST).len(),
        1,
        "fixture leaves a body request outstanding"
    );
    assert_eq!(
        state.coordinator.delivery().status(&ann_id),
        ModifierStatus::Requested
    );

    // The peer replays the announcement. That answers nothing we are
    // waiting for — we are waiting for BODIES.
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK,
        &ann_payload,
    );
    assert_eq!(
        state.coordinator.delivery().status(&ann_id),
        ModifierStatus::Requested,
        "a replayed announcement must not clear the body expectation"
    );

    // So the real body delivery still counts as solicited.
    assert_eq!(
        state.coordinator.delivery().on_received(&ann_id, &peer),
        DeliveryAction::Accept,
        "the code-104 reply keeps its solicited status"
    );
    let before = state.peer_manager.get(&peer).unwrap().last_progress;
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
    assert!(
        state.peer_manager.get(&peer).unwrap().last_progress > before,
        "the solicited 104 is progress"
    );
    assert_eq!(
        state.coordinator.delivery().status(&ann_id),
        ModifierStatus::Received,
        "and it is the frame that clears the expectation"
    );
}

/// The phase map must not outlive the requests it describes: the
/// delivery tracker's own timeout sweep releases ids we never got an
/// answer for, and the tick prunes the records that went with them.
#[test]
fn expectation_records_are_pruned_when_their_request_leaves_the_tracker() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let start = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19671,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        start,
    );
    let tag = state.input_blocks.as_mut().unwrap().tag(peer);

    let block = [0x61u8; 32];
    let _ = execute_effects(
        &mut state,
        vec![Effect::RequestInputBlock {
            id: block,
            from: tag,
        }],
        start,
    );
    assert_eq!(
        state
            .input_blocks
            .as_ref()
            .unwrap()
            .expected_ids()
            .collect::<Vec<_>>(),
        vec![block],
        "the request records its phase"
    );

    // Past the tracker's delivery timeout: the sweep releases the id,
    // and the tick must drop the record with it.
    let later = start + ergo_p2p::delivery::DELIVERY_TIMEOUT + std::time::Duration::from_secs(1);
    let _ = state.coordinator.check_timeouts(later, &[]);
    let _ = on_tick(&mut state, later);
    assert!(
        state
            .input_blocks
            .as_ref()
            .unwrap()
            .expected_ids()
            .next()
            .is_none(),
        "a request the tracker no longer holds leaves no record behind"
    );
}

/// Round 2, finding 5: the ordering hook used to ride the mempool's
/// tip-change diff, which sits behind `handle_mempool_tick`'s
/// mempool-disabled early return — so a node with input blocks on and
/// the mempool off would let the processor's ordering tip go stale while
/// committed blocks advanced.
///
/// The pairing is now refused at config load, and the hook is driven
/// from the committed state on the heartbeat tick regardless, which is
/// what this pins: no mempool tick is involved anywhere.
#[test]
fn ordering_tip_reaches_the_processor_from_the_tick_not_the_mempool() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let headers = seed_header_chain(&mut state, 3);
    seed_best_ordering(&mut state);
    let before = state
        .input_blocks
        .as_ref()
        .unwrap()
        .processor()
        .generation();

    // Commit a block. Nothing touches the mempool notifier.
    let tip = &headers[1];
    let tip_id = header_id_of(tip);
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .advance_best_full_block(tip_id, tip.height)
        .unwrap();

    let _ = on_tick(&mut state, Instant::now());
    let rt = state.input_blocks.as_ref().unwrap();
    assert!(
        rt.processor().generation() > before,
        "the committed tip reached the processor"
    );
    assert_eq!(rt.last_ordering_tip, Some(tip_id));

    // A second tick at the same tip is not a new event.
    let generation = rt.processor().generation();
    let _ = on_tick(&mut state, Instant::now());
    assert_eq!(
        state
            .input_blocks
            .as_ref()
            .unwrap()
            .processor()
            .generation(),
        generation,
        "an unchanged tip is not re-announced"
    );
}

/// Reorg-vs-linear is classified on the exact rule — does the new tip's
/// parent pointer name the tip we last reported? — rather than on the
/// mempool-level proxy "were any pooled transactions demoted", which
/// would call a reorg with an empty pool a linear apply.
#[test]
fn ordering_tip_classifies_a_fork_switch_as_a_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let headers = seed_header_chain(&mut state, 3);
    seed_best_ordering(&mut state);

    let advance = |state: &mut NodeState, h: &Header| {
        let id = header_id_of(h);
        state
            .store
            .as_utxo_mut()
            .unwrap()
            .advance_best_full_block(id, h.height)
            .unwrap();
        let _ = on_tick(state, Instant::now());
        id
    };

    // h1 then h2: h2's parent IS h1, so this is a linear apply.
    advance(&mut state, &headers[0]);
    let h2 = advance(&mut state, &headers[1]);
    assert_eq!(
        state.input_blocks.as_ref().unwrap().last_ordering_tip,
        Some(h2)
    );

    // Now jump to h3's SIBLING position by going back to h1: h1's parent
    // is not h2, so this is a switch, not an apply.
    let generation = state
        .input_blocks
        .as_ref()
        .unwrap()
        .processor()
        .generation();
    let h1 = advance(&mut state, &headers[0]);
    let rt = state.input_blocks.as_ref().unwrap();
    assert_eq!(rt.last_ordering_tip, Some(h1));
    assert!(
        rt.processor().generation() > generation,
        "a switch is an event too"
    );
}

/// Round 2, finding 6: spec 9.1 credits 102 / 104 / 105 only when the
/// frame answers a request of ours that is still outstanding. The
/// dispatcher credited 105 whenever serving happened to succeed, which
/// let a peer hold its slot by asking us for data we have — the exact
/// trickle the progress rule exists to refuse.
#[test]
fn serving_a_105_is_progress_only_while_a_request_of_ours_is_outstanding() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer, _rx) = handshake_peer(
        &mut state,
        19680,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        now,
    );

    // Seat an announcement plus its bodies so the 105 below is servable.
    let bodies = [ts::body(0x71, 1)];
    let id = seed_announcement(&mut state, peer, 51, &bodies);
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

    let req = ergo_p2p::message::serialize_input_block_txs_request(
        &ergo_p2p::message::InputBlockTxsRequest {
            input_block_id: id,
            weak_ids: vec![bodies[0].weak_id],
        },
    );

    // Nothing of ours is outstanding for this block any more.
    let before = state.peer_manager.get(&peer).unwrap().last_progress;
    let actions = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST,
        &req,
    );
    assert_eq!(
        sent_frames(&actions, ergo_p2p::message::CODE_INPUT_BLOCK_TXS).len(),
        1,
        "we do serve it"
    );
    assert_eq!(
        state.peer_manager.get(&peer).unwrap().last_progress,
        before,
        "but serving alone is not progress"
    );

    // With a request of ours outstanding for the same block, the frame
    // coincides with something we are waiting on and does count.
    crate::node::register_expectation(
        &mut state,
        peer,
        ergo_p2p::types::ModifierTypeId::InputBlockTransactionIds.as_byte(),
        &[id],
        now,
    );
    let before = state.peer_manager.get(&peer).unwrap().last_progress;
    let _ = send_to(
        &mut state,
        peer,
        ergo_p2p::message::CODE_INPUT_BLOCK_TXS_REQUEST,
        &req,
    );
    assert!(
        state.peer_manager.get(&peer).unwrap().last_progress > before,
        "a 105 that coincides with an outstanding request of ours counts"
    );
    assert_eq!(
        state.coordinator.delivery().status(&id),
        ergo_p2p::delivery::ModifierStatus::Requested,
        "and it does NOT consume that expectation — the peer asking us \
         for bodies is not the peer answering us"
    );
}

// ----- fix round 3 -----

/// Round 3, finding 1: `tracked_request_modifier` asks only for the ids
/// the delivery tracker actually registered, but the Inv path recorded a
/// phase for every id it *wanted*. So a second peer advertising a set
/// that overlaps an outstanding request stole the record for the
/// overlapping id — and the first peer's legitimate reply could then
/// acknowledge nothing.
#[test]
fn a_batch_inv_does_not_steal_another_peer_s_outstanding_expectation() {
    use ergo_p2p::delivery::ModifierStatus;
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let now = Instant::now();
    let (peer_a, _ra) = handshake_peer_with_mode(
        &mut state,
        19690,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        Some(utxo_mode()),
        now,
    );
    let (peer_b, _rb) = handshake_peer_with_mode(
        &mut state,
        19691,
        ergo_p2p::handshake::Version::SUBBLOCKS,
        Some(utxo_mode()),
        now,
    );

    let oa = ts::ordering_announcement([0u8; 32], 1, 61, Vec::new());
    let x = ts::header_id(&oa.header);
    let y = [0x7fu8; 32];

    // A asks for X first, and owns the outstanding request.
    let a_actions = send_to(
        &mut state,
        peer_a,
        ergo_p2p::message::CODE_INV,
        &request_modifier_payload(
            ergo_p2p::types::ModifierTypeId::OrderingBlockAnnouncement.as_byte(),
            &[x],
        ),
    );
    assert_eq!(
        sent_frames(&a_actions, ergo_p2p::message::CODE_REQUEST_MODIFIER).len(),
        1,
        "A's request goes out"
    );
    assert_eq!(
        state.coordinator.delivery().status(&x),
        ModifierStatus::Requested
    );

    // B advertises [X, Y]. X is already in flight from A, so the tracker
    // registers only Y — and only Y may take a phase record.
    let b_actions = send_to(
        &mut state,
        peer_b,
        ergo_p2p::message::CODE_INV,
        &request_modifier_payload(
            ergo_p2p::types::ModifierTypeId::OrderingBlockAnnouncement.as_byte(),
            &[x, y],
        ),
    );
    let b_reqs = sent_frames(&b_actions, ergo_p2p::message::CODE_REQUEST_MODIFIER);
    assert_eq!(b_reqs.len(), 1);
    assert_eq!(
        ergo_p2p::message::deserialize_inv(&b_reqs[0]).unwrap().ids,
        vec![y],
        "B is only asked for the id the tracker registered to it"
    );

    // A's reply must still be recognised as the answer to A's request.
    let before = state.peer_manager.get(&peer_a).unwrap().last_progress;
    let _ = send_to(
        &mut state,
        peer_a,
        ergo_p2p::message::CODE_ORDERING_BLOCK_ANNOUNCEMENT,
        &ergo_p2p::message::serialize_ordering_block_announcement_msg(&oa).unwrap(),
    );
    assert_eq!(
        state.coordinator.delivery().status(&x),
        ModifierStatus::Received,
        "A's 106 acknowledges A's own outstanding request"
    );
    assert!(
        state.peer_manager.get(&peer_a).unwrap().last_progress > before,
        "and A is credited for serving us"
    );
}

/// Round 3, finding 2: the tip classifier only recognised the previous
/// tip's IMMEDIATE child as a linear apply, so two committed blocks
/// between heartbeat ticks — a one-second window, entirely ordinary on a
/// fast chain — were reported as `OrderingReorg`. That is the wrong
/// event, and its handler destructively retains only the new tip's tree.
///
/// Classification is by ancestry: walk parent pointers back from the new
/// tip, bounded by the height delta.
#[test]
fn a_multi_block_linear_advance_is_an_apply_not_a_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let headers = seed_header_chain(&mut state, 6);

    // Start at h1, then commit h2 AND h3 before the next tick fires.
    let h1 = header_id_of(&headers[0]);
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .advance_best_full_block(h1, headers[0].height)
        .unwrap();
    seed_best_ordering(&mut state);

    for h in &headers[1..3] {
        state
            .store
            .as_utxo_mut()
            .unwrap()
            .advance_best_full_block(header_id_of(h), h.height)
            .unwrap();
    }

    assert_eq!(
        classify_tip_change(&state, h1, header_id_of(&headers[2]), headers[2].height),
        TipChange::Applied,
        "h3 descends from h1 through h2 — a linear advance, not a switch"
    );

    let _ = on_tick(&mut state, Instant::now());
    assert_eq!(
        state.input_blocks.as_ref().unwrap().last_ordering_tip,
        Some(header_id_of(&headers[2]))
    );
}

/// The classifier's truth table WITHIN the walk cap, against a real
/// forked header store: descendants at several distances are applies; a
/// sibling, an ancestor (rollback) and an unrelated id are switches.
/// Beyond the cap is covered by
/// `a_linear_advance_beyond_the_walk_cap_is_still_an_apply` and
/// `a_far_advance_that_abandons_the_previous_tip_is_a_reorg`.
#[test]
fn tip_change_classification_truth_table() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let main = seed_header_chain(&mut state, 5);

    // A sibling of h3: same height, different parent-chain position.
    let fork = ts::header(header_id_of(&main[0]), 3, 9_999, [0u8; 32]);
    let fork_id = header_id_of(&fork);
    seed_mainnet_headers(
        &mut state,
        &[(
            fork.height,
            fork_id,
            {
                let (bytes, _) = serialize_header(&fork).unwrap();
                bytes
            },
            fork.clone(),
        )],
        false,
    );

    let id = |i: usize| header_id_of(&main[i]);

    // Descendants, at one and at three removes.
    assert_eq!(
        classify_tip_change(&state, id(0), id(1), main[1].height),
        TipChange::Applied,
        "immediate child"
    );
    assert_eq!(
        classify_tip_change(&state, id(0), id(3), main[3].height),
        TipChange::Applied,
        "three blocks on"
    );

    // Not descendants.
    assert_eq!(
        classify_tip_change(&state, id(1), fork_id, fork.height),
        TipChange::Reorg,
        "a sibling branch is a switch"
    );
    assert_eq!(
        classify_tip_change(&state, id(3), id(1), main[1].height),
        TipChange::Reorg,
        "moving BACK to an ancestor is a switch, not an apply"
    );
    assert_eq!(
        classify_tip_change(&state, id(3), id(3), main[3].height),
        TipChange::Reorg,
        "equal height, and the same id is filtered by the caller"
    );
    assert_eq!(
        classify_tip_change(&state, [0xcc; 32], id(3), main[3].height),
        TipChange::Reorg,
        "an unknown previous tip cannot be shown to be an ancestor"
    );
}

/// A real fork switch still reaches the processor as a reorg, and a
/// reorg still discards the trees a linear apply would keep.
#[test]
fn a_fork_switch_still_reaches_the_processor_as_a_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let main = seed_header_chain(&mut state, 3);

    let h2 = header_id_of(&main[1]);
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .advance_best_full_block(h2, main[1].height)
        .unwrap();
    seed_best_ordering(&mut state);

    // Switch to a sibling of h2 at the same height.
    let fork = ts::header(header_id_of(&main[0]), 2, 8_888, [0u8; 32]);
    let fork_id = header_id_of(&fork);
    seed_mainnet_headers(
        &mut state,
        &[(
            fork.height,
            fork_id,
            {
                let (bytes, _) = serialize_header(&fork).unwrap();
                bytes
            },
            fork.clone(),
        )],
        false,
    );
    assert_eq!(
        classify_tip_change(&state, h2, fork_id, fork.height),
        TipChange::Reorg
    );

    state
        .store
        .as_utxo_mut()
        .unwrap()
        .advance_best_full_block(fork_id, fork.height)
        .unwrap();
    let generation = state
        .input_blocks
        .as_ref()
        .unwrap()
        .processor()
        .generation();
    let _ = on_tick(&mut state, Instant::now());
    let rt = state.input_blocks.as_ref().unwrap();
    assert_eq!(rt.last_ordering_tip, Some(fork_id));
    assert!(
        rt.processor().generation() > generation,
        "the switch reached the processor"
    );
}

/// Round 4: an advance beyond the walk cap was classified as a reorg
/// unconditionally, so a node that fell behind and caught up over a
/// fully stored LINEAR chain reported `OrderingReorg` — the wrong event,
/// and one whose handler discards trees.
///
/// Beyond the cap the question is answered without walking: is the tip
/// we last reported still on the best chain? If it is, the chain moved
/// forward over it.
#[test]
fn a_linear_advance_beyond_the_walk_cap_is_still_an_apply() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let chain = seed_header_chain(&mut state, MAX_LINEAR_CATCHUP + 6);

    let prev = header_id_of(&chain[0]);
    let far = &chain[(MAX_LINEAR_CATCHUP + 1) as usize];
    assert_eq!(
        far.height - chain[0].height,
        MAX_LINEAR_CATCHUP + 1,
        "the fixture must exceed the walk cap"
    );

    assert_eq!(
        classify_tip_change(&state, prev, header_id_of(far), far.height),
        TipChange::Applied,
        "a fully stored linear catch-up is an apply, however far it ran"
    );
}

/// The counterpart: beyond the cap, a tip that ABANDONED the previous
/// tip is still a reorg. `is_on_best_chain` is what separates them.
#[test]
fn a_far_advance_that_abandons_the_previous_tip_is_a_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = live_state(dir.path());
    let chain = seed_header_chain(&mut state, MAX_LINEAR_CATCHUP + 6);

    // A sibling of height 1, stored but never on the best chain.
    let orphan = ts::header([0u8; 32], 1, 77_777, [0u8; 32]);
    let orphan_id = header_id_of(&orphan);
    seed_mainnet_headers(
        &mut state,
        &[(
            orphan.height,
            orphan_id,
            {
                let (bytes, _) = serialize_header(&orphan).unwrap();
                bytes
            },
            orphan.clone(),
        )],
        false,
    );

    let far = &chain[(MAX_LINEAR_CATCHUP + 1) as usize];
    assert!(
        far.height - orphan.height > MAX_LINEAR_CATCHUP,
        "beyond the walk cap"
    );
    assert_eq!(
        classify_tip_change(&state, orphan_id, header_id_of(far), far.height),
        TipChange::Reorg,
        "the previous tip is not on the best chain, so it was abandoned"
    );

    // And a previous tip we no longer hold at all stays a reorg.
    assert_eq!(
        classify_tip_change(&state, [0xde; 32], header_id_of(far), far.height),
        TipChange::Reorg,
        "an unknown previous tip cannot be shown to be an ancestor"
    );
}

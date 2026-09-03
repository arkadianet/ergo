//! Mode 5 (digest verifier) inbound header sync through the REAL executor.
//!
//! Companion to `mode5_executor_replay.rs`, which covers the block-apply
//! half of Mode 5. This file covers the half that runs FIRST on a live
//! node: a peer announces a header, the action loop turns it into
//! `Action::ValidateHeader`, and the executor's header pipeline must
//! validate and persist it against a `StateBackendKind::Digest` backend.
//!
//! The pipeline reaches the store through the `HeaderSectionStore` +
//! `ChainStateRead` traits, which both backends implement — a digest node
//! must complete header sync exactly as a UTXO node does, because Mode 5
//! derives its state root from ADProofs and still needs the full
//! header chain for PoW, difficulty and fork choice.
//!
//! Fixture: `test-vectors/mode5/prior_headers.json` (canonical mainnet
//! header bytes, id-gated by `extract_mode5_prior_headers`) — the same
//! window the replay oracle already pins. Every fed header sits strictly
//! inside a post-EIP-37 128-block difficulty epoch (no fed height has a
//! parent at a multiple of 128), so `previous_heights_for_recalculation`
//! asks for the parent alone and the fixture's lower bound at
//! `1_795_072` is a complete difficulty context.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use ergo_crypto::difficulty::DifficultyParams;
use ergo_p2p::peer::PeerId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use ergo_state::chain::{ChainStateMeta, HeaderAvailability, HeaderMeta};
use ergo_state::{ChainStateRead, DigestStateStore, HeaderSectionStore, StateBackendKind};
use ergo_sync::coordinator::{Action, SyncCoordinator};
use ergo_sync::executor::SyncExecutor;
use ergo_validation::context::ProtocolParams;

/// Seeded chain tip: the fed headers descend from it, so it is the only
/// ancestor the pipeline has to resolve.
const SEED_HEIGHT: u32 = 1_795_073;
/// First fed header.
const FEED_LO: u32 = 1_795_074;
/// Last fed header. `FEED_LO ..= FEED_HI` all have parents strictly
/// inside the 128-block epoch that starts at `1_795_072`.
const FEED_HI: u32 = 1_795_083;

// ----- helpers -----

fn prior_headers() -> BTreeMap<u32, Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors")
        .join("mode5")
        .join("prior_headers.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read prior_headers.json: {e}\n\
             Generate it with: cargo run -p ergo-state --example extract_mode5_prior_headers"
        )
    });
    let v: serde_json::Value = serde_json::from_str(&raw).expect("prior_headers.json");
    let mut out = BTreeMap::new();
    for (k, val) in v["headers"].as_object().expect("headers object") {
        let h: u32 = k.parse().expect("header height key");
        let bytes = hex::decode(val.as_str().expect("header bytes hex")).expect("header bytes");
        out.insert(h, bytes);
    }
    for h in SEED_HEIGHT..=FEED_HI {
        assert!(out.contains_key(&h), "prior_headers.json missing {h}");
    }
    out
}

fn parse_header(bytes: &[u8]) -> Header {
    read_header(&mut VlqReader::new(bytes)).expect("parse header")
}

fn header_id(bytes: &[u8]) -> [u8; 32] {
    *ergo_primitives::digest::blake2b256(bytes).as_bytes()
}

/// Open a genesis-seeded digest store and stamp `SEED_HEIGHT` in as the
/// committed tip: header bytes + meta + height index + chain state. Fork
/// choice is exercised for real by the fed headers, so the seeded
/// cumulative score is the score every subsequent header builds on.
fn seeded_digest_backend(
    dir: &std::path::Path,
    headers: &BTreeMap<u32, Vec<u8>>,
) -> StateBackendKind {
    let mut store = DigestStateStore::open(
        &dir.join("digest_state.redb"),
        ergo_validation::scala_launch(),
        ergo_chain_spec::VotingParams::mainnet(),
        ergo_chain_spec::GenesisParams::mainnet().state_digest,
    )
    .expect("open digest store");

    let seed_bytes = &headers[&SEED_HEIGHT];
    let seed_header = parse_header(seed_bytes);
    let seed_id = header_id(seed_bytes);
    // Any monotonic score works for fork choice — each fed header adds its
    // own decoded difficulty on top, so `is_new_best` must hold all the way.
    let seed_score = (SEED_HEIGHT as u64).to_be_bytes().to_vec();
    let meta = HeaderMeta {
        parent_id: *seed_header.parent_id.as_bytes(),
        height: SEED_HEIGHT,
        cumulative_score: seed_score.clone(),
        pow_validity: 1,
        timestamp: seed_header.timestamp,
    };
    store
        .store_validated_header(&seed_id, seed_bytes, &meta, None)
        .expect("store seed header");
    store
        .seed_header_chain_index_for_test(SEED_HEIGHT, &seed_id)
        .expect("seed chain index");
    store.seed_tip_for_test(
        *seed_header.state_root.as_bytes(),
        ChainStateMeta {
            best_header_id: seed_id,
            best_header_height: SEED_HEIGHT,
            best_header_score: seed_score,
            best_full_block_id: seed_id,
            best_full_block_height: SEED_HEIGHT,
            header_availability: HeaderAvailability::Dense,
        },
    );

    assert_eq!(ChainStateRead::height(&store), SEED_HEIGHT);
    StateBackendKind::Digest(store)
}

// ----- happy path -----

#[test]
fn mode5_inbound_header_advances_the_digest_header_tip() {
    // Regression for the Mode 5 first-inbound-header abort: the executor's
    // header pipeline used to unwrap the backend to a UTXO `StateStore`, so
    // the FIRST header a digest node received from a peer aborted the action
    // loop. `mode_5_survives_a_sync_tick` runs a peerless node and never
    // reaches the pipeline, so nothing caught it.
    //
    // Drives the real `Action::ValidateHeader` path — the same call the node
    // event loop makes for a peer-delivered header — against a digest
    // backend, over canonical mainnet headers. Every header must be
    // accepted, persisted, and advance the header tip.
    let tmp = tempfile::tempdir().expect("tempdir");
    let headers = prior_headers();
    let mut store = seeded_digest_backend(tmp.path(), &headers);

    let mut coordinator = SyncCoordinator::new(SEED_HEIGHT);
    coordinator.sync_state_mut().set_headers_chain_synced();
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let peer: PeerId = "127.0.0.1:9030".parse().expect("peer addr");
    let now = Instant::now();

    for h in FEED_LO..=FEED_HI {
        let bytes = headers[&h].clone();
        let id = header_id(&bytes);
        let actions = executor.execute(
            Action::ValidateHeader {
                peer,
                header_bytes: bytes,
            },
            &mut store,
            &mut coordinator,
            now,
            None,
        );
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Penalize { .. })),
            "digest node penalized the peer for a canonical mainnet header at {h}: {actions:?}"
        );
        assert!(
            store.get_header(&id).expect("read header").is_some(),
            "header {h} was not persisted by the digest backend"
        );
        assert_eq!(
            store.chain_state_meta().best_header_height,
            h,
            "digest header tip did not advance to {h}"
        );
        assert_eq!(
            store.chain_state_meta().best_header_id,
            id,
            "best_header_id must be the header just validated at {h}"
        );
    }

    assert_eq!(
        executor.orphan_headers_len(),
        0,
        "a linear canonical chain must leave no orphans buffered"
    );
}

// ----- error paths -----

#[test]
fn mode5_unlinked_header_is_buffered_not_fatal() {
    // The pipeline's non-happy branch must also stay on the digest backend:
    // a header whose parent is absent is buffered as an orphan (the same
    // ParentNotFound path a UTXO node takes), not a panic and not a tip
    // advance. Feeding `FEED_LO + 1` first leaves `FEED_LO` missing.
    let tmp = tempfile::tempdir().expect("tempdir");
    let headers = prior_headers();
    let mut store = seeded_digest_backend(tmp.path(), &headers);

    let mut coordinator = SyncCoordinator::new(SEED_HEIGHT);
    coordinator.sync_state_mut().set_headers_chain_synced();
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );

    let orphan = headers[&(FEED_LO + 1)].clone();
    executor.execute(
        Action::ValidateHeader {
            peer: "127.0.0.1:9030".parse().expect("peer addr"),
            header_bytes: orphan,
        },
        &mut store,
        &mut coordinator,
        Instant::now(),
        None,
    );

    assert_eq!(
        executor.orphan_headers_len(),
        1,
        "header with a missing parent must be buffered as an orphan"
    );
    assert_eq!(
        store.chain_state_meta().best_header_height,
        SEED_HEIGHT,
        "an unlinked header must not advance the digest header tip"
    );
}

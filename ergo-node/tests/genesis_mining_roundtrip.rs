//! Increment 4 acceptance: build block 1 — the genesis block — on a BARE devnet
//! genesis, CPU-solve it at difficulty 1, and drive it through the SAME apply
//! path a submitted / peer-received block takes:
//!   verify_solution → apply_mined_block → process_header_cfg [→ process_genesis_header]
//!                   → process_block [→ apply_genesis].
//! The tip must advance to height 1 with block 1's id. This proves the built
//! genesis block is consensus-valid END TO END (its `state_root` matches the
//! post-coinbase UTXO digest that `apply_genesis` recomputes) — not merely
//! well-shaped (which `ergo-mining/tests/genesis_candidate.rs` already pins).
//!
//! This is the DEVNET block-1 scenario the node hits from a fresh start; the
//! test drives the mechanism directly (no node boot / HTTP) by calling
//! `generate_candidate` with `Some(GenesisBuildInputs)` and the canonical
//! apply functions in sequence.

use ergo_chain_spec::Network;
use ergo_crypto::autolykos::common::calc_n;
use ergo_crypto::autolykos::v2::hit_for_v2;
use ergo_crypto::difficulty::{get_target, DifficultyParams};
use ergo_mempool::MempoolReadSnapshot;
use ergo_mining::candidate::{generate_candidate, BuildMode};
use ergo_mining::emission_rules::MonetarySettings;
use ergo_mining::genesis::{genesis_emission_box, synthetic_genesis_header, GenesisBuildInputs};
use ergo_mining::solution::{verify_solution, SolutionOutcome};
use ergo_mining::submit::apply_mined_block;
use ergo_mining::work_message::MinerSolution;
use ergo_node::genesis::genesis_boxes_for;
use ergo_ser::difficulty::encode_compact_bits;
use ergo_state::store::StateStore;
use ergo_state::StateBackendKind;
use ergo_sync::block_proc::process_block;
use ergo_sync::header_proc::process_header_cfg;
use ergo_validation::context::ProtocolParams;
use num_bigint::BigUint;

const MINER_PK: [u8; 33] = [0x02u8; 33];

/// CPU-solve a difficulty-1 candidate: the first nonce whose Autolykos v2 hit is
/// strictly below the target (strict `<`, so the header also passes the apply
/// path's authoritative `verify_pow_solution` re-check). At difficulty 1 the
/// target is the secp256k1 order, so the first nonce essentially always wins.
fn solve(msg: &[u8; 32], height: u32, version: u8, n_bits: u32) -> [u8; 8] {
    let n = calc_n(version, height);
    let target = get_target(n_bits);
    for i in 0u64..1_000_000 {
        let nonce = i.to_be_bytes();
        if hit_for_v2(msg, &nonce, height, n) < target {
            return nonce;
        }
    }
    panic!("no difficulty-1 solution in 1e6 nonces (should be immediate)");
}

#[test]
fn devnet_mines_and_applies_block_1_from_bare_genesis() {
    let config = DifficultyParams::devnet();

    // 1. Bare devnet genesis: seed the REAL (testnet) genesis box set, exactly
    //    what the live devnet seeds via `genesis_boxes_for(Devnet)`.
    let dir = tempfile::tempdir().unwrap();
    // Open with the devnet launch params (block_version 2, Autolykos v2) — the
    // same params the live devnet boots with, so the built header round-trips.
    let mut store = StateStore::open_with_launch_params(
        dir.path().join("state.redb").as_path(),
        ergo_validation::active_params::scala_launch_for_network(Network::Devnet),
    )
    .unwrap();
    let genesis_boxes = genesis_boxes_for(Network::Devnet);
    store.initialize_genesis(&genesis_boxes).unwrap();
    assert_eq!(
        store.chain_state().best_full_block_height,
        0,
        "bare genesis starts at height 0"
    );

    // 2. Resolve genesis build inputs the way the node will at boot: synthetic
    //    parent header carrying the ACTUAL committed genesis state root + the
    //    initial-difficulty nBits, plus the resolved genesis emission box.
    let initial_nbits = encode_compact_bits(&BigUint::from_bytes_be(&config.initial_difficulty));
    let parent_header = synthetic_genesis_header(store.root_digest(), initial_nbits);
    let emission_box = genesis_emission_box(&genesis_boxes).expect("resolve genesis emission box");
    let inputs = GenesisBuildInputs {
        parent_header,
        emission_box,
    };

    // 3. Build block 1.
    let (candidate, _work, _timings) = generate_candidate(
        &store,
        BuildMode::Full,
        MempoolReadSnapshot::empty(),
        &MINER_PK,
        &MonetarySettings::mainnet(),
        None,
        None,
        &config,
        &[],
        &std::collections::BTreeMap::new(),
        &ergo_validation::VotingSettings::mainnet(),
        &mut Vec::new(),
        Some(&inputs),
    )
    .expect("genesis candidate builds")
    .expect("candidate is Some");
    assert_eq!(candidate.header.height, 1, "block 1");
    assert_eq!(candidate.parent_id, [0u8; 32], "parent is genesis sentinel");

    // 4. CPU-solve at difficulty 1, then run the API-side solution acceptance.
    let nonce = solve(
        &candidate.msg,
        candidate.header.height,
        candidate.header.version,
        candidate.header.n_bits,
    );
    let solution = MinerSolution { nonce, pk: None };
    let submitted = match verify_solution(&candidate, &solution, &store).expect("verify_solution") {
        SolutionOutcome::Accepted(b) => b,
        other => panic!("solution not accepted: {other:?}"),
    };

    // 5. Drive the canonical apply path — identical to mining_dispatch's submit
    //    handler and to peer-block ingest.
    let mut backend = StateBackendKind::Utxo(store);
    let (header_id, header_bytes) =
        apply_mined_block(backend.as_utxo_mut().unwrap(), submitted).expect("apply_mined_block");
    process_header_cfg(backend.as_utxo_mut().unwrap(), &header_bytes, &config)
        .expect("process_header_cfg routes to process_genesis_header");
    let processed = process_block(
        &mut backend,
        &header_id,
        &ProtocolParams::mainnet_default(),
        None,
        None,
        None,
        None,
        None,
    )
    .expect("process_block routes to apply_genesis and applies");
    assert_eq!(processed.height, 1, "processed block is height 1");

    // 6. The tip advanced to height 1 with block 1's id — block 1 is
    //    consensus-valid end to end.
    let s = backend.as_utxo().expect("utxo backend");
    assert_eq!(
        s.chain_state().best_full_block_height,
        1,
        "tip advanced to height 1"
    );
    assert_eq!(
        s.chain_state().best_full_block_id,
        header_id,
        "tip is the mined block 1"
    );
}

//! Devnet genesis-block build: `generate_candidate` must build block 1 — the
//! genesis block — on a BARE genesis, where there is no stored parent header and
//! no parent block to read a difficulty window / emission box from. The block it
//! produces must have the consensus shape the apply path accepts
//! (`ergo_sync::header_proc::process_genesis_header` + block-extension
//! validation): height 1, `parent_id == [0;32]`, an EMPTY extension (block 1 is
//! the first block — height 2 is the first to carry interlinks), `n_bits`
//! decoding to `initial_difficulty`, and a coinbase that spends the seeded
//! genesis emission box.
//!
//! Oracles for the shape: `test-vectors/mining/interlinks_corpus/1.json`
//! (height-1 block has 0 extension fields) and `process_genesis_header`
//! (`n_bits == encode(initial_difficulty)`, parent lookup bypassed).

use ergo_crypto::difficulty::DifficultyParams;
use ergo_mempool::MempoolReadSnapshot;
use ergo_mining::candidate::{generate_candidate, BuildMode};
use ergo_mining::emission_rules::MonetarySettings;
use ergo_mining::genesis::{genesis_emission_box, synthetic_genesis_header, GenesisBuildInputs};
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::difficulty::{decode_compact_bits, encode_compact_bits};
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::AdditionalRegisters;
use ergo_state::store::StateStore;
use num_bigint::BigUint;

const MINER_PK: [u8; 33] = [0x02u8; 33];

/// The testnet/devnet genesis emission box: the network-identical emission tree,
/// value 93,409,132,500,000,000, creation height 0, no registers — matching
/// `test-vectors/testnet/genesis_boxes.json` box[0]. Returns the box plus the
/// `(box_id, serialized_bytes)` pair `initialize_genesis` / `genesis_emission_box`
/// consume.
fn genesis_emission_box_seed() -> (ErgoBox, ([u8; 32], Vec<u8>)) {
    let tree_bytes = ergo_chain_spec::emission_tree_bytes();
    let mut r = VlqReader::new(&tree_bytes);
    let tree = read_ergo_tree(&mut r).unwrap();
    let cand = ErgoBoxCandidate::from_trusted_raw_parts(
        93_409_132_500_000_000,
        tree,
        tree_bytes,
        0,
        Vec::new(),
        AdditionalRegisters::empty(),
        vec![0x00],
    );
    let eb = ErgoBox {
        candidate: cand,
        transaction_id: ModifierId::from_bytes([0u8; 32]),
        index: 0,
    };
    let id = *eb.box_id().expect("emission box id").as_bytes();
    let bytes = serialize_ergo_box(&eb).expect("serialize emission box");
    (eb, (id, bytes))
}

#[test]
fn generate_candidate_builds_block_1_on_bare_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    let (em_box, seed) = genesis_emission_box_seed();
    store
        .initialize_genesis(std::slice::from_ref(&seed))
        .unwrap();

    // Genesis build inputs: the synthetic height-0 header carries the seeded
    // genesis state root (block 1's `last_block_utxo_root`) and the initial
    // difficulty; the emission box is resolved from the genesis box set.
    let config = DifficultyParams::mainnet();
    let initial_nbits = encode_compact_bits(&BigUint::from_bytes_be(&config.initial_difficulty));
    let parent_header = synthetic_genesis_header(store.root_digest(), initial_nbits);
    let emission_box =
        genesis_emission_box(std::slice::from_ref(&seed)).expect("resolve genesis emission box");
    let inputs = GenesisBuildInputs {
        parent_header,
        emission_box,
    };

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

    // 1. Height 1, parent = the zeroed genesis sentinel.
    assert_eq!(candidate.header.height, 1, "block 1");
    assert_eq!(candidate.parent_id, [0u8; 32], "parent is genesis sentinel");
    assert_eq!(
        *candidate.header.parent_id.as_bytes(),
        [0u8; 32],
        "header parent_id is genesis sentinel"
    );

    // 2. EMPTY extension — block 1 carries no interlinks (oracle: interlinks
    //    corpus height 1 has 0 extension fields).
    assert!(
        candidate.extension_fields.is_empty(),
        "genesis block has an empty extension, got {:?}",
        candidate.extension_fields
    );

    // 3. n_bits decodes to the initial difficulty (what process_genesis_header
    //    requires for block 1).
    let header_nbits = encode_compact_bits(&decode_compact_bits(candidate.header.n_bits));
    assert_eq!(
        header_nbits, initial_nbits,
        "genesis n_bits == encode(initial_difficulty)"
    );

    // 4. The coinbase (tx[0]) spends the seeded genesis emission box.
    let em_box_id = *em_box.box_id().expect("emission box id").as_bytes();
    let coinbase = candidate
        .transactions
        .first()
        .expect("candidate has a coinbase tx");
    assert_eq!(
        *coinbase.inputs[0].box_id.as_bytes(),
        em_box_id,
        "coinbase spends the genesis emission box"
    );
}

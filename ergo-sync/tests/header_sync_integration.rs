//! Integration tests for header processing pipeline against real mainnet data.
//!
//! Tests process_header() with real headers from test vectors, verifying:
//! - Height check rejection
//! - Cumulative score accumulation and best-header promotion
//! - is_on_best_chain correctness via ChainView impl on StateStore

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::header::read_header;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_state::chain::HeaderMeta;
use ergo_state::store::StateStore;
use ergo_state::{ChainStateRead, HeaderSectionStore};

use ergo_sync::header_proc::HeaderProcessError;

// ---- Helpers (same as ergo-state tests) ----

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct GenesisBoxJson {
    #[serde(rename = "boxId")]
    box_id: String,
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u32,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: std::collections::HashMap<String, String>,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
}

fn parse_genesis_box(json: &GenesisBoxJson) -> ErgoBox {
    let tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();
    let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
    for (key, val_hex) in &json.additional_registers {
        let reg_idx = match key.as_str() {
            "R4" => 0,
            "R5" => 1,
            "R6" => 2,
            "R7" => 3,
            "R8" => 4,
            "R9" => 5,
            _ => panic!("unknown register {key}"),
        };
        let val_bytes = hex::decode(val_hex).unwrap();
        let mut vr = VlqReader::new(&val_bytes);
        let (tpe, value) = read_constant(&mut vr).unwrap();
        reg_vec.push((reg_idx, RegisterValue { tpe, value }));
    }
    reg_vec.sort_by_key(|(idx, _)| *idx);
    let registers = AdditionalRegisters {
        registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
    };
    let candidate = ErgoBoxCandidate::new(
        json.value,
        ergo_tree,
        json.creation_height,
        Vec::new(),
        registers,
    )
    .unwrap();
    let tx_id_bytes: [u8; 32] = hex::decode(&json.transaction_id)
        .unwrap()
        .try_into()
        .unwrap();
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id_bytes),
        index: json.index,
    }
}

fn init_genesis(store: &mut StateStore) {
    let genesis_data =
        std::fs::read_to_string("../test-vectors/mainnet/genesis_boxes.json").unwrap();
    let genesis_boxes: Vec<GenesisBoxJson> = serde_json::from_str(&genesis_data).unwrap();
    let boxes: Vec<([u8; 32], Vec<u8>)> = genesis_boxes
        .iter()
        .map(|json_box| {
            let ergo_box = parse_genesis_box(json_box);
            let box_id = ergo_box.box_id().unwrap();
            let serialized = serialize_ergo_box(&ergo_box).unwrap();
            (*box_id.as_bytes(), serialized)
        })
        .collect();
    store.initialize_genesis(&boxes).unwrap();
}

fn load_headers() -> Vec<serde_json::Value> {
    let data = std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    serde_json::from_str(&data).unwrap()
}

fn load_headers_file(name: &str) -> Vec<serde_json::Value> {
    let path = format!("../test-vectors/mainnet/{name}");
    let data =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    serde_json::from_str(&data).unwrap()
}

fn get_header_bytes(headers: &[serde_json::Value], height: u32) -> Vec<u8> {
    let h = headers
        .iter()
        .find(|h| h["height"].as_u64().unwrap() == height as u64)
        .unwrap();
    hex::decode(h["bytes"].as_str().unwrap()).unwrap()
}

#[allow(dead_code)]
fn get_header_id(headers: &[serde_json::Value], height: u32) -> [u8; 32] {
    let h = headers
        .iter()
        .find(|h| h["height"].as_u64().unwrap() == height as u64)
        .unwrap();
    hex::decode(h["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[allow(dead_code)]
fn seed_genesis_header(store: &mut StateStore, headers: &[serde_json::Value]) {
    // Block 1's parent_id = genesis header ID.
    let h1_bytes = get_header_bytes(headers, 1);
    let mut r = VlqReader::new(&h1_bytes);
    let h1 = read_header(&mut r).unwrap();
    let genesis_header_id = *h1.parent_id.as_bytes();

    // We need the actual genesis header bytes. We'll load them from test vectors
    // if available, or synthesize a minimal entry in header_meta.
    // For these tests, just store the genesis header metadata so process_header
    // can find the parent.
    let genesis_meta = HeaderMeta {
        parent_id: [0u8; 32],
        height: 0,
        cumulative_score: vec![1], // genesis difficulty
        pow_validity: 1,
        timestamp: 0,
    };
    store
        .store_header_meta(&genesis_header_id, &genesis_meta)
        .unwrap();

    // Also store the actual genesis header bytes (block 1 needs the parent
    // header for timestamp check). We'll use a dummy — the important thing
    // is that parent_id lookup works.
    // NOTE: This means validate_header will fail on timestamp/PoW checks
    // for block 1. These integration tests focus on the pipeline mechanics
    // (height check, score accumulation, best-header promotion), not full
    // cryptographic validation. Full validation is covered by ergo-validation tests.

    // Update chain state to point to genesis
    store
        .test_force_set_best_header_unsafe(genesis_header_id, 0, vec![1])
        .unwrap();
}

// ---- Helpers for seeding header 1 as a "known parent" ----

/// Seed header 1 into the store so process_header can find it as a parent
/// for header 2. Stores both the raw bytes and the header_meta.
fn seed_header_1(store: &mut StateStore, headers: &[serde_json::Value]) {
    let h1_bytes = get_header_bytes(headers, 1);
    let h1_id_bytes = get_header_id(headers, 1);

    // Parse header 1 to get its fields
    let mut r = VlqReader::new(&h1_bytes);
    let h1 = read_header(&mut r).unwrap();

    // Store header bytes
    store.store_header(&h1_id_bytes, &h1_bytes).unwrap();

    // Store header meta with initial cumulative score
    let meta = HeaderMeta {
        parent_id: *h1.parent_id.as_bytes(),
        height: h1.height,
        cumulative_score: ergo_ser::difficulty::decode_compact_bits(h1.n_bits).to_bytes_be(),
        pow_validity: 1,
        timestamp: h1.timestamp,
    };
    store.store_header_meta(&h1_id_bytes, &meta).unwrap();
    store
        .test_force_set_best_header_unsafe(h1_id_bytes, h1.height, meta.cumulative_score.clone())
        .unwrap();
}

// ---- Tests ----

// ----- happy path -----

#[test]
fn process_header_with_real_mainnet_header() {
    // Process header 2 with header 1 as the known parent.
    // This exercises the full process_header pipeline: deserialize, parent
    // lookup, height check, PoW validation, cumulative score, persist.
    use ergo_sync::header_proc::process_header;

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let headers = load_headers();
    seed_header_1(&mut store, &headers);

    let h2_bytes = get_header_bytes(&headers, 2);
    let h2_id = get_header_id(&headers, 2);

    let result = process_header(&mut store, &h2_bytes);
    match result {
        Ok(processed) => {
            assert_eq!(processed.header_id, h2_id);
            assert_eq!(processed.height, 2);
            assert!(processed.is_new_best, "h2 should become new best header");
            // Verify persistence
            assert!(store.get_header(&h2_id).unwrap().is_some());
            let meta = store.get_header_meta(&h2_id).unwrap().unwrap();
            assert_eq!(meta.height, 2);
            assert_eq!(meta.pow_validity, 1);
            assert!(!meta.cumulative_score.is_empty());
            // Score should be h1_score + h2_difficulty
            assert_eq!(store.chain_state().best_header_height, 2);
            assert_eq!(store.chain_state().best_header_id, h2_id);
        }
        Err(e) => panic!("process_header failed: {e}"),
    }
}

#[test]
fn process_header_refuses_child_of_invalidated_parent() {
    // Regression for the branch-invalidation liveness fix: once a header is
    // durably invalidated (full-block validation reject), NO descendant may
    // extend it. process_header_inner rejects a header whose parent is
    // invalid, so a peer cannot re-grow the dead branch one header at a time
    // and re-wedge the apply loop. Scala parity: HeadersProcessor fails a
    // header whose parent isSemanticallyValid == Invalid.
    use ergo_sync::header_proc::process_header;

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let headers = load_headers();
    seed_header_1(&mut store, &headers);

    // Durably invalidate header 1 (the parent of header 2).
    let h1_id = get_header_id(&headers, 1);
    let mut h1_meta = store.get_header_meta(&h1_id).unwrap().unwrap();
    h1_meta.pow_validity = 3; // full-block validation invalid
    store.store_header_meta(&h1_id, &h1_meta).unwrap();
    assert!(store.is_invalid(&h1_id).unwrap());

    let h2_bytes = get_header_bytes(&headers, 2);
    let err = process_header(&mut store, &h2_bytes)
        .expect_err("child of an invalidated parent must be refused");
    assert!(
        matches!(err, HeaderProcessError::Invalid { .. }),
        "expected Invalid, got {err:?}"
    );
}

#[test]
fn process_header_chain_2_through_5() {
    // Process headers 2-5 sequentially, verifying cumulative score grows.
    use ergo_sync::header_proc::process_header;

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let headers = load_headers();
    seed_header_1(&mut store, &headers);

    let mut prev_score = store.chain_state().best_header_score.clone();

    for height in 2..=5 {
        let h_bytes = get_header_bytes(&headers, height);
        let processed = process_header(&mut store, &h_bytes)
            .unwrap_or_else(|e| panic!("process_header failed at height {height}: {e}"));
        assert_eq!(processed.height, height);
        assert!(processed.is_new_best);
        // Score must be strictly increasing
        let new_score = store.chain_state().best_header_score.clone();
        assert!(
            new_score > prev_score,
            "cumulative score must increase: {prev_score:?} -> {new_score:?}"
        );
        prev_score = new_score;
    }
    assert_eq!(store.chain_state().best_header_height, 5);
}

#[test]
fn process_header_rejects_height_mismatch() {
    // Process header 2 but with a parent whose metadata claims height 5
    // instead of 1. Header 2 (height=2) should fail: expected 6, got 2.
    use ergo_sync::header_proc::process_header;

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let headers = load_headers();

    // Seed header 1 with WRONG height in metadata
    let h1_bytes = get_header_bytes(&headers, 1);
    let h1_id = get_header_id(&headers, 1);
    let mut r = VlqReader::new(&h1_bytes);
    let h1 = read_header(&mut r).unwrap();
    store.store_header(&h1_id, &h1_bytes).unwrap();
    store
        .store_header_meta(
            &h1_id,
            &HeaderMeta {
                parent_id: *h1.parent_id.as_bytes(),
                height: 5, // WRONG — real height is 1
                cumulative_score: vec![1],
                pow_validity: 1,
                timestamp: h1.timestamp,
            },
        )
        .unwrap();
    store
        .test_force_set_best_header_unsafe(h1_id, 5, vec![1])
        .unwrap();

    // Try to process header 2 (height=2, but parent claims height=5 → expects 6)
    let h2_bytes = get_header_bytes(&headers, 2);
    let result = process_header(&mut store, &h2_bytes);
    match result {
        Err(HeaderProcessError::HeightMismatch {
            expected: 6,
            got: 2,
        }) => {} // correct
        Err(e) => panic!("expected HeightMismatch, got: {e}"),
        Ok(_) => panic!("should have rejected height mismatch"),
    }
}

#[test]
fn process_header_rejects_duplicate() {
    use ergo_sync::header_proc::process_header;

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let headers = load_headers();
    seed_header_1(&mut store, &headers);

    let h2_bytes = get_header_bytes(&headers, 2);
    process_header(&mut store, &h2_bytes).unwrap(); // first time: ok
    let result = process_header(&mut store, &h2_bytes); // second time: duplicate
    assert!(matches!(
        result,
        Err(HeaderProcessError::AlreadyKnown { .. })
    ));
}

#[test]
fn is_on_best_chain_rejects_fork_headers() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    // Build a chain: genesis → h1 → h2 (best chain)
    //                           └→ h1_fork (fork)
    let genesis_id = [0x01; 32];
    store
        .store_header_meta(
            &genesis_id,
            &HeaderMeta {
                parent_id: [0u8; 32],
                height: 0,
                cumulative_score: vec![1],
                pow_validity: 1,
                timestamp: 1000,
            },
        )
        .unwrap();
    store
        .test_force_set_best_header_unsafe(genesis_id, 0, vec![1])
        .unwrap();
    store
        .test_force_put_header_chain_index(0, &genesis_id)
        .unwrap();

    let h1_id = [0x02; 32];
    store
        .store_header_meta(
            &h1_id,
            &HeaderMeta {
                parent_id: genesis_id,
                height: 1,
                cumulative_score: vec![10],
                pow_validity: 1,
                timestamp: 2000,
            },
        )
        .unwrap();
    store
        .test_force_set_best_header_unsafe(h1_id, 1, vec![10])
        .unwrap();
    store.test_force_put_header_chain_index(1, &h1_id).unwrap();

    let h2_id = [0x03; 32];
    store
        .store_header_meta(
            &h2_id,
            &HeaderMeta {
                parent_id: h1_id,
                height: 2,
                cumulative_score: vec![20],
                pow_validity: 1,
                timestamp: 3000,
            },
        )
        .unwrap();
    store
        .test_force_set_best_header_unsafe(h2_id, 2, vec![20])
        .unwrap();
    store.test_force_put_header_chain_index(2, &h2_id).unwrap();

    // Fork header: same parent as h1 (genesis), same height 1, lower score
    let h1_fork_id = [0xFF; 32];
    store
        .store_header_meta(
            &h1_fork_id,
            &HeaderMeta {
                parent_id: genesis_id,
                height: 1,
                cumulative_score: vec![5],
                pow_validity: 1,
                timestamp: 2001,
            },
        )
        .unwrap();
    // NOT updated as best — lower score

    // Check best chain membership via ChainView impl on StateStore
    use ergo_sync::coordinator::ChainView;
    let view = &store;

    assert!(
        view.is_on_best_chain(&genesis_id),
        "genesis should be on best chain"
    );
    assert!(view.is_on_best_chain(&h1_id), "h1 should be on best chain");
    assert!(
        view.is_on_best_chain(&h2_id),
        "h2 should be on best chain (it IS best)"
    );
    assert!(
        !view.is_on_best_chain(&h1_fork_id),
        "fork header should NOT be on best chain"
    );
}

#[test]
fn is_on_best_chain_unknown_header_returns_false() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    use ergo_sync::coordinator::ChainView;
    let view = &store;
    assert!(!view.is_on_best_chain(&[0x99; 32]));
}

/// Process mainnet headers 2-1025 through the real pipeline, exercising
/// the first pre-EIP37 epoch boundary at height 1025 (parent 1024 is a
/// multiple of epoch_length 1024).
///
/// This is the definitive test that epoch-header collection works: at
/// height 1025, verify_header_difficulty needs headers at heights 0 and
/// 1024. The pipeline must walk the full parent chain to find them.
///
/// Note: difficulty constants are mainnet-hardcoded. Testnet uses different
/// parameters and would need a configurable difficulty module — queued for
/// a follow-up pass.
#[test]
fn process_header_across_epoch_boundary_1025() {
    use ergo_sync::header_proc::process_header;

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);

    let headers = load_headers_file("headers_1_2000.json");
    // Seed header 1 manually (its parent is genesis, not in test vectors)
    seed_header_1(&mut store, &headers);

    let mut last_height = 1u32;
    let mut prev_score = num_bigint::BigUint::from_bytes_be(&store.chain_state().best_header_score);

    // Process headers 2 through 1025
    for height in 2..=1025 {
        let h_bytes = get_header_bytes(&headers, height);
        let result = process_header(&mut store, &h_bytes);
        match result {
            Ok(processed) => {
                assert_eq!(processed.height, height);
                assert!(processed.is_new_best, "header {height} should be new best");
                let new_score =
                    num_bigint::BigUint::from_bytes_be(&store.chain_state().best_header_score);
                assert!(
                    new_score > prev_score,
                    "score must increase at height {height}: {prev_score} -> {new_score}"
                );
                prev_score = new_score;
                last_height = height;
            }
            Err(e) => {
                panic!("process_header failed at height {height}: {e}");
            }
        }
    }

    assert_eq!(last_height, 1025);
    assert_eq!(store.chain_state().best_header_height, 1025);

    // Verify the epoch boundary was crossed: height 1025 required headers
    // at heights 0 and 1024 for difficulty recalculation.
    // If epoch-header collection was broken, process_header would have
    // failed at height 1025 with EpochHeaderMissing or a difficulty error.
}

/// End-to-end executor test: ValidateHeader → on_header_validated →
/// section requests → simulate section delivery → AssembleBlock →
/// process_block → on_block_applied.
///
/// Uses real mainnet header + transaction data for block 2.
/// Constructs BlockTransactions and Extension section bytes, feeds them
/// through the coordinator + executor pipeline.
#[test]
fn executor_end_to_end_block_2() {
    use ergo_p2p::types::InvData;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::block_transactions::write_block_transactions;
    use ergo_ser::extension::write_extension;
    use ergo_ser::header::read_header;
    use ergo_ser::modifier_id::compute_section_id;
    use ergo_ser::transaction::read_transaction;
    use ergo_state::store::StateStore;
    use ergo_sync::coordinator::{Action, SyncCoordinator};

    use ergo_sync::executor::SyncExecutor;
    use ergo_validation::context::ProtocolParams;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9030);
    let now = Instant::now();

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);

    let headers = load_headers();
    seed_header_1(&mut store, &headers);

    // Also need to apply block 1 to UTXO state so block 2's inputs exist
    let tx_data: Vec<serde_json::Value> = {
        let data =
            std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
        serde_json::from_str(&data).unwrap()
    };
    let digests_data: Vec<serde_json::Value> = {
        let data =
            std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
        serde_json::from_str(&data).unwrap()
    };
    // Apply block 1 to UTXO state
    {
        let tx1_hex = tx_data
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == 1)
            .unwrap()["bytes"]
            .as_str()
            .unwrap();
        let tx1 = read_transaction(&mut VlqReader::new(&hex::decode(tx1_hex).unwrap())).unwrap();
        let digest1: [u8; 33] = {
            let d = digests_data
                .iter()
                .find(|d| d["height"].as_u64().unwrap() == 1)
                .unwrap();
            hex::decode(d["stateRoot"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let h1_id = get_header_id(&headers, 1);
        store
            .apply_block_unchecked_for_test(
                1,
                &h1_id,
                &ergo_primitives::digest::ADDigest::from_bytes(digest1),
                &[tx1],
            )
            .unwrap();
    }

    // Setup is done on the concrete UTXO store; the executor drives the
    // backend enum, so wrap here before the sync interactions.
    let mut store = ergo_state::StateBackendKind::Utxo(store);

    // Create coordinator and executor
    let mut coordinator = SyncCoordinator::new(1); // best_full_block = 1
                                                   // Force headers_chain_synced so section requests are produced
                                                   // (test uses old mainnet headers whose timestamps are not "recent")
    coordinator.sync_state_mut().set_headers_chain_synced();
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
    );

    // === Step 1: ValidateHeader for block 2 ===
    let h2_bytes = get_header_bytes(&headers, 2);
    let h2_id = get_header_id(&headers, 2);
    let actions = executor.execute_all(
        vec![Action::ValidateHeader {
            peer,
            header_bytes: h2_bytes.clone(),
        }],
        &mut store,
        &mut coordinator,
        now,
        None,
    );

    // Should produce RequestModifier actions for block sections
    let request_actions: Vec<_> = actions
        .iter()
        .filter(|a| matches!(a, Action::SendToPeer { code: 22, .. }))
        .collect();
    assert!(
        !request_actions.is_empty(),
        "executor should produce section requests after header validation"
    );

    // Verify header 2 is now stored
    assert!(store.get_header(&h2_id).unwrap().is_some());
    assert_eq!(store.chain_state_meta().best_header_height, 2);

    // === Step 2: Construct and deliver block sections ===
    // Parse header 2 for section roots
    let h2 = read_header(&mut VlqReader::new(&h2_bytes)).unwrap();

    // Construct serialized BlockTransactions section
    let tx2_hex = tx_data
        .iter()
        .find(|t| t["height"].as_u64().unwrap() == 2)
        .unwrap()["bytes"]
        .as_str()
        .unwrap();
    let tx2 = read_transaction(&mut VlqReader::new(&hex::decode(tx2_hex).unwrap())).unwrap();
    let bt = ergo_ser::block_transactions::BlockTransactions {
        header_id: ergo_primitives::digest::ModifierId::from_bytes(h2_id),
        transactions: vec![tx2],
    };
    let bt_bytes = {
        let mut w = VlqWriter::new();
        write_block_transactions(&mut w, &bt).unwrap();
        w.result()
    };

    // Construct serialized Extension section with real extension data.
    // Block 2's extension has one field: key=0100, value=01+block1_id
    let ext = ergo_ser::extension::Extension {
        header_id: ergo_primitives::digest::ModifierId::from_bytes(h2_id),
        fields: vec![ergo_ser::extension::ExtensionField {
            key: [0x01, 0x00],
            value: {
                let mut v = vec![0x01];
                v.extend_from_slice(&get_header_id(&headers, 1));
                v
            },
        }],
    };
    let ext_bytes = {
        let mut w = VlqWriter::new();
        write_extension(&mut w, &ext).expect("synthetic extension fits wire bounds");
        w.result()
    };

    // Compute section modifier IDs
    let tx_section_id = compute_section_id(102, &h2_id, h2.transactions_root.as_bytes());
    let ext_section_id = compute_section_id(108, &h2_id, h2.extension_root.as_bytes());

    // Deliver sections through the coordinator + executor pipeline
    // First, register them as requested (simulate Inv + RequestModifier)
    let inv_tx = InvData {
        type_id: 102,
        ids: vec![tx_section_id],
    };
    let inv_ext = InvData {
        type_id: 108,
        ids: vec![ext_section_id],
    };
    let chain_view = &store;
    coordinator.on_inv(peer, &inv_tx, chain_view, now);
    coordinator.on_inv(peer, &inv_ext, chain_view, now);

    // Deliver the sections
    let tx_actions = coordinator.on_modifier_received(peer, 102, tx_section_id, bt_bytes);
    let ext_actions = coordinator.on_modifier_received(peer, 108, ext_section_id, ext_bytes);

    // Execute all resulting actions (PersistSection + possibly AssembleBlock)
    let mut all_actions = tx_actions;
    all_actions.extend(ext_actions);
    let _network_actions =
        executor.execute_all(all_actions, &mut store, &mut coordinator, now, None);

    // === Step 3: Verify block was applied ===
    assert_eq!(
        store.height(),
        2,
        "UTXO state should be at height 2 after block application"
    );
    assert_eq!(coordinator.sync_state().best_full_block_height(), 2);

    // Verify state digest matches expected
    let expected_digest: [u8; 33] = {
        let d = digests_data
            .iter()
            .find(|d| d["height"].as_u64().unwrap() == 2)
            .unwrap();
        hex::decode(d["stateRoot"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let actual_digest = store.as_utxo_mut().unwrap().root_digest();
    assert_eq!(
        *actual_digest.as_bytes(),
        expected_digest,
        "state digest at height 2 should match Scala node"
    );
}

/// Restart/resume test: process headers 2-5, drop executor, recreate,
/// hydrate from store, verify the recent-header window is populated.
#[test]
fn executor_hydrate_restores_recent_headers() {
    use ergo_sync::executor::SyncExecutor;
    use ergo_sync::header_proc::process_header;
    use ergo_validation::context::ProtocolParams;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    // Phase 1: process headers 2-5 with one executor
    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        let headers = load_headers();
        seed_header_1(&mut store, &headers);

        // Apply block 1 to UTXO so chain state is at height 1
        let tx_data: Vec<serde_json::Value> = {
            let data =
                std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
            serde_json::from_str(&data).unwrap()
        };
        let digests_data: Vec<serde_json::Value> = {
            let data =
                std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
            serde_json::from_str(&data).unwrap()
        };
        let tx1_hex = tx_data
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == 1)
            .unwrap()["bytes"]
            .as_str()
            .unwrap();
        let tx1 = ergo_ser::transaction::read_transaction(&mut VlqReader::new(
            &hex::decode(tx1_hex).unwrap(),
        ))
        .unwrap();
        let digest1: [u8; 33] = {
            let d = digests_data
                .iter()
                .find(|d| d["height"].as_u64().unwrap() == 1)
                .unwrap();
            hex::decode(d["stateRoot"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let h1_id = get_header_id(&headers, 1);
        store
            .apply_block_unchecked_for_test(
                1,
                &h1_id,
                &ergo_primitives::digest::ADDigest::from_bytes(digest1),
                &[tx1],
            )
            .unwrap();

        // Process headers 2-5
        for height in 2..=5 {
            let h_bytes = get_header_bytes(&headers, height);
            process_header(&mut store, &h_bytes).unwrap();
        }
        assert_eq!(store.chain_state().best_header_height, 5);
    }
    // executor dropped here — simulates restart

    // Phase 2: recreate executor, hydrate, verify window
    {
        let store = StateStore::open(&db_path).unwrap();
        assert_eq!(store.chain_state().best_header_height, 5);
        let store = ergo_state::StateBackendKind::Utxo(store);

        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            ergo_crypto::difficulty::DifficultyParams::mainnet(),
        );
        assert!(
            executor.last_headers().is_empty(),
            "before hydration, window should be empty"
        );

        executor
            .hydrate_from_store(&store)
            .expect("hydrate from clean fixture");
        assert_eq!(
            executor.last_headers().len(),
            5,
            "should have 5 headers (heights 5,4,3,2,1) after hydration"
        );

        // Verify they're in newest-first order
        let heights: Vec<u32> = executor.last_headers().iter().map(|h| h.height()).collect();
        assert_eq!(
            heights,
            vec![5, 4, 3, 2, 1],
            "headers should be newest-first"
        );
    }
}

/// Post-restart block processing: apply blocks 1-5, restart, hydrate,
/// then process block 6 through the full executor pipeline and verify
/// state digest matches Scala node.
///
/// This proves CONTEXT.headers-dependent validation works after restart.
#[test]
fn executor_post_restart_block_processing() {
    use ergo_p2p::types::InvData;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::block_transactions::write_block_transactions;
    use ergo_ser::extension::write_extension;
    use ergo_ser::modifier_id::compute_section_id;
    use ergo_ser::transaction::read_transaction;
    use ergo_sync::coordinator::SyncCoordinator;

    use ergo_sync::executor::SyncExecutor;
    use ergo_sync::header_proc::process_header;
    use ergo_validation::context::ProtocolParams;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9030);
    let now = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    let headers = load_headers();
    let tx_data: Vec<serde_json::Value> = {
        let data =
            std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
        serde_json::from_str(&data).unwrap()
    };
    let digests_data: Vec<serde_json::Value> = {
        let data =
            std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
        serde_json::from_str(&data).unwrap()
    };

    // Extension field data (from Scala node):
    // Block 2: key=0100, val=01+block1_id
    // Blocks 3-6: key=0100 same + key=0101 val=05+block2_id
    let block1_id = get_header_id(&headers, 1);
    let block2_id = get_header_id(&headers, 2);
    let ext_field_0100 = {
        let mut v = vec![0x01];
        v.extend_from_slice(&block1_id);
        v
    };
    let ext_field_0101 = {
        let mut v = vec![0x05];
        v.extend_from_slice(&block2_id);
        v
    };

    // Phase 1: process headers 2-6 and apply blocks 1-5 to UTXO state
    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        seed_header_1(&mut store, &headers);

        // Apply blocks 1-5 via unchecked path (already proven in other tests)
        for height in 1..=5 {
            let tx_hex = tx_data
                .iter()
                .find(|t| t["height"].as_u64().unwrap() == height as u64)
                .unwrap()["bytes"]
                .as_str()
                .unwrap();
            let tx = read_transaction(&mut VlqReader::new(&hex::decode(tx_hex).unwrap())).unwrap();
            let digest: [u8; 33] = {
                let d = digests_data
                    .iter()
                    .find(|d| d["height"].as_u64().unwrap() == height as u64)
                    .unwrap();
                hex::decode(d["stateRoot"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            };
            let h_id = get_header_id(&headers, height);
            store
                .apply_block_unchecked_for_test(
                    height,
                    &h_id,
                    &ergo_primitives::digest::ADDigest::from_bytes(digest),
                    &[tx],
                )
                .unwrap();
        }

        // Process headers 2-6 (validate + persist + best-header tracking)
        for height in 2..=6 {
            let h_bytes = get_header_bytes(&headers, height);
            process_header(&mut store, &h_bytes).unwrap();
        }

        assert_eq!(store.height(), 5);
        assert_eq!(store.chain_state().best_header_height, 6);
    }
    // Store dropped — simulates restart

    // Phase 2: restart, hydrate, process block 6 through executor
    {
        let mut store = ergo_state::StateBackendKind::Utxo(StateStore::open(&db_path).unwrap());
        assert_eq!(
            store.height(),
            5,
            "UTXO state should be at height 5 after restart"
        );
        assert_eq!(store.chain_state_meta().best_header_height, 6);

        let mut coordinator = SyncCoordinator::new(5);
        coordinator.sync_state_mut().set_headers_chain_synced();
        let mut executor = SyncExecutor::new(
            ProtocolParams::mainnet_default(),
            ergo_crypto::difficulty::DifficultyParams::mainnet(),
        );
        executor
            .hydrate_from_store(&store)
            .expect("hydrate from clean fixture");
        executor.load_header_index(&store).unwrap();

        assert!(
            !executor.last_headers().is_empty(),
            "recent-header window should be populated after hydration"
        );

        let recovered = executor
            .recover_coordinator(&store, &mut coordinator)
            .expect("recover from clean fixture");
        assert_eq!(recovered, 1, "should recover 1 pending header (height 6)");

        let h6_id = get_header_id(&headers, 6);
        let h6_bytes = get_header_bytes(&headers, 6);
        let h6 = read_header(&mut VlqReader::new(&h6_bytes)).unwrap();

        // BlockTransactions for block 6
        let tx6_hex = tx_data
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == 6)
            .unwrap()["bytes"]
            .as_str()
            .unwrap();
        let tx6 = read_transaction(&mut VlqReader::new(&hex::decode(tx6_hex).unwrap())).unwrap();
        let bt6 = ergo_ser::block_transactions::BlockTransactions {
            header_id: ergo_primitives::digest::ModifierId::from_bytes(h6_id),
            transactions: vec![tx6],
        };
        let bt6_bytes = {
            let mut w = VlqWriter::new();
            write_block_transactions(&mut w, &bt6).unwrap();
            w.result()
        };

        // Extension for block 6 (two fields: 0100 and 0101)
        let ext6 = ergo_ser::extension::Extension {
            header_id: ergo_primitives::digest::ModifierId::from_bytes(h6_id),
            fields: vec![
                ergo_ser::extension::ExtensionField {
                    key: [0x01, 0x00],
                    value: ext_field_0100.clone(),
                },
                ergo_ser::extension::ExtensionField {
                    key: [0x01, 0x01],
                    value: ext_field_0101.clone(),
                },
            ],
        };
        let ext6_bytes = {
            let mut w = VlqWriter::new();
            write_extension(&mut w, &ext6).expect("synthetic extension fits wire bounds");
            w.result()
        };

        // Compute section IDs
        let tx_section_id = compute_section_id(102, &h6_id, h6.transactions_root.as_bytes());
        let ext_section_id = compute_section_id(108, &h6_id, h6.extension_root.as_bytes());

        // Register sections as requested via coordinator
        let chain_view = &store;
        let inv_tx = InvData {
            type_id: 102,
            ids: vec![tx_section_id],
        };
        let inv_ext = InvData {
            type_id: 108,
            ids: vec![ext_section_id],
        };
        coordinator.on_inv(peer, &inv_tx, chain_view, now);
        coordinator.on_inv(peer, &inv_ext, chain_view, now);

        // Deliver sections through coordinator
        let tx_actions = coordinator.on_modifier_received(peer, 102, tx_section_id, bt6_bytes);
        let ext_actions = coordinator.on_modifier_received(peer, 108, ext_section_id, ext6_bytes);

        // Execute all actions through the executor
        let mut all_actions = tx_actions;
        all_actions.extend(ext_actions);
        let _network = executor.execute_all(all_actions, &mut store, &mut coordinator, now, None);

        // Verify block 6 was applied
        assert_eq!(
            store.height(),
            6,
            "UTXO state should be at height 6 after post-restart block processing"
        );

        let expected_digest: [u8; 33] = {
            let d = digests_data
                .iter()
                .find(|d| d["height"].as_u64().unwrap() == 6)
                .unwrap();
            hex::decode(d["stateRoot"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        assert_eq!(
            *store.as_utxo_mut().unwrap().root_digest().as_bytes(),
            expected_digest,
            "state digest at height 6 should match Scala node after post-restart processing"
        );
    }
}

/// Fork-resolution: receiving a header whose parent isn't stored (e.g. because
/// we're on an orphaned chain and the peer's canonical chain diverges above
/// our best_header) must emit a `RequestModifier(Header, [parent_id])` so the
/// chain can be stitched backward until it meets a common ancestor. Without
/// this, the header sits in the orphan buffer forever because `drain_orphans`
/// alone can't resolve a dangling chain whose root isn't in our store.
///
/// Setup: genesis only, no header 1. Deliver header 2 → executor must buffer
/// as orphan AND emit a RequestModifier for header 1's id.
#[test]
fn executor_parent_walk_requests_missing_parent() {
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_p2p::types::InvData;
    use ergo_sync::coordinator::{Action, SyncCoordinator};
    use ergo_sync::executor::SyncExecutor;
    use ergo_validation::context::ProtocolParams;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 9030);
    let now = Instant::now();

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);
    let headers = load_headers();

    // Seed header 1's PARENT (genesis) meta but NOT header 1 itself. Now our
    // store knows genesis; header 2 will orphan because its parent (header 1)
    // is missing. This is the minimal reproduction of the fork-catchup case.
    seed_genesis_header(&mut store, &headers);

    let h1_id = get_header_id(&headers, 1);
    let h2_bytes = get_header_bytes(&headers, 2);

    let mut coordinator = SyncCoordinator::new(0);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut store = ergo_state::StateBackendKind::Utxo(store);

    let actions = executor.execute_all(
        vec![Action::ValidateHeader {
            peer,
            header_bytes: h2_bytes.clone(),
        }],
        &mut store,
        &mut coordinator,
        now,
        None,
    );

    // The executor must emit a RequestModifier for the missing parent.
    // Header type_id = 101; CODE_REQUEST_MODIFIER = 22.
    let found_parent_request = actions.iter().any(|a| {
        let Action::SendToPeer {
            peer: p,
            code,
            payload,
        } = a
        else {
            return false;
        };
        if *p != peer || *code != 22 {
            return false;
        }
        let inv = match ergo_p2p::message::deserialize_inv(payload) {
            Ok(i) => i,
            Err(_) => return false,
        };
        inv.type_id == 101 && inv.ids.contains(&h1_id)
    });
    assert!(
        found_parent_request,
        "parent-walk must emit RequestModifier(Header=101, [h1_id]) to the \
         peer that delivered the orphan; got {actions:?}"
    );

    // And header 2 must still be buffered — not silently dropped.
    assert_eq!(
        store.chain_state_meta().best_header_height,
        0,
        "best_header must not advance on an orphaned header"
    );
    assert!(
        store
            .get_header(&get_header_id(&headers, 2))
            .unwrap()
            .is_none(),
        "orphan header must not be persisted before its parent arrives",
    );

    // Silence unused-import warnings from the idiomatic helper.
    let _ = InvData {
        type_id: 101,
        ids: vec![h1_id],
    };
}

// ---------------------------------------------------------------------------
// Phase 2: classify EpochContextIncomplete as orphan-buffer + retry, NOT
// peer misbehavior. The validator-level contract that an undersized EIP-37
// window surfaces as Difficulty(MissingEpochHeaders) is pinned in
// ergo-validation/tests/header_validation.rs; this test pins the executor's
// classification on top of that contract.
// ---------------------------------------------------------------------------

/// Real mainnet header at the EIP-37 recalculation boundary 1_761_793 with
/// only the parent (1_761_792) seeded — the eight older epoch ancestors
/// the difficulty math wants are deliberately absent. Pre-Phase-1 this
/// path panicked in `eip37_calculate`; Phase 1 turned that into
/// `DifficultyError::MissingEpochHeaders`; Phase 2 now routes it to
/// `HeaderProcessError::EpochContextIncomplete` and treats the delivering
/// peer as innocent.
#[test]
fn process_header_at_eip37_boundary_with_truncated_lookback_buffers_not_penalizes() {
    use ergo_crypto::difficulty::DifficultyParams;
    use ergo_p2p::peer::Penalty;
    use ergo_ser::difficulty::decode_compact_bits;
    use ergo_sync::coordinator::{Action, SyncCoordinator};
    use ergo_sync::executor::SyncExecutor;
    use ergo_validation::context::ProtocolParams;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 23)), 9030);
    let now = Instant::now();

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
    init_genesis(&mut store);

    let headers = load_headers_file("headers_1761792_1761795_eip37_curated.json");

    // Seed ONLY the parent at 1_761_792. None of the 8 older epoch
    // ancestors at 1_761_664, 1_761_536, ..., 1_760_768 are present —
    // `find_header_at_height` will return EpochHeaderMissing for each
    // and `process_header_inner`'s collection loop will skip them, so
    // `validate_header_after_pow_cfg` runs against a one-element
    // window. Post-EIP-37 + recalculation boundary + len < 2 →
    // MissingEpochHeaders (Phase 1 contract).
    let parent_height = 1_761_792u32;
    let child_height = 1_761_793u32;
    let parent_bytes = get_header_bytes(&headers, parent_height);
    let parent_id = get_header_id(&headers, parent_height);
    let child_bytes = get_header_bytes(&headers, child_height);
    let child_id = get_header_id(&headers, child_height);

    let parent_header = {
        let mut r = VlqReader::new(&parent_bytes);
        read_header(&mut r).unwrap()
    };
    store.store_header(&parent_id, &parent_bytes).unwrap();
    let parent_meta = HeaderMeta {
        parent_id: *parent_header.parent_id.as_bytes(),
        height: parent_height,
        cumulative_score: decode_compact_bits(parent_header.n_bits).to_bytes_be(),
        pow_validity: 1,
        timestamp: parent_header.timestamp,
    };
    store.store_header_meta(&parent_id, &parent_meta).unwrap();
    store
        .test_force_set_best_header_unsafe(
            parent_id,
            parent_height,
            parent_meta.cumulative_score.clone(),
        )
        .unwrap();

    let mut coordinator = SyncCoordinator::new(0);
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    );
    let mut store = ergo_state::StateBackendKind::Utxo(store);

    let actions = executor.execute_all(
        vec![Action::ValidateHeader {
            peer,
            header_bytes: child_bytes.clone(),
        }],
        &mut store,
        &mut coordinator,
        now,
        None,
    );

    // 1. Critical: no peer-penalty action emitted. The peer delivered a
    //    valid header; our local context is incomplete, not their fault.
    let penalized = actions.iter().any(|a| {
        matches!(
            a,
            Action::Penalize {
                peer: _,
                penalty: Penalty::Misbehavior,
            }
        )
    });
    assert!(
        !penalized,
        "EpochContextIncomplete must not penalize the delivering peer; got {actions:?}"
    );

    // 2. Critical guardrail: the header was NOT short-circuited to
    //    "accepted." Difficulty validation never completed, so the
    //    header must remain unpersisted and the chain tip unchanged.
    assert!(
        store.get_header(&child_id).unwrap().is_none(),
        "context-incomplete header must not be persisted",
    );
    assert!(
        store.get_header_meta(&child_id).unwrap().is_none(),
        "context-incomplete header must have no meta",
    );
    assert_eq!(
        store.chain_state_meta().best_header_height,
        parent_height,
        "best_header must not advance past the parent",
    );
    assert_eq!(
        store.chain_state_meta().best_header_id,
        parent_id,
        "best_header_id must remain at the seeded parent",
    );

    // 3. Header retained for retry (orphan-buffered keyed by parent_id).
    //    On mainnet/testnet this code path is empirically unreachable
    //    (the parent's ancestors are always in store); for custom
    //    configs / partial-window recovery the buffer keeps the header
    //    alive until older epoch ancestors arrive via other sync paths.
    assert!(
        executor.orphan_headers_len() >= 1,
        "context-incomplete header must be buffered for retry, orphan_headers_len = 0",
    );
}

/// `recover_coordinator` walks `best_full_block+1 .. best_header` to
/// rebuild the pending-block queue. Same trust contract as hydrate_*:
/// every walked id must resolve to a header row whose bytes hash to the
/// DB key. A row deleted from the HEADERS table mid-walk must surface as
/// `MissingPersistedRow { phase: "recover_coordinator" }`, not as a
/// silent truncation that leaves a height gap unrecovered.
#[test]
fn recover_coordinator_rejects_missing_persisted_header_row() {
    use ergo_sync::executor::{HydrationError, SyncExecutor};
    use ergo_sync::header_proc::process_header;
    use ergo_validation::context::ProtocolParams;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    // Setup: genesis + apply block 1 + process headers 2..=5 so
    // best_full_block_height=1, best_header_height=5, walk depth=4.
    let h3_id;
    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        let headers = load_headers();
        seed_header_1(&mut store, &headers);
        apply_block_1_for_recovery_test(&mut store, &headers);
        for height in 2..=5 {
            let h_bytes = get_header_bytes(&headers, height);
            process_header(&mut store, &h_bytes).unwrap();
        }
        h3_id = get_header_id(&headers, 3);
    }

    // Drop a single mid-walk row, then run the recovery path and
    // assert the typed corruption error.
    let mut store = StateStore::open(&db_path).unwrap();
    store
        .test_remove_header_row_unsafe(&h3_id)
        .expect("remove header row");

    let mut coordinator = ergo_sync::coordinator::SyncCoordinator::new(5);
    coordinator.sync_state_mut().set_headers_chain_synced();
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
    );
    // Skip hydrate_from_store — it would hit the same corruption before
    // we get to recover_coordinator. load_header_index reads
    // HEADER_CHAIN_INDEX (separate table from HEADERS), which is still
    // intact, so the recovery walk seeds correctly and only trips when
    // it dereferences h3.
    let store = ergo_state::StateBackendKind::Utxo(store);
    executor
        .load_header_index(&store)
        .expect("load header index");

    match executor.recover_coordinator(&store, &mut coordinator) {
        Err(HydrationError::MissingPersistedRow {
            phase,
            kind,
            ref id,
        }) => {
            assert_eq!(phase, "recover_coordinator");
            assert_eq!(kind, "header");
            assert_eq!(id, &hex::encode(h3_id));
        }
        other => panic!("expected MissingPersistedRow at h3, got {other:?}"),
    }
}

/// Persisted bytes that no longer hash to the DB key (body/key drift)
/// must surface as `HeaderIntegrity { source: HeaderIdMismatch }`. This
/// is the load-bearing guard `from_persisted_parts` adds: a buggy write
/// path that stored mutated bytes, or a row tampered post-write, is
/// rejected at the recovery boundary rather than feeding bogus
/// `transactions_root` / `extension_root` into the section-request
/// pipeline.
#[test]
fn recover_coordinator_rejects_persisted_header_id_drift() {
    use ergo_sync::executor::{HydrationError, SyncExecutor};
    use ergo_sync::header_proc::process_header;
    use ergo_validation::context::ProtocolParams;
    use ergo_validation::header::HeaderValidationError;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    let h3_id;
    let original_h3_bytes;
    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        let headers = load_headers();
        seed_header_1(&mut store, &headers);
        apply_block_1_for_recovery_test(&mut store, &headers);
        for height in 2..=5 {
            let h_bytes = get_header_bytes(&headers, height);
            process_header(&mut store, &h_bytes).unwrap();
        }
        h3_id = get_header_id(&headers, 3);
        original_h3_bytes = get_header_bytes(&headers, 3);
    }

    // Mutate the persisted h3 bytes (flip the last byte). The DB key is
    // unchanged, so blake2b256(mutated_bytes) != h3_id and the
    // expected/computed mismatch fires inside from_persisted_parts.
    let mut mutated = original_h3_bytes.clone();
    let last = mutated.len() - 1;
    mutated[last] ^= 0x01;

    let mut store = StateStore::open(&db_path).unwrap();
    store
        .test_corrupt_header_bytes_unsafe(&h3_id, &mutated)
        .expect("overwrite header bytes");

    let mut coordinator = ergo_sync::coordinator::SyncCoordinator::new(5);
    coordinator.sync_state_mut().set_headers_chain_synced();
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
    );
    // Skip hydrate_from_store — it walks from best_header backwards and
    // would catch the same drift first. We want to pin recover_coordinator's
    // branch specifically.
    let store = ergo_state::StateBackendKind::Utxo(store);
    executor
        .load_header_index(&store)
        .expect("load header index");

    match executor.recover_coordinator(&store, &mut coordinator) {
        Err(HydrationError::HeaderIntegrity {
            phase,
            ref id,
            source: HeaderValidationError::HeaderIdMismatch { expected, computed },
        }) => {
            assert_eq!(phase, "recover_coordinator");
            assert_eq!(id, &hex::encode(h3_id));
            assert_eq!(expected, h3_id);
            assert_ne!(computed, h3_id);
        }
        other => panic!("expected recover_coordinator HeaderIdMismatch, got {other:?}"),
    }
}

/// `valid_header_bytes ++ junk` whose hash matches the DB key (because
/// we install corrupted_id = blake2b256(corrupted_bytes) ourselves).
/// This is the only way to reach the EOF guard inside
/// `from_persisted_parts` — the upstream hash check passes, leaving
/// trailing-bytes detection as the sole remaining gate.
#[test]
fn recover_coordinator_rejects_trailing_bytes_in_unapplied_header_gap() {
    use ergo_primitives::digest::blake2b256;
    use ergo_state::chain::HeaderMeta;
    use ergo_sync::coordinator::SyncCoordinator;
    use ergo_sync::executor::{HydrationError, SyncExecutor};
    use ergo_sync::header_proc::process_header;
    use ergo_validation::context::ProtocolParams;
    use ergo_validation::header::HeaderValidationError;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    let h2_id;
    let h3_timestamp_ms;
    let valid_h3_bytes;
    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        let headers = load_headers();
        seed_header_1(&mut store, &headers);
        apply_block_1_for_recovery_test(&mut store, &headers);
        for height in 2..=3 {
            let h_bytes = get_header_bytes(&headers, height);
            process_header(&mut store, &h_bytes).unwrap();
        }
        h2_id = get_header_id(&headers, 2);
        valid_h3_bytes = get_header_bytes(&headers, 3);
        // Pull h3's timestamp out of the parsed header so the synthetic
        // meta we install below stays Scala-consistent.
        let h3 = ergo_ser::header::read_header(&mut VlqReader::new(&valid_h3_bytes)).unwrap();
        h3_timestamp_ms = h3.timestamp;
    }

    // Construct the trailing-bytes attack: append junk to valid h3 bytes,
    // then anchor the resulting hash as the new "h3 id". The persisted
    // row, meta, and chain_index all have to agree on this synthetic id
    // so the recover_coordinator walk both reaches it AND passes the
    // hash-check inside from_persisted_parts. Only the EOF guard
    // (the part of the constructor that asserts `r.position() ==
    // header_bytes.len()`) can catch this.
    let mut corrupted_bytes = valid_h3_bytes.clone();
    corrupted_bytes.extend_from_slice(&[0xAA; 4]);
    let corrupted_id: [u8; 32] = *blake2b256(&corrupted_bytes).as_bytes();

    let mut store = StateStore::open(&db_path).unwrap();
    store
        .test_corrupt_header_bytes_unsafe(&corrupted_id, &corrupted_bytes)
        .expect("install corrupted bytes under their own hash");
    store
        .store_header_meta(
            &corrupted_id,
            &HeaderMeta {
                parent_id: h2_id,
                height: 3,
                cumulative_score: vec![0u8; 8],
                pow_validity: 1,
                timestamp: h3_timestamp_ms,
            },
        )
        .expect("install synthetic meta for corrupted id");
    store
        .test_force_put_header_chain_index(3, &corrupted_id)
        .expect("rewire HEADER_CHAIN_INDEX h3 -> corrupted_id");
    store
        .test_force_set_best_header_unsafe(corrupted_id, 3, vec![0u8; 8])
        .expect("rewire chain_state best_header_id -> corrupted_id");

    let mut coordinator = SyncCoordinator::new(1);
    coordinator.sync_state_mut().set_headers_chain_synced();
    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
    );
    let store = ergo_state::StateBackendKind::Utxo(store);
    executor
        .load_header_index(&store)
        .expect("load header index");

    match executor.recover_coordinator(&store, &mut coordinator) {
        Err(HydrationError::HeaderIntegrity {
            phase,
            ref id,
            source: HeaderValidationError::HeaderParseFailed(ref msg),
        }) => {
            assert_eq!(phase, "recover_coordinator");
            assert_eq!(id, &hex::encode(corrupted_id));
            assert!(
                msg.contains("trailing"),
                "expected trailing-bytes message, got: {msg}"
            );
        }
        other => {
            panic!("expected recover_coordinator trailing-bytes HeaderParseFailed, got {other:?}")
        }
    }
}

/// Apply block 1 to UTXO via the unchecked test path so a follow-up
/// process_header chain has a valid `best_full_block_height = 1`.
/// Extracted so the recover_coordinator corruption tests can share
/// the setup without re-pasting JSON parsing.
fn apply_block_1_for_recovery_test(store: &mut StateStore, headers: &[serde_json::Value]) {
    let tx_data: Vec<serde_json::Value> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap(),
    )
    .unwrap();
    let digests_data: Vec<serde_json::Value> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap(),
    )
    .unwrap();
    let tx1_hex = tx_data
        .iter()
        .find(|t| t["height"].as_u64().unwrap() == 1)
        .unwrap()["bytes"]
        .as_str()
        .unwrap();
    let tx1 = ergo_ser::transaction::read_transaction(&mut VlqReader::new(
        &hex::decode(tx1_hex).unwrap(),
    ))
    .unwrap();
    let digest1: [u8; 33] = hex::decode(
        digests_data
            .iter()
            .find(|d| d["height"].as_u64().unwrap() == 1)
            .unwrap()["stateRoot"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let h1_id = get_header_id(headers, 1);
    store
        .apply_block_unchecked_for_test(
            1,
            &h1_id,
            &ergo_primitives::digest::ADDigest::from_bytes(digest1),
            &[tx1],
        )
        .unwrap();
}

/// Same fail-fast contract for `hydrate_block_context`:
/// `chain_state.best_full_block_id` pointing at a header table row that
/// does not exist is mid-chain corruption, not legitimate termination.
#[test]
fn hydrate_block_context_rejects_missing_persisted_header_row() {
    use ergo_sync::executor::{HydrationError, SyncExecutor};
    use ergo_validation::context::ProtocolParams;

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    init_genesis(&mut store);

    let phantom_id = [0xCDu8; 32];
    store
        .test_force_set_best_full_block_unsafe(phantom_id, 5)
        .expect("force-set best full block for test");

    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
    );
    let store = ergo_state::StateBackendKind::Utxo(store);
    match executor.hydrate_block_context(&store) {
        Err(HydrationError::MissingPersistedRow {
            phase,
            kind,
            ref id,
        }) => {
            assert_eq!(phase, "hydrate_block_context");
            assert_eq!(kind, "header");
            assert_eq!(id, &hex::encode(phantom_id));
        }
        other => panic!("expected MissingPersistedRow header, got {other:?}"),
    }
}

/// chain_state.best_header_id pointing at a header table row that does not
/// exist is mid-chain corruption, NOT a legitimate chain-end termination.
/// `hydrate_from_store` must surface this as `MissingPersistedRow` rather
/// than silently truncating the cache and continuing.
#[test]
fn hydrate_from_store_rejects_missing_persisted_header_row() {
    use ergo_sync::executor::{HydrationError, SyncExecutor};
    use ergo_validation::context::ProtocolParams;

    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    init_genesis(&mut store);

    // Pin best_header_id at an arbitrary 32-byte id we never wrote a header
    // for. Mirrors the on-disk shape of "best_header_id is set but the row
    // for it was deleted / never persisted" — a real corruption surface.
    let phantom_id = [0xABu8; 32];
    store
        .test_force_set_best_header_unsafe(phantom_id, 5, vec![0u8; 8])
        .expect("force-set best header for test");

    let mut executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
    );
    let store = ergo_state::StateBackendKind::Utxo(store);
    match executor.hydrate_from_store(&store) {
        Err(HydrationError::MissingPersistedRow {
            phase,
            kind,
            ref id,
        }) => {
            assert_eq!(phase, "hydrate_from_store");
            assert_eq!(kind, "header");
            assert_eq!(id, &hex::encode(phantom_id));
        }
        other => panic!("expected MissingPersistedRow header, got {other:?}"),
    }
}

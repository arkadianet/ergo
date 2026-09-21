//! Tests for the chain storage layer:
//! - HeaderMeta roundtrip serialization
//! - ChainStateMeta roundtrip serialization
//! - Chain state persistence across restart (open → apply → reopen)
//! - Rollback via `rollback_to` (the production reorg sync path)
//! - mark_pow_invalid / mark_session_invalid / is_invalid

use ergo_primitives::digest::{ADDigest, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::{read_transaction, Transaction};
use ergo_state::chain::{ChainStateMeta, HeaderMeta};
use ergo_state::store::StateStore;

/// Re-install the `hci_version=1` sentinel on the underlying redb after a
/// `test_force_set_best_header_unsafe` call. Without this, the next
/// `StateStore::open` would run backfill and fail because the forced
/// best_header points at a synthetic id with no matching HEADER_META.
/// Tests that pin a synthetic best_header for restart-persistence checks
/// declare with this helper: "pretend the index already reflects the forced
/// state — skip backfill."
fn force_install_hci_sentinel(db_path: &std::path::Path) {
    let db = std::sync::Arc::new(redb::Database::create(db_path).unwrap());
    let txn = ergo_state::begin_write_qr(&db).unwrap();
    {
        let mut meta = txn
            .open_table(redb::TableDefinition::<&str, &[u8]>::new("state_meta"))
            .unwrap();
        meta.insert("hci_version", [1u8].as_slice()).unwrap();
    }
    txn.commit().unwrap();
}

// ---- Test helpers (same as persistent_blocks_1_10) ----

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

#[derive(serde::Deserialize)]
struct DigestJson {
    height: u32,
    #[serde(rename = "stateRoot")]
    state_root: String,
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

fn parse_block_tx(tx_hex: &str) -> Transaction {
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let mut r = VlqReader::new(&tx_bytes);
    read_transaction(&mut r).unwrap()
}

struct TestData {
    digests: Vec<DigestJson>,
    all_txs: Vec<serde_json::Value>,
    headers: Vec<serde_json::Value>,
}

fn load_test_data() -> TestData {
    let digests_data =
        std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    TestData {
        digests: serde_json::from_str(&digests_data).unwrap(),
        all_txs: serde_json::from_str(&tx_data).unwrap(),
        headers: serde_json::from_str(&headers_data).unwrap(),
    }
}

fn apply_blocks(store: &mut StateStore, data: &TestData, from: u32, to: u32) {
    for height in from..=to {
        let expected = data.digests.iter().find(|d| d.height == height).unwrap();
        let expected_digest = ADDigest::from_bytes(
            hex::decode(&expected.state_root)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let tx_entry = data
            .all_txs
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
        let header = data
            .headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        store
            .apply_block_unchecked_for_test(height, &header_id, &expected_digest, &[tx])
            .unwrap_or_else(|e| panic!("apply_block failed at height {height}: {e}"));
    }
}

fn get_header_id(data: &TestData, height: u32) -> [u8; 32] {
    let header = data
        .headers
        .iter()
        .find(|h| h["height"].as_u64().unwrap() == height as u64)
        .unwrap();
    hex::decode(header["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

// ---- Serialization roundtrip tests ----

// ----- happy path -----

#[test]
fn header_meta_roundtrip() {
    let meta = HeaderMeta {
        parent_id: [0xAA; 32],
        height: 12345,
        cumulative_score: vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB],
        pow_validity: 1,
        timestamp: 1700000000000,
    };
    let bytes = meta.serialize();
    let restored = HeaderMeta::deserialize(&bytes).expect("round-trip must decode");
    assert_eq!(restored.parent_id, meta.parent_id);
    assert_eq!(restored.height, meta.height);
    assert_eq!(restored.cumulative_score, meta.cumulative_score);
    assert_eq!(restored.pow_validity, meta.pow_validity);
    assert_eq!(restored.timestamp, meta.timestamp);
}

#[test]
fn chain_state_meta_roundtrip() {
    let meta = ChainStateMeta {
        best_header_id: [0xBB; 32],
        best_header_height: 500000,
        best_header_score: vec![0xFF, 0xEE, 0xDD],
        best_full_block_id: [0xCC; 32],
        best_full_block_height: 499990,
        header_availability: ergo_state::chain::HeaderAvailability::Dense,
    };
    let bytes = meta.serialize();
    let restored = ChainStateMeta::deserialize(&bytes).expect("roundtrip decode");
    assert_eq!(restored.best_header_id, meta.best_header_id);
    assert_eq!(restored.best_header_height, meta.best_header_height);
    assert_eq!(restored.best_header_score, meta.best_header_score);
    assert_eq!(restored.best_full_block_id, meta.best_full_block_id);
    assert_eq!(restored.best_full_block_height, meta.best_full_block_height);
}

// ---- Chain state persistence across restart ----

#[test]
fn chain_state_persisted_after_apply_block() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let data = load_test_data();

    let header_id_5;
    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        apply_blocks(&mut store, &data, 1, 5);
        header_id_5 = get_header_id(&data, 5);
        // Verify chain state is correct before drop
        assert_eq!(store.chain_state().best_full_block_height, 5);
        assert_eq!(store.chain_state().best_full_block_id, header_id_5);
    }

    // Reopen — chain_state_meta should survive restart
    {
        let store = StateStore::open(&db_path).unwrap();
        assert_eq!(store.height(), 5);
        assert_eq!(store.chain_state().best_full_block_height, 5);
        assert_eq!(store.chain_state().best_full_block_id, header_id_5);
    }
}

#[test]
fn chain_state_derived_from_utxo_when_meta_absent() {
    // Simulate a pre-Phase-7 database: has state_meta but no chain_state_meta.
    // open() should derive chain state from committed UTXO state.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let data = load_test_data();

    // Apply blocks 1-3
    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        apply_blocks(&mut store, &data, 1, 3);
    }

    // Delete chain_state_meta to simulate pre-Phase-7 DB
    {
        let db = redb::Database::open(&db_path).unwrap();
        let write_txn = ergo_state::begin_write_qr(&db).unwrap();
        {
            // Try to delete — if table doesn't exist that's fine too
            if let Ok(mut table) = write_txn.open_table(redb::TableDefinition::<&str, &[u8]>::new(
                "chain_state_meta",
            )) {
                let _ = table.remove("chain_state");
            }
        }
        write_txn.commit().unwrap();
    }

    // Reopen — should derive from state_meta
    {
        let store = StateStore::open(&db_path).unwrap();
        assert_eq!(store.height(), 3);
        let header_id_3 = get_header_id(&data, 3);
        assert_eq!(store.chain_state().best_full_block_height, 3);
        assert_eq!(store.chain_state().best_full_block_id, header_id_3);
    }
}

// ---- Header/section storage ----

#[test]
fn store_and_retrieve_header() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    let header_id = [0x42; 32];
    let header_bytes = vec![1, 2, 3, 4, 5];

    assert!(store.get_header(&header_id).unwrap().is_none());
    store.store_header(&header_id, &header_bytes).unwrap();
    assert_eq!(store.get_header(&header_id).unwrap().unwrap(), header_bytes);
}

#[test]
fn store_and_retrieve_block_section() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    let modifier_id = [0x99; 32];
    let section_bytes = vec![10, 20, 30];

    assert!(store.get_block_section(&modifier_id).unwrap().is_none());
    store
        .store_block_section(&modifier_id, &section_bytes)
        .unwrap();
    assert_eq!(
        store.get_block_section(&modifier_id).unwrap().unwrap(),
        section_bytes
    );
}

// ---- Header meta + validity ----

#[test]
fn header_meta_storage_and_validity() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    let header_id = [0x11; 32];
    let meta = HeaderMeta {
        parent_id: [0x00; 32],
        height: 100,
        cumulative_score: vec![0x01, 0x00],
        pow_validity: 0,
        timestamp: 1700000000000,
    };

    // Store and retrieve
    store.store_header_meta(&header_id, &meta).unwrap();
    let retrieved = store.get_header_meta(&header_id).unwrap().unwrap();
    assert_eq!(retrieved.height, 100);
    assert_eq!(retrieved.pow_validity, 0);

    // Not invalid yet
    assert!(!store.is_invalid(&header_id).unwrap());

    // Mark session invalid
    store.mark_session_invalid(header_id);
    assert!(store.is_invalid(&header_id).unwrap());

    // Session invalids cleared on "restart" (new ChainState)
    // Just check the pow path:
    let header_id_2 = [0x22; 32];
    let meta2 = HeaderMeta {
        parent_id: [0x00; 32],
        height: 101,
        cumulative_score: vec![0x02],
        pow_validity: 0,
        timestamp: 1700000000001,
    };
    store.store_header_meta(&header_id_2, &meta2).unwrap();
    store.mark_pow_invalid(&header_id_2).unwrap();
    assert!(store.is_invalid(&header_id_2).unwrap());

    // Verify pow_validity persisted
    let retrieved2 = store.get_header_meta(&header_id_2).unwrap().unwrap();
    assert_eq!(retrieved2.pow_validity, 2);
}

#[test]
fn mark_pow_invalid_fails_without_header_meta() {
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    let header_id = [0x33; 32];
    let err = store
        .mark_pow_invalid(&header_id)
        .expect_err("should fail when header_meta missing");
    // Caller-side contract: header_meta must exist before
    // mark_pow_invalid. Pin the exact typed variant so this path
    // can't silently drift back to DbCorruption (which would
    // overclaim a corruption signal).
    match err {
        ergo_state::store::StateError::InvalidPrecondition { what } => {
            assert!(
                what.contains("mark_pow_invalid"),
                "unexpected precondition label: {what}",
            );
        }
        other => panic!("expected InvalidPrecondition, got {other:?}"),
    }
}

// ---- Rollback chain state sync + restart verification ----

#[test]
fn chain_state_updated_after_rollback_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let data = load_test_data();
    let header_id_3 = get_header_id(&data, 3);

    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        apply_blocks(&mut store, &data, 1, 5);
        assert_eq!(store.chain_state().best_full_block_height, 5);

        store.rollback_to(3, None, None).unwrap();
        assert_eq!(store.height(), 3);
        assert_eq!(store.chain_state().best_full_block_height, 3);
        assert_eq!(store.chain_state().best_full_block_id, header_id_3);
    }

    // Reopen — chain_state_meta must survive restart after rollback.
    {
        let store = StateStore::open(&db_path).unwrap();
        assert_eq!(store.height(), 3);
        assert_eq!(store.chain_state().best_full_block_height, 3);
        assert_eq!(store.chain_state().best_full_block_id, header_id_3);
    }
}

#[test]
fn test_force_set_best_header_unsafe_persists_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    let fake_header_id = [0xAA; 32];
    let fake_score = vec![0x01, 0xFF];

    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);

        store
            .test_force_set_best_header_unsafe(fake_header_id, 99999, fake_score.clone())
            .unwrap();
        assert_eq!(store.chain_state().best_header_id, fake_header_id);
        assert_eq!(store.chain_state().best_header_height, 99999);
        assert_eq!(store.chain_state().best_header_score, fake_score);
        // best_full_block should still be at genesis
        assert_eq!(store.chain_state().best_full_block_height, 0);
    }
    // Unsafe force clears hci_version; re-install it so backfill skips on reopen
    // (the forced best_header_id has no HEADER_META and would fail strict walk).
    force_install_hci_sentinel(&db_path);

    // Reopen — best_header must survive, best_full_block still at 0.
    {
        let store = StateStore::open(&db_path).unwrap();
        assert_eq!(store.chain_state().best_header_id, fake_header_id);
        assert_eq!(store.chain_state().best_header_height, 99999);
        assert_eq!(store.chain_state().best_header_score, fake_score);
        assert_eq!(store.chain_state().best_full_block_height, 0);
    }
}

#[test]
fn best_header_ahead_of_best_full_block_survives_rollback_and_restart() {
    // Simulate header-first sync: best_header is far ahead of best_full_block.
    // Then rollback best_full_block and verify both pointers survive restart.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let data = load_test_data();

    let fake_header_id = [0xBB; 32];
    let fake_score = vec![0x42];
    let header_id_3 = get_header_id(&data, 3);

    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
        apply_blocks(&mut store, &data, 1, 5);

        // Simulate header sync advancing far ahead of full block validation.
        store
            .test_force_set_best_header_unsafe(fake_header_id, 50000, fake_score.clone())
            .unwrap();

        assert_eq!(store.chain_state().best_header_height, 50000);
        assert_eq!(store.chain_state().best_full_block_height, 5);

        // Rollback full blocks to height 3. best_header should stay at 50000.
        store.rollback_to(3, None, None).unwrap();
        assert_eq!(store.chain_state().best_full_block_height, 3);
        assert_eq!(store.chain_state().best_header_height, 50000);
        assert_eq!(store.chain_state().best_header_id, fake_header_id);
    }
    // Unsafe force cleared hci_version; re-install it so backfill skips on
    // reopen (the forced best_header_id has no HEADER_META).
    force_install_hci_sentinel(&db_path);

    // Reopen — both pointers must be correct.
    {
        let store = StateStore::open(&db_path).unwrap();
        assert_eq!(store.height(), 3);
        assert_eq!(store.chain_state().best_full_block_height, 3);
        assert_eq!(store.chain_state().best_full_block_id, header_id_3);
        assert_eq!(store.chain_state().best_header_height, 50000);
        assert_eq!(store.chain_state().best_header_id, fake_header_id);
        assert_eq!(store.chain_state().best_header_score, fake_score);
    }
}

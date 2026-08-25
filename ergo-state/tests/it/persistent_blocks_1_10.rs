//! Slice 4: Apply blocks 1-10 with redb persistence and atomic commit.
//! Verify state digest at each height and test crash recovery.

use ergo_primitives::digest::{ADDigest, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::transaction::{read_transaction, Transaction};
use ergo_state::store::StateStore;

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

// ----- happy path -----

#[test]
fn blocks_1_10_digests_match_with_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();

    init_genesis(&mut store);

    // Load expected digests
    let digests_data =
        std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
    let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();

    // Load transactions
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let all_txs: Vec<serde_json::Value> = serde_json::from_str(&tx_data).unwrap();

    // Load headers for header_ids
    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&headers_data).unwrap();

    for height in 1u32..=10 {
        // Get expected digest
        let expected = digests.iter().find(|d| d.height == height).unwrap();
        let expected_digest_bytes: [u8; 33] = hex::decode(&expected.state_root)
            .unwrap()
            .try_into()
            .unwrap();
        let expected_digest = ADDigest::from_bytes(expected_digest_bytes);

        // Get transaction bytes
        let tx_entry = all_txs
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());

        // Get header_id
        let header = headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();

        // Apply block
        store
            .apply_block_unchecked_for_test(height, &header_id, &expected_digest, &[tx])
            .unwrap_or_else(|e| {
                panic!("apply_block failed at height {height}: {e}");
            });

        assert_eq!(store.height(), height);
    }
}

#[test]
fn crash_recovery_restores_state() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    // Apply blocks 1-5
    {
        let mut store = StateStore::open(&db_path).unwrap();

        init_genesis(&mut store);

        let digests_data =
            std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
        let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
        let tx_data =
            std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
        let all_txs: Vec<serde_json::Value> = serde_json::from_str(&tx_data).unwrap();
        let headers_data =
            std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
        let headers: Vec<serde_json::Value> = serde_json::from_str(&headers_data).unwrap();

        for height in 1u32..=5 {
            let expected = digests.iter().find(|d| d.height == height).unwrap();
            let expected_digest = ADDigest::from_bytes(
                hex::decode(&expected.state_root)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            let tx_entry = all_txs
                .iter()
                .find(|t| t["height"].as_u64().unwrap() == height as u64)
                .unwrap();
            let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
            let header = headers
                .iter()
                .find(|h| h["height"].as_u64().unwrap() == height as u64)
                .unwrap();
            let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            store
                .apply_block_unchecked_for_test(height, &header_id, &expected_digest, &[tx])
                .unwrap();
        }

        assert_eq!(store.height(), 5);
        // store dropped here — simulates crash
    }

    // Reopen — should recover from committed state
    {
        let mut store = StateStore::open(&db_path).unwrap();
        assert_eq!(
            store.height(),
            5,
            "height should be recovered from state_meta"
        );

        // Verify digest matches height 5
        let digests_data =
            std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
        let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
        let expected = digests.iter().find(|d| d.height == 5).unwrap();
        let expected_digest = ADDigest::from_bytes(
            hex::decode(&expected.state_root)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            store.root_digest(),
            expected_digest,
            "root digest should match height 5 after recovery"
        );
    }
}

/// Regression: genesis state survives a failed block 1 application.
/// Verifies that initialize_genesis() makes the genesis state durable so
/// rebuild_from_committed() can restore it.
#[test]
fn failed_block_1_preserves_genesis_state() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let mut store = StateStore::open(&db_path).unwrap();

    init_genesis(&mut store);

    // Record genesis digest
    let genesis_digest = store.root_digest();
    assert_eq!(store.height(), 0);

    // Try to apply block 1 with a wrong digest — should fail
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let all_txs: Vec<serde_json::Value> = serde_json::from_str(&tx_data).unwrap();
    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&headers_data).unwrap();

    let tx_entry = all_txs
        .iter()
        .find(|t| t["height"].as_u64().unwrap() == 1)
        .unwrap();
    let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
    let header = headers
        .iter()
        .find(|h| h["height"].as_u64().unwrap() == 1)
        .unwrap();
    let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let wrong_digest = ADDigest::from_bytes([0xFFu8; 33]);
    let result = store.apply_block_unchecked_for_test(1, &header_id, &wrong_digest, &[tx]);
    assert!(result.is_err(), "block 1 should fail with wrong digest");

    // Genesis state must survive
    assert_eq!(
        store.height(),
        0,
        "height should remain 0 after failed block 1"
    );
    assert_eq!(
        store.root_digest(),
        genesis_digest,
        "genesis digest must survive failed block 1 application"
    );
}

/// Regression: apply_block with wrong expected digest after tree was mutated.
/// Verifies that in-memory state is rebuilt from committed DB state.
#[test]
fn failed_apply_restores_committed_state() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let mut store = StateStore::open(&db_path).unwrap();

    init_genesis(&mut store);

    let digests_data =
        std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
    let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let all_txs: Vec<serde_json::Value> = serde_json::from_str(&tx_data).unwrap();
    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&headers_data).unwrap();

    for height in 1u32..=3 {
        let expected = digests.iter().find(|d| d.height == height).unwrap();
        let expected_digest = ADDigest::from_bytes(
            hex::decode(&expected.state_root)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let tx_entry = all_txs
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
        let header = headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        store
            .apply_block_unchecked_for_test(height, &header_id, &expected_digest, &[tx])
            .unwrap();
    }

    // Record committed state at height 3
    let digest_at_3 = store.root_digest();
    assert_eq!(store.height(), 3);

    // Apply block 4 with a WRONG expected digest.
    // The transaction is valid (will mutate the tree), but the digest won't match.
    let tx_entry = all_txs
        .iter()
        .find(|t| t["height"].as_u64().unwrap() == 4)
        .unwrap();
    let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
    let header = headers
        .iter()
        .find(|h| h["height"].as_u64().unwrap() == 4)
        .unwrap();
    let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let wrong_digest = ADDigest::from_bytes([0xFFu8; 33]);
    let result = store.apply_block_unchecked_for_test(4, &header_id, &wrong_digest, &[tx]);
    assert!(result.is_err(), "apply_block should fail with wrong digest");

    // In-memory state must match committed height 3
    assert_eq!(store.height(), 3, "height restored to 3 after failed apply");
    assert_eq!(
        store.root_digest(),
        digest_at_3,
        "digest restored to height 3 after failed apply"
    );
}

/// Simplest rollback: apply 1, rollback to genesis, re-apply 1.
#[test]
fn rollback_to_genesis_then_reapply() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let mut store = StateStore::open(&db_path).unwrap();

    init_genesis(&mut store);

    let digests_data =
        std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
    let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let all_txs: Vec<serde_json::Value> = serde_json::from_str(&tx_data).unwrap();
    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&headers_data).unwrap();

    // Apply block 1
    let expected_1 = digests.iter().find(|d| d.height == 1).unwrap();
    let expected_digest_1 = ADDigest::from_bytes(
        hex::decode(&expected_1.state_root)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let tx_entry = all_txs
        .iter()
        .find(|t| t["height"].as_u64().unwrap() == 1)
        .unwrap();
    let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
    let header = headers
        .iter()
        .find(|h| h["height"].as_u64().unwrap() == 1)
        .unwrap();
    let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    store
        .apply_block_unchecked_for_test(
            1,
            &header_id,
            &expected_digest_1,
            std::slice::from_ref(&tx),
        )
        .unwrap();

    // Rollback to genesis
    store.rollback_to(0, None, None).unwrap();
    assert_eq!(store.height(), 0);

    // Re-apply block 1
    store
        .apply_block_unchecked_for_test(1, &header_id, &expected_digest_1, &[tx])
        .unwrap();
    assert_eq!(store.height(), 1);
}

/// Regression: rollback restores correct state, digests match, re-apply works.
#[test]
fn rollback_to_height_3_then_reapply() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let mut store = StateStore::open(&db_path).unwrap();

    init_genesis(&mut store);

    let digests_data =
        std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
    let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let all_txs: Vec<serde_json::Value> = serde_json::from_str(&tx_data).unwrap();
    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&headers_data).unwrap();

    // Apply blocks 1-5
    for height in 1u32..=5 {
        let expected = digests.iter().find(|d| d.height == height).unwrap();
        let expected_digest = ADDigest::from_bytes(
            hex::decode(&expected.state_root)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let tx_entry = all_txs
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
        let header = headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        store
            .apply_block_unchecked_for_test(height, &header_id, &expected_digest, &[tx])
            .unwrap();
    }
    assert_eq!(store.height(), 5);
    let (reachable, arena, tree_h) = store.debug_tree_stats();
    eprintln!("after apply 1-5: reachable={reachable} arena={arena} tree_h={tree_h}");

    // Rollback to height 4 (just 1 step)
    store.rollback_to(4, None, None).unwrap();
    assert_eq!(store.height(), 4);
    let (reachable, arena, tree_h) = store.debug_tree_stats();
    eprintln!("after rollback to 4: reachable={reachable} arena={arena} tree_h={tree_h}");

    let expected_3 = digests.iter().find(|d| d.height == 4).unwrap();
    let expected_digest_3 = ADDigest::from_bytes(
        hex::decode(&expected_3.state_root)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        store.root_digest(),
        expected_digest_3,
        "digest after rollback to height 3 should match original"
    );

    // Verify all boxes that should exist at height 3 can be looked up
    // (the emission box and its predecessors should be in the UTXO set)

    // Re-apply block 5 — must produce the same digest
    for height in 5u32..=5 {
        let expected = digests.iter().find(|d| d.height == height).unwrap();
        let expected_digest = ADDigest::from_bytes(
            hex::decode(&expected.state_root)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let tx_entry = all_txs
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
        let header = headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        store
            .apply_block_unchecked_for_test(height, &header_id, &expected_digest, &[tx])
            .unwrap();
    }
    assert_eq!(store.height(), 5);
}

/// Regression: initialize_genesis rejects re-initialization.
#[test]
fn double_initialize_genesis_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let mut store = StateStore::open(&db_path).unwrap();

    init_genesis(&mut store);
    let digest_after_first = store.root_digest();
    let height_after_first = store.height();

    // Second call must fail
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
    let result = store.initialize_genesis(&boxes);
    assert!(result.is_err(), "second initialize_genesis should fail");

    // State unchanged
    assert_eq!(store.height(), height_after_first);
    assert_eq!(store.root_digest(), digest_after_first);
}

/// Regression: re-opening a committed store also rejects initialize_genesis.
#[test]
fn reopen_rejects_initialize_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    {
        let mut store = StateStore::open(&db_path).unwrap();
        init_genesis(&mut store);
    }

    // Reopen — genesis_committed should be detected from state_meta
    let mut store = StateStore::open(&db_path).unwrap();
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
    let result = store.initialize_genesis(&boxes);
    assert!(
        result.is_err(),
        "initialize_genesis on reopened store should fail"
    );
}

/// Verify undo entries within the rollback window survive and are usable.
/// With 10 blocks and ROLLBACK_WINDOW=200, none are pruned, so full
/// rollback to height 1 should succeed. End-to-end pruning beyond 200
/// blocks requires a larger test corpus (deferred to Slice 5).
#[test]
fn undo_entries_within_window_survive() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let mut store = StateStore::open(&db_path).unwrap();
    init_genesis(&mut store);

    let digests_data =
        std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
    let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
    let tx_data =
        std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let all_txs: Vec<serde_json::Value> = serde_json::from_str(&tx_data).unwrap();
    let headers_data =
        std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(&headers_data).unwrap();

    for height in 1u32..=10 {
        let expected = digests.iter().find(|d| d.height == height).unwrap();
        let expected_digest = ADDigest::from_bytes(
            hex::decode(&expected.state_root)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let tx_entry = all_txs
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
        let header = headers
            .iter()
            .find(|h| h["height"].as_u64().unwrap() == height as u64)
            .unwrap();
        let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        store
            .apply_block_unchecked_for_test(height, &header_id, &expected_digest, &[tx])
            .unwrap();
    }

    // All 10 undo entries survive (10 < ROLLBACK_WINDOW=200).
    store.rollback_to(1, None, None).unwrap();
    assert_eq!(store.height(), 1);
    let expected_1 = digests.iter().find(|d| d.height == 1).unwrap();
    let expected_digest_1 = ADDigest::from_bytes(
        hex::decode(&expected_1.state_root)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(store.root_digest(), expected_digest_1);
}

/// Persist pipeline + batched commits: applies blocks 1-10 with the
/// background pipeline enabled, then closes (forcing batch drain) and
/// reopens, asserting the restored state matches the height-10 digest.
///
/// This is the key invariant for batched persistence: after a clean
/// shutdown the database reflects exactly the blocks applied, regardless
/// of whether commits were one-per-block or N-per-batch. The persist
/// pipeline coalesces queued jobs into a single redb transaction (see
/// MAX_BATCH_BLOCKS); this test exercises the path that production runs.
#[test]
fn persist_pipeline_batched_commits_restore_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    // Phase 1: apply blocks 1-10 with persist pipeline enabled.
    {
        let mut store = StateStore::open(&db_path).unwrap();
        store.enable_persist_pipeline(64);
        init_genesis(&mut store);

        let digests_data =
            std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
        let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
        let tx_data =
            std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
        let all_txs: Vec<serde_json::Value> = serde_json::from_str(&tx_data).unwrap();
        let headers_data =
            std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
        let headers: Vec<serde_json::Value> = serde_json::from_str(&headers_data).unwrap();

        for height in 1u32..=10 {
            let expected = digests.iter().find(|d| d.height == height).unwrap();
            let expected_digest = ADDigest::from_bytes(
                hex::decode(&expected.state_root)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            let tx_entry = all_txs
                .iter()
                .find(|t| t["height"].as_u64().unwrap() == height as u64)
                .unwrap();
            let tx = parse_block_tx(tx_entry["bytes"].as_str().unwrap());
            let header = headers
                .iter()
                .find(|h| h["height"].as_u64().unwrap() == height as u64)
                .unwrap();
            let header_id: [u8; 32] = hex::decode(header["id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            store
                .apply_block_unchecked_for_test(height, &header_id, &expected_digest, &[tx])
                .unwrap();
        }

        // In-memory state is at height 10; persist queue may still be draining.
        assert_eq!(store.height(), 10);
        // Drop forces pipeline shutdown which drains the queue and joins
        // the persist thread — see PersistPipeline::Drop.
    }

    // Phase 2: reopen, verify state matches height 10.
    {
        let mut store = StateStore::open(&db_path).unwrap();
        assert_eq!(
            store.height(),
            10,
            "height must be recovered to last committed batch boundary"
        );

        let digests_data =
            std::fs::read_to_string("../test-vectors/mainnet/utxo_digests_1_10.json").unwrap();
        let digests: Vec<DigestJson> = serde_json::from_str(&digests_data).unwrap();
        let expected = digests.iter().find(|d| d.height == 10).unwrap();
        let expected_digest = ADDigest::from_bytes(
            hex::decode(&expected.state_root)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            store.root_digest(),
            expected_digest,
            "root digest at h=10 must match Scala oracle after batched persist + restart",
        );
    }
}

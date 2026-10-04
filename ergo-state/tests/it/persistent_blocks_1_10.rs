//! Slice 4: Apply blocks 1-10 with redb persistence and atomic commit.
//! Verify captured state digests, ordinary clean reopen and rollback.

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

/// Replay a genuinely non-empty next block through the public cached prover.
/// Both committed roots come from the captured mainnet headers, while proof
/// bytes are compared against fresh snapshot/live hydration of the same state.
#[test]
fn cached_nonempty_mainnet_advance_matches_roots_fresh_proofs_and_reopen() {
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
    use ergo_ser::header::{read_header, serialize_header};
    use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
    use ergo_state::store::BaseDisposition;

    let headers: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/headers_1_10.json"
    ))
    .unwrap();
    let txs: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/transactions_1_10.json"
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let mut store = StateStore::open(&path).unwrap();
    init_genesis(&mut store);
    let mut base = None;
    let mut root_one = None;
    let mut expected_tip = [0; 32];
    for height in 1..=2 {
        let row = headers.iter().find(|r| r["height"] == height).unwrap();
        let bytes = hex::decode(row["bytes"].as_str().unwrap()).unwrap();
        let mut reader = VlqReader::new(&bytes);
        let header = read_header(&mut reader).unwrap();
        assert_eq!(reader.remaining(), 0);
        let id: [u8; 32] = hex::decode(row["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(serialize_header(&header).unwrap().1.as_bytes(), &id);
        let tx = parse_block_tx(
            txs.iter().find(|r| r["height"] == height).unwrap()["bytes"]
                .as_str()
                .unwrap(),
        );
        assert!(!tx.inputs.is_empty());
        assert!(!tx.output_candidates.is_empty());
        let section = BlockTransactions {
            header_id: ModifierId::from_bytes(id),
            transactions: vec![tx.clone()],
        };
        let mut writer = VlqWriter::new();
        write_block_transactions_with_version(&mut writer, &section, header.version).unwrap();
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &id,
            header.transactions_root.as_bytes(),
        );
        store.store_header(&id, &bytes).unwrap();
        store
            .store_block_section(&section_id, &writer.result())
            .unwrap();
        store
            .apply_block_unchecked_for_test(height, &id, &header.state_root, &[tx])
            .unwrap();
        assert_eq!(store.root_digest(), header.state_root);
        let snapshot = store.committed_snapshot().unwrap().unwrap();
        let mut disposition = None;
        let got = snapshot
            .candidate_dry_run_cached(&mut base, &[], &mut disposition)
            .unwrap();
        assert_eq!(got, snapshot.candidate_dry_run(&[]).unwrap());
        assert_eq!(got, store.candidate_dry_run(&[]).unwrap());
        assert_eq!(got.0, header.state_root);
        assert_eq!(got.2, id);
        assert_eq!(base.as_ref().unwrap().tip_id(), id);
        if height == 1 {
            root_one = Some(got.0);
            assert_eq!(disposition, Some(BaseDisposition::Rehydrated));
        } else {
            assert_ne!(root_one.unwrap(), got.0, "N+1 must change the UTXO tree");
            assert_eq!(disposition, Some(BaseDisposition::Advanced));
            let mut hit = None;
            assert_eq!(
                snapshot
                    .candidate_dry_run_cached(&mut base, &[], &mut hit)
                    .unwrap(),
                got
            );
            assert_eq!(hit, Some(BaseDisposition::Hit));
        }
        expected_tip = id;
    }
    let expected_root = store.root_digest();
    drop(base);
    drop(store);
    let mut reopened = StateStore::open(&path).unwrap();
    assert_eq!(reopened.height(), 2);
    assert_eq!(reopened.root_digest(), expected_root);
    assert_eq!(reopened.chain_state().best_full_block_id, expected_tip);
    let snapshot = reopened.committed_snapshot().unwrap().unwrap();
    assert_eq!(
        snapshot.candidate_dry_run(&[]).unwrap(),
        reopened.candidate_dry_run(&[]).unwrap()
    );
}

#[test]
fn snapshot_install_preserves_mainnet_lookups_forward_apply_and_reopen() {
    use ergo_avltree_rust::authenticated_tree_ops::AuthenticatedTreeOps;
    use ergo_ser::header::read_header;
    use ergo_state::avl::snapshot_codec::reconstruct_tree;
    use ergo_state::chain::HeaderMeta;

    /// Rebuild the committed tree from every persisted node. Cached labels
    /// and single-box lookups miss nodes overwritten by a stale allocator.
    fn committed_tree_root(store: &StateStore) -> ADDigest {
        let digest = store
            .committed_snapshot()
            .unwrap()
            .unwrap()
            .hydrate_prover()
            .unwrap()
            .digest()
            .unwrap();
        ADDigest::from_bytes(digest.as_ref().try_into().unwrap())
    }

    let headers: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/headers_1_10.json"
    ))
    .unwrap();
    let tx_rows: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/transactions_1_10.json"
    ))
    .unwrap();
    let parsed: Vec<_> = headers
        .iter()
        .map(|row| {
            let bytes = hex::decode(row["bytes"].as_str().unwrap()).unwrap();
            let header = read_header(&mut VlqReader::new(&bytes)).unwrap();
            let id: [u8; 32] = hex::decode(row["id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let tx = tx_rows
                .iter()
                .find(|tx| tx["height"].as_u64() == Some(u64::from(header.height)))
                .unwrap();
            (
                header,
                id,
                bytes,
                parse_block_tx(tx["bytes"].as_str().unwrap()),
            )
        })
        .collect();
    let source_dir = tempfile::tempdir().unwrap();
    let mut source = StateStore::open(&source_dir.path().join("state.redb")).unwrap();
    init_genesis(&mut source);
    for (header, id, _, tx) in parsed.iter().take(9) {
        source
            .apply_block_unchecked_for_test(
                header.height,
                id,
                &header.state_root,
                std::slice::from_ref(tx),
            )
            .unwrap();
    }
    let pinned_root = parsed[8].0.state_root;
    assert_eq!(source.root_digest(), pinned_root);
    let served = source.build_snapshot_at_tip(2).unwrap();
    let chunks = served.chunks.iter().cloned().collect();
    let spend_id = *parsed[9].3.inputs[0].box_id.as_bytes();
    let spend_bytes = source.get_box_bytes(&spend_id).unwrap();

    for (pipelined, reopen_before_install) in [(false, true), (true, false), (true, true)] {
        for reopen_before_apply in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.redb");
            let mut store = StateStore::open(&path).unwrap();
            init_genesis(&mut store);
            if reopen_before_install {
                // An ordinary reopen materializes the genesis allocator row.
                drop(store);
                store = StateStore::open(&path).unwrap();
            }
            for (header, id, bytes, _) in &parsed {
                let meta = HeaderMeta {
                    height: header.height,
                    parent_id: *header.parent_id.as_bytes(),
                    timestamp: header.timestamp,
                    cumulative_score: u64::from(header.height).to_be_bytes().to_vec(),
                    pow_validity: 1,
                };
                store
                    .store_validated_header(
                        id,
                        bytes,
                        &meta,
                        Some((header.height, meta.cumulative_score.clone())),
                    )
                    .unwrap();
            }
            if pipelined {
                store.enable_persist_pipeline(2).unwrap();
            }
            let old_root = store.root_digest();
            let old_committed = store.committed_snapshot().unwrap().unwrap();
            store
                .install_snapshot_state(
                    reconstruct_tree(&served.manifest_bytes, &chunks).unwrap(),
                    9,
                    parsed[8].1,
                    &pinned_root,
                )
                .unwrap();
            assert_eq!(store.height(), 9);
            assert_eq!(store.root_digest(), pinned_root);
            assert_eq!(old_committed.state_root(), old_root);
            assert_eq!(old_committed.lookup_box(&spend_id).unwrap(), None);
            drop(old_committed);
            assert_eq!(store.get_box_bytes(&spend_id), Some(spend_bytes.clone()));
            let committed = store.committed_snapshot().unwrap().unwrap();
            assert_eq!(
                committed.lookup_box(&spend_id).unwrap(),
                Some(spend_bytes.clone())
            );
            assert_eq!(
                committed
                    .hydrate_prover()
                    .unwrap()
                    .digest()
                    .unwrap()
                    .as_ref(),
                pinned_root.as_bytes()
            );
            drop(committed);

            if reopen_before_apply {
                store.shutdown_cleanly().unwrap();
                drop(store);
                store = StateStore::open(&path).unwrap();
                assert_eq!(store.height(), 9);
                assert_eq!(store.get_box_bytes(&spend_id), Some(spend_bytes.clone()));
                if pipelined {
                    store.enable_persist_pipeline(2).unwrap();
                }
            }
            store
                .apply_block_unchecked_for_test(
                    10,
                    &parsed[9].1,
                    &parsed[9].0.state_root,
                    std::slice::from_ref(&parsed[9].3),
                )
                .unwrap();
            store.flush_persist_pipeline().unwrap();
            if pipelined {
                let progress = store.persistence_progress().unwrap();
                assert_eq!(progress.enqueued_jobs, 1);
                assert_eq!(progress.committed_jobs, 1);
                // The worker must publish commit progress to the arena the
                // install created, or committed nodes stay pinned for good.
                assert_eq!(store.metrics().arena_unpersisted_pinned_bytes, 0);
            }
            assert_eq!(store.root_digest(), parsed[9].0.state_root);
            assert_eq!(committed_tree_root(&store), parsed[9].0.state_root);
            store.rollback_to(9, None, None).unwrap();
            assert_eq!(store.root_digest(), pinned_root);
            assert_eq!(store.get_box_bytes(&spend_id), Some(spend_bytes.clone()));
            assert_eq!(committed_tree_root(&store), pinned_root);
            store.shutdown_cleanly().unwrap();
            drop(store);
            let mut reopened = StateStore::open(&path).unwrap();
            assert_eq!(reopened.height(), 9);
            assert_eq!(reopened.root_digest(), pinned_root);
            assert_eq!(reopened.get_box_bytes(&spend_id), Some(spend_bytes.clone()));
            assert_eq!(committed_tree_root(&reopened), pinned_root);
        }
    }
}

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
fn clean_reopen_restores_state() {
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
        // Ordinary Drop closes the store; this does not simulate process exit
        // or physical power loss.
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
fn rollback_to_height_4_then_reapply() {
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

    let expected_4 = digests.iter().find(|d| d.height == 4).unwrap();
    let expected_digest_4 = ADDigest::from_bytes(
        hex::decode(&expected_4.state_root)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        store.root_digest(),
        expected_digest_4,
        "digest after rollback to height 4 should match original"
    );

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
/// pipeline may coalesce queued jobs into a redb transaction; scheduling here
/// does not prove that any particular batch contains multiple jobs.
#[test]
fn persist_pipeline_batched_commits_restore_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");

    // Phase 1: apply blocks 1-10 with persist pipeline enabled.
    {
        let mut store = StateStore::open(&db_path).unwrap();
        store.enable_persist_pipeline(64).unwrap();
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

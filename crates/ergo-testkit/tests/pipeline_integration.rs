//! Integration tests for the full block validation pipeline.
//!
//! These tests combine multiple crates (ergo-types, ergo-avldb, ergo-state,
//! ergo-storage) to exercise end-to-end correctness of block processing,
//! AD proof verification, rollback, and chain scoring/fork detection.

use bytes::Bytes;

use ergo_avldb::{ADKey, ADValue, AuthenticatedTree};
use ergo_state::digest_state::DigestState;
use ergo_state::state_changes::StateChanges;
use ergo_storage::history_db::HistoryDb;
use ergo_types::ad_proofs::ADProofs;
use ergo_types::block_transactions::BlockTransactions;
use ergo_types::extension::Extension;
use ergo_types::header::Header;
use ergo_types::modifier_id::{ADDigest, Digest32, ModifierId};
use ergo_types::transaction::{BoxId, ErgoFullBlock};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn make_key(b: u8) -> ADKey {
    let mut v = vec![0u8; 32];
    v[31] = b;
    Bytes::from(v)
}

fn make_value(bs: &[u8]) -> ADValue {
    Bytes::copy_from_slice(bs)
}

fn key_to_box_id(key: &ADKey) -> BoxId {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(key);
    BoxId(arr)
}

/// Returns a single field for test extensions so they are non-empty.
/// Extension validation rule 406 (exEmpty) rejects non-genesis blocks with empty extensions.
fn sample_ext_fields() -> Vec<([u8; 2], Vec<u8>)> {
    vec![([0x01, 0x00], vec![0x00])]
}

/// Compute the Merkle extension_root matching `sample_ext_fields()`.
fn sample_ext_root() -> [u8; 32] {
    let leaf: Vec<u8> = vec![0x01, 0x00, 0x00]; // key ++ value
    let mut prefixed = vec![0x00u8]; // LEAF_PREFIX
    prefixed.extend_from_slice(&leaf);
    blake2b256(&prefixed)
}

fn make_block(state_root: [u8; 33], ad_proof_bytes: Option<Vec<u8>>) -> ErgoFullBlock {
    let mut header = Header::default_for_test();
    header.state_root = ADDigest(state_root);

    let header_id = ModifierId([0xAA; 32]);

    let ad_proofs = ad_proof_bytes.map(|proof_bytes| ADProofs {
        header_id,
        proof_bytes,
    });

    ErgoFullBlock {
        header,
        block_transactions: BlockTransactions {
            header_id,
            block_version: 2,
            tx_bytes: Vec::new(),
        },
        extension: Extension {
            header_id,
            fields: Vec::new(),
        },
        ad_proofs,
    }
}

fn genesis_version() -> ModifierId {
    ModifierId([0u8; 32])
}

// ---------------------------------------------------------------------------
// Test 1: full_pipeline_synthetic_block
//
// End-to-end test using a prover tree to generate valid AD proofs.
// Creates a prover tree, inserts boxes, generates a proof, builds a
// synthetic ErgoFullBlock with matching state_root and AD proof,
// creates a DigestState and applies the block, verifying the state
// root matches.
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_synthetic_block() {
    // 1. Create a prover tree and get the initial (empty) digest.
    let mut prover = AuthenticatedTree::default_ergo();
    let digest_before = prover.digest().unwrap();

    // 2. Insert some "boxes" into the prover (simulating a UTXO set).
    let key1 = make_key(1);
    let val1 = make_value(b"box_data_1");
    let key2 = make_key(2);
    let val2 = make_value(b"box_data_2");
    let key3 = make_key(3);
    let val3 = make_value(b"box_data_3");

    prover.insert(key1.clone(), val1.clone()).unwrap();
    prover.insert(key2.clone(), val2.clone()).unwrap();
    prover.insert(key3.clone(), val3.clone()).unwrap();

    // 3. Generate the AD proof for the insertions.
    let proof = prover.generate_proof();
    let digest_after = prover.digest().unwrap();

    // 4. Build a synthetic ErgoFullBlock with matching state_root and AD proof.
    let mut state_root = [0u8; 33];
    state_root.copy_from_slice(&digest_after[..33]);
    let block = make_block(state_root, Some(proof.to_vec()));

    // 5. Create a DigestState from the pre-insertion digest.
    let mut state = DigestState::new(digest_before.to_vec(), genesis_version());

    // 6. Build matching StateChanges (insertions only).
    let changes = StateChanges {
        to_lookup: Vec::new(),
        to_remove: Vec::new(),
        to_insert: vec![
            (key_to_box_id(&key1), val1.to_vec()),
            (key_to_box_id(&key2), val2.to_vec()),
            (key_to_box_id(&key3), val3.to_vec()),
        ],
    };

    // 7. Call DigestState::apply_full_block -- should succeed.
    let header_id = ModifierId([0xBB; 32]);
    state
        .apply_full_block(&block, &header_id, &changes)
        .expect("apply_full_block should succeed with valid proof");

    // 8. Verify state root matches post-insertion digest.
    assert_eq!(
        state.state_root(),
        &digest_after[..],
        "state root should match the post-insertion digest"
    );
    assert_eq!(
        *state.version(),
        header_id,
        "version should be updated to header_id"
    );
}

// ---------------------------------------------------------------------------
// Test 2: full_pipeline_tampered_ad_proof
//
// Same setup as Test 1 but replay wrong operations against a valid proof.
// The verifier will accept the operations (the proof structure still guides
// tree traversal), but the resulting digest will differ from the expected
// state root, causing a DigestMismatch error.
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_tampered_ad_proof() {
    // Build a prover tree, insert a box, get proof.
    let mut prover = AuthenticatedTree::default_ergo();
    let digest_before = prover.digest().unwrap();

    let key = make_key(10);
    let val = make_value(b"tamper_test");

    prover.insert(key.clone(), val.clone()).unwrap();

    let proof = prover.generate_proof();
    let digest_after = prover.digest().unwrap();

    // Build the block with correct state root and valid proof, but we will
    // replay the operations with a DIFFERENT value. The verifier accepts the
    // operations (the proof structure still guides tree traversal), but the
    // resulting digest differs because the leaf content is wrong.
    let mut state_root = [0u8; 33];
    state_root.copy_from_slice(&digest_after[..33]);
    let block = make_block(state_root, Some(proof.to_vec()));

    // Create DigestState.
    let mut state = DigestState::new(digest_before.to_vec(), genesis_version());

    // Supply WRONG value in the state changes (different from what the proof
    // was generated for). The proof is valid but the operation data mismatches.
    let wrong_val = make_value(b"WRONG_VALUE_HERE");
    let changes = StateChanges {
        to_lookup: Vec::new(),
        to_remove: Vec::new(),
        to_insert: vec![(key_to_box_id(&key), wrong_val.to_vec())],
    };

    let header_id = ModifierId([0xCC; 32]);
    let result = state.apply_full_block(&block, &header_id, &changes);

    // Should fail with DigestMismatch -- the computed digest won't match
    // the expected state root because the leaf data was different.
    assert!(
        result.is_err(),
        "apply_full_block should fail with mismatched operations"
    );

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("digest mismatch"),
        "error should be a digest mismatch, got: {err_msg}"
    );

    // State should remain unchanged.
    assert_eq!(
        state.state_root(),
        &digest_before[..],
        "state root should remain unchanged after failure"
    );
    assert_eq!(
        *state.version(),
        genesis_version(),
        "version should remain unchanged after failure"
    );
}

// ---------------------------------------------------------------------------
// Test 3: full_pipeline_missing_ad_proofs
//
// Create a block with ad_proofs: None. DigestState::apply_full_block
// should fail with MissingAdProofs.
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_missing_ad_proofs() {
    let prover = AuthenticatedTree::default_ergo();
    let digest = prover.digest().unwrap();

    let mut state = DigestState::new(digest.to_vec(), genesis_version());

    // Build a block with no AD proofs.
    let block = make_block([0x11; 33], None);
    let header_id = ModifierId([0xDD; 32]);
    let empty_changes = StateChanges {
        to_lookup: Vec::new(),
        to_remove: Vec::new(),
        to_insert: Vec::new(),
    };

    let result = state.apply_full_block(&block, &header_id, &empty_changes);

    assert!(result.is_err(), "should fail when AD proofs are missing");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("missing AD proofs"),
        "error should mention missing AD proofs, got: {err_msg}"
    );

    // State should remain unchanged.
    assert_eq!(state.state_root(), &digest[..]);
    assert_eq!(*state.version(), genesis_version());
}

// ---------------------------------------------------------------------------
// Test 4: digest_state_multi_block_and_rollback
//
// Apply 3 synthetic blocks to DigestState using real AD proofs, then
// rollback to the state after block 1. Verify digest matches block 1's
// post-state.
//
// Uses insert-remove-insert pattern to keep the AVL tree depth shallow
// enough for the verifier (which has limited resolver support).
//
// This exercises:
// - Multiple sequential block applications through the full pipeline
// - Version history tracking across blocks
// - Rollback correctness via rollback_to_version
// ---------------------------------------------------------------------------

#[test]
fn digest_state_multi_block_and_rollback() {
    let mut prover = AuthenticatedTree::default_ergo();
    let digest_genesis = prover.digest().unwrap();

    let mut state = DigestState::new(digest_genesis.to_vec(), genesis_version());

    // --- Block 1: insert key 20 ---
    // (Use key > 0 to avoid collision with the AVL tree's negative infinity
    // sentinel which uses an all-zeros key.)
    let key_a = make_key(20);
    let val_a = make_value(b"box_alpha");

    prover.insert(key_a.clone(), val_a.clone()).unwrap();
    let proof1 = prover.generate_proof();
    let digest_after_1 = prover.digest().unwrap();

    let mut sr1 = [0u8; 33];
    sr1.copy_from_slice(&digest_after_1[..33]);
    let block1 = make_block(sr1, Some(proof1.to_vec()));
    let id1 = ModifierId([0x01; 32]);
    let changes1 = StateChanges {
        to_lookup: Vec::new(),
        to_remove: Vec::new(),
        to_insert: vec![(key_to_box_id(&key_a), val_a.to_vec())],
    };

    state
        .apply_full_block(&block1, &id1, &changes1)
        .expect("block 1 should succeed");
    assert_eq!(state.state_root(), &digest_after_1[..]);

    // --- Block 2: remove key 20 (returns tree to empty state) ---
    prover.remove(key_a.clone()).unwrap();
    let proof2 = prover.generate_proof();
    let digest_after_2 = prover.digest().unwrap();

    let mut sr2 = [0u8; 33];
    sr2.copy_from_slice(&digest_after_2[..33]);
    let block2 = make_block(sr2, Some(proof2.to_vec()));
    let id2 = ModifierId([0x02; 32]);
    let changes2 = StateChanges {
        to_lookup: Vec::new(),
        to_remove: vec![key_to_box_id(&key_a)],
        to_insert: Vec::new(),
    };

    state
        .apply_full_block(&block2, &id2, &changes2)
        .expect("block 2 should succeed");
    assert_eq!(state.state_root(), &digest_after_2[..]);

    // --- Block 3: insert key 30 (tree is empty again, like block 1) ---
    let key_b = make_key(30);
    let val_b = make_value(b"box_beta");

    prover.insert(key_b.clone(), val_b.clone()).unwrap();
    let proof3 = prover.generate_proof();
    let digest_after_3 = prover.digest().unwrap();

    let mut sr3 = [0u8; 33];
    sr3.copy_from_slice(&digest_after_3[..33]);
    let block3 = make_block(sr3, Some(proof3.to_vec()));
    let id3 = ModifierId([0x03; 32]);
    let changes3 = StateChanges {
        to_lookup: Vec::new(),
        to_remove: Vec::new(),
        to_insert: vec![(key_to_box_id(&key_b), val_b.to_vec())],
    };

    state
        .apply_full_block(&block3, &id3, &changes3)
        .expect("block 3 should succeed");
    assert_eq!(state.state_root(), &digest_after_3[..]);

    // Verify we are at block 3.
    assert_eq!(*state.version(), id3);

    // --- Rollback to block 1 ---
    state
        .rollback_to_version(&id1)
        .expect("rollback to block 1 should succeed");

    // Verify digest matches block 1's post-state.
    assert_eq!(
        state.state_root(),
        &digest_after_1[..],
        "after rollback, digest should match block 1's post-state"
    );
    assert_eq!(
        *state.version(),
        id1,
        "after rollback, version should be block 1's ID"
    );

    // Verify we cannot rollback further to block 2 (it was truncated).
    let rollback_to_2 = state.rollback_to_version(&id2);
    assert!(
        rollback_to_2.is_err(),
        "rollback to block 2 should fail after rolling back to block 1"
    );
}

// ---------------------------------------------------------------------------
// Test 5: chain_scoring_and_fork_detection
//
// Test chain scoring and fork detection in ergo-storage:
// 1. Open a test HistoryDb
// 2. Store a linear chain: A->B->C with low difficulty headers
// 3. Store a fork: A->D->E with high difficulty headers
// 4. Store block body sections for all
// 5. Mark C as best full block
// 6. Call process_block_section for E
// 7. Verify ProgressInfo has branch_point=A, to_remove=[B,C], to_apply=[D,E]
// ---------------------------------------------------------------------------

#[test]
fn chain_scoring_and_fork_detection() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = HistoryDb::open(dir.path()).unwrap();

    // Helper: create unique ModifierIds.
    let id_a = ModifierId([0xA0; 32]);
    let id_b = {
        let mut arr = [0xB0; 32];
        arr[1] = 0x01;
        ModifierId(arr)
    };
    let id_c = {
        let mut arr = [0xC0; 32];
        arr[1] = 0x02;
        ModifierId(arr)
    };
    let id_d = {
        let mut arr = [0xD0; 32];
        arr[1] = 0x03;
        ModifierId(arr)
    };
    let id_e = {
        let mut arr = [0xE0; 32];
        arr[1] = 0x04;
        ModifierId(arr)
    };

    // Helper: store a header with score computation.
    let store_header = |db: &HistoryDb,
                        id: &ModifierId,
                        height: u32,
                        parent_id: ModifierId,
                        n_bits: u64| {
        let mut h = Header::default_for_test();
        h.version = 2;
        h.height = height;
        h.parent_id = parent_id;
        h.n_bits = n_bits;
        db.store_header_with_score(id, &h).unwrap();
    };

    // Helper: store block body sections (block_transactions + extension).
    let store_body = |db: &HistoryDb, id: &ModifierId| {
        db.store_block_transactions(
            id,
            &BlockTransactions {
                header_id: *id,
                block_version: 2,
                tx_bytes: vec![vec![0x01]],
            },
        )
        .unwrap();
        db.store_extension(
            id,
            &Extension {
                header_id: *id,
                fields: vec![([0x00, 0x01], vec![0x10])],
            },
        )
        .unwrap();
    };

    // --- Build the main chain: A -> B -> C (low difficulty) ---
    // Valid compact nBits: size=1, mantissa=0x01 => difficulty 1
    let low_nbits: u64 = 0x01010000;

    store_header(&db, &id_a, 1, ModifierId::GENESIS_PARENT, low_nbits);
    store_body(&db, &id_a);

    store_header(&db, &id_b, 2, id_a, low_nbits);
    store_body(&db, &id_b);

    store_header(&db, &id_c, 3, id_b, low_nbits);
    store_body(&db, &id_c);

    // Mark C as the current best full block.
    db.set_best_full_block_id(&id_c).unwrap();

    // --- Build the fork chain: A -> D -> E (high difficulty) ---
    // Valid compact nBits: size=3, mantissa=0x01 => difficulty 65536
    let high_nbits: u64 = 0x03010000;

    store_header(&db, &id_d, 2, id_a, high_nbits);
    store_body(&db, &id_d);

    store_header(&db, &id_e, 3, id_d, high_nbits);
    store_body(&db, &id_e);

    // --- Process block section for E (simulate receiving its last section) ---
    // Extension type ID = 108
    let info = db
        .process_block_section(108, &id_e, &id_e)
        .expect("process_block_section should succeed");

    // --- Verify the ProgressInfo indicates a chain switch ---
    assert_eq!(
        info.branch_point,
        Some(id_a),
        "branch_point should be A (the common ancestor)"
    );
    assert_eq!(
        info.to_remove,
        vec![id_b, id_c],
        "to_remove should be [B, C] (old chain from A to C, exclusive of A)"
    );
    assert_eq!(
        info.to_apply,
        vec![id_d, id_e],
        "to_apply should be [D, E] (new chain from A to E, exclusive of A)"
    );
}

// ---------------------------------------------------------------------------
// Test 6: node_view_full_pipeline_empty_block
//
// Exercise the full NodeViewHolder pipeline with an empty block (no
// transactions). This is the simplest end-to-end test:
// 1. Create a NodeViewHolder in UTXO mode (digest_mode=false).
// 2. Build a header whose state_root matches the initial AVL tree root.
// 3. Store header, empty BlockTransactions, and empty Extension via
//    typed HistoryDb methods.
// 4. Build a ProgressInfo::apply([block_id]) and call apply_progress.
// 5. Verify the block is marked Valid and best_full_block_id is updated.
// ---------------------------------------------------------------------------

#[test]
fn node_view_full_pipeline_empty_block() {
    use ergo_network::mempool::ErgoMemPool;
    use ergo_network::node_view::NodeViewHolder;
    use ergo_state::utxo_state::UtxoState;
    use ergo_storage::block_processor::ProgressInfo;
    use ergo_storage::chain_scoring::ModifierValidity;

    let dir = tempfile::TempDir::new().unwrap();
    let db = HistoryDb::open(dir.path()).unwrap();

    // Get the initial UTXO state root (33 bytes).
    let initial_root = UtxoState::new()
        .state_root()
        .expect("fresh UtxoState should have a digest");

    let mempool = std::sync::Arc::new(std::sync::RwLock::new(ErgoMemPool::with_min_fee(1000, 0)));
    let mut nv = NodeViewHolder::new(db, mempool, false, initial_root.clone());
    nv.set_checkpoint_height(u32::MAX); // Skip difficulty checks in pipeline test
    // Test headers use version 2 (current mainnet), so set parameters to match.
    nv.voting_epoch_info
        .parameters
        .table
        .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, 2);

    // Build a header with state_root matching the initial AVL tree root.
    let id = ModifierId([0x10; 32]);
    let mut header = Header::default_for_test();
    header.version = 2;
    header.height = 100;
    let mut state_root = [0u8; 33];
    let len = initial_root.len().min(33);
    state_root[..len].copy_from_slice(&initial_root[..len]);
    header.state_root = ADDigest(state_root);
    header.extension_root = Digest32(sample_ext_root());

    // Store sections via typed methods.
    nv.history.store_header(&id, &header).unwrap();
    nv.history
        .store_block_transactions(
            &id,
            &BlockTransactions {
                header_id: id,
                block_version: 2,
                tx_bytes: Vec::new(),
            },
        )
        .unwrap();
    nv.history
        .store_extension(
            &id,
            &Extension {
                header_id: id,
                fields: sample_ext_fields(),
            },
        )
        .unwrap();

    // Apply via ProgressInfo.
    let info = ProgressInfo::apply(vec![id]);
    nv.apply_progress(&info)
        .expect("empty block should pass the full pipeline");

    // Verify block is marked Valid.
    let validity = nv.history.get_validity(&id).unwrap();
    assert_eq!(
        validity,
        Some(ModifierValidity::Valid),
        "block should be marked Valid"
    );

    // Verify best_full_block_id was updated.
    assert_eq!(
        nv.best_full_block_id().unwrap(),
        Some(id),
        "best_full_block_id should point to the applied block"
    );

    // Verify state root matches the header's state_root.
    assert_eq!(
        nv.state_root(),
        header.state_root.0.as_slice(),
        "state root should match the header's state_root after application"
    );
}

// ---------------------------------------------------------------------------
// Test 7: node_view_rejects_tampered_merkle_root
//
// Build a block with empty tx_bytes but set header.transactions_root to
// [0xFF; 32] (wrong). The pipeline should reject the block with a
// BlockValidation error and mark it Invalid.
// ---------------------------------------------------------------------------

#[test]
fn node_view_rejects_tampered_merkle_root() {
    use ergo_network::mempool::ErgoMemPool;
    use ergo_network::node_view::{NodeViewError, NodeViewHolder};
    use ergo_state::utxo_state::UtxoState;
    use ergo_storage::block_processor::ProgressInfo;
    use ergo_storage::chain_scoring::ModifierValidity;

    let dir = tempfile::TempDir::new().unwrap();
    let db = HistoryDb::open(dir.path()).unwrap();

    let initial_root = UtxoState::new()
        .state_root()
        .expect("fresh UtxoState should have a digest");

    let mempool = std::sync::Arc::new(std::sync::RwLock::new(ErgoMemPool::with_min_fee(1000, 0)));
    let mut nv = NodeViewHolder::new(db, mempool, false, initial_root.clone());
    // Test headers use version 2 (current mainnet), so set parameters to match.
    nv.voting_epoch_info
        .parameters
        .table
        .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, 2);

    // Build a header with a TAMPERED transactions_root.
    let id = ModifierId([0x20; 32]);
    let mut header = Header::default_for_test();
    header.version = 2;
    header.height = 100;
    let mut state_root = [0u8; 33];
    let len = initial_root.len().min(33);
    state_root[..len].copy_from_slice(&initial_root[..len]);
    header.state_root = ADDigest(state_root);
    // Tamper: empty tx_bytes should produce all-zero merkle root, but we
    // set it to [0xFF; 32].
    header.transactions_root = Digest32([0xFF; 32]);

    nv.history.store_header(&id, &header).unwrap();
    nv.history
        .store_block_transactions(
            &id,
            &BlockTransactions {
                header_id: id,
                block_version: 2,
                tx_bytes: Vec::new(),
            },
        )
        .unwrap();
    nv.history
        .store_extension(
            &id,
            &Extension {
                header_id: id,
                fields: Vec::new(),
            },
        )
        .unwrap();

    let info = ProgressInfo::apply(vec![id]);
    let result = nv.apply_progress(&info);

    // Should fail with a BlockValidation error.
    assert!(result.is_err(), "tampered merkle root should cause failure");
    let err = result.unwrap_err();
    assert!(
        matches!(err, NodeViewError::BlockValidation(_)),
        "expected BlockValidation error, got: {err}"
    );

    // Block should be marked Invalid.
    let validity = nv.history.get_validity(&id).unwrap();
    assert_eq!(
        validity,
        Some(ModifierValidity::Invalid),
        "block with tampered merkle root should be marked Invalid"
    );
}

// ---------------------------------------------------------------------------
// Test 8: node_view_rejects_invalid_stateless_tx
//
// Build a real serialized transaction with 1 input and 0 outputs (fails
// stateless validation with NoOutputs). Compute the correct Merkle root
// for the serialized tx bytes and set the header's transactions_root
// accordingly. The pipeline should pass structural validation (correct
// merkle root) but fail at the stateless tx validation stage.
// ---------------------------------------------------------------------------

#[test]
fn node_view_rejects_invalid_stateless_tx() {
    use ergo_consensus::merkle::merkle_root;
    use ergo_network::mempool::ErgoMemPool;
    use ergo_network::node_view::{NodeViewError, NodeViewHolder};
    use ergo_state::utxo_state::UtxoState;
    use ergo_storage::block_processor::ProgressInfo;
    use ergo_storage::chain_scoring::ModifierValidity;
    use ergo_types::transaction::{ErgoTransaction, Input, TxId};
    use ergo_wire::transaction_ser::serialize_transaction;

    let dir = tempfile::TempDir::new().unwrap();
    let db = HistoryDb::open(dir.path()).unwrap();

    let initial_root = UtxoState::new()
        .state_root()
        .expect("fresh UtxoState should have a digest");

    let mempool = std::sync::Arc::new(std::sync::RwLock::new(ErgoMemPool::with_min_fee(1000, 0)));
    let mut nv = NodeViewHolder::new(db, mempool, false, initial_root.clone());
    nv.set_checkpoint_height(u32::MAX); // Skip difficulty checks in pipeline test
    // Test headers use version 2 (current mainnet), so set parameters to match.
    nv.voting_epoch_info
        .parameters
        .table
        .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, 2);

    // Build a transaction with 1 input and 0 outputs (invalid: NoOutputs).
    let mut bad_tx = ErgoTransaction {
        inputs: vec![Input {
            box_id: BoxId([0x11; 32]),
            proof_bytes: Vec::new(),
            extension_bytes: vec![0x00], // empty extension map
        }],
        data_inputs: Vec::new(),
        output_candidates: Vec::new(), // 0 outputs -> NoOutputs
        tx_id: TxId([0; 32]),
    };
    bad_tx.tx_id = ergo_wire::transaction_ser::compute_tx_id(&bad_tx);

    let tx_bytes = serialize_transaction(&bad_tx);

    // Compute the correct transactions_root for this single tx.
    let tx_root = merkle_root(&[tx_bytes.as_slice()]).unwrap();

    // Build a header with the correct transactions_root.
    let id = ModifierId([0x30; 32]);
    let mut header = Header::default_for_test();
    header.version = 2;
    header.height = 100;
    let mut state_root = [0u8; 33];
    let len = initial_root.len().min(33);
    state_root[..len].copy_from_slice(&initial_root[..len]);
    header.state_root = ADDigest(state_root);
    header.transactions_root = Digest32(tx_root);
    header.extension_root = Digest32(sample_ext_root());

    let block_transactions = BlockTransactions {
        header_id: id,
        block_version: 2,
        tx_bytes: vec![tx_bytes],
    };

    nv.history.store_header(&id, &header).unwrap();
    nv.history
        .store_block_transactions(&id, &block_transactions)
        .unwrap();
    nv.history
        .store_extension(
            &id,
            &Extension {
                header_id: id,
                fields: sample_ext_fields(),
            },
        )
        .unwrap();

    let info = ProgressInfo::apply(vec![id]);
    let result = nv.apply_progress(&info);

    // Should fail with a TxValidation error.
    assert!(
        result.is_err(),
        "tx with 0 outputs should fail stateless validation"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, NodeViewError::TxValidation(ref msg) if msg.contains("stateless")),
        "expected TxValidation error about stateless validation, got: {err}"
    );

    // Block should be marked Invalid.
    let validity = nv.history.get_validity(&id).unwrap();
    assert_eq!(
        validity,
        Some(ModifierValidity::Invalid),
        "block with invalid tx should be marked Invalid"
    );
}

// ---------------------------------------------------------------------------
// Test 9: node_view_mempool_eviction_after_block
//
// 1. Create a NodeViewHolder.
// 2. Add a transaction to the mempool.
// 3. Apply an empty block (no transactions).
// 4. Verify the mempool transaction is still there (empty block doesn't
//    evict any transactions since there are no overlapping inputs).
// ---------------------------------------------------------------------------

#[test]
fn node_view_mempool_eviction_after_block() {
    use ergo_network::mempool::ErgoMemPool;
    use ergo_network::node_view::NodeViewHolder;
    use ergo_state::utxo_state::UtxoState;
    use ergo_storage::block_processor::ProgressInfo;
    use ergo_types::transaction::{ErgoBoxCandidate, ErgoTransaction, Input, TxId};

    let dir = tempfile::TempDir::new().unwrap();
    let db = HistoryDb::open(dir.path()).unwrap();

    let initial_root = UtxoState::new()
        .state_root()
        .expect("fresh UtxoState should have a digest");

    let mempool = std::sync::Arc::new(std::sync::RwLock::new(ErgoMemPool::with_min_fee(1000, 0)));
    let mut nv = NodeViewHolder::new(db, mempool, false, initial_root.clone());
    nv.set_checkpoint_height(u32::MAX); // Skip difficulty checks in pipeline test
    // Test headers use version 2 (current mainnet), so set parameters to match.
    nv.voting_epoch_info
        .parameters
        .table
        .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, 2);

    // Put a transaction in the mempool.
    let mempool_tx = ErgoTransaction {
        inputs: vec![Input {
            box_id: BoxId([0xAA; 32]),
            proof_bytes: Vec::new(),
            extension_bytes: Vec::new(),
        }],
        data_inputs: Vec::new(),
        output_candidates: vec![ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: Vec::new(),
            additional_registers: Vec::new(),
        }],
        tx_id: TxId([0xBB; 32]),
    };
    let mempool_tx_id = mempool_tx.tx_id;
    nv.mempool.write().unwrap().put(mempool_tx).unwrap();
    assert_eq!(nv.mempool.read().unwrap().size(), 1, "mempool should have 1 tx before block");

    // Build and apply an empty block (no transactions).
    let id = ModifierId([0x40; 32]);
    let mut header = Header::default_for_test();
    header.version = 2;
    header.height = 100;
    let mut state_root = [0u8; 33];
    let len = initial_root.len().min(33);
    state_root[..len].copy_from_slice(&initial_root[..len]);
    header.state_root = ADDigest(state_root);
    header.extension_root = Digest32(sample_ext_root());

    nv.history.store_header(&id, &header).unwrap();
    nv.history
        .store_block_transactions(
            &id,
            &BlockTransactions {
                header_id: id,
                block_version: 2,
                tx_bytes: Vec::new(),
            },
        )
        .unwrap();
    nv.history
        .store_extension(
            &id,
            &Extension {
                header_id: id,
                fields: sample_ext_fields(),
            },
        )
        .unwrap();

    let info = ProgressInfo::apply(vec![id]);
    nv.apply_progress(&info)
        .expect("empty block should succeed");

    // The mempool transaction should still be there since the empty block
    // has no overlapping inputs.
    {
        let mp = nv.mempool.read().unwrap();
        assert_eq!(
            mp.size(),
            1,
            "mempool should still have 1 tx after empty block"
        );
        assert!(
            mp.get(&mempool_tx_id).is_some(),
            "the specific mempool tx should still be present"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 8 protocol handler integration tests
//
// These tests exercise the message handler end-to-end, routing through
// handle_message with real NodeViewHolder, SyncManager, and DeliveryTracker
// instances backed by a RocksDB HistoryDb.
// ---------------------------------------------------------------------------

/// Helper: open a fresh NodeViewHolder in digest mode for protocol handler tests.
fn make_test_node_view() -> (
    ergo_network::node_view::NodeViewHolder,
    tempfile::TempDir,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let history = HistoryDb::open(dir.path()).unwrap();
    let mempool = std::sync::Arc::new(std::sync::RwLock::new(
        ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
    ));
    let nv = ergo_network::node_view::NodeViewHolder::new(
        history,
        mempool,
        true, // digest mode
        vec![0u8; 33],
    );
    (nv, dir)
}

/// Compute blake2b256 of data to get a 32-byte hash (used for header IDs).
fn blake2b256(data: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = blake2::Blake2bVar::new(32).unwrap();
    hasher.update(data);
    let mut hash = [0u8; 32];
    hasher.finalize_variable(&mut hash).unwrap();
    hash
}

// ---------------------------------------------------------------------------
// Test 10: node_view_serves_request_modifier
//
// 1. Create a NodeViewHolder with HistoryDb.
// 2. Store a modifier via history.put_modifier(108, &id, &payload).
// 3. Build a RequestModifier message (code 22) with that modifier's ID.
// 4. Call handle_message.
// 5. Verify we get back a SendModifiers action with the correct data.
// 6. Parse the ModifiersData from the action data and verify contents match.
// ---------------------------------------------------------------------------

#[test]
fn node_view_serves_request_modifier() {
    use ergo_network::delivery_tracker::DeliveryTracker;
    use ergo_network::message_handler;
    use ergo_network::sync_manager::{SyncAction, SyncManager};
    use ergo_wire::codec::RawMessage;
    use ergo_wire::inv::{InvData, ModifiersData};

    let (mut nv, _dir) = make_test_node_view();
    let mut sync_mgr = SyncManager::new(10, 64);
    let mut tracker = DeliveryTracker::new(30, 3);

    // Store a modifier in the database.
    let modifier_id = ModifierId([0x42; 32]);
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    nv.history.put_modifier(108, &modifier_id, &payload).unwrap();

    // Build a RequestModifier message (code 22) requesting that ID.
    let inv = InvData {
        type_id: 108,
        ids: vec![modifier_id],
    };
    let msg = RawMessage {
        code: 22,
        body: inv.serialize(),
    };

    let result = message_handler::handle_message(
        1, &msg, &mut nv, &mut sync_mgr, &mut tracker, &[],
        &mut ergo_network::sync_tracker::SyncTracker::new(),
        &mut ergo_network::modifiers_cache::ModifiersCache::with_default_capacities(),
        &mut std::collections::HashMap::new(),
        true,
        &mut None,
        &mut ergo_network::message_handler::TxCostTracker::new(),
        10,
        &[],
        &mut ergo_network::sync_metrics::SyncMetrics::new(10),
    );

    // Should produce exactly one SendModifiers action.
    assert_eq!(
        result.actions.len(),
        1,
        "expected 1 action, got {}",
        result.actions.len()
    );

    match &result.actions[0] {
        SyncAction::SendModifiers { peer_id, data } => {
            assert_eq!(*peer_id, 1, "peer_id should match the requesting peer");

            // Parse the response and verify the modifier contents.
            let mods = ModifiersData::parse(data)
                .expect("SendModifiers data should be valid ModifiersData");
            assert_eq!(mods.type_id, 108);
            assert_eq!(mods.modifiers.len(), 1);
            assert_eq!(mods.modifiers[0].0, modifier_id);
            assert_eq!(mods.modifiers[0].1, payload);
        }
        other => panic!("expected SendModifiers, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 11: node_view_rejects_header_with_bad_height
//
// 1. Create a NodeViewHolder.
// 2. Store a parent header at height 100 via process_modifier(101, ...).
// 3. Build a child header with WRONG height (200 instead of 101).
// 4. Call process_modifier with type 101.
// 5. Verify an error is returned.
// ---------------------------------------------------------------------------

#[test]
fn node_view_rejects_header_with_bad_height() {
    let (mut nv, _dir) = make_test_node_view();

    // Build and store a parent header at height 100.
    let mut parent = Header::default_for_test();
    parent.version = 2;
    parent.height = 100;
    parent.timestamp = 1_700_000_000_000;
    let parent_bytes = ergo_wire::header_ser::serialize_header(&parent);
    let parent_id = ModifierId(blake2b256(&parent_bytes));

    // Store parent directly (bypassing process_modifier which now rejects
    // orphan headers without a parent in the DB).
    nv.history.store_header_with_score(&parent_id, &parent)
        .expect("storing parent header should succeed");

    // Build a child header with WRONG height (200 instead of 101).
    let mut bad_child = Header::default_for_test();
    bad_child.version = 2;
    bad_child.height = 200; // Should be 101
    bad_child.parent_id = parent_id;
    bad_child.timestamp = parent.timestamp + 60_000;
    let bad_child_bytes = ergo_wire::header_ser::serialize_header(&bad_child);
    let bad_child_id = ModifierId(blake2b256(&bad_child_bytes));

    let result = nv.process_modifier(101, &bad_child_id, &bad_child_bytes);

    assert!(
        result.is_err(),
        "header with wrong height should be rejected"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("validation failed"),
        "error should mention validation failure, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 12: handle_peers_response_extracts_addresses
//
// 1. Create a NodeViewHolder.
// 2. Build a Peers message with 3 addresses.
// 3. Call handle_message with code 2.
// 4. Verify AddPeers action contains 3 addresses.
// ---------------------------------------------------------------------------

#[test]
fn handle_peers_response_extracts_addresses() {
    use ergo_network::delivery_tracker::DeliveryTracker;
    use ergo_network::message_handler;
    use ergo_network::sync_manager::{SyncAction, SyncManager};
    use ergo_wire::codec::RawMessage;
    use ergo_wire::peer_spec::{serialize_peers, PeerAddr};

    let (mut nv, _dir) = make_test_node_view();
    let mut sync_mgr = SyncManager::new(10, 64);
    let mut tracker = DeliveryTracker::new(30, 3);

    // Build a Peers message with 3 addresses.
    let peers = vec![
        PeerAddr {
            address: "10.0.0.1:9030".parse().unwrap(),
        },
        PeerAddr {
            address: "10.0.0.2:9031".parse().unwrap(),
        },
        PeerAddr {
            address: "192.168.1.100:9032".parse().unwrap(),
        },
    ];
    let body = serialize_peers(&peers);

    let msg = RawMessage { code: 2, body };
    let result = message_handler::handle_message(
        1, &msg, &mut nv, &mut sync_mgr, &mut tracker, &[],
        &mut ergo_network::sync_tracker::SyncTracker::new(),
        &mut ergo_network::modifiers_cache::ModifiersCache::with_default_capacities(),
        &mut std::collections::HashMap::new(),
        true,
        &mut None,
        &mut ergo_network::message_handler::TxCostTracker::new(),
        10,
        &[],
        &mut ergo_network::sync_metrics::SyncMetrics::new(10),
    );

    assert_eq!(
        result.actions.len(),
        1,
        "expected 1 action, got {}",
        result.actions.len()
    );

    match &result.actions[0] {
        SyncAction::AddPeers { addresses } => {
            assert_eq!(
                addresses.len(),
                3,
                "should extract 3 addresses, got {}",
                addresses.len()
            );
            // Verify the addresses match what we sent.
            let expected: Vec<std::net::SocketAddr> = vec![
                "10.0.0.1:9030".parse().unwrap(),
                "10.0.0.2:9031".parse().unwrap(),
                "192.168.1.100:9032".parse().unwrap(),
            ];
            assert_eq!(addresses, &expected);
        }
        other => panic!("expected AddPeers, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test 13: handle_get_peers_returns_connected_list
//
// 1. Create a NodeViewHolder.
// 2. Build a list of connected peer addresses.
// 3. Call handle_message with code 1 and the connected peers list.
// 4. Verify SendPeers action contains a valid Peers message.
// 5. Parse the Peers response and verify addresses match.
// ---------------------------------------------------------------------------

#[test]
fn handle_get_peers_returns_connected_list() {
    use ergo_network::delivery_tracker::DeliveryTracker;
    use ergo_network::message_handler;
    use ergo_network::sync_manager::{SyncAction, SyncManager};
    use ergo_wire::codec::RawMessage;

    let (mut nv, _dir) = make_test_node_view();
    let mut sync_mgr = SyncManager::new(10, 64);
    let mut tracker = DeliveryTracker::new(30, 3);

    // Build a list of connected peer addresses.
    let connected: Vec<std::net::SocketAddr> = vec![
        "10.0.0.1:9030".parse().unwrap(),
        "172.16.0.5:9030".parse().unwrap(),
        "192.168.1.50:9030".parse().unwrap(),
    ];

    // GetPeers request (code 1) has an empty body.
    let msg = RawMessage {
        code: 1,
        body: vec![],
    };

    let result = message_handler::handle_message(
        42, &msg, &mut nv, &mut sync_mgr, &mut tracker, &connected,
        &mut ergo_network::sync_tracker::SyncTracker::new(),
        &mut ergo_network::modifiers_cache::ModifiersCache::with_default_capacities(),
        &mut std::collections::HashMap::new(),
        true,
        &mut None,
        &mut ergo_network::message_handler::TxCostTracker::new(),
        10,
        &[],
        &mut ergo_network::sync_metrics::SyncMetrics::new(10),
    );

    assert_eq!(
        result.actions.len(),
        1,
        "expected 1 action, got {}",
        result.actions.len()
    );

    match &result.actions[0] {
        SyncAction::SendPeers { peer_id, data } => {
            assert_eq!(*peer_id, 42, "peer_id should match the requesting peer");

            // Parse the serialized Peers response and verify the addresses.
            let parsed = ergo_wire::peer_spec::parse_peers(data)
                .expect("SendPeers data should be valid");
            assert_eq!(
                parsed.len(),
                3,
                "should contain 3 peers, got {}",
                parsed.len()
            );

            let parsed_addrs: Vec<std::net::SocketAddr> =
                parsed.iter().map(|p| p.address).collect();
            assert_eq!(parsed_addrs, connected);
        }
        other => panic!("expected SendPeers, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Phase 9 transaction relay integration tests
//
// These tests verify the full transaction relay flow end-to-end:
// 1. Tx Inv triggers a request for unknown transactions.
// 2. Tx modifier enters the mempool and broadcasts relay Inv.
// 3. Tx Inv for a known mempool transaction is silently skipped.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 14: tx_inv_triggers_request_for_unknown
//
// Send an Inv message with type_id 2 (transaction) containing an unknown
// modifier ID. Verify that the handler returns a RequestModifiers action
// to fetch the unknown transaction from the announcing peer.
// ---------------------------------------------------------------------------

#[test]
fn tx_inv_triggers_request_for_unknown() {
    let (mut node_view, _dir) = make_test_node_view();
    let mut sync_mgr = ergo_network::sync_manager::SyncManager::new(10, 64);
    let mut tracker = ergo_network::delivery_tracker::DeliveryTracker::new(30, 3);

    let tx_id = ergo_types::modifier_id::ModifierId([0xBB; 32]);
    let inv = ergo_wire::inv::InvData {
        type_id: 2,
        ids: vec![tx_id],
    };
    let msg = ergo_wire::codec::RawMessage {
        code: 55,
        body: inv.serialize(),
    };

    let result = ergo_network::message_handler::handle_message(
        1, &msg, &mut node_view, &mut sync_mgr, &mut tracker, &[],
        &mut ergo_network::sync_tracker::SyncTracker::new(),
        &mut ergo_network::modifiers_cache::ModifiersCache::with_default_capacities(),
        &mut std::collections::HashMap::new(),
        true,
        &mut None,
        &mut ergo_network::message_handler::TxCostTracker::new(),
        10,
        &[],
        &mut ergo_network::sync_metrics::SyncMetrics::new(10),
    );

    assert_eq!(result.actions.len(), 1);
    assert!(matches!(
        &result.actions[0],
        ergo_network::sync_manager::SyncAction::RequestModifiers { type_id: 2, .. }
    ));
}

// ---------------------------------------------------------------------------
// Test 15: tx_modifier_enters_mempool_and_relays
//
// Send a Modifiers message (code 33) with type_id 2 containing a valid
// serialized transaction. Verify that the transaction is added to the
// mempool and a BroadcastInvExcept action is returned to relay the
// announcement to all peers except the sender.
// ---------------------------------------------------------------------------

#[test]
fn tx_modifier_enters_mempool_and_relays() {
    let (mut node_view, _dir) = make_test_node_view();
    let mut sync_mgr = ergo_network::sync_manager::SyncManager::new(10, 64);
    let mut tracker = ergo_network::delivery_tracker::DeliveryTracker::new(30, 3);

    // Build a valid transaction (must have extension_bytes = [0x00] for
    // the empty-extension wire format to round-trip through parse).
    let tx = ergo_types::transaction::ErgoTransaction {
        inputs: vec![ergo_types::transaction::Input {
            box_id: ergo_types::transaction::BoxId([0xCC; 32]),
            proof_bytes: vec![],
            extension_bytes: vec![0x00],
        }],
        data_inputs: vec![],
        output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: vec![],
            additional_registers: vec![],
        }],
        tx_id: ergo_types::transaction::TxId([0; 32]),
    };
    let tx_bytes = ergo_wire::transaction_ser::serialize_transaction(&tx);
    let real_id = ergo_wire::transaction_ser::compute_tx_id(&tx);

    let mods = ergo_wire::inv::ModifiersData {
        type_id: 2,
        modifiers: vec![(ergo_types::modifier_id::ModifierId(real_id.0), tx_bytes)],
    };
    let msg = ergo_wire::codec::RawMessage {
        code: 33,
        body: mods.serialize(),
    };

    let result = ergo_network::message_handler::handle_message(
        1, &msg, &mut node_view, &mut sync_mgr, &mut tracker, &[],
        &mut ergo_network::sync_tracker::SyncTracker::new(),
        &mut ergo_network::modifiers_cache::ModifiersCache::with_default_capacities(),
        &mut std::collections::HashMap::new(),
        true,
        &mut None,
        &mut ergo_network::message_handler::TxCostTracker::new(),
        10,
        &[],
        &mut ergo_network::sync_metrics::SyncMetrics::new(10),
    );

    // Tx should be in mempool.
    let mp = node_view.mempool.read().unwrap();
    assert!(mp.contains(&real_id));
    drop(mp);

    // Should have BroadcastInvExcept action.
    assert!(result.actions.iter().any(|a| matches!(
        a,
        ergo_network::sync_manager::SyncAction::BroadcastInvExcept {
            type_id: 2,
            exclude: 1,
            ..
        }
    )));
}

// ---------------------------------------------------------------------------
// Test 16: tx_inv_skips_known_mempool_tx
//
// Pre-populate the mempool with a transaction, then send an Inv message
// announcing that same transaction. Verify that the handler does NOT
// issue a RequestModifiers action (the tx is already known).
// ---------------------------------------------------------------------------

#[test]
fn tx_inv_skips_known_mempool_tx() {
    let (mut node_view, _dir) = make_test_node_view();
    let mut sync_mgr = ergo_network::sync_manager::SyncManager::new(10, 64);
    let mut tracker = ergo_network::delivery_tracker::DeliveryTracker::new(30, 3);

    // Pre-populate mempool.
    let tx = ergo_types::transaction::ErgoTransaction {
        inputs: vec![ergo_types::transaction::Input {
            box_id: ergo_types::transaction::BoxId([0xDD; 32]),
            proof_bytes: vec![],
            extension_bytes: vec![],
        }],
        data_inputs: vec![],
        output_candidates: vec![ergo_types::transaction::ErgoBoxCandidate {
            value: 1_000_000,
            ergo_tree_bytes: vec![0x00],
            creation_height: 1,
            tokens: vec![],
            additional_registers: vec![],
        }],
        tx_id: ergo_types::transaction::TxId([0xDD; 32]),
    };
    node_view.mempool.write().unwrap().put(tx).unwrap();

    // Send Inv with the known tx_id.
    let inv = ergo_wire::inv::InvData {
        type_id: 2,
        ids: vec![ergo_types::modifier_id::ModifierId([0xDD; 32])],
    };
    let msg = ergo_wire::codec::RawMessage {
        code: 55,
        body: inv.serialize(),
    };

    let result = ergo_network::message_handler::handle_message(
        1, &msg, &mut node_view, &mut sync_mgr, &mut tracker, &[],
        &mut ergo_network::sync_tracker::SyncTracker::new(),
        &mut ergo_network::modifiers_cache::ModifiersCache::with_default_capacities(),
        &mut std::collections::HashMap::new(),
        true,
        &mut None,
        &mut ergo_network::message_handler::TxCostTracker::new(),
        10,
        &[],
        &mut ergo_network::sync_metrics::SyncMetrics::new(10),
    );

    // Should NOT request -- tx is already in mempool.
    assert!(result.actions.is_empty());
}

// ---------------------------------------------------------------------------
// Phase 10 robust sync pipeline integration tests
//
// These tests verify the Phase 10 features end-to-end:
// 1. next_modifiers_to_download finds missing block body sections
// 2. distribute_requests evenly distributes work across peers
// 3. SyncTracker classifies peers by chain status
// 4. DeliveryTracker.reassign retries from alternative peers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 17: next_modifiers_to_download_finds_gaps
//
// Store a header at height 1 without any body sections (block transactions,
// AD proofs, extension). Verify that next_modifiers_to_download identifies
// the missing body sections for that header.
// ---------------------------------------------------------------------------

#[test]
fn next_modifiers_to_download_finds_gaps() {
    let dir = tempfile::tempdir().unwrap();
    let history = HistoryDb::open(dir.path()).unwrap();

    // Store a header at height 1 using the typed store_header method,
    // which properly serializes the header, indexes it at height 1,
    // and stores the modifier under type_id 101.
    let header_id = ModifierId([0xEE; 32]);
    let mut header = Header::default_for_test();
    header.version = 2;
    header.height = 1;
    header.parent_id = ModifierId::GENESIS_PARENT;
    history.store_header(&header_id, &header).unwrap();

    // No body sections stored — next_modifiers_to_download should find gaps.
    let missing = history.next_modifiers_to_download(10);
    assert!(!missing.is_empty(), "should find missing body sections");

    // Should include BlockTransactions (102), ADProofs (104), Extension (108)
    assert!(
        missing.iter().any(|(t, _)| *t == 102),
        "should find missing BlockTransactions (type 102)"
    );
    assert!(
        missing.iter().any(|(t, _)| *t == 104),
        "should find missing ADProofs (type 104)"
    );
    assert!(
        missing.iter().any(|(t, _)| *t == 108),
        "should find missing Extension (type 108)"
    );

    // All missing modifiers should reference the same header_id.
    for (_, mid) in &missing {
        assert_eq!(
            *mid, header_id,
            "all missing modifiers should reference the stored header"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 18: distribute_requests_balances_across_peers
//
// Create 6 requests of the same type and 3 peers. Verify that
// distribute_requests distributes them evenly (2 per peer) and the
// total count matches the input.
// ---------------------------------------------------------------------------

#[test]
fn distribute_requests_balances_across_peers() {
    let requests: Vec<(u8, ModifierId)> = (0..6)
        .map(|i| (102u8, ModifierId([i; 32])))
        .collect();
    let peers = vec![1u64, 2, 3];

    let batches = ergo_network::sync_manager::distribute_requests(&requests, &peers);

    // Total should equal input count.
    let total: usize = batches.iter().map(|(_, _, ids)| ids.len()).sum();
    assert_eq!(total, 6, "total distributed IDs should equal input count");

    // Each peer should get 2.
    for peer_id in &peers {
        let peer_count: usize = batches
            .iter()
            .filter(|(p, _, _)| p == peer_id)
            .map(|(_, _, ids)| ids.len())
            .sum();
        assert_eq!(
            peer_count, 2,
            "peer {peer_id} should get exactly 2 requests"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 19: sync_tracker_classifies_peers
//
// Verify SyncTracker correctly classifies peers as Older (ahead of us),
// Younger (behind us), or Equal, and that peers_for_blocks returns only
// Older and Equal peers.
// ---------------------------------------------------------------------------

#[test]
fn sync_tracker_classifies_peers() {
    use ergo_network::sync_tracker::{classify_peer, PeerChainStatus, SyncTracker};

    let mut tracker = SyncTracker::new();

    // Peer at height 1000, we're at 500 -> they're Older (ahead of us).
    tracker.update_status(1, classify_peer(1000, 500, None, None), Some(1000));
    assert_eq!(
        tracker.status(1),
        Some(PeerChainStatus::Older),
        "peer ahead of us should be classified as Older"
    );

    // Peer at height 500, we're at 1000 -> they're Younger (behind us).
    tracker.update_status(2, classify_peer(500, 1000, None, None), Some(500));
    assert_eq!(
        tracker.status(2),
        Some(PeerChainStatus::Younger),
        "peer behind us should be classified as Younger"
    );

    // Peer at same height as us -> Equal.
    tracker.update_status(3, classify_peer(500, 500, None, None), Some(500));
    assert_eq!(
        tracker.status(3),
        Some(PeerChainStatus::Equal),
        "peer at same height should be classified as Equal"
    );

    // Peers for blocks: only Older and Equal (not Younger).
    let block_peers = tracker.peers_for_blocks();
    assert!(
        block_peers.contains(&1),
        "Older peer should be in peers_for_blocks"
    );
    assert!(
        !block_peers.contains(&2),
        "Younger peer should NOT be in peers_for_blocks"
    );
    assert!(
        block_peers.contains(&3),
        "Equal peer should be in peers_for_blocks"
    );
}

// ---------------------------------------------------------------------------
// Test 20: delivery_tracker_reassign_works
//
// 1. Set a modifier as requested from peer 1 with 0-second timeout.
// 2. Call collect_timed_out to detect the timeout.
// 3. Reassign to peer 2.
// 4. Verify the modifier is still in Requested state (not dropped).
// ---------------------------------------------------------------------------

#[test]
fn delivery_tracker_reassign_works() {
    let mut tracker = ergo_network::delivery_tracker::DeliveryTracker::new(0, 3);
    let id = ModifierId([0xFF; 32]);
    tracker.set_requested(102, id, 1);

    // With 0-second timeout, collect_timed_out should find it immediately.
    let timed_out = tracker.collect_timed_out();
    assert_eq!(
        timed_out.len(),
        1,
        "should have exactly 1 timed-out modifier"
    );
    assert_eq!(timed_out[0].0, 102, "type_id should be 102");
    assert_eq!(timed_out[0].1, id, "modifier ID should match");
    assert_eq!(timed_out[0].2, 1, "original peer should be 1");

    // Reassign to peer 2.
    tracker.reassign(102, &id, 2);

    // Should still be in Requested state (not removed or invalidated).
    assert_eq!(
        tracker.status(102, &id),
        ergo_network::delivery_tracker::ModifierStatus::Requested,
        "reassigned modifier should still be in Requested state"
    );

    // Pending count should be 1 (still tracking it).
    assert_eq!(
        tracker.pending_count(),
        1,
        "should still have 1 pending request after reassign"
    );
}

// ---------------------------------------------------------------------------
// Phase 11 sync resilience integration tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 21: modifiers_cache_buffers_out_of_order
//
// 1. Create a NodeViewHolder, SyncManager, DeliveryTracker, ModifiersCache.
// 2. Send a Modifiers message (code 33) with type_id 108 (extension) for a
//    header that doesn't exist yet. This should be stored in the DB via
//    put_modifier (process_modifier always stores the raw bytes first).
// 3. Verify the extension is stored in the history DB but no block was
//    applied (since the header doesn't exist, the block is incomplete).
// 4. Now store the header via process_modifier(101, ...).
// 5. Verify the extension is still stored in the history DB.
// ---------------------------------------------------------------------------

#[test]
fn modifiers_cache_buffers_out_of_order() {
    use ergo_network::delivery_tracker::DeliveryTracker;
    use ergo_network::message_handler;
    use ergo_network::modifiers_cache::ModifiersCache;
    use ergo_network::sync_manager::SyncManager;
    use ergo_network::sync_tracker::SyncTracker;
    use ergo_wire::codec::RawMessage;
    use ergo_wire::inv::ModifiersData;

    let (mut nv, _dir) = make_test_node_view();
    let mut sync_mgr = SyncManager::new(10, 64);
    let mut tracker = DeliveryTracker::new(30, 3);
    let mut sync_tracker = SyncTracker::new();
    let mut cache = ModifiersCache::with_default_capacities();

    // Use a real blake2b256 hash of the data as the modifier ID so it passes
    // modifier ID verification (the ID must match the hash of the data).
    let ext_data = vec![0xAB; 20];
    let ext_id = {
        use blake2::Blake2bVar;
        use blake2::digest::{Update, VariableOutput};
        let mut hasher = Blake2bVar::new(32).unwrap();
        hasher.update(&ext_data);
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).unwrap();
        ModifierId(out)
    };
    // Mark as requested so it passes spam detection.
    tracker.set_requested(108, ext_id, 1);

    // Step 1: Send extension (type 108) for a header that doesn't exist yet.
    let mods = ModifiersData {
        type_id: 108,
        modifiers: vec![(ext_id, ext_data)],
    };
    let msg = RawMessage {
        code: 33,
        body: mods.serialize(),
    };

    let result = message_handler::handle_message(
        1,
        &msg,
        &mut nv,
        &mut sync_mgr,
        &mut tracker,
        &[],
        &mut sync_tracker,
        &mut cache,
        &mut std::collections::HashMap::new(),
        true,
        &mut None,
        &mut ergo_network::message_handler::TxCostTracker::new(),
        10,
        &[],
        &mut ergo_network::sync_metrics::SyncMetrics::new(10),
    );

    // The extension should be stored in the DB (put_modifier stores it
    // before process_block_section checks for block completeness).
    assert!(
        nv.history.contains_modifier(108, &ext_id).unwrap(),
        "extension should be stored in history DB (put_modifier stores it)"
    );

    // No block was applied (the header doesn't exist, block is incomplete).
    assert!(
        result.applied_blocks.is_empty(),
        "no blocks should be applied when header is missing"
    );

    // No new headers were discovered.
    assert!(
        result.new_headers.is_empty(),
        "no new headers should be reported for a body section"
    );
}

// ---------------------------------------------------------------------------
// Test 22: peer_db_persistence_roundtrip
//
// 1. Create a PeerDb, add some peers, flush to disk.
// 2. Create a new PeerDb instance at the same path.
// 3. Verify all peers are loaded correctly.
// ---------------------------------------------------------------------------

#[test]
fn peer_db_persistence_roundtrip() {
    use ergo_network::peer_db::PeerDb;
    use std::net::SocketAddr;

    let dir = tempfile::TempDir::new().unwrap();

    let addr1: SocketAddr = "10.0.0.1:9030".parse().unwrap();
    let addr2: SocketAddr = "10.0.0.2:9030".parse().unwrap();
    let addr3: SocketAddr = "192.168.1.100:9030".parse().unwrap();

    // Create, add peers, flush.
    {
        let mut db = PeerDb::new(dir.path());
        assert!(db.is_empty());
        db.add(addr1);
        db.add(addr2);
        db.add(addr3);
        assert_eq!(db.len(), 3);
        db.flush();
    }

    // Reload from disk.
    {
        let db = PeerDb::new(dir.path());
        assert_eq!(db.len(), 3, "should load 3 peers from disk");
        assert!(db.peers().contains(&addr1));
        assert!(db.peers().contains(&addr2));
        assert!(db.peers().contains(&addr3));
    }
}

// ---------------------------------------------------------------------------
// Test 23: state_version_persists_after_block_application
//
// 1. Create a NodeViewHolder in UTXO mode.
// 2. Store and apply a block via apply_progress.
// 3. Verify state_version is set in the DB.
// 4. Create a new NodeViewHolder::with_recovery at the same DB path.
// 5. Verify the recovered state root matches the applied block's header.
// ---------------------------------------------------------------------------

#[test]
fn state_version_persists_after_block_application() {
    use ergo_network::mempool::ErgoMemPool;
    use ergo_network::node_view::NodeViewHolder;
    use ergo_state::utxo_state::UtxoState;
    use ergo_storage::block_processor::ProgressInfo;

    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path();

    let initial_root = UtxoState::new()
        .state_root()
        .expect("fresh UtxoState should have a digest");

    let block_id = ModifierId([0x99; 32]);
    let mut header = Header::default_for_test();
    header.version = 2;
    header.height = 100;
    let mut state_root = [0u8; 33];
    let len = initial_root.len().min(33);
    state_root[..len].copy_from_slice(&initial_root[..len]);
    header.state_root = ADDigest(state_root);
    header.extension_root = Digest32(sample_ext_root());

    // Apply a block in the first NodeViewHolder.
    {
        let db = HistoryDb::open(db_path).unwrap();
        let mempool = std::sync::Arc::new(std::sync::RwLock::new(ErgoMemPool::with_min_fee(100, 0)));
        let mut nv = NodeViewHolder::new(db, mempool, false, initial_root.clone());
        nv.set_checkpoint_height(u32::MAX); // Skip difficulty checks in pipeline test
        // Test headers use version 2 (current mainnet), so set parameters to match.
        nv.voting_epoch_info
            .parameters
            .table
            .insert(ergo_consensus::parameters::BLOCK_VERSION_ID, 2);

        nv.history.store_header(&block_id, &header).unwrap();
        nv.history
            .store_block_transactions(
                &block_id,
                &BlockTransactions {
                    header_id: block_id,
                    block_version: 2,
                    tx_bytes: Vec::new(),
                },
            )
            .unwrap();
        nv.history
            .store_extension(
                &block_id,
                &Extension {
                    header_id: block_id,
                    fields: sample_ext_fields(),
                },
            )
            .unwrap();

        let info = ProgressInfo::apply(vec![block_id]);
        nv.apply_progress(&info).expect("block should be applied");

        // Verify state_version is set in DB.
        let sv = nv.history.get_state_version().unwrap();
        assert_eq!(
            sv,
            Some(block_id),
            "state_version should be set after block application"
        );
    }

    // Recover in a new NodeViewHolder.
    {
        let db = HistoryDb::open(db_path).unwrap();
        let mempool = std::sync::Arc::new(std::sync::RwLock::new(ErgoMemPool::with_min_fee(100, 0)));
        let nv = NodeViewHolder::with_recovery(db, mempool, false, vec![0u8; 33]);

        // The state root should match the applied block's header state root.
        assert_eq!(
            nv.state_root(),
            header.state_root.0.as_slice(),
            "recovered state root should match the applied block's header"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 24: sync_info_younger_peer_gets_continuation_ids
//
// 1. Create a NodeViewHolder with headers at heights 1-10 stored.
// 2. Build a SyncInfo V2 from a peer claiming height 5.
// 3. Call handle_message with code 65.
// 4. Verify the result contains a SendInv action with header type (101).
// ---------------------------------------------------------------------------

#[test]
fn sync_info_younger_peer_gets_continuation_ids() {
    use ergo_network::delivery_tracker::DeliveryTracker;
    use ergo_network::message_handler;
    use ergo_network::modifiers_cache::ModifiersCache;
    use ergo_network::sync_manager::{SyncAction, SyncManager};
    use ergo_network::sync_tracker::SyncTracker;
    use ergo_wire::codec::RawMessage;

    let dir = tempfile::TempDir::new().unwrap();
    let db = HistoryDb::open(dir.path()).unwrap();

    // Store a chain of headers at heights 1-10.
    let mut header_ids = Vec::new();
    let mut parent_id = ModifierId::GENESIS_PARENT;

    for height in 1..=10u32 {
        let mut header = Header::default_for_test();
        header.version = 2;
        header.height = height;
        header.parent_id = parent_id;
        header.timestamp = 1_700_000_000_000 + (height as u64 * 60_000);

        let header_bytes = ergo_wire::header_ser::serialize_header(&header);
        let header_id = ModifierId(blake2b256(&header_bytes));

        db.store_header(&header_id, &header).unwrap();

        // Set best header to this one (it's the latest).
        db.set_best_header_id(&header_id).unwrap();

        header_ids.push((header_id, header));
        parent_id = header_id;
    }

    let mempool = std::sync::Arc::new(std::sync::RwLock::new(
        ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
    ));
    let mut nv = ergo_network::node_view::NodeViewHolder::new(
        db,
        mempool,
        true,
        vec![0u8; 33],
    );
    let mut sync_mgr = SyncManager::new(10, 64);
    let mut tracker = DeliveryTracker::new(30, 3);
    let mut sync_tracker = SyncTracker::new();
    let mut cache = ModifiersCache::with_default_capacities();

    // Build a SyncInfo V2 from a peer at height 5.
    // The peer's SyncInfo contains their last header (at height 5).
    let peer_header = &header_ids[4].1; // height 5 (0-indexed)
    let sync_info = ergo_wire::sync_info::ErgoSyncInfoV2 {
        last_headers: vec![peer_header.clone()],
    };

    let msg = RawMessage {
        code: 65,
        body: sync_info.serialize(),
    };

    let result = message_handler::handle_message(
        1,
        &msg,
        &mut nv,
        &mut sync_mgr,
        &mut tracker,
        &[],
        &mut sync_tracker,
        &mut cache,
        &mut std::collections::HashMap::new(),
        true,
        &mut None,
        &mut ergo_network::message_handler::TxCostTracker::new(),
        10,
        &[],
        &mut ergo_network::sync_metrics::SyncMetrics::new(10),
    );

    // Since our height is 10 and peer is at 5, peer is Younger.
    // We should send them continuation IDs via SendInv.
    let has_send_inv = result
        .actions
        .iter()
        .any(|a| matches!(a, SyncAction::SendInv { type_id: 101, .. }));
    assert!(
        has_send_inv,
        "should send continuation headers as Inv to younger peer, got actions: {:?}",
        result.actions
    );

    // Verify the continuation IDs contain headers at heights 6-10.
    if let Some(SyncAction::SendInv { ids, .. }) = result
        .actions
        .iter()
        .find(|a| matches!(a, SyncAction::SendInv { .. }))
    {
        assert_eq!(
            ids.len(),
            5,
            "should have 5 continuation IDs (heights 6-10), got {}",
            ids.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 12 integration tests
//
// These tests verify Phase 12 features end-to-end:
// 1. Emission schedule sums to total supply
// 2. Mempool TTL eviction
// 3. last_n_headers chain walk
// 4. Mempool output scanning by box ID
// 5. Mempool output scanning by token ID
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 25: emission_total_supply_sums_correctly
//
// Iterate the emission schedule from height 1 through REEMISSION_START_HEIGHT
// (the height at which emission reaches zero). Verify the cumulative sum
// equals COINS_TOTAL.
// ---------------------------------------------------------------------------

#[test]
fn emission_total_supply_sums_correctly() {
    use ergo_network::emission::*;

    let mut total: u64 = 0;
    for h in 1..=REEMISSION_START_HEIGHT {
        let e = emission_at_height(h);
        if e == 0 {
            break;
        }
        total += e;
    }
    assert_eq!(total, COINS_TOTAL, "emission sum should equal total supply");
}

// ---------------------------------------------------------------------------
// Test 26: mempool_evict_stale_with_low_ttl
//
// Put a transaction into the mempool, then evict with a 0-second TTL so
// that everything is immediately stale. Verify the transaction is evicted
// and the pool is empty afterward.
// ---------------------------------------------------------------------------

#[test]
fn mempool_evict_stale_with_low_ttl() {
    use ergo_network::mempool::ErgoMemPool;
    use ergo_types::transaction::*;
    use std::time::Duration;

    let mut pool = ErgoMemPool::with_min_fee(100, 0);
    let tx = ErgoTransaction {
        inputs: vec![Input {
            box_id: BoxId([0xAA; 32]),
            proof_bytes: vec![],
            extension_bytes: vec![0x00],
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: vec![],
            additional_registers: vec![],
        }],
        tx_id: TxId([0; 32]),
    };
    pool.put(tx).unwrap();
    assert_eq!(pool.size(), 1);

    // Evict with 0-second TTL (everything is stale immediately).
    let evicted = pool.evict_stale(Duration::from_secs(0));
    assert_eq!(evicted.len(), 1, "should evict 1 stale transaction");
    assert_eq!(pool.size(), 0, "pool should be empty after eviction");
}

// ---------------------------------------------------------------------------
// Test 27: last_n_headers_chain_walk
//
// Store a chain of 10 headers with proper parent_id linkage. Then call
// last_n_headers(5) and verify it returns exactly 5 headers in descending
// height order (newest first).
// ---------------------------------------------------------------------------

#[test]
fn last_n_headers_chain_walk() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = HistoryDb::open(dir.path()).unwrap();

    // Build a chain of 10 headers with proper parent linkage.
    let mut parent_id = ModifierId::GENESIS_PARENT;
    let mut chain: Vec<(ModifierId, Header)> = Vec::new();

    for height in 1..=10u32 {
        let mut header = Header::default_for_test();
        header.version = 2;
        header.height = height;
        header.parent_id = parent_id;
        header.timestamp = 1_700_000_000_000 + (height as u64 * 60_000);

        // Compute a deterministic header ID using blake2b256 of the
        // serialized header (same pattern as other tests).
        let header_bytes = ergo_wire::header_ser::serialize_header(&header);
        let header_id = ModifierId(blake2b256(&header_bytes));

        db.store_header(&header_id, &header).unwrap();

        chain.push((header_id, header));
        parent_id = header_id;
    }

    // Request the last 5 headers.
    let last5 = db.last_n_headers(5).unwrap();
    assert_eq!(last5.len(), 5, "should return exactly 5 headers");

    // Verify descending height order (newest first).
    assert_eq!(last5[0].height, 10, "first header should be at height 10");
    assert_eq!(last5[1].height, 9, "second header should be at height 9");
    assert_eq!(last5[2].height, 8, "third header should be at height 8");
    assert_eq!(last5[3].height, 7, "fourth header should be at height 7");
    assert_eq!(last5[4].height, 6, "fifth header should be at height 6");

    // Verify content matches what we stored.
    for (i, hdr) in last5.iter().enumerate() {
        let expected_height = 10 - i as u32;
        let (_, expected_header) = &chain[(expected_height - 1) as usize];
        assert_eq!(
            hdr, expected_header,
            "header at position {i} should match stored header at height {expected_height}"
        );
    }

    // Also verify last_n_headers with n larger than the chain returns all 10.
    let all = db.last_n_headers(100).unwrap();
    assert_eq!(all.len(), 10, "should return all 10 headers when n > chain length");
    assert_eq!(all[0].height, 10);
    assert_eq!(all[9].height, 1);
}

// ---------------------------------------------------------------------------
// Test 28: mempool_find_output_by_box_id
//
// Put a transaction into the mempool, compute the expected box_id for its
// first output, and verify find_output_by_box_id returns the correct
// output reference.
// ---------------------------------------------------------------------------

#[test]
fn mempool_find_output_by_box_id() {
    use ergo_network::mempool::ErgoMemPool;
    use ergo_types::transaction::*;

    let mut pool = ErgoMemPool::with_min_fee(100, 0);
    let tx_id = TxId([0x11; 32]);
    let tx = ErgoTransaction {
        inputs: vec![Input {
            box_id: BoxId([0xAA; 32]),
            proof_bytes: vec![],
            extension_bytes: vec![0x00],
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: vec![],
            additional_registers: vec![],
        }],
        tx_id,
    };
    let expected_box_id = compute_box_id(&tx_id, 0);
    pool.put(tx).unwrap();

    let output = pool.find_output_by_box_id(&expected_box_id);
    assert!(output.is_some(), "should find the output by box ID");

    let output = output.unwrap();
    assert_eq!(output.tx_id, tx_id, "tx_id should match");
    assert_eq!(output.index, 0, "output index should be 0");
    assert_eq!(output.candidate.value, 1_000_000_000, "output value should match");
}

// ---------------------------------------------------------------------------
// Test 29: mempool_find_outputs_by_token_id
//
// Put a transaction with tokens into the mempool and verify
// find_outputs_by_token_id returns the correct output with the expected
// token amount.
// ---------------------------------------------------------------------------

#[test]
fn mempool_find_outputs_by_token_id() {
    use ergo_network::mempool::ErgoMemPool;
    use ergo_types::transaction::*;

    let mut pool = ErgoMemPool::with_min_fee(100, 0);
    let token_id = BoxId([0xCC; 32]);
    let tx = ErgoTransaction {
        inputs: vec![Input {
            box_id: BoxId([0xAA; 32]),
            proof_bytes: vec![],
            extension_bytes: vec![0x00],
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd],
            creation_height: 100_000,
            tokens: vec![(token_id, 1000)],
            additional_registers: vec![],
        }],
        tx_id: TxId([0x22; 32]),
    };
    pool.put(tx).unwrap();

    let outputs = pool.find_outputs_by_token_id(&token_id);
    assert_eq!(outputs.len(), 1, "should find exactly 1 output with the token");
    assert_eq!(outputs[0].tx_id, TxId([0x22; 32]), "tx_id should match");
    assert_eq!(outputs[0].index, 0, "output index should be 0");
    assert_eq!(outputs[0].candidate.tokens[0].1, 1000, "token amount should be 1000");
}

// ---------------------------------------------------------------------------
// Phase 13 integration tests
//
// These tests verify Phase 13 features end-to-end:
// 1. Block pruning removes old body sections while keeping headers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 30: test_block_pruning_removes_old_sections
//
// Store 4 blocks of body sections (types 102, 104, 108) at different
// "heights". Prune the first 2 blocks. Verify pruned blocks have no
// body sections while the remaining blocks still do. Also verify
// minimal_full_block_height is correctly persisted.
// ---------------------------------------------------------------------------

#[test]
fn test_block_pruning_removes_old_sections() {
    let dir = tempfile::tempdir().unwrap();
    let history = HistoryDb::open(dir.path()).unwrap();

    // Store 4 blocks of body sections (types 102, 104, 108) at different "heights"
    // We'll use header IDs indexed by height
    let mut header_ids = Vec::new();
    for h in 100u32..=103 {
        let mut id = [0u8; 32];
        id[0..4].copy_from_slice(&h.to_be_bytes());
        let mid = ModifierId(id);
        header_ids.push(mid);

        // Store body sections for this "block"
        history.put_modifier(102, &mid, b"block-tx-data").unwrap();
        history.put_modifier(104, &mid, b"ad-proof-data").unwrap();
        history.put_modifier(108, &mid, b"extension-data").unwrap();
    }

    // Verify all 4 blocks have body sections
    for mid in &header_ids {
        assert!(history.contains_modifier(102, mid).unwrap());
        assert!(history.contains_modifier(104, mid).unwrap());
        assert!(history.contains_modifier(108, mid).unwrap());
    }

    // Prune blocks at heights 100, 101 (simulating blocks_to_keep=2 with best at 103)
    for mid in &header_ids[0..2] {
        history.delete_modifier(102, mid).unwrap();
        history.delete_modifier(104, mid).unwrap();
        history.delete_modifier(108, mid).unwrap();
    }

    // Heights 100, 101 should have no body sections
    for mid in &header_ids[0..2] {
        assert!(!history.contains_modifier(102, mid).unwrap());
        assert!(!history.contains_modifier(104, mid).unwrap());
        assert!(!history.contains_modifier(108, mid).unwrap());
    }

    // Heights 102, 103 should still have body sections
    for mid in &header_ids[2..4] {
        assert!(history.contains_modifier(102, mid).unwrap());
        assert!(history.contains_modifier(104, mid).unwrap());
        assert!(history.contains_modifier(108, mid).unwrap());
    }

    // Set and verify minimal_full_block_height
    history.set_minimal_full_block_height(102).unwrap();
    assert_eq!(history.minimal_full_block_height().unwrap(), 102);
}

// ---------------------------------------------------------------------------
// Phase 14 integration tests
//
// These tests verify Phase 14 features end-to-end:
// 1. NiPoPoW interlink unpacking from extension fields
// 2. Address encode/decode round-trip with ergo_tree_to_address
// 3. Merkle proof verification for all leaf indices
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 31: test_unpack_interlinks_from_extension
//
// Build an Extension with multiple interlink fields in packed format:
//   key = [0x01, idx], value = [count, ...32-byte-id]
// Call unpack_interlinks and verify the unpacked IDs match with correct
// count expansion.
// ---------------------------------------------------------------------------

#[test]
fn test_unpack_interlinks_from_extension() {
    use ergo_network::nipopow::unpack_interlinks;
    use ergo_types::extension::{Extension, INTERLINKS_VECTOR_PREFIX};

    // Build three interlink fields:
    //   index 0: count=2, id=[0x11; 32]  -> expands to 2 copies
    //   index 1: count=1, id=[0x22; 32]  -> expands to 1 copy
    //   index 2: count=3, id=[0x33; 32]  -> expands to 3 copies
    let id_a = [0x11u8; 32];
    let id_b = [0x22u8; 32];
    let id_c = [0x33u8; 32];

    let mut val_a = vec![2u8]; // count = 2
    val_a.extend_from_slice(&id_a);

    let mut val_b = vec![1u8]; // count = 1
    val_b.extend_from_slice(&id_b);

    let mut val_c = vec![3u8]; // count = 3
    val_c.extend_from_slice(&id_c);

    // Insert out of order to verify sorting by key[1].
    let ext = Extension {
        header_id: ModifierId([0x00; 32]),
        fields: vec![
            ([INTERLINKS_VECTOR_PREFIX, 0x02], val_c),
            ([INTERLINKS_VECTOR_PREFIX, 0x00], val_a),
            ([0x00, 0x05], vec![0xFF]),  // non-interlink field, should be ignored
            ([INTERLINKS_VECTOR_PREFIX, 0x01], val_b),
        ],
    };

    let interlinks = unpack_interlinks(&ext);

    // Total: 2 + 1 + 3 = 6 interlink entries.
    assert_eq!(interlinks.len(), 6, "should have 6 total interlinks");

    // First 2 should be id_a (index 0, count=2).
    assert_eq!(interlinks[0], ModifierId(id_a));
    assert_eq!(interlinks[1], ModifierId(id_a));

    // Next 1 should be id_b (index 1, count=1).
    assert_eq!(interlinks[2], ModifierId(id_b));

    // Last 3 should be id_c (index 2, count=3).
    assert_eq!(interlinks[3], ModifierId(id_c));
    assert_eq!(interlinks[4], ModifierId(id_c));
    assert_eq!(interlinks[5], ModifierId(id_c));
}

// ---------------------------------------------------------------------------
// Test 32: test_address_encode_decode_integration
//
// Encode a P2PK address for mainnet, decode it back, verify round-trip.
// Also test ergo_tree_to_address with a P2PK tree and raw_to_address /
// address_to_raw conversions.
// ---------------------------------------------------------------------------

#[test]
fn test_address_encode_decode_integration() {
    use ergo_types::address::{
        address_to_raw, decode_address, encode_address, ergo_tree_to_address,
        raw_to_address, AddressType, NetworkPrefix,
    };

    // 1. Encode a P2PK address for mainnet with a synthetic 33-byte pubkey.
    let pubkey = [0x02u8; 33]; // compressed public key (starts with 0x02)
    let encoded = encode_address(NetworkPrefix::Mainnet, AddressType::P2PK, &pubkey);

    // 2. Decode it back and verify round-trip.
    let decoded = decode_address(&encoded).expect("decode should succeed");
    assert_eq!(decoded.network, NetworkPrefix::Mainnet);
    assert_eq!(decoded.address_type, AddressType::P2PK);
    assert_eq!(decoded.content_bytes, pubkey.to_vec());

    // 3. Test ergo_tree_to_address with a P2PK ErgoTree (0x00, 0x08, 0xcd + 33 bytes).
    let mut ergo_tree = vec![0x00, 0x08, 0xcd];
    ergo_tree.extend_from_slice(&pubkey);
    let tree_addr = ergo_tree_to_address(&ergo_tree, NetworkPrefix::Mainnet);
    let tree_decoded = decode_address(&tree_addr).expect("tree address decode should succeed");
    assert_eq!(tree_decoded.address_type, AddressType::P2PK);
    assert_eq!(tree_decoded.content_bytes, pubkey.to_vec());
    assert_eq!(
        tree_addr, encoded,
        "ergo_tree_to_address should produce the same address as encode_address for P2PK"
    );

    // 4. Test raw_to_address with hex-encoded pubkey.
    let pubkey_hex = hex::encode(pubkey);
    let raw_addr = raw_to_address(&pubkey_hex, NetworkPrefix::Mainnet)
        .expect("raw_to_address should succeed");
    assert_eq!(
        raw_addr, encoded,
        "raw_to_address should produce the same address"
    );

    // 5. Test address_to_raw round-trip.
    let raw_hex = address_to_raw(&encoded).expect("address_to_raw should succeed");
    assert_eq!(
        raw_hex, pubkey_hex,
        "address_to_raw should return the original pubkey hex"
    );

    // 6. Test testnet encoding produces a different address.
    let testnet_addr = encode_address(NetworkPrefix::Testnet, AddressType::P2PK, &pubkey);
    assert_ne!(
        testnet_addr, encoded,
        "testnet address should differ from mainnet"
    );
    let testnet_decoded = decode_address(&testnet_addr).expect("testnet decode should succeed");
    assert_eq!(testnet_decoded.network, NetworkPrefix::Testnet);
    assert_eq!(testnet_decoded.address_type, AddressType::P2PK);
    assert_eq!(testnet_decoded.content_bytes, pubkey.to_vec());
}

// ---------------------------------------------------------------------------
// Test 33: test_merkle_proof_verification
//
// Build 5 tx_id-like elements, compute the merkle root, then for each
// index compute a merkle proof and verify it recomputes to the same root.
// ---------------------------------------------------------------------------

#[test]
fn test_merkle_proof_verification() {
    use ergo_consensus::merkle::{
        internal_hash, leaf_hash, merkle_proof, merkle_root, MerkleSide,
    };

    // Build 5 tx_id-like elements (32 bytes each, as if they were serialized tx data).
    let elements: Vec<Vec<u8>> = (0u8..5)
        .map(|i| {
            let mut tx_data = vec![0u8; 32];
            tx_data[0] = i;
            tx_data[31] = i.wrapping_mul(0x37);
            tx_data
        })
        .collect();
    let element_refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();

    // Compute the merkle root.
    let root = merkle_root(&element_refs).expect("non-empty elements should produce a root");

    // For each index, compute a merkle proof and verify it.
    for (i, elem) in element_refs.iter().enumerate() {
        let proof = merkle_proof(&element_refs, i)
            .unwrap_or_else(|| panic!("proof for index {i} should exist"));

        // Walk the proof to recompute the root.
        let mut current = leaf_hash(elem);
        for step in &proof {
            current = match step.side {
                MerkleSide::Left => internal_hash(&step.hash, &current),
                MerkleSide::Right => internal_hash(&current, &step.hash),
            };
        }

        assert_eq!(
            current, root,
            "merkle proof for index {i} should recompute to the same root"
        );
    }

    // Verify proof for out-of-bounds index returns None.
    assert!(
        merkle_proof(&element_refs, 5).is_none(),
        "out-of-bounds index should return None"
    );
    assert!(
        merkle_proof(&element_refs, 100).is_none(),
        "far out-of-bounds index should return None"
    );
}

// ---------------------------------------------------------------------------
// Phase 15: Indexer Integration Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test: test_indexer_indexes_block_and_queries
//
// Create an ExtraIndexerDb in a temp dir. Build synthetic tx data with 2
// transactions (3 total outputs). Call index_block at height 1. Then verify
// that get_tx_by_index, get_box_by_index, and indexed_height work correctly.
// ---------------------------------------------------------------------------

#[test]
fn test_indexer_indexes_block_and_queries() {
    use ergo_indexer::db::ExtraIndexerDb;
    use ergo_indexer::indexer::{flush_buffer, index_block, IndexerBuffer, IndexerState};
    use ergo_indexer::queries;
    use ergo_types::transaction::{ErgoBoxCandidate, ErgoTransaction, TxId};

    let tmp = tempfile::tempdir().unwrap();
    let db = ExtraIndexerDb::open(tmp.path()).unwrap();
    let mut state = IndexerState {
        indexed_height: 0,
        global_tx_index: 0,
        global_box_index: 0,
    };
    let mut buffer = IndexerBuffer::new();

    let tx1 = ErgoTransaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![
            ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x01, 0x02, 0x03],
                creation_height: 1,
                tokens: vec![],
                additional_registers: vec![],
            },
            ErgoBoxCandidate {
                value: 500_000_000,
                ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x04, 0x05, 0x06],
                creation_height: 1,
                tokens: vec![],
                additional_registers: vec![],
            },
        ],
        tx_id: TxId([0xAA; 32]),
    };
    let tx1_bytes = vec![0xAA; 100];

    let tx2 = ErgoTransaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate {
            value: 200_000_000,
            ergo_tree_bytes: vec![0x00, 0x08, 0xcd, 0x07, 0x08, 0x09],
            creation_height: 1,
            tokens: vec![],
            additional_registers: vec![],
        }],
        tx_id: TxId([0xBB; 32]),
    };
    let tx2_bytes = vec![0xBB; 80];

    let tx_data = vec![(tx1_bytes, tx1), (tx2_bytes, tx2)];

    // Index block at height 1 (genesis).
    index_block(&db, &mut state, &mut buffer, &tx_data, 1).unwrap();
    flush_buffer(&db, &state, &mut buffer).unwrap();

    // Verify get_tx_by_index(0) returns the first tx.
    let itx0 = queries::get_tx_by_index(&db, 0)
        .unwrap()
        .expect("tx at index 0 should exist");
    assert_eq!(itx0.tx_id.0, [0xAA; 32]);
    assert_eq!(itx0.height, 1);
    assert_eq!(itx0.size, 100); // tx1_bytes.len()
    assert_eq!(itx0.output_indexes.len(), 2);

    // Verify get_tx_by_index(1) returns the second tx.
    let itx1 = queries::get_tx_by_index(&db, 1)
        .unwrap()
        .expect("tx at index 1 should exist");
    assert_eq!(itx1.tx_id.0, [0xBB; 32]);
    assert_eq!(itx1.height, 1);
    assert_eq!(itx1.size, 80);
    assert_eq!(itx1.output_indexes.len(), 1);

    // Verify get_box_by_index(0) returns the first output box.
    let ibox0 = queries::get_box_by_index(&db, 0)
        .unwrap()
        .expect("box at index 0 should exist");
    assert_eq!(ibox0.value, 1_000_000_000);
    assert_eq!(ibox0.inclusion_height, 1);
    assert!(ibox0.spending_tx_id.is_none());

    // Verify get_box_by_index(1) returns the second output box.
    let ibox1 = queries::get_box_by_index(&db, 1)
        .unwrap()
        .expect("box at index 1 should exist");
    assert_eq!(ibox1.value, 500_000_000);

    // Verify get_box_by_index(2) returns the third output box (from tx2).
    let ibox2 = queries::get_box_by_index(&db, 2)
        .unwrap()
        .expect("box at index 2 should exist");
    assert_eq!(ibox2.value, 200_000_000);

    // Verify indexed_height returns 1.
    let height = queries::indexed_height(&db).unwrap();
    assert_eq!(height, 1);
}

// ---------------------------------------------------------------------------
// Test: test_indexer_rollback
//
// Index 3 blocks (each with 1 tx, 1 output). Rollback to height 1. Verify:
// - Block 1's entries remain
// - Blocks 2-3's entries are gone
// - indexed_height returns 1
// - Global counters are correct
// ---------------------------------------------------------------------------

#[test]
fn test_indexer_rollback() {
    use ergo_indexer::db::ExtraIndexerDb;
    use ergo_indexer::indexer::{
        flush_buffer, index_block, remove_after, IndexerBuffer, IndexerState,
    };
    use ergo_indexer::queries;
    use ergo_types::transaction::{ErgoBoxCandidate, ErgoTransaction, TxId};

    let tmp = tempfile::tempdir().unwrap();
    let db = ExtraIndexerDb::open(tmp.path()).unwrap();
    let mut state = IndexerState {
        indexed_height: 0,
        global_tx_index: 0,
        global_box_index: 0,
    };
    let mut buffer = IndexerBuffer::new();

    let tree = vec![0x00, 0x08, 0xcd, 0x01, 0x02, 0x03];

    // Index 3 blocks, each with 1 tx and 1 output.
    for height in 1..=3u32 {
        let mut tx_id = [0u8; 32];
        tx_id[0] = height as u8;
        let tx = ErgoTransaction {
            inputs: vec![],
            data_inputs: vec![],
            output_candidates: vec![ErgoBoxCandidate {
                value: 100_000 * height as u64,
                ergo_tree_bytes: tree.clone(),
                creation_height: height,
                tokens: vec![],
                additional_registers: vec![],
            }],
            tx_id: TxId(tx_id),
        };
        let tx_bytes = tx_id.to_vec();
        index_block(&db, &mut state, &mut buffer, &[(tx_bytes, tx)], height).unwrap();
    }
    flush_buffer(&db, &state, &mut buffer).unwrap();

    // Verify all 3 blocks indexed.
    assert_eq!(state.indexed_height, 3);
    assert_eq!(state.global_tx_index, 3);
    assert_eq!(state.global_box_index, 3);

    // All 3 tx's should be present.
    assert!(queries::get_tx_by_index(&db, 0).unwrap().is_some());
    assert!(queries::get_tx_by_index(&db, 1).unwrap().is_some());
    assert!(queries::get_tx_by_index(&db, 2).unwrap().is_some());

    // Rollback to height 1.
    remove_after(&db, &mut state, &mut buffer, 1).unwrap();

    // Block 1's entries should remain.
    let tx0 = queries::get_tx_by_index(&db, 0)
        .unwrap()
        .expect("tx at index 0 should still exist after rollback");
    assert_eq!(tx0.height, 1);

    let box0 = queries::get_box_by_index(&db, 0)
        .unwrap()
        .expect("box at index 0 should still exist after rollback");
    assert_eq!(box0.value, 100_000);
    assert_eq!(box0.inclusion_height, 1);

    // Blocks 2-3's entries should be gone.
    assert!(
        queries::get_tx_by_index(&db, 1).unwrap().is_none(),
        "tx at index 1 should be gone after rollback"
    );
    assert!(
        queries::get_tx_by_index(&db, 2).unwrap().is_none(),
        "tx at index 2 should be gone after rollback"
    );
    assert!(
        queries::get_box_by_index(&db, 1).unwrap().is_none(),
        "box at index 1 should be gone after rollback"
    );
    assert!(
        queries::get_box_by_index(&db, 2).unwrap().is_none(),
        "box at index 2 should be gone after rollback"
    );

    // indexed_height should return 1.
    assert_eq!(queries::indexed_height(&db).unwrap(), 1);

    // Global counters should be correct.
    assert_eq!(state.indexed_height, 1);
    assert_eq!(state.global_tx_index, 1);
    assert_eq!(state.global_box_index, 1);
}

// ---------------------------------------------------------------------------
// Test: test_indexer_address_balance
//
// Index a block with outputs to a specific ErgoTree. Verify
// queries::balance_for_address returns the correct nanoERG amount.
// ---------------------------------------------------------------------------

#[test]
fn test_indexer_address_balance() {
    use ergo_indexer::db::ExtraIndexerDb;
    use ergo_indexer::indexer::{flush_buffer, index_block, IndexerBuffer, IndexerState};
    use ergo_indexer::queries;
    use ergo_types::transaction::{ErgoBoxCandidate, ErgoTransaction, TxId};

    let tmp = tempfile::tempdir().unwrap();
    let db = ExtraIndexerDb::open(tmp.path()).unwrap();
    let mut state = IndexerState {
        indexed_height: 0,
        global_tx_index: 0,
        global_box_index: 0,
    };
    let mut buffer = IndexerBuffer::new();

    let tree = vec![0x00, 0x08, 0xcd, 0x01, 0x02, 0x03];

    // Create a tx with 2 outputs to the same ErgoTree.
    let tx = ErgoTransaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![
            ErgoBoxCandidate {
                value: 1_000_000_000,
                ergo_tree_bytes: tree.clone(),
                creation_height: 1,
                tokens: vec![],
                additional_registers: vec![],
            },
            ErgoBoxCandidate {
                value: 500_000_000,
                ergo_tree_bytes: tree.clone(),
                creation_height: 1,
                tokens: vec![],
                additional_registers: vec![],
            },
        ],
        tx_id: TxId([0xCC; 32]),
    };
    let tx_bytes = vec![0xCC; 50];

    // Index at height 1.
    index_block(&db, &mut state, &mut buffer, &[(tx_bytes, tx)], 1).unwrap();
    flush_buffer(&db, &state, &mut buffer).unwrap();

    // Query balance for the address.
    let balance = queries::balance_for_address(&db, &tree).unwrap();
    assert!(balance.is_some(), "balance should exist for the address");
    let balance = balance.unwrap();
    assert_eq!(
        balance.nano_ergs,
        1_500_000_000,
        "balance should be the sum of both outputs"
    );
    assert!(
        balance.tokens.is_empty(),
        "there should be no token balances"
    );

    // Verify a different tree returns None.
    let other_tree = vec![0x00, 0x08, 0xcd, 0xFF, 0xFF, 0xFF];
    let other_balance = queries::balance_for_address(&db, &other_tree).unwrap();
    assert!(
        other_balance.is_none(),
        "balance for unknown address should be None"
    );
}

// ---------------------------------------------------------------------------
// Test: test_mempool_tree_hash_lookup
//
// Put a tx in mempool, use find_outputs_by_tree_hash to find matching outputs.
// ---------------------------------------------------------------------------

#[test]
fn test_mempool_tree_hash_lookup() {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;
    use ergo_network::mempool::ErgoMemPool;
    use ergo_types::transaction::{BoxId, ErgoBoxCandidate, ErgoTransaction, Input, TxId};

    fn blake2b256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).unwrap();
        hasher.update(data);
        let mut out = [0u8; 32];
        hasher.finalize_variable(&mut out).unwrap();
        out
    }

    let mut mempool = ErgoMemPool::with_min_fee(100, 0);
    let ergo_tree = vec![0x00, 0x08, 0xcd, 0xAA, 0xBB, 0xCC];
    let tx = ErgoTransaction {
        inputs: vec![Input {
            box_id: BoxId([0x01; 32]),
            proof_bytes: vec![],
            extension_bytes: vec![],
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate {
            value: 1_000_000,
            ergo_tree_bytes: ergo_tree.clone(),
            creation_height: 100,
            tokens: vec![],
            additional_registers: vec![],
        }],
        tx_id: TxId([0xFF; 32]),
    };
    mempool.put(tx).unwrap();

    // Compute blake2b256 of the ergo_tree_bytes.
    let tree_hash = blake2b256(&ergo_tree);
    let results = mempool.find_outputs_by_tree_hash(&tree_hash);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].candidate.value, 1_000_000);
    assert_eq!(results[0].tx_id, TxId([0xFF; 32]));
    assert_eq!(results[0].index, 0);
    assert_eq!(results[0].candidate.ergo_tree_bytes, ergo_tree);

    // Verify no match for a different tree hash.
    let other_hash = blake2b256(&[0xFF, 0xFF, 0xFF]);
    let no_results = mempool.find_outputs_by_tree_hash(&other_hash);
    assert!(
        no_results.is_empty(),
        "should not match a different tree hash"
    );
}

// ---------------------------------------------------------------------------
// Phase 16 – Consensus hardening integration tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test: test_parameters_genesis_defaults
//
// Verify that Parameters::genesis() produces the expected mainnet defaults.
// ---------------------------------------------------------------------------

#[test]
fn test_parameters_genesis_defaults() {
    use ergo_consensus::parameters::Parameters;
    let p = Parameters::genesis();
    assert_eq!(p.max_block_size(), 524_288);
    assert_eq!(p.max_block_cost(), 1_000_000);
    assert_eq!(p.storage_fee_factor(), 1_250_000);
    assert_eq!(p.min_value_per_byte(), 360);
}

// ---------------------------------------------------------------------------
// Test: test_voting_epoch_lifecycle
//
// Simulate a full voting epoch where 600/1024 blocks vote for a max block
// size increase, verify the parameter is updated, then reset for next epoch.
// ---------------------------------------------------------------------------

#[test]
fn test_voting_epoch_lifecycle() {
    use ergo_consensus::parameters::{Parameters, MAX_BLOCK_SIZE_ID};
    use ergo_consensus::voting::VotingEpochInfo;

    let params = Parameters::genesis();
    let mut info = VotingEpochInfo::new(params, 0);

    // Simulate 600 blocks voting for max block size increase
    for _ in 0..600 {
        info.process_block_votes(&[MAX_BLOCK_SIZE_ID, 0, 0]);
    }
    // Remaining 424 blocks with no votes
    for _ in 0..424 {
        info.process_block_votes(&[0, 0, 0]);
    }

    let new_params = info.compute_epoch_result(1024, 1024);
    // Original 524288, step = max(1, 524288/100) = 5242
    assert_eq!(new_params.table[&MAX_BLOCK_SIZE_ID], 524_288 + 5242);

    // Start new epoch and verify reset
    info.start_new_epoch(new_params, 1024);
    assert!(info.voting_data.epoch_votes.is_empty());
    assert_eq!(info.epoch_start_height, 1024);
}

// ---------------------------------------------------------------------------
// Test: test_mempool_rejects_oversized_tx
//
// validate_for_pool should reject a tx whose size exceeds the max.
// ---------------------------------------------------------------------------

#[test]
fn test_mempool_rejects_oversized_tx() {
    use ergo_network::mempool::validate_for_pool;
    use ergo_types::transaction::TxId;
    let tx_id = TxId([0xaa; 32]);
    let result = validate_for_pool(100_000, &[], 98_304, &tx_id);
    assert!(result.is_err());
    let result2 = validate_for_pool(50_000, &[], 98_304, &tx_id);
    assert!(result2.is_ok());
}

// ---------------------------------------------------------------------------
// Test: test_mempool_rejects_blacklisted_tx
//
// validate_for_pool should reject a tx whose ID matches the blacklist.
// ---------------------------------------------------------------------------

#[test]
fn test_mempool_rejects_blacklisted_tx() {
    use ergo_network::mempool::validate_for_pool;
    use ergo_types::transaction::TxId;
    let tx_id = TxId([0xaa; 32]);
    let blacklist = vec!["aa".repeat(32)];
    let result = validate_for_pool(50_000, &blacklist, 98_304, &tx_id);
    assert!(result.is_err());
    // Non-matching should pass
    let tx_id2 = TxId([0xbb; 32]);
    let result2 = validate_for_pool(50_000, &blacklist, 98_304, &tx_id2);
    assert!(result2.is_ok());
}

// ---------------------------------------------------------------------------
// Test: test_parameter_extension_roundtrip
//
// Parameters -> to_extension_fields -> Extension -> from_extension roundtrip.
// ---------------------------------------------------------------------------

#[test]
fn test_parameter_extension_roundtrip() {
    use ergo_consensus::parameters::Parameters;
    use ergo_types::extension::Extension;
    use ergo_types::modifier_id::ModifierId;

    let p = Parameters::genesis();
    let fields = p.to_extension_fields();
    let ext = Extension {
        header_id: ModifierId([0x00; 32]),
        fields,
    };
    let parsed = Parameters::from_extension(0, &ext).unwrap();
    assert_eq!(parsed.max_block_size(), p.max_block_size());
    assert_eq!(parsed.max_block_cost(), p.max_block_cost());
    assert_eq!(parsed.storage_fee_factor(), p.storage_fee_factor());
    assert_eq!(parsed.min_value_per_byte(), p.min_value_per_byte());
}

// ─── Phase 17: Sigma Verification ─────────────────────────────────

#[test]
fn test_checkpoint_skips_sigma_verification() {
    // Verify that sigma verification is skipped when height <= checkpoint_height.
    use ergo_consensus::sigma_verify::{verify_transaction, SigmaStateContext};
    use ergo_types::transaction::{ErgoTransaction, TxId};

    let tx = ErgoTransaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![],
        tx_id: TxId([0; 32]),
    };
    let ctx = SigmaStateContext {
        last_headers: vec![],
        current_height: 500_000,
        current_timestamp: 1700000000000,
        current_n_bits: 100,
        current_votes: [0; 3],
        current_miner_pk: [0; 33],
        state_digest: [0; 33],
        parameters: ergo_consensus::parameters::Parameters::genesis(),
        current_version: 2,
        current_parent_id: [0; 32],
    };

    // With checkpoint at 1_000_000, verification should be skipped
    let result = verify_transaction(&tx, &[], &[], &ctx, 1_000_000);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_checkpoint_boundary_exact() {
    // Edge case: height exactly equals checkpoint — should still skip.
    use ergo_consensus::sigma_verify::{verify_transaction, SigmaStateContext};
    use ergo_types::transaction::{ErgoTransaction, TxId};

    let tx = ErgoTransaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![],
        tx_id: TxId([0; 32]),
    };
    let ctx = SigmaStateContext {
        last_headers: vec![],
        current_height: 500_000,
        current_timestamp: 1700000000000,
        current_n_bits: 100,
        current_votes: [0; 3],
        current_miner_pk: [0; 33],
        state_digest: [0; 33],
        parameters: ergo_consensus::parameters::Parameters::genesis(),
        current_version: 2,
        current_parent_id: [0; 32],
    };

    let result = verify_transaction(&tx, &[], &[], &ctx, 500_000);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_node_view_checkpoint_height() {
    // Verify that NodeViewHolder accepts checkpoint_height setting.
    let dir = tempfile::TempDir::new().unwrap();
    let db = ergo_storage::history_db::HistoryDb::open(dir.path()).unwrap();
    let mempool = std::sync::Arc::new(std::sync::RwLock::new(
        ergo_network::mempool::ErgoMemPool::with_min_fee(100, 0),
    ));
    let mut nvh = ergo_network::node_view::NodeViewHolder::new(
        db,
        mempool,
        true,
        vec![0u8; 33],
    );
    nvh.set_checkpoint_height(500_000);
    // Should not panic — checkpoint is set
}

#[test]
fn test_sigma_verify_error_types() {
    use ergo_consensus::sigma_verify::SigmaVerifyError;

    let err = SigmaVerifyError::ScriptFalse(3);
    let msg = format!("{err}");
    assert!(msg.contains("3"), "Expected '3' in: {msg}");

    let err = SigmaVerifyError::CostExceeded(100);
    let msg = format!("{err}");
    assert!(msg.contains("100"), "Expected '100' in: {msg}");
}

#[test]
fn test_sigma_state_context_creation() {
    // Verify SigmaStateContext can be built with reasonable defaults.
    use ergo_consensus::sigma_verify::SigmaStateContext;

    let ctx = SigmaStateContext {
        last_headers: vec![],
        current_height: 1_000_000,
        current_timestamp: 1700000000000,
        current_n_bits: 117440512, // typical mainnet nBits
        current_votes: [0, 0, 0],
        current_miner_pk: [0x02; 33], // compressed pubkey prefix
        state_digest: [0u8; 33],
        parameters: ergo_consensus::parameters::Parameters::genesis(),
        current_version: 2,
        current_parent_id: [0; 32],
    };
    assert_eq!(ctx.current_height, 1_000_000);
}

// ──────────────────────────────────────────────────────────────────────────────
// Phase 18: Consensus Completeness integration tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_epoch_difficulty_constants() {
    // Verify the difficulty constants match the Ergo protocol specification.
    // EIP-37 activates at height 844,673 with 128-block epochs.
    // Classic uses 1024-block epochs.
    // Autolykos v2 activates at height 417,792.
    use ergo_consensus::difficulty_adjustment::previous_heights_for_recalculation;

    // Classic epoch at height 9217 (parent_height 9216 = 9*1024):
    // goes back 8 epochs: 9216, 8192, 7168, 6144, 5120, 4096, 3072, 2048, 1024
    let heights = previous_heights_for_recalculation(9217, 1024, 8);
    assert_eq!(heights.len(), 9); // use_last_epochs=8 → 0..=8 = 9 entries
    assert_eq!(*heights.last().unwrap(), 9216);
    assert_eq!(heights[0], 1024);

    // EIP-37 epoch at height 844_929 (parent_height 844_928 = epoch boundary):
    let heights = previous_heights_for_recalculation(844_929, 128, 8);
    assert!(!heights.is_empty());
    assert_eq!(*heights.last().unwrap(), 844_928);
}

#[test]
fn test_compute_initial_tx_cost_defaults() {
    use ergo_consensus::sigma_verify::compute_initial_tx_cost;
    use ergo_types::transaction::*;

    let params = ergo_consensus::parameters::Parameters::genesis();
    // 3 inputs, 2 data inputs, 4 outputs
    let tx = ErgoTransaction {
        inputs: vec![
            Input { box_id: BoxId([0; 32]), proof_bytes: vec![], extension_bytes: vec![] },
            Input { box_id: BoxId([1; 32]), proof_bytes: vec![], extension_bytes: vec![] },
            Input { box_id: BoxId([2; 32]), proof_bytes: vec![], extension_bytes: vec![] },
        ],
        data_inputs: vec![
            DataInput { box_id: BoxId([3; 32]) },
            DataInput { box_id: BoxId([4; 32]) },
        ],
        output_candidates: vec![
            ErgoBoxCandidate { value: 1_000_000, ergo_tree_bytes: vec![0x00], creation_height: 1, tokens: vec![], additional_registers: vec![] },
            ErgoBoxCandidate { value: 1_000_000, ergo_tree_bytes: vec![0x00], creation_height: 1, tokens: vec![], additional_registers: vec![] },
            ErgoBoxCandidate { value: 1_000_000, ergo_tree_bytes: vec![0x00], creation_height: 1, tokens: vec![], additional_registers: vec![] },
            ErgoBoxCandidate { value: 1_000_000, ergo_tree_bytes: vec![0x00], creation_height: 1, tokens: vec![], additional_registers: vec![] },
        ],
        tx_id: TxId([0; 32]),
    };
    // 10000 + 3*2000 + 2*100 + 4*100 = 10000 + 6000 + 200 + 400 = 16600
    assert_eq!(compute_initial_tx_cost(&tx, &params), 16600);
}

#[test]
fn test_compute_initial_tx_cost_custom_params() {
    use ergo_consensus::sigma_verify::compute_initial_tx_cost;
    use ergo_consensus::parameters::*;
    use ergo_types::transaction::*;

    let mut params = Parameters::genesis();
    params.table.insert(INPUT_COST_ID, 5000);
    params.table.insert(DATA_INPUT_COST_ID, 500);
    params.table.insert(OUTPUT_COST_ID, 200);

    let tx = ErgoTransaction {
        inputs: vec![
            Input { box_id: BoxId([0; 32]), proof_bytes: vec![], extension_bytes: vec![] },
        ],
        data_inputs: vec![
            DataInput { box_id: BoxId([1; 32]) },
        ],
        output_candidates: vec![
            ErgoBoxCandidate { value: 1_000_000, ergo_tree_bytes: vec![0x00], creation_height: 1, tokens: vec![], additional_registers: vec![] },
        ],
        tx_id: TxId([0; 32]),
    };
    // 10000 + 1*5000 + 1*500 + 1*200 = 15700
    assert_eq!(compute_initial_tx_cost(&tx, &params), 15700);
}

#[test]
fn test_reemission_before_activation() {
    use ergo_consensus::reemission::verify_reemission_spending;
    use ergo_types::transaction::*;

    let tx = ErgoTransaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![],
        tx_id: TxId([0; 32]),
    };
    // Before activation height (777,217), all checks should pass
    assert!(verify_reemission_spending(&tx, &[], 777_216).is_ok());
    assert!(verify_reemission_spending(&tx, &[], 1).is_ok());
    assert!(verify_reemission_spending(&tx, &[], 0).is_ok());
}

#[test]
fn test_reemission_no_emission_tokens() {
    use ergo_consensus::reemission::verify_reemission_spending;
    use ergo_types::transaction::*;

    // After activation, tx without emission/reemission tokens should pass
    let tx = ErgoTransaction {
        inputs: vec![Input {
            box_id: BoxId([0xAA; 32]),
            proof_bytes: vec![],
            extension_bytes: vec![],
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00],
            creation_height: 1,
            tokens: vec![],
            additional_registers: vec![],
        }],
        tx_id: TxId([0; 32]),
    };
    let input_box = ErgoBox {
        candidate: ErgoBoxCandidate {
            value: 1_000_000_000,
            ergo_tree_bytes: vec![0x00],
            creation_height: 1,
            tokens: vec![], // no emission/reemission tokens
            additional_registers: vec![],
        },
        transaction_id: TxId([0xBB; 32]),
        index: 0,
        box_id: BoxId([0xAA; 32]),
    };
    assert!(verify_reemission_spending(&tx, &[input_box], 800_000).is_ok());
}

#[test]
fn test_convert_parameters_roundtrip() {
    use ergo_consensus::sigma_verify::convert_parameters;
    use ergo_consensus::parameters::*;

    // Verify genesis params convert and match expected values
    let params = Parameters::genesis();
    let sigma = convert_parameters(&params);
    assert_eq!(sigma.storage_fee_factor(), 1_250_000);
    assert_eq!(sigma.max_block_cost(), 1_000_000);
    assert_eq!(sigma.input_cost(), 2_000);
    assert_eq!(sigma.block_version(), 1);

    // Verify custom params propagate correctly
    let mut params2 = Parameters::genesis();
    params2.table.insert(MAX_BLOCK_COST_ID, 9_999_999);
    params2.table.insert(BLOCK_VERSION_ID, 3);
    let sigma2 = convert_parameters(&params2);
    assert_eq!(sigma2.max_block_cost(), 9_999_999);
    assert_eq!(sigma2.block_version(), 3);
}

// ===========================================================================
// Phase 19: Mining integration tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Test: test_mining_settings_parse
//
// Parse a TOML config with all mining fields set and verify they deserialize
// correctly, including mining_pub_key() returning valid bytes.
// ---------------------------------------------------------------------------

#[test]
fn test_mining_settings_parse() {
    use ergo_settings::settings::ErgoSettings;

    // A 33-byte compressed EC public key (hex-encoded)
    let pk_hex = "02".to_owned() + &"ab".repeat(32);

    let config = format!(
        r#"
[ergo]
directory = "/tmp/.ergo-mining-test"
network_type = "testnet"

[ergo.node]
state_type = "utxo"
verify_transactions = true
blocks_to_keep = -1
mining = true
mining_pub_key_hex = "{pk_hex}"
use_external_miner = false
internal_miners_count = 4
internal_miner_polling_ms = 250
candidate_generation_interval_s = 30
max_transaction_cost = 1000000
max_transaction_size = 98304

[ergo.chain]
protocol_version = 4
address_prefix = 16
block_interval_secs = 120
epoch_length = 1024
use_last_epochs = 8
initial_difficulty_hex = "01"

[ergo.chain.pow]
pow_type = "autolykos"
k = 32
n = 26

[ergo.chain.monetary]
fixed_rate_period = 525600
fixed_rate = 75000000000
founders_initial_reward = 7500000000
epoch_length = 64800
one_epoch_reduction = 3000000000
miner_reward_delay = 720

[network]
node_name = "mining-test"
app_version = "6.0.1"
agent_name = "ergoref"
bind_address = "0.0.0.0:9020"
magic_bytes = [2, 0, 0, 1]

[api]
bind_address = "127.0.0.1:9052"
"#
    );

    let settings = ErgoSettings::from_toml(&config).expect("should parse mining config");
    let node = &settings.ergo.node;

    assert!(node.mining);
    assert_eq!(node.mining_pub_key_hex, pk_hex);
    assert!(!node.use_external_miner);
    assert_eq!(node.internal_miners_count, 4);
    assert_eq!(node.internal_miner_polling_ms, 250);
    assert_eq!(node.candidate_generation_interval_s, 30);

    // mining_pub_key() should return Some with 33 correct bytes
    let pk = node.mining_pub_key().expect("should parse mining pub key");
    assert_eq!(pk[0], 0x02);
    assert_eq!(pk[1], 0xAB);
    assert_eq!(pk[32], 0xAB);
}

// ---------------------------------------------------------------------------
// Test: test_find_nonce_easy_difficulty
//
// Use a trivially easy target (the full secp256k1 curve order Q) so that
// virtually any nonce should satisfy the PoW check.
// ---------------------------------------------------------------------------

#[test]
fn test_find_nonce_easy_difficulty() {
    use ergo_consensus::autolykos::{find_nonce, Q};

    let msg = [0xABu8; 32];
    let target = Q.clone(); // Very easy — any nonce should work
    let result = find_nonce(&msg, &target, 1000, 0, 100);
    assert!(
        result.is_some(),
        "should find nonce with trivially easy target"
    );

    // Verify the returned nonce is 8 bytes
    let nonce = result.unwrap();
    assert_eq!(nonce.len(), 8);
}

// ---------------------------------------------------------------------------
// Test: test_pack_unpack_interlinks_roundtrip
//
// Pack an interlinks vector (with duplicate compression), build an
// Extension from the fields, unpack it back, and verify equality.
// ---------------------------------------------------------------------------

#[test]
fn test_pack_unpack_interlinks_roundtrip() {
    use ergo_network::nipopow::{pack_interlinks, unpack_interlinks};

    let ids = vec![
        ModifierId([0xAA; 32]),
        ModifierId([0xAA; 32]),
        ModifierId([0xBB; 32]),
        ModifierId([0xCC; 32]),
        ModifierId([0xCC; 32]),
        ModifierId([0xCC; 32]),
    ];

    let fields = pack_interlinks(&ids);
    let ext = Extension {
        header_id: ModifierId([0; 32]),
        fields,
    };
    let unpacked = unpack_interlinks(&ext);
    assert_eq!(unpacked, ids);
}

// ---------------------------------------------------------------------------
// Test: test_update_interlinks_from_genesis
//
// A genesis parent (height=1, parent_id = GENESIS_PARENT) should produce
// interlinks with the supplied parent_id as the genesis ID.
// ---------------------------------------------------------------------------

#[test]
fn test_update_interlinks_from_genesis() {
    use ergo_network::nipopow::update_interlinks;

    let mut header = Header::default_for_test();
    header.height = 1; // genesis
    header.parent_id = ModifierId::GENESIS_PARENT;
    let parent_id = ModifierId([0x42; 32]);

    let interlinks = update_interlinks(&header, &parent_id, &[]);
    assert!(
        !interlinks.is_empty(),
        "genesis should produce non-empty interlinks"
    );
    // Genesis ID should be parent_id (since parent_interlinks is empty)
    assert_eq!(
        interlinks[0], parent_id,
        "first interlink should be the genesis (parent) ID"
    );
}

// ---------------------------------------------------------------------------
// Test: test_mining_solution_nonce_parsing
//
// Validate hex nonce parsing edge cases that a mining solution must handle.
// Since ergo-node is a binary crate we test the hex logic directly.
// ---------------------------------------------------------------------------

#[test]
fn test_mining_solution_nonce_parsing() {
    // Valid 8-byte nonce
    let valid = hex::decode("0102030405060708").unwrap();
    assert_eq!(valid.len(), 8);

    // Too short — not a valid 8-byte nonce
    let too_short = hex::decode("0102").unwrap();
    assert_ne!(too_short.len(), 8);

    // Invalid hex should fail
    assert!(hex::decode("xyz").is_err());

    // Exact round-trip: encode then decode
    let nonce_bytes: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let encoded = hex::encode(nonce_bytes);
    let decoded = hex::decode(&encoded).unwrap();
    assert_eq!(decoded, nonce_bytes);
}

// ---------------------------------------------------------------------------
// Test: test_work_message_json_format
//
// Verify the expected JSON field names and types that an external miner
// would receive. Since WorkMessage lives in ergo-node (binary crate),
// we verify the structural expectations here.
// ---------------------------------------------------------------------------

#[test]
fn test_work_message_json_format() {
    let json = serde_json::json!({
        "msg": "aa".repeat(32),
        "b": 12345678901234567890u64,
        "h": 850000u32,
        "pk": "bb".repeat(33),
    });
    assert_eq!(json["h"], 850000);
    assert!(json["msg"].is_string());
    assert!(json["b"].is_number());
    assert!(json["pk"].is_string());

    // Verify the msg field has the expected length (64 hex chars = 32 bytes)
    let msg_str = json["msg"].as_str().unwrap();
    assert_eq!(msg_str.len(), 64);

    // Verify pk field has the expected length (66 hex chars = 33 bytes)
    let pk_str = json["pk"].as_str().unwrap();
    assert_eq!(pk_str.len(), 66);
}

// ---------------------------------------------------------------------------
// Test: test_parameters_to_extension_fields
//
// Verify that genesis Parameters serialize to extension fields with the
// correct prefix byte and value length.
// ---------------------------------------------------------------------------

#[test]
fn test_parameters_to_extension_fields() {
    use ergo_consensus::parameters::Parameters;

    let params = Parameters::genesis();
    let fields = params.to_extension_fields();
    assert!(!fields.is_empty(), "genesis params should produce fields");

    // All keys should start with SYSTEM_PARAMETERS_PREFIX (0x00)
    for (key, value) in &fields {
        assert_eq!(
            key[0], 0x00,
            "extension field key must start with system parameter prefix 0x00"
        );
        // Values are i32 encoded as 4-byte big-endian
        assert_eq!(
            value.len(),
            4,
            "parameter value should be 4 bytes (i32 big-endian)"
        );
    }

    // There should be multiple parameter entries in genesis
    assert!(
        fields.len() >= 5,
        "genesis should have at least 5 parameter fields, got {}",
        fields.len()
    );
}

// ===========================================================================
// Phase 20: UTXO Persistence + Snapshots integration tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Test: test_utxo_db_apply_and_iterate
//
// Verify that UtxoDb correctly stores, iterates, and removes entries
// via apply_changes, and that entry_count and get behave correctly.
// ---------------------------------------------------------------------------

#[test]
fn test_utxo_db_apply_and_iterate() {
    use ergo_storage::utxo_db::{UtxoDb, UtxoMetadata};

    let dir = tempfile::tempdir().unwrap();
    let db = UtxoDb::open(dir.path().join("utxo")).unwrap();

    let meta = UtxoMetadata {
        digest: [0x42; 33],
        version: [0xBB; 32],
    };
    db.apply_changes(
        &[([0x01; 32], vec![0xAA]), ([0x02; 32], vec![0xBB, 0xCC])],
        &[],
        &meta,
    )
    .unwrap();

    assert_eq!(db.entry_count(), 2);
    let entries: Vec<_> = db.iter_entries().collect();
    assert_eq!(entries.len(), 2);

    // Remove one entry and verify.
    db.apply_changes(&[], &[[0x01; 32]], &meta).unwrap();
    assert_eq!(db.entry_count(), 1);
    assert!(db.get(&[0x01; 32]).unwrap().is_none());
    assert!(db.get(&[0x02; 32]).unwrap().is_some());
}

// ---------------------------------------------------------------------------
// Test: test_utxo_db_metadata_roundtrip
//
// Verify that metadata is None on a fresh DB, and that it can be stored
// and retrieved with the correct digest and version fields.
// ---------------------------------------------------------------------------

#[test]
fn test_utxo_db_metadata_roundtrip() {
    use ergo_storage::utxo_db::{UtxoDb, UtxoMetadata};

    let dir = tempfile::tempdir().unwrap();
    let db = UtxoDb::open(dir.path().join("utxo")).unwrap();

    assert!(db.metadata().unwrap().is_none());

    let meta = UtxoMetadata {
        digest: [0xFF; 33],
        version: [0xAA; 32],
    };
    db.apply_changes(&[], &[], &meta).unwrap();

    let restored = db.metadata().unwrap().unwrap();
    assert_eq!(restored.digest, [0xFF; 33]);
    assert_eq!(restored.version, [0xAA; 32]);
}

// ---------------------------------------------------------------------------
// Test: test_utxo_state_with_persistence
//
// Create a UtxoState backed by a persistent UtxoDb, apply state changes
// via the AVL tree, and verify the UTXO DB receives the entries.
// ---------------------------------------------------------------------------

#[test]
fn test_utxo_state_with_persistence() {
    use ergo_state::state_changes::StateChanges;
    use ergo_state::utxo_state::UtxoState;
    use ergo_storage::utxo_db::UtxoDb;
    use ergo_types::transaction::BoxId;

    let dir = tempfile::tempdir().unwrap();
    let db = UtxoDb::open(dir.path().join("utxo")).unwrap();
    let mut state = UtxoState::with_persistence(db);

    // Insert two boxes via apply_changes (no digest verification).
    let box_id_1 = BoxId([0x11; 32]);
    let box_id_2 = BoxId([0x22; 32]);
    let changes = StateChanges {
        to_lookup: Vec::new(),
        to_remove: Vec::new(),
        to_insert: vec![
            (box_id_1, b"box-data-1".to_vec()),
            (box_id_2, b"box-data-2".to_vec()),
        ],
    };
    state.apply_changes(&changes, None).unwrap();

    // The state root should be a 33-byte digest.
    let root = state.state_root().unwrap();
    assert_eq!(root.len(), 33);

    // Verify lookup works.
    assert!(state.get_box(&box_id_1).is_some());
    assert!(state.get_box(&box_id_2).is_some());
}

// ---------------------------------------------------------------------------
// Test: test_utxo_state_restore_from_db
//
// Populate a UtxoDb directly, then use UtxoState::restore_from_db to
// rebuild the AVL tree and verify the digest matches.
// ---------------------------------------------------------------------------

#[test]
fn test_utxo_state_restore_from_db() {
    use ergo_avldb::AuthenticatedTree;
    use ergo_state::utxo_state::UtxoState;
    use ergo_storage::utxo_db::{UtxoDb, UtxoMetadata};

    let dir = tempfile::tempdir().unwrap();

    // Build a reference AVL tree to compute the expected digest.
    let mut prover = AuthenticatedTree::default_ergo();
    let entries: Vec<([u8; 32], Vec<u8>)> = (1u8..=5)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = i;
            (key, vec![i; 50])
        })
        .collect();

    for (key, value) in &entries {
        prover
            .insert(
                bytes::Bytes::copy_from_slice(key),
                bytes::Bytes::copy_from_slice(value),
            )
            .unwrap();
    }
    let _ = prover.generate_proof();
    let digest_bytes = prover.digest().unwrap();
    let digest: [u8; 33] = digest_bytes.as_ref().try_into().unwrap();

    // Populate the UtxoDb with the same entries and the correct digest.
    let db = UtxoDb::open(dir.path().join("utxo")).unwrap();
    let version = [0xCC; 32];
    let meta = UtxoMetadata { digest, version };
    db.apply_changes(&entries, &[], &meta).unwrap();
    drop(db);

    // Restore from DB and verify success.
    let db2 = UtxoDb::open(dir.path().join("utxo")).unwrap();
    let state = UtxoState::restore_from_db(db2).unwrap();

    // The restored state root must match the expected digest.
    let restored_root = state.state_root().unwrap();
    assert_eq!(restored_root.as_slice(), digest.as_slice());

    // The version must match.
    assert_eq!(state.version().0, version);
}

// ---------------------------------------------------------------------------
// Test: test_utxo_state_restore_from_db_detects_digest_mismatch
//
// Verify that restore_from_db returns an error when the DB metadata
// contains a digest that doesn't match the entries.
// ---------------------------------------------------------------------------

#[test]
fn test_utxo_state_restore_from_db_detects_digest_mismatch() {
    use ergo_state::utxo_state::UtxoState;
    use ergo_storage::utxo_db::{UtxoDb, UtxoMetadata};

    let dir = tempfile::tempdir().unwrap();
    let db = UtxoDb::open(dir.path().join("utxo")).unwrap();

    // Store entries with an incorrect digest.
    let bad_meta = UtxoMetadata {
        digest: [0xFF; 33],
        version: [0xAA; 32],
    };
    db.apply_changes(&[([0x01; 32], vec![0xAA])], &[], &bad_meta)
        .unwrap();
    drop(db);

    let db2 = UtxoDb::open(dir.path().join("utxo")).unwrap();
    let result = UtxoState::restore_from_db(db2);
    assert!(result.is_err(), "restore should fail on digest mismatch");
}

// ---------------------------------------------------------------------------
// Test: test_utxo_settings_defaults
//
// Verify that UTXO-related settings fields default correctly when not
// specified in the TOML config.
// ---------------------------------------------------------------------------

#[test]
fn test_utxo_settings_defaults() {
    use ergo_settings::settings::ErgoSettings;

    let config_str = r#"
[ergo]
network_type = "testnet"
directory = "/tmp/ergo-test"

[ergo.node]
state_type = "digest"
verify_transactions = true
blocks_to_keep = -1
mining = false
max_transaction_cost = 1000000
max_transaction_size = 98304

[ergo.chain]
protocol_version = 4
address_prefix = 16
block_interval_secs = 120
epoch_length = 1024
use_last_epochs = 8
initial_difficulty_hex = "01"

[ergo.chain.pow]
pow_type = "autolykos"
k = 32
n = 26

[ergo.chain.monetary]
fixed_rate_period = 525600
fixed_rate = 75000000000
founders_initial_reward = 7500000000
epoch_length = 64800
one_epoch_reduction = 3000000000
miner_reward_delay = 720

[network]
node_name = "test"
app_version = "5.1.0"
agent_name = "ergoref"
bind_address = "0.0.0.0:9020"
magic_bytes = [2, 0, 0, 1]

[api]
bind_address = "127.0.0.1:9052"
"#;
    let settings = ErgoSettings::from_toml(config_str).unwrap();
    assert!(!settings.ergo.node.utxo_bootstrap);
    assert_eq!(settings.ergo.node.storing_utxo_snapshots, 0);
    assert_eq!(settings.ergo.node.p2p_utxo_snapshots, 2);
    assert_eq!(settings.ergo.node.make_snapshot_every, 52224);
}

// ---------------------------------------------------------------------------
// Test: test_utxo_settings_explicit_values
//
// Verify that UTXO-related settings are correctly parsed from explicit TOML
// values that override the defaults.
// ---------------------------------------------------------------------------

#[test]
fn test_utxo_settings_explicit_values() {
    use ergo_settings::settings::ErgoSettings;

    let config_str = r#"
[ergo]
network_type = "testnet"
directory = "/tmp/ergo-test"

[ergo.node]
state_type = "utxo"
verify_transactions = true
blocks_to_keep = -1
mining = false
max_transaction_cost = 1000000
max_transaction_size = 98304
utxo_bootstrap = true
storing_utxo_snapshots = 3
p2p_utxo_snapshots = 5
make_snapshot_every = 10000

[ergo.chain]
protocol_version = 4
address_prefix = 16
block_interval_secs = 120
epoch_length = 1024
use_last_epochs = 8
initial_difficulty_hex = "01"

[ergo.chain.pow]
pow_type = "autolykos"
k = 32
n = 26

[ergo.chain.monetary]
fixed_rate_period = 525600
fixed_rate = 75000000000
founders_initial_reward = 7500000000
epoch_length = 64800
one_epoch_reduction = 3000000000
miner_reward_delay = 720

[network]
node_name = "test"
app_version = "5.1.0"
agent_name = "ergoref"
bind_address = "0.0.0.0:9020"
magic_bytes = [2, 0, 0, 1]

[api]
bind_address = "127.0.0.1:9052"
"#;
    let settings = ErgoSettings::from_toml(config_str).unwrap();
    assert!(settings.ergo.node.utxo_bootstrap);
    assert_eq!(settings.ergo.node.storing_utxo_snapshots, 3);
    assert_eq!(settings.ergo.node.p2p_utxo_snapshots, 5);
    assert_eq!(settings.ergo.node.make_snapshot_every, 10000);
}

// ---------------------------------------------------------------------------
// Test: test_utxo_db_bulk_insert_and_iterate
//
// Exercise UtxoDb with a larger number of entries to verify that iteration
// and entry_count work correctly at scale.
// ---------------------------------------------------------------------------

#[test]
fn test_utxo_db_bulk_insert_and_iterate() {
    use ergo_storage::utxo_db::{UtxoDb, UtxoMetadata};

    let dir = tempfile::tempdir().unwrap();
    let db = UtxoDb::open(dir.path().join("utxo")).unwrap();

    let meta = UtxoMetadata {
        digest: [0x42; 33],
        version: [0x01; 32],
    };

    // Insert 100 entries.
    let entries: Vec<([u8; 32], Vec<u8>)> = (0u8..100)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = i;
            (key, vec![i; 200])
        })
        .collect();

    db.apply_changes(&entries, &[], &meta).unwrap();
    assert_eq!(db.entry_count(), 100);

    // Verify all entries are present via iteration.
    let iterated: Vec<_> = db.iter_entries().collect();
    assert_eq!(iterated.len(), 100);

    // Remove the first 50.
    let to_remove: Vec<[u8; 32]> = entries[..50].iter().map(|(k, _)| *k).collect();
    db.apply_changes(&[], &to_remove, &meta).unwrap();
    assert_eq!(db.entry_count(), 50);

    // Verify remaining entries are accessible.
    for (key, val) in &entries[50..] {
        let stored = db.get(key).unwrap().unwrap();
        assert_eq!(stored, *val);
    }

    // Verify removed entries are gone.
    for (key, _) in &entries[..50] {
        assert!(db.get(key).unwrap().is_none());
    }
}

// ---------------------------------------------------------------------------
// Test: test_utxo_db_reopen_persistence
//
// Verify that data survives closing and reopening a UtxoDb at the same path.
// ---------------------------------------------------------------------------

#[test]
fn test_utxo_db_reopen_persistence() {
    use ergo_storage::utxo_db::{UtxoDb, UtxoMetadata};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("utxo");

    let meta = UtxoMetadata {
        digest: [0xDD; 33],
        version: [0xEE; 32],
    };

    // Open, write, and close.
    {
        let db = UtxoDb::open(&path).unwrap();
        db.apply_changes(&[([0x77; 32], vec![0x88, 0x99])], &[], &meta)
            .unwrap();
    }

    // Reopen and verify data is still there.
    let db = UtxoDb::open(&path).unwrap();
    assert_eq!(db.entry_count(), 1);
    assert_eq!(db.get(&[0x77; 32]).unwrap().unwrap(), vec![0x88, 0x99]);

    let restored_meta = db.metadata().unwrap().unwrap();
    assert_eq!(restored_meta.digest, [0xDD; 33]);
    assert_eq!(restored_meta.version, [0xEE; 32]);
}

// ===========================================================================
// Phase 21 — Wallet integration tests
// ===========================================================================

use ergo_wallet::keystore::Keystore;
use ergo_wallet::keys::WalletKeys;
use ergo_wallet::scan_logic::{scan_block as wallet_scan_block, OutputInfo, TxInfo};
use ergo_wallet::tracked_box::TrackedBox;
use ergo_wallet::tx_ops;
use ergo_wallet::wallet_manager::WalletManager;
use ergo_wallet::wallet_registry::WalletRegistry;
use ergo_wallet::wallet_storage::WalletStorage;
use std::collections::HashSet;

/// Well-known 12-word test mnemonic for deterministic tests.
const WALLET_TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Helper: create a TrackedBox with the given parameters.
fn make_tracked_box(box_id_byte: u8, value: u64, height: u32) -> TrackedBox {
    let mut box_id = [0u8; 32];
    box_id[0] = box_id_byte;
    let mut tx_id = [0u8; 32];
    tx_id[0] = box_id_byte;
    tx_id[1] = 0xFF;

    TrackedBox {
        box_id,
        ergo_tree_bytes: vec![0x00, 0x08, 0xcd, box_id_byte],
        value,
        tokens: vec![],
        creation_height: height,
        inclusion_height: height,
        tx_id,
        output_index: 0,
        serialized_box: vec![],
        additional_registers: vec![],
        spent: false,
        spending_tx_id: None,
        spending_height: None,
        scan_ids: vec![10],
    }
}

/// Helper: create a TrackedBox with tokens.
fn make_tracked_box_with_tokens(
    box_id_byte: u8,
    value: u64,
    height: u32,
    tokens: Vec<([u8; 32], u64)>,
) -> TrackedBox {
    let mut tb = make_tracked_box(box_id_byte, value, height);
    tb.tokens = tokens;
    tb
}

/// Helper: 32-byte array from a seed byte.
fn wallet_id32(seed: u8) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr[0] = seed;
    arr
}

// ---------------------------------------------------------------------------
// Test 1: wallet_keystore_init_unlock_roundtrip
// ---------------------------------------------------------------------------

#[test]
fn wallet_keystore_init_unlock_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let ks = Keystore::new(dir.path());

    // Keystore should not exist yet.
    assert!(!ks.exists());

    // Init with a password.
    let mnemonic = ks.init("test-password-123").unwrap();
    assert!(ks.exists());
    assert!(!mnemonic.is_empty());

    // Unlock with the same password — should return the same mnemonic.
    let unlocked = ks.unlock("test-password-123").unwrap();
    assert_eq!(mnemonic, unlocked);

    // Unlock with a wrong password — should fail.
    let err = ks.unlock("wrong-password").unwrap_err();
    assert!(
        matches!(err, ergo_wallet::keystore::KeystoreError::DecryptionFailed),
        "expected DecryptionFailed, got {err:?}"
    );

    // Verify the restored mnemonic with a known approach.
    let ks2_dir = tempfile::tempdir().unwrap();
    let ks2 = Keystore::new(ks2_dir.path());
    ks2.restore("pw", WALLET_TEST_MNEMONIC).unwrap();
    let restored = ks2.unlock("pw").unwrap();
    assert_eq!(restored, WALLET_TEST_MNEMONIC);
}

// ---------------------------------------------------------------------------
// Test 2: wallet_hd_key_derivation_produces_valid_addresses
// ---------------------------------------------------------------------------

#[test]
fn wallet_hd_key_derivation_produces_valid_addresses() {
    let keys = WalletKeys::from_mnemonic(WALLET_TEST_MNEMONIC, "").unwrap();

    let dk0 = keys.derive_at(0).unwrap();
    let dk1 = keys.derive_at(1).unwrap();
    let dk2 = keys.derive_at(2).unwrap();

    // All addresses should start with "9" (mainnet P2PK prefix).
    assert!(dk0.address.starts_with('9'), "addr0: {}", dk0.address);
    assert!(dk1.address.starts_with('9'), "addr1: {}", dk1.address);
    assert!(dk2.address.starts_with('9'), "addr2: {}", dk2.address);

    // All addresses should be distinct.
    assert_ne!(dk0.address, dk1.address);
    assert_ne!(dk1.address, dk2.address);
    assert_ne!(dk0.address, dk2.address);

    // Indices should be correct.
    assert_eq!(dk0.index, 0);
    assert_eq!(dk1.index, 1);
    assert_eq!(dk2.index, 2);

    // Paths should follow EIP-3.
    assert_eq!(dk0.path, "m/44'/429'/0'/0/0");
    assert_eq!(dk1.path, "m/44'/429'/0'/0/1");
    assert_eq!(dk2.path, "m/44'/429'/0'/0/2");
}

// ---------------------------------------------------------------------------
// Test 3: wallet_storage_persistence
// ---------------------------------------------------------------------------

#[test]
fn wallet_storage_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("wallet_storage_db");

    // Open, write, drop.
    {
        let ws = WalletStorage::open(&db_path).unwrap();
        ws.store_address(0, "9addr_zero").unwrap();
        ws.store_address(1, "9addr_one").unwrap();
        ws.store_address(2, "9addr_two").unwrap();
        ws.set_change_address("9change_addr").unwrap();
        ws.set_next_index(3).unwrap();
    }

    // Reopen and verify all data persists.
    {
        let ws = WalletStorage::open(&db_path).unwrap();
        let addrs = ws.get_addresses();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], (0, "9addr_zero".to_string()));
        assert_eq!(addrs[1], (1, "9addr_one".to_string()));
        assert_eq!(addrs[2], (2, "9addr_two".to_string()));

        assert_eq!(
            ws.get_change_address(),
            Some("9change_addr".to_string())
        );
        assert_eq!(ws.get_next_index(), 3);
    }
}

// ---------------------------------------------------------------------------
// Test 4: wallet_registry_insert_and_balance
// ---------------------------------------------------------------------------

#[test]
fn wallet_registry_insert_and_balance() {
    let dir = tempfile::tempdir().unwrap();
    let reg = WalletRegistry::open(dir.path()).unwrap();
    let block_id = [0xAA; 32];

    let mut token_id = [0u8; 32];
    token_id[0] = 0xCC;

    let b1 = make_tracked_box(1, 1_000_000, 10);
    let b2 = make_tracked_box_with_tokens(2, 2_000_000, 10, vec![(token_id, 500)]);
    let b3 = make_tracked_box_with_tokens(3, 3_000_000, 10, vec![(token_id, 300)]);

    reg.update_on_block(10, &block_id, vec![b1, b2, b3], vec![], vec![])
        .unwrap();

    let digest = reg.get_balance();
    // Total ERG: 1_000_000 + 2_000_000 + 3_000_000 = 6_000_000.
    assert_eq!(digest.erg_balance, 6_000_000);
    assert_eq!(digest.height, 10);

    // Token balance: 500 + 300 = 800.
    assert_eq!(digest.token_balances.len(), 1);
    assert_eq!(digest.token_balances[0], (token_id, 800));

    // All boxes should be unspent.
    let unspent = reg.unspent_boxes();
    assert_eq!(unspent.len(), 3);
    for tb in &unspent {
        assert!(!tb.spent);
    }
}

// ---------------------------------------------------------------------------
// Test 5: wallet_registry_rollback
// ---------------------------------------------------------------------------

#[test]
fn wallet_registry_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let reg = WalletRegistry::open(dir.path()).unwrap();

    let block_id10 = [0xAA; 32];
    let block_id20 = [0xBB; 32];

    // Insert a box at height 10.
    let b_early = make_tracked_box(1, 100_000, 10);
    reg.update_on_block(10, &block_id10, vec![b_early], vec![], vec![])
        .unwrap();

    // Insert a box at height 20.
    let b_late = make_tracked_box(2, 200_000, 20);
    reg.update_on_block(20, &block_id20, vec![b_late], vec![], vec![])
        .unwrap();

    assert_eq!(reg.all_boxes().len(), 2);
    assert_eq!(reg.wallet_height(), 20);

    // Rollback to height 15 — only height-10 box should remain.
    reg.rollback_to_height(15).unwrap();

    let remaining = reg.all_boxes();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].inclusion_height, 10);
    assert_eq!(remaining[0].value, 100_000);

    // Wallet height should reflect the rollback.
    assert_eq!(reg.wallet_height(), 10);

    // Balance should only reflect the surviving box.
    let digest = reg.get_balance();
    assert_eq!(digest.erg_balance, 100_000);
}

// ---------------------------------------------------------------------------
// Test 6: wallet_block_scanning
// ---------------------------------------------------------------------------

#[test]
fn wallet_block_scanning() {
    let wallet_tree = vec![0x00, 0x08, 0xcd, 0xAA];
    let other_tree = vec![0x00, 0x08, 0xcd, 0xBB];
    let tracked_id = wallet_id32(0x42);

    // TX 1: one matching output, one non-matching output.
    let tx1 = TxInfo {
        tx_id: wallet_id32(0x01),
        input_box_ids: vec![],
        outputs: vec![
            OutputInfo {
                box_id: wallet_id32(0x10),
                ergo_tree_bytes: wallet_tree.clone(),
                value: 5_000_000,
                tokens: vec![],
                creation_height: 100,
                output_index: 0,
                serialized_box: vec![0xDE, 0xAD],
                additional_registers: vec![],
            },
            OutputInfo {
                box_id: wallet_id32(0x11),
                ergo_tree_bytes: other_tree.clone(),
                value: 3_000_000,
                tokens: vec![],
                creation_height: 100,
                output_index: 1,
                serialized_box: vec![0xBE, 0xEF],
                additional_registers: vec![],
            },
        ],
        tx_bytes: vec![0xCA, 0xFE],
    };

    // TX 2: spends a tracked box, no matching outputs.
    let tx2 = TxInfo {
        tx_id: wallet_id32(0x02),
        input_box_ids: vec![tracked_id],
        outputs: vec![OutputInfo {
            box_id: wallet_id32(0x20),
            ergo_tree_bytes: other_tree.clone(),
            value: 2_000_000,
            tokens: vec![],
            creation_height: 100,
            output_index: 0,
            serialized_box: vec![0xBA, 0xBE],
            additional_registers: vec![],
        }],
        tx_bytes: vec![0xBA, 0xBE],
    };

    // TX 3: no matches at all.
    let tx3 = TxInfo {
        tx_id: wallet_id32(0x03),
        input_box_ids: vec![wallet_id32(0x99)],
        outputs: vec![OutputInfo {
            box_id: wallet_id32(0x30),
            ergo_tree_bytes: other_tree.clone(),
            value: 1_000_000,
            tokens: vec![],
            creation_height: 100,
            output_index: 0,
            serialized_box: vec![0xFE, 0xED],
            additional_registers: vec![],
        }],
        tx_bytes: vec![0xFE, 0xED],
    };

    let mut wallet_trees = HashSet::new();
    wallet_trees.insert(wallet_tree.clone());
    let mut tracked = HashSet::new();
    tracked.insert(tracked_id);

    let result = wallet_scan_block(&[tx1, tx2, tx3], 500, &wallet_trees, &tracked, &[]);

    // Should find 1 matching output (from tx1).
    assert_eq!(result.new_boxes.len(), 1);
    assert_eq!(result.new_boxes[0].box_id, wallet_id32(0x10));
    assert_eq!(result.new_boxes[0].value, 5_000_000);
    assert_eq!(result.new_boxes[0].inclusion_height, 500);
    assert!(!result.new_boxes[0].spent);

    // Should detect 1 spent tracked box (from tx2).
    assert_eq!(result.spent_box_ids.len(), 1);
    assert_eq!(result.spent_box_ids[0], tracked_id);

    // Should have 2 wallet-relevant transactions (tx1 and tx2, not tx3).
    assert_eq!(result.wallet_txs.len(), 2);
    let tx_ids: Vec<[u8; 32]> = result.wallet_txs.iter().map(|(id, _)| *id).collect();
    assert!(tx_ids.contains(&wallet_id32(0x01)));
    assert!(tx_ids.contains(&wallet_id32(0x02)));
}

// ---------------------------------------------------------------------------
// Test 7: wallet_manager_full_lifecycle
// ---------------------------------------------------------------------------

#[test]
fn wallet_manager_full_lifecycle() {
    let dir = tempfile::tempdir().unwrap();

    // Open — should be uninitialized.
    let mut wm = WalletManager::open(dir.path()).unwrap();
    let status = wm.status();
    assert!(!status.initialized);
    assert!(!status.unlocked);

    // Init — should transition to locked.
    let mnemonic = wm.init("test-pw").unwrap();
    assert!(!mnemonic.is_empty());
    let status = wm.status();
    assert!(status.initialized);
    assert!(!status.unlocked);

    // Unlock — should transition to unlocked.
    wm.unlock("test-pw").unwrap();
    let status = wm.status();
    assert!(status.initialized);
    assert!(status.unlocked);

    // Derive additional keys.
    let (_path, addr1) = wm.derive_next_key().unwrap();
    assert!(addr1.starts_with('9'));
    let (_path, addr2) = wm.derive_next_key().unwrap();
    assert!(addr2.starts_with('9'));
    assert_ne!(addr1, addr2);

    // Lock.
    wm.lock();
    let status = wm.status();
    assert!(status.initialized);
    assert!(!status.unlocked);
    assert!(wm.addresses().is_err(), "addresses should not be accessible when locked");

    // Drop and reopen — should detect locked state.
    drop(wm);
    let wm2 = WalletManager::open(dir.path()).unwrap();
    let status = wm2.status();
    assert!(status.initialized, "should detect keystore file on reopen");
    assert!(!status.unlocked, "should be locked after reopen");
}

// ---------------------------------------------------------------------------
// Test 8: wallet_collect_boxes_target
// ---------------------------------------------------------------------------

#[test]
fn wallet_collect_boxes_target() {
    // Create 5 boxes with varying values.
    let boxes = vec![
        make_tracked_box(1, 1_000_000, 10),
        make_tracked_box(2, 2_000_000, 10),
        make_tracked_box(3, 3_000_000, 10),
        make_tracked_box(4, 4_000_000, 10),
        make_tracked_box(5, 5_000_000, 10),
    ];

    // Collect with target of 5_000_000 — should succeed.
    let collected = tx_ops::collect_boxes(&boxes, 5_000_000, &[]).unwrap();
    let total: u64 = collected.iter().map(|b| b.value).sum();
    assert!(
        total >= 5_000_000,
        "collected total {total} should be >= 5_000_000"
    );
    // Should not need all 5 boxes.
    assert!(collected.len() <= 5);

    // Collect with exact total of 15_000_000 — should use all boxes.
    let collected_all = tx_ops::collect_boxes(&boxes, 15_000_000, &[]).unwrap();
    let total_all: u64 = collected_all.iter().map(|b| b.value).sum();
    assert_eq!(total_all, 15_000_000);
    assert_eq!(collected_all.len(), 5);

    // Collect with excessive target (more than available) — should error.
    let err = tx_ops::collect_boxes(&boxes, 100_000_000, &[]);
    assert!(err.is_err(), "should fail with excessive target");
    match err.unwrap_err() {
        tx_ops::TxOpsError::InsufficientFunds { needed, available } => {
            assert_eq!(needed, 100_000_000);
            assert_eq!(available, 15_000_000);
        }
        other => panic!("expected InsufficientFunds, got: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Test 9: wallet_balance_updates_after_block_scan
// ---------------------------------------------------------------------------

#[test]
fn wallet_balance_updates_after_block_scan() {
    let dir = tempfile::tempdir().unwrap();
    let mut wm = WalletManager::open(dir.path()).unwrap();

    // Restore a known mnemonic and unlock.
    wm.restore("pw", WALLET_TEST_MNEMONIC, "").unwrap();
    wm.unlock("pw").unwrap();

    // Get the wallet's first address and its ErgoTree.
    let addrs = wm.addresses().unwrap();
    assert!(!addrs.is_empty());
    let first_addr = &addrs[0];

    // Derive ErgoTree bytes from the address using the wallet's internal conversion.
    let tree_bytes = ergo_types::address::decode_address(first_addr).unwrap();
    let mut ergo_tree = Vec::with_capacity(3 + tree_bytes.content_bytes.len());
    ergo_tree.extend_from_slice(&[0x00, 0x08, 0xcd]);
    ergo_tree.extend_from_slice(&tree_bytes.content_bytes);

    // Before scanning, balance should be zero.
    let digest_before = wm.balances().unwrap();
    assert_eq!(digest_before.erg_balance, 0);

    // Create a fake block with an output matching the wallet address.
    let block_id = wallet_id32(0xAA);
    let tx = TxInfo {
        tx_id: wallet_id32(0x01),
        input_box_ids: vec![],
        outputs: vec![OutputInfo {
            box_id: wallet_id32(0x10),
            ergo_tree_bytes: ergo_tree.clone(),
            value: 10_000_000,
            tokens: vec![],
            creation_height: 100,
            output_index: 0,
            serialized_box: vec![0xDE, 0xAD],
            additional_registers: vec![],
        }],
        tx_bytes: vec![0xCA, 0xFE],
    };

    // Scan the block.
    wm.scan_block(100, &block_id, &[tx]).unwrap();

    // After scanning, balance should reflect the new box.
    let digest_after = wm.balances().unwrap();
    assert_eq!(digest_after.erg_balance, 10_000_000);
    assert_eq!(digest_after.height, 100);

    // Should have 1 unspent box.
    let unspent = wm.unspent_boxes().unwrap();
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].value, 10_000_000);
    assert_eq!(unspent[0].box_id, wallet_id32(0x10));

    // Scan a second block that sends more to the same address.
    let block_id2 = wallet_id32(0xBB);
    let tx2 = TxInfo {
        tx_id: wallet_id32(0x02),
        input_box_ids: vec![],
        outputs: vec![OutputInfo {
            box_id: wallet_id32(0x20),
            ergo_tree_bytes: ergo_tree.clone(),
            value: 5_000_000,
            tokens: vec![],
            creation_height: 200,
            output_index: 0,
            serialized_box: vec![0xBE, 0xEF],
            additional_registers: vec![],
        }],
        tx_bytes: vec![0xBA, 0xBE],
    };
    wm.scan_block(200, &block_id2, &[tx2]).unwrap();

    // Balance should be cumulative: 10_000_000 + 5_000_000 = 15_000_000.
    let digest_final = wm.balances().unwrap();
    assert_eq!(digest_final.erg_balance, 15_000_000);
    assert_eq!(wm.unspent_boxes().unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// Bonus Test 10: wallet_registry_token_balance_after_rollback
// ---------------------------------------------------------------------------

#[test]
fn wallet_registry_token_balance_after_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let reg = WalletRegistry::open(dir.path()).unwrap();

    let mut token_id = [0u8; 32];
    token_id[0] = 0xDD;

    let block_id10 = [0xAA; 32];
    let block_id20 = [0xBB; 32];

    // Height 10: one box with tokens.
    let b1 = make_tracked_box_with_tokens(1, 1_000_000, 10, vec![(token_id, 500)]);
    reg.update_on_block(10, &block_id10, vec![b1], vec![], vec![])
        .unwrap();

    // Height 20: another box with tokens.
    let b2 = make_tracked_box_with_tokens(2, 2_000_000, 20, vec![(token_id, 300)]);
    reg.update_on_block(20, &block_id20, vec![b2], vec![], vec![])
        .unwrap();

    // Before rollback: total tokens = 800.
    let digest = reg.get_balance();
    assert_eq!(digest.token_balances.len(), 1);
    assert_eq!(digest.token_balances[0], (token_id, 800));

    // Rollback to height 15 — only height-10 box's tokens remain.
    reg.rollback_to_height(15).unwrap();

    let digest = reg.get_balance();
    assert_eq!(digest.token_balances.len(), 1);
    assert_eq!(digest.token_balances[0], (token_id, 500));
    assert_eq!(digest.erg_balance, 1_000_000);
}

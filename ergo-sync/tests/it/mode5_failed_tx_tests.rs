use super::*;
use ergo_crypto::difficulty::DifficultyParams;
use ergo_sync::block_proc::BlockProcessError;
use ergo_sync::coordinator::SyncCoordinator;
use ergo_sync::executor::SyncExecutor;
use ergo_validation::block::BlockValidationError;

// ----- helpers -----

fn executor() -> SyncExecutor {
    SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        DifficultyParams::mainnet(),
    )
}

fn apply_first(executor: &mut SyncExecutor, backend: &mut StateBackendKind) {
    let mut coordinator = SyncCoordinator::new(APPLY_LO - 1);
    executor.try_apply_next_blocks(backend, &mut coordinator, std::time::Instant::now(), None);
    assert_eq!(
        backend.chain_state_meta().best_full_block_height,
        APPLY_LO - 1
    );
}

// ----- happy path -----

// ----- round-trips -----

// ----- error paths -----

#[test]
fn digest_valid_proofs_transaction_failure_queues_exact_id_and_durably_invalidates() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut store, rows) = build_seeded_store(tmp.path());
    // Keep the authenticated state transition intact; a restricted transaction
    // budget forces a verdict only after the real ADProofs resolve the inputs.
    let mut params = store.active_params().clone();
    params.max_block_cost = 1;
    store.seed_voted_params_row_for_test(&params).unwrap();
    let row = &rows[&APPLY_LO];
    let txs = ergo_ser::block_transactions::read_block_transactions(&mut VlqReader::new(
        &row.block_tx_bytes,
    ))
    .unwrap();
    let expected = *ergo_ser::transaction::transaction_id(&txs.transactions[0])
        .unwrap()
        .as_bytes();
    let mut backend = StateBackendKind::Digest(store);
    let error = process_block(
        &mut backend,
        &row.header_id,
        &ProtocolParams::mainnet_default(),
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            BlockProcessError::TransactionValidation {
                source: BlockValidationError::Transaction {
                    index: 0,
                    error: ergo_validation::ValidationError::CostExceeded { .. },
                },
                ..
            } | BlockProcessError::Validation(BlockValidationError::Transaction {
                index: 0,
                error: ergo_validation::ValidationError::CostExceeded { .. },
            })
        ),
        "expected transaction zero's validation verdict after proof resolution: {error:?}"
    );

    let mut executor = executor();
    apply_first(&mut executor, &mut backend);
    assert_eq!(executor.take_failed_transactions(), vec![expected]);
    assert!(executor.take_failed_transactions().is_empty());
    // Read the persisted invalidity table, independently of session marks.
    assert!(backend.is_durably_invalid(&row.header_id).unwrap());
}

#[test]
fn digest_unavailable_proofs_queues_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, rows) = build_seeded_store_with_proof(tmp.path(), false);
    let mut backend = StateBackendKind::Digest(store);
    let msg = process_first_applied(&mut backend, &rows).unwrap_err();
    assert!(msg.contains("ADProofs section not yet available"), "{msg}");
    let mut executor = executor();
    apply_first(&mut executor, &mut backend);
    assert!(executor.take_failed_transactions().is_empty());
    assert!(!backend.is_invalid(&rows[&APPLY_LO].header_id).unwrap());
}

#[test]
fn digest_rejected_proofs_queues_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, rows) = build_seeded_store(tmp.path());
    let row = &rows[&APPLY_LO];
    let header = parse_header(&row.header_bytes);
    let ad_id = compute_section_id(
        TYPE_AD_PROOFS,
        &row.header_id,
        header.ad_proofs_root.as_bytes(),
    );
    let mut proof = row.proof_bytes.clone();
    let mid = proof.len() / 2;
    proof[mid] ^= 0xff;
    store
        .store_block_section_typed(
            &ad_id,
            &ad_proofs_section_bytes(row.header_id, &proof),
            TYPE_AD_PROOFS,
        )
        .unwrap();
    let mut backend = StateBackendKind::Digest(store);
    let msg = process_first_applied(&mut backend, &rows).unwrap_err();
    assert!(msg.contains("ADProofs root mismatch"), "{msg}");
    let mut executor = executor();
    apply_first(&mut executor, &mut backend);
    assert!(executor.take_failed_transactions().is_empty());
    assert!(backend.is_invalid(&row.header_id).unwrap());
    assert!(!backend.is_durably_invalid(&row.header_id).unwrap());
}

// ----- oracle parity -----

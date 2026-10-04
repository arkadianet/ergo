use super::*;
use ergo_mempool::admission::{MockPlan, MockStructure, MockValidator, ValidationErr};
use ergo_mempool::types::{MempoolConfig, TipPointer};
use ergo_mempool::{weight, Mempool};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::{transaction_id, write_transaction, Transaction};
use ergo_state::ChainStateRead;

// ----- helpers -----

/// A one-input transaction with a trivially true output, spending box
/// `[input; 32]`.
fn tx(input: u8) -> Transaction {
    Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes([input; 32]),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate::new(
            1_000_000,
            read_ergo_tree(&mut VlqReader::new(&[0, 8, 0xd3])).unwrap(),
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()],
    }
}

/// Signed bytes and id of [`tx`].
fn signed_tx(input: u8) -> (Vec<u8>, Digest32) {
    let tx = tx(input);
    let mut writer = VlqWriter::new();
    write_transaction(&mut writer, &tx).unwrap();
    let id = transaction_id(&tx).unwrap();
    (writer.result(), Digest32::from_bytes(*id.as_bytes()))
}

/// A node whose applied chain is genesis plus `blocks` empty blocks.
fn chain(blocks: u32) -> (tempfile::TempDir, NodeState) {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = crate::node::tests::make_state(&tmp.path().join("state.redb"));
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .initialize_genesis(&[])
        .unwrap();
    for _ in 0..blocks {
        append_block(&mut state, vec![], 0);
    }
    (tmp, state)
}

/// Apply a synthetic block carrying `txs` (after an unrelated filler, since a
/// block is never empty) on the applied tip, without validation; `fork`
/// distinguishes competing blocks at one height. Only the header, the
/// block-transactions section, and the applied chain index are written, which
/// is all confirmation tracking reads.
fn append_block(state: &mut NodeState, txs: Vec<Transaction>, fork: u8) -> [u8; 32] {
    use ergo_primitives::digest::{ADDigest, ModifierId};
    use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
    use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
    let tip = state.store.chain_state_meta();
    let height = tip.best_full_block_height + 1;
    let header = ergo_ser::header::Header {
        version: 2,
        parent_id: ModifierId::from_bytes(tip.best_full_block_id),
        ad_proofs_root: Digest32::from_bytes([0; 32]),
        transactions_root: Digest32::from_bytes([fork; 32]),
        state_root: ADDigest::from_bytes([0; 33]),
        timestamp: 1_000_000 + u64::from(height),
        extension_root: Digest32::from_bytes([0; 32]),
        n_bits: 16842752,
        height,
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
        solution: ergo_ser::autolykos::AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
            nonce: [0; 8],
        },
    };
    let (bytes, id) = ergo_ser::header::serialize_header(&header).unwrap();
    let id = *id.as_bytes();
    let store = state.store.as_utxo_mut().unwrap();
    store.store_header(&id, &bytes).unwrap();
    let mut writer = VlqWriter::new();
    write_block_transactions(
        &mut writer,
        &BlockTransactions {
            header_id: ModifierId::from_bytes(id),
            transactions: std::iter::once(tx(0xFF)).chain(txs).collect(),
        },
    )
    .unwrap();
    store
        .store_block_section_typed(
            &compute_section_id(TYPE_BLOCK_TRANSACTIONS, &id, &[fork; 32]),
            &writer.result(),
            TYPE_BLOCK_TRANSACTIONS,
        )
        .unwrap();
    let root = store.root_digest();
    store
        .apply_block_unchecked_for_test(height, &id, &root, &[])
        .unwrap();
    id
}

fn tip_id(state: &NodeState) -> String {
    hex::encode(state.store.chain_state_meta().best_full_block_id)
}

/// The queue entry for [`signed_tx`], as admission builds it.
fn queued_entry(input: u8) -> Entry {
    let (bytes, id) = signed_tx(input);
    Entry::new(
        id,
        Arc::from(bytes.clone()),
        vec![Digest32::from_bytes([input; 32])],
        vec![],
        vec![],
        0,
        0,
        bytes.len() as u32,
        100,
        TxSource::Wallet,
    )
}

/// Queue `input`'s transaction directly and register it the way admission
/// does, bypassing chain validation.
fn queue_directly(
    state: &mut NodeState,
    handle: &MiningHandle,
    input: u8,
    options: ergo_mining::private_queue::PrivateTransactionOptions,
) -> String {
    let entry = queued_entry(input);
    let item = handle
        .private_queue()
        .admit(&entry, options, crate::snapshot::unix_now_ms(), 100)
        .unwrap();
    state.mempool.register_private_transaction(entry.tx_id);
    item.tx_id
}

fn mining_handle() -> MiningHandle {
    MiningHandle::new(
        [0x02; 33],
        ergo_mining::emission_rules::MonetarySettings::mainnet(),
        None,
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
        ergo_validation::VotingSettings::mainnet(),
    )
}

struct NoBoxes;
impl ergo_validation::UtxoView for NoBoxes {
    fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
        None
    }
}

// ----- admission -----

#[test]
fn admission_rejects_a_transaction_staged_by_public_admission() {
    // An orphan staged from an earlier public submit can be promoted and
    // relayed once its parent arrives, so it cannot become private.
    let tmp = tempfile::tempdir().unwrap();
    let mut state = crate::node::tests::make_state(&tmp.path().join("state.redb"));
    state.mempool = Mempool::new(
        MempoolConfig {
            staging_enabled: true,
            min_relay_fee_nano_erg: 0,
            ..MempoolConfig::default()
        },
        weight::from_config("cost").unwrap(),
    );
    let (bytes, id) = signed_tx(1);
    let validator = MockValidator::new()
        .plan(
            bytes.clone(),
            MockPlan {
                result: Err(ValidationErr::UnresolvedInput),
                charge: 0,
                peek_fee: Some(0),
                peek_tx_id: Some(id),
            },
        )
        .structure(
            bytes.clone(),
            MockStructure {
                tx_id: id,
                fee: 0,
                input_box_ids: vec![Digest32::from_bytes([1; 32])],
                output_box_ids: vec![],
            },
        );
    let tx_context = ergo_validation::TransactionContext {
        height: 101,
        miner_pubkey: [0; 33],
        pre_header_timestamp: 0,
        activated_script_version: 2,
        pre_header_version: 3,
        pre_header_parent_id: [0; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0; 3],
    };
    let params = ergo_validation::ProtocolParams::mainnet_default();
    let tip = ergo_mempool::admission::TipContext {
        tip: TipPointer {
            height: 100,
            header_id: Digest32::from_bytes([9; 32]),
        },
        best_header_height: 100,
        best_full_block_height: 100,
        utxo: &NoBoxes,
        tx_context: &tx_context,
        params: &params,
        last_headers: &[],
        reemission: None,
    };
    state.mempool.process(
        &bytes,
        TxSource::Api,
        std::time::Instant::now(),
        &tip,
        &validator,
    );
    assert!(state.mempool.is_staged(&id), "precondition: staged orphan");

    let handle = mining_handle();
    let error = admit(
        &mut state,
        &handle,
        &bytes,
        PrivateTransactionOptions::default(),
    )
    .expect_err("a staged transaction cannot become private");
    assert!(
        matches!(&error, MiningApiError::BadRequest(detail) if detail.contains("public mempool")),
        "{error:?}"
    );
    assert!(handle.private_queue().list().is_empty());
    assert!(!state.mempool.is_private_transaction(&id));
}

// ----- withdrawal releases the public-admission guard -----

#[test]
fn cancelling_lets_the_transaction_through_public_admission_again() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = crate::node::tests::make_state(&tmp.path().join("state.redb"));
    let handle = mining_handle();
    let tx_id = queue_directly(&mut state, &handle, 1, Default::default());
    let id = queued_entry(1).tx_id;
    assert!(state.mempool.is_private_transaction(&id));

    let (reply, mut response) = tokio::sync::oneshot::channel();
    let _ = crate::node::mining_dispatch::handle_mining_request(
        &mut state,
        Some(&handle),
        false,
        crate::mining_bridge::MiningRequest::CancelPrivateTransaction {
            tx_id: tx_id.clone(),
            reply,
        },
    );
    assert_eq!(response.try_recv().unwrap().unwrap().state, "cancelled");
    assert!(
        !state.mempool.is_private_transaction(&id),
        "the operator may now broadcast it through this node"
    );
}

#[test]
fn expiry_lets_the_transaction_through_public_admission_again() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = crate::node::tests::make_state(&tmp.path().join("state.redb"));
    let handle = mining_handle();
    let tx_id = queue_directly(
        &mut state,
        &handle,
        1,
        ergo_mining::private_queue::PrivateTransactionOptions {
            expires_at_ms: Some(crate::snapshot::unix_now_ms() + 5),
            ..Default::default()
        },
    );
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(expire(&mut state, &handle).unwrap());
    assert_eq!(
        handle.private_queue().entry(&tx_id).unwrap().state,
        PrivateTransactionState::Expired
    );
    assert!(!state.mempool.is_private_transaction(&queued_entry(1).tx_id));
}

#[test]
fn startup_registers_only_transactions_still_waiting_for_this_miner() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = crate::node::tests::make_state(&tmp.path().join("state.redb"));
    let handle = mining_handle();
    queue_directly(&mut state, &handle, 1, Default::default());
    let cancelled = queue_directly(&mut state, &handle, 2, Default::default());
    handle.private_queue().cancel(&cancelled).unwrap();

    let mut restarted = Mempool::new(
        MempoolConfig::default(),
        weight::from_config("cost").unwrap(),
    );
    register_queued(&mut restarted, &handle.private_queue());
    assert!(restarted.is_private_transaction(&queued_entry(1).tx_id));
    assert!(!restarted.is_private_transaction(&queued_entry(2).tx_id));
}

// ----- reconciliation before expiry -----

/// Queue input `input`'s transaction at the applied tip, eligible through
/// `last_height`.
fn queue_until(state: &NodeState, handle: &MiningHandle, input: u8, last_height: u32) -> String {
    handle
        .private_queue()
        .admit_at_tip(
            &queued_entry(input),
            ergo_mining::private_queue::PrivateTransactionOptions {
                expires_at_height: Some(last_height),
                ..Default::default()
            },
            crate::snapshot::unix_now_ms(),
            state.store.chain_state_meta().best_full_block_height,
            Some(tip_id(state)),
        )
        .unwrap()
        .tx_id
}

#[test]
fn a_transaction_mined_in_its_last_eligible_block_is_recorded_mined() {
    let (_dir, mut state) = chain(4);
    let handle = mining_handle();
    let tx_id = queue_until(&state, &handle, 1, 5);
    // Height 5 is the last eligible block, and it confirms the transaction.
    append_block(&mut state, vec![tx(1)], 0);
    run_lifecycle(&mut state, &handle);
    let item = handle.private_queue().entry(&tx_id).unwrap();
    assert_eq!(item.state, PrivateTransactionState::Mined);
    assert_eq!(item.mined_height, Some(5));
}

#[test]
fn a_mining_request_before_reconciliation_does_not_expire_a_confirmed_transaction() {
    // Every mining request applies deadlines first; the block confirming the
    // transaction in its last eligible height is not reconciled yet.
    let (_dir, mut state) = chain(4);
    let handle = mining_handle();
    let tx_id = queue_until(&state, &handle, 1, 5);
    append_block(&mut state, vec![tx(1)], 0);
    let (reply, _response) = tokio::sync::oneshot::channel();
    let _ = crate::node::mining_dispatch::handle_mining_request(
        &mut state,
        Some(&handle),
        false,
        crate::mining_bridge::MiningRequest::ListPrivateTransactions { reply },
    );
    assert_ne!(
        handle.private_queue().entry(&tx_id).unwrap().state,
        PrivateTransactionState::Expired
    );
    run_lifecycle(&mut state, &handle);
    assert_eq!(
        handle.private_queue().entry(&tx_id).unwrap().state,
        PrivateTransactionState::Mined
    );
}

#[test]
fn a_confirmation_deeper_than_the_rollback_window_releases_bytes_and_guard() {
    let (_dir, mut state) = chain(4);
    state.store.as_utxo_mut().unwrap().set_rollback_window(3);
    let handle = mining_handle();
    let tx_id = queue_until(&state, &handle, 1, 100);
    let id = queued_entry(1).tx_id;
    state.mempool.register_private_transaction(id);
    append_block(&mut state, vec![tx(1)], 0);
    run_lifecycle(&mut state, &handle);
    for _ in 0..2 {
        append_block(&mut state, vec![], 0);
        run_lifecycle(&mut state, &handle);
    }
    assert_eq!(
        handle.private_queue().guarded_ids().len(),
        1,
        "still rollbackable"
    );
    assert!(state.mempool.is_private_transaction(&id));
    append_block(&mut state, vec![], 0);
    run_lifecycle(&mut state, &handle);
    assert!(handle.private_queue().guarded_ids().is_empty());
    assert!(!state.mempool.is_private_transaction(&id));
    let item = handle.private_queue().entry(&tx_id).unwrap();
    assert_eq!(item.state, PrivateTransactionState::Mined);
    assert!(item.input_ids.is_empty(), "no reservation once settled");
}

#[test]
fn an_unconfirmed_transaction_expires_once_its_last_height_is_reconciled() {
    let (_dir, mut state) = chain(4);
    let handle = mining_handle();
    let tx_id = queue_until(&state, &handle, 1, 5);
    append_block(&mut state, vec![], 0);
    run_lifecycle(&mut state, &handle);
    assert_eq!(
        handle.private_queue().entry(&tx_id).unwrap().state,
        PrivateTransactionState::Expired
    );
}

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

// ----- helpers -----

/// Signed bytes and id of a one-input transaction with a trivially true
/// output, spending box `[input; 32]`.
fn signed_tx(input: u8) -> (Vec<u8>, Digest32) {
    let tx = Transaction {
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
    };
    let mut writer = VlqWriter::new();
    write_transaction(&mut writer, &tx).unwrap();
    let id = transaction_id(&tx).unwrap();
    (writer.result(), Digest32::from_bytes(*id.as_bytes()))
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

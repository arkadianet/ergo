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
    // Later forks score higher, so a competing branch becomes the best chain.
    let score = vec![u8::try_from(height * 2).unwrap() + fork];
    store
        .store_validated_header(
            &id,
            &bytes,
            &ergo_state::chain::HeaderMeta {
                parent_id: tip.best_full_block_id,
                height,
                cumulative_score: score.clone(),
                pow_validity: 1,
                timestamp: header.timestamp,
            },
            Some((height, score)),
        )
        .unwrap();
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

/// Publish a template on the applied tip whose user transactions are `txs`,
/// all built as private ones, identified by `msg`.
fn serve(handle: &MiningHandle, state: &NodeState, txs: Vec<Transaction>, msg: [u8; 32]) {
    serve_at(handle, state, txs, msg, 0x0101_0000);
}

/// [`serve`] at the difficulty encoded by `n_bits`.
fn serve_at(
    handle: &MiningHandle,
    state: &NodeState,
    txs: Vec<Transaction>,
    msg: [u8; 32],
    n_bits: u32,
) {
    use ergo_primitives::digest::ADDigest;
    use ergo_validation::pre_header::{
        build_last_block_utxo_root, CandidatePreHeader, CandidateValidationContext,
    };
    let tip = state.store.chain_state_meta();
    let parent = tip.best_full_block_id;
    let height = tip.best_full_block_height + 1;
    handle.set_best_tip(ergo_mining::engine::BestTip {
        parent_id: parent,
        chain_seq: 1,
        synced: true,
    });
    let header = ergo_ser::header::Header {
        version: 2,
        parent_id: ergo_primitives::digest::ModifierId::from_bytes(parent),
        ad_proofs_root: Digest32::from_bytes([0; 32]),
        transactions_root: Digest32::from_bytes(msg),
        state_root: ADDigest::from_bytes([0; 33]),
        timestamp: 1_000_000 + u64::from(height),
        extension_root: Digest32::from_bytes([0; 32]),
        n_bits,
        height,
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
        solution: ergo_ser::autolykos::AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
            nonce: [0; 8],
        },
    };
    let observation = ergo_mining::inspection::CandidateObservation {
        transactions: txs
            .iter()
            .map(|_| ergo_mining::inspection::TransactionObservation {
                category: "private",
                ..Default::default()
            })
            .collect(),
        operator_generation: handle.operator_generation(),
        ..Default::default()
    };
    let target = ergo_crypto::difficulty::get_target(n_bits);
    let candidate = ergo_mining::candidate::Candidate {
        header,
        validation_ctx: CandidateValidationContext {
            pre_header: CandidatePreHeader {
                version: 2,
                parent_id: parent,
                height,
                timestamp: 1_000_000 + u64::from(height),
                n_bits,
                votes: [0; 3],
                miner_pubkey: [2; 33],
            },
            activated_script_version: 2,
            last_headers: Vec::new(),
            last_block_utxo_root: build_last_block_utxo_root(ADDigest::from_bytes([0; 33])),
        },
        transactions: txs,
        ad_proof_bytes: Vec::new(),
        extension_fields: Vec::new(),
        msg,
        target: target.clone(),
        parent_id: parent,
        observation,
    };
    let work = ergo_mining::work_message::WorkMessage {
        msg,
        target,
        height,
        pk: [2; 33],
        metrics: Default::default(),
    };
    handle
        .publish_if_current(
            candidate,
            work,
            &parent,
            || 0,
            ergo_mining::engine::BuildReason::MempoolRefresh,
        )
        .expect("publishes on the applied tip");
}

/// A box guarded by a trivially true script, created at genesis.
fn spendable_box(value: u64, creator: u8) -> ErgoBox {
    ErgoBox {
        candidate: ErgoBoxCandidate::new(
            value,
            read_ergo_tree(&mut VlqReader::new(&[0, 8, 0xd3])).unwrap(),
            0,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap(),
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes([creator; 32]),
        index: 0,
    }
}

/// A node `blocks` deep whose UTXO set holds `boxes`, with the block context
/// admission validates against.
fn admitting_chain(blocks: u32, boxes: &[ErgoBox]) -> (tempfile::TempDir, NodeState) {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = crate::node::tests::make_state(&tmp.path().join("state.redb"));
    let genesis: Vec<_> = boxes
        .iter()
        .map(|b| {
            (
                *b.box_id().unwrap().as_bytes(),
                ergo_ser::ergo_box::serialize_ergo_box(b).unwrap(),
            )
        })
        .collect();
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .initialize_genesis(&genesis)
        .unwrap();
    for _ in 0..blocks {
        append_block(&mut state, vec![], 0);
    }
    state.executor.hydrate_block_context(&state.store).unwrap();
    (tmp, state)
}

/// Zero-fee signed bytes moving `input` to one trivially true output.
fn spend(input: &ErgoBox) -> Vec<u8> {
    let tx = Transaction {
        inputs: vec![Input {
            box_id: input.box_id().unwrap(),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate::new(
            input.candidate.value,
            read_ergo_tree(&mut VlqReader::new(&[0, 8, 0xd3])).unwrap(),
            1,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()],
    };
    let mut writer = VlqWriter::new();
    write_transaction(&mut writer, &tx).unwrap();
    writer.result()
}

/// A mining handle whose queue persists at `path`.
fn persisted_handle(path: &std::path::Path) -> MiningHandle {
    mining_handle().with_private_queue(Arc::new(
        ergo_mining::private_queue::PrivateTransactionQueue::open(path).unwrap(),
    ))
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
    expire(&mut state, &handle);
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
    queue_at_tip(
        state,
        handle,
        input,
        ergo_mining::private_queue::PrivateTransactionOptions {
            expires_at_height: Some(last_height),
            ..Default::default()
        },
    )
}

/// Queue input `input`'s transaction at the applied tip.
fn queue_at_tip(
    state: &NodeState,
    handle: &MiningHandle,
    input: u8,
    options: ergo_mining::private_queue::PrivateTransactionOptions,
) -> String {
    handle
        .private_queue()
        .admit_at_tip(
            &queued_entry(input),
            options,
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

// ----- event-driven lifecycle -----

#[test]
fn the_lifecycle_works_only_when_the_applied_tip_changes() {
    let (dir, mut state) = chain(4);
    let path = dir.path().join("queue.json");
    let handle = persisted_handle(&path);
    queue_until(&state, &handle, 1, 100);
    run_lifecycle(&mut state, &handle);
    let passes = state.private_mining.reconcile_passes;
    let written = std::fs::read(&path).unwrap();
    // Peer batches, mempool and sync ticks, and API requests all end in a
    // lifecycle pass; none of them may reconcile or rewrite an unchanged queue.
    for _ in 0..100 {
        run_lifecycle(&mut state, &handle);
    }
    assert_eq!(state.private_mining.reconcile_passes, passes);
    assert_eq!(std::fs::read(&path).unwrap(), written, "no rewrite");
    append_block(&mut state, vec![], 0);
    run_lifecycle(&mut state, &handle);
    assert_eq!(state.private_mining.reconcile_passes, passes + 1);
}

#[test]
fn candidate_membership_is_read_from_the_served_template_without_a_write() {
    let (dir, mut state) = chain(4);
    let path = dir.path().join("queue.json");
    let handle = persisted_handle(&path);
    queue_until(&state, &handle, 1, 100);
    run_lifecycle(&mut state, &handle);
    let revision = handle.private_queue().revision();
    let written = std::fs::read(&path).unwrap();

    serve(&handle, &state, vec![tx(1)], [0x51; 32]);
    run_lifecycle(&mut state, &handle);
    assert_eq!(list(&handle)[0].state, "in_candidate");
    serve(&handle, &state, vec![], [0x52; 32]);
    run_lifecycle(&mut state, &handle);
    assert_eq!(list(&handle)[0].state, "queued");

    assert_eq!(handle.private_queue().revision(), revision);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        written,
        "membership is never stored"
    );
}

#[test]
fn a_rollback_reopens_an_orphaned_confirmation_and_rescans_the_new_branch() {
    let (_dir, mut state) = chain(4);
    let handle = mining_handle();
    let tx_id = queue_until(&state, &handle, 1, 100);
    append_block(&mut state, vec![tx(1)], 0);
    run_lifecycle(&mut state, &handle);
    assert_eq!(
        handle.private_queue().entry(&tx_id).unwrap().mined_height,
        Some(5)
    );
    // A competing branch replaces block 5 and does not contain it.
    state
        .store
        .as_utxo_mut()
        .unwrap()
        .rollback_to(4, None, None)
        .unwrap();
    append_block(&mut state, vec![], 1);
    append_block(&mut state, vec![], 1);
    run_lifecycle(&mut state, &handle);
    let item = handle.private_queue().entry(&tx_id).unwrap();
    assert_ne!(item.state, PrivateTransactionState::Mined, "orphaned");
    assert_eq!(item.mined_height, None);
    assert_eq!(
        handle.private_queue().observation_cursor(),
        (6, Some(tip_id(&state))),
        "the cursor follows the new branch"
    );
    // The same transaction confirmed again on the new branch.
    append_block(&mut state, vec![tx(1)], 1);
    run_lifecycle(&mut state, &handle);
    let item = handle.private_queue().entry(&tx_id).unwrap();
    assert_eq!(item.state, PrivateTransactionState::Mined);
    assert_eq!(item.mined_height, Some(7));
}

#[test]
fn a_long_offline_interval_is_reconciled_in_bounded_steps() {
    let (_dir, mut state) = chain(4);
    let handle = mining_handle();
    let tx_id = queue_until(&state, &handle, 1, 1_000);
    for _ in 0..40 {
        append_block(&mut state, vec![], 0);
    }
    append_block(&mut state, vec![tx(1)], 0);
    run_lifecycle(&mut state, &handle);
    assert_eq!(
        handle.private_queue().observed_height(),
        4 + 32,
        "one batch"
    );
    // Catch-up continues on later passes without a new block.
    run_lifecycle(&mut state, &handle);
    let item = handle.private_queue().entry(&tx_id).unwrap();
    assert_eq!(item.state, PrivateTransactionState::Mined);
    assert_eq!(item.mined_height, Some(45));
}

// ----- withdrawal scope -----

/// Send a cancel request through the mining dispatcher.
fn cancel_request(
    state: &mut NodeState,
    handle: &MiningHandle,
    tx_id: &str,
) -> Result<ergo_api::mining::PrivateTransactionEntry, MiningApiError> {
    let (reply, mut response) = tokio::sync::oneshot::channel();
    let rebuild = crate::node::mining_dispatch::handle_mining_request(
        state,
        Some(handle),
        false,
        crate::mining_bridge::MiningRequest::CancelPrivateTransaction {
            tx_id: tx_id.into(),
            reply,
        },
    );
    assert!(!rebuild, "a queue change is not a failed mined block");
    response.try_recv().unwrap()
}

#[test]
fn admission_keeps_serving_current_templates_and_asks_for_a_refresh() {
    let boxes = [spendable_box(1_000_000_000, 0x31)];
    let (_dir, mut state) = admitting_chain(4, &boxes);
    let handle = mining_handle();
    serve(&handle, &state, vec![], [0x61; 32]);
    let generation = handle.operator_generation();
    let revision = handle.private_queue().revision();
    let entry = admit(&mut state, &handle, &spend(&boxes[0]), Default::default())
        .expect("a valid zero-fee transaction is queued");
    assert_eq!(entry.state, "queued");
    assert_eq!(
        handle
            .cached_template_if_synced()
            .expect("still served")
            .0
            .msg,
        [0x61; 32],
        "adding work invalidates nothing"
    );
    assert_eq!(handle.operator_generation(), generation);
    assert_ne!(
        handle.private_queue().revision(),
        revision,
        "the action loop rebuilds on the revision change"
    );
}

#[test]
fn cancelling_withdraws_only_templates_that_include_the_transaction() {
    let (_dir, mut state) = chain(4);
    let handle = mining_handle();
    let tx_id = queue_until(&state, &handle, 1, 100);
    serve(&handle, &state, vec![tx(1)], [0x61; 32]);
    serve(&handle, &state, vec![], [0x62; 32]);
    let generation = handle.operator_generation();
    assert_eq!(
        cancel_request(&mut state, &handle, &tx_id).unwrap().state,
        "cancelled"
    );
    assert_eq!(
        handle
            .inspect_template(Some([0x61; 32]), None)
            .unwrap()
            .status,
        "withdrawn"
    );
    assert_eq!(
        handle.cached_template_if_synced().expect("served").0.msg,
        [0x62; 32],
        "unrelated work keeps serving and accepting solutions"
    );
    assert_eq!(
        handle.operator_generation(),
        generation + 1,
        "builds frozen before the cancel cannot publish it"
    );
}

#[test]
fn cancelling_an_unknown_or_confirmed_id_touches_no_template() {
    let (_dir, mut state) = chain(4);
    let handle = mining_handle();
    let tx_id = queue_until(&state, &handle, 1, 100);
    append_block(&mut state, vec![tx(1)], 0);
    run_lifecycle(&mut state, &handle);
    serve(&handle, &state, vec![], [0x61; 32]);
    let generation = handle.operator_generation();
    assert!(cancel_request(&mut state, &handle, &"ab".repeat(32)).is_err());
    assert!(
        cancel_request(&mut state, &handle, &tx_id).is_err(),
        "a confirmed transaction cannot be cancelled"
    );
    assert_eq!(handle.operator_generation(), generation);
    assert!(handle.cached_template_if_synced().is_some());
}

#[test]
fn expiring_conflicted_work_retires_no_build_or_template() {
    let (_dir, mut state) = chain(4);
    let handle = mining_handle();
    let deadline = crate::snapshot::unix_now_ms() + 1_000;
    let tx_id = queue_at_tip(
        &state,
        &handle,
        1,
        ergo_mining::private_queue::PrivateTransactionOptions {
            expires_at_ms: Some(deadline),
            ..Default::default()
        },
    );
    // Its input is not on the applied chain, so it cannot be selected.
    append_block(&mut state, vec![], 0);
    run_lifecycle(&mut state, &handle);
    assert_eq!(
        handle.private_queue().entry(&tx_id).unwrap().state,
        PrivateTransactionState::Conflicted
    );
    serve(&handle, &state, vec![], [0x61; 32]);
    let generation = handle.operator_generation();
    let remaining = deadline.saturating_sub(crate::snapshot::unix_now_ms());
    std::thread::sleep(std::time::Duration::from_millis(remaining + 10));
    run_lifecycle(&mut state, &handle);
    assert_eq!(
        handle.private_queue().entry(&tx_id).unwrap().state,
        PrivateTransactionState::Expired
    );
    assert_eq!(handle.operator_generation(), generation);
    assert!(handle.cached_template_if_synced().is_some());
}

// ----- failing durable expiry -----

#[test]
fn a_failing_expiry_write_withdraws_once_and_keeps_mining() {
    let (dir, mut state) = chain(4);
    let path = dir.path().join("queue.json");
    let handle = persisted_handle(&path);
    let deadline = crate::snapshot::unix_now_ms() + 1_000;
    let tx_id = queue_at_tip(
        &state,
        &handle,
        1,
        ergo_mining::private_queue::PrivateTransactionOptions {
            expires_at_ms: Some(deadline),
            ..Default::default()
        },
    );
    run_lifecycle(&mut state, &handle);
    // Hard enough that the nonce below is no solution for either template.
    let n_bits =
        ergo_ser::difficulty::encode_compact_bits(&(num_bigint::BigUint::from(1u8) << 200));
    serve_at(&handle, &state, vec![tx(1)], [0x61; 32], n_bits);
    serve_at(&handle, &state, vec![], [0x62; 32], n_bits);
    // Every later write of the queue fails.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let remaining = deadline.saturating_sub(crate::snapshot::unix_now_ms());
    std::thread::sleep(std::time::Duration::from_millis(remaining + 10));

    let generation = handle.operator_generation();
    for _ in 0..50 {
        run_lifecycle(&mut state, &handle);
    }
    assert_eq!(
        handle.operator_generation(),
        generation + 1,
        "elapsed work is withdrawn once, not on every pass"
    );
    assert_eq!(
        handle
            .inspect_template(Some([0x61; 32]), None)
            .unwrap()
            .status,
        "withdrawn"
    );
    assert_eq!(
        handle.cached_template_if_synced().expect("served").0.msg,
        [0x62; 32]
    );
    assert_eq!(
        handle.private_queue().entry(&tx_id).unwrap().state,
        PrivateTransactionState::Queued,
        "no input is released without a durable expiry"
    );
    assert_eq!(
        handle.private_queue().reserved_inputs(),
        std::collections::BTreeSet::from([[1; 32]])
    );

    // Solutions are still verified, not refused over the pending expiry.
    let (reply, mut response) = tokio::sync::oneshot::channel();
    let _ = crate::node::mining_dispatch::handle_mining_request(
        &mut state,
        Some(&handle),
        false,
        crate::mining_bridge::MiningRequest::SubmitSolution {
            solution: ergo_rest_json::mining::AutolykosSolutionJson {
                pk: None,
                w: None,
                n: "0000000000000000".into(),
                d: None,
            },
            reply,
        },
    );
    assert!(
        matches!(
            response.try_recv().unwrap(),
            Err(MiningApiError::InvalidPow)
        ),
        "the solution reached verification"
    );
    assert_eq!(handle.operator_generation(), generation + 1);

    // Once the disk recovers, the next retry commits the expiry.
    std::fs::remove_dir(&path).unwrap();
    state.private_mining.expiry_retry_at = None;
    run_lifecycle(&mut state, &handle);
    assert_eq!(
        handle.private_queue().entry(&tx_id).unwrap().state,
        PrivateTransactionState::Expired
    );
    assert!(handle.private_queue().reserved_inputs().is_empty());
    assert_eq!(handle.operator_generation(), generation + 1);
}

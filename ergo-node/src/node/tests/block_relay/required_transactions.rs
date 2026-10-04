// ----- required transactions never withhold work -----

/// A `sigmaProp(true)` genesis box: spendable with an empty proof.
fn spendable_box(seed: u8) -> ergo_ser::ergo_box::ErgoBox {
    use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
    let tree = ergo_ser::ergo_tree::ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
        reserved_header_bits: 0,
        constants: vec![],
        body: ergo_ser::opcode::Expr::Const {
            tpe: ergo_ser::sigma_type::SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        },
    };
    ergo_ser::ergo_box::ErgoBox {
        candidate: ergo_ser::ergo_box::ErgoBoxCandidate::new(
            1_000_000_000,
            tree,
            0,
            vec![],
            ergo_ser::register::AdditionalRegisters::empty(),
        )
        .unwrap(),
        transaction_id: ModifierId::from_bytes([seed; 32]),
        index: 0,
    }
}

/// A zero-fee transaction moving `input` to a box with the same script.
fn spend(input: &ergo_ser::ergo_box::ErgoBox) -> ergo_ser::transaction::Transaction {
    ergo_ser::transaction::Transaction {
        inputs: vec![ergo_ser::input::Input {
            box_id: input.box_id().unwrap(),
            spending_proof: ergo_ser::input::SpendingProof::new(
                Vec::new(),
                ergo_ser::input::ContextExtension::empty(),
            )
            .unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![input.candidate.clone()],
    }
}

/// `tx` as a pooled entry carrying its real identifiers.
fn pooled(tx: &ergo_ser::transaction::Transaction) -> ergo_mempool::Entry {
    let id = ergo_ser::transaction::transaction_id(tx).unwrap();
    let outputs = (0..tx.output_candidates.len())
        .map(|index| {
            ergo_ser::ergo_box::ErgoBox {
                candidate: tx.output_candidates[index].clone(),
                transaction_id: id,
                index: index as u16,
            }
            .box_id()
            .unwrap()
        })
        .collect();
    let mut writer = VlqWriter::new();
    ergo_ser::transaction::write_transaction(&mut writer, tx).unwrap();
    let bytes = writer.result();
    let size = bytes.len() as u32;
    ergo_mempool::Entry::new(
        ergo_mempool::TxId::from_bytes(*id.as_bytes()),
        bytes.into(),
        tx.inputs.iter().map(|i| i.box_id).collect(),
        outputs,
        vec![],
        0,
        0,
        size,
        20_000,
        ergo_mempool::TxSource::Api,
    )
}

/// Make `ids` the only policy requirements.
fn require(handle: &MiningHandle, ids: &[ergo_mempool::TxId]) {
    handle
        .set_policy(ergo_mining::policy::BlockPolicy {
            required_tx_ids: ids.iter().map(|id| hex::encode(id.as_bytes())).collect(),
            ..Default::default()
        })
        .unwrap();
}

/// Drive the production engine coordinator and build worker for one intent
/// on the applied tip, as the action loop signals it, and return the
/// templates published on that tip once one was built in `mode`
/// (`initial` or `enriched`). The coordinator always builds the minimal
/// template first and refreshes it only after that one is published.
async fn engine_publishes(
    state: &NodeState,
    handle: &MiningHandle,
    mempool: ergo_mempool::MempoolReadSnapshot,
    mode: &str,
) -> Vec<ergo_mining::inspection::InspectionSnapshot> {
    let (parent, height) = sync_handle_to_tip(state, handle);
    let (intent_tx, intent_rx) = tokio::sync::watch::channel(None);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (engine, worker) = super::spawn_engine_with_worker(
        state.store.as_utxo().unwrap().reader_handle(),
        handle.clone(),
        None,
        intent_rx,
        cancel_rx,
    );
    intent_tx
        .send(Some(ergo_mining::engine::BuildIntent {
            private_transactions: std::sync::Arc::new(Vec::new()),
            operator_generation: handle.operator_generation(),
            operator_owned: true,
            expected_parent: parent,
            expected_height: height,
            mempool: std::sync::Arc::new(mempool),
            miner_pk: MINER_PK,
            reason: BuildReason::Tip,
        }))
        .unwrap();
    let on_parent = || {
        handle
            .inspect_history()
            .into_iter()
            .filter(|s| s.template.candidate.parent_id == parent)
            .collect::<Vec<_>>()
    };
    let published = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let templates = on_parent();
            if templates
                .iter()
                .any(|s| s.template.candidate.observation.mode == mode)
            {
                return templates;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    cancel_tx.send(true).unwrap();
    engine.await.unwrap();
    tokio::task::spawn_blocking(move || worker.join())
        .await
        .unwrap()
        .unwrap();
    published.unwrap_or_else(|_| {
        panic!(
            "no {mode} template was published; templates on the tip: {:?}",
            on_parent()
                .iter()
                .map(|s| s.template.candidate.observation.mode)
                .collect::<Vec<_>>()
        )
    })
}

/// The newest template in `templates` built in `mode`.
fn built<'a>(
    templates: &'a [ergo_mining::inspection::InspectionSnapshot],
    mode: &str,
) -> &'a ergo_mining::engine::Template {
    &templates
        .iter()
        .find(|s| s.template.candidate.observation.mode == mode)
        .unwrap()
        .template
}

fn includes(template: &ergo_mining::engine::Template, id: ergo_mempool::TxId) -> bool {
    template.candidate.transactions.iter().any(|tx| {
        ergo_ser::transaction::transaction_id(tx)
            .unwrap()
            .as_bytes()
            == id.as_bytes()
    })
}

fn exclusion_reasons(
    template: &ergo_mining::engine::Template,
    id: ergo_mempool::TxId,
) -> Vec<&str> {
    template
        .candidate
        .observation
        .excluded
        .iter()
        .filter(|e| e.tx_id.as_bytes() == id.as_bytes())
        .map(|e| e.reason.as_str())
        .collect()
}

#[tokio::test]
async fn engine_publishes_a_satisfiable_requirement_after_the_initial_template() {
    let dir = tempfile::tempdir().unwrap();
    let input = spendable_box(0x31);
    let (state, handle) = devnet_node_with_boxes(dir.path(), std::slice::from_ref(&input));
    let required = pooled(&spend(&input));
    require(&handle, &[required.tx_id]);

    let templates = engine_publishes(
        &state,
        &handle,
        ergo_mempool::MempoolReadSnapshot::from_entries(vec![required.clone()]),
        "enriched",
    )
    .await;
    let initial = built(&templates, "initial");
    assert!(initial.candidate.observation.policy_requires_transactions);
    assert!(!includes(initial, required.tx_id));
    let enriched = built(&templates, "enriched");
    assert!(
        enriched.identity.template_seq > initial.identity.template_seq,
        "the requirement arrives with the enriched refresh of served work"
    );
    let first_user = &enriched.candidate.transactions[1];
    assert_eq!(
        ergo_ser::transaction::transaction_id(first_user)
            .unwrap()
            .as_bytes(),
        required.tx_id.as_bytes(),
        "the requirement is the first transaction after the emission"
    );
    assert!(enriched.candidate.observation.excluded.is_empty());
}

#[tokio::test]
async fn engine_keeps_mining_and_reports_an_unavailable_requirement() {
    let dir = tempfile::tempdir().unwrap();
    let input = spendable_box(0x32);
    let (state, handle) = devnet_node_with_boxes(dir.path(), std::slice::from_ref(&input));
    let public = pooled(&spend(&input));
    let missing = ergo_mempool::TxId::from_bytes([0xAB; 32]);
    require(&handle, &[missing]);

    let templates = engine_publishes(
        &state,
        &handle,
        ergo_mempool::MempoolReadSnapshot::from_entries(vec![public.clone()]),
        "enriched",
    )
    .await;
    let enriched = built(&templates, "enriched");
    assert!(includes(enriched, public.tx_id));
    assert_eq!(
        exclusion_reasons(enriched, missing),
        ["required_unavailable"]
    );
    assert_eq!(
        handle.policy().required_tx_ids,
        [hex::encode(missing.as_bytes())],
        "the requirement stays until the operator clears it"
    );
}

#[tokio::test]
async fn mined_requirement_does_not_stall_the_next_tip() {
    let dir = tempfile::tempdir().unwrap();
    let input = spendable_box(0x33);
    let (mut state, handle) = devnet_node_with_boxes(dir.path(), std::slice::from_ref(&input));
    let required = pooled(&spend(&input));
    state.mempool.pool_mut().insert(required.clone()).unwrap();
    require(&handle, &[required.tx_id]);

    // Mine the block that confirms the requirement.
    publish_candidate(&state, &handle);
    let served = handle.inspect_template(None, None).unwrap();
    assert!(includes(&served.template, required.tx_id));
    let mined = solve(&state, &handle, 0);
    submit_solution(&mut state, &handle, mined.nonce).unwrap();
    assert_eq!(state.store.chain_state_meta().best_full_block_id, mined.id);

    // The policy still names it and the pool has not caught up yet: the next
    // tip publishes its initial template and an enriched refresh that
    // reports the requirement instead of withholding work.
    let templates = engine_publishes(
        &state,
        &handle,
        ergo_mempool::MempoolReadSnapshot::from_pool(&state.mempool),
        "enriched",
    )
    .await;
    assert!(templates
        .iter()
        .all(|s| s.template.candidate.parent_id == mined.id));
    let enriched = built(&templates, "enriched");
    assert!(!includes(enriched, required.tx_id));
    assert_eq!(
        exclusion_reasons(enriched, required.tx_id),
        ["required_input_unavailable"]
    );
}

async fn check_requested_worker_disconnect(before_start: bool) {
    use crate::node::mining_engine::{run_build_worker, BuildRequest, REQUESTED_CANCEL_HOOK};
    use ergo_mining::engine::BuildIntent;
    let dir = tempfile::tempdir().unwrap();
    let (state, handle) = devnet_node(dir.path());
    let (parent, height) = sync_handle_to_tip(&state, &handle);
    let intent = BuildIntent {
        expected_parent: parent,
        expected_height: height,
        mempool: std::sync::Arc::new(ergo_mempool::MempoolReadSnapshot::empty()),
        private_transactions: std::sync::Arc::new(vec![]),
        operator_generation: handle.operator_generation(),
        operator_owned: true,
        miner_pk: MINER_PK,
        reason: BuildReason::Requested,
    };
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
    let (request_tx, request_rx) = std::sync::mpsc::channel();
    let (reply, response) = tokio::sync::oneshot::channel();
    request_tx
        .send(BuildRequest::requested(
            intent.clone(),
            vec![],
            vec![],
            reply,
            slots.clone().try_acquire_owned().unwrap(),
        ))
        .unwrap();
    let mut response = Some(response);
    if before_start {
        response.take();
    }
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let reader = state.store.as_utxo().unwrap().reader_handle();
    let worker_handle = handle.clone();
    let worker = std::thread::spawn(move || {
        let mut first_check = true;
        REQUESTED_CANCEL_HOOK.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move |pk| {
                if pk == MINER_PK && first_check {
                    first_check = false;
                    assert!(
                        !before_start,
                        "disconnected queued work must not start building"
                    );
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                }
            }))
        });
        run_build_worker(reader, worker_handle, None, false, request_rx);
    });
    if !before_start {
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        response.take();
        release_tx.send(()).unwrap();
    }
    // A different key prevents the follow-up from hiding an accidental publish
    // behind a requested cache hit. Its reply is also a worker-drain barrier.
    let mut follow_up = intent;
    follow_up.miner_pk[0] = 3;
    let (reply, response) = tokio::sync::oneshot::channel();
    request_tx
        .send(BuildRequest::requested(
            follow_up,
            vec![],
            vec![],
            reply,
            slots.clone().try_acquire_owned().unwrap(),
        ))
        .unwrap();
    drop(request_tx);
    let result = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(slots.available_permits(), 2);
    let history = handle.inspect_history();
    assert_eq!(history.len(), 1, "abandoned work must never publish");
    assert_ne!(history[0].template.work.pk, MINER_PK);
}

#[tokio::test]
async fn requested_worker_disconnect_before_build_releases_permit_without_build() {
    check_requested_worker_disconnect(true).await;
}

#[tokio::test]
async fn requested_worker_disconnect_during_build_cancels_and_releases_permit() {
    check_requested_worker_disconnect(false).await;
}

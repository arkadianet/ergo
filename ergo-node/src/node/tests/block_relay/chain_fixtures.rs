/// Copy a block using remote validation and peer-delivered sections.
fn copy_remote_block(source: &NodeState, target: &mut NodeState, id: [u8; 32]) {
    let bytes = source.store.get_header(&id).unwrap().unwrap();
    remote_header(target, &bytes);
    remote_sections(source, target, id, false);
}

/// Open a digest peer at the source's genesis root.
fn digest_peer(source: &mut NodeState, dir: &Path) -> NodeState {
    let spec = ergo_chain_spec::ChainSpec::devnet();
    std::fs::create_dir(dir.join("digest")).unwrap();
    let digest = ergo_state::DigestStateStore::open(
        &dir.join("digest/state.redb"),
        ergo_validation::scala_launch_for_network(spec.network),
        spec.voting,
        *source.store.as_utxo_mut().unwrap().root_digest().as_bytes(),
    )
    .unwrap();
    let mut state = make_state_with_backend(
        ergo_state::StateBackendKind::Digest(digest),
        crate::config::StateType::Digest,
        MempoolConfig {
            enabled: false,
            ..Default::default()
        },
    );
    state.executor = SyncExecutor::new(ProtocolParams::mainnet_default(), spec.difficulty);
    state
}

/// Store `header_bytes` through the executor's local header pipeline.
fn process_header(state: &mut NodeState, header_bytes: &[u8]) {
    let (_, actions) = state
        .executor
        .process_local_header(
            &mut state.store,
            &mut state.coordinator,
            header_bytes,
            Instant::now(),
        )
        .unwrap();
    flush_actions(state, actions);
}

/// Replace the candidate's ADProofs with bytes that hash to its header
/// root but are not the proof apply regenerates: a durable validation
/// verdict (`AdProofsHashMismatch`) that passes every header check.
fn replace_ad_proofs(candidate: &mut Candidate) {
    candidate.ad_proof_bytes = vec![1, 2, 3];
    candidate.header.ad_proofs_root = ergo_primitives::digest::Digest32::from_bytes(
        ergo_crypto::autolykos::common::blake2b256(&candidate.ad_proof_bytes),
    );
}

/// Declare a state root apply does not reach: apply fails the UTXO
/// state-root check (`StateError::DigestMismatch`), a failure without a
/// validation verdict, so the block is only session-marked.
fn replace_state_root(candidate: &mut Candidate) {
    candidate.header.state_root = ADDigest::from_bytes([7; 33]);
}

fn apply_failed(result: &Result<(), ergo_api::MiningApiError>) -> bool {
    matches!(result, Err(ergo_api::MiningApiError::Internal(reason)) if reason.starts_with("block apply failed"))
}

fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// Synthetic genesis isolates successful full-block application from PoW.
// The executor still parses sections and checks the resulting state root.
fn prepare_block(state: &mut NodeState, timestamp: u64) -> ([u8; 32], ExpectedSections) {
    let store = state.store.as_utxo_mut().unwrap();
    store.initialize_genesis(&[]).unwrap();
    let (_, bytes) = synthetic_header_with_state_root(1, store.root_digest());
    let mut header = read_header(&mut VlqReader::new(&bytes)).unwrap();
    header.timestamp = timestamp;
    let (bytes, id) = serialize_header(&header).unwrap();
    let id = *id.as_bytes();
    let sections = ExpectedSections::from_header(&id, &[0; 32], &[0; 32], &[0; 32]);
    store
        .store_validated_header(
            &id,
            &bytes,
            &ergo_state::chain::HeaderMeta {
                parent_id: [0; 32],
                height: 1,
                cumulative_score: vec![1],
                pow_validity: 1,
                timestamp,
            },
            Some((1, vec![1])),
        )
        .unwrap();
    let mut writer = VlqWriter::new();
    ergo_ser::block_transactions::write_block_transactions(
        &mut writer,
        &ergo_ser::block_transactions::BlockTransactions {
            header_id: ModifierId::from_bytes(id),
            transactions: vec![ergo_ser::transaction::Transaction {
                inputs: vec![],
                data_inputs: vec![],
                output_candidates: vec![],
            }],
        },
    )
    .unwrap();
    store
        .store_block_section_typed(&sections.transactions_id, &writer.result(), 102)
        .unwrap();
    let mut writer = VlqWriter::new();
    ergo_ser::extension::write_extension(
        &mut writer,
        &ergo_ser::extension::Extension {
            header_id: ModifierId::from_bytes(id),
            fields: vec![],
        },
    )
    .unwrap();
    store
        .store_block_section_typed(&sections.extension_id, &writer.result(), 108)
        .unwrap();
    (id, sections)
}

fn apply(state: &mut NodeState, id: [u8; 32]) -> Vec<Action> {
    let actions = state.executor.execute(
        Action::AssembleBlock { header_id: id },
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
    assert_eq!(state.store.chain_state_meta().best_full_block_id, id);
    actions
}

fn inventories(rx: &mut crate::peer_loop::outbound::Receiver) -> Inventory {
    let mut result = Vec::new();
    while let Ok(frame) = rx.try_recv() {
        assert_eq!(frame.code, message::CODE_INV);
        let inv = message::deserialize_inv(&frame.payload).unwrap();
        result.push((inv.type_id, inv.ids));
    }
    result
}

fn prepare_mainnet_catch_up(store: &mut ergo_state::store::StateStore) -> Vec<[u8; 32]> {
    use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
    use ergo_ser::extension::{write_extension, Extension, ExtensionField};
    use ergo_validation::popow::algos::{pack_interlinks, update_interlinks};
    store
        .initialize_genesis(&crate::genesis::mainnet_genesis_boxes())
        .unwrap();
    let headers: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../../../test-vectors/mainnet/headers_1_10.json"
    ))
    .unwrap();
    let txs: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../../../test-vectors/mainnet/transactions_1_10.json"
    ))
    .unwrap();
    let mut ids = Vec::new();
    let mut prev = None;
    let mut links = Vec::new();
    for height in 1..=10 {
        let row = &headers[height - 1];
        let bytes = hex::decode(row["bytes"].as_str().unwrap()).unwrap();
        let id: [u8; 32] = hex::decode(row["id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let header = read_header(&mut VlqReader::new(&bytes)).unwrap();
        if let Some(parent) = prev.as_ref() {
            links = update_interlinks(parent, &links).unwrap();
        }
        store
            .store_validated_header(
                &id,
                &bytes,
                &ergo_state::chain::HeaderMeta {
                    parent_id: *header.parent_id.as_bytes(),
                    height: header.height,
                    cumulative_score: vec![height as u8],
                    pow_validity: 1,
                    timestamp: header.timestamp,
                },
                Some((height as u32, vec![height as u8])),
            )
            .unwrap();
        let tx_row = txs
            .iter()
            .find(|t| t["height"].as_u64() == Some(height as u64))
            .unwrap();
        let tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(
            &hex::decode(tx_row["bytes"].as_str().unwrap()).unwrap(),
        ))
        .unwrap();
        let sections = ExpectedSections::from_header(
            &id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        );
        let mut w = VlqWriter::new();
        write_block_transactions(
            &mut w,
            &BlockTransactions {
                header_id: ModifierId::from_bytes(id),
                transactions: vec![tx],
            },
        )
        .unwrap();
        store
            .store_block_section_typed(&sections.transactions_id, &w.result(), 102)
            .unwrap();
        let mut w = VlqWriter::new();
        write_extension(
            &mut w,
            &Extension {
                header_id: ModifierId::from_bytes(id),
                fields: pack_interlinks(&links)
                    .into_iter()
                    .map(|(key, value)| ExtensionField {
                        key: key.try_into().unwrap(),
                        value,
                    })
                    .collect(),
            },
        )
        .unwrap();
        store
            .store_block_section_typed(&sections.extension_id, &w.result(), 108)
            .unwrap();
        ids.push(id);
        prev = Some(header);
    }
    ids
}

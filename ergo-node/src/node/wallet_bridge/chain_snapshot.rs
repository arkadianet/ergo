use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::Header;
use ergo_state::store::{CommittedSnapshot, StateError};
use ergo_validation::pre_header::CandidatePreHeader;
use ergo_validation::{ActiveProtocolParameters, ProtocolParams, ReemissionRuleInputs};
use ergo_wallet::tx_context::{BlockchainParameters, BlockchainStateContext};
use ergo_wallet_service::chain::CommittedTip;
use ergo_wallet_service::engine::{ChainAccessError, MempoolCandidate, SigningView};

/// A committed-state read failure, rendered exactly as the node has always
/// reported it (`chain state read failed: ...`).
pub(super) fn chain_state_read_failed(error: StateError) -> ChainAccessError {
    ChainAccessError::State(format!("chain state read failed: {error}"))
}

pub struct ChainSnapshot {
    committed: CommittedSnapshot,
    tip: CommittedTip,
    headers: Vec<Header>,
    header_ids: Vec<[u8; 32]>,
    state_context: BlockchainStateContext,
    /// The block after the tip as this node's mempool admits against it.
    candidate: Option<MempoolCandidate>,
    active_params: ActiveProtocolParameters,
    signing_params: BlockchainParameters,
    protocol_params: ProtocolParams,
    reemission: Option<ReemissionRuleInputs>,
    pool_outputs:
        std::sync::Arc<std::collections::HashMap<ergo_primitives::digest::Digest32, ErgoBox>>,
}

pub(super) fn decode_utxo_box(box_id: &[u8; 32], bytes: &[u8]) -> Result<ErgoBox, StateError> {
    let mut reader = VlqReader::new(bytes);
    let ergo_box = read_ergo_box(&mut reader)
        .map_err(|error| StateError::Serialization(format!("UTXO box decode: {error}")))?;
    if !reader.is_empty() {
        return Err(StateError::Serialization(
            "UTXO box has trailing bytes".to_string(),
        ));
    }
    let actual_id = ergo_box
        .box_id()
        .map_err(|error| StateError::Serialization(format!("UTXO box id: {error}")))?;
    if actual_id.as_bytes() != box_id {
        return Err(StateError::DbCorruption {
            table: "avl_nodes",
            key: hex::encode(box_id),
            reason: format!(
                "decoded box id {} does not match requested box id {}",
                hex::encode(actual_id.as_bytes()),
                hex::encode(box_id)
            ),
        });
    }
    Ok(ergo_box)
}

impl ChainSnapshot {
    /// Builds the signing view from one committed full-block snapshot.
    ///
    /// Contracts are signed against [`MempoolCandidate`], the block after the
    /// tip as the mempool predicts it (Scala's `simplifiedUpcoming()`), so a
    /// transaction that self-verifies is one this node admits. A script that
    /// reads pre-header fields can still evaluate differently in the block
    /// that finally includes it. `state_context` is the older synthetic
    /// successor (the tip's miner key and zero votes), kept for the wire
    /// spending context and the synthetic signing gate.
    pub fn from_committed(
        committed: CommittedSnapshot,
        reemission: Option<&ReemissionRuleInputs>,
    ) -> Result<Self, StateError> {
        let tip = CommittedTip::new(
            committed.best_full_block_height(),
            committed.best_full_block_id(),
        );
        let header_window = committed.last_ancestor_header_window_with_ids()?;
        let headers: Vec<Header> = header_window
            .iter()
            .map(|(header, _)| header.clone())
            .collect();
        let header_ids: Vec<[u8; 32]> = header_window
            .into_iter()
            .map(|(_, header_id)| header_id)
            .collect();
        let tip_header = headers.first().ok_or(StateError::InternalInvariant {
            what: "ChainSnapshot::from_committed: empty ancestor header window",
        })?;
        let active_params = committed.active_params()?;
        let validation_settings = committed.validation_settings()?;
        let signing_params = BlockchainParameters {
            max_block_cost: active_params.max_block_cost as u64,
            input_cost: active_params.input_cost as u64,
            data_input_cost: active_params.data_input_cost as u64,
            output_cost: active_params.output_cost as u64,
            token_access_cost: active_params.token_access_cost as u64,
            interpreter_init_cost: ergo_validation::INTERPRETER_INIT_COST,
            block_version: active_params.block_version,
        };
        let protocol_params =
            ProtocolParams::from_active_with_settings(&active_params, &validation_settings);
        let state_context = BlockchainStateContext {
            sigma_last_headers: headers.clone(),
            sigma_pre_header: CandidatePreHeader {
                version: tip_header.version,
                parent_id: tip.header_id,
                height: tip.height + 1,
                timestamp: tip_header.timestamp + 1,
                n_bits: tip_header.n_bits,
                votes: [0, 0, 0].into(),
                miner_pubkey: *tip_header.solution.pk().as_bytes(),
            },
            previous_state_digest: committed.state_root(),
        };
        let candidate = MempoolCandidate::new(
            &headers,
            &header_ids,
            committed.state_root(),
            active_params.block_version,
        );
        Ok(Self {
            committed,
            tip,
            headers,
            header_ids,
            state_context,
            candidate,
            active_params,
            signing_params,
            protocol_params,
            reemission: reemission.cloned(),
            pool_outputs: Default::default(),
        })
    }

    pub fn with_pool_outputs(
        mut self,
        outputs: std::sync::Arc<
            std::collections::HashMap<ergo_primitives::digest::Digest32, ErgoBox>,
        >,
    ) -> Self {
        self.pool_outputs = outputs;
        self
    }

    pub fn lookup_utxo(&self, box_id: &[u8; 32]) -> Result<Option<ErgoBox>, StateError> {
        let Some(bytes) = self.committed.lookup_box(box_id)? else {
            return Ok(self
                .pool_outputs
                .get(&ergo_primitives::digest::Digest32::from_bytes(*box_id))
                .cloned());
        };
        decode_utxo_box(box_id, &bytes).map(Some)
    }
}

impl SigningView for ChainSnapshot {
    fn intended_candidate_context(&self) -> Option<ergo_wallet::tx_context::SigningContext<'_>> {
        self.candidate
            .as_ref()
            .map(|candidate| candidate.signing_context(&self.protocol_params.validation_settings))
    }

    fn tip(&self) -> CommittedTip {
        self.tip.clone()
    }

    fn headers(&self) -> &[Header] {
        &self.headers
    }

    fn header_ids(&self) -> &[[u8; 32]] {
        &self.header_ids
    }

    fn state_context(&self) -> &BlockchainStateContext {
        &self.state_context
    }

    fn active_params(&self) -> &ActiveProtocolParameters {
        &self.active_params
    }

    fn signing_params(&self) -> &BlockchainParameters {
        &self.signing_params
    }

    fn protocol_params(&self) -> &ProtocolParams {
        &self.protocol_params
    }

    fn reemission_rules(&self) -> Option<&ReemissionRuleInputs> {
        self.reemission.as_ref()
    }

    fn lookup_utxo(&self, box_id: &[u8; 32]) -> Result<Option<ErgoBox>, ChainAccessError> {
        ChainSnapshot::lookup_utxo(self, box_id)
            .map_err(|error| ChainAccessError::State(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::serialize_header;
    use ergo_state::store::StateStore;
    use ergo_wallet_service::engine::WalletChainAccess;

    fn header(height: u32, parent: ModifierId) -> Header {
        Header {
            version: 2,
            parent_id: parent,
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 1_000_000 + height as u64,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 16842752,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
                nonce: [0; 8],
            },
        }
    }

    fn apply_headers(store: &mut StateStore, count: u32) -> (ModifierId, [u8; 32]) {
        let mut parent = ModifierId::from_bytes([0; 32]);
        let mut tip = [0; 32];
        for height in 1..=count {
            let (bytes, id) = serialize_header(&header(height, parent)).unwrap();
            tip = *id.as_bytes();
            store.store_header(&tip, &bytes).unwrap();
            let root = store.root_digest();
            store
                .apply_block_unchecked_for_test(height, &tip, &root, &[])
                .unwrap();
            parent = id;
        }
        (parent, tip)
    }

    fn snapshot_with_boxes(boxes: Vec<([u8; 32], Vec<u8>)>) -> (tempfile::TempDir, ChainSnapshot) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&boxes).unwrap();
        apply_headers(&mut store, 5);
        let reader = ergo_state::reader::ChainStoreReader::new_from_db(store.db_arc());
        let accessor = super::super::ChainStateAccessorImpl::chain_only(reader, false, None);
        let snapshot = accessor.chain_snapshot().unwrap();
        (dir, snapshot)
    }

    fn valid_box_bytes() -> ([u8; 32], Vec<u8>) {
        let tree = ergo_ser::ergo_tree::ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            reserved_header_bits: 0,
            constants: vec![(
                ergo_ser::sigma_type::SigmaType::SBoolean,
                ergo_ser::sigma_value::SigmaValue::Boolean(true),
            )],
            body: ergo_ser::opcode::Expr::Const {
                tpe: ergo_ser::sigma_type::SigmaType::SBoolean,
                val: ergo_ser::sigma_value::SigmaValue::Boolean(true),
            },
        };
        let candidate = ergo_ser::ergo_box::ErgoBoxCandidate::new(
            1_000_000,
            tree,
            1,
            Vec::new(),
            ergo_ser::register::AdditionalRegisters::empty(),
        )
        .unwrap();
        let ergo_box = ergo_ser::ergo_box::ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes([7; 32]),
            index: 0,
        };
        let box_id = *ergo_box.box_id().unwrap().as_bytes();
        let bytes = ergo_ser::ergo_box::serialize_ergo_box(&ergo_box).unwrap();
        (box_id, bytes)
    }

    #[test]
    fn snapshot_supports_short_chain_with_five_headers() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        apply_headers(&mut store, 5);
        let reader = ergo_state::reader::ChainStoreReader::new_from_db(store.db_arc());
        let accessor = super::super::ChainStateAccessorImpl::chain_only(reader, false, None);
        let snapshot = accessor.chain_snapshot().unwrap();
        assert_eq!(snapshot.tip().height, 5);
        assert_eq!(snapshot.headers().len(), 5);
        assert_eq!(snapshot.headers()[0].height, 5);
    }

    #[test]
    fn snapshot_lookup_distinguishes_absent_from_invalid_box_bytes() {
        let invalid_id = [0x77; 32];
        let (_dir, snapshot) = snapshot_with_boxes(vec![(invalid_id, vec![0x01, 0x02])]);

        assert!(matches!(snapshot.lookup_utxo(&[0x78; 32]), Ok(None)));
        assert!(matches!(
            snapshot.lookup_utxo(&invalid_id),
            Err(StateError::Serialization(_))
        ));
    }

    #[test]
    fn snapshot_lookup_rejects_trailing_bytes_and_box_id_mismatch() {
        let (box_id, bytes) = valid_box_bytes();
        let mut trailing = bytes.clone();
        trailing.push(0xAA);
        let (_dir, snapshot) = snapshot_with_boxes(vec![(box_id, trailing), ([0x99; 32], bytes)]);

        assert!(matches!(
            snapshot.lookup_utxo(&box_id),
            Err(StateError::Serialization(message)) if message.contains("trailing")
        ));
        assert!(matches!(
            snapshot.lookup_utxo(&[0x99; 32]),
            Err(StateError::DbCorruption { .. })
        ));
    }

    #[test]
    fn snapshot_stale_after_committed_tip_moves() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        let (parent, _) = apply_headers(&mut store, 11);
        let reader = ergo_state::reader::ChainStoreReader::new_from_db(store.db_arc());
        let accessor = super::super::ChainStateAccessorImpl::chain_only(reader, false, None);
        let snapshot = accessor.chain_snapshot().unwrap();
        assert_eq!(snapshot.tip().height, 11);
        assert_eq!(snapshot.headers()[0].height, 11);

        let (bytes, id) = serialize_header(&header(12, parent)).unwrap();
        let id_bytes = *id.as_bytes();
        store.store_header(&id_bytes, &bytes).unwrap();
        let root = store.root_digest();
        store
            .apply_block_unchecked_for_test(12, &id_bytes, &root, &[])
            .unwrap();

        assert!(matches!(
            accessor.ensure_view_current(&snapshot),
            Err(ChainAccessError::StaleTip { .. })
        ));
    }
    #[test]
    fn node_contexts_retain_cumulative_statuses_after_an_empty_epoch_and_reopen() {
        use ergo_validation::{ErgoValidationSettingsUpdate, RuleStatus};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.redb");
        let mut store = StateStore::open(&path)
            .unwrap()
            .with_non_durable_commits_for_test();
        store.initialize_genesis(&[]).unwrap();
        let mut parent = ModifierId::from_bytes([0; 32]);
        // Unchecked synthetic persistence transitions exercise the node's
        // consumers. The pinned JVM context fixture in ergo-validation owns
        // the independent cumulative-settings semantics, not a chain verdict.
        for height in 1..=2048 {
            let mut synthetic_header = header(height, parent);
            // Match the unchecked helper's synthesized HEADER_META timestamp
            // so normal startup hydration still performs its integrity checks.
            synthetic_header.timestamp = 1_700_000_000 + u64::from(height);
            let (bytes, id) = serialize_header(&synthetic_header).unwrap();
            store.store_header(id.as_bytes(), &bytes).unwrap();
            let voted = height.is_multiple_of(1024).then(|| {
                let mut row = ergo_validation::scala_launch();
                row.epoch_start_height = height;
                row.activated_update = if height == 1024 {
                    ErgoValidationSettingsUpdate {
                        rules_to_disable: vec![215],
                        status_updates: vec![
                            (1007, RuleStatus::Disabled),
                            (1008, RuleStatus::Changed(vec![10, 11])),
                        ],
                    }
                } else {
                    ErgoValidationSettingsUpdate::empty()
                };
                row
            });
            let root = store.root_digest();
            store
                .apply_block_unchecked_for_test_with_voted_params(
                    height,
                    id.as_bytes(),
                    &root,
                    &[],
                    voted,
                )
                .unwrap();
            parent = id;
        }

        fn check(store: StateStore) {
            use ergo_sigma::evaluator::{RuleStatus as Sigma, SigmaValidationSettings};
            use ergo_state::ChainStateRead;
            let mut node = crate::node::tests::make_state_with_store(store);
            node.executor.hydrate_block_context(&node.store).unwrap();
            assert!(node
                .store
                .active_params()
                .activated_update
                .status_updates
                .is_empty());
            let expected = SigmaValidationSettings(
                [
                    (1007, Sigma::Disabled),
                    (1008, Sigma::Changed(vec![10, 11])),
                ]
                .into_iter()
                .collect(),
            );
            let live = crate::node::tip_context::build_tip_context(&node).unwrap();
            assert_eq!(live.tip.height, 2048);
            assert_eq!(live.params.validation_settings, expected);

            let accessor = super::super::ChainStateAccessorImpl::chain_only(
                ergo_state::reader::ChainStoreReader::new_from_db(
                    node.store.as_utxo().unwrap().db_arc(),
                ),
                false,
                None,
            );
            let signing = accessor.chain_snapshot().unwrap();
            assert_eq!(signing.tip().height, 2048);
            assert_eq!(signing.protocol_params().validation_settings, expected);
        }

        check(store);
        check(StateStore::open(&path).unwrap());
    }
    fn pool_test_engine(
        storage: std::sync::Arc<parking_lot::RwLock<ergo_wallet::storage::SecretStorage>>,
        state: std::sync::Arc<parking_lot::RwLock<ergo_wallet_service::state::WalletState>>,
        db: std::sync::Arc<redb::Database>,
        chain: std::sync::Arc<dyn ergo_wallet_service::engine::WalletChainAccess>,
        mempool: std::sync::Arc<dyn ergo_wallet_service::engine::MempoolOverlay>,
        submitter: std::sync::Arc<dyn ergo_wallet_service::engine::TxSubmitter>,
    ) -> ergo_wallet_service::engine::WalletEngine {
        use ergo_wallet_service::engine::{
            RescanCoordinator, StoreCursorChain, WalletEngine, WalletEngineConfig,
            WalletEngineParts,
        };
        let store: std::sync::Arc<dyn ergo_wallet_service::WalletStore> =
            std::sync::Arc::new(ergo_wallet_service::RedbWalletStore::new(db));
        WalletEngine::new(WalletEngineParts {
            storage,
            state,
            store: store.clone(),
            // The node's accessor carries no wallet; the cursor comes from
            // the wallet store, as in the daemon.
            chain: std::sync::Arc::new(StoreCursorChain::new(chain, store)),
            mempool,
            submitter,
            service: None,
            rescan: std::sync::Arc::new(RescanCoordinator::new()),
            config: WalletEngineConfig {
                network: ergo_ser::address::NetworkPrefix::Mainnet,
                expose_private_keys: false,
                reemission: None,
                min_relay_fee_nano_erg: 1_000_000,
                max_tx_size_bytes: 100_000,
            },
        })
    }

    struct NoPoolSubmit;
    #[async_trait::async_trait]
    impl ergo_wallet_service::engine::TxSubmitter for NoPoolSubmit {
        async fn submit_transaction(
            &self,
            _: Vec<u8>,
        ) -> Result<String, ergo_wallet_service::engine::TxSubmitError> {
            panic!("sign-only test must not submit")
        }
    }

    #[tokio::test]
    async fn captured_pool_parents_survive_removal_and_committed_boxes_take_precedence() {
        use ergo_ser::ergo_box::serialize_ergo_box;
        use std::{collections::HashMap, sync::Arc};

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/wallet/native_mint_burn_scala.json"
        ))
        .unwrap();
        let committed_bytes = hex::decode(fixture["input_hex"].as_str().unwrap()).unwrap();
        let committed_box = read_ergo_box(&mut VlqReader::new(&committed_bytes)).unwrap();
        let committed_id = committed_box.box_id().unwrap();
        let mut pool_parent = committed_box.clone();
        pool_parent.transaction_id = ModifierId::from_bytes([0x42; 32]);
        let pool_id = pool_parent.box_id().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&directory.path().join("state.redb")).unwrap();
        store
            .initialize_genesis(&[(*committed_id.as_bytes(), committed_bytes)])
            .unwrap();
        apply_headers(&mut store, 5);
        let accessor = super::super::ChainStateAccessorImpl::chain_only(
            ergo_state::reader::ChainStoreReader::new_from_db(store.db_arc()),
            false,
            None,
        );
        // A conflicting overlay value must never override an authoritative UTXO.
        let mut outputs = HashMap::from([
            (pool_id, pool_parent.clone()),
            (committed_id, pool_parent.clone()),
        ]);
        let captured = accessor
            .chain_snapshot()
            .unwrap()
            .with_pool_outputs(Arc::new(outputs.clone()));
        outputs.clear();
        let later = accessor
            .chain_snapshot()
            .unwrap()
            .with_pool_outputs(Arc::new(outputs));
        assert!(later.lookup_utxo(pool_id.as_bytes()).unwrap().is_none());
        assert_eq!(
            serialize_ergo_box(&captured.lookup_utxo(pool_id.as_bytes()).unwrap().unwrap())
                .unwrap(),
            serialize_ergo_box(&pool_parent).unwrap()
        );
        assert_eq!(
            serialize_ergo_box(
                &captured
                    .lookup_utxo(committed_id.as_bytes())
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            serialize_ergo_box(&committed_box).unwrap()
        );
        accessor.ensure_view_current(&captured).unwrap();

        // Native signing must resolve the same unconfirmed parent and run its
        // normal proof/self-verification gates, even with a locked wallet.
        struct PoolView(Arc<HashMap<Digest32, ErgoBox>>);
        impl ergo_wallet_service::engine::MempoolOverlay for PoolView {
            fn is_spent_by_pool(&self, _: &Digest32) -> bool {
                false
            }
            fn pool_spending_tx(&self, _: &Digest32) -> Option<Digest32> {
                None
            }
            fn pool_outputs(&self) -> Arc<HashMap<Digest32, ErgoBox>> {
                self.0.clone()
            }
        }
        use ergo_wallet_protocol::native::dto::{ExternalSecret, SignTxRequest, TxRepr};
        let unsigned = ergo_ser::transaction::UnsignedTransaction {
            inputs: vec![ergo_ser::input::UnsignedInput {
                box_id: pool_id,
                extension: ergo_ser::input::ContextExtension::empty(),
            }],
            data_inputs: vec![],
            output_candidates: vec![pool_parent.candidate.clone()],
        };
        let mut writer = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::transaction::write_unsigned_transaction(&mut writer, &unsigned).unwrap();
        let request = SignTxRequest {
            unsigned_transaction: TxRepr::from_bytes(&writer.result()),
            external_secrets: vec![ExternalSecret::Dlog {
                secret: format!("{:064x}", 1),
            }],
        };
        let storage = parking_lot::RwLock::new(ergo_wallet::storage::SecretStorage::open(
            directory.path().join("wallet"),
        ));
        let wallet =
            parking_lot::RwLock::new(ergo_wallet_service::state::WalletState::empty(false));
        let db = store.db_arc();
        let pool = PoolView(Arc::new(HashMap::from([(pool_id, pool_parent)])));
        let engine = pool_test_engine(
            std::sync::Arc::new(storage),
            std::sync::Arc::new(wallet),
            db,
            std::sync::Arc::new(accessor),
            std::sync::Arc::new(pool),
            std::sync::Arc::new(NoPoolSubmit),
        );
        let signed = engine.native_sign_transaction(request).unwrap();
        let bytes = hex::decode(signed.signed_transaction.bytes_hex()).unwrap();
        let transaction =
            ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        assert_eq!(transaction.inputs[0].box_id, pool_id);
        assert_eq!(transaction.output_candidates, unsigned.output_candidates);
        assert_eq!(
            hex::encode(
                ergo_ser::transaction::transaction_id(&transaction)
                    .unwrap()
                    .as_bytes()
            ),
            signed.tx_id
        );
    }

    #[tokio::test]
    async fn intent_send_reuses_selection_pool_snapshot_for_signing() {
        use ergo_ser::{address::NetworkPrefix, ergo_box::serialize_ergo_box};
        use ergo_state::wallet::{
            tables::WALLET_BOXES,
            types::{BoxProvenance, BoxStatus, WalletBox},
        };
        use ergo_wallet_protocol::native::dto::{InputSource, SendTxRequest, TxIntent};
        use std::{
            collections::{HashMap, HashSet},
            sync::{
                atomic::{AtomicUsize, Ordering},
                Arc, Mutex,
            },
        };

        struct ChangingPool {
            first: ergo_wallet_service::engine::mempool::MempoolBoxSnapshot,
            captures: AtomicUsize,
            committed_id: Digest32,
        }
        impl ergo_wallet_service::engine::MempoolOverlay for ChangingPool {
            fn is_spent_by_pool(&self, _: &Digest32) -> bool {
                panic!("intent send must use the coherent box snapshot");
            }
            fn pool_spending_tx(&self, _: &Digest32) -> Option<Digest32> {
                panic!("intent send must use the coherent box snapshot");
            }
            fn pool_outputs(&self) -> Arc<HashMap<Digest32, ErgoBox>> {
                panic!("intent send must use the coherent box snapshot");
            }
            fn box_snapshot(
                &self,
                committed_ids: &[Digest32],
            ) -> ergo_wallet_service::engine::mempool::MempoolBoxSnapshot {
                if self.captures.fetch_add(1, Ordering::SeqCst) == 0 {
                    // Capturing before the wallet IDs are known would miss spent
                    // committed inputs in implementations using the trait default.
                    assert!(committed_ids.contains(&self.committed_id));
                    self.first.clone()
                } else {
                    // The parent is evicted immediately after selection. A fresh
                    // capture during signing can no longer resolve this input.
                    ergo_wallet_service::engine::mempool::MempoolBoxSnapshot {
                        outputs: Arc::new(HashMap::new()),
                        spent_box_ids: HashSet::new(),
                    }
                }
            }
        }

        #[derive(Default)]
        struct RecordingSubmitter(Mutex<Vec<Vec<u8>>>);
        #[async_trait::async_trait]
        impl ergo_wallet_service::engine::TxSubmitter for RecordingSubmitter {
            async fn submit_transaction(
                &self,
                bytes: Vec<u8>,
            ) -> Result<String, ergo_wallet_service::engine::TxSubmitError> {
                let transaction =
                    ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
                let id = ergo_ser::transaction::transaction_id(&transaction).unwrap();
                self.0.lock().unwrap().push(bytes);
                Ok(hex::encode(id.as_bytes()))
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&directory.path().join("state.redb")).unwrap();
        let db = store.db_arc();
        let mut storage =
            ergo_wallet::storage::SecretStorage::open(directory.path().join("wallet"));
        storage
            .restore(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "",
                "test",
                false,
            )
            .unwrap();
        let mut wallet = ergo_wallet_service::state::WalletState::empty(false);
        ergo_wallet_service::engine::WalletBootService::unlock_and_sync(
            &mut storage,
            &mut wallet,
            &ergo_wallet_service::RedbWalletStore::new(db.clone()),
            NetworkPrefix::Mainnet,
            "test",
        )
        .unwrap();
        let address = wallet.change_address().unwrap().to_owned();
        let pubkey =
            ergo_ser::address::decode_p2pk_address(&address, NetworkPrefix::Mainnet).unwrap();
        let tree_bytes = ergo_ser::address::build_p2pk_tree_bytes(&pubkey).unwrap();
        let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&tree_bytes)).unwrap();
        let pool_parent = ErgoBox {
            candidate: ergo_ser::ergo_box::ErgoBoxCandidate::new(
                10_000_000,
                tree,
                1,
                vec![],
                Default::default(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([0x42; 32]),
            index: 0,
        };
        let pool_id = pool_parent.box_id().unwrap();
        let mut committed_box = pool_parent.clone();
        committed_box.transaction_id = ModifierId::from_bytes([0x43; 32]);
        committed_box.candidate.value = 100_000_000;
        let committed_id = committed_box.box_id().unwrap();
        store
            .initialize_genesis(&[(
                *committed_id.as_bytes(),
                serialize_ergo_box(&committed_box).unwrap(),
            )])
            .unwrap();
        apply_headers(&mut store, 5);
        let accessor = super::super::ChainStateAccessorImpl::chain_only(
            ergo_state::reader::ChainStoreReader::new_from_db(db.clone()),
            false,
            None,
        );
        assert!(accessor
            .chain_snapshot()
            .unwrap()
            .lookup_utxo(pool_id.as_bytes())
            .unwrap()
            .is_none());
        let record = WalletBox {
            box_id: *committed_id.as_bytes(),
            creation_tx_id: *committed_box.transaction_id.as_bytes(),
            creation_output_index: committed_box.index,
            creation_height: 1,
            value: committed_box.candidate.value,
            assets: vec![],
            status: BoxStatus::Confirmed,
            provenance: BoxProvenance::Owned,
        };
        let write = db.begin_write().unwrap();
        write
            .open_table(WALLET_BOXES)
            .unwrap()
            .insert(record.box_id, bincode::serialize(&record).unwrap())
            .unwrap();
        write.commit().unwrap();

        let pool = ChangingPool {
            first: ergo_wallet_service::engine::mempool::MempoolBoxSnapshot {
                outputs: Arc::new(HashMap::from([(pool_id, pool_parent)])),
                spent_box_ids: HashSet::from([committed_id]),
            },
            captures: AtomicUsize::new(0),
            committed_id,
        };
        let mut intent: TxIntent = serde_json::from_value(serde_json::json!({
            "outputs": [{"type": "payment", "address": address, "value": "2000000"}]
        }))
        .unwrap();
        intent.inputs = InputSource::Auto {
            min_confirmations: -1,
            exclude_box_ids: vec![],
        };
        let submitter = Arc::new(RecordingSubmitter::default());
        let pool = Arc::new(pool);
        let engine = pool_test_engine(
            Arc::new(parking_lot::RwLock::new(storage)),
            Arc::new(parking_lot::RwLock::new(wallet)),
            db,
            Arc::new(accessor),
            pool.clone(),
            submitter.clone(),
        );
        let response = engine
            .native_send_transaction(SendTxRequest::Intent {
                intent,
                delivery: Default::default(),
                private_options: None,
            })
            .await
            .unwrap();

        assert!(response.accepted);
        assert_eq!(pool.captures.load(Ordering::SeqCst), 1);
        let submitted = submitter.0.lock().unwrap();
        assert_eq!(submitted.len(), 1);
        let transaction =
            ergo_ser::transaction::read_transaction(&mut VlqReader::new(&submitted[0])).unwrap();
        assert_eq!(transaction.inputs.len(), 1);
        assert_eq!(transaction.inputs[0].box_id, pool_id);
        assert!(!transaction.inputs[0].spending_proof.proof.is_empty());
        assert_eq!(
            hex::encode(
                ergo_ser::transaction::transaction_id(&transaction)
                    .unwrap()
                    .as_bytes()
            ),
            response.tx_id
        );
    }

    /// 0-conf chaining on the compat route: `/wallet/transaction/send` with an
    /// explicit input that is the wallet's own unconfirmed output builds,
    /// signs (resolving the parent from the same pool snapshot) and submits.
    /// The same box already spent by a pending transaction is refused.
    #[tokio::test]
    async fn compat_send_chains_off_a_named_unconfirmed_wallet_output() {
        use ergo_ser::{address::NetworkPrefix, ergo_box::serialize_ergo_box};
        use ergo_wallet_protocol::scala::sending::{PaymentRequestDto, TransactionSendRequest};
        use ergo_wallet_protocol::WalletAdminError;
        use std::{
            collections::{HashMap, HashSet},
            sync::{Arc, Mutex},
        };

        struct Pool(Mutex<ergo_wallet_service::engine::mempool::MempoolBoxSnapshot>);
        impl ergo_wallet_service::engine::MempoolOverlay for Pool {
            fn is_spent_by_pool(&self, id: &Digest32) -> bool {
                self.0.lock().unwrap().spent_box_ids.contains(id)
            }
            fn pool_spending_tx(&self, _: &Digest32) -> Option<Digest32> {
                None
            }
            fn pool_outputs(&self) -> Arc<HashMap<Digest32, ErgoBox>> {
                self.0.lock().unwrap().outputs.clone()
            }
            fn box_snapshot(
                &self,
                _: &[Digest32],
            ) -> ergo_wallet_service::engine::mempool::MempoolBoxSnapshot {
                self.0.lock().unwrap().clone()
            }
        }

        #[derive(Default)]
        struct RecordingSubmitter(Mutex<Vec<Vec<u8>>>);
        #[async_trait::async_trait]
        impl ergo_wallet_service::engine::TxSubmitter for RecordingSubmitter {
            async fn submit_transaction(
                &self,
                bytes: Vec<u8>,
            ) -> Result<String, ergo_wallet_service::engine::TxSubmitError> {
                let transaction =
                    ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
                let id = ergo_ser::transaction::transaction_id(&transaction).unwrap();
                self.0.lock().unwrap().push(bytes);
                Ok(hex::encode(id.as_bytes()))
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&directory.path().join("state.redb")).unwrap();
        let db = store.db_arc();
        let mut storage =
            ergo_wallet::storage::SecretStorage::open(directory.path().join("wallet"));
        storage
            .restore(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "",
                "test",
                false,
            )
            .unwrap();
        let mut wallet = ergo_wallet_service::state::WalletState::empty(false);
        ergo_wallet_service::engine::WalletBootService::unlock_and_sync(
            &mut storage,
            &mut wallet,
            &ergo_wallet_service::RedbWalletStore::new(db.clone()),
            NetworkPrefix::Mainnet,
            "test",
        )
        .unwrap();
        let address = wallet.change_address().unwrap().to_owned();
        let pubkey =
            ergo_ser::address::decode_p2pk_address(&address, NetworkPrefix::Mainnet).unwrap();
        let tree_bytes = ergo_ser::address::build_p2pk_tree_bytes(&pubkey).unwrap();
        let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&tree_bytes)).unwrap();
        // The change output of a transaction the wallet just sent: in the pool,
        // not in the UTXO set.
        let change = ErgoBox {
            candidate: ergo_ser::ergo_box::ErgoBoxCandidate::new(
                10_000_000,
                tree,
                1,
                vec![],
                Default::default(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([0x44; 32]),
            index: 1,
        };
        let change_id = change.box_id().unwrap();
        let mut unrelated = change.clone();
        unrelated.transaction_id = ModifierId::from_bytes([0x45; 32]);
        let unrelated_id = unrelated.box_id().unwrap();
        store
            .initialize_genesis(&[(
                *unrelated_id.as_bytes(),
                serialize_ergo_box(&unrelated).unwrap(),
            )])
            .unwrap();
        apply_headers(&mut store, 5);
        let accessor = super::super::ChainStateAccessorImpl::chain_only(
            ergo_state::reader::ChainStoreReader::new_from_db(db.clone()),
            false,
            None,
        );
        assert!(accessor
            .chain_snapshot()
            .unwrap()
            .lookup_utxo(change_id.as_bytes())
            .unwrap()
            .is_none());
        let pool = Arc::new(Pool(Mutex::new(
            ergo_wallet_service::engine::mempool::MempoolBoxSnapshot {
                outputs: Arc::new(HashMap::from([(change_id, change)])),
                spent_box_ids: HashSet::new(),
            },
        )));
        let submitter = Arc::new(RecordingSubmitter::default());
        let engine = pool_test_engine(
            Arc::new(parking_lot::RwLock::new(storage)),
            Arc::new(parking_lot::RwLock::new(wallet)),
            db,
            Arc::new(accessor),
            pool.clone(),
            submitter.clone(),
        );
        let request = || TransactionSendRequest {
            requests: vec![PaymentRequestDto {
                address: address.clone(),
                value: 2_000_000,
                assets: vec![],
            }],
            inputs: Some(vec![hex::encode(change_id.as_bytes())]),
            data_inputs: None,
            fee: None,
        };

        let tx_id = engine.transaction_send(request()).await.unwrap();
        let submitted = submitter.0.lock().unwrap().clone();
        assert_eq!(submitted.len(), 1);
        let transaction =
            ergo_ser::transaction::read_transaction(&mut VlqReader::new(&submitted[0])).unwrap();
        assert_eq!(transaction.inputs.len(), 1);
        assert_eq!(transaction.inputs[0].box_id, change_id);
        assert!(!transaction.inputs[0].spending_proof.proof.is_empty());
        assert_eq!(
            hex::encode(
                ergo_ser::transaction::transaction_id(&transaction)
                    .unwrap()
                    .as_bytes()
            ),
            tx_id
        );

        // Once a pending transaction spends it, naming it again is a double spend.
        pool.0.lock().unwrap().spent_box_ids.insert(change_id);
        assert!(matches!(
            engine.transaction_send(request()).await,
            Err(WalletAdminError::BadRequest(m)) if m.contains("already spent by a pending transaction")
        ));
        assert_eq!(submitter.0.lock().unwrap().len(), 1);
    }

    /// Compat `/wallet/transaction/sign` for a transaction spending an
    /// unconfirmed output. It used to answer 500 ("input 0 box … not found in
    /// UTXO set"): the route ignored the caller's `inputs` box bytes and
    /// resolved inputs from the committed UTXO set only. It now resolves from
    /// the pool, as the native sign does, and from supplied serialized boxes.
    #[tokio::test]
    async fn compat_sign_spends_an_unconfirmed_parent_from_the_pool_or_supplied_bytes() {
        use ergo_ser::{address::NetworkPrefix, ergo_box::serialize_ergo_box};
        use ergo_wallet_protocol::scala::sending::{TransactionSignRequest, UnsignedTxDto};
        use ergo_wallet_protocol::WalletAdminError;
        use std::{
            collections::{HashMap, HashSet},
            sync::{Arc, Mutex},
        };

        struct Pool(Mutex<ergo_wallet_service::engine::mempool::MempoolBoxSnapshot>);
        impl ergo_wallet_service::engine::MempoolOverlay for Pool {
            fn is_spent_by_pool(&self, id: &Digest32) -> bool {
                self.0.lock().unwrap().spent_box_ids.contains(id)
            }
            fn pool_spending_tx(&self, _: &Digest32) -> Option<Digest32> {
                None
            }
            fn pool_outputs(&self) -> Arc<HashMap<Digest32, ErgoBox>> {
                self.0.lock().unwrap().outputs.clone()
            }
            fn box_snapshot(
                &self,
                _: &[Digest32],
            ) -> ergo_wallet_service::engine::mempool::MempoolBoxSnapshot {
                self.0.lock().unwrap().clone()
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&directory.path().join("state.redb")).unwrap();
        let db = store.db_arc();
        let mut storage =
            ergo_wallet::storage::SecretStorage::open(directory.path().join("wallet"));
        storage
            .restore(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "",
                "test",
                false,
            )
            .unwrap();
        let mut wallet = ergo_wallet_service::state::WalletState::empty(false);
        ergo_wallet_service::engine::WalletBootService::unlock_and_sync(
            &mut storage,
            &mut wallet,
            &ergo_wallet_service::RedbWalletStore::new(db.clone()),
            NetworkPrefix::Mainnet,
            "test",
        )
        .unwrap();
        let address = wallet.change_address().unwrap().to_owned();
        let pubkey =
            ergo_ser::address::decode_p2pk_address(&address, NetworkPrefix::Mainnet).unwrap();
        let tree_bytes = ergo_ser::address::build_p2pk_tree_bytes(&pubkey).unwrap();
        let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&tree_bytes)).unwrap();
        // The change of a transaction still in the pool.
        let change = ErgoBox {
            candidate: ergo_ser::ergo_box::ErgoBoxCandidate::new(
                10_000_000,
                tree,
                1,
                vec![],
                Default::default(),
            )
            .unwrap(),
            transaction_id: ModifierId::from_bytes([0x46; 32]),
            index: 1,
        };
        let change_id = change.box_id().unwrap();
        let mut unrelated = change.clone();
        unrelated.transaction_id = ModifierId::from_bytes([0x47; 32]);
        store
            .initialize_genesis(&[(
                *unrelated.box_id().unwrap().as_bytes(),
                serialize_ergo_box(&unrelated).unwrap(),
            )])
            .unwrap();
        apply_headers(&mut store, 5);
        let accessor = super::super::ChainStateAccessorImpl::chain_only(
            ergo_state::reader::ChainStoreReader::new_from_db(db.clone()),
            false,
            None,
        );
        let pool = Arc::new(Pool(Mutex::new(
            ergo_wallet_service::engine::mempool::MempoolBoxSnapshot {
                outputs: Arc::new(HashMap::new()),
                spent_box_ids: HashSet::new(),
            },
        )));
        let engine = pool_test_engine(
            Arc::new(parking_lot::RwLock::new(storage)),
            Arc::new(parking_lot::RwLock::new(wallet)),
            db,
            Arc::new(accessor),
            pool.clone(),
            Arc::new(NoPoolSubmit),
        );
        let unsigned = ergo_ser::transaction::UnsignedTransaction {
            inputs: vec![ergo_ser::input::UnsignedInput {
                box_id: change_id,
                extension: ergo_ser::input::ContextExtension::empty(),
            }],
            data_inputs: vec![],
            output_candidates: vec![change.candidate.clone()],
        };
        let mut writer = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::transaction::write_unsigned_transaction(&mut writer, &unsigned).unwrap();
        let unsigned_hex = hex::encode(writer.result());
        let request = |inputs: Option<Vec<String>>| TransactionSignRequest {
            unsigned_tx: UnsignedTxDto {
                bytes: unsigned_hex.clone(),
            },
            external_secrets: None,
            hints: None,
            inputs,
            data_inputs: None,
        };
        let signed_input =
            |response: ergo_wallet_protocol::scala::sending::TransactionSignResponse| {
                let bytes = hex::decode(response.transaction.bytes).unwrap();
                let tx =
                    ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
                assert!(!tx.inputs[0].spending_proof.proof.is_empty());
                tx.inputs[0].box_id
            };
        let change_hex = hex::encode(serialize_ergo_box(&change).unwrap());

        // Parent neither confirmed nor in this daemon's pool view: unresolvable
        // without the caller's bytes (still the old error, not a new one) ...
        assert!(engine.transaction_sign(request(None)).is_err());
        // ... and signed with them, as Scala's `inputsRaw`.
        let response = engine
            .transaction_sign(request(Some(vec![change_hex.clone()])))
            .unwrap();
        assert_eq!(signed_input(response), change_id);
        // A box id entry keeps meaning "look it up".
        assert!(engine
            .transaction_sign(request(Some(vec![hex::encode(change_id.as_bytes())])))
            .is_err());

        // Supplied bytes must be the input's own box: tampered bytes hash to
        // another id, and an unrelated box is refused.
        let mut tampered = change.clone();
        tampered.candidate.value += 1;
        for bad in [&tampered, &unrelated] {
            assert!(matches!(
                engine.transaction_sign(request(Some(vec![hex::encode(
                    serialize_ergo_box(bad).unwrap()
                )]))),
                Err(WalletAdminError::BadRequest(m)) if m.contains("is not an input of this transaction")
            ));
        }
        assert!(matches!(
            engine.transaction_sign(request(Some(vec!["00ff".into()]))),
            Err(WalletAdminError::BadRequest(_))
        ));

        // Parent in the pool (the reported case): signed with or without bytes.
        pool.0.lock().unwrap().outputs = Arc::new(HashMap::from([(change_id, change.clone())]));
        assert_eq!(
            signed_input(engine.transaction_sign(request(None)).unwrap()),
            change_id
        );
        assert_eq!(
            signed_input(
                engine
                    .transaction_sign(request(Some(vec![change_hex])))
                    .unwrap()
            ),
            change_id
        );
    }

    /// #684: walletd signs a contract input against the context this node's
    /// mempool admits with. The contract is
    /// `sigmaProp(CONTEXT.preHeader.minerPk == groupGenerator) && proveDlog(groupGenerator)`:
    /// true only under the mempool prediction (the generator as miner), false
    /// under the synthetic successor (the tip's miner, 7*G here).
    #[tokio::test]
    async fn native_sign_spends_a_contract_input_the_mempool_admits() {
        use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBoxCandidate};
        use ergo_wallet_protocol::native::dto::{ExternalSecret, SignTxRequest, TxRepr};
        use std::sync::Arc;

        // 00 | SigmaAnd(2): BoolToSigmaProp(EQ(CONTEXT.preHeader.minerPk, groupGenerator)),
        //                   ProveDlog(groupGenerator)
        let tree_bytes = hex::decode("00ea02d193db6906db6503fe82cd82").unwrap();
        let tree = ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(&tree_bytes)).unwrap();
        let contract = ErgoBox {
            candidate: ErgoBoxCandidate::new(1_000_000_000, tree, 1, vec![], Default::default())
                .unwrap(),
            transaction_id: ModifierId::from_bytes([0x51; 32]),
            index: 0,
        };
        let contract_id = contract.box_id().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&directory.path().join("state.redb"))
            .unwrap()
            .with_non_durable_commits_for_test();
        store
            .initialize_genesis(&[(
                *contract_id.as_bytes(),
                serialize_ergo_box(&contract).unwrap(),
            )])
            .unwrap();
        let seven_g: [u8; 33] =
            hex::decode("025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
                .unwrap()
                .try_into()
                .unwrap();
        let mut parent = ModifierId::from_bytes([0; 32]);
        for height in 1..=12u32 {
            let mut synthetic = header(height, parent);
            // The unchecked helper's HEADER_META timestamp, for hydration.
            synthetic.timestamp = 1_700_000_000 + u64::from(height);
            synthetic.solution = AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from(seven_g),
                nonce: [0; 8],
            };
            // Empty blocks: every header commits to the genesis UTXO root, as
            // the signing context checks against the tip.
            let root = store.root_digest();
            synthetic.state_root = root;
            let (bytes, id) = serialize_header(&synthetic).unwrap();
            store.store_header(id.as_bytes(), &bytes).unwrap();
            store
                .apply_block_unchecked_for_test(height, id.as_bytes(), &root, &[])
                .unwrap();
            parent = id;
        }
        let accessor = super::super::ChainStateAccessorImpl::chain_only(
            ergo_state::reader::ChainStoreReader::new_from_db(store.db_arc()),
            false,
            None,
        );
        let snapshot = accessor.chain_snapshot().unwrap();
        assert_eq!(
            snapshot.state_context().sigma_pre_header.miner_pubkey,
            seven_g,
            "the synthetic successor would make the contract false"
        );

        let unsigned = ergo_ser::transaction::UnsignedTransaction {
            inputs: vec![ergo_ser::input::UnsignedInput {
                box_id: contract_id,
                extension: ergo_ser::input::ContextExtension::empty(),
            }],
            data_inputs: vec![],
            output_candidates: vec![contract.candidate.clone()],
        };
        let mut writer = ergo_primitives::writer::VlqWriter::new();
        ergo_ser::transaction::write_unsigned_transaction(&mut writer, &unsigned).unwrap();
        let request = SignTxRequest {
            unsigned_transaction: TxRepr::from_bytes(&writer.result()),
            external_secrets: vec![ExternalSecret::Dlog {
                secret: format!("{:064x}", 1),
            }],
        };
        let engine = pool_test_engine(
            Arc::new(parking_lot::RwLock::new(
                ergo_wallet::storage::SecretStorage::open(directory.path().join("wallet")),
            )),
            Arc::new(parking_lot::RwLock::new(
                ergo_wallet_service::state::WalletState::empty(false),
            )),
            store.db_arc(),
            Arc::new(accessor),
            Arc::new(ergo_wallet_service::engine::NoopMempoolOverlay::new()),
            Arc::new(NoPoolSubmit),
        );
        let signed = engine
            .native_sign_transaction(request)
            .expect("a contract input over a held key signs");
        let bytes = hex::decode(signed.signed_transaction.bytes_hex()).unwrap();

        // The node's mempool admission context is the one walletd signed for.
        let candidate = snapshot.intended_candidate_context().unwrap();
        let mut node = crate::node::tests::make_state_with_store(store);
        node.executor.hydrate_block_context(&node.store).unwrap();
        let owned = crate::node::tip_context::build_tip_context(&node).unwrap();
        let pre = &candidate.state_context.sigma_pre_header;
        assert_eq!(pre.height, owned.tx_context.height);
        assert_eq!(pre.parent_id, owned.tx_context.pre_header_parent_id);
        assert_eq!(pre.timestamp, owned.tx_context.pre_header_timestamp);
        assert_eq!(u64::from(pre.n_bits), owned.tx_context.pre_header_n_bits);
        assert_eq!(pre.version, owned.tx_context.pre_header_version);
        assert_eq!(pre.votes, owned.tx_context.pre_header_votes);
        assert_eq!(pre.miner_pubkey, owned.tx_context.miner_pubkey);
        assert_eq!(
            candidate.state_context.sigma_last_headers,
            owned.last_headers
        );
        let mut cost = ergo_primitives::cost::CostAccumulator::new(
            ergo_primitives::cost::JitCost::from_block_cost(owned.params.max_block_cost).unwrap(),
        );
        ergo_validation::tx::validate_transaction(
            &bytes,
            node.store.as_utxo().unwrap(),
            &ergo_validation::LocalPolicy::default_policy(),
            &mut ergo_validation::TxValidationCtx {
                ctx: &owned.tx_context,
                params: &owned.params,
                cost: &mut cost,
                last_headers: &owned.last_headers,
                rules: Default::default(),
            },
        )
        .expect("the mempool admits what walletd signed");
    }
}

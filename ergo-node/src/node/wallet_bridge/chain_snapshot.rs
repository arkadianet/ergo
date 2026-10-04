use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::Header;
use ergo_state::store::{CommittedSnapshot, StateError};
use ergo_validation::pre_header::CandidatePreHeader;
use ergo_validation::{ActiveProtocolParameters, ProtocolParams, ReemissionRuleInputs};
use ergo_wallet::tx_context::{BlockchainParameters, BlockchainStateContext};
use ergo_wallet_service::chain::CommittedTip;
use ergo_wallet_service::engine::{ChainAccessError, SigningView};

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
    /// The candidate preheader is synthetic: its timestamp is the committed
    /// tip timestamp plus one, votes are zero, and its miner key is copied
    /// from the tip header. Scripts that inspect those preheader fields can
    /// therefore evaluate differently from a real candidate block.
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
                votes: [0, 0, 0],
                miner_pubkey: *tip_header.solution.pk().as_bytes(),
            },
            previous_state_digest: committed.state_root(),
        };
        Ok(Self {
            committed,
            tip,
            headers,
            header_ids,
            state_context,
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
        let wallet_store: std::sync::Arc<dyn ergo_state::wallet::WalletStore> =
            std::sync::Arc::new(ergo_state::wallet::RedbWalletStore::new(store.db_arc()));
        let accessor = super::super::ChainStateAccessorImpl::new(reader, wallet_store, false, None);
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
        let wallet_store: std::sync::Arc<dyn ergo_state::wallet::WalletStore> =
            std::sync::Arc::new(ergo_state::wallet::RedbWalletStore::new(store.db_arc()));
        let accessor = super::super::ChainStateAccessorImpl::new(reader, wallet_store, false, None);
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
        let wallet_store: std::sync::Arc<dyn ergo_state::wallet::WalletStore> =
            std::sync::Arc::new(ergo_state::wallet::RedbWalletStore::new(store.db_arc()));
        let accessor = super::super::ChainStateAccessorImpl::new(reader, wallet_store, false, None);
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

            let accessor = super::super::ChainStateAccessorImpl::new(
                ergo_state::reader::ChainStoreReader::new_from_db(
                    node.store.as_utxo().unwrap().db_arc(),
                ),
                std::sync::Arc::new(ergo_state::wallet::RedbWalletStore::new(
                    node.store.as_utxo().unwrap().db_arc(),
                )),
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
            RescanCoordinator, WalletEngine, WalletEngineConfig, WalletEngineParts,
        };
        WalletEngine::new(WalletEngineParts {
            storage,
            state,
            store: std::sync::Arc::new(ergo_wallet_service::RedbWalletStore::new(db)),
            chain,
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
        let accessor = super::super::ChainStateAccessorImpl::new(
            ergo_state::reader::ChainStoreReader::new_from_db(store.db_arc()),
            std::sync::Arc::new(ergo_wallet_service::wallet::RedbWalletStore::new(
                store.db_arc(),
            )),
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
        let accessor = super::super::ChainStateAccessorImpl::new(
            ergo_state::reader::ChainStoreReader::new_from_db(db.clone()),
            std::sync::Arc::new(ergo_wallet_service::wallet::RedbWalletStore::new(
                db.clone(),
            )),
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
            .native_send_transaction(SendTxRequest::Intent { intent })
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
}

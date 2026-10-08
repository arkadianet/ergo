//! Real node chain routes and the daemon's owned spending adapters.

use std::sync::Arc;
use std::time::Instant;

use ergo_api::types::{ApiInfo, ApiWeightFunction, SubmitError, SubmitMode};
use ergo_node::node::wallet_bridge::InProcessChainClient;
use ergo_node::snapshot::{NodeSnapshot, SnapshotHandle, SnapshotPublisher};
use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::{read_transaction, transaction_id, write_transaction, Transaction};
use ergo_state::store::StateStore;
use ergo_wallet_protocol::chain as wire;
use ergo_wallet_service::engine::{
    ChainAccessError, MempoolOverlay, TxSubmitter, WalletChainAccess,
};
use ergo_wallet_service::{ChainClient, ChainClientError, CommittedTip, RedbWalletStore};
use ergo_walletd::chain_http::HttpChainClient;
use ergo_walletd::config::{ApiKey, Network};
use ergo_walletd::host::SpendingPreparation;
use ergo_walletd::spending::RemoteSpendingAccess;

use super::node_api::{serve_node_client_with_governor, NODE_API_KEY};

fn serve_node_client(client: Arc<dyn ChainClient>) -> super::node_api::NodeApi {
    serve_node_client_with_governor(
        client,
        ergo_api::v1::GovernorConfig {
            burst: 10_000.0,
            refill_per_sec: 10_000.0,
            ..Default::default()
        },
    )
}

struct SnapshotRead(SnapshotHandle);
impl ergo_api::NodeReadState for SnapshotRead {
    fn info(&self) -> ergo_api::types::ApiInfo {
        self.0.load().info.clone()
    }
    fn status(&self) -> ergo_api::types::ApiStatus {
        self.0.load().status.clone()
    }
    fn tip(&self) -> ergo_api::types::ApiTip {
        self.0.load().tip.clone()
    }
    fn sync(&self) -> ergo_api::types::ApiSyncStatus {
        self.0.load().sync.clone()
    }
    fn peers(&self) -> Vec<ergo_api::types::ApiPeer> {
        self.0.load().peers.clone()
    }
    fn mempool_summary(&self) -> ergo_api::types::ApiMempoolSummary {
        self.0.load().mempool.clone()
    }
    fn mempool_transactions(&self) -> ergo_api::types::ApiMempoolTransactions {
        self.0.load().mempool_transactions.clone()
    }
    fn mempool_transaction(&self, _: &str) -> Option<ergo_api::types::ApiMempoolTransaction> {
        None
    }
    fn health(&self) -> ergo_api::types::ApiHealth {
        self.0.load().health.clone()
    }
}

fn serve_node_with_stored_queue(
    client: Arc<dyn ChainClient>,
    snapshot: SnapshotHandle,
    queue: Arc<ergo_mining::private_queue::PrivateTransactionQueue>,
) -> super::node_api::NodeApi {
    let auth = Arc::new(
        ergo_api::auth::ApiSecurity::new(ergo_api::auth::ApiSecurity::hash_key(NODE_API_KEY))
            .unwrap(),
    );
    let auth = ergo_api::v1::V1AuthConfig::new(Some(auth)).into_shared();
    let governor = ergo_api::v1::Governor::new(ergo_api::v1::GovernorConfig {
        burst: 10_000.0,
        refill_per_sec: 10_000.0,
        ..Default::default()
    })
    .unwrap();
    let chain = ergo_node::node::wallet_bridge::WalletChainAdapter::new(client).into_dyn();
    let router = ergo_api::v1::wallet_chain_router(
        ergo_api::v1::WalletChainState::with_chain(chain),
        governor.clone(),
        auth.clone(),
    );
    let operator = ergo_api::v1::operator::operator_router(
        ergo_api::v1::operator::OperatorState {
            blocking: ergo_api::v1::BlockingReads::new(Default::default()).unwrap(),
            read: Arc::new(SnapshotRead(snapshot)),
            chain: None,
            admin: None,
            mining: None,
            private_queue: Some(Arc::new(
                ergo_node::node::wallet_bridge::StoredPrivateQueueBridge::new(queue),
            )),
            network: Network::Mainnet.prefix(),
        },
        governor,
        auth,
    );
    super::node_api::serve_node_router(router.merge(operator))
}

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const LOCAL_KEY: &str = "daemon-spending-local-credential";

fn phrase_key() -> [u8; 33] {
    let mnemonic = ergo_wallet::mnemonic::Mnemonic::import(PHRASE).unwrap();
    let seed = mnemonic.to_seed("");
    let master =
        ergo_wallet::extended_key::ExtendedSecretKey::derive_master_key(&seed[..]).unwrap();
    master
        .derive_at_path(&ergo_wallet::derivation::DerivationPath::eip3_first_address())
        .unwrap()
        .public_key()
        .compressed_bytes()
}

struct VerifyingSubmit {
    pk: [u8; 33],
    input: [u8; 32],
    signed: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[async_trait::async_trait]
impl ergo_api::NodeSubmit for VerifyingSubmit {
    async fn submit_transaction(
        &self,
        bytes: Vec<u8>,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        let tx = read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].box_id.as_bytes(), &self.input);
        assert!(!tx.inputs[0].spending_proof.proof.is_empty());
        assert!(ergo_sigma::verify::verify_sigma_proof(
            &ergo_ser::sigma_value::SigmaBoolean::ProveDlog(
                ergo_primitives::group_element::GroupElement::from(self.pk)
            ),
            &tx.inputs[0].spending_proof.proof,
            &ergo_ser::transaction::bytes_to_sign(&tx).unwrap()
        )
        .unwrap());
        self.signed.lock().unwrap().push(bytes);
        Ok(hex::encode(transaction_id(&tx).unwrap().as_bytes()))
    }
    async fn submit_transaction_json(
        &self,
        _input: ergo_api::compat::types::ScalaTransactionInput,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "unsupported".into(),
            detail: None,
        })
    }
}

async fn daemon_request(
    app: &axum::Router,
    path: &str,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("api_key", LOCAL_KEY)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn fund_wallet(wallet: &dyn ergo_wallet_service::WalletStore, input: &ErgoBox, tip: [u8; 32]) {
    use ergo_wallet_service::wallet::types::OwnedBlockOutput;
    let keys = wallet
        .read()
        .unwrap()
        .tracked_pubkeys_with_paths()
        .unwrap()
        .into_iter()
        .map(|(index, pk, _)| (index, pk))
        .collect::<std::collections::BTreeMap<_, _>>();
    let trees = keys
        .values()
        .map(|pk| {
            let mut tree = vec![0x00, 0x08, 0xcd];
            tree.extend(pk);
            tree
        })
        .collect();
    let block = ergo_wallet_service::wallet::scan::RescanBlock {
        block_id: tip,
        txs: vec![ergo_wallet_service::wallet::scan::RescanTx {
            tx_id: *input.transaction_id.as_bytes(),
            inputs: Vec::new(),
            outputs: vec![OwnedBlockOutput {
                box_id: *input.box_id().unwrap().as_bytes(),
                output_index: input.index,
                ergo_tree_bytes: input.candidate.ergo_tree_bytes().to_vec(),
                value: input.candidate.value,
                assets: Vec::new(),
                miner_reward_pubkey: None,
                box_bytes: serialize_ergo_box(input).unwrap(),
            }],
        }],
    };
    let mut write = wallet.begin_write().unwrap();
    write
        .apply_rescan_block(1, &trees, &keys, &block, None)
        .unwrap();
    write.finish_rescan(0).unwrap();
    write.commit().unwrap();
    assert_eq!(
        wallet.read().unwrap().unspent_boxes().unwrap().len(),
        1,
        "funding payload must add the tracked input"
    );
}

fn transaction() -> Transaction {
    let tree = read_ergo_tree(&mut VlqReader::new(
        &hex::decode("0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap(),
    ))
    .unwrap();
    Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes([0x31; 32]),
            spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
        }],
        data_inputs: Vec::new(),
        output_candidates: vec![ErgoBoxCandidate::new(
            10_000_000,
            tree,
            1,
            Vec::new(),
            AdditionalRegisters::empty(),
        )
        .unwrap()],
    }
}

fn bytes(tx: &Transaction) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_transaction(&mut w, tx).unwrap();
    w.result()
}

fn apply_empty_block(store: &mut StateStore, height: u32, parent: [u8; 32]) -> [u8; 32] {
    let miner: [u8; 33] =
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .try_into()
            .unwrap();
    let header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent),
        ad_proofs_root: Digest32::from_bytes([0; 32]),
        transactions_root: Digest32::from_bytes([0; 32]),
        state_root: store.root_digest(),
        timestamp: 1_000_000 + u64::from(height),
        extension_root: Digest32::from_bytes([0; 32]),
        n_bits: 16842752,
        height,
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from(miner),
            nonce: [height as u8; 8],
        },
    };
    let (header_bytes, id) = serialize_header(&header).unwrap();
    store.store_header(id.as_bytes(), &header_bytes).unwrap();
    let mut writer = VlqWriter::new();
    write_block_transactions(
        &mut writer,
        &BlockTransactions {
            header_id: id,
            transactions: vec![transaction()],
        },
    )
    .unwrap();
    let section = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        id.as_bytes(),
        header.transactions_root.as_bytes(),
    );
    store
        .store_block_section(&section, &writer.result())
        .unwrap();
    let root = store.root_digest();
    store
        .apply_block_unchecked_for_test(height, id.as_bytes(), &root, &[])
        .unwrap();
    *id.as_bytes()
}

fn publication(store: &StateStore, tx: &Transaction, sequence: u64) -> NodeSnapshot {
    let info = ApiInfo {
        agent_name: "test".into(),
        node_name: "test".into(),
        network: "mainnet".into(),
        version: "test".into(),
        started_at_unix_ms: 0,
        uptime_seconds: 0,
        target_block_interval_ms: 120_000,
    };
    let mut snapshot = NodeSnapshot::empty(info, ApiWeightFunction::default());
    let (height, id) = store.reader_handle().committed_tip().unwrap().unwrap();
    snapshot.publication_sequence = sequence;
    snapshot.tip.best_full_block.height = height;
    snapshot.tip.best_full_block.header_id = hex::encode(id);
    snapshot.pool_full_txs = Arc::new(vec![(
        Digest32::from_bytes(*transaction_id(tx).unwrap().as_bytes()),
        Arc::from(bytes(tx)),
    )]);
    snapshot
}

fn published(store: &StateStore, tx: &Transaction) -> SnapshotHandle {
    let snapshot = publication(store, tx, 1);
    let publisher = SnapshotPublisher::new(
        snapshot.info.clone(),
        Instant::now(),
        ApiWeightFunction::default(),
    );
    let handle = publisher.handle();
    handle.store(Arc::new(snapshot));
    handle
}

fn client(url: &str) -> Arc<HttpChainClient> {
    Arc::new(
        HttpChainClient::new(
            reqwest::Url::parse(url).unwrap(),
            ApiKey::from_test(NODE_API_KEY.to_vec()),
        )
        .unwrap(),
    )
}

struct TypedSubmit;
#[async_trait::async_trait]
impl ergo_api::NodeSubmit for TypedSubmit {
    async fn submit_transaction(
        &self,
        bytes: Vec<u8>,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        let tx = read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        if tx.inputs[0].spending_proof.proof.is_empty() {
            return Err(SubmitError {
                reason: "unresolved_input".into(),
                detail: Some("missing committed input".into()),
            });
        }
        Ok(hex::encode(transaction_id(&tx).unwrap().as_bytes()))
    }
    async fn submit_transaction_json(
        &self,
        _input: ergo_api::compat::types::ScalaTransactionInput,
        _mode: SubmitMode,
    ) -> Result<String, SubmitError> {
        Err(SubmitError {
            reason: "unsupported".into(),
            detail: None,
        })
    }
}

#[test]
fn real_node_owned_spending_context_authenticates_pool_params_rules_and_inputs() {
    let node_dir = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();
    let tx = transaction();
    let committed_box = ErgoBox::new(
        tx.output_candidates[0].clone(),
        ModifierId::from_bytes([0x61; 32]),
        0,
    );
    let id = *committed_box.box_id().unwrap().as_bytes();
    let mut store = StateStore::open(&node_dir.path().join("state.redb")).unwrap();
    store
        .initialize_genesis(&[(id, serialize_ergo_box(&committed_box).unwrap())])
        .unwrap();
    let tip = apply_empty_block(&mut store, 1, [0; 32]);
    let pool = published(&store, &tx);
    let rules = ergo_validation::ReemissionRuleInputs::from_chain_spec(
        &ergo_chain_spec::ChainSpec::mainnet(),
        true,
    )
    .unwrap();
    let provider = InProcessChainClient::from_chain_reader(
        store.reader_handle(),
        Arc::new(TypedSubmit),
        false,
        Some(rules.clone()),
    )
    .with_spending_context(pool.clone(), 2_500_000, 55_000, None);
    let node = serve_node_client(Arc::new(provider));
    let http = client(&node.url());
    let wallet =
        Arc::new(RedbWalletStore::open_standalone(wallet_dir.path().join("wallet.redb")).unwrap());
    let remote = RemoteSpendingAccess::new(wallet, http.clone(), Network::Mainnet);
    let config = remote.refresh().unwrap();
    assert_eq!(config.min_relay_fee_nano_erg, 2_500_000);
    assert_eq!(config.max_tx_size_bytes, 55_000);
    assert_eq!(config.reemission, Some(rules));
    let view = remote.signing_view().unwrap();
    assert_eq!(view.tip(), CommittedTip::new(1, tip));
    assert_eq!(
        view.state_context().previous_state_digest,
        store.root_digest()
    );
    assert_eq!(
        view.active_params(),
        &store
            .reader_handle()
            .committed_snapshot()
            .unwrap()
            .unwrap()
            .active_params()
            .unwrap()
    );
    assert_eq!(view.lookup_utxo(&id).unwrap(), Some(committed_box));
    let pool_tx_id = Digest32::from_bytes(*transaction_id(&tx).unwrap().as_bytes());
    assert_eq!(
        remote.pool_spending_tx(&tx.inputs[0].box_id),
        Some(pool_tx_id)
    );
    assert_eq!(remote.pool_outputs().len(), 1);
    assert!(!remote.is_pruned());
    assert!(!remote.private_mining_configured());
    assert!(remote.read_block_at_supported().unwrap());
    assert_eq!(remote.read_block_at(1).unwrap().unwrap().txs.len(), 1);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let rejection = runtime
        .block_on(remote.submit_transaction(bytes(&tx)))
        .unwrap_err();
    assert_eq!(rejection.reason, "unresolved_input");
    assert_eq!(rejection.detail.as_deref(), Some("missing committed input"));

    let mut invalid = publication(&store, &tx, 2);
    invalid.tip.best_full_block.header_id = "ab".repeat(32);
    pool.store(Arc::new(invalid));
    assert!(remote.refresh().is_err());
    assert!(matches!(
        remote.signing_view(),
        Err(ChainAccessError::Unsupported)
    ));
    // Previously returned views remain owned, and do not get rewritten by a refresh.
    assert_eq!(view.tip(), CommittedTip::new(1, tip));
    let new_tip = apply_empty_block(&mut store, 2, tip);
    let stale = view.lookup_utxo(&id);
    assert!(
        matches!(stale, Err(ChainAccessError::StaleTip { .. })),
        "{stale:?}"
    );
    assert!(matches!(
        http.block_at(1, CommittedTip::new(1, tip)),
        Err(ChainClientError::Conflict)
    ));
    assert!(matches!(
        http.admit_transaction(wire::SubmitRequest {
            transaction: hex::encode(bytes(&tx)),
            snapshot_id: Some(hex::encode(tip))
        }),
        Err(ChainClientError::Conflict)
    ));
    assert_ne!(new_tip, tip);
    store
        .test_force_set_minimal_full_block_height_unsafe(2)
        .unwrap();
    assert_eq!(
        http.block_at(1, CommittedTip::new(2, new_tip)).unwrap_err(),
        ChainClientError::HistoryPruned {
            minimum_height: Some(2)
        }
    );
}

#[test]
fn real_spending_context_requires_operator_auth_and_declines_network_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    store.initialize_genesis(&[]).unwrap();
    apply_empty_block(&mut store, 1, [0; 32]);
    let tx = transaction();
    let provider = InProcessChainClient::from_chain_reader(
        store.reader_handle(),
        None::<Arc<dyn ergo_api::NodeSubmit>>,
        false,
        None,
    )
    .with_spending_context(published(&store, &tx), 1_000_000, 90_000, None);
    let node = serve_node_client(Arc::new(provider));
    let bad = HttpChainClient::new(
        reqwest::Url::parse(&node.url()).unwrap(),
        ApiKey::from_test(b"wrong-key".to_vec()),
    )
    .unwrap();
    assert_eq!(
        bad.spending_context().unwrap_err(),
        ChainClientError::Unauthorized
    );
    let wallet =
        Arc::new(RedbWalletStore::open_standalone(wallet_dir.path().join("wallet.redb")).unwrap());
    let remote = RemoteSpendingAccess::new(wallet, client(&node.url()), Network::Testnet);
    assert!(remote.refresh().is_err());
    assert!(matches!(
        remote.signing_view(),
        Err(ChainAccessError::Unsupported)
    ));
}

#[test]
fn context_response_retains_its_admission_until_body_is_dropped() {
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    store.initialize_genesis(&[]).unwrap();
    apply_empty_block(&mut store, 1, [0; 32]);
    let tx = transaction();
    let provider = Arc::new(
        InProcessChainClient::from_chain_reader(
            store.reader_handle(),
            None::<Arc<dyn ergo_api::NodeSubmit>>,
            false,
            None,
        )
        .with_spending_context(published(&store, &tx), 1_000_000, 90_000, None),
    );
    let chain = ergo_node::node::wallet_bridge::WalletChainAdapter::new(provider).into_dyn();
    let auth = Arc::new(
        ergo_api::auth::ApiSecurity::new(ergo_api::auth::ApiSecurity::hash_key(NODE_API_KEY))
            .unwrap(),
    );
    let app = ergo_api::v1::wallet_chain_router(
        ergo_api::v1::WalletChainState::with_chain(chain),
        ergo_api::v1::Governor::new(ergo_api::v1::GovernorConfig {
            burst: 10_000.0,
            ..Default::default()
        })
        .unwrap(),
        ergo_api::v1::V1AuthConfig::new(Some(auth)).into_shared(),
    );
    let request = || {
        axum::http::Request::builder()
            .uri("/api/v1/chain/spending-context")
            .header("api_key", std::str::from_utf8(NODE_API_KEY).unwrap())
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), axum::http::StatusCode::OK);
        let rejected = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(
            rejected.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        // Merely returning the Response does not release the full-pool budget.
        drop(first);
        let next = app.oneshot(request()).await.unwrap();
        assert_eq!(next.status(), axum::http::StatusCode::OK);
    });
}

#[test]
fn daemon_and_embedded_wallet_build_same_transaction_and_remote_send_verifies_proofs() {
    use ergo_wallet_service::engine::{
        RescanCoordinator, WalletEngine, WalletEngineConfig, WalletEngineParts,
    };
    use ergo_wallet_service::{WalletService, WalletStore};
    use ergo_walletd::host::{SpendingCapabilities, WalletHost};
    let node_dir = tempfile::tempdir().unwrap();
    let wallet_dir = tempfile::tempdir().unwrap();
    let embedded_dir = tempfile::tempdir().unwrap();
    let pk = phrase_key();
    let mut tree = vec![0x00, 0x08, 0xcd];
    tree.extend(pk);
    let tree = read_ergo_tree(&mut VlqReader::new(&tree)).unwrap();
    let input = ErgoBox::new(
        ErgoBoxCandidate::new(
            100_000_000,
            tree,
            0,
            Vec::new(),
            AdditionalRegisters::empty(),
        )
        .unwrap(),
        ModifierId::from_bytes([0x62; 32]),
        0,
    );
    let input_id = *input.box_id().unwrap().as_bytes();
    let mut node_store = StateStore::open(&node_dir.path().join("state.redb")).unwrap();
    node_store
        .initialize_genesis(&[(input_id, serialize_ergo_box(&input).unwrap())])
        .unwrap();
    let tip = apply_empty_block(&mut node_store, 1, [0; 32]);
    let mut snapshot = publication(&node_store, &transaction(), 1);
    snapshot.pool_full_txs = Arc::new(Vec::new());
    let publisher = SnapshotPublisher::new(
        snapshot.info.clone(),
        Instant::now(),
        ApiWeightFunction::default(),
    );
    let pool = publisher.handle();
    pool.store(Arc::new(snapshot));
    let submitter = Arc::new(VerifyingSubmit {
        pk,
        input: input_id,
        signed: Default::default(),
    });
    let queue_path = node_dir.path().join("private-queue.json");
    let private_queue =
        Arc::new(ergo_mining::private_queue::PrivateTransactionQueue::open(&queue_path).unwrap());
    let mut rules = ergo_validation::ReemissionRuleInputs::from_chain_spec(
        &ergo_chain_spec::ChainSpec::mainnet(),
        true,
    )
    .unwrap();
    rules.activation_height = 0;
    let provider = InProcessChainClient::from_chain_reader(
        node_store.reader_handle(),
        submitter.clone(),
        false,
        Some(rules.clone()),
    )
    .with_spending_context(pool.clone(), 1_000_000, 90_000, Some(private_queue.clone()));
    let node =
        serve_node_with_stored_queue(Arc::new(provider), pool.clone(), private_queue.clone());
    let http = client(&node.url());
    let wallet: Arc<dyn WalletStore> = Arc::new(
        RedbWalletStore::open_standalone(wallet_dir.path().join("wallet.redb"))
            .unwrap()
            .rebuild_history_on_key_additions(),
    );
    let service = Arc::new(WalletService::new(wallet.clone(), http.clone()));
    let remote = Arc::new(RemoteSpendingAccess::new(
        wallet.clone(),
        http.clone(),
        Network::Mainnet,
    ));
    let host = WalletHost::with_spending(
        wallet.clone(),
        service.clone(),
        SpendingCapabilities {
            chain: remote.clone(),
            preparation: remote.clone(),
            submitter: remote.clone(),
            mempool: remote.clone(),
        },
        wallet_dir.path(),
        Network::Mainnet,
    )
    .unwrap();
    let context = ergo_walletd::api::ApiContext {
        service,
        network: Network::Mainnet,
        tip: Arc::new(ergo_walletd::tip::CachedNodeTip::new(http)),
        tip_max_age: std::time::Duration::from_secs(60),
    };
    let app = ergo_walletd::full_api::seed_router(
        context,
        host.clone(),
        ApiKey::from_test(LOCAL_KEY.as_bytes().to_vec()),
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let status = runtime.block_on(host.native_status()).unwrap();
    assert_eq!(
        status.rescan,
        ergo_wallet_protocol::native::dto::RescanStateDto::Idle
    );
    assert_eq!(status.tip_height, 1);
    assert!(status.eip27_active);
    assert!(matches!(
        remote.signing_view(),
        Err(ChainAccessError::Unsupported)
    ));
    runtime
        .block_on(host.restore(PHRASE.into(), "".into(), "correct-password".into(), false))
        .unwrap();
    runtime
        .block_on(host.unlock("correct-password".into()))
        .unwrap();
    fund_wallet(wallet.as_ref(), &input, tip);

    // The second engine owns separate encrypted secrets but the same persisted
    // public state. Its chain/mempool adapters are the embedded production ones.
    let mut secret = ergo_wallet::storage::SecretStorage::open(embedded_dir.path().join("wallet"));
    secret
        .restore(PHRASE, "", "correct-password", false)
        .unwrap();
    let mut state = ergo_wallet_service::state::WalletState::empty(false);
    let hydration = ergo_wallet_service::wallet::hydration::HydrationSnapshot::load(
        wallet.read().unwrap().as_ref(),
    )
    .unwrap();
    state
        .hydrate_from_reader(&hydration, Network::Mainnet.prefix())
        .unwrap();
    let chain = Arc::new(ergo_node::node::wallet_bridge::ChainStateAccessorImpl::new(
        node_store.reader_handle(),
        wallet.clone(),
        false,
        Some(rules.clone()),
    ));
    let embedded_pool = ergo_node::api_bridge::SnapshotMempoolView::new(pool.clone()).into_dyn();
    let mut embedded = WalletEngine::new(WalletEngineParts {
        storage: Arc::new(parking_lot::RwLock::new(secret)),
        state: Arc::new(parking_lot::RwLock::new(state)),
        store: wallet.clone(),
        chain,
        config: WalletEngineConfig {
            network: Network::Mainnet.prefix(),
            expose_private_keys: false,
            reemission: Some(rules),
            min_relay_fee_nano_erg: 1_000_000,
            max_tx_size_bytes: 90_000,
        },
        submitter: Arc::new(ergo_node::node::wallet_bridge::NodeSubmitAdapter::new(
            submitter.clone(),
        )),
        mempool: Arc::new(ergo_node::node::wallet_bridge::MempoolViewOverlay::new(
            embedded_pool,
        )),
        service: None,
        rescan: Arc::new(RescanCoordinator::new()),
    });
    embedded.unlock("correct-password".into()).unwrap();
    assert_eq!(wallet.read().unwrap().unspent_boxes().unwrap().len(), 1);
    let address =
        ergo_wallet::address::pubkey_to_p2pk_address(&pk, Network::Mainnet.prefix()).unwrap();
    let intent = serde_json::json!({"outputs":[{"type":"payment","address":address,"value":"10000000"}],"fee":"1000000"});
    let embedded_build = embedded
        .native_build_transaction(serde_json::from_value(intent.clone()).unwrap())
        .unwrap();
    let (status, build) = runtime.block_on(daemon_request(
        &app,
        "/api/v1/wallet/transactions/build",
        intent.clone(),
    ));
    assert_eq!(status, axum::http::StatusCode::OK, "{build}");
    let daemon_build: ergo_wallet_protocol::native::dto::BuildTxResponse =
        serde_json::from_value(build).unwrap();
    assert_eq!(daemon_build, embedded_build);
    let (status, signed) = runtime.block_on(daemon_request(
        &app,
        "/api/v1/wallet/transactions/sign",
        serde_json::json!({"unsignedTransaction":daemon_build.unsigned_transaction}),
    ));
    assert_eq!(status, axum::http::StatusCode::OK, "{signed}");
    let signed: ergo_wallet_protocol::native::dto::SignTxResponse =
        serde_json::from_value(signed).unwrap();
    let (status, sent) = runtime.block_on(daemon_request(
        &app,
        "/api/v1/wallet/transactions/send",
        serde_json::json!({"type":"signed","signedTransaction":signed.signed_transaction}),
    ));
    assert_eq!(status, axum::http::StatusCode::OK, "{sent}");
    assert_eq!(sent["txId"], signed.tx_id);
    assert_eq!(submitter.signed.lock().unwrap().len(), 1);
    let (status, sent) = runtime.block_on(daemon_request(
        &app,
        "/api/v1/wallet/transactions/send",
        serde_json::json!({"type":"intent","intent":intent.clone()}),
    ));
    assert_eq!(status, axum::http::StatusCode::OK, "{sent}");
    assert_eq!(submitter.signed.lock().unwrap().len(), 2);

    let mut conflicting = transaction();
    conflicting.inputs[0].box_id = Digest32::from_bytes(input_id);
    let reserved_bytes = bytes(&conflicting);
    let reserved = ergo_mempool::Entry::new(
        Digest32::from_bytes(*transaction_id(&conflicting).unwrap().as_bytes()),
        Arc::from(reserved_bytes.clone()),
        vec![Digest32::from_bytes(input_id)],
        Vec::new(),
        Vec::new(),
        0,
        0,
        reserved_bytes.len() as u32,
        0,
        ergo_mempool::TxSource::Wallet,
    );
    let before_revision = private_queue.reservation_snapshot().0;
    let private = private_queue
        .admit(&reserved, Default::default(), 0, 1)
        .unwrap();
    let record = ergo_wallet_service::engine::jobs::Record {
        job: ergo_wallet_protocol::native::dto::WalletJob {
            id: "1".into(),
            request: ergo_wallet_protocol::native::dto::WalletJobRequest {
                label: "queued owner-approved renewal".into(),
                task: ergo_wallet_protocol::native::dto::WalletJobTask::Renew {
                    box_ids: vec![hex::encode(input_id)],
                },
                not_before_height: 1,
                expires_at_height: 100,
                max_attempts: 1,
            },
            state: ergo_wallet_protocol::native::dto::WalletJobState::Queued,
            created_at_ms: 0,
            updated_at_ms: 0,
            attempts: 1,
            tx_id: Some(private.tx_id.clone()),
            detail: None,
        },
        signed_hex: Some(hex::encode(reserved_bytes)),
        last_attempt_height: Some(1),
    };
    ergo_wallet_service::engine::jobs::save(wallet.as_ref(), 1, &record).unwrap();
    let queue_view = client(&node.url()).spending_context().unwrap();
    // Disabling candidate construction does not release queued reservations.
    assert!(!queue_view.private_mining_configured);
    assert_eq!(
        queue_view.private_reserved_inputs,
        vec![hex::encode(input_id)]
    );
    assert!(queue_view.private_queue_revision.unwrap() > before_revision);
    let (status, refusal) = runtime.block_on(daemon_request(
        &app,
        "/api/v1/wallet/transactions/build",
        intent.clone(),
    ));
    assert_ne!(status, axum::http::StatusCode::OK, "{refusal}");
    // A withdrawal which cannot be persisted must leave both the daemon's
    // public job journal and the remote queue's reservations intact.
    std::fs::remove_file(&queue_path).unwrap();
    std::fs::create_dir(&queue_path).unwrap();
    let (status, refusal) = runtime.block_on(daemon_request(
        &app,
        "/api/v1/wallet/mining-jobs/1/cancel",
        serde_json::json!({}),
    ));
    assert_ne!(status, axum::http::StatusCode::OK, "{refusal}");
    assert_eq!(
        private_queue.reservation_snapshot().1,
        std::collections::BTreeSet::from([input_id])
    );
    assert_eq!(
        ergo_wallet_service::engine::jobs::reserved_inputs(wallet.as_ref()).unwrap(),
        std::collections::BTreeSet::from([input_id])
    );
    assert_eq!(
        ergo_wallet_service::engine::jobs::list(wallet.as_ref())
            .unwrap()
            .items[0]
            .state,
        ergo_wallet_protocol::native::dto::WalletJobState::Queued
    );
    std::fs::remove_dir(&queue_path).unwrap();
    let (status, cancelled) = runtime.block_on(daemon_request(
        &app,
        "/api/v1/wallet/mining-jobs/1/cancel",
        serde_json::json!({}),
    ));
    assert_eq!(status, axum::http::StatusCode::OK, "{cancelled}");
    assert!(private_queue.reservation_snapshot().1.is_empty());
    assert!(
        ergo_wallet_service::engine::jobs::reserved_inputs(wallet.as_ref())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        ergo_wallet_service::engine::jobs::list(wallet.as_ref())
            .unwrap()
            .items[0]
            .state,
        ergo_wallet_protocol::native::dto::WalletJobState::Cancelled
    );
    let (status, available) = runtime.block_on(daemon_request(
        &app,
        "/api/v1/wallet/transactions/build",
        intent.clone(),
    ));
    assert_eq!(status, axum::http::StatusCode::OK, "{available}");
    let mut snapshot = publication(&node_store, &conflicting, 2);
    // The pool transaction's output pays another key, so there are no alternate funds.
    snapshot.pool_outputs = Arc::new(std::collections::HashMap::new());
    pool.store(Arc::new(snapshot));
    let (status, refusal) = runtime.block_on(daemon_request(
        &app,
        "/api/v1/wallet/transactions/build",
        intent,
    ));
    assert_ne!(status, axum::http::StatusCode::OK, "{refusal}");
    assert_eq!(submitter.signed.lock().unwrap().len(), 2);
    runtime.block_on(host.shutdown()).unwrap();
    let restarted_http = client(&node.url());
    let restarted_service = Arc::new(WalletService::new(wallet.clone(), restarted_http.clone()));
    let restarted_remote = Arc::new(RemoteSpendingAccess::new(
        wallet.clone(),
        restarted_http,
        Network::Mainnet,
    ));
    let restarted = WalletHost::with_spending(
        wallet,
        restarted_service,
        SpendingCapabilities {
            chain: restarted_remote.clone(),
            preparation: restarted_remote.clone(),
            submitter: restarted_remote.clone(),
            mempool: restarted_remote.clone(),
        },
        wallet_dir.path(),
        Network::Mainnet,
    )
    .unwrap();
    let status = runtime.block_on(restarted.native_status()).unwrap();
    assert!(status.locked);
    assert_eq!(
        status.rescan,
        ergo_wallet_protocol::native::dto::RescanStateDto::Idle
    );
    assert_eq!(status.tip_height, 1);
    assert!(status.eip27_active);
    assert!(matches!(
        restarted_remote.signing_view(),
        Err(ChainAccessError::Unsupported)
    ));
    runtime.block_on(restarted.shutdown()).unwrap();
}

#[test]
fn node_refuses_oversized_spending_context_before_hex_encoding_pool() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
    store.initialize_genesis(&[]).unwrap();
    apply_empty_block(&mut store, 1, [0; 32]);
    let tx = transaction();
    let mut snapshot = publication(&store, &tx, 1);
    // Deliberately opaque bytes: a context must reject its wire budget before
    // allocating a hex string or trying to transport the pool to the daemon.
    snapshot.pool_full_txs = Arc::new(vec![(
        Digest32::from_bytes([0x7b; 32]),
        Arc::from(vec![0; wire::MAX_SPENDING_CONTEXT_BYTES / 2]),
    )]);
    let publisher = SnapshotPublisher::new(
        snapshot.info.clone(),
        Instant::now(),
        ApiWeightFunction::default(),
    );
    let pool = publisher.handle();
    pool.store(Arc::new(snapshot));
    let provider = InProcessChainClient::from_chain_reader(
        store.reader_handle(),
        None::<Arc<dyn ergo_api::NodeSubmit>>,
        false,
        None,
    )
    .with_spending_context(pool, 1_000_000, 90_000, None);
    let error = provider.spending_context().unwrap_err();
    assert!(
        matches!(error, ChainClientError::Unavailable(ref detail) if detail.contains("8 MiB wire budget"))
    );
    let node = serve_node_client(Arc::new(provider));
    assert!(matches!(
        client(&node.url()).spending_context(),
        Err(ChainClientError::Unavailable(_))
    ));
}

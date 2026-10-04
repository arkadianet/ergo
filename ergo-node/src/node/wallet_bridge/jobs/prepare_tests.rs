//! Job preparation against a funded chain and an unlocked wallet. Every signed
//! transaction must pass the consensus validation private admission runs.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::transaction::Transaction;
use ergo_state::store::StateStore;
use ergo_state::wallet::tables::WALLET_BOXES;

use super::*;
use crate::node::wallet_bridge::{
    ChainStateAccessor, ChainStateAccessorImpl, TxSubmitter, WriterConfig,
};

/// Past the first voting epoch and the 720-block reward delay, so a height-0
/// reward box is spendable.
const TIP: u32 = 1030;
const EPOCH: u32 = 1024;
const ERG: u64 = 1_000_000_000;
const TOKEN_A: [u8; 32] = [0xA1; 32];
const TOKEN_B: [u8; 32] = [0xB2; 32];
/// Compressed secp256k1 generator: a valid key this wallet does not track.
const EXTERNAL_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// ----- helpers -----

/// Private mining queue that accepts every admission and records its bytes.
#[derive(Default)]
struct PrivateQueue(Mutex<Vec<Vec<u8>>>);

#[async_trait]
impl TxSubmitter for PrivateQueue {
    async fn submit_transaction(&self, _: Vec<u8>) -> Result<String, ergo_api::types::SubmitError> {
        panic!("maintenance must never broadcast");
    }

    async fn private_transactions(
        &self,
    ) -> Result<Vec<ergo_api::mining::PrivateTransactionEntry>, ergo_api::types::SubmitError> {
        Ok(Vec::new())
    }

    async fn submit_private_transaction(
        &self,
        bytes: Vec<u8>,
        _: ergo_api::mining::PrivateTransactionOptions,
    ) -> Result<String, ergo_api::types::SubmitError> {
        let tx_id = sign_submit::signed_tx_id_hex(&bytes).unwrap();
        self.0.lock().push(bytes);
        Ok(tx_id)
    }

    async fn cancel_private_transaction(
        &self,
        _: String,
    ) -> Result<(), ergo_api::types::SubmitError> {
        Ok(())
    }
}

fn header(height: u32, parent: ModifierId) -> ergo_ser::header::Header {
    ergo_ser::header::Header {
        version: 2,
        parent_id: parent,
        ad_proofs_root: Digest32::from_bytes([0; 32]),
        transactions_root: Digest32::from_bytes([0; 32]),
        state_root: ADDigest::from_bytes([0; 33]),
        // Matches the header metadata the unchecked apply synthesizes, so node
        // block-context hydration accepts these headers.
        timestamp: 1_700_000_000 + u64::from(height),
        extension_root: Digest32::from_bytes([0; 32]),
        n_bits: 16842752,
        height,
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
        solution: ergo_ser::autolykos::AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from([2; 33]),
            nonce: [0; 8],
        },
    }
}

fn tree(bytes: &[u8]) -> ergo_ser::ergo_tree::ErgoTree {
    ergo_ser::ergo_tree::read_ergo_tree(&mut VlqReader::new(bytes)).unwrap()
}

fn tokens(assets: &[([u8; 32], u64)]) -> Vec<ergo_ser::token::Token> {
    assets
        .iter()
        .map(|(id, amount)| ergo_ser::token::Token {
            token_id: Digest32::from_bytes(*id),
            amount: *amount,
        })
        .collect()
}

fn decode(bytes: &[u8]) -> Transaction {
    ergo_ser::transaction::read_transaction(&mut VlqReader::new(bytes)).unwrap()
}

/// A mainnet wallet, unlocked, over a committed chain whose genesis state
/// holds the funded boxes. EIP-27 is active well below the tip.
struct Funded {
    _directory: tempfile::TempDir,
    store: StateStore,
    db: Arc<redb::Database>,
    storage: Arc<RwLock<ergo_wallet::storage::SecretStorage>>,
    state: Arc<RwLock<ergo_wallet::state::WalletState>>,
    wallet_store: Arc<dyn ergo_state::wallet::WalletStore>,
    chain: Arc<dyn ChainStateAccessor>,
    queue: Arc<PrivateQueue>,
    submitter: Arc<dyn TxSubmitter>,
    mempool: Arc<dyn ergo_api::MempoolView>,
    rescan: Arc<crate::wallet_boot::RescanControl>,
    config: WriterConfig,
    rules: ergo_validation::ReemissionRuleInputs,
    address: String,
    pubkey: [u8; 33],
}

impl Funded {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::open(&directory.path().join("state.redb"))
            .unwrap()
            .with_non_durable_commits_for_test();
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
        let mut state = ergo_wallet::state::WalletState::empty(false);
        crate::wallet_boot::WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &db,
            ergo_ser::address::NetworkPrefix::Mainnet,
            "test",
        )
        .unwrap();
        let address = state.change_address().unwrap().to_owned();
        let pubkey = ergo_ser::address::decode_p2pk_address(
            &address,
            ergo_ser::address::NetworkPrefix::Mainnet,
        )
        .unwrap();
        let spec = ergo_chain_spec::ChainSpec::for_network(ergo_chain_spec::Network::Mainnet);
        let rules = ergo_validation::ReemissionRuleInputs {
            activation_height: 100,
            reemission_token_id: *spec
                .reemission
                .as_ref()
                .unwrap()
                .reemission_token_id
                .as_bytes(),
            pay_to_reemission_tree: spec.emission_script_trees().unwrap().pay_to_reemission,
        };
        let queue = Arc::new(PrivateQueue::default());
        Self {
            chain: Arc::new(ChainStateAccessorImpl::new(
                db.clone(),
                false,
                Some(rules.clone()),
            )),
            wallet_store: Arc::new(ergo_state::wallet::RedbWalletStore::new(db.clone())),
            storage: Arc::new(RwLock::new(storage)),
            state: Arc::new(RwLock::new(state)),
            submitter: queue.clone(),
            queue,
            mempool: Arc::new(ergo_api::NoopMempoolView::new()),
            rescan: Arc::new(crate::wallet_boot::RescanControl::default()),
            config: WriterConfig {
                network: ergo_ser::address::NetworkPrefix::Mainnet,
                expose_private_keys: false,
                min_relay_fee_nano_erg: 1_000_000,
                max_tx_size_bytes: 98_304,
                reemission: Some(rules.clone()),
            },
            rules,
            address,
            pubkey,
            store,
            db,
            _directory: directory,
        }
    }

    fn owned(
        &self,
        value: u64,
        assets: &[([u8; 32], u64)],
        registers: &[u8],
    ) -> (ErgoBoxCandidate, BoxProvenance) {
        let tree_bytes = ergo_ser::address::build_p2pk_tree_bytes(&self.pubkey).unwrap();
        let registers = ergo_ser::register::read_registers(&mut VlqReader::new(registers)).unwrap();
        let candidate =
            ErgoBoxCandidate::new(value, tree(&tree_bytes), 0, tokens(assets), registers).unwrap();
        (candidate, BoxProvenance::Owned)
    }

    fn reward(&self, value: u64, assets: &[([u8; 32], u64)]) -> (ErgoBoxCandidate, BoxProvenance) {
        let script = ergo_mining::reward_output_script(&self.pubkey);
        let candidate = ErgoBoxCandidate::new(
            value,
            tree(&script),
            0,
            tokens(assets),
            ergo_ser::register::AdditionalRegisters::empty(),
        )
        .unwrap();
        (candidate, BoxProvenance::MinerReward)
    }

    /// Commit the boxes in genesis state, apply the header chain up to `TIP`
    /// and record the boxes as confirmed wallet boxes. Returns their IDs.
    fn fund(&mut self, boxes: Vec<(ErgoBoxCandidate, BoxProvenance)>) -> Vec<String> {
        let mut genesis = Vec::new();
        let mut records = Vec::new();
        for (index, (candidate, provenance)) in boxes.into_iter().enumerate() {
            let ergo_box =
                ErgoBox::new(candidate, ModifierId::from_bytes([index as u8 + 1; 32]), 0);
            let box_id = *ergo_box.box_id().unwrap().as_bytes();
            genesis.push((box_id, serialize_ergo_box(&ergo_box).unwrap()));
            records.push(WalletBox {
                box_id,
                creation_tx_id: *ergo_box.transaction_id.as_bytes(),
                creation_output_index: 0,
                creation_height: 1,
                value: ergo_box.candidate.value,
                assets: ergo_box
                    .candidate
                    .tokens
                    .iter()
                    .map(|token| (*token.token_id.as_bytes(), token.amount))
                    .collect(),
                status: BoxStatus::Confirmed,
                provenance,
            });
        }
        self.store.initialize_genesis(&genesis).unwrap();
        let mut parent = ModifierId::from_bytes([0; 32]);
        for height in 1..=TIP {
            let (bytes, id) = ergo_ser::header::serialize_header(&header(height, parent)).unwrap();
            self.store.store_header(id.as_bytes(), &bytes).unwrap();
            let root = self.store.root_digest();
            // Version 2 activates script version 1, which the mainnet
            // pay-to-reemission contract requires.
            let voted = (height == EPOCH).then(|| ergo_validation::ActiveProtocolParameters {
                epoch_start_height: EPOCH,
                block_version: 2,
                ..ergo_validation::scala_launch()
            });
            self.store
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
        let write = self.db.begin_write().unwrap();
        {
            let mut table = write.open_table(WALLET_BOXES).unwrap();
            for record in &records {
                table
                    .insert(record.box_id, bincode::serialize(record).unwrap())
                    .unwrap();
            }
        }
        write.commit().unwrap();
        records
            .iter()
            .map(|record| hex::encode(record.box_id))
            .collect()
    }

    fn context(&self) -> WriterContext<'_> {
        WriterContext {
            rescan: &self.rescan,
            rescan_workers: &self.rescan.workers,
            storage: &self.storage,
            state: &self.state,
            db: &self.db,
            store: &self.wallet_store,
            chain: &self.chain,
            cfg: &self.config,
            submit_handle: &self.submitter,
            mempool: &self.mempool,
        }
    }

    fn job(&self, task: WalletJobTask) -> WalletJobRequest {
        WalletJobRequest {
            label: "funded job".into(),
            task,
            not_before_height: TIP,
            expires_at_height: TIP + 720,
            max_attempts: 3,
        }
    }

    /// Approve one job and run the scheduler wake that prepares and submits it.
    async fn prepare(&self, task: WalletJobTask) -> (WalletJob, Transaction) {
        create_owned(&self.context(), self.job(task)).unwrap();
        tick(&self.context()).await.unwrap();
        let job = list(&self.db).unwrap().items.remove(0);
        assert_eq!(job.state, WalletJobState::Queued, "{:?}", job.detail);
        let submissions = self.queue.0.lock().clone();
        assert_eq!(submissions.len(), 1);
        assert_eq!(
            job.tx_id.as_deref(),
            Some(
                sign_submit::signed_tx_id_hex(&submissions[0])
                    .unwrap()
                    .as_str()
            )
        );
        (job, decode(&submissions[0]))
    }

    /// Run the consensus validation private admission applies at the tip.
    fn admit(self, transaction: &Transaction) -> u64 {
        use ergo_mempool::admission::Validator;
        let bytes = sign_submit::serialize_signed_tx(transaction).unwrap();
        let mut node = crate::node::tests::make_state_with_store(self.store);
        node.executor.hydrate_block_context(&node.store).unwrap();
        node.executor.set_reemission_rules(Some(self.rules));
        let owned = crate::node::tip_context::build_tip_context(&node).unwrap();
        assert_eq!(owned.tip.height, TIP);
        let store = node.store.as_utxo().unwrap();
        let outputs = Default::default();
        let inputs = ergo_mempool::overlay::PoolUtxoOverlay::new(store, &outputs);
        let mut cost = ergo_primitives::cost::CostAccumulator::new(
            ergo_primitives::cost::JitCost::from_block_cost(node.mempool.config().max_tx_cost)
                .unwrap(),
        );
        let mut context = ergo_validation::TxValidationCtx {
            ctx: &owned.tx_context,
            params: &owned.params,
            cost: &mut cost,
            last_headers: &owned.last_headers,
            rules: ergo_validation::TxValidationRules {
                reemission: owned.reemission.as_ref(),
            },
        };
        ergo_mempool::ErgoValidator
            .validate(&bytes, &inputs, store, &mut context)
            .unwrap()
            .fee
    }
}

fn tracked_tree(funded: &Funded) -> Vec<u8> {
    ergo_ser::address::build_p2pk_tree_bytes(&funded.pubkey).unwrap()
}

fn no_fee_output(transaction: &Transaction) -> bool {
    transaction.output_candidates.iter().all(|output| {
        output.ergo_tree_bytes() != ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES
    })
}

// ----- happy path -----
#[tokio::test]
async fn consolidation_signs_one_zero_fee_output_with_every_token() {
    let mut funded = Funded::new();
    let first = funded.owned(ERG, &[(TOKEN_A, 5)], &[0]);
    let second = funded.owned(2 * ERG, &[(TOKEN_A, 2), (TOKEN_B, 7)], &[0]);
    let box_ids = funded.fund(vec![first, second]);
    let (_, transaction) = funded
        .prepare(WalletJobTask::Consolidate {
            box_ids: box_ids.clone(),
            destination: funded.address.clone(),
        })
        .await;
    assert_eq!(
        transaction
            .inputs
            .iter()
            .map(|input| hex::encode(input.box_id.as_bytes()))
            .collect::<Vec<_>>(),
        box_ids
    );
    assert_eq!(transaction.output_candidates.len(), 1);
    let output = &transaction.output_candidates[0];
    assert_eq!(output.value, 3 * ERG);
    assert_eq!(output.ergo_tree_bytes(), tracked_tree(&funded));
    assert_eq!(output.tokens, tokens(&[(TOKEN_A, 7), (TOKEN_B, 7)]));
    assert_eq!(output.creation_height, TIP);
    assert_eq!(funded.admit(&transaction), 0);
}

#[tokio::test]
async fn renewal_preserves_script_value_tokens_and_registers_at_a_new_height() {
    let mut funded = Funded::new();
    // R4 = Int 42, R5 = Coll[Byte](1, 2, 3).
    let renewed = funded.owned(ERG, &[(TOKEN_B, 9)], &[2, 0x04, 0x54, 0x0e, 0x03, 1, 2, 3]);
    let original = renewed.0.clone();
    let box_ids = funded.fund(vec![renewed]);
    let (_, transaction) = funded
        .prepare(WalletJobTask::Renew {
            box_ids: box_ids.clone(),
        })
        .await;
    assert_eq!(transaction.output_candidates.len(), 1);
    let output = &transaction.output_candidates[0];
    assert_eq!(output.value, original.value);
    assert_eq!(output.ergo_tree_bytes(), original.ergo_tree_bytes());
    assert_eq!(output.tokens, original.tokens);
    assert_eq!(output.register_bytes(), original.register_bytes());
    assert_eq!(original.creation_height, 0);
    assert_eq!(output.creation_height, TIP);
    assert!(no_fee_output(&transaction));
    assert_eq!(funded.admit(&transaction), 0);
}

#[tokio::test]
async fn reward_retrieval_burns_reemission_tokens_without_a_miner_fee() {
    let mut funded = Funded::new();
    let token = funded.rules.reemission_token_id;
    let reward = funded.reward(10 * ERG, &[(token, 3 * ERG), (TOKEN_A, 1)]);
    let box_ids = funded.fund(vec![reward]);
    let (_, transaction) = funded
        .prepare(WalletJobTask::Rewards {
            box_ids,
            destination: funded.address.clone(),
        })
        .await;
    assert_eq!(transaction.output_candidates.len(), 2);
    let (destination, reemission) = (
        &transaction.output_candidates[0],
        &transaction.output_candidates[1],
    );
    assert_eq!(destination.ergo_tree_bytes(), tracked_tree(&funded));
    assert_eq!(destination.value, 7 * ERG);
    assert_eq!(destination.tokens, tokens(&[(TOKEN_A, 1)]));
    assert_eq!(
        reemission.ergo_tree_bytes(),
        funded.rules.pay_to_reemission_tree.as_slice()
    );
    assert_eq!(reemission.value, 3 * ERG);
    assert!(reemission.tokens.is_empty());
    assert!(no_fee_output(&transaction));
    assert_eq!(funded.admit(&transaction), 0);
}

#[tokio::test]
async fn payment_returns_change_to_the_wallet_without_a_miner_fee() {
    let mut funded = Funded::new();
    let source = funded.owned(5 * ERG, &[(TOKEN_A, 10)], &[0]);
    let box_ids = funded.fund(vec![source]);
    let external = hex::decode(EXTERNAL_KEY).unwrap();
    let recipient = ergo_ser::address::encode_p2pk_from_pubkey(
        ergo_ser::address::NetworkPrefix::Mainnet,
        &external,
    )
    .unwrap();
    let intent: TxIntent = serde_json::from_value(serde_json::json!({
        "outputs": [{
            "type": "payment",
            "address": recipient,
            "value": ERG.to_string(),
            "assets": [{"tokenId": hex::encode(TOKEN_A), "amount": "4"}],
        }],
        "fee": "0",
        "inputs": {"type": "boxIds", "boxIds": box_ids},
    }))
    .unwrap();
    let (_, transaction) = funded.prepare(WalletJobTask::Send { intent }).await;
    assert_eq!(transaction.output_candidates.len(), 2);
    let (payment, change) = (
        &transaction.output_candidates[0],
        &transaction.output_candidates[1],
    );
    assert_eq!(
        payment.ergo_tree_bytes(),
        ergo_ser::address::build_p2pk_tree_bytes(&external.try_into().unwrap())
            .unwrap()
            .as_slice()
    );
    assert_eq!(payment.value, ERG);
    assert_eq!(payment.tokens, tokens(&[(TOKEN_A, 4)]));
    assert_eq!(change.ergo_tree_bytes(), tracked_tree(&funded));
    assert_eq!(change.value, 4 * ERG);
    assert_eq!(change.tokens, tokens(&[(TOKEN_A, 6)]));
    assert_eq!(funded.admit(&transaction), 0);
}

// ----- round-trips -----
#[tokio::test]
async fn approval_reserves_pinned_inputs_until_cancelled() {
    let mut funded = Funded::new();
    let source = funded.owned(ERG, &[(TOKEN_A, 42)], &[0]);
    let box_ids = funded.fund(vec![source]);
    let request = funded.job(WalletJobTask::Renew { box_ids });
    let job = create_owned(&funded.context(), request.clone()).unwrap();
    assert_eq!(job.state, WalletJobState::Waiting);
    assert_eq!(job.attempts, 0);
    assert!(create_owned(&funded.context(), request.clone()).is_err());
    assert_eq!(list(&funded.db).unwrap().items[0].request, request);
    for _ in 0..2 {
        let cancelled = cancel(&funded.context(), &job.id).await.unwrap();
        assert_eq!(cancelled.state, WalletJobState::Cancelled);
    }
    create_owned(&funded.context(), request).unwrap();
}

// ----- error paths -----
#[tokio::test]
async fn approval_requires_an_unlocked_wallet_and_a_bounded_deadline() {
    let mut funded = Funded::new();
    let source = funded.owned(ERG, &[], &[0]);
    let box_ids = funded.fund(vec![source]);
    let mut request = funded.job(WalletJobTask::Renew { box_ids });
    funded.storage.write().lock();
    assert!(matches!(
        create_owned(&funded.context(), request.clone()),
        Err(WalletAdminError::Locked)
    ));
    assert!(list(&funded.db).unwrap().items.is_empty());
    funded.storage.write().unlock("test").unwrap();
    request.expires_at_height = TIP + MAX_SCHEDULE_BLOCKS + 1;
    assert!(matches!(
        create_owned(&funded.context(), request.clone()),
        Err(WalletAdminError::BadRequest(_))
    ));
    request.expires_at_height -= 1;
    create_owned(&funded.context(), request).unwrap();
}

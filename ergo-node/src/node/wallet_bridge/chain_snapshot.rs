use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::Header;
use ergo_state::store::{CommittedSnapshot, StateError};
use ergo_validation::pre_header::CandidatePreHeader;
use ergo_validation::{ActiveProtocolParameters, ProtocolParams, ReemissionRuleInputs};
use ergo_wallet::tx_context::{BlockchainParameters, BlockchainStateContext};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    pub height: u32,
    pub header_id: [u8; 32],
}

#[derive(Debug, Error)]
pub enum ChainStateError {
    #[error("chain state read failed: {0}")]
    State(#[source] StateError),
    #[error("no committed chain state")]
    NoCommittedState,
    #[error("chain snapshot is unsupported by this accessor")]
    Unsupported,
    #[error("committed chain tip moved from ({expected_height}, {expected_id}) to ({actual_height}, {actual_id})")]
    StaleTip {
        expected_height: u32,
        expected_id: String,
        actual_height: u32,
        actual_id: String,
    },
}

impl From<StateError> for ChainStateError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

pub struct ChainSnapshot {
    committed: CommittedSnapshot,
    tip: ChainTip,
    headers: Vec<Header>,
    state_context: BlockchainStateContext,
    active_params: ActiveProtocolParameters,
    signing_params: BlockchainParameters,
    protocol_params: ProtocolParams,
    reemission: Option<ReemissionRuleInputs>,
    pool_outputs:
        std::sync::Arc<std::collections::HashMap<ergo_primitives::digest::Digest32, ErgoBox>>,
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
        let tip = ChainTip {
            height: committed.best_full_block_height(),
            header_id: committed.best_full_block_id(),
        };
        let headers = committed.last_ancestor_headers_window()?;
        let tip_header = headers.first().ok_or(StateError::InternalInvariant {
            what: "ChainSnapshot::from_committed: empty ancestor header window",
        })?;
        let active_params = committed.active_params()?;
        let signing_params = BlockchainParameters {
            max_block_cost: active_params.max_block_cost as u64,
            input_cost: active_params.input_cost as u64,
            data_input_cost: active_params.data_input_cost as u64,
            output_cost: active_params.output_cost as u64,
            token_access_cost: active_params.token_access_cost as u64,
            interpreter_init_cost: ergo_validation::INTERPRETER_INIT_COST,
            block_version: active_params.block_version,
        };
        let protocol_params = ProtocolParams::from_active(&active_params);
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
            state_context,
            active_params,
            signing_params,
            protocol_params,
            reemission: reemission.cloned(),
            pool_outputs: Default::default(),
        })
    }

    pub fn tip(&self) -> ChainTip {
        self.tip
    }

    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    pub fn state_context(&self) -> &BlockchainStateContext {
        &self.state_context
    }

    pub fn active_params(&self) -> &ActiveProtocolParameters {
        &self.active_params
    }

    pub fn signing_params(&self) -> &BlockchainParameters {
        &self.signing_params
    }

    pub fn protocol_params(&self) -> &ProtocolParams {
        &self.protocol_params
    }

    pub fn reemission_rules(&self) -> Option<&ReemissionRuleInputs> {
        self.reemission.as_ref()
    }

    /// Add an immutable pool-parent overlay for native signing. Committed UTXO
    /// boxes take precedence when a parent confirms between build and sign.
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
        let mut reader = VlqReader::new(&bytes);
        let ergo_box = read_ergo_box(&mut reader)
            .map_err(|error| StateError::Serialization(format!("snapshot box decode: {error}")))?;
        Ok(Some(ergo_box))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::wallet_bridge::ChainStateAccessor;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::serialize_header;
    use ergo_state::store::StateStore;

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

    #[test]
    fn snapshot_supports_short_chain_with_five_headers() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        apply_headers(&mut store, 5);
        let accessor = super::super::ChainStateAccessorImpl::new(store.db_arc(), false, None);
        let snapshot = accessor.chain_snapshot().unwrap();
        assert_eq!(snapshot.tip().height, 5);
        assert_eq!(snapshot.headers().len(), 5);
        assert_eq!(snapshot.headers()[0].height, 5);
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
        let accessor = super::super::ChainStateAccessorImpl::new(store.db_arc(), false, None);
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
        accessor.ensure_snapshot_current(&captured).unwrap();

        // Native signing must resolve the same unconfirmed parent and run its
        // normal proof/self-verification gates, even with a locked wallet.
        struct PoolView(Arc<HashMap<Digest32, ErgoBox>>);
        impl ergo_api::MempoolView for PoolView {
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
        use ergo_api::wallet::native::dto::{ExternalSecret, SignTxRequest, TxRepr};
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
        let wallet = parking_lot::RwLock::new(ergo_wallet::state::WalletState::empty(false));
        let db = store.db_arc();
        let pool = PoolView(Arc::new(HashMap::from([(pool_id, pool_parent)])));
        let signed = super::super::support::sign_submit::sign_transaction_native_impl(
            &request, &storage, &wallet, &db, &accessor, &pool,
        )
        .await
        .unwrap();
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

    #[test]
    fn snapshot_stale_after_committed_tip_moves() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&dir.path().join("state.redb")).unwrap();
        store.initialize_genesis(&[]).unwrap();
        let (parent, _) = apply_headers(&mut store, 11);
        let accessor = super::super::ChainStateAccessorImpl::new(store.db_arc(), false, None);
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
            accessor.ensure_snapshot_current(&snapshot),
            Err(ChainStateError::StaleTip { .. })
        ));
    }
}

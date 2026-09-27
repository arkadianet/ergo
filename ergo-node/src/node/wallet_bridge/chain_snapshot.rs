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
    header_ids: Vec<[u8; 32]>,
    state_context: BlockchainStateContext,
    active_params: ActiveProtocolParameters,
    signing_params: BlockchainParameters,
    protocol_params: ProtocolParams,
    reemission: Option<ReemissionRuleInputs>,
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
        let tip = ChainTip {
            height: committed.best_full_block_height(),
            header_id: committed.best_full_block_id(),
        };
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
            header_ids,
            state_context,
            active_params,
            signing_params,
            protocol_params,
            reemission: reemission.cloned(),
        })
    }

    pub fn tip(&self) -> ChainTip {
        self.tip
    }

    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    pub fn header_ids(&self) -> &[[u8; 32]] {
        &self.header_ids
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

    pub fn lookup_utxo(&self, box_id: &[u8; 32]) -> Result<Option<ErgoBox>, StateError> {
        let Some(bytes) = self.committed.lookup_box(box_id)? else {
            return Ok(None);
        };
        decode_utxo_box(box_id, &bytes).map(Some)
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
            accessor.ensure_snapshot_current(&snapshot),
            Err(ChainStateError::StaleTip { .. })
        ));
    }
}

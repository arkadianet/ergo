//! Controlled host views exercise the explicit-candidate capability. They are
//! test embeddings, not evidence that standard node pre-headers are real.
use super::*;
use crate::{
    chain::CommittedTip,
    engine::{chain::PoolSigningView, ChainAccessError, WalletChainAccess},
    wallet::scan::{RescanBlock, RescanReadError},
    RedbWalletStore,
};
use ergo_primitives::{
    digest::{ADDigest, Digest32, ModifierId},
    group_element::GroupElement,
    reader::VlqReader,
};
use ergo_ser::{
    autolykos::AutolykosSolution,
    ergo_box::{read_ergo_box, ErgoBox},
    header::{serialize_header, Header},
    transaction::UnsignedTransaction,
};
use ergo_sigma::evaluator::SigmaValidationSettings;
use ergo_validation::{ActiveProtocolParameters, ProtocolParams, ReemissionRuleInputs};
use ergo_wallet::{
    proving::{external::ProverExternalSecret, hints::TransactionHintsBag},
    tx_context::{BlockchainParameters, BlockchainStateContext, SigningContext},
    ReducedTransaction,
};
use ergo_wallet_protocol::scala::{
    multi_sig::{GenerateCommitmentsRequest, HintExtractionRequest},
    sending::ExternalSecretDto,
};
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone)]
struct ControlledView {
    state: BlockchainStateContext,
    intended: Option<BlockchainStateContext>,
    intended_settings: SigmaValidationSettings,
    ids: Vec<[u8; 32]>,
    tip: CommittedTip,
    active: ActiveProtocolParameters,
    signing: BlockchainParameters,
    protocol: ProtocolParams,
    utxos: HashMap<[u8; 32], ErgoBox>,
    reemission: Option<ReemissionRuleInputs>,
}

impl SigningView for ControlledView {
    fn intended_candidate_context(&self) -> Option<SigningContext<'_>> {
        self.intended.as_ref().map(|state| SigningContext {
            state_context: state,
            header_ids: &self.ids,
            validation_settings: &self.intended_settings,
        })
    }
    fn tip(&self) -> CommittedTip {
        self.tip.clone()
    }
    fn headers(&self) -> &[Header] {
        &self.state.sigma_last_headers
    }
    fn header_ids(&self) -> &[[u8; 32]] {
        &self.ids
    }
    fn state_context(&self) -> &BlockchainStateContext {
        &self.state
    }
    fn active_params(&self) -> &ActiveProtocolParameters {
        &self.active
    }
    fn signing_params(&self) -> &BlockchainParameters {
        &self.signing
    }
    fn protocol_params(&self) -> &ProtocolParams {
        &self.protocol
    }
    fn reemission_rules(&self) -> Option<&ReemissionRuleInputs> {
        self.reemission.as_ref()
    }
    fn lookup_utxo(&self, id: &[u8; 32]) -> Result<Option<ErgoBox>, ChainAccessError> {
        Ok(self.utxos.get(id).cloned())
    }
}

struct ControlledChain(ControlledView);
impl WalletChainAccess for ControlledChain {
    fn wallet_scan_height(&self) -> Result<u32, ChainAccessError> {
        Ok(self.0.tip.height)
    }
    fn tip_height(&self) -> Result<u32, ChainAccessError> {
        Ok(self.0.tip.height)
    }
    fn is_pruned(&self) -> bool {
        false
    }
    fn read_block_at(&self, _: u32) -> Result<Option<RescanBlock>, RescanReadError> {
        Ok(None)
    }
    fn signing_view(&self) -> Result<Box<dyn SigningView>, ChainAccessError> {
        Ok(Box::new(self.0.clone()))
    }
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../test-vectors/wallet/reduced_scala_6_0_7.json"
    ))
    .unwrap()
}

fn point(n: u64) -> [u8; 33] {
    (ProjectivePoint::GENERATOR * Scalar::from(n))
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn external_dtos() -> Vec<ExternalSecretDto> {
    let mut secrets: Vec<_> = (1..=3)
        .map(|n| ExternalSecretDto::Dlog {
            dlog: format!("{n:064x}"),
        })
        .collect();
    secrets.push(ExternalSecretDto::DhTuple {
        g: hex::encode(point(2)),
        h: hex::encode(point(2)),
        u: hex::encode(point(6)),
        v: hex::encode(point(6)),
        x: format!("{:064x}", 3),
    });
    secrets
}

fn external_secrets() -> Vec<ProverExternalSecret> {
    external_dtos()
        .iter()
        .map(decode_external_secret)
        .collect::<Result<_, _>>()
        .unwrap()
}

fn case(row: &serde_json::Value) -> (ReducedTransaction, ControlledView) {
    let reduced = ReducedTransaction::from_bytes(
        &hex::decode(row["reduced_hex"].as_str().unwrap()).unwrap(),
        4,
    )
    .unwrap();
    let mut utxos = HashMap::new();
    for field in ["input_boxes", "data_boxes"] {
        for encoded in row[field].as_array().unwrap() {
            let bytes = hex::decode(encoded.as_str().unwrap()).unwrap();
            let b = read_ergo_box(&mut VlqReader::new(&bytes).with_activated_script_version(3))
                .unwrap();
            utxos.insert(*b.box_id().unwrap().as_bytes(), b);
        }
    }
    let mut headers = Vec::new();
    let mut ids = Vec::new();
    let mut parent = ModifierId::from_bytes([0; 32]);
    for height in 399_990..400_000 {
        let header = Header {
            version: 4,
            parent_id: parent,
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 1,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits: 0,
            height,
            votes: [0; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes(point(1)),
                nonce: [0; 8],
            },
        };
        parent = serialize_header(&header).unwrap().1;
        ids.push(*parent.as_bytes());
        headers.push(header);
    }
    ids.reverse();
    headers.reverse();
    let state = BlockchainStateContext {
        sigma_last_headers: headers,
        sigma_pre_header: ergo_ser::pre_header::CandidatePreHeader {
            version: 4,
            parent_id: ids[0],
            height: 400_000,
            timestamp: 2,
            n_bits: 0,
            votes: [0; 3],
            miner_pubkey: point(1),
        },
        previous_state_digest: ADDigest::from_bytes([0; 33]),
    };
    let mut intended = state.clone();
    intended.sigma_pre_header.timestamp = 3;
    let mut active = ergo_validation::scala_launch();
    active.block_version = 4;
    active.max_block_cost = 1_000_000;
    let protocol = ProtocolParams::from_active(&active);
    let signing = BlockchainParameters {
        max_block_cost: protocol.max_block_cost,
        input_cost: protocol.input_cost,
        data_input_cost: protocol.data_input_cost,
        output_cost: protocol.output_cost,
        token_access_cost: protocol.token_access_cost,
        interpreter_init_cost: ergo_validation::INTERPRETER_INIT_COST,
        block_version: protocol.block_version,
    };
    let tip = CommittedTip::new(399_999, ids[0]);
    (
        reduced,
        ControlledView {
            state,
            intended: Some(intended),
            intended_settings: protocol.validation_settings.clone(),
            ids,
            tip,
            active,
            signing,
            protocol,
            utxos,
            reemission: None,
        },
    )
}

fn sign_with_view(
    unsigned: &UnsignedTransaction,
    view: &dyn SigningView,
) -> Result<ergo_ser::transaction::Transaction, WalletAdminError> {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(redb::Database::create(dir.path().join("wallet.redb")).unwrap());
    let store = RedbWalletStore::new(db);
    let storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
    sign_unsigned_tx(
        unsigned,
        &storage,
        &store,
        view,
        &external_secrets(),
        &TransactionHintsBag::empty(),
    )
}

#[test]
fn intended_host_signs_and_self_verifies_all_reference_contracts() {
    for row in fixture()["cases"].as_array().unwrap() {
        let (reduced, view) = case(row);
        let signed = sign_with_view(&reduced.unsigned_transaction, &view)
            .unwrap_or_else(|error| panic!("{}: {error}", row["name"]));
        let message = ergo_ser::transaction::bytes_to_sign(&signed).unwrap();
        for (input, reduction) in signed.inputs.iter().zip(&reduced.reduced_inputs) {
            assert!(ergo_sigma::verify::verify_sigma_proof(
                &reduction.sigma,
                &input.spending_proof.proof,
                &message,
            )
            .unwrap());
        }
    }
}

#[test]
fn committed_synthetic_host_retains_contract_gate_and_constant_signing() {
    let fixture = fixture();
    let (constant, mut view) = case(&fixture["cases"][1]);
    view.intended = None;
    assert!(sign_with_view(&constant.unsigned_transaction, &view).is_ok());
    for index in 6..11 {
        let (contract, mut view) = case(&fixture["cases"][index]);
        view.intended = None;
        assert!(matches!(
            sign_with_view(&contract.unsigned_transaction, &view),
            Err(WalletAdminError::UnsupportedScript),
        ));
    }
}

#[test]
fn intended_host_rejects_context_from_another_tip_root_settings_or_budget() {
    let fixture = fixture();
    let (reduced, view) = case(&fixture["cases"][6]);
    let mut mixed = view.clone();
    mixed.intended.as_mut().unwrap().sigma_pre_header.parent_id = [1; 32];
    assert!(sign_with_view(&reduced.unsigned_transaction, &mixed).is_err());
    let mut mixed = view.clone();
    mixed.intended.as_mut().unwrap().previous_state_digest = ADDigest::from_bytes([1; 33]);
    assert!(sign_with_view(&reduced.unsigned_transaction, &mixed).is_err());
    let mut mixed = view.clone();
    mixed
        .intended_settings
        .0
        .insert(1001, ergo_sigma::evaluator::RuleStatus::Disabled);
    assert!(sign_with_view(&reduced.unsigned_transaction, &mixed).is_err());
    let mut mixed = view.clone();
    mixed.signing.input_cost += 1;
    assert!(sign_with_view(&reduced.unsigned_transaction, &mixed).is_err());
    let mut limited = view;
    limited.signing.max_block_cost = u64::from(reduced.cost) - 1;
    limited.protocol.max_block_cost = limited.signing.max_block_cost;
    assert!(sign_with_view(&reduced.unsigned_transaction, &limited).is_err());
}

#[test]
fn pool_snapshot_preserves_explicit_candidate_capability_and_guards() {
    let fixture = fixture();
    let (reduced, view) = case(&fixture["cases"][6]);
    let pool = PoolSigningView::new(Box::new(view), Default::default());
    assert!(pool.intended_candidate_context().is_some());
    assert!(sign_with_view(&reduced.unsigned_transaction, &pool).is_ok());
}

#[test]
fn multisig_host_uses_same_context_selection_as_signing() {
    let fixture = fixture();
    let (reduced, view) = case(&fixture["cases"][10]);
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(redb::Database::create(dir.path().join("wallet.redb")).unwrap());
    let store = RedbWalletStore::new(db);
    let storage = RwLock::new(ergo_wallet::storage::SecretStorage::open(
        dir.path().join("wallet"),
    ));
    let request = GenerateCommitmentsRequest {
        unsigned_tx: hex::encode(serialize_unsigned_tx(&reduced.unsigned_transaction).unwrap()),
        external_secrets: Some(external_dtos()),
        inputs: None,
        data_inputs: None,
    };
    let hints = crate::engine::multisig::generate_commitments_impl(
        &request,
        &storage,
        &store,
        &ControlledChain(view.clone()),
    )
    .unwrap();
    assert!(!hints.hints.secret_hints["0"].is_empty());
    let signed = sign_with_view(&reduced.unsigned_transaction, &view).unwrap();
    let extraction = HintExtractionRequest {
        tx: hex::encode(serialize_signed_tx(&signed).unwrap()),
        real: vec![hex::encode(point(1))],
        simulated: vec![],
        inputs: None,
        data_inputs: None,
    };
    let hints = crate::engine::multisig::extract_hints_impl(
        &extraction,
        &storage,
        &ControlledChain(view.clone()),
    )
    .unwrap();
    assert!(!hints.hints.public_hints["0"].is_empty());
    let mut synthetic = view;
    synthetic.intended = None;
    assert!(matches!(
        crate::engine::multisig::generate_commitments_impl(
            &request,
            &storage,
            &store,
            &ControlledChain(synthetic.clone()),
        ),
        Err(WalletAdminError::UnsupportedScript),
    ));
    assert!(matches!(
        crate::engine::multisig::extract_hints_impl(
            &extraction,
            &storage,
            &ControlledChain(synthetic),
        ),
        Err(WalletAdminError::UnsupportedScript),
    ));
}

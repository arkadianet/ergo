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
    ergo_box::{read_ergo_box, ErgoBox, ErgoBoxCandidate},
    ergo_tree::read_ergo_tree,
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
use k256::{elliptic_curve::sec1::ToSec1Point, ProjectivePoint, Scalar};
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
        .to_sec1_point(true)
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
            votes: [0; 3].into(),
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
    sign_with_hints(unsigned, view, &TransactionHintsBag::empty())
}

fn sign_with_hints(
    unsigned: &UnsignedTransaction,
    view: &dyn SigningView,
    hints: &TransactionHintsBag,
) -> Result<ergo_ser::transaction::Transaction, WalletAdminError> {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(redb::Database::create(dir.path().join("wallet.redb")).unwrap());
    let store = RedbWalletStore::new(db);
    let storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
    sign_unsigned_tx(unsigned, &storage, &store, view, &external_secrets(), hints)
}

#[test]
fn intended_host_signs_and_self_verifies_all_reference_contracts() {
    for row in fixture()["cases"].as_array().unwrap() {
        let (reduced, view) = case(row);
        let signed = sign_with_view(&reduced.unsigned_transaction, &view)
            .unwrap_or_else(|error| panic!("{}: {error}", row["name"]));
        let message = ergo_ser::transaction::bytes_to_sign(&signed).unwrap();
        assert_eq!(
            ergo_wallet::proving::prover::Prover::bytes_to_sign_for_signed_tx_bounded(&signed)
                .unwrap(),
            message,
        );
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
fn intended_timestamp_is_used_for_both_signing_and_self_verification() {
    let fixture = fixture();
    let (mut reduced, mut view) = case(&fixture["cases"][0]);
    let original = view.utxos[reduced.unsigned_transaction.inputs[0].box_id.as_bytes()].clone();
    // sigmaProp(CONTEXT.preHeader.timestamp == 3L). This observes the field
    // that intentionally differs between the controlled intended/synthetic views.
    let bytes = hex::decode("00d193db6903db6503fe0506").unwrap();
    let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
    let input = ErgoBox::new(
        ErgoBoxCandidate::new(
            original.candidate.value,
            tree,
            original.candidate.creation_height,
            original.candidate.tokens.clone(),
            original.candidate.additional_registers().clone(),
        )
        .unwrap(),
        original.transaction_id,
        original.index,
    );
    reduced.unsigned_transaction.inputs[0].box_id = input.box_id().unwrap();
    view.utxos.clear();
    view.utxos
        .insert(*input.box_id().unwrap().as_bytes(), input.clone());
    let signed = sign_with_view(&reduced.unsigned_transaction, &view).unwrap();
    assert!(signed.inputs[0].spending_proof.proof.is_empty());

    let mut changed = view.clone();
    changed
        .intended
        .as_mut()
        .unwrap()
        .sigma_pre_header
        .timestamp = 2;
    assert!(sign_with_view(&reduced.unsigned_transaction, &changed).is_err());
    let changed_context = changed.intended_candidate_context().unwrap();
    assert!(
        self_verify_signed_tx(&signed, &[input], &[], &changed, Some(&changed_context)).is_err()
    );
    let mut synthetic = view;
    synthetic.intended = None;
    assert!(matches!(
        sign_with_view(&reduced.unsigned_transaction, &synthetic),
        Err(WalletAdminError::UnsupportedScript),
    ));
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
    let mut mixed = view.clone();
    mixed.signing.input_cost += 1;
    mixed.protocol.input_cost = mixed.signing.input_cost;
    assert!(matches!(
        super::super::chain::intended_signing_context(&mixed),
        Err(WalletAdminError::Internal(_)),
    ));
    let mut limited = view;
    limited.signing.max_block_cost = u64::from(reduced.cost) - 1;
    limited.protocol.max_block_cost = limited.signing.max_block_cost;
    limited.active.max_block_cost = limited.signing.max_block_cost as i32;
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
        None,
    )
    .unwrap();
    assert!(!hints.hints.secret_hints["0"].is_empty());
    let internal_hints =
        crate::engine::hints_codec::tx_hints_bag_from_dto(&hints.hints, Default::default())
            .unwrap();
    let commitment = internal_hints.public_hints[&0]
        .hints
        .iter()
        .find(|hint| matches!(hint, ergo_wallet::proving::hints::Hint::RealCommitment(_)))
        .unwrap()
        .clone();
    // Use the generated private nonce exactly once, together with its public
    // commitment. Extraction must recover that actual commitment from the proof.
    let signed = sign_with_hints(&reduced.unsigned_transaction, &view, &internal_hints).unwrap();
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
    let extracted =
        crate::engine::hints_codec::tx_hints_bag_from_dto(&hints.hints, Default::default())
            .unwrap();
    assert!(extracted.public_hints[&0].hints.contains(&commitment));
    assert!(extracted.public_hints[&0]
        .hints
        .iter()
        .any(|hint| matches!(hint, ergo_wallet::proving::hints::Hint::RealSecretProof(_))));
    let mut synthetic = view;
    synthetic.intended = None;
    assert!(matches!(
        crate::engine::multisig::generate_commitments_impl(
            &request,
            &storage,
            &store,
            &ControlledChain(synthetic.clone()),
            None,
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

/// Custodian for engine tests: the single-use, bound contract of the
/// daemon's vault, plus a record of every nonce it was handed so a test can
/// look for them in responses.
#[derive(Default)]
struct RecordingCustody {
    held: parking_lot::Mutex<HashMap<String, ([u8; 32], crate::engine::NonceBinding)>>,
    seen: parking_lot::Mutex<Vec<[u8; 32]>>,
}

impl crate::engine::NonceCustody for RecordingCustody {
    fn deposit(
        &self,
        nonce: zeroize::Zeroizing<[u8; 32]>,
        binding: crate::engine::NonceBinding,
    ) -> String {
        let mut seen = self.seen.lock();
        seen.push(*nonce);
        let handle = format!("{}{}", crate::engine::NONCE_HANDLE_PREFIX, seen.len());
        self.held.lock().insert(handle.clone(), (*nonce, binding));
        handle
    }
    fn withdraw(
        &self,
        handle: &str,
        binding: &crate::engine::NonceBinding,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, crate::engine::NonceRefusal> {
        let (nonce, issued) = self
            .held
            .lock()
            .remove(handle)
            .ok_or(crate::engine::NonceRefusal::Unavailable)?;
        if issued != *binding {
            return Err(crate::engine::NonceRefusal::WrongCommitment);
        }
        Ok(zeroize::Zeroizing::new(nonce))
    }
    fn clear(&self) {
        self.held.lock().clear();
    }
}

struct NoSubmit;

#[async_trait::async_trait]
impl crate::engine::TxSubmitter for NoSubmit {
    async fn submit_transaction(
        &self,
        _tx_bytes: Vec<u8>,
    ) -> Result<String, crate::engine::TxSubmitError> {
        unreachable!("multisig tests never submit")
    }
}

/// A box locked by `alice && bob`, where the wallet holds Bob's key and Alice
/// signs elsewhere. Bob's commitment nonce stays in custody: the handle signs
/// once, a second use is refused, a nonce chosen by the caller for Bob's key
/// is refused, and locking the wallet wipes outstanding handles.
#[test]
fn two_of_two_multisig_signs_with_a_custody_held_single_use_nonce() {
    use crate::engine::{WalletEngine, WalletEngineParts};
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::hints::{Hint, HintsBag};
    use ergo_wallet::proving::randomness::OsRngBackend;
    use ergo_wallet::proving::secrets::SecretRegistry;
    use ergo_wallet_protocol::scala::sending::{HintDto, TransactionSignRequest, UnsignedTxDto};

    // Bob: the wallet's first EIP-3 key.
    let mnemonic =
        ergo_wallet::mnemonic::Mnemonic::generate(ergo_wallet::mnemonic::MnemonicStrength::Words15)
            .unwrap();
    let bob_pk =
        ergo_wallet::extended_key::ExtendedSecretKey::derive_master_key(&mnemonic.to_seed("")[..])
            .unwrap()
            .derive_at_path(&ergo_wallet::derivation::DerivationPath::eip3_first_address())
            .unwrap()
            .public_key()
            .compressed_bytes();
    let bob = SigmaBoolean::ProveDlog(GroupElement::from_bytes(bob_pk));
    // Alice: a key the wallet never sees.
    let alice_secret = Scalar::from(17u64);
    let alice_pk = point(17);
    let alice = SigmaBoolean::ProveDlog(GroupElement::from_bytes(alice_pk));
    let both = SigmaBoolean::Cand(vec![alice.clone(), bob.clone()].into());

    let tree = |sb: &SigmaBoolean| {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        w.put_u8(0x00);
        w.put_u8(0x08);
        ergo_ser::sigma_value::write_sigma_boolean(&mut w, sb).unwrap();
        read_ergo_tree(&mut VlqReader::new(&w.result())).unwrap()
    };
    let value = 1_000_000_000;
    let locked = ErgoBox::new(
        ErgoBoxCandidate::new(
            value,
            tree(&both),
            0,
            vec![],
            ergo_ser::register::AdditionalRegisters::empty(),
        )
        .unwrap(),
        ModifierId::from_bytes([0x42; 32]),
        0,
    );
    let fixture = fixture();
    let (_, mut view) = case(&fixture["cases"][0]);
    view.utxos = HashMap::from([(*locked.box_id().unwrap().as_bytes(), locked.clone())]);

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RedbWalletStore::new(Arc::new(
        redb::Database::create(dir.path().join("wallet.redb")).unwrap(),
    )));
    let mut engine = WalletEngine::new(WalletEngineParts {
        storage: Arc::new(RwLock::new(ergo_wallet::storage::SecretStorage::open(
            dir.path().join("wallet"),
        ))),
        state: Arc::new(RwLock::new(crate::state::WalletState::empty(false))),
        store,
        chain: Arc::new(ControlledChain(view.clone())),
        config: crate::engine::WalletEngineConfig {
            network: ergo_ser::address::NetworkPrefix::Mainnet,
            expose_private_keys: false,
            reemission: None,
            min_relay_fee_nano_erg: 1_000_000,
            max_tx_size_bytes: 98_304,
        },
        submitter: Arc::new(NoSubmit),
        mempool: Arc::new(crate::engine::NoopMempoolOverlay::new()),
        service: None,
        rescan: Arc::new(crate::engine::RescanCoordinator::new()),
    });
    let custody = Arc::new(RecordingCustody::default());
    engine.set_nonce_custody(custody.clone());
    engine
        .restore(
            mnemonic.phrase().to_string(),
            String::new(),
            "pw".into(),
            false,
        )
        .unwrap();
    engine.unlock("pw".into()).unwrap();

    let unsigned = UnsignedTransaction {
        inputs: vec![ergo_ser::input::UnsignedInput {
            box_id: locked.box_id().unwrap(),
            extension: ergo_ser::input::ContextExtension::empty(),
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate::new(
            value,
            tree(&SigmaBoolean::TrivialProp(true)),
            1,
            vec![],
            ergo_ser::register::AdditionalRegisters::empty(),
        )
        .unwrap()],
    };
    let unsigned_hex = hex::encode(serialize_unsigned_tx(&unsigned).unwrap());
    let message = ergo_ser::transaction::bytes_to_sign(&ergo_ser::transaction::Transaction {
        inputs: unsigned
            .inputs
            .iter()
            .map(|input| ergo_ser::input::Input {
                box_id: input.box_id,
                spending_proof: ergo_ser::input::SpendingProof::new(
                    Vec::new(),
                    input.extension.clone(),
                )
                .unwrap(),
            })
            .collect(),
        data_inputs: vec![],
        output_candidates: unsigned.output_candidates.clone(),
    })
    .unwrap();
    let commit = |engine: &WalletEngine| {
        engine
            .generate_commitments(GenerateCommitmentsRequest {
                unsigned_tx: unsigned_hex.clone(),
                external_secrets: None,
                inputs: None,
                data_inputs: None,
            })
            .unwrap()
    };

    // 1. Bob's wallet commits. Only public data and a handle come back.
    let response = commit(&engine);
    let wire = serde_json::to_string(&response).unwrap();
    let logged = format!("{response:?}");
    let seen = custody.seen.lock().clone();
    assert_eq!(seen.len(), 1);
    for nonce in &seen {
        assert!(!wire.contains(&hex::encode(nonce)), "nonce in response");
        assert!(!logged.contains(&hex::encode(nonce)), "nonce in Debug");
    }
    let bob_bag = response.hints;
    let HintDto::OwnCommitment { secret, .. } = &bob_bag.secret_hints["0"][0] else {
        panic!("own commitment expected");
    };
    assert!(secret.starts_with(crate::engine::NONCE_HANDLE_PREFIX));
    let mut bob_public_dto = bob_bag.clone();
    bob_public_dto.secret_hints.clear();
    let bob_public: Vec<Hint> =
        crate::engine::hints_codec::tx_hints_bag_from_dto(&bob_public_dto, Default::default())
            .unwrap()
            .public_hints[&0]
            .hints
            .clone();
    assert_eq!(bob_public.len(), 1);

    // 2. Alice signs her leaf with her own commitment and Bob's public one.
    let alice_registry = SecretRegistry::empty()
        .merge_external_secrets(&[ProverExternalSecret::Dlog {
            pk: alice_pk,
            scalar: alice_secret.into(),
        }])
        .unwrap();
    let mut alice_hints = ergo_wallet::proving::commitments::generate_commitments_for(
        &both,
        std::slice::from_ref(&alice),
        &mut OsRngBackend,
    )
    .unwrap();
    alice_hints.extend(HintsBag { hints: bob_public });
    let (partial, _) = ergo_wallet::proving::sigma::prove_sigma_partial(
        &both,
        &alice_registry,
        &message,
        &alice_hints,
        &mut OsRngBackend,
    )
    .unwrap();
    let alice_proof =
        ergo_wallet::proving::extract::bag_for_multisig(&both, &partial, &[alice], &[]).unwrap();
    let mut alice_bag = TransactionHintsBag::empty();
    alice_bag.add_for_input(0, alice_proof);
    let alice_dto = crate::engine::hints_codec::tx_hints_bag_to_dto(&alice_bag, None);

    // 3. Bob's wallet completes with the handle plus Alice's public proof.
    let mut hints = bob_bag.clone();
    hints
        .public_hints
        .get_mut("0")
        .unwrap()
        .extend(alice_dto.public_hints["0"].iter().cloned());
    let request = TransactionSignRequest {
        unsigned_tx: UnsignedTxDto {
            bytes: unsigned_hex.clone(),
        },
        external_secrets: None,
        hints: Some(hints),
        inputs: None,
        data_inputs: None,
    };
    let signed = engine
        .transaction_sign(request.clone())
        .expect("2-of-2 signing completes");
    let signed_tx = ergo_ser::transaction::read_transaction(&mut VlqReader::new(
        &hex::decode(signed.transaction.bytes).unwrap(),
    ))
    .unwrap();
    assert!(ergo_sigma::verify::verify_sigma_proof(
        &both,
        &signed_tx.inputs[0].spending_proof.proof,
        &message
    )
    .unwrap());

    // 4. The handle was consumed: the same commitment cannot sign again.
    let reuse = engine.transaction_sign(request.clone()).unwrap_err();
    assert!(
        matches!(&reuse, WalletAdminError::BadRequest(m) if m.contains("already used")),
        "{reuse:?}"
    );

    // 5. A nonce chosen (or replayed) by the caller for Bob's key is refused,
    //    and the refusal does not echo it.
    let chosen_nonce = hex::encode(seen[0]);
    let mut chosen = request.clone();
    if let Some(HintDto::OwnCommitment { secret, .. }) = chosen
        .hints
        .as_mut()
        .and_then(|bag| bag.secret_hints.get_mut("0"))
        .and_then(|hints| hints.first_mut())
    {
        *secret = chosen_nonce.clone();
    }
    let refused = engine.transaction_sign(chosen).unwrap_err();
    assert!(
        matches!(&refused, WalletAdminError::BadRequest(m) if m.contains("caller-supplied secret nonces are refused")),
        "{refused:?}"
    );
    assert!(!format!("{refused:?}").contains(&chosen_nonce));

    // 6. Locking the wallet wipes outstanding handles.
    let fresh = commit(&engine).hints;
    engine.lock().unwrap();
    let wiped = engine
        .transaction_sign(TransactionSignRequest {
            hints: Some(fresh),
            ..request
        })
        .unwrap_err();
    assert!(
        matches!(&wiped, WalletAdminError::BadRequest(m) if m.contains("unknown, expired or already used")),
        "{wiped:?}"
    );
}

/// An engine built without any nonce configuration keeps multisig nonces
/// itself; handing them to the caller is an explicit opt-in.
#[test]
fn an_unconfigured_engine_keeps_nonces_and_caller_mode_is_an_opt_in() {
    use crate::engine::{WalletEngine, WalletEngineParts};
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet_protocol::scala::sending::HintDto;

    let mnemonic =
        ergo_wallet::mnemonic::Mnemonic::generate(ergo_wallet::mnemonic::MnemonicStrength::Words15)
            .unwrap();
    let bob_pk =
        ergo_wallet::extended_key::ExtendedSecretKey::derive_master_key(&mnemonic.to_seed("")[..])
            .unwrap()
            .derive_at_path(&ergo_wallet::derivation::DerivationPath::eip3_first_address())
            .unwrap()
            .public_key()
            .compressed_bytes();
    let bob = SigmaBoolean::ProveDlog(GroupElement::from_bytes(bob_pk));
    let tree = |sb: &SigmaBoolean| {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        w.put_u8(0x00);
        w.put_u8(0x08);
        ergo_ser::sigma_value::write_sigma_boolean(&mut w, sb).unwrap();
        read_ergo_tree(&mut VlqReader::new(&w.result())).unwrap()
    };
    let locked = ErgoBox::new(
        ErgoBoxCandidate::new(
            1_000_000_000,
            tree(&bob),
            0,
            vec![],
            ergo_ser::register::AdditionalRegisters::empty(),
        )
        .unwrap(),
        ModifierId::from_bytes([0x42; 32]),
        0,
    );
    let fixture = fixture();
    let (_, mut view) = case(&fixture["cases"][0]);
    view.utxos = HashMap::from([(*locked.box_id().unwrap().as_bytes(), locked.clone())]);

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(RedbWalletStore::new(Arc::new(
        redb::Database::create(dir.path().join("wallet.redb")).unwrap(),
    )));
    let mut engine = WalletEngine::new(WalletEngineParts {
        storage: Arc::new(RwLock::new(ergo_wallet::storage::SecretStorage::open(
            dir.path().join("wallet"),
        ))),
        state: Arc::new(RwLock::new(crate::state::WalletState::empty(false))),
        store,
        chain: Arc::new(ControlledChain(view.clone())),
        config: crate::engine::WalletEngineConfig {
            network: ergo_ser::address::NetworkPrefix::Mainnet,
            expose_private_keys: false,
            reemission: None,
            min_relay_fee_nano_erg: 1_000_000,
            max_tx_size_bytes: 98_304,
        },
        submitter: Arc::new(NoSubmit),
        mempool: Arc::new(crate::engine::NoopMempoolOverlay::new()),
        service: None,
        rescan: Arc::new(crate::engine::RescanCoordinator::new()),
    });
    engine
        .restore(
            mnemonic.phrase().to_string(),
            String::new(),
            "pw".into(),
            false,
        )
        .unwrap();
    engine.unlock("pw".into()).unwrap();
    let unsigned = UnsignedTransaction {
        inputs: vec![ergo_ser::input::UnsignedInput {
            box_id: locked.box_id().unwrap(),
            extension: ergo_ser::input::ContextExtension::empty(),
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate::new(
            1_000_000_000,
            tree(&SigmaBoolean::TrivialProp(true)),
            1,
            vec![],
            ergo_ser::register::AdditionalRegisters::empty(),
        )
        .unwrap()],
    };
    let unsigned_hex = hex::encode(serialize_unsigned_tx(&unsigned).unwrap());
    let commit = |engine: &WalletEngine| {
        let response = engine
            .generate_commitments(GenerateCommitmentsRequest {
                unsigned_tx: unsigned_hex.clone(),
                external_secrets: None,
                inputs: None,
                data_inputs: None,
            })
            .unwrap();
        let HintDto::OwnCommitment { secret, .. } = &response.hints.secret_hints["0"][0] else {
            panic!("own commitment expected");
        };
        secret.clone()
    };

    // Default: a handle, never the nonce.
    let secret = commit(&engine);
    assert!(
        secret.starts_with(crate::engine::NONCE_HANDLE_PREFIX),
        "{secret}"
    );

    // Opt-in: the Scala wire form returns the 32-byte nonce itself.
    engine.allow_caller_nonces();
    let secret = commit(&engine);
    assert!(
        !secret.starts_with(crate::engine::NONCE_HANDLE_PREFIX),
        "{secret}"
    );
    assert_eq!(hex::decode(&secret).unwrap().len(), 32);
}

#[test]
fn a_dh_tuple_secret_counts_as_caller_held_only_when_its_scalar_matches() {
    let decode = |x: u64, v: u64| {
        decode_external_secret(&ExternalSecretDto::DhTuple {
            g: hex::encode(point(2)),
            h: hex::encode(point(5)),
            u: hex::encode(point(2 * x)),
            v: hex::encode(point(v)),
            x: format!("{x:064x}"),
        })
        .unwrap()
    };
    assert!(crate::engine::send::proven_image(&decode(3, 15)).is_some());
    assert!(crate::engine::send::proven_image(&decode(3, 16)).is_none());
}

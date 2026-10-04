use super::*;
use ergo_mempool::admission::{MockPlan, MockStructure, MockValidator, ValidationErr};
use ergo_mempool::types::{MempoolConfig, TipPointer};
use ergo_mempool::{weight, Mempool};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::{transaction_id, write_transaction, Transaction};

// ----- helpers -----

/// Signed bytes and id of a one-input transaction with a trivially true
/// output, spending box `[input; 32]`.
fn signed_tx(input: u8) -> (Vec<u8>, Digest32) {
    let tx = Transaction {
        inputs: vec![Input {
            box_id: Digest32::from_bytes([input; 32]),
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![ErgoBoxCandidate::new(
            1_000_000,
            read_ergo_tree(&mut VlqReader::new(&[0, 8, 0xd3])).unwrap(),
            100,
            vec![],
            AdditionalRegisters::empty(),
        )
        .unwrap()],
    };
    let mut writer = VlqWriter::new();
    write_transaction(&mut writer, &tx).unwrap();
    let id = transaction_id(&tx).unwrap();
    (writer.result(), Digest32::from_bytes(*id.as_bytes()))
}

fn mining_handle() -> MiningHandle {
    MiningHandle::new(
        [0x02; 33],
        ergo_mining::emission_rules::MonetarySettings::mainnet(),
        None,
        ergo_crypto::difficulty::DifficultyParams::mainnet(),
        ergo_validation::VotingSettings::mainnet(),
    )
}

struct NoBoxes;
impl ergo_validation::UtxoView for NoBoxes {
    fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
        None
    }
}

// ----- admission -----

#[test]
fn admission_rejects_a_transaction_staged_by_public_admission() {
    // An orphan staged from an earlier public submit can be promoted and
    // relayed once its parent arrives, so it cannot become private.
    let tmp = tempfile::tempdir().unwrap();
    let mut state = crate::node::tests::make_state(&tmp.path().join("state.redb"));
    state.mempool = Mempool::new(
        MempoolConfig {
            staging_enabled: true,
            min_relay_fee_nano_erg: 0,
            ..MempoolConfig::default()
        },
        weight::from_config("cost").unwrap(),
    );
    let (bytes, id) = signed_tx(1);
    let validator = MockValidator::new()
        .plan(
            bytes.clone(),
            MockPlan {
                result: Err(ValidationErr::UnresolvedInput),
                charge: 0,
                peek_fee: Some(0),
                peek_tx_id: Some(id),
            },
        )
        .structure(
            bytes.clone(),
            MockStructure {
                tx_id: id,
                fee: 0,
                input_box_ids: vec![Digest32::from_bytes([1; 32])],
                output_box_ids: vec![],
            },
        );
    let tx_context = ergo_validation::TransactionContext {
        height: 101,
        miner_pubkey: [0; 33],
        pre_header_timestamp: 0,
        activated_script_version: 2,
        pre_header_version: 3,
        pre_header_parent_id: [0; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0; 3],
    };
    let params = ergo_validation::ProtocolParams::mainnet_default();
    let tip = ergo_mempool::admission::TipContext {
        tip: TipPointer {
            height: 100,
            header_id: Digest32::from_bytes([9; 32]),
        },
        best_header_height: 100,
        best_full_block_height: 100,
        utxo: &NoBoxes,
        tx_context: &tx_context,
        params: &params,
        last_headers: &[],
        reemission: None,
    };
    state.mempool.process(
        &bytes,
        TxSource::Api,
        std::time::Instant::now(),
        &tip,
        &validator,
    );
    assert!(state.mempool.is_staged(&id), "precondition: staged orphan");

    let handle = mining_handle();
    let error = admit(
        &mut state,
        &handle,
        &bytes,
        PrivateTransactionOptions::default(),
    )
    .expect_err("a staged transaction cannot become private");
    assert!(
        matches!(&error, MiningApiError::BadRequest(detail) if detail.contains("public mempool")),
        "{error:?}"
    );
    assert!(handle.private_queue().list().is_empty());
    assert!(!state.mempool.is_private_transaction(&id));
}

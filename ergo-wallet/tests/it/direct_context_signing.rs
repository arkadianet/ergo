//! Direct signing against explicit chain snapshots, independently checked SDK fixtures.
use ergo_primitives::{digest::ADDigest, reader::VlqReader};
use ergo_ser::{
    ergo_box::{read_ergo_box, ErgoBox, ErgoBoxCandidate},
    pre_header::CandidatePreHeader,
    sigma_value::SigmaValue,
    transaction::{bytes_to_sign, Transaction, UnsignedTransaction},
};
use ergo_sigma::evaluator::SigmaValidationSettings;
use ergo_wallet::{
    proving::{
        external::ProverExternalSecret, hints::TransactionHintsBag, prover::Prover,
        secrets::SecretRegistry,
    },
    tx_context::{BlockchainParameters, BlockchainStateContext, SigningContext},
    ReducedTransaction,
};
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../test-vectors/wallet/reduced_scala_6_0_7.json"
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

fn prover(limit: u64) -> Prover {
    let mut external: Vec<_> = (1..=3)
        .map(|n| ProverExternalSecret::Dlog {
            pk: point(n),
            scalar: Scalar::from(n).into(),
        })
        .collect();
    external.push(ProverExternalSecret::DhTuple {
        g: point(2),
        h: point(2),
        u: point(6),
        v: point(6),
        scalar: Scalar::from(3u64).into(),
    });
    Prover::new(
        SecretRegistry::empty()
            .merge_external_secrets(&external)
            .unwrap(),
        BlockchainParameters {
            max_block_cost: limit,
            input_cost: 2000,
            data_input_cost: 100,
            output_cost: 100,
            token_access_cost: 100,
            interpreter_init_cost: 10000,
            block_version: 4,
        },
    )
}

fn state() -> BlockchainStateContext {
    BlockchainStateContext {
        sigma_last_headers: vec![],
        previous_state_digest: ADDigest::from_bytes([0; 33]),
        sigma_pre_header: CandidatePreHeader {
            version: 4,
            parent_id: [0; 32],
            height: 400000,
            timestamp: 3,
            n_bits: 0,
            votes: [0; 3],
            miner_pubkey: point(1),
        },
    }
}

fn boxes(row: &Value, field: &str) -> Vec<ErgoBox> {
    row[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|encoded| {
            let bytes = hex::decode(encoded.as_str().unwrap()).unwrap();
            let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
            let b = read_ergo_box(&mut reader).unwrap();
            assert_eq!(reader.remaining(), 0);
            b
        })
        .collect()
}

fn reduced(row: &Value) -> ReducedTransaction {
    ReducedTransaction::from_bytes(
        &hex::decode(row["reduced_hex"].as_str().unwrap()).unwrap(),
        4,
    )
    .unwrap()
}

fn assert_signed(row: &Value, frozen: &ReducedTransaction, signed: &Transaction) {
    let message = bytes_to_sign(signed).unwrap();
    assert_eq!(
        hex::encode(&message),
        row["unsigned_message_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(
            ergo_ser::transaction::transaction_id(signed)
                .unwrap()
                .as_bytes()
        ),
        row["transaction_id"].as_str().unwrap()
    );
    assert_eq!(signed.inputs.len(), frozen.reduced_inputs.len());
    for ((input, unsigned), reduction) in signed
        .inputs
        .iter()
        .zip(&frozen.unsigned_transaction.inputs)
        .zip(&frozen.reduced_inputs)
    {
        assert_eq!(input.box_id, unsigned.box_id);
        assert_eq!(input.spending_proof.extension(), &unsigned.extension);
        assert!(
            ergo_sigma::verify::verify_sigma_proof(
                &reduction.sigma,
                &input.spending_proof.proof,
                &message
            )
            .unwrap(),
            "{}",
            row["name"]
        );
    }
}

#[test]
fn direct_explicit_context_signs_all_sdk_contract_fixtures_and_preserves_legacy_gate() {
    let fixture = fixture();
    let settings = SigmaValidationSettings::default();
    for preheader_version in [3, 4] {
        let mut state = state();
        state.sigma_pre_header.version = preheader_version;
        let context = SigningContext {
            state_context: &state,
            header_ids: &[],
            validation_settings: &settings,
        };
        for row in fixture["cases"].as_array().unwrap() {
            let frozen = reduced(row);
            let inputs = boxes(row, "input_boxes");
            let data = boxes(row, "data_boxes");
            let signer = prover(1_000_000);
            let signed = signer
                .sign(
                    &frozen.unsigned_transaction,
                    &inputs,
                    &data,
                    &context,
                    &TransactionHintsBag::empty(),
                )
                .unwrap();
            assert_signed(row, &frozen, &signed);
            if !row["source"].as_str().unwrap().is_empty() {
                let error = signer
                    .sign(
                        &frozen.unsigned_transaction,
                        &inputs,
                        &data,
                        &state,
                        &TransactionHintsBag::empty(),
                    )
                    .unwrap_err();
                assert!(
                    error.to_string().contains("unsupported script family"),
                    "{error}"
                );
            }
        }
    }
}

#[test]
fn direct_signing_uses_actual_height_and_output_creation_context() {
    let fixture = fixture();
    let row = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "height_contract")
        .unwrap();
    let frozen = reduced(row);
    let inputs = boxes(row, "input_boxes");
    let settings = SigmaValidationSettings::default();
    let mut state = state();
    state.sigma_pre_header.height = 350000;
    let context = SigningContext {
        state_context: &state,
        header_ids: &[],
        validation_settings: &settings,
    };
    assert!(prover(1_000_000)
        .sign(
            &frozen.unsigned_transaction,
            &inputs,
            &[],
            &context,
            &TransactionHintsBag::empty()
        )
        .is_err());
    state.sigma_pre_header.height = 350001;
    let context = SigningContext {
        state_context: &state,
        header_ids: &[],
        validation_settings: &settings,
    };
    let signed = prover(1_000_000)
        .sign(
            &frozen.unsigned_transaction,
            &inputs,
            &[],
            &context,
            &TransactionHintsBag::empty(),
        )
        .unwrap();
    assert_signed(row, &frozen, &signed);
    let mut wrong_output = frozen.unsigned_transaction.clone();
    wrong_output.output_candidates[0].creation_height = 101;
    assert!(prover(1_000_000)
        .sign(
            &wrong_output,
            &inputs,
            &[],
            &context,
            &TransactionHintsBag::empty()
        )
        .is_err());
}

#[test]
fn direct_signing_reads_actual_ageusd_oracle_data_registers_and_checks_ids() {
    let fixture = fixture();
    let row = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "ageusd_bank_mint")
        .unwrap();
    let frozen = reduced(row);
    let inputs = boxes(row, "input_boxes");
    let mut data = boxes(row, "data_boxes");
    let state = state();
    let settings = SigmaValidationSettings::default();
    let context = SigningContext {
        state_context: &state,
        header_ids: &[],
        validation_settings: &settings,
    };
    let mut registers = data[0].candidate.additional_registers().clone();
    registers.registers[0].value = SigmaValue::Long(200_000_000);
    let candidate = &data[0].candidate;
    data[0].candidate = ErgoBoxCandidate::new(
        candidate.value,
        candidate.ergo_tree().clone(),
        candidate.creation_height,
        candidate.tokens.clone(),
        registers,
    )
    .unwrap();
    // Stale oracle identity must fail before evaluating the altered contract.
    assert!(prover(1_000_000)
        .sign(
            &frozen.unsigned_transaction,
            &inputs,
            &data,
            &context,
            &TransactionHintsBag::empty()
        )
        .is_err());
    let mut updated_id = frozen.unsigned_transaction.clone();
    updated_id.data_inputs[0].box_id = data[0].box_id().unwrap();
    // The new oracle price changes the mint condition even with a matching ID.
    assert!(prover(1_000_000)
        .sign(
            &updated_id,
            &inputs,
            &data,
            &context,
            &TransactionHintsBag::empty()
        )
        .is_err());
}

#[test]
fn direct_signing_checks_order_and_complete_reduction_plus_proof_budget() {
    let fixture = fixture();
    let state = state();
    let settings = SigmaValidationSettings::default();
    let context = SigningContext {
        state_context: &state,
        header_ids: &[],
        validation_settings: &settings,
    };
    for row in fixture["cases"].as_array().unwrap() {
        let frozen = reduced(row);
        let inputs = boxes(row, "input_boxes");
        let data = boxes(row, "data_boxes");
        let total = row["reduction_cost"].as_u64().unwrap() + row["crypto_cost"].as_u64().unwrap();
        assert!(
            prover(total)
                .sign(
                    &frozen.unsigned_transaction,
                    &inputs,
                    &data,
                    &context,
                    &TransactionHintsBag::empty()
                )
                .is_ok(),
            "{}",
            row["name"]
        );
        assert!(
            prover(total - 1)
                .sign(
                    &frozen.unsigned_transaction,
                    &inputs,
                    &data,
                    &context,
                    &TransactionHintsBag::empty()
                )
                .is_err(),
            "{}",
            row["name"]
        );
        if inputs.len() > 1 {
            let mut reordered = inputs.clone();
            reordered.reverse();
            assert!(prover(1_000_000)
                .sign(
                    &frozen.unsigned_transaction,
                    &reordered,
                    &data,
                    &context,
                    &TransactionHintsBag::empty()
                )
                .is_err());
        }
        let mut wrong_id: UnsignedTransaction = frozen.unsigned_transaction.clone();
        wrong_id.inputs[0].box_id = ergo_primitives::digest::Digest32::from_bytes([0x77; 32]);
        assert!(prover(1_000_000)
            .sign(
                &wrong_id,
                &inputs,
                &data,
                &context,
                &TransactionHintsBag::empty()
            )
            .is_err());
    }
}

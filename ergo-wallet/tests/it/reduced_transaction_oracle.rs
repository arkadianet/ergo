//! Independent Scala SDK wire, reduction-cost and proof fixtures.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use ergo_primitives::{
    digest::{blake2b256, ADDigest},
    reader::VlqReader,
    writer::VlqWriter,
};
use ergo_ser::{
    ergo_box::{read_ergo_box, ErgoBox},
    pre_header::CandidatePreHeader,
    transaction::{bytes_to_sign, UnsignedTransaction},
};
use ergo_sigma::evaluator::SigmaValidationSettings;
use ergo_wallet::{
    proving::{
        commitments::generate_bound_commitments_for_reduced, external::ProverExternalSecret,
        hints::TransactionHintsBag, prover::Prover, randomness::OsRngBackend,
        secrets::SecretRegistry,
    },
    tx_context::{BlockchainParameters, BlockchainStateContext, SigningContext},
    ReducedTransaction,
};
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use serde_json::{json, Value};
use zeroize::Zeroizing;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../test-vectors/wallet/reduced_scala_6_0_7.json"
    ))
    .unwrap()
}
fn parameters(limit: u64) -> BlockchainParameters {
    BlockchainParameters {
        max_block_cost: limit,
        input_cost: 2000,
        data_input_cost: 100,
        output_cost: 100,
        token_access_cost: 100,
        interpreter_init_cost: 10000,
        block_version: 4,
    }
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
    let secrets = SecretRegistry::empty();
    let mut external: Vec<_> = (1..=3)
        .map(|n| ProverExternalSecret::Dlog {
            pk: point(n),
            scalar: Zeroizing::new(Scalar::from(n)),
        })
        .collect();
    external.push(ProverExternalSecret::DhTuple {
        g: point(2),
        h: point(2),
        u: point(6),
        v: point(6),
        scalar: Zeroizing::new(Scalar::from(3u64)),
    });
    let secrets = secrets.merge_external_secrets(&external).unwrap();
    Prover::new(secrets, parameters(limit))
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
fn boxes(row: &Value, key: &str) -> Vec<ErgoBox> {
    row[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let bytes = hex::decode(b.as_str().unwrap()).unwrap();
            let mut r = VlqReader::new(&bytes).with_activated_script_version(3);
            let b = read_ergo_box(&mut r).unwrap();
            assert_eq!(r.remaining(), 0);
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
fn unsigned_message(tx: &UnsignedTransaction) -> Vec<u8> {
    let signed = ergo_ser::transaction::Transaction {
        inputs: tx
            .inputs
            .iter()
            .map(|i| ergo_ser::input::Input {
                box_id: i.box_id,
                spending_proof: ergo_ser::input::SpendingProof::new(vec![], i.extension.clone())
                    .unwrap(),
            })
            .collect(),
        data_inputs: tx.data_inputs.clone(),
        output_candidates: tx.output_candidates.clone(),
    };
    bytes_to_sign(&signed).unwrap()
}

#[test]
fn scala_reduced_wire_costs_and_both_proof_directions() {
    let fixture = fixture();
    let state = state();
    let settings = SigmaValidationSettings::default();
    let context = SigningContext {
        state_context: &state,
        header_ids: &[],
        validation_settings: &settings,
    };
    let prover = prover(1000000);
    let mut reverse = vec![];
    for row in fixture["cases"].as_array().unwrap() {
        let frozen = reduced(row);
        let input = boxes(row, "input_boxes");
        let data = boxes(row, "data_boxes");
        let actual = Prover::new(SecretRegistry::empty(), parameters(1_000_000))
            .reduce_transaction(&frozen.unsigned_transaction, &input, &data, &context)
            .unwrap();
        assert_eq!(
            hex::encode(actual.to_bytes().unwrap()),
            row["reduced_hex"].as_str().unwrap(),
            "{}",
            row["name"]
        );
        assert_eq!(actual.cost as u64, row["reduction_cost"].as_u64().unwrap());
        assert_eq!(
            actual
                .reduced_inputs
                .iter()
                .map(|i| i.cost)
                .collect::<Vec<_>>(),
            row["input_costs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap())
                .collect::<Vec<_>>(),
            "SDK reduced-input costs are cumulative, including transaction initialization/assets"
        );
        let message = unsigned_message(&frozen.unsigned_transaction);
        for (input, proof) in frozen
            .reduced_inputs
            .iter()
            .zip(row["scala_proofs"].as_array().unwrap())
        {
            assert!(ergo_sigma::verify::verify_sigma_proof(
                &input.sigma,
                &hex::decode(proof.as_str().unwrap()).unwrap(),
                &message
            )
            .unwrap());
        }
        let signed = prover
            .sign_reduced(&frozen, &TransactionHintsBag::empty())
            .unwrap();
        assert_eq!(bytes_to_sign(&signed).unwrap(), message);
        for (input, reduction) in signed.inputs.iter().zip(&frozen.reduced_inputs) {
            assert!(ergo_sigma::verify::verify_sigma_proof(
                &reduction.sigma,
                &input.spending_proof.proof,
                &message
            )
            .unwrap());
        }
        let mut wire = VlqWriter::new();
        ergo_ser::transaction::write_transaction(&mut wire, &signed).unwrap();
        let signed_hex = hex::encode(wire.as_slice());
        // AppKit SignedTransaction.toBytes() includes its SDK-only crypto-cost trailer.
        wire.put_u32(row["crypto_cost"].as_u64().unwrap().try_into().unwrap());
        reverse.push(json!({"name":row["name"],"reduced_hex":row["reduced_hex"],
            "signed_hex":signed_hex,"appkit_signed_hex":hex::encode(wire.as_slice()),
            "crypto_cost":row["crypto_cost"],
            "proofs":signed.inputs.iter().map(|i| hex::encode(&i.spending_proof.proof)).collect::<Vec<_>>() }));
    }
    if let Some(path) = std::env::var_os("ERGO_REDUCED_PROOFS_FILE") {
        std::fs::write(path, serde_json::to_vec_pretty(&reverse).unwrap()).unwrap();
    }
}

#[test]
fn reduction_and_signing_enforce_aggregate_cost_before_proof_work() {
    let fixture = fixture();
    let state = state();
    let settings = SigmaValidationSettings::default();
    let context = SigningContext {
        state_context: &state,
        header_ids: &[],
        validation_settings: &settings,
    };
    for row in fixture["cases"].as_array().unwrap() {
        let r = reduced(row);
        let input = boxes(row, "input_boxes");
        let data = boxes(row, "data_boxes");
        assert!(prover(u64::from(r.cost) - 1)
            .reduce_transaction(&r.unsigned_transaction, &input, &data, &context)
            .is_err());
        let total = u64::from(r.cost) + row["crypto_cost"].as_u64().unwrap();
        assert!(prover(total)
            .sign_reduced(&r, &TransactionHintsBag::empty())
            .is_ok());
        assert!(prover(total - 1)
            .sign_reduced(&r, &TransactionHintsBag::empty())
            .is_err());
    }
}

#[test]
fn strict_context_preserves_output_ids_and_rejects_participant_mismatch() {
    let fixture = fixture();
    let row = &fixture["cases"][8];
    let r = reduced(row);
    let input = boxes(row, "input_boxes");
    let data = boxes(row, "data_boxes");
    let state = state();
    let settings = SigmaValidationSettings::default();
    let context = SigningContext {
        state_context: &state,
        header_ids: &[],
        validation_settings: &settings,
    };
    let owned = context
        .build_reduction_owned_for_tx(&r.unsigned_transaction, 0, &input, &data, 3)
        .unwrap();
    let id = blake2b256(&unsigned_message(&r.unsigned_transaction));
    assert_eq!(owned.outputs[0].transaction_id, *id.as_bytes());
    let b = ErgoBox {
        candidate: r.unsigned_transaction.output_candidates[0].clone(),
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes(*id.as_bytes()),
        index: 0,
    };
    assert_eq!(owned.outputs[0].id, *b.box_id().unwrap().as_bytes());
    let mut wrong = r.unsigned_transaction.clone();
    wrong.inputs[0].box_id = ergo_primitives::digest::Digest32::from_bytes([9; 32]);
    assert!(prover(1000000)
        .reduce_transaction(&wrong, &input, &data, &context)
        .is_err());
    if !data.is_empty() {
        let mut wrong = r.unsigned_transaction.clone();
        wrong.data_inputs[0].box_id = ergo_primitives::digest::Digest32::from_bytes([9; 32]);
        assert!(prover(1000000)
            .reduce_transaction(&wrong, &input, &data, &context)
            .is_err());
    }
}

#[test]
fn reduced_parser_rejects_trailing_truncated_oversized_and_malformed_sigma() {
    let fixture = fixture();
    let r = reduced(&fixture["cases"][0]);
    let bytes = r.to_bytes().unwrap();
    for n in 0..bytes.len() {
        assert!(ReducedTransaction::from_bytes(&bytes[..n], 4).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ReducedTransaction::from_bytes(&trailing, 4).is_err());
    assert!(ReducedTransaction::from_bytes(
        &vec![0; ergo_wallet::reduced::MAX_REDUCED_TRANSACTION_BYTES + 1],
        4
    )
    .is_err());
    let mut malformed = r.clone();
    malformed.reduced_inputs[0].sigma = ergo_ser::sigma_value::SigmaBoolean::ProveDlog(
        ergo_primitives::group_element::GroupElement::from_bytes([0x42; 33]),
    );
    assert!(ReducedTransaction::from_bytes(&malformed.to_bytes().unwrap(), 4).is_err());
}

#[test]
fn untrusted_reduced_compounds_reject_non_normal_forms_before_nonce_work() {
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::randomness::ProvingRng;
    #[derive(Default)]
    struct CountingRng {
        calls: usize,
    }
    impl ProvingRng for CountingRng {
        fn sample_scalar(&mut self) -> Scalar {
            self.calls += 1;
            Scalar::ONE
        }
        fn sample_challenge(&mut self) -> [u8; 24] {
            self.calls += 1;
            [0; 24]
        }
    }
    let fixture = fixture();
    let original = reduced(&fixture["cases"][1]);
    let leaf = original.reduced_inputs[0].sigma.clone();
    let prover = prover(1_000_000);
    let mut cases = Vec::new();
    for truth in [false, true] {
        for sigma in [
            SigmaBoolean::Cand(vec![SigmaBoolean::TrivialProp(truth), leaf.clone()].into()),
            SigmaBoolean::Cor(vec![SigmaBoolean::TrivialProp(truth), leaf.clone()].into()),
            SigmaBoolean::Cthreshold {
                k: 1,
                children: vec![SigmaBoolean::TrivialProp(truth), leaf.clone()].into(),
            },
            SigmaBoolean::Cand(
                vec![
                    SigmaBoolean::Cor(vec![leaf.clone(), SigmaBoolean::TrivialProp(truth)].into()),
                    leaf.clone(),
                ]
                .into(),
            ),
        ] {
            cases.push((sigma, "nested trivial proposition"));
        }
    }
    for children in [vec![], vec![leaf.clone()]] {
        cases.push((
            SigmaBoolean::Cand(children.clone().into()),
            "degenerate compound",
        ));
        cases.push((SigmaBoolean::Cor(children.into()), "degenerate compound"));
    }
    for (k, children) in [
        (0, vec![]),
        (0, vec![leaf.clone(), leaf.clone()]),
        (1, vec![leaf.clone()]),
        (2, vec![leaf.clone(), leaf.clone()]),
    ] {
        cases.push((
            SigmaBoolean::Cthreshold {
                k,
                children: children.into(),
            },
            "degenerate threshold",
        ));
    }
    // Malformed descendants must be caught inside an otherwise normal compound.
    cases.push((
        SigmaBoolean::Cand(vec![leaf.clone(), SigmaBoolean::Cor(vec![leaf.clone()].into())].into()),
        "degenerate compound",
    ));
    cases.push((
        SigmaBoolean::Cor(
            vec![
                leaf.clone(),
                SigmaBoolean::Cthreshold {
                    k: 0,
                    children: vec![leaf.clone(), leaf.clone()].into(),
                },
            ]
            .into(),
        ),
        "degenerate threshold",
    ));
    for (sigma, expected_error) in cases {
        let mut malformed = original.clone();
        malformed.reduced_inputs[0].sigma = sigma;
        let bytes = malformed.to_bytes().unwrap();
        let received = ReducedTransaction::from_bytes(&bytes, 4).unwrap();
        // The codec preserves interchange bytes; signing rejects unsupported
        // normal forms before any commitment nonce can be sampled.
        assert_eq!(received.to_bytes().unwrap(), bytes);
        let error = prover
            .sign_reduced(&received, &TransactionHintsBag::empty())
            .unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error}");
        assert!(prover
            .sign_reduced(&malformed, &TransactionHintsBag::empty())
            .is_err());
        assert!(prover
            .sign_reduced_partial(&received, &TransactionHintsBag::empty())
            .is_err());
        let mut rng = CountingRng::default();
        let error = generate_bound_commitments_for_reduced(
            &received,
            4,
            std::slice::from_ref(&leaf),
            &mut rng,
        )
        .unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error}");
        assert_eq!(
            rng.calls, 0,
            "invalid frozen reductions must not consume nonce randomness"
        );
    }
}

#[test]
fn reduced_commitments_sign_once_and_reject_changed_transaction() {
    let fixture = fixture();
    let r = reduced(&fixture["cases"][1]);
    let sigma = r.reduced_inputs[0].sigma.clone();
    let bound = generate_bound_commitments_for_reduced(
        &r,
        4,
        std::slice::from_ref(&sigma),
        &mut OsRngBackend,
    )
    .unwrap();
    assert!(prover(1000000).sign_reduced_bound(&r, bound).is_ok());
    let bound = generate_bound_commitments_for_reduced(&r, 4, &[sigma], &mut OsRngBackend).unwrap();
    let mut changed = r.clone();
    changed.unsigned_transaction.output_candidates[0].value += 1;
    assert!(prover(1000000).sign_reduced_bound(&changed, bound).is_err());
    for replacement in [
        ergo_ser::sigma_value::SigmaBoolean::TrivialProp(true),
        ergo_ser::sigma_value::SigmaBoolean::ProveDlog(
            ergo_primitives::group_element::GroupElement::from_bytes(point(2)),
        ),
    ] {
        let bound = generate_bound_commitments_for_reduced(
            &r,
            4,
            std::slice::from_ref(&r.reduced_inputs[0].sigma),
            &mut OsRngBackend,
        )
        .unwrap();
        let mut substituted = r.clone();
        // The unsigned transaction is identical; only its frozen reduction changed.
        substituted.reduced_inputs[0].sigma = replacement;
        let error = prover(1_000_000)
            .sign_reduced_bound(&substituted, bound)
            .unwrap_err();
        assert!(
            error.to_string().contains("different frozen reduction"),
            "{error}"
        );
    }
}

#[test]
fn reduced_two_party_and_threshold_rounds_keep_secrets_separate() {
    use ergo_ser::sigma_value::SigmaBoolean;
    use ergo_wallet::proving::extract::bag_for_reduced_transaction;
    let fixture = fixture();
    for index in [3, 5] {
        let r = reduced(&fixture["cases"][index]);
        let alice = SigmaBoolean::ProveDlog(
            ergo_primitives::group_element::GroupElement::from_bytes(point(1)),
        );
        let bob = SigmaBoolean::ProveDlog(
            ergo_primitives::group_element::GroupElement::from_bytes(point(2)),
        );
        let carol = SigmaBoolean::ProveDlog(
            ergo_primitives::group_element::GroupElement::from_bytes(point(3)),
        );
        let party = |n| {
            Prover::new(
                SecretRegistry::empty()
                    .merge_external_secrets(&[ProverExternalSecret::Dlog {
                        pk: point(n),
                        scalar: Scalar::from(n).into(),
                    }])
                    .unwrap(),
                parameters(1000000),
            )
        };
        let mut alice_bound = generate_bound_commitments_for_reduced(
            &r,
            4,
            std::slice::from_ref(&alice),
            &mut OsRngBackend,
        )
        .unwrap();
        let mut bob_bound = generate_bound_commitments_for_reduced(
            &r,
            4,
            std::slice::from_ref(&bob),
            &mut OsRngBackend,
        )
        .unwrap();
        alice_bound
            .add_public_hints(&bob_bound.public_hints())
            .unwrap();
        let partial = party(1)
            .sign_reduced_partial_bound(&r, alice_bound)
            .unwrap();
        let message = bytes_to_sign(&partial).unwrap();
        assert!(!ergo_sigma::verify::verify_sigma_proof(
            &r.reduced_inputs[0].sigma,
            &partial.inputs[0].spending_proof.proof,
            &message
        )
        .unwrap());
        let extracted = bag_for_reduced_transaction(&r, &partial, 4, &[alice], &[carol]).unwrap();
        bob_bound.add_public_hints(&extracted).unwrap();
        let signed = party(2).sign_reduced_bound(&r, bob_bound).unwrap();
        assert!(ergo_sigma::verify::verify_sigma_proof(
            &r.reduced_inputs[0].sigma,
            &signed.inputs[0].spending_proof.proof,
            &message
        )
        .unwrap());
    }
}

#[test]
fn reduced_serialization_rejects_shared_exponential_sigma_without_expansion() {
    use ergo_ser::sigma_value::SigmaBoolean;
    let fixture = fixture();
    let mut r = reduced(&fixture["cases"][1]);
    let mut sigma = r.reduced_inputs[0].sigma.clone();
    for _ in 0..30 {
        sigma = SigmaBoolean::Cand(vec![sigma.clone(), sigma].into());
    }
    r.reduced_inputs[0].sigma = sigma;
    assert!(r.to_bytes().is_err());
}

// Transport adapters intentionally stay in the oracle harness. EIP19 is a QR
// payload protocol; a mobile UI / camera implementation is not a core dependency.
fn join_qr_pages(pages: &[Value], direction: &str) -> Result<String, &'static str> {
    let mut chunks = std::collections::BTreeMap::new();
    for raw in pages.iter().rev() {
        let page: Value = serde_json::from_str(raw.as_str().ok_or("invalid QR payload")?)
            .map_err(|_| "invalid envelope")?;
        if page
            .get(if direction == "CSR" { "CSTX" } else { "CSR" })
            .is_some()
        {
            return Err("mixed QR directions");
        }
        let index = match page.get("p") {
            None => 1,
            Some(v) => v.as_u64().ok_or("invalid page index")?,
        };
        let total = match page.get("n") {
            None => 1,
            Some(v) => v.as_u64().ok_or("invalid page count")?,
        };
        if index == 0 || index > total || total != pages.len() as u64 {
            return Err("incomplete QR scan");
        }
        let data = page[direction].as_str().ok_or("wrong QR direction")?;
        if chunks.insert(index, data.to_owned()).is_some() {
            return Err("duplicate QR page");
        }
    }
    if chunks.is_empty() {
        return Err("empty QR scan");
    }
    Ok(chunks.into_values().collect())
}

fn parse_appkit_signed(bytes: &[u8]) -> Result<(ergo_ser::transaction::Transaction, u32), String> {
    let mut reader = VlqReader::new(bytes).with_activated_script_version(3);
    let tx = ergo_ser::transaction::read_transaction(&mut reader).map_err(|e| e.to_string())?;
    // AppKit SignedTransaction is the node transaction followed by VLQ UInt cost.
    let cost = reader.get_u32_exact().map_err(|e| e.to_string())?;
    if reader.remaining() != 0 {
        return Err("trailing AppKit signed transaction bytes".into());
    }
    Ok((tx, cost))
}

#[test]
fn appkit_qr_and_ergopay_payloads_preserve_bytes_participants_extensions_and_proofs() {
    let fixture = fixture();
    let mut request_multipage = false;
    let mut response_multipage = false;
    let mut extension_present = false;
    for row in fixture["cases"].as_array().unwrap() {
        let request_pages = row["csr_qr_low_pages"].as_array().unwrap();
        let response_pages = row["cstx_qr_low_pages"].as_array().unwrap();
        request_multipage |= request_pages.len() > 1;
        response_multipage |= response_pages.len() > 1;
        let request_json = join_qr_pages(request_pages, "CSR").unwrap();
        assert_eq!(request_json, row["cold_request"].as_str().unwrap());
        let request: Value = serde_json::from_str(&request_json).unwrap();
        let bytes = STANDARD
            .decode(request["reducedTx"].as_str().unwrap())
            .unwrap();
        assert_eq!(hex::encode(&bytes), row["reduced_hex"].as_str().unwrap());
        let reduced = ReducedTransaction::from_bytes(&bytes, 4).unwrap();
        assert_eq!(reduced.to_bytes().unwrap(), bytes);
        assert_eq!(
            request["inputs"].as_array().unwrap().len(),
            reduced.unsigned_transaction.inputs.len()
        );
        for ((encoded, input), fixture_box) in request["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&reduced.unsigned_transaction.inputs)
            .zip(row["input_boxes"].as_array().unwrap())
        {
            let bytes = STANDARD.decode(encoded.as_str().unwrap()).unwrap();
            assert_eq!(hex::encode(&bytes), fixture_box.as_str().unwrap());
            let mut reader = VlqReader::new(&bytes).with_activated_script_version(3);
            let b = read_ergo_box(&mut reader).unwrap();
            assert_eq!(reader.remaining(), 0);
            assert_eq!(b.box_id().unwrap(), input.box_id);
            extension_present |= !input.extension.values.is_empty();
        }
        let message = unsigned_message(&reduced.unsigned_transaction);
        assert_eq!(
            hex::encode(&message),
            row["unsigned_message_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(blake2b256(&message).as_bytes()),
            row["transaction_id"].as_str().unwrap()
        );

        // Static ErgoPay's URL-safe alphabet differs from cold QR's standard one.
        let uri = row["ergopay_uri"].as_str().unwrap();
        let b64 = uri.strip_prefix("ergopay:").unwrap();
        assert_eq!(URL_SAFE.decode(b64).unwrap(), bytes);
        assert_eq!(format!("ergopay:{}", URL_SAFE.encode(&bytes)), uri);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(b64.trim_end_matches('=')).unwrap(),
            bytes
        );
        // Dynamic ErgoPay response uses the same encoded reduced object, with metadata.
        let dynamic_json = serde_json::to_string(&row["ergopay_request"]).unwrap();
        let dynamic: Value = serde_json::from_str(&dynamic_json).unwrap();
        assert_eq!(
            URL_SAFE
                .decode(dynamic["reducedTx"].as_str().unwrap())
                .unwrap(),
            bytes
        );

        let response_json = join_qr_pages(response_pages, "CSTX").unwrap();
        assert_eq!(response_json, row["cold_response"].as_str().unwrap());
        let response: Value = serde_json::from_str(&response_json).unwrap();
        let signed_bytes = STANDARD
            .decode(response["signedTx"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            hex::encode(&signed_bytes),
            row["appkit_signed_hex"].as_str().unwrap()
        );
        let (signed, cost) = parse_appkit_signed(&signed_bytes).unwrap();
        assert_eq!(u64::from(cost), row["crypto_cost"].as_u64().unwrap());
        let mut wire = VlqWriter::new();
        ergo_ser::transaction::write_transaction(&mut wire, &signed).unwrap();
        assert_eq!(
            hex::encode(wire.as_slice()),
            row["scala_signed_hex"].as_str().unwrap()
        );
        wire.put_u32(cost);
        assert_eq!(wire.result(), signed_bytes);
        assert_eq!(bytes_to_sign(&signed).unwrap(), message);
        assert_eq!(
            signed.inputs.len(),
            reduced.unsigned_transaction.inputs.len()
        );
        for ((input, unsigned), reduction) in signed
            .inputs
            .iter()
            .zip(&reduced.unsigned_transaction.inputs)
            .zip(&reduced.reduced_inputs)
        {
            assert_eq!(input.box_id, unsigned.box_id);
            assert_eq!(input.spending_proof.extension(), &unsigned.extension);
            assert!(ergo_sigma::verify::verify_sigma_proof(
                &reduction.sigma,
                &input.spending_proof.proof,
                &message
            )
            .unwrap());
        }
        let mut trailing = signed_bytes.clone();
        trailing.push(0);
        assert!(parse_appkit_signed(&trailing).is_err());
        assert!(parse_appkit_signed(&signed_bytes[..signed_bytes.len() - 1]).is_err());
    }
    assert!(request_multipage && response_multipage && extension_present);
}

#[test]
fn qr_transport_oracle_rejects_missing_duplicate_and_mixed_direction_pages() {
    let fixture = fixture();
    let pages = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["csr_qr_low_pages"].as_array().unwrap())
        .find(|p| p.len() > 1)
        .unwrap();
    assert!(join_qr_pages(&pages[..pages.len() - 1], "CSR").is_err());
    let mut duplicate = pages.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(join_qr_pages(&duplicate, "CSR").is_err());
    let mut mixed = pages.clone();
    let mut wrong: Value = serde_json::from_str(mixed[0].as_str().unwrap()).unwrap();
    wrong["CSTX"] = wrong["CSR"].clone();
    mixed[0] = Value::String(serde_json::to_string(&wrong).unwrap());
    assert!(join_qr_pages(&mixed, "CSR").is_err());
    wrong.as_object_mut().unwrap().remove("CSTX");
    for index in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!(null),
        json!(pages.len() + 1),
    ] {
        wrong["p"] = index;
        mixed[0] = Value::String(serde_json::to_string(&wrong).unwrap());
        assert!(join_qr_pages(&mixed, "CSR").is_err());
    }
    // EIP19 envelopes contain no session identifier; equal-count mixed requests
    // require full transaction/input review. Reduction rejects mismatched boxes.
    let first = reduced(&fixture["cases"][0]);
    let other_inputs = boxes(&fixture["cases"][1], "input_boxes");
    let state = state();
    let settings = SigmaValidationSettings::default();
    let context = SigningContext {
        state_context: &state,
        header_ids: &[],
        validation_settings: &settings,
    };
    assert!(prover(1_000_000)
        .reduce_transaction(&first.unsigned_transaction, &other_inputs, &[], &context)
        .is_err());
}

#[test]
fn reduced_endpoints_use_active_parameters_independently_of_preheader_version() {
    let fixture = fixture();
    let row = &fixture["cases"][1]; // Version-zero P2PK spans these activation epochs.
    let encoded = hex::decode(row["reduced_hex"].as_str().unwrap()).unwrap();
    let inputs = boxes(row, "input_boxes");
    for block_version in [2, 3, 4] {
        let frozen = ReducedTransaction::from_bytes(&encoded, block_version).unwrap();
        assert_eq!(frozen.to_bytes().unwrap(), encoded);
        for preheader_version in [3, 4] {
            let mut state = state();
            state.sigma_pre_header.version = preheader_version;
            let settings = SigmaValidationSettings::default();
            let context = SigningContext {
                state_context: &state,
                header_ids: &[],
                validation_settings: &settings,
            };
            let mut params = parameters(1_000_000);
            params.block_version = block_version;
            let owned = context
                .build_reduction_owned_for_tx(
                    &frozen.unsigned_transaction,
                    0,
                    &inputs,
                    &[],
                    params.activated_script_version(),
                )
                .unwrap();
            assert_eq!(owned.pre_header_version, preheader_version);
            assert_eq!(owned.activated_script_version, block_version - 1);
            // Active parameters can differ from the physical header mid-epoch.
            let reducer = Prover::new(SecretRegistry::empty(), params);
            assert_eq!(
                reducer
                    .reduce_transaction(&frozen.unsigned_transaction, &inputs, &[], &context)
                    .unwrap()
                    .to_bytes()
                    .unwrap(),
                encoded
            );
        }
    }
    let settings = SigmaValidationSettings::default();
    let mut state = state();
    state.sigma_pre_header.version = 3;
    let context = SigningContext {
        state_context: &state,
        header_ids: &[],
        validation_settings: &settings,
    };
    for (tree_version, block_version, accepted) in [(3, 4, true), (3, 3, false), (5, 5, false)] {
        let mut input = inputs[0].clone();
        let mut tree = input.candidate.ergo_tree().clone();
        tree.version = tree_version;
        tree.has_size = true;
        input.candidate = ergo_ser::ergo_box::ErgoBoxCandidate::new(
            input.candidate.value,
            tree,
            input.candidate.creation_height,
            input.candidate.tokens.clone(),
            input.candidate.additional_registers().clone(),
        )
        .unwrap();
        let mut tx = reduced(row).unsigned_transaction;
        tx.inputs[0].box_id = input.box_id().unwrap();
        let mut params = parameters(1_000_000);
        params.block_version = block_version;
        let result = Prover::new(SecretRegistry::empty(), params).reduce_transaction(
            &tx,
            &[input],
            &[],
            &context,
        );
        assert_eq!(result.is_ok(), accepted,
            "script version {tree_version}, active block parameters {block_version}, physical preheader 3: {result:?}");
    }
}

#[test]
fn transaction_reduction_rejects_verifier_only_validation_soft_forks() {
    use ergo_ser::{
        ergo_box::ErgoBoxCandidate,
        ergo_tree::read_ergo_tree,
        sigma_type::SigmaType,
        sigma_value::{CollValue, SigmaValue},
    };
    use ergo_sigma::evaluator::RuleStatus;

    let fixture = fixture();
    let row = &fixture["cases"][0];
    let state = state();
    for (script, rule, payload) in [
        ("08020402", 1001, None), // Retained parser validation failure.
        ("00d1d40100", 1000, Some(vec![0x04, 0x02])), // Deserialize type mismatch.
    ] {
        let bytes = hex::decode(script).unwrap();
        let tree = read_ergo_tree(&mut VlqReader::new(&bytes)).unwrap();
        let mut input = boxes(row, "input_boxes").remove(0);
        input.candidate = ErgoBoxCandidate::new(
            input.candidate.value,
            tree,
            input.candidate.creation_height,
            input.candidate.tokens.clone(),
            input.candidate.additional_registers().clone(),
        )
        .unwrap();
        let mut tx = reduced(row).unsigned_transaction;
        tx.inputs[0].box_id = input.box_id().unwrap();
        if let Some(payload) = payload {
            tx.inputs[0].extension.values.insert(
                0,
                (
                    SigmaType::SColl(Box::new(SigmaType::SByte)),
                    SigmaValue::Coll(CollValue::Bytes(payload)),
                ),
            );
        }
        let mut settings = SigmaValidationSettings::default();
        settings.0.insert(rule, RuleStatus::Replaced(2000));
        let context = SigningContext {
            state_context: &state,
            header_ids: &[],
            validation_settings: &settings,
        };
        for block_version in [3, 4] {
            let mut params = parameters(1_000_000);
            params.block_version = block_version;
            let error = Prover::new(SecretRegistry::empty(), params)
                .reduce_transaction(&tx, std::slice::from_ref(&input), &[], &context)
                .expect_err(
                    "unknown scripts must not produce reduced True inputs for cold signing",
                );
            assert!(
                error.to_string().contains("cannot reduce"),
                "script {script}, replaced rule {rule}, active block version {block_version}: {error}",
            );
        }
    }
}

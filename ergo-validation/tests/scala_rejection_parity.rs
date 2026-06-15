//! Oracle-backed rejection parity: validates that our validator rejects
//! the same transactions the Scala node rejects.
//!
//! Each test vector was:
//! 1. Constructed and serialized by Scala (ergo-wallet 6.1.0)
//! 2. Submitted to a running Ergo Scala node's /transactions/check endpoint
//! 3. Rejected by the node with a specific error message
//!
//! This test verifies that our validator also rejects each transaction.

use std::collections::HashMap;

use ergo_primitives::digest::{Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_value::read_constant;
use ergo_ser::token::Token;
use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::CostAccumulator;
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

struct TestUtxo(HashMap<Digest32, ErgoBox>);

impl UtxoView for TestUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.0.get(box_id).cloned()
    }
}

#[derive(serde::Deserialize)]
struct RejectionVector {
    label: String,
    #[serde(rename = "expectedCategory")]
    expected_category: String,
    #[serde(rename = "txHex")]
    tx_hex: String,
    #[serde(rename = "scalaError")]
    scala_error: String,
    height: u32,
    #[serde(rename = "sourceBox")]
    source_box: SourceBoxJson,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct SourceBoxJson {
    #[serde(rename = "boxId")]
    box_id: String,
    value: u64,
    #[serde(rename = "ergoTree")]
    ergo_tree: String,
    #[serde(rename = "creationHeight")]
    creation_height: u32,
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u16,
    #[serde(rename = "additionalRegisters", default)]
    additional_registers: HashMap<String, String>,
    #[serde(default)]
    assets: Vec<serde_json::Value>,
}

fn parse_source_box(json: &SourceBoxJson) -> ErgoBox {
    let tree_bytes = hex::decode(&json.ergo_tree).unwrap();
    let mut r = VlqReader::new(&tree_bytes);
    let ergo_tree = read_ergo_tree(&mut r).unwrap();

    let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
    for (key, val_hex) in &json.additional_registers {
        let reg_idx = match key.as_str() {
            "R4" => 0,
            "R5" => 1,
            "R6" => 2,
            "R7" => 3,
            "R8" => 4,
            "R9" => 5,
            _ => continue,
        };
        let val_bytes = hex::decode(val_hex).unwrap();
        let mut vr = VlqReader::new(&val_bytes);
        let (tpe, value) = read_constant(&mut vr).unwrap();
        reg_vec.push((reg_idx, RegisterValue { tpe, value }));
    }
    reg_vec.sort_by_key(|(idx, _)| *idx);
    let registers = AdditionalRegisters {
        registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
    };

    let tokens: Vec<Token> = json
        .assets
        .iter()
        .map(|asset| {
            let token_id_hex = asset["tokenId"].as_str().unwrap();
            let amount = asset["amount"].as_u64().unwrap();
            let token_id_bytes: [u8; 32] = hex::decode(token_id_hex).unwrap().try_into().unwrap();
            Token {
                token_id: Digest32::from_bytes(token_id_bytes),
                amount,
            }
        })
        .collect();

    let candidate = ErgoBoxCandidate::new(
        json.value,
        ergo_tree,
        json.creation_height,
        tokens,
        registers,
    )
    .unwrap();

    let tx_id_bytes: [u8; 32] = hex::decode(&json.transaction_id)
        .unwrap()
        .try_into()
        .unwrap();
    ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id_bytes),
        index: json.index,
    }
}

/// Load the Scala-sourced rejection corpus and verify our validator
/// rejects every transaction that the Scala node rejected.
#[test]
fn scala_sourced_rejection_parity() {
    let data = std::fs::read_to_string("../test-vectors/mainnet/scala_rejection_corpus.json")
        .expect("scala_rejection_corpus.json not found — run build_rejection_corpus.sh first");
    let vectors: Vec<RejectionVector> = serde_json::from_str(&data).unwrap();

    assert!(!vectors.is_empty(), "corpus should not be empty");

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();

    let mut tested = 0;
    for v in &vectors {
        let source_box = parse_source_box(&v.source_box);
        let box_id = source_box.box_id().unwrap();

        let mut utxo = HashMap::new();
        utxo.insert(box_id, source_box);
        let utxo_view = TestUtxo(utxo);

        let ctx = TransactionContext {
            height: v.height,
            miner_pubkey: [0u8; 33],
            pre_header_timestamp: 0,
            activated_script_version: 2,
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        };

        let tx_bytes = hex::decode(&v.tx_hex).unwrap();
        let mut cost = CostAccumulator::recording_only();
        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
        };

        let result = validate_transaction(&tx_bytes, &utxo_view, &policy, &mut tx_cx);

        assert!(
            result.is_err(),
            "mutation '{}' should be rejected (Scala said: {}), but our validator accepted it",
            v.label,
            &v.scala_error[..v.scala_error.len().min(100)]
        );

        let err = result.unwrap_err();

        // Assert category-level parity with Scala node
        let our_category = match &err {
            ValidationError::NoInputs
            | ValidationError::NoOutputs
            | ValidationError::DuplicateInput { .. }
            | ValidationError::TooManyInputs { .. }
            | ValidationError::TooManyDataInputs { .. }
            | ValidationError::TooManyOutputs { .. }
            | ValidationError::InputBoxNotFound { .. }
            | ValidationError::DataInputBoxNotFound { .. }
            | ValidationError::ResolvedInputsMismatch { .. }
            | ValidationError::ResolvedInputIdMismatch { .. }
            | ValidationError::ResolvedDataInputsMismatch { .. }
            | ValidationError::ResolvedDataInputIdMismatch { .. } => "STRUCTURAL",
            // The "MONETARY" bucket here is intentionally broader than
            // pure ERG / token conservation: it covers everything
            // surfaced by Scala's `validateStateful` / `verifyOutput`
            // path (`ergo-core/.../ErgoTransaction.scala:163-177`),
            // which fires per-output checks alongside the
            // conservation arithmetic. Rules 111 (dust), 112
            // (txFuture), 120 (boxSize), 121 (boxPropositionSize)
            // all land here in the corpus, even though our mempool
            // routes them through `ValidationErr::Structural` for
            // admission fast-fail. The mempool category is about
            // Rust pipeline stage; this category is about Scala
            // verifier provenance — the two intentionally differ.
            ValidationError::ErgNotConserved { .. }
            | ValidationError::TokenNotConserved { .. }
            | ValidationError::NonPositiveTokenAmount { .. }
            | ValidationError::InvalidMinting { .. }
            | ValidationError::OutputValueTooLow { .. }
            | ValidationError::TooManyTokens { .. }
            | ValidationError::BoxTooLarge { .. }
            | ValidationError::PropositionTooLarge { .. }
            | ValidationError::OutputFromFuture { .. }
            | ValidationError::OutputCreationHeightBelowInputs { .. } => "MONETARY",
            ValidationError::ScriptError { .. } => "SCRIPT",
            ValidationError::ProofFailed { .. } => "PROOF",
            ValidationError::CostExceeded { .. } | ValidationError::JitCostOverflow(_) => "COST",
            ValidationError::Deserialization(_) | ValidationError::NonCanonical => "CANONICAL",
            ValidationError::InternalInvariantViolated(_) => "INTERNAL",
        };

        // Scala groups script eval failures and proof failures under one bucket
        // ("Scripts of all transaction inputs should pass verification").
        // Our validator distinguishes ScriptError from ProofFailed.
        // For parity: SCRIPT and PROOF are compatible when Scala says "SCRIPT" or "PROOF".
        let categories_match = our_category == v.expected_category
            || (matches!(our_category, "SCRIPT" | "PROOF")
                && matches!(v.expected_category.as_str(), "SCRIPT" | "PROOF"));

        assert!(
            categories_match,
            "mutation '{}': category mismatch — ours={}, expected={}\n  our error: {:?}\n  scala error: {}",
            v.label, our_category, v.expected_category, err,
            &v.scala_error[..v.scala_error.len().min(120)]
        );

        eprintln!(
            "  {} [expected={}] → [ours={}] {:?}",
            v.label, v.expected_category, our_category, err
        );

        tested += 1;
    }

    assert_eq!(tested, 7, "expected exactly 7 rejection vectors");
    eprintln!(
        "Rejection parity: {tested}/{tested} — all mutations rejected with matching categories"
    );
}

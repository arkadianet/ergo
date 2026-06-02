//! Rejection parity tests: verify that the validation pipeline correctly
//! rejects transactions in each failure category.
//!
//! These are locally-crafted tests (not sourced from the Scala node).
//! They verify that our rejection logic fires correctly for known-bad inputs.

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
use ergo_ser::transaction::{read_transaction, write_transaction, Transaction};

use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::{CostAccumulator, JitCost};
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

struct TestUtxo(HashMap<Digest32, ErgoBox>);

impl UtxoView for TestUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.0.get(box_id).cloned()
    }
}

fn default_ctx() -> TransactionContext {
    TransactionContext {
        height: 100,
        miner_pubkey: [0u8; 33],
        pre_header_timestamp: 0,
        activated_script_version: 0,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
    }
}

fn serialize_tx(tx: &Transaction) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    write_transaction(&mut w, tx).unwrap();
    w.result()
}

/// Build an ErgoTree that trivially reduces to TrivialProp(false).
/// Body = Const { tpe: SSigmaProp, val: SigmaProp(TrivialProp(false)) }
fn false_sigma_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(false)),
        },
    }
}

/// Build an ErgoTree that trivially reduces to TrivialProp(true).
fn true_sigma_tree() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
        },
    }
}

/// Build an ErgoTree that reduces to ProveDlog(generator_point).
/// Uses `build_prove_dlog_ergo_tree` from ergo-crypto's schnorr module.
fn p2pk_tree(pk_bytes: &[u8; 33]) -> ErgoTree {
    let tree_bytes = ergo_sigma::schnorr::build_prove_dlog_ergo_tree(pk_bytes);
    let mut r = VlqReader::new(&tree_bytes);
    ergo_ser::ergo_tree::read_ergo_tree(&mut r).unwrap()
}

fn make_box_with_tree(value: u64, tree: ErgoTree, fill: u8) -> ErgoBox {
    let candidate =
        ErgoBoxCandidate::new(value, tree, 100, vec![], AdditionalRegisters::empty()).unwrap();
    ErgoBox {
        candidate,
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes([fill; 32]),
        index: 0,
    }
}

fn make_input_for_box(b: &ErgoBox, proof: Vec<u8>) -> Input {
    Input {
        box_id: b.box_id().unwrap(),
        spending_proof: SpendingProof::new(proof, ContextExtension::empty()).unwrap(),
    }
}

// ---------------------------------------------------------------------------
// Test 1: script evaluates to false → ProofFailed
// ---------------------------------------------------------------------------

/// An input whose ErgoTree reduces to TrivialProp(false) must be rejected
/// with ProofFailed regardless of the spending proof bytes.
#[test]
fn reject_script_evaluates_to_false() {
    let input_box = make_box_with_tree(1_000_000_000, false_sigma_tree(), 1);
    let input_box_id = input_box.box_id().unwrap();

    let mut utxo_map = HashMap::new();
    utxo_map.insert(input_box_id, input_box.clone());

    // Use a TrivialProp(true) output so monetary conservation holds.
    let output = ErgoBoxCandidate::new(
        1_000_000_000,
        true_sigma_tree(),
        100,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap();

    let tx = Transaction {
        inputs: vec![make_input_for_box(&input_box, vec![])],
        data_inputs: vec![],
        output_candidates: vec![output],
    };
    let tx_bytes = serialize_tx(&tx);
    let utxo = TestUtxo(utxo_map);
    let mut cost = CostAccumulator::recording_only();
    let ctx = default_ctx();
    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut tx_cx = ergo_validation::TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
    };

    let err = validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx).unwrap_err();

    assert!(
        matches!(err, ValidationError::ProofFailed { index: 0 }),
        "expected ProofFailed, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: valid P2PK box with garbage spending proof → ProofFailed or ScriptError
// ---------------------------------------------------------------------------

/// A box protected by a valid ProveDlog proposition must be rejected when
/// the spending proof is garbage bytes that don't satisfy the Schnorr protocol.
#[test]
fn reject_invalid_spending_proof() {
    // secp256k1 generator point (compressed): standard well-known bytes
    let generator_pk: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    let input_box = make_box_with_tree(1_000_000_000, p2pk_tree(&generator_pk), 2);
    let input_box_id = input_box.box_id().unwrap();

    let mut utxo_map = HashMap::new();
    utxo_map.insert(input_box_id, input_box.clone());

    let output = ErgoBoxCandidate::new(
        1_000_000_000,
        true_sigma_tree(),
        100,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap();

    // Schnorr proof is 56 bytes (24 challenge + 32 z). Provide all-0xFF garbage.
    let garbage_proof = vec![0xFF; 56];

    let tx = Transaction {
        inputs: vec![make_input_for_box(&input_box, garbage_proof)],
        data_inputs: vec![],
        output_candidates: vec![output],
    };
    let tx_bytes = serialize_tx(&tx);
    let utxo = TestUtxo(utxo_map);
    let mut cost = CostAccumulator::recording_only();
    let ctx = default_ctx();
    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut tx_cx = ergo_validation::TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
    };

    let err = validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx).unwrap_err();

    assert!(
        matches!(
            err,
            ValidationError::ProofFailed { .. } | ValidationError::ScriptError { .. }
        ),
        "expected ProofFailed or ScriptError, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: transaction exceeding block cost limit → CostExceeded
// ---------------------------------------------------------------------------

/// Load a real mainnet transaction from the blocks 2-10 corpus and validate it
/// with an impossibly low cost limit. The transaction-level init cost alone
/// must exceed a 1-block-unit limit, producing CostExceeded.
#[test]
fn reject_transaction_exceeding_block_cost() {
    #[derive(serde::Deserialize)]
    struct TxVector {
        bytes: String,
        height: u32,
    }

    let data = std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let vectors: Vec<TxVector> = serde_json::from_str(&data).unwrap();

    // Use the block-2 transaction (index 1, since index 0 is the genesis block tx).
    let v = &vectors[1];
    let tx_bytes = hex::decode(&v.bytes).unwrap();

    // Parse and apply block-1's outputs to bootstrap the UTXO.
    let tx1_bytes = hex::decode(&vectors[0].bytes).unwrap();
    let mut r = VlqReader::new(&tx1_bytes);
    let tx1 = read_transaction(&mut r).unwrap();

    let tx1_id = ergo_ser::transaction::transaction_id(&tx1).unwrap();
    let mut utxo_map = HashMap::new();
    for (i, candidate) in tx1.output_candidates.iter().enumerate() {
        let b = ErgoBox {
            candidate: candidate.clone(),
            transaction_id: tx1_id,
            index: i as u16,
        };
        utxo_map.insert(b.box_id().unwrap(), b);
    }
    let utxo = TestUtxo(utxo_map);

    // Load the header to get the real miner pubkey and timestamp.
    #[derive(serde::Deserialize)]
    struct HeaderVector {
        height: u32,
        bytes: String,
    }
    let hdata = std::fs::read_to_string("../test-vectors/mainnet/headers_1_10.json").unwrap();
    let headers: Vec<HeaderVector> = serde_json::from_str(&hdata).unwrap();
    let hv = headers.iter().find(|h| h.height == v.height).unwrap();
    let header_bytes = hex::decode(&hv.bytes).unwrap();
    let mut hr = VlqReader::new(&header_bytes);
    let header = ergo_ser::header::read_header(&mut hr).unwrap();

    let ctx = TransactionContext {
        height: v.height,
        miner_pubkey: *header.solution.pk().as_bytes(),
        pre_header_timestamp: header.timestamp,
        activated_script_version: 2,
        pre_header_version: 0,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
    };

    // Limit of 1 block-cost unit → JitCost::from_jit(10). The init cost for even a minimal
    // transaction is INTERPRETER_INIT_COST (10_000) which far exceeds this.
    let mut cost = CostAccumulator::new(JitCost::from_block_cost(1).unwrap());
    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut tx_cx = ergo_validation::TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
    };

    let err = validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx).unwrap_err();

    assert!(
        matches!(err, ValidationError::CostExceeded { .. }),
        "expected CostExceeded, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: non-canonical encoding (trailing byte) → Deserialization
// ---------------------------------------------------------------------------

/// Appending a trailing 0x00 byte to valid transaction bytes must produce
/// a Deserialization error (trailing bytes are not consumed).
#[test]
fn reject_non_canonical_encoding() {
    #[derive(serde::Deserialize)]
    struct TxVector {
        bytes: String,
    }

    let data = std::fs::read_to_string("../test-vectors/mainnet/transactions_1_10.json").unwrap();
    let vectors: Vec<TxVector> = serde_json::from_str(&data).unwrap();

    // Use block-1's tx bytes (structural validation fires before UTXO lookup).
    let mut tx_bytes = hex::decode(&vectors[0].bytes).unwrap();
    tx_bytes.push(0x00); // trailing garbage

    // No UTXO needed — deserialization error fires first.
    let utxo = TestUtxo(HashMap::new());
    let mut cost = CostAccumulator::recording_only();
    let ctx = default_ctx();
    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut tx_cx = ergo_validation::TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
    };

    let err = validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx).unwrap_err();

    assert!(
        matches!(err, ValidationError::Deserialization(_)),
        "expected Deserialization, got: {err}"
    );
}

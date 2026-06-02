//! Negative validation tests: assert that each validation stage
//! rejects the right kind of bad transaction at the right stage.

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::input::{ContextExtension, DataInput, Input, SpendingProof};
use ergo_ser::opcode::Expr;
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::token::{Token, TokenId};
use ergo_ser::transaction::Transaction;

use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::{CostAccumulator, CostError, JitCost};
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

struct TestUtxo(HashMap<Digest32, ErgoBox>);

impl UtxoView for TestUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.0.get(box_id).cloned()
    }
}

fn simple_tree() -> ErgoTree {
    // TrivialTrue — SigmaProp constant that always validates
    ErgoTree {
        version: 0,
        has_size: true,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(ergo_ser::sigma_value::SigmaBoolean::TrivialProp(true)),
        },
    }
}

fn make_candidate(value: u64) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(
        value,
        simple_tree(),
        100,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap()
}

fn make_input(fill: u8) -> Input {
    Input {
        box_id: Digest32::from_bytes([fill; 32]),
        spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
    }
}

fn make_ergo_box(value: u64, fill: u8) -> ErgoBox {
    let candidate = make_candidate(value);
    ErgoBox {
        candidate,
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes([fill; 32]),
        index: 0,
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
    ergo_ser::transaction::write_transaction(&mut w, tx).unwrap();
    w.result()
}

// --- Structural validation tests ---

#[test]
fn reject_no_inputs() {
    let tx = Transaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![make_candidate(1_000_000_000)],
    };
    let tx_bytes = serialize_tx(&tx);
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
    assert!(matches!(err, ValidationError::NoInputs));
}

#[test]
fn reject_duplicate_inputs() {
    let tx = Transaction {
        inputs: vec![make_input(1), make_input(1)],
        data_inputs: vec![],
        output_candidates: vec![make_candidate(1_000_000_000)],
    };
    let tx_bytes = serialize_tx(&tx);
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
    assert!(matches!(err, ValidationError::DuplicateInput { index: 1 }));
}

#[test]
fn reject_output_value_too_low() {
    let tx = Transaction {
        inputs: vec![make_input(1)],
        data_inputs: vec![],
        output_candidates: vec![make_candidate(1)], // 1 nanoErg, way below minimum
    };
    let tx_bytes = serialize_tx(&tx);
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
    assert!(matches!(err, ValidationError::OutputValueTooLow { .. }));
}

// --- State-dependent: missing input box ---

#[test]
fn reject_missing_input_box() {
    let tx = Transaction {
        inputs: vec![make_input(1)],
        data_inputs: vec![],
        output_candidates: vec![make_candidate(1_000_000_000)],
    };
    let tx_bytes = serialize_tx(&tx);
    // Empty UTXO — input box won't be found
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
    assert!(matches!(err, ValidationError::InputBoxNotFound { .. }));
}

// --- Monetary: ERG not conserved ---

#[test]
fn reject_erg_inflation() {
    let input_box = make_ergo_box(1_000_000_000, 1); // 1 ERG input
    let input_box_id = input_box.box_id().unwrap();
    let mut utxo_map = HashMap::new();
    utxo_map.insert(input_box_id, input_box);
    let utxo = TestUtxo(utxo_map);

    let tx = Transaction {
        inputs: vec![Input {
            box_id: input_box_id,
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![make_candidate(2_000_000_000)], // 2 ERG output > 1 ERG input
    };
    let tx_bytes = serialize_tx(&tx);
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
    assert!(matches!(err, ValidationError::ErgNotConserved { .. }));
}

// --- Monetary: invalid token minting ---

#[test]
fn reject_invalid_token_minting() {
    let input_box = make_ergo_box(1_000_000_000, 1);
    let input_box_id = input_box.box_id().unwrap();
    let mut utxo_map = HashMap::new();
    utxo_map.insert(input_box_id, input_box);
    let utxo = TestUtxo(utxo_map);

    // Output has a token whose ID != inputs[0].boxId
    let fake_token_id = TokenId::from_bytes([0xAA; 32]);
    let output = ErgoBoxCandidate::new(
        500_000_000,
        simple_tree(),
        100,
        vec![Token {
            token_id: fake_token_id,
            amount: 100,
        }],
        AdditionalRegisters::empty(),
    )
    .unwrap();

    let tx = Transaction {
        inputs: vec![Input {
            box_id: input_box_id,
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![output],
    };
    let tx_bytes = serialize_tx(&tx);
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
    assert!(matches!(err, ValidationError::InvalidMinting { .. }));
}

// --- Cost accumulator: recording vs enforcing ---

#[test]
fn cost_recording_only_never_rejects() {
    let mut cost = CostAccumulator::recording_only();
    for _ in 0..1_000_000 {
        cost.add(JitCost::try_from_jit(1000).unwrap()).unwrap();
    }
    assert_eq!(cost.total(), JitCost::try_from_jit(1_000_000_000).unwrap());
}

#[test]
fn cost_enforcing_rejects_over_limit() {
    let mut cost = CostAccumulator::new(JitCost::try_from_jit(100).unwrap());
    cost.add(JitCost::try_from_jit(50).unwrap()).unwrap();
    cost.add(JitCost::try_from_jit(50).unwrap()).unwrap();
    let err = cost.add(JitCost::try_from_jit(1).unwrap()).unwrap_err();
    assert!(matches!(
        err,
        CostError::LimitExceeded {
            current: 101,
            limit: 100
        }
    ));
}

// --- Canonical encoding ---

#[test]
fn reject_trailing_bytes() {
    let tx = Transaction {
        inputs: vec![make_input(1)],
        data_inputs: vec![],
        output_candidates: vec![make_candidate(1_000_000_000)],
    };
    let mut tx_bytes = serialize_tx(&tx);
    tx_bytes.push(0xFF); // trailing garbage
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
    assert!(matches!(err, ValidationError::Deserialization(_)));
}

// --- Duplicate data inputs ---

#[test]
fn allow_duplicate_data_inputs() {
    // Duplicate data inputs are allowed per Scala consensus (read-only references).
    // Build a fully-resolvable transaction to prove it passes structural validation.
    let input_box = make_ergo_box(2_000_000_000, 1);
    let input_box_id = input_box.box_id().unwrap();
    let data_box = make_ergo_box(1_000_000_000, 2);
    let data_box_id = data_box.box_id().unwrap();

    let tx = Transaction {
        inputs: vec![Input {
            box_id: input_box_id,
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![
            DataInput {
                box_id: data_box_id,
            },
            DataInput {
                box_id: data_box_id,
            }, // duplicate — should be allowed
        ],
        output_candidates: vec![make_candidate(1_000_000_000)],
    };
    let tx_bytes = serialize_tx(&tx);
    let mut utxo_map = HashMap::new();
    utxo_map.insert(input_box_id, input_box);
    utxo_map.insert(data_box_id, data_box);
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

    // Transaction must pass validation — TrivialTrue script, valid monetary, duplicates allowed.
    validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx)
        .expect("duplicate data inputs should be accepted");
}

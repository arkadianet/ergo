//! Oracle: test-vectors/weak-blocks/soft_fields.json
//!
//! Scala-vectored parity for `TxValidationRules::soft_fields_allowed`
//! (Task 7): for each script/policy pair the Scala harness recorded
//! (`scripts/jvm_weak_blocks_oracle/WeakBlocksOracle.scala::softFieldCases`),
//! build a one-input transaction spending a synthetic box whose ErgoTree is
//! the vector's `tree_hex`, validate it under the matching
//! `soft_fields_allowed` policy, and assert the outcome and (for the `Ok`
//! cases) the raw per-input JIT evaluation cost match the JVM reference.

use ergo_primitives::cost::CostAccumulator;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::{read_ergo_tree, ErgoTree};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::sigma_value::SECP256K1_GENERATOR;
use ergo_ser::transaction::Transaction;

use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction_parsed;
use ergo_validation::{TxValidationCtx, TxValidationRules};

use serde::Deserialize;

// ----- helpers -----

#[derive(Debug, Deserialize)]
struct SoftFieldCase {
    name: String,
    tree_hex: String,
    soft_fields_allowed: bool,
    outcome: String,
    error_class: String,
    cost: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SoftFieldVector {
    cases: Vec<SoftFieldCase>,
}

fn parse_tree(tree_hex: &str) -> ErgoTree {
    let bytes = hex::decode(tree_hex).unwrap();
    let mut r = VlqReader::new(&bytes);
    read_ergo_tree(&mut r).expect("parse soft_fields.json tree_hex")
}

fn make_box(tree: ErgoTree, value: u64, fill: u8, creation_height: u32) -> ErgoBox {
    let candidate = ErgoBoxCandidate::new(
        value,
        tree,
        creation_height,
        vec![],
        AdditionalRegisters::empty(),
    )
    .unwrap();
    ErgoBox {
        candidate,
        transaction_id: ergo_primitives::digest::ModifierId::from_bytes([fill; 32]),
        index: 0,
    }
}

fn serialize_tx(tx: &Transaction) -> Vec<u8> {
    let mut w = ergo_primitives::writer::VlqWriter::new();
    ergo_ser::transaction::write_transaction(&mut w, tx).unwrap();
    w.result()
}

fn run_case(case: &SoftFieldCase) -> Result<u64, ValidationError> {
    let tree = parse_tree(&case.tree_hex);
    let value = 1_000_000_000u64;
    let input_box = make_box(tree.clone(), value, 0x11, 100);
    let box_id = input_box.box_id().expect("box_id");
    let output_candidate =
        ErgoBoxCandidate::new(value, tree, 100, vec![], AdditionalRegisters::empty()).unwrap();

    let tx = Transaction {
        inputs: vec![Input {
            box_id,
            spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
        }],
        data_inputs: vec![],
        output_candidates: vec![output_candidate],
    };
    let tx_bytes = serialize_tx(&tx);

    let ctx = TransactionContext {
        height: 100,
        miner_pubkey: SECP256K1_GENERATOR,
        pre_header_timestamp: 3,
        activated_script_version: 3,
        pre_header_version: 4,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
    };
    let params = ProtocolParams::mainnet_default();

    let mut cost = CostAccumulator::recording_only();
    let mut tx_cx = TxValidationCtx {
        ctx: &ctx,
        params: &params,
        cost: &mut cost,
        last_headers: &[],
        rules: TxValidationRules {
            reemission: None,
            soft_fields_allowed: case.soft_fields_allowed,
        },
    };

    ergo_sigma::cost_trace::enable();
    let result =
        validate_transaction_parsed(tx, &tx_bytes, vec![input_box], vec![], false, &mut tx_cx);
    let trace = ergo_sigma::cost_trace::take().unwrap();

    result.map(|_| {
        // Raw (unsnapped) per-input eval JIT cost: `InputStart:0`'s recorded
        // total is `reduce.rs`'s `pre_eval` baseline (no rent/deserialize
        // charge lands between the two for this synthetic single-input tx);
        // the first `snap_to_block_boundary` entry's `before` is the
        // accumulated total right before Rust truncates it to the block
        // boundary and adds crypto cost — the same point the Scala harness
        // reads via `accu.totalCost.value` (which never truncates or adds
        // crypto). Subtracting isolates exactly the evaluator-only JIT cost
        // Scala recorded, independent of tx-init cost bookkeeping.
        let start = trace
            .entries
            .iter()
            .find(|e| e.label == "InputStart:0")
            .expect("InputStart:0 recorded")
            .total;
        let before_snap = trace.snaps.first().expect("one snap for input 0").0;
        before_snap - start
    })
}

// ----- oracle parity -----

#[test]
fn soft_fields_oracle_parity() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-vectors/weak-blocks/soft_fields.json"
    ))
    .expect("read soft_fields.json");
    let vector: SoftFieldVector = serde_json::from_str(&raw).expect("parse soft_fields.json");
    assert!(!vector.cases.is_empty());

    for case in &vector.cases {
        let result = run_case(case);
        match case.outcome.as_str() {
            "Ok" => {
                let cost = result.unwrap_or_else(|e| {
                    panic!(
                        "{} (soft_fields_allowed={}): expected Ok, got {e}",
                        case.name, case.soft_fields_allowed
                    )
                });
                if let Some(expected_cost) = case.cost {
                    assert_eq!(
                        cost, expected_cost,
                        "{} (soft_fields_allowed={}): JIT eval cost mismatch",
                        case.name, case.soft_fields_allowed
                    );
                }
            }
            "SoftFieldAccess" => {
                let err = result.err().unwrap_or_else(|| {
                    panic!(
                        "{} (soft_fields_allowed={}): expected SoftFieldAccess, Rust accepted",
                        case.name, case.soft_fields_allowed
                    )
                });
                assert!(
                    matches!(err, ValidationError::SoftFieldAccess { index: 0, .. }),
                    "{} (soft_fields_allowed={}): expected SoftFieldAccess, got {err:?}",
                    case.name,
                    case.soft_fields_allowed
                );
                assert_eq!(
                    case.error_class, "SoftFieldAccessException",
                    "{} (soft_fields_allowed={}): vector's error_class should be \
                     SoftFieldAccessException for a SoftFieldAccess outcome",
                    case.name, case.soft_fields_allowed
                );
            }
            other => panic!("unexpected outcome {other} in soft_fields.json"),
        }
    }
}

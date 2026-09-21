//! Oracle: test-vectors/weak-blocks/input_block_validation.json
//!
//! Scala-vectored parity for `ergo_validation::input_block::
//! validate_input_block_transactions` (Plan 1 Task 9) against the reference
//! node's own `UtxoState.applyInputBlock`
//! (`scripts/jvm_weak_blocks_oracle/WeakBlocksOracle.scala::
//! inputBlockValidationCases`).
//!
//! The harness builds a real UTXO state, advances it by three real full
//! blocks, then records the verdict and block cost of `applyInputBlock` for
//! fourteen scenarios — including three whose box scripts read `HEIGHT`,
//! `CONTEXT.headers(0).id` and `CONTEXT.preHeader.height`, so spec 6.4's
//! context mapping is pinned by Scala rather than assumed. This test rebuilds the same inputs in memory — the UTXO set
//! from `utxo_boxes_hex`, the spec-6.4 validation context from
//! `last_headers_hex` (tip first) and `current_parameters` — and asserts the
//! Rust verdict, the rejection class, and (for accepted blocks) the summed
//! block cost all match the JVM.

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::{read_header, Header};
use ergo_ser::transaction::{read_transaction, Transaction};

use ergo_validation::context::{ProtocolParams, TransactionContext, UtxoView};
use ergo_validation::error::ValidationError;
use ergo_validation::input_block::{
    validate_input_block_transactions, InputBlockTxBytes, InputBlockValidationError,
};
use ergo_validation::TxValidationRules;

use serde::Deserialize;

// ----- helpers -----

#[derive(Debug, Deserialize)]
struct InputBlockCase {
    name: String,
    last_headers_hex: Vec<String>,
    current_parameters: HashMap<String, i64>,
    utxo_boxes_hex: Vec<String>,
    previous_tx_hex: Vec<String>,
    tx_hex: Vec<String>,
    outcome: String,
    /// Simple name of the JVM throwable `applyInputBlock` returned.
    error_class: String,
    error_message: String,
    /// Scala-derived discriminator: the case's first transaction validates
    /// under `softFieldsAllowed = true` and fails under `false`, i.e. Scala
    /// rejected it *because of* a soft pre-header field. Needed because Scala
    /// buries `SoftFieldAccessException` inside a generic
    /// `MalformedModifierError("Scripts ... should pass verification")`.
    soft_field_sensitive: bool,
    cost: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct InputBlockVector {
    cases: Vec<InputBlockCase>,
}

/// In-memory UTXO set built from the vector's `utxo_boxes_hex`.
struct MapUtxo(HashMap<Digest32, ErgoBox>);

impl UtxoView for MapUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.0.get(box_id).cloned()
    }
}

fn parse_hex_list<T>(items: &[String], f: impl Fn(&mut VlqReader) -> T) -> Vec<T> {
    items
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).expect("vector hex");
            let mut r = VlqReader::new(&bytes);
            f(&mut r)
        })
        .collect()
}

fn parse_txs(items: &[String]) -> Vec<Transaction> {
    parse_hex_list(items, |r| read_transaction(r).expect("vector tx bytes"))
}

fn tx_bytes(items: &[String]) -> Vec<Vec<u8>> {
    items.iter().map(|h| hex::decode(h).unwrap()).collect()
}

/// Scala `Parameters.parametersTable` ids (`settings/Parameters.scala`).
fn params_from_table(table: &HashMap<String, i64>) -> ProtocolParams {
    let get = |id: &str| -> i64 {
        *table
            .get(id)
            .unwrap_or_else(|| panic!("current_parameters missing id {id}"))
    };
    let mut p = ProtocolParams::mainnet_default();
    p.storage_fee_factor = get("1") as i32;
    p.min_value_per_byte = get("2") as u64;
    p.max_block_size = get("3") as u32;
    p.max_block_cost = get("4") as u64;
    p.token_access_cost = get("5") as u64;
    p.input_cost = get("6") as u64;
    p.data_input_cost = get("7") as u64;
    p.output_cost = get("8") as u64;
    p
}

/// Spec 6.4: the context is the state context of the LAST APPLIED full block
/// `B` — pre-header from `B`, `CONTEXT.headers` the headers before `B`,
/// `activated_script_version = blockVersion - 1` from the state's parameters.
fn context_for(case: &InputBlockCase, params_table: &HashMap<String, i64>) -> TransactionContext {
    let headers: Vec<Header> = parse_hex_list(&case.last_headers_hex, |r| {
        read_header(r).expect("vector header bytes")
    });
    let b = headers.first().expect("non-empty last_headers_hex");
    let block_version = *params_table.get("123").expect("blockVersion param") as u8;
    TransactionContext {
        height: b.height,
        miner_pubkey: *b.solution.pk().as_bytes(),
        pre_header_timestamp: b.timestamp,
        activated_script_version: block_version.saturating_sub(1),
        pre_header_version: b.version,
        pre_header_parent_id: *b.parent_id.as_bytes(),
        pre_header_n_bits: b.n_bits as u64,
        pre_header_votes: b.votes,
    }
}

fn run_case(case: &InputBlockCase) -> Result<u64, InputBlockValidationError> {
    let boxes: Vec<ErgoBox> = parse_hex_list(&case.utxo_boxes_hex, |r| {
        read_ergo_box(r).expect("vector box bytes")
    });
    let utxo = MapUtxo(
        boxes
            .into_iter()
            .map(|b| (b.box_id().expect("box_id"), b))
            .collect(),
    );

    let previous = parse_txs(&case.previous_tx_hex);
    let previous_refs: Vec<&Transaction> = previous.iter().collect();

    let txs = parse_txs(&case.tx_hex);
    let raw = tx_bytes(&case.tx_hex);
    let items: Vec<InputBlockTxBytes<'_>> = txs
        .iter()
        .zip(raw.iter())
        .map(|(tx, bytes)| InputBlockTxBytes {
            bytes: bytes.as_slice(),
            tx,
        })
        .collect();

    let params = params_from_table(&case.current_parameters);
    let tx_ctx = context_for(case, &case.current_parameters);
    // `sigmaLastHeaders = lastHeaders.drop(1)`.
    let all_headers: Vec<Header> = parse_hex_list(&case.last_headers_hex, |r| {
        read_header(r).expect("vector header bytes")
    });
    let last_headers = &all_headers[1..];

    validate_input_block_transactions(
        &items,
        &previous_refs,
        &utxo,
        &tx_ctx,
        &params,
        last_headers,
        TxValidationRules {
            soft_fields_allowed: false,
            ..Default::default()
        },
    )
}

// ----- oracle parity -----

#[test]
fn input_block_validation_matches_scala_apply_input_block() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-vectors/weak-blocks/input_block_validation.json"
    ))
    .expect("read input_block_validation.json");
    let vector: InputBlockVector =
        serde_json::from_str(&raw).expect("parse input_block_validation.json");
    assert_eq!(vector.cases.len(), 14, "expected the full scenario table");
    // Coverage that cannot be inferred from the outcome column alone, so it
    // must be named: the cumulative-budget check (`input_block.rs`'s running
    // `total` against `max_block_cost`) is only reachable when two
    // transactions each fit the limit on their own but their sum does not, and
    // spec 6.4's context mapping is only pinned by scripts that read the
    // height and the headers of the state context (a wrong mapping would make
    // these three reject where Scala accepts).
    for required in [
        "cumulative_cost_limit_rejected",
        "height_sensitive_ok",
        "headers_sensitive_ok",
        "preheader_height_sensitive_ok",
    ] {
        assert!(
            vector.cases.iter().any(|c| c.name == required),
            "vector must cover {required}"
        );
    }

    for case in &vector.cases {
        let result = run_case(case);
        match case.outcome.as_str() {
            "Ok" => {
                let cost = result.unwrap_or_else(|e| {
                    panic!("{}: Scala accepted, Rust rejected with {e}", case.name)
                });
                assert_eq!(
                    Some(cost),
                    case.cost,
                    "{}: block cost mismatch vs Scala",
                    case.name
                );
                assert!(
                    case.error_class.is_empty(),
                    "{}: an accepted case must carry no error_class, got {:?}",
                    case.name,
                    case.error_class
                );
            }
            "Failure" => {
                let err = result
                    .err()
                    .unwrap_or_else(|| panic!("{}: Scala rejected, Rust accepted", case.name));
                assert_rejection_class(case, &err);
            }
            other => panic!("{}: unexpected outcome {other}", case.name),
        }
    }
}

/// Map Scala's rejection reason onto the Rust error variant that must carry
/// it. Each branch pins **both** halves of the JVM verdict: the throwable class
/// `applyInputBlock` returned (`error_class`) and the message that selects the
/// rule, plus the `soft_field_sensitive` discriminator for the one rejection
/// Scala reports without a distinguishing class or message.
fn assert_rejection_class(case: &InputBlockCase, err: &InputBlockValidationError) {
    let msg = case.error_message.as_str();
    let class = case.error_class.as_str();
    // Scala raises the ordering / double-spend guards as a bare
    // `new Exception(...)` inside `applyInputBlock`, while every rejection that
    // comes out of `execTransactions` is wrapped by `ModifierValidator` into a
    // `MalformedModifierError`. Pinning the class keeps a regenerated vector
    // from silently re-routing a case through a different Scala code path.
    let expect_class = |expected: &str| {
        assert_eq!(
            class, expected,
            "{}: expected Scala error_class {expected}, vector has {class}",
            case.name
        )
    };

    if case.soft_field_sensitive {
        // F9a: Scala buries `SoftFieldAccessException` inside the generic
        // script-verification failure, so the class alone cannot identify it.
        expect_class("MalformedModifierError");
        assert!(
            msg.contains("Scripts of all transaction inputs should pass verification"),
            "{}: a soft-field rejection must surface as a script failure, got {msg:?}",
            case.name
        );
        assert!(
            matches!(
                err,
                InputBlockValidationError::Transaction {
                    error: ValidationError::SoftFieldAccess { .. },
                    ..
                }
            ),
            "{}: expected a soft-field rejection, got {err:?}",
            case.name
        );
    } else if msg.starts_with("Double spending") {
        expect_class("Exception");
        assert!(
            matches!(
                err,
                InputBlockValidationError::DoubleSpendPrevious { .. }
                    | InputBlockValidationError::DoubleSpendCurrent { .. }
            ),
            "{}: expected a double-spend rejection, got {err:?}",
            case.name
        );
    } else if msg.starts_with("Out-of-order spending") {
        expect_class("Exception");
        assert!(
            matches!(err, InputBlockValidationError::OutOfOrder { .. }),
            "{}: expected an out-of-order rejection, got {err:?}",
            case.name
        );
    } else if msg.contains("Every input of the transaction should be in UTXO") {
        expect_class("MalformedModifierError");
        assert!(
            matches!(
                err,
                InputBlockValidationError::Transaction {
                    error: ValidationError::InputBoxNotFound { .. },
                    ..
                }
            ),
            "{}: expected a missing-input rejection, got {err:?}",
            case.name
        );
    } else if msg.contains("Accumulated cost of block transactions should not exceed") {
        expect_class("MalformedModifierError");
        // Scala trips `bsBlockTransactionsCost` on `accumulatedCost +
        // initialCost`, so one vector (`cost_limit_rejected`) fails on the
        // transaction's own cost and the other
        // (`cumulative_cost_limit_rejected`, limit 20000 against two 12105-cost
        // transactions) only on the running block total. Rust reaches the first
        // through its per-tx accumulator cap and the second through the block
        // budget; both are accepted here because Scala only promises "rejected
        // on cost", and the two vectors together cover both Rust paths.
        assert!(
            matches!(
                err,
                InputBlockValidationError::CostExceeded { .. }
                    | InputBlockValidationError::Transaction {
                        error: ValidationError::CostExceeded { .. },
                        ..
                    }
            ),
            "{}: expected a cost-limit rejection, got {err:?}",
            case.name
        );
    } else {
        panic!("{}: unclassified Scala rejection {msg:?}", case.name);
    }
}

//! Transaction validation corpus: validates real mainnet transactions
//! through the full pipeline (structural, monetary, script).
//!
//! Uses chain-sequential UTXO tracking: parse each block's transaction,
//! validate it against the accumulated UTXO set, then add its outputs
//! to the UTXO set for subsequent blocks.

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::{read_header, Header};
use ergo_ser::transaction::{bytes_to_sign, read_transaction, Transaction};

use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::{CostAccumulator, JitCost};
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

/// In-memory UTXO set for testing.
struct TestUtxo {
    boxes: HashMap<Digest32, ErgoBox>,
}

impl TestUtxo {
    fn new() -> Self {
        Self {
            boxes: HashMap::new(),
        }
    }

    /// Add a transaction's outputs to the UTXO set.
    fn apply_tx(&mut self, tx: &Transaction) {
        let tx_id = ergo_ser::transaction::transaction_id(tx).unwrap();
        for (i, candidate) in tx.output_candidates.iter().enumerate() {
            let ergo_box = ErgoBox {
                candidate: candidate.clone(),
                transaction_id: tx_id,
                index: i as u16,
            };
            let box_id = ergo_box.box_id().unwrap();
            self.boxes.insert(box_id, ergo_box);
        }
    }

    /// Remove a transaction's inputs from the UTXO set.
    fn spend_inputs(&mut self, tx: &Transaction) {
        for input in &tx.inputs {
            self.boxes.remove(&input.box_id);
        }
    }
}

impl UtxoView for TestUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.boxes.get(box_id).cloned()
    }
}

#[derive(serde::Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
    #[serde(rename = "bytesToSign")]
    bytes_to_sign: String,
    height: u32,
}

fn load_tx_vectors(path: &str) -> Vec<TxVector> {
    let data = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&data).unwrap()
}

fn parse_tx(hex_bytes: &str) -> Transaction {
    let bytes = hex::decode(hex_bytes).unwrap();
    let mut r = VlqReader::new(&bytes);
    read_transaction(&mut r).unwrap()
}

#[derive(serde::Deserialize)]
struct HeaderVector {
    height: u32,
    bytes: String,
}

fn load_header_vectors(path: &str) -> Vec<HeaderVector> {
    let data = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&data).unwrap()
}

fn parse_header(hex_bytes: &str) -> Header {
    let bytes = hex::decode(hex_bytes).unwrap();
    let mut r = VlqReader::new(&bytes);
    read_header(&mut r).unwrap()
}

/// Build a height → (miner_pubkey, timestamp) map from header test vectors.
fn load_header_info(path: &str) -> HashMap<u32, ([u8; 33], u64)> {
    let vectors = load_header_vectors(path);
    vectors
        .iter()
        .map(|v| {
            let header = parse_header(&v.bytes);
            (
                v.height,
                (*header.solution.pk().as_bytes(), header.timestamp),
            )
        })
        .collect()
}

/// Strict chain validation: blocks 2-10, stops on first failure.
///
/// Block 1's transaction cannot be fully validated because its input
/// (the genesis emission box) is not available as a serialized ErgoBox.
/// We use block 1 only to bootstrap the UTXO set.
///
/// This test is a regression gate. If any transaction fails, the test
/// fails. If a new interpreter limitation causes a regression, the fix
/// is to implement the missing opcode, not to weaken the assertion.
#[test]
fn chain_validate_blocks_2_through_10() {
    let vectors = load_tx_vectors("../test-vectors/mainnet/transactions_1_10.json");
    assert!(vectors.len() >= 10, "expected 10+ vectors");

    let header_info = load_header_info("../test-vectors/mainnet/headers_1_10.json");

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();

    // Bootstrap: parse block 1's tx and add its outputs to UTXO
    let tx1 = parse_tx(&vectors[0].bytes);
    let mut utxo = TestUtxo::new();
    utxo.apply_tx(&tx1);

    // Strict chain validation: each block validated against the UTXO
    // produced by all prior successful validations. Stops on first failure.
    for v in &vectors[1..] {
        let tx_bytes = hex::decode(&v.bytes).unwrap();
        let (miner_pubkey, timestamp) = *header_info.get(&v.height).unwrap_or_else(|| {
            panic!(
                "missing header vector for height {} — test fixture incomplete",
                v.height
            )
        });
        let ctx = TransactionContext {
            height: v.height,
            miner_pubkey,
            pre_header_timestamp: timestamp,
            activated_script_version: 1,
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        };
        let mut cost =
            CostAccumulator::new(JitCost::from_block_cost(params.max_block_cost).unwrap());
        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
            rules: ergo_validation::TxValidationRules::default(),
        };

        let checked =
            validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx).unwrap_or_else(|e| {
                panic!(
                    "height {} tx {}: validation failed: {e}",
                    v.height,
                    &v.id[..16]
                )
            });

        assert!(
            cost.total().value() > 0,
            "cost should accumulate for height {}",
            v.height
        );

        // Verify tx ID matches expected
        let computed_id = ergo_ser::transaction::transaction_id(checked.transaction()).unwrap();
        assert_eq!(
            hex::encode(computed_id.as_bytes()),
            v.id,
            "tx ID mismatch at height {}",
            v.height
        );

        // Update UTXO for next block
        utxo.spend_inputs(checked.transaction());
        utxo.apply_tx(checked.transaction());
    }

    eprintln!("9/9 transactions validated (blocks 2-10)");
}

/// Verify bytes_to_sign computation matches test vectors.
#[test]
fn bytes_to_sign_matches_vectors() {
    let vectors = load_tx_vectors("../test-vectors/mainnet/transactions_1_10.json");
    for v in &vectors {
        let tx = parse_tx(&v.bytes);
        let computed = bytes_to_sign(&tx).unwrap();
        let expected = hex::decode(&v.bytes_to_sign).unwrap();
        assert_eq!(
            computed, expected,
            "bytes_to_sign mismatch at height {}",
            v.height,
        );
    }
    eprintln!("{} bytes_to_sign verified", vectors.len());
}

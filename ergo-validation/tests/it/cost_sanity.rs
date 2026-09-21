//! Cost sanity tests on the mainnet corpus (heights 700000-700200).
//!
//! Validates that cost accumulation is plumbed correctly: costs are
//! non-zero for every passing transaction and remain within the block
//! cost limit. Does NOT test exact parity with Scala cost values.

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::read_header;
use ergo_ser::transaction::Transaction;

use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::{CostAccumulator, JitCost};
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

const BLOCK_COST_LIMIT: u64 = 1_000_000;

struct ProgressiveUtxo {
    boxes: HashMap<Digest32, ErgoBox>,
}

impl ProgressiveUtxo {
    fn new() -> Self {
        Self {
            boxes: HashMap::new(),
        }
    }

    fn apply_tx(&mut self, tx: &Transaction) {
        for input in &tx.inputs {
            self.boxes.remove(&input.box_id);
        }
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
}

impl UtxoView for ProgressiveUtxo {
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.boxes.get(box_id).cloned()
    }
}

#[derive(serde::Deserialize)]
struct TxVector {
    #[allow(dead_code)]
    id: String,
    bytes: String,
    #[serde(rename = "bytesToSign")]
    #[allow(dead_code)]
    bytes_to_sign: String,
    height: u32,
}

#[derive(serde::Deserialize)]
struct HeaderVector {
    height: u32,
    bytes: String,
}

type HeaderContextByHeight = HashMap<u32, ([u8; 33], u64)>;

/// Shared setup: load corpus, build header map, return sorted tx vectors.
fn load_corpus() -> (Vec<TxVector>, HeaderContextByHeight) {
    let tx_data: Vec<TxVector> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/transactions_700000_700200.json")
            .unwrap(),
    )
    .unwrap();

    let header_data: Vec<HeaderVector> = serde_json::from_str(
        &std::fs::read_to_string("../test-vectors/mainnet/headers_700000_700500.json").unwrap(),
    )
    .unwrap();

    let header_info: HashMap<u32, ([u8; 33], u64)> = header_data
        .iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            let header = read_header(&mut r).unwrap();
            (
                v.height,
                (*header.solution.pk().as_bytes(), header.timestamp),
            )
        })
        .collect();

    (tx_data, header_info)
}

/// Validate all corpus transactions with recording-only cost, returning
/// per-tx block costs for passing transactions and summary counts.
fn run_corpus_recording(
    tx_data: &[TxVector],
    header_info: &HashMap<u32, ([u8; 33], u64)>,
) -> (Vec<u64>, usize, usize) {
    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut utxo = ProgressiveUtxo::new();

    let mut sorted_txs: Vec<&TxVector> = tx_data.iter().collect();
    sorted_txs.sort_by_key(|v| v.height);

    let mut pass_costs: Vec<u64> = Vec::new();
    let mut fail_count = 0usize;

    for v in &sorted_txs {
        let tx_bytes = hex::decode(&v.bytes).unwrap();
        let (miner_pubkey, timestamp) = *header_info
            .get(&v.height)
            .unwrap_or_else(|| panic!("missing header for height {}", v.height));
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
        let mut cost = CostAccumulator::recording_only();
        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
            rules: ergo_validation::TxValidationRules::default(),
        };

        match validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx) {
            Ok(checked) => {
                let block_cost = cost.total_block_cost();
                pass_costs.push(block_cost);
                utxo.apply_tx(checked.transaction());
            }
            Err(_) => {
                fail_count += 1;
                // Still apply tx to UTXO so later txs can find inputs
                if let Ok(tx) = {
                    let mut r = VlqReader::new(&tx_bytes);
                    ergo_ser::transaction::read_transaction(&mut r)
                } {
                    utxo.apply_tx(&tx);
                }
            }
        }
    }

    let total = sorted_txs.len();
    (pass_costs, fail_count, total)
}

#[test]
#[ignore = "load_corpus needs gitignored transactions_700000_700200.json + headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn corpus_costs_are_within_block_limit() {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(corpus_costs_within_block_limit_inner)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn corpus_costs_within_block_limit_inner() {
    let (tx_data, header_info) = load_corpus();
    let (pass_costs, fail_count, total) = run_corpus_recording(&tx_data, &header_info);

    let pass_count = pass_costs.len();
    assert!(
        pass_count > 0,
        "no transactions passed validation — cost sanity test is vacuous"
    );

    let min_cost = *pass_costs.iter().min().unwrap();
    let max_cost = *pass_costs.iter().max().unwrap();
    let avg_cost = pass_costs.iter().sum::<u64>() / pass_count as u64;

    eprintln!("\n=== COST SANITY: recording_only ({total} transactions) ===\n");
    eprintln!("  Passed:    {pass_count}");
    eprintln!("  Failed:    {fail_count}  (expected — missing pre-range UTXO)");
    eprintln!("  Min cost:  {min_cost} block-cost units");
    eprintln!("  Max cost:  {max_cost} block-cost units");
    eprintln!("  Avg cost:  {avg_cost} block-cost units");
    eprintln!();

    for (i, &bc) in pass_costs.iter().enumerate() {
        // Every passing tx must have accumulated some cost
        assert!(
            bc > 0,
            "transaction {i} passed with zero cost — cost accumulation is broken"
        );
        // Every passing tx must be within the block cost limit
        assert!(
            bc <= BLOCK_COST_LIMIT,
            "transaction {i} cost {bc} exceeds block limit {BLOCK_COST_LIMIT}"
        );
    }
}

#[test]
#[ignore = "load_corpus needs gitignored transactions_700000_700200.json + headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn corpus_passes_with_enforcing_cost() {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(corpus_passes_with_enforcing_inner)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn corpus_passes_with_enforcing_inner() {
    let (tx_data, header_info) = load_corpus();

    // First pass: recording_only to identify which txs pass
    let (recording_costs, _, _) = run_corpus_recording(&tx_data, &header_info);
    let recording_pass_count = recording_costs.len();

    // Second pass: enforcing mode — fresh accumulator per transaction
    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut utxo = ProgressiveUtxo::new();

    let mut sorted_txs: Vec<&TxVector> = tx_data.iter().collect();
    sorted_txs.sort_by_key(|v| v.height);

    let mut enforcing_pass_count = 0usize;
    let mut enforcing_fail_count = 0usize;

    for v in &sorted_txs {
        let tx_bytes = hex::decode(&v.bytes).unwrap();
        let (miner_pubkey, timestamp) = *header_info
            .get(&v.height)
            .unwrap_or_else(|| panic!("missing header for height {}", v.height));
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
        // Fresh enforcing accumulator per transaction
        let mut cost = CostAccumulator::new(JitCost::from_block_cost(BLOCK_COST_LIMIT).unwrap());
        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &[],
            rules: ergo_validation::TxValidationRules::default(),
        };

        match validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx) {
            Ok(checked) => {
                enforcing_pass_count += 1;
                utxo.apply_tx(checked.transaction());
            }
            Err(_) => {
                enforcing_fail_count += 1;
                if let Ok(tx) = {
                    let mut r = VlqReader::new(&tx_bytes);
                    ergo_ser::transaction::read_transaction(&mut r)
                } {
                    utxo.apply_tx(&tx);
                }
            }
        }
    }

    eprintln!(
        "\n=== COST SANITY: enforcing ({} transactions) ===\n",
        sorted_txs.len()
    );
    eprintln!("  Recording pass:  {recording_pass_count}");
    eprintln!("  Enforcing pass:  {enforcing_pass_count}");
    eprintln!("  Enforcing fail:  {enforcing_fail_count}");
    eprintln!();

    // Every transaction that passed in recording mode must also pass
    // in enforcing mode (costs are within limit).
    assert_eq!(
        enforcing_pass_count, recording_pass_count,
        "enforcing mode rejected transactions that recording mode accepted \
         — {recording_pass_count} recording vs {enforcing_pass_count} enforcing"
    );
}

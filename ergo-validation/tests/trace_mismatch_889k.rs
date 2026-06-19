#![cfg(feature = "cost-trace")]
//! Trace the 2 cost mismatches in 889000-890000 to identify exact discrepancy.
//!
//! Both txs have delta=+3 (Rust overcharges by 3 block_cost = 30 JitCost).
//!
//! ROOT CAUSE: LogicalNot (0xEF) costs fixed(20) but Scala charges fixed(15).
//! Each input has 2× LogicalNot = 10 JitCost overcharge per input.
//! 3 inputs × 10 = 30 JitCost = 3 block_cost.
//! Fix: change 0xEF from fixed(20) to fixed(15).

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::read_header;
use ergo_ser::transaction::Transaction;
use ergo_sigma::cost_trace;

use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::{CostAccumulator, JitCost};
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

const BLOCK_COST_LIMIT: u64 = 1_000_000;
const VECTORS_DIR: &str = "../test-vectors/mainnet";

const TARGET_TXS: &[&str] = &[
    "f0d5e00ba3fc8211aff27af11767e3e5c5b7b84edd539d51de5da1dda3763222",
    "c9ab14a108b38f95b9c2b84de95126763191cf1f6433093174bcf8f672c81bfc",
];

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
    id: String,
    bytes: String,
    height: u32,
}

#[derive(serde::Deserialize)]
struct HeaderVector {
    height: u32,
    bytes: String,
}

#[derive(serde::Deserialize)]
struct ScalaCostVector {
    tx_id: String,
    block_cost: u64,
}

#[test]
#[ignore] // diagnostic: run manually with --ignored --nocapture
fn trace_889k_mismatches() {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(trace_inner)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn trace_inner() {
    let tx_raw = std::fs::read_to_string(format!("{VECTORS_DIR}/transactions_889000_890000.json"))
        .expect("need transactions_889000_890000.json");
    let tx_data: Vec<TxVector> = serde_json::from_str(&tx_raw).unwrap();

    let hdr_raw = std::fs::read_to_string(format!("{VECTORS_DIR}/headers_889000_890300.json"))
        .expect("need headers_889000_890300.json");
    let header_data: Vec<HeaderVector> = serde_json::from_str(&hdr_raw).unwrap();

    let scala_raw = std::fs::read_to_string(format!("{VECTORS_DIR}/tx_costs_889000_890000.json"))
        .expect("need tx_costs_889000_890000.json");
    let scala_costs: Vec<ScalaCostVector> = serde_json::from_str(&scala_raw).unwrap();
    let scala_map: HashMap<String, u64> = scala_costs
        .iter()
        .map(|c| (c.tx_id.clone(), c.block_cost))
        .collect();

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

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut utxo = ProgressiveUtxo::new();

    let mut sorted_txs: Vec<&TxVector> = tx_data.iter().collect();
    sorted_txs.sort_by_key(|v| v.height);

    for v in &sorted_txs {
        let tx_bytes = hex::decode(&v.bytes).unwrap();
        let (miner_pubkey, timestamp) = match header_info.get(&v.height) {
            Some(info) => *info,
            None => {
                if let Ok(tx) = {
                    let mut r = VlqReader::new(&tx_bytes);
                    ergo_ser::transaction::read_transaction(&mut r)
                } {
                    utxo.apply_tx(&tx);
                }
                continue;
            }
        };

        let is_target = TARGET_TXS.contains(&v.id.as_str());
        if is_target {
            cost_trace::enable();
        }

        let ctx = TransactionContext {
            height: v.height,
            miner_pubkey,
            pre_header_timestamp: timestamp,
            activated_script_version: 2,
            pre_header_version: 0,
            pre_header_parent_id: [0u8; 32],
            pre_header_n_bits: 0,
            pre_header_votes: [0u8; 3],
        };
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
                if is_target {
                    let rust_cost = cost.total_block_cost();
                    let scala_cost = scala_map.get(&v.id).copied().unwrap_or(0);
                    let trace = cost_trace::take().unwrap();

                    eprintln!("\n╔══════════════════════════════════════════════════════════╗");
                    eprintln!("║ TX: {} ║", &v.id[..16]);
                    eprintln!(
                        "║ height={} rust_block={} scala_block={} delta={} ║",
                        v.height,
                        rust_cost,
                        scala_cost,
                        rust_cost as i64 - scala_cost as i64
                    );
                    eprintln!("║ rust_jit={} ║", cost.total().value());
                    eprintln!("╠══════════════════════════════════════════════════════════╣");

                    trace.dump(&v.id[..16]);

                    // Write to file for offline analysis
                    let mut lines = Vec::new();
                    lines.push(format!(
                        "TX: {} height={} rust_jit={} rust_block={} scala_block={} delta={}",
                        v.id,
                        v.height,
                        cost.total().value(),
                        rust_cost,
                        scala_cost,
                        rust_cost as i64 - scala_cost as i64
                    ));
                    for e in &trace.entries {
                        lines.push(format!("+{:<6} {:<40} total={}", e.delta, e.label, e.total));
                    }
                    for &(before, after) in &trace.snaps {
                        lines.push(format!(
                            "SNAP: {} -> {} (dropped {})",
                            before,
                            after,
                            before - after
                        ));
                    }
                    for line in &lines {
                        eprintln!("{line}");
                    }

                    // Group by prefix
                    let prefixes = ["OP:", "EQ:", "Arith:", "Method:", "Crypto:"];
                    for p in &prefixes {
                        let sum = trace.sum_by_prefix(p);
                        let count = trace.count_by_prefix(p);
                        if count > 0 {
                            eprintln!("  {p:<10} count={count:<4} sum={sum}");
                        }
                    }
                    for &(before, after) in &trace.snaps {
                        eprintln!(
                            "  SNAP: {} -> {} (dropped {})",
                            before,
                            after,
                            before - after
                        );
                    }
                    eprintln!("╚══════════════════════════════════════════════════════════╝\n");
                }
                utxo.apply_tx(checked.transaction());
            }
            Err(ref e) => {
                if is_target {
                    let _ = cost_trace::take();
                    eprintln!("ERROR on target tx {}: {e}", &v.id[..16]);
                }
                let is_missing = matches!(
                    e,
                    ValidationError::InputBoxNotFound { .. }
                        | ValidationError::DataInputBoxNotFound { .. }
                );
                if is_missing {
                    if let Ok(tx) = {
                        let mut r = VlqReader::new(&tx_bytes);
                        ergo_ser::transaction::read_transaction(&mut r)
                    } {
                        utxo.apply_tx(&tx);
                    }
                }
            }
        }
    }
}

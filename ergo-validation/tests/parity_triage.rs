#![cfg(feature = "diagnostics")]
//! Parity triage for high-signal ranges (889k, 1500k).
//!
//! For each transaction, categorizes the outcome:
//!   - exact_match: cost matches Scala
//!   - cost_mismatch: validated but cost differs
//!   - proof_failed: script reduced but proof verification failed
//!   - eval_error: script evaluation error (unsupported opcode, type error, etc.)
//!   - structural_error: structural/monetary/canonical rejection
//!   - missing_utxo: input box not found (expected, skip)
//!
//! Run with: cargo test -p ergo-validation --test parity_triage -- --nocapture

use std::collections::HashMap;

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::read_header;
use ergo_ser::transaction::Transaction;

use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::cost::{CostAccumulator, JitCost};
use ergo_validation::error::ValidationError;
use ergo_validation::tx::validate_transaction;
use ergo_validation::UtxoView;

const BLOCK_COST_LIMIT: u64 = 1_000_000;
const VECTORS_DIR: &str = "../test-vectors/mainnet";

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

#[derive(serde::Deserialize)]
struct ScalaCostVector {
    tx_id: String,
    #[allow(dead_code)]
    height: u32,
    block_cost: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Category {
    ExactMatch,
    CostMismatch,
    ProofFailed,
    EvalError,
    StructuralError,
    MissingUtxo,
    SkipNoHeader,
}

struct TxResult {
    tx_id: String,
    height: u32,
    category: Category,
    detail: String,
}

#[test]
fn triage_high_signal_ranges() {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(triage_inner)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn triage_inner() {
    let ranges = &["889000_890000", "1500000_1501000"];
    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut ranges_processed = 0usize;

    for range_label in ranges {
        let tx_file = format!("{VECTORS_DIR}/transactions_{range_label}.json");
        let cost_file = format!("{VECTORS_DIR}/tx_costs_{range_label}.json");
        let parts: Vec<&str> = range_label.split('_').collect();
        let start: u32 = parts[0].parse().unwrap();
        let end: u32 = parts[1].parse().unwrap();

        if !std::path::Path::new(&tx_file).exists() {
            eprintln!("SKIP: {tx_file} not found");
            continue;
        }

        let header_file = find_header_file(start, end);
        if header_file.is_none() {
            eprintln!("SKIP: no header file for {range_label}");
            continue;
        }
        ranges_processed += 1;

        let tx_data: Vec<TxVector> =
            serde_json::from_str(&std::fs::read_to_string(&tx_file).unwrap()).unwrap();
        let scala_costs: HashMap<String, u64> = if std::path::Path::new(&cost_file).exists() {
            let raw: Vec<ScalaCostVector> =
                serde_json::from_str(&std::fs::read_to_string(&cost_file).unwrap()).unwrap();
            raw.into_iter().map(|c| (c.tx_id, c.block_cost)).collect()
        } else {
            HashMap::new()
        };
        let header_data: Vec<HeaderVector> =
            serde_json::from_str(&std::fs::read_to_string(header_file.unwrap()).unwrap()).unwrap();
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

        let mut utxo = ProgressiveUtxo::new();
        let mut sorted: Vec<&TxVector> = tx_data.iter().collect();
        sorted.sort_by_key(|v| v.height);

        let mut results: Vec<TxResult> = Vec::new();

        for v in &sorted {
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
                    results.push(TxResult {
                        tx_id: v.id.clone(),
                        height: v.height,
                        category: Category::SkipNoHeader,
                        detail: String::new(),
                    });
                    continue;
                }
            };
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
                CostAccumulator::new(JitCost::from_block_cost(BLOCK_COST_LIMIT).unwrap());
            let mut tx_cx = ergo_validation::TxValidationCtx {
                ctx: &ctx,
                params: &params,
                cost: &mut cost,
                last_headers: &[],
            };

            match validate_transaction(&tx_bytes, &utxo, &policy, &mut tx_cx) {
                Ok(checked) => {
                    let rust_cost = cost.total_block_cost();
                    let category = match scala_costs.get(&v.id) {
                        Some(&sc) if sc == rust_cost => Category::ExactMatch,
                        Some(&_sc) => Category::CostMismatch,
                        None => Category::ExactMatch, // no scala vector to compare
                    };
                    let detail = match scala_costs.get(&v.id) {
                        Some(&sc) if sc != rust_cost => {
                            format!(
                                "rust={rust_cost} scala={sc} delta={}",
                                rust_cost as i64 - sc as i64
                            )
                        }
                        _ => String::new(),
                    };
                    results.push(TxResult {
                        tx_id: v.id.clone(),
                        height: v.height,
                        category,
                        detail,
                    });
                    utxo.apply_tx(checked.transaction());
                }
                Err(ref e) => {
                    let (category, detail) = categorize_error(e);
                    if matches!(category, Category::MissingUtxo) {
                        if let Ok(tx) = {
                            let mut r = VlqReader::new(&tx_bytes);
                            ergo_ser::transaction::read_transaction(&mut r)
                        } {
                            utxo.apply_tx(&tx);
                        }
                    }
                    results.push(TxResult {
                        tx_id: v.id.clone(),
                        height: v.height,
                        category,
                        detail,
                    });
                }
            }
        }

        // Print summary
        let mut counts: HashMap<Category, usize> = HashMap::new();
        for r in &results {
            *counts.entry(r.category).or_default() += 1;
        }
        eprintln!(
            "\n=== TRIAGE: {range_label} ({} transactions) ===",
            results.len()
        );
        for cat in &[
            Category::ExactMatch,
            Category::CostMismatch,
            Category::ProofFailed,
            Category::EvalError,
            Category::StructuralError,
            Category::MissingUtxo,
            Category::SkipNoHeader,
        ] {
            if let Some(&n) = counts.get(cat) {
                eprintln!("  {cat:?}: {n}");
            }
        }

        // Detail: first 10 of each non-match category
        for cat in &[
            Category::ProofFailed,
            Category::EvalError,
            Category::StructuralError,
            Category::CostMismatch,
        ] {
            let items: Vec<&TxResult> = results.iter().filter(|r| r.category == *cat).collect();
            if items.is_empty() {
                continue;
            }
            eprintln!("\n  --- {cat:?} (first 10 of {}) ---", items.len());
            for r in items.iter().take(10) {
                eprintln!("    tx {} h={}: {}", &r.tx_id[..16], r.height, r.detail);
            }
        }

        // Cost mismatch delta histogram
        let mismatches: Vec<i64> = results
            .iter()
            .filter(|r| r.category == Category::CostMismatch)
            .filter_map(|r| {
                r.detail
                    .rsplit("delta=")
                    .next()
                    .and_then(|s| s.parse::<i64>().ok())
            })
            .collect();
        if !mismatches.is_empty() {
            let neg: Vec<&i64> = mismatches.iter().filter(|d| **d < 0).collect();
            let pos: Vec<&i64> = mismatches.iter().filter(|d| **d > 0).collect();
            eprintln!(
                "\n  --- Cost delta summary ({} mismatches) ---",
                mismatches.len()
            );
            eprintln!("    negative (Rust < Scala): {} txs", neg.len());
            eprintln!("    positive (Rust > Scala): {} txs", pos.len());
            if !neg.is_empty() {
                let min = neg.iter().map(|d| **d).min().unwrap();
                let max = neg.iter().map(|d| **d).max().unwrap();
                let avg: f64 = neg.iter().map(|d| **d as f64).sum::<f64>() / neg.len() as f64;
                eprintln!("    neg range: {min} to {max}, avg {avg:.0}");
            }
            if !pos.is_empty() {
                let min = pos.iter().map(|d| **d).min().unwrap();
                let max = pos.iter().map(|d| **d).max().unwrap();
                let avg: f64 = pos.iter().map(|d| **d as f64).sum::<f64>() / pos.len() as f64;
                eprintln!("    pos range: +{min} to +{max}, avg +{avg:.0}");
            }
        }
    }

    assert!(
        ranges_processed > 0,
        "parity_triage: no mainnet ranges available — extract via test-vectors/scripts before running with --ignored",
    );
}

fn categorize_error(e: &ValidationError) -> (Category, String) {
    match e {
        ValidationError::InputBoxNotFound { .. } | ValidationError::DataInputBoxNotFound { .. } => {
            (Category::MissingUtxo, String::new())
        }
        ValidationError::ProofFailed { index } => (Category::ProofFailed, format!("input {index}")),
        ValidationError::ScriptError { index, reason } => {
            // Distinguish proof-adjacent from pure eval errors
            if reason.contains("spending proof") {
                (Category::ProofFailed, format!("input {index}: {reason}"))
            } else {
                (Category::EvalError, format!("input {index}: {reason}"))
            }
        }
        ValidationError::NonCanonical => (Category::StructuralError, "non-canonical".into()),
        ValidationError::OutputValueTooLow { index, value, min } => (
            Category::StructuralError,
            format!("output {index}: value {value} < min {min}"),
        ),
        _ => (Category::StructuralError, format!("{e}")),
    }
}

fn find_header_file(start: u32, end: u32) -> Option<String> {
    let entries = std::fs::read_dir(VECTORS_DIR).ok()?;
    let mut best: Option<String> = None;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("headers_") || !name.ends_with(".json") {
            continue;
        }
        let stem = name
            .trim_start_matches("headers_")
            .trim_end_matches(".json");
        let parts: Vec<&str> = stem.split('_').collect();
        if parts.len() != 2 {
            continue;
        }
        let h_start: u32 = parts[0].parse().unwrap_or(u32::MAX);
        let h_end: u32 = parts[1].parse().unwrap_or(0);
        if h_start <= start && h_end >= end {
            match &best {
                None => best = Some(entry.path().to_string_lossy().to_string()),
                Some(prev) => {
                    let prev_span = {
                        let n = std::path::Path::new(prev)
                            .file_name()
                            .unwrap()
                            .to_string_lossy();
                        let s = n.trim_start_matches("headers_").trim_end_matches(".json");
                        let p: Vec<&str> = s.split('_').collect();
                        p[1].parse::<u32>().unwrap_or(u32::MAX) - p[0].parse::<u32>().unwrap_or(0)
                    };
                    if (h_end - h_start) < prev_span {
                        best = Some(entry.path().to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    best
}

#![cfg(feature = "diagnostics")]
//! Triage test: captures full error messages for all eval_errors across
//! all cost parity ranges and writes frequency analysis to /tmp/.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

struct CostRange {
    label: String,
    tx_file: PathBuf,
    header_file: PathBuf,
}

struct ErrorRecord {
    tx_id: String,
    height: u32,
    range_label: String,
    error_msg: String,
}

fn find_header_file(dir: &Path, start: u32, end: u32) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut best: Option<PathBuf> = None;

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
                None => best = Some(entry.path()),
                Some(prev) => {
                    let prev_name = prev.file_name().unwrap().to_string_lossy().to_string();
                    let prev_stem = prev_name
                        .trim_start_matches("headers_")
                        .trim_end_matches(".json");
                    let prev_parts: Vec<&str> = prev_stem.split('_').collect();
                    let prev_span = prev_parts[1].parse::<u32>().unwrap_or(u32::MAX)
                        - prev_parts[0].parse::<u32>().unwrap_or(0);
                    let this_span = h_end - h_start;
                    if this_span < prev_span {
                        best = Some(entry.path());
                    }
                }
            }
        }
    }
    best
}

fn build_range(start: u32, end: u32) -> Option<CostRange> {
    let dir = Path::new(VECTORS_DIR);
    let tx_file = dir.join(format!("transactions_{start}_{end}.json"));
    if !tx_file.exists() {
        return None;
    }
    let header_file = find_header_file(dir, start, end)?;
    Some(CostRange {
        label: format!("{start}-{end}"),
        tx_file,
        header_file,
    })
}

fn collect_errors(
    range: &CostRange,
    params: &ProtocolParams,
    policy: &LocalPolicy,
) -> Vec<ErrorRecord> {
    let tx_raw = std::fs::read_to_string(&range.tx_file).unwrap();
    let tx_data: Vec<TxVector> = serde_json::from_str(&tx_raw).unwrap();

    let hdr_raw = std::fs::read_to_string(&range.header_file).unwrap();
    let header_data: Vec<HeaderVector> = serde_json::from_str(&hdr_raw).unwrap();

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
    let mut sorted_txs: Vec<&TxVector> = tx_data.iter().collect();
    sorted_txs.sort_by_key(|v| v.height);

    let mut errors = Vec::new();

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
        let mut cost = CostAccumulator::new(JitCost::from_block_cost(BLOCK_COST_LIMIT).unwrap());
        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params,
            cost: &mut cost,
            last_headers: &[],
            rules: ergo_validation::TxValidationRules::default(),
        };

        match validate_transaction(&tx_bytes, &utxo, policy, &mut tx_cx) {
            Ok(checked) => {
                utxo.apply_tx(checked.transaction());
            }
            Err(ref e) => {
                let is_missing_utxo = matches!(
                    e,
                    ValidationError::InputBoxNotFound { .. }
                        | ValidationError::DataInputBoxNotFound { .. }
                );
                if is_missing_utxo {
                    if let Ok(tx) = {
                        let mut r = VlqReader::new(&tx_bytes);
                        ergo_ser::transaction::read_transaction(&mut r)
                    } {
                        utxo.apply_tx(&tx);
                    }
                } else {
                    errors.push(ErrorRecord {
                        tx_id: v.id.clone(),
                        height: v.height,
                        range_label: range.label.clone(),
                        error_msg: format!("{e}"),
                    });
                }
            }
        }
    }

    errors
}

/// Normalize error messages into canonical patterns for grouping.
fn normalize_error(msg: &str) -> String {
    // Extract the core error from "input N: script evaluation failed: <core>"
    let core = if let Some(pos) = msg.find("script evaluation failed: ") {
        &msg[pos + "script evaluation failed: ".len()..]
    } else {
        msg
    };

    // Normalize specific patterns
    if core.starts_with("unsupported opcode: ") {
        return core.to_string(); // keep opcode hex
    }
    if core.starts_with("unsupported constant type: ") {
        return core.to_string(); // keep type
    }
    if core.starts_with("type error: ") {
        return core.to_string(); // keep type info
    }
    if core.starts_with("cost limit exceeded") {
        return "cost limit exceeded".to_string();
    }
    if core.starts_with("constant index ") {
        return "constant index out of bounds".to_string();
    }
    if core.starts_with("evaluation depth limit") {
        return "evaluation depth limit exceeded".to_string();
    }
    if core.starts_with("arity mismatch") {
        return core.to_string();
    }

    // For deserialization/structural errors, keep as-is
    core.to_string()
}

#[test]
fn eval_error_triage() {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(eval_error_triage_inner)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn eval_error_triage_inner() {
    let ranges: Vec<(u32, u32)> = vec![
        (500_000, 501_000),
        (700_000, 700_200),
        (700_000, 701_000),
        (750_000, 751_000),
        (889_000, 890_000),
        (900_000, 901_000),
        (1_000_000, 1_001_000),
        (1_100_000, 1_101_000),
        (1_300_000, 1_301_000),
        (1_500_000, 1_501_000),
        (1_750_000, 1_751_000),
    ];

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();

    let mut all_errors: Vec<ErrorRecord> = Vec::new();
    let mut ranges_processed = 0usize;

    for (start, end) in &ranges {
        let range = match build_range(*start, *end) {
            Some(r) => r,
            None => {
                eprintln!("SKIP: missing vectors for {start}-{end}");
                continue;
            }
        };
        let errors = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collect_errors(&range, &params, &policy)
        }));
        match errors {
            Ok(errs) => {
                eprintln!("{}: {} eval_errors", range.label, errs.len());
                all_errors.extend(errs);
                ranges_processed += 1;
            }
            Err(_) => {
                eprintln!("{}: PANIC during collection", range.label);
            }
        }
    }

    assert!(
        ranges_processed > 0,
        "eval_error_triage: no mainnet ranges available — extract via test-vectors/scripts before running with --ignored",
    );

    // Write full error log
    let mut full_log = String::new();
    full_log.push_str(&format!("TOTAL EVAL ERRORS: {}\n", all_errors.len()));
    full_log.push_str(&format!("Generated: {}\n\n", chrono_stub()));

    for (i, e) in all_errors.iter().enumerate() {
        full_log.push_str(&format!(
            "[{:04}] range={} height={} tx_id={}\n       error: {}\n\n",
            i + 1,
            e.range_label,
            e.height,
            e.tx_id,
            e.error_msg,
        ));
    }
    std::fs::write("/tmp/eval_errors_full.txt", &full_log).unwrap();

    // Frequency analysis by normalized pattern
    let mut freq: HashMap<String, Vec<&ErrorRecord>> = HashMap::new();
    for e in &all_errors {
        let pattern = normalize_error(&e.error_msg);
        freq.entry(pattern).or_default().push(e);
    }

    let mut sorted_patterns: Vec<(String, Vec<&ErrorRecord>)> = freq.into_iter().collect();
    sorted_patterns.sort_by_key(|p| std::cmp::Reverse(p.1.len()));

    let mut analysis = String::new();
    analysis.push_str("EVAL ERROR FREQUENCY ANALYSIS\n");
    analysis.push_str(&format!("Total errors: {}\n", all_errors.len()));
    analysis.push_str(&format!("Distinct patterns: {}\n\n", sorted_patterns.len()));

    analysis.push_str("RANK | COUNT | PATTERN\n");
    analysis.push_str("-----|-------|--------\n");
    for (rank, (pattern, records)) in sorted_patterns.iter().enumerate() {
        analysis.push_str(&format!(
            "{:4} | {:5} | {}\n",
            rank + 1,
            records.len(),
            pattern
        ));
    }

    analysis.push_str("\n\nDETAILS (one example per pattern):\n\n");
    for (rank, (pattern, records)) in sorted_patterns.iter().enumerate() {
        let example = records[0];
        analysis.push_str(&format!(
            "--- Pattern #{} ({} occurrences) ---\nPattern: {}\nExample tx_id: {}\nExample height: {}\nExample range: {}\nFull error: {}\n\n",
            rank + 1, records.len(), pattern, example.tx_id, example.height, example.range_label, example.error_msg,
        ));
    }

    // Per-range breakdown
    analysis.push_str("\nPER-RANGE BREAKDOWN:\n\n");
    for (start, end) in &ranges {
        let label = format!("{start}-{end}");
        let range_errors: Vec<&ErrorRecord> = all_errors
            .iter()
            .filter(|e| e.range_label == label)
            .collect();
        if range_errors.is_empty() {
            analysis.push_str(&format!("{}: 0 errors\n", label));
            continue;
        }
        let mut range_freq: HashMap<String, usize> = HashMap::new();
        for e in &range_errors {
            *range_freq.entry(normalize_error(&e.error_msg)).or_default() += 1;
        }
        let mut sorted: Vec<(String, usize)> = range_freq.into_iter().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
        analysis.push_str(&format!("{}: {} errors\n", label, range_errors.len()));
        for (pat, count) in &sorted {
            analysis.push_str(&format!("  {:5} | {}\n", count, pat));
        }
        analysis.push('\n');
    }

    std::fs::write("/tmp/eval_errors_triage.txt", &analysis).unwrap();

    // Print to test output too
    eprintln!("\n{}", analysis);
    eprintln!("Full error log written to /tmp/eval_errors_full.txt");
    eprintln!("Triage analysis written to /tmp/eval_errors_triage.txt");
}

fn chrono_stub() -> String {
    "2026-04-11".to_string()
}

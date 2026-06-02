#![cfg(feature = "diagnostics")]
//! Exact cost-value parity tests: Rust vs Scala sigmastate-interpreter.
//!
//! Each range is a separate test for cargo-level parallelism.
//! Fails on ANY numerical mismatch — no tolerance, no rounding.
//!
//! To generate vectors for all ranges:
//!   ./test-vectors/scripts/extract_all_cost_vectors.sh
//!
//! The generated `tx_costs_*.json` ranges are large and gitignored, so
//! these oracle tests are opt-in:
//!   cargo test -p ergo-validation --test cost_parity -- --ignored

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

// ---------------------------------------------------------------------------
// Shared infrastructure
// ---------------------------------------------------------------------------

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

struct CostRange {
    label: String,
    cost_file: PathBuf,
    tx_file: PathBuf,
    header_file: PathBuf,
}

struct RangeResult {
    label: String,
    matched: usize,
    mismatches: Vec<String>,
    #[allow(dead_code)]
    rust_only: usize,
    scala_unmatched: usize,
    eval_errors: usize,
}

/// Find a header file covering the given range.
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

/// Run cost parity for a single range. Panics on missing files.
fn run_range(range: &CostRange, params: &ProtocolParams, policy: &LocalPolicy) -> RangeResult {
    let scala_costs_raw = std::fs::read_to_string(&range.cost_file)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", range.cost_file.display()));
    let scala_costs: Vec<ScalaCostVector> = serde_json::from_str(&scala_costs_raw).unwrap();
    let scala_map: HashMap<String, u64> = scala_costs
        .iter()
        .map(|c| (c.tx_id.clone(), c.block_cost))
        .collect();

    let tx_raw = std::fs::read_to_string(&range.tx_file).unwrap();
    let tx_data: Vec<TxVector> = serde_json::from_str(&tx_raw).unwrap();

    let hdr_raw = std::fs::read_to_string(&range.header_file).unwrap();
    let header_data: Vec<HeaderVector> = serde_json::from_str(&hdr_raw).unwrap();

    // Store full headers by height for SContext.headers and miner pk/timestamp.
    let headers_by_height: HashMap<u32, ergo_ser::header::Header> = header_data
        .iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            let header = read_header(&mut r).unwrap();
            (v.height, header)
        })
        .collect();

    // Sorted heights for building last-10 context.
    let mut sorted_heights: Vec<u32> = headers_by_height.keys().copied().collect();
    sorted_heights.sort();

    let header_info: HashMap<u32, ([u8; 33], u64)> = headers_by_height
        .iter()
        .map(|(&h, hdr)| (h, (*hdr.solution.pk().as_bytes(), hdr.timestamp)))
        .collect();

    let mut utxo = ProgressiveUtxo::new();
    let mut sorted_txs: Vec<&TxVector> = tx_data.iter().collect();
    sorted_txs.sort_by_key(|v| v.height);

    let mut matched = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
    let mut rust_only = 0usize;
    let mut eval_errors = 0usize;
    let mut scala_only_checked = std::collections::HashSet::new();

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

        // Build last 10 headers for CONTEXT.headers.
        // Find up to 10 headers with height < current block height.
        let last_headers: Vec<ergo_ser::header::Header> = {
            let pos = sorted_heights.partition_point(|&h| h < v.height);
            let start = pos.saturating_sub(10);
            sorted_heights[start..pos]
                .iter()
                .filter_map(|h| headers_by_height.get(h).cloned())
                .collect()
        };

        let mut tx_cx = ergo_validation::TxValidationCtx {
            ctx: &ctx,
            params,
            cost: &mut cost,
            last_headers: &last_headers,
        };
        match validate_transaction(&tx_bytes, &utxo, policy, &mut tx_cx) {
            Ok(checked) => {
                let rust_cost = cost.total_block_cost();

                if let Some(&scala_cost) = scala_map.get(&v.id) {
                    scala_only_checked.insert(v.id.clone());
                    if rust_cost != scala_cost {
                        mismatches.push(format!(
                            "[{}] tx {} (h={}): rust={} scala={} delta={}",
                            range.label,
                            v.id,
                            v.height,
                            rust_cost,
                            scala_cost,
                            rust_cost as i64 - scala_cost as i64,
                        ));
                    } else {
                        matched += 1;
                    }
                } else {
                    rust_only += 1;
                }

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
                    eval_errors += 1;
                }
            }
        }
    }

    let scala_unmatched = scala_map.len() - scala_only_checked.len();

    RangeResult {
        label: range.label.clone(),
        matched,
        mismatches,
        rust_only,
        scala_unmatched,
        eval_errors,
    }
}

/// Build a CostRange for a specific (start, end) pair if all required files exist.
fn build_range(start: u32, end: u32) -> Option<CostRange> {
    let dir = Path::new(VECTORS_DIR);
    let cost_file = dir.join(format!("tx_costs_{start}_{end}.json"));
    let tx_file = dir.join(format!("transactions_{start}_{end}.json"));
    if !cost_file.exists() || !tx_file.exists() {
        return None;
    }
    let header_file = find_header_file(dir, start, end)?;
    Some(CostRange {
        label: format!("{start}-{end}"),
        cost_file,
        tx_file,
        header_file,
    })
}

/// Run parity for a single (start, end) range and assert zero mismatches.
fn assert_range_parity(start: u32, end: u32) {
    let range = build_range(start, end)
        .unwrap_or_else(|| panic!("required cost parity vectors missing for {start}-{end}"));
    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let r = run_range(&range, &params, &policy);

    let compared = r.matched + r.mismatches.len();
    eprintln!(
        "{}: {}/{} matched, {} eval_errors, {} scala_unmatched",
        r.label, r.matched, compared, r.eval_errors, r.scala_unmatched,
    );

    assert!(
        r.mismatches.is_empty(),
        "COST PARITY FAILED for {}: {} mismatches\n{}",
        r.label,
        r.mismatches.len(),
        r.mismatches
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// Wrapper that runs assert_range_parity on a thread with enough stack.
fn assert_range_parity_threaded(start: u32, end: u32) {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || assert_range_parity(start, end))
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

// ---------------------------------------------------------------------------
// Per-range tests — cargo runs these in parallel
// ---------------------------------------------------------------------------

#[test]
fn cost_parity_500000_501000() {
    assert_range_parity_threaded(500_000, 501_000);
}

#[test]
fn cost_parity_700000_700200() {
    assert_range_parity_threaded(700_000, 700_200);
}

#[test]
fn cost_parity_700000_701000() {
    assert_range_parity_threaded(700_000, 701_000);
}

#[test]
fn cost_parity_750000_751000() {
    assert_range_parity_threaded(750_000, 751_000);
}

#[test]
fn cost_parity_889000_890000() {
    assert_range_parity_threaded(889_000, 890_000);
}

#[test]
fn cost_parity_900000_901000() {
    assert_range_parity_threaded(900_000, 901_000);
}

#[test]
fn cost_parity_1000000_1001000() {
    assert_range_parity_threaded(1_000_000, 1_001_000);
}

#[test]
fn cost_parity_1100000_1101000() {
    assert_range_parity_threaded(1_100_000, 1_101_000);
}

#[test]
fn cost_parity_1300000_1301000() {
    assert_range_parity_threaded(1_300_000, 1_301_000);
}

#[test]
fn cost_parity_1500000_1501000() {
    assert_range_parity_threaded(1_500_000, 1_501_000);
}

#[test]
fn cost_parity_1750000_1751000() {
    assert_range_parity_threaded(1_750_000, 1_751_000);
}

// ---------------------------------------------------------------------------
// Aggregate summary — optional, for combined reporting
// ---------------------------------------------------------------------------

#[test]
fn cost_parity_all_ranges_summary() {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(all_ranges_summary_inner)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn all_ranges_summary_inner() {
    let dir = Path::new(VECTORS_DIR);
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "{}: missing — run test-vectors/scripts/extract_all_cost_vectors.sh first ({e})",
            dir.display()
        )
    });

    let mut ranges = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("tx_costs_") || !name.ends_with(".json") {
            continue;
        }
        let stem = name
            .trim_start_matches("tx_costs_")
            .trim_end_matches(".json");
        let parts: Vec<&str> = stem.split('_').collect();
        if parts.len() != 2 {
            continue;
        }
        let start: u32 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end: u32 = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(r) = build_range(start, end) {
            ranges.push(r);
        }
    }
    ranges.sort_by_key(|r| r.label.clone());

    assert!(
        !ranges.is_empty(),
        "no cost-parity ranges found under {} — run test-vectors/scripts/extract_all_cost_vectors.sh",
        dir.display()
    );

    let params = ProtocolParams::mainnet_default();
    let policy = LocalPolicy::default_policy();
    let mut total_matched = 0usize;
    let mut total_mismatches = 0usize;

    eprintln!("\n╔══════════════════════════════════════════════════��═══════╗");
    eprintln!("║              COST PARITY: Rust vs Scala                 ║");
    eprintln!("╠══════════════════════════════════════════════════════════╣");

    for range in &ranges {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_range(range, &params, &policy)
        }));
        match r {
            Ok(r) => {
                let n = r.matched + r.mismatches.len();
                let status = if r.mismatches.is_empty() {
                    "✓"
                } else {
                    "✗"
                };
                eprintln!(
                    "║ {status} {:<20} {:>5}/{:<5} matched  {:>3} err  {:>3} skip ║",
                    r.label, r.matched, n, r.eval_errors, r.scala_unmatched,
                );
                total_matched += r.matched;
                total_mismatches += r.mismatches.len();
            }
            Err(_) => {
                eprintln!(
                    "║ ✗ {:<20} PANIC                                    ║",
                    range.label
                );
                total_mismatches += 1;
            }
        }
    }

    let total = total_matched + total_mismatches;
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!(
        "║   TOTAL: {}/{} exact matches across {} ranges          ║",
        total_matched,
        total,
        ranges.len(),
    );
    eprintln!("╚══════════════════════════════════════════════════════════╝");

    assert_eq!(
        total_mismatches, 0,
        "{total_mismatches} mismatches across all ranges"
    );
}

// ---------------------------------------------------------------------------
// Manifest coverage guard — fails if on-disk cost vectors drift from list
// ---------------------------------------------------------------------------

const EXPECTED_COST_RANGES: &[(u32, u32)] = &[
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

#[test]
fn cost_parity_manifest_coverage() {
    let dir = Path::new(VECTORS_DIR);
    let on_disk: std::collections::BTreeSet<String> = std::fs::read_dir(dir)
        .expect("test-vectors/mainnet dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("tx_costs_") && n.ends_with(".json"))
        .collect();

    let manifest: std::collections::BTreeSet<String> = EXPECTED_COST_RANGES
        .iter()
        .map(|(s, e)| format!("tx_costs_{s}_{e}.json"))
        .collect();

    let untested: Vec<&String> = on_disk.difference(&manifest).collect();
    let missing: Vec<&String> = manifest.difference(&on_disk).collect();

    assert!(
        untested.is_empty() && missing.is_empty(),
        "Cost parity manifest out of sync.\n  \
         Untested on-disk files (add sharded test): {untested:?}\n  \
         Missing from disk (remove sharded test): {missing:?}"
    );
}

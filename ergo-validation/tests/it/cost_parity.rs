//! Oracle: test-vectors/scripts/scala/ComputeTransactionCosts.scala
//! Field-by-field block-unit comparisons against one JVM validateStateful run.

use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::{ergo_box, header, transaction};
use ergo_sigma::cost_trace::{self, CostTrace};
use ergo_validation::context::{LocalPolicy, ProtocolParams, TransactionContext};
use ergo_validation::{tx::validate_transaction, TxValidationCtx, TxValidationRules, UtxoView};
use serde::Deserialize;
use std::collections::HashMap;

// ----- helpers -----

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct InputCost {
    index: usize,
    eval_block_cost: u64,
    crypto_block_cost: u64,
    rent: u64,
}

#[derive(Debug, Deserialize)]
struct ScalaCostVector {
    tx_id: String,
    height: u32,
    block_cost: u64,
    init_block_cost: u64,
    token_block_cost: u64,
    inputs: Vec<InputCost>,
}

/// Read observations from the accepted production validation run. Crypto deltas
/// are already rounded by the evaluator; input boundary totals include its snap.
fn compare_breakdown(expected: &ScalaCostVector, total: u64, trace: &CostTrace) {
    let mut inputs = Vec::new();
    let mut start = None;
    let mut crypto = 0;
    let mut rent = 0;
    for entry in &trace.entries {
        if let Some(index) = entry.label.strip_prefix("InputStart:") {
            assert!(start.is_none(), "overlapping input observations");
            start = Some((index.parse::<usize>().unwrap(), entry.total));
            crypto = 0;
            rent = 0;
        } else if entry.label.starts_with("Crypto:") {
            crypto += entry.delta;
        } else if entry.label.starts_with("Rent:") {
            rent += entry.delta;
        } else if let Some(index) = entry.label.strip_prefix("InputEnd:") {
            let (expected_index, before) = start.take().expect("input start");
            let index = index.parse::<usize>().unwrap();
            assert_eq!(index, expected_index);
            assert_eq!((entry.total - before) % 10, 0);
            inputs.push(InputCost {
                index,
                eval_block_cost: (entry.total - before - crypto - rent) / 10,
                crypto_block_cost: crypto / 10,
                rent: rent / 10,
            });
        }
    }
    assert!(start.is_none(), "unfinished input observation");
    assert_eq!(trace.count_by_prefix("TxInit"), 1);
    assert_eq!(trace.count_by_prefix("TxToken"), 1);
    let init = trace.sum_by_prefix("TxInit") / 10;
    let token = trace.sum_by_prefix("TxToken") / 10;
    assert_eq!(init, expected.init_block_cost, "{} init", expected.tx_id);
    assert_eq!(token, expected.token_block_cost, "{} token", expected.tx_id);
    assert_eq!(inputs, expected.inputs, "{} inputs", expected.tx_id);
    assert_eq!(total, expected.block_cost, "{} total", expected.tx_id);
    assert_eq!(
        init + token
            + inputs
                .iter()
                .map(|i| i.eval_block_cost + i.crypto_block_cost + i.rent)
                .sum::<u64>(),
        total,
        "{} Rust reconciliation",
        expected.tx_id
    );
    assert_eq!(
        expected.init_block_cost
            + expected.token_block_cost
            + expected
                .inputs
                .iter()
                .map(|i| i.eval_block_cost + i.crypto_block_cost + i.rent)
                .sum::<u64>(),
        expected.block_cost,
        "{} JVM reconciliation",
        expected.tx_id
    );
}

struct MapUtxo(HashMap<Digest32, ergo_box::ErgoBox>);
impl UtxoView for MapUtxo {
    fn get_box(&self, id: &Digest32) -> Option<ergo_box::ErgoBox> {
        self.0.get(id).cloned()
    }
}

#[derive(Deserialize)]
struct FixtureTransaction {
    #[serde(flatten)]
    cost: ScalaCostVector,
    tx_bytes: String,
}

#[derive(Deserialize)]
struct HeaderBytes {
    height: u32,
    bytes: String,
}

#[derive(Deserialize)]
struct BoxBytes {
    box_id: String,
    bytes: String,
}

#[derive(Deserialize)]
struct Parameters {
    storage_fee_factor: i32,
    min_value_per_byte: u64,
    max_block_cost: u64,
    input_cost: u64,
    data_input_cost: u64,
    output_cost: u64,
    token_access_cost: u64,
    block_version: u8,
}

#[derive(Deserialize)]
struct Fixture {
    manifest: serde_json::Value,
    headers: Vec<HeaderBytes>,
    boxes: Vec<BoxBytes>,
    parameters: HashMap<String, Parameters>,
    transactions: Vec<FixtureTransaction>,
}

// ----- oracle parity -----

#[test]
fn transaction_breakdown_mainnet_all_ten_match_jvm() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../test-vectors/ergo-sigma/cost-total/breakdown_700000_700001.json"
    ))
    .unwrap();
    assert_eq!(fixture.manifest["ergo_core_version"], "6.0.5");
    assert_eq!(fixture.manifest["ergo_wallet_version"], "6.0.5");
    assert_eq!(fixture.manifest["sigma_state_version"], "6.0.6");
    assert_eq!(fixture.transactions.len(), 10);
    let headers: HashMap<_, _> = fixture
        .headers
        .iter()
        .map(|h| {
            let bytes = hex::decode(&h.bytes).unwrap();
            let parsed = header::read_header(&mut VlqReader::new(&bytes)).unwrap();
            assert_eq!(parsed.height, h.height);
            (h.height, parsed)
        })
        .collect();
    let utxo = MapUtxo(
        fixture
            .boxes
            .iter()
            .map(|b| {
                let bytes = hex::decode(&b.bytes).unwrap();
                let parsed = ergo_box::read_ergo_box(&mut VlqReader::new(&bytes)).unwrap();
                let id = parsed.box_id().unwrap();
                assert_eq!(hex::encode(id.as_bytes()), b.box_id);
                (id, parsed)
            })
            .collect(),
    );
    for tx in &fixture.transactions {
        let h = tx.cost.height;
        let hdr = &headers[&h];
        let p = &fixture.parameters[&h.to_string()];
        let params = ProtocolParams {
            storage_fee_factor: p.storage_fee_factor,
            min_value_per_byte: p.min_value_per_byte,
            max_block_cost: p.max_block_cost,
            input_cost: p.input_cost,
            data_input_cost: p.data_input_cost,
            output_cost: p.output_cost,
            token_access_cost: p.token_access_cost,
            ..ProtocolParams::mainnet_default()
        };
        let ctx = TransactionContext {
            height: h,
            miner_pubkey: *hdr.solution.pk().as_bytes(),
            pre_header_timestamp: hdr.timestamp,
            activated_script_version: p.block_version - 1,
            pre_header_version: hdr.version,
            pre_header_parent_id: *hdr.parent_id.as_bytes(),
            pre_header_n_bits: u64::from(hdr.n_bits),
            pre_header_votes: hdr.votes,
        };
        let last_headers: Vec<_> = (h - 9..h).rev().map(|i| headers[&i].clone()).collect();
        let mut cost = CostAccumulator::new(JitCost::from_block_cost(p.max_block_cost).unwrap());
        let mut cx = TxValidationCtx {
            ctx: &ctx,
            params: &params,
            cost: &mut cost,
            last_headers: &last_headers,
            rules: TxValidationRules::default(),
        };
        let bytes = hex::decode(&tx.tx_bytes).unwrap();
        let parsed = transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
        assert_eq!(
            hex::encode(transaction::transaction_id(&parsed).unwrap().as_bytes()),
            tx.cost.tx_id
        );
        cost_trace::enable();
        let result = validate_transaction(&bytes, &utxo, &LocalPolicy::default_policy(), &mut cx);
        let trace = cost_trace::take().unwrap();
        result.unwrap_or_else(|e| panic!("{}: JVM Accept, Rust {e}", tx.cost.tx_id));
        compare_breakdown(&tx.cost, cost.total_block_cost(), &trace);
    }
}

#[cfg(feature = "diagnostics")]
mod ranges {
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

    // ----- helpers -----

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
        _bytes_to_sign: String,
        height: u32,
    }

    #[derive(serde::Deserialize)]
    struct HeaderVector {
        height: u32,
        bytes: String,
    }

    use super::{compare_breakdown, ScalaCostVector};
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
        let scala_map: HashMap<String, &ScalaCostVector> =
            scala_costs.iter().map(|c| (c.tx_id.clone(), c)).collect();

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

        // Sorted heights for building last-nine context.
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
                activated_script_version: headers_by_height[&v.height].version - 1,
                pre_header_version: headers_by_height[&v.height].version,
                pre_header_parent_id: *headers_by_height[&v.height].parent_id.as_bytes(),
                pre_header_n_bits: u64::from(headers_by_height[&v.height].n_bits),
                pre_header_votes: headers_by_height[&v.height].votes,
            };
            let mut cost =
                CostAccumulator::new(JitCost::from_block_cost(BLOCK_COST_LIMIT).unwrap());

            // Build last nine headers for CONTEXT.headers.
            // Find up to nine headers with height < current block height.
            let last_headers: Vec<ergo_ser::header::Header> = {
                let pos = sorted_heights.partition_point(|&h| h < v.height);
                let start = pos.saturating_sub(9);
                sorted_heights[start..pos]
                    .iter()
                    .rev()
                    .filter_map(|h| headers_by_height.get(h).cloned())
                    .collect()
            };

            let mut tx_cx = ergo_validation::TxValidationCtx {
                ctx: &ctx,
                params,
                cost: &mut cost,
                last_headers: &last_headers,
                rules: ergo_validation::TxValidationRules::default(),
            };
            ergo_sigma::cost_trace::enable();
            let result = validate_transaction(&tx_bytes, &utxo, policy, &mut tx_cx);
            let trace = ergo_sigma::cost_trace::take().unwrap();
            match result {
                Ok(checked) => {
                    let rust_cost = cost.total_block_cost();

                    if let Some(expected) = scala_map.get(&v.id) {
                        assert_eq!(expected.height, v.height);
                        compare_breakdown(expected, rust_cost, &trace);
                        let scala_cost = expected.block_cost;
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
                        assert!(
                            !scala_map.contains_key(&v.id),
                            "{}: JVM Accept, Rust rejected: {e}",
                            v.id
                        );
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
            "{}: {}/{} matched, {} eval_errors, {} scala_unmatched, {} rust_only",
            r.label, r.matched, compared, r.eval_errors, r.scala_unmatched, r.rust_only,
        );

        assert!(compared > 0, "no transactions compared");
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

    // ----- oracle parity -----

    #[test]
    fn cost_parity_500000_501000_matches_jvm() {
        assert_range_parity_threaded(500_000, 501_000);
    }

    #[test]
    fn cost_parity_700000_700200_matches_jvm() {
        assert_range_parity_threaded(700_000, 700_200);
    }

    #[test]
    fn cost_parity_700000_701000_matches_jvm() {
        assert_range_parity_threaded(700_000, 701_000);
    }

    #[test]
    fn cost_parity_750000_751000_matches_jvm() {
        assert_range_parity_threaded(750_000, 751_000);
    }

    #[test]
    fn cost_parity_889000_890000_matches_jvm() {
        assert_range_parity_threaded(889_000, 890_000);
    }

    #[test]
    fn cost_parity_900000_901000_matches_jvm() {
        assert_range_parity_threaded(900_000, 901_000);
    }

    #[test]
    fn cost_parity_1000000_1001000_matches_jvm() {
        assert_range_parity_threaded(1_000_000, 1_001_000);
    }

    #[test]
    fn cost_parity_1100000_1101000_matches_jvm() {
        assert_range_parity_threaded(1_100_000, 1_101_000);
    }

    #[test]
    fn cost_parity_1300000_1301000_matches_jvm() {
        assert_range_parity_threaded(1_300_000, 1_301_000);
    }

    #[test]
    fn cost_parity_1500000_1501000_matches_jvm() {
        assert_range_parity_threaded(1_500_000, 1_501_000);
    }

    #[test]
    fn cost_parity_1750000_1751000_matches_jvm() {
        assert_range_parity_threaded(1_750_000, 1_751_000);
    }

    #[test]
    fn cost_parity_all_ranges_match_jvm() {
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
    fn cost_parity_manifest_covers_ranges() {
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
}

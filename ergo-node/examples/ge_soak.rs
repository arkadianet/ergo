//! Scan stored transaction sections for GroupElements rejected by the production validator.
//!
//! The default gate requires every section at heights 1..=the committed full-block
//! tip. Missing sections or an empty range make the result incomplete. Explicit
//! `--allow-partial` mode can pass a nonempty subset, labelled `PARTIAL_PASS`;
//! it never certifies missing history. A clean complete scan covers points exposed
//! by the production transaction parser in this database, without independently
//! authenticating its chain or proving absence of points the parser does not expose.
//!
//! The scan uses one committed read transaction. Opening `StateStore` can perform
//! its normal maintenance; use an offline copy with the owning node stopped
//! (redb takes an exclusive lock).
//!
//! Usage: `cargo run --release --example ge_soak -- --data-dir <data_dir>`.
//! The store file must already exist at `<data_dir>/state.redb`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions_with_group_elements;
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_state::store::{CommittedSnapshot, StateStore};

#[derive(Parser)]
#[command(about = "Check GroupElements in stored historical transaction sections")]
struct Args {
    /// Node data directory containing an existing state.redb.
    #[arg(long)]
    data_dir: PathBuf,
    /// Permit a labelled partial result when transaction sections are missing.
    #[arg(long)]
    allow_partial: bool,
}

#[derive(Default)]
struct ScanSummary {
    tip: u32,
    scanned_sections: u32,
    missing_sections: u32,
    transactions: u64,
    group_elements: u64,
    rejections: u64,
    rejected_examples: Vec<(u32, String, String)>,
}

#[derive(Debug, PartialEq)]
enum Verdict {
    CompletePass,
    PartialPass,
    Incomplete,
    Rejected,
}

impl ScanSummary {
    fn verdict(&self, allow_partial: bool) -> Verdict {
        if self.rejections > 0 {
            Verdict::Rejected
        } else if self.scanned_sections == 0 {
            Verdict::Incomplete
        } else if self.missing_sections == 0 {
            Verdict::CompletePass
        } else if allow_partial {
            Verdict::PartialPass
        } else {
            Verdict::Incomplete
        }
    }
}

impl Verdict {
    fn message(&self) -> &'static str {
        match self {
            Self::CompletePass => {
                "PASS (all parsed group elements in the complete stored range passed)"
            }
            Self::PartialPass => {
                "PARTIAL_PASS (inspected sections passed; missing history is unverified)"
            }
            Self::Incomplete => "INCOMPLETE (the full stored range was not inspected)",
            Self::Rejected => "FAIL (stored group elements were rejected)",
        }
    }

    fn exit_code(&self) -> u8 {
        match self {
            Self::CompletePass | Self::PartialPass => 0,
            Self::Incomplete | Self::Rejected => 1,
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    match scan_data_dir(&args.data_dir) {
        Ok(summary) => {
            println!("---- GE soak summary ----");
            println!("tip height         : {}", summary.tip);
            println!("inspected sections : {}", summary.scanned_sections);
            println!("missing sections   : {}", summary.missing_sections);
            println!("transactions       : {}", summary.transactions);
            println!("group elements     : {}", summary.group_elements);
            println!("rejections         : {}", summary.rejections);
            let verdict = summary.verdict(args.allow_partial);
            println!("RESULT: {}", verdict.message());
            for (height, point, error) in &summary.rejected_examples {
                println!("  h={height} ge={point} err={error}");
            }
            let omitted = summary.rejections - summary.rejected_examples.len() as u64;
            if omitted > 0 {
                println!("  .. and {omitted} more");
            }
            ExitCode::from(verdict.exit_code())
        }
        Err(error) => {
            eprintln!("RESULT: ERROR ({error})");
            ExitCode::FAILURE
        }
    }
}

fn scan_data_dir(data_dir: &Path) -> Result<ScanSummary, String> {
    let db_path = data_dir.join("state.redb");
    if !db_path.is_file() {
        return Err(format!("existing store required: {}", db_path.display()));
    }
    eprintln!("opening {}", db_path.display());
    let store = StateStore::open(&db_path).map_err(|e| format!("open failed: {e}"))?;
    let snapshot = store
        .committed_snapshot()
        .map_err(|e| format!("committed_snapshot failed: {e}"))?
        .ok_or_else(|| "no committed snapshot".to_owned())?;
    scan_snapshot(&snapshot)
}

fn scan_snapshot(snapshot: &CommittedSnapshot) -> Result<ScanSummary, String> {
    let mut summary = ScanSummary {
        tip: snapshot.best_full_block_height(),
        ..ScanSummary::default()
    };
    eprintln!(
        "best_full_block_height = {}; scanning 1..={}",
        summary.tip, summary.tip
    );
    for height in 1..=summary.tip {
        let header_id = snapshot
            .header_id_at_height(height)
            .map_err(|e| format!("height {height}: header_id_at_height: {e}"))?
            .ok_or_else(|| format!("height {height}: no header id in index"))?;
        let header = snapshot
            .header(&header_id)
            .map_err(|e| format!("height {height}: header: {e}"))?
            .ok_or_else(|| format!("height {height}: header bytes missing"))?;
        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &header_id,
            header.transactions_root.as_bytes(),
        );
        let Some(bytes) = snapshot
            .block_section(&section_id)
            .map_err(|e| format!("height {height}: block_section: {e}"))?
        else {
            summary.missing_sections += 1;
            continue;
        };
        // The production reader drains its sideband per transaction; collect
        // from its returned vectors rather than from the reader afterwards.
        let (transactions, per_tx_points) =
            read_block_transactions_with_group_elements(&mut VlqReader::new(&bytes))
                .map_err(|e| format!("height {height}: read_block_transactions: {e}"))?;
        summary.scanned_sections += 1;
        summary.transactions += transactions.transactions.len() as u64;
        for point in per_tx_points.into_iter().flatten() {
            summary.group_elements += 1;
            if let Err(error) = ergo_sigma::evaluator::validate_group_element(point) {
                summary.rejections += 1;
                if summary.rejected_examples.len() < 50 {
                    summary
                        .rejected_examples
                        .push((height, hex::encode(point), error.to_string()));
                }
            }
        }
        if height % 100_000 == 0 {
            eprintln!(
                "  .. h={height} txs={} ges={} rejects={}",
                summary.transactions, summary.group_elements, summary.rejections
            );
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::{digest::ModifierId, writer::VlqWriter};
    use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};

    // ----- helpers -----

    fn fixture_store(sections: &[u32]) -> (StateStore, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&directory.path().join("state.redb")).unwrap();
        store
            .initialize_genesis(&ergo_node::genesis::mainnet_genesis_boxes())
            .unwrap();
        let headers = ergo_state::test_helpers::seed_dense_mainnet_headers(&mut store, 3).unwrap();
        let transactions: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../test-vectors/mainnet/transactions_1_10.json"
        ))
        .unwrap();
        for (height, id) in &headers {
            if !sections.contains(height) {
                continue;
            }
            let row = transactions
                .iter()
                .find(|row| row["height"].as_u64() == Some(u64::from(*height)))
                .unwrap();
            let bytes = hex::decode(row["bytes"].as_str().unwrap()).unwrap();
            let transaction =
                ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap();
            let header_bytes = store.get_header(id).unwrap().unwrap();
            let header = ergo_ser::header::read_header(&mut VlqReader::new(&header_bytes)).unwrap();
            let section_id = compute_section_id(
                TYPE_BLOCK_TRANSACTIONS,
                id,
                header.transactions_root.as_bytes(),
            );
            let mut writer = VlqWriter::new();
            write_block_transactions(
                &mut writer,
                &BlockTransactions {
                    header_id: ModifierId::from_bytes(*id),
                    transactions: vec![transaction],
                },
            )
            .unwrap();
            store
                .store_block_section_typed(&section_id, &writer.result(), TYPE_BLOCK_TRANSACTIONS)
                .unwrap();
        }
        // Only the stored scan range matters here. This metadata does not
        // claim the fixture transactions have been applied to UTXO state.
        store.advance_best_full_block(headers[2].1, 3).unwrap();
        (store, directory)
    }

    // ----- happy path -----

    #[test]
    fn complete_fixture_history_passes_with_exact_section_denominator() {
        let (store, _directory) = fixture_store(&[1, 2, 3]);
        let summary = scan_snapshot(&store.committed_snapshot().unwrap().unwrap()).unwrap();
        assert_eq!(summary.scanned_sections, 3);
        assert_eq!(summary.missing_sections, 0);
        assert_eq!(summary.transactions, 3);
        assert_eq!(summary.rejections, 0);
        assert_eq!(summary.verdict(false), Verdict::CompletePass);
        assert_eq!(summary.verdict(false).exit_code(), 0);
    }

    #[test]
    fn explicit_partial_mode_labels_only_the_inspected_subset() {
        let (store, _directory) = fixture_store(&[1, 3]);
        let summary = scan_snapshot(&store.committed_snapshot().unwrap().unwrap()).unwrap();
        assert_eq!(summary.scanned_sections, 2);
        assert_eq!(summary.missing_sections, 1);
        assert_eq!(summary.verdict(true), Verdict::PartialPass);
        assert!(summary.verdict(true).message().starts_with("PARTIAL_PASS"));
        assert_eq!(summary.verdict(true).exit_code(), 0);
    }

    // ----- error paths -----

    #[test]
    fn missing_one_or_all_sections_cannot_pass_the_full_history_gate() {
        for sections in [&[1, 3][..], &[][..]] {
            let (store, _directory) = fixture_store(sections);
            let summary = scan_snapshot(&store.committed_snapshot().unwrap().unwrap()).unwrap();
            assert_eq!(summary.scanned_sections as usize, sections.len());
            assert_eq!(summary.missing_sections as usize, 3 - sections.len());
            assert_eq!(summary.verdict(false), Verdict::Incomplete);
            assert_eq!(summary.verdict(false).exit_code(), 1);
            if sections.is_empty() {
                assert_eq!(summary.verdict(true), Verdict::Incomplete);
            }
        }
    }

    #[test]
    fn rejection_fails_even_when_partial_mode_is_requested() {
        let summary = ScanSummary {
            tip: 3,
            scanned_sections: 2,
            missing_sections: 1,
            rejections: 1,
            ..ScanSummary::default()
        };
        for allow_partial in [false, true] {
            assert_eq!(summary.verdict(allow_partial), Verdict::Rejected);
            assert_eq!(summary.verdict(allow_partial).exit_code(), 1);
        }
    }

    #[test]
    fn empty_range_and_absent_database_fail_without_creating_a_store() {
        assert_eq!(ScanSummary::default().verdict(true), Verdict::Incomplete);
        let directory = tempfile::tempdir().unwrap();
        assert!(scan_data_dir(directory.path()).is_err());
        assert!(!directory.path().join("state.redb").exists());
    }
}

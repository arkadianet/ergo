//! Full-history GroupElement on-curve soak (gate for the deserialize curve-check fix).
//!
//! Read-only scan of an archival state store: for every full block 1..=tip it
//! reads the persisted block-transactions section, re-parses it through the
//! production `VlqReader` (which records every 33-byte group element on the
//! crypto-free sideband), and curve-checks each point via the exact production
//! validator (`ergo_sigma::evaluator::validate_group_element`).
//!
//! For an accept-invalid fix the soak's job is to prove **no false positive**:
//! every group element ever accepted by the Scala reference (mainnet history)
//! must pass the new check. Expected result is zero rejections. A non-empty
//! reject list means our curve check is stricter than JVM `decodePoint` — a
//! reject-valid divergence we'd be introducing.
//!
//! Read-only by discipline: opens the store but only issues read transactions
//! (`committed_snapshot`), never a write. Run only while the owning node is
//! stopped (redb takes an exclusive lock).
//!
//! Usage: `cargo run --release --example ge_soak -- --data-dir <data_dir>`
//! (`<data_dir>` is the node's `data_dir`; the store file is `<data_dir>/state.redb`.)

use std::path::PathBuf;

use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions_with_group_elements;
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS};
use ergo_state::store::StateStore;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut data_dir: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--data-dir" => data_dir = args.next().map(PathBuf::from),
            other => {
                if data_dir.is_none() && !other.starts_with("--") {
                    data_dir = Some(PathBuf::from(other));
                } else {
                    eprintln!("unexpected arg: {other}");
                    std::process::exit(2);
                }
            }
        }
    }
    let data_dir = data_dir.unwrap_or_else(|| {
        eprintln!("usage: ge_soak --data-dir <data_dir>");
        std::process::exit(2);
    });

    let db_path = data_dir.join("state.redb");
    eprintln!("opening (read-only) {}", db_path.display());
    let store = StateStore::open(&db_path).unwrap_or_else(|e| {
        eprintln!("open failed: {e:?}");
        std::process::exit(1);
    });
    let snap = store
        .committed_snapshot()
        .unwrap_or_else(|e| {
            eprintln!("committed_snapshot failed: {e:?}");
            std::process::exit(1);
        })
        .unwrap_or_else(|| {
            eprintln!("no committed snapshot (empty store?)");
            std::process::exit(1);
        });

    let tip = snap.best_full_block_height();
    eprintln!("best_full_block_height = {tip}; scanning 1..={tip}");

    let mut total_txs: u64 = 0;
    let mut total_ges: u64 = 0;
    let mut missing_sections: u64 = 0;
    let mut rejects: Vec<(u32, String, String)> = Vec::new();

    for height in 1..=tip {
        let header_id = match snap.header_id_at_height(height) {
            Ok(Some(id)) => id,
            Ok(None) => {
                eprintln!("height {height}: no header id in index — aborting");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("height {height}: header_id_at_height: {e:?}");
                std::process::exit(1);
            }
        };
        let header = match snap.header(&header_id) {
            Ok(Some(h)) => h,
            Ok(None) => {
                eprintln!("height {height}: header bytes missing — aborting");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("height {height}: header: {e:?}");
                std::process::exit(1);
            }
        };

        let section_id = compute_section_id(
            TYPE_BLOCK_TRANSACTIONS,
            &header_id,
            header.transactions_root.as_bytes(),
        );
        let bytes = match snap.block_section(&section_id) {
            Ok(Some(b)) => b,
            Ok(None) => {
                // Pruned/absent section. On an archival node (blocks_to_keep=-1)
                // this should not happen below tip; count it so the summary is honest.
                missing_sections += 1;
                continue;
            }
            Err(e) => {
                eprintln!("height {height}: block_section: {e:?}");
                std::process::exit(1);
            }
        };

        let mut r = VlqReader::new(&bytes);
        // Use the GE-collecting reader: read_block_transactions now drains the
        // reader's group-element sideband per tx, so points must be taken from
        // the returned per-tx vec, not off the reader afterwards.
        let (bt, per_tx_ges) = match read_block_transactions_with_group_elements(&mut r) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("height {height}: read_block_transactions: {e:?}");
                std::process::exit(1);
            }
        };
        total_txs += bt.transactions.len() as u64;

        for ge in per_tx_ges.into_iter().flatten() {
            total_ges += 1;
            if let Err(e) = ergo_sigma::evaluator::validate_group_element(ge) {
                rejects.push((height, hex::encode(ge), format!("{e:?}")));
            }
        }

        if height % 100_000 == 0 {
            eprintln!(
                "  .. h={height} txs={total_txs} ges={total_ges} rejects={}",
                rejects.len()
            );
        }
    }

    println!("---- GE soak summary ----");
    println!("tip height        : {tip}");
    println!("transactions       : {total_txs}");
    println!("group elements     : {total_ges}");
    println!("missing sections   : {missing_sections}");
    println!("rejections         : {}", rejects.len());
    if rejects.is_empty() {
        println!("RESULT: PASS (every historical group element is on-curve / identity)");
    } else {
        println!("RESULT: FAIL — these points would now be rejected (reject-valid risk):");
        for (h, ge, err) in rejects.iter().take(50) {
            println!("  h={h} ge={ge} err={err}");
        }
        if rejects.len() > 50 {
            println!("  .. and {} more", rejects.len() - 50);
        }
        std::process::exit(1);
    }
}

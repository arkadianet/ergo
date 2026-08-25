#![cfg(feature = "diagnostics")]
//! Triage harness for the 17 transaction roundtrip failures.
//! Identifies first divergence offset and surrounding byte windows.

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::transaction::{read_transaction, write_transaction};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionVector {
    id: String,
    bytes: String,
    height: u32,
}

fn load_all_vectors() -> Vec<TransactionVector> {
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/mainnet");
    let mut all = Vec::new();
    for entry in fs::read_dir(&vectors_dir).expect("test-vectors/mainnet dir") {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("transactions_") && name.ends_with(".json") {
            let data = fs::read_to_string(entry.path()).unwrap();
            let vectors: Vec<TransactionVector> = serde_json::from_str(&data)
                .unwrap_or_else(|e| panic!("failed to parse {name}: {e}"));
            all.extend(vectors);
        }
    }
    all
}

#[test]
fn triage_roundtrip_failures() {
    let vectors = load_all_vectors();
    let mut failures = Vec::new();

    for v in &vectors {
        let raw = hex::decode(&v.bytes).unwrap();
        let mut r = VlqReader::new(&raw);
        let tx = match read_transaction(&mut r) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("PARSE ERROR: tx {}... h={} err={e}", &v.id[..16], v.height);
                continue;
            }
        };

        let mut w = VlqWriter::new();
        write_transaction(&mut w, &tx).unwrap();
        let reser = w.result();

        if raw != reser {
            failures.push((v, raw, reser));
        }
    }

    eprintln!("\n=== {} ROUNDTRIP FAILURES ===\n", failures.len());

    for (v, raw, reser) in &failures {
        let first_diff = raw
            .iter()
            .zip(reser.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(raw.len().min(reser.len()));

        let len_diff: i64 = raw.len() as i64 - reser.len() as i64;

        eprintln!(
            "TX {}  h={}  orig={}  reser={}  len_delta={:+}  first_diff={}",
            &v.id[..16],
            v.height,
            raw.len(),
            reser.len(),
            len_diff,
            first_diff
        );

        // Show byte window around first divergence
        let start = first_diff.saturating_sub(8);
        let end_orig = (first_diff + 16).min(raw.len());
        let end_reser = (first_diff + 16).min(reser.len());

        eprintln!(
            "  orig [{start}..{end_orig}]: {}",
            hex::encode(&raw[start..end_orig])
        );
        eprintln!(
            "  rser [{start}..{end_reser}]: {}",
            hex::encode(&reser[start..end_reser])
        );

        // Compare bytes_to_sign (proofs stripped) to isolate proof vs output divergence
        let mut r2 = VlqReader::new(raw);
        if let Ok(tx) = read_transaction(&mut r2) {
            eprintln!(
                "  n_inputs={} n_data_inputs={} n_outputs={}",
                tx.inputs.len(),
                tx.data_inputs.len(),
                tx.output_candidates.len()
            );

            let bts = ergo_ser::transaction::bytes_to_sign(&tx).unwrap();
            let mut w_full = VlqWriter::new();
            write_transaction(&mut w_full, &tx).unwrap();
            let reser_full = w_full.result();

            // bytes_to_sign has: box_ids + empty_proofs + data_inputs + outputs
            // If bts roundtrips differently, the divergence is in outputs.
            // If bts matches but full tx doesn't, divergence is in proofs.

            // Re-parse reserialized to get bytes_to_sign
            let mut r3 = VlqReader::new(&reser_full);
            if let Ok(tx2) = read_transaction(&mut r3) {
                let bts2 = ergo_ser::transaction::bytes_to_sign(&tx2).unwrap();
                if bts == bts2 {
                    eprintln!("  DIVERGENCE IN: spending proofs (bytes_to_sign matches)");
                } else {
                    let bts_diff = bts
                        .iter()
                        .zip(bts2.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(bts.len().min(bts2.len()));
                    eprintln!(
                        "  DIVERGENCE IN: outputs/data (bytes_to_sign differs at {})",
                        bts_diff
                    );
                }
            }
        }
        eprintln!();
    }
}

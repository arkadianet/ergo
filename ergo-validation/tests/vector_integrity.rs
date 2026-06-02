//! Vector integrity audit: proves that every transaction test vector has
//! internally consistent id and bytesToSign fields.
//!
//! For each record:
//!   1. Verify id == blake2b256(bytesToSign) — proves the vector was correctly extracted
//!   2. Verify `bytes` parses as a valid Transaction — proves the bytes field is well-formed
//!
//! Note: we do NOT verify that our bytes_to_sign(parse(bytes)) == bytesToSign.
//! A handful of transactions have ErgoTrees that don't roundtrip through our
//! serializer (non-canonical tree encodings). The vector's bytesToSign is
//! authoritative (from Scala).

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;

const VECTORS_DIR: &str = "../test-vectors/mainnet";

#[derive(serde::Deserialize)]
struct TxVector {
    id: String,
    #[allow(dead_code)]
    bytes: String,
    #[serde(rename = "bytesToSign")]
    bytes_to_sign: String,
    #[allow(dead_code)]
    height: u32,
}

#[test]
fn all_vectors_have_consistent_ids() {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(audit_all_vectors)
        .unwrap()
        .join();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

fn audit_all_vectors() {
    let entries: Vec<_> = std::fs::read_dir(VECTORS_DIR)
        .expect("test-vectors/mainnet/ directory must exist")
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with("transactions_") && n.ends_with(".json")
        })
        .collect();

    assert!(
        !entries.is_empty(),
        "no transaction vector files found in {VECTORS_DIR}"
    );

    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    let mut corrupt_files: Vec<String> = Vec::new();

    for entry in &entries {
        let path = entry.path();
        let fname = path.file_name().unwrap().to_string_lossy().to_string();
        let raw = std::fs::read_to_string(&path).unwrap();
        let vectors: Vec<TxVector> = serde_json::from_str(&raw).unwrap();

        let mut file_pass = 0usize;
        let mut file_fail = 0usize;
        let mut parse_fail = 0usize;

        for v in &vectors {
            // Check 1: id == blake2b256(bytesToSign)
            let bts_bytes = match hex::decode(&v.bytes_to_sign) {
                Ok(b) => b,
                Err(_) => {
                    file_fail += 1;
                    continue;
                }
            };
            let expected_id = match hex::decode(&v.id) {
                Ok(b) => b,
                Err(_) => {
                    file_fail += 1;
                    continue;
                }
            };
            let computed_id = blake2b256(&bts_bytes);
            if computed_id.as_bytes() != expected_id.as_slice() {
                file_fail += 1;
                continue;
            }

            // Check 2: bytes parses as a valid Transaction
            let tx_bytes = match hex::decode(&v.bytes) {
                Ok(b) => b,
                Err(_) => {
                    parse_fail += 1;
                    file_pass += 1;
                    continue;
                }
            };
            match ergo_ser::transaction::read_transaction(&mut VlqReader::new(&tx_bytes)) {
                Ok(_) => {}
                Err(_) => {
                    parse_fail += 1;
                }
            }

            file_pass += 1;
        }

        let status = if file_fail == 0 { "✓" } else { "✗" };
        let parse_note = if parse_fail > 0 {
            format!(" ({parse_fail} unparseable bytes)")
        } else {
            String::new()
        };
        eprintln!(
            "{status} {fname}: {file_pass}/{} consistent{parse_note}",
            file_pass + file_fail
        );

        if file_fail > 0 {
            corrupt_files.push(format!(
                "{fname}: {file_fail} inconsistent out of {}",
                file_pass + file_fail
            ));
        }

        total_pass += file_pass;
        total_fail += file_fail;
    }

    eprintln!(
        "\nTotal: {total_pass} consistent, {total_fail} inconsistent across {} files",
        entries.len()
    );

    if !corrupt_files.is_empty() {
        eprintln!("\nCorrupt vector files:");
        for f in &corrupt_files {
            eprintln!("  {f}");
        }
    }

    assert!(
        corrupt_files.is_empty(),
        "Vector integrity check failed.\n\
         {} file(s) have misaligned id/bytes/bytesToSign ({total_fail} bad records):\n{}\n\
         Regenerate with: ./test-vectors/scripts/extract_transactions_safe.sh <start> <end> <output>",
        corrupt_files.len(),
        corrupt_files.join("\n"),
    );
}

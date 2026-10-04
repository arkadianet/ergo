//! Hash consistency and complete transaction decoding for the captured corpus.
//!
//! Every record must satisfy id == blake2b256(bytesToSign), decode under the
//! explicit storage-reader script-version1 context, and consume all wire bytes.
//! This does not validate scripts, UTXO membership, or canonical reserialization:
//! captured bytesToSign remains independent Scala extraction evidence.

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;

const VECTORS_DIR: &str = "../test-vectors/mainnet";
const EXPECTED_FILES: [&str; 5] = [
    "transactions_1_10.json",
    "transactions_1_1000.json",
    "transactions_1_200.json",
    "transactions_205000_205200.json",
    "transactions_700000.json",
];
const EXPECTED_RECORDS: usize = 1548;

#[derive(serde::Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
    #[serde(rename = "bytesToSign")]
    bytes_to_sign: String,
    height: u32,
}

fn check_record(vector: &TxVector) -> Result<(), String> {
    let bytes_to_sign =
        hex::decode(&vector.bytes_to_sign).map_err(|error| format!("bytesToSign hex: {error}"))?;
    let expected_id = hex::decode(&vector.id).map_err(|error| format!("id hex: {error}"))?;
    if expected_id.as_slice() != blake2b256(&bytes_to_sign).as_bytes() {
        return Err("id differs from blake2b256(bytesToSign)".to_owned());
    }
    let bytes = hex::decode(&vector.bytes).map_err(|error| format!("bytes hex: {error}"))?;
    let mut reader = VlqReader::new(&bytes).with_activated_script_version(1);
    ergo_ser::transaction::read_transaction(&mut reader)
        .map_err(|error| format!("transaction parse: {error}"))?;
    if reader.position() != bytes.len() {
        return Err(format!(
            "trailing wire bytes: decoded {} of {}",
            reader.position(),
            bytes.len()
        ));
    }
    Ok(())
}

#[test]
fn all_vectors_have_consistent_ids_and_complete_wire_decoding() {
    let result = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(audit_all_vectors)
        .unwrap()
        .join();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

fn audit_all_vectors() {
    let mut entries: Vec<_> = std::fs::read_dir(VECTORS_DIR)
        .expect("test-vectors/mainnet/ directory must exist")
        .map(|entry| entry.expect("read corpus directory entry"))
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            name.starts_with("transactions_") && name.ends_with(".json")
        })
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect::<Vec<_>>(),
        EXPECTED_FILES
    );
    let mut checked = 0;
    for entry in entries {
        let path = entry.path();
        let raw = std::fs::read_to_string(&path).unwrap();
        let vectors: Vec<TxVector> = serde_json::from_str(&raw).unwrap();
        assert!(!vectors.is_empty(), "empty corpus file {}", path.display());
        for vector in &vectors {
            check_record(vector).unwrap_or_else(|error| {
                panic!(
                    "{} height{} transaction{}: {error}",
                    path.display(),
                    vector.height,
                    vector.id
                )
            });
            checked += 1;
        }
        eprintln!(
            "{}: {}/{} hash-consistent and fully decoded",
            path.display(),
            vectors.len(),
            vectors.len()
        );
    }
    assert_eq!(
        checked, EXPECTED_RECORDS,
        "captured corpus denominator changed"
    );
}

#[test]
fn malformed_hex_parse_and_trailing_wire_bytes_fail_integrity() {
    let mut vectors: Vec<TxVector> = serde_json::from_str(include_str!(
        "../../../test-vectors/mainnet/transactions_1_10.json"
    ))
    .unwrap();
    let mut vector = vectors.remove(0);
    check_record(&vector).unwrap();
    let original = vector.bytes.clone();
    vector.bytes = "not-hex".to_owned();
    assert!(check_record(&vector).unwrap_err().starts_with("bytes hex:"));
    vector.bytes = String::new();
    assert!(check_record(&vector)
        .unwrap_err()
        .starts_with("transaction parse:"));
    vector.bytes = format!("{original}00");
    assert!(check_record(&vector)
        .unwrap_err()
        .starts_with("trailing wire bytes:"));
}

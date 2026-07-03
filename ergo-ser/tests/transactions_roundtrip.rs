//! Transaction roundtrip tests, sharded per vector file for parallelism.
//!
//! Each test verifies: byte-identical roundtrip, bytes_to_sign, and tx ID.

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::transaction::{bytes_to_sign, read_transaction, transaction_id, write_transaction};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionVector {
    id: String,
    bytes: String,
    bytes_to_sign: String,
    height: u32,
}

fn vectors_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/mainnet")
}

fn load_file(filename: &str) -> Vec<TransactionVector> {
    let path = vectors_dir().join(filename);
    assert!(path.exists(), "required vector file missing: {filename}");
    let data = fs::read_to_string(&path).unwrap();
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("failed to parse {filename}: {e}"))
}

fn assert_roundtrip(vectors: &[TransactionVector], label: &str) {
    assert!(!vectors.is_empty(), "{label}: vector file was empty");

    let mut pass = 0;
    let mut fail = 0;
    for v in vectors {
        let raw = hex::decode(&v.bytes)
            .unwrap_or_else(|e| panic!("bad hex for tx {} at height {}: {e}", v.id, v.height));

        let mut r = VlqReader::new(&raw);
        let tx = match read_transaction(&mut r) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL: tx {} height {} parse error: {e}", v.id, v.height);
                fail += 1;
                continue;
            }
        };

        let mut w = VlqWriter::new();
        write_transaction(&mut w, &tx).unwrap();
        let reserialized = w.result();

        if raw != reserialized {
            eprintln!(
                "FAIL: tx {} height {} byte mismatch ({} vs {} bytes)",
                v.id,
                v.height,
                raw.len(),
                reserialized.len()
            );
            fail += 1;
            continue;
        }

        let computed_bts = bytes_to_sign(&tx).unwrap();
        let expected_bts = hex::decode(&v.bytes_to_sign).unwrap();
        if computed_bts != expected_bts {
            eprintln!(
                "FAIL: tx {} height {} bytes_to_sign mismatch ({} vs {} bytes)",
                v.id,
                v.height,
                computed_bts.len(),
                expected_bts.len()
            );
            fail += 1;
            continue;
        }

        let computed_id = transaction_id(&tx).unwrap();
        let expected_id = hex::decode(&v.id).unwrap();
        if computed_id.as_bytes() != expected_id.as_slice() {
            eprintln!("FAIL: tx {} height {} ID mismatch", v.id, v.height);
            fail += 1;
            continue;
        }

        pass += 1;
    }

    eprintln!(
        "{label}: {pass} passed, {fail} failed out of {} total",
        vectors.len()
    );
    assert_eq!(fail, 0, "{label}: {fail} transactions failed roundtrip");
}

fn assert_bytes_to_sign_roundtrip(vectors: &[TransactionVector], label: &str) {
    if vectors.is_empty() {
        return;
    }

    let mut pass = 0;
    let mut fail = 0;
    for v in vectors {
        let bts_raw = hex::decode(&v.bytes_to_sign)
            .unwrap_or_else(|e| panic!("bad bytesToSign hex for tx {}: {e}", v.id));

        let mut r = VlqReader::new(&bts_raw);
        let tx = match read_transaction(&mut r) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL: bytesToSign tx {} parse error: {e}", v.id);
                fail += 1;
                continue;
            }
        };

        for (j, inp) in tx.inputs.iter().enumerate() {
            assert!(
                inp.spending_proof.proof.is_empty(),
                "tx {} input {j}: proof should be empty in bytesToSign",
                v.id
            );
        }

        let reserialized = bytes_to_sign(&tx).unwrap();
        if bts_raw != reserialized {
            eprintln!(
                "FAIL: bytesToSign tx {} byte mismatch ({} vs {} bytes)",
                v.id,
                bts_raw.len(),
                reserialized.len()
            );
            fail += 1;
            continue;
        }

        let computed_id = blake2b256(&bts_raw);
        let expected_id = hex::decode(&v.id).unwrap();
        if computed_id.as_bytes() != expected_id.as_slice() {
            eprintln!("FAIL: bytesToSign tx {} ID mismatch", v.id);
            fail += 1;
            continue;
        }

        pass += 1;
    }

    eprintln!("{label}: {pass} bytesToSign roundtrips passed, {fail} failed");
    assert_eq!(fail, 0, "{label}: {fail} bytesToSign roundtrips failed");
}

// ---------------------------------------------------------------------------
// Per-file sharded tests — cargo runs these in parallel
// ---------------------------------------------------------------------------

macro_rules! tx_roundtrip_test {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            let vectors = load_file($file);
            assert_roundtrip(&vectors, $file);
            assert_bytes_to_sign_roundtrip(&vectors, $file);
        }
    };
    (@ignored $name:ident, $file:expr) => {
        #[test]
        #[ignore = "needs gitignored mainnet tx range — extract via test-vectors/scripts then run with --ignored"]
        fn $name() {
            let vectors = load_file($file);
            assert_roundtrip(&vectors, $file);
            assert_bytes_to_sign_roundtrip(&vectors, $file);
        }
    };
    (@ignored_broad $name:ident, $file:expr) => {
        #[test]
        #[ignore = "broad corpus — run with --ignored"]
        fn $name() {
            let vectors = load_file($file);
            assert_roundtrip(&vectors, $file);
            assert_bytes_to_sign_roundtrip(&vectors, $file);
        }
    };
}

// Tracked tiny fixtures: run by default.
tx_roundtrip_test!(tx_roundtrip_1_10, "transactions_1_10.json");
tx_roundtrip_test!(tx_roundtrip_700000, "transactions_700000.json");

// Tracked broad fixtures: opt-in via --ignored.
tx_roundtrip_test!(@ignored_broad tx_roundtrip_1_200, "transactions_1_200.json");
tx_roundtrip_test!(@ignored_broad tx_roundtrip_1_1000, "transactions_1_1000.json");
tx_roundtrip_test!(
    @ignored_broad tx_roundtrip_205000_205200,
    "transactions_205000_205200.json"
);
// transactions_1_10000 / transactions_1761000_1762000 bulk ranges retired
// (see test-vectors/mainnet/FIXTURES.md); deep contiguous roundtrip coverage
// now runs via `ergo-difftest --bin replay`.

// Gitignored fixtures: opt-in via --ignored after extracting the range.
tx_roundtrip_test!(
    @ignored tx_roundtrip_417785_417800,
    "transactions_417785_417800.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_500000_501000,
    "transactions_500000_501000.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_700000_700200,
    "transactions_700000_700200.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_700000_701000,
    "transactions_700000_701000.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_750000_751000,
    "transactions_750000_751000.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_889000_890000,
    "transactions_889000_890000.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_900000_901000,
    "transactions_900000_901000.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_1000000_1001000,
    "transactions_1000000_1001000.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_1100000_1101000,
    "transactions_1100000_1101000.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_1300000_1301000,
    "transactions_1300000_1301000.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_1500000_1501000,
    "transactions_1500000_1501000.json"
);
tx_roundtrip_test!(
    @ignored tx_roundtrip_1750000_1751000,
    "transactions_1750000_1751000.json"
);

// ---------------------------------------------------------------------------
// Manifest coverage guard — fails if on-disk vectors drift from hardcoded list
// ---------------------------------------------------------------------------

const EXPECTED_TX_FILES: &[&str] = &[
    "transactions_1_10.json",
    "transactions_1_200.json",
    "transactions_1_1000.json",
    "transactions_1_10000.json",
    "transactions_205000_205200.json",
    "transactions_417785_417800.json",
    "transactions_500000_501000.json",
    "transactions_700000.json",
    "transactions_700000_700200.json",
    "transactions_700000_701000.json",
    "transactions_750000_751000.json",
    "transactions_889000_890000.json",
    "transactions_900000_901000.json",
    "transactions_1000000_1001000.json",
    "transactions_1100000_1101000.json",
    "transactions_1300000_1301000.json",
    "transactions_1500000_1501000.json",
    "transactions_1750000_1751000.json",
    "transactions_1761000_1762000.json",
];

#[test]
#[ignore = "manifest spans gitignored ranges; runs only with full extracted corpus — use --ignored"]
fn tx_roundtrip_manifest_coverage() {
    let dir = vectors_dir();
    let on_disk: std::collections::BTreeSet<String> = fs::read_dir(&dir)
        .expect("test-vectors/mainnet dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("transactions_") && n.ends_with(".json"))
        .collect();

    let manifest: std::collections::BTreeSet<String> =
        EXPECTED_TX_FILES.iter().map(|s| s.to_string()).collect();

    let untested: Vec<&String> = on_disk.difference(&manifest).collect();
    let missing: Vec<&String> = manifest.difference(&on_disk).collect();

    assert!(
        untested.is_empty() && missing.is_empty(),
        "Transaction roundtrip manifest out of sync.\n  \
         Untested on-disk files (add to macro list): {untested:?}\n  \
         Missing from disk (remove from macro list): {missing:?}"
    );
}

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::header::{read_header, write_header};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct HeaderVector {
    height: u32,
    id: String,
    bytes: String,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/mainnet")
}

fn load_header_file(filename: &str) -> Vec<HeaderVector> {
    let path = vectors_dir().join(filename);
    let data =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {filename}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("failed to parse {filename}: {e}"))
}

fn load_all_header_vectors() -> Vec<HeaderVector> {
    let mut all = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("test-vectors/mainnet dir") {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("headers_") && name.ends_with(".json") {
            let data = fs::read_to_string(entry.path()).unwrap();
            let vectors: Vec<HeaderVector> = serde_json::from_str(&data)
                .unwrap_or_else(|e| panic!("failed to parse {name}: {e}"));
            all.extend(vectors);
        }
    }
    all
}

fn assert_header_roundtrip(vectors: &[HeaderVector], min_pass: usize) {
    assert!(!vectors.is_empty(), "no header vectors found");

    let mut pass = 0;
    let mut fail = 0;
    for v in vectors {
        let raw =
            hex::decode(&v.bytes).unwrap_or_else(|e| panic!("bad hex at height {}: {e}", v.height));

        let mut r = VlqReader::new(&raw);
        let header = match read_header(&mut r) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("FAIL: height {} parse error: {e}", v.height);
                fail += 1;
                continue;
            }
        };

        let mut w = VlqWriter::new();
        write_header(&mut w, &header).expect("real mainnet header must serialize");
        let reserialized = w.result();

        if raw != reserialized {
            eprintln!(
                "FAIL: height {} byte mismatch (original {} bytes, reserialized {} bytes)",
                v.height,
                raw.len(),
                reserialized.len()
            );
            fail += 1;
            continue;
        }

        let computed_id = blake2b256(&raw);
        let expected_id = hex::decode(&v.id).unwrap();
        if computed_id.as_bytes() != expected_id.as_slice() {
            eprintln!(
                "FAIL: height {} ID mismatch: expected {}, got {:?}",
                v.height, v.id, computed_id
            );
            fail += 1;
            continue;
        }

        assert_eq!(header.height, v.height, "parsed height mismatch");
        pass += 1;
    }

    eprintln!(
        "{pass} headers passed, {fail} failed out of {} total",
        vectors.len()
    );
    assert_eq!(fail, 0, "{fail} headers failed roundtrip");
    assert!(
        pass >= min_pass,
        "need at least {min_pass} header vectors, got {pass}"
    );
}

/// Default-suite header oracle: roundtrips the tiny tracked
/// `headers_1_10.json` corpus only. Larger tracked shards are gated by
/// `header_roundtrip_broad` below.
#[test]
fn header_roundtrip_default() {
    let vectors = load_header_file("headers_1_10.json");
    assert_header_roundtrip(&vectors, 10);
}

/// Default-suite v2-era header oracle: five real mainnet headers
/// straddling the Autolykos-v2 fork boundary (h=417792) plus mid- and
/// late-v2 samples. Closes the v1-only gap left after Phase 2a moved
/// the broad header shards behind `--ignored`. Each entry in the
/// curated JSON carries `sourceFile` / `sourceHeight` / `selectionReason`
/// provenance fields, which serde tolerates because `HeaderVector`
/// declares only the three load-bearing fields.
#[test]
fn header_roundtrip_v2_curated() {
    let vectors = load_header_file("headers_v2_curated.json");
    assert_header_roundtrip(&vectors, 5);
}

#[test]
#[ignore = "broad corpus — run with --ignored"]
fn header_roundtrip_broad() {
    let vectors = load_all_header_vectors();
    assert_header_roundtrip(&vectors, 10);
}

use ergo_primitives::digest::blake2b256;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{parse_ergo_box_bytes, write_ergo_box};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BoxVector {
    box_id: String,
    bytes: String,
    ergo_tree: String,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/mainnet")
}

fn load_box_files(filenames: &[&str]) -> Vec<BoxVector> {
    let mut all = Vec::new();
    for name in filenames {
        let path = vectors_dir().join(name);
        let data =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {name}: {e}"));
        let vectors: Vec<BoxVector> =
            serde_json::from_str(&data).unwrap_or_else(|e| panic!("failed to parse {name}: {e}"));
        all.extend(vectors);
    }
    all
}

fn load_all_box_vectors() -> Vec<BoxVector> {
    let mut all = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("test-vectors/mainnet dir") {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("boxes_") && name.ends_with(".json") {
            let data = fs::read_to_string(entry.path()).unwrap();
            let vectors: Vec<BoxVector> = serde_json::from_str(&data)
                .unwrap_or_else(|e| panic!("failed to parse {name}: {e}"));
            all.extend(vectors);
        }
    }
    all
}

/// Known implementation gaps in the committed box corpus.
///
/// Each entry maps boxId -> reason. Keep this hook explicit so unsupported
/// boxes are tracked instead of being silently dropped from vectors.
fn known_gaps() -> BTreeMap<&'static str, &'static str> {
    // Keep the hook even when empty so future unsupported corpus boxes are
    // tracked explicitly instead of being silently dropped from vectors.
    BTreeMap::new()
}

fn assert_box_roundtrip(vectors: &[BoxVector], min_pass: usize) {
    assert!(!vectors.is_empty(), "no box vectors found");
    let gaps = known_gaps();

    let mut pass = 0;
    let mut expected_fail = 0;
    let mut unexpected_fail = 0;
    for (i, v) in vectors.iter().enumerate() {
        let raw = hex::decode(&v.bytes)
            .unwrap_or_else(|e| panic!("bad hex for box #{i} ({}): {e}", v.box_id));
        let tree_bytes = hex::decode(&v.ergo_tree)
            .unwrap_or_else(|e| panic!("bad ergoTree hex for box #{i} ({}): {e}", v.box_id));

        let ergo_box = match parse_ergo_box_bytes(&raw, &tree_bytes) {
            Ok(b) => b,
            Err(e) => {
                if let Some(reason) = gaps.get(v.box_id.as_str()) {
                    eprintln!("KNOWN GAP: box {} — {reason}", v.box_id);
                    expected_fail += 1;
                } else {
                    eprintln!("UNEXPECTED FAIL: box #{i} ({}) parse error: {e}", v.box_id);
                    unexpected_fail += 1;
                }
                continue;
            }
        };

        let mut w = VlqWriter::new();
        write_ergo_box(&mut w, &ergo_box).unwrap();
        let reserialized = w.result();

        if raw != reserialized {
            eprintln!(
                "UNEXPECTED FAIL: box #{i} ({}) byte mismatch ({} vs {} bytes)",
                v.box_id,
                raw.len(),
                reserialized.len()
            );
            unexpected_fail += 1;
            continue;
        }

        let computed_id = blake2b256(&raw);
        let expected_id = hex::decode(&v.box_id).unwrap();
        if computed_id.as_bytes() != expected_id.as_slice() {
            eprintln!("UNEXPECTED FAIL: box #{i} ({}) ID mismatch", v.box_id,);
            unexpected_fail += 1;
            continue;
        }

        pass += 1;
    }

    eprintln!(
        "{pass} passed, {expected_fail} known gaps, {unexpected_fail} unexpected failures \
         (out of {} total)",
        vectors.len()
    );
    assert_eq!(
        unexpected_fail, 0,
        "{unexpected_fail} boxes had UNEXPECTED failures"
    );
    assert!(
        pass >= min_pass,
        "need at least {min_pass} box vectors, got {pass}"
    );
}

/// Default-suite box oracle: roundtrips the tiny tracked
/// `boxes_recent.json` + `boxes_1759500.json`. Broader tracked corpora are
/// gated by `box_roundtrip_broad` below.
#[test]
fn box_roundtrip_default() {
    let vectors = load_box_files(&["boxes_recent.json", "boxes_1759500.json"]);
    assert_box_roundtrip(&vectors, 25);
}

#[test]
#[ignore = "broad corpus — run with --ignored"]
fn box_roundtrip_broad() {
    let vectors = load_all_box_vectors();
    assert_box_roundtrip(&vectors, 5);
}

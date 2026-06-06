use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct ErgoTreeVector {
    source: String,
    bytes: String,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/mainnet")
}

fn load_ergotree_files(filenames: &[&str]) -> Vec<ErgoTreeVector> {
    let mut all = Vec::new();
    for name in filenames {
        let path = vectors_dir().join(name);
        let data =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {name}: {e}"));
        let vectors: Vec<ErgoTreeVector> =
            serde_json::from_str(&data).unwrap_or_else(|e| panic!("failed to parse {name}: {e}"));
        all.extend(vectors);
    }
    all
}

fn load_all_ergotree_vectors() -> Vec<ErgoTreeVector> {
    let mut all = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("test-vectors/mainnet dir") {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("ergotrees_") && name.ends_with(".json") {
            let data = fs::read_to_string(entry.path()).unwrap();
            let vectors: Vec<ErgoTreeVector> = serde_json::from_str(&data)
                .unwrap_or_else(|e| panic!("failed to parse {name}: {e}"));
            all.extend(vectors);
        }
    }
    all
}

fn assert_ergotree_roundtrip(vectors: &[ErgoTreeVector], min_pass: usize) {
    assert!(!vectors.is_empty(), "no ErgoTree vectors found");

    let mut pass = 0;
    let mut fail = 0;
    for (i, v) in vectors.iter().enumerate() {
        let raw = hex::decode(&v.bytes)
            .unwrap_or_else(|e| panic!("bad hex for tree #{i} ({}): {e}", v.source));

        let mut r = VlqReader::new(&raw);
        let tree = match read_ergo_tree(&mut r) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("FAIL: tree #{i} ({}) parse error: {e}", v.source);
                fail += 1;
                continue;
            }
        };

        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &tree).unwrap();
        let reserialized = w.result();

        if raw != reserialized {
            eprintln!(
                "FAIL: tree #{i} ({}) byte mismatch ({} vs {} bytes)",
                v.source,
                raw.len(),
                reserialized.len()
            );
            fail += 1;
            continue;
        }
        pass += 1;
    }

    eprintln!(
        "{pass} ErgoTrees passed, {fail} failed out of {} total",
        vectors.len()
    );
    assert_eq!(fail, 0, "{fail} ErgoTrees failed roundtrip");
    assert!(
        pass >= min_pass,
        "need at least {min_pass} ErgoTree vectors, got {pass}"
    );
}

/// Default-suite ErgoTree oracle: roundtrips the tiny tracked
/// `ergotrees_1_10.json` + `ergotrees_1_100.json`. Broader tracked
/// corpora are gated by `ergotree_roundtrip_broad` below.
#[test]
fn ergotree_roundtrip_default() {
    let vectors = load_ergotree_files(&["ergotrees_1_10.json", "ergotrees_1_100.json"]);
    assert_ergotree_roundtrip(&vectors, 60);
}

#[test]
#[ignore = "broad corpus — run with --ignored"]
fn ergotree_roundtrip_broad() {
    let vectors = load_all_ergotree_vectors();
    assert_ergotree_roundtrip(&vectors, 10);
}

// ----- oracle parity -----

/// Testnet block h=247,361 tx[2] out[0]: 630-byte v0 const-segregated
/// tree whose body uses `XorOf(Coll[SBoolean])` (opcode 0xFF). Scala's
/// `LogicalTransformerSerializer.parse` reads exactly one child value
/// (the Coll[SBoolean] input); pinning a successful parse + canonical
/// re-serialize ensures the 0xFF dispatch arm cannot regress to a
/// two-arg shape and over-consume sibling bytes.
#[test]
fn xorof_v0_tree_h247361_roundtrips() {
    let hex_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/testnet/v3_xorof_tree_h247361.hex");
    let tree_hex = fs::read_to_string(&hex_path)
        .expect("v3_xorof_tree_h247361.hex must exist under test-vectors/testnet/");
    let raw = hex::decode(tree_hex.trim()).expect("vector must be valid hex");
    assert_eq!(raw.len(), 630, "fixture changed: expected 630-byte tree");

    let mut r = VlqReader::new(&raw);
    let tree = read_ergo_tree(&mut r).expect("XorOf v0 tree must parse");

    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, &tree).expect("re-serialize must succeed");
    assert_eq!(
        raw,
        w.result(),
        "canonical re-serialized bytes must equal the testnet wire bytes",
    );
}

/// Testnet h=210,076 contract carrying an `SUnsignedBigInt` constant
/// (the secp256k1 curve order `n`). Header byte `0x1b` encodes the v6 /
/// Sigma 6.0 wire format — `version=3`, `has_size=true`,
/// `constant_segregation=true` — so this fixture exercises the v6
/// ErgoTree codec path against real testnet bytes. Pinning a
/// byte-identical roundtrip guards against regression in the v3 header
/// layout, the size-prefixed body framing, and the v6-only constant
/// types appearing in the segregated table.
///
/// Note on scope: this closes only the v6 ErgoTree codec gap. A v6
/// transaction-level oracle (full `Transaction` + `bytes_to_sign` +
/// `tx_id`) still requires fresh post-EIP-50 capture; the testnet
/// `.gitignore` excludes `transactions_*` shards, and none are tracked.
#[test]
fn v6_unsigned_bigint_tree_h210076_roundtrips() {
    let hex_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/testnet/v6_unsigned_bigint_script_h210076.hex");
    let tree_hex = fs::read_to_string(&hex_path)
        .expect("v6_unsigned_bigint_script_h210076.hex must exist under test-vectors/testnet/");
    let raw = hex::decode(tree_hex.trim()).expect("vector must be valid hex");
    assert_eq!(raw.len(), 932, "fixture changed: expected 932-byte tree");
    assert_eq!(
        raw[0], 0x1b,
        "header byte must be 0x1b (v3, has_size, cseg) for the v6 fixture",
    );

    let mut r = VlqReader::new(&raw);
    let tree = read_ergo_tree(&mut r).expect("v6 SUnsignedBigInt tree must parse");
    assert_eq!(tree.version, 3, "v6 / Sigma 6.0 trees encode as version 3");
    assert!(tree.has_size);
    assert!(tree.constant_segregation);

    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, &tree).expect("re-serialize must succeed");
    assert_eq!(
        raw,
        w.result(),
        "canonical re-serialized bytes must equal the testnet wire bytes",
    );
}

#[derive(Deserialize)]
struct V6TypeArgVectorFile {
    vectors: Vec<V6TypeArgVector>,
}

#[derive(Deserialize)]
struct V6TypeArgVector {
    method: String,
    call: String,
    type_id: u8,
    method_id: u8,
    tree_hex: String,
}

/// Scala-extracted oracle: v6 method calls carrying explicit type-arg
/// bytes inside v0-header (`0x10`) trees. The official Scala node 6.1.2
/// compiler emits exactly this shape — the tree-header version byte is a
/// wire-format selector, so `method_explicit_type_args_count` must key
/// the trailing-type-byte read on `(type_id, method_id)` alone, never on
/// `tree_version`. Covers all six Sigma 6.0.2 `hasExplicitTypeArgs`
/// pairs plus a literal-index `getReg` control that folds to
/// `ExtractRegisterAs` (no MethodCall, no type byte). Provenance and
/// re-extraction steps:
/// `test-vectors/scala/sigma/v6_methodcall_typeargs_v0_header/README.md`.
#[test]
fn v6_methodcall_typeargs_v0_header_trees_roundtrip() {
    const METHOD_CALL: u8 = 0xdc;
    const PROPERTY_CALL: u8 = 0xdb;
    const EXTRACT_REGISTER_AS: u8 = 0xc6;

    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/scala/sigma/v6_methodcall_typeargs_v0_header/golden_vectors.json");
    let data = fs::read_to_string(&path)
        .expect("v6_methodcall_typeargs_v0_header/golden_vectors.json must exist");
    let file: V6TypeArgVectorFile = serde_json::from_str(&data).expect("vector file must parse");
    assert_eq!(file.vectors.len(), 7, "fixture changed: expected 7 vectors");

    for v in &file.vectors {
        let raw =
            hex::decode(&v.tree_hex).unwrap_or_else(|e| panic!("bad hex for {}: {e}", v.method));
        assert_eq!(
            raw[0], 0x10,
            "{}: header byte must be 0x10 (v0, cseg, no size bit)",
            v.method,
        );

        let mut r = VlqReader::new(&raw);
        let tree = read_ergo_tree(&mut r)
            .unwrap_or_else(|e| panic!("{}: Scala-compiled v0 tree must parse: {e}", v.method));
        assert_eq!(tree.version, 0, "{}: tree version", v.method);
        assert!(!tree.has_size, "{}: no size bit", v.method);
        assert!(tree.constant_segregation, "{}: cseg bit", v.method);

        // The wire bytes must really carry the claimed call shape.
        match v.call.as_str() {
            "MethodCall" | "PropertyCall" => {
                let opcode = if v.call == "MethodCall" {
                    METHOD_CALL
                } else {
                    PROPERTY_CALL
                };
                let triple = [opcode, v.type_id, v.method_id];
                assert!(
                    raw.windows(3).any(|w| w == triple),
                    "{}: bytes must contain [0x{opcode:02x}, {}, {}]",
                    v.method,
                    v.type_id,
                    v.method_id,
                );
            }
            "ExtractRegisterAs" => {
                assert!(
                    raw.contains(&EXTRACT_REGISTER_AS),
                    "{}: control vector must use the ExtractRegisterAs primitive",
                    v.method,
                );
                assert!(
                    !raw.windows(3).any(|w| w == [METHOD_CALL, 99, 19]),
                    "{}: literal-index getReg must NOT emit the (99,19) MethodCall",
                    v.method,
                );
            }
            other => panic!("{}: unknown call kind {other}", v.method),
        }

        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &tree)
            .unwrap_or_else(|e| panic!("{}: re-serialize must succeed: {e}", v.method));
        assert_eq!(
            raw,
            w.result(),
            "{}: canonical re-serialized bytes must equal the Scala node's wire bytes",
            v.method,
        );
    }
}

//! SANTA wire-tier conformance vectors, graded against both SANTA's own
//! expectation and an independent JVM verdict.
//!
//! The vectors under `test-vectors/santa/wire/` are vendored verbatim from
//! SANTA (<https://github.com/mwaddip/santa>, MIT License, Copyright (c) 2026
//! The SANTA Authors); `test-vectors/santa/README.md` records the commit.
//! Each `<op>.json` is paired with an `<op>.jvm.tsv` written by
//! `scripts/santa_wire_oracle/SantaWireOracle.scala`, which re-parses every
//! entry on sigma-state / ergo-core 6.0.6 under the entry's own
//! `VersionContext`. SANTA and JVM must always agree; node differences are
//! permitted only by the explicit list below. The three verdicts are:
//!
//! - SANTA's expectation: `error == "errored"` means the JVM rejects the bytes;
//!   otherwise they must round-trip to `expected_bytes_hex`, or to themselves
//!   when that field is absent;
//! - the JVM line: `REJECT <exception>` or `ACCEPT <re-serialized hex>`;
//! - the node: the entry's `kind` parsed at the entry's activated script
//!   version, then written back.
//!
//! Every vector file in the directory is graded, so a new family is covered by
//! adding its two files. Known differences must still diverge; all other
//! entries must agree. The three unparsed-soft-fork entries agree through
//! production codecs: vixen's size-flag stripping caused their reported coal.

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{read_ergo_box, write_ergo_box};
use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::sigma_value::{read_constant, read_value, write_constant, write_sigma_boolean};
use ergo_ser::transaction::{read_transaction, write_transaction};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// Independently confirmed JVM/node differences. A fix must remove its entry.
const KNOWN_DIVERGENCES: &[(&str, &str)] = &[
    (
        "v6/authored/Box.tree_parse_acceptance.json",
        "box-v0-methodcall-no-args-propertycall-accept#44",
    ),
    (
        "v6/authored/Box.tree_parse_acceptance.json",
        "box-v3-coll-long-plus-int-long-reject#32",
    ),
    (
        "v6/authored/Transaction.tree_parse_acceptance.json",
        "transaction-v0-methodcall-no-args-propertycall-accept#44",
    ),
    (
        "v6/authored/Transaction.tree_parse_acceptance.json",
        "transaction-v3-coll-long-plus-int-long-reject#32",
    ),
];

// ----- helpers -----

#[derive(Deserialize)]
struct VectorFile {
    op: String,
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    name: String,
    kind: String,
    bytes_hex: String,
    #[serde(default)]
    expected_bytes_hex: Option<String>,
    #[serde(default)]
    error: Option<String>,
    version: Version,
}

#[derive(Deserialize)]
struct Version {
    activated: u8,
}

/// What the bytes must do: be refused, or round-trip to these bytes.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Reject,
    Accept(String),
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-vectors/santa/wire")
}

fn vector_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            vector_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

/// `<name> TAB ACCEPT <hex>` / `<name> TAB REJECT <exception>` lines.
fn jvm_verdicts(path: &Path) -> BTreeMap<String, Verdict> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: missing JVM verdicts: {e}", path.display()));
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let (name, verdict) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("{}: malformed line {line:?}", path.display()));
            let verdict = match verdict.split_once(' ') {
                Some(("ACCEPT", hex)) => Verdict::Accept(hex.to_ascii_lowercase()),
                Some(("REJECT", _)) => Verdict::Reject,
                _ => panic!("{}: malformed verdict {verdict:?}", path.display()),
            };
            (name.to_string(), verdict)
        })
        .collect()
}

/// Parse `bytes` as `kind` at `activated`, then write it back.
fn node_round_trip(kind: &str, bytes: &[u8], activated: u8) -> Result<Vec<u8>, String> {
    let mut r = VlqReader::new(bytes).with_activated_script_version(activated);
    let mut w = VlqWriter::new();
    let err = |e: &dyn std::fmt::Debug| format!("{e:?}");
    match kind {
        "Transaction" => {
            let tx = read_transaction(&mut r).map_err(|e| err(&e))?;
            write_transaction(&mut w, &tx).map_err(|e| err(&e))?;
        }
        "Box" => {
            let b = read_ergo_box(&mut r).map_err(|e| err(&e))?;
            write_ergo_box(&mut w, &b).map_err(|e| err(&e))?;
        }
        "Constant" => {
            let (tpe, val) = read_constant(&mut r).map_err(|e| err(&e))?;
            write_constant(&mut w, &tpe, &val).map_err(|e| err(&e))?;
        }
        "SigmaBoolean" => match read_value(&mut r, &SigmaType::SSigmaProp) {
            Ok(SigmaValue::SigmaProp(sb)) => {
                write_sigma_boolean(&mut w, &sb).map_err(|e| err(&e))?
            }
            other => return Err(format!("{other:?}")),
        },
        "ErgoTree" => {
            let tree = read_ergo_tree(&mut r).map_err(|e| err(&e))?;
            write_ergo_tree(&mut w, &tree).map_err(|e| err(&e))?;
        }
        other => panic!("unsupported SANTA wire kind {other:?}"),
    }
    if !r.is_empty() {
        return Err(format!("{} trailing bytes", r.remaining()));
    }
    Ok(w.result())
}

// ----- oracle parity -----

#[test]
fn santa_wire_vectors_match_santa_the_jvm_and_the_node() {
    let mut files = Vec::new();
    vector_files(&vectors_dir(), &mut files);
    files.sort();
    assert!(!files.is_empty(), "no SANTA wire vectors vendored");

    let mut failures = Vec::new();
    let mut graded = 0;
    let mut seen = BTreeSet::new();
    assert_eq!(
        KNOWN_DIVERGENCES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        KNOWN_DIVERGENCES.len(),
        "duplicate known divergence"
    );
    for path in &files {
        let file: VectorFile = serde_json::from_str(&std::fs::read_to_string(path).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let jvm = jvm_verdicts(&path.with_extension("jvm.tsv"));
        assert_eq!(
            jvm.len(),
            file.entries.len(),
            "{}: JVM entry count",
            path.display()
        );
        let relative = path
            .strip_prefix(vectors_dir())
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        for entry in &file.entries {
            let id = format!("{relative}/{} ({})", entry.name, file.op);
            let santa = if entry.error.as_deref() == Some("errored") {
                Verdict::Reject
            } else {
                Verdict::Accept(
                    entry
                        .expected_bytes_hex
                        .as_deref()
                        .unwrap_or(&entry.bytes_hex)
                        .to_ascii_lowercase(),
                )
            };
            match jvm.get(&entry.name) {
                Some(v) if *v == santa => {}
                Some(v) => failures.push(format!("{id}: SANTA expects {santa:?}, JVM says {v:?}")),
                None => failures.push(format!("{id}: no JVM verdict")),
            }
            let bytes = hex::decode(&entry.bytes_hex).unwrap();
            let node = match node_round_trip(&entry.kind, &bytes, entry.version.activated) {
                Ok(out) => Verdict::Accept(hex::encode(out)),
                Err(_) => Verdict::Reject,
            };
            println!("WIRE\t{relative}\t{}\t{santa:?}\t{node:?}", entry.name);
            let key = (relative.as_str(), entry.name.as_str());
            if KNOWN_DIVERGENCES.contains(&key) {
                seen.insert((relative.clone(), entry.name.clone()));
                if jvm.get(&entry.name) == Some(&node) {
                    failures.push(format!(
                        "{id}: known divergence now agrees; remove it from KNOWN_DIVERGENCES"
                    ));
                }
            } else if node != santa {
                failures.push(format!("{id}: expected {santa:?}, node gives {node:?}"));
            }
            graded += 1;
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {graded} SANTA wire entries disagree:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(
        seen.len(),
        KNOWN_DIVERGENCES.len(),
        "stale known divergence: missing file/entry"
    );
}

// Fresh JVM 6.0.7 check: parse ErgoTransaction in VersionContext(3,3),
// then force outputs(0).bytes and outputs(0).id in the ambient (1,1).
// This pins UTXO persistence independently of the transaction wire cache.
#[test]
fn evaluated_output_box_bytes_and_ids_match_jvm_607() {
    let path = vectors_dir()
        .parent()
        .unwrap()
        .join("transaction/v6/authored/evaluated-values-spend.json");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for (name, expected_bytes, expected_id) in [
        ("bwr-v0-reader-17-accept#51", "8094ebdc030008d30100018602040204020c010fefd92e5160fa3744d9d593ced322a23a92c03321fa4635da5e479db21600", "6bcac94dd4288ab820574617f2ba19a3e743e607c5bc20fca724773c2d95b57d"),
        ("bytes-v3-reader-50-accept#60", "8094ebdc030008d301000186020402040250d469d61784a71ef1102a56f25674663b684c68483fb0dcc69e619aa7a0887300", "aa5323e9230b4dbd82110348e782fa1a9bf04405c31ee0affba27e2b37a45570"),
    ] {
        let entry = fixture["entries"].as_array().unwrap().iter().find(|e| e["name"] == name).unwrap();
        let bytes = hex::decode(entry["tx_bytes_hex"].as_str().unwrap()).unwrap();
        let tx = read_transaction(&mut VlqReader::new(&bytes).with_activated_script_version(3)).unwrap();
        let tx_id = ergo_ser::transaction::transaction_id(&tx).unwrap();
        // State/mempool callers construct outputs directly from the parsed candidate.
        let output = ergo_ser::ergo_box::ErgoBox { candidate: tx.output_candidates[0].clone(), transaction_id: tx_id, index: 0 };
        let sealed = ergo_ser::ergo_box::ErgoBox::new(tx.output_candidates[0].clone(), tx_id, 0);
        for output in [&output, &sealed] {
            assert_eq!(hex::encode(ergo_ser::ergo_box::serialize_ergo_box(output).unwrap()), expected_bytes, "{name}");
            assert_eq!(hex::encode(output.box_id().unwrap().as_bytes()), expected_id, "{name}");
        }
        let mut wire = VlqWriter::new();
        write_transaction(&mut wire, &tx).unwrap();
        assert_eq!(wire.result(), bytes, "{name}: indexed wire encoding retains Upcast");
        // The same box received in its v3 form parses under the default
        // context and serializes there like the forced (1,1) bytes above.
        let candidate = &tx.output_candidates[0];
        let mut received = VlqWriter::new();
        ergo_ser::ergo_box::write_ergo_box_candidate_versioned(&mut received, candidate, 3)
            .unwrap();
        received.put_bytes(tx_id.as_bytes());
        received.put_u16(0);
        let received = received.result();
        assert_ne!(hex::encode(&received), expected_bytes, "{name}: v3 form keeps Upcast");
        let parsed =
            ergo_ser::ergo_box::parse_ergo_box_bytes(&received, candidate.ergo_tree_bytes())
                .unwrap();
        assert_eq!(
            hex::encode(ergo_ser::ergo_box::serialize_ergo_box(&parsed).unwrap()),
            expected_bytes,
            "{name}: default-context parse"
        );
    }
    let entry = fixture["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "c2-twin-output-register-reject#46")
        .unwrap();
    let bytes = hex::decode(entry["tx_bytes_hex"].as_str().unwrap()).unwrap();
    let tx =
        read_transaction(&mut VlqReader::new(&bytes).with_activated_script_version(3)).unwrap();
    let output = ergo_ser::ergo_box::ErgoBox::new(
        tx.output_candidates[0].clone(),
        ergo_ser::transaction::transaction_id(&tx).unwrap(),
        0,
    );
    assert!(
        ergo_ser::ergo_box::serialize_ergo_box(&output).is_err(),
        "JVM MatchError: function type cannot serialize in (1,1)"
    );
}

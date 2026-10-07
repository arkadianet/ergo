//! SANTA wire-tier conformance vectors, graded against both SANTA's own
//! expectation and an independent JVM verdict.
//!
//! The vectors under `test-vectors/santa/wire/` are vendored verbatim from
//! SANTA (<https://github.com/mwaddip/santa>, MIT License, Copyright (c) 2026
//! The SANTA Authors); `test-vectors/santa/README.md` records the commit.
//! Each `<op>.json` is paired with an `<op>.jvm.tsv` written by
//! `scripts/santa_wire_oracle/SantaWireOracle.scala`, which re-parses every
//! entry on sigma-state / ergo-core 6.0.6 under the entry's own
//! `VersionContext`. An entry passes only when all three agree:
//!
//! - SANTA's expectation: `error == "errored"` means the JVM rejects the bytes;
//!   otherwise they must round-trip to `expected_bytes_hex`, or to themselves
//!   when that field is absent;
//! - the JVM line: `REJECT <exception>` or `ACCEPT <re-serialized hex>`;
//! - the node: the entry's `kind` parsed at the entry's activated script
//!   version, then written back.
//!
//! Every vector file in the directory is graded, so a new family is covered by
//! adding its two files.

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_box::{read_ergo_box, write_ergo_box};
use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::SigmaValue;
use ergo_ser::sigma_value::{read_constant, read_value, write_constant, write_sigma_boolean};
use ergo_ser::transaction::{read_transaction, write_transaction};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    for path in &files {
        let file: VectorFile = serde_json::from_str(&std::fs::read_to_string(path).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let jvm = jvm_verdicts(&path.with_extension("jvm.tsv"));
        for entry in &file.entries {
            let id = format!("{}/{}", file.op, entry.name);
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
            if node != santa {
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
}

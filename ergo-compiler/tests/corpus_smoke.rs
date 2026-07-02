//! Real-contract corpus parity — the M1 parser's long-tail acceptance gate.
//!
//! `test-vectors/ergoscript/corpus/` vendors ~79 real deployed ErgoScript
//! sources (Dexy, HodlCoin/Phoenix, ChainCash/Basis, Rosen Bridge, CrystalPool,
//! CurveTreeVerifier-v6, LSP examples — see `corpus/MANIFEST.md`). The committed
//! `corpus/verdicts.json` is the accept/reject verdict of the REAL Scala
//! reference parser (`sigmastate.lang.SigmaParser`, sigma-state 6.0.2) for each
//! file, produced by `scripts/jvm_parser_oracle/ParserOracle.scala`. It is an
//! external ORACLE, never a self-oracle: the Rust parser is graded against it,
//! it is never adjusted to make the Rust parser pass.
//!
//! - `corpus_verdict_parity` (always-on): `ergo_compiler::parse(src, 3)` must
//!   agree with the committed verdict — accept/reject, and on reject the exact
//!   1-based `line:col`.
//! - `corpus_live_oracle_parity` (`#[ignore]`): re-derives every verdict live
//!   from the JVM oracle and asserts it equals the committed file. Run it after
//!   editing the corpus or the oracle to refresh/verify `verdicts.json`:
//!
//!   ```text
//!   cargo test -p ergo-compiler --test corpus_smoke -- --ignored --nocapture
//!   ```
//!
//!   It needs `scala-cli` on PATH and (first run) network to resolve
//!   `sigma-state:6.0.2` from Maven Central; the first query blocks through the
//!   oracle's compile/dependency resolution.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `<crate>/../test-vectors/ergoscript/corpus`.
fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors/ergoscript/corpus")
}

/// The vendored `.es` files, keyed by their forward-slash corpus-relative path
/// (matching the keys in `verdicts.json`), each paired with its UTF-8 source.
/// Sorted, so the ordering is stable for the batched live-oracle run.
fn corpus_files() -> BTreeMap<String, String> {
    let root = corpus_dir();
    let mut out = BTreeMap::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read corpus dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("es") {
                let rel = path
                    .strip_prefix(&root)
                    .expect("under corpus root")
                    .to_str()
                    .expect("utf-8 path")
                    .replace('\\', "/");
                let src =
                    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
                out.insert(rel, src);
            }
        }
    }
    out
}

/// One expected verdict from `verdicts.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject { line: u32, col: u32 },
}

/// Parse the committed `verdicts.json` into `path -> Verdict`.
fn load_verdicts() -> BTreeMap<String, Verdict> {
    let raw =
        std::fs::read_to_string(corpus_dir().join("verdicts.json")).expect("read verdicts.json");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("verdicts.json is valid JSON");
    let obj = json.as_object().expect("verdicts.json is an object");
    obj.iter()
        .map(|(k, v)| {
            let verdict = match v["verdict"].as_str().expect("verdict field is a string") {
                "accept" => Verdict::Accept,
                "reject" => Verdict::Reject {
                    line: v["line"].as_u64().expect("reject has line") as u32,
                    col: v["col"].as_u64().expect("reject has col") as u32,
                },
                other => panic!("unknown verdict {other:?} for {k}"),
            };
            (k.clone(), verdict)
        })
        .collect()
}

/// The Rust parser's verdict for one source (tree_version = 3, as the oracle).
fn rust_verdict(src: &str) -> Verdict {
    match ergo_compiler::parse(src, 3) {
        Ok(_) => Verdict::Accept,
        Err(e) => {
            let (line, col) = e.line_col(src);
            Verdict::Reject { line, col }
        }
    }
}

// ----- happy path / parity -----

/// Every vendored source: the Rust parser's accept/reject (and reject position)
/// must equal the committed JVM-oracle verdict. A mismatch is a parser bug.
#[test]
fn corpus_verdict_parity() {
    let files = corpus_files();
    let verdicts = load_verdicts();

    // The corpus and the verdict file must describe exactly the same set — a
    // vendored file with no verdict (or a verdict with no file) is a corpus bug.
    let file_keys: Vec<&String> = files.keys().collect();
    let verdict_keys: Vec<&String> = verdicts.keys().collect();
    assert_eq!(
        file_keys, verdict_keys,
        "corpus files and verdicts.json keys must match 1:1"
    );
    assert!(!files.is_empty(), "corpus is empty");

    let mut divergences = Vec::new();
    for (rel, src) in &files {
        let expected = &verdicts[rel];
        let actual = rust_verdict(src);
        if &actual != expected {
            divergences.push(format!("{rel}: expected {expected:?}, got {actual:?}"));
        }
    }
    assert!(
        divergences.is_empty(),
        "{} corpus verdict divergence(s) vs the JVM oracle:\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}

// ----- oracle parity (live) -----

/// Re-derive every verdict from the live JVM oracle and assert it equals the
/// committed `verdicts.json`. Spawns the scala-cli oracle once (batch mode:
/// feed all sources, close stdin, read all replies), then diffs. `#[ignore]` —
/// needs scala-cli + (first run) network. See the module doc for how to run.
#[test]
#[ignore]
fn corpus_live_oracle_parity() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let files = corpus_files();
    let committed = load_verdicts();
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("scripts/jvm_parser_oracle/ParserOracle.scala");

    // Same spawn shape as ergo-difftest/src/oracle.rs:65-70; batch mode so a
    // scala-cli startup banner on stdout can't desync a per-line handshake.
    let mut child = Command::new("scala-cli")
        .arg("run")
        .arg(&script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn scala-cli (is it on PATH?)");

    // Preserve order: the oracle echoes verdicts in the order sources arrive.
    let ordered: Vec<(&String, &String)> = files.iter().collect();
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        for (_rel, src) in &ordered {
            writeln!(stdin, "parse {}", hex(src.as_bytes())).expect("write to oracle");
        }
        // Drop stdin -> EOF -> the oracle's read loop terminates and it exits.
    }

    // Keep only verdict-grammar lines (drops any scala-cli banner/hint noise).
    let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let live: Vec<Verdict> = stdout
        .lines()
        .map(|l| l.expect("read oracle line"))
        .filter_map(|l| parse_oracle_line(&l))
        .collect();
    child.wait().expect("oracle exit");

    assert_eq!(
        live.len(),
        ordered.len(),
        "oracle returned {} verdicts for {} inputs",
        live.len(),
        ordered.len()
    );

    let mut divergences = Vec::new();
    for ((rel, _src), got) in ordered.iter().zip(&live) {
        let want = &committed[*rel];
        if got != want {
            divergences.push(format!("{rel}: committed {want:?}, live oracle {got:?}"));
        }
    }
    assert!(
        divergences.is_empty(),
        "{} live-oracle divergence(s) — verdicts.json is stale, regenerate it:\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}

// ----- helpers -----

/// Lowercase hex of `bytes` — the wire form the oracle decodes back to UTF-8.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse one oracle reply line into a `Verdict`, or `None` for non-verdict
/// lines (banner/hint noise). Panics on a malformed `REJECT` / an `ERR`.
fn parse_oracle_line(line: &str) -> Option<Verdict> {
    let line = line.trim();
    if line == "ACCEPT" {
        Some(Verdict::Accept)
    } else if let Some(pos) = line.strip_prefix("REJECT ") {
        let (l, c) = pos
            .split_once(':')
            .unwrap_or_else(|| panic!("bad REJECT: {line:?}"));
        Some(Verdict::Reject {
            line: l.parse().expect("REJECT line"),
            col: c.parse().expect("REJECT col"),
        })
    } else if line.starts_with("ERR ") {
        panic!("oracle ERR: {line:?}");
    } else {
        None
    }
}

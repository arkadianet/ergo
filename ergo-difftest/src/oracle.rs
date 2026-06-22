//! Phase 2: differential testing against the Scala reference node.
//!
//! Spawns the JVM serde oracle (`scripts/jvm_serde_oracle/ErgoSerdeOracle.scala`,
//! the real `sigma-state` the consensus node runs) once and streams inputs to
//! it over a pipe. For each input we compute the node's verdict and the JVM's
//! verdict and diff them:
//!
//! * **accept/reject mismatch** — one side parses, the other refuses. This is
//!   the reject-valid (stall) / accept-invalid (fork) class — e.g. the UTF-8
//!   STypeVar bug. The highest-severity signal.
//! * **canonical mismatch** — both accept but re-serialize to different bytes.
//!   Reported separately because the soft-fork "unparsed" path can re-encode
//!   legitimately differently; these need triage, not an automatic verdict.
//!
//! This module is NOT exercised by `cargo test` (it needs `scala-cli` and, on
//! first run, network). It is driven by `difftest --oracle`.

use std::io::{self, BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;

use crate::to_hex;

/// A parse verdict from either implementation.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Parsed; carries the canonical re-serialization (hex).
    Accept(String),
    /// Refused (carries the reason / error class).
    Reject(String),
    /// The oracle could not handle the line (harness/oracle problem, not a node finding).
    Err(String),
}

/// A divergence between the node and the JVM reference for one input.
#[derive(Debug, Clone)]
pub struct Divergence {
    pub surface: &'static str,
    pub kind: DivergenceKind,
    pub input_hex: String,
    pub rust: Verdict,
    pub jvm: Verdict,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DivergenceKind {
    /// One side accepted, the other rejected — stall/fork class.
    AcceptReject,
    /// Both accepted but canonical bytes differ — triage (may be soft-fork).
    Canonical,
}

/// Handle to the long-lived JVM oracle process.
pub struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Oracle {
    /// Spawn `scala-cli run <script>`. The first query blocks through the
    /// oracle's compile/dependency-resolution; subsequent queries are fast.
    pub fn spawn(script: &str) -> io::Result<Oracle> {
        let mut child = Command::new("scala-cli")
            .arg("run")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null()) // compile/resolve noise goes to stderr
            .spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        Ok(Oracle {
            child,
            stdin,
            stdout,
        })
    }

    /// Ask the JVM reference for its verdict on `bytes` at `surface`.
    pub fn query(&mut self, surface: &str, bytes: &[u8]) -> io::Result<Verdict> {
        writeln!(self.stdin, "{surface} {}", to_hex(bytes))?;
        self.stdin.flush()?;
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "oracle closed its output",
            ));
        }
        Ok(parse_verdict(line.trim()))
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        // Kill the JVM oracle and reap it so it never lingers as a zombie.
        // (SIGKILL rather than closing stdin for EOF: scala-cli/JVM does not
        // reliably exit on stdin EOF, and a stuck oracle would hang Drop.)
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn parse_verdict(line: &str) -> Verdict {
    match line.split_once(' ') {
        Some(("ACCEPT", rest)) => Verdict::Accept(rest.to_string()),
        Some(("REJECT", rest)) => Verdict::Reject(rest.to_string()),
        Some(("ERR", rest)) => Verdict::Err(rest.to_string()),
        _ if line == "ACCEPT" => Verdict::Accept(String::new()),
        _ => Verdict::Err(format!("unparseable oracle line: {line:?}")),
    }
}

/// A surface the oracle can diff: how the node parses+canonicalizes it, and how
/// to compare against the JVM.
pub struct SurfaceSpec {
    /// Name sent to the JVM oracle (must match a `handle` case in the .scala).
    pub name: &'static str,
    /// Node verdict + bytes consumed (so the JVM gets the exact same range).
    pub rust_verdict: fn(&[u8]) -> (Verdict, usize),
    /// Compare canonical bytes when both accept. Off for surfaces where the node
    /// re-serializes from retained original bytes (e.g. a box reuses the
    /// original ergoTree slice, so its canonical won't match the JVM's
    /// re-encoded tree even when both are correct).
    pub compare_canonical: bool,
    /// Skip canonical comparison for soft-fork "unparsed" trees (header version
    /// above MAX_SUPPORTED_TREE_VERSION = 3): the node emits a placeholder while
    /// the JVM preserves original bytes — an expected, non-bug difference.
    pub soft_fork_header: bool,
}

/// All surfaces the JVM oracle currently supports.
pub fn oracle_surfaces() -> Vec<SurfaceSpec> {
    vec![
        SurfaceSpec {
            name: "ergo_tree",
            rust_verdict: ergo_tree_verdict,
            compare_canonical: true,
            soft_fork_header: true,
        },
        SurfaceSpec {
            // node retains the original ergoTree slice for box re-serialization,
            // so only accept/reject is comparable, not canonical bytes.
            name: "ergo_box_candidate",
            rust_verdict: ergo_box_candidate_verdict,
            compare_canonical: false,
            soft_fork_header: false,
        },
        SurfaceSpec {
            // tx output boxes retain original ergoTree slices → canonical not comparable.
            name: "transaction",
            rust_verdict: transaction_verdict,
            compare_canonical: false,
            soft_fork_header: false,
        },
        SurfaceSpec {
            // headers are a pure codec (no retained-bytes substructure).
            name: "header",
            rust_verdict: header_verdict,
            compare_canonical: true,
            soft_fork_header: false,
        },
    ]
}

/// `ergo_tree`: the CONSENSUS surface = `read_ergo_tree` + the three gates the
/// box-script readers enforce after parsing: `check_header_size_bit` (rule 1012),
/// `check_tree_version_supported` (tree version > activated, #120), and
/// `check_resolvable_methods` (a method the tree's registry can't resolve, #125).
/// Bare `read_ergo_tree` is lenient (it wraps a future-version tree), so without
/// these gates this surface reports false divergences against the JVM oracle —
/// which now runs at activatedVersion = 3 and rejects exactly these.
fn ergo_tree_verdict(bytes: &[u8]) -> (Verdict, usize) {
    let mut r = VlqReader::new(bytes);
    match ergo_ser::ergo_tree::read_ergo_tree(&mut r) {
        Err(e) => (Verdict::Reject(format!("{e:?}")), r.position()),
        Ok(tree) => {
            let consumed = r.position();
            if let Err(e) = ergo_ser::ergo_tree::check_header_size_bit(&tree) {
                return (Verdict::Reject(format!("{e:?}")), consumed);
            }
            if let Err(e) = ergo_ser::ergo_tree::check_tree_version_supported(&tree) {
                return (Verdict::Reject(format!("{e:?}")), consumed);
            }
            if let Err(e) = ergo_ser::ergo_tree::check_resolvable_methods(&tree) {
                return (Verdict::Reject(format!("{e:?}")), consumed);
            }
            let mut w = VlqWriter::new();
            let v = match ergo_ser::ergo_tree::write_ergo_tree(&mut w, &tree) {
                Ok(()) => Verdict::Accept(to_hex(&w.result())),
                Err(_) => Verdict::Accept(String::new()),
            };
            (v, consumed)
        }
    }
}

fn ergo_box_candidate_verdict(bytes: &[u8]) -> (Verdict, usize) {
    let mut r = VlqReader::new(bytes);
    match ergo_ser::ergo_box::read_ergo_box_candidate(&mut r) {
        Err(e) => (Verdict::Reject(format!("{e:?}")), r.position()),
        Ok(candidate) => {
            let consumed = r.position();
            let mut w = VlqWriter::new();
            let v = match ergo_ser::ergo_box::write_ergo_box_candidate(&mut w, &candidate) {
                Ok(()) => Verdict::Accept(to_hex(&w.result())),
                Err(_) => Verdict::Accept(String::new()),
            };
            (v, consumed)
        }
    }
}

fn transaction_verdict(bytes: &[u8]) -> (Verdict, usize) {
    let mut r = VlqReader::new(bytes);
    match ergo_ser::transaction::read_transaction(&mut r) {
        Err(e) => (Verdict::Reject(format!("{e:?}")), r.position()),
        Ok(tx) => {
            let consumed = r.position();
            let mut w = VlqWriter::new();
            let v = match ergo_ser::transaction::write_transaction(&mut w, &tx) {
                Ok(()) => Verdict::Accept(to_hex(&w.result())),
                Err(_) => Verdict::Accept(String::new()),
            };
            (v, consumed)
        }
    }
}

fn header_verdict(bytes: &[u8]) -> (Verdict, usize) {
    let mut r = VlqReader::new(bytes);
    match ergo_ser::header::read_header(&mut r) {
        Err(e) => (Verdict::Reject(format!("{e:?}")), r.position()),
        Ok(h) => {
            let consumed = r.position();
            let mut w = VlqWriter::new();
            let v = match ergo_ser::header::write_header(&mut w, &h) {
                Ok(()) => Verdict::Accept(to_hex(&w.result())),
                Err(_) => Verdict::Accept(String::new()),
            };
            (v, consumed)
        }
    }
}

/// Compare the node and the JVM on one input for `spec`. `None` when they agree
/// (or the oracle erred), `Some(Divergence)` otherwise.
pub fn diff(
    spec: &SurfaceSpec,
    bytes: &[u8],
    oracle: &mut Oracle,
) -> io::Result<Option<Divergence>> {
    let (rust, consumed) = (spec.rust_verdict)(bytes);
    // Feed the JVM exactly the bytes the node treated as this object — trailing
    // bytes a sizeless parse ignores would be an unfair diff.
    let jvm_input: &[u8] = match &rust {
        Verdict::Accept(_) => &bytes[..consumed],
        _ => bytes,
    };
    let jvm = oracle.query(spec.name, jvm_input)?;

    let kind = match (&rust, &jvm) {
        (_, Verdict::Err(_)) | (Verdict::Err(_), _) => return Ok(None),
        (Verdict::Accept(_), Verdict::Reject(_)) | (Verdict::Reject(_), Verdict::Accept(_)) => {
            DivergenceKind::AcceptReject
        }
        (Verdict::Accept(a), Verdict::Accept(b)) => {
            if !spec.compare_canonical || a.is_empty() || b.is_empty() || a == b {
                return Ok(None);
            }
            if spec.soft_fork_header && jvm_input.first().map(|h| h & 0x07).unwrap_or(0) > 3 {
                return Ok(None);
            }
            DivergenceKind::Canonical
        }
        (Verdict::Reject(_), Verdict::Reject(_)) => return Ok(None),
    };

    Ok(Some(Divergence {
        surface: spec.name,
        kind,
        input_hex: to_hex(jvm_input),
        rust,
        jvm,
    }))
}

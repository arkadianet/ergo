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
        Ok(parse_verdict(&self.query_raw(surface, bytes)?))
    }

    /// Ask the JVM reference and return its RAW response line (trimmed). Used by
    /// surfaces whose reply is not an ACCEPT/REJECT verdict — e.g. `mc_root`, which
    /// answers `SIGMA` / `WRAP` / `THROW <exc>` for the MethodCall typechecker-
    /// registry harness.
    pub fn query_raw(&mut self, surface: &str, bytes: &[u8]) -> io::Result<String> {
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
        Ok(line.trim().to_string())
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
        SurfaceSpec {
            // eval/cost differential: the canonical comparison IS the reduced
            // `P:<prop>|<cost>` string (both sides reduce to it).
            name: "reduce",
            rust_verdict: reduce_verdict,
            compare_canonical: true,
            soft_fork_header: false,
        },
        SurfaceSpec {
            // stateless structural validity (Scala `ErgoTransaction.statelessValidity`).
            // Accept/reject only — no canonical form to compare.
            name: "validate",
            rust_verdict: validate_verdict,
            compare_canonical: false,
            soft_fork_header: false,
        },
        SurfaceSpec {
            // AVL+ batch-proof verification twin.
            // `compare_canonical = true`: when both sides accept, compare the
            // final digest hex — a mismatch is an accept-wrong-digest divergence.
            name: "verify_avl",
            rust_verdict: verify_avl_verdict,
            compare_canonical: true,
            soft_fork_header: false,
        },
    ]
}

/// `ergo_tree`: the CONSENSUS surface = `read_ergo_tree` + the four gates the
/// box-script readers enforce after parsing: `check_header_size_bit` (rule 1012),
/// `check_tree_version_supported` (tree version > activated, #120),
/// `check_resolvable_methods` (a method the tree's registry can't resolve, #125),
/// and `check_sigma_prop_root` (a non-SigmaProp root, rule 1001). Bare
/// `read_ergo_tree` is lenient (it wraps a future-version tree), so without these
/// gates this surface reports false divergences against the JVM oracle — which
/// now runs at activatedVersion = 3 and rejects exactly these.
fn ergo_tree_verdict(bytes: &[u8]) -> (Verdict, usize) {
    // Bare codec surface: no GroupElement curve-check (deferred by the node's
    // lenient `read_ergo_tree`; see `deserialize_box_script`).
    let (res, consumed) = deserialize_box_script(bytes, false);
    match res {
        Err(e) => (Verdict::Reject(e), consumed),
        Ok(tree) => {
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

/// Drain the group elements the parse recorded on the reader's sideband and
/// curve-check each the way Scala's `GroupElementSerializer.parse` does at
/// deserialize time (`0x00`-lead identity accepted; any other lead must be an
/// on-curve SecP256K1 point). This is the exact production consensus check
/// (`ergo-validation` `tx::ge::validate_group_elements`); the box-script surfaces
/// run it so an off-curve point is a reject, matching the node and the JVM oracle
/// instead of a false accept-invalid divergence.
fn drain_and_check_group_elements(r: &mut VlqReader) -> Result<(), String> {
    for ge in r.take_group_elements() {
        ergo_sigma::evaluator::validate_group_element(ge)
            .map_err(|e| format!("invalid group element: {e:?}"))?;
    }
    Ok(())
}

/// Deserialize a box script the way the consensus box-script readers do, so the
/// `ergo_tree` and `reduce` surfaces share a deserialize path: `read_ergo_tree` +
/// the four post-parse gates the JVM `deserializeErgoTree` enforces (size bit,
/// tree version, resolvable method, non-SigmaProp root). The GroupElement
/// curve-check is OPTIONAL (`check_group_elements`) because it is a full-consensus
/// gate the node defers to tx-validation — see the inline note. Returns the parsed
/// tree or a reject reason, plus the bytes consumed (`take_group_elements` does
/// not advance position).
fn deserialize_box_script(
    bytes: &[u8],
    check_group_elements: bool,
) -> (Result<ergo_ser::ergo_tree::ErgoTree, String>, usize) {
    let mut r = VlqReader::new(bytes);
    let tree = match ergo_ser::ergo_tree::read_ergo_tree(&mut r) {
        Ok(t) => t,
        Err(e) => return (Err(format!("{e:?}")), r.position()),
    };
    let consumed = r.position();
    // The GroupElement curve-check is a FULL-CONSENSUS (tx-validation) gate, not a
    // bare-codec one: the node's `read_ergo_tree` is deliberately lenient and
    // defers it to `ergo-validation`, while Scala's `deserializeErgoTree`
    // curve-checks GE *constants* inline but WRAPS a body whose parse fails (an
    // off-curve point reached only by over-reading past a failed/wrapped body is
    // never seen). So this runs ONLY on the `reduce` surface (where the JVM also
    // reduces, rejecting a wrapped/unparsed tree) — applying it to the bare
    // `ergo_tree` codec surface would reject-valid a tree the JVM wraps-and-accepts.
    if check_group_elements {
        if let Err(e) = drain_and_check_group_elements(&mut r) {
            return (Err(e), consumed);
        }
    }
    if let Err(e) = ergo_ser::ergo_tree::check_header_size_bit(&tree) {
        return (Err(format!("{e:?}")), consumed);
    }
    if let Err(e) = ergo_ser::ergo_tree::check_tree_version_supported(&tree) {
        return (Err(format!("{e:?}")), consumed);
    }
    if let Err(e) = ergo_ser::ergo_tree::check_resolvable_methods(&tree) {
        return (Err(format!("{e:?}")), consumed);
    }
    if let Err(e) = ergo_ser::ergo_tree::check_sigma_prop_root(&tree) {
        return (Err(format!("{e:?}")), consumed);
    }
    (Ok(tree), consumed)
}

/// `reduce`: the EVAL/COST differential. Deserialize the tree (full box-script
/// gates, via [`deserialize_box_script`]) and reduce its root to the on-chain
/// sigma proposition + raw JIT cost, against the same minimal "dummy" context the
/// JVM oracle uses (`EvalCore.dummyContext`): SELF = the tree at 1M nanoErg, the
/// sole input; no data/outputs; empty extension; activated v6; the cost limit =
/// `scriptCostLimitInEvaluator` (1,000,000 block cost). Emits
/// `P:<sigmaboolean-hex>|<cost>` so a `(prop, cost)` divergence — a
/// cost-accounting bug invisible to the deserialize-only surfaces — shows as a canonical
/// mismatch. A soft-fork-wrapped body can't reduce to a prop (the JVM eval also
/// fails), so it rejects.
/// Construct the `reduce` surface's SELF box to match `EvalCore.dummyContext`'s
/// `new ErgoBox(value = 1M, ergoTree = tree, transactionId = 32 zeros, index = 0,
/// creationHeight = 0)`, with the box's full serialized bytes + `Blake2b256` id
/// populated (via the node's own `serialize_ergo_box` / `box_id`) so `SELF.bytes`
/// (ExtractBytes) and `SELF.id` (ExtractId) read identically to the JVM box.
/// `script_bytes` is the ORIGINAL wire tree, matching Scala's preserved
/// `propositionBytes`.
fn build_dummy_self_box(
    tree: &ergo_ser::ergo_tree::ErgoTree,
    script_bytes: Vec<u8>,
) -> Result<ergo_sigma::evaluator::EvalBox, String> {
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
    use ergo_ser::register::AdditionalRegisters;
    use ergo_sigma::evaluator::EvalBox;

    // Empty register block on the wire is a single count byte (0).
    let register_bytes = vec![0u8];
    let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
        1_000_000,
        tree.clone(),
        script_bytes.clone(),
        0,
        vec![],
        AdditionalRegisters::empty(),
        register_bytes.clone(),
    );
    let boxed = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes([0u8; 32]),
        index: 0,
    };
    // Surface a serialization/id failure rather than masking it as empty
    // `SELF.bytes` / a zero `SELF.id` (which would be a false reduce result for a
    // contract that inspects them). The box is well-formed here, so this is a
    // harness invariant — a failure is a real bug to report, not to swallow.
    let raw_bytes = serialize_ergo_box(&boxed)
        .map_err(|e| format!("dummy SELF box serialization failed: {e:?}"))?;
    let id = boxed
        .box_id()
        .map(|d| *d.as_bytes())
        .map_err(|e| format!("dummy SELF box id failed: {e:?}"))?;
    Ok(EvalBox {
        value: 1_000_000,
        script_bytes,
        creation_height: 0,
        id,
        transaction_id: [0u8; 32],
        output_index: 0,
        registers: [None, None, None, None, None, None],
        tokens: vec![],
        raw_bytes,
        register_bytes,
    })
}

fn reduce_verdict(bytes: &[u8]) -> (Verdict, usize) {
    use ergo_primitives::cost::{CostAccumulator, JitCost};
    use ergo_sigma::evaluator::{reduce_expr_with_cost, ReductionContext};

    // Full-consensus surface: curve-check group elements (the node's
    // `ergo-validation` tx gate), matching the JVM's deserialize-time GE check.
    let (res, consumed) = deserialize_box_script(bytes, true);
    let tree = match res {
        Ok(t) => t,
        Err(e) => return (Verdict::Reject(e), consumed),
    };
    if matches!(tree.body, ergo_ser::opcode::Expr::Unparsed(_)) {
        return (Verdict::Reject("UnparsedErgoTree".into()), consumed);
    }
    // Build SELF exactly as EvalCore.dummyContext does — `new ErgoBox(value = 1M,
    // ergoTree = tree, transactionId = 32 zeros, index = 0, creationHeight = 0)` —
    // and populate the box's serialized bytes + derived id so a script reading
    // `SELF.bytes` / `SELF.id` reduces to the SAME value on both sides (the bare
    // `EvalBox::simple` has empty bytes / zero id → a false divergence).
    let script_bytes = bytes[..consumed].to_vec();
    let self_box = match build_dummy_self_box(&tree, script_bytes) {
        Ok(b) => b,
        Err(e) => return (Verdict::Reject(e), consumed),
    };
    let inputs = [self_box];
    // Mirror EvalCore.dummyContext field-for-field so a script reading context
    // (preHeader.timestamp, minerPubkey, lastBlockUtxoRoot) reduces to the SAME
    // value on both sides — otherwise the JVM's timestamp 3 / generator miner key
    // / AvlTreeData.dummy vs the Rust defaults would be a FALSE divergence.
    let ctx = ReductionContext {
        self_box: Some(&inputs[0]),
        inputs: &inputs,
        pre_header_version: 4, // activated(3) + 1, matching EvalCore.dummyPreHeader
        pre_header_timestamp: 3, // CPreHeader.timestamp = 3L
        miner_pubkey: ergo_sigma::evaluator::SECP256K1_GENERATOR, // dlogGroup.generator
        // AvlTreeData.dummy: 33 zero bytes, all ops allowed, keyLength 32, no value length.
        last_block_utxo_root: Some(ergo_ser::sigma_value::AvlTreeData {
            digest: vec![0u8; 33],
            insert_allowed: true,
            update_allowed: true,
            remove_allowed: true,
            key_length: 32,
            value_length_opt: None,
        }),
        ergo_tree_version: tree.version,
        ..ReductionContext::minimal(0, 0)
    };
    let limit = match JitCost::from_block_cost(1_000_000) {
        Ok(l) => l,
        Err(_) => return (Verdict::Reject("cost-limit".into()), consumed),
    };
    let mut cost = CostAccumulator::new(limit);
    match reduce_expr_with_cost(&tree.body, &ctx, &tree.constants, &mut cost) {
        Ok(sb) => {
            let mut w = VlqWriter::new();
            if let Err(e) = ergo_ser::sigma_value::write_sigma_boolean(&mut w, &sb) {
                return (Verdict::Reject(format!("serialize: {e:?}")), consumed);
            }
            (
                Verdict::Accept(format!(
                    "P:{}|{}",
                    to_hex(&w.result()),
                    cost.total().value()
                )),
                consumed,
            )
        }
        Err(e) => (Verdict::Reject(format!("{e:?}")), consumed),
    }
}

/// `validate`: stateless structural transaction validity.
///
/// Mirrors Scala `ErgoTransaction.statelessValidity()`: the context-free checks
/// that need only the serialized transaction (no UTXO set, no state context).
/// These are: non-empty inputs, non-empty outputs, count caps at `Short.MaxValue`,
/// no duplicate inputs, per-output box-size / proposition-size / value / token-count
/// limits.
///
/// Group-element curve-checks and canonical-encoding checks are **not** included:
/// Scala performs GE checks at deserialization time (not inside `statelessValidity`)
/// and canonical encoding is a separate check (`ergoTransactionNonCanonical`) run
/// by the full validator, not by `statelessValidity`.
fn validate_verdict(bytes: &[u8]) -> (Verdict, usize) {
    let mut r = VlqReader::new(bytes);
    let tx = match ergo_ser::transaction::read_transaction(&mut r) {
        Err(e) => return (Verdict::Reject(format!("{e:?}")), r.position()),
        Ok(tx) => tx,
    };
    let consumed = r.position();
    let params = ergo_validation::context::ProtocolParams::mainnet_default();
    match ergo_validation::tx::structural::validate_structural(&tx, &params) {
        Ok(()) => (Verdict::Accept(String::new()), consumed),
        Err(e) => (Verdict::Reject(format!("{e:?}")), consumed),
    }
}

/// `verify_avl`: AVL+ batch-proof verification.
///
/// Decodes an [`crate::avl_frame::AvlFrame`], constructs the
/// `ergo_sigma::avl::AvlVerifier` (the guarded wrapper around the upstream
/// `ergo_avltree_rust::BatchAVLVerifier`), and applies every operation in
/// the frame. On success returns the final tree digest as hex; on any op
/// failure returns `Reject`.
///
/// The guard's `catch_unwind` boundary is what makes this surface safe against
/// a real upstream panic path:
/// a structurally-valid-but-wrong proof (e.g. a Lookup proof used for a Remove)
/// causes the upstream crate to `panic!` at op-time; the guard catches it and
/// returns `Err(())`, which surfaces here as `Verdict::Reject`. On a patched
/// (unguarded) codebase the panic escapes this function and is caught by
/// `run_one`'s outer `catch_unwind`, yielding `Outcome::Bug`.
fn verify_avl_verdict(bytes: &[u8]) -> (Verdict, usize) {
    use crate::avl_frame::{AvlFrame, AvlOp};
    use ergo_sigma::avl::AvlVerifier;

    let frame = match AvlFrame::decode(bytes) {
        Ok(f) => f,
        // Framing errors are oracle/harness problems → Err, not Reject.
        Err(e) => return (Verdict::Err(format!("avl_frame: {e}")), 0),
    };
    // The frame consumes all of `bytes` (no concatenation with other fields).
    let consumed = bytes.len();

    let mut verifier = match AvlVerifier::new(
        &frame.starting_digest,
        &frame.proof,
        frame.key_len as usize,
        frame.value_len_opt.map(|n| n as usize),
    ) {
        Ok(v) => v,
        Err(e) => return (Verdict::Reject(format!("construction: {e}")), consumed),
    };

    for (i, op) in frame.ops.iter().enumerate() {
        let result = match op {
            AvlOp::Lookup { key } => verifier.lookup(key).map(|_| ()),
            AvlOp::Insert { key, value } => verifier.insert(key, value),
            AvlOp::Update { key, value } => verifier.update(key, value),
            AvlOp::Remove { key } => verifier.remove(key),
        };
        if result.is_err() {
            return (Verdict::Reject(format!("op[{i}] failed")), consumed);
        }
    }

    match verifier.digest() {
        Some(d) => (Verdict::Accept(to_hex(&d)), consumed),
        // digest() returns None only when the verifier was poisoned by a
        // caught op-time panic.  This is a stronger rejection than a clean
        // operation failure; surface it as Reject to match the JVM's behaviour
        // (a failed op leaves topNode = None → subsequent digest() returns None).
        None => (Verdict::Reject("AvlVerifierPoisoned".into()), consumed),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::from_hex;

    /// Rule-1001 `valDefTypeStore` parity (Finding E): the node's verdict on
    /// duplicate-binding-id trees must equal the JVM's, which resolves every
    /// `ValUse` from a FLAT, never-scoped, last-write-wins store evolving in
    /// PARSE order (`ValDefSerializer.parse` writes `store[id] = rhs.tpe` AFTER
    /// the rhs; `FuncValueSerializer.parse` writes each arg's declared type
    /// BEFORE the body; `ValUseSerializer.parse` reads at its position).
    ///
    /// Live-oracle test: needs `scala-cli` on PATH; the first query resolves
    /// JVM dependencies (minutes). Run with
    /// `cargo test -p ergo-difftest --lib valdef_type_store -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs scala-cli (live JVM oracle)"]
    fn valdef_type_store_shapes_match_jvm_oracle() {
        use ergo_primitives::writer::VlqWriter;
        use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
        use ergo_ser::opcode::{Expr, IrNode, Payload};
        use ergo_ser::sigma_type::SigmaType;
        use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};

        fn op(opcode: u8, payload: Payload) -> Expr {
            Expr::Op(IrNode { opcode, payload })
        }
        fn long0() -> Expr {
            Expr::Const {
                tpe: SigmaType::SLong,
                val: SigmaValue::Long(0),
            }
        }
        fn sigma_const() -> Expr {
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
            }
        }
        fn val_def(id: u32, rhs: Expr) -> Expr {
            op(
                0xD6,
                Payload::ValDef {
                    id,
                    tpe: None,
                    rhs: Box::new(rhs),
                },
            )
        }
        fn fun_def(id: u32, rhs: Expr) -> Expr {
            op(
                0xD7,
                Payload::FunDef {
                    id,
                    tpe: None,
                    tpe_args: vec![SigmaType::STypeVar("T".into())],
                    rhs: Box::new(rhs),
                },
            )
        }
        fn val_use(id: u32) -> Expr {
            op(0x72, Payload::ValUse { id })
        }
        fn block(items: Vec<Expr>, result: Expr) -> Expr {
            op(
                0xD8,
                Payload::BlockValue {
                    items,
                    result: Box::new(result),
                },
            )
        }
        fn func_value(args: Vec<(u32, Option<SigmaType>)>, body: Expr) -> Expr {
            op(
                0xD9,
                Payload::FuncValue {
                    args,
                    body: Box::new(body),
                },
            )
        }
        /// Sizeless v0 tree (the class where rule 1001 is a plain REJECT on
        /// both sides, so accept/reject diffing is clean) — or has_size v0
        /// (where rule 1001 soft-fork-WRAPS on both sides instead: verdict
        /// stays ACCEPT and the canonical bytes are the preserved original).
        fn tree_bytes_sized(body: Expr, has_size: bool) -> Vec<u8> {
            let tree = ErgoTree {
                version: 0,
                has_size,
                constant_segregation: false,
                constants: vec![],
                body,
            };
            let mut w = VlqWriter::new();
            write_ergo_tree(&mut w, &tree).expect("write probe tree");
            w.result()
        }
        fn tree_bytes(body: Expr) -> Vec<u8> {
            tree_bytes_sized(body, false)
        }

        let dup_id_body = || block(vec![val_def(1, long0()), val_def(1, long0())], val_use(1));
        // (name, tree bytes, assert_parity). `assert_parity = false` probes are
        // reported only (documented residuals outside the rule-1001 typer).
        let probes: Vec<(&str, Vec<u8>, bool)> = vec![
            (
                // The Finding-E accept-invalid: root ValUse of a reused id is
                // SLong at its parse position -> Scala REJECTS.
                "dup_id_long { val x = 0L; val x = 0L; x }",
                tree_bytes(dup_id_body()),
                true,
            ),
            (
                // The same dup-id body under has_size: rule 1001 soft-fork
                // WRAPS on both sides -> ACCEPT with the original bytes as the
                // canonical form (checked below when both accept).
                "dup_id_long_has_size (wrap parity)",
                tree_bytes_sized(dup_id_body(), true),
                true,
            ),
            (
                // THE GUARDRAIL (reject-valid = chain stall if broken): y is
                // fixed to SigmaProp BEFORE the rebind -> Scala ACCEPTS.
                "guardrail { val x = sigma; val y = x; val x = 0L; y }",
                tree_bytes(block(
                    vec![
                        val_def(1, sigma_const()),
                        val_def(2, val_use(1)),
                        val_def(1, long0()),
                    ],
                    val_use(2),
                )),
                true,
            ),
            (
                // Last-write-wins in the ACCEPT direction: final store[x] is
                // SigmaProp -> Scala ACCEPTS (a first-write-wins bug rejects).
                "lastwrite_sigma { val x = 0L; val x = sigma; x }",
                tree_bytes(block(
                    vec![val_def(1, long0()), val_def(1, sigma_const())],
                    val_use(1),
                )),
                true,
            ),
            (
                // Dup ids present but the root is independent of them -> ACCEPT.
                "dup_id_unused_root { val x = 0L; val x = 0L; sigma }",
                tree_bytes(block(
                    vec![val_def(1, long0()), val_def(1, long0())],
                    sigma_const(),
                )),
                true,
            ),
            (
                // Off-spine rebind: the rebind of x sits inside the SECOND
                // item's rhs (a nested block the type spine never visits) but
                // is parsed BEFORE the root ValUse -> store[x] = SLong -> REJECT.
                "offspine_rebind { val x = sigma; val d = { val x = 0L; 0L }; x }",
                tree_bytes(block(
                    vec![
                        val_def(1, sigma_const()),
                        val_def(2, block(vec![val_def(1, long0())], long0())),
                    ],
                    val_use(1),
                )),
                true,
            ),
            (
                // FuncValue ARG rebind: FuncValueSerializer.parse writes each
                // arg's declared type into the store (never popped) -> the
                // lambda's arg id 1 rebinds x to SLong -> REJECT.
                "funcvalue_arg_rebind { val x = sigma; val f = (id1: Long) => 0L; x }",
                tree_bytes(block(
                    vec![
                        val_def(1, sigma_const()),
                        val_def(2, func_value(vec![(1, Some(SigmaType::SLong))], long0())),
                    ],
                    val_use(1),
                )),
                true,
            ),
            (
                // Rebind inside a FuncValue BODY (flat store, no scoping): the
                // nested ValDef in the lambda body rebinds x -> REJECT.
                "funcvalue_body_rebind { val x = sigma; val f = (id3: Long) => { val x = 0L; 0L }; x }",
                tree_bytes(block(
                    vec![
                        val_def(1, sigma_const()),
                        val_def(
                            2,
                            func_value(
                                vec![(3, Some(SigmaType::SLong))],
                                block(vec![val_def(1, long0())], long0()),
                            ),
                        ),
                    ],
                    val_use(1),
                )),
                true,
            ),
            (
                // FunDef (0xD7) writes the store exactly like ValDef -> the
                // ValDef rebind after it wins -> root ValUse = SLong -> REJECT.
                "fundef_rebind { fun f[T] = sigma; val f = 0L; f }",
                tree_bytes(block(
                    vec![fun_def(1, sigma_const()), val_def(1, long0())],
                    val_use(1),
                )),
                true,
            ),
            (
                // A bare ValDef root types as its rhs (Scala `ValDef.tpe =
                // rhs.tpe`, values.scala:924): a Long rhs -> REJECT...
                "bare_valdef_root_long { val x = 0L }",
                tree_bytes(val_def(1, long0())),
                true,
            ),
            (
                // ...and a sigma rhs -> ACCEPT.
                "bare_valdef_root_sigma { val x = sigma }",
                tree_bytes(val_def(1, sigma_const())),
                true,
            ),
            (
                // ValUse of an id NEVER bound: Scala's `store(id)` throws
                // NoSuchElementException at PARSE (not a ValidationException,
                // so a hard reject even under has_size). The node's parser
                // accepts an unbound ValUse and the typer stays lenient — a
                // PARSE-layer divergence outside the rule-1001 typer, reported
                // here as a documented residual (not asserted).
                "unbound_valuse { x }",
                tree_bytes(block(vec![], val_use(1))),
                false,
            ),
        ];

        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../scripts/jvm_serde_oracle/ErgoSerdeOracle.scala"
        );
        let mut oracle = Oracle::spawn(script).expect("spawn JVM oracle");

        let mut failures = Vec::new();
        for (name, bytes, assert_parity) in probes {
            let (rust, _consumed) = ergo_tree_verdict(&bytes);
            let jvm = oracle.query("ergo_tree", &bytes).expect("oracle query");
            let class = |v: &Verdict| match v {
                Verdict::Accept(_) => "ACCEPT",
                Verdict::Reject(_) => "REJECT",
                Verdict::Err(_) => "ERR",
            };
            println!(
                "{name}\n  bytes: {}\n  node: {} | jvm: {}{}",
                to_hex(&bytes),
                class(&rust),
                class(&jvm),
                if assert_parity { "" } else { "  (report-only)" },
            );
            assert!(
                !matches!(jvm, Verdict::Err(_)),
                "oracle ERR on {name}: {jvm:?}"
            );
            if assert_parity {
                if class(&rust) != class(&jvm) {
                    failures.push(format!(
                        "{name}: node={} jvm={} ({rust:?} vs {jvm:?})",
                        class(&rust),
                        class(&jvm)
                    ));
                } else if let (Verdict::Accept(a), Verdict::Accept(b)) = (&rust, &jvm) {
                    // Both accepted: the canonical re-serialization must agree
                    // too (a soft-fork WRAP preserves the original bytes on
                    // both sides, so a wrap-vs-plain-accept split shows here).
                    if !a.is_empty() && !b.is_empty() && a != b {
                        failures.push(format!("{name}: canonical mismatch node={a} jvm={b}"));
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "node/JVM rule-1001 verdict divergence:\n{}",
            failures.join("\n")
        );
    }

    // ----- oracle parity -----

    /// The `reduce` surface's node half must agree with the JVM reference on the
    /// `P:<sigma-prop>|<jit-cost>` form. The expected strings below come from the
    /// JVM oracle (`ErgoSerdeOracle` `reduce`, sigma-state 6.0.2, activated v3) —
    /// NOT from `reduce_verdict` itself; this pins the prop serialization, the
    /// Bool→TrivialProp coercion, and the cost path against the Scala node so a
    /// `cargo test` run catches a reduce/cost drift without needing `scala-cli`.
    #[test]
    fn reduce_verdict_known_trees_match_jvm_oracle() {
        for (hex, want) in [
            // P2PK → self-reduces to its ProveDlog, base cost 5.
            (
                "0008cd02000a518dc9761306f048c70ad44e1a7fc9e4ce2ceeea529646f73aada1ea6640",
                "P:cd02000a518dc9761306f048c70ad44e1a7fc9e4ce2ceeea529646f73aada1ea6640|5",
            ),
            // constant TrueProp / FalseProp → Bool→TrivialProp coercion.
            ("0008d3", "P:d3|5"),
            ("0008d2", "P:d2|5"),
            // a real segregated contract that reduces to FalseProp at cost 128
            // (exercises the cost-accumulation path, not just the base cost).
            (
                "100204a00b08cd0204b680ae52835e22f12fc3c51c4cd9e18852ac4f4a8131be29920678aceeeebeea02d192a39a8cc7a70173007301",
                "P:d2|128",
            ),
        ] {
            let bytes = from_hex(hex).unwrap();
            let (v, _consumed) = reduce_verdict(&bytes);
            assert_eq!(v, Verdict::Accept(want.to_string()), "mismatch on {hex}");
        }
    }

    // ----- LIVE JVM-oracle differential for the #215 evaluator fixes -----
    //
    // Ignored by default (needs `scala-cli` on PATH; first query resolves the
    // sigma-state deps). Run with:
    //   cargo test -p ergo-difftest --lib reduce_diff_serialize_and_flatmap -- --ignored --nocapture
    //
    // Each tree exercises a #215 fix so its reduced `P:<prop>|<cost>` MUST match
    // the JVM reference. Both sides reduce against the same dummy context
    // (SELF = the box whose script IS the tree; INPUTS = [SELF]).
    #[test]
    #[ignore = "requires scala-cli"]
    fn reduce_diff_serialize_and_flatmap_match_jvm_oracle() {
        use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};
        use ergo_ser::opcode::{Expr, IrNode, Payload};
        use ergo_ser::sigma_type::SigmaType;
        use ergo_ser::sigma_value::{CollValue, SigmaValue};

        fn op(opcode: u8, payload: Payload) -> Expr {
            Expr::Op(IrNode { opcode, payload })
        }
        fn tree_bytes(body: Expr) -> Vec<u8> {
            let tree = ErgoTree {
                version: 3,
                has_size: true,
                constant_segregation: false,
                constants: vec![],
                body,
            };
            let mut w = ergo_primitives::writer::VlqWriter::new();
            write_ergo_tree(&mut w, &tree).expect("write tree");
            w.result()
        }
        let self_box = || op(0xA7, Payload::Zero); // SELF
        let global = || op(0xDD, Payload::Zero); // SGlobal receiver
        let serialize = |arg: Expr| {
            op(
                0xDC,
                Payload::MethodCall {
                    type_id: 106,
                    method_id: 3, // SGlobal.serialize
                    obj: Box::new(global()),
                    args: vec![arg],
                    type_args: vec![],
                },
            )
        };
        let bool_to_prop = |b: Expr| op(0xD1, Payload::One(Box::new(b)));

        // #2a serialize(SELF) == SELF.bytes  → the canonical-bytes analogy the fix
        // relies on; TRUE on both iff serialize(SELF) equals ErgoBox.bytes.
        let v_self = bool_to_prop(op(
            0x93, // Eq
            Payload::Two(
                Box::new(serialize(self_box())),
                Box::new(op(0xC3, Payload::One(Box::new(self_box())))), // SELF.bytes
            ),
        ));

        // #2b serialize(INPUTS).size > 0  → the BoxCollection resolve path accepts
        // (pre-fix it rejected → REJECT vs the JVM's ACCEPT), and the serialized
        // length + cost must match.
        let v_inputs = bool_to_prop(op(
            0x91, // Gt
            Payload::Two(
                Box::new(op(
                    0xB1,                                                       // SizeOf
                    Payload::One(Box::new(serialize(op(0xA4, Payload::Zero)))), // serialize(INPUTS)
                )),
                Box::new(Expr::Const {
                    tpe: SigmaType::SInt,
                    val: SigmaValue::Int(0),
                }),
            ),
        ));

        // #4 serialize(Coll[Long]().flatMap(x => Coll[Long](x))) == serialize(Coll[Long]())
        // → the empty-flatMap output must be tagged Coll[Long] (fix), not Coll[Byte];
        // both serialize to the same bytes only when the element type is preserved.
        let empty_long = || Expr::Const {
            tpe: SigmaType::SColl(Box::new(SigmaType::SLong)),
            val: SigmaValue::Coll(CollValue::Values(vec![])),
        };
        let mapper = op(
            0xD9, // FuncValue
            Payload::FuncValue {
                args: vec![(1, Some(SigmaType::SLong))],
                body: Box::new(op(
                    0x83, // ConcreteCollection
                    Payload::ConcreteCollection {
                        elem_type: SigmaType::SLong,
                        items: vec![op(0x72, Payload::ValUse { id: 1 })],
                    },
                )),
            },
        );
        let flat_mapped = op(
            0xDC,
            Payload::MethodCall {
                type_id: 12,
                method_id: 15, // Coll.flatMap
                obj: Box::new(empty_long()),
                args: vec![mapper],
                type_args: vec![],
            },
        );
        let v_flatmap = bool_to_prop(op(
            0x93, // Eq
            Payload::Two(
                Box::new(serialize(flat_mapped)),
                Box::new(serialize(empty_long())),
            ),
        ));

        let vectors = [
            ("serialize(SELF)==SELF.bytes", tree_bytes(v_self)),
            ("serialize(INPUTS).size>0", tree_bytes(v_inputs)),
            ("empty flatMap type", tree_bytes(v_flatmap)),
        ];

        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../scripts/jvm_serde_oracle/ErgoSerdeOracle.scala"
        );
        let mut oracle = Oracle::spawn(script).expect("spawn scala-cli oracle");
        for (name, bytes) in vectors {
            let (node, _consumed) = reduce_verdict(&bytes);
            let jvm = oracle.query("reduce", &bytes).expect("oracle query");
            eprintln!("[{name}] node={node:?}  jvm={jvm:?}");
            assert!(
                matches!(node, Verdict::Accept(_)),
                "[{name}] node must ACCEPT (a malformed tree or rejected fix would REJECT): {node:?}"
            );
            assert_eq!(node, jvm, "[{name}] node vs JVM reduce divergence");
        }
    }
}

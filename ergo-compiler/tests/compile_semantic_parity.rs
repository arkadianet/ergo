//! Compile-vector corpus + SigmaBoolean semantic-parity gate (M3 Task 10).
//!
//! The M3 acceptance test for [`ergo_compiler::compile`]: our compiled trees
//! must EVALUATE identically to the Scala-compiled trees across the whole
//! corpus, even though the byte representations legitimately differ until the
//! M4 constant-segregation transform (we emit non-segregated header `0x00`;
//! Scala segregates every non-bare-constant root, header `0x10`).
//!
//! **Vector corpus** (`test-vectors/ergoscript/compile/compile_seed.json`):
//! every typecheck-ACCEPT source in `golden_seed.txt` fed through the matching
//! compile verb of the JVM oracle (`tc`→`cc`, `tce`→`cce`, `tcs`→`ccs`;
//! `scripts/jvm_typer_oracle/TyperOracle.scala`, sigma-state 6.0.2,
//! `ORACLE_TREE_VERSION=3`, `ORACLE_NETWORK=testnet`), plus the 79-contract
//! real-world corpus (`test-vectors/ergoscript/corpus/`) under `cc`, plus
//! the compile-only probe list (`compile_probes.txt`, Task-11 wave-1
//! GraphBuilding gate vectors, per-line `ORACLE_TREE_VERSION`). Oracle
//! REJECTs for golden-seed/probe sources are recorded verbatim (a
//! typecheck-accept may compile-reject — that verdict is signal, cf.
//! golden_seed §22); corpus compile-REJECTs are counted in the JSON
//! `_source` note and excluded, per the task brief. No oracle field is ever
//! hand-edited.
//!
//! **The gate** ([`compile_seed_semantic_parity`], always-on, committed JSON
//! only):
//! - oracle REJECT → our `compile()` must also reject (class advisory only);
//! - oracle ACCEPT → our `compile()` must accept, and BOTH our
//!   `ergo_tree.body` and the parsed oracle `tree_hex` body must reduce — via
//!   `ergo_sigma::evaluator::reduce_expr` under the difftest-pinned dummy
//!   context (`ergo-difftest/src/oracle.rs:400-431`, field-for-field) — to
//!   the SAME `write_sigma_boolean` hex (NO cost comparison). `Err/Err` is
//!   parity (both error strings recorded as telemetry — the design for
//!   context-bound scripts that read registers/OUTPUTS the dummy context
//!   lacks); mixed `Ok`/`Err` is a FAIL.
//! - byte telemetry (non-gating): counts `tree_bytes == tree_hex`; equality
//!   is ASSERTED only for the bare-constant class (root = `Const SigmaProp`
//!   on both sides — the one class where Scala also takes the
//!   `withoutSegregation` branch, generalizing Task 9's single PK pin).
//!
//! **Live recapture** ([`compile_seed_live_recapture`], `#[ignore]`): spawns
//! the oracle once (batch stdin, EOF-close, grammar grep-filter — the
//! `corpus_smoke.rs` pattern), regenerates the JSON, and diffs it against the
//! committed file (capture-date field excluded); on drift it refreshes the
//! file on disk and fails so the diff can be reviewed. Needs `scala-cli` on
//! PATH (+ network on first run):
//!
//! ```text
//! cargo test -p ergo-compiler --test compile_semantic_parity -- --ignored --nocapture
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ergo_compiler::{compile, EnvValue, GroupElement, NetworkPrefix, ScriptEnv};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{read_ergo_tree, ErgoTree};
use ergo_ser::opcode::Expr;
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{write_sigma_boolean, AvlTreeData, SigmaValue};
use ergo_sigma::evaluator::{reduce_expr, EvalBox, ReductionContext, SECP256K1_GENERATOR};

// =============================================================================
// SEMANTIC_SKIP — semantic-gate exclusions (same discipline as SWEEP_SKIP).
// =============================================================================
//
// `(source, reason + ledger tag)` pairs excluded from the semantic-parity
// sweep. Every entry needs a reason and a lib.rs ledger D-tag.
//
// The ONE open class at Task-10 close is D-C3 (lib.rs ledger): sources mixing
// SigmaProp and Boolean in a logical context typecheck into trees carrying
// `SigmaPropIsProven` coercions. Scala's IR pipeline eliminates them
// (GraphBuilding.scala:528-529/765-767 `isProven` → `isValid`, then constant
// folding / sigma reconstruction — the oracle trees are folded); our emit
// maps the node 1:1 to wire opcode 0xCF, which NO evaluator accepts (ours:
// `InternalOpcode`; Scala JIT: `costKind = notSupportedError`, no `eval`,
// transformers.scala:321-329). Closing needs the M4/M5 IR lowering; a local
// pre-reject would flip the divergence direction (we-reject/oracle-accepts).
// Context-bound scripts are handled by Err/Err parity, never skipped.
const SEMANTIC_SKIP: &[(&str, &str)] = &[
    (
        "allOf(Coll(proveDlog(g1)))",
        "D-C3: SigmaPropIsProven inside AND; Scala folds to a bare SigmaPropConstant",
    ),
    (
        "sigmaProp(true) && (1 == 1)",
        "D-C3: isProven residual in BinAnd; Scala folds sigmaProp(true).isValid -> true",
    ),
    (
        "(1 == 1) && sigmaProp(true)",
        "D-C3: isProven residual in BinAnd (mirrored operands)",
    ),
    (
        "sigmaProp(true) ^ (1 == 1)",
        "D-C3: isProven residual in BinXor; Scala folds the whole XOR to a false constant",
    ),
    (
        "(1 == 1) ^ sigmaProp(true)",
        "D-C3: isProven residual in BinXor (mirrored operands)",
    ),
];

// =============================================================================
// Environment builders (mirror TyperOracle.scala demo/sigmaTyperTest envs;
// same construction as tests/typer_oracle_parity.rs:127-175).
// =============================================================================

/// The secp256k1 generator point, SEC1-compressed (g1/g2 in both envs).
fn generator_ge() -> GroupElement {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .expect("valid hex");
    bytes[1..].copy_from_slice(&x);
    GroupElement::from_bytes(bytes)
}

/// `g^7` — the fixed NON-generator point, `TyperOracle.scala:demoEnv`'s `g3`.
fn non_generator_ge() -> GroupElement {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    let x = hex::decode("5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
        .expect("valid hex");
    bytes[1..].copy_from_slice(&x);
    GroupElement::from_bytes(bytes)
}

/// Demo env (`cce`): matches `TyperOracle.scala:demoEnv`.
fn demo_env() -> ScriptEnv {
    let ge = generator_ge();
    let mut env = ScriptEnv::new();
    env.insert("a", EnvValue::ByteArray(vec![1, 2]));
    env.insert("b", EnvValue::ByteArray(vec![3, 4]));
    env.insert("col1", EnvValue::LongArray(vec![1, 2]));
    env.insert("col2", EnvValue::LongArray(vec![3, 4]));
    env.insert("g1", EnvValue::GroupElement(ge));
    env.insert("g2", EnvValue::GroupElement(ge));
    env.insert("g3", EnvValue::GroupElement(non_generator_ge()));
    env.insert("n1", EnvValue::BigInt("5".to_string()));
    env.insert("bb1", EnvValue::Byte(1));
    env.insert("bb2", EnvValue::Byte(2));
    env
}

/// SigmaTyperTest env (`ccs`): mirrors `LangTests.scala:52-69`.
fn typer_test_env() -> ScriptEnv {
    let ge = generator_ge();
    let mut env = ScriptEnv::new();
    env.insert("x", EnvValue::Int(10));
    env.insert("y", EnvValue::Int(11));
    env.insert("c1", EnvValue::Bool(true));
    env.insert("c2", EnvValue::Bool(false));
    env.insert("height1", EnvValue::Long(100));
    env.insert("height2", EnvValue::Long(200));
    env.insert("b1", EnvValue::Byte(1));
    env.insert("b2", EnvValue::Byte(2));
    env.insert("arr1", EnvValue::ByteArray(vec![1, 2]));
    env.insert("arr2", EnvValue::ByteArray(vec![10, 20]));
    env.insert("col1", EnvValue::LongArray(vec![1, 2]));
    env.insert("col2", EnvValue::LongArray(vec![10, 20]));
    env.insert("g1", EnvValue::GroupElement(ge));
    env.insert("g2", EnvValue::GroupElement(ge));
    env.insert("p1", EnvValue::SigmaProp("p1".to_string()));
    env.insert("p2", EnvValue::SigmaProp("p2".to_string()));
    env.insert("n1", EnvValue::BigInt("10".to_string()));
    env.insert("n2", EnvValue::BigInt("20".to_string()));
    env
}

/// The Rust env matching an oracle compile verb.
fn env_for_verb(verb: &str) -> ScriptEnv {
    match verb {
        "cc" => ScriptEnv::new(),
        "cce" => demo_env(),
        "ccs" => typer_test_env(),
        other => panic!("unknown compile verb {other:?}"),
    }
}

// =============================================================================
// Vector model + JSON I/O.
// =============================================================================

/// `<crate>/../test-vectors/ergoscript/compile/compile_seed.json`.
fn seed_json_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors/ergoscript/compile/compile_seed.json")
}

/// One committed compile vector (decision-8 schema).
#[derive(Debug, Clone)]
struct Vector {
    verb: String,
    source: String,
    network: String,
    tree_version: u8,
    /// `"ACCEPT"` or `"REJECT"` — the oracle's compile verdict.
    oracle: String,
    tree_hex: Option<String>,
    reject_class: Option<String>,
    /// Corpus-relative `.es` path for corpus-sourced vectors (provenance).
    corpus_path: Option<String>,
}

fn str_field(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|s| s.as_str()).map(|s| s.to_string())
}

/// Load the committed `compile_seed.json` into `(full JSON, vectors)`.
fn load_vectors() -> (serde_json::Value, Vec<Vector>) {
    let raw = std::fs::read_to_string(seed_json_path()).expect(
        "read compile_seed.json — regenerate it with \
         `cargo test -p ergo-compiler --test compile_semantic_parity -- --ignored`",
    );
    let json: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    let vectors = json["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .map(|v| Vector {
            verb: str_field(v, "verb").expect("verb"),
            source: str_field(v, "source").expect("source"),
            network: str_field(v, "network").expect("network"),
            tree_version: v["tree_version"].as_u64().expect("tree_version") as u8,
            oracle: str_field(v, "oracle").expect("oracle"),
            tree_hex: str_field(v, "tree_hex"),
            reject_class: str_field(v, "reject_class"),
            corpus_path: str_field(v, "corpus_path"),
        })
        .collect();
    (json, vectors)
}

fn network_of(v: &Vector) -> NetworkPrefix {
    match v.network.as_str() {
        "testnet" => NetworkPrefix::Testnet,
        "mainnet" => NetworkPrefix::Mainnet,
        other => panic!("unknown network {other:?}"),
    }
}

// =============================================================================
// Reduction under the difftest-pinned dummy context.
// =============================================================================

/// Construct the dummy SELF box exactly as `EvalCore.dummyContext` does —
/// field-for-field copy of `ergo-difftest/src/oracle.rs::build_dummy_self_box`
/// (`new ErgoBox(value = 1M, ergoTree = tree, transactionId = 32 zeros,
/// index = 0, creationHeight = 0)`), with serialized bytes + Blake2b id
/// populated so `SELF.bytes` / `SELF.id` reduce to real values. Each side's
/// box is built from its OWN tree/bytes — mirroring what Scala's dummy eval
/// would see for that tree.
fn build_dummy_self_box(tree: &ErgoTree, script_bytes: Vec<u8>) -> Result<EvalBox, String> {
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
    use ergo_ser::register::AdditionalRegisters;

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

/// Reduce a tree's body to its `write_sigma_boolean` hex under the
/// difftest-pinned dummy context (`ergo-difftest/src/oracle.rs:400-431`
/// field-for-field): SELF = the tree at 1M nanoErg (sole input),
/// pre-header version 4 / timestamp 3 / generator miner key,
/// `AvlTreeData.dummy` UTXO root, activated v6 (`minimal`'s default 3), and
/// `ergo_tree_version` = the tree's OWN header version. The tree's own
/// `constants` slice resolves `ConstPlaceholder` bodies in segregated oracle
/// trees; our non-segregated trees pass an empty slice. NO cost comparison
/// (recording-only accumulator inside `reduce_expr`).
fn reduce_to_sigma_hex(tree: &ErgoTree, wire_bytes: &[u8]) -> Result<String, String> {
    let self_box = build_dummy_self_box(tree, wire_bytes.to_vec())?;
    let inputs = [self_box];
    let ctx = ReductionContext {
        self_box: Some(&inputs[0]),
        inputs: &inputs,
        pre_header_version: 4, // activated(3) + 1, matching EvalCore.dummyPreHeader
        pre_header_timestamp: 3, // CPreHeader.timestamp = 3L
        miner_pubkey: SECP256K1_GENERATOR, // dlogGroup.generator
        // AvlTreeData.dummy: 33 zero bytes, all ops allowed, keyLength 32.
        last_block_utxo_root: Some(AvlTreeData {
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
    match reduce_expr(&tree.body, &ctx, &tree.constants) {
        Ok(sb) => {
            let mut w = VlqWriter::new();
            write_sigma_boolean(&mut w, &sb);
            Ok(hex::encode(w.result()))
        }
        Err(e) => Err(format!("{e:?}")),
    }
}

/// First identifier of an error's Debug string — the "class" used for the
/// Err/Err telemetry pairs (e.g. `TypeError { .. }` → `TypeError`).
fn err_head(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// `true` when the tree is the bare-constant `SigmaProp` class — the ONE
/// byte-gated class at M3 (Scala's `fromProposition` also takes the
/// `withoutSegregation` branch for a bare `SigmaPropConstant`).
fn is_bare_sigma_const(tree: &ErgoTree) -> bool {
    !tree.constant_segregation
        && matches!(
            &tree.body,
            Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(_),
            }
        )
}

// =============================================================================
// The M3 gate (always-on; committed JSON only).
// =============================================================================

/// Semantic-parity sweep over every committed compile vector. See the module
/// docs for the comparison rules. Prints the byte-parity telemetry line and
/// the Err/Err class-pair telemetry (visible with `--nocapture`).
#[test]
fn compile_seed_semantic_parity() {
    let (_, vectors) = load_vectors();
    assert!(
        vectors.len() >= 140,
        "only {} compile vectors — the seed may have shrunk",
        vectors.len()
    );

    let mut divergences: Vec<String> = Vec::new();
    let mut class_advisories: Vec<String> = Vec::new();
    // (our-error head, oracle-tree-error head) -> (count, first vector label).
    let mut err_pairs: BTreeMap<(String, String), (usize, String)> = BTreeMap::new();
    let mut accept_total = 0usize;
    let mut byte_match = 0usize;
    let mut bare_total = 0usize;
    let mut bare_match = 0usize;
    let mut skipped = 0usize;

    for v in &vectors {
        let label = v
            .corpus_path
            .as_deref()
            .map(|p| format!("{} corpus:{p}", v.verb))
            .unwrap_or_else(|| format!("{} {:?}", v.verb, v.source));
        if let Some(&(_, reason)) = SEMANTIC_SKIP.iter().find(|(s, _)| *s == v.source) {
            eprintln!("SEMANTIC_SKIP {label}: {reason}");
            skipped += 1;
            continue;
        }
        let env = env_for_verb(&v.verb);
        let result = compile(&env, &v.source, v.tree_version, network_of(v));

        if v.oracle == "REJECT" {
            match result {
                Ok(_) => divergences.push(format!(
                    "{label}: oracle compile-REJECTs ({}) but our compile() ACCEPTs",
                    v.reject_class.as_deref().unwrap_or("?"),
                )),
                Err(e) => {
                    // Verdict parity holds; the class is advisory telemetry only
                    // (Scala rejects at GraphBuilding/IR stages we don't mirror).
                    let oracle_class = v.reject_class.as_deref().unwrap_or("?");
                    if e.class() != oracle_class {
                        class_advisories
                            .push(format!("{label}: oracle={oracle_class} rust={}", e.class()));
                    }
                }
            }
            continue;
        }

        // Oracle ACCEPT.
        let ours = match result {
            Ok(r) => r,
            Err(e) => {
                divergences.push(format!(
                    "{label}: oracle compile-ACCEPTs but our compile() rejects: {e:?}"
                ));
                continue;
            }
        };
        accept_total += 1;
        let oracle_bytes = hex::decode(v.tree_hex.as_deref().expect("ACCEPT vector has tree_hex"))
            .expect("tree_hex is hex");
        let mut r = VlqReader::new(&oracle_bytes);
        let oracle_tree = match read_ergo_tree(&mut r) {
            Ok(t) => t,
            Err(e) => {
                divergences.push(format!("{label}: oracle tree_hex does not parse: {e:?}"));
                continue;
            }
        };

        // Byte telemetry (non-gating except for the bare-constant class).
        if ours.tree_bytes == oracle_bytes {
            byte_match += 1;
        }
        if is_bare_sigma_const(&ours.ergo_tree) && is_bare_sigma_const(&oracle_tree) {
            bare_total += 1;
            if ours.tree_bytes == oracle_bytes {
                bare_match += 1;
            } else {
                divergences.push(format!(
                    "{label}: bare-const SigmaProp class must be byte-identical: \
                     ours={} oracle={}",
                    hex::encode(&ours.tree_bytes),
                    hex::encode(&oracle_bytes),
                ));
            }
        }

        // The semantic gate: reduce both bodies under the dummy context.
        let mine = reduce_to_sigma_hex(&ours.ergo_tree, &ours.tree_bytes);
        let theirs = reduce_to_sigma_hex(&oracle_tree, &oracle_bytes);
        match (mine, theirs) {
            (Ok(a), Ok(b)) => {
                if a != b {
                    divergences.push(format!(
                        "{label}: SigmaBoolean divergence: ours={a} oracle-tree={b}"
                    ));
                }
            }
            (Err(a), Err(b)) => {
                // Err/Err = parity — USUALLY a context-bound script (the dummy
                // context lacks the registers/outputs it reads, both sides err
                // the same way). KNOWN NON-CONTEXT-BOUND RESIDENT: the
                // (RuntimeException, TypeError) pair is D-C4 (multi-arg fold
                // lambdas emit an unevaluable multi-arg FuncValue; see the
                // lib.rs ledger) passing by coincidence of the dummy context —
                // when the reduction context is enriched or the lowering lands,
                // those vectors flip to a LOUD mixed Ok/Err failure here.
                // Record the class pair, with the first vector's full errors.
                let entry = err_pairs
                    .entry((err_head(&a), err_head(&b)))
                    .or_insert_with(|| (0, format!("{label}: ours={a} oracle-tree={b}")));
                entry.0 += 1;
            }
            (Ok(a), Err(b)) => divergences.push(format!(
                "{label}: ours reduces (={a}) but the oracle tree errs: {b}"
            )),
            (Err(a), Ok(b)) => divergences.push(format!(
                "{label}: oracle tree reduces (={b}) but ours errs: {a}"
            )),
        }
    }

    // Telemetry (non-gating counters; the bare-const class is gated above).
    println!(
        "byte-parity telemetry: {byte_match}/{accept_total} (bare-const {bare_match}/{bare_total})"
    );
    if !err_pairs.is_empty() {
        println!("Err/Err parity class pairs (ours, oracle-tree) x count [first vector]:");
        for ((a, b), (n, first)) in &err_pairs {
            println!("  ({a}, {b}) x {n} [{first}]");
        }
    }
    if !class_advisories.is_empty() {
        println!(
            "reject-class advisories ({} — verdict parity holds):",
            class_advisories.len()
        );
        for a in &class_advisories {
            println!("  {a}");
        }
    }
    println!("skipped {skipped} (SEMANTIC_SKIP)");

    assert!(
        divergences.is_empty(),
        "{} semantic-parity divergence(s):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
    // The bare-constant class must actually be exercised (PK vectors).
    assert!(bare_total >= 1, "no bare-const SigmaProp vector swept");
    // Err/Err composition pin: D-C4 proved a masked shape divergence can hide
    // as Err/Err parity. Any pair class OUTSIDE this audited set is a NEW,
    // un-triaged masking candidate — fail loudly instead of letting it ride
    // as telemetry nobody reads on green runs. Extend the set ONLY with a
    // ledger entry explaining the new pair (audit trail: lib.rs D-C3/D-C4).
    const AUDITED_ERR_PAIRS: &[(&str, &str)] = &[
        ("TypeError", "TypeError"),        // context-bound scripts (both sides)
        ("RuntimeException", "TypeError"), // D-C4 multi-arg fold lambdas
    ];
    for (pair, (n, first)) in &err_pairs {
        assert!(
            AUDITED_ERR_PAIRS.contains(&(pair.0.as_str(), pair.1.as_str())),
            "un-audited Err/Err class pair ({}, {}) x {n} — a new masked-divergence \
             candidate; triage it (ledger + audit-set entry) before accepting: {first}",
            pair.0,
            pair.1,
        );
    }
}

// =============================================================================
// Live recapture (spawns the JVM oracle; regenerates + diffs the JSON).
// =============================================================================

/// Golden-seed record parsing (same format as `typer_oracle_parity.rs`).
fn parse_seed_line(line: &str) -> Option<(&str, &str, &str)> {
    if line.starts_with('#') || line.trim().is_empty() {
        return None;
    }
    let parts: Vec<&str> = line.splitn(3, '\t').collect();
    if parts.len() == 3 {
        Some((parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

/// All vendored corpus `.es` files, keyed by corpus-relative path (the
/// `corpus_smoke.rs` loader).
fn corpus_files() -> BTreeMap<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors/ergoscript/corpus");
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

/// One capture request: compile verb, source, oracle tree version, corpus
/// provenance.
struct Request {
    verb: String,
    source: String,
    /// `ORACLE_TREE_VERSION` for this request (3 for seed/corpus sources;
    /// per-line for `compile_probes.txt` — the wave-1 SNumericType vectors
    /// are v2-only).
    tree_version: u8,
    corpus_path: Option<String>,
    /// `true` for `compile_probes.txt` sources (counted separately in the
    /// `_source` note; probe REJECTs are kept like seed REJECTs).
    probe: bool,
}

/// The full request list: every unique typecheck-ACCEPT golden-seed source
/// through its matching compile verb (seed order), then the whole 79-contract
/// corpus under `cc` (path order), then the compile-only probe list
/// (`compile_probes.txt`, the Task-11 wave-1 GraphBuilding gate vectors —
/// provenance notes in that file).
fn capture_requests() -> Vec<Request> {
    let seed = include_str!("../../test-vectors/ergoscript/typer/golden_seed.txt");
    let mut seen = std::collections::BTreeSet::new();
    let mut requests = Vec::new();
    for line in seed.lines() {
        let Some((verb, src, expected)) = parse_seed_line(line) else {
            continue;
        };
        if !expected.starts_with("OK ") {
            continue; // only typecheck-ACCEPT sources feed the compile corpus
        }
        let cverb = match verb {
            "tc" => "cc",
            "tce" => "cce",
            "tcs" => "ccs",
            other => panic!("unknown seed verb {other:?}"),
        };
        if seen.insert((cverb.to_string(), src.to_string(), 3u8)) {
            requests.push(Request {
                verb: cverb.to_string(),
                source: src.to_string(),
                tree_version: 3,
                corpus_path: None,
                probe: false,
            });
        }
    }
    for (rel, src) in corpus_files() {
        requests.push(Request {
            verb: "cc".to_string(),
            source: src,
            tree_version: 3,
            corpus_path: Some(rel),
            probe: false,
        });
    }
    let probes = include_str!("../../test-vectors/ergoscript/compile/compile_probes.txt");
    for line in probes.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        let [verb, version, src] = parts[..] else {
            panic!("malformed compile_probes.txt line: {line:?}");
        };
        let tree_version: u8 = version
            .parse()
            .unwrap_or_else(|_| panic!("bad tree_version in compile_probes.txt line: {line:?}"));
        if seen.insert((verb.to_string(), src.to_string(), tree_version)) {
            requests.push(Request {
                verb: verb.to_string(),
                source: src.to_string(),
                tree_version,
                corpus_path: None,
                probe: true,
            });
        }
    }
    requests
}

/// One parsed oracle compile reply.
enum Reply {
    Accept {
        tree_hex: String,
        p2s: String,
        p2sh: String,
    },
    Reject {
        pos: String,
        class: String,
    },
}

/// Run the whole request list through the oracle, ONE process per distinct
/// `tree_version` (`ORACLE_TREE_VERSION` is a process-level pin); replies
/// come back in the original request order.
fn run_oracle_batch(requests: &[Request]) -> Vec<Reply> {
    let versions: std::collections::BTreeSet<u8> =
        requests.iter().map(|r| r.tree_version).collect();
    let mut replies: Vec<Option<Reply>> = requests.iter().map(|_| None).collect();
    for version in versions {
        let idx: Vec<usize> = (0..requests.len())
            .filter(|&i| requests[i].tree_version == version)
            .collect();
        let subset: Vec<&Request> = idx.iter().map(|&i| &requests[i]).collect();
        for (i, reply) in idx
            .into_iter()
            .zip(run_oracle_batch_version(&subset, version))
        {
            replies[i] = Some(reply);
        }
    }
    replies
        .into_iter()
        .map(|r| r.expect("every request answered by its version batch"))
        .collect()
}

/// Run one same-version batch through ONE oracle process (the
/// `corpus_smoke.rs` spawn pattern — batch stdin, EOF-close, grammar filter,
/// `child.wait()` — with one adaptation: the stdin feed runs on its OWN
/// thread while this thread drains stdout. Compile replies carry full tree
/// hexes, so writing the whole request batch before reading deadlocks once
/// both 64 KiB pipe buffers fill (the parse oracle's one-word verdicts never
/// hit this). Retries up to 3× on a reply-count mismatch; panics on an `ERR`
/// reply.
fn run_oracle_batch_version(requests: &[&Request], tree_version: u8) -> Vec<Reply> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let oracle_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("scripts/jvm_typer_oracle");

    let lines_to_send: Vec<String> = requests
        .iter()
        .map(|req| {
            let hex: String = req
                .source
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            format!("{} {hex}", req.verb)
        })
        .collect();

    for attempt in 1..=3 {
        let mut child = Command::new("scala-cli")
            .arg("run")
            .arg(&oracle_path)
            .env("ORACLE_TREE_VERSION", tree_version.to_string())
            .env("ORACLE_NETWORK", "testnet")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scala-cli (is it on PATH?)");
        let mut stdin = child.stdin.take().expect("piped stdin");
        let batch = lines_to_send.clone();
        let feeder = std::thread::spawn(move || {
            for line in &batch {
                writeln!(stdin, "{line}").expect("write to oracle");
            }
            // Drop stdin -> EOF -> the oracle's read loop terminates.
        });
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let lines: Vec<String> = stdout
            .lines()
            .map(|l| l.expect("read oracle line"))
            .filter(|l| l.starts_with("OK ") || l.starts_with("REJECT ") || l.starts_with("ERR "))
            .collect();
        feeder.join().expect("stdin feeder thread");
        child.wait().expect("oracle exit");

        if lines.len() != requests.len() {
            eprintln!(
                "attempt {attempt}: oracle returned {} replies for {} requests — retrying",
                lines.len(),
                requests.len()
            );
            continue;
        }
        return lines
            .iter()
            .zip(requests)
            .map(|(line, req)| {
                if let Some(rest) = line.strip_prefix("OK ") {
                    let mut it = rest.split_whitespace();
                    Reply::Accept {
                        tree_hex: it.next().expect("tree hex").to_string(),
                        p2s: it.next().expect("p2s").to_string(),
                        p2sh: it.next().expect("p2sh").to_string(),
                    }
                } else if let Some(rest) = line.strip_prefix("REJECT ") {
                    let mut it = rest.split_whitespace();
                    Reply::Reject {
                        pos: it.next().expect("pos").to_string(),
                        class: it.next().unwrap_or("?").to_string(),
                    }
                } else {
                    panic!("oracle ERR for {} {:?}: {line}", req.verb, req.source);
                }
            })
            .collect();
    }
    panic!("oracle reply count never matched request count after 3 attempts");
}

/// Regenerate `compile_seed.json` from the live oracle and diff it against
/// the committed file (ignoring the `_captured` date). On drift the file is
/// refreshed on disk and the test fails so the change lands in git review.
#[test]
#[ignore = "live oracle recapture: needs scala-cli; run after editing golden_seed.txt or the corpus"]
fn compile_seed_live_recapture() {
    let requests = capture_requests();
    let replies = run_oracle_batch(&requests);

    let mut vectors: Vec<serde_json::Value> = Vec::new();
    let (mut seed_accepts, mut seed_rejects) = (0usize, 0usize);
    let (mut probe_accepts, mut probe_rejects) = (0usize, 0usize);
    let (mut corpus_fed, mut corpus_kept, mut corpus_rejected) = (0usize, 0usize, 0usize);
    for (req, reply) in requests.iter().zip(&replies) {
        let is_corpus = req.corpus_path.is_some();
        if is_corpus {
            corpus_fed += 1;
        }
        let mut record = serde_json::json!({
            "verb": req.verb,
            "source": req.source,
            "network": "testnet",
            "tree_version": req.tree_version,
        });
        let obj = record.as_object_mut().expect("record object");
        match reply {
            Reply::Accept {
                tree_hex,
                p2s,
                p2sh,
            } => {
                obj.insert("oracle".into(), "ACCEPT".into());
                obj.insert("tree_hex".into(), tree_hex.as_str().into());
                obj.insert("p2s_address".into(), p2s.as_str().into());
                obj.insert("p2sh_address".into(), p2sh.as_str().into());
                obj.insert("reject_class".into(), serde_json::Value::Null);
                if is_corpus {
                    corpus_kept += 1;
                } else if req.probe {
                    probe_accepts += 1;
                } else {
                    seed_accepts += 1;
                }
            }
            Reply::Reject { pos, class } => {
                if is_corpus {
                    // Brief step 2: corpus compile-REJECTs are counted in the
                    // `_source` note and excluded from the vector set.
                    corpus_rejected += 1;
                    continue;
                }
                if req.probe {
                    probe_rejects += 1;
                } else {
                    seed_rejects += 1;
                }
                obj.insert("oracle".into(), "REJECT".into());
                obj.insert("tree_hex".into(), serde_json::Value::Null);
                obj.insert("p2s_address".into(), serde_json::Value::Null);
                obj.insert("p2sh_address".into(), serde_json::Value::Null);
                obj.insert("reject_class".into(), class.as_str().into());
                obj.insert("reject_pos".into(), pos.as_str().into());
            }
        }
        if let Some(rel) = &req.corpus_path {
            obj.insert("corpus_path".into(), rel.as_str().into());
        }
        vectors.push(record);
    }

    let captured: String = String::from_utf8(
        std::process::Command::new("date")
            .arg("+%Y-%m-%d")
            .output()
            .expect("date")
            .stdout,
    )
    .expect("utf8 date")
    .trim()
    .to_string();
    let fresh = serde_json::json!({
        "_source": format!(
            "TyperOracle.scala cc/cce/ccs verbs, scala-cli sigma-state 6.0.2, \
             ORACLE_TREE_VERSION per-record (one oracle spawn per version) \
             ORACLE_NETWORK=testnet; golden_seed.txt \
             typecheck-ACCEPT sources: {} vectors ({} compile-ACCEPT, {} \
             compile-REJECT recorded verbatim); corpus: {} sources fed under \
             cc, {} compile-ACCEPT kept, {} compile-REJECT excluded (counted \
             here per the Task-10 brief); compile_probes.txt (Task-11 wave-1 \
             GraphBuilding gate): {} vectors ({} compile-ACCEPT, {} \
             compile-REJECT recorded verbatim)",
            seed_accepts + seed_rejects,
            seed_accepts,
            seed_rejects,
            corpus_fed,
            corpus_kept,
            corpus_rejected,
            probe_accepts + probe_rejects,
            probe_accepts,
            probe_rejects,
        ),
        "_format": "verb: cc|cce|ccs; oracle reply fields verbatim (never hand-edited); \
                    settings pinned per-record",
        "_captured": captured,
        "vectors": vectors,
    });

    let path = seed_json_path();
    let committed: Option<serde_json::Value> = std::fs::read_to_string(&path)
        .ok()
        .map(|raw| serde_json::from_str(&raw).expect("committed compile_seed.json is valid JSON"));

    // Diff everything EXCEPT the capture date (which changes every run).
    let strip_date = |v: &serde_json::Value| {
        let mut c = v.clone();
        c.as_object_mut().map(|o| o.remove("_captured"));
        c
    };
    let up_to_date = committed
        .as_ref()
        .map(|c| strip_date(c) == strip_date(&fresh))
        .unwrap_or(false);
    if !up_to_date {
        std::fs::create_dir_all(path.parent().expect("parent dir")).expect("mkdir");
        let mut pretty = serde_json::to_string_pretty(&fresh).expect("serialize");
        pretty.push('\n');
        std::fs::write(&path, pretty).expect("write compile_seed.json");
        panic!(
            "compile_seed.json was stale (or missing) — refreshed on disk at {}; \
             review the git diff, re-run the always-on gate, and commit",
            path.display()
        );
    }
}

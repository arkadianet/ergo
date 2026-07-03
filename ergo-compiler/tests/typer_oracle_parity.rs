//! Typer oracle parity — M2 differential battery + corpus typed-verdict gate.
//!
//! **Deliverable 1 — Curated battery (golden-seed sweep):**
//! Drive every committed `golden_seed.txt` record end-to-end through the PUBLIC
//! [`ergo_compiler::typecheck`] API (not internal `assign_type`):
//! - `OK` records (not in [`SWEEP_SKIP`]): assert `print_typed` byte-matches the
//!   committed s-expression.
//! - `REJECT` records: assert the compile fails + exception class matches.
//! - `SWEEP_SKIP` records: assert the compile ACCEPTS (verdict check only —
//!   M2 printer has known deviations for PK/demo-env GroupElement constants).
//! - v2-gate records (§6): run at `tree_version = 2`; assert REJECT MethodNotFound.
//!
//! This is the **single source of truth** for [`SWEEP_SKIP`]; the identical constant
//! in `typer/assign.rs::tests` has been removed to eliminate duplication.
//!
//! **Deliverable 2 — Gapcheck-mandated edge vectors (§16):**
//! The three new golden-seed §16 records (Task-9 mandate) are swept by the battery
//! above. Their specific assertions are also spelled out in
//! [`gap_check_edge_vectors`] for clarity.
//!
//! **Deliverable 3 — Corpus typed-verdict parity:**
//! All 79 M1-parse contracts from `test-vectors/ergoscript/corpus/` typechecked
//! through `typecheck(empty env, v3)` and compared against the committed JVM-oracle
//! verdicts in `test-vectors/ergoscript/typer/corpus_verdicts.json`:
//! - `corpus_typed_verdict_parity` (always-on): verdict (accept/reject) must match.
//!   Class matching is restricted to compiler-level exceptions
//!   (`ParserException`, `TyperException` family, `BinderException` family) that
//!   our implementation can reproduce; Java-runtime classes
//!   (`IllegalArgumentException`, `AssertionError`) are excluded from class matching
//!   since they are JVM-specific and not part of our error taxonomy.
//! - `corpus_live_oracle_parity` (#[ignore]): re-derives every verdict from the live
//!   JVM oracle and asserts it equals the committed `corpus_verdicts.json`.  Run it
//!   after updating the corpus to refresh the committed file.
//!
//! **SWEEP_SKIP — M3 rendering exclusions (single source of truth):**
//! Sources that ACCEPT typecheck but whose `print_typed` output deviates from the
//! oracle due to known M2 printer limitations.  Each entry is documented below.
//! Fix at M3: replace M2 hex placeholders with the decompressed `Ecp (x,y,1)` form.
//!
//! References:
//! - `test-vectors/ergoscript/typer/golden_seed.txt` — committed oracle captures
//! - `test-vectors/ergoscript/typer/corpus_verdicts.json` — JVM-oracle corpus runs
//! - `dev-docs/ergoscript-compiler-m2-typer-plan.md` §Task-9
//! - `scripts/jvm_typer_oracle/TyperOracle.scala` — the JVM oracle

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ergo_compiler::{
    print_typed, typecheck, typecheck_with_network, CompileError, EnvValue, GroupElement,
    NetworkPrefix, ScriptEnv,
};

// =============================================================================
// SWEEP_SKIP — single source of truth (M3-rendering exclusions).
// =============================================================================
//
// Sources in this list are excluded from **byte-comparison** in the golden-seed
// sweep.  They still typecheck (verdict ACCEPT is enforced by
// `seed_accept_skip_set_accepts`).  Each entry cites the deviation it represents
// and the M3 fix.
const SWEEP_SKIP: &[&str] = &[
    // D-T4 (lib.rs M2 deviation ledger): PK prints ProveDlog with an M2 hex
    // placeholder instead of the oracle's `(CSigmaProp (ProveDlog (Ecp @(x,y,1))))`.
    // Fix at M3: use the full decompressed form from `typed.rs` + `typed_print.rs`.
    "PK(\"3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN\")",
    // D-T4 (same): env.rs `lift` renders the 33-byte GroupElement key as a hex
    // placeholder (`<0x...>`), not the oracle's decompressed `Ecp (x,y,1)` form.
    // Records whose output contains demo-env GE constants (g1/g2) are affected.
    "proveDlog(g1)",
    "atLeast(1, Coll(proveDlog(g1)))",
    "allOf(Coll(proveDlog(g1)))",
    "g1.exp(n1)",
    "g1.negate",
    "g1.multiply(g2)",
    "proveDHTuple(g1, g2, g1, g2)",
];

// V2-gated sources: appear TWICE in the seed — once in §4 (v3 → OK) and once in
// §6 (v2 → REJECT MethodNotFound).  The batch reject-class sweep at v3 would
// wrongly pass (since v3 accepts); the v2 test is handled separately in
// `v2_gated_sources_reject_method_not_found`.
const V2_REJECT_SOURCES: &[&str] = &[
    "Global.fromBigEndianBytes[Long](a)",
    "Global.deserializeTo[Long](a)",
    "Global.none[Int]()",
];

// Sources with documented class deviations where the oracle class and Rust class
// differ but verdict parity (REJECT) holds.  Class checking is skipped for these.
//
// Deviations (golden_seed.txt §10/§13):
// - `PK(1)`: oracle=TyperException (Scala MatchError on non-String, caught by typer
//   harness); rust=InvalidArguments (binder-level type check on PK's argument).
// - `unsignedBigInt("-5")`: oracle=InvalidArguments (Scala irBuilder validates
//   non-negative at bind time); rust=TyperException (our typer validates the literal).
const CLASS_DEVIATION_SOURCES: &[&str] = &["PK(1)", "unsignedBigInt(\"-5\")"];

// =============================================================================
// Environment builders (mirrors TyperOracle.scala demo/sigmaTyperTest envs).
// =============================================================================

/// The secp256k1 generator point, SEC1-compressed.
/// Used for g1/g2 in both the demo env and the SigmaTyperTest env.
fn generator_ge() -> GroupElement {
    let mut bytes = [0u8; 33];
    bytes[0] = 0x02;
    let x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .expect("valid hex");
    bytes[1..].copy_from_slice(&x);
    GroupElement::from_bytes(bytes)
}

/// Demo env (`tce`): `a,b:Coll[Byte]; col1,col2:Coll[Long]; g1,g2:GroupElement;
/// n1:BigInt; bb1,bb2:Byte`.  Matches `TyperOracle.scala:demoEnv`.
fn demo_env() -> ScriptEnv {
    let ge = generator_ge();
    let mut env = ScriptEnv::new();
    env.insert("a", EnvValue::ByteArray(vec![1, 2]));
    env.insert("b", EnvValue::ByteArray(vec![3, 4]));
    env.insert("col1", EnvValue::LongArray(vec![1, 2]));
    env.insert("col2", EnvValue::LongArray(vec![3, 4]));
    env.insert("g1", EnvValue::GroupElement(ge));
    env.insert("g2", EnvValue::GroupElement(ge));
    env.insert("n1", EnvValue::BigInt("5".to_string()));
    env.insert("bb1", EnvValue::Byte(1));
    env.insert("bb2", EnvValue::Byte(2));
    env
}

/// SigmaTyperTest env (`tcs`): mirrors `LangTests.scala:52-69`.
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

/// Run `typecheck` with the verb's env and return the printed s-expr.
fn typecheck_verb(verb: &str, src: &str, tree_version: u8) -> Result<String, CompileError> {
    let env = match verb {
        "tc" => ScriptEnv::new(),
        "tce" => demo_env(),
        "tcs" => typer_test_env(),
        other => panic!("unknown seed verb {other:?}"),
    };
    // PK records use testnet addresses; everything else is network-independent.
    let network = if src.contains("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN") {
        NetworkPrefix::Testnet
    } else {
        NetworkPrefix::Mainnet
    };
    typecheck_with_network(&env, src, tree_version, network).map(|t| print_typed(&t))
}

/// Parse one golden-seed record from a tab-separated line.
/// Returns `(verb, source, expected_output)` or `None` for comment/empty lines.
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

/// Panics with a helpful message if `result` is `Ok`.
fn assert_err(result: Result<String, CompileError>, verb: &str, src: &str) -> CompileError {
    match result {
        Ok(printed) => panic!("expected REJECT for {verb} {src:?}, got OK: {printed}"),
        Err(e) => e,
    }
}

// =============================================================================
// Deliverable 1 + 2: Golden-seed battery.
// =============================================================================

/// Every `OK` record in the committed golden seed:
/// `typecheck(verb_env, src, v3)` must produce a printed s-expr byte-equal to
/// the committed oracle output, UNLESS the source is in [`SWEEP_SKIP`].
///
/// This is the single always-on sweep, replacing the `seed_accept_records_byte_match_oracle_v3`
/// test that was previously in `typer/assign.rs::tests`.  The guard at the end
/// ensures we exercise at least 85 accept records (adding §16 to §1..§15).
#[test]
fn seed_accept_records_byte_parity() {
    let seed = include_str!("../../test-vectors/ergoscript/typer/golden_seed.txt");
    let mut checked = 0usize;
    for line in seed.lines() {
        let Some((verb, src, expected)) = parse_seed_line(line) else {
            continue;
        };
        let Some(sexpr) = expected.strip_prefix("OK ") else {
            continue; // REJECT / ERR records handled elsewhere
        };
        if SWEEP_SKIP.contains(&src) {
            continue; // verdict checked by `seed_accept_skip_set_accepts`
        }
        let got = typecheck_verb(verb, src, 3)
            .unwrap_or_else(|e| panic!("expected OK for {verb} {src:?}, got reject: {e:?}"));
        assert_eq!(got, sexpr, "byte-parity mismatch for {verb} {src:?}");
        checked += 1;
    }
    // Guard: §16 adds 1 OK record (col1(0)+n1); previous floor was 80.
    assert!(
        checked >= 85,
        "swept only {checked} accept records — seed may have shrunk"
    );
}

/// Every `REJECT` record in the seed (except v2-gate duplicates in §6):
/// `typecheck(verb_env, src, v3)` must return an `Err` whose `class()` matches
/// the committed oracle exception class.
#[test]
fn seed_reject_records_class_parity() {
    let seed = include_str!("../../test-vectors/ergoscript/typer/golden_seed.txt");
    let mut checked = 0usize;
    for line in seed.lines() {
        let Some((verb, src, expected)) = parse_seed_line(line) else {
            continue;
        };
        let Some(rest) = expected.strip_prefix("REJECT ") else {
            continue; // OK / ERR records handled elsewhere
        };
        // §6 records are the SAME sources as §4 but at v2.
        // Running them at v3 would pass (they accept); skip them here.
        if V2_REJECT_SOURCES.contains(&src) {
            continue;
        }
        // rest = "<line>:<col> <ExClass>" or just "<line>:<col>" (rare)
        let ex_class = rest.split_whitespace().nth(1).unwrap_or("TyperException");
        let err = assert_err(typecheck_verb(verb, src, 3), verb, src);
        // Only assert class equality for compiler-level exceptions we can reproduce,
        // and skip documented class-deviation sources (golden_seed.txt §10).
        // Java-runtime exceptions (`Exception`, `AssertionError`, etc.) may map to a
        // more specific Rust class — these are documented deviations.
        if is_reproducible_class(ex_class) && !CLASS_DEVIATION_SOURCES.contains(&src) {
            assert_eq!(
                err.class(),
                ex_class,
                "class mismatch for {verb} {src:?}: oracle={ex_class} rust={}",
                err.class()
            );
        }
        checked += 1;
    }
    // 26 REJECT records − 3 V2_REJECT_SOURCES = 23 checked (plus future §N additions).
    assert!(
        checked >= 20,
        "swept only {checked} reject records — seed may have shrunk"
    );
}

/// Sources in [`SWEEP_SKIP`] still typecheck successfully (verdict ACCEPT).
/// We don't assert the printed form here (M2 rendering deviations are documented);
/// we only assert that the compile does not fail.
#[test]
fn seed_accept_skip_set_accepts() {
    // SWEEP_SKIP entries use the demo env (g1/g2/n1 references).
    // The PK entry uses testnet network.
    let sources = [
        ("tce", "proveDlog(g1)"),
        ("tce", "atLeast(1, Coll(proveDlog(g1)))"),
        ("tce", "allOf(Coll(proveDlog(g1)))"),
        ("tce", "g1.exp(n1)"),
        ("tce", "g1.negate"),
        ("tce", "g1.multiply(g2)"),
        ("tce", "proveDHTuple(g1, g2, g1, g2)"),
    ];
    for (verb, src) in sources {
        typecheck_verb(verb, src, 3)
            .unwrap_or_else(|e| panic!("SWEEP_SKIP source {src:?} must accept, got {e:?}"));
    }
    // PK testnet case (separate network call).
    let pk_src = "PK(\"3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN\")";
    typecheck_with_network(&ScriptEnv::new(), pk_src, 3, NetworkPrefix::Testnet)
        .unwrap_or_else(|e| panic!("PK SWEEP_SKIP source must accept, got {e:?}"));
}

/// V2-gate: the 3 sources in §6 REJECT at tree_version=2 with MethodNotFound.
/// (The same sources appear in §4 at v3 and ACCEPT; they are covered by the
/// byte-parity sweep above.)
#[test]
fn v2_gated_sources_reject_method_not_found() {
    let cases = [
        ("tce", "Global.fromBigEndianBytes[Long](a)"),
        ("tce", "Global.deserializeTo[Long](a)"),
        ("tc", "Global.none[Int]()"),
    ];
    for (verb, src) in cases {
        let err = assert_err(typecheck_verb(verb, src, 2), verb, src);
        assert_eq!(
            err.class(),
            "MethodNotFound",
            "v2 gate class for {verb} {src:?}"
        );
    }
}

// =============================================================================
// Deliverable 2: Gapcheck-mandated edge vectors (§16).
// =============================================================================

/// Task-9 gapcheck mandates (golden-seed §16).  These are also swept by
/// `seed_accept_records_byte_parity` / `seed_reject_records_class_parity`; the
/// inline assertions here serve as explicit documentation of each gap.
///
/// **E4 — empty containers (SBoolean, SString):**
/// Both `SBoolean` and `SString` are `SProduct` types with no declared methods.
/// `getMethod(SBoolean, "foo")` returns `None` → `MethodNotFound` (E4 confirms the
/// error is NOT the "non-product type" path, but the lookup-returns-None path).
///
/// **ByIndex/BigInt upcast-placement:**
/// Oracle confirms the Upcast wraps the ByIndex RESULT (§1.16 bimap path):
/// `col1(0)` → `ByIndex:Long`; `n1` → `BigInt`; both widened to BigInt → the Long
/// gets an `Upcast:BigInt` wrapper AROUND the ByIndex node (not inside it).
#[test]
fn gap_check_edge_vectors() {
    // E4: SBoolean has no methods → MethodNotFound (NOT "non-product").
    let err = typecheck(&ScriptEnv::new(), "true.foo", 3).expect_err("true.foo must reject");
    assert_eq!(
        err.class(),
        "MethodNotFound",
        "true.foo: expected MethodNotFound"
    );

    // E4: SString has no methods → MethodNotFound.
    let err = typecheck(&ScriptEnv::new(), r#""x".foo"#, 3).expect_err(r#""x".foo must reject"#);
    assert_eq!(
        err.class(),
        "MethodNotFound",
        r#""x".foo: expected MethodNotFound"#
    );

    // ByIndex/BigInt upcast-placement (oracle §16):
    // col1(0) → ByIndex:Long; adding n1:BigInt → numeric upcast via bimap.
    // The Upcast wraps the ByIndex RESULT (confirmed oracle: Upcast:BigInt(...ByIndex...)).
    // Refutes the cannonQ-harvest claim flagged CRITICAL in m2-gap.md check (d) —
    // oracle wraps the RESULT.
    let seed_expected = {
        let seed = include_str!("../../test-vectors/ergoscript/typer/golden_seed.txt");
        seed.lines()
            .filter_map(|l| parse_seed_line(l))
            .find(|(verb, src, exp)| {
                *verb == "tce" && *src == "col1(0) + n1" && exp.starts_with("OK ")
            })
            .map(|(_, _, exp)| exp.strip_prefix("OK ").unwrap().to_string())
            .expect("col1(0) + n1 seed record not found")
    };
    let got = typecheck_verb("tce", "col1(0) + n1", 3).expect("col1(0) + n1 must accept");
    assert_eq!(
        got, seed_expected,
        "ByIndex/BigInt upcast-placement mismatch"
    );
    // Structural: must contain Upcast:BigInt wrapping a ByIndex:Long.
    assert!(
        got.contains("(Upcast:BigInt (ByIndex:Long"),
        "Upcast must wrap ByIndex result: {got}"
    );

    // Bool↔SigmaProp coercion cells (verified by golden_seed §14 sweep above).
    // If exact-type reject (verified by golden_seed §11 sweep above).
    // ConcreteCollection no-widening (verified by golden_seed §11 sweep above).
    // Lambda annotation-required reject (verified by golden_seed §11 sweep above).
}

// Live re-derivation (disabled in CI; see module doc for how to run).
/// Re-derive every accept record from the live JVM oracle and assert byte parity.
/// `#[ignore]` — requires `scala-cli` on PATH + network for first run.
#[test]
#[ignore = "live oracle re-derivation: run manually after editing golden_seed.txt"]
fn seed_live_oracle_parity() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let seed = include_str!("../../test-vectors/ergoscript/typer/golden_seed.txt");
    let oracle_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("scripts/jvm_typer_oracle");

    let mut ordered: Vec<(String, String, String)> = Vec::new(); // (verb, src, expected_sexpr)
    for line in seed.lines() {
        let Some((verb, src, expected)) = parse_seed_line(line) else {
            continue;
        };
        if let Some(sexpr) = expected.strip_prefix("OK ") {
            if !SWEEP_SKIP.contains(&src) {
                ordered.push((verb.to_string(), src.to_string(), sexpr.to_string()));
            }
        }
    }

    let mut child = Command::new("scala-cli")
        .arg("run")
        .arg(&oracle_path)
        .env("ORACLE_TREE_VERSION", "3")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn scala-cli");

    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        for (verb, src, _) in &ordered {
            let hex = src
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            writeln!(stdin, "{verb} {hex}").expect("write");
        }
    }

    let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let live: Vec<String> = stdout
        .lines()
        .map(|l| l.expect("read line"))
        .filter(|l| l.starts_with("OK ") || l.starts_with("REJECT ") || l.starts_with("ERR "))
        .collect();
    child.wait().expect("oracle exit");

    assert_eq!(live.len(), ordered.len(), "oracle returned fewer verdicts");
    let mut divergences = Vec::new();
    for ((verb, src, committed), live_line) in ordered.iter().zip(&live) {
        let live_sexpr = live_line.strip_prefix("OK ").unwrap_or_else(|| {
            panic!("expected OK from live oracle for {verb} {src:?}, got {live_line}")
        });
        if live_sexpr != committed {
            divergences.push(format!("{verb} {src:?}: committed != live\n  committed: {committed}\n  live:      {live_sexpr}"));
        }
    }
    assert!(
        divergences.is_empty(),
        "{} live-oracle divergence(s):\n{}",
        divergences.len(),
        divergences.join("\n")
    );
}

// =============================================================================
// Deliverable 3: Corpus typed-verdict parity.
// =============================================================================

/// `<crate>/../test-vectors/ergoscript/corpus`.
fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors/ergoscript/corpus")
}

/// `<crate>/../test-vectors/ergoscript/typer/corpus_verdicts.json`.
fn corpus_typer_verdicts_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors/ergoscript/typer/corpus_verdicts.json")
}

/// All vendored `.es` files, keyed by corpus-relative forward-slash path.
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

/// Oracle verdict classes that our implementation can reproduce.
///
/// Java-runtime exceptions (`IllegalArgumentException`, `AssertionError`) and
/// Java's base `Exception` class are excluded: they are JVM-specific and cannot
/// be matched by our Rust error taxonomy.  Only compiler-level exception classes
/// (parser, typer, binder families) are checked for class parity.
fn is_reproducible_class(cls: &str) -> bool {
    matches!(
        cls,
        "ParserException"
            | "TyperException"
            | "MethodNotFound"
            | "NonApplicableMethod"
            | "InvalidBinaryOperationParameters"
            | "InvalidUnaryOperationParameters"
            | "NotImplementedError"
            | "InvalidArguments"
            | "BinderException"
            | "InvalidAddress"
    )
}

/// One oracle verdict from `corpus_verdicts.json`.
#[derive(Debug, Clone)]
struct CorpusVerdict {
    verdict: String,       // "accept" | "reject" | "error"
    class: Option<String>, // present iff verdict == "reject"
}

/// Load the committed `corpus_verdicts.json` (typer layer).
fn load_typer_verdicts() -> BTreeMap<String, CorpusVerdict> {
    let raw = std::fs::read_to_string(corpus_typer_verdicts_path())
        .expect("read corpus_verdicts.json (typer)");
    let json: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    let obj = json.as_object().expect("JSON object");
    obj.iter()
        .map(|(k, v)| {
            let verdict = v["verdict"].as_str().expect("verdict field").to_string();
            let class = v
                .get("class")
                .and_then(|c| c.as_str())
                .map(|s| s.to_string());
            (k.clone(), CorpusVerdict { verdict, class })
        })
        .collect()
}

/// Run `typecheck(empty env, src, v3)` using the same network as the JVM oracle.
///
/// The JVM oracle defaults to `ORACLE_NETWORK=testnet` (TyperOracle.scala:105-107),
/// so we must use testnet here to match.  This matters for `PK("3W...")` addresses:
/// testnet P2PK addresses succeed at bind time under testnet, whereas mainnet would
/// reject them with `InvalidAddress` before the typer even runs.
fn rust_typecheck_verdict(src: &str) -> Result<(), CompileError> {
    let env = ScriptEnv::new();
    typecheck_with_network(&env, src, 3, NetworkPrefix::Testnet).map(|_| ())
}

// =============================================================================
// Named allowlist for residual accept-invalid deviations.
// =============================================================================
//
// Each entry is (corpus-relative file path, deviation id from lib.rs).
// The test ASSERTS the divergence direction — oracle=reject AND rust=accept —
// so fixing a deviation here will cause a loud failure (rather than silently
// passing with wrong parity).
//
// Expected: empty after Fix round 1 (fromBase58/64 validation closes the 20
// real divergences; `deserialize` is not used in any corpus contract).
const KNOWN_ACCEPT_INVALID: &[(&str, &str)] = &[];

/// Every vendored corpus contract: `typecheck(empty env, v3)` verdict must
/// match the committed JVM-oracle verdict.
///
/// Verdict check: strict for all entries — oracle=reject MUST mean rust=reject.
/// Class check: only for compiler-level exceptions reproducible by our impl
/// (`is_reproducible_class`); Java-runtime classes (`IllegalArgumentException`,
/// `AssertionError`) are not asserted on class but ARE asserted on verdict.
///
/// A mismatch on verdict is a real bug (accept-invalid or reject-valid).
/// A mismatch on class for a reproducible exception class is also a real bug.
///
/// Residual accept-invalid deviations must be listed in `KNOWN_ACCEPT_INVALID`
/// with the lib.rs deviation id; each entry asserts the divergence direction so
/// that closing it later causes a loud test failure.
#[test]
fn corpus_typed_verdict_parity() {
    let files = corpus_files();
    let oracle = load_typer_verdicts();

    let file_keys: Vec<&String> = files.keys().collect();
    let oracle_keys: Vec<&String> = oracle.keys().collect();
    assert_eq!(
        file_keys, oracle_keys,
        "corpus files and corpus_verdicts.json keys must match 1:1"
    );
    assert!(!files.is_empty(), "corpus is empty");

    let mut divergences: Vec<String> = Vec::new();
    for (rel, src) in &files {
        let expected = &oracle[rel];
        let oracle_class = expected.class.as_deref();
        let result = rust_typecheck_verdict(src);
        let oracle_accepts = expected.verdict == "accept";
        let rust_accepts = result.is_ok();

        if oracle_accepts != rust_accepts {
            let rust_info = match &result {
                Ok(()) => "ACCEPT".to_string(),
                Err(e) => format!("REJECT {}", e.class()),
            };

            // Check if this is a known documented deviation.
            if let Some(&(_file, dev_id)) = KNOWN_ACCEPT_INVALID
                .iter()
                .find(|(f, _)| *f == rel.as_str())
            {
                // Assert the known direction: oracle=reject, rust=accept.
                // Closing this deviation later must fail loudly.
                assert!(
                    !oracle_accepts && rust_accepts,
                    "KNOWN_ACCEPT_INVALID entry {rel} ({dev_id}) no longer diverges \
                     in the expected direction — remove it from the allowlist. \
                     oracle={} rust={rust_info}",
                    expected.verdict
                );
                continue;
            }

            divergences.push(format!(
                "{rel}: verdict mismatch — oracle={} rust={rust_info}",
                expected.verdict
            ));
        } else if !rust_accepts {
            // Both reject: check class for reproducible exceptions.
            // Non-reproducible classes (AssertionError, IllegalArgumentException) are
            // NOT class-checked but their REJECT verdict is enforced above.
            if let Some(cls) = oracle_class {
                if is_reproducible_class(cls) {
                    let rust_class = result.unwrap_err().class();
                    if *cls != *rust_class {
                        divergences.push(format!(
                            "{rel}: class mismatch — oracle={cls} rust={rust_class}"
                        ));
                    }
                }
            }
        }
    }

    assert!(
        divergences.is_empty(),
        "{} corpus typed-verdict divergence(s):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}

/// Re-derive all corpus typed-verdicts from the live JVM oracle and assert
/// they equal the committed `corpus_verdicts.json`.  `#[ignore]` — requires
/// `scala-cli` on PATH + network (first run).  Run after updating the corpus:
///
/// ```text
/// cargo test -p ergo-compiler --test typer_oracle_parity -- --ignored --nocapture
/// ```
#[test]
#[ignore = "live oracle re-derivation: run manually after editing the corpus"]
fn corpus_live_oracle_parity() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    let files = corpus_files();
    let committed = load_typer_verdicts();
    let oracle_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("scripts/jvm_typer_oracle");

    let ordered: Vec<(&String, &String)> = files.iter().collect();

    let mut child = Command::new("scala-cli")
        .arg("run")
        .arg(&oracle_path)
        .env("ORACLE_TREE_VERSION", "3")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn scala-cli");

    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        for (_rel, src) in &ordered {
            let hex = src
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            writeln!(stdin, "tc {hex}").expect("write");
        }
    }

    let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let live_lines: Vec<String> = stdout
        .lines()
        .map(|l| l.expect("read line"))
        .filter(|l| l.starts_with("OK ") || l.starts_with("REJECT ") || l.starts_with("ERR "))
        .collect();
    child.wait().expect("oracle exit");

    assert_eq!(
        live_lines.len(),
        ordered.len(),
        "oracle returned {} verdicts for {} inputs",
        live_lines.len(),
        ordered.len()
    );

    let mut divergences = Vec::new();
    for ((rel, _src), live_line) in ordered.iter().zip(&live_lines) {
        let committed_v = &committed[*rel];
        let live_accepts = live_line.starts_with("OK ");
        let committed_accepts = committed_v.verdict == "accept";

        if live_accepts != committed_accepts {
            divergences.push(format!(
                "{rel}: committed={} live={live_line}",
                committed_v.verdict
            ));
        } else if !live_accepts {
            if let Some(live_class) = live_line.split_whitespace().nth(2) {
                if let Some(committed_class) = &committed_v.class {
                    if live_class != committed_class {
                        divergences.push(format!(
                            "{rel}: class committed={committed_class} live={live_class}"
                        ));
                    }
                }
            }
        }
    }
    assert!(
        divergences.is_empty(),
        "{} live-oracle divergence(s) — regenerate corpus_verdicts.json:\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}

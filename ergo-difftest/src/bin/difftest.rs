//! CLI campaign runner for the Ergo decoder fuzzer.
//!
//! Examples:
//!   difftest                                  # 100k iters, seed 1, all surfaces
//!   difftest --iters 1000000 --seed 7
//!   difftest --surface ergo_tree --iters 500000
//!   difftest --corpus test-vectors/mainnet    # mutate real wire bytes (raw files)
//!   difftest --repro 1b1501040a...            # run one hex input through all surfaces
//!   difftest --repro 00938503 --surface ergo_tree --check-canonical 00938503
//!                                             # hermetic canonical-bytes gate (known-bug re-injection)

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use ergo_difftest::{from_hex, run_campaign, run_input, Outcome};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut seed: u64 = 1;
    let mut iters: u64 = 100_000;
    let mut only: Option<String> = None;
    let mut corpus_dir: Option<String> = None;
    let mut repro: Option<String> = None;
    let mut oracle_mode = false;
    let mut oracle_script: Option<String> = None;
    let mut methodcall_mode = false;
    let mut structured_mode = false;
    let mut check_canonical: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                seed = parse_next(&args, &mut i, "--seed");
            }
            "--iters" => {
                iters = parse_next(&args, &mut i, "--iters");
            }
            "--surface" => {
                only = Some(take_next(&args, &mut i, "--surface"));
            }
            "--corpus" => {
                corpus_dir = Some(take_next(&args, &mut i, "--corpus"));
            }
            "--repro" => {
                repro = Some(take_next(&args, &mut i, "--repro"));
            }
            "--oracle" => {
                oracle_mode = true;
            }
            "--oracle-script" => {
                oracle_script = Some(take_next(&args, &mut i, "--oracle-script"));
            }
            "--check-canonical" => {
                check_canonical = Some(take_next(&args, &mut i, "--check-canonical"));
            }
            "--methodcall" => {
                methodcall_mode = true;
            }
            "--structured" => {
                structured_mode = true;
            }
            "--selftest" => {
                return match ergo_difftest::selftest() {
                    Ok(()) => {
                        println!("selftest: ok");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("selftest: FAILED: {e}");
                        ExitCode::FAILURE
                    }
                };
            }
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_help();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    // Reject a misspelled/unsupported --surface so a typo can't silently run zero
    // checks and look clean. `--oracle` (campaign OR repro) uses the oracle
    // surfaces (a comparable subset, plus the oracle-only `reduce` surface); the
    // hermetic paths use the hermetic registry. Both `--repro` modes follow their
    // selected execution mode below, so oracle-only surfaces stay replayable.
    if let Some(s) = &only {
        let known: Vec<&str> = if structured_mode && !oracle_mode {
            ergo_difftest::gen::SURFACES.to_vec()
        } else if oracle_mode {
            ergo_difftest::oracle::oracle_surfaces()
                .iter()
                .map(|spec| spec.name)
                .collect()
        } else {
            ergo_difftest::surfaces::names()
        };
        if !known.contains(&s.as_str()) {
            eprintln!(
                "--surface: unknown surface {s:?}; known: {}",
                known.join(", ")
            );
            return ExitCode::from(2);
        }
    }

    // --repro: triage a single input and exit. Under `--oracle` it replays the one
    // input against the JVM oracle (so a `reduce` finding can be reproduced from
    // the CLI); otherwise it runs the hermetic decoders.
    if let Some(hex) = repro {
        let Some(bytes) = from_hex(&hex) else {
            eprintln!("--repro: not valid hex");
            return ExitCode::from(2);
        };

        // --check-canonical <expected_hex>: hermetic known-bug re-injection gate.
        // Decodes the input as an ErgoTree, re-encodes it, and compares the result
        // to the pinned expected canonical bytes.  Exit 0 = bytes match (no bug);
        // exit 1 = mismatch (bug detected).  Hermetic: no JVM required.
        if let Some(ref expected_hex) = check_canonical {
            return run_check_canonical(&bytes, expected_hex);
        }

        if oracle_mode {
            return run_oracle_repro(&bytes, oracle_script, only.as_deref());
        }
        let mut any_bug = false;
        for (name, outcome) in run_input(&bytes, only.as_deref()) {
            match outcome {
                Outcome::Bug(detail) => {
                    any_bug = true;
                    println!("  [BUG]  {name}: {detail}");
                }
                o => println!("  [{:>13?}]  {name}", o),
            }
        }
        return if any_bug {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
    }

    if methodcall_mode {
        return run_methodcall(oracle_script);
    }

    let corpus = match &corpus_dir {
        Some(dir) => load_corpus(dir),
        None => Vec::new(),
    };

    if structured_mode {
        if oracle_mode {
            return run_oracle(seed, iters, oracle_script, only.as_deref(), &corpus, true);
        }
        return run_structured(seed, iters, only.as_deref());
    }

    if oracle_mode {
        return run_oracle(seed, iters, oracle_script, only.as_deref(), &corpus, false);
    }

    println!(
        "difftest: seed={seed} iters={iters} surface={} corpus={} seeds",
        only.as_deref().unwrap_or("ALL"),
        corpus.len()
    );

    let (stats, findings) = run_campaign(seed, iters, only.as_deref(), &corpus, false);

    println!(
        "runs={} accepted={} rejected={} write_rejected={} bugs={}",
        stats.iters, stats.accepted, stats.rejected, stats.write_rejected, stats.bugs
    );

    if findings.is_empty() {
        println!("no invariant violations");
        return ExitCode::SUCCESS;
    }

    println!("\n{} finding(s):", findings.len());
    for f in &findings {
        println!(
            "  {} @ seed={} iter={}\n    {}\n    repro: difftest --repro {}",
            f.surface, f.seed, f.iter, f.detail, f.input_hex
        );
    }
    ExitCode::FAILURE
}

/// Hermetic canonical-bytes gate for the known-bug re-injection harness.
///
/// Decodes `input` as an ErgoTree via `read_ergo_tree`, re-encodes it via
/// `write_ergo_tree`, and compares the hex of the result to `expected_hex`.
///
/// Exit 0 — bytes match: the encoder is correct (no bug present).
/// Exit 1 — mismatch: the encoder diverges from canonical (bug detected).
///
/// This exercises the canonical class of bugs (e.g. relation2-0x85-noncanonical)
/// hermetically — no JVM oracle required.
fn run_check_canonical(input: &[u8], expected_hex: &str) -> ExitCode {
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::ergo_tree::{read_ergo_tree, write_ergo_tree};

    let mut r = VlqReader::new(input);
    let tree = match read_ergo_tree(&mut r) {
        Ok(t) => t,
        Err(e) => {
            println!(
                "[CANONICAL-GATE] SKIP: input rejected by read_ergo_tree — cannot check canonical form ({e:?})"
            );
            // A rejection on clean HEAD means the trigger_hex is bad.
            // We exit 0 so the gate (which expects exit 0 on clean HEAD)
            // isn't tripped by an unusable trigger, but the SKIP makes it
            // visible.  The re-injection path will also fail at this step
            // if the bugged code also rejects — meaning the class is wrong.
            return ExitCode::SUCCESS;
        }
    };

    let mut w = VlqWriter::new();
    if let Err(e) = write_ergo_tree(&mut w, &tree) {
        eprintln!("[CANONICAL-GATE] write_ergo_tree failed: {e:?}");
        return ExitCode::FAILURE;
    }
    let actual_hex: String = w.result().iter().map(|b| format!("{b:02x}")).collect();

    if actual_hex == expected_hex {
        println!("[CANONICAL-GATE] PASS: re-encoded = {actual_hex}");
        ExitCode::SUCCESS
    } else {
        println!(
            "[CANONICAL-GATE] FAIL: re-encoded != expected\n  got:      {actual_hex}\n  expected: {expected_hex}"
        );
        ExitCode::FAILURE
    }
}

/// Print the failing probes of a pass, showing the oracle vs node verdicts.
fn print_fails(probes: &[ergo_difftest::methodcall::Probe]) {
    for p in probes.iter().filter(|p| !p.ok) {
        println!(
            "  [FAIL] ({}, {}) {} -> oracle={} node={}",
            p.type_id, p.method_id, p.name, p.oracle, p.rust
        );
    }
}

/// MethodCall typechecker-registry verification harness: construct a
/// MethodCall-root tree for every `(type_id, method_id)` and classify its root
/// against the JVM oracle (`mc_root`). See `ergo_difftest::methodcall`.
fn run_methodcall(script: Option<String>) -> ExitCode {
    use ergo_difftest::methodcall;
    use ergo_difftest::oracle::Oracle;

    let script = script.unwrap_or_else(|| "scripts/jvm_serde_oracle/ErgoSerdeOracle.scala".into());
    eprintln!("methodcall: spawning `scala-cli run {script}` (first query resolves deps)...");
    let mut oracle = match Oracle::spawn(&script) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("methodcall: spawn failed: {e}\n(is scala-cli on PATH?)");
            return ExitCode::FAILURE;
        }
    };

    let report = match methodcall::run(&mut oracle) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("methodcall: oracle pipe error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // SELF pass: tally verdicts; any SIGMA is a FAIL (an unconditionally-SigmaProp
    // method, which must not exist).
    let mut sigma = 0u32;
    let mut wrap = 0u32;
    // Everything else: THROW *or* WRAPOTHER (a non-rule-1001 wrap), both of which
    // are construction failures — hence `other`, not `throw`.
    let mut other = 0u32;
    for p in &report.self_pass {
        match p.oracle.as_str() {
            "SIGMA" => sigma += 1,
            "WRAP" => wrap += 1,
            _ => other += 1,
        }
    }
    println!(
        "SELF pass ({} methods, wrong-type receiver): WRAP={wrap} OTHER={other} SIGMA={sigma} (all must WRAP, node==oracle)",
        report.self_pass.len()
    );
    print_fails(&report.self_pass);

    println!(
        "landmine pass ({} type-variable methods, SigmaProp receiver): all must answer SIGMA (node==oracle)",
        report.landmine_pass.len()
    );
    for p in &report.landmine_pass {
        let mark = if p.ok { "ok" } else { "FAIL" };
        println!(
            "  [{mark}] ({}, {}) {} -> oracle={} node={}",
            p.type_id, p.method_id, p.name, p.oracle, p.rust
        );
    }

    // Wrapper pass: count and only print FAILs (a polymorphic method that becomes
    // SigmaProp but is not a known landmine, or a node/oracle disagreement).
    let wrap_ok = report.wrapper_pass.iter().filter(|p| p.ok).count();
    println!(
        "wrapper pass ({} other type-variable methods, type var -> SigmaProp): {wrap_ok} WRAP & node==oracle, must be all",
        report.wrapper_pass.len()
    );
    print_fails(&report.wrapper_pass);

    let failures = report.failures();
    if failures == 0 {
        println!(
            "methodcall: OK — node agrees with the JVM oracle on all {} probes; no method is unconditionally SigmaProp; exactly the {} landmines are SigmaProp-capable",
            report.self_pass.len() + report.landmine_pass.len() + report.wrapper_pass.len(),
            report.landmine_pass.len()
        );
        ExitCode::SUCCESS
    } else {
        println!("methodcall: {failures} FAILURE(s)");
        ExitCode::FAILURE
    }
}

/// Hermetic STRUCTURED campaign: run [`ergo_difftest::run_structured_campaign`]
/// and print the no-panic / fixed-point stats PLUS the per-surface adversarial-
/// feature coverage union and ratio. The coverage report is the point of this
/// mode — it proves each surface's generator reaches every declared bug surface.
fn run_structured(seed: u64, iters: u64, only: Option<&str>) -> ExitCode {
    use ergo_difftest::run_structured_campaign;

    println!(
        "difftest: STRUCTURED seed={seed} iters={iters} surface={}",
        only.unwrap_or("ALL"),
    );

    let (stats, coverage, findings) = run_structured_campaign(seed, iters, only, &[]);

    println!(
        "runs={} accepted={} rejected={} write_rejected={} bugs={}",
        stats.iters, stats.accepted, stats.rejected, stats.write_rejected, stats.bugs
    );

    println!("\ncoverage (touched / declared adversarial features per surface):");
    for c in &coverage.0 {
        let touched = c.touched.intersect(&c.declared);
        println!(
            "  {:<20} {:>2}/{:<2}  ratio={:.2}",
            c.surface,
            touched.len(),
            c.declared.len(),
            c.ratio(),
        );
        for f in c.declared.iter() {
            let mark = if c.touched.contains(f) {
                "+"
            } else {
                "MISSING"
            };
            let bug = f.bug_id().map(|b| format!(" [{b}]")).unwrap_or_default();
            println!("      {mark:<7} {}{bug}", f.name());
        }
    }

    let total_touched = coverage.total_touched();
    let total_declared = coverage.total_declared();
    println!(
        "\nunion: {}/{} declared features reached across all surfaces",
        total_touched.intersect(&total_declared).len(),
        total_declared.len(),
    );

    if !findings.is_empty() {
        println!("\n{} finding(s):", findings.len());
        for f in &findings {
            println!(
                "  {} @ seed={} iter={}\n    {}\n    repro: difftest --repro {}",
                f.surface, f.seed, f.iter, f.detail, f.input_hex
            );
        }
        return ExitCode::FAILURE;
    }
    println!("\nno invariant violations");
    ExitCode::SUCCESS
}

/// Differential campaign against the JVM reference oracle. Without `only` it
/// diffs every oracle surface per input; with `only` it restricts to that one
/// (already validated against the oracle surface set in `main`). When
/// `structured` is set, each surface is fed bytes from
/// [`ergo_difftest::gen::gen_structured`] targeted at that surface (the `reduce`
/// surface, which consumes ErgoTree bytes, is fed the `ergo_tree` generator);
/// otherwise a single shared input is diffed across every surface.
fn run_oracle(
    seed: u64,
    iters: u64,
    script: Option<String>,
    only: Option<&str>,
    corpus: &[Vec<u8>],
    structured: bool,
) -> ExitCode {
    use ergo_difftest::oracle::{diff, oracle_surfaces, Oracle};
    use ergo_difftest::rng::Rng;

    let script = script.unwrap_or_else(|| "scripts/jvm_serde_oracle/ErgoSerdeOracle.scala".into());
    eprintln!(
        "oracle: spawning `scala-cli run {script}` (first run resolves deps, may take ~1 min)..."
    );
    let mut oracle = match Oracle::spawn(&script) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("oracle: spawn failed: {e}\n(is scala-cli on PATH?)");
            return ExitCode::FAILURE;
        }
    };

    let surfaces: Vec<_> = oracle_surfaces()
        .into_iter()
        .filter(|spec| only.is_none_or(|o| spec.name == o))
        .collect();
    let mut rng = Rng::new(seed);
    // Dedup by root-cause signature so a soak reports unique CLASSES (with a
    // count + one representative), not thousands of instances of the same bug.
    let mut classes: std::collections::HashMap<String, (u64, ergo_difftest::oracle::Divergence)> =
        std::collections::HashMap::new();
    let mut total = 0u64;
    let mut checked = 0u64;
    'outer: for iter in 0..iters {
        // Non-structured: one shared input diffed across every surface.
        // Structured: per-surface targeted bytes (generated inside the loop).
        let shared_input = if structured {
            Vec::new()
        } else {
            ergo_difftest::generate::gen_input(&mut rng, corpus)
        };
        for spec in &surfaces {
            let input: Vec<u8> = if structured {
                structured_oracle_bytes(seed, iter, spec.name)
            } else {
                shared_input.clone()
            };
            match diff(spec, &input, &mut oracle) {
                Ok(None) => {}
                Ok(Some(d)) => {
                    total += 1;
                    classes
                        .entry(divergence_signature(&d))
                        .and_modify(|e| e.0 += 1)
                        .or_insert((1, d));
                }
                Err(e) => {
                    eprintln!("oracle: pipe error after {checked} checks: {e}");
                    break 'outer;
                }
            }
            checked += 1;
        }
        if checked.is_multiple_of(50_000) {
            eprintln!(
                "oracle: {checked} checks, {} unique class(es), {total} total",
                classes.len()
            );
        }
    }

    println!(
        "oracle: checks={checked} surfaces={} unique_classes={} total_divergences={total}",
        surfaces.len(),
        classes.len(),
    );
    if classes.is_empty() {
        println!("node and JVM reference agree on all checked inputs");
        return ExitCode::SUCCESS;
    }
    let mut sorted: Vec<_> = classes.into_values().collect();
    sorted.sort_by_key(|(count, _)| std::cmp::Reverse(*count));
    for (count, d) in &sorted {
        println!(
            "  [{:?}] {} (x{count})\n    rust={:?}\n    jvm ={:?}\n    repro: difftest --repro {}",
            d.kind, d.surface, d.rust, d.jvm, d.input_hex
        );
    }
    ExitCode::FAILURE
}

/// Replay a SINGLE input against the JVM oracle (the `--oracle --repro` path), so
/// a campaign finding — including an oracle-only surface like `reduce` — can be
/// reproduced and triaged from the CLI. Diffs every oracle surface (or just
/// `only`) for the one input and prints the node vs JVM verdicts.
fn run_oracle_repro(bytes: &[u8], script: Option<String>, only: Option<&str>) -> ExitCode {
    use ergo_difftest::oracle::{diff, oracle_surfaces, Oracle};

    let script = script.unwrap_or_else(|| "scripts/jvm_serde_oracle/ErgoSerdeOracle.scala".into());
    eprintln!(
        "oracle: spawning `scala-cli run {script}` (first run resolves deps, may take ~1 min)..."
    );
    let mut oracle = match Oracle::spawn(&script) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("oracle: spawn failed: {e}\n(is scala-cli on PATH?)");
            return ExitCode::FAILURE;
        }
    };

    let surfaces: Vec<_> = oracle_surfaces()
        .into_iter()
        .filter(|spec| only.is_none_or(|o| spec.name == o))
        .collect();
    let mut any_divergence = false;
    for spec in &surfaces {
        match diff(spec, bytes, &mut oracle) {
            Ok(None) => println!("  [{:>13}]  {}", "agree", spec.name),
            Ok(Some(d)) => {
                any_divergence = true;
                println!(
                    "  [{:?}] {}\n    rust={:?}\n    jvm ={:?}",
                    d.kind, spec.name, d.rust, d.jvm
                );
            }
            Err(e) => {
                eprintln!("oracle: pipe error on surface {}: {e}", spec.name);
                return ExitCode::FAILURE;
            }
        }
    }
    if any_divergence {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Structured bytes for an ORACLE surface. Maps the oracle surface name onto a
/// gen surface (the `reduce` surface consumes ErgoTree bytes, so it is fed the
/// `ergo_tree` generator; an oracle surface with no matching gen surface also
/// falls back to `ergo_tree`), then returns [`ergo_difftest::gen::gen_structured_at`].
fn structured_oracle_bytes(seed: u64, iter: u64, oracle_surface: &str) -> Vec<u8> {
    let gen_surface = if ergo_difftest::gen::SURFACES.contains(&oracle_surface) {
        oracle_surface
    } else {
        "ergo_tree"
    };
    ergo_difftest::gen::gen_structured_at(seed, iter, gen_surface).bytes
}

/// Root-cause signature for deduping divergences: surface + kind + each side's
/// verdict class (the JVM error class distinguishes reject causes).
fn divergence_signature(d: &ergo_difftest::oracle::Divergence) -> String {
    use ergo_difftest::oracle::Verdict;
    let cls = |v: &Verdict| match v {
        Verdict::Accept(_) => "accept".to_string(),
        Verdict::Reject(e) => format!("reject:{}", e.split_whitespace().next().unwrap_or("")),
        Verdict::Err(_) => "err".to_string(),
    };
    format!(
        "{}|{:?}|rust={}|jvm={}",
        d.surface,
        d.kind,
        cls(&d.rust),
        cls(&d.jvm)
    )
}

fn parse_next(args: &[String], i: &mut usize, flag: &str) -> u64 {
    let v = take_next(args, i, flag);
    v.parse().unwrap_or_else(|_| {
        eprintln!("{flag}: expected an integer, got {v:?}");
        std::process::exit(2);
    })
}

fn take_next(args: &[String], i: &mut usize, flag: &str) -> String {
    *i += 1;
    args.get(*i).cloned().unwrap_or_else(|| {
        eprintln!("{flag}: missing value");
        std::process::exit(2);
    })
}

/// Load seed bytes from every regular file in `dir`:
/// * `.hex` — the whole file is one hex string,
/// * `.json` — every quoted hex string (≥ 8 hex chars) is extracted as a seed
///   (covers the `bytes`/`ergoTree`/register hex fields in the test vectors),
/// * anything else — raw bytes.
///
/// A mixed real-wire-bytes corpus is good: mutations of real trees, boxes, and
/// constants exercise every oracle surface near the valid manifold.
fn load_corpus(dir: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(Path::new(dir)) else {
        eprintln!("--corpus: cannot read directory {dir}");
        return out;
    };
    for e in entries.flatten() {
        let path = e.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
        match ext {
            "hex" => {
                if let Ok(data) = fs::read(&path) {
                    if let Some(b) = from_hex(&String::from_utf8_lossy(&data)) {
                        out.push(b);
                    }
                }
            }
            "json" => {
                if let Ok(text) = fs::read_to_string(&path) {
                    out.extend(extract_hex_strings(&text));
                }
            }
            "txt" | "md" => {}
            _ => {
                if let Ok(data) = fs::read(&path) {
                    out.push(data);
                }
            }
        }
    }
    out
}

/// Pull every quoted, even-length hex string of ≥ 8 chars out of JSON text.
fn extract_hex_strings(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for chunk in text.split('"') {
        let len = chunk.len();
        if len >= 8 && len.is_multiple_of(2) && chunk.bytes().all(|b| b.is_ascii_hexdigit()) {
            if let Some(b) = from_hex(chunk) {
                out.push(b);
            }
        }
    }
    out
}

fn print_help() {
    eprintln!(
        "difftest — Ergo decoder invariant fuzzer\n\
         \n\
         OPTIONS:\n\
         \x20 --seed N         PRNG seed (default 1)\n\
         \x20 --iters N        iterations (default 100000)\n\
         \x20 --surface NAME   restrict to one surface\n\
         \x20 --corpus DIR     mutate raw seed files in DIR\n\
         \x20 --repro HEX      run a single hex input through all surfaces\n\
         \x20 --check-canonical HEX  hermetic canonical-bytes gate (requires --repro)\n\
         \x20 --oracle         differential campaign vs the JVM reference (ergo_tree)\n\
         \x20 --oracle-script P  path to ErgoSerdeOracle.scala\n\
         \x20 --methodcall     verify the MethodCall typechecker registry vs the JVM oracle\n\
         \x20 --structured     structure-aware generators + per-surface coverage report\n\
         \x20                  (combine with --oracle to diff structured bytes vs the JVM)\n\
         \x20 --selftest       verify the harness's own bug-detection has teeth\n"
    );
}

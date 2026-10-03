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

use std::path::Path;
use std::process::ExitCode;
use std::{fs, io};

use ergo_difftest::{from_hex, run_campaign, run_input, Outcome};

/// Exit code for a HARNESS/ORACLE failure, distinct from both "clean" (0) and
/// "divergences found" (1) so a caller can tell "nothing was wrong" from
/// "nothing was checked". Usage errors keep code 2.
const EXIT_HARNESS_ERROR_CODE: u8 = 3;

/// [`EXIT_HARNESS_ERROR_CODE`] as an [`ExitCode`] (`ExitCode::from` is not const).
fn exit_harness_error() -> ExitCode {
    ExitCode::from(EXIT_HARNESS_ERROR_CODE)
}

/// Marker every oracle-pipe failure is printed with, so a wrapper script can
/// grep a log for it even when it only has the log (not the exit code).
const ORACLE_ERROR_MARKER: &str = "oracle: HARNESS ERROR:";

/// Upper bound on `--iters`. `iters` is user-controlled up to `u64::MAX`, and
/// `run_oracle`'s planned-check-count report multiplies it by the surface
/// count; this bound (plus computing that product in `u128`, belt-and-
/// suspenders) keeps the multiplication overflow-free and rejects a typo'd
/// extra zero rather than starting a campaign that would run for millennia.
const MAX_ITERS: u64 = 1_000_000_000_000;

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
    let mut minimize_mode = false;
    let mut regressions_dir: Option<String> = None;
    let mut min_coverage: Option<f64> = None;
    let mut selftest_mode = false;

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
            "--minimize" => {
                minimize_mode = true;
            }
            "--regressions-dir" => {
                regressions_dir = Some(take_next(&args, &mut i, "--regressions-dir"));
            }
            "--min-coverage" => {
                let v = take_next(&args, &mut i, "--min-coverage");
                min_coverage = Some(v.parse().unwrap_or_else(|_| {
                    eprintln!("--min-coverage: expected a float in 0.0..=1.0, got {v:?}");
                    std::process::exit(2);
                }));
            }
            "--selftest" => selftest_mode = true,
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

    if selftest_mode {
        if args.len() != 1 {
            eprintln!("--selftest must be used alone");
            return ExitCode::from(2);
        }
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
    if let Some(threshold) = min_coverage {
        if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
            eprintln!("--min-coverage: expected a finite float in 0.0..=1.0");
            return ExitCode::from(2);
        }
        if !structured_mode || oracle_mode || repro.is_some() || methodcall_mode {
            eprintln!("--min-coverage requires a hermetic --structured campaign");
            return ExitCode::from(2);
        }
    }
    if iters == 0 && repro.is_none() && !methodcall_mode {
        eprintln!("--iters must be positive for a campaign");
        return ExitCode::from(2);
    }
    if minimize_mode && !oracle_mode {
        eprintln!("--minimize requires --oracle");
        return ExitCode::from(2);
    }
    if oracle_script.is_some() && !oracle_mode && !methodcall_mode {
        eprintln!("--oracle-script requires --oracle or --methodcall");
        return ExitCode::from(2);
    }
    if regressions_dir.is_some() && (!oracle_mode || !minimize_mode) {
        eprintln!("--regressions-dir requires --oracle --minimize");
        return ExitCode::from(2);
    }
    if methodcall_mode && (oracle_mode || structured_mode || repro.is_some() || minimize_mode) {
        eprintln!("--methodcall cannot be combined with other execution modes");
        return ExitCode::from(2);
    }
    if corpus_dir.is_some() && (structured_mode || repro.is_some() || methodcall_mode) {
        eprintln!("--corpus is only used by byte-mutation campaigns");
        return ExitCode::from(2);
    }
    if oracle_mode && structured_mode && repro.is_none() {
        let unsupported: Vec<_> = ergo_difftest::oracle::oracle_surfaces()
            .into_iter()
            .filter(|spec| only.as_deref().is_none_or(|name| spec.name == name))
            .filter(|spec| structured_oracle_surface(spec.name).is_none())
            .map(|spec| spec.name)
            .collect();
        if !unsupported.is_empty() {
            eprintln!("--structured --oracle: no matching framed generator for {}; select a supported --surface", unsupported.join(", "));
            return ExitCode::from(2);
        }
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

    // Reject an absurd --iters before it reaches the planned-check-count math
    // (`iters * surfaces.len()` in `run_oracle`): `iters` is user-controlled up
    // to u64::MAX, and a naive u64 multiply there would panic in debug and
    // silently wrap in release. MAX_ITERS keeps that product comfortably inside
    // u128 (belt-and-suspenders alongside the u128 cast in `run_oracle`) and
    // rejects a typo'd extra zero rather than starting a campaign that would
    // run for millennia.
    if iters > MAX_ITERS {
        eprintln!("--iters: {iters} exceeds the maximum of {MAX_ITERS}");
        return ExitCode::from(2);
    }

    // `--check-canonical` only takes effect inside the `--repro` path below;
    // without `--repro` it would silently no-op, so reject that combination.
    if check_canonical.is_some() && repro.is_none() {
        eprintln!("--check-canonical requires --repro <hex>");
        return ExitCode::from(2);
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
            if minimize_mode {
                let surface = only.as_deref().unwrap_or_else(|| {
                    eprintln!("--repro --oracle --minimize requires --surface <s>");
                    std::process::exit(2);
                });
                let reg_dir = regressions_dir
                    .as_deref()
                    .unwrap_or("ergo-difftest/regressions");
                return run_oracle_repro_minimize(
                    &bytes,
                    oracle_script,
                    surface,
                    std::path::Path::new(reg_dir),
                );
            }
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
        Some(dir) => match load_corpus(dir) {
            Ok(corpus) => corpus,
            Err(error) => {
                eprintln!("{ORACLE_ERROR_MARKER} --corpus {dir:?}: {error}");
                return exit_harness_error();
            }
        },
        None => Vec::new(),
    };

    if structured_mode {
        if oracle_mode {
            let reg_dir = regressions_dir
                .as_deref()
                .unwrap_or("ergo-difftest/regressions");
            return run_oracle(
                seed,
                iters,
                oracle_script,
                only.as_deref(),
                &corpus,
                true,
                minimize_mode,
                std::path::Path::new(reg_dir),
            );
        }
        return run_structured(seed, iters, only.as_deref(), min_coverage);
    }

    if oracle_mode {
        let reg_dir = regressions_dir
            .as_deref()
            .unwrap_or("ergo-difftest/regressions");
        return run_oracle(
            seed,
            iters,
            oracle_script,
            only.as_deref(),
            &corpus,
            false,
            minimize_mode,
            std::path::Path::new(reg_dir),
        );
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

    let Some(expected) = from_hex(expected_hex) else {
        eprintln!("--check-canonical: expected valid hex");
        return ExitCode::from(2);
    };
    let expected_hex = ergo_difftest::to_hex(&expected);
    let mut r = VlqReader::new(input);
    let tree = match read_ergo_tree(&mut r) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[CANONICAL-GATE] HARNESS ERROR: input rejected; canonical form was not checked ({e:?})");
            return exit_harness_error();
        }
    };

    if r.remaining() != 0 {
        eprintln!("[CANONICAL-GATE] HARNESS ERROR: trailing input bytes");
        return exit_harness_error();
    }
    let mut w = VlqWriter::new();
    if let Err(e) = write_ergo_tree(&mut w, &tree) {
        eprintln!("[CANONICAL-GATE] HARNESS ERROR: write_ergo_tree failed: {e:?}");
        return exit_harness_error();
    }
    let actual_hex = ergo_difftest::to_hex(&w.result());

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
/// mode measures the declared constructor labels reached; it does not prove
/// execution coverage or known-bug rediscovery.
///
/// If `min_coverage` is `Some(threshold)`, the binary exits non-zero when the
/// overall union coverage ratio (touched / declared across all surfaces) is
/// below `threshold`. This is the machine-checkable CI gate.
fn run_structured(
    seed: u64,
    iters: u64,
    only: Option<&str>,
    min_coverage: Option<f64>,
) -> ExitCode {
    use ergo_difftest::run_structured_campaign;

    println!(
        "difftest: STRUCTURED seed={seed} iters={iters} surface={}{}",
        only.unwrap_or("ALL"),
        min_coverage
            .map(|m| format!(" min-coverage={m:.2}"))
            .unwrap_or_default(),
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
    let total_declared_count = total_declared.len();
    let union_reached = total_touched.intersect(&total_declared).len();
    let union_ratio = if total_declared_count > 0 {
        union_reached as f64 / total_declared_count as f64
    } else {
        1.0
    };
    println!(
        "\nunion: {union_reached}/{total_declared_count} declared features reached across all surfaces  ratio={union_ratio:.3}",
    );

    // ── Coverage gate ──────────────────────────────────────────────────────────
    // Machine-checkable exit: CI can invoke `--min-coverage 0.80` and the job
    // fails loud when the generator drops below that fraction of declared bug
    // surfaces. An exit-0 here means every asserted threshold was met.
    let coverage_failed = if let Some(min) = min_coverage {
        if union_ratio < min {
            println!(
                "\ncoverage-gate FAIL: union ratio {union_ratio:.3} < min {min:.2} — generator is missing declared vocabulary"
            );
            true
        } else {
            println!("\ncoverage-gate PASS: union ratio {union_ratio:.3} >= min {min:.2}");
            false
        }
    } else {
        false
    };

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

    if coverage_failed {
        return ExitCode::FAILURE;
    }

    println!("\nno invariant violations");
    ExitCode::SUCCESS
}

/// One observed differential class, retaining its first concrete occurrence.
struct CampaignClass {
    count: u64,
    first_iter: u64,
    divergence: ergo_difftest::oracle::Divergence,
}

fn observe_divergence(
    classes: &mut std::collections::HashMap<String, CampaignClass>,
    divergence: ergo_difftest::oracle::Divergence,
    iter: u64,
) {
    classes
        .entry(divergence_signature(&divergence))
        .and_modify(|class| class.count += 1)
        .or_insert(CampaignClass {
            count: 1,
            first_iter: iter,
            divergence,
        });
}

/// Differential campaign against the JVM reference oracle. Without `only` it
/// diffs every oracle surface per input; with `only` it restricts to that one
/// (already validated against the oracle surface set in `main`). When
/// `structured` is set, each surface is fed bytes from
/// [`ergo_difftest::gen::gen_structured`] targeted at that surface (the `reduce`
/// surface, which consumes ErgoTree bytes, is fed the `ergo_tree` generator);
/// otherwise a single shared input is diffed across every surface.
///
/// With `do_minimize`: after the campaign, for each unique divergence, minimize
/// + classify + auto-file it under `regressions_dir`.
#[allow(clippy::too_many_arguments)]
fn run_oracle(
    seed: u64,
    iters: u64,
    script: Option<String>,
    only: Option<&str>,
    corpus: &[Vec<u8>],
    structured: bool,
    do_minimize: bool,
    regressions_dir: &std::path::Path,
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
            eprintln!("{ORACLE_ERROR_MARKER} spawn failed: {e}\n(is scala-cli on PATH?)");
            return exit_harness_error();
        }
    };

    let surfaces: Vec<_> = oracle_surfaces()
        .into_iter()
        .filter(|spec| only.is_none_or(|o| spec.name == o))
        .collect();
    let mut rng = Rng::new(seed);
    // Group by observable signature, not a proven common root cause. Retain
    // the first concrete generating iteration with its representative input.
    let mut classes: std::collections::HashMap<String, CampaignClass> =
        std::collections::HashMap::new();
    let mut total = 0u64;
    let mut checked = 0u64;
    let mut harness_error = false;
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
                    observe_divergence(&mut classes, d, iter);
                }
                Err(e) => {
                    // A dead pipe is a HARNESS failure, not a clean campaign.
                    // Reporting it and then falling through to the normal
                    // summary would let an oracle that died at check 3 of 2000
                    // exit 0 — a green guard that checked almost nothing.
                    eprintln!("{ORACLE_ERROR_MARKER} pipe error after {checked} checks: {e}");
                    harness_error = true;
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

    let unique = classes.len();
    println!(
        "oracle: checks={checked} surfaces={} unique_classes={unique} total_divergences={total}",
        surfaces.len(),
    );
    if harness_error {
        println!(
            "{ORACLE_ERROR_MARKER} campaign aborted after {checked}/{} planned checks — \
             the verdicts below cover only what was actually checked",
            planned_checks(iters, surfaces.len()),
        );
    }
    if classes.is_empty() {
        if harness_error {
            return exit_harness_error();
        }
        println!("node and JVM reference agree on all checked inputs");
        return ExitCode::SUCCESS;
    }
    let mut sorted: Vec<_> = classes.into_values().collect();
    sorted.sort_by_key(|class| {
        (
            std::cmp::Reverse(class.count),
            divergence_signature(&class.divergence),
        )
    });
    for class in &sorted {
        let count = class.count;
        let d = &class.divergence;
        println!(
            "  [{:?}] {} (x{count})\n    rust={:?}\n    jvm ={:?}\n    repro: difftest --repro {}",
            d.kind, d.surface, d.rust, d.jvm, d.input_hex
        );
    }

    // ── Minimize + classify + file ──────────────────────────────────────────
    if do_minimize
        && !minimize_and_file_campaign(
            &sorted,
            &surfaces,
            &mut oracle,
            regressions_dir,
            seed,
            if structured {
                "structured-gen"
            } else {
                "oracle-mutation"
            },
        )
    {
        // Optional processing failures remain harness errors even when original
        // pending records were preserved. Incomplete filing also fails loudly.
        harness_error = true;
    }

    if harness_error {
        exit_harness_error()
    } else {
        ExitCode::FAILURE
    }
}

/// Minimize and file every observed class, retaining the original on failure.
///
/// Any processing or filing error makes the run incomplete. Successful fallback
/// filing preserves evidence; it does not convert failed minimization to a pass.
fn minimize_and_file_campaign(
    sorted: &[CampaignClass],
    surfaces: &[ergo_difftest::oracle::SurfaceSpec],
    oracle: &mut ergo_difftest::oracle::Oracle,
    regressions_dir: &std::path::Path,
    campaign_seed: u64,
    provenance: &str,
) -> bool {
    use ergo_difftest::from_hex;
    use ergo_difftest::minimize::minimize_divergence;
    use ergo_difftest::regressions::{auto_file, record_after_minimization, SeedInfo};

    let mut minimized_count = 0u64;
    let mut filed_count = 0u64;
    let mut complete = true;
    for class in sorted {
        let div = &class.divergence;
        let result = (|| {
            let spec = surfaces
                .iter()
                .find(|spec| spec.name == div.surface)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "missing SurfaceSpec for detected divergence",
                    )
                })?;
            let bytes = from_hex(&div.input_hex).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid input_hex in detected divergence",
                )
            })?;
            eprintln!("minimize: {} ({} bytes)", div.surface, bytes.len());
            minimize_divergence(&bytes, spec, oracle).map(|(_, divergence)| divergence)
        })();
        let record = record_after_minimization(
            div,
            result,
            Some(SeedInfo {
                seed: campaign_seed,
                iter: class.first_iter,
            }),
            provenance,
        );
        if let Some(error) = &record.processing_error {
            eprintln!("{ORACLE_ERROR_MARKER} minimize failed for {}: {error}; retaining original pending input", div.surface);
            complete = false;
        } else {
            minimized_count += 1;
        }
        match auto_file(&record, regressions_dir) {
            Ok(path) => {
                filed_count += 1;
                println!("  [PENDING] filed → {}", path.display());
            }
            Err(error) => {
                eprintln!(
                    "{ORACLE_ERROR_MARKER} file error for {}: {error}",
                    div.surface
                );
                complete = false;
            }
        }
    }
    println!(
        "\nminimize summary: checks={} unique_divergences={} minimized={minimized_count} pending_queued={filed_count} known_artifacts=0",
        sorted.iter().map(|class| class.count).sum::<u64>(),
        sorted.len(),
    );
    complete && usize::try_from(filed_count).ok() == Some(sorted.len())
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
            eprintln!("{ORACLE_ERROR_MARKER} spawn failed: {e}\n(is scala-cli on PATH?)");
            return exit_harness_error();
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
                eprintln!(
                    "{ORACLE_ERROR_MARKER} pipe error on surface {}: {e}",
                    spec.name
                );
                return exit_harness_error();
            }
        }
    }
    if any_divergence {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Minimize + classify + file a single divergence from the `--repro` path.
///
/// Used with `--oracle --repro <hex> --minimize --surface <s>`.
fn run_oracle_repro_minimize(
    bytes: &[u8],
    script: Option<String>,
    surface: &str,
    regressions_dir: &std::path::Path,
) -> ExitCode {
    use ergo_difftest::minimize::minimize_divergence;
    use ergo_difftest::oracle::{diff, oracle_surfaces, Oracle};
    use ergo_difftest::regressions::{auto_file, record_after_minimization};

    let script = script.unwrap_or_else(|| "scripts/jvm_serde_oracle/ErgoSerdeOracle.scala".into());
    eprintln!(
        "oracle: spawning `scala-cli run {script}` (first run resolves deps, may take ~1 min)..."
    );
    let mut oracle = match Oracle::spawn(&script) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{ORACLE_ERROR_MARKER} spawn failed: {e}\n(is scala-cli on PATH?)");
            return exit_harness_error();
        }
    };

    let Some(spec) = oracle_surfaces().into_iter().find(|s| s.name == surface) else {
        eprintln!("--surface: unknown oracle surface {surface:?}");
        return ExitCode::from(2);
    };

    let original = match diff(&spec, bytes, &mut oracle) {
        Ok(Some(divergence)) => divergence,
        Ok(None) => {
            println!("node and JVM reference agree on this input; nothing to minimize");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{ORACLE_ERROR_MARKER} initial repro check failed: {error}");
            return exit_harness_error();
        }
    };
    let result = minimize_divergence(bytes, &spec, &mut oracle).map(|(_, divergence)| divergence);
    let record = record_after_minimization(&original, result, None, "repro");
    let failed = record.processing_error.is_some();
    if let Some(error) = &record.processing_error {
        eprintln!(
            "{ORACLE_ERROR_MARKER} minimize failed: {error}; retaining original pending input"
        );
    }
    match auto_file(&record, regressions_dir) {
        Ok(path) => {
            println!("  [PENDING] filed → {}", path.display());
            if failed {
                exit_harness_error()
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("{ORACLE_ERROR_MARKER} file error: {error}");
            exit_harness_error()
        }
    }
}

/// Grammar mapping for supported structured oracle surfaces. Framed verifier
/// protocols have no matching generator and are refused before spawning a JVM.
fn structured_oracle_surface(oracle_surface: &str) -> Option<&str> {
    match oracle_surface {
        "reduce" => Some("sigma_expr"),
        "reduce_ctx" => Some("ctx_expr"),
        "validate" => Some("transaction"),
        s if ergo_difftest::gen::SURFACES.contains(&s) => Some(s),
        _ => None,
    }
}

fn structured_oracle_bytes(seed: u64, iter: u64, oracle_surface: &str) -> Vec<u8> {
    let gen_surface = structured_oracle_surface(oracle_surface)
        .expect("structured oracle surfaces validated before dispatch");
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

/// `iters * surfaces` for the "planned checks" report. Computed in `u128` so
/// that even a near-`u64::MAX` `iters` (the `MAX_ITERS` gate in `main` is
/// belt-and-suspenders, not the thing this relies on) can never overflow the
/// multiply — a plain `u64` product panics in debug and wraps in release.
fn planned_checks(iters: u64, surfaces: usize) -> u128 {
    u128::from(iters) * surfaces as u128
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

/// Load regular files in lexical path order. JSON contributes decoded string
/// values (not object keys), hex files must be valid UTF-8 hex, and other files
/// contribute raw bytes. Requested unreadable/malformed/empty corpora fail.
fn load_corpus(dir: &str) -> io::Result<Vec<Vec<u8>>> {
    let mut entries = fs::read_dir(Path::new(dir))?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    let mut out = Vec::new();
    for entry in entries {
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
        if matches!(ext, "txt" | "md") {
            continue;
        }
        let data = fs::read(&path)?;
        match ext {
            "hex" => {
                let text = std::str::from_utf8(&data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: {e}", path.display()),
                    )
                })?;
                out.push(from_hex(text).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: invalid hex", path.display()),
                    )
                })?);
            }
            "json" => {
                let value: serde_json::Value = serde_json::from_slice(&data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: {e}", path.display()),
                    )
                })?;
                extract_hex_values(&value, &mut out);
            }
            _ => out.push(data),
        }
    }
    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "requested corpus contains no usable seeds",
        ));
    }
    Ok(out)
}

fn extract_hex_values(value: &serde_json::Value, out: &mut Vec<Vec<u8>>) {
    match value {
        serde_json::Value::String(text) if text.len() >= 8 => {
            if let Some(bytes) = from_hex(text) {
                out.push(bytes);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                extract_hex_values(value, out);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                extract_hex_values(value, out);
            }
        }
        _ => {}
    }
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
         \x20 --min-coverage R  coverage gate: exit non-zero if union ratio < R (0.0..1.0)\n\
         \x20                  requires hermetic --structured; CI uses 0.80\n\
         \x20 --minimize       after --oracle campaign: minimize+classify+file each unique\n\
         \x20                  divergence; with --repro: minimize+file that one input\n\
         \x20                  (--repro --minimize requires --surface)\n\
         \x20 --regressions-dir D  where to file records (default: ergo-difftest/regressions)\n\
         \x20 --selftest       verify the harness's own bug-detection has teeth\n\
         \n\
         EXIT CODES:\n\
         \x20 0  clean — every check ran and node and reference agreed\n\
         \x20 1  divergences found (or a hermetic invariant violation)\n\
         \x20 2  usage error\n\
         \x20 3  harness/oracle error — the oracle could not be spawned, or the\n\
         \x20    pipe died mid-campaign, so the run checked LESS than it planned.\n\
         \x20    Never read a 3 as a clean run.\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn planned_checks_typical_iters_matches_product() {
        assert_eq!(planned_checks(100_000, 12), 1_200_000u128);
    }

    #[test]
    fn corpus_order_and_json_values_are_deterministic() {
        let directory = tempfile::tempdir().unwrap();
        // Creation order deliberately differs from lexical path order.
        fs::write(directory.path().join("b.bin"), [2]).unwrap();
        fs::write(directory.path().join("a.bin"), [1]).unwrap();
        fs::write(
            directory.path().join("c.json"),
            br#"{"deadbeef":{"nested":["12345678","\u0061bcdef01"]},"count":12345678}"#,
        )
        .unwrap();
        let expected = vec![
            vec![1],
            vec![2],
            vec![0x12, 0x34, 0x56, 0x78],
            vec![0xab, 0xcd, 0xef, 1],
        ];
        let path = directory.path().to_str().unwrap();
        assert_eq!(load_corpus(path).unwrap(), expected);
        assert_eq!(load_corpus(path).unwrap(), expected);
    }

    #[test]
    fn structured_oracle_mapping_preserves_protocol_frames() {
        assert_eq!(structured_oracle_surface("reduce"), Some("sigma_expr"));
        assert_eq!(structured_oracle_surface("reduce_ctx"), Some("ctx_expr"));
        assert_eq!(structured_oracle_surface("validate"), Some("transaction"));
        assert_eq!(structured_oracle_surface("header"), Some("header"));
        assert_eq!(structured_oracle_surface("verify"), None);
        assert_eq!(structured_oracle_surface("verify_avl"), None);
    }

    #[test]
    fn grouped_class_preserves_its_first_nonzero_generating_iteration() {
        use ergo_difftest::oracle::{Divergence, DivergenceKind, Verdict};
        let first = Divergence {
            surface: "ergo_tree",
            kind: DivergenceKind::Canonical,
            input_hex: "deadbeef".into(),
            rust: Verdict::Accept("00".into()),
            jvm: Verdict::Accept("01".into()),
        };
        let mut later = first.clone();
        later.input_hex = "aabb".into();
        let mut classes = std::collections::HashMap::new();
        observe_divergence(&mut classes, first.clone(), 42);
        observe_divergence(&mut classes, later, 99);
        let class = classes.values().next().unwrap();
        assert_eq!(classes.len(), 1);
        assert_eq!(class.count, 2);
        assert_eq!(class.first_iter, 42);
        assert_eq!(class.divergence, first);
    }

    // ----- round-trips -----

    #[test]
    fn planned_checks_max_iters_bound_does_not_overflow() {
        // MAX_ITERS is the CLI-level gate; confirm the report math it protects
        // stays correct (not just non-panicking) at that boundary.
        let expected = u128::from(MAX_ITERS) * 64u128;
        assert_eq!(planned_checks(MAX_ITERS, 64), expected);
    }

    // ----- error paths -----

    #[test]
    fn requested_corpus_failures_are_errors() {
        let directory = tempfile::tempdir().unwrap();
        assert!(load_corpus(directory.path().join("missing").to_str().unwrap()).is_err());
        assert!(load_corpus(directory.path().to_str().unwrap()).is_err());
        let hex = directory.path().join("bad.hex");
        fs::write(&hex, "not hex").unwrap();
        assert!(load_corpus(directory.path().to_str().unwrap()).is_err());
        fs::remove_file(hex).unwrap();
        fs::write(directory.path().join("bad.json"), "{").unwrap();
        assert!(load_corpus(directory.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn planned_checks_u64_max_iters_does_not_overflow() {
        // A plain `u64` product of u64::MAX * surfaces panics in debug builds
        // (the bug this guards against) and silently wraps in release. The
        // u128 computation must neither panic nor wrap for any u64 `iters`,
        // independent of the MAX_ITERS CLI gate.
        let surfaces = 37usize;
        let expected = u128::from(u64::MAX) * surfaces as u128;
        assert_eq!(planned_checks(u64::MAX, surfaces), expected);
    }
}

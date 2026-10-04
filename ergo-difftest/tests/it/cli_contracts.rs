//! CLI exit contracts for incomplete work and invalid option combinations.
//! These checks do not launch a JVM or run a mutation campaign.

use std::process::{Command, Output};

// ----- happy path -----

#[test]
fn canonical_control_compares_complete_expected_bytes() {
    let output = run(&["--repro", "0008d3", "--check-canonical", "0008D3"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("[CANONICAL-GATE] PASS"));
}

// ----- error paths -----

#[test]
fn canonical_rejection_or_trailing_bytes_is_incomplete() {
    for input in ["", "0008d300"] {
        let output = run(&["--repro", input, "--check-canonical", "0008d3"]);
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("HARNESS ERROR"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("PASS"));
    }
}

#[test]
fn coverage_thresholds_and_modes_are_validated() {
    for threshold in ["NaN", "inf", "-0.1", "1.1"] {
        let output = run(&["--structured", "--min-coverage", threshold]);
        assert_eq!(output.status.code(), Some(2), "{threshold}: {output:?}");
    }
    for flags in [
        vec!["--min-coverage", "0.8"],
        vec!["--structured", "--min-coverage", "0.8", "--oracle"],
        vec!["--structured", "--min-coverage", "0.8", "--repro", "0008d3"],
        vec!["--structured", "--iters", "0", "--min-coverage", "0.0"],
        vec!["--selftest", "--min-coverage", "NaN"],
    ] {
        let output = run(&flags);
        assert_eq!(output.status.code(), Some(2), "{flags:?}: {output:?}");
    }
}

#[test]
fn unsupported_structured_frames_fail_before_oracle_spawn() {
    for surface in ["verify", "verify_avl"] {
        let output = run(&["--structured", "--oracle", "--surface", surface]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("no matching framed generator"));
        assert!(!stderr.contains("spawning"));
    }
}

#[test]
fn oracle_campaigns_accept_a_journal_directory() {
    // Every oracle campaign writes an execution journal, so its location must
    // be selectable with or without --minimize. A missing oracle script stops
    // the run at spawn, before any JVM or journal.
    let directory = tempfile::tempdir().unwrap();
    let journals = directory.path().join("journals");
    let script = directory.path().join("missing.scala");
    let common = [
        "--oracle",
        "--iters",
        "1",
        "--regressions-dir",
        journals.to_str().unwrap(),
        "--oracle-script",
        script.to_str().unwrap(),
    ];
    for extra in [
        &[][..],
        &["--minimize"],
        &["--structured", "--surface", "reduce"],
    ] {
        let output = run(&[&common[..], extra].concat());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{extra:?}: {output:?}");
        assert!(stderr.contains("spawn failed"), "{extra:?}: {stderr}");
        assert!(!journals.exists());
    }
}

#[test]
fn journal_directory_needs_a_journaled_oracle_run() {
    // A plain oracle repro or a hermetic run writes no journal.
    for flags in [
        vec![
            "--repro",
            "0008d3",
            "--oracle",
            "--regressions-dir",
            "unused",
        ],
        vec!["--iters", "1", "--regressions-dir", "unused"],
    ] {
        let output = run(&flags);
        assert_eq!(output.status.code(), Some(2), "{flags:?}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("--regressions-dir requires"));
    }
}

#[test]
fn missing_requested_corpus_fails_the_run() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");
    let output = run(&["--corpus", missing.to_str().unwrap(), "--iters", "1"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("HARNESS ERROR"));
}

// ----- helpers -----

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_difftest"))
        .args(args)
        .output()
        .expect("run difftest")
}

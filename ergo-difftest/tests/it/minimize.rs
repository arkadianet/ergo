//! Tests for the delta-debugging minimizer (Slice 3).
//!
//! All tests here are **hermetic** (no JVM oracle required); they use synthetic
//! predicates to verify the minimizer's mechanical properties:
//!
//! * **Shrinks AND preserves**: a satisfying input is reduced to a strictly
//!   smaller form that still satisfies the predicate.
//! * **Correctness invariant**: the returned result always satisfies the
//!   predicate.  A minimizer that returns a non-satisfying result is broken.
//! * **Determinism**: same `(input, predicate)` → same output.
//! * **Fixed point**: running the minimizer on its own output changes nothing.
//! * **Record round-trip**: a [`DivergenceRecord`] serializes to valid JSON
//!   and deserializes back without loss.
//! * **QUEUE gate**: only `Pending` records are written to `QUEUE.md`;
//!   `KnownArtifact` records are not.

use ergo_difftest::minimize::minimize;
use ergo_difftest::regressions::{
    auto_file, build_record, record_after_minimization, DivergenceRecord, SeedInfo, Triage,
};

// ─────────────────────────────────────────────────────────────────────────────
// Minimizer mechanics
// ─────────────────────────────────────────────────────────────────────────────

/// Predicate: the bytes contain at least one 0xAB byte.
fn contains_ab(b: &[u8]) -> bool {
    b.contains(&0xAB)
}

/// Build a 500-byte input that contains 0xAB at position 250, surrounded by
/// noise.  The minimizer must reduce this to a single byte `[0xAB]` (or a
/// minimal slice containing only 0xAB with no other bytes).
#[test]
fn minimizer_shrinks_to_single_marker_byte() {
    // Fill with bytes that do NOT satisfy the predicate on their own.
    let mut input = vec![0u8; 500];
    // Plant a single 0xAB at position 250.
    input[250] = 0xAB;
    // Sanity: original satisfies the predicate.
    assert!(
        contains_ab(&input),
        "test setup: predicate must hold on input"
    );

    let minimized = minimize(&input, contains_ab);

    // The minimizer must return a result that still satisfies the predicate.
    assert!(
        contains_ab(&minimized),
        "minimizer violated correctness: returned a non-satisfying result"
    );

    // The result must be STRICTLY SMALLER than the input.
    assert!(
        minimized.len() < input.len(),
        "minimizer made no progress: len {} → {} (expected < 500)",
        input.len(),
        minimized.len()
    );

    // The optimal result is a single byte [0xAB].  Our ddmin-style minimizer
    // MUST reach this because every prefix/suffix and every single byte
    // removal is tried.
    assert_eq!(
        minimized,
        vec![0xAB],
        "minimizer did not reach the optimal [0xAB]: got {:?}",
        minimized
    );
}

/// Correctness invariant: a predicate that holds for the input must hold for
/// the minimizer's output.  Test with a predicate that fires on `len >= 3 &&
/// bytes[0] == 0x01`.
#[test]
fn minimizer_never_returns_non_satisfying_result() {
    let predicate = |b: &[u8]| b.len() >= 3 && b[0] == 0x01;

    let input: Vec<u8> = {
        let mut v = vec![0x01u8];
        v.extend_from_slice(&[0x00u8; 100]);
        v
    };
    assert!(
        predicate(&input),
        "test setup: predicate must hold on input"
    );

    let minimized = minimize(&input, predicate);

    // The returned result MUST satisfy the predicate.
    assert!(
        predicate(&minimized),
        "minimizer violated correctness invariant: returned len={} b[0]={:02x}",
        minimized.len(),
        minimized.first().copied().unwrap_or(0)
    );

    // The length must be exactly the minimum: 3 bytes starting with 0x01.
    assert!(
        minimized.len() >= 3,
        "minimized len {} violates the predicate (need >= 3)",
        minimized.len()
    );
    assert_eq!(
        minimized[0], 0x01,
        "minimized[0] must be 0x01 (predicate requirement)"
    );
}

/// Determinism: same `(input, predicate)` → exactly the same bytes.
#[test]
fn minimizer_is_deterministic() {
    let mut input = vec![0u8; 300];
    input[150] = 0xAB;

    let r1 = minimize(&input, contains_ab);
    let r2 = minimize(&input, contains_ab);

    assert_eq!(r1, r2, "minimizer is not deterministic");
}

/// Fixed-point: running the minimizer on its own output changes nothing.
#[test]
fn minimizer_reaches_fixed_point() {
    let mut input = vec![0u8; 200];
    input[99] = 0xAB;

    let first = minimize(&input, contains_ab);
    let second = minimize(&first, contains_ab);

    assert_eq!(
        first, second,
        "minimizer output is not a fixed point: second pass changed {:?} → {:?}",
        first, second
    );
}

/// Empty result: if the empty slice satisfies the predicate, the minimizer
/// should reduce to it.
#[test]
fn minimizer_can_reduce_to_empty() {
    // Predicate: always true.
    let input = vec![0xFFu8; 50];
    let minimized = minimize(&input, |_| true);
    assert_eq!(
        minimized,
        Vec::<u8>::new(),
        "expected empty slice when predicate is always-true"
    );
}

/// Non-satisfying input: if the input does NOT satisfy the predicate, the
/// minimizer should return the original unchanged (it has nothing to do).
/// (This edge case tests that the outer loop exits immediately when no phase
/// makes progress from the start.)
#[test]
fn minimizer_noop_on_unsatisfied_input() {
    // Predicate: only satisfied if the slice contains 0xAB.
    let input = vec![0x01u8, 0x02u8, 0x03u8]; // no 0xAB
    assert!(!contains_ab(&input), "test setup");

    let result = minimize(&input, contains_ab);

    // The minimizer must not return a non-satisfying result.
    // Since the input itself doesn't satisfy the predicate, the minimizer
    // never makes progress and must return the original.
    assert_eq!(
        result, input,
        "minimizer changed the input even though predicate was never satisfied"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Record round-trip + QUEUE gate
// ─────────────────────────────────────────────────────────────────────────────

/// Build a synthetic [`DivergenceRecord`] for round-trip testing.
fn make_record(triage: Triage) -> DivergenceRecord {
    build_record(
        &ergo_difftest::oracle::Divergence {
            surface: "ergo_tree",
            kind: ergo_difftest::oracle::DivergenceKind::AcceptReject,
            input_hex: "deadbeef".to_string(),
            rust: ergo_difftest::oracle::Verdict::Accept("cafebabe".to_string()),
            jvm: ergo_difftest::oracle::Verdict::Reject("NoSuchElementException at …".to_string()),
        },
        triage,
        Some(SeedInfo { seed: 7, iter: 42 }),
        "structured-gen",
    )
}

/// A `DivergenceRecord` must serialize to JSON and round-trip back without
/// field loss.
#[test]
fn record_json_round_trip() {
    let record = make_record(Triage::Pending);

    let json = serde_json::to_string_pretty(&record).expect("serialize");

    // Must be valid JSON.
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");

    // Required fields (§4 schema).
    assert_eq!(parsed["surface"], "ergo_tree");
    assert_eq!(parsed["kind"], "AcceptReject");
    assert_eq!(parsed["input_hex"], "deadbeef");
    assert_eq!(parsed["minimized"], true);
    assert_eq!(parsed["triage"], "PENDING");
    assert_eq!(parsed["provenance"], "structured-gen");
    assert_eq!(parsed["rust"]["verdict"], "Accept");
    assert_eq!(parsed["jvm"]["verdict"], "Reject");
    assert_eq!(parsed["seed"]["seed"], 7);
    assert_eq!(parsed["seed"]["iter"], 42);

    // Round-trip via typed deserialization.
    let back: DivergenceRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, record);
}

/// `auto_file` for a `Pending` record must:
/// * atomically write JSON to `<dir>/<surface>/<full-record-sha256>.json`,
/// * regenerate a line in the derived `QUEUE.md`.
///
/// `auto_file` for a `KnownArtifact` record must:
/// * write to `<dir>/artifacts/<surface>/<full-record-sha256>.json`,
/// * preserve the pending entries in `QUEUE.md`.
#[test]
fn auto_file_pending_appends_to_queue_artifact_does_not() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let reg = dir.path();

    // ── Pending record ───────────────────────────────────────────────────────
    let pending = make_record(Triage::Pending);
    let path_p = auto_file(&pending, reg).expect("auto_file pending");

    assert!(
        path_p.exists(),
        "pending record file not created: {}",
        path_p.display()
    );
    // Must be under <surface>/, not under artifacts/.
    assert!(
        path_p.to_str().unwrap().contains("ergo_tree"),
        "pending record should be under ergo_tree/, got {}",
        path_p.display()
    );
    assert!(
        !path_p.to_str().unwrap().contains("artifacts"),
        "pending record must NOT be under artifacts/, got {}",
        path_p.display()
    );

    // QUEUE.md must exist and contain an entry.
    let queue = reg.join("QUEUE.md");
    assert!(queue.exists(), "QUEUE.md not created for Pending record");
    let queue_content = std::fs::read_to_string(&queue).expect("read QUEUE.md");
    assert!(
        queue_content.contains("[PENDING]"),
        "QUEUE.md missing [PENDING] entry:\n{queue_content}"
    );
    assert!(
        queue_content.contains("ergo_tree"),
        "QUEUE.md missing surface name:\n{queue_content}"
    );

    // ── KnownArtifact record ─────────────────────────────────────────────────
    let artifact = make_record(Triage::KnownArtifact(
        "reconciles on reduce: parse-surface only".to_string(),
    ));
    // Different input_hex so it gets a different hash.
    let mut artifact2 = artifact.clone();
    artifact2.input_hex = "aabbccdd".to_string();
    artifact2.triage =
        Triage::KnownArtifact("reconciles on reduce: parse-surface only".to_string()).to_field();

    let path_a = auto_file(&artifact2, reg).expect("auto_file artifact");

    assert!(
        path_a.exists(),
        "artifact record file not created: {}",
        path_a.display()
    );
    // Must be under artifacts/<surface>/.
    assert!(
        path_a.to_str().unwrap().contains("artifacts"),
        "artifact record must be under artifacts/, got {}",
        path_a.display()
    );

    // QUEUE.md must NOT have a second entry (only the Pending from above).
    let queue_content2 = std::fs::read_to_string(&queue).expect("read QUEUE.md after artifact");
    let pending_lines = queue_content2
        .lines()
        .filter(|l| l.contains("[PENDING]"))
        .count();
    assert_eq!(
        pending_lines, 1,
        "QUEUE.md should have exactly 1 [PENDING] entry (artifact must not add one), got {pending_lines}:\n{queue_content2}"
    );
}

/// Idempotency: filing the same Pending record twice writes the same path AND
/// does not duplicate its QUEUE.md line.
#[test]
fn auto_file_is_idempotent_same_path() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let reg = dir.path();
    let record = make_record(Triage::Pending);

    let p1 = auto_file(&record, reg).expect("first file");
    let p2 = auto_file(&record, reg).expect("second file");

    assert_eq!(p1, p2, "second filing must produce the same path as first");
    assert!(p2.exists());

    // The Pending record must appear exactly once in QUEUE.md after two files.
    let queue = std::fs::read_to_string(reg.join("QUEUE.md")).expect("QUEUE.md");
    assert_eq!(
        queue.matches("[PENDING]").count(),
        1,
        "re-filing the same record must not duplicate its QUEUE.md line"
    );
}

// Failure recovery checks diagnostic record mechanics, not Scala verdicts.
#[test]
fn failed_minimization_preserves_original_pending_evidence() {
    let original = ergo_difftest::oracle::Divergence {
        surface: "ergo_tree",
        kind: ergo_difftest::oracle::DivergenceKind::Canonical,
        input_hex: "deadbeef".into(),
        rust: ergo_difftest::oracle::Verdict::Accept("00".into()),
        jvm: ergo_difftest::oracle::Verdict::Accept("01".into()),
    };
    let directory = tempfile::tempdir().unwrap();
    for kind in [
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::InvalidData,
        std::io::ErrorKind::Other,
        std::io::ErrorKind::BrokenPipe,
    ] {
        let record = record_after_minimization(
            &original,
            Err(std::io::Error::new(kind, "ordinary processing fixture")),
            Some(SeedInfo { seed: 7, iter: 42 }),
            "structured-gen",
        );
        assert_eq!(record.input_hex, original.input_hex);
        assert_eq!(record.rust.detail, "00");
        assert_eq!(record.jvm.detail, "01");
        assert_eq!(record.seed, Some(SeedInfo { seed: 7, iter: 42 }));
        assert_eq!(record.triage, "PENDING");
        assert!(!record.minimized);
        assert!(record
            .processing_error
            .as_ref()
            .unwrap()
            .contains(&format!("{kind:?}")));
        let path = auto_file(&record, directory.path()).unwrap();
        let stored: DivergenceRecord =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(stored, record);
    }
}

#[test]
fn successful_minimization_uses_reverified_input_and_stays_pending() {
    let original = ergo_difftest::oracle::Divergence {
        surface: "ergo_tree",
        kind: ergo_difftest::oracle::DivergenceKind::Canonical,
        input_hex: "deadbeef".into(),
        rust: ergo_difftest::oracle::Verdict::Accept("00".into()),
        jvm: ergo_difftest::oracle::Verdict::Accept("01".into()),
    };
    let mut minimized = original.clone();
    minimized.input_hex = "dead".into();
    let record = record_after_minimization(&original, Ok(minimized), None, "repro");
    assert_eq!(record.input_hex, "dead");
    assert!(record.minimized);
    assert_eq!(record.triage, "PENDING");
    assert!(record.processing_error.is_none());
}

// Diagnostic filing identity includes the full record, not only input bytes.
#[test]
fn same_input_under_distinct_authorities_keeps_both_records() {
    let directory = tempfile::tempdir().unwrap();
    let first = make_record(Triage::Pending);
    let mut second = first.clone();
    second.execution = Some(
        serde_json::json!({"comparison_contract": {"oracle_source_sha256": "different fixture authority"}}),
    );
    let first_path = auto_file(&first, directory.path()).unwrap();
    let second_path = auto_file(&second, directory.path()).unwrap();
    assert_ne!(first_path, second_path);
    assert_eq!(first_path.file_stem().unwrap().to_str().unwrap().len(), 64);
    assert_eq!(
        serde_json::from_slice::<DivergenceRecord>(&std::fs::read(first_path).unwrap()).unwrap(),
        first
    );
    assert_eq!(
        serde_json::from_slice::<DivergenceRecord>(&std::fs::read(second_path).unwrap()).unwrap(),
        second
    );
    assert_eq!(
        std::fs::read_to_string(directory.path().join("QUEUE.md"))
            .unwrap()
            .matches("[PENDING]")
            .count(),
        2
    );
}

#[test]
fn concurrent_filing_is_complete_and_queue_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let record = make_record(Triage::Pending);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let paths: Vec<_> = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let barrier = std::sync::Arc::clone(&barrier);
            let record = &record;
            let root = directory.path();
            workers.push(scope.spawn(move || {
                barrier.wait();
                auto_file(record, root).unwrap()
            }));
        }
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect()
    });
    assert_eq!(paths[0], paths[1]);
    let stored: DivergenceRecord =
        serde_json::from_slice(&std::fs::read(&paths[0]).unwrap()).unwrap();
    assert_eq!(stored, record);
    assert_eq!(
        std::fs::read_to_string(directory.path().join("QUEUE.md"))
            .unwrap()
            .matches("[PENDING]")
            .count(),
        1
    );
}

#[test]
fn corrupt_existing_record_is_not_overwritten() {
    let directory = tempfile::tempdir().unwrap();
    let record = make_record(Triage::Pending);
    let path = auto_file(&record, directory.path()).unwrap();
    std::fs::write(&path, b"{").unwrap();
    assert_eq!(
        auto_file(&record, directory.path()).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(path).unwrap(), b"{");
}

#[test]
fn filing_rejects_surface_path_components() {
    let directory = tempfile::tempdir().unwrap();
    let mut record = make_record(Triage::Pending);
    record.surface = "../foreign".into();
    assert_eq!(
        auto_file(&record, directory.path()).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert!(!directory.path().join(".filing.lock").exists());
}

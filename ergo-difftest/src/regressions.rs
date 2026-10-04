//! Classification, auto-filing, and the divergence record schema for the
//! fuzz-differential harness.
//!
//! ## Schema
//! [`DivergenceRecord`] is the on-disk record shared with the triage tooling.
//!
//! ## Classification rule
//! New divergences stay [`Triage::Pending`] for human review. Agreement or
//! rejection under one dummy reduction context does not explain a parse
//! difference or establish benignity. [`Triage::KnownArtifact`] remains an
//! explicit, reviewed disposition for externally explained records.
//!
//! ## Auto-filing
//! [`auto_file`] writes the record to content-addressed paths under a
//! caller-supplied `regressions_dir`:
//! * **Pending** → `<dir>/<surface>/<full-record-sha256>.json`, derived entry in
//!   `<dir>/QUEUE.md`.
//! * **KnownArtifact** → `<dir>/artifacts/<surface>/<full-record-sha256>.json`,
//!   **not** appended to `QUEUE.md` (so the queue stays signal, not noise).
//!
//! Filing is serialized and atomic. Identical complete records are idempotent;
//! differing evidence is never overwritten. QUEUE.md is a derived view.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::oracle::{Divergence, DivergenceKind, Verdict};

pub(crate) mod storage;

// ─────────────────────────────────────────────────────────────────────────────
// Schema (§4)
// ─────────────────────────────────────────────────────────────────────────────

/// A detected divergence with processing and triage state.  Matches `interface-contracts.md §4`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DivergenceRecord {
    /// Oracle surface or `"block:<height>"`.
    pub surface: String,
    /// Kind tag matching the `DivergenceKind` enum:
    /// `"AcceptReject"` | `"Canonical"` | `"Reduce"` | `"Cost"` | etc.
    pub kind: String,
    /// Hex of the minimized input, or original input if processing failed.
    pub input_hex: String,
    /// Rust node verdict.
    pub rust: VerdictInfo,
    /// JVM reference verdict.
    pub jvm: VerdictInfo,
    /// CLI command to reproduce the finding.
    pub repro: String,
    /// Seed used to generate this input, or `null` if unknown.
    pub seed: Option<SeedInfo>,
    /// True only after successful minimization and final re-verification.
    /// False preserves an original finding when optional processing fails.
    pub minimized: bool,
    /// Failed processing remains evidence and makes the campaign incomplete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processing_error: Option<String>,
    /// Immutable execution metadata reference and stable comparison contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<serde_json::Value>,
    /// How this input was produced: `"structured-gen"`, `"oracle-mutation"`,
    /// `"replay:h<height>"`, etc.
    pub provenance: String,
    /// `"PENDING"` until a human edits it; or `"KnownArtifact(<reason>)"`.
    pub triage: String,
}

/// Verdict from one side of the differential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerdictInfo {
    /// `"Accept"`, `"Reject"`, or `"Err"`.
    pub verdict: String,
    /// Canonical hex, error class, or `P:<prop>|<cost>` string.
    pub detail: String,
}

/// Campaign seed + iteration for reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeedInfo {
    pub seed: u64,
    pub iter: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Triage
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a divergence.  The harness NEVER sets which side is right.
#[derive(Debug, Clone, PartialEq)]
pub enum Triage {
    /// Explained benign.  The `reason` string is stored verbatim in the
    /// `triage` JSON field as `"KnownArtifact(<reason>)"`.
    KnownArtifact(String),
    /// Genuine candidate for human triage.  Filed in the QUEUE.
    Pending,
}

impl Triage {
    /// Serialize to the `triage` JSON field value.
    pub fn to_field(&self) -> String {
        match self {
            Triage::KnownArtifact(reason) => format!("KnownArtifact({reason})"),
            Triage::Pending => "PENDING".to_string(),
        }
    }

    /// True iff this is `Pending`.
    pub fn is_pending(&self) -> bool {
        matches!(self, Triage::Pending)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Record construction
// ─────────────────────────────────────────────────────────────────────────────

fn verdict_to_info(v: &Verdict) -> VerdictInfo {
    match v {
        Verdict::Accept(d) => VerdictInfo {
            verdict: "Accept".to_string(),
            detail: d.clone(),
        },
        Verdict::Reject(d) => VerdictInfo {
            verdict: "Reject".to_string(),
            detail: d.clone(),
        },
        Verdict::Err(d) => VerdictInfo {
            verdict: "Err".to_string(),
            detail: d.clone(),
        },
    }
}

fn kind_to_string(k: &DivergenceKind) -> String {
    match k {
        DivergenceKind::AcceptReject => "AcceptReject".to_string(),
        DivergenceKind::Canonical => "Canonical".to_string(),
    }
}

/// Build a [`DivergenceRecord`] from a minimized [`Divergence`] + classification.
///
/// `seed` is `None` when the input came from a repro path rather than a seeded
/// campaign. `provenance` is a free-form tag (`"structured-gen"`,
/// `"oracle-mutation"`, `"replay:h<height>"`, etc.).
pub fn build_record(
    divergence: &Divergence,
    triage: Triage,
    seed: Option<SeedInfo>,
    provenance: &str,
) -> DivergenceRecord {
    let input_hex = divergence.input_hex.clone();
    let repro = format!(
        "difftest --oracle --repro {input_hex} --surface {}",
        divergence.surface
    );
    DivergenceRecord {
        surface: divergence.surface.to_string(),
        kind: kind_to_string(&divergence.kind),
        input_hex,
        rust: verdict_to_info(&divergence.rust),
        jvm: verdict_to_info(&divergence.jvm),
        repro,
        seed,
        minimized: true,
        processing_error: None,
        execution: None,
        provenance: provenance.to_string(),
        triage: triage.to_field(),
    }
}

/// Preserve a detected divergence through optional minimization.
///
/// On success, use the re-verified minimized divergence. Every error retains
/// the original input/verdicts as an unminimized pending record and stores the
/// processing error. Callers must report such an error as an incomplete harness
/// run even if the fallback record is filed successfully.
pub fn record_after_minimization(
    original: &Divergence,
    minimized: io::Result<Divergence>,
    seed: Option<SeedInfo>,
    provenance: &str,
) -> DivergenceRecord {
    match minimized {
        Ok(divergence) => build_record(&divergence, Triage::Pending, seed, provenance),
        Err(error) => {
            let mut record = build_record(original, Triage::Pending, seed, provenance);
            record.minimized = false;
            record.processing_error = Some(format!("{:?}: {error}", error.kind()));
            record
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-file
// ─────────────────────────────────────────────────────────────────────────────

/// Atomically publish a complete immutable record under its full JSON SHA-256.
///
/// Pending records use `<dir>/<surface>/<hash>.json`; explicit artifacts use
/// `<dir>/artifacts/<surface>/<hash>.json`. A cross-process filing lock protects
/// publication and regeneration of the derived pending `QUEUE.md`. An identical
/// record is idempotent; conflicting/corrupt files cause an error, never overwrite.
/// Legacy short-input-hash records require a fresh output directory, preserving
/// their original evidence. This is diagnostic integrity, not a power-loss proof.
pub fn auto_file(record: &DivergenceRecord, regressions_dir: &Path) -> io::Result<PathBuf> {
    storage::file(record, regressions_dir)
}

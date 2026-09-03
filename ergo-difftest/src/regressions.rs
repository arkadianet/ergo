//! Classification, auto-filing, and the divergence record schema for the
//! fuzz-differential harness.
//!
//! ## Schema
//! [`DivergenceRecord`] is the on-disk record shared with the triage tooling.
//!
//! ## Classification rule
//! For a divergence on a **parse** surface (`ergo_tree`, `ergo_box_candidate`,
//! `transaction`, `header`): re-run `diff` on the **`reduce`** surface for the
//! same bytes.  If `reduce` **agrees** (no divergence), the parse-surface
//! divergence is a [`Triage::KnownArtifact`] — the node retains original wire
//! bytes / defers the curve-check, so the difference is benign.  If `reduce`
//! **also diverges**, or if the original divergence was already on the `reduce`
//! surface, the record is [`Triage::Pending`].
//!
//! The harness **never** sets a which-side-is-right verdict.  `Pending` means
//! "a human must decide"; `KnownArtifact` means "explained benign, no consensus
//! impact."
//!
//! ## Auto-filing
//! [`auto_file`] writes the record to content-addressed paths under a
//! caller-supplied `regressions_dir`:
//! * **Pending** → `<dir>/<surface>/<sha256hex[..16]>.json`, entry appended to
//!   `<dir>/QUEUE.md`.
//! * **KnownArtifact** → `<dir>/artifacts/<surface>/<sha256hex[..16]>.json`,
//!   **not** appended to `QUEUE.md` (so the queue stays signal, not noise).
//!
//! Filing is idempotent: same `input_hex` → same path → overwrite is fine.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::oracle::{
    diff, oracle_surfaces, Divergence, DivergenceKind, Oracle, SurfaceSpec, Verdict,
};

// ─────────────────────────────────────────────────────────────────────────────
// Schema (§4)
// ─────────────────────────────────────────────────────────────────────────────

/// A minimized, classified divergence record.  Matches `interface-contracts.md §4`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DivergenceRecord {
    /// Oracle surface or `"block:<height>"`.
    pub surface: String,
    /// Kind tag matching the `DivergenceKind` enum:
    /// `"AcceptReject"` | `"Canonical"` | `"Reduce"` | `"Cost"` | etc.
    pub kind: String,
    /// Hex of the **minimized** input (post-shrink).
    pub input_hex: String,
    /// Rust node verdict.
    pub rust: VerdictInfo,
    /// JVM reference verdict.
    pub jvm: VerdictInfo,
    /// CLI command to reproduce the finding.
    pub repro: String,
    /// Seed used to generate this input, or `null` if unknown.
    pub seed: Option<SeedInfo>,
    /// Always `true` (this type represents a post-minimization record).
    pub minimized: bool,
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
// Classification
// ─────────────────────────────────────────────────────────────────────────────

/// The reduction surface a parse-surface divergence is reconciled against, and
/// how to turn the parse-surface bytes into an input for it.
///
/// Reconciliation is only meaningful when the SAME bytes can be handed to a
/// surface that actually EVALUATES them:
///
/// * `ergo_tree` bytes are a script → `reduce` consumes them directly.
/// * `ergo_box_candidate` bytes are a box → prefixing an empty context
///   extension (`0x00`) makes them a `reduce_ctx` frame, which reduces the
///   box's own script with the box as SELF (registers included).
///
/// `transaction` and `header` bytes are NEITHER. Feeding them to `reduce` makes
/// both sides reject on the first byte, which "agrees" for a reason that has
/// nothing to do with the finding — so a real transaction-surface divergence
/// (e.g. a context-extension value the node refuses to parse) would be filed
/// as benign. Those surfaces therefore have no reconciliation channel and stay
/// `Pending` for a human.
fn reduction_channel(surface: &str) -> Option<(&'static str, &'static [u8])> {
    match surface {
        "ergo_tree" => Some(("reduce", &[])),
        "ergo_box_candidate" => Some(("reduce_ctx", &[0x00])),
        _ => None,
    }
}

/// Classify a minimized divergence.
///
/// **Key rule**: for a parse-surface divergence with a reduction channel (see
/// [`reduction_channel`]), re-run `diff` on that channel for the same bytes. If
/// the reduction **agrees**, the parse-surface divergence is a
/// [`Triage::KnownArtifact`] — the node retains original wire bytes / defers the
/// curve-check, so the difference is benign. If the reduction **also diverges**,
/// or the surface has no reduction channel, the record is [`Triage::Pending`].
///
/// This function never sets a which-side-is-right verdict.
pub fn classify(
    spec: &SurfaceSpec,
    minimized_input: &[u8],
    oracle: &mut Oracle,
) -> io::Result<Triage> {
    let Some((channel, prefix)) = reduction_channel(spec.name) else {
        return Ok(Triage::Pending);
    };
    let channel_spec = oracle_surfaces()
        .into_iter()
        .find(|s| s.name == channel)
        .expect("reduction channel surfaces are always present in oracle_surfaces()");
    let mut input = Vec::with_capacity(prefix.len() + minimized_input.len());
    input.extend_from_slice(prefix);
    input.extend_from_slice(minimized_input);

    match diff(&channel_spec, &input, oracle)? {
        None => Ok(Triage::KnownArtifact(format!(
            "reconciles on {channel}: parse-surface only, node retains original bytes / defers curve-check"
        ))),
        Some(_) => Ok(Triage::Pending),
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
        provenance: provenance.to_string(),
        triage: triage.to_field(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-file
// ─────────────────────────────────────────────────────────────────────────────

/// Write a [`DivergenceRecord`] to disk and (for `Pending` records only) append
/// a line to `QUEUE.md`.
///
/// **Path scheme:**
/// * `Pending`      → `<regressions_dir>/<surface>/<sha256hex[..16]>.json`
/// * `KnownArtifact`→ `<regressions_dir>/artifacts/<surface>/<sha256hex[..16]>.json`
///
/// **QUEUE.md** — one entry per `Pending` record, format:
/// `- [PENDING] <surface>/<hash16> — <repro_command>`.
/// `KnownArtifact` records are NOT appended to the queue.
///
/// **Idempotent**: same `input_hex` → same path; overwriting is fine.
///
/// Returns the path the record was written to.
pub fn auto_file(record: &DivergenceRecord, regressions_dir: &Path) -> io::Result<PathBuf> {
    // Content-addressed filename: SHA-256 of the input hex, first 16 hex chars.
    let hash = {
        let mut h = Sha256::new();
        h.update(record.input_hex.as_bytes());
        format!("{:x}", h.finalize())
    };
    let short_hash = &hash[..16];

    let is_pending = record.triage == "PENDING";

    // Choose directory.
    let dir = if is_pending {
        regressions_dir.join(&record.surface)
    } else {
        regressions_dir.join("artifacts").join(&record.surface)
    };
    std::fs::create_dir_all(&dir)?;

    // Write JSON.
    let path = dir.join(format!("{short_hash}.json"));
    let json = serde_json::to_string_pretty(record)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, json.as_bytes())?;

    // Append to QUEUE.md only for Pending.
    if is_pending {
        let queue_path = regressions_dir.join("QUEUE.md");
        let entry = format!(
            "- [PENDING] {}/{short_hash} — {}\n",
            record.surface, record.repro
        );
        // Idempotent like the record file: skip if this record's content-addressed
        // key is already queued, so re-filing the same divergence doesn't duplicate
        // its QUEUE.md line.
        let key = format!("{}/{short_hash} —", record.surface);
        let already_queued = std::fs::read_to_string(&queue_path)
            .map(|q| q.contains(&key))
            .unwrap_or(false);
        if !already_queued {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&queue_path)?;
            f.write_all(entry.as_bytes())?;
        }
    }

    Ok(path)
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience: classify-and-file pipeline (used by the CLI)
// ─────────────────────────────────────────────────────────────────────────────

/// One-stop pipeline: classify `divergence`, build the record, and file it.
///
/// Returns `(path, triage)` so the caller can update its counters.
pub fn classify_and_file(
    divergence: &Divergence,
    spec: &SurfaceSpec,
    oracle: &mut Oracle,
    seed: Option<SeedInfo>,
    provenance: &str,
    regressions_dir: &Path,
) -> io::Result<(PathBuf, Triage)> {
    let input = crate::from_hex(&divergence.input_hex)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad input_hex in divergence"))?;
    let triage = classify(spec, &input, oracle)?;
    let record = build_record(divergence, triage.clone(), seed, provenance);
    let path = auto_file(&record, regressions_dir)?;
    Ok((path, triage))
}

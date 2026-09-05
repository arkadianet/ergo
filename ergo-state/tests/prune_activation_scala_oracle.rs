//! Runtime-oracle parity check for the Mode 3 prune-sentinel
//! **activation** seed, `activation_minimal_full_block_height`.
//!
//! Sibling of `prune_formula_scala_oracle.rs`, which pins the
//! steady-state per-apply formula. This file pins the flip-time seed:
//! the value Scala writes when `ToDownloadProcessor.toDownload`
//! observes the first fresh header, flips `isHeadersChainSynced`, and
//! calls `FullBlockPruningProcessor.updateBestFullBlock(header)`
//! (`ToDownloadProcessor.scala:110-118`).
//!
//! Ground truth is the `flip_*` rows of
//! `test-vectors/mode3-pruning/runtime-vectors.json`, produced by
//! `test-vectors/mode3-pruning/oracle-harness/run.sh` driving the real
//! upstream processor. Each flip row encodes the state of a FRESH
//! pruned node at the flip: sentinel row absent (Scala's
//! `readMinimalFullBlockHeight()` returns `GenesisHeight`) and no full
//! block applied.
//!
//! Rust returns `None` where Scala's write is a no-op at
//! `GenesisHeight`; the mapping `None => 1` below is the whole of the
//! declared divergence, and it is asserted in both directions.

#![cfg(feature = "test-helpers")]

use std::path::PathBuf;

use ergo_state::store::activation_minimal_full_block_height;
use serde::Deserialize;

// ----- helpers -----

#[derive(Debug, Deserialize)]
struct Inputs {
    current_min: u32,
    header_height: u32,
    blocks_to_keep: i32,
    voting_length: u32,
}

#[derive(Debug, Deserialize)]
struct RuntimeVector {
    id: String,
    inputs: Inputs,
    scala_runtime_output: u32,
}

#[derive(Debug, Deserialize)]
struct RuntimeFile {
    vectors: Vec<RuntimeVector>,
}

#[derive(Debug, Deserialize)]
struct FlipInputRow {
    id: String,
}

#[derive(Debug, Deserialize)]
struct FixtureFile {
    flip_vectors: Vec<FlipInputRow>,
}

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root is ergo-state/..")
        .join("test-vectors/mode3-pruning")
}

fn load_runtime() -> RuntimeFile {
    let path = vectors_root().join("runtime-vectors.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read runtime vectors at {} (regenerate via \
             test-vectors/mode3-pruning/oracle-harness/run.sh): {e}",
            path.display()
        )
    });
    serde_json::from_slice(&bytes).expect("runtime vectors JSON must deserialize")
}

fn load_fixture() -> FixtureFile {
    let path = vectors_root().join("prune-formula-vectors.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read input fixture at {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("input fixture JSON must deserialize")
}

fn flip_rows(runtime: &RuntimeFile) -> Vec<&RuntimeVector> {
    runtime
        .vectors
        .iter()
        .filter(|v| v.id.starts_with("flip_"))
        .collect()
}

// ----- oracle parity -----

#[test]
fn runtime_vectors_cover_every_declared_flip_id() {
    // A partially-regenerated runtime fixture would otherwise silently
    // shrink activation coverage to zero and still pass the parity test
    // below (which iterates whatever rows it finds).
    let fixture = load_fixture();
    let runtime = load_runtime();
    let present: Vec<&str> = flip_rows(&runtime).iter().map(|v| v.id.as_str()).collect();
    let missing: Vec<&str> = fixture
        .flip_vectors
        .iter()
        .map(|r| r.id.as_str())
        .filter(|id| !present.contains(id))
        .collect();
    assert!(
        missing.is_empty(),
        "runtime-vectors.json is missing {} declared flip id(s): {:?}. \
         Regenerate via test-vectors/mode3-pruning/oracle-harness/run.sh.",
        missing.len(),
        missing,
    );
    assert!(
        fixture.flip_vectors.len() >= 10,
        "activation coverage floor: expected at least 10 flip vectors, got {}",
        fixture.flip_vectors.len(),
    );
}

#[test]
fn activation_seed_matches_scala_runtime_at_the_flip() {
    let runtime = load_runtime();
    let rows = flip_rows(&runtime);
    assert!(!rows.is_empty(), "flip vectors must exist in the fixture");

    for v in rows {
        // Flip-time state: sentinel row absent, no full block applied.
        assert_eq!(
            v.inputs.current_min, 1,
            "{}: a flip vector models an absent sentinel row, so \
             current_min must be Scala's GenesisHeight default",
            v.id,
        );
        let got = activation_minimal_full_block_height(
            None,
            v.inputs.header_height,
            0,
            v.inputs.blocks_to_keep,
            v.inputs.voting_length,
        );
        // Rust reports "nothing to record" as `None` where Scala writes
        // GenesisHeight back over GenesisHeight; the persisted read-side
        // default is 1 either way, so the two agree observationally.
        let effective = got.unwrap_or(1);
        assert_eq!(
            effective,
            v.scala_runtime_output,
            "{}: Rust seeds {} (raw {:?}) but Scala's updateBestFullBlock \
             emitted {} (inputs: header_height={}, blocks_to_keep={}, \
             voting_length={})",
            v.id,
            effective,
            got,
            v.scala_runtime_output,
            v.inputs.header_height,
            v.inputs.blocks_to_keep,
            v.inputs.voting_length,
        );
        assert_eq!(
            got.is_none(),
            v.scala_runtime_output == 1,
            "{}: the None arm must fire exactly when Scala's write is a \
             GenesisHeight no-op",
            v.id,
        );
    }
}

// ----- error paths -----

#[test]
fn activation_seed_archive_and_mode_6_never_fire() {
    // `blocks_to_keep < 0` (archive) and `== 0` (canonical Mode 6) do
    // not prune, so the flip must leave the sentinel absent. This is
    // the same `blocks_to_keep <= 0` refusal the steady-state formula
    // makes, restated at the activation seam so a future edit cannot
    // arm pruning for a non-pruning mode.
    for btk in [-1i32, 0] {
        assert_eq!(
            activation_minimal_full_block_height(None, 5000, 0, btk, 1024),
            None,
            "blocks_to_keep = {btk} must never seed a sentinel",
        );
    }
}

#[test]
fn activation_seed_refuses_a_store_that_already_has_full_blocks() {
    // Past the flip, the forward-apply eviction seam owns the sentinel.
    // Seeding from a header tip well above the applied tip would jump
    // the sentinel past history the node actually holds.
    assert_eq!(
        activation_minimal_full_block_height(None, 5000, 1, 232, 1024),
        None,
    );
}

#[test]
fn activation_seed_refuses_an_already_present_sentinel_row() {
    // One-shot latch. `install_snapshot_state` / `apply_popow_proof`
    // materialize the row during Mode 2 / Mode 4 bootstrap, and the
    // seed itself materializes it, so neither a composed bootstrap nor
    // a flip observed twice (boot, then tick) can move it again.
    assert_eq!(
        activation_minimal_full_block_height(Some(1), 5000, 0, 232, 1024),
        None,
    );
    assert_eq!(
        activation_minimal_full_block_height(Some(4096), 5000, 0, 232, 1024),
        None,
    );
}

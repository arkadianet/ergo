//! Track B touch-surface guard — Track-B PR-review audit only.
//!
//! Touch-surface regression: assert that no `ergo-ser` files are
//! modified by Track B. Catches future scope creep into the
//! byte-preservation layer.
//!
//! Scope: this is a one-shot audit for use during the Track B PR
//! review window. It is `#[ignore]` by default so it does not freeze
//! `ergo-ser/` against legitimate post-Track-B changes (which would
//! be the wrong thing to enforce — the byte-preservation layer
//! evolves on its own cadence). Reviewers run it explicitly:
//!
//!     cargo test -p ergo-api --test track_b_touch_surface -- --ignored
//!
//! Once Track B merges and the contract is documented in the
//! followups spec, this file can be deleted.

use std::process::Command;

const BASELINE_COMMIT: &str = "43b4dbf5f9eb746d30a639ff8c2ff40be36cd63a";

#[test]
#[ignore = "Track-B PR-review audit only; run explicitly with --ignored"]
fn track_b_does_not_modify_ergo_ser() {
    assert!(
        is_baseline_reachable(),
        "pre-Track-B baseline {BASELINE_COMMIT} is not reachable; \
         run from a full clone with the baseline commit present."
    );

    let output = Command::new("git")
        .args(["diff", "--name-only", BASELINE_COMMIT, "--", "ergo-ser/"])
        .output()
        .expect("git diff");
    assert!(
        output.status.success(),
        "git diff failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let touched: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        touched.is_empty(),
        "Track B must not modify ergo-ser. Offending paths since \
         {BASELINE_COMMIT}:\n  {}",
        touched.join("\n  ")
    );
}

fn is_baseline_reachable() -> bool {
    Command::new("git")
        .args(["cat-file", "-e", BASELINE_COMMIT])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

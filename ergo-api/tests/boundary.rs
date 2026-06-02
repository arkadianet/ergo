//! Operator-API dependency boundary.
//!
//! `ergo-api` must not depend on any internal node crate or storage
//! primitive. The boundary is what prevents internal refactors from
//! rippling into the wire schema, and it is easy to regress by adding
//! one stray `use` import or `path = ".."` line. This test catches that
//! by walking `cargo tree`.

use std::process::Command;

const FORBIDDEN: &[&str] = &[
    "ergo-state",
    "ergo-p2p",
    "ergo-mempool",
    "ergo-sync",
    "ergo-node",
    "redb",
];

#[test]
fn ergo_api_has_no_forbidden_deps() {
    let output = Command::new(env!("CARGO"))
        .args(["tree", "-p", "ergo-api", "-e", "normal", "--prefix", "none"])
        .output()
        .expect("invoke cargo tree");
    assert!(
        output.status.success(),
        "cargo tree -p ergo-api failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut violations = Vec::new();
    for line in stdout.lines() {
        for &forbidden in FORBIDDEN {
            if line.starts_with(&format!("{forbidden} ")) {
                violations.push(format!("{forbidden}: {line}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "ergo-api must not depend on any internal node crate or storage primitive.\n\
         Violations:\n  {}\n\nFull cargo tree output:\n{stdout}",
        violations.join("\n  "),
    );
}
